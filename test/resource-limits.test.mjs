// lib/resource-limits.mjs: a supervised Uptime Goblin reads the memory, process and CPU limits of its own
// cgroup back at every start, because neither Docker nor systemd says when one does not apply (an
// override file that sets one of compose.yaml's to 0, a drop-in, a controller the LXC host does
// not delegate, a CPU set Docker discarded), and refuses to start (exit status 78) unless each is
// in force or GOBLIN_ALLOW_UNLIMITED names it (the maintainer's decision of 2026-10-11; until then it only
// warned and started). These tests lay out /proc/self/cgroup, a cgroup2 tree and /sys as the
// kernel shows them, for each row of the decision table and each start line; the real ones are
// checked under Docker (test/installer/docker.test.mjs) and systemd
// (test/installer/systemd.test.mjs), and the start itself in test/startup.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  LIMITS_REFUSAL,
  LIMIT_NAMES,
  limitsStatus,
  parseAllowUnlimited,
  readLimits,
  superviseLimits,
  unenforcedLimits,
} from '../lib/resource-limits.mjs';

const repository = path.resolve(import.meta.dirname, '..');
const shipped = { 'memory.max': '1073741824\n', 'pids.max': '256\n', 'cpu.max': '200000 100000\n' };

/**
 * A /proc, a cgroup root and a /sys in a temporary directory: `membership` is /proc/self/cgroup,
 * `cgroup` (a path below the root) holds `files`, with cgroup.controllers listing `controllers`,
 * and `online` is /sys/devices/system/cpu/online (none when null): the host's CPUs, never those
 * of the machine running the test.
 */
function layout(
  t,
  {
    membership = '0::/system.slice/uptime-goblin.service\n',
    cgroup = '/system.slice/uptime-goblin.service',
    controllers = 'cpu memory pids',
    files = shipped,
    online = '0-3\n',
  } = {}
) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-cgroup-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const proc = path.join(base, 'proc'),
    cgroupRoot = path.join(base, 'cgroup'),
    sys = path.join(base, 'sys');
  fs.mkdirSync(path.join(proc, 'self'), { recursive: true });
  if (membership !== null) fs.writeFileSync(path.join(proc, 'self', 'cgroup'), membership);
  fs.mkdirSync(path.join(sys, 'devices', 'system', 'cpu'), { recursive: true });
  if (online !== null)
    fs.writeFileSync(path.join(sys, 'devices', 'system', 'cpu', 'online'), online);
  const directory = path.join(cgroupRoot, cgroup);
  fs.mkdirSync(directory, { recursive: true });
  if (controllers !== null)
    fs.writeFileSync(path.join(directory, 'cgroup.controllers'), `${controllers}\n`);
  for (const [name, text] of Object.entries(files))
    fs.writeFileSync(path.join(directory, name), text);
  return { proc, cgroupRoot, sys, directory };
}

const pathsOf = ({ proc, cgroupRoot, sys }) => ({ proc, cgroupRoot, sys });
// The three states, as a supervised Uptime Goblin on Linux reads them.
const states = (paths, platform = 'linux') =>
  Object.fromEntries(
    Object.entries(readLimits({ ...pathsOf(paths), platform }).limits).map(([name, limit]) => [
      name,
      `${limit.state}: ${limit.detail}`,
    ])
  );
// The start's decision, supervised, with GOBLIN_ALLOW_UNLIMITED `allow` (unset when undefined).
const decide = (paths, allow, { supervised = true, platform = 'linux' } = {}) =>
  superviseLimits({
    env: allow === undefined ? {} : { GOBLIN_ALLOW_UNLIMITED: allow },
    supervised,
    ...pathsOf(paths),
    platform,
  });

// What each line says of a limit, and how to apply it (lib/resource-limits.mjs, limitTexts).
const apply = {
  memory:
    'Under Docker, give mem_limit in compose.yaml or compose.override.yaml (docker run --memory); under systemd, MemoryMax= in uptime-goblin.service or a drop-in (systemctl cat uptime-goblin.service shows them; MemoryMax=infinity lifts it); in an LXC, its host must delegate the memory controller to the container.',
  cpu: "Under Docker, give cpus in compose.yaml or compose.override.yaml (docker run --cpus), or, where the kernel cannot limit CPU time, a CPU set (cpuset: '0') that Docker applies; under systemd, CPUQuota= in uptime-goblin.service or a drop-in (an empty CPUQuota= lifts it); in an LXC, its host must delegate the cpu controller to the container.",
  pids: 'Under Docker, give pids_limit in compose.yaml or compose.override.yaml (docker run --pids-limit); under systemd, TasksMax= in uptime-goblin.service or a drop-in (TasksMax=infinity lifts it); in an LXC, its host must delegate the pids controller to the container.',
};
const header = names =>
  `Uptime Goblin refused to start without its resource limits: under a service manager (started with --supervised or GOBLIN_SUPERVISED=1) it starts only where its own cgroup holds its memory, CPU time and processes to a limit, and here its ${names} not in force.`;
const waysOut = (setting, plural) =>
  `To start Uptime Goblin, apply each limit named above (docs/installation.md, "Resource limits", has the steps for Docker, systemd and LXC hosts), or, on a platform that cannot apply ${plural ? 'them' : 'it'}, set GOBLIN_ALLOW_UNLIMITED=${setting} in Uptime Goblin's environment (/etc/uptime-goblin.env for the systemd unit, .env for Docker Compose): Uptime Goblin then starts without ${setting.includes(',') ? 'those limits' : 'that limit'} and says so at every start.`;

test('the limits compose.yaml and uptime-goblin.service set are in force: a supervised start goes on, with nothing to say', t => {
  for (const host of [
    {},
    // Docker's own cgroup namespace: Uptime Goblin's cgroup is its root, /sys/fs/cgroup itself.
    { membership: '0::/\n', cgroup: '/' },
    // A Docker host without a cgroup namespace for the container.
    {
      membership: '0::/system.slice/docker-0123abcd.scope\n',
      cgroup: '/system.slice/docker-0123abcd.scope',
    },
  ]) {
    const paths = layout(t, host);
    assert.deepEqual(states(paths), {
      memory: 'enforced: memory.max 1073741824',
      cpu: 'enforced: cpu.max 200000 100000: 2 CPUs',
      pids: 'enforced: pids.max 256',
    });
    const decision = decide(paths);
    assert.equal(decision.refusal, null);
    assert.deepEqual(decision.warnings, []);
    assert.deepEqual(decision.status, {
      supervised: true,
      allowUnlimited: [],
      limits: {
        memory: { state: 'enforced', detail: 'memory.max 1073741824', allowed: false },
        cpu: { state: 'enforced', detail: 'cpu.max 200000 100000: 2 CPUs', allowed: false },
        pids: { state: 'enforced', detail: 'pids.max 256', allowed: false },
      },
    });
    assert.ok(Object.isFrozen(decision.status) && Object.isFrozen(decision.status.limits.cpu));
  }
  // compose.yaml's own: 1 GiB, 1 CPU, 256 processes.
  assert.equal(
    states(layout(t, { files: { ...shipped, 'cpu.max': '100000 100000\n' } })).cpu,
    'enforced: cpu.max 100000 100000: 1 CPU'
  );
});

test('decision table, memory: enforced, missing (no controller, max, more than 2^52 bytes) and unverifiable', t => {
  const memory = (files, controllers) =>
    states(layout(t, { files: { ...shipped, ...files }, controllers })).memory;
  assert.equal(memory({ 'memory.max': '536870912\n' }), 'enforced: memory.max 536870912');
  // 2^52 bytes is still a limit; one byte more limits nothing.
  assert.equal(memory({ 'memory.max': `${2 ** 52}\n` }), `enforced: memory.max ${2 ** 52}`);
  assert.equal(
    memory({ 'memory.max': '4503599627370497\n' }),
    'missing: memory.max is 4503599627370497, more than 2^52 bytes, which limits nothing'
  );
  // As cgroup v1 shows no limit (the largest page-aligned 63-bit number).
  assert.equal(
    memory({ 'memory.max': '9223372036854771712\n' }),
    'missing: memory.max is 9223372036854771712, more than 2^52 bytes, which limits nothing'
  );
  // mem_limit: 0 in an override file, or MemoryMax=infinity in a drop-in.
  assert.equal(memory({ 'memory.max': 'max\n' }), 'missing: memory.max is max');
  // An LXC whose host gives the container no memory controller: systemd takes MemoryMax= but
  // has no memory.max to write it to.
  const { 'memory.max': _, ...rest } = shipped;
  assert.equal(
    states(layout(t, { controllers: 'cpu pids', files: rest })).memory,
    "missing: Uptime Goblin's cgroup has no memory controller, so no memory limit can apply to it"
  );
  // A limit file it cannot read as a limit: missing, a word, a negative or fractional number,
  // too long, a directory.
  for (const text of [undefined, 'x\n', '-1\n', '1.5\n', '', '1 2\n', 'x'.repeat(5000)]) {
    const files = text === undefined ? rest : { ...shipped, 'memory.max': text };
    assert.equal(
      states(layout(t, { files })).memory,
      'unverifiable: Uptime Goblin cannot read memory.max of its cgroup as a limit',
      JSON.stringify(text)
    );
  }
  const paths = layout(t, { files: rest });
  fs.mkdirSync(path.join(paths.directory, 'memory.max'));
  assert.match(states(paths).memory, /^unverifiable: /);
});

test('decision table, processes: enforced, missing (no controller, max) and unverifiable', t => {
  const pids = (files, controllers) =>
    states(layout(t, { files: { ...shipped, ...files }, controllers })).pids;
  assert.equal(pids({ 'pids.max': '512\n' }), 'enforced: pids.max 512');
  // pids_limit: 0 or a negative number in an override file, or TasksMax=infinity in a drop-in.
  assert.equal(pids({ 'pids.max': 'max\n' }), 'missing: pids.max is max');
  const { 'pids.max': _, ...rest } = shipped;
  assert.equal(
    states(layout(t, { controllers: 'cpu memory', files: rest })).pids,
    "missing: Uptime Goblin's cgroup has no pids controller, so no process limit can apply to it"
  );
  for (const text of [undefined, 'none\n', '-1\n', '', 'x'.repeat(5000)])
    assert.equal(
      states(layout(t, { files: text === undefined ? rest : { ...shipped, 'pids.max': text } }))
        .pids,
      'unverifiable: Uptime Goblin cannot read pids.max of its cgroup as a limit',
      JSON.stringify(text)
    );
});

// The CPU limit is cpu.max's quota, or else a CPU set Uptime Goblin's own cgroup sets (maintainer decision D21, PU5):
// its cpuset.cpus not empty, a CPU list and only of CPUs the host has online, its
// cpuset.cpus.effective not empty, a CPU list and within that set, and both fewer CPUs than the
// host has online (independent review F-01: which CPUs, not only how many). Docker left a container given
// --cpuset-cpus 0 (or cpus: 0 with cpuset: '0') cpu.max `max 100000`, cpuset.cpus `0` and
// cpuset.cpus.effective `0`; one whose CPU set Docker discarded had no cpuset controller at all;
// one with no CPU option inside a Docker held to CPUs 0-1 had an empty cpuset.cpus and effective
// `0-1`.
const noCpuTime = { ...shipped, 'cpu.max': 'max 100000\n' };
const { 'cpu.max': _cpuMax, ...noCpuMax } = shipped;
const withSet = (
  effective,
  { own = effective, cpuMax = 'max 100000\n', controllers, ...extra } = {}
) => ({
  controllers: controllers ?? 'cpuset cpu memory pids',
  files: {
    ...noCpuMax,
    ...(cpuMax === null ? {} : { 'cpu.max': cpuMax }),
    ...(own === null ? {} : { 'cpuset.cpus': own }),
    ...(effective === null ? {} : { 'cpuset.cpus.effective': effective }),
  },
  ...extra,
});

test('decision table, CPU: a quota, or a CPU set of its own that applies, is enforced', t => {
  const cpu = host => states(layout(t, host)).cpu;
  // A quota counts whatever the CPU set says, one it cannot read included.
  assert.equal(
    cpu({ ...withSet('x\n', { cpuMax: '50000 100000\n' }), online: null }),
    'enforced: cpu.max 50000 100000: 0.5 CPUs'
  );
  // The operators' CPU set where the kernel cannot limit CPU time, on an 18-CPU host.
  assert.equal(
    cpu(withSet('0\n', { online: '0-17\n' })),
    "enforced: cpuset.cpus 0, cpuset.cpus.effective 0: 1 of this host's 18 CPUs"
  );
  // No cpu controller, or one without cpu.max (a kernel without CPU bandwidth control): the set
  // still counts.
  assert.equal(
    cpu(withSet('0\n', { cpuMax: null, controllers: 'cpuset memory pids', online: '0-17\n' })),
    "enforced: cpuset.cpus 0, cpuset.cpus.effective 0: 1 of this host's 18 CPUs"
  );
  assert.equal(
    cpu(withSet('0\n', { cpuMax: null, online: '0-17\n' })),
    "enforced: cpuset.cpus 0, cpuset.cpus.effective 0: 1 of this host's 18 CPUs"
  );
  // Ranges and single CPUs are counted on both sides; one CPU fewer than the host still counts.
  assert.equal(
    cpu(withSet('0-1,4\n', { online: '0-7\n' })),
    "enforced: cpuset.cpus 0-1,4, cpuset.cpus.effective 0-1,4: 3 of this host's 8 CPUs"
  );
  assert.equal(
    cpu(withSet('2\n', { online: '0-1,2-3\n' })),
    "enforced: cpuset.cpus 2, cpuset.cpus.effective 2: 1 of this host's 4 CPUs"
  );
  assert.equal(
    cpu(withSet('0-2\n', { online: '0-3\n' })),
    "enforced: cpuset.cpus 0-2, cpuset.cpus.effective 0-2: 3 of this host's 4 CPUs"
  );
});

test('decision table, CPU: no quota and no CPU set that applies is missing, with the reason', t => {
  const cpu = host => states(layout(t, host)).cpu;
  const none = "missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ";
  // Where Docker discarded the CPU set (no cpuset controller), or a native unit, which has none.
  assert.equal(cpu({ files: noCpuTime }), `${none}Uptime Goblin's cgroup has no cpuset controller`);
  assert.equal(
    cpu({ controllers: 'memory pids', files: noCpuMax }),
    "missing: Uptime Goblin's cgroup has no cpu controller, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller"
  );
  // A one-CPU host: cpuset '0' is all of it.
  assert.equal(
    cpu(withSet('0\n', { online: '0\n' })),
    `${none}this host has one CPU (online 0), so a CPU set is all of it`
  );
  // cpus: 0 alone, docker run without --cpus, an empty cpuset.
  assert.equal(
    cpu(withSet('0-17\n', { own: '\n', online: '0-17\n' })),
    `${none}Uptime Goblin's cgroup sets none of its own (cpuset.cpus is empty), so it may run on every CPU it is given (cpuset.cpus.effective 0-17, online 0-17)`
  );
  // A set Uptime Goblin only inherits (Docker in a container or LXC held to CPUs 0-1).
  assert.equal(
    cpu(withSet('0-1\n', { own: '\n', online: '0-17\n' })),
    `${none}Uptime Goblin's cgroup sets none of its own (cpuset.cpus is empty), so it may run on every CPU it is given (cpuset.cpus.effective 0-1, online 0-17)`
  );
  // A set of every CPU (--cpuset-cpus 0-17 there), also one the cgroups around it narrow.
  assert.equal(
    cpu(withSet('0-17\n', { online: '0-17\n' })),
    `${none}the one Uptime Goblin's cgroup sets holds every CPU this host has online (cpuset.cpus 0-17, online 0-17)`
  );
  assert.equal(
    cpu(withSet('0-1\n', { own: '0-17\n', online: '0-17\n' })),
    `${none}the one Uptime Goblin's cgroup sets holds every CPU this host has online (cpuset.cpus 0-17, online 0-17)`
  );
  // A set of its own with no CPU online: the kernel then gives the CPUs of the cgroup around it.
  assert.equal(
    cpu(withSet('0-3\n', { own: '7\n', online: '0-3\n' })),
    `${none}Uptime Goblin may run on every CPU this host has online (cpuset.cpus.effective 0-3, online 0-3)`
  );
  // A long list is shown cut.
  const long = Array.from({ length: 40 }, (_, i) => String(i * 2)).join(',');
  assert.match(
    cpu(withSet(`${long}\n`, { online: '0-79\n' })),
    /^enforced: cpuset\.cpus 0,2,4,.{50,60}…, cpuset\.cpus\.effective 0,2,4/
  );
});

// A CPU set counts only where the CPUs Uptime Goblin runs on are all among those it asks for: where the
// cgroup around Uptime Goblin's can grant none of the CPUs its own cpuset.cpus names (systemd
// AllowedCPUs=17 in an LXC held to CPUs 0-3), the kernel gives Uptime Goblin's cgroup the CPUs of that
// cgroup instead (cgroup v2, cpuset.cpus.effective), which bound the whole group, not Uptime Goblin. A set
// its parent narrows still counts, and so does one that names exactly the CPUs of the cgroup
// around it (Docker held to CPUs 1-2, cpuset '1-2').
test('decision table, CPU: a CPU set counts only where the CPUs Uptime Goblin runs on are all among those its cgroup asks for; the equal-parent set still counts', t => {
  const cpu = host => states(layout(t, host)).cpu;
  const notGranted = (own, effective) =>
    `the CPUs Uptime Goblin runs on are not all among those its cgroup sets (cpuset.cpus ${own}, cpuset.cpus.effective ${effective}): the kernel gives a cgroup the CPUs of the one around it when it can grant none of those it asks for, which limits that whole group, not Uptime Goblin within it`;
  // The kernel's fallback: none of the CPUs asked for is granted.
  assert.equal(
    cpu(withSet('0-3\n', { own: '17\n', online: '0-17\n' })),
    `missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ${notGranted('17', '0-3')}`
  );
  assert.equal(
    cpu(
      withSet('0-3\n', {
        own: '17\n',
        cpuMax: null,
        controllers: 'cpuset memory pids',
        online: '0-17\n',
      })
    ),
    `missing: Uptime Goblin's cgroup has no cpu controller, and no CPU set of Uptime Goblin's own limits it: ${notGranted('17', '0-3')}`
  );
  assert.equal(
    cpu(withSet('0-3\n', { own: '17\n', cpuMax: null, online: '0-17\n' })),
    `unverifiable: Uptime Goblin's cgroup has the cpu controller but no cpu.max it can read (a kernel without CPU bandwidth control has none), and no CPU set of Uptime Goblin's own limits it: ${notGranted('17', '0-3')}`
  );
  // Effective CPUs beyond those asked for, in a list or in ranges.
  assert.equal(
    cpu(withSet('4-5\n', { own: '5\n', online: '0-17\n' })),
    `missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ${notGranted('5', '4-5')}`
  );
  assert.equal(
    cpu(withSet('0,2,9\n', { own: '0-3,8\n', online: '0-17\n' })),
    `missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ${notGranted('0-3,8', '0,2,9')}`
  );
  // The explicit equal-parent set (Docker held to CPUs 1-2 and cpuset '1-2'): its own, and counted.
  assert.equal(
    cpu(withSet('1-2\n', { online: '0-17\n' })),
    "enforced: cpuset.cpus 1-2, cpuset.cpus.effective 1-2: 2 of this host's 18 CPUs"
  );
  // A set the cgroup around it narrows: the CPUs Uptime Goblin runs on are still among its own.
  assert.equal(
    cpu(withSet('2-3\n', { own: '2-5\n', online: '0-17\n' })),
    "enforced: cpuset.cpus 2-5, cpuset.cpus.effective 2-3: 2 of this host's 18 CPUs"
  );
  // Ranges that touch are read as one, on either side.
  assert.equal(
    cpu(withSet('1-2\n', { own: '0-1,2-3\n', online: '0-17\n' })),
    "enforced: cpuset.cpus 0-1,2-3, cpuset.cpus.effective 1-2: 2 of this host's 18 CPUs"
  );
  assert.equal(
    cpu(withSet('0,1,2\n', { own: '0-2\n', online: '0-17\n' })),
    "enforced: cpuset.cpus 0-2, cpuset.cpus.effective 0,1,2: 3 of this host's 18 CPUs"
  );
  // Lists of millions of CPUs are compared as ranges.
  assert.equal(
    cpu(withSet('2-9999998\n', { own: '1-9999998\n', online: '0-9999999\n' })),
    "enforced: cpuset.cpus 1-9999998, cpuset.cpus.effective 2-9999998: 9999997 of this host's 10000000 CPUs"
  );
  assert.match(
    cpu(withSet('0-9999998\n', { own: '1-9999998\n', online: '0-9999999\n' })),
    /^missing: cpu\.max is max, and no CPU set of Uptime Goblin's own limits it: the CPUs Uptime Goblin runs on are not all among those/
  );
  // The start: refused (78) for want of a CPU limit, and with GOBLIN_ALLOW_UNLIMITED=cpu it starts
  // and reports the limit as run without, in /api/system and the audit, not as Uptime Goblin's own.
  const fallback = layout(t, withSet('0-3\n', { own: '17\n', online: '0-17\n' }));
  const refused = decide(fallback);
  assert.ok(refused.refusal);
  assert.equal(
    refused.refusal[1],
    `CPU limit: none (cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ${notGranted('17', '0-3')}). ${apply.cpu}`
  );
  const waived = decide(fallback, 'cpu');
  assert.equal(waived.refusal, null);
  assert.equal(waived.status.limits.cpu.state, 'missing');
  assert.deepEqual(unenforcedLimits(limitsStatus(waived.status)), ['cpu']);
});

// A CPU set counts only where every CPU it names is one the host has online (independent review F-01):
// a set of fewer CPUs than the host's can still name CPUs that are offline, that do not exist or
// that this process cannot see in /sys (LXCFS can hide the host's CPUs from an LXC), and what it
// then holds Uptime Goblin to cannot be told: unverifiable, never a limit, whatever its count. The sets
// are compared as ranges, on discontiguous online CPUs and at the ends of a range; the reasons
// of before keep their order; a cpu.max quota still counts by itself.
test('decision table, CPU: a CPU set counts only where every CPU it names is online, whatever its count; a quota counts by itself', t => {
  const cpu = host => states(layout(t, host)).cpu;
  const hidden =
    'CPUs that are offline, that do not exist, or that this process cannot see in /sys (as under LXCFS), so Uptime Goblin cannot tell what that set holds it to';
  const names = (which, own, effective, online) =>
    `the one Uptime Goblin's cgroup sets names ${which} (cpuset.cpus ${own}, cpuset.cpus.effective ${effective}, online ${online}): ${hidden}`;
  const offlineOnly = (own, effective, online) =>
    names('only CPUs this host does not have online', own, effective, online);
  const offlineToo = (own, effective, online) =>
    names('CPUs this host does not have online besides some it has', own, effective, online);
  const cannotTell = (why, time = 'cpu.max is max') =>
    `unverifiable: ${time}, and Uptime Goblin cannot tell whether a CPU set limits it instead: ${why}`;
  const counted = (own, effective, count, hostCount) =>
    `enforced: cpuset.cpus ${own}, cpuset.cpus.effective ${effective}: ${count} of this host's ${hostCount} CPUs`;
  // Online 0-3: CPU 8 alone, and CPU 0 with CPU 8 where Uptime Goblin runs on CPU 0, are fewer CPUs than
  // the host's, and neither counts.
  assert.equal(cpu(withSet('8\n', { online: '0-3\n' })), cannotTell(offlineOnly('8', '8', '0-3')));
  assert.equal(
    cpu(withSet('0\n', { own: '0,8\n', online: '0-3\n' })),
    cannotTell(offlineToo('0,8', '0', '0-3'))
  );
  // Online CPUs 0-1 and 4-5: a CPU in the gap, one beyond them and a range across the gap do not
  // count; sets within them do.
  const gap = { online: '0-1,4-5\n' };
  assert.equal(cpu(withSet('2\n', gap)), cannotTell(offlineOnly('2', '2', '0-1,4-5')));
  assert.equal(cpu(withSet('2-3\n', gap)), cannotTell(offlineOnly('2-3', '2-3', '0-1,4-5')));
  assert.equal(cpu(withSet('6\n', gap)), cannotTell(offlineOnly('6', '6', '0-1,4-5')));
  assert.equal(
    cpu(withSet('1,4\n', { ...gap, own: '1-4\n' })),
    cannotTell(offlineToo('1-4', '1,4', '0-1,4-5'))
  );
  assert.equal(
    cpu(withSet('4\n', { ...gap, own: '4,6\n' })),
    cannotTell(offlineToo('4,6', '4', '0-1,4-5'))
  );
  assert.equal(cpu(withSet('4-5\n', gap)), counted('4-5', '4-5', 2, 4));
  assert.equal(cpu(withSet('0,4\n', { ...gap, own: '0-1,4\n' })), counted('0-1,4', '0,4', 2, 4));
  // The ends of the online range count; one CPU past either end does not.
  assert.equal(cpu(withSet('0\n', { online: '0-3\n' })), counted('0', '0', 1, 4));
  assert.equal(cpu(withSet('3\n', { online: '0-3\n' })), counted('3', '3', 1, 4));
  assert.equal(cpu(withSet('1-3\n', { online: '0-3\n' })), counted('1-3', '1-3', 3, 4));
  assert.equal(cpu(withSet('4\n', { online: '0-3\n' })), cannotTell(offlineOnly('4', '4', '0-3')));
  assert.equal(
    cpu(withSet('3\n', { own: '3-4\n', online: '0-3\n' })),
    cannotTell(offlineToo('3-4', '3', '0-3'))
  );
  assert.equal(
    cpu(withSet('2\n', { own: '1-2\n', online: '2-5\n' })),
    cannotTell(offlineToo('1-2', '2', '2-5'))
  );
  assert.equal(
    cpu(withSet('0-2\n', { own: '0-2,4\n', online: '0-3\n' })),
    cannotTell(offlineToo('0-2,4', '0-2', '0-3'))
  );
  // The CPUs Uptime Goblin runs on outside its own set: the kernel's fallback, as before, said first.
  const notGranted = (own, effective) =>
    `missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: the CPUs Uptime Goblin runs on are not all among those its cgroup sets (cpuset.cpus ${own}, cpuset.cpus.effective ${effective}): the kernel gives a cgroup the CPUs of the one around it when it can grant none of those it asks for, which limits that whole group, not Uptime Goblin within it`;
  assert.equal(cpu(withSet('2\n', { own: '0-1\n', online: '0-3\n' })), notGranted('0-1', '2'));
  assert.equal(
    cpu(withSet('0-1,8\n', { own: '0-1\n', online: '0-3\n' })),
    notGranted('0-1', '0-1,8')
  );
  assert.equal(cpu(withSet('9\n', { own: '8\n', online: '0-3\n' })), notGranted('8', '9'));
  // Every online CPU, also with offline CPUs besides; a one-CPU host, also where the set names
  // another CPU; a set Uptime Goblin only inherits: no limit, as before.
  const none = "missing: cpu.max is max, and no CPU set of Uptime Goblin's own limits it: ";
  assert.equal(
    cpu(withSet('0-3\n', { online: '0-3\n' })),
    `${none}the one Uptime Goblin's cgroup sets holds every CPU this host has online (cpuset.cpus 0-3, online 0-3)`
  );
  assert.equal(
    cpu(withSet('0-3\n', { own: '0-7\n', online: '0-3\n' })),
    `${none}the one Uptime Goblin's cgroup sets holds every CPU this host has online (cpuset.cpus 0-7, online 0-3)`
  );
  assert.equal(
    cpu(withSet('1\n', { online: '0\n' })),
    `${none}this host has one CPU (online 0), so a CPU set is all of it`
  );
  assert.equal(
    cpu(withSet('8\n', { own: '\n', online: '0-3\n' })),
    `${none}Uptime Goblin's cgroup sets none of its own (cpuset.cpus is empty), so it may run on every CPU it is given (cpuset.cpus.effective 8, online 0-3)`
  );
  // A file it cannot read as a CPU list is said first, as before.
  assert.equal(
    cpu(withSet('8\n', { online: null })),
    'unverifiable: cpu.max is max, and Uptime Goblin cannot read /sys/devices/system/cpu/online to tell whether a CPU set limits it instead'
  );
  assert.equal(
    cpu(withSet('8\n', { own: '8-\n', online: '0-3\n' })),
    'unverifiable: cpu.max is max, and Uptime Goblin cannot read cpuset.cpus to tell whether a CPU set limits it instead'
  );
  // Without a cpu controller, where CPU time is known to have no limit, such a set is still
  // unverifiable, not missing.
  assert.equal(
    cpu(withSet('8\n', { cpuMax: null, controllers: 'cpuset memory pids', online: '0-3\n' })),
    cannotTell(offlineOnly('8', '8', '0-3'), "Uptime Goblin's cgroup has no cpu controller")
  );
  // A quota counts by itself, whatever CPUs the set names.
  assert.equal(
    cpu(withSet('8\n', { cpuMax: '50000 100000\n', online: '0-3\n' })),
    'enforced: cpu.max 50000 100000: 0.5 CPUs'
  );
  assert.equal(
    cpu(withSet('0\n', { own: '0,8\n', cpuMax: '100000 100000\n', online: '0-3\n' })),
    'enforced: cpu.max 100000 100000: 1 CPU'
  );
  // Lists of millions of CPUs are compared as ranges here too.
  assert.equal(
    cpu(withSet('1-2\n', { own: '1-9999998\n', online: '0-4999999\n' })),
    cannotTell(offlineToo('1-9999998', '1-2', '0-4999999'))
  );
  assert.equal(
    cpu(withSet('5000000-9999999\n', { online: '0-4999999\n' })),
    cannotTell(offlineOnly('5000000-9999999', '5000000-9999999', '0-4999999'))
  );
  // The start: refused (78) for want of a CPU limit it can verify; with GOBLIN_ALLOW_UNLIMITED=cpu
  // it starts, says so, and reports the limit as run without, in /api/system and the audit.
  const offline = layout(t, withSet('0\n', { own: '0,8\n', online: '0-3\n' }));
  const why = offlineToo('0,8', '0', '0-3');
  const refused = decide(offline);
  assert.deepEqual(refused.refusal, [
    header('CPU limit is'),
    `CPU limit: cannot be verified (cpu.max is max, and Uptime Goblin cannot tell whether a CPU set limits it instead: ${why}). ${apply.cpu}`,
    waysOut('cpu', false),
  ]);
  assert.ok(refused.refusal[0].startsWith(LIMITS_REFUSAL));
  assert.equal(refused.status.limits.cpu.state, 'unverifiable');
  assert.deepEqual(refused.warnings, []);
  // A setting that names another limit does not let it start.
  assert.equal(decide(offline, 'memory').refusal.at(-1), waysOut('memory,cpu', false));
  const waived = decide(offline, 'cpu');
  assert.equal(waived.refusal, null);
  assert.deepEqual(waived.warnings, [
    `Uptime Goblin runs without a CPU limit, as GOBLIN_ALLOW_UNLIMITED allows: cannot be verified (cpu.max is max, and Uptime Goblin cannot tell whether a CPU set limits it instead: ${why}). Nothing keeps a runaway collection or a flood of requests from taking all of this host's CPU time; apply the limit once the platform can (docs/installation.md, "Resource limits").`,
  ]);
  assert.equal(waived.status.limits.cpu.allowed, true);
  assert.deepEqual(unenforcedLimits(limitsStatus(waived.status)), ['cpu']);
});

test('decision table, CPU: what cannot be read is unverifiable, never a limit', t => {
  const cpu = host => states(layout(t, host)).cpu;
  // A cpu controller without cpu.max (a kernel without CPU bandwidth control), and no set.
  assert.equal(
    cpu({ files: noCpuMax }),
    "unverifiable: Uptime Goblin's cgroup has the cpu controller but no cpu.max it can read (a kernel without CPU bandwidth control has none), and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller"
  );
  assert.equal(
    cpu(withSet('0-3\n', { own: '\n', cpuMax: null })),
    "unverifiable: Uptime Goblin's cgroup has the cpu controller but no cpu.max it can read (a kernel without CPU bandwidth control has none), and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup sets none of its own (cpuset.cpus is empty), so it may run on every CPU it is given (cpuset.cpus.effective 0-3, online 0-3)"
  );
  // cpu.max it cannot read as a quota.
  for (const text of ['0 100000\n', 'max 0\n', '100000\n', '-1 100000\n', 'max  100000\n', 'max\n'])
    assert.equal(
      cpu({ files: { ...shipped, 'cpu.max': text } }),
      "unverifiable: Uptime Goblin cannot read cpu.max of its cgroup as a limit, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller",
      JSON.stringify(text)
    );
  // Too long to be a limit file, or not a regular file: no cpu.max it can read.
  assert.match(
    cpu({ files: { ...shipped, 'cpu.max': 'x'.repeat(5000) } }),
    /^unverifiable: Uptime Goblin's cgroup has the cpu controller but no cpu\.max it can read /
  );
  // No quota, and a CPU set file it cannot read as a CPU list (an empty effective set
  // included): it cannot tell.
  const cannot = file =>
    `unverifiable: cpu.max is max, and Uptime Goblin cannot read ${file} to tell whether a CPU set limits it instead`;
  assert.equal(cpu(withSet('0\n', { own: null })), cannot('cpuset.cpus'));
  assert.equal(cpu(withSet(null, { own: '0\n' })), cannot('cpuset.cpus.effective'));
  assert.equal(
    cpu(withSet('\n', { own: '0\n', online: '0-17\n' })),
    cannot('cpuset.cpus.effective')
  );
  assert.equal(cpu(withSet('0\n', { online: null })), cannot('/sys/devices/system/cpu/online'));
  for (const list of ['3-1', '1,0', '0,0', 'x', '0-', '12345678'])
    assert.equal(cpu(withSet(`${list}\n`, { own: '0\n' })), cannot('cpuset.cpus.effective'), list);
  assert.equal(
    cpu(withSet(null, { own: null, online: null })),
    cannot('cpuset.cpus, cpuset.cpus.effective and /sys/devices/system/cpu/online')
  );
});

test('decision table, all three: cgroup v1, a hybrid layout or no cgroup it can read, and not Linux, are unverifiable', t => {
  const v2 =
    'unverifiable: Uptime Goblin reads its limits under cgroup v2 only, which it did not find here (cgroup v1 or a hybrid layout)';
  const every = detail => ({ memory: detail, cpu: detail, pids: detail });
  // cgroup v1: one line per hierarchy, none of them "0::".
  assert.deepEqual(
    states(layout(t, { membership: '12:memory:/docker/x\n11:pids:/docker/x\n' })),
    every(v2)
  );
  // Hybrid: the unified hierarchy is not where the limits are (no cgroup.controllers there).
  assert.deepEqual(states(layout(t, { controllers: null })), every(v2));
  // No /proc/self/cgroup, and paths that are not absolute or climb out of the cgroup root.
  assert.deepEqual(states(layout(t, { membership: null })), every(v2));
  for (const membership of ['0::system.slice\n', '0::/../../etc\n', '0::\n'])
    assert.deepEqual(states(layout(t, { membership, cgroup: '/' })), every(v2), membership);
  // A supervised Uptime Goblin on macOS (the tests start it so): nothing to read.
  assert.deepEqual(
    states(layout(t), 'darwin'),
    every(
      'unverifiable: Uptime Goblin reads its limits from Linux cgroups, and this system is darwin'
    )
  );
  assert.deepEqual(
    states(layout(t), 'Not A\nPlatform'),
    every(
      'unverifiable: Uptime Goblin reads its limits from Linux cgroups, and this system is not Linux'
    )
  );
});

// test/installer/docker.test.mjs cites this test for the refusal for want of a CPU limit.
test('each missing limit is named once, with why, how to apply it and the two ways out: a supervised start refuses (78) while a limit is not in force', t => {
  // pids_limit: 0 in an override file, or TasksMax=infinity in a drop-in: one limit.
  const one = decide(layout(t, { files: { ...shipped, 'pids.max': 'max\n' } }));
  assert.deepEqual(one.refusal, [
    header('process limit is'),
    `Process limit: none (pids.max is max). ${apply.pids}`,
    waysOut('pids', false),
  ]);
  assert.deepEqual(one.warnings, []);
  assert.ok(one.refusal[0].startsWith(LIMITS_REFUSAL));
  assert.equal(one.status.limits.pids.state, 'missing');
  // All three: an override file that sets mem_limit, cpus and pids_limit to 0.
  const all = decide(
    layout(t, { files: { 'memory.max': 'max\n', 'pids.max': 'max\n', 'cpu.max': 'max 100000\n' } })
  );
  assert.deepEqual(all.refusal, [
    header('memory, CPU and process limits are'),
    `Memory limit: none (memory.max is max). ${apply.memory}`,
    `CPU limit: none (cpu.max is max, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller). ${apply.cpu}`,
    `Process limit: none (pids.max is max). ${apply.pids}`,
    waysOut('memory,cpu,pids', true),
  ]);
  // A limit it cannot verify refuses as one that is missing does.
  const v1 = decide(layout(t, { membership: '12:memory:/docker/x\n' }));
  assert.equal(
    v1.refusal[1],
    `Memory limit: cannot be verified (Uptime Goblin reads its limits under cgroup v2 only, which it did not find here (cgroup v1 or a hybrid layout)). ${apply.memory}`
  );
  assert.equal(v1.refusal.length, 5);
  // Where Docker discarded the CPU set: no cpuset controller, cpu.max max.
  const discarded = decide(layout(t, { files: noCpuTime }));
  assert.deepEqual(discarded.refusal, [
    header('CPU limit is'),
    `CPU limit: none (cpu.max is max, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller). ${apply.cpu}`,
    waysOut('cpu', false),
  ]);
  // A one-CPU host's CPU set.
  assert.match(
    decide(layout(t, withSet('0\n', { online: '0\n' }))).refusal[1],
    /^CPU limit: none \(cpu\.max is max, and no CPU set of Uptime Goblin's own limits it: this host has one CPU/
  );
  // An override that names some, not all: only the others refuse, and the way out names both.
  const partly = decide(
    layout(t, { files: { ...shipped, 'memory.max': 'max\n', 'pids.max': 'max\n' } }),
    'pids'
  );
  assert.deepEqual(partly.refusal, [
    header('memory limit is'),
    `Memory limit: none (memory.max is max). ${apply.memory}`,
    waysOut('memory,pids', false),
  ]);
  assert.equal(partly.status.limits.pids.allowed, true);
  assert.equal(partly.status.limits.memory.allowed, false);
});

test('with GOBLIN_ALLOW_UNLIMITED naming them, a supervised start goes on, and says which limits it runs without, and why', t => {
  const runs = (what, words, detail, runaway) =>
    `Uptime Goblin runs without a ${what} limit, as GOBLIN_ALLOW_UNLIMITED allows: ${words} (${detail}). Nothing keeps a runaway collection or a flood of requests ${runaway}; apply the limit once the platform can (docs/installation.md, "Resource limits").`;
  // Missing: each, in the order memory, CPU, processes, whatever order the setting gives.
  const all = decide(
    layout(t, { files: { 'memory.max': 'max\n', 'pids.max': 'max\n', 'cpu.max': 'max 100000\n' } }),
    'pids,cpu,memory'
  );
  assert.equal(all.refusal, null);
  assert.deepEqual(all.warnings, [
    runs('memory', 'none', 'memory.max is max', "from taking all of this host's memory"),
    runs(
      'CPU',
      'none',
      "cpu.max is max, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller",
      "from taking all of this host's CPU time"
    ),
    runs(
      'process',
      'none',
      'pids.max is max',
      'from starting processes until this host can start no more'
    ),
  ]);
  assert.deepEqual(all.status.allowUnlimited, ['memory', 'cpu', 'pids']);
  assert.deepEqual(unenforcedLimits(all.status), ['memory', 'cpu', 'pids']);
  // Unverifiable: the same line, saying it cannot be verified.
  const v1 = decide(layout(t, { controllers: null }), 'memory,cpu,pids');
  assert.equal(v1.refusal, null);
  assert.equal(
    v1.warnings[1],
    runs(
      'CPU',
      'cannot be verified',
      'Uptime Goblin reads its limits under cgroup v2 only, which it did not find here (cgroup v1 or a hybrid layout)',
      "from taking all of this host's CPU time"
    )
  );
  // A name the setting gives needlessly (the limit is in force) is said, so that the setting
  // cannot hide that limit if it is lifted later; the start goes on.
  const needless = decide(
    layout(t, { files: { ...shipped, 'cpu.max': 'max 100000\n' } }),
    'cpu,pids'
  );
  assert.equal(needless.refusal, null);
  assert.deepEqual(needless.warnings, [
    runs(
      'CPU',
      'none',
      "cpu.max is max, and no CPU set of Uptime Goblin's own limits it: Uptime Goblin's cgroup has no cpuset controller",
      "from taking all of this host's CPU time"
    ),
    "GOBLIN_ALLOW_UNLIMITED names pids, but Uptime Goblin's process limit is in force (pids.max 256): remove pids from it, so that it cannot hide that limit if it is lifted later.",
  ]);
  assert.deepEqual(unenforcedLimits(needless.status), ['cpu']);
  // Every limit in force: only the needless line.
  assert.deepEqual(decide(layout(t), 'memory').warnings, [
    "GOBLIN_ALLOW_UNLIMITED names memory, but Uptime Goblin's memory limit is in force (memory.max 1073741824): remove memory from it, so that it cannot hide that limit if it is lifted later.",
  ]);
  assert.deepEqual(unenforcedLimits(decide(layout(t), 'memory').status), []);
});

test('an unsupervised start reads no limit and refuses none, but a malformed GOBLIN_ALLOW_UNLIMITED refuses it too', t => {
  // Every limit missing: unsupervised (npm start, node server.mjs), nothing is checked.
  const paths = layout(t, {
    files: { 'memory.max': 'max\n', 'pids.max': 'max\n', 'cpu.max': 'max 100000\n' },
  });
  for (const allow of [undefined, '', 'cpu'])
    assert.deepEqual(decide(paths, allow, { supervised: false }), {
      refusal: null,
      warnings: [],
      status: { supervised: false },
    });
  assert.throws(
    () => decide(paths, 'all', { supervised: false }),
    error => error.refusal === true && /^GOBLIN_ALLOW_UNLIMITED must list/.test(error.message)
  );
  // A supervised start reads the setting before its limits.
  assert.throws(() => decide(paths, 'cpu,cpu'), /names cpu twice/);
});

test('GOBLIN_ALLOW_UNLIMITED: memory, cpu and pids, comma-separated, each once; every other value refuses, shown escaped', () => {
  for (const [value, list] of [
    [undefined, []],
    [null, []],
    ['', []],
    ['cpu', ['cpu']],
    ['memory', ['memory']],
    ['pids', ['pids']],
    ['pids,memory', ['memory', 'pids']],
    ['cpu,memory,pids', ['memory', 'cpu', 'pids']],
    ['memory,cpu,pids', ['memory', 'cpu', 'pids']],
  ])
    assert.deepEqual(parseAllowUnlimited(value), list, String(value));
  const refused = (value, shown, problem) =>
    assert.throws(
      () => parseAllowUnlimited(value),
      error =>
        error.refusal === true &&
        error.message ===
          `GOBLIN_ALLOW_UNLIMITED must list the limits Uptime Goblin may run without, from memory, cpu and pids, separated by commas, each at most once and without spaces (such as cpu, or memory,cpu); it is ${shown}, ${problem}.`,
      JSON.stringify(value)
    );
  const character = 'which holds a character that is neither a lowercase letter nor a comma';
  // No "all" (a limit added later is never waived unnamed), and nothing else either.
  refused('all', '"all"', 'in which "all" is not one of them');
  refused('memory,swap', '"memory,swap"', 'in which "swap" is not one of them');
  refused('none', '"none"', 'in which "none" is not one of them');
  refused('cpus', '"cpus"', 'in which "cpus" is not one of them');
  refused('processes', '"processes"', 'in which "processes" is not one of them');
  // Another case, spaces, tabs, quotes, other separators.
  for (const value of [
    'ALL',
    'Cpu',
    'CPU',
    ' cpu',
    'cpu ',
    'cpu, pids',
    'cpu\t',
    '"cpu"',
    "'cpu'",
    'cpu;pids',
    'cpu|pids',
    'cpu=1',
    'cpu pids',
    '1',
  ])
    refused(value, JSON.stringify(value), character);
  // Empty entries.
  for (const value of [',', ',cpu', 'cpu,', 'cpu,,pids', ',,'])
    refused(value, JSON.stringify(value), 'which holds an empty entry');
  // Twice.
  refused('cpu,cpu', '"cpu,cpu"', 'which names cpu twice');
  refused('memory,cpu,pids,memory', '"memory,cpu,pids,memory"', 'which names memory twice');
  // Control characters, line breaks and terminal escapes, shown escaped: never raw in the log.
  refused('cpu\n', '"cpu\\n"', character);
  refused('cpu\r\nGOBLIN_FAKE=1', '"cpu\\r\\nGOBLIN_FAKE=1"', character);
  refused('cpu\u001b[2J', '"cpu\\u001b[2J"', character);
  refused('cpu\u0085', '"cpu\\u0085"', character);
  refused('cpu\u2028', '"cpu\\u2028"', character);
  refused('\u202ecpu', '"\\u202ecpu"', character);
  // Look-alike letters and invisible ones: Cyrillic letters, a fullwidth one, a zero-width space.
  refused('\u0441\u0440u', '"\u0441\u0440u"', character);
  refused('\uff43pu', '"\uff43pu"', character);
  refused('cpu\u200b', '"cpu\u200b"', character);
  // Longer than any such list (memory,cpu,pids is 15 characters): cut at 40 when shown, and
  // refused before it is read any further.
  refused(
    'memory,cpu,pids,memory,cpu,pids,m',
    '"memory,cpu,pids,memory,cpu,pids,m"',
    'which is longer than any such list'
  );
  refused(
    'memory,cpu,pids,memory,cpu,pids,',
    '"memory,cpu,pids,memory,cpu,pids,"',
    'which holds an empty entry'
  );
  const huge = `cpu,${'x'.repeat(1_000_000)}`;
  const started = performance.now();
  refused(
    huge,
    `${JSON.stringify(huge.slice(0, 40)).slice(0, -1)}…"`,
    'which is longer than any such list'
  );
  assert.ok(performance.now() - started < 1000);
  // The longest valid list fits.
  assert.deepEqual(parseAllowUnlimited('pids,cpu,memory'), ['memory', 'cpu', 'pids']);
});

test('a FIFO in place of /proc/self/cgroup, a limit file or a CPU set file is never waited on', t => {
  if (spawnSync('mkfifo', ['--help']).error) return t.skip('mkfifo is not available');
  const paths = layout(t, {
    files: { ...noCpuTime, 'cpuset.cpus': '0\n', 'cpuset.cpus.effective': '0\n' },
    controllers: 'cpuset cpu memory pids',
    online: '0-17\n',
  });
  // In a child with a deadline: a blocking open would hang this process, and the test run, for
  // good instead of failing.
  const inChild = () => {
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { readLimits } from ${JSON.stringify(new URL('../lib/resource-limits.mjs', import.meta.url).href)};
         const { limits } = readLimits({ proc: process.argv[1], cgroupRoot: process.argv[2], sys: process.argv[3], platform: 'linux' });
         process.stdout.write(JSON.stringify(Object.fromEntries(Object.entries(limits).map(([k, v]) => [k, v.state]))));`,
        paths.proc,
        paths.cgroupRoot,
        paths.sys,
      ],
      { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' }
    );
    assert.equal(result.signal, null, 'waited on a FIFO');
    return JSON.parse(result.stdout);
  };
  assert.deepEqual(inChild(), { memory: 'enforced', cpu: 'enforced', pids: 'enforced' });
  const fifo = file => {
    fs.rmSync(file, { force: true });
    assert.equal(spawnSync('mkfifo', [file]).status, 0);
  };
  const restore = (file, text) => {
    fs.rmSync(file);
    fs.writeFileSync(file, text);
  };
  // No cgroup it can read: it says so, and goes on.
  const membership = path.join(paths.proc, 'self', 'cgroup');
  fifo(membership);
  assert.deepEqual(inChild(), {
    memory: 'unverifiable',
    cpu: 'unverifiable',
    pids: 'unverifiable',
  });
  restore(membership, '0::/system.slice/uptime-goblin.service\n');
  for (const [file, text, name] of [
    ['memory.max', '1073741824\n', 'memory'],
    ['pids.max', '256\n', 'pids'],
    ['cpuset.cpus', '0\n', 'cpu'],
    ['cpuset.cpus.effective', '0\n', 'cpu'],
  ]) {
    fifo(path.join(paths.directory, file));
    assert.equal(inChild()[name], 'unverifiable', file);
    restore(path.join(paths.directory, file), text);
  }
  const online = path.join(paths.sys, 'devices', 'system', 'cpu', 'online');
  fifo(online);
  assert.equal(inChild().cpu, 'unverifiable', 'online');
  restore(online, '0-17\n');
  // cpu.max as a FIFO, with the CPU set that applies: still enforced, by the set.
  fifo(path.join(paths.directory, 'cpu.max'));
  assert.equal(inChild().cpu, 'enforced');
});

// The swap and core-dump lines are warnings, as before: a start with every limit in force (or
// named in GOBLIN_ALLOW_UNLIMITED) says them, after the lines for the limits it runs without and
// the needless names, and a refusal leaves them out (it says why it does not start). As the kernel
// shows them: /proc/swaps (a header, then the swap areas in use) and the core file size line of
// /proc/self/limits.
const limitsFile = core =>
  `Limit                     Soft Limit           Hard Limit           Units\nMax core file size        ${core}                    ${core}                    bytes\n`;
const swapsInUse = 'Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t1048572\t0\t-2\n';
const noSwapInUse = 'Filename\tType\n';
const swapCannotTell =
  "Uptime Goblin cannot tell whether its memory can be swapped out: this host has swap, but Uptime Goblin cannot read the swap limit of its cgroup (memory.swap.max), which memswap_limit in compose.yaml and MemorySwapMax=0 in the systemd unit set. A kernel without swap accounting has no such limit, and Docker and systemd start Uptime Goblin without it; on a cgroup v1 or hybrid host, or where the container's host does not delegate the memory controller, Uptime Goblin cannot read it. Swapped out, the encryption key and passwords Uptime Goblin holds reach the disk: turn swap off on this host, or encrypt it.";
// A layout with /proc/swaps (`swapAreas`, none when null), the core line (`core`, none when
// undefined) and memory.swap.max (`swapMax`, none when undefined).
const lay = (t, { swapMax, core, swapAreas = swapsInUse, ...host } = {}) => {
  const paths = layout(t, {
    ...host,
    files: {
      ...(host.files ?? shipped),
      ...(swapMax === undefined ? {} : { 'memory.swap.max': swapMax }),
    },
  });
  if (core !== undefined)
    fs.writeFileSync(path.join(paths.proc, 'self', 'limits'), limitsFile(core));
  if (swapAreas !== null) fs.writeFileSync(path.join(paths.proc, 'swaps'), swapAreas);
  return paths;
};

test('swap or core dumps allowed are named at the start: either writes the key and passwords in memory to disk', t => {
  // As compose.yaml and the unit leave them: nothing to say.
  assert.deepEqual(decide(lay(t, { swapMax: '0\n', core: '0' })).warnings, []);
  // A drop-in with MemorySwapMax=infinity and LimitCORE=infinity (the unit's limits kept).
  const both = decide(lay(t, { swapMax: 'max\n', core: 'unlimited' })).warnings;
  assert.equal(both.length, 1);
  assert.match(
    both[0],
    /^Uptime Goblin's memory can be written to disk: swap and core dumps are allowed, /
  );
  assert.match(
    both[0],
    /a drop-in sets MemorySwapMax= and LimitCORE= \(systemctl cat uptime-goblin\.service\)\.$/
  );
  assert.match(
    both[0],
    /an override file or a changed compose\.yaml changes memswap_limit and ulimits core, or docker run was given no --memory-swap equal to --memory and --ulimit core=0\./
  );
  const core = decide(lay(t, { swapMax: '0\n', core: '1024' })).warnings;
  assert.equal(core.length, 1);
  assert.match(core[0], /^Uptime Goblin's memory can be written to disk: core dumps are allowed/);
  // Swap allowed on a host without swap is no risk, and nor is a swap limit it cannot read there
  // (none at all, or one it cannot read: R2 of the B48 consumer review); a kernel without
  // /proc/swaps or the core line tells nothing.
  assert.deepEqual(
    decide(lay(t, { swapMax: 'max\n', core: '0', swapAreas: noSwapInUse })).warnings,
    []
  );
  assert.deepEqual(decide(lay(t, { core: '0', swapAreas: noSwapInUse })).warnings, []);
  const unreadable = lay(t, { core: '0', swapAreas: noSwapInUse });
  fs.mkdirSync(path.join(unreadable.directory, 'memory.swap.max'));
  assert.deepEqual(decide(unreadable).warnings, []);
  assert.deepEqual(decide(lay(t, { core: '0', swapAreas: null })).warnings, []);
  assert.equal(decide(lay(t, { swapMax: 'max\n' })).warnings.length, 1);
  // After the line for a limit it runs without: two lines, in that order.
  const two = decide(
    lay(t, { swapMax: 'max\n', core: '0', files: { ...shipped, 'pids.max': 'max\n' } }),
    'pids'
  ).warnings;
  assert.equal(two.length, 2);
  assert.match(two[0], /^Uptime Goblin runs without a process limit, /);
  assert.match(two[1], /^Uptime Goblin's memory can be written to disk: swap is allowed/);
  // After a needless name too.
  const needless = decide(lay(t, { swapMax: '0\n', core: 'unlimited' }), 'memory').warnings;
  assert.equal(needless.length, 2);
  assert.match(needless[0], /^GOBLIN_ALLOW_UNLIMITED names memory, but /);
  assert.match(
    needless[1],
    /^Uptime Goblin's memory can be written to disk: core dumps are allowed, /
  );
  // A refusal says only why it does not start.
  const refusal = decide(lay(t, { core: 'unlimited', files: { ...shipped, 'pids.max': 'max\n' } }));
  assert.equal(refusal.refusal.length, 3);
  assert.deepEqual(refusal.warnings, []);
});

// A kernel without swap accounting has no memory.swap.max: Docker and systemd start Uptime Goblin without
// the memswap_limit or MemorySwapMax=0 they were given, and its memory can be swapped out. Uptime Goblin
// cannot tell that from a limit it is only kept from reading (cgroup v1, a hybrid layout, no
// memory controller), so on a host with swap it says it cannot tell wherever it cannot read the
// limit.
test('on a host with swap, a swap limit Uptime Goblin cannot read is named: it cannot tell whether its memory can be swapped out', t => {
  // cgroup v2 without swap accounting: the unit's (or compose.yaml's) limits, no memory.swap.max.
  assert.deepEqual(decide(lay(t, { core: '0' })).warnings, [swapCannotTell]);
  // In Docker's own cgroup namespace too.
  assert.deepEqual(decide(lay(t, { core: '0', membership: '0::/\n', cgroup: '/' })).warnings, [
    swapCannotTell,
  ]);
  // An empty memory.swap.max is no limit it can read either, nor is a directory in its place.
  assert.deepEqual(decide(lay(t, { core: '0', swapMax: '\n' })).warnings, [swapCannotTell]);
  const directory = lay(t, { core: '0' });
  fs.mkdirSync(path.join(directory.directory, 'memory.swap.max'));
  assert.deepEqual(decide(directory).warnings, [swapCannotTell]);
  // Core dumps allowed as well: that line, then this one.
  const core = decide(lay(t, { core: 'unlimited' })).warnings;
  assert.equal(core.length, 2);
  assert.match(core[0], /^Uptime Goblin's memory can be written to disk: core dumps are allowed, /);
  assert.equal(core[1], swapCannotTell);
  // A memory controller the LXC's host does not delegate: no memory limit (named in
  // GOBLIN_ALLOW_UNLIMITED here, so Uptime Goblin starts), and no swap limit it can read, even a max one.
  const { 'memory.max': _, ...rest } = shipped;
  for (const swapMax of [undefined, 'max\n']) {
    const undelegated = decide(
      lay(t, { core: '0', swapMax, controllers: 'cpu pids', files: rest }),
      'memory'
    ).warnings;
    assert.equal(undelegated.length, 2);
    assert.match(undelegated[0], /^Uptime Goblin runs without a memory limit, /);
    assert.equal(undelegated[1], swapCannotTell);
  }
  // cgroup v1 or a hybrid layout: no limit it can verify, nor the swap one.
  for (const host of [{ membership: '12:memory:/docker/x\n' }, { controllers: null }]) {
    const lines = decide(lay(t, { core: '0', ...host }), 'memory,cpu,pids').warnings;
    assert.equal(lines.length, 4);
    for (const line of lines.slice(0, 3))
      assert.match(line, /^Uptime Goblin runs without a .* limit, /);
    assert.equal(lines[3], swapCannotTell);
  }
  // Not Linux: no swap or core line.
  assert.deepEqual(
    decide(lay(t, { core: 'unlimited' }), 'memory,cpu,pids', { platform: 'darwin' }).warnings
      .length,
    3
  );
  // A swap limit it can read is said as before: 0 is nothing, max is swap allowed.
  assert.deepEqual(decide(lay(t, { core: '0', swapMax: '0\n' })).warnings, []);
  assert.match(
    decide(lay(t, { core: '0', swapMax: 'max\n' })).warnings[0],
    /^Uptime Goblin's memory can be written to disk: swap is allowed, /
  );
});

// The core file size limit is the process's own (/proc/self/limits), so it is checked whatever
// the cgroup layout: on a cgroup v1 or hybrid host (older Debian and Ubuntu, NAS Docker), a
// LimitCORE=infinity drop-in or docker run without --ulimit core=0 is named too.
test('core dumps allowed are named on a cgroup v1 or hybrid host too', t => {
  for (const host of [
    { membership: '12:memory:/docker/x\n11:pids:/docker/x\n' },
    { controllers: null },
  ]) {
    const paths = lay(t, { ...host, core: 'unlimited', swapAreas: null });
    const found = decide(paths, 'memory,cpu,pids').warnings;
    assert.equal(found.length, 4, JSON.stringify(found));
    assert.match(
      found[3],
      /^Uptime Goblin's memory can be written to disk: core dumps are allowed, /
    );
    // As compose.yaml and the unit leave it: only the limits it runs without.
    fs.writeFileSync(path.join(paths.proc, 'self', 'limits'), limitsFile('0'));
    assert.equal(decide(paths, 'memory,cpu,pids').warnings.length, 3);
  }
});

test('the status /api/system shows is rebuilt from its known fields only', () => {
  assert.deepEqual(limitsStatus(undefined), { supervised: false });
  assert.deepEqual(limitsStatus({ supervised: 'yes', limits: {} }), { supervised: false });
  const shown = limitsStatus({
    supervised: true,
    allowUnlimited: ['cpu', 'all', 'cpu', '<b>'],
    limits: {
      memory: { state: 'enforced', detail: 'memory.max 1', allowed: true, extra: 1 },
      cpu: { state: 'off', detail: 'x'.repeat(1000) },
      pids: null,
    },
    extra: 'dropped',
  });
  assert.deepEqual(shown, {
    supervised: true,
    allowUnlimited: ['cpu'],
    limits: {
      memory: { state: 'enforced', detail: 'memory.max 1', allowed: false },
      cpu: { state: 'unverifiable', detail: 'x'.repeat(400), allowed: true },
      pids: { state: 'unverifiable', detail: '', allowed: false },
    },
  });
  assert.ok(Object.isFrozen(shown) && Object.isFrozen(shown.limits.memory));
  assert.deepEqual(LIMIT_NAMES, ['memory', 'cpu', 'pids']);
});

// A literal screen of deploy/install.sh's text, and no more: the file must hold neither the
// exact old glob (LIMITS_REFUSAL's value between *' and '*) nor, ignoring case, any of the five
// runs of four contiguous words of LIMITS_REFUSAL (its colon dropped). A pattern split across
// strings, assembled from variables, written as a regular expression or with other whitespace,
// wildcards, fewer words or other words is outside what this checks, and a harmless comment
// holding four of those words in a row would fail it. It reads the file as text and runs nothing:
// it does not show that the installer has no way to recognise a refusal, what it prints, that it
// draws no advice from the log, or which start wrote a log line. The installer's behaviour after
// a refused start is for the regressions in test/installer/installer.test.mjs.
test('install.sh text: neither the old LIMITS_REFUSAL glob nor four contiguous words of it', () => {
  const installer = fs.readFileSync(path.join(repository, 'deploy/install.sh'), 'utf8');
  assert.ok(!installer.includes(`*'${LIMITS_REFUSAL}'*`), 'install.sh: no LIMITS_REFUSAL glob');
  const text = installer.toLowerCase();
  const words = LIMITS_REFUSAL.toLowerCase().replace(/:$/, '').split(' ');
  for (let at = 0; at + 4 <= words.length; at++) {
    const run = words.slice(at, at + 4).join(' ');
    assert.ok(!text.includes(run), `install.sh does not hold "${run}"`);
  }
  assert.equal(LIMITS_REFUSAL, 'Uptime Goblin refused to start without its resource limits:');
});

// The systemd unit's Environment=GOBLIN_SUPERVISED=1 is overridden by /etc/uptime-goblin.env, and the
// image's ENV by docker run -e or a Compose override: a 0 there, an empty value or a typo would
// turn the limits check off with no limit named. The unit and the image start Uptime Goblin with
// --supervised, which no environment changes. (Imported here, so that on a tree without these
// exports only these tests fail.)
test('supervision: --supervised wins over any GOBLIN_SUPERVISED; without it GOBLIN_SUPERVISED decides; nothing else is taken', async () => {
  const { SUPERVISED_ARGUMENT, supervision, supervisedSetting } = await import(
    '../lib/resource-limits.mjs'
  );
  assert.equal(SUPERVISED_ARGUMENT, '--supervised');
  const ignored = value =>
    `GOBLIN_SUPERVISED=${JSON.stringify(value)} is ignored: Uptime Goblin was started with --supervised, as the systemd unit and the Docker image start it, which this setting cannot turn off. Uptime Goblin checks its memory, CPU and process limits as always; only GOBLIN_ALLOW_UNLIMITED lets it start without one of them (docs/installation.md, "Resource limits"). Remove the setting.`;
  for (const [argv, value, supervised, warned] of [
    [['--supervised'], undefined, true, false],
    [['--supervised'], '', true, false],
    [['--supervised'], '1', true, false],
    [['--supervised'], 'on', true, false],
    [['--supervised'], '0', true, true],
    [['--supervised'], 'off', true, true],
    [['--supervised'], 'False', true, true],
    [['--supervised'], 'NO', true, true],
    [[], undefined, false, false],
    [[], '', false, false],
    [[], '0', false, false],
    [[], '1', true, false],
    [[], 'Yes', true, false],
  ])
    assert.deepEqual(
      supervision({ argv, env: value === undefined ? {} : { GOBLIN_SUPERVISED: value } }),
      { supervised, warnings: warned ? [ignored(value)] : [] },
      `${argv} ${value}`
    );
  // Any other GOBLIN_SUPERVISED refuses, with or without the argument, shown escaped and cut.
  for (const value of [
    'maybe',
    ' 1',
    '0 ',
    '"1"',
    '2',
    'true\n',
    '1\r\nGOBLIN_FAKE=1',
    '\u001b[2Jon',
    '\u202eon',
    'o\u200bn',
    '\uff4f\uff4e',
    'x'.repeat(100000),
  ]) {
    for (const argv of [[], ['--supervised']])
      assert.throws(
        () => supervision({ argv, env: { GOBLIN_SUPERVISED: value } }),
        error =>
          error.refusal === true &&
          error.message.startsWith(
            'GOBLIN_SUPERVISED must be 1 or 0 (true, yes or on; false, no or off), or empty; it is "'
          ) &&
          !/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(
            error.message
          ) &&
          error.message.length < 200,
        JSON.stringify(value).slice(0, 40)
      );
    assert.throws(() => supervisedSetting(value), { refusal: true });
  }
  assert.equal(supervisedSetting(undefined), null);
  assert.equal(supervisedSetting(''), null);
  assert.equal(supervisedSetting('TRUE'), true);
  assert.equal(supervisedSetting('off'), false);
  // Arguments: none, or exactly one --supervised. A misspelt one would otherwise start unchecked.
  for (const argv of [
    ['--supervise'],
    ['--supervised=1'],
    ['--SUPERVISED'],
    ['--supervised '],
    ['\u2014supervised'],
    ['--supervised', '--supervised'],
    ['--supervised', ''],
    [''],
    ['\u001b]0;title\u0007'],
    ['x'.repeat(10000)],
    Array.from({ length: 1000 }, () => 'a'),
  ])
    assert.throws(
      () => supervision({ argv, env: { GOBLIN_SUPERVISED: '1' } }),
      error =>
        error.refusal === true &&
        /^server\.mjs takes no argument but --supervised, which the systemd unit and the Docker image give it; it was given "/.test(
          error.message
        ) &&
        !/[\u0000-\u001f\u007f-\u009f]/.test(error.message) &&
        error.message.length < 400,
      JSON.stringify(argv).slice(0, 40)
    );
});
