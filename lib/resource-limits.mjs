// compose.yaml and deploy/uptime-goblin.service limit Uptime Goblin's memory, processes and CPU time, so that a
// runaway collection or a flood of requests cannot take the whole host. Both set the limits on
// Uptime Goblin's cgroup, and neither Docker nor systemd says a word when one does not apply: an override
// file can set one of compose.yaml's to 0, which Docker reads as "no limit" (as it reads a
// negative pids_limit), a drop-in can set MemoryMax=infinity, an LXC whose host does not delegate
// a controller leaves the unit's limit without effect, and Docker discards a CPU set it cannot
// apply with only a warning ("… Cpuset discarded."). So a supervised Uptime Goblin (the systemd unit and
// the image start it with --supervised, which the environment file cannot take away: supervision)
// reads its own cgroup's limits back at every start and refuses to start (exit status 78) unless
// each of the three is confirmed in force or named in GOBLIN_ALLOW_UNLIMITED, which an operator
// sets on a platform that cannot apply it (superviseLimits). server.mjs makes this check in its
// main block, after its modules have loaded and the launch setup has run, and before createApp():
// before the start sequence takes goblin.lock or reads Uptime Goblin's data. What the modules do as they
// load is outside this check, and nothing here says that no file was read or written before it.
// A limit counts only where Uptime Goblin reads it applied: memory.max and pids.max finite, cpu.max a
// quota, or else a CPU set of Uptime Goblin's own cgroup that names only CPUs the host has online, not
// all, the CPUs it runs on all among them (cpuSet). It reads them under Linux cgroup v2 only;
// elsewhere (cgroup v1, a hybrid layout, not Linux) none of them can be confirmed. Unsupervised
// (npm start, node server.mjs, the tests' createApp) no limit is read, but a malformed
// GOBLIN_ALLOW_UNLIMITED still refuses the start. Every path, the platform, the environment and the
// arguments can be given, so the decision can be checked over a fake /proc, cgroup tree and /sys.
import fs from 'node:fs';
import path from 'node:path';
import { flagValue, quoted } from './environment.mjs';

const refusal = message => Object.assign(new Error(message), { refusal: true });

/**
 * The one argument server.mjs takes. The systemd unit (ExecStart=) and the Docker image (CMD)
 * give it, besides GOBLIN_SUPERVISED=1, which a hand-written unit or another service manager may
 * set alone.
 */
export const SUPERVISED_ARGUMENT = '--supervised';

/**
 * GOBLIN_SUPERVISED as a start reads it: true (1, true, yes, on), false (0, false, no, off) or null
 * (unset or empty), any case. Any other value throws a refusal (exit status 78), shown escaped:
 * the setting turns a security check on, so a typo is not taken for off. The native installer
 * checks /etc/uptime-goblin.env with it before an upgrade stops the running Uptime Goblin.
 */
export function supervisedSetting(text) {
  const value = flagValue(text);
  if (value === undefined)
    throw refusal(
      `GOBLIN_SUPERVISED must be 1 or 0 (true, yes or on; false, no or off), or empty; it is ${quoted(text)}.`
    );
  return value;
}

/**
 * Whether this `node server.mjs` start is supervised, and the start lines that go with it:
 * {supervised, warnings}. `argv` is what follows server.mjs on its command line. The command line
 * decides first, because the environment file cannot change it: systemd lets /etc/uptime-goblin.env
 * override the unit's Environment=, and docker run -e or a Compose override the image's ENV, so
 * GOBLIN_SUPERVISED=0 there (or an empty value, or a typo) would turn off the limits check and the
 * exit status rule without naming a limit. With --supervised, GOBLIN_SUPERVISED cannot turn
 * supervision off: a value that says no is said at the start and changes nothing, and only
 * GOBLIN_ALLOW_UNLIMITED, limit by limit, lets Uptime Goblin start without one. Without it, Uptime Goblin is
 * supervised when GOBLIN_SUPERVISED says yes. Throws a refusal for any argument other than one
 * --supervised (a misspelt one would otherwise start unchecked), and for a GOBLIN_SUPERVISED that
 * is neither yes nor no (supervisedSetting), each shown escaped and cut.
 */
export function supervision({ argv = process.argv.slice(2), env = process.env } = {}) {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== SUPERVISED_ARGUMENT))
    throw refusal(
      `server.mjs takes no argument but ${SUPERVISED_ARGUMENT}, which the systemd unit and the Docker image give it; it was given ${argv
        .slice(0, 4)
        .map(arg => quoted(arg))
        .join(', ')}${argv.length > 4 ? ` and ${argv.length - 4} more` : ''}.`
    );
  const flagged = argv.length === 1;
  const setting = supervisedSetting(env.GOBLIN_SUPERVISED);
  return {
    supervised: flagged || setting === true,
    warnings:
      flagged && setting === false
        ? [
            `GOBLIN_SUPERVISED=${quoted(env.GOBLIN_SUPERVISED)} is ignored: Uptime Goblin was started with ${SUPERVISED_ARGUMENT}, as the systemd unit and the Docker image start it, which this setting cannot turn off. Uptime Goblin checks its memory, CPU and process limits as always; only GOBLIN_ALLOW_UNLIMITED lets it start without one of them (docs/installation.md, "Resource limits"). Remove the setting.`,
          ]
        : [],
  };
}

/** /proc/self/cgroup and a cgroup's limit files hold a line or two; anything longer is not one. */
const fileLimit = 4096;

/**
 * The text of a small kernel file, or null when it is missing, not a regular file, longer than
 * fileLimit or unreadable. Opened without waiting on a FIFO, then read from that descriptor.
 */
function readSmallFile(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    if (!fs.fstatSync(descriptor).isFile()) return null;
    // Kernel files report size 0, so read until the end (or one byte past the limit).
    const buffer = Buffer.alloc(fileLimit + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    return length > fileLimit ? null : buffer.toString('utf8', 0, length);
  } catch {
    return null;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

/** The three limits, in the order every message names them. */
export const LIMIT_NAMES = Object.freeze(['memory', 'cpu', 'pids']);

/**
 * The first words of a refusal for want of a limit, as an operator reads them in the service's
 * log. The native installer (deploy/install.sh) shows that log after a failed start as it is:
 * it neither looks for these words nor tells which start wrote a line.
 */
export const LIMITS_REFUSAL = 'Uptime Goblin refused to start without its resource limits:';

// Each limit: its name in a sentence (`limit`) and as a line's label, what a runaway could do,
// and how to apply it on each platform (docs/installation.md, "Resource limits", has the steps).
const limitTexts = {
  memory: {
    limit: 'memory limit',
    label: 'Memory limit',
    runaway: "from taking all of this host's memory",
    apply:
      'Under Docker, give mem_limit in compose.yaml or compose.override.yaml (docker run --memory); under systemd, MemoryMax= in uptime-goblin.service or a drop-in (systemctl cat uptime-goblin.service shows them; MemoryMax=infinity lifts it); in an LXC, its host must delegate the memory controller to the container.',
  },
  cpu: {
    limit: 'CPU limit',
    label: 'CPU limit',
    runaway: "from taking all of this host's CPU time",
    apply:
      "Under Docker, give cpus in compose.yaml or compose.override.yaml (docker run --cpus), or, where the kernel cannot limit CPU time, a CPU set (cpuset: '0') that Docker applies; under systemd, CPUQuota= in uptime-goblin.service or a drop-in (an empty CPUQuota= lifts it); in an LXC, its host must delegate the cpu controller to the container.",
  },
  pids: {
    limit: 'process limit',
    label: 'Process limit',
    runaway: 'from starting processes until this host can start no more',
    apply:
      'Under Docker, give pids_limit in compose.yaml or compose.override.yaml (docker run --pids-limit); under systemd, TasksMax= in uptime-goblin.service or a drop-in (TasksMax=infinity lifts it); in an LXC, its host must delegate the pids controller to the container.',
  },
};

/** "a", "a and b", "a, b and c". */
const listed = items =>
  items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;

// The most memory a limit may give: 2^52 bytes (4 PiB), all the physical memory x86-64 and arm64
// can address, so a larger memory.max limits nothing (cgroup v1 and an unlimited container show
// a number near 2^63 instead of `max`).
const memoryMost = 2n ** 52n;

// A CPU list as printed: at most 64 characters of the validated list (digits, commas, hyphens).
const shownList = list => (list.length > 64 ? `${list.slice(0, 64)}…` : list);

/**
 * The CPUs a kernel CPU list names ("0-3,8,10-11", as cpuset.cpus, cpuset.cpus.effective and
 * /sys/devices/system/cpu/online give them, with a line end), as ranges [first, last] in order,
 * those that touch joined ("0-1,2-3" gives [[0, 3]]), or null for any other text: empty, a range
 * that runs backwards, CPUs out of order or named twice, a number of more than 7 digits. Ranges,
 * not a set of numbers: a 4096-byte file can name millions of CPUs.
 */
function cpuRanges(text) {
  const list = text?.trim();
  if (!list || !/^\d{1,7}(?:-\d{1,7})?(?:,\d{1,7}(?:-\d{1,7})?)*$/.test(list)) return null;
  const ranges = [];
  let next = 0;
  for (const range of list.split(',')) {
    const [first, last = first] = range.split('-').map(Number);
    if (first < next || last < first) return null;
    if (ranges.length && first === next) ranges.at(-1)[1] = last;
    else ranges.push([first, last]);
    next = last + 1;
  }
  return ranges;
}

/** How many CPUs `ranges` (cpuRanges) name. */
const cpuCount = ranges => ranges.reduce((sum, [first, last]) => sum + last - first + 1, 0);

/** Whether every CPU of `inner` is one of `outer` (both cpuRanges, in order). */
function within(inner, outer) {
  let k = 0;
  for (const [first, last] of inner) {
    while (k < outer.length && outer[k][1] < first) k++;
    if (k === outer.length || outer[k][0] > first || outer[k][1] < last) return false;
  }
  return true;
}

/** Whether some CPU of `a` is one of `b` (both cpuRanges, in order). */
function meets(a, b) {
  let k = 0;
  for (const [first, last] of a) {
    while (k < b.length && b[k][1] < first) k++;
    if (k < b.length && b[k][0] <= last) return true;
  }
  return false;
}

/**
 * Where Docker cannot limit CPU time (a kernel without CPU bandwidth control: "NanoCPUs can not be
 * set …"), compose.override.yaml gives cpus: 0 with cpuset: '0': Uptime Goblin then runs on the host's
 * CPU 0 alone, at most one CPU's time. So where its CPU time has no limit, a CPU set is its CPU
 * limit, and only when all of these hold (maintainer decision D21, PU5): Uptime Goblin's own cgroup sets one
 * (cpuset.cpus, which Compose's cpuset, docker run --cpuset-cpus and systemd's AllowedCPUs= write;
 * empty when none was set or Docker discarded it) that is not empty, reads as a CPU list and
 * names only CPUs the host has online (`sys`/devices/system/cpu/online); the CPUs Uptime Goblin actually
 * gets (cpuset.cpus.effective) are not empty, read as a CPU list, and are all among those of its
 * own set; and both its own set and the effective one hold fewer CPUs than the host has online.
 * So each is some, not all, of the CPUs online: a count alone says nothing of which CPUs a set
 * names (independent review F-01). Each of these fails closed:
 *   - a set Uptime Goblin only inherits (its own cpuset.cpus empty) is no limit of its own: Docker in a
 *     container or LXC that a CPU set holds to some CPUs gives a container with no cpuset of its
 *     own only those CPUs, which must not be taken for the CPU limit Docker was not given;
 *   - a set Uptime Goblin asks for but does not get is none either: where the cgroup around Uptime Goblin's can
 *     grant none of the CPUs it names, the kernel gives Uptime Goblin's cgroup the CPUs of that cgroup
 *     instead, which bound the whole group, not Uptime Goblin within it;
 *   - a set of every online CPU limits nothing, and on a one-CPU host the sole CPU is every CPU;
 *   - a set that names a CPU the host does not have online cannot be verified: that CPU is
 *     offline, does not exist, or is one this process cannot see in /sys (LXCFS can hide the
 *     host's CPUs from an LXC), so what Uptime Goblin reads of the set does not tell what it holds it to;
 *   - a file that is missing, unreadable, empty where a list is needed, or not a CPU list leaves
 *     the set unverifiable.
 * A set that names exactly the CPUs the cgroup around it has (Docker held to CPUs 1-2, cpuset
 * '1-2') is Uptime Goblin's own, and counts. "The host" is what this process sees in /sys: inside an LXC
 * that is the container's view, which LXCFS can narrow; that, Docker in LXC, hot-plugged CPUs and
 * rootless Docker are not qualified here. Returns {limit: true, detail} for such a limit,
 * {limit: false, why} for none, {limit: false, unsure: true, why} for a set that names CPUs the
 * host does not have online, and {unread} with the files it cannot read as CPU lists.
 */
function cpuSet(directory, available, sys) {
  if (!available.has('cpuset'))
    return { limit: false, why: "Uptime Goblin's cgroup has no cpuset controller" };
  const own = readSmallFile(path.join(directory, 'cpuset.cpus'))?.trim();
  const effective = readSmallFile(path.join(directory, 'cpuset.cpus.effective'))?.trim();
  const online = readSmallFile(path.join(sys, 'devices', 'system', 'cpu', 'online'))?.trim();
  // An empty cpuset.cpus is no CPU set of Uptime Goblin's own; any other text must be a CPU list.
  const ownRanges = own === '' ? [] : cpuRanges(own),
    effectiveRanges = cpuRanges(effective),
    hostRanges = cpuRanges(online);
  const unread = [
    ...(ownRanges === null ? ['cpuset.cpus'] : []),
    ...(effectiveRanges === null ? ['cpuset.cpus.effective'] : []),
    ...(hostRanges === null ? ['/sys/devices/system/cpu/online'] : []),
  ];
  if (unread.length) return { unread };
  const ownCount = cpuCount(ownRanges),
    count = cpuCount(effectiveRanges),
    hostCount = cpuCount(hostRanges);
  const no = why => ({ limit: false, why });
  // The first of these that holds is why the set does not count. Each compares which CPUs the
  // sets name (within, meets), never only how many.
  if (hostCount === 1)
    return no(`this host has one CPU (online ${shownList(online)}), so a CPU set is all of it`);
  if (ownCount === 0)
    return no(
      `Uptime Goblin's cgroup sets none of its own (cpuset.cpus is empty), so it may run on every CPU it is given (cpuset.cpus.effective ${shownList(effective)}, online ${shownList(online)})`
    );
  if (within(hostRanges, ownRanges))
    return no(
      `the one Uptime Goblin's cgroup sets holds every CPU this host has online (cpuset.cpus ${shownList(own)}, online ${shownList(online)})`
    );
  if (within(hostRanges, effectiveRanges))
    return no(
      `Uptime Goblin may run on every CPU this host has online (cpuset.cpus.effective ${shownList(effective)}, online ${shownList(online)})`
    );
  if (!within(effectiveRanges, ownRanges))
    return no(
      `the CPUs Uptime Goblin runs on are not all among those its cgroup sets (cpuset.cpus ${shownList(own)}, cpuset.cpus.effective ${shownList(effective)}): the kernel gives a cgroup the CPUs of the one around it when it can grant none of those it asks for, which limits that whole group, not Uptime Goblin within it`
    );
  if (!within(ownRanges, hostRanges)) {
    const which = meets(ownRanges, hostRanges)
      ? 'CPUs this host does not have online besides some it has'
      : 'only CPUs this host does not have online';
    return {
      limit: false,
      unsure: true,
      why: `the one Uptime Goblin's cgroup sets names ${which} (cpuset.cpus ${shownList(own)}, cpuset.cpus.effective ${shownList(effective)}, online ${shownList(online)}): CPUs that are offline, that do not exist, or that this process cannot see in /sys (as under LXCFS), so Uptime Goblin cannot tell what that set holds it to`,
    };
  }
  // Its own set is some, not all, of the CPUs online, and the CPUs it runs on are all among them,
  // so they are fewer than the host's too.
  return {
    limit: true,
    detail: `cpuset.cpus ${shownList(own)}, cpuset.cpus.effective ${shownList(effective)}: ${count} of this host's ${hostCount} CPUs`,
  };
}

const enforced = detail => ({ state: 'enforced', detail });
const missing = detail => ({ state: 'missing', detail });
const unverifiable = detail => ({ state: 'unverifiable', detail });

/** memory.max: a whole number of bytes from 0 to 2^52 is a limit; `max` or more is none. */
function memoryLimit(directory, available) {
  if (!available.has('memory'))
    return missing(
      "Uptime Goblin's cgroup has no memory controller, so no memory limit can apply to it"
    );
  const text = readSmallFile(path.join(directory, 'memory.max'))?.trim();
  if (text === 'max') return missing('memory.max is max');
  if (text === undefined || !/^\d{1,20}$/.test(text))
    return unverifiable('Uptime Goblin cannot read memory.max of its cgroup as a limit');
  if (BigInt(text) > memoryMost)
    return missing(`memory.max is ${text}, more than 2^52 bytes, which limits nothing`);
  return enforced(`memory.max ${text}`);
}

/** pids.max: a whole number is a limit; `max` is none. */
function pidsLimit(directory, available) {
  if (!available.has('pids'))
    return missing(
      "Uptime Goblin's cgroup has no pids controller, so no process limit can apply to it"
    );
  const text = readSmallFile(path.join(directory, 'pids.max'))?.trim();
  if (text === 'max') return missing('pids.max is max');
  if (text === undefined || !/^\d{1,20}$/.test(text))
    return unverifiable('Uptime Goblin cannot read pids.max of its cgroup as a limit');
  return enforced(`pids.max ${text}`);
}

/**
 * The CPU limit: cpu.max `<quota> <period>`, both above 0, whatever the CPU set; where there is no
 * quota (cpu.max `max`, no cpu controller) or it cannot be read (no cpu.max: a kernel without CPU
 * bandwidth control), a CPU set of Uptime Goblin's own (cpuSet). Neither: missing where both are known to
 * be absent, unverifiable where either could not be read or the CPU set names CPUs the host does
 * not have online.
 */
function cpuLimit(directory, available, sys) {
  let time, timeKnown;
  if (!available.has('cpu')) {
    time = "Uptime Goblin's cgroup has no cpu controller";
    timeKnown = true;
  } else {
    const text = readSmallFile(path.join(directory, 'cpu.max'))?.trim();
    const match = text === undefined ? null : /^(max|\d{1,19}) (\d{1,19})$/.exec(text);
    if (match && match[1] !== 'max' && BigInt(match[1]) > 0n && BigInt(match[2]) > 0n) {
      const cpus = Number((Number(match[1]) / Number(match[2])).toFixed(2));
      return enforced(`cpu.max ${match[1]} ${match[2]}: ${cpus} CPU${cpus === 1 ? '' : 's'}`);
    }
    timeKnown = Boolean(match && match[1] === 'max' && BigInt(match[2]) > 0n);
    time = timeKnown
      ? 'cpu.max is max'
      : text === undefined
        ? "Uptime Goblin's cgroup has the cpu controller but no cpu.max it can read (a kernel without CPU bandwidth control has none)"
        : 'Uptime Goblin cannot read cpu.max of its cgroup as a limit';
  }
  const set = cpuSet(directory, available, sys);
  if (set.limit) return enforced(set.detail);
  if (set.unread)
    return unverifiable(
      `${time}, and Uptime Goblin cannot read ${listed(set.unread)} to tell whether a CPU set limits it instead`
    );
  if (set.unsure)
    return unverifiable(
      `${time}, and Uptime Goblin cannot tell whether a CPU set limits it instead: ${set.why}`
    );
  const detail = `${time}, and no CPU set of Uptime Goblin's own limits it: ${set.why}`;
  return timeKnown ? missing(detail) : unverifiable(detail);
}

/**
 * What lets Uptime Goblin's memory reach the disk, though compose.yaml and the systemd unit turn it off:
 * swap (memory.swap.max not 0, while the host has swap) and core dumps (a core file size limit
 * other than 0). Either would write the encryption key and passwords held in memory to disk,
 * and a drop-in (MemorySwapMax=infinity, LimitCORE=infinity) or a changed compose.yaml lifts
 * them without a word. The core limit is the process's own (/proc/self/limits), so it is checked
 * whatever the cgroup layout; nothing when it cannot be read. The swap limit is read only from
 * Uptime Goblin's cgroup v2 `directory` (null without one) with its memory controller. On a host with
 * swap, a swap limit Uptime Goblin cannot read is said in a line of its own, since it cannot tell: a
 * kernel without swap accounting has no memory.swap.max, and Docker and systemd start Uptime Goblin
 * without the limit they were given (memswap_limit, MemorySwapMax=0), while its memory can be
 * swapped out; under cgroup v1, a hybrid layout or no memory controller, Uptime Goblin does not read it.
 * These are warnings: Uptime Goblin starts with them (superviseLimits says them after the lines for the
 * limits it runs without), and a refusal leaves them out.
 */
function toDisk(proc, directory, available) {
  const found = [];
  const swapMax =
    directory !== null && available.has('memory')
      ? readSmallFile(path.join(directory, 'memory.swap.max'))?.trim()
      : undefined;
  // /proc/swaps: a header line, then one line per swap area in use.
  const swapAreas = readSmallFile(path.join(proc, 'swaps'))
    ?.split('\n')
    .slice(1)
    .filter(line => line.trim()).length;
  const unknownSwap =
    swapAreas > 0 && !swapMax
      ? [
          "Uptime Goblin cannot tell whether its memory can be swapped out: this host has swap, but Uptime Goblin cannot read the swap limit of its cgroup (memory.swap.max), which memswap_limit in compose.yaml and MemorySwapMax=0 in the systemd unit set. A kernel without swap accounting has no such limit, and Docker and systemd start Uptime Goblin without it; on a cgroup v1 or hybrid host, or where the container's host does not delegate the memory controller, Uptime Goblin cannot read it. Swapped out, the encryption key and passwords Uptime Goblin holds reach the disk: turn swap off on this host, or encrypt it.",
        ]
      : [];
  if (swapMax && swapMax !== '0' && swapAreas > 0)
    found.push({
      what: 'swap',
      compose: 'memswap_limit',
      run: '--memory-swap equal to --memory',
      unit: 'MemorySwapMax=',
    });
  const core = readSmallFile(path.join(proc, 'self', 'limits'))
    ?.split('\n')
    .find(line => line.startsWith('Max core file size'))
    ?.slice('Max core file size'.length)
    .trim()
    .split(/\s+/)[0];
  if (core !== undefined && core !== '0')
    found.push({
      what: 'core dumps',
      compose: 'ulimits core',
      run: '--ulimit core=0',
      unit: 'LimitCORE=',
    });
  if (!found.length) return unknownSwap;
  const each = key => listed(found.map(item => item[key]));
  return [
    `Uptime Goblin's memory can be written to disk: ${each('what')} ${found.length === 1 && found[0].what === 'swap' ? 'is' : 'are'} allowed, which compose.yaml and the systemd unit turn off so that the encryption key and passwords Uptime Goblin holds never reach the disk. Under Docker, an override file or a changed compose.yaml changes ${each('compose')}, or docker run was given no ${each('run')}. Under systemd, a drop-in sets ${each('unit')} (systemctl cat uptime-goblin.service).`,
    ...unknownSwap,
  ];
}

/**
 * The state of each limit in Uptime Goblin's own cgroup ({memory, cpu, pids}, each {state, detail}:
 * 'enforced', 'missing' or 'unverifiable'), and the swap and core-dump warnings (toDisk). Under
 * cgroup v2 a process belongs to one cgroup, the "0::<path>" line of /proc/self/cgroup, relative
 * to the root of its cgroup namespace (Docker's container, or the LXC), which is what is mounted
 * at `cgroupRoot`. Every cgroup v2 directory lists the controllers that can limit it: one that is
 * not there has no file to set, so its limit cannot apply. A hybrid host has the "0::" line, but
 * its cgroup2 file system is not the one mounted there: no cgroup.controllers. `proc`,
 * `cgroupRoot` and `sys` are where /proc, the cgroup2 file system and /sys are mounted. Not Linux
 * (npm start on a Mac): nothing is read, and every limit is unverifiable.
 */
export function readLimits({
  proc = '/proc',
  cgroupRoot = '/sys/fs/cgroup',
  sys = '/sys',
  platform = process.platform,
} = {}) {
  const all = detail => Object.fromEntries(LIMIT_NAMES.map(name => [name, unverifiable(detail)]));
  if (platform !== 'linux')
    return {
      limits: all(
        `Uptime Goblin reads its limits from Linux cgroups, and this system is ${/^[a-z0-9]{1,16}$/.test(platform) ? platform : 'not Linux'}`
      ),
      toDisk: [],
    };
  const own = readSmallFile(path.join(proc, 'self', 'cgroup'))
    ?.split('\n')
    .find(line => line.startsWith('0::'))
    ?.slice(3);
  const directory =
    own?.startsWith('/') && !own.split('/').includes('..') ? path.join(cgroupRoot, own) : null;
  const controllers =
    directory === null ? null : readSmallFile(path.join(directory, 'cgroup.controllers'));
  if (controllers === null)
    return {
      limits: all(
        'Uptime Goblin reads its limits under cgroup v2 only, which it did not find here (cgroup v1 or a hybrid layout)'
      ),
      toDisk: toDisk(proc, null, new Set()),
    };
  const available = new Set(controllers.trim().split(/\s+/));
  return {
    limits: {
      memory: memoryLimit(directory, available),
      cpu: cpuLimit(directory, available, sys),
      pids: pidsLimit(directory, available),
    },
    toDisk: toDisk(proc, directory, available),
  };
}

/** Longer than any list of the three names (memory,cpu,pids has 15 characters). */
const allowMaxLength = 32;

/**
 * GOBLIN_ALLOW_UNLIMITED: the limits an operator lets Uptime Goblin run without, where the platform cannot
 * apply them, as a list of LIMIT_NAMES in that order. Unset or empty: none. Otherwise exactly
 * memory, cpu and pids separated by commas, each at most once, in lower case and without spaces;
 * anything else refuses the start (exit status 78), the value shown escaped and cut: a space,
 * another case, a look-alike letter, a control character or an empty entry could otherwise be
 * read as a name by one reader and not by another. There is no `all`: a limit added later is
 * never waived without someone naming it.
 */
export function parseAllowUnlimited(text) {
  if (text === undefined || text === null || text === '') return [];
  const value = String(text);
  const refuse = problem => {
    throw refusal(
      `GOBLIN_ALLOW_UNLIMITED must list the limits Uptime Goblin may run without, from memory, cpu and pids, separated by commas, each at most once and without spaces (such as cpu, or memory,cpu); it is ${quoted(value)}, ${problem}.`
    );
  };
  if (value.length > allowMaxLength) refuse('which is longer than any such list');
  if (/[^a-z,]/.test(value))
    refuse('which holds a character that is neither a lowercase letter nor a comma');
  const entries = value.split(',');
  if (entries.includes('')) refuse('which holds an empty entry');
  const unknown = entries.find(entry => !LIMIT_NAMES.includes(entry));
  if (unknown !== undefined) refuse(`in which ${quoted(unknown)} is not one of them`);
  const twice = entries.find((entry, index) => entries.indexOf(entry) !== index);
  if (twice !== undefined) refuse(`which names ${twice} twice`);
  return LIMIT_NAMES.filter(name => entries.includes(name));
}

/** What a line says of a limit that is not enforced: none, or cannot be verified. */
const stateWords = limit => (limit.state === 'missing' ? 'none' : 'cannot be verified');

/** The GOBLIN_ALLOW_UNLIMITED value that would let a refused start go on. */
const allowSetting = (refused, allowUnlimited) =>
  LIMIT_NAMES.filter(name => refused.includes(name) || allowUnlimited.includes(name)).join(',');

/** A refusal's line for each limit it names: the state, why, and how to apply it. */
const refusalLine = (name, limit) =>
  `${limitTexts[name].label}: ${stateWords(limit)} (${limit.detail}). ${limitTexts[name].apply}`;

/**
 * The start's decision (docs/installation.md, "Resource limits"). `env` gives
 * GOBLIN_ALLOW_UNLIMITED, which is checked whether or not Uptime Goblin is `supervised` (a malformed value
 * throws a refusal before any limit is read); only a supervised start reads its limits
 * (readLimits, whose path and platform options it passes on). Returns {refusal, warnings, status}:
 * `refusal`, the lines of a refusal (null to start), when a limit is neither enforced nor named in
 * GOBLIN_ALLOW_UNLIMITED; `warnings`, the start lines otherwise, in this order: each limit Uptime Goblin
 * runs without (memory, CPU, processes), each name the setting gives needlessly, then the swap and
 * core-dump lines (toDisk); `status`, frozen, for /api/system and the audit: {supervised: false},
 * or {supervised: true, allowUnlimited, limits: {memory, cpu, pids}}, each limit {state, detail,
 * allowed}.
 */
export function superviseLimits({ env = process.env, supervised = false, ...paths } = {}) {
  const allowUnlimited = parseAllowUnlimited(env.GOBLIN_ALLOW_UNLIMITED);
  if (!supervised)
    return { refusal: null, warnings: [], status: Object.freeze({ supervised: false }) };
  const read = readLimits(paths);
  const limits = Object.fromEntries(
    LIMIT_NAMES.map(name => [
      name,
      Object.freeze({ ...read.limits[name], allowed: allowUnlimited.includes(name) }),
    ])
  );
  const status = Object.freeze({
    supervised: true,
    allowUnlimited: Object.freeze([...allowUnlimited]),
    limits: Object.freeze(limits),
  });
  const notEnforced = LIMIT_NAMES.filter(name => limits[name].state !== 'enforced');
  const refused = notEnforced.filter(name => !limits[name].allowed);
  if (refused.length) {
    const names = refused.map(name => limitTexts[name].limit.replace(/ limit$/, ''));
    const setting = allowSetting(refused, allowUnlimited);
    return {
      refusal: [
        `${LIMITS_REFUSAL} under a service manager (started with --supervised or GOBLIN_SUPERVISED=1) it starts only where its own cgroup holds its memory, CPU time and processes to a limit, and here its ${listed(names)} limit${refused.length > 1 ? 's are' : ' is'} not in force.`,
        ...refused.map(name => refusalLine(name, limits[name])),
        `To start Uptime Goblin, apply each limit named above (docs/installation.md, "Resource limits", has the steps for Docker, systemd and LXC hosts), or, on a platform that cannot apply ${refused.length > 1 ? 'them' : 'it'}, set GOBLIN_ALLOW_UNLIMITED=${setting} in Uptime Goblin's environment (/etc/uptime-goblin.env for the systemd unit, .env for Docker Compose): Uptime Goblin then starts without ${setting.includes(',') ? 'those limits' : 'that limit'} and says so at every start.`,
      ],
      warnings: [],
      status,
    };
  }
  return {
    refusal: null,
    warnings: [
      ...notEnforced.map(
        name =>
          `Uptime Goblin runs without a ${limitTexts[name].limit}, as GOBLIN_ALLOW_UNLIMITED allows: ${stateWords(limits[name])} (${limits[name].detail}). Nothing keeps a runaway collection or a flood of requests ${limitTexts[name].runaway}; apply the limit once the platform can (docs/installation.md, "Resource limits").`
      ),
      ...LIMIT_NAMES.filter(name => limits[name].state === 'enforced' && limits[name].allowed).map(
        name =>
          `GOBLIN_ALLOW_UNLIMITED names ${name}, but Uptime Goblin's ${limitTexts[name].limit} is in force (${limits[name].detail}): remove ${name} from it, so that it cannot hide that limit if it is lifted later.`
      ),
      ...read.toDisk,
    ],
    status,
  };
}

/**
 * `status` (superviseLimits's) as /api/system shows it, rebuilt from its known fields only: a
 * frozen {supervised: false}, or {supervised: true, allowUnlimited, limits} with each of the three
 * limits {state, detail (at most 400 characters), allowed}. Read-only: no route sets it.
 */
export function limitsStatus(status) {
  if (status?.supervised !== true) return Object.freeze({ supervised: false });
  const given = Array.isArray(status.allowUnlimited) ? status.allowUnlimited : [];
  const allowUnlimited = LIMIT_NAMES.filter(name => given.includes(name));
  const states = ['enforced', 'missing', 'unverifiable'];
  const limits = Object.fromEntries(
    LIMIT_NAMES.map(name => {
      const limit = status.limits?.[name];
      return [
        name,
        Object.freeze({
          state: states.includes(limit?.state) ? limit.state : 'unverifiable',
          detail: typeof limit?.detail === 'string' ? limit.detail.slice(0, 400) : '',
          allowed: allowUnlimited.includes(name),
        }),
      ];
    })
  );
  return Object.freeze({
    supervised: true,
    allowUnlimited: Object.freeze(allowUnlimited),
    limits: Object.freeze(limits),
  });
}

/** The limits Uptime Goblin runs without under GOBLIN_ALLOW_UNLIMITED (status above): for the audit. */
export function unenforcedLimits(status) {
  if (status?.supervised !== true || !status.limits) return [];
  return LIMIT_NAMES.filter(
    name => status.limits[name]?.state !== 'enforced' && status.limits[name]?.allowed === true
  );
}
