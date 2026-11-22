// Memory admission (roadmap §2.3, IR-18). One process-wide budget keeps a 1 GB host safe: work
// that can hold a lot of memory at once (a collection reading up to 32-64 MiB, a backup's
// 128 MiB scrypt, restore staging, a raw export) reserves its worst case first and waits while
// the budget is spent. Waiters are admitted in arrival order, so a large reservation is never
// starved by a stream of small ones. A reservation larger than the whole budget is clamped to
// it: it then runs alone instead of never running.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const MiB = 1024 * 1024;
// cgroup v1 writes "no limit" as LONG_MAX rounded down to a page; v2 writes "max".
const UNLIMITED = 2 ** 62;

export class BudgetConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BudgetConfigError';
    // server.mjs treats `refusal` as "exit 78 with this message" (invalid configuration).
    this.refusal = true;
  }
}

export class BudgetTimeoutError extends Error {
  constructor(label, bytes, timeoutMs) {
    super(
      `Waited ${Math.round(timeoutMs / 1000)} s for ${Math.ceil(bytes / MiB)} MiB of working memory${label ? ` (${label})` : ''}; try again later.`
    );
    this.name = 'BudgetTimeoutError';
    this.code = 'GOBLIN_BUDGET_TIMEOUT';
  }
}

/**
 * The lowest memory limit (bytes) of the cgroups this process is in: its own and each parent up
 * to the root it can see, from `memory.max` and `memory.high` (cgroup v2) or
 * `memory.limit_in_bytes` and `memory.soft_limit_in_bytes` (v1). 0 when none is set or none can
 * be read. process.constrainedMemory() (libuv) reads only the process's own cgroup: Uptime Goblin's
 * systemd unit runs in a child cgroup (system.slice/uptime-goblin.service) that has no limit of its own,
 * so in a memory-limited LXC or container its "max" would hide the limit on a parent. The
 * argument names the two places read, for tests: {proc: '/proc/self/cgroup', mount:
 * '/sys/fs/cgroup'}.
 */
export function cgroupMemoryLimit({ proc = '/proc/self/cgroup', mount = '/sys/fs/cgroup' } = {}) {
  let lines;
  try {
    lines = fs.readFileSync(proc, 'utf8').split('\n');
  } catch {
    return 0;
  }
  // v1 (or hybrid, where the memory controller stays on v1): "<id>:<controllers>:<path>".
  const v1 = lines.find(line => line.split(':')[1]?.split(',').includes('memory'));
  const v2 = lines.find(line => line.startsWith('0::'));
  const [base, own, files] = v1
    ? [
        path.join(mount, 'memory'),
        v1.split(':').slice(2).join(':'),
        ['memory.limit_in_bytes', 'memory.soft_limit_in_bytes'],
      ]
    : v2
      ? [mount, v2.slice(3), ['memory.max', 'memory.high']]
      : [];
  // A path outside this cgroup namespace ("/../..") names no cgroup visible here.
  if (!base || !own.startsWith('/') || own.split('/').includes('..')) return 0;
  const segments = own.split('/').filter(Boolean);
  let lowest = 0;
  for (let depth = segments.length; depth >= 0; depth--)
    for (const file of files) {
      let text;
      try {
        text = fs.readFileSync(path.join(base, ...segments.slice(0, depth), file), 'utf8').trim();
      } catch {
        continue; // not mounted here, or the root of the hierarchy (it has no limit files)
      }
      const bytes = /^\d+$/.test(text) ? Number(text) : 0; // "max" is no limit
      if (bytes > 0 && bytes < UNLIMITED && (!lowest || bytes < lowest)) lowest = bytes;
    }
  return lowest;
}

// The smaller of two limits, either of which may be 0 (none) or not a number.
const tighter = (a, b) => {
  const set = [a, b].filter(value => Number.isFinite(value) && value > 0);
  return set.length ? Math.min(...set) : 0;
};

/**
 * The budget in bytes: GOBLIN_COLLECTION_MEMORY_MB when set (16-1,048,576 MiB), otherwise 25 % of
 * the memory limit or of total memory, whichever is lower (256 MiB on a 1 GB LXC), and never
 * below 16 MiB. The limit is the lower of process.constrainedMemory() and the lowest limit of
 * the process's cgroups, its own or a parent's (cgroupMemoryLimit(cgroupFiles)).
 */
export function defaultBudgetBytes({
  env = process.env,
  cgroupFiles,
  constrained = tighter(process.constrainedMemory?.() ?? 0, cgroupMemoryLimit(cgroupFiles)),
  total = os.totalmem(),
} = {}) {
  const raw = env.GOBLIN_COLLECTION_MEMORY_MB;
  if (raw !== undefined && raw !== '') {
    const mb = Number(raw);
    if (!/^\d+$/.test(String(raw).trim()) || !Number.isSafeInteger(mb) || mb < 16 || mb > 1048576)
      throw new BudgetConfigError(
        'GOBLIN_COLLECTION_MEMORY_MB must be a whole number of MiB from 16 to 1048576.'
      );
    return { bytes: mb * MiB, source: 'GOBLIN_COLLECTION_MEMORY_MB' };
  }
  // Node reports 0 (or a huge number) when no cgroup limit applies.
  const limited = Number.isFinite(constrained) && constrained > 0 && constrained < total;
  const base = limited ? constrained : total;
  return {
    bytes: Math.max(16 * MiB, Math.floor(base / 4)),
    source: limited ? 'cgroup' : 'total',
  };
}

const abortReason = signal =>
  signal.reason ??
  Object.assign(new Error('The reservation was cancelled.'), { name: 'AbortError' });

/**
 * new MemoryBudget({totalBytes, clock}) with
 * - reserve(bytes, {label, serial, signal, timeoutMs}) -> Promise<lease>
 * - tryReserve(bytes, {label, serial}) -> lease | null (never jumps the queue)
 * - resize(totalBytes), status()
 * A lease is {bytes, label, release()} and also releases through `using` (Symbol.dispose).
 * Reservations sharing a `serial` key run one at a time (for example 'scrypt').
 */
export class MemoryBudget {
  #total;
  #used = 0;
  #leases = new Set();
  #waiting = [];
  #serials = new Map();
  #clock;
  #stats = { admitted: 0, waited: 0, timedOut: 0, cancelled: 0, clamped: 0, peakBytes: 0 };

  constructor({
    totalBytes = defaultBudgetBytes().bytes,
    clock = {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: handle => clearTimeout(handle),
    },
  } = {}) {
    this.#total = MemoryBudget.#validTotal(totalBytes);
    this.#clock = clock;
  }

  static #validTotal(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 1)
      throw new TypeError('totalBytes must be a positive whole number');
    return bytes;
  }

  #weight(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0)
      throw new TypeError('A reservation must be 0 or more bytes');
    const whole = Math.ceil(bytes);
    if (whole > this.#total) this.#stats.clamped++;
    return Math.min(whole, this.#total);
  }

  get totalBytes() {
    return this.#total;
  }
  get usedBytes() {
    return this.#used;
  }
  get availableBytes() {
    return Math.max(0, this.#total - this.#used);
  }

  #fits(bytes, serial) {
    return this.#used + bytes <= this.#total && !(serial && this.#serials.get(serial));
  }

  #grant(bytes, label, serial) {
    this.#used += bytes;
    this.#stats.admitted++;
    this.#stats.peakBytes = Math.max(this.#stats.peakBytes, this.#used);
    if (serial) this.#serials.set(serial, (this.#serials.get(serial) ?? 0) + 1);
    let released = false;
    const lease = {
      bytes,
      label,
      serial: serial ?? null,
      release: () => {
        if (released) return;
        released = true;
        this.#leases.delete(lease);
        this.#used -= bytes;
        if (serial) {
          const held = this.#serials.get(serial) - 1;
          if (held > 0) this.#serials.set(serial, held);
          else this.#serials.delete(serial);
        }
        this.#pump();
      },
      [Symbol.dispose]() {
        this.release();
      },
    };
    this.#leases.add(lease);
    return lease;
  }

  // Admits waiters in order. A waiter that does not fit stops the scan (first come, first
  // served); one held back only by its serial key is skipped, since its turn depends on another
  // reservation of the same kind rather than on free memory.
  #pump() {
    for (let i = 0; i < this.#waiting.length; ) {
      const waiter = this.#waiting[i];
      if (waiter.serial && this.#serials.get(waiter.serial)) {
        i++;
        continue;
      }
      if (!this.#fits(waiter.bytes, null)) break;
      this.#waiting.splice(i, 1);
      waiter.admit(this.#grant(waiter.bytes, waiter.label, waiter.serial));
    }
  }

  // True when a waiter is held back by memory (not only by its serial key): newcomers queue
  // behind it. #pump() runs on every change, so such a waiter does not fit right now.
  #queueBlocked() {
    return this.#waiting.some(waiter => !(waiter.serial && this.#serials.get(waiter.serial)));
  }

  tryReserve(bytes, { label = '', serial } = {}) {
    const weight = this.#weight(bytes);
    if (this.#queueBlocked() || !this.#fits(weight, serial)) return null;
    return this.#grant(weight, label, serial);
  }

  reserve(bytes, { label = '', serial, signal, timeoutMs } = {}) {
    const weight = this.#weight(bytes);
    if (signal?.aborted) return Promise.reject(abortReason(signal));
    if (!this.#queueBlocked() && this.#fits(weight, serial))
      return Promise.resolve(this.#grant(weight, label, serial));
    this.#stats.waited++;
    return new Promise((resolve, reject) => {
      let timer = null;
      const waiter = {
        bytes: weight,
        label,
        serial,
        admit: lease => {
          cleanup();
          resolve(lease);
        },
      };
      const leave = error => {
        const index = this.#waiting.indexOf(waiter);
        if (index < 0) return;
        this.#waiting.splice(index, 1);
        cleanup();
        reject(error);
        // Someone smaller behind a departed head may fit now.
        this.#pump();
      };
      const onAbort = () => {
        this.#stats.cancelled++;
        leave(abortReason(signal));
      };
      const cleanup = () => {
        if (timer !== null) this.#clock.clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      if (Number.isFinite(timeoutMs))
        timer = this.#clock.setTimeout(() => {
          this.#stats.timedOut++;
          leave(new BudgetTimeoutError(label, weight, timeoutMs));
        }, timeoutMs);
      this.#waiting.push(waiter);
    });
  }

  /** Changes the budget. Leases already granted keep their memory; waiters are re-examined. */
  resize(totalBytes) {
    this.#total = MemoryBudget.#validTotal(totalBytes);
    for (const waiter of this.#waiting) waiter.bytes = Math.min(waiter.bytes, this.#total);
    this.#pump();
  }

  status() {
    const byLabel = {};
    for (const lease of this.#leases)
      byLabel[lease.label || 'other'] = (byLabel[lease.label || 'other'] ?? 0) + lease.bytes;
    return {
      totalBytes: this.#total,
      usedBytes: this.#used,
      availableBytes: this.availableBytes,
      leases: this.#leases.size,
      waiting: this.#waiting.length,
      waitingBytes: this.#waiting.reduce((sum, waiter) => sum + waiter.bytes, 0),
      byLabel,
      ...this.#stats,
    };
  }
}
