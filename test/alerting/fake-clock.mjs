// A controllable clock for the job runner and the delivery modules (not a test file itself).
// `burn(ms)` moves time forward synchronously, as busy code would, without firing timers;
// `advance(ms)` moves time forward and runs every timer that falls due, in order, letting
// promise callbacks and I/O settle between them; `step(ms)` moves only the wall clock (an NTP
// correction, a restored VM), as the system clock does while monotonic time goes on.
export const settle = async (turns = 10) => {
  for (let i = 0; i < turns; i++) await new Promise(resolve => setImmediate(resolve));
};

export function fakeClock({ start = 1000, wallStart = 1_800_000_000_000 } = {}) {
  let now = start,
    sequence = 0,
    offset = 0;
  const timers = new Set();
  const due = limit => {
    let next = null;
    for (const timer of timers)
      if (
        timer.at <= limit &&
        (!next || timer.at < next.at || (timer.at === next.at && timer.seq < next.seq))
      )
        next = timer;
    return next;
  };
  const clock = {
    now: () => now,
    wall: () => wallStart + (now - start) + offset,
    step(ms) {
      offset += ms;
    },
    setTimeout(fn, ms) {
      const timer = { at: now + Math.max(0, Number(ms) || 0), fn, seq: ++sequence };
      timers.add(timer);
      return timer;
    },
    clearTimeout(timer) {
      timers.delete(timer);
    },
    burn(ms) {
      now += ms;
    },
    get pending() {
      return timers.size;
    },
    nextAt() {
      return due(Infinity)?.at ?? null;
    },
    async advance(ms = 0) {
      const target = now + ms;
      for (;;) {
        await settle();
        const timer = due(target);
        if (!timer) break;
        timers.delete(timer);
        now = Math.max(now, timer.at);
        timer.fn();
      }
      now = Math.max(now, target);
      await settle();
    },
  };
  return clock;
}

export const quietLogger = () => {
  const lines = { error: [], warn: [], info: [] };
  return {
    lines,
    error: (...args) => lines.error.push(args.join(' ')),
    warn: (...args) => lines.warn.push(args.join(' ')),
    info: (...args) => lines.info.push(args.join(' ')),
  };
};
