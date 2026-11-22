// How much of the event loop one wall display's history reads may take (DOS-1). A history
// answer is built synchronously (a node:sqlite query, then JSON), and a 30-day one costs from
// about 75 ms to a few hundred on a small host, so a stolen display cookie that keeps asking for
// one on every connection it may hold slows every other request, /health included. Each display
// session therefore has a budget of milliseconds: an answer is built while the budget is above
// zero and then costs what it took (at least 1 ms), the budget refills at a fixed rate up to its
// burst, and while it is spent the request is answered 429 with Retry-After. A display's page asks
// for one chart at a time, at most every 15 seconds, which stays far inside it.

/** The defaults: up to 2 s of work at once, then 100 ms per second (a tenth of the loop). */
export const historyBudgetDefaults = Object.freeze({ burstMs: 2000, refillPerSecond: 100 });

/**
 * A budget per key (a display session's scope). `now` is monotonic milliseconds; tests may pass
 * their own burst and rate. Returns {run(key, work)}: runs `work` and returns {value} while the
 * key's budget is above zero, else {retryAfter} (whole seconds until it is) without running it.
 */
export function historyBudget({
  burstMs = historyBudgetDefaults.burstMs,
  refillPerSecond = historyBudgetDefaults.refillPerSecond,
  now = () => performance.now(),
  maxKeys = 1024,
} = {}) {
  const budgets = new Map();
  const level = (entry, at) =>
    Math.min(burstMs, entry.tokens + ((at - entry.at) / 1000) * refillPerSecond);
  return {
    run(key, work) {
      const at = now();
      const entry = budgets.get(key) ?? { tokens: burstMs, at };
      const tokens = level(entry, at);
      if (tokens <= 0)
        return {
          retryAfter: Math.max(1, Math.ceil((-tokens + 1) / Math.max(refillPerSecond, 1e-9))),
        };
      const started = performance.now();
      try {
        return { value: work() };
      } finally {
        const cost = Math.max(1, performance.now() - started);
        budgets.delete(key);
        budgets.set(key, { tokens: tokens - cost, at });
        // Sessions are few, but their keys are not kept for ever: a full budget is forgotten.
        if (budgets.size > maxKeys)
          for (const [other, value] of budgets)
            if (other !== key && level(value, at) >= burstMs) budgets.delete(other);
      }
    },
  };
}
