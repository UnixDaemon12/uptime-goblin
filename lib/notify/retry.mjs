// Retry, backoff and dead-letter policy for the outbox (alerting design §2.7, decision C16).
// - Backoff after attempt n: min(15 min, 30 s × 2^(n−1)) × U(0.5, 1).
// - A server's Retry-After (seconds, a decimal such as Discord's, or an HTTP date) wins when it
//   asks for longer, up to 1 hour.
// - A row older than its maximum age (24 h by default, 1-168 h) becomes a dead letter.
// - After 5 consecutive failures a channel's circuit opens for 60 s × 2^k (up to 15 min); the
//   next send is a single probe.

export const DELIVERY_POLICY = Object.freeze({
  baseMs: 30 * 1000,
  capMs: 15 * 60 * 1000,
  retryAfterCapMs: 60 * 60 * 1000,
  maxAgeMs: 24 * 60 * 60 * 1000,
  leaseMs: 60 * 1000,
  circuitAfter: 5,
  circuitBaseMs: 60 * 1000,
  circuitCapMs: 15 * 60 * 1000,
});

/** Milliseconds to wait after attempt `attempt` (1 = the first send failed). */
export function backoffMs(attempt, { rng = Math.random, baseMs, capMs } = {}) {
  baseMs ??= DELIVERY_POLICY.baseMs;
  capMs ??= DELIVERY_POLICY.capMs;
  const n = Math.max(1, Math.floor(Number(attempt) || 1));
  const ceiling = Math.min(capMs, baseMs * 2 ** Math.min(n - 1, 40));
  const u = Math.min(1, Math.max(0, Number(rng()) || 0));
  return Math.round(ceiling * (0.5 + 0.5 * u));
}

/**
 * Retry-After as milliseconds, or null when absent or unusable. A number is taken as seconds
 * (Telegram's retry_after, Discord's float retry_after); text is delta-seconds or an HTTP date.
 */
export function parseRetryAfter(value, nowMs = Date.now()) {
  if (value === undefined || value === null) return null;
  if (typeof value === 'number')
    return Number.isFinite(value) && value >= 0 ? Math.round(value * 1000) : null;
  const text = String(Array.isArray(value) ? value[0] : value).trim();
  if (/^\d{1,10}(?:\.\d{1,6})?$/.test(text)) return Math.round(Number(text) * 1000);
  // HTTP-date (IMF-fixdate, and the obsolete forms Date.parse understands).
  if (/^[A-Za-z]{3},? /.test(text)) {
    const at = Date.parse(text);
    if (Number.isFinite(at)) return Math.max(0, at - nowMs);
  }
  return null;
}

/** The wait before the next attempt: the backoff, or Retry-After when longer (capped). */
export function retryDelayMs({ attempt, afterMs = null, rng = Math.random, policy = {} } = {}) {
  const p = { ...DELIVERY_POLICY, ...policy };
  const backoff = backoffMs(attempt, { rng, baseMs: p.baseMs, capMs: p.capMs });
  if (!Number.isFinite(afterMs) || afterMs === null) return backoff;
  return Math.max(backoff, Math.min(Math.max(0, afterMs), p.retryAfterCapMs));
}

/** How long a channel's circuit stays open after `failures` consecutive failures (0 = closed). */
export function circuitDelayMs(failures, policy = {}) {
  const p = { ...DELIVERY_POLICY, ...policy };
  if (!(failures >= p.circuitAfter)) return 0;
  return Math.min(p.circuitCapMs, p.circuitBaseMs * 2 ** Math.min(failures - p.circuitAfter, 40));
}

/** Validates the maxAgeHours setting (1-168, default 24) and returns milliseconds. */
export function maxAgeMs(hours = 24) {
  if (!Number.isInteger(hours) || hours < 1 || hours > 168)
    throw new RangeError('maxAgeHours must be a whole number of hours from 1 to 168');
  return hours * 60 * 60 * 1000;
}
