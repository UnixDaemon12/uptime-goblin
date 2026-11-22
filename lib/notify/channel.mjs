// The channel interface (contract C-JOB). A channel delivers one message and says what happened;
// it never retries, waits or records anything itself, because the outbox owns all of that:
//
//   channel = {
//     name,                                   // the channel id, e.g. 'email' or 'env-webhook'
//     send(message, {signal}) -> Promise<outcome>,
//     digest?: {windowMs, maxFactor},         // batch rows like 1.4.2's email (60 s quiet, 3× cap)
//     concurrency?: 1..4,                     // sends in flight for this channel (default 1)
//     unknown?: {resendAfterMs, maxResends},  // what to do when acceptance is unknown
//     maxAgeMs?,                              // rows older than this become dead (default 24 h)
//   }
//
//   message = {uid, channelId, target, kind, attempt, digest, events: [snapshot, ...]}
//   (one event, or several for a digest; `uid` is stable across retries of the same delivery)
//
// Outcomes: accepted, retry(afterMs), failed(reason) as in C-JOB, plus unknown (the request may
// have been accepted: a timeout after sending), pause (the channel is misconfigured, for example
// 401/403/404 or EAUTH: hold its rows) and skipped (nothing to do, for example email alerts are
// switched off). A pause is `transient` when its cause may clear by itself (a 404 while a proxy
// restarts, a certificate being renewed): the outbox then lets one probe through every 15
// minutes. Any other pause waits for a fix, Resume, or the probe at the next start.

export const OUTCOME_TYPES = Object.freeze([
  'accepted',
  'retry',
  'failed',
  'unknown',
  'pause',
  'skipped',
]);

const CHANNEL_ID = /^[a-z0-9][a-z0-9_-]{0,39}$/;

/**
 * One line, at most 300 characters, and never a URL (webhook URLs and paths carry secrets).
 * Well-formed, so the outbox stores it (an unpaired surrogate, from the text or from a cut
 * between the halves of a pair, is refused at bind) and as U+FFFD instead.
 */
export function safeReason(text) {
  return String(text ?? '')
    .replace(/[\p{Cc}\p{Zl}\p{Zp}\p{Cf}]/gu, ' ')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, '[url]')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300)
    .toWellFormed();
}

// A reference the receiving service gave (a message ID): kept as given, but storable, since a
// NUL or an unpaired surrogate is refused at bind.
const storableReference = value =>
  String(value).slice(0, 200).toWellFormed().replaceAll('\u0000', '');

const httpStatus = value =>
  Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;

export const accepted = ({ status = null, externalRef = null } = {}) => ({
  type: 'accepted',
  status: httpStatus(status),
  externalRef: externalRef === null ? null : storableReference(externalRef),
});
export const retry = (
  afterMs = null,
  reason = 'Delivery failed; it will be retried.',
  { status } = {}
) => ({
  type: 'retry',
  afterMs: Number.isFinite(afterMs) && afterMs >= 0 ? Math.round(afterMs) : null,
  reason: safeReason(reason),
  status: httpStatus(status),
});
export const failed = (reason, { status } = {}) => ({
  type: 'failed',
  reason: safeReason(reason),
  status: httpStatus(status),
});
export const unknown = (reason, { status } = {}) => ({
  type: 'unknown',
  reason: safeReason(reason),
  status: httpStatus(status),
});
export const pause = (reason, { status, transient = false } = {}) => ({
  type: 'pause',
  reason: safeReason(reason),
  status: httpStatus(status),
  transient: transient === true,
});
export const skipped = reason => ({ type: 'skipped', reason: safeReason(reason), status: null });

/** Whatever a channel returned, as a valid outcome. Anything else is a retry, never a success. */
export function normaliseOutcome(value) {
  switch (value?.type) {
    case 'accepted':
      return accepted(value);
    case 'retry':
      return retry(value.afterMs, value.reason || undefined, value);
    case 'failed':
      return failed(value.reason || 'The channel refused the message.', value);
    case 'unknown':
      return unknown(value.reason || 'Delivery acceptance is unknown.', value);
    case 'pause':
      return pause(value.reason || 'The channel needs attention.', value);
    case 'skipped':
      return skipped(value.reason || 'Nothing to send.');
    default:
      return retry(null, 'The channel returned an invalid result.');
  }
}

/** Validates a channel object and returns it with defaults filled in. */
export function defineChannel(channel) {
  if (!channel || !CHANNEL_ID.test(channel.name ?? ''))
    throw new TypeError(`A channel needs a name matching ${CHANNEL_ID}`);
  if (typeof channel.send !== 'function')
    throw new TypeError(`Channel ${channel.name} needs a send(message, {signal}) function`);
  const concurrency = channel.concurrency ?? 1;
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4)
    throw new TypeError(`Channel ${channel.name}: concurrency must be 1-4`);
  if (channel.digest) {
    const { windowMs, maxFactor = 3 } = channel.digest;
    if (!(windowMs > 0) || !(maxFactor >= 1))
      throw new TypeError(`Channel ${channel.name}: digest needs windowMs > 0 and maxFactor >= 1`);
  }
  if (channel.unknown) {
    const { resendAfterMs, maxResends } = channel.unknown;
    if (!(resendAfterMs >= 0) || !(Number.isInteger(maxResends) && maxResends >= 0))
      throw new TypeError(`Channel ${channel.name}: unknown needs resendAfterMs and maxResends`);
  }
  if (channel.maxAgeMs !== undefined && !(channel.maxAgeMs > 0))
    throw new TypeError(`Channel ${channel.name}: maxAgeMs must be above 0`);
  return Object.freeze({ ...channel, concurrency });
}
