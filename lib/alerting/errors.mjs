// The errors of the delivery routes and service (delivery spec §6.6, Phase 0; texts verbatim, but
// the signing ones name the signing key since the webhook moved to public keys, 2026-11-12, and
// reveal_rate_limited went with the reveal). A DeliveryError carries its HTTP status, a stable
// code and a message written for the admin; the pipeline answers it as {error, code}, with Retry-After
// on a 429 or 503.
//
//   throw deliveryError('channel_paused', {name: 'Webhook', reason: 'The webhook answered 401.'});
//   throw deliveryError('delivery_not_retryable', {variant: 'sending'});
//   throw deliveryError('signing_unavailable', {retryAfter: 60});

export class DeliveryError extends Error {
  constructor(status, code, message, { retryAfter } = {}) {
    super(message);
    this.name = 'DeliveryError';
    this.status = status;
    this.code = code;
    if (Number.isFinite(retryAfter) && retryAfter >= 0) this.retryAfter = Math.ceil(retryAfter);
  }
  /** The answer's body. */
  get body() {
    return { error: this.message, code: this.code };
  }
}

// A reason or detail placed inside a sentence: one line, and ending where the template expects.
const sentence = text => {
  const value = String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  return !value || /[.!?]$/.test(value) ? value : `${value}.`;
};
const clause = text =>
  String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[.]+$/, '');

const notRetryable = {
  sending: 'This notification is being sent right now.',
  waiting: 'This notification has not had its first attempt yet.',
  finished: 'Only failed notifications and notifications waiting to retry can be retried.',
  // What the send-time recheck (D24) would skip: Retry would only say it sends it again.
  source_deleted: 'The source of this notification was deleted, so Uptime Goblin does not send it.',
  switched_off:
    'Alerts of this kind are switched off, so Uptime Goblin does not send this notification.',
  // A member of an email digest, which is retried as a whole: another notification in it.
  digest_source_deleted:
    'This notification was sent in one email with another whose source was deleted, so Uptime Goblin does not send that email again.',
  digest_switched_off:
    'This notification was sent in one email with another of a kind of alert that is switched off, so Uptime Goblin does not send that email again.',
  // Another notification of the digest is being sent, waits for its first attempt or has
  // finished (cancelled when its source was deleted, say), whatever this one's own state.
  digest_other:
    'This notification was sent in one email with another that cannot be retried now, so Retry cannot send that email again.',
};

// delivery_outdated: the row itself, or (`digest`) another notification of its email digest,
// whose alert's later notification was delivered or is being sent.
const outdated = {
  own: 'A later notification for the same alert was already delivered or is being sent on this channel, so sending this one now would arrive out of order.',
  digest:
    'This notification was sent in one email with another whose alert already had a later notification delivered or being sent on this channel, so sending that email again would arrive out of order.',
};

// Retry on a channel that is not set up (amendment A45): the row would only be skipped when sent.
const notSetUp = {
  'env-webhook':
    'Webhook is not set up, so Uptime Goblin cannot send this notification: set GOBLIN_WEBHOOK_URL on the Uptime Goblin server and restart Uptime Goblin.',
  email:
    'Email is not set up, so Uptime Goblin cannot send this notification: complete the email settings under Configure → Email.',
  'email-off':
    'Email alerts are switched off, so Uptime Goblin cannot send this notification: switch them on under Configure → Email.',
  ntfy: 'ntfy is not set up, so Uptime Goblin cannot send this notification: save a server and topic under Configure → Notifications.',
  'ntfy-off':
    'ntfy notifications are switched off, so Uptime Goblin cannot send this notification: switch them on under Configure → Notifications.',
  gotify:
    'Gotify is not set up, so Uptime Goblin cannot send this notification: save a server and application token under Configure → Notifications.',
  'gotify-off':
    'Gotify notifications are switched off, so Uptime Goblin cannot send this notification: switch them on under Configure → Notifications.',
  // A test of a channel that is not set up: there is nothing to test with.
  'ntfy-test': 'Save an ntfy server and topic before sending a test notification.',
  'gotify-test': 'Save a Gotify server and application token before sending a test notification.',
};

/** code → [status, message(options), default Retry-After in seconds]. */
export const DELIVERY_ERRORS = Object.freeze({
  invalid_request: [
    400,
    ({ detail, reason }) => `This request is not valid: ${clause(detail ?? reason)}.`,
  ],
  delivery_not_found: [
    404,
    () => "That notification is no longer in Uptime Goblin's delivery history.",
  ],
  delivery_not_retryable: [409, ({ variant }) => notRetryable[variant] ?? notRetryable.finished],
  delivery_outdated: [409, ({ variant } = {}) => outdated[variant] ?? outdated.own],
  channel_paused: [
    409,
    ({ name, reason }) =>
      `${name ?? 'These'} notifications are paused: ${sentence(reason)} Resume the channel to send them.`,
  ],
  channel_unknown: [404, () => 'There is no notification channel with that name.'],
  channel_not_set_up: [
    409,
    ({ variant }) =>
      notSetUp[variant] ??
      "This notification's channel is not set up, so Uptime Goblin cannot send this notification.",
  ],
  webhook_not_configured: [
    404,
    () =>
      'The alert webhook is not set up: set GOBLIN_WEBHOOK_URL on the Uptime Goblin server and restart Uptime Goblin.',
  ],
  signing_unavailable: [
    503,
    () =>
      'The webhook signing key cannot be read right now. Uptime Goblin replaces it at its next start if the encryption key changed.',
    60,
  ],
  signing_compatibility: [
    409,
    () =>
      'A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.',
  ],
  signing_conflict: [
    409,
    () => 'The signing key was just replaced elsewhere. Reload to see the current one.',
  ],
  channel_settings_invalid: [
    400,
    ({ detail }) => `These settings were not saved: ${sentence(detail)}`,
  ],
  channel_settings_conflict: [
    409,
    () => 'These settings were changed elsewhere meanwhile. Reload to see the current ones.',
  ],
  channel_settings_newer: [
    409,
    () =>
      'A newer Uptime Goblin saved these settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.',
  ],
  channel_settings_unavailable: [
    503,
    () =>
      'Uptime Goblin cannot seal secrets right now (its encryption key is not open), so these settings were not saved.',
    60,
  ],
  test_rate_limited: [
    429,
    () => 'Please wait 30 seconds between test notifications on one channel.',
    30,
  ],
  delivery_status_unavailable: [
    503,
    () => 'Delivery status is unavailable: Uptime Goblin could not read its control database.',
    15,
  ],
  storage_full: [
    503,
    () =>
      "Uptime Goblin's disk is full, so this change was not saved. Free some space on the Uptime Goblin host, then try again. Sign-in and alert delivery keep working on space Uptime Goblin keeps in reserve.",
    60,
  ],
});

/**
 * The DeliveryError of `code`. Options: variant (delivery_not_retryable: sending, waiting,
 * finished, source_deleted, switched_off, digest_source_deleted, digest_switched_off or
 * digest_other; delivery_outdated: digest; channel_not_set_up: env-webhook, email, email-off,
 * ntfy, ntfy-off, ntfy-test, gotify, gotify-off or gotify-test), name and reason
 * (channel_paused), detail or reason (invalid_request, channel_settings_invalid), and
 * retryAfter in seconds (429 and 503; each has a default).
 */
export function deliveryError(code, { variant, name, reason, detail, retryAfter } = {}) {
  const entry = DELIVERY_ERRORS[code];
  if (!entry) throw new TypeError(`Unknown delivery error ${code}`);
  const [status, message, defaultRetryAfter] = entry;
  return new DeliveryError(status, code, message({ variant, name, reason, detail }), {
    retryAfter: status === 429 || status === 503 ? (retryAfter ?? defaultRetryAfter) : undefined,
  });
}
