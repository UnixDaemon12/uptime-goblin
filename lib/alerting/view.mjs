// What the delivery routes and the dashboard show (delivery spec §6.5), as pure functions of
// outbox rows and channel status. Nothing here ever returns a URL, a secret, a rendered request
// or a response body: a row's snapshot holds 1.4.2's event fields only, and the webhook's host
// name is the one part of GOBLIN_WEBHOOK_URL that is shown (for ntfy and Gotify, the server's
// host name: never its path, the topic, a token or a password).
import { initialChannelStatus } from '../notify/outbox.mjs';
import { emailConfigured } from '../mail.mjs';
import { ntfySetup } from '../notify/channels/ntfy.mjs';
import { gotifySetup } from '../notify/channels/gotify.mjs';

export const BUILT_IN_CHANNELS = Object.freeze(['email', 'env-webhook', 'ntfy', 'gotify']);
export const CHANNEL_NAMES = Object.freeze({
  email: 'Email',
  'env-webhook': 'Webhook',
  ntfy: 'ntfy',
  gotify: 'Gotify',
});
export const channelName = id => CHANNEL_NAMES[id] ?? id;

const DAY = 24 * 60 * 60 * 1000;
const FINISHED_STATUS = Object.freeze({
  delivered: 'delivered',
  superseded: 'replaced',
  skipped: 'skipped',
  stale: 'not-sent',
  cancelled: 'not-sent',
});
const DEAD_STATUS = Object.freeze({ failed: 'failed', expired: 'expired', unknown: 'unconfirmed' });

/** A channel status with every field present (a channel that never sent has no row yet). */
export const fullStatus = status => ({ ...initialChannelStatus(), ...(status ?? {}) });

/**
 * Paused: the channel's own state, or a pause that no accepted or refused answer has ended yet
 * (a probe in progress, or a probe answered with a retry). Retry and the views use the same rule,
 * so a channel the page shows as paused never accepts a retry.
 */
export const isPaused = status => status?.state === 'paused' || status?.pausedSince != null;

/** The Delivery `status` of a row (§6.5): what happened to it, in the page's words. */
export function deliveryStatus(row) {
  switch (row.state) {
    case 'queued':
      return row.attempts > 0 ? 'retrying' : 'waiting';
    case 'sending':
      return 'sending';
    case 'held':
      return 'paused';
    case 'dead':
      return DEAD_STATUS[row.deadReason] ?? 'failed';
    default:
      // A state this release does not know (written by a newer one) was not sent by this one.
      return FINISHED_STATUS[row.state] ?? 'not-sent';
  }
}

const text = value => (typeof value === 'string' ? value : null);
const time = value => (Number.isFinite(value) ? value : null);

/** The alert a row notifies about, from its snapshot (1.4.2's event fields). */
export function alertOf(row) {
  const event = row.event && typeof row.event === 'object' ? row.event : {};
  return {
    service: text(event.service),
    name: text(event.name) ?? text(event.service),
    category: text(event.category),
    rule: text(event.rule),
    message: text(event.message),
    time: time(event.time),
  };
}

/**
 * One row as a Delivery. `channel` is the channel's status (for when a queued row can go, and the
 * next probe of a held one); `retryable` is decided by the caller, which can read later rows.
 * `digestDueAt`: for an email row waiting for its first try, when its digest goes out (the
 * caller reads the other waiting rows); its own `nextAt` is only its creation time.
 */
export function deliveryView(row, { channel = null, retryable = false, digestDueAt = null } = {}) {
  const status = fullStatus(channel);
  let nextAttemptAt = null;
  if (row.state === 'queued')
    nextAttemptAt = Math.max(digestDueAt ?? row.nextAt ?? 0, status.nextSendAt ?? 0);
  else if (row.state === 'held' && status.nextSendAt > 0) nextAttemptAt = status.nextSendAt;
  return {
    uid: row.uid,
    channel: row.channelId,
    kind: row.kind,
    status: deliveryStatus(row),
    state: row.state,
    alert: alertOf(row),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    attempts: row.attempts ?? 0,
    nextAttemptAt,
    sentAt: time(row.sentAt),
    lastStatus: Number.isInteger(row.lastStatus) ? row.lastStatus : null,
    lastError: text(row.lastError),
    batch: text(row.digestKey),
    saved: !String(row.id).startsWith('m:'),
    retryable: Boolean(retryable),
  };
}

/** The webhook's host name (never the path, query or credentials), or null. */
export function webhookHost(url) {
  if (!url) return null;
  try {
    return new URL(String(url).trim()).hostname.replace(/^\[|\]$/g, '') || null;
  } catch {
    return null;
  }
}

const zeroCounts = () => ({ waiting: 0, retrying: 0, sending: 0, paused: 0, failed: 0 });

/** The counts of one channel from store.summary() (held rows are "paused"). */
export const countsOf = summary => ({
  waiting: summary?.waiting ?? 0,
  retrying: summary?.retrying ?? 0,
  sending: summary?.sending ?? 0,
  paused: summary?.held ?? 0,
  failed: summary?.failed ?? 0,
});

/** The start of the window `failed` counts in (D29): since the last success, at most 24 h. */
export const failedSinceOf = (status, now) => Math.max(status?.lastSuccess ?? 0, now - DAY);

/**
 * Whether a channel's refusals by the backlog cap still need saying (amendment A46): the last
 * was less than 24 hours before `now`, as D29 bounds the failed count. A refused alert has no row,
 * so this is the only place the admin learns of it besides the log.
 */
export const notQueuedRecently = (channel, now) =>
  channel.notQueued > 0 && channel.notQueuedAt !== null && channel.notQueuedAt > now - DAY;

/**
 * One Channel (§6.5). `summary` is its part of store.summary(); `nextRetryAt` the earliest time a
 * row waiting to retry may go (null when none waits); `notQueued` the outbox's {count, lastAt}
 * of rows the backlog cap refused since this start (A46).
 */
export function channelView(
  id,
  {
    status,
    summary = null,
    now,
    configured,
    enabled,
    host = null,
    nextRetryAt = null,
    notQueued = null,
  }
) {
  const s = fullStatus(status),
    paused = isPaused(s),
    refusing = s.consecutiveRefusals >= 3;
  // The health changes only on a send outcome, so rows that end without one (their source
  // deleted, their kind of alert switched off, expired) leave it as the last failure set it,
  // until the next send. A back-off still to come, or rows still to go, are what "Waiting before
  // the next try" and "Retrying" are about; with neither, the channel is shown as it would be
  // without the failure (amendment A57).
  const backingOff = s.nextSendAt > now,
    pending = (summary?.waiting ?? 0) + (summary?.retrying ?? 0) + (summary?.sending ?? 0) > 0;
  const state = !configured
    ? 'not-configured'
    : !enabled
      ? 'off'
      : paused
        ? 'paused'
        : s.state === 'circuit-open' && backingOff
          ? 'circuit-open'
          : (s.state === 'circuit-open' || s.state === 'retrying') && (backingOff || pending)
            ? 'retrying'
            : refusing
              ? 'refusing'
              : 'ok';
  let nextAttemptAt = null;
  if (paused) nextAttemptAt = s.nextSendAt > 0 ? s.nextSendAt : null;
  else if (state === 'circuit-open') nextAttemptAt = s.nextSendAt;
  else if (nextRetryAt !== null) nextAttemptAt = Math.max(nextRetryAt, s.nextSendAt ?? 0);
  else if (s.nextSendAt > now) nextAttemptAt = s.nextSendAt;
  return {
    id,
    name: channelName(id),
    configured: Boolean(configured),
    enabled: Boolean(enabled),
    state,
    pausedReason: paused ? (s.pausedReason ?? null) : null,
    pausedSince: paused ? (s.pausedSince ?? null) : null,
    nextAttemptAt,
    consecutiveFailures: s.consecutiveFailures,
    consecutiveRefusals: s.consecutiveRefusals,
    deliveredTotal: s.deliveredTotal,
    failedTotal: s.failedTotal,
    lastAttempt: s.lastAttempt,
    lastSuccess: s.lastSuccess,
    lastFailure: s.lastFailure,
    lastError: s.lastError ? { time: s.lastError.time, message: s.lastError.message } : null,
    counts: summary ? countsOf(summary) : zeroCounts(),
    failedSince: failedSinceOf(s, now),
    oldestWaitingAt: summary?.oldestWaitingAt ?? null,
    host: id === 'email' ? null : host,
    notQueued: notQueued?.count ?? 0,
    notQueuedAt: notQueued?.lastAt ?? null,
  };
}

/**
 * Whether each built-in channel is set up and switched on (§6.5: webhook both = the URL). `push`
 * holds the ntfy and Gotify settings ({ntfy, gotify}, each a value or null).
 */
export function channelSetup(id, { webhook = '', email = {}, push = {} } = {}) {
  if (id === 'env-webhook') return { configured: Boolean(webhook), enabled: Boolean(webhook) };
  if (id === 'ntfy') return ntfySetup(push.ntfy ?? null);
  if (id === 'gotify') return gotifySetup(push.gotify ?? null);
  return { configured: emailConfigured(email), enabled: Boolean(email?.enabled) };
}

/** The Status of §6.5 from the channel views and the store's state. */
export function statusView({
  channels,
  now,
  saving = true,
  unsavedSince = null,
  unsavedReason = null,
  notQueued = 0,
  signing = null,
}) {
  const totals = zeroCounts();
  let oldest = null;
  for (const channel of channels) {
    for (const key of Object.keys(totals)) totals[key] += channel.counts[key];
    if (channel.oldestWaitingAt !== null && (oldest === null || channel.oldestWaitingAt < oldest))
      oldest = channel.oldestWaitingAt;
  }
  return {
    available: true,
    saving,
    unsavedSince: saving ? null : unsavedSince,
    unsavedReason: saving ? null : unsavedReason,
    updatedAt: now,
    totals,
    oldestWaitingAt: oldest,
    notQueued,
    channels,
    signing,
  };
}

/**
 * 1.4.x's `notifications` fields of /api/dashboard (D12), with their value sets unchanged, from a
 * Status. `configured` and `webhook` follow GOBLIN_WEBHOOK_URL; `lastError` is the time of the
 * webhook's last failure when it is newer than its last success (1.4.x kept that time); `email`
 * has EmailNotifier.status()'s fields.
 */
export function legacyView(status, { webhook = '', email = {} } = {}) {
  const byId = Object.fromEntries((status?.channels ?? []).map(channel => [channel.id, channel]));
  const hook = byId['env-webhook'],
    mail = byId.email;
  const lastError =
    hook?.lastFailure != null && (hook.lastSuccess == null || hook.lastFailure > hook.lastSuccess)
      ? hook.lastFailure
      : null;
  const enabled = Boolean(email?.enabled),
    configured = emailConfigured(email);
  const failing =
    mail?.lastError && (mail.lastSuccess == null || mail.lastError.time >= mail.lastSuccess);
  const state = !enabled
    ? 'disabled'
    : !configured
      ? 'unconfigured'
      : mail && (mail.state === 'paused' || mail.state === 'refusing' || failing)
        ? 'error'
        : mail?.lastSuccess != null
          ? 'accepted'
          : 'ready';
  const counts = mail?.counts ?? zeroCounts();
  return {
    configured: Boolean(webhook),
    lastError,
    webhook: { configured: Boolean(webhook), lastError },
    email: {
      enabled,
      configured,
      state,
      pending: counts.waiting + counts.retrying + counts.sending + counts.paused,
      lastAttempt: mail?.lastAttempt ?? null,
      lastAccepted: mail?.lastSuccess ?? null,
      lastError: mail?.lastError ?? null,
      failedCount: mail?.failedTotal ?? 0,
    },
  };
}

/**
 * The additive `notifications` fields of /api/dashboard (§6.5), merged into the legacy ones:
 * `email` keeps its 1.4.x fields and gains channelState, pausedReason, nextAttemptAt, waiting,
 * retrying and failed. `waiting` counts every email row not yet sent (a first try, a retry or
 * held); `retrying` only the rows waiting to retry, the ones `nextAttemptAt` is about, so the
 * Email page never counts newer alerts waiting for their own digest as retries (amendment A44).
 * `status.available` false keeps every figure as last computed (updatedAt says when).
 */
export function dashboardNotifications(legacy, status) {
  const channels = status?.channels ?? [];
  const mail = channels.find(channel => channel.id === 'email');
  const configuredChannels = channels.filter(channel => channel.configured && channel.enabled);
  return {
    ...legacy,
    available: Boolean(status?.available),
    updatedAt: status?.updatedAt ?? null,
    saving: status?.saving ?? true,
    unsavedSince: status?.unsavedSince ?? null,
    attention: {
      waiting: configuredChannels.reduce((n, channel) => n + channel.counts.waiting, 0),
      retrying: configuredChannels.reduce((n, channel) => n + channel.counts.retrying, 0),
      failed: configuredChannels.reduce((n, channel) => n + channel.counts.failed, 0),
      paused: configuredChannels.filter(c => c.state === 'paused').map(c => c.id),
      refusing: configuredChannels.filter(c => c.state === 'refusing').map(c => c.id),
      // A46: channels whose backlog cap refused alerts in the last 24 hours (the banner).
      notQueued: configuredChannels
        .filter(c => notQueuedRecently(c, status?.updatedAt ?? 0))
        .map(c => c.id),
    },
    channels: channels.map(channel => ({
      id: channel.id,
      state: channel.state,
      pausedReason: channel.pausedReason,
      nextAttemptAt: channel.nextAttemptAt,
      lastAttempt: channel.lastAttempt,
      notQueued: channel.notQueued ?? 0,
      notQueuedAt: channel.notQueuedAt ?? null,
    })),
    email: {
      ...legacy.email,
      channelState: mail?.state ?? null,
      pausedReason: mail?.pausedReason ?? null,
      nextAttemptAt: mail?.nextAttemptAt ?? null,
      waiting: mail ? mail.counts.waiting + mail.counts.retrying + mail.counts.paused : 0,
      retrying: mail?.counts.retrying ?? 0,
      failed: mail?.counts.failed ?? 0,
    },
  };
}
