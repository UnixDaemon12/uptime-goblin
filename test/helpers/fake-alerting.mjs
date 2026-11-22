// A stand-in for the delivery service (lib/alerting/service.mjs; delivery spec §5.5) for route
// and web-app tests (delivery spec §2.1 item 9; frozen once the lanes use it). It keeps
// everything in memory and decides deterministically: no network, no database, no timers. Its
// answers have the shapes of §6.5 (built with lib/alerting/view.mjs, as the real service builds
// them) and its errors are the real DeliveryErrors of §6.6.
//
//   const fake = fakeAlerting({clock});
//   fake.add({channel: 'env-webhook', status: 'failed', alert: {service: 'plex'}});
//   fake.setChannel('env-webhook', {state: 'paused', pausedReason: 'The webhook answered 401.'});
//   fake.setAvailable(false);   // reads answer delivery_status_unavailable; snapshot() says so
//   fake.setSaving(false);      // "Notifications are not being saved"
//
// Further controls: fake.fail(method, error) makes the next call of a method throw `error`;
// fake.setEmailSending(bool); fake.setSigning(patch); fake.calls lists every call made.
import { createHash, createPrivateKey } from 'node:crypto';
import { deliveryError } from '../../lib/alerting/errors.mjs';
import { publicSigningKey } from '../../lib/notify/sign.mjs';
import {
  BUILT_IN_CHANNELS,
  channelName,
  dashboardNotifications,
  legacyView,
  statusView,
} from '../../lib/alerting/view.mjs';
import { systemClock } from '../../lib/jobs.mjs';

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const code = (prefix, n) => {
  let text = '';
  for (let value = n; value > 0; value = Math.floor(value / 32)) text = BASE32[value % 32] + text;
  return prefix + text.padStart(26, 'a');
};
const STATE_OF = {
  waiting: 'queued',
  retrying: 'queued',
  sending: 'sending',
  paused: 'held',
  delivered: 'delivered',
  failed: 'dead',
  expired: 'dead',
  unconfirmed: 'dead',
  replaced: 'superseded',
  skipped: 'skipped',
  'not-sent': 'cancelled',
};
const FILTERS = {
  all: null,
  active: ['waiting', 'retrying', 'sending', 'paused'],
  problems: ['retrying', 'paused', 'failed', 'expired', 'unconfirmed'],
  delivered: ['delivered'],
};
const FINISHED = new Set(['delivered', 'skipped', 'replaced', 'not-sent']);
const FAILED = new Set(['failed', 'expired', 'unconfirmed']);
const copy = value => structuredClone(value);
// The fake's signing keys are deterministic: Ed25519 private keys (PKCS#8 PEM, as Uptime Goblin seals
// them) whose seeds are the SHA-256 of a counter.
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
export const fakeSigningKey = n =>
  createPrivateKey({
    key: Buffer.concat([
      PKCS8_ED25519,
      createHash('sha256').update(`fake-signing-key-${n}`).digest(),
    ]),
    format: 'der',
    type: 'pkcs8',
  }).export({ type: 'pkcs8', format: 'pem' });

export function fakeAlerting({
  clock = systemClock,
  webhook = 'https://hooks.example.test/orbit',
  email = { enabled: true, configured: true },
} = {}) {
  const calls = [],
    failures = new Map();
  let available = true,
    saving = true,
    unsavedSince = null,
    emailSending = false,
    nextId = 1,
    last = null; // the last Status computed while available
  const deliveries = []; // Delivery shapes plus {id}
  const channels = Object.fromEntries(
    BUILT_IN_CHANNELS.map(id => [
      id,
      {
        id,
        name: channelName(id),
        // ntfy and Gotify start not set up (setPush() sets them up).
        configured:
          id === 'email'
            ? Boolean(email.configured)
            : id === 'env-webhook'
              ? Boolean(webhook)
              : false,
        enabled:
          id === 'email' ? Boolean(email.enabled) : id === 'env-webhook' ? Boolean(webhook) : false,
        state: 'ok',
        pausedReason: null,
        pausedSince: null,
        nextAttemptAt: null,
        consecutiveFailures: 0,
        consecutiveRefusals: 0,
        deliveredTotal: 0,
        failedTotal: 0,
        lastAttempt: null,
        lastSuccess: null,
        lastFailure: null,
        lastError: null,
        counts: null, // derived from the deliveries unless a test sets them
        failedSince: 0,
        oldestWaitingAt: null,
        host: id === 'env-webhook' && webhook ? new URL(webhook).hostname : null,
        notQueued: 0,
        notQueuedAt: null,
      },
    ])
  );
  const pushSecrets = ['token', 'password'];
  const push = {
    ntfy: {
      version: 0,
      updatedAt: null,
      value: {
        enabled: false,
        server: 'https://ntfy.sh',
        topic: '',
        username: '',
        password: null,
        token: null,
        priorityFiring: 4,
        priorityResolved: 3,
        tags: [],
        dashboardUrl: '',
        allowPlainHttp: false,
      },
    },
    gotify: {
      version: 0,
      updatedAt: null,
      value: {
        enabled: false,
        server: '',
        token: null,
        priorityFiring: 8,
        priorityResolved: 4,
        dashboardUrl: '',
        allowPlainHttp: false,
      },
    },
  };
  const signing = {
    configured: Boolean(webhook),
    saved: true,
    counter: 1,
    key: fakeSigningKey(1),
    previousKey: null,
    createdAt: clock.wall(),
    previousUntil: null,
    heldSince: null,
    readOnly: false,
  };

  // A function among a call's options (the route's check() or audit recorder) is listed
  // as `true` in its place: a function cannot be copied.
  const listed = value =>
    value && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value).map(([key, item]) => [key, typeof item === 'function' || item])
        )
      : value;
  function record(name, args) {
    calls.push([name, ...copy(args.map(listed))]);
    const error = failures.get(name);
    if (error) {
      failures.delete(name);
      throw error;
    }
  }
  const unavailable = () => deliveryError('delivery_status_unavailable');
  const alertKey = item => `${item.channel}\n${item.alert.service}\n${item.alert.rule}`;
  const view = item => {
    const { id, ...shape } = item;
    return copy(shape);
  };

  function countsOf(id) {
    const counts = { waiting: 0, retrying: 0, sending: 0, paused: 0, failed: 0 };
    let oldest = null;
    for (const item of deliveries) {
      if (item.channel !== id) continue;
      if (item.status in counts) counts[item.status]++;
      else if (FAILED.has(item.status)) counts.failed++;
      if (
        (item.status === 'waiting' || item.status === 'retrying' || item.status === 'paused') &&
        (oldest === null || item.createdAt < oldest)
      )
        oldest = item.createdAt;
    }
    return { counts, oldest };
  }

  function compute() {
    const now = clock.wall();
    const list = BUILT_IN_CHANNELS.map(id => {
      const channel = channels[id],
        derived = countsOf(id);
      return {
        ...copy(channel),
        counts: channel.counts ? copy(channel.counts) : derived.counts,
        oldestWaitingAt: channel.oldestWaitingAt ?? derived.oldest,
        failedSince: channel.failedSince || Math.max(channel.lastSuccess ?? 0, now - 86400000),
      };
    });
    return statusView({
      channels: list,
      now,
      saving,
      unsavedSince,
      unsavedReason: saving
        ? null
        : 'Uptime Goblin cannot write its control database (SQLITE_FULL).',
      notQueued: 0,
      signing: describe(),
    });
  }

  function snapshot() {
    if (available) last = compute();
    return available ? last : { ...(last ?? compute()), available: false };
  }

  function describe() {
    if (!signing.configured) return null;
    return {
      configured: true,
      saved: signing.saved,
      createdAt: signing.key ? signing.createdAt : null,
      previousUntil:
        signing.previousUntil && signing.previousUntil > clock.wall()
          ? signing.previousUntil
          : null,
    };
  }

  function add(delivery = {}) {
    const id = nextId++,
      now = clock.wall();
    const status = delivery.status ?? 'waiting';
    const item = {
      uid: delivery.uid ?? code('d_', id),
      channel: delivery.channel ?? 'env-webhook',
      kind: delivery.kind ?? 'firing',
      status,
      state: delivery.state ?? STATE_OF[status] ?? 'queued',
      alert: {
        service: 'plex',
        name: 'Plex',
        category: 'availability',
        rule: '__availability',
        message: 'Source is unavailable',
        time: now,
        ...delivery.alert,
      },
      createdAt: delivery.createdAt ?? now,
      updatedAt: delivery.updatedAt ?? now,
      attempts: delivery.attempts ?? (status === 'waiting' ? 0 : 1),
      nextAttemptAt:
        delivery.nextAttemptAt ?? (status === 'waiting' || status === 'retrying' ? now : null),
      sentAt: delivery.sentAt ?? (status === 'delivered' ? now : null),
      lastStatus: delivery.lastStatus ?? null,
      lastError: delivery.lastError ?? null,
      batch: delivery.batch ?? null,
      saved: delivery.saved ?? true,
      retryable: delivery.retryable ?? (FAILED.has(status) || status === 'retrying'),
      id,
    };
    deliveries.push(item);
    return view(item);
  }

  // Queues one delivery per routed channel, as 1.4.2's switches would (both channels when set up).
  function queue(event, { exclude = [] } = {}) {
    let enqueued = 0;
    for (const id of BUILT_IN_CHANNELS) {
      const channel = channels[id];
      if (!channel.configured || !channel.enabled || exclude.includes(id)) continue;
      add({
        channel: id,
        kind: event.kind,
        status: channel.state === 'paused' ? 'paused' : 'waiting',
        alert: {
          service: event.service,
          name: event.name ?? event.service,
          category: event.category ?? null,
          rule: event.rule ?? null,
          message: event.message ?? null,
          time: event.time ?? clock.wall(),
        },
        saved: saving,
      });
      enqueued++;
    }
    return enqueued;
  }

  // As the service (A45): Retry only while the row's channel is set up and on; otherwise it is
  // refused in place of a pause, or of being accepted.
  const ready = id => channels[id].configured && channels[id].enabled;
  const notSetUp = id =>
    deliveryError('channel_not_set_up', {
      variant: id === 'email' ? (channels.email.configured ? 'email-off' : 'email') : id,
    });
  function refusal(item) {
    if (item.status === 'sending')
      return deliveryError('delivery_not_retryable', { variant: 'sending' });
    const channel = channels[item.channel];
    if (channel.state === 'paused' || item.status === 'paused')
      return ready(item.channel)
        ? deliveryError('channel_paused', {
            name: channel.name,
            reason: channel.pausedReason ?? 'paused.',
          })
        : notSetUp(item.channel);
    if (item.status === 'waiting')
      return deliveryError('delivery_not_retryable', { variant: 'waiting' });
    if (FINISHED.has(item.status))
      return deliveryError('delivery_not_retryable', { variant: 'finished' });
    if (
      FAILED.has(item.status) &&
      deliveries.some(
        other =>
          other.id > item.id &&
          alertKey(other) === alertKey(item) &&
          (other.status === 'delivered' || other.status === 'sending')
      )
    )
      return deliveryError('delivery_outdated');
    return ready(item.channel) ? null : notSetUp(item.channel);
  }

  const fake = {
    calls,
    deliveriesList: deliveries,
    add,
    setChannel(id, patch) {
      if (!channels[id]) throw new TypeError(`No channel ${id}`);
      Object.assign(channels[id], copy(patch));
    },
    setAvailable(value) {
      if (value) available = true;
      else {
        snapshot();
        available = false;
      }
    },
    setSaving(value) {
      saving = Boolean(value);
      unsavedSince = saving ? null : clock.wall();
    },
    setEmailSending(value) {
      emailSending = Boolean(value);
    },
    setSigning(patch) {
      Object.assign(signing, patch);
    },
    fail(method, error) {
      failures.set(method, error);
    },

    // --- the §5.5 interface ---
    start() {
      record('start', []);
    },
    async transitions(events) {
      record('transitions', [events]);
      let enqueued = 0;
      for (const event of events ?? []) enqueued += queue(event);
      return { enqueued, marked: (events ?? []).length, deferred: 0 };
    },
    async enqueueDirect(event, uid, options = {}) {
      record('enqueueDirect', [event, uid, options]);
      return { enqueued: queue(event, options) };
    },
    async forgetSource(serviceId) {
      record('forgetSource', [serviceId]);
      let cancelled = 0;
      for (const item of deliveries)
        if (
          item.alert.service === serviceId &&
          (item.status === 'waiting' || item.status === 'retrying' || item.status === 'paused')
        ) {
          Object.assign(item, {
            status: 'not-sent',
            state: 'cancelled',
            lastError: 'Not sent: the source was deleted.',
            retryable: false,
          });
          cancelled++;
        }
      return { cancelled };
    },
    diskChanged(state) {
      record('diskChanged', [state]);
    },
    storageChanged(state) {
      record('storageChanged', [state]);
    },
    // No history-storage outage is carried from an earlier run (amendment A40).
    storageCarried() {
      return null;
    },
    async emailChanged() {
      record('emailChanged', []);
      Object.assign(channels.email, {
        state: 'ok',
        pausedReason: null,
        pausedSince: null,
        nextAttemptAt: null,
        consecutiveFailures: 0,
        consecutiveRefusals: 0,
        lastError: null,
      });
    },
    async flush(options) {
      record('flush', [options ?? {}]);
      return true;
    },
    async stop(options) {
      record('stop', [options ?? {}]);
      return { cancelled: 0, unsettled: 0 };
    },
    snapshot,
    async refresh() {
      record('refresh', []);
      snapshot();
    },
    legacy() {
      return legacyView(snapshot(), {
        webhook,
        email: email.configured
          ? {
              enabled: email.enabled,
              host: 'smtp.example.test',
              port: 465,
              from: 'orbit@example.test',
              to: 'dana@example.test',
              password: 'x',
            }
          : { enabled: email.enabled },
      });
    },
    /** The dashboard's notifications field, as server.mjs builds it from the service. */
    dashboard() {
      return dashboardNotifications(fake.legacy(), snapshot());
    },
    async deliveries({ filter = 'all', channel, cursor, limit = 50 } = {}) {
      record('deliveries', [{ filter, channel, cursor, limit }]);
      if (!Object.hasOwn(FILTERS, filter))
        throw deliveryError('invalid_request', {
          detail: 'filter is all, active, problems or delivered',
        });
      if (channel != null && !BUILT_IN_CHANNELS.includes(channel))
        throw deliveryError('invalid_request', { detail: 'channel is email or env-webhook' });
      // As the service (A30): a row id, or m:<n> for a row kept in memory.
      const memoryCursor =
        typeof cursor === 'string' && /^m:[1-9][0-9]{0,15}$/.test(cursor)
          ? Number(cursor.slice(2))
          : null;
      const before =
        memoryCursor !== null || cursor == null || cursor === '' ? null : Number(cursor);
      if (before !== null && !(Number.isSafeInteger(before) && before > 0))
        throw deliveryError('invalid_request', { detail: 'cursor is a delivery row id' });
      if (!available) throw unavailable();
      const statuses = FILTERS[filter];
      const matching = deliveries
        .filter(item => !statuses || statuses.includes(item.status))
        .filter(item => !channel || item.channel === channel)
        .sort((a, b) => b.id - a.id);
      const savedRows = matching.filter(item => item.saved);
      // As the service: the memory rows first, page by page, then the saved ones filling the
      // page; a cursor only while an older row matches.
      let page = [],
        nextCursor = null;
      if (before === null) {
        const memory = matching.filter(
          item => !item.saved && (memoryCursor === null || item.id < memoryCursor)
        );
        page = memory.slice(0, limit);
        if (page.length >= limit && (memory.length > limit || savedRows.length))
          nextCursor = `m:${page.at(-1).id}`;
      }
      if (page.length < limit) {
        const older = savedRows.filter(item => before === null || item.id < before),
          room = limit - page.length;
        page = [...page, ...older.slice(0, room)];
        if (older.length > room) nextCursor = String(older[room - 1].id);
      }
      return {
        deliveries: page.map(item => ({
          ...view(item),
          retryable: item.retryable && ready(item.channel),
        })),
        nextCursor,
        unsaved: deliveries.filter(item => !item.saved).length,
      };
    },
    async retry(uid, options = {}) {
      record('retry', [uid, options]);
      if (!available) throw unavailable();
      const item = deliveries.find(entry => entry.uid === uid);
      if (!item) throw deliveryError('delivery_not_found');
      const batch = item.batch ? deliveries.filter(entry => entry.batch === item.batch) : [item];
      for (const entry of batch.sort((a, b) => a.id - b.id)) {
        const error = refusal(entry);
        if (error) throw error;
      }
      // As the service: the route's re-check of its session, right before the requeue.
      options.check?.();
      const now = clock.wall();
      for (const entry of batch)
        Object.assign(entry, {
          status: 'retrying',
          state: 'queued',
          nextAttemptAt: now,
          updatedAt: now,
          retryable: true,
        });
      return { retried: batch.length, delivery: view(item) };
    },
    async resume(channelId, options = {}) {
      record('resume', [channelId, options]);
      if (!BUILT_IN_CHANNELS.includes(channelId)) throw deliveryError('channel_unknown');
      let released = 0;
      const holding = channelId === 'env-webhook' && fake.signing.held;
      const held = deliveries.some(entry => entry.channel === channelId && entry.state === 'held');
      if (channels[channelId].state === 'paused' || held || holding) {
        // As the service: the route's re-check of its session, right before the release.
        options.check?.();
        if (holding) await fake.signing.releaseHold(options);
        record('outbox.resume', [channelId]);
        Object.assign(channels[channelId], {
          state: 'ok',
          pausedReason: null,
          pausedSince: null,
          nextAttemptAt: null,
          consecutiveFailures: 0,
          consecutiveRefusals: 0,
        });
        for (const entry of deliveries)
          if (entry.channel === channelId && entry.state === 'held') {
            Object.assign(entry, {
              status: 'waiting',
              state: 'queued',
              nextAttemptAt: clock.wall(),
            });
            released++;
          }
      }
      return { released, channel: copy(compute().channels.find(c => c.id === channelId)) };
    },
    emailSending() {
      return emailSending;
    },
    // The ntfy and Gotify settings (secrets as {set}), their save and their test.
    async pushSettings(channelId) {
      record('pushSettings', [channelId]);
      const entry = push[channelId];
      if (!entry) throw deliveryError('channel_unknown');
      return copy({
        channel: channelId,
        version: entry.version,
        readOnly: false,
        unreadable: [],
        settings: Object.fromEntries(
          Object.entries(entry.value).map(([key, value]) => [
            key,
            pushSecrets.includes(key) ? { set: value !== null && value !== '' } : value,
          ])
        ),
        updatedAt: entry.updatedAt,
      });
    },
    async savePush(channelId, patch, options = {}) {
      record('savePush', [channelId, patch, options]);
      const entry = push[channelId];
      if (!entry) throw deliveryError('channel_unknown');
      if (options.version !== undefined && options.version !== entry.version)
        throw deliveryError('channel_settings_conflict');
      Object.assign(entry.value, patch);
      entry.version++;
      entry.updatedAt = clock.wall();
      const setUp =
        channelId === 'ntfy'
          ? Boolean(entry.value.topic)
          : Boolean(entry.value.server && entry.value.token);
      Object.assign(channels[channelId], {
        configured: setUp,
        enabled: entry.value.enabled === true,
        host: setUp ? new URL(entry.value.server).hostname : null,
      });
      return fake.pushSettings(channelId);
    },
    async testPush(channelId) {
      record('testPush', [channelId]);
      if (!push[channelId]) throw deliveryError('channel_unknown');
      if (!channels[channelId].configured)
        throw deliveryError('channel_not_set_up', { variant: `${channelId}-test` });
      return {
        accepted: true,
        message: `${channelName(channelId)} accepted the test notification.`,
      };
    },
    async recordTest({ accepted = false, message = '' } = {}) {
      calls.push(['recordTest', { accepted, message }]);
      const now = clock.wall();
      const mail = channels.email;
      if (accepted) {
        Object.assign(mail, { lastAttempt: now, lastSuccess: now });
        if (mail.state === 'paused') await fake.resume('email');
      } else
        Object.assign(mail, {
          lastAttempt: now,
          lastFailure: now,
          lastError: { time: now, message },
          failedTotal: mail.failedTotal + 1,
        });
    },
    signing: {
      describe,
      get held() {
        return signing.configured && (signing.heldSince != null || !signing.key);
      },
      async releaseHold({ actor, check = () => {} } = {}) {
        record('signing.releaseHold', [{ actor, check }]);
        if (signing.readOnly && fake.signing.held) throw deliveryError('signing_compatibility');
        if (!signing.key) throw deliveryError('signing_unavailable');
        check();
        signing.heldSince = null;
      },
      // As the service: public material only, read from what is saved.
      async publicKeys() {
        record('signing.publicKeys', []);
        if (!signing.configured) throw deliveryError('webhook_not_configured');
        if (!signing.key) throw deliveryError('signing_unavailable');
        const until = describe().previousUntil,
          overlap = Boolean(signing.previousKey && until);
        const part = key => {
          const { keyId, publicKey, publicKeyRaw } = publicSigningKey(key);
          return { keyId, publicKey, publicKeyRaw };
        };
        return {
          ...publicSigningKey(signing.key),
          createdAt: signing.createdAt,
          previousUntil: overlap ? until : null,
          previous: overlap ? part(signing.previousKey) : null,
        };
      },
      // `audit` (the route's ctx.audit.inUnit(…), audit spec §5.3) is called as the settings
      // store calls it: once per rotation that changed the key, inside its unit (tx null
      // here), with the settings diff in the `path` form, after `check` (the route's re-check of
      // its session); a throw from either changes nothing. The call is listed with `audit: true`
      // and `check: true` in their places (a function cannot be copied).
      async rotate({ audit, check, ...options } = {}) {
        record('signing.rotate', [
          { ...options, ...(audit ? { audit } : {}), ...(check ? { check } : {}) },
        ]);
        if (!signing.configured) throw deliveryError('webhook_not_configured');
        if (signing.readOnly) throw deliveryError('signing_compatibility');
        const now = clock.wall();
        // A deterministic next key: the one of the next counter value.
        const next = fakeSigningKey(signing.counter + 1);
        const before = {
          signingKey: signing.key,
          previousSigningKey: signing.previousKey,
          previousUntil: signing.previousUntil,
          createdAt: signing.createdAt,
        };
        const after = {
          signingKey: next,
          previousSigningKey: signing.key,
          previousUntil: now + 86400000,
          createdAt: now,
        };
        const secrets = new Set(['signingKey', 'previousSigningKey']);
        const diff = [];
        for (const [path, to] of Object.entries(after)) {
          const from = before[path];
          if (from === to) continue;
          if (!secrets.has(path)) diff.push({ path, from, to });
          else
            diff.push({
              path,
              change: to === null ? 'cleared' : from === null ? 'set' : 'changed',
            });
        }
        check?.();
        audit?.(null, { diff });
        Object.assign(signing, {
          previousKey: signing.key,
          key: next,
          counter: signing.counter + 1,
          createdAt: now,
          previousUntil: now + 86400000,
          saved: true,
        });
        return { createdAt: now, previousUntil: now + 86400000 };
      },
    },
  };
  return fake;
}
