// Alert delivery as the admin sees and acts on it (delivery spec §6.4): the delivery status, the
// delivery history, Retry, Resume, the environment webhook's signing key (its public key, and
// Replace), and the ntfy and Gotify channels' settings and test. Everything here goes through the delivery service (lib/alerting/service.mjs,
// `app.alerting`); this module only checks what a request may ask for and turns the answers into
// JSON.
//
// Nothing a route answers contains a URL, a rendered request, a response body or a secret: the
// service's views (lib/alerting/view.mjs) never hold them, and the signing key's route answers
// only its public half (the private key never leaves lib/alerting/signing.mjs and the settings
// store). The ntfy and Gotify settings routes answer tokens and passwords only as {set: true|false}:
// they are write-only, sealed in the settings store, and their audit rows say only that they
// were set, changed or cleared.
import { deliveryError } from '../../alerting/errors.mjs';
import { json } from '../body.mjs';

/** An outbox delivery id (X-Goblin-Delivery): `d_` and 26 base32 characters. */
export const deliveryUidPattern = /^d_[a-z2-7]{26}$/;
/** The built-in channels of this release (delivery spec D5, and ntfy and Gotify). */
export const channelIds = Object.freeze(['email', 'env-webhook', 'ntfy', 'gotify']);
/** The channels whose settings these routes edit and test. */
export const pushChannelIds = Object.freeze(['ntfy', 'gotify']);
/** The most a settings change may take (every field at its longest fits well within it). */
export const pushSettingsBodyLimit = 16384;
/** One test notification per channel this often at most (monotonic clock). */
export const pushTestIntervalMs = 30000;
/**
 * A history cursor from an earlier page: the id of a control.sqlite outbox row, or m:<n>, a row
 * kept in memory while control.sqlite refuses writes (the memory rows are paged first, A30).
 */
export const cursorPattern = /^(?:m:)?[1-9][0-9]{0,15}$/;
/** The history filters (§6.4): all, active, problems, delivered. */
export const deliveryFilters = Object.freeze(['all', 'active', 'problems', 'delivered']);

const limitPattern = /^[1-9][0-9]{0,2}$/;
const defaultLimit = 50,
  maxLimit = 100;

/** 400 invalid_request: "This request is not valid: {detail}." (§6.6). */
export const invalidRequest = detail => deliveryError('invalid_request', { detail });

// The parameters a route reads, each at most once (which of two values was meant cannot be
// told). Other names are ignored, as on every other Uptime Goblin route, so a widget's cache-busting
// parameter (`?_=…`) keeps working.
function readQuery(url, names) {
  const values = {};
  for (const name of names) {
    const all = url.searchParams.getAll(name);
    if (all.length > 1) throw invalidRequest(`${name} may be given only once`);
    if (all.length) values[name] = all[0];
  }
  return values;
}

// The POST routes take an empty JSON object: nothing in a body changes what they do, and a body
// that carries fields is a client that expects something this release does not do.
function emptyBody(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length)
    throw invalidRequest('send an empty JSON object ({})');
}

/**
 * Who asked, for the service's log lines (its `onEvent` records that carry it are left to the
 * routes' own audit rows, audit spec D24): the signed-in login ('admin' until accounts exist).
 * Never a secret.
 */
export function actorOf(access) {
  return access?.principal?.login || 'unknown';
}

/**
 * The query of GET /api/notifications/deliveries as the service takes it:
 * `{filter, channel, cursor, limit}` (filter 'all' and limit 50 by default; channel and cursor
 * null when absent; cursor a number, or the string m:<n> for a row kept in memory). Throws
 * invalid_request.
 */
export function deliveriesQuery(url) {
  const query = readQuery(url, ['filter', 'channel', 'cursor', 'limit']);
  const filter = query.filter ?? 'all';
  if (!deliveryFilters.includes(filter))
    throw invalidRequest(`filter must be one of ${deliveryFilters.join(', ')}`);
  const channel = query.channel ?? null;
  if (channel !== null && !channelIds.includes(channel))
    throw invalidRequest(`channel must be one of ${channelIds.join(', ')}`);
  let cursor = null;
  if (query.cursor !== undefined) {
    const memory = query.cursor.startsWith('m:');
    cursor = Number(memory ? query.cursor.slice(2) : query.cursor);
    // Past 2^53 − 1 a number no longer names one row exactly (the service refuses it too).
    if (!cursorPattern.test(query.cursor) || !Number.isSafeInteger(cursor))
      throw invalidRequest('cursor must be the nextCursor of an earlier page');
    if (memory) cursor = query.cursor;
  }
  let limit = defaultLimit;
  if (query.limit !== undefined) {
    limit = limitPattern.test(query.limit) ? Number(query.limit) : 0;
    if (limit < 1 || limit > maxLimit)
      throw invalidRequest(`limit must be a whole number from 1 to ${maxLimit}`);
  }
  return { filter, channel, cursor, limit };
}

/**
 * `app` (see createApp in server.mjs): `alerting` (the delivery service, §5.5 of the delivery
 * spec) and `guard` (the storage guard: a secret rotation is a configuration write, refused
 * while the disk is full). Route factories only keep references, so the table can be built
 * without a running Uptime Goblin.
 */
export function notificationRoutes(app) {
  // When each channel may be tested again (performance.now(), which no clock change moves).
  const nextTest = new Map();
  const requirePush = id => {
    if (!pushChannelIds.includes(id)) throw deliveryError('channel_unknown');
  };
  const read = (path, summary, handler) => ({
    method: 'GET',
    path,
    auth: 'session',
    permission: 'notifications:read',
    summary,
    handler,
  });
  // The actions take `{}` and are small: 1 KiB is plenty.
  const action = (path, permission, audit, summary, handler, extra = {}) => ({
    method: 'POST',
    path,
    auth: 'session',
    permission,
    bodyLimit: 1024,
    audit,
    summary,
    handler,
    ...extra,
  });
  // The webhook's signing key exists only while GOBLIN_WEBHOOK_URL is set.
  const requireWebhook = () => {
    if (!app.alerting.signing.describe()) throw deliveryError('webhook_not_configured');
  };
  return [
    read(
      '/api/notifications',
      'Delivery status: each channel, what waits, what failed, the signing key',
      async ({ res, assertCurrent }) => {
        // The page polls this: let the service read its tables again, so a status that could
        // not be read becomes available as soon as control.sqlite answers again. A failure
        // there is the service's to report (available: false), never this request's.
        try {
          await app.alerting.refresh();
        } catch {}
        const status = app.alerting.snapshot();
        // Signed out while the status was read: no delivery details for the old session.
        assertCurrent();
        // Old figures are never presented as current (delivery spec D12).
        if (!status || status.available === false)
          throw deliveryError('delivery_status_unavailable');
        json(res, 200, status);
      }
    ),
    read(
      '/api/notifications/deliveries',
      'Delivery history, newest first, a page at a time',
      async ({ res, url, assertCurrent }) => {
        const page = await app.alerting.deliveries(deliveriesQuery(url));
        assertCurrent();
        json(res, 200, {
          deliveries: page.deliveries,
          nextCursor: page.nextCursor == null ? null : String(page.nextCursor),
          unsaved: page.unsaved ?? 0,
        });
      }
    ),
    action(
      '/api/notifications/deliveries/:uid/retry',
      'notifications:operate',
      'delivery',
      'Send a failed notification again, or a retrying one now',
      async ({ access, params, body, committed, assertCurrent, audit }) => {
        if (!deliveryUidPattern.test(params.uid)) throw deliveryError('delivery_not_found');
        emptyBody(await body());
        // The attempt row first (audit spec §5.3): when it cannot be written, nothing is
        // requeued (503 audit_unavailable). A refusal of the service becomes the result.
        const change = await audit.begin({
          action: 'delivery.retry',
          target: { type: 'delivery', id: params.uid, name: null },
        });
        assertCurrent();
        // Checked again right before the requeue, after the service's reads: a session that
        // ended during them gets 401 with nothing requeued.
        const { retried, delivery } = await app.alerting.retry(params.uid, {
          actor: actorOf(access),
          check: assertCurrent,
        });
        change.note({ detail: { retried } });
        // Requeued: a session that ended meanwhile gets 401, and its keyed retry after signing
        // in again gets this answer, never a second Retry (A62). Resume and rotation alike.
        committed(200, { retried, delivery });
      }
    ),
    action(
      '/api/notifications/channels/:id/resume',
      'notifications:operate',
      'channel',
      'Resume a paused notification channel and send what it held',
      async ({ access, params, body, committed, assertCurrent, audit }) => {
        if (!channelIds.includes(params.id)) throw deliveryError('channel_unknown');
        emptyBody(await body());
        const change = await audit.begin({
          action: 'channel.resume',
          target: { type: 'channel', id: params.id, name: null },
        });
        assertCurrent();
        // Checked again right before the release, as Retry before its requeue.
        const { released, channel } = await app.alerting.resume(params.id, {
          actor: actorOf(access),
          check: assertCurrent,
        });
        change.note({ detail: { released } });
        committed(200, { released, channel });
      }
    ),
    // Public material only (receivers verify X-Goblin-Signature with it), so the narrowest read
    // of notification settings: notifications:read, unrecorded like the status it sits beside.
    read(
      '/api/notifications/webhook/public-key',
      "The alert webhook's public signing key (and the previous one while it still signs)",
      async ({ res, assertCurrent }) => {
        requireWebhook();
        const keys = await app.alerting.signing.publicKeys();
        assertCurrent();
        json(res, 200, keys);
      }
    ),
    // ntfy and Gotify settings: every field but the secrets, which read as {set: true|false}.
    // Not public material (a topic on a public ntfy server is all a reader needs), so the read of
    // configuration, not of the delivery status.
    {
      method: 'GET',
      path: '/api/notifications/channels/:id/settings',
      auth: 'session',
      permission: 'config:read',
      summary: 'The ntfy or Gotify channel settings (tokens and passwords only as set or not)',
      async handler({ res, params, assertCurrent }) {
        requirePush(params.id);
        const settings = await app.alerting.pushSettings(params.id);
        assertCurrent();
        json(res, 200, settings);
      },
    },
    {
      method: 'PATCH',
      path: '/api/notifications/channels/:id/settings',
      auth: 'session',
      permission: 'channels:write',
      bodyLimit: pushSettingsBodyLimit,
      // Written in the settings store's unit with the change (in-unit, as Replace signing key):
      // a refused or conflicting change leaves neither.
      audit: 'secret',
      summary: 'Change the ntfy or Gotify channel settings (secrets are write-only)',
      async handler({ access, params, body, committed, assertCurrent, audit }) {
        requirePush(params.id);
        const input = await body();
        if (!input || typeof input !== 'object' || Array.isArray(input))
          throw deliveryError('channel_settings_invalid', {
            detail: 'Send the settings as a JSON object',
          });
        const { version, ...patch } = input;
        if (version !== undefined && !(Number.isSafeInteger(version) && version >= 0))
          throw deliveryError('channel_settings_invalid', {
            detail: 'version must be the version the settings were read at',
          });
        // A sealed secret is a configuration write: refused while the disk is full, before
        // anything is recorded.
        app.guard.admitConfigWrite();
        const saved = await app.alerting.savePush(params.id, patch, {
          version,
          actor: actorOf(access),
          audit: audit.inUnit({
            action: 'channel.settings',
            target: { type: 'channel', id: params.id, name: null },
          }),
          check: assertCurrent,
        });
        committed(200, saved);
      },
    },
    action(
      '/api/notifications/channels/:id/test',
      'channels:write',
      'operation',
      'Send a test notification on ntfy or Gotify with the saved settings',
      async ({ params, body, committed, audit }) => {
        requirePush(params.id);
        emptyBody(await body());
        const now = performance.now();
        if (now < (nextTest.get(params.id) ?? 0))
          throw deliveryError('test_rate_limited', {
            retryAfter: Math.max(1, Math.ceil((nextTest.get(params.id) - now) / 1000)),
          });
        nextTest.set(params.id, now + pushTestIntervalMs);
        const operation = audit.operation({
          action: 'channel.test',
          target: { type: 'channel', id: params.id, name: null },
        });
        let result;
        try {
          result = await app.alerting.testPush(params.id);
        } catch (error) {
          // Nothing was sent (not set up): the next test need not wait.
          if (error?.code === 'channel_not_set_up') nextTest.delete(params.id);
          throw error;
        }
        operation.note({ detail: { accepted: result.accepted } });
        // Tried: kept under the Idempotency-Key before the session is checked, so a keyed
        // retry after signing in again replays it rather than sending a second test (A62).
        if (!result.accepted) {
          committed(422, { error: result.message, accepted: false, status: result.status });
          return;
        }
        committed(200, { ok: true, accepted: true, message: result.message });
      }
    ),
    action(
      '/api/notifications/webhook/signing-secret',
      'channels:write',
      'secret',
      "Replace the alert webhook's signing key (the old one signs for 24 more hours)",
      async ({ access, body, committed, assertCurrent, audit }) => {
        emptyBody(await body());
        requireWebhook();
        // A new sealed private key is a configuration write: refused while the disk is full,
        // before anything is recorded.
        app.guard.admitConfigWrite();
        // Its row is written in the settings store's own unit, with the change (audit spec
        // §5.3): a conflict or a storage error leaves neither. The session is checked again in
        // that unit too, after the document was read: one that ended meanwhile gets 401 with
        // nothing replaced and nothing recorded.
        const { createdAt, previousUntil } = await app.alerting.signing.rotate({
          actor: actorOf(access),
          audit: audit.inUnit({
            action: 'signing.rotate',
            target: { type: 'secret', id: 'env-webhook', name: null },
          }),
          check: assertCurrent,
        });
        // Replaced: a second rotation for the same key would end the 24 hours of the signing
        // key this one made previous, so the keyed retry after signing in again replays this
        // (A62).
        committed(200, { createdAt, previousUntil });
      }
    ),
  ];
}
