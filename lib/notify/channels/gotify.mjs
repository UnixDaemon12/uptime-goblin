// The Gotify channel (a self-hosted Gotify server). Each notification is one POST to the
// server's /message with the application token in the X-Gotify-Key header (never in the URL,
// where proxies log it):
//   {"title","message","priority"[, "extras": {"client::notification": {"click": {"url"}}}]}
// Priorities are Gotify's 0-10: an alert that began is sent with the firing priority (8, which
// the Gotify apps show as high, by default), a recovery with the resolved one (4 by default).
// The click-through opens Uptime Goblin when its address is saved.
//
// As for ntfy (channels/ntfy.mjs), every request carries X-Goblin-Delivery, the settings are read
// when a row is sent, and channels/push.mjs maps the answer to an outcome.
import { post as defaultPost } from '../http.mjs';
import { pushAddressProblem } from '../address-policy.mjs';
import { DELIVERY_HEADER } from '../sign.mjs';
import { failed, pause, skipped, defineChannel } from '../channel.mjs';
import {
  PUSH_LIMITS,
  PUSH_TOKEN,
  PUSH_UNKNOWN,
  PushConfigError,
  classifyPushError,
  classifyPushResponse,
  endpoint,
  parseDashboardUrl,
  parseServerUrl,
  pushMessage,
  pushPriority,
  pushTitle,
} from './push.mjs';

/** Validators of the settings fields (lib/alerting/push-settings.mjs). */
export const gotifyFields = Object.freeze({
  token(value) {
    if (typeof value !== 'string' || !PUSH_TOKEN.test(value))
      throw new Error('must be 1-512 printable characters without spaces');
    return value;
  },
  priority(value) {
    if (!Number.isInteger(value) || value < 0 || value > 10)
      throw new Error('must be a whole number from 0 to 10');
    return value;
  },
});

/**
 * The whole document's rule: while Gotify is switched on, a usable server address and an
 * application token; a server address, when given, valid either way; a valid dashboard address.
 */
export function checkGotify(settings) {
  if (settings.server || settings.enabled)
    parseServerUrl(settings.server, {
      label: 'The Gotify server address',
      allowPlainHttp: settings.allowPlainHttp === true,
    });
  if (settings.enabled && !settings.token)
    throw new PushConfigError('Enter the Gotify application token.');
  parseDashboardUrl(settings.dashboardUrl);
}

/** Whether Gotify is set up (a usable server address and a token) and switched on. */
export function gotifySetup(settings) {
  if (!settings) return { configured: false, enabled: false };
  let configured = Boolean(settings.server && settings.token);
  if (configured)
    try {
      checkGotify({ ...settings, enabled: true });
    } catch {
      configured = false;
    }
  return { configured, enabled: settings.enabled === true };
}

/** Gotify's JSON body for one event (pure). */
export function gotifyBody(event, settings) {
  const click = settings.dashboardUrl ? parseDashboardUrl(settings.dashboardUrl) : '';
  return {
    title: pushTitle(event),
    message: pushMessage(event),
    priority: pushPriority(event, {
      firing: settings.priorityFiring ?? 8,
      resolved: settings.priorityResolved ?? 4,
    }),
    ...(click ? { extras: { 'client::notification': { click: { url: click } } } } : {}),
  };
}

/**
 * createGotifyChannel({getSettings, post, addressPolicy, timeoutMs, now, userAgent, unknown,
 * lookup, ca}): as createNtfyChannel.
 */
export function createGotifyChannel({
  getSettings,
  post = defaultPost,
  addressPolicy = pushAddressProblem,
  timeoutMs = PUSH_LIMITS.timeoutMs,
  now = Date.now,
  userAgent = 'Uptime-Goblin',
  unknown: unknownRule = PUSH_UNKNOWN,
  lookup,
  ca,
} = {}) {
  if (typeof getSettings !== 'function') throw new TypeError('getSettings is required');
  return defineChannel({
    name: 'gotify',
    unknown: unknownRule,
    async send(message, { signal, test = false } = {}) {
      const saved = getSettings();
      if (!saved)
        return pause('The Gotify settings cannot be read right now.', { transient: true });
      const settings = saved.value ?? {};
      // A test (the delivery service's testPush) is sent while the channel is switched off.
      if (!settings.enabled && !test) return skipped('Gotify notifications are switched off.');
      if ((saved.unreadable ?? []).includes('token'))
        return pause(
          'The saved Gotify application token cannot be opened (the encryption key changed). Enter it again under Configure → Notifications.'
        );
      let target;
      try {
        checkGotify({ ...settings, enabled: true });
        target = endpoint(
          parseServerUrl(settings.server, { allowPlainHttp: settings.allowPlainHttp === true }),
          'message'
        );
      } catch (error) {
        if (!(error instanceof PushConfigError)) throw error;
        return pause(`Gotify is not set up: ${error.message}`);
      }
      const event = message.events?.[0];
      if (!event) return failed('The delivery has no event.');
      try {
        const response = await post(target, JSON.stringify(gotifyBody(event, settings)), {
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': userAgent,
            'X-Gotify-Key': settings.token,
            [DELIVERY_HEADER]: message.uid,
          },
          timeoutMs,
          signal,
          addressPolicy,
          ca,
          ...(lookup ? { lookup } : {}),
          maxRequestBytes: PUSH_LIMITS.maxRequestBytes,
          maxResponseBytes: PUSH_LIMITS.maxResponseBytes,
        });
        return classifyPushResponse('Gotify', response.status, response.headers, now());
      } catch (error) {
        return classifyPushError('Gotify', error);
      }
    },
  });
}
