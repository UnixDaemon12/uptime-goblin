// The ntfy channel (https://ntfy.sh, or a self-hosted ntfy server). Each notification is one
// POST of ntfy's JSON form to the server's root address:
//   {"topic","title","message","priority","tags"[, "click"]}
// with the access token as `Authorization: Bearer …`, or a user name and password as Basic, when
// they are saved. Priorities are ntfy's 1-5 (min, low, default, high, max): an alert that began
// is sent with the firing priority (high by default), a recovery with the resolved one (default
// by default). The saved tags come first, then one for the kind (warning, white_check_mark),
// which ntfy shows as an emoji. `click` opens Uptime Goblin when its address is saved.
//
// Every request carries X-Goblin-Delivery, stable across retries of one notification, as the
// webhook's; ntfy ignores it, so a receiver cannot drop a repeat by it (see docs/notifications.md).
// The settings are read when a row is sent (`getSettings()`, the delivery service's copy of the
// saved document), so a change applies to what still waits. Classification: channels/push.mjs.
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

export const NTFY_DEFAULT_SERVER = 'https://ntfy.sh';
/** ntfy's own topic rule: letters, digits, _ and -, at most 64. */
export const NTFY_TOPIC = /^[A-Za-z0-9_-]{1,64}$/;
/** A tag: an emoji short code or a word (letters, digits, _, + and -), at most 32. */
export const NTFY_TAG = /^[A-Za-z0-9_+-]{1,32}$/;
export const NTFY_MAX_TAGS = 5;
const KIND_TAGS = Object.freeze({ firing: 'warning', resolved: 'white_check_mark', test: 'bell' });

/** Validators of the settings fields (lib/alerting/push-settings.mjs), with messages for the admin. */
export const ntfyFields = Object.freeze({
  topic(value) {
    if (typeof value !== 'string') throw new Error('must be text');
    const text = value.trim();
    if (text && !NTFY_TOPIC.test(text))
      throw new Error('may hold only letters, digits, _ and -, at most 64 characters');
    return text;
  },
  username(value) {
    if (typeof value !== 'string') throw new Error('must be text');
    const text = value.trim();
    if (text.length > 128) throw new Error('must be at most 128 characters');
    if (/[\u0000-\u001f\u007f:]/.test(text))
      throw new Error('must not contain a colon or control characters');
    return text;
  },
  token(value) {
    if (typeof value !== 'string' || !PUSH_TOKEN.test(value))
      throw new Error('must be 1-512 printable characters without spaces');
    return value;
  },
  password(value) {
    if (typeof value !== 'string' || !value || value.length > 512)
      throw new Error('must be 1-512 characters');
    if (/[\u0000-\u001f\u007f]/.test(value)) throw new Error('must not contain control characters');
    return value;
  },
  priority(value) {
    if (!Number.isInteger(value) || value < 1 || value > 5)
      throw new Error('must be a whole number from 1 (min) to 5 (max)');
    return value;
  },
  tags(value) {
    if (!Array.isArray(value)) throw new Error('must be a list');
    if (value.length > NTFY_MAX_TAGS) throw new Error(`may hold at most ${NTFY_MAX_TAGS} tags`);
    const tags = value.map(tag => (typeof tag === 'string' ? tag.trim() : tag));
    if (!tags.every(tag => typeof tag === 'string' && NTFY_TAG.test(tag)))
      throw new Error('each tag holds only letters, digits, _, + and -, at most 32 characters');
    return [...new Set(tags)];
  },
});

/**
 * The whole document's rule: a server address the channel can use (parseServerUrl), a topic
 * while ntfy is switched on, a token or a user name with a password but not both, and a valid
 * dashboard address. Throws PushConfigError.
 */
export function checkNtfy(settings) {
  parseServerUrl(settings.server, {
    label: 'The ntfy server address',
    allowPlainHttp: settings.allowPlainHttp === true,
  });
  if (settings.enabled && !settings.topic)
    throw new PushConfigError('Enter the ntfy topic to send to.');
  if (settings.token && (settings.username || settings.password))
    throw new PushConfigError(
      'Use either an ntfy access token or a user name and password, not both.'
    );
  if (Boolean(settings.username) !== Boolean(settings.password))
    throw new PushConfigError(
      'An ntfy user name needs its password, and a password its user name.'
    );
  parseDashboardUrl(settings.dashboardUrl);
}

/** Whether ntfy is set up (a topic and a usable server address) and switched on. */
export function ntfySetup(settings) {
  if (!settings) return { configured: false, enabled: false };
  let configured = Boolean(settings.topic);
  if (configured)
    try {
      checkNtfy({ ...settings, enabled: true });
    } catch {
      configured = false;
    }
  return { configured, enabled: settings.enabled === true };
}

/** ntfy's JSON body for one event (pure). `kind` 'test' marks a test notification. */
export function ntfyBody(event, settings) {
  const kind =
    event?.rule === '__test' ? 'test' : event?.kind === 'resolved' ? 'resolved' : 'firing';
  const tags = [...(settings.tags ?? []), KIND_TAGS[kind]].filter(
    (tag, index, all) => all.indexOf(tag) === index
  );
  const click = settings.dashboardUrl ? parseDashboardUrl(settings.dashboardUrl) : '';
  return {
    topic: settings.topic,
    title: pushTitle(event),
    message: pushMessage(event),
    priority: pushPriority(event, {
      firing: settings.priorityFiring ?? 4,
      resolved: settings.priorityResolved ?? 3,
    }),
    tags,
    ...(click ? { click } : {}),
  };
}

/** The Authorization header for the saved credentials, or null. */
export function ntfyAuthorization(settings) {
  if (settings.token) return `Bearer ${settings.token}`;
  if (settings.username && settings.password)
    return `Basic ${Buffer.from(`${settings.username}:${settings.password}`, 'utf8').toString('base64')}`;
  return null;
}

/**
 * createNtfyChannel({getSettings, post, addressPolicy, timeoutMs, now, userAgent, unknown,
 * lookup, ca}). `getSettings()` returns the saved document ({value, unreadable}) or null while
 * it cannot be read. `lookup` and `ca` are for tests.
 */
export function createNtfyChannel({
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
    name: 'ntfy',
    unknown: unknownRule,
    async send(message, { signal, test = false } = {}) {
      const saved = getSettings();
      if (!saved) return pause('The ntfy settings cannot be read right now.', { transient: true });
      const settings = saved.value ?? {};
      // A test (the delivery service's testPush) is sent while the channel is switched off.
      if (!settings.enabled && !test) return skipped('ntfy notifications are switched off.');
      const unreadable = (saved.unreadable ?? []).filter(name =>
        ['token', 'password'].includes(name)
      );
      if (unreadable.length)
        return pause(
          'The saved ntfy credentials cannot be opened (the encryption key changed). Enter them again under Configure → Notifications.'
        );
      let target;
      try {
        checkNtfy({ ...settings, enabled: true });
        target = endpoint(
          parseServerUrl(settings.server, { allowPlainHttp: settings.allowPlainHttp === true })
        );
      } catch (error) {
        if (!(error instanceof PushConfigError)) throw error;
        return pause(`ntfy is not set up: ${error.message}`);
      }
      const event = message.events?.[0];
      if (!event) return failed('The delivery has no event.');
      const headers = {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,
        [DELIVERY_HEADER]: message.uid,
      };
      const authorization = ntfyAuthorization(settings);
      if (authorization) headers.Authorization = authorization;
      try {
        const response = await post(target, JSON.stringify(ntfyBody(event, settings)), {
          headers,
          timeoutMs,
          signal,
          addressPolicy,
          ca,
          ...(lookup ? { lookup } : {}),
          maxRequestBytes: PUSH_LIMITS.maxRequestBytes,
          maxResponseBytes: PUSH_LIMITS.maxResponseBytes,
        });
        return classifyPushResponse('ntfy', response.status, response.headers, now());
      } catch (error) {
        return classifyPushError('ntfy', error);
      }
    },
  });
}
