// What the ntfy and Gotify channels share (channels/ntfy.mjs, channels/gotify.mjs): the server
// address rule, the notification's title and text, and how an HTTP answer or a transport failure
// becomes an outcome. Both send through lib/notify/http.mjs, as the environment webhook does: the
// address policy is applied to every address a name resolves to when Uptime Goblin connects (no second
// lookup can swap one in), redirects are never followed, TLS is verified, and the request, the
// answer read and the time taken are bounded.
//
//   2xx accepted · 408, 425, 429, 5xx and network errors retry (honouring Retry-After) ·
//   401 and 403 pause until something changes (a token or password that is wrong or was
//   revoked: saving the settings, Resume, a test the server accepts or the probe at the next
//   start ends it) · 404, 410, redirects and an untrusted certificate pause transiently (probed
//   every 15 minutes) · a refused address pauses until it is fixed · other 4xx fail the row ·
//   a timeout after the request was sent, before the answer's status arrived, is "unknown": sent
//   once more after 2 minutes with the same X-Goblin-Delivery, then given up as "may have arrived".
//
// Nothing here returns or logs a URL, a token or a password: reasons name the channel only.
import net from 'node:net';
import { isTlsError } from '../http.mjs';
import { parseRetryAfter } from '../retry.mjs';
import { accepted, retry, failed, unknown, pause } from '../channel.mjs';

/** The longest server or dashboard address taken. */
export const MAX_PUSH_URL = 2048;
/** Request and answer bounds, and the deadline of one request (as the webhook's). */
export const PUSH_LIMITS = Object.freeze({
  timeoutMs: 8000,
  maxRequestBytes: 16384,
  maxResponseBytes: 4096,
});
/** An access token or a password as ntfy and Gotify take it: printable ASCII, no spaces. */
export const PUSH_TOKEN = /^[\x21-\x7e]{1,512}$/;
/** What the channels do when acceptance is unknown: one resend, 2 minutes later (as D30). */
export const PUSH_UNKNOWN = Object.freeze({ resendAfterMs: 2 * 60 * 1000, maxResends: 1 });

export class PushConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PushConfigError';
  }
}

const loopbackList = new net.BlockList();
loopbackList.addSubnet('127.0.0.0', 8);
loopbackList.addAddress('::1', 'ipv6');

/** Whether `hostname` (a URL's) names this computer: localhost or a loopback address. */
export function loopbackHost(hostname) {
  const host = String(hostname ?? '')
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  const family = net.isIP(host);
  return Boolean(family) && loopbackList.check(host, family === 6 ? 'ipv6' : 'ipv4');
}

/**
 * Parses a server address (`label` names the field in errors, which never repeat the value):
 * http: or https:, a host, no user name or password (credentials have their own fields, which
 * are sealed), no query or fragment, at most 2048 characters. A path is kept (a server behind a
 * reverse proxy under /ntfy), without its trailing slash. Plain http: to another computer needs
 * `allowPlainHttp`: the token or password and every notification would cross the network
 * unencrypted. Returns the URL.
 */
export function parseServerUrl(
  value,
  { label = 'The server address', allowPlainHttp = false } = {}
) {
  const text = String(value ?? '').trim();
  if (!text) throw new PushConfigError(`${label} is required.`);
  if (text.length > MAX_PUSH_URL)
    throw new PushConfigError(`${label} is longer than ${MAX_PUSH_URL} characters.`);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new PushConfigError(`${label} is not a valid address.`);
  }
  // No "//" in these texts: safeReason() takes "https://." for a URL and would show "[url]".
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    throw new PushConfigError(`${label} must be an http: or https: address.`);
  if (url.username || url.password)
    throw new PushConfigError(
      `${label} must not contain a user name or password: use the credential fields, which Uptime Goblin keeps sealed.`
    );
  if (!url.hostname) throw new PushConfigError(`${label} has no host name.`);
  if (url.search || url.hash || text.includes('?') || text.includes('#'))
    throw new PushConfigError(`${label} must not contain a query (?) or fragment (#).`);
  if (url.protocol === 'http:' && !allowPlainHttp && !loopbackHost(url.hostname))
    throw new PushConfigError(
      `${label} uses plain HTTP to another computer, so the token or password and every notification would cross the network unencrypted. Use an https: address, or switch on "Allow plain HTTP" for a network you trust.`
    );
  url.pathname = url.pathname.replace(/\/+$/, '') || '/';
  return url;
}

/**
 * The dashboard address a notification links to (optional): http: or https:, no user name or
 * password, at most 2048 characters. Returns the text as given (trimmed), or '' when empty.
 */
export function parseDashboardUrl(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  if (text.length > MAX_PUSH_URL)
    throw new PushConfigError(`Uptime Goblin's address is longer than ${MAX_PUSH_URL} characters.`);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new PushConfigError("Uptime Goblin's address is not a valid address.");
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    throw new PushConfigError("Uptime Goblin's address must be an http: or https: address.");
  if (url.username || url.password)
    throw new PushConfigError("Uptime Goblin's address must not contain a user name or password.");
  return url.href;
}

/** `base` (parseServerUrl's) with `segment` appended to its path. */
export function endpoint(base, segment = '') {
  const url = new URL(base.href);
  const path = url.pathname.replace(/\/+$/, '');
  url.pathname = `${path}/${segment}`;
  return url;
}

/** The host name a channel card shows (never the path, which may carry a topic). */
export function serverHost(value) {
  try {
    return new URL(String(value ?? '').trim()).hostname.replace(/^\[|\]$/g, '') || null;
  } catch {
    return null;
  }
}

const oneLine = (text, max) =>
  [
    ...String(text ?? '')
      .replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, ' ')
      .replace(/\s+/g, ' ')
      .trim(),
  ]
    .slice(0, max)
    .join('');

/** A notification's title: what it is about and whether it began or ended. */
export function pushTitle(event) {
  const name = oneLine(event?.name || event?.service || 'Uptime Goblin', 200) || 'Uptime Goblin';
  if (event?.rule === '__test') return `${name}: test notification`;
  return event?.kind === 'resolved' ? `${name} recovered` : `${name} alert`;
}

/** A notification's text: the alert's message, at most 2,000 characters. */
export function pushMessage(event) {
  const text = oneLine(event?.message, 2000);
  if (text) return text;
  return event?.kind === 'resolved' ? 'The alert recovered.' : 'An alert began.';
}

/** The priority for an event: `firing` for an alert that began, `resolved` for a recovery. */
export const pushPriority = (event, { firing, resolved }) =>
  event?.kind === 'resolved' ? resolved : firing;

/** Maps an HTTP answer to an outcome (pure). `name` is the channel's name in reasons. */
export function classifyPushResponse(name, status, headers = {}, nowMs = Date.now()) {
  if (status >= 200 && status <= 299) return accepted({ status });
  if ([408, 425, 429].includes(status) || status >= 500)
    return retry(parseRetryAfter(headers['retry-after'], nowMs), `${name} answered ${status}.`, {
      status,
    });
  if (status === 401 || status === 403)
    return pause(
      `${name} refused Uptime Goblin's credentials (${status}). Check the token or password under Configure → Notifications; queued alerts wait until it is fixed.`,
      { status }
    );
  if (status === 404 || status === 410)
    return pause(
      `${name} answered ${status}. Check the server address; queued alerts wait until it is fixed.`,
      { status, transient: true }
    );
  if (status >= 300 && status <= 399)
    return pause(
      `${name} answered with a redirect (${status}), which Uptime Goblin does not follow. Set the server address to the final address.`,
      { status, transient: true }
    );
  return failed(`${name} refused the notification (${status}).`, { status });
}

/** Maps a transport failure to an outcome (pure). */
export function classifyPushError(name, error) {
  if (error?.code === 'EPOLICY') return pause(error.message);
  if (isTlsError(error)) return pause(error.message, { transient: true });
  if (error?.code === 'ETOOLARGE') return failed(`The notification is too large for ${name}.`);
  if (error?.sent) return unknown(`${error.message} ${name} may have received the notification.`);
  return retry(null, error?.message || `${name} could not be reached.`);
}
