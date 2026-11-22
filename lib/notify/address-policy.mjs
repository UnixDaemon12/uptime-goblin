// Address rules for the environment webhook (GOBLIN_WEBHOOK_URL; roadmap §2.10, decision C14).
// It keeps what 1.4.2 allowed, loopback and plain http:, and now refuses link-local (including
// cloud metadata at 169.254.169.254), multicast and reserved addresses, using the same list as
// collectors (lib/destinations.mjs), also when they are embedded in an IPv6 address (NAT64,
// IPv4-compatible, IPv4-translated, 6to4). The rule is applied to every address a name
// resolves to, at connect time (lib/notify/http.mjs), so DNS cannot swap in a refused address
// afterwards.
import net from 'node:net';
import { destinationProblem, embeddedIPv4 } from '../destinations.mjs';

const loopback = new net.BlockList();
loopback.addSubnet('127.0.0.0', 8);
loopback.addAddress('::1', 'ipv6');

export const ENV_WEBHOOK_REFUSED =
  'The alert webhook address is link-local, multicast or reserved, and Uptime Goblin does not send there. Point GOBLIN_WEBHOOK_URL at another address.';

/** null when the env webhook may connect to `address` (an IP address), otherwise the reason. */
export async function envWebhookAddressProblem(address) {
  const bare = String(address ?? '').split('%')[0];
  const family = net.isIP(bare);
  if (!family) return 'The alert webhook host did not resolve to an IP address.';
  // Loopback stays allowed for the env webhook only, as in 1.4.2 (destinations.mjs refuses it
  // for collectors unless GOBLIN_ALLOW_LOOPBACK is set). An IPv6 address embedding a loopback
  // IPv4 address (NAT64, IPv4-compatible, IPv4-translated, 6to4) is treated as that loopback
  // address.
  if (loopback.check(bare, family === 6 ? 'ipv6' : 'ipv4')) return null;
  const inner = embeddedIPv4(bare);
  if (inner && loopback.check(inner, 'ipv4')) return null;
  const literal = family === 6 ? `[${bare}]` : bare;
  return (await destinationProblem(`http://${literal}/`)) ? ENV_WEBHOOK_REFUSED : null;
}

export class WebhookUrlError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WebhookUrlError';
  }
}

/** The longest GOBLIN_WEBHOOK_URL taken: a chat webhook's address with its token fits easily. */
export const MAX_WEBHOOK_URL = 2048;

/**
 * Parses GOBLIN_WEBHOOK_URL: http: or https:, a host, no user name or password (fetch in 1.4.2
 * refused those too), and at most 2048 characters (it was taken at any length and sent with
 * every notification). Errors never repeat the URL, which may carry a secret.
 */
export function parseWebhookUrl(value) {
  const text = String(value ?? '').trim();
  if (text.length > MAX_WEBHOOK_URL)
    throw new WebhookUrlError(`GOBLIN_WEBHOOK_URL is longer than ${MAX_WEBHOOK_URL} characters.`);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new WebhookUrlError('GOBLIN_WEBHOOK_URL is not a valid URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:')
    // No "//" in the text: safeReason() takes "https://." for a URL and would show "[url]".
    throw new WebhookUrlError('GOBLIN_WEBHOOK_URL must be an http: or https: address.');
  if (url.username || url.password)
    throw new WebhookUrlError('GOBLIN_WEBHOOK_URL must not contain a user name or password.');
  if (!url.hostname) throw new WebhookUrlError('GOBLIN_WEBHOOK_URL has no host name.');
  url.hash = '';
  return url;
}

/**
 * Whether `url` (parseWebhookUrl's) is plain http: to a host other than this computer's
 * loopback: its path and query (where chat webhooks keep their token), every notification and
 * its signature then cross the network unencrypted. Allowed as in 1.4.2, with a start warning.
 */
export function plainWebhookHost(url) {
  if (url.protocol !== 'http:') return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const family = net.isIP(host);
  if (host.toLowerCase() === 'localhost') return null;
  if (family && loopback.check(host, family === 6 ? 'ipv6' : 'ipv4')) return null;
  return host;
}

export const PUSH_REFUSED =
  'The notification server address is link-local, multicast or reserved, and Uptime Goblin does not send there. Use another address.';
export const PUSH_LOOPBACK =
  'The notification server address is a loopback address (the Uptime Goblin host itself), which Uptime Goblin does not send to by default. Set GOBLIN_ALLOW_LOOPBACK=1 to use a server on the Uptime Goblin host.';

/**
 * null when the ntfy or Gotify channel may connect to `address` (an IP address), otherwise the
 * reason. These channels take the collectors' rule (lib/destinations.mjs), not the env
 * webhook's: link-local (cloud metadata included), multicast, unspecified and reserved
 * addresses are refused, also embedded in an IPv6 address, and loopback is refused unless
 * GOBLIN_ALLOW_LOOPBACK is set. Private (RFC 1918, ULA) addresses stay allowed for a homelab
 * server. Like the webhook's, it runs on every address a name resolves to at connect time
 * (lib/notify/http.mjs), so DNS cannot swap in a refused address afterwards.
 */
export async function pushAddressProblem(address) {
  const bare = String(address ?? '').split('%')[0];
  const family = net.isIP(bare);
  if (!family) return 'The notification server host did not resolve to an IP address.';
  const literal = family === 6 ? `[${bare}]` : bare;
  const reason = await destinationProblem(`http://${literal}/`);
  if (!reason) return null;
  return /loopback/i.test(reason) ? PUSH_LOOPBACK : PUSH_REFUSED;
}
