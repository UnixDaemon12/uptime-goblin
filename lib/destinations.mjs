// Outbound destination policy for collectors. Uptime Goblin is meant to reach private homelab
// addresses, so RFC 1918 and ULA ranges stay allowed. Link-local (including cloud metadata
// at 169.254.169.254), multicast, unspecified and reserved ranges are never collection
// targets. Loopback is refused by default so the Uptime Goblin host's own local-only services
// cannot be reached through a source; GOBLIN_ALLOW_LOOPBACK=1 opts in.
//
// An IPv6 address can carry an IPv4 address inside it: NAT64 (the well-known 64:ff9b::/96 and
// the local-use 64:ff9b:1::/96 of RFC 8215), the deprecated IPv4-compatible form (::/96), SIIT's
// IPv4-translated form (::ffff:0:0:0/96, RFC 2765) and 6to4 (2002::/16). A NAT64 gateway or a
// 6to4 relay forwards such an address to the IPv4 host it names, so the IPv4 rules apply to that
// host as well: 64:ff9b::a9fe:a9fe is refused like 169.254.169.254. (RFC 2765 gives the
// IPv4-translated form to IPv6 hosts, so a translator should not send it to IPv4; it gets the
// same rules anyway, since nothing a homelab monitors lives there.) IPv4-mapped ::ffff:0:0/96 is
// matched by net.BlockList itself. A network-specific NAT64 prefix, or the local-use /48 laid
// out other than as 64:ff9b:1::/96, cannot be told from an ordinary address and is not
// recognised. The env webhook shares these rules (lib/notify/address-policy.mjs).
import net from 'node:net';
import dns from 'node:dns/promises';

const always = new net.BlockList();
always.addSubnet('0.0.0.0', 8);
always.addSubnet('169.254.0.0', 16);
always.addSubnet('224.0.0.0', 3); // multicast, reserved and broadcast
always.addAddress('::', 'ipv6');
always.addSubnet('fe80::', 10, 'ipv6');
always.addSubnet('ff00::', 8, 'ipv6');
always.addAddress('fd00:ec2::254', 'ipv6'); // AWS IPv6 metadata

const loopback = new net.BlockList();
loopback.addSubnet('127.0.0.0', 8);
loopback.addAddress('::1', 'ipv6');

let policy = {
  allowLoopback: false,
  lookup: host => dns.lookup(host, { all: true, verbatim: true }),
  // Monotonic, so a system clock change cannot pin a cached answer.
  now: () => performance.now(),
};

// getaddrinfo cannot be cancelled and libuv runs only a few at a time, so concurrent checks
// share one lookup per name while it is in flight. A lookup that hung is remembered for
// under a second so callers arriving together share its failure; retries (at least a
// second later) and quick failures such as "not found" always ask DNS again.
const lookups = new Map();
const RESOLVED_MS = 30000,
  // Shorter than the smallest retry delay (1 s): retries always ask DNS again, while
  // callers arriving together still share one lookup.
  STALLED_MS = 900,
  STALLED_CODES = new Set(['EAI_AGAIN', 'ETIMEOUT', 'ETIMEDOUT', 'ESERVFAIL']),
  MAX_NAMES = 500;

// Reconfiguring (tests inject lookups) also drops cached answers so results stay predictable.
export function configureDestinations(options = {}) {
  policy = { ...policy, ...options };
  lookups.clear();
}

function resolve(host) {
  const cached = lookups.get(host);
  // An entry without an expiry is still in flight and is shared.
  if (cached && (cached.expires === undefined || cached.expires > policy.now()))
    return cached.addresses;
  const { lookup } = policy,
    started = policy.now(),
    entry = {},
    keep = ms => {
      if (lookups.get(host) !== entry) return;
      if (ms > 0) entry.expires = policy.now() + ms;
      else lookups.delete(host);
    };
  entry.addresses = new Promise(settle => settle(lookup(host))).then(
    result => {
      keep(RESOLVED_MS);
      return result.map(item => item.address);
    },
    error => {
      // Only a lookup that really hung is remembered; a quick failure (a DNS server
      // restarting) is cheap to repeat, so a retry gets a fresh answer.
      keep(STALLED_CODES.has(error?.code) && policy.now() - started >= 1000 ? STALLED_MS : 0);
      throw error;
    }
  );
  lookups.delete(host);
  if (lookups.size >= MAX_NAMES) lookups.delete(lookups.keys().next().value);
  lookups.set(host, entry);
  return entry.addresses;
}

// The eight 16-bit groups of a valid IPv6 address (a zone id is ignored), or null.
function ipv6Groups(address) {
  let text = String(address).split('%')[0].toLowerCase(),
    tail = [];
  // A trailing dotted IPv4 part ("::1.2.3.4", "64:ff9b::1.2.3.4") is two groups.
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number);
    tail = [(a << 8) | b, (c << 8) | d];
    text = text.slice(0, dotted.index);
    if (text.endsWith(':') && !text.endsWith('::')) text = text.slice(0, -1);
  }
  const groups = part => (part ? part.split(':').map(group => parseInt(group, 16)) : []);
  let words;
  if (text.includes('::')) {
    const [head, rest] = text.split('::').map(groups);
    const fill = 8 - head.length - rest.length - tail.length;
    if (fill < 0) return null;
    words = [...head, ...Array(fill).fill(0), ...rest, ...tail];
  } else words = [...groups(text), ...tail];
  return words.length === 8 && words.every(word => word >= 0 && word <= 0xffff) ? words : null;
}

/**
 * The IPv4 address an IPv6 address embeds and that a gateway would forward to: NAT64
 * (64:ff9b::/96 and the local-use 64:ff9b:1::/96, the last 32 bits), IPv4-compatible (::/96
 * other than :: and ::1, the last 32 bits), IPv4-translated (::ffff:0:0:0/96, the last 32 bits)
 * or 6to4 (2002::/16, bits 16-47). null for anything else, IPv4 addresses included.
 */
export function embeddedIPv4(address) {
  if (!net.isIPv6(String(address).split('%')[0])) return null;
  const w = ipv6Groups(address);
  if (!w) return null;
  const v4 = (high, low) => `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
  const zero = (from, to) => w.slice(from, to).every(word => word === 0);
  if (w[0] === 0x64 && w[1] === 0xff9b && zero(2, 6)) return v4(w[6], w[7]);
  if (w[0] === 0x64 && w[1] === 0xff9b && w[2] === 1 && zero(3, 6)) return v4(w[6], w[7]);
  if (zero(0, 6) && !(w[6] === 0 && w[7] <= 1)) return v4(w[6], w[7]);
  if (zero(0, 4) && w[4] === 0xffff && w[5] === 0) return v4(w[6], w[7]);
  if (w[0] === 0x2002) return v4(w[1], w[2]);
  return null;
}

function problem(address) {
  const type = net.isIPv4(address) ? 'ipv4' : 'ipv6';
  if (always.check(address, type))
    return 'Uptime Goblin does not collect from link-local, multicast or reserved addresses.';
  if (!policy.allowLoopback && loopback.check(address, type))
    return 'Uptime Goblin does not collect from loopback addresses by default. Set GOBLIN_ALLOW_LOOPBACK=1 to monitor services on the Uptime Goblin host itself.';
  const inner = embeddedIPv4(address);
  return inner ? problem(inner) : null;
}

async function check(url, lookupFailed) {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  let addresses;
  if (net.isIP(host)) addresses = [host];
  else if (host === 'localhost' || host.endsWith('.localhost')) addresses = ['127.0.0.1', '::1'];
  else {
    try {
      addresses = await resolve(host);
    } catch (error) {
      return lookupFailed(error);
    }
  }
  for (const address of addresses) {
    const reason = net.isIP(address) ? problem(address) : null;
    if (reason) return { addresses: [...addresses], problem: reason };
  }
  return { addresses: [...addresses], problem: null };
}

/**
 * Exact policy-checked addresses for callers that connect to them without resolving the name
 * again: collectors and Website checks (lib/net/outbound.mjs) and SMTP (lib/mail.mjs).
 */
export async function resolvedDestination(url) {
  const result = await check(url, error => {
    throw error;
  });
  if (!result.addresses.length || result.addresses.some(address => !net.isIP(address)))
    throw Object.assign(new Error('DNS did not return usable IP addresses.'), {
      code: 'ENOTFOUND',
    });
  return result;
}

/**
 * Returns a user-facing reason when the URL's host resolves to a refused address, or null.
 * Names that fail to resolve are left to the request itself, which reports the DNS error.
 * The check happens before connecting: a caller that then resolves the name again (rather than
 * connecting to resolvedDestination()'s addresses, or checking each address at connect time as
 * the env webhook does) can be given a different answer a moment later (answers are also
 * reused for up to 30 seconds).
 */
export async function destinationProblem(url) {
  return (await check(url, () => ({ addresses: [], problem: null }))).problem;
}

/**
 * Collector variant of destinationProblem: a name that fails to resolve rejects with the
 * lookup error, so the caller can report DNS at once instead of fetch resolving it again.
 */
export async function checkDestination(url) {
  return (
    await check(url, error => {
      throw error;
    })
  ).problem;
}
