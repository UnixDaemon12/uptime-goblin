import net from 'node:net';
import { quoted } from './environment.mjs';

// Per-client sign-in throttling. After a few free attempts, each failed credential
// doubles the lockout for that client, so a reachable Uptime Goblin cannot be guessed at
// network speed. Correct credentials are also refused while locked, so the lockout
// is never an oracle. Only memory is used; a restart clears it.
export class LoginThrottle {
  #clients = new Map();
  #pending = new Map();
  // Clients that recently presented the correct password, and recent failed password checks
  // from everyone. When failures across all clients exceed the budget (an attacker spreading
  // guesses over many addresses), only recently trusted clients may try to sign in.
  #trusted = new Map();
  #recent = [];
  constructor({
    freeAttempts = 5,
    baseMs = 1000,
    maxMs = 15 * 60 * 1000,
    forgetMs = 60 * 60 * 1000,
    maxClients = 10000,
    globalFailures = 50,
    globalWindowMs = 10 * 60 * 1000,
    trustMs = 30 * 24 * 60 * 60 * 1000,
    now = Date.now,
  } = {}) {
    Object.assign(this, {
      freeAttempts,
      baseMs,
      maxMs,
      forgetMs,
      maxClients,
      globalFailures,
      globalWindowMs,
      trustMs,
      now,
    });
  }
  /** True while failures from all clients together exceed the budget for the window. */
  globalLocked() {
    const cutoff = this.now() - this.globalWindowMs;
    while (this.#recent.length && this.#recent[0] <= cutoff) this.#recent.shift();
    return this.#recent.length >= this.globalFailures;
  }
  /** True for a client that presented the correct password within trustMs. */
  trusted(key) {
    const until = this.#trusted.get(key);
    if (until === undefined) return false;
    if (until > this.now()) return true;
    this.#trusted.delete(key);
    return false;
  }
  #entry(key) {
    const entry = this.#clients.get(key);
    if (entry && this.now() - entry.last > this.forgetMs) {
      this.#clients.delete(key);
      return undefined;
    }
    return entry;
  }
  /** Milliseconds until this client may try again; 0 when not locked. */
  retryAfter(key) {
    const entry = this.#entry(key);
    return entry ? Math.max(0, entry.lockedUntil - this.now()) : 0;
  }
  failure(key) {
    const now = this.now(),
      entry = this.#entry(key) || { failures: 0, lockedUntil: 0, last: now };
    entry.failures++;
    entry.last = now;
    const excess = entry.failures - this.freeAttempts;
    if (excess > 0)
      entry.lockedUntil = now + Math.min(this.maxMs, this.baseMs * 2 ** Math.min(30, excess - 1));
    // Re-insert so Map order approximates least-recently-failed first.
    this.#clients.delete(key);
    this.#clients.set(key, entry);
    // When full, forget the oldest client that is not locked out; evicting locked clients
    // would let an attacker reset their own lockouts by failing from many other addresses.
    if (this.#clients.size > this.maxClients) {
      let victim;
      for (const [candidate, value] of this.#clients)
        if (value.lockedUntil <= now) {
          victim = candidate;
          break;
        }
      this.#clients.delete(victim ?? this.#clients.keys().next().value);
    }
    this.#recent.push(now);
    if (this.#recent.length > this.globalFailures) this.#recent.shift();
  }
  /** A fully checked password: clears the client's failures and trusts it. */
  success(key) {
    this.#clients.delete(key);
    this.trust(key);
  }
  /** Any request with the correct password (checked or cached) keeps its client trusted. */
  trust(key) {
    this.#trusted.delete(key);
    this.#trusted.set(key, this.now() + this.trustMs);
    while (this.#trusted.size > this.maxClients)
      this.#trusted.delete(this.#trusted.keys().next().value);
  }
  /**
   * Starts a password check for a client and returns a release function, or null when the
   * client already has checks in progress that, with its failures, use up its free
   * attempts. Parallel guesses therefore get no more checks than sequential ones.
   */
  begin(key) {
    const pending = this.#pending.get(key) ?? 0,
      failures = this.#entry(key)?.failures ?? 0;
    if (pending > 0 && failures + pending >= this.freeAttempts) return null;
    this.#pending.set(key, pending + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const left = (this.#pending.get(key) ?? 1) - 1;
      if (left > 0) this.#pending.set(key, left);
      else this.#pending.delete(key);
    };
  }
  get size() {
    return this.#clients.size;
  }
}

function expandIPv6(address) {
  let text = address.split('%')[0].toLowerCase();
  const tail = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (tail) {
    const [a, b, c, d] = tail[1].split('.').map(Number);
    text =
      text.slice(0, -tail[1].length) +
      ((a << 8) | b).toString(16) +
      ':' +
      ((c << 8) | d).toString(16);
  }
  const [head, rest] = text.includes('::') ? text.split('::') : [text, undefined];
  const left = head ? head.split(':') : [],
    right = rest ? rest.split(':') : [];
  const groups =
    rest === undefined
      ? left
      : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.map(group => group.padStart(4, '0'));
}

/**
 * The throttling key for an address. IPv4-mapped IPv6 becomes plain IPv4, and IPv6
 * is grouped by /64 because one client normally controls a whole /64.
 */
export function throttleKey(address) {
  if (typeof address !== 'string' || !address) return 'unknown';
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return mapped[1];
  if (net.isIPv4(address)) return address;
  if (!net.isIPv6(address.split('%')[0])) return address.slice(0, 64);
  const groups = expandIPv6(address);
  if (groups.slice(0, 6).join(':') === '0000:0000:0000:0000:0000:ffff')
    return [parseInt(groups[6], 16), parseInt(groups[7], 16)]
      .flatMap(word => [word >> 8, word & 255])
      .join('.');
  return groups.slice(0, 4).join(':') + '::/64';
}

// Every peer in a trusted range chooses the client address Uptime Goblin throttles and records for it
// (X-Forwarded-For) and whether its request counts as HTTPS (X-Forwarded-Proto). A proxy is one
// host or a small network: a range wider than these prefix lengths is refused, one wider than
// the second pair (a /24 of IPv4, one IPv6 network) is a start warning.
const widestPrefix = { ipv4: 8, ipv6: 32 },
  widePrefix = { ipv4: 24, ipv6: 64 };

// The same rule for the list as a whole: many ranges each within the limit (256 /8 ranges)
// trusted every client, as 0.0.0.0/0 does. All of them together may cover at most two of the
// widest ranges (the private IPv4 ranges and 100.64.0.0/10 fit; loopback is not counted, since
// no other host can connect from it), and the list holds at most 64 entries, as
// GOBLIN_ALLOWED_HOSTS does: each request's peer is checked against every one.
const widestTotal = {
    ipv4: 2n ** BigInt(32 - widestPrefix.ipv4 + 1),
    ipv6: 2n ** BigInt(128 - widestPrefix.ipv6 + 1),
  },
  maxTrustedEntries = 64;

// The /96 prefixes whose IPv6 addresses each stand for one IPv4 address, as 96 leading bits:
// the /96 forms lib/destinations.mjs reads (embeddedIPv4()), and IPv4-mapped, which net.BlockList
// matches itself. IPv4-mapped (::ffff:0:0/96): net.BlockList checks an IPv4 peer as that
// address, so an IPv6 range holding them trusts IPv4 peers too. NAT64, the well-known
// 64:ff9b::/96 and the local-use 64:ff9b:1::/96 (RFC 8215): a NAT64 gateway connects from
// 64:ff9b::a.b.c.d for the IPv4 client a.b.c.d, so the whole prefix is the IPv4 internet. SIIT's
// IPv4-translated ::ffff:0:0:0/96 (RFC 2765) and the deprecated IPv4-compatible ::/96 (other
// than :: and ::1, RFC 4291) carry an IPv4 address in their last 32 bits the same way. 6to4
// (2002::/16, which destinations.mjs reads too) is not one of them: a 6to4 address is a host in
// the IPv6 /48 of the IPv4 address in its bits 16-47, an IPv6 network like any other, held to
// the IPv6 widths (2002::/16 itself is wider than /32 and refused).
const bitsOf = address =>
  expandIPv6(address)
    .map(group => parseInt(group, 16).toString(2).padStart(16, '0'))
    .join('');
const embeddingPrefixes = Object.freeze([
  { name: 'the IPv4-mapped prefix ::ffff:0:0/96', bits: bitsOf('::ffff:0:0').slice(0, 96) },
  { name: 'the NAT64 prefix 64:ff9b::/96', bits: bitsOf('64:ff9b::').slice(0, 96) },
  { name: 'the local-use NAT64 prefix 64:ff9b:1::/96', bits: bitsOf('64:ff9b:1::').slice(0, 96) },
  {
    name: 'the IPv4-translated prefix ::ffff:0:0:0/96',
    bits: bitsOf('::ffff:0:0:0').slice(0, 96),
  },
  { name: 'the IPv4-compatible prefix ::/96', bits: bitsOf('::').slice(0, 96) },
]);

/**
 * What a valid entry's range really covers: {type, prefix, loopback, within}. An IPv6 range
 * inside one of embeddingPrefixes is the IPv4 range it stands for (::ffff:10.0.0.0/104 and
 * 64:ff9b::10.0.0.0/104 are 10.0.0.0/8), and one that holds a whole such prefix (::/0, ::/80,
 * 64:ff9b::/96, 64:ff9b::/64, ::/96) trusts every IPv4 address: an IPv4 /0. `within` names that
 * prefix then, else it is null. The addresses :: and ::1 alone are IPv6 (unspecified, loopback),
 * not IPv4-compatible. Only an IPv4-mapped address of 127.0.0.0/8 is loopback: a gateway or
 * translator never connects for a loopback client.
 */
function coverage(address, prefix, type) {
  if (type === 'ipv6') {
    const bits = bitsOf(address);
    if (prefix === 128 && /^0{127}[01]$/.test(bits))
      return { type, prefix, loopback: bits.endsWith('1'), within: null };
    for (const [index, { name, bits: inner }] of embeddingPrefixes.entries()) {
      if (prefix <= 96 && bits.slice(0, prefix) === inner.slice(0, prefix))
        return { type: 'ipv4', prefix: 0, loopback: false, within: name };
      if (prefix > 96 && bits.slice(0, 96) === inner)
        return {
          type: 'ipv4',
          prefix: prefix - 96,
          loopback: index === 0 && prefix >= 104 && parseInt(bits.slice(96, 104), 2) === 127,
          within: name,
        };
    }
    return {
      type,
      prefix,
      loopback: prefix === 128 && bits === '0'.repeat(127) + '1',
      within: null,
    };
  }
  return { type, prefix, loopback: prefix >= 8 && address.split('.')[0] === '127', within: null };
}

/**
 * Parses GOBLIN_TRUST_PROXY into a check for peers whose X-Forwarded-For header may be
 * believed. '1', 'true', 'yes' and 'loopback' trust a proxy on the same host (loopback
 * peers); otherwise the value is a comma-separated list of proxy addresses or CIDR
 * ranges. Empty, '0', 'false' and 'no' disable forwarding support; a value of only commas and
 * blanks names no proxy and refuses the start (exit status 78). A range wider than /8
 * (IPv4) or /32 (IPv6), 0.0.0.0/0 and ::/0 included, refuses the start: with it any client
 * could pick its own lockout key and audit address and pass plain HTTP off as HTTPS; so does
 * an IPv6 range that stands for such an IPv4 range (an IPv4-mapped, NAT64, IPv4-translated or
 * IPv4-compatible /96 prefix, or any range holding one, is every IPv4 address), more than 64
 * entries, and ranges that together cover more than two such ranges. The check carries
 * `warnings`, the start warnings for ranges wider than /24 or /64.
 */
export function trustedProxies(value) {
  if (value === true) value = 'loopback';
  if (!value || /^(0|false|no|off)$/i.test(String(value).trim())) return null;
  const list = new net.BlockList(),
    warnings = [],
    total = { ipv4: 0n, ipv6: 0n };
  const entries = String(value)
    .split(',')
    .map(raw => raw.trim())
    .filter(Boolean);
  // Only commas and blanks: no proxy is named, yet the value is not one of those that turn
  // proxy trust off. It refuses, so that Uptime Goblin and the native installer, which judges the value
  // with this function, give one answer (it trusted no peer with no word at the start).
  if (!entries.length)
    throw Object.assign(
      new Error(
        `GOBLIN_TRUST_PROXY names no proxy: it holds only commas and blanks (it is ${quoted(value, 60)}). Name your reverse proxy (loopback for one on this computer, or its address), or leave it empty (or set it to off) to trust none.`
      ),
      { refusal: true }
    );
  if (entries.length > maxTrustedEntries)
    throw Object.assign(
      new Error(
        `GOBLIN_TRUST_PROXY has ${entries.length} entries; at most ${maxTrustedEntries} are allowed. Name your proxies' addresses, or the smallest ranges that hold them.`
      ),
      { refusal: true }
    );
  for (const entry of entries) {
    if (/^(1|true|yes|loopback)$/i.test(entry)) {
      list.addSubnet('127.0.0.0', 8);
      list.addAddress('::1', 'ipv6');
      continue;
    }
    const [address, bits, extra] = entry.split('/'),
      type = net.isIPv4(address) ? 'ipv4' : net.isIPv6(address) ? 'ipv6' : null;
    const prefix = bits === undefined ? null : Number(bits);
    if (
      !type ||
      extra !== undefined ||
      (bits !== undefined && (!/^\d{1,3}$/.test(bits) || prefix > (type === 'ipv4' ? 32 : 128)))
    )
      // Shown escaped and cut: the entry is what failed to parse, so it may hold anything, a
      // line break or a terminal escape that would forge a line of the log included.
      throw Object.assign(
        new Error(`GOBLIN_TRUST_PROXY has an invalid entry: ${quoted(entry, 60)}`),
        { refusal: true }
      );
    const covered = coverage(address, prefix ?? (type === 'ipv4' ? 32 : 128), type);
    if (prefix !== null) {
      // An IPv6 range that stands for IPv4 addresses says which, and as how wide an IPv4 range:
      // 64:ff9b::/96 is no wide IPv6 range, but it is every IPv4 address.
      const standsFor = covered.within
        ? ` (${covered.prefix === 0 ? `it holds ${covered.within}, which stands for every IPv4 address` : `inside ${covered.within} it stands for an IPv4 /${covered.prefix}`})`
        : '';
      if (covered.prefix < widestPrefix[covered.type])
        throw Object.assign(
          new Error(
            `GOBLIN_TRUST_PROXY entry ${entry.slice(0, 60)} trusts too many addresses${standsFor}: every client in a trusted range chooses the address Uptime Goblin records for it and whether it counts as HTTPS. Name your proxy's address, or the smallest range that holds it (no wider than /${widestPrefix.ipv4} for IPv4 or /${widestPrefix.ipv6} for IPv6).`
          ),
          { refusal: true }
        );
      if (covered.prefix < widePrefix[covered.type] && !covered.loopback)
        warnings.push(
          `GOBLIN_TRUST_PROXY entry ${entry.slice(0, 60)} trusts a wide range: every client in it chooses the address Uptime Goblin records and throttles for it, and whether it counts as HTTPS. Name only your proxy's address if you can.`
        );
    }
    if (!covered.loopback) {
      total[covered.type] += 2n ** BigInt((covered.type === 'ipv4' ? 32 : 128) - covered.prefix);
      if (total[covered.type] > widestTotal[covered.type])
        throw Object.assign(
          new Error(
            `GOBLIN_TRUST_PROXY trusts too many addresses in all: its ranges together cover more than two /${widestPrefix[covered.type]} ranges of ${covered.type === 'ipv4' ? 'IPv4' : 'IPv6'}, and every client in a trusted range chooses the address Uptime Goblin records for it and whether it counts as HTTPS. Name your proxies' addresses, or the smallest ranges that hold them.`
          ),
          { refusal: true }
        );
    }
    if (prefix === null) list.addAddress(address, type);
    else list.addSubnet(address, prefix, type);
  }
  // A mapped peer (a dual-stack listener's ::ffff:a.b.c.d) is checked as plain IPv4. net.BlockList
  // matches the two spellings across, both ways, so an entry written as an IPv4-mapped address or
  // range (kept as an IPv6 rule) trusts its proxy however the peer is spelled, as the plain entry
  // does; test/throttle.test.mjs pins that for each user of the check.
  const check = peer => {
    if (typeof peer !== 'string') return false;
    const plain = peer.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
    return list.check(plain, net.isIPv4(plain) ? 'ipv4' : 'ipv6');
  };
  check.warnings = Object.freeze(warnings);
  return check;
}

/**
 * How many connections the listener accepts at once (`maxConnections`), and how many of them
 * one client may hold by default (`maxConnectionsPerClient`), so that one client cannot take all
 * of them. lib/http/pipeline.mjs serverLimits holds these; they are here, in a module without
 * package dependencies (it, and the Uptime Goblin modules it imports, use only node: built-ins), so that
 * the native installer judges GOBLIN_MAX_CONNECTIONS_PER_CLIENT by the same rule as Uptime Goblin
 * (connectionsPerClient below) before an upgrade changes anything.
 */
export const connectionLimits = Object.freeze({ maxConnections: 256, maxConnectionsPerClient: 32 });

/**
 * GOBLIN_MAX_CONNECTIONS_PER_CLIENT: how many connections one client may hold open at once, a
 * whole number from 8 (a browser opens up to 6 to one site) to connectionLimits.maxConnections,
 * written in digits without a leading zero. Unset or empty is
 * connectionLimits.maxConnectionsPerClient. Anything else refuses the start (exit status 78)
 * before anything is written; the value is shown escaped and cut.
 */
export function connectionsPerClient(value) {
  const most = connectionLimits.maxConnections;
  if (value === undefined || value === null || value === '')
    return connectionLimits.maxConnectionsPerClient;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 8 && value <= most)
    return value;
  if (typeof value === 'string' && /^[1-9][0-9]{0,2}$/.test(value)) {
    const number = Number(value);
    if (number >= 8 && number <= most) return number;
  }
  throw Object.assign(
    new Error(
      `GOBLIN_MAX_CONNECTIONS_PER_CLIENT must be a whole number from 8 to ${most}, written in digits without a leading zero (empty for the default, ${connectionLimits.maxConnectionsPerClient}); it is ${quoted(String(value))}.`
    ),
    { refusal: true }
  );
}

function forwardedAddress(value) {
  let entry = value.trim();
  const bracketed = entry.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) entry = bracketed[1];
  else if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(entry)) entry = entry.split(':')[0];
  return net.isIP(entry) ? entry : null;
}

/**
 * The throttling key for a request. X-Forwarded-For is used only when the connecting
 * peer is a trusted proxy; then its last entry, the address that proxy saw, is used.
 */
export function clientAddress(req, trusted = null) {
  const peer = req.socket?.remoteAddress;
  if (typeof trusted === 'function' && trusted(peer)) {
    // Only the last entry matters (the one the proxy added); read it from the tail so a
    // client-supplied prefix, however long, cannot push Uptime Goblin back to the proxy's address.
    const forwarded = req.headers['x-forwarded-for'];
    const tail =
      typeof forwarded === 'string' ? forwarded.slice(forwarded.lastIndexOf(',') + 1) : '';
    const last = tail.length <= 64 ? forwardedAddress(tail) : null;
    if (last) return throttleKey(last);
  }
  return throttleKey(peer);
}
