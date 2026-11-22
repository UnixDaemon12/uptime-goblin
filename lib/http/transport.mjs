// How a request reached Uptime Goblin (sessions spec §6.2). A session cookie is only as private as the
// connection it travels on, so the transport decides whether a browser may sign in and which
// cookie it gets:
//
//   https     a trusted reverse proxy says the browser used HTTPS (X-Forwarded-Proto: https)
//   loopback  a browser or script on the Uptime Goblin host itself, with no forwarding headers, that
//             asked for a loopback name (localhost, 127.x.x.x, [::1])
//   http      anything else: plain HTTP on the network, or a proxy Uptime Goblin cannot believe
//
// The Host header never makes a request `loopback`: a LAN client sending `Host: localhost` is
// still `http`. It can only take `loopback` away: a loopback peer asking for another name (an
// GOBLIN_ALLOWED_HOSTS entry such as goblin.example) is a proxy on this host that sends no
// forwarding headers, relaying browsers from anywhere, and is `http`. The browser's Origin never
// changes the transport either; the login route only uses it to refuse (routes/auth.mjs).
import net from 'node:net';
import { requestHeader } from '../legacy-names.mjs';

/**
 * Headers that show a request came through a proxy. Any of them makes a loopback peer `http`
 * (a proxy on the same host is not the owner's own browser), X-Forwarded-Proto included.
 */
export const forwardingHeaders = Object.freeze([
  'x-forwarded-for',
  'x-forwarded-proto',
  'x-forwarded-host',
  'forwarded',
  'x-real-ip',
]);

// ::1 and IPv4-mapped 127.0.0.0/8 in any IPv6 spelling ('0:0:0:0:0:0:0:1', '::ffff:7f00:1').
const loopbackV6 = new net.BlockList();
loopbackV6.addAddress('::1', 'ipv6');
loopbackV6.addSubnet('::ffff:7f00:0', 104, 'ipv6');

/** 127.0.0.0/8, ::1 and IPv4-mapped 127.x.x.x: a peer on this host. */
export function isLoopbackPeer(peer) {
  if (typeof peer !== 'string') return false;
  if (net.isIPv4(peer)) return peer.startsWith('127.');
  return net.isIPv6(peer) && loopbackV6.check(peer, 'ipv6');
}

/**
 * True for a Host header (or an Origin's host) that names this computer: `localhost`,
 * 127.0.0.0/8 or `[::1]`, with or without a port, in any case. The same names the default
 * GOBLIN_ALLOWED_HOSTS and the installer treat as loopback.
 */
export function isLoopbackHost(host) {
  return (
    typeof host === 'string' &&
    /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?$/i.test(host)
  );
}

// The last comma-separated element: the one the nearest (trusted) proxy added. Anything a
// client sent before it is the client's own claim.
const lastElement = value => {
  const text = Array.isArray(value) ? value.join(',') : String(value);
  return text.slice(text.lastIndexOf(',') + 1).trim();
};
const protocol = value => {
  const lower = value.replace(/^"(.*)"$/, '$1').toLowerCase();
  return lower === 'http' || lower === 'https' ? lower : null;
};

// The last proto= of a Forwarded header (RFC 7239): its last element, or earlier ones when the
// last element names none, so a proxy that appends `for=` only still leaves the earlier proto.
function forwardedProto(value) {
  const text = Array.isArray(value) ? value.join(',') : String(value);
  let found = null;
  for (const element of text.split(','))
    for (const pair of element.split(';')) {
      const at = pair.indexOf('=');
      if (at > 0 && pair.slice(0, at).trim().toLowerCase() === 'proto')
        found = protocol(pair.slice(at + 1).trim());
    }
  return found;
}

/**
 * The transport of a request: `{kind, forwardedProto, proxied}`.
 *
 * - `proxied`: any of forwardingHeaders is present (believed or not).
 * - `forwardedProto`: only from a trusted peer (`trusted(peer)`): the last element of
 *   X-Forwarded-Proto, or when that header is absent the last proto= of Forwarded; `http`,
 *   `https` or null.
 * - `kind`: `https` when forwardedProto is https; `loopback` for a loopback peer that sent no
 *   forwarding header and a loopback Host (isLoopbackHost); otherwise `http`.
 */
export function decideTransport({ peer, headers = {}, trusted = null }) {
  const proxied = forwardingHeaders.some(name => headers[name] !== undefined);
  let proto = null;
  if (typeof trusted === 'function' && trusted(peer)) {
    if (headers['x-forwarded-proto'] !== undefined)
      proto = protocol(lastElement(headers['x-forwarded-proto']));
    else if (headers.forwarded !== undefined) proto = forwardedProto(headers.forwarded);
  }
  const kind =
    proto === 'https'
      ? 'https'
      : isLoopbackPeer(peer) && !proxied && isLoopbackHost(headers.host)
        ? 'loopback'
        : 'http';
  return { kind, forwardedProto: proto, proxied };
}

/** The scheme of an Origin header ('https:', 'http:', …), or null when it is not a URL. */
export function originScheme(origin) {
  if (typeof origin !== 'string' || !origin) return null;
  try {
    return new URL(origin).protocol;
  } catch {
    return null;
  }
}

/** The lower-case host (with a non-default port) of an Origin header, or null. */
export function originHost(origin) {
  if (typeof origin !== 'string' || !origin) return null;
  try {
    const host = new URL(origin).host.toLowerCase();
    return host || null;
  } catch {
    return null;
  }
}

/**
 * True for a request made by a browser page: it carries Sec-Fetch-Site (every current browser
 * sends it over HTTPS and to localhost) or X-Goblin-Client (the web app always sends it; X-Orbit-Client before 1.5).
 * Sec-Fetch-Mode is not enough, because Node's fetch sends it too and scripts use Node's fetch.
 * A browser context's Authorization header is never evaluated (a browser that cached 1.4.x
 * Basic credentials keeps sending them), so it cannot be counted as a guess or lock anyone out.
 * Browsers send no fetch metadata to a plain-HTTP address on the network, so there a request
 * the browser makes on its own (a navigation, a link, an image) carries neither header and is
 * taken for a script's: where Uptime Goblin accepts Basic there, a 1.4.x Basic login it remembers is
 * checked and counted like one.
 */
export function browserContext(headers = {}) {
  return headers['sec-fetch-site'] !== undefined || requestHeader(headers, 'Client') !== undefined;
}
