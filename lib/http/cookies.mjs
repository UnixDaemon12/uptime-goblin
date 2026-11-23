// Uptime Goblin's session cookie (sessions spec §6.3, D23). Cookies are not isolated by port, and a
// parent domain's cookies (Cloudflare Access, Authelia, other homelab apps) reach Uptime Goblin too, so
// only Uptime Goblin's own cookie may decide anything: other cookies, however large or malformed, are
// skipped and never fail a request. There is no size cap here; Node refuses a request whose
// headers pass its own limit (16 KiB by default) with 431 before Uptime Goblin sees it.

import { legacySessionCookieName } from '../legacy-names.mjs';

// RFC 7230 token characters: what a cookie name may consist of.
const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

// A piece without its leading and trailing spaces and tabs. Two indexes, not a regular
// expression: `/[ \t]+$/` retries from every position of a run of blanks that does not end the
// piece, which is quadratic, and every request that passes the Host allowlist is parsed before
// any sign-in, so one 16 KiB Cookie header of blanks would stall the whole process.
function trimBlanks(text) {
  let start = 0,
    end = text.length;
  while (start < end && (text[start] === ' ' || text[start] === '\t')) start++;
  while (end > start && (text[end - 1] === ' ' || text[end - 1] === '\t')) end--;
  return text.slice(start, end);
}

/**
 * Parses the Cookie headers of a request (`req.headersDistinct.cookie`, an array, or
 * undefined). Each header is split on `;`; pieces are trimmed of spaces and tabs, and empty
 * pieces, pieces whose `=` is missing or first, and names that are not tokens are skipped. One
 * pair of surrounding double quotes is removed from a value. `all(name)` returns every value
 * of exactly that name, in the order sent.
 */
export function readCookies(values) {
  const found = new Map();
  for (const header of Array.isArray(values) ? values : values === undefined ? [] : [values]) {
    if (typeof header !== 'string') continue;
    for (const raw of header.split(';')) {
      const piece = trimBlanks(raw);
      const at = piece.indexOf('=');
      if (at < 1) continue;
      const name = piece.slice(0, at);
      if (!token.test(name)) continue;
      let value = piece.slice(at + 1);
      if (value.length >= 2 && value.startsWith('"') && value.endsWith('"'))
        value = value.slice(1, -1);
      let list = found.get(name);
      if (!list) found.set(name, (list = []));
      list.push(value);
    }
  }
  return Object.freeze({ all: name => [...(found.get(name) ?? [])] });
}

/**
 * The session cookie's name on a transport (lib/http/transport.mjs). On `https` the `__Host-`
 * prefix makes the browser refuse the cookie unless it is Secure, host-only and Path=/, so a
 * plain-HTTP page or a sibling subdomain cannot plant one (cookie tossing). `loopback` and
 * `http` (only with GOBLIN_INSECURE_HTTP_SESSIONS=1) cannot use the prefix: browsers refuse
 * Secure cookies there. Each transport reads only its own name.
 */
export function sessionCookieName(kind) {
  return kind === 'https' ? '__Host-goblin_session' : 'goblin_session';
}

/**
 * The Set-Cookie value for a session. HttpOnly keeps it from page scripts; SameSite=Strict
 * keeps other sites from sending it. Without `maxAgeSeconds` it is a browser-session cookie
 * (closing the browser signs out); with it, it persists ("Keep me signed in").
 */
export function sessionCookie({ kind, value, maxAgeSeconds = null }) {
  const attributes =
    kind === 'https'
      ? 'Path=/; Secure; HttpOnly; SameSite=Strict'
      : 'Path=/; HttpOnly; SameSite=Strict';
  const cookie = `${sessionCookieName(kind)}=${value}; ${attributes}`;
  return maxAgeSeconds === null || maxAgeSeconds === undefined
    ? cookie
    : `${cookie}; Max-Age=${maxAgeSeconds}`;
}

/** The Set-Cookie value that removes the session cookie of a transport. */
export function expiredSessionCookie(kind) {
  return sessionCookie({ kind, value: '', maxAgeSeconds: 0 });
}

/**
 * The Set-Cookie values that remove the session cookies of their names before 1.5 (orbit_session
 * and __Host-orbit_session, lib/legacy-names.mjs) that `cookies` (readCookies()) carries: an answer
 * that sets or ends the session cookie removes them too, so none outlives the change.
 */
export function expiredLegacySessionCookies(cookies) {
  return ['https', 'http']
    .filter(kind => cookies.all(legacySessionCookieName(kind)).length > 0)
    .map(kind => {
      const attributes =
        kind === 'https'
          ? 'Path=/; Secure; HttpOnly; SameSite=Strict'
          : 'Path=/; HttpOnly; SameSite=Strict';
      return `${legacySessionCookieName(kind)}=; ${attributes}; Max-Age=0`;
    });
}
