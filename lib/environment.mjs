// The environment is input like a request body: HOST, PORT and the GOBLIN_* settings come from
// /etc/uptime-goblin.env, .env, Compose or a shell, typed by hand. Each is read by one rule, here or in
// the module that owns it (the audit settings in lib/audit/index.mjs, the capability flags in
// lib/features.mjs, GOBLIN_TRUST_PROXY and GOBLIN_MAX_CONNECTIONS_PER_CLIENT in lib/throttle.mjs,
// the keys in lib/keyring.mjs): a value that cannot mean anything refuses
// the start (exit status 78) before anything is read or written, and a value Uptime Goblin does not use
// is said once at the start instead of being taken silently for something else. A value is
// shown back escaped and cut, never raw: it could carry a terminal escape, a forged log line, or
// a secret pasted into the wrong variable.
// GOBLIN_SUPERVISED and GOBLIN_ALLOW_UNLIMITED are read by lib/resource-limits.mjs in server.mjs's
// main block, after the modules have loaded and before createApp(): for their refusals that order
// is what holds, not that nothing at all was read or written before them.
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { shellWord } from './admin-command.mjs';

const refusal = message => Object.assign(new Error(message), { refusal: true });

// What a terminal or a log reader would act on: the C0 and C1 controls and DEL (a line break, a
// tab, an escape), the Unicode line and paragraph separators (U+2028, U+2029) and the
// text-direction embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069).
// One set for what is escaped when shown and what a path from the environment or the command
// line may not hold (GOBLIN_DATA_DIR, --data-dir, the key files): two sets drifted apart, and a
// data directory one accepted made a key path the other refused. The direction marks (U+061C,
// U+200E, U+200F) are not in it, as measurement keys keep them: they override nothing.
const unprintable = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
// JSON.stringify escapes the C0 controls itself; this escapes the rest of the set.
const unescaped = new RegExp(unprintable.source, 'g');
// A character as the \u escape JSON writes for it.
const jsonEscape = character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;

const codePoint = character =>
  `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;

/**
 * Why `text` (a path from the environment or the command line) cannot be printed or used as it
 * is, or null: it holds one of the characters above, named by its code point (a refusal cuts
 * the path it quotes, so the character itself may not be shown).
 */
export function unprintableProblem(text) {
  const found = unprintable.exec(String(text));
  return found
    ? `a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (it holds ${codePoint(found[0])})`
    : null;
}

/**
 * `value` for a start warning or a refusal: quoted, cut to `max` characters (with … when cut)
 * and with every control character escaped, so a value of any size stays one short line.
 */
export function quoted(value, max = 40) {
  const text = String(value);
  const cut = text.length > max ? `${text.slice(0, max)}…` : text;
  return JSON.stringify(cut).replace(unescaped, jsonEscape);
}

// The characters of the set above that JSON.stringify writes as they are: DEL, the C1 controls,
// U+2028, U+2029 and the text-direction embeddings, overrides and isolates. (It escapes the C0
// controls itself, so the only line breaks in its output are those of its own indentation.)
const unescapedInJson = /[\u{7f}-\u{9f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/gu;

/**
 * `value` as JSON for a terminal (goblin-admin --json): JSON.stringify(value, null, space), with
 * each of those characters written as its \u escape inside the string that holds it. It is the
 * same JSON, so JSON.parse gives back `value` exactly, with nothing removed or cut; but saved text
 * in it cannot move the cursor, start a line of its own or reorder what a terminal shows.
 */
export function jsonText(value, space = 2) {
  return JSON.stringify(value, null, space).replace(unescapedInJson, jsonEscape);
}

const truthy = /^(1|true|yes|on)$/i,
  falsy = /^(0|false|no|off)$/i;

/**
 * A yes/no value as every Uptime Goblin flag reads it: true for 1, true, yes or on, false for 0, false,
 * no or off (any case), null when unset or empty, and undefined for anything else (a typo, or
 * a space around the word), which the caller warns about and replaces by its default.
 */
export function flagValue(text) {
  if (text === undefined || text === null || text === '') return null;
  if (truthy.test(text)) return true;
  if (falsy.test(text)) return false;
  return undefined;
}

/** The warning for a flag value that is neither yes nor no; never more than 40 characters of it. */
export const flagWarning = (name, text) =>
  `${name}=${quoted(text)} is not 1 or 0; the default applies.`;

/**
 * The yes/no setting `name` of `env`: `fallback` (off) when unset, empty or not a yes/no value;
 * the last also pushes its warning onto `warnings`. GOBLIN_ALLOW_LOOPBACK reads `on` as the
 * capability flags always did (it took only 1, true or yes, so `on` was silently off).
 * GOBLIN_SUPERVISED is read by flagValue too, but a value that is neither refuses the start
 * (supervisedSetting in lib/resource-limits.mjs): it turns a security check on.
 */
export function envFlag(env, name, warnings = [], fallback = false) {
  const text = env[name];
  const value = flagValue(text);
  if (value === undefined) warnings.push(flagWarning(name, text));
  return value ?? fallback;
}

/**
 * GOBLIN_LEGACY_BASIC as a start reads it: true (1, true, yes, on), false (0, false, no, off) or
 * null (unset or empty: the default, lib/features.mjs), any case. Any other value throws a
 * refusal (exit status 78), shown escaped: Basic is on by default for installs upgraded from
 * 1.4.x, so a typo meant as off (`of`, `disabled`) must not leave it on. server.mjs checks it
 * before anything is written, and the native installer checks /etc/uptime-goblin.env with it before an
 * upgrade stops the running Uptime Goblin.
 */
export function legacyBasicSetting(text) {
  const value = flagValue(text);
  if (value === undefined)
    throw refusal(
      `GOBLIN_LEGACY_BASIC must be 1 or 0 (true, yes or on; false, no or off), or empty for the default; it is ${quoted(text)}.`
    );
  return value;
}

/**
 * PORT: a port number from 1 to 65535 in decimal digits, without a leading zero. Unset or empty
 * is 4317. Number() took `abc`, `70000` and `4317.5` through the whole start (a key generated,
 * the databases created) to a failed listen that the service manager retried for ever, ` 0x0 `
 * as a random port and `1e3` as port 1000; and 0 (`00000` too) served on a port the system
 * chose, which no proxy and no healthcheck could find (the healthcheck tried port 0 itself and
 * reported Uptime Goblin unreachable). Each is now a refusal before anything is written. A number given by a caller (createApp's `port`)
 * may also be 0, for a free port the system chooses: the tests' way to run several Orbits.
 */
export function listenPort(value) {
  if (value === undefined || value === null || value === '') return 4317;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65535)
    return value;
  if (typeof value === 'string' && /^[1-9][0-9]{0,4}$/.test(value) && Number(value) <= 65535)
    return Number(value);
  // The message names the form too: `04317` is the number 4317, refused only for how it is
  // written (1.4.x read it as 4317), as are `+4317`, `4317.0` and `0x10DD`.
  throw refusal(
    `PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is ${quoted(value)}.`
  );
}

/**
 * HOST: an IP address (an IPv6 one without brackets, as Node's listen() takes it) or a host
 * name of letters, digits, dots, hyphens and underscores, at most 253 characters. Unset or
 * empty is 127.0.0.1. A space, brackets or a port gave a failed listen after the whole start.
 */
export function listenHost(value) {
  if (value === undefined || value === null || value === '') return '127.0.0.1';
  const text = String(value);
  if (net.isIP(text) || (/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$/.test(text) && !text.includes('..')))
    return text;
  throw refusal(
    `HOST must be an IP address or a host name, without spaces, brackets or a port (such as 127.0.0.1, 0.0.0.0 or ::1); it is ${quoted(value)}.`
  );
}

/**
 * Why `directory` (GOBLIN_DATA_DIR or --data-dir) cannot be a data directory, or null. Its path
 * reaches log lines, terminals, printed command lines and SQLite (the history index's temporary
 * directory), and every start reads `<data>/secret.key` by the rule for key paths: a character
 * that rule refuses accepted here started Uptime Goblin once, printed raw, and refused every later start.
 * No real path needs one.
 */
export function dataDirectoryProblem(directory) {
  const problem = unprintableProblem(directory);
  return problem ? `must not contain ${problem}` : null;
}

/**
 * The end of a refusal ("must not contain …; it is …, resolved against the working directory to
 * …") for a `directory` that dataDirectoryProblem accepts as given but whose path, resolved
 * against the working directory (`resolved`), holds such a character; null otherwise. A relative
 * value (`data`) passed that check while the working directory's own path held a line break or
 * U+202E: the first start printed it raw (a line break wrote a line of its own), and every later
 * one refused `<data>/secret.key` by the rule for key paths.
 */
export function resolvedDataDirectoryProblem(directory, resolved = path.resolve(directory)) {
  const problem = dataDirectoryProblem(resolved);
  return problem
    ? `${problem}; it is ${quoted(directory, 80)}, resolved against the working directory to ${quoted(resolved, 80)}`
    : null;
}

/**
 * The data directory a start uses, refusing one dataDirectoryProblem names (exit 78), as given
 * or once resolved against the working directory (resolvedDataDirectoryProblem), before anything
 * is written. `warnings` gets a note for spaces around it, which a hand-edited environment file
 * keeps (the directory is used as given, as before, since one may exist with that name).
 */
export function dataDirectory(directory, warnings = []) {
  const problem = dataDirectoryProblem(directory);
  if (problem) throw refusal(`GOBLIN_DATA_DIR ${problem}; it is ${quoted(directory, 80)}.`);
  const resolved = resolvedDataDirectoryProblem(directory);
  if (resolved) throw refusal(`GOBLIN_DATA_DIR ${resolved}.`);
  if (String(directory) !== String(directory).trim())
    warnings.push(
      `GOBLIN_DATA_DIR ${quoted(directory, 80)} begins or ends with a space, which is part of the directory's name; remove the space if that was not meant.`
    );
  return directory;
}

/** At most this many GOBLIN_ALLOWED_HOSTS entries, each compared with every request's Host. */
export const MAX_ALLOWED_HOSTS = 64;

const hostName =
  /^[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*\.?$/;

/**
 * Whether `entry` (lower case) is a Host value a browser can send: a host name, an IPv4
 * address or a bracketed IPv6 address, then optionally a colon and a port of 1 to 65535.
 */
export function isHostValue(entry) {
  const match = /^(\[[^\]]*\]|[^:[\]]+)(?::([0-9]{1,5}))?$/.exec(entry);
  if (!match || entry.length > 261) return false;
  const [, host, port] = match;
  if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) return false;
  if (host.startsWith('[')) return net.isIPv6(host.slice(1, -1));
  return net.isIPv4(host) || (host.length <= 253 && hostName.test(host));
}

/**
 * GOBLIN_ALLOWED_HOSTS: {hosts, warnings}. `hosts` are the entries a request's Host can match,
 * lower case, each once. An entry that is no Host value (`*`, `https://goblin.example`,
 * `goblin.example/`, a bare IPv6 address) never matched a request; it is left out with a warning
 * that names it, since a refused browser gave no hint why. More than 64 entries refuse the start.
 */
export function allowedHostList(value) {
  const entries = String(value ?? '')
    .split(',')
    .map(entry => entry.trim())
    .filter(Boolean);
  if (entries.length > MAX_ALLOWED_HOSTS)
    throw refusal(
      `GOBLIN_ALLOWED_HOSTS lists ${entries.length} hosts; at most ${MAX_ALLOWED_HOSTS} are allowed.`
    );
  const hosts = new Set(),
    warnings = [];
  for (const entry of entries) {
    const lower = entry.toLowerCase();
    if (isHostValue(lower)) hosts.add(lower);
    else
      warnings.push(
        `GOBLIN_ALLOWED_HOSTS entry ${quoted(entry, 80)} is not a host name or address with an optional port (such as goblin.example, goblin.example:8443 or [2001:db8::1]:4317; no scheme, path or wildcard), so no request can match it; it is ignored.`
      );
  }
  return { hosts: [...hosts], warnings };
}

const loopbackAddress = value =>
  value === 'localhost' || value === '::1' || /^127(?:\.\d{1,3}){3}$/.test(value);

const ipv6Loopback = new net.BlockList();
ipv6Loopback.addAddress('::1', 'ipv6');

/**
 * Whether `text` (GOBLIN_PUBLISHED_ADDRESS: an IPv4 address, or an IPv6 one with or without
 * brackets) is a loopback IP address: one in 127.0.0.0/8, or ::1 however it is written. Docker
 * publishes a port on an IP address only, so anything else (a host name, a space around the
 * address, an IPv4 address in brackets, a malformed value) is not loopback: what it decides
 * then fails closed.
 */
export function loopbackPublished(text) {
  const value = String(text ?? '');
  const bracketed = /^\[(.*)\]$/.exec(value);
  if (!bracketed && net.isIPv4(value)) return value.startsWith('127.');
  const address = bracketed ? bracketed[1] : value;
  return net.isIPv6(address) && ipv6Loopback.check(address, 'ipv6');
}

/**
 * Whether GOBLIN_TRUST_PROXY (`value`, as trustedProxies in lib/throttle.mjs reads it, which
 * refuses an entry that is no address or range) names at least one proxy: it is not empty, not
 * 0, false, no or off, and not only commas and blanks.
 */
export function namesProxy(value) {
  if (value === true) return true;
  if (!value || /^(0|false|no|off)$/i.test(String(value).trim())) return false;
  return String(value)
    .split(',')
    .some(entry => entry.trim() !== '');
}

/**
 * The value compose.yaml passes for GOBLIN_INSECURE_HTTP_SESSIONS while .env does not set it
 * (`${GOBLIN_INSECURE_HTTP_SESSIONS-compose-default}`). It is neither yes nor no: Uptime Goblin decides by
 * where Compose publishes the port (insecureHttpSessionsSetting below).
 */
export const composeDefault = 'compose-default';

/**
 * GOBLIN_INSECURE_HTTP_SESSIONS as Uptime Goblin reads it, the one rule for the start (server.mjs) and
 * the capability flag (lib/features.mjs): {enabled, source, warning?, refusal?}. `env` holds
 * GOBLIN_INSECURE_HTTP_SESSIONS, GOBLIN_PUBLISHED_ADDRESS (compose.yaml sets it from
 * GOBLIN_BIND_ADDRESS) and GOBLIN_TRUST_PROXY.
 * - 1, true, yes or on: on; 0, false, no or off: off (any case; source 'env'). Unset or empty:
 *   off (source 'default').
 * - compose-default with GOBLIN_PUBLISHED_ADDRESS set (source 'compose'): on while that is a
 *   loopback IP address (only the Docker host reaches the port); off when it is not and
 *   GOBLIN_TRUST_PROXY names a proxy (sign-in then comes through that proxy's HTTPS); otherwise
 *   off with `refusal`, the reason a start refuses (exit status 78) and what to set in .env.
 *   Docker Compose turns plain-HTTP sign-in on by itself only where the network cannot see it.
 * - Any other value, compose-default without GOBLIN_PUBLISHED_ADDRESS (outside Compose)
 *   included: off, with `warning` (source 'default'), as for every capability flag.
 * It never throws: the control database's features read it wherever one is opened (goblin-admin
 * too), and createApp refuses with `refusal` before anything is written.
 */
export function insecureHttpSessionsSetting(env = {}) {
  const text = env.GOBLIN_INSECURE_HTTP_SESSIONS;
  const published = env.GOBLIN_PUBLISHED_ADDRESS;
  if (
    text === composeDefault &&
    published !== undefined &&
    published !== null &&
    published !== ''
  ) {
    if (loopbackPublished(published)) return { enabled: true, source: 'compose' };
    if (namesProxy(env.GOBLIN_TRUST_PROXY)) return { enabled: false, source: 'compose' };
    return {
      enabled: false,
      source: 'compose',
      refusal: `Docker Compose publishes Uptime Goblin on ${quoted(published, 64)} (GOBLIN_BIND_ADDRESS), which is not a loopback address, with no reverse proxy Uptime Goblin trusts (GOBLIN_TRUST_PROXY), so browsers and scripts would sign in over plain HTTP and the network would see each password and sign-in cookie. Uptime Goblin allows that only when you choose it. In .env, either serve Uptime Goblin over HTTPS through a reverse proxy and set GOBLIN_TRUST_PROXY to the address it connects from (it must send X-Forwarded-Proto; nginx: proxy_set_header X-Forwarded-Proto $scheme;), or set GOBLIN_INSECURE_HTTP_SESSIONS=1 to keep sign-in over plain HTTP on that network (the password and the sign-in cookie cross it unencrypted), or set GOBLIN_INSECURE_HTTP_SESSIONS=0 to refuse it. Then run docker compose up -d.`,
    };
  }
  const value = flagValue(text);
  if (value === undefined)
    return {
      enabled: false,
      source: 'default',
      warning: flagWarning('GOBLIN_INSECURE_HTTP_SESSIONS', text),
    };
  return value === null ? { enabled: false, source: 'default' } : { enabled: value, source: 'env' };
}

// Whether `entry` (a GOBLIN_ALLOWED_HOSTS entry as allowedHostList keeps it: lower case, an
// optional port) names this computer: localhost, an address in 127.0.0.0/8 or [::1].
function loopbackHostEntry(entry) {
  const host = /^(\[[^\]]*\]|[^:[\]]+)(?::[0-9]{1,5})?$/.exec(entry)?.[1] ?? '';
  return host === 'localhost' || loopbackPublished(host);
}

/**
 * The start warning for plain-HTTP sign-in that the network can see, or null. `published` is
 * GOBLIN_PUBLISHED_ADDRESS, which compose.yaml sets from GOBLIN_BIND_ADDRESS: inside its container
 * Uptime Goblin listens on 0.0.0.0 whatever the host publishes, so only Compose knows. Natively `host`
 * (HOST) is the address. On a network address it is the long warning. On loopback (only this
 * computer, or the Docker host, reaches the port) it is a shorter one while `trustProxy`
 * (GOBLIN_TRUST_PROXY) names a proxy or `allowedHosts` (GOBLIN_ALLOWED_HOSTS, as allowedHostList
 * keeps them) a host that is not loopback: a proxy there that relays plain HTTP (one that sends
 * X-Forwarded-Proto: http, an untrusted one that sends forwarding headers, or one that sends none
 * and forwards the browser's host name) is accepted under the same opt-in. Compose's loopback
 * default with no proxy and no other host stays quiet. The same opt-in admits legacy Basic on
 * the plain-HTTP transport (lib/http/pipeline.mjs): while `legacyBasic` is on, the warning
 * names the password every such script sends too.
 */
export function plainHttpWarning({
  insecureHttpSessions,
  legacyBasic = false,
  host,
  published = '',
  trustProxy = '',
  allowedHosts = [],
}) {
  if (!insecureHttpSessions) return null;
  const address = String(published || host)
    .trim()
    .replace(/^\[(.*)\]$/, '$1');
  const basic = legacyBasic
    ? ', the password each script sends with HTTP Basic (GOBLIN_LEGACY_BASIC)'
    : '';
  const onLoopback = published
    ? loopbackPublished(published)
    : loopbackAddress(address.toLowerCase());
  if (!onLoopback) {
    // The published address as it was judged (untrimmed: " 127.0.0.1" is not loopback).
    const where = published
      ? `Docker Compose publishes Uptime Goblin on ${quoted(published, 64)} (GOBLIN_BIND_ADDRESS)`
      : `Uptime Goblin listens on ${quoted(address, 64)} (HOST)`;
    return `Plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS) and ${where}, so the password at each sign-in${basic} and the sign-in cookie cross that network unencrypted. Serve Uptime Goblin through an HTTPS proxy and set GOBLIN_INSECURE_HTTP_SESSIONS=0, or keep it on a network you trust.`;
  }
  const reasons = [];
  if (namesProxy(trustProxy)) reasons.push('GOBLIN_TRUST_PROXY names a reverse proxy');
  const remote = [...allowedHosts].find(entry => !loopbackHostEntry(String(entry)));
  if (remote !== undefined) reasons.push(`GOBLIN_ALLOWED_HOSTS names ${quoted(remote, 64)}`);
  if (!reasons.length) return null;
  const on = published
    ? 'Docker Compose publishes Uptime Goblin on loopback only'
    : 'Uptime Goblin listens on loopback only';
  return `Plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS). ${on}, but ${reasons.join(' and ')}: a sign-in that a proxy relays without telling Uptime Goblin it used HTTPS (X-Forwarded-Proto) is accepted as plain HTTP, so where that proxy takes plain HTTP from the network, the password at each sign-in${basic} and the sign-in cookie cross it unencrypted. Make the proxy serve HTTPS and send X-Forwarded-Proto (GOBLIN_TRUST_PROXY must name it), then set GOBLIN_INSECURE_HTTP_SESSIONS=0.`;
}

/**
 * Warnings for the environment files Node loaded for this process (--env-file=… and
 * --env-file-if-exists=…, as npm start passes .env) that users other than the owner can read or
 * change: they hold GOBLIN_PASSWORD, and can hold the encryption key. `execArgv` and `cwd` are
 * the process's (tests give their own).
 */
export function envFileWarnings({ execArgv = process.execArgv, cwd = process.cwd() } = {}) {
  const files = [];
  for (let i = 0; i < execArgv.length; i++) {
    const match = /^--env-file(?:-if-exists)?(?:=(.*))?$/.exec(execArgv[i]);
    if (!match) continue;
    const file = match[1] ?? execArgv[++i];
    if (file) files.push(path.resolve(cwd, file));
  }
  const warnings = [];
  for (const file of new Set(files)) {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      continue;
    }
    if (!stat.isFile() || !(stat.mode & 0o077)) continue;
    const mode = (stat.mode & 0o777).toString(8).padStart(4, '0');
    // The file is resolved against the working directory, whose path may hold a line break or a
    // terminal escape (it wrote a line of its own): shown escaped then, and with no command line
    // to paste, which would carry the character too.
    const problem = unprintableProblem(file);
    warnings.push(
      problem
        ? `${quoted(file, 200)} (mode ${mode}) can be read by other users of this computer, and it holds GOBLIN_PASSWORD: make it private with chmod 600 (its path, shown escaped, holds ${problem}).`
        : `${file} (mode ${mode}) can be read by other users of this computer, and it holds GOBLIN_PASSWORD: make it private with chmod 600 ${shellWord(file)}.`
    );
  }
  return warnings;
}

// How long a wall display stays signed in (B6 design §7.5, as amended by the integration spec
// §7): at most GOBLIN_DISPLAY_SESSION_DAYS from its code's redemption, and GOBLIN_DISPLAY_IDLE_DAYS
// without a request. Both can only be lowered from their defaults.
const displayDays = Object.freeze({
  GOBLIN_DISPLAY_SESSION_DAYS: {
    min: 1,
    max: 30,
    fallback: 30,
    why: 'a wall display signs in again at least every 30 days',
  },
  GOBLIN_DISPLAY_IDLE_DAYS: {
    min: 1,
    max: 7,
    fallback: 7,
    why: 'a wall display nobody uses signs out within 7 days',
  },
});

/**
 * The wall display session limits from `env`: {absoluteMs, idleMs}. Unset or empty is the
 * default (compose.yaml passes an empty value when .env says nothing). Anything else that is not
 * a whole number of days in range refuses the start (exit 78), before anything is written: a
 * display signed in for longer than its owner chose is not a default to fall back to.
 */
export function displaySessionLimits(env = process.env) {
  const days = {};
  for (const [name, { min, max, fallback, why }] of Object.entries(displayDays)) {
    const text = env[name];
    if (text === undefined || text === '') {
      days[name] = fallback;
      continue;
    }
    const value = /^\d{1,3}$/.test(text) ? Number(text) : NaN;
    if (!(value >= min && value <= max))
      throw Object.assign(
        new Error(
          `${name} must be a whole number of days from ${min} to ${max}: ${why}. It is ${quoted(text)}; leave it empty for ${fallback}.`
        ),
        { refusal: true }
      );
    days[name] = value;
  }
  const absoluteMs = days.GOBLIN_DISPLAY_SESSION_DAYS * 86400e3;
  return Object.freeze({
    absoluteMs,
    idleMs: Math.min(days.GOBLIN_DISPLAY_IDLE_DAYS * 86400e3, absoluteMs),
  });
}

// Every GOBLIN_* name some part of Uptime Goblin reads, so a misspelt one (GOBLIN_TRUST_PROXIES, which
// leaves the proxy untrusted without a word) is said at the start. Grouped by reader; the
// packaging test keeps this list in step with the documentation and the deployment files.
export const knownVariables = Object.freeze([
  // Uptime Goblin itself (server.mjs and the modules it starts).
  'GOBLIN_DATA_DIR',
  'GOBLIN_PASSWORD',
  'GOBLIN_ALLOWED_HOSTS',
  'GOBLIN_WEBHOOK_URL',
  'GOBLIN_TRUST_PROXY',
  'GOBLIN_MAX_CONNECTIONS_PER_CLIENT',
  'GOBLIN_ALLOW_LOOPBACK',
  'GOBLIN_INSECURE_HTTP_SESSIONS',
  'GOBLIN_LEGACY_BASIC',
  'GOBLIN_AUDIT_LOG',
  'GOBLIN_AUDIT_RETENTION_DAYS',
  'GOBLIN_DISPLAY_SESSION_DAYS',
  'GOBLIN_DISPLAY_IDLE_DAYS',
  'GOBLIN_SECRET_KEY',
  'GOBLIN_SECRET_KEY_FILE',
  'GOBLIN_SECRET_KEY_PREVIOUS',
  'GOBLIN_SECRET_KEY_PREVIOUS_FILE',
  'GOBLIN_SUPERVISED',
  'GOBLIN_ALLOW_UNLIMITED',
  'GOBLIN_EXPERIMENTAL',
  'GOBLIN_PUBLISHED_ADDRESS',
  // Capabilities of later releases (lib/features.mjs warns that this one ignores them).
  'GOBLIN_FORWARD_AUTH_HEADER',
  'GOBLIN_DATABASE_URL',
  'GOBLIN_STATUS_LISTEN',
  // Read by lib/budget.mjs, which this release does not use yet (warned about below).
  'GOBLIN_COLLECTION_MEMORY_MB',
  // goblin-admin, the installer, Docker Compose (.env) and the release packaging.
  'GOBLIN_ADMIN_DEBUG',
  'GOBLIN_INSTALL_ROOT',
  'GOBLIN_INSTALLER_TEST',
  'GOBLIN_BIND_ADDRESS',
  'GOBLIN_SIGNING_KEY',
]);
const known = new Set(knownVariables);

/** At most this many unknown names are listed, so a crowded environment stays a few lines. */
const MAX_UNKNOWN = 8;

/**
 * Start warnings for GOBLIN_* variables this release does not read (a misspelt name, or one of a
 * later release) and for GOBLIN_COLLECTION_MEMORY_MB, which it reads nowhere yet. Names are
 * shown escaped and cut; values never are (one could be a password).
 */
export function unusedVariableWarnings(env = process.env) {
  const warnings = [];
  const unknown = Object.keys(env).filter(name => name.startsWith('GOBLIN_') && !known.has(name));
  for (const name of unknown.slice(0, MAX_UNKNOWN))
    warnings.push(
      `${/^GOBLIN_[A-Z0-9_]{1,58}$/.test(name) ? name : quoted(name, 64)} is not a setting this release reads; it is ignored (check its spelling).`
    );
  if (unknown.length > MAX_UNKNOWN)
    warnings.push(
      `${unknown.length - MAX_UNKNOWN} more GOBLIN_ variables are not settings this release reads.`
    );
  if (env.GOBLIN_COLLECTION_MEMORY_MB !== undefined && env.GOBLIN_COLLECTION_MEMORY_MB !== '')
    warnings.push(
      'GOBLIN_COLLECTION_MEMORY_MB is set, but this release does not limit collection memory with it yet; it is ignored.'
    );
  return warnings;
}
