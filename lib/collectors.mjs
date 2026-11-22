// Collectors return only normalized numeric measurements, never raw API payloads.
import { createHash } from 'node:crypto';
import { parseHttpExpectedStatus } from './config.mjs';
import { resolvedDestination } from './destinations.mjs';
import { fetchPinned } from './net/outbound.mjs';
const sessions = new Map();
const loginBlocks = new Map();
const previous = new Map();
export function resetCollector(id) {
  for (const map of [sessions, loginBlocks, previous])
    for (const key of map.keys()) if (key.startsWith(id + ':')) map.delete(key);
}
function number(value) {
  if (typeof value === 'string') {
    if (value.length > 128) return null;
    value = value.trim();
    if (!/^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?$/.test(value)) return null;
    value = Number(value);
  }
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}
/**
 * A measurement as collect() returns it, or null when `value` is not a finite number. Keys,
 * labels and units are Uptime Goblin's own, checked mappings, or bounded already (upstreamKey,
 * upstreamLabel, upstreamUnit), so one beyond these limits is a bug and fails the collection.
 */
function reading(key, label, value, unit = '') {
  const n = number(value);
  if (n === null) return null;
  if (
    typeof key !== 'string' ||
    key.length > 200 ||
    typeof label !== 'string' ||
    label.length > 240 ||
    typeof unit !== 'string' ||
    unit.length > 30
  )
    throw new Error('Source measurement names or units exceed supported limits');
  return { key, label, value: n, unit };
}
/**
 * A built-in reading: a count, a size, a rate, a duration or a percentage, so never negative,
 * and a percentage is at most 100. A source that reports otherwise (a broken counter, a used
 * value above its total) has that reading left out, as one that is not a number is, so history
 * scales and threshold alerts never see it.
 */
function metric(key, label, value, unit = '') {
  const n = number(value);
  return n === null || n < 0 || (unit === '%' && n > 100) ? null : reading(key, label, n, unit);
}
// A custom mapping's reading keeps whatever the source sends: the admin chose what it measures and
// its unit (a temperature below zero, a change in percent).
const mapped = (m, value) => reading(m.key, m.label, value, m.unit);
function sum(items, key) {
  return items.reduce(
    (total, item) => total + (number(typeof key === 'function' ? key(item) : item[key]) ?? 0),
    0
  );
}
// A body or list entry that is not the shape the source's API documents (null, a primitive, an
// object where a list belongs). Said as such, rather than as the TypeError that reading it
// raised (which pointed at the address and credential format), and not retried: the next
// answer is the same.
const unexpectedResponse = () =>
  new CollectionError(
    'Source returned an unexpected response. Check the API URL and that the source version is supported.'
  );
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
/** `value` when it is a JSON object, else the unexpected-response error. */
function requireObject(value) {
  if (!isObject(value)) throw unexpectedResponse();
  return value;
}
/** `value` when it is an array (of objects only, with `objects`), else the same error. */
function requireArray(value, { objects = false } = {}) {
  if (!Array.isArray(value) || (objects && !value.every(isObject))) throw unexpectedResponse();
  return value;
}
// Text a source controls (the names and IDs of devices, guests, storages and indexers, paths,
// units) becomes part of measurement keys and labels, which history, alert messages, emails and
// webhook bodies carry. Only a string or a finite number is used: an object read
// "[object Object]" and a missing ID "undefined", so entries without one collided and all but
// the first were dropped unnoticed; such an entry is now left out and noted. In keys and labels
// alike, each run of control characters (C0, DEL, C1) and line and paragraph separators becomes
// one space and the text-direction embeddings, overrides and isolates are removed (what
// lib/config.mjs refuses in a line of display text), so a name cannot break a line of a log or an
// email, or display as another. An unpaired surrogate (a JSON escape such as \ud800 in an ID)
// becomes U+FFFD, the character SQLite stored for it: a key holding one was stored as another
// string than the one evaluation compared, so its alert row never matched again. A label also
// loses the direction marks (U+061C, U+200E, U+200F) and white space at either end
// (upstreamText); a key keeps them (upstreamId), as 1.4.3 did, since changing a key restarts its
// history and leaves the alert rules on it matching nothing.
const upstreamControls = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g,
  upstreamEmbeddings = /[\u202a-\u202e\u2066-\u2069]/g,
  upstreamDirection = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
/** A source's name or ID as one line of text (see above), or null when it has none. */
function upstreamText(value) {
  if (typeof value === 'number' ? !Number.isFinite(value) : typeof value !== 'string') return null;
  const text = String(value)
    .toWellFormed()
    .replace(upstreamDirection, '')
    .replace(upstreamControls, ' ')
    .trim();
  return text || null;
}
/** The first of `values` that upstreamText() takes, as it returns it, or null. */
function firstText(...values) {
  for (const value of values) {
    const text = upstreamText(value);
    if (text !== null) return text;
  }
  return null;
}
/**
 * A source's ID or path as a measurement key holds it (see above): whole, with control characters
 * as a space and without direction embeddings, overrides or isolates, but otherwise as the source
 * sent it. null when upstreamText() finds no text in it.
 */
function upstreamId(value) {
  if (upstreamText(value) === null) return null;
  return String(value)
    .toWellFormed()
    .replace(upstreamEmbeddings, '')
    .replace(upstreamControls, ' ');
}
/** The first of `values` that upstreamId() takes, as it returns it, or null. */
function firstId(...values) {
  for (const value of values) {
    const id = upstreamId(value);
    if (id !== null) return id;
  }
  return null;
}
/**
 * A measurement key from a source's ID (upstreamId): at most the 150 characters an alert rule
 * takes (pathKey shortens a longer one with a hash, where a long one failed the whole source),
 * and never starting with "__", which Uptime Goblin keeps for its own rules. 1.4.3 used the ID as the
 * source sent it. The cases in which a key differs from the one 1.4.3 made (from upstreamId(),
 * from this limit and "~", and from each caller's choice of ID when one is blank, not text or
 * 0) are listed in docs/troubleshooting.md, "Measurement keys after an upgrade from 1.4.x", and
 * test/collectors-metrics.test.mjs checks each one against the key 1.4.3 made.
 */
function upstreamKey(prefix, id, suffix = '') {
  if (!prefix && id.startsWith('__')) prefix = '~';
  return pathKey(prefix, id + suffix);
}
/**
 * A label from a source's name (upstreamText): composed (NFC), so names that look the same are
 * the same, and shortened to the label limit (shortName), then Uptime Goblin's own suffix (" · CPU").
 */
const upstreamLabel = (name, suffix = '') => shortName(name.normalize('NFC')) + suffix;
/** A unit a source names (AMP's Units): one line of at most 30 characters, else none. */
function upstreamUnit(value) {
  const unit = typeof value === 'string' ? upstreamText(value)?.normalize('NFC') : null;
  return unit && unit.length <= 30 ? unit : '';
}
function compact(items) {
  return items.filter(Boolean);
}
// Where a cap leaves readings out, the collection says so in a note instead of dropping them
// silently. collect() attaches the notes to its readings as a non-enumerable `notes` property
// ([{code, message, omitted?}]), so the readings array itself is unchanged. Messages are
// fixed text and counts, never upstream content, and stay within 200 characters.
const thousands = n => n.toLocaleString('en');
// No prototype: a stored note code such as 'constructor' must not find an inherited member.
export const noteMessages = Object.freeze(
  Object.assign(Object.create(null), {
    arr_library_too_large: ({ product }) =>
      `The ${product} library exceeds a reading limit (64 MB total, 200,000 entries, or 1 MB per entry). Library counts are left out; queue, health and disk readings continue.`,
    crowdsec_alerts_too_large: () =>
      'CrowdSec alerts exceed the 16 MB response limit, so the 24-hour alert count is left out. Decision and ban counts continue.',
    crowdsec_alerts_capped: () =>
      'CrowdSec returns at most 1,000 alerts per request, so the 24-hour alert count may be higher than shown.',
    unifi_devices_capped: ({ omitted }) =>
      `Per-device readings cover the first 64 devices; ${thousands(omitted)} more online devices are counted in the totals but not shown individually.`,
    unifi_lists_capped: () =>
      'UniFi lists are read up to 20,000 entries or 100 pages each, so devices, clients or sites beyond that are left out of the counts.',
    interfaces_capped: ({ omitted }) =>
      `Network rates include the first 256 interfaces; ${thousands(omitted)} more are left out of the receive and send totals.`,
    proxmox_guests_capped: ({ omitted }) =>
      `Per-guest readings cover the 128 lowest VMIDs; ${thousands(omitted)} more guests are counted in the totals but not shown individually.`,
    filesystems_capped: ({ omitted }) =>
      `Disk readings cover the first 200 filesystems; ${thousands(omitted)} more are left out.`,
    measurements_capped: ({ omitted }) =>
      `This source reported more than 512 measurements; Uptime Goblin keeps the first 512 and leaves out ${thousands(omitted)}.`,
    unifi_sites_capped: ({ omitted }) =>
      `Device and client readings cover the first 50 UniFi sites; ${thousands(omitted)} more are left out.`,
    unnamed_entries_left_out: ({ omitted }) =>
      `The source listed ${thousands(omitted)} ${omitted === 1 ? 'entry' : 'entries'} without a usable name or ID; their readings are left out.`,
    duplicate_keys_left_out: ({ omitted }) =>
      `${thousands(omitted)} ${omitted === 1 ? 'reading has' : 'readings have'} the measurement key of an earlier one (an ID or path listed twice, or two different ones that make one key) and ${omitted === 1 ? 'is' : 'are'} left out.`,
    mappings_ambiguous: ({ omitted }) =>
      `${thousands(omitted)} ${omitted === 1 ? 'mapping reads' : 'mappings read'} nothing: a label filter or path holding U+FFFD matches more than one text the source sent once half of a surrogate pair reads as U+FFFD.`,
  })
);
class Notes {
  #notes = new Map();
  #unnamed = 0;
  /** Entries left out because they have no usable name or ID (upstreamText): one note in all. */
  unnamed(count = 1) {
    this.#unnamed += count;
  }
  // One note per code: a cap met twice in one collection (receive and send interfaces, two
  // UniFi lists) keeps the larger omission.
  add(code, detail = {}) {
    const omitted = detail.omitted,
      previous = this.#notes.get(code);
    if (previous && (previous.omitted ?? 0) >= (omitted ?? 0)) return;
    this.#notes.set(code, {
      code,
      message: noteMessages[code](detail),
      ...(omitted > 0 ? { omitted } : {}),
    });
  }
  attach(readings) {
    if (this.#unnamed) this.add('unnamed_entries_left_out', { omitted: this.#unnamed });
    return Object.defineProperty(readings, 'notes', {
      value: [...this.#notes.values()],
      enumerable: false,
    });
  }
}
// NZBGet splits 64-bit sizes and rates into a high and a low 32-bit half. Each must be a whole
// number that fits 32 bits (the low half may come signed, as XML-RPC's i4 carries it), the high
// one not negative; otherwise the combined value means nothing and the single field is used.
function highLow(obj, prefix, fallback) {
  const hi = number(obj[prefix + 'Hi']),
    lo = number(obj[prefix + 'Lo']);
  const word = n => Number.isInteger(n) && n >= -2147483648 && n < 4294967296;
  return word(hi) && hi >= 0 && word(lo)
    ? hi * 4294967296 + (lo < 0 ? lo + 4294967296 : lo)
    : number(obj[fallback || prefix]);
}
function base(service) {
  const u = new URL(service.apiUrl);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password)
    throw new Error('Use an HTTP or HTTPS endpoint without embedded credentials');
  return u.href.replace(/\/$/, '');
}
/**
 * How a request is sent once its destination is checked: fetchPinned (lib/net/outbound.mjs),
 * called as fetch(url, init) with the checked addresses as a third argument, connects to those
 * addresses only. Tests replace `transport.fetch` to answer without a network.
 */
export const transport = { fetch: fetchPinned };
// Retry policy uses structured, internal metadata; raw network causes never reach the UI.
export class CollectionError extends Error {
  constructor(message, { retryable = false, status } = {}) {
    super(message);
    this.name = 'CollectionError';
    this.retryable = retryable;
    if (status !== undefined) this.status = status;
  }
}
function httpError(status, website = false, headers) {
  const error = new CollectionError(
    website
      ? 'Website returned unexpected HTTP ' + status
      : status === 401 || status === 403
        ? 'Authentication failed. Check this source’s credentials and read permissions.'
        : status === 429
          ? 'The source is limiting requests (HTTP 429). Uptime Goblin will try again later.'
          : 'Source returned HTTP ' + status,
    { status, retryable: status === 408 || status === 429 || status >= 500 }
  );
  // Retry-After in seconds (dates are rare for APIs and ignored), capped at an hour.
  const retryAfter = Number(headers?.get?.('retry-after'));
  if (Number.isFinite(retryAfter) && retryAfter > 0)
    error.retryAfterMs = Math.min(retryAfter, 3600) * 1000;
  return error;
}
const dnsFailure = () =>
  new CollectionError('DNS lookup failed. Check the source hostname and DNS server.', {
    retryable: true,
  });
const interrupted = () =>
  new CollectionError(
    'Connection was interrupted. Check network access and source responsiveness.',
    { retryable: true }
  );
const timeoutCodes = [
  'ETIMEDOUT',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
];
// Causes of a body read that fail the same way on every attempt: invalid HTTP framing (a
// premature end of the stream is a dropped connection instead) and corrupt or mislabelled
// compressed bodies (zlib, brotli and zstd, which lib/net/outbound.mjs no longer decodes, and a
// chain of codings that expands beyond its limit there).
const malformedCode = code =>
  (/^(?:HPE_|Z_|ERR__ERROR_|ERR_BROTLI|ZSTD_)/.test(code) || code === 'ERR_CONTENT_CODING_LIMIT') &&
  code !== 'HPE_INVALID_EOF_STATE';
// `reading` marks a failure while the body was read (fetch's TypeError('terminated')).
function networkError(error, reading = false) {
  let cause = error,
    parserError = false;
  const codes = [];
  for (let n = 0; cause && n < 5; n++, cause = cause.cause) {
    if (typeof cause.code === 'string') codes.push(cause.code);
    if (Array.isArray(cause.errors))
      codes.push(...cause.errors.map(e => e?.code).filter(c => typeof c === 'string'));
    // Node's HTTP parser errors often carry no code.
    if (cause.name === 'HTTPParserError' && !/EOF/i.test(String(cause.message))) parserError = true;
  }
  // Response headers (or trailers) beyond the HTTP parser's limit (16 KiB) arrive the same way
  // on every attempt, so they are not retried, and they are no connection or TLS problem.
  if (codes.some(code => ['UND_ERR_HEADERS_OVERFLOW', 'HPE_HEADER_OVERFLOW'].includes(code)))
    return new CollectionError(
      'Source sent HTTP headers larger than Uptime Goblin accepts. Check any proxy in front of the source.'
    );
  // The headers had arrived, so address, TLS and credentials worked. Usually the connection
  // dropped mid-response (a restart, proxy reload, HTTP/2 reset or blip), which is retried.
  // A malformed body (invalid chunked framing, a corrupt or mislabelled compressed body)
  // fails the same way on every attempt, so it is not retried, and the detail is not shown.
  if (reading && !codes.some(code => timeoutCodes.includes(code)))
    return (parserError && !codes.includes('HPE_INVALID_EOF_STATE')) || codes.some(malformedCode)
      ? new CollectionError(
          'Source sent a malformed response: its HTTP framing or compressed body could not be read. Check the API URL and any proxy in front of the source.'
        )
      : interrupted();
  // An https:// address on a plain-HTTP port fails with an SSL code too, but it is a scheme
  // mistake rather than a certificate problem.
  if (
    codes.some(code =>
      ['ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_PACKET_LENGTH_TOO_LONG', 'EPROTO'].includes(code)
    )
  )
    return new CollectionError(
      'The source did not answer with TLS on this port. Check whether the address should use http:// or https://.'
    );
  if (
    codes.some(code =>
      /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ALTNAME|INVALID_CA|INVALID_PURPOSE|PATH_LENGTH|HOSTNAME_MISMATCH/.test(
        code
      )
    )
  )
    return new CollectionError(
      'TLS certificate verification failed. Check the source certificate, trust chain, and hostname.'
    );
  // Other handshake failures (old protocol versions, no shared cipher) are not certificate
  // problems; point at the source's TLS settings instead.
  if (codes.some(code => /TLS|SSL/.test(code)))
    return new CollectionError(
      'TLS handshake failed. The source may only offer old TLS versions or ciphers; Uptime Goblin requires TLS 1.2 or newer.'
    );
  if (codes.some(code => ['ENOTFOUND', 'EAI_AGAIN'].includes(code))) return dnsFailure();
  if (codes.some(code => timeoutCodes.includes(code)))
    return new CollectionError(
      'Connection timed out. Check network access and source responsiveness.',
      { retryable: true }
    );
  if (codes.includes('ECONNREFUSED'))
    return new CollectionError(
      'Connection refused. Check that the service is listening on the configured port.',
      { retryable: true }
    );
  if (codes.some(code => ['ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET'].includes(code)))
    return interrupted();
  if (codes.some(code => ['EHOSTUNREACH', 'ENETUNREACH'].includes(code)))
    return new CollectionError(
      'Source network is unreachable. Check routing and firewall access.',
      { retryable: true }
    );
  if (
    codes.some(code =>
      ['ERR_INVALID_URL', 'ERR_INVALID_ARG_VALUE', 'ERR_INVALID_ARG_TYPE'].includes(code)
    ) ||
    error.cause?.message === 'bad port'
  )
    return new CollectionError(
      'Invalid source address or request configuration. Check the endpoint and port.'
    );
  if (error.cause?.message === 'unexpected redirect')
    return new CollectionError('The source redirected. Use its final API address.');
  return new CollectionError(
    'Could not connect. Check the address, network access, and TLS certificate.',
    { retryable: true }
  );
}
// Runs inside the request deadline: a slow DNS answer is cancelled like a slow response.
// A failed lookup is reported at once. Returns the checked addresses, the only ones the request
// then connects to (transport): resolving the name again could give a refused one.
async function assertDestination(url, signal) {
  signal.throwIfAborted();
  let cancel;
  const aborted = new Promise((_, reject) => {
    cancel = () => reject(signal.reason);
    signal.addEventListener('abort', cancel, { once: true });
  });
  try {
    const { addresses, problem } = await Promise.race([
      resolvedDestination(url).catch(() => {
        throw dnsFailure();
      }),
      aborted,
    ]);
    if (problem) throw new CollectionError(problem);
    return addresses;
  } finally {
    signal.removeEventListener('abort', cancel);
  }
}
// A request that runs out of time while its destination check is still waiting on DNS
// reports the resolver, not the source.
const dnsTimeout = limitMs =>
  new CollectionError(
    `DNS lookup timed out after ${limitMs / 1000} seconds. Check the source hostname and DNS server.`,
    { retryable: true }
  );
// JSON.parse can build an object graph many times larger than its input, so buffered bodies
// are also bounded by structural values ('{', '[' and ','). Each collection has one read
// budget across all of its buffered requests and pages (32 MB and 750,000 values; there is
// no separate per-response value limit), so one source (hostile or huge) cannot hold more
// than a bounded amount of memory, and never uses up a share that other sources need.
// Lists that are only tallied (Sonarr/Radarr libraries, CrowdSec decisions) are streamed
// instead: each element is parsed and dropped on its own, so a read holds one element however
// long the list is. A list that is only counted (CrowdSec alerts) is not parsed at all, so it
// holds no element either. Streamed reads have their own byte and element limits (and, when
// parsed, an element-size limit) and do not draw on the budget.
const RESPONSE_LIMIT = 16 * 1024 * 1024,
  JSON_DEPTH_LIMIT = 64,
  COLLECTION_BYTES = 32 * 1024 * 1024,
  // Deep or key-heavy hostile shapes retain up to about 160 bytes per value once parsed.
  COLLECTION_TOKENS = 750000,
  // A library has no smaller endpoint with the same counts. *arr servers send indented JSON
  // of about 5-7 KB per movie or series (more for long-running shows), so the byte limit,
  // not the value count, is what binds: 16 MB ran out near 2,500 items, 64 MB allows about
  // 10,000 movies or 4,000-12,000 series.
  LIBRARY_LIMIT = 64 * 1024 * 1024,
  STREAM_ITEM_LIMIT = 1024 * 1024,
  STREAM_ITEMS = 200000;
export const readBudget = () => ({ bytes: COLLECTION_BYTES, tokens: COLLECTION_TOKENS });
// UniFi Integration API lists (see the 'unifi' collector).
const UNIFI_LIST_ENTRIES = 20000,
  UNIFI_LIST_PAGES = 100,
  UNIFI_SITES = 50,
  UNIFI_LIST_REQUESTS = 1000;
const invalidJson = () => new Error('Source did not return valid JSON. Check the API URL.');
const tooDeep = () =>
  new CollectionError(
    `Source response nests more than ${JSON_DEPTH_LIMIT} levels deep, which Uptime Goblin does not accept.`
  );
// `tooLarge` lets a collector keep its other readings when one oversized list is skipped.
const tooLarge = message =>
  Object.assign(new CollectionError(message + ' Use a more focused source or endpoint.'), {
    tooLarge: true,
  });
const isSpace = byte => byte === 0x20 || byte === 0x0a || byte === 0x0d || byte === 0x09;
const hasBom = bytes => bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
/**
 * Streams a top-level JSON array: each element is parsed on its own, handed to `each` and
 * dropped. Without `each` the elements are only counted: none is kept or parsed, so one entry
 * has no size limit, and only the list's framing (strings, brackets and commas) is checked.
 * `end()` returns the element count, or null when the body is JSON `null` (CrowdSec sends that
 * for an empty list). String and escape state carry across chunks, as in scanJson.
 */
function arrayItems(each) {
  // 0: before the array, 1: inside it, 2: after it, 3: a literal (only `null` is accepted).
  let phase = 0,
    depth = 0,
    string = false,
    escape = false,
    first = true,
    open = false,
    expectItem = false,
    count = 0,
    parts = [],
    size = 0,
    literal = '';
  // The closing bracket each open one inside an element needs (']' is '[' + 2, '}' is '{' + 2).
  const closers = [];
  const finish = (chunk, start, end) => {
    let value;
    if (each) {
      if (size + end - start > STREAM_ITEM_LIMIT)
        throw tooLarge('A source list entry exceeds the 1 MB limit.');
      try {
        value = JSON.parse(Buffer.concat([...parts, chunk.subarray(start, end)]).toString('utf8'));
      } catch {
        throw invalidJson();
      }
      parts = [];
      size = 0;
    }
    open = false;
    if (++count > STREAM_ITEMS)
      throw tooLarge(`Source list exceeds the ${STREAM_ITEMS.toLocaleString('en')} entry limit.`);
    each?.(value);
  };
  return {
    push(chunk) {
      let i = first && hasBom(chunk) ? 3 : 0,
        start = 0;
      first = false;
      for (; i < chunk.length; i++) {
        const byte = chunk[i];
        if (phase === 1) {
          if (string) {
            if (escape) escape = false;
            else if (byte === 0x5c) escape = true;
            else if (byte === 0x22) string = false;
            continue;
          }
          if (depth === 1 && (byte === 0x2c || byte === 0x5d)) {
            if (open) finish(chunk, start, i);
            else if (byte === 0x2c || expectItem) throw invalidJson();
            expectItem = byte === 0x2c;
            if (byte === 0x5d) phase = 2;
            continue;
          }
          if (!open) {
            if (isSpace(byte)) continue;
            open = true;
            start = i;
          }
          if (byte === 0x22) string = true;
          else if (byte === 0x5b || byte === 0x7b) {
            if (++depth > JSON_DEPTH_LIMIT) throw tooDeep();
            closers.push(byte + 2);
          } else if (byte === 0x5d || byte === 0x7d) {
            if (closers.pop() !== byte) throw invalidJson();
            depth--;
          }
        } else if (phase === 0) {
          if (isSpace(byte)) continue;
          if (byte === 0x5b) {
            phase = 1;
            depth = 1;
          } else if (byte === 0x6e) {
            phase = 3;
            i--;
          } else throw new Error('Unexpected response: an array was required');
        } else if (phase === 3) {
          if ((literal += String.fromCharCode(byte)).length > 8) throw invalidJson();
        } else if (!isSpace(byte)) throw invalidJson();
      }
      // An element that continues into the next chunk is kept, within the element limit.
      if (open && each) {
        parts.push(Buffer.from(chunk.subarray(start)));
        if ((size += chunk.length - start) > STREAM_ITEM_LIMIT)
          throw tooLarge('A source list entry exceeds the 1 MB limit.');
      }
    },
    end() {
      if (phase === 3 && literal.trim() === 'null') return null;
      if (phase !== 2) throw invalidJson();
      return count;
    },
  };
}
// Counts structural values outside strings and tracks nesting depth, carrying string and
// escape state across chunks. Returns the number of values in this chunk, or -1 when the
// document nests deeper than JSON_DEPTH_LIMIT.
function scanJson(state, bytes) {
  let count = 0;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (state.string) {
      if (state.escape) state.escape = false;
      else if (byte === 0x5c) state.escape = true;
      else if (byte === 0x22) state.string = false;
    } else if (byte === 0x22) state.string = true;
    else if (byte === 0x2c) count++;
    else if (byte === 0x5b || byte === 0x7b) {
      count++;
      if (++state.depth > JSON_DEPTH_LIMIT) return -1;
    } else if (byte === 0x5d || byte === 0x7d) state.depth--;
  }
  return count;
}
// Exporters that negotiate content (Spring Boot, MicroProfile servers) answer a JSON Accept
// header with JSON or HTTP 406, so text scrapes ask for the Prometheus text format.
const PROMETHEUS_ACCEPT = 'text/plain;version=0.0.4;q=1,*/*;q=0.1';
/**
 * Reads one source response. `text` returns the body as text; otherwise it is parsed as JSON
 * within the collection's read budget. With `each`, the body must be a JSON array (or null)
 * that is streamed element by element (see arrayItems) under `limit` bytes (16 MB by
 * default), and the element count is returned. `count: true` streams it the same way but only
 * counts the elements, without parsing them. The request's time limit covers the whole
 * exchange: the destination check (DNS), connecting, TLS, the answer and its body.
 */
export async function request(service, route = '', options = {}) {
  service.signal?.throwIfAborted();
  const { onHeaders, each, count, limit, ...fetchOptions } = options;
  const url = base(service) + route;
  const controller = new AbortController(),
    signal = service.signal
      ? AbortSignal.any([controller.signal, service.signal])
      : controller.signal;
  // The abort waits for the check phase, so a response that arrived while the event loop was
  // busy (the timer expired meanwhile) is read before the expired timer cancels it.
  const limitMs = requestTimeout(service),
    timeout = setTimeout(() => setImmediate(() => controller.abort()), limitMs);
  const budget = service.readBudget ?? readBudget();
  let response,
    resolving = true;
  try {
    const addresses = await assertDestination(url, signal);
    resolving = false;
    response = await transport.fetch(
      url,
      {
        ...fetchOptions,
        redirect: 'error',
        signal,
        headers: {
          Accept: options.text ? PROMETHEUS_ACCEPT : 'application/json',
          ...options.headers,
        },
      },
      addresses
    );
    service.signal?.throwIfAborted();
    if (!response.ok) throw httpError(response.status, false, response.headers);
    onHeaders?.(response.headers);
    if (!response.body) {
      if (options.text) return '';
      throw new Error('Source returned an empty response. Check the API URL.');
    }
    const reader = response.body.getReader(),
      items = each || count ? arrayItems(each) : null,
      maxBytes = (items && limit) || RESPONSE_LIMIT;
    let length = 0;
    const scan = { string: false, escape: false, depth: 0 };
    const buffers = [];
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > maxBytes)
          throw tooLarge(`Source response exceeds the ${maxBytes / 1048576} MB collection limit.`);
        if (items) {
          items.push(value);
          continue;
        }
        if ((budget.bytes -= value.length) < 0)
          throw new CollectionError(
            'Source responses for one collection exceed the 32 MB limit. Use a more focused source or endpoint.'
          );
        if (!options.text) {
          const found = scanJson(scan, value);
          if (found < 0) throw tooDeep();
          if ((budget.tokens -= found) < 0)
            throw new CollectionError(
              'Source response is too complex: it exceeds the JSON value collection limit.'
            );
        }
        buffers.push(Buffer.from(value));
      }
    } catch (e) {
      void reader.cancel().catch(() => {});
      throw e;
    }
    service.signal?.throwIfAborted();
    if (items) return items.end();
    // TextDecoder drops a leading UTF-8 byte order mark (as browsers and Response.json() do),
    // which Windows tools often write and JSON.parse rejects.
    const text = new TextDecoder().decode(Buffer.concat(buffers));
    if (options.text) return text;
    try {
      return JSON.parse(text);
    } catch {
      throw invalidJson();
    }
  } catch (e) {
    if (service.signal?.aborted) throw service.signal.reason;
    if (controller.signal.aborted || e.name === 'AbortError')
      throw resolving
        ? dnsTimeout(limitMs)
        : new CollectionError(`Source timed out after ${limitMs / 1000} seconds`, {
            retryable: true,
          });
    if (e.message === 'fetch failed') throw networkError(e);
    if (e instanceof TypeError && e.message === 'terminated') throw networkError(e, true);
    if (e.message.includes('redirect'))
      throw new CollectionError('The source redirected. Use its final API address.');
    throw e;
  } finally {
    clearTimeout(timeout);
    try {
      if (response?.body && !response.bodyUsed) void response.body.cancel().catch(() => {});
    } catch {}
    controller.abort();
  }
}
const keyHeaders = s => ({ 'X-Api-Key': s.apiKey });
const basicHeaders = s => ({
  Authorization: 'Basic ' + Buffer.from(`${s.username}:${s.password}`).toString('base64'),
});
const jsonBody = obj => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(obj),
});
// A Website check may fall back to the card URL, which can carry a query or fragment. The
// fragment is never sent, and a check path replaces the query instead of landing inside it.
function probeUrl(service) {
  const u = new URL(base(service));
  u.hash = '';
  if (!service.metricPath) return u.href.replace(/\/$/, '');
  u.search = '';
  u.pathname = u.pathname.replace(/\/$/, '') + service.metricPath;
  return u.href;
}
async function probeHttp(service) {
  service.signal?.throwIfAborted();
  const ranges = parseHttpExpectedStatus(service.httpExpectedStatus ?? '200-399'),
    method = service.httpMethod ?? 'GET';
  if (!['GET', 'HEAD'].includes(method))
    throw new Error('Website check method must be GET or HEAD');
  const controller = new AbortController(),
    signal = service.signal
      ? AbortSignal.any([controller.signal, service.signal])
      : controller.signal,
    limitMs = requestTimeout(service),
    // As in request(): a response that already arrived wins over the expired timer.
    timer = setTimeout(() => setImmediate(() => controller.abort()), limitMs);
  let response,
    resolving = true;
  try {
    const addresses = await assertDestination(base(service), signal);
    resolving = false;
    // Monotonic, so a clock step during the check cannot make the response time negative.
    const started = performance.now();
    // A reachability probe never forwards native API credentials or follows redirects.
    response = await transport.fetch(
      probeUrl(service),
      {
        method,
        redirect: 'manual',
        credentials: 'omit',
        signal,
        headers: { Accept: '*/*' },
      },
      addresses
    );
    const elapsed = Math.round(performance.now() - started),
      status = response.status;
    try {
      void response.body?.cancel().catch(() => {});
    } catch {}
    service.signal?.throwIfAborted();
    if (controller.signal.aborted)
      throw new Error(`Website check timed out after ${limitMs / 1000} seconds`);
    if (!ranges.some(([start, end]) => status >= start && status <= end))
      throw httpError(status, true);
    return [
      metric('response', 'Response', elapsed, 'ms'),
      metric('available', 'Available', 1),
      metric('http_status', 'HTTP status', status),
    ];
  } catch (error) {
    if (service.signal?.aborted) throw service.signal.reason;
    if (controller.signal.aborted || error.name === 'AbortError')
      throw resolving
        ? dnsTimeout(limitMs)
        : new CollectionError(`Website check timed out after ${limitMs / 1000} seconds`, {
            retryable: true,
          });
    if (error.message === 'fetch failed') throw networkError(error);
    throw error;
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}
// UniFi OS local sessions are kept only in memory and scoped to one source/origin.
async function unifiLocal(service, now, notes) {
  const endpoint = new URL(service.apiUrl);
  if (endpoint.protocol !== 'https:' || endpoint.pathname.replace(/\/$/, '') !== '')
    throw new Error(
      'UniFi local login requires the HTTPS console root address, without an API path.'
    );
  if (!service.username || !service.password)
    throw new Error(
      'Enter a UniFi local account with Network View Only access, or an Integration API key.'
    );
  const site = service.siteId || 'default';
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(site))
    throw new Error('UniFi local login needs a site name such as default.');
  const login = async () => {
    const session = { cookies: new Map() };
    const answer = await request(service, '/api/auth/login', {
      ...jsonBody({ username: service.username, password: service.password }),
      onHeaders: headers => readCookies(headers, session.cookies),
    });
    if (answer?.meta?.rc === 'error' || answer?.error || !session.cookies.size)
      throw new Error('UniFi login failed. Use a local account with Network View Only access.');
    // UniFi OS session cookies are JWTs; reuse them until shortly before they expire.
    session.expiresAt = jwtExpiry(session.cookies.get('TOKEN'));
    return session;
  };
  return withSession(service, 'UniFi', { maxAgeMs: 12 * 3600 * 1000, login }, async session => {
    async function read(name) {
      const headers = {
        Cookie: [...session.cookies].map(([name, value]) => name + '=' + value).join('; '),
      };
      const response = await request(
        service,
        '/proxy/network/api/s/' + encodeURIComponent(site) + '/stat/' + name,
        { headers, onHeaders: headers => readCookies(headers, session.cookies) }
      );
      // An expired session can come back as a 200 carrying LoginRequired.
      if (response?.meta?.msg === 'api.err.LoginRequired')
        throw new CollectionError('UniFi session expired.', { status: 401 });
      if (response?.meta?.rc !== 'ok')
        throw new Error(
          'UniFi rejected the read request. Check the local account permissions and site name.'
        );
      return requireArray(response.data);
    }
    const [health, devices, clients] = await Promise.all([
      read('health'),
      read('device'),
      read('sta'),
    ]);
    service.signal?.throwIfAborted();
    return unifiLocalMetrics(health, devices, clients, notes);
  });
}
function readCookies(headers, cookies) {
  // Node's getSetCookie preserves separate headers, including Expires commas.
  for (const line of headers.getSetCookie()) {
    const parts = line.split(';'),
      pair = parts.shift().trim(),
      at = pair.indexOf('=');
    if (at < 1) continue;
    const name = pair.slice(0, at),
      value = pair.slice(at + 1);
    if (
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
      /[^\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]/.test(value)
    )
      throw new Error('UniFi returned an invalid session cookie.');
    const expired = parts.some(
      part =>
        /^\s*max-age\s*=\s*0\s*$/i.test(part) ||
        (/^\s*expires\s*=/i.test(part) &&
          Date.parse(part.slice(part.indexOf('=') + 1)) < Date.now())
    );
    if (!value || expired) cookies.delete(name);
    else cookies.set(name, value);
  }
  if (
    cookies.size > 32 ||
    [...cookies].reduce((size, [name, value]) => size + name.length + value.length, 0) > 16384
  )
    throw new Error('UniFi session cookies exceed supported limits.');
}
function unifiLocalMetrics(health, devices, clients, notes) {
  for (const rows of [health, devices, clients])
    if (
      rows.length > 20000 ||
      rows.some(row => !row || typeof row !== 'object' || Array.isArray(row))
    )
      throw new Error('UniFi returned an unsupported inventory response.');
  const nonnegative = value => {
    const n = number(value);
    return n !== null && n >= 0 ? n : null;
  };
  const percent = value => {
    const n = nonnegative(value);
    return n !== null && n <= 100 ? n : null;
  };
  const wan = health.find(row => row.subsystem === 'wan'),
    www = health.find(row => row.subsystem === 'www'),
    gateway = wan?.['gw_system-stats'];
  const metrics = [
    metric('devices', 'Devices', devices.length),
    metric('clients', 'Clients', clients.length),
    metric('sites', 'Sites', 1),
    metric('devices_online', 'Devices online', devices.filter(d => number(d.state) === 1).length),
    metric(
      'devices_offline',
      'Devices disconnected',
      devices.filter(d => number(d.state) === 0).length
    ),
    metric('cpu', 'Gateway CPU', percent(gateway?.cpu), '%'),
    metric('memory', 'Gateway memory', percent(gateway?.mem), '%'),
    metric('uptime', 'Gateway uptime', nonnegative(gateway?.uptime), 'seconds'),
    metric('wan_receive', 'WAN receive', nonnegative(wan?.['rx_bytes-r']), 'bytes/s'),
    metric('wan_transmit', 'WAN send', nonnegative(wan?.['tx_bytes-r']), 'bytes/s'),
    metric('wan_latency', 'Internet latency', nonnegative(www?.latency), 'ms'),
  ];
  if (clients.every(c => typeof c.is_wired === 'boolean'))
    metrics.push(
      metric('clients_wired', 'Wired clients', clients.filter(c => c.is_wired).length),
      metric('clients_wireless', 'Wireless clients', clients.filter(c => !c.is_wired).length)
    );
  // Disconnected/transitional devices may retain old telemetry: do not record it as live.
  const beyond = devices.slice(64).filter(d => number(d.state) === 1).length;
  if (beyond) notes.add('unifi_devices_capped', { omitted: beyond });
  for (const d of devices.slice(0, 64)) {
    if (number(d.state) !== 1) continue;
    const id = firstId(d._id, d.mac, d.device_id);
    if (id === null) {
      notes.unnamed();
      continue;
    }
    const key = suffix => upstreamKey('device_', id, suffix),
      name = firstText(d.name, d._id, d.mac, d.device_id),
      label = suffix => upstreamLabel(name, suffix),
      stats = d['system-stats'];
    metrics.push(
      metric(key('_cpu'), label(' · CPU'), percent(stats?.cpu), '%'),
      metric(key('_memory'), label(' · Memory'), percent(stats?.mem), '%'),
      metric(key('_uptime'), label(' · Uptime'), nonnegative(d.uptime ?? stats?.uptime), 'seconds'),
      metric(key('_rx'), label(' · Receive'), nonnegative(d.uplink?.['rx_bytes-r']), 'bytes/s'),
      metric(key('_tx'), label(' · Send'), nonnegative(d.uplink?.['tx_bytes-r']), 'bytes/s')
    );
  }
  return metrics;
}
// The lines one Prometheus body may have, comments and blank lines included: ten times the
// 100,000-sample limit leaves room for the # HELP and # TYPE lines of every metric family.
const prometheusLineLimit = 1000000;
/**
 * The samples of a Prometheus text body. With `budget` (the collection's read budget, see
 * readBudget()), each kept sample costs one value and each label read one more, as JSON values
 * do: a 16 MB body of label-heavy lines otherwise builds an object graph about nine times its
 * size, bounded only by the 100,000-sample limit. A label is charged when it is read, before its
 * line is kept or left out: a line left out at a 65th label, a repeated label name or a bad
 * escape has had up to 64 labels read first, and a body of such lines, never charged, held the
 * event loop as long as one of kept labels (about 0.4 s per 16 MB).
 */
export function parsePrometheus(text, budget) {
  const samples = [];
  const charge = () => {
    if (budget && --budget.tokens < 0)
      throw new CollectionError(
        'Source response is too complex: its measurements and labels exceed the collection value limit.'
      );
  };
  // Line by line, never split('\n'): a body within the 16 MB limit can hold 16 million empty or
  // comment lines, and an array of them took about 150 MB and a third of a second per scrape
  // before any sample was looked at. Every line counts toward prometheusLineLimit, comments
  // and blank lines too, so such a body stops early instead.
  let lines = 0;
  for (let start = 0; start < text.length; ) {
    let end = text.indexOf('\n', start);
    if (end < 0) end = text.length;
    const line = text.slice(start, end);
    start = end + 1;
    if (++lines > prometheusLineLimit)
      throw new Error('Prometheus source exceeds the 1,000,000 line limit');
    if (line.startsWith('#') || !line.trim()) continue;
    if (line.length > 8192) throw new Error('Prometheus measurement line exceeds the 8 KB limit');
    // The label body cannot cross an unquoted '}', so it has one possible end. A greedy (.*)
    // could end at every '}' and made hostile lines quadratic on the event loop.
    const match = line.match(
      /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{((?:[^"}]|"(?:\\.|[^"\\])*")*)\})?\s+([-+\d.eE]+)(?:\s+\S+)?(?:\s+#.*)?$/
    );
    if (!match) continue;
    const value = number(match[3]);
    if (value === null) continue;
    const labels = Object.create(null),
      body = match[2] || '';
    const label = /\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"\s*(?:,|$)/y;
    let offset = 0,
      count = 0,
      valid = true;
    while (offset < body.length) {
      charge();
      label.lastIndex = offset;
      const part = label.exec(body);
      if (!part || ++count > 64 || Object.hasOwn(labels, part[1])) {
        valid = false;
        break;
      }
      try {
        labels[part[1]] = JSON.parse('"' + part[2] + '"');
      } catch {
        valid = false;
        break;
      }
      offset = label.lastIndex;
    }
    if (!valid) continue;
    if (samples.length >= 100000)
      throw new Error('Prometheus source exceeds the 100,000 measurement limit');
    charge();
    samples.push({ name: match[1], labels, value });
  }
  return samples;
}
const sampleIndexes = new WeakMap();
// A label value as selected() compares it: as the exporter sent it, or with `whole` made whole.
const labelValue = (value, whole) =>
  whole && typeof value === 'string' && !value.isWellFormed() ? value.toWellFormed() : value;
/**
 * The samples named `name` whose labels equal `filters`. With `whole`, each label value is
 * compared made whole, half of a surrogate pair as U+FFFD (see mappedSamples()).
 */
function selected(samples, name, filters = {}, whole = false) {
  let index = sampleIndexes.get(samples);
  if (!index) {
    index = new Map();
    for (const sample of samples) {
      let group = index.get(sample.name);
      if (!group) {
        group = { items: [], labels: new Map() };
        index.set(sample.name, group);
      }
      group.items.push(sample);
    }
    sampleIndexes.set(samples, index);
  }
  const group = index.get(name);
  if (!group) return [];
  const entries = Object.entries(filters);
  if (!entries.length) return group.items;
  const indexes = whole ? (group.whole ??= new Map()) : group.labels;
  let candidates = group.items;
  for (const [key, value] of entries) {
    let values = indexes.get(key);
    if (!values) {
      values = new Map();
      for (const sample of group.items) {
        const v = labelValue(sample.labels[key], whole);
        let items = values.get(v);
        if (!items) {
          items = [];
          values.set(v, items);
        }
        items.push(sample);
      }
      indexes.set(key, values);
    }
    const items = values.get(value);
    if (!items) return [];
    if (items.length < candidates.length) candidates = items;
  }
  return candidates.filter(sample =>
    entries.every(([key, value]) => labelValue(sample.labels[key], whole) === value)
  );
}
// A mapping's label filters or JSON path that 1.4.x saved holding half of a surrogate pair (a \u
// escape) hold U+FFFD instead since the start made them whole (wholeTexts() in lib/config.mjs),
// while the exporter still sends the half: compared as sent, the mapping lost its reading and the
// rules on it. So when nothing matches a filter or a path step holding U+FFFD as the exporter
// sent it, its label values or member names are compared made whole. A match as sent always
// comes first, and a filter or step without U+FFFD matches nothing more this way.
// The repair lost which half the filter held, so this gives the 1.4.x reading back while the
// exporter sends no other text there that reads the same: U+FFFD itself matches as sent and is
// read instead, and any half matches made whole. Texts the exporter sent differently that read
// the same made whole (two different halves) are neither summed nor picked from: the mapping
// reads nothing, and the collection says so in a note (mappings_ambiguous).
const halfMark = '\ufffd';
/**
 * The samples a Prometheus mapping `m` sums (see above), or null when, made whole, a filter
 * matches label values the exporter sent differently.
 */
function mappedSamples(samples, m) {
  const filters = m.labels || {};
  const matches = selected(samples, m.path, filters);
  const marked = Object.keys(filters).filter(key => String(filters[key]).includes(halfMark));
  if (matches.length || !marked.length) return matches;
  const whole = selected(samples, m.path, filters, true);
  // Only a filter holding U+FFFD can match more than one value as sent: a text made whole holds
  // U+FFFD wherever it held a half.
  for (const key of marked) {
    const sent = whole[0]?.labels[key];
    if (whole.some(sample => sample.labels[key] !== sent)) return null;
  }
  return whole;
}
// Match companion series on their identifying labels only; matching every label lets an
// exporter with many labels per series make each lookup expensive.
function identity(labels, keys) {
  const out = {};
  for (const key of keys) if (labels[key] !== undefined) out[key] = labels[key];
  return out;
}
function first(samples, name, filters = {}) {
  return selected(samples, name, filters)[0]?.value ?? null;
}
function total(samples, name, filters = {}) {
  const a = selected(samples, name, filters);
  return a.length ? sum(a, 'value') : null;
}
function delta(id, key, value, now, updates) {
  if (value === null) return null;
  const k = id + ':' + key;
  const old = previous.get(k);
  updates.set(k, { value, now });
  return old && value >= old.value && now > old.now
    ? (value - old.value) / ((now - old.now) / 1000)
    : null;
}
// Bridges, veth/tap pairs, tunnels, bonds, VLANs and Hyper-V vEthernet adapters count traffic
// that a physical NIC counts too, so they are left out unless nothing else is reported.
const virtualLinux =
  /^(?:veth|tap|tun|fwbr|fwpr|fwln|vmbr|br-|br\d|bridge|virbr|vnet|docker|podman|cni|flannel|cali|cilium|lxc|lxdbr|incusbr|kube-|weave|vxlan|genev|wg|tailscale|zt|ifb|dummy|bond|team|vlan)|\./;
const virtualWindows =
  /vEthernet|Hyper[-_ ]?V[-_ ]Virtual|isatap|Teredo|6to4|IP[-_ ]?HTTPS|Loopback|Pseudo|WAN[-_ ]Miniport|Kernel[-_ ]Debug|VirtualBox|VMware[-_ ]Virtual|TAP[-_ ]Windows|Wintun|WireGuard|Tailscale|ZeroTier/i;
// Rates are taken per device and then added, so an interface that appears, disappears or resets
// drops out of one reading instead of blanking or shrinking the total.
function interfaceRate(id, direction, counters, label, virtual, now, updates, notes) {
  const physical = counters.filter(m => !virtual.test(m.labels[label]));
  const prefix = id + ':' + direction + ':',
    seen = new Set();
  let rate = null;
  const devices = physical.length ? physical : counters;
  for (const m of devices.slice(0, 256)) {
    const device = m.labels[label];
    if (typeof device !== 'string' || seen.has(device)) continue;
    seen.add(device);
    const r = delta(id, direction + ':' + device, m.value, now, updates);
    if (r !== null) rate = (rate ?? 0) + r;
  }
  const beyond = new Set(
    devices
      .slice(256)
      .map(m => m.labels[label])
      .filter(device => typeof device === 'string' && !seen.has(device))
  ).size;
  if (beyond) notes.add('interfaces_capped', { omitted: beyond });
  // Forget devices that are gone so container and VM churn cannot grow the baseline map.
  for (const key of previous.keys())
    if (key.startsWith(prefix) && !seen.has(key.slice(prefix.length))) updates.set(key, undefined);
  return rate;
}
// The first `length` UTF-16 units of `text`, or one fewer when the last of them is the first
// half of a surrogate pair (an emoji, say): cut there, a key or label ends in half a character,
// which SQLite stores as U+FFFD, so the key was stored as another string than the one
// evaluation compared and its alert row never matched again.
function cutText(text, length) {
  const last = text.charCodeAt(length - 1);
  return text.slice(0, last >= 0xd800 && last <= 0xdbff ? length - 1 : length);
}
// Alert rule keys are limited to 150 characters; longer keys keep a prefix and a stable hash.
function pathKey(prefix, path) {
  const key = prefix + path;
  if (key.length <= 150) return key;
  return cutText(key, 137) + '~' + createHash('sha256').update(path).digest('hex').slice(0, 12);
}
// Display names from paths and labels stay within the measurement label limit.
const shortName = value => {
  const name = String(value);
  return name.length > 200 ? cutText(name, 199) + '…' : name;
};
// Counter families behind the Linux and Windows rate readings. A rate is missing on the first
// poll and after a counter reset, but it is still the host's own reading.
const rateFamilies = {
  linux: {
    cpu: 'node_cpu_seconds_total',
    receive: 'node_network_receive_bytes_total',
    transmit: 'node_network_transmit_bytes_total',
  },
  windows: {
    cpu: 'windows_cpu_time_total',
    received: 'windows_net_bytes_received_total',
    sent: 'windows_net_bytes_sent_total',
  },
};
// The member names of a JSON object that are not whole, by their whole spelling, built once per
// object a poll reads (see mappedSamples()). A whole spelling that two or more such names share
// names none of them: it maps to `ambiguous`.
const wholeNames = new WeakMap(),
  ambiguous = Symbol('ambiguous');
function wholeMember(object, key) {
  let names = wholeNames.get(object);
  if (!names) {
    names = new Map();
    for (const name of Object.keys(object)) {
      if (name.isWellFormed()) continue;
      const whole = name.toWellFormed();
      names.set(whole, names.has(whole) ? ambiguous : name);
    }
    wholeNames.set(object, names);
  }
  return names.get(key);
}
// Only own properties of objects and arrays are followed: indexing into a string (one character
// or its length at a time) would let mappings read back secrets the source echoes. A step holding
// U+FFFD that names no member as the source sent it may name one made whole (see mappedSamples()).
// When it names two or more made whole, the path reads nothing and `onAmbiguous` is called.
function pathValue(data, path, onAmbiguous = () => {}) {
  return path
    .split('.')
    .filter(Boolean)
    .reduce((value, key) => {
      if (value === null || typeof value !== 'object') return undefined;
      if (Object.hasOwn(value, key)) return value[key];
      if (Array.isArray(value) || !key.includes(halfMark)) return undefined;
      const name = wholeMember(value, key);
      if (name === ambiguous) onAmbiguous();
      return name === undefined || name === ambiguous ? undefined : value[name];
    }, data);
}
// Storage and totals are emitted before per-guest detail, and detail is limited to the 128
// lowest VMIDs, so large clusters cannot push capacity readings past the 512-measurement limit.
function detailedGuests(guests, notes) {
  const vmid = r => number(r.vmid) ?? Number.MAX_SAFE_INTEGER;
  if (guests.length > 128) notes.add('proxmox_guests_capped', { omitted: guests.length - 128 });
  return [...guests].sort((a, b) => vmid(a) - vmid(b)).slice(0, 128);
}
function proxmoxNodeMetrics(resources, nodeName, notes) {
  const visible = resources.filter(r => r?.type === 'node' && r.node === nodeName);
  if (visible.length !== 1)
    throw new CollectionError(
      'The selected Proxmox node is not uniquely visible. Check its exact name and token read permissions.'
    );
  const node = visible[0];
  if (!['online', 'offline'].includes(node.status))
    throw new Error('Proxmox did not report a known status for the selected node.');
  const online = node.status === 'online',
    known = online ? '' : ' (last reported)';
  const nonnegative = value => {
    const n = number(value);
    return n !== null && n >= 0 ? n : null;
  };
  const positive = value => {
    const n = nonnegative(value);
    return n > 0 ? n : null;
  };
  const memory = nonnegative(node.mem),
    memoryTotal = positive(node.maxmem),
    disk = nonnegative(node.disk),
    diskTotal = positive(node.maxdisk),
    cpu = nonnegative(node.cpu);
  const metadata = [
    metric('node_online', 'Node online', Number(online)),
    metric('nodes_online', 'Nodes online', Number(online)),
    metric('nodes_total', 'Nodes', 1),
    metric('cpu_cores', 'Logical CPUs' + known, positive(node.maxcpu)),
    metric('memory_total', 'Memory capacity' + known, memoryTotal, 'bytes'),
    metric('root_disk_total', 'Root disk capacity' + known, diskTotal, 'bytes'),
  ];
  // Offline cluster entries can retain old values. Record status/capacity only,
  // never their CPU, used memory, uptime, guest state or storage usage as live.
  if (!online) return metadata;
  const selected = resources.filter(r => r?.node === nodeName),
    guests = selected.filter(r => ['qemu', 'lxc'].includes(r.type));
  const metrics = [
    metric('cpu', 'CPU', cpu !== null && cpu <= 1 ? cpu * 100 : null, '%'),
    metric(
      'memory',
      'Memory',
      memory !== null && memoryTotal !== null ? (memory / memoryTotal) * 100 : null,
      '%'
    ),
    metric('guests_running', 'Guests', guests.filter(r => r.status === 'running').length),
    ...metadata,
    metric('guests_total', 'Total guests', guests.length),
    metric('memory_used', 'Memory used', memory, 'bytes'),
    metric('uptime', 'Uptime', nonnegative(node.uptime), 'seconds'),
    metric('root_disk_used', 'Root disk used', disk, 'bytes'),
    metric(
      'root_disk',
      'Root disk used',
      disk !== null && diskTotal !== null ? (disk / diskTotal) * 100 : null,
      '%'
    ),
  ];
  proxmoxStorages(selected, notes, metrics);
  for (const r of [node, ...detailedGuests(guests, notes)]) {
    const { id, name } = proxmoxEntry(r, notes) ?? {};
    if (id === undefined) continue;
    const cpu = nonnegative(r.cpu);
    metrics.push(
      metric(
        upstreamKey('', id, '.cpu'),
        upstreamLabel(name, ' · CPU'),
        cpu !== null && cpu <= 1 ? cpu * 100 : null,
        '%'
      ),
      metric(upstreamKey('', id, '.memory'), upstreamLabel(name, ' · Memory'), r.mem, 'bytes'),
      metric(upstreamKey('', id, '.uptime'), upstreamLabel(name, ' · Uptime'), r.uptime, 'seconds')
    );
  }
  return metrics;
}
// A node's or guest's key prefix and name: its resource ID ("node/pve", "qemu/100") and its name.
// Without them a node goes by its node name and a guest by its VMID (a guest's node name is its
// host's, which every guest there shares). null, and noted, when it has neither.
function proxmoxEntry(resource, notes) {
  const own = resource.type === 'node' ? resource.node : resource.vmid,
    id = firstId(resource.id, own);
  if (id === null) {
    notes.unnamed();
    return null;
  }
  return { id, name: firstText(resource.name, own, resource.id) };
}
// The used and total bytes of each storage that has an ID ("storage/pve/local"), appended to
// `metrics` one by one: a spread of a large storage list into one push() overflowed the call
// stack (RangeError) and failed the whole source, where the 512-reading cap should apply.
function proxmoxStorages(resources, notes, metrics) {
  for (const r of resources.filter(r => r.type === 'storage')) {
    const id = upstreamId(r.id);
    if (id === null) {
      notes.unnamed();
      continue;
    }
    const name = firstText(r.storage, r.id);
    metrics.push(
      metric(upstreamKey('', id, '.used'), upstreamLabel(name, ' · Used'), r.disk, 'bytes'),
      metric(upstreamKey('', id, '.total'), upstreamLabel(name, ' · Capacity'), r.maxdisk, 'bytes')
    );
  }
}
// Each request's own time limit. The server passes one scaled to the collection deadline;
// direct callers (and tests) get the historic 12 seconds.
function requestTimeout(service) {
  const ms = service.requestTimeoutMs;
  return Number.isFinite(ms) && ms >= 1000 ? Math.round(ms) : 12000;
}
// *arr health entries are notice, warning or error; only warnings and errors are issues.
const healthIssues = health =>
  health.filter(h => h?.type === 'warning' || h?.type === 'error').length;
/**
 * The session token a sign-in answered with (NPM and CrowdSec: a JWT; AMP: a session GUID), or
 * a CollectionError. Uptime Goblin sends it back in a header or a JSON body and keeps it for the
 * session's life, so only a token68 (RFC 7235: letters, digits and -._~+/, then '=' padding)
 * of at most 8,192 characters is kept: an object would be sent as "[object Object]", a line
 * break would make the header invalid on every read until the session expired, and the error
 * quoting it would carry the token. Nothing of the answer is repeated.
 */
function sessionToken(value, product) {
  if (typeof value !== 'string' || value.length > 8192 || !/^[A-Za-z0-9\-._~+/]+=*$/.test(value))
    throw new CollectionError(`${product} sign-in returned an unusable session token.`);
  return value;
}
function jwtExpiry(token) {
  const part = typeof token === 'string' ? token.split('.')[1] : undefined;
  if (!part) return null;
  try {
    const exp = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')).exp;
    return Number.isFinite(exp) ? exp * 1000 : null;
  } catch {
    return null;
  }
}
/**
 * Runs `use` with a signed-in session. Sessions are kept until the service rejects them
 * (401/403) or their token expires, not dropped on timeouts or server errors: dropping them
 * made every retry sign in again, and services that rate-limit sign-in (UniFi OS does) then
 * turned a brief blip into a long lockout. Renewal starts a little before a token expires;
 * if renewing fails (timeout, server error, rate limit) the still-valid session is used.
 * A sign-in answered with HTTP 429 pauses sign-ins for Retry-After (60 s by default).
 */
async function withSession(service, name, { maxAgeMs, login }, use) {
  const key = service.id + ':' + name + ':' + service.apiUrl,
    now = Date.now(),
    hhmm = time => new Date(time).toISOString().slice(11, 16);
  let session = sessions.get(key),
    reused = Boolean(session);
  // A session past its renewal time stays usable until its token's real expiry (if known).
  const usable = session && (session.hardExpiry == null || now < session.hardExpiry);
  if (!session || now >= session.renewAt) {
    const blocked = loginBlocks.get(key);
    if (blocked && now < blocked.until) {
      if (!usable)
        throw new CollectionError(
          `${name} is limiting sign-ins from Uptime Goblin. Uptime Goblin will sign in again after ${hhmm(blocked.until)} UTC.`
        );
    } else
      try {
        const next = await login();
        service.signal?.throwIfAborted();
        loginBlocks.delete(key);
        const expiry = Number.isFinite(next.expiresAt) ? next.expiresAt : null;
        next.hardExpiry = expiry;
        next.renewAt = Math.min(
          now + maxAgeMs,
          expiry ? Math.max(now + 60 * 1000, expiry - 5 * 60 * 1000) : Infinity
        );
        sessions.set(key, next);
        session = next;
        reused = false;
      } catch (error) {
        service.signal?.throwIfAborted();
        const limited = error instanceof CollectionError && error.status === 429;
        if (limited) loginBlocks.set(key, { until: now + (error.retryAfterMs ?? 60 * 1000) });
        const rejected = error instanceof CollectionError && [401, 403].includes(error.status);
        if (!usable || rejected) {
          if (rejected) sessions.delete(key);
          if (limited)
            throw new CollectionError(
              `${name} is limiting sign-ins from Uptime Goblin (HTTP 429). Uptime Goblin will sign in again after ${hhmm(loginBlocks.get(key).until)} UTC.`,
              { status: 429 }
            );
          throw error;
        }
      }
  }
  try {
    return await use(session, reused);
  } catch (error) {
    if (error instanceof CollectionError && [401, 403].includes(error.status)) {
      if (sessions.get(key) === session) sessions.delete(key);
      throw rejectedCachedSession(error, reused);
    }
    throw error;
  }
}
function rejectedCachedSession(error, cached) {
  if (cached && error instanceof CollectionError && [401, 403].includes(error.status))
    error.refreshSession = true;
  return error;
}
export async function collect(service) {
  // A rejected cached session may be refreshed once. A rejected fresh login/session
  // is permanent, and this remains inside the logical poll's original deadline.
  const budget = service.sessionRefreshBudget ?? { remaining: 1 };
  for (;;) {
    service.signal?.throwIfAborted();
    const controller = new AbortController(),
      signal = service.signal
        ? AbortSignal.any([service.signal, controller.signal])
        : controller.signal;
    try {
      // A fresh read budget per attempt: it spans every request and page of one collection.
      return await collectOnce({ ...service, signal, readBudget: readBudget() });
    } catch (error) {
      service.signal?.throwIfAborted();
      if (budget.remaining <= 0 || error.refreshSession !== true) throw error;
      budget.remaining--;
    } finally {
      controller.abort();
    }
  }
}
async function collectOnce(service) {
  const get = (route, headers = {}) => request(service, route, { headers });
  const now = Date.now(),
    rateUpdates = new Map(),
    notes = new Notes();
  let metrics = [];
  switch (service.type) {
    case 'http': {
      metrics = await probeHttp(service);
      break;
    }
    case 'cosmos': {
      const headers = { Authorization: 'Bearer ' + service.apiKey };
      let hostNow;
      const [response, apps] = await Promise.all([
        request(
          service,
          '/cosmos/api/metrics?metrics=cosmos.system.cpu.0,cosmos.system.ram,cosmos.system.netRx,cosmos.system.netTx',
          { headers, onHeaders: h => (hostNow = Date.parse(h.get('date'))) }
        ),
        get('/cosmos/api/servapps', headers),
      ]);
      // Sample times come from the Cosmos host's clock, so their age is measured against that
      // clock (its Date header) when it sends one: a clock difference between the hosts would
      // otherwise make fresh samples look stale, or stale ones fresh.
      const reference = Number.isFinite(hostNow) ? hostNow : now;
      if (requireObject(response).status !== 'OK' || requireObject(apps).status !== 'OK')
        throw new CollectionError('Cosmos rejected the request. Check API token permissions.');
      const rows = requireArray(response.data, { objects: true }),
        containers = requireArray(apps.data, { objects: true });
      const current = key => {
        const m = rows.find(r => r.Key === key);
        if (!m || !Array.isArray(m.Values) || !m.Values.length) return null;
        requireArray(m.Values, { objects: true });
        const value = m.Values.reduce((a, b) => (new Date(b.Date) > new Date(a.Date) ? b : a));
        const date = Date.parse(value.Date || m.LastUpdate);
        if (!Number.isFinite(date) || reference - date > 180000)
          throw new Error(
            'Cosmos measurements are stale. Check that native monitoring is enabled.'
          );
        return {
          value: number(value.Value),
          max: number(m.Max),
          scale: number(m.Scale) || 1,
          seconds: (number(m.TimeScale) || 1) * 30,
        };
      };
      const cpu = current('cosmos.system.cpu.0'),
        ram = current('cosmos.system.ram'),
        rx = current('cosmos.system.netRx'),
        tx = current('cosmos.system.netTx');
      if (!cpu && !ram)
        throw new Error('Cosmos returned no recent system measurements. Enable native monitoring.');
      metrics = [
        metric('cpu', 'CPU', cpu?.value == null ? null : cpu.value / cpu.scale, '%'),
        metric(
          'memory',
          'Memory',
          ram?.max && ram?.value !== null ? (ram.value / ram.max) * 100 : null,
          '%'
        ),
        metric('containers', 'Containers', containers.length),
        metric('running', 'Running', containers.filter(c => c.State === 'running').length),
        metric('memory_used', 'Memory used', ram?.value, 'bytes'),
        metric('memory_total', 'Memory total', ram?.max, 'bytes'),
        metric('receive', 'Receive', rx?.value == null ? null : rx.value / rx.seconds, 'bytes/s'),
        metric('transmit', 'Send', tx?.value == null ? null : tx.value / tx.seconds, 'bytes/s'),
      ];
      break;
    }
    case 'amp': {
      const unwrap = v =>
        v && Object.keys(v).length === 1 && Object.hasOwn(v, 'result') ? v.result : v;
      async function call(route, body) {
        const options = jsonBody(body);
        options.headers.Accept = 'application/vnd.cubecoders-ampapi';
        return unwrap(await request(service, '/API/' + route, options));
      }
      const login = async () => {
        const answer = await call('Core/Login', {
          username: service.username,
          password: service.password,
          token: service.apiKey || '',
          rememberMe: false,
        });
        if (!answer?.success || !answer.sessionID)
          throw new CollectionError(
            'AMP login failed. Check credentials or use a service login token.'
          );
        return { token: sessionToken(answer.sessionID, 'AMP') };
      };
      const status = await withSession(
        service,
        'AMP',
        { maxAgeMs: 20 * 60 * 1000, login },
        async (session, reused) => {
          const answer = await call('Core/GetStatus', { SESSIONID: session.token });
          // AMP reports a session it no longer knows (after a restart) in the body of a
          // normal response; treat that, or no metrics from a reused session, as expired.
          if (
            answer?.Title === 'Unauthorized Access' ||
            (answer?.Status === false && /session|auth/i.test(String(answer?.Message ?? ''))) ||
            (reused && !answer?.Metrics)
          )
            throw new CollectionError('AMP session expired.', { status: 401 });
          if (!answer?.Metrics)
            throw new Error('AMP returned no instance metrics. Use a direct managed-instance URL.');
          return answer;
        }
      );
      // Every metric AMP lists is an object ({RawValue, MaxValue, Percent, Units}).
      const entries = requireObject(status.Metrics);
      if (!Object.values(entries).every(isObject)) throw unexpectedResponse();
      const cpu = entries['CPU Usage'],
        memory = entries['Memory Usage'],
        users = entries['Active Users'];
      metrics = [
        metric('cpu', 'CPU', cpu?.Percent ?? cpu?.RawValue, '%'),
        metric('memory', 'Memory', memory?.RawValue, upstreamUnit(memory?.Units)),
        metric('players', 'Players', users?.RawValue),
        metric('memory_percent', 'Memory used', memory?.Percent, '%'),
        metric('players_max', 'Player capacity', users?.MaxValue),
      ];
      for (const [name, value] of Object.entries(entries)) {
        if (['CPU Usage', 'Memory Usage', 'Active Users'].includes(name)) continue;
        const key = upstreamKey('amp_', name.replace(/[^a-zA-Z0-9]/g, '_'));
        metrics.push(
          metric(
            key,
            upstreamLabel(upstreamText(name) ?? key),
            value.RawValue,
            upstreamUnit(value.Units)
          )
        );
      }
      break;
    }
    case 'proxmox': {
      const token = service.apiKey.startsWith('PVEAPIToken=')
        ? service.apiKey
        : 'PVEAPIToken=' + service.apiKey;
      const resources = requireArray(
        requireObject(await get('/api2/json/cluster/resources', { Authorization: token })).data,
        { objects: true }
      );
      if (service.nodeName) {
        metrics = proxmoxNodeMetrics(resources, service.nodeName, notes);
        break;
      }
      if (!resources.length)
        throw new CollectionError('No resources visible. Check API token permissions.');
      // As in node mode, a node that is not online keeps its last capacity and usage: it counts
      // toward nodes_total only, and its runtime, guests' runtime and storage are left out so
      // the cluster totals describe the nodes that are running.
      const nodes = resources.filter(r => r.type === 'node'),
        online = nodes.filter(r => r.status === 'online'),
        down = new Set(nodes.filter(r => r.status !== 'online').map(r => r.node)),
        live = r => !down.has(r.node),
        guests = resources.filter(r => ['qemu', 'lxc'].includes(r.type));
      // Each node reports its CPU use as a share of its own CPUs (0-1): clamped to that range and
      // weighted by its CPU count, so one node's broken value cannot take the cluster below 0 %
      // or above 100 %.
      const cpus = n => Math.max(0, number(n.maxcpu) ?? 0),
        share = n => Math.min(1, Math.max(0, number(n.cpu) ?? 0));
      const mem = sum(online, 'mem'),
        maxmem = sum(online, 'maxmem'),
        cores = sum(online, cpus);
      metrics = [
        metric(
          'cpu',
          'CPU',
          cores ? (sum(online, n => share(n) * cpus(n)) / cores) * 100 : null,
          '%'
        ),
        metric('memory', 'Memory', maxmem ? (mem / maxmem) * 100 : null, '%'),
        metric(
          'guests_running',
          'Guests',
          guests.filter(r => live(r) && r.status === 'running').length
        ),
        metric('nodes_online', 'Nodes online', online.length),
        metric('nodes_total', 'Nodes', nodes.length),
        metric('guests_total', 'Total guests', guests.length),
        metric('memory_used', 'Memory used', mem, 'bytes'),
        metric('memory_total', 'Memory total', maxmem, 'bytes'),
      ];
      proxmoxStorages(resources.filter(live), notes, metrics);
      for (const r of [...online, ...detailedGuests(guests.filter(live), notes)]) {
        const { id, name } = proxmoxEntry(r, notes) ?? {};
        if (id === undefined) continue;
        metrics.push(
          metric(
            upstreamKey('', id, '.cpu'),
            upstreamLabel(name, ' · CPU'),
            number(r.cpu) === null ? null : number(r.cpu) * 100,
            '%'
          ),
          metric(upstreamKey('', id, '.memory'), upstreamLabel(name, ' · Memory'), r.mem, 'bytes'),
          metric(
            upstreamKey('', id, '.uptime'),
            upstreamLabel(name, ' · Uptime'),
            r.uptime,
            'seconds'
          )
        );
      }
      break;
    }
    case 'sonarr':
    case 'radarr': {
      const isTv = service.type === 'sonarr',
        headers = keyHeaders(service);
      // Only counts are needed from the library, so it is streamed (see LIBRARY_LIMIT).
      const tally = { files: 0, missing: 0 };
      const library = request(service, '/api/v3/' + (isTv ? 'series' : 'movie'), {
        headers,
        limit: LIBRARY_LIMIT,
        each: isTv
          ? series => {
              const files = number(series?.statistics?.episodeFileCount) ?? 0;
              tally.files += files;
              // Fallback count; like Sonarr's Wanted view it leaves out unmonitored series.
              if (series?.monitored !== false)
                tally.missing += Math.max(
                  0,
                  (number(series?.statistics?.episodeCount) ?? 0) - files
                );
            }
          : movie => {
              // Matches Radarr's Wanted view: unmonitored and not-yet-released movies are not
              // missing.
              if (
                movie &&
                movie.monitored !== false &&
                movie.isAvailable !== false &&
                !movie.hasFile
              )
                tally.missing++;
            },
      }).then(
        count => count ?? requireArray(null),
        // An oversized library costs only its own readings: queue, health and disk (and
        // Sonarr's missing count) are still reported rather than failing the whole source.
        error => {
          if (!error?.tooLarge) throw error;
          notes.add('arr_library_too_large', { product: isTv ? 'Sonarr' : 'Radarr' });
          return null;
        }
      );
      // Sonarr's Wanted > Missing count, read as the total of a one-record page. The library
      // count stands in only where that endpoint is missing.
      const wanted = isTv
        ? get('/api/v3/wanted/missing?page=1&pageSize=1&monitored=true', headers).catch(error => {
            if (error?.status === 404) return null;
            throw error;
          })
        : null;
      const [items, queue, health, disk, missing] = await Promise.all([
        library,
        get('/api/v3/queue/status', headers),
        get('/api/v3/health', headers),
        get('/api/v3/diskspace', headers),
        wanted,
      ]);
      requireObject(queue);
      requireArray(health, { objects: true });
      requireArray(disk, { objects: true });
      const counted = value => (items === null ? null : value);
      metrics = isTv
        ? [
            metric('series', 'Series', items),
            metric('episodes', 'Episodes', counted(tally.files)),
            metric('queue', 'Queue', queue.totalCount ?? queue.count),
            metric(
              'missing',
              'Missing episodes',
              number(missing?.totalRecords) ?? counted(tally.missing)
            ),
          ]
        : [
            metric('movies', 'Movies', items),
            metric('missing', 'Missing', counted(tally.missing)),
            metric('queue', 'Queue', queue.totalCount ?? queue.count),
          ];
      metrics.push(
        // Notices (e.g. an update is available) are informational; issues are warnings/errors.
        metric('health_issues', 'Health issues', healthIssues(health)),
        metric('health_notices', 'Health notices', health.filter(h => h.type === 'notice').length),
        metric(
          'queue_errors',
          'Queue has errors',
          typeof queue.errors === 'boolean'
            ? Number(Boolean(queue.errors || queue.unknownErrors))
            : queue.errors
        ),
        metric(
          'queue_warnings',
          'Queue has warnings',
          typeof queue.warnings === 'boolean'
            ? Number(Boolean(queue.warnings || queue.unknownWarnings))
            : queue.warnings
        )
      );
      // Keys follow the path: the list order shifts when a mount appears or goes stale, and an
      // index key would then point history and rules at a different filesystem. A path listed
      // twice gives the same keys twice, which collect() keeps once and notes.
      disk.forEach((d, i) => {
        const path = typeof d.path === 'string' ? upstreamId(d.path) : null,
          free = path === null ? 'disk_' + i + '_free' : pathKey('disk_free_', path),
          name =
            (typeof d.path === 'string' ? upstreamText(d.path) : null) ??
            firstText(d.label) ??
            'Disk ' + (i + 1);
        metrics.push(
          metric(free, upstreamLabel(name, ' · Free'), d.freeSpace, 'bytes'),
          metric(
            path === null ? 'disk_' + i + '_total' : pathKey('disk_total_', path),
            upstreamLabel(name, ' · Capacity'),
            d.totalSpace,
            'bytes'
          )
        );
      });
      break;
    }
    case 'seerr': {
      const counts = requireObject(await get('/api/v1/request/count', keyHeaders(service)));
      if (number(counts.total) === null) throw new Error('Seerr did not return request counts');
      metrics = [
        'pending',
        'approved',
        'available',
        'processing',
        'declined',
        'completed',
        'total',
        'movie',
        'tv',
      ].map(k => metric(k, k[0].toUpperCase() + k.slice(1), counts[k]));
      break;
    }
    case 'prowlarr': {
      const end = new Date(now).toISOString(),
        start = new Date(now - 86400000).toISOString();
      const [stats, indexers, health] = await Promise.all([
        get(
          `/api/v1/indexerstats?startDate=${encodeURIComponent(start)}&endDate=${encodeURIComponent(end)}`,
          keyHeaders(service)
        ),
        get('/api/v1/indexer', keyHeaders(service)),
        get('/api/v1/health', keyHeaders(service)),
      ]);
      const items = requireArray(requireObject(stats).indexers, { objects: true });
      requireArray(indexers);
      requireArray(health, { objects: true });
      metrics = [
        metric('indexers', 'Indexers', indexers.length),
        metric(
          'queries_24h',
          'Queries · 24h',
          sum(items, 'numberOfQueries') + sum(items, 'numberOfRssQueries')
        ),
        metric(
          'failures_24h',
          'Failures · 24h',
          sum(items, 'numberOfFailedQueries') +
            sum(items, 'numberOfFailedGrabs') +
            sum(items, 'numberOfFailedRssQueries') +
            sum(items, 'numberOfFailedAuthQueries')
        ),
        metric('grabs_24h', 'Grabs · 24h', sum(items, 'numberOfGrabs')),
        metric('health_issues', 'Health issues', healthIssues(health)),
        metric('health_notices', 'Health notices', health.filter(h => h.type === 'notice').length),
      ];
      for (const i of items) {
        const id = upstreamId(i.indexerId);
        if (id === null) {
          notes.unnamed();
          continue;
        }
        metrics.push(
          metric(
            upstreamKey('indexer_', id, '_response'),
            upstreamLabel(firstText(i.indexerName, i.indexerId), ' · Response'),
            i.averageResponseTime,
            'ms'
          )
        );
      }
      break;
    }
    case 'sabnzbd': {
      const result = await get(
        '/api?mode=queue&output=json&apikey=' + encodeURIComponent(service.apiKey)
      );
      if (!requireObject(result).queue)
        throw new Error('SABnzbd rejected the API request. Use the full API key.');
      const q = requireObject(result.queue);
      metrics = [
        metric(
          'speed',
          'Speed',
          number(q.kbpersec) === null ? null : Number(q.kbpersec) * 1024,
          'bytes/s'
        ),
        metric('queue', 'Queue', q.noofslots_total ?? q.noofslots),
        metric(
          'remaining',
          'Remaining',
          number(q.mbleft) === null ? null : Number(q.mbleft) * 1048576,
          'bytes'
        ),
        metric('paused', 'Paused', q.paused === undefined ? null : Number(q.paused)),
        metric(
          'download_disk_free',
          'Download disk free',
          number(q.diskspace1) === null ? null : Number(q.diskspace1) * 1073741824,
          'bytes'
        ),
        metric(
          'complete_disk_free',
          'Completed disk free',
          number(q.diskspace2) === null ? null : Number(q.diskspace2) * 1073741824,
          'bytes'
        ),
      ];
      break;
    }
    case 'nzbget': {
      const rpc = jsonBody({ jsonrpc: '2.0', method: 'status', params: [], id: 1 });
      rpc.headers = { ...rpc.headers, ...basicHeaders(service) };
      const response = await request(service, '/jsonrpc', rpc);
      if (requireObject(response).error || !response.result)
        throw new Error('NZBGet rejected the status request');
      const q = requireObject(response.result);
      metrics = [
        metric('speed', 'Speed', highLow(q, 'DownloadRate'), 'bytes/s'),
        metric('post_jobs', 'Post-processing', q.PostJobCount),
        metric(
          'remaining',
          'Remaining',
          highLow(q, 'RemainingSize') ??
            (number(q.RemainingSizeMB) === null ? null : Number(q.RemainingSizeMB) * 1048576),
          'bytes'
        ),
        metric(
          'downloaded',
          'Downloaded',
          highLow(q, 'DownloadedSize') ??
            (number(q.DownloadedSizeMB) === null ? null : Number(q.DownloadedSizeMB) * 1048576),
          'bytes'
        ),
        metric('uptime', 'Uptime', q.UpTimeSec, 'seconds'),
        metric(
          'paused',
          'Paused',
          q.DownloadPaused === undefined ? null : Number(q.DownloadPaused)
        ),
        metric(
          'free_disk',
          'Free disk',
          highLow(q, 'FreeDiskSpace') ??
            (number(q.FreeDiskSpaceMB) === null ? null : Number(q.FreeDiskSpaceMB) * 1048576),
          'bytes'
        ),
      ];
      break;
    }
    case 'plex': {
      const container = requireObject(
        await get('/status/sessions', { 'X-Plex-Token': service.apiKey })
      ).MediaContainer;
      if (!container || number(container.size) === null)
        throw new Error('Plex did not return session information');
      const items = requireArray(container.Metadata ?? [], { objects: true });
      // Plex attaches a TranscodeSession to Direct Stream (remux) sessions too. As in Tautulli,
      // only a video or audio 'transcode' decision is a transcode; a 'copy' is a direct stream.
      // A session without decisions (older servers) still counts as a transcode.
      const decisions = s => {
        const t = s?.TranscodeSession;
        return t && typeof t === 'object' ? [t.videoDecision, t.audioDecision] : null;
      };
      const transcoding = s => {
        const d = decisions(s);
        return Boolean(d && (d.includes('transcode') || d.every(v => v === undefined)));
      };
      metrics = [
        metric('streams', 'Streams', container.size),
        metric('transcodes', 'Transcodes', items.filter(transcoding).length),
        metric(
          'bandwidth',
          'Bandwidth',
          (sum(items, s => s.Session?.bandwidth) * 1000) / 8,
          'bytes/s'
        ),
        metric('paused', 'Paused', items.filter(s => s.Player?.state === 'paused').length),
        metric(
          'direct_stream',
          'Direct stream',
          items.filter(s => !transcoding(s) && decisions(s)?.includes('copy')).length
        ),
      ];
      break;
    }
    case 'tautulli': {
      // Query-key authentication is supported by older Tautulli releases too.
      const result = requireObject(
        await get('/api/v2?cmd=get_activity&apikey=' + encodeURIComponent(service.apiKey))
      ).response;
      if (result?.result !== 'success') throw new Error('Tautulli rejected the activity request');
      const s = requireObject(result.data);
      metrics = [
        metric('streams', 'Streams', s.stream_count),
        metric('transcodes', 'Transcodes', s.stream_count_transcode),
        metric(
          'bandwidth',
          'Bandwidth',
          number(s.total_bandwidth) === null ? null : (Number(s.total_bandwidth) * 1000) / 8,
          'bytes/s'
        ),
        metric('direct_play', 'Direct play', s.stream_count_direct_play),
        metric('direct_stream', 'Direct stream', s.stream_count_direct_stream),
        metric(
          'lan_bandwidth',
          'LAN bandwidth',
          number(s.lan_bandwidth) === null ? null : (Number(s.lan_bandwidth) * 1000) / 8,
          'bytes/s'
        ),
        metric(
          'wan_bandwidth',
          'WAN bandwidth',
          number(s.wan_bandwidth) === null ? null : (Number(s.wan_bandwidth) * 1000) / 8,
          'bytes/s'
        ),
      ];
      break;
    }
    case 'unifi': {
      if (!service.apiKey) {
        metrics = await unifiLocal(service, now, notes);
        break;
      }
      const headers = { 'X-API-KEY': service.apiKey };
      // Only the address path can already point at the Integration API; a host name such as
      // integration.example.com must not.
      const suffix = /(^|\/)integration(\/|$)/.test(new URL(service.apiUrl).pathname)
        ? ''
        : '/proxy/network/integration';
      // Lists are read in pages of 200 (the Integration API's largest): each list up to
      // UNIFI_LIST_PAGES pages and UNIFI_LIST_ENTRIES entries, devices and clients for up to
      // UNIFI_SITES sites, and at most UNIFI_LIST_REQUESTS list requests per collection, whatever
      // totalCount says. A broken or hostile controller answering one entry per page with a huge
      // total was otherwise asked tens of thousands of times a second until the deadline.
      let listRequests = 0;
      async function pages(route) {
        const all = [];
        let offset = 0;
        for (let page = 0; page < UNIFI_LIST_PAGES; page++) {
          if (++listRequests > UNIFI_LIST_REQUESTS)
            throw new CollectionError(
              `UniFi lists took more than ${thousands(UNIFI_LIST_REQUESTS)} requests in one collection. Enter one site ID, or check the controller.`
            );
          const body = requireObject(
            await get(suffix + route + `?offset=${offset}&limit=200`, headers)
          );
          const list = requireArray(body.data, { objects: true }),
            total = body.totalCount ?? null;
          if (total !== null && !(Number.isSafeInteger(total) && total >= 0))
            throw unexpectedResponse();
          // One entry at a time, up to the cap: spreading a page of 100,000s of entries into
          // push() overflowed the call stack (a RangeError), and a page longer than the cap was
          // counted in full.
          for (const entry of list.slice(0, UNIFI_LIST_ENTRIES - all.length)) all.push(entry);
          offset += list.length;
          if (!list.length || offset >= (total ?? offset)) {
            if (offset > all.length) notes.add('unifi_lists_capped');
            return all;
          }
          if (all.length >= UNIFI_LIST_ENTRIES) break;
        }
        // More entries remain than the entry or page limit reads.
        notes.add('unifi_lists_capped');
        return all;
      }
      const sites = await pages('/v1/sites');
      // A site is read by its ID, which must be a string, and once: a controller that ignores
      // the offset lists the same sites again.
      const named = sites.filter(site => typeof site.id === 'string' && site.id),
        ids = new Set(),
        unique = named.filter(site => !ids.has(site.id) && ids.add(site.id));
      if (named.length < sites.length) notes.unnamed(sites.length - named.length);
      const wanted = service.siteId ? unique.filter(s => s.id === service.siteId) : unique;
      if (!wanted.length) throw new Error('No UniFi sites visible. Check the API key and site ID.');
      if (wanted.length > UNIFI_SITES)
        notes.add('unifi_sites_capped', { omitted: wanted.length - UNIFI_SITES });
      let devices = [],
        clients = [];
      for (const site of wanted.slice(0, UNIFI_SITES)) {
        const [d, c] = await Promise.all([
          pages(`/v1/sites/${encodeURIComponent(site.id)}/devices`),
          pages(`/v1/sites/${encodeURIComponent(site.id)}/clients`),
        ]);
        for (const device of d) devices.push({ ...device, siteId: site.id });
        for (const client of c) clients.push(client);
      }
      metrics = [
        metric('devices', 'Devices', devices.length),
        metric('clients', 'Clients', clients.length),
        metric('sites', 'Sites', wanted.length),
        metric(
          'devices_online',
          'Devices online',
          devices.filter(d => d.state === 'ONLINE').length
        ),
      ];
      // Device-level readings are serialized to avoid a controller request burst. They are
      // best-effort, so together they get one request time limit, and each at most 5 s: hung
      // statistics endpoints then cost device detail, not the collection deadline and the
      // counts above.
      const detailEnds = performance.now() + requestTimeout(service);
      const beyond = devices.slice(64).filter(d => d.state === 'ONLINE').length;
      if (beyond) notes.add('unifi_devices_capped', { omitted: beyond });
      for (const d of devices.slice(0, 64)) {
        if (d.state !== 'ONLINE') continue;
        // Read by its ID (a string), and named by it when it has no usable name.
        const id = typeof d.id === 'string' ? upstreamId(d.id) : null;
        if (id === null) {
          notes.unnamed();
          continue;
        }
        const left = Math.min(5000, detailEnds - performance.now());
        if (left < 1000) break;
        let stats;
        try {
          stats = await request(
            { ...service, requestTimeoutMs: left },
            suffix +
              `/v1/sites/${encodeURIComponent(d.siteId)}/devices/${encodeURIComponent(d.id)}/statistics/latest`,
            { headers }
          );
        } catch {
          service.signal?.throwIfAborted();
          continue;
        }
        if (!isObject(stats)) continue;
        const key = suffix => upstreamKey('device_', id, suffix),
          name = firstText(d.name, d.id),
          label = suffix => upstreamLabel(name, suffix),
          rate = value => (number(value) === null ? null : number(value) / 8);
        metrics.push(
          metric(key('_cpu'), label(' · CPU'), stats.cpuUtilizationPct, '%'),
          metric(key('_memory'), label(' · Memory'), stats.memoryUtilizationPct, '%'),
          metric(key('_uptime'), label(' · Uptime'), stats.uptimeSec, 'seconds'),
          metric(key('_rx'), label(' · Receive'), rate(stats.uplink?.rxRateBps), 'bytes/s'),
          metric(key('_tx'), label(' · Send'), rate(stats.uplink?.txRateBps), 'bytes/s')
        );
      }
      break;
    }
    case 'adguard': {
      const s = requireObject(await get('/control/stats', basicHeaders(service)));
      const queries = number(s.num_dns_queries),
        blocked = number(s.num_blocked_filtering);
      if (queries === null) throw new Error('AdGuard Home did not return statistics');
      metrics = [
        metric('queries', 'Queries', s.num_dns_queries),
        metric('blocked', 'Blocked', s.num_blocked_filtering),
        metric(
          'response',
          'Response',
          number(s.avg_processing_time) === null ? null : s.avg_processing_time * 1000,
          'ms'
        ),
        metric(
          'blocked_percent',
          'Blocked',
          queries === 0 ? 0 : blocked === null ? null : (100 * blocked) / queries,
          '%'
        ),
        metric('safe_browsing', 'Safe browsing', s.num_replaced_safebrowsing),
        metric('parental', 'Parental filtering', s.num_replaced_parental),
      ];
      break;
    }
    case 'npm': {
      const login = async () => {
        const answer = await request(
          service,
          '/api/tokens',
          jsonBody({ identity: service.username, secret: service.password })
        );
        if (!requireObject(answer).token) throw new Error('Nginx Proxy Manager login failed');
        const token = sessionToken(answer.token, 'Nginx Proxy Manager');
        return { token, expiresAt: jwtExpiry(token) };
      };
      const hosts = await withSession(
        service,
        'Nginx Proxy Manager',
        { maxAgeMs: 30 * 60 * 1000, login },
        async session =>
          requireArray(
            await get('/api/nginx/proxy-hosts', { Authorization: 'Bearer ' + session.token }),
            { objects: true }
          )
      );
      metrics = [
        metric('enabled', 'Enabled', hosts.filter(h => h.enabled).length),
        metric('disabled', 'Disabled', hosts.filter(h => !h.enabled).length),
        metric('hosts', 'Hosts', hosts.length),
      ];
      break;
    }
    case 'docker': {
      const containers = requireArray(await get('/containers/json?all=1'), { objects: true });
      metrics = [
        metric('running', 'Running', containers.filter(c => c.State === 'running').length),
        metric('stopped', 'Stopped', containers.filter(c => c.State !== 'running').length),
        metric('containers', 'Containers', containers.length),
      ];
      break;
    }
    case 'crowdsec': {
      const login = async () => {
        const answer = await request(
          service,
          '/v1/watchers/login',
          jsonBody({ machine_id: service.username, password: service.password })
        );
        if (!requireObject(answer).token) throw new Error('CrowdSec machine login failed');
        const token = sessionToken(answer.token, 'CrowdSec');
        return { token, expiresAt: jwtExpiry(token) };
      };
      // Local activity only, as `cscli alerts list` and `cscli decisions list` show it: an
      // enrolled LAPI also holds tens of thousands of community (CAPI) and subscribed blocklist
      // entries, which swamp local counts. Both lists are streamed, so a busy LAPI cannot
      // exceed the collection read budget. Alerts carry their events and decisions (a bulk
      // `cscli decisions import` puts every imported decision in one alert, often over 1 MB),
      // so they are only counted, never parsed.
      const alerts = await withSession(
        service,
        'CrowdSec',
        { maxAgeMs: 30 * 60 * 1000, login },
        session =>
          request(service, '/v1/alerts?since=24h&limit=1000&include_capi=false', {
            headers: { Authorization: 'Bearer ' + session.token },
            count: true,
          }).then(
            count => {
              if (count >= 1000) notes.add('crowdsec_alerts_capped');
              return count ?? 0;
            },
            // Alerts over the response limit cost only their own count when decision and ban
            // counts can still be reported.
            error => {
              if (!error?.tooLarge || !service.apiKey) throw error;
              notes.add('crowdsec_alerts_too_large');
              return null;
            }
          )
      );
      // The bouncer key is separate from the machine session: its errors never drop the session.
      let decisions,
        bans = 0;
      if (service.apiKey)
        decisions =
          (await request(service, '/v1/decisions?origins=crowdsec,cscli,cscli-import,console', {
            headers: { 'X-Api-Key': service.apiKey },
            each: d => {
              if (d?.type === 'ban') bans++;
            },
          })) ?? 0;
      metrics = [
        metric('alerts_24h', 'Alerts · 24h (max 1k)', alerts),
        metric('decisions', 'Local decisions', decisions),
        metric('bans', 'Local bans', decisions === undefined ? null : bans),
      ];
      break;
    }
    case 'linux':
    case 'windows':
    case 'synology':
    case 'wireguard':
    case 'prometheus': {
      const samples = parsePrometheus(
        await request(service, service.metricPath || '/metrics', {
          text: true,
          headers: service.apiKey ? { Authorization: 'Bearer ' + service.apiKey } : {},
        }),
        service.readBudget ?? readBudget()
      );
      if (!samples.length) throw new Error('No numeric Prometheus measurements found');
      if (service.type === 'linux') {
        const idle = total(samples, 'node_cpu_seconds_total', { mode: 'idle' }),
          all = total(samples, 'node_cpu_seconds_total');
        const idleRate = delta(service.id, 'cpu_idle', idle, now, rateUpdates),
          allRate = delta(service.id, 'cpu_total', all, now, rateUpdates);
        const memory = first(samples, 'node_memory_MemTotal_bytes'),
          available = first(samples, 'node_memory_MemAvailable_bytes');
        // Boot time is on the exporter host's clock, so uptime uses that host's own time
        // (node_time_seconds, on by default) and Uptime Goblin's clock only when it is missing.
        const boot = first(samples, 'node_boot_time_seconds'),
          hostNow = first(samples, 'node_time_seconds') ?? now / 1000;
        metrics = [
          metric(
            'cpu',
            'CPU',
            allRate > 0 && idleRate !== null
              ? Math.max(0, Math.min(100, (1 - idleRate / allRate) * 100))
              : null,
            '%'
          ),
          metric(
            'memory',
            'Memory',
            memory && available !== null ? (1 - available / memory) * 100 : null,
            '%'
          ),
        ];
        const filesystems = selected(samples, 'node_filesystem_size_bytes').filter(
          m =>
            m.labels.fstype !== 'tmpfs' &&
            !/^(proc|sysfs|devtmpfs|overlay|squashfs)$/.test(m.labels.fstype)
        );
        if (filesystems.length > 200)
          notes.add('filesystems_capped', { omitted: filesystems.length - 200 });
        for (const disk of filesystems.slice(0, 200)) {
          const a = first(
            samples,
            'node_filesystem_avail_bytes',
            identity(disk.labels, ['mountpoint', 'device', 'fstype'])
          );
          const mount = upstreamId(disk.labels.mountpoint);
          if (mount === null) {
            notes.unnamed();
            continue;
          }
          const name = upstreamText(disk.labels.mountpoint);
          metrics.push(
            metric(
              pathKey('disk_', mount),
              upstreamLabel(name, ' · Used'),
              disk.value && a !== null ? (1 - a / disk.value) * 100 : null,
              '%'
            ),
            metric(pathKey('disk_free_', mount), upstreamLabel(name, ' · Free'), a, 'bytes')
          );
        }
        metrics.push(
          metric(
            'memory_used',
            'Memory used',
            memory !== null && available !== null ? memory - available : null,
            'bytes'
          ),
          metric('memory_total', 'Memory total', memory, 'bytes'),
          metric('load1', 'Load · 1m', first(samples, 'node_load1')),
          metric('uptime', 'Uptime', boot === null ? null : Math.max(0, hostNow - boot), 'seconds')
        );
        for (const direction of ['receive', 'transmit']) {
          const counters = selected(samples, 'node_network_' + direction + '_bytes_total').filter(
            m => m.labels.device !== 'lo'
          );
          metrics.push(
            metric(
              direction,
              direction === 'receive' ? 'Receive' : 'Send',
              interfaceRate(
                service.id,
                direction,
                counters,
                'device',
                virtualLinux,
                now,
                rateUpdates,
                notes
              ),
              'bytes/s'
            )
          );
        }
      } else if (service.type === 'windows') {
        // Windows counts DPC and interrupt time inside privileged time, so only the disjoint
        // idle, user and privileged modes add up to the elapsed CPU time.
        const [idle, user, privileged] = ['idle', 'user', 'privileged'].map(mode =>
          total(samples, 'windows_cpu_time_total', { mode })
        );
        const all =
          idle === null || (user === null && privileged === null)
            ? null
            : idle + (user ?? 0) + (privileged ?? 0);
        const ir = delta(service.id, 'cpu_idle', idle, now, rateUpdates),
          ar = delta(service.id, 'cpu_all', all, now, rateUpdates);
        const totalMem =
          first(samples, 'windows_cs_physical_memory_bytes') ??
          first(samples, 'windows_memory_physical_total_bytes');
        const free =
          first(samples, 'windows_os_physical_memory_free_bytes') ??
          first(samples, 'windows_memory_physical_free_bytes');
        metrics = [
          metric(
            'cpu',
            'CPU',
            ar > 0 && ir !== null ? Math.max(0, Math.min(100, (1 - ir / ar) * 100)) : null,
            '%'
          ),
          metric(
            'memory',
            'Memory',
            totalMem && free !== null ? (1 - free / totalMem) * 100 : null,
            '%'
          ),
        ];
        const volumes = selected(samples, 'windows_logical_disk_size_bytes');
        if (volumes.length > 200)
          notes.add('filesystems_capped', { omitted: volumes.length - 200 });
        for (const d of volumes.slice(0, 200)) {
          const freeDisk = first(
            samples,
            'windows_logical_disk_free_bytes',
            identity(d.labels, ['volume'])
          );
          const volume = upstreamId(d.labels.volume);
          if (volume === null) {
            notes.unnamed();
            continue;
          }
          const name = upstreamText(d.labels.volume);
          metrics.push(
            metric(
              pathKey('disk_', volume),
              upstreamLabel(name, ' · Used'),
              d.value && freeDisk !== null ? (1 - freeDisk / d.value) * 100 : null,
              '%'
            ),
            metric(pathKey('disk_free_', volume), upstreamLabel(name, ' · Free'), freeDisk, 'bytes')
          );
        }
        metrics.push(
          metric('memory_total', 'Memory total', totalMem, 'bytes'),
          metric('memory_free', 'Memory free', free, 'bytes')
        );
        for (const direction of ['received', 'sent'])
          metrics.push(
            metric(
              direction,
              direction === 'received' ? 'Receive' : 'Send',
              interfaceRate(
                service.id,
                direction,
                selected(samples, 'windows_net_bytes_' + direction + '_total'),
                'nic',
                virtualWindows,
                now,
                rateUpdates,
                notes
              ),
              'bytes/s'
            )
          );
      }
      if (service.metrics?.length) {
        // A mapping gives way to a built-in reading of the same key that this host reports,
        // including a rate whose counters are present but that has no value yet (so rules and
        // charts do not switch to the mapping on a first poll). A host without that reading
        // (for example node_exporter on FreeBSD, without MemTotal) keeps the mapping.
        const taken = new Set([
          ...compact(metrics).map(m => m.key),
          ...Object.entries(rateFamilies[service.type] ?? {})
            .filter(([, family]) => selected(samples, family).length)
            .map(([key]) => key),
        ]);
        let unclear = 0;
        for (const m of service.metrics) {
          if (taken.has(m.key)) continue;
          const matches = mappedSamples(samples, m);
          if (matches === null) unclear++;
          else if (matches.length) metrics.push(mapped(m, sum(matches, 'value') * (m.scale ?? 1)));
        }
        if (unclear) notes.add('mappings_ambiguous', { omitted: unclear });
      } else if (!['linux', 'windows'].includes(service.type))
        throw new Error('Add metric mappings for this exporter in Advanced settings.');
      break;
    }
    case 'json': {
      const response = await get(
        service.metricPath || '',
        service.apiKey ? keyHeaders(service) : {}
      );
      if (!service.metrics?.length)
        throw new Error('Add numeric JSON metric mappings in Advanced settings');
      let unclear = 0;
      metrics = service.metrics.map(m => {
        const value = pathValue(response, m.path, () => unclear++);
        return mapped(m, number(value) === null ? null : Number(value) * (m.scale ?? 1));
      });
      if (unclear) notes.add('mappings_ambiguous', { omitted: unclear });
      break;
    }
    default:
      throw new Error('This source is a launch link. Choose a collector to monitor measurements.');
  }
  // One reading per key: rules and history look a key up by its first match. Two entries can give
  // one key: an ID or path listed twice, or two different ones that make one key (upstreamId holds
  // one space for each run of control characters, leaves out direction embeddings, overrides and
  // isolates, and holds U+FFFD for half a surrogate pair; an AMP metric's key holds _ for each
  // character other than an ASCII letter or digit). The later readings are left out, and noted.
  const keys = new Set(),
    readings = compact(metrics);
  metrics = readings.filter(m => !keys.has(m.key) && keys.add(m.key));
  if (metrics.length < readings.length)
    notes.add('duplicate_keys_left_out', { omitted: readings.length - metrics.length });
  if (metrics.length > 512) {
    notes.add('measurements_capped', { omitted: metrics.length - 512 });
    metrics = metrics.slice(0, 512);
  }
  if (!metrics.length) throw new Error('No supported numeric measurements returned');
  service.signal?.throwIfAborted();
  for (const [key, value] of rateUpdates)
    if (value === undefined) previous.delete(key);
    else previous.set(key, value);
  return notes.attach(metrics);
}
