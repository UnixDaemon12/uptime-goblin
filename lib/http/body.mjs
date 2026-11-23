// Request and response bodies: bounded reads, strict UTF-8 JSON whose member names are unique
// and cannot reach a prototype, and JSON answers kept on the response so an Idempotency-Key
// retry can repeat them.
import { InputError } from '../config.mjs';

/** The most a request body may hold unless its route declares a smaller or larger limit. */
export const bodyLimit = 150000;

/** What a write that takes no body reads at most: nothing, or `{}` with a few spaces. */
export const emptyBodyLimit = 64;

/** How deeply a JSON request body may nest objects and arrays (Uptime Goblin's own need at most 4). */
export const maxJsonDepth = 64;

/**
 * A body larger than its route takes: answered 413, and the connection is closed instead of
 * read to its end (see answerClosing in the pipeline). An InputError, so it is the client's
 * mistake everywhere a 400 is.
 */
export class TooLargeError extends InputError {
  constructor() {
    super('Request is too large');
    this.status = 413;
  }
}

/**
 * The body a request announces: its Content-Length, Infinity for any Transfer-Encoding (a body
 * of unknown length), or 0 for none. Node's parser has already refused a malformed, repeated or
 * conflicting Content-Length.
 */
export function announcedBytes(req) {
  const headers = req.headers ?? {};
  if (headers['transfer-encoding'] !== undefined) return Infinity;
  const length = headers['content-length'];
  return length === undefined ? 0 : Number(length);
}

/**
 * Whether answering `req` now must close its connection: part of its body has not arrived, and
 * the request announced more than `limit` bytes (or an unknown amount). After an answer Node
 * reads and discards the rest of a body so the connection can be reused; that is bounded only
 * by what the request announced, so beyond the route's limit the connection is closed instead.
 */
export function unboundedRemainder(req, limit) {
  return !req.complete && announcedBytes(req) > limit;
}

/**
 * Reads the whole request body; more than `limit` bytes is refused as too large (TooLargeError),
 * before a byte is read when the announced length already says so. The request is not destroyed
 * when the limit is passed: the 413 must still reach the client on this connection, which the
 * pipeline then closes.
 */
export async function readBody(req, limit = bodyLimit) {
  return readRequestBody(req, limit, false);
}

/** Read a password-bearing body, clearing every consumed input chunk on all exits. The
 * returned concatenated Buffer belongs to the caller, which must clear it after parsing.
 * Refusal before reading owns no chunks; bytes not read remain the HTTP stream's responsibility.
 * This preserves the reader's boundedness and non-destroying early return for a 413 response.
 */
export async function readSensitiveBody(req, limit = bodyLimit) {
  return readRequestBody(req, limit, true);
}

async function readRequestBody(req, limit, sensitive) {
  const announced = announcedBytes(req);
  if (announced !== Infinity && announced > limit) throw new TooLargeError();
  let size = 0;
  const chunks = [];
  try {
    for await (const chunk of req.iterator({ destroyOnReturn: false })) {
      size += chunk.length;
      if (size > limit) {
        if (sensitive) chunk.fill(0);
        throw new TooLargeError();
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally {
    if (sensitive) for (const chunk of chunks) chunk.fill(0);
  }
}

/**
 * The first shape anywhere in a parsed JSON value that reaches an object's prototype, or null.
 * JSON.parse keeps every key as an ordinary own property, but a later key-by-key copy or merge
 * of the body would follow these two to a prototype instead, so a body carrying either at any
 * depth is refused (X9):
 *
 * - '__proto__': writing it replaces the target's prototype, and a merge that descends into it
 *   writes onto Object.prototype;
 * - 'prototype' directly inside 'constructor' ('constructor.prototype'): a merge descends from
 *   target.constructor (Object) into Object.prototype.
 *
 * 'constructor' and 'prototype' on their own are ordinary names. Orbit 1.4.x saves any \w+ metric
 * label name (lib/config.mjs), and the source drawer sends the whole metrics array back, so
 * refusing them stopped an upgraded source with such a label from being saved or tested.
 */
export function forbiddenKey(value) {
  // A list instead of recursion: a deeply nested body cannot exhaust the stack here.
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (item === null || typeof item !== 'object') continue;
    if (Array.isArray(item)) {
      for (const entry of item) pending.push(entry);
      continue;
    }
    for (const key of Object.keys(item)) {
      if (key === '__proto__') return key;
      const child = item[key];
      // Only an object under 'constructor' can hold the 'prototype' key (JSON arrays have
      // none); its other keys are walked as usual.
      if (
        key === 'constructor' &&
        child !== null &&
        typeof child === 'object' &&
        Object.hasOwn(child, 'prototype')
      )
        return 'constructor.prototype';
      pending.push(child);
    }
  }
  return null;
}

/**
 * The first problem with the member names and nesting of `text`, already known to be valid JSON,
 * or null: `{duplicate: name}` for a name given twice in one object, at any depth, or
 * `{tooDeep: true}` past maxJsonDepth levels of objects and arrays. JSON.parse keeps the last of
 * two equal names, so a proxy, a firewall or a log that reads the first one would see another
 * request than the one Uptime Goblin acts on. One pass, without recursion; names are compared decoded,
 * so "a" and "a" are the same name.
 */
export function memberProblem(text) {
  // One entry per open object (the names it has so far) or array (null).
  const open = [];
  // Whether the next string is a member name: after '{' and after ',' inside an object.
  let nameNext = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      let end = i + 1;
      while (text.charCodeAt(end) !== 0x22) end += text.charCodeAt(end) === 0x5c ? 2 : 1;
      if (nameNext) {
        const raw = text.slice(i + 1, end);
        const name = raw.includes('\\') ? JSON.parse(text.slice(i, end + 1)) : raw;
        const names = open.at(-1);
        if (names.has(name)) return { duplicate: name };
        names.add(name);
        nameNext = false;
      }
      i = end;
    } else if (c === 0x7b || c === 0x5b) {
      open.push(c === 0x7b ? new Set() : null);
      if (open.length > maxJsonDepth) return { tooDeep: true };
      nameNext = c === 0x7b;
    } else if (c === 0x7d || c === 0x5d) {
      open.pop();
      nameNext = false;
    } else if (c === 0x2c) nameNext = open.at(-1) instanceof Set;
  }
  return null;
}

// Strict UTF-8: a body that is not is refused instead of having its bytes replaced by U+FFFD
// and saved that way. A byte order mark stays a character (not JSON), as before.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

// A \u escape of half a surrogate pair: the one way valid UTF-8 JSON can still carry text that
// is not Unicode, which becomes U+FFFD when it is written out as UTF-8 later (config.json, an
// email, a webhook). An escaped backslash before "u" matches too; illFormed() then decides.
const surrogateEscape = /\\u[dD][89a-fA-F][0-9a-fA-F]{2}/;

/** Whether a member name or string anywhere in the parsed JSON `value` is not well-formed. */
function illFormed(value) {
  // A list instead of recursion, as in forbiddenKey.
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (typeof item === 'string') {
      if (!item.isWellFormed()) return true;
    } else if (Array.isArray(item)) {
      // Not push(...item): a long array would overflow the call stack.
      for (const entry of item) pending.push(entry);
    } else if (item !== null && typeof item === 'object')
      for (const key of Object.keys(item)) {
        if (!key.isWellFormed()) return true;
        pending.push(item[key]);
      }
  }
  return false;
}

/**
 * Parses a JSON request body. The client's mistakes, each a 400: bytes that are not UTF-8, or a
 * \u escape that leaves half a surrogate pair ("Request bodies must be UTF-8 JSON"), invalid
 * JSON, a member name given twice in one object ("Field name <name> is given twice", the name
 * cleaned and cut to 60 characters), nesting deeper than maxJsonDepth, and a shape that reaches
 * a prototype ("Field name __proto__ is not allowed", "Field name constructor.prototype is not
 * allowed").
 */
export function parseJson(buffer) {
  let text, value;
  try {
    text = utf8.decode(buffer);
  } catch {
    throw new InputError('Request bodies must be UTF-8 JSON');
  }
  try {
    value = JSON.parse(text);
  } catch {
    throw new InputError('Expected valid JSON');
  }
  if (surrogateEscape.test(text) && illFormed(value))
    throw new InputError('Request bodies must be UTF-8 JSON');
  const problem = memberProblem(text);
  if (problem?.tooDeep)
    throw new InputError(`Request bodies may nest at most ${maxJsonDepth} levels`);
  if (problem)
    throw new InputError(
      `Field name ${problem.duplicate.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, 60)} is given twice`
    );
  const key = forbiddenKey(value);
  if (key !== null) throw new InputError(`Field name ${key} is not allowed`);
  return value;
}

/**
 * Refuses the body of a write that takes none (a route with `body: 'empty'`): only no body at
 * all or an empty JSON object, so a client that sends fields learns that nothing reads them.
 */
export function assertEmptyBody(raw) {
  if (!raw.length) return;
  const value = parseJson(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length)
    throw new InputError('This request takes no body: send nothing or {}');
}

// Headers a handler may set before its JSON answer; an idempotent replay repeats them.
export const replayedHeaders = Object.freeze([
  'retry-after',
  'allow',
  'content-disposition',
  'www-authenticate',
]);

/** The JSON answer `{status, body, headers}` as json() records it and replay() repeats it. */
export function recordedAnswer(res, status, value) {
  return {
    status,
    body: JSON.stringify(value),
    headers: Object.fromEntries(
      replayedHeaders.filter(name => res.hasHeader(name)).map(name => [name, res.getHeader(name)])
    ),
  };
}

/** Answers with JSON that is never cached, and records the answer for idempotent replay. */
export function json(res, status, value) {
  // Kept on the response so an Idempotency-Key retry can be answered with the same outcome.
  const answer = (res.orbitResponse = recordedAnswer(res, status, value));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(answer.body);
}

/** Repeats an answer recorded by json(), marked as a replay. */
export function replay(res, { status, body, headers }) {
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
  res.setHeader('Idempotent-Replayed', 'true');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}
