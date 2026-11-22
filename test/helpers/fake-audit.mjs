// An in-memory audit service for route, identity and web-app tests (audit spec §2.1 item 16).
// It has every method of the §4.1 interface (the names of noopAudit(), lib/audit/noop.mjs), keeps
// what it is given in memory, and needs no database and no key:
//
//   const audit = fakeAudit({clock});
//   audit.rows       every row recorded, in order: {mode, action, outcome, at, actor, client,
//                    userAgent, requestId, target, status, count, ref, detail, configRevision,
//                    meta, seq}; mode is record, inbox, append, attempt, result, single,
//                    operation, system or aggregate; seq counts from 1
//   audit.counts     every count() event (its login reduced to its class at once, as D9)
//   audit.unrecorded.calls  every {event, error} given to unrecorded() (the §4.1 method takes
//                    the name the spec also gives this list, so the list hangs on the method)
//   audit.unwritten  every row the real service would have printed as audit.unwritten, with
//                    its `error`
//   audit.setFailing(kind, error)   record, append, begin, end, single, operation or system
//                    (and list, export, verify) fail with `error` until setFailing(kind, null):
//                    record throws it (as a storage error does inside a unit); append, begin,
//                    single, list, export and verify reject it; end, operation and system, which
//                    never reject in the real service, put their row in `unwritten`
//   audit.answer(name)   what list, export and verify resolve: the entry of
//                    test/contract/audit-bodies.json at that path (default list.entries,
//                    export.csv, verify.intact)
//   audit.flush()    writes the aggregated summary rows now (the end of their windows); an
//                    event of a later window, and close(), write them too
//
// Like the real writer (§4.3), record(tx, event) inside a write unit keeps its row until that
// unit commits (tx.onCommit): a unit that throws after record(), or an attempt rolled back and
// run again (retryOnce), leaves no row of its own. A tx without onCommit (null: the fake
// identity, the memory stores) writes at once.
//
// It refuses what the real writer refuses before it writes (§4.1, D32): an action outside
// ACTIONS, an outcome the action does not have (begin: `attempt`), a detail key the action does
// not list, a meta key outside §3.4, an actor type or via outside D25, a number that is not a
// safe integer, and anything in detail that is not plain data (plain objects, dense arrays,
// text, safe integers, booleans, null: what canonical JSON stores faithfully). So a lane finds
// such an event while it builds against the fake, not at integration, where the writer would
// drop the row. A refused event goes where the real writer sends it: record() keeps it in
// `unwritten` (after the unit commits, never thrown); append, begin and single reject
// auditError('audit_unavailable', {cause}); end, operation, system and aggregated rows put it in
// `unwritten`. The error is a TypeError naming what was refused.
//
// It is ready (attached) from the start unless made with {ready: false}: then record() and
// system() write `inbox` rows, and append, begin, single and operation throw a TypeError, until
// attach() is called, as before a data directory's first keyring (D8).
//
// The contract bodies hold placeholders for volatile values ("<seq>", "<ms>", "<hash>", "<id>",
// "<time>", "<iso>", "<stamp>"). Every lane reads them the same way through:
//   auditBody(name)                 the entry as stored, placeholders and all
//   concreteBody(name, {now, firstSeq})   the entry with real-looking values in their place
//   matchesBody(actual, name), bodyMismatches(actual, name)   whether a real answer has the
//                                   entry's shape, every placeholder standing for any value of
//                                   its kind (bodyMismatches lists where it does not)
//
// This file is a Phase 0 contract (frozen): lanes change it only together, through the
// integrator.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import {
  ACTIONS,
  ACTOR_TYPES,
  MAX_ROWS,
  META_KEYS,
  RETENTION_DEFAULT_DAYS,
  VIAS,
  auditTime,
  eventFrom,
} from '../../lib/audit/actions.mjs';
import { auditError } from '../../lib/audit/errors.mjs';

const bodies = JSON.parse(
  fs.readFileSync(new URL('../contract/audit-bodies.json', import.meta.url), 'utf8')
);
/** The audit-bodies.json entry at the dotted path `name` (list.entries, verify.broken.seq_gap). */
export function auditBody(name) {
  let value = bodies;
  for (const part of String(name).split('.')) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, part))
      throw new Error(`test/contract/audit-bodies.json has no ${name}`);
    value = value[part];
  }
  return structuredClone(value);
}

// ---------------------------------------------------------------------------------------------
// The placeholders of audit-bodies.json.

const placeholderNames = ['seq', 'ms', 'hash', 'id', 'time', 'iso', 'stamp'];
const wholePlaceholder = new RegExp(`^<(${placeholderNames.join('|')})>$`);
const anyPlaceholder = new RegExp(`<(${placeholderNames.join('|')})>`, 'g');
/** The time concreteBody() uses unless given one: 2026-10-03 12:00:00 UTC. */
export const bodyNow = Date.UTC(2026, 9, 3, 12);
// A number as the verification texts write it (§6.6: thousands separators), without Intl, so it
// is the same on every Node build.
const grouped = n => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
// The YYYYMMDD-HHMMSS of an export's file name (§6.3).
const stampOf = ms =>
  new Date(ms).toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
// The format of an export entry's `body` text: NDJSON lines are compared and filled as JSON
// (their numbers are bare there, though the stored entry quotes the placeholder); CSV cells hold
// plain numbers; any other text (a verification message) groups the digits of a number.
const bodyFormat = (key, parent) =>
  key !== 'body' || typeof parent?.contentType !== 'string'
    ? 'text'
    : parent.contentType.startsWith('application/x-ndjson')
      ? 'ndjson'
      : parent.contentType.startsWith('text/csv')
        ? 'csv'
        : 'text';
const ndjsonLines = (text, each) =>
  text
    .split('\n')
    .map(line => (line ? each(line) : line))
    .join('\n');

/**
 * The entry `name` of audit-bodies.json with a value of its kind in place of each placeholder,
 * for tests that need a body a page or a client can use as a real one (distinct entries, real
 * times). Each "<seq>", in document order, takes the next number: in a list (list.*, newest
 * first) firstSeq, firstSeq − 1, …, so the entries are distinct and descending, a result's `ref`
 * is below its own seq, and `nextCursor` (text, as the API sends it) and `retention.oldest` are
 * below every entry; elsewhere (verification, exports: in seq order) firstSeq, firstSeq + 1, …,
 * so first ≤ last and from ≤ to, while each `ref` counts down from firstSeq − 1 (an attempt comes
 * before its result). "<ms>" is `now` (a `durationMs` is 840); "<hash>" 64 hex digits and "<id>"
 * an id, distinct each time; "<time>" auditTime(now), "<iso>" now in ISO 8601 with milliseconds,
 * "<stamp>" its YYYYMMDD-HHMMSS. Inside an export's body, NDJSON numbers are bare and CSV cells
 * plain; inside any other text, numbers have thousands separators.
 */
export function concreteBody(name, { now = bodyNow, firstSeq = 5000 } = {}) {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(firstSeq) || firstSeq < 1)
    throw new TypeError('concreteBody needs a whole-number now and a positive firstSeq');
  const newestFirst = String(name).startsWith('list.');
  let nextSeq = firstSeq,
    nextRef = firstSeq - 1,
    ids = 0,
    hashes = 0;
  const valueOf = (placeholder, key) => {
    switch (placeholder) {
      case 'seq': {
        const seq = key === 'ref' && !newestFirst ? nextRef-- : newestFirst ? nextSeq-- : nextSeq++;
        if (seq < 1 || !Number.isSafeInteger(seq))
          throw new RangeError(`firstSeq ${firstSeq} leaves no room for ${name}`);
        return key === 'nextCursor' ? String(seq) : seq;
      }
      case 'ms':
        return key === 'durationMs' ? 840 : now;
      case 'hash':
        return createHash('sha256').update(`audit-bodies ${++hashes}`).digest('hex');
      case 'id':
        return `id-${++ids}`;
      case 'time':
        return auditTime(now);
      case 'iso':
        return new Date(now).toISOString();
      default:
        return stampOf(now);
    }
  };
  const fill = (node, key, parent) => {
    if (Array.isArray(node)) return node.map(item => fill(item, key, node));
    if (node !== null && typeof node === 'object')
      return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, fill(v, k, node)]));
    if (typeof node !== 'string') return node;
    const whole = wholePlaceholder.exec(node);
    if (whole) return valueOf(whole[1], key);
    const format = bodyFormat(key, parent);
    if (format === 'ndjson')
      return ndjsonLines(node, line => JSON.stringify(fill(JSON.parse(line), null, null)));
    return node.replace(anyPlaceholder, (_, placeholder) => {
      const value = valueOf(placeholder, null);
      return typeof value === 'number' && format === 'text' ? grouped(value) : String(value);
    });
  };
  return fill(auditBody(name), null, null);
}

// What each placeholder stands for in a real answer: a value of its own, or a part of a text.
const isValue = {
  seq: (value, key) =>
    key === 'nextCursor'
      ? typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value)
      : Number.isSafeInteger(value),
  ms: value => Number.isSafeInteger(value),
  hash: value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value),
  id: value => typeof value === 'string' && value.length > 0,
  time: value =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/.test(value),
  iso: value =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value),
  stamp: value => typeof value === 'string' && /^\d{8}-\d{6}$/.test(value),
};
const number = '-?(?:0|[1-9][0-9]{0,2}(?:,?[0-9]{3})*)';
const inText = {
  seq: number,
  ms: number,
  hash: '[0-9a-f]{64}',
  id: '[^"\\r\\n]+',
  time: '\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} UTC',
  iso: '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z',
  stamp: '\\d{8}-\\d{6}',
};
const textPattern = expected =>
  new RegExp(
    `^${expected
      .split(anyPlaceholder)
      .map((part, index) =>
        index % 2 ? `(?:${inText[part]})` : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      )
      .join('')}$`
  );
const shown = value => {
  const text = JSON.stringify(value) ?? String(value);
  return text.length > 80 ? `${text.slice(0, 77)}…` : text;
};

/**
 * Where `actual` differs from the entry `name` of audit-bodies.json, as ["path: …"] (empty when
 * it matches). Objects must have the same keys (in any order) and arrays the same length; a
 * placeholder matches any value of its kind ("<seq>" and "<ms>" a safe integer, "<seq>" at
 * `nextCursor` its text; "<hash>" 64 lower-case hex digits; "<id>" any non-empty text; "<time>"
 * auditTime()'s format; "<iso>" ISO 8601 with milliseconds and Z; "<stamp>" YYYYMMDD-HHMMSS);
 * inside a text, each placeholder matches its kind's text (a number with or without thousands
 * separators); an NDJSON export body is compared line by line as JSON. Everything else must be
 * equal.
 */
export function bodyMismatches(actual, name) {
  const found = [];
  const compare = (expected, value, path, key, parent) => {
    if (typeof expected === 'string') {
      const whole = wholePlaceholder.exec(expected);
      if (whole) {
        if (!isValue[whole[1]](value, key))
          found.push(`${path}: expected ${expected}, got ${shown(value)}`);
        return;
      }
      if (expected.match(anyPlaceholder)) {
        if (typeof value !== 'string')
          return found.push(`${path}: expected text, got ${shown(value)}`);
        if (bodyFormat(key, parent) === 'ndjson') {
          const want = expected.split('\n'),
            got = value.split('\n');
          if (want.length !== got.length)
            return found.push(`${path}: expected ${want.length} lines, got ${got.length}`);
          want.forEach((line, index) => {
            if (!line) {
              if (got[index]) found.push(`${path} line ${index + 1}: expected an empty line`);
              return;
            }
            let parsed;
            try {
              parsed = JSON.parse(got[index]);
            } catch {
              return found.push(`${path} line ${index + 1}: not JSON: ${shown(got[index])}`);
            }
            compare(JSON.parse(line), parsed, `${path} line ${index + 1}`, null, null);
          });
          return;
        }
        if (!textPattern(expected).test(value))
          found.push(`${path}: ${shown(value)} does not match ${shown(expected)}`);
        return;
      }
    }
    if (Array.isArray(expected)) {
      if (!Array.isArray(value)) return found.push(`${path}: expected a list, got ${shown(value)}`);
      if (value.length !== expected.length)
        return found.push(`${path}: expected ${expected.length} items, got ${value.length}`);
      expected.forEach((item, index) =>
        compare(item, value[index], `${path}[${index}]`, key, expected)
      );
      return;
    }
    if (expected !== null && typeof expected === 'object') {
      if (value === null || typeof value !== 'object' || Array.isArray(value))
        return found.push(`${path}: expected an object, got ${shown(value)}`);
      const want = Object.keys(expected),
        got = Object.keys(value);
      for (const k of got.filter(k => !Object.hasOwn(expected, k)))
        found.push(`${path}.${k}: not expected`);
      for (const k of want) {
        if (!Object.hasOwn(value, k)) found.push(`${path}.${k}: missing`);
        else compare(expected[k], value[k], `${path}.${k}`, k, expected);
      }
      return;
    }
    if (!Object.is(expected, value))
      found.push(`${path}: expected ${shown(expected)}, got ${shown(value)}`);
  };
  compare(auditBody(name), actual, name, null, null);
  return found;
}

/** Whether `actual` has the shape of the entry `name` of audit-bodies.json (bodyMismatches). */
export const matchesBody = (actual, name) => bodyMismatches(actual, name).length === 0;

// ---------------------------------------------------------------------------------------------
// What the writer refuses (§4.1).

// The actor of an event that names none (§4.1).
const systemActor = Object.freeze({
  type: 'system',
  id: null,
  name: 'orbit',
  via: 'system',
  sessionId: null,
});

const isPlain = value => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};
// Why `value` is not plain data canonical JSON stores faithfully, or null. A lone surrogate is
// not refused: the writer makes strings well-formed before it hashes them (§4.1).
function notData(value, path) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return null;
  if (typeof value === 'number')
    return Number.isSafeInteger(value) ? null : `${path} is ${value}, not a safe integer`;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      if (!(index in value)) return `${path}[${index}] is a hole`;
      const why = notData(value[index], `${path}[${index}]`);
      if (why) return why;
    }
    return null;
  }
  if (isPlain(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      const why = notData(item, `${path}.${key}`);
      if (why) return why;
    }
    return null;
  }
  const kind =
    value !== null && typeof value === 'object'
      ? (Object.getPrototypeOf(value)?.constructor?.name ?? 'object')
      : typeof value;
  return `${path} holds ${kind}, not plain data`;
}
const optionalText = value => value === undefined || value === null || typeof value === 'string';
const optionalInteger = value =>
  value === undefined || value === null || Number.isSafeInteger(value);

/** Why the writer would refuse `event` (§4.1), or null when it would write it. */
export function auditDefect(event) {
  if (!isPlain(event)) return 'an event is a plain object';
  const entry = Object.hasOwn(ACTIONS, event.action) ? ACTIONS[event.action] : null;
  if (!entry) return `${shown(event.action)} is not an action of the catalogue`;
  if (!entry.outcomes.includes(event.outcome))
    return `${event.action} has no outcome ${shown(event.outcome)}`;
  const actor = event.actor ?? systemActor;
  if (!isPlain(actor) || !ACTOR_TYPES.includes(actor.type))
    return `actor.type must be one of ${ACTOR_TYPES.join(', ')}`;
  if (actor.via !== undefined && actor.via !== null && !VIAS.includes(actor.via))
    return `actor.via must be one of ${VIAS.join(', ')} or null`;
  for (const field of ['id', 'name', 'sessionId'])
    if (!optionalText(actor[field])) return `actor.${field} must be text or null`;
  for (const field of ['client', 'userAgent', 'requestId'])
    if (!optionalText(event[field])) return `${field} must be text or null`;
  for (const field of ['at', 'status', 'ref', 'configRevision'])
    if (!optionalInteger(event[field])) return `${field} must be a safe integer or null`;
  if (event.count !== undefined && !(Number.isSafeInteger(event.count) && event.count >= 1))
    return 'count must be a whole number of 1 or more';
  if (event.target !== undefined && event.target !== null) {
    if (!isPlain(event.target)) return 'target must be a plain object';
    for (const field of ['type', 'id', 'name'])
      if (!optionalText(event.target[field])) return `target.${field} must be text or null`;
  }
  if (event.detail !== undefined && event.detail !== null) {
    if (!isPlain(event.detail)) return 'detail must be a plain object';
    for (const [key, value] of Object.entries(event.detail))
      if (value !== undefined && !entry.detail.includes(key))
        return `${event.action} has no detail key ${key}`;
    const why = notData(event.detail, 'detail');
    if (why) return why;
  }
  if (event.meta !== undefined && event.meta !== null) {
    if (!isPlain(event.meta)) return 'meta must be a plain object';
    for (const [key, value] of Object.entries(event.meta)) {
      if (!META_KEYS.includes(key)) return `meta key ${key} is not one of audit spec §3.4`;
      if (typeof value !== 'string' && !Number.isSafeInteger(value))
        return `meta.${key} must be text`;
    }
  }
  return null;
}
const defectOf = event => {
  const why = auditDefect(event);
  return why === null ? null : new TypeError(`The audit writer refuses this event: ${why}.`);
};

// ---------------------------------------------------------------------------------------------
// The service.

const failingKinds = new Set([
  'record',
  'append',
  'begin',
  'end',
  'single',
  'operation',
  'system',
  'list',
  'export',
  'verify',
]);
// A copy taken when the event is recorded, so a caller that changes its object later does not
// change the row; a value structuredClone refuses (a function in a refused event) is kept as is.
const copy = value => {
  if (value === undefined) return null;
  try {
    return structuredClone(value);
  } catch {
    return value;
  }
};
// Runs `fn` once `tx` commits, as the writer's onCommit work does; at once without a unit.
const afterCommit = (tx, fn) => (typeof tx?.onCommit === 'function' ? tx.onCommit(fn) : fn());

/** The class a login string is reduced to at once (D9): admin, other, or null. */
export const loginClass = login =>
  typeof login === 'string' && login.normalize('NFKC').trim()
    ? login.normalize('NFKC').trim().toLowerCase() === 'admin'
      ? 'admin'
      : 'other'
    : null;

// The window of an aggregated action: the UTC hour, or the UTC day for auth.basic.used (§4.5).
const windowOf = (action, at) => {
  const size = action === 'auth.basic.used' ? 86400000 : 3600000;
  return Math.floor(at / size) * size;
};
// The immediate row's actor and target (§4.5): anonymous for the two refusals of unknown clients.
const anonymousActions = new Set(['session.login', 'auth.basic.failed']);
const anonymous = Object.freeze({
  type: 'anonymous',
  id: null,
  name: null,
  via: null,
  sessionId: null,
});

export function fakeAudit({ clock = Date.now, ready: startReady = true } = {}) {
  let seq = 0,
    ready = startReady,
    since = null;
  const failing = new Map(),
    answers = { list: 'list.entries', export: 'export.csv', verify: 'verify.intact' },
    open = new Set(), // seqs of changes begun and not ended
    windows = new Map(); // action → {start, end, counted: [events not given a row]}

  const failure = kind => failing.get(kind) ?? null;
  const notReady = method => {
    if (!ready) throw new TypeError(`audit.${method}() before attach(): no request is served yet`);
  };
  function build(mode, event) {
    return {
      mode,
      action: event.action,
      outcome: event.outcome,
      at: event.at ?? clock(),
      actor: copy(event.actor ?? systemActor),
      client: event.client ?? null,
      userAgent: event.userAgent ?? null,
      requestId: event.requestId ?? null,
      target: copy(event.target ?? null),
      status: event.status ?? null,
      count: event.count ?? 1,
      ref: event.ref ?? null,
      detail: copy(event.detail ?? null),
      configRevision: event.configRevision ?? null,
      meta: copy(event.meta ?? null),
    };
  }
  function push(row) {
    const stored = { ...row, seq: ++seq };
    fake.rows.push(stored);
    return stored;
  }
  // A row that could not be written: the real service prints it to stderr.
  function lose(row, error) {
    fake.unwritten.push({ ...row, error });
    since ??= clock();
  }
  // A best-effort row (result, operation, system, aggregated): written, or lost when the event
  // is refused or the kind is failing; never thrown.
  function bestEffort(mode, event, kind) {
    const row = build(mode, event);
    const error = defectOf(event) ?? (kind ? failure(kind) : null);
    if (error) lose(row, error);
    else push(row);
  }
  // A fail-closed row (append, attempt, single): written, or rejected.
  function failClosed(mode, event, kind) {
    const defect = defectOf(event);
    if (defect) throw auditError('audit_unavailable', { cause: defect });
    const error = failure(kind);
    if (error) throw error;
    return push(build(mode, event));
  }

  const fake = {
    rows: [],
    counts: [],
    unwritten: [],

    // --- test controls ---
    setFailing(kind, error) {
      if (!failingKinds.has(kind)) throw new TypeError(`fakeAudit cannot fail ${kind}`);
      if (error) failing.set(kind, error);
      else failing.delete(kind);
    },
    answer(name) {
      const method = String(name).split('.')[0];
      if (!Object.hasOwn(answers, method))
        throw new TypeError(`${name} is not a list, export or verify answer`);
      auditBody(name);
      answers[method] = name;
    },
    /** The seqs of the changes begun and not ended ("in progress", D19). */
    open: () => [...open],
    flush(only = null) {
      for (const [action, window] of windows) {
        if (only !== null && action !== only) continue;
        windows.delete(action);
        if (!window.counted.length) continue;
        const events = window.counted;
        const codes = {},
          clients = [];
        for (const event of events) {
          const code = event.detail?.code;
          if (code) codes[code] = (codes[code] ?? 0) + 1;
          if (event.client && !clients.includes(event.client)) clients.push(event.client);
        }
        const outcome =
          action === 'auth.basic.used'
            ? 'ok'
            : events.some(event => event.outcome === 'failed')
              ? 'failed'
              : 'denied';
        bestEffort('aggregate', {
          action,
          outcome,
          at: window.end,
          // As the real one: the first actor named, the first signed-in one when they mix the
          // admin with refusals made before anyone signed in (independent review A5).
          actor: anonymousActions.has(action)
            ? anonymous
            : events
                .map(event => event.actor)
                .reduce((a, b) =>
                  !a ? b : b && a.type === 'anonymous' && b.type !== 'anonymous' ? b : a
                ),
          target: {
            type: 'account',
            id: anonymousActions.has(action) ? null : 'u_admin',
            name: null,
          },
          count: events.length,
          detail: {
            codes,
            clients: clients.length,
            more: false,
            sample: clients.slice(0, 10),
            from: events[0].at,
            to: events.at(-1).at,
          },
        });
      }
    },

    // --- the §4.1 interface, in its order ---
    async attach() {
      ready = true;
    },
    record(tx, event) {
      const row = build(ready ? 'record' : 'inbox', event);
      // As the writer: a refused event is caught before any write and never thrown (D32); a
      // storage failure is thrown into the caller's unit.
      const defect = defectOf(event);
      if (!defect) {
        const error = failure('record');
        if (error) throw error;
      }
      afterCommit(tx, () => (defect ? lose(row, defect) : push(row)));
    },
    unrecorded: Object.assign(
      (event, error) => {
        fake.unrecorded.calls.push({ event: copy(event), error });
      },
      { calls: [] }
    ),
    async append(event) {
      notReady('append');
      return { seq: failClosed('append', event, 'append').seq };
    },
    async system(event) {
      bestEffort(ready ? 'system' : 'inbox', event, 'system');
    },
    count(event) {
      const at = event.at ?? clock();
      const kept = { ...copy({ ...event, login: undefined }), at, login: loginClass(event.login) };
      fake.counts.push(kept);
      const start = windowOf(event.action, at),
        size = event.action === 'auth.basic.used' ? 86400000 : 3600000;
      let window = windows.get(event.action);
      if (window && window.start !== start) {
        fake.flush(event.action);
        window = null;
      }
      if (!window) {
        window = { start, end: start + size, counted: [] };
        windows.set(event.action, window);
        const named = kept.login === 'admin';
        const detail = anonymousActions.has(event.action)
          ? { code: event.detail?.code ?? null, login: kept.login }
          : event.detail?.code
            ? { code: event.detail.code }
            : null;
        bestEffort('aggregate', {
          action: event.action,
          outcome: event.outcome,
          at,
          actor: anonymousActions.has(event.action) ? anonymous : event.actor,
          client: event.client,
          userAgent: event.userAgent,
          target: {
            type: 'account',
            id: anonymousActions.has(event.action) ? (named ? 'admin' : null) : 'u_admin',
            name: null,
          },
          detail,
        });
        return;
      }
      window.counted.push(kept);
    },
    async begin(request, { action, target, detail, configRevision } = {}) {
      notReady('begin');
      const attempt = failClosed(
        'attempt',
        eventFrom(request, { action, outcome: 'attempt', target, detail, configRevision }),
        'begin'
      );
      open.add(attempt.seq);
      let noted = {},
        ended = false;
      return {
        seq: attempt.seq,
        note(values = {}) {
          const { detail: more, ...rest } = values;
          noted = { ...noted, ...rest, detail: { ...noted.detail, ...more } };
        },
        async end({ status = null, outcome = null, code = null } = {}) {
          if (ended) return;
          ended = true;
          open.delete(attempt.seq);
          // The result row carries everything (D19 hides its attempt): the attempt's detail,
          // then what the handler noted, then settle's code.
          const detail = { ...attempt.detail, ...noted.detail };
          if (code && detail.code === undefined) detail.code = code;
          bestEffort(
            'result',
            {
              action,
              outcome: noted.outcome ?? outcome,
              actor: attempt.actor,
              client: attempt.client,
              userAgent: attempt.userAgent,
              requestId: attempt.requestId,
              target: noted.target ?? attempt.target,
              status: noted.status ?? status,
              ref: attempt.seq,
              detail: Object.keys(detail).length ? detail : null,
              configRevision: noted.configRevision ?? attempt.configRevision,
            },
            'end'
          );
        },
      };
    },
    async single(request, { action, target, detail } = {}) {
      notReady('single');
      failClosed('single', eventFrom(request, { action, outcome: 'ok', target, detail }), 'single');
    },
    operation(request, { action, target, detail } = {}) {
      notReady('operation');
      let noted = {},
        ended = false;
      return {
        note(values = {}) {
          const { detail: more, ...rest } = values;
          noted = { ...noted, ...rest, detail: { ...noted.detail, ...more } };
        },
        async end({ status = null, outcome = null, code = null } = {}) {
          if (ended) return;
          ended = true;
          const merged = { ...detail, ...noted.detail };
          if (code && merged.code === undefined) merged.code = code;
          bestEffort(
            'operation',
            eventFrom(request, {
              action,
              outcome: noted.outcome ?? outcome,
              target: noted.target ?? target,
              status: noted.status ?? status,
              detail: Object.keys(merged).length ? merged : null,
            }),
            'operation'
          );
        },
      };
    },
    configSnapshot: value => ({ revision: value?.revision ?? null, public: {}, secrets: {} }),
    async start() {},
    async started() {},
    async maintain() {},
    async list() {
      const error = failure('list');
      if (error) throw error;
      return auditBody(answers.list);
    },
    async export() {
      const error = failure('export');
      if (error) throw error;
      const entry = auditBody(answers.export);
      return {
        body: Buffer.from(entry.body),
        rows: entry.rows,
        more: entry.more,
        filename: entry.filename,
        contentType: entry.contentType,
      };
    },
    async verify() {
      const error = failure('verify');
      if (error) throw error;
      return auditBody(answers.verify);
    },
    // D24: a record with an actor is its route's to record; the system records become rows.
    fromDelivery(record) {
      if (!record || typeof record !== 'object' || record.actor !== undefined) return;
      const at = record.at;
      const rows = {
        'signing.created': () => ({
          target: { type: 'secret', id: 'env-webhook', name: null },
          detail: { replaced: Boolean(record.detail?.replaced) },
        }),
        'channel.paused': () => ({
          target: { type: 'channel', id: record.target ?? null, name: null },
          detail: {
            reason:
              typeof record.detail?.reason === 'string' ? record.detail.reason.slice(0, 200) : null,
            transient: Boolean(record.detail?.transient),
          },
        }),
        'channel.working': () => ({
          target: { type: 'channel', id: record.target ?? null, name: null },
        }),
        'notifications.unsaved': () => ({ target: { type: 'outbox', id: null, name: null } }),
        'notifications.saved': () => ({ target: { type: 'outbox', id: null, name: null } }),
      };
      if (!Object.hasOwn(rows, record.action)) return;
      void fake.system({ action: record.action, outcome: 'info', at, ...rows[record.action]() });
    },
    state: () => ({
      ready,
      unwritten: fake.unwritten.length ? { since, count: fake.unwritten.length } : null,
      retention: { days: RETENTION_DEFAULT_DAYS, maxRows: MAX_ROWS },
    }),
    async idle() {},
    async close() {
      fake.flush();
    },
  };
  return fake;
}

/** Every name of the §4.1 interface, in its order (noopAudit()'s keys). */
export const auditMethods = Object.freeze([
  'attach',
  'record',
  'unrecorded',
  'append',
  'system',
  'count',
  'begin',
  'single',
  'operation',
  'configSnapshot',
  'start',
  'started',
  'maintain',
  'list',
  'export',
  'verify',
  'fromDelivery',
  'state',
  'idle',
  'close',
]);
