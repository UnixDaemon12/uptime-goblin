// The audit writer (audit spec §4.1, §4.3, §4.6): how an event becomes a chained row, and what
// every unit that appends does. lib/audit/index.mjs (createAudit) runs these in its own units and
// inside identity's and the settings store's units; goblin-admin's key commands call
// appendDirect() and recordWith() (§7.2).
//
// A unit that appends, in order (§4.3):
//   1. the head check (D27): audit_head against the newest row; when they disagree the unit's
//      first row is audit.gap {reason: 'head-mismatch'} and it continues at the higher seq + 1,
//      linked to the newest row, so a stale or edited head never blocks a write and the evidence
//      stays in the chain (verification reports the gap as log_truncated);
//   2. a waiting snapshot restore (D16): meta.restored differing from audit_restore_seen gives
//      system.restore {cause: 'snapshot'} as the next row, linked to the restored chain;
//   3. the rows, each hashed onto the one before; then the inserts, the head and the meta keys.
// Everything that can fail for another reason than storage (the reads, the validation, canonical
// JSON, the MAC) happens before the first write statement (D4), so such a failure leaves the
// unit exactly as its caller made it: inside identity's unit that is what lets a sign-in go on
// without its row (D32). Nothing here prints or keeps state: a unit may run twice (an error of
// class `retry`), so lines and memory change only in tx.onCommit, which the callers register.
import {
  ACTIONS,
  ACTOR_TYPES,
  DETAIL_MAX_BYTES,
  META_KEYS,
  VALUE_MAX_CHARS,
  VIAS,
} from './actions.mjs';
import { GENESIS, canonicalJSON, rowHash } from './chain.mjs';
import { auditOps } from '../repo/audit.mjs';

/** The actor of an event that names none (§4.1). */
export const systemActor = Object.freeze({
  type: 'system',
  id: null,
  name: 'orbit',
  via: 'system',
  sessionId: null,
});

/** An event the writer refuses before it writes anything (§4.1): a defect, never stored. */
export class AuditDefect extends TypeError {
  constructor(why) {
    super(`The audit writer refuses this event: ${why}.`);
    this.name = 'AuditDefect';
    this.code = 'audit_defect';
  }
}
const refuse = why => {
  throw new AuditDefect(why);
};

const isPlain = value => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};
const shown = value => {
  try {
    const text = JSON.stringify(value) ?? String(value);
    return text.length > 60 ? `${text.slice(0, 57)}…` : text;
  } catch {
    return typeof value;
  }
};

// ---------------------------------------------------------------------------------------------
// Values (§4.1): strings made well-formed, control characters removed, then cut by code points
// (SQLite's length() counts characters, so a cut by UTF-16 units could still overflow a column,
// and a cut between the halves of a pair would leave a lone surrogate canonical JSON refuses).

const control = /\p{Cc}/u,
  controls = /\p{Cc}/gu;
/** `text` well-formed, without control characters, at most `max` characters (code points). */
export function cleanText(text, max = Infinity) {
  let value = text.isWellFormed() ? text : text.toWellFormed();
  if (control.test(value)) value = value.replace(controls, '');
  if (value.length <= max) return value;
  const points = Array.from(value);
  return points.length <= max ? value : points.slice(0, max).join('');
}

// A text field of the event: text or null, cleaned and cut to `max`.
function textField(value, label, max) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') refuse(`${label} must be text or null`);
  return cleanText(value, max);
}
// An identifier field: text or null, cleaned, never cut (a cut id names something else).
function idField(value, label, max) {
  const text = textField(value, label, Infinity);
  if (text !== null && Array.from(text).length > max)
    refuse(`${label} is longer than ${max} characters`);
  return text;
}
function integerField(value, label) {
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value)) refuse(`${label} must be a safe integer or null`);
  return value;
}

// Detail values: plain data only (what canonical JSON stores faithfully), every string cleaned
// and cut to 200 characters; undefined object members are left out.
function detailValue(value, path) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return cleanText(value, VALUE_MAX_CHARS);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) refuse(`${path} is ${value}, not a safe integer`);
    return value;
  }
  if (Array.isArray(value)) {
    const out = [];
    for (let index = 0; index < value.length; index++) {
      if (!(index in value) || value[index] === undefined) refuse(`${path}[${index}] is a hole`);
      out.push(detailValue(value[index], `${path}[${index}]`));
    }
    return out;
  }
  if (isPlain(value)) {
    const out = {};
    for (const [key, item] of Object.entries(value))
      if (item !== undefined) out[cleanText(key)] = detailValue(item, `${path}.${key}`);
    return out;
  }
  refuse(`${path} holds ${value?.constructor?.name ?? typeof value}, not plain data`);
}

const bytes = text => Buffer.byteLength(text, 'utf8');

/**
 * The detail as stored: its canonical JSON at most DETAIL_MAX_BYTES (16 KiB). A detail with a
 * diff that does not fit keeps the first changes that do, with `truncated: true` and `changes`
 * (the total); anything else that large is a defect (§4.1, D11).
 */
export function fitDetail(detail) {
  const text = canonicalJSON(detail);
  if (bytes(text) <= DETAIL_MAX_BYTES) return { detail, text };
  if (!Array.isArray(detail.diff)) refuse(`the detail is larger than ${DETAIL_MAX_BYTES} bytes`);
  const changes = Number.isSafeInteger(detail.changes) ? detail.changes : detail.diff.length;
  const cut = keep => ({ ...detail, diff: detail.diff.slice(0, keep), truncated: true, changes });
  // The most changes that fit, by bisection (each probe is one canonical JSON of ≤ 16 KiB).
  let low = 0,
    high = detail.diff.length - 1;
  if (bytes(canonicalJSON(cut(0))) > DETAIL_MAX_BYTES)
    refuse(`the detail is larger than ${DETAIL_MAX_BYTES} bytes without its diff`);
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (bytes(canonicalJSON(cut(middle))) <= DETAIL_MAX_BYTES) low = middle;
    else high = middle - 1;
  }
  const fitted = cut(low);
  return { detail: fitted, text: canonicalJSON(fitted) };
}

/**
 * The row of `event` (§4.1) without seq, key_id, prev_hash and hash: validated (an AuditDefect
 * when the writer must refuse it) and normalised. `clock` gives the time of an event without
 * `at`. The row's `detail` is the stored object and `detailText` its canonical JSON.
 */
export function buildRow(event, clock) {
  if (!isPlain(event)) refuse('an event is a plain object');
  const entry = Object.hasOwn(ACTIONS, event.action) ? ACTIONS[event.action] : null;
  if (!entry) refuse(`${shown(event.action)} is not an action of the catalogue`);
  if (!entry.outcomes.includes(event.outcome))
    refuse(`${event.action} has no outcome ${shown(event.outcome)}`);
  const actor = event.actor ?? systemActor;
  if (!isPlain(actor) || !ACTOR_TYPES.includes(actor.type))
    refuse(`actor.type must be one of ${ACTOR_TYPES.join(', ')}`);
  const via = actor.via ?? null;
  if (via !== null && !VIAS.includes(via)) refuse(`actor.via must be one of ${VIAS.join(', ')}`);
  const target = event.target ?? null;
  if (target !== null && !isPlain(target)) refuse('target must be a plain object');
  const count = event.count ?? 1;
  if (!Number.isSafeInteger(count) || count < 1) refuse('count must be a whole number from 1');
  let detail = null,
    detailText = null;
  if (event.detail !== undefined && event.detail !== null) {
    if (!isPlain(event.detail)) refuse('detail must be a plain object');
    const allowed = entry.detail.includes('diff')
      ? [...entry.detail, 'truncated', 'changes']
      : entry.detail;
    for (const [key, value] of Object.entries(event.detail))
      if (value !== undefined && !allowed.includes(key))
        refuse(`${event.action} has no detail key ${key}`);
    const value = detailValue(event.detail, 'detail');
    if (Object.keys(value).length) ({ detail, text: detailText } = fitDetail(value));
  }
  const time = integerField(event.at, 'at');
  return {
    v: 1,
    time: time ?? clock(),
    ref: integerField(event.ref, 'ref'),
    actor_type: actor.type,
    actor_id: idField(actor.id, 'actor.id', 64),
    actor_name: textField(actor.name, 'actor.name', VALUE_MAX_CHARS),
    via,
    session_id: idField(actor.sessionId, 'actor.sessionId', 32),
    client_key: textField(event.client, 'client', 64),
    user_agent: textField(event.userAgent, 'userAgent', VALUE_MAX_CHARS),
    request_id: textField(event.requestId, 'requestId', 64),
    action: event.action,
    target_type: target ? idField(target.type, 'target.type', 32) : null,
    target_id: target ? textField(target.id, 'target.id', 128) : null,
    target_name: target ? textField(target.name, 'target.name', VALUE_MAX_CHARS) : null,
    outcome: event.outcome,
    status: integerField(event.status, 'status'),
    count,
    detail,
    detailText,
    config_revision: integerField(event.configRevision, 'configRevision'),
  };
}

/** The §3.4 meta keys of `event` as [[key, text]], validated (an AuditDefect otherwise). */
export function metaOf(event) {
  if (event?.meta === undefined || event.meta === null) return [];
  if (!isPlain(event.meta)) refuse('meta must be a plain object');
  const found = [];
  for (const [key, value] of Object.entries(event.meta)) {
    if (value === undefined) continue;
    if (!META_KEYS.includes(key)) refuse(`meta key ${key} is not one of audit spec §3.4`);
    if (typeof value !== 'string' && !Number.isSafeInteger(value))
      refuse(`meta.${key} must be text`);
    found.push([key, String(value)]);
  }
  return found;
}

/** The event a built row came from (the inbox keeps it so; a drain builds it again). */
export function eventOfRow(row) {
  return {
    action: row.action,
    outcome: row.outcome,
    at: row.time,
    actor: {
      type: row.actor_type,
      id: row.actor_id,
      name: row.actor_name,
      via: row.via,
      sessionId: row.session_id,
    },
    client: row.client_key,
    userAgent: row.user_agent,
    requestId: row.request_id,
    target:
      row.target_type === null && row.target_id === null && row.target_name === null
        ? null
        : { type: row.target_type, id: row.target_id, name: row.target_name },
    status: row.status,
    count: row.count,
    ref: row.ref,
    detail: row.detail,
    configRevision: row.config_revision,
  };
}

// ---------------------------------------------------------------------------------------------
// The unit (§4.3).

// meta.restored is {snapshot, at} as restore-snapshot stamps it; anything else (not JSON, a long
// snapshot id, a time that is not a safe integer) is anchored with nulls, never refused.
function restoredFields(text) {
  let value = null;
  try {
    value = JSON.parse(text);
  } catch {}
  const snapshot =
    typeof value?.snapshot === 'string' && value.snapshot.length <= VALUE_MAX_CHARS
      ? value.snapshot
      : null;
  const at = Number.isSafeInteger(value?.at) ? value.at : null;
  return { snapshot, at };
}

/**
 * Plans one unit's rows inside `tx` (reads and computation only, no write): the head check, a
 * waiting snapshot restore when `restore` is true, then `events`. Options: kid and mac (the
 * audit key that signs), now (the time of the gap and anchor rows), clock (events without `at`),
 * restore, headOfReset (key.reset's detail.head: the row the unit links to), meta (a function
 * (tx) => [[key, value]] read in this phase, applied with the rows), actor (of the gap and
 * anchor rows the unit adds itself; Uptime Goblin's by default). Returns {rows, meta, anchored,
 * restoreChecked}; throws an AuditDefect, a TypeError from canonical JSON or a SealError before
 * anything is written.
 */
export function planUnit(
  tx,
  events,
  { kid, mac, now, clock, restore = false, meta = null, actor = null }
) {
  const head = auditOps.head(tx),
    last = auditOps.last(tx);
  const agree =
    (head === null && last === null) ||
    (head !== null && last !== null && head.seq === last.seq && head.hash === last.hash);
  // Independent review A1: Uptime Goblin numbers its entries from 1 (D27). A newest row at seq 0 or below is
  // none of them (someone with the database put it there; verification reports it): the unit
  // starts the chain at seq 1 from GENESIS, as in an empty log, so Uptime Goblin never signs a row
  // numbered 0 or below, nor links one of its entries to such a row.
  const tail = last !== null && last.seq >= 1 ? last : null;
  let seq = Math.max(0, head?.seq ?? 0, tail?.seq ?? 0),
    prev = tail?.hash ?? GENESIS,
    link = tail ? { seq: tail.seq, hash: tail.hash } : null;
  const rows = [],
    sets = [];
  const add = row => {
    seq += 1;
    const chained = { ...row, seq, key_id: kid, prev_hash: prev };
    chained.hash = rowHash(mac, prev, chained);
    prev = chained.hash;
    link = { seq, hash: chained.hash };
    rows.push(chained);
  };
  const fixed = () => now;
  const by = actor ? { actor } : {};
  if (!agree)
    add(
      buildRow(
        {
          action: 'audit.gap',
          outcome: 'info',
          ...by,
          at: now,
          target: { type: 'audit', id: null, name: null },
          detail: {
            reason: 'head-mismatch',
            head: head ? { seq: head.seq, hash: head.hash } : null,
            lastSeq: last?.seq ?? null,
          },
        },
        fixed
      )
    );
  let anchored = false;
  if (restore) {
    const { restored, seen } = auditOps.restoreState(tx);
    if (restored !== null && restored !== seen) {
      add(
        buildRow(
          {
            action: 'system.restore',
            outcome: 'info',
            ...by,
            at: now,
            target: { type: 'orbit', id: null, name: null },
            detail: { cause: 'snapshot', ...restoredFields(restored), restoredHead: link },
          },
          fixed
        )
      );
      sets.push(['audit_restore_seen', restored]);
      anchored = true;
    }
  }
  for (const event of events) {
    let built = event;
    // The anchors the writer completes: system.restore and key.reset name the row they follow.
    if (event?.action === 'system.restore' && isPlain(event.detail))
      built = { ...event, detail: { ...event.detail, restoredHead: link } };
    else if (event?.action === 'key.reset' && isPlain(event.detail))
      built = { ...event, detail: { ...event.detail, head: link } };
    const row = buildRow(built, clock);
    sets.push(...metaOf(event));
    add(row);
  }
  if (meta) sets.push(...meta(tx));
  return { rows, meta: sets, anchored, restoreChecked: restore, kid };
}

/** Writes a planned unit: the rows, the head, the meta keys. Storage errors are thrown. */
export function writePlan(tx, plan, now) {
  for (const row of plan.rows) auditOps.insertRow(tx, row);
  const newest = plan.rows.at(-1);
  if (newest)
    auditOps.setHead(tx, {
      seq: newest.seq,
      hash: newest.hash,
      key_id: plan.kid,
      updated_at: now,
    });
  for (const [key, value] of plan.meta) auditOps.setMeta(tx, key, value, now);
}

// ---------------------------------------------------------------------------------------------
// Lines (§4.6): one JSON line each, printed after the unit committed.

const actorOf = row => ({
  type: row.actor_type,
  id: row.actor_id,
  name: row.actor_name,
  via: row.via,
  sessionId: row.session_id,
  client: row.client_key,
  userAgent: row.user_agent,
});
const targetOf = row => ({ type: row.target_type, id: row.target_id, name: row.target_name });

/** The mirror line of a stored row (D13): without detail unless `full`. */
export function mirrorLine(row, { instance, full = false }) {
  return JSON.stringify({
    orbit: 'audit',
    v: 1,
    instance,
    seq: row.seq,
    time: row.time,
    actor: actorOf(row),
    requestId: row.request_id,
    action: row.action,
    target: targetOf(row),
    outcome: row.outcome,
    status: row.status,
    count: row.count,
    ref: row.ref,
    configRevision: row.config_revision,
    ...(full ? { detail: row.detail } : {}),
    hash: row.hash,
  });
}

/** The checkpoint object of a row (or a prune checkpoint): what checkpointMac signs (§4.2). */
export const checkpointOf = (row, { instance, reason = 'commit', keyId }) => ({
  instance,
  seq: row.seq,
  time: row.time,
  hash: row.hash,
  reason,
  key_id: keyId,
});

/** The checkpoint line (§4.6), with its MAC. */
export function checkpointLine(checkpoint, mac) {
  return JSON.stringify({
    orbit: 'audit.checkpoint',
    v: 1,
    instance: checkpoint.instance,
    seq: checkpoint.seq,
    time: checkpoint.time,
    hash: checkpoint.hash,
    key_id: checkpoint.key_id,
    reason: checkpoint.reason,
    mac,
  });
}

/** The word an unwritten line names its error by: a storage class, else a code, else a name. */
export const errorWord = error =>
  String(
    (typeof error === 'string' ? error : null) ??
      error?.class ??
      error?.code ??
      error?.name ??
      'error'
  ).slice(0, 64);

// The row of an unwritten line: the mirror shape with detail, without seq and hash. From a built
// row when the event was valid, else from what a row of the refused event could hold: the line
// goes to Uptime Goblin's log, and the refusal may be of the very key or value a secret was put in, so
// detail keeps only the keys of its action's catalogue entry whose values are plain data, and
// every other field is cleaned and cut as buildRow does (or null).
function unwrittenRow(event, row) {
  if (row)
    return {
      time: row.time,
      actor: actorOf(row),
      requestId: row.request_id,
      action: row.action,
      target: targetOf(row),
      outcome: row.outcome,
      status: row.status,
      count: row.count,
      ref: row.ref,
      configRevision: row.config_revision,
      detail: row.detail,
    };
  const given = isPlain(event) ? event : {};
  const text = (value, max) => (typeof value === 'string' ? cleanText(value, max) : null);
  const integer = value => (Number.isSafeInteger(value) ? value : null);
  const actor = isPlain(given.actor) ? given.actor : systemActor;
  const target = isPlain(given.target) ? given.target : null;
  const entry =
    typeof given.action === 'string' && Object.hasOwn(ACTIONS, given.action)
      ? ACTIONS[given.action]
      : null;
  let detail = null;
  if (entry && isPlain(given.detail)) {
    const kept = {};
    for (const key of entry.detail.includes('diff')
      ? [...entry.detail, 'truncated', 'changes']
      : entry.detail)
      if (Object.hasOwn(given.detail, key) && given.detail[key] !== undefined)
        try {
          kept[key] = detailValue(given.detail[key], `detail.${key}`);
        } catch {}
    try {
      if (Object.keys(kept).length) detail = fitDetail(kept).detail;
    } catch {}
  }
  return {
    time: integer(given.at),
    actor: {
      type: text(actor.type, 32),
      id: text(actor.id, 64),
      name: text(actor.name, VALUE_MAX_CHARS),
      via: text(actor.via, 32),
      sessionId: text(actor.sessionId, 32),
      client: text(given.client, 64),
      userAgent: text(given.userAgent, VALUE_MAX_CHARS),
    },
    requestId: text(given.requestId, 64),
    action: text(given.action, 64),
    target: target
      ? {
          type: text(target.type, 32),
          id: text(target.id, 128),
          name: text(target.name, VALUE_MAX_CHARS),
        }
      : null,
    outcome: text(given.outcome, 32),
    status: integer(given.status),
    count: given.count === undefined ? 1 : integer(given.count),
    ref: integer(given.ref),
    configRevision: integer(given.configRevision),
    detail,
  };
}

// JSON that never throws: a BigInt becomes text, a cycle or anything else unprintable null.
function safeJSON(value) {
  const seen = new WeakSet();
  try {
    return JSON.stringify(value, (key, item) => {
      if (typeof item === 'bigint') return String(item);
      if (typeof item === 'object' && item !== null) {
        if (seen.has(item)) return null;
        seen.add(item);
      }
      return item;
    });
  } catch {
    return 'null';
  }
}

/**
 * The audit.unwritten line of an event that could not be written (§4.6), at `now`: from its
 * built row when it validates, else from the event as given.
 */
export function unwrittenLine(event, error, { instance, now, clock = () => now }) {
  let row = null;
  try {
    row = buildRow(event, clock);
  } catch {}
  return safeJSON({
    orbit: 'audit.unwritten',
    v: 1,
    instance,
    time: now,
    error: errorWord(error),
    row: unwrittenRow(event, row),
  });
}

/** The audit.unwritten line of aggregated counts close() could not write (§4.5, §4.6). */
export function unwrittenCountsLine(counts, error, { instance, now }) {
  return safeJSON({
    orbit: 'audit.unwritten',
    v: 1,
    instance,
    time: now,
    error: errorWord(error),
    counts,
  });
}

// ---------------------------------------------------------------------------------------------
// goblin-admin (§7.2): rows written under the keyring the command opened.

const auditMac = (keyring, kid) => data => keyring.hmac('audit', data, kid).mac;

// The rows goblin-admin's unit adds itself (a head-mismatch gap, a waiting restore's anchor) name
// the command's actor (review round 2): they are written by goblin-admin, and the next start
// reads whether Uptime Goblin stopped cleanly from the newest row that is not (auditOps.lastOwnAction).
const commandActor = event => (event?.actor?.type === 'cli' ? event.actor : null);

/**
 * One own unit, as §4.3, for goblin-admin's key commands (D17, D20): the head check, a waiting
 * restore anchor (always looked for: goblin-admin is never attached), the row. Prints nothing
 * (goblin-admin is not Uptime Goblin's journal; Uptime Goblin's next unit covers its rows). Resolves {seq};
 * rejects on any failure.
 */
export async function appendDirect({ db, keyring, clock = Date.now }, event) {
  const kid = keyring.activeKid('audit');
  const mac = auditMac(keyring, kid);
  return db.write(tx => {
    const now = clock();
    const plan = planUnit(tx, [event], {
      kid,
      mac,
      now,
      clock,
      restore: true,
      actor: commandActor(event),
    });
    writePlan(tx, plan, now);
    return { seq: plan.rows.at(-1).seq };
  });
}

/**
 * The same inside the keyring reset's unit (D17): `kid` and `mac` are the new audit key's, which
 * Keyring.reset hands its inUnit. For key.reset it fills detail.head, the {seq, hash} the unit
 * links to (null for an empty log), so verification can tell which rows the reset made
 * uncheckable. Throws on any failure: the reset and its anchor commit together or not at all.
 */
export function recordWith(tx, { kid, mac }, event, { clock = Date.now } = {}) {
  if (!tx) throw new TypeError('recordWith needs the reset unit');
  const now = clock();
  const plan = planUnit(tx, [event], {
    kid,
    mac,
    now,
    clock,
    restore: true,
    actor: commandActor(event),
  });
  writePlan(tx, plan, now);
  return { seq: plan.rows.at(-1).seq };
}
