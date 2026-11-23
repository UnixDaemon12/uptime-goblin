// The audit trail's tables in control.sqlite (audit spec §3, §4.3): `audit_log`, `audit_head`,
// `audit_checkpoints` and `audit_inbox`, plus the `meta` keys the audit writer keeps (§3.4). This
// is the only audit module that issues SQL (import-graph rule 5 keeps lib/db/sql.mjs to lib/db,
// lib/repo and lib/series); lib/audit/** calls these inside its own db.read and db.write
// callbacks, and inside the units of identity and the settings store (record()).
//
// Every function takes the transaction first and runs synchronously (the SQLite guard: a unit of
// work never spans an await). Rows come back as plain objects with the stored column names (the
// names the chain hashes, lib/audit/chain.mjs rowObject) and numbers through the dialect's own
// mappers: an INTEGER beyond the safe range is not turned into text here, its read throws
// ERR_OUT_OF_RANGE (class `poison`), which the callers treat as a damaged log (D28).
import { sql, id, json, list, toSafeNumber } from '../db/sql.mjs';
import { metaOps } from '../db/control.mjs';

/** Every column of audit_log, in table order (an NDJSON export writes them in this order). */
export const auditColumns = Object.freeze([
  'seq',
  'v',
  'time',
  'ref',
  'actor_type',
  'actor_id',
  'actor_name',
  'via',
  'session_id',
  'client_key',
  'user_agent',
  'request_id',
  'action',
  'target_type',
  'target_id',
  'target_name',
  'outcome',
  'status',
  'count',
  'detail',
  'config_revision',
  'key_id',
  'prev_hash',
  'hash',
]);
const integerColumns = new Set(['seq', 'v', 'time', 'ref', 'status', 'count', 'config_revision']);
const checkpointColumns = Object.freeze(['seq', 'time', 'hash', 'key_id', 'reason', 'mac']);

const T = Object.freeze({
  log: id('audit_log'),
  head: id('audit_head'),
  checkpoints: id('audit_checkpoints'),
  inbox: id('audit_inbox'),
  id: id('id'),
  seq: id('seq'),
  time: id('time'),
  ref: id('ref'),
  hash: id('hash'),
  keyId: id('key_id'),
  action: id('action'),
  outcome: id('outcome'),
  actorType: id('actor_type'),
  actorName: id('actor_name'),
  targetType: id('target_type'),
  targetId: id('target_id'),
  status: id('status'),
  prevHash: id('prev_hash'),
  // The outer row and the result row of the hiding condition (§6.2).
  outer: name => id('audit_log', name),
  result: name => id('r', name),
});
const columnList = names => sql.join(names.map(name => id(name)));
const selectRows = sql`SELECT ${columnList(auditColumns)} FROM ${T.log}`;
const num = toSafeNumber;
// A statement binds at most 2,000 values on every engine; ids and seqs go in slices well below.
const slice = 500;

/**
 * A stored row as the chain hashes it: the stored column names, numbers as numbers, `detail`
 * parsed. `detailText` is the stored text itself, which verification compares with the canonical
 * JSON of `detail` (review round 2: the CSV export writes that canonical JSON). A detail that
 * does not parse (json_valid makes that impossible, short of an edit of the file) is kept as
 * its text, which no canonical JSON matches: hash_mismatch, never a crash (D28).
 */
export function rowOf(raw) {
  if (!raw) return null;
  const row = {};
  for (const column of auditColumns)
    row[column] = integerColumns.has(column) ? num(raw[column] ?? null) : (raw[column] ?? null);
  row.detailText = raw.detail ?? null;
  if (row.detailText !== null)
    try {
      row.detail = JSON.parse(row.detailText);
    } catch {
      row.detail = row.detailText;
    }
  return row;
}

// ---------------------------------------------------------------------------------------------
// The list and export filters (§6.2), as parsed by lib/audit/view.mjs parseAuditQuery().

// The type an actor name implies (D25): orbit is system, cli:<user> is cli, any other name a
// user's ('admin', 'local', and the names a later release gives its users). Matching a name
// within its type lets the filter read through audit_log_actor (actor_type, seq); there is no
// index on actor_name, and Phase 0 froze the registry.
const typeOfName = name => (name === 'orbit' ? 'system' : name.startsWith('cli:') ? 'cli' : 'user');

// The upper bound of an action prefix ('session.' → 'session/'): every action that starts with
// the prefix sorts between the two (actions are [a-z0-9.-], '/' follows '.').
const prefixEnd = prefix => `${prefix.slice(0, -1)}/`;

// An attempt row that has a result of the same action written after it (§6.2, D19): the list
// leaves it out, the result row carrying everything. Through audit_log_ref.
const hasResult = sql`EXISTS (SELECT 1 FROM ${T.log} r WHERE ${T.result('ref')} = ${T.outer('seq')} AND ${T.result('action')} = ${T.outer('action')} AND ${T.result('seq')} > ${T.outer('seq')} AND ${T.result('outcome')} <> ${'attempt'})`;

// The action items as disjoint alternatives: an item that a prefix item covers is left out
// (session.login beside session.), so no row matches two of them.
function actionAlternatives(actions = []) {
  const prefixes = actions.filter(item => item.prefix).map(item => item.name);
  const kept = [];
  for (const item of actions) {
    if (prefixes.some(prefix => prefix !== item.name && item.name.startsWith(prefix))) continue;
    if (kept.some(other => other.name === item.name)) continue;
    kept.push(item);
  }
  return kept.map(({ name, prefix }) =>
    prefix
      ? sql`${T.action} >= ${name} AND ${T.action} < ${prefixEnd(name)}`
      : sql`${T.action} = ${name}`
  );
}

/**
 * The WHERE conditions of a query: {parts, alternatives}, the action items apart. `hide` (the
 * list without an outcome) leaves out the attempt rows that have a result; `open` is the seqs of
 * the changes open in this process (unknown).
 */
function conditions(query, { open = [], hide = false } = {}) {
  const found = [];
  if (query.from !== null && query.from !== undefined) found.push(sql`${T.time} >= ${query.from}`);
  if (query.to !== null && query.to !== undefined) found.push(sql`${T.time} <= ${query.to}`);
  if (query.actor?.type) found.push(sql`${T.actorType} = ${query.actor.type}`);
  else if (typeof query.actor?.name === 'string')
    found.push(
      sql`${T.actorType} = ${typeOfName(query.actor.name)} AND ${T.actorName} = ${query.actor.name}`
    );
  if (query.target?.type) {
    found.push(sql`${T.targetType} = ${query.target.type}`);
    if (query.target.id !== null && query.target.id !== undefined)
      found.push(sql`${T.targetId} = ${query.target.id}`);
  }
  switch (query.outcome) {
    case null:
    case undefined:
      if (hide) found.push(sql`NOT (${T.outcome} = ${'attempt'} AND ${hasResult})`);
      break;
    case 'attempt':
      found.push(sql`${T.outcome} = ${'attempt'}`);
      break;
    case 'unknown':
      found.push(sql`${T.outcome} = ${'attempt'} AND NOT ${hasResult}`);
      for (let start = 0; start < open.length; start += slice)
        found.push(sql`${T.seq} NOT IN ${list(open.slice(start, start + slice))}`);
      break;
    default:
      found.push(sql`${T.outcome} = ${query.outcome}`);
  }
  return { parts: found, alternatives: actionAlternatives(query.actions ?? []) };
}
const where = parts => (parts.length ? sql`WHERE ${sql.join(parts, sql` AND `)}` : sql``);

// The newest `limit` rows matching `parts` and one of `alternatives`. Several action items are
// one SELECT each, joined by UNION ALL, so each reads through audit_log_action: as one OR, the
// planner may walk the whole table newest first instead, which reads every row when the
// actions are rare.
function newest(tx, { parts, alternatives }, limit) {
  const order = tx.dialect.orderBy(['seq', 'desc', 'not null']);
  if (alternatives.length <= 1)
    return tx.all(
      sql`${selectRows} ${where([...alternatives, ...parts])} ${order} ${tx.dialect.limit(limit)}`
    );
  const arms = alternatives.map(
    alternative => sql`${selectRows} ${where([alternative, ...parts])}`
  );
  return tx.all(
    sql`SELECT ${columnList(auditColumns)} FROM (${sql.join(arms, sql` UNION ALL `)}) AS u ${order} ${tx.dialect.limit(limit)}`
  );
}

// ---------------------------------------------------------------------------------------------

export const auditOps = Object.freeze({
  /** The head (audit_head id 1): {seq, hash, keyId}, or null. */
  head(tx) {
    const row = tx.get(
      sql`SELECT ${T.seq}, ${T.hash}, ${T.keyId} FROM ${T.head} WHERE ${T.id} = ${1}`
    );
    return row ? { seq: num(row.seq), hash: row.hash, keyId: row.key_id } : null;
  },

  /**
   * The newest row: {seq, hash, action}, or null. Only these columns: the writer reads nothing
   * else before it appends, so a damaged value elsewhere in the row never stops a sign-in (D28).
   */
  last(tx) {
    const row = tx.get(
      sql`SELECT ${T.seq}, ${T.hash}, ${T.action} FROM ${T.log} ${tx.dialect.orderBy(['seq', 'desc', 'not null'])} ${tx.dialect.limit(1)}`
    );
    return row ? { seq: num(row.seq), hash: row.hash, action: row.action } : null;
  },

  /**
   * The action of the newest row not written by goblin-admin (actor_type `cli`), or null. The
   * key commands that need Uptime Goblin stopped write their rows after its system.stop, so the start
   * after them reads whether Uptime Goblin stopped cleanly from this row, not from theirs.
   */
  lastOwnAction(tx) {
    const row = tx.get(
      sql`SELECT ${T.action} FROM ${T.log} WHERE ${T.actorType} IS NULL OR ${T.actorType} <> ${'cli'} ${tx.dialect.orderBy(['seq', 'desc', 'not null'])} ${tx.dialect.limit(1)}`
    );
    return row ? row.action : null;
  },

  /** The oldest row: {seq, time, prevHash}, or null. */
  first(tx) {
    const row = tx.get(
      sql`SELECT ${T.seq}, ${T.time}, ${T.prevHash} FROM ${T.log} ${tx.dialect.orderBy(['seq', 'asc', 'not null'])} ${tx.dialect.limit(1)}`
    );
    return row ? { seq: num(row.seq), time: num(row.time), prevHash: row.prev_hash } : null;
  },

  /** The row `seq` (rowOf), or null. */
  rowAt(tx, seq) {
    return rowOf(tx.get(sql`${selectRows} WHERE ${T.seq} = ${seq}`));
  },

  /**
   * Inserts a built row: every column given, `seq` explicitly (D27), `detail` as the canonical
   * JSON text the writer hashed (bound as text, so the stored bytes are the hashed ones).
   */
  insertRow(tx, row) {
    tx.run(
      tx.dialect.insert('audit_log', auditColumns, [
        auditColumns.map(column => (column === 'detail' ? (row.detailText ?? null) : row[column])),
      ])
    );
  },

  /** The head after a unit's rows: {seq, hash, key_id, updated_at} (id is always 1). */
  setHead(tx, { seq, hash, key_id, updated_at }) {
    tx.run(
      tx.dialect.upsert(
        'audit_head',
        ['id'],
        ['id', 'seq', 'hash', 'key_id', 'updated_at'],
        [[1, seq, hash, key_id, updated_at]]
      )
    );
  },

  /** Stores a prune checkpoint {seq, time, hash, key_id, reason, mac}. */
  insertCheckpoint(tx, checkpoint) {
    tx.run(
      tx.dialect.insert('audit_checkpoints', checkpointColumns, [
        checkpointColumns.map(column => checkpoint[column]),
      ])
    );
  },

  /** The stored checkpoints, by seq: [{seq, time, hash, key_id, reason, mac}]. */
  checkpoints(tx) {
    return tx
      .all(
        sql`SELECT ${columnList(checkpointColumns)} FROM ${T.checkpoints} ${tx.dialect.orderBy(['seq', 'asc', 'not null'], ['id', 'asc', 'not null'])}`
      )
      .map(row => ({
        seq: num(row.seq),
        time: num(row.time),
        hash: row.hash,
        key_id: row.key_id,
        reason: row.reason,
        mac: row.mac,
      }));
  },

  /**
   * Whether a stored prune checkpoint names `seq` (review round 1: verification reads only those,
   * so another stored there must not keep the prune from storing its own).
   */
  hasCheckpoint(tx, seq) {
    return Boolean(
      tx.get(
        sql`SELECT ${T.id} FROM ${T.checkpoints} WHERE ${T.seq} = ${seq} AND ${id('reason')} = ${'prune'} ${tx.dialect.limit(1)}`
      )
    );
  },

  /** Deletes the checkpoints below `seq`: they verify nothing that remains after a prune. */
  deleteCheckpointsBefore(tx, seq) {
    return tx.run(tx.dialect.deleteFrom('audit_checkpoints', sql`${T.seq} < ${seq}`)).changes;
  },

  /** {restored, seen}: meta.restored (stamped by restore-snapshot) and audit_restore_seen. */
  restoreState(tx) {
    return {
      restored: metaOps.get(tx, 'restored'),
      seen: metaOps.get(tx, 'audit_restore_seen'),
    };
  },

  /** A meta value, or null. */
  meta: (tx, key) => metaOps.get(tx, key),

  /** Sets a meta value (the §3.4 keys, in the unit of the row they describe). */
  setMeta: (tx, key, value, now) => metaOps.set(tx, key, value, now),

  // ---- the inbox (D8) ------------------------------------------------------------------------

  /** Inserts an inbox row; returns its id. */
  inboxInsert(tx, { time, source, event }) {
    return tx.run(
      tx.dialect.insert('audit_inbox', ['time', 'source', 'event'], [[time, source, json(event)]])
    ).lastInsertRowid;
  },

  /**
   * Every inbox row in id order: [{id, time, source, event}], `event` parsed (null when it does
   * not parse: such a row is discarded).
   */
  inboxAll(tx) {
    return tx
      .all(
        sql`SELECT ${T.id}, ${T.time}, ${id('source')}, ${id('event')} FROM ${T.inbox} ${tx.dialect.orderBy(['id', 'asc', 'not null'])}`
      )
      .map(row => {
        let event = null;
        try {
          event = JSON.parse(row.event);
        } catch {}
        return { id: num(row.id), time: num(row.time), source: row.source, event };
      });
  },

  /** Deletes the inbox rows `ids`. */
  inboxDelete(tx, ids) {
    let changes = 0;
    for (let start = 0; start < ids.length; start += slice)
      changes += tx.run(
        tx.dialect.deleteFrom(
          'audit_inbox',
          sql`${T.id} IN ${list(ids.slice(start, start + slice))}`
        )
      ).changes;
    return changes;
  },

  /** Deletes every inbox row; returns how many went. */
  inboxClear(tx) {
    return tx.run(tx.dialect.deleteFrom('audit_inbox', sql`${T.id} IS NOT NULL`)).changes;
  },

  // ---- reading the log (§6.2, §6.4, §4.7) --------------------------------------------------

  /**
   * One list page (§6.2): the rows matching `query`, newest first, at most `limit` + 1 (one
   * more tells whether an older page exists). Without an outcome the attempt rows that have a
   * result are left out; `open` is the seqs of the changes open in this process (unknown).
   */
  page(tx, query, { open = [], limit }) {
    const found = conditions(query, { open, hide: true });
    // Always bounded by seq (the cursor, else the largest): when the planner reads the page
    // through the primary key, newest first, that is a search of the key that LIMIT ends, not
    // a table scan.
    found.parts.push(sql`${T.seq} < ${query.cursor ?? Number.MAX_SAFE_INTEGER}`);
    return newest(tx, found, limit + 1).map(rowOf);
  },

  /**
   * The result row of each attempt `seqs` (same action, written after it, not an attempt):
   * [{ref, seq, outcome, status, time}], the first by seq for each attempt.
   */
  results(tx, seqs) {
    const found = new Map();
    for (let start = 0; start < seqs.length; start += slice) {
      const part = seqs.slice(start, start + slice);
      const rows = tx.all(
        sql`SELECT ${T.result('ref')}, ${T.result('seq')}, ${T.result('outcome')}, ${T.result('status')}, ${T.result('time')} FROM ${T.log} r JOIN ${T.log} a ON ${id('a', 'seq')} = ${T.result('ref')} WHERE ${T.result('ref')} IN ${list(part)} AND ${T.result('action')} = ${id('a', 'action')} AND ${T.result('seq')} > ${id('a', 'seq')} AND ${T.result('outcome')} <> ${'attempt'}`
      );
      for (const row of rows) {
        const result = {
          ref: num(row.ref),
          seq: num(row.seq),
          outcome: row.outcome,
          status: num(row.status ?? null),
          time: num(row.time),
        };
        const known = found.get(result.ref);
        if (!known || result.seq < known.seq) found.set(result.ref, result);
      }
    }
    return [...found.values()];
  },

  /**
   * Rows after `afterSeq` up to `toSeq`, oldest first, at most `limit` (verification). Independent
   * review A1: `afterSeq` null reads from the lowest stored row whatever its seq (0 and below
   * included), so verification and the prune's check read every stored row.
   */
  rowsFrom(tx, { afterSeq = 0, toSeq, limit }) {
    const upTo = sql`${T.seq} <= ${toSeq}`;
    return tx
      .all(
        sql`${selectRows} ${where(afterSeq === null ? [upTo] : [sql`${T.seq} > ${afterSeq}`, upTo])} ${tx.dialect.orderBy(['seq', 'asc', 'not null'])} ${tx.dialect.limit(limit)}`
      )
      .map(rowOf);
  },

  /** The rows of `action` up to `toSeq`, oldest first (the key.reset anchors, §6.4 step 3). */
  rowsOf(tx, action, { toSeq }) {
    return tx
      .all(
        sql`${selectRows} WHERE ${T.action} = ${action} AND ${T.seq} <= ${toSeq} ${tx.dialect.orderBy(['seq', 'asc', 'not null'])}`
      )
      .map(rowOf);
  },

  /**
   * Export rows (§6.3): matching `query` (no row hidden), at most `toSeq` (the head when the
   * export began) and below `beforeSeq`, newest first, at most `limit`.
   */
  exportRows(tx, query, { open = [], toSeq, beforeSeq = null, limit }) {
    const found = conditions(query, { open });
    found.parts.push(sql`${T.seq} <= ${toSeq}`);
    if (beforeSeq !== null) found.parts.push(sql`${T.seq} < ${beforeSeq}`);
    return newest(tx, found, limit).map(rowOf);
  },

  /**
   * The prune targets (§4.7): `age`, the seq before the lowest seq whose time is at or after
   * `cutoff` (through audit_log_time; null when no row is that recent), so only the leading run
   * of expired rows goes and a row with a wrong time near the head moves nothing; `cap`, the seq
   * of the (maxRows + 1)-th newest row (through the primary key), or 0.
   */
  pruneTarget(tx, { cutoff, maxRows }) {
    const recent = tx.get(
      sql`SELECT MIN(${T.seq}) AS lowest FROM ${T.log} WHERE ${T.time} >= ${cutoff}`
    );
    const lowest = num(recent?.lowest ?? null);
    const capped = tx.get(
      sql`SELECT ${T.seq} FROM ${T.log} ${tx.dialect.orderBy(['seq', 'desc', 'not null'])} ${tx.dialect.limit(1, maxRows)}`
    );
    return { age: lowest === null ? null : lowest - 1, cap: num(capped?.seq ?? null) ?? 0 };
  },

  /** The greatest stored seq at or below `seq`, or null (a prune target inside a seq jump). */
  atOrBelow(tx, seq) {
    const row = tx.get(sql`SELECT MAX(${T.seq}) AS found FROM ${T.log} WHERE ${T.seq} <= ${seq}`);
    return num(row?.found ?? null);
  },

  /**
   * A DELETE of at most `limit` rows with seq ≤ `seq`, oldest first, as drainChunks
   * (lib/repo/chunks.mjs) wants it: `deleteThrough(dialect, seq)(limit)`.
   */
  deleteThrough(dialect, seq) {
    return limit =>
      dialect.deleteFrom(
        'audit_log',
        sql`${T.seq} IN (SELECT ${T.seq} FROM ${T.log} WHERE ${T.seq} <= ${seq} ${dialect.orderBy(['seq', 'asc', 'not null'])} ${dialect.limit(limit)})`
      );
  },
});
