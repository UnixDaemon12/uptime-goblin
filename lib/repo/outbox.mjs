// The control-database OutboxStore (delivery spec §4.1): lib/notify/outbox.mjs's store over
// control.sqlite's alerting_outbox and alerting_channel_status (lib/alerting/tables.mjs), so
// notifications survive a restart. It passes test/notify/store-contract.mjs row for row, as the
// memory store does; the failover store (lib/notify/memory-store.mjs) wraps it and keeps rows in
// memory while this one cannot be written.
//
//   const store = createControlOutboxStore({db: control.db});
//   const outbox = createOutbox({store: createFailoverStore({primary: store}), …});
//
// Every write is one synchronous db.write() unit, and every call does a bounded amount of work
// per unit (inserts 200 rows, claims and completions 100, bulk state changes 500, prune 1000), so
// no unit holds the write lock or the event loop for long, and none needs much WAL space on a
// nearly full disk. Calls that may touch more loop over several units; between them other work
// can run, which is safe because each unit re-checks the state it changes.
//
// Errors keep the class the Db gave them (full, unavailable, retry …), so the failover store's
// isStorageError() recognises a full disk; a value this store refuses before writing is a
// TypeError (a programming error, never a storage failure).
import { sql, id, json } from '../db/sql.mjs';
import { OUTBOX_COLUMNS, CHANNEL_STATUS_COLUMNS } from '../alerting/tables.mjs';

/** Rows of one insert unit, ids of one claim/complete/unclaim unit, rows of one bulk change. */
export const OUTBOX_UNIT_LIMITS = Object.freeze({
  insert: 200,
  lease: 100,
  bulk: 500,
  candidates: 200,
  list: 100,
  prune: 1000,
  batch: 100,
  keys: 200,
});

const ACTIVE = Object.freeze(['queued', 'sending', 'held']);
const FINISHED = Object.freeze(['delivered', 'superseded', 'stale', 'skipped', 'cancelled']);
const expiredText = 'It could not be delivered before it expired.';

const outboxColumns = Object.freeze(Object.keys(OUTBOX_COLUMNS));
const fieldColumn = Object.freeze(
  Object.fromEntries(Object.entries(OUTBOX_COLUMNS).map(([column, field]) => [field, column]))
);
const integerColumns = new Set([
  'id',
  'attempts',
  'unknowns',
  'next_at',
  'created_at',
  'expires_at',
  'lease_until',
  'epoch',
  'sent_at',
  'last_status',
  'updated_at',
]);
// A completion may change these; the row's identity (id, uid, event, channel, target) never.
const fixedFields = new Set(['id', 'uid', 'eventUid', 'channelId', 'target']);

const statusColumns = Object.freeze([
  'channel_id',
  ...Object.keys(CHANNEL_STATUS_COLUMNS),
  'updated_at',
]);
// The column defaults of alerting_channel_status: a status written without a field gets these.
const statusDefaults = Object.freeze({
  state: 'ok',
  paused_reason: null,
  next_send_at: 0,
  consecutive_failures: 0,
  failed_total: 0,
  delivered_total: 0,
  last_attempt: null,
  last_success: null,
  last_failure: null,
  last_error: null,
  paused_since: null,
  consecutive_refusals: 0,
});

const T = Object.freeze({
  outbox: id('alerting_outbox'),
  status: id('alerting_channel_status'),
  ...Object.fromEntries(outboxColumns.map(column => [column, id(column)])),
  // Columns as qualified by the aliases o (the row), p (an earlier row) and c (its channel).
  o: column => id('o', column),
  p: column => id('p', column),
  c: column => id('c', column),
});

/**
 * An INTEGER column value. Times computed with a random factor (retry backoff) are fractional;
 * a STRICT INTEGER column refuses those, so they are rounded up (never earlier than computed).
 */
function integer(column, value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value))
    throw new TypeError(`The outbox column ${column} needs a finite number, not ${value}`);
  return Number.isInteger(value) ? value : Math.ceil(value);
}

/** A row field as its column value. */
function columnValue(column, value) {
  if (column === 'event') {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new TypeError('An outbox row needs an event snapshot object');
    return json(value);
  }
  if (integerColumns.has(column)) return integer(column, value);
  if (value === undefined || value === null) return column === 'target' ? '' : null;
  return String(value);
}

// Saved JSON read back: the json_valid CHECKs stop ordinary writes, but a row written with the
// checks off, an edited page or a damaged file can hold anything. undefined when it does not
// parse; the error, which quotes the text, never leaves here.
function storedJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * A stored row as the OutboxStore row (every field; `null` columns are `null` fields). `event`
 * is null when the saved snapshot is not a JSON object: such a row is never sent (candidates()
 * sets it dead), and the page shows it without its alert.
 */
function rowOf(record) {
  const row = {};
  for (const [column, field] of Object.entries(OUTBOX_COLUMNS)) row[field] = record[column] ?? null;
  const event = storedJson(record.event);
  row.event = event !== null && typeof event === 'object' && !Array.isArray(event) ? event : null;
  return row;
}

/** A stored channel status as the outbox's status object (an unreadable last error is none). */
function statusOf(record) {
  const status = {};
  for (const [column, field] of Object.entries(CHANNEL_STATUS_COLUMNS))
    status[field] = record[column] ?? null;
  status.lastError = record.last_error == null ? null : (storedJson(record.last_error) ?? null);
  return status;
}

const unreadableText =
  'Uptime Goblin could not read this notification as it was saved, so it was not sent.';

const chunks = (list, size) => {
  const out = [];
  for (let start = 0; start < list.length; start += size) out.push(list.slice(start, start + size));
  return out;
};
const rowIds = ids => ids.map(Number).filter(value => Number.isSafeInteger(value) && value > 0);
const keyMatch = (alias, orderKey) =>
  orderKey === null || orderKey === undefined
    ? sql`${alias('order_key')} IS NULL`
    : sql`${alias('order_key')} = ${String(orderKey)}`;
const self = column => id(column);

/**
 * The bounds of rows whose order key starts with `prefix`, under the column's binary collation:
 * prefix <= key < upper, where upper is the prefix with its last character's code point one
 * higher (UTF-8 byte order is code point order). Null when that is not a plain character (a
 * surrogate or U+FFFF); the caller then filters in JavaScript.
 */
function prefixUpperBound(prefix) {
  const last = prefix.charCodeAt(prefix.length - 1);
  if (last >= 0xd800 && last <= 0xdfff) return null;
  if (last === 0xffff) return null;
  return prefix.slice(0, -1) + String.fromCharCode(last + 1);
}

/**
 * The OutboxStore over control.sqlite. `db` is the control database's Db (lib/db/sqlite.mjs),
 * migrated with alerting-001-outbox; `clock` stamps channel status writes.
 */
export function createControlOutboxStore({ db, clock = Date.now } = {}) {
  if (typeof db?.write !== 'function' || typeof db?.read !== 'function')
    throw new TypeError('createControlOutboxStore needs the control database (a Db)');
  const read = fn => db.read(fn);
  const write = fn => db.write(fn);
  const active = () => sql.list([...ACTIVE]);

  const selectRows = where => sql`SELECT * FROM ${T.outbox} WHERE ${where}`;

  // Bulk changes: `select(tx, limit)` names at most `limit` rows to change (ids), `change(tx,
  // ids)` changes them and returns the count. Repeated, one unit each, until a unit changes fewer
  // than the bound. Every change takes rows out of the selection, so the loop ends.
  async function bulk(select, change) {
    let total = 0;
    for (;;) {
      const changed = await write(tx => {
        const ids = select(tx, OUTBOX_UNIT_LIMITS.bulk);
        return ids.length ? change(tx, ids) : 0;
      });
      total += changed;
      if (changed < OUTBOX_UNIT_LIMITS.bulk) return total;
    }
  }
  const idsWhere = (tx, where, limit) =>
    tx
      .all(
        sql`SELECT ${T.id} FROM ${T.outbox} WHERE ${where} ${tx.dialect.orderBy(['id', 'asc', 'not null'])} ${tx.dialect.limit(limit)}`
      )
      .map(row => row.id);
  const updateIds = (tx, set, ids, guard = sql`1 = 1`) =>
    tx.run(tx.dialect.update('alerting_outbox', set, sql`${T.id} IN ${sql.list(ids)} AND ${guard}`))
      .changes;

  return {
    kind: 'control',

    /**
     * Inserts rows (each as createOutbox's newRow() builds it), at most 200 per unit. A row whose
     * uid exists (the same event, channel and target) is a duplicate and writes nothing.
     */
    async insert(rows) {
      const inserted = [],
        duplicates = [];
      for (const part of chunks(rows, OUTBOX_UNIT_LIMITS.insert)) {
        const values = part.map(row => {
          if (!row || typeof row !== 'object') throw new TypeError('An outbox row is an object');
          if (typeof row.uid !== 'string' || !row.uid)
            throw new TypeError('An outbox row needs a uid');
          return outboxColumns
            .filter(column => column !== 'id')
            .map(column => columnValue(column, row[OUTBOX_COLUMNS[column]]));
        });
        const result = await write(tx => {
          const added = [],
            skipped = [];
          values.forEach((value, index) => {
            const ran = tx.run(
              tx.dialect.insertIgnore(
                'alerting_outbox',
                outboxColumns.filter(column => column !== 'id'),
                [value],
                { conflict: ['uid'] }
              )
            );
            if (ran.changes === 1) added.push([index, ran.lastInsertRowid]);
            else skipped.push(index);
          });
          return { added, skipped };
        });
        for (const [index, rowId] of result.added)
          inserted.push({
            ...structuredClone(part[index]),
            target: String(part[index].target ?? ''),
            id: rowId,
          });
        for (const index of result.skipped) duplicates.push(part[index].uid);
      }
      return { inserted, duplicates };
    },

    /**
     * Queued rows due now on channels that may send (neither paused nor in back-off), in id
     * order, at most `limit` (≤ 200). A row is left out while an earlier active row of its
     * (channel, order key) is not itself due: "earlier" is a lower id, since the relay inserts the
     * rows of one order key in the order the alert changed (delivery spec D23).
     */
    async candidates({ now, limit = OUTBOX_UNIT_LIMITS.candidates, channels = null } = {}) {
      if (!Number.isFinite(now)) throw new TypeError('candidates() needs now');
      if (Array.isArray(channels) && !channels.length) return [];
      const most = Math.max(1, Math.min(Math.floor(limit) || 1, OUTBOX_UNIT_LIMITS.candidates));
      const only = Array.isArray(channels)
        ? sql`AND ${T.o('channel_id')} IN ${sql.list(channels.map(String))}`
        : sql``;
      const records = await read(tx =>
        tx.all(
          sql`SELECT o.* FROM ${T.outbox} o LEFT JOIN ${T.status} c ON ${T.c('channel_id')} = ${T.o('channel_id')} WHERE ${T.o('state')} = ${'queued'} AND ${T.o('next_at')} <= ${now} AND ${T.o('expires_at')} > ${now} ${only} AND (${T.c('channel_id')} IS NULL OR (${T.c('state')} <> ${'paused'} AND ${T.c('next_send_at')} <= ${now})) AND (${T.o('order_key')} IS NULL OR NOT EXISTS (SELECT 1 FROM ${T.outbox} p WHERE ${T.p('channel_id')} = ${T.o('channel_id')} AND ${T.p('order_key')} = ${T.o('order_key')} AND ${T.p('id')} < ${T.o('id')} AND ${T.p('state')} IN ${active()} AND NOT (${T.p('state')} = ${'queued'} AND ${T.p('next_at')} <= ${now} AND ${T.p('expires_at')} > ${now}))) ${tx.dialect.orderBy([T.o('id'), 'asc', 'not null'])} ${tx.dialect.limit(most)}`
        )
      );
      const rows = records.map(rowOf);
      // A row whose saved event cannot be read is never sent, and never stops the rows and
      // channels after it: it is set dead ('unreadable', in its own unit) and left out. Should
      // that write fail, it is left out all the same and tried again at the next pass.
      const unreadable = rows.filter(row => row.event === null).map(row => row.id);
      if (unreadable.length) {
        console.warn(
          `Notification rows ${unreadable.join(', ')} could not be read from control.sqlite; they are not sent.`
        );
        await write(tx =>
          updateIds(
            tx,
            {
              state: 'dead',
              dead_reason: 'unreadable',
              last_error: unreadableText,
              updated_at: integer('updated_at', now),
            },
            unreadable,
            sql`${T.state} = ${'queued'}`
          )
        ).catch(() => {});
      }
      return rows.filter(row => row.event !== null);
    },

    /**
     * Leases queued rows: they become 'sending' with the owner, epoch and lease, one attempt
     * more, and the digest key (kept when none is given). Rows no longer queued are skipped.
     * Returns the claimed rows in the order of `ids`; at most 100 ids per unit.
     */
    async claim(ids, { owner, epoch, now, leaseUntil, digestKey = null } = {}) {
      const claimed = new Map();
      for (const part of chunks(rowIds(ids), OUTBOX_UNIT_LIMITS.lease)) {
        const records = await write(tx =>
          tx.all(
            tx.dialect.update(
              'alerting_outbox',
              {
                state: 'sending',
                lease_owner: columnValue('lease_owner', owner),
                lease_until: integer('lease_until', leaseUntil),
                epoch: integer('epoch', epoch),
                attempts: sql`${self('attempts')} + 1`,
                digest_key: digestKey === null ? sql`${self('digest_key')}` : String(digestKey),
                updated_at: integer('updated_at', now),
              },
              sql`${T.id} IN ${sql.list(part)} AND ${T.state} = ${'queued'}`,
              { returning: outboxColumns }
            )
          )
        );
        for (const record of records) claimed.set(record.id, rowOf(record));
      }
      return rowIds(ids)
        .filter(rowId => claimed.has(rowId))
        .map(rowId => claimed.get(rowId));
    },

    /**
     * Applies send outcomes: each patch changes its row only while it is 'sending' under the
     * same owner and epoch (a completion from a lost lease changes nothing). At most 100 patches
     * per unit. Returns the rows changed.
     */
    async complete(patches, { owner, epoch } = {}) {
      const prepared = patches.map(({ id: rowId, patch }) => {
        const set = {};
        for (const [field, value] of Object.entries(patch ?? {})) {
          // An own property only: constructor, toString or __proto__ are no outbox fields.
          const column = Object.hasOwn(fieldColumn, field) ? fieldColumn[field] : undefined;
          if (!column || fixedFields.has(field))
            throw new TypeError(`An outbox completion cannot set ${field}`);
          set[column] = columnValue(column, value);
        }
        return { rowId: Number(rowId), set };
      });
      const lease =
        owner === null || owner === undefined
          ? sql`${T.lease_owner} IS NULL`
          : sql`${T.lease_owner} = ${String(owner)}`;
      let changed = 0;
      for (const part of chunks(prepared, OUTBOX_UNIT_LIMITS.lease))
        changed += await write(tx => {
          let count = 0;
          for (const { rowId, set } of part) {
            if (!Number.isSafeInteger(rowId)) continue;
            const where = sql`${T.id} = ${rowId} AND ${T.state} = ${'sending'} AND ${lease} AND ${T.epoch} = ${integer('epoch', epoch)}`;
            // An empty patch still counts the row it would have changed, as the memory store does.
            count += Object.keys(set).length
              ? tx.run(tx.dialect.update('alerting_outbox', set, where)).changes
              : tx.all(sql`SELECT ${T.id} FROM ${T.outbox} WHERE ${where}`).length;
          }
          return count;
        });
      return changed;
    },

    /**
     * Gives back rows claimed by a pass that met stop(): 'sending' rows of that owner and epoch
     * become queued again with the attempt not counted (nextAt and digest key kept).
     */
    async unclaim(ids, { owner, epoch, now } = {}) {
      const lease =
        owner === null || owner === undefined
          ? sql`${T.lease_owner} IS NULL`
          : sql`${T.lease_owner} = ${String(owner)}`;
      let changed = 0;
      for (const part of chunks(rowIds(ids), OUTBOX_UNIT_LIMITS.lease))
        changed += await write(tx =>
          updateIds(
            tx,
            {
              state: 'queued',
              attempts: sql`${self('attempts')} - 1`,
              lease_owner: null,
              lease_until: null,
              updated_at: integer('updated_at', now),
            },
            part,
            sql`${T.state} = ${'sending'} AND ${lease} AND ${T.epoch} = ${integer('epoch', epoch)}`
          )
        );
      return changed;
    },

    async sending() {
      const records = await read(tx =>
        tx.all(
          sql`${selectRows(sql`${T.state} = ${'sending'}`)} ${tx.dialect.orderBy(['id', 'asc', 'not null'])}`
        )
      );
      return records.map(rowOf);
    },

    /**
     * Queued and held rows at or past their expiry become dead ('expired'). An indexed read
     * first: with nothing to expire, no write unit is opened (the idle worker calls this every
     * few seconds, delivery spec D21).
     */
    async expire(now) {
      const due = sql`${T.state} IN ${sql.list(['queued', 'held'])} AND ${T.expires_at} <= ${now}`;
      const any = await read(tx =>
        tx.get(
          sql`SELECT 1 AS present FROM ${T.outbox} WHERE ${due} ${tx.dialect.orderBy(['id', 'asc', 'not null'])} ${tx.dialect.limit(1)}`
        )
      );
      if (!any) return 0;
      return bulk(
        (tx, limit) => idsWhere(tx, due, limit),
        (tx, ids) =>
          updateIds(
            tx,
            {
              state: 'dead',
              dead_reason: 'expired',
              last_error: sql`COALESCE(${self('last_error')}, ${expiredText})`,
              updated_at: integer('updated_at', now),
            },
            ids,
            due
          )
      );
    },

    /** A paused channel's queued rows are held. */
    async hold(channelId, now) {
      const where = sql`${T.channel_id} = ${String(channelId)} AND ${T.state} = ${'queued'}`;
      return bulk(
        (tx, limit) => idsWhere(tx, where, limit),
        (tx, ids) =>
          updateIds(tx, { state: 'held', updated_at: integer('updated_at', now) }, ids, where)
      );
    },

    /** Held rows are queued again and rows waiting to retry become due, all now. */
    async release(channelId, now) {
      const at = integer('next_at', now);
      const where = sql`${T.channel_id} = ${String(channelId)} AND (${T.state} = ${'held'} OR (${T.state} = ${'queued'} AND ${T.next_at} > ${at}))`;
      return bulk(
        (tx, limit) => idsWhere(tx, where, limit),
        (tx, ids) => updateIds(tx, { state: 'queued', next_at: at, updated_at: at }, ids, where)
      );
    },

    /**
     * Queued or held rows of `kinds` on the channel and order key become superseded, with
     * `reason` as their last error when given, and only those created before `createdBefore`
     * when given (D26: 1.4.x handled a later change of the alert).
     */
    async supersede({ channelId, orderKey, kinds, now, reason, createdBefore } = {}) {
      if (!Array.isArray(kinds) || !kinds.length) return 0;
      const before =
        createdBefore === undefined || createdBefore === null
          ? sql``
          : sql`AND ${T.created_at} < ${integer('created_at', createdBefore)}`;
      const where = sql`${T.channel_id} = ${String(channelId)} AND ${keyMatch(self, orderKey)} AND ${T.state} IN ${sql.list(['queued', 'held'])} AND ${T.kind} IN ${sql.list(kinds.map(String))} ${before}`;
      const set = { state: 'superseded', updated_at: integer('updated_at', now) };
      if (reason !== undefined && reason !== null) set.last_error = String(reason);
      return bulk(
        (tx, limit) => idsWhere(tx, where, limit),
        (tx, ids) => updateIds(tx, set, ids, where)
      );
    },

    async channel(channelId) {
      const record = await read(tx =>
        tx.get(sql`SELECT * FROM ${T.status} WHERE ${id('channel_id')} = ${String(channelId)}`)
      );
      return record ? statusOf(record) : null;
    },

    /** Replaces a channel's status; fields left out take the column defaults. */
    async setChannel(channelId, status = {}) {
      const values = { channel_id: String(channelId), ...statusDefaults };
      for (const [column, field] of Object.entries(CHANNEL_STATUS_COLUMNS)) {
        if (status[field] === undefined) continue;
        const value = status[field];
        if (column === 'last_error') values[column] = value === null ? null : json(value);
        else if (['state', 'paused_reason'].includes(column))
          values[column] = value === null ? null : String(value);
        else values[column] = integer(column, value);
      }
      values.updated_at = integer('updated_at', clock());
      await write(tx =>
        tx.run(
          tx.dialect.upsert('alerting_channel_status', ['channel_id'], statusColumns, [
            statusColumns.map(column => values[column]),
          ])
        )
      );
    },

    async channelIds() {
      const records = await read(tx =>
        tx.all(
          sql`SELECT ${id('channel_id')} FROM ${T.status} ${tx.dialect.orderBy(['channel_id', 'asc', 'not null'])}`
        )
      );
      return records.map(record => record.channel_id);
    },

    async countActive() {
      const record = await read(tx =>
        tx.get(sql`SELECT COUNT(*) AS n FROM ${T.outbox} WHERE ${T.state} IN ${active()}`)
      );
      return Number(record.n);
    },

    /**
     * Rows per state, overall and per channel, and the oldest queued or held row's creation.
     * Reads every row (wave 1's operation, kept for outbox.status() and tests); the service
     * uses summary().
     */
    async counts() {
      return read(tx => {
        const total = {},
          byChannel = {};
        for (const record of tx.all(
          sql`SELECT ${T.channel_id}, ${T.state}, COUNT(*) AS n FROM ${T.outbox} GROUP BY ${T.channel_id}, ${T.state}`
        )) {
          const n = Number(record.n);
          total[record.state] = (total[record.state] ?? 0) + n;
          byChannel[record.channel_id] ??= {};
          byChannel[record.channel_id][record.state] = n;
        }
        const oldest = tx.get(
          sql`SELECT MIN(${T.created_at}) AS oldest FROM ${T.outbox} WHERE ${T.state} IN ${sql.list(['queued', 'held'])}`
        );
        return { total, byChannel, oldestQueuedAt: oldest?.oldest ?? null };
      });
    },

    /** The next moment a queued row becomes due or a lease runs out, after `now`; or null. */
    async nextDueAt(now) {
      return read(tx => {
        const queued = tx.get(
          sql`SELECT MIN(${T.next_at}) AS at FROM ${T.outbox} WHERE ${T.state} = ${'queued'} AND ${T.next_at} > ${now}`
        )?.at;
        const lease = tx.get(
          sql`SELECT MIN(${T.lease_until}) AS at FROM ${T.outbox} WHERE ${T.state} = ${'sending'} AND ${T.lease_until} > ${now}`
        )?.at;
        const times = [queued, lease].filter(value => value !== null && value !== undefined);
        return times.length ? Math.min(...times) : null;
      });
    },

    /**
     * Rows newest first (id descending), at most `limit` (≤ 100), filtered by `states` (or the
     * alias `state`), `channelId` and `orderKey`, and paged by `beforeId` (ids below it) or
     * `afterId` (ids above it). `excludeWaiting` leaves out queued rows not tried yet (attempts
     * 0): the history's Problems filter, whose pages must hold `limit` problems whenever that
     * many exist, however many rows wait for their first attempt (a backlog behind an open
     * circuit).
     */
    async list({
      states,
      state,
      channelId,
      orderKey,
      beforeId,
      afterId,
      excludeWaiting = false,
      limit = 100,
    } = {}) {
      const wanted = states ?? (state ? [state] : null);
      if (Array.isArray(wanted) && !wanted.length) return [];
      const most = Math.max(1, Math.min(Math.floor(limit) || 1, OUTBOX_UNIT_LIMITS.list));
      const terms = [sql`1 = 1`];
      if (wanted) terms.push(sql`${T.state} IN ${sql.list(wanted.map(String))}`);
      if (excludeWaiting) terms.push(sql`NOT (${T.state} = ${'queued'} AND ${T.attempts} = ${0})`);
      if (channelId !== undefined && channelId !== null)
        terms.push(sql`${T.channel_id} = ${String(channelId)}`);
      if (orderKey !== undefined) terms.push(keyMatch(self, orderKey));
      for (const [bound, value, operator] of [
        ['beforeId', beforeId, 'below'],
        ['afterId', afterId, 'above'],
      ]) {
        if (value === undefined || value === null) continue;
        const at = Number(value);
        if (!Number.isSafeInteger(at)) throw new TypeError(`list(): ${bound} is a row id`);
        terms.push(operator === 'below' ? sql`${T.id} < ${at}` : sql`${T.id} > ${at}`);
      }
      const records = await read(tx =>
        tx.all(
          sql`${selectRows(sql.join(terms, sql` AND `))} ${tx.dialect.orderBy(['id', 'desc', 'not null'])} ${tx.dialect.limit(most)}`
        )
      );
      return records.map(rowOf);
    },

    /**
     * Retention: finished rows (delivered, superseded, stale, skipped, cancelled) and dead rows,
     * each group oldest first (by updatedAt, then id), lose the rows past `maxAgeMs` and the
     * oldest beyond `maxRows`; at most `limit` (≤ 1000) rows per call in all.
     */
    async prune({ now, finished, dead, limit = OUTBOX_UNIT_LIMITS.prune } = {}) {
      let left = Math.max(0, Math.min(Math.floor(limit) || 0, OUTBOX_UNIT_LIMITS.prune)),
        removed = 0;
      for (const [states, rule] of [
        [FINISHED, finished],
        [['dead'], dead],
      ]) {
        if (!left || !rule) continue;
        const group = sql`${T.state} IN ${sql.list([...states])}`;
        const count = await write(tx => {
          const all = Number(tx.get(sql`SELECT COUNT(*) AS n FROM ${T.outbox} WHERE ${group}`).n);
          const old = Number(
            tx.get(
              sql`SELECT COUNT(*) AS n FROM ${T.outbox} WHERE ${group} AND ${T.updated_at} <= ${now - rule.maxAgeMs}`
            ).n
          );
          const take = Math.min(left, Math.max(all - rule.maxRows, old, 0));
          if (!take) return 0;
          return tx.run(
            tx.dialect.deleteFrom(
              'alerting_outbox',
              sql`${T.id} IN (SELECT ${T.id} FROM ${T.outbox} WHERE ${group} ${tx.dialect.orderBy(['updated_at', 'asc', 'not null'], ['id', 'asc', 'not null'])} ${tx.dialect.limit(take)})`
            )
          ).changes;
        });
        removed += count;
        left -= count;
      }
      return removed;
    },

    // --- Delivery spec §5.2 additions -----------------------------------------------------

    /** The row with this delivery id, or null (through alerting_outbox_uid). */
    async find(uid) {
      const record = await read(tx => tx.get(selectRows(sql`${T.uid} = ${String(uid)}`)));
      return record ? rowOf(record) : null;
    },

    /**
     * Every row of a digest batch, in id order (at most the 100 of one batch); with `states`, only
     * the rows in those states. digest_key has no index: without `states` only Retry, an admin
     * action, calls this. The worker asks for a batch's active rows before it sends a batch that
     * was tried before (it goes out whole); that read searches an index that starts with the
     * state (SQLite picks alerting_outbox_due or alerting_outbox_finished), so it never scans the
     * finished rows.
     */
    async batch(digestKey, { states } = {}) {
      if (Array.isArray(states) && !states.length) return [];
      const inStates = Array.isArray(states)
        ? sql`${T.state} IN ${sql.list(states.map(String))} AND `
        : sql``;
      const records = await read(tx =>
        tx.all(
          sql`${selectRows(sql`${inStates}${T.digest_key} = ${String(digestKey)}`)} ${tx.dialect.orderBy(['id', 'asc', 'not null'])} ${tx.dialect.limit(OUTBOX_UNIT_LIMITS.batch)}`
        )
      );
      return records.map(rowOf);
    },

    /**
     * Retry now (D18): dead and queued rows become queued and due now, lease cleared and dead
     * reason dropped; a dead row also gets `expiresAt` (when given) and its unknown count reset.
     * Other states are left alone. Returns the rows changed.
     */
    async requeue(ids, { now, expiresAt } = {}) {
      const at = integer('next_at', now);
      let changed = 0;
      for (const part of chunks(rowIds(ids), OUTBOX_UNIT_LIMITS.bulk))
        changed += await write(tx => {
          // Each row is changed once: which rows are dead and which queued is read first.
          const states = new Map(
            tx
              .all(
                sql`SELECT ${T.id}, ${T.state} FROM ${T.outbox} WHERE ${T.id} IN ${sql.list(part)} AND ${T.state} IN ${sql.list(['dead', 'queued'])}`
              )
              .map(record => [record.id, record.state])
          );
          const dead = part.filter(rowId => states.get(rowId) === 'dead'),
            queued = part.filter(rowId => states.get(rowId) === 'queued');
          const common = {
            state: 'queued',
            next_at: at,
            lease_owner: null,
            lease_until: null,
            dead_reason: null,
            updated_at: at,
          };
          const fromDead = { ...common, unknowns: 0 };
          if (expiresAt !== undefined && expiresAt !== null)
            fromDead.expires_at = integer('expires_at', expiresAt);
          return (
            (dead.length ? updateIds(tx, fromDead, dead, sql`${T.state} = ${'dead'}`) : 0) +
            (queued.length ? updateIds(tx, common, queued, sql`${T.state} = ${'queued'}`) : 0)
          );
        });
      return changed;
    },

    /** D16: queued, held and sending rows become 'stale' with `reason`, never to be sent. */
    async stale({ now, reason } = {}) {
      const where = sql`${T.state} IN ${active()}`;
      return bulk(
        (tx, limit) => idsWhere(tx, where, limit),
        (tx, ids) =>
          updateIds(
            tx,
            {
              state: 'stale',
              last_error: reason === undefined || reason === null ? null : String(reason),
              lease_owner: null,
              lease_until: null,
              updated_at: integer('updated_at', now),
            },
            ids,
            where
          )
      );
    },

    /**
     * D24: queued and held rows whose order key starts with `orderKeyPrefix` (a deleted
     * source's, "<service id>\n") become 'cancelled' with `reason`.
     */
    async cancel({ orderKeyPrefix, now, reason } = {}) {
      if (typeof orderKeyPrefix !== 'string' || !orderKeyPrefix)
        throw new TypeError('cancel() needs an order key prefix');
      const waiting = sql`${T.state} IN ${sql.list(['queued', 'held'])}`;
      const set = {
        state: 'cancelled',
        last_error: reason === undefined || reason === null ? null : String(reason),
        updated_at: integer('updated_at', now),
      };
      const upper = prefixUpperBound(orderKeyPrefix);
      if (upper !== null) {
        const where = sql`${waiting} AND ${T.order_key} >= ${orderKeyPrefix} AND ${T.order_key} < ${upper}`;
        return bulk(
          (tx, limit) => idsWhere(tx, where, limit),
          (tx, ids) => updateIds(tx, set, ids, where)
        );
      }
      // A prefix ending in a surrogate or U+FFFF: match in JavaScript.
      return bulk(
        (tx, limit) =>
          tx
            .all(
              sql`SELECT ${T.id}, ${T.order_key} FROM ${T.outbox} WHERE ${waiting} AND ${T.order_key} >= ${orderKeyPrefix} ${tx.dialect.orderBy(['id', 'asc', 'not null'])}`
            )
            .filter(record => record.order_key.startsWith(orderKeyPrefix))
            .slice(0, limit)
            .map(record => record.id),
        (tx, ids) => updateIds(tx, set, ids, waiting)
      );
    },

    /**
     * Of the given [{channelId, orderKey}] (in input order), those with a queued, sending or
     * held row: point lookups on alerting_outbox_order, one read unit per 200 keys.
     */
    async activeKeys(keys) {
      const found = [];
      for (const part of chunks(keys ?? [], OUTBOX_UNIT_LIMITS.keys))
        found.push(
          ...(await read(tx =>
            part.filter(key =>
              tx.get(
                sql`SELECT 1 AS present FROM ${T.outbox} WHERE ${T.channel_id} = ${String(key.channelId)} AND ${keyMatch(self, key.orderKey)} AND ${T.state} IN ${active()} ${tx.dialect.orderBy(['id', 'asc', 'not null'])} ${tx.dialect.limit(1)}`
              )
            )
          ))
        );
      return found.map(key => ({ channelId: key.channelId, orderKey: key.orderKey }));
    },

    /** D25, a forward clock step: active rows' expiry moves on by `by`. */
    async shiftExpiry({ by, now } = {}) {
      const step = integer('expires_at', by);
      if (!step) return 0;
      let after = 0,
        total = 0;
      // By id, so no row is moved twice, whatever else changes between the units.
      for (;;) {
        const { changed, ids } = await write(tx => {
          const ids = idsWhere(
            tx,
            sql`${T.state} IN ${active()} AND ${T.id} > ${after}`,
            OUTBOX_UNIT_LIMITS.bulk
          );
          if (!ids.length) return { changed: 0, ids };
          const set = {
            expires_at: sql`${self('expires_at')} + ${step}`,
            updated_at: integer('updated_at', now),
          };
          return { changed: updateIds(tx, set, ids, sql`${T.state} IN ${active()}`), ids };
        });
        total += changed;
        if (ids.length < OUTBOX_UNIT_LIMITS.bulk) return total;
        after = ids.at(-1);
      }
    },

    /**
     * D25, a backward clock step: queued rows' nextAt, active rows' expiresAt and sending rows'
     * leaseUntil are lowered to at most the given values. Returns the rows changed.
     */
    async clampTimes({ now, nextAtMax, expiresAtMax, leaseUntilMax } = {}) {
      const caps = [];
      const set = { updated_at: integer('updated_at', now) };
      if (nextAtMax !== undefined && nextAtMax !== null) {
        const cap = integer('next_at', nextAtMax);
        caps.push(sql`(${T.state} = ${'queued'} AND ${T.next_at} > ${cap})`);
        set.next_at = sql`CASE WHEN ${self('state')} = ${'queued'} AND ${self('next_at')} > ${cap} THEN ${cap} ELSE ${self('next_at')} END`;
      }
      if (expiresAtMax !== undefined && expiresAtMax !== null) {
        const cap = integer('expires_at', expiresAtMax);
        caps.push(sql`(${T.state} IN ${active()} AND ${T.expires_at} > ${cap})`);
        set.expires_at = sql`CASE WHEN ${self('expires_at')} > ${cap} THEN ${cap} ELSE ${self('expires_at')} END`;
      }
      if (leaseUntilMax !== undefined && leaseUntilMax !== null) {
        const cap = integer('lease_until', leaseUntilMax);
        caps.push(sql`(${T.state} = ${'sending'} AND ${T.lease_until} > ${cap})`);
        set.lease_until = sql`CASE WHEN ${self('state')} = ${'sending'} AND ${self('lease_until')} > ${cap} THEN ${cap} ELSE ${self('lease_until')} END`;
      }
      if (!caps.length) return 0;
      const where = sql`(${sql.join(caps, sql` OR `)})`;
      return bulk(
        (tx, limit) => idsWhere(tx, where, limit),
        (tx, ids) => updateIds(tx, set, ids, where)
      );
    },

    /**
     * Per channel: waiting (queued, no attempt yet), retrying (queued after an attempt),
     * sending, held, failed (dead rows finished after failedSince[channel], 0 when absent) and
     * oldestWaitingAt (the oldest queued or held row's creation). Active rows are read through
     * alerting_outbox_due, dead rows through alerting_outbox_finished. A channel with none of
     * these is absent.
     */
    async summary({ failedSince = {} } = {}) {
      return read(tx => {
        const out = {};
        const entry = channelId =>
          (out[channelId] ??= {
            waiting: 0,
            retrying: 0,
            sending: 0,
            held: 0,
            failed: 0,
            oldestWaitingAt: null,
          });
        for (const record of tx.all(
          sql`SELECT ${T.channel_id}, ${T.state}, COUNT(*) AS n, SUM(CASE WHEN ${T.attempts} > 0 THEN 1 ELSE 0 END) AS tried, MIN(${T.created_at}) AS oldest FROM ${T.outbox} WHERE ${T.state} IN ${active()} GROUP BY ${T.channel_id}, ${T.state}`
        )) {
          const item = entry(record.channel_id),
            n = Number(record.n),
            tried = Number(record.tried ?? 0);
          if (record.state === 'queued') {
            item.retrying += tried;
            item.waiting += n - tried;
          } else item[record.state] += n;
          if (record.state !== 'sending' && record.oldest !== null)
            item.oldestWaitingAt =
              item.oldestWaitingAt === null
                ? record.oldest
                : Math.min(item.oldestWaitingAt, record.oldest);
        }
        // Channels sharing a threshold are counted by one query (channels not named use 0).
        const thresholdOf = channelId =>
          Number.isFinite(failedSince?.[channelId]) ? failedSince[channelId] : 0;
        const thresholds = new Set([0, ...Object.keys(failedSince ?? {}).map(thresholdOf)]);
        for (const at of thresholds)
          for (const record of tx.all(
            sql`SELECT ${T.channel_id}, COUNT(*) AS n FROM ${T.outbox} WHERE ${T.state} = ${'dead'} AND ${T.updated_at} > ${at} GROUP BY ${T.channel_id}`
          ))
            if (thresholdOf(record.channel_id) === at && Number(record.n))
              entry(record.channel_id).failed = Number(record.n);
        return out;
      });
    },
  };
}
