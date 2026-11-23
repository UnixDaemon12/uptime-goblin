// Identity's tables in control.sqlite (sessions spec §4): `users`, `sessions` and
// `identity_settings`, plus the two `meta` keys identity uses (credentials_ever, restored). This
// is the only identity module that issues SQL (import-graph rule 5 keeps lib/db/sql.mjs to
// lib/db, lib/repo and lib/series); lib/identity/** calls these inside its own db.read and
// db.write callbacks.
//
// Every function takes the transaction first and runs synchronously (the SQLite guard: a unit
// of work never spans an await). Rows come back as plain objects with camel-case names and
// numbers, so callers never see a driver's representation (BigInt, 0/1 booleans, JSON text).
import { sql, id, json, list, toSafeNumber } from '../db/sql.mjs';
import { metaOps } from '../db/control.mjs';

const userColumns = Object.freeze([
  'id',
  'login',
  'display_name',
  'role',
  'kind',
  'password',
  'password_changed_at',
  'epoch',
  'disabled_at',
  'created_at',
  'updated_at',
  'last_login_at',
  'row_version',
]);
const sessionColumns = Object.freeze([
  'id',
  'token_hash',
  'user_id',
  'kind',
  'stage',
  'via',
  'transport',
  'persistent',
  'created_at',
  'auth_time',
  'last_seen_at',
  'idle_expires_at',
  'expires_at',
  'client_key',
  'user_agent',
]);
const displayColumns = Object.freeze([
  'id',
  'name',
  'code_hash',
  'state',
  'origin',
  'code_expires_at',
  'created_at',
  'created_by',
  'created_session',
  'created_scope',
  'session_id',
  'redeemed_at',
  'redeemed_client',
  'cancelled_at',
  'cancel_cause',
  'cancel_recorded',
]);
const T = Object.freeze({
  users: id('users'),
  sessions: id('sessions'),
  settings: id('identity_settings'),
  displays: id('displays'),
  state: id('state'),
  codeHash: id('code_hash'),
  codeExpiresAt: id('code_expires_at'),
  sessionId: id('session_id'),
  cancelledAt: id('cancelled_at'),
  cancelRecorded: id('cancel_recorded'),
  redeemedAt: id('redeemed_at'),
  id: id('id'),
  userId: id('user_id'),
  tokenHash: id('token_hash'),
  expiresAt: id('expires_at'),
  idleExpiresAt: id('idle_expires_at'),
  transport: id('transport'),
  key: id('key'),
  value: id('value'),
});
const columnList = names => sql.join(names.map(name => id(name)));
// A statement binds at most 2,000 values on every engine; ids are deleted in slices well below.
const idSlice = 500;
const num = toSafeNumber;

function userOf(row) {
  if (!row) return null;
  return {
    id: row.id,
    login: row.login,
    displayName: row.display_name,
    role: row.role,
    kind: row.kind,
    // Left as text: identity decides what a record that does not parse means (§5.7 check 2).
    passwordText: row.password ?? null,
    passwordChangedAt: num(row.password_changed_at),
    epoch: num(row.epoch),
    disabledAt: num(row.disabled_at),
    createdAt: num(row.created_at),
    updatedAt: num(row.updated_at),
    lastLoginAt: num(row.last_login_at),
    rowVersion: num(row.row_version),
  };
}

function sessionOf(row) {
  if (!row) return null;
  return {
    id: row.id,
    tokenHash: row.token_hash,
    userId: row.user_id,
    kind: row.kind,
    stage: row.stage,
    via: row.via,
    transport: row.transport,
    persistent: Number(row.persistent) === 1,
    createdAt: num(row.created_at),
    authTime: num(row.auth_time),
    lastSeenAt: num(row.last_seen_at),
    idleExpiresAt: num(row.idle_expires_at),
    expiresAt: num(row.expires_at),
    clientKey: row.client_key ?? null,
    userAgent: row.user_agent ?? null,
  };
}

function displayOf(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    codeHash: row.code_hash,
    state: row.state,
    origin: row.origin,
    codeExpiresAt: num(row.code_expires_at),
    createdAt: num(row.created_at),
    createdBy: row.created_by,
    createdSession: row.created_session ?? null,
    createdScope: row.created_scope ?? null,
    sessionId: row.session_id ?? null,
    redeemedAt: num(row.redeemed_at),
    redeemedClient: row.redeemed_client ?? null,
    cancelledAt: num(row.cancelled_at),
    cancelCause: row.cancel_cause ?? null,
    cancelRecorded: Number(row.cancel_recorded) === 1,
  };
}

const selectSessions = sql`SELECT ${columnList(sessionColumns)} FROM ${T.sessions}`;
const selectDisplays = sql`SELECT ${columnList(displayColumns)} FROM ${T.displays}`;
// A day: how long a stale code's hash is kept, so typing it is recognised and not counted as a
// guess (B6 design §7.2, §7.4).
const staleCodeMs = 86400e3;
const brief = rows => rows.map(row => ({ id: row.id, expiresAt: num(row.expires_at) }));

function deleteIds(tx, ids) {
  let changes = 0;
  for (let start = 0; start < ids.length; start += idSlice)
    changes += tx.run(
      tx.dialect.deleteFrom('sessions', sql`${T.id} IN ${list(ids.slice(start, start + idSlice))}`)
    ).changes;
  return changes;
}

export const identityOps = Object.freeze({
  // ---- users ------------------------------------------------------------------------------

  /** The user `userId`, or null. */
  user(tx, userId) {
    return userOf(
      tx.get(sql`SELECT ${columnList(userColumns)} FROM ${T.users} WHERE ${T.id} = ${userId}`)
    );
  },

  /** Inserts a user with epoch 1 and row_version 1. `password` is a record or null. */
  insertUser(tx, { id: userId, login, displayName, role, kind, password, passwordChangedAt, now }) {
    tx.run(
      tx.dialect.insert('users', userColumns, {
        id: userId,
        login,
        display_name: displayName,
        role,
        kind,
        password: password === null ? null : json(password),
        password_changed_at: passwordChangedAt ?? null,
        epoch: 1,
        disabled_at: null,
        created_at: now,
        updated_at: now,
        last_login_at: null,
        row_version: 1,
      })
    );
  },

  /**
   * Sets the password (a record, or null) with a compare-and-swap on row_version, which moves
   * on by one; `bumpEpoch` also moves the epoch on (imports: every earlier access ends).
   * Returns false, changing nothing, when the row changed since `rowVersion` was read.
   */
  setPassword(tx, userId, { password, passwordChangedAt, now, rowVersion, bumpEpoch = false }) {
    const set = {
      password: password === null ? null : json(password),
      password_changed_at: passwordChangedAt ?? null,
      updated_at: now,
      row_version: sql`${id('row_version')} + 1`,
    };
    if (bumpEpoch) set.epoch = sql`${id('epoch')} + 1`;
    return (
      tx.run(
        tx.dialect.update(
          'users',
          set,
          sql`${T.id} = ${userId} AND ${id('row_version')} = ${rowVersion}`
        )
      ).changes === 1
    );
  },

  /** epoch + 1 and row_version + 1 (a restore signs everyone out), with the same CAS. */
  bumpEpoch(tx, userId, { now, rowVersion }) {
    return (
      tx.run(
        tx.dialect.update(
          'users',
          {
            epoch: sql`${id('epoch')} + 1`,
            row_version: sql`${id('row_version')} + 1`,
            updated_at: now,
          },
          sql`${T.id} = ${userId} AND ${id('row_version')} = ${rowVersion}`
        )
      ).changes === 1
    );
  },

  /** last_login_at: bookkeeping only, so row_version (which guards the password) stays. */
  setLastLogin(tx, userId, now) {
    tx.run(tx.dialect.update('users', { last_login_at: now }, sql`${T.id} = ${userId}`));
  },

  // ---- sessions ---------------------------------------------------------------------------

  /** The session whose secret hashes to `tokenHash`, or null. */
  sessionByHash(tx, tokenHash) {
    return sessionOf(tx.get(sql`${selectSessions} WHERE ${T.tokenHash} = ${tokenHash}`));
  },

  /** The sessions whose secrets hash to one of `tokenHashes` (any number), in no order. */
  sessionsByHashes(tx, tokenHashes) {
    const found = [];
    for (let start = 0; start < tokenHashes.length; start += idSlice)
      found.push(
        ...tx
          .all(
            sql`${selectSessions} WHERE ${T.tokenHash} IN ${list(tokenHashes.slice(start, start + idSlice))}`
          )
          .map(sessionOf)
      );
    return found;
  },

  /** The session `sessionId`, or null. */
  session(tx, sessionId) {
    return sessionOf(tx.get(sql`${selectSessions} WHERE ${T.id} = ${sessionId}`));
  },

  /** Every session of `userId`, most recently seen first. */
  userSessions(tx, userId) {
    return tx
      .all(
        sql`${selectSessions} WHERE ${T.userId} = ${userId} ${tx.dialect.orderBy(
          ['last_seen_at', 'desc', 'not null'],
          ['created_at', 'desc', 'not null'],
          ['id', 'asc', 'not null']
        )}`
      )
      .map(sessionOf);
  },

  /** The latest auth_time among the sessions of `userId` (ended rows included), or null. */
  newestAuthTime(tx, userId) {
    const row = tx.get(
      sql`SELECT MAX(${id('auth_time')}) AS newest FROM ${T.sessions} WHERE ${T.userId} = ${userId}`
    );
    return num(row?.newest ?? null);
  },

  /** Inserts a session (camel-case fields as sessionOf returns them). */
  insertSession(tx, session) {
    tx.run(
      tx.dialect.insert('sessions', sessionColumns, {
        id: session.id,
        token_hash: session.tokenHash,
        user_id: session.userId,
        kind: session.kind,
        stage: session.stage,
        via: session.via,
        transport: session.transport,
        persistent: session.persistent === true,
        created_at: session.createdAt,
        auth_time: session.authTime,
        last_seen_at: session.lastSeenAt,
        idle_expires_at: session.idleExpiresAt,
        expires_at: session.expiresAt,
        client_key: session.clientKey ?? null,
        user_agent: session.userAgent ?? null,
      })
    );
  },

  /**
   * Records activity: `lastSeenAt` and/or `idleExpiresAt` (either may be undefined). Returns
   * the number of rows changed (0 when the session is gone).
   */
  touchSession(tx, sessionId, { lastSeenAt, idleExpiresAt }) {
    const set = {};
    if (lastSeenAt !== undefined) set.last_seen_at = lastSeenAt;
    if (idleExpiresAt !== undefined) set.idle_expires_at = idleExpiresAt;
    if (!Object.keys(set).length) return 0;
    return tx.run(tx.dialect.update('sessions', set, sql`${T.id} = ${sessionId}`)).changes;
  },

  /** Deletes the sessions `ids` (any number); returns how many rows went. */
  deleteSessions(tx, ids) {
    return ids.length ? deleteIds(tx, ids) : 0;
  },

  /** Deletes every session of `userId`; returns [{id, expiresAt}] of the rows deleted. */
  deleteUserSessions(tx, userId) {
    const rows = brief(
      tx.all(sql`SELECT ${T.id}, ${T.expiresAt} FROM ${T.sessions} WHERE ${T.userId} = ${userId}`)
    );
    deleteIds(
      tx,
      rows.map(row => row.id)
    );
    return rows;
  },

  /**
   * Makes room for new sessions: deletes the least recently seen sessions of `userId` (ties:
   * the oldest first) until at most `keep` remain. Returns [{id, expiresAt}] of those deleted.
   */
  evictSessions(tx, userId, keep) {
    const { n } = tx.get(
      sql`SELECT COUNT(*) AS n FROM ${T.sessions} WHERE ${T.userId} = ${userId}`
    );
    const excess = Number(n) - Math.max(0, keep);
    if (excess <= 0) return [];
    const rows = brief(
      tx.all(
        sql`SELECT ${T.id}, ${T.expiresAt} FROM ${T.sessions} WHERE ${T.userId} = ${userId} ${tx.dialect.orderBy(
          ['last_seen_at', 'asc', 'not null'],
          ['created_at', 'asc', 'not null'],
          ['id', 'asc', 'not null']
        )} ${tx.dialect.limit(excess)}`
      )
    );
    deleteIds(
      tx,
      rows.map(row => row.id)
    );
    return rows;
  },

  /**
   * Deletes every session signed in over `transport` (the plain-HTTP ones, once
   * GOBLIN_INSECURE_HTTP_SESSIONS is off); returns [{id, expiresAt}] of those deleted.
   */
  deleteSessionsOver(tx, transport) {
    const rows = brief(
      tx.all(
        sql`SELECT ${T.id}, ${T.expiresAt} FROM ${T.sessions} WHERE ${T.transport} = ${transport}`
      )
    );
    deleteIds(
      tx,
      rows.map(row => row.id)
    );
    return rows;
  },

  /** Deletes sessions past their absolute or idle expiry at `now`; returns the count. */
  deleteExpiredSessions(tx, now) {
    return tx.run(
      tx.dialect.deleteFrom(
        'sessions',
        sql`${T.expiresAt} <= ${now} OR ${T.idleExpiresAt} <= ${now}`
      )
    ).changes;
  },

  // ---- displays (one-time wall display codes, B6 design §7) ----------------------------------

  /** Inserts a waiting display code (camel-case fields as displayOf returns them). */
  insertDisplay(tx, display) {
    tx.run(
      tx.dialect.insert('displays', displayColumns, {
        id: display.id,
        name: display.name,
        code_hash: display.codeHash,
        state: 'waiting',
        origin: display.origin ?? 'cli',
        code_expires_at: display.codeExpiresAt,
        created_at: display.createdAt,
        created_by: display.createdBy,
        created_session: display.createdSession ?? null,
        created_scope: display.createdScope ?? null,
        session_id: null,
        redeemed_at: null,
        redeemed_client: null,
        cancelled_at: null,
        cancel_cause: null,
        cancel_recorded: true,
      })
    );
  },

  /** How many codes wait unexpired at `now`. */
  waitingDisplays(tx, now) {
    const { n } = tx.get(
      sql`SELECT COUNT(*) AS n FROM ${T.displays} WHERE ${T.state} = ${'waiting'} AND ${T.codeExpiresAt} > ${now}`
    );
    return Number(n);
  },

  /** Every display still kept, newest first (at most `limit`). */
  listDisplays(tx, limit) {
    const order = tx.dialect.orderBy(['created_at', 'desc', 'not null'], ['id', 'asc', 'not null']);
    return tx.all(sql`${selectDisplays} ${order} ${tx.dialect.limit(limit)}`).map(displayOf);
  },

  /** Restore boundary: remove every display record, including formerly used codes. */
  deleteDisplays(tx) {
    return tx.run(tx.dialect.deleteFrom('displays', sql`1 = 1`)).changes;
  },

  /** The display `displayId`, or null. */
  display(tx, displayId) {
    return displayOf(tx.get(sql`${selectDisplays} WHERE ${T.id} = ${displayId}`));
  },

  /** The display whose code hashes to `codeHash`, or null. */
  displayByHash(tx, codeHash) {
    return displayOf(tx.get(sql`${selectDisplays} WHERE ${T.codeHash} = ${codeHash}`));
  },

  /** The displays the sessions `sessionIds` were redeemed as (any number), in no order. */
  displaysForSessions(tx, sessionIds) {
    const found = [];
    for (let start = 0; start < sessionIds.length; start += idSlice)
      found.push(
        ...tx
          .all(
            sql`${selectDisplays} WHERE ${T.sessionId} IN ${list(sessionIds.slice(start, start + idSlice))}`
          )
          .map(displayOf)
      );
    return found;
  },

  /**
   * Claims a waiting, unexpired code for the session `sessionId`: one UPDATE that changes
   * exactly one row or none (two redemptions of one code: one wins). Returns the changes.
   */
  claimDisplay(tx, codeHash, { sessionId, now, client }) {
    return tx.run(
      tx.dialect.update(
        'displays',
        {
          state: 'redeemed',
          session_id: sessionId,
          redeemed_at: now,
          redeemed_client: client ?? null,
        },
        sql`${T.codeHash} = ${codeHash} AND ${T.state} = ${'waiting'} AND ${T.codeExpiresAt} > ${now}`
      )
    ).changes;
  },

  /**
   * Cancels waiting codes: `ids` (a list), or every waiting one when `ids` is null; with
   * `codeHash` only the waiting, unexpired code of that hash. `recorded` false marks each
   * cancellation's audit row as owed. Returns [{id, name}] of the rows cancelled.
   */
  cancelDisplays(tx, { ids = null, codeHash = null, cause, now, recorded = true }) {
    let where = sql`${T.state} = ${'waiting'}`;
    if (codeHash !== null)
      where = sql`${where} AND ${T.codeHash} = ${codeHash} AND ${T.codeExpiresAt} > ${now}`;
    else if (ids !== null) {
      if (!ids.length) return [];
      where = sql`${where} AND ${T.id} IN ${list(ids)}`;
    }
    const rows = tx
      .all(sql`SELECT ${T.id}, ${id('name')} FROM ${T.displays} WHERE ${where}`)
      .map(row => ({ id: row.id, name: row.name }));
    if (rows.length)
      tx.run(
        tx.dialect.update(
          'displays',
          {
            state: 'cancelled',
            cancelled_at: now,
            cancel_cause: cause,
            cancel_recorded: recorded,
          },
          sql`${T.id} IN ${list(rows.map(row => row.id))}`
        )
      );
    return rows;
  },

  /** Cancellations whose audit row is owed (at most `limit`), oldest first. */
  unrecordedCancels(tx, limit) {
    return tx
      .all(
        sql`${selectDisplays} WHERE ${T.state} = ${'cancelled'} AND ${T.cancelRecorded} = ${false} ${tx.dialect.orderBy(
          ['cancelled_at', 'asc', 'not null'],
          ['id', 'asc', 'not null']
        )} ${tx.dialect.limit(limit)}`
      )
      .map(displayOf);
  },

  /** Marks the cancellations of `ids` as recorded. */
  markCancelsRecorded(tx, ids) {
    if (!ids.length) return 0;
    return tx.run(
      tx.dialect.update('displays', { cancel_recorded: true }, sql`${T.id} IN ${list(ids)}`)
    ).changes;
  },

  /**
   * Deletes display rows no longer needed (§7.2): a waiting code a day after its expiry, a
   * recorded cancellation a day after it, and a redeemed code whose session is gone, a day after
   * its redemption. Returns the count.
   */
  pruneDisplays(tx, now) {
    const before = now - staleCodeMs;
    return tx.run(
      tx.dialect.deleteFrom(
        'displays',
        sql`(${T.state} = ${'waiting'} AND ${T.codeExpiresAt} <= ${before})
          OR (${T.state} = ${'cancelled'} AND ${T.cancelRecorded} = ${true} AND ${T.cancelledAt} <= ${before})
          OR (${T.state} = ${'redeemed'} AND ${T.redeemedAt} <= ${before}
            AND NOT EXISTS (SELECT 1 FROM ${T.sessions} WHERE ${T.sessions}.${T.id} = ${T.displays}.${T.sessionId}))`
      )
    ).changes;
  },

  // ---- identity_settings (node-local bookkeeping, D3) ---------------------------------------

  /** Every key and value. */
  settings(tx) {
    return Object.fromEntries(
      tx.all(sql`SELECT ${T.key}, ${T.value} FROM ${T.settings}`).map(row => [row.key, row.value])
    );
  },

  setSetting(tx, key, value, now) {
    tx.run(
      tx.dialect.upsert(
        'identity_settings',
        ['key'],
        ['key', 'value', 'updated_at'],
        [[key, String(value), now]]
      )
    );
  },

  deleteSetting(tx, key) {
    tx.run(tx.dialect.deleteFrom('identity_settings', sql`${T.key} = ${key}`));
  },

  // ---- meta ---------------------------------------------------------------------------------

  /** A meta value, or null. */
  meta: (tx, key) => metaOps.get(tx, key),

  /**
   * meta.credentials_ever = 1, one way: the admin has had a password (D4). Kept in the data
   * contract; no start depends on it, since server.mjs and startControl refuse every start
   * without auth.json or GOBLIN_PASSWORD.
   */
  markCredentials: (tx, now) => metaOps.setIfAbsent(tx, 'credentials_ever', '1', now),
});
