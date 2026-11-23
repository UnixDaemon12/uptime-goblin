// Identity: the built-in admin (u_admin), its password and its sign-in sessions (sessions spec
// §5). server.mjs imports only this file:
//
//   const sources = readBuiltinSources({directory, password});        // before startControl
//   const identity = await createIdentity({control, directory, sources, audit});
//   const {access, issue} = await identity.login({login, password, remember, client, …});
//   const access = await identity.authenticateSession(cookieValue, {activity});
//   identity.assertCurrent(access);                                   // sync, after every await
//
// Identity knows nothing about HTTP (D5): the http layer hands it cookie values and decoded
// Basic credentials, and turns its AuthErrors (lib/identity/errors.mjs) into answers.
//
// Sessions live in control.sqlite (only the SHA-256 of each secret); a session request costs one
// indexed read and at most one write a minute, and never a KDF derivation. Revocation deletes
// the row and, first, enters the id in an in-memory map, so assertCurrent() stays synchronous
// (exclusive() and the idempotency loop re-check after their last await): every revocation is in
// the map no later than the synchronous db.write callback that commits it (§5.9, D6).
//
// A session can end only sessions that signed in no later than it did (auth_time; Basic, which
// proves the password with every request, ends any). A cookie copied from a lost device or a
// plain-HTTP network must not end the sign-ins that prove the password again: otherwise its
// holder could end each one, in a loop, before it could sign the cookie out or change the
// password. A sign-in's auth_time is later than that of every session there is, even after the
// clock was set back, so signing in again always outranks a stolen cookie.
import { permissions as routerPermissions } from '../http/router.mjs';
import { identityOps } from '../repo/identity.mjs';
import { eventFrom } from '../audit/actions.mjs';
import { identityError } from './errors.mjs';
import {
  createHasher,
  makeRecord,
  verifyRecord,
  verifyDummy,
  checkNewPassword,
  tightenAuthRecord,
  writeAuthRecord as writeAuthFile,
  maxPasswordBytes,
} from './password.mjs';
import { newSession, sessionTokenHash, isSessionId, displayCodeHash } from './secrets.mjs';
import {
  BUILTIN_ID,
  readBuiltinSources,
  bootstrapBuiltin,
  passwordRequiredMessage,
  controlFileIdentity,
  mirrorAuthRecord,
  mirrorLines,
  keys,
  writeRecorded,
  recordSystem,
  mirrorFailedEvent,
  accountTarget,
  sessionTarget,
} from './bootstrap.mjs';
import { createBasicVerifier } from './basic.mjs';

export { BUILTIN_ID, readBuiltinSources, passwordRequiredMessage };

export const defaultLimits = Object.freeze({
  idleMs: 12 * 3600e3, // every interactive session (D7)
  absoluteMs: 7 * 86400e3, // without "Keep me signed in"
  rememberMs: 30 * 86400e3, // with "Keep me signed in"
  maxSessions: 20, // per user; the least recently seen is evicted
  touchMs: 60e3, // last_seen_at / idle_expires_at written at most this often
  pruneMs: 3600e3, // expired-row prune and mirror retry
  retiredMs: 86400e3, // Basic: replaced passwords refused without counting
});

// A wall display's limits (B6 design §7.5, as amended): 30 days from its code's redemption, 7
// days without a request. lib/environment.mjs displaySessionLimits() reads the two variables.
export const defaultDisplayLimits = Object.freeze({
  absoluteMs: 30 * 86400e3,
  idleMs: 7 * 86400e3,
});

// The only session kinds 1.5 knows (§4.1; B6 design §7.5): the admin's sign-in with the
// password, and a wall display's, made from a one-time display code. A row with anything else
// (a later release's kinds and stages) is treated as unauthenticated: fail closed.
const kinds = Object.freeze({
  interactive: Object.freeze({ stage: 'full', via: 'password' }),
  kiosk: Object.freeze({ stage: 'full', via: 'display_code' }),
});
const known = Object.freeze({ kind: 'interactive', ...kinds.interactive });
// The transports a session is signed in over (lib/http/transport.mjs), recorded with it. A
// session is bound to the cookie of its transport: an `https` one travels only as the Secure
// cookie and the others never do, so a secret that crossed a network in clear (an `http`
// session) is never accepted as the Secure cookie, and turning GOBLIN_INSECURE_HTTP_SESSIONS off
// can end exactly the sessions it allowed (D16).
const transports = new Set(['https', 'loopback', 'http']);
const secureCookie = transport => transport === 'https';
const maxUserAgent = 256;
const maxLogin = 256;

/**
 * The most cookie values one sign-in, sign-out or rotation looks up (§19 G1). Every value a
 * request presents is looked up, not only the first one or two: a cookie of Uptime Goblin's name that
 * another site set (another port of the host, a parent domain, an injection over plain HTTP) is
 * sent beside the browser's own, and before it when its path is longer, so a small bound would
 * let a few such cookies push the browser's own session out of the revocation. 256 is more than
 * a browser can send within Node's 16 KiB header limit (and its own limit of about 180 cookies
 * a site), so the bound only caps the work a script can ask for.
 */
export const maxPresented = 256;

/** The token hashes of `values`, each once, malformed values left out, at most maxPresented. */
function presentedHashes(values) {
  const hashes = new Set();
  for (const value of Array.isArray(values) ? values : []) {
    if (hashes.size >= maxPresented) break;
    const hash = sessionTokenHash(value);
    if (hash) hashes.add(hash);
  }
  return [...hashes];
}

// A Set that refuses changes once built: access.permissions is shared by every access.
const sealedSets = new WeakSet();
class ReadonlySet extends Set {
  constructor(values) {
    super(values);
    sealedSets.add(this);
  }
  add(value) {
    if (sealedSets.has(this)) throw new TypeError('This permission set is read-only');
    return super.add(value);
  }
  delete() {
    throw new TypeError('This permission set is read-only');
  }
  clear() {
    throw new TypeError('This permission set is read-only');
  }
}
// The admin holds every permission the router knows. A wall display reads the dashboard and
// knows (and can end) its own session, nothing else: no configuration, no account, no change.
const adminPermissions = new ReadonlySet(routerPermissions);
// D7 option A: Basic retains display management, but never API-token administration.
const basicPermissions = new ReadonlySet(
  routerPermissions.filter(permission => !['tokens:manage', 'tokens:own'].includes(permission))
);
const kioskPermissions = new ReadonlySet(['dashboard:read', 'session:self']);

const refusal = message => Object.assign(new Error(message), { refusal: true });
const codePoints = text => {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
};
// Control characters stripped (they have no place in a list shown to the admin) and unpaired
// surrogates replaced (not storable as UTF-8), 256 characters at most.
const cleanUserAgent = value =>
  typeof value === 'string'
    ? [...value.toWellFormed().replace(/[\u0000-\u001f\u007f-\u009f]/g, '')]
        .slice(0, maxUserAgent)
        .join('') || null
    : null;
const cleanClient = value => (typeof value === 'string' && value ? value.slice(0, 64) : null);

// The actor of an audit row (audit spec D25): the admin, by session, by a wall display's session
// (`kiosk`, B6 design §2) or by Basic.
const actorOf = access => ({
  type: 'user',
  id: BUILTIN_ID,
  name: 'admin',
  via: access?.via === 'basic' ? 'basic' : access?.kind === 'kiosk' ? 'kiosk' : 'session',
  sessionId: access?.via === 'session' ? access.sessionId : null,
});
// The admin acting through the session `id`: a sign-in names the session it created, and a
// presented sign-out the session it ends (holding its cookie is what ends it, §5.1).
const sessionActor = (id, kind = 'interactive') => actorOf({ via: 'session', kind, sessionId: id });
const displayTarget = display => ({ type: 'display', id: display.id, name: display.name });
const anonymous = Object.freeze({
  type: 'anonymous',
  id: null,
  name: null,
  via: null,
  sessionId: null,
});
// Thrown inside a redemption's write when no waiting, unexpired code has the hash.
const noCode = Symbol('no display code');
// The owed cancellations recorded in one pass, at most (B6 design §16).
const owedPerPass = 20;
/**
 * An audit event with the request's facts (§5.1): the pipeline's frozen request names the
 * client, the user agent, the request id and the actor; without one (a test, a call outside a
 * request) the call's client and user agent and the access's actor. `fields` win over both.
 */
const eventOf = (request, { actor, client = null, userAgent = null }, fields) =>
  request ? eventFrom(request, fields) : { actor, client, userAgent, requestId: null, ...fields };

/**
 * Starts identity on the control database `control` (from startControl) for the data directory
 * `directory`, with `sources` from readBuiltinSources(): runs the bootstrap (import, restore,
 * mirror retry), tightens auth.json's mode and starts one hourly, unref'd prune timer. A start
 * without any admin password (none stored, and neither auth.json nor GOBLIN_PASSWORD) is refused
 * (exit 78, passwordRequiredMessage) before anything is written: Uptime Goblin always requires one.
 * `insecureHttpSessions` (GOBLIN_INSECURE_HTTP_SESSIONS=1) allows sessions signed in over plain
 * HTTP; without it, none is issued or accepted, and those a start with it left are deleted now.
 * `audit` is the audit recorder (lib/audit: createAudit() or noopAudit(); audit spec D23),
 * required so no start can run identity without one: every change identity makes records its
 * row in the write unit of that change (§5.1; see writeRecorded in bootstrap.mjs).
 * Options for tests: clock, derive (a deterministic KDF), limits, log, writeAuthRecord (replaces
 * the auth.json write, to make mirrors fail).
 */
export async function createIdentity({
  control,
  directory,
  sources,
  audit,
  insecureHttpSessions = false,
  displayLimits = defaultDisplayLimits,
  clock = Date.now,
  derive,
  limits: limitOptions = defaultLimits,
  log = console,
  writeAuthRecord = writeAuthFile,
} = {}) {
  const db = control?.db;
  if (!db || typeof db.read !== 'function' || typeof db.write !== 'function')
    throw new TypeError('createIdentity needs the control database (startControl().control)');
  if (db.name !== 'sqlite')
    throw refusal(
      'Uptime Goblin 1.5 keeps sign-in only in a SQLite control database (control.sqlite); PostgreSQL and SQL Server sign-in arrive in a later release.'
    );
  if (!sources || typeof sources !== 'object')
    throw new TypeError('createIdentity needs the sources readBuiltinSources() returned');
  if (typeof directory !== 'string' || !directory)
    throw new TypeError('createIdentity needs the data directory');
  // Checked after the database: a control database that is not SQLite is still refused first.
  if (typeof audit?.record !== 'function')
    throw new TypeError('createIdentity needs the audit recorder (createAudit() or noopAudit())');
  const limits = Object.freeze({ ...defaultLimits, ...limitOptions });
  const displays = Object.freeze({ ...defaultDisplayLimits, ...displayLimits });
  // The idle limit of a session row of `kind`.
  const idleOf = kind => (kind === 'kiosk' ? displays.idleMs : limits.idleMs);
  const info = message => (log.info ?? log.log)?.call(log, message);
  const warn = message => (log.warn ?? log.log)?.call(log, message);

  const hasher = createHasher(derive ? { derive } : {});
  // Which file control.sqlite is, so a restored backup of the data directory signs everyone
  // out (bootstrap.mjs). Unknown (no check) when the file cannot be read.
  const controlFile = typeof control.file === 'string' ? controlFileIdentity(control.file) : null;
  if (typeof control.file === 'string' && controlFile === null)
    warn(
      'Uptime Goblin could not read which file control.sqlite is, so it cannot tell whether the data directory was restored from a backup at this start; after restoring one, sign out the other devices under Configure → Account.'
    );
  const boot = await bootstrapBuiltin({
    db,
    directory,
    sources,
    hasher,
    clock,
    log,
    audit,
    writeAuthRecord,
    controlFile,
  });
  tightenAuthRecord(directory, { warn: (...args) => (log.warn ?? log.log)?.call(log, ...args) });
  // Turning GOBLIN_INSECURE_HTTP_SESSIONS off ends the sessions signed in over plain HTTP (D16):
  // their secrets crossed the network in clear, and otherwise they would keep working until
  // their absolute expiry on loopback, or as the Secure cookie through an https proxy. Best
  // effort: a row this cannot delete is still refused and not listed (plainRefused).
  if (!insecureHttpSessions) {
    try {
      // Recorded only when sessions ended; a full disk deletes them without the row (D32).
      const ended = await writeRecorded(
        db,
        audit,
        tx => {
          const result = identityOps.deleteSessionsOver(tx, 'http');
          return {
            result,
            events: result.length
              ? [
                  {
                    action: 'session.revoked',
                    outcome: 'info',
                    target: sessionTarget(null),
                    detail: { cause: 'insecure_http_off', count: result.length },
                  },
                ]
              : [],
          };
        },
        { fallback: true }
      );
      if (ended.length)
        info(
          `Signed out ${ended.length} session${ended.length === 1 ? '' : 's'} that signed in over plain HTTP: GOBLIN_INSECURE_HTTP_SESSIONS is off.`
        );
    } catch (error) {
      warn(
        `Uptime Goblin could not remove the sessions signed in over plain HTTP from control.sqlite (${error?.class || error?.code || 'error'}); they stay refused.`
      );
    }
  }

  // In-memory state. Only this process writes u_admin and its sessions (goblin.lock), so these
  // mirror the database; they change inside the write callbacks that commit their rows.
  let user = boot.user;
  let record = boot.record;
  let source = boot.source;
  let mirrorPending = boot.mirrorPending;
  // The in-process password generation: a Basic access, or a check in progress, from before a
  // change is no longer current. It only ever grows.
  let credential = 0;
  let changing = false;
  let closed = false;
  // Session ids this process revoked → their absolute expiry (entries then fall away in prune).
  const revoked = new Map();
  // Session id → a token for the revocation that entered it last. A write that SQLite rolled
  // back takes back only the marks it made itself (unmark), never one that a later, explicit
  // revocation (a sign-out during the retry wait) has claimed since.
  const revokedBy = new Map();
  const claim = (id, expiresAt) => {
    const token = Symbol('revocation');
    revoked.set(id, expiresAt);
    revokedBy.set(id, token);
    return token;
  };
  // Session ids this process has authenticated or issued and not revoked → {expiresAt,
  // authTime}, so "sign out other devices" can revoke every live access it may end
  // synchronously, before any await.
  const live = new Map();
  let lastTouchWarning = -Infinity;
  let mirroring = Promise.resolve();

  // bootstrapBuiltin refuses a start without a password, so `record` is never null here; a
  // check that finds no usable admin still signs nobody in (fail closed).
  const adminUsable = () =>
    Boolean(
      record &&
        user &&
        user.id === BUILTIN_ID &&
        user.login === 'admin' &&
        user.role === 'admin' &&
        user.kind === 'person' &&
        user.disabledAt === null
    );
  const principal = () =>
    Object.freeze({
      userId: BUILTIN_ID,
      login: 'admin',
      display: user?.displayName || 'Administrator',
      role: 'admin',
      kind: 'person',
      builtin: true,
    });
  const scopeOf = epoch => `user:${BUILTIN_ID}:${epoch}`;

  // Enters sessions in the revoked map; returns what this call added (so undoing it never
  // removes an entry another revocation made), with the live entry each one had.
  const mark = entries => {
    const added = [];
    for (const { id, expiresAt } of entries) {
      const known = live.get(id);
      live.delete(id);
      if (revoked.has(id)) {
        // Already refused: this revocation now owns the mark, so an earlier tentative one
        // (a rolled-back write's) can no longer take it back.
        revokedBy.set(id, Symbol('revocation'));
        continue;
      }
      added.push({ id, known, token: claim(id, expiresAt) });
    }
    return added;
  };
  // Takes back revocations whose write failed: those sessions are still in the database. A
  // mark claimed since by another revocation stays.
  const unmark = added => {
    for (const { id, known, token } of added) {
      if (revokedBy.get(id) !== token) continue;
      revoked.delete(id);
      revokedBy.delete(id);
      if (known) live.set(id, known);
    }
  };
  // The auth_time a session must not exceed for `access` to end it: its own session's; Basic
  // proves the password with every request, so it ends any; a wall display ends none.
  const rankOf = access =>
    access?.via === 'session'
      ? access.kind === 'kiosk'
        ? -Infinity
        : (access.session?.authTime ?? -Infinity)
      : Infinity;
  // A wall display may read the dashboard and end its own session, nothing else (B6 design §2),
  // whatever the route asked: the account methods refuse it.
  const refuseDisplay = access => {
    if (access?.kind === 'kiosk') throw identityError('forbidden');
  };
  // A new session's auth_time (inside the write that inserts it): now, but always after every
  // session of the user's, so a sign-in outranks each of them even if the clock went back.
  const nextAuthTime = (tx, now) => {
    const newest = identityOps.newestAuthTime(tx, BUILTIN_ID);
    return newest === null ? now : Math.max(now, newest + 1);
  };
  // A full disk is answered with storage_full (`variant` 'signout' for a revocation, whose
  // session stays refused in this process); any other failure is passed on as it is.
  const storageError = (error, variant) =>
    error?.class === 'full' ? identityError('storage_full', variant ? { variant } : {}) : error;
  // Thrown inside a login's write callback when a password change committed before it ran.
  const staleLogin = Symbol('stale login');

  function sessionAccess(row, { lastSeenAt, idleExpiresAt }) {
    const kiosk = row.kind === 'kiosk';
    live.set(
      row.id,
      Object.freeze({ expiresAt: row.expiresAt, authTime: row.authTime, kind: row.kind })
    );
    return Object.freeze({
      via: 'session',
      kind: row.kind,
      authenticated: true,
      verified: false,
      principal: principal(),
      permissions: kiosk ? kioskPermissions : adminPermissions,
      sessionId: row.id,
      session: Object.freeze({
        createdAt: row.createdAt,
        lastSeenAt,
        expiresAt: row.expiresAt,
        idleExpiresAt,
        persistent: row.persistent,
        // Not part of describe(): http shows a session signed in over plain HTTP as insecure
        // even when its later requests arrive another way (a proxy that sends no headers).
        transport: row.transport,
        // Not part of describe() either: which sessions this one may end (rankOf).
        authTime: row.authTime,
      }),
      epoch: user.epoch,
      credential,
      // A display's writes (only its sign-out) never share kept replies with the admin's.
      scope: kiosk ? `kiosk:${row.id}` : scopeOf(user.epoch),
    });
  }
  const basicAccess = (verified, generation) =>
    Object.freeze({
      via: 'basic',
      kind: 'basic',
      authenticated: true,
      verified,
      principal: principal(),
      permissions: basicPermissions,
      sessionId: null,
      session: null,
      epoch: user.epoch,
      credential: generation,
      scope: scopeOf(user.epoch),
    });

  // A fresh session row for u_admin (login, and the rotation of a password change).
  function sessionRow({ persistent, client, userAgent, now, transport }) {
    const issued = newSession();
    const expiresAt = now + (persistent ? limits.rememberMs : limits.absoluteMs);
    return {
      issued,
      row: {
        id: issued.id,
        tokenHash: issued.tokenHash,
        userId: BUILTIN_ID,
        kind: known.kind,
        stage: known.stage,
        via: known.via,
        transport,
        persistent,
        createdAt: now,
        authTime: now,
        lastSeenAt: now,
        idleExpiresAt: Math.min(now + limits.idleMs, expiresAt),
        expiresAt,
        clientKey: cleanClient(client),
        userAgent: cleanUserAgent(userAgent),
      },
    };
  }
  const issueOf = (row, value, now) =>
    Object.freeze({
      id: row.id,
      value,
      persistent: row.persistent,
      expiresAt: row.expiresAt,
      maxAgeSeconds: row.persistent ? Math.floor((row.expiresAt - now) / 1000) : null,
    });

  // A session signed in over plain HTTP while GOBLIN_INSECURE_HTTP_SESSIONS is not set.
  const plainRefused = row => row.transport === 'http' && !insecureHttpSessions;
  const usableRow = row =>
    row &&
    row.userId === BUILTIN_ID &&
    Object.hasOwn(kinds, row.kind) &&
    row.stage === kinds[row.kind].stage &&
    row.via === kinds[row.kind].via &&
    transports.has(row.transport);

  // Writes the stored password to auth.json, one mirror at a time (§5.7 mirror write). Resolves
  // 'ok', 'unrecorded' (auth.json written, its record not: see mirrorAuthRecord), 'failed' or
  // 'none'; never rejects: a password change awaits it after its commit, and a rejection there
  // answered 500 without the rotated cookie, so the browser was signed out of a change that had
  // gone through.
  function queueMirror() {
    const run = mirroring.then(async () => {
      if (!record || !mirrorPending) return 'none';
      const rowVersion = user.rowVersion;
      let result;
      try {
        result = await mirrorAuthRecord({
          db,
          directory,
          record,
          rowVersion,
          clock,
          writeAuthRecord,
        });
      } catch (error) {
        // mirrorAuthRecord resolves every failure it knows; anything else is still a failure.
        result = { ok: false, code: String(error?.class || error?.code || 'error').slice(0, 40) };
      }
      if (result.written) {
        // A rollback uses the current password, so no mirror is owed in this process: no banner,
        // no hourly rewrite (which, on a disk still full, would say auth.json was not updated).
        // The flag stays in control.sqlite until the next start adopts the file. Only while the
        // password written is still the current one: a change committed meanwhile owes its own
        // mirror, queued after this one.
        if (user.rowVersion === rowVersion) {
          warn(mirrorLines.unrecorded(result.code));
          mirrorPending = false;
          source = 'auth.json';
        }
        return 'unrecorded';
      }
      if (!result.ok) {
        warn(mirrorLines.failed(result.code));
        await recordSystem(audit, mirrorFailedEvent(result.code));
        return 'failed';
      }
      if (result.recorded) {
        mirrorPending = false;
        source = 'auth.json';
      }
      return 'ok';
    });
    mirroring = run.catch(() => {});
    return run;
  }

  /**
   * The write of a sign-out or revocation (audit spec §5.1, D32): `change(tx)` deletes and
   * returns {result, events}, recorded in its unit; on a full disk the delete is made alone, its
   * rows going to audit.unrecorded(). When even that fails, `failed` (session.logout rows of a
   * sign-out) is recorded through audit.system(), best effort, and the answer is storage_full
   * (variant signout: the sessions stay refused in this process until prune or flushRevoked).
   */
  async function endSessions(change, { failed = [] } = {}) {
    try {
      return await writeRecorded(db, audit, change, { fallback: true });
    } catch (error) {
      if (error?.class === 'full') for (const event of failed) await recordSystem(audit, event);
      throw storageError(error, 'signout');
    }
  }

  // Why `access` no longer signs in (the error assertCurrent throws), or null while it does.
  const endedBy = access => {
    try {
      service.assertCurrent(access);
      return null;
    } catch (error) {
      return error;
    }
  };
  // Deletes the sessions of `ids` in the unit `tx`, one by one; returns the ids of those whose
  // row it removed (one another sign-out or prune removed meanwhile is left out).
  const deleteEach = (tx, ids) =>
    ids.filter(sessionId => identityOps.deleteSessions(tx, [sessionId]) > 0);
  // The row of sessions a revocation signed out while its access was current, deleted once that
  // access had ended (see endedPartWay): Uptime Goblin removing them, never a revocation by the access
  // that ended. `removed`: deleteEach's ids. Its target, as in every session.revoked row, is the
  // session that was ended: named when the delete removed only one (also when it was deleting
  // more and the others had gone meanwhile, so the one it removed is in a row), otherwise none,
  // as in the other rows that count the sessions they removed. The access that ended is named
  // neither as actor nor as target (a target filter for it must not read it as revoked).
  // Its own cause: flushRevoked's 'retried' says an earlier delete failed, which none did here.
  const removedEvent = removed => ({
    action: 'session.revoked',
    outcome: 'info',
    target: sessionTarget(removed.length === 1 ? removed[0] : null),
    detail: { cause: 'ended_part_way', count: removed.length },
  });

  /**
   * Ends a revocation whose own access ended during its awaits (a sign-out, a revocation or a
   * password change elsewhere), rejecting with `refusal` (endedBy's). The sessions of `ids`,
   * which it signed out in memory while it was still current, stay signed out: their rows are
   * deleted now (a restart forgets the in-memory mark), recorded as removedEvent. Nothing else is
   * read, deleted or recorded for the access that ended. A delete that fails leaves the marks to
   * prune and flushRevoked; the answer is still the refusal.
   */
  async function endedPartWay(ids, refusal) {
    if (ids.length)
      try {
        await endSessions(tx => {
          const removed = deleteEach(tx, ids);
          return {
            result: removed.length,
            events: removed.length ? [removedEvent(removed)] : [],
          };
        });
      } catch {}
    throw refusal;
  }

  const service = {
    get limits() {
      return limits;
    },

    status() {
      return {
        source,
        mirrorPending,
        importedAtStart: boot.importedAtStart,
        restoredAtStart: boot.restoredAtStart,
      };
    },

    /**
     * The access of the session whose cookie value is `value`, or null (unknown, malformed,
     * expired, revoked, or not a session 1.5 understands). `transport` is the request's: the
     * value must come as the cookie of the transport the session was signed in over (the
     * Secure one only for `https`), and a plain-HTTP session needs GOBLIN_INSECURE_HTTP_SESSIONS.
     * `activity: 'background'` (polls) never extends the idle limit; last_seen_at and
     * idle_expires_at are written at most once a minute, in one UPDATE, and a failed write
     * never fails the request.
     */
    async authenticateSession(value, { activity = 'foreground', transport = 'https' } = {}) {
      const tokenHash = sessionTokenHash(value);
      if (!tokenHash || !adminUsable()) return null;
      const row = await db.read(tx => identityOps.sessionByHash(tx, tokenHash));
      if (!usableRow(row) || revoked.has(row.id) || !adminUsable()) return null;
      if (secureCookie(row.transport) !== secureCookie(transport) || plainRefused(row)) return null;
      const now = clock();
      if (now >= row.expiresAt || now >= row.idleExpiresAt) {
        live.delete(row.id);
        // Best effort: prune removes it otherwise.
        db.write(tx => identityOps.deleteSessions(tx, [row.id])).catch(() => {});
        return null;
      }
      const touch = {};
      if (now - row.lastSeenAt >= limits.touchMs) touch.lastSeenAt = now;
      const extended = Math.min(now + idleOf(row.kind), row.expiresAt);
      // A wall display's every request is use (B6 design §7.5): it has nobody to click, and its
      // idle limit is days, so an unplugged display ends while a working one stays signed in.
      const foreground = activity === 'foreground' || row.kind === 'kiosk';
      if (foreground && extended - row.idleExpiresAt >= limits.touchMs)
        touch.idleExpiresAt = extended;
      let lastSeenAt = row.lastSeenAt,
        idleExpiresAt = row.idleExpiresAt;
      if (touch.lastSeenAt !== undefined || touch.idleExpiresAt !== undefined) {
        try {
          const changes = await db.write(tx => identityOps.touchSession(tx, row.id, touch));
          // Gone meanwhile (revoked, evicted, pruned): not a session any more.
          if (changes !== 1) return null;
          lastSeenAt = touch.lastSeenAt ?? lastSeenAt;
          idleExpiresAt = touch.idleExpiresAt ?? idleExpiresAt;
        } catch (error) {
          // A full or failing disk must not sign anyone out: the stored values still hold.
          if (now - lastTouchWarning >= 60e3) {
            lastTouchWarning = now;
            warn(
              `Uptime Goblin could not record sign-in activity in control.sqlite (${error?.class || error?.code || 'error'}); sessions stay valid.`
            );
          }
        }
      }
      if (revoked.has(row.id) || !adminUsable()) return null;
      return sessionAccess(row, { lastSeenAt, idleExpiresAt });
    },

    /**
     * Verifies a legacy Basic credential (`bytes` = 'admin:<password>'; the caller keeps and
     * zero-fills it). Resolves an access or null; may reject with `busy`.
     */
    async authenticateBasic(bytes, { admit } = {}) {
      if (!Buffer.isBuffer(bytes)) return null;
      const result = await basic.check(bytes, { admit });
      if (!result || !adminUsable()) return null;
      return basicAccess(result.verified, result.generation);
    },

    /** True when `bytes` carry a password replaced in this process within retiredMs. */
    isRetiredBasic(bytes) {
      return Buffer.isBuffer(bytes) && basic.isRetired(bytes);
    },

    /**
     * Signs in (§5.10). One derivation whatever the input (a wrong name costs a dummy one, T2),
     * then one write: the least recently seen sessions beyond the cap are evicted, the sessions
     * of `replacing` (every cookie value the request presented, under either name, at most
     * maxPresented) are deleted when they are u_admin's (rotation: no fixation; a cookie another
     * site set beside the browser's own cannot keep it out), the new session is inserted, bound
     * to `transport` (the one http issues its cookie for; `http` only with
     * GOBLIN_INSECURE_HTTP_SESSIONS), and its `session.login` row recorded in the same write
     * (audit spec §5.1; a refusal records nothing here: the route counts it, §5.2). `request`:
     * the pipeline's facts, for the row. Resolves {access, issue}.
     */
    async login(
      {
        login,
        password,
        remember,
        client,
        userAgent,
        replacing = [],
        admit,
        transport = 'https',
      } = {},
      { request } = {}
    ) {
      if (
        typeof login !== 'string' ||
        !login ||
        codePoints(login) > maxLogin ||
        typeof password !== 'string' ||
        (remember !== undefined && typeof remember !== 'boolean') ||
        !transports.has(transport)
      )
        throw identityError('invalid_request', { variant: 'login' });
      if (transport === 'http' && !insecureHttpSessions) throw identityError('https_required');
      const name = login.normalize('NFKC').trim().toLowerCase();
      const bytes = Buffer.from(password, 'utf8');
      const generation = credential;
      let release, ok;
      try {
        release = admit?.();
        ok =
          name === 'admin' && bytes.length <= maxPasswordBytes && adminUsable()
            ? await verifyRecord(hasher, record, bytes)
            : await verifyDummy(hasher, bytes);
      } finally {
        release?.();
        bytes.fill(0);
      }
      // A check that started before a password change proves only the old password.
      const refused = () => identityError('invalid_credentials', { variant: 'login' });
      const stale = () => generation !== credential || !adminUsable();
      if (!ok || stale()) throw refused();
      const now = clock();
      const persistent = remember === true;
      const { issued, row } = sessionRow({ persistent, client, userAgent, now, transport });
      const replaced = presentedHashes(replacing);
      let added = [];
      try {
        await db.write(tx => {
          // A retried attempt starts from a rolled-back database: undo the last attempt's marks.
          unmark(added);
          added = [];
          // Checked again here, synchronously with the COMMIT: db.write runs this callback
          // again after an asynchronous wait when it meets SQLITE_BUSY, and a password change
          // that committed during that wait leaves this check proving only the old password.
          if (stale()) throw staleLogin;
          row.authTime = nextAuthTime(tx, now);
          const gone = (replaced.length ? identityOps.sessionsByHashes(tx, replaced) : [])
            .filter(old => old.userId === BUILTIN_ID)
            .map(old => ({ id: old.id, expiresAt: old.expiresAt }));
          identityOps.deleteSessions(
            tx,
            gone.map(old => old.id)
          );
          gone.push(...identityOps.evictSessions(tx, BUILTIN_ID, limits.maxSessions - 1));
          identityOps.insertSession(tx, row);
          identityOps.setLastLogin(tx, BUILTIN_ID, now);
          // The row names the new session, which acts from now on; `ended` counts the sessions
          // it rotated and those the cap evicted.
          audit.record(
            tx,
            eventOf(
              request,
              { client: row.clientKey, userAgent: row.userAgent },
              {
                action: 'session.login',
                outcome: 'ok',
                at: now,
                actor: sessionActor(row.id),
                target: sessionTarget(row.id),
                detail: { persistent, transport, ended: gone.length },
              }
            )
          );
          added = mark(gone);
        });
      } catch (error) {
        unmark(added);
        if (error === staleLogin) throw refused();
        throw storageError(error);
      }
      user = { ...user, lastLoginAt: now };
      return {
        access: sessionAccess(row, { lastSeenAt: now, idleExpiresAt: row.idleExpiresAt }),
        issue: issueOf(row, issued.value, now),
      };
    },

    /**
     * Signs a wall display in with a one-time display code (B6 design §7.4). The code is checked
     * for shape first (invalid_request variant display_code: not looked up). Then one write:
     * the waiting, unexpired code is claimed for the new session (two redemptions of one code:
     * one wins), the presented sessions are rotated and the cap applied as at a sign-in, the
     * kiosk session is inserted (persistent, GOBLIN_DISPLAY_SESSION_DAYS absolute and
     * GOBLIN_DISPLAY_IDLE_DAYS idle) and its `session.login` row recorded, all in one unit. A code
     * that claims nothing rejects with display_code_invalid; its `stale` is true when the code
     * is known (expired, used or cancelled: no guess, so not counted) and false when it is not.
     * Resolves {access, issue, display: {id, name}}.
     */
    async redeemDisplayCode(
      { code, client, userAgent, replacing = [], transport = 'https' } = {},
      { request } = {}
    ) {
      if (!transports.has(transport))
        throw identityError('invalid_request', { variant: 'display' });
      if (transport === 'http' && !insecureHttpSessions)
        throw identityError('https_required', { variant: 'display_code' });
      const codeHash = displayCodeHash(code);
      if (!codeHash) throw identityError('invalid_request', { variant: 'display_code' });
      const refused = stale => Object.assign(identityError('display_code_invalid'), { stale });
      if (!adminUsable()) throw refused(false);
      const now = clock();
      const issued = newSession();
      const expiresAt = now + displays.absoluteMs;
      const row = {
        id: issued.id,
        tokenHash: issued.tokenHash,
        userId: BUILTIN_ID,
        kind: 'kiosk',
        stage: kinds.kiosk.stage,
        via: kinds.kiosk.via,
        transport,
        persistent: true,
        createdAt: now,
        authTime: now,
        lastSeenAt: now,
        idleExpiresAt: Math.min(now + displays.idleMs, expiresAt),
        expiresAt,
        clientKey: cleanClient(client),
        userAgent: cleanUserAgent(userAgent),
      };
      const replaced = presentedHashes(replacing);
      let added = [],
        display = null,
        stale = false;
      try {
        await db.write(tx => {
          unmark(added);
          added = [];
          display = null;
          stale = false;
          if (!adminUsable()) throw staleLogin;
          if (
            identityOps.claimDisplay(tx, codeHash, {
              sessionId: row.id,
              now,
              client: row.clientKey,
            }) !== 1
          ) {
            stale = identityOps.displayByHash(tx, codeHash) !== null;
            throw noCode;
          }
          display = identityOps.displayByHash(tx, codeHash);
          row.authTime = nextAuthTime(tx, now);
          const gone = (replaced.length ? identityOps.sessionsByHashes(tx, replaced) : [])
            .filter(old => old.userId === BUILTIN_ID)
            .map(old => ({ id: old.id, expiresAt: old.expiresAt }));
          identityOps.deleteSessions(
            tx,
            gone.map(old => old.id)
          );
          gone.push(...identityOps.evictSessions(tx, BUILTIN_ID, limits.maxSessions - 1));
          identityOps.insertSession(tx, row);
          audit.record(
            tx,
            eventOf(
              request,
              { client: row.clientKey, userAgent: row.userAgent },
              {
                action: 'session.login',
                outcome: 'ok',
                at: now,
                actor: sessionActor(row.id, 'kiosk'),
                target: sessionTarget(row.id),
                detail: {
                  kind: 'kiosk',
                  display: display.id,
                  persistent: true,
                  transport,
                  ended: gone.length,
                },
              }
            )
          );
          added = mark(gone);
        });
      } catch (error) {
        unmark(added);
        if (error === noCode) throw refused(stale);
        if (error === staleLogin) throw refused(false);
        throw storageError(error);
      }
      return {
        access: sessionAccess(row, { lastSeenAt: now, idleExpiresAt: row.idleExpiresAt }),
        issue: issueOf(row, issued.value, now),
        display: { id: display.id, name: display.name },
      };
    },

    /**
     * Cancels the waiting, unexpired display code `code` (B6 design §7.4, R2A-6): a sign-in that
     * carried it was refused for its transport, so the code may have crossed a network in clear.
     * Best effort: one read by hash, and a unit only for a live code, recording
     * `display.code.cancelled` (anonymous; on a full disk the cancel alone). Resolves whether a
     * code was cancelled; never rejects.
     */
    async cancelDisplayCode(code, { cause = 'plain_http' } = {}, { request } = {}) {
      const codeHash = displayCodeHash(code);
      if (!codeHash) return false;
      try {
        const now = clock();
        const found = await db.read(tx => identityOps.displayByHash(tx, codeHash));
        if (!found || found.state !== 'waiting' || found.codeExpiresAt <= now) return false;
        const cancelled = await writeRecorded(
          db,
          audit,
          tx => {
            const rows = identityOps.cancelDisplays(tx, { codeHash, cause, now });
            return {
              result: rows,
              events: rows.map(display =>
                eventOf(
                  request,
                  { actor: anonymous },
                  {
                    action: 'display.code.cancelled',
                    outcome: 'ok',
                    at: now,
                    actor: anonymous,
                    target: displayTarget(display),
                    detail: { cause },
                  }
                )
              ),
            };
          },
          { fallback: true }
        );
        return cancelled.length > 0;
      } catch {
        return false;
      }
    },

    /**
     * Signs the access's session out: its row is deleted, and its id is revoked before the
     * write starts, so the access fails assertCurrent() at once, and stays revoked (fail closed)
     * even when the delete fails. A failed delete rejects (storage_full on a full disk), so the
     * caller can say the sign-out was not recorded: the row is still in control.sqlite, and
     * only this process refuses it until the hourly prune or the stop (flushRevoked) deletes
     * it. No-op for Basic.
     * `also`: cookie values of other sessions the same browser presented (on https, every
     * plain-HTTP cookie value: the one a sign-in over the opt-in left, beside any another site
     * set; at most maxPresented); those that are u_admin's are signed out too, as a sign-in
     * replaces them, since their secret crossed the network in clear and expiring the cookie
     * alone would leave them usable by anyone who captured it. They are looked up and revoked
     * before the delete, as above.
     * The delete records `session.logout` (and `session.revoked` per other session) in its unit
     * for each session it ended (audit spec §5.1); `request`: the pipeline's facts, for the rows.
     */
    async logout(access, { also = [], request } = {}) {
      if (access?.via !== 'session' || !isSessionId(access.sessionId)) return;
      const id = access.sessionId;
      mark([{ id, expiresAt: access.session?.expiresAt ?? clock() + limits.rememberMs }]);
      const hashes = presentedHashes(also);
      const others = (
        hashes.length ? await db.read(tx => identityOps.sessionsByHashes(tx, hashes)) : []
      )
        .filter(row => row.userId === BUILTIN_ID && row.id !== id)
        .map(row => ({ id: row.id, expiresAt: row.expiresAt }));
      mark(others);
      const by = { actor: actorOf(access) };
      const signedOut = (outcome, detail) =>
        eventOf(request, by, {
          action: 'session.logout',
          outcome,
          target: sessionTarget(id),
          detail,
        });
      await endSessions(
        tx => {
          // Only the sessions this delete ended are recorded: one that another sign-out removed
          // meanwhile was ended, and recorded, by that one (as revokeSession).
          const ends = sessionId => identityOps.deleteSessions(tx, [sessionId]) > 0;
          return {
            events: [
              ...(ends(id) ? [signedOut('ok', { cause: 'signout' })] : []),
              ...others
                .filter(row => ends(row.id))
                .map(row =>
                  eventOf(request, by, {
                    action: 'session.revoked',
                    outcome: 'ok',
                    target: sessionTarget(row.id),
                    detail: { cause: 'insecure_cookie' },
                  })
                ),
            ],
          };
        },
        { failed: [signedOut('failed', { code: 'storage_full' })] }
      );
    },

    /**
     * Signs out the u_admin sessions whose cookie values are among `values` (at most
     * maxPresented), for a sign-out that cannot tell which one is the browser's own: it sent
     * two or more cookies of Uptime Goblin's name, one of them set by another site (§19 G1). Holding a
     * session's secret is enough to end that session (as a sign-out with it would), so nothing
     * else is checked and no other session can be reached. The rows are read first, then
     * revoked before the delete (fail closed, as logout). Resolves the number of sessions
     * ended (by this, or by another sign-out after the read); a failed delete rejects
     * (storage_full on a full disk).
     * Each session the delete ended records `session.logout` in its unit, with itself as the
     * actor (the request is not signed in; holding the session's cookie is what ends it) and
     * `cause` ('presented', or 'ended' for a session that had already ended elsewhere), in the
     * order the values were presented (audit spec §5.1).
     */
    async revokePresented(values, { cause = 'presented', request } = {}) {
      // `cause` is recorded as passed, never checked here: a wrong one is a defect of the row,
      // which must not leave the sign-out undone (D32).
      const hashes = presentedHashes(values);
      if (!hashes.length) return 0;
      const order = new Map(hashes.map((hash, index) => [hash, index]));
      const rows = (await db.read(tx => identityOps.sessionsByHashes(tx, hashes)))
        .filter(row => row.userId === BUILTIN_ID)
        .sort((a, b) => order.get(a.tokenHash) - order.get(b.tokenHash));
      if (!rows.length) return 0;
      mark(rows.map(row => ({ id: row.id, expiresAt: row.expiresAt })));
      const signedOut = (row, outcome, detail) =>
        eventOf(
          request,
          {},
          {
            action: 'session.logout',
            outcome,
            actor: sessionActor(row.id),
            target: sessionTarget(row.id),
            detail,
          }
        );
      await endSessions(
        tx => {
          // Only the sessions this delete ended: one another sign-out removed after the read
          // above was ended, and recorded, by that one.
          const ended = rows.filter(row => identityOps.deleteSessions(tx, [row.id]) > 0);
          return { events: ended.map(row => signedOut(row, 'ok', { cause })) };
        },
        { failed: rows.map(row => signedOut(row, 'failed', { code: 'storage_full' })) }
      );
      return rows.length;
    },

    /** How many wall displays are signed in now (for the start line after an upgrade). */
    async signedInDisplays() {
      const rows = await db.read(tx => identityOps.userSessions(tx, BUILTIN_ID));
      const now = clock();
      return rows.filter(
        row =>
          row.kind === 'kiosk' &&
          usableRow(row) &&
          !revoked.has(row.id) &&
          now < row.expiresAt &&
          now < row.idleExpiresAt
      ).length;
    },

    /**
     * u_admin's unexpired sessions: the access's own first, then the most recently seen.
     * `newer`: signed in after the access's own session, which therefore cannot end it.
     */
    async listSessions(access) {
      refuseDisplay(access);
      // Wall displays are listed with the name their code was created with.
      const { rows, names } = await db.read(tx => {
        const rows = identityOps.userSessions(tx, BUILTIN_ID);
        const kiosks = rows.filter(row => row.kind === 'kiosk').map(row => row.id);
        const names = new Map(
          (kiosks.length ? identityOps.displaysForSessions(tx, kiosks) : []).map(display => [
            display.sessionId,
            display.name,
          ])
        );
        return { rows, names };
      });
      const now = clock();
      const current = access?.via === 'session' ? access.sessionId : null;
      const mine = rankOf(access);
      return rows
        .filter(
          row =>
            usableRow(row) &&
            !plainRefused(row) &&
            !revoked.has(row.id) &&
            now < row.expiresAt &&
            now < row.idleExpiresAt
        )
        .map(row => ({
          id: row.id,
          kind: row.kind,
          display: row.kind === 'kiosk' ? (names.get(row.id) ?? null) : null,
          current: row.id === current,
          // Any session may end a wall display (B6 design §7.5).
          newer: row.id !== current && row.kind !== 'kiosk' && row.authTime > mine,
          createdAt: row.createdAt,
          lastSeenAt: row.lastSeenAt,
          expiresAt: row.expiresAt,
          idleExpiresAt: row.idleExpiresAt,
          persistent: row.persistent,
          client: row.clientKey,
          userAgent: row.userAgent,
        }))
        .sort((a, b) => Number(b.current) - Number(a.current) || b.lastSeenAt - a.lastSeenAt);
    },

    /**
     * Signs out the session `id` of u_admin. Resolves {found, current}; rejects with
     * `session_newer` for a session that signed in after the access's own (see rankOf). A
     * session this process knows is revoked before the first await (like logout); an unknown
     * id is looked up first. A session revoked before by a delete that failed (refused only in
     * this process) is still found while its row exists, and its delete is tried again: a
     * retry tells the truth. `session.revoked` is recorded in the unit of the delete, only when
     * that delete removed the row (audit spec §5.1); `request`: the pipeline's facts. An access
     * that had ended before the call (unless `id` is its own session) rejects as assertCurrent
     * does, having ended nothing; one that ended during the lookup or before the delete rejects
     * the same way, having ended only what it signed out while still current (endedPartWay).
     */
    async revokeSession(access, id, { request } = {}) {
      // Ending its own session is the one thing an access that ended may still finish: that is
      // what it asked.
      refuseDisplay(access);
      const own = access?.via === 'session' && access.sessionId === id;
      // An access that had already ended when this was called (signed out while the route
      // waited for its request's body, say) decides nothing: nothing is signed out, deleted or
      // recorded for it.
      const before = own ? null : endedBy(access);
      if (before) throw before;
      if (!isSessionId(id)) return { found: false, current: false };
      const mine = rankOf(access);
      // A session with a live access in this process is revoked before the first await, like
      // logout; if the lookup then fails, it stays revoked (fail closed).
      const known = live.get(id);
      const early = Boolean(known && (known.kind === 'kiosk' || known.authTime <= mine));
      if (early) mark([{ id, expiresAt: known.expiresAt }]);
      const row = await db.read(tx => identityOps.session(tx, id));
      // Signed out, revoked or its password changed during the lookup: it decides nothing more.
      const ended = own ? null : endedBy(access);
      if (ended) return endedPartWay(early ? [id] : [], ended);
      const now = clock();
      if (!usableRow(row) || now >= row.expiresAt || now >= row.idleExpiresAt)
        return { found: false, current: false };
      // A newer session is refused, unless it was signed out here already by one that could
      // (its delete failed): then only the delete is left to do, which any session may finish.
      // A wall display proves no password, so any session may end it.
      if (row.kind !== 'kiosk' && row.authTime > mine && !revoked.has(id))
        throw identityError('session_newer');
      live.delete(id);
      claim(id, row.expiresAt);
      let refusal = null;
      const deleted = await endSessions(tx => {
        const count = identityOps.deleteSessions(tx, [id]);
        // Checked again in the unit, after the write's own wait for its turn: an access that
        // ended meanwhile still deletes the session it signed out while current, but the row
        // is Uptime Goblin's removal (removedEvent), never a revocation by the ended access.
        refusal = own ? null : endedBy(access);
        return {
          result: count,
          events: !count
            ? []
            : refusal
              ? [removedEvent([id])]
              : [
                  eventOf(
                    request,
                    { actor: actorOf(access) },
                    {
                      action: 'session.revoked',
                      outcome: 'ok',
                      target: sessionTarget(id),
                      detail: { cause: 'by_user' },
                    }
                  ),
                ],
        };
      });
      if (refusal) throw refusal;
      // Gone meanwhile (another sign-out, prune): not found by this one, and not recorded.
      if (!deleted) return { found: false, current: false };
      return { found: true, current: access?.via === 'session' && access.sessionId === id };
    },

    /**
     * Signs out every u_admin session except the access's own that signed in no later than it
     * (all of them for Basic; see rankOf). Every live access this process knows of
     * those is revoked before the first await; the rows are then read and exactly those are
     * deleted. Resolves {revoked: the number of rows deleted, kept: the other sessions still
     * signed in because they signed in after this one}. `session.revoked-others` is recorded in
     * the unit of the delete when it ended any (audit spec §5.1); `request`: the pipeline's facts.
     * An access that had ended before the call rejects as assertCurrent does, having ended
     * nothing. One that ended during the read or before the delete rejects the same way, having
     * ended only what it signed out while still current (endedPartWay): the live sessions it
     * marked first, or, once past the read, the sessions it was deleting.
     */
    async revokeOtherSessions(access, { request } = {}) {
      refuseDisplay(access);
      // An access that had already ended when this was called decides nothing (see
      // revokeSession): no session is signed out for it, not even one live here.
      const before = endedBy(access);
      if (before) throw before;
      const keep = access?.via === 'session' ? access.sessionId : null;
      const mine = rankOf(access);
      // Every wall display ends too, whenever it signed in (B6 design §7.5).
      const early = [...live]
        .filter(([id, known]) => id !== keep && (known.kind === 'kiosk' || known.authTime <= mine))
        .map(([id, known]) => ({ id, expiresAt: known.expiresAt }));
      mark(early);
      const rows = await db.read(tx => identityOps.userSessions(tx, BUILTIN_ID));
      // Signed out, revoked or its password changed during the read: the rows it read decide
      // nothing (older sessions this process has not seen live are not deleted for it).
      const ended = endedBy(access);
      if (ended)
        return endedPartWay(
          early.map(entry => entry.id),
          ended
        );
      const now = clock();
      // Every other unexpired session it may end: those the list shows, and those signed out
      // before by a delete that failed (an earlier try of this, a sign-out; whoever ended
      // them), which this process refuses but a restart would accept again, so their rows go
      // now and are counted. Expired rows are refused after a restart too; prune removes them.
      const unexpired = rows.filter(
        row => row.id !== keep && usableRow(row) && now < row.expiresAt && now < row.idleExpiresAt
      );
      const others = unexpired.filter(
        row => row.kind === 'kiosk' || row.authTime <= mine || revoked.has(row.id)
      );
      // Those the list shows as signed in after this one.
      const kept = unexpired.filter(
        row =>
          row.kind !== 'kiosk' && row.authTime > mine && !revoked.has(row.id) && !plainRefused(row)
      ).length;
      if (!others.length) return { revoked: 0, kept };
      mark(others.map(row => ({ id: row.id, expiresAt: row.expiresAt })));
      let refusal = null;
      const count = await endSessions(tx => {
        const removed = deleteEach(
          tx,
          others.map(row => row.id)
        );
        const ended = removed.length;
        // Checked again in the unit, after the write's own wait for its turn: the sessions
        // marked above were signed out while this access was current, so they are deleted
        // either way, but an access that ended meanwhile gets no row of its own (removedEvent).
        refusal = endedBy(access);
        return {
          result: ended,
          // Nothing recorded when every one had gone meanwhile: nothing was ended.
          events: !ended
            ? []
            : refusal
              ? [removedEvent(removed)]
              : [
                  eventOf(
                    request,
                    { actor: actorOf(access) },
                    {
                      action: 'session.revoked-others',
                      outcome: 'ok',
                      target: accountTarget,
                      detail: { count: ended, kept },
                    }
                  ),
                ],
        };
      });
      if (refusal) throw refusal;
      return { revoked: count, kept };
    },

    /**
     * Changes the admin password (§5.12): the current password is required; one write with a
     * compare-and-swap on row_version stores the new record, deletes every other session and,
     * for a session access, replaces the current one (new id, new secret, same persistence);
     * then auth.json is mirrored. The epoch stays: this change revokes the others explicitly.
     * The write records `account.password.changed` (audit spec §5.1): the access's own session
     * acted (the old id), the rotated one is `newSessionId`; a refusal records nothing here (the
     * route counts it, §5.2). `request`: the pipeline's facts, for the row.
     * Resolves {issue (session access only), revokedOtherSessions, mirrorPending}.
     */
    async changePassword(access, input, { client, userAgent, request } = {}) {
      if (!access?.authenticated) throw identityError('signin_required');
      refuseDisplay(access);
      if (changing) throw identityError('change_in_progress');
      changing = true;
      let current, next;
      try {
        service.assertCurrent(access);
        const password = checkNewPassword(input);
        current = Buffer.from(input.currentPassword, 'utf8');
        // Step-up: a borrowed session alone cannot take over the login.
        if (!(await verifyRecord(hasher, record, current)))
          throw identityError('current_password_incorrect');
        service.assertCurrent(access);
        const now = clock();
        next = Buffer.from(password, 'utf8');
        const candidate = await makeRecord(hasher, next, now);
        service.assertCurrent(access);

        const rotate = access.via === 'session';
        const fresh = rotate
          ? sessionRow({
              persistent: access.session.persistent,
              client,
              userAgent,
              now,
              // The rotated session keeps the cookie the browser holds.
              transport: access.session.transport,
            })
          : null;
        const before = { user, record };
        const generation = credential;
        const expectedRowVersion = user.rowVersion;
        let added = [],
          others = 0,
          bumped = false;
        // Undoes what an attempt of the write callback did in memory, for a retry after SQLite
        // rolled it back (SQLITE_BUSY) and for a final failure.
        const undo = () => {
          unmark(added);
          added = [];
          ({ user, record } = before);
          if (bumped && credential === generation + 1) credential = generation;
          bumped = false;
        };
        try {
          await db.write(tx => {
            undo();
            // The write may run only after a busy wait (SQLite retries after a jittered delay),
            // and this request's authority can end during it: a sign-out, an expiry or another
            // password change. Check at the write itself, synchronously, after undoing what a
            // rolled-back attempt changed in memory, so a valid retry is not refused by the
            // credential generation its own earlier attempt advanced.
            service.assertCurrent(access);
            if (
              !identityOps.setPassword(tx, BUILTIN_ID, {
                password: candidate,
                passwordChangedAt: now,
                now,
                rowVersion: expectedRowVersion,
              })
            )
              throw identityError('change_in_progress');
            // The change proves the password, as a sign-in does.
            if (fresh) fresh.row.authTime = nextAuthTime(tx, now);
            const gone = identityOps.deleteUserSessions(tx, BUILTIN_ID);
            others = gone.filter(row => row.id !== access.sessionId).length;
            if (fresh) identityOps.insertSession(tx, fresh.row);
            identityOps.setSetting(tx, keys.mirrorPending, '1', now);
            audit.record(
              tx,
              eventOf(
                request,
                {
                  actor: actorOf(access),
                  client: cleanClient(client),
                  userAgent: cleanUserAgent(userAgent),
                },
                {
                  action: 'account.password.changed',
                  outcome: 'ok',
                  at: now,
                  target: accountTarget,
                  detail: { revokedOtherSessions: others, newSessionId: fresh?.row.id ?? null },
                  // The time stored above: the start's drift check sees this change as recorded.
                  meta: { audit_password_changed_at: String(now) },
                }
              )
            );
            // Wall displays ended with every other session above; the codes still waiting go
            // too, so nobody holding one from before the change can sign a display in.
            const cancelled = identityOps.cancelDisplays(tx, { cause: 'password_change', now });
            if (cancelled.length)
              audit.record(
                tx,
                eventOf(
                  request,
                  { actor: actorOf(access) },
                  {
                    action: 'display.code.cancelled',
                    outcome: 'info',
                    at: now,
                    target: accountTarget,
                    detail: { cause: 'password_change', count: cancelled.length },
                  }
                )
              );
            // The last statement ran: from here no continuation may see the old state.
            if (credential === generation) {
              credential += 1;
              bumped = true;
            }
            added = mark(gone);
            user = {
              ...before.user,
              passwordChangedAt: now,
              updatedAt: now,
              rowVersion: expectedRowVersion + 1,
            };
            record = candidate;
          });
        } catch (error) {
          undo();
          throw storageError(error);
        }
        mirrorPending = true;
        basic.passwordChanged(current, next);
        await queueMirror();
        return {
          issue: fresh ? issueOf(fresh.row, fresh.issued.value, now) : null,
          revokedOtherSessions: others,
          mirrorPending,
        };
      } finally {
        current?.fill(0);
        next?.fill(0);
        changing = false;
      }
    },

    /**
     * The identity part of GET /api/session (§6.11). A wall display learns only that it is one,
     * what it may do and its session's times (B6 design §7.5): not who the admin is, nor
     * whether auth.json owes the password.
     */
    describe(access) {
      const p = access.principal;
      if (access.kind === 'kiosk')
        return {
          user: null,
          via: 'session',
          kind: 'kiosk',
          permissions: [...access.permissions].sort(),
          session: {
            id: access.sessionId,
            createdAt: access.session.createdAt,
            lastSeenAt: access.session.lastSeenAt,
            expiresAt: access.session.expiresAt,
            idleExpiresAt: access.session.idleExpiresAt,
            persistent: true,
          },
          mirrorPending: false,
        };
      return {
        kind: access.kind ?? (access.via === 'basic' ? 'basic' : 'interactive'),
        user: {
          id: p.userId,
          login: p.login,
          display: p.display,
          role: p.role,
          kind: p.kind,
          builtin: p.builtin,
        },
        via: access.via,
        permissions: [...access.permissions].sort(),
        session:
          access.via === 'session'
            ? {
                id: access.sessionId,
                createdAt: access.session.createdAt,
                lastSeenAt: access.session.lastSeenAt,
                expiresAt: access.session.expiresAt,
                idleExpiresAt: access.session.idleExpiresAt,
                persistent: access.session.persistent,
              }
            : null,
        mirrorPending,
      };
    },

    /** /api/system's `authentication` (shape unchanged from 1.4.x). */
    metadata() {
      return {
        username: 'admin',
        // Always: every Uptime Goblin has an admin password (1.4.x's shape, which reported false for
        // its passwordless local preview).
        passwordChangeAvailable: true,
        passwordChangedAt: user?.passwordChangedAt ?? null,
      };
    },

    /**
     * Verify a same-request password for AO-2, without granting any action or caching success.
     * The pipeline must still enforce route kind/permission, locks, safe transport, throttling
     * and its narrowly declared Basic exception, then re-check currentness before committing.
     * Shares the existing bounded KDF queue. Only our byte copy is cleared; callers own theirs.
     */
    async verifyPassword(access, passwordBytes) {
      service.assertCurrent(access);
      if (!['interactive', 'basic'].includes(access.kind)) throw identityError('forbidden');
      if (
        !Buffer.isBuffer(passwordBytes) ||
        passwordBytes.length < 1 ||
        passwordBytes.length > maxPasswordBytes
      )
        throw new TypeError('verifyPassword requires 1–1024 password bytes');
      const bytes = Buffer.from(passwordBytes);
      const generation = credential,
        epoch = user.epoch;
      try {
        const matches = await verifyRecord(hasher, record, bytes);
        service.assertCurrent(access);
        if (generation !== credential || epoch !== user.epoch)
          throw identityError(access.via === 'basic' ? 'signin_required' : 'session_expired');
        return matches;
      } finally {
        bytes.fill(0);
      }
    },

    /**
     * Throws unless `access` is still good (§5.13); synchronous, for the re-checks after every
     * await (body, exclusive(), the idempotency loop, long handlers).
     */
    assertCurrent(access) {
      if (!access?.authenticated) throw identityError('signin_required');
      if (access.via === 'basic') {
        if (access.credential !== credential || access.epoch !== user.epoch)
          throw identityError('signin_required');
        return;
      }
      if (access.via === 'session') {
        const now = clock();
        if (
          revoked.has(access.sessionId) ||
          access.epoch !== user.epoch ||
          now >= access.session.expiresAt ||
          now >= access.session.idleExpiresAt
        )
          throw identityError('session_expired');
        return;
      }
      throw identityError('signin_required');
    },

    /**
     * Hourly housekeeping: deletes expired sessions and rows still in the revoked map (a
     * revocation whose write failed), forgets revoked ids past their expiry, and retries a
     * pending mirror. Resolves {sessions (rows deleted), mirror: 'ok' | 'failed' | 'none'}.
     */
    async prune(now = clock()) {
      let sessions = 0;
      const ids = [...revoked.keys()];
      try {
        sessions = await db.write(
          tx => identityOps.deleteExpiredSessions(tx, now) + identityOps.deleteSessions(tx, ids)
        );
      } catch (error) {
        warn(
          `Uptime Goblin could not remove ended sessions from control.sqlite (${error?.class || error?.code || 'error'}); it tries again in an hour.`
        );
      }
      // Display codes: the rows no longer needed go, and the cancellations goblin-admin made
      // without the key get their audit row now (B6 design §7.3), in the unit that marks them.
      try {
        await db.write(tx => identityOps.pruneDisplays(tx, now));
        const owed = await db.read(tx => identityOps.unrecordedCancels(tx, owedPerPass));
        if (owed.length)
          await db.write(tx => {
            const marked = identityOps.markCancelsRecorded(
              tx,
              owed.map(display => display.id)
            );
            if (marked)
              for (const display of owed)
                audit.record(tx, {
                  action: 'display.code.cancelled',
                  outcome: 'ok',
                  at: now,
                  target: displayTarget(display),
                  detail: { cause: display.cancelCause ?? 'cancelled', late: true },
                });
          });
      } catch (error) {
        warn(
          `Uptime Goblin could not tidy the wall display codes in control.sqlite (${error?.class || error?.code || 'error'}); it tries again in an hour.`
        );
      }
      for (const [id, expiresAt] of revoked)
        if (expiresAt <= now) {
          revoked.delete(id);
          revokedBy.delete(id);
        }
      for (const [id, known] of live) if (known.expiresAt <= now) live.delete(id);
      // A change in progress mirrors its own password when it commits.
      const mirror = mirrorPending && !changing ? await queueMirror() : 'none';
      if (mirror === 'ok') info(mirrorLines.ok);
      // auth.json was updated either way; the unrecorded line said the rest.
      return { sessions, mirror: mirror === 'unrecorded' ? 'ok' : mirror };
    },

    /**
     * Before the control database closes (Uptime Goblin stops): deletes the rows of sessions this
     * process signed out but could not delete (a full or failing disk), which it refuses only in
     * memory, so a restart would accept them again. When some rows remain, says so in the log,
     * with what to do. The rows it deletes are counted in one `session.revoked` row (cause
     * `retried`, audit spec §5.1) in its unit, or, on a full disk, deleted without it (D32).
     * Resolves the number of signed-out sessions still in the database; never rejects.
     */
    async flushRevoked() {
      const ids = [...revoked.keys()];
      if (!ids.length) return 0;
      let failure;
      try {
        // Most ids are of rows deleted long ago; only rows still there count.
        await writeRecorded(
          db,
          audit,
          tx => {
            const count = identityOps.deleteSessions(tx, ids);
            return {
              events: count
                ? [
                    {
                      action: 'session.revoked',
                      outcome: 'info',
                      target: sessionTarget(null),
                      detail: { cause: 'retried', count },
                    },
                  ]
                : [],
            };
          },
          { fallback: true }
        );
        return 0;
      } catch (error) {
        failure = error;
      }
      // Which of them are still there; a read needs no free space.
      let left = ids.length;
      try {
        const now = clock();
        left = (await db.read(tx => identityOps.userSessions(tx, BUILTIN_ID))).filter(
          row => revoked.has(row.id) && now < row.expiresAt && now < row.idleExpiresAt
        ).length;
      } catch {}
      if (left)
        warn(
          `Uptime Goblin could not remove ${left} signed-out session${left === 1 ? '' : 's'} from control.sqlite (${failure?.class || failure?.code || 'error'}), so ${left === 1 ? 'it is' : 'they are'} accepted again after Uptime Goblin starts. Free some space on the Uptime Goblin host, start Uptime Goblin, and sign out the other devices again under Configure → Account (or change the admin password).`
        );
      return left;
    },

    /** Stops the prune timer. The database is the caller's to close. */
    close() {
      closed = true;
      clearInterval(timer);
    },
  };

  const basic = createBasicVerifier({
    hasher,
    clock,
    retiredMs: limits.retiredMs,
    current: () => ({ record: adminUsable() ? record : null, generation: credential }),
  });

  const timer = setInterval(() => {
    if (closed) return;
    service.prune().catch(error => warn(`Identity housekeeping failed: ${error?.message}`));
  }, limits.pruneMs);
  timer.unref?.();
  return Object.freeze(service);
}
