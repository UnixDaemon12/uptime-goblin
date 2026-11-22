// An in-memory identity service for HTTP tests (sessions spec §2.1 item 10, §5.5). It keeps the
// observable behaviour of lib/identity/index.mjs (the same method names, access objects, error
// codes, session lifetimes, touch rules and revocation ordering) without scrypt or a database:
// the password is compared directly, and a start without one is refused, as Uptime Goblin always
// requires an admin password.
// test/helpers/identity-contract.mjs holds the behaviour both must show.
//
// It records the audit rows of audit spec §5.1 through its `audit` recorder (fakeAudit() by
// default), each inside the write of its change: a write that fails records nothing, and a
// recorder that fails as storage does fails the change, except that a sign-out or revocation is
// then made without its rows, which go to audit.unrecorded() (D32). A sign-out whose delete
// itself fails on a full disk rejects with storage_full and records `session.logout` failed
// (detail.code) through audit.system() (§5.1).
//
// This file is a Phase 0 contract (frozen): lanes change it only together, through the
// integrator. Test-only controls live under `identity.test` and are not part of §5.5.
import { createHash, randomBytes } from 'node:crypto';
import { identityError } from '../../lib/identity/errors.mjs';
import { passwordRequiredMessage } from '../../lib/identity/bootstrap.mjs';
import { permissions as allPermissions } from '../../lib/http/router.mjs';
import { eventFrom } from '../../lib/audit/actions.mjs';
import { fakeAudit } from './fake-audit.mjs';

export const BUILTIN_ID = 'u_admin';

/** The same limits as lib/identity/index.mjs defaultLimits (§5.2). */
export const fakeLimits = Object.freeze({
  idleMs: 12 * 3600e3,
  absoluteMs: 7 * 86400e3,
  rememberMs: 30 * 86400e3,
  maxSessions: 20,
  touchMs: 60e3,
  pruneMs: 3600e3,
  retiredMs: 86400e3,
});

/** The same bound as lib/identity/index.mjs maxPresented (§19 G1). */
export const fakeMaxPresented = 256;

const valuePattern = /^v1\.[A-Za-z0-9_-]{43}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

/** The stored hash of a cookie value, or null unless it is a canonical v1 value (§5.9). */
export function fakeTokenHash(value) {
  if (typeof value !== 'string' || !valuePattern.test(value)) return null;
  const encoded = value.slice(3),
    bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== encoded) return null;
  return sha256(bytes);
}

// A read-only view of the admin's permissions: every route permission (§5.4).
const permissionList = Object.freeze([...allPermissions].sort());
function readonlyPermissionSet(list) {
  const set = new Set(list);
  return Object.freeze({
    has: permission => set.has(permission),
    get size() {
      return set.size;
    },
    [Symbol.iterator]: () => set.values(),
    values: () => set.values(),
  });
}
const readonlyPermissions = readonlyPermissionSet(permissionList);
const basicPermissions = readonlyPermissionSet(
  permissionList.filter(permission => !['tokens:manage', 'tokens:own'].includes(permission))
);

const principal = Object.freeze({
  userId: BUILTIN_ID,
  login: 'admin',
  display: 'Administrator',
  role: 'admin',
  kind: 'person',
  builtin: true,
});

const cleanAgent = value =>
  typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 256) : null;

// The transports a session is bound to (as lib/identity/index.mjs): an `https` one is accepted
// only as the Secure cookie, the others never as it; `http` ones need insecureHttpSessions.
const transports = new Set(['https', 'loopback', 'http']);
const secureCookie = transport => transport === 'https';

// The actor of an access (audit spec D25): the admin, by session or Basic.
const actorOf = access => ({
  type: 'user',
  id: BUILTIN_ID,
  name: 'admin',
  via: access?.via === 'basic' ? 'basic' : 'session',
  sessionId: access?.sessionId ?? null,
});
// An event as §5.1 builds it: with the pipeline's request facts, the client, user agent, request
// id and actor are the request's; without, the call's and the access's. `fields` win over both
// (a sign-in names its new session, a presented sign-out the session it ends).
const eventOf = (request, { actor, client = null, userAgent = null }, fields) =>
  request ? eventFrom(request, fields) : { actor, client, userAgent, requestId: null, ...fields };
const sessionTarget = id => ({ type: 'session', id, name: null });
const accountTarget = { type: 'account', id: BUILTIN_ID, name: null };

/**
 * `fakeIdentity({clock, password, limits, insecureHttpSessions, audit})` → the §5.5 service, with
 * the audit spec §5.1 signatures. Without a password it throws the start refusal (exit 78) the
 * real service throws. `identity.test` offers:
 * `rows()` (the session rows), `checks` (password comparisons made, the stand-in for KDF
 * derivations), `saturated` (true: every new check refuses with busy/queue, as a full hasher
 * does), `gate` (a promise every new check awaits, to hold checks in flight), `beforeWrite`
 * (called before each write; throw from it to fail the write, for example with
 * `fullWrite()`), `mirrorFails` (password changes report mirrorPending), `setPassword(p)` (a
 * change made outside Uptime Goblin: an import that ends every session) and `audit` (the recorder,
 * whose `rows` are the §5.1 rows).
 */
export function fakeIdentity({
  clock = Date.now,
  password = null,
  limits = fakeLimits,
  insecureHttpSessions = false,
  audit = fakeAudit({ clock }),
} = {}) {
  if (typeof password !== 'string' || !password)
    throw Object.assign(new Error(passwordRequiredMessage), { refusal: true });
  let current = password,
    epoch = 1,
    rowVersion = 1,
    credential = 0,
    passwordChangedAt = null,
    changing = false,
    successKey = null,
    mirrorPending = false;
  const sessions = new Map(), // id → row
    revoked = new Map(), // id → expiresAt
    retired = new Map(), // credential text → expiry
    checks = new Map(); // in-flight Basic checks
  const control = {
    checks: 0,
    saturated: false,
    gate: null,
    beforeWrite: null,
    mirrorFails: false,
    audit,
  };

  // As db.write: the callback and its commit happen synchronously within the call, so an
  // entry added to the revoked map inside it is visible before any continuation runs.
  // `plan()` returns {apply, events}: the change and its audit rows, recorded in the same unit
  // (audit spec §5.1), so a recorder that throws leaves the change unmade. A recorder failing
  // with class `full` fails a sign-in or password change with storage_full; a sign-out or
  // revocation (`signout`) is made without its rows instead, which go to audit.unrecorded() (D32).
  function write(plan, { signout = false } = {}) {
    let change;
    try {
      control.beforeWrite?.();
      change = plan();
      for (const event of change.events ?? []) audit.record(null, event);
    } catch (error) {
      if (!change || !signout || error?.class !== 'full')
        return Promise.reject(
          change && error?.class === 'full' ? identityError('storage_full') : error
        );
      for (const event of change.events) audit.unrecorded(event, error);
    }
    change.apply();
    return Promise.resolve();
  }
  // A sign-out (§5.1): made without its rows when only they cannot be written (write() above);
  // when the delete itself fails on a full disk, the sign-out rejects with storage_full and
  // `failed` (session.logout failed, detail.code) is recorded through audit.system(), best
  // effort, outside any unit, as the real service does once the unit is gone.
  async function signOut(failed, plan) {
    try {
      await write(plan, { signout: true });
    } catch (error) {
      if (error?.code === 'storage_full' || error?.class === 'full')
        for (const event of failed) await audit.system(event);
      throw error;
    }
  }

  const sessionPart = row =>
    row
      ? Object.freeze({
          createdAt: row.created_at,
          lastSeenAt: row.last_seen_at,
          expiresAt: row.expires_at,
          idleExpiresAt: row.idle_expires_at,
          persistent: row.persistent,
          transport: row.transport,
          authTime: row.auth_time,
        })
      : null;

  function accessFor(via, { row = null, verified = false } = {}) {
    return Object.freeze({
      kind: via === 'basic' ? 'basic' : 'interactive',
      via,
      authenticated: true,
      verified,
      principal,
      permissions: via === 'basic' ? basicPermissions : readonlyPermissions,
      sessionId: row?.id ?? null,
      session: sessionPart(row),
      epoch,
      credential,
      scope: `user:${BUILTIN_ID}:${epoch}`,
    });
  }

  const known = row =>
    row.user_id === BUILTIN_ID &&
    row.kind === 'interactive' &&
    row.stage === 'full' &&
    row.via === 'password' &&
    transports.has(row.transport);

  function newRow({ persistent, client, userAgent, now, transport }) {
    const secret = randomBytes(32),
      expires = now + (persistent ? limits.rememberMs : limits.absoluteMs);
    const row = {
      id: 's_' + randomBytes(12).toString('base64url'),
      token_hash: sha256(secret),
      user_id: BUILTIN_ID,
      kind: 'interactive',
      stage: 'full',
      via: 'password',
      transport,
      persistent: Boolean(persistent),
      created_at: now,
      auth_time: now,
      last_seen_at: now,
      idle_expires_at: Math.min(now + limits.idleMs, expires),
      expires_at: expires,
      client_key: client ?? null,
      user_agent: cleanAgent(userAgent),
    };
    const value = 'v1.' + secret.toString('base64url');
    secret.fill(0);
    return { row, value };
  }

  const issueFor = ({ row, value }, now) =>
    Object.freeze({
      id: row.id,
      value,
      persistent: row.persistent,
      expiresAt: row.expires_at,
      maxAgeSeconds: row.persistent ? Math.floor((row.expires_at - now) / 1000) : null,
    });

  // Least recently seen first (ties: oldest created), so inserting one keeps at most max.
  function evictFor(extra) {
    const rows = [...sessions.values()]
      .filter(row => row.user_id === BUILTIN_ID)
      .sort((a, b) => a.last_seen_at - b.last_seen_at || a.created_at - b.created_at);
    const evicted = [];
    while (rows.length + extra > limits.maxSessions) evicted.push(rows.shift());
    return evicted;
  }

  // As lib/identity/index.mjs: a session ends only sessions that signed in no later than it
  // (Basic: any), and a new session's auth_time is after every existing one's.
  const rankOf = access =>
    access?.via === 'session' ? (access.session?.authTime ?? -Infinity) : Infinity;
  function nextAuthTime(now) {
    let newest = null;
    for (const row of sessions.values())
      if (row.user_id === BUILTIN_ID && (newest === null || row.auth_time > newest))
        newest = row.auth_time;
    return newest === null ? now : Math.max(now, newest + 1);
  }

  const byValue = value => {
    const hash = fakeTokenHash(value);
    if (!hash) return null;
    for (const row of sessions.values()) if (row.token_hash === hash) return row;
    return null;
  };
  // The u_admin sessions of the cookie values a request presented: every distinct well-formed
  // value up to the bound, as the real service looks them up (§19 G1).
  const presentedRows = values => {
    const hashes = new Set();
    for (const value of Array.isArray(values) ? values : []) {
      if (hashes.size >= fakeMaxPresented) break;
      const hash = fakeTokenHash(value);
      if (hash) hashes.add(hash);
    }
    return [...sessions.values()].filter(
      row => hashes.has(row.token_hash) && row.user_id === BUILTIN_ID
    );
  };

  const text = bytes => Buffer.from(bytes).toString('utf8');

  function isRetired(key) {
    const now = clock();
    for (const [entry, until] of retired) if (until <= now) retired.delete(entry);
    return retired.has(key);
  }

  // One comparison, standing in for one KDF derivation, bounded like the real hasher.
  async function compare(candidate) {
    if (control.saturated) throw identityError('busy', { scope: 'queue' });
    control.checks++;
    if (control.gate) await control.gate;
    return candidate === current;
  }

  function checkNewPassword(input) {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      typeof input.currentPassword !== 'string' ||
      typeof input.password !== 'string' ||
      typeof input.confirmPassword !== 'string'
    )
      throw identityError('invalid_request', { variant: 'change' });
    if (Buffer.byteLength(input.currentPassword, 'utf8') > 1024)
      throw identityError('current_password_incorrect');
    const value = input.password;
    if (!value.isWellFormed() || Buffer.byteLength(value, 'utf8') > 1024 || [...value].length < 12)
      throw identityError('password_invalid');
    if (value !== input.confirmPassword) throw identityError('password_mismatch');
    return value;
  }

  const identity = {
    limits,
    status: () => ({
      source: 'env',
      mirrorPending,
      importedAtStart: null,
      restoredAtStart: false,
    }),
    async authenticateSession(value, { activity = 'foreground', transport = 'https' } = {}) {
      const row = byValue(value);
      const now = clock();
      if (!row || !known(row) || revoked.has(row.id)) return null;
      if (secureCookie(row.transport) !== secureCookie(transport)) return null;
      if (row.transport === 'http' && !insecureHttpSessions) return null;
      if (now >= row.expires_at || now >= row.idle_expires_at) {
        sessions.delete(row.id);
        return null;
      }
      const touch = {};
      if (now - row.last_seen_at >= limits.touchMs) touch.last_seen_at = now;
      const idle = Math.min(now + limits.idleMs, row.expires_at);
      if (activity === 'foreground' && idle - row.idle_expires_at >= limits.touchMs)
        touch.idle_expires_at = idle;
      if (Object.keys(touch).length) {
        try {
          await write(() => ({ apply: () => Object.assign(row, touch) }));
        } catch {
          // A failed touch never fails the request; the stored values stay.
        }
      }
      return accessFor('session', { row });
    },
    async authenticateBasic(bytes, { admit } = {}) {
      const key = text(bytes),
        generation = credential;
      if (successKey === `${generation}:${key}`) return accessFor('basic');
      const flightKey = `${generation}:${key}`;
      let check = checks.get(flightKey);
      if (!check) {
        const release = admit?.();
        check = compare(key.slice(6)).finally(() => {
          checks.delete(flightKey);
          release?.();
        });
        checks.set(flightKey, check);
      }
      if (!(await check) || generation !== credential) return null;
      successKey = flightKey;
      return accessFor('basic', { verified: true });
    },
    isRetiredBasic: bytes => isRetired(text(bytes)),
    async login(
      {
        login,
        password: attempt,
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
        login.length < 1 ||
        login.length > 256 ||
        typeof attempt !== 'string' ||
        (remember !== undefined && typeof remember !== 'boolean') ||
        !transports.has(transport)
      )
        throw identityError('invalid_request', { variant: 'login' });
      if (transport === 'http' && !insecureHttpSessions) throw identityError('https_required');
      const name = login.normalize('NFKC').trim().toLowerCase();
      const release = admit?.();
      let right;
      try {
        // Exactly one comparison whatever the name, as the real service runs one derivation.
        right =
          (await compare(
            name === 'admin' && Buffer.byteLength(attempt) <= 1024 ? attempt : null
          )) && name === 'admin';
      } finally {
        release?.();
      }
      // A refusal records nothing: the route counts it (audit spec §5.2).
      if (!right) throw identityError('invalid_credentials', { variant: 'login' });
      const now = clock(),
        made = newRow({ persistent: remember === true, client, userAgent, now, transport });
      const replaced = presentedRows(replacing);
      const added = [];
      try {
        await write(() => {
          // `ended` counts each session once, evicted or rotated (a presented one may be both).
          const gone = [
            ...new Map([...evictFor(1), ...replaced].map(row => [row.id, row])).values(),
          ];
          const id = made.row.id;
          return {
            events: [
              eventOf(
                request,
                { client, userAgent },
                {
                  action: 'session.login',
                  outcome: 'ok',
                  actor: actorOf({ via: 'session', sessionId: id }),
                  target: sessionTarget(id),
                  detail: { persistent: made.row.persistent, transport, ended: gone.length },
                }
              ),
            ],
            apply() {
              made.row.auth_time = nextAuthTime(now);
              for (const row of gone) {
                sessions.delete(row.id);
                revoked.set(row.id, row.expires_at);
                added.push(row.id);
              }
              sessions.set(id, made.row);
            },
          };
        });
      } catch (error) {
        for (const id of added) revoked.delete(id);
        throw error;
      }
      return { access: accessFor('session', { row: made.row }), issue: issueFor(made, now) };
    },
    async logout(access, { also = [], request } = {}) {
      if (access?.via !== 'session') return;
      const row = sessions.get(access.sessionId);
      // Revoked before the write: fail closed if the write fails (prune removes the row).
      revoked.set(access.sessionId, row?.expires_at ?? access.session.expiresAt);
      // The other sessions this browser presented (its plain-HTTP cookie on https) end too.
      const others = presentedRows(also).filter(other => other.id !== access.sessionId);
      for (const other of others) revoked.set(other.id, other.expires_at);
      const by = { actor: actorOf(access) };
      await signOut(
        [
          eventOf(request, by, {
            action: 'session.logout',
            outcome: 'failed',
            target: sessionTarget(access.sessionId),
            detail: { code: 'storage_full' },
          }),
        ],
        () => ({
          events: [
            eventOf(request, by, {
              action: 'session.logout',
              outcome: 'ok',
              target: sessionTarget(access.sessionId),
              detail: { cause: 'signout' },
            }),
            ...others.map(other =>
              eventOf(request, by, {
                action: 'session.revoked',
                outcome: 'ok',
                target: sessionTarget(other.id),
                detail: { cause: 'insecure_cookie' },
              })
            ),
          ],
          apply() {
            sessions.delete(access.sessionId);
            for (const other of others) sessions.delete(other.id);
          },
        })
      );
    },
    async revokePresented(values, { cause = 'presented', request } = {}) {
      const rows = presentedRows(values);
      if (!rows.length) return 0;
      // Revoked before the write, as logout: fail closed if the write fails.
      for (const row of rows) revoked.set(row.id, row.expires_at);
      const presented = row => ({
        actor: actorOf({ via: 'session', sessionId: row.id }),
        target: sessionTarget(row.id),
      });
      await signOut(
        rows.map(row =>
          eventOf(
            request,
            {},
            {
              action: 'session.logout',
              outcome: 'failed',
              ...presented(row),
              detail: { code: 'storage_full' },
            }
          )
        ),
        () => ({
          // Each session ended is its own actor: holding its cookie is what ends it (§5.1).
          events: rows.map(row =>
            eventOf(
              request,
              {},
              {
                action: 'session.logout',
                outcome: 'ok',
                ...presented(row),
                detail: { cause },
              }
            )
          ),
          apply() {
            for (const row of rows) sessions.delete(row.id);
          },
        })
      );
      return rows.length;
    },
    async changePassword(access, input, { client, userAgent, request } = {}) {
      if (!access?.authenticated) throw identityError('signin_required');
      if (changing) throw identityError('change_in_progress');
      changing = true;
      try {
        identity.assertCurrent(access);
        const next = checkNewPassword(input);
        // A refusal records nothing: the route counts it (audit spec §5.2).
        if (!(await compare(input.currentPassword)))
          throw identityError('current_password_incorrect');
        identity.assertCurrent(access);
        const now = clock(),
          seenVersion = rowVersion;
        const others = [...sessions.values()].filter(
          row => row.user_id === BUILTIN_ID && row.id !== access.sessionId
        );
        const own = access.via === 'session' ? sessions.get(access.sessionId) : null;
        const made = own
          ? newRow({
              persistent: own.persistent,
              client,
              userAgent: own.user_agent,
              now,
              transport: own.transport,
            })
          : null;
        const added = [];
        try {
          await write(() => {
            if (rowVersion !== seenVersion) throw identityError('change_in_progress');
            return {
              events: [
                eventOf(
                  request,
                  { actor: actorOf(access), client, userAgent },
                  {
                    action: 'account.password.changed',
                    outcome: 'ok',
                    target: accountTarget,
                    // The access's own (old) session acted; the rotated one is named here.
                    detail: {
                      revokedOtherSessions: others.length,
                      newSessionId: made?.row.id ?? null,
                    },
                    meta: { audit_password_changed_at: String(now) },
                  }
                ),
              ],
              apply() {
                const previous = current;
                current = next;
                passwordChangedAt = now;
                rowVersion++;
                credential++;
                successKey = null;
                if (made) made.row.auth_time = nextAuthTime(now);
                for (const row of own ? [...others, own] : others) {
                  sessions.delete(row.id);
                  revoked.set(row.id, row.expires_at);
                  added.push(row.id);
                }
                if (made) sessions.set(made.row.id, made.row);
                retired.delete(`admin:${next}`);
                if (previous !== next) retired.set(`admin:${previous}`, now + limits.retiredMs);
                while (retired.size > 4) retired.delete(retired.keys().next().value);
              },
            };
          });
        } catch (error) {
          for (const id of added) revoked.delete(id);
          throw error;
        }
        mirrorPending = control.mirrorFails;
        return {
          issue: made ? issueFor(made, now) : null,
          revokedOtherSessions: others.length,
          mirrorPending,
        };
      } finally {
        changing = false;
      }
    },
    async listSessions(access) {
      const now = clock(),
        mine = rankOf(access);
      return [...sessions.values()]
        .filter(
          row => row.user_id === BUILTIN_ID && now < row.expires_at && now < row.idle_expires_at
        )
        .sort(
          (a, b) =>
            (b.id === access?.sessionId) - (a.id === access?.sessionId) ||
            b.last_seen_at - a.last_seen_at
        )
        .map(row => ({
          id: row.id,
          kind: 'interactive',
          display: null,
          current: row.id === access?.sessionId,
          newer: row.id !== access?.sessionId && row.auth_time > mine,
          createdAt: row.created_at,
          lastSeenAt: row.last_seen_at,
          expiresAt: row.expires_at,
          idleExpiresAt: row.idle_expires_at,
          persistent: row.persistent,
          client: row.client_key,
          userAgent: row.user_agent,
        }));
    },
    async revokeSession(access, id, { request } = {}) {
      const row = sessions.get(id);
      if (!row || row.user_id !== BUILTIN_ID) return { found: false, current: false };
      if (row.auth_time > rankOf(access) && !revoked.has(id)) throw identityError('session_newer');
      revoked.set(id, row.expires_at);
      await write(
        () => ({
          // Only when the delete removes the row (§5.1): one ended meanwhile records nothing.
          events: sessions.has(id)
            ? [
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
              ]
            : [],
          apply: () => sessions.delete(id),
        }),
        { signout: true }
      );
      return { found: true, current: id === access?.sessionId };
    },
    async revokeOtherSessions(access, { request } = {}) {
      const now = clock(),
        mine = rankOf(access);
      const all = [...sessions.values()].filter(
        row => row.user_id === BUILTIN_ID && row.id !== access?.sessionId
      );
      const rows = all.filter(row => row.auth_time <= mine || revoked.has(row.id));
      const kept = all.filter(
        row =>
          row.auth_time > mine &&
          !revoked.has(row.id) &&
          now < row.expires_at &&
          now < row.idle_expires_at
      ).length;
      for (const row of rows) revoked.set(row.id, row.expires_at);
      await write(
        () => ({
          // Nothing recorded when nothing was ended (§5.1).
          events: rows.length
            ? [
                eventOf(
                  request,
                  { actor: actorOf(access) },
                  {
                    action: 'session.revoked-others',
                    outcome: 'ok',
                    target: accountTarget,
                    detail: { count: rows.length, kept },
                  }
                ),
              ]
            : [],
          apply() {
            for (const row of rows) sessions.delete(row.id);
          },
        }),
        { signout: true }
      );
      return { revoked: rows.length, kept };
    },
    describe(access) {
      const row = access.sessionId ? sessions.get(access.sessionId) : null;
      return {
        kind: access.via === 'basic' ? 'basic' : 'interactive',
        user: {
          id: BUILTIN_ID,
          login: 'admin',
          display: 'Administrator',
          role: 'admin',
          kind: 'person',
          builtin: true,
        },
        via: access.via,
        permissions: [...access.permissions],
        session:
          access.via === 'session'
            ? {
                id: access.sessionId,
                createdAt: access.session.createdAt,
                lastSeenAt: row?.last_seen_at ?? access.session.lastSeenAt,
                expiresAt: access.session.expiresAt,
                idleExpiresAt: row?.idle_expires_at ?? access.session.idleExpiresAt,
                persistent: access.session.persistent,
              }
            : null,
        mirrorPending,
      };
    },
    metadata: () => ({
      username: 'admin',
      passwordChangeAvailable: true,
      passwordChangedAt,
    }),
    assertCurrent(access) {
      if (!access?.authenticated) throw identityError('signin_required');
      if (access.via === 'basic') {
        if (access.credential !== credential || access.epoch !== epoch)
          throw identityError('signin_required');
        return;
      }
      // As the real service: only a Basic or a session access is ever current.
      if (access.via !== 'session') throw identityError('signin_required');
      const now = clock();
      if (
        revoked.has(access.sessionId) ||
        access.epoch !== epoch ||
        now >= access.session.expiresAt ||
        now >= access.session.idleExpiresAt
      )
        throw identityError('session_expired');
    },
    async prune(now = clock()) {
      let count = 0;
      for (const row of [...sessions.values()])
        if (row.expires_at <= now || row.idle_expires_at <= now || revoked.has(row.id)) {
          sessions.delete(row.id);
          count++;
        }
      for (const [id, until] of revoked) if (until <= now) revoked.delete(id);
      return { sessions: count, mirror: 'none' };
    },
    close() {},
    test: Object.assign(control, {
      rows: () => [...sessions.values()].map(row => ({ ...row })),
      revokedIds: () => [...revoked.keys()],
      // A password set outside Uptime Goblin and imported at start: every session ends (§5.7).
      setPassword(value) {
        const previous = current;
        current = value;
        epoch++;
        rowVersion++;
        credential++;
        successKey = null;
        for (const row of sessions.values()) revoked.set(row.id, row.expires_at);
        sessions.clear();
        if (previous !== value) retired.set(`admin:${previous}`, clock() + limits.retiredMs);
      },
    }),
  };
  return identity;
}

/** An error as the real service raises when control.sqlite is full (§5.3 storage_full). */
export const fullWrite = () => {
  throw identityError('storage_full');
};
