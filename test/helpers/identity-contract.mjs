// The observable identity service behaviour (sessions spec §5.5, §8.1 "contract") that the real
// service (lib/identity/index.mjs, run by test/identity/contract.test.mjs) and the in-memory fake
// (test/helpers/fake-identity.mjs, run by test/http-pipeline/fake-identity.test.mjs) must both
// show, so tests written against the fake hold for the real thing.
//
//   identityContract(test, make)
//
// `make({clock, password, insecureHttpSessions, audit}, t)` returns the service (or a promise of
// it): `clock` is a manual clock (a function returning epoch ms), `password` the admin password
// (null: none, which the start refuses), `insecureHttpSessions` GOBLIN_INSECURE_HTTP_SESSIONS,
// `audit` the recorder the service records its audit spec §5.1 rows through (a fakeAudit()).
// `t` is the test context, for cleanup (t.after). The contract calls identity.close() itself.
// fakeIdentity has exactly this signature, so `identityContract(test, fakeIdentity)` works as is.
// The rows are checked when `recordsAudit` (an option, by default the flag below) is true.
//
// This file is a Phase 0 contract (frozen): lanes change it only together, through the
// integrator; lane I sets `recordsAudit` (audit spec §2.2).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { AuthError } from '../../lib/auth.mjs';
import { errorCodes } from '../../lib/identity/errors.mjs';
import { passwordRequiredMessage } from '../../lib/identity/bootstrap.mjs';
import { permissions as routerPermissions } from '../../lib/http/router.mjs';
import { fakeAudit } from './fake-audit.mjs';

/**
 * Whether lib/identity records the §5.1 rows through its `audit` option: false until lane I
 * moves identity's emit() sites into its write units and sets it (audit spec §2.2, D23). The
 * fake records them already (test/http-pipeline/fake-identity.test.mjs passes true).
 */
export const recordsAudit = true;

const password = 'contract admin password';
const nextPassword = 'contract next password';
const valuePattern = /^v1\.[A-Za-z0-9_-]{43}$/;
const idPattern = /^s_[A-Za-z0-9_-]{16}$/;
const hour = 3600e3,
  day = 24 * hour;

function manualClock(start = Date.UTC(2026, 8, 1)) {
  let value = start;
  const clock = () => value;
  clock.advance = ms => (value += ms);
  return clock;
}

/** Asserts `error` is the AuthError of `code`, with the status and a message of errorCodes. */
export function assertIdentityError(error, code) {
  assert.ok(error instanceof AuthError, `an AuthError, got ${error?.name}: ${error?.message}`);
  assert.equal(error.code, code);
  const entry = errorCodes[code];
  assert.ok(entry, `${code} is in errorCodes`);
  assert.equal(error.status, entry.status);
  assert.ok(
    Object.values(entry.messages).includes(error.message),
    `${JSON.stringify(error.message)} is a message of ${code}`
  );
  return true;
}
const rejectsWith = (promise, code) =>
  assert.rejects(promise, error => assertIdentityError(error, code));
const throwsWith = (fn, code) => assert.throws(fn, error => assertIdentityError(error, code));

const fixtureFile = new URL('../contract/identity-bodies.json', import.meta.url);
// The http layer adds these to identity.describe() for GET /api/session (§6.11).
const httpKeys = new Set(['transport', 'legacyBasic', 'build']);

/** describe() with the volatile values written as the fixture writes them. */
function shaped(described) {
  return {
    ...described,
    session: described.session && {
      ...described.session,
      id: '<id>',
      createdAt: '<ms>',
      lastSeenAt: '<ms>',
      expiresAt: '<ms>',
      idleExpiresAt: '<ms>',
    },
  };
}

export function identityContract(
  test,
  make,
  { name = 'identity contract', recordsAudit: checkRows = recordsAudit } = {}
) {
  async function start(t, { password: configured = password, insecureHttpSessions = false } = {}) {
    const clock = manualClock();
    const audit = fakeAudit({ clock });
    const identity = await make({ clock, password: configured, insecureHttpSessions, audit }, t);
    t.after(() => identity.close());
    const signIn = (options = {}) =>
      identity.login({
        login: 'admin',
        password: configured,
        client: '192.0.2.10',
        userAgent: 'contract agent',
        replacing: [],
        ...options,
      });
    return { identity, clock, signIn, audit };
  }

  test(`${name}: a start without a password is refused; there is no passwordless access`, async t => {
    await assert.rejects(
      start(t, { password: null }),
      error => error.refusal === true && error.message === passwordRequiredMessage
    );
    const { identity } = await start(t);
    // Nothing of the former local preview is left: no local() and no `required` flag.
    assert.equal('local' in identity, false);
    assert.equal('required' in identity, false);
    // No access without a credential, also for a password change.
    throwsWith(() => identity.assertCurrent(null), 'signin_required');
    throwsWith(
      () => identity.assertCurrent({ via: 'local', authenticated: true }),
      'signin_required'
    );
    await rejectsWith(
      identity.changePassword(null, {
        currentPassword: password,
        password: nextPassword,
        confirmPassword: nextPassword,
      }),
      'signin_required'
    );
    assert.deepEqual(Object.keys(identity.metadata()).sort(), [
      'passwordChangeAvailable',
      'passwordChangedAt',
      'username',
    ]);
    assert.equal(identity.metadata().username, 'admin');
    assert.equal(identity.metadata().passwordChangeAvailable, true);
  });

  test(`${name}: login issues a session; a wrong password, name or shape is refused`, async t => {
    const { identity, clock, signIn } = await start(t);
    const now = clock();
    const { access, issue } = await signIn();
    assert.match(issue.value, valuePattern);
    assert.match(issue.id, idPattern);
    assert.equal(access.via, 'session');
    assert.equal(access.authenticated, true);
    assert.equal(access.sessionId, issue.id);
    assert.equal(access.scope, `user:u_admin:${access.epoch}`);
    assert.equal(access.principal.userId, 'u_admin');
    assert.equal(access.principal.login, 'admin');
    for (const permission of routerPermissions) assert.ok(access.permissions.has(permission));
    assert.ok(Object.isFrozen(access));
    assert.equal(issue.persistent, false);
    assert.equal(issue.maxAgeSeconds, null);
    assert.equal(issue.expiresAt, now + 7 * day);
    assert.equal(access.session.idleExpiresAt, now + 12 * hour);
    assert.equal(access.session.persistent, false);

    const remembered = await signIn({ remember: true });
    assert.equal(remembered.issue.persistent, true);
    assert.equal(remembered.issue.expiresAt, now + 30 * day);
    assert.equal(remembered.issue.maxAgeSeconds, Math.floor((30 * day) / 1000));
    assert.notEqual(remembered.issue.value, issue.value);
    assert.notEqual(remembered.issue.id, issue.id);

    // The name is compared after NFKC, trimming and lower-casing.
    assert.equal((await signIn({ login: ' ADMIN ' })).access.via, 'session');
    await rejectsWith(signIn({ password: 'not the admin password' }), 'invalid_credentials');
    await rejectsWith(signIn({ login: 'root' }), 'invalid_credentials');
    for (const input of [
      { login: '', password },
      { login: 'admin', password: 7 },
      { login: 'admin', password, remember: 'yes' },
      { login: 'x'.repeat(257), password },
    ])
      await rejectsWith(identity.login(input), 'invalid_request');
  });

  test(`${name}: an issued value authenticates; unknown, malformed and expired ones do not`, async t => {
    const { identity, clock, signIn } = await start(t);
    const { access, issue } = await signIn();
    const again = await identity.authenticateSession(issue.value, { activity: 'foreground' });
    assert.equal(again.via, 'session');
    assert.equal(again.sessionId, access.sessionId);
    assert.equal(again.scope, access.scope);
    identity.assertCurrent(again);
    const unknown = 'v1.' + Buffer.alloc(32, 7).toString('base64url');
    for (const value of [
      unknown,
      'v1.short',
      issue.value + 'x',
      'v2.' + issue.value.slice(3),
      '',
      null,
      undefined,
    ])
      assert.equal(await identity.authenticateSession(value, { activity: 'foreground' }), null);

    // Background polls never extend the idle limit; a foreground request does.
    clock.advance(11 * hour);
    const polled = await identity.authenticateSession(issue.value, { activity: 'background' });
    assert.equal(polled.session.idleExpiresAt, access.session.idleExpiresAt);
    const used = await identity.authenticateSession(issue.value, { activity: 'foreground' });
    assert.equal(used.session.idleExpiresAt, clock() + 12 * hour);
    // 12 idle hours end it, for the access in hand and for the cookie.
    clock.advance(12 * hour);
    throwsWith(() => identity.assertCurrent(used), 'session_expired');
    assert.equal(await identity.authenticateSession(issue.value, { activity: 'foreground' }), null);
  });

  test(`${name}: logout and revocations fail assertCurrent synchronously, before they resolve`, async t => {
    const { identity, signIn } = await start(t);
    // b signs in last: a session ends only those that signed in no later than it.
    const a = await signIn(),
      c = await signIn(),
      d = await signIn(),
      e = await signIn(),
      b = await signIn();

    const out = identity.logout(a.access);
    throwsWith(() => identity.assertCurrent(a.access), 'session_expired');
    await out;
    assert.equal(
      await identity.authenticateSession(a.issue.value, { activity: 'foreground' }),
      null
    );

    const one = identity.revokeSession(b.access, c.access.sessionId);
    throwsWith(() => identity.assertCurrent(c.access), 'session_expired');
    assert.deepEqual(await one, { found: true, current: false });
    identity.assertCurrent(b.access);
    assert.deepEqual(await identity.revokeSession(b.access, c.access.sessionId), {
      found: false,
      current: false,
    });
    assert.deepEqual(await identity.revokeSession(b.access, 's_AAAAAAAAAAAAAAAA'), {
      found: false,
      current: false,
    });

    const others = identity.revokeOtherSessions(b.access);
    throwsWith(() => identity.assertCurrent(d.access), 'session_expired');
    throwsWith(() => identity.assertCurrent(e.access), 'session_expired');
    identity.assertCurrent(b.access);
    assert.deepEqual(await others, { revoked: 2, kept: 0 });
    for (const gone of [d, e])
      assert.equal(
        await identity.authenticateSession(gone.issue.value, { activity: 'foreground' }),
        null
      );

    const own = identity.revokeSession(b.access, b.access.sessionId);
    throwsWith(() => identity.assertCurrent(b.access), 'session_expired');
    assert.deepEqual(await own, { found: true, current: true });
    assert.deepEqual(await identity.listSessions(b.access), []);
  });

  test(`${name}: a session cannot end one that signed in after it; a newer sign-in ends it`, async t => {
    const { identity, clock, signIn } = await start(t);
    const stolen = await signIn(),
      older = await signIn();
    // The clock goes back: a sign-in still comes after every session there is.
    clock.advance(-hour);
    const owner = await signIn();
    // The holder of an older cookie, in a loop, cannot end the owner's new sign-in…
    await rejectsWith(
      identity.revokeSession(stolen.access, owner.access.sessionId),
      'session_newer'
    );
    assert.deepEqual(await identity.revokeOtherSessions(stolen.access), { revoked: 0, kept: 2 });
    identity.assertCurrent(owner.access);
    identity.assertCurrent(older.access);
    assert.deepEqual(
      Object.fromEntries(
        (await identity.listSessions(stolen.access)).map(view => [view.id, view.newer])
      ),
      {
        [stolen.access.sessionId]: false,
        [owner.access.sessionId]: true,
        [older.access.sessionId]: true,
      }
    );
    // …which ends it, and its "Sign out other devices" every other session.
    const out = identity.revokeOtherSessions(owner.access);
    throwsWith(() => identity.assertCurrent(stolen.access), 'session_expired');
    assert.deepEqual(await out, { revoked: 2, kept: 0 });
    for (const gone of [stolen, older])
      assert.equal(await identity.authenticateSession(gone.issue.value, {}), null);
    identity.assertCurrent(owner.access);
    // A password change proves the password too: its rotated session outranks the others.
    const later = await signIn();
    const changed = await identity.changePassword(owner.access, {
      currentPassword: password,
      password: nextPassword,
      confirmPassword: nextPassword,
    });
    assert.equal(changed.revokedOtherSessions, 1);
    throwsWith(() => identity.assertCurrent(later.access), 'session_expired');
    const rotated = await identity.authenticateSession(changed.issue.value, {});
    const next = await identity.login({ login: 'admin', password: nextPassword });
    await rejectsWith(identity.revokeSession(rotated, next.access.sessionId), 'session_newer');
    assert.deepEqual(await identity.revokeSession(next.access, rotated.sessionId), {
      found: true,
      current: false,
    });
  });

  test(`${name}: logout also ends the other sessions the browser presents (its plain-HTTP cookie)`, async t => {
    const { identity, signIn } = await start(t, { insecureHttpSessions: true });
    const secure = await signIn({ transport: 'https' }),
      plain = await signIn({ transport: 'http' }),
      bystander = await signIn({ transport: 'https' });
    const unknown = 'v1.' + Buffer.alloc(32, 9).toString('base64url');
    const out = identity.logout(secure.access, {
      also: [plain.issue.value, unknown, 'not a cookie'],
    });
    throwsWith(() => identity.assertCurrent(secure.access), 'session_expired');
    await out;
    throwsWith(() => identity.assertCurrent(plain.access), 'session_expired');
    for (const [gone, transport] of [
      [secure, 'https'],
      [plain, 'http'],
    ])
      assert.equal(
        await identity.authenticateSession(gone.issue.value, { activity: 'foreground', transport }),
        null
      );
    // Only those: another device stays signed in.
    identity.assertCurrent(bystander.access);
    assert.deepEqual(
      (await identity.listSessions(bystander.access)).map(view => view.id),
      [bystander.access.sessionId]
    );
  });

  test(`${name}: every presented value counts, however many another site set beside it`, async t => {
    // §19 G1: cookies of Uptime Goblin's name that another site set are sent beside the browser's own,
    // before it when their path is longer. A sign-in, a sign-out and its https end of the
    // plain-HTTP session must still reach the browser's own.
    const { identity, signIn } = await start(t, { insecureHttpSessions: true });
    const planted = Array.from(
      { length: 8 },
      (_, i) => 'v1.' + Buffer.alloc(32, i + 1).toString('base64url')
    );
    const secure = await signIn({ transport: 'https' }),
      plain = await signIn({ transport: 'http' });
    await identity.logout(secure.access, { also: [...planted, 'x', plain.issue.value] });
    throwsWith(() => identity.assertCurrent(plain.access), 'session_expired');
    const old = await signIn();
    const fresh = await signIn({ replacing: [...planted, old.issue.value] });
    throwsWith(() => identity.assertCurrent(old.access), 'session_expired');
    identity.assertCurrent(fresh.access);
  });

  test(`${name}: revokePresented ends exactly the admin's sessions among the values`, async t => {
    // A sign-out sent with two cookies of Uptime Goblin's name (§19 G1): holding a secret is enough to
    // end its session, and nothing else is reached.
    const { identity, signIn } = await start(t);
    const a = await signIn(),
      b = await signIn(),
      bystander = await signIn();
    const unknown = 'v1.' + Buffer.alloc(32, 7).toString('base64url');
    assert.equal(await identity.revokePresented([]), 0);
    assert.equal(await identity.revokePresented([unknown, 'x', null, 42]), 0);
    assert.equal(
      await identity.revokePresented([unknown, a.issue.value, 'x', b.issue.value, a.issue.value]),
      2
    );
    for (const gone of [a, b]) {
      throwsWith(() => identity.assertCurrent(gone.access), 'session_expired');
      assert.equal(await identity.authenticateSession(gone.issue.value, {}), null);
    }
    identity.assertCurrent(bystander.access);
    assert.deepEqual(
      (await identity.listSessions(bystander.access)).map(view => view.id),
      [bystander.access.sessionId]
    );
    // Already ended: nothing more to end.
    assert.equal(await identity.revokePresented([a.issue.value]), 0);
  });

  test(`${name}: listSessions shows the current session first and never a secret`, async t => {
    const { identity, clock, signIn } = await start(t);
    const first = await signIn({ userAgent: 'first agent', client: '192.0.2.1' });
    clock.advance(2 * 60e3);
    const second = await signIn({ userAgent: 'second agent', client: '192.0.2.2', remember: true });
    clock.advance(2 * 60e3);
    const list = await identity.listSessions(first.access);
    assert.equal(list.length, 2);
    for (const view of list)
      assert.deepEqual(Object.keys(view).sort(), [
        'client',
        'createdAt',
        'current',
        'display',
        'expiresAt',
        'id',
        'idleExpiresAt',
        'kind',
        'lastSeenAt',
        'newer',
        'persistent',
        'userAgent',
      ]);
    assert.deepEqual(
      list.map(view => [
        view.id,
        view.current,
        view.newer,
        view.client,
        view.userAgent,
        view.persistent,
      ]),
      [
        [first.access.sessionId, true, false, '192.0.2.1', 'first agent', false],
        // Signed in after the first: the first cannot end it.
        [second.access.sessionId, false, true, '192.0.2.2', 'second agent', true],
      ]
    );
    // A wall display's entry names it (B6 design §7.5); an admin session's names none.
    for (const view of list) assert.deepEqual([view.kind, view.display], ['interactive', null]);
    assert.deepEqual(
      (await identity.listSessions(second.access)).map(view => [view.current, view.newer]),
      [
        [true, false],
        [false, false],
      ]
    );
    const text = JSON.stringify(list);
    for (const secret of [first.issue.value, second.issue.value, 'token_hash', 'tokenHash'])
      assert.ok(!text.includes(secret));
  });

  test(`${name}: changePassword rotates this session and revokes the others`, async t => {
    const { identity, signIn } = await start(t);
    const mine = await signIn({ remember: true }),
      other = await signIn();
    const input = {
      currentPassword: password,
      password: nextPassword,
      confirmPassword: nextPassword,
    };
    await rejectsWith(
      identity.changePassword(mine.access, { ...input, currentPassword: 'wrong current password' }),
      'current_password_incorrect'
    );
    await rejectsWith(
      identity.changePassword(mine.access, {
        ...input,
        password: 'short',
        confirmPassword: 'short',
      }),
      'password_invalid'
    );
    await rejectsWith(
      identity.changePassword(mine.access, {
        ...input,
        confirmPassword: 'something else entirely',
      }),
      'password_mismatch'
    );
    await rejectsWith(
      identity.changePassword(mine.access, { password: nextPassword }),
      'invalid_request'
    );
    identity.assertCurrent(mine.access);

    const result = await identity.changePassword(mine.access, input, {
      client: '192.0.2.10',
      userAgent: 'contract agent',
    });
    assert.deepEqual(Object.keys(result).sort(), [
      'issue',
      'mirrorPending',
      'revokedOtherSessions',
    ]);
    assert.equal(result.revokedOtherSessions, 1);
    assert.equal(typeof result.mirrorPending, 'boolean');
    assert.match(result.issue.value, valuePattern);
    assert.notEqual(result.issue.value, mine.issue.value);
    assert.notEqual(result.issue.id, mine.access.sessionId);
    assert.equal(result.issue.persistent, true);
    throwsWith(() => identity.assertCurrent(mine.access), 'session_expired');
    throwsWith(() => identity.assertCurrent(other.access), 'session_expired');
    for (const old of [mine, other])
      assert.equal(
        await identity.authenticateSession(old.issue.value, { activity: 'foreground' }),
        null
      );
    const rotated = await identity.authenticateSession(result.issue.value, {
      activity: 'foreground',
    });
    assert.equal(rotated.sessionId, result.issue.id);
    await rejectsWith(signIn(), 'invalid_credentials');
    assert.equal((await signIn({ password: nextPassword })).access.via, 'session');
    assert.ok(identity.metadata().passwordChangedAt > 0);
  });

  test(`${name}: legacy Basic checks the password and ends with a password change`, async t => {
    const { identity, signIn } = await start(t);
    const bytes = value => Buffer.from('admin:' + value, 'utf8');
    const first = await identity.authenticateBasic(bytes(password), {});
    assert.equal(first.via, 'basic');
    assert.equal(first.verified, true);
    assert.equal(first.sessionId, null);
    assert.equal(first.session, null);
    assert.equal(first.scope, `user:u_admin:${first.epoch}`);
    assert.equal((await identity.authenticateBasic(bytes(password), {})).verified, false);
    assert.equal(await identity.authenticateBasic(bytes('not the admin password'), {}), null);
    const { access } = await signIn();
    await identity.changePassword(first, {
      currentPassword: password,
      password: nextPassword,
      confirmPassword: nextPassword,
    });
    throwsWith(() => identity.assertCurrent(first), 'signin_required');
    throwsWith(() => identity.assertCurrent(access), 'session_expired');
    assert.equal(await identity.authenticateBasic(bytes(password), {}), null);
    assert.equal(identity.isRetiredBasic(bytes(password)), true);
    assert.equal(identity.isRetiredBasic(bytes('never used password')), false);
    assert.equal((await identity.authenticateBasic(bytes(nextPassword), {})).via, 'basic');
  });

  test(`${name}: a session is accepted only as the cookie of the transport it was signed in over`, async t => {
    const { identity, signIn } = await start(t, { insecureHttpSessions: true });
    const kinds = ['https', 'loopback', 'http'];
    const issued = {};
    for (const transport of kinds) issued[transport] = await signIn({ transport });
    const accepted = async (value, transport) =>
      (await identity.authenticateSession(value, { activity: 'foreground', transport })) !== null;
    // The Secure cookie (https) and the plain one (loopback, http) never stand in for each
    // other: a secret that crossed a network in clear is never accepted as the Secure cookie.
    for (const issuedOver of kinds)
      for (const transport of kinds)
        assert.equal(
          await accepted(issued[issuedOver].issue.value, transport),
          (issuedOver === 'https') === (transport === 'https'),
          `signed in over ${issuedOver}, presented on ${transport}`
        );
    // Without a transport, both sides mean https.
    assert.equal(await accepted(issued.https.issue.value, undefined), true);
    assert.notEqual(await identity.authenticateSession(issued.https.issue.value, {}), null);
    assert.equal(await identity.authenticateSession(issued.loopback.issue.value, {}), null);
    assert.notEqual((await signIn({ transport: undefined })).access, null);
    for (const transport of ['HTTPS', 'ftp', null, 7])
      await rejectsWith(signIn({ transport }), 'invalid_request');
    // A password change rotates the session into the same transport: the browser's cookie.
    const changed = await identity.changePassword(issued.http.access, {
      currentPassword: password,
      password: nextPassword,
      confirmPassword: nextPassword,
    });
    assert.equal(await accepted(changed.issue.value, 'http'), true);
    assert.equal(await accepted(changed.issue.value, 'https'), false);
  });

  test(`${name}: without GOBLIN_INSECURE_HTTP_SESSIONS nothing signs in or is accepted over plain HTTP`, async t => {
    const { identity, signIn } = await start(t);
    await rejectsWith(signIn({ transport: 'http' }), 'https_required');
    for (const transport of ['https', 'loopback']) {
      const { issue } = await signIn({ transport });
      const access = await identity.authenticateSession(issue.value, {
        activity: 'foreground',
        transport,
      });
      assert.equal(access?.via, 'session', transport);
    }
  });

  test(`${name}: describe() has exactly the identity keys of GET /api/session`, async t => {
    const { identity, signIn } = await start(t);
    const { access } = await signIn();
    const basicAccess = await identity.authenticateBasic(Buffer.from('admin:' + password), {});
    const described = {
      session: identity.describe(access),
      basic: identity.describe(basicAccess),
    };
    assert.deepEqual(Object.keys(described.session), [
      'kind',
      'user',
      'via',
      'permissions',
      'session',
      'mirrorPending',
    ]);
    assert.deepEqual(described.session.permissions, [...routerPermissions].sort());
    assert.deepEqual(described.session.session.id, access.sessionId);
    assert.equal(described.session.mirrorPending, false);
    // The fixture pins the whole GET /api/session body; identity supplies all but the http keys.
    if (fs.existsSync(fixtureFile)) {
      const fixture = JSON.parse(fs.readFileSync(fixtureFile, 'utf8')).session;
      assert.deepEqual(Object.keys(fixture).sort(), ['basic', 'session']);
      for (const via of ['session', 'basic']) {
        const expected = Object.fromEntries(
          Object.entries(fixture[via]).filter(([key]) => !httpKeys.has(key))
        );
        assert.deepEqual(shaped(described[via]), expected, via);
      }
    }
  });
  test(
    `${name}: records the audit spec §5.1 rows, each in the unit of its change`,
    {
      skip: checkRows ? false : 'lib/identity records no audit rows yet (lane I sets recordsAudit)',
    },
    async t => {
      const { identity, clock, signIn, audit } = await start(t, { insecureHttpSessions: true });
      // The rows recorded since `from`, without their volatile seq and time.
      const rowsFrom = from => audit.rows.slice(from).map(({ seq, at, ...row }) => row);
      const admin = sessionId => ({
        type: 'user',
        id: 'u_admin',
        name: 'admin',
        via: 'session',
        sessionId,
      });
      const row = (action, fields) => ({
        mode: 'record',
        action,
        outcome: 'ok',
        actor: null,
        client: null,
        userAgent: null,
        requestId: null,
        target: null,
        status: null,
        count: 1,
        ref: null,
        detail: null,
        configRevision: null,
        meta: null,
        ...fields,
      });
      const session = id => ({ type: 'session', id, name: null });
      const account = { type: 'account', id: 'u_admin', name: null };

      // A refused sign-in records nothing: the sign-in route counts refusals (§5.2).
      await rejectsWith(signIn({ password: 'not the admin password' }), 'invalid_credentials');
      assert.deepEqual(audit.rows, []);
      const first = await signIn();
      assert.deepEqual(rowsFrom(0), [
        row('session.login', {
          actor: admin(first.issue.id),
          client: '192.0.2.10',
          userAgent: 'contract agent',
          target: session(first.issue.id),
          detail: { persistent: false, transport: 'https', ended: 0 },
        }),
      ]);

      // With the request's facts: its client, user agent and request id; the actor is still
      // the new session, and the session it rotated counts as ended.
      const request = Object.freeze({
        requestId: 'contract-request-1',
        route: 'POST /api/auth/login',
        client: '198.51.100.4',
        userAgent: 'request agent',
        actor: { type: 'anonymous', id: null, name: null, via: null, sessionId: null },
      });
      let from = audit.rows.length;
      const second = await identity.login(
        {
          login: 'admin',
          password,
          remember: true,
          client: '192.0.2.99',
          userAgent: 'not the request',
          replacing: [first.issue.value],
          transport: 'https',
        },
        { request }
      );
      assert.deepEqual(rowsFrom(from), [
        row('session.login', {
          actor: admin(second.issue.id),
          client: '198.51.100.4',
          userAgent: 'request agent',
          requestId: 'contract-request-1',
          target: session(second.issue.id),
          detail: { persistent: true, transport: 'https', ended: 1 },
        }),
      ]);

      // A sign-out, and the browser's plain-HTTP session it ends with it.
      const plain = await signIn({ transport: 'http' });
      from = audit.rows.length;
      await identity.logout(second.access, { also: [plain.issue.value] });
      assert.deepEqual(rowsFrom(from), [
        row('session.logout', {
          actor: admin(second.access.sessionId),
          target: session(second.access.sessionId),
          detail: { cause: 'signout' },
        }),
        row('session.revoked', {
          actor: admin(second.access.sessionId),
          target: session(plain.access.sessionId),
          detail: { cause: 'insecure_cookie' },
        }),
      ]);

      // Presented sessions: each one ended is its own actor, with the cause passed.
      const a = await signIn(),
        b = await signIn();
      from = audit.rows.length;
      assert.equal(
        await identity.revokePresented([a.issue.value, b.issue.value], { cause: 'ended' }),
        2
      );
      assert.deepEqual(rowsFrom(from), [
        row('session.logout', {
          actor: admin(a.access.sessionId),
          target: session(a.access.sessionId),
          detail: { cause: 'ended' },
        }),
        row('session.logout', {
          actor: admin(b.access.sessionId),
          target: session(b.access.sessionId),
          detail: { cause: 'ended' },
        }),
      ]);

      // One device signed out by another; a session already gone records nothing.
      const c = await signIn(),
        d = await signIn();
      from = audit.rows.length;
      await identity.revokeSession(d.access, c.access.sessionId);
      await identity.revokeSession(d.access, c.access.sessionId);
      assert.deepEqual(rowsFrom(from), [
        row('session.revoked', {
          actor: admin(d.access.sessionId),
          target: session(c.access.sessionId),
          detail: { cause: 'by_user' },
        }),
      ]);

      // "Sign out other devices"; again with nothing left to end, no row.
      const e = await signIn();
      from = audit.rows.length;
      assert.deepEqual(await identity.revokeOtherSessions(e.access), { revoked: 1, kept: 0 });
      assert.deepEqual(await identity.revokeOtherSessions(e.access), { revoked: 0, kept: 0 });
      assert.deepEqual(rowsFrom(from), [
        row('session.revoked-others', {
          actor: admin(e.access.sessionId),
          target: account,
          detail: { count: 1, kept: 0 },
        }),
      ]);

      // A refused password change records nothing (the route counts it); a change names the
      // session that acted (the old id) and the one it rotated to.
      const input = {
        currentPassword: password,
        password: nextPassword,
        confirmPassword: nextPassword,
      };
      from = audit.rows.length;
      await rejectsWith(
        identity.changePassword(e.access, { ...input, currentPassword: 'wrong current password' }),
        'current_password_incorrect'
      );
      assert.deepEqual(rowsFrom(from), []);
      const other = await signIn();
      clock.advance(1000);
      from = audit.rows.length;
      const changed = await identity.changePassword(e.access, input, {
        client: '192.0.2.10',
        userAgent: 'contract agent',
      });
      assert.deepEqual(rowsFrom(from), [
        row('account.password.changed', {
          actor: admin(e.access.sessionId),
          client: '192.0.2.10',
          userAgent: 'contract agent',
          target: account,
          detail: { revokedOtherSessions: 1, newSessionId: changed.issue.id },
          meta: { audit_password_changed_at: String(identity.metadata().passwordChangedAt) },
        }),
      ]);
      assert.notEqual(other.access.sessionId, changed.issue.id);
    }
  );
}
