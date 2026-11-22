// Sessions (lib/identity/index.mjs and secrets.mjs, sessions spec §5.9, §5.13), on a manual
// clock: formats and hash-only storage, lifetimes, activity, the touch rate, the cap, prune,
// fail-closed rows, and the revocation map's ordering (D6).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { newSession, sessionTokenHash, isSessionId } from '../../lib/identity/secrets.mjs';
import { defaultLimits } from '../../lib/identity/index.mjs';
import { sql, id } from '../../lib/db/sql.mjs';
import {
  temporary,
  startIdentity,
  instrumented,
  rows,
  adminRow,
  adminPassword,
} from './helpers.mjs';

const minute = 60e3,
  hour = 60 * minute,
  day = 24 * hour;
const foreground = { activity: 'foreground' },
  background = { activity: 'background' };
const expired = error => error.code === 'session_expired' && error.status === 401;
// A revocation whose delete failed on a full disk: refused in this process, not recorded.
const signoutFull = error =>
  error.code === 'storage_full' && /could not record this sign-out/.test(error.message);

async function started(t, options = {}) {
  const context = await startIdentity(t, temporary(t), {
    password: adminPassword,
    wrap: instrumented,
    ...options,
  });
  const signIn = (extra = {}) =>
    context.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.7',
      userAgent: 'test agent',
      ...extra,
    });
  return { ...context, signIn };
}
const updateSession = (control, sessionId, set) =>
  control.db.write(tx =>
    tx.run(tx.dialect.update('sessions', set, sql`${id('id')} = ${sessionId}`))
  );

test('a session value is v1. + 43 base64url characters; only its SHA-256 is stored', async t => {
  const made = newSession();
  assert.match(made.value, /^v1\.[A-Za-z0-9_-]{43}$/);
  assert.match(made.id, /^s_[A-Za-z0-9_-]{16}$/);
  assert.ok(isSessionId(made.id));
  const secret = Buffer.from(made.value.slice(3), 'base64url');
  assert.equal(secret.length, 32);
  assert.equal(made.tokenHash, createHash('sha256').update(secret).digest('hex'));
  assert.equal(sessionTokenHash(made.value), made.tokenHash);
  // Only a canonical encoding of 32 bytes is a value.
  const last = made.value.at(-1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const sibling =
    alphabet[(alphabet.indexOf(last) & ~3) + ((alphabet.indexOf(last) & 3) === 0 ? 1 : 0)];
  for (const value of [
    made.value.slice(0, -1) + sibling, // same bytes, non-canonical trailing bits
    made.value + 'A',
    made.value.slice(0, -1),
    'v2.' + made.value.slice(3),
    made.value.replace('v1.', 'V1.'),
    ' ' + made.value,
    made.value.slice(0, 10) + '+' + made.value.slice(11),
    null,
    42,
    {},
  ])
    assert.equal(sessionTokenHash(value), null, String(value));
  assert.notEqual(newSession().value, made.value);
  assert.equal(isSessionId('s_short'), false);
  assert.equal(isSessionId(made.id + 'x'), false);

  const { identity, control, signIn } = await started(t);
  const { issue } = await signIn();
  const [row] = await rows(control, 'sessions');
  assert.equal(row.id, issue.id);
  assert.equal(row.token_hash, sessionTokenHash(issue.value));
  assert.equal(row.user_id, 'u_admin');
  assert.deepEqual([row.kind, row.stage, row.via], ['interactive', 'full', 'password']);
  assert.ok(!JSON.stringify(row).includes(issue.value.slice(3)));
  assert.equal((await identity.authenticateSession(issue.value, foreground)).sessionId, issue.id);
});

test('unknown and malformed values are null without a lookup; an expired row found is deleted', async t => {
  const { identity, control, db, clock, signIn } = await started(t);
  const reads = db.reads;
  for (const value of ['', 'garbage', 'v1.' + 'A'.repeat(42), undefined])
    assert.equal(await identity.authenticateSession(value, foreground), null);
  assert.equal(db.reads, reads, 'a malformed value never reaches the database');
  assert.equal(await identity.authenticateSession(newSession().value, foreground), null);
  const { issue } = await signIn();
  clock.advance(12 * hour);
  assert.equal(await identity.authenticateSession(issue.value, foreground), null);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(await rows(control, 'sessions'), [], 'the expired row is gone');
});

test('lifetimes: 12 h idle, 7 days absolute, 30 days with Keep me signed in', async t => {
  const { identity, clock, signIn } = await started(t);
  assert.deepEqual(identity.limits, defaultLimits);
  // Idle: exactly 12 h without a foreground request ends it.
  const idle = await signIn();
  clock.advance(12 * hour - 1);
  identity.assertCurrent(idle.access);
  clock.advance(1);
  assert.throws(() => identity.assertCurrent(idle.access), expired);
  assert.equal(await identity.authenticateSession(idle.issue.value, foreground), null);

  // Absolute: used every 11 h, it still ends 7 days after sign-in.
  const start = clock();
  const used = await signIn();
  let access = used.access;
  while (clock() + 11 * hour < start + 7 * day) {
    clock.advance(11 * hour);
    access = await identity.authenticateSession(used.issue.value, foreground);
    assert.ok(access, 'still signed in');
    assert.equal(access.session.expiresAt, start + 7 * day);
  }
  assert.equal(access.session.idleExpiresAt, start + 7 * day, 'idle never passes the absolute end');
  clock.set(start + 7 * day);
  assert.throws(() => identity.assertCurrent(access), expired);
  assert.equal(await identity.authenticateSession(used.issue.value, foreground), null);

  // Remembered: 30 days (and still the 12 h idle limit).
  const at = clock();
  const kept = await signIn({ remember: true });
  assert.equal(kept.issue.expiresAt, at + 30 * day);
  assert.equal(kept.issue.maxAgeSeconds, 30 * 24 * 3600);
  assert.equal(kept.access.session.idleExpiresAt, at + 12 * hour);
  let remembered = kept.access;
  for (let i = 0; i < 65; i += 1) {
    clock.advance(11 * hour);
    remembered = await identity.authenticateSession(kept.issue.value, foreground);
    assert.ok(remembered);
    assert.equal(remembered.session.expiresAt, at + 30 * day);
    assert.ok(remembered.session.idleExpiresAt <= at + 30 * day);
  }
  clock.set(at + 30 * day);
  assert.throws(() => identity.assertCurrent(remembered), expired);
  assert.equal(await identity.authenticateSession(kept.issue.value, foreground), null);
});

test('background activity never extends idle; foreground does, and the access carries it', async t => {
  const { identity, clock, signIn } = await started(t);
  const start = clock();
  const { issue } = await signIn({ remember: true });
  const active = await signIn({ remember: true });
  let polled;
  for (let i = 1; i <= 100; i += 1) {
    clock.set(start + Math.floor((i * (12 * hour - 1)) / 100));
    polled = await identity.authenticateSession(issue.value, background);
    assert.ok(polled, 'the original idle deadline has not passed');
    assert.equal(polled.session.idleExpiresAt, start + 12 * hour);
    assert.equal(polled.session.expiresAt, start + 30 * day);
    assert.equal(polled.session.lastSeenAt, clock(), 'polls still record that the tab is open');
  }
  identity.assertCurrent(polled);
  const used = await identity.authenticateSession(active.issue.value, foreground);
  assert.equal(used.session.idleExpiresAt, clock() + 12 * hour);
  assert.equal(used.session.expiresAt, start + 30 * day);
  identity.assertCurrent(used);
  clock.set(start + 12 * hour);
  assert.throws(() => identity.assertCurrent(polled), expired);
  assert.equal(await identity.authenticateSession(issue.value, background), null);
  // Past the original idle end: only the genuine foreground request kept this session alive.
  clock.advance(1);
  const later = await identity.authenticateSession(active.issue.value, background);
  assert.ok(later);
  assert.equal(later.session.idleExpiresAt, used.session.idleExpiresAt);
  // An unknown activity value is treated as background: it never extends.
  clock.advance(hour);
  const odd = await identity.authenticateSession(active.issue.value, { activity: 'kiosk' });
  assert.equal(odd.session.idleExpiresAt, used.session.idleExpiresAt);
  assert.equal(odd.session.expiresAt, start + 30 * day);
});

test('activity is written at most once a minute and never moves row_version', async t => {
  const { identity, control, db, clock, signIn } = await started(t);
  const { issue } = await signIn();
  const version = (await adminRow(control)).row_version;
  const writes = db.writes;
  for (let i = 0; i < 20; i += 1) {
    clock.advance(2e3);
    await identity.authenticateSession(issue.value, i % 2 ? foreground : background);
  }
  assert.equal(db.writes, writes, '40 s of requests: no write');
  clock.advance(20e3);
  const touched = await identity.authenticateSession(issue.value, background);
  assert.equal(db.writes, writes + 1, 'one write once a minute passed');
  assert.equal(touched.session.lastSeenAt, clock());
  const [row] = await rows(control, 'sessions');
  assert.equal(row.last_seen_at, clock());
  assert.equal(row.idle_expires_at, touched.session.idleExpiresAt);
  await identity.authenticateSession(issue.value, foreground);
  assert.equal(db.writes, writes + 2, 'a foreground request a minute past the last extension');
  await identity.authenticateSession(issue.value, foreground);
  assert.equal(db.writes, writes + 2);
  assert.equal((await adminRow(control)).row_version, version);
});

test('a failed touch never fails the request and is logged at most once a minute', async t => {
  const { identity, db, clock, signIn, logged } = await started(t);
  const { issue, access } = await signIn();
  clock.advance(2 * minute);
  db.failWrites(3);
  const first = await identity.authenticateSession(issue.value, foreground);
  assert.equal(first.session.idleExpiresAt, access.session.idleExpiresAt, 'the stored values');
  assert.equal(first.session.lastSeenAt, access.session.lastSeenAt);
  clock.advance(1e3);
  assert.ok(await identity.authenticateSession(issue.value, foreground));
  clock.advance(minute);
  assert.ok(await identity.authenticateSession(issue.value, foreground));
  const warnings = logged.lines.filter(line => /could not record sign-in activity/.test(line.text));
  assert.equal(warnings.length, 2);
  assert.match(warnings[0].text, /\(full\)/);
  assert.ok(!logged.text().includes(issue.id), 'no session id in the log');
});

test('the cap keeps 20 sessions, evicting the least recently seen (ties: the oldest)', async t => {
  const { identity, clock, signIn, control } = await started(t);
  const made = [];
  for (let i = 0; i < 20; i += 1) {
    made.push(await signIn());
    clock.advance(2 * minute);
  }
  // Use the two oldest, so the third-oldest is now the least recently seen.
  await identity.authenticateSession(made[0].issue.value, background);
  await identity.authenticateSession(made[1].issue.value, background);
  const extra = await signIn();
  assert.equal((await rows(control, 'sessions')).length, 20);
  assert.throws(() => identity.assertCurrent(made[2].access), expired);
  assert.equal(await identity.authenticateSession(made[2].issue.value, foreground), null);
  for (const kept of [made[0], made[1], made[3], extra])
    assert.ok(await identity.authenticateSession(kept.issue.value, background));
  // Ties on last_seen_at: the oldest created goes first.
  await updateSession(control, made[3].issue.id, { last_seen_at: 1 });
  await updateSession(control, made[4].issue.id, { last_seen_at: 1 });
  await signIn();
  assert.equal(await identity.authenticateSession(made[3].issue.value, foreground), null);
  assert.ok(await identity.authenticateSession(made[4].issue.value, background));
});

test('rows 1.5 does not understand fail closed: kind, stage, via, owner, disabled or foreign role', async t => {
  const { identity, control, signIn } = await started(t);
  for (const set of [
    { kind: 'kiosk' },
    { stage: 'mfa' },
    { via: 'oidc' },
    { user_id: 'u_someone' },
  ]) {
    const { issue } = await signIn();
    await updateSession(control, issue.id, set);
    assert.equal(
      await identity.authenticateSession(issue.value, foreground),
      null,
      JSON.stringify(set)
    );
  }
  const listed = await identity.listSessions(null);
  assert.equal(listed.length, 0, 'not listed either');
});

test('a disabled or non-admin u_admin row (a later release) authenticates nothing', async t => {
  const directory = temporary(t);
  const first = await startIdentity(t, directory, { password: adminPassword });
  const { issue } = await first.identity.login({ login: 'admin', password: adminPassword });
  await first.control.db.write(tx =>
    tx.run(tx.dialect.update('users', { disabled_at: 1 }, sql`${id('id')} = ${'u_admin'}`))
  );
  first.stop();
  const second = await startIdentity(t, directory, { password: adminPassword });
  assert.equal(await second.identity.authenticateSession(issue.value, foreground), null);
  await assert.rejects(
    second.identity.login({ login: 'admin', password: adminPassword }),
    error => error.code === 'invalid_credentials'
  );
  assert.equal(
    await second.identity.authenticateBasic(Buffer.from('admin:' + adminPassword), {}),
    null
  );
});

test('revokePresented fails closed: a failed delete rejects storage_full, the sessions stay refused, prune deletes them', async t => {
  // A sign-out sent with two cookies of Uptime Goblin's name (§19 G1) ends the sessions among them like
  // any sign-out: refused at once, and an unrecorded delete is not answered as done.
  const { identity, control, db, signIn } = await started(t);
  const own = await signIn(),
    bystander = await signIn();
  // The delete fails with its audit row and again alone (audit spec D32).
  db.failWrites(2);
  await assert.rejects(
    identity.revokePresented([`v1.${'A'.repeat(43)}`, own.issue.value]),
    signoutFull
  );
  assert.throws(() => identity.assertCurrent(own.access), expired);
  assert.equal(await identity.authenticateSession(own.issue.value, foreground), null);
  assert.equal((await rows(control, 'sessions')).length, 2);
  assert.deepEqual(await identity.prune(), { sessions: 1, mirror: 'none' });
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id),
    [bystander.issue.id]
  );
  identity.assertCurrent(bystander.access);
});

test('prune removes expired rows and rows a failed revocation left; the map forgets expired ids', async t => {
  const { identity, control, db, clock, signIn } = await started(t);
  const old = await signIn();
  clock.advance(13 * hour);
  const fresh = await signIn(),
    stuck = await signIn();
  // The delete fails with its audit row and again alone (audit spec D32).
  db.failWrites(2);
  await assert.rejects(identity.logout(stuck.access), signoutFull);
  // Fail closed: revoked at once although its row is still there.
  assert.throws(() => identity.assertCurrent(stuck.access), expired);
  assert.equal(await identity.authenticateSession(stuck.issue.value, foreground), null);
  assert.equal((await rows(control, 'sessions')).length, 3);
  assert.deepEqual(await identity.prune(), { sessions: 2, mirror: 'none' });
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id),
    [fresh.issue.id]
  );
  assert.ok(await identity.authenticateSession(fresh.issue.value, foreground));
  assert.throws(() => identity.assertCurrent(old.access), expired);
  // A failing prune is logged, not thrown.
  db.failWrites(1);
  const failed = await identity.prune();
  assert.equal(failed.sessions, 0);
});

test('a failed cap or rotation write takes its revocations back; a failed logout keeps its own', async t => {
  const { identity, control, db, clock, signIn } = await started(t, { limits: { maxSessions: 2 } });
  const a = await signIn();
  clock.advance(2 * minute);
  const b = await signIn();
  // At the cap: the next sign-in evicts a, the least recently seen. Its write fails.
  db.failWrites(1);
  await assert.rejects(signIn(), error => error.code === 'storage_full');
  // Nothing changed in the database, so a stays signed in (its revocation was taken back).
  identity.assertCurrent(a.access);
  // A sign-in that rotates b (the cookie it presented) fails the same way: b stays.
  db.failWrites(1);
  await assert.rejects(
    signIn({ replacing: [b.issue.value] }),
    error => error.code === 'storage_full'
  );
  identity.assertCurrent(b.access);
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id).sort(),
    [a.issue.id, b.issue.id].sort()
  );
  // With a working disk: the cap evicts a; rotation replaces b.
  const c = await signIn();
  assert.throws(() => identity.assertCurrent(a.access), expired);
  identity.assertCurrent(b.access);
  const d = await signIn({ replacing: [b.issue.value] });
  assert.throws(() => identity.assertCurrent(b.access), expired);
  identity.assertCurrent(c.access);
  identity.assertCurrent(d.access);
  for (const gone of [a, b])
    assert.equal(await identity.authenticateSession(gone.issue.value, background), null);
  // A failed logout keeps the session revoked (fail closed); prune removes the row later. Its
  // delete fails with its audit row and again alone (audit spec D32).
  db.failWrites(2);
  await assert.rejects(identity.logout(c.access), signoutFull);
  assert.throws(() => identity.assertCurrent(c.access), expired);
  assert.equal(await identity.authenticateSession(c.issue.value, background), null);
});

test('assertCurrent: revoke, logout, expiry while queued, and epoch changes', async t => {
  const { identity, clock, signIn } = await started(t);
  const a = await signIn(),
    b = await signIn();
  // An access held across an await (a write queued in exclusive()) that expires meanwhile.
  clock.advance(12 * hour);
  assert.throws(() => identity.assertCurrent(a.access), expired);
  clock.advance(-12 * hour);
  identity.assertCurrent(a.access);
  // b signed in after a, so b may end a (not the other way round).
  const revoking = identity.revokeSession(b.access, a.access.sessionId);
  assert.throws(() => identity.assertCurrent(a.access), expired);
  await revoking;
  // An access whose epoch is not the user's (from before an import) is over.
  assert.throws(() => identity.assertCurrent({ ...b.access, epoch: b.access.epoch - 1 }), expired);
  assert.throws(
    () => identity.assertCurrent(null),
    error => error.code === 'signin_required'
  );
  assert.throws(
    () => identity.assertCurrent({ ...a.access, via: 'token' }),
    error => error.code === 'signin_required'
  );
  // An unknown session id is not a session this process knows: looked up, then refused.
  assert.deepEqual(await identity.revokeSession(b.access, 'not-an-id'), {
    found: false,
    current: false,
  });
  // An access that has ended learns not even that: it is refused first.
  await assert.rejects(identity.revokeSession(a.access, 'not-an-id'), expired);
});

test('a sign-out revokes sessions read from the database too, not only those seen here', async t => {
  const directory = temporary(t);
  const first = await startIdentity(t, directory, { password: adminPassword });
  const signIn = identity => identity.login({ login: 'admin', password: adminPassword });
  // a signs in last: a session ends only those that signed in no later than it.
  const b = await signIn(first.identity),
    c = await signIn(first.identity),
    a = await signIn(first.identity);
  first.stop();
  // A new process has seen none of them.
  const second = await startIdentity(t, directory, { password: adminPassword });
  const mine = await second.identity.authenticateSession(a.issue.value, foreground);
  assert.deepEqual(await second.identity.revokeSession(mine, b.issue.id), {
    found: true,
    current: false,
  });
  assert.deepEqual(await second.identity.revokeOtherSessions(mine), { revoked: 1, kept: 0 });
  for (const gone of [b, c])
    assert.equal(await second.identity.authenticateSession(gone.issue.value, foreground), null);
  assert.ok(await second.identity.authenticateSession(a.issue.value, foreground));
  // Basic (and local) accesses sign out every session.
  const basic = await second.identity.authenticateBasic(Buffer.from('admin:' + adminPassword), {});
  assert.deepEqual(await second.identity.revokeOtherSessions(basic), { revoked: 1, kept: 0 });
  assert.equal(await second.identity.authenticateSession(a.issue.value, foreground), null);
  assert.deepEqual(await second.identity.revokeOtherSessions(basic), { revoked: 0, kept: 0 });
  assert.deepEqual(
    second.events.map(event => event.action),
    ['session.revoked', 'session.revoked-others', 'session.revoked-others']
  );
});

test('listSessions leaves out expired and revoked sessions', async t => {
  const { identity, clock, signIn } = await started(t);
  const old = await signIn();
  clock.advance(11 * hour);
  const a = await signIn(),
    b = await signIn();
  clock.advance(2 * hour);
  const pending = identity.logout(b.access);
  const listed = await identity.listSessions(a.access);
  await pending;
  assert.deepEqual(
    listed.map(view => view.id),
    [a.access.sessionId]
  );
  assert.throws(() => identity.assertCurrent(old.access), expired, 'idle for 13 h');
});

test('"sign out other devices" counts the sessions the list showed; ended rows are left to prune', async t => {
  const { identity, control, clock, signIn } = await started(t);
  const stale = await signIn();
  clock.advance(13 * hour);
  const other = await signIn(),
    mine = await signIn();
  // The stale session's idle limit has passed; its row is still there until prune.
  assert.equal((await rows(control, 'sessions')).length, 3);
  assert.deepEqual(
    (await identity.listSessions(mine.access)).map(view => view.id),
    [mine.access.sessionId, other.access.sessionId]
  );
  assert.deepEqual(await identity.revokeOtherSessions(mine.access), { revoked: 1, kept: 0 });
  assert.throws(() => identity.assertCurrent(other.access), expired);
  assert.throws(() => identity.assertCurrent(stale.access), expired);
  identity.assertCurrent(mine.access);
  assert.equal((await identity.prune()).sessions, 1);
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id),
    [mine.access.sessionId]
  );
});

test('a start without GOBLIN_INSECURE_HTTP_SESSIONS deletes the sessions signed in over plain HTTP (D16)', async t => {
  const directory = temporary(t);
  const start = insecureHttpSessions =>
    startIdentity(t, directory, { password: adminPassword, insecureHttpSessions });
  const signIn = (identity, transport) =>
    identity.login({ login: 'admin', password: adminPassword, transport });
  const first = await start(true);
  const issued = {};
  for (const transport of ['http', 'loopback', 'https'])
    issued[transport] = await signIn(first.identity, transport);
  assert.deepEqual((await rows(first.control, 'sessions')).map(row => row.transport).sort(), [
    'http',
    'https',
    'loopback',
  ]);
  first.stop();
  // A restart that keeps the opt-in keeps them all.
  const kept = await start(true);
  assert.equal((await rows(kept.control, 'sessions')).length, 3);
  assert.equal(
    (await kept.identity.authenticateSession(issued.http.issue.value, { transport: 'http' }))
      ?.sessionId,
    issued.http.access.sessionId
  );
  assert.doesNotMatch(kept.logged.text(), /plain HTTP/);
  kept.stop();
  // Removed: the plain-HTTP session is deleted and refused on every transport; the others stay.
  const removed = await start(false);
  assert.deepEqual(
    (await rows(removed.control, 'sessions')).map(row => row.id).sort(),
    [issued.loopback.access.sessionId, issued.https.access.sessionId].sort()
  );
  for (const transport of ['http', 'loopback', 'https'])
    assert.equal(
      await removed.identity.authenticateSession(issued.http.issue.value, { transport }),
      null,
      transport
    );
  for (const transport of ['loopback', 'https'])
    assert.equal(
      (await removed.identity.authenticateSession(issued[transport].issue.value, { transport }))
        ?.sessionId,
      issued[transport].access.sessionId
    );
  assert.match(
    removed.logged.text(),
    /^Signed out 1 session that signed in over plain HTTP: GOBLIN_INSECURE_HTTP_SESSIONS is off\.$/m
  );
});

test('a session signed in over plain HTTP that is still stored is refused without the opt-in', async t => {
  // The start's delete is best effort: a row it could not remove is still never accepted.
  const { identity, control } = await started(t);
  const { issue } = await identity.login({
    login: 'admin',
    password: adminPassword,
    transport: 'loopback',
  });
  await control.db.write(tx =>
    tx.run(
      tx.dialect.update(
        'sessions',
        { transport: 'http' },
        sql`${id('token_hash')} = ${sessionTokenHash(issue.value)}`
      )
    )
  );
  for (const transport of ['http', 'loopback'])
    assert.equal(await identity.authenticateSession(issue.value, { transport }), null, transport);
  assert.deepEqual(await identity.listSessions(null), [], 'and not listed as signed in');
});

/**
 * Wraps control.sqlite's db so the next read or write, once armed with holdNext(kind), waits for
 * release(); `entered` resolves when it is reached. Everything else passes straight through.
 */
function holdingDb() {
  let armed = null,
    entered,
    release;
  const arm = kind => {
    armed = kind;
    const reached = new Promise(resolve => (entered = resolve));
    const gate = new Promise(resolve => (release = resolve));
    return { reached, gate };
  };
  let current = null;
  const pass = (db, kind, fn, options) => {
    if (armed !== kind) return db[kind](fn, options);
    armed = null;
    entered();
    return current.gate.then(() => db[kind](fn, options));
  };
  return {
    wrap: control => ({
      ...control,
      db: {
        name: control.db.name,
        get dialect() {
          return control.db.dialect;
        },
        read: (fn, options) => pass(control.db, 'read', fn, options),
        write: (fn, options) => pass(control.db, 'write', fn, options),
      },
    }),
    holdNext(kind) {
      current = arm(kind);
      return current.reached;
    },
    release: () => release(),
  };
}

// Sessions spec §5.9: a revocation re-checks its own access after every await. One whose access
// ended meanwhile (here signed out by a newer session) answers session_expired. What it signed
// out while still current stays signed out, and that row deletion is recorded as Uptime Goblin removing
// signed-out sessions; nothing is recorded as its revocation, and nothing else is deleted for it.
test('a revocation whose own session ends while it waits decides nothing more, and records nothing as its own', async t => {
  const directory = temporary(t);
  // d signs in before a restart: its row is one this process has never seen live.
  const first = await startIdentity(t, directory, { password: adminPassword });
  const d = await first.identity.login({ login: 'admin', password: adminPassword });
  first.stop();
  const hold = holdingDb();
  const { identity, control, clock, events } = await startIdentity(t, directory, {
    password: adminPassword,
    wrap: hold.wrap,
  });
  const signIn = () => identity.login({ login: 'admin', password: adminPassword });
  const c = await signIn();
  clock.advance(1000);
  const a = await signIn(); // a stolen cookie, say
  clock.advance(1000);
  const b = await signIn(); // the admin, signed in again
  const sessionIds = async () => (await rows(control, 'sessions')).map(row => row.id).sort();
  const revocations = () =>
    events
      .filter(event => event.action.startsWith('session.revoked'))
      .map(event => [event.action, event.outcome, event.detail, event.actor.type]);

  // 1. Ended during the read: only c, which a signed out (live, before the read) while it was
  // current, goes; d, which a would have learnt of from the read, stays.
  let reached = hold.holdNext('read');
  const others = identity.revokeOtherSessions(a.access);
  await reached;
  assert.deepEqual(await identity.revokeSession(b.access, a.access.sessionId), {
    found: true,
    current: false,
  });
  hold.release();
  await assert.rejects(others, expired);
  assert.equal(await identity.authenticateSession(c.issue.value, foreground), null);
  assert.deepEqual(await sessionIds(), [b.access.sessionId, d.issue.id].sort());
  assert.deepEqual(revocations(), [
    ['session.revoked', 'ok', { cause: 'by_user' }, 'user'],
    ['session.revoked', 'info', { cause: 'ended_part_way', count: 1 }, 'system'],
  ]);
  // Its target is c, the one session removed.
  assert.equal(events.at(-1).target.id, c.access.sessionId);

  // 2. One session: f looks up d (not live here) and its own session ends during the lookup:
  // d stays signed in, and nothing is recorded for f.
  const f = await signIn();
  clock.advance(1000);
  const e = await signIn();
  clock.advance(1000);
  const g = await signIn();
  events.length = 0;
  reached = hold.holdNext('read');
  const one = identity.revokeSession(f.access, d.issue.id);
  await reached;
  await identity.revokeSession(g.access, f.access.sessionId);
  hold.release();
  await assert.rejects(one, expired);
  assert.deepEqual(await sessionIds(), [b, d, e, g].map(session => session.issue.id).sort());
  assert.deepEqual(revocations(), [['session.revoked', 'ok', { cause: 'by_user' }, 'user']]);

  // 3. Ended after the read, while its delete waited for its turn: the sessions it had signed
  // out by then (b and d, older than e) are deleted all the same, recorded as Uptime Goblin's removal,
  // and it gets session_expired; g, newer, is kept.
  events.length = 0;
  reached = hold.holdNext('write');
  const late = identity.revokeOtherSessions(e.access);
  await reached;
  await identity.revokeSession(g.access, e.access.sessionId);
  hold.release();
  await assert.rejects(late, expired);
  assert.deepEqual(await sessionIds(), [g.access.sessionId]);
  assert.deepEqual(revocations(), [
    ['session.revoked', 'ok', { cause: 'by_user' }, 'user'],
    ['session.revoked', 'info', { cause: 'ended_part_way', count: 2 }, 'system'],
  ]);
  // Uptime Goblin's removal of two sessions names neither of them, nor e, which had signed them out:
  // its target is the session removed, and there was more than one.
  assert.equal(events.at(-1).target.id, null);

  // 4. One session, ended while its delete waited for its turn: the session it signed out (live
  // here, so before its first await) is deleted all the same, as Uptime Goblin's removal; it gets
  // session_expired and no revocation is recorded as its own.
  const h = await signIn();
  clock.advance(1000);
  const i = await signIn();
  clock.advance(1000);
  const j = await signIn();
  events.length = 0;
  reached = hold.holdNext('write');
  const single = identity.revokeSession(i.access, h.access.sessionId);
  await reached;
  await identity.revokeSession(j.access, i.access.sessionId);
  hold.release();
  await assert.rejects(single, expired);
  assert.equal(await identity.authenticateSession(h.issue.value, foreground), null);
  assert.deepEqual(await sessionIds(), [g, j].map(session => session.issue.id).sort());
  assert.deepEqual(revocations(), [
    ['session.revoked', 'ok', { cause: 'by_user' }, 'user'],
    ['session.revoked', 'info', { cause: 'ended_part_way', count: 1 }, 'system'],
  ]);
  // Its target is h, the one session removed (never i, which had ended: a target filter for i
  // would read it as i revoked).
  assert.equal(events.at(-1).target.id, h.access.sessionId);
});

// An access that had already ended when the revocation was called (its route waited for the
// request's body while the admin signed that session out): it signs out nothing, not even the
// sessions this process knows live, and nothing is recorded, neither as its own nor as Uptime Goblin's
// removal. Ending its own session is still a sign-out (the route's logout path).
test('a revocation by an access that had already ended when it was called signs out nothing and records nothing', async t => {
  const { identity, control, events, signIn } = await started(t);
  const c = await signIn(); // an older device, live here
  const d = await signIn(); // another, live here
  const a = await signIn(); // a stolen cookie, say
  const b = await signIn(); // the admin, signed in again
  assert.deepEqual(await identity.revokeSession(b.access, a.access.sessionId), {
    found: true,
    current: false,
  });
  events.length = 0;
  await assert.rejects(identity.revokeOtherSessions(a.access), expired);
  await assert.rejects(identity.revokeSession(a.access, d.access.sessionId), expired);
  for (const session of [c, d, b])
    assert.ok(await identity.authenticateSession(session.issue.value, foreground));
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id).sort(),
    [b, c, d].map(session => session.issue.id).sort()
  );
  assert.deepEqual(events, []);
  // A Basic access whose password changed meanwhile is over too, and ends nothing either.
  const basic = await identity.authenticateBasic(Buffer.from('admin:' + adminPassword), {});
  const next = 'fixture-sessions-unit-next-password';
  await identity.changePassword(b.access, {
    currentPassword: adminPassword,
    password: next,
    confirmPassword: next,
  });
  events.length = 0;
  const e = await identity.login({ login: 'admin', password: next });
  await assert.rejects(identity.revokeOtherSessions(basic), {
    code: 'signin_required',
  });
  assert.ok(await identity.authenticateSession(e.issue.value, foreground));
  assert.equal(
    events.some(event => event.action.startsWith('session.revoked')),
    false
  );
});

// Uptime Goblin's removal (cause ended_part_way) names the session it removed when it removed only one,
// also when it was deleting more and another sign-out removed the rest meanwhile: the session
// removed is otherwise in no row. It never names the access that ended.
test('a removal of signed-out sessions names the one session it removed, though it was deleting more', async t => {
  const hold = holdingDb();
  const { identity, control, clock, events } = await startIdentity(t, temporary(t), {
    password: adminPassword,
    wrap: hold.wrap,
  });
  const signIn = async () => {
    const session = await identity.login({ login: 'admin', password: adminPassword });
    clock.advance(1000);
    return session;
  };
  const sessionIds = async () => (await rows(control, 'sessions')).map(row => row.id).sort();
  const removals = () =>
    events
      .filter(event => event.detail?.cause === 'ended_part_way')
      .map(event => [event.detail.count, event.target.id]);

  // 1. Ended after the read, while its delete of b and c waited for its turn; the admin (m) signed
  // out a, then c. Only b was left for that delete to remove.
  const b = await signIn();
  const c = await signIn();
  const a = await signIn();
  const m = await signIn();
  events.length = 0;
  let reached = hold.holdNext('write');
  const late = identity.revokeOtherSessions(a.access);
  await reached;
  await identity.revokeSession(m.access, a.access.sessionId);
  await identity.revokeSession(m.access, c.access.sessionId);
  hold.release();
  await assert.rejects(late, expired);
  assert.deepEqual(await sessionIds(), [m.access.sessionId]);
  assert.deepEqual(removals(), [[1, b.access.sessionId]]);

  // 2. Ended during the read: the sessions it had signed out first (d and e, live here) are
  // deleted; the admin (n) signed out f, then e, meanwhile. Only d was left to remove. (m signs
  // itself out first, or f would sign it out too.)
  await identity.revokeSession(m.access, m.access.sessionId);
  const d = await signIn();
  const e = await signIn();
  const f = await signIn();
  const n = await signIn();
  events.length = 0;
  reached = hold.holdNext('read');
  const early = identity.revokeOtherSessions(f.access);
  await reached;
  await identity.revokeSession(n.access, f.access.sessionId);
  await identity.revokeSession(n.access, e.access.sessionId);
  hold.release();
  await assert.rejects(early, expired);
  assert.deepEqual(await sessionIds(), [n.access.sessionId]);
  assert.deepEqual(removals(), [[1, d.access.sessionId]]);
});
