// Sign-in (identity.login, sessions spec §5.10): one derivation whatever the input (T2), the
// name rules, admit and the shared hasher, rotation of presented sessions, last_login_at, and
// storage_full.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { newSession, sessionTokenHash } from '../../lib/identity/secrets.mjs';
import { maxPresented, passwordRequiredMessage } from '../../lib/identity/index.mjs';
import {
  temporary,
  startIdentity,
  instrumented,
  countingDerive,
  fakeKey,
  rows,
  adminRow,
  adminPassword,
  otherPassword,
} from './helpers.mjs';

const settle = () => new Promise(resolve => setImmediate(resolve));
const withCode = code => error => error.code === code;

async function started(t, options = {}) {
  const derive = options.derive ?? countingDerive();
  const context = await startIdentity(t, temporary(t), {
    password: adminPassword,
    derive,
    wrap: instrumented,
    ...options,
  });
  derive.calls = 0;
  const signIn = (extra = {}) =>
    context.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.8',
      userAgent: 'login test',
      ...extra,
    });
  return { ...context, derive, signIn };
}

test('a right password signs in; a wrong password and a wrong name cost the same one derivation', async t => {
  const { identity, derive, signIn, events } = await started(t);
  const { access, issue } = await signIn();
  assert.equal(derive.calls, 1);
  assert.equal(access.via, 'session');
  assert.equal(access.verified, false);
  assert.equal(access.sessionId, issue.id);
  for (const attempt of [
    { password: otherPassword },
    { login: 'root' },
    { login: 'administrator', password: adminPassword },
    { login: 'root', password: 'x'.repeat(2000) },
  ]) {
    const before = derive.calls;
    await assert.rejects(signIn(attempt), error => {
      assert.equal(error.code, 'invalid_credentials');
      assert.equal(error.status, 401);
      assert.equal(error.message, 'The login name or password is incorrect.');
      return true;
    });
    assert.equal(derive.calls, before + 1, JSON.stringify(attempt).slice(0, 60));
  }
  // Only the sign-in is recorded (audit spec §5.1): the route counts refusals (§5.2), and no
  // row holds the name or the password typed.
  const logins = events.filter(event => event.action === 'session.login');
  assert.deepEqual(
    logins.map(event => event.outcome),
    ['ok']
  );
  assert.equal(logins[0].actor.sessionId, issue.id);
  assert.equal(logins[0].target.id, issue.id);
  assert.equal(logins[0].client, '192.0.2.8');
  const text = JSON.stringify(logins);
  for (const secret of [adminPassword, otherPassword, 'root', 'administrator', issue.value])
    assert.ok(!text.includes(secret), secret);
  // No passwordless mode is left to ask about.
  assert.equal('required' in identity, false);
});

test('the name is compared after NFKC, trimming and lower case; a password over 1024 bytes cannot match', async t => {
  const { derive, signIn } = await started(t);
  for (const login of ['ADMIN', ' admin ', '\tAdmin\n', 'ａｄｍｉｎ', 'ＡＤＭＩＮ'])
    assert.equal((await signIn({ login })).access.via, 'session', JSON.stringify(login));
  const overlong = 'é'.repeat(513);
  const before = derive.calls;
  await assert.rejects(signIn({ password: overlong }), withCode('invalid_credentials'));
  assert.equal(derive.calls, before + 1, 'still one (dummy) derivation');
});

test('the request shape is checked first, without a derivation and without admit', async t => {
  const { identity, derive } = await started(t);
  let admitted = 0;
  const admit = () => {
    admitted += 1;
    return () => {};
  };
  for (const input of [
    undefined,
    {},
    { login: '', password: adminPassword },
    { login: 'x'.repeat(257), password: adminPassword },
    { login: ['admin'], password: adminPassword },
    { login: 'admin' },
    { login: 'admin', password: null },
    { login: 'admin', password: adminPassword, remember: 1 },
  ])
    await assert.rejects(identity.login(input && { ...input, admit }), error => {
      assert.equal(error.code, 'invalid_request');
      assert.equal(error.status, 400);
      assert.equal(error.message, 'Enter your login name and password.');
      return true;
    });
  assert.equal(derive.calls, 0);
  assert.equal(admitted, 0);
  // 256 characters (code points, not UTF-16 units) is the most a name may have.
  await assert.rejects(
    identity.login({ login: '😀'.repeat(256), password: adminPassword }),
    withCode('invalid_credentials')
  );
});

test('admit is asked once per check and released after it; its refusal stops the check', async t => {
  const { derive, signIn } = await started(t);
  const calls = [];
  const admit = () => {
    calls.push('admit');
    return () => calls.push('release');
  };
  await signIn({ admit });
  await assert.rejects(signIn({ admit, password: otherPassword }), withCode('invalid_credentials'));
  assert.deepEqual(calls, ['admit', 'release', 'admit', 'release']);
  const before = derive.calls;
  const refusal = Object.assign(new Error('Too many sign-in attempts at once.'), {
    code: 'busy',
    scope: 'client',
    status: 429,
  });
  await assert.rejects(
    signIn({
      admit: () => {
        throw refusal;
      },
    }),
    error => error === refusal
  );
  assert.equal(derive.calls, before, 'no derivation for a refused attempt');
});

test('a full hasher refuses with busy (scope queue), and no password was checked', async t => {
  const derive = countingDerive();
  const { signIn } = await started(t, { derive });
  derive.hold();
  // Two derivations run and sixteen wait (the defaults); the next is refused at once.
  const waiting = Array.from({ length: 18 }, () => signIn().catch(error => error));
  await settle();
  const released = [];
  await assert.rejects(
    signIn({
      admit: () => () => released.push(true),
    }),
    error => {
      assert.equal(error.code, 'busy');
      assert.equal(error.scope, 'queue');
      assert.equal(error.retryAfter, 5);
      return true;
    }
  );
  assert.deepEqual(released, [true], 'admit is released on a queue refusal too');
  derive.release();
  const results = await Promise.all(waiting);
  assert.ok(results.every(result => result.access?.via === 'session'));
});

test('without a password identity does not start, so nothing can sign in', async t => {
  await assert.rejects(
    startIdentity(t, temporary(t), { password: '' }),
    error => error.refusal === true && error.message === passwordRequiredMessage
  );
});

test('sign-in rotates the sessions the request presented, when they are the admin’s', async t => {
  const { identity, control, signIn } = await started(t);
  const a = await signIn(),
    b = await signIn(),
    c = await signIn();
  const fresh = await signIn({
    replacing: [a.issue.value, b.issue.value, 'v1.' + 'A'.repeat(43), 'not a value', null],
  });
  for (const old of [a, b]) {
    assert.throws(() => identity.assertCurrent(old.access), withCode('session_expired'));
    assert.equal(await identity.authenticateSession(old.issue.value, {}), null);
  }
  identity.assertCurrent(c.access);
  const ids = (await rows(control, 'sessions')).map(row => row.id).sort();
  assert.deepEqual(ids, [c.issue.id, fresh.issue.id].sort());
  // Server-generated: the new id and value are never a presented one.
  assert.notEqual(sessionTokenHash(fresh.issue.value), sessionTokenHash(a.issue.value));
  // Every value is considered, not only the first two (§19 G1): cookies of Uptime Goblin's name that
  // another site set reach the request beside the browser's own, and before it when their path
  // is longer, so they must not keep the browser's own session out of the rotation.
  const d = await signIn(),
    e = await signIn(),
    f = await signIn();
  const planted = Array.from({ length: 8 }, () => newSession().value);
  await signIn({ replacing: [...planted, d.issue.value, e.issue.value, f.issue.value] });
  for (const old of [d, e, f])
    assert.throws(() => identity.assertCurrent(old.access), withCode('session_expired'));
  // Up to maxPresented distinct well-formed values: repeats and malformed values take no
  // place, and the bound caps what a script can ask for.
  const g = await signIn(),
    h = await signIn();
  const many = Array.from({ length: maxPresented - 1 }, () => newSession().value);
  await signIn({
    replacing: [...many, 'x'.repeat(46), ...many, g.issue.value, h.issue.value],
  });
  assert.throws(() => identity.assertCurrent(g.access), withCode('session_expired'));
  identity.assertCurrent(h.access);
});

test('last_login_at is recorded without moving row_version; client and user agent are kept clean', async t => {
  const { control, clock, signIn, identity } = await started(t);
  const version = (await adminRow(control)).row_version;
  clock.advance(5000);
  const { access } = await signIn({
    userAgent: 'Agent\u0000with\u001bcontrol\u007fcharacters ' + 'x'.repeat(400),
    client: '2001:db8::/64',
  });
  const row = await adminRow(control);
  assert.equal(row.last_login_at, clock());
  assert.equal(row.row_version, version);
  const [view] = await identity.listSessions(access);
  assert.equal(view.client, '2001:db8::/64');
  assert.equal(view.userAgent.length, 256);
  assert.match(view.userAgent, /^Agentwithcontrolcharacters x+$/);
  const { access: bare } = await signIn({ userAgent: undefined, client: undefined });
  const listed = (await identity.listSessions(bare)).find(item => item.current);
  assert.equal(listed.userAgent, null);
  assert.equal(listed.client, null);
});

test('a sign-in whose write fails on a full disk answers storage_full; existing sessions keep working', async t => {
  const { identity, control, db, signIn } = await started(t);
  const kept = await signIn();
  db.failWrites(1);
  await assert.rejects(signIn(), error => {
    assert.equal(error.code, 'storage_full');
    assert.equal(error.status, 503);
    assert.equal(error.retryAfter, 30);
    return true;
  });
  assert.equal((await rows(control, 'sessions')).length, 1);
  identity.assertCurrent(kept.access);
  assert.ok(await identity.authenticateSession(kept.issue.value, { activity: 'background' }));
  // Any other write failure is passed on unchanged.
  const other = Object.assign(new Error('database is locked'), { class: 'retry' });
  db.failWrites(1, () => other);
  await assert.rejects(signIn(), error => error === other);
});

test('a check that started before a password change proves only the old password', async t => {
  // Holds exactly the next derivation until `open()`.
  let gate = null;
  const derive = async (password, salt) => {
    derive.calls += 1;
    const key = fakeKey(Buffer.from(password), Buffer.from(salt));
    if (gate) {
      const wait = gate.promise;
      gate = null;
      await wait;
    }
    return key;
  };
  derive.calls = 0;
  const { identity, signIn } = await started(t, { derive });
  const { access } = await signIn();
  gate = Promise.withResolvers();
  const open = gate.resolve;
  const racing = signIn();
  await settle();
  await identity.changePassword(access, {
    currentPassword: adminPassword,
    password: otherPassword,
    confirmPassword: otherPassword,
  });
  open();
  await assert.rejects(racing, withCode('invalid_credentials'));
  assert.equal((await signIn({ password: otherPassword })).access.via, 'session');
});

test('a sign-in whose write is retried after SQLITE_BUSY is refused when the password changed meanwhile', async t => {
  // db.write runs its callback again after an asynchronous wait when another connection holds
  // the write lock (lib/db/sqlite.mjs). A password change that commits during that wait must
  // stop the sign-in: its check proved only the old password.
  let duringRetry = null,
    retries = 0;
  const { identity, control, events, signIn, directory } = await started(t, {
    controlOptions: {
      busyTimeoutMs: 0,
      // The retry wait: the change runs (and commits) here, before the second attempt.
      sleep: async () => {
        retries += 1;
        const run = duringRetry;
        duringRetry = null;
        await run?.();
      },
    },
  });
  const { access: owner } = await signIn();
  // Another connection holds the write lock (an operator's sqlite3 shell, say).
  const writer = new DatabaseSync(path.join(directory, 'control.sqlite'));
  t.after(() => writer.close());
  writer.exec('PRAGMA busy_timeout=0');
  writer.exec('BEGIN IMMEDIATE');
  let changed = null;
  duringRetry = async () => {
    writer.exec('COMMIT');
    changed = await identity.changePassword(owner, {
      currentPassword: adminPassword,
      password: otherPassword,
      confirmPassword: otherPassword,
    });
  };
  const before = events.length;
  await assert.rejects(signIn({ client: '203.0.113.9' }), withCode('invalid_credentials'));
  assert.equal(retries, 1, 'the sign-in met SQLITE_BUSY once and was retried');
  assert.ok(changed, 'the password change committed during the wait');
  assert.equal(changed.revokedOtherSessions, 0);
  // Only the owner's rotated session exists: nothing was issued for the old password.
  const sessions = await rows(control, 'sessions');
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].token_hash, sessionTokenHash(changed.issue.value));
  // The refused sign-in records nothing here: its route counts it (audit spec §5.2).
  assert.deepEqual(
    events.slice(before).map(event => [event.action, event.outcome]),
    [['account.password.changed', 'ok']]
  );
  // The new password signs in; the old one does not.
  assert.equal((await signIn({ password: otherPassword })).access.via, 'session');
  await assert.rejects(signIn(), withCode('invalid_credentials'));
});
