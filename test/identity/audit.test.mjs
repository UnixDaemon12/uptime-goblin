// Identity's audit rows (audit spec §5.1, D23, D32; §9.1 I): every change identity makes in
// control.sqlite records its row in the write unit of that change, so the row and the change
// commit, roll back and are retried together; a sign-out, a revocation, flushRevoked and a
// start's units are made without the row when only the row does not fit on the disk, while a
// sign-in and a password change fail with it.
//
// Each test runs once per recorder of ./recorders.mjs that can show what it checks: `fake`
// (fakeAudit, rows in memory), `table` (the rows in control.sqlite's audit_inbox, in the unit)
// and `writer` (lane O's chained writer; skipped until integration, §2.3).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { sql, id, list } from '../../lib/db/sql.mjs';
import { metaOps } from '../../lib/db/control.mjs';
import { replacedLine } from '../../lib/identity/bootstrap.mjs';
import { retryOnce } from '../helpers/retry-once.mjs';
import {
  temporary,
  manualClock,
  startIdentity,
  instrumented,
  rows as tableRows,
  meta,
  adminPassword,
  otherPassword,
  fakeRecord,
  writeAuthJson,
  basicBytes,
} from './helpers.mjs';
import {
  fakeRecorder,
  tableRecorder,
  writerRecorder,
  writerMissing,
  failingAuditInserts,
  failingUnits,
  chainedRows,
  inboxEvents,
} from './recorders.mjs';

const kinds = {
  fake: { make: clock => fakeRecorder({ clock }) },
  table: { make: clock => tableRecorder({ clock }) },
  writer: { make: clock => writerRecorder({ clock }), skip: writerMissing },
};
/** One test per recorder in `names` (all three by default): `body(t, name)`. */
function forRecorders(title, body, names = Object.keys(kinds)) {
  for (const name of names)
    test(`${title} (${name})`, { skip: kinds[name].skip ?? false }, t => body(t, name));
}

/** Starts identity on `directory` with the recorder (a new one of `name` unless given). */
async function begin(
  t,
  name,
  { directory = temporary(t), clock = manualClock(), recorder, ...options } = {}
) {
  recorder ??= await kinds[name].make(clock);
  const started = await startIdentity(t, directory, {
    password: adminPassword,
    clock,
    audit: recorder.audit,
    ...options,
  });
  const signIn = (extra = {}) =>
    started.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.10',
      userAgent: 'audit test',
      ...extra,
    });
  return { ...started, recorder, signIn, clock, directory };
}

/**
 * begin()'s `wrap` for a race: `gate.next = fn` runs fn ahead of identity's next write, between
 * the read of a sign-out or revocation and its delete; `gate.next` is null again once it ran.
 */
function raceGate() {
  const gate = {
    next: null,
    wrap: control => ({
      ...control,
      db: new Proxy(control.db, {
        get(target, key) {
          if (key === 'write')
            return async (fn, options) => {
              const run = gate.next;
              gate.next = null;
              await run?.();
              return target.write(fn, options);
            };
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }),
    }),
  };
  return gate;
}
/** Deletes the session rows `ids` as another sign-out (or the prune) would. */
const deleteSessionRows = (control, ids) =>
  control.db.write(tx =>
    tx.run(tx.dialect.deleteFrom('sessions', sql`${id('id')} IN ${list(ids)}`))
  );

/** A function resolving the rows the recorder got since now. */
async function mark(recorder) {
  const from = (await recorder.rows()).length;
  return async () => (await recorder.rows()).slice(from);
}
/** Rows without what only some recorders keep (mode, seq, hash, meta). */
const views = rows =>
  rows.map(({ action, outcome, actor, client, userAgent, requestId, target, detail }) => ({
    action,
    outcome,
    actor,
    client,
    userAgent,
    requestId,
    target,
    detail,
  }));
/**
 * meta.audit_password_changed_at as a row set it (§3.4): the event's own `meta` for the fake and
 * table recorders; the meta table, which the writer sets in the row's unit, for the writer.
 */
const passwordMeta = async (name, row, control) =>
  name === 'writer'
    ? meta(control, 'audit_password_changed_at')
    : (row.meta?.audit_password_changed_at ?? null);

const admin = (sessionId, via = 'session') => ({
  type: 'user',
  id: 'u_admin',
  name: 'admin',
  via,
  sessionId,
});
const orbit = { type: 'system', id: null, name: 'orbit', via: 'system', sessionId: null };
const anonymous = { type: 'anonymous', id: null, name: null, via: null, sessionId: null };
const session = id => ({ type: 'session', id, name: null });
const account = { type: 'account', id: 'u_admin', name: null };
const row = (action, outcome, fields = {}) => ({
  action,
  outcome,
  actor: orbit,
  client: null,
  userAgent: null,
  requestId: null,
  target: null,
  detail: null,
  ...fields,
});
// The pipeline's frozen request facts (audit spec §4.4).
const requestOf = (actor, n) =>
  Object.freeze({
    requestId: `audit-request-${n}`,
    route: 'POST /api/test',
    client: '198.51.100.7',
    userAgent: 'request agent',
    actor,
  });
const fromRequest = n => ({
  client: '198.51.100.7',
  userAgent: 'request agent',
  requestId: `audit-request-${n}`,
});
const input = (from, to) => ({ currentPassword: from, password: to, confirmPassword: to });
const storageFull = { code: 'storage_full' };

// A data directory's control.sqlite put back from a copy (tar, cp, a volume copy).
const backUpControl = (directory, backup) => {
  for (const name of fs.readdirSync(directory))
    if (name.startsWith('control.sqlite'))
      fs.copyFileSync(path.join(directory, name), path.join(backup, name));
};
const replaceControl = (directory, backup) => {
  for (const suffix of ['', '-wal', '-shm'])
    fs.rmSync(path.join(directory, 'control.sqlite' + suffix), { force: true });
  for (const name of fs.readdirSync(backup))
    if (name.startsWith('control.sqlite'))
      fs.copyFileSync(path.join(backup, name), path.join(directory, name));
};

// ---------------------------------------------------------------------------------------------
// "rows": every row of §5.1, written by its unit, with the actor, target and detail given there.

forRecorders(
  "rows: a sign-in names the session it made, with the request's facts when given",
  async (t, name) => {
    const { identity, recorder, signIn } = await begin(t, name, { limits: { maxSessions: 2 } });
    const added = await mark(recorder);
    // A refusal records nothing here: the sign-in route counts it (§5.2).
    await assert.rejects(signIn({ password: otherPassword }), { code: 'invalid_credentials' });
    await assert.rejects(signIn({ login: 'root' }), { code: 'invalid_credentials' });
    const first = await signIn({ userAgent: 'audit\u0007 agent', transport: 'loopback' });
    const request = requestOf(anonymous, 1);
    const second = await identity.login(
      {
        login: 'admin',
        password: adminPassword,
        remember: true,
        client: '192.0.2.99',
        userAgent: 'not the request',
        replacing: [first.issue.value],
      },
      { request }
    );
    // The cap is two: the fourth sign-in evicts the least recently seen, which counts as ended.
    const third = await signIn();
    const fourth = await signIn();
    assert.deepEqual(views(await added()), [
      row('session.login', 'ok', {
        actor: admin(first.issue.id),
        client: '192.0.2.10',
        userAgent: 'audit agent',
        target: session(first.issue.id),
        detail: { persistent: false, transport: 'loopback', ended: 0 },
      }),
      // The request's client, user agent and request id; the actor is still the new session, and
      // the session it rotated counts as ended.
      row('session.login', 'ok', {
        actor: admin(second.issue.id),
        ...fromRequest(1),
        target: session(second.issue.id),
        detail: { persistent: true, transport: 'https', ended: 1 },
      }),
      row('session.login', 'ok', {
        actor: admin(third.issue.id),
        client: '192.0.2.10',
        userAgent: 'audit test',
        target: session(third.issue.id),
        detail: { persistent: false, transport: 'https', ended: 0 },
      }),
      row('session.login', 'ok', {
        actor: admin(fourth.issue.id),
        client: '192.0.2.10',
        userAgent: 'audit test',
        target: session(fourth.issue.id),
        detail: { persistent: false, transport: 'https', ended: 1 },
      }),
    ]);
    const text = JSON.stringify(await recorder.rows());
    for (const secret of [
      adminPassword,
      otherPassword,
      'root',
      first.issue.value,
      second.issue.value,
    ])
      assert.ok(!text.includes(secret), secret);
  }
);

forRecorders(
  'rows: a sign-out records its session and the plain-HTTP session it ends with it',
  async (t, name) => {
    const { identity, recorder, signIn } = await begin(t, name, { insecureHttpSessions: true });
    const mine = await signIn(),
      plain = await signIn({ transport: 'http' }),
      other = await signIn();
    const added = await mark(recorder);
    await identity.logout(mine.access, { also: [plain.issue.value] });
    await identity.logout(other.access, { request: requestOf(admin(other.access.sessionId), 2) });
    // A Basic access has no session to sign out: nothing changes, nothing recorded.
    await identity.logout(await identity.authenticateBasic(basicBytes(adminPassword), {}));
    assert.deepEqual(views(await added()), [
      row('session.logout', 'ok', {
        actor: admin(mine.access.sessionId),
        target: session(mine.access.sessionId),
        detail: { cause: 'signout' },
      }),
      row('session.revoked', 'ok', {
        actor: admin(mine.access.sessionId),
        target: session(plain.access.sessionId),
        detail: { cause: 'insecure_cookie' },
      }),
      row('session.logout', 'ok', {
        actor: admin(other.access.sessionId),
        ...fromRequest(2),
        target: session(other.access.sessionId),
        detail: { cause: 'signout' },
      }),
    ]);
  }
);

forRecorders(
  'presented actor: revokePresented records each session it ends as its own actor, with the cause passed',
  async (t, name) => {
    const { identity, recorder, signIn } = await begin(t, name);
    const made = [];
    for (let i = 0; i < 5; i += 1) made.push(await signIn());
    const ended = await signIn(),
      bystander = await signIn();
    const added = await mark(recorder);
    const unknown = 'v1.' + Buffer.alloc(32, 7).toString('base64url');
    // Presented newest first, with a value that is no session: the rows follow the values.
    const presented = [...made].reverse();
    const linesBefore = recorder.lines?.().length;
    assert.equal(
      await identity.revokePresented([unknown, ...presented.map(entry => entry.issue.value)]),
      5
    );
    // One unit ends the five, so one line (D12): the writer's checkpoint names its newest row.
    if (recorder.lines) {
      const lines = recorder.lines().slice(linesBefore);
      assert.equal(lines.length, 1, JSON.stringify(lines));
      if (name === 'writer') assert.equal(lines[0].seq, (await recorder.rows()).at(-1).seq);
    }
    assert.equal(
      await identity.revokePresented([ended.issue.value], {
        cause: 'ended',
        request: requestOf(anonymous, 3),
      }),
      1
    );
    // A cause other than the routes' two is a defect of the row, never a sign-out left undone
    // (D32): the session ends and the row carries the cause as passed.
    assert.equal(await identity.revokePresented([bystander.issue.value], { cause: 'mistyped' }), 1);
    assert.throws(() => identity.assertCurrent(bystander.access), { code: 'session_expired' });
    assert.deepEqual(views(await added()), [
      ...presented.map(entry =>
        row('session.logout', 'ok', {
          actor: admin(entry.access.sessionId),
          target: session(entry.access.sessionId),
          detail: { cause: 'presented' },
        })
      ),
      // The request is not signed in: holding the cookie is what ends the session, its actor.
      row('session.logout', 'ok', {
        actor: admin(ended.access.sessionId),
        ...fromRequest(3),
        target: session(ended.access.sessionId),
        detail: { cause: 'ended' },
      }),
      row('session.logout', 'ok', {
        actor: admin(bystander.access.sessionId),
        target: session(bystander.access.sessionId),
        detail: { cause: 'mistyped' },
      }),
    ]);
  }
);

forRecorders(
  'rows: signing out another device, and the other devices, names the access that did it',
  async (t, name) => {
    const { identity, recorder, signIn } = await begin(t, name);
    const c = await signIn(),
      d = await signIn(),
      p = await signIn(),
      q = await signIn(),
      r = await signIn();
    const added = await mark(recorder);
    assert.deepEqual(await identity.revokeSession(d.access, c.access.sessionId), {
      found: true,
      current: false,
    });
    // Already gone: nothing ended, nothing recorded.
    assert.deepEqual(await identity.revokeSession(d.access, c.access.sessionId), {
      found: false,
      current: false,
    });
    // q ends d and p, which signed in before it; r signed in after it and stays.
    assert.deepEqual(
      await identity.revokeOtherSessions(q.access, {
        request: requestOf(admin(q.access.sessionId), 5),
      }),
      { revoked: 2, kept: 1 }
    );
    // Basic proves the password with each request: it ends every session.
    const basic = await identity.authenticateBasic(basicBytes(adminPassword), {});
    assert.deepEqual(await identity.revokeOtherSessions(basic), { revoked: 2, kept: 0 });
    // Nothing left to end: no row.
    assert.deepEqual(await identity.revokeOtherSessions(basic), { revoked: 0, kept: 0 });
    assert.deepEqual(views(await added()), [
      row('session.revoked', 'ok', {
        actor: admin(d.access.sessionId),
        target: session(c.access.sessionId),
        detail: { cause: 'by_user' },
      }),
      row('session.revoked-others', 'ok', {
        actor: admin(q.access.sessionId),
        ...fromRequest(5),
        target: account,
        detail: { count: 2, kept: 1 },
      }),
      row('session.revoked-others', 'ok', {
        actor: admin(null, 'basic'),
        target: account,
        detail: { count: 2, kept: 0 },
      }),
    ]);
    for (const gone of [c, d, p, q, r])
      assert.equal(await identity.authenticateSession(gone.issue.value, {}), null);
  }
);

forRecorders(
  'revoked meanwhile: revokeSession of a row deleted meanwhile records nothing',
  async (t, name) => {
    const gate = raceGate();
    const { identity, control, recorder, signIn } = await begin(t, name, { wrap: gate.wrap });
    const gone = await signIn(),
      mine = await signIn();
    const added = await mark(recorder);
    // Another sign-out (or the prune) deletes it after identity read it.
    gate.next = () => deleteSessionRows(control, [gone.access.sessionId]);
    assert.deepEqual(await identity.revokeSession(mine.access, gone.access.sessionId), {
      found: false,
      current: false,
    });
    assert.equal(gate.next, null, 'the delete ran in between');
    assert.deepEqual(await added(), []);
    // "Sign out other devices" whose sessions all went meanwhile ended nothing: no row either.
    const other = await signIn(),
      newest = await signIn();
    const later = await mark(recorder);
    gate.next = () => deleteSessionRows(control, [mine.access.sessionId, other.access.sessionId]);
    assert.deepEqual(await identity.revokeOtherSessions(newest.access), { revoked: 0, kept: 0 });
    assert.equal(gate.next, null, 'the delete ran in between');
    assert.deepEqual(await later(), []);
  }
);

forRecorders(
  'revoked meanwhile: a sign-out records only the sessions its delete ended',
  async (t, name) => {
    const gate = raceGate();
    const { identity, control, recorder, signIn } = await begin(t, name, {
      wrap: gate.wrap,
      insecureHttpSessions: true,
    });
    const gone = await signIn(),
      kept = await signIn();
    const added = await mark(recorder);
    // Another sign-out ends one of the presented sessions after revokePresented read both: that
    // one recorded its end, so this one names only the session it ended. Both are ended, which
    // the answer counts (the route then expires the browser's cookies as for any sign-out).
    gate.next = () => deleteSessionRows(control, [gone.access.sessionId]);
    assert.equal(await identity.revokePresented([gone.issue.value, kept.issue.value]), 2);
    assert.equal(gate.next, null, 'the delete ran in between');
    assert.deepEqual(views(await added()), [
      row('session.logout', 'ok', {
        actor: admin(kept.access.sessionId),
        target: session(kept.access.sessionId),
        detail: { cause: 'presented' },
      }),
    ]);
    // A sign-out whose plain-HTTP session went meanwhile records only its own session; one whose
    // own session went meanwhile (signed out twice at once) records nothing the second time.
    const mine = await signIn(),
      plain = await signIn({ transport: 'http' }),
      twice = await signIn();
    const later = await mark(recorder);
    gate.next = () => deleteSessionRows(control, [plain.access.sessionId]);
    await identity.logout(mine.access, { also: [plain.issue.value] });
    assert.equal(gate.next, null, 'the delete ran in between');
    gate.next = () => deleteSessionRows(control, [twice.access.sessionId]);
    await identity.logout(twice.access);
    assert.equal(gate.next, null, 'the delete ran in between');
    assert.deepEqual(views(await later()), [
      row('session.logout', 'ok', {
        actor: admin(mine.access.sessionId),
        target: session(mine.access.sessionId),
        detail: { cause: 'signout' },
      }),
    ]);
  }
);

forRecorders(
  'password change: the session that changed it acts, the rotated one is named',
  async (t, name) => {
    const { identity, control, recorder, signIn, clock } = await begin(t, name);
    const mine = await signIn({ remember: true }),
      other = await signIn();
    clock.advance(1000);
    const added = await mark(recorder);
    // A refused change records nothing here: the password route counts it (§5.2).
    await assert.rejects(
      identity.changePassword(mine.access, input('not the current one', otherPassword)),
      { code: 'current_password_incorrect' }
    );
    const result = await identity.changePassword(mine.access, input(adminPassword, otherPassword), {
      client: '192.0.2.11',
      userAgent: 'change agent',
    });
    const firstChange = identity.metadata().passwordChangedAt;
    // By Basic: no session acted and none was rotated; the request's facts name who asked.
    const basic = await identity.authenticateBasic(basicBytes(otherPassword), {});
    clock.advance(1000);
    await identity.changePassword(basic, input(otherPassword, adminPassword), {
      request: requestOf(admin(null, 'basic'), 6),
    });
    const rows = await added();
    assert.deepEqual(views(rows), [
      row('account.password.changed', 'ok', {
        actor: admin(mine.access.sessionId),
        client: '192.0.2.11',
        userAgent: 'change agent',
        target: account,
        detail: { revokedOtherSessions: 1, newSessionId: result.issue.id },
      }),
      row('account.password.changed', 'ok', {
        actor: admin(null, 'basic'),
        ...fromRequest(6),
        target: account,
        detail: { revokedOtherSessions: 1, newSessionId: null },
      }),
    ]);
    assert.notEqual(result.issue.id, mine.access.sessionId);
    assert.notEqual(other.access.sessionId, result.issue.id);
    // The change time it stored, so the start's drift check sees the change as recorded (§3.4).
    const last = String(identity.metadata().passwordChangedAt);
    assert.notEqual(last, String(firstChange));
    if (name !== 'writer')
      assert.equal(await passwordMeta(name, rows[0], control), String(firstChange));
    assert.equal(await passwordMeta(name, rows[1], control), last);
    const text = JSON.stringify(await recorder.rows());
    for (const secret of [adminPassword, otherPassword, result.issue.value])
      assert.ok(!text.includes(secret), secret);
  }
);

forRecorders(
  'rows: a mirror that fails after a password change is recorded after it, through system()',
  async (t, name) => {
    const failing = () => {
      throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
    };
    const { identity, recorder, signIn } = await begin(t, name, { writeAuthRecord: failing });
    const { access } = await signIn();
    const added = await mark(recorder);
    const result = await identity.changePassword(access, input(adminPassword, otherPassword));
    assert.equal(result.mirrorPending, true);
    const rows = await added();
    assert.deepEqual(
      rows.map(entry => [entry.action, entry.outcome]),
      [
        ['account.password.changed', 'ok'],
        ['identity.mirror.failed', 'failed'],
      ]
    );
    // In the change's unit, then in its own (the writer chains both alike).
    if (name !== 'writer')
      assert.deepEqual(
        rows.map(entry => entry.mode),
        ['record', 'system']
      );
    assert.deepEqual(views(rows)[1], {
      ...row('identity.mirror.failed', 'failed'),
      target: { type: 'file', id: 'auth.json', name: null },
      detail: { code: 'EROFS' },
    });
  }
);

forRecorders(
  'rows: a sign-out that cannot be saved records session.logout failed through system()',
  async (t, name) => {
    const { identity, db, recorder, signIn } = await begin(t, name, { wrap: instrumented });
    const mine = await signIn(),
      a = await signIn(),
      b = await signIn(),
      c = await signIn(),
      other = await signIn();
    const added = await mark(recorder);
    // The delete fails with its row and again alone (D32): the sign-out is not saved.
    db.failWrites(2);
    await assert.rejects(
      identity.logout(mine.access, { request: requestOf(admin(mine.access.sessionId), 7) }),
      storageFull
    );
    db.failWrites(2);
    await assert.rejects(identity.revokePresented([a.issue.value, b.issue.value]), storageFull);
    // Another failure, not a full disk, records nothing more.
    db.failWrites(1, () => Object.assign(new Error('disk I/O error'), { class: 'unavailable' }));
    await assert.rejects(identity.logout(c.access), /disk I\/O error/);
    // Revocations of other sessions have no failed row (§5.8).
    db.failWrites(2);
    await assert.rejects(identity.revokeOtherSessions(other.access), storageFull);
    const failed = (who, fields = {}) =>
      row('session.logout', 'failed', {
        actor: admin(who.access.sessionId),
        target: session(who.access.sessionId),
        detail: { code: 'storage_full' },
        ...fields,
      });
    const rows = await added();
    assert.deepEqual(views(rows), [failed(mine, fromRequest(7)), failed(a), failed(b)]);
    if (name !== 'writer')
      assert.deepEqual(
        rows.map(entry => entry.mode),
        ['system', 'system', 'system']
      );
    assert.deepEqual(recorder.unwritten(), [], 'nothing was made without its row');
    // Each stays refused in this process (fail closed).
    for (const ended of [mine, a, b, c])
      assert.throws(() => identity.assertCurrent(ended.access), { code: 'session_expired' });
  }
);

forRecorders(
  'rows: flushRevoked counts the signed-out sessions it removed at last',
  async (t, name) => {
    const { identity, control, db, recorder, signIn } = await begin(t, name, {
      wrap: instrumented,
    });
    const stuck = await signIn(),
      done = await signIn(),
      kept = await signIn();
    await identity.logout(done.access);
    db.failWrites(2);
    await assert.rejects(identity.logout(stuck.access), storageFull);
    const added = await mark(recorder);
    assert.equal(await identity.flushRevoked(), 0);
    // The revoked ids of rows deleted before count nothing: once more, no row.
    assert.equal(await identity.flushRevoked(), 0);
    assert.deepEqual(views(await added()), [
      row('session.revoked', 'info', {
        target: session(null),
        detail: { cause: 'retried', count: 1 },
      }),
    ]);
    assert.deepEqual(
      (await tableRows(control, 'sessions')).map(entry => entry.id),
      [kept.access.sessionId]
    );
  }
);

forRecorders(
  'rows: a first start sets the account up and records where its password came from',
  async (t, name) => {
    const clock = manualClock();
    const env = await begin(t, name, { clock });
    const withFile = temporary(t);
    writeAuthJson(withFile, fakeRecord(adminPassword, { passwordChangedAt: 1750000000000 }));
    const file = await begin(t, name, { directory: withFile, clock, password: undefined });
    // Without a password there is no first start, so nothing to record (no source 'none').
    const recorder = await kinds[name].make(clock);
    await assert.rejects(begin(t, name, { clock, recorder, password: '' }), { refusal: true });
    assert.deepEqual(await recorder.rows(), []);
    for (const [started, source, changedAt] of [
      // GOBLIN_PASSWORD stores no change time (1.4.x reported none for it).
      [env, 'env', ''],
      [file, 'auth.json', '1750000000000'],
    ]) {
      const rows = await started.recorder.rows();
      assert.deepEqual(views(rows), [
        row('account.bootstrap', 'info', { target: account, detail: { source } }),
      ]);
      assert.equal(await passwordMeta(name, rows[0], started.control), changedAt, source);
    }
  }
);

forRecorders(
  'rows: a later start records the password it imported, and the account it claimed',
  async (t, name) => {
    const clock = manualClock();
    // auth.json changed outside Uptime Goblin (a rollback to 1.4.x).
    const directory = temporary(t);
    writeAuthJson(directory, fakeRecord(adminPassword));
    const recorder = await kinds[name].make(clock);
    const set = await begin(t, name, { directory, clock, recorder, password: undefined });
    let added = await mark(recorder);
    set.stop();
    writeAuthJson(
      directory,
      fakeRecord(otherPassword, { salt: Buffer.alloc(32, 9), passwordChangedAt: 1750000000000 })
    );
    const imported = await begin(t, name, { directory, clock, recorder, password: undefined });
    let rows = await added();
    assert.deepEqual(views(rows), [
      row('account.password.changed-outside', 'info', {
        target: account,
        detail: { source: 'auth.json' },
      }),
    ]);
    assert.equal(await passwordMeta(name, rows[0], imported.control), '1750000000000');
    imported.stop();

    // GOBLIN_PASSWORD changed between starts: no change time.
    const envDirectory = temporary(t);
    const envRecorder = await kinds[name].make(clock);
    const envSet = await begin(t, name, { directory: envDirectory, clock, recorder: envRecorder });
    added = await mark(envRecorder);
    envSet.stop();
    const fromEnv = await begin(t, name, {
      directory: envDirectory,
      clock,
      recorder: envRecorder,
      password: otherPassword,
    });
    rows = await added();
    assert.deepEqual(views(rows), [
      row('account.password.changed-outside', 'info', {
        target: account,
        detail: { source: 'env' },
      }),
    ]);
    assert.equal(await passwordMeta(name, rows[0], fromEnv.control), '');
    fromEnv.stop();

    // A database carried from another data directory: its account is kept, and mirrored to an
    // auth.json that cannot be written here.
    const carried = temporary(t);
    writeAuthJson(carried, fakeRecord(adminPassword));
    const carriedRecorder = await kinds[name].make(clock);
    const first = await begin(t, name, {
      directory: carried,
      clock,
      recorder: carriedRecorder,
      password: undefined,
    });
    await first.control.db.write(tx => {
      tx.run(tx.dialect.deleteFrom('identity_settings', sql`${id('key')} IS NOT NULL`));
      tx.run(tx.dialect.deleteFrom('meta', sql`${id('key')} = ${'credentials_ever'}`));
    });
    added = await mark(carriedRecorder);
    first.stop();
    const failing = () => {
      throw Object.assign(new Error('permission denied'), { code: 'EACCES' });
    };
    await begin(t, name, {
      directory: carried,
      clock,
      recorder: carriedRecorder,
      password: undefined,
      writeAuthRecord: failing,
    });
    rows = await added();
    assert.deepEqual(views(rows), [
      row('account.claimed', 'info', { target: account }),
      row('identity.mirror.failed', 'failed', {
        target: { type: 'file', id: 'auth.json', name: null },
        detail: { code: 'EACCES' },
      }),
    ]);
  }
);

forRecorders(
  'rows: a start without GOBLIN_INSECURE_HTTP_SESSIONS records the plain-HTTP sessions it ended',
  async (t, name) => {
    const directory = temporary(t),
      clock = manualClock();
    const recorder = await kinds[name].make(clock);
    const first = await begin(t, name, { directory, clock, recorder, insecureHttpSessions: true });
    await first.signIn({ transport: 'http' });
    await first.signIn({ transport: 'http' });
    await first.signIn();
    const added = await mark(recorder);
    first.stop();
    (await begin(t, name, { directory, clock, recorder })).stop();
    // Only when rows were deleted: the next start records nothing.
    const last = await begin(t, name, { directory, clock, recorder });
    assert.deepEqual(views(await added()), [
      row('session.revoked', 'info', {
        target: session(null),
        detail: { cause: 'insecure_http_off', count: 2 },
      }),
    ]);
  }
);

// ---------------------------------------------------------------------------------------------
// Units

forRecorders(
  'throw after record: a unit that throws after its record() leaves no row',
  async (t, name) => {
    const failing = failingUnits();
    const { identity, control, recorder, signIn } = await begin(t, name, {
      wrap: failing.wrap,
      insecureHttpSessions: true,
    });
    // Each unit runs its callback to its end, its record() included, then fails as a COMMIT can
    // (not a full disk, so nothing is made again without the row): first the unit of each
    // change, then the unit of each row. Both are the same unit, so neither leaves a row or a
    // change; a row recorded in another unit (or outside one), or a change made in another unit
    // than its row, would survive.
    for (const kind of ['change', 'record']) {
      failing.kind = kind;
      const a = await signIn(),
        b = await signIn(),
        c = await signIn(),
        d = await signIn(),
        e = await signIn({ transport: 'http' });
      const added = await mark(recorder);
      const linesBefore = recorder.lines?.().length;
      const sessionsBefore = (await tableRows(control, 'sessions')).length;
      const arm = () => (failing.armed = 1);
      const refused = /disk I\/O error/;
      arm();
      await assert.rejects(signIn(), refused);
      arm();
      await assert.rejects(identity.logout(a.access, { also: [e.issue.value] }), refused);
      arm();
      await assert.rejects(identity.revokeSession(d.access, b.access.sessionId), refused);
      arm();
      await assert.rejects(identity.revokePresented([c.issue.value]), refused);
      arm();
      await assert.rejects(identity.revokeOtherSessions(d.access), refused);
      arm();
      await assert.rejects(
        identity.changePassword(d.access, input(adminPassword, otherPassword)),
        refused
      );
      assert.equal(failing.armed, 0, `each ${kind} unit failed`);
      assert.deepEqual(await added(), [], kind);
      if (recorder.lines) assert.equal(recorder.lines().length, linesBefore, `no line (${kind})`);
      assert.equal(
        (await tableRows(control, 'sessions')).length,
        sessionsBefore,
        `nothing deleted or added (${kind})`
      );
      await assert.rejects(signIn({ password: otherPassword }), { code: 'invalid_credentials' });
    }
  }
);

forRecorders(
  'retry once: a sign-in, a sign-out and a password change each leave one row and one line',
  async (t, name) => {
    // Every write unit's callback runs twice: the first attempt is rolled back (class retry).
    const { identity, recorder, signIn } = await begin(t, name, {
      wrap: control => ({ ...control, db: retryOnce(control.db) }),
    });
    assert.deepEqual(
      (await recorder.rows()).map(entry => entry.action),
      ['account.bootstrap'],
      'the first start too'
    );
    const added = await mark(recorder);
    const linesBefore = recorder.lines?.().length;
    const mine = await signIn(),
      other = await signIn();
    await identity.logout(other.access);
    const changed = await identity.changePassword(mine.access, input(adminPassword, otherPassword));
    const rows = await added();
    assert.deepEqual(
      rows.map(entry => entry.action),
      ['session.login', 'session.login', 'session.logout', 'account.password.changed']
    );
    assert.equal(rows[3].detail.newSessionId, changed.issue.id);
    assert.equal(rows[3].detail.revokedOtherSessions, 0);
    // One line per unit, printed once its unit committed (the writer's checkpoint line).
    if (recorder.lines) {
      const lines = recorder.lines().slice(linesBefore);
      assert.equal(lines.length, 4);
      if (name === 'writer')
        assert.deepEqual(
          lines.map(line => line.seq),
          rows.map(entry => entry.seq)
        );
      else
        assert.deepEqual(lines, [
          ['session.login'],
          ['session.login'],
          ['session.logout'],
          ['account.password.changed'],
        ]);
    }
  }
);

// "first start": before the audit holds the keyring, identity's rows go to the inbox in the
// unit of their change (D8); once it is attached, to the chain.
test('first start: rows are inbox rows before the audit is attached, chained after (fake)', async t => {
  const clock = manualClock();
  const recorder = fakeRecorder({ clock, ready: false });
  const { signIn } = await begin(t, 'fake', { clock, recorder });
  await recorder.audit.attach();
  await signIn();
  assert.deepEqual(
    (await recorder.rows()).map(entry => [entry.mode, entry.action]),
    [
      ['inbox', 'account.bootstrap'],
      ['record', 'session.login'],
    ]
  );
});

test('first start: the bootstrap row commits with the admin it set up (table)', async t => {
  const directory = temporary(t),
    clock = manualClock();
  const recorder = tableRecorder({ clock });
  // The unit that sets the admin up fails as a COMMIT can, once: its row goes with it.
  const failing = failingUnits('change');
  failing.armed = 1;
  await assert.rejects(
    begin(t, 'table', { directory, clock, recorder, wrap: failing.wrap }),
    /disk I\/O error/
  );
  const second = await begin(t, 'table', { directory, clock, recorder, wrap: failing.wrap });
  assert.equal((await tableRows(second.control, 'users')).length, 1);
  assert.deepEqual(
    (await inboxEvents(second.control)).map(event => event.action),
    ['account.bootstrap']
  );
});

test(
  'first start: the writer chains the inbox rows identity wrote before it held the keyring (writer)',
  { skip: writerMissing },
  async t => {
    const directory = temporary(t),
      clock = manualClock();
    const recorder = await writerRecorder({ clock, attach: false });
    const first = await begin(t, 'writer', { directory, clock, recorder });
    assert.deepEqual(
      (await inboxEvents(first.control)).map(event => event.action),
      ['account.bootstrap']
    );
    assert.deepEqual(await chainedRows(first.control), []);
    // The keyring exists now (server.mjs 7b): the same start chains them.
    await recorder.attachNow();
    await first.signIn();
    assert.deepEqual(await inboxEvents(first.control), []);
    assert.deepEqual(
      (await recorder.rows()).map(entry => entry.action),
      ['account.bootstrap', 'session.login']
    );
    assert.equal(await recorder.verify(), 'intact');
    first.stop();
    // Every later start attaches before identity: its rows are chained directly.
    const later = await writerRecorder({ clock });
    const second = await begin(t, 'writer', { directory, clock, recorder: later });
    await second.signIn();
    assert.deepEqual(await inboxEvents(second.control), []);
    assert.deepEqual(
      (await later.rows()).map(entry => entry.action),
      ['account.bootstrap', 'session.login', 'session.login']
    );
    assert.equal(await later.verify(), 'intact');
  }
);

// ---------------------------------------------------------------------------------------------
// Restores

forRecorders(
  'control_file anchor: a whole-file restore records its anchor and sign-out in the bootstrap unit, once',
  async (t, name) => {
    const directory = temporary(t),
      backup = temporary(t),
      clock = manualClock();
    const recorder = await kinds[name].make(clock);
    const first = await begin(t, name, { directory, clock, recorder });
    const lost = await first.signIn();
    first.stop();
    backUpControl(directory, backup);
    const second = await begin(t, name, { directory, clock, recorder });
    await second.signIn();
    second.stop();
    replaceControl(directory, backup);
    // The process stops right after the unit that signed everyone out: its log line throws.
    const stopping = {
      info(message) {
        if (message === replacedLine) throw new Error('stopped after the unit');
      },
      log() {},
      warn() {},
      error() {},
    };
    await assert.rejects(
      begin(t, name, { directory, clock, recorder, log: stopping }),
      /stopped after the unit/
    );
    const third = await begin(t, name, { directory, clock, recorder });
    assert.equal(third.identity.status().restoredAtStart, false, 'handled by the stopped start');
    assert.equal(await third.identity.authenticateSession(lost.issue.value, {}), null);
    const rows = await recorder.rows();
    const anchored = rows.filter(entry =>
      ['system.restore', 'session.revoked-restore'].includes(entry.action)
    );
    assert.deepEqual(
      anchored.map(entry => [entry.action, entry.detail.cause, entry.target]),
      [
        ['system.restore', 'control_file', { type: 'orbit', id: null, name: null }],
        ['session.revoked-restore', 'control_file', account],
      ],
      'recorded once'
    );
    const at = rows.indexOf(anchored[0]);
    assert.equal(rows[at + 1], anchored[1], 'one after the other');
    if (name === 'writer') {
      // The next row of the restored chain, linked to the row it continues (D16).
      assert.deepEqual(anchored[0].detail.restoredHead, {
        seq: rows[at - 1].seq,
        hash: rows[at - 1].hash,
      });
      assert.equal(anchored[1].seq, anchored[0].seq + 1);
    } else assert.deepEqual(anchored[0].detail, { cause: 'control_file' });
  }
);

forRecorders(
  "snapshot anchor: a snapshot restore records its sign-out in one unit, after the writer's anchor",
  async (t, name) => {
    const directory = temporary(t),
      clock = manualClock();
    const recorder = await kinds[name].make(clock);
    const first = await begin(t, name, { directory, clock, recorder });
    const lost = await first.signIn();
    // What restoreSnapshot stamps into the incoming control.sqlite.
    const marker = JSON.stringify({ snapshot: 'manual-1.5.0-dev.2-20261003T120000Z', at: 1 });
    await first.control.db.write(tx => metaOps.set(tx, 'restored', marker, clock()));
    const linesBefore = recorder.lines?.().length;
    const added = await mark(recorder);
    first.stop();
    const second = await begin(t, name, { directory, clock, recorder });
    assert.equal(await second.identity.authenticateSession(lost.issue.value, {}), null);
    const rows = await added();
    const revoked = row('session.revoked-restore', 'info', {
      target: account,
      detail: { cause: 'snapshot', snapshot: 'manual-1.5.0-dev.2-20261003T120000Z' },
    });
    if (name === 'writer') {
      // The writer's anchor first, in the same unit (D16): one line, for the unit's last row.
      assert.deepEqual(
        rows.map(entry => entry.action),
        ['system.restore', 'session.revoked-restore']
      );
      assert.deepEqual(rows[0].detail, {
        cause: 'snapshot',
        snapshot: 'manual-1.5.0-dev.2-20261003T120000Z',
        at: 1,
        restoredHead: {
          seq: rows[0].seq - 1,
          hash: (await chainedRows(second.control)).at(-3).hash,
        },
      });
      assert.deepEqual(views(rows.slice(1)), [revoked]);
      const lines = recorder.lines().slice(linesBefore);
      assert.deepEqual(
        lines.map(line => line.seq),
        [rows[1].seq]
      );
    } else assert.deepEqual(views(rows), [revoked]);
    second.stop();

    // A snapshot id that is not a short string is not recorded as one.
    for (const value of [JSON.stringify({ snapshot: 'x'.repeat(201), at: 2 }), 'not json']) {
      const again = await begin(t, name, { directory, clock, recorder });
      await again.control.db.write(tx => metaOps.set(tx, 'restored', value, clock()));
      const next = await mark(recorder);
      again.stop();
      const restored = await begin(t, name, { directory, clock, recorder });
      const revokedRows = (await next()).filter(
        entry => entry.action === 'session.revoked-restore'
      );
      restored.stop();
      assert.deepEqual(
        revokedRows.map(entry => entry.detail),
        [{ cause: 'snapshot', snapshot: null }]
      );
    }
  }
);

// ---------------------------------------------------------------------------------------------
// D32: only a storage failure fails a change; a sign-out wins over its row.

forRecorders(
  'D32: sign-outs, revocations, flushRevoked and a start are made without a row the disk cannot hold; a sign-in is not',
  async (t, name) => {
    const directory = temporary(t),
      clock = manualClock();
    const recorder = await kinds[name].make(clock);
    // fakeAudit's record() throws as a storage error does; on a real database, the audit inserts
    // of identity's units fail with class full (the writer's and the table's alike).
    const failing = failingAuditInserts();
    const fail = on => (name === 'fake' ? recorder.failRecords(on) : (failing.on = on));
    const wrap = control => instrumented(failing.wrap(control));
    const first = await begin(t, name, {
      directory,
      clock,
      recorder,
      wrap,
      insecureHttpSessions: true,
    });
    const { identity, control, db, signIn } = first;
    const stuck = await signIn(),
      a = await signIn(),
      b = await signIn(),
      c = await signIn(),
      d = await signIn(),
      e = await signIn(),
      plain = await signIn({ transport: 'http' });
    // stuck's delete fails alone too: it stays refused in memory, for flushRevoked below.
    db.failWrites(2);
    await assert.rejects(identity.logout(stuck.access), storageFull);
    const stored = (await recorder.rows()).length;
    fail(true);

    // A sign-in and a password change fail with their row (§13 M2): nothing changed.
    const sessions = (await tableRows(control, 'sessions')).length;
    await assert.rejects(signIn(), storageFull);
    assert.equal((await tableRows(control, 'sessions')).length, sessions, 'no session issued');
    await assert.rejects(
      identity.changePassword(e.access, input(adminPassword, otherPassword)),
      storageFull
    );
    identity.assertCurrent(e.access);
    await assert.rejects(signIn({ password: otherPassword }), { code: 'invalid_credentials' });

    // The sign-outs and revocations are made, their rows going to stderr (unrecorded()).
    await identity.logout(a.access);
    assert.deepEqual(await identity.revokeSession(e.access, b.access.sessionId), {
      found: true,
      current: false,
    });
    assert.equal(await identity.revokePresented([c.issue.value], { cause: 'ended' }), 1);
    assert.equal(await identity.flushRevoked(), 0);
    // plain signed in after e: kept.
    assert.deepEqual(await identity.revokeOtherSessions(e.access), { revoked: 1, kept: 1 });
    assert.deepEqual(
      (await tableRows(control, 'sessions')).map(entry => entry.id).sort(),
      [e.access.sessionId, plain.access.sessionId].sort()
    );
    void d;

    // A start's units too: the end of the plain-HTTP sessions, then a restore's sign-out.
    first.stop();
    const second = await begin(t, name, { directory, clock, recorder, wrap });
    assert.deepEqual(
      (await tableRows(second.control, 'sessions')).map(entry => entry.id),
      [e.access.sessionId]
    );
    await second.control.db.write(tx =>
      metaOps.set(tx, 'restored', JSON.stringify({ snapshot: 's1', at: 1 }), clock())
    );
    second.stop();
    const third = await begin(t, name, { directory, clock, recorder, wrap });
    assert.equal(third.identity.status().restoredAtStart, true, 'the start went on');
    assert.deepEqual(await tableRows(third.control, 'sessions'), []);

    // One stderr line each (D32), in the order the changes were made.
    assert.deepEqual(
      recorder.unwritten().map(entry => [entry.action, entry.detail]),
      [
        ['session.logout', { cause: 'signout' }],
        ['session.revoked', { cause: 'by_user' }],
        ['session.logout', { cause: 'ended' }],
        ['session.revoked', { cause: 'retried', count: 1 }],
        ['session.revoked-others', { count: 1, kept: 1 }],
        ['session.revoked', { cause: 'insecure_http_off', count: 1 }],
        ['session.revoked-restore', { cause: 'snapshot', snapshot: 's1' }],
      ]
    );
    assert.equal((await recorder.rows()).length, stored, 'no row written meanwhile');
    if (name !== 'fake') assert.ok(failing.refused > 0, 'the audit inserts were refused');
  }
);

forRecorders(
  'D32: a first start whose account.bootstrap row cannot be written still sets the admin up',
  async (t, name) => {
    // Lane I's reading of D32 ("no start fails because of its audit row"): the first start's
    // unit is a start's unit too, so it is made without the row the disk cannot hold.
    const clock = manualClock();
    const recorder = await kinds[name].make(clock);
    const failing = failingAuditInserts();
    failing.on = true;
    if (name === 'fake') recorder.failRecords(true);
    const { identity, control } = await begin(t, name, { clock, recorder, wrap: failing.wrap });
    assert.equal((await tableRows(control, 'users')).length, 1);
    // Set up with its password (a check that writes nothing, as the disk is still full).
    assert.equal(
      (await identity.authenticateBasic(Buffer.from('admin:' + adminPassword))).via,
      'basic'
    );
    assert.deepEqual(await recorder.rows(), []);
    assert.deepEqual(
      recorder.unwritten().map(entry => [entry.action, entry.detail]),
      [['account.bootstrap', { source: 'env' }]]
    );
  }
);

forRecorders(
  'D32: a sign-out whose unit failed before it held its row is not made again without it',
  async (t, name) => {
    // The unit could not begin (its callback never ran): the row cannot be why it failed, so the
    // sign-out fails as on a full disk, and is not made again as if the row were the cause.
    let refuse = 0;
    const wrap = control => ({
      ...control,
      db: new Proxy(control.db, {
        get(target, key) {
          if (key === 'write')
            return (fn, options) =>
              refuse-- > 0
                ? Promise.reject(
                    Object.assign(new Error('database or disk is full'), { class: 'full' })
                  )
                : target.write(fn, options);
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }),
    });
    const { identity, control, recorder, signIn } = await begin(t, name, { wrap });
    const mine = await signIn();
    const added = await mark(recorder);
    refuse = 1;
    await assert.rejects(identity.logout(mine.access), storageFull);
    assert.equal(refuse, 0, 'one write was tried');
    assert.deepEqual(
      (await tableRows(control, 'sessions')).map(entry => entry.id),
      [mine.access.sessionId],
      'still stored, refused in this process only'
    );
    assert.deepEqual(
      (await added()).map(entry => [entry.action, entry.outcome]),
      [['session.logout', 'failed']]
    );
    assert.deepEqual(recorder.unwritten(), []);
  }
);

// ---------------------------------------------------------------------------------------------
// The writer's own checks inside identity's unit (D27, D28, D32): integration only.

test(
  'damaged log: with the last row out of range a sign-in succeeds, writes no row and prints one line (writer)',
  { skip: writerMissing },
  async t => {
    const { control, recorder, signIn } = await begin(t, 'writer');
    await signIn();
    const count = () =>
      control.db.read(tx => Number(tx.get(sql`SELECT COUNT(*) AS n FROM ${id('audit_log')}`).n));
    // A seq beyond the safe range, set by hand: reading it fails with class poison.
    await control.db.write(tx => {
      const { newest } = tx.get(sql`SELECT MAX(${id('seq')}) AS newest FROM ${id('audit_log')}`);
      tx.run(
        tx.dialect.update('audit_log', { seq: 2n ** 53n + 1n }, sql`${id('seq')} = ${newest}`)
      );
    });
    const before = await count(),
      unwritten = recorder.unwritten().length;
    const { access } = await signIn();
    assert.equal(access.via, 'session');
    assert.equal(await count(), before, 'no row');
    assert.deepEqual(
      recorder
        .unwritten()
        .slice(unwritten)
        .map(entry => entry.action),
      ['session.login']
    );
  }
);

test(
  'head behind: a sign-in writes the gap row and its own row in its unit (writer)',
  { skip: writerMissing },
  async t => {
    const { control, recorder, signIn } = await begin(t, 'writer');
    await signIn();
    await signIn();
    const before = await chainedRows(control);
    const behind = before.at(-2);
    await control.db.write(tx =>
      tx.run(
        tx.dialect.update(
          'audit_head',
          { seq: behind.seq, hash: behind.hash },
          sql`${id('id')} = ${1}`
        )
      )
    );
    const linesBefore = recorder.lines().length;
    await signIn();
    const added = (await chainedRows(control)).slice(before.length);
    assert.deepEqual(
      added.map(entry => [entry.seq, entry.action, entry.detail?.reason ?? null]),
      [
        [before.at(-1).seq + 1, 'audit.gap', 'head-mismatch'],
        [before.at(-1).seq + 2, 'session.login', null],
      ]
    );
    assert.deepEqual(
      recorder
        .lines()
        .slice(linesBefore)
        .map(line => line.seq),
      [added[1].seq]
    );
  }
);
