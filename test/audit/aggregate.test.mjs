// Aggregated events (lib/audit/aggregate.mjs, audit spec D9, §4.5) with a manual clock and timers:
// at most one immediate and one summary row per action and window whatever the traffic, the
// client cap, the login class, a full disk, failed and forced flushes, and no timer while idle.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createAggregator, loginClass, windowOf } from '../../lib/audit/aggregate.mjs';
import { auditFixture, linesOf, manualClock, storedRows } from './helpers.mjs';

const HOUR = 3600000,
  DAY = 86400000,
  MINUTE = 60000;

// An aggregator over a manual clock and timers; `writes` holds every row it wrote.
function harness({
  start = Date.UTC(2026, 9, 3, 0),
  full = () => false,
  fails = () => false,
} = {}) {
  const clock = manualClock(start);
  const timers = new Set();
  const writes = [];
  const delays = []; // every delay given to setTimer
  const aggregator = createAggregator({
    clock,
    full,
    write: async (event, kind) => {
      if (fails(event, kind)) return false;
      writes.push({ ...event, kind });
      return true;
    },
    setTimer: (fn, ms) => {
      delays.push(ms);
      const timer = { at: clock() + ms, fn };
      timers.add(timer);
      return timer;
    },
    clearTimer: timer => timers.delete(timer),
  });
  // Moves the clock on, firing the timers that come due on the way.
  const advance = async ms => {
    const end = clock() + ms;
    for (;;) {
      const due = [...timers].filter(timer => timer.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      timers.delete(due);
      clock.set(Math.max(clock(), due.at));
      due.fn();
      await aggregator.idle();
    }
    clock.set(end);
    await aggregator.idle();
  };
  return { aggregator, clock, timers, writes, delays, advance };
}
const refusal = (
  client,
  { action = 'session.login', code = 'invalid_credentials', login = 'admin' } = {}
) => ({
  action,
  outcome:
    code === 'invalid_credentials' || code === 'current_password_incorrect' ? 'failed' : 'denied',
  client,
  userAgent: 'curl/8.5.0',
  login,
  detail: { code },
});

test('budget: per action and UTC hour one immediate row and one summary; auth.basic.used per UTC day', async () => {
  const h = harness();
  for (let n = 0; n < 5; n++) h.aggregator.count(refusal(`192.0.2.${n}`));
  for (let n = 0; n < 3; n++)
    h.aggregator.count({
      action: 'account.password.changed',
      outcome: 'failed',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_1' },
      client: '192.0.2.50',
      detail: { code: 'current_password_incorrect' },
    });
  for (let n = 0; n < 4; n++)
    h.aggregator.count({
      action: 'auth.basic.used',
      outcome: 'ok',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'basic', sessionId: null },
      client: `198.51.100.${n}`,
    });
  await h.aggregator.idle();
  assert.deepEqual(
    h.writes.map(w => [w.action, w.kind, w.count ?? 1]),
    [
      ['session.login', 'immediate', 1],
      ['account.password.changed', 'immediate', 1],
      ['auth.basic.used', 'immediate', 1],
    ]
  );
  const [login, password, basic] = h.writes;
  assert.deepEqual(login.actor.type, 'anonymous');
  assert.deepEqual(login.target, { type: 'account', id: 'admin', name: null });
  assert.deepEqual(login.detail, { code: 'invalid_credentials', login: 'admin' });
  assert.equal(login.client, '192.0.2.0');
  assert.equal(password.actor.via, 'session');
  assert.deepEqual(password.target, { type: 'account', id: 'u_admin', name: null });
  assert.deepEqual(password.detail, { code: 'current_password_incorrect' });
  assert.equal(basic.detail, null);
  await h.advance(HOUR);
  const summaries = h.writes.filter(w => w.kind === 'summary');
  assert.deepEqual(
    summaries.map(w => [w.action, w.count, w.at]),
    [
      ['session.login', 4, Date.UTC(2026, 9, 3, 1)],
      ['account.password.changed', 2, Date.UTC(2026, 9, 3, 1)],
    ]
  );
  assert.deepEqual(summaries[0].detail, {
    codes: { invalid_credentials: 4 },
    clients: 4,
    more: false,
    sample: ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'],
    from: Date.UTC(2026, 9, 3, 0),
    to: Date.UTC(2026, 9, 3, 0),
  });
  assert.equal(summaries[0].outcome, 'failed');
  assert.equal(summaries[0].client, undefined);
  assert.deepEqual(summaries[0].target, { type: 'account', id: null, name: null });
  // A new hour: a new immediate row. auth.basic.used waits for the end of its UTC day.
  h.aggregator.count(refusal('192.0.2.99', { code: 'locked' }));
  await h.aggregator.idle();
  assert.equal(h.writes.at(-1).kind, 'immediate');
  await h.advance(DAY);
  const basicSummary = h.writes.find(w => w.action === 'auth.basic.used' && w.kind === 'summary');
  assert.equal(basicSummary.count, 3);
  assert.equal(basicSummary.at, Date.UTC(2026, 9, 4));
  assert.equal(basicSummary.outcome, 'ok');
  assert.deepEqual(windowOf('auth.basic.used', Date.UTC(2026, 9, 4, 13)), {
    start: Date.UTC(2026, 9, 4),
    end: Date.UTC(2026, 9, 5),
  });
});

test('flood: 10 new client keys a minute for 24 hours write exactly 48 session.login rows, their counts summing to the events', async () => {
  const h = harness();
  let events = 0;
  for (let minute = 0; minute < 24 * 60; minute++) {
    for (let n = 0; n < 10; n++) {
      h.aggregator.count(
        refusal(`10.${minute >> 8}.${minute & 255}.${n}`, { login: `user${minute}-${n}` })
      );
      events += 1;
    }
    await h.advance(MINUTE);
  }
  await h.advance(HOUR);
  const rows = h.writes.filter(w => w.action === 'session.login');
  assert.equal(rows.length, 48);
  assert.equal(rows.filter(w => w.kind === 'immediate').length, 24);
  assert.equal(
    rows.reduce((sum, w) => sum + (w.count ?? 1), 0),
    events
  );
});

test('clients cap: 10,000 refusals from 1,500 client keys in 10 minutes count 1,000 clients, more, and a sample of 10', async () => {
  const h = harness();
  for (let n = 0; n < 10000; n++) {
    h.aggregator.count(refusal(`client-${n % 1500}`));
    if (n % 1000 === 999) await h.advance(MINUTE);
  }
  await h.advance(HOUR);
  const summary = h.writes.find(w => w.kind === 'summary');
  assert.equal(summary.count, 9999);
  assert.equal(summary.detail.clients, 1000);
  assert.equal(summary.detail.more, true);
  assert.equal(summary.detail.sample.length, 10);
  assert.deepEqual(
    summary.detail.sample,
    Array.from({ length: 10 }, (_, i) => `client-${i + 1}`)
  );
});

test('400 days: continuous refusals on both anonymous actions write at most 96 rows a day', async () => {
  const h = harness();
  let written = 0;
  const days = 400;
  for (let step = 0; step < days * 24 * 6; step++) {
    h.aggregator.count(refusal(`a-${step % 7}`));
    h.aggregator.count(refusal(`b-${step % 5}`, { action: 'auth.basic.failed', login: 'svc' }));
    await h.advance(10 * MINUTE);
  }
  written = h.writes.length;
  assert.ok(written <= 96 * days, `${written} rows`);
  assert.ok(written >= 94 * days, 'a row each window, immediate and summary');
});

// Independent review A5: a password change refused before a credential signed in (none sent, an
// ended session) is counted as nobody signed in, beside the refusals a signed-in session gets.
// A summary names its first actor; one that mixes both names the first signed-in session (its
// `codes` show which refusals came before sign-in), never no one: only a signed-in session can
// make the change's own refusals, and naming no one let a client nobody authenticated wipe that
// session's id from the log (A5 verification). Each alone keeps its actor, as before.
const a5Actors = () => ({
  admin: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_1' },
  stolen: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_2' },
  anonymous: { type: 'anonymous', id: null, name: null, via: null, sessionId: null },
});
const passwordRefusal = (actor, code, client = '192.0.2.60') => ({
  action: 'account.password.changed',
  outcome: code === 'current_password_incorrect' ? 'failed' : 'denied',
  actor,
  client,
  userAgent: 'curl/8.5.0',
  detail: { code },
});

test('Independent review A5: a summary mixing refusals of nobody signed in with those of a session names that session; each alone keeps its actor', async () => {
  let failing = false;
  const h = harness({ fails: (event, kind) => failing && kind === 'summary' });
  const { admin, anonymous } = a5Actors();
  const refused = passwordRefusal;
  const hour = async events => {
    for (const event of events) h.aggregator.count(event);
    await h.advance(HOUR);
  };
  const rows = () => h.writes.map(w => [w.kind, w.actor.type, w.actor.sessionId ?? null]);
  // Nobody signed in first: its immediate row names no one; the mixed summary names the admin.
  await hour([
    refused(anonymous, 'signin_required'),
    refused(admin, 'current_password_incorrect'),
    refused(anonymous, 'session_expired', '192.0.2.61'),
  ]);
  assert.deepEqual(h.writes[0].target, { type: 'account', id: 'u_admin', name: null });
  assert.deepEqual(h.writes[0].detail, { code: 'signin_required' });
  // The admin first, then nobody signed in: the summary still names the admin.
  await hour([
    refused(admin, 'password_mismatch'),
    refused(admin, 'current_password_incorrect'),
    refused(anonymous, 'signin_required', '192.0.2.62'),
  ]);
  // Only the admin, or only nobody signed in: the summary keeps their actor, as before.
  await hour([refused(admin, 'password_mismatch'), refused(admin, 'password_invalid')]);
  await hour([refused(anonymous, 'signin_required'), refused(anonymous, 'session_expired')]);
  assert.deepEqual(rows(), [
    ['immediate', 'anonymous', null],
    ['summary', 'user', 's_1'],
    ['immediate', 'user', 's_1'],
    ['summary', 'user', 's_1'],
    ['immediate', 'user', 's_1'],
    ['summary', 'user', 's_1'],
    ['immediate', 'anonymous', null],
    ['summary', 'anonymous', null],
  ]);
  assert.deepEqual(h.writes[1].detail.codes, { current_password_incorrect: 1, session_expired: 1 });
  assert.deepEqual(h.writes[3].detail.codes, { current_password_incorrect: 1, signin_required: 1 });
  // Counts carried past a summary that could not be written: the admin's, then nobody's.
  h.writes.length = 0;
  failing = true;
  await hour([refused(admin, 'password_mismatch'), refused(admin, 'password_invalid')]);
  failing = false;
  await hour([refused(anonymous, 'signin_required'), refused(anonymous, 'session_expired')]);
  assert.deepEqual(rows(), [
    ['immediate', 'user', 's_1'],
    ['immediate', 'anonymous', null],
    ['summary', 'user', 's_1'],
  ]);
  assert.equal(h.writes.at(-1).count, 2);
  // Nobody's carried back while the admin's were counted (the hour ended with no timer run, the
  // summary's write failed): put back beside them, they go under the admin's session.
  h.writes.length = 0;
  h.aggregator.count(refused(anonymous, 'signin_required'));
  h.aggregator.count(refused(anonymous, 'session_expired'));
  await h.aggregator.idle();
  h.clock.set(h.clock() + HOUR);
  failing = true;
  h.aggregator.count(refused(admin, 'password_mismatch'));
  h.aggregator.count(refused(admin, 'password_invalid'));
  await h.aggregator.idle();
  failing = false;
  await h.advance(HOUR);
  assert.deepEqual(rows(), [
    ['immediate', 'anonymous', null],
    ['immediate', 'user', 's_1'],
    ['summary', 'user', 's_1'],
  ]);
  assert.deepEqual(h.writes.at(-1).detail.codes, { session_expired: 1, password_invalid: 1 });
  // The admin's carried counts with the admin's again keep the admin.
  h.writes.length = 0;
  failing = true;
  await hour([refused(admin, 'password_mismatch'), refused(admin, 'password_invalid')]);
  failing = false;
  await hour([refused(admin, 'password_mismatch'), refused(admin, 'password_invalid')]);
  assert.deepEqual(rows(), [
    ['immediate', 'user', 's_1'],
    ['immediate', 'user', 's_1'],
    ['summary', 'user', 's_1'],
  ]);
});

// A5 verification: with a summary that mixed both naming no one, a thief holding a stolen
// session sent two password changes without a credential at the top of the hour (the first
// takes the immediate row, the second puts nobody into the summary), then guessed the current
// password from the session: no row named the session. The guesses must name it, however the
// refusals of nobody signed in surround them, written at once or carried past a failed summary.
test('Independent review A5: refusals before sign-in cannot wipe a guessing session from the log; two of them and four guesses still name it', async () => {
  let failing = false;
  const h = harness({ fails: (event, kind) => failing && kind === 'summary' });
  const { stolen, anonymous } = a5Actors();
  const refused = passwordRefusal;
  const guesses = n =>
    Array.from({ length: n }, () => refused(stolen, 'current_password_incorrect', '192.0.2.70'));
  const named = () => h.writes.filter(w => w.actor.sessionId === 's_2');
  // Two refusals before sign-in, then four guesses, in one hour.
  for (const event of [
    refused(anonymous, 'signin_required', '192.0.2.71'),
    refused(anonymous, 'signin_required', '192.0.2.71'),
    ...guesses(4),
  ])
    h.aggregator.count(event);
  await h.advance(HOUR);
  assert.deepEqual(
    h.writes.map(w => [w.kind, w.outcome, w.count ?? 1, w.actor.type, w.actor.sessionId]),
    [
      ['immediate', 'denied', 1, 'anonymous', null],
      ['summary', 'failed', 5, 'user', 's_2'],
    ]
  );
  assert.deepEqual(h.writes[1].detail.codes, { current_password_incorrect: 4, signin_required: 1 });
  // Refusals before sign-in on either side of the guesses: the session is still named.
  h.writes.length = 0;
  for (const event of [
    refused(anonymous, 'signin_required'),
    refused(anonymous, 'session_expired'),
    ...guesses(3),
    refused(anonymous, 'signin_required'),
    refused(anonymous, 'session_expired'),
  ])
    h.aggregator.count(event);
  await h.advance(HOUR);
  assert.deepEqual(
    named().map(w => [w.kind, w.count]),
    [['summary', 6]]
  );
  // The guesses' summary could not be written and carries into an hour of refusals of nobody
  // signed in, counted while the failing write was still in flight: still the session.
  h.writes.length = 0;
  for (const event of [refused(anonymous, 'signin_required'), ...guesses(3)])
    h.aggregator.count(event);
  await h.aggregator.idle();
  h.clock.set(h.clock() + HOUR);
  failing = true;
  h.aggregator.count(refused(anonymous, 'signin_required'));
  h.aggregator.count(refused(anonymous, 'session_expired'));
  h.aggregator.count(refused(anonymous, 'session_expired'));
  await h.aggregator.idle();
  failing = false;
  await h.advance(HOUR);
  assert.deepEqual(
    h.writes.map(w => [w.kind, w.actor.type, w.actor.sessionId]),
    [
      ['immediate', 'anonymous', null],
      ['immediate', 'anonymous', null],
      ['summary', 'user', 's_2'],
    ]
  );
  assert.deepEqual(h.writes[2].detail.codes, {
    current_password_incorrect: 3,
    session_expired: 2,
  });
  // The guesses alone, as a control: named at once and in the summary.
  h.writes.length = 0;
  for (const event of guesses(4)) h.aggregator.count(event);
  await h.advance(HOUR);
  assert.deepEqual(
    named().map(w => [w.kind, w.count ?? 1]),
    [
      ['immediate', 1],
      ['summary', 3],
    ]
  );
});

// Independent review A5: a client nobody authenticated now reaches a third aggregated action (the
// password change refused before sign-in), so it can make Uptime Goblin write at most 144 rows a day.
test('Independent review A5: continuous refusals on the three actions a client nobody authenticated reaches write at most 144 rows a day', async () => {
  const h = harness();
  const days = 7;
  const anonymous = { type: 'anonymous', id: null, name: null, via: null, sessionId: null };
  for (let step = 0; step < days * 24 * 6; step++) {
    h.aggregator.count(refusal(`a-${step % 7}`));
    h.aggregator.count(refusal(`b-${step % 5}`, { action: 'auth.basic.failed', login: 'svc' }));
    h.aggregator.count({
      ...refusal(`c-${step % 3}`, { action: 'account.password.changed', code: 'signin_required' }),
      actor: anonymous,
    });
    await h.advance(10 * MINUTE);
  }
  assert.ok(h.writes.length <= 144 * days, `${h.writes.length} rows`);
  assert.ok(h.writes.length >= 141 * days, 'a row each window, immediate and summary');
  assert.ok(h.writes.every(w => w.actor.type === 'anonymous'));
});

test('login class: only admin, other or null is stored, and nothing derived from another login', async () => {
  assert.equal(loginClass('admin'), 'admin');
  assert.equal(loginClass(' ADMIN '), 'admin');
  assert.equal(loginClass('ａｄｍｉｎ'), 'admin', 'NFKC');
  assert.equal(loginClass('administrator'), 'other');
  assert.equal(loginClass(''), null);
  assert.equal(loginClass('   '), null);
  assert.equal(loginClass(null), null);
  assert.equal(loginClass(42), null);
  const typed = 'CanaryTypedIntoLogin-0f1e2d3c';
  const h = harness();
  h.aggregator.count(refusal('192.0.2.1', { login: typed }));
  h.aggregator.count(refusal('192.0.2.2', { login: typed }));
  h.aggregator.count(refusal('192.0.2.3', { action: 'auth.basic.failed', login: typed }));
  await h.advance(HOUR);
  const text = JSON.stringify(h.writes);
  assert.ok(!text.includes(typed));
  assert.ok(!text.includes('CanaryTypedIntoLogin'));
  assert.deepEqual(
    h.writes.filter(w => w.kind === 'immediate').map(w => [w.detail.login, w.target.id]),
    [
      ['other', null],
      ['other', null],
    ]
  );
});

test('guard full: nothing is written while full, then one summary holds every count', async () => {
  let full = true;
  const h = harness({ full: () => full });
  for (let n = 0; n < 20; n++) h.aggregator.count(refusal(`192.0.2.${n}`));
  await h.advance(3 * HOUR);
  assert.deepEqual(h.writes, []);
  full = false;
  h.aggregator.count(refusal('192.0.2.200'));
  await h.advance(HOUR);
  const summary = h.writes.find(w => w.kind === 'summary');
  assert.equal(summary.count, 20);
  assert.equal(summary.detail.from, Date.UTC(2026, 9, 3, 0), 'from keeps the earliest time');
  assert.equal(h.writes.filter(w => w.kind === 'immediate').length, 1);
});

test('failed flush: counts that could not be written carry into the next summary', async () => {
  let failing = true;
  const h = harness({ fails: (event, kind) => failing && kind === 'summary' });
  for (let n = 0; n < 4; n++) h.aggregator.count(refusal(`192.0.2.${n}`));
  await h.advance(HOUR);
  assert.equal(h.writes.filter(w => w.kind === 'summary').length, 0);
  assert.equal(h.aggregator.pending()['session.login'].count, 3);
  failing = false;
  h.aggregator.count(refusal('192.0.2.9'));
  h.aggregator.count(refusal('192.0.2.10'));
  await h.advance(HOUR);
  const summaries = h.writes.filter(w => w.kind === 'summary');
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].count, 4, '3 carried + 1 counted (the other took the immediate row)');
  assert.deepEqual(h.aggregator.pending(), {});
});

test('a failed immediate row is counted into the summary', async () => {
  const h = harness({ fails: (event, kind) => kind === 'immediate' });
  h.aggregator.count(refusal('192.0.2.1'));
  h.aggregator.count(refusal('192.0.2.2'));
  await h.aggregator.idle();
  await h.advance(HOUR);
  assert.deepEqual(
    h.writes.map(w => [w.kind, w.count]),
    [['summary', 2]]
  );
});

// Review round 2: a window opened while the clock was ahead kept its end after the clock was
// stepped back, so its timer waited for that end; more than 2^31 ms away, Node fired it at once,
// flush() wrote nothing (the window had not ended) and armed it again: a 1 ms loop that held the
// waiting counts back until the clock caught up.
test('clock stepped back: counts waiting in a window that now begins later reach a summary within the hour, and no timer waits longer than a window', async () => {
  const ahead = Date.UTC(2027, 9, 3, 12, 59, 59, 850),
    back = Date.UTC(2026, 9, 3, 12, 59, 59, 850);
  const h = harness({ start: ahead });
  for (let n = 0; n < 3; n++) h.aggregator.count(refusal(`192.0.2.${n}`));
  await h.aggregator.idle();
  assert.deepEqual(
    h.writes.map(w => w.kind),
    ['immediate']
  );
  h.clock.set(back);
  // The timer armed before the step fires after its own delay, whatever the clock says, and the
  // hourly job flushes too.
  for (const timer of [...h.timers]) {
    h.timers.delete(timer);
    timer.fn();
  }
  await h.aggregator.flush();
  await h.aggregator.idle();
  assert.ok(
    h.delays.every(ms => ms >= 0 && ms <= HOUR),
    `every delay at most a window: ${h.delays.join(', ')}`
  );
  await h.advance(HOUR);
  const summaries = h.writes.filter(w => w.kind === 'summary');
  assert.deepEqual(
    summaries.map(w => [w.count, w.at]),
    [[2, Date.UTC(2026, 9, 3, 13)]]
  );
  assert.deepEqual(h.aggregator.pending(), {});
  assert.ok(
    h.delays.every(ms => ms >= 0 && ms <= HOUR),
    h.delays.join(', ')
  );

  // An event after the step: what waited for the later window is written at once, dated now.
  const g = harness({ start: ahead });
  for (let n = 0; n < 3; n++) g.aggregator.count(refusal(`192.0.2.${n}`));
  await g.aggregator.idle();
  g.clock.set(back);
  g.aggregator.count(refusal('192.0.2.9'));
  await g.aggregator.idle();
  assert.deepEqual(
    g.writes.map(w => [w.kind, w.count ?? 1, w.at]),
    [
      ['immediate', 1, ahead],
      ['summary', 2, back],
      ['immediate', 1, back],
    ]
  );
});

test('close flush and idle: a forced flush writes what waits; no timer is armed while nothing waits', async () => {
  const h = harness();
  assert.equal(h.aggregator.armed, false);
  h.aggregator.count(refusal('192.0.2.1'));
  await h.aggregator.idle();
  assert.equal(h.aggregator.armed, false, 'the immediate row leaves nothing waiting');
  h.aggregator.count(refusal('192.0.2.2'));
  assert.equal(h.aggregator.armed, true);
  await h.aggregator.flush({ force: true });
  assert.equal(h.writes.at(-1).kind, 'summary');
  assert.equal(h.writes.at(-1).at, h.clock(), 'forced before the window ends: now');
  assert.equal(h.aggregator.armed, false);
  h.aggregator.stop();
  // count() never throws, whatever it is given.
  h.aggregator.count(null);
  h.aggregator.count({ action: 'session.login', detail: { code: 5 }, client: {}, at: 'x' });
  h.aggregator.count({ action: 'not.aggregated' });
});

test('through the service: the immediate row and the summary are rows of the log; while full nothing, then the summary', async t => {
  const guard = { full: false, state: () => ({ full: guard.full }) };
  const { audit, db, clock, err } = await auditFixture(t, {
    guard,
    clock: manualClock(Date.UTC(2026, 9, 3, 0)),
  });
  audit.count(refusal('192.0.2.1'));
  await audit.idle();
  guard.full = true;
  for (let n = 0; n < 20; n++) audit.count(refusal(`192.0.2.${n + 10}`, { login: `name${n}` }));
  await audit.idle();
  assert.equal((await storedRows(db)).length, 1);
  guard.full = false;
  clock.advance(HOUR);
  await audit.maintain({});
  await audit.idle();
  const rows = (await storedRows(db)).filter(row => row.action === 'session.login');
  assert.deepEqual(
    rows.map(row => [row.count, row.client_key, row.time]),
    [
      [1, '192.0.2.1', Date.UTC(2026, 9, 3, 0)],
      [20, null, Date.UTC(2026, 9, 3, 1)],
    ]
  );
  assert.equal(rows[1].detail.clients, 20);
  assert.deepEqual(
    linesOf(err, 'audit.unwritten'),
    [],
    'aggregated events are counted, never printed'
  );
});

// Review round 2: docs/authentication.md described the refused script sign-ins of the Scripts
// with a password kind as "counted the same way" as the daily auth.basic.used rows; they are
// counted per UTC hour (D9), so a script refused all day leaves up to 48 entries, not 2.
test('docs: Scripts with a password counts uses per day and refusals per hour, as authentication.md says', async () => {
  const h = harness();
  // One refused and one accepted Basic sign-in every 10 minutes for one UTC day.
  for (let minute = 0; minute < 24 * 60; minute += 10) {
    h.aggregator.count(refusal('192.0.2.7', { action: 'auth.basic.failed', login: 'svc' }));
    h.aggregator.count({
      action: 'auth.basic.used',
      outcome: 'ok',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'basic', sessionId: null },
      client: '198.51.100.7',
    });
    await h.advance(10 * MINUTE);
  }
  const rows = action => h.writes.filter(w => w.action === action).map(w => w.kind);
  assert.deepEqual(rows('auth.basic.used'), ['immediate', 'summary']);
  assert.equal(rows('auth.basic.failed').length, 48);
  assert.equal(rows('auth.basic.failed').filter(kind => kind === 'immediate').length, 24);
  const guide = fs.readFileSync(new URL('../../docs/authentication.md', import.meta.url), 'utf8');
  const paragraph = guide.slice(
    guide.indexOf('To see which scripts still use Basic'),
    guide.indexOf('\n\n## Lockouts')
  );
  assert.match(paragraph, /the first script sign-in of each day gets an entry/);
  assert.match(paragraph, /a summary at the end of the day/);
  assert.doesNotMatch(paragraph, /counted the same way/);
  assert.match(
    paragraph,
    /Refused script sign-ins are listed there too, counted by the hour instead: the first of each hour gets an entry at once, and the others of that hour one summary at its end\./
  );
});
