// Wall displays (B6 design §7): one-time display codes, their redemption into read-only kiosk
// sessions with their own limits, and what a kiosk session may and may not do.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  newDisplayCode,
  displayCodeHash,
  displayAlphabet,
  isDisplayId,
} from '../../lib/identity/secrets.mjs';
import { identityOps } from '../../lib/repo/identity.mjs';
import { temporary, startIdentity, rows, adminPassword } from './helpers.mjs';
import { displaysAfterUpgradeMessage } from '../../server.mjs';

const minute = 60e3,
  hour = 60 * minute,
  day = 24 * hour;
const change = (from, to) => ({ currentPassword: from, password: to, confirmPassword: to });
const invalid = stale => error =>
  error.code === 'display_code_invalid' && error.status === 401 && error.stale === stale;

async function started(t, options = {}) {
  const context = await startIdentity(t, temporary(t), { password: adminPassword, ...options });
  const signIn = (extra = {}) =>
    context.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.7',
      userAgent: 'test agent',
      ...extra,
    });
  // A waiting code, as goblin-admin display code makes it.
  const waiting = async ({ name = 'Lobby TV', lifetime = 10 * minute } = {}) => {
    const made = newDisplayCode();
    const now = context.clock();
    await context.db.write(tx =>
      identityOps.insertDisplay(tx, {
        id: made.id,
        name,
        codeHash: made.codeHash,
        codeExpiresAt: now + lifetime,
        createdAt: now,
        createdBy: 'cli:test',
      })
    );
    return made;
  };
  const redeem = (code, extra = {}) =>
    context.identity.redeemDisplayCode({
      code,
      client: '192.0.2.50',
      userAgent: 'wall display',
      ...extra,
    });
  return { ...context, signIn, waiting, redeem };
}

test('a display code is 25 Crockford symbols and a check symbol; its input is forgiving', () => {
  const { id, code, codeHash } = newDisplayCode();
  assert.ok(isDisplayId(id));
  assert.match(code, /^([0-9A-Z]{5}-){5}[0-9A-Z]$/);
  for (const symbol of code.replaceAll('-', '')) assert.ok(displayAlphabet.includes(symbol));
  const data = code.replaceAll('-', '').slice(0, 25);
  assert.equal(
    codeHash,
    createHash('sha256').update(`orbit-display-code-v1\0${data}`).digest('hex')
  );
  assert.equal(displayCodeHash(code), codeHash);
  assert.equal(displayCodeHash(code.toLowerCase()), codeHash);
  assert.equal(displayCodeHash(code.replaceAll('-', ' ')), codeHash);
  assert.equal(displayCodeHash(code.replaceAll('-', '')), codeHash);
  // I and L read as 1, O as 0: the letters a reader may take a printed digit for.
  const ones = code.replaceAll('1', 'l').replaceAll('0', 'O');
  assert.equal(displayCodeHash(ones), codeHash);
  // A wrong check symbol, a short code, a symbol outside the alphabet, an over-long input.
  const check = code.at(-1);
  const other = displayAlphabet[(displayAlphabet.indexOf(check) + 1) % 32];
  assert.equal(displayCodeHash(code.slice(0, -1) + other), null);
  assert.equal(displayCodeHash(code.slice(0, -3)), null);
  assert.equal(displayCodeHash('U' + code.slice(1)), null);
  assert.equal(displayCodeHash(code + ' '.repeat(40)), null);
  assert.equal(displayCodeHash(null), null);
  assert.notEqual(newDisplayCode().code, code);
});

test('a code signs a wall display in once, read-only, for 30 days with a 7-day idle limit', async t => {
  const { identity, control, clock, waiting, redeem, events } = await started(t);
  const made = await waiting();
  const result = await redeem(made.code);
  assert.equal(result.access.kind, 'kiosk');
  assert.deepEqual([...result.access.permissions].sort(), ['dashboard:read', 'session:self']);
  assert.deepEqual(result.display, { id: made.id, name: 'Lobby TV' });
  assert.equal(result.issue.persistent, true);
  assert.equal(result.issue.expiresAt, clock() + 30 * day);
  const [session] = (await rows(control, 'sessions')).filter(row => row.kind === 'kiosk');
  assert.equal(session.idle_expires_at, clock() + 7 * day);
  const [display] = await rows(control, 'displays');
  assert.equal(display.state, 'redeemed');
  assert.equal(display.session_id, session.id);
  const login = events.find(row => row.action === 'session.login');
  assert.equal(login.detail.kind, 'kiosk');
  assert.equal(login.detail.display, made.id);

  // Used once: a second redemption is refused as stale (not a guess).
  await assert.rejects(redeem(made.code), invalid(true));
  // A code that was never made counts as a guess.
  await assert.rejects(redeem(newDisplayCode().code), invalid(false));
  // So does one that is not a code at all, before any lookup.
  await assert.rejects(
    redeem('not a code'),
    error => error.code === 'invalid_request' && /not a display code/.test(error.message)
  );

  const described = identity.describe(result.access);
  assert.equal(described.kind, 'kiosk');
  assert.equal(described.user, null);
});

test('a wall display that only polls stays signed in; it signs out after 7 quiet days or 30 days', async t => {
  const { identity, clock, waiting, redeem } = await started(t);
  const value = (await redeem((await waiting()).code)).issue.value;
  // Every request of a wall display is activity, even the background reads that do not keep an
  // admin's page signed in: the display shows the dashboard and nothing else.
  for (let i = 0; i < 4; i++) {
    clock.advance(6 * day);
    const access = await identity.authenticateSession(value, { activity: 'background' });
    assert.equal(access.kind, 'kiosk');
  }
  clock.advance(6 * day + hour);
  assert.equal(await identity.authenticateSession(value, { activity: 'background' }), null);

  const quiet = (await redeem((await waiting()).code)).issue.value;
  clock.advance(7 * day + minute);
  assert.equal(await identity.authenticateSession(quiet), null);
});

test('signedInDisplays counts live wall displays only, for the start line after an upgrade', async t => {
  const { identity, clock, signIn, waiting, redeem } = await started(t);
  await signIn();
  assert.equal(await identity.signedInDisplays(), 0);
  await redeem((await waiting()).code);
  await redeem((await waiting({ name: 'Hall' })).code);
  assert.equal(await identity.signedInDisplays(), 2);
  assert.equal(
    displaysAfterUpgradeMessage(2),
    '2 wall displays are signed in. If an earlier Uptime Goblin release ran since this one last did, it could not show or sign them out: check Configure → Account → Sessions.'
  );
  assert.match(displaysAfterUpgradeMessage(1), /^1 wall display is signed in\. .*sign it out/);
  clock.advance(7 * day + minute);
  assert.equal(await identity.signedInDisplays(), 0);
});

test('GOBLIN_DISPLAY_SESSION_DAYS and GOBLIN_DISPLAY_IDLE_DAYS set a display session’s limits', async t => {
  const { clock, waiting, redeem, control } = await started(t, {
    displayLimits: { absoluteMs: 2 * day, idleMs: 1 * day },
  });
  const result = await redeem((await waiting()).code);
  assert.equal(result.issue.expiresAt, clock() + 2 * day);
  const [session] = (await rows(control, 'sessions')).filter(row => row.kind === 'kiosk');
  assert.equal(session.idle_expires_at, clock() + day);
});

test('an expired or cancelled code is refused without counting as a guess', async t => {
  const { identity, clock, waiting, redeem, events } = await started(t);
  const late = await waiting({ lifetime: 10 * minute });
  clock.advance(10 * minute);
  await assert.rejects(redeem(late.code), invalid(true));

  const crossed = await waiting();
  assert.equal(await identity.cancelDisplayCode(crossed.code), true);
  assert.equal(await identity.cancelDisplayCode(crossed.code), false);
  await assert.rejects(redeem(crossed.code), invalid(true));
  const cancelled = events.filter(row => row.action === 'display.code.cancelled');
  assert.equal(cancelled.length, 1);
  assert.equal(cancelled[0].detail.cause, 'plain_http');
  assert.equal(cancelled[0].target.id, crossed.id);
});

test('a code over plain HTTP without the opt-in is refused before it is looked up', async t => {
  const { waiting, redeem, control } = await started(t);
  const made = await waiting();
  await assert.rejects(
    redeem(made.code, { transport: 'http' }),
    error => error.code === 'https_required' && /Uptime Goblin cancelled it/.test(error.message)
  );
  assert.equal((await rows(control, 'displays'))[0].state, 'waiting');
});

test('a wall display cannot manage sessions or the password; the admin can sign it out', async t => {
  const { identity, waiting, redeem, signIn } = await started(t);
  const admin = (await signIn()).access;
  const display = (await redeem((await waiting()).code)).access;
  const forbidden = error => error.code === 'forbidden';
  await assert.rejects(identity.listSessions(display), forbidden);
  await assert.rejects(identity.revokeOtherSessions(display), forbidden);
  await assert.rejects(identity.revokeSession(display, admin.sessionId), forbidden);
  await assert.rejects(
    identity.changePassword(display, change(adminPassword, 'a new long password')),
    forbidden
  );

  const listed = await identity.listSessions(admin);
  const shown = listed.sessions ?? listed;
  const entry = shown.find(row => row.id === display.sessionId);
  assert.ok(entry, 'the admin sees the wall display among the sessions');
  const ended = await identity.revokeSession(admin, display.sessionId);
  assert.equal(ended.found, true);
  assert.throws(() => identity.assertCurrent(display));
  // A wall display may sign itself out.
  const again = (await redeem((await waiting()).code)).access;
  await identity.logout(again);
  assert.throws(() => identity.assertCurrent(again));
});

test('changing the password ends wall displays and cancels the codes still waiting', async t => {
  const { identity, control, waiting, redeem, signIn, events } = await started(t);
  const admin = (await signIn()).access;
  const display = (await redeem((await waiting()).code)).access;
  const pending = await waiting({ name: 'Hall' });
  await identity.changePassword(admin, change(adminPassword, 'a brand new admin password'));
  assert.throws(() => identity.assertCurrent(display));
  const row = (await rows(control, 'displays')).find(entry => entry.id === pending.id);
  assert.equal(row.state, 'cancelled');
  assert.equal(row.cancel_cause, 'password_change');
  const cancelled = events.find(entry => entry.action === 'display.code.cancelled');
  assert.equal(cancelled.detail.cause, 'password_change');
  assert.equal(cancelled.detail.count, 1);
});

test('prune records the cancellations goblin-admin could not audit, and drops old displays', async t => {
  const { identity, control, clock, waiting, events, db } = await started(t);
  const owed = await waiting({ name: 'Keyless' });
  await db.write(tx =>
    identityOps.cancelDisplays(tx, {
      ids: [owed.id],
      cause: 'cancelled',
      now: clock(),
      recorded: false,
    })
  );
  await identity.prune();
  const recorded = events.filter(row => row.action === 'display.code.cancelled');
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].target.id, owed.id);
  assert.equal(recorded[0].detail.late, true);
  await identity.prune();
  assert.equal(events.filter(row => row.action === 'display.code.cancelled').length, 1);

  clock.advance(40 * day);
  await identity.prune();
  assert.equal((await rows(control, 'displays')).length, 0);
});
