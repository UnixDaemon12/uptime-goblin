// The Account page (#configure/account): how you are signed in, changing your password, and
// the devices where you are signed in, each of which you can sign out.
import { api } from '../core/api.js';
import { $, esc, icon } from '../core/dom.js';
import { dateTime } from '../core/format.js';
import { formSnapshot, lockForm, updateDirtyIndicator } from '../core/forms.js';
import { page } from '../core/page.js';
import { applySession, bannerTexts, currentSession } from './session.js';
import { signInTexts } from './signin.js';

/** A short name for the browser and system in a User-Agent, for the sessions list. */
export function deviceName(userAgent) {
  if (!userAgent) return 'Unknown device';
  const ua = String(userAgent);
  const browser = /Edg(?:e|A|iOS)?\//.test(ua)
    ? 'Edge'
    : /OPR\//.test(ua)
      ? 'Opera'
      : /Firefox\/|FxiOS\//.test(ua)
        ? 'Firefox'
        : /Chrome\/|CriOS\//.test(ua)
          ? 'Chrome'
          : /Safari\//.test(ua)
            ? 'Safari'
            : '';
  const system = /iPhone|iPad|iPod/.test(ua)
    ? 'iOS'
    : /Android/.test(ua)
      ? 'Android'
      : /CrOS/.test(ua)
        ? 'ChromeOS'
        : /Macintosh|Mac OS X/.test(ua)
          ? 'macOS'
          : /Windows/.test(ua)
            ? 'Windows'
            : /Linux/.test(ua)
              ? 'Linux'
              : '';
  if (browser && system) return `${browser} on ${system}`;
  if (browser || system) return browser || system;
  // A script or an unusual browser: its own words, shortened.
  return ua.length > 60 ? `${ua.slice(0, 59)}…` : ua;
}
/** When a session ends if nothing else happens: its idle limit or its absolute one. */
const endsAt = s => Math.min(s.expiresAt, s.idleExpiresAt);
// A session cannot end one that signed in after it (Uptime Goblin refuses: a cookie copied from a lost
// device must not be able to end the sign-ins that prove the password), so such a row offers no
// Sign out, and this says what does.
const newerLabel = 'Signed in later';
const newerNote = `“${newerLabel}”: that device signed in after this one, so only a newer sign-in can sign it out. If you do not recognise it, change your password, which signs out every other device. Otherwise sign out here and sign in again, then sign it out.`;
/**
 * What the page says when Uptime Goblin did not answer (a restart, a dropped network, the time limit, a
 * proxy's error page: an error without `status`). The browser's own words for that ("Failed to
 * fetch", "Load failed") do not say whether a lost device was signed out, which is what this
 * page is for: a sign-out without an answer may or may not have happened.
 */
export const accountTexts = Object.freeze({
  revokeUnanswered:
    'Uptime Goblin did not confirm the sign-out, so that device may still be signed in. If it is still listed, sign it out again.',
  revokeOthersUnanswered:
    'Uptime Goblin did not confirm the sign-out, so your other devices may still be signed in. If any are still listed, sign them out again.',
});
/**
 * The text for a failed read of this page: the sign-in form's for no answer. Read when it is
 * needed, not when this module loads: signin.js may not have run yet (import cycles).
 */
const readFailure = error => (error.status === undefined ? signInTexts.network : error.message);

/** The page, drawn at once from what this tab knows; loadAccount() then asks Uptime Goblin. */
export function accountPage() {
  const s = currentSession();
  return `<section id="account-details" class="settings-block" aria-labelledby="account-details-title"><div class="settings-block-heading"><h3 id="account-details-title">Your sign-in</h3></div><div id="account-sign-in">${signInDetails(s)}</div></section><section class="settings-block" aria-labelledby="password-title"><div class="settings-block-heading"><h3 id="password-title">Change your password</h3><p>Confirm your current password, then choose a new one.</p></div><form id="password-form"><input id="password-username" name="username" type="text" autocomplete="username" value="${esc(s?.user?.login || 'admin')}" readonly hidden><div class="field"><label for="current-password">Current password</label><input id="current-password" name="current-password" type="password" autocomplete="current-password" required></div><div class="field"><label for="new-password">New password</label><input id="new-password" name="new-password" type="password" autocomplete="new-password" required aria-describedby="password-guidance"><small id="password-guidance">Use at least 12 characters. A long, unique passphrase is a good choice. Spaces are kept exactly as entered.</small></div><div class="field"><label for="confirm-new-password">Confirm new password</label><input id="confirm-new-password" name="confirm-new-password" type="password" autocomplete="new-password" required></div><p class="settings-info">This changes the admin password for Uptime Goblin. Your other devices are signed out; this one stays signed in.</p><p id="password-error" class="field-error" role="alert" hidden></p><p id="password-result" class="account-result" role="status" hidden></p><div class="save-bar password-save-bar"><span id="dirty-status" role="status">Your sign-in is unchanged</span><div><button class="button" type="button" data-discard>Discard</button><button class="button primary" type="submit">Change password</button></div></div></form></section><section id="account-sessions" class="settings-block" aria-labelledby="sessions-title"><div class="settings-block-heading"><h3 id="sessions-title" tabindex="-1">Where you are signed in</h3><p>Each browser you signed in with. Sign out any you no longer use or do not recognise.</p></div><div class="table-scroll"><table id="sessions-list" class="sessions-table"><caption>Sessions</caption><thead><tr><th scope="col">Device</th><th scope="col">Address</th><th scope="col">Signed in</th><th scope="col">Last active</th><th scope="col">Ends</th><th scope="col"><span class="sr-only">Action</span></th></tr></thead><tbody><tr><td colspan="6" class="loading">Reading your sessions…</td></tr></tbody></table></div><p id="sessions-newer" class="settings-info account-note" hidden>${esc(newerNote)}</p><p id="sessions-error" class="field-error" role="alert" hidden></p><p id="sessions-result" class="account-result" role="status" hidden></p><div class="inline-actions"><button class="button" type="button" id="sign-out-others" disabled>Sign out other devices</button></div></section>`;
}
function signInDetails(s) {
  if (!s) return '<p class="loading" role="status">Checking your sign-in…</p>';
  const session = s.session,
    facts = [
      ...(session
        ? [
            ['Signed in', dateTime(session.createdAt)],
            ['Ends', dateTime(endsAt(session))],
            ...(session.persistent ? [['On this device', 'Kept on this device']] : []),
          ]
        : []),
    ];
  // The idle limit moves on while Uptime Goblin is used; the absolute one does not.
  const idleFirst = session && session.idleExpiresAt < session.expiresAt;
  return `<div class="account-identity">${icon('lock', 20)}<div><span>Login name</span><strong>${esc(s.user?.login || '—')}</strong></div><small>${esc(s.user?.display || '')}</small></div>${facts.length ? `<dl class="system-facts">${facts.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>` : ''}${idleFirst ? `<p class="settings-info account-note">Using Uptime Goblin keeps you signed in, until ${esc(dateTime(session.expiresAt))} at the latest.${session.persistent ? '' : ' Closing the browser signs you out.'}</p>` : ''}`;
}

/**
 * Fills the page from Uptime Goblin: this session, and every session of yours. What an earlier action
 * on the list said (a refusal after Cancel included) no longer describes what it shows.
 */
export async function loadAccount() {
  if (!$('#account-details')) return;
  sessionsMessage('', '');
  await Promise.all([loadDetails(), loadSessions()]);
}
async function loadDetails() {
  const target = $('#account-sign-in');
  if (!target) return;
  try {
    const body = await api('/api/session');
    applySession(body);
    if (target === $('#account-sign-in')) target.innerHTML = signInDetails(body);
  } catch (error) {
    if (target === $('#account-sign-in'))
      target.innerHTML = `<p class="field-error" role="alert">${esc(readFailure(error))}</p><button class="button" type="button" data-retry-account>Try again</button>`;
  }
}
async function loadSessions() {
  const table = $('#sessions-list');
  if (!table) return;
  let sessions,
    problem = '';
  try {
    sessions = (await api('/api/account/sessions')).sessions;
    if (!Array.isArray(sessions)) problem = 'Uptime Goblin sent an unexpected list of sessions.';
  } catch (error) {
    problem = readFailure(error);
  }
  if (problem) {
    if (table !== $('#sessions-list')) return;
    table.tBodies[0].innerHTML = `<tr><td colspan="6"><span class="field-error">${esc(problem)}</span> <button class="quiet-button" type="button" data-retry-account>Try again</button></td></tr>`;
    $('#sign-out-others').disabled = true;
    $('#sessions-newer').hidden = true;
    return;
  }
  if (table !== $('#sessions-list')) return;
  table.tBodies[0].innerHTML =
    sessions
      .map(s => {
        // A wall display (B6 design §7.5) shows by the name its code was created with.
        const wall = s.kind === 'kiosk';
        const device = wall
          ? s.display
            ? `Wall display “${s.display}”`
            : 'Wall display'
          : deviceName(s.userAgent);
        return `<tr data-session="${esc(s.id)}"${s.current ? ' class="current-session"' : ''}${wall && !s.current && !s.newer ? ' data-wall' : ''}><td><span${s.userAgent ? ` title="${esc(s.userAgent)}"` : ''}>${esc(device)}</span>${wall ? '<small>Read only, with a display code</small>' : s.persistent ? '<small>Kept signed in</small>' : ''}</td><td>${esc(s.client || 'Unknown')}</td><td>${esc(dateTime(s.createdAt))}</td><td>${esc(dateTime(s.lastSeenAt))}</td><td>${esc(dateTime(endsAt(s)))}</td><td>${s.current ? '<span class="session-current">This device</span>' : s.newer ? `<span class="session-newer">${esc(newerLabel)}</span>` : `<button class="quiet-button" type="button" data-revoke-session="${esc(s.id)}" aria-label="Sign out ${esc(device)}, last active ${esc(dateTime(s.lastSeenAt))}">Sign out</button>`}</td></tr>`;
      })
      .join('') || '<tr><td colspan="6">No sessions.</td></tr>';
  $('#sign-out-others').disabled = !sessions.some(s => !s.current && !s.newer);
  $('#sessions-newer').hidden = !sessions.some(s => s.newer);
}
function sessionsMessage(error, result) {
  const alert = $('#sessions-error'),
    status = $('#sessions-result');
  if (!alert || !status) return;
  alert.textContent = error;
  alert.hidden = !error;
  status.textContent = result;
  status.hidden = !result;
}
/** Focus leaves with a removed row: it goes to the list's heading instead of the page. */
function focusSessions() {
  const heading = $('#sessions-title');
  if (heading && (!document.activeElement || document.activeElement === document.body))
    heading.focus({ preventScroll: true });
}
/**
 * Runs `request` for `button` of the sessions list, which says what it did (or why not:
 * `unanswered` when Uptime Goblin did not answer), then shows the list as it is now. The button is disabled meanwhile, which drops its focus to
 * <body>: it is page.busyFocus until then, as a form's control is (lockForm()), so a sign-in
 * dialog the request opens gives the focus back to it once it works again.
 *
 * A 401 means the user cancelled signing in again (api() asks first). Reading the list again
 * would only be refused too, and ask again: the dialog that Cancel is closing would open again
 * at once, so it took a second Cancel. The list stays as it was, and the button works again
 * (it asks to sign in, as the notice's Sign in does).
 */
async function sessionsAction(button, request, unanswered) {
  if (document.activeElement === button) page.busyFocus = button;
  button.disabled = true;
  sessionsMessage('', '');
  try {
    try {
      sessionsMessage('', await request());
    } catch (error) {
      sessionsMessage(error.status === undefined ? unanswered : error.message, '');
      if (error.status === 401) {
        button.disabled = false;
        return;
      }
    }
    await loadSessions();
    focusSessions();
  } finally {
    if (page.busyFocus === button) page.busyFocus = null;
  }
}
function revokeSession(button) {
  return sessionsAction(
    button,
    async () => {
      try {
        await api(`/api/account/sessions/${encodeURIComponent(button.dataset.revokeSession)}`, {
          method: 'DELETE',
        });
      } catch (error) {
        if (error.status === 404) error.message = 'That session had already ended.';
        throw error;
      }
      return 'That device is signed out.';
    },
    accountTexts.revokeUnanswered
  );
}
function revokeOthers(button) {
  // Wall displays are among the other devices (B6 design §7.5): each needs a new code afterwards.
  const walls = document.querySelectorAll('#sessions-list tr[data-wall]').length;
  return sessionsAction(
    button,
    async () => {
      const { revoked, kept } = await api('/api/account/sessions', { method: 'DELETE' });
      const later = Number(kept) || 0;
      return `${
        revoked === 1
          ? 'Signed out 1 other device.'
          : `Signed out ${Number(revoked) || 0} other devices.`
      }${
        later === 1
          ? ' 1 device that signed in later is still signed in.'
          : later
            ? ` ${later} devices that signed in later are still signed in.`
            : ''
      }${
        walls === 1
          ? ' This included 1 wall display: set it up again with a new display code.'
          : walls
            ? ` This included ${walls} wall displays: set each up again with a new display code.`
            : ''
      }`;
    },
    accountTexts.revokeOthersUnanswered
  );
}

/** The same rules Uptime Goblin applies, checked first so a typing mistake is explained at once. */
function passwordInputError(password, confirmation) {
  if ([...password].length < 12) return 'Use at least 12 characters for your new password.';
  if (new TextEncoder().encode(password).length > 1024)
    return 'This password is too long. Use no more than 1,024 UTF-8 bytes.';
  if (password !== confirmation)
    return 'The two passwords do not match. Enter the same new password in both fields.';
  return '';
}
let changing = false;
export async function changePassword(form) {
  if (!form.reportValidity() || changing) return;
  const currentPassword = $('#current-password').value,
    password = $('#new-password').value,
    confirmation = $('#confirm-new-password').value,
    error = $('#password-error'),
    result = $('#password-result'),
    invalid = passwordInputError(password, confirmation);
  error.hidden = true;
  result.hidden = true;
  if (invalid) {
    error.textContent = invalid;
    error.hidden = false;
    return;
  }
  changing = true;
  const unlock = lockForm(form);
  try {
    const answer = await api('/api/account/password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, password, confirmPassword: confirmation }),
    });
    for (const id of ['current-password', 'new-password', 'confirm-new-password'])
      $(`#${id}`).value = '';
    page.pageBaseline = formSnapshot(form);
    updateDirtyIndicator();
    // The answer replaced this browser's session (a new cookie), so it stays signed in.
    result.textContent = `Password changed. Other devices were signed out.${answer?.mirrorPending ? ` ${bannerTexts.mirrorPending}` : ''}`;
    result.hidden = false;
  } catch (failure) {
    error.textContent =
      failure.status === undefined
        ? 'Uptime Goblin did not confirm the change, so your password may or may not have changed. If Uptime Goblin asks you to sign in again, try the new password.'
        : `${failure.message}${failure.status === 429 && failure.retryAfter ? ` You can try again in ${failure.retryAfter} s.` : ''}`;
    error.hidden = false;
    return;
  } finally {
    changing = false;
    unlock();
  }
  // This session, its list and the banners now describe the new session.
  await loadAccount();
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  document.addEventListener('submit', async e => {
    if (e.target.id !== 'password-form') return;
    e.preventDefault();
    await changePassword(e.target);
  });
  document.addEventListener('click', async e => {
    if (e.target.closest('[data-retry-account]')) {
      await loadAccount();
      return;
    }
    const revoke = e.target.closest('[data-revoke-session]');
    if (revoke) {
      await revokeSession(revoke);
      return;
    }
    const others = e.target.closest('#sign-out-others');
    if (others) await revokeOthers(others);
  });
}
