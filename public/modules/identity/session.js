// Who is signed in, and what happens when that changes: the boot probe (GET /api/session), the
// sign-in view, the sign-in dialog that keeps drafts open when a session ends, the user chip
// with Sign out, and the persistent session banners.
//
// Uptime Goblin 1.5 signs browsers in with an HttpOnly cookie that scripts never see, so this module
// learns about the session only from Uptime Goblin's answers: GET /api/session says who is signed in
// (the built-in admin), and a 401 with code signin_required or session_expired says the session
// is gone.
import { api } from '../core/api.js';
import { reloadSection } from '../configure/pages.js';
import { $, closeDialog, openDialog, toast } from '../core/dom.js';
import { drawerDirty, focusable, pageDirty } from '../core/forms.js';
import {
  clearSignedOut,
  load,
  olderReleaseText,
  showOlderRelease,
  showSignedOut,
} from '../core/load.js';
import { kiosk, page } from '../core/page.js';
import { dateTime } from '../core/format.js';
import {
  displayPlainHttpWarning,
  displayTransportNotice,
  plainHttpWarning,
  plainText,
  prepareForm,
  refusedInClear,
  signInTexts,
  showText,
  transportNotice,
} from './signin.js';

// While Uptime Goblin does not answer at start, the page asks again this often.
const retryMs = 5000;
// How often a signed-in page reads GET /api/session again for its banners (refreshSession()).
// The dashboard's polls do not carry them, and they change while a page is open: Uptime Goblin's hourly
// retry of auth.json clears mirrorPending, and a password change in another tab sets it.
export const sessionRefreshMs = 300000;
// The way back from plain HTTP is GOBLIN_INSECURE_HTTP_SESSIONS=0, which ends it in every install
// mode: under Docker Compose an unset variable means compose-default (compose.yaml), which is on
// while the port is published on loopback, and natively the installer stops at its next run
// while Uptime Goblin listens on the network without a trusted proxy and /etc/uptime-goblin.env does not decide
// (it never adds the line by itself).
// Compose reads .env only when it creates the container: docker compose up -d, not restart.
// `insecure` (GET /api/session's transport) is true on the plain-HTTP transport, which Uptime Goblin
// accepts a password on only while plain-HTTP sign-in is on (GOBLIN_INSECURE_HTTP_SESSIONS=1, or
// Compose's compose-default on a loopback publish): the banner says so on every signed-in page
// for as long as the session is plain HTTP.
export const bannerTexts = Object.freeze({
  insecure:
    'This session uses plain HTTP, so anyone who can watch the traffic between your browser and Uptime Goblin can see its sign-in cookie, and your password each time you sign in or change it. Serve Uptime Goblin over HTTPS, then set GOBLIN_INSECURE_HTTP_SESSIONS=0 and restart Uptime Goblin (Docker: in .env, then docker compose up -d).',
  // The page itself is https:, so "serve Uptime Goblin over HTTPS" is already done and would change
  // nothing: what is missing is the proxy telling Uptime Goblin so (the sign-in view's
  // proxy_proto_missing text, which the opt-in silences).
  insecureBehindProxy:
    'Your browser uses HTTPS, but the reverse proxy in front of Uptime Goblin does not tell Uptime Goblin so, and with GOBLIN_INSECURE_HTTP_SESSIONS this session signed in as plain HTTP: its sign-in cookie is not marked Secure, so this browser would also send it to a plain http:// address of this host, where the network can see it. In nginx add `proxy_set_header X-Forwarded-Proto $scheme;` to Uptime Goblin’s location and reload nginx (GOBLIN_TRUST_PROXY must name the proxy), then set GOBLIN_INSECURE_HTTP_SESSIONS=0, restart Uptime Goblin (Docker: in .env, then docker compose up -d) and sign in again.',
  mirrorPending:
    'Uptime Goblin saved the admin password but could not update auth.json. Until it does, a rollback to 1.4.x would still use the previous password. Uptime Goblin retries hourly.',
  // A ?kiosk=1 page signed in with the admin password, as wall displays were before display
  // codes (B6 design §7.6): it holds every right Uptime Goblin has and signs out after 12 hours.
  oldDisplay:
    "This wall display is signed in as the admin, with every right. From Uptime Goblin 1.5 it signs out after 12 hours without use. Set it up as a read-only wall display: create a code on the Uptime Goblin host (`goblin-admin display code --name <name>`), press Set up and type the code here. Then delete Uptime Goblin's saved password from this browser.",
  // A wall display's session in its last 3 days (B6 design §7.5).
  displayEnding: date =>
    `This wall display signs in again by ${date}: ask an admin for a new code then.`,
});
const displayNoticeMs = 3 * 86400e3;
const state = {
  // The last GET /api/session answer (or sign-in answer) this tab saw, when (performance.now())
  // and the banners drawn from it (renderBanners()).
  session: null,
  sessionAt: 0,
  banners: null,
  // A GET /api/session for refreshSession() is on its way.
  refreshing: false,
  // Resolves startSession() once someone is signed in.
  started: null,
  // The open sign-in request: {promise, resolve, reject, reason, reasons}. One at a time,
  // shared by every request that found the session gone; `reasons` holds each one's 401.
  request: null,
  // The element to focus again once the sign-in dialog has closed.
  returnFocus: null,
  // The user cancelled signing in again: polls stop until they sign in (see signInPending()).
  signedOut: false,
  // A GET /api/session asked because the tab came back into view is still on its way.
  probing: false,
  // The start's GET /api/session is on its way, or its retry is waiting (retryTimer).
  starting: false,
  retryTimer: null,
  // A sign-out's failure arrived while the user menu was closed: #sign-out-error has not been
  // shown yet, so opening the menu keeps it (see signOut()).
  signOutUnseen: false,
  // The sign-out that started this page left another site's cookie of Uptime Goblin's name (see
  // rememberOtherCookie()): the start's sign-in view says so, once.
  otherCookie: false,
};

/** The session Uptime Goblin last described, or null before the first answer. */
export function currentSession() {
  return state.session;
}
/**
 * True while background requests should wait: the sign-in dialog is open, or the user
 * cancelled it. Their requests would only be refused (and reopen the dialog every poll).
 */
export function signInPending() {
  return !!state.request || state.signedOut;
}

/**
 * A load was refused because the browser sent two cookies of Uptime Goblin's name (401
 * multiple_credentials: another site set one beside Uptime Goblin's own; core/load.js). No sign-in can
 * succeed until this site's cookies are removed, so nobody is asked: the page says so, with no
 * Sign in, and polls stop as after Cancel. Each poll would only be refused again and draw the
 * notice again. A look at the tab (probeAgain()) finds out when that has changed: Uptime Goblin
 * answers again (the other cookie went), or asks for a sign-in (the cookies were removed),
 * which the notice's Sign in then offers.
 */
export function refusedCookies() {
  state.signedOut = true;
  showSignedOut('multiple_credentials');
}

/** Keeps `body` (a GET /api/session answer) and shows it in the chip and the banners. */
export function applySession(body) {
  if (!body || typeof body !== 'object') return;
  state.session = body;
  state.sessionAt = performance.now();
  const display = body.kind === 'kiosk';
  // A wall display reads the dashboard and nothing else: the controls that need more are hidden
  // (style.css), and the configuration pages are not offered.
  document.body.classList.toggle('display-mode', display);
  if (display && location.hash.startsWith('#configure')) location.replace('#');
  $('#user-chip-name').textContent = display
    ? 'Wall display'
    : body.user?.display || body.user?.login || 'Signed in';
  $('#user-chip').hidden = false;
  renderBanners();
}
/** Whether the session Uptime Goblin last described is a wall display's (a kiosk session). */
export function displaySession() {
  return state.session?.kind === 'kiosk';
}
/**
 * The plain-HTTP banner for `transport` as seen from a page at `protocol` (this page's by
 * default), or '' when the session is not plain HTTP.
 */
export function insecureBanner(transport, protocol = location.protocol) {
  if (!transport?.insecure) return '';
  return protocol === 'https:' ? bannerTexts.insecureBehindProxy : bannerTexts.insecure;
}
function renderBanners() {
  const s = state.session,
    lines = [];
  const insecure = insecureBanner(s?.transport);
  if (insecure) lines.push(insecure);
  if (s?.mirrorPending) lines.push(bannerTexts.mirrorPending);
  const ends = s?.kind === 'kiosk' ? s.session?.expiresAt : null;
  if (Number.isFinite(ends) && ends - Date.now() < displayNoticeMs)
    lines.push(bannerTexts.displayEnding(dateTime(ends)));
  // #session-banner is a role="status" region, which reads out every change: the same banners
  // drawn again (each new read of the session) must not be read out again.
  const oldDisplay = kiosk && s?.via === 'session' && s.kind !== 'kiosk';
  const drawn = JSON.stringify([lines, oldDisplay]);
  if (drawn === state.banners) return;
  state.banners = drawn;
  const banner = $('#session-banner');
  banner.replaceChildren(
    ...lines.map(text => {
      const line = document.createElement('p');
      // `quoted` parts show as code, as in the sign-in view's notices; nothing is parsed as HTML.
      showText(line, text);
      return line;
    })
  );
  banner.hidden = !lines.length;
  if (oldDisplay) showText($('#display-banner-text'), bannerTexts.oldDisplay);
  $('#display-banner').hidden = !oldDisplay;
}

/**
 * Finds out who is signed in, before the web app loads anything else. Resolves once someone
 * is: 'session' when Uptime Goblin already knew this browser (or needs no sign-in), 'view' after the
 * sign-in view signed it in. Until then only GET /api/session is asked, so a signed-out page
 * never holds any of the dashboard's data.
 */
export function startSession() {
  // Nothing that needs a signed-in Uptime Goblin can be used before the start finds someone signed in:
  // a click while Uptime Goblin is not answering yet would only send requests that fail, or are refused
  // and ask for a sign-in the start itself is about to ask for.
  for (const selector of startControls) $(selector).hidden = true;
  // Taken now, whatever the start finds: a note left for this page must not surface on a later
  // one, hours after the sign-out it was about.
  state.otherCookie = takeOtherCookie();
  return new Promise(resolve => {
    state.started = resolve;
    probeAtStart();
  });
}
async function probeAtStart() {
  clearTimeout(state.retryTimer);
  state.retryTimer = null;
  state.starting = true;
  let body;
  try {
    body = await api('/api/session', { signIn: false });
  } catch (error) {
    state.starting = false;
    // 401: nobody is signed in. 403: Uptime Goblin refuses this browser before any sign-in (the Host
    // allowlist); the view says why.
    if (error.status === 401 || error.status === 403) {
      showSignInView(error);
      return;
    }
    // 429, 5xx, a proxy's error page or no answer: Uptime Goblin is not ready. Ask again shortly. A
    // sign-in view that a look at the tab asked again for (probeAgain()) says so in place of its
    // notice, which named the restart this is likely to be: the dashboard's is hidden behind it.
    const notice = $('#signin-page').hidden ? $('#notice') : $('#signin-notice');
    notice.hidden = false;
    notice.textContent =
      'Uptime Goblin is not answering. This page connects by itself once it is back.';
    $('#connection').textContent = 'Reconnecting…';
    state.retryTimer = setTimeout(probeAtStart, retryMs);
    return;
  }
  state.starting = false;
  $('#notice').hidden = true;
  // A look at a sign-in view that offered no form (probeAgain()) found this browser signed in,
  // by another tab once Uptime Goblin allowed it: the view gives way as after its own sign-in.
  if (!$('#signin-page').hidden) {
    signedIn('view', body);
    return;
  }
  applySession(body);
  finishStart('session');
}
function finishStart(how) {
  const started = state.started;
  state.started = null;
  for (const selector of startControls) $(selector).hidden = false;
  started?.(how);
}

/** The parts of the page a signed-out visitor must not see or use. */
const appParts = ['#dashboard-page', '#configuration-page', '#refresh', '#settings'];
/** The controls hidden until the start has found someone signed in (see startSession()). */
const startControls = ['#refresh', '#settings', '.workspace-actions'];
function showSignInView(error) {
  for (const selector of appParts) $(selector).hidden = true;
  $('#user-chip').hidden = true;
  closeMenu(false);
  $('#notice').hidden = true;
  $('#connection').textContent = 'Signed out';
  $('#connection').classList.remove('live');
  const view = $('#signin-page'),
    notice = $('#signin-notice'),
    blocked = error.status === 403,
    // Drawn again by a look at the tab (probeAgain()), with what Uptime Goblin answers then.
    shown = !view.hidden;
  // A refusal before sign-in cannot be fixed by signing in: say why, and offer no form. Nor
  // when Uptime Goblin will refuse any sign-in from this plain-HTTP page (refusedInClear()): the
  // password, or a display code, would cross the network unencrypted before that refusal.
  // On ?kiosk=1 the view holds the display code form only, never the password form (B6 design
  // §7.7): the admin signs in with the password at the address without ?kiosk=1.
  const noForm = blocked || !!refusedInClear(error.transport),
    codeForm = kiosk;
  $('#signin-form').hidden = noForm || codeForm;
  $('#display-form').hidden = noForm || !codeForm;
  $('#signin-title').textContent = codeForm
    ? 'Set up this wall display'
    : 'Sign in to Uptime Goblin';
  const otherCookie = state.otherCookie;
  state.otherCookie = false;
  // Where Uptime Goblin allows sign-in over plain HTTP from the network, the password the form asks
  // for crosses it unencrypted: the notice says so before it is typed (plainHttpWarning()).
  const text = blocked
    ? error.message
    : codeForm
      ? displayTransportNotice(error.transport) || displayPlainHttpWarning(error.transport)
      : transportNotice(error.transport) ||
        [
          otherCookie
            ? signInTexts.signed_out_other_cookie
            : error.code === 'session_expired' || error.code === 'multiple_credentials'
              ? signInTexts[error.code]
              : '',
          plainHttpWarning(error.transport),
        ]
          .filter(Boolean)
          .join(' ');
  // The notice is a status region, which reads out every change: an unchanged one is not drawn
  // again at each look at the tab.
  if (notice.textContent !== plainText(text)) showText(notice, text);
  notice.hidden = !text;
  view.hidden = false;
  // A view drawn again keeps the focus where the user left it.
  if (!shown && !view.contains(document.activeElement))
    $('#signin-title').focus({ preventScroll: true });
}

/**
 * Called by the sign-in form once Uptime Goblin has signed this browser in and the browser has shown
 * that it kept the cookie: `body` is the new GET /api/session answer.
 */
export function signedIn(kind, body) {
  applySession(body);
  if (kind === 'view') {
    state.signedOut = false;
    $('#signin-page').hidden = true;
    $('#dashboard-page').hidden = false;
    $('#refresh').hidden = false;
    $('#settings').hidden = false;
    $('#connection').textContent = 'Connecting…';
    focusPageHeading();
    finishStart('view');
    return;
  }
  signedInAgain({ newSession: true });
  settle(true);
}

/**
 * Signed in again: through the dialog, or in another tab (a probe found the shared cookie
 * working). After the user cancelled signing in (state.signedOut) the signed-out notices go and
 * the page loads at once, so a sign-in that no load follows (the Account page, Help, an export)
 * does not leave "Signed out" and a Sign in button beside what it shows.
 *
 * The open configuration page then reads again what it reads for itself (reloadSection()),
 * which load() does not: after Cancel the Account and System pages show the refusal their own
 * requests got ("Your session has ended. Sign in again."), and after any sign-in that ended a
 * dialog (`newSession`) the Account page would go on listing the session that ended as this
 * device's. A probe that finds the session working without a dialog changed nothing there.
 */
function signedInAgain({ newSession = false } = {}) {
  const wasSignedOut = state.signedOut;
  if (wasSignedOut) {
    state.signedOut = false;
    clearSignedOut();
    load();
  }
  if (wasSignedOut || newSession) reloadSection();
}

/**
 * Focuses the page's heading when the focus was lost: it is on <body>, or on a control that is
 * hidden or disabled now (a signed-out notice's Sign in, which the load after signing in hides).
 */
export function focusIfLost() {
  const focused = document.activeElement;
  if (!focused || focused === document.body || !focusable(focused)) focusPageHeading();
}

/** Focuses the heading of the page that shows, as after choosing it in the navigation. */
export function focusPageHeading() {
  const heading = $('#configuration-page').hidden
    ? $('#dashboard-title')?.closest('h1')
    : $('#configuration-section-title');
  if (!heading) return;
  if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
  heading.focus({ preventScroll: true });
}

/**
 * Asks the user to sign in again, over whatever is open (a drawer, a form with changes), so
 * nothing is lost. Resolves once signed in; rejects with `reason` if the user cancels. Every
 * caller while the question is open shares one promise. It first asks Uptime Goblin: when another tab
 * has signed in meanwhile (the cookie is shared), nothing needs to be asked; when a release
 * before 1.5 answers (Uptime Goblin was rolled back), nothing can be, and it rejects without asking.
 */
export function requireSignIn({ reason = null } = {}) {
  // Before the start has found anyone signed in, the sign-in view is the way in, not the
  // dialog: a dialog sign-in would not start the page (no polls), and the view would open
  // behind it. The request that found the session missing fails as it is; the start asks at
  // once instead of waiting for its retry, and shows the view.
  if (state.started) {
    if (!state.starting && $('#signin-page').hidden) probeAtStart();
    return Promise.reject(reason);
  }
  if (state.request) {
    // Joined: an answer that ends the request for every caller says why to each of them
    // (olderRelease(), refuseInClear()), not only to the first.
    state.request.reasons.push(reason);
    return state.request.promise;
  }
  const request = { reason, reasons: [reason] };
  request.promise = new Promise((resolve, reject) => {
    request.resolve = resolve;
    request.reject = reject;
  });
  state.request = request;
  // Only the first caller's focus is worth returning to: later ones are background requests.
  // A form or button waiting for this request disabled the control that had the focus
  // (lockForm(), holdFocus()), which dropped it to <body>: that control is where it goes back.
  state.returnFocus =
    document.activeElement === document.body && page.busyFocus?.isConnected
      ? page.busyFocus
      : document.activeElement;
  (async () => {
    try {
      const body = await api('/api/session', { signIn: false, background: true });
      if (state.request !== request) return;
      applySession(body);
      signedInAgain();
      settle(true);
    } catch (error) {
      if (state.request !== request) return;
      // A 401 without a code: Uptime Goblin was rolled back to a release before 1.5, which has no
      // sign-in of this page's kind (no /api/session, no /api/auth/login) and answers with the
      // browser's own Basic prompt. The dialog could never succeed, and each attempt would only
      // bring that prompt up: as api() does for such a 401, nobody is asked. api() reported the
      // change of release, so the page reloads into it, or its update banner offers that.
      if (error?.status === 401 && error.code === undefined) {
        olderRelease();
        return;
      }
      // Uptime Goblin will refuse any sign-in from this plain-HTTP page, and only once the password has
      // crossed the network unencrypted (refusedInClear(): plain-HTTP sessions were turned off
      // while the page was open, or a proxy claims HTTPS for it). Nobody is asked: the notices
      // say why, with no Sign in, and polls stop as after Cancel. A look at the tab
      // (probeAgain()) finds out when that has changed.
      if (error?.status === 401 && refusedInClear(error.transport)) {
        refuseInClear(error);
        return;
      }
      openSignInDialog();
    }
  })();
  return request.promise;
}
function openSignInDialog() {
  const previous = state.session;
  // A wall display has no password to type: its session ended (30 days, 7 days without a
  // request, or signed out), and only a new display code signs it in. An old admin session on
  // ?kiosk=1 also returns to the code view, never the password dialog.
  if (kiosk || previous?.kind === 'kiosk') {
    page.signingOut = true;
    const address = new URL(location.href);
    address.searchParams.set('kiosk', '1');
    address.hash = '';
    location.replace(address.href);
    return;
  }
  prepareForm('dialog', {
    login: previous?.user?.login === 'admin' ? 'admin' : '',
    remember: !!previous?.session?.persistent,
  });
  const dialog = $('#signin-dialog');
  openDialog(dialog);
  $('#reauth-password').focus();
}
/**
 * Ends the open sign-in request because a release before 1.5 answered its GET /api/session (a
 * 401 without a code: Uptime Goblin was rolled back), and says to reload (showOlderRelease()). Every
 * action that found the session gone and shares the request (a Save, a Refresh, a dashboard
 * load), whichever asked first, is thrown its own 401 (its `reasons`) as that release's: without
 * a code, and saying to reload rather than 1.5's "Sign in to Uptime Goblin.". A load that fails with it
 * then draws the same notice, rather than "Signed out" and a Sign in from that older 401 over
 * it, which could never succeed against that release.
 */
function olderRelease() {
  const request = state.request;
  state.request = null;
  for (const reason of request.reasons)
    if (reason instanceof Error) {
      reason.message = olderReleaseText;
      delete reason.code;
    }
  request.reject(request.reason);
  showOlderRelease();
  restoreFocus();
}
/**
 * Ends the open sign-in request because Uptime Goblin will refuse any sign-in from this plain-HTTP page
 * (`error`, its 401: refusedInClear()). Every action that found the session gone and shares
 * the request (a Save, a Refresh, a dashboard load) shows that refusal rather than Uptime Goblin's own
 * "Sign in to Uptime Goblin.", which nothing on the page could follow: api() throws each caller the 401
 * it got (its `reasons`), which takes this answer's transport too, since Uptime Goblin may have allowed
 * the sign-in when that 401 came (a dialog left open, or a request that joined before the
 * question's GET /api/session answered). A load that fails with it then draws the same notices
 * (showSignedOut()), rather than a Sign in from that older 401 over them. The notices say it
 * with no Sign in, and polls stop as after Cancel. An open sign-in dialog closes before its
 * password is sent (probeAgain()), and the password typed so far goes.
 */
function refuseInClear(error) {
  const request = state.request;
  state.request = null;
  state.signedOut = true;
  const message = plainText(signInTexts[refusedInClear(error.transport)]);
  for (const reason of request.reasons)
    if (reason instanceof Error) {
      reason.message = message;
      reason.transport = error.transport;
    }
  request.reject(request.reason);
  showSignedOut(error.code, error.transport);
  $('#reauth-password').value = '';
  const dialog = $('#signin-dialog');
  if (dialog.open) closeDialog(dialog);
  else restoreFocus();
}
/** Ends the open sign-in request: signed in (`success`), or cancelled. */
function settle(success) {
  const request = state.request;
  if (!request) return;
  state.request = null;
  if (success) request.resolve();
  else {
    // Polls stop, and the page says it is signed out, whatever request asked: a person's
    // action (a card's pause, a save) is never followed by a load that would say so.
    state.signedOut = true;
    request.reject(request.reason);
    showSignedOut();
  }
  const dialog = $('#signin-dialog');
  if (dialog.open) closeDialog(dialog);
  else restoreFocus();
}
function restoreFocus() {
  const target = state.returnFocus;
  state.returnFocus = null;
  if (!target || target === document.body) return;
  // A control still waiting for its answer (lockForm() disabled it, or a button that holds its
  // focus did: page.busyFocus) gets the focus back from its owner when that comes.
  if (target.disabled && (page.busyForm?.contains(target) || target === page.busyFocus)) return;
  if (focusable(target)) target.focus({ preventScroll: true });
  // Hidden or gone meanwhile (the notice's Sign in, once the load hid the notice): the focus
  // would stay on <body>, so it goes to the page's heading.
  else focusIfLost();
}
/**
 * Reads GET /api/session again for the banners, at most every sessionRefreshMs; main.js calls it
 * after each poll that loaded. A background request: it keeps no idle session signed in, and
 * asks nobody to sign in (a session that ended is the polls' to find out and say).
 */
export async function refreshSession() {
  const s = state.session;
  if (!s || signInPending() || state.probing || state.refreshing) return;
  if (performance.now() - state.sessionAt < sessionRefreshMs) return;
  state.refreshing = true;
  try {
    const body = await api('/api/session', { signIn: false, background: true });
    // Signed out meanwhile (the dialog, or its Cancel): what the sign-in shows wins.
    if (!signInPending()) applySession(body);
  } catch {
    // Not answering, or the session ended: the banners stay as they are until the next read.
  } finally {
    state.refreshing = false;
  }
}
/** Asks Uptime Goblin whether this browser is signed in again, e.g. by another tab. */
async function probeAgain() {
  // Before anyone signed in, the start's sign-in view is all there is. One that offers no form
  // (a refusal before sign-in, or Uptime Goblin refusing any sign-in from this plain-HTTP page) waits
  // for a change to Uptime Goblin's configuration and a restart, as its notice says: nothing on the page
  // could find that out, so the start asks again (probeAtStart()). That offers the form, says
  // that Uptime Goblin is not answering yet (and asks again by itself), or starts the page when another
  // tab signed in meanwhile. A view with a form is left alone: an answer to a look could come
  // after the form's own sign-in, and draw the view over the page that started.
  if (state.started) {
    if (
      !state.starting &&
      !$('#signin-page').hidden &&
      $('#signin-form').hidden &&
      $('#display-form').hidden
    )
      probeAtStart();
    return;
  }
  if (state.probing || !(state.request || state.signedOut)) return;
  state.probing = true;
  try {
    const body = await api('/api/session', { signIn: false, background: true });
    applySession(body);
    // With the dialog open, another tab's sign-in ends it as the user's own would have.
    signedInAgain({ newSession: !!state.request });
    if (state.request) settle(true);
  } catch (error) {
    // The sign-in dialog is open, and Uptime Goblin now refuses any sign-in from this plain-HTTP page
    // (plain-HTTP sessions were turned off while it waited): the dialog would send the password
    // unencrypted and only then be refused. It closes, as requireSignIn() would not have
    // opened it, and the notices say why.
    if (state.request && error?.status === 401 && refusedInClear(error.transport)) {
      refuseInClear(error);
      return;
    }
    // Still signed out: the dialog stays as it is. The notices follow Uptime Goblin's answer, which
    // changes when this site's cookies were removed after two were refused (refusedCookies()):
    // Sign in can help now, and the notice offers it again. Or the other way round, when
    // another site set a cookie of Uptime Goblin's name meanwhile. The same when Uptime Goblin starts or stops
    // refusing every sign-in from this plain-HTTP page (refusedInClear()). Drawn only when
    // that changes.
    if (state.request || !state.signedOut || error?.status !== 401) return;
    if (!['signin_required', 'session_expired', 'multiple_credentials'].includes(error.code))
      return;
    const focused = document.activeElement;
    showSignedOut(error.code, error.transport);
    // The notice's Sign in had the focus, and went with it.
    if (focused && !focused.isConnected) focusPageHeading();
  } finally {
    state.probing = false;
  }
}

/** What the user menu says when Uptime Goblin did not confirm a sign-out. */
export const signOutTexts = Object.freeze({
  unanswered:
    'Uptime Goblin did not confirm the sign-out, so this browser may still be signed in. Try again.',
  failed: message => `Uptime Goblin could not record the sign-out (${message}). Try again.`,
  twoCookies:
    'Uptime Goblin could not sign this browser out: it sent two Uptime Goblin sign-in cookies, and another site set one of them. Remove this site’s cookies in the browser to sign out.',
});

// Kept across the reload that follows a sign-out (this tab's sessionStorage): Uptime Goblin ended this
// browser's sessions, but the browser also sent a cookie of Uptime Goblin's name that another site set,
// which Uptime Goblin cannot remove. The sign-in view says so once, instead of "Your session has ended"
// for that cookie, so whoever signs in next learns why signing in again would fail.
const otherCookieKey = 'orbit-signout-other-cookie';
function rememberOtherCookie() {
  try {
    sessionStorage.setItem(otherCookieKey, '1');
  } catch {
    // Storage refused (a private window's quota, a policy): the sign-in view keeps its usual
    // notice, and the first sign-in attempt names the two cookies.
  }
}
function takeOtherCookie() {
  try {
    const found = sessionStorage.getItem(otherCookieKey) !== null;
    sessionStorage.removeItem(otherCookieKey);
    return found;
  } catch {
    return false;
  }
}

/**
 * Signs this browser out: Uptime Goblin deletes the session and expires its cookie, and the page
 * starts again at the sign-in view. Unsaved changes are lost, so the user is asked first.
 *
 * The page starts again only once Uptime Goblin confirmed it: 204; 200 with code
 * `multiple_credentials` (the browser also sent a cookie of Uptime Goblin's name that another site
 * set: Uptime Goblin ended every session among them and expired its own cookie, and the sign-in view
 * says to remove this site's cookies); or 401 for a session that had already ended
 * (`signin_required`, `session_expired`, or a 401 without a code: Uptime Goblin was rolled back to a
 * release before 1.5, which the new page uses). Without an answer (Uptime Goblin restarting, a dropped
 * network, the time limit) the cookie and the session may both still be valid, and a new page
 * would sign itself back in without a word; an error from Uptime Goblin means the sign-out was not
 * recorded, and a 401 `multiple_credentials` that Uptime Goblin ended nothing (the browser keeps its
 * cookie). Either way the page stays, says so, and Sign out can be pressed again. After an
 * error Uptime Goblin refuses the session but keeps the browser's cookie, so that pressing again
 * deletes it (§20 H1); a 401 `session_expired` to that press means Uptime Goblin no longer stores it.
 */
export async function signOut() {
  if ((pageDirty() || drawerDirty()) && !confirm('Discard your unsaved changes and sign out?'))
    return;
  const button = $('#sign-out'),
    problem = $('#sign-out-error'),
    // Disabling the button drops its focus to <body>; a failure gives it back (as lockForm()
    // does for a form), so a keyboard user's next Tab goes on from Sign out.
    focused = document.activeElement === button;
  button.disabled = true;
  button.textContent = 'Signing out…';
  problem.hidden = true;
  state.signOutUnseen = false;
  let failure = null,
    answer = null;
  try {
    answer = await api('/api/auth/logout', { method: 'POST', signIn: false });
  } catch (error) {
    if (error.status !== 401 || error.code === 'multiple_credentials') failure = error;
  }
  if (!failure) {
    if (answer?.code === 'multiple_credentials') rememberOtherCookie();
    // Agreed above: leaving the page asks nothing more.
    page.signingOut = true;
    page.pageBaseline = '';
    page.drawerBaseline = '';
    // replace(): Back does not return to the signed-in page.
    location.replace(location.pathname + location.search);
    return;
  }
  button.disabled = false;
  button.textContent = 'Sign out';
  problem.textContent =
    failure.status === undefined
      ? signOutTexts.unanswered
      : failure.code === 'storage_full'
        ? failure.message
        : failure.code === 'multiple_credentials'
          ? signOutTexts.twoCookies
          : signOutTexts.failed(failure.message);
  problem.hidden = false;
  if (menuOpen()) {
    const now = document.activeElement;
    if (focused && (!now || now === document.body)) button.focus({ preventScroll: true });
    return;
  }
  // The menu was closed while the request was out (it can take a minute): an alert inside it
  // is neither shown nor announced, and the user may leave believing this browser is signed
  // out. The toast says it now, and the menu keeps it until it has been opened once.
  state.signOutUnseen = true;
  toast(problem.textContent);
}

function menuOpen() {
  return !$('#user-menu').hidden;
}
function closeMenu(returnFocus) {
  if (!menuOpen()) return;
  $('#user-menu').hidden = true;
  $('#user-chip').setAttribute('aria-expanded', 'false');
  if (returnFocus) $('#user-chip').focus();
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  // The chip is a disclosure button: Enter and Space toggle it as for any button.
  $('#user-chip').addEventListener('click', () => {
    const open = !menuOpen();
    // A sign-out's failure is news only until the menu is opened again after showing it: one
    // that arrived while the menu was closed shows now, once.
    if (open && !$('#sign-out').disabled) {
      if (state.signOutUnseen) state.signOutUnseen = false;
      else $('#sign-out-error').hidden = true;
    }
    $('#user-menu').hidden = !open;
    $('#user-chip').setAttribute('aria-expanded', String(open));
  });
  $('#sign-out').addEventListener('click', signOut);
  // A wall display's footer has its own Sign out: the account chip is hidden there.
  $('#display-sign-out').addEventListener('click', signOut);
  // An old wall display, signed in with the password: Set up signs it out, and the sign-in
  // view that follows asks for a display code.
  $('#display-banner-setup').addEventListener('click', signOut);
  // Only a press that starts and ends outside the menu closes it, as for the dialogs
  // (configure/events.js). A press inside that is released outside (selecting the text of
  // #sign-out-error to copy it) clicks their common ancestor, outside the menu: closing then
  // would also hide that error, the page's only record of a sign-out that did not happen, at
  // the next opening. A keyboard's click (detail 0) has no press: its target alone counts.
  const inMenu = target => !!target?.closest?.('.user-area');
  let pressedInMenu = false,
    releasedInMenu = false;
  document.addEventListener('pointerdown', e => {
    pressedInMenu = inMenu(e.target);
    releasedInMenu = false;
  });
  document.addEventListener('pointerup', e => {
    releasedInMenu = inMenu(e.target);
  });
  document.addEventListener('click', e => {
    const pressed = e.detail > 0 && (pressedInMenu || releasedInMenu);
    pressedInMenu = releasedInMenu = false;
    // Account navigates through the route handler (configure/events.js). The menu closes, and
    // its link, which has the focus, is hidden with it, so the focus goes to the chip, as for
    // Escape; a page that opens then moves it to its heading. No page opens when the Account
    // page shows already, or when the user kept their unsaved changes at the prompt: the focus
    // dropped to <body> then, and a keyboard user started again at the top.
    if (e.target.closest('#user-account')) closeMenu(true);
    else if (!(pressed || inMenu(e.target))) closeMenu(false);
    // Signing in again loads the page (signedInAgain()), which hides this notice and so the
    // button the focus returns to: then the page's heading takes it.
    if (e.target.closest('#notice-sign-in, #configuration-sign-in'))
      requireSignIn()
        .then(() => load({ join: true }))
        .then(focusIfLost, () => {});
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || e.isComposing || !menuOpen()) return;
    e.preventDefault();
    closeMenu(true);
  });
  window.addEventListener('hashchange', () => closeMenu(false));

  const dialog = $('#signin-dialog');
  $('#reauth-cancel').addEventListener('click', () => settle(false));
  // Escape, and any other close request, is Cancel. The keydown is handled here rather than
  // through 'cancel' alone, because Chromium ignores preventDefault() on a second 'cancel'
  // without user activation in between; it is cancelled so the drawer below stays open.
  dialog.addEventListener('keydown', e => {
    if (e.key !== 'Escape' || e.isComposing) return;
    e.preventDefault();
    settle(false);
  });
  dialog.addEventListener('cancel', e => {
    e.preventDefault();
    settle(false);
  });
  dialog.addEventListener('close', () => {
    // Closed by the browser rather than by settle() (it could not be stopped): cancelled.
    if (state.request) settle(false);
    restoreFocus();
  });
  // Signed in again somewhere else (another tab, the same browser): the next look at this
  // tab finds out without asking the user.
  window.addEventListener('focus', probeAgain);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) probeAgain();
  });
  // A page brought back from the browser's back/forward cache still shows what it showed
  // when it was left; if its session has ended since (signed out in another tab), start
  // again at the sign-in view rather than keep showing it.
  window.addEventListener('pageshow', async e => {
    if (!e.persisted || !state.session) return;
    try {
      await api('/api/session', { signIn: false, background: true });
    } catch (error) {
      if (error.status === 401) location.reload();
    }
  });
}
