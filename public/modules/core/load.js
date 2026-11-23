// Loads the dashboard snapshot and applies it to every view.
import { historyDue, loadHistory } from '../charts/charts.js';
import { deliveryNotice, diskNotice } from '../configure/notifications.js';
import { refreshConfiguration, renderRoute } from '../configure/pages.js';
import { api, stuckLoadMs } from './api.js';
import { $, esc } from './dom.js';
import { checkTimeZone, dateTime } from './format.js';
import { page } from './page.js';
import { patchHtml } from './patch.js';
import { render } from '../dashboard/dashboard.js';
import { refusedCookies } from '../identity/session.js';
import { refusedInClear, showText, signInTexts } from '../identity/signin.js';
import { offerUpdate, restoreScroll } from '../update/update.js';

let loading = false,
  loadPromise,
  reloadRequested = false,
  // Whether the extra fetch a caller asked for while a load was running may be a background
  // one: any caller that is a person's action makes it a foreground request.
  rerunBackground = true;
let routeInitialized = false,
  firstLoad = true;
let loadGeneration = 0,
  loadStarted = 0;
/**
 * Refreshes `data` and the dashboard. Resolves to true when fresh data was applied.
 * `background`: a poll no person asked for. Its request says so, and Uptime Goblin then does not count
 * it as activity that keeps an idle session signed in. Every read on ?kiosk=1 is background
 * regardless of this option (see api.js). `join`: a caller that needs only a load to
 * finish, not one sent after its own change, waits for the load in flight instead.
 */
export async function load({ background = false, join = false } = {}) {
  if (loading && join && performance.now() - loadStarted < stuckLoadMs) return loadPromise;
  // A load already in flight may have fetched before the caller's change, so run one
  // more fetch after it and resolve every caller with that one. Watchdog: one running for
  // three polls is stuck (a connection that will never answer), so it is dropped instead.
  if (loading) {
    if (performance.now() - loadStarted < stuckLoadMs) {
      reloadRequested = true;
      rerunBackground &&= background;
      return loadPromise;
    }
    page.dashboardController?.abort();
  }
  const generation = ++loadGeneration;
  loading = true;
  loadStarted = performance.now();
  rerunBackground = true;
  loadPromise = (async () => {
    try {
      let loaded,
        quiet = background;
      do {
        reloadRequested = false;
        loaded = await loadOnce(quiet);
        quiet = rerunBackground;
        rerunBackground = true;
      } while (reloadRequested && generation === loadGeneration);
      return loaded;
    } finally {
      if (generation === loadGeneration) loading = false;
    }
  })();
  return loadPromise;
}
async function loadOnce(background) {
  let fresh;
  const controller = new AbortController();
  page.dashboardController = controller;
  try {
    fresh = await api('/api/dashboard', { signal: controller.signal, background });
  } catch (e) {
    // Dropped by the watchdog or a reconnect: a newer load takes over.
    if (controller.signal.aborted && !e.timeout) return false;
    // 401 reaches this point when the user cancelled signing in again (api() asks first), when
    // Uptime Goblin will refuse any sign-in from this plain-HTTP page (nobody was asked, and the notices
    // say why: showSignedOut()), or without a code: a release before 1.5 answered (Uptime Goblin was
    // rolled back), and api() has reported the change of release. That release signs browsers
    // in its own way, so a Sign in here could never succeed: the page says to reload instead.
    // A 401 of 1.5's whose sign-in question that release answered comes without a code too
    // (olderRelease() in identity/session.js).
    // With code multiple_credentials the browser sent two cookies of Uptime Goblin's name (another site
    // set one beside Uptime Goblin's own): no sign-in succeeds until this site's cookies are removed,
    // so api() asked nobody, and the page says what to do and stops polling (refusedCookies()).
    // 429 comes from a sign-in lockout, not from collection. No HTTP status means Uptime Goblin did
    // not answer at all (restarting, or the network dropped): keep trying.
    // What the notices say now is this failure, not the last snapshot's banners.
    noticesCurrent = false;
    if (e.status === 401) {
      if (e.code === undefined) showOlderRelease();
      else if (e.code === 'multiple_credentials') refusedCookies();
      else showSignedOut(e.code, e.transport);
      return false;
    }
    const message =
      e.status === 429
        ? `${e.message}${e.retryAfter > 1 ? ` Sign-in is paused for about ${waitTime(e.retryAfter)}.` : ''} Readings resume automatically afterwards.`
        : e.status === undefined
          ? 'Uptime Goblin is not answering. Displayed readings may be stale; this page reconnects by itself.'
          : 'Uptime Goblin cannot reach its collector. Displayed readings may be stale.';
    $('#notice').hidden = false;
    $('#notice').textContent = message;
    $('#connection').textContent =
      e.status === 429
        ? 'Sign-in paused'
        : e.status === undefined
          ? 'Reconnecting…'
          : 'Collector unavailable';
    $('#connection').classList.remove('live');
    if (!page.data && location.hash.startsWith('#configure'))
      showConfigurationHint(
        e.status === 429
          ? esc(message)
          : 'Configuration is unavailable until Uptime Goblin reconnects. Try refreshing the page.'
      );
    return false;
  } finally {
    if (page.dashboardController === controller) page.dashboardController = null;
  }
  // A snapshot the server built before this tab's own write can arrive after it; applying it
  // would roll back the revision and the change. Fetch again instead (a few times at most,
  // in case the server's configuration really went back, such as after a restore).
  if (fresh.config.revision < page.writtenRevision && page.staleSnapshots < 3) {
    page.staleSnapshots++;
    reloadRequested = true;
    return false;
  }
  page.staleSnapshots = 0;
  page.writtenRevision = fresh.config.revision;
  page.data = fresh;
  // This tab now shows what Uptime Goblin has, so any earlier change without an answer is settled.
  if (!page.writesPending) page.writeUnknown = false;
  checkTimeZone();
  if (firstLoad) {
    page.range = page.data.config.appearance?.defaultRange || '24h';
    // After reloading for an update, carry on where the page was.
    if (page.restored) {
      if (['1h', '6h', '24h', '7d', '30d'].includes(page.restored.range))
        page.range = page.restored.range;
      if (page.data.config.services.some(s => s.id === page.restored.expanded))
        page.expanded = page.restored.expanded;
      if (typeof page.restored.metric === 'string') page.selectedMetric = page.restored.metric;
      if (Number.isFinite(page.restored.scrollY)) {
        page.pendingScroll = page.restored.scrollY;
        // Stop following the old position if the chart never finishes loading.
        setTimeout(() => (page.pendingScroll = null), 10000);
      }
    }
    firstLoad = false;
  }
  // A display bug must not be reported as a collector outage, and must not stop routing.
  let renderError = null;
  try {
    render();
  } catch (e) {
    renderError = e;
  }
  try {
    if (!routeInitialized) {
      routeInitialized = true;
      renderRoute(false);
    } else refreshConfiguration();
  } catch (e) {
    renderError ??= e;
  }
  restoreScroll();
  // Not awaited: a slow history download must not hold up, or stack, dashboard polls. A poll's
  // refetch is a background request too, or an open chart would keep an idle session alive.
  if (page.expanded && !page.configurationSection && historyDue(page.expanded))
    loadHistory(page.expanded, { background });
  // A save or a closed form may have made a waiting update safe to apply.
  if (page.updateBuild) offerUpdate();
  if (renderError) console.error(renderError);
  // Signed in and loading again: a signed-out notice gives way to what is true now.
  noticesCurrent = true;
  drawNotices(renderError);
  return true;
}
// Whether the notices show the last snapshot's banners (false once a load failed: they say why),
// and the display error of that snapshot's drawing.
let noticesCurrent = false,
  lastRenderError = null;
/**
 * Draws the banner that applies first, the same on the dashboard (#notice) and on configuration
 * pages (#configuration-notice), or hides them: a full disk; history writes failing (collection
 * and alerts continue, but readings are not saved); a page that could not be fully displayed;
 * then the delivery banners (configure/notifications.js). One at a time, so the most urgent is
 * never pushed down by another. A notice that already says the same is left as it is: both are
 * live regions, which read out every change, and a poll every 15 s must not repeat them.
 * Drawn after each load, and again (showNotices()) by the delivery banners once a detail they
 * lacked is known, unless a load has failed since: the notices then say that.
 */
export function showNotices() {
  if (noticesCurrent) drawNotices(lastRenderError);
}
function drawNotices(renderError) {
  lastRenderError = renderError;
  if (!page.data) return;
  const html =
    diskNotice() ??
    (page.data.storage
      ? esc(
          `Uptime Goblin cannot save new readings to its history database (${page.data.storage.code}) since ${dateTime(page.data.storage.since)}. The disk may be full. Alerts still run. Free disk space on the Uptime Goblin host; lowering retention does not free disk space by itself.`
        )
      : null) ??
    (renderError
      ? esc(
          `This page could not be fully displayed (${renderError.message}). Reload the page. Collection continues on the Uptime Goblin server.`
        )
      : null) ??
    deliveryNotice();
  for (const notice of [$('#notice'), $('#configuration-notice')]) {
    if (!html) {
      notice.hidden = true;
      continue;
    }
    // Patched: only the nodes that differ change (a signed-out notice's Sign in goes, a text
    // that stayed the same is not touched).
    patchHtml(notice, html);
    notice.hidden = false;
  }
}
/** What a signed-out page says where its readings and configuration would be. */
export const signedOutText = 'Signed out. Sign in to see current readings.';
const signInButton = id =>
  ` <button class="quiet-button notice-action" type="button" id="${id}">Sign in</button>`;
// What signInButton() adds to a notice's textContent.
const signInLabel = ' Sign in';
// A text's textContent once showText() has drawn it: its `quoted` parts without the quotes.
const shownText = text => text.replaceAll('`', '');
/**
 * Shows that this page is signed out, whichever request found it out: the dashboard's notice
 * with a Sign in button, the connection chip, and on a configuration page (where the
 * dashboard's notice is hidden) a notice of its own. Called when a load is refused with 401 and
 * when the user cancels signing in again (identity/session.js): polls stop then, so a page
 * whose sign-in was asked by a person's action (a card's pause, a save) would otherwise go on
 * saying it is live while its readings no longer change.
 *
 * `code` 'multiple_credentials': Uptime Goblin refuses this browser because it sent two cookies of
 * Uptime Goblin's name. Signing in fails the same way until this site's cookies are removed, so the
 * notices say that (the sign-in form's text for the code) and offer no Sign in.
 *
 * `transport` (a 401's): when Uptime Goblin will refuse any sign-in from this plain-HTTP page
 * (refusedInClear() in identity/signin.js), the notices say why, as the sign-in view does, and
 * offer no Sign in either: the password would cross the network unencrypted before the refusal.
 *
 * A notice that already shows what it would draw is left as it is. It is a role="status"
 * region, which reads out every change, and drawing it again would also replace its Sign in:
 * the keyboard focus on that button would drop to <body>, and the sign-in dialog opened from
 * it would find it gone after Cancel (its focus then went to the page's heading).
 */
export function showSignedOut(code = null, transport = null) {
  noticesCurrent = false;
  // A refusal no sign-in from this page can get past: said without a Sign in.
  const refused = code === 'multiple_credentials' ? code : refusedInClear(transport),
    text = refused ? signInTexts[refused] : signedOutText;
  for (const [notice, button] of [
    ['#notice', 'notice-sign-in'],
    ['#configuration-notice', 'configuration-sign-in'],
  ]) {
    const element = $(notice);
    if (
      !element.hidden &&
      (refused
        ? element.textContent === shownText(text) && !element.querySelector('button')
        : element.textContent === text + signInLabel && element.querySelector(`#${button}`))
    )
      continue;
    element.hidden = false;
    // `quoted` parts show as code, as in the sign-in view; nothing is parsed as HTML.
    showText(element, text);
    if (!refused) element.insertAdjacentHTML('beforeend', signInButton(button));
  }
  $('#connection').textContent = 'Signed out';
  $('#connection').classList.remove('live');
  // A configuration page that never loaded has nothing to draw: it says so under its notice,
  // whose Sign in stays the way in (polls stop, and routes draw nothing without data).
  if (!page.data && location.hash.startsWith('#configure'))
    showConfigurationHint(esc(signedOutHint));
}
/** Under a signed-out configuration page's notice when it never had data to draw. */
export const signedOutHint = 'Configuration shows once you sign in.';
/** What the page says once Uptime Goblin answers as a release before 1.5 (it was rolled back). */
export const olderReleaseText =
  'Uptime Goblin now runs an older release, which this page cannot sign in to, so what it shows is no longer updated. Reload the page to use that release.';
/**
 * Shows that Uptime Goblin was replaced by a release before 1.5 (a 401 without a code): the dashboard's
 * notice and the configuration page's, with no Sign in. The page reloads into that release by
 * itself when nothing would be lost; otherwise the update banner's Reload is the way in, and
 * the older release's own sign-in (the browser's prompt) takes over after it (§7.5).
 *
 * A notice that says so already is left as it is: it is a role="status" region, which reads out
 * every change, and each poll that release refuses says it again, as does a load that shared the
 * sign-in question that found it (identity/session.js).
 */
export function showOlderRelease() {
  noticesCurrent = false;
  for (const notice of ['#notice', '#configuration-notice']) {
    const element = $(notice);
    if (!element.hidden && element.textContent === olderReleaseText) continue;
    element.hidden = false;
    element.textContent = olderReleaseText;
  }
  $('#connection').textContent = 'Reload needed';
  $('#connection').classList.remove('live');
  if (!page.data && location.hash.startsWith('#configure'))
    showConfigurationHint(esc('Configuration shows once the page has reloaded.'));
}
/**
 * Undoes showSignedOut() once signed in again (identity/session.js): its notices go and the
 * chip says the page is connecting, until the load that follows says more.
 */
export function clearSignedOut() {
  for (const notice of ['#notice', '#configuration-notice'])
    if (
      [
        signedOutText,
        ...['multiple_credentials', 'https_required', 'proxy_proto_mismatch'].map(code =>
          shownText(signInTexts[code])
        ),
      ].some(t => $(notice).textContent.startsWith(t))
    )
      $(notice).hidden = true;
  if ($('#connection').textContent === 'Signed out') $('#connection').textContent = 'Connecting…';
}
// Without any data the configuration page cannot be drawn: it says why instead.
function showConfigurationHint(html) {
  $('#dashboard-page').hidden = true;
  $('#configuration-page').hidden = false;
  $('#configuration-content').innerHTML = `<div class="settings-hint">${html}</div>`;
}
function waitTime(seconds) {
  const minutes = Math.ceil(seconds / 60);
  return seconds < 60 ? `${seconds} seconds` : `${minutes} minute${minutes === 1 ? '' : 's'}`;
}
