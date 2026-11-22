// Updates: noticing a new Uptime Goblin release, reloading safely into it, and returning to the same view.
import { $, toast } from '../core/dom.js';
import { drawerDirty, pageDirty } from '../core/forms.js';
import { kiosk, page, pageBuild } from '../core/page.js';

let buildSeen = false,
  updateTimer = null,
  lastInput = -Infinity;
// Updates. Uptime Goblin names its build on every answer, sign-in refusals included (only /health
// does not). A page from another build reloads itself when nothing would be lost (no unsaved
// form, no change on its way or without an answer, no open dialog, nothing typed into the
// sign-in form), returning to the same view; otherwise a banner offers the reload. Wall
// displays (?kiosk=1, or a display code's session: body.display-mode) always reload. At most 2 unsuccessful automatic reloads per 10 minutes,
// so a proxy or cache that keeps serving an old page cannot make it reload for ever.
const wallDisplay = () => kiosk || document.body.classList.contains('display-mode');
const reloadLogKey = 'orbit-update-reloads',
  restoreKey = 'orbit-update-restore';
/** Compares the build Uptime Goblin reported with this page's own. */
export function noticeBuild(serverBuild, orbitAnswer) {
  if (serverBuild) buildSeen = true;
  // A successful answer matching this page proves the update succeeded, or was rolled
  // back before we reloaded. Retire its offer and failed attempts; a later genuine
  // release gets its own chance without being mistaken for a stuck cache.
  if (serverBuild && serverBuild === pageBuild && orbitAnswer) {
    page.updateBuild = null;
    clearTimeout(updateTimer);
    updateTimer = null;
    $('#update-banner').hidden = true;
    try {
      sessionStorage.removeItem(reloadLogKey);
    } catch {}
    return;
  }
  // A page without a build (an index.html from before 1.4.3, kept by a cache) is older than
  // any build Uptime Goblin reports. A build that stops being reported means Uptime Goblin went back to a
  // release before 1.4.3; only Uptime Goblin's own successful answers count, not a proxy's error page.
  const changed = serverBuild ? serverBuild !== pageBuild : buildSeen && orbitAnswer;
  if (!changed || (page.updateBuild && page.updateBuild === (serverBuild || 'unknown'))) return;
  page.updateBuild = serverBuild || 'unknown';
  offerUpdate();
}
/** True while the sign-in view shows and the user has typed into it. */
function signInTyped() {
  const view = $('#signin-page');
  return (
    !!view &&
    !view.hidden &&
    [...view.querySelectorAll('input:not([type=checkbox])')].some(input => input.value)
  );
}
function updateSafe() {
  return (
    !page.writesPending &&
    !page.writeUnknown &&
    !page.busyForm &&
    !pageDirty() &&
    !drawerDirty() &&
    // Any open dialog, the sign-in dialog included: its drafts stay open behind it.
    !document.querySelector('dialog[open]') &&
    !signInTyped()
  );
}
function recentReloads() {
  const log = JSON.parse(sessionStorage.getItem(reloadLogKey) || '[]');
  return Array.isArray(log) ? log.filter(t => Number.isFinite(t) && Date.now() - t < 600000) : [];
}
export function offerUpdate() {
  if (!page.updateBuild || updateTimer) return;
  if (!wallDisplay() && !updateSafe()) {
    showUpdateBanner(false);
    return;
  }
  let allowed = false;
  try {
    allowed = recentReloads().length < 2;
  } catch {}
  if (!allowed) {
    showUpdateBanner(true);
    return;
  }
  // Someone using the page gets a moment: wait until 10 s after their last key or click.
  const busy = document.hidden || wallDisplay() ? 0 : lastInput + 10000 - performance.now();
  if (busy > 0) {
    updateTimer = setTimeout(() => {
      updateTimer = null;
      offerUpdate();
    }, busy);
    return;
  }
  if (!document.hidden) toast('Uptime Goblin was updated. Reloading this page…');
  updateTimer = setTimeout(
    () => {
      updateTimer = null;
      if (wallDisplay() || updateSafe()) reloadForUpdate(true);
      else showUpdateBanner(false);
    },
    document.hidden ? 0 : 1000
  );
}
/** Reloads into the new release, keeping this tab's view (the route stays in the URL). */
function reloadForUpdate(automatic) {
  try {
    if (automatic)
      sessionStorage.setItem(reloadLogKey, JSON.stringify([...recentReloads(), Date.now()]));
    sessionStorage.setItem(
      restoreKey,
      JSON.stringify({
        at: Date.now(),
        expanded: page.expanded,
        range: page.range,
        metric: page.selectedMetric,
        scrollY: window.scrollY,
      })
    );
  } catch {
    // Without a record of reloads an automatic one could repeat for ever: ask instead.
    if (automatic) {
      showUpdateBanner(false);
      return;
    }
  }
  page.kioskUpdateReloading = automatic && wallDisplay();
  location.reload();
}
function showUpdateBanner(looping) {
  $('#update-text').textContent = looping
    ? 'Uptime Goblin was updated, but this page is still the older version after reloading. A proxy or browser cache may be serving an old copy: reload again, or clear this site’s cached files.'
    : 'Uptime Goblin was updated. Reload to use the new version; changes you have not saved are lost when the page reloads.';
  $('#update-banner').hidden = false;
}
/** Returns to the scroll position the page had before an update reload. */
export function restoreScroll(chartDrawn = false) {
  if (page.pendingScroll === null) return;
  window.scrollTo({ top: page.pendingScroll, behavior: 'instant' });
  // The page has its final height once the open chart is drawn (or when none is open).
  if (chartDrawn || !page.expanded) page.pendingScroll = null;
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  try {
    page.restored = JSON.parse(sessionStorage.getItem(restoreKey) || 'null');
    sessionStorage.removeItem(restoreKey);
    if (
      !page.restored ||
      typeof page.restored !== 'object' ||
      !(Date.now() - page.restored.at < 300000)
    )
      page.restored = null;
  } catch {
    page.restored = null;
  }
  // Builds the update banner if the page lacks it. In 1.4.x this ran for the pre-1.4.3 HTML
  // a cache could still return while its unversioned app.js loaded the new release. From 1.5
  // that cannot happen: /boot.js starts this module only in a page that loads /boot.js itself
  // and names a build, whose modules these are, and that release's index.html has the banner
  // (test/web.test.mjs checks it); an older page is never run but replaced, by /boot.js's
  // reloads and background checks. So this runs only if something rewrote the page on its way
  // (a proxy or a browser extension that removed the banner), and it keeps the Reload button
  // working there rather than failing to start.
  if (!$('#update-banner')) {
    const banner = document.createElement('div');
    banner.id = 'update-banner';
    banner.className = 'update-banner';
    banner.setAttribute('role', 'status');
    banner.hidden = true;
    banner.innerHTML =
      '<p id="update-text"></p><button class="button primary" type="button" id="update-reload">Reload</button>';
    $('#dashboard-page').before(banner);
  }
  $('#update-reload').addEventListener('click', () => reloadForUpdate(false));
  for (const type of ['keydown', 'pointerdown', 'wheel', 'touchstart'])
    document.addEventListener(
      type,
      e => {
        if (!e.isTrusted) return;
        lastInput = performance.now();
        // The user has moved on: stop returning to the position from before the reload.
        page.pendingScroll = null;
      },
      { capture: true, passive: true }
    );
  for (const dialog of document.querySelectorAll('dialog'))
    dialog.addEventListener('close', () => {
      if (page.updateBuild) setTimeout(offerUpdate);
    });
}
