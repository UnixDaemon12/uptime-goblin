// Orbit's loader, the only script index.html names. The page says which release wrote it in
// <meta name="orbit-build">, and this loads that release's web app from /assets/<build>/, whose
// files never change, so a page never mixes code from two releases. Every page, old or new, runs
// the current copy of this file (it is served no-cache), so it stays the same from release to
// release; a test pins its hash.
//
// When the web app cannot load, the page reloads to fetch the current index.html: its release's
// files are gone (an open tab or a cached copy from an earlier release), it is a page from before
// 1.5 (it asked for /app.js, which now only loads this file), or loading failed on the way. These
// reloads share the update check's allowance (at most 2 automatic reloads per 10 minutes, kept in
// sessionStorage), so a proxy that keeps serving an old page cannot make it reload for ever. Then
// the page says what happened and offers a Reload button. A page that is still an older version
// after those reloads (a proxy or the browser cache kept it) cannot run this release's web app,
// whose markup differs, so it keeps asking for the page in the background and reloads once the
// answer is a current page: a wall display nobody watches opens by itself once the cache lets go.
// While Orbit does not answer at all (it is restarting, or a proxy reports it down), the page says
// so and waits for it instead, asking again every few seconds, so it opens by itself once Orbit
// is back rather than reloading into the browser's error page. There is no inline script, so the
// strict Content-Security-Policy holds.
const reloadLogKey = 'orbit-update-reloads',
  checkKey = 'orbit-stale-checks';
// The background checks of a page stuck on an older version: the first 30 s after the page says
// so (a cache that served the old page briefly, around the upgrade, has usually let go by then,
// and the page has just reloaded twice), then twice as long each time, up to every 10 minutes,
// the reload allowance's window. A wall display then opens at most 10 minutes after the cache
// serves the current page, and a cache that never does costs one small request per 10 minutes.
const firstCheck = 30000,
  lastCheck = 600000;
const loader = 'script[type="module"][src="/boot.js"], script[type="module"][src^="/boot.js?"]';

/**
 * The build of a page from 1.5 on, which loads /boot.js itself and names its build, or '' for
 * any other page, such as one from before 1.5 that reached this file through the /app.js shim.
 */
function pageBuild(doc) {
  const build = doc.querySelector('meta[name="orbit-build"]')?.content ?? '';
  return doc.querySelector(loader) && /^[0-9a-f]{6,64}$/.test(build) ? build : '';
}
const build = pageBuild(document);

function recentReloads() {
  const log = JSON.parse(sessionStorage.getItem(reloadLogKey) || '[]');
  return Array.isArray(log) ? log.filter(t => Number.isFinite(t) && Date.now() - t < 600000) : [];
}
/**
 * This tab's record of the background checks, kept across reloads: when the last one ran (or
 * the checks began) and how long after that the next is due. Null when there is none.
 */
function checks() {
  const record = JSON.parse(sessionStorage.getItem(checkKey) || 'null');
  return Number.isFinite(record?.at) && record.wait >= firstCheck && record.wait <= lastCheck
    ? record
    : null;
}

/** Shows `message` in the page's update banner, which pages before 1.4.3 do not have. */
function notice(message) {
  let banner = document.getElementById('update-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'update-banner';
    banner.className = 'update-banner';
    banner.setAttribute('role', 'status');
    const text = document.createElement('p'),
      button = document.createElement('button');
    text.id = 'update-text';
    button.id = 'update-reload';
    button.type = 'button';
    button.className = 'button primary';
    button.textContent = 'Reload';
    banner.append(text, button);
    document.body.prepend(banner);
  }
  document.getElementById('update-text').textContent = message;
  document.getElementById('update-reload').onclick = () => location.reload();
  banner.hidden = false;
}

/**
 * Reloads once more if the allowance permits, or explains; a page that is `stale` (an older
 * version) then checks in the background for the current one.
 */
function recover(stale) {
  try {
    const log = recentReloads();
    // Once this tab has said its page is stuck, only the background check reloads it: a cache
    // that answers the check with the current page but a reload with the old one then costs one
    // reload per check, not two more whenever the allowance's 10 minutes have passed.
    if (log.length < 2 && !(stale && checks())) {
      sessionStorage.setItem(reloadLogKey, JSON.stringify([...log, Date.now()]));
      location.reload();
      return;
    }
  } catch {
    // Without a record of reloads, a reload could repeat for ever: explain instead.
  }
  const older =
    'Uptime Goblin was updated, but this page is still the older version after reloading. A proxy or browser cache may be serving an old copy';
  if (!stale)
    notice(
      'Uptime Goblin’s web app could not be loaded. It may be restarting or out of reach: reload in a moment.'
    );
  else if (watch())
    notice(
      `${older}: this page checks again by itself and opens the new version once it is served. You can also reload, or clear this site’s cached files.`
    );
  else notice(`${older}: reload again, or clear this site’s cached files.`);
}

let checkTimer = 0,
  checking = null;
/**
 * Starts the background checks of a page stuck on an older version, keeping this tab's
 * schedule across reloads. False when sessionStorage cannot keep it: each reload would then
 * start again from the first interval, so the page waits for its Reload button instead.
 */
function watch() {
  let record;
  try {
    record = checks() ?? { at: Date.now(), wait: firstCheck };
    sessionStorage.setItem(checkKey, JSON.stringify(record));
  } catch {
    return false;
  }
  // Due one interval after the last check, even when that check was made by the page before a
  // reload, and never later than one interval from now, in case the clock was turned back.
  clearTimeout(checkTimer);
  checkTimer = setTimeout(
    check,
    Math.min(record.wait, Math.max(0, record.at + record.wait - Date.now()))
  );
  return true;
}
/**
 * One background check. It asks for this page's URL past the browser's cache: cache: 'reload'
 * replaces the browser's copy and sends no-cache, so a well-behaved proxy asks Orbit again. The
 * page reloads only when the answer is a page this one is not, one from 1.5 on with another
 * build; the same old page, an error or no answer waits for the next check. The next check is
 * recorded before this one asks, so even a proxy that answers the check with the current page but
 * the reload with the old one gets one reload per check, whose interval keeps growing.
 */
async function check() {
  let wait;
  try {
    wait = Math.min((checks()?.wait ?? firstCheck) * 2, lastCheck);
    sessionStorage.setItem(checkKey, JSON.stringify({ at: Date.now(), wait }));
  } catch {
    return;
  }
  // A check still waiting for its answer when the next is due is dropped, so a proxy that holds
  // requests open cannot stop the checks or pile them up.
  checking?.abort();
  const controller = (checking = new AbortController());
  checkTimer = setTimeout(check, wait);
  let found = '';
  try {
    const response = await fetch(location.href, { cache: 'reload', signal: controller.signal });
    // DOMParser only reads the answer: nothing in it runs or loads.
    if (response.ok)
      found = pageBuild(new DOMParser().parseFromString(await response.text(), 'text/html'));
  } catch {}
  if (found && found !== build) {
    clearTimeout(checkTimer);
    location.reload();
  }
}

/**
 * The web app did not load: asks Orbit about this page's build. 404 means Orbit no longer has
 * it (reload into the current release); any other answer from Orbit means loading failed on the
 * way (reload). No answer, or "not now" (429, or 502-504 from Orbit or a proxy in front of it),
 * means Orbit is not answering: say so, and ask again after `wait` ms, less often each time.
 */
async function failed(wait) {
  let status = 0;
  try {
    status = (
      await fetch(`/assets/${build}/modules/main.js`, { method: 'HEAD', cache: 'no-store' })
    ).status;
  } catch {}
  if (status && ![429, 502, 503, 504].includes(status)) {
    recover(status === 404);
    return;
  }
  notice(
    'Uptime Goblin is not answering. It may be restarting: this page opens by itself once it is back.'
  );
  setTimeout(() => failed(Math.min(wait * 2, 10000)), wait);
}

// Only a page from 1.5 on has the markup this release's web app expects; any other is replaced.
if (!build) recover(true);
else
  import(`/assets/${build}/modules/main.js`).then(
    () => {
      // The web app runs, so this tab is no longer stuck on an older page: should it get one
      // again, it starts over with the reload allowance and the first check interval.
      try {
        sessionStorage.removeItem(checkKey);
      } catch {}
    },
    () => failed(1000)
  );
