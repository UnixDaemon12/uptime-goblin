// The web app's entry point, loaded by /boot.js from /assets/<build>/modules/main.js. It installs
// every module's event handlers in the order public/app.js registered them before 1.5 (the
// identity modules of 1.5 after them), finds out who is signed in, and only then starts the
// clock, the first load and the polls: a signed-out page loads nothing but the sign-in view.
import { install as installCharts } from './charts/charts.js';
import { install as installAudit } from './configure/audit.js';
import { install as installConfigure } from './configure/events.js';
import { install as installKumaImport } from './configure/kuma-import.js';
import { install as installNotifications, pollNotifications } from './configure/notifications.js';
import { api, versionProbeMs } from './core/api.js';
import { $ } from './core/dom.js';
import { load } from './core/load.js';
import { kiosk, page } from './core/page.js';
import { clock, install as installDashboard } from './dashboard/dashboard.js';
import { install as installDrawer } from './drawer/drawer.js';
import { install as installAccount } from './identity/account.js';
import {
  displaySession,
  focusPageHeading,
  install as installSession,
  refreshSession,
  signInPending,
  startSession,
} from './identity/session.js';
import { install as installSignIn } from './identity/signin.js';
import { install as installUpdate } from './update/update.js';

// Event handlers first, in the order public/app.js (1.4.3) registered them, then the 1.5 ones
// (identity, then notifications, then the audit log, then the Uptime Kuma import). The sign-in
// form's submit handler is among them, so it is in place before the sign-in view can show.
installDrawer();
installCharts();
installDashboard();
installConfigure();
installUpdate();
installSession();
installSignIn();
installAccount();
installNotifications();
installAudit();
installKumaImport();
// Not awaited at the top level: /boot.js learns that the web app loaded as soon as this module
// has run, not only once somebody signs in.
startSession().then(how => {
  clock();
  setInterval(clock, 30000);
  const firstLoad = load({ background: kiosk });
  // Signed in through the sign-in view: focus went to the dashboard's heading. When the
  // address opens a configuration page instead, the first load shows it; its heading then
  // takes the focus.
  if (how === 'view')
    firstLoad.then(() => {
      const focused = document.activeElement;
      if (!focused || focused === document.body || focused.closest('[hidden]')) focusPageHeading();
    });
  page.dashboardPollTimer = setInterval(pollDashboard, 15000);
});
// Polls are background requests, so a dashboard left open does not keep its session signed in
// for ever, including wall displays (?kiosk=1). Kiosk reads never extend the idle limit.
// While the session has ended they wait: signing in again resumes them. Every few minutes a
// poll that loaded also reads the session again for its banners (refreshSession()): only then,
// so a release before 1.5 (Uptime Goblin rolled back), which refuses the poll, is not asked as well.
// The Notifications page (and the Alerts page's channel rows) read the delivery status at the
// same rhythm, beside the dashboard, so a dashboard that cannot load does not hide that the
// status cannot be read either.
function pollDashboard() {
  if (!document.hidden && (kiosk || !$('#settings-dialog').open) && !signInPending()) {
    load({ background: true }).then(loaded => {
      if (loaded) refreshSession();
    });
    // A wall display may not read the delivery status (dashboard:read only).
    if (!displaySession()) void pollNotifications();
  }
}
// Polling stops in a background tab; catch up at once, so a drawer or form opened after
// returning starts from the current configuration.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && page.data) pollDashboard();
});
// A background tab does not poll, but still learns about a new release every 5 minutes.
setInterval(() => {
  if (document.hidden && page.data && !signInPending())
    api('/api/version', { background: true }).catch(() => {});
}, versionProbeMs);
// The network is back: drop a request that may never answer, and load now.
window.addEventListener('online', () => {
  if (!page.data) return;
  page.dashboardController?.abort();
  pollDashboard();
});
