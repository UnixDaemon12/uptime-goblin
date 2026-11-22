// This page: the state its modules share (the `let` bindings more than one module reads or writes
// live on `page`), what it is (its build, whether it is a wall display) and the state of a source.

// The `let` bindings of public/app.js (1.4.3) that more than one module uses, in their original
// order with their original comments. Code reads and writes them as page.<name>.
export const page = {
  data: undefined,
  expanded: null,
  range: '24h',
  selectedMetric: '',
  settingsId: null,
  draftRules: [],
  testController: undefined,
  configurationSection: null,
  pageBaseline: '',
  drawerBaseline: '',
  drawerRulesBaseline: '',
  // Configuration revision the settings page and the source drawer were drawn from.
  pageRevision: undefined,
  drawerRevision: undefined,
  busyForm: null,
  // The control that had the focus when a request disabled it: busyForm's (lockForm()), a
  // button of the Account page's sessions list, an export or Test connection (holdFocus()).
  busyFocus: null,
  dashboardPollTimer: undefined,
  writesPending: 0,
  // A change sent without an answer: it may have been saved. Cleared by the next load().
  writeUnknown: false,
  // The newer release Uptime Goblin reported ('unknown' when it stopped reporting one).
  updateBuild: null,
  kioskUpdateReloading: false,
  // Set once the user chose Sign out (and agreed to discard unsaved changes), so leaving the
  // page does not ask again.
  signingOut: false,
  dashboardController: null,
  // Scroll position to return to after an update reload, until the chart is drawn.
  pendingScroll: null,
  // The newest revision this tab's own writes produced, and how many older dashboard
  // snapshots have been skipped in a row because of it.
  writtenRevision: 0,
  staleSnapshots: 0,
  restored: null,
  // The card whose details are folding away (see collapseExpanded() in dashboard.js).
  collapsingId: null,
  // Each fold gets a number; opening any card moves it on, so an older fold's timer can
  // never close a card that was opened again meanwhile.
  collapseGeneration: 0,
  // The guide the Help page opens with when a link asked for one (data-help), instead of the
  // configuration guide.
  helpDoc: null,
  // The Kind the Audit log opens with when a link asked for one (data-audit-kind), instead of
  // every kind.
  auditKind: null,
};
// The release this page came from (the server writes it into index.html), and whether the
// page is a wall display (?kiosk=1), which always reloads itself for a new release.
export const pageBuild = document.querySelector('meta[name="orbit-build"]')?.content || '';
export const kiosk = new URLSearchParams(location.search).get('kiosk') === '1';
export function stateFor(id) {
  return page.data.services.find(s => s.id === id) || { status: 'unconfigured', metrics: [] };
}
