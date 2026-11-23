// The dashboard: appearance, source cards, the summary strip, alerts dialog and the clock.
import { forgetHistory, refreshHistory, renderGraph } from '../charts/charts.js';
import { refreshAlertsDialog } from '../configure/notifications.js';
import { navigate } from '../configure/pages.js';
import { api, conflictMessage, replaceService, writeConfig } from '../core/api.js';
import { $, esc, exitMs, icon, openDialog, reducedMotion, states, toast } from '../core/dom.js';
import { dateTime, format, when } from '../core/format.js';
import { load } from '../core/load.js';
import { page, stateFor } from '../core/page.js';
import { patchHtml } from '../core/patch.js';
import { configure } from '../drawer/drawer.js';

function launchAttributes() {
  return page.data?.config.appearance?.openInNewTab === false
    ? ''
    : 'target="_blank" rel="noopener noreferrer"';
}
function applyAppearance() {
  const a = page.data.config.appearance || {};
  document.documentElement.style.setProperty(
    '--mint',
    `var(--${['cyan', 'orange', 'blue', 'violet', 'amber', 'pink', 'green'].includes(a.accent) ? a.accent : 'cyan'})`
  );
  document.documentElement.dataset.density = a.density || 'comfortable';
  document.documentElement.dataset.columns = a.columns || 'auto';
  document.documentElement.dataset.reduceMotion = String(!!a.reduceMotion);
  $('.summary').hidden = a.showSummary === false;
  $('#dashboard-title').textContent = page.data.config.title || 'Overview';
  $('#dashboard-subtitle').textContent = page.data.config.subtitle || '';
  $('#dashboard-subtitle').hidden = !page.data.config.subtitle;
  document.title = `${page.data.config.title || 'Uptime Goblin'} · Homelab`;
  clock();
}
export function render() {
  if (!page.data) return;
  const focused = document.activeElement;
  const focusKey = focused?.dataset.expand
    ? `[data-expand="${CSS.escape(focused.dataset.expand)}"]`
    : focused?.dataset.toggle
      ? `[data-toggle="${CSS.escape(focused.dataset.toggle)}"]`
      : focused?.id === 'metric-select'
        ? '#metric-select'
        : null;
  applyAppearance();
  const allServices = page.data.config.services,
    a = page.data.config.appearance || {},
    services = allServices.filter(
      s =>
        s.showOnDashboard !== false &&
        (a.showPaused !== false || s.enabled) &&
        (a.showUnconfigured !== false || stateFor(s.id).status !== 'unconfigured')
    );
  if (a.sortBy === 'name') services.sort((x, y) => x.name.localeCompare(y.name));
  if (a.sortBy === 'status') {
    const order = {
      error: 0,
      stale: 1,
      collecting: 2,
      live: 3,
      unconfigured: 4,
      disabled: 5,
      link: 6,
    };
    services.sort(
      (x, y) =>
        (order[stateFor(x.id).status] ?? 9) - (order[stateFor(y.id).status] ?? 9) ||
        x.name.localeCompare(y.name)
    );
  }
  const active = allServices.filter(s => s.enabled),
    monitored = page.data.services.filter(s => s.configured && active.some(c => c.id === s.id)),
    live = monitored.filter(s => s.status === 'live').length,
    paused = allServices.length - active.length;
  $('#connected-count').innerHTML = `${live}<span> / ${monitored.length}</span>`;
  $('#connected-note').textContent = monitored.length
    ? paused
      ? `${paused} source${paused === 1 ? '' : 's'} paused`
      : 'Configured sources'
    : 'Connect your first source';
  $('#connection').textContent = live
    ? 'Collection active'
    : monitored.length
      ? 'Checking sources'
      : 'Awaiting connections';
  $('#connection').classList.toggle('live', live > 0);
  $('#alert-count').textContent = page.data.alerts.length;
  $('#alert-note').textContent =
    page.data.config.alerts?.enabled === false
      ? 'Alert evaluation paused'
      : page.data.alerts.length
        ? 'Requires your attention'
        : monitored.length
          ? 'No active alerts'
          : 'No measurements yet';
  $('#alerts-button').classList.toggle('has-alert', page.data.alerts.length > 0);
  $('#last-collected').textContent = when(page.data.lastCollected);
  $('#retention').innerHTML = `${page.data.config.retentionDays}<span> days</span>`;
  $('#source-count').textContent =
    services.length === allServices.length
      ? services.length
      : `${services.length} of ${allServices.length}`;
  $('#footer-status').textContent = `Every ${page.data.config.pollSeconds}s · stored locally`;
  patchHtml(
    $('#services'),
    services.length
      ? [...new Set(services.map(s => s.group))]
          .map(group => {
            const items = services.filter(s => s.group === group);
            return `<section class="group" data-group="${esc(group)}"><div class="group-heading"><h2>${esc(group)}</h2><span>${String(items.length).padStart(2, '0')}</span></div><div class="cards">${items.map(card).join('')}</div></section>`;
          })
          .join('')
      : allServices.length
        ? '<div class="empty-history"><h4>A quieter view</h4><p>Your sources are hidden by your dashboard preferences. Monitoring continues for enabled connections.</p><a class="button" href="#configure/sources">Manage sources</a></div>'
        : '<div class="empty-history"><h4>Room for your homelab</h4><p>Add your first source to start collecting measurements.</p><button class="button" data-add-source>Add a source</button></div>'
  );
  if (page.expanded) renderGraph(page.expanded);
  if (focusKey && !focused.isConnected) $(focusKey)?.focus({ preventScroll: true });
}
/** Folds the expanded card away with the same subtle motion. */
export function collapseExpanded() {
  const id = page.expanded;
  if (!id || page.collapsingId === id) return;
  const generation = ++page.collapseGeneration;
  const finish = () => {
    // Another card was opened meanwhile (possibly this one again): this fold is obsolete.
    if (generation !== page.collapseGeneration) return;
    page.collapsingId = null;
    if (page.expanded !== id) return;
    page.expanded = null;
    page.selectedMetric = '';
    forgetHistory();
    render();
  };
  const card = document.querySelector(`.service[data-id="${CSS.escape(id)}"]`);
  if (!card || reducedMotion()) return finish();
  page.collapsingId = id;
  card.classList.add('collapsing');
  setTimeout(finish, exitMs);
}
function card(s) {
  const state = stateFor(s.id),
    open = page.expanded === s.id,
    metrics = state.metrics?.slice(0, 3) || [],
    // The effective collector decides, not the card type: a Website card can be switched
    // to Bookmark only, and a Bookmark card to a Website check.
    labels =
      state.collector === 'http'
        ? ['Response', 'Available', 'HTTP status']
        : state.collector === 'none'
          ? []
          : s.labels;
  const count = Math.max(labels.length, metrics.length);
  return `<article class="service ${open ? 'expanded' : ''} ${page.collapsingId === s.id ? 'collapsing' : ''} ${!s.enabled ? 'paused' : ''}" style="--accent:var(--${esc(s.color)})" data-id="${esc(s.id)}">
 <div class="card-top"><div class="service-icon">${icon(s.icon)}</div><div class="service-title"><h3>${s.url ? `<a href="${esc(s.url)}" ${launchAttributes()}>${esc(s.name)} ${icon('external', 12)}</a>` : esc(s.name)}</h3><span class="state ${esc(state.status)}">${states[state.status] || 'Unknown'}</span></div>
 <div class="card-controls"><button class="pause-control ${!s.enabled ? 'is-paused' : ''}" data-toggle="${esc(s.id)}" aria-label="${s.enabled ? 'Pause' : 'Resume'} ${esc(s.name)}" title="${s.enabled ? 'Pause monitoring' : 'Resume monitoring'}">${icon(s.enabled ? 'pause' : 'play', 13)}</button><button class="expand" data-expand="${esc(s.id)}" aria-expanded="${open}" aria-controls="detail-${esc(s.id)}" aria-label="${open ? 'Hide' : 'Show'} stats for ${esc(s.name)}">${icon('chevron', 15)}</button></div></div>
 ${count ? `<div class="mini-metrics">${Array.from({ length: Math.min(count, 3) }, (_, i) => `<div><span>${esc(metrics[i]?.label || labels[i] || 'Measurement')}</span><strong class="${metrics[i] ? '' : 'empty'}">${esc(metrics[i] ? format(metrics[i].value, metrics[i].unit) : '—')}</strong></div>`).join('')}</div>` : `<p class="utility-note${s.url ? '' : ' launch-note'}">${s.url ? 'Your workspace, one click away' : 'Add a destination to launch this service'}</p>`}
 ${s.enabled ? noteList(state.notes) : ''}
 <div id="detail-${esc(s.id)}" ${open ? '' : 'hidden'} class="detail">${open ? detail(s, state) : ''}</div></article>`;
}
/**
 * Collector notes: readings a collection left out because of a limit (a library too large to
 * count, more devices than Uptime Goblin reads), in the collector's own words.
 */
export function noteList(notes, className = 'source-notes') {
  return Array.isArray(notes) && notes.length
    ? `<ul class="${className}">${notes.map(n => `<li>${esc(n?.message)}</li>`).join('')}</ul>`
    : '';
}
function detail(s, state) {
  const hasMetrics = state.metrics?.length;
  return `<div class="detail-top"><div><h4>${esc(s.name)} <span class="muted">/</span> Insights</h4><p>${!s.enabled ? 'Monitoring paused · saved readings are preserved' : state.lastSuccess ? 'Last successful reading ' + dateTime(state.lastSuccess) : 'Current measurements and historical trends'}</p></div><div class="detail-actions"><div class="ranges" aria-label="History period">${['1h', '6h', '24h', '7d', '30d'].map(r => `<button class="range-button ${page.range === r ? 'active' : ''}" data-range="${r}" aria-pressed="${page.range === r}">${r}</button>`).join('')}</div><button class="button" data-configure="${esc(s.id)}">Configure</button></div></div>
 ${state.error && s.enabled ? `<div class="detail-error">${esc(state.error)}</div>` : ''}
 ${hasMetrics ? `<div id="graph-${esc(s.id)}" class="graph-layout" data-graph><div class="loading">Loading history…</div></div>` : `<div class="empty-history"><div class="empty-symbol">${icon('chart', 27)}</div><h4>${!s.enabled ? 'Taking a breather' : state.collector === 'none' ? 'A place for your service' : state.configured ? 'No measurements yet' : 'Ready when you are'}</h4><p>${!s.enabled ? 'Resume this source whenever you want to collect new readings. Existing settings are saved.' : state.collector === 'none' ? 'Set a destination URL to open this service from Uptime Goblin.' : state.configured ? (state.error ? 'Uptime Goblin has this connection but has not received a reading yet. Check the error above, then edit the connection if needed.' : 'Waiting for the first reading. Historical graphs build automatically as readings arrive.') : 'Connect this source to see real measurements. Historical graphs build automatically as readings arrive.'}</p><button class="button" ${!s.enabled ? `data-toggle="${esc(s.id)}"` : `data-configure="${esc(s.id)}"`}>${!s.enabled ? 'Resume monitoring' : state.configured ? 'Edit connection' : 'Connect ' + esc(s.name)} ${icon('external', 12)}</button></div>`}
 <div class="detail-foot"><span>${!s.enabled ? 'Polling and alerts are paused' : hasMetrics ? (s.rules.length ? `${s.rules.length} metric rule${s.rules.length === 1 ? '' : 's'} · connection monitored` : 'Connection monitored · no metric rules') : 'No measurements collected'}</span><div class="detail-foot-actions">${hasMetrics ? `<button class="quiet-button" data-export-history="${esc(s.id)}">Export ${esc(page.range)} CSV</button>` : ''}${s.url ? `<a href="${esc(s.url)}" ${launchAttributes()}>Open ${esc(s.name)} ↗</a>` : '<span class="launch-note">Destination not set</span>'}</div></div>`;
}
export function renderAlerts() {
  const active = page.data.alerts
    .map(
      a =>
        `<div class="alert-row"><span class="alert-kind">${a.rule === '__availability' ? 'Connection check' : 'Metric threshold'}</span><strong>${esc(a.name)}</strong><p>${esc(a.message)}</p><small>Since ${dateTime(a.since)}</small></div>`
    )
    .join('');
  const events = (page.data.events || [])
    .slice(0, 12)
    .map(
      e =>
        `<div class="event-row"><span class="${e.kind === 'resolved' ? 'resolved' : 'firing'}">${e.kind === 'resolved' ? 'Resolved' : 'Alert'}</span><div><strong>${esc(e.name)}</strong><p>${esc(e.message)}</p></div><time>${when(e.time)}</time></div>`
    )
    .join('');
  $('#alerts-content').innerHTML =
    (active
      ? '<p class="settings-info">A connection alert means Uptime Goblin could not complete its check. A metric alert means a reported measurement crossed its threshold; the service may still be reachable.</p>'
      : '') +
    (active ||
      `<div class="empty-history"><div class="empty-symbol">${icon('check', 25)}</div><h4>No active alerts</h4><p>${page.data.services.some(s => s.configured) ? 'Enabled sources are checked in the background. Paused sources do not generate alerts.' : 'Connect your sources to begin monitoring, then set thresholds for the measurements that matter.'}</p></div>`) +
    // One line per channel that needs attention, from the delivery status (read once the
    // dialog shows, and only when the dashboard says a channel needs attention).
    '<div id="alerts-delivery-lines"></div>' +
    (events ? `<section class="config-section"><h3>Recent activity</h3>${events}</section>` : '');
  void refreshAlertsDialog();
}
export async function toggleSource(id) {
  const s = page.data.config.services.find(s => s.id === id);
  if (!s) return;
  try {
    await writeConfig(
      `/api/services/${id}`,
      { method: 'PATCH', body: JSON.stringify({ enabled: !s.enabled }) },
      { revision: () => page.data.config.revision, apply: replaceService, source: id }
    );
    // The chart shows the pause gap, and the first reading after a resume, at once.
    if (id === page.expanded) refreshHistory(id);
    await load();
    toast(s.enabled ? `${s.name} paused. Settings and history are saved.` : `${s.name} resumed.`);
  } catch (e) {
    toast(e.status === 409 ? `${conflictMessage} The latest settings are shown now.` : e.message);
    if (e.status === 409) await load();
  }
}
export function clock() {
  $('#clock').textContent = dateTime(Date.now(), {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  $('#settings').onclick = () => navigate(page.configurationSection ? '#' : '#configure/overview');
  $('#add-source').onclick = () => configure(null, true);
  $('#collapse-all').onclick = () => collapseExpanded();
  // A click anywhere else on the dashboard that is not a control folds the open card away.
  // The click that closes a pop-up (a dialog's backdrop, or outside the open user menu) does
  // only that, and a click on a pop-up or a banner (its padding, its text) is not "elsewhere".
  // main.js installs this before identity/session.js's handler that closes the user menu, so
  // the menu is still open here on the click that closes it.
  document.addEventListener('click', e => {
    if (!page.expanded || e.button !== 0 || e.defaultPrevented) return;
    const target = e.target;
    if (!(target instanceof Element) || !target.isConnected) return;
    if ($('#dashboard-page').hidden || document.querySelector('dialog[open]')) return;
    if (!$('#user-menu').hidden) return;
    if (
      target.closest(
        '.service.expanded, a, button, input, select, textarea, label, summary, [role="button"], [tabindex], [contenteditable], dialog, .toast, #update-banner, .user-area, #session-banner'
      )
    )
      return;
    // Releasing a text selection is not a click on the page.
    if (String(getSelection() || '')) return;
    collapseExpanded();
  });
  $('#refresh').onclick = async () => {
    try {
      await api('/api/refresh', { method: 'POST', body: '{}' });
      toast('Refreshing enabled sources…');
      if (page.expanded) refreshHistory(page.expanded);
      await load();
      setTimeout(load, 2000);
    } catch (e) {
      toast(e.message);
    }
  };
  $('#alerts-button').onclick = () => {
    if (!page.data) return;
    renderAlerts();
    openDialog($('#alerts-dialog'));
  };
}
