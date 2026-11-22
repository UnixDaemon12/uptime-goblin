// Configuration pages and their routes: overview, appearance, sources, monitoring, alerts, email,
// notifications, account, audit log, data, system and help.
import { historyDue, loadHistory, renderGraph } from '../charts/charts.js';
import { auditPage, loadAudit } from './audit.js';
import { emailSettings, emailStatusText } from './email.js';
import { kumaImportPanel } from './kuma-import.js';
import {
  alertsDeliveryRows,
  loadNotifications,
  notificationsPage,
  refreshAlertsDelivery,
  resetAlertsDelivery,
} from './notifications.js';
import { loadSystem } from './system.js';
import { conflictMessage, mergeSettings, writeConfig } from '../core/api.js';
import { $, closeDialog, esc, icon, states, toast } from '../core/dom.js';
import { timeZoneNote } from '../core/format.js';
import {
  allowDrawerLeave,
  allowPageLeave,
  field,
  formSnapshot,
  lockForm,
  pageDirty,
  pageForm,
  saveBar,
  selectField,
  settingsBlock,
  switchField,
  updateDirtyIndicator,
} from '../core/forms.js';
import { load } from '../core/load.js';
import { page, stateFor } from '../core/page.js';
import { patchHtml } from '../core/patch.js';
import { loadDocumentation } from '../docs/docs.js';
import { accountPage, loadAccount } from '../identity/account.js';

const configurationSections = [
  ['overview', 'Overview', 'orbit', 'A clear view of your workspace.'],
  ['appearance', 'Appearance', 'grid', 'Make Uptime Goblin feel like home.'],
  ['sources', 'Sources', 'layers', 'Every connection, in one place.'],
  ['monitoring', 'Monitoring', 'activity', 'Set a steady rhythm for your homelab.'],
  ['alerts', 'Alerts', 'shield', 'Keep the signals that matter.'],
  ['email', 'Email', 'ticket', 'A heads-up, wherever you are.'],
  ['notifications', 'Notifications', 'route', 'Know that every alert got through.'],
  ['account', 'Account', 'lock', 'Your sign-in and sessions.'],
  ['audit', 'Audit log', 'list', 'Who changed what, and when.'],
  ['data', 'Data & history', 'drive', 'Your readings, on your terms.'],
  ['system', 'System', 'server', 'What is happening behind the scenes.'],
  ['help', 'Help', 'globe', 'A little guidance when you need it.'],
];
export function navigate(hash) {
  if (location.hash === hash || (hash === '#' && !location.hash)) return;
  if (!allowPageLeave()) return;
  if ($('#settings-dialog').open && !allowDrawerLeave()) return;
  page.pageBaseline = '';
  page.drawerBaseline = '';
  closeDialog($('#settings-dialog'));
  location.hash = hash;
}
function routeName() {
  const match = location.hash.match(/^#configure(?:\/([a-z]+))?$/);
  return match
    ? configurationSections.some(s => s[0] === match[1])
      ? match[1]
      : 'overview'
    : null;
}
export function renderRoute(focus = true) {
  page.configurationSection = routeName();
  $('#dashboard-page').hidden = !!page.configurationSection;
  $('#configuration-page').hidden = !page.configurationSection;
  $('#settings').innerHTML = page.configurationSection
    ? 'Dashboard <span aria-hidden="true">↗</span>'
    : 'Configure <span aria-hidden="true">↗</span>';
  $('#settings').setAttribute(
    'aria-label',
    page.configurationSection ? 'Back to dashboard' : 'Open configuration'
  );
  if (!page.configurationSection) {
    page.pageBaseline = '';
    if (focus) $('#dashboard-title').closest('h1').setAttribute('tabindex', '-1');
    if (focus) $('#dashboard-title').closest('h1').focus({ preventScroll: true });
    // The chart could not be drawn or refreshed while the dashboard was hidden.
    if (page.expanded) {
      renderGraph(page.expanded);
      if (historyDue(page.expanded)) loadHistory(page.expanded);
    }
    return;
  }
  renderConfigurationNav();
  renderConfiguration();
  if (focus) {
    $('#configuration-section-title').focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }
}
function renderConfigurationNav() {
  patchHtml(
    $('#configuration-nav'),
    configurationSections
      .map(
        ([key, label, symbol]) =>
          `<a href="#configure/${key}" ${key === page.configurationSection ? 'aria-current="page"' : ''}>${icon(symbol, 18)}<span>${label}</span>${key === 'sources' ? `<small>${page.data.config.services.length}</small>` : ''}</a>`
      )
      .join('')
  );
}
/** Brings the open configuration page up to date after `data` was reloaded. */
export function refreshConfiguration() {
  if (!page.configurationSection) return;
  renderConfigurationNav();
  if (page.configurationSection === 'sources') renderSourceList();
  if (page.configurationSection === 'overview') renderConfiguration(true);
  // The email status follows the dashboard's delivery figures (a form that is redrawn below
  // draws it too).
  if (page.configurationSection === 'email' && $('#email-status'))
    $('#email-status').textContent = emailStatusText();
  // A form nobody has touched shows what is saved now, so a later save cannot revert a
  // change made elsewhere; a form with edits keeps them (the save then reports a conflict).
  const form = $('#settings-form') || $('#email-form');
  if (
    form &&
    Number.isInteger(page.data.config.revision) &&
    page.data.config.revision !== page.pageRevision &&
    !pageDirty() &&
    !page.busyForm
  ) {
    const focusedId = document.activeElement?.closest('#configuration-content')
      ? document.activeElement.id
      : '';
    renderConfiguration();
    if (focusedId) document.getElementById(focusedId)?.focus({ preventScroll: true });
  }
}
export function renderConfiguration(refresh = false) {
  const c = page.data.config,
    a = c.appearance || {},
    m = c.monitoring || {},
    alerts = c.alerts || {},
    section = configurationSections.find(s => s[0] === page.configurationSection);
  if (!section) return;
  let content = '',
    form = false;
  if (page.configurationSection === 'overview') {
    const active = c.services.filter(s => s.enabled && stateFor(s.id).configured).length,
      hidden = c.services.filter(s => s.showOnDashboard === false).length;
    content = `<div class="configuration-welcome"><div class="welcome-orbit" aria-hidden="true">${icon('orbit', 40)}</div><div><p class="eyebrow">MADE FOR YOUR HOMELAB</p><h3>Everything in its place.</h3><p>Keep your dashboard quiet. Fine-tune the details here.</p></div></div><div class="configuration-stat-grid"><div><strong>${c.services.length}</strong><span>Sources in your workspace</span></div><div><strong>${active}</strong><span>Enabled connections</span></div><div><strong>${c.retentionDays}<small> days</small></strong><span>History retained</span></div></div>`;
    content += `<div class="settings-shortcuts">${[
      [
        'sources',
        'layers',
        'Your connections',
        `${hidden ? hidden + ' hidden · ' : ''}Add, organize, test and tune each source.`,
      ],
      [
        'appearance',
        'grid',
        'A view that feels like you',
        'Color, spacing and the details you see first.',
      ],
      [
        'monitoring',
        'activity',
        'Your collection rhythm',
        `Default interval: ${c.pollSeconds} seconds. Each source can have its own.`,
      ],
      [
        'alerts',
        'shield',
        'The right heads-up',
        `${alerts.enabled === false ? 'Alert evaluation is paused.' : page.data.alerts.length + ' active alerts.'} Choose how Uptime Goblin gets your attention.`,
      ],
    ]
      .map(
        ([key, symbol, title, copy]) =>
          `<a class="settings-shortcut" href="#configure/${key}"><span class="shortcut-icon">${icon(symbol, 22)}</span><div><h3>${title}</h3><p>${esc(copy)}</p></div><span aria-hidden="true">↗</span></a>`
      )
      .join(
        ''
      )}</div><p class="configuration-footnote">Changes stay on your Uptime Goblin server and apply to everyone who uses this dashboard.</p>`;
  }
  if (page.configurationSection === 'appearance') {
    form = true;
    content = settingsBlock(
      'Make it yours',
      'A familiar name, a little color, and room to breathe.',
      `${field('workspace-title', 'Dashboard name', c.title, { required: true, maxLength: 80 })}${field('workspace-subtitle', 'Subtitle', c.subtitle, { maxLength: 160, placeholder: 'Your homelab, at a glance' })}<fieldset class="accent-field"><legend>Accent color</legend><div class="accent-options">${['cyan', 'orange', 'blue', 'violet', 'amber', 'pink', 'green'].map(color => `<label style="--swatch:var(--${color})"><input type="radio" name="appearance-accent" value="${color}" ${(a.accent || 'cyan') === color ? 'checked' : ''}><span class="swatch" aria-hidden="true">✓</span><span>${color[0].toUpperCase() + color.slice(1)}</span></label>`).join('')}</div></fieldset>`
    );
    content += settingsBlock(
      'Layout & first impressions',
      'Choose how much of your workspace is on display.',
      `<div class="field-row">${selectField(
        'appearance-density',
        'Card spacing',
        a.density || 'comfortable',
        [
          ['comfortable', 'Comfortable'],
          ['compact', 'Compact'],
        ]
      )}${selectField(
        'appearance-columns',
        'Columns on larger screens',
        a.columns || 'auto',
        [
          ['auto', 'Automatic'],
          ['2', 'Two columns'],
          ['3', 'Three columns'],
          ['4', 'Four columns'],
        ],
        'Smaller screens adapt automatically.'
      )}</div><div class="field-row">${selectField(
        'appearance-range',
        'Default history view',
        a.defaultRange || '24h',
        [
          ['1h', 'Last hour'],
          ['6h', 'Last 6 hours'],
          ['24h', 'Last 24 hours'],
          ['7d', 'Last 7 days'],
          ['30d', 'Last 30 days'],
        ]
      )}${selectField('appearance-sort', 'Source order within groups', a.sortBy || 'manual', [
        ['manual', 'Saved order'],
        ['name', 'Alphabetical'],
        ['status', 'Needs attention first'],
      ])}</div>${switchField('appearance-summary', 'Summary strip', a.showSummary !== false, 'Connected sources, alerts, latest collection and history at a glance.')}${switchField('appearance-paused', 'Show paused sources', a.showPaused !== false, 'Keep deliberately paused services visible on the dashboard.')}${switchField('appearance-unconfigured', 'Show unconnected sources', a.showUnconfigured !== false, 'Keep sources that still need a connection visible.')}`
    );
    content += settingsBlock(
      'Everyday details',
      'Small preferences that make a difference.',
      `${switchField('appearance-newtab', 'Open services in a new tab', a.openInNewTab !== false, 'Your dashboard stays ready while you visit a service.')}${switchField('appearance-motion', 'Reduce motion', !!a.reduceMotion, 'Remove animations and smooth scrolling. System preferences are also respected.')}<div class="field-row">${field('appearance-timezone', 'Time zone', a.timezone || 'local', { required: true, maxLength: 100, placeholder: 'local, UTC+05:30 or America/Chicago', hint: 'Use “local” for your browser’s time zone, a fixed offset such as UTC+05:30 or UTC-08:00, or an IANA name such as America/Chicago.' })}${selectField(
        'appearance-timeformat',
        'Time format',
        a.timeFormat || 'auto',
        [
          ['auto', 'Browser default'],
          ['12h', '12-hour clock'],
          ['24h', '24-hour clock'],
        ]
      )}</div><div id="timezone-note">${timeZoneNote()}</div>`
    );
  }
  if (page.configurationSection === 'sources') {
    content = `<div class="source-toolbar"><div class="source-search"><label class="sr-only" for="source-search">Search sources</label><input id="source-search" type="search" placeholder="Find a source, group or type…" autocomplete="off"></div><div class="field filter-field"><label class="sr-only" for="source-filter">Filter sources</label><select id="source-filter"><option value="all">All sources</option><option value="connected">Connected</option><option value="attention">Needs attention</option><option value="unconfigured">Not connected</option><option value="paused">Paused</option><option value="hidden">Hidden from dashboard</option><option value="links">Bookmarks</option></select></div><button class="button" type="button" data-kuma-import>${icon('download', 17)} Import from Uptime Kuma</button><button class="button primary" data-add-source>${icon('plus', 17)} Add source</button></div><p class="settings-info source-explainer">Hiding a source only changes the dashboard. Pausing it stops collection and alerts; saved history stays.</p>${kumaImportPanel()}<p id="source-results-count" class="source-results-count" role="status"></p><div id="configured-sources" class="configured-sources"></div>`;
  }
  if (page.configurationSection === 'monitoring') {
    form = true;
    content = settingsBlock(
      'Collection rhythm',
      'Collect often enough to stay informed, with room for your services to respond.',
      `<div class="field-row">${field('poll-seconds', 'Default interval (seconds)', c.pollSeconds, { type: 'number', min: 15, max: 3600, step: 1, required: true, hint: 'Applies to sources without their own interval.' })}${field('monitoring-timeout', 'Total collection deadline (seconds)', m.timeoutSeconds ?? 90, { type: 'number', min: 5, max: 120, step: 1, required: true, hint: 'Includes every attempt and retry delay within one scheduled check.' })}</div>${field('monitoring-concurrency', 'Simultaneous collections', m.concurrency ?? 4, { type: 'number', min: 1, max: 8, step: 1, required: true, hint: 'Lower this for busy networks or slower hosts. Range: 1–8.' })}<p class="settings-info">Manage individual intervals in <a class="text-link" href="#configure/sources">Sources</a>. Your browser refreshes readings automatically; collection continues when the dashboard is closed.</p>`
    );
    content += settingsBlock(
      'Retry failed checks',
      'Give a brief network interruption a second chance before recording a failed check.',
      `<div class="field-row">${field('monitoring-retries', 'Extra attempts', m.retryCount ?? 2, { type: 'number', min: 0, max: 3, step: 1, required: true, hint: '0 disables retries. 2 allows up to three attempts in total.' })}${field('monitoring-retry-delay', 'Delay between retries (seconds)', m.retryDelaySeconds ?? 2, { type: 'number', min: 1, max: 30, step: 1, required: true, hint: 'Wait between transient failures, within the total collection deadline.' })}</div><p class="settings-info">Only temporary network failures, timeouts and retryable HTTP responses are retried. Rejected credentials and invalid responses need attention instead. All attempts together produce one completed check.</p>`
    );
    content += settingsBlock(
      'Confirm problems & recovery',
      'Require a sustained pattern before starting or resolving an alert.',
      `<div class="field-row">${field('availability-failures', 'Failed checks before alerting', m.availabilityFailures ?? 2, { type: 'number', min: 1, max: 10, step: 1, required: true, hint: 'Consecutive completed checks that failed after retries.' })}${field('availability-seconds', 'Failure grace (seconds)', m.availabilitySeconds ?? 60, { type: 'number', min: 0, max: 3600, step: 1, required: true, hint: 'Both this duration and the failure count must be reached. 0 adds no extra delay.' })}</div><div class="field-row">${field('recovery-successes', 'Healthy checks before recovery', m.recoverySuccesses ?? 2, { type: 'number', min: 1, max: 10, step: 1, required: true, hint: 'Consecutive successful checks, including metric recovery when a threshold is active.' })}${field('recovery-seconds', 'Recovery grace (seconds)', m.recoverySeconds ?? 60, { type: 'number', min: 0, max: 3600, step: 1, required: true, hint: 'Recovery requires this duration and the healthy-check count. 0 adds no extra delay.' })}</div><p class="settings-info">Metric thresholds keep their own trigger duration. A recovery boundary can add breathing room, such as alerting above 90% memory and recovering at 88% or below. Retries do not suppress a real measurement warning. Override these defaults in each source when needed.</p>`
    );
  }
  if (page.configurationSection === 'alerts') {
    form = true;
    content = settingsBlock(
      'Alert behavior',
      'Connection failures and metric thresholds are different signals. A reachable service can still report high memory, disk pressure or application health warnings.',
      `${switchField('alerts-enabled', 'Evaluate alerts', alerts.enabled !== false, 'Checks connection failures and source thresholds. Turning this off clears active alerts while measurements continue.')}${switchField('alerts-availability', 'Connection notifications', alerts.notifyAvailability !== false, 'Send email or webhooks for failed checks and their recoveries. Active warnings remain visible when muted.')}${switchField('alerts-measurements', 'Metric notifications', alerts.notifyMeasurements !== false, 'Send email or webhooks for measured threshold breaches and their recoveries. Individual sources can override these category defaults.')}${switchField('alerts-start', 'Notify when an alert begins', alerts.notifyOnAlert !== false, 'Send through configured email and webhook delivery channels.')}${switchField('alerts-recovery', 'Notify when a source recovers', alerts.notifyOnRecovery !== false, 'Send a recovery message after an active alert resolves.')}`
    );
    // The channels' rows say what GET /api/notifications says about them (refreshAlertsDelivery()
    // reads it once the page is drawn, and the 15-second poll again).
    if (!refresh) resetAlertsDelivery();
    content += settingsBlock(
      'Delivery & thresholds',
      'Use source-specific thresholds for the measurements that matter.',
      `<div id="alerts-delivery">${alertsDeliveryRows()}</div><div class="inline-actions"><a class="button" href="#configure/notifications">View deliveries</a><a class="button" href="#configure/sources">Manage source thresholds</a><button class="button" type="button" data-view-alerts>View alerts & recent activity</button></div>`
    );
  }
  if (page.configurationSection === 'notifications') content = notificationsPage();
  if (page.configurationSection === 'email')
    content = `${emailSettings()}<div class="email-dirty-note"><span id="dirty-status" role="status">All changes saved</span><button class="quiet-button" type="button" data-discard>Discard unsaved changes</button></div>`;
  if (page.configurationSection === 'data') {
    form = true;
    content = settingsBlock(
      'History that stays yours',
      'Measurements and alert events live on your Uptime Goblin server.',
      `${field('retention-days', 'Keep history for (days)', c.retentionDays, { type: 'number', min: 1, max: 365, step: 1, required: true, hint: 'Reducing retention removes older readings and events. This cannot be undone.' })}<div class="settings-hint">Historical graphs fill with real readings over time. Gaps remain visible when a source could not be reached; Uptime Goblin never invents missing measurements.</div>`
    );
    content += settingsBlock(
      'Take a copy',
      'Portable, readable exports for your own records.',
      `<div class="export-option"><div><h4>Configuration without credentials</h4><p>Download source definitions and preferences as JSON. Passwords and tokens are removed; private hostnames, addresses and account names remain. Keep this file private. It is a reference copy, not a full backup.</p></div><button class="button" type="button" id="export-config">${icon('download', 17)} Export configuration</button></div><div class="export-option"><div><h4>Readings as CSV</h4><p>Export a source’s sampled history for the selected range. Large ranges are grouped just like the graphs; failures and gaps are included.</p></div><div class="history-export-fields">${selectField(
        'export-source',
        'Source',
        c.services[0]?.id || '',
        c.services.map(s => [s.id, s.name])
      )}${selectField('export-range', 'History period', page.range, [
        ['1h', 'Last hour'],
        ['6h', 'Last 6 hours'],
        ['24h', 'Last 24 hours'],
        ['7d', 'Last 7 days'],
        ['30d', 'Last 30 days'],
      ])}<button class="button" type="button" id="export-history">${icon('download', 17)} Export CSV</button></div></div>`
    );
  }
  if (page.configurationSection === 'account') content = accountPage();
  if (page.configurationSection === 'audit') content = auditPage();
  if (page.configurationSection === 'system')
    content =
      '<div id="system-details" class="settings-block"><p class="loading" role="status">Reading system information…</p></div>';
  if (page.configurationSection === 'help')
    content = `<div class="help-layout"><div class="help-topics" role="group" aria-label="Documentation topics">${[
      ['installation', 'Installation'],
      ['configuration', 'Configuration'],
      ['notifications', 'Alerts and notifications'],
      ['integrations', 'Integrations'],
      ['architecture', 'How Uptime Goblin works'],
      ['security', 'Security'],
      ['authentication', 'Signing in'],
      ['troubleshooting', 'Troubleshooting'],
    ]
      .map(
        ([key, label]) =>
          `<button class="button" type="button" data-doc="${key}" aria-pressed="false">${label}</button>`
      )
      .join(
        ''
      )}</div><article id="documentation" class="documentation" aria-live="polite"><p class="loading">Opening the configuration guide…</p></article></div>`;
  const html = `<div class="configuration-section-heading"><p class="eyebrow">${esc(section[1])}</p><h2 id="configuration-section-title" tabindex="-1">${esc(section[3])}</h2></div>${form ? `<form id="settings-form" data-section="${page.configurationSection}">${content}${saveBar()}</form>` : content}`;
  // Refreshing updates the (form-free) overview in place, keeping focus on its links.
  if (refresh) {
    patchHtml($('#configuration-content'), html);
    return;
  }
  $('#configuration-content').innerHTML = html;
  page.pageRevision = page.data.config.revision;
  page.pageBaseline = formSnapshot(pageForm());
  updateDirtyIndicator();
  if (page.configurationSection === 'sources') renderSourceList();
  if (page.configurationSection === 'account') loadAccount();
  if (page.configurationSection === 'audit') loadAudit();
  if (page.configurationSection === 'system') loadSystem();
  if (page.configurationSection === 'notifications') loadNotifications();
  if (page.configurationSection === 'alerts') refreshAlertsDelivery();
  if (page.configurationSection === 'help') loadDocumentation(page.helpDoc || 'configuration');
  page.helpDoc = null;
}
/**
 * Reads again what the open configuration page reads for itself rather than from the dashboard
 * snapshot, once this page is signed in again (identity/session.js): the Account page (this
 * device's session and the list), the Audit log (its first page), the System page, the
 * Notifications page, the Alerts page's channel rows, and a Help guide that could not open. Until
 * then they show the refusal their own request got after Cancel, "Your session has ended. Sign
 * in again.", or the session that has since ended; load() redraws none of them. A guide that
 * opened is left as it is, so its scroll position stays.
 */
export function reloadSection() {
  if (page.configurationSection === 'account') loadAccount();
  else if (page.configurationSection === 'audit') loadAudit();
  else if (page.configurationSection === 'system') loadSystem();
  else if (page.configurationSection === 'notifications') loadNotifications();
  else if (page.configurationSection === 'alerts') refreshAlertsDelivery();
  else if (page.configurationSection === 'help') {
    const retry = $('#documentation .field-error') && $('#documentation [data-doc]');
    if (retry) loadDocumentation(retry.dataset.doc);
  }
}
export function renderSourceList() {
  const list = $('#configured-sources');
  if (!list) return;
  const query = ($('#source-search')?.value || '').trim().toLowerCase(),
    filter = $('#source-filter')?.value || 'all';
  const sources = page.data.config.services.filter(s => {
    const status = stateFor(s.id).status;
    return (
      (!query || [s.name, s.group, s.type].join(' ').toLowerCase().includes(query)) &&
      (filter === 'all' ||
        (filter === 'connected' && status === 'live') ||
        (filter === 'attention' &&
          (['error', 'stale'].includes(status) ||
            page.data.alerts.some(a => a.service === s.id))) ||
        (filter === 'unconfigured' && status === 'unconfigured') ||
        (filter === 'paused' && !s.enabled) ||
        (filter === 'hidden' && s.showOnDashboard === false) ||
        (filter === 'links' && stateFor(s.id).collector === 'none'))
    );
  });
  $('#source-results-count').textContent =
    `${sources.length} of ${page.data.config.services.length} sources`;
  // Patched rather than replaced: the dashboard poll refreshes this list every 15 s.
  patchHtml(
    list,
    sources
      .map(s => {
        const state = stateFor(s.id),
          warnings = page.data.alerts.filter(a => a.service === s.id).length;
        return `<article class="configured-source" data-id="${esc(s.id)}" style="--accent:var(--${esc(s.color)})"><div class="service-icon">${icon(s.icon)}</div><div class="configured-source-info"><h3>${esc(s.name)}</h3><p><span class="state ${esc(state.status)}">${esc(states[state.status] || 'Unknown')}</span>${warnings ? `<span class="source-warning">${warnings} warning${warnings === 1 ? '' : 's'}</span>` : ''}<span>${esc(s.group)}</span><span>${s.pollSeconds ? `${s.pollSeconds}s` : `Default · ${page.data.config.pollSeconds}s`}</span>${s.showOnDashboard === false ? '<span class="hidden-source-tag">Hidden</span>' : ''}</p></div><div class="source-row-actions"><button class="quiet-button" data-visibility="${esc(s.id)}" aria-label="${s.showOnDashboard === false ? 'Show' : 'Hide'} ${esc(s.name)} on dashboard">${s.showOnDashboard === false ? 'Show' : 'Hide'}</button><button class="button" data-toggle="${esc(s.id)}" aria-label="${s.enabled ? 'Pause' : 'Resume'} ${esc(s.name)}">${s.enabled ? 'Pause' : 'Resume'}</button><button class="button" data-configure="${esc(s.id)}" aria-label="Edit ${esc(s.name)}">Edit</button></div></article>`;
      })
      .join('') ||
      '<div class="empty-history"><h4>No matching sources</h4><p>Try another search or filter, or add your first connection.</p></div>'
  );
}
function settingsInput(section) {
  const number = id => Number($('#' + id).value),
    check = id => $('#' + id).checked,
    value = id => $('#' + id).value;
  if (section === 'appearance')
    return {
      title: value('workspace-title'),
      subtitle: value('workspace-subtitle'),
      appearance: {
        accent: $('[name="appearance-accent"]:checked').value,
        density: value('appearance-density'),
        columns: value('appearance-columns'),
        defaultRange: value('appearance-range'),
        sortBy: value('appearance-sort'),
        showSummary: check('appearance-summary'),
        showPaused: check('appearance-paused'),
        showUnconfigured: check('appearance-unconfigured'),
        openInNewTab: check('appearance-newtab'),
        reduceMotion: check('appearance-motion'),
        timezone: value('appearance-timezone'),
        timeFormat: value('appearance-timeformat'),
      },
    };
  if (section === 'monitoring')
    return {
      pollSeconds: number('poll-seconds'),
      monitoring: {
        concurrency: number('monitoring-concurrency'),
        timeoutSeconds: number('monitoring-timeout'),
        availabilityFailures: number('availability-failures'),
        availabilitySeconds: number('availability-seconds'),
        retryCount: number('monitoring-retries'),
        retryDelaySeconds: number('monitoring-retry-delay'),
        recoverySuccesses: number('recovery-successes'),
        recoverySeconds: number('recovery-seconds'),
      },
    };
  if (section === 'alerts')
    return {
      alerts: {
        enabled: check('alerts-enabled'),
        notifyOnAlert: check('alerts-start'),
        notifyOnRecovery: check('alerts-recovery'),
        notifyAvailability: check('alerts-availability'),
        notifyMeasurements: check('alerts-measurements'),
      },
    };
  if (section === 'data') return { retentionDays: number('retention-days') };
  return {};
}
export async function saveSettings(form) {
  if (!form.reportValidity()) return;
  const section = form.dataset.section,
    input = settingsInput(section),
    button = form.querySelector('[type=submit]'),
    error = $('#settings-error');
  if (
    section === 'data' &&
    input.retentionDays < page.data.config.retentionDays &&
    !confirm(
      `Keep only ${input.retentionDays} days of history? Older readings and events will be permanently removed.`
    )
  )
    return;
  const unlock = lockForm(form);
  error.hidden = true;
  try {
    const result = await writeConfig(
      '/api/settings',
      { method: 'PATCH', body: JSON.stringify(input) },
      { revision: () => page.pageRevision, apply: config => mergeSettings(config, input) }
    );
    page.pageBaseline = formSnapshot(form);
    page.pageRevision = result.revision ?? page.pageRevision;
    if (input.appearance) page.range = input.appearance.defaultRange;
    await load();
    if ($('#timezone-note')) $('#timezone-note').innerHTML = timeZoneNote();
    updateDirtyIndicator();
    toast('Your changes are saved.');
  } catch (e) {
    // Other devices' changes are not overwritten; Discard loads them into this form.
    error.textContent =
      e.status === 409
        ? `${conflictMessage} Choose Discard to load the latest settings, then make your change again.`
        : e.message;
    error.hidden = false;
    error.scrollIntoView({ block: 'nearest' });
    if (e.status === 409) await load();
  } finally {
    unlock();
  }
}
