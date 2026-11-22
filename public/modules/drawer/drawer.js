// The source drawer: editing a connection, its credentials, alert settings and threshold rules, and
// testing it.
import { forgetHistory, loadHistory, refreshHistory, renderGraph } from '../charts/charts.js';
import { emailAction } from '../configure/email.js';
import { api, conflictMessage, replaceService, testTimeoutMs, writeConfig } from '../core/api.js';
import { $, closeDialog, esc, icon, openDialog, toast } from '../core/dom.js';
import { format } from '../core/format.js';
import {
  allowDrawerLeave,
  field,
  formSnapshot,
  holdFocus,
  lockForm,
  selectField,
} from '../core/forms.js';
import { load } from '../core/load.js';
import { page, stateFor } from '../core/page.js';
import { collapseExpanded, noteList, render, toggleSource } from '../dashboard/dashboard.js';

let editingRule = null,
  draftCredentials = {};
const hints = {
  proxmox:
    'Use a reachable Proxmox cluster address including port 8006. All node cards can share this collection address and a read-only PVEAuditor token (user@realm!token=secret). Each card can open its own node URL.',
  linux:
    'Use a node_exporter address. CPU and network rates appear after two readings. Add a separate source for each host.',
  windows:
    'Use a windows_exporter address. CPU and network rates appear after two readings. Add a separate source for each PC or server.',
  unifi:
    'Use an Integration API key, or leave it empty and use a local account with Network View Only access. A saved key takes priority. Local login needs the HTTPS console root and uses site name default when empty; API keys use site UUIDs and collect all visible sites when empty. Cloud sign-in and MFA are not supported.',
  cosmos:
    'Use the Cosmos server address and its native cosmos_ API token. Native monitoring must be enabled. Each Cosmos server has its own connection.',
  amp: 'Use a direct AMP managed-instance URL. Enter a username/password or a service login token. Controller-wide discovery is not included; add game instances separately.',
  synology:
    'Use a Prometheus exporter for your NAS, then map its numeric metrics under Advanced. This connector does not log in to DSM.',
  wireguard:
    'Use a WireGuard Prometheus exporter and map its numeric metrics under Advanced. No tunnel keys are needed by Uptime Goblin.',
  prometheus:
    'Use a Prometheus text-format exporter. Add the metric names, optional label filters, and display labels under Advanced.',
  json: 'Use a read-only JSON endpoint. Map numeric fields with dot-separated paths under Advanced.',
  docker:
    'Use a restricted Docker socket proxy that permits inventory reads. Do not expose an unrestricted Docker daemon.',
  crowdsec:
    'Use CrowdSec Local API machine credentials for alerts. Add a separate bouncer API key for decision and ban counts.',
  npm: 'Use your Nginx Proxy Manager admin address and a view-only account. Interactive MFA challenges are not supported.',
  adguard:
    'Use your AdGuard Home address and account. Your laptop-only instance must be reachable from the Uptime Goblin host.',
  tautulli:
    'Use your Tautulli address and API key. Playback statistics are collected without sending session details to your browser.',
  nzbget:
    'Use your NZBGet address and a control or restricted account with permission to read status.',
  plex: 'Use your Plex server address, normally port 32400, and a Plex token.',
  netbox:
    'Set the destination URL for quick access. To collect metrics, choose an exporter or JSON API as the Monitoring method.',
  link: 'Set a destination URL. Bookmark-only sources do not poll or generate alerts.',
  http: 'Check an HTTP or HTTPS URL without API credentials. Uptime Goblin records response time, availability and the HTTP status. Accepted redirects are not followed; a sign-in redirect only checks the front door.',
};
export function configure(id = null, add = false, { discard = false } = {}) {
  if (!page.data) return;
  if ($('#settings-dialog').open && !allowDrawerLeave(discard)) {
    const picker = $('#source-picker');
    if (picker) picker.value = page.settingsId || '';
    return;
  }
  const nextId = add ? null : id || page.data.config.services[0]?.id || null;
  const s = nextId
    ? page.data.config.services.find(s => s.id === nextId)
    : {
        type: 'cosmos',
        name: '',
        group: 'Utilities',
        enabled: true,
        url: '',
        apiUrl: '',
        username: '',
        collector: 'native',
        metrics: [],
        rules: [],
      };
  if (!s) {
    // Removed on another device or tab after this page was drawn.
    void closeMissingSource(nextId);
    return;
  }
  page.testController?.abort();
  page.settingsId = nextId;
  page.drawerRevision = page.data.config.revision;
  page.draftRules = structuredClone(s.rules || []);
  editingRule = null;
  draftCredentials = {};
  $('#settings-content').innerHTML =
    `<div class="connection-picker"><div class="field"><label for="source-picker">Source</label><select id="source-picker">${!page.settingsId ? '<option value="">New source</option>' : ''}${page.data.config.services.map(c => `<option value="${esc(c.id)}" ${c.id === page.settingsId ? 'selected' : ''}>${esc(c.name)}${c.enabled ? '' : ' · paused'}</option>`).join('')}</select></div><button class="button add-source" data-add-source aria-label="Add another source">${icon('plus', 18)}</button></div>
 <form id="connection-form"><div class="field"><label for="source-type">Service type</label><select id="source-type" ${page.settingsId ? 'disabled' : ''}>${page.data.catalog.map(c => `<option value="${c.type}" ${c.type === s.type ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}</select></div>
 <div id="type-hint" class="settings-hint">${esc(hints[s.type] || 'Use the application address and its API key. Credentials stay on the Uptime Goblin server.')}</div>
 ${field('source-name', 'Display name', s.name, { required: true, maxLength: 100, placeholder: 'e.g. Cosmos · media' })}
 <div class="field-row">${field('source-group', 'Group', s.group, { required: true, maxLength: 100 })}<div class="field"><label for="source-color">Accent</label><select id="source-color">${['violet', 'cyan', 'blue', 'orange', 'amber', 'pink', 'green'].map(c => `<option ${c === (s.color || 'violet') ? 'selected' : ''} value="${c}">${c[0].toUpperCase() + c.slice(1)}</option>`).join('')}</select></div></div>
 ${field('source-url', 'Open this URL when clicked', s.url, { type: 'url', maxLength: 2048, placeholder: 'https://service.your-domain' })}
 ${selectField('source-collector', 'Monitoring method', s.collector || 'native', [
   ['native', 'Default for this service'],
   ['http', 'Website check'],
   ['linux', 'Linux node_exporter'],
   ['windows', 'Windows exporter'],
   ['prometheus', 'Custom Prometheus exporter'],
   ['json', 'Custom JSON API'],
   ['none', 'Bookmark only'],
 ])}
 <div id="endpoint-fields">${field('source-api', 'Collect measurements from', s.apiUrl, { type: 'url', maxLength: 2048, placeholder: 'https://internal-address:port', hint: 'May be different from the address you open in your browser.' })}</div>
 <div id="http-fields" hidden><div class="field-row">${selectField(
   'source-http-method',
   'Request method',
   s.httpMethod || 'GET',
   [
     ['GET', 'GET · check the response'],
     ['HEAD', 'HEAD · headers only'],
   ]
 )}${field('source-http-status', 'Accepted HTTP statuses', s.httpExpectedStatus || '200-399', { maxLength: 200, placeholder: '200-399', hint: 'Codes or ranges separated by commas. Add 401 or 403 only if an authentication response is expected.' })}</div><p class="settings-info">The default accepts successful responses and redirects. Redirects are not followed, so a login redirect checks the front door. HEAD uses less data, but some services only support GET. Checks the initial response, not page assets. Saved API credentials are not sent.</p></div>
 <div id="proxmox-fields" ${s.type === 'proxmox' ? '' : 'hidden'}>${field('source-node', 'Proxmox node name (optional)', s.nodeName || '', { maxLength: 63, placeholder: 'e.g. Proxmox-1', hint: 'Leave blank for the whole cluster. Enter the exact, case-sensitive node name for a single host. Native Proxmox collection only.' })}</div>
 <div id="credential-fields"></div><div id="credential-clear"></div>
 <label class="check-row"><input id="source-enabled" type="checkbox" ${s.enabled ? 'checked' : ''}> Monitoring enabled <span class="muted">· turn off while this server is stopped</span></label>
 <label class="check-row"><input id="source-visible" type="checkbox" ${s.showOnDashboard !== false ? 'checked' : ''}> Show this source on the dashboard</label>${field('source-poll', 'Collection interval (seconds)', s.pollSeconds || 0, { type: 'number', min: 0, max: 3600, step: 1, required: true, hint: `0 uses the workspace default (${page.data.config.pollSeconds}s). Otherwise choose 15–3600 seconds. Hiding a card does not pause collection.` })}<details class="advanced" id="connection-advanced"><summary>Advanced connection settings</summary>
 <div id="metric-path-field">${field('metric-path', 'Custom endpoint path', s.metricPath || '', { maxLength: 500, placeholder: '/metrics', hint: 'Optional path appended to the collection address.' })}</div>
 <div id="site-fields">${field('site-id', 'UniFi site UUID or local site name (optional)', s.siteId || '', { maxLength: 100, hint: 'API key: site UUID, or all sites when empty. Local account: site name, usually default.' })}</div>
 <div class="field" id="mapping-fields"><label for="metric-mappings">Custom metric mappings (JSON)</label><textarea id="metric-mappings" rows="6" spellcheck="false" placeholder='[{"key":"cpu","label":"CPU","path":"system.cpu","unit":"%"}]'>${esc(JSON.stringify(s.metrics || [], null, 2))}</textarea><small>JSON: dot-separated field paths. Exporters: metric names, optional labels, and scale. No credentials here.</small></div></details>
 <div class="connection-test-actions"><button class="button" id="test-connection" type="button">Test connection</button><small>Checks these settings with the selected retry policy, without saving history or creating alerts.</small></div><div id="connection-test" class="connection-test" role="status" hidden></div>
 ${sourceAlertSettings(s)}
 <section class="config-section"><h3>Metric thresholds</h3><p class="settings-info">These warnings describe measurements, not whether the service is reachable. A separate recovery boundary can prevent repeated alerts when a value hovers near a limit. Add or update a rule before saving this connection.</p><div id="rule-list"></div><div class="rule-builder"><div class="field"><label for="rule-key">Measurement</label><input id="rule-key" list="metric-options" maxlength="150" placeholder="Select or enter a metric key"><datalist id="metric-options">${(stateFor(s.id).metrics || []).map(m => `<option value="${esc(m.key)}">${esc(m.label)} (${esc(m.unit || 'count')})</option>`).join('')}</datalist></div><div class="field-row"><div class="field"><label for="rule-operator">Condition</label><select id="rule-operator"><option value="gt">Above</option><option value="lt">Below</option></select></div>${field('rule-threshold', 'Threshold', '', { type: 'number', step: 'any' })}</div>${field('rule-duration', 'Sustained for (seconds)', '120', { type: 'number', min: 0, max: 86400 })}${field('rule-recovery', 'Recovery boundary (optional)', '', { type: 'number', step: 'any', hint: 'Blank uses the alert threshold. Example: memory above 90% alerts, then 88% or below confirms recovery.' })}<div class="rule-editor-actions"><button class="button" id="add-rule" type="button">${icon('plus', 14)} Add rule</button><button class="quiet-button" id="cancel-rule-edit" type="button" hidden>Cancel edit</button></div></div></section>
 <p class="field-error" id="form-error" role="alert" hidden></p><div class="form-buttons"><button class="button primary" type="submit">${page.settingsId ? 'Save connection' : 'Add source'}</button>${page.settingsId ? '<button class="quiet-button danger" id="delete-source" type="button">Remove source</button>' : ''}</div></form>
`;
  renderCredentials(s);
  renderMonitoringMethod();
  renderRules();
  page.drawerBaseline = formSnapshot($('#connection-form'));
  page.drawerRulesBaseline = JSON.stringify(page.draftRules);
  openDialog($('#settings-dialog'));
}
function renderCredentials(s) {
  for (const key of ['username', 'password', 'key']) {
    const field = $('#source-' + key);
    if (field) draftCredentials[key] = field.value;
  }
  if ($('#clear-credentials')) draftCredentials.clear = $('#clear-credentials').checked;
  const mode = $('#source-collector')?.value;
  if (mode && mode !== 'native') s = { ...s, type: mode };
  const passwordTypes = ['amp', 'adguard', 'nzbget', 'npm', 'crowdsec', 'unifi'];
  const keyTypes = [
    'proxmox',
    'cosmos',
    'amp',
    'unifi',
    'plex',
    'tautulli',
    'sonarr',
    'radarr',
    'prowlarr',
    'seerr',
    'sabnzbd',
    'crowdsec',
    'prometheus',
    'json',
    'linux',
    'windows',
    'synology',
    'wireguard',
  ];
  $('#credential-fields').innerHTML =
    (passwordTypes.includes(s.type)
      ? field(
          'source-username',
          s.type === 'crowdsec'
            ? 'Machine ID'
            : s.type === 'unifi'
              ? 'Local Network View Only username'
              : 'Username',
          s.username || '',
          { maxLength: 200 }
        ) +
        field('source-password', 'Password', '', {
          type: 'password',
          maxLength: 8192,
          autocomplete: 'new-password',
          placeholder: s.passwordConfigured ? 'Saved · leave blank to keep' : 'Password',
        })
      : '') +
    (keyTypes.includes(s.type)
      ? field(
          'source-key',
          s.type === 'crowdsec'
            ? 'Bouncer API key (optional)'
            : s.type === 'amp'
              ? 'Service login token (optional)'
              : s.type === 'unifi'
                ? 'Integration API key (optional; takes priority)'
                : s.type === 'proxmox'
                  ? 'API token ID and secret'
                  : 'API key / token',
          '',
          {
            type: 'password',
            maxLength: 8192,
            autocomplete: 'new-password',
            placeholder: s.apiKeyConfigured ? 'Saved · leave blank to keep' : 'Token',
            hint: 'Saved credentials are never returned to your browser.',
          }
        )
      : '');
  // Kept outside #credential-fields so it stays available in Website check and Bookmark
  // modes, which hide the credential inputs but may still hold saved secrets.
  const inputs = !!$('#credential-fields').innerHTML;
  $('#credential-clear').innerHTML =
    s.apiKeyConfigured || s.passwordConfigured
      ? `<label class="check-row"><input id="clear-credentials" type="checkbox"> Clear saved credentials <span class="muted">· ${inputs ? 'keeps any you enter above' : 'this monitoring method does not use them'}</span></label>`
      : '';
  for (const key of ['username', 'password', 'key'])
    if (draftCredentials[key] !== undefined && $('#source-' + key))
      $('#source-' + key).value = draftCredentials[key];
  if ($('#clear-credentials') && draftCredentials.clear !== undefined)
    $('#clear-credentials').checked = draftCredentials.clear;
}
function renderMonitoringMethod() {
  const type = $('#source-type').value,
    chosen = $('#source-collector').value,
    method =
      chosen === 'native'
        ? type === 'http'
          ? 'http'
          : type === 'link' || type === 'netbox'
            ? 'none'
            : type
        : chosen,
    website = method === 'http',
    bookmark = method === 'none';
  $('#type-hint').textContent =
    hints[chosen === 'none' ? 'link' : method] ||
    hints[type] ||
    'Use the application address and its API key. Credentials stay on the Uptime Goblin server.';
  // Hidden sections are disabled too: the browser then skips their validation instead of
  // silently blocking Save, and connectionInput() leaves their saved values alone.
  const show = (selector, visible) => {
    const section = $(selector);
    section.hidden = !visible;
    for (const control of section.querySelectorAll('input,select,textarea'))
      control.disabled = !visible;
  };
  show('#http-fields', website);
  show('#endpoint-fields', !bookmark);
  show('#credential-fields', !website && !bookmark);
  show('#proxmox-fields', type === 'proxmox' && chosen === 'native');
  show('#site-fields', type === 'unifi' && chosen === 'native');
  // Only the exporter and JSON collectors read mappings and a custom path (plus the path of
  // a Website check); native integrations use fixed endpoints and would ignore them.
  const mapped = ['linux', 'windows', 'synology', 'wireguard', 'prometheus', 'json'].includes(
    method
  );
  show('#mapping-fields', mapped);
  show('#metric-path-field', mapped || website);
  $('label[for="source-api"]').textContent = website
    ? 'Website URL to check'
    : 'Collect measurements from';
  $('#endpoint-fields small').textContent = website
    ? 'Leave blank to check the URL opened by this card. Use the full HTTP or HTTPS address, with no embedded credentials.'
    : 'May be different from the address you open in your browser.';
  $('#connection-advanced').hidden = !(
    mapped ||
    website ||
    (type === 'unifi' && chosen === 'native')
  );
  $('#connection-advanced summary').textContent = website
    ? 'Optional website path'
    : 'Advanced connection settings';
  $('label[for="metric-path"]').textContent = website
    ? 'Optional check path'
    : 'Custom endpoint path';
  $('#metric-path-field small').textContent = website
    ? 'Appended to the URL above. Usually blank. Clear an old /metrics or API path to check the website root.'
    : 'Optional path appended to the collection address.';
  if (website && $('#metric-path').value) $('#connection-advanced').open = true;
}
const monitoringFields = [
  ['retryCount', 'Extra attempts', 0, 3, 2],
  ['retryDelaySeconds', 'Delay between retries (seconds)', 1, 30, 2],
  ['timeoutSeconds', 'Total collection deadline (seconds)', 5, 120, 90],
  ['availabilityFailures', 'Failed checks before alerting', 1, 10, 2],
  ['availabilitySeconds', 'Failure grace (seconds)', 0, 3600, 60],
  ['recoverySuccesses', 'Healthy checks before recovery', 1, 10, 2],
  ['recoverySeconds', 'Recovery grace (seconds)', 0, 3600, 60],
];
function sourceAlertSettings(s) {
  const monitoring = s.monitoring || {},
    alerts = s.alerts || {},
    global = page.data.config.alerts || {},
    overrides = Object.values(monitoring).filter(v => v !== null && v !== undefined).length;
  const preference = (key, label) =>
    selectField(
      'source-alert-' + key,
      label,
      alerts[key] === true ? 'true' : alerts[key] === false ? 'false' : 'inherit',
      [
        ['inherit', `Workspace default · ${global[key] === false ? 'muted' : 'send'}`],
        ['true', 'Send notifications'],
        ['false', 'Mute notifications'],
      ]
    );
  return `<section class="config-section"><h3>Notifications for this source</h3><p class="settings-info">Choose which kinds of warnings send email or webhooks. Active warnings and history remain visible; the workspace alert/recovery delivery switches still apply.</p><div class="field-row">${preference('notifyAvailability', 'Connection notifications')}${preference('notifyMeasurements', 'Metric notifications')}</div><details class="advanced retry-overrides" ${overrides ? 'open' : ''}><summary>Retry & confirmation overrides <span class="muted">${overrides ? '· ' + overrides + ' custom' : '· using workspace defaults'}</span></summary><p class="settings-info">Leave a field blank to inherit its workspace value. Zero is an explicit setting where allowed. Retries belong to one completed check; they do not count as extra alert confirmations.</p><div class="field-row">${monitoringFields.map(([key, label, min, max, fallback]) => field('source-monitoring-' + key, label, monitoring[key] ?? '', { type: 'number', min, max, step: 1, placeholder: `Workspace: ${page.data.config.monitoring?.[key] ?? fallback}`, hint: `Workspace default: ${page.data.config.monitoring?.[key] ?? fallback}. Allowed: ${min}–${max}.` })).join('')}</div><p class="settings-info">The collection deadline includes all attempts and retry delays. Recovery needs consecutive successful checks plus its grace period; metric readings must also reach their recovery boundary. Rejected logins and invalid-response errors are not retried.</p></details></section>`;
}
function renderRules() {
  $('#rule-list').innerHTML = page.draftRules
    .map(
      (r, i) =>
        `<div class="rule ${editingRule === i ? 'editing' : ''}"><span><strong>${esc(r.key)}</strong> ${r.operator === 'gt' ? 'above' : 'below'} ${esc(r.threshold)} <small>for ${r.forSeconds}s${r.recoveryThreshold !== undefined && r.recoveryThreshold !== null ? ` · recover at ${esc(r.recoveryThreshold)} or ${r.operator === 'gt' ? 'below' : 'above'}` : ''}</small></span><div class="rule-actions"><button type="button" class="quiet-button" data-edit-rule="${i}" aria-label="Edit rule for ${esc(r.key)}">Edit</button><button type="button" class="icon-button" data-remove-rule="${i}" aria-label="Remove rule for ${esc(r.key)}">×</button></div></div>`
    )
    .join('');
}
function clearRuleEditor() {
  editingRule = null;
  $('#rule-key').value = '';
  $('#rule-threshold').value = '';
  $('#rule-recovery').value = '';
  $('#rule-duration').value = '120';
  $('#rule-operator').value = 'gt';
  $('#add-rule').innerHTML = icon('plus', 14) + ' Add rule';
  $('#cancel-rule-edit').hidden = true;
  renderRules();
}
/**
 * The measurement key in the rule editor. A rule matches its reading's key exactly, and a key
 * made from a source's ID or path keeps white space at either end, as 1.4.3 did (upstreamId in
 * lib/collectors.mjs): trimmed, a rule on "disk_/mnt/data " was saved as "disk_/mnt/data" and
 * never fired. So a key the list offers (the last readings, or the last connection test) and
 * the key of the rule being edited are taken exactly; other text is typed, and is trimmed.
 */
function ruleKey() {
  const value = $('#rule-key').value,
    offered =
      [...$('#metric-options').options].some(option => option.value === value) ||
      (editingRule !== null && page.draftRules[editingRule]?.key === value);
  return offered ? value : value.trim();
}
/** An unadded rule would otherwise be dropped silently when the connection is saved. */
function ruleDraftPending() {
  return (
    editingRule === null &&
    ['#rule-key', '#rule-threshold', '#rule-recovery'].some(
      id => $(id)?.value.trim() || $(id)?.validity.badInput
    )
  );
}
/** The draft stays in the drawer; replacing it with the latest settings is the user's call. */
async function showDrawerConflict() {
  $('#form-error').hidden = false;
  $('#form-error').innerHTML =
    `${esc(conflictMessage)} <button class="quiet-button" type="button" data-reload-source>Discard my edits and load the latest</button>`;
  await load();
}
async function closeMissingSource(id) {
  stopConnectionTest();
  page.drawerBaseline = '';
  closeDialog($('#settings-dialog'));
  if (page.expanded === id) page.expanded = null;
  forgetHistory();
  await load();
  toast('This source no longer exists. It may have been removed on another device.');
}
function resetTestButton() {
  const button = $('#test-connection');
  if (!button) return;
  button.disabled = false;
  button.textContent = 'Test connection';
}
function stopConnectionTest() {
  if (page.testController) {
    page.testController.abort();
    page.testController = null;
    // A refused save/removal leaves the form open. Its canceled test is no longer running.
    $('#connection-test').hidden = true;
  }
  // Reset before locking, so a failed change restores an enabled test button.
  resetTestButton();
}
function connectionInput() {
  if (editingRule !== null)
    throw new Error(
      'Update the edited rule or cancel its edit before saving or testing this connection.'
    );
  const poll = Number($('#source-poll').value);
  if (!Number.isInteger(poll) || poll < 0 || poll > 3600 || (poll > 0 && poll < 15))
    throw new Error('Choose 0 for the default interval, or 15–3600 seconds.');
  // Fields in sections this monitoring method hides stay undefined, which omits them from
  // the request so the server keeps their saved values. (Not `disabled`: lockForm() sets
  // that on every control while saving.)
  const shown = id => {
    const control = $('#' + id);
    return control && !control.closest('[hidden]') ? control.value : undefined;
  };
  const input = {
    type: $('#source-type').value,
    name: $('#source-name').value,
    group: $('#source-group').value,
    color: $('#source-color').value,
    url: $('#source-url').value,
    apiUrl: shown('source-api'),
    enabled: $('#source-enabled').checked,
    showOnDashboard: $('#source-visible').checked,
    pollSeconds: Number($('#source-poll').value),
    collector: $('#source-collector').value,
    metricPath: shown('metric-path'),
    siteId: shown('site-id'),
    nodeName: shown('source-node'),
    httpMethod: shown('source-http-method'),
    httpExpectedStatus: shown('source-http-status'),
    username: shown('source-username'),
    // A typed key or password is kept even when 'Clear saved credentials' is ticked.
    apiKey: shown('source-key') || undefined,
    password: shown('source-password') || undefined,
    monitoring: Object.fromEntries(
      monitoringFields.map(([key]) => [
        key,
        $('#source-monitoring-' + key).value.trim() === ''
          ? null
          : Number($('#source-monitoring-' + key).value),
      ])
    ),
    alerts: Object.fromEntries(
      ['notifyAvailability', 'notifyMeasurements'].map(key => [
        key,
        $('#source-alert-' + key).value === 'inherit'
          ? null
          : $('#source-alert-' + key).value === 'true',
      ])
    ),
    rules: page.draftRules,
  };
  if (input.httpExpectedStatus === '') input.httpExpectedStatus = '200-399';
  if ($('#clear-credentials')?.checked) {
    input.apiKey ??= '';
    input.password ??= '';
  }
  const mappings = shown('metric-mappings');
  if (mappings !== undefined) {
    try {
      input.metrics = JSON.parse(mappings || '[]');
    } catch {
      throw new Error('Metric mappings must contain valid JSON.');
    }
  }
  return input;
}
async function testConnection() {
  const form = $('#connection-form');
  if (!form.reportValidity()) return;
  page.testController?.abort();
  const controller = new AbortController();
  page.testController = controller;
  const button = $('#test-connection'),
    result = $('#connection-test'),
    // Keeps the focus of the button it disables, through a sign-in dialog the test may open.
    release = holdFocus(button);
  button.disabled = true;
  button.textContent = 'Testing…';
  result.hidden = false;
  result.className = 'connection-test';
  result.textContent = 'Connecting and checking available measurements…';
  try {
    const response = await api('/api/test-service', {
      method: 'POST',
      body: JSON.stringify({ serviceId: page.settingsId, settings: connectionInput() }),
      signal: controller.signal,
      timeout: testTimeoutMs,
    });
    if (controller.signal.aborted) return;
    result.classList.add('success');
    const website = response.metrics.some(m => m.key === 'http_status');
    result.innerHTML = `<strong>Connected · ${response.metrics.length} measurements</strong><p>${response.metrics
      .slice(0, 4)
      .map(m => `${esc(m.label)}: ${esc(format(m.value, m.unit))}`)
      .join(
        ' · '
      )}</p>${noteList(response.notes, 'source-notes test-notes')}<small>Test completed in ${(response.elapsedMs / 1000).toFixed(1)}s. Save the connection when you’re ready. ${website ? 'The HTTP status matches your accepted statuses. Redirects are not followed.' : 'CPU and network rates may need two scheduled readings.'}${response.credentialsCleared ? ' Saving will clear the saved credentials: this method does not use them, and Uptime Goblin never sends them to a new address.' : ''}</small>`;
    $('#metric-options').innerHTML = response.metrics
      .map(
        m => `<option value="${esc(m.key)}">${esc(m.label)} (${esc(m.unit || 'count')})</option>`
      )
      .join('');
  } catch (e) {
    if (controller.signal.aborted) return;
    result.classList.add('failed');
    result.textContent = e.message;
  } finally {
    // A newer test, or a save that locked the form, owns the button now.
    if (page.testController === controller) {
      page.testController = null;
      if (page.busyForm !== form) resetTestButton();
    }
    release();
  }
}
async function submitConnection(form) {
  stopConnectionTest();
  const id = page.settingsId,
    unlock = lockForm(form);
  try {
    if (ruleDraftPending())
      throw new Error(
        'Add the rule you started with Add rule, or clear its fields, before saving this connection.'
      );
    const input = connectionInput();
    const result = await writeConfig(
      id ? `/api/services/${id}` : '/api/services',
      { method: id ? 'PATCH' : 'POST', body: JSON.stringify(input) },
      id
        ? { revision: () => page.drawerRevision, apply: replaceService, source: id }
        : {
            // A new source is added to the configuration as this tab has it. Naming that
            // revision lets a retry after a lost answer be refused instead of added twice.
            revision: () => page.data.config.revision,
            apply: (config, { service }) => (config.services = [...config.services, service]),
          }
    );
    if (id && id === page.expanded) refreshHistory(id);
    page.drawerBaseline = '';
    closeDialog($('#settings-dialog'));
    await load();
    toast(
      `${result.service.name} saved${result.service.enabled ? '' : ' · monitoring paused'}${result.credentialsCleared ? ' · saved credentials cleared for the new address' : ''}`
    );
  } catch (e) {
    if (e.status === 404 && id) await closeMissingSource(id);
    else if (e.status === 409 && id) await showDrawerConflict();
    else {
      $('#form-error').hidden = false;
      $('#form-error').textContent =
        e.status === 409
          ? 'Settings changed on another device or tab while you added this source, so it was not added. Your entries are kept: choose Add source again.'
          : e.message;
      if (e.status === 409) await load();
    }
  } finally {
    unlock();
  }
}
function clearConnectionTest(e) {
  if (e.target.closest('#connection-form')) {
    page.testController?.abort();
    const result = $('#connection-test');
    if (result) result.hidden = true;
  }
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  document.addEventListener('click', async e => {
    if (e.target.closest('#test-email')) {
      await emailAction(true);
      return;
    }
    if (e.target.closest('#test-connection')) {
      await testConnection();
      return;
    }
    const expand = e.target.closest('[data-expand]');
    if (expand) {
      if (page.expanded === expand.dataset.expand) {
        collapseExpanded();
        return;
      }
      page.expanded = expand.dataset.expand;
      page.collapsingId = null;
      page.collapseGeneration++;
      page.selectedMetric = '';
      forgetHistory();
      render();
      if (page.expanded) await loadHistory(page.expanded);
      return;
    }
    if (e.target.closest('[data-reload-source]')) {
      // An explicit discard still obeys the pending-change lock. Do not clear the draft's
      // baseline until configure can actually replace or close its editor.
      configure(page.settingsId, false, { discard: true });
      return;
    }
    const config = e.target.closest('[data-configure]');
    if (config) {
      configure(config.dataset.configure);
      return;
    }
    if (e.target.closest('[data-add-source]')) {
      configure(null, true);
      return;
    }
    const toggle = e.target.closest('[data-toggle]');
    if (toggle) {
      await toggleSource(toggle.dataset.toggle);
      return;
    }
    const r = e.target.closest('[data-range]');
    if (r) {
      page.range = r.dataset.range;
      render();
      await loadHistory(page.expanded);
      $(`[data-range="${page.range}"]`)?.focus({ preventScroll: true });
      return;
    }
    const edit = e.target.closest('[data-edit-rule]');
    if (edit) {
      editingRule = Number(edit.dataset.editRule);
      const rule = page.draftRules[editingRule];
      $('#rule-key').value = rule.key;
      $('#rule-operator').value = rule.operator;
      $('#rule-threshold').value = rule.threshold;
      $('#rule-duration').value = rule.forSeconds;
      $('#rule-recovery').value = rule.recoveryThreshold ?? '';
      $('#add-rule').textContent = 'Update rule';
      $('#cancel-rule-edit').hidden = false;
      renderRules();
      $('#rule-recovery').focus();
      return;
    }
    if (e.target.closest('#cancel-rule-edit')) {
      clearRuleEditor();
      return;
    }
    const remove = e.target.closest('[data-remove-rule]');
    if (remove) {
      const index = Number(remove.dataset.removeRule);
      page.draftRules.splice(index, 1);
      if (editingRule === index) clearRuleEditor();
      else {
        if (editingRule !== null && editingRule > index) editingRule--;
        renderRules();
      }
      return;
    }
    if (e.target.closest('#add-rule')) {
      const key = ruleKey(),
        threshold = Number($('#rule-threshold').value),
        forSeconds = Number($('#rule-duration').value),
        operator = $('#rule-operator').value,
        recoveryText = $('#rule-recovery').value.trim(),
        recovery = recoveryText === '' ? null : Number(recoveryText);
      // A number input reports '' for text it cannot parse (e.g. '2m' or '88%'), and
      // Number('') is 0, so check for blank and unreadable input before converting.
      if ($('#rule-threshold').validity.badInput) {
        toast('Enter the threshold as a number.');
        return;
      }
      if ($('#rule-duration').value.trim() === '' || $('#rule-duration').validity.badInput) {
        toast('Enter how long the condition must last, in whole seconds (0–86400).');
        return;
      }
      if ($('#rule-recovery').validity.badInput) {
        toast('Enter the recovery boundary as a number, or leave it blank.');
        return;
      }
      if (
        !key ||
        $('#rule-threshold').value === '' ||
        !Number.isFinite(threshold) ||
        !Number.isInteger(forSeconds) ||
        forSeconds < 0 ||
        forSeconds > 86400
      ) {
        toast('Choose a measurement, threshold, and valid duration.');
        return;
      }
      if (
        recovery !== null &&
        (!Number.isFinite(recovery) ||
          (operator === 'gt' ? recovery > threshold : recovery < threshold))
      ) {
        toast(
          operator === 'gt'
            ? 'Recovery must be at or below the alert threshold.'
            : 'Recovery must be at or above the alert threshold.'
        );
        return;
      }
      if (page.draftRules.some((r, i) => r.key === key && i !== editingRule)) {
        toast('This measurement already has a rule.');
        return;
      }
      const rule = {
        key,
        threshold,
        forSeconds,
        operator,
        ...(recovery !== null ? { recoveryThreshold: recovery } : {}),
      };
      if (editingRule === null) page.draftRules.push(rule);
      else page.draftRules[editingRule] = rule;
      clearRuleEditor();
      return;
    }
    if (e.target.closest('#delete-source')) {
      const s = page.data.config.services.find(s => s.id === page.settingsId);
      if (!s) {
        await closeMissingSource(page.settingsId);
        return;
      }
      if (confirm(`Remove ${s.name} and its saved history? Pause it instead to keep everything.`)) {
        stopConnectionTest();
        const id = s.id,
          unlock = lockForm($('#connection-form'));
        try {
          let alreadyRemoved = false;
          try {
            await writeConfig(
              `/api/services/${id}`,
              { method: 'DELETE', body: '{}' },
              {
                revision: () => page.drawerRevision,
                apply: config => (config.services = config.services.filter(s => s.id !== id)),
                source: id,
              }
            );
          } catch (error) {
            // Uptime Goblin checks whether the source exists before comparing revisions. Another
            // device's completed removal therefore answers 404 rather than a conflict.
            if (error.status !== 404) throw error;
            alreadyRemoved = true;
          }
          page.drawerBaseline = '';
          closeDialog($('#settings-dialog'));
          if (page.expanded === id) page.expanded = null;
          forgetHistory();
          await load();
          toast(
            alreadyRemoved ? 'Source was already removed on another device.' : 'Source removed.'
          );
        } catch (error) {
          if (error.status === 409) await showDrawerConflict();
          else toast(error.message);
        } finally {
          unlock();
        }
      }
    }
  });
  document.addEventListener('input', clearConnectionTest);
  // The browser cannot point at an invalid field inside a closed <details>, so it would
  // cancel Save or Test without a message. Open it first ('invalid' does not bubble).
  document.addEventListener(
    'invalid',
    e => {
      const details = e.target.closest('details');
      if (details) details.open = true;
    },
    true
  );
  document.addEventListener('change', e => {
    clearConnectionTest(e);
    if (e.target.id === 'email-security' && ['465', '587'].includes($('#email-port').value))
      $('#email-port').value = e.target.value === 'tls' ? '465' : '587';
    if (e.target.id === 'metric-select') {
      page.selectedMetric = e.target.value;
      renderGraph(page.expanded);
      $('#metric-select').focus({ preventScroll: true });
    }
    if (e.target.id === 'source-picker') configure(e.target.value, !e.target.value);
    if (e.target.id === 'source-collector') {
      const saved = page.data.config.services.find(s => s.id === page.settingsId) || {
        type: $('#source-type').value,
      };
      renderCredentials({ ...saved, type: $('#source-type').value });
      renderMonitoringMethod();
    }
    if (e.target.id === 'source-type') {
      const type = e.target.value,
        def = page.data.catalog.find(c => c.type === type);
      $('#source-group').value = def.group;
      $('#source-color').value = def.color;
      renderCredentials({ type });
      renderMonitoringMethod();
    }
  });
  document.addEventListener('submit', async e => {
    if (e.target.id === 'email-form') {
      e.preventDefault();
      await emailAction();
    }
    if (e.target.id === 'connection-form') {
      e.preventDefault();
      await submitConnection(e.target);
    }
  });
  // Enter in a rule field adds the rule instead of submitting (and saving) the whole form.
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || e.isComposing || !e.target.closest?.('.rule-builder')) return;
    if (e.target.matches('button')) return;
    e.preventDefault();
    const missing = ['#rule-key', '#rule-threshold']
      .map(id => $(id))
      .find(field => !field.value.trim() && !field.validity.badInput);
    if (missing) missing.focus();
    else $('#add-rule').click();
  });
  // The 'close' event arrives in a later task: if the drawer was opened again meanwhile, it
  // belongs to the new drawer's work, which must keep its connection test and baseline.
  $('#settings-dialog').addEventListener('close', () => {
    if (!$('#settings-dialog').open) page.testController?.abort();
  });
}
