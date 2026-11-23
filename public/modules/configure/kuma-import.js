// Configure → Sources → Import from Uptime Kuma: choose a backup, see what would be added,
// changed and skipped, and confirm. The backup is read in this browser and reduced
// (public/shared/uptime-kuma.js) before it is sent, so no credential of a monitor leaves the
// browser; nothing is saved without the confirmation, which names the previewed revision.
import { api, conflictMessage } from '../core/api.js';
import { $, esc, toast } from '../core/dom.js';
import { holdFocus } from '../core/forms.js';
import { load } from '../core/load.js';
import { page } from '../core/page.js';
import { KUMA_FILE_MAX_BYTES, reduceKumaBackup } from '../../shared/uptime-kuma.js';

// Uptime Goblin's limit on a request body (lib/http/body.mjs bodyLimit).
const requestMaxBytes = 150000;
// The preview being shown: the reduced backup as sent, and the revision it was planned against.
let shown = null;

const fieldNames = {
  url: 'address',
  apiUrl: 'separate check address (cleared)',
  metricPath: 'website path (cleared)',
  httpMethod: 'method',
  httpExpectedStatus: 'accepted statuses',
  pollSeconds: 'interval',
  group: 'group',
};
const interval = seconds => (seconds ? `${seconds} s` : 'Default');
const notes = list =>
  list.length ? `<ul class="kuma-notes">${list.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : '';

/** The panel's markup, on the Sources page (configure/pages.js). */
export const kumaImportPanel = () =>
  `<section id="kuma-import" class="settings-block kuma-import" hidden aria-labelledby="kuma-import-title"><div class="settings-block-heading"><h3 id="kuma-import-title">Import from Uptime Kuma</h3><p>Choose a JSON backup from Uptime Kuma 1.x (Settings → Backup → Export). HTTP(S) and keyword monitors become Website checks. This browser removes credentials before anything is sent, and nothing is saved until you confirm.</p></div><div class="field"><label for="kuma-file">Uptime Kuma backup (.json)</label><input id="kuma-file" type="file" accept=".json,application/json"></div><p id="kuma-error" class="field-error" role="alert" hidden></p><div id="kuma-preview" aria-live="polite"></div><div class="inline-actions"><button class="button primary" type="button" id="kuma-apply" hidden disabled>Import</button><button class="button" type="button" data-kuma-cancel>Cancel</button></div></section>`;

function showError(message) {
  const error = $('#kuma-error');
  if (!error) return;
  error.textContent = message;
  error.hidden = !message;
}
// Clears the preview, and the chosen file unless `keepFile` (a file just chosen).
function reset({ keepFile = false } = {}) {
  shown = null;
  showError('');
  if ($('#kuma-preview')) $('#kuma-preview').innerHTML = '';
  if ($('#kuma-file') && !keepFile) $('#kuma-file').value = '';
  const apply = $('#kuma-apply');
  if (apply) {
    apply.hidden = true;
    apply.disabled = true;
  }
}
function renderPreview(plan) {
  const added = plan.add,
    changed = plan.change,
    skipped = plan.skip;
  const table = (caption, head, rows) =>
    rows.length
      ? `<div class="table-scroll"><table class="kuma-table"><caption>${caption}</caption><thead><tr>${head.map(h => `<th scope="col">${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`
      : '';
  const credentials = item =>
    item.needsCredentials ? '<span class="kuma-flag">Needs credentials re-entered</span>' : '';
  $('#kuma-preview').innerHTML =
    `<h4 id="kuma-preview-title" tabindex="-1">${added.length} to add, ${changed.length} to change, ${skipped.length} skipped</h4>${notes(plan.notes)}` +
    table(
      'Will be added',
      ['Name', 'Group', 'Address', 'Interval', 'Notes'],
      added.map(
        a =>
          `<tr data-kuma="add"><td>${esc(a.name)}${a.enabled ? '' : ' <small>(paused)</small>'}</td><td>${esc(a.group)}</td><td><code>${esc(a.method)}</code> ${esc(a.url)}<small>Accepts ${esc(a.expectedStatus)}</small></td><td>${interval(a.pollSeconds)}</td><td>${credentials(a)}${notes(a.notes)}</td></tr>`
      )
    ) +
    table(
      'Will be changed (same name)',
      ['Source', 'Changes', 'Notes'],
      changed.map(
        c =>
          `<tr data-kuma="change"><td>${esc(c.name)}</td><td>${c.fields.map(f => esc(fieldNames[f] ?? f)).join(', ')}<small><code>${esc(c.method)}</code> ${esc(c.url)} · ${interval(c.pollSeconds)}</small></td><td>${credentials(c)}${notes(c.notes)}</td></tr>`
      )
    ) +
    table(
      'Skipped',
      ['Monitor', 'Type', 'Reason'],
      skipped.map(
        s =>
          `<tr data-kuma="skip"><td>${esc(s.name ?? `Monitor ${s.kumaId ?? '?'}`)}</td><td>${esc(s.type)}</td><td>${esc(s.reason)}</td></tr>`
      )
    );
  const apply = $('#kuma-apply'),
    count = added.length + changed.length;
  apply.hidden = false;
  apply.disabled = count === 0;
  apply.textContent = count
    ? `Import ${count} ${count === 1 ? 'monitor' : 'monitors'}`
    : 'Nothing to import';
}
async function preview(body) {
  const plan = await api('/api/import/uptime-kuma/preview', { method: 'POST', body });
  if (!$('#kuma-preview')) return;
  shown = { body, revision: plan.revision, count: plan.add.length + plan.change.length };
  renderPreview(plan);
  $('#kuma-preview-title').focus({ preventScroll: true });
}
async function chooseFile(input) {
  const file = input.files?.[0];
  reset({ keepFile: true });
  if (!file) return;
  if (file.size > KUMA_FILE_MAX_BYTES) {
    showError('This file is larger than 8 MB, too large for an Uptime Kuma backup.');
    return;
  }
  let body;
  try {
    let value;
    try {
      value = JSON.parse(await file.text());
    } catch {
      showError('This file is not valid JSON. Choose the backup file Uptime Kuma exported.');
      return;
    }
    body = JSON.stringify(reduceKumaBackup(value));
  } catch (error) {
    showError(error.message);
    return;
  }
  if (new TextEncoder().encode(body).length > requestMaxBytes) {
    showError(
      'This backup has more monitors than one import can take. Export fewer monitors from Uptime Kuma and import them in parts.'
    );
    return;
  }
  try {
    await preview(body);
  } catch (error) {
    showError(error.message);
  }
}
async function confirmImport(button) {
  if (!shown) return;
  const release = holdFocus(button);
  button.disabled = true;
  try {
    const result = await api('/api/import/uptime-kuma', {
      method: 'POST',
      body: shown.body,
      headers: { 'If-Match': String(shown.revision) },
    });
    reset();
    $('#kuma-import').hidden = true;
    await load();
    toast(
      `Imported from Uptime Kuma: ${result.added.length} added, ${result.changed.length} changed.`
    );
  } catch (error) {
    if (error.status === 409 && shown) {
      // Sources changed since the preview: show the plan as it is now, to confirm again.
      try {
        await preview(shown.body);
        showError(`${conflictMessage} The preview below is up to date; confirm again to import.`);
      } catch (again) {
        showError(again.message);
      }
    } else {
      showError(error.message);
      if (error.unconfirmed || error.timeout) await load();
    }
  } finally {
    if (shown && $('#kuma-apply')) $('#kuma-apply').disabled = shown.count === 0;
    release();
  }
}

/** Registers the panel's handlers; main.js calls it once. */
export function install() {
  document.addEventListener('click', e => {
    if (page.configurationSection !== 'sources') return;
    if (e.target.closest('[data-kuma-import]')) {
      const panel = $('#kuma-import');
      panel.hidden = !panel.hidden;
      if (!panel.hidden) $('#kuma-file').focus();
      else reset();
      return;
    }
    if (e.target.closest('[data-kuma-cancel]')) {
      reset();
      $('#kuma-import').hidden = true;
      $('[data-kuma-import]')?.focus();
      return;
    }
    const apply = e.target.closest('#kuma-apply');
    if (apply && !apply.disabled) void confirmImport(apply);
  });
  document.addEventListener('change', e => {
    if (e.target.id === 'kuma-file') void chooseFile(e.target);
  });
}
