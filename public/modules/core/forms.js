// Form fields and blocks, form locking, and the unsaved-changes checks for the configuration page
// and the source drawer.
import { $, esc, toast } from './dom.js';
import { page } from './page.js';
import { offerUpdate } from '../update/update.js';

export function field(id, label, value = '', options = {}) {
  return `<div class="field"><label for="${id}">${label}</label><input id="${id}" name="${id}" type="${options.type || 'text'}" value="${esc(value)}" ${options.required ? 'required' : ''} ${options.min !== undefined ? `min="${options.min}"` : ''} ${options.max !== undefined ? `max="${options.max}"` : ''} ${options.step ? `step="${options.step}"` : ''} ${options.maxLength ? `maxlength="${options.maxLength}"` : ''} placeholder="${esc(options.placeholder || '')}" autocomplete="${options.autocomplete || 'off'}">${options.hint ? `<small>${esc(options.hint)}</small>` : ''}</div>`;
}
export function selectField(id, label, value, options, hint = '') {
  return `<div class="field"><label for="${id}">${label}</label><select id="${id}" name="${id}">${options.map(([key, text]) => `<option value="${esc(key)}" ${String(value) === String(key) ? 'selected' : ''}>${esc(text)}</option>`).join('')}</select>${hint ? `<small>${esc(hint)}</small>` : ''}</div>`;
}
export function switchField(id, label, checked, description) {
  return `<label class="setting-switch" for="${id}"><span><strong>${esc(label)}</strong><small>${esc(description)}</small></span><input type="checkbox" id="${id}" name="${id}" ${checked ? 'checked' : ''}><span class="switch-track" aria-hidden="true"></span></label>`;
}
export function settingsBlock(title, description, content) {
  return `<section class="settings-block"><div class="settings-block-heading"><h3>${title}</h3>${description ? `<p>${description}</p>` : ''}</div>${content}</section>`;
}
export function saveBar(label = 'Save changes') {
  return `<div class="save-bar"><span id="dirty-status" role="status">All changes saved</span><div><button class="button" type="button" data-discard>Discard</button><button class="button primary" type="submit">${label}</button></div></div><p id="settings-error" class="field-error" role="alert" hidden></p>`;
}
/** True when `element` can take the focus now: in the page, enabled, shown and not inert. */
export function focusable(element) {
  return (
    !!element?.isConnected &&
    !element.disabled &&
    element.getClientRects().length > 0 &&
    !element.closest('[inert]')
  );
}
/**
 * Disables the form's controls while its request is on its way; returns unlock(). Disabling
 * the control that has the focus (the submit button, or the field Enter was pressed in) drops
 * the focus to <body>, so it is kept (page.busyFocus: a sign-in dialog the request opens returns
 * there too) and given back on unlock, unless the focus has moved on meanwhile.
 */
export function lockForm(form) {
  const controls = [...form.querySelectorAll('input,select,textarea,button')].map(element => [
    element,
    element.disabled,
  ]);
  const focused = form.contains(document.activeElement) ? document.activeElement : null;
  for (const [element] of controls) element.disabled = true;
  page.busyForm = form;
  page.busyFocus = focused;
  return () => {
    for (const [element, disabled] of controls) element.disabled = disabled;
    if (page.busyForm === form) {
      page.busyForm = null;
      page.busyFocus = null;
    }
    const now = document.activeElement;
    if ((!now || now === document.body) && focusable(focused))
      focused.focus({ preventScroll: true });
    // A saved (or failed) form may be what kept a waiting update from reloading the page.
    if (page.updateBuild) setTimeout(offerUpdate);
  };
}
/**
 * For a button that disables itself while its request is on its way (an export, Test
 * connection), as lockForm() does for a form's controls. Call it before disabling the button:
 * disabling it drops its focus to <body>, so it is page.busyFocus meanwhile, and a sign-in
 * dialog the request opens returns the focus to it, not to <body>. Call the returned function
 * once the button works again: it gives the focus back, unless the focus has moved on.
 */
export function holdFocus(button) {
  const focused = document.activeElement === button;
  if (focused) page.busyFocus = button;
  return () => {
    if (page.busyFocus === button) page.busyFocus = null;
    const now = document.activeElement;
    if (focused && (!now || now === document.body) && focusable(button))
      button.focus({ preventScroll: true });
  };
}
export function formSnapshot(form) {
  if (!form) return '';
  return JSON.stringify(
    [...form.querySelectorAll('input,select,textarea')]
      .filter(el => !['export-source', 'export-range'].includes(el.id))
      .map(el => [el.id, el.value, ['checkbox', 'radio'].includes(el.type) ? el.checked : null])
  );
}
export function pageForm() {
  return $('#settings-form') || $('#email-form') || $('#password-form');
}
export function pageDirty() {
  return !!page.pageBaseline && formSnapshot(pageForm()) !== page.pageBaseline;
}
export function drawerDirty() {
  return (
    !!page.drawerBaseline &&
    (formSnapshot($('#connection-form')) !== page.drawerBaseline ||
      JSON.stringify(page.draftRules) !== page.drawerRulesBaseline)
  );
}
export function updateDirtyIndicator() {
  const dirty = pageDirty(),
    status = $('#dirty-status');
  if (status) {
    status.textContent = $('#password-form')
      ? dirty
        ? 'New password not saved'
        : 'Your sign-in is unchanged'
      : dirty
        ? 'You have unsaved changes'
        : 'All changes saved';
    status.classList.toggle('is-dirty', dirty);
  }
  $('#configuration-page').classList.toggle('has-unsaved', dirty);
}
export function allowDrawerLeave(discard = false) {
  // A finished change may still be reloading the dashboard after its form was replaced.
  if (page.busyForm && page.busyForm === $('#connection-form')) {
    toast('Finishing the connection change…');
    return false;
  }
  return discard || !drawerDirty() || confirm('Discard your unsaved connection changes?');
}
export function allowPageLeave() {
  if (page.busyForm && page.busyForm.id !== 'connection-form') {
    toast('Finishing your request…');
    return false;
  }
  return !pageDirty() || confirm('Discard your unsaved configuration changes?');
}
