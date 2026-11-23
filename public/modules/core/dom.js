// DOM helpers: $, HTML escaping, icons, status labels, opening and closing dialogs, and the toast.

export const $ = selector => document.querySelector(selector);
export const esc = value =>
  String(value ?? '').replace(
    /[&<>"']/g,
    char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]
  );
const paths = {
  server: 'M3 3h18v7H3z M3 14h18v7H3z M7 6.5h.01 M7 17.5h.01',
  terminal: 'm5 6 5 6-5 6 M13 18h6',
  window: 'M3 3h8v8H3z M14 3h7v8h-7z M3 14h8v7H3z M14 14h7v7h-7z',
  network: 'M12 8v5 M5 13h14 M5 13v4 M19 13v4 M9 2h6v6H9z M2 17h6v5H2z M16 17h6v5h-6z',
  drive: 'M5 4h14l3 12H2z M2 16v5h20v-5 M16 18.5h.01 M19 18.5h.01',
  layers: 'm12 3 10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5',
  play: 'm8 4 12 8-12 8z',
  activity: 'M2 12h4l3-9 5 18 3-9h5',
  ticket: 'M4 5h16v5a2 2 0 0 0 0 4v5H4v-5a2 2 0 0 0 0-4z M14 5v3 M14 11v2 M14 16v3',
  tv: 'M3 7h18v14H3z M7 2l5 5 5-5',
  film: 'M3 3h18v18H3z M7 3v18 M17 3v18 M3 8h4 M3 16h4 M17 8h4 M17 16h4',
  radar: 'M12 3a9 9 0 1 0 9 9 M12 7a5 5 0 1 0 5 5 M12 12 21 3 M17 3h4v4',
  download: 'M12 3v12 m-5-5 5 5 5-5 M4 16v5h16v-5',
  shield: 'M12 2 3 6v6c0 6 9 10 9 10s9-4 9-10V6z m-5 10 3 3 5-6',
  route: 'M5 3v18 M5 7h9c5 0 5 10 0 10h-3 M3 3h4 M3 21h4 m11-8-4 4 4 4',
  lock: 'M5 10h14v12H5z M8 10V6a4 4 0 0 1 8 0v4 M12 15v3',
  orbit: 'M12 3a9 9 0 1 0 9 9 M15 3a3 3 0 1 0 6 0 M12 10v4 M10 12h4',
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  chevron: 'm6 9 6 6 6-6',
  external: 'M14 3h7v7 m-1-6-9 9 M10 3H3v18h18v-7',
  chart: 'M3 3v18h18 M6 16l4-6 4 3 6-8',
  pause: 'M8 5v14 M16 5v14',
  plus: 'M12 5v14 M5 12h14',
  gamepad:
    'M7 7h10c3 0 4 4 4 10s-4 3-6-1H9c-2 4-6 7-6 1s1-10 4-10z M7 9v6 M4 12h6 M16 11h.01 M18 14h.01',
  globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3a19 19 0 0 1 0 18 19 19 0 0 1 0-18',
  check: 'm5 12 4 4L19 6',
  list: 'M8 6h13 M8 12h13 M8 18h13 M3 6h.01 M3 12h.01 M3 18h.01',
};
export function icon(type, size = 20) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${paths[type] || paths.grid}"/></svg>`;
}
export const states = {
  unconfigured: 'Not connected',
  live: 'Connected',
  error: 'Check failed',
  stale: 'Last reading · stale',
  disabled: 'Paused',
  link: 'Link only',
  collecting: 'Connecting',
};
let toastTimer;

// Pop-ups and expanded card details leave with a short exit motion (see style.css). With
// reduced motion they close at once. A leaving dialog is inert, so nothing in it (a second
// "Add source" click, a keypress) can act during the motion. Opening it again while it is
// still leaving cancels the close, so a quick "close, reopen" never ends with it shut.
export const exitMs = 190;
const leaving = new WeakMap();
export const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
/**
 * `now`: closes at once, as with reduced motion, also a dialog already leaving. For a route
 * change: while a modal leaves, the page under it stays inert, so the new page could not take
 * the focus, and the browser would give it back to the opener on the page just hidden.
 */
export function closeDialog(dialog, { now = false } = {}) {
  if (now && leaving.has(dialog)) {
    clearTimeout(leaving.get(dialog));
    leaving.delete(dialog);
    dialog.classList.remove('closing');
    dialog.inert = false;
  }
  if (!dialog.open || leaving.has(dialog)) return;
  if (now || reducedMotion()) {
    dialog.close();
    return;
  }
  dialog.classList.add('closing');
  dialog.inert = true;
  leaving.set(
    dialog,
    setTimeout(() => {
      leaving.delete(dialog);
      dialog.classList.remove('closing');
      dialog.inert = false;
      dialog.close();
    }, exitMs)
  );
}
export function openDialog(dialog) {
  if (leaving.has(dialog)) {
    clearTimeout(leaving.get(dialog));
    leaving.delete(dialog);
    dialog.classList.remove('closing');
    dialog.inert = false;
  }
  if (!dialog.open) dialog.showModal();
}
export function toast(message) {
  (document.querySelector('dialog[open]:not(.closing)') || document.body).append($('#toast'));
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($('#toast').hidden = true), 4500);
}
