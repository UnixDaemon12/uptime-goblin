// Numbers, dates and the time zone the page shows times in.
import { formatTime, isSupported } from '../../shared/timezone.js';
import { esc } from './dom.js';
import { page } from './page.js';

let displayTimeZone,
  unsupportedTimeZone = null;
export function format(value, unit = '') {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (unit === 'bytes' || unit === 'bytes/s') {
    let n = value,
      i = 0;
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    while (Math.abs(n) >= 1024 && i < 4) {
      n /= 1024;
      i++;
    }
    return `${n.toLocaleString(undefined, { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}${unit === 'bytes/s' ? '/s' : ''}`;
  }
  if (unit === 'seconds') {
    if (value >= 86400) return `${(value / 86400).toFixed(1)} d`;
    if (value >= 3600) return `${(value / 3600).toFixed(1)} h`;
    if (value >= 60) return `${Math.round(value / 60)} m`;
    return `${Math.round(value)} s`;
  }
  return `${value.toLocaleString(undefined, { maximumFractionDigits: Math.abs(value) < 10 ? 2 : 1 })}${unit === '%' ? '%' : unit ? ' ' + unit : ''}`;
}
/**
 * Checks the saved zone once per configuration load. Fixed offsets (UTC+05:30) always work;
 * browsers know different region names, and an unknown one is shown in local time.
 */
export function checkTimeZone() {
  const zone = page.data.config.appearance?.timezone;
  displayTimeZone = 'local';
  unsupportedTimeZone = null;
  if (!zone || zone === 'local') return;
  if (isSupported(zone)) displayTimeZone = zone;
  else unsupportedTimeZone = zone;
}
export function timeZoneNote() {
  if (!unsupportedTimeZone) return '';
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return `<p class="field-error">This browser does not support the saved time zone “${esc(unsupportedTimeZone)}”, so it shows times in its own local time zone${local ? ` (${esc(local)})` : ''}. Choose “local”, a fixed offset such as UTC+05:30, or an IANA name such as America/Chicago.</p>`;
}
function dateOptions(options = {}) {
  const a = page.data?.config.appearance || {};
  return {
    ...options,
    ...(a.timeFormat === '12h'
      ? { hour12: true }
      : a.timeFormat === '24h'
        ? { hour12: false }
        : {}),
  };
}
export function dateTime(t, options) {
  if (!t) return '—';
  try {
    return formatTime(t, displayTimeZone, dateOptions(options)) || '—';
  } catch {
    return new Date(t).toLocaleString([], options);
  }
}
export function when(t) {
  return dateTime(t, { hour: '2-digit', minute: '2-digit' });
}
