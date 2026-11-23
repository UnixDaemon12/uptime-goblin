// Display time zones, shared by the browser (public/app.js) and the server (lib/time.mjs), so
// both accept the same settings and show the same times. No imports, no DOM, no eval.
//
// A display time zone is one of:
//   'local'       the viewer's own time zone;
//   'UTC'         (UTC+00:00 and UTC-00:00 are the same zone and are saved as 'UTC');
//   'UTC±HH:MM'   a fixed offset: hours 00-14, minutes 00, 15, 30 or 45 (UTC+05:30, UTC-08:00);
//   a region-based IANA name such as Europe/London or America/Argentina/Buenos_Aires.
// Abbreviations (BST, IST), POSIX names (EST5EDT) and legacy aliases (US/Eastern) are refused:
// ICU accepts some of them but Firefox and Safari do not, and BST resolves to Dhaka in ICU.
//
// Fixed offsets never reach Intl: the instant is shifted by the offset and formatted as UTC,
// so they work in engines whose Intl rejects offset time zones. A zone that is invalid, or a
// region this engine does not know, is shown in local time (isSupported says which).

const MINUTE = 60000;
const DAY = 86400000;
const OFFSET = /^UTC([+\-\u2212])(0\d|1[0-4]):(00|15|30|45)$/;
const REGION =
  /^(?:Africa|America|Antarctica|Arctic|Asia|Atlantic|Australia|Europe|Indian|Pacific|Etc)\/[A-Z][A-Za-z0-9_+-]*(?:\/[A-Z][A-Za-z0-9_+-]*)*$/;
const MAX_LENGTH = 100;
// The largest instant a Date can hold; a shifted offset time must stay inside it.
const MAX_TIME = 8.64e15;

/**
 * Parses a display time zone setting.
 * @returns {{kind: 'local'|'utc'|'offset'|'region', id: string, offsetMinutes?: number} | null}
 *   `id` is the canonical spelling to save; `offsetMinutes` (east of UTC) is set for 'utc'
 *   and 'offset'. Returns null for anything else. A region is only checked for its shape;
 *   isSupported() says whether this engine knows it.
 */
export function parseTimeZone(value) {
  if (typeof value !== 'string' || value.length > MAX_LENGTH) return null;
  if (value === 'local') return { kind: 'local', id: 'local' };
  if (value === 'UTC') return { kind: 'utc', id: 'UTC', offsetMinutes: 0 };
  const offset = OFFSET.exec(value);
  if (offset) {
    const minutes = Number(offset[2]) * 60 + Number(offset[3]);
    if (minutes === 0) return { kind: 'utc', id: 'UTC', offsetMinutes: 0 };
    const sign = offset[1] === '+' ? '+' : '-';
    return {
      kind: 'offset',
      id: `UTC${sign}${offset[2]}:${offset[3]}`,
      offsetMinutes: sign === '+' ? minutes : -minutes,
    };
  }
  if (REGION.test(value)) return { kind: 'region', id: value };
  return null;
}

/** The canonical spelling of a valid setting (UTC+00:00 becomes UTC), or null. */
export function canonicalTimeZone(value) {
  return parseTimeZone(value)?.id ?? null;
}

const supported = new Map();
/**
 * Whether this engine can show times in the zone: 'local', 'UTC' and every valid offset
 * always; a region name only when this engine's Intl knows it. False for invalid settings.
 */
export function isSupported(timezone) {
  const zone = parseTimeZone(timezone);
  if (!zone) return false;
  if (zone.kind !== 'region') return true;
  if (!supported.has(zone.id)) {
    if (supported.size >= 64) supported.clear();
    let known = true;
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: zone.id });
    } catch {
      known = false;
    }
    supported.set(zone.id, known);
  }
  return supported.get(zone.id);
}

// The zone actually used: an invalid or unknown zone falls back to local time, so one bad
// setting never stops a page from rendering.
function effective(timezone) {
  const zone = parseTimeZone(timezone);
  return zone && (zone.kind !== 'region' || isSupported(zone.id)) ? zone : { kind: 'local' };
}

function epoch(value) {
  const time = typeof value === 'number' ? value : value instanceof Date ? value.getTime() : NaN;
  return Number.isFinite(time) && Math.abs(time) <= MAX_TIME ? time : NaN;
}

const partFormatters = new Map();
function partFormatter(id) {
  let formatter = partFormatters.get(id);
  if (!formatter) {
    if (partFormatters.size >= 64) partFormatters.clear();
    formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: id,
      hourCycle: 'h23',
      era: 'short',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
    partFormatters.set(id, formatter);
  }
  return formatter;
}
// Milliseconds since the epoch of a wall-clock time read as if it were UTC. Unlike Date.UTC,
// years 0-99 are not moved to the 1900s.
function wallClock(year, month, day, hour = 0, minute = 0, second = 0, millisecond = 0) {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millisecond);
  return date.getTime();
}
function floorMod(value, divisor) {
  return ((value % divisor) + divisor) % divisor;
}
// Wall-clock fields of an instant in a region zone, read from Intl.
function regionParts(time, id) {
  const fields = {};
  for (const part of partFormatter(id).formatToParts(time)) fields[part.type] = part.value;
  let year = Number(fields.year);
  if (/^B/i.test(fields.era || '')) year = 1 - year;
  const millisecond = floorMod(time, 1000);
  const parts = {
    year,
    month: Number(fields.month),
    day: Number(fields.day),
    // Some engines write midnight as 24 even with hourCycle h23.
    hour: Number(fields.hour) % 24,
    minute: Number(fields.minute),
    second: Number(fields.second),
    millisecond,
  };
  // Milliseconds, not minutes: historical local mean times have offsets in whole seconds.
  parts.offsetMs =
    wallClock(parts.year, parts.month, parts.day, parts.hour, parts.minute, parts.second) +
    millisecond -
    time;
  return parts;
}

/**
 * Wall-clock fields of an instant in a zone: {year, month (1-12), day, hour (0-23), minute,
 * second, millisecond, weekday (0 = Sunday), offsetMinutes (east of UTC)}. An invalid or
 * unknown zone gives local time. Returns null for an invalid instant.
 */
export function zonedParts(epochMs, timezone) {
  const time = epoch(epochMs);
  if (Number.isNaN(time)) return null;
  const zone = effective(timezone);
  let parts;
  if (zone.kind === 'local') {
    const date = new Date(time);
    parts = {
      year: date.getFullYear(),
      month: date.getMonth() + 1,
      day: date.getDate(),
      hour: date.getHours(),
      minute: date.getMinutes(),
      second: date.getSeconds(),
      millisecond: date.getMilliseconds(),
      offsetMinutes: -date.getTimezoneOffset(),
    };
  } else if (zone.kind === 'region') {
    const { offsetMs, ...fields } = regionParts(time, zone.id);
    parts = { ...fields, offsetMinutes: offsetMs / MINUTE };
  } else {
    const date = new Date(time + zone.offsetMinutes * MINUTE);
    parts = {
      year: date.getUTCFullYear(),
      month: date.getUTCMonth() + 1,
      day: date.getUTCDate(),
      hour: date.getUTCHours(),
      minute: date.getUTCMinutes(),
      second: date.getUTCSeconds(),
      millisecond: date.getUTCMilliseconds(),
      offsetMinutes: zone.offsetMinutes,
    };
  }
  parts.weekday = new Date(wallClock(parts.year, parts.month, parts.day)).getUTCDay();
  return parts;
}

/** Minutes east of UTC in effect in the zone at an instant (default now); NaN if invalid. */
export function offsetMinutes(timezone, epochMs = Date.now()) {
  return zonedParts(epochMs, timezone)?.offsetMinutes ?? NaN;
}

/**
 * The instant of a wall-clock time in a zone: {year, month (1-12), day, hour, minute, second,
 * millisecond} (time fields default to 0). A time repeated when clocks go back gives the
 * earlier instant; a time skipped when clocks go forward is moved forward by the length of the
 * gap (so a skipped midnight gives the first instant of that day). An invalid or unknown zone
 * is read as local time. Throws RangeError for invalid fields.
 */
export function fromZonedParts(parts, timezone) {
  const { year, month, day, hour = 0, minute = 0, second = 0, millisecond = 0 } = parts || {};
  for (const [name, value, min, max] of [
    ['year', year, -270000, 270000],
    ['month', month, 1, 12],
    ['day', day, 1, 31],
    ['hour', hour, 0, 23],
    ['minute', minute, 0, 59],
    ['second', second, 0, 59],
    ['millisecond', millisecond, 0, 999],
  ])
    if (!Number.isInteger(value) || value < min || value > max)
      throw new RangeError(`Invalid ${name}`);
  const wall = wallClock(year, month, day, hour, minute, second, millisecond);
  if (new Date(wall).getUTCDate() !== day) throw new RangeError('Invalid day');
  const zone = effective(timezone);
  if (zone.kind === 'utc' || zone.kind === 'offset') return wall - zone.offsetMinutes * MINUTE;
  if (zone.kind === 'local') {
    // Date's local-time constructor already resolves repeated and skipped times this way.
    const date = new Date(year, month - 1, day, hour, minute, second, millisecond);
    if (year >= 0 && year < 100) date.setFullYear(year);
    return date.getTime();
  }
  // Offsets in effect around the wall time: a transition near it changes the offset within
  // a day either side.
  const offsetAt = time => regionParts(time, zone.id).offsetMs;
  const before = offsetAt(wall - DAY),
    after = offsetAt(wall + DAY);
  const matches = [...new Set([before, offsetAt(wall), after])]
    .map(offset => wall - offset)
    .filter(time => offsetAt(time) === wall - time)
    .sort((a, b) => a - b);
  // Skipped: read with the offset before the gap, which lands after the transition.
  return matches.length ? matches[0] : wall - before;
}

/** The first instant of the calendar day containing an instant, in a zone. NaN if invalid. */
export function startOfDay(epochMs, timezone) {
  const parts = zonedParts(epochMs, timezone);
  if (!parts) return NaN;
  return fromZonedParts({ year: parts.year, month: parts.month, day: parts.day }, timezone);
}

/**
 * A calendar month (month 1-12) in a zone as {from, to}: from is its first instant and to the
 * first instant of the next month (exclusive), whatever daylight saving does in between.
 */
export function monthRange(year, month, timezone) {
  if (!Number.isInteger(month) || month < 1 || month > 12) throw new RangeError('Invalid month');
  const next = month === 12 ? { year: year + 1, month: 1 } : { year, month: month + 1 };
  return {
    from: fromZonedParts({ year, month, day: 1 }, timezone),
    to: fromZonedParts({ ...next, day: 1 }, timezone),
  };
}

// Like Date.prototype.toLocaleString: options without any date or time field show both.
const FIELDS = [
  'weekday',
  'year',
  'month',
  'day',
  'dayPeriod',
  'hour',
  'minute',
  'second',
  'fractionalSecondDigits',
  'dateStyle',
  'timeStyle',
];
const formatters = new Map();
function formatter(locale, options) {
  const key = JSON.stringify([locale ?? null, options]);
  let value = formatters.get(key);
  if (!value) {
    if (formatters.size >= 64) formatters.clear();
    value = new Intl.DateTimeFormat(locale, options);
    formatters.set(key, value);
  }
  return value;
}

/**
 * Formats an instant (epoch milliseconds or a Date) in a display time zone.
 * `options` are Intl.DateTimeFormat options plus `locale` (a tag or list; default: the
 * engine's); their own `timeZone` is ignored. Like toLocaleString, options without any date or
 * time field show both. For a fixed offset, a requested time zone name (`timeZoneName`, or the
 * long and full `timeStyle`) is written as the offset itself, such as "UTC+05:30". An invalid
 * or unknown zone shows local time. Returns '' for an invalid instant; invalid options throw
 * RangeError, as Intl does.
 */
export function formatTime(epochMs, timezone, options = {}) {
  const time = epoch(epochMs);
  if (Number.isNaN(time)) return '';
  // The zone argument decides; an Intl timeZone option would bypass the offset handling.
  const { locale, timeZone: _ignored, ...intl } = options || {};
  const zone = effective(timezone);
  if (!FIELDS.some(key => intl[key] !== undefined))
    Object.assign(intl, {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
  let instant = time,
    suffix = '';
  if (zone.kind === 'offset') {
    instant = time + zone.offsetMinutes * MINUTE;
    if (Math.abs(instant) > MAX_TIME) return '';
    intl.timeZone = 'UTC';
    if (intl.timeZoneName !== undefined) {
      delete intl.timeZoneName;
      suffix = ' ' + zone.id;
    }
    if (intl.timeStyle === 'long' || intl.timeStyle === 'full') {
      intl.timeStyle = 'medium';
      suffix = ' ' + zone.id;
    }
  } else if (zone.kind === 'local')
    // Not cached: a formatter keeps the zone it was made in, and the device's zone can change
    // while a page stays open (a laptop that travels, a server whose TZ is changed).
    return new Date(time).toLocaleString(locale, intl);
  else intl.timeZone = zone.id;
  return formatter(locale, intl).format(instant) + suffix;
}

/**
 * A short name for the zone times are shown in: the offset or region name as saved, 'UTC',
 * or for 'local' (and invalid or unknown zones, which show local time) the engine's own zone
 * name when it has one.
 */
export function timeZoneLabel(timezone) {
  const zone = effective(timezone);
  if (zone.kind !== 'local') return zone.id;
  try {
    return new Intl.DateTimeFormat().resolvedOptions().timeZone || 'local';
  } catch {
    return 'local';
  }
}
