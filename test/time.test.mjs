// public/shared/timezone.js (and its server re-export lib/time.mjs), tested without a browser.
// Engines that lack offset time zones, or a region, are simulated by replacing Intl in a fresh
// copy of the module.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseTimeZone,
  canonicalTimeZone,
  isSupported,
  formatTime,
  zonedParts,
  offsetMinutes,
  fromZonedParts,
  startOfDay,
  monthRange,
  timeZoneLabel,
} from '../public/shared/timezone.js';
import * as server from '../lib/time.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const shared = path.join(root, 'public', 'shared', 'timezone.js');
const HOUR = 3600000,
  DAY = 24 * HOUR;
const iso = time => new Date(time).toISOString();
const at = text => Date.parse(text);
// Runs a test body with the process (and so Date and Intl) in another local time zone.
async function inLocalZone(zone, body) {
  const saved = process.env.TZ;
  process.env.TZ = zone;
  try {
    return await body();
  } finally {
    if (saved === undefined) delete process.env.TZ;
    else process.env.TZ = saved;
  }
}
// A fresh copy of the module (its caches empty) running with a replaced Intl.DateTimeFormat.
let copies = 0;
async function withEngine(accepts, body) {
  const Original = Intl.DateTimeFormat;
  const zones = [];
  function Limited(locale, options = {}) {
    if (options.timeZone !== undefined) {
      zones.push(options.timeZone);
      if (!accepts(options.timeZone))
        throw new RangeError(`Invalid time zone specified: ${options.timeZone}`);
    }
    return new Original(locale, options);
  }
  Limited.supportedLocalesOf = Original.supportedLocalesOf;
  Intl.DateTimeFormat = Limited;
  try {
    const module = await import(`../public/shared/timezone.js?engine=${++copies}`);
    return await body(module, zones);
  } finally {
    Intl.DateTimeFormat = Original;
  }
}
// An engine whose Intl knows region names but no offset time zones (as older Safari and
// Firefox releases).
const regionsOnly = zone => zone === 'UTC' || /^[A-Z][A-Za-z_]+\/[A-Za-z_+\-/0-9]+$/.test(zone);

test('settings: local, UTC, UTC±HH:MM offsets and region-based IANA names, saved canonically', () => {
  for (const [value, kind, id, offset] of [
    ['local', 'local', 'local', undefined],
    ['UTC', 'utc', 'UTC', 0],
    ['UTC+00:00', 'utc', 'UTC', 0],
    ['UTC-00:00', 'utc', 'UTC', 0],
    ['UTC+05:30', 'offset', 'UTC+05:30', 330],
    ['UTC-08:00', 'offset', 'UTC-08:00', -480],
    ['UTC+05:45', 'offset', 'UTC+05:45', 345],
    ['UTC+12:45', 'offset', 'UTC+12:45', 765],
    ['UTC-09:30', 'offset', 'UTC-09:30', -570],
    ['UTC+14:00', 'offset', 'UTC+14:00', 840],
    ['UTC-12:00', 'offset', 'UTC-12:00', -720],
    ['UTC+14:45', 'offset', 'UTC+14:45', 885],
    ['UTC+00:15', 'offset', 'UTC+00:15', 15],
    // The minus sign (U+2212) as written in most offset tables is saved as a hyphen.
    ['UTC\u221203:00', 'offset', 'UTC-03:00', -180],
    ['Europe/London', 'region', 'Europe/London', undefined],
    ['America/Argentina/Buenos_Aires', 'region', 'America/Argentina/Buenos_Aires', undefined],
    ['Etc/GMT+5', 'region', 'Etc/GMT+5', undefined],
  ]) {
    assert.deepEqual(
      parseTimeZone(value),
      offset === undefined ? { kind, id } : { kind, id, offsetMinutes: offset },
      value
    );
    assert.equal(canonicalTimeZone(value), id, value);
  }
  for (const refused of [
    '',
    'Local',
    'utc',
    'GMT',
    'UTC+5:30',
    'UTC+05',
    'UTC+0530',
    'UTC+05:30:00',
    'UTC+05:10',
    'UTC+05:60',
    'UTC+15:00',
    'UTC-15:00',
    'UTC+24:00',
    'UTC 05:30',
    'UTC +05:30',
    ' UTC+05:30',
    'UTC+05:30 ',
    '+05:30',
    'GMT+05:30',
    'UTC+٠٥:٣٠',
    'US/Eastern',
    'EST5EDT',
    'BST',
    'europe/london',
    'Mars/Olympus_Mons',
    '../etc/passwd',
    'Europe/' + 'A'.repeat(100),
    null,
    undefined,
    330,
    { kind: 'offset' },
  ]) {
    assert.equal(parseTimeZone(refused), null, String(refused));
    assert.equal(canonicalTimeZone(refused), null, String(refused));
    assert.equal(isSupported(refused), false, String(refused));
  }
});

test('isSupported: offsets always; region names only when Intl knows them', async () => {
  for (const zone of ['local', 'UTC', 'UTC+05:30', 'UTC-12:00', 'Asia/Kathmandu', 'Etc/GMT-14'])
    assert.equal(isSupported(zone), true, zone);
  // Shaped like a region name, but no such zone.
  assert.equal(isSupported('Europe/Atlantis'), false);
  // An engine that rejects every offset time zone still supports offset settings.
  await withEngine(regionsOnly, async module => {
    assert.throws(() => new Intl.DateTimeFormat('en', { timeZone: '+05:30' }), RangeError);
    for (const zone of ['UTC+05:30', 'UTC-08:00', 'UTC', 'local', 'Europe/London'])
      assert.equal(module.isSupported(zone), true, zone);
  });
  // An engine with older time zone data than the server: that region is unsupported.
  await withEngine(
    zone => zone !== 'America/Ciudad_Juarez',
    async module => {
      assert.equal(module.isSupported('America/Ciudad_Juarez'), false);
      assert.equal(module.isSupported('America/Chicago'), true);
    }
  );
});

test('formatTime: offsets shift the instant and format it as UTC', () => {
  const t = at('2026-09-29T12:34:56.789Z');
  const clock = { locale: 'en-GB', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  const dated = { ...clock, year: 'numeric', month: '2-digit', day: '2-digit' };
  assert.equal(formatTime(t, 'UTC+05:30', clock), '18:04');
  assert.equal(formatTime(t, 'UTC+05:45', clock), '18:19');
  assert.equal(formatTime(t, 'UTC-08:00', clock), '04:34');
  assert.equal(formatTime(t, 'UTC-09:30', clock), '03:04');
  assert.equal(formatTime(t, 'UTC+12:45', dated), '30/09/2026, 01:19');
  assert.equal(formatTime(t, 'UTC+14:00', dated), '30/09/2026, 02:34');
  assert.equal(formatTime(at('2026-01-01T03:00:00Z'), 'UTC-08:00', dated), '31/12/2025, 19:00');
  assert.equal(formatTime(t, 'UTC', clock), '12:34');
  assert.equal(formatTime(t, 'UTC+00:00', clock), '12:34');
  assert.equal(formatTime(t, 'UTC\u221203:00', clock), '09:34');
  // A requested zone name is the offset itself, never Intl's "UTC" for the shifted instant.
  assert.equal(formatTime(t, 'UTC+05:30', { ...clock, timeZoneName: 'short' }), '18:04 UTC+05:30');
  assert.equal(formatTime(t, 'UTC', { ...clock, timeZoneName: 'short' }), '12:34 UTC');
  for (const timeStyle of ['long', 'full']) {
    const text = formatTime(t, 'UTC-08:00', { locale: 'en-US', timeStyle });
    assert.equal(text, '4:34:56 AM UTC-08:00', timeStyle);
    assert.doesNotMatch(text, /Coordinated|UTC(?!-08:00)/);
  }
  assert.equal(formatTime(t, 'UTC-08:00', { locale: 'en-US', timeStyle: 'short' }), '4:34 AM');
  assert.equal(
    formatTime(t, 'UTC+05:30', { locale: 'en-US', dateStyle: 'medium', timeStyle: 'short' }),
    'Sep 29, 2026, 6:04 PM'
  );
  // 12- and 24-hour preferences pass through.
  assert.equal(
    formatTime(t, 'UTC+05:30', {
      locale: 'en-GB',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    }),
    '6:04 pm'
  );
  assert.equal(
    formatTime(t, 'UTC+05:30', {
      locale: 'en-US',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }),
    '18:04'
  );
});

test('formatTime: region names follow daylight saving; options mirror toLocaleString', () => {
  const clock = { locale: 'en-GB', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  assert.equal(formatTime(at('2026-07-01T12:00:00Z'), 'Europe/London', clock), '13:00');
  assert.equal(formatTime(at('2026-12-01T12:00:00Z'), 'Europe/London', clock), '12:00');
  assert.equal(formatTime(at('2026-07-01T12:00:00Z'), 'America/Chicago', clock), '07:00');
  assert.equal(formatTime(at('2026-07-01T12:00:00Z'), 'Asia/Kathmandu', clock), '17:45');
  const t = at('2026-09-29T12:34:56Z');
  // Without a date or time field, both are shown, as toLocaleString does.
  for (const [zone, intlZone] of [
    ['UTC', 'UTC'],
    ['Europe/London', 'Europe/London'],
    ['America/Chicago', 'America/Chicago'],
  ]) {
    const expected = new Date(t).toLocaleString('en-US', { timeZone: intlZone });
    assert.equal(formatTime(t, zone, { locale: 'en-US' }), expected, zone);
    assert.equal(
      formatTime(t, zone, { locale: 'en-US', timeZoneName: 'short' }),
      new Date(t).toLocaleString('en-US', { timeZone: intlZone, timeZoneName: 'short' }),
      zone
    );
  }
  assert.equal(formatTime(t, 'UTC+05:30', { locale: 'en-US' }), '9/29/2026, 6:04:56 PM');
  // The zone argument decides; a timeZone option cannot bypass the offset handling.
  assert.equal(formatTime(t, 'UTC+05:30', { ...clock, timeZone: 'America/Chicago' }), '18:04');
  assert.equal(formatTime(new Date(t), 'UTC+05:30', clock), '18:04');
  for (const invalid of [undefined, null, NaN, Infinity, '1759149296000', 9e15, new Date(NaN)])
    assert.equal(formatTime(invalid, 'UTC+05:30', clock), '', String(invalid));
  // An offset that would move the instant past the largest Date is invalid too.
  assert.equal(formatTime(8.64e15, 'UTC+05:30', clock), '');
  assert.throws(() => formatTime(t, 'UTC', { hour: 'sometimes' }), RangeError);
});

test('formatTime: local time, and invalid or unknown zones shown in local time', async () => {
  await inLocalZone('America/Chicago', () => {
    const t = at('2026-09-29T12:34:56Z');
    const options = { locale: 'en-US', hour: '2-digit', minute: '2-digit' };
    assert.equal(formatTime(t, 'local', options), '07:34 AM');
    assert.equal(formatTime(t, 'local', { locale: 'en-US' }), new Date(t).toLocaleString('en-US'));
    for (const zone of ['Bogus/Zone', 'Europe/Atlantis', 'UTC+5:30', '', undefined])
      assert.equal(formatTime(t, zone, options), '07:34 AM', String(zone));
    assert.equal(timeZoneLabel('local'), 'America/Chicago');
    assert.equal(timeZoneLabel('Europe/Atlantis'), 'America/Chicago');
  });
  // Local time follows the device's zone when it changes while the page stays open.
  const short = { locale: 'en-GB', timeStyle: 'short' };
  await inLocalZone('America/Chicago', () =>
    assert.equal(formatTime(at('2026-09-29T12:34:56Z'), 'local', short), '07:34')
  );
  await inLocalZone('Asia/Kolkata', () =>
    assert.equal(formatTime(at('2026-09-29T12:34:56Z'), 'local', short), '18:04')
  );
  assert.equal(timeZoneLabel('UTC'), 'UTC');
  assert.equal(timeZoneLabel('UTC+05:30'), 'UTC+05:30');
  assert.equal(timeZoneLabel('UTC+00:00'), 'UTC');
  assert.equal(timeZoneLabel('Europe/London'), 'Europe/London');
});

test('an engine without offset time zones shows offsets, and never passes one to Intl', async () => {
  const t = at('2026-09-29T12:34:56Z');
  const clock = { locale: 'en-GB', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' };
  await withEngine(regionsOnly, async (module, zones) => {
    assert.equal(module.formatTime(t, 'UTC+05:30', clock), '18:04');
    assert.equal(
      module.formatTime(t, 'UTC-08:00', { ...clock, timeZoneName: 'long' }),
      '04:34 UTC-08:00'
    );
    assert.equal(module.formatTime(t, 'Europe/London', clock), '13:34');
    assert.equal(module.offsetMinutes('UTC+05:45', t), 345);
    assert.equal(module.startOfDay(t, 'UTC+05:30'), at('2026-09-28T18:30:00Z'));
    assert.deepEqual(module.monthRange(2026, 9, 'UTC-08:00'), {
      from: at('2026-09-01T08:00:00Z'),
      to: at('2026-10-01T08:00:00Z'),
    });
    assert.ok(zones.length > 0);
    for (const zone of zones) assert.ok(regionsOnly(zone), `Intl was given ${zone}`);
  });
  // A region the engine does not know falls back to local time instead of throwing.
  await inLocalZone('America/Chicago', () =>
    withEngine(
      zone => zone !== 'America/Ciudad_Juarez',
      async module => {
        assert.equal(
          module.formatTime(t, 'America/Ciudad_Juarez', clock),
          module.formatTime(t, 'local', clock)
        );
        assert.equal(module.formatTime(t, 'America/Ciudad_Juarez', clock), '07:34');
      }
    )
  );
});

test('zonedParts and offsetMinutes', () => {
  const t = at('2026-09-29T12:34:56.789Z');
  assert.deepEqual(zonedParts(t, 'UTC+05:45'), {
    year: 2026,
    month: 9,
    day: 29,
    hour: 18,
    minute: 19,
    second: 56,
    millisecond: 789,
    offsetMinutes: 345,
    weekday: 2,
  });
  assert.deepEqual(zonedParts(t, 'Pacific/Chatham'), {
    year: 2026,
    month: 9,
    day: 30,
    hour: 2,
    minute: 19,
    second: 56,
    millisecond: 789,
    offsetMinutes: 825,
    weekday: 3,
  });
  assert.deepEqual(zonedParts(at('2026-01-01T03:00:00Z'), 'UTC-08:00'), {
    year: 2025,
    month: 12,
    day: 31,
    hour: 19,
    minute: 0,
    second: 0,
    millisecond: 0,
    offsetMinutes: -480,
    weekday: 3,
  });
  for (const [zone, winter, summer] of [
    ['Europe/London', 0, 60],
    ['America/Chicago', -360, -300],
    ['Asia/Kolkata', 330, 330],
    ['Asia/Kathmandu', 345, 345],
    // Southern hemisphere: daylight saving in January.
    ['Australia/Lord_Howe', 660, 630],
    ['Pacific/Chatham', 825, 765],
    ['America/Santiago', -180, -240],
    ['UTC+05:30', 330, 330],
    ['UTC', 0, 0],
  ]) {
    assert.equal(offsetMinutes(zone, at('2026-01-15T12:00:00Z')), winter, zone);
    assert.equal(offsetMinutes(zone, at('2026-07-15T12:00:00Z')), summer, zone);
  }
  // Historical local mean time is offset by whole seconds.
  assert.equal(offsetMinutes('Africa/Monrovia', at('1960-06-01T12:00:00Z')), -44.5);
  assert.equal(zonedParts(NaN, 'UTC'), null);
  assert.ok(Number.isNaN(offsetMinutes('UTC', NaN)));
});

test('fromZonedParts: repeated times give the earlier instant, skipped times move forward', async () => {
  // Chicago: 01:00-02:00 happens twice on 1 November 2026, 02:00-03:00 never on 8 March.
  const repeated = { year: 2026, month: 11, day: 1, hour: 1, minute: 30 };
  const skipped = { year: 2026, month: 3, day: 8, hour: 2, minute: 30 };
  assert.equal(iso(fromZonedParts(repeated, 'America/Chicago')), '2026-11-01T06:30:00.000Z');
  assert.equal(iso(fromZonedParts(skipped, 'America/Chicago')), '2026-03-08T08:30:00.000Z');
  // Local time resolves the same way.
  await inLocalZone('America/Chicago', () => {
    assert.equal(iso(fromZonedParts(repeated, 'local')), '2026-11-01T06:30:00.000Z');
    assert.equal(iso(fromZonedParts(skipped, 'local')), '2026-03-08T08:30:00.000Z');
  });
  assert.equal(
    iso(fromZonedParts({ year: 2026, month: 9, day: 29, hour: 18, minute: 4 }, 'UTC+05:30')),
    '2026-09-29T12:34:00.000Z'
  );
  assert.equal(
    iso(fromZonedParts({ year: 1960, month: 6, day: 1 }, 'Africa/Monrovia')),
    '1960-06-01T00:44:30.000Z'
  );
  for (const invalid of [
    { year: 2026, month: 2, day: 30 },
    { year: 2026, month: 13, day: 1 },
    { year: 2026, month: 1, day: 1, hour: 24 },
    { year: 2026, month: 1, day: 1, minute: 1.5 },
    { year: '2026', month: 1, day: 1 },
    null,
  ])
    assert.throws(() => fromZonedParts(invalid, 'UTC'), RangeError, JSON.stringify(invalid));
});

test('day boundaries stay exact across daylight saving changes', () => {
  // Noon on that date in the zone (never inside a daylight saving gap).
  const noon = (zone, date) => {
    const [year, month, day] = date.split('-').map(Number);
    return fromZonedParts({ year, month, day, hour: 12 }, zone);
  };
  const length = (zone, date) => {
    const start = startOfDay(noon(zone, date), zone);
    return (startOfDay(start + 36 * HOUR, zone) - start) / HOUR;
  };
  for (const [zone, date, start, hours] of [
    // Clocks go forward at 01:00 GMT: a 23-hour day.
    ['Europe/London', '2026-03-29', '2026-03-29T00:00:00.000Z', 23],
    ['Europe/London', '2026-10-25', '2026-10-24T23:00:00.000Z', 25],
    ['America/Chicago', '2026-03-08', '2026-03-08T06:00:00.000Z', 23],
    ['America/Chicago', '2026-11-01', '2026-11-01T05:00:00.000Z', 25],
    // Santiago skips midnight: 6 September starts at 01:00 and has 23 hours.
    ['America/Santiago', '2026-09-05', '2026-09-05T04:00:00.000Z', 24],
    ['America/Santiago', '2026-09-06', '2026-09-06T04:00:00.000Z', 23],
    // Clocks go back from midnight to 23:00: Saturday has 25 hours.
    ['America/Santiago', '2026-04-04', '2026-04-04T03:00:00.000Z', 25],
    // A half-hour change.
    ['Australia/Lord_Howe', '2026-10-04', '2026-10-03T13:30:00.000Z', 23.5],
    ['Pacific/Chatham', '2026-09-27', '2026-09-26T11:15:00.000Z', 23],
    ['Asia/Kathmandu', '2026-09-29', '2026-09-28T18:15:00.000Z', 24],
    ['Asia/Kolkata', '2026-09-29', '2026-09-28T18:30:00.000Z', 24],
    ['UTC+05:30', '2026-09-29', '2026-09-28T18:30:00.000Z', 24],
    ['UTC-09:30', '2026-09-29', '2026-09-29T09:30:00.000Z', 24],
    ['UTC', '2026-09-29', '2026-09-29T00:00:00.000Z', 24],
  ]) {
    assert.equal(iso(startOfDay(noon(zone, date), zone)), start, `${zone} ${date}`);
    assert.equal(length(zone, date), hours, `${zone} ${date}`);
  }
  assert.ok(Number.isNaN(startOfDay(NaN, 'UTC')));
});

test('every instant of a year lies in the day startOfDay gives it, in every kind of zone', async () => {
  const zones = [
    'Europe/London',
    'America/Chicago',
    'America/Santiago',
    'Australia/Lord_Howe',
    'Pacific/Chatham',
    'Asia/Kathmandu',
    'UTC+05:30',
    'UTC-03:30',
    'UTC',
    'local',
  ];
  await inLocalZone('America/Havana', () => {
    for (const zone of zones)
      for (let t = at('2026-01-01T00:00:00Z'); t < at('2027-01-01T00:00:00Z'); t += 7 * HOUR + 1) {
        const start = startOfDay(t, zone),
          day = zonedParts(t, zone),
          first = zonedParts(start, zone),
          before = zonedParts(start - 1, zone);
        assert.ok(start <= t && t - start < 26 * HOUR, `${zone} ${iso(t)}`);
        assert.deepEqual(
          [first.year, first.month, first.day],
          [day.year, day.month, day.day],
          `${zone} ${iso(t)}`
        );
        assert.notDeepEqual(
          [before.year, before.month, before.day],
          [day.year, day.month, day.day],
          `${zone} ${iso(t)}`
        );
      }
  });
});

test('monthRange: calendar months in a zone, whatever daylight saving does', async () => {
  const hours = ({ from, to }) => (to - from) / HOUR;
  assert.deepEqual(monthRange(2026, 3, 'Europe/London'), {
    from: at('2026-03-01T00:00:00Z'),
    to: at('2026-03-31T23:00:00Z'),
  });
  assert.equal(hours(monthRange(2026, 3, 'Europe/London')), 31 * 24 - 1);
  assert.equal(hours(monthRange(2026, 11, 'America/Chicago')), 30 * 24 + 1);
  assert.equal(hours(monthRange(2026, 10, 'Australia/Lord_Howe')), 31 * 24 - 0.5);
  assert.equal(hours(monthRange(2026, 9, 'America/Santiago')), 30 * 24 - 1);
  assert.deepEqual(monthRange(2026, 12, 'UTC+05:30'), {
    from: at('2026-11-30T18:30:00Z'),
    to: at('2026-12-31T18:30:00Z'),
  });
  assert.deepEqual(monthRange(2024, 2, 'UTC'), {
    from: at('2024-02-01T00:00:00Z'),
    to: at('2024-03-01T00:00:00Z'),
  });
  await inLocalZone('America/Chicago', () =>
    assert.deepEqual(monthRange(2026, 11, 'local'), monthRange(2026, 11, 'America/Chicago'))
  );
  for (const month of [0, 13, 1.5, '3'])
    assert.throws(() => monthRange(2026, month, 'UTC'), RangeError);
});

test('the server uses the browser module unchanged, and accepts only zones it knows', () => {
  for (const name of [
    'parseTimeZone',
    'canonicalTimeZone',
    'isSupported',
    'formatTime',
    'zonedParts',
    'offsetMinutes',
    'fromZonedParts',
    'startOfDay',
    'monthRange',
    'timeZoneLabel',
  ])
    assert.equal(typeof server[name], 'function', name);
  assert.equal(server.formatTime, formatTime);
  assert.equal(server.normalizeTimeZone('UTC+00:00'), 'UTC');
  assert.equal(server.normalizeTimeZone('UTC\u221208:00'), 'UTC-08:00');
  assert.equal(server.normalizeTimeZone('Asia/Kathmandu'), 'Asia/Kathmandu');
  assert.equal(server.normalizeTimeZone('local'), 'local');
  assert.equal(server.normalizeTimeZone('Europe/Atlantis'), null);
  assert.equal(server.normalizeTimeZone('UTC+5:30'), null);
});

test('the shared module loads in a browser page under the strict CSP', () => {
  const source = fs.readFileSync(shared, 'utf8');
  // No imports (the page serves it alone), no DOM or Node globals, no code from strings.
  assert.doesNotMatch(source, /^\s*import\b|\bimport\s*\(|\brequire\s*\(/m);
  assert.doesNotMatch(source, /\b(?:document|window|process|Buffer|globalThis)\b/);
  assert.doesNotMatch(source, /\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(/);
  assert.match(source, /^export function formatTime\(epochMs, timezone, options = \{\}\)/m);
  assert.match(source, /^export function isSupported\(timezone\)/m);
});
