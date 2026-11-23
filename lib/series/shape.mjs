// The 1.x reading shapes, shared by lib/store.mjs and the SeriesStore v1 (lib/series/v1.mjs):
// what a stored reading, a latest row and a chart look like to callers. Pure functions only,
// so both paths give the same answers from the same rows and the equivalence tests can say so.

// Null prototype: range names come from the query string, so 'constructor' or '__proto__'
// must not look like periods.
export const periods = Object.freeze(
  Object.assign(Object.create(null), {
    '1h': 3600000,
    '6h': 21600000,
    '24h': 86400000,
    '7d': 604800000,
    '30d': 2592000000,
  })
);
// Longest expected spacing between readings: the scheduler sets the next due time after a
// poll finishes, and queueing for a concurrency slot adds more.
export const maxGapMs = (pollSeconds, timeoutSeconds) =>
  ((pollSeconds || 60) + (timeoutSeconds ?? 90)) * 3000;
// Marks a deliberate break in collection (pause, resume, reconfigure) in the readings table.
export const GAP = '__gap';
// Collector notes say which readings a cap left out of a collection. Each is
// {code, message, omitted?}: at most 8 per source, one per code, messages of 200 characters
// or less. Anything else is dropped, so a caller cannot store arbitrary text or size.
export const noteLimits = Object.freeze({ count: 8, message: 200 });
export function cleanNotes(notes) {
  const kept = [],
    codes = new Set();
  if (!Array.isArray(notes)) return kept;
  for (const note of notes) {
    if (kept.length >= noteLimits.count) break;
    if (
      !note ||
      typeof note !== 'object' ||
      typeof note.code !== 'string' ||
      !/^[a-z][a-z0-9_]{0,63}$/.test(note.code) ||
      codes.has(note.code) ||
      typeof note.message !== 'string'
    )
      continue;
    let message = note.message.trim();
    if (!message) continue;
    if (message.length > noteLimits.message)
      message = message.slice(0, noteLimits.message - 1) + '…';
    codes.add(note.code);
    kept.push(
      Number.isSafeInteger(note.omitted) && note.omitted > 0
        ? { code: note.code, message, omitted: note.omitted }
        : { code: note.code, message }
    );
  }
  return kept;
}
export function storedNotes(text) {
  try {
    return cleanNotes(JSON.parse(text));
  } catch {
    return [];
  }
}
// The most characters of a failed collection's reason that history keeps: server.mjs
// (collectionError) cuts the reason to the same length before it records it.
export const maxErrorLength = 300;
/**
 * A failed collection's reason as history stores it, whoever records it: text of at most
 * maxErrorLength characters, cut between characters (never inside a surrogate pair), with an
 * unpaired surrogate as U+FFFD (what SQLite stored for one) and without NUL. The 1.x tables have
 * no CHECK, so without this one caller could store megabytes per reading, and a reason that is
 * not a string (an Error) failed the whole record.
 */
export function storedError(error) {
  const text = String(error)
    .slice(0, maxErrorLength * 2)
    .toWellFormed()
    .replaceAll('\u0000', '');
  return text.length <= maxErrorLength ? text : Array.from(text).slice(0, maxErrorLength).join('');
}
// The note a latest row carries when its saved readings cannot be read (a damaged or edited
// history.sqlite): the source shows no readings until its next successful collection replaces
// the row, instead of failing every dashboard request.
const unreadableNote = Object.freeze({
  code: 'stored_reading_unreadable',
  message:
    'The saved readings of the last collection could not be read; the next one replaces them.',
});
/**
 * The readings saved as `text` (a JSON list of {key, …}), or null when it is not one. Only
 * entries that are objects with a string key are kept: the dashboard and the charts read those.
 */
export function storedMetrics(text) {
  let list;
  try {
    list = JSON.parse(text);
  } catch {
    return null;
  }
  if (!Array.isArray(list)) return null;
  return list.filter(m => m !== null && typeof m === 'object' && typeof m.key === 'string');
}
// A source nothing was recorded for yet.
export const emptyLatest = id => ({
  id,
  lastAttempt: null,
  lastSuccess: null,
  metrics: [],
  error: null,
  notes: [],
});
// `row` is {attempted, success, metrics, error, notes_time, notes} from latest LEFT JOIN
// latest_notes, or undefined. Notes belong to the successful collection that wrote them. A
// release without notes (1.4.2, after a rollback) records successes without touching
// latest_notes, so notes older than the last success are stale and not returned.
export function latestFromRow(id, row) {
  if (!row) return emptyLatest(id);
  const metrics = storedMetrics(row.metrics);
  const notes = row.notes !== null && row.notes_time === row.success ? storedNotes(row.notes) : [];
  return {
    id,
    lastAttempt: row.attempted,
    lastSuccess: row.success,
    metrics: metrics ?? [],
    error: row.error,
    notes: metrics ? notes : [unreadableNote, ...notes].slice(0, noteLimits.count),
  };
}
// History summaries (lib/store.mjs): one row per source and 5-minute slot, each slot starting at
// a multiple of summarySlotMs since the epoch.
export const summarySlotMs = 300000;
// Charts of at least this long are built from the summaries: their buckets are whole slots.
export const summaryMinPeriodMs = periods['7d'];
// The time window and bucket width of a chart. Unknown periods chart 24 hours.
export function historyWindow(
  period = '24h',
  now = Date.now(),
  pollSeconds = 60,
  timeoutSeconds = 90
) {
  const duration = Object.hasOwn(periods, period) ? periods[period] : periods['24h'];
  return windowFor(duration, now, pollSeconds, timeoutSeconds);
}
/**
 * The window of a chart `duration` ms long ending at `now`. Bound JSON decoding to about 300
 * representative readings, regardless of retention. From summaryMinPeriodMs (7 days) on, the
 * buckets are whole 5-minute slots: the width is the smallest multiple of summarySlotMs of at
 * least duration / 300 and `from` is rounded down to a slot boundary (at most 5 minutes earlier),
 * so every bucket holds whole summaries; such a chart has at most 299 buckets (7d: 35 min wide,
 * 30d: 145 min). Shorter charts keep `from` = now - duration and ceil(duration / 300) (301 at
 * most).
 */
export function windowFor(duration, now = Date.now(), pollSeconds = 60, timeoutSeconds = 90) {
  const gapAfter = maxGapMs(pollSeconds, timeoutSeconds);
  if (duration >= summaryMinPeriodMs)
    return {
      from: Math.floor((now - duration) / summarySlotMs) * summarySlotMs,
      to: now,
      gapAfter,
      width: Math.ceil(duration / 300 / summarySlotMs) * summarySlotMs,
    };
  return { from: now - duration, to: now, gapAfter, width: Math.max(1, Math.ceil(duration / 300)) };
}
/**
 * The summary of one source's readings in one 5-minute slot (lib/store.mjs keeps one row per
 * slot in history_summaries), from `rows`: the slot's readings as {time, ok, marker} (marker:
 * the reading is a pause marker, error '__gap'), in time order, and `previous`: the time of the
 * source's last reading before the slot, or null. Returns null for no readings, and
 * false when a reading is not one Uptime Goblin writes (a time that is not a safe integer, or ok other
 * than 0 and 1): such a source is charted from its readings instead.
 *
 * It keeps what historyFromBuckets needs of the slot for any bucket made of whole slots: the
 * successes (count), the last success, the last failure that is not a marker, the last marker,
 * the first failure or marker, the first and last reading, and the reading before the slot (the
 * silence before the slot counts when that reading is in the chart too). The silences inside
 * the slot are kept per point: sample_gap is the longest
 * silence before a reading that falls after the previous point (in time order) and at or before
 * the last success, and likewise failure_gap and marker_gap. historyFromBuckets marks a silence
 * on the first point of its bucket at or after the reading that ends it; inside a bucket made of
 * whole slots that is the first bucket point at or after the slot point that closes the
 * silence's segment, so the chart needs only whether each segment holds a silence longer than
 * its gapAfter, which varies per source and is known only when the chart is drawn.
 */
export function summarizeSlot(rows, previous = null) {
  if (!rows.length) return null;
  let successes = 0,
    sample = null,
    failure = null,
    marker = null,
    firstFailure = null;
  for (const row of rows) {
    if (!Number.isSafeInteger(row.time) || (row.ok !== 0 && row.ok !== 1)) return false;
    if (row.ok === 1) {
      successes += 1;
      sample = row.time;
      continue;
    }
    firstFailure ??= row.time;
    if (row.marker) marker = row.time;
    else failure = row.time;
  }
  // Every reading is a success, a failure or a marker, so the last one is always a point.
  const points = [sample, failure, marker].filter(time => time !== null).sort((a, b) => a - b),
    longest = new Map();
  for (let i = 1; i < rows.length; i += 1) {
    const time = rows[i].time,
      silence = time - rows[i - 1].time,
      end = points.find(point => point >= time);
    if (silence > (longest.get(end) ?? 0)) longest.set(end, silence);
  }
  const gapAt = point => (point === null ? null : (longest.get(point) ?? null));
  return {
    successes,
    first_time: rows[0].time,
    last_time: rows.at(-1).time,
    previous_time: previous,
    sample_time: sample,
    failure_time: failure,
    marker_time: marker,
    first_failure_time: firstFailure,
    sample_gap: gapAt(sample),
    failure_gap: gapAt(failure),
    marker_gap: gapAt(marker),
  };
}
// Builds a chart from the bucket rows of the history query: per bucket {sample_time,
// failure_time, marker_time, first_failure_time, count, gaps, metrics, failure_error}. Each
// bucket keeps its last successful sample, its last failure and its last pause marker
// separately, so a pause cannot hide why collection failed just before it (or the reverse).
// `gaps` lists readings that follow a silence longer than gapAfter. `options.metrics` (a list
// of measurement keys) keeps only those readings in each point, so a chart of one measurement
// does not download every other one. Without it, or with an empty list, every reading is
// returned; keys the source never reported match nothing.
export function historyFromBuckets(rows, window, options) {
  const keys = options?.metrics,
    wanted = Array.isArray(keys) && keys.length ? new Set(keys) : null,
    // A reading that cannot be read (a damaged row) charts as a sample without readings,
    // rather than failing every chart window that holds it.
    readings = text => {
      const all = storedMetrics(text) ?? [];
      return wanted ? all.filter(m => wanted.has(m.key)) : all;
    };
  const points = [];
  for (const row of rows) {
    const bucket = [];
    if (row.sample_time !== null)
      bucket.push({
        time: row.sample_time,
        ok: true,
        // A failure hidden by downsampling must still break the line before this sample.
        gapBefore: row.first_failure_time !== null && row.first_failure_time < row.sample_time,
        metrics: readings(row.metrics),
      });
    if (row.failure_time !== null)
      bucket.push({
        time: row.failure_time,
        ok: false,
        gapBefore: false,
        metrics: [],
        error: row.failure_error ?? null,
      });
    // Pause, resume and reconfigure markers are gaps, not failed collections.
    if (row.marker_time !== null)
      bucket.push({
        time: row.marker_time,
        ok: false,
        gapBefore: false,
        metrics: [],
        gap: true,
        error: null,
      });
    bucket.sort((a, b) => a.time - b.time);
    // A silence belongs to the first point after it, whether that point succeeded or not.
    // The bucket's last reading is always one of its points, so every silence lands.
    for (const time of row.gaps?.split(',') ?? [])
      bucket.find(p => p.time >= Number(time)).gapBefore = true;
    points.push(...bucket);
  }
  points.sort((a, b) => a.time - b.time);
  return {
    from: window.from,
    to: window.to,
    totalSamples: rows.reduce((n, r) => n + r.count, 0),
    maxGapMs: window.gapAfter,
    points,
    aggregation:
      'Last successful sample, last failure and last pause marker per time bucket; collection gaps preserved',
  };
}
