// The legacy notification rules (1.4.2's notify() in server.mjs), as pure functions so the
// outbox can be fed exactly what 1.4.2 would have sent (roadmap #15; design §2.8 step 1).
// Evaluation is unchanged; these only decide which built-in channels get a row.
import { SNAPSHOT_LIMIT } from '../notify/limits.mjs';

/**
 * 1.4.2's switches, moved verbatim: may this event notify at all?
 * `settings` is config.value.alerts; `sourceAlerts` is the source's own overrides
 * (config.get(event.service)?.alerts), or undefined.
 */
export function legacyAllows(settings, sourceAlerts, event) {
  const category = event.category === 'availability' ? 'notifyAvailability' : 'notifyMeasurements';
  return !(
    !settings.enabled ||
    (event.kind === 'firing' && !settings.notifyOnAlert) ||
    (event.kind === 'resolved' && !settings.notifyOnRecovery) ||
    // Uptime Goblin's own health (category 'system') is not muted by per-source categories.
    (event.category !== 'system' && (sourceAlerts?.[category] ?? settings[category]) === false)
  );
}

/**
 * The built-in channels an allowed event goes to, as in 1.4.2: the environment webhook when
 * GOBLIN_WEBHOOK_URL is set, and email when it is switched on (the email channel checks again
 * when it sends, since settings can change while a row waits); then `push`, the ntfy and Gotify
 * channels that are set up and switched on (each checks again when it sends, too).
 */
export function legacyChannels({
  webhookConfigured = false,
  emailEnabled = false,
  push = [],
} = {}) {
  return [
    ...(webhookConfigured ? ['env-webhook'] : []),
    ...(emailEnabled ? ['email'] : []),
    ...['ntfy', 'gotify'].filter(id => push.includes(id)),
  ];
}

/** The most an event snapshot may take, as JSON in UTF-8 (the outbox's limit). */
export const SNAPSHOT_BYTES = SNAPSHOT_LIMIT;

// Cuts `text` to at most `bytes` bytes of UTF-8 without splitting a character.
function cutUtf8(text, bytes) {
  if (Buffer.byteLength(text) <= bytes) return text;
  let out = '',
    used = 0;
  for (const character of text) {
    const size = Buffer.byteLength(character);
    if (used + size > bytes) break;
    out += character;
    used += size;
  }
  return out;
}

/**
 * The snapshot a built-in channel renders: 1.4.2's event fields only, in 1.4.2's order, so the
 * webhook body stays byte-for-byte what 1.4.2 sent. Text is capped (message 2,000 characters,
 * name 200, service and rule 200) and the message is shortened further if the whole snapshot
 * would pass 4 KiB of JSON, so an unusual event can never be refused by the outbox.
 */
export function legacySnapshot(event) {
  const snapshot = {};
  for (const field of ['service', 'name', 'kind', 'category', 'rule', 'message', 'time'])
    if (event[field] !== undefined) snapshot[field] = event[field];
  for (const [field, max] of [
    ['service', 200],
    ['name', 200],
    ['rule', 200],
    ['message', 2000],
  ])
    if (typeof snapshot[field] === 'string')
      snapshot[field] = [...snapshot[field]].slice(0, max).join('');
  // Each character takes at least as many bytes in JSON as in UTF-8, so cutting the message by
  // the excess (in UTF-8 bytes) always brings the JSON within the limit.
  const over = Buffer.byteLength(JSON.stringify(snapshot)) - SNAPSHOT_BYTES;
  if (over > 0 && typeof snapshot.message === 'string')
    snapshot.message = cutUtf8(
      snapshot.message,
      Math.max(0, Buffer.byteLength(snapshot.message) - over)
    );
  return snapshot;
}

/** Rows for one alert keep their order per (service, rule): a recovery never overtakes. */
export const legacyOrderKey = event => `${event.service ?? ''}\n${event.rule ?? ''}`;

/** Severity by category (design §2.6): availability, system and agent are critical. */
export const legacySeverity = event =>
  event.category === 'measurement' ? 'warning' : event.category ? 'critical' : 'warning';

/**
 * The outbox entries for one event under 1.5's default routing, which equals 1.4.2's notify():
 * nothing when legacyAllows() says no, otherwise one entry per built-in channel. `eventUid` is
 * the event's stable id (events.uid in 1.5), so relaying the same event again writes nothing.
 * `settings`, `sourceAlerts`, `webhookConfigured`, `emailEnabled` and `push` are as above, read
 * when the event is relayed.
 */
export function legacyEntries(
  event,
  { eventUid, settings, sourceAlerts, webhookConfigured = false, emailEnabled = false, push = [] }
) {
  if (typeof eventUid !== 'string' || !eventUid)
    throw new TypeError('legacyEntries needs an eventUid');
  if (!legacyAllows(settings, sourceAlerts, event)) return [];
  const snapshot = legacySnapshot(event),
    orderKey = legacyOrderKey(event),
    severity = legacySeverity(event);
  return legacyChannels({ webhookConfigured, emailEnabled, push }).map(channelId => ({
    eventUid,
    channelId,
    kind: event.kind,
    severity,
    orderKey,
    event: snapshot,
    ...(Number.isFinite(event.time) ? { createdAt: event.time } : {}),
  }));
}
