// The legacy notification rules (lib/alerting/policy.mjs) against 1.4.2's notify(), which is
// copied below as the oracle, over random events and settings.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  legacyAllows,
  legacyChannels,
  legacySnapshot,
  legacyOrderKey,
  legacySeverity,
  legacyEntries,
  SNAPSHOT_BYTES,
} from '../../lib/alerting/policy.mjs';
import { legacyWebhookBody } from '../../lib/notify/channels/webhook.mjs';
import { createOutbox, SNAPSHOT_LIMIT } from '../../lib/notify/outbox.mjs';
import { createMemoryOutboxStore } from '../../lib/notify/memory-store.mjs';
import { alertDefaults } from '../../lib/catalog.mjs';
import { fakeClock, quietLogger } from './fake-clock.mjs';

// 1.4.2 server.mjs:160-172 (git show v1.4.2:server.mjs), with `config` passed in. It posted to
// the webhook when GOBLIN_WEBHOOK_URL was set, and queued email, which EmailNotifier sent only
// while email was switched on.
function notify142(event, { alerts, sourceAlerts, webhookConfigured, emailEnabled }) {
  const config = {
    value: { alerts },
    get: () => (sourceAlerts ? { alerts: sourceAlerts } : undefined),
  };
  const settings = config.value.alerts,
    category = event.category === 'availability' ? 'notifyAvailability' : 'notifyMeasurements';
  if (
    !settings.enabled ||
    (event.kind === 'firing' && !settings.notifyOnAlert) ||
    (event.kind === 'resolved' && !settings.notifyOnRecovery) ||
    (event.category !== 'system' &&
      (config.get(event.service)?.alerts?.[category] ?? settings[category]) === false)
  )
    return [];
  return [...(webhookConfigured ? ['env-webhook'] : []), ...(emailEnabled ? ['email'] : [])];
}

// A small seeded generator, so a failure can be reproduced.
function random(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let x = state;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
  const pick = list => list[Math.floor(next() * list.length)];
  return { next, pick, bool: () => next() < 0.5 };
}

test('the relay selects exactly what 1.4.2 notify() sent, for random events and settings', () => {
  const r = random(20260929);
  const maybeBool = () => r.pick([true, false, undefined]);
  for (let i = 0; i < 5000; i++) {
    const alerts = {
      ...alertDefaults(),
      enabled: r.bool(),
      notifyOnAlert: r.bool(),
      notifyOnRecovery: r.bool(),
      notifyAvailability: r.bool(),
      notifyMeasurements: r.bool(),
    };
    const sourceAlerts = r.pick([
      undefined,
      {},
      { notifyAvailability: maybeBool(), notifyMeasurements: maybeBool() },
    ]);
    const event = {
      service: r.pick(['plex', 'nas', 'orbit']),
      name: 'Source',
      kind: r.pick(['firing', 'resolved', 'reminder', 'acknowledged']),
      category: r.pick(['availability', 'measurement', 'system', undefined]),
      rule: r.pick(['__availability', 'cpu', '__storage']),
      message: 'Message',
      time: 1_800_000_000_000 + i,
    };
    const switches = { webhookConfigured: r.bool(), emailEnabled: r.bool() };
    const expected = notify142(event, { alerts, sourceAlerts, ...switches });
    const entries = legacyEntries(event, {
      eventUid: `ev-${i}`,
      settings: alerts,
      sourceAlerts,
      ...switches,
    });
    assert.deepEqual(
      entries.map(entry => entry.channelId),
      expected,
      JSON.stringify({ i, alerts, sourceAlerts, event, switches })
    );
    // The prefilter alone: 1.4.2 would have posted to a configured webhook.
    assert.equal(
      legacyAllows(alerts, sourceAlerts, event),
      notify142(event, { alerts, sourceAlerts, webhookConfigured: true }).length === 1
    );
  }
  assert.deepEqual(legacyChannels(), []);
  assert.deepEqual(legacyChannels({ webhookConfigured: true, emailEnabled: true }), [
    'env-webhook',
    'email',
  ]);
});

test('the snapshot keeps 1.4.2 fields in 1.4.2 order, so the webhook body is unchanged', () => {
  const event142 = {
    service: 'plex',
    name: 'Plex',
    kind: 'firing',
    category: 'availability',
    rule: '__availability',
    message: 'Source is unavailable: connect ECONNREFUSED',
    time: 1_800_000_000_000,
  };
  // 1.5 events carry more (since, uid, relayed); the body a receiver gets does not change.
  const event15 = { uid: 'ev-1', since: 1_799_999_000_000, ...event142, relayed: 0 };
  const snapshot = legacySnapshot(event15);
  assert.deepEqual(Object.keys(snapshot), [
    'service',
    'name',
    'kind',
    'category',
    'rule',
    'message',
    'time',
  ]);
  assert.equal(legacyWebhookBody(snapshot), JSON.stringify({ source: 'orbit', ...event142 }));
  // Fields 1.4.2 did not send are left out rather than sent as null.
  assert.deepEqual(legacySnapshot({ service: 'orbit', kind: 'firing' }), {
    service: 'orbit',
    kind: 'firing',
  });
});

test('a snapshot always fits the outbox limit of 4 KiB of JSON', () => {
  assert.equal(SNAPSHOT_BYTES, SNAPSHOT_LIMIT);
  const huge = {
    service: 's'.repeat(500),
    name: '名'.repeat(500),
    kind: 'firing',
    category: 'measurement',
    rule: 'r'.repeat(500),
    message: '💥"\n'.repeat(3000),
    time: 1,
  };
  const snapshot = legacySnapshot(huge);
  assert.ok(Buffer.byteLength(JSON.stringify(snapshot)) <= SNAPSHOT_LIMIT);
  assert.equal([...snapshot.name].length, 200);
  assert.equal(snapshot.service.length, 200);
  assert.ok(snapshot.message.startsWith('💥"\n'));
  // Never a broken character.
  assert.ok(!/[\uD800-\uDFFF]/.test(snapshot.message.replace(/💥/gu, '')));
  // Ordinary messages are kept whole.
  const ordinary = legacySnapshot({
    ...huge,
    name: 'Plex',
    service: 'plex',
    rule: 'cpu',
    message: 'CPU is 97 %',
  });
  assert.equal(ordinary.message, 'CPU is 97 %');
});

test('legacyEntries: one entry per built-in channel, ready for the outbox', async () => {
  const event = {
    service: 'plex',
    name: 'Plex',
    kind: 'resolved',
    category: 'measurement',
    rule: 'cpu',
    message: 'CPU is back to normal',
    time: 1_800_000_000_000,
  };
  const options = {
    eventUid: 'ev-42',
    settings: { ...alertDefaults(), enabled: true },
    webhookConfigured: true,
    emailEnabled: true,
  };
  const entries = legacyEntries(event, options);
  assert.deepEqual(entries, [
    {
      eventUid: 'ev-42',
      channelId: 'env-webhook',
      kind: 'resolved',
      severity: 'warning',
      orderKey: 'plex\ncpu',
      event: legacySnapshot(event),
      createdAt: event.time,
    },
    {
      eventUid: 'ev-42',
      channelId: 'email',
      kind: 'resolved',
      severity: 'warning',
      orderKey: 'plex\ncpu',
      event: legacySnapshot(event),
      createdAt: event.time,
    },
  ]);
  assert.equal(legacyOrderKey(event), 'plex\ncpu');
  assert.equal(legacySeverity({ category: 'availability' }), 'critical');
  assert.equal(legacySeverity({ category: 'system' }), 'critical');
  assert.equal(legacySeverity({ category: 'agent' }), 'critical');
  assert.equal(legacySeverity({ category: 'measurement' }), 'warning');
  assert.throws(() => legacyEntries(event, { ...options, eventUid: '' }), TypeError);
  assert.deepEqual(
    legacyEntries(event, { ...options, settings: { ...options.settings, enabled: false } }),
    []
  );

  // The outbox accepts them as they are; relaying the same event twice writes nothing new.
  const clock = fakeClock({ wallStart: event.time });
  const outbox = createOutbox({
    store: createMemoryOutboxStore(),
    clock,
    logger: quietLogger(),
    channels: [
      { name: 'env-webhook', send: async () => ({ type: 'accepted' }) },
      { name: 'email', digest: { windowMs: 60000 }, send: async () => ({ type: 'accepted' }) },
    ],
  });
  assert.equal((await outbox.enqueue(entries)).inserted, 2);
  assert.equal((await outbox.enqueue(legacyEntries(event, options))).duplicates, 2);
  await outbox.stop({ timeoutMs: 0 });
});
