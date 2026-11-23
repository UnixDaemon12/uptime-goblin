// Sizes the outbox accepts (design §3.3), shared by the outbox (which validates entries) and the
// table declarations in lib/alerting/tables.mjs (whose key sizes depend on them).
export const OUTBOX_LIMITS = Object.freeze({
  eventUid: 128,
  channelId: 40,
  target: 254,
  orderKey: 300,
  kind: 40,
});

/** The most an event snapshot may take, as JSON in UTF-8 bytes. */
export const SNAPSHOT_LIMIT = 4096;
