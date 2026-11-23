// The control-database tables of durable delivery (roadmap #15; design §3.2, amended), declared
// in the portable schema DSL for lane P to append to the table registry and the control steps.
// They hold what lib/notify/outbox.mjs's OutboxStore reads and writes, column for column:
//
//   registry.mjs:  ...alertingTableSpecs.map(([name, options]) => defineTable(name, options))
//   control.mjs:   defineSteps([...platformSteps, ...alertingSteps])
//
// Plain specifications rather than defineTable() entries, so lib/db/registry.mjs can import this
// module without an import cycle. Deviations from design §3.2, all deliberate:
// - the event snapshot is a column of the row (`event`, at most 4 KiB), because the relay and
//   alerting_events arrive with #14; a row renders from it at send time;
// - `uid` (a hash of event, channel and target) is the unique key; it implies the design's
//   UNIQUE (event_uid, channel_id, target) and keeps the index within SQL Server's key size;
// - `order_key` (service and rule) orders rows instead of `incident_id`, which #14 adds;
// - `unknowns`, `dead_reason` and `external_ref` record the delivery engine's outcomes.
import { id, text, bigint, json } from '../db/dialect/schema.mjs';
import { OUTBOX_LIMITS } from '../notify/limits.mjs';

const alerting = {
  component: 'alerting',
  lane: 'A',
  since: '1.5.0',
  class: 'control',
  db: 'control',
};

export const alertingTableSpecs = Object.freeze([
  [
    'alerting_outbox',
    {
      ...alerting,
      description:
        'Notifications waiting for, in, or after delivery (lib/notify/outbox.mjs). Restoring a backup must not send old alerts again.',
      backup: 'never',
      retention: 'outbox.prune',
      columns: {
        id: id(),
        uid: text(64),
        event_uid: text(OUTBOX_LIMITS.eventUid),
        channel_id: text(OUTBOX_LIMITS.channelId),
        target: text(OUTBOX_LIMITS.target).default(''),
        kind: text(OUTBOX_LIMITS.kind),
        severity: text(16).nullable(),
        order_key: text(OUTBOX_LIMITS.orderKey).nullable(),
        event: json(),
        state: text(16),
        attempts: bigint().default(0),
        unknowns: bigint().default(0),
        next_at: bigint(),
        created_at: bigint(),
        expires_at: bigint(),
        digest_key: text(64).nullable(),
        lease_owner: text(64).nullable(),
        lease_until: bigint().nullable(),
        epoch: bigint().default(0),
        sent_at: bigint().nullable(),
        last_status: bigint().nullable(),
        last_error: text(300).nullable(),
        dead_reason: text(16).nullable(),
        external_ref: text(200).nullable(),
        updated_at: bigint(),
      },
      unique: [{ name: 'alerting_outbox_uid', columns: ['uid'] }],
      indexes: [
        { name: 'alerting_outbox_due', columns: ['state', 'next_at'] },
        { name: 'alerting_outbox_order', columns: ['channel_id', 'order_key', 'id'] },
        { name: 'alerting_outbox_finished', columns: ['state', 'updated_at'] },
      ],
    },
  ],
  [
    'alerting_channel_status',
    {
      ...alerting,
      description:
        "Each delivery channel's health: paused, retrying or circuit-open, and its counters.",
      backup: 'never',
      columns: {
        channel_id: text(OUTBOX_LIMITS.channelId),
        state: text(16).default('ok'),
        paused_reason: text(300).nullable(),
        next_send_at: bigint().default(0),
        consecutive_failures: bigint().default(0),
        failed_total: bigint().default(0),
        delivered_total: bigint().default(0),
        last_attempt: bigint().nullable(),
        last_success: bigint().nullable(),
        last_failure: bigint().nullable(),
        last_error: json().nullable(),
        // When the current pause began, kept through probes (the pause notice's uid names it).
        paused_since: bigint().nullable(),
        // Outcomes in a row that the endpoint refused (`failed`): three mean "refusing".
        consecutive_refusals: bigint().default(0),
        updated_at: bigint(),
      },
      primaryKey: ['channel_id'],
    },
  ],
]);

/** The control-database step that creates them (expand: a 1.4.x or 1.5.x rollback ignores it). */
export const alertingSteps = Object.freeze([
  {
    id: 'alerting-001-outbox',
    component: 'alerting',
    kind: 'expand',
    db: 'control',
    after: ['platform-001-control-tables'],
    description: 'Durable delivery: the outbox and channel health.',
    up: { createTables: ['alerting_outbox', 'alerting_channel_status'] },
  },
]);

/** The OutboxStore row field for each alerting_outbox column (the adapter's mapping). */
export const OUTBOX_COLUMNS = Object.freeze({
  id: 'id',
  uid: 'uid',
  event_uid: 'eventUid',
  channel_id: 'channelId',
  target: 'target',
  kind: 'kind',
  severity: 'severity',
  order_key: 'orderKey',
  event: 'event',
  state: 'state',
  attempts: 'attempts',
  unknowns: 'unknowns',
  next_at: 'nextAt',
  created_at: 'createdAt',
  expires_at: 'expiresAt',
  digest_key: 'digestKey',
  lease_owner: 'leaseOwner',
  lease_until: 'leaseUntil',
  epoch: 'epoch',
  sent_at: 'sentAt',
  last_status: 'lastStatus',
  last_error: 'lastError',
  dead_reason: 'deadReason',
  external_ref: 'externalRef',
  updated_at: 'updatedAt',
});

/** The channel status field for each alerting_channel_status column. */
export const CHANNEL_STATUS_COLUMNS = Object.freeze({
  state: 'state',
  paused_reason: 'pausedReason',
  next_send_at: 'nextSendAt',
  consecutive_failures: 'consecutiveFailures',
  failed_total: 'failedTotal',
  delivered_total: 'deliveredTotal',
  last_attempt: 'lastAttempt',
  last_success: 'lastSuccess',
  last_failure: 'lastFailure',
  last_error: 'lastError',
  paused_since: 'pausedSince',
  consecutive_refusals: 'consecutiveRefusals',
});
