// Reference tables that use every feature of the schema DSL, so the golden DDL pins how each
// engine renders them (the registry's own tables are pinned separately, see golden.test.mjs).
import {
  table,
  id,
  text,
  bigint,
  double,
  bool,
  bytes,
  json,
} from '../../../lib/db/dialect/schema.mjs';

export const referenceTables = [
  table('ref_outbox', {
    class: 'control',
    columns: {
      id: id(),
      dedupe_key: text(128),
      channel: text(64),
      state: text(16).default('pending'),
      attempts: bigint().default(0),
      next_at: bigint(),
      payload: json(),
      secret: bytes().nullable(),
      weight: double().nullable(),
      enabled: bool().default(true),
      rule: text(64).nullable().asKey(),
    },
    unique: [{ columns: ['dedupe_key'], ignoreDuplicates: true }],
    indexes: [
      {
        name: 'ref_outbox_due',
        columns: ['state', ['next_at', 'desc']],
        where: [['state', '=', 'pending']],
      },
      {
        columns: ['channel'],
        where: [
          ['weight', 'is not null'],
          ['enabled', '=', true],
        ],
      },
    ],
  }),
  table('ref_rollup', {
    class: 'series',
    modes: ['single'],
    withoutRowid: true,
    columns: {
      series_id: bigint(),
      bucket: bigint(),
      min: double(),
      max: double(),
      sum: double(),
      count: bigint(),
      last: double().nullable(),
    },
    primaryKey: ['series_id', 'bucket'],
  }),
  table('ref_names', {
    class: 'state',
    columns: { key: text(225), user: text(64).nullable(), note: text() },
    primaryKey: { columns: ['key'], ignoreDuplicates: true },
  }),
  table('ref_head', {
    class: 'series',
    modes: ['cluster'],
    columns: {
      shard: bigint(),
      target_id: bigint(),
      slot: bigint(),
      status: bigint(),
      vals: bytes(),
    },
    primaryKey: ['shard', 'target_id', 'slot'],
    partition: { column: 'slot', interval: 'hour' },
  }),
];
