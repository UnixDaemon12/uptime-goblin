// The table registry (roadmap §2.1 "Table registry", amended by §10.5): one entry per table,
// with one owner. Everything that needs to know the tables reads it from here:
// - identifiers: dialect.render(query, {identifiers: registry.identifiers}) refuses any id()
//   that no table, column or index here declares (§10.4 "Identifiers are quoted from the
//   registry");
// - the schema: new tables are declared with the portable schema DSL (./dialect/schema.mjs),
//   whose renderTable(dialect, table) writes the DDL of each engine (golden files gate CI);
// - placement: `class` (control | state | series) and `db` (control | history in SQLite mode,
//   `*` for every database) decide where a table lives; `modes` whether it exists in
//   single-node and cluster mode;
// - backups and transfers: `backup` (always | never | history:rollups | history:all) and the
//   `transfer` order generate the allowlists of backup, restore, migrate-to-postgres and
//   export-sqlite.
//
// The 1.x tables of history.sqlite (readings, latest, alerts, events, latest_notes) are
// registered as `legacy`: they stay hand-written in lib/store.mjs, outside the DSL, and are
// never altered (invariant 1). They are listed so their names can be quoted and classified.
// 1.5's history_summaries and history_summary_marks are registered the same way: lib/store.mjs
// creates them with sql`…`.
//
// A registry entry is the DSL table (name, class, modes, columns, primaryKey, unique, indexes,
// withoutRowid, partition) plus: component, lane, db, backup, transfer, retention, sealed,
// since, description, shared and legacy. Components add tables with one appended entry; only
// lane P edits this file.
import {
  table as dslTable,
  id,
  text,
  bigint,
  bool,
  json,
  CLASSES,
  MODES,
} from './dialect/schema.mjs';
import { alertingTableSpecs } from '../alerting/tables.mjs';

export { CLASSES as storeClasses, MODES as modes };
/** Databases in SQLite mode. */
export const databases = Object.freeze(['control', 'history']);
export const backupKinds = Object.freeze(['always', 'never', 'history:rollups', 'history:all']);
const lanes = /^[PIASOD]$/;
const namePattern = /^[a-z_][a-z0-9_]{0,62}$/;

export class RegistryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RegistryError';
  }
}

// Entries registryEntry() produced, so createRegistry() does not validate them twice.
const entries = new WeakSet();

function checkMetadata(name, meta, dsl) {
  const problems = [];
  const { component, lane, db, backup, transfer = null, since, shared = [], sealed = [] } = meta;
  if (!component || !namePattern.test(component)) problems.push('component is required');
  if (!lanes.test(lane ?? '')) problems.push('lane must be one of P, I, A, S, O, D');
  if (db !== '*' && !databases.includes(db))
    problems.push(`db must be ${databases.join('|')} or *`);
  if (!backupKinds.includes(backup)) problems.push(`backup must be ${backupKinds.join('|')}`);
  if (transfer !== null && !Number.isInteger(transfer))
    problems.push('transfer must be an integer');
  if (!/^\d+\.\d+\.\d+$/.test(since ?? '')) problems.push('since must name a release (x.y.z)');
  if (!Array.isArray(shared) || shared.some(c => !CLASSES.includes(c) || c === dsl.class))
    problems.push('shared lists the other store classes that may read the table');
  for (const column of sealed)
    if (!Object.hasOwn(dsl.columns, column))
      problems.push(`sealed column ${column} is not a column`);
  if (problems.length) throw new RegistryError(`Table ${name}: ${problems.join('; ')}`);
}

function entry(dsl, meta) {
  checkMetadata(dsl.name, meta, dsl);
  const value = Object.freeze({
    ...dsl,
    component: meta.component,
    lane: meta.lane,
    db: meta.db,
    backup: meta.backup,
    transfer: meta.transfer ?? null,
    retention: meta.retention ?? null,
    sealed: Object.freeze([...(meta.sealed ?? [])]),
    shared: Object.freeze([...(meta.shared ?? [])]),
    since: meta.since,
    description: meta.description ?? '',
    legacy: meta.legacy === true,
  });
  entries.add(value);
  return value;
}

/**
 * A table declared in the DSL: `options` are the DSL's (class, modes, columns, primaryKey,
 * unique, indexes, withoutRowid, partition) plus the registry metadata above.
 */
export function defineTable(name, options) {
  const {
    component,
    lane,
    db,
    backup,
    transfer,
    retention,
    sealed,
    shared,
    since,
    description,
    ...dsl
  } = options;
  return entry(dslTable(name, dsl), {
    component,
    lane,
    db,
    backup,
    transfer,
    retention,
    sealed,
    shared,
    since,
    description,
  });
}

/**
 * A hand-written 1.x table outside the DSL (never rendered, never altered). `columns` are
 * names with a descriptive type; `indexes` are the names lib/store.mjs creates, with the
 * columns they cover and, for a partial index, `where` in the DSL's form
 * ([[column, '=' | '<>' | 'is null' | 'is not null', value?]]).
 */
export function defineLegacyTable(name, options) {
  const { columns, primaryKey, indexes = [], class: storeClass, ...meta } = options;
  if (!namePattern.test(name)) throw new RegistryError(`invalid table name ${name}`);
  if (!CLASSES.includes(storeClass)) throw new RegistryError(`Table ${name}: unknown class`);
  const described = {};
  for (const [column, type] of Object.entries(columns)) {
    if (!namePattern.test(column))
      throw new RegistryError(`Table ${name}: invalid column ${column}`);
    described[column] = Object.freeze({ type, legacy: true });
  }
  for (const column of primaryKey)
    if (!described[column])
      throw new RegistryError(`Table ${name}: key column ${column} is unknown`);
  const dsl = {
    name,
    class: storeClass,
    modes: Object.freeze(['single']),
    columns: Object.freeze(described),
    primaryKey: Object.freeze({
      columns: Object.freeze(primaryKey.map(column => Object.freeze({ column, desc: false }))),
      ignoreDuplicates: false,
    }),
    unique: Object.freeze([]),
    indexes: Object.freeze(
      indexes.map(index => {
        if (!namePattern.test(index.name ?? ''))
          throw new RegistryError(`Table ${name}: invalid index name ${index.name}`);
        for (const column of index.columns)
          if (!described[column])
            throw new RegistryError(`Table ${name}: index ${index.name} names unknown ${column}`);
        const where = (index.where ?? []).map(([column, op, value]) => {
          if (!described[column])
            throw new RegistryError(`Table ${name}: index ${index.name} filters unknown ${column}`);
          if (!legacyWhereOps.includes(op))
            throw new RegistryError(`Table ${name}: index ${index.name} operator ${op}`);
          return Object.freeze({ column, op, value });
        });
        return Object.freeze({
          name: index.name,
          columns: Object.freeze(
            index.columns.map(column => Object.freeze({ column, desc: false }))
          ),
          where: Object.freeze(where),
        });
      })
    ),
    withoutRowid: false,
    partition: null,
  };
  return entry(dsl, { ...meta, legacy: true });
}

const legacyWhereOps = Object.freeze(['=', '<>', 'is null', 'is not null']);

const indexNamesOf = table => [
  `${table.name}_pkey`,
  ...table.unique.map(index => index.name),
  ...table.indexes.map(index => index.name),
];

/**
 * A registry over `tables` (entries from defineTable / defineLegacyTable): lookups, the
 * identifier allowlist and the generated lists. A table or index name claimed twice, by one
 * component or two, is refused.
 */
export function createRegistry(tables) {
  const byName = new Map(),
    indexOwner = new Map();
  for (const table of tables) {
    if (!entries.has(table))
      throw new RegistryError(`${table?.name} was not made by defineTable()`);
    if (byName.has(table.name))
      throw new RegistryError(
        `Table ${table.name} is claimed by ${byName.get(table.name).component} and ${table.component}`
      );
    byName.set(table.name, table);
  }
  for (const table of tables)
    for (const index of indexNamesOf(table)) {
      if (indexOwner.has(index) || byName.has(index))
        throw new RegistryError(`The index name ${index} (${table.name}) is used twice`);
      indexOwner.set(index, table.name);
    }
  const names = new Set();
  for (const table of tables) {
    names.add(table.name);
    for (const column of Object.keys(table.columns)) names.add(column);
    for (const index of indexNamesOf(table)) names.add(index);
  }
  const columnLists = new Map(
    tables.map(table => [table.name, Object.freeze(Object.keys(table.columns))])
  );
  // The allowlist is a read-only view: Object.freeze() does not stop a Set's add() or delete(),
  // so a Set handed out here could be extended by any module that holds the registry.
  // columnsOf(table) lets the statement builders refuse a column of another table.
  const identifiers = Object.freeze({
    has: name => names.has(name),
    get size() {
      return names.size;
    },
    [Symbol.iterator]: () => names.values(),
    columnsOf: table => columnLists.get(table) ?? null,
  });
  const inDatabase = (table, db) => table.db === '*' || table.db === db;
  const registry = {
    tables: Object.freeze([...tables]),
    /** Tables the DSL renders (golden DDL, migrations); legacy tables are left out. */
    dslTables: Object.freeze(tables.filter(table => !table.legacy)),
    /** Every table, column and index name: pass to dialect.render(q, {identifiers}). */
    identifiers: Object.freeze(identifiers),
    has: name => byName.has(name),
    table(name) {
      const table = byName.get(name);
      if (!table) throw new RegistryError(`${name} is not a registered table`);
      return table;
    },
    /** Tables that exist in `db` (control | history) in SQLite mode. */
    forDatabase: db =>
      tables.filter(table => inDatabase(table, db) && table.modes.includes('single')),
    forClass: storeClass => tables.filter(table => table.class === storeClass),
    forComponent: component => tables.filter(table => table.component === component),
    forMode: mode => tables.filter(table => table.modes.includes(mode)),
    /** The store class of a table name, or null (import-graph and repository checks). */
    classOf: name => byName.get(name)?.class ?? null,
    /**
     * Tables a backup of `db` carries at a history level (none | rollups | all): every
     * `always` table, plus history tables up to that level. `never` tables never travel.
     */
    backupAllowlist(db, history = 'none') {
      const levels = {
        none: [],
        rollups: ['history:rollups'],
        all: ['history:rollups', 'history:all'],
      };
      if (!levels[history]) throw new RegistryError(`Unknown history level ${history}`);
      return tables
        .filter(table => inDatabase(table, db))
        .filter(table => table.backup === 'always' || levels[history].includes(table.backup))
        .map(table => table.name);
    },
    /** Tables in transfer order (lowest first); tables without an order are not transferred. */
    transferOrder: db =>
      tables
        .filter(table => table.transfer !== null && (!db || inDatabase(table, db)))
        .sort((a, b) => a.transfer - b.transfer || (a.name < b.name ? -1 : 1))
        .map(table => table.name),
    /**
     * Compares the tables present in a SQLite database with the registry: `unregistered` are
     * present but unknown (sqlite_* internals are ignored), `missing` are registered DSL tables
     * of that database that are absent.
     */
    drift(db, present) {
      const names = new Set([...present].filter(name => !name.startsWith('sqlite_')));
      return {
        unregistered: [...names].filter(name => !byName.has(name)).sort(),
        missing: registry
          .forDatabase(db)
          .filter(table => !table.legacy && !names.has(table.name))
          .map(table => table.name)
          .sort(),
      };
    },
  };
  return Object.freeze(registry);
}

// ---------------------------------------------------------------------------------------------
// Platform (lane P): control.sqlite, 1.5.0.

const platform = { component: 'platform', lane: 'P', since: '1.5.0', class: 'control' };

export const platformTables = Object.freeze([
  defineTable('schema_migrations', {
    ...platform,
    description:
      'Applied migration steps of this database (a set, so merge order does not matter).',
    db: '*',
    backup: 'always',
    transfer: 0,
    columns: {
      id: text(128),
      component: text(64),
      kind: text(16),
      release: text(32),
      applied_at: bigint(),
    },
    primaryKey: ['id'],
  }),
  defineTable('schema_fences', {
    ...platform,
    description: 'Minimum releases that may open this data, raised when a feature is first used.',
    db: 'control',
    backup: 'always',
    transfer: 1,
    columns: {
      name: text(128),
      min_release: text(32),
      reason: text(500),
      set_at: bigint(),
    },
    primaryKey: ['name'],
  }),
  defineTable('meta', {
    ...platform,
    description:
      'instance_id, created_by_release, last_version, upgrade_history, credentials_ever, session_seq and config_revision_seen; the audit writer keys audit_config_public, audit_config_secrets, audit_release_marker, audit_snapshot_seen, audit_restore_seen, audit_password_changed_at and audit_security_seen.',
    db: 'control',
    backup: 'always',
    transfer: 2,
    columns: {
      key: text(64),
      value: text(),
      updated_at: bigint(),
    },
    primaryKey: ['key'],
  }),
  defineTable('keyring', {
    ...platform,
    description: 'Data keys, each wrapped by the master key; retired keys still open old values.',
    db: 'control',
    backup: 'always',
    transfer: 3,
    columns: {
      kid: text(32),
      purpose: text(32),
      wrapped: text(512),
      created_at: bigint(),
      retired_at: bigint().nullable(),
    },
    primaryKey: ['kid'],
  }),
  defineTable('settings', {
    ...platform,
    description: 'Settings documents of new features, versioned for compare-and-swap.',
    db: 'control',
    backup: 'always',
    transfer: 4,
    columns: {
      component: text(64),
      key: text(128),
      schema: bigint(),
      value: json(),
      version: bigint(),
      updated_at: bigint(),
      updated_by: text(128).nullable(),
    },
    primaryKey: ['component', 'key'],
  }),
  defineTable('jobs', {
    ...platform,
    description: "Background job status, written by lib/jobs.mjs's statusSink.",
    db: 'control',
    backup: 'never',
    columns: {
      name: text(128),
      last_started: bigint().nullable(),
      last_finished: bigint().nullable(),
      last_ok: bigint().nullable(),
      last_error: text(500).nullable(),
      runs: bigint(),
      failures: bigint(),
      duration_ms: bigint().nullable(),
      updated_at: bigint(),
    },
    primaryKey: ['name'],
  }),
  defineTable('idempotency_keys', {
    ...platform,
    description:
      'Idempotency-Key records, scoped by principal and bound to the route and body hash (lib/http/idempotency.mjs).',
    db: 'control',
    backup: 'never',
    retention: 'idempotency.prune',
    columns: {
      principal: text(64),
      key: text(128),
      route: text(256),
      body_sha256: text(64),
      state: text(16),
      status: bigint().nullable(),
      response: json().nullable(),
      created_at: bigint(),
      expires_at: bigint(),
    },
    primaryKey: ['principal', 'key'],
    indexes: [{ name: 'idempotency_keys_expiry', columns: ['expires_at'] }],
  }),
]);

// ---------------------------------------------------------------------------------------------
// Identity (lane I): control.sqlite, 1.5.0. Only the built-in admin in 1.5.

const identity = {
  component: 'identity',
  lane: 'I',
  since: '1.5.0',
  class: 'control',
  db: 'control',
};

export const identityTables = Object.freeze([
  defineTable('users', {
    ...identity,
    description: 'People who sign in. In 1.5 the only row is the built-in admin, u_admin.',
    backup: 'always',
    transfer: 10,
    columns: {
      id: text(64),
      login: text(64),
      display_name: text(200),
      role: text(16),
      kind: text(16),
      password: json().nullable(),
      password_changed_at: bigint().nullable(),
      epoch: bigint(),
      disabled_at: bigint().nullable(),
      created_at: bigint(),
      updated_at: bigint(),
      last_login_at: bigint().nullable(),
      row_version: bigint(),
    },
    primaryKey: ['id'],
    unique: [{ name: 'users_login_key', columns: ['login'] }],
  }),
  defineTable('sessions', {
    ...identity,
    description:
      'Sign-in sessions: only the SHA-256 of each secret is stored; the public id is s_…. Each is bound to the transport it was signed in over (https, loopback or http).',
    backup: 'never',
    retention: 'identity.prune',
    columns: {
      id: text(32),
      token_hash: text(64),
      user_id: text(64),
      kind: text(16),
      stage: text(24),
      via: text(16),
      transport: text(16),
      persistent: bool(),
      created_at: bigint(),
      auth_time: bigint(),
      last_seen_at: bigint(),
      idle_expires_at: bigint(),
      expires_at: bigint(),
      client_key: text(64).nullable(),
      user_agent: text(256).nullable(),
    },
    primaryKey: ['id'],
    unique: [{ name: 'sessions_token_hash_key', columns: ['token_hash'] }],
    indexes: [
      { name: 'sessions_user_idx', columns: ['user_id', 'last_seen_at'] },
      { name: 'sessions_expiry_idx', columns: ['expires_at'] },
    ],
  }),
  defineTable('identity_settings', {
    ...identity,
    description:
      "Node-local identity state of this data directory: the built-in admin's password source, the auth.json fingerprint, the GOBLIN_PASSWORD verifier, the pending mirror flag and the last restore handled. Never backed up or transferred.",
    backup: 'never',
    columns: { key: text(128), value: text(), updated_at: bigint() },
    primaryKey: ['key'],
  }),
  defineTable('displays', {
    ...identity,
    description:
      'One-time wall display codes (goblin-admin display code): only the SHA-256 of each code is stored; the public id is d_…. A redeemed row names the read-only display session it became; one created from the web page names the session that created it.',
    backup: 'never',
    retention: 'identity.prune',
    columns: {
      id: text(32),
      name: text(64),
      code_hash: text(64),
      state: text(16),
      origin: text(8),
      code_expires_at: bigint(),
      created_at: bigint(),
      created_by: text(128),
      created_session: text(32).nullable(),
      created_scope: text(64).nullable(),
      session_id: text(32).nullable(),
      redeemed_at: bigint().nullable(),
      redeemed_client: text(64).nullable(),
      cancelled_at: bigint().nullable(),
      cancel_cause: text(16).nullable(),
      cancel_recorded: bool().default(true),
    },
    primaryKey: ['id'],
    unique: [{ name: 'displays_code_hash_key', columns: ['code_hash'] }],
    indexes: [
      { name: 'displays_session_idx', columns: ['session_id'] },
      { name: 'displays_created_session_idx', columns: ['created_session'] },
    ],
  }),
]);

// ---------------------------------------------------------------------------------------------
// Alerting (lane A): control.sqlite, 1.5.0. Durable delivery's outbox and channel health,
// declared in lib/alerting/tables.mjs (plain specifications, so no import cycle).

export const alertingTables = Object.freeze(
  alertingTableSpecs.map(([name, options]) => defineTable(name, options))
);

// ---------------------------------------------------------------------------------------------
// The audit trail (lane O): control.sqlite, 1.5.0. Append-only, HMAC-chained (lib/audit).
const audit = { component: 'audit', lane: 'O', since: '1.5.0', class: 'control', db: 'control' };

export const auditTables = Object.freeze([
  defineTable('audit_log', {
    ...audit,
    description:
      'The audit trail: append-only rows, each chained to the one before by an HMAC under the keyring audit key (lib/audit).',
    backup: 'always',
    transfer: 30,
    retention: 'audit.prune',
    columns: {
      seq: id(),
      v: bigint().default(1),
      time: bigint(),
      ref: bigint().nullable(),
      actor_type: text(16),
      actor_id: text(64).nullable(),
      actor_name: text(200).nullable(),
      via: text(16).nullable(),
      session_id: text(32).nullable(),
      client_key: text(64).nullable(),
      user_agent: text(200).nullable(),
      request_id: text(64).nullable(),
      action: text(64),
      target_type: text(32).nullable(),
      target_id: text(128).nullable(),
      target_name: text(200).nullable(),
      outcome: text(16),
      status: bigint().nullable(),
      count: bigint().default(1),
      detail: json().nullable(),
      config_revision: bigint().nullable(),
      key_id: text(32),
      prev_hash: text(64),
      hash: text(64),
    },
    indexes: [
      { name: 'audit_log_time', columns: ['time'] },
      { name: 'audit_log_action', columns: ['action', 'seq'] },
      { name: 'audit_log_target', columns: ['target_type', 'target_id', 'seq'] },
      { name: 'audit_log_ref', columns: ['ref'] },
      { name: 'audit_log_outcome', columns: ['outcome', 'seq'] },
      { name: 'audit_log_actor', columns: ['actor_type', 'seq'] },
    ],
  }),
  defineTable('audit_head', {
    ...audit,
    description: 'The newest row of audit_log (id 1 only): its seq and hash, for the next append.',
    backup: 'always',
    transfer: 31,
    columns: {
      id: bigint(),
      seq: bigint(),
      hash: text(64),
      key_id: text(32),
      updated_at: bigint(),
    },
    primaryKey: ['id'],
  }),
  defineTable('audit_checkpoints', {
    ...audit,
    description:
      'Signed checkpoints written before each prune of audit_log (every checkpoint is also printed to stdout).',
    backup: 'always',
    transfer: 32,
    columns: {
      id: id(),
      seq: bigint(),
      time: bigint(),
      hash: text(64),
      key_id: text(32),
      reason: text(16),
      mac: text(64),
    },
    indexes: [{ name: 'audit_checkpoints_seq', columns: ['seq'] }],
  }),
  defineTable('audit_inbox', {
    ...audit,
    description:
      "Audit events of a data directory's first start, written before its keyring exists; Uptime Goblin chains them once it does.",
    backup: 'always',
    transfer: 33,
    columns: { id: id(), time: bigint(), source: text(16), event: json() },
  }),
]);

// ---------------------------------------------------------------------------------------------
// history.sqlite 1.x tables: hand-written in lib/store.mjs, never altered (invariant 1).

const history = { db: 'history', lane: 'S' };

export const legacyHistoryTables = Object.freeze([
  defineLegacyTable('readings', {
    ...history,
    component: 'scale',
    class: 'series',
    since: '1.0.0',
    backup: 'history:all',
    transfer: 20,
    description: 'Raw readings; a row with ok=0 and error "__gap" marks a break in collection.',
    columns: { service: 'text', time: 'bigint', ok: 'bigint', metrics: 'json', error: 'text' },
    primaryKey: ['service', 'time'],
    indexes: [
      { name: 'readings_time', columns: ['time'] },
      { name: 'readings_history', columns: ['service', 'time', 'ok', 'error'] },
    ],
  }),
  defineLegacyTable('latest', {
    ...history,
    component: 'scale',
    class: 'state',
    shared: ['series'],
    since: '1.0.0',
    backup: 'history:rollups',
    transfer: 21,
    description: 'Latest status (state) and latest values (read by the series store) per source.',
    columns: {
      service: 'text',
      attempted: 'bigint',
      success: 'bigint',
      metrics: 'json',
      error: 'text',
    },
    primaryKey: ['service'],
  }),
  defineLegacyTable('alerts', {
    ...history,
    component: 'alerting',
    lane: 'A',
    class: 'state',
    since: '1.0.0',
    backup: 'history:all',
    transfer: 22,
    columns: {
      service: 'text',
      rule: 'text',
      state: 'text',
      since: 'bigint',
      count: 'bigint',
      message: 'text',
      updated: 'bigint',
      recovery_since: 'bigint',
      recovery_count: 'bigint',
    },
    primaryKey: ['service', 'rule'],
  }),
  defineLegacyTable('events', {
    ...history,
    component: 'alerting',
    lane: 'A',
    class: 'state',
    since: '1.0.0',
    backup: 'history:all',
    transfer: 23,
    // since, uid and relayed (1.5): the event row is durable delivery's outbox record. relayed
    // is 0 until the relay copied it into alerting_outbox, 1 after, and NULL in rows 1.4.x wrote,
    // which are never relayed. events_unrelayed covers only the rows still to relay.
    columns: {
      id: 'bigint',
      service: 'text',
      time: 'bigint',
      kind: 'text',
      message: 'text',
      category: 'text',
      rule: 'text',
      since: 'bigint',
      uid: 'text',
      relayed: 'bigint',
    },
    primaryKey: ['id'],
    indexes: [
      { name: 'events_time', columns: ['time'] },
      { name: 'events_unrelayed', columns: ['id'], where: [['relayed', '=', 0]] },
    ],
  }),
  defineLegacyTable('latest_notes', {
    ...history,
    component: 'ops',
    lane: 'O',
    class: 'series',
    since: '1.4.3',
    backup: 'history:rollups',
    transfer: 24,
    description: 'Collector notes of the latest collection (JSON [{code, message, omitted?}]).',
    columns: { service: 'text', time: 'bigint', notes: 'json' },
    primaryKey: ['service'],
  }),
]);

// ---------------------------------------------------------------------------------------------
// history.sqlite 1.5 summaries and their coverage marks: hand-written in lib/store.mjs like the
// 1.x tables beside them (the Store's connection takes only its frozen statements and sql`…`,
// never the DSL's DDL), and additive: a release that does not know them never reads or writes
// them. Derived from readings, so never backed up or transferred: a start checks the summaries
// against the readings (skipping a source whose mark still matches) and rebuilds what is missing
// or stale.

export const summaryHistoryTables = Object.freeze([
  defineLegacyTable('history_summaries', {
    ...history,
    component: 'scale',
    class: 'series',
    since: '1.5.0',
    backup: 'never',
    description:
      'One row per source and 5-minute slot summarising its readings (lib/series/shape.mjs summarizeSlot), read by charts of 7 days or more.',
    columns: {
      service: 'text',
      slot: 'bigint',
      successes: 'bigint',
      first_time: 'bigint',
      last_time: 'bigint',
      previous_time: 'bigint',
      sample_time: 'bigint',
      failure_time: 'bigint',
      marker_time: 'bigint',
      first_failure_time: 'bigint',
      sample_gap: 'bigint',
      failure_gap: 'bigint',
      marker_gap: 'bigint',
    },
    primaryKey: ['service', 'slot'],
    indexes: [{ name: 'history_summaries_slot', columns: ['slot'] }],
  }),
  defineLegacyTable('history_summary_marks', {
    ...history,
    component: 'scale',
    class: 'series',
    since: '1.5.0',
    backup: 'never',
    description:
      'One row per source whose summaries matched its readings when the Store last closed, with a fingerprint of those readings and the summary count: a start skips the check of a source whose fingerprint is unchanged.',
    columns: {
      service: 'text',
      reading_count: 'bigint',
      first_time: 'bigint',
      last_time: 'bigint',
      time_sum: 'bigint',
      success_sum: 'bigint',
      marker_sum: 'bigint',
      summary_count: 'bigint',
    },
    primaryKey: ['service'],
  }),
]);

/** The registry of this release. */
export const registry = createRegistry([
  ...platformTables,
  ...identityTables,
  ...alertingTables,
  ...auditTables,
  ...legacyHistoryTables,
  ...summaryHistoryTables,
]);
export default registry;
