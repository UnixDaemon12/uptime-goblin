// The control database, <data>/control.sqlite (roadmap §2.1, §3.3): identity, audit, settings,
// the keyring, the outbox and every other small, uncapped table that must survive a full
// history. It is separate from history.sqlite, which is capped and recycles itself.
//
//   const control = openControl(directory, {release});
//   const state = await control.inspect();      // refusal? pending steps? (reads only)
//   await control.migrate();                    // one BEGIN IMMEDIATE unit per step
//   await control.meta.get('instance_id');
//
// server.mjs calls startControl() (below) in its start sequence after taking goblin.lock and
// checking config.json read-only: it refuses (exit 78) before writing anything, snapshots,
// migrates and opens the keyring when there is one. It must run before ConfigStore and Store
// open, because an install is "created by this release" only when none of their files existed
// yet (or created-by.json says an earlier 1.5+ start found it so: see createdByFile);
// migrateHistory() (not wired yet: there are no history steps) runs after Store has created its
// 1.x tables.
//
// Also here: the store adapters for lib/keyring.mjs, lib/settings.mjs, lib/jobs.mjs and
// lib/http/idempotency.mjs, which issue no SQL themselves.
//
// The platform component's tables and steps live here; other components append their steps
// to controlSteps and historySteps (lane P merges them).
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { sql, id, json } from './sql.mjs';
import { openSqlite, plantedObjects } from './sqlite.mjs';
import {
  createMigrator,
  defineSteps,
  requireRelease,
  newInstanceId,
  compareReleases,
  coreRelease,
  orderSteps,
  parseRelease,
  RefusalError,
} from './migrate.mjs';
import defaultRegistry from './registry.mjs';
import { renderTable } from './dialect/schema.mjs';
import { createSqliteDialect } from './dialect/sqlite.mjs';
import { createSettings, SettingsError } from '../settings.mjs';
import { createFeatures, featureToggles } from '../features.mjs';
import { resolveKey, Keyring, keyFingerprint, dataDirectoryKeyNote } from '../keyring.mjs';
import {
  assertSnapshotsDirectory,
  createSnapshot,
  interruptedRestore,
  isPre15,
  isSnapshotId,
  listSnapshots,
  removeEmptyRestoreFolders,
  removeRestoreLeftovers,
  snapshotsDirectory,
  unchangedSince,
} from './snapshot.mjs';
import { adminCommand, fromKeptCopy, runningLayout } from '../admin-command.mjs';
import { alertingSteps } from '../alerting/tables.mjs';
import { assertDatabaseFiles } from '../saved-data.mjs';

export const controlFile = 'control.sqlite';
/** Files whose presence means the data directory predates this release's control database. */
export const legacyDataFiles = Object.freeze(['config.json', 'auth.json', 'history.sqlite']);
const historyLimit = 50;

/** This release's version, from package.json. */
export function packageRelease() {
  return JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
    .version;
}

/**
 * <data>/created-by.json: {"release": "<x.y.z>", "createdAt": "<ISO time>"}, the release that
 * created the data directory. meta.created_by_release decides G2 (legacy Basic is on by
 * default only for data upgraded from 1.4.x), but it lives in control.sqlite, which an operator
 * may move aside to start over with a new one (docs/authentication.md). Without this file the
 * next start would find config.json and history.sqlite, take the directory for 1.4.x data and
 * turn legacy Basic on. 1.4.x never writes it and no snapshot or restore touches it, so a new
 * control.sqlite records the release that really created the directory.
 */
export const createdByFile = 'created-by.json';
// Far more than the record needs; a larger file is not read (it still counts, see below).
const createdByBytes = 4096;

const entryExists = file => {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return false;
    throw error;
  }
};

/**
 * The release that created <directory> according to created-by.json, or null when there is
 * none. Any entry by that name counts: 1.4.x never writes one, so a damaged or edited file still
 * means 1.5 or later created the directory (failing towards legacy Basic off, which
 * GOBLIN_LEGACY_BASIC=1 overrides), and `fallback` stands in for a release it does not name.
 * Only a small regular file is read: a FIFO there must not block the start.
 */
export function readCreatedBy(directory, fallback) {
  const file = path.join(directory, createdByFile);
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null;
    throw error;
  }
  if (stat.isFile() && stat.size <= createdByBytes)
    try {
      const { release } = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (typeof release === 'string') {
        parseRelease(release);
        return release;
      }
    } catch {
      // Not a record this release can read: the fallback below.
    }
  return fallback;
}

/**
 * Writes created-by.json naming `release`, unless an entry by that name exists (the release that
 * first created the directory stays named), through an exclusive temporary file that is fsynced
 * and renamed into place. Runs under goblin.lock (startControl), so nothing else writes the name
 * meanwhile. A write lost to a power loss is repeated by the next start, from
 * meta.created_by_release. Returns whether it wrote the file.
 */
export function recordCreatedBy(directory, release, now = Date.now()) {
  const file = path.join(directory, createdByFile);
  if (!release || entryExists(file)) return false;
  const temporary = `${file}.${randomUUID()}.tmp`;
  let descriptor,
    created = false;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    created = true;
    fs.writeFileSync(
      descriptor,
      JSON.stringify({ release, createdAt: new Date(now).toISOString() }) + '\n'
    );
    fs.fsyncSync(descriptor);
    const closing = descriptor;
    descriptor = undefined;
    fs.closeSync(closing);
    fs.renameSync(temporary, file);
    return true;
  } catch (error) {
    if (descriptor !== undefined)
      try {
        fs.closeSync(descriptor);
      } catch {}
    if (created)
      try {
        fs.unlinkSync(temporary);
      } catch {}
    throw error;
  }
}

/** The warning of a start that could not write created-by.json (`code`: the error's code). */
export const createdByWarning = code =>
  `Uptime Goblin could not write ${createdByFile} in the data directory (${code}); it tries again at the next start. Until then, if control.sqlite were removed, Uptime Goblin would take this data directory for one upgraded from 1.4.x and turn legacy Basic for scripts on by default.`;

// ---------------------------------------------------------------------------------------------
// Platform migration steps.

export const platformSteps = Object.freeze([
  {
    id: 'platform-001-control-tables',
    component: 'platform',
    kind: 'expand',
    db: 'control',
    description: 'The platform tables: fences, meta, keyring, settings, jobs and idempotency keys.',
    up: {
      createTables: ['schema_fences', 'meta', 'keyring', 'settings', 'jobs', 'idempotency_keys'],
    },
  },
  {
    id: 'platform-002-instance',
    component: 'platform',
    kind: 'expand',
    db: 'control',
    after: ['platform-001-control-tables'],
    description:
      'The instance id, and created_by_release for data directories this release created.',
    // Portable: only sql`…` and dialect helpers, so every engine runs it. context.createdBy is
    // openControl's (created-by.json's release, or this one for a fresh directory).
    up(tx, context) {
      const now = context.now ?? Date.now();
      const rows = [['instance_id', newInstanceId(), now]];
      const createdBy = context.createdBy ?? (context.fresh ? context.release : null);
      if (createdBy) rows.push(['created_by_release', createdBy, now]);
      tx.run(tx.dialect.insertIgnore('meta', ['key', 'value', 'updated_at'], rows));
    },
  },
]);

// Identity (lane I): the built-in admin's tables. No row is inserted here: the u_admin row
// needs auth.json, GOBLIN_PASSWORD and scrypt, so identity creates it at start
// (lib/identity/bootstrap.mjs). No fence is raised: 1.5.0 is the first reader.
export const identitySteps = Object.freeze([
  {
    id: 'identity-001-builtin-admin',
    component: 'identity',
    kind: 'expand',
    db: 'control',
    after: ['platform-002-instance'],
    description: 'Built-in admin sign-in: the users, sessions and identity_settings tables.',
    up: { createTables: ['users', 'sessions', 'identity_settings'] },
  },
  // Expand only: an earlier 1.5 build tolerates the applied step and the table, and refuses the
  // kiosk session rows it does not know (fail closed).
  {
    id: 'identity-002-displays',
    component: 'identity',
    kind: 'expand',
    db: 'control',
    after: ['identity-001-builtin-admin'],
    description: 'Wall displays: the displays table of one-time display codes.',
    up: { createTables: ['displays'] },
  },
]);

// The audit trail (lane O). Expand only: every earlier 1.5 build tolerates an unknown applied
// expand step, and 1.4.x never opens control.sqlite, so no fence is raised (audit-spec D2).
export const auditSteps = Object.freeze([
  {
    id: 'audit-001-log',
    component: 'audit',
    kind: 'expand',
    db: 'control',
    after: ['platform-002-instance'],
    description: 'The audit trail: audit_log, audit_head, audit_checkpoints and audit_inbox.',
    up: { createTables: ['audit_log', 'audit_head', 'audit_checkpoints', 'audit_inbox'] },
  },
]);

/**
 * Every control-database step of this release, validated. Alerting's step (the outbox and
 * channel health, lib/alerting/tables.mjs) runs after the platform tables, and ties are broken
 * by id, so the plan is platform-001, alerting-001, platform-002, audit-001, identity-001.
 */
export const controlSteps = defineSteps([
  ...platformSteps,
  ...identitySteps,
  ...alertingSteps,
  ...auditSteps,
]);

/**
 * The migration steps of history.sqlite (store classes state and series in SQLite mode). There
 * are none yet: components append theirs here (alerting's `events` columns, scale's tables) and
 * lane P merges them. They run through migrateHistory().
 */
export const historySteps = defineSteps([]);
export const historyFile = 'history.sqlite';

// ---------------------------------------------------------------------------------------------
// meta: small named values. These take a transaction, for use inside another unit (for example
// bumping session_seq in the same transaction as a CLI revocation).

export const metaOps = Object.freeze({
  get(tx, key) {
    return (
      tx.get(sql`SELECT ${id('value')} FROM ${id('meta')} WHERE ${id('key')} = ${key}`)?.value ??
      null
    );
  },
  set(tx, key, value, now) {
    tx.run(
      tx.dialect.upsert(
        'meta',
        ['key'],
        ['key', 'value', 'updated_at'],
        [[key, String(value), now]]
      )
    );
  },
  /** Sets `key` only when absent; true when this call set it. */
  setIfAbsent(tx, key, value, now) {
    return (
      tx.run(
        tx.dialect.insertIgnore('meta', ['key', 'value', 'updated_at'], [[key, String(value), now]])
      ).changes === 1
    );
  },
  /**
   * Increments session_seq (the CLI's revocation signal) and returns the new value. A value
   * that is not a count (a damaged or hand-edited row) is replaced by the time, which no count
   * reached, so every reader that remembered an earlier value sees a change.
   */
  bumpSessionSeq(tx, now) {
    const current = sessionSeqOf(metaOps.get(tx, 'session_seq') ?? '0');
    const next = current === null || current >= Number.MAX_SAFE_INTEGER ? now : current + 1;
    metaOps.set(tx, 'session_seq', next, now);
    return next;
  },
});

/**
 * meta.session_seq as a count, or null when the stored text is not one (a damaged or edited
 * row): Number() would make it NaN, which equals nothing, or a fraction or a negative number
 * that a later increment could bring back to a value already seen. A reader comparing it with a
 * value it remembered treats null as a change (revoking), never as the same.
 */
export function sessionSeqOf(text) {
  if (typeof text !== 'string' || !/^(?:0|[1-9][0-9]{0,15})$/.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : null;
}

// A release as meta records it: a version such as 1.5.0 or 1.5.0-dev.2 (safeRelease's
// characters), at most 64 of them.
const releaseName = value => typeof value === 'string' && /^[0-9A-Za-z.+-]{1,64}$/.test(value);

/**
 * meta.upgrade_history as the entries recordRelease writes, newest last: at most historyLimit
 * {from, to, at}, each release a release name of at most 64 characters (or null for `from`, data
 * from before 1.5) and `at` a time. Entries that are not are left out, and anything that is not
 * such a list reads as none, so a damaged row neither grows without bound nor reaches the audit
 * log or a terminal as it is.
 */
export function upgradeHistoryOf(text) {
  let list;
  try {
    list = JSON.parse(text ?? '[]');
  } catch {
    return [];
  }
  if (!Array.isArray(list)) return [];
  return list
    .slice(-historyLimit)
    .filter(
      entry =>
        entry &&
        typeof entry === 'object' &&
        (entry.from === null || releaseName(entry.from)) &&
        releaseName(entry.to) &&
        Number.isSafeInteger(entry.at)
    )
    .map(({ from, to, at }) => ({ from, to, at }));
}

function createMeta(db, clock) {
  return Object.freeze({
    get: key => db.read(tx => metaOps.get(tx, key)),
    async all() {
      const rows = await db.read(tx =>
        tx.all(sql`SELECT ${id('key')}, ${id('value')} FROM ${id('meta')}`)
      );
      return Object.fromEntries(rows.map(row => [row.key, row.value]));
    },
    set: (key, value) => db.write(tx => metaOps.set(tx, key, value, clock())),
    setIfAbsent: (key, value) => db.write(tx => metaOps.setIfAbsent(tx, key, value, clock())),
    instanceId: () => db.read(tx => metaOps.get(tx, 'instance_id')),
    /** The release that created this data directory, or null for one upgraded from before 1.5. */
    createdByRelease: () => db.read(tx => metaOps.get(tx, 'created_by_release')),
    /**
     * One-way record that the admin has had a password (X2), kept in the data contract. No start
     * depends on it: startControl refuses every start without a password source.
     */
    markCredentials: () =>
      db.write(tx => metaOps.setIfAbsent(tx, 'credentials_ever', '1', clock())),
    credentialsEver: async () => (await db.read(tx => metaOps.get(tx, 'credentials_ever'))) === '1',
    /** The count, 0 before the first bump, or null when the stored value is not a count. */
    sessionSeq: async () =>
      sessionSeqOf((await db.read(tx => metaOps.get(tx, 'session_seq'))) ?? '0'),
    bumpSessionSeq: () => db.write(tx => metaOps.bumpSessionSeq(tx, clock())),
    upgradeHistory: async () =>
      upgradeHistoryOf(await db.read(tx => metaOps.get(tx, 'upgrade_history'))),
  });
}

// Records this release in meta.last_version and meta.upgrade_history (newest last, capped).
function recordRelease(tx, release, now) {
  const last = metaOps.get(tx, 'last_version');
  if (last === release) return false;
  // Only the entries upgradeHistoryOf() keeps are carried on, and a last_version that is not a
  // release name (a damaged row) is recorded as unknown, as data from before 1.5 is.
  const history = upgradeHistoryOf(metaOps.get(tx, 'upgrade_history'));
  history.push({ from: releaseName(last) ? last : null, to: release, at: now });
  metaOps.set(tx, 'upgrade_history', JSON.stringify(history.slice(-historyLimit)), now);
  metaOps.set(tx, 'last_version', release, now);
  return true;
}

// ---------------------------------------------------------------------------------------------
// Store adapters for lib/keyring.mjs, lib/settings.mjs and lib/jobs.mjs (which issue no SQL).

// Asked of the dialect's catalog (lib/db/dialect/base.mjs), not of SQLite's sqlite_master, so
// the statement ports to every engine (test/dialect/portability.test.mjs).
const tableExists = (tx, name) => Boolean(tx.get(tx.dialect.catalog.tableExists(name)));

const keyringColumns = ['kid', 'purpose', 'wrapped', 'created_at', 'retired_at'];

export function createKeyringStore(db) {
  return Object.freeze({
    list: () =>
      db.read(tx =>
        tx.all(
          sql`SELECT ${id('kid')}, ${id('purpose')}, ${id('wrapped')}, ${id('created_at')}, ${id('retired_at')} FROM ${id('keyring')}`
        )
      ),
    /** Whether any data key exists (false before the keyring table does). */
    exists: () =>
      db.read(tx =>
        tableExists(tx, 'keyring')
          ? Boolean(
              // SQL Server takes a limit only after an order (OFFSET … FETCH).
              tx.get(
                sql`SELECT ${id('kid')} FROM ${id('keyring')} ${tx.dialect.orderBy(['kid', 'asc', 'not null'])} ${tx.dialect.limit(1)}`
              )
            )
          : false
      ),
    // inUnit(tx) runs last inside the same unit (Keyring.reset's audit anchor, audit spec D17):
    // the keys and what it writes commit together, and a throw from it rolls both back.
    save: ({ insert = [], rewrap = [], retire = [], clear = false, inUnit = null } = {}) =>
      db.write(tx => {
        if (clear) tx.run(tx.dialect.deleteFrom('keyring', sql`${id('kid')} IS NOT NULL`));
        for (const { kid, wrapped } of rewrap)
          if (
            !tx.run(tx.dialect.update('keyring', { wrapped }, sql`${id('kid')} = ${kid}`)).changes
          )
            throw new Error(`The keyring has no key ${kid}`);
        for (const { kid, retired_at } of retire)
          tx.run(tx.dialect.update('keyring', { retired_at }, sql`${id('kid')} = ${kid}`));
        if (insert.length)
          tx.run(
            tx.dialect.insert(
              'keyring',
              keyringColumns,
              insert.map(row => keyringColumns.map(column => row[column] ?? null))
            )
          );
        inUnit?.(tx);
      }),
  });
}

const settingsColumns = [
  'component',
  'key',
  'schema',
  'value',
  'version',
  'updated_at',
  'updated_by',
];

export function createSettingsStore(db) {
  const select = sql`SELECT ${id('component')}, ${id('key')}, ${id('schema')}, ${id('value')}, ${id('version')}, ${id('updated_at')}, ${id('updated_by')} FROM ${id('settings')}`;
  return Object.freeze({
    get: (component, key) =>
      db.read(tx =>
        tx.get(sql`${select} WHERE ${id('component')} = ${component} AND ${id('key')} = ${key}`)
      ),
    list: component =>
      db.read(tx =>
        tx.all(
          component === undefined ? select : sql`${select} WHERE ${id('component')} = ${component}`
        )
      ),
    /**
     * Compare-and-swap on version: ifVersion 0 inserts only when absent. inUnit(tx) runs inside
     * the same unit only when the swap changed the row (the rotation's audit row, audit spec D5),
     * so a conflict records nothing and a throw from it rolls the change back.
     */
    put: (row, { ifVersion, inUnit = null }) =>
      db.write(tx => {
        let changed;
        if (ifVersion === 0)
          changed =
            tx.run(
              tx.dialect.insertIgnore('settings', settingsColumns, [
                settingsColumns.map(column => row[column] ?? null),
              ])
            ).changes === 1;
        else {
          const { component, key, ...rest } = row;
          changed =
            tx.run(
              tx.dialect.update(
                'settings',
                {
                  schema: rest.schema,
                  value: rest.value,
                  version: rest.version,
                  updated_at: rest.updated_at,
                  updated_by: rest.updated_by ?? null,
                },
                sql`${id('component')} = ${component} AND ${id('key')} = ${key} AND ${id('version')} = ${ifVersion}`
              )
            ).changes === 1;
        }
        if (changed) inUnit?.(tx);
        return changed;
      }),
  });
}

const jobColumns = [
  'name',
  'last_started',
  'last_finished',
  'last_ok',
  'last_error',
  'runs',
  'failures',
  'duration_ms',
  'updated_at',
];

// Text kept for diagnosis only (a job's name and last error, a keyed request's route), cut to
// `max` UTF-16 units and made storable: a cut between the halves of a pair, or an unpaired
// surrogate or NUL in the text, is refused at bind, so such a character becomes U+FFFD or goes.
const boundedText = (value, max) =>
  String(value).slice(0, max).toWellFormed().replaceAll('\u0000', '');

/** The `jobs` table: record(status) is lib/jobs.mjs's statusSink. */
export function createJobsStore(db, clock = Date.now) {
  return Object.freeze({
    record(status) {
      const error = status.lastError;
      const text =
        error == null
          ? null
          : boundedText(
              typeof error === 'object' ? (error.message ?? error.text ?? '') : error,
              500
            );
      const row = [
        boundedText(status.name, 128),
        status.lastStarted ?? null,
        status.lastFinished ?? null,
        status.lastOk ?? null,
        text,
        status.runs ?? 0,
        status.failures ?? 0,
        status.durationMs ?? null,
        clock(),
      ];
      return db.write(tx => tx.run(tx.dialect.upsert('jobs', ['name'], jobColumns, [row])));
    },
    list: () =>
      db.read(tx =>
        tx.all(
          sql`SELECT ${join(jobColumns)} FROM ${id('jobs')} ${tx.dialect.orderBy(['name', 'asc', 'not null'])}`
        )
      ),
  });
}
const join = columns => sql.join(columns.map(column => id(column)));

/**
 * The idempotency_keys table as a store for lib/http/idempotency.mjs (its adapter contract:
 * begin, takeOver, finish, abandon, prune), so keyed requests survive a restart (roadmap §2.4
 * step 13, #6). The adapter receives the whole scope ([...scope, key] joined by newlines): the
 * table keeps its last line (the Idempotency-Key) as `key`, the SHA-256 of the rest as
 * `principal`, and the rest itself, cut to 256 characters, as `route` for diagnosis only.
 * `body_sha256` holds the caller's body digest; a running entry's `expires_at` is its lease, a
 * finished one's the end of its replay window. prune(now) removes finished entries past their
 * window, running entries whose lease ended more than `staleMs` ago (their process died and no
 * retry came), and the oldest finished entries beyond `maxEntries`. Use it with a wall clock
 * and a secret that survives restarts (see createIdempotency).
 */
export function createIdempotencyStore(
  db,
  { clock = Date.now, maxEntries = 256, staleMs = 60 * 60 * 1000 } = {}
) {
  const columns = [
    'principal',
    'key',
    'route',
    'body_sha256',
    'state',
    'status',
    'response',
    'created_at',
    'expires_at',
  ];
  const locate = scope => {
    const text = String(scope);
    const cut = text.lastIndexOf('\n');
    const prefix = cut < 0 ? '' : text.slice(0, cut);
    return {
      principal: createHash('sha256').update(prefix).digest('hex'),
      key: text.slice(cut + 1),
      route: boundedText(prefix, 256),
    };
  };
  const where = ({ principal, key }) =>
    sql`${id('principal')} = ${principal} AND ${id('key')} = ${key}`;
  const entryOf = row => {
    let response = null;
    if (row.state === 'done')
      try {
        const parsed = JSON.parse(row.response);
        response = {
          status: Number(row.status),
          body: String(parsed.body ?? ''),
          headers: parsed.headers && typeof parsed.headers === 'object' ? parsed.headers : {},
        };
      } catch {
        response = { status: Number(row.status), body: '', headers: {} };
      }
    return {
      digest: row.body_sha256,
      response,
      expiresAt: row.state === 'done' ? Number(row.expires_at) : null,
      leaseUntil: row.state === 'done' ? null : Number(row.expires_at),
    };
  };
  const select = place =>
    sql`SELECT ${join(columns)} FROM ${id('idempotency_keys')} WHERE ${where(place)}`;
  return Object.freeze({
    kind: 'control',
    begin: (scope, { digest, leaseUntil }) =>
      db.write(tx => {
        const place = locate(scope);
        const row = tx.get(select(place));
        if (row) return { entry: entryOf(row) };
        tx.run(
          tx.dialect.insert('idempotency_keys', columns, [
            [
              place.principal,
              place.key,
              place.route,
              digest,
              'running',
              null,
              null,
              clock(),
              leaseUntil,
            ],
          ])
        );
        return { entry: null };
      }),
    takeOver: (scope, { digest, leaseUntil, now }) =>
      db.write(
        tx =>
          tx.run(
            tx.dialect.update(
              'idempotency_keys',
              { body_sha256: digest, expires_at: leaseUntil },
              sql`${where(locate(scope))} AND ${id('state')} = ${'running'} AND ${id('expires_at')} <= ${now}`
            )
          ).changes === 1
      ),
    finish: (scope, { response, expiresAt }) =>
      db.write(tx => {
        tx.run(
          tx.dialect.update(
            'idempotency_keys',
            {
              state: 'done',
              status: response.status,
              response: json({
                body: String(response.body),
                headers: { ...(response.headers ?? {}) },
              }),
              expires_at: expiresAt,
            },
            sql`${where(locate(scope))} AND ${id('state')} = ${'running'}`
          )
        );
      }),
    abandon: scope =>
      db.write(tx => {
        tx.run(
          tx.dialect.deleteFrom(
            'idempotency_keys',
            sql`${where(locate(scope))} AND ${id('state')} = ${'running'}`
          )
        );
      }),
    prune: now =>
      db.write(tx => {
        let removed = tx.run(
          tx.dialect.deleteFrom(
            'idempotency_keys',
            sql`(${id('state')} = ${'done'} AND ${id('expires_at')} <= ${now}) OR (${id('state')} = ${'running'} AND ${id('expires_at')} <= ${now - staleMs})`
          )
        ).changes;
        const { n } = tx.get(
          sql`SELECT COUNT(*) AS n FROM ${id('idempotency_keys')} WHERE ${id('state')} = ${'done'}`
        );
        if (Number(n) > maxEntries) {
          const oldest = tx.all(
            sql`SELECT ${id('principal')}, ${id('key')} FROM ${id('idempotency_keys')} WHERE ${id('state')} = ${'done'} ${tx.dialect.orderBy(['created_at', 'asc', 'not null'], ['principal', 'asc', 'not null'], ['key', 'asc', 'not null'])} ${tx.dialect.limit(Number(n) - maxEntries)}`
          );
          for (const row of oldest)
            removed += tx.run(tx.dialect.deleteFrom('idempotency_keys', where(row))).changes;
        }
        return removed;
      }),
  });
}

// ---------------------------------------------------------------------------------------------

/**
 * The plan for a data directory that has no control database yet: every step in order, with
 * its SQLite DDL (goblin-admin migrate --plan, the installer's preflight).
 */
export function planFromScratch({ steps = controlSteps, registry = defaultRegistry } = {}) {
  const dialect = createSqliteDialect({ identifiers: registry.identifiers });
  return orderSteps(steps)
    .filter(step => step.db === 'control' && (step.modes ?? ['single']).includes('single'))
    .map(step => ({
      id: step.id,
      kind: step.kind,
      db: step.db,
      description: step.description ?? '',
      ddl: Array.isArray(step.up?.createTables)
        ? step.up.createTables.flatMap(name => renderTable(dialect, registry.table(name)))
        : [],
    }));
}

/**
 * Refuses a start (RefusalError 'schema_planted', exit 78) on a database `file` whose catalog
 * holds a trigger, a view or any row that is not a table or an index as SQLite writes one
 * (catalogKind in lib/db/sqlite.mjs; a trigger whose row says 'TRIGGER' runs too): Uptime Goblin
 * creates none, and a trigger would run inside its writes. `goblin-admin check-data` names them
 * too, and lets the start be put right offline.
 */
function refusePlanted(file, catalog) {
  const planted = plantedObjects(catalog);
  if (planted.length)
    throw new RefusalError(
      'schema_planted',
      `${file} holds ${planted.join(', ')}, which Uptime Goblin never creates: a trigger runs inside Uptime Goblin's own writes, where it could undo a sign-out or rewrite a password. With Uptime Goblin stopped, restore ${file} from a snapshot or a backup taken before it appeared (goblin-admin check-data lists them), then start Uptime Goblin again.`
    );
}

/**
 * Whether <directory>/control.sqlite exists: any entry, a symbolic link to nothing or a loop of
 * links included, so that opening it refuses (see assertDatabaseFiles) instead of passing for a
 * data directory without one.
 */
export const controlExists = directory => entryExists(path.join(directory, controlFile));

/**
 * Opens <directory>/control.sqlite (created 0600 unless `readOnly`). Options: release (default
 * package.json's), readOnly, env, clock, registry, steps, settingsDefinitions, keyring, and the
 * Db options busyTimeoutMs, retries and sleep. Returns {file, db, release, fresh, meta,
 * settings, features, keyringStore, jobs, migrator, inspect(), plan(), migrate(),
 * requireRelease(tx, fence), keyringExists(), attachKeyring(keyring), close()}.
 */
export function openControl(directory, options = {}) {
  const {
    release = packageRelease(),
    readOnly = false,
    env = process.env,
    clock = Date.now,
    registry = defaultRegistry,
    steps = controlSteps,
    settingsDefinitions = [],
    keyring: initialKeyring = null,
    busyTimeoutMs,
    retries,
    sleep,
  } = options;
  const file = path.join(directory, controlFile);
  // Decided before anything creates files: no 1.x data means this release created the install.
  // Any entry counts, a symbolic link to a missing file included (a config.json on a volume
  // that is not mounted): such data was not created by this release.
  const fresh = !legacyDataFiles.some(name => entryExists(path.join(directory, name)));
  // What a control database created now records as created_by_release: the release
  // created-by.json names (a directory 1.5 created, whose control.sqlite was removed or lost),
  // else this one for a fresh directory, else null (data from before 1.5).
  const createdBy = readCreatedBy(directory, release) ?? (fresh ? release : null);
  if (!readOnly) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  const db = openSqlite(file, {
    registry,
    readOnly,
    clock,
    ...(busyTimeoutMs === undefined ? {} : { busyTimeoutMs }),
    ...(retries === undefined ? {} : { retries }),
    ...(sleep === undefined ? {} : { sleep }),
  });
  let keyring = initialKeyring;
  try {
    const migrator = createMigrator({
      db,
      classes: ['control'],
      steps,
      release,
      registry,
      clock,
      context: {
        fresh,
        createdBy,
        get now() {
          return clock();
        },
      },
    });
    const meta = createMeta(db, clock);
    const settings = createSettings({
      store: createSettingsStore(db),
      definitions: [featureToggles, ...settingsDefinitions],
      env,
      keyring: () => keyring,
      clock,
    });
    const features = createFeatures({ env, meta, settings, release });
    const keyringStore = createKeyringStore(db);
    return Object.freeze({
      file,
      db,
      release,
      fresh,
      meta,
      settings,
      features,
      keyringStore,
      jobs: createJobsStore(db, clock),
      migrator,
      /** Applied, pending and unknown steps, fences and the refusal (reads only). */
      inspect: opts => migrator.inspect(opts),
      /** The pending steps with their DDL (reads only). */
      plan: opts => migrator.plan(opts),
      /**
       * Refuses (RefusalError, exit 78) or applies the pending steps, then records this release
       * in meta (last_version, upgrade_history). Resolves {applied, pendingData, upgraded}.
       */
      async migrate(opts) {
        const result = await migrator.migrate(opts);
        const upgraded = await db.write(tx => recordRelease(tx, release, clock()));
        return { ...result, upgraded };
      },
      /** Raises a fence in the caller's write unit (see lib/db/migrate.mjs requireRelease). */
      requireRelease(tx, { name, minRelease, reason }) {
        if (compareReleases(minRelease, coreRelease(release)) > 0)
          throw new RangeError(
            `${name}: a fence cannot require ${minRelease}, newer than this release`
          );
        return requireRelease(tx, { name, minRelease, reason, now: clock() });
      },
      keyringExists: () => keyringStore.exists(),
      /** Gives settings the opened keyring (lib/keyring.mjs), for secret fields. */
      attachKeyring(value) {
        keyring = value;
      },
      close: () => db.close(),
    });
  } catch (error) {
    db.close();
    throw error;
  }
}

/**
 * Migrates <directory>/history.sqlite (start step 9: after lib/store.mjs has created its 1.x
 * tables, before collection starts), under goblin.lock. It inspects read-only first, so a
 * refusal (an applied contract step this release does not know: RefusalError, exit 78) writes
 * nothing, and opens the file for writing only when a step is pending. A missing file is left
 * missing. Resolves {exists, applied, pending, pendingData} (step ids). Data steps are only
 * reported: a background job runs them with createMigrator(…).runData() (wave 2 schedules it).
 */
export async function migrateHistory(directory, options = {}) {
  const {
    release = packageRelease(),
    steps = historySteps,
    registry = defaultRegistry,
    clock = Date.now,
    apply = true,
    onProgress,
    snapshotHint,
  } = options;
  const file = path.join(directory, historyFile);
  if (!fs.existsSync(file)) return { exists: false, applied: [], pending: [], pendingData: [] };
  const migratorFor = db =>
    createMigrator({ db, classes: ['state', 'series'], steps, release, registry, clock });
  const reader = openSqlite(file, { registry, readOnly: true, clock });
  let state;
  try {
    state = await migratorFor(reader).inspect({ snapshotHint });
  } finally {
    reader.close();
  }
  if (state.refusal) throw state.refusal;
  const pending = state.pending.map(step => step.id);
  const pendingData = state.pendingData.map(step => step.id);
  if (!apply || !state.pending.some(step => step.kind !== 'data'))
    return { exists: true, applied: [], pending, pendingData };
  const db = openSqlite(file, { registry, clock });
  try {
    const result = await migratorFor(db).migrate({
      snapshotHint,
      onProgress: progress =>
        onProgress?.({ phase: 'migrating', database: 'history', ...progress }),
    });
    return { exists: true, applied: result.applied, pending: [], pendingData: result.pendingData };
  } finally {
    db.close();
  }
}

/**
 * The snapshot taken before migrating a data directory (start step 7, goblin-admin migrate
 * --apply; the installer takes none of its own: the service it restarts takes it at start step
 * 7): pre-upgrade when `release` differs from `lastVersion` (the release
 * that last ran, null for data from before 1.5, whose snapshots are pinned: the way back to
 * 1.4.x), otherwise pre-migrate. The newest snapshot of the same kind already taken for this
 * release from the same version is reused while config.json and auth.json are still what it
 * holds, so a crash loop during a migration never fills the disk. Data changed since (a restore
 * of that snapshot, then changes under 1.4.x, then this release again) gets a snapshot of its
 * own. Only a start with steps pending calls this (startControl): after a code-only rollback,
 * control.sqlite stays migrated, so what 1.4.x writes before the next upgrade is in no snapshot,
 * and the newest pinned one holds the data as that first upgrading start found it. Returns null
 * when the directory holds no data yet (no entry by any of those names), else {id, reused}.
 *
 * `history` (default false) leaves history.sqlite out (D24): a control-database migration never
 * touches it, and copying it could fail on space (history grows until the filesystem keeps only
 * its reserve), outrun the installer's verification and stay pinned for ever. Restoring such a
 * snapshot keeps the live history.sqlite. A future migrateHistory() passes true when history
 * steps are pending.
 */
export async function takeMigrationSnapshot(
  directory,
  { release, lastVersion = null, clock = Date.now, history = false }
) {
  // Any entry counts, a symbolic link to nothing included (a volume that is not mounted), as in
  // openControl's `fresh`: read as no data, goblin-admin migrate --apply (which, unlike the start,
  // does not check config.json, auth.json or history.sqlite first) took no snapshot, created and
  // migrated control.sqlite, and the pinned way back to 1.4.x was never taken. createSnapshot
  // then refuses (live_file_unusable, exit 78), writing nothing, a link to nothing in place of a
  // file it copies; history.sqlite, left out here, is recorded as left out (a restore keeps it).
  const hasData = [...legacyDataFiles, controlFile].some(name =>
    entryExists(path.join(directory, name))
  );
  if (!hasData) return null;
  const reason = lastVersion === release ? 'pre-migrate' : 'pre-upgrade';
  // Only a folder named as createSnapshot names one: the id goes into a refusal's restore
  // command line, which an operator may copy into a root shell.
  const earlier = listSnapshots(directory).find(
    item =>
      item.valid &&
      isSnapshotId(item.id) &&
      item.reason === reason &&
      item.release === release &&
      (item.fromRelease ?? null) === lastVersion
  );
  if (earlier && (await unchangedSince(directory, earlier.id)))
    return { id: earlier.id, reused: true };
  const created = await createSnapshot(directory, {
    reason,
    release,
    fromRelease: lastVersion,
    history,
    clock,
    ...(reason === 'pre-upgrade' && isPre15(lastVersion) ? { pin: true } : {}),
  });
  return { id: created.id, reused: false };
}

/**
 * The refusal of a start without any admin password source, neither auth.json nor a non-empty
 * GOBLIN_PASSWORD (exit status 78): Uptime Goblin always requires one, and never generates it. server.mjs
 * refuses with it before the lock is taken or anything is written (to decide, it reads only
 * auth.json and GOBLIN_PASSWORD); startControl (`credentialConfigured: false`) and
 * bootstrapBuiltin refuse with it too, before their first write, for any other caller. Defined
 * here, where lib/identity/bootstrap.mjs takes it from, so that the refusals cannot drift apart.
 * docs/authentication.md quotes it word for word.
 */
export const passwordRequiredMessage =
  "Uptime Goblin needs an admin password, and none is set: the data directory has no auth.json, and GOBLIN_PASSWORD is not set or is empty. Set GOBLIN_PASSWORD (12 to 1024 characters) in Uptime Goblin's environment file (/etc/uptime-goblin.env for a native install, where the installer sets one; .env for npm start and Docker Compose), then start Uptime Goblin again. If Uptime Goblin had a password before, restore auth.json from a backup instead, or set GOBLIN_PASSWORD: it becomes the admin password and signs out every session.";

/**
 * bootstrapBuiltin's refusal of a start whose control.sqlite holds an admin password while
 * neither auth.json nor GOBLIN_PASSWORD is present (D4, roadmap X2). server.mjs and startControl
 * refuse every such start first, with passwordRequiredMessage; this is the backstop's text.
 */
export const localModeGuardMessage =
  'Uptime Goblin had an admin password, but neither auth.json nor GOBLIN_PASSWORD is present now, and Uptime Goblin does not start without one. Restore auth.json from a backup, or set GOBLIN_PASSWORD (it becomes the admin password and signs out every session), then start Uptime Goblin again.';

/**
 * The refusal of a start on a data directory whose snapshot restore was interrupted (`journal`
 * from interruptedRestore()): running the same restore again finishes it. goblin-admin status
 * and migrate --apply say the same, also from the 1.5 copy kept after a code rollback, when the
 * installed 1.4.x would start on the directory regardless (it knows nothing of the journal):
 * hence the release. From that copy the command names the copy itself (/opt/uptime-goblin holds 1.4.x,
 * which has no goblin-admin), and the service is kept disabled until the restore has finished,
 * as docs/installation.md does it, so that a reboot does not start 1.4.x on it either. The line
 * names the key file as a key command's does (`keyFile`: the one the start was given), since
 * restore-snapshot checks a keyring it brings back with the key in its own environment (review
 * F2v2: without it, the check found no key, or an older one left in the data directory).
 */
export function interruptedRestoreMessage({ snapshot, keepHistory = false }, { keyFile } = {}) {
  const lead =
    'was interrupted part way (a crash or a power loss), so the data directory may hold part of the snapshot and part of the files it replaced. Uptime Goblin 1.5 and later will not start on it; Orbit 1.4.x, after a code rollback, does not check, so keep it stopped as well.';
  const kept = fromKeptCopy();
  // From the copy a rollback kept, the service is the one of the layout 1.4.x runs on: orbit.service
  // on the Orbit layout, where the installer's rollback puts it (runningLayout).
  const { product, unit } = runningLayout();
  const stopped = kept
    ? `with ${product} stopped and its service disabled (sudo systemctl disable --now ${unit})`
    : 'with Uptime Goblin stopped';
  const then = kept
    ? `Then enable and start ${product} (sudo systemctl enable --now ${unit}).`
    : 'Then start Uptime Goblin.';
  return snapshot
    ? `A restore of snapshot ${snapshot} ${lead} Run the same restore again to finish it, ${stopped}: ${adminCommand(`restore-snapshot ${snapshot}${keepHistory ? ' --keep-history' : ''}`, { key: true, keyFile })}. ${then}`
    : `A snapshot restore ${lead} Its record cannot be read: list the snapshots (${adminCommand('snapshots')}) and run the restore again, ${stopped}. ${then}`;
}

/**
 * The line a start logs after it removed a restore's temporary copies (`leftovers` from
 * startControl), so the operator knows where the free space came from.
 */
export function restoreLeftoversRemovedMessage(leftovers) {
  const names = leftovers.flatMap(item => item.names);
  const bytes = leftovers.reduce((sum, item) => sum + item.bytes, 0);
  return `Removed ${names.join(', ')} (${(bytes / 2 ** 20).toFixed(1)} MiB) from the data directory: temporary copies of a snapshot's files that a restore stopped by a crash or a power loss left behind. No restore needed them any more.`;
}

// The temporary files of config.json, auth.json and created-by.json saves (<name>.<uuid>.tmp,
// lib/config.mjs, lib/identity/password.mjs and recordCreatedBy). Each save renames its own once
// it is complete and removes it when it fails, so one left behind belongs to a save that a crash
// or a power loss stopped: never completed, never acknowledged, and read by nothing.
const saveLeftoverPattern =
  /^(?:config|auth|created-by)\.json\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;

/**
 * Removes the temporary files of interrupted saves (saveLeftoverPattern) from the data directory
 * and returns their names. They hold the whole configuration, credentials included (or the
 * password's hash), and otherwise stayed for good, in every later backup of the directory. Only
 * regular files are removed (a save never makes anything else under these names). Call it only
 * under goblin.lock, before anything saves: no other Uptime Goblin 1.5 process is saving then.
 */
export function removeSaveLeftovers(directory) {
  const removed = [];
  for (const name of fs.readdirSync(directory)) {
    if (!saveLeftoverPattern.test(name)) continue;
    const file = path.join(directory, name);
    try {
      if (!fs.lstatSync(file).isFile()) continue;
      fs.unlinkSync(file);
      removed.push(name);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return removed;
}

/** The line a start logs after removeSaveLeftovers() removed `names` (never their contents). */
export const saveLeftoversRemovedMessage = names =>
  `Removed ${names.join(', ')} from the data directory: temporary files of saves that a crash or a power loss stopped before they completed. Nothing used them; they could hold credentials.`;

/**
 * The warning of a start on a data directory that other users of this host can list or enter
 * (mode `mode`): every file in it, snapshots included, is then protected by its own mode alone,
 * and a file a hand edit or a restore left readable (config.json, a snapshot copy) is open to
 * them. Native installs (systemd's StateDirectoryMode) and the image make it 0700; a warning,
 * not a chmod, since a bind mount may be shared with a backup account on purpose.
 */
export const dataDirectoryModeWarning = (directory, mode) =>
  `The data directory ${directory} is open to other users of this host (mode ${mode.toString(8).padStart(4, '0')}), so its files are protected only by their own modes. Make it private: chmod 700 ${directory}`;

// Removes snapshots/.staging-* folders. Only a process holding goblin.lock creates them, and
// createSnapshot removes its own on failure, so any found under the lock belong to a process
// that died mid-snapshot (kill -9, power loss); a crash loop would otherwise pile them up.
// .restoring-* folders are not touched here: they may hold the only copy of files an interrupted
// restore moved aside (removeEmptyRestoreFolders removes only empty ones). The same goes for the
// temporary files of restore journals (.restore-in-progress.json.<uuid>.tmp) that a crash
// stopped before their rename: the journal itself is only ever the renamed file.
const journalTemporaryPattern =
  /^\.restore-in-progress\.json\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;
function removeStaleStaging(directory) {
  const root = path.join(directory, snapshotsDirectory);
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  const removed = [];
  for (const entry of entries)
    if (
      (entry.isDirectory() && entry.name.startsWith('.staging-')) ||
      (entry.isFile() && journalTemporaryPattern.test(entry.name))
    ) {
      fs.rmSync(path.join(root, entry.name), { recursive: true, force: true });
      removed.push(entry.name);
    }
  return removed;
}

/**
 * The platform part of the start sequence (roadmap §2.2 steps 4, 5, 7 and 8; sessions spec
 * §3.1-§3.2). server.mjs calls it after it took goblin.lock and checked config.json, and before
 * identity starts and ConfigStore and Store open:
 *   1. Refuse (RefusalError 'snapshots_not_directory', exit 78) when snapshots/ is not a
 *      directory, and (RefusalError 'restore_interrupted') while a snapshot restore is
 *      unfinished (snapshots/.restore-in-progress.json, see restoreSnapshot). Inspect
 *      control.sqlite read-only. A refusal (an applied contract step this release does
 *      not know, a fence newer than it) throws RefusalError (exit 78). So does a start without
 *      an admin password: with `credentialConfigured: false` (neither auth.json nor a non-empty
 *      GOBLIN_PASSWORD), RefusalError 'password_required' with passwordRequiredMessage, whatever
 *      the data directory holds (meta.credentials_ever included): Uptime Goblin always requires one.
 *   2. The master key. With `keyring: 'required'` (the wave-1 behaviour, the default) the key
 *      is found or, when no keyring exists, generated (resolveKey). With `keyring: 'existing'`
 *      (tools; the sessions milestone's server, D2) a key is needed only when a keyring already
 *      exists: without one no key is resolved, read, generated or removed from `env`, and the
 *      result has `keyring: null`. With `keyring: 'deferred'` (server.mjs from the delivery
 *      milestone, delivery spec D6) the key sources are always resolved here, so
 *      GOBLIN_SECRET_KEY and GOBLIN_SECRET_KEY_PREVIOUS leave `env` and every key refusal
 *      (key_missing, key_mismatch, key_invalid, key_file_unreadable) comes before anything is
 *      written; nothing is generated. A keyring with no key throws KeyError key_missing, and a
 *      key that opens none of its data keys key_mismatch (both exit 78).
 *   Every refusal comes before anything is written: the data directory is left byte-identical
 *   (T11).
 *   3. Remove the temporary files of saves a crash stopped (removeSaveLeftovers),
 *      snapshots/.staging-* left by a process that died, and the temporary copies a
 *      snapshot restore that a crash stopped left in the data directory (removeRestoreLeftovers:
 *      a journal would have refused in step 1, so no restore needs them) and its empty
 *      snapshots/.restoring-* folders (removeEmptyRestoreFolders); then, when steps are
 *      pending and the directory holds data, take a snapshot without history.sqlite (D24):
 *      pre-upgrade when this release differs from the last one that ran (the first of data from
 *      before 1.5 is pinned), otherwise pre-migrate. A restart after a crash reuses the one
 *      already taken. `snapshot: false` skips it: an option for tests only, which no
 *      production caller passes (server.mjs takes the default).
 *   4. Open control.sqlite read-write and apply the pending steps, one unit each, reporting
 *      onProgress({phase: 'migrating', step, index, total}). A new control.sqlite records as
 *      created_by_release the release created-by.json names, or this one on a fresh directory;
 *      then, when meta.created_by_release is set and created-by.json is missing, write it.
 *   5. Open the keyring (when there is one, or one is required), creating missing data keys,
 *      and give it to settings. With 'deferred' and no keyring yet, nothing is created here:
 *      the result's createKeyring() does it once the caller (server.mjs, after identity has
 *      accepted the start) is sure the start goes on, so identity's own refusals also leave the
 *      data directory as it was. It generates <data>/secret.key when step 2 found no source,
 *      creates the keyring with the key, gives it to settings and zeroes the key; it runs once.
 *      discardKey() zeroes a key kept for it when the start is abandoned.
 * `signal` (an AbortSignal: a stop requested during the start) is checked before the snapshot,
 * after it and after the migration. An abort closes what was opened and throws the signal's
 * reason; a step already started completes (each step is one unit of work), and a snapshot
 * already taken is kept, so the next start reuses it.
 * Resolves {control (as openControl returns it; the caller closes it), keyring (null without
 * one), key: {source, file, fingerprint, warnings, needsRewrap, previous} | null (previous: the
 * previous key's fingerprint, or null), snapshot: {id, reused} | null, migration, leftovers: the
 * restore copies removed in step 3 ({id, names, bytes}; the server logs them), warnings:
 * messages the server logs (a data directory open to other users, the save leftovers removed,
 * created-by.json could not be written)}; with 'deferred' also
 * createKeyring (a function while there is no keyring, else null) and discardKey(). The master
 * key itself is not returned; its bytes are zeroed once the keyring holds its copy. Options:
 * lock (required), credentialConfigured (required: true or false, whether an admin password
 * source is configured; any other value, a missing one included, throws TypeError before any
 * file of the data directory is read), release, env, clock, snapshot, onProgress, keySources
 * ({credentialsDirectory, secretsDirectory}, for tests), keyring, signal and openControl's
 * options.
 */
export async function startControl(directory, options = {}) {
  const {
    lock,
    release = packageRelease(),
    env = process.env,
    clock = Date.now,
    snapshot = true,
    onProgress,
    keySources = {},
    keyring: keyringMode = 'required',
    credentialConfigured,
    signal = null,
    ...openOptions
  } = options;
  if (!lock?.held || path.dirname(lock.file) !== fs.realpathSync(directory))
    throw new TypeError('startControl needs goblin.lock held for this data directory');
  if (!['required', 'existing', 'deferred'].includes(keyringMode))
    throw new TypeError(`startControl: keyring must be 'required', 'existing' or 'deferred'`);
  // No default: a caller that does not say whether an admin password source is configured
  // starts nothing (default-deny), rather than passing for one that has a password.
  if (typeof credentialConfigured !== 'boolean')
    throw new TypeError('startControl needs credentialConfigured: true or false');
  const deferred = keyringMode === 'deferred';
  const { registry = defaultRegistry, steps = controlSteps } = openOptions;

  // 1. Refusals, reading only. snapshots/ must be a directory (a symbolic link to one
  // included): a file or a FIFO there, or a link to nothing or a loop of links, would fail
  // every later step the same way, so it is a refusal, not a start to retry.
  assertSnapshotsDirectory(directory);
  // An interrupted snapshot restore next: the directory may lack control.sqlite or auth.json
  // part way through one, which would otherwise pass for new data or for a password changed
  // outside Uptime Goblin (an import from GOBLIN_PASSWORD).
  const interrupted = interruptedRestore(directory);
  if (interrupted)
    throw new RefusalError(
      'restore_interrupted',
      interruptedRestoreMessage(interrupted, {
        keyFile: env.GOBLIN_SECRET_KEY_FILE ? path.resolve(env.GOBLIN_SECRET_KEY_FILE) : null,
      }),
      { snapshot: interrupted.snapshot }
    );
  // No admin password source: refused on any data directory, new or not, and whatever
  // meta.credentials_ever says (Uptime Goblin always requires a password). server.mjs refuses a start
  // without one before it calls startControl, so for it that refusal comes before the
  // interrupted restore's; this is the data layer's own backstop for any other caller, checked
  // after the interrupted restore, which can be why auth.json is missing.
  if (!credentialConfigured) throw new RefusalError('password_required', passwordRequiredMessage);
  // history.sqlite is opened only after the migration (lib/store.mjs, which checks it too): one
  // that is a FIFO or a directory, or a link to nothing, or with a FIFO for its journal, refuses
  // now, before anything is written. control.sqlite is checked as it is opened read-only below
  // (controlExists counts a link to nothing, so it is opened, and refused). Either holding a
  // trigger, a view or another catalog row Uptime Goblin does not write (plantedObjects) refuses too: a
  // trigger would run inside Uptime Goblin's writes.
  const history = path.join(directory, historyFile);
  assertDatabaseFiles(history);
  if (fs.existsSync(history)) {
    // Only a catalog that can be read decides here: a history.sqlite that is not a database
    // (damaged, or a 1.x file being replaced) is the history store's to report when it opens it.
    let catalog = null;
    try {
      const reader = openSqlite(history, { readOnly: true });
      try {
        catalog = await reader.catalog();
      } finally {
        reader.close();
      }
    } catch (error) {
      if (error?.refusal === true) throw error;
    }
    if (catalog) refusePlanted(historyFile, catalog);
  }
  let pending = planFromScratch({ steps, registry }).length,
    lastVersion = null,
    keyRows = [];
  if (controlExists(directory)) {
    const existing = openControl(directory, {
      readOnly: true,
      release,
      env: {},
      clock,
      registry,
      steps,
    });
    try {
      const state = await existing.inspect();
      if (state.refusal) throw state.refusal;
      refusePlanted(controlFile, await existing.db.catalog());
      pending = state.pending.filter(step => step.kind !== 'data').length;
      lastVersion = await existing.db.read(tx =>
        tableExists(tx, 'meta') ? metaOps.get(tx, 'last_version') : null
      );
      if (await existing.keyringStore.exists()) keyRows = await existing.keyringStore.list();
    } finally {
      existing.close();
    }
  }

  // 2. The key, and the keycheck against the stored data keys (still writing nothing). With
  // keyring 'existing' and no keyring, nothing is sealed, so no key is looked for (D2). With
  // 'deferred' the sources are always read (and the environment keys removed), but nothing is
  // generated before createKeyring().
  const needKey = keyringMode !== 'existing' || keyRows.length > 0;
  const found = needKey
    ? resolveKey({
        env,
        directory,
        keyringExists: keyRows.length > 0,
        ...(keyringMode === 'required' ? {} : { generate: false }),
        ...keySources,
      })
    : null;
  // The key kept for createKeyring() ('deferred' without a keyring) is zeroed by it or by
  // discardKey(), not when this returns.
  let kept = false;
  const wipe = () => {
    found?.key.fill(0);
    found?.previous?.fill(0);
  };
  try {
    // A refusal names the key files this start read, so its key rotate line runs as printed
    // (docs audit, keys 19); a key from elsewhere gets the installer's file, as before.
    if (keyRows.length)
      await Keyring.check(
        { list: async () => keyRows },
        {
          key: found.key,
          previous: found.previous,
          keyFile: found.source === 'file' ? path.resolve(found.file) : null,
          previousFile: found.previousFile ? path.resolve(found.previousFile) : null,
        }
      );
  } catch (error) {
    // A <data>/secret.key that the refused source outranked may be the key of this data (1.5
    // ran without that source, perhaps before a rollback to 1.4.x): the refusal names it.
    if (error?.code === 'key_mismatch')
      try {
        const note = await dataDirectoryKeyNote({ directory, found, rows: keyRows });
        if (note) error.message = `${error.message} ${note}`;
      } catch {}
    wipe();
    throw error;
  }

  // 3. Leftovers of a process that died (a snapshot's staging folder, a restore's temporary
  // copies, which can be as large as history.sqlite, a save's temporary file), then the
  // snapshot. A data directory open to others is said once per start.
  let taken = null,
    leftovers = [];
  const notes = [];
  try {
    signal?.throwIfAborted();
    const mode = fs.statSync(directory).mode & 0o777;
    if (mode & 0o077) notes.push(dataDirectoryModeWarning(directory, mode));
    const saves = removeSaveLeftovers(directory);
    if (saves.length) notes.push(saveLeftoversRemovedMessage(saves));
    removeStaleStaging(directory);
    leftovers = removeRestoreLeftovers(directory).map(({ id, names, bytes }) => ({
      id,
      names,
      bytes,
    }));
    // Empty, so not logged: nothing was in them, but `snapshots` listed each as an interrupted
    // restore's (and --verify failed) for as long as it stayed.
    removeEmptyRestoreFolders(directory);
    if (snapshot && pending)
      taken = await takeMigrationSnapshot(directory, { release, lastVersion, clock });
    signal?.throwIfAborted();
  } catch (error) {
    wipe();
    throw error;
  }

  // 4. and 5. Migrate, then open the keyring.
  let control;
  try {
    control = openControl(directory, { ...openOptions, release, env, clock });
    const migration = await control.migrate({
      snapshotHint: taken?.id,
      // A refusal's restore-snapshot line names the key file this start read, as its key lines do.
      keyFile: found?.source === 'file' ? path.resolve(found.file) : null,
      onProgress: progress => onProgress?.({ phase: 'migrating', ...progress }),
    });
    // created-by.json beside control.sqlite, so G2 outlives it (see createdByFile); this also
    // adds the file to a directory created before it existed. A failure is only a warning: the
    // file matters only once control.sqlite is gone, and it must not keep Uptime Goblin from starting.
    const warnings = [...notes];
    try {
      recordCreatedBy(directory, await control.meta.createdByRelease(), clock());
    } catch (error) {
      warnings.push(createdByWarning(error?.code || error?.name || 'Error'));
    }
    signal?.throwIfAborted();
    const common = { control, snapshot: taken, migration, leftovers, warnings };
    if (deferred && !keyRows.length) {
      control.attachKeyring(null);
      kept = Boolean(found);
      return {
        ...common,
        keyring: null,
        key: found ? keyInfo(found, false) : null,
        ...deferredKeyring(control, found, {
          env,
          directory,
          clock,
          keySources,
          release: () => (kept = false),
        }),
      };
    }
    if (!found) {
      control.attachKeyring(null);
      return { ...common, keyring: null, key: null };
    }
    const keyring = await Keyring.open(control.keyringStore, {
      key: found.key,
      previous: found.previous,
      clock,
    });
    control.attachKeyring(keyring);
    return {
      ...common,
      keyring,
      key: keyInfo(found, keyring.needsRewrap),
      ...(deferred ? { createKeyring: null, discardKey: () => {} } : {}),
    };
  } catch (error) {
    control?.close();
    kept = false;
    throw error;
  } finally {
    if (!kept) wipe();
  }
}

// What a start reports about its key: never the key, nor the previous key's bytes.
const keyInfo = (found, needsRewrap) => ({
  source: found.source,
  file: found.file ?? null,
  // The file GOBLIN_SECRET_KEY_PREVIOUS_FILE named, for the needs-rewrap warning's command line.
  previousFile: found.previousFile ?? null,
  fingerprint: found.fingerprint,
  warnings: found.warnings,
  needsRewrap,
  previous: found.previous ? keyFingerprint(found.previous) : null,
});

/**
 * startControl's createKeyring() and discardKey() for a 'deferred' start without a keyring.
 * `found` is the key step 2 resolved (kept, not yet zeroed), or null when no source exists.
 */
function deferredKeyring(control, found, { env, directory, clock, keySources, release }) {
  let state = 'pending'; // pending | running | done | discarded
  const wipe = () => {
    found?.key.fill(0);
    found?.previous?.fill(0);
    release();
  };
  return {
    /**
     * Creates the keyring (once identity has accepted the start): with the key step 2 found,
     * or a newly generated <data>/secret.key (fsynced) when there was none. Resolves {keyring,
     * key}; the key's bytes are zeroed once the keyring holds its copy. Runs once.
     */
    async createKeyring() {
      if (state !== 'pending')
        throw new TypeError(
          state === 'discarded'
            ? 'createKeyring(): the key was discarded'
            : 'createKeyring() runs once'
        );
      state = 'running';
      let key = found;
      try {
        // No source at step 2: generate one now (resolveKey finds any that appeared since).
        key ??= resolveKey({
          env,
          directory,
          keyringExists: false,
          generate: true,
          ...keySources,
        });
        const keyring = await Keyring.open(control.keyringStore, {
          key: key.key,
          previous: key.previous,
          clock,
        });
        control.attachKeyring(keyring);
        state = 'done';
        return { keyring, key: keyInfo(key, keyring.needsRewrap) };
      } catch (error) {
        state = 'done';
        throw error;
      } finally {
        key?.key.fill(0);
        key?.previous?.fill(0);
        wipe();
      }
    },
    /** Zeroes a key kept for createKeyring() when the start is abandoned; a no-op otherwise. */
    discardKey() {
      if (state !== 'pending') return;
      state = 'discarded';
      wipe();
    },
  };
}

/**
 * Whether the given control.sqlite (a copy: the native installer copies the live file and its
 * -wal into a private directory first) holds a keyring and, with `key` (a Buffer from parseKey,
 * and `previous`), whether that key opens it. Opened read-only through the Db wrapper. Resolves
 * {keyring: boolean, matches: boolean | null}: matches is null without a key or a keyring, false
 * for key_mismatch. Any read error rejects: the caller must treat it as "unknown", never as "no
 * keyring".
 */
export async function inspectKeyring(file, { key = null, previous = null } = {}) {
  const db = openSqlite(file, { readOnly: true, create: false });
  try {
    const rows = await db.read(tx => {
      // A copy torn while Uptime Goblin wrote (or damaged) fails here: every page is read and checked,
      // so a missing keyring page can never pass for "no keyring".
      const check = tx.all(sql`PRAGMA quick_check`).map(row => Object.values(row)[0]);
      if (check.length !== 1 || check[0] !== 'ok')
        throw Object.assign(new Error(`The database copy is damaged: ${check.join('; ')}`), {
          code: 'SQLITE_CORRUPT',
          class: 'fatal',
        });
      return tableExists(tx, 'keyring')
        ? tx.all(
            sql`SELECT ${id('kid')}, ${id('purpose')}, ${id('wrapped')}, ${id('created_at')}, ${id('retired_at')} FROM ${id('keyring')}`
          )
        : [];
    });
    if (!rows.length) return { keyring: false, matches: null };
    if (!key) return { keyring: true, matches: null };
    try {
      await Keyring.check({ list: async () => rows }, { key, previous });
      return { keyring: true, matches: true };
    } catch (error) {
      if (error?.code === 'key_mismatch') return { keyring: true, matches: false };
      throw error;
    }
  } finally {
    db.close();
  }
}

/**
 * The keyring rows ({kid, purpose, wrapped}) of the control.sqlite at `file`, read-only; [] without
 * a keyring table. restore-snapshot compares the keyring it brought back with the one it replaced
 * (docs audit, keys 9), and checks both with the key it was given, whose unwrapping binds each data
 * key to its purpose (review OPS-801-2). Any read error rejects.
 */
export async function readKeyringRows(file) {
  const db = openSqlite(file, { readOnly: true, create: false });
  try {
    return await db.read(tx =>
      tableExists(tx, 'keyring')
        ? tx.all(sql`SELECT ${id('kid')}, ${id('purpose')}, ${id('wrapped')} FROM ${id('keyring')}`)
        : []
    );
  } finally {
    db.close();
  }
}

/**
 * What Uptime Goblin's starts recorded in the control.sqlite at `file`, read-only: {restored, settings}.
 * `restored` is the stamp restore-snapshot puts on a database it brings back (meta.restored),
 * `settings` the identity_settings values named in `keys`, such as the stamp of the restore the
 * last start handled and which file that start found control.sqlite to be (builtin.restoreSeen
 * and builtin.controlFile: lib/identity/bootstrap.mjs names them, and it imports this file).
 * Each is null when absent, or when its table is. restore-snapshot tells by them whether the
 * keyring it replaced is the one Uptime Goblin last ran with (review OPS-801-2). Any read error rejects.
 */
export async function readStartRecords(file, keys = []) {
  const db = openSqlite(file, { readOnly: true, create: false });
  try {
    return await db.read(tx => {
      const settings = Object.fromEntries(keys.map(key => [key, null]));
      if (tableExists(tx, 'identity_settings'))
        for (const key of keys)
          settings[key] =
            tx.get(
              sql`SELECT ${id('value')} FROM ${id('identity_settings')} WHERE ${id('key')} = ${key}`
            )?.value ?? null;
      return {
        restored: tableExists(tx, 'meta') ? metaOps.get(tx, 'restored') : null,
        settings,
      };
    });
  } finally {
    db.close();
  }
}

export { SettingsError };
