// The audit service (audit spec §4): createAudit() records what identity, the HTTP pipeline,
// delivery and Uptime Goblin itself do, in the append-only, HMAC-chained audit_log of control.sqlite, and
// reads it back for the Audit log page, its exports and its integrity check.
//
//   const audit = createAudit({db: control.db, directory, release, mirror, retention, guard});
//   await audit.attach({keyring, instanceId});     // before identity whenever a keyring exists
//   identity: audit.record(tx, event)              // inside its own write unit (in-unit rows)
//   pipeline: const change = await audit.begin(request, {action, target}); … change.end({status})
//   await audit.start({config, passwordChangedAt}); … listen() … await audit.started({security})
//
// How each kind of change is recorded (D5): inside the unit of the change when it lives in
// control.sqlite (record); an attempt row before and a result row after a change outside it,
// failing closed when the attempt cannot be written (begin/end); one row before an export
// (single); one row after an operation, best effort (operation); Uptime Goblin's own events, best effort
// (system). A row that is best effort and cannot be written goes to stderr once as an
// audit.unwritten line and is never written later (D6); `state().unwritten` counts them for the
// Audit log page. While the disk is full, only the admin's own fail-closed and result rows are
// tried (D7). Every unit that wrote rows prints one checkpoint line for its newest row after it
// committed (D12), whatever GOBLIN_AUDIT_LOG says: the journal is what detects a cut end.
//
// Every write is done in a write unit whose callback may run twice (an error of class `retry`),
// so lines, open changes and the other in-memory state change only in tx.onCommit (D4).
import { setTimeout as sleep } from 'node:timers/promises';
import {
  ACTIONS,
  CLOCK_STEP_MS,
  CLOSE_MS,
  MAINTAIN_RUN_MS,
  MAX_ROWS,
  RETENTION_DEFAULT_DAYS,
  RETENTION_MAX_DAYS,
  RETENTION_MIN_DAYS,
  SNAPSHOT_ROWS_MAX,
  VALUE_MAX_CHARS,
  eventFrom,
} from './actions.mjs';
import { canonicalJSON, checkpointMac } from './chain.mjs';
import { auditError } from './errors.mjs';
import {
  AuditDefect,
  buildRow,
  checkpointLine,
  checkpointOf,
  cleanText,
  eventOfRow,
  metaOf,
  mirrorLine,
  planUnit,
  unwrittenCountsLine,
  unwrittenLine,
  writePlan,
} from './writer.mjs';
import { configDiff, configSnapshot as snapshotOf, sameContent } from './diff.mjs';
import { createAggregator } from './aggregate.mjs';
import { checkPrune, grouped, verifyAudit } from './verify.mjs';
import { exportAudit } from './export.mjs';
import { readList } from './view.mjs';
import { auditOps } from '../repo/audit.mjs';
import { drainChunks } from '../repo/chunks.mjs';
import { listSnapshots } from '../db/snapshot.mjs';
import { upgradeHistoryOf } from '../db/control.mjs';
import { serverLimits } from '../http/pipeline.mjs';
import { displaySessionLimits } from '../environment.mjs';

export { parseAuditQuery } from './view.mjs';

const DAY = 86400000;
// Review round 2: the most inbox rows another process inserted that a drain into an empty log
// chains (D8). A start before the keyring leaves a few (identity's bootstrap, a mirror failure);
// more are discarded with one gap row, so the inbox can never fill a log past the row cap, whose
// prune would sign a checkpoint covering every journal line printed before it.
const INBOX_FOREIGN_MAX = 100;
const MIRRORS = Object.freeze(['off', 'stdout', 'stdout-full']);
// A value from the environment as a warning may quote it: no control characters, 40 characters.
const quoted = value => cleanText(String(value), 40);

/**
 * GOBLIN_AUDIT_LOG (D13): {mirror, warning}. Unset or empty is off; any other value than off,
 * stdout or stdout-full, exactly so (`STDOUT` is another value), is off with the start warning.
 * server.mjs's auditSettings() reads both settings through these two (review round 1).
 */
export function auditLogSetting(value) {
  if (value === undefined || value === null || value === '')
    return { mirror: 'off', warning: null };
  if (MIRRORS.includes(value)) return { mirror: value, warning: null };
  return {
    mirror: 'off',
    warning: `GOBLIN_AUDIT_LOG must be off, stdout or stdout-full; it is set to ${quoted(value)}, so the audit log is not copied to Uptime Goblin's log.`,
  };
}

/**
 * GOBLIN_AUDIT_RETENTION_DAYS (D14, the maintainer's OD7: 90 days by default): {days, warning}. A whole
 * number outside 30–3650 is clamped with a warning; anything else gives 90 with a warning.
 */
export function retentionSetting(value) {
  if (value === undefined || value === null || value === '')
    return { days: RETENTION_DEFAULT_DAYS, warning: null };
  const text = String(value).trim();
  if (!/^[0-9]+$/.test(text))
    return {
      days: RETENTION_DEFAULT_DAYS,
      warning: `GOBLIN_AUDIT_RETENTION_DAYS must be a whole number of days from ${RETENTION_MIN_DAYS} to ${RETENTION_MAX_DAYS}; it is set to ${quoted(value)}, so Uptime Goblin keeps audit entries for ${RETENTION_DEFAULT_DAYS} days.`,
    };
  const days = Number(text);
  if (days >= RETENTION_MIN_DAYS && days <= RETENTION_MAX_DAYS) return { days, warning: null };
  const clamped = days < RETENTION_MIN_DAYS ? RETENTION_MIN_DAYS : RETENTION_MAX_DAYS;
  const shown = Number.isSafeInteger(days) ? String(days) : quoted(text);
  return {
    days: clamped,
    warning: `GOBLIN_AUDIT_RETENTION_DAYS must be from ${RETENTION_MIN_DAYS} to ${RETENTION_MAX_DAYS} days; it is ${shown}, so Uptime Goblin keeps audit entries for ${clamped} days.`,
  };
}

/**
 * The security settings from the environment as system.start records them (D30): booleans, the
 * proxy setting's text (200 characters) or null, the allowed hosts sorted (20, each 200
 * characters), whether a webhook is set (never its URL), the key source's name, the connections
 * one client may hold open at once (`maxConnectionsPerClient`, a whole number, only when given:
 * server.mjs always gives it; a stored snapshot without it reads as the default, see started())
 * and, only when there is one, `unlimited`: the resource limits (memory, cpu, pids, in that
 * order) Uptime Goblin runs without because GOBLIN_ALLOW_UNLIMITED allows it. A start without any such
 * limit has no `unlimited` key, as every start before it, so the upgrade reads as no change.
 * `displaySessionDays` and `displayIdleDays`, whole numbers, are a wall display's limits (B6
 * design §7.5), only when given, as `maxConnectionsPerClient`.
 */
export function securitySnapshot(security = {}) {
  const unlimited = ['memory', 'cpu', 'pids'].filter(
    name => Array.isArray(security.unlimited) && security.unlimited.includes(name)
  );
  const text = value =>
    typeof value === 'string' && value ? cleanText(value, VALUE_MAX_CHARS) : null;
  const hosts = Array.isArray(security.allowedHosts)
    ? security.allowedHosts
        .filter(host => typeof host === 'string' && host)
        .map(host => cleanText(host, VALUE_MAX_CHARS))
        .sort()
        .slice(0, 20)
    : [];
  return {
    legacyBasic: Boolean(security.legacyBasic),
    insecureHttpSessions: Boolean(security.insecureHttpSessions),
    trustProxy: text(security.trustProxy),
    allowedHosts: hosts,
    webhook: Boolean(security.webhook),
    keySource: text(security.keySource),
    ...(Number.isSafeInteger(security.maxConnectionsPerClient)
      ? { maxConnectionsPerClient: security.maxConnectionsPerClient }
      : {}),
    ...(unlimited.length ? { unlimited } : {}),
    ...Object.fromEntries(
      ['displaySessionDays', 'displayIdleDays']
        .filter(name => Number.isSafeInteger(security[name]))
        .map(name => [name, security[name]])
    ),
  };
}

// A wall display's limits when neither variable is set (B6 design §7.5).
const displayDefaults = displaySessionLimits({});
const displayDefaultDays = Object.freeze({
  displaySessionDays: displayDefaults.absoluteMs / 86400e3,
  displayIdleDays: displayDefaults.idleMs / 86400e3,
});

// The errors that are the storage's (D32): thrown into the caller's unit. Anything else inside
// another component's unit (a defect, a value out of range, a key the keyring lacks) is caught.
const storageClasses = new Set(['full', 'unavailable', 'retry', 'fatal', 'timeout', 'fenced']);
const driverCodes = new Set(['ERR_SQLITE_ERROR', 'ERR_INVALID_STATE', 'ERR_OUT_OF_RANGE']);
function isStorageError(error, dialect) {
  if (error instanceof AuditDefect) return false;
  const found =
    typeof error?.class === 'string'
      ? error.class
      : driverCodes.has(error?.code)
        ? dialect?.classify?.(error)
        : null;
  return storageClasses.has(found);
}

const parsed = text => {
  if (text === null || text === undefined) return null;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};
const orbitTarget = Object.freeze({ type: 'orbit', id: null, name: null });
const auditTarget = Object.freeze({ type: 'audit', id: null, name: null });

/**
 * The audit service (§4.1). Options: db (control.db), directory (the data directory, for the
 * snapshot manifests), release {version, build}, clock, mirror (GOBLIN_AUDIT_LOG, validated),
 * retention {days, maxRows}, guard (the storage guard), out (checkpoint and mirror lines), err
 * (audit.unwritten lines), log (warnings), wrapDb(db, purpose) (tests: the Db each own unit and
 * read uses).
 */
export function createAudit({
  db,
  directory = null,
  release = { version: null, build: null },
  clock = Date.now,
  mirror = 'off',
  retention = { days: RETENTION_DEFAULT_DAYS, maxRows: MAX_ROWS },
  guard = null,
  out = line => console.log(line),
  err = line => console.error(line),
  log = console,
  wrapDb = target => target,
} = {}) {
  if (!db || typeof db.write !== 'function' || typeof db.read !== 'function')
    throw new TypeError('createAudit needs the control database (control.db)');
  const mirrorMode = MIRRORS.includes(mirror) ? mirror : 'off';
  const kept = {
    days: Math.min(
      RETENTION_MAX_DAYS,
      Math.max(RETENTION_MIN_DAYS, retention?.days ?? RETENTION_DEFAULT_DAYS)
    ),
    maxRows:
      Number.isSafeInteger(retention?.maxRows) && retention.maxRows > 0
        ? retention.maxRows
        : MAX_ROWS,
  };

  // This process's start, as the audit saw it: no row the drain signs is older (review round 2).
  const since = clock();
  let keyring = null,
    instance = null,
    ready = false,
    closing = null,
    restoreWaiting = false,
    atAttach = { empty: false, cleanStop: false },
    unwritten = null,
    startConfig = null,
    startPassword,
    startedAt = null,
    verifying = null,
    clockWarned = null,
    uncheckedWarned = null,
    // The lowest revision of an applied configuration change whose result row was not written
    // (this process; review round 2). No later result moves the configuration keys to it or
    // past it, so the next start still records that change as config.changed-outside (D6).
    configLostFrom = null,
    // The after-snapshots of written results whose configuration keys were held back by an
    // earlier change still unsettled (independent review A3): at most the newest one between two
    // unsettled revisions, which the result that settles the earlier change publishes.
    heldBack = [],
    queue = Promise.resolve(); // prune and verification exclude each other (§4.7)
  // Independent review A3: the applied configuration changes whose result row is neither written nor
  // lost yet, as the seq of their attempt row → the revision of their after-snapshot. A change
  // is entered when it is noted (exclusive() notes it inside its turn, before the next queued
  // write starts), so a later result written while this one's result waits (its settle not
  // reached, or its unit sleeping between SQLite retries) cannot move the keys to or past it:
  // had this one then been lost, its change would be in neither a result row nor the drift
  // the next start records.
  const unsettled = new Map();
  const open = new Set(), // seqs of the changes begun and not ended (D19)
    remembered = new Set(), // ids of the inbox rows this process inserted (D8)
    inflight = new Set(),
    // The rows record() wrote in each attempt of another component's unit (D12: one checkpoint
    // line per unit). A retried attempt is a new transaction, so its rows start afresh.
    recordedIn = new WeakMap();

  const full = () => {
    try {
      return Boolean(guard?.state?.().full);
    } catch {
      return false;
    }
  };
  const unitDb = purpose => wrapDb(db, purpose);
  const macFor = kid => data => keyring.hmac('audit', data, kid).mac;
  const print = (sink, line) => {
    try {
      sink(line);
    } catch {}
  };
  const track = promise => {
    inflight.add(promise);
    promise.then(
      () => inflight.delete(promise),
      () => inflight.delete(promise)
    );
    return promise;
  };
  const exclusively = task => {
    const run = queue.then(task, task);
    queue = run.then(
      () => {},
      () => {}
    );
    return run;
  };

  // A row that could not be written: one stderr line at once, never retried (D6).
  function lose(events, error) {
    const now = clock();
    for (const event of events) print(err, unwrittenLine(event, error, { instance, now, clock }));
    if (!events.length) return;
    unwritten ??= { since: now, count: 0 };
    unwritten.count += events.length;
  }

  // After a unit committed: the mirror lines, one checkpoint line for its newest row, and the
  // restore it anchored (or found anchored).
  function committed(plan) {
    for (const row of plan.rows)
      if (mirrorMode !== 'off')
        print(out, mirrorLine(row, { instance, full: mirrorMode === 'stdout-full' }));
    const newest = plan.rows.at(-1);
    if (newest)
      try {
        const checkpoint = checkpointOf(newest, { instance, keyId: plan.kid });
        print(out, checkpointLine(checkpoint, checkpointMac(macFor(plan.kid), checkpoint)));
      } catch {}
    if (plan.restoreChecked) restoreWaiting = false;
  }

  // One own unit (§4.3) of `purpose` appending `events` (a list, or (tx) => list read in the
  // unit), with `meta(tx)` adding §3.4 keys read in the unit. Rejects with the failure.
  function ownUnit(purpose, events, { meta = null, after = null } = {}) {
    const kid = keyring.activeKid('audit');
    const mac = macFor(kid);
    return unitDb(purpose).write(tx => {
      const now = clock();
      const list = typeof events === 'function' ? events(tx) : events;
      const plan = planUnit(tx, list, { kid, mac, now, clock, restore: restoreWaiting, meta });
      writePlan(tx, plan, now);
      tx.onCommit(() => {
        committed(plan);
        after?.(plan);
      });
      return plan;
    });
  }

  // A best-effort unit: written, or its rows printed as unwritten. Not tried while the disk is
  // full (D7), except a result row (`whileFull`), which is the admin's own change.
  function bestEffort(
    purpose,
    events,
    { whileFull = false, meta = null, after = null, lines = events } = {}
  ) {
    if (!ready) {
      lose(lines, 'not_attached');
      return Promise.resolve(false);
    }
    if (!whileFull && full()) {
      lose(lines, 'storage_full');
      return Promise.resolve(false);
    }
    return track(
      ownUnit(purpose, events, { meta, after }).then(
        () => true,
        error => {
          lose(lines, error);
          return false;
        }
      )
    );
  }

  // A fail-closed unit (append, attempt, single): any failure is audit_unavailable (D6).
  async function failClosed(purpose, events, options) {
    if (!ready)
      throw new TypeError(`audit: no ${purpose} row before attach(): no request is served yet`);
    try {
      return await track(ownUnit(purpose, events, options));
    } catch (error) {
      throw auditError('audit_unavailable', { cause: error });
    }
  }

  // ---- aggregation (§4.5) ----------------------------------------------------------------------
  const aggregator = createAggregator({
    clock,
    full,
    // An aggregated row that cannot be written is counted into the next summary, not printed.
    write: event =>
      ready && !full()
        ? track(
            ownUnit('aggregate', [event]).then(
              () => true,
              () => false
            )
          )
        : Promise.resolve(false),
  });

  // ---- the inbox (D8) ------------------------------------------------------------------------
  const isPlain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  async function drain() {
    if (!ready || full()) return;
    let waiting;
    try {
      waiting = await unitDb('read').read(tx => auditOps.inboxAll(tx).length);
    } catch {
      return;
    }
    if (!waiting) return;
    const kid = keyring.activeKid('audit');
    const mac = macFor(kid);
    try {
      await track(
        unitDb('inbox').write(tx => {
          const now = clock();
          const rows = auditOps.inboxAll(tx);
          // Another process's rows are chained only into an empty log (a first start that
          // stopped before its keyring was made, or whose drain failed), and only a few
          // (review round 2): an empty log and a full inbox are what someone with the database
          // but not the key can make.
          const foreignTaken =
            auditOps.head(tx) === null &&
            auditOps.last(tx) === null &&
            rows.filter(row => !remembered.has(row.id)).length <= INBOX_FOREIGN_MAX;
          // Review round 2: a row's time comes from the database, so it is kept only within this
          // process's start and now: a planted row dated back would be the leading run of
          // expired rows, which the next prune would remove under a checkpoint Uptime Goblin signs, and
          // every journal line printed before it would then read covered.
          const timeOf = time =>
            Number.isSafeInteger(time) ? Math.min(Math.max(time, since), now) : time;
          const events = [],
            ids = [];
          let discarded = 0;
          for (const row of rows) {
            ids.push(row.id);
            const event = isPlain(row.event)
              ? { ...row.event, at: timeOf(row.time), meta: undefined }
              : null;
            let taken =
              event !== null &&
              (remembered.has(row.id) || foreignTaken) &&
              Object.hasOwn(ACTIONS, event.action) &&
              ACTIONS[event.action].inbox === true;
            if (taken)
              try {
                buildRow(event, clock);
              } catch {
                taken = false;
              }
            if (taken) events.push(event);
            else discarded += 1;
          }
          if (discarded)
            events.push({
              action: 'audit.gap',
              outcome: 'info',
              at: now,
              target: auditTarget,
              detail: { reason: 'inbox-discarded', count: discarded },
            });
          const plan = planUnit(tx, events, { kid, mac, now, clock, restore: restoreWaiting });
          writePlan(tx, plan, now);
          auditOps.inboxDelete(tx, ids);
          tx.onCommit(() => {
            committed(plan);
            for (const id of ids) remembered.delete(id);
          });
        })
      );
    } catch {
      // The rows stay; maintain() tries again while this process remembers them.
    }
  }

  // ---- start rows (§5.6) -----------------------------------------------------------------------
  const readMeta = keys =>
    unitDb('read').read(tx => Object.fromEntries(keys.map(key => [key, auditOps.meta(tx, key)])));
  // A start row: its own unit, best effort, not while the disk is full (D7): its marker then
  // stays, so a later start writes it.
  const startUnit = events => bestEffort('start', events);
  const metaOnly = sets =>
    full()
      ? Promise.resolve(false)
      : track(
          unitDb('start').write(tx => {
            const now = clock();
            for (const [key, value] of sets) auditOps.setMeta(tx, key, value, now);
          })
        );
  // Whether the keyring holds the audit key `kid` (a lost-key reset removes the old ones).
  const holds = kid => {
    try {
      keyring.hmac('audit', '', kid);
      return true;
    } catch {
      return false;
    }
  };
  const snapshotWith = (value, kid) => snapshotOf(value, { kid, mac: macFor(kid) });

  // 1. system.upgrade: the releases that opened the data since the last audited start.
  async function upgradeStep() {
    const facts = await readMeta(['upgrade_history', 'audit_release_marker']);
    // Saved text: only well-formed entries, the newest 50, reach the log (upgradeHistoryOf).
    const entries = upgradeHistoryOf(facts.upgrade_history);
    if (!entries.length) return;
    const marker = facts.audit_release_marker === null ? null : parsed(facts.audit_release_marker);
    let after,
      markerLost = false;
    if (facts.audit_release_marker === null) after = [entries.at(-1)];
    else {
      const index = isPlain(marker)
        ? entries.findLastIndex(entry => entry.to === marker.to && entry.at === marker.at)
        : -1;
      if (index < 0) {
        after = entries;
        markerLost = true;
      } else after = entries.slice(index + 1);
    }
    if (!after.length) return;
    const newest = entries.at(-1);
    await startUnit([
      {
        action: 'system.upgrade',
        outcome: 'info',
        target: orbitTarget,
        detail: { release: release?.version ?? null, entries: after, markerLost },
        meta: { audit_release_marker: canonicalJSON({ to: newest.to, at: newest.at }) },
      },
    ]);
  }

  // 2. data.snapshot: the snapshot manifests newer than the marker (20 at most).
  async function snapshotStep() {
    if (!directory) return;
    let manifests;
    try {
      manifests = listSnapshots(directory)
        .filter(
          item => item.valid && typeof item.id === 'string' && Number.isSafeInteger(item.createdAt)
        )
        .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    } catch {
      return;
    }
    const newest = manifests.at(-1);
    // With no snapshot the baseline is before every snapshot, so the first one taken after this
    // start is recorded at the next.
    const markerValue = canonicalJSON(
      newest ? { createdAt: newest.createdAt, id: newest.id } : { createdAt: 0, id: '' }
    );
    const facts = await readMeta(['audit_snapshot_seen']);
    // Without a marker the snapshots predate the log: only the marker is set.
    if (facts.audit_snapshot_seen === null) return metaOnly([['audit_snapshot_seen', markerValue]]);
    if (!manifests.length) return;
    const marker = parsed(facts.audit_snapshot_seen);
    const newer = manifests.filter(item =>
      !isPlain(marker) || !Number.isSafeInteger(marker.createdAt)
        ? true
        : item.createdAt > marker.createdAt ||
          (item.createdAt === marker.createdAt && item.id > String(marker.id))
    );
    if (!newer.length) return;
    const shown = newer.slice(-SNAPSHOT_ROWS_MAX),
      left = newer.length - shown.length;
    const events = shown.map((item, index) => ({
      action: 'data.snapshot',
      outcome: 'info',
      target: { type: 'snapshot', id: item.id, name: null },
      detail: {
        reason:
          typeof item.reason === 'string' && /^[a-z][a-z0-9-]{0,31}$/.test(item.reason)
            ? item.reason
            : null,
        createdAt: item.createdAt,
        ...(index === shown.length - 1 && left ? { more: left } : {}),
      },
    }));
    events.at(-1).meta = { audit_snapshot_seen: markerValue };
    await startUnit(events);
  }

  // 3. config.changed-outside: the configuration's content (not its revision) differs from what
  // the log last recorded: a hand edit, a repair at load, or a write by a build without the log.
  async function configStep() {
    const value = startConfig?.value;
    if (!value) return;
    const facts = await readMeta([
      'config_revision_seen',
      'audit_config_public',
      'audit_config_secrets',
    ]);
    if (facts.audit_config_public === null) return;
    const before = {
      public: parsed(facts.audit_config_public) ?? {},
      secrets: parsed(facts.audit_config_secrets) ?? {},
    };
    const activeKid = keyring.activeKid('audit');
    const storedKid = typeof before.secrets?.key_id === 'string' ? before.secrets.key_id : null;
    const comparable = storedKid !== null && holds(storedKid);
    const current = snapshotWith(value, comparable ? storedKid : activeKid);
    if (sameContent(before, current)) return;
    const fresh = comparable && storedKid === activeKid ? current : snapshotWith(value, activeKid);
    const baseline = {
      config_revision_seen: String(value.revision ?? 0),
      audit_config_public: canonicalJSON(fresh.public),
      audit_config_secrets: canonicalJSON(fresh.secrets),
    };
    const diff = configDiff(before, current);
    if (!diff.length) return metaOnly(Object.entries(baseline));
    const seen = Number(facts.config_revision_seen);
    await startUnit([
      {
        action: 'config.changed-outside',
        outcome: 'info',
        target: { type: 'config', id: null, name: null },
        configRevision: Number.isSafeInteger(value.revision) ? value.revision : null,
        detail: {
          from: Number.isSafeInteger(seen) && facts.config_revision_seen !== null ? seen : null,
          to: Number.isSafeInteger(value.revision) ? value.revision : null,
          diff,
          repaired: startConfig.repaired === true,
        },
        meta: baseline,
      },
    ]);
  }

  // 4. account.password.changed-outside: the admin's password-change time moved without an
  // audited change (an earlier 1.5 build changed it in-app).
  async function passwordStep() {
    if (startPassword === undefined) return;
    const facts = await readMeta(['audit_password_changed_at']);
    if (facts.audit_password_changed_at === null) return;
    const current = startPassword === null ? '' : String(startPassword);
    if (facts.audit_password_changed_at === current) return;
    await startUnit([
      {
        action: 'account.password.changed-outside',
        outcome: 'info',
        target: { type: 'account', id: 'u_admin', name: null },
        detail: { source: 'control.sqlite' },
        meta: { audit_password_changed_at: current },
      },
    ]);
  }

  // ---- the prune (§4.7) ------------------------------------------------------------------------
  async function prune(ctx = {}) {
    const now = clock();
    const facts = await unitDb('read').read(tx => {
      const first = auditOps.first(tx),
        last = auditOps.last(tx),
        head = auditOps.head(tx);
      return {
        first,
        last,
        head,
        newest: last ? (auditOps.rowAt(tx, last.seq)?.time ?? null) : null,
      };
    });
    const { first, last, head } = facts;
    if (!first || !last) return;
    const window = kept.days * DAY;
    const needAge = first.time < now - window - DAY;
    const needCap = last.seq - first.seq + 1 > kept.maxRows + 1000;
    if (!needAge && !needCap) return;
    // A clock more than an hour behind the newest row would make every row look recent, or a
    // step back and forth expire rows early: the age part waits for a sane clock (D14).
    const behind = facts.newest !== null && now < facts.newest - CLOCK_STEP_MS;
    if (behind && needAge) {
      const day = Math.floor(now / DAY);
      if (clockWarned !== day) {
        clockWarned = day;
        try {
          log.warn?.(
            `Uptime Goblin's clock is behind its newest audit entry, so it did not remove audit entries older than ${kept.days} days this time. Check the time of the Uptime Goblin host.`
          );
        } catch {}
      }
    }
    const headSeq = Math.max(head?.seq ?? 0, last.seq);
    const target = await unitDb('read').read(tx => {
      const { age, cap } = auditOps.pruneTarget(tx, {
        cutoff: now - window,
        maxRows: kept.maxRows,
      });
      // Once a prune runs, for either reason, both targets apply (§4.7: P = max(P_age, P_cap));
      // the 1,000 rows above the cap only decide whether the cap starts one.
      const pAge = behind ? 0 : (age ?? headSeq - 1);
      // Never the newest stored row: the next row links to it. A head ahead of the rows (a cut
      // end) would otherwise let the prune delete every row, and with them the evidence.
      const through = auditOps.atOrBelow(tx, Math.min(Math.max(pAge, cap), last.seq - 1));
      // The reason names what removed rows: expired ones, rows beyond the cap, or both.
      const aged = pAge >= first.seq,
        capped = cap > pAge && cap >= first.seq;
      return { through, reason: aged && capped ? 'both' : capped ? 'cap' : 'age' };
    });
    const through = target.through;
    if (through === null || through < first.seq) return;
    // Review round 1: the entries it removes are checked first, as verification checks them,
    // since the times that chose them are not what signs them: someone with the database but not
    // the key who set the oldest entries' time back would otherwise have Uptime Goblin sign a checkpoint
    // over them, and what remains would read intact. One that does not check stops the prune,
    // with one warning a UTC day; Check integrity shows it.
    const checked = await checkPrune(unitDb('read'), { keyring, through });
    if (checked.unchecked !== null) {
      const day = Math.floor(now / DAY);
      if (uncheckedWarned !== day) {
        uncheckedWarned = day;
        try {
          log.warn?.(
            `Uptime Goblin did not remove old audit entries, because entry #${grouped(checked.unchecked)} does not check: use Check integrity on the Audit log page.`
          );
        } catch {}
      }
      return;
    }
    // Unit 1: the prune checkpoint, stored and printed before anything is deleted, so what
    // remains always starts from a checkpoint (§6.4 step 1). If it fails, nothing is deleted.
    const kid = keyring.activeKid('audit');
    await unitDb('prune').write(tx => {
      const row = auditOps.rowAt(tx, through);
      if (!row) throw new Error('The prune target is gone');
      // The entry the check read, not one changed since.
      if (row.hash !== checked.hash || row.time !== checked.time)
        throw new Error('The prune target changed');
      const checkpoint = {
        seq: through,
        time: row.time,
        hash: row.hash,
        key_id: kid,
        reason: 'prune',
      };
      // A stored checkpoint has no instance column: its MAC covers meta.instance_id, which is
      // what verification signs it with again.
      const stored = auditOps.meta(tx, 'instance_id') ?? instance;
      const mac = checkpointMac(macFor(kid), { ...checkpoint, instance: stored });
      if (!auditOps.hasCheckpoint(tx, through))
        auditOps.insertCheckpoint(tx, { ...checkpoint, mac });
      tx.onCommit(() => print(out, checkpointLine({ ...checkpoint, instance: stored }, mac)));
    });
    const stop = new AbortController();
    const timer = setTimeout(() => stop.abort(), MAINTAIN_RUN_MS);
    timer.unref?.();
    const onAbort = () => stop.abort();
    ctx.signal?.addEventListener?.('abort', onAbort, { once: true });
    let deleted = 0;
    try {
      const pruneDb = unitDb('prune');
      deleted = await drainChunks(
        {
          dialect: db.dialect,
          // The jobs runner's slices: commit, then yield when asked (lib/jobs.mjs).
          async write(fn) {
            if (ctx.shouldYield?.()) await ctx.yieldNow?.();
            return pruneDb.write(fn);
          },
        },
        auditOps.deleteThrough(db.dialect, through),
        { dialect: db.dialect, signal: stop.signal }
      );
      await pruneDb.write(tx => auditOps.deleteCheckpointsBefore(tx, through));
    } finally {
      clearTimeout(timer);
      ctx.signal?.removeEventListener?.('abort', onAbort);
    }
    await service.system({
      action: 'audit.pruned',
      outcome: 'info',
      target: auditTarget,
      detail: { through, deleted, reason: target.reason },
    });
  }

  // ---- the service (§4.1; its method names are noopAudit()'s, in that order) ------------------
  const noted = (current, values) => {
    const { detail: more, ...rest } = values ?? {};
    return { ...current, ...rest, detail: { ...current.detail, ...more } };
  };

  // ---- the configuration keys of result rows (§3.4, D6) ----------------------------------------
  // The after-snapshot a change's result row moves the configuration keys towards: that of a
  // change noted as applied, with both snapshots and a revision; null otherwise.
  const forwardOf = notes =>
    notes.before &&
    notes.after &&
    notes.applied === true &&
    Number.isSafeInteger(notes.after.revision)
      ? notes.after
      : null;
  // The §3.4 keys of an after-snapshot, as [[key, text]].
  const keysOf = snapshot => [
    ['config_revision_seen', String(snapshot.revision)],
    ['audit_config_public', canonicalJSON(snapshot.public)],
    ['audit_config_secrets', canonicalJSON(snapshot.secrets)],
  ];
  // A held-back snapshot ({revision, keys}) is kept while it can still be published: below the
  // lowest lost revision, and the newest of those between two unsettled revisions (the result
  // that settles the lower one publishes the newest it may, so an older one is never needed).
  const keepHeld = () => {
    const waits = [...unsettled.values()];
    const below = heldBack.filter(
      held => configLostFrom === null || held.revision < configLostFrom
    );
    heldBack = below.filter(
      held =>
        !below.some(
          other =>
            other.revision > held.revision &&
            !waits.some(revision => revision > held.revision && revision <= other.revision)
        )
    );
  };
  // Read in the unit of the result row of change `own` (the seq of its attempt row), whose
  // after-snapshot is `forward`: {limit, keys}, the keys the unit sets ([] for none). They move
  // only forward by revision (§3.4, IMP-5), and never to or past `limit`, the lowest revision of
  // a change whose result row was lost (review round 2) or is not settled yet (independent review A3).
  // They are those of the newest of `forward` and the held-back snapshots below `limit`: the
  // change that settles last publishes what the later ones held back.
  const keysFor = (tx, own, forward) => {
    let limit = configLostFrom ?? Infinity;
    for (const [seq, revision] of unsettled) if (seq !== own && revision < limit) limit = revision;
    let newest = forward.revision < limit ? { revision: forward.revision, keys: null } : null;
    for (const held of heldBack)
      if (held.revision < limit && (newest === null || held.revision > newest.revision))
        newest = held;
    if (newest === null) return { limit, keys: [] };
    const seenText = auditOps.meta(tx, 'config_revision_seen');
    const seen = Number(seenText);
    if (seenText !== null && Number.isSafeInteger(seen) && seen >= newest.revision)
      return { limit, keys: [] };
    return { limit, keys: newest.keys ?? keysOf(forward), revision: newest.revision };
  };
  // After the result row of change `own` committed (`set` is what keysFor() gave its unit):
  // settled, and `forward` held back when it was at or past the limit.
  const resultWritten = (own, forward, set) => {
    unsettled.delete(own);
    if (!forward || !set) return;
    if (set.revision !== undefined)
      heldBack = heldBack.filter(held => held.revision > set.revision);
    if (forward.revision >= set.limit)
      try {
        heldBack.push({ revision: forward.revision, keys: keysOf(forward) });
      } catch {
        // Not publishable: the keys stay behind it, and the next start records it as drift.
      }
    keepHeld();
  };
  // The result row of change `own` was not written: settled, and its revision lost.
  const resultLost = own => {
    if (!unsettled.has(own)) return;
    const revision = unsettled.get(own);
    unsettled.delete(own);
    configLostFrom = Math.min(configLostFrom ?? revision, revision);
    keepHeld();
  };

  const service = {
    async attach({ keyring: given, instanceId = null } = {}) {
      try {
        if (!given) return;
        keyring = given;
        instance = instanceId ?? null;
        try {
          const facts = await unitDb('read').read(tx => {
            const { restored, seen } = auditOps.restoreState(tx);
            const head = auditOps.head(tx),
              last = auditOps.last(tx);
            return {
              waiting: restored !== null && restored !== seen,
              empty: head === null && last === null,
              // Uptime Goblin's own newest row: goblin-admin key rotate, rewrap and reset run while
              // Uptime Goblin is stopped, so their rows follow a clean stop's system.stop.
              lastAction: last === null ? null : auditOps.lastOwnAction(tx),
            };
          });
          restoreWaiting = facts.waiting;
          atAttach = { empty: facts.empty, cleanStop: facts.lastAction === 'system.stop' };
        } catch {
          // Treated as nothing waiting: the units that append read the restore state again
          // only while one waits, and goblin-admin's key commands always do.
          restoreWaiting = false;
        }
        ready = true;
        await drain();
      } catch {
        // attach() never rejects: a start never fails on the audit.
      }
    },

    record(tx, event) {
      if (!tx || typeof tx.onCommit !== 'function') return lose([event], 'no_unit');
      if (!ready) {
        // Before the keyring exists (a data directory's first start): the inbox, in the caller's
        // unit, with the event's meta keys; attach() chains it once the keyring exists.
        let row, sets;
        try {
          row = buildRow(event, clock);
          sets = metaOf(event);
        } catch (error) {
          tx.onCommit(() => lose([event], error));
          return;
        }
        const now = clock();
        const id = auditOps.inboxInsert(tx, {
          time: row.time,
          source: 'start',
          event: eventOfRow(row),
        });
        for (const [key, value] of sets) auditOps.setMeta(tx, key, value, now);
        tx.onCommit(() => remembered.add(id));
        return;
      }
      const now = clock();
      let plan;
      try {
        const kid = keyring.activeKid('audit');
        plan = planUnit(tx, [event], {
          kid,
          mac: macFor(kid),
          now,
          clock,
          restore: restoreWaiting,
        });
      } catch (error) {
        // D32: only a storage error fails the caller's change; anything else is one stderr line
        // once the caller's unit commits (none when it rolls back).
        if (isStorageError(error, tx.dialect)) throw error;
        // A driver's error inside the callback has no class yet: the line names it.
        const named = driverCodes.has(error?.code)
          ? { class: tx.dialect?.classify?.(error) ?? 'fatal' }
          : error;
        tx.onCommit(() => lose([event], named));
        return;
      }
      writePlan(tx, plan, now);
      // A unit that records several rows (a sign-out of several sessions, a whole-file restore's
      // anchor and sign-out) prints one checkpoint line, for its newest row (D12): its rows
      // share the commit callback the first record() registered.
      let unit = recordedIn.get(tx);
      if (!unit) {
        unit = { rows: [], kid: plan.kid, restoreChecked: false };
        recordedIn.set(tx, unit);
        tx.onCommit(() => committed(unit));
      }
      unit.rows.push(...plan.rows);
      unit.kid = plan.kid;
      unit.restoreChecked ||= Boolean(plan.restoreChecked);
    },

    unrecorded(event, error) {
      lose([event], error);
    },

    async append(event) {
      const plan = await failClosed('append', [event]);
      return { seq: plan.rows.at(-1).seq };
    },

    async system(event) {
      if (ready) {
        await bestEffort('system', [event]);
        return;
      }
      // Before the keyring exists: an inbox row in its own unit, best effort.
      if (full()) return lose([event], 'storage_full');
      let row, sets;
      try {
        row = buildRow(event, clock);
        sets = metaOf(event);
      } catch (error) {
        return lose([event], error);
      }
      try {
        await track(
          unitDb('system').write(tx => {
            const now = clock();
            const id = auditOps.inboxInsert(tx, {
              time: row.time,
              source: 'start',
              event: eventOfRow(row),
            });
            for (const [key, value] of sets) auditOps.setMeta(tx, key, value, now);
            tx.onCommit(() => remembered.add(id));
          })
        );
      } catch (error) {
        lose([event], error);
      }
    },

    count(event) {
      aggregator.count(event);
    },

    async begin(request, { action, target, detail, configRevision } = {}) {
      const attempt = eventFrom(request, {
        action,
        outcome: 'attempt',
        target,
        detail,
        configRevision,
      });
      const plan = await failClosed('attempt', [attempt], {
        after: committedPlan => open.add(committedPlan.rows.at(-1).seq),
      });
      const row = plan.rows.at(-1);
      let notes = {},
        ended = false;
      // Independent review A3: an applied change is unsettled from its note to its result's settle.
      const unsettle = forward => {
        if (forward) unsettled.set(row.seq, forward.revision);
        else unsettled.delete(row.seq);
      };
      return Object.freeze({
        seq: row.seq,
        note(values) {
          notes = noted(notes, values);
          if (!ended) unsettle(forwardOf(notes));
        },
        async end({ status = null, outcome = null, code = null } = {}) {
          if (ended) return;
          ended = true;
          try {
            const merged = { ...(row.detail ?? {}), ...notes.detail };
            if (code && merged.code === undefined) merged.code = code;
            if (notes.before && notes.after)
              try {
                const diff = configDiff(notes.before, notes.after);
                if (diff.length) merged.diff = diff;
              } catch {}
            const forward = forwardOf(notes);
            unsettle(forward);
            const result = {
              action: row.action,
              outcome: notes.outcome ?? outcome ?? (notes.applied === true ? 'ok' : null),
              actor: attempt.actor,
              client: attempt.client,
              userAgent: attempt.userAgent,
              requestId: attempt.requestId,
              target: notes.target ?? attempt.target,
              status: notes.status ?? status,
              ref: row.seq,
              detail: Object.keys(merged).length ? merged : null,
              configRevision: notes.configRevision ?? row.config_revision,
            };
            // The configuration keys move only forward by revision (§3.4): the results of
            // queued writes, written after their answers, never move them back. Nor to or past
            // a change whose result row was lost (review round 2), or is not settled yet (independent
            // review A3): a later after-snapshot holds that change, so the next start would
            // find nothing to record. A result held back so is published by the one that
            // settles the earlier change, when it is written (keysFor()).
            let set = null;
            const meta = forward
              ? tx => {
                  set = keysFor(tx, row.seq, forward);
                  return set.keys;
                }
              : null;
            await bestEffort('result', [result], {
              whileFull: true,
              meta,
              after: () => resultWritten(row.seq, forward, set),
            });
          } catch {
            // end() never rejects (D6).
          } finally {
            open.delete(row.seq);
            // Not written (lost, or never tried): no later result moves the keys to or past it.
            resultLost(row.seq);
          }
        },
      });
    },

    // The row is written right before the answer it precedes, which is the 200 that sends the
    // export (the contract's list.more shows it so); a failure here means no answer at all.
    async single(request, { action, target, detail } = {}) {
      await failClosed('single', [
        eventFrom(request, { action, outcome: 'ok', status: 200, target, detail }),
      ]);
    },

    operation(request, { action, target, detail } = {}) {
      if (!ready)
        throw new TypeError('audit: no operation row before attach(): no request is served yet');
      let notes = {},
        ended = false;
      return Object.freeze({
        note(values) {
          notes = noted(notes, values);
        },
        async end({ status = null, outcome = null, code = null } = {}) {
          if (ended) return;
          ended = true;
          try {
            const merged = { ...(detail ?? {}), ...notes.detail };
            if (code && merged.code === undefined) merged.code = code;
            await bestEffort('operation', [
              eventFrom(request, {
                action,
                outcome: notes.outcome ?? outcome,
                target: notes.target ?? target,
                status: notes.status ?? status,
                detail: Object.keys(merged).length ? merged : null,
              }),
            ]);
          } catch {}
        },
      });
    },

    configSnapshot(value) {
      if (!keyring) throw new TypeError('audit.configSnapshot() before attach()');
      return snapshotWith(value, keyring.activeKid('audit'));
    },

    // passwordChangedAt: identity.metadata().passwordChangedAt (a time, or null for none). Not
    // given, the password is not compared (nothing to compare it with).
    async start({ config = null, passwordChangedAt } = {}) {
      startConfig = config;
      startPassword = passwordChangedAt;
      if (!ready) return;
      for (const step of [upgradeStep, snapshotStep, configStep, passwordStep])
        try {
          await step();
        } catch {
          // A start never fails on the audit; a step that failed writes at a later start.
        }
    },

    async started({ security = {} } = {}) {
      try {
        if (!ready) return;
        const snapshot = securitySnapshot(security);
        const value = startConfig?.value ?? null;
        const revision = Number.isSafeInteger(value?.revision) ? value.revision : null;
        const event = {
          action: 'system.start',
          outcome: 'info',
          target: orbitTarget,
          configRevision: revision,
          detail: {
            version: release?.version ?? null,
            build: release?.build ?? null,
            first: atAttach.empty,
            cleanStop: atAttach.cleanStop,
            configRevision: revision,
            security: snapshot,
          },
        };
        // Read in the unit: the security settings last recorded (D30), and the baselines the
        // first audited start sets (§3.4).
        const events = tx => {
          const sets = { audit_security_seen: canonicalJSON(snapshot) };
          const seenText = auditOps.meta(tx, 'audit_security_seen');
          let securityChanged;
          if (seenText !== null) {
            const parsedSeen = parsed(seenText);
            const seen = isPlain(parsedSeen) ? { ...parsedSeen } : {};
            // A key generated at a start is <data>/secret.key, which every later start reads
            // as 'data-directory': the same key from the same place, not a changed setting.
            if (seen.keySource === 'generated') seen.keySource = 'data-directory';
            // A start of a 1.5 build before the per-client connection share was recorded stored
            // no `maxConnectionsPerClient`: it reads as the default share, so the upgrade with
            // GOBLIN_MAX_CONNECTIONS_PER_CLIENT unset is no change, and one set to another value
            // reads as changed from the default (the earlier build did not say what it applied).
            if (!Object.hasOwn(seen, 'maxConnectionsPerClient'))
              seen.maxConnectionsPerClient = serverLimits.maxConnectionsPerClient;
            // Likewise a wall display's limits, recorded from the build that brought displays:
            // before it, the defaults would have applied.
            for (const [name, days] of Object.entries(displayDefaultDays))
              if (!Object.hasOwn(seen, name)) seen[name] = days;
            // `unlimited` is in a snapshot only while Uptime Goblin runs without a limit, so its going is
            // a change too. (Only these names: the stored snapshot is data, not a list of names.)
            securityChanged = [...new Set([...Object.keys(snapshot), 'unlimited'])]
              .filter(
                name => canonicalJSON(seen[name] ?? null) !== canonicalJSON(snapshot[name] ?? null)
              )
              .sort();
          }
          if (value) {
            const storedPublic = auditOps.meta(tx, 'audit_config_public');
            if (storedPublic === null) {
              const current = service.configSnapshot(value);
              sets.config_revision_seen = String(revision ?? 0);
              sets.audit_config_public = canonicalJSON(current.public);
              sets.audit_config_secrets = canonicalJSON(current.secrets);
            } else if (auditOps.meta(tx, 'config_revision_seen') !== String(revision ?? 0)) {
              // Only the revision moved (start() found the content unchanged): follow it.
              const stored = {
                public: parsed(storedPublic) ?? {},
                secrets: parsed(auditOps.meta(tx, 'audit_config_secrets')) ?? {},
              };
              const kid =
                typeof stored.secrets?.key_id === 'string' && holds(stored.secrets.key_id)
                  ? stored.secrets.key_id
                  : keyring.activeKid('audit');
              if (sameContent(stored, snapshotWith(value, kid)))
                sets.config_revision_seen = String(revision ?? 0);
            }
          }
          if (
            startPassword !== undefined &&
            auditOps.meta(tx, 'audit_password_changed_at') === null
          )
            sets.audit_password_changed_at = startPassword === null ? '' : String(startPassword);
          return [
            {
              ...event,
              detail: { ...event.detail, ...(securityChanged ? { securityChanged } : {}) },
              meta: sets,
            },
          ];
        };
        await bestEffort('start', events, {
          lines: [event],
          after: () => {
            startedAt = clock();
          },
        });
      } catch {}
    },

    async maintain(ctx = {}) {
      try {
        if (!ready) return;
        // A summary whose timer was missed (a clock that jumped) is written by the hourly job.
        await aggregator.flush();
        if (remembered.size) await drain();
        if (full()) return;
        await exclusively(() => prune(ctx));
      } catch {
        // The next run continues where this one stopped.
      }
    },

    async list(query) {
      try {
        return await unitDb('read').read(tx =>
          readList(tx, query ?? {}, { open, retention: kept, unwritten: service.state().unwritten })
        );
      } catch (error) {
        throw auditError('audit_read_unavailable', { cause: error });
      }
    },

    async export(query, format = query?.format) {
      try {
        return await exportAudit(
          unitDb('read'),
          { ...query, format },
          { clock, instance, open: [...open] }
        );
      } catch (error) {
        throw auditError('audit_read_unavailable', { cause: error });
      }
    },

    verify({ journal = null } = {}) {
      // At most one verification runs in the process; a second request joins it (§6.3).
      if (verifying && journal === null) return verifying;
      const run = exclusively(() => verifyAudit(unitDb('read'), { keyring, journal, clock })).catch(
        error => {
          throw auditError('audit_read_unavailable', { cause: error });
        }
      );
      if (journal === null) {
        verifying = run;
        run.then(
          () => (verifying = null),
          () => (verifying = null)
        );
      }
      return run;
    },

    // D24: a record with an actor is its route's to record (with the full access); the system
    // records become system rows.
    fromDelivery(record) {
      if (!record || typeof record !== 'object' || record.actor !== undefined) return;
      const at = Number.isSafeInteger(record.at) ? record.at : undefined;
      const target = record.target ?? null;
      const rows = {
        'signing.created': () => ({
          target: { type: 'secret', id: 'env-webhook', name: null },
          detail: { replaced: Boolean(record.detail?.replaced) },
        }),
        'channel.paused': () => ({
          target: { type: 'channel', id: typeof target === 'string' ? target : null, name: null },
          detail: {
            reason:
              typeof record.detail?.reason === 'string' ? record.detail.reason.slice(0, 200) : null,
            transient: Boolean(record.detail?.transient),
          },
        }),
        'channel.working': () => ({
          target: { type: 'channel', id: typeof target === 'string' ? target : null, name: null },
        }),
        'notifications.unsaved': () => ({ target: { type: 'outbox', id: null, name: null } }),
        'notifications.saved': () => ({ target: { type: 'outbox', id: null, name: null } }),
      };
      if (!Object.hasOwn(rows, record.action)) return;
      void service.system({ action: record.action, outcome: 'info', at, ...rows[record.action]() });
    },

    state() {
      return {
        ready,
        unwritten: unwritten ? { ...unwritten } : null,
        retention: { days: kept.days, maxRows: kept.maxRows },
      };
    },

    async idle() {
      while (inflight.size) await Promise.allSettled([...inflight]);
      await aggregator.idle();
      while (inflight.size) await Promise.allSettled([...inflight]);
    },

    close() {
      closing ??= (async () => {
        const work = (async () => {
          aggregator.stop();
          const stop =
            startedAt !== null
              ? {
                  action: 'system.stop',
                  outcome: 'info',
                  target: orbitTarget,
                  detail: { uptimeMs: Math.max(0, clock() - startedAt) },
                }
              : null;
          if (ready && !full()) {
            await aggregator.flush({ force: true });
            await aggregator.idle();
          }
          const counts = aggregator.pending();
          if (Object.keys(counts).length)
            print(
              err,
              unwrittenCountsLine(counts, full() ? 'storage_full' : 'not_written', {
                instance,
                now: clock(),
              })
            );
          if (stop) await bestEffort('system', [stop]);
          await service.idle();
        })();
        await Promise.race([work.catch(() => {}), sleep(CLOSE_MS, undefined, { ref: false })]);
      })();
      return closing;
    },
  };
  return Object.freeze(service);
}
