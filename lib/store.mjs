import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  GAP,
  maxGapMs,
  periods,
  cleanNotes,
  noteLimits,
  latestFromRow,
  historyWindow,
  historyFromBuckets,
  storedError,
  summarySlotMs,
  summarizeSlot,
} from './series/shape.mjs';
import { createDiskBudget } from './series/disk-budget.mjs';
import { newEventUid } from './notify/outbox.mjs';
import { sql, id } from './db/sql.mjs';
import { createSqliteDialect } from './db/dialect/sqlite.mjs';
import registry from './db/registry.mjs';
import { assertDatabaseFiles, tightenMode } from './saved-data.mjs';
import { storeConnectionsExposed } from './store-connections.mjs';
// Kept here too: server.mjs and older callers import them from the store.
export { periods, cleanNotes, noteLimits };
// History index size per reading, on the generous side (short errors take about 25 bytes).
// Only decides whether a build is worth trying: the build checks its real size.
const indexBytesPerReading = 40;
// Rows per delete transaction. One large DELETE needs WAL space for every page it touches,
// which a nearly full disk may not have, and then it deletes nothing.
const chunk = 1000;
// Longest a background deletion should hold the event loop in one step.
const stepMs = 50;
// SQLITE_FULL, which SQLite also reports for ENOSPC.
const full = e => (e?.errcode & 0xff) === 13;
// An alert change not yet relayed to the outbox is kept this long whatever the history budget,
// so recycling cannot drop it before the relay has copied it (delivery spec §4.2).
const unrelayedKeepMs = 24 * 3600 * 1000;
// Rows per unit of the relay's history operations (markRelayed, unrelayedEvents, discard).
const relayBatch = 200;
const discardBatch = 500;
// The 1.5 statements of this file are written with sql`…` and the registry's identifiers, and
// rendered by the SQLite dialect onto this 1.x connection (the 1.x statements stay as written).
const dialect = createSqliteDialect({ identifiers: registry.identifiers });
// History summaries (history_summaries, 1.5): one row per source and 5-minute slot, kept in the
// transaction of every write that changes the slot's readings, and read by charts of 7 days or
// more (see history()).
const S = Object.freeze({
  table: id('history_summaries'),
  slotIndex: id('history_summaries_slot'),
  readings: id('readings'),
  service: id('service'),
  time: id('time'),
  ok: id('ok'),
  error: id('error'),
  slot: id('slot'),
  successes: id('successes'),
  first: id('first_time'),
  last: id('last_time'),
  previous: id('previous_time'),
  metrics: id('metrics'),
  value: id('value'),
  sample: id('sample_time'),
  failure: id('failure_time'),
  marker: id('marker_time'),
  firstFailure: id('first_failure_time'),
  sampleGap: id('sample_gap'),
  failureGap: id('failure_gap'),
  markerGap: id('marker_gap'),
});
// The columns summarizeSlot() fills, after service and slot.
const summaryFields = Object.freeze([
  'successes',
  'first_time',
  'last_time',
  'previous_time',
  'sample_time',
  'failure_time',
  'marker_time',
  'first_failure_time',
  'sample_gap',
  'failure_gap',
  'marker_gap',
]);
const slotOf = time => Math.floor(time / summarySlotMs) * summarySlotMs;
// The summary check at start, per transaction: slots per step to begin with (fewer for a source
// with more readings per slot, so its first step stays near coverStartRows readings), the most
// per step, and how long a step should hold the event loop (the step adapts to the rows per slot).
const coverSlots = 12;
const coverStartRows = 1000;
const coverMaxSlots = 2016;
const coverStepMs = 5;
// Summaries written per statement by the check (a fixed size, so one statement text serves).
const coverBatch = 64;
// Summary rows deleted per transaction by prune() and forget().
const summaryChunk = 1000;
// Coverage marks (history_summary_marks, 1.5): one row per source whose summaries matched its
// readings when a Store last closed, holding a fingerprint of those readings (the ones with a
// time from -2^53 to 2^53, the only ones summarised): their count, first and last time, and the
// sums modulo 2^24 of the times of all of them, of the successes and of the pause markers, plus
// the source's summary count. A start skips the slot-by-slot check of a source whose fingerprint
// still equals its mark. A write to its readings since then, by whichever release or tool (a new
// reading, a prune, a replaced outcome, a deleted reading), changes the fingerprint, so that
// source is checked as before. The fingerprint reads the history index, not the measurements.
// Marks are written only by close(), so after a crash the readings written since the last clean
// close no longer match theirs.
const K = Object.freeze({
  table: id('history_summary_marks'),
  service: id('service'),
  count: id('reading_count'),
  first: id('first_time'),
  last: id('last_time'),
  timeSum: id('time_sum'),
  successSum: id('success_sum'),
  markerSum: id('marker_sum'),
  summaries: id('summary_count'),
});
const markFields = Object.freeze([
  'reading_count',
  'first_time',
  'last_time',
  'time_sum',
  'success_sum',
  'marker_sum',
  'summary_count',
]);
const fingerprintModulus = 2 ** 24;
// The time span of the first fingerprint step of a source (the step then adapts like the check's).
const fingerprintStartMs = 86400000;
const fingerprintMinMs = 60000;
// How long close() may spend fingerprinting sources for their marks (see #keepMarks): a stop is
// held while it runs, so it stops after this budget and leaves the remaining sources' marks as
// they were (such a mark matches only while that source's readings are unchanged, so a start
// checks the sources left out that changed). About 0.2 s marks 40 sources with 30 days each.
const closeMarkBudgetMs = 1000;
// A summary read that fails for a passing reason (SQLite's primary codes BUSY, LOCKED, NOMEM,
// INTERRUPT, IOERR and FULL, the last for a sort's temporary space) sends only that chart to the
// readings, until it fails this many times in a row.
const passingReadFailures = new Set([5, 6, 7, 9, 10, 13]);
const summaryReadLimit = 3;
const E = Object.freeze({
  events: id('events'),
  id: id('id'),
  uid: id('uid'),
  service: id('service'),
  time: id('time'),
  kind: id('kind'),
  message: id('message'),
  category: id('category'),
  rule: id('rule'),
  since: id('since'),
  relayed: id('relayed'),
});
const duration = ms => {
  const minutes = Math.max(1, Math.round(ms / 60000));
  return minutes < 90 ? `${minutes} min` : `${(minutes / 60).toFixed(1)} h`;
};
// Cached answers are shared by every caller, so none may change one for the others.
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}
export class Store {
  // The 1.x connection. Private: routes hold the Store, and a raw connection would let any of
  // them run SQL text that neither sql`…` nor scripts/sql-lint.mjs ever sees. Tests reach it
  // through `db` once test/setup.mjs has called exposeStoreConnections() (store-connections.mjs).
  #db;
  // The disk budget of this connection (lib/series/disk-budget.mjs): history.sqlite is capped
  // below the filesystem's free space, so a history that outgrows the disk hits SQLITE_FULL
  // (and #write recycles it) while the WAL and config.json still fit. Writes refresh it every
  // minute and on SQLITE_FULL, and prune() after deleting, so the cap follows space that other
  // programs use or free.
  #disk;
  // Prepared statements by SQL text. Every call used to compile its statement again; the
  // texts are fixed, so the cache stays small. SQLite recompiles a cached statement by itself
  // when the schema changes (an index built later, say).
  #statements = new Map();
  // Source ID → what latest() returned, when options.cacheLatest is set (see latest()).
  #latest = null;
  // While it returns true, readings are not saved (the disk is full; see record()).
  #pauseReadings;
  #clock;
  // History summaries (history_summaries; see history()). #summaries: the table is usable and
  // every write keeps it. A source's charts read it only once the start's check (#cover) has
  // found or made its summaries complete: #covered lists the sources checked so far, and
  // #coveredAll says the check finished, so every source is (a source new since then has only
  // readings this Store wrote, each with its summary). Not while prune() deletes readings
  // (#pruning) or forget() erases the source (#erasing), nor for a source whose readings Uptime Goblin
  // cannot summarise (#unsummarized: a time that is not an integer, written by something else).
  #summaries = false;
  #covered = new Set();
  #coveredAll = false;
  #pruning = 0;
  #erasing = new Map();
  #unsummarized = new Set();
  #checked;
  // Whether history_summary_marks is usable (see K), and the summary reads that failed in a row
  // for a passing reason (see #summaryReadFailed).
  #marks = false;
  #readFailures = 0;
  // PRAGMA data_version when the Store opened: it changes when another connection commits to the
  // database, whose writes keep no summaries and may come after the check (see #keepMarks).
  #dataVersion;
  #closeMarkBudgetMs = closeMarkBudgetMs;
  // `options.cacheLatest` keeps latest() answers in memory: record() and forget() drop a
  // source's entry and the next latest() reads it again. Only for a process that writes
  // `latest` through this Store alone; a write made on `db` directly is not seen.
  // `options.pauseReadings` (() => boolean, the storage guard's "full"): while true, record()
  // and markGap() write nothing. `options.clock` (epoch ms) dates the unrelayed-event guard of
  // budget recycling.
  constructor(directory, options = {}) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    // Resolved: node:sqlite reads a string starting 'file:' as a URI, which would open (and
    // leave at mode 0644) another file than the one checked and chmodded here.
    const file = path.resolve(directory, 'history.sqlite');
    this.directory = directory;
    if (options.cacheLatest) this.#latest = new Map();
    this.#pauseReadings =
      typeof options.pauseReadings === 'function' ? options.pauseReadings : () => false;
    this.#clock = typeof options.clock === 'function' ? options.clock : Date.now;
    // `options.closeMarkBudgetMs` (tests only): close()'s fingerprinting budget, see #keepMarks.
    if (Number.isFinite(options.closeMarkBudgetMs) && options.closeMarkBudgetMs >= 0)
      this.#closeMarkBudgetMs = options.closeMarkBudgetMs;
    // A FIFO or a directory in its place or its journal's, or a link to nothing, fails every
    // start the same way: a refusal (exit 78) instead of a wait for good, or a disk error the
    // service manager would retry for ever.
    assertDatabaseFiles(file);
    this.#db = new DatabaseSync(file);
    // Not through a symbolic link: its target is not Uptime Goblin's to change.
    tightenMode(file, 0o600);
    this.#disk = createDiskBudget({
      directory,
      pages: {
        get: name => this.#pragma(name),
        setMax: pages => this.#db.exec(`PRAGMA max_page_count=${pages}`),
        checkpoint: () => this.#db.exec('PRAGMA wal_checkpoint(PASSIVE)'),
      },
    });
    // trusted_schema=OFF: a trigger or view in the file may use only innocuous functions and
    // tables (see lib/db/sqlite.mjs).
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000; PRAGMA trusted_schema=OFF;
 CREATE TABLE IF NOT EXISTS readings (service TEXT NOT NULL, time INTEGER NOT NULL, ok INTEGER NOT NULL, metrics TEXT NOT NULL, PRIMARY KEY(service,time));
 CREATE INDEX IF NOT EXISTS readings_time ON readings(time);
 CREATE TABLE IF NOT EXISTS latest (service TEXT PRIMARY KEY, attempted INTEGER, success INTEGER, metrics TEXT NOT NULL DEFAULT '[]', error TEXT);
 CREATE TABLE IF NOT EXISTS alerts (service TEXT NOT NULL, rule TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, count INTEGER NOT NULL, message TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(service,rule));
 CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, service TEXT NOT NULL, time INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS events_time ON events(time);
 CREATE TABLE IF NOT EXISTS latest_notes (service TEXT PRIMARY KEY, time INTEGER NOT NULL, notes TEXT NOT NULL);`);
    // Additive migrations preserve active alerts and event history from older releases.
    for (const [table, columns] of [
      // Why a collection failed, kept with the failed reading for later diagnosis.
      ['readings', [['error', 'TEXT']]],
      [
        'alerts',
        [
          ['recovery_since', 'INTEGER'],
          ['recovery_count', 'INTEGER NOT NULL DEFAULT 0'],
        ],
      ],
      [
        'events',
        [
          ['category', 'TEXT'],
          ['rule', 'TEXT'],
          // 1.5, durable delivery: the alert's since (resolved: the old since), the event's
          // random uid, and relayed (0 pending, 1 copied to the outbox, NULL written by 1.4.x).
          // Schema-only changes, constant time on any table.
          ['since', 'INTEGER'],
          ['uid', 'TEXT'],
          ['relayed', 'INTEGER'],
        ],
      ],
    ]) {
      const existing = new Set(
        this.#db
          .prepare(`PRAGMA table_info(${table})`)
          .all()
          .map(c => c.name)
      );
      for (const [name, type] of columns)
        if (!existing.has(name)) this.#db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
    }
    // Capped first, so the index build cannot use the reserve either. The index only speeds
    // up charts, so no failure to build it (a damaged page, an unusable temp directory) may
    // stop Uptime Goblin from starting.
    this.#disk.refresh();
    try {
      this.#historyIndex();
    } catch (e) {
      console.error(
        'History index could not be built; charts stay slower until it is:',
        e.errcode ?? e.code ?? e.name
      );
    }
    // The events still to relay to the outbox (a partial index: only rows with relayed = 0,
    // so it stays small). Without it the relay's sweep scans the events table, which works, so
    // a failure (a full disk) must not keep Uptime Goblin from starting.
    try {
      if (
        !this.#db
          .prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?")
          .get('events_unrelayed')
      ) {
        this.#db.exec(
          'CREATE INDEX IF NOT EXISTS events_unrelayed ON events(id) WHERE relayed = 0'
        );
        // The cap counts from the pages the database has; the new index took some.
        this.#disk.refresh();
      }
    } catch (e) {
      console.error(
        'The pending-notification index could not be built; Uptime Goblin builds it at a later start:',
        e.errcode ?? e.code ?? e.name
      );
    }
    this.#openSummaries();
    this.#dataVersion = this.#pragma('data_version');
    // The check starts once the caller's synchronous start-up work is done, and runs in short
    // steps between collections and requests.
    this.#checked = this.#summaries ? nextTurn().then(() => this.#cover()) : Promise.resolve();
  }
  // Creates history_summaries and its slot index where they are missing (additive: a release
  // that does not know them never touches them). Charts only get faster with them, so no failure
  // here (a full disk, a table of that name with other columns) may stop Uptime Goblin from starting:
  // charts then read every reading, as before 1.5, until a later start.
  #openSummaries() {
    try {
      this.#run(
        sql`CREATE TABLE IF NOT EXISTS ${S.table} (${S.service} TEXT NOT NULL, ${S.slot} INTEGER NOT NULL, ${S.successes} INTEGER NOT NULL, ${S.first} INTEGER NOT NULL, ${S.last} INTEGER NOT NULL, ${S.previous} INTEGER, ${S.sample} INTEGER, ${S.failure} INTEGER, ${S.marker} INTEGER, ${S.firstFailure} INTEGER, ${S.sampleGap} INTEGER, ${S.failureGap} INTEGER, ${S.markerGap} INTEGER, PRIMARY KEY (${S.service}, ${S.slot}))`
      );
      this.#run(sql`CREATE INDEX IF NOT EXISTS ${S.slotIndex} ON ${S.table} (${S.slot})`);
      const present = new Set(
        this.#all(dialect.catalog.columns('history_summaries')).map(column => column.name)
      );
      if (!['service', 'slot', ...summaryFields].every(name => present.has(name)))
        throw Object.assign(new Error('history_summaries has other columns'), {
          code: 'SUMMARY_COLUMNS',
        });
      this.#summaries = true;
      // The cap counts from the pages the database has; the new table took some.
      this.#disk.refresh();
    } catch (e) {
      console.error(
        'History summaries are unavailable; long charts read every reading until a later start:',
        e.errcode ?? e.code ?? e.name
      );
      return;
    }
    // The marks only save a start work: without them (a full disk, a table of that name with
    // other columns) every start checks every source.
    try {
      this.#run(
        sql`CREATE TABLE IF NOT EXISTS ${K.table} (${K.service} TEXT NOT NULL, ${K.count} INTEGER NOT NULL, ${K.first} INTEGER, ${K.last} INTEGER, ${K.timeSum} INTEGER NOT NULL, ${K.successSum} INTEGER NOT NULL, ${K.markerSum} INTEGER NOT NULL, ${K.summaries} INTEGER NOT NULL, PRIMARY KEY (${K.service}))`
      );
      const present = new Set(
        this.#all(dialect.catalog.columns('history_summary_marks')).map(column => column.name)
      );
      if (!['service', ...markFields].every(name => present.has(name)))
        throw Object.assign(new Error('history_summary_marks has other columns'), {
          code: 'SUMMARY_MARK_COLUMNS',
        });
      this.#marks = true;
      this.#disk.refresh();
    } catch (e) {
      console.error(
        'History summary marks are unavailable; each start checks every source:',
        e.errcode ?? e.code ?? e.name
      );
    }
  }
  // After a failure to keep the summaries (anything but a full disk inside a write, which the
  // write handles), they are left alone until the next start checks and repairs them.
  #summariesFailed(e) {
    if (!this.#summaries) return;
    this.#summaries = false;
    console.error(
      'History summaries stopped; long charts read every reading until a later start rebuilds them:',
      e?.errcode ?? e?.code ?? e?.name
    );
  }
  // After a summary read failed: a passing failure leaves only that chart on the readings, unless
  // it is the summaryReadLimit-th in a row; any other failure (a damaged page, a missing table or
  // column, an SQLite without concat_ws, which fail every read the same way) stops the summaries
  // until the next start.
  #summaryReadFailed(e) {
    this.#readFailures += 1;
    if (passingReadFailures.has(e?.errcode & 0xff) && this.#readFailures < summaryReadLimit) {
      console.error(
        'A history summary read failed; that chart read every reading instead:',
        e.errcode ?? e.code ?? e.name
      );
      return;
    }
    this.#summariesFailed(e);
  }
  // Whether charts of 7 days or more of `service` may read its summaries now.
  #summarized(service) {
    return (
      this.#summaries &&
      !this.#pruning &&
      !this.#erasing.has(service) &&
      !this.#unsummarized.has(service) &&
      (this.#coveredAll || this.#covered.has(service))
    );
  }
  // Writes (or deletes, for null or false) the summary of one slot.
  #putSummary(service, slot, summary) {
    if (summary === false) this.#unsummarized.add(service);
    if (!summary) {
      this.#run(
        dialect.deleteFrom(
          'history_summaries',
          sql`${S.service} = ${service} AND ${S.slot} = ${slot}`
        )
      );
      return;
    }
    this.#run(
      dialect.upsert(
        'history_summaries',
        ['service', 'slot'],
        ['service', 'slot', ...summaryFields],
        [[service, slot, ...summaryFields.map(field => summary[field])]]
      )
    );
  }
  // The readings of `service` from `start` (inclusive) to `end` (exclusive), as summarizeSlot
  // takes them, in time order.
  #slotReadings(service, start, end) {
    return this.#all(
      sql`SELECT ${S.time}, ${S.ok}, ${S.error} IS ${GAP} AS marker FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} >= ${start} AND ${S.time} < ${end} ${dialect.orderBy(['time', 'asc', 'not null'])}`
    );
  }
  // The time of the last reading of `service` before `time`, or null.
  #readingBefore(service, time) {
    return this.#all(
      sql`SELECT MAX(${S.time}) AS found FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} < ${time}`
    )[0].found;
  }
  // Summarises one slot again from its readings, inside the caller's transaction, and keeps the
  // reading before the next summarised slot, which a change in this one may have moved.
  #summarize(service, slot) {
    this.#putSummary(
      service,
      slot,
      summarizeSlot(
        this.#slotReadings(service, slot, slot + summarySlotMs),
        this.#readingBefore(service, slot)
      )
    );
    const [{ found: next }] = this.#all(
      sql`SELECT MIN(${S.slot}) AS found FROM ${S.table} WHERE ${S.service} = ${service} AND ${S.slot} > ${slot}`
    );
    if (next !== null) this.#setPrevious(service, next, this.#readingBefore(service, next));
  }
  #setPrevious(service, slot, previous) {
    this.#run(
      dialect.update(
        'history_summaries',
        { previous_time: previous },
        sql`${S.service} = ${service} AND ${S.slot} = ${slot} AND ${S.previous} IS NOT ${previous}`
      )
    );
  }
  // The summary part of a write of one reading (record(), markGap()), in its transaction. A full
  // disk is the write's to handle (#write recycles and retries); any other failure stops the
  // summaries, not the write.
  #keepSummary(service, time) {
    if (!this.#summaries) return;
    if (!Number.isSafeInteger(time)) {
      this.#unsummarized.add(service);
      return;
    }
    try {
      this.#summarize(service, slotOf(time));
    } catch (e) {
      if (full(e)) throw e;
      this.#summariesFailed(e);
    }
  }
  // After the oldest readings were deleted (prune(), recycling): every reading older than
  // `oldest` (the oldest left, or null for none) is gone and no younger one was touched, so the
  // summaries of older slots go, and the slot holding `oldest` is summarised again for each
  // source that had readings there up to `oldest` (two sources may share a millisecond). At most
  // `limit` summaries are deleted; returns true once nothing is left to do.
  #trimSummaries(oldest, limit = summaryChunk) {
    const below = oldest === null ? Number.MAX_SAFE_INTEGER : slotOf(oldest);
    const deleted = this.#all(
      dialect.deleteFrom(
        'history_summaries',
        sql`(${S.service}, ${S.slot}) IN (SELECT ${S.service}, ${S.slot} FROM ${S.table} WHERE ${S.slot} < ${below} ${dialect.orderBy(['slot', 'asc', 'not null'])} ${dialect.limit(limit)})`,
        { returning: ['service'] }
      )
    );
    // The first summary left of a source whose summaries went has no reading before it.
    for (const service of new Set(deleted.map(row => row.service))) {
      const [{ found: first }] = this.#all(
        sql`SELECT MIN(${S.slot}) AS found FROM ${S.table} WHERE ${S.service} = ${service}`
      );
      if (first !== null) this.#setPrevious(service, first, this.#readingBefore(service, first));
    }
    if (deleted.length >= limit) return false;
    if (oldest !== null)
      for (const { service } of this.#all(
        sql`SELECT ${S.service} FROM ${S.table} WHERE ${S.slot} = ${below} AND ${S.first} <= ${oldest}`
      ))
        this.#summarize(service, below);
    return true;
  }
  // The oldest reading's time, or null when no reading has a numeric time.
  #oldestReading() {
    const { oldest } = this.#prepare('SELECT MIN(time) AS oldest FROM readings').get();
    return typeof oldest === 'number' ? oldest : null;
  }
  /**
   * Resolves once the start's summary check has finished, or stopped (the Store closed, or a
   * failure that leaves charts on the readings). For tests and measurement tools.
   */
  summariesChecked() {
    return this.#checked;
  }
  /** Whether charts of 7 days or more of `service` read its summaries now (see history()). */
  summarized(service) {
    return this.#summarized(service);
  }
  // The start's summary check. Readings may have been written without summaries (by a release
  // before 1.5 after a rollback, by a restore, by a tool) and summaries may be stale or left over,
  // so every source with readings or summaries is checked slot by slot against its readings, and
  // what differs is rewritten, in short transactions that yield to the event loop between them
  // (never one long rebuild). Until a source is done, its charts read its readings.
  async #cover() {
    try {
      const open = () => this.#db.isOpen && this.#summaries;
      for (
        let service = this.#nextSource();
        service !== null;
        service = this.#nextSource(service)
      ) {
        if (!open()) return;
        if (await this.#unchanged(service)) this.#covered.add(service);
        else await this.#coverSource(service);
        if (!open()) return;
      }
      this.#coveredAll = true;
    } catch (e) {
      if (this.#db.isOpen) this.#summariesFailed(e);
    }
  }
  // Whether `service` has a mark that its readings and summaries still match (see K).
  async #unchanged(service) {
    if (!this.#marks) return false;
    const [mark] = this.#all(
      sql`SELECT ${K.count}, ${K.first}, ${K.last}, ${K.timeSum}, ${K.successSum}, ${K.markerSum}, ${K.summaries} FROM ${K.table} WHERE ${K.service} = ${service}`
    );
    if (!mark) return false;
    const print = await this.#fingerprint(service);
    return print !== null && markFields.every(field => print[field] === mark[field]);
  }
  // The fingerprint of `service` (see K), in steps of about coverStepMs between which the event
  // loop runs, or null when the Store closed or the summaries stopped meanwhile. The Store's own
  // writes in between keep the summaries, so mixing them in can only make the fingerprint differ
  // from the mark, which checks the source.
  async #fingerprint(service) {
    const print = this.#fingerprintStart(service);
    const { first_time: first, last_time: last } = print;
    if (typeof first === 'number' && typeof last === 'number')
      for (let from = first, span = fingerprintStartMs; from <= last; ) {
        const to = Math.min(from + span, last + 1),
          began = performance.now();
        this.#fingerprintAdd(print, service, from, to);
        const took = Math.max(0.1, performance.now() - began);
        span = Math.max(
          fingerprintMinMs,
          Math.min(2 * span, Math.round((span * coverStepMs) / took))
        );
        from = to;
        await nextTurn();
        if (!this.#db.isOpen || !this.#summaries) return null;
      }
    return print;
  }
  // The fingerprint of `service` in one go (for close(), which cannot yield).
  #fingerprintNow(service) {
    const print = this.#fingerprintStart(service);
    if (typeof print.first_time === 'number' && typeof print.last_time === 'number')
      this.#fingerprintAdd(print, service, print.first_time, print.last_time + 1);
    return print;
  }
  // A fingerprint with the first and last time and the summary count of `service`, and sums of 0.
  #fingerprintStart(service) {
    const [{ first_time, last_time }] = this.#all(
      sql`SELECT MIN(${S.time}) AS ${K.first}, MAX(${S.time}) AS ${K.last} FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} >= ${-Number.MAX_SAFE_INTEGER} AND ${S.time} <= ${Number.MAX_SAFE_INTEGER}`
    );
    const [{ found }] = this.#all(
      sql`SELECT COUNT(*) AS found FROM ${S.table} WHERE ${S.service} = ${service}`
    );
    return {
      reading_count: 0,
      first_time,
      last_time,
      time_sum: 0,
      success_sum: 0,
      marker_sum: 0,
      summary_count: found,
    };
  }
  // Adds the readings of `service` from `from` (inclusive) to `to` (exclusive) to `print`: one
  // range of the history index.
  #fingerprintAdd(print, service, from, to) {
    const [part] = this.#all(
      sql`SELECT COUNT(*) AS ${K.count}, SUM(${S.time} % ${fingerprintModulus}) AS ${K.timeSum}, SUM(CASE WHEN ${S.ok} = ${1} THEN ${S.time} % ${fingerprintModulus} ELSE ${0} END) AS ${K.successSum}, SUM(CASE WHEN ${S.error} IS ${GAP} THEN ${S.time} % ${fingerprintModulus} ELSE ${0} END) AS ${K.markerSum} FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} >= ${from} AND ${S.time} < ${to}`
    );
    for (const field of ['reading_count', 'time_sum', 'success_sum', 'marker_sum'])
      print[field] += part[field] ?? 0;
  }
  // At close(): marks every source whose summaries match its readings now (checked this start or
  // since kept by every write), and drops the marks of sources it cannot summarise. The marks of
  // sources not checked yet stay: they match only while those readings are unchanged. Nothing
  // while a prune deletes readings (its summaries follow afterwards) or once the summaries
  // stopped. Best effort: without a mark a start checks the source. Fingerprinting stops once it
  // has taken #closeMarkBudgetMs, so a stop is not held for long by a large history: the
  // sources it did not reach keep their old marks, as sources not checked yet do.
  #keepMarks() {
    if (!this.#db.isOpen || !this.#summaries || !this.#marks || this.#pruning) return;
    try {
      // Another connection (a tool, another program) wrote since this Store opened: what it
      // changed may have been checked before it wrote, so no mark can be trusted.
      if (this.#pragma('data_version') !== this.#dataVersion) {
        this.#run(dialect.deleteFrom('history_summary_marks', sql`${K.service} IS NOT NULL`));
        return;
      }
      const rows = [];
      const began = performance.now();
      for (
        let service = this.#nextSource();
        service !== null;
        service = this.#nextSource(service)
      ) {
        if (performance.now() - began >= this.#closeMarkBudgetMs) break;
        if (
          (this.#coveredAll || this.#covered.has(service)) &&
          !this.#erasing.has(service) &&
          !this.#unsummarized.has(service)
        ) {
          const print = this.#fingerprintNow(service);
          rows.push([service, ...markFields.map(field => print[field])]);
        }
      }
      this.#transaction(() => {
        const whole = rows.length - (rows.length % coverBatch);
        for (let at = 0; at < rows.length; at += at < whole ? coverBatch : 1)
          this.#run(
            dialect.upsert(
              'history_summary_marks',
              ['service'],
              ['service', ...markFields],
              rows.slice(at, at < whole ? at + coverBatch : at + 1)
            )
          );
        for (const service of this.#unsummarized)
          this.#run(dialect.deleteFrom('history_summary_marks', sql`${K.service} = ${service}`));
      });
    } catch (e) {
      console.error(
        'History summary marks could not be saved; the next start checks the sources changed since the last ones:',
        e.errcode ?? e.code ?? e.name
      );
    }
  }
  // The next source ID after `after` (in SQLite's order) with readings or summaries, or null.
  // Each MIN is one index lookup, however many readings a source has.
  #nextSource(after) {
    const [{ found }] =
      after === undefined
        ? this.#all(
            sql`SELECT MIN(found) AS found FROM (SELECT MIN(${S.service}) AS found FROM ${S.readings} UNION ALL SELECT MIN(${S.service}) FROM ${S.table}) AS candidates`
          )
        : this.#all(
            sql`SELECT MIN(found) AS found FROM (SELECT MIN(${S.service}) AS found FROM ${S.readings} WHERE ${S.service} > ${after} UNION ALL SELECT MIN(${S.service}) FROM ${S.table} WHERE ${S.service} > ${after}) AS candidates`
          );
    return found;
  }
  async #coverSource(service) {
    const ends = [
      this.#all(
        sql`SELECT MIN(${S.time}) AS found FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} >= ${-Number.MAX_SAFE_INTEGER}`
      )[0].found,
      this.#all(
        sql`SELECT MAX(${S.time}) AS found FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} <= ${Number.MAX_SAFE_INTEGER}`
      )[0].found,
      this.#all(
        sql`SELECT MIN(${S.slot}) AS found FROM ${S.table} WHERE ${S.service} = ${service}`
      )[0].found,
      this.#all(
        sql`SELECT MAX(${S.slot}) AS found FROM ${S.table} WHERE ${S.service} = ${service}`
      )[0].found,
    ]
      .filter(value => typeof value === 'number' && Number.isFinite(value))
      .map(slotOf);
    let span = this.#coverSpan(service);
    for (let start = Math.min(...ends), last = Math.max(...ends); start <= last; ) {
      const end = Math.min(start + span * summarySlotMs, last + summarySlotMs),
        began = performance.now();
      const found = this.#transaction(() => this.#coverRange(service, start, end));
      const took = Math.max(0.1, performance.now() - began);
      // At most twice as many slots as the last step: the next ones may hold many more readings.
      span = Math.max(
        1,
        Math.min(coverMaxSlots, 2 * span, Math.round((span * coverStepMs) / took))
      );
      // An empty step skips to the next slot with a reading or a summary, so a stray reading far
      // from the others (a time a tool wrote) costs one step, not one per empty stretch between.
      start = found ? end : this.#nextCovered(service, end, last + summarySlotMs);
      await nextTurn();
      if (!this.#db.isOpen || !this.#summaries) return;
    }
    if (!this.#unsummarized.has(service)) this.#covered.add(service);
  }
  // The slots of the first step of the check of `service`: coverSlots, or fewer when its newest
  // hour holds more than coverStartRows readings (the count stops there: one bounded index range).
  #coverSpan(service) {
    const [{ newest }] = this.#all(
      sql`SELECT MAX(${S.time}) AS newest FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} <= ${Number.MAX_SAFE_INTEGER}`
    );
    if (typeof newest !== 'number') return coverSlots;
    const [{ found }] = this.#all(
      sql`SELECT COUNT(*) AS found FROM (SELECT 1 FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} > ${newest - coverSlots * summarySlotMs} AND ${S.time} <= ${newest} ${dialect.limit(coverSlots * coverStartRows)}) AS recent`
    );
    return Math.max(1, Math.min(coverSlots, Math.floor((coverSlots * coverStartRows) / found)));
  }
  // The slot of the first reading or summary of `service` from `from` on, or `past` when none is
  // before it.
  #nextCovered(service, from, past) {
    const [{ reading }] = this.#all(
      sql`SELECT MIN(${S.time}) AS reading FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} >= ${from} AND ${S.time} <= ${Number.MAX_SAFE_INTEGER}`
    );
    const [{ summary }] = this.#all(
      sql`SELECT MIN(${S.slot}) AS summary FROM ${S.table} WHERE ${S.service} = ${service} AND ${S.slot} >= ${from}`
    );
    return Math.min(
      past,
      ...[reading, summary].filter(value => typeof value === 'number').map(slotOf)
    );
  }
  // Makes the summaries of `service` from `start` to `end` (whole slots) match its readings, and
  // says whether it found any reading or summary there.
  #coverRange(service, start, end) {
    const readings = this.#slotReadings(service, start, end),
      stored = new Map(
        this.#all(
          sql`SELECT ${S.slot}, ${S.successes}, ${S.first}, ${S.last}, ${S.previous}, ${S.sample}, ${S.failure}, ${S.marker}, ${S.firstFailure}, ${S.sampleGap}, ${S.failureGap}, ${S.markerGap} FROM ${S.table} WHERE ${S.service} = ${service} AND ${S.slot} >= ${start} AND ${S.slot} < ${end}`
        ).map(row => [row.slot, row])
      );
    const changed = [];
    let previous = this.#readingBefore(service, start);
    for (let i = 0; i < readings.length; ) {
      const slot = slotOf(readings[i].time);
      let j = i + 1;
      while (j < readings.length && slotOf(readings[j].time) === slot) j += 1;
      const summary = summarizeSlot(readings.slice(i, j), previous),
        old = stored.get(slot);
      previous = readings[j - 1].time;
      if (!summary) this.#putSummary(service, slot, summary);
      else if (!old || summaryFields.some(field => summary[field] !== old[field]))
        changed.push([service, slot, ...summaryFields.map(field => summary[field])]);
      stored.delete(slot);
      i = j;
    }
    // A first build writes every slot: whole batches in one statement each, the rest one by one.
    const whole = changed.length - (changed.length % coverBatch);
    for (let at = 0; at < changed.length; at += at < whole ? coverBatch : 1)
      this.#run(
        dialect.upsert(
          'history_summaries',
          ['service', 'slot'],
          ['service', 'slot', ...summaryFields],
          changed.slice(at, at < whole ? at + coverBatch : at + 1)
        )
      );
    // Summaries of slots without readings (deleted by something else) go.
    const found = readings.length > 0 || stored.size > 0;
    for (const slot of stored.keys()) this.#putSummary(service, slot, null);
    return found;
  }
  // Covers everything history() scans, so a chart reads a few index pages instead of one
  // table page per reading (readings of all sources interleave in the table). Building it on
  // a large existing database takes seconds, once, before collection or HTTP start.
  // For a moment it needs about three times its size on disk: the sort's temporary files, and
  // the WAL holding its pages until the checkpoint copies them into the growing database.
  // Without that much room above the reserve, Uptime Goblin starts without it (history is slower)
  // and a later start builds it. The sort runs in the data directory, which that check
  // covers, not in /tmp (a 16 MiB tmpfs in the Compose setup).
  #historyIndex() {
    const name = 'readings_history';
    if (this.#db.prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?").get(name))
      return;
    const { readings } = this.#db.prepare('SELECT COUNT(*) AS readings FROM readings').get();
    if (!this.#disk.room(3 * readings * indexBytesPerReading)) return;
    const file = path.join(this.directory, 'history.sqlite'),
      bytes = at => {
        try {
          return fs.statSync(at).size;
        } catch {
          return 0;
        }
      },
      used = () => this.#pragma('page_count') - this.#pragma('freelist_count'),
      walBefore = bytes(`${file}-wal`),
      usedBefore = used();
    // Process-wide in SQLite; reset below, and only index builds use it.
    this.#db.exec(`PRAGMA temp_store_directory = '${this.directory.replaceAll("'", "''")}'`);
    try {
      this.#transaction(() => {
        this.#db.exec(`CREATE INDEX ${name} ON readings(service,time,ok,error)`);
        // Long error texts make the estimate low, so check the real size before committing:
        // a committed index whose checkpoint does not fit would keep the disk full, and
        // dropping it would not help (the database does not shrink).
        const size = this.#pragma('page_size'),
          wal = (used() - usedBefore + 4) * (size + 24) - (bytes(`${file}-wal`) - walBefore),
          growth = this.#pragma('page_count') * size - bytes(file);
        if (!this.#disk.room(Math.max(0, wal) + Math.max(0, growth)))
          throw Object.assign(new Error('No room for the history index'), { errcode: 13 });
      });
    } catch (e) {
      // Rolled back, but pages already spilled to the WAL keep their disk space until the
      // WAL is truncated.
      try {
        this.#db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
      } catch {}
      if (full(e)) return;
      throw e;
    } finally {
      this.#db.exec("PRAGMA temp_store_directory = ''");
    }
    // Do not leave the whole index behind in the WAL, which shares the disk reserve. This
    // fits unless other programs took more than the reserve meanwhile; SQLite then finishes
    // it at a later commit, once there is space.
    try {
      this.#db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch (e) {
      if (!full(e)) throw e;
    }
    this.#disk.refresh();
  }
  // `text` is a statement written in this file (scripts/sql-lint.mjs freezes them) or one the
  // dialect rendered from sql`…`; never `sql`, the imported tag.
  #prepare(text) {
    let statement = this.#statements.get(text);
    if (!statement) this.#statements.set(text, (statement = this.#db.prepare(text)));
    return statement;
  }
  #pragma(name) {
    return this.#prepare(`PRAGMA ${name}`).get()[name];
  }
  // A 1.5 statement (sql`…`), rendered for this connection and prepared once per text.
  #query(query) {
    const { text, params } = dialect.render(query);
    return { statement: this.#prepare(text), params };
  }
  #all(query) {
    const { statement, params } = this.#query(query);
    return statement.all(...params);
  }
  #run(query) {
    const { statement, params } = this.#query(query);
    return Number(statement.run(...params).changes);
  }
  #transaction(fn) {
    this.#db.exec('BEGIN');
    try {
      const result = fn();
      this.#db.exec('COMMIT');
      return result;
    } catch (e) {
      // SQLite may already have rolled back (it does on SQLITE_FULL); a blind ROLLBACK
      // would replace the real error with "no transaction is active".
      if (this.#db.isTransaction) this.#db.exec('ROLLBACK');
      throw e;
    }
  }
  // When Uptime Goblin's own history fills the database, recycle the oldest of it and retry once,
  // so collection and alerting keep working instead of stopping until someone frees space.
  // Recycling and the retried write share one transaction: if the write still does not fit,
  // the recycled readings come back, so a write that can never fit cannot erode history.
  #write(fn) {
    this.#disk.beforeWrite();
    let error;
    try {
      return this.#transaction(fn);
    } catch (e) {
      if (!full(e)) throw e;
      error = e;
    }
    // The cap may predate space freed on the host: use that before recycling any history.
    if (this.#disk.grow())
      try {
        return this.#transaction(fn);
      } catch (e) {
        if (!full(e)) throw e;
        error = e;
      }
    return this.#transaction(() => {
      if (!this.#pruneOldest()) throw error;
      return fn();
    });
  }
  // Drops at most one chunk (and at most a tenth) of the oldest readings, plus events older
  // than the history that remains, except alert changes still to relay to the outbox that are
  // younger than 24 h (relayed = 0): a small budget must not lose them before they are sent.
  #pruneOldest() {
    const { count } = this.#prepare('SELECT COUNT(*) AS count FROM readings').get();
    const readings = this.#prepare(
      'DELETE FROM readings WHERE rowid IN (SELECT rowid FROM readings ORDER BY time LIMIT ?)'
    ).run(Math.min(chunk, Math.ceil(count / 10))).changes;
    const { oldest } = this.#prepare('SELECT MIN(time) AS oldest FROM readings').get();
    const events =
      oldest === null
        ? 0
        : this.#prepare(
            'DELETE FROM events WHERE id IN (SELECT id FROM events WHERE time<? AND (relayed IS NOT 0 OR time<=?) ORDER BY time LIMIT ?)'
          ).run(oldest, this.#clock() - unrelayedKeepMs, chunk).changes;
    if (this.#summaries && readings)
      try {
        const left = typeof oldest === 'number' ? oldest : null;
        while (!this.#trimSummaries(left));
      } catch (e) {
        if (full(e)) throw e;
        this.#summariesFailed(e);
      }
    return readings + events;
  }
  // `notes` defaults to the notes a collector attached to its readings (see collect()). Only a
  // successful collection replaces them: a failure keeps showing the last successful
  // readings, and the notes that describe those readings. latest_notes holds one row per
  // source, and only while it has notes, so sources without notes never write it.
  // Returns true once the reading is written, and false while readings are paused: a paused
  // reading is not a successful history write (the server's storage notice counts only those).
  record(id, metrics, error = null, time = Date.now(), notes = metrics?.notes) {
    // A full disk (the storage guard): readings wait until space is freed. Nothing is logged
    // here; the guard logs the change of state once and sends its notice.
    if (this.#pauseReadings()) return false;
    const ok = error === null,
      kept = ok ? cleanNotes(notes) : [],
      // One text for both tables, bounded, whatever the caller passed (see storedError).
      reason = ok ? null : storedError(error);
    // Dropped whatever the outcome: the next latest() reads the row as the write left it.
    this.#latest?.delete(id);
    this.#write(() => {
      if (ok && kept.length)
        this.#prepare(
          'INSERT INTO latest_notes(service,time,notes) VALUES (?,?,?) ON CONFLICT(service) DO UPDATE SET time=excluded.time,notes=excluded.notes'
        ).run(id, time, JSON.stringify(kept));
      else if (ok) this.#prepare('DELETE FROM latest_notes WHERE service=?').run(id);
      this.#prepare(
        'INSERT OR REPLACE INTO readings(service,time,ok,metrics,error) VALUES (?,?,?,?,?)'
      ).run(id, time, Number(ok), JSON.stringify(ok ? metrics : []), reason);
      this.#keepSummary(id, time);
      if (ok)
        this.#prepare(
          'INSERT INTO latest VALUES (?,?,?,?,NULL) ON CONFLICT(service) DO UPDATE SET attempted=excluded.attempted,success=excluded.success,metrics=excluded.metrics,error=NULL'
        ).run(id, time, time, JSON.stringify(metrics));
      else
        this.#prepare(
          'INSERT INTO latest(service,attempted,metrics,error) VALUES(?,?,?,?) ON CONFLICT(service) DO UPDATE SET attempted=excluded.attempted,error=excluded.error'
        ).run(id, time, '[]', reason);
    });
    return true;
  }
  // Notes belong to the successful collection that wrote them. A release without notes
  // (1.4.2, after a rollback) records successes without touching latest_notes, so notes
  // older than the last success are stale and not returned.
  // With options.cacheLatest the answer is kept (frozen, as callers share it) until record()
  // or forget() changes the source, so a dashboard of n sources reads only the sources that
  // changed since the last one instead of n rows.
  latest(id) {
    const cached = this.#latest?.get(id);
    if (cached) return cached;
    const value = this.#readLatest(id);
    if (this.#latest && typeof id === 'string') this.#latest.set(id, deepFreeze(value));
    return value;
  }
  #readLatest(id) {
    return latestFromRow(
      id,
      this.#prepare(
        'SELECT l.attempted,l.success,l.metrics,l.error,n.time AS notes_time,n.notes FROM latest l LEFT JOIN latest_notes n ON n.service=l.service WHERE l.service=?'
      ).get(id)
    );
  }
  // A chart of at most 301 buckets (see historyFromBuckets for what each holds).
  // `options.metrics` (a list of measurement keys) keeps only those readings in each point.
  history(id, period = '24h', now = Date.now(), pollSeconds = 60, timeoutSeconds = 90, options) {
    return this.historyOver(id, historyWindow(period, now, pollSeconds, timeoutSeconds), options);
  }
  /**
   * The chart of `window` (historyWindow or windowFor in lib/series/shape.mjs). A window of whole
   * 5-minute slots (7 days or more) reads the source's summaries, at most one row per slot,
   * when they are complete (see #summarized); otherwise, and for shorter windows, every reading
   * in it. Both give the same chart. `options.path` is for tests and measurements: 'raw' reads
   * the readings whatever the window, 'summaries' only the summaries (null when they cannot
   * answer).
   */
  historyOver(id, window, options) {
    if (options?.path !== 'raw') {
      // A summary read that fails sends this chart to the readings, and may stop the summaries
      // until the next start (see #summaryReadFailed).
      let rows = null;
      try {
        rows = this.#summaryBuckets(id, window);
        if (rows) this.#readFailures = 0;
      } catch (e) {
        this.#summaryReadFailed(e);
      }
      if (rows) return historyFromBuckets(rows, window, options);
      if (options?.path === 'summaries') return null;
    }
    const rows = this.#prepare(
      `WITH ordered AS (SELECT time,ok,ok=0 AND error IS ? AS marker,LAG(time) OVER (ORDER BY time) AS previous FROM readings WHERE service=? AND time>=? AND time<=?), buckets AS (SELECT MAX(CASE WHEN ok=1 THEN time END) AS sample_time,MAX(CASE WHEN ok=0 AND NOT marker THEN time END) AS failure_time,MAX(CASE WHEN marker THEN time END) AS marker_time,MIN(CASE WHEN ok=0 THEN time END) AS first_failure_time,SUM(ok) AS count,GROUP_CONCAT(CASE WHEN time-previous>? THEN time END) AS gaps FROM ordered GROUP BY CAST((time-?)/? AS INTEGER)) SELECT b.*,r.metrics,f.error AS failure_error FROM buckets b LEFT JOIN readings r ON r.service=? AND r.time=b.sample_time LEFT JOIN readings f ON f.service=? AND f.time=b.failure_time`
    ).all(GAP, id, window.from, window.to, window.gapAfter, window.from, window.width, id, id);
    return historyFromBuckets(rows, window, options);
  }
  // The bucket rows of the history query, built from summaries, or null when they cannot give
  // them. A bucket holds whole slots, so its last success, last failure, last marker, first
  // failure and count are those of its slots; a silence inside a slot is reported at the slot
  // point that closes its segment (summarizeSlot), and the silence before a slot, when the
  // reading before it is in the chart too, at the slot's first point: historyFromBuckets marks
  // each on the point it marks for the silence's own reading. One subquery per bucket reads its
  // slots through the primary key (a GROUP BY would sort every slot of the window), then one
  // statement reads the readings and errors of the chosen points.
  #summaryBuckets(service, { from, to, width, gapAfter }) {
    if (
      !this.#summarized(service) ||
      !Number.isSafeInteger(from) ||
      !Number.isSafeInteger(to) ||
      from % summarySlotMs ||
      width <= 0 ||
      width % summarySlotMs
    )
      return null;
    // The slot holding `to` may also hold later readings (the clock was set back), which the
    // chart must leave out: the readings answer that rare chart.
    const [tail] = this.#all(
      sql`SELECT ${S.last} FROM ${S.table} WHERE ${S.service} = ${service} AND ${S.slot} = ${slotOf(to)}`
    );
    if (tail && tail.last_time > to) return null;
    const rows = [];
    for (const { bucket } of this.#all(
      sql`WITH RECURSIVE buckets AS (SELECT ${from} AS start UNION ALL SELECT start + ${width} FROM buckets WHERE start + ${width} <= ${to}) SELECT (SELECT json_array(MAX(${S.sample}), MAX(${S.failure}), MAX(${S.marker}), MIN(${S.firstFailure}), SUM(${S.successes}), GROUP_CONCAT(NULLIF(concat_ws(${','}, CASE WHEN ${S.sampleGap} > ${gapAfter} THEN ${S.sample} END, CASE WHEN ${S.failureGap} > ${gapAfter} THEN ${S.failure} END, CASE WHEN ${S.markerGap} > ${gapAfter} THEN ${S.marker} END, CASE WHEN ${S.previous} >= ${from} AND ${S.first} - ${S.previous} > ${gapAfter} THEN MIN(COALESCE(${S.sample}, ${S.last}), COALESCE(${S.failure}, ${S.last}), COALESCE(${S.marker}, ${S.last})) END), ${''}))) FROM ${S.table} WHERE ${S.service} = ${service} AND ${S.slot} >= start AND ${S.slot} < start + ${width} AND ${S.slot} <= ${to}) AS bucket FROM buckets`
    )) {
      const [sample, failure, marker, firstFailure, count, gaps] = JSON.parse(bucket);
      if (count !== null)
        rows.push({
          sample_time: sample,
          failure_time: failure,
          marker_time: marker,
          first_failure_time: firstFailure,
          count,
          gaps,
          metrics: null,
          failure_error: null,
        });
    }
    const times = rows
      .flatMap(row => [row.sample_time, row.failure_time])
      .filter(time => time !== null);
    if (times.length) {
      const found = new Map(
        this.#all(
          sql`SELECT ${S.time}, ${S.metrics}, ${S.error} FROM ${S.readings} WHERE ${S.service} = ${service} AND ${S.time} IN (SELECT ${S.value} FROM json_each(${JSON.stringify(times)}))`
        ).map(row => [row.time, row])
      );
      for (const row of rows) {
        if (row.sample_time !== null) row.metrics = found.get(row.sample_time)?.metrics ?? null;
        if (row.failure_time !== null)
          row.failure_error = found.get(row.failure_time)?.error ?? null;
      }
    }
    return rows;
  }

  // One transaction, so a failed write cannot leave half-updated alert state.
  evaluate(service, metrics, error, time = Date.now()) {
    return this.#write(() => this.#evaluate(service, metrics, error, time));
  }
  #evaluate(service, metrics, error, time) {
    // A rule key holding half a surrogate pair (a hand-edited config.json, a 1.4.x save) is bound
    // as U+FFFD, so its alert row never matched the key compared, and the rule never fired;
    // collectors already make such reading keys whole (U+FFFD). Keys are compared and bound made
    // whole here too, and of two rules that become one key the first is kept.
    const whole = key => String(key).toWellFormed();
    const byKey = new Map();
    for (const rule of service.rules || []) {
      const key = whole(rule.key);
      if (!byKey.has(key)) byKey.set(key, { ...rule, key });
    }
    const transitions = [],
      rules = [
        {
          key: '__availability',
          operator: 'gt',
          threshold: 0,
          forSeconds: service.availabilitySeconds ?? 60,
        },
        ...byKey.values(),
      ],
      activeKeys = new Set(rules.map(r => r.key));
    // The caller may allow for a full collection cycle (many slow sources sharing a few
    // workers), so queueing is not mistaken for a monitoring gap; a longer silence
    // (a restart, a suspended host, a storage outage) still resets pending state.
    const staleAfter = Math.max(
      maxGapMs(service.pollSeconds, service.collectionTimeoutSeconds),
      Number.isFinite(service.staleAfterMs) ? service.staleAfterMs : 0
    );
    const remove = key =>
      this.#prepare('DELETE FROM alerts WHERE service=? AND rule=?').run(service.id, key);
    const resetRecovery = key =>
      this.#prepare(
        'UPDATE alerts SET recovery_since=NULL,recovery_count=0,updated=? WHERE service=? AND rule=?'
      ).run(time, service.id, key);
    const write = (rule, state, since, count, message, recoverySince = null, recoveryCount = 0) =>
      this.#prepare(
        'INSERT OR REPLACE INTO alerts(service,rule,state,since,count,message,updated,recovery_since,recovery_count) VALUES(?,?,?,?,?,?,?,?,?)'
      ).run(service.id, rule.key, state, since, count, message, time, recoverySince, recoveryCount);
    for (const old of this.#prepare('SELECT * FROM alerts WHERE service=?').all(service.id))
      if (!activeKeys.has(old.rule)) remove(old.rule);
    for (const rule of rules) {
      let old = this.#prepare('SELECT * FROM alerts WHERE service=? AND rule=?').get(
        service.id,
        rule.key
      );
      const gap = old && time - old.updated > staleAfter;
      if (old?.state === 'pending' && gap) {
        remove(rule.key);
        old = null;
      }
      const metric = metrics.find(m => whole(m.key) === rule.key),
        available = rule.key === '__availability',
        value = available ? Number(Boolean(error)) : metric?.value;
      // uid and since (1.5, additive): the event row is the outbox record the relay copies.
      const event = (kind, message, since) => ({
        service: service.id,
        name: service.name,
        kind,
        category: available ? 'availability' : 'measurement',
        rule: rule.key,
        message,
        time,
        uid: newEventUid(),
        since,
      });
      // Failed/missing measurements cannot confirm recovery, even if prior data looked healthy.
      if (!available && (error || !Number.isFinite(value))) {
        if (old?.state === 'pending') remove(rule.key);
        else if (old) resetRecovery(rule.key);
        continue;
      }
      const matches = rule.operator === 'gt' ? value > rule.threshold : value < rule.threshold;
      // Say why: "Source is unavailable" alone gave no hint what to fix.
      const message = available
        ? error
          ? `Source is unavailable: ${String(error).slice(0, 300)}`
          : 'Source is unavailable'
        : `${metric.label} is ${Number(value.toFixed(2))}${metric.unit ? ' ' + metric.unit : ''} (${rule.operator === 'gt' ? 'above' : 'below'} ${rule.threshold})`;
      if (old?.state === 'firing') {
        const boundary = rule.recoveryThreshold ?? rule.threshold,
          healthy = rule.operator === 'gt' ? value <= boundary : value >= boundary;
        if (matches || !healthy) {
          write(
            rule,
            'firing',
            old.since,
            old.count + (matches ? 1 : 0),
            matches ? message : old.message
          );
          continue;
        }
        const since = !gap && old.recovery_since !== null ? old.recovery_since : time,
          count = (!gap ? old.recovery_count : 0) + 1;
        if (
          count >= (service.recoverySuccesses ?? 2) &&
          time - since >= (service.recoverySeconds ?? 60) * 1000
        ) {
          remove(rule.key);
          transitions.push(
            event(
              'resolved',
              available
                ? `Connection restored after ${duration(since - old.since)}`
                : `${metric.label} returned within its recovery boundary`,
              old.since
            )
          );
        } else write(rule, 'firing', old.since, old.count, old.message, since, count);
      } else if (matches) {
        const since = old?.since ?? time,
          count = (old?.count ?? 0) + 1,
          state =
            count >= (available ? (service.availabilityFailures ?? 2) : 2) &&
            time - since >= rule.forSeconds * 1000
              ? 'firing'
              : 'pending';
        write(rule, state, since, count, message);
        if (state === 'firing') transitions.push(event('firing', message, since));
      } else if (old) remove(rule.key);
    }
    // relayed = 0: the relay copies each row into the outbox, then marks it by uid.
    for (const event of transitions)
      this.#prepare(
        'INSERT INTO events(service,time,kind,message,category,rule,since,uid,relayed) VALUES(?,?,?,?,?,?,?,?,0)'
      ).run(
        event.service,
        event.time,
        event.kind,
        event.message,
        event.category,
        event.rule,
        event.since,
        event.uid
      );
    return transitions;
  }
  reconcileRules(id, oldRules, newRules) {
    for (const previous of oldRules) {
      const next = newRules.find(rule => rule.key === previous.key);
      if (!next || ['operator', 'threshold', 'forSeconds'].some(key => next[key] !== previous[key]))
        this.#prepare('DELETE FROM alerts WHERE service=? AND rule=?').run(id, previous.key);
      else if ((next.recoveryThreshold ?? null) !== (previous.recoveryThreshold ?? null))
        this.#prepare(
          'UPDATE alerts SET recovery_since=NULL,recovery_count=0 WHERE service=? AND rule=?'
        ).run(id, previous.key);
    }
  }
  clearAlerts(id) {
    this.#prepare('DELETE FROM alerts WHERE service=?').run(id);
  }
  clearAllAlerts() {
    this.#db.exec('DELETE FROM alerts');
  }
  stats() {
    return {
      samples: this.#prepare('SELECT COUNT(*) AS count FROM readings').get().count,
      events: this.#prepare('SELECT COUNT(*) AS count FROM events').get().count,
      activeAlerts: this.#prepare("SELECT COUNT(*) AS count FROM alerts WHERE state='firing'").get()
        .count,
    };
  }
  markGap(id, time = Date.now()) {
    if (this.#pauseReadings()) return;
    this.#write(() => {
      this.#prepare(
        'INSERT OR REPLACE INTO readings(service,time,ok,metrics,error) VALUES (?,?,0,?,?)'
      ).run(id, time, '[]', GAP);
      this.#keepSummary(id, time);
    });
  }
  alerts() {
    return this.#prepare(
      "SELECT service,rule,since,message,updated FROM alerts WHERE state='firing' ORDER BY since DESC"
    ).all();
  }
  // The 1.x columns only: the dashboard's events keep their 1.4.x shape.
  events() {
    return this.#prepare(
      'SELECT id,service,time,kind,message,category,rule FROM events ORDER BY time DESC LIMIT 50'
    ).all();
  }
  /**
   * Alert changes still to relay to the outbox (relayed = 0, written by 1.5 with a uid), oldest
   * first, after `afterId`, at most `limit` (≤ 200), through the events_unrelayed index. 1.4.x's
   * rows (relayed NULL) are never returned. The relay pages from 0 within one sweep only: ids are
   * reused after a source is deleted (V1), so a cursor must never outlive a pass.
   */
  unrelayedEvents({ afterId = 0, limit = relayBatch } = {}) {
    const most = Math.max(1, Math.min(Math.floor(limit) || 1, relayBatch));
    return this.#all(
      sql`SELECT ${E.id}, ${E.uid}, ${E.service}, ${E.time}, ${E.kind}, ${E.message}, ${E.category}, ${E.rule}, ${E.since} FROM ${E.events} WHERE ${E.relayed} = 0 AND ${E.uid} IS NOT NULL AND ${E.id} > ${Number(afterId) || 0} ${dialect.orderBy(['id', 'asc', 'not null'])} ${dialect.limit(most)}`
    ).map(row => ({ ...row }));
  }
  /**
   * Marks events relayed by uid (never by id: V1), at most 200 per transaction; returns the rows
   * changed. A plain transaction, not the recycling write: a full history must not drop readings
   * to record a relay. Errors (a full disk) are thrown to the relay, which tries again.
   */
  markRelayed(uids) {
    const list = [...new Set((uids ?? []).filter(uid => typeof uid === 'string' && uid))];
    let changed = 0;
    for (let start = 0; start < list.length; start += relayBatch) {
      const part = list.slice(start, start + relayBatch);
      changed += this.#transaction(() =>
        this.#run(
          sql`UPDATE ${E.events} SET ${E.relayed} = 1 WHERE ${E.relayed} = 0 AND ${E.uid} IN ${sql.list(part)}`
        )
      );
    }
    return changed;
  }
  /**
   * For the roll-forward supersede (delivery spec D26, A63): of the given `keys` ([{service,
   * rule}], the alerts of the waiting notifications; a rule '' also matches NULL, as the outbox's
   * order key writes both), each (service, rule) with an event 1.4.x wrote (relayed NULL) after
   * `time`, and the newest such time. Every key is checked, however many other alerts 1.4.x
   * changed: 200 keys per statement, read through events_time. [{service, rule, time}]
   */
  legacyEventsAfter(time, { keys = [] } = {}) {
    const wanted = [];
    const seen = new Set();
    for (const key of keys ?? []) {
      if (typeof key?.service !== 'string') continue;
      const rule = typeof key.rule === 'string' ? key.rule : '';
      const name = `${key.service}\n${rule}`;
      if (seen.has(name)) continue;
      seen.add(name);
      wanted.push([key.service, rule]);
    }
    const found = [];
    for (let start = 0; start < wanted.length; start += relayBatch) {
      const part = wanted.slice(start, start + relayBatch);
      found.push(
        ...this.#all(
          sql`SELECT ${E.service}, ${E.rule}, MAX(${E.time}) AS newest FROM ${E.events} WHERE ${E.time} > ${Number(time) || 0} AND ${E.relayed} IS NULL AND (${E.service}, IFNULL(${E.rule}, ${''})) IN (VALUES ${sql.join(part.map(sql.list))}) GROUP BY ${E.service}, ${E.rule} ${dialect.orderBy(['service', 'asc', 'not null'], ['rule', 'asc', 'first'])}`
        ).map(row => ({ service: row.service, rule: row.rule, time: row.newest }))
      );
    }
    return found;
  }
  /**
   * After a restore (delivery spec D16): every event still to relay is marked relayed without
   * being sent, in transactions of at most 500 rows. Returns the rows changed.
   */
  discardUnrelayed() {
    let changed = 0;
    for (;;) {
      const part = this.#transaction(() =>
        this.#run(
          sql`UPDATE ${E.events} SET ${E.relayed} = 1 WHERE ${E.id} IN (SELECT ${E.id} FROM ${E.events} WHERE ${E.relayed} = 0 ${dialect.limit(discardBatch)})`
        )
      );
      changed += part;
      if (part < discardBatch) return changed;
    }
  }
  // Runs a chunked DELETE (its last parameter is the chunk size) until it removes less than
  // a full chunk. Each chunk commits on its own and the event loop runs between chunks, so
  // deleting days of history or a large source neither needs much WAL space nor stalls
  // collection and HTTP for seconds. Chunks start small and adapt to row size (a Proxmox
  // reading can be 40 KB), so each step stays short. No transaction spans a yield, so
  // record() and evaluate() can run in between. If the store is closed meanwhile (shutdown),
  // it stops and leaves the rest for the next prune.
  async #drain(text, parameters, shouldContinue = () => true) {
    let statement,
      limit = chunk / 10;
    while (this.#db.isOpen && shouldContinue()) {
      statement ??= this.#db.prepare(text);
      const started = performance.now();
      if (statement.run(...parameters, limit).changes < limit) return;
      const took = Math.max(1, performance.now() - started);
      limit = Math.max(10, Math.min(chunk, Math.round((limit * stepMs) / took)));
      await nextTurn();
    }
  }
  async prune(days, now = Date.now(), { shouldContinue = () => true } = {}) {
    const before = now - days * 86400000;
    // Charts read readings, not summaries, until the summaries of deleted readings are gone.
    this.#pruning += 1;
    try {
      try {
        // Committed chunks stay deleted even if a later one fails. An alert change still to
        // relay (relayed = 0) younger than 24 h is kept whatever the retention, until it is sent.
        for (const table of ['readings', 'events'])
          await this.#drain(
            `DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE time<?${table === 'events' ? ' AND (relayed IS NOT 0 OR time<=?)' : ''} ORDER BY time LIMIT ?)`,
            table === 'events' ? [before, now - unrelayedKeepMs] : [before],
            shouldContinue
          );
      } finally {
        // Whatever stopped the readings (done, stopped early or failed), the summaries follow
        // what is left, in short transactions. Any failure leaves charts on the readings until
        // a later start.
        try {
          while (this.#db.isOpen && this.#summaries) {
            if (this.#transaction(() => this.#trimSummaries(this.#oldestReading()))) break;
            await nextTurn();
          }
        } catch (e) {
          this.#summariesFailed(e);
        }
      }
      if (!this.#db.isOpen) return;
      // A passive checkpoint (best effort: the rows are already gone, and SQLite retries
      // checkpoints on later commits), then the cap follows the space freed.
      this.#disk.afterDelete();
    } finally {
      this.#pruning -= 1;
    }
  }
  async forget(id) {
    // Its charts read readings, not summaries, until both are gone.
    this.#erasing.set(id, (this.#erasing.get(id) ?? 0) + 1);
    let erased = false;
    try {
      // A large source's readings are deleted in short transactions, like prune(), so the
      // write-ahead log stays small even when the database is at its size budget.
      for (const table of ['readings', 'events'])
        await this.#drain(
          `DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE service=? LIMIT ?)`,
          [id]
        );
      // Its summaries too (a year of them is over 100,000 rows).
      try {
        while (this.#db.isOpen && this.#summaries) {
          const deleted = this.#transaction(() =>
            this.#run(
              dialect.deleteFrom(
                'history_summaries',
                sql`${S.service} = ${id} AND ${S.slot} IN (SELECT ${S.slot} FROM ${S.table} WHERE ${S.service} = ${id} ${dialect.orderBy(['slot', 'asc', 'not null'])} ${dialect.limit(summaryChunk)})`
              )
            )
          );
          if (deleted < summaryChunk) break;
          await nextTurn();
        }
      } catch (e) {
        this.#summariesFailed(e);
      }
      if (!this.#db.isOpen) return;
      // Also removes anything recorded for the source while the chunks ran.
      this.#transaction(() => {
        for (const table of ['latest', 'latest_notes', 'alerts', 'events', 'readings'])
          this.#prepare(`DELETE FROM ${table} WHERE service=?`).run(id);
        if (this.#summaries)
          try {
            this.#run(dialect.deleteFrom('history_summaries', sql`${S.service} = ${id}`));
            if (this.#marks)
              this.#run(dialect.deleteFrom('history_summary_marks', sql`${K.service} = ${id}`));
          } catch (e) {
            if (full(e)) throw e;
            this.#summariesFailed(e);
          }
      });
      this.#latest?.delete(id);
      erased = true;
    } finally {
      // Nothing of it is left, so nothing of it is unsummarised; after a failure part way, its
      // charts read its readings until the next start checks it.
      if (erased) this.#unsummarized.delete(id);
      else this.#unsummarized.add(id);
      const left = this.#erasing.get(id) - 1;
      if (left) this.#erasing.set(id, left);
      else this.#erasing.delete(id);
    }
  }
  close() {
    this.#keepMarks();
    this.#db.close();
  }
  /**
   * The raw connection, for tests only (exposeStoreConnections in lib/store-connections.mjs,
   * which no other server module may import); server code never has it.
   */
  get db() {
    if (!storeConnectionsExposed())
      throw new Error('The Store keeps its connection to itself; use its methods.');
    return this.#db;
  }
}
