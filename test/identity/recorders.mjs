// The audit recorders identity's audit tests run against (audit spec §9.1 I, §2.3): every test of
// test/identity/audit.test.mjs runs once per recorder that can show what it checks.
//
// - `fake`: fakeAudit() (test/helpers/fake-audit.mjs, Phase 0): rows in memory, kept until the
//   caller's unit commits (tx.onCommit), events validated as the writer validates them.
// - `table`: the same rows kept in control.sqlite itself: record(tx, event) inserts the event
//   into audit_inbox in the caller's unit, as the writer does before it holds the keyring
//   (§4.3), and prints one line per unit that recorded (tx.onCommit, as the writer's checkpoint
//   line). It shows on a real database, before lane O's writer exists on this branch, that a row
//   commits, rolls back and is retried with its change.
// - `writer`: lane O's createAudit() (lib/audit/index.mjs, §4.1) over the same control.sqlite,
//   attached to a real keyring: the chained rows, their checkpoint lines and verification. On a
//   branch without the writer the tests that need it skip, naming integration (§2.3 step 2).
//
// Each recorder gives {name, audit (or a factory for startIdentity's `audit`), rows() (the rows,
// in order, as {action, outcome, actor, client, userAgent, requestId, target, detail, meta}),
// lines() (one entry per unit that wrote rows, after its commit), unwritten() (rows that reached
// stderr: unrecorded() and refused rows)}.
import fs from 'node:fs';
import path from 'node:path';
import { sql, id, json } from '../../lib/db/sql.mjs';
import { Keyring } from '../../lib/keyring.mjs';
import { fakeAudit, auditDefect } from '../helpers/fake-audit.mjs';

const systemActor = Object.freeze({
  type: 'system',
  id: null,
  name: 'orbit',
  via: 'system',
  sessionId: null,
});

/** An event as a row shows it: the writer's defaults filled in (§4.1). */
export const viewOf = event => ({
  action: event.action,
  outcome: event.outcome,
  actor: { ...systemActor, ...(event.actor ?? {}) },
  client: event.client ?? null,
  userAgent: event.userAgent ?? null,
  requestId: event.requestId ?? null,
  target: event.target ?? null,
  detail: event.detail ?? null,
  meta: event.meta ?? null,
});

const fullError = () => Object.assign(new Error('database or disk is full'), { class: 'full' });

/** The fake recorder (see the top). */
export function fakeRecorder({ clock, ready = true } = {}) {
  const audit = fakeAudit({ clock, ready });
  return {
    name: 'fake',
    audit,
    rows: async () => audit.rows.map(row => ({ mode: row.mode, ...viewOf(row) })),
    // fakeAudit prints nothing; its rows commit with their unit, so a unit that recorded is
    // counted by the rows it left (the table and writer recorders count real lines).
    lines: null,
    unwritten: () => [
      ...audit.unrecorded.calls.map(({ event }) => viewOf(event)),
      ...audit.unwritten.map(viewOf),
    ],
    failRecords: on => audit.setFailing('record', on ? fullError() : null),
  };
}

/** The table recorder (see the top): rows in control.sqlite's audit_inbox. */
export function tableRecorder({ clock } = {}) {
  const fake = fakeAudit({ clock });
  const lines = [];
  const units = new WeakMap();
  let control = null;
  // `source` tells the stand-in's two kinds apart: `start` for record() (the writer's own value
  // for identity's inbox rows), `system` for system() (a row in its own unit).
  const insert = (tx, event, source) => {
    // A refused event is a defect of identity's: these tests fail on it at once.
    const why = auditDefect(event);
    if (why) throw new TypeError(`identity recorded an event the writer refuses: ${why}`);
    tx.run(
      tx.dialect.insert('audit_inbox', ['time', 'source', 'event'], {
        time: event.at ?? clock(),
        source,
        event: json(event),
      })
    );
    let unit = units.get(tx);
    if (!unit) {
      unit = [];
      units.set(tx, unit);
      tx.onCommit(() => lines.push(unit));
    }
    unit.push(event.action);
  };
  const audit = {
    ...fake,
    record: (tx, event) => insert(tx, event, 'start'),
    system: event => control.db.write(tx => insert(tx, event, 'system')),
  };
  return {
    name: 'table',
    // startIdentity calls this with the migrated control database, before createIdentity.
    audit: opened => {
      control = opened;
      return audit;
    },
    async rows() {
      const stored = await control.db.read(tx =>
        tx.all(
          sql`SELECT ${id('source')}, ${id('event')} FROM ${id('audit_inbox')} ORDER BY ${id('id')}`
        )
      );
      return stored.map(row => ({
        mode: row.source === 'start' ? 'record' : 'system',
        ...viewOf(JSON.parse(row.event)),
      }));
    },
    lines: () => lines,
    unwritten: () => [
      ...fake.unrecorded.calls.map(({ event }) => viewOf(event)),
      ...fake.unwritten.map(viewOf),
    ],
  };
}

/**
 * A `wrap` for startIdentity whose units fail every audit insert (into audit_log or audit_inbox)
 * with class `full` while `on` is set, as a disk with room for the change but not for its row
 * would (audit spec §9.1 I "D32"): the tx identity's callbacks get is the real one but for that.
 */
export function failingAuditInserts() {
  const state = { on: false, refused: 0 };
  const proxied = tx =>
    new Proxy(tx, {
      get(target, key) {
        if (key === 'run')
          return query => {
            if (
              state.on &&
              /^INSERT INTO "audit_(?:log|inbox)"/.test(target.dialect.render(query).text)
            ) {
              state.refused += 1;
              throw fullError();
            }
            return target.run(query);
          };
        const value = Reflect.get(target, key, target);
        // The transaction's methods use private fields, so they run on it.
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  state.wrap = control => {
    const db = control.db;
    return {
      ...control,
      db: new Proxy(db, {
        get(target, key) {
          if (key === 'write') return (fn, options) => target.write(tx => fn(proxied(tx)), options);
          const value = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }),
    };
  };
  return state;
}

/**
 * A `wrap` for startIdentity that fails the next `armed` units of one kind, after their callback
 * ran to its end, as a COMMIT can fail (class `unavailable`: not a full disk, so nothing is made
 * again without its row). `kind` is `change`, a unit that changed one of identity's own tables
 * (anything but the audit's), or `record`, a unit in which a row was recorded (an audit insert,
 * or a commit callback registered, as every recorder does). Identity records in the unit of its
 * change, so either kind fails both the change and its row; a row recorded in another unit, or
 * outside one, survives the failure of the change, and a change made in another unit survives
 * the failure of its row: "throw after record" finds either.
 */
export function failingUnits(kind = 'change') {
  const state = { armed: 0, kind };
  const changes = text => /^(?:INSERT INTO|UPDATE|DELETE FROM) "(?!audit_)/.test(text);
  const records = text => /^INSERT INTO "audit_/.test(text);
  const noting = (tx, touched) =>
    new Proxy(tx, {
      get(target, key) {
        if (key === 'run')
          return query => {
            const text = target.dialect.render(query).text;
            if (state.kind === 'change' ? changes(text) : records(text)) touched.value = true;
            return target.run(query);
          };
        if (key === 'onCommit')
          return fn => {
            if (state.kind === 'record') touched.value = true;
            return target.onCommit(fn);
          };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  state.wrap = control => ({
    ...control,
    db: new Proxy(control.db, {
      get(target, key) {
        if (key === 'write')
          return (fn, options) =>
            target.write(tx => {
              const touched = { value: false };
              const result = fn(noting(tx, touched));
              if (touched.value && state.armed > 0) {
                state.armed -= 1;
                throw Object.assign(new Error('disk I/O error'), { class: 'unavailable' });
              }
              return result;
            }, options);
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }),
  });
  return state;
}

// ---------------------------------------------------------------------------------------------
// Lane O's writer (integration).

const writerFile = new URL('../../lib/audit/index.mjs', import.meta.url);
/** Why the writer tests skip on this branch, or false when lib/audit/index.mjs is here. */
export const writerMissing = fs.existsSync(writerFile)
  ? false
  : "lane O's audit writer (lib/audit/index.mjs) is not on this branch: runs at integration (audit spec §2.3)";

const auditKey = Buffer.alloc(32, 11);
// The JSON lines of a stream with `orbit` set to `kind` (anything else printed is left out).
const linesOf = (lines, kind) =>
  lines.flatMap(line => {
    try {
      const parsed = JSON.parse(line);
      return parsed?.orbit === kind ? [parsed] : [];
    } catch {
      return [];
    }
  });
const version = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url))).version;

/** The rows of audit_log, in seq order, as rows() gives them (detail parsed). */
export async function chainedRows(control) {
  const stored = await control.db.read(tx =>
    tx.all(sql`SELECT * FROM ${id('audit_log')} ORDER BY ${id('seq')}`)
  );
  return stored.map(row => ({
    mode: 'record',
    seq: Number(row.seq),
    hash: row.hash,
    action: row.action,
    outcome: row.outcome,
    actor: {
      type: row.actor_type,
      id: row.actor_id,
      name: row.actor_name,
      via: row.via,
      sessionId: row.session_id,
    },
    client: row.client_key,
    userAgent: row.user_agent,
    requestId: row.request_id,
    target:
      row.target_type === null && row.target_id === null && row.target_name === null
        ? null
        : { type: row.target_type, id: row.target_id, name: row.target_name },
    detail: row.detail === null ? null : JSON.parse(row.detail),
    // The writer applies an event's meta to the meta table in the row's unit (§3.4).
    meta: null,
  }));
}

/** The events of audit_inbox, in id order. */
export async function inboxEvents(control) {
  const stored = await control.db.read(tx =>
    tx.all(sql`SELECT ${id('event')} FROM ${id('audit_inbox')} ORDER BY ${id('id')}`)
  );
  return stored.map(row => JSON.parse(row.event));
}

/**
 * The writer recorder: createAudit() over the control database identity uses, attached to a
 * keyring (made here, as server.mjs's start makes one) before identity starts, unless
 * `attach: false` (a data directory's first start: identity's rows go to the inbox until
 * `attachNow()`). `lines()` holds the checkpoint lines, `unwritten()` the audit.unwritten lines.
 */
export async function writerRecorder({ clock, attach = true } = {}) {
  const { createAudit } = await import(writerFile.href);
  const out = [],
    err = [];
  const quiet = { info() {}, log() {}, warn() {}, error() {} };
  let control = null,
    audit = null;
  const recorder = {
    name: 'writer',
    audit: async opened => {
      control = opened;
      audit = createAudit({
        db: opened.db,
        directory: path.dirname(opened.file),
        release: { version, build: 'identity-audit-test' },
        clock,
        out: line => out.push(line),
        err: line => err.push(line),
        log: quiet,
      });
      if (attach) await recorder.attachNow();
      return audit;
    },
    async attachNow() {
      const keyring = await Keyring.open(control.keyringStore, { key: auditKey, clock });
      await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
    },
    rows: async () => {
      await audit.idle();
      return chainedRows(control);
    },
    lines: () => linesOf(out, 'audit.checkpoint'),
    unwritten: () => linesOf(err, 'audit.unwritten').map(line => line.row),
    verify: async () => (await audit.verify()).result,
  };
  return recorder;
}
