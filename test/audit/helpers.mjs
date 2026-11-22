// Shared helpers for the audit core's tests (test/audit/**, test/repo/audit.test.mjs): a real,
// migrated control.sqlite with a real keyring, and the audit service over it with its stdout and
// stderr lines captured. Nothing here writes outside the temporary directories the tests make.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openControl } from '../../lib/db/control.mjs';
import { Keyring } from '../../lib/keyring.mjs';
import { createAudit } from '../../lib/audit/index.mjs';

export const keyA = Buffer.alloc(32, 0xa1);
export const keyB = Buffer.alloc(32, 0xb2);
export const release = JSON.parse(
  fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')
).version;

/** A temporary directory removed after the test. */
export function temporary(t, prefix = 'orbit-audit-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A manual clock: clock() returns the time; set(ms) and advance(ms) move it. */
export function manualClock(start = Date.UTC(2026, 9, 3, 12)) {
  let value = start;
  const clock = () => value;
  clock.advance = ms => (value += ms);
  clock.set = ms => (value = ms);
  return clock;
}

/**
 * A migrated control database in a new data directory: {directory, control, db, clock}. Closed
 * after the test. `directory` reuses an existing one.
 */
export async function migratedControl(t, { directory, clock = manualClock() } = {}) {
  directory ??= temporary(t);
  const control = openControl(directory, { release, env: {}, clock });
  t.after(() => control.close());
  await control.migrate();
  return { directory, control, db: control.db, clock };
}

/** The keyring of `control` under `key` (created when missing). */
export const openKeyring = (control, { key = keyA, clock = Date.now } = {}) =>
  Keyring.open(control.keyringStore, { key, clock });

/**
 * The audit service over a migrated control database, attached to a real keyring, with its
 * lines captured: {audit, control, db, keyring, clock, out, err, warnings, directory}. Options
 * pass to createAudit (wrapDb, guard, mirror, retention…); `attach: false` leaves it unattached.
 */
export async function auditFixture(t, options = {}) {
  const { attach = true, directory: given, clock: givenClock, key = keyA, ...rest } = options;
  const clock = givenClock ?? manualClock();
  const { directory, control, db } = await migratedControl(t, { directory: given, clock });
  const keyring = await openKeyring(control, { key, clock });
  const out = [],
    err = [],
    warnings = [];
  const audit = createAudit({
    db,
    directory,
    release: { version: release, build: 'test' },
    clock,
    out: line => out.push(line),
    err: line => err.push(line),
    log: { warn: line => warnings.push(line), info() {}, error() {} },
    ...rest,
  });
  if (attach) await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
  t.after(() => audit.close());
  return { audit, control, db, keyring, clock, out, err, warnings, directory };
}

/** The parsed lines of `lines` whose `orbit` is `kind` (audit.checkpoint, audit, audit.unwritten). */
export const linesOf = (lines, kind) =>
  lines
    .map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(line => line?.orbit === kind);

/** Every audit_log row, oldest first, as stored (lib/repo/audit.mjs rowOf). */
export async function storedRows(db) {
  const { auditOps } = await import('../../lib/repo/audit.mjs');
  return db.read(tx =>
    auditOps.rowsFrom(tx, { afterSeq: 0, toSeq: Number.MAX_SAFE_INTEGER, limit: 1e6 })
  );
}

/** A request's frozen facts as the pipeline builds them (audit spec §4.4). */
export const adminRequest = (overrides = {}) =>
  Object.freeze({
    requestId: 'req-1',
    route: 'PATCH /api/settings',
    client: '192.0.2.10',
    userAgent: 'Mozilla/5.0 (test)',
    actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_test1' },
    ...overrides,
  });

/** A write unit that runs a statement of its own and record()s `event` (another component's unit). */
export function recordIn(db, audit, event, { before = () => {}, after = () => {} } = {}) {
  return db.write(tx => {
    before(tx);
    audit.record(tx, event);
    after(tx);
  });
}
