// Shared helpers for the identity tests (test/identity/**): real control databases on temporary
// directories, migrated with the release steps, and a deterministic KDF where speed matters.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { openControl } from '../../lib/db/control.mjs';
import { createIdentity, readBuiltinSources } from '../../lib/identity/index.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { scryptParameters } from '../../lib/identity/password.mjs';
import { sql, id } from '../../lib/db/sql.mjs';

export const adminPassword = 'fixture admin password';
export const otherPassword = 'another fixture password';

/** A temporary directory removed after the test. */
export function temporary(t, prefix = 'orbit-identity-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A manual clock: clock() returns the time; advance(ms) and set(ms) move it. */
export function manualClock(start = Date.UTC(2026, 8, 1)) {
  let value = start;
  const clock = () => value;
  clock.advance = ms => (value += ms);
  clock.set = ms => (value = ms);
  return clock;
}

/** A deterministic stand-in for scrypt (64 bytes, like the real key). Production uses scrypt. */
export const fakeKey = (password, salt) =>
  createHash('sha512').update(salt).update(password).digest();

/** A derive that counts its calls (`derive.calls`) and can be held (`derive.hold()`). */
export function countingDerive() {
  const held = [];
  let holding = false;
  const derive = async (password, salt) => {
    derive.calls += 1;
    const key = fakeKey(Buffer.from(password), Buffer.from(salt));
    if (!holding) return key;
    return new Promise(resolve => held.push(() => resolve(key)));
  };
  derive.calls = 0;
  derive.hold = () => (holding = true);
  derive.release = () => {
    holding = false;
    held.splice(0).forEach(resolve => resolve());
  };
  derive.pending = () => held.length;
  return derive;
}

/** A v1 record of `password` under the fake KDF. */
export function fakeRecord(
  password,
  { salt = Buffer.alloc(32, 7), passwordChangedAt = 123456 } = {}
) {
  return {
    version: 1,
    algorithm: 'scrypt',
    parameters: { ...scryptParameters },
    salt: salt.toString('hex'),
    hash: fakeKey(Buffer.from(password), salt).toString('hex'),
    passwordChangedAt,
  };
}

/** Writes auth.json as 1.4.x does (or `text` as is); returns the bytes written. */
export function writeAuthJson(directory, record, { text } = {}) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const bytes = Buffer.from(text ?? JSON.stringify(record) + '\n');
  fs.writeFileSync(path.join(directory, 'auth.json'), bytes, { mode: 0o600 });
  return bytes;
}

export const readAuthJson = directory => fs.readFileSync(path.join(directory, 'auth.json'), 'utf8');

/** The decoded Basic credential for `password`. */
export const basicBytes = (password, user = 'admin') => Buffer.from(`${user}:${password}`, 'utf8');

/** A log that records every line: {log, lines, text()}. */
export function captureLog() {
  const lines = [];
  const add =
    level =>
    (...args) =>
      lines.push({ level, text: args.join(' ') });
  return {
    log: { info: add('info'), log: add('log'), warn: add('warn'), error: add('error') },
    lines,
    text: () => lines.map(line => line.text).join('\n'),
  };
}

/** Opens and migrates <directory>/control.sqlite (the release steps); closed after the test. */
export async function openTestControl(t, directory, { clock = Date.now } = {}) {
  const control = openControl(directory, { release: '1.5.0', env: {}, clock });
  t.after(() => control.close());
  await control.migrate();
  return control;
}

/**
 * Starts identity on `directory` as server.mjs does (sources read first, then the control
 * database, then createIdentity). Options: password (GOBLIN_PASSWORD), insecureHttpSessions,
 * clock, derive, limits, displayLimits, audit (the recorder, or a function of the migrated control database
 * that returns it, awaited before createIdentity; a fakeAudit({clock}) by default),
 * writeAuthRecord, log, wrap (control → the object createIdentity gets, for instrumented()),
 * controlOptions (more openControl options: busyTimeoutMs, retries, sleep).
 * Returns {identity, control, db (the Db identity uses), directory, clock, audit, events (the
 * rows the audit recorded: audit.rows of a fakeAudit), logged, stop()}; stop() closes both (also
 * done after the test), for a restart.
 */
export async function startIdentity(t, directory, options = {}) {
  const {
    password,
    insecureHttpSessions = false,
    clock = manualClock(),
    derive = fakeKey,
    limits,
    displayLimits,
    audit: recorder = fakeAudit({ clock }),
    writeAuthRecord,
    log,
    wrap,
    controlOptions = {},
  } = options;
  const sources = readBuiltinSources({ directory, password });
  const control = openControl(directory, { release: '1.5.0', env: {}, clock, ...controlOptions });
  let stopped = false;
  const logged = log ? null : captureLog();
  let identity;
  const stop = () => {
    if (stopped) return;
    stopped = true;
    identity?.close();
    control.close();
  };
  t.after(stop);
  await control.migrate();
  const audit = typeof recorder === 'function' ? await recorder(control) : recorder;
  const used = wrap ? wrap(control) : control;
  identity = await createIdentity({
    control: used,
    directory,
    sources,
    insecureHttpSessions,
    clock,
    derive,
    ...(limits ? { limits } : {}),
    ...(displayLimits ? { displayLimits } : {}),
    audit,
    ...(writeAuthRecord ? { writeAuthRecord } : {}),
    log: log ?? logged.log,
  });
  return {
    identity,
    control,
    db: used.db,
    directory,
    clock,
    audit,
    events: audit.rows ?? [],
    logged,
    stop,
    sources,
  };
}

/** Rows of an identity table, read directly (tests only). */
export function rows(control, table) {
  return control.db.read(tx => tx.all(sql`SELECT * FROM ${id(table)}`));
}

/** identity_settings as {key: value}. */
export async function settings(control) {
  return Object.fromEntries(
    (await rows(control, 'identity_settings')).map(row => [row.key, row.value])
  );
}

/** A meta value, or null. */
export async function meta(control, key) {
  return (
    (
      await control.db.read(tx =>
        tx.get(sql`SELECT ${id('value')} FROM ${id('meta')} WHERE ${id('key')} = ${key}`)
      )
    )?.value ?? null
  );
}

/** The u_admin row as stored. */
export async function adminRow(control) {
  return (await rows(control, 'users')).find(row => row.id === 'u_admin') ?? null;
}

/**
 * A Db wrapper that counts write units and can make the next writes fail (`failWrites(n,
 * error)`), for the storage and ordering tests. createIdentity uses only `control.db`.
 */
export function instrumented(control) {
  let failures = 0,
    failure = null;
  const db = control.db;
  const wrapper = {
    writes: 0,
    reads: 0,
    name: db.name,
    get dialect() {
      return db.dialect;
    },
    read(fn, options) {
      wrapper.reads += 1;
      return db.read(fn, options);
    },
    write(fn, options) {
      wrapper.writes += 1;
      if (failures > 0) {
        failures -= 1;
        // Like a failing COMMIT: the callback runs (synchronously, as db.write does), then
        // everything it did is rolled back and the call rejects.
        const error = failure();
        return db
          .write(tx => {
            fn(tx);
            throw error;
          }, options)
          .catch(() => Promise.reject(error));
      }
      return db.write(fn, options);
    },
    failWrites(count, make = () => Object.assign(new Error('disk full'), { class: 'full' })) {
      failures = count;
      failure = make;
    },
  };
  return { ...control, db: wrapper };
}

/**
 * Records, in order, the calls that decide what a power loss can leave of an auth.json write:
 * `fsync <what>` (a path relative to `directory`, '.' for the directory itself) and
 * `rename <from> -> <to>`, a temporary's random part shown as <uuid>. Options: `events` (the
 * array to push to, shared with notingRecords), `failFlush` (an fsync of `directory` itself
 * throws EIO, as on a failing disk). Returns {events, stop() (puts fs back; also done after
 * the test), at(event, from) (its index at or after `from`, asserted present)}.
 */
export function traceDurability(t, directory, { events = [], failFlush = false } = {}) {
  const opened = new Map();
  const short = file =>
    path.relative(directory, String(file)).replace(/[0-9a-f-]{36}/, '<uuid>') || '.';
  const { openSync, fsyncSync, renameSync } = fs;
  const stop = () => Object.assign(fs, { openSync, fsyncSync, renameSync });
  t.after(stop);
  fs.openSync = function (...args) {
    const handle = openSync.apply(this, args);
    opened.set(handle, short(args[0]));
    return handle;
  };
  fs.fsyncSync = function (...args) {
    const what = opened.get(args[0]);
    events.push(`fsync ${what}`);
    if (failFlush && what === '.')
      throw Object.assign(new Error('input/output error'), { code: 'EIO' });
    return fsyncSync.apply(this, args);
  };
  fs.renameSync = function (...args) {
    events.push(`rename ${short(args[0])} -> ${short(args[1])}`);
    return renameSync.apply(this, args);
  };
  const at = (event, from = 0) => {
    const index = events.indexOf(event, from);
    if (index === -1) throw new Error(`${event} (after #${from}) not in:\n${events.join('\n')}`);
    return index;
  };
  return { events, stop, at };
}

/**
 * A `wrap` for startIdentity that pushes 'record' to `events` from each write that changes
 * builtin.authJsonSha256, once its callback ran (its COMMIT follows), so a test can order the
 * record after the fsyncs and renames traceDurability notes.
 */
export const notingRecords = events => control => {
  const db = control.db;
  const fingerprint = tx =>
    tx.get(
      sql`SELECT ${id('value')} FROM ${id('identity_settings')} WHERE ${id('key')} = ${'builtin.authJsonSha256'}`
    )?.value ?? null;
  return {
    ...control,
    db: {
      name: db.name,
      get dialect() {
        return db.dialect;
      },
      read: (fn, options) => db.read(fn, options),
      write: (fn, options) =>
        db.write(tx => {
          const before = fingerprint(tx);
          const result = fn(tx);
          if (fingerprint(tx) !== before) events.push('record');
          return result;
        }, options),
    },
  };
};
