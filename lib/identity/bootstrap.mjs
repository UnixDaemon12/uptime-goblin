// The built-in admin's password at start (sessions spec §5.6, §5.7): where it comes from, what
// changed while Uptime Goblin was stopped, and the auth.json mirror that keeps a rollback to 1.4.x on
// the current password.
//
// control.sqlite is authoritative (users.password). 1.4.x reads only auth.json and
// GOBLIN_PASSWORD, so:
// - every in-app change is mirrored to auth.json (index.mjs; retried here at start and hourly);
// - a password changed outside Uptime Goblin (under 1.4.x during a rollback, by moving auth.json aside
//   and setting GOBLIN_PASSWORD, or by editing GOBLIN_PASSWORD) is detected by comparing what the
//   sources hold now with what identity_settings recorded, and imported: every session ends;
// - a snapshot restore (meta.restored) signs everyone out once, whatever the password;
// - so does a control.sqlite that is not the file Uptime Goblin last ran with (a backup of the data
//   directory restored by tar, cp or a volume copy, or one copied or moved to another disk):
//   sessions live in that file, so a backup brings back every session it held, including those
//   signed out since, and its auth.json matches its own fingerprint, so nothing is imported.
// Scrypt work runs first; one db.write then applies the outcome with a compare-and-swap on
// users.row_version, and records what it did in the same unit (writeRecorded, below).
import fs from 'node:fs';
import { localModeGuardMessage, passwordRequiredMessage } from '../db/control.mjs';
import { identityOps } from '../repo/identity.mjs';
import {
  readAuthRecord,
  checkBootstrapPassword,
  makeRecord,
  verifyRecord,
  validRecord,
  flushDirectory,
  writeAuthRecord as writeAuthFile,
} from './password.mjs';

/** The built-in admin's user id. */
export const BUILTIN_ID = 'u_admin';

const refusal = message => Object.assign(new Error(message), { refusal: true });

// The refusals of a start without any admin password source (exit status 78): Uptime Goblin always
// requires one, and never generates it. passwordRequiredMessage is the one server.mjs and
// startControl give (they refuse first); bootstrapBuiltin gives it too, before its first write,
// for any other caller, and localModeGuardMessage for a stored password without a source (the
// fail-closed backstop). One definition each, in lib/db/control.mjs, so the refusals cannot
// drift apart.
export { localModeGuardMessage, passwordRequiredMessage };
const damagedMessage =
  'The saved admin password in control.sqlite is damaged, and neither auth.json nor GOBLIN_PASSWORD is present to restore it. Restore auth.json from a backup, or set GOBLIN_PASSWORD, then start Uptime Goblin again.';

/** identity_settings keys (§4.3). */
export const keys = Object.freeze({
  source: 'builtin.source',
  sha: 'builtin.authJsonSha256',
  verifier: 'builtin.envVerifier',
  mirrorPending: 'builtin.mirrorPending',
  restoreSeen: 'builtin.restoreSeen',
  controlFile: 'builtin.controlFile',
  credentialsAnchor: 'tokens.anchor',
});

/**
 * Which file `file` (control.sqlite, open) is, as JSON text for builtin.controlFile:
 * {"ino": "<inode>"} plus "birth" (its creation time in ns) where the system reports one. A
 * restored or copied control.sqlite is a new file, with a new inode or, when the file system
 * reuses the inode number of the deleted one, a new birth time; SQLite writes in place, so
 * Uptime Goblin's own writes change neither. The device number is left out: it can change at a reboot
 * (ZFS, btrfs), which is not a restore. A birth time of 0, or one equal to the change time,
 * is a system without one (Linux without statx reports the change time), so it is left out.
 * Null when the file cannot be read (the check is then skipped).
 */
export function controlFileIdentity(file) {
  let stat;
  try {
    stat = fs.statSync(file, { bigint: true });
  } catch {
    return null;
  }
  const identity = { ino: String(stat.ino) };
  if (stat.birthtimeNs > 0n && stat.birthtimeNs !== stat.ctimeNs)
    identity.birth = String(stat.birthtimeNs);
  return JSON.stringify(identity);
}

// Whether two builtin.controlFile values name another file: another inode, or another birth
// time when both have one. Null when either is unknown or does not parse (no conclusion).
function otherFile(recorded, current) {
  let a, b;
  try {
    a = JSON.parse(recorded);
    b = JSON.parse(current);
  } catch {
    return null;
  }
  if (typeof a?.ino !== 'string' || typeof b?.ino !== 'string') return null;
  if (a.ino !== b.ino) return true;
  return typeof a.birth === 'string' && typeof b.birth === 'string' && a.birth !== b.birth;
}

/**
 * Whether the control.sqlite at `file` was put in place after the last start that ran on it, as
 * the next start would find (and sign everyone out for): a snapshot restore whose stamp no start
 * has handled yet, or another file than the one the last start recorded (a backup put back, a
 * copy). `records` is readStartRecords(file, [keys.restoreSeen, keys.controlFile]). False when
 * they show neither, also when no start has recorded anything in it yet. restore-snapshot asks
 * this of the file it replaced: only a keyring Uptime Goblin last ran with shows the key Uptime Goblin uses
 * (review OPS-801-2).
 */
export function placedSinceLastStart(file, { restored, settings }) {
  if (restored !== null && restored !== (settings[keys.restoreSeen] ?? null)) return true;
  const recorded = settings[keys.controlFile] ?? null;
  return recorded !== null && otherFile(recorded, controlFileIdentity(file)) === true;
}

/** The credential boundary is separate from builtin markers written by older builds. */
export function credentialAnchorChanged({ anchor, restored, controlFile, hasCredentials }) {
  let value;
  try {
    value = JSON.parse(anchor);
  } catch {}
  const valid =
    value &&
    !Array.isArray(value) &&
    Object.hasOwn(value, 'controlFile') &&
    Object.hasOwn(value, 'restoreSeen') &&
    (value.controlFile === null ||
      (typeof value.controlFile === 'string' &&
        otherFile(value.controlFile, value.controlFile) !== null)) &&
    (value.restoreSeen === null || typeof value.restoreSeen === 'string');
  if (!valid) return Boolean(hasCredentials);
  // Unknown file identity is not proof that retained credentials belong to this file.
  if (hasCredentials && (value.controlFile === null || controlFile === null)) return true;
  return (
    (restored !== null && restored !== value.restoreSeen) ||
    otherFile(value.controlFile, controlFile) === true
  );
}

/** CLI preflight only: callers must coordinate restores with active writers. */
export function credentialsPlacedSinceLastStart(file, records, { hasCredentials = false } = {}) {
  return (
    placedSinceLastStart(file, records) ||
    credentialAnchorChanged({
      anchor: records.settings[keys.credentialsAnchor] ?? null,
      restored: records.restored,
      controlFile: controlFileIdentity(file),
      hasCredentials,
    })
  );
}

/**
 * What this data directory's configured sources hold now, read before startControl (so a bad
 * auth.json or GOBLIN_PASSWORD refuses before control.sqlite exists). Reads only: it never
 * creates the directory or changes a mode.
 * - auth.json: 1.4.3's rules (see readAuthRecord): a symlink or bad content refuses (78),
 *   another system error is rethrown (exit 1, retried).
 * - GOBLIN_PASSWORD (`password`): only when auth.json is absent, as 1.4.x: validated then, and
 *   ignored (unvalidated) while auth.json exists.
 * Returns {authJson: {record, sha256} | null, env: {password} | null, configured}.
 */
export function readBuiltinSources({ directory, password } = {}) {
  const authJson = readAuthRecord(directory);
  const env = !authJson && password ? { password: checkBootstrapPassword(password) } : null;
  return { authJson, env, configured: Boolean(authJson || env) };
}

/** The stored record: {record} when valid, {record: null} when none, {damaged: true} otherwise. */
export function parseStored(text) {
  if (text === null || text === undefined) return { record: null, damaged: false };
  try {
    const record = JSON.parse(text);
    if (validRecord(record)) return { record, damaged: false };
  } catch {}
  return { record: null, damaged: true };
}

const parseVerifier = text => {
  const parsed = parseStored(text ?? null);
  return parsed.damaged ? null : parsed.record;
};

// A value from the data directory, fit for one log line: no control characters, bounded.
const printable = value =>
  String(value)
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .slice(0, 200);

// ---------------------------------------------------------------------------------------------
// Audit rows (audit spec §5.1, D23, D32). Each change identity makes in control.sqlite records
// its row through audit.record(tx, event) inside the write callback of that change, after its
// last statement: a callback db.write runs again after an error of class `retry` records again
// in the attempt that commits (the rolled-back attempt's row went with it), and a throw rolls
// the change and its row back together. The audit writes the row (lib/audit): chained once it
// holds the keyring, else into audit_inbox in the same unit (a data directory's first start).
// Events carry no actor where Uptime Goblin acted on its own: the writer's default is the system actor.

/** The account target of identity's rows (§5.8). */
export const accountTarget = Object.freeze({ type: 'account', id: BUILTIN_ID, name: null });
/** A session target: one session's id, or null for a row that counts several. */
export const sessionTarget = id => ({ type: 'session', id, name: null });
const authFileTarget = Object.freeze({ type: 'file', id: 'auth.json', name: null });
const orbitTarget = Object.freeze({ type: 'orbit', id: null, name: null });

/**
 * Runs one write unit of `change` and records its audit rows in it (see above). `change(tx)`
 * makes the change and returns {result, events}; the events are recorded after it returned, so
 * after its last statement. With `fallback` (a sign-out, a revocation, flushRevoked, a start's
 * unit) a unit that fails with class `full` once its callback ran is made again without its
 * rows, and each event goes to audit.unrecorded() (one stderr line): the session rows are
 * deleted whenever the disk allows the delete alone, so no revocation fails open and no start
 * fails because of its audit row (D32, §13 M8). A unit that failed before its callback ran never
 * held its rows, so they cannot be why: that failure is the caller's, as is any other, and every
 * failure without `fallback` (a sign-in, a password change: they succeed or fail with their row,
 * §13 M2). Resolves the change's result.
 */
export async function writeRecorded(db, audit, change, { fallback = false } = {}) {
  let ran = false;
  try {
    return await db.write(tx => {
      ran = true;
      const { result, events = [] } = change(tx);
      for (const event of events) audit.record(tx, event);
      return result;
    });
  } catch (error) {
    if (!fallback || !ran || error?.class !== 'full') throw error;
    // The events of the attempt that committed: a retried attempt's are replaced, not added.
    let made = [];
    const result = await db.write(tx => {
      const { result: value, events = [] } = change(tx);
      made = events;
      return value;
    });
    for (const event of made) audit.unrecorded(event, error);
    return result;
  }
}

/**
 * Records a row of something that changed nothing in control.sqlite (a mirror that failed, a
 * sign-out that could not be saved) through audit.system(): its own unit, best effort. system()
 * never rejects; the catch keeps a recorder's defect from failing a change that already stands.
 */
export async function recordSystem(audit, event) {
  try {
    await audit.system(event);
  } catch {}
}

/** identity.mirror.failed (§5.1): auth.json could not be written; `code` an error code. */
export const mirrorFailedEvent = code => ({
  action: 'identity.mirror.failed',
  outcome: 'failed',
  target: authFileTarget,
  detail: { code },
});

// users.password_changed_at as the audit keeps it (meta.audit_password_changed_at, §3.4): the
// start compares it with the stored value to find a change made by an earlier 1.5 build.
const changedAtMeta = value => ({
  audit_password_changed_at: value === null || value === undefined ? '' : String(value),
});

// The snapshot id of a restore marker, for its row: a string of at most 200 characters (as
// printable() reads it for the log line), else null; never a value cut to fit.
function snapshotOf(marker) {
  try {
    const snapshot = JSON.parse(marker)?.snapshot;
    return typeof snapshot === 'string' && snapshot.length <= 200 ? snapshot : null;
  } catch {
    return null;
  }
}

/**
 * Writes the stored admin password to auth.json (the mirror, §5.7), then records the new
 * fingerprint and clears builtin.mirrorPending, but only while users.row_version still is
 * `rowVersion`: if the password changed meanwhile, that change's own mirror is owed and its flag
 * stays. The record follows the data directory's flush (writeAuthRecord), never precedes it.
 * Resolves {ok: true, recorded}, {ok: false, code} when auth.json could not be written, or
 * {ok: false, code, written: true} when it was but is not recorded: the record could not be
 * written (a full disk), or the directory could not be flushed, so the rename may not be on
 * disk yet. auth.json then holds the stored password, builtin.mirrorPending stays set with the
 * previous fingerprint, and the next start adopts the file (or, should a power loss have undone
 * its rename, mirrors it again). Never rejects: it runs after a password change committed, whose
 * caller must still get its new cookie. Callers serialise mirrors (one at a time per process).
 */
export async function mirrorAuthRecord({
  db,
  directory,
  record,
  rowVersion,
  clock,
  writeAuthRecord = writeAuthFile,
}) {
  let written;
  try {
    written = writeAuthRecord(directory, record);
  } catch (error) {
    const code = printable(error?.code || error?.name || 'Error');
    // Renamed, not flushed: recording the fingerprint now could outlive the rename, and a start
    // after a power loss would import the previous file as a change made outside Uptime Goblin. Left
    // unrecorded, the previous fingerprint still names the previous file, so that start mirrors
    // the stored password again instead.
    if (error?.replaced === true) return { ok: false, code, written: true };
    return { ok: false, code };
  }
  let recorded;
  try {
    recorded = await db.write(tx => {
      const user = identityOps.user(tx, BUILTIN_ID);
      if (!user || user.rowVersion !== rowVersion) return false;
      const now = clock();
      identityOps.setSetting(tx, keys.source, 'auth.json', now);
      identityOps.setSetting(tx, keys.sha, written.sha256, now);
      identityOps.deleteSetting(tx, keys.mirrorPending);
      return true;
    });
  } catch (error) {
    return {
      ok: false,
      code: printable(error?.class || error?.code || error?.name || 'Error'),
      written: true,
    };
  }
  return { ok: true, recorded };
}

/** The start's line when control.sqlite is not the file Uptime Goblin last ran with. */
export const replacedLine =
  'control.sqlite is not the file Uptime Goblin last ran with: its data directory was restored from a backup, copied or moved. Every session was signed out, so sessions that ended after the backup was made cannot come back; sign in again.';

const mirrorFailedLine = code =>
  `Uptime Goblin could not update auth.json (${code}); a rollback to 1.4.x would still use the previous admin password. Uptime Goblin retries hourly.`;
// auth.json was written, so a rollback uses the current password; only its fingerprint is not
// recorded, which the next start does (it adopts the file without signing anyone out).
const mirrorUnrecordedLine = code =>
  `auth.json now holds the current admin password, but Uptime Goblin could not record that in control.sqlite (${code}); the next start of Uptime Goblin records it.`;
export const mirrorLines = Object.freeze({
  ok: 'auth.json now holds the current admin password again.',
  failed: mirrorFailedLine,
  unrecorded: mirrorUnrecordedLine,
});

/**
 * The rows of a later start's unit (§5.1), in the order they happened: the sign-out of a
 * restore, then the password it imported or the account it claimed. A snapshot restore's own
 * `system.restore` anchor is the writer's (it reads meta.restored, D16); a control.sqlite that
 * is not the file of the last start (`replaced`, restored outside restore-snapshot) is found only
 * here, so its anchor is recorded here, in the unit that signs everyone out, and cannot be lost
 * between that unit and a later one (MEC-4). An adoption records nothing: the password in
 * control.sqlite stayed what it was (§5.1, "Not recorded").
 */
function startEvents({
  restore,
  replaced,
  anchorChanged,
  action,
  changedAt,
  now,
  displayCodes = 0,
}) {
  const events = [];
  const add = (name, fields) => events.push({ action: name, outcome: 'info', at: now, ...fields });
  if (restore !== null)
    add('session.revoked-restore', {
      target: accountTarget,
      detail: {
        cause: 'snapshot',
        snapshot: snapshotOf(restore),
        ...(displayCodes ? { displayCodes } : {}),
      },
    });
  else if (replaced) {
    add('system.restore', { target: orbitTarget, detail: { cause: 'control_file' } });
    add('session.revoked-restore', {
      target: accountTarget,
      detail: { cause: 'control_file', ...(displayCodes ? { displayCodes } : {}) },
    });
  }
  if (restore === null && !replaced && anchorChanged && displayCodes)
    add('session.revoked-restore', {
      target: accountTarget,
      detail: { cause: 'credentials_anchor', displayCodes },
    });
  if (action?.kind === 'import')
    add('account.password.changed-outside', {
      target: accountTarget,
      detail: { source: action.from },
      // The value the unit stored (§3.4): the start's drift check then sees no change.
      meta: changedAtMeta(changedAt),
    });
  else if (action?.kind === 'claim') add('account.claimed', { target: accountTarget });
  return events;
}

/**
 * Brings u_admin in control.sqlite up to date with the configured sources (§5.7) and returns
 * what the service keeps in memory: {user, record, source, mirrorPending, importedAtStart,
 * restoredAtStart}. `controlFile` is controlFileIdentity() of the open control.sqlite, or null
 * (not known: no check). `audit` records the start's rows (audit spec §5.1) in the unit of each
 * change. Throws a refusal (exit 78), before anything is written, for a damaged stored record
 * without a source to restore it, for a stored password without any source
 * (localModeGuardMessage), and for no password at all (no stored one and no source:
 * passwordRequiredMessage). Uptime Goblin always requires a password: server.mjs and startControl refuse
 * every start without a source first; these are the backstops.
 */
export async function bootstrapBuiltin({
  db,
  directory,
  sources,
  hasher,
  clock,
  log,
  audit,
  writeAuthRecord,
  controlFile = null,
}) {
  const info = message => (log.info ?? log.log)?.call(log, message);
  const warn = message => (log.warn ?? log.log)?.call(log, message);
  const state = await db.read(tx => ({
    user: identityOps.user(tx, BUILTIN_ID),
    settings: identityOps.settings(tx),
    restored: identityOps.meta(tx, 'restored'),
    hasCredentials: identityOps.listDisplays(tx, 1).length > 0,
  }));
  const { authJson, env } = sources;
  const settings = state.settings;
  const anchor = JSON.stringify({ controlFile, restoreSeen: state.restored });
  const recordAnchor = settings[keys.credentialsAnchor] !== anchor;
  const anchorChanged = credentialAnchorChanged({
    anchor: settings[keys.credentialsAnchor] ?? null,
    restored: state.restored,
    controlFile,
    hasCredentials: state.hasCredentials,
  });
  // Re-read credential rows and markers inside each attempted write unit. A CLI may
  // create a code while password verification yields; the earlier snapshot cannot certify it.
  const anchorAt = tx => {
    const restored = identityOps.meta(tx, 'restored');
    return {
      value: JSON.stringify({ controlFile, restoreSeen: restored }),
      changed: credentialAnchorChanged({
        anchor: identityOps.settings(tx)[keys.credentialsAnchor] ?? null,
        restored,
        controlFile,
        hasCredentials: identityOps.listDisplays(tx, 1).length > 0,
      }),
    };
  };
  let importedAtStart = null,
    restoredAtStart = false,
    mirror = false;

  if (!state.user) {
    // First start: create u_admin from what 1.4.x would have used. Never without a password.
    const now = clock();
    let password,
      changedAt = null;
    const set = { [keys.credentialsAnchor]: anchor };
    if (authJson) {
      password = authJson.record;
      changedAt = authJson.record.passwordChangedAt;
      Object.assign(set, { [keys.source]: 'auth.json', [keys.sha]: authJson.sha256 });
    } else if (env) {
      // passwordChangedAt = now keeps the record a valid v1 one; the column stays null, which
      // 1.4.x's metadata reported for a bootstrap password ("not changed in Uptime Goblin yet").
      password = await makeRecord(hasher, env.password, now);
      Object.assign(set, { [keys.source]: 'env', [keys.verifier]: JSON.stringify(password) });
    } else throw refusal(passwordRequiredMessage);
    // A restore marker in a directory whose control.sqlite has no admin yet: nothing to sign
    // out, but it is handled, once.
    if (state.restored !== null) set[keys.restoreSeen] = state.restored;
    if (controlFile !== null) set[keys.controlFile] = controlFile;
    await writeRecorded(
      db,
      audit,
      tx => {
        const boundary = anchorAt(tx);
        const anchorChanged = boundary.changed;
        set[keys.credentialsAnchor] = boundary.value;
        const displayCodes = anchorChanged ? identityOps.deleteDisplays(tx) : 0;
        identityOps.insertUser(tx, {
          id: BUILTIN_ID,
          login: 'admin',
          displayName: 'Administrator',
          role: 'admin',
          kind: 'person',
          password,
          passwordChangedAt: changedAt,
          now,
        });
        identityOps.markCredentials(tx, now);
        for (const [key, value] of Object.entries(set)) identityOps.setSetting(tx, key, value, now);
        return {
          events: [
            ...startEvents({ restore: null, replaced: false, anchorChanged, now, displayCodes }),
            {
              action: 'account.bootstrap',
              outcome: 'info',
              at: now,
              target: accountTarget,
              detail: { source: set[keys.source] },
              meta: changedAtMeta(changedAt),
            },
          ],
        };
      },
      { fallback: true }
    );
  } else {
    const stored = parseStored(state.user.passwordText);
    const restore =
      state.restored !== null && state.restored !== (settings[keys.restoreSeen] ?? null)
        ? state.restored
        : null;
    // Not the file of the last start: restored from a backup, or copied (see the top). The
    // first start that records it has nothing to compare with, so it signs nobody out.
    const recordedFile = settings[keys.controlFile] ?? null;
    const replaced =
      controlFile !== null &&
      recordedFile !== null &&
      otherFile(recordedFile, controlFile) === true;
    const recordFile = controlFile !== null && controlFile !== recordedFile;
    let action = null; // {kind: 'import', from: 'auth.json' | 'env'} | {kind: 'adopt'} | {kind: 'claim'}
    let source = settings[keys.source] ?? null;
    if (stored.damaged) {
      // Never "no password": drift, restored from a source.
      if (authJson) action = { kind: 'import', from: 'auth.json' };
      else if (env) action = { kind: 'import', from: 'env' };
      else throw refusal(damagedMessage);
    } else if (source === null && stored.record) {
      // A database from another data directory (a later restore or transfer, D26): its password
      // is authoritative. It is mirrored to this directory's auth.json, never replaced by it.
      action = { kind: 'claim' };
    } else {
      source ??= 'none';
      // A configured source with no stored password (an account that an earlier 1.5 build set up
      // without one, source 'none') is always imported: the first credential.
      if (authJson) {
        if (stored.record && authJson.sha256 === settings[keys.sha]) action = null;
        else if (
          stored.record &&
          stored.record.salt === authJson.record.salt &&
          stored.record.hash === authJson.record.hash
        )
          // A mirror whose rename landed before a crash: the file already holds our password.
          action = { kind: 'adopt' };
        // Changed outside Uptime Goblin (a 1.4.x rollback): the newer password, even over a pending mirror.
        else action = { kind: 'import', from: 'auth.json' };
      } else if (env) {
        if (source === 'env' && stored.record) {
          const verifier = parseVerifier(settings[keys.verifier]);
          const bytes = Buffer.from(env.password, 'utf8');
          let matches = false;
          try {
            matches = verifier ? await verifyRecord(hasher, verifier, bytes) : false;
          } finally {
            bytes.fill(0);
          }
          // Unchanged: an in-app change made since stays authoritative.
          if (!matches) action = { kind: 'import', from: 'env' };
        } else action = { kind: 'import', from: 'env' }; // auth.json moved aside, or a first credential
      } else if (stored.record) throw refusal(localModeGuardMessage);
      else throw refusal(passwordRequiredMessage);
    }

    // An adoption records the fingerprint of a file a mirror renamed into place, perhaps one whose
    // directory it could not flush (mirrorAuthRecord): flushed here first, so the record never
    // names a file that a power loss can still take back. Not flushed, nothing is adopted: a
    // mirror still owed is written again below, and otherwise the next start tries again.
    if (action?.kind === 'adopt')
      try {
        flushDirectory(directory);
      } catch {
        action = null;
      }

    let importRecord = null;
    if (action?.kind === 'import')
      importRecord =
        action.from === 'auth.json'
          ? authJson.record
          : await makeRecord(hasher, env.password, clock());
    const pendingBefore = settings[keys.mirrorPending] === '1';

    if (restore !== null || replaced || recordFile || recordAnchor || anchorChanged || action) {
      const now = clock();
      // auth.json keeps its change time; a GOBLIN_PASSWORD value has none (1.4.x).
      const importedChangedAt =
        action?.kind === 'import' && action.from === 'auth.json'
          ? importRecord.passwordChangedAt
          : null;
      const applied = await writeRecorded(
        db,
        audit,
        tx => {
          // No access exists yet in this process, so deleting the rows is the whole revocation.
          const boundary = anchorAt(tx);
          const anchorChanged = boundary.changed;
          let rowVersion = state.user.rowVersion;
          let displayCodes = 0;
          if (restore !== null || replaced || anchorChanged)
            displayCodes = identityOps.deleteDisplays(tx);
          if (restore !== null || replaced) {
            identityOps.deleteUserSessions(tx, BUILTIN_ID);
            if (!identityOps.bumpEpoch(tx, BUILTIN_ID, { now, rowVersion }))
              return { result: false };
            rowVersion += 1;
            if (restore !== null) identityOps.setSetting(tx, keys.restoreSeen, restore, now);
          }
          identityOps.setSetting(tx, keys.credentialsAnchor, boundary.value, now);
          if (recordFile) identityOps.setSetting(tx, keys.controlFile, controlFile, now);
          if (action?.kind === 'import') {
            identityOps.deleteUserSessions(tx, BUILTIN_ID);
            if (
              !identityOps.setPassword(tx, BUILTIN_ID, {
                password: importRecord,
                passwordChangedAt: importedChangedAt,
                now,
                rowVersion,
                bumpEpoch: true,
              })
            )
              return { result: false };
            identityOps.markCredentials(tx, now);
            if (action.from === 'auth.json') {
              identityOps.setSetting(tx, keys.source, 'auth.json', now);
              identityOps.setSetting(tx, keys.sha, authJson.sha256, now);
            } else {
              // An import from GOBLIN_PASSWORD is not mirrored (D13): an env-only install stays
              // env-only, as 1.4.x left it, so a rollback uses the same GOBLIN_PASSWORD.
              identityOps.setSetting(tx, keys.source, 'env', now);
              identityOps.setSetting(tx, keys.verifier, JSON.stringify(importRecord), now);
              identityOps.deleteSetting(tx, keys.sha);
            }
            identityOps.deleteSetting(tx, keys.mirrorPending);
          } else if (action?.kind === 'adopt') {
            identityOps.setSetting(tx, keys.source, 'auth.json', now);
            identityOps.setSetting(tx, keys.sha, authJson.sha256, now);
            identityOps.deleteSetting(tx, keys.mirrorPending);
          } else if (action?.kind === 'claim') {
            identityOps.setSetting(tx, keys.mirrorPending, '1', now);
            // The carried row has a password: record that a credential has existed here.
            identityOps.markCredentials(tx, now);
          }
          // A code is a credential too: importing a password or restoring an older database
          // must not leave waiting codes usable (including codes used since the backup).
          // Keep an owed receipt in the same unit. Hourly housekeeping records it atomically,
          // also when this start's audit falls back because the disk is full.
          if (action?.kind === 'import')
            identityOps.cancelDisplays(tx, {
              cause: 'password_change',
              now,
              recorded: false,
            });
          return {
            result: true,
            events: startEvents({
              restore,
              replaced,
              anchorChanged,
              action,
              changedAt: importedChangedAt,
              now,
              displayCodes,
            }),
          };
        },
        { fallback: true }
      );
      // Only this process writes u_admin, under goblin.lock: a mismatch means the database
      // changed under a start, which must not guess.
      if (!applied)
        throw new Error(
          'The admin account changed while Uptime Goblin was starting; start Uptime Goblin again.'
        );
      if (restore !== null) {
        restoredAtStart = true;
        let snapshot = 'unknown';
        try {
          snapshot = JSON.parse(restore)?.snapshot ?? snapshot;
        } catch {}
        info(
          `Uptime Goblin's data was restored from snapshot ${printable(snapshot)}; every session was signed out.`
        );
      } else if (replaced) {
        // A snapshot restore also replaces the file; its own line above says so.
        restoredAtStart = true;
        info(replacedLine);
      }
      if (action?.kind === 'import') {
        importedAtStart = action.from;
        info(
          `Imported the admin password from ${action.from === 'auth.json' ? 'auth.json' : 'GOBLIN_PASSWORD'}, which changed outside Uptime Goblin; every session was signed out.`
        );
      }
    }
    // An import or adoption settled auth.json; otherwise a mirror still owed is retried now.
    mirror = action?.kind === 'claim' || (pendingBefore && action === null);
  }

  // Load what the service keeps in memory, after every change above.
  let loaded = await db.read(tx => ({
    user: identityOps.user(tx, BUILTIN_ID),
    settings: identityOps.settings(tx),
  }));
  let record = parseStored(loaded.user.passwordText).record;
  // auth.json written, its record not (see mirrorAuthRecord): nothing is owed in this process.
  let unrecorded = false;
  if (mirror && record) {
    const result = await mirrorAuthRecord({
      db,
      directory,
      record,
      rowVersion: loaded.user.rowVersion,
      clock,
      writeAuthRecord,
    });
    if (result.ok) {
      info(mirrorLines.ok);
      loaded = await db.read(tx => ({
        user: identityOps.user(tx, BUILTIN_ID),
        settings: identityOps.settings(tx),
      }));
      record = parseStored(loaded.user.passwordText).record;
    } else if (result.written) {
      unrecorded = true;
      warn(mirrorLines.unrecorded(result.code));
    } else {
      warn(mirrorLines.failed(result.code));
      await recordSystem(audit, mirrorFailedEvent(result.code));
    }
  }
  return {
    user: loaded.user,
    record,
    source: unrecorded ? 'auth.json' : (loaded.settings[keys.source] ?? 'none'),
    mirrorPending: !unrecorded && loaded.settings[keys.mirrorPending] === '1',
    importedAtStart,
    restoredAtStart,
  };
}
