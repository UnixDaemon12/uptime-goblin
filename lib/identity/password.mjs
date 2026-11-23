// Passwords and auth.json (sessions spec §5.8), extracted from 1.4.3's lib/auth.mjs with the same
// parameters, pool semantics, messages and file rules, so a rollback to 1.4.x reads what 1.5
// writes and the reverse.
//
// - The KDF is scrypt with OWASP's profile; every derivation goes through one bounded pool per
//   identity (createHasher), shared by sign-in, Basic, password changes and the bootstrap, so a
//   burst of guesses delays a real sign-in instead of exhausting memory.
// - auth.json is the v1 scrypt record 1.4.x reads. 1.5 keeps the password in control.sqlite and
//   mirrors every in-app change back to auth.json (lib/identity/index.mjs), byte for byte as
//   1.4.3 writes it: JSON.stringify(record) + '\n', written to an exclusive temporary file and
//   renamed into place; 1.5 then flushes the directory, so the rename is on disk before Uptime Goblin
//   records the file's fingerprint.
import fs from 'node:fs';
import path from 'node:path';
import { scrypt, randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { identityError } from './errors.mjs';

// OWASP's scrypt profile: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// Node's asynchronous API: https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback
export const scryptParameters = Object.freeze({ N: 32768, r: 8, p: 3, keyLength: 64 });
const maxmem = 64 * 1024 * 1024;
const authFile = 'auth.json';
const maxAuthBytes = 8192;
/** The most password bytes ever derived: longer input is refused before any KDF work. */
export const maxPasswordBytes = 1024;

const scryptDerive = (password, salt) =>
  new Promise((resolve, reject) =>
    scrypt(
      password,
      salt,
      scryptParameters.keyLength,
      { N: scryptParameters.N, r: scryptParameters.r, p: scryptParameters.p, maxmem },
      (error, key) => (error ? reject(error) : resolve(key))
    )
  );

const same = (a, b) => a.length === b.length && timingSafeEqual(a, b);
// A Buffer over the same memory (no copy), so zero-filling the original clears every view.
const view = bytes => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);

/** Whether `record` is a v1 scrypt record with this release's parameters (1.4.3's rule). */
export function validRecord(record) {
  return Boolean(
    record &&
      typeof record === 'object' &&
      !Array.isArray(record) &&
      record.version === 1 &&
      record.algorithm === 'scrypt' &&
      Object.keys(scryptParameters).every(
        key => record.parameters?.[key] === scryptParameters[key]
      ) &&
      typeof record.salt === 'string' &&
      /^[a-f0-9]{64}$/.test(record.salt) &&
      typeof record.hash === 'string' &&
      /^[a-f0-9]{128}$/.test(record.hash) &&
      Number.isSafeInteger(record.passwordChangedAt) &&
      record.passwordChangedAt > 0
  );
}

/**
 * The record with 1.4.3's key order (version, algorithm, parameters, salt, hash,
 * passwordChangedAt), so what Uptime Goblin writes to auth.json is byte-identical to what 1.4.3 wrote
 * for the same values, whatever order the stored copy had.
 */
export function canonicalRecord(record) {
  return {
    version: 1,
    algorithm: 'scrypt',
    parameters: { ...scryptParameters },
    salt: record.salt,
    hash: record.hash,
    passwordChangedAt: record.passwordChangedAt,
  };
}

/** The exact bytes of auth.json for `record`. */
export const authRecordBytes = record =>
  Buffer.from(JSON.stringify(canonicalRecord(record)) + '\n');

/**
 * The pool every derivation of one identity goes through. At most `maxActive` run at once;
 * up to `maxWaiting` more wait in arrival order for at most `waitMs` each, then are refused;
 * beyond that a request is refused at once. Both refusals are `busy` with scope 'queue':
 * other clients filled the pool and no password was checked, so http never counts them.
 * `derive(passwordBytes, salt)` defaults to scrypt; tests pass a deterministic KDF.
 */
export function createHasher({
  derive = scryptDerive,
  maxActive = 2,
  maxWaiting = 16,
  waitMs = 5000,
} = {}) {
  let active = 0;
  const waiting = [];
  async function hash(password, salt) {
    if (active >= maxActive) {
      if (waiting.length >= maxWaiting) throw identityError('busy', { scope: 'queue' });
      await new Promise((resolve, reject) => {
        const waiter = { resolve };
        waiter.timer = setTimeout(() => {
          waiting.splice(waiting.indexOf(waiter), 1);
          reject(identityError('busy', { scope: 'queue' }));
        }, waitMs);
        waiting.push(waiter);
      });
    } else active += 1;
    try {
      return await derive(password, salt);
    } finally {
      // Hand the slot straight to the next waiter, so a newcomer cannot overtake the queue.
      const next = waiting.shift();
      if (next) {
        clearTimeout(next.timer);
        next.resolve();
      } else active -= 1;
    }
  }
  return Object.freeze({
    hash,
    get active() {
      return active;
    },
    get waiting() {
      return waiting.length;
    },
  });
}

/**
 * A new v1 record of `password` (a string or its UTF-8 bytes) with a fresh 32-byte salt and
 * passwordChangedAt `now`. One derivation.
 */
export async function makeRecord(hasher, password, now) {
  const bytes = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
  const salt = randomBytes(32);
  let derived;
  try {
    derived = await hasher.hash(bytes, salt);
    return canonicalRecord({
      salt: salt.toString('hex'),
      hash: view(derived).toString('hex'),
      passwordChangedAt: now,
    });
  } finally {
    derived?.fill(0);
    if (bytes !== password) bytes.fill(0);
  }
}

/** Whether `bytes` (the password's UTF-8 bytes) match `record`. Exactly one derivation. */
export async function verifyRecord(hasher, record, bytes) {
  if (!validRecord(record)) return verifyDummy(hasher, bytes);
  const expected = Buffer.from(record.hash, 'hex');
  let derived;
  try {
    derived = await hasher.hash(bytes, Buffer.from(record.salt, 'hex'));
    return same(view(derived), expected);
  } finally {
    derived?.fill(0);
    expected.fill(0);
  }
}

// A process-random record nobody knows the password of: a wrong login name costs the same
// derivation as a wrong password (T2), so the time taken does not reveal which was wrong.
const dummy = { salt: randomBytes(32), hash: randomBytes(scryptParameters.keyLength) };

/** One derivation of the same cost as verifyRecord, over a dummy record. Resolves false. */
export async function verifyDummy(hasher, bytes) {
  let derived;
  try {
    derived = await hasher.hash(bytes, dummy.salt);
    same(view(derived), dummy.hash);
    return false;
  } finally {
    derived?.fill(0);
  }
}

/**
 * The new password of a change request `{currentPassword, password, confirmPassword}` (1.4.3's
 * rules): at least 12 Unicode characters, at most 1024 UTF-8 bytes, well-formed, equal to its
 * confirmation. A current password over 1024 bytes cannot be right, so it is refused as
 * incorrect before any derivation.
 */
export function checkNewPassword(input) {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    typeof input.currentPassword !== 'string' ||
    typeof input.password !== 'string' ||
    typeof input.confirmPassword !== 'string'
  )
    throw identityError('invalid_request', { variant: 'change' });
  if (Buffer.byteLength(input.currentPassword, 'utf8') > maxPasswordBytes)
    throw identityError('current_password_incorrect');
  const value = input.password;
  if (
    !value.isWellFormed() ||
    Buffer.byteLength(value, 'utf8') > maxPasswordBytes ||
    [...value].length < 12
  )
    throw identityError('password_invalid');
  if (value !== input.confirmPassword) throw identityError('password_mismatch');
  return value;
}

const refusal = message => Object.assign(new Error(message), { refusal: true });

/**
 * GOBLIN_PASSWORD as 1.4.x accepts it: well-formed, not only spaces, 12 to 1024 characters and at
 * most 1024 UTF-8 bytes. Anything else refuses the start (exit 78) with 1.4.x's text.
 */
export function checkBootstrapPassword(value) {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    !value.trim() ||
    [...value].length < 12 ||
    Buffer.byteLength(value, 'utf8') > maxPasswordBytes
  )
    throw refusal(
      'GOBLIN_PASSWORD must be 12 to 1024 characters and not only spaces. Choose a longer password and restart.'
    );
  return value;
}

const unreadable = () =>
  refusal(
    'Saved authentication could not be loaded. Restore a valid auth.json backup before starting Uptime Goblin.'
  );

/**
 * Reads <directory>/auth.json with 1.4.3's rules: never through a symlink (O_NOFOLLOW), a
 * regular file of at most 8192 bytes holding a valid v1 record, opened without waiting (a FIFO
 * is refused at once) and read no further than 8193 bytes. Returns {record, sha256} (the
 * SHA-256 of the exact bytes, lower-case hex), or null when the file does not exist. A symlink
 * or unusable content refuses the start (exit 78). Any other system error (a full, read-only,
 * failing or busy disk) says nothing about the file itself and is rethrown unchanged, so the
 * start is retried. Reads only: no mode is changed and nothing is created.
 */
export function readAuthRecord(directory) {
  const file = path.join(directory, authFile);
  let descriptor;
  try {
    // O_NONBLOCK: a FIFO in its place is refused below instead of holding the start (and
    // goblin.lock) until something writes to it.
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maxAuthBytes) throw unreadable();
    // At most the limit and one byte more, however the file changes after fstat (a writer
    // racing us): a short read is not the end, and a record that grew past the limit is refused.
    const buffer = Buffer.alloc(maxAuthBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, length);
      if (!read) break;
      length += read;
    }
    if (length > maxAuthBytes) throw unreadable();
    const bytes = buffer.subarray(0, length);
    let record;
    try {
      record = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw unreadable();
    }
    if (!validRecord(record)) throw unreadable();
    return {
      record: canonicalRecord(record),
      sha256: createHash('sha256').update(bytes).digest('hex'),
    };
  } catch (error) {
    if (error.refusal) throw error;
    if (error.code === 'ENOENT') return null;
    // A symlink is refused like a bad record; other system errors are retried.
    if (error.code === 'ELOOP') throw unreadable();
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

/**
 * Sets auth.json's mode to 0600 (1.4.3 did so at every start). Housekeeping only: a read-only
 * disk must not stop a valid record, so a failure is a warning. A missing file is left alone, and
 * so is anything but a regular file: readAuthRecord refuses that, and the open never waits for a
 * FIFO's writer (O_NONBLOCK) should one take the record's place in between.
 */
export function tightenAuthRecord(directory, { warn = (...args) => console.warn(...args) } = {}) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      path.join(directory, authFile),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    if (!fs.fstatSync(descriptor).isFile()) return;
    fs.fchmodSync(descriptor, 0o600);
  } catch (error) {
    if (error.code !== 'ENOENT')
      warn('auth.json permissions could not be tightened:', error.code || error.name);
  } finally {
    if (descriptor !== undefined)
      try {
        fs.closeSync(descriptor);
      } catch {}
  }
}

/**
 * Flushes <directory>'s entries to disk (an fsync of the directory itself), so that a rename
 * into it survives a power loss. A rename is atomic but not durable by itself: some file systems
 * persist it only with the directory or with their next transaction, not when another file is
 * fsynced (btrfs, which Synology's Docker volumes use, commits it up to 30 s later). Throws the
 * system error when the directory cannot be opened or flushed.
 */
export function flushDirectory(directory) {
  const descriptor = fs.openSync(directory, 'r');
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

/**
 * Replaces <directory>/auth.json with `record`, atomically and durably: an exclusive
 * auth.json.<uuid>.tmp created 0600, written, fsynced and closed, then renamed over auth.json
 * (1.4.3's write), then the data directory flushed, so the rename is on disk before the caller
 * records the new fingerprint (mirrorAuthRecord). On failure only a temporary file this call
 * created is removed, never an occupied path, and a descriptor is never closed twice (close() may
 * fail after releasing its number to another open file). Returns {sha256} of the bytes written.
 * Throws an Error whose `code` names the cause (never a path) when anything fails: before the
 * rename the old auth.json is left as it was; when only the flush failed the error has
 * `replaced: true`: auth.json holds `record`, but a power loss may still bring back the old file.
 */
export function writeAuthRecord(directory, record) {
  const file = path.join(directory, authFile);
  const tmp = file + '.' + randomUUID() + '.tmp';
  const bytes = authRecordBytes(record);
  let descriptor,
    created = false;
  try {
    descriptor = fs.openSync(tmp, 'wx', 0o600);
    created = true;
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const closing = descriptor;
    descriptor = undefined;
    fs.closeSync(closing);
    fs.renameSync(tmp, file);
  } catch (error) {
    if (descriptor !== undefined)
      try {
        fs.closeSync(descriptor);
      } catch {}
    if (created)
      try {
        fs.unlinkSync(tmp);
      } catch {}
    throw Object.assign(new Error('auth.json could not be written'), {
      code: error?.code || error?.name || 'Error',
      cause: error,
    });
  }
  // 1.4.3's write ended at the rename. Recorded before the rename is on disk, the new
  // fingerprint could outlive it: after a power loss the previous auth.json would sit under a
  // fingerprint naming this one, and the next start would import it as a change made outside
  // Uptime Goblin (signing everyone out, and bringing the previous password back).
  try {
    flushDirectory(directory);
  } catch (error) {
    throw Object.assign(new Error('auth.json was replaced but could not be flushed to disk'), {
      code: error?.code || error?.name || 'Error',
      replaced: true,
      cause: error,
    });
  }
  return { sha256: createHash('sha256').update(bytes).digest('hex') };
}
