// The keyring: one master key (the KEK) wraps a random data key (DEK) per purpose, and the
// DEKs seal secrets and key the HMACs other components keep (roadmap §2.8).
//
// - resolveKey() finds the KEK in a fixed order of sources, removes GOBLIN_SECRET_KEY from the
//   environment once read, and generates <data>/secret.key only while no keyring exists (the
//   file and the data directory fsynced before it returns, so a power cut cannot leave a
//   keyring whose key file is empty or missing). A keyring without a key refuses to start
//   ("key missing"); it never generates a stray key. A <data>/secret.key left beside another
//   source is reported, since every copy of the data directory carries it, with the line that
//   deletes it safely (`goblin-admin key remove-data-copy` for a copy of the key, `… --unused` for
//   an older key, removeDataKeyCopy); so is a source whose file lies in the data directory, and
//   one that is <data>/secret.key itself is never called unused (deleting it would delete the
//   key), nor is a <data>/secret.key that GOBLIN_SECRET_KEY_PREVIOUS_FILE names.
// - Keyring.open() unwraps every DEK with the KEK (the keycheck). A DEK that only the previous
//   key (GOBLIN_SECRET_KEY_PREVIOUS) opens is usable and reported, so `goblin-admin key rotate`
//   can re-wrap it; one that no key opens refuses to start.
// - seal()/open() use AES-256-GCM in the envelope v1.<kid>.<iv>.<ct>.<tag> with an AAD that
//   binds the purpose, the key id and the caller's context. A blob that will not open throws a
//   SealError for that item only.
//
// This module never issues SQL: the rows live in control.sqlite, reached through a store
// adapter ({list, save}) that lib/db/control.mjs provides. memoryKeyringStore() is the
// in-memory adapter for tests and tools. Refusals carry {refusal: true, exitCode: 78}, which
// server.mjs's startupExitCode() already maps to exit status 78.
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { adminCommand, adminLine, nativeInstallNote } from './admin-command.mjs';
import { quoted, unprintableProblem } from './environment.mjs';

/** The DEK purposes in 1.5. seal and sessions encrypt; login and audit key HMACs. */
export const keyPurposes = Object.freeze(['seal', 'sessions', 'login', 'audit']);
const sealing = new Set(['seal', 'sessions']);
const hashing = new Set(['login', 'audit']);
/** The fallback key file in the data directory (source 5). */
export const secretKeyFile = 'secret.key';
const keyBytes = 32;
// A key file larger than this is not a key; reading it whole would only waste memory.
const keyFileLimit = 4096;
const aadLimit = 1024;

export class KeyError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'KeyError';
    this.code = code;
    // A refusal: starting again cannot help until someone fixes the key (exit status 78).
    this.refusal = true;
    this.exitCode = 78;
    Object.assign(this, details);
  }
}

/** A sealed value that does not open. Only that item is affected; nothing refuses to start. */
export class SealError extends Error {
  constructor(message, code = 'seal_open_failed') {
    super(message);
    this.name = 'SealError';
    this.code = code;
  }
}

const b64 = buffer => Buffer.from(buffer).toString('base64url');
const unb64 = text => (/^[A-Za-z0-9_-]*$/.test(text) ? Buffer.from(text, 'base64url') : null);
const derive = (key, info, length = keyBytes) =>
  Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), info, length));

/**
 * Parses a 32-byte key written as 64 hexadecimal digits or as base64 (standard or URL-safe,
 * with or without its one padding character). Placeholders such as 64 zeros are refused.
 */
export function parseKey(text, label = 'the key') {
  const value = String(text ?? '').trim();
  let bytes = null;
  if (/^[0-9a-fA-F]{64}$/.test(value)) bytes = Buffer.from(value, 'hex');
  else if (/^[A-Za-z0-9+/_-]{43}=?$/.test(value))
    bytes = Buffer.from(
      value.replace(/=$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
      'base64url'
    );
  if (!bytes || bytes.length !== keyBytes)
    throw new KeyError(
      'key_invalid',
      `${label} must be 32 random bytes written as 64 hexadecimal digits or in base64 (for example the output of "openssl rand -hex 32").`
    );
  if (bytes.every(byte => byte === bytes[0]))
    throw new KeyError(
      'key_invalid',
      `${label} is a placeholder (every byte is the same). Generate a key with "openssl rand -hex 32".`
    );
  return bytes;
}

/** A short, non-reversible identifier of a key, safe to show and log. */
export function keyFingerprint(key) {
  return createHash('sha256')
    .update(derive(key, 'orbit/key-fingerprint/v1'))
    .digest('hex')
    .slice(0, 16);
}

// A key file's path comes from the environment (GOBLIN_SECRET_KEY_FILE,
// GOBLIN_SECRET_KEY_PREVIOUS_FILE, CREDENTIALS_DIRECTORY, GOBLIN_DATA_DIR for <data>/secret.key)
// and is printed in start lines and refusals, where a line break or a terminal escape would
// forge a line of the log. It may hold no character GOBLIN_DATA_DIR may not (one rule, in
// lib/environment.mjs); no real path needs one. A relative path is checked as resolved against
// the working directory too: the messages that name the file as a command line resolve it, and
// the working directory's own path may hold such a character.
// The key file's text, read into `buffer`, is zeroed once parsed, also when it does not parse
// (review F2v2, round 4: restore-snapshot reads keys too, and left both files' hex text in
// memory). The string made from it cannot be wiped: JavaScript strings are immutable.
function readKeyFile(file, label) {
  const problem = unprintableProblem(file);
  if (problem)
    throw new KeyError(
      'key_file_unreadable',
      `${label} must be a path without ${problem}; it is ${quoted(file, 80)}.`
    );
  const resolved = path.resolve(file);
  const inherited = unprintableProblem(resolved);
  if (inherited)
    throw new KeyError(
      'key_file_unreadable',
      `${label} must be a path without ${inherited}; it is ${quoted(file, 80)}, resolved against the working directory to ${quoted(resolved, 80)}.`
    );
  let handle, buffer;
  try {
    // Never waits: a FIFO (or a device) in place of the key would otherwise hold the start, and
    // goblin.lock with it, until something writes to it. Symlinks stay allowed (a systemd
    // credential or a Compose secret may be one); the descriptor is what is checked and read.
    handle = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(handle);
    if (!stat.isFile())
      throw new KeyError('key_file_unreadable', `${label} (${file}) is not a file.`);
    if (stat.size > keyFileLimit)
      throw new KeyError('key_invalid', `${label} (${file}) is too large to hold a key.`);
    // At most the limit and one byte more, however the file changes after fstat: a short read
    // is not the end, and a file that grew past the limit is refused like a large one.
    buffer = Buffer.alloc(keyFileLimit + 1);
    let read = 0;
    while (read < buffer.length) {
      const bytes = fs.readSync(handle, buffer, read, buffer.length - read, read);
      if (!bytes) break;
      read += bytes;
    }
    if (read > keyFileLimit)
      throw new KeyError('key_invalid', `${label} (${file}) is too large to hold a key.`);
    const warnings =
      stat.mode & 0o007
        ? [`${label} (${file}) can be read by every user of this host; make it 0600 or 0440.`]
        : [];
    // Which file this descriptor read, exactly (64-bit inode numbers lose bits as numbers), so
    // the caller can tell whether it is <data>/secret.key itself.
    const { dev, ino } = fs.fstatSync(handle, { bigint: true });
    return {
      key: parseKey(buffer.subarray(0, read).toString('utf8'), `${label} (${file})`),
      warnings,
      identity: `${dev}:${ino}`,
    };
  } catch (e) {
    if (e instanceof KeyError) throw e;
    throw new KeyError(
      'key_file_unreadable',
      `${label} (${file}) cannot be read: ${e.code || e.message}.`
    );
  } finally {
    buffer?.fill(0);
    if (handle !== undefined) fs.closeSync(handle);
  }
}

const present = value => typeof value === 'string' && value !== '';

/**
 * Writes a new key file exclusively (0600) and makes it durable: the file, then its directory,
 * are fsynced before this returns. Throws EEXIST when the file exists (never overwritten).
 */
function writeKeyFile(file, key) {
  let descriptor = fs.openSync(file, 'wx', 0o600);
  try {
    const text = Buffer.from(key.toString('hex') + '\n');
    let offset = 0;
    while (offset < text.length) offset += fs.writeSync(descriptor, text, offset);
    fs.fsyncSync(descriptor);
  } catch (error) {
    try {
      fs.closeSync(descriptor);
    } catch {}
    descriptor = undefined;
    // A partial key file must never be taken for a key at the next start.
    try {
      fs.unlinkSync(file);
    } catch {}
    throw error;
  }
  fs.closeSync(descriptor);
  // The new name must survive a power cut too: fsync the directory entry. A file system that
  // cannot fsync a directory (EINVAL, ENOTSUP) orders the entry with the file itself.
  const directory = fs.openSync(path.dirname(file), 'r');
  try {
    fs.fsyncSync(directory);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP'].includes(error.code)) throw error;
  } finally {
    fs.closeSync(directory);
  }
}

/** How a key source is named in the start line and in warnings (delivery spec §6.7). */
export function keySourceLabel({ source, file } = {}, directory) {
  switch (source) {
    case 'env':
      return 'GOBLIN_SECRET_KEY';
    case 'file':
      return `GOBLIN_SECRET_KEY_FILE (${file})`;
    case 'credentials':
      return `the systemd credential (${file})`;
    case 'secrets':
      return `the Compose secret (${file})`;
    case 'generated':
      return `a new ${file ?? path.join(directory ?? '', secretKeyFile)} (generated now)`;
    default:
      return file ?? path.join(directory ?? '', secretKeyFile);
  }
}

// How to keep a key file's copy outside the data directory, per source.
const moveOut = {
  file: 'set GOBLIN_SECRET_KEY_FILE to that copy',
  credentials: 'load the credential from that copy',
  secrets: "make that copy the Compose secret's file",
};
const capitalised = text => text[0].toUpperCase() + text.slice(1);

/**
 * Where the key file a source read (`identity`, its device and inode) lies against the data
 * directory. `inUse`: Uptime Goblin reads <data>/secret.key itself, because the source names that path
 * or the file read is that very file (a link to it, a hard link, a bind mount of it: Compose
 * mounts a secret, and a data directory mounted from the host can hold the secret's file), so
 * deleting <data>/secret.key would delete the key Uptime Goblin reads. `inside`: the key lies in the
 * data directory, so every copy of the data directory carries it. A <data>/secret.key that is a
 * symbolic link holds no key of its own: deleting a link deletes no key.
 */
function keyFilePlace(file, identity, directory, own) {
  const real = target => {
    try {
      return fs.realpathSync(target);
    } catch {
      return null;
    }
  };
  let sameFile = false;
  try {
    const stat = fs.lstatSync(own, { bigint: true });
    sameFile = stat.isFile() && `${stat.dev}:${stat.ino}` === identity;
  } catch {}
  const home = real(directory);
  const named =
    path.resolve(file) === path.resolve(own) ||
    (path.basename(file) === secretKeyFile && home !== null && real(path.dirname(file)) === home);
  const at = real(file);
  const inside = sameFile || (home !== null && at !== null && at.startsWith(home + path.sep));
  return { inUse: named || sameFile, sameFile, inside };
}

// The warning for a key that a source other than the data directory reads from inside it: it
// travels with every copy of the data directory like a generated one. When that file is
// <data>/secret.key, the advice is to copy it out first: deleting it would delete the key.
function insideWarning(own, found, place) {
  const label = keySourceLabel(found);
  const what =
    place.sameFile && path.resolve(found.file) !== path.resolve(own)
      ? `${label}, which is ${own} itself,`
      : label;
  const keep = `Keep backups of the data and of the key apart: copy the key to a file outside the data directory and ${moveOut[found.source]}.`;
  return `${capitalised(what)} is inside the data directory, so every copy of the data directory carries the key. ${keep}${place.sameFile ? ` Delete ${own} only once Uptime Goblin has started with the copy: until then it is the key Uptime Goblin reads.` : ''}`;
}

/**
 * The command line that deletes <data>/secret.key with `goblin-admin key remove-data-copy`, which
 * runs beside a live Uptime Goblin and needs the key Uptime Goblin is given (removeDataKeyCopy), with `--unused`
 * for an older key that opens none of the data's keys. `compose`: in Uptime Goblin's own container (docker
 * compose exec, whose environment and mounts are Uptime Goblin's); otherwise the native install's line,
 * which names the key file (`keyFile`, else the one goblin-admin was given, else the installer's).
 * The command alone, so the whole line runs as printed: a message gives it last, or on a line of
 * its own, and says before it which install it is for (removalNote).
 */
export function removeDataKeyLine({ compose = false, unused = false, keyFile = null } = {}) {
  const args = `key remove-data-copy${unused ? ' --unused' : ''}`;
  return compose
    ? `docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs ${args}`
    : adminLine(args, { key: true, keyFile });
}

/** What a message says of a removeDataKeyLine() line, before it: which install it is for. */
export const removalNote = compose => (compose ? '' : ` (${nativeInstallNote})`);

// A start warning's last sentence: removeDataKeyLine()'s line for the key the start found, and
// what it checks (`condition`). Under Docker Compose when that key is the Compose secret,
// natively with the file GOBLIN_SECRET_KEY_FILE names. The line ends the warning.
const removalFor = (found, unused, condition) => {
  const compose = found.source === 'secrets';
  const line = removeDataKeyLine({
    compose,
    unused,
    keyFile: found.source === 'file' ? path.resolve(found.file) : null,
  });
  return `This line${removalNote(compose)} deletes it only while ${condition}, and otherwise says why and deletes nothing: ${line}`;
};

// The warning for a <data>/secret.key that another source makes unused: it still travels with
// every copy of the data directory, so once Uptime Goblin runs with the other source it should go, with
// the line that deletes it only as what it is (removeDataKeyCopy). A copy of the key goes with
// `key remove-data-copy`, and an older key (the data moved from it with `key rewrap`), which
// that command keeps on purpose, with `key remove-data-copy --unused`, which deletes it only while
// the key Uptime Goblin is given opens every data key and that file opens none. A systemd credential is a
// copy systemd makes at each start, and a Compose secret may be mounted from that very file on the
// host: Uptime Goblin cannot see where either came from. So when the key is the same, deleting
// <data>/secret.key comes only after the credential or secret no longer comes from it. A file
// GOBLIN_SECRET_KEY_PREVIOUS_FILE names (`prior`: {file, identity}) is read at every start, and a
// symbolic link or a file that is no key cannot be checked: none of them is given a line.
function unusedKeyWarning(own, found, prior, directory) {
  let link;
  try {
    // A link that leads nowhere is no key either (existsSync follows it).
    if (!fs.existsSync(own)) return null;
    link = fs.lstatSync(own).isSymbolicLink();
  } catch {
    return null;
  }
  const label = keySourceLabel(found);
  const copied = found.source === 'credentials' || found.source === 'secrets';
  const carried = 'every copy of the data directory carries it';
  if (prior?.file && keyFilePlace(prior.file, prior.identity, directory, own).inUse)
    return `${own} is the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names, which Uptime Goblin reads at every start, so deleting it would stop Uptime Goblin from starting; the key comes from ${label} (fingerprint ${found.fingerprint}). Once every data key opens with that key (goblin-admin key rewrap), remove GOBLIN_SECRET_KEY_PREVIOUS_FILE and start Uptime Goblin again: this warning then gives the line that deletes ${own}; ${carried}.`;
  if (link)
    return `${own} is a symbolic link, which Uptime Goblin does not use: the key comes from ${label} (fingerprint ${found.fingerprint}). Deleting the link deletes no key.`;
  const caution =
    found.source === 'credentials'
      ? `If the credential is loaded from ${own} (LoadCredential=orbit-secret-key:${own}), deleting it would stop Uptime Goblin from starting: first copy the key to a file outside the data directory and load the credential from there. Once the credential no longer comes from ${own} and Uptime Goblin has started with it, delete ${own}; ${carried}.`
      : `If the Compose secret's file is this ${secretKeyFile} (a data directory mounted from the host), deleting it would stop Uptime Goblin from starting: first copy the key to a file outside the data directory and make that the secret's file. Once the secret no longer comes from ${own} and Uptime Goblin has started with it, delete ${own}; ${carried}. ${removalFor(found, false, 'the key it is given is another file that holds the same key and opens the data')}`;
  let theirs;
  try {
    theirs = readKeyFile(own, 'The data-directory key').key;
  } catch {
    return `${own} (which could not be read) is not used: the key comes from ${label} (fingerprint ${found.fingerprint}). Uptime Goblin cannot tell whether it is a copy of that key or an older one, so goblin-admin key remove-data-copy keeps it; ${carried}: find out what it holds before you delete it.`;
  }
  const fingerprint = keyFingerprint(theirs);
  theirs.fill(0);
  if (fingerprint !== found.fingerprint)
    return `${own} (fingerprint ${fingerprint}) is an older key, which Uptime Goblin does not use: the key comes from ${label} (fingerprint ${found.fingerprint}), as after goblin-admin key rewrap, and ${carried}. ${removalFor(found, true, `the key it is given opens every data key and ${own} opens none`)}`;
  return copied
    ? `${own} holds the same key as ${label}, which Uptime Goblin uses. ${caution}`
    : `${own} is a copy of the key Uptime Goblin uses, which comes from ${label}, and ${carried}. ${removalFor(found, false, 'the key it is given holds the same key and opens the data')}`;
}

/**
 * For a key_mismatch refusal: what <data>/secret.key says about the data, when another source
 * outranked it (unusedKeyWarning() is printed only on a start that succeeds). Uptime Goblin generates
 * that file when it runs without another source, and a rollback to 1.4.x leaves it there, so a
 * key adopted later (Compose's new-key recipe after a rollback, a new GOBLIN_SECRET_KEY_FILE)
 * meets data sealed with it: the refusal then names that key, its fingerprint and whether it
 * opens the data, instead of sending the reader after a key that is not lost. `found` is
 * resolveKey()'s result (its key may already be zeroed), `rows` the keyring's stored rows.
 * Resolves the note, or null when there is no such file or it holds the key that was refused.
 */
export async function dataDirectoryKeyNote({ directory, found, rows }) {
  if (!found || found.source === 'data-directory' || found.source === 'generated') return null;
  const own = path.join(directory, secretKeyFile);
  if (!fs.existsSync(own)) return null;
  let theirs;
  try {
    theirs = readKeyFile(own, 'The data-directory key').key;
  } catch (error) {
    return `${own} is in the data directory too, and may be the key that opens this data, but it could not be read: ${error.message}`;
  }
  try {
    const fingerprint = keyFingerprint(theirs);
    if (fingerprint === found.fingerprint) return null;
    let opens = true;
    try {
      await Keyring.check({ list: async () => rows }, { key: theirs });
    } catch (error) {
      if (error?.code !== 'key_mismatch') throw error;
      opens = false;
    }
    if (!opens)
      return `${own} (fingerprint ${fingerprint}) is in the data directory too, but it does not open this data either.`;
    const label = keySourceLabel(found, directory);
    // The secret's file holds a key that does not open the data: it is set aside, never copied
    // over (the check of compose.secret.yaml prints MOVE here; review of 9a7d6e5). The MOVE
    // recipe reads <data>/secret.key with a container of its own: docker compose cp read it
    // through this refused container, which failed once its orbit_secret_key was set aside (A65).
    const compose =
      found.source === 'secrets'
        ? ` (Docker Compose: the check in compose.secret.yaml prints MOVE: take that file's MOVE recipe, which puts this key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused)`
        : '';
    return `${own} (fingerprint ${fingerprint}) opens this data: Uptime Goblin generated it there when it ran without ${label}, and a rollback to 1.4.x leaves it in place. Use that key: make ${label} hold it${compose}, or remove ${label} so that Uptime Goblin reads ${own} again.`;
  } finally {
    theirs.fill(0);
  }
}

/**
 * Which Compose key recipe a volume takes, for `goblin-admin key compose-check`, which the check of
 * compose.secret.yaml runs (with that file when orbit_secret_key exists, so that its key is
 * mounted in `secretsDirectory`). A file's name says nothing about the data: after a move to the
 * Compose secret with `key rewrap`, <data>/secret.key holds the old key, and the check that saw
 * only that file said COPY, whose copy over orbit_secret_key left Uptime Goblin refusing to start
 * (key_mismatch; review of 9a7d6e5). So each key there is is compared with the keyring's `rows`
 * (none: nothing is sealed yet), and no answer has a key that opens the data replaced. It only
 * reads. Resolves {verdict, reason, secret, volume, command} (secret and volume: the keys'
 * fingerprints, or null; command: a line to run next, or null):
 *   NEW      nothing is sealed yet, and the volume holds no key (or the Compose secret is there):
 *            the new-key recipe, which keeps an orbit_secret_key that exists
 *   KEEP     the Compose secret opens the data. A <data>/secret.key beside it is not used: when
 *            it is a copy of that key, `command` is `key remove-data-copy` in Uptime Goblin's container;
 *            when it is an older key that opens none of the data's keys (after `key rewrap`),
 *            `key remove-data-copy --unused` (the check said only that Uptime Goblin does not use it,
 *            and compose.secret.yaml "keep that file", so it stayed in every copy of the volume)
 *   COPY     there is no Compose secret, and <data>/secret.key opens the data (or nothing is
 *            sealed yet): the copy recipe
 *   MOVE     the Compose secret does not open the data, and <data>/secret.key does: the MOVE
 *            recipe (that key read and checked first, then the secret's file set aside and the
 *            key put in a new one)
 *   RESTORE  no key here opens the data: put back the key it was sealed with
 * A key file that cannot be read as a key rejects with its KeyError, and nothing is compared.
 */
export async function composeKeyChoice({
  directory,
  secretsDirectory = '/run/secrets',
  rows = [],
}) {
  const secretFile = path.join(secretsDirectory, 'orbit_secret_key');
  const own = path.join(directory, secretKeyFile);
  const read = (file, label, unreadable) => {
    if (!fs.existsSync(file)) return null;
    try {
      return readKeyFile(file, label).key;
    } catch (error) {
      if (error instanceof KeyError)
        error.message += ` Nothing was compared: make no key and copy none until this check can read it as a key${/EACCES|EPERM/.test(error.message) ? unreadable : ''}.`;
      throw error;
    }
  };
  const secret = read(
    secretFile,
    'The Compose secret',
    ' (on a Linux host, uid 1000 must be able to read it: sudo chown 1000 orbit_secret_key)'
  );
  let volume = null;
  try {
    volume = read(own, 'The data-directory key', '');
    const prints = {
      secret: secret ? keyFingerprint(secret) : null,
      volume: volume ? keyFingerprint(volume) : null,
    };
    const theSecret = `the Compose secret orbit_secret_key (${secretFile}, fingerprint ${prints.secret})`;
    const theVolume = `${own} (fingerprint ${prints.volume})`;
    const answer = (verdict, reason, command = null) => ({ verdict, reason, ...prints, command });
    if (!rows.length) {
      if (secret)
        return answer(
          'NEW',
          `No data is sealed with a key yet, and ${theSecret} is there: the new-key recipe keeps it.`
        );
      return volume
        ? answer(
            'COPY',
            `No data is sealed with a key yet, and there is no orbit_secret_key: take the copy recipe for ${theVolume}, the key Uptime Goblin generated.`
          )
        : answer('NEW', 'No data is sealed with a key yet, and the volume holds no key.');
    }
    const opens = async key => {
      try {
        await Keyring.check({ list: async () => rows }, { key });
        return true;
      } catch (error) {
        if (error?.code !== 'key_mismatch') throw error;
        return false;
      }
    };
    if (secret && (await opens(secret))) {
      const keep = `${capitalised(theSecret)} opens this data: keep orbit_secret_key and COMPOSE_FILE, make no key and copy none.`;
      if (!volume) return answer('KEEP', keep);
      // The volume's key beside it is not the key Uptime Goblin uses: a copy of the secret's key (the
      // copy recipe stopped before its last line), or an older key the data moved from with
      // `key rewrap`. Each goes only with the line that checks it is that (removeDataKeyCopy).
      const later =
        'Every copy of the volume carries it: once Uptime Goblin runs with orbit_secret_key (COMPOSE_FILE in .env, then docker compose up -d), the line below deletes it';
      if (timingSafeEqual(secret, volume))
        return answer(
          'KEEP',
          `${keep} ${theVolume} is there too, a copy of that key. ${later}, only while Uptime Goblin's key is the Compose secret, holding the same key, and opens the data.`,
          removeDataKeyLine({ compose: true })
        );
      if (!keysOpened(rows, volume))
        return answer(
          'KEEP',
          `${keep} ${theVolume} is there too: an older key, which Uptime Goblin does not use and which opens none of this data's keys (as after key rewrap). ${later}, only while Uptime Goblin's key opens every data key and that file opens none.`,
          removeDataKeyLine({ compose: true, unused: true })
        );
      return answer(
        'KEEP',
        `${keep} ${theVolume} is there too, and opens some of this data's keys: keep it.`
      );
    }
    if (volume && (await opens(volume)))
      return secret
        ? answer(
            'MOVE',
            `${capitalised(theSecret)} does not open this data, and ${theVolume} does: take the MOVE recipe of compose.secret.yaml, which puts that key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused, then start Uptime Goblin with docker compose up -d --force-recreate.`
          )
        : answer(
            'COPY',
            `${theVolume} opens this data, and there is no orbit_secret_key: take the copy recipe.`
          );
    const tried = [secret && theSecret, volume && theVolume].filter(Boolean);
    return answer(
      'RESTORE',
      `No key here opens this data (${tried.length ? `${tried.join(' and ')} ${tried.length > 1 ? 'do' : 'does'} not` : 'there is no orbit_secret_key, and the volume holds no key'}): make no key and copy none. Put back the orbit_secret_key the data was sealed with, then run this check again (docs/troubleshooting.md#lost-encryption-key only if it is truly lost).`
    );
  } finally {
    secret?.fill(0);
    volume?.fill(0);
  }
}

/**
 * Whether the key source `file`, opened afresh, still holds `key` as the file of `identity`
 * (device:inode, as removeDataKeyCopy's stat found it): 'same'; 'gone' when it has no link left
 * (deleted, though still reachable); otherwise 'changed' (it cannot be opened or read, is another
 * file, or holds no key or another one). For removeDataKeyCopy's last check (4): a stat alone
 * does not show that a file still holds the key. A file bind-mounted through FUSE or virtiofs (a
 * host's file in an OrbStack or Docker Desktop container) keeps its old attributes, links
 * included, for tens of milliseconds after the host deletes it, while opening it fails at once.
 * It never waits: the file is opened without blocking, so a FIFO put in the source's place since
 * that stat is 'changed' at once (a plain open waits for a writer before fstat can refuse it,
 * and the command hung). Links are followed, as the stat that found `identity` followed them.
 */
function sourceHolds(file, identity, key) {
  let handle, text;
  try {
    handle = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const stat = fs.fstatSync(handle, { bigint: true });
    if (stat.nlink === 0n) return 'gone';
    if (
      !stat.isFile() ||
      `${stat.dev}:${stat.ino}` !== identity ||
      stat.size > BigInt(keyFileLimit)
    )
      return 'changed';
    text = Buffer.alloc(Number(stat.size));
    const read = text.length ? fs.readSync(handle, text, 0, text.length, 0) : 0;
    const theirs = parseKey(text.subarray(0, read).toString('utf8'));
    try {
      return timingSafeEqual(theirs, key) ? 'same' : 'changed';
    } finally {
      theirs.fill(0);
    }
  } catch {
    return 'changed';
  } finally {
    text?.fill(0);
    if (handle !== undefined) fs.closeSync(handle);
  }
}

/**
 * Deletes <data>/secret.key only while it is a copy of the key Uptime Goblin is given, for `goblin-admin
 * key remove-data-copy`, the last line of the Compose copy and MOVE recipes, which runs in Uptime Goblin's
 * own container (docker compose exec: its environment and its mounts), so `found`, resolveKey()'s
 * result there, is the key Uptime Goblin is given. Those recipes ended with `docker compose exec uptime-goblin rm
 * /app/data/secret.key`, which a block pasted whole runs whatever stopped before it: in the COPY
 * state (Uptime Goblin running without the override, whose start failed) or in a container that had just
 * mounted another key, it deleted the only key that opens the data (A66). Now the file goes only
 * when (1) the key comes from another source than that file: not <data>/secret.key itself, nor a
 * file that is it (keyFilePlace: its path, a link, a bind mount of it), nor a systemd credential,
 * which systemd may copy from it unseen; (2) that key opens every data key of `rows` (Keyring.check,
 * without the previous key); (3) the file holds the same key, its 32 bytes equal byte for byte;
 * and (4) the source's file, if any, opened again right before the deletion, is still the file
 * found (device and inode) and holds that key (sourceHolds). The file is read and deleted as the
 * same file (device and inode), never through a link.
 *
 * `unused` (`key remove-data-copy --unused`, A67) deletes an older key instead: one the data
 * moved from with `key rewrap`, which (3) keeps on purpose, so it stayed in every copy of the data
 * directory with no safe way out (the start warning said to delete it, with no command). It goes
 * only when (1) and (2) hold as above, the file holds another key (the same key is a copy: that
 * takes the command without --unused), and that key opens none of the data keys of `rows`
 * (keysOpened). A credential holding another key does not come from that file, so (1) admits it
 * here. Neither mode deletes the file `previousFile` (GOBLIN_SECRET_KEY_PREVIOUS_FILE as this
 * command is given it, Uptime Goblin's own under docker compose exec) names by path, link or inode: Uptime Goblin
 * reads it at every start, and a missing one refuses it.
 *
 * Resolves {deleted: true, file, fingerprint, theirs?} (theirs: with `unused`, the deleted key's
 * fingerprint) or, deleting nothing, {deleted: false, code, file, fingerprint, source?, theirs?,
 * opened?, opensNone?, message?}: code none (no such file), not_a_file, data_directory (the key
 * comes from that file: no other source reached this process), same_file, credential, gone (the
 * source's file was deleted, though still open or mounted), source_changed (source: the source's
 * file, which, found or opened again, was gone, unreadable, another file or held no key or
 * another one), previous_file, previous_changed (source: the file `previousFile` names, which
 * cannot be found or read), no_keyring, not_opening, unreadable (message: why),
 * different (theirs: that file's fingerprint; opensNone: it opens no data key, so --unused would
 * take it), copy (with `unused`: the same key), opening (with `unused`: it opens `opened` data
 * keys) or changed (<data>/secret.key was replaced or removed while it was checked).
 */
export async function removeDataKeyCopy({
  directory,
  found,
  rows = [],
  unused = false,
  previousFile = null,
}) {
  const own = path.join(directory, secretKeyFile);
  const fingerprint = found?.fingerprint ?? null;
  const kept = (code, extra = {}) => ({ deleted: false, code, file: own, fingerprint, ...extra });
  const identityOf = stat => `${stat.dev}:${stat.ino}`;
  let before;
  try {
    before = fs.lstatSync(own, { bigint: true });
  } catch (error) {
    if (error.code === 'ENOENT') return kept('none');
    return kept('unreadable', {
      message: `${own} cannot be read: ${error.code || error.message}.`,
    });
  }
  if (!before.isFile()) return kept('not_a_file');
  if (!found || found.source === 'data-directory' || found.source === 'generated')
    return kept('data_directory');
  if (found.source === 'credentials' && !unused) return kept('credential');
  let source = null;
  if (found.file) {
    let stat = null;
    try {
      stat = fs.statSync(found.file, { bigint: true });
    } catch {}
    if (stat === null) return kept('source_changed', { source: found.file });
    // A file deleted since it was opened or mounted (a Linux bind mount keeps the inode of a
    // host file deleted under it): no lasting copy of the key.
    if (stat.nlink === 0n) return kept('gone');
    source = identityOf(stat);
    if (keyFilePlace(found.file, source, directory, own).inUse) return kept('same_file');
  }
  if (present(previousFile)) {
    let stat = null;
    try {
      stat = fs.statSync(previousFile, { bigint: true });
    } catch {}
    if (stat === null) return kept('previous_changed', { source: previousFile });
    if (keyFilePlace(previousFile, identityOf(stat), directory, own).inUse)
      return kept('previous_file');
  }
  if (!rows.length) return kept('no_keyring');
  try {
    await Keyring.check({ list: async () => rows }, { key: found.key });
  } catch (error) {
    if (error?.code !== 'key_mismatch') throw error;
    return kept('not_opening');
  }
  let theirs;
  try {
    theirs = readKeyFile(own, 'The data-directory key');
  } catch (error) {
    if (!(error instanceof KeyError)) throw error;
    return kept('unreadable', { message: error.message });
  }
  let older = null;
  try {
    if (theirs.identity !== identityOf(before)) return kept('changed');
    const same = timingSafeEqual(theirs.key, found.key);
    if (unused) {
      if (same) return kept(found.source === 'credentials' ? 'credential' : 'copy');
      older = keyFingerprint(theirs.key);
      const opened = keysOpened(rows, theirs.key);
      if (opened) return kept('opening', { theirs: older, opened });
    } else if (!same)
      return kept('different', {
        theirs: keyFingerprint(theirs.key),
        opensNone: keysOpened(rows, theirs.key) === 0,
      });
  } finally {
    theirs.key.fill(0);
  }
  // Still the file that was read: a replacement since then (a new key put there) is never deleted.
  let now;
  try {
    now = fs.lstatSync(own, { bigint: true });
  } catch {
    return kept('changed');
  }
  if (!now.isFile() || identityOf(now) !== theirs.identity) return kept('changed');
  // The source's file once more, last: a stat alone does not show that it still holds the key.
  if (found.file) {
    const held = sourceHolds(found.file, source, found.key);
    if (held === 'gone') return kept('gone');
    if (held !== 'same') return kept('source_changed', { source: found.file });
  }
  fs.unlinkSync(own);
  return unused
    ? { deleted: true, file: own, fingerprint, theirs: older }
    : { deleted: true, file: own, fingerprint };
}

// The decrypt-only previous key, from GOBLIN_SECRET_KEY_PREVIOUS (removed once read) or
// GOBLIN_SECRET_KEY_PREVIOUS_FILE: {key, file, identity} (file and identity for a file), or null.
function previousKey(env) {
  if (Object.hasOwn(env, 'GOBLIN_SECRET_KEY_PREVIOUS')) {
    const text = env.GOBLIN_SECRET_KEY_PREVIOUS;
    delete env.GOBLIN_SECRET_KEY_PREVIOUS;
    if (present(text)) return { key: parseKey(text, 'GOBLIN_SECRET_KEY_PREVIOUS') };
  }
  if (present(env.GOBLIN_SECRET_KEY_PREVIOUS_FILE)) {
    const file = env.GOBLIN_SECRET_KEY_PREVIOUS_FILE;
    const { key, identity } = readKeyFile(file, 'GOBLIN_SECRET_KEY_PREVIOUS_FILE');
    return { key, file, identity };
  }
  return null;
}

/**
 * Finds the master key. Sources, in order:
 *   1. GOBLIN_SECRET_KEY (deleted from `env` as soon as it is read, set or not)
 *   2. the file named by GOBLIN_SECRET_KEY_FILE (the native installer's /etc/uptime-goblin/secret.key)
 *   3. $CREDENTIALS_DIRECTORY/orbit-secret-key (systemd LoadCredential=)
 *   4. /run/secrets/orbit_secret_key (Compose secrets:)
 *   5. <data>/secret.key, generated (0600, O_EXCL, file and directory fsynced) only when
 *      `keyringExists` is false
 * Returns {key, previous, source, file?, fingerprint, warnings, checked}. With a keyring and
 * no key it throws KeyError 'key_missing' naming every source it checked; `generate: false`
 * returns null instead of creating secret.key. A source other than the data directory while
 * <data>/secret.key exists adds a warning naming both keys' fingerprints and the line that
 * deletes it as a copy or an older key (unusedKeyWarning), unless that source reads
 * <data>/secret.key itself; a key file inside the data directory adds the warning that every copy
 * of the data directory carries it. A key it read and does not return is wiped before it returns
 * or throws, the previous key too, which it reads first (review F2v2: a missing key file, or no
 * key at all, left the previous key in memory). A previous key it cannot read, or that is no key,
 * throws its KeyError, as Uptime Goblin's start needs it to; with `onPreviousError` it is handed to that
 * function instead, and the search goes on without a previous key (restore-snapshot's keyring
 * check, which says so: review F2v2, round 6, a previous key file it could not read kept it from
 * checking the key it could).
 */
export function resolveKey(options = {}) {
  const { env = process.env, directory, onPreviousError = null } = options;
  if (!directory) throw new TypeError('resolveKey needs the data directory');
  // Read (and remove) both environment keys before anything can fail, so neither lingers in
  // process.env (and /proc/<pid>/environ of children) after an error.
  const hasKey = Object.hasOwn(env, 'GOBLIN_SECRET_KEY'),
    keyText = env.GOBLIN_SECRET_KEY;
  delete env.GOBLIN_SECRET_KEY;
  let prior = null;
  try {
    prior = previousKey(env);
  } catch (error) {
    if (!onPreviousError || !(error instanceof KeyError)) throw error;
    onPreviousError(error);
  }
  const held = { key: null };
  try {
    const found = locateKey({ ...options, env }, { hasKey, keyText, prior, held });
    if (!found) prior?.key.fill(0);
    return found;
  } catch (error) {
    held.key?.fill(0);
    prior?.key.fill(0);
    throw error;
  }
}

// resolveKey's search once both environment keys are read (`prior`: the previous key). `held.key`
// is the key it last read, for resolveKey to wipe when this throws.
function locateKey(
  {
    env,
    directory,
    keyringExists = false,
    credentialsDirectory = env.CREDENTIALS_DIRECTORY,
    secretsDirectory = '/run/secrets',
    generate = true,
  },
  { hasKey, keyText, prior, held }
) {
  const previous = prior?.key ?? null;
  const checked = [];
  const own = path.join(directory, secretKeyFile);
  const found = (key, source, extra = {}) => ({
    key: (held.key = key),
    previous,
    // The file GOBLIN_SECRET_KEY_PREVIOUS_FILE named, for the command lines Uptime Goblin prints.
    previousFile: prior?.file ?? null,
    source,
    fingerprint: keyFingerprint(key),
    warnings: [],
    checked,
    ...extra,
  });
  // Another source wins over <data>/secret.key; say so when one is there too. Unless that source
  // reads <data>/secret.key itself (GOBLIN_SECRET_KEY_FILE naming it, say): then it is the key in
  // use, which travels with the data directory, and never one to delete.
  const elsewhere = (key, source, { identity, ...extra } = {}) => {
    const result = found(key, source, extra);
    const place = identity
      ? keyFilePlace(result.file, identity, directory, own)
      : { inUse: false, inside: false };
    if (place.inside) result.warnings = [insideWarning(own, result, place), ...result.warnings];
    const unused = place.inUse ? null : unusedKeyWarning(own, result, prior, directory);
    if (unused) result.warnings = [...result.warnings, unused];
    return result;
  };
  if (hasKey && present(keyText)) return elsewhere(parseKey(keyText, 'GOBLIN_SECRET_KEY'), 'env');
  checked.push('GOBLIN_SECRET_KEY');
  if (present(env.GOBLIN_SECRET_KEY_FILE)) {
    const { key, warnings, identity } = readKeyFile(
      env.GOBLIN_SECRET_KEY_FILE,
      'GOBLIN_SECRET_KEY_FILE'
    );
    return elsewhere(key, 'file', { file: env.GOBLIN_SECRET_KEY_FILE, warnings, identity });
  }
  checked.push('GOBLIN_SECRET_KEY_FILE');
  for (const [source, base, name] of [
    ['credentials', credentialsDirectory, 'orbit-secret-key'],
    ['secrets', secretsDirectory, 'orbit_secret_key'],
  ]) {
    if (!present(base)) {
      if (source === 'credentials') checked.push('$CREDENTIALS_DIRECTORY/orbit-secret-key');
      continue;
    }
    const file = path.join(base, name);
    checked.push(file);
    if (fs.existsSync(file)) {
      const { key, warnings, identity } = readKeyFile(
        file,
        source === 'credentials' ? 'The systemd credential' : 'The Compose secret'
      );
      return elsewhere(key, source, { file, warnings, identity });
    }
  }
  checked.push(own);
  const travels = `${own} is inside the data directory, so every copy of the data directory carries the key. Keep backups of the data and of the key apart (set GOBLIN_SECRET_KEY_FILE to a key outside the data directory).`;
  if (fs.existsSync(own)) {
    const { key, warnings } = readKeyFile(own, 'The data-directory key');
    return found(key, 'data-directory', { file: own, warnings: [travels, ...warnings] });
  }
  if (keyringExists)
    throw new KeyError(
      'key_missing',
      `The encryption key is missing: this data has a keyring, but no key was found (checked ${checked.join(', ')}). Restore the key. Only if it is truly lost, give up what it protects (docs/troubleshooting.md#lost-encryption-key): put a new key in place, then run, with Uptime Goblin stopped: ${adminCommand('key reset --confirm-lost-key', { key: true })}.`,
      { checked }
    );
  if (!generate) return null;
  const key = (held.key = randomBytes(keyBytes));
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  try {
    writeKeyFile(own, key);
  } catch (e) {
    // Another process generated it first: use that one, never overwrite a key.
    if (e.code !== 'EEXIST') throw e;
    key.fill(0);
    const { key: theirs, warnings } = readKeyFile(own, 'The data-directory key');
    return found(theirs, 'data-directory', { file: own, warnings: [travels, ...warnings] });
  }
  return found(key, 'generated', { file: own, warnings: [travels] });
}

// DEKs are wrapped with a key derived from the KEK, bound to their id and purpose.
const wrapAad = (kid, purpose) => Buffer.from(`orbit-keyring-v1|${kid}|${purpose}`);
function wrap(kek, dek, kid, purpose) {
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', derive(kek, 'orbit/kek-wrap/v1'), iv);
  cipher.setAAD(wrapAad(kid, purpose));
  const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
  return ['w1', b64(iv), b64(ct), b64(cipher.getAuthTag())].join('.');
}
function unwrap(kek, wrapped, kid, purpose) {
  const parts = String(wrapped).split('.');
  if (parts.length !== 4 || parts[0] !== 'w1') return null;
  const [iv, ct, tag] = parts.slice(1).map(unb64);
  if (!iv || iv.length !== 12 || !ct || ct.length !== keyBytes || !tag || tag.length !== 16)
    return null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', derive(kek, 'orbit/kek-wrap/v1'), iv);
    decipher.setAAD(wrapAad(kid, purpose));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null;
  }
}

/** How many of the keyring's `rows` (its stored data keys) `key` opens, writing nothing. */
function keysOpened(rows, key) {
  let opened = 0;
  for (const row of rows) {
    const dek = unwrap(key, row.wrapped, row.kid, row.purpose);
    if (dek) {
      dek.fill(0);
      opened++;
    }
  }
  return opened;
}

const newKid = () => randomBytes(6).toString('hex');
const sealAad = (purpose, kid, aad) => Buffer.from(`orbit-seal-v1|${purpose}|${kid}|${aad}`);
function checkAad(aad) {
  if (typeof aad !== 'string' || !aad || aad.length > aadLimit)
    throw new TypeError(`A sealed value needs a context string (1-${aadLimit} characters)`);
}

/**
 * Per-component hooks for `goblin-admin key rotate` and `key reset`. rotate({keyring,
 * purposes}) re-seals a component's values under the new data keys; reset({keyring}) drops
 * what can no longer be opened. They run in registration order; one failing stops the rest.
 */
export class KeyHooks {
  #hooks = new Map();
  register(component, { rotate, reset } = {}) {
    if (this.#hooks.has(component)) throw new Error(`Key hooks for ${component} are registered`);
    this.#hooks.set(component, { rotate, reset });
    return this;
  }
  get components() {
    return [...this.#hooks.keys()];
  }
  async run(kind, context) {
    const ran = [];
    for (const [component, hooks] of this.#hooks) {
      if (typeof hooks[kind] !== 'function') continue;
      await hooks[kind](context);
      ran.push(component);
    }
    return ran;
  }
}

/**
 * The opened keyring. Construct it with Keyring.open(store, {key, previous}).
 * store: {list(): Promise<row[]>, save({insert, rewrap, retire, clear, inUnit}):
 * Promise<void>}, rows {kid, purpose, wrapped, created_at, retired_at}.
 */
export class Keyring {
  #kek;
  #store;
  #clock;
  #keys = new Map(); // kid -> {purpose, dek, retired}
  #active = new Map(); // purpose -> kid
  #stale = new Set(); // kids that only the previous key unwraps
  constructor(secret, store, clock) {
    if (secret !== Keyring.#token) throw new TypeError('Use Keyring.open()');
    this.#store = store;
    this.#clock = clock;
  }
  static #token = Symbol('keyring');

  /**
   * Unwraps every data key (the keycheck), creating the missing ones. `create: false` opens
   * an existing keyring only (read-only tools); with `complete: false` too, a purpose without an
   * active key is no error (goblin-admin verify-audit, audit review round 2: every key the store
   * holds still opens for hmac() under its kid, as a retired key does, and a missing one is
   * reported by what it signed). Throws KeyError 'key_mismatch' when a data key opens with
   * neither the key nor the previous key.
   */
  static async open(
    store,
    { key, previous = null, clock = Date.now, create = true, complete = true } = {}
  ) {
    const keyring = new Keyring(Keyring.#token, store, clock);
    const { rows, keys, stale } = await Keyring.#unwrapAll(store, key, previous);
    keyring.#kek = Buffer.from(key);
    keyring.#keys = keys;
    keyring.#stale = stale;
    // The newest unretired key of each purpose is the active one.
    for (const row of [...rows].sort((a, b) => a.created_at - b.created_at))
      if (row.retired_at == null) keyring.#active.set(row.purpose, row.kid);
    const missing = keyPurposes.filter(purpose => !keyring.#active.has(purpose));
    if (missing.length) {
      if (!create) {
        if (!complete) return keyring;
        throw new KeyError('keyring_incomplete', `The keyring has no ${missing.join(', ')} key`);
      }
      await keyring.#add(missing);
    }
    return keyring;
  }

  // The keycheck: every data key must open with the key or the previous key.
  static async #unwrapAll(store, key, previous, { keyFile = null, previousFile = null } = {}) {
    if (!Buffer.isBuffer(key) || key.length !== keyBytes)
      throw new TypeError('The keyring needs the 32-byte master key');
    const rows = await store.list(),
      keys = new Map(),
      stale = new Set();
    for (const row of rows) {
      let dek = unwrap(key, row.wrapped, row.kid, row.purpose);
      if (!dek && previous) {
        dek = unwrap(previous, row.wrapped, row.kid, row.purpose);
        if (dek) stale.add(row.kid);
      }
      if (!dek) {
        // The data keys it unwrapped so far go unused: wipe them (review F2v2, round 4).
        for (const entry of keys.values()) entry.dek.fill(0);
        throw new KeyError(
          'key_mismatch',
          `The encryption key (fingerprint ${keyFingerprint(key)}) does not match this data. Restore the key it was created with; or, to move to this key, put the old one in a file the uptime-goblin user can read and run, with Uptime Goblin stopped: ${adminCommand('key rotate', { key: true, previous: true, keyFile, previousFile })}.`
        );
      }
      keys.set(row.kid, { purpose: row.purpose, dek, retired: row.retired_at != null });
    }
    return { rows, keys, stale };
  }

  /**
   * The keycheck alone, writing nothing (the start sequence runs it before it migrates, so a
   * wrong key refuses to start with the data directory unchanged). Resolves {keys: number of
   * data keys, stale: kids only the previous key opens}; throws KeyError 'key_mismatch', whose
   * command line names `keyFile` and `previousFile` (the files the start read the keys from)
   * instead of the installer's file and a placeholder.
   */
  static async check(store, { key, previous = null, keyFile = null, previousFile = null } = {}) {
    const { keys, stale } = await Keyring.#unwrapAll(store, key, previous, {
      keyFile,
      previousFile,
    });
    // The data keys it unwrapped are not returned: wipe them (review F2v2, round 4).
    for (const { dek } of keys.values()) dek.fill(0);
    return { keys: keys.size, stale: [...stale] };
  }

  async #add(purposes, retire = []) {
    const now = this.#clock(),
      insert = [],
      added = new Map();
    for (const purpose of purposes) {
      const kid = newKid(),
        dek = randomBytes(keyBytes);
      insert.push({
        kid,
        purpose,
        wrapped: wrap(this.#kek, dek, kid, purpose),
        created_at: now,
        retired_at: null,
      });
      added.set(kid, { purpose, dek, retired: false });
    }
    await this.#store.save({ insert, retire: retire.map(kid => ({ kid, retired_at: now })) });
    for (const kid of retire) this.#keys.get(kid).retired = true;
    for (const [kid, entry] of added) {
      this.#keys.set(kid, entry);
      this.#active.set(entry.purpose, kid);
    }
  }

  /** The master key's fingerprint (never the key). */
  get fingerprint() {
    return keyFingerprint(this.#kek);
  }
  /** True when some data key opened only with the previous master key. */
  get needsRewrap() {
    return this.#stale.size > 0;
  }
  activeKid(purpose) {
    const kid = this.#active.get(purpose);
    if (!kid) throw new TypeError(`Unknown key purpose ${purpose}`);
    return kid;
  }
  /** {kid, purpose, retired, active} for every data key; never the keys themselves. */
  describe() {
    return [...this.#keys].map(([kid, { purpose, retired }]) => ({
      kid,
      purpose,
      retired,
      active: this.#active.get(purpose) === kid,
    }));
  }
  #entry(purpose, kid, allowed) {
    if (!allowed.has(purpose)) throw new TypeError(`The ${purpose} key cannot be used for this`);
    const entry = this.#keys.get(kid);
    return entry && entry.purpose === purpose ? entry : null;
  }

  /** Seals `plaintext` (string or Buffer) for `purpose`, bound to the context string `aad`. */
  seal(purpose, plaintext, aad) {
    checkAad(aad);
    const kid = this.activeKid(purpose),
      { dek } = this.#entry(purpose, kid, sealing),
      iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', derive(dek, `orbit/${purpose}/enc/v1`), iv);
    cipher.setAAD(sealAad(purpose, kid, aad));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return ['v1', kid, b64(iv), b64(ct), b64(cipher.getAuthTag())].join('.');
  }
  /** Opens an envelope from seal(); throws SealError when it does not open in this context. */
  open(purpose, envelope, aad) {
    checkAad(aad);
    const parts = typeof envelope === 'string' ? envelope.split('.') : [];
    if (parts.length !== 5 || parts[0] !== 'v1')
      throw new SealError('The sealed value is malformed', 'seal_malformed');
    const [, kid] = parts,
      [iv, ct, tag] = parts.slice(2).map(unb64),
      entry = this.#entry(purpose, kid, sealing);
    if (!entry)
      throw new SealError(
        `The key ${kid} that sealed this value is not in the keyring`,
        'seal_unknown_key'
      );
    if (!iv || iv.length !== 12 || !ct || !tag || tag.length !== 16)
      throw new SealError('The sealed value is malformed', 'seal_malformed');
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        derive(entry.dek, `orbit/${purpose}/enc/v1`),
        iv
      );
      decipher.setAAD(sealAad(purpose, kid, aad));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
      throw new SealError(
        'The sealed value does not open (wrong key or context, or it was altered)'
      );
    }
  }
  sealText(purpose, text, aad) {
    return this.seal(purpose, Buffer.from(String(text), 'utf8'), aad);
  }
  openText(purpose, envelope, aad) {
    return this.open(purpose, envelope, aad).toString('utf8');
  }
  /** The kid of an envelope, or null (to find values a rotation must re-seal). */
  static kidOf(envelope) {
    const parts = typeof envelope === 'string' ? envelope.split('.') : [];
    return parts.length === 5 && parts[0] === 'v1' ? parts[1] : null;
  }
  /** HMAC-SHA256 (hex) of `data` under the active login or audit key, and that key's id. */
  hmac(purpose, data, kid = this.activeKid(purpose)) {
    const entry = this.#entry(purpose, kid, hashing);
    if (!entry) throw new SealError(`The key ${kid} is not in the keyring`, 'seal_unknown_key');
    return {
      kid,
      mac: createHmac('sha256', derive(entry.dek, `orbit/${purpose}/mac/v1`))
        .update(data)
        .digest('hex'),
    };
  }
  /** An HKDF subkey of the active `purpose` key, for a component's own construction. */
  subkey(purpose, info, length = keyBytes) {
    if (typeof info !== 'string' || !info) throw new TypeError('A subkey needs an info string');
    const entry = this.#keys.get(this.activeKid(purpose));
    return derive(entry.dek, `orbit/${purpose}/sub/${info}`, length);
  }

  /** Re-wraps every data key under the current master key (after the master key changed). */
  async rewrap() {
    const rewrap = [...this.#keys].map(([kid, { purpose, dek }]) => ({
      kid,
      wrapped: wrap(this.#kek, dek, kid, purpose),
    }));
    await this.#store.save({ rewrap });
    const count = this.#stale.size;
    this.#stale.clear();
    return { rewrapped: rewrap.length, wereStale: count };
  }
  /**
   * New data keys for `purposes`; the old ones are retired (they still open old values).
   * Then the component hooks re-seal their values. Returns the new kids and the hooks run.
   */
  async rotate({ purposes = keyPurposes, hooks = null } = {}) {
    for (const purpose of purposes)
      if (!keyPurposes.includes(purpose)) throw new TypeError(`Unknown key purpose ${purpose}`);
    // Each purpose once: a repeated one added a new key per occurrence, and the one not left
    // active was never retired by a later rotation.
    purposes = [...new Set(purposes)];
    const retire = purposes.map(purpose => this.#active.get(purpose)).filter(Boolean);
    if (this.#stale.size) await this.rewrap();
    await this.#add(purposes, retire);
    const ran = hooks ? await hooks.run('rotate', { keyring: this, purposes }) : [];
    return {
      retired: retire,
      active: purposes.map(purpose => this.#active.get(purpose)),
      hooks: ran,
    };
  }
  /**
   * For a lost master key only: forgets every data key, makes new ones under `key`, and lets
   * each component drop what it can no longer open.
   *
   * `inUnit(tx, {kid, mac})` records the reset's audit anchor in the same unit as the new keys
   * (audit spec D17): `kid` is the new audit key's id and `mac(data)` the hex HMAC-SHA256 of the
   * UTF-8 `data` under it, exactly as keyring.hmac('audit', data, kid) computes it once the
   * reset keyring is open. The reset and its anchor commit together; a throw from inUnit rolls
   * both back, so the old keys stay. tx is null with an in-memory store.
   */
  static async reset(
    store,
    { key, confirmLostKey = false, hooks = null, clock = Date.now, inUnit = null } = {}
  ) {
    if (confirmLostKey !== true)
      throw new KeyError(
        'reset_unconfirmed',
        'A key reset discards every sealed value; confirm it explicitly.'
      );
    if (!Buffer.isBuffer(key) || key.length !== keyBytes)
      throw new TypeError('Keyring.reset needs the new 32-byte master key');
    if (inUnit !== null && typeof inUnit !== 'function')
      throw new TypeError('inUnit must be a function');
    const discarded = (await store.list()).length,
      now = clock();
    // The new audit data key is kept (only) until the save returned, so inUnit can sign with it
    // before the keyring that holds it exists: the anchor cannot wait for a second unit.
    let auditKey = null,
      auditKid = null;
    // One save: the old keys are never gone without their replacements (a stop in between
    // would otherwise look like a new install and generate a stray key).
    const insert = keyPurposes.map(purpose => {
      const kid = newKid(),
        dek = randomBytes(keyBytes);
      const wrapped = wrap(key, dek, kid, purpose);
      if (purpose === 'audit' && inUnit) [auditKey, auditKid] = [dek, kid];
      else dek.fill(0);
      return { kid, purpose, wrapped, created_at: now, retired_at: null };
    });
    let macKey = null,
      saving = true;
    try {
      let unit;
      if (inUnit) {
        macKey = derive(auditKey, 'orbit/audit/mac/v1');
        // Usable only inside the unit: afterwards the key is wiped, and a MAC under zeros
        // would be a signature nothing could check.
        const mac = data => {
          if (!saving) throw new TypeError('The reset audit key is wiped once the save returned');
          return createHmac('sha256', macKey).update(data, 'utf8').digest('hex');
        };
        unit = tx => inUnit(tx, { kid: auditKid, mac });
      }
      await store.save({ clear: true, insert, ...(unit ? { inUnit: unit } : {}) });
    } finally {
      saving = false;
      auditKey?.fill(0);
      macKey?.fill(0);
    }
    const keyring = await Keyring.open(store, { key, clock, create: false });
    const ran = hooks ? await hooks.run('reset', { keyring }) : [];
    return { keyring, discarded, hooks: ran };
  }
}

/** An in-memory keyring store with the adapter's contract (tests and offline tools). */
export function memoryKeyringStore(initial = []) {
  let rows = initial.map(row => ({ ...row }));
  return {
    get rows() {
      return rows.map(row => ({ ...row }));
    },
    async list() {
      return rows.map(row => ({ ...row }));
    },
    // As the control store: inUnit runs after the change, and a throw from it undoes the change.
    async save({ insert = [], rewrap = [], retire = [], clear = false, inUnit = null } = {}) {
      let next = clear ? [] : rows.map(row => ({ ...row }));
      for (const { kid, wrapped } of rewrap) {
        const row = next.find(item => item.kid === kid);
        if (!row) throw new Error(`No key ${kid}`);
        row.wrapped = wrapped;
      }
      for (const { kid, retired_at } of retire) {
        const row = next.find(item => item.kid === kid);
        if (!row) throw new Error(`No key ${kid}`);
        row.retired_at = retired_at;
      }
      for (const row of insert) {
        if (next.some(item => item.kid === row.kid)) throw new Error(`Duplicate key ${row.kid}`);
        next.push({ ...row });
      }
      const previous = rows;
      rows = next;
      try {
        inUnit?.(null);
      } catch (error) {
        rows = previous;
        throw error;
      }
    },
  };
}
