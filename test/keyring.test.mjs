// The keyring (lib/keyring.mjs, roadmap §2.8): where the master key comes from, the keycheck,
// sealing with context binding, HMAC keys, rotation, rewrap after a master-key change, and
// the reset for a lost key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  parseKey,
  keyFingerprint,
  resolveKey,
  Keyring,
  KeyHooks,
  KeyError,
  SealError,
  keyPurposes,
  memoryKeyringStore,
  removeDataKeyCopy,
  secretKeyFile,
} from '../lib/keyring.mjs';
import { openControl, metaOps } from '../lib/db/control.mjs';
import { dataDirectoryProblem } from '../lib/environment.mjs';
import { platformSubtest } from './helpers/platform.mjs';

const hex = 'a1'.repeat(16) + 'b2'.repeat(16);
const keyA = Buffer.from(hex, 'hex');
const keyB = Buffer.from('c3'.repeat(16) + 'd4'.repeat(16), 'hex');

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-keyring-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
// Key sources that exist nowhere unless a test creates them.
const sources = directory => ({
  credentialsDirectory: path.join(directory, 'credentials'),
  secretsDirectory: path.join(directory, 'secrets'),
});
const mode = file => fs.statSync(file).mode & 0o777;

test('parseKey accepts 32 bytes in hex or base64 and refuses anything else, including placeholders', () => {
  assert.deepEqual(parseKey(hex), keyA);
  assert.deepEqual(parseKey(` ${hex}\n`), keyA);
  assert.deepEqual(parseKey(keyA.toString('base64')), keyA);
  assert.deepEqual(parseKey(keyA.toString('base64url')), keyA);
  assert.deepEqual(parseKey(keyA.toString('base64').replace(/=$/, '')), keyA);
  for (const bad of ['', 'short', hex.slice(2), `${hex}00`, '0'.repeat(64), 'zz'.repeat(32)])
    assert.throws(
      () => parseKey(bad, 'TEST_KEY'),
      error =>
        error instanceof KeyError && error.code === 'key_invalid' && /TEST_KEY/.test(error.message),
      bad
    );
  const fingerprint = keyFingerprint(keyA);
  assert.match(fingerprint, /^[0-9a-f]{16}$/);
  assert.notEqual(fingerprint, keyFingerprint(keyB));
  assert.ok(!hex.includes(fingerprint), 'the fingerprint is not part of the key');
});

test('resolveKey: GOBLIN_SECRET_KEY first, removed from the environment whether or not it is used', t => {
  const directory = temporary(t);
  const env = { GOBLIN_SECRET_KEY: hex, GOBLIN_SECRET_KEY_PREVIOUS: keyB.toString('hex') };
  const found = resolveKey({ env, directory, ...sources(directory) });
  assert.equal(found.source, 'env');
  assert.deepEqual(found.key, keyA);
  assert.deepEqual(found.previous, keyB);
  assert.equal(found.fingerprint, keyFingerprint(keyA));
  assert.ok(!('GOBLIN_SECRET_KEY' in env) && !('GOBLIN_SECRET_KEY_PREVIOUS' in env));
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  // An invalid key still leaves the environment.
  const bad = { GOBLIN_SECRET_KEY: 'nope', GOBLIN_SECRET_KEY_PREVIOUS: 'also nope' };
  assert.throws(() => resolveKey({ env: bad, directory, ...sources(directory) }), {
    code: 'key_invalid',
  });
  assert.deepEqual(bad, {});
  assert.throws(() => resolveKey({ env: {} }), /data directory/);
});

test('resolveKey: then GOBLIN_SECRET_KEY_FILE, the systemd credential and the Compose secret, in that order', t => {
  // The key sources beside the data directory, never in it (a key there travels with the data).
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  fs.mkdirSync(credentialsDirectory);
  fs.mkdirSync(secretsDirectory);
  const keyFile = path.join(base, 'secret-file.key');
  fs.writeFileSync(keyFile, `${hex}\n`, { mode: 0o640 });
  fs.writeFileSync(path.join(credentialsDirectory, 'orbit-secret-key'), keyB.toString('hex'), {
    mode: 0o400,
  });
  fs.writeFileSync(path.join(secretsDirectory, 'orbit_secret_key'), keyB.toString('base64'), {
    mode: 0o444,
  });
  const resolve = env =>
    resolveKey({ env, directory, credentialsDirectory, secretsDirectory, keyringExists: true });
  const fromFile = resolve({ GOBLIN_SECRET_KEY_FILE: keyFile });
  assert.deepEqual([fromFile.source, fromFile.file, fromFile.warnings], ['file', keyFile, []]);
  assert.deepEqual(fromFile.key, keyA);
  const credential = resolve({});
  assert.equal(credential.source, 'credentials');
  assert.deepEqual(credential.key, keyB);
  fs.rmSync(path.join(credentialsDirectory, 'orbit-secret-key'));
  const secret = resolve({});
  assert.equal(secret.source, 'secrets');
  assert.match(secret.warnings[0], /every user of this host/);
  // A named file that cannot be read, or a directory, is an error, never a fallback.
  assert.throws(() => resolve({ GOBLIN_SECRET_KEY_FILE: path.join(directory, 'missing') }), {
    code: 'key_file_unreadable',
  });
  assert.throws(() => resolve({ GOBLIN_SECRET_KEY_FILE: directory }), {
    code: 'key_file_unreadable',
  });
  fs.writeFileSync(keyFile, 'x'.repeat(5000));
  assert.throws(() => resolve({ GOBLIN_SECRET_KEY_FILE: keyFile }), /too large/);
  // A path with a line break or a terminal escape is refused as it is named, escaped: it was
  // printed raw into the refusal ("… cannot be read: ENOENT"), forging a line of the log.
  const forged = '/nonexistent\n[orbit] FORGED \u001b[2J';
  for (const variable of ['GOBLIN_SECRET_KEY_FILE', 'GOBLIN_SECRET_KEY_PREVIOUS_FILE'])
    assert.throws(
      () => resolve({ GOBLIN_SECRET_KEY_FILE: keyFile, [variable]: forged }),
      error =>
        error instanceof KeyError &&
        error.code === 'key_file_unreadable' &&
        error.message ===
          `${variable} must be a path without a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (it holds U+000A); it is "/nonexistent\\n[orbit] FORGED \\u001b[2J".`,
      variable
    );
});

// A key path and a data directory refuse the same characters, by one rule: GOBLIN_DATA_DIR
// refused only the C0 and C1 controls and DEL, so a data directory holding U+202E or U+2028
// started Uptime Goblin once, and every later start refused its own <data>/secret.key ("The
// data-directory key must be a path without ..."). The direction marks (U+061C, U+200E, U+200F)
// are refused by neither: a key file whose path holds one is read.
test('a key path refuses exactly what a data directory refuses, naming the code point; a direction mark is read', t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  const resolve = file =>
    resolveKey({
      env: { GOBLIN_SECRET_KEY_FILE: file },
      directory,
      ...sources(base),
      keyringExists: true,
    });
  // Every code point of the Basic Multilingual Plane, and one beyond it.
  const refused = [];
  for (let point = 0; point <= 0x10000; point++) {
    if (point >= 0xd800 && point <= 0xdfff) continue;
    const character = String.fromCodePoint(point);
    const file = path.join(base, `k${character}ey`);
    let message = '';
    try {
      resolve(file);
    } catch (error) {
      assert.equal(error.code, 'key_file_unreadable', `U+${point.toString(16)}`);
      message = error.message;
    }
    const byKey = /^GOBLIN_SECRET_KEY_FILE must be a path without /.test(message);
    assert.equal(byKey, dataDirectoryProblem(file) !== null, `U+${point.toString(16)}`);
    if (!byKey) continue;
    refused.push(point);
    const name = `U+${point.toString(16).toUpperCase().padStart(4, '0')}`;
    assert.ok(message.includes(`(it holds ${name}); it is "`), message);
    assert.ok(!message.includes(character), `${name} is printed escaped`);
  }
  assert.equal(refused.length, 32 + 1 + 32 + 2 + 5 + 4);
  // A real file whose path holds a direction mark is the key, as the path says.
  for (const mark of ['\u061c', '\u200e', '\u200f']) {
    const file = path.join(base, `key${mark}.key`);
    fs.writeFileSync(file, `${hex}\n`, { mode: 0o600 });
    const found = resolve(file);
    assert.deepEqual([found.source, found.file], ['file', file]);
    assert.deepEqual(found.key, keyA);
  }
  // The data-directory key is read by the same rule: <data>/secret.key under a <data> holding
  // U+202E is refused, and so is that <data>, so a start never gets as far as making it.
  const odd = path.join(base, 'x\u202edata');
  fs.mkdirSync(odd);
  fs.writeFileSync(path.join(odd, secretKeyFile), `${hex}\n`, { mode: 0o600 });
  assert.throws(
    () => resolveKey({ env: {}, directory: odd, ...sources(base), keyringExists: true }),
    error =>
      error.code === 'key_file_unreadable' &&
      /^The data-directory key must be a path without .* \(it holds U\+202E\)/.test(error.message)
  );
  assert.match(dataDirectoryProblem(odd), /\(it holds U\+202E\)$/);
});

test('resolveKey generates <data>/secret.key only while no keyring exists; a keyring without a key refuses', t => {
  const directory = path.join(temporary(t), 'data');
  const options = { directory, ...sources(directory) };
  // No keyring: generate 0600, exclusively, and warn that it travels with the data.
  const generated = resolveKey({ env: {}, ...options });
  assert.equal(generated.source, 'generated');
  const file = path.join(directory, secretKeyFile);
  assert.equal(generated.file, file);
  assert.equal(mode(file), 0o600);
  assert.match(generated.warnings[0], /every copy of the data directory carries the key/);
  assert.deepEqual(parseKey(fs.readFileSync(file, 'utf8')), generated.key);
  // Next start: the same key, read back.
  const again = resolveKey({ env: {}, ...options, keyringExists: true });
  assert.equal(again.source, 'data-directory');
  assert.deepEqual(again.key, generated.key);
  // A keyring and no key anywhere: exit 78, naming every source checked, generating nothing.
  fs.rmSync(file);
  assert.throws(
    () => resolveKey({ env: {}, ...options, keyringExists: true }),
    error =>
      error instanceof KeyError &&
      error.code === 'key_missing' &&
      error.exitCode === 78 &&
      error.refusal === true &&
      error.checked.includes('GOBLIN_SECRET_KEY') &&
      error.checked.includes(file) &&
      // A command that runs as printed (there is no goblin-admin on the PATH), naming the key file:
      // goblin-admin reads the key from its own environment, never from /etc/uptime-goblin.env.
      error.message.includes(
        'Restore the key. Only if it is truly lost, give up what it protects (docs/troubleshooting.md#lost-encryption-key): put a new key in place, then run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key reset --confirm-lost-key --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
      ) &&
      !error.message.includes('"goblin-admin')
  );
  assert.equal(fs.existsSync(file), false);
  // generate: false only reports.
  assert.equal(resolveKey({ env: {}, ...options, generate: false }), null);
  assert.equal(fs.existsSync(file), false);
});

// Review F2v2: resolveKey reads the previous key first, then failed on a key file it could not
// read, a key it could not parse or no key at all, and the previous key stayed in memory (as
// restore-snapshot's key check left it). Every key it read and does not return is wiped; a key it
// returns is the caller's to wipe.
test('resolveKey wipes the previous key, and any key it read, when it throws or returns none', t => {
  const directory = path.join(temporary(t), 'data');
  fs.mkdirSync(directory);
  const options = { directory, ...sources(directory) };
  const previousFile = path.join(directory, '..', 'previous.key');
  fs.writeFileSync(previousFile, `${'e5'.repeat(16)}${'f6'.repeat(16)}\n`, { mode: 0o600 });
  // Every 32-byte key parsed from hex while resolveKey runs (parseKey makes them).
  const parsed = [];
  const from = Buffer.from;
  t.mock.method(Buffer, 'from', function (value, encoding, ...rest) {
    const made = from.call(this, value, encoding, ...rest);
    if (encoding === 'hex' && typeof value === 'string' && made.length === 32) parsed.push(made);
    return made;
  });
  const wiped = buffer => buffer.every(byte => byte === 0);
  for (const [name, env, extra, code] of [
    [
      'a key file that cannot be read',
      {
        GOBLIN_SECRET_KEY_FILE: path.join(directory, 'missing'),
        GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile,
      },
      {},
      'key_file_unreadable',
    ],
    [
      'a key that does not parse',
      {
        GOBLIN_SECRET_KEY: 'not a key',
        GOBLIN_SECRET_KEY_PREVIOUS: `${'e5'.repeat(16)}${'f6'.repeat(16)}`,
      },
      {},
      'key_invalid',
    ],
    [
      'no key, with a keyring',
      { GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile },
      { keyringExists: true },
      'key_missing',
    ],
  ]) {
    parsed.length = 0;
    assert.throws(() => resolveKey({ env, ...options, ...extra }), { code }, name);
    assert.equal(parsed.length, 1, `${name}: the previous key was read`);
    assert.ok(parsed.every(wiped), `${name}: the previous key is wiped`);
  }
  // No key and no keyring, without generating: nothing is returned, so nothing is kept.
  parsed.length = 0;
  assert.equal(
    resolveKey({
      env: { GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile },
      ...options,
      generate: false,
    }),
    null
  );
  assert.equal(parsed.length, 1);
  assert.ok(parsed.every(wiped), 'the previous key is wiped when none is returned');
  // Found, both are the caller's: returned whole, not wiped.
  parsed.length = 0;
  const found = resolveKey({
    env: { GOBLIN_SECRET_KEY: hex, GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile },
    ...options,
  });
  assert.deepEqual(found.key, keyA);
  assert.ok(!wiped(found.previous));
  assert.equal(parsed.length, 2);
  found.key.fill(0);
  found.previous.fill(0);
});

// Review F2v2, round 6: restore-snapshot's keyring check read the previous key file first, and one
// it could not read failed the whole check, so the key it could read was never checked. With
// onPreviousError a previous key it cannot read, or that is no key, is handed over and left out;
// without it (Uptime Goblin's start) it still throws.
test('resolveKey leaves out a previous key it cannot read only when given onPreviousError', t => {
  const directory = path.join(temporary(t), 'data');
  fs.mkdirSync(directory);
  const options = { directory, ...sources(directory) };
  const keyFile = path.join(directory, '..', 'key');
  fs.writeFileSync(keyFile, `${hex}\n`, { mode: 0o600 });
  const missing = path.join(directory, '..', 'missing.key');
  for (const [name, previous, code, message] of [
    [
      'a previous key file that is not there',
      { GOBLIN_SECRET_KEY_PREVIOUS_FILE: missing },
      'key_file_unreadable',
      `GOBLIN_SECRET_KEY_PREVIOUS_FILE (${missing}) cannot be read: ENOENT.`,
    ],
    [
      'a previous key file that is a directory',
      { GOBLIN_SECRET_KEY_PREVIOUS_FILE: directory },
      'key_file_unreadable',
      `GOBLIN_SECRET_KEY_PREVIOUS_FILE (${directory}) is not a file.`,
    ],
    [
      'a previous key that is no key',
      { GOBLIN_SECRET_KEY_PREVIOUS: 'not a key' },
      'key_invalid',
      /^GOBLIN_SECRET_KEY_PREVIOUS must be 32 random bytes/,
    ],
  ]) {
    // As Uptime Goblin's start calls it: the previous key's error, and no key.
    assert.throws(
      () => resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: keyFile, ...previous }, ...options }),
      { code, message },
      name
    );
    const errors = [];
    const env = { GOBLIN_SECRET_KEY_FILE: keyFile, ...previous };
    const found = resolveKey({ env, ...options, onPreviousError: error => errors.push(error) });
    assert.deepEqual(found.key, keyA, name);
    assert.equal(found.previous, null, name);
    assert.equal(found.previousFile, null, name);
    assert.equal(found.source, 'file', name);
    assert.equal(errors.length, 1, name);
    assert.ok(errors[0] instanceof KeyError, name);
    assert.equal(errors[0].code, code, name);
    if (typeof message === 'string') assert.equal(errors[0].message, message, name);
    else assert.match(errors[0].message, message, name);
    assert.ok(!Object.hasOwn(env, 'GOBLIN_SECRET_KEY_PREVIOUS'), `${name}: removed once read`);
    found.key.fill(0);
  }
  // A key that cannot be read still throws, with the previous key's error handed over first.
  const errors = [];
  assert.throws(
    () =>
      resolveKey({
        env: {
          GOBLIN_SECRET_KEY_FILE: path.join(directory, 'nope'),
          GOBLIN_SECRET_KEY_PREVIOUS_FILE: missing,
        },
        ...options,
        onPreviousError: error => errors.push(error),
      }),
    { code: 'key_file_unreadable', message: /^GOBLIN_SECRET_KEY_FILE \(/ }
  );
  assert.equal(errors.length, 1);
});

// Review F2v2, round 4: restore-snapshot reads keys too, and after it returned the text of both key
// files (the key and the previous key, as read) was still in memory. A key file's text is zeroed
// once parsed, also when it does not parse; the parsed key is the caller's.
test('resolveKey zeroes the text it read from a key file, whether the key parses or not', t => {
  const directory = path.join(temporary(t), 'data');
  fs.mkdirSync(directory);
  const options = { directory, ...sources(directory) };
  const previousHex = 'e5'.repeat(16) + 'f6'.repeat(16);
  const keyFile = path.join(directory, '..', 'key');
  const previousFile = path.join(directory, '..', 'previous.key');
  fs.writeFileSync(keyFile, `${hex}\n`, { mode: 0o600 });
  fs.writeFileSync(previousFile, `${previousHex}\n`, { mode: 0o600 });
  // Every buffer readKeyFile reads a key file into, allocated while resolveKey runs: one byte more
  // than its 4096-byte limit for a key file, whatever the file's size (it reads up to the limit
  // and one byte more, so a file that grew after fstat is refused like a large one).
  const read = [];
  const alloc = Buffer.alloc;
  t.mock.method(Buffer, 'alloc', function (size, ...rest) {
    const made = alloc.call(this, size, ...rest);
    if (size === 4096 + 1) read.push(made);
    return made;
  });
  const holdsText = buffer => [hex, previousHex].some(text => buffer.includes(text));
  const found = resolveKey({
    env: { GOBLIN_SECRET_KEY_FILE: keyFile, GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile },
    ...options,
  });
  assert.deepEqual(found.key, keyA);
  assert.equal(read.length, 2, 'both key files were read');
  assert.ok(!read.some(holdsText), 'neither key file text is left in its read buffer');
  found.key.fill(0);
  found.previous.fill(0);
  // A file whose text is no key: refused, and its text is zeroed too.
  const bad = path.join(directory, '..', 'bad.key');
  fs.writeFileSync(bad, `${hex.slice(0, 63)}g\n`, { mode: 0o600 });
  read.length = 0;
  assert.throws(() => resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: bad }, ...options }), {
    code: 'key_invalid',
  });
  assert.equal(read.length, 1);
  assert.ok(
    read[0].every(byte => byte === 0),
    'the refused text is zeroed'
  );
});

// Review F2v2, round 4: Keyring.check (restore-snapshot's check, key status, the start's keycheck)
// unwraps every data key and returns only how many there are: the data keys it unwrapped are
// wiped, also those unwrapped before a data key that does not open refused the check.
test('Keyring.check wipes the data keys it unwrapped, when it passes and when it refuses', async t => {
  const store = memoryKeyringStore();
  await Keyring.open(store, { key: keyA });
  const rows = await store.list();
  assert.ok(rows.length >= 2);
  // The same keyring with one more data key, wrapped with another key: the check refuses at it,
  // after unwrapping the others.
  const other = memoryKeyringStore();
  await Keyring.open(other, { key: keyB });
  const mixed = { list: async () => [...rows, (await other.list())[0]] };
  // Every 32-byte buffer Buffer.concat makes while the check runs (unwrap makes each data key so).
  const made = [];
  const concat = Buffer.concat;
  t.mock.method(Buffer, 'concat', function (...args) {
    const buffer = concat.apply(this, args);
    if (buffer.length === 32) made.push(buffer);
    return buffer;
  });
  const wiped = () => made.every(buffer => buffer.every(byte => byte === 0));
  assert.equal((await Keyring.check(store, { key: keyA })).keys, rows.length);
  assert.equal(made.length, rows.length, 'every data key was unwrapped');
  assert.ok(wiped(), 'the data keys are wiped once checked');
  made.length = 0;
  await assert.rejects(Keyring.check(mixed, { key: keyA }), { code: 'key_mismatch' });
  assert.equal(made.length, rows.length, 'the data keys before the refusal were unwrapped');
  assert.ok(wiped(), 'and wiped when the check refused');
});

test('a generated key is written exclusively and fsynced, the file and then the data directory', t => {
  const directory = path.join(temporary(t), 'data');
  const opened = new Map(),
    synced = [],
    open = fs.openSync,
    fsync = fs.fsyncSync;
  t.mock.method(fs, 'openSync', function (file, ...rest) {
    const descriptor = open.call(fs, file, ...rest);
    opened.set(descriptor, String(file));
    return descriptor;
  });
  t.mock.method(fs, 'fsyncSync', function (descriptor) {
    const file = opened.get(descriptor);
    // When the file is synced its whole content is already written.
    synced.push([
      file,
      file?.endsWith(secretKeyFile) ? fs.readFileSync(file, 'utf8').length : null,
    ]);
    return fsync.call(fs, descriptor);
  });
  const generated = resolveKey({ env: {}, directory, ...sources(directory) });
  assert.equal(generated.source, 'generated');
  const file = path.join(directory, secretKeyFile);
  // Only the calls can be checked (no test can cut the power): file first, then directory.
  assert.deepEqual(synced, [
    [file, 65],
    [directory, null],
  ]);
  assert.equal(mode(file), 0o600);
  // Never overwritten: a second generation reads the key that is there.
  synced.length = 0;
  const again = resolveKey({ env: {}, directory, ...sources(directory) });
  assert.deepEqual(again.key, generated.key);
  assert.equal(again.source, 'data-directory');
  assert.deepEqual(synced, []);
});

test('a key file that fails part way is removed, so no start mistakes it for a key', t => {
  const directory = path.join(temporary(t), 'data');
  t.mock.method(fs, 'fsyncSync', () => {
    throw Object.assign(new Error('I/O error'), { code: 'EIO' });
  });
  assert.throws(() => resolveKey({ env: {}, directory, ...sources(directory) }), { code: 'EIO' });
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
});

// A67: the warning for an older key (the data moved from it with key rewrap) said "is not used"
// and to delete it, with no command: key remove-data-copy keeps such a key on purpose (it is not
// a copy), so it stayed in every copy of the data directory. Each warning now gives the line that
// deletes the file as what it is: a copy with key remove-data-copy, an older key with --unused,
// under Docker Compose for the Compose secret, natively with the key file Uptime Goblin reads.
// The line ends the warning, alone: which install it is for comes before it (P3 of Codex's
// 1.5.0-dev.1 milestone review: a note after the command made the whole line fail in sh and zsh).
const nativeLine = (args, keyFile = '/etc/uptime-goblin/secret.key') =>
  `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${keyFile} node /opt/uptime-goblin/lib/cli/goblin-admin.mjs ${args} --data-dir /var/lib/uptime-goblin`;
const composeLine = args =>
  `docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs ${args}`;
const thisLine = line =>
  line.startsWith('docker compose ')
    ? 'This line'
    : 'This line (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin)';
const olderKey = (own, theirs, label, ours, line) =>
  `${own} (fingerprint ${keyFingerprint(theirs)}) is an older key, which Uptime Goblin does not use: the key comes from ${label} (fingerprint ${keyFingerprint(ours)}), as after goblin-admin key rewrap, and every copy of the data directory carries it. ${thisLine(line)} deletes it only while the key it is given opens every data key and ${own} opens none, and otherwise says why and deletes nothing: ${line}`;

test('a <data>/secret.key that another source makes unused is reported with both fingerprints and the line that deletes it as what it is', t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  const options = { directory, credentialsDirectory, secretsDirectory, keyringExists: true };
  // No secret.key: no warning.
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY: hex }, ...options }).warnings, []);
  // A different key: both fingerprints, and the --unused line (natively: the installer's key
  // file, as other native key lines name it when the key is no file).
  fs.writeFileSync(own, keyB.toString('hex') + '\n', { mode: 0o600 });
  const different = resolveKey({ env: { GOBLIN_SECRET_KEY: hex }, ...options });
  assert.equal(different.source, 'env');
  assert.deepEqual(different.warnings, [
    olderKey(own, keyB, 'GOBLIN_SECRET_KEY', keyA, nativeLine('key remove-data-copy --unused')),
  ]);
  assert.doesNotMatch(different.warnings[0], /is not used/);
  // The same, beside the Compose secret: the line runs in Uptime Goblin's container.
  fs.mkdirSync(secretsDirectory);
  const compose = path.join(secretsDirectory, 'orbit_secret_key');
  fs.writeFileSync(compose, hex, { mode: 0o400 });
  assert.deepEqual(resolveKey({ env: {}, ...options }).warnings, [
    olderKey(
      own,
      keyB,
      `the Compose secret (${compose})`,
      keyA,
      composeLine('key remove-data-copy --unused')
    ),
  ]);
  // And beside GOBLIN_SECRET_KEY_FILE: natively, with that file.
  const newer = path.join(base, 'newer.key');
  fs.writeFileSync(newer, hex, { mode: 0o600 });
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: newer }, ...options }).warnings, [
    olderKey(
      own,
      keyB,
      `GOBLIN_SECRET_KEY_FILE (${newer})`,
      keyA,
      nativeLine('key remove-data-copy --unused', newer)
    ),
  ]);
  // A copy beside GOBLIN_SECRET_KEY_FILE: the line without --unused.
  fs.writeFileSync(newer, keyB.toString('hex'), { mode: 0o600 });
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: newer }, ...options }).warnings, [
    `${own} is a copy of the key Uptime Goblin uses, which comes from GOBLIN_SECRET_KEY_FILE (${newer}), and every copy of the data directory carries it. ${thisLine(nativeLine('key remove-data-copy'))} deletes it only while the key it is given holds the same key and opens the data, and otherwise says why and deletes nothing: ${nativeLine('key remove-data-copy', newer)}`,
  ]);
  fs.rmSync(newer);
  fs.rmSync(compose);
  // The same key (copied out of the data directory, as the Compose recipe does). Uptime Goblin cannot
  // see where a secret was mounted from, which may be this very file on the host: deleting it
  // comes after the secret no longer comes from it.
  fs.writeFileSync(compose, keyB.toString('hex'), { mode: 0o400 });
  const same = resolveKey({ env: {}, ...options });
  assert.equal(same.source, 'secrets');
  assert.deepEqual(same.warnings, [
    `${own} holds the same key as the Compose secret (${compose}), which Uptime Goblin uses. If the Compose secret's file is this secret.key (a data directory mounted from the host), deleting it would stop Uptime Goblin from starting: first copy the key to a file outside the data directory and make that the secret's file. Once the secret no longer comes from ${own} and Uptime Goblin has started with it, delete ${own}; every copy of the data directory carries it. This line deletes it only while the key it is given is another file that holds the same key and opens the data, and otherwise says why and deletes nothing: docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy`,
  ]);
  // One that cannot be read.
  fs.writeFileSync(own, 'not a key\n');
  const keyFile = path.join(base, 'outside.key');
  fs.writeFileSync(keyFile, hex, { mode: 0o600 });
  const unreadable = resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: keyFile }, ...options });
  assert.deepEqual(unreadable.warnings, [
    `${own} (which could not be read) is not used: the key comes from GOBLIN_SECRET_KEY_FILE (${keyFile}) (fingerprint ${keyFingerprint(keyA)}). Uptime Goblin cannot tell whether it is a copy of that key or an older one, so goblin-admin key remove-data-copy keeps it; every copy of the data directory carries it: find out what it holds before you delete it.`,
  ]);
  // The data-directory key in use is not "unused".
  fs.writeFileSync(own, hex);
  fs.rmSync(compose);
  const inUse = resolveKey({ env: {}, ...options });
  assert.equal(inUse.source, 'data-directory');
  assert.ok(inUse.warnings.every(warning => !/is not used/.test(warning)));
});

// Review round 3: GOBLIN_SECRET_KEY_FILE naming <data>/secret.key was told that file "is not
// used" and to delete it, which deleted the only copy of the key (the next start: exit 78,
// key_file_unreadable, ENOENT), and the warning that every copy of the data carries the key was
// missing. The same advice reached a systemd credential loaded from that file.
test('a key source that reads <data>/secret.key itself is never called unused: it travels with the data and is copied out before it is deleted', t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  const options = { directory, credentialsDirectory, secretsDirectory, keyringExists: true };
  // The data directory's key, as Uptime Goblin generated it.
  const generated = resolveKey({ env: {}, directory, credentialsDirectory, secretsDirectory });
  assert.equal(generated.source, 'generated');
  const fingerprint = generated.fingerprint;
  const copyOut = (label, how) =>
    `${label} is inside the data directory, so every copy of the data directory carries the key. Keep backups of the data and of the key apart: copy the key to a file outside the data directory and ${how}. Delete ${own} only once Uptime Goblin has started with the copy: until then it is the key Uptime Goblin reads.`;
  // GOBLIN_SECRET_KEY_FILE naming it: the key in use, with the copy-out advice, and the start
  // after that still finds it.
  const named = resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: own }, ...options });
  assert.deepEqual(
    [named.source, named.file, named.fingerprint],
    ['file', own, fingerprint],
    'the same key'
  );
  assert.deepEqual(named.warnings, [
    copyOut(`GOBLIN_SECRET_KEY_FILE (${own})`, 'set GOBLIN_SECRET_KEY_FILE to that copy'),
  ]);
  assert.ok(named.warnings.every(warning => !/is not used/.test(warning)));
  assert.equal(
    resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: own }, ...options }).fingerprint,
    fingerprint
  );
  // Named through the data directory written another way (a relative path) and through a link
  // outside it: the same file.
  const relative = path.relative(process.cwd(), own);
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: relative }, ...options }).warnings, [
    copyOut(`GOBLIN_SECRET_KEY_FILE (${relative})`, 'set GOBLIN_SECRET_KEY_FILE to that copy'),
  ]);
  const link = path.join(base, 'linked.key');
  fs.symlinkSync(own, link);
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: link }, ...options }).warnings, [
    copyOut(
      `GOBLIN_SECRET_KEY_FILE (${link}), which is ${own} itself,`,
      'set GOBLIN_SECRET_KEY_FILE to that copy'
    ),
  ]);
  // A Compose secret mounted from that very file on the host (a hard link stands in for the
  // bind mount: the same device and inode).
  fs.mkdirSync(secretsDirectory);
  const compose = path.join(secretsDirectory, 'orbit_secret_key');
  fs.linkSync(own, compose);
  assert.deepEqual(resolveKey({ env: {}, ...options }).warnings, [
    copyOut(
      `The Compose secret (${compose}), which is ${own} itself,`,
      "make that copy the Compose secret's file"
    ),
  ]);
  fs.rmSync(compose);
  // A systemd credential: a copy systemd makes, which may come from <data>/secret.key. Never
  // "delete it" without "first move the key out".
  fs.mkdirSync(credentialsDirectory);
  fs.copyFileSync(own, path.join(credentialsDirectory, 'orbit-secret-key'));
  const credential = resolveKey({ env: {}, ...options });
  const label = `the systemd credential (${path.join(credentialsDirectory, 'orbit-secret-key')})`;
  assert.deepEqual(credential.warnings, [
    `${own} holds the same key as ${label}, which Uptime Goblin uses. If the credential is loaded from ${own} (LoadCredential=orbit-secret-key:${own}), deleting it would stop Uptime Goblin from starting: first copy the key to a file outside the data directory and load the credential from there. Once the credential no longer comes from ${own} and Uptime Goblin has started with it, delete ${own}; every copy of the data directory carries it.`,
  ]);
  fs.rmSync(path.join(credentialsDirectory, 'orbit-secret-key'));
  // Another key file inside the data directory: it travels too (no deletion clause for it), and
  // <data>/secret.key beside it is unused.
  const inside = path.join(directory, 'keys', 'orbit.key');
  fs.mkdirSync(path.dirname(inside));
  fs.writeFileSync(inside, keyB.toString('hex'), { mode: 0o600 });
  const other = resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: inside }, ...options });
  assert.deepEqual(other.warnings, [
    `GOBLIN_SECRET_KEY_FILE (${inside}) is inside the data directory, so every copy of the data directory carries the key. Keep backups of the data and of the key apart: copy the key to a file outside the data directory and set GOBLIN_SECRET_KEY_FILE to that copy.`,
    `${own} (fingerprint ${fingerprint}) is an older key, which Uptime Goblin does not use: the key comes from GOBLIN_SECRET_KEY_FILE (${inside}) (fingerprint ${keyFingerprint(keyB)}), as after goblin-admin key rewrap, and every copy of the data directory carries it. ${thisLine(nativeLine(''))} deletes it only while the key it is given opens every data key and ${own} opens none, and otherwise says why and deletes nothing: ${nativeLine('key remove-data-copy --unused', inside)}`,
  ]);
  // <data>/secret.key that is only a link to a key outside, named by GOBLIN_SECRET_KEY_FILE: it
  // is the path Uptime Goblin reads (never "unused"), and no key lies in the data directory.
  const outside = path.join(base, 'outside.key');
  fs.copyFileSync(own, outside);
  fs.rmSync(own);
  fs.symlinkSync(outside, own);
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: own }, ...options }).warnings, []);
  // The same link while GOBLIN_SECRET_KEY_FILE names the key outside: deleting the link loses
  // nothing, so it is reported as unused, with no remove-data-copy line (which deletes only a
  // regular file).
  assert.deepEqual(resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: outside }, ...options }).warnings, [
    `${own} is a symbolic link, which Uptime Goblin does not use: the key comes from GOBLIN_SECRET_KEY_FILE (${outside}) (fingerprint ${fingerprint}). Deleting the link deletes no key.`,
  ]);
});

test('Keyring.open creates one data key per purpose; the keycheck refuses a different master key', async () => {
  const store = memoryKeyringStore();
  const keyring = await Keyring.open(store, { key: keyA, clock: () => 10 });
  assert.deepEqual(
    keyring
      .describe()
      .map(entry => entry.purpose)
      .sort(),
    [...keyPurposes].sort()
  );
  assert.ok(keyring.describe().every(entry => entry.active && !entry.retired));
  assert.equal(keyring.fingerprint, keyFingerprint(keyA));
  assert.equal(keyring.needsRewrap, false);
  // Wrapped keys never contain the key material in the clear.
  for (const row of store.rows) {
    assert.match(row.wrapped, /^w1\./);
    assert.equal(row.created_at, 10);
  }
  // Opening again finds the same keys and adds none.
  const reopened = await Keyring.open(store, { key: keyA });
  assert.equal(store.rows.length, 4);
  assert.deepEqual(reopened.describe(), keyring.describe());
  await assert.rejects(
    Keyring.open(store, { key: keyB }),
    error =>
      error instanceof KeyError &&
      error.code === 'key_mismatch' &&
      error.exitCode === 78 &&
      error.message.endsWith(
        'put the old one in a file the uptime-goblin user can read and run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key rotate --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
      )
  );
  await assert.rejects(Keyring.check(store, { key: keyB }), { code: 'key_mismatch' });
  assert.deepEqual(await Keyring.check(store, { key: keyA }), { keys: 4, stale: [] });
  await assert.rejects(Keyring.open(store, { key: Buffer.alloc(16) }), TypeError);
  await assert.rejects(Keyring.open(memoryKeyringStore(), { key: keyA, create: false }), {
    code: 'keyring_incomplete',
  });
  // Audit review round 2: `complete: false` (goblin-admin verify-audit) opens a keyring that
  // lacks an active key, with every key it holds, retired ones included, and writes nothing.
  const retired = memoryKeyringStore(
    store.rows.map(row => (row.purpose === 'audit' ? { ...row, retired_at: 1 } : row))
  );
  await assert.rejects(Keyring.open(retired, { key: keyA, create: false }), {
    code: 'keyring_incomplete',
  });
  const partial = await Keyring.open(retired, { key: keyA, create: false, complete: false });
  assert.equal(retired.rows.length, 4, 'nothing added');
  const auditKid = keyring.activeKid('audit');
  assert.equal(partial.hmac('audit', 'x', auditKid).mac, keyring.hmac('audit', 'x', auditKid).mac);
  assert.throws(() => partial.activeKid('audit'), TypeError);
  const none = await Keyring.open(memoryKeyringStore(), {
    key: keyA,
    create: false,
    complete: false,
  });
  assert.deepEqual(none.describe(), []);
  await assert.rejects(Keyring.open(retired, { key: keyB, create: false, complete: false }), {
    code: 'key_mismatch',
  });
  // A tampered wrapped key fails the keycheck too.
  const tampered = memoryKeyringStore(
    store.rows.map((row, index) =>
      index
        ? row
        : {
            ...row,
            wrapped: row.wrapped.replace(/^w1\.(.)/, (_, c) => `w1.${c === 'A' ? 'B' : 'A'}`),
          }
    )
  );
  await assert.rejects(Keyring.open(tampered, { key: keyA }), { code: 'key_mismatch' });
});

test('seal and open: AES-GCM envelopes bound to purpose and context; a bad blob fails only itself', async () => {
  const keyring = await Keyring.open(memoryKeyringStore(), { key: keyA });
  const envelope = keyring.sealText('seal', 'channel-token', 'channel:7:token');
  const parts = envelope.split('.');
  assert.equal(parts.length, 5);
  assert.equal(parts[0], 'v1');
  assert.equal(parts[1], keyring.activeKid('seal'));
  assert.equal(Keyring.kidOf(envelope), parts[1]);
  assert.equal(Keyring.kidOf('garbage'), null);
  assert.notEqual(
    keyring.sealText('seal', 'channel-token', 'channel:7:token'),
    envelope,
    'random IV'
  );
  assert.equal(keyring.openText('seal', envelope, 'channel:7:token'), 'channel-token');
  const binary = keyring.seal('sessions', Buffer.from([0, 1, 2]), 'session:a');
  assert.deepEqual(keyring.open('sessions', binary, 'session:a'), Buffer.from([0, 1, 2]));
  // Another context, another purpose, or an altered envelope does not open.
  assert.throws(() => keyring.openText('seal', envelope, 'channel:8:token'), SealError);
  assert.throws(() => keyring.openText('sessions', envelope, 'channel:7:token'), {
    code: 'seal_unknown_key',
  });
  const altered = [
    ...parts.slice(0, 3),
    parts[3].replace(/^./, c => (c === 'A' ? 'B' : 'A')),
    parts[4],
  ].join('.');
  assert.throws(() => keyring.openText('seal', altered, 'channel:7:token'), SealError);
  assert.throws(() => keyring.openText('seal', 'v2.x.y.z.w', 'a'), { code: 'seal_malformed' });
  assert.throws(() => keyring.openText('seal', 'v1.nokid.AAAA.AAAA.AAAA', 'a'), {
    code: 'seal_unknown_key',
  });
  assert.throws(() => keyring.openText('seal', `v1.${parts[1]}.!!.AAAA.AAAA`, 'a'), {
    code: 'seal_malformed',
  });
  // Contexts are required and bounded; HMAC keys cannot seal and sealing keys cannot MAC.
  assert.throws(() => keyring.sealText('seal', 'x', ''), TypeError);
  assert.throws(() => keyring.sealText('seal', 'x', 'y'.repeat(1025)), TypeError);
  assert.throws(() => keyring.sealText('login', 'x', 'ctx'), TypeError);
  assert.throws(() => keyring.hmac('seal', 'x'), TypeError);
  assert.throws(() => keyring.activeKid('nothing'), TypeError);
});

test('hmac and subkey: stable per key, different per purpose', async () => {
  const store = memoryKeyringStore();
  const keyring = await Keyring.open(store, { key: keyA });
  const first = keyring.hmac('login', 'ip:192.0.2.1');
  assert.equal(first.kid, keyring.activeKid('login'));
  assert.match(first.mac, /^[0-9a-f]{64}$/);
  assert.deepEqual((await Keyring.open(store, { key: keyA })).hmac('login', 'ip:192.0.2.1'), first);
  assert.notEqual(keyring.hmac('audit', 'ip:192.0.2.1').mac, first.mac);
  assert.throws(() => keyring.hmac('login', 'x', 'unknown-kid'), { code: 'seal_unknown_key' });
  const subkey = keyring.subkey('sessions', 'collector');
  assert.equal(subkey.length, 32);
  assert.deepEqual(keyring.subkey('sessions', 'collector'), subkey);
  assert.notDeepEqual(keyring.subkey('sessions', 'other'), subkey);
  assert.equal(keyring.subkey('seal', 'x', 16).length, 16);
  assert.throws(() => keyring.subkey('seal', ''), TypeError);
});

test('rotate: new data keys, old ones retired but still opening old values; hooks re-seal', async () => {
  const store = memoryKeyringStore();
  let now = 100;
  const keyring = await Keyring.open(store, { key: keyA, clock: () => now });
  const old = keyring.sealText('seal', 'secret', 'ctx');
  const oldMac = keyring.hmac('audit', 'row');
  const resealed = [];
  const hooks = new KeyHooks()
    .register('alerting', {
      rotate: ({ keyring: current, purposes }) => {
        resealed.push(purposes);
        return current.sealText('seal', current.openText('seal', old, 'ctx'), 'ctx');
      },
    })
    .register('identity', {});
  assert.throws(() => hooks.register('alerting', {}), /registered/);
  assert.deepEqual(hooks.components, ['alerting', 'identity']);
  now = 200;
  const result = await keyring.rotate({ purposes: ['seal', 'audit'], hooks });
  assert.equal(result.retired.length, 2);
  assert.deepEqual(result.hooks, ['alerting']);
  assert.deepEqual(resealed, [['seal', 'audit']]);
  assert.notEqual(keyring.activeKid('seal'), Keyring.kidOf(old));
  assert.equal(keyring.openText('seal', old, 'ctx'), 'secret', 'retired keys still open');
  assert.equal(Keyring.kidOf(keyring.sealText('seal', 'x', 'ctx')), keyring.activeKid('seal'));
  // An old MAC can still be checked with its kid.
  assert.deepEqual(keyring.hmac('audit', 'row', oldMac.kid), oldMac);
  const retired = store.rows.filter(row => row.retired_at !== null);
  assert.deepEqual(
    retired.map(row => row.retired_at),
    [200, 200]
  );
  // The reopened keyring agrees on the active keys.
  const reopened = await Keyring.open(store, { key: keyA });
  assert.equal(reopened.activeKid('seal'), keyring.activeKid('seal'));
  assert.equal(reopened.openText('seal', old, 'ctx'), 'secret');
  await assert.rejects(keyring.rotate({ purposes: ['nope'] }), TypeError);
});

test('a master-key change: the previous key opens the data, rewrap moves every data key to the new one', async () => {
  const store = memoryKeyringStore();
  const original = await Keyring.open(store, { key: keyA });
  const sealed = original.sealText('seal', 'kept', 'ctx');
  // The new key alone does not open the data; with the previous key it does, and says so.
  await assert.rejects(Keyring.open(store, { key: keyB }), { code: 'key_mismatch' });
  assert.deepEqual((await Keyring.check(store, { key: keyB, previous: keyA })).stale.length, 4);
  const moving = await Keyring.open(store, { key: keyB, previous: keyA });
  assert.equal(moving.needsRewrap, true);
  assert.equal(moving.openText('seal', sealed, 'ctx'), 'kept');
  assert.deepEqual(await moving.rewrap(), { rewrapped: 4, wereStale: 4 });
  assert.equal(moving.needsRewrap, false);
  const after = await Keyring.open(store, { key: keyB });
  assert.equal(after.openText('seal', sealed, 'ctx'), 'kept');
  await assert.rejects(Keyring.open(store, { key: keyA }), { code: 'key_mismatch' });
});

test('reset for a lost key: needs confirmation, replaces every data key at once, and runs the reset hooks', async () => {
  const store = memoryKeyringStore();
  const lost = await Keyring.open(store, { key: keyA });
  const sealed = lost.sealText('seal', 'gone', 'ctx');
  await assert.rejects(Keyring.reset(store, { key: keyB }), { code: 'reset_unconfirmed' });
  await assert.rejects(
    Keyring.reset(store, { key: Buffer.alloc(3), confirmLostKey: true }),
    TypeError
  );
  const dropped = [];
  const hooks = new KeyHooks().register('identity', {
    reset: ({ keyring }) => dropped.push(keyring.fingerprint),
  });
  const {
    keyring,
    discarded,
    hooks: ran,
  } = await Keyring.reset(store, {
    key: keyB,
    confirmLostKey: true,
    hooks,
  });
  assert.equal(discarded, 4);
  assert.deepEqual(ran, ['identity']);
  assert.deepEqual(dropped, [keyFingerprint(keyB)]);
  assert.equal(store.rows.length, 4);
  assert.throws(() => keyring.openText('seal', sealed, 'ctx'), { code: 'seal_unknown_key' });
  assert.equal((await Keyring.open(store, { key: keyB })).describe().length, 4);
});

// Audit spec D17, §2.1 item 7: `goblin-admin key reset` writes its audit anchor, signed by the
// new audit key, in the unit that saves the new keys, so the reset and its anchor commit together.
test('reset inUnit: the anchor commits with the new keys, signed as keyring.hmac signs, or neither does', async t => {
  const control = openControl(temporary(t), { release: '1.5.0', env: {} });
  t.after(() => control.close());
  await control.migrate();
  const store = control.keyringStore;
  await Keyring.open(store, { key: keyA });
  const anchor = tx => metaOps.get(tx, 'test_anchor');
  let given = null;
  const { keyring } = await Keyring.reset(store, {
    key: keyB,
    confirmLostKey: true,
    inUnit(tx, { kid, mac }) {
      // Inside the save's unit: what it writes commits with the keys.
      metaOps.set(tx, 'test_anchor', mac('the anchor'), 1);
      given = { kid, mac, sample: mac('{"seq":1}'), unicode: mac('Grüße ✓') };
    },
  });
  assert.equal(given.kid, keyring.activeKid('audit'));
  assert.equal(given.sample, keyring.hmac('audit', '{"seq":1}').mac);
  assert.equal(given.unicode, keyring.hmac('audit', 'Grüße ✓', given.kid).mac);
  assert.equal(await control.db.read(anchor), keyring.hmac('audit', 'the anchor').mac);
  // The key it signed with is wiped once the save returned: a late MAC is refused, never zeros.
  assert.throws(() => given.mac('late'), TypeError);

  // An inUnit that throws rolls the unit back: the old keys stay and nothing it wrote remains.
  const before = await store.list();
  await assert.rejects(
    Keyring.reset(store, {
      key: keyA,
      confirmLostKey: true,
      inUnit(tx) {
        metaOps.set(tx, 'test_anchor', 'not kept', 2);
        throw new Error('the anchor could not be written');
      },
    }),
    /the anchor could not be written/
  );
  assert.deepEqual(await store.list(), before);
  assert.equal(await control.db.read(anchor), keyring.hmac('audit', 'the anchor').mac);
  assert.equal((await Keyring.open(store, { key: keyB })).activeKid('audit'), given.kid);
  await assert.rejects(Keyring.open(store, { key: keyA }), { code: 'key_mismatch' });
  await assert.rejects(
    Keyring.reset(store, { key: keyA, confirmLostKey: true, inUnit: 'no' }),
    TypeError
  );

  // The memory store keeps the same contract: inUnit(null) after the change, undone on a throw.
  const memory = memoryKeyringStore();
  await Keyring.open(memory, { key: keyA });
  const kept = memory.rows;
  await assert.rejects(
    Keyring.reset(memory, {
      key: keyB,
      confirmLostKey: true,
      inUnit(tx) {
        assert.equal(tx, null);
        assert.equal(memory.rows.length, 4, 'called after the change');
        assert.notDeepEqual(memory.rows, kept);
        throw new Error('refused');
      },
    }),
    /refused/
  );
  assert.deepEqual(memory.rows, kept);
  let memoryKid = null;
  const reset = await Keyring.reset(memory, {
    key: keyB,
    confirmLostKey: true,
    inUnit: (tx, { kid, mac }) => (memoryKid = [kid, mac('x')]),
  });
  assert.deepEqual(memoryKid, [
    reset.keyring.activeKid('audit'),
    reset.keyring.hmac('audit', 'x').mac,
  ]);
});

test('the memory store refuses unknown and duplicate keys', async () => {
  const store = memoryKeyringStore([{ kid: 'a', purpose: 'seal', wrapped: 'w', created_at: 1 }]);
  await assert.rejects(store.save({ rewrap: [{ kid: 'b', wrapped: 'x' }] }), /No key b/);
  await assert.rejects(store.save({ retire: [{ kid: 'b', retired_at: 1 }] }), /No key b/);
  await assert.rejects(
    store.save({ insert: [{ kid: 'a', purpose: 'seal', wrapped: 'w', created_at: 1 }] }),
    /Duplicate key a/
  );
  assert.equal((await store.list()).length, 1);
});

// Review of 9a7d6e5: the Compose check said COPY whenever /app/data/secret.key existed, but after
// a move to the Compose secret with `key rewrap` that file is the old key, and the copy recipe
// put it over the working orbit_secret_key (key_mismatch at every start). composeKeyChoice tries
// each key there is on the data instead (imported here, so that only this test fails without it).
test('composeKeyChoice: each key is tried on the data; a working Compose secret beside an older secret.key is KEEP, never COPY', async t => {
  const { composeKeyChoice } = await import('../lib/keyring.mjs');
  assert.equal(typeof composeKeyChoice, 'function', 'lib/keyring.mjs exports composeKeyChoice');
  const keyC = Buffer.from('e5'.repeat(16) + 'f6'.repeat(16), 'hex');
  const base = temporary(t);
  const directory = path.join(base, 'data');
  const { secretsDirectory } = sources(base);
  fs.mkdirSync(directory);
  fs.mkdirSync(secretsDirectory);
  const own = path.join(directory, secretKeyFile),
    secret = path.join(secretsDirectory, 'orbit_secret_key');
  const put = (file, key) => {
    fs.rmSync(file, { force: true });
    if (key) fs.writeFileSync(file, key.toString('hex') + '\n', { mode: 0o400 });
  };
  const choose = async (rows, { secretKey, volumeKey }) => {
    put(secret, secretKey);
    put(own, volumeKey);
    const before = fs.readdirSync(base, { recursive: true }).sort();
    const choice = await composeKeyChoice({ directory, secretsDirectory, rows });
    assert.deepEqual(fs.readdirSync(base, { recursive: true }).sort(), before, 'it only reads');
    return choice;
  };
  const print = key => keyFingerprint(key);

  // The reviewer's state: data sealed under A (generated in the volume), moved to the Compose
  // secret B with rewrap; A stays in the volume, and Uptime Goblin warns that it is not used.
  const moved = memoryKeyringStore();
  const sealed = (await Keyring.open(moved, { key: keyA })).sealText('seal', 'signing', 'ctx');
  await (await Keyring.open(moved, { key: keyB, previous: keyA })).rewrap();
  put(secret, keyB);
  put(own, keyA);
  const found = resolveKey({ ...sources(base), directory, keyringExists: true, env: {} });
  assert.equal(found.source, 'secrets');
  assert.ok(
    found.warnings.some(warning =>
      warning.includes('is an older key, which Uptime Goblin does not use')
    )
  );
  assert.equal(
    (await Keyring.open(moved, { key: found.key })).openText('seal', sealed, 'ctx'),
    'signing'
  );
  const keep = await choose(moved.rows, { secretKey: keyB, volumeKey: keyA });
  assert.equal(keep.verdict, 'KEEP');
  assert.deepEqual([keep.secret, keep.volume], [print(keyB), print(keyA)]);
  // A67: the older key beside it is named as such, with the line that deletes it (the check said
  // only that Uptime Goblin does not use it, and compose.secret.yaml "keep that file").
  assert.equal(
    keep.reason,
    `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(keyB)}) opens this data: keep orbit_secret_key and COMPOSE_FILE, make no key and copy none. ${own} (fingerprint ${print(keyA)}) is there too: an older key, which Uptime Goblin does not use and which opens none of this data's keys (as after key rewrap). Every copy of the volume carries it: once Uptime Goblin runs with orbit_secret_key (COMPOSE_FILE in .env, then docker compose up -d), the line below deletes it, only while Uptime Goblin's key opens every data key and that file opens none.`
  );
  assert.equal(
    keep.command,
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused'
  );
  const alone = await choose(moved.rows, { secretKey: keyB });
  assert.deepEqual(
    [alone.verdict, alone.reason, alone.command],
    [
      'KEEP',
      `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(keyB)}) opens this data: keep orbit_secret_key and COMPOSE_FILE, make no key and copy none.`,
      null,
    ]
  );
  // Without the secret's file, or with another key in it, the old key in the volume is no answer.
  const restore = await choose(moved.rows, { volumeKey: keyA });
  assert.equal(restore.verdict, 'RESTORE');
  assert.match(
    restore.reason,
    /^No key here opens this data \(.+ does not\): make no key and copy none\. Put back the orbit_secret_key the data was sealed with/
  );
  assert.equal((await choose(moved.rows, { secretKey: keyC, volumeKey: keyA })).verdict, 'RESTORE');
  assert.equal((await choose(moved.rows, {})).verdict, 'RESTORE');

  // Data sealed with the key 1.5 generated in the volume (it ran without compose.secret.yaml).
  const generated = memoryKeyringStore();
  await Keyring.open(generated, { key: keyA });
  const copy = await choose(generated.rows, { volumeKey: keyA });
  assert.equal(copy.verdict, 'COPY');
  assert.equal(copy.secret, null);
  // A new key made for that volume by mistake: set it aside, never copy over it blindly.
  const move = await choose(generated.rows, { secretKey: keyC, volumeKey: keyA });
  assert.equal(move.verdict, 'MOVE');
  assert.equal(
    move.reason,
    `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(keyC)}) does not open this data, and ${own} (fingerprint ${print(keyA)}) does: take the MOVE recipe of compose.secret.yaml, which puts that key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused, then start Uptime Goblin with docker compose up -d --force-recreate.`
  );
  // After the copy, before the volume's copy is deleted: the same key in both, KEEP, with the
  // copy recipe's last line.
  const copied = await choose(generated.rows, { secretKey: keyA, volumeKey: keyA });
  assert.equal(copied.verdict, 'KEEP');
  assert.equal(
    copied.reason,
    `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(keyA)}) opens this data: keep orbit_secret_key and COMPOSE_FILE, make no key and copy none. ${own} (fingerprint ${print(keyA)}) is there too, a copy of that key. Every copy of the volume carries it: once Uptime Goblin runs with orbit_secret_key (COMPOSE_FILE in .env, then docker compose up -d), the line below deletes it, only while Uptime Goblin's key is the Compose secret, holding the same key, and opens the data.`
  );
  assert.equal(
    copied.command,
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy'
  );
  for (const other of [move, copy, restore]) assert.equal(other.command, null, other.verdict);

  // Nothing sealed yet: a new key, or the one Uptime Goblin generated; an orbit_secret_key is kept.
  assert.equal((await choose([], {})).verdict, 'NEW');
  assert.equal((await choose([], { secretKey: keyB })).verdict, 'NEW');
  assert.equal((await choose([], { secretKey: keyB, volumeKey: keyA })).verdict, 'NEW');
  assert.equal((await choose([], { volumeKey: keyA })).verdict, 'COPY');

  // A key file it cannot read as a key: nothing is compared, and the error says so.
  put(own, null);
  fs.writeFileSync(secret, '', { mode: 0o600 });
  await assert.rejects(
    composeKeyChoice({ directory, secretsDirectory, rows: moved.rows }),
    error => {
      assert.equal(error.code, 'key_invalid');
      assert.match(
        error.message,
        /Nothing was compared: make no key and copy none until this check can read it as a key\.$/
      );
      return true;
    }
  );
  if (process.getuid?.() !== 0) {
    fs.writeFileSync(secret, keyB.toString('hex') + '\n', { mode: 0o600 });
    fs.chmodSync(secret, 0o000);
    await assert.rejects(
      composeKeyChoice({ directory, secretsDirectory, rows: moved.rows }),
      error => {
        assert.equal(error.code, 'key_file_unreadable');
        assert.match(
          error.message,
          /cannot be read: EACCES\. Nothing was compared: .* \(on a Linux host, uid 1000 must be able to read it: sudo chown 1000 orbit_secret_key\)\.$/
        );
        return true;
      }
    );
    fs.chmodSync(secret, 0o600);
  }
});

// A66: removeDataKeyCopy, which `goblin-admin key remove-data-copy` runs (test/db/cli.test.mjs
// covers the command), deletes <data>/secret.key only while the key found where Uptime Goblin runs comes
// from another file, opens the data and is the same key. Here, what a command cannot set up: the
// source's file gone after it was read, and a found key that is not the file's.
test('removeDataKeyCopy: deletes the data directory key only as a copy of a key that opens the data, and never when the source changed', async t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  fs.mkdirSync(secretsDirectory);
  const secret = path.join(secretsDirectory, 'orbit_secret_key');
  const store = memoryKeyringStore();
  await Keyring.open(store, { key: keyA });
  const rows = await store.list();
  const find = () =>
    resolveKey({ env: {}, directory, credentialsDirectory, secretsDirectory, keyringExists: true });
  fs.writeFileSync(own, `${hex}\n`, { mode: 0o600 });
  fs.writeFileSync(secret, `${hex}\n`, { mode: 0o400 });
  // The secret's file is gone once it was read (a host file deleted under its mount): no answer,
  // and the answer names that file, not <data>/secret.key, which did not change.
  let found = find();
  fs.rmSync(secret);
  assert.deepEqual(await removeDataKeyCopy({ directory, found, rows }), {
    deleted: false,
    code: 'source_changed',
    file: own,
    fingerprint: keyFingerprint(keyA),
    source: secret,
  });
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
  // Without rows nothing is checked, so nothing goes.
  fs.writeFileSync(secret, `${hex}\n`, { mode: 0o400 });
  found = find();
  assert.equal((await removeDataKeyCopy({ directory, found, rows: [] })).code, 'no_keyring');
  // No key found at all, and the data-directory key itself.
  assert.equal((await removeDataKeyCopy({ directory, found: null, rows })).code, 'data_directory');
  fs.rmSync(secret);
  assert.equal(
    (await removeDataKeyCopy({ directory, found: find(), rows })).code,
    'data_directory'
  );
  // The copy: deleted, and only that file.
  fs.writeFileSync(secret, `${hex}\n`, { mode: 0o400 });
  assert.deepEqual(await removeDataKeyCopy({ directory, found: find(), rows }), {
    deleted: true,
    file: own,
    fingerprint: keyFingerprint(keyA),
  });
  assert.deepEqual(fs.readdirSync(directory), []);
  assert.equal(fs.readFileSync(secret, 'utf8'), `${hex}\n`);
  assert.equal((await removeDataKeyCopy({ directory, found: find(), rows })).code, 'none');
  // A source file deleted while it is still open (a Linux bind mount of a host file deleted under
  // it keeps its inode the same way): no lasting copy, never taken for one. Linux only: the open
  // file is reached through /proc/self/fd. That needs a filesystem that keeps a deleted file
  // still open reachable there, as ext4, overlayfs and tmpfs do. A FUSE or virtiofs mount does
  // not (TMPDIR bind-mounted into an OrbStack or Docker Desktop container): the kernel asks the
  // host, which no longer has the file, so stat fails with ENOENT and removeDataKeyCopy answers
  // 'source_changed', as for the secret deleted above, and keeps the file either way. So the source is
  // made in the temporary directory if it keeps such a file reachable, else on /dev/shm (tmpfs).
  // A subtest registered on Linux only (test/platform-manifest.json).
  await platformSubtest(
    t,
    import.meta.url,
    'keyring.remove-copy.deleted-open-file',
    'on Linux: a source deleted while it is still open is never taken for a lasting copy',
    {},
    async () => {
      fs.writeFileSync(own, `${hex}\n`, { mode: 0o600 });
      const tried = [];
      let held = null,
        mounted = null;
      for (const parent of [base, '/dev/shm']) {
        if (!fs.existsSync(parent)) {
          tried.push(`${parent}: missing`);
          continue;
        }
        const mount = fs.mkdtempSync(path.join(parent, 'orbit-keyring-mount-'));
        t.after(() => fs.rmSync(mount, { recursive: true, force: true }));
        const source = path.join(mount, 'orbit_secret_key');
        fs.writeFileSync(source, `${hex}\n`, { mode: 0o400 });
        const descriptor = fs.openSync(source, 'r');
        mounted = resolveKey({
          env: {},
          directory,
          credentialsDirectory,
          secretsDirectory: mount,
          keyringExists: true,
        });
        fs.rmSync(source);
        try {
          const { nlink } = fs.statSync(`/proc/self/fd/${descriptor}`, { bigint: true });
          if (nlink === 0n) {
            held = descriptor;
            break;
          }
          tried.push(`${parent}: nlink ${nlink}`);
        } catch (error) {
          tried.push(`${parent}: ${error.code}`);
        }
        fs.closeSync(descriptor);
      }
      assert.ok(
        held !== null,
        `no directory here keeps a deleted, open file reachable through /proc/self/fd (${tried.join('; ')})`
      );
      try {
        assert.equal(mounted.source, 'secrets');
        assert.deepEqual(
          await removeDataKeyCopy({
            directory,
            found: { ...mounted, file: `/proc/self/fd/${held}` },
            rows,
          }),
          { deleted: false, code: 'gone', file: own, fingerprint: keyFingerprint(keyA) }
        );
        assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
      } finally {
        fs.closeSync(held);
      }
    }
  );
});

// A source's file deleted, or given another key, after a stat of it: the copy is kept. On a FUSE or
// virtiofs bind mount (a host's file in an OrbStack or Docker Desktop container), a stat still
// shows a file the host deleted, with its link, for tens of milliseconds, while opening it fails at
// once: measured on OrbStack, a key deleted on the host between the command's lookup and its
// check had the data directory's copy deleted 10 times in 10. Here the stub shows the source as
// such a stat does; removeDataKeyCopy opens it again just before the deletion.
test('removeDataKeyCopy: keeps the copy when the source no longer holds the key, though a stat still shows it (a FUSE or virtiofs bind mount)', async t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  fs.mkdirSync(secretsDirectory);
  const secret = path.join(secretsDirectory, 'orbit_secret_key');
  const store = memoryKeyringStore();
  await Keyring.open(store, { key: keyA });
  const rows = await store.list();
  const find = () =>
    resolveKey({ env: {}, directory, credentialsDirectory, secretsDirectory, keyringExists: true });
  const kept = {
    deleted: false,
    code: 'source_changed',
    file: own,
    fingerprint: keyFingerprint(keyA),
    source: secret,
  };
  const { statSync } = fs;
  // `change` runs between the lookup and the check, while every stat of the source shows it as
  // it was at the lookup.
  const removal = async change => {
    fs.writeFileSync(own, `${hex}\n`, { mode: 0o600 });
    fs.rmSync(secret, { force: true });
    fs.writeFileSync(secret, `${hex}\n`, { mode: 0o600 });
    const found = find();
    assert.equal(found.source, 'secrets');
    const shown = statSync(secret, { bigint: true });
    change();
    const stat = t.mock.method(fs, 'statSync', (file, options) =>
      file === secret ? shown : statSync(file, options)
    );
    try {
      return await removeDataKeyCopy({ directory, found, rows });
    } finally {
      assert.ok(stat.mock.calls.some(call => call.arguments[0] === secret));
      stat.mock.restore();
    }
  };
  // Deleted on the host: kept, and so is the copy.
  assert.deepEqual(await removal(() => fs.rmSync(secret)), kept);
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
  // Given another key in place (the same file), or replaced by another file (renamed over it),
  // which is not the file checked, even holding the same key.
  assert.deepEqual(
    await removal(() => fs.writeFileSync(secret, `${keyB.toString('hex')}\n`)),
    kept
  );
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
  assert.deepEqual(
    await removal(() => {
      fs.writeFileSync(`${secret}.new`, `${hex}\n`, { mode: 0o600 });
      fs.renameSync(`${secret}.new`, secret);
    }),
    kept
  );
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
  // Unchanged: the copy goes.
  assert.deepEqual(await removal(() => {}), {
    deleted: true,
    file: own,
    fingerprint: keyFingerprint(keyA),
  });
  assert.deepEqual(fs.readdirSync(directory), []);
});

// The source's file renamed over, at its last check, by a FIFO: removeDataKeyCopy opened it
// with a plain open, which waits for a writer before fstat can refuse it, so the command hung
// (the copy was kept, but the command never answered). It runs in a child, since a blocked open
// blocks the whole process, which is killed if it does not answer in time. The child renames the
// replacement over the source's file just as removeDataKeyCopy opens it again, after every
// other check, and then lets that open run on the real filesystem.
const swapChild = `
import fs from 'node:fs';
import path from 'node:path';
const [keyring, base, mode] = process.argv.slice(1);
const { Keyring, memoryKeyringStore, resolveKey, removeDataKeyCopy } = await import(keyring);
const directory = path.join(base, 'data');
const secretsDirectory = path.join(base, 'secrets');
const source = path.join(secretsDirectory, 'orbit_secret_key');
const key = Buffer.from(fs.readFileSync(path.join(base, 'key'), 'utf8').trim(), 'hex');
const store = memoryKeyringStore();
await Keyring.open(store, { key });
const rows = await store.list();
const found = resolveKey({
  env: {},
  directory,
  secretsDirectory,
  credentialsDirectory: path.join(base, 'credentials'),
  keyringExists: true,
});
const open = fs.openSync;
let opens = 0,
  held;
fs.openSync = function (file, ...rest) {
  if (file !== source) return open(file, ...rest);
  opens += 1;
  if (mode !== 'none') fs.renameSync(path.join(base, 'replacement'), source);
  fs.writeFileSync(path.join(base, 'reached'), mode);
  held = open(file, ...rest);
  return held;
};
const result = await removeDataKeyCopy({ directory, found, rows });
fs.openSync = open;
let closed = held === undefined;
try {
  if (!closed) fs.fstatSync(held);
} catch (error) {
  closed = error.code === 'EBADF';
}
process.stdout.write(JSON.stringify({ found: found.source, opens, result, closed }));
`;

test('removeDataKeyCopy: a source replaced by a FIFO at its last check is refused at once, never waited on; an ordinary replacement is refused too', t => {
  const keyring = new URL('../lib/keyring.mjs', import.meta.url).href;
  const run = mode => {
    const base = temporary(t);
    const directory = path.join(base, 'data');
    const secretsDirectory = path.join(base, 'secrets');
    fs.mkdirSync(directory);
    fs.mkdirSync(secretsDirectory);
    const own = path.join(directory, secretKeyFile);
    const secret = path.join(secretsDirectory, 'orbit_secret_key');
    const replacement = path.join(base, 'replacement');
    fs.writeFileSync(path.join(base, 'key'), `${hex}\n`, { mode: 0o600 });
    fs.writeFileSync(own, `${hex}\n`, { mode: 0o600 });
    fs.writeFileSync(secret, `${hex}\n`, { mode: 0o400 });
    if (mode === 'fifo') {
      const made = spawnSync('mkfifo', [replacement], { encoding: 'utf8' });
      assert.equal(made.status, 0, made.stderr);
    } else if (mode === 'file') {
      // Another key: a new file that reused the old one's inode number would still be refused.
      fs.writeFileSync(replacement, `${keyB.toString('hex')}\n`, { mode: 0o400 });
    }
    const child = spawnSync(
      process.execPath,
      ['--input-type=module', '--eval', swapChild, keyring, base, mode],
      { encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL' }
    );
    const reached = fs.existsSync(path.join(base, 'reached'));
    assert.ok(
      child.status === 0 && child.error === undefined,
      `the command must answer by itself (${mode}; replacement put in place at the last check: ${reached}): ${child.error?.code ?? `status ${child.status}`}, signal ${child.signal}, ${child.stderr}`
    );
    assert.equal(reached, true, `${mode}: the last check opened the source`);
    return { ...JSON.parse(child.stdout), own, secret };
  };
  const kept = (own, secret) => ({
    deleted: false,
    code: 'source_changed',
    file: own,
    fingerprint: keyFingerprint(keyA),
    source: secret,
  });

  // The FIFO: refused at once, the copy kept, the descriptor closed, the FIFO left as it is.
  const fifo = run('fifo');
  assert.equal(fifo.found, 'secrets');
  assert.equal(fifo.opens, 1);
  assert.deepEqual(fifo.result, kept(fifo.own, fifo.secret));
  assert.equal(fifo.closed, true, 'the FIFO descriptor is closed');
  assert.equal(fs.readFileSync(fifo.own, 'utf8'), `${hex}\n`);
  assert.ok(fs.lstatSync(fifo.secret).isFIFO());

  // An ordinary file with another key renamed over it at the same moment: refused as well.
  const file = run('file');
  assert.equal(file.opens, 1);
  assert.deepEqual(file.result, kept(file.own, file.secret));
  assert.equal(file.closed, true);
  assert.equal(fs.readFileSync(file.own, 'utf8'), `${hex}\n`);

  // Nothing replaced: the same open reads the key, and the copy goes.
  const none = run('none');
  assert.equal(none.opens, 1);
  assert.deepEqual(none.result, {
    deleted: true,
    file: none.own,
    fingerprint: keyFingerprint(keyA),
  });
  assert.equal(none.closed, true);
  assert.equal(fs.existsSync(none.own), false);
  assert.equal(fs.readFileSync(none.secret, 'utf8'), `${hex}\n`);
});

// A67: after `key rewrap` moved the data from A (generated in the data directory) to B, A stays
// in <data>/secret.key: an older key Uptime Goblin does not use, which every copy of the data directory
// carries. removeDataKeyCopy kept it on purpose (it is no copy), and nothing else deleted it
// safely. With `unused` it goes only while the key Uptime Goblin is given (another source) opens every
// data key and the file holds another key that opens none; never the key in use, a copy, a key a
// data key still needs, or the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names.
test('removeDataKeyCopy unused: deletes an older key that opens none of the data keys, only while the key Uptime Goblin is given opens them all', async t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  fs.mkdirSync(secretsDirectory);
  const secret = path.join(secretsDirectory, 'orbit_secret_key');
  const keyC = Buffer.from('e5'.repeat(16) + 'f6'.repeat(16), 'hex');
  const put = (file, key, mode = 0o600) => {
    fs.rmSync(file, { force: true });
    if (key) fs.writeFileSync(file, `${key.toString('hex')}\n`, { mode });
  };
  const find = (env = {}, extra = {}) =>
    resolveKey({
      env,
      directory,
      credentialsDirectory,
      secretsDirectory,
      keyringExists: true,
      ...extra,
    });
  const remove = (found, rows, extra = {}) =>
    removeDataKeyCopy({ directory, found, rows, unused: true, ...extra });
  const code = async (...args) => (await remove(...args)).code;
  // Data sealed under A, the generated key.
  const store = memoryKeyringStore();
  await Keyring.open(store, { key: keyA });
  put(own, keyA);
  put(secret, keyB, 0o400);
  // The key change is not finished: B opens no data key (with A as the previous key, Uptime Goblin
  // starts, but rewrap has not run). A is still the key the data needs.
  const unfinished = find({ GOBLIN_SECRET_KEY_PREVIOUS_FILE: own });
  assert.equal(await code(unfinished, await store.list()), 'not_opening');
  assert.equal(await code(find(), await store.list()), 'not_opening');
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`);
  // After key rewrap (B wraps every data key; A opens none).
  await (await Keyring.open(store, { key: keyB, previous: keyA })).rewrap();
  const rows = await store.list();
  // The copy mode keeps it, and says --unused would take it.
  const different = await removeDataKeyCopy({ directory, found: find(), rows });
  assert.deepEqual(
    [different.code, different.theirs, different.opensNone],
    ['different', keyFingerprint(keyA), true]
  );
  // Never the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names (Uptime Goblin reads it at every start): by its
  // path, a symbolic link, a hard link; in both modes.
  const link = path.join(base, 'previous-link.key'),
    hard = path.join(base, 'previous-hard.key');
  fs.symlinkSync(own, link);
  fs.linkSync(own, hard);
  for (const previousFile of [own, link, hard]) {
    const found = find({ GOBLIN_SECRET_KEY_PREVIOUS_FILE: previousFile });
    assert.equal(await code(found, rows, { previousFile }), 'previous_file', previousFile);
    assert.equal(
      (await removeDataKeyCopy({ directory, found, rows, previousFile })).code,
      'previous_file',
      previousFile
    );
  }
  fs.rmSync(link);
  fs.rmSync(hard);
  // Nor while that file cannot be found: it names the file, which is not <data>/secret.key.
  const missing = path.join(base, 'previous-missing.key');
  for (const extra of [{}, { unused: true }])
    assert.deepEqual(
      await removeDataKeyCopy({ directory, found: find(), rows, previousFile: missing, ...extra }),
      {
        deleted: false,
        code: 'previous_changed',
        file: own,
        fingerprint: keyFingerprint(keyB),
        source: missing,
      }
    );
  // Never the key in use: no other source, or a source that is that file.
  put(secret, null);
  assert.equal(await code(find(), rows), 'data_directory');
  assert.equal(await code(null, rows), 'data_directory');
  assert.equal(await code(find({ GOBLIN_SECRET_KEY_FILE: own }), rows), 'same_file');
  // Never a copy: the same key in both (the copy mode takes it).
  put(secret, keyA, 0o400);
  put(own, keyA);
  const copy = find();
  assert.equal(await code(copy, (await memoryKeyringStoreFor(keyA)).rows), 'copy');
  // A Compose secret that does not open the data: the volume's key may be the one that does.
  put(secret, keyC, 0o400);
  assert.equal(await code(find(), rows), 'not_opening');
  // No keyring: nothing tells.
  put(secret, keyB, 0o400);
  assert.equal(await code(find(), []), 'no_keyring');
  assert.equal(fs.readFileSync(own, 'utf8'), `${hex}\n`, 'every refusal kept it');
  // The older key goes, and only it: B, the Compose secret, opens every data key, and A none.
  assert.deepEqual(await remove(find(), rows), {
    deleted: true,
    file: own,
    fingerprint: keyFingerprint(keyB),
    theirs: keyFingerprint(keyA),
  });
  assert.deepEqual(fs.readdirSync(directory), []);
  assert.equal(fs.readFileSync(secret, 'utf8'), `${keyB.toString('hex')}\n`);
  assert.equal(await code(find(), rows), 'none');
  // GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE outside and a systemd credential holding B are other
  // sources too: a credential that holds another key does not come from that file.
  put(secret, null);
  const outside = path.join(base, 'b.key');
  put(outside, keyB);
  fs.mkdirSync(credentialsDirectory);
  const credential = path.join(credentialsDirectory, 'orbit-secret-key');
  for (const [env, label] of [
    [{ GOBLIN_SECRET_KEY: keyB.toString('hex') }, 'env'],
    [{ GOBLIN_SECRET_KEY_FILE: outside }, 'file'],
    [{}, 'credentials'],
  ]) {
    if (label === 'credentials') put(credential, keyB, 0o400);
    put(own, keyA);
    const found = find(env);
    assert.equal(found.source, label);
    assert.equal((await remove(found, rows)).deleted, true, label);
    assert.equal(fs.existsSync(own), false, label);
  }
  // A credential holding the same key may be loaded from that very file: kept.
  put(own, keyB);
  assert.equal(await code(find(), rows), 'credential');
  assert.equal(fs.readFileSync(own, 'utf8'), `${keyB.toString('hex')}\n`);
});

// A keyring sealed under `key`, for the cases above that need one of their own.
async function memoryKeyringStoreFor(key) {
  const store = memoryKeyringStore();
  await Keyring.open(store, { key });
  return { rows: await store.list() };
}

// A67: a <data>/secret.key that GOBLIN_SECRET_KEY_PREVIOUS_FILE names is read at every start (a
// missing one refuses it), so the start warning never gives a line that deletes it.
test('a <data>/secret.key that GOBLIN_SECRET_KEY_PREVIOUS_FILE names is never given a line that deletes it', t => {
  const base = temporary(t);
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  const own = path.join(directory, secretKeyFile);
  const { credentialsDirectory, secretsDirectory } = sources(base);
  fs.writeFileSync(own, `${hex}\n`, { mode: 0o600 });
  const link = path.join(base, 'previous.key');
  fs.symlinkSync(own, link);
  for (const previous of [own, link]) {
    const found = resolveKey({
      env: { GOBLIN_SECRET_KEY: keyB.toString('hex'), GOBLIN_SECRET_KEY_PREVIOUS_FILE: previous },
      directory,
      credentialsDirectory,
      secretsDirectory,
      keyringExists: true,
    });
    assert.deepEqual(found.warnings, [
      `${own} is the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names, which Uptime Goblin reads at every start, so deleting it would stop Uptime Goblin from starting; the key comes from GOBLIN_SECRET_KEY (fingerprint ${keyFingerprint(keyB)}). Once every data key opens with that key (goblin-admin key rewrap), remove GOBLIN_SECRET_KEY_PREVIOUS_FILE and start Uptime Goblin again: this warning then gives the line that deletes ${own}; every copy of the data directory carries it.`,
    ]);
    assert.deepEqual(found.previous, keyA);
  }
});

test('a key file that is a FIFO, or a symbolic link to one, refuses the start promptly; one that grows past the limit too', t => {
  const keyring = new URL('../lib/keyring.mjs', import.meta.url).href;
  // Every way a key file is named: GOBLIN_SECRET_KEY_FILE, its previous key, the systemd
  // credential, the Compose secret and the data directory's own secret.key. Each may be a link
  // (a credential or a secret often is), which is followed: to a FIFO, it is refused the same way.
  for (const linked of [false, true])
    for (const where of ['file', 'previous', 'credential', 'secret', 'own']) {
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        { credentialsDirectory, secretsDirectory } = sources(directory);
      fs.mkdirSync(data);
      fs.mkdirSync(credentialsDirectory);
      fs.mkdirSync(secretsDirectory);
      const entry = {
        file: path.join(directory, 'key.fifo'),
        previous: path.join(directory, 'previous.fifo'),
        credential: path.join(credentialsDirectory, 'orbit-secret-key'),
        secret: path.join(secretsDirectory, 'orbit_secret_key'),
        own: path.join(data, secretKeyFile),
      }[where];
      const fifo = linked ? path.join(directory, 'target.fifo') : entry;
      const label = `${where}${linked ? ' (a link to a FIFO)' : ''}`;
      assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
      if (linked) fs.symlinkSync(fifo, entry);
      const env = {
        ...(where === 'file' ? { GOBLIN_SECRET_KEY_FILE: entry } : {}),
        ...(where === 'previous'
          ? { GOBLIN_SECRET_KEY: hex, GOBLIN_SECRET_KEY_PREVIOUS_FILE: entry }
          : {}),
      };
      // In a child with a deadline: a blocking open would hang this process for good.
      const child = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import assert from 'node:assert/strict';
           import { resolveKey, KeyError } from ${JSON.stringify(keyring)};
           const [env, directory, credentialsDirectory, secretsDirectory, entry] = JSON.parse(process.argv[1]);
           assert.throws(
             () => resolveKey({ env, directory, credentialsDirectory, secretsDirectory, keyringExists: true }),
             error => error instanceof KeyError && error.code === 'key_file_unreadable' && error.message.endsWith(\`(\${entry}) is not a file.\`)
           );`,
          JSON.stringify([env, data, credentialsDirectory, secretsDirectory, entry]),
        ],
        { encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' }
      );
      assert.equal(child.error, undefined, `${label}: the start must return before the deadline`);
      assert.equal(child.status, 0, `${label}: ${child.stderr}`);
      assert.ok(fs.statSync(fifo).isFIFO(), `${label}: the FIFO is left as it was`);
      if (linked) assert.ok(fs.lstatSync(entry).isSymbolicLink(), `${label}: so is the link`);
    }
  // A key file that grows after it was inspected is read no further than the limit.
  const directory = temporary(t),
    file = path.join(directory, 'key');
  fs.writeFileSync(file, hex, { mode: 0o600 });
  const stat = fs.fstatSync;
  t.mock.method(fs, 'fstatSync', (descriptor, ...rest) => {
    const result = stat(descriptor, ...rest);
    if (!rest.length) fs.writeFileSync(file, hex.padEnd(8192, ' '));
    return result;
  });
  assert.throws(
    () => resolveKey({ env: { GOBLIN_SECRET_KEY_FILE: file }, directory, ...sources(directory) }),
    error => error instanceof KeyError && /too large to hold a key/.test(error.message)
  );
});

test('a FIFO as <data>/secret.key beside the key in use, or as the Compose secret, is never waited on: the start warning, the key_mismatch note and the Compose check', t => {
  const keyring = new URL('../lib/keyring.mjs', import.meta.url).href;
  // <data>/secret.key is read again where another source wins (the start's warning), where that
  // source does not open the data (the refusal's note) and by the check of compose.secret.yaml,
  // which reads the Compose secret first.
  for (const linked of [false, true]) {
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      { secretsDirectory } = sources(directory),
      // Where no credential and no Compose secret is.
      none = path.join(directory, 'none'),
      own = path.join(data, secretKeyFile),
      secret = path.join(secretsDirectory, 'orbit_secret_key'),
      fifo = file => (linked ? `${file}.fifo` : file),
      label = linked ? 'links to FIFOs' : 'FIFOs';
    fs.mkdirSync(data);
    fs.mkdirSync(secretsDirectory);
    for (const file of [own, secret]) {
      assert.equal(spawnSync('mkfifo', [fifo(file)]).status, 0);
      if (linked) fs.symlinkSync(fifo(file), file);
    }
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import assert from 'node:assert/strict';
         import { resolveKey, dataDirectoryKeyNote, composeKeyChoice, KeyError } from ${JSON.stringify(keyring)};
         const [hex, directory, none, secretsDirectory, own, secret, linked] = JSON.parse(process.argv[1]);
         const found = resolveKey({ env: { GOBLIN_SECRET_KEY: hex }, directory, credentialsDirectory: none, secretsDirectory, keyringExists: true });
         assert.equal(found.source, 'env');
         // A link there is never read (Uptime Goblin does not use it); a FIFO is read without waiting.
         const warning = linked ? \`\${own} is a symbolic link, which Uptime Goblin does not use:\` : \`\${own} (which could not be read) is not used:\`;
         assert.ok(found.warnings.some(text => text.startsWith(warning)), found.warnings.join('\\n'));
         assert.equal(
           await dataDirectoryKeyNote({ directory, found, rows: [] }),
           \`\${own} is in the data directory too, and may be the key that opens this data, but it could not be read: The data-directory key (\${own}) is not a file.\`
         );
         await assert.rejects(
           composeKeyChoice({ directory, secretsDirectory, rows: [] }),
           error => error instanceof KeyError && error.message.startsWith(\`The Compose secret (\${secret}) is not a file. Nothing was compared:\`)
         );
         await assert.rejects(
           composeKeyChoice({ directory, secretsDirectory: none, rows: [] }),
           error => error instanceof KeyError && error.message.startsWith(\`The data-directory key (\${own}) is not a file. Nothing was compared:\`)
         );`,
        JSON.stringify([hex, data, none, secretsDirectory, own, secret, linked]),
      ],
      { encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' }
    );
    assert.equal(child.error, undefined, `${label}: each read must return before the deadline`);
    assert.equal(child.status, 0, `${label}: ${child.stderr}`);
    for (const file of [own, secret]) {
      assert.ok(fs.statSync(fifo(file)).isFIFO(), `${label}: ${file} is left as it was`);
      assert.equal(fs.lstatSync(file).isSymbolicLink(), linked);
    }
  }
});
