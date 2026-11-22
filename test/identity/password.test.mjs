// Passwords and auth.json I/O (lib/identity/password.mjs, sessions spec §5.8): 1.4.3's record,
// pool, validation and file rules, re-created here from test/auth.test.mjs and
// test/hardening.test.mjs when PasswordAuth moved into identity.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, scryptSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  scryptParameters,
  validRecord,
  canonicalRecord,
  authRecordBytes,
  createHasher,
  makeRecord,
  verifyRecord,
  verifyDummy,
  checkNewPassword,
  checkBootstrapPassword,
  readAuthRecord,
  tightenAuthRecord,
  writeAuthRecord,
} from '../../lib/identity/password.mjs';
import {
  temporary,
  fakeKey,
  fakeRecord,
  writeAuthJson,
  countingDerive,
  traceDurability,
} from './helpers.mjs';

const secret = 'fixture-bootstrap-password';
const changed = 'a different fixture password';
const settle = () => new Promise(resolve => setImmediate(resolve));
const code = expected => error => error.code === expected;
const mode = file => fs.statSync(file).mode & 0o777;

test('records are 1.4.3 v1 scrypt records with OWASP parameters, derived by real scrypt', async () => {
  assert.deepEqual(scryptParameters, { N: 32768, r: 8, p: 3, keyLength: 64 });
  const hasher = createHasher();
  const record = await makeRecord(hasher, secret, 1790000000000);
  assert.deepEqual(Object.keys(record), [
    'version',
    'algorithm',
    'parameters',
    'salt',
    'hash',
    'passwordChangedAt',
  ]);
  assert.deepEqual(record.parameters, { N: 32768, r: 8, p: 3, keyLength: 64 });
  assert.equal(record.version, 1);
  assert.equal(record.algorithm, 'scrypt');
  assert.match(record.salt, /^[a-f0-9]{64}$/);
  assert.match(record.hash, /^[a-f0-9]{128}$/);
  assert.equal(record.passwordChangedAt, 1790000000000);
  assert.ok(validRecord(record));
  // The same derivation 1.4.3 ran, so either release verifies what the other wrote.
  const expected = scryptSync(Buffer.from(secret), Buffer.from(record.salt, 'hex'), 64, {
    N: 32768,
    r: 8,
    p: 3,
    maxmem: 64 * 1024 * 1024,
  });
  assert.equal(record.hash, expected.toString('hex'));
  assert.equal(await verifyRecord(hasher, record, Buffer.from(secret)), true);
  assert.equal(await verifyRecord(hasher, record, Buffer.from(changed)), false);
  const again = await makeRecord(hasher, secret, 1790000000000);
  assert.notEqual(again.salt, record.salt, 'a fresh salt every time');
  // The serialised form is 1.4.3's, whatever key order the input had.
  const shuffled = { hash: record.hash, salt: record.salt, passwordChangedAt: 5, ...record };
  assert.equal(
    authRecordBytes(shuffled).toString(),
    JSON.stringify({
      version: 1,
      algorithm: 'scrypt',
      parameters: { N: 32768, r: 8, p: 3, keyLength: 64 },
      salt: record.salt,
      hash: record.hash,
      passwordChangedAt: record.passwordChangedAt,
    }) + '\n'
  );
  assert.deepEqual(canonicalRecord(shuffled), record);
});

test('validRecord refuses anything but a v1 record with these parameters', () => {
  const good = fakeRecord(secret);
  assert.equal(validRecord(good), true);
  for (const bad of [
    null,
    [],
    'text',
    {},
    { ...good, version: 2 },
    { ...good, algorithm: 'argon2id' },
    { ...good, parameters: { N: 1, r: 8, p: 3, keyLength: 64 } },
    { ...good, salt: 'AB'.repeat(32) },
    { ...good, salt: 'ab' },
    { ...good, hash: 'ab'.repeat(63) },
    { ...good, passwordChangedAt: 0 },
    { ...good, passwordChangedAt: 1.5 },
    { ...good, passwordChangedAt: '123456' },
  ])
    assert.equal(validRecord(bad), false, JSON.stringify(bad));
});

test('a wrong login name costs one derivation of the same kind (verifyDummy), and never matches', async () => {
  const derive = countingDerive();
  const hasher = createHasher({ derive });
  assert.equal(await verifyDummy(hasher, Buffer.from(secret)), false);
  assert.equal(derive.calls, 1);
  // An unusable record never matches either, and costs the same.
  assert.equal(await verifyRecord(hasher, { version: 9 }, Buffer.from(secret)), false);
  assert.equal(derive.calls, 2);
  assert.equal(await verifyRecord(hasher, fakeRecord(secret), Buffer.from(secret)), true);
  assert.equal(derive.calls, 3);
});

test('the hasher runs 2 derivations, queues 16 for 5 s in order, then refuses as busy (queue)', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const derive = countingDerive();
  derive.hold();
  const hasher = createHasher({ derive });
  const order = [];
  const jobs = Array.from({ length: 18 }, (_, index) =>
    hasher.hash(Buffer.from('p' + index), Buffer.alloc(32)).then(
      () => order.push(index),
      error => order.push(`refused ${index}: ${error.code}/${error.scope}`)
    )
  );
  await settle();
  assert.equal(hasher.active, 2);
  assert.equal(hasher.waiting, 16);
  assert.equal(derive.calls, 2);
  // Beyond the queue: refused at once, with no derivation.
  await assert.rejects(hasher.hash(Buffer.from('one too many'), Buffer.alloc(32)), error => {
    assert.equal(error.code, 'busy');
    assert.equal(error.scope, 'queue');
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, 5);
    return true;
  });
  assert.equal(derive.calls, 2);
  // Releasing the two running hands their slots to the first waiters, in order.
  derive.release();
  derive.hold();
  await settle();
  await settle();
  assert.deepEqual(order.slice(0, 2), [0, 1]);
  assert.equal(derive.calls, 4);
  assert.equal(hasher.waiting, 14);
  // The rest wait at most 5 s, then are refused rather than held for ever.
  t.mock.timers.tick(5000);
  await settle();
  assert.equal(hasher.waiting, 0);
  assert.equal(order.filter(entry => /refused .*busy\/queue/.test(entry)).length, 14);
  derive.release();
  await Promise.all(jobs);
  assert.deepEqual(order.slice(-2).sort(), [2, 3]);
  assert.equal(hasher.active, 0);
  // Free again: the next derivation starts at once.
  await hasher.hash(Buffer.from('later'), Buffer.alloc(32));
  assert.equal(derive.calls, 5);
});

test('smaller pools keep the same semantics (1.4.3: two run, one waits briefly, the rest are refused)', async () => {
  const derive = countingDerive();
  derive.hold();
  const hasher = createHasher({ derive, maxWaiting: 1, waitMs: 20 });
  const a = hasher.hash(Buffer.from('a'), Buffer.alloc(32)),
    b = hasher.hash(Buffer.from('b'), Buffer.alloc(32)),
    queued = hasher.hash(Buffer.from('c'), Buffer.alloc(32));
  await settle();
  await assert.rejects(hasher.hash(Buffer.from('d'), Buffer.alloc(32)), code('busy'));
  await assert.rejects(queued, code('busy'));
  derive.release();
  await Promise.all([a, b]);
  assert.equal(derive.calls, 2);
});

test('new password validation checks Unicode characters, bytes, confirmation and shape, with codes', () => {
  const current = secret;
  for (const [input, expected] of [
    [null, 'invalid_request'],
    [[], 'invalid_request'],
    [{}, 'invalid_request'],
    [{ password: changed, confirmPassword: changed }, 'invalid_request'],
    [{ currentPassword: current, password: 7, confirmPassword: 7 }, 'invalid_request'],
    [
      { currentPassword: 'x'.repeat(1025), password: changed, confirmPassword: changed },
      'current_password_incorrect',
    ],
    [{ currentPassword: current, password: '', confirmPassword: '' }, 'password_invalid'],
    [
      // Exactly 12 characters: long enough, so the confirmation decides.
      { currentPassword: current, password: 'short-secret', confirmPassword: 'different-secret' },
      'password_mismatch',
    ],
    [
      { currentPassword: current, password: 'eleven char', confirmPassword: 'eleven char' },
      'password_invalid',
    ],
    [
      { currentPassword: current, password: '😀'.repeat(11), confirmPassword: '😀'.repeat(11) },
      'password_invalid',
    ],
    [
      { currentPassword: current, password: 'é'.repeat(513), confirmPassword: 'é'.repeat(513) },
      'password_invalid',
    ],
    [
      { currentPassword: current, password: 'x'.repeat(1025), confirmPassword: 'x'.repeat(1025) },
      'password_invalid',
    ],
    [
      {
        currentPassword: current,
        password: 'a'.repeat(12) + '\ud800',
        confirmPassword: 'a'.repeat(12) + '\ud800',
      },
      'password_invalid',
    ],
    [
      {
        currentPassword: current,
        password: 'long enough secret',
        confirmPassword: 'long enough secreT',
      },
      'password_mismatch',
    ],
  ])
    assert.throws(
      () => checkNewPassword(input),
      error => {
        assert.equal(error.code, expected, JSON.stringify(input)?.slice(0, 80));
        assert.equal(error.status, expected === 'current_password_incorrect' ? 403 : 400);
        // Messages never repeat what was typed.
        for (const typed of ['short-secret', 'long enough secret', current])
          assert.ok(!error.message.includes(typed));
        return true;
      }
    );
  // 12 characters of 4 bytes each, and 512 two-byte characters (1024 bytes), are accepted.
  assert.equal(
    checkNewPassword({
      currentPassword: current,
      password: '😀'.repeat(12),
      confirmPassword: '😀'.repeat(12),
    }),
    '😀'.repeat(12)
  );
  const long = 'é'.repeat(512);
  assert.equal(
    checkNewPassword({ currentPassword: current, password: long, confirmPassword: long }),
    long
  );
});

test('the bootstrap password must be 12 to 1024 characters and not only spaces', () => {
  for (const bad of [
    'short',
    ' '.repeat(20),
    'x'.repeat(1025),
    'é'.repeat(600),
    'a'.repeat(12) + '\ud800',
    42,
  ])
    assert.throws(
      () => checkBootstrapPassword(bad),
      error =>
        error.refusal === true &&
        /^GOBLIN_PASSWORD must be 12 to 1024 characters and not only spaces/.test(error.message)
    );
  assert.equal(checkBootstrapPassword('twelve chars'), 'twelve chars');
});

test('auth.json is written atomically, 0600, as JSON.stringify(record) + newline', t => {
  const directory = temporary(t);
  const record = fakeRecord(secret, { passwordChangedAt: 99 });
  const { sha256 } = writeAuthRecord(directory, record);
  const file = path.join(directory, 'auth.json');
  const bytes = fs.readFileSync(file);
  assert.equal(bytes.toString(), JSON.stringify(record) + '\n');
  assert.equal(sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(mode(file), 0o600);
  assert.deepEqual(fs.readdirSync(directory), ['auth.json']);
  // A replacement over a looser file leaves a private one.
  fs.chmodSync(file, 0o644);
  writeAuthRecord(directory, fakeRecord(changed));
  assert.equal(mode(file), 0o600);
  assert.equal(readAuthRecord(directory).record.hash, fakeRecord(changed).hash);
});

test('failed atomic persistence leaves the old auth.json and no temporary file', t => {
  const directory = temporary(t);
  const saved = writeAuthJson(directory, fakeRecord(secret));
  const rename = t.mock.method(fs, 'renameSync', () => {
    throw new Error('private filesystem details /var/lib/uptime-goblin');
  });
  assert.throws(
    () => writeAuthRecord(directory, fakeRecord(changed)),
    error =>
      error.code === 'Error' &&
      error.message === 'auth.json could not be written' &&
      !error.message.includes('/var/lib')
  );
  assert.equal(rename.mock.callCount(), 1);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'auth.json')), saved);
  assert.deepEqual(fs.readdirSync(directory), ['auth.json']);
  rename.mock.restore();
  const failing = t.mock.method(fs, 'fsyncSync', () => {
    throw Object.assign(new Error('input/output error'), { code: 'EIO' });
  });
  assert.throws(() => writeAuthRecord(directory, fakeRecord(changed)), code('EIO'));
  failing.mock.restore();
  assert.deepEqual(fs.readdirSync(directory), ['auth.json']);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'auth.json')), saved);
});

test('auth.json is flushed with its directory after the rename; a failed flush says the file was replaced', t => {
  // 1.4.3's write ended at the rename, which btrfs (Synology's Docker volumes) commits up to
  // 30 s later: the fingerprint control.sqlite recorded next (fsynced) could outlive it (r6).
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(secret));
  const traced = traceDurability(t, directory);
  writeAuthRecord(directory, fakeRecord(changed));
  traced.stop();
  assert.deepEqual(traced.events, [
    'fsync auth.json.<uuid>.tmp',
    'rename auth.json.<uuid>.tmp -> auth.json',
    'fsync .',
  ]);
  // The flush failed: the file is replaced, but the rename may not be on disk, which the error
  // says (`replaced`), so that the caller records nothing.
  const third = 'a third fixture password';
  const failing = traceDurability(t, directory, { failFlush: true });
  assert.throws(
    () => writeAuthRecord(directory, fakeRecord(third)),
    error => error.code === 'EIO' && error.replaced === true && !error.message.includes(directory)
  );
  failing.stop();
  assert.equal(readAuthRecord(directory).record.hash, fakeRecord(third).hash);
  assert.deepEqual(fs.readdirSync(directory), ['auth.json']);
  // A failure before the rename is not `replaced`.
  t.mock.method(fs, 'renameSync', () => {
    throw Object.assign(new Error('input/output error'), { code: 'EIO' });
  });
  assert.throws(
    () => writeAuthRecord(directory, fakeRecord(changed)),
    error => error.code === 'EIO' && error.replaced === undefined
  );
});

for (const kind of ['file', 'symlink'])
  test(`an auth.json write preserves an unowned temporary ${kind} on exclusive-create collision`, t => {
    const directory = temporary(t);
    const saved = writeAuthJson(directory, fakeRecord(secret));
    const file = path.join(directory, 'auth.json');
    const unrelated = path.join(temporary(t), 'unrelated.txt'),
      contents = 'Keep this unrelated file';
    fs.writeFileSync(unrelated, contents, { mode: 0o640 });
    const open = fs.openSync;
    let collision, inode, permissions;
    t.mock.method(fs, 'openSync', (target, flags, fileMode) => {
      if (!collision && typeof target === 'string' && target.startsWith(file + '.')) {
        collision = target;
        if (kind === 'symlink') fs.symlinkSync(unrelated, collision);
        else {
          const descriptor = open(collision, 'wx', 0o640);
          fs.writeFileSync(descriptor, contents);
          fs.closeSync(descriptor);
        }
        inode = fs.lstatSync(collision).ino;
        permissions = fs.statSync(collision).mode & 0o777;
      }
      return open(target, flags, fileMode);
    });
    assert.throws(() => writeAuthRecord(directory, fakeRecord(changed)), code('EEXIST'));
    assert.ok(collision);
    assert.equal(fs.lstatSync(collision).ino, inode, 'cleanup must preserve the unowned entry');
    assert.equal(fs.lstatSync(collision).isSymbolicLink(), kind === 'symlink');
    assert.equal(fs.readFileSync(collision, 'utf8'), contents);
    assert.equal(fs.readFileSync(unrelated, 'utf8'), contents);
    assert.equal(fs.statSync(collision).mode & 0o777, permissions);
    assert.deepEqual(fs.readFileSync(file), saved);
  });

test('an auth.json write never closes a descriptor reused after a close error', t => {
  const directory = temporary(t);
  const saved = writeAuthJson(directory, fakeRecord(secret));
  const file = path.join(directory, 'auth.json');
  const unrelated = path.join(temporary(t), 'unrelated.txt'),
    contents = 'An unrelated open file';
  fs.writeFileSync(unrelated, contents);
  const open = fs.openSync,
    close = fs.closeSync;
  let savingDescriptor, replacement;
  t.after(() => {
    if (replacement !== undefined)
      try {
        close(replacement);
      } catch {}
  });
  t.mock.method(fs, 'openSync', (target, flags, fileMode) => {
    const descriptor = open(target, flags, fileMode);
    if (typeof target === 'string' && target.startsWith(file + '.')) savingDescriptor = descriptor;
    return descriptor;
  });
  t.mock.method(fs, 'closeSync', descriptor => {
    if (descriptor === savingDescriptor && replacement === undefined) {
      close(descriptor);
      replacement = open(unrelated, 'r');
      assert.equal(replacement, descriptor, 'the fixture reuses the released descriptor');
      throw Object.assign(new Error('fixture close failure'), { code: 'EIO' });
    }
    return close(descriptor);
  });
  assert.throws(() => writeAuthRecord(directory, fakeRecord(changed)), code('EIO'));
  assert.ok(replacement !== undefined);
  assert.equal(fs.readFileSync(replacement, 'utf8'), contents, 'the replacement must remain open');
  assert.deepEqual(fs.readdirSync(directory), ['auth.json']);
  assert.deepEqual(fs.readFileSync(file), saved);
});

test('corrupt, unsupported, oversized and symlinked auth records refuse the start', t => {
  for (const value of [
    'not-json',
    '{}',
    'null',
    JSON.stringify({ ...fakeRecord(secret), parameters: { N: 1, r: 8, p: 3, keyLength: 64 } }),
    'x'.repeat(8193),
    JSON.stringify(fakeRecord(secret)).padEnd(8193, ' '),
  ]) {
    const directory = temporary(t);
    writeAuthJson(directory, null, { text: value });
    assert.throws(
      () => readAuthRecord(directory),
      error =>
        error.refusal === true &&
        error.message ===
          'Saved authentication could not be loaded. Restore a valid auth.json backup before starting Uptime Goblin.'
    );
  }
  const directory = temporary(t);
  fs.symlinkSync('missing-target', path.join(directory, 'auth.json'));
  assert.throws(
    () => readAuthRecord(directory),
    error => error.refusal === true
  );
  const target = path.join(temporary(t), 'auth.json');
  writeAuthJson(path.dirname(target), fakeRecord(secret));
  const linked = temporary(t);
  fs.symlinkSync(target, path.join(linked, 'auth.json'));
  assert.throws(
    () => readAuthRecord(linked),
    error => error.refusal === true
  );
  const dir = temporary(t);
  fs.mkdirSync(path.join(dir, 'auth.json'));
  assert.throws(
    () => readAuthRecord(dir),
    error => error.refusal === true
  );
});

test('a FIFO in place of auth.json is refused without waiting for a writer; a valid record still loads', t => {
  const moduleUrl = new URL('../../lib/identity/password.mjs', import.meta.url).href;
  for (const fifo of [false, true]) {
    const directory = temporary(t);
    if (fifo) assert.equal(spawnSync('mkfifo', [path.join(directory, 'auth.json')]).status, 0);
    else writeAuthJson(directory, fakeRecord(secret));
    // In a child with a deadline: a blocking open would hang this process for good.
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import assert from 'node:assert/strict';
         import { readAuthRecord } from ${JSON.stringify(moduleUrl)};
         ${
           fifo
             ? 'assert.throws(() => readAuthRecord(process.argv[1]), error => error.refusal === true && /Saved authentication/.test(error.message));'
             : 'assert.ok(readAuthRecord(process.argv[1]).record);'
         }`,
        directory,
      ],
      { encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' }
    );
    assert.equal(child.error, undefined, 'the read must return before the child deadline');
    assert.equal(child.status, 0, child.stderr);
    if (fifo) assert.ok(fs.statSync(path.join(directory, 'auth.json')).isFIFO());
  }
});

test('auth.json is read no further than its limit, even when it grows after inspection', t => {
  const directory = temporary(t),
    record = fakeRecord(secret),
    file = path.join(directory, 'auth.json'),
    stat = fs.fstatSync;
  writeAuthJson(directory, record);
  let inspected;
  t.mock.method(fs, 'fstatSync', (descriptor, ...rest) => {
    const result = stat(descriptor, ...rest);
    inspected = descriptor;
    // Still valid JSON, and 16 MiB: a read to the end would take all of it into memory.
    fs.writeFileSync(file, JSON.stringify(record).padEnd(16 * 1024 * 1024, ' '));
    return result;
  });
  // Every byte read from the record's descriptor, whichever call reads it.
  let read = 0;
  const readSync = fs.readSync,
    readFileSync = fs.readFileSync;
  t.mock.method(fs, 'readSync', (descriptor, ...rest) => {
    const bytes = readSync(descriptor, ...rest);
    if (descriptor === inspected) read += bytes;
    return bytes;
  });
  t.mock.method(fs, 'readFileSync', (target, ...rest) => {
    const bytes = readFileSync(target, ...rest);
    if (target === inspected) read += bytes.length;
    return bytes;
  });
  assert.throws(
    () => readAuthRecord(directory),
    error => error.refusal === true && /Saved authentication/.test(error.message)
  );
  assert.ok(inspected !== undefined);
  assert.ok(read <= 8193, `read ${read} bytes`);
  assert.throws(() => stat(inspected), { code: 'EBADF' }, 'the refused descriptor is closed');
  t.mock.restoreAll();
  // A valid record exactly at the limit still loads.
  fs.writeFileSync(file, JSON.stringify(record).padEnd(8192, ' '));
  assert.equal(readAuthRecord(directory).record.hash, record.hash);
});

test('readAuthRecord reads only: it fingerprints the exact bytes, and a missing file or directory is absent', t => {
  const directory = temporary(t);
  const record = fakeRecord(secret);
  // A file 1.4.x or a person wrote, with its own spacing and key order.
  const text = JSON.stringify({ hash: record.hash, ...record }, null, 2);
  const bytes = writeAuthJson(directory, null, { text });
  fs.chmodSync(path.join(directory, 'auth.json'), 0o644);
  const read = readAuthRecord(directory);
  assert.deepEqual(read.record, canonicalRecord(record));
  assert.equal(read.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(mode(path.join(directory, 'auth.json')), 0o644, 'no mode change while reading');
  assert.deepEqual(fs.readFileSync(path.join(directory, 'auth.json')), bytes);
  assert.equal(readAuthRecord(temporary(t)), null);
  const missing = path.join(temporary(t), 'not-created');
  assert.equal(readAuthRecord(missing), null);
  assert.equal(fs.existsSync(missing), false);
});

test('disk trouble reading auth.json is retried, not a refusal; tightening warns on a read-only disk', t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(secret));
  fs.chmodSync(path.join(directory, 'auth.json'), 0o644);
  const failing = t.mock.method(fs, 'openSync', () => {
    throw Object.assign(new Error('input/output error'), { code: 'EIO' });
  });
  assert.throws(
    () => readAuthRecord(directory),
    error => error.code === 'EIO' && error.refusal === undefined
  );
  failing.mock.restore();

  const warnings = [];
  const readOnly = t.mock.method(fs, 'fchmodSync', () => {
    throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
  });
  tightenAuthRecord(directory, { warn: (...args) => warnings.push(args.join(' ')) });
  assert.deepEqual(warnings, ['auth.json permissions could not be tightened: EROFS']);
  readOnly.mock.restore();
  // The default warning goes to console.warn, as in 1.4.3.
  const consoleWarnings = [];
  t.mock.method(console, 'warn', (...args) => consoleWarnings.push(args.join(' ')));
  t.mock.method(fs, 'fchmodSync', () => {
    throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
  });
  tightenAuthRecord(directory);
  assert.match(consoleWarnings.join('\n'), /could not be tightened: EROFS/);
  t.mock.restoreAll();

  tightenAuthRecord(directory, { warn: (...args) => warnings.push(args.join(' ')) });
  assert.equal(mode(path.join(directory, 'auth.json')), 0o600);
  // No file: nothing to tighten, nothing to warn about.
  tightenAuthRecord(temporary(t), { warn: (...args) => warnings.push(args.join(' ')) });
  assert.equal(warnings.length, 1);
});

test('fakeKey mirrors the real key length, so fixtures exercise the same comparisons', () => {
  assert.equal(fakeKey(Buffer.from(secret), Buffer.alloc(32)).length, scryptParameters.keyLength);
});

test('tightenAuthRecord returns at once when a FIFO takes the record’s place, and leaves it as it is', t => {
  const moduleUrl = new URL('../../lib/identity/password.mjs', import.meta.url).href;
  const directory = temporary(t);
  const file = path.join(directory, 'auth.json');
  assert.equal(spawnSync('mkfifo', [file]).status, 0);
  fs.chmodSync(file, 0o644);
  // In a child with a deadline: a blocking open would hang this process for good.
  const child = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import { tightenAuthRecord } from ${JSON.stringify(moduleUrl)};
       const warnings = [];
       tightenAuthRecord(process.argv[1], { warn: (...args) => warnings.push(args.join(' ')) });
       process.stdout.write(JSON.stringify(warnings));`,
      directory,
    ],
    { encoding: 'utf8', timeout: 3000, killSignal: 'SIGKILL' }
  );
  assert.equal(child.error, undefined, 'it returns before the child deadline');
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), [], 'nothing to warn about: it is not a record');
  assert.ok(fs.statSync(file).isFIFO());
  assert.equal(fs.statSync(file).mode & 0o777, 0o644, 'only a regular file is tightened');
});
