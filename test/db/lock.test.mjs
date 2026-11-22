// The data-directory lock (lib/db/lock.mjs): one owner per data directory, released by the
// operating system however the owner exits.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { acquireLock, isLocked, LockHeldError, lockFile } from '../../lib/db/lock.mjs';
import { temporary, mode } from './helpers.mjs';

const lockModule = fileURLToPath(new URL('../../lib/db/lock.mjs', import.meta.url));
// A child that tries to take the lock: exit 0 when it got it, 75 when it is held.
const tryLock = directory =>
  spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import { acquireLock } from ${JSON.stringify(lockModule)};
       try { acquireLock(${JSON.stringify(directory)}).release(); } catch (e) { process.exit(e.exitCode ?? 1); }`,
    ],
    { encoding: 'utf8' }
  ).status;

test('acquireLock owns the directory until release; a second owner gets exit status 75', t => {
  const directory = path.join(temporary(t), 'data');
  const lock = acquireLock(directory, { purpose: 'test', clock: () => 42 });
  t.after(() => lock.release());
  assert.equal(mode(directory), 0o700);
  assert.equal(mode(path.join(directory, lockFile)), 0o600);
  // orbit.lock, the lock's name before the rename, is held with it (lib/legacy-names.mjs).
  assert.equal(mode(path.join(directory, 'orbit.lock')), 0o600);
  assert.equal(lock.legacyFile, path.join(fs.realpathSync(directory), 'orbit.lock'));
  assert.deepEqual([lock.purpose, lock.acquiredAt, lock.held], ['test', 42, true]);
  // No journal or WAL file appears beside the lock.
  assert.deepEqual(fs.readdirSync(directory).sort(), [lockFile, 'orbit.lock']);
  assert.throws(
    () => acquireLock(directory),
    error => error instanceof LockHeldError && error.exitCode === 75
  );
  assert.equal(isLocked(directory), true);
  assert.equal(tryLock(directory), 75, 'another process cannot take it');
  lock.release();
  lock.release(); // idempotent
  assert.equal(lock.held, false);
  assert.equal(isLocked(directory), false);
  assert.equal(tryLock(directory), 0, 'released, another process can take it');
  const again = acquireLock(directory);
  again.release();
  assert.equal(isLocked(path.join(directory, 'missing')), false);
});

test('the lock ends with its process, even after SIGKILL', async t => {
  const directory = temporary(t);
  const child = spawn(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import { acquireLock } from ${JSON.stringify(lockModule)};
       acquireLock(${JSON.stringify(directory)}); console.log('held'); setInterval(() => {}, 1000);`,
    ],
    { stdio: ['ignore', 'pipe', 'inherit'] }
  );
  t.after(() => child.kill('SIGKILL'));
  const [chunk] = await once(child.stdout, 'data');
  assert.equal(String(chunk).trim(), 'held');
  assert.throws(() => acquireLock(directory), LockHeldError);
  child.kill('SIGKILL');
  await once(child, 'exit');
  const lock = acquireLock(directory);
  assert.equal(lock.held, true);
  lock.release();
});

test('a lock file that is not a lock is reported, not taken', t => {
  const directory = temporary(t);
  fs.writeFileSync(
    path.join(directory, lockFile),
    'garbage that is not a SQLite database file'.repeat(100)
  );
  assert.throws(
    () => acquireLock(directory),
    error =>
      !(error instanceof LockHeldError) && /Cannot use the data-directory lock/.test(error.message)
  );
});

test('goblin.lock that is a FIFO or a directory is a refusal (78) that says to remove it; a linked lock file keeps its mode', t => {
  for (const make of [
    file => assert.equal(spawnSync('mkfifo', [file]).status, 0),
    file => fs.mkdirSync(file),
  ]) {
    const directory = temporary(t);
    const file = path.join(fs.realpathSync(directory), lockFile);
    make(file);
    assert.throws(
      () => acquireLock(directory),
      error =>
        error.refusal === true &&
        error.message ===
          `The data-directory lock ${file} is not a regular file. Remove it with Uptime Goblin stopped (Uptime Goblin creates it again), then start Uptime Goblin again.`
    );
    assert.ok(fs.lstatSync(file).isFIFO() || fs.lstatSync(file).isDirectory(), 'left in place');
  }
  // The lock is taken through a symbolic link as before, but the target's mode is not Uptime Goblin's.
  const directory = temporary(t);
  const target = path.join(temporary(t), 'elsewhere.lock');
  fs.writeFileSync(target, '');
  fs.chmodSync(target, 0o644);
  fs.symlinkSync(target, path.join(directory, lockFile));
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  assert.equal(mode(target), 0o644);
});
