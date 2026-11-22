import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const script = fileURLToPath(new URL('../deploy/install-plan.sh', import.meta.url));
const run = args =>
  spawnSync('/bin/sh', [script, ...args], { encoding: 'utf8', env: { PATH: '' } });
test('both packaging plans are explicit read-only deterministic previews', () => {
  for (const mode of ['docker', 'linux']) {
    const first = run(['--dry-run', mode]);
    const second = run(['--dry-run', mode]);
    assert.equal(first.status, 0);
    assert.equal(first.stderr, '');
    assert.equal(first.stdout, second.stdout);
    assert.match(first.stdout, /NOT executed/);
    assert.match(first.stdout, /loopback/);
    assert.match(first.stdout, /restore procedure/);
  }
});
test('no implicit install, permissive flags or extra arguments', () => {
  for (const args of [
    [],
    ['docker'],
    ['--apply', 'docker'],
    ['--dry-run', 'other'],
    ['--dry-run', 'linux', '--force'],
  ]) {
    const result = run(args);
    assert.equal(result.status, 64);
    assert.equal(result.stdout, '');
  }
});
test('Docker plan does not equate version or loopback bind with isolation proof', () => {
  const { stdout } = run(['--dry-run', 'docker']);
  assert.match(stdout, /version is not isolation proof/);
  assert.match(stdout, /denied LAN\/direct-route/);
  assert.match(stdout, /credential gates remain required/);
});
