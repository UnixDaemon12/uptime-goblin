import test from 'node:test';
import assert from 'node:assert/strict';
import { lockdownSetting, ALL_LOCKS, LOCK_NAMES } from '../../lib/admin/actions.mjs';

test('unset, empty and none are off; all excludes named-only logging', () => {
  for (const value of [undefined, '', 'none']) {
    const state = lockdownSetting(value);
    assert.equal(state.locked.size, 0);
    assert.equal(state.invalid, false);
    assert.equal(state.all, false);
    assert.equal(state.warning, null);
  }
  const all = lockdownSetting('all');
  assert.deepEqual([...all.locked], [...ALL_LOCKS].sort());
  assert.equal(all.all, true);
  assert.equal(all.locked.has('logging'), false);
});

test('recognized lists sort and keep logging as named-only', () => {
  const state = lockdownSetting('display-code,logging');
  assert.deepEqual([...state.locked], ['display-code', 'logging']);
  assert.equal(state.invalid, false);
  assert.equal(state.all, false);
  for (const name of LOCK_NAMES) assert.deepEqual([...lockdownSetting(name).locked], [name]);
});

test('invalid syntax, unknown names and non-string values lock every recognized action', () => {
  for (const value of [
    'ALL',
    ' all',
    'none ',
    '  ',
    'display-code, logging',
    'snapshot-delete,snapshot-delete',
    '\nnone',
    '\tnone',
    'none\r',
    ' '.repeat(2000) + 'none',
    'x'.repeat(1025),
    'none,logging',
    'all,display-code',
    'display-code,',
    ',',
    'display-code,,logging',
    'future-action',
    'logging;none',
    'display-code\nlogging',
    null,
    true,
    1,
    {},
    [],
  ]) {
    const state = lockdownSetting(value);
    assert.deepEqual([...state.locked], [...LOCK_NAMES].sort());
    assert.equal(state.invalid, true);
    assert.equal(state.all, false);
    assert.equal(state.locked.has('logging'), true);
    assert.match(state.warning, /every lockable action is turned off/);
  }
});

test('warnings bound and clean untrusted setting text; results cannot mutate later settings', () => {
  const state = lockdownSetting('\u001b\u202e' + 'x'.repeat(1000) + '\n');
  assert.equal(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/.test(state.warning), false);
  assert.ok(state.warning.includes('it is set to ' + 'x'.repeat(40) + ', so'));
  assert.throws(() => state.locked.clear(), TypeError);
  assert.throws(() => state.locked.delete('logging'), TypeError);
  assert.throws(() => state.locked.add('unknown'), TypeError);
  assert.throws(() => {
    state.invalid = false;
  }, TypeError);
  assert.equal(lockdownSetting('none').locked.size, 0);
});

test('intrinsic Set mutators and callback receivers cannot bypass read-only lock state', () => {
  const state = lockdownSetting('all');
  assert.equal(state.locked instanceof Set, true);
  assert.throws(() => Set.prototype.clear.call(state.locked), TypeError);
  assert.throws(() => Set.prototype.delete.call(state.locked, 'audit-accept'), TypeError);
  assert.throws(() => Set.prototype.add.call(state.locked, 'logging'), TypeError);
  assert.equal(state.locked.valueOf(), state.locked);
  state.locked.forEach((value, key, set) => {
    assert.equal(set, state.locked);
    assert.equal(key, value);
    assert.throws(() => Set.prototype.clear.call(set), TypeError);
  });
  assert.equal(state.locked.size, 9);
  assert.deepEqual([...state.locked], [...ALL_LOCKS].sort());
});

test('raw settings over1024 characters fail closed before any normalization', () => {
  const oversized = 'none' + ' '.repeat(1021);
  const state = lockdownSetting(oversized);
  assert.equal(state.invalid, true);
  assert.deepEqual([...state.locked], [...LOCK_NAMES].sort());
  for (const character of ['\0', '\n', '\r', '\t', '\u007f', '\u0085']) {
    assert.equal(lockdownSetting(character + 'none').invalid, true);
    assert.equal(lockdownSetting('none' + character).invalid, true);
  }
});

test('warnings remove all Unicode control and format characters, not only bidi overrides', () => {
  for (const codepoint of [
    0x00ad, 0x061c, 0x200b, 0x200e, 0x202e, 0x2060, 0x2066, 0xfeff, 0xe0001,
  ]) {
    const state = lockdownSetting(String.fromCodePoint(codepoint) + 'none');
    assert.equal(state.invalid, true);
    assert.equal(state.locked.size, LOCK_NAMES.length);
    assert.equal(/[\p{Cc}\p{Cf}]/u.test(state.warning), false);
  }
});
