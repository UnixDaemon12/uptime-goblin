// The database part of the secrets canary (T4/T19, sessions spec §8.1): after real sign-ins
// (real scrypt), a remembered session and a password change, no cookie value, no secret (in
// any encoding) and no plaintext password is in control.sqlite, its -wal or -shm, or auth.json.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { temporary, startIdentity, adminPassword, otherPassword } from './helpers.mjs';

function needles(label, text) {
  const bytes = Buffer.from(text, 'utf8');
  return [
    [`${label} (utf-8)`, bytes],
    [`${label} (utf-16)`, Buffer.from(text, 'utf16le')],
    [`${label} (hex)`, Buffer.from(bytes.toString('hex'))],
    [`${label} (base64)`, Buffer.from(bytes.toString('base64'))],
  ];
}
function secretNeedles(label, value) {
  const secret = Buffer.from(value.slice(3), 'base64url');
  return [
    [`${label} cookie value`, Buffer.from(value)],
    [`${label} secret (base64url)`, Buffer.from(value.slice(3))],
    [`${label} secret (base64)`, Buffer.from(secret.toString('base64'))],
    [`${label} secret (hex)`, Buffer.from(secret.toString('hex'))],
    [`${label} secret (raw)`, secret],
  ];
}

test('control.sqlite, its WAL and auth.json hold no cookie value, secret or plaintext password', async t => {
  const directory = temporary(t);
  // Real scrypt: what is stored is what production stores.
  const { identity, stop } = await startIdentity(t, directory, {
    password: adminPassword,
    derive: null,
  });
  const signIn = (password, remember) =>
    identity.login({
      login: 'admin',
      password,
      remember,
      client: '192.0.2.1',
      userAgent: 'canary',
    });
  const first = await signIn(adminPassword, false);
  const kept = await signIn(adminPassword, true);
  await assert.rejects(signIn('a wrong canary guess', false));
  const touched = await identity.authenticateSession(kept.issue.value, {
    activity: 'foreground',
  });
  const changed = await identity.changePassword(touched, {
    currentPassword: adminPassword,
    password: otherPassword,
    confirmPassword: otherPassword,
  });
  const after = await signIn(otherPassword, false);
  const basic = await identity.authenticateBasic(Buffer.from('admin:' + otherPassword));
  assert.equal(basic.via, 'basic');

  const searched = [
    ...needles('the first password', adminPassword),
    ...needles('the new password', otherPassword),
    ...needles('a wrong guess', 'a wrong canary guess'),
    ...secretNeedles('first', first.issue.value),
    ...secretNeedles('remembered', kept.issue.value),
    ...secretNeedles('rotated', changed.issue.value),
    ...secretNeedles('after', after.issue.value),
  ];
  const files = () =>
    ['control.sqlite', 'control.sqlite-wal', 'control.sqlite-shm', 'auth.json']
      .map(name => path.join(directory, name))
      .filter(file => fs.existsSync(file));
  const check = moment => {
    const found = files();
    assert.ok(found.some(file => file.endsWith('control.sqlite')));
    for (const file of found) {
      const bytes = fs.readFileSync(file);
      for (const [label, needle] of searched)
        assert.equal(bytes.indexOf(needle), -1, `${label} in ${path.basename(file)} (${moment})`);
    }
  };
  // While Uptime Goblin runs (the WAL holds the recent writes) and after it stopped (checkpointed).
  check('running');
  assert.ok(fs.existsSync(path.join(directory, 'control.sqlite-wal')), 'the WAL was searched');
  stop();
  check('stopped');
});
