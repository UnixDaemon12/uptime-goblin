// Settings documents (lib/settings.mjs, roadmap §2.6): strict validation, compare-and-swap on
// version, audit diffs that never show secrets, environment locks, sealed secrets, and
// documents written by other releases (newer: read-only; older: upgraded; unknown fields kept).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  defineSetting,
  createSettings,
  memorySettingsStore,
  validators,
  SettingsError,
} from '../lib/settings.mjs';
import { Keyring, memoryKeyringStore } from '../lib/keyring.mjs';
import { openControl, createSettingsStore, metaOps } from '../lib/db/control.mjs';

const channel = defineSetting({
  component: 'alerting',
  key: 'email',
  schema: 2,
  description: 'Email channel',
  fields: {
    enabled: { default: false, validate: validators.boolean },
    host: { default: '', validate: validators.text(253) },
    port: {
      default: 587,
      validate: validators.integer(1, 65535),
      env: 'GOBLIN_SMTP_PORT',
      fromEnv: Number,
    },
    security: { default: 'starttls', validate: validators.oneOf('starttls', 'tls', 'none') },
    password: { secret: true, validate: validators.secret(200) },
  },
  check(value) {
    if (value.enabled && !value.host) throw new Error('an enabled channel needs a host');
  },
  upgrade(value, fromSchema) {
    // Schema 1 called the host "server".
    if (fromSchema === 1 && 'server' in value) {
      value.host = value.server;
      delete value.server;
    }
    return value;
  },
});

async function setup({ env = {}, keyring = true, store = memorySettingsStore(), clock } = {}) {
  const opened = keyring
    ? await Keyring.open(memoryKeyringStore(), { key: Buffer.alloc(32, 1).fill(2, 0, 1) })
    : null;
  const settings = createSettings({ store, definitions: [channel], env, keyring: opened, clock });
  return { settings, store, keyring: opened };
}
const rejects = (promise, code, pattern) =>
  assert.rejects(promise, error => {
    assert.ok(error instanceof SettingsError, String(error));
    assert.equal(error.code, code);
    if (pattern) assert.match(error.message, pattern);
    return true;
  });

test('defineSetting validates its declaration', () => {
  const field = { default: 1, validate: v => v };
  for (const [declaration, pattern] of [
    [{ component: 'Bad', key: 'k', fields: { a: field } }, /component/],
    [{ component: 'c', key: '', fields: { a: field } }, /key/],
    [{ component: 'c', key: 'k', schema: 0, fields: { a: field } }, /schema/],
    [{ component: 'c', key: 'k', fields: {} }, /needs fields/],
    [{ component: 'c', key: 'k', fields: { __proto__: field } }, /needs fields|Invalid field/],
    [{ component: 'c', key: 'k', fields: { constructor: field } }, /Invalid field/],
    [{ component: 'c', key: 'k', fields: { $sealed: field } }, /Invalid field/],
    [{ component: 'c', key: 'k', fields: { a: { default: 1 } } }, /needs validate/],
    [
      { component: 'c', key: 'k', fields: { a: { ...field, secret: true } } },
      /cannot have a default/,
    ],
    [{ component: 'c', key: 'k', fields: { a: { ...field, env: 'PATH' } } }, /GOBLIN_ variable/],
  ])
    assert.throws(() => defineSetting(declaration), pattern, JSON.stringify(declaration));
  assert.ok(Object.isFrozen(channel) && Object.isFrozen(channel.fields));
  assert.equal(channel.fields.password.default, null);
});

test('get returns defaults for a document never saved; view hides secrets', async () => {
  const { settings } = await setup();
  const current = await settings.get('alerting', 'email');
  assert.deepEqual(current.value, {
    enabled: false,
    host: '',
    port: 587,
    security: 'starttls',
    password: null,
  });
  assert.deepEqual(
    [current.version, current.schema, current.readOnly, current.locked, current.updatedAt],
    [0, 2, false, [], null]
  );
  assert.deepEqual((await settings.view('alerting', 'email')).value.password, { set: false });
  await rejects(settings.get('alerting', 'nothing'), 'settings_unknown');
  assert.equal(settings.has('alerting', 'email'), true);
  assert.equal(settings.definitions().length, 1);
  assert.throws(() => settings.define(channel), /defined twice/);
});

test('update validates strictly, compares and swaps on version, and returns an audit diff without secrets', async () => {
  const { settings, store } = await setup({ clock: () => 1234 });
  const saved = await settings.update(
    'alerting',
    'email',
    { enabled: true, host: '  mail.example.test ', password: 'hunter2hunter2' },
    { ifVersion: 0, by: 'u_admin' }
  );
  assert.equal(saved.version, 1);
  assert.equal(saved.value.host, 'mail.example.test', 'validators normalise');
  assert.deepEqual(saved.value.password, { set: true });
  assert.deepEqual(saved.diff, [
    { field: 'enabled', from: false, to: true },
    { field: 'host', from: '', to: 'mail.example.test' },
    { field: 'password', change: 'set' },
  ]);
  const row = await store.get('alerting', 'email');
  assert.deepEqual(
    [row.version, row.schema, row.updated_at, row.updated_by],
    [1, 2, 1234, 'u_admin']
  );
  assert.doesNotMatch(row.value, /hunter2/, 'secrets are sealed at rest');
  assert.equal((await settings.get('alerting', 'email')).value.password, 'hunter2hunter2');

  // A stale version is refused; so are unknown fields, invalid values and a failing check.
  await rejects(
    settings.update('alerting', 'email', { port: 25 }, { ifVersion: 0 }),
    'settings_conflict'
  );
  await rejects(
    settings.update('alerting', 'email', { colour: 'red' }),
    'settings_invalid',
    /no field colour/
  );
  await rejects(settings.update('alerting', 'email', { __proto__: { x: 1 } }), 'settings_invalid');
  await rejects(
    settings.update('alerting', 'email', JSON.parse('{"__proto__": 1}')),
    'settings_invalid'
  );
  await rejects(
    settings.update('alerting', 'email', { port: 0 }),
    'settings_invalid',
    /port must be/
  );
  await rejects(settings.update('alerting', 'email', { security: 'ssl' }), 'settings_invalid');
  await rejects(settings.update('alerting', 'email', { host: 'a\u0000b' }), 'settings_invalid');
  await rejects(settings.update('alerting', 'email', ['not an object']), 'settings_invalid');
  await rejects(
    settings.update('alerting', 'email', { host: '' }),
    'settings_invalid',
    /needs a host/
  );
  const error = await settings.update('alerting', 'email', { port: 70000 }).catch(e => e);
  assert.equal(error.status, 400);
  assert.equal(error.field, 'port');

  // Changing a secret shows only that it changed; clearing it shows "cleared".
  const changed = await settings.update(
    'alerting',
    'email',
    { password: 'another-password' },
    { ifVersion: 1 }
  );
  assert.deepEqual(changed.diff, [{ field: 'password', change: 'changed' }]);
  const cleared = await settings.update('alerting', 'email', { password: null });
  assert.deepEqual(cleared.diff, [{ field: 'password', change: 'cleared' }]);
  assert.equal((await settings.get('alerting', 'email')).value.password, null);
  // No change writes nothing.
  const same = await settings.update('alerting', 'email', { port: 587 });
  assert.deepEqual([same.version, same.diff], [cleared.version, []]);
});

test('a store that changed between read and write is a conflict, not a lost update', async () => {
  const store = memorySettingsStore();
  const { settings } = await setup({ store });
  await settings.update('alerting', 'email', { host: 'a.example.test' });
  const racing = {
    ...store,
    get: store.get,
    async put(row, options) {
      // Another writer saves first.
      await store.put({ ...row, value: '{}', version: row.version }, options);
      return store.put(row, options);
    },
    list: store.list,
  };
  const other = createSettings({ store: racing, definitions: [channel], env: {} });
  await rejects(other.update('alerting', 'email', { host: 'b.example.test' }), 'settings_conflict');
});

// Audit spec §2.1 items 4 and 8: the webhook signing key's rotation records its audit row in
// the unit of the settings write, through put's inUnit, which the update's `audit` supplies.
test('put inUnit: runs in the unit of a swap that changed the row, never on a conflict; a throw undoes the change', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-settings-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  await control.migrate();
  const row = (version, key = 'email') => ({
    component: 'alerting',
    key,
    schema: 2,
    value: JSON.stringify({ version }),
    version,
    updated_at: version,
    updated_by: null,
  });
  const marks = () => control.db.read(tx => metaOps.get(tx, 'test_mark'));
  for (const [label, store, sqlite] of [
    ['control.sqlite', createSettingsStore(control.db), true],
    ['memory', memorySettingsStore(), false],
  ]) {
    const calls = [];
    // A unit's own write, so the test sees that it commits or rolls back with the document.
    const mark = (value, then) => tx => {
      calls.push(value);
      assert.equal(tx === null, !sqlite, `${label}: the unit's transaction, or null in memory`);
      if (tx) metaOps.set(tx, 'test_mark', value, 1);
      then?.();
    };
    assert.equal(await store.put(row(1), { ifVersion: 0, inUnit: mark('inserted') }), true);
    // A conflict changes no row and never calls it, whether inserting or swapping.
    assert.equal(await store.put(row(2), { ifVersion: 0, inUnit: mark('conflict') }), false);
    assert.equal(await store.put(row(2), { ifVersion: 7, inUnit: mark('conflict') }), false);
    assert.equal(await store.put(row(2), { ifVersion: 1, inUnit: mark('swapped') }), true);
    assert.deepEqual(calls, ['inserted', 'swapped'], label);
    if (sqlite) assert.equal(await marks(), 'swapped');
    // A throw rolls the change back with what it wrote, and reaches the caller.
    const refuse = () => {
      throw new Error('the audit row could not be written');
    };
    await assert.rejects(
      store.put(row(3), { ifVersion: 2, inUnit: mark('refused', refuse) }),
      /could not be written/
    );
    assert.equal((await store.get('alerting', 'email')).version, 2, label);
    await assert.rejects(
      store.put(row(1, 'other'), { ifVersion: 0, inUnit: mark('refused', refuse) }),
      /could not be written/
    );
    assert.equal(await store.get('alerting', 'other'), undefined, label);
    if (sqlite) assert.equal(await marks(), 'swapped', 'what the refused units wrote is gone');
    // Without inUnit, nothing changes.
    assert.equal(await store.put(row(3), { ifVersion: 2 }), true);
  }
});

test('update with audit: the recorder gets the change list in the path form, in the unit, only for a change', async () => {
  const { settings, store } = await setup();
  const calls = [];
  const audit = (tx, { diff }) => calls.push({ tx, diff });
  const saved = await settings.update(
    'alerting',
    'email',
    { enabled: true, host: 'mail.example.test', password: 'hunter2hunter2' },
    { ifVersion: 0, audit }
  );
  assert.deepEqual(calls, [
    {
      tx: null,
      diff: [
        { path: 'enabled', from: false, to: true },
        { path: 'host', from: '', to: 'mail.example.test' },
        { path: 'password', change: 'set' },
      ],
    },
  ]);
  assert.doesNotMatch(JSON.stringify(calls), /hunter2/, 'never a secret');
  // The answer's own diff keeps `field`, as before.
  assert.equal(saved.diff[0].field, 'enabled');
  // A conflict, or an update that changes nothing, never calls it.
  await rejects(
    settings.update('alerting', 'email', { port: 25 }, { ifVersion: 0, audit }),
    'settings_conflict'
  );
  await settings.update('alerting', 'email', { port: 587 }, { audit });
  assert.equal(calls.length, 1);
  // A recorder that throws leaves the document as it was.
  await assert.rejects(
    settings.update(
      'alerting',
      'email',
      { password: 'another-password' },
      {
        audit: () => {
          throw new Error('no audit row');
        },
      }
    ),
    /no audit row/
  );
  assert.equal((await store.get('alerting', 'email')).version, 1);
  assert.equal((await settings.get('alerting', 'email')).value.password, 'hunter2hunter2');
  const changed = await settings.update('alerting', 'email', { password: null }, { audit });
  assert.deepEqual(calls.at(-1).diff, [{ path: 'password', change: 'cleared' }]);
  assert.equal(changed.version, 2);
  await assert.rejects(
    settings.update('alerting', 'email', { port: 25 }, { audit: 'not a function' }),
    TypeError
  );
});

test('an environment variable locks its field: its value wins and the API cannot change it', async () => {
  const { settings } = await setup({ env: { GOBLIN_SMTP_PORT: '2525' } });
  const current = await settings.get('alerting', 'email');
  assert.equal(current.value.port, 2525);
  assert.deepEqual(current.locked, ['port']);
  await rejects(
    settings.update('alerting', 'email', { port: 25 }),
    'settings_locked',
    /GOBLIN_SMTP_PORT/
  );
  // Sending the locked value back unchanged is accepted (a form submits every field).
  assert.equal((await settings.update('alerting', 'email', { port: 2525, host: 'h' })).version, 1);
  const invalid = await setup({ env: { GOBLIN_SMTP_PORT: 'many' } });
  await rejects(invalid.settings.get('alerting', 'email'), 'settings_invalid', /GOBLIN_SMTP_PORT/);
});

test('secrets need the keyring; one that no longer opens degrades to unset and is kept until changed', async () => {
  const store = memorySettingsStore();
  const without = await setup({ keyring: false, store });
  await rejects(
    without.settings.update('alerting', 'email', { password: 'pw-1234567' }),
    'settings_keyring'
  );
  await without.settings.update('alerting', 'email', { host: 'h.example.test' });
  const { settings } = await setup({ store });
  await settings.update('alerting', 'email', { password: 'pw-1234567' });
  const sealed = JSON.parse((await store.get('alerting', 'email')).value).password;
  // Another keyring (a reset after a lost key) cannot open it.
  const other = await setup({ store });
  const current = await other.settings.get('alerting', 'email');
  assert.equal(current.value.password, null);
  assert.deepEqual(current.unreadable, ['password']);
  // Changing another field keeps the unreadable secret as it is.
  await other.settings.update('alerting', 'email', { port: 2526 });
  assert.deepEqual(JSON.parse((await store.get('alerting', 'email')).value).password, sealed);
  // Clearing it removes the sealed value, also as the only change, and the diff (the audit's)
  // says so (review TD-1: it read as unset, so the diff left it out, and alone it wrote nothing).
  const { version } = await store.get('alerting', 'email');
  const cleared = await other.settings.update('alerting', 'email', { password: null });
  assert.deepEqual(
    [cleared.version, cleared.diff],
    [version + 1, [{ field: 'password', change: 'cleared' }]]
  );
  assert.equal(JSON.parse((await store.get('alerting', 'email')).value).password, undefined);
  assert.deepEqual((await other.settings.get('alerting', 'email')).unreadable, []);
  // Setting it again replaces it.
  await other.settings.update('alerting', 'email', { password: 'new-password' });
  assert.equal((await other.settings.get('alerting', 'email')).value.password, 'new-password');
  // A sealed value is bound to its document and field: copied into another one, it does not
  // open (the AAD names component, key and field).
  const { password } = JSON.parse((await store.get('alerting', 'email')).value);
  other.settings.define({
    component: 'alerting',
    key: 'webhook',
    fields: { token: { secret: true, validate: validators.secret() } },
  });
  await store.put(
    {
      component: 'alerting',
      key: 'webhook',
      schema: 1,
      value: JSON.stringify({ token: password }),
      version: 1,
      updated_at: 1,
    },
    { ifVersion: 0 }
  );
  const copied = await other.settings.get('alerting', 'webhook');
  assert.equal(copied.value.token, null);
  assert.deepEqual(copied.unreadable, ['token']);
  assert.equal(
    other.keyring.openText('seal', password.$sealed, 'settings:alerting:email:password'),
    'new-password'
  );
});

test('documents from other releases: newer is read-only (409), older is upgraded, unknown fields are kept', async () => {
  const store = memorySettingsStore();
  const { settings } = await setup({ store });
  // Written by a newer release (schema 3) with a field this release does not know.
  await store.put(
    {
      component: 'alerting',
      key: 'email',
      schema: 3,
      value: JSON.stringify({ host: 'new.example.test', port: 465, future: { x: 1 } }),
      version: 1,
      updated_at: 1,
    },
    { ifVersion: 0 }
  );
  const newer = await settings.get('alerting', 'email');
  assert.equal(newer.readOnly, true);
  assert.equal(newer.value.host, 'new.example.test');
  assert.equal(newer.schema, 3);
  const refused = await settings.update('alerting', 'email', { port: 25 }).catch(e => e);
  assert.equal(refused.code, 'settings_newer');
  assert.equal(refused.status, 409);

  // Written by an older release (schema 1): upgraded on read, and on the next write.
  const older = memorySettingsStore();
  await older.put(
    {
      component: 'alerting',
      key: 'email',
      schema: 1,
      value: JSON.stringify({ server: 'old.example.test', port: 'bad', extra: [1, 2] }),
      version: 4,
      updated_at: 1,
    },
    { ifVersion: 0 }
  );
  const legacy = await setup({ store: older });
  const upgraded = await legacy.settings.get('alerting', 'email');
  assert.equal(upgraded.value.host, 'old.example.test');
  assert.equal(
    upgraded.value.port,
    587,
    'a stored value this release refuses reads as the default'
  );
  const written = await legacy.settings.update(
    'alerting',
    'email',
    { enabled: true },
    { ifVersion: 4 }
  );
  assert.equal(written.version, 5);
  const row = await older.get('alerting', 'email');
  assert.equal(row.schema, 2);
  const stored = JSON.parse(row.value);
  assert.deepEqual(stored.extra, [1, 2], 'unknown fields are kept, never dropped');
  assert.equal(stored.host, 'old.example.test');
  assert.equal('server' in stored, false);
  // A stored document that is not an object reads as defaults.
  await older.put(
    { component: 'alerting', key: 'email', schema: 2, value: '[1,2]', version: 6, updated_at: 1 },
    { ifVersion: 5 }
  );
  assert.equal((await legacy.settings.get('alerting', 'email')).value.host, '');
});

test('the common validators', () => {
  assert.equal(validators.boolean(true), true);
  assert.throws(() => validators.boolean('true'));
  assert.equal(validators.integer(1, 3)(2), 2);
  assert.throws(() => validators.integer(1, 3)(2.5));
  assert.throws(() => validators.integer(1, 3)(4));
  assert.equal(validators.text(3)(' ab '), 'ab');
  assert.throws(() => validators.text(3)('abcd'));
  assert.throws(() => validators.text(3, { empty: false })('  '));
  assert.equal(validators.text(2)('é€'), 'é€', 'counted in characters');
  assert.equal(validators.oneOf('a', 'b')('b'), 'b');
  assert.throws(() => validators.oneOf('a')('c'));
  assert.equal(validators.secret(5)('abc'), 'abc');
  assert.throws(() => validators.secret(5)(''));
  assert.throws(() => validators.secret(5)('abcdef'));
});
