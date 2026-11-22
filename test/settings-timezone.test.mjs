// appearance.timezone accepts fixed offsets written UTC±HH:MM (1.4.3), is saved in one
// canonical spelling, and survives a restart; values nothing can show are still repaired.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.mjs';
import { ConfigStore, validateAppearance, InputError } from '../lib/config.mjs';

const password = 'fixture-timezone-password';
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-timezone-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
// Starts a ConfigStore on a config.json saved with this time zone, collecting warnings.
function load(t, timezone) {
  const directory = temporary(t);
  const file = path.join(directory, 'config.json');
  fs.writeFileSync(file, JSON.stringify({ revision: 4, appearance: { timezone }, services: [] }));
  const warnings = [];
  const warn = console.warn;
  console.warn = message => warnings.push(String(message));
  try {
    const config = new ConfigStore(directory);
    return { config, warnings, saved: () => JSON.parse(fs.readFileSync(file, 'utf8')) };
  } finally {
    console.warn = warn;
  }
}

test('offsets written UTC±HH:MM are accepted and saved canonically', () => {
  for (const [input, saved] of [
    ['UTC+05:30', 'UTC+05:30'],
    ['UTC-08:00', 'UTC-08:00'],
    ['UTC+05:45', 'UTC+05:45'],
    ['UTC+12:45', 'UTC+12:45'],
    ['UTC-09:30', 'UTC-09:30'],
    ['UTC+14:00', 'UTC+14:00'],
    ['UTC-12:00', 'UTC-12:00'],
    [' UTC+01:00 ', 'UTC+01:00'],
    ['UTC\u221205:00', 'UTC-05:00'],
    // Orbit 1.4.2 accepts 'UTC' but not 'UTC+00:00'.
    ['UTC+00:00', 'UTC'],
    ['UTC-00:00', 'UTC'],
    ['UTC', 'UTC'],
    ['local', 'local'],
    ['Asia/Kathmandu', 'Asia/Kathmandu'],
  ])
    assert.equal(validateAppearance({ timezone: input }).timezone, saved, input);
  for (const refused of [
    'UTC+5:30',
    'UTC+05',
    'UTC+0530',
    'UTC+05:20',
    'UTC+15:00',
    'utc+05:30',
    'GMT+05:30',
    '+05:30',
    'UTC+05:30:00',
    'US/Eastern',
    'Europe/Atlantis',
  ])
    assert.throws(
      () => validateAppearance({ timezone: refused }),
      error =>
        error instanceof InputError &&
        /UTC\+05:30/.test(error.message) &&
        /Europe\/London/.test(error.message),
      refused
    );
});

test('the settings API saves an offset, and it survives a restart without a repair', async t => {
  const directory = temporary(t);
  const start = async () => {
    const app = await createApp({
      directory,
      port: 0,
      password,
      allowedHosts: '',
      webhook: '',
      startScheduler: false,
      trustProxy: '',
    });
    const { port } = await app.listen();
    t.after(() => app.close());
    const call = async (route, method = 'GET', body) => {
      const response = await fetch(`http://127.0.0.1:${port}${route}`, {
        method,
        headers: {
          Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
          'Content-Type': 'application/json',
          'X-Goblin-Request': '1',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    };
    return { app, call };
  };
  const zone = timezone => ({ appearance: { timezone } });
  const first = await start();
  assert.equal((await first.call('/api/settings', 'PATCH', zone('UTC+05:30'))).status, 200);
  const dashboard = await first.call('/api/dashboard');
  assert.equal(dashboard.body.config.appearance.timezone, 'UTC+05:30');
  const refused = await first.call('/api/settings', 'PATCH', zone('UTC+5:30'));
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /UTC\+05:30/);
  assert.equal(first.app.config.value.appearance.timezone, 'UTC+05:30');
  assert.equal((await first.call('/api/settings', 'PATCH', zone('UTC-00:00'))).status, 200);
  assert.equal(first.app.config.value.appearance.timezone, 'UTC');
  assert.equal((await first.call('/api/settings', 'PATCH', zone('UTC-09:30'))).status, 200);
  await first.app.close();
  const saved = JSON.parse(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'));
  assert.equal(saved.appearance.timezone, 'UTC-09:30');
  const warnings = [];
  const warn = console.warn;
  console.warn = message => warnings.push(String(message));
  let second;
  try {
    second = await start();
  } finally {
    console.warn = warn;
  }
  // 1.5: a key Uptime Goblin generated in the data directory is warned about at every start (delivery
  // spec §6.7); no other warning, so no repair.
  assert.deepEqual(
    warnings.filter(message => !/secret\.key/.test(message)),
    []
  );
  assert.equal(second.app.config.value.appearance.timezone, 'UTC-09:30');
  assert.equal(second.app.config.value.revision, saved.revision);
});

test('a saved offset loads unchanged; other spellings and unusable zones are repaired once', t => {
  const kept = load(t, 'UTC+05:45');
  assert.equal(kept.config.value.appearance.timezone, 'UTC+05:45');
  assert.deepEqual(kept.warnings, []);
  assert.equal(kept.saved().revision, 4, 'nothing to repair, so nothing is rewritten');

  for (const [timezone, repaired, message] of [
    ['UTC+00:00', 'UTC', /time zone "UTC\+00:00" was replaced by "UTC"/],
    ['UTC\u221208:00', 'UTC-08:00', /time zone "UTC\u221208:00" was replaced by "UTC-08:00"/],
    ['UTC+5:30', 'local', /unsupported time zone "UTC\+5:30" was replaced by "local"/],
    ['UTC+15:00', 'local', /unsupported time zone/],
    ['US/Eastern', 'local', /unsupported time zone/],
  ]) {
    const started = load(t, timezone);
    assert.equal(started.config.value.appearance.timezone, repaired, timezone);
    assert.equal(started.warnings.length, 1, timezone);
    assert.match(started.warnings[0], message);
    assert.equal(started.saved().appearance.timezone, repaired, 'the repair is saved');
    // The next start neither repeats nor logs it.
    const warnings = [];
    const warn = console.warn;
    console.warn = message => warnings.push(message);
    try {
      new ConfigStore(path.dirname(started.config.file));
    } finally {
      console.warn = warn;
    }
    assert.deepEqual(warnings, [], timezone);
  }
});

test('an unsupported saved time zone is repaired without printing control characters or more than 64 characters of it', t => {
  const crafted =
    'SYNTH-TZ-CANARY\u001b[2J\n[orbit] Uptime Goblin is ready at http://0.0.0.0:4317' +
    'A'.repeat(100000);
  const { config, warnings } = load(t, crafted);
  assert.equal(config.value.appearance.timezone, 'local');
  assert.deepEqual(warnings, [
    'Configuration: unsupported time zone "(hidden)" was replaced by "local".',
  ]);
  // One that looks like a time zone is still named, as before.
  const named = load(t, 'Mars/Olympus_Mons');
  assert.deepEqual(named.warnings, [
    'Configuration: unsupported time zone "Mars/Olympus_Mons" was replaced by "local".',
  ]);
});
