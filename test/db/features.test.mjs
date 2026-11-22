// Feature flags (lib/features.mjs, roadmap §2.7): capabilities by configuration, admin toggles
// in the platform/features settings document, and dark-launch experiments.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createFeatures,
  capabilities,
  toggles,
  experiments,
  featureClasses,
  featureToggles,
} from '../../lib/features.mjs';
import { createSettings, memorySettingsStore } from '../../lib/settings.mjs';

const meta = createdBy => ({
  calls: 0,
  async get(key) {
    this.calls += 1;
    assert.equal(key, 'created_by_release');
    return createdBy;
  },
});

test('the catalogue: three classes, unique names, each entry dated', () => {
  assert.deepEqual(featureClasses, ['capability', 'toggle', 'experimental']);
  const names = [...capabilities, ...toggles, ...experiments].map(entry => entry.name);
  assert.equal(new Set(names).size, names.length);
  for (const entry of [...capabilities, ...toggles])
    assert.match(entry.since, /^\d+\.\d+\.\d+$/, entry.name);
  assert.deepEqual(experiments, [], 'no experiments in 1.5');
  assert.deepEqual(
    Object.keys(featureToggles.fields),
    toggles.map(toggle => toggle.name)
  );
  assert.equal(featureToggles.fields.mfaPolicy.default, 'off');
  assert.throws(() => createFeatures({}), /running release/);
});

test('legacy Basic: on for installs upgraded from 1.4.x until 1.6, off for new installs, the environment wins (G2, D-2)', async () => {
  const upgraded = createFeatures({ env: {}, meta: meta(null), release: '1.5.0' });
  assert.equal(await upgraded.enabled('legacyBasic'), true);
  const created = createFeatures({ env: {}, meta: meta('1.5.0'), release: '1.5.0' });
  assert.equal(await created.enabled('legacyBasic'), false);
  // From 1.6 (pre-releases included) it is off on upgraded installs too.
  for (const release of ['1.6.0', '1.6.0-rc.1'])
    assert.equal(
      await createFeatures({ env: {}, meta: meta(null), release }).enabled('legacyBasic'),
      false,
      release
    );
  // GOBLIN_LEGACY_BASIC decides when set.
  const forced = createFeatures({
    env: { GOBLIN_LEGACY_BASIC: '1' },
    meta: meta('1.5.0'),
    release: '1.6.0',
  });
  assert.equal(await forced.enabled('legacyBasic'), true);
  const off = createFeatures({
    env: { GOBLIN_LEGACY_BASIC: 'off' },
    meta: meta(null),
    release: '1.5.0',
  });
  assert.equal(await off.enabled('legacyBasic'), false);
  // 2.0 removes it.
  const gone = createFeatures({
    env: { GOBLIN_LEGACY_BASIC: '1' },
    meta: meta(null),
    release: '2.0.0',
  });
  assert.equal(await gone.enabled('legacyBasic'), false);
  assert.ok(!(await gone.list()).some(row => row.name === 'legacyBasic'));
  // created_by_release is read once.
  const counting = meta(null);
  const features = createFeatures({ env: {}, meta: counting, release: '1.5.0' });
  await features.enabled('legacyBasic');
  await features.list();
  assert.equal(counting.calls, 1);
});

test('capabilities by configuration: presence or a 1/0 value; a value that is neither warns, or refuses for legacy Basic', async () => {
  const env = {
    GOBLIN_INSECURE_HTTP_SESSIONS: 'yes',
    GOBLIN_DATABASE_URL: 'postgres://x',
  };
  const features = createFeatures({ env, meta: meta('1.5.0'), release: '1.7.0' });
  assert.equal(await features.enabled('insecureHttpSessions'), true);
  assert.equal(await features.enabled('postgres'), true, 'presence is enough');
  assert.equal(await features.enabled('oidc'), false);
  assert.deepEqual(features.warnings, []);
  // A flag that is neither yes nor no warns and keeps its default (off).
  const typo = createFeatures({
    env: { GOBLIN_INSECURE_HTTP_SESSIONS: 'maybe' },
    meta: meta('1.5.0'),
    release: '1.5.0',
  });
  assert.equal(await typo.enabled('insecureHttpSessions'), false, 'the default applies');
  assert.deepEqual(typo.warnings, [
    'GOBLIN_INSECURE_HTTP_SESSIONS="maybe" is not 1 or 0; the default applies.',
  ]);
  // Except GOBLIN_LEGACY_BASIC, whose default is on for upgraded installs: such a value refuses
  // (exit status 78; server.mjs refuses it first, before anything is written), whatever the
  // install. In a release that no longer has the feature it is only said to be ignored.
  for (const created of [null, '1.5.0'])
    assert.throws(
      () =>
        createFeatures({
          env: { GOBLIN_LEGACY_BASIC: 'maybe' },
          meta: meta(created),
          release: '1.5.0',
        }),
      error =>
        error.refusal === true &&
        error.message ===
          'GOBLIN_LEGACY_BASIC must be 1 or 0 (true, yes or on; false, no or off), or empty for the default; it is "maybe".'
    );
  assert.deepEqual(
    createFeatures({ env: { GOBLIN_LEGACY_BASIC: 'maybe' }, meta: meta(null), release: '2.0.0' })
      .warnings,
    [
      'GOBLIN_LEGACY_BASIC is set, but this release no longer has that feature (removed in 2.0.0); it is ignored.',
    ]
  );
  // In 1.5 the 1.7 capabilities do not exist yet, whatever the environment says.
  const early = createFeatures({ env, meta: meta('1.5.0'), release: '1.5.0' });
  assert.equal(await early.enabled('postgres'), false);
  await assert.rejects(early.enabled('teleport'), /Unknown feature/);
});

test('admin toggles come from the platform/features settings document', async () => {
  const settings = createSettings({
    store: memorySettingsStore(),
    definitions: [featureToggles],
    env: {},
  });
  const features = createFeatures({ env: {}, meta: meta('1.5.0'), settings, release: '1.5.0' });
  assert.equal(await features.enabled('heartbeat'), false);
  await settings.update('platform', 'features', { heartbeat: true, mfaPolicy: 'admins' });
  assert.equal(await features.enabled('heartbeat'), true);
  // A toggle newer than the release is unavailable even when the document sets it.
  assert.equal(await features.enabled('mfaPolicy'), false);
  const later = createFeatures({ env: {}, meta: meta('1.5.0'), settings, release: '1.6.0' });
  assert.equal(await later.enabled('mfaPolicy'), 'admins');
  // Without settings, toggles read their defaults.
  const bare = createFeatures({ env: {}, release: '1.6.0' });
  assert.equal(await bare.enabled('mfaPolicy'), 'off');
  assert.equal(await bare.enabled('lifecycleNotice'), false);
});

test('list() shows what this release has, with class, source and environment variable', async () => {
  const settings = createSettings({
    store: memorySettingsStore(),
    definitions: [featureToggles],
    env: {},
  });
  await settings.update('platform', 'features', { lifecycleNotice: true });
  const features = createFeatures({
    env: { GOBLIN_INSECURE_HTTP_SESSIONS: '1', GOBLIN_EXPERIMENTAL: 'warp, ,' },
    meta: meta(null),
    settings,
    release: '1.5.0-rc.2',
  });
  const rows = await features.list();
  assert.deepEqual(
    rows.map(row => [row.name, row.class, row.enabled, row.source]),
    [
      ['legacyBasic', 'capability', true, 'default'],
      ['insecureHttpSessions', 'capability', true, 'env'],
      ['lifecycleNotice', 'toggle', true, 'settings'],
      ['heartbeat', 'toggle', false, 'settings'],
    ]
  );
  assert.equal(rows[1].env, 'GOBLIN_INSECURE_HTTP_SESSIONS');
  assert.ok(!('env' in rows[2]));
  assert.deepEqual(features.warnings, [
    'GOBLIN_EXPERIMENTAL names "warp", which this release does not have; it is ignored.',
  ]);
  assert.equal(features.experimental('warp'), false);
  const all = await features.list({ all: true });
  assert.equal(all.length, capabilities.length + toggles.length + experiments.length);
  assert.equal(all.find(row => row.name === 'oidc').source, 'unavailable');
});
