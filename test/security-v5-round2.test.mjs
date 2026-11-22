// gate-draft-r4, round 2: the corrections after the independent check of round 1 (verify-1-order
// and verify-1-scope of the gate-draft-r4 handover). Each test names the item it covers.
//
// - Hole (fixed): v5's change 19 was checked only against container-build and systemd-test-image.
//   platform-manifest, and candidate-policy with it, must also end before every stage that
//   executes candidate code: the lints, the npm script stages and the test stages, whose tests
//   build images in this draft. In v5 the end of phase N orders these; this one-record draft has
//   no phase boundary, so they are order rules here.
// - Claim (fixed in code as well as in words): the test stages' own image builds have no
//   pre-build authority record, so the finalizer keeps every test stage pending (v5 C5).
// - Bug (fixed): a calendar-invalid time (2026-09-31, T24:00) counted as well formed.
// - Low items (fixed): an activation binding member absent or null; the catalog's arrays not
//   pinned to v5's exactly; the T8 order without an activation stage; a commit run record of a
//   candidate with the platform contract lacking its catalog or platform judgment.
//
// Every run here is synthetic (test/helpers/platform-run.mjs), and every check is local
// consistency, not authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const load = async () => ({
  catalog: await import('../scripts/security-catalog.mjs'),
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A Linux gate run and its darwin-platform companion for one synthetic candidate. */
async function scenario(t, { main = {}, now = Date.now() } = {}) {
  const modules = await load();
  const security = temporary(t, 'orbit-v5-round2-');
  const candidate = modules.fixture.platformCandidate();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: main });
  const companions = [modules.fixture.writeCompanion(security, candidate, { now })];
  const inspect = (at = now) =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions }, at);
  const sealed = () => modules.finalization.readSealedRun(run);
  const activation = () =>
    modules.platform.t8ActivationProblems(sealed(), {
      manifest: candidate.manifest,
      runId: 'linux-full',
      catalogSha256: modules.catalog.installedCatalog().sha256,
    });
  return { ...modules, candidate, run, companions, inspect, activation };
}
const blockers = inventory => inventory.blockers.join('\n');
const stageOf = (record, name) => record.stages.find(item => item.name === name);
const iso = ms => new Date(ms).toISOString();
const at = (name, started, finished = started) => ({
  name,
  started: iso(started),
  finished: iso(finished),
});
const windowed = stages => ({ started: iso(0), finished: iso(100000), stages });

/**
 * Records a synthetic gate run's stages again in `order`, each with an interval of its own, as
 * the fixture does, with the network snapshots around each test stage timed again to match.
 */
function retime(fixture, written, files, order) {
  const start = Date.parse(written.started);
  const step = Math.floor((Date.parse(written.finished) - start - 10) / written.stages.length);
  written.stages = fixture.inOrder(written.stages, order, start + 5, step);
  for (const snapshot of stageOf(written, 'network-policy')?.snapshots ?? []) {
    const stage = stageOf(written, snapshot.stage);
    const started = Date.parse(stage.started),
      finished = Date.parse(stage.finished);
    snapshot.before.readAt = iso(started - 200);
    snapshot.after.readAt = iso(finished + 200);
    files[snapshot.before.file] = `${JSON.stringify(fixture.networkState(iso(started - 400)))}\n`;
    files[snapshot.after.file] = `${JSON.stringify(
      fixture.networkState(iso(finished + 100), {
        counters: {
          'egress-drop': { packets: 5, bytes: 300 },
          'egress-allow': { packets: 0, bytes: 0 },
        },
      })
    )}\n`;
  }
}

/**
 * The gate's order with the dependency install, the npm audit stages, both builds and the stages
 * after them recorded after the test stages: every other order rule still holds, so only the rule
 * under test can refuse it.
 */
const testsBeforeInstall = gateOrder => {
  const moved = [
    'pristine-copy',
    'dependencies-install',
    'dependencies-all',
    'dependencies-production',
    'registry-signatures',
    'container-build',
    'container-identity',
    'container-vulnerabilities',
    'container-sbom',
    'systemd-test-image',
  ];
  const order = gateOrder.filter(name => !moved.includes(name));
  order.splice(order.indexOf('platform-coverage-minimum-runtime') + 1, 0, ...moved);
  return order;
};

// ---------------------------------------------------------------------------------------------
// Hole (verify-1-order): change 19 against every stage that executes candidate code

test('platform-manifest and candidate-policy end before every candidate-controlled build and every stage that executes candidate code: the lints, the npm script stages and the test stages', async () => {
  const { platform } = await load();
  const check = stages =>
    platform.orderProblems(windowed(stages), { prefix: 'full-tests-' }).join('\n');
  const later = [
    'sql-lint',
    'import-lint',
    'format',
    'syntax-manifest',
    'documentation',
    'full-tests-current-runtime',
    'full-tests-minimum-runtime',
    'container-build',
    'systemd-test-image',
  ];
  for (const name of later) {
    // The exact boundary is accepted (an inclusive handoff).
    assert.equal(check([at('platform-manifest', 1000, 2000), at(name, 2000, 2500)]), '', name);
    assert.equal(check([at('candidate-policy', 1000, 2000), at(name, 2000, 2500)]), '', name);
    // One millisecond late is refused, and the rule is named.
    assert.match(
      check([at('platform-manifest', 1000, 2001), at(name, 2000, 2500)]),
      new RegExp(`platform-manifest must end before ${name} starts: .*change 19`),
      name
    );
    assert.match(
      check([at('candidate-policy', 1000, 2001), at(name, 2000, 2500)]),
      new RegExp(
        `candidate-policy must end before ${name} starts: candidate-policy, a trusted static check of phase N`
      ),
      name
    );
    // Recorded after the stage, with times that would fit: refused (array place is not order,
    // but a rule needs both the record order and the times).
    assert.match(
      check([at(name, 500, 900), at('platform-manifest', 1000, 2000)]),
      new RegExp(`platform-manifest must end before ${name} starts`),
      name
    );
    // No valid end on platform-manifest: the rule cannot hold.
    assert.match(
      check([{ name: 'platform-manifest', started: iso(1000) }, at(name, 2000, 2500)]),
      /platform-manifest has no recorded start and end, present and well formed, so it breaks the order rule/,
      name
    );
  }
  // Stages that run no candidate code are not ordered after platform-manifest by this rule.
  for (const name of ['dependencies-all', 'secrets-source', 'scanner-database', 'test-host'])
    assert.equal(check([at(name, 500, 900), at('platform-manifest', 1000, 2000)]), '', name);
});

test('through the finalizer: platform-manifest ending after sql-lint or after a test stage starts is refused; the controls are accepted', async t => {
  const control = await scenario(t);
  assert.deepEqual(control.inspect().blockers, []);
  const { fixture } = control;
  // platform-manifest ends 1 ms after sql-lint starts (in the gate's order, before
  // dependencies-install, so no other rule is broken).
  const lint = await scenario(t, {
    main: {
      record: r =>
        (stageOf(r, 'platform-manifest').finished = iso(
          Date.parse(stageOf(r, 'sql-lint').started) + 1
        )),
    },
  });
  assert.match(
    blockers(lint.inspect()),
    /Order: .*platform-manifest must end before sql-lint starts: .*change 19/
  );
  // The same at the exact boundary: accepted.
  const lintBoundary = await scenario(t, {
    main: {
      record: r => (stageOf(r, 'platform-manifest').finished = stageOf(r, 'sql-lint').started),
    },
  });
  assert.deepEqual(lintBoundary.inspect().blockers, []);
  // The test stages before the install and both builds (every other rule still holds): accepted.
  const reordered = await scenario(t, {
    main: {
      record: (r, files) => retime(fixture, r, files, testsBeforeInstall(fixture.gateOrder)),
    },
  });
  assert.deepEqual(reordered.inspect().blockers, []);
  // Then platform-manifest ends 1 ms after the first full-test stage starts: refused, by this
  // rule (the stage runs the candidate's tests, which build images).
  const tests = await scenario(t, {
    main: {
      record: (r, files) => {
        retime(fixture, r, files, testsBeforeInstall(fixture.gateOrder));
        stageOf(r, 'platform-manifest').finished = iso(
          Date.parse(stageOf(r, 'full-tests-current-runtime').started) + 1
        );
      },
    },
  });
  assert.match(
    blockers(tests.inspect()),
    /platform-manifest must end before full-tests-current-runtime starts/
  );
  // candidate-policy ending 1 ms after sql-lint starts: refused.
  const policy = await scenario(t, {
    main: {
      record: r =>
        (stageOf(r, 'candidate-policy').finished = iso(
          Date.parse(stageOf(r, 'sql-lint').started) + 1
        )),
    },
  });
  assert.match(blockers(policy.inspect()), /candidate-policy must end before sql-lint starts/);
});

// ---------------------------------------------------------------------------------------------
// Claim (verify-1-order, verify-1-scope): the test stages' own image builds

test('every test stage stays pending while its tests may build images with no pre-build authority record; the finalizer, not the stage, judges it', async t => {
  const { platform } = await load();
  const s = await scenario(t);
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.verdict, 'pending');
  // The gate recorded both full-test stages as passed; the finalizer judges them pending.
  const record = s.finalization.readSealedRun(s.run).record;
  for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime']) {
    assert.equal(stageOf(record, name).status, 'pass', name);
    assert.ok(inventory.pending.includes(`${name} is pending`), name);
    assert.match(
      inventory.pending.join('\n'),
      new RegExp(`${name}: its tests ran with TEST_REQUIRE including docker`),
      name
    );
  }
  // A companion's test stages too: its tests run with the same TEST_REQUIRE.
  const [companion] = inventory.platform.companions;
  for (const name of ['platform-tests-current-runtime', 'platform-tests-minimum-runtime'])
    assert.ok(companion.catalog.pending.includes(name), name);
  assert.equal(inventory.obligations['required-catalogs'].status, 'pending');
  // Why: every test stage gets the gate's TEST_REQUIRE, which includes docker.
  assert.ok(platform.testRequire.split(',').includes('docker'));
  assert.match(
    platform.testStageBuilds,
    /TEST_REQUIRE including docker.*test\/installer\/docker\.test\.mjs builds the candidate's own image and a FROM scratch context.*no such build has a pre-build authority record \(v5 C5 changes 3 and 15/
  );
});

// ---------------------------------------------------------------------------------------------
// Bug (verify-1-order): calendar-invalid times

test('a time that names no real calendar instant (2026-09-31, T24:00) is malformed, directly and through the finalizer', async t => {
  const { platform } = await load();
  // A window of 2026-10-01T00:00:00Z + 100 s.
  const B = Date.parse('2026-10-01T00:00:00.000Z');
  const record = (identity, authenticity) => ({
    started: iso(B),
    finished: iso(B + 100000),
    stages: [
      { name: 't8-image-identity', ...identity },
      { name: 't8-image-authenticity', ...authenticity },
      at('sql-lint', B + 50000),
    ],
  });
  const good = record(
    { started: iso(B + 1000), finished: iso(B + 2000) },
    { started: iso(B + 2000), finished: iso(B + 3000) }
  );
  assert.deepEqual(platform.t8OrderProblems(good, 'full-tests-'), []);
  assert.deepEqual(platform.runTimeProblems(good, B + 100000), []);
  for (const [label, identity, authenticity, name] of [
    [
      'authenticity starting on 2026-09-31 (V8 reads 2026-10-01)',
      { started: iso(B + 1000), finished: iso(B + 2000) },
      { started: '2026-09-31T00:00:02.000Z', finished: iso(B + 3000) },
      't8-image-authenticity',
    ],
    [
      'identity ending at hour 24 of 2026-09-30 (V8 reads 2026-10-01T00:00:00)',
      { started: iso(B), finished: '2026-09-30T24:00:00.000Z' },
      { started: iso(B + 2000), finished: iso(B + 3000) },
      't8-image-identity',
    ],
    [
      'a minute of 60 (V8 reads no time at all)',
      { started: iso(B + 1000), finished: '2026-10-01T00:60:00.000Z' },
      { started: iso(B + 2000), finished: iso(B + 3000) },
      't8-image-identity',
    ],
  ]) {
    const value = record(identity, authenticity);
    assert.match(
      platform.t8OrderProblems(value, 'full-tests-').join('\n'),
      new RegExp(`${name} has no recorded start and end, present and well formed`),
      label
    );
    assert.match(
      platform.runTimeProblems(value, B + 100000).join('\n'),
      new RegExp(`${name} records no start and finish time`),
      label
    );
  }
  // Canonical forms of real instants stay well formed: no fraction, or one or two digits of it.
  assert.deepEqual(
    platform.t8OrderProblems(
      record(
        { started: '2026-10-01T00:00:01Z', finished: '2026-10-01T00:00:02.5Z' },
        { started: '2026-10-01T00:00:02.50Z', finished: '2026-10-01T00:00:03.000Z' }
      ),
      'full-tests-'
    ),
    []
  );
  // 29 February 2027 does not exist (V8 reads 1 March); 29 February 2028 does.
  // A run of a few seconds around that day's start, in each year.
  const leap = (started, day, finished) => ({
    started,
    finished,
    stages: [{ name: 'gate-identity', started: day, finished }],
  });
  assert.match(
    platform
      .runTimeProblems(
        leap('2027-02-28T23:59:59Z', '2027-02-29T00:00:00Z', '2027-03-01T00:00:01Z'),
        Date.parse('2027-03-01T00:00:06Z')
      )
      .join('\n'),
    /gate-identity records no start and finish time/
  );
  assert.deepEqual(
    platform.runTimeProblems(
      leap('2028-02-28T23:59:59Z', '2028-02-29T00:00:00Z', '2028-02-29T00:00:01Z'),
      Date.parse('2028-02-29T00:00:06Z')
    ),
    []
  );
  // Through the finalizer: a run near 2026-10-01T00:00:03Z whose t8-image-authenticity start is
  // written as 2026-09-31, the same instant to V8; and its control.
  const now = Date.parse('2026-10-01T00:00:03.000Z');
  const control = await scenario(t, { now });
  assert.deepEqual(control.inspect().blockers, []);
  const invalid = await scenario(t, {
    now,
    main: {
      record: r => {
        const authenticity = stageOf(r, 't8-image-authenticity');
        assert.ok(authenticity.started.startsWith('2026-10-01T'));
        authenticity.started = authenticity.started.replace('2026-10-01', '2026-09-31');
      },
    },
  });
  assert.match(
    blockers(invalid.inspect()),
    /t8-image-authenticity records no start and finish time/
  );
});

// ---------------------------------------------------------------------------------------------
// Low items

test('the activation binding must hold exactly its members: an extra member is refused even when null, and a missing member is not taken as null', async t => {
  const control = await scenario(t);
  assert.deepEqual(control.inspect().blockers, []);
  for (const [label, change, pattern] of [
    ['an extra member that is null', b => (b.extra = null), /binding holds "extra"/],
    ['an extra member that is false', b => (b.extra = false), /binding holds "extra"/],
    [
      'the result member dropped',
      b => delete b.result,
      /binding lacks result: an absent member is not taken as null/,
    ],
    [
      'the gate identity member dropped',
      b => delete b.gateIdentity,
      /binding lacks gateIdentity: an absent member is not taken as null/,
    ],
  ]) {
    const changed = await scenario(t, { main: { activation: change } });
    assert.match(
      blockers(changed.inspect()),
      new RegExp(`T8 reconciliation \\(image-approvals\\): .*${pattern.source}`),
      label
    );
    assert.match(changed.activation().join('\n'), pattern, label);
  }
});

test("the catalog's seven arrays must be exactly v5's C23 arrays, even when every placed stage is kept", async () => {
  const { catalog } = await load();
  const good = catalog.installedCatalog().catalog;
  const bytes = value => Buffer.from(catalog.canonicalJson(value));
  const changed = change => {
    const value = structuredClone(good);
    change(value);
    return bytes(value);
  };
  const without = (list, id) => list.filter(item => item !== id);
  for (const [label, input, pattern] of [
    [
      'N without gitleaks-version (27)',
      changed(
        v => (v.profiles['linux-full'].N = without(v.profiles['linux-full'].N, 'gitleaks-version'))
      ),
      /linux-full N is not v5 C23's array exactly \(28 entries, in its order\): 27 entries/,
    ],
    [
      'the F commit array without image-approvals',
      changed(v => (v.finalization.commit = without(v.finalization.commit, 'image-approvals'))),
      /finalization commit is not v5 C23's array exactly/,
    ],
    [
      'O with two entries swapped',
      changed(v => {
        const { O } = v.profiles['linux-full'];
        [O[5], O[6]] = [O[6], O[5]];
      }),
      /linux-full O is not v5 C23's array exactly \(25 entries, in its order\): 25 entries, another set or order/,
    ],
    [
      'a darwin-platform array without prepared-inputs',
      changed(
        v =>
          (v.profiles['darwin-platform'].platform = without(
            v.profiles['darwin-platform'].platform,
            'prepared-inputs'
          ))
      ),
      /darwin-platform is not v5 C23's array exactly/,
    ],
    [
      'a release scanner array with an extra scanner',
      changed(v => v.scanners.release.push('grype')),
      /scanners release is not v5 C23's array exactly/,
    ],
  ])
    assert.throws(() => catalog.parseCatalog(input), pattern, label);
  // The installed catalog's arrays are the module's copy of v5's (test/security-v5-alignment.test.mjs
  // compares the installed N, O and darwin-platform arrays with the contract's text).
  for (const [where, list] of [
    ['linux-full N', good.profiles['linux-full'].N],
    ['linux-full O', good.profiles['linux-full'].O],
    ['darwin-platform', good.profiles['darwin-platform'].platform],
    ['finalization commit', good.finalization.commit],
    ['finalization release', good.finalization.release],
    ['scanners commit', good.scanners.commit],
    ['scanners release', good.scanners.release],
  ])
    assert.deepEqual(list, catalog.CONTRACT_ARRAYS[where], where);
});

test('the T8 stages end before any candidate code also when the record has no t8-image-activation', async () => {
  const { platform } = await load();
  const check = stages => platform.t8OrderProblems(windowed(stages), 'full-tests-').join('\n');
  assert.equal(
    check([
      at('t8-image-identity', 1000, 2000),
      at('t8-image-authenticity', 2000, 3000),
      at('sql-lint', 3000, 4000),
      at('full-tests-current-runtime', 5000),
    ]),
    ''
  );
  for (const name of [
    'sql-lint',
    'import-lint',
    'format',
    'syntax-manifest',
    'documentation',
    'full-tests-current-runtime',
  ])
    for (const t8 of ['t8-image-identity', 't8-image-authenticity'])
      assert.match(
        check([
          at(name, 500, 900),
          at('t8-image-identity', 1000, 2000),
          at('t8-image-authenticity', 2000, 3000),
        ]),
        new RegExp(
          `${t8} must end before ${name} starts: the T8 image identity and authenticity end before any candidate code runs`
        ),
        `${t8} after ${name}`
      );
});

test('a commit run record of a candidate with the platform contract must hold its catalog and platform judgment; only the maintenance form may lack them', async t => {
  const { finalization } = await load();
  const control = await scenario(t);
  const good = JSON.parse(fs.readFileSync(path.join(control.run, 'result.json'), 'utf8'));
  const read = value => finalization.parseRunRecord(Buffer.from(JSON.stringify(value)));
  const without = (value, ...keys) => {
    const copy = structuredClone(value);
    for (const key of keys) delete copy[key];
    return copy;
  };
  assert.equal(good.candidate.platformManifest.state, 'valid');
  assert.doesNotThrow(() => read(good));
  // (The record is the local run family's, not a C12 phase record: GDR4-02.)
  assert.throws(() => read(without(good, 'catalog')), /incomplete: it lacks catalog \(GDR4-02\)/);
  assert.throws(() => read(without(good, 'platform')), /incomplete: it lacks platform \(GDR4-02\)/);
  assert.throws(
    () => read(without(good, 'catalog', 'platform')),
    /incomplete: it lacks catalog, platform/
  );
  // The maintenance form (its candidate identity says the manifest path never held a manifest)
  // may lack both; any other state of that path may not.
  const maintenance = {
    ...without(good, 'catalog', 'platform'),
    candidate: { ...good.candidate, platformManifest: { state: 'never-held' } },
  };
  assert.doesNotThrow(() => read(maintenance));
  for (const state of [
    { state: 'never-held', sha256: 'a'.repeat(64) },
    { state: 'Never-held' },
    null,
    'never-held',
  ])
    assert.throws(
      () => read({ ...maintenance, candidate: { ...good.candidate, platformManifest: state } }),
      /incomplete: it lacks catalog, platform/,
      JSON.stringify(state)
    );
  // Through the finalizer: a sealed contract run without its catalog is refused by the reader,
  // before any stage is read.
  const sealed = await scenario(t, { main: { record: r => delete r.catalog } });
  assert.throws(() => sealed.inspect(), /incomplete: it lacks catalog/);
});
