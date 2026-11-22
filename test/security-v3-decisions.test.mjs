// Daybreak's decisions on the choices GATE-CONTRACT v3 put to review (its review of v3, table
// "Decisions on the draft's requested choices"), where this draft implements them: F chooses the
// mode, the profile and the catalog itself and compares each with what a record names; the T8
// image stages come before the candidate code they guard (as GATE-CONTRACT v5 now places them:
// identity and authenticity before every candidate-controlled build, the activation before any
// candidate code in O); final-artifacts is an F
// release obligation, not a stage of a run; the 24-hour ceiling is inclusive. And gate-harness-r3's
// string-only run nonce stays. The gate-level cases are in test/security-evidence.test.mjs. Every
// run here is synthetic (test/helpers/platform-run.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const load = async () => ({
  catalog: await import('../scripts/security-catalog.mjs'),
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  coverage: await import('../scripts/check-platform-coverage.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

async function scenario(
  t,
  { main = {}, companion = {}, companionRun, manifest, now = Date.now() } = {}
) {
  const modules = await load();
  const security = temporary(t, 'orbit-v3-decisions-');
  const candidate = modules.fixture.platformCandidate(manifest ? { manifest } : {});
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: main });
  const companions = [
    modules.fixture.writeCompanion(security, candidate, {
      now,
      change: companion,
      ...(companionRun ? { runId: companionRun } : {}),
    }),
  ];
  const inspect = (at = now) =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions }, at);
  return { ...modules, candidate, run, companions, inspect, now };
}
const blockers = inventory => inventory.blockers.join('\n');

test('F selects the main profile itself, from the installed catalog and the judged manifest, never from the run', async t => {
  const s = await scenario(t);
  const { catalog } = s.catalog.installedCatalog();
  assert.deepEqual(s.platform.selectMainProfile(catalog, s.candidate.manifest), {
    profile: 'linux-full',
    platform: 'linux',
    declared: 'linux',
  });
  // The platform is F's own (PROFILE_PLATFORMS), not the manifest's: a manifest that declares
  // linux-full on darwin still gives linux, with what it declared beside it (verify-1 of
  // gate-draft-r3 found the platform taken from the manifest).
  assert.deepEqual(s.catalog.PROFILE_PLATFORMS, {
    'darwin-platform': 'darwin',
    'linux-full': 'linux',
  });
  const onDarwin = structuredClone(s.candidate.manifest);
  onDarwin.runs['linux-full'].platform = 'darwin';
  assert.deepEqual(s.platform.selectMainProfile(catalog, onDarwin), {
    profile: 'linux-full',
    platform: 'linux',
    declared: 'darwin',
  });
  // A profile F binds no platform to is not selected.
  assert.equal(
    s.platform.selectMainProfile(
      { profiles: { 'other-full': { N: ['a'], O: ['b'] } } },
      { runs: { 'other-full': { platform: 'linux', files: 'all' } } }
    ),
    null
  );
  // No single full run with a reviewed main array: F selects nothing.
  const withoutLinux = structuredClone(s.candidate.manifest);
  delete withoutLinux.runs['linux-full'];
  assert.equal(s.platform.selectMainProfile(catalog, withoutLinux), null);
  assert.equal(s.platform.selectMainProfile(catalog, { runs: [] }), null);
  assert.equal(s.platform.selectMainProfile({ profiles: {} }, s.candidate.manifest), null);
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.profile, 'linux-full');
  // A run on another host is not the run F selected, whatever it says of its own profile; a run
  // naming another profile, mode or catalog is refused.
  for (const [label, change, pattern] of [
    [
      'a gate run on darwin that claims linux-full',
      r => (r.host.platform = 'darwin'),
      /F selected the profile linux-full, a run on linux; this gate run ran on "darwin"/,
    ],
    [
      'a run naming the darwin-platform profile',
      r => (r.catalog = { ...r.catalog, profile: 'darwin-platform' }),
      /records the catalog .*not .*"profile":"linux-full"/,
    ],
    [
      'a run naming no profile',
      r => (r.catalog = { ...r.catalog, profile: null }),
      /records the catalog/,
    ],
    [
      'a run naming the release mode',
      r => (r.catalog = { ...r.catalog, mode: 'release' }),
      /records the catalog/,
    ],
    [
      'a run naming another catalog',
      r => (r.catalog = { ...r.catalog, sha256: 'f'.repeat(64) }),
      /records the catalog/,
    ],
  ]) {
    const changed = await scenario(t, { main: { record: change } });
    assert.match(blockers(changed.inspect()), pattern, label);
  }
});

// verify-1 of gate-draft-r3: the main profile's platform came from the candidate's own manifest,
// so an introduction manifest (no earlier manifest to compare with) that declares linux-full on
// darwin made a darwin gate run the selected one, and it was eligible. F binds the platform of a
// catalog profile itself (PROFILE_PLATFORMS): such a manifest is refused, for the main run and for
// a companion alike.
test("F binds each catalog profile's platform itself: a manifest that declares it on another platform is refused", async t => {
  const modules = await load();
  const security = temporary(t, 'orbit-v3-profile-platform-');
  const now = Date.now();
  const manifest = modules.fixture.syntheticManifest();
  manifest.runs['linux-full'].platform = 'darwin';
  delete manifest.runs['darwin-full'];
  manifest.runs['t8-container'].hostRuns = ['linux-full'];
  manifest.entries = manifest.entries.filter(entry => entry.id !== 'linux.acl');
  for (const entry of manifest.entries) {
    if (entry.id.startsWith('t8.driver')) {
      entry.platforms = ['darwin'];
      entry.evidence = ['linux-full'];
    }
    if (entry.id === 'mac.acl') entry.evidence = ['darwin-platform', 'linux-full'];
  }
  const candidate = modules.fixture.platformCandidate({ manifest });
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, {
    platform: 'darwin',
    now,
    change: { record: r => (r.catalog = modules.fixture.catalogOf('linux-full')) },
  });
  const inventory = modules.finalization.inspectRun(
    run,
    { ...candidate.current, companions: [] },
    now
  );
  assert.equal(inventory.eligible, false);
  assert.match(
    blockers(inventory),
    /The candidate's manifest declares linux-full on "darwin", but F binds the profile linux-full to linux itself/
  );
  // A companion of a catalog profile that the manifest declares on another platform.
  assert.throws(
    () =>
      modules.platform.checkCompanion(
        {
          name: 'synthetic-companion',
          record: {
            kind: 'orbit-gate-local-diagnostic-run',
            kindVersion: 1,
            mode: 'platform',
            status: 'pass',
            platformRun: 'darwin-platform',
          },
        },
        { manifest: { runs: { 'darwin-platform': { platform: 'linux' } } } }
      ),
    /the candidate's manifest declares darwin-platform on "linux", but F binds the profile darwin-platform to darwin itself/
  );
});

test('F selects each companion profile itself: a companion of a run the candidate does not need is refused', async t => {
  const control = await scenario(t);
  assert.deepEqual(blockers(control.inspect()), '');
  // The companion's own record names a profile F did not select for it.
  const claimed = await scenario(t, {
    companion: {
      record: r => {
        r.platformRun = 'linux-full';
        r.catalog = { ...r.catalog, profile: 'linux-full' };
      },
    },
  });
  assert.match(
    blockers(claimed.inspect()),
    /covers no run this candidate still needs|F selected no such companion profile|it ran on/
  );
  // A companion record naming another mode or catalog than F's.
  for (const [label, change] of [
    ['another mode', r => (r.catalog = { ...r.catalog, mode: 'release' })],
    ['another catalog', r => (r.catalog = { ...r.catalog, sha256: 'f'.repeat(64) })],
  ]) {
    const changed = await scenario(t, { companion: { record: change } });
    assert.match(blockers(changed.inspect()), /records the catalog/, label);
  }
});

// GATE-CONTRACT v5 replaces v3's single placement of the T8 stages (both in O, before any
// candidate code), which Daybreak's review of v3 accepted only on that condition and the N builds
// broke (GCV4-01): t8-image-identity and t8-image-authenticity now run in N, before every
// candidate-controlled build, and the distinct t8-image-activation in O, before every stage that
// executes candidate code (v5 changes 2 and 4). The v5 cases themselves are in
// test/security-v5-alignment.test.mjs; this keeps the earlier cases, judged by v5's rules.
test('the T8 image identity and authenticity stages come before every candidate-controlled build, and the activation before any candidate code in O', async t => {
  const { platform } = await load();
  const at = (name, started, finished = started) => ({
    name,
    started: new Date(started).toISOString(),
    finished: new Date(finished).toISOString(),
  });
  const run = stages => ({
    started: new Date(0).toISOString(),
    finished: new Date(100000).toISOString(),
    stages,
  });
  const ok = [
    at('candidate-policy', 1000),
    at('t8-image-identity', 2000),
    at('t8-image-authenticity', 3000),
    at('t8-image-activation', 3000, 3500),
    at('sql-lint', 3500, 4000),
    at('import-lint', 4000),
    at('container-build', 4500),
    at('full-tests-current-runtime', 5000),
  ];
  assert.deepEqual(platform.t8OrderProblems(run(ok), 'full-tests-'), []);
  // The two image builds run the RUN steps of the candidate's own Dockerfiles: the
  // candidate-controlled build instructions of a run (v5 C3, C5).
  assert.deepEqual([...platform.candidateBuildStages].sort(), [
    'container-build',
    'systemd-test-image',
  ]);
  assert.deepEqual([...platform.candidateCodeStages].sort(), [
    'documentation',
    'format',
    'import-lint',
    'sql-lint',
    'syntax-manifest',
  ]);
  for (const build of ['container-build', 'systemd-test-image']) {
    const first = run([at(build, 500, 900), ...ok.filter(item => item.name !== build)]);
    assert.match(
      platform.t8OrderProblems(first, 'full-tests-').join('\n'),
      new RegExp(`t8-image-identity must end before ${build} starts`),
      build
    );
    const overlapping = run([
      ...ok.slice(0, 3).map(item => ({ ...item })),
      at(build, 2500, 2600),
      ...ok.slice(3).filter(item => item.name !== build),
    ]);
    assert.match(
      platform.t8OrderProblems(overlapping, 'full-tests-').join('\n'),
      new RegExp(`t8-image-authenticity must end before ${build} starts`),
      `${build} in time`
    );
    // After the T8 stages, in order and in time: no problem.
    const after = run([...ok.filter(item => item.name !== build), at(build, 6000)]);
    assert.deepEqual(platform.t8OrderProblems(after, 'full-tests-'), [], `${build} after`);
  }
  // npm ci --ignore-scripts runs no candidate script: not counted.
  assert.deepEqual(
    platform.t8OrderProblems(run([at('dependencies-install', 500, 900), ...ok]), 'full-tests-'),
    []
  );
  const moved = (from, to) => {
    const stages = ok.map(item => ({ ...item }));
    const [item] = stages.splice(from, 1);
    stages.splice(to, 0, item);
    return run(stages);
  };
  for (const [label, record, pattern] of [
    [
      'the activation after sql-lint',
      run(
        ok.map(item =>
          item.name === 't8-image-activation' ? at('t8-image-activation', 3000, 3800) : item
        )
      ),
      /t8-image-activation must end before sql-lint starts/,
    ],
    [
      'identity after the activation',
      run(ok.map(item => (item.name === 't8-image-identity' ? at(item.name, 3200) : item))),
      /t8-image-identity must end before t8-image-activation starts/,
    ],
    [
      'authenticity recorded before identity',
      moved(2, 1),
      /t8-image-identity must end before t8-image-authenticity starts/,
    ],
    [
      'a test stage first in time',
      run(
        ok.map(item => (item.name === 'full-tests-current-runtime' ? at(item.name, 1500) : item))
      ),
      /t8-image-activation must end before full-tests-current-runtime starts/,
    ],
    [
      'no times',
      run(ok.map(item => (item.name === 't8-image-identity' ? { name: item.name } : item))),
      /t8-image-identity has no recorded start and end, present and well formed/,
    ],
  ])
    assert.match(platform.t8OrderProblems(record, 'full-tests-').join('\n'), pattern, label);
  // A companion that hosts T8: before its own test stages.
  assert.match(
    platform
      .t8OrderProblems(
        run([at('platform-tests-current-runtime', 1000), at('t8-image-identity', 2000)]),
        'platform-tests-'
      )
      .join('\n'),
    /must end before platform-tests-current-runtime starts/
  );
  // In a finalized run: the synthetic gate run has them in the gate's order; moved to the end,
  // refused.
  const control = await scenario(t);
  assert.deepEqual(control.inspect().blockers, []);
  const late = await scenario(t, {
    main: {
      record: r => {
        const t8 = r.stages.filter(item => item.name.startsWith('t8-image-'));
        const last = Date.parse(r.stages.at(-1).finished);
        t8.forEach((item, index) => {
          item.started = new Date(last + index + 1).toISOString();
          item.finished = item.started;
        });
        r.stages = [...r.stages.filter(item => !item.name.startsWith('t8-image-')), ...t8];
      },
    },
  });
  assert.match(
    blockers(late.inspect()),
    /t8-image-identity must end before container-build starts/
  );
  // Either image build moved before the T8 stages, in order and in time: refused.
  for (const build of ['container-build', 'systemd-test-image']) {
    const early = await scenario(t, {
      main: {
        record: r => {
          const [item] = r.stages.splice(
            r.stages.findIndex(x => x.name === build),
            1
          );
          const identity = r.stages.find(x => x.name === 't8-image-identity');
          item.started = identity.started;
          item.finished = identity.started;
          r.stages.splice(
            r.stages.findIndex(x => x.name === 't8-image-identity'),
            0,
            item
          );
        },
      },
    });
    const inventory = early.inspect();
    assert.equal(inventory.eligible, false, build);
    assert.match(
      blockers(inventory),
      new RegExp(`t8-image-identity must end before ${build} starts`),
      build
    );
  }
});

test('final-artifacts is an F release obligation, never a stage of a run', async () => {
  const { catalog } = await load();
  const { finalization, profiles } = catalog.installedCatalog().catalog;
  assert.ok(finalization.release.includes('final-artifacts'));
  assert.ok(!finalization.commit.includes('final-artifacts'));
  for (const phases of Object.values(profiles))
    for (const list of Object.values(phases)) assert.ok(!list.includes('final-artifacts'));
  const required = ['a-stage'];
  const judged = catalog.judgeStages(
    [
      { name: 'a-stage', status: 'pass' },
      { name: 'final-artifacts', status: 'blocked' },
    ],
    required
  );
  assert.equal(judged.verdict, 'fail');
  assert.match(
    judged.failed.join('\n'),
    /final-artifacts is reported: a release F obligation, not a stage of a run/
  );
});

test('the 24-hour ceiling is inclusive, for a main run and a companion run alike; every stage stays inside its run', async t => {
  const { platform } = await load();
  const now = Date.parse('2026-10-14T12:00:00.000Z');
  const DAY = 24 * 60 * 60 * 1000;
  const run = started => ({
    started: new Date(started).toISOString(),
    finished: new Date(started + 1000).toISOString(),
    stages: [
      {
        name: 'a',
        started: new Date(started).toISOString(),
        finished: new Date(started + 1000).toISOString(),
      },
    ],
  });
  assert.deepEqual(platform.runTimeProblems(run(now - DAY), now + 0), []);
  assert.match(
    platform.runTimeProblems(run(now - DAY - 1), now).join('\n'),
    /stale: it started more than 24 hours ago/
  );
  // Through the finalizer: F at exactly 24 hours after the earlier start (the companion's)
  // accepts both runs; one millisecond later, that run is stale.
  const exact = await scenario(t);
  const startOf = file => Date.parse(JSON.parse(fs.readFileSync(file, 'utf8')).started);
  const earliest = Math.min(
    startOf(path.join(exact.run, 'result.json')),
    startOf(path.join(exact.companions[0], 'result.json'))
  );
  assert.doesNotMatch(blockers(exact.inspect(earliest + DAY)), /the run is stale/);
  assert.match(
    blockers(exact.inspect(earliest + DAY + 1)),
    /the run is stale: it started more than 24 hours ago/
  );
  // Every shorter bound is still enforced on its own, and the earliest wins: the synthetic
  // scanner database expires an hour after the run, so at 24 hours it already refuses.
  assert.match(
    blockers(exact.inspect(earliest + DAY)),
    /Vulnerability database evidence is missing or stale/
  );
});

test("gate-harness-r3's run nonce stays a string only: a list holding it is refused", async () => {
  const { coverage, fixture } = await load();
  const manifest = fixture.syntheticManifest();
  const checked = nonce =>
    coverage
      .checkCoverage({
        manifest,
        manifestSha256: createHash('sha256').update(fixture.manifestText(manifest)).digest('hex'),
        runId: 'darwin-platform',
        runtime: '26',
        tap: 'TAP version 13\n1..0\n# tests 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n',
        records: [],
        nonce,
        allFiles: fixture.testFiles,
      })
      .problems.join('\n');
  assert.doesNotMatch(checked('a'.repeat(64)), /run nonce/);
  for (const nonce of [['a'.repeat(64)], [['a'.repeat(64)]]])
    assert.match(checked(nonce), /the run nonce is not 64 lowercase hex digits/);
});
