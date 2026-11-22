// gate-draft-r4: GDR3-01 and the alignment with GATE-CONTRACT v5 round 2 (sha256 d0398079…, which
// Daybreak accepted as the design baseline for this draft) and the coordinator decision that
// confirmed its change 19 (GATE-CONTRACT-v5-change19-decision.txt, sha256 aa2d5863…).
//
// - GDR3-01, a new defect fixed: t8-image-identity must end before t8-image-authenticity starts,
//   judged on both stages' valid recorded intervals (v5 change 18), not only on their order in a
//   list; directly, and through the finalizer.
// - Changed requirements from v5: the catalog's N array of 28 and O array of 25, bound to v5 and
//   binding the record-pack profile; the v5 C23 order rules a run's records can show, change 19
//   included; F's reconciliation of N's T8 records with O's t8-image-activation; neither catalog
//   build starting while its pre-build authority is pending, and the T8 and build stages never a
//   pass.
// - gate-draft-r4 read the local run record as "schema 3" and called that C12 alignment; it is
//   not (Daybreak GDR4-02): since gate-draft-r5 the record is read only as its own local family
//   (kind and kindVersion 1), a diagnostic record and no C12 phase record, with the record pack's
//   own format a separate series (test 11; test/security-record-family.test.mjs).
//
// Every run here is synthetic (test/helpers/platform-run.mjs), and every check is local
// consistency, not authority. The gate-level cases are in test/security-evidence.test.mjs, and
// the corrections of gate-draft-r4's round 2 in test/security-v5-round2.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const load = async () => ({
  catalog: await import('../scripts/security-catalog.mjs'),
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
});
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A Linux gate run and its darwin-platform companion for one synthetic candidate. */
async function scenario(t, { main = {}, companion = {}, now = Date.now() } = {}) {
  const modules = await load();
  const security = temporary(t, 'orbit-v5-alignment-');
  const candidate = modules.fixture.platformCandidate();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: main });
  const companions = [
    modules.fixture.writeCompanion(security, candidate, { now, change: companion }),
  ];
  const inspect = (at = now) =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions }, at);
  const sealed = () => modules.finalization.readSealedRun(run);
  const activation = () =>
    modules.platform.t8ActivationProblems(sealed(), {
      manifest: candidate.manifest,
      runId: 'linux-full',
      catalogSha256: modules.catalog.installedCatalog().sha256,
    });
  return { ...modules, security, candidate, run, companions, inspect, sealed, activation, now };
}
const blockers = inventory => inventory.blockers.join('\n');
const stageOf = (record, name) => record.stages.find(item => item.name === name);
const iso = ms => new Date(ms).toISOString();

// A record with a window of 0 to 100 s and stages at the given times (ms).
const at = (name, started, finished = started) => ({
  name,
  started: iso(started),
  finished: iso(finished),
});
const windowed = stages => ({ started: iso(0), finished: iso(100000), stages });

// ---------------------------------------------------------------------------------------------
// The catalog (changed requirements from v5: C1, C21, C23, C24; v5 changes 2, 4, 6, 9, 11)

// GATE-CONTRACT v5's C23 arrays, as its text gives them.
const V5 = {
  N: [
    'snapshot-clone',
    'snapshot-index',
    'snapshot-files',
    'gate-identity',
    'gate-import-closure',
    'gate-implementation',
    'candidate-policy',
    'platform-manifest',
    'pristine-copy',
    'gitleaks-version',
    'trivy-version',
    'actionlint-version',
    'docker-version',
    'npm-version',
    'runtime-identity',
    'dependencies-install',
    'dependencies-all',
    'dependencies-production',
    'registry-signatures',
    'sast-rules',
    'sast-image',
    'image-approval',
    't8-image-identity',
    't8-image-authenticity',
    'container-build',
    'container-identity',
    'systemd-test-image',
    'candidate-unchanged',
  ],
  O: [
    'sql-lint',
    'import-lint',
    'format',
    'syntax-manifest',
    'documentation',
    'workflow-analysis',
    'secrets-source',
    'secrets-history',
    'secrets-metadata',
    'source-analysis',
    'container-configuration',
    'container-vulnerabilities',
    'container-sbom',
    'scanner-database',
    'test-host',
    'runtime-identity',
    'network-policy',
    'full-tests-current-runtime',
    'platform-coverage-current-runtime',
    'minimum-runtime-available',
    'full-tests-minimum-runtime',
    'platform-coverage-minimum-runtime',
    't8-image-activation',
    'independent-review',
    'candidate-unchanged',
  ],
};

test('the catalog carries v5 C23 exactly: N 28 with both T8 stages, O 25 with t8-image-activation, the Darwin, F and scanner arrays unchanged', async () => {
  const { catalog } = await load();
  const { catalog: installed } = catalog.installedCatalog();
  assert.deepEqual(installed.profiles['linux-full'].N, V5.N);
  assert.deepEqual(installed.profiles['linux-full'].O, V5.O);
  assert.equal(V5.N.length, 28);
  assert.equal(V5.O.length, 25);
  for (const id of ['t8-image-identity', 't8-image-authenticity']) {
    assert.ok(installed.profiles['linux-full'].N.includes(id), id);
    assert.ok(!installed.profiles['linux-full'].O.includes(id), id);
  }
  assert.ok(installed.profiles['linux-full'].O.includes('t8-image-activation'));
  assert.ok(!installed.profiles['linux-full'].N.includes('t8-image-activation'));
  // Unchanged from the gate-draft-r3 catalog (v3's arrays, which v5 keeps).
  assert.equal(
    sha(catalog.canonicalJson(installed.profiles['darwin-platform'])),
    sha(
      catalog.canonicalJson({
        platform: [
          'gate-identity',
          'gate-import-closure',
          'candidate-policy',
          'platform-manifest',
          'prepared-inputs',
          'test-host',
          'npm-version',
          'runtime-identity',
          'platform-tests-current-runtime',
          'platform-coverage-current-runtime',
          'minimum-runtime-available',
          'platform-tests-minimum-runtime',
          'platform-coverage-minimum-runtime',
          'candidate-unchanged',
        ],
      })
    )
  );
  assert.deepEqual(
    [installed.finalization.commit.length, installed.finalization.release.length],
    [12, 22]
  );
  assert.deepEqual([installed.scanners.commit.length, installed.scanners.release.length], [9, 14]);
  // v5 adds no F obligation: F reconciles the T8 records within image-approvals.
  assert.ok(installed.finalization.commit.includes('image-approvals'));
  // A contract version is not an identity version: the gate identity stays version 3.
  const identity = await import('../scripts/security-gate-identity.mjs');
  assert.equal(identity.GATE_IDENTITY_VERSION, 3);
});

test('a partial migration is refused: v4 arrays, a v4 placement, another contract, catalog version 1, no record-pack binding, a stale catalog digest', async t => {
  const { catalog, platform } = await load();
  const good = catalog.installedCatalog().catalog;
  const bytes = value => Buffer.from(catalog.canonicalJson(value));
  const changed = change => {
    const value = structuredClone(good);
    change(value);
    return bytes(value);
  };
  // v4's arrays: the T8 stages in O after the N builds, no t8-image-activation (26 and 26).
  const v4 = value => {
    const { N, O } = value.profiles['linux-full'];
    value.profiles['linux-full'].N = N.filter(id => !id.startsWith('t8-image-'));
    value.profiles['linux-full'].O = [
      ...O.filter(
        id =>
          id !== 't8-image-activation' &&
          id !== 'independent-review' &&
          id !== 'candidate-unchanged'
      ),
      't8-image-identity',
      't8-image-authenticity',
      'independent-review',
      'candidate-unchanged',
    ];
  };
  for (const [label, input, pattern] of [
    ['v4 arrays (26 and 26)', changed(v4), /linux-full N lacks t8-image-identity/],
    [
      'v4 placement: the T8 stages in O',
      changed(v => {
        v.profiles['linux-full'].O.splice(-2, 0, 't8-image-identity');
      }),
      /linux-full O holds t8-image-identity: v4's placement/,
    ],
    [
      'the activation in N',
      changed(v => v.profiles['linux-full'].N.splice(-1, 0, 't8-image-activation')),
      /linux-full N holds t8-image-activation/,
    ],
    [
      'no t8-image-activation',
      changed(v => {
        v.profiles['linux-full'].O = v.profiles['linux-full'].O.filter(
          id => id !== 't8-image-activation'
        );
      }),
      /linux-full O lacks t8-image-activation/,
    ],
    [
      'a build in O',
      changed(v => v.profiles['linux-full'].O.splice(-2, 0, 'container-build')),
      /linux-full O holds container-build/,
    ],
    [
      'the v4 contract',
      changed(
        v =>
          (v.contract.sha256 = '4788c26daa09d0d4d68f300abe7b512e866c7c3a4367100a036825638a373b56')
      ),
      /not v5 .*: the arrays of another contract are a partial migration/,
    ],
    [
      'no change-19 decision',
      changed(v => (v.contract.decision = { document: 'none', sha256: '0'.repeat(64) })),
      /another decision than the coordinator's confirmation of v5 change 19/,
    ],
    [
      'catalog version 1',
      changed(v => (v.version = 1)),
      /is version 1, the form that binds no record-pack profile/,
    ],
    ['no record-pack binding', changed(v => delete v.recordPack), /the catalog lacks recordPack/],
    [
      'a record-pack binding of another profile',
      changed(v => (v.recordPack = { ...v.recordPack, name: 'captured-archive' })),
      /is not record-pack version 1/,
    ],
    ['a catalog naming no version', changed(v => delete v.version), /names no version/],
  ])
    assert.throws(() => catalog.parseCatalog(input), pattern, label);
  // A catalog whose binding names another sha256 parses as a catalog, but no producer or reader of
  // a pack accepts it (v5 C21, C24 change 11).
  const other = structuredClone(good);
  other.recordPack = { ...other.recordPack, sha256: '0'.repeat(64) };
  assert.doesNotThrow(() => catalog.parseCatalog(bytes(other)));
  assert.match(
    platform.recordPackBindingProblems(other).join('\n'),
    /the catalog binds the record-pack profile .*, not this validator's/
  );
  assert.deepEqual(platform.recordPackBindingProblems(good), []);
  // A run bound to the gate-draft-r3 catalog (v4 arrays, sha256 759a8c2e…): a stale digest.
  const stale = await scenario(t, {
    main: {
      record: r =>
        (r.catalog = {
          ...r.catalog,
          sha256: '759a8c2ec2a5627a622617f09287d09ee0f2b135ea99be3df170365244ec129f',
        }),
    },
  });
  assert.match(blockers(stale.inspect()), /records the catalog .*759a8c2e/);
});

test('the catalog binds the record-pack profile: with a catalog binding another profile, no pack is written or read', async t => {
  const { platform } = await load();
  // A copy of the gate modules whose catalog binds another record-pack sha256.
  const copy = temporary(t, 'orbit-v5-recordpack-');
  const scripts = new URL('../scripts/', import.meta.url);
  for (const name of [
    'security-catalog.mjs',
    'security-entries.mjs',
    'security-platform.mjs',
    'security-evidence.mjs',
    'security-gate-identity.mjs',
    'check-platform-coverage.mjs',
  ])
    fs.copyFileSync(new URL(name, scripts), path.join(copy, name));
  const value = JSON.parse(fs.readFileSync(new URL('security-catalog.json', scripts), 'utf8'));
  value.recordPack = { ...value.recordPack, sha256: 'f'.repeat(64) };
  const { canonicalJson } = await import('../scripts/security-catalog.mjs');
  fs.writeFileSync(path.join(copy, 'security-catalog.json'), canonicalJson(value));
  const other = await import(pathToFileURL(path.join(copy, 'security-platform.mjs')).href);
  const records = temporary(t, 'orbit-v5-records-');
  fs.writeFileSync(
    path.join(records, '4242-00000000-0000-0000-0000-000000000000.jsonl'),
    '{"kind":"result"}\n'
  );
  const pack = platform.packRecords(records);
  assert.doesNotThrow(() => platform.validatePack(pack));
  assert.throws(
    () => other.packRecords(records),
    /binds the record-pack profile .*, not this validator's/
  );
  assert.throws(
    () => other.validatePack(pack),
    /binds the record-pack profile .*, not this validator's/
  );
});

// ---------------------------------------------------------------------------------------------
// GDR3-01 (a new defect fixed; v5 change 18): identity ends before authenticity starts

test('GDR3-01: t8-image-authenticity may not start before t8-image-identity ends; the exact boundary is accepted', async () => {
  const { platform } = await load();
  const check = stages => platform.t8OrderProblems(windowed(stages), 'full-tests-');
  const gdr =
    /t8-image-identity must end before t8-image-authenticity starts: .*inclusive.*GDR3-01/;
  // Daybreak's counterexample: identity 2-5 s, authenticity 3-4 s, sql-lint at 6 s. r3 returned
  // no problem; it is refused, although the record lists identity first and no candidate code
  // starts before both end.
  assert.match(
    check([
      at('t8-image-identity', 2000, 5000),
      at('t8-image-authenticity', 3000, 4000),
      at('sql-lint', 6000, 7000),
    ]).join('\n'),
    gdr
  );
  // The exact boundary: authenticity starts at the instant identity ends.
  assert.deepEqual(
    check([
      at('t8-image-identity', 2000, 3000),
      at('t8-image-authenticity', 3000, 4000),
      at('sql-lint', 6000),
    ]),
    []
  );
  // One millisecond of overlap.
  assert.match(
    check([
      at('t8-image-identity', 2000, 3000),
      at('t8-image-authenticity', 2999, 4000),
      at('sql-lint', 6000),
    ]).join('\n'),
    gdr
  );
  // Reversed times with the record listing identity first.
  assert.match(
    check([
      at('t8-image-identity', 5000, 5500),
      at('t8-image-authenticity', 2000, 2500),
      at('sql-lint', 6000),
    ]).join('\n'),
    gdr
  );
  // Reversed record order with valid, correctly ordered times: also refused.
  assert.match(
    check([
      at('t8-image-authenticity', 3000, 4000),
      at('t8-image-identity', 2000, 3000),
      at('sql-lint', 6000),
    ]).join('\n'),
    gdr
  );
  // Missing, malformed, inverted and out-of-window times, on either stage.
  for (const [label, change, pattern] of [
    ['no start', s => delete s.started, /no recorded start and end, present and well formed/],
    ['no end', s => delete s.finished, /no recorded start and end, present and well formed/],
    [
      'a start that is not UTC',
      s => (s.started = new Date(2000).toString()),
      /no recorded start and end/,
    ],
    ['a start that is not a time', s => (s.started = 'yesterday'), /no recorded start and end/],
    ['an end before its start', s => (s.finished = iso(1000)), /an end before its start/],
    [
      'before the record window',
      s => Object.assign(s, { started: iso(-500), finished: iso(-100) }),
      /an interval outside its record's window/,
    ],
    [
      'after the record window',
      s => (s.finished = iso(200000)),
      /an interval outside its record's window/,
    ],
  ])
    for (const name of ['t8-image-identity', 't8-image-authenticity']) {
      const stages = [
        at('t8-image-identity', 2000, 3000),
        at('t8-image-authenticity', 3000, 4000),
        at('sql-lint', 6000),
      ];
      change(stages.find(item => item.name === name));
      assert.match(
        check(stages).join('\n'),
        new RegExp(`${name} has ${pattern.source}`),
        `${label}: ${name}`
      );
    }
  // A record without a valid window of its own gives no valid interval to judge.
  assert.match(
    platform
      .t8OrderProblems(
        { stages: [at('t8-image-identity', 2000, 3000), at('t8-image-authenticity', 3000, 4000)] },
        'full-tests-'
      )
      .join('\n'),
    /no record window to lie in/
  );
});

test('GDR3-01 through the finalizer: an overlapping or reversed T8 identity and authenticity is refused, the exact boundary accepted, and an activation bound to such records refused', async t => {
  const control = await scenario(t);
  assert.deepEqual(control.inspect().blockers, []);
  assert.equal(control.inspect().verdict, 'pending');
  assert.deepEqual(control.activation(), []);
  const gdr = /t8-image-identity must end before t8-image-authenticity starts/;
  // One millisecond of overlap: the activation is rebuilt from the changed records, as the gate
  // would bind them, and is refused too.
  const overlap = await scenario(t, {
    main: {
      record: r => {
        const identity = stageOf(r, 't8-image-identity');
        stageOf(r, 't8-image-authenticity').started = iso(Date.parse(identity.finished) - 1);
      },
    },
  });
  const overlapInventory = overlap.inspect();
  assert.equal(overlapInventory.eligible, false);
  assert.match(blockers(overlapInventory), gdr);
  assert.match(
    overlap.activation().join('\n'),
    /t8-image-activation binds N records that do not show t8-image-identity ends before t8-image-authenticity starts/
  );
  // The exact boundary: authenticity starts when identity ends.
  const boundary = await scenario(t, {
    main: {
      record: r =>
        (stageOf(r, 't8-image-authenticity').started = stageOf(r, 't8-image-identity').finished),
    },
  });
  assert.deepEqual(boundary.inspect().blockers, []);
  assert.equal(boundary.inspect().verdict, 'pending');
  assert.deepEqual(boundary.activation(), []);
  // The two stages' intervals swapped, the record still listing identity first.
  const reversed = await scenario(t, {
    main: {
      record: r => {
        const identity = stageOf(r, 't8-image-identity');
        const authenticity = stageOf(r, 't8-image-authenticity');
        const times = { started: identity.started, finished: identity.finished };
        Object.assign(identity, { started: authenticity.started, finished: authenticity.finished });
        Object.assign(authenticity, times);
      },
    },
  });
  assert.match(blockers(reversed.inspect()), gdr);
  // A missing time on either stage: refused.
  for (const name of ['t8-image-identity', 't8-image-authenticity']) {
    const missing = await scenario(t, { main: { record: r => delete stageOf(r, name).finished } });
    assert.equal(missing.inspect().eligible, false, name);
    assert.match(
      blockers(missing.inspect()),
      new RegExp(`${name} records no start and finish time`),
      name
    );
  }
  // The run's own records are in order, but the activation binds records that overlap.
  const bound = await scenario(t, {
    main: {
      activation: binding => {
        binding.records.authenticity.started = iso(
          Date.parse(binding.records.identity.finished) - 1
        );
      },
    },
  });
  const boundInventory = bound.inspect();
  assert.equal(boundInventory.eligible, false);
  assert.match(
    blockers(boundInventory),
    /T8 reconciliation \(image-approvals\): t8-image-activation binds another records than this run's/
  );
  assert.match(
    bound.activation().join('\n'),
    /binds N records that do not show t8-image-identity ends before t8-image-authenticity starts/
  );
});

// ---------------------------------------------------------------------------------------------
// The v5 C23 order rules on recorded intervals (changed requirements from v5)

test('v5 change 19: platform-manifest ends before container-build, systemd-test-image or any other candidate-controlled build starts', async t => {
  const { platform } = await load();
  const rule =
    /platform-manifest must end before (container-build|systemd-test-image) starts: .*change 19.*confirmed by the coordinator decision/;
  const check = stages => platform.orderProblems(windowed(stages), { prefix: 'full-tests-' });
  for (const build of platform.candidateBuildStages) {
    assert.deepEqual(
      check([at('platform-manifest', 1000, 2000), at(build, 2000, 2500)]),
      [],
      build
    );
    assert.match(
      check([at('platform-manifest', 1000, 2001), at(build, 2000, 2500)]).join('\n'),
      rule,
      build
    );
    assert.match(
      check([at(build, 500, 900), at('platform-manifest', 1000, 2000)]).join('\n'),
      rule,
      build
    );
    assert.match(
      check([{ name: 'platform-manifest' }, at(build, 2000, 2500)]).join('\n'),
      /platform-manifest has no recorded start and end, present and well formed, so it breaks the order rule that platform-manifest ends before every candidate-controlled build starts/,
      build
    );
  }
  // Through the finalizer: platform-manifest moved after container-build's start.
  const late = await scenario(t, {
    main: {
      record: r => {
        const build = stageOf(r, 'container-build');
        Object.assign(stageOf(r, 'platform-manifest'), {
          started: build.started,
          finished: build.finished,
        });
      },
    },
  });
  assert.match(
    blockers(late.inspect()),
    /platform-manifest must end before container-build starts/
  );
});

test("v5's other order rules hold on recorded intervals; a stage's place in a catalog array orders nothing", async () => {
  const { platform } = await load();
  const main = stages =>
    platform.orderProblems(windowed(stages), { prefix: 'full-tests-' }).join('\n');
  const companion = stages =>
    platform.orderProblems(windowed(stages), { prefix: 'platform-tests-' }).join('\n');
  for (const [label, problems, pattern] of [
    [
      'dependencies-install before candidate-policy ends',
      main([at('candidate-policy', 1000, 2000), at('dependencies-install', 1500)]),
      /candidate-policy must end before dependencies-install starts/,
    ],
    [
      'dependencies-install before pristine-copy',
      main([at('dependencies-install', 1000), at('pristine-copy', 2000)]),
      /pristine-copy must end before dependencies-install starts/,
    ],
    [
      'a scan of an image before image-approval',
      main([at('container-sbom', 1000), at('image-approval', 2000)]),
      /image-approval must end before container-sbom starts/,
    ],
    [
      'the Semgrep image run before image-approval',
      main([at('source-analysis', 1000), at('image-approval', 2000)]),
      /image-approval must end before source-analysis starts/,
    ],
    [
      'a test stage (the T8 driver) before image-approval',
      main([at('full-tests-current-runtime', 1000), at('image-approval', 2000)]),
      /image-approval must end before full-tests-current-runtime starts/,
    ],
    [
      'a stage between container-build and container-identity',
      main([
        at('container-build', 1000),
        at('scanner-database', 1500),
        at('container-identity', 2000),
      ]),
      /container-identity must directly follow container-build/,
    ],
    [
      'format before the lints',
      main([at('format', 1000), at('sql-lint', 2000), at('import-lint', 3000)]),
      /sql-lint must end before format starts/,
    ],
    [
      'a test stage before import-lint',
      main([at('import-lint', 1000, 3000), at('full-tests-current-runtime', 2000)]),
      /import-lint must end before full-tests-current-runtime starts/,
    ],
    [
      'runtime-identity after a full-test stage',
      main([at('full-tests-current-runtime', 1000), at('runtime-identity', 2000)]),
      /runtime-identity must end before full-tests-current-runtime starts/,
    ],
    [
      'test-host after a full-test stage',
      main([at('full-tests-minimum-runtime', 1000), at('test-host', 2000)]),
      /test-host must end before full-tests-minimum-runtime starts/,
    ],
    [
      'a coverage stage that does not directly follow its test stage',
      main([
        at('full-tests-current-runtime', 1000),
        at('network-policy', 1500),
        at('platform-coverage-current-runtime', 2000),
      ]),
      /platform-coverage-current-runtime must directly follow full-tests-current-runtime/,
    ],
    [
      'a stage after candidate-unchanged',
      main([at('candidate-unchanged', 1000), at('independent-review', 2000)]),
      /candidate-unchanged must be the last stage/,
    ],
    [
      'candidate-unchanged overlapping an earlier stage',
      main([at('independent-review', 1000, 3000), at('candidate-unchanged', 2000)]),
      /candidate-unchanged must be the last stage/,
    ],
    [
      'the activation ending after sql-lint starts',
      main([at('t8-image-activation', 1000, 2500), at('sql-lint', 2000)]),
      /t8-image-activation must end before sql-lint starts/,
    ],
    [
      'the activation after documentation',
      main([at('documentation', 1000), at('t8-image-activation', 2000)]),
      /t8-image-activation must end before documentation starts/,
    ],
    [
      'the activation after the first use of the T8 image',
      main([at('full-tests-minimum-runtime', 1000), at('t8-image-activation', 2000)]),
      /t8-image-activation must end before full-tests-minimum-runtime starts/,
    ],
    [
      'the activation before authenticity ends',
      main([at('t8-image-authenticity', 1000, 2500), at('t8-image-activation', 2000)]),
      /t8-image-authenticity must end before t8-image-activation starts/,
    ],
    [
      'a companion test stage before platform-manifest',
      companion([at('platform-tests-current-runtime', 1000), at('platform-manifest', 2000)]),
      /platform-manifest must end before platform-tests-current-runtime starts/,
    ],
    [
      'a companion coverage stage that does not directly follow',
      companion([
        at('platform-tests-minimum-runtime', 1000),
        at('runtime-identity', 1500),
        at('platform-coverage-minimum-runtime', 2000),
      ]),
      /platform-coverage-minimum-runtime must directly follow platform-tests-minimum-runtime/,
    ],
    [
      'a companion stage after candidate-unchanged',
      companion([at('candidate-unchanged', 1000), at('test-host', 2000)]),
      /candidate-unchanged must be the last stage/,
    ],
  ])
    assert.match(problems, pattern, label);
  // Array membership is never order: v5's N array lists image-approval before t8-image-identity,
  // but no rule orders the two, so either order is accepted; and a record in catalog-array order
  // whose intervals break a rule is refused.
  assert.equal(main([at('t8-image-identity', 1000), at('image-approval', 2000)]), '');
  assert.equal(main([at('image-approval', 1000), at('t8-image-identity', 2000)]), '');
  assert.match(
    main([at('t8-image-identity', 1000, 3000), at('t8-image-authenticity', 2000, 4000)]),
    /t8-image-identity must end before t8-image-authenticity starts/
  );
  // Inclusive handoffs: a stage may start at the instant its predecessor ends.
  assert.equal(
    main([
      at('candidate-policy', 1000, 2000),
      at('platform-manifest', 2000, 2000),
      at('pristine-copy', 2000, 3000),
      at('dependencies-install', 3000),
    ]),
    ''
  );
});

test('the synthetic gate run and companion keep every order rule, and moving a stage out of its place is refused by the finalizer', async t => {
  const control = await scenario(t);
  const { platform, finalization, run, companions } = control;
  assert.deepEqual(
    platform.orderProblems(finalization.readSealedRun(run).record, { prefix: 'full-tests-' }),
    []
  );
  assert.deepEqual(
    platform.orderProblems(
      finalization.readSealedRun(companions[0], { mode: 'platform', exact: true }).record,
      { prefix: 'platform-tests-' }
    ),
    []
  );
  for (const [label, change, pattern] of [
    [
      'runtime-identity after the full-test stages',
      r => {
        const identity = stageOf(r, 'runtime-identity');
        const network = stageOf(r, 'network-policy');
        Object.assign(identity, { started: network.started, finished: network.started });
      },
      /Order: .*runtime-identity must end before full-tests-current-runtime starts/,
    ],
    [
      'the activation after sql-lint started',
      r => (stageOf(r, 't8-image-activation').finished = stageOf(r, 'sql-lint').finished),
      /t8-image-activation must end before sql-lint starts/,
    ],
  ]) {
    const changed = await scenario(t, { main: { record: change } });
    assert.match(blockers(changed.inspect()), pattern, label);
  }
  // A companion whose coverage stage is moved away from its test stage.
  const companion = await scenario(t, {
    companion: {
      record: r => {
        const coverage = r.stages.findIndex(
          item => item.name === 'platform-coverage-current-runtime'
        );
        const [item] = r.stages.splice(coverage, 1);
        r.stages.splice(r.stages.length - 1, 0, item);
        const last = stageOf(r, 'candidate-unchanged');
        Object.assign(item, { started: last.started, finished: last.started });
      },
    },
  });
  assert.match(
    blockers(companion.inspect()),
    /platform-coverage-current-runtime must directly follow platform-tests-current-runtime/
  );
});

// ---------------------------------------------------------------------------------------------
// The T8 records, the builds and F's reconciliation (changed requirements from v5: C5, C14, C17
// item 12, C23; v5 changes 2 to 5)

test("F reconciles O's t8-image-activation with N's sealed T8 records under the same run, candidate, gate identity, catalog, platform, consumer and purpose", async t => {
  const control = await scenario(t);
  const inventory = control.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.verdict, 'pending');
  assert.equal(inventory.obligations['image-approvals'].status, 'pending');
  assert.match(
    inventory.obligations['image-approvals'].reason,
    /reconciliation of N's T8 identity and authenticity records .* with O's t8-image-activation, whose record forms are pending/
  );
  for (const name of ['t8-image-identity', 't8-image-authenticity', 't8-image-activation'])
    assert.match(inventory.pending.join('\n'), new RegExp(`${name} is pending`), name);
  const binding = JSON.parse(
    fs.readFileSync(path.join(control.run, control.platform.activationBindingFile), 'utf8')
  );
  assert.equal(binding.form, control.platform.ACTIVATION_PROPOSAL.form);
  assert.match(binding.form, /proposal.*not reviewed, and no producer is qualified/);
  assert.equal(binding.result, null);
  // Each dimension changed in the sealed binding: refused.
  for (const [label, change, pattern] of [
    ['another run', b => (b.run = 'another-run'), /binds another run/],
    [
      'another candidate',
      b => (b.candidateIdentitySha256 = 'e'.repeat(64)),
      /binds another candidateIdentitySha256/,
    ],
    [
      'another gate identity',
      b => (b.gateIdentity = { sha256: 'e'.repeat(64), version: 3 }),
      /binds another gateIdentity/,
    ],
    ['no gate identity', b => (b.gateIdentity = null), /binds another gateIdentity/],
    [
      'another catalog',
      b => (b.catalogSha256 = '759a8c2ec2a5627a622617f09287d09ee0f2b135ea99be3df170365244ec129f'),
      /binds another catalogSha256/,
    ],
    [
      'another platform',
      b => (b.platform = { architecture: 'amd64', os: 'linux' }),
      /binds another platform/,
    ],
    ['another consumer', b => (b.consumer = 'sast-image'), /binds another consumer/],
    ['another purpose', b => (b.purpose = 'release-scan'), /binds another purpose/],
    [
      'another image',
      b => (b.images[0].imageId = `sha256:${'e'.repeat(64)}`),
      /binds another images/,
    ],
    [
      'other N records',
      b => (b.records.identity.evidence[0].sha256 = 'e'.repeat(64)),
      /binds another records/,
    ],
    [
      'a result record',
      b => (b.result = { path: 'result.json', sha256: 'e'.repeat(64) }),
      /binds another result/,
    ],
    ['an authenticity claim', b => (b.outcome = 'verified'), /binding holds "outcome"/],
  ]) {
    const changed = await scenario(t, { main: { activation: change } });
    assert.match(
      blockers(changed.inspect()),
      new RegExp(`T8 reconciliation \\(image-approvals\\): .*${pattern.source}`),
      label
    );
  }
  // The activation stage asserting authenticity on its own, or binding nothing.
  for (const [label, change, pattern] of [
    [
      'an activation with authenticity records of its own',
      r =>
        (stageOf(r, 't8-image-activation').records = stageOf(r, 't8-image-authenticity').records),
      /t8-image-activation records "records": it is a binding check, not a second authenticity claim/,
    ],
    [
      'an activation with no binding',
      r => delete stageOf(r, 't8-image-activation').binding,
      /t8-image-activation sealed no binding of N's T8 records/,
    ],
    [
      'no t8-image-activation',
      r => (r.stages = r.stages.filter(item => item.name !== 't8-image-activation')),
      /t8-image-activation is missing/,
    ],
    [
      'the T8 stages in place of the activation',
      r => (stageOf(r, 't8-image-activation').name = 't8-image-identity'),
      /t8-image-identity is reported twice|t8-image-activation is missing|the T8 image identity and authenticity stages are missing/,
    ],
  ]) {
    const changed = await scenario(t, { main: { record: change } });
    assert.match(blockers(changed.inspect()), pattern, label);
  }
  // A run that hosts no T8 image binds nothing.
  const { platform } = control;
  const manifest = control.fixture.syntheticManifest();
  delete manifest.runs['t8-container'];
  assert.match(
    platform
      .t8ActivationProblems(control.sealed(), {
        manifest,
        runId: 'linux-full',
        catalogSha256: control.catalog.installedCatalog().sha256,
      })
      .join('\n'),
    /binds T8 records, but the run hosts no pinned T8 image/
  );
});

test('the T8 stages and both builds are never a pass, and neither image build may have started while its pre-build authority is pending', async t => {
  const { platform } = await load();
  assert.deepEqual(Object.keys(platform.pendingRecordStages).sort(), [
    'container-build',
    'container-identity',
    'systemd-test-image',
    't8-image-activation',
    't8-image-authenticity',
    't8-image-identity',
  ]);
  for (const name of Object.keys(platform.pendingRecordStages)) {
    const passed = await scenario(t, {
      main: {
        record: r => {
          const stage = stageOf(r, name);
          stage.status = 'pass';
          delete stage.reason;
        },
      },
    });
    assert.match(
      blockers(passed.inspect()),
      new RegExp(
        `${name} is recorded as passed, but .*no producer is qualified, so it is never a pass`
      ),
      name
    );
  }
  for (const name of [
    'container-build',
    'systemd-test-image',
    'container-identity',
    'container-vulnerabilities',
    'container-sbom',
  ]) {
    const ran = await scenario(t, {
      main: {
        // writeRun writes a log for each stage that names one.
        record: r =>
          Object.assign(stageOf(r, name), {
            command: ['docker', 'build', '--tag', 'synthetic', '.'],
            exit: 0,
            log: `${name}.log`,
          }),
      },
    });
    assert.match(
      blockers(ran.inspect()),
      new RegExp(
        `${name} ran: no candidate-controlled build may start while its pre-build authority is pending`
      ),
      name
    );
  }
  // t8-image-identity may have run exactly its local read-only observation, nothing else.
  const other = await scenario(t, {
    main: { record: r => stageOf(r, 't8-image-identity').command.push('--no-trunc') },
  });
  assert.match(
    blockers(other.inspect()),
    /A pending stage needs a reason and runs nothing: t8-image-identity/
  );
});

// ---------------------------------------------------------------------------------------------
// The run record: the local run family only (GDR4-02, replacing gate-draft-r4's "schema 3"
// framing: the local record is not a C12 phase record); the record pack's own format a separate
// series. test/security-record-family.test.mjs has the cross-family cases.

test('the local run record is read only as its own family (kind, kindVersion 1): other versions, no family, the frozen r4 form, cross-labelled and incomplete forms are refused before any other member is used', async t => {
  const { finalization, platform } = await load();
  const control = await scenario(t);
  const good = JSON.parse(fs.readFileSync(path.join(control.run, 'result.json'), 'utf8'));
  assert.equal(good.kind, 'orbit-gate-local-diagnostic-run');
  assert.equal(good.kindVersion, 1);
  const read = (value, mode) =>
    finalization.parseRunRecord(Buffer.from(JSON.stringify(value)), mode ? { mode } : {});
  assert.doesNotThrow(() => read(good));
  const without = (value, ...keys) => {
    const copy = structuredClone(value);
    for (const key of keys) delete copy[key];
    return copy;
  };
  const unlabelled = without(good, 'kind', 'kindVersion');
  // The earlier local form: one `parent`, no catalog binding or candidate identity.
  const older = {
    ...without(good, 'parents', 'catalog', 'candidate', 'candidateIdentitySha256'),
    parent: good.parents[0],
  };
  const frozen =
    /names schemaVersion .*: that is the frozen gate-draft-r4 local form \(schemaVersion 3\), a record pack or another form, not a record of the local run family/;
  for (const [label, value, pattern] of [
    ['the frozen r4 form (schemaVersion 3)', { ...unlabelled, schemaVersion: 3 }, frozen],
    ['schemaVersion 1', { ...unlabelled, schemaVersion: 1 }, frozen],
    ['schemaVersion 2', { ...unlabelled, schemaVersion: 2 }, frozen],
    [
      'the older form labelled schemaVersion 2',
      { ...without(older, 'kind', 'kindVersion'), schemaVersion: 2 },
      frozen,
    ],
    [
      'version 2 with another mode: the family is judged first',
      { ...good, kindVersion: 2, mode: 'scan' },
      /names kindVersion 2: only version 1 of the family is read/,
    ],
    ['the text "1"', { ...good, kindVersion: '1' }, /names kindVersion "1": only version 1/],
    ['version 2', { ...good, kindVersion: 2 }, /names kindVersion 2/],
    ['null', { ...good, kindVersion: null }, /names kindVersion null/],
    ['a list', { ...good, kindVersion: [1] }, /names kindVersion \[1\]/],
    ['no version', without(good, 'kindVersion'), /names no kindVersion: no version of the family/],
    ['no family', unlabelled, /names no record family: none is assumed or inferred/],
    [
      'another family',
      { ...good, kind: 'orbit-gate-run' },
      /names the unknown record family "orbit-gate-run"/,
    ],
    [
      'the older form labelled as the family',
      older,
      /holds "parent", which that form does not have: another form labelled as this family is refused/,
    ],
    ['an unknown member', { ...good, runNonceGuess: 'x' }, /holds "runNonceGuess"/],
    [
      'incomplete: no candidate identity',
      without(good, 'candidate'),
      /incomplete: it lacks candidate/,
    ],
    ['incomplete: no stages', without(good, 'stages'), /incomplete: it lacks stages/],
    [
      'incomplete: parents not a list',
      { ...good, parents: good.parents[0] },
      /incomplete: its parents, stages, host or candidate identity record is not of its form/,
    ],
  ])
    assert.throws(() => read(value), pattern, label);
  // A companion's form needs its run, catalog and judgment; a commit run is not one.
  const companion = JSON.parse(
    fs.readFileSync(path.join(control.companions[0], 'result.json'), 'utf8')
  );
  assert.doesNotThrow(() => read(companion, 'platform'));
  assert.throws(
    () => read(without(companion, 'platformRun'), 'platform'),
    /incomplete: it lacks platformRun/
  );
  assert.throws(
    () => read(good, 'platform'),
    /Only sealed local runs \(orbit-gate-local-diagnostic-run version 1\) of mode platform/
  );
  // A member named twice (another family, then this one) is refused by the strict reader before
  // the family is read.
  assert.throws(
    () =>
      finalization.parseRunRecord(Buffer.from(`{"kind":"other",${JSON.stringify(good).slice(1)}`)),
    /names the member "kind" twice/
  );
  // Through the finalizer: a sealed run whose record names version 2 of the family.
  const sealed2 = await scenario(t, { main: { record: r => (r.kindVersion = 2) } });
  assert.throws(() => sealed2.inspect(), /names kindVersion 2/);
  // The record pack's own format (schemaVersion 2) is a separate series: neither reader takes
  // one for the other.
  const records = temporary(t, 'orbit-v5-pack-');
  fs.writeFileSync(
    path.join(records, '4242-00000000-0000-0000-0000-000000000000.jsonl'),
    '{"kind":"result"}\n'
  );
  const pack = platform.packRecords(records);
  assert.equal(JSON.parse(pack).schemaVersion, platform.PACK_SCHEMA);
  assert.equal(platform.PACK_SCHEMA, 2);
  assert.throws(() => finalization.parseRunRecord(pack), frozen);
  assert.throws(() => platform.validatePack(Buffer.from(JSON.stringify(good))));
  assert.throws(() =>
    platform.validatePack(
      Buffer.from(pack.toString('utf8').replace('"schemaVersion":2', '"schemaVersion":3'))
    )
  );
});

// ---------------------------------------------------------------------------------------------
// What stays pending (Daybreak's gate-draft-r3 integration obligations)

test('what stays pending is named, and nothing pending becomes a pass', async t => {
  const { catalog, finalization } = await load();
  const { pending } = catalog.installedCatalog().catalog;
  assert.match(
    pending['record-forms'],
    /the exact forms of the T8 records, each build's pre-build authority record, the same-run result record and t8-image-activation's binding record/
  );
  assert.match(
    pending['record-forms'],
    /neither image build starts; the test stages, whose tests may build images .* stay pending too/
  );
  assert.match(
    pending['record-pack-bounds'],
    /path, depth and byte bounds and their workload fit, and an entry-count and byte bound for a companion run folder/
  );
  assert.match(pending.order, /separate N and O phase records/);
  assert.match(
    finalization.fObligationsOwnedByF['phase-evidence'],
    /schema 3 N and O phase records/
  );
  // Every finalization this draft writes stays pending: the F obligations are F's.
  const s = await scenario(t);
  const inventory = s.inspect();
  assert.equal(inventory.verdict, 'pending');
  for (const id of Object.keys(finalization.fObligationsOwnedByF))
    assert.equal(inventory.obligations[id].status, 'pending', id);
});
