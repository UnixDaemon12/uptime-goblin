// The catalog of required stages and F obligations (scripts/security-catalog.json: the C23 arrays of
// GATE-CONTRACT v5 round 2, accepted by Daybreak as a design baseline; the v5 cases are in
// test/security-v5-alignment.test.mjs), the finalizer's use of it, the
// pinned Actionlint of a run (Daybreak GD-R2), the times of a main run's stages (GD-R3), the T8
// image authority (IP-01) and the run nonce. Every run here is synthetic
// (test/helpers/platform-run.mjs): test evidence for the checks, never a test or scan result.
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
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// ---------------------------------------------------------------------------------------------
// The catalog file

test('the catalog file holds exactly the C23 arrays, as canonical JSON, with what is pending', async () => {
  const { catalog, platform } = await load();
  const bytes = fs.readFileSync(new URL('../scripts/security-catalog.json', import.meta.url));
  const parsed = catalog.parseCatalog(bytes);
  assert.equal(parsed.sha256, sha(bytes));
  assert.deepEqual(catalog.installedCatalog(), parsed);
  const { profiles, finalization, scanners, pending, contract, recordPack, version } =
    parsed.catalog;
  // GATE-CONTRACT v5's C23 arrays: N 28 (the T8 identity and authenticity stages moved from O),
  // O 25 (with t8-image-activation), the Darwin, F and scanner arrays unchanged.
  assert.deepEqual(
    [
      profiles['linux-full'].N.length,
      profiles['linux-full'].O.length,
      profiles['darwin-platform'].platform.length,
      finalization.commit.length,
      finalization.release.length,
      scanners.commit.length,
      scanners.release.length,
    ],
    [28, 25, 14, 12, 22, 9, 14]
  );
  assert.equal(version, 2);
  assert.equal(contract.document, 'GATE-CONTRACT-v5.md');
  assert.equal(contract.sha256, 'd0398079284bd0a707eeb086c5b3461dbbb7b40200a1401dc810a5d64cfaa9d8');
  assert.deepEqual(contract.decision, {
    document: 'GATE-CONTRACT-v5-change19-decision.txt',
    sha256: 'aa2d586322aab80bcc4bbf23669bbaccd2c9ecc81bb235e79d099dc6d062d200',
  });
  assert.match(contract.status, /approves no implementation, this draft included, and no release/);
  // The catalog names and binds the record-pack profile: the installed validator's own.
  assert.deepEqual(recordPack, platform.recordPackIdentity());
  assert.deepEqual(Object.keys(pending).sort(), [
    'darwin-full',
    'entries',
    'order',
    'record-forms',
    'record-pack-bounds',
    'scanners',
  ]);
  // The first and last ids of each array, as C23 orders them.
  assert.deepEqual(
    [profiles['linux-full'].N[0], profiles['linux-full'].N.at(-1)],
    ['snapshot-clone', 'candidate-unchanged']
  );
  assert.deepEqual(
    [profiles['linux-full'].O[0], profiles['linux-full'].O[1]],
    ['sql-lint', 'import-lint']
  );
  assert.deepEqual(finalization.release.slice(0, 12), finalization.commit);
  // The profile a main run reports: only Linux has a reviewed array.
  assert.equal(catalog.mainProfileFor('linux'), 'linux-full');
  assert.equal(catalog.mainProfileFor('darwin'), null);
  assert.throws(() => catalog.profileStages(parsed.catalog, 'darwin-full', 'commit'), /pending/);
  assert.throws(() => catalog.profileStages(parsed.catalog, 'linux-full', 'scan'), /no mode/);
  const all = catalog.profileStages(parsed.catalog, 'linux-full', 'commit').all;
  assert.equal(all.length, 51, 'runtime-identity and candidate-unchanged are in both phases');
});

test('a catalog that is empty, duplicated, wildcard, unknown, not canonical or narrower is refused', async () => {
  const { catalog } = await load();
  const good = catalog.installedCatalog().catalog;
  const bytes = value => Buffer.from(catalog.canonicalJson(value));
  assert.doesNotThrow(() => catalog.parseCatalog(bytes(good)));
  const changed = change => {
    const value = structuredClone(good);
    change(value);
    return bytes(value);
  };
  for (const [label, input, pattern] of [
    ['pretty-printed', Buffer.from(JSON.stringify(good, null, 2)), /not canonical/],
    [
      'a member twice',
      Buffer.from(`{"version":1,${catalog.canonicalJson(good).slice(1)}`),
      /twice/,
    ],
    ['an empty array', changed(v => (v.profiles['linux-full'].O = [])), /not a nonempty list/],
    [
      'a repeated id',
      changed(v => v.profiles['darwin-platform'].platform.push('test-host')),
      /names test-host twice/,
    ],
    ['a wildcard', changed(v => v.finalization.commit.push('*')), /not a stage id/],
    ['an unknown member', changed(v => (v.extra = true)), /unknown member/],
    [
      'an unknown profile',
      changed(v => (v.profiles['linux-amd64'] = { N: ['x'] })),
      /unknown member/,
    ],
    ['another version', changed(v => (v.version = 3)), /another version/],
    [
      'version 1, which binds no record-pack profile',
      changed(v => (v.version = 1)),
      /version 1, the form that binds no record-pack profile: only version 2 is read/,
    ],
    [
      'release narrower than commit',
      changed(v => v.finalization.release.splice(3, 1)),
      /release array lacks the commit item required-catalogs/,
    ],
    ['nothing pending', changed(v => (v.pending = {})), /names nothing pending/],
  ])
    assert.throws(() => catalog.parseCatalog(input), pattern, label);
});

test('a run reports exactly its profile: missing, extra, repeated, renamed and unknown stages fail; pending is never a pass', async () => {
  const { catalog } = await load();
  const required = ['a-stage', 'b-stage', 'c-stage'];
  const records = statuses => statuses.map(([name, status]) => ({ name, status }));
  const judge = statuses => catalog.judgeStages(records(statuses), required);
  assert.equal(
    judge([
      ['a-stage', 'pass'],
      ['b-stage', 'pass'],
      ['c-stage', 'pass'],
    ]).verdict,
    'pass'
  );
  const pending = judge([
    ['a-stage', 'pass'],
    ['b-stage', 'pending'],
    ['c-stage', 'not-run'],
  ]);
  assert.deepEqual([pending.verdict, pending.pending], ['pending', ['b-stage', 'c-stage']]);
  for (const [label, statuses, pattern] of [
    [
      'missing',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'pass'],
      ],
      /c-stage is missing/,
    ],
    [
      'extra',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'pass'],
        ['c-stage', 'pass'],
        ['d-stage', 'pass'],
      ],
      /d-stage is not a stage of this profile/,
    ],
    [
      'repeated',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'pass'],
        ['c-stage', 'pass'],
        ['a-stage', 'pass'],
      ],
      /a-stage is reported twice/,
    ],
    [
      'renamed',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'pass'],
        ['c-stage', 'pass'],
        ['sast-rules-download', 'pass'],
      ],
      /one of three names for sast-rules/,
    ],
    [
      'blocked',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'blocked'],
        ['c-stage', 'pass'],
      ],
      /b-stage did not pass/,
    ],
    [
      'unknown status',
      [
        ['a-stage', 'pass'],
        ['b-stage', 'skipped'],
        ['c-stage', 'pass'],
      ],
      /unknown status/,
    ],
  ]) {
    const judged = judge(statuses);
    assert.equal(judged.verdict, 'fail', label);
    assert.match(judged.failed.join('\n'), pattern, label);
  }
  assert.equal(catalog.judgeStages('not a list', required).verdict, 'fail');
});

// ---------------------------------------------------------------------------------------------
// The finalizer and the catalog

/** A Linux gate run with a darwin-platform companion, for one synthetic candidate. */
async function scenario(t, { main = {}, companion = {}, now = Date.now() } = {}) {
  const modules = await load();
  const security = temporary(t, 'orbit-catalog-runs-');
  const candidate = modules.fixture.platformCandidate(main.candidate);
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: main.change });
  const companions = [
    modules.fixture.writeCompanion(security, candidate, { now, change: companion.change }),
  ];
  const inspect = (extra = {}, at = now) =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions, ...extra }, at);
  return { ...modules, security, candidate, run, companions, inspect, now };
}
const blockers = inventory => inventory.blockers.join('\n');

test('the finalizer selects the profile itself and judges the run against the catalog exactly', async t => {
  const s = await scenario(t);
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.catalogSha256, s.catalog.installedCatalog().sha256);
  assert.equal(inventory.profile, 'linux-full');
  for (const [label, change, pattern] of [
    [
      'an earlier name',
      r =>
        r.stages.push({
          ...r.stages.find(x => x.name === 'candidate-policy'),
          name: 'sast-rules-download',
        }),
      /sast-rules-download is reported: one of three names/,
    ],
    [
      'a missing stage',
      r => (r.stages = r.stages.filter(x => x.name !== 'gate-identity')),
      /gate-identity is missing/,
    ],
    [
      'an extra stage',
      r =>
        r.stages.push({
          ...r.stages.find(x => x.name === 'candidate-policy'),
          name: 'unreviewed-check',
        }),
      /unreviewed-check is not a stage of this profile/,
    ],
    [
      'another catalog',
      r => (r.catalog = { ...r.catalog, sha256: '0'.repeat(64) }),
      /records the catalog/,
    ],
    [
      'another profile',
      r => (r.catalog = { ...r.catalog, profile: 'darwin-platform' }),
      /records the catalog/,
    ],
    ['another mode', r => (r.catalog = { ...r.catalog, mode: 'release' }), /records the catalog/],
  ]) {
    const changed = await scenario(t, { main: { change: { record: change } } });
    assert.match(blockers(changed.inspect()), pattern, label);
  }
  // No catalog at all: the record of a candidate with the platform contract is incomplete, and the
  // local run record's reader refuses it before any stage is read (gate-draft-r4 round 2; the
  // record is the local run family's, not a C12 phase record: GDR4-02).
  const uncatalogued = await scenario(t, { main: { change: { record: r => delete r.catalog } } });
  assert.throws(() => uncatalogued.inspect(), /incomplete: it lacks catalog \(GDR4-02\)/);
  // A stage this draft does not implement, recorded pending: nothing local is wrong, the verdict
  // is pending.
  const pendingStage = await scenario(t, {
    main: {
      change: {
        record: r =>
          Object.assign(
            r.stages.find(x => x.name === 'gate-identity'),
            { status: 'pending', reason: 'synthetic: the trusted bootstrap is pending' }
          ),
      },
    },
  });
  const pendingInventory = pendingStage.inspect();
  assert.deepEqual(pendingInventory.blockers, []);
  assert.equal(pendingInventory.verdict, 'pending');
  assert.match(pendingInventory.pending.join('\n'), /gate-identity is pending/);
  // A pending stage that ran something, or says nothing about why, is refused.
  const bare = await scenario(t, {
    main: {
      change: {
        record: r =>
          Object.assign(
            r.stages.find(x => x.name === 'gate-identity'),
            { status: 'pending' }
          ),
      },
    },
  });
  assert.match(blockers(bare.inspect()), /pending stage needs a reason and runs nothing/);
});

test('the F obligations stay pending in this draft: its finalization is pending, and only a pass that F writes is accepted', async t => {
  const s = await scenario(t);
  const inventory = s.inspect();
  const commit = s.catalog.installedCatalog().catalog.finalization.commit;
  assert.deepEqual(Object.keys(inventory.obligations), commit);
  for (const id of Object.keys(s.finalization.fObligationsOwnedByF))
    assert.equal(inventory.obligations[id].status, 'pending', id);
  assert.equal(inventory.obligations['candidate-identity'].status, 'pass');
  const review = path.join(s.security, 'review.json');
  const { platform, ...binding } = s.fixture.reviewBinding(inventory);
  fs.writeFileSync(
    review,
    JSON.stringify({
      ...binding,
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(s.now).toISOString(),
      expiresAt: new Date(s.now + 3600000).toISOString(),
      unresolved: [],
      documents: {},
      dispositions: [],
    }),
    { mode: 0o600 }
  );
  assert.ok(platform);
  const current = { ...s.candidate.current, companions: s.companions };
  const approval = s.finalization.finalizeRun(s.run, review, current, s.now);
  assert.equal(approval.status, 'pending');
  assert.equal(approval.catalogSha256, inventory.catalogSha256);
  assert.match(
    approval.pending.join('\n'),
    /F obligation controller-completion: owned by F on the Mac/
  );
  const guard = { ...s.candidate.current, companions: undefined };
  assert.throws(
    () => s.finalization.validateFinalization(s.run, guard, s.now),
    /Finalization is "pending", not pass/
  );
  // As F would write it: every obligation passed. Then each binding is checked.
  s.fixture.asIfFinalizedByF(s.run);
  assert.equal(s.finalization.validateFinalization(s.run, guard, s.now).status, 'pass');
  const file = path.join(s.run, 'finalization/approval.json');
  const passed = fs.readFileSync(file, 'utf8');
  for (const [label, change, pattern] of [
    [
      'an obligation pending',
      a => (a.obligations['controller-completion'] = 'pending'),
      /every F obligation passed/,
    ],
    [
      'an obligation missing',
      a => delete a.obligations['evidence-seal'],
      /every F obligation passed/,
    ],
    ['another catalog', a => (a.catalogSha256 = '0'.repeat(64)), /installed catalog/],
    ['another profile', a => (a.profile = 'darwin-platform'), /installed catalog/],
    ['a parent added', a => a.parents.push('e'.repeat(40)), /complete candidate identity/],
    [
      'another identity',
      a => (a.candidateIdentitySha256 = '0'.repeat(64)),
      /complete candidate identity/,
    ],
  ]) {
    const approvalValue = JSON.parse(passed);
    change(approvalValue);
    fs.writeFileSync(file, JSON.stringify(approvalValue), { mode: 0o600 });
    assert.throws(() => s.finalization.validateFinalization(s.run, guard, s.now), pattern, label);
  }
});

test('a companion reports exactly the darwin-platform array: the earlier snapshot and install stages are refused', async t => {
  for (const [label, change, pattern] of [
    [
      'the earlier install stage',
      r =>
        r.stages.push({
          ...r.stages.find(x => x.name === 'npm-version'),
          name: 'dependencies-install',
          log: 'dependencies-install.log',
        }),
      /dependencies-install is not a stage of this profile/,
    ],
    [
      'prepared-inputs missing',
      r => (r.stages = r.stages.filter(x => x.name !== 'prepared-inputs')),
      /prepared-inputs is missing/,
    ],
    [
      'the grant profile',
      r => (r.catalog = { ...r.catalog, profile: 'linux-full' }),
      /records the catalog/,
    ],
  ]) {
    const s = await scenario(t, { companion: { change: { record: change } } });
    assert.match(blockers(s.inspect()), pattern, label);
  }
});

// ---------------------------------------------------------------------------------------------
// GD-R2: the pinned Actionlint of a run

test('GD-R2: a run counts the workflow analysis only from the pinned Actionlint with the gate-owned configuration', async t => {
  const s = await scenario(t);
  assert.deepEqual(s.inspect().blockers, []);
  for (const [label, change, pattern] of [
    [
      'the bare PATH binary',
      r => (r.stages.find(x => x.name === 'workflow-analysis').command = ['actionlint']),
      /did not run the pinned Actionlint/,
    ],
    [
      'another binary',
      r =>
        (r.stages.find(x => x.name === 'workflow-analysis').command[0] =
          '/usr/local/bin/actionlint'),
      /did not run the pinned Actionlint/,
    ],
    [
      'without the gate-owned configuration',
      r => r.stages.find(x => x.name === 'workflow-analysis').command.splice(1, 2),
      /did not run the pinned Actionlint/,
    ],
    [
      'a configuration that is not empty',
      (r, files) => (files['actionlint-config.yaml'] = 'paths: {}\n'),
      /did not run the pinned Actionlint/,
    ],
    [
      'a pin of another sha256',
      r => (r.stages.find(x => x.name === 'actionlint-version').tool.sha256 = '0'.repeat(64)),
      /another binary than its golden-tool record pins/,
    ],
    [
      'a pass without a pinned binary',
      r =>
        Object.assign(
          r.stages.find(x => x.name === 'actionlint-version'),
          { status: 'pending', reason: 'synthetic: no reviewed golden-tool record' }
        ),
      /passed without a pinned Actionlint/,
    ],
    [
      'no sealed golden-tool record',
      r => (r.stages.find(x => x.name === 'actionlint-version').tool.record = 'missing.json'),
      /sealed no golden-tool record/,
    ],
    [
      'a golden-tool record of another version',
      (r, files) => {
        const name = r.stages.find(x => x.name === 'actionlint-version').tool.record;
        files[name] = `${JSON.stringify({ ...JSON.parse(files[name]), version: '1.0.0' })}\n`;
      },
      /not a version 2 record of actionlint/,
    ],
  ]) {
    const changed = await scenario(t, { main: { change: { record: change } } });
    assert.match(blockers(changed.inspect()), pattern, label);
  }
  // Pending Actionlint stages leave the verdict pending, never pass.
  const pending = await scenario(t, {
    main: {
      change: {
        record: r => {
          for (const name of ['actionlint-version', 'workflow-analysis']) {
            const index = r.stages.findIndex(x => x.name === name);
            // Each keeps its own recorded interval, so the run's order holds (v5 C23).
            const { started, finished } = r.stages[index];
            r.stages.splice(index, 1, {
              name,
              status: 'pending',
              reason: 'synthetic: no reviewed golden-tool record',
              // What the gate names when no reviewed pin exists (Codex decision 8).
              missingPin: s.platform.missingToolPin({
                tool: 'actionlint',
                version: r.tools.actionlint,
                platform: r.host.platform,
                arch: r.host.arch,
              }),
              started,
              finished,
            });
          }
        },
      },
    },
  });
  const inventory = pending.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.match(inventory.pending.join('\n'), /actionlint-version is pending/);
  assert.match(inventory.pending.join('\n'), /workflow-analysis is pending/);
});

// verify-1: candidate code runs between actionlint-version and workflow-analysis, so a passing
// workflow-analysis must show that the binary it ran still had the pinned sha256 immediately
// before and after it ran (scripts/security-gate.mjs records both).
test('GD-R2: a passing workflow-analysis shows the pinned sha256 immediately before and after it ran', async t => {
  const s = await scenario(t);
  assert.deepEqual(s.inspect().blockers, []);
  const analysis = r => r.stages.find(x => x.name === 'workflow-analysis');
  for (const [label, change] of [
    ['no sha256 recorded', r => delete analysis(r).binarySha256],
    ['changed before it ran', r => (analysis(r).binarySha256.before = '0'.repeat(64))],
    ['changed while it ran', r => (analysis(r).binarySha256.after = '0'.repeat(64))],
    ['only one of the two', r => (analysis(r).binarySha256 = { before: 'f'.repeat(64) })],
    [
      'given as one-item lists',
      r => (analysis(r).binarySha256 = { before: ['f'.repeat(64)], after: ['f'.repeat(64)] }),
    ],
  ]) {
    const changed = await scenario(t, { main: { change: { record: change } } });
    assert.match(
      blockers(changed.inspect()),
      /did not show that the binary it ran still had the pinned sha256 immediately before and after it ran/,
      label
    );
  }
});

// verify-1: after its commit exists, a finalization is read again (recordedApproval, behind
// --verify-commit and the reference-transaction hook) with everything that does not depend on the
// moment the commit was made: for a candidate with a platform contract, the installed catalog with
// exactly its F obligations passed, the reviewed platform evidence and companions that still
// verify as sealed.
test('a recorded approval of a candidate with a platform contract binds the installed catalog, exactly its F obligations, its review and its companions', async t => {
  const s = await scenario(t);
  const inventory = s.inspect();
  const review = path.join(s.security, 'review.json');
  const { platform, ...binding } = s.fixture.reviewBinding(inventory);
  fs.writeFileSync(
    review,
    JSON.stringify({
      ...binding,
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(s.now).toISOString(),
      expiresAt: new Date(s.now + 3600000).toISOString(),
      unresolved: [],
      documents: {},
      dispositions: [],
    }),
    { mode: 0o600 }
  );
  assert.ok(platform);
  s.finalization.finalizeRun(
    s.run,
    review,
    { ...s.candidate.current, companions: s.companions },
    s.now
  );
  // As this draft writes it: pending, so no recorded approval.
  assert.throws(
    () => s.finalization.recordedApproval(s.run, { lintStages: s.candidate.current.lintStages }),
    /not a commit pass/
  );
  s.fixture.asIfFinalizedByF(s.run);
  const recorded = s.finalization.recordedApproval(s.run, {
    lintStages: s.candidate.current.lintStages,
  });
  assert.equal(recorded.approval.status, 'pass');
  const file = path.join(s.run, 'finalization/approval.json');
  assert.equal(recorded.approvalSha256, sha(fs.readFileSync(file)));
  const passed = fs.readFileSync(file, 'utf8');
  for (const [label, change, pattern] of [
    ['another catalog', a => (a.catalogSha256 = '0'.repeat(64)), /installed catalog/],
    ['an obligation missing', a => delete a.obligations['evidence-seal'], /installed catalog/],
    ['an obligation added', a => (a.obligations.anything = 'pass'), /installed catalog/],
    ['an obligation pending', a => (a.obligations.freshness = 'pending'), /installed catalog/],
    ['no profile', a => delete a.profile, /installed catalog/],
    ['no catalog binding', a => delete a.catalogSha256, /without a catalog binding approves only/],
    ['other platform evidence', a => (a.platform.excused = ['x']), /reviewed platform evidence/],
    ['a parent added', a => a.parents.push('e'.repeat(40)), /sealed run or its retained review/],
  ]) {
    const value = JSON.parse(passed);
    change(value);
    fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
    assert.throws(
      () => s.finalization.recordedApproval(s.run, { lintStages: s.candidate.current.lintStages }),
      pattern,
      label
    );
  }
  fs.writeFileSync(file, passed, { mode: 0o600 });
  assert.equal(
    s.finalization.recordedApproval(s.run, { lintStages: s.candidate.current.lintStages }).approval
      .status,
    'pass'
  );
  // A companion changed after it was finalized: refused.
  const companionResult = path.join(s.companions[0], 'result.json');
  fs.appendFileSync(companionResult, ' ');
  assert.throws(
    () => s.finalization.recordedApproval(s.run, { lintStages: s.candidate.current.lintStages }),
    /Run evidence changed/
  );
});

test('a golden-tool record is strict: tool, platform, architecture, version, absolute path, digests and review', async () => {
  const { platform, fixture } = await load();
  const good = fixture.goldenActionlint('linux', Date.now());
  const pin = { tool: 'actionlint', platform: 'linux', arch: 'arm64', version: good.version };
  const bytes = value => Buffer.from(JSON.stringify(value));
  assert.equal(platform.parseGoldenTool(bytes(good), pin).path, good.path);
  for (const [label, change] of [
    ['another tool', v => (v.tool = 'trivy')],
    ['another platform', v => (v.platform = 'darwin')],
    ['another architecture', v => (v.arch = 'x64')],
    ['another version', v => (v.version = '0.0.1')],
    ['a relative path', v => (v.path = 'bin/actionlint')],
    ['a path that is not normalized', v => (v.path = '/synthetic/../actionlint')],
    ['a sha256 in a list', v => (v.sha256 = ['f'.repeat(64)])],
    ['no review', v => delete v.reviewer],
    ['an unknown field', v => (v.verified = true)],
    ['no provenance', v => delete v.provenance],
  ]) {
    const value = structuredClone(good);
    change(value);
    assert.throws(() => platform.parseGoldenTool(bytes(value), pin), undefined, label);
  }
  assert.deepEqual(platform.actionlintArguments('/x/actionlint-config.yaml'), [
    '-config-file',
    '/x/actionlint-config.yaml',
    '-shellcheck=',
    '-pyflakes=',
    '-no-color',
  ]);
  for (const file of [
    '.github/actionlint.yaml',
    '.github/actionlint.yml',
    '.github/ACTIONLINT.YAML',
  ])
    assert.equal(platform.actionlintCandidateConfig(file), true, file);
  for (const file of [
    '.github/workflows/actionlint.yaml',
    'actionlint.yaml',
    '.github/actionlint.json',
  ])
    assert.equal(platform.actionlintCandidateConfig(file), false, file);
});

// ---------------------------------------------------------------------------------------------
// GD-R3: the times of a main run and its stages

test('GD-R3: every stage of a main run lies inside the run, and the run inside the 24-hour ceiling', async t => {
  const now = Date.now();
  const at = offset => new Date(now + offset).toISOString();
  const stage = (r, name = 'candidate-policy') => r.stages.find(x => x.name === name);
  for (const [label, change, pattern] of [
    [
      'a stage wholly before the run',
      r => Object.assign(stage(r), { started: at(-5000), finished: at(-4000) }),
      /candidate-policy is outside the run's times/,
    ],
    [
      'a stage wholly after the run',
      r => Object.assign(stage(r), { started: at(-500), finished: at(-400) }),
      /candidate-policy is outside the run's times/,
    ],
    [
      'a stage ending before it starts',
      r => Object.assign(stage(r), { started: at(-1100), finished: at(-1900) }),
      /finishes before it starts/,
    ],
    [
      'a stage without times',
      r => (delete stage(r).started, delete stage(r).finished),
      /records no start and finish time/,
    ],
    [
      'a stage time that is not UTC',
      r => (stage(r).started = new Date(now - 1500).toString()),
      /records no start and finish time/,
    ],
    [
      'a test stage outside the run',
      r => (stage(r, 'full-tests-current-runtime').finished = at(-100)),
      /full-tests-current-runtime is outside the run's times/,
    ],
    ['the run finishing in the future', r => (r.finished = at(3600000)), /finishes later than now/],
    [
      'inverted run times',
      r => Object.assign(r, { started: at(-1000), finished: at(-2000) }),
      /invalid or inverted times/,
    ],
  ]) {
    const s = await scenario(t, { now, main: { change: { record: change } } });
    assert.match(blockers(s.inspect()), pattern, label);
  }
  // At the boundaries: the first stage starting exactly at the run's start, and the last ending
  // exactly at its end, are inside. (A stage spanning the whole run would also break v5's order
  // rules, which other stages' intervals must keep.)
  const edges = await scenario(t, {
    now,
    main: {
      change: {
        record: r => {
          r.stages[0].started = r.started;
          r.stages.at(-1).finished = r.finished;
        },
      },
    },
  });
  assert.deepEqual(edges.inspect().blockers, []);
  // The ceiling: a run that started exactly 24 hours before now is inside it (v3's proposed
  // inclusive reading); one millisecond more is stale.
  const s = await scenario(t, { now });
  const started = Date.parse(
    JSON.parse(fs.readFileSync(path.join(s.run, 'result.json'), 'utf8')).started
  );
  const day = 24 * 60 * 60 * 1000;
  // (Without the companion, which started earlier and has a ceiling of its own.)
  const at24 = s.inspect({ companions: [] }, started + day);
  assert.doesNotMatch(blockers(at24), /stale/);
  assert.match(blockers(at24), /No companion run covers darwin-platform/);
  assert.match(
    blockers(s.inspect({ companions: [] }, started + day + 1)),
    /stale: it started more than 24 hours ago/
  );
});

// ---------------------------------------------------------------------------------------------
// IP-01: the T8 image authority; the run nonce and patterns only on strings

test('a consistent image authenticity record still leaves the T8 image check pending: it is evidence, not authority', async t => {
  const s = await scenario(t);
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.match(inventory.pending.join('\n'), /no reviewed activation record \(v3 C5\)/);
  assert.match(inventory.pending.join('\n'), /index digest as the image ID/);
  // A record of the config digest as the image ID (the classic store) is still not authority.
  const reasons = s.platform.imageAuthorityPending(
    { indexDigest: `sha256:${'a'.repeat(64)}` },
    { image: 'synthetic@sha256:x', imageId: `sha256:${'b'.repeat(64)}` }
  );
  assert.equal(reasons.length, 1);
  assert.match(reasons[0], /activation record/);
});

test('the run nonce and the record patterns apply only to strings: a list holding the value is refused', async () => {
  const { coverage, platform, fixture } = await load();
  const manifest = fixture.syntheticManifest();
  const checked = nonce =>
    coverage
      .checkCoverage({
        manifest,
        manifestSha256: sha(fixture.manifestText(manifest)),
        runId: 'darwin-platform',
        runtime: '26',
        tap: 'TAP version 13\n1..0\n# tests 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n',
        records: [],
        nonce,
        allFiles: fixture.testFiles,
      })
      .problems.join('\n');
  assert.doesNotMatch(checked('a'.repeat(64)), /run nonce/);
  for (const nonce of [['a'.repeat(64)], [['a'.repeat(64)]], undefined, 7])
    assert.match(
      checked(nonce),
      /the run nonce is not 64 lowercase hex digits/,
      JSON.stringify(nonce)
    );
  assert.equal(platform.matches(/^[0-9a-f]{64}$/, 'a'.repeat(64)), true);
  assert.equal(platform.matches(/^[0-9a-f]{64}$/, ['a'.repeat(64)]), false);
  const records = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-catalog-records-')));
  fs.chmodSync(records, 0o700);
  try {
    assert.throws(
      () => platform.testEnvironment({}, { records, run: ['a'.repeat(64)] }),
      /run code must be 64 lowercase hex digits/
    );
    assert.equal(
      platform.testEnvironment({}, { records, run: 'a'.repeat(64) }).TEST_PLATFORM_RUN,
      'a'.repeat(64)
    );
  } finally {
    fs.rmSync(records, { recursive: true, force: true });
  }
});

test('a scan that completed with findings counts for the catalog; its findings go to the review', async t => {
  const s = await scenario(t, {
    main: {
      change: {
        record: (r, files) => {
          Object.assign(
            r.stages.find(x => x.name === 'secrets-source'),
            { exit: 10, status: 'blocked' }
          );
          files['secrets-source.json'] = JSON.stringify([
            {
              RuleID: 'synthetic-key',
              File: 'example.mjs',
              StartLine: 1,
              EndLine: 1,
              Fingerprint: 'synthetic:1',
              Secret: 'REDACTED',
            },
          ]);
        },
      },
    },
  });
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.findings.length, 1);
  assert.doesNotMatch(inventory.pending.join('\n'), /secrets-source/);
  // The same stage blocked by an execution problem still fails.
  const broken = await scenario(t, {
    main: {
      change: {
        record: r =>
          Object.assign(
            r.stages.find(x => x.name === 'secrets-source'),
            { exit: 10, status: 'blocked' }
          ),
      },
    },
  });
  assert.match(blockers(broken.inspect()), /Scanner exit and findings disagree/);
});

// gate-draft-r9, round 2 (check-1 of gate-draft-r9, CONTRACT-T4; GDR8-AUTH-SCAN-01): the
// recorded-approval reader skipped every scanner stage recorded as pending, so a contract
// (catalog-bound) approval whose secrets-source was recorded pending although it ran (its command,
// sealed log and finding exit, a finding in its sealed report) and that counted no finding gave
// authority, while the finalizer refuses that run ("A pending stage needs a reason and runs
// nothing"). Both now apply one pending-stage rule (pendingStageProblem): a pending stage needs a
// reason and records nothing a command leaves (no command, log, exit, signal or error), as the gate
// withholds a stage; only t8-image-identity may have run its read-only inspect. Each twin below is
// a second run of the clean run's candidate that differs in its secrets-source stage, with the
// clean run's recorded approval (finalized by this tree and passed as F would) rebound to it, as an
// earlier finalizer could have written it: only the reader judges it.
test('GDR8-AUTH-SCAN-01, round 2 (check-1 CONTRACT-T4): the finalizer and the recorded-approval reader apply one pending-stage rule, so a contract approval whose scanner is recorded as pending although it ran gives no authority', async t => {
  const s = await scenario(t);
  const current = { ...s.candidate.current, companions: s.companions };
  const lint = { lintStages: s.candidate.current.lintStages };
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  const reviewFile = path.join(s.security, 'review.json');
  const { platform, ...binding } = s.fixture.reviewBinding(inventory);
  assert.ok(platform);
  fs.writeFileSync(
    reviewFile,
    JSON.stringify({
      ...binding,
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(s.now).toISOString(),
      expiresAt: new Date(s.now + 3600000).toISOString(),
      unresolved: [],
      documents: {},
      dispositions: [],
    }),
    { mode: 0o600 }
  );
  s.finalization.finalizeRun(s.run, reviewFile, current, s.now);
  s.fixture.asIfFinalizedByF(s.run);
  assert.equal(s.finalization.recordedApproval(s.run, lint).approval.status, 'pass');
  const finding = JSON.stringify([
    {
      RuleID: 'synthetic-key',
      File: 'example.mjs',
      StartLine: 1,
      EndLine: 1,
      Fingerprint: 'synthetic:0',
      Secret: 'REDACTED',
    },
  ]);
  const stageOf = (record, name) => record.stages.find(item => item.name === name);
  let twins = 0;
  const twin = change => {
    const run = path.join(s.security, `${s.candidate.current.tree}-commit-twin-${(twins += 1)}`);
    s.fixture.writeMainRun(run, s.candidate, {
      platform: 'linux',
      now: s.now,
      change: { record: change },
    });
    const finalized = path.join(run, 'finalization');
    fs.mkdirSync(finalized, { mode: 0o700 });
    const runSha256 = sha(fs.readFileSync(path.join(run, 'run-manifest.json')));
    const clean = path.join(s.run, 'finalization');
    const review = JSON.parse(fs.readFileSync(path.join(clean, 'review.json'), 'utf8'));
    review.runSha256 = runSha256;
    const reviewBytes = Buffer.from(JSON.stringify(review));
    fs.writeFileSync(path.join(finalized, 'review.json'), reviewBytes, { mode: 0o600 });
    const approval = JSON.parse(fs.readFileSync(path.join(clean, 'approval.json'), 'utf8'));
    Object.assign(approval, { runSha256, reviewSha256: sha(reviewBytes), findings: 0 });
    fs.writeFileSync(path.join(finalized, 'approval.json'), JSON.stringify(approval), {
      mode: 0o600,
    });
    return { run, inventory: s.finalization.inspectRun(run, current, s.now) };
  };
  // Control of the twin construction: an unchanged twin is accepted.
  const unchanged = twin(() => {});
  assert.deepEqual(unchanged.inventory.blockers, []);
  assert.equal(s.finalization.recordedApproval(unchanged.run, lint).approval.status, 'pass');
  const pendingRule = /A pending stage needs a reason and runs nothing: secrets-source/;
  const readerRefusal =
    /The recorded approval's sealed scanner results are not those the finalizer accepts, so it gives no authority \(GDR8-AUTH-SCAN-01\): .*A pending stage needs a reason and runs nothing: secrets-source/;
  for (const [label, change] of [
    [
      'CONTRACT-T4: recorded pending with a reason, but it ran (its command, sealed log and exit 10), a finding in its report',
      (record, files) => {
        files['secrets-source.json'] = finding;
        Object.assign(stageOf(record, 'secrets-source'), {
          status: 'pending',
          reason: 'synthetic: recorded pending after it ran',
          exit: 10,
        });
      },
    ],
    [
      'recorded pending with a reason and no command, but with its sealed log and exit 10, a finding in its report',
      (record, files) => {
        files['secrets-source.json'] = finding;
        const stage = stageOf(record, 'secrets-source');
        delete stage.command;
        Object.assign(stage, { status: 'pending', reason: 'synthetic: no command', exit: 10 });
      },
    ],
    [
      'recorded pending with no reason, nothing run',
      record => {
        const stage = stageOf(record, 'secrets-source');
        for (const key of ['command', 'log', 'exit', 'signal']) delete stage[key];
        stage.status = 'pending';
      },
    ],
  ]) {
    const { run, inventory: judged } = twin(change);
    // The finalizer refuses it ...
    assert.equal(judged.eligible, false, label);
    assert.match(judged.blockers[0], pendingRule, label);
    const before = fs.readFileSync(path.join(run, 'run-manifest.json'));
    // ... and so does the recorded-approval reader now, naming the same rule.
    assert.throws(() => s.finalization.recordedApproval(run, lint), readerRefusal, label);
    assert.deepEqual(fs.readFileSync(path.join(run, 'run-manifest.json')), before, label);
  }
  // Still accepted by both: a scanner withheld as the gate withholds it (a reason, nothing run),
  // gives no findings at either. gate-draft-r10 (GDR9-AUTH-SCAN-02): the fixture now seals no report
  // for it, as the gate writes none; one sealed beside it is refused (the GDR9-AUTH-SCAN-02 test).
  const withheld = twin(record => {
    const stage = stageOf(record, 'secrets-source');
    for (const key of ['command', 'log', 'exit', 'signal']) delete stage[key];
    Object.assign(stage, { status: 'pending', reason: 'synthetic: withheld before dispatch' });
  });
  assert.equal(fs.existsSync(path.join(withheld.run, 'secrets-source.json')), false);
  assert.deepEqual(withheld.inventory.blockers, []);
  assert.equal(withheld.inventory.findings.length, 0);
  assert.equal(s.finalization.recordedApproval(withheld.run, lint).approval.findings, 0);
});

// gate-draft-r10, GDR9-AUTH-SCAN-02 (review finding; Codex's GATE decision 6): a withheld or no-run
// scanner could carry a sealed fixed report that neither the finalizer nor the recorded-approval
// reader read (Daybreak's P4, CONTRACT-R2-6), and the synthetic fixtures sealed every report for
// every run, a withheld scanner's included, so they defined that as normal. The fixtures now seal a
// scanner's report only when its stage ran, as the gate creates one only when it starts the
// scanner, and one shared reconciliation of stages and reports (scannerReportProblems), used by
// the finalizer and the reader alike, refuses a report beside a scanner recorded as pending,
// empty, malformed or not, and a report whose scanner has no stage. A genuinely withheld scanner
// without a report, and a scanner that ran, are judged as before.
test('GDR9-AUTH-SCAN-02: the fixtures seal no report for a withheld scanner, and the finalizer refuses a report sealed beside a withheld scanner through the reconciliation it shares with the recorded-approval reader (whose refusals, and those of the entry points, are in test/security-parents.test.mjs)', async t => {
  const s = await scenario(t);
  // The linux-full fixture withholds the scans of the built image, as the gate does: no report.
  const sealed = s.finalization.readSealedRun(s.run);
  assert.equal(
    sealed.record.stages.find(item => item.name === 'container-vulnerabilities').status,
    'pending'
  );
  assert.equal(sealed.has('container-security.json'), false);
  assert.deepEqual(s.inspect().blockers, []);
  const image = `sha256:${'a'.repeat(64)}`;
  const cleanImageReport = JSON.stringify({
    SchemaVersion: 2,
    Trivy: {
      Version: JSON.parse(
        fs.readFileSync(new URL('../scripts/security-tools.json', import.meta.url), 'utf8')
      ).trivy,
    },
    ArtifactID: image,
    ArtifactName: 'synthetic:tag',
    Metadata: { ImageID: image },
    Results: [{ Target: 'synthetic OS', Class: 'os-pkgs', Vulnerabilities: [] }],
  });
  const finding = JSON.stringify([
    {
      RuleID: 'synthetic-key',
      File: 'example.mjs',
      StartLine: 1,
      EndLine: 1,
      Fingerprint: 'synthetic:0',
      Secret: 'REDACTED',
    },
  ]);
  const withheld = record => {
    const stage = record.stages.find(item => item.name === 'secrets-source');
    for (const key of ['command', 'log', 'exit', 'signal']) delete stage[key];
    Object.assign(stage, { status: 'pending', reason: 'synthetic: withheld before dispatch' });
  };
  const pendingReport = name =>
    new RegExp(
      `${name} is recorded as pending \\(withheld, nothing run\\), but its fixed report \\S+ is sealed with the run`
    );
  for (const [label, change, pattern] of [
    [
      'the built image withheld, a clean image report sealed beside it (as the fixtures sealed one before)',
      (record, files) => (files['container-security.json'] = cleanImageReport),
      pendingReport('container-vulnerabilities'),
    ],
    [
      "Daybreak's P4: secrets-source withheld, a finding in its sealed report",
      (record, files) => {
        withheld(record);
        files['secrets-source.json'] = finding;
      },
      pendingReport('secrets-source'),
    ],
    [
      'secrets-source withheld, a zero-byte report',
      (record, files) => {
        withheld(record);
        files['secrets-source.json'] = '';
      },
      pendingReport('secrets-source'),
    ],
    [
      'secrets-source withheld, a malformed report',
      (record, files) => {
        withheld(record);
        files['secrets-source.json'] = '[{';
      },
      pendingReport('secrets-source'),
    ],
  ]) {
    const changed = await scenario(t, { main: { change: { record: change } } });
    const inventory = changed.inspect();
    assert.equal(inventory.eligible, false, label);
    assert.match(inventory.blockers[0], new RegExp(`^Scanner reports: ${pattern.source}`), label);
  }
  // Positives: withheld with no report, and a scanner that ran with a finding (its review then
  // disposes of it).
  const quiet = await scenario(t, { main: { change: { record: withheld } } });
  assert.deepEqual(quiet.inspect().blockers, []);
  assert.equal(quiet.finalization.readSealedRun(quiet.run).has('secrets-source.json'), false);
  const ran = await scenario(t, {
    main: {
      change: {
        record: (record, files) => {
          Object.assign(
            record.stages.find(item => item.name === 'secrets-source'),
            { exit: 10, status: 'blocked' }
          );
          files['secrets-source.json'] = finding;
        },
      },
    },
  });
  assert.deepEqual(ran.inspect().blockers, []);
  assert.equal(ran.inspect().findings.length, 1);
});
