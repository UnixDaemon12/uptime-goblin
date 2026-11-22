import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sourceManifest, sha256, testTotals, checkReview } from '../scripts/security-evidence.mjs';
import { requiredLintStages, packageScripts } from '../scripts/check-security-approval.mjs';
import { inspectRun } from '../scripts/security-finalization.mjs';
import {
  allStages,
  candidate,
  finalizedRun,
  maintenanceInputs,
  securityTools,
  writeRun,
} from './helpers/security-run.mjs';
import { declareGit } from './helpers/git.mjs';
import { syntheticAuthority } from './helpers/dispatch-authority.mjs';
import { gateRuntimes, writeRuntimeIdentity } from './helpers/runtime-identity.mjs';

// The tests that make a repository, run the gate or install the commit guard run Git.
const gitSkip = declareGit();

const repository = fileURLToPath(new URL('..', import.meta.url));
// The gate and the modules it imports, which a fixture repository copies.
const gateScripts = [
  'security-gate.mjs',
  'security-evidence.mjs',
  'security-finalization.mjs',
  'security-findings.mjs',
  'security-platform.mjs',
  'security-catalog.mjs',
  'security-catalog.json',
  'security-entries.mjs',
  'security-gate-identity.mjs',
  'security-dispatch.mjs',
  'security-authority.mjs',
  'check-platform-coverage.mjs',
];
function temporary(t, prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
const blobId = (bytes, algorithm = 'sha1') =>
  createHash(algorithm)
    .update(`blob ${Buffer.byteLength(bytes)}\0`)
    .update(bytes)
    .digest('hex');
const entry = (file, bytes, mode = '100644', algorithm = 'sha1') =>
  `${mode} blob ${blobId(bytes, algorithm)}\t${file}\0`;
const totals = (values = {}) =>
  Object.entries({ tests: 2, pass: 2, fail: 0, cancelled: 0, skipped: 0, todo: 0, ...values })
    .map(([name, value]) => `# ${name} ${value}`)
    .join('\n') + '\n';
// The 1.5 lint commands as candidate-policy requires them (in a canonical package.json), with
// synthetic lint sources that say they ran (the gate runs those files itself).
const gateLintFiles = {
  'package.json': `${JSON.stringify(
    {
      scripts: {
        'lint:sql': 'node scripts/sql-lint.mjs',
        'lint:imports': 'node scripts/import-graph.mjs',
      },
    },
    null,
    2
  )}\n`,
  'scripts/sql-lint.mjs': "console.log('synthetic sql-lint ran');\n",
  'scripts/import-graph.mjs': "console.log('synthetic import-graph ran');\n",
};

function reviewFixture() {
  const files = [
    'README.md',
    'docs/security.md',
    'deploy/manifest.txt',
    'test/synthetic.md',
    'server.mjs',
  ].map(file => ({ file }));
  const context = { tree: 'a'.repeat(40), parents: ['b'.repeat(40), 'd'.repeat(40)], files };
  const review = {
    tree: context.tree,
    parents: context.parents,
    reviewer: 'Independent fixture reviewer',
    reference: 'synthetic-review.txt',
    unresolved: [],
    documents: {
      'README.md': { status: 'updated', reason: 'Describes the changed behavior.' },
      'docs/security.md': {
        status: 'checked unchanged',
        reason: 'Security contract remains accurate.',
      },
      'deploy/manifest.txt': { status: 'checked unchanged', reason: 'No runtime file added.' },
    },
  };
  return { context, review };
}
const releaseAreas = [
  'threatModel',
  'authentication',
  'ssrf',
  'storageRecovery',
  'browserAccessibility',
  'installUpgradeRollback',
  'historyPublication',
  'artifactSignatures',
  'buildProvenance',
  'platformMatrix',
  'netxeoAudit',
  'performance',
  'clairImageScan',
  'snykScan',
];

test('source manifest binds Git blob IDs, actual bytes and executable mode', t => {
  const root = temporary(t, 'orbit-evidence-source-');
  const bytes = Buffer.from([0, 255, 13, 10, 42]);
  fs.writeFileSync(path.join(root, 'binary.dat'), bytes, { mode: 0o644 });
  fs.writeFileSync(path.join(root, 'run.sh'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const manifest = sourceManifest(
    root,
    entry('binary.dat', bytes) + entry('run.sh', '#!/bin/sh\nexit 0\n', '100755')
  );
  assert.deepEqual(manifest[0], {
    file: 'binary.dat',
    mode: '100644',
    blob: blobId(bytes),
    sha256: sha256(bytes),
  });
  assert.equal(manifest[1].mode, '100755');
  assert.equal(
    sourceManifest(root, entry('binary.dat', bytes, '100644', 'sha256'))[0].blob.length,
    64
  );
  fs.writeFileSync(path.join(root, 'binary.dat'), 'changed bytes');
  assert.throws(
    () => sourceManifest(root, entry('binary.dat', bytes)),
    /content or executable mode/
  );
  // Git's executable bit is the owner's; group/other execute bits are not a substitute.
  fs.chmodSync(path.join(root, 'run.sh'), 0o654);
  assert.throws(
    () => sourceManifest(root, entry('run.sh', '#!/bin/sh\nexit 0\n', '100755')),
    /content or executable mode/
  );
  fs.chmodSync(path.join(root, 'run.sh'), 0o644);
  assert.throws(
    () => sourceManifest(root, entry('run.sh', '#!/bin/sh\nexit 0\n', '100755')),
    /content or executable mode/
  );
});

test('source manifest rejects unsupported tree modes, missing files and path escapes', t => {
  const root = temporary(t, 'orbit-evidence-modes-');
  for (const listing of [
    '120000 blob ' + 'a'.repeat(40) + '\tlink\0',
    '160000 commit ' + 'a'.repeat(40) + '\tsubmodule\0',
    '040000 tree ' + 'a'.repeat(40) + '\tdirectory\0',
  ])
    assert.throws(() => sourceManifest(root, listing), /unsupported/);
  assert.throws(() => sourceManifest(root, entry('../outside.txt', 'synthetic')), /escapes/);
  assert.throws(() => sourceManifest(root, entry('missing.txt', 'synthetic')), /ENOENT/);
  fs.mkdirSync(path.join(root, 'directory'));
  assert.throws(() => sourceManifest(root, entry('directory', 'synthetic')), /not a regular file/);
});

test('source manifest rejects direct and ancestor symlinks even with matching bytes', t => {
  const root = temporary(t, 'orbit-evidence-links-');
  const outside = temporary(t, 'orbit-evidence-outside-');
  const bytes = 'Synthetic identical contents.\n';
  fs.writeFileSync(path.join(outside, 'file.txt'), bytes, { mode: 0o644 });
  fs.symlinkSync(path.join(outside, 'file.txt'), path.join(root, 'link.txt'));
  assert.throws(() => sourceManifest(root, entry('link.txt', bytes)));
  fs.symlinkSync(outside, path.join(root, 'docs'), 'dir');
  assert.throws(() => sourceManifest(root, entry('docs/file.txt', bytes)));
});

test('TAP totals accept a complete passing run and reject missing or duplicate totals', () => {
  assert.deepEqual(
    testTotals('TAP version 13\nok 1 - synthetic\nok 2 - synthetic\n1..2\n' + totals()),
    { tests: 2, pass: 2, fail: 0, cancelled: 0, skipped: 0, todo: 0 }
  );
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    assert.throws(
      () => testTotals(totals().replace(new RegExp(`^# ${name} .*\\n`, 'm'), '')),
      /Missing or ambiguous/,
      name
    );
    assert.throws(() => testTotals(totals() + `# ${name} 0\n`), /Missing or ambiguous/, name);
  }
  assert.throws(() => testTotals(''), /Missing or ambiguous/);
});

test('TAP totals fail closed for failing, skipped, cancelled, todo and inconsistent runs', () => {
  for (const values of [
    { fail: 1 },
    { cancelled: 1 },
    { skipped: 1 },
    { todo: 1 },
    { tests: 0, pass: 0 },
    { tests: 3, pass: 2 },
    { tests: 1, pass: 2 },
  ])
    assert.throws(
      () => testTotals(totals(values)),
      /Incomplete test coverage/,
      JSON.stringify(values)
    );
  for (const bad of ['-1', '2.5', 'NaN', 'Infinity', '9'.repeat(400), '9007199254740993'])
    assert.throws(() => testTotals(totals({ tests: bad, pass: bad })), undefined, bad);
});

test('independent review is bound to the exact tree and complete parent vector and closes every document', () => {
  const { context, review } = reviewFixture();
  assert.doesNotThrow(() => checkReview(review, context));
  for (const changed of [
    { tree: 'c'.repeat(40) },
    { parents: ['c'.repeat(40), 'd'.repeat(40)] },
    { parents: ['d'.repeat(40), 'b'.repeat(40)] },
    { parents: ['b'.repeat(40)] },
    { parents: [...context.parents, 'c'.repeat(40)] },
    { parents: 'b'.repeat(40) },
    { parents: undefined },
  ])
    assert.throws(
      () => checkReview({ ...review, ...changed }, context),
      /does not match/,
      JSON.stringify(changed)
    );
  // A review naming a single parent is the earlier form: no authority, even for one parent
  // (maintainer decision "C18 legacy approvals").
  assert.throws(
    () =>
      checkReview(
        { ...review, parents: ['b'.repeat(40)], parent: 'b'.repeat(40) },
        { ...context, parents: ['b'.repeat(40)] }
      ),
    /names a single parent, which gives no authority/
  );
  for (const key of ['reviewer', 'reference'])
    for (const value of [undefined, '', '   '])
      assert.throws(
        () => checkReview({ ...review, [key]: value }, context),
        /reviewer and an evidence reference/
      );
  for (const unresolved of [undefined, ['Synthetic unresolved issue']])
    assert.throws(() => checkReview({ ...review, unresolved }, context), /unresolved/);
  for (const file of Object.keys(review.documents)) {
    const missing = structuredClone(review);
    delete missing.documents[file];
    assert.throws(() => checkReview(missing, context), /Missing documentation disposition/, file);
    for (const disposition of [
      { status: 'ignored', reason: 'No.' },
      { status: 'updated', reason: ' ' },
    ]) {
      const invalid = structuredClone(review);
      invalid.documents[file] = disposition;
      assert.throws(() => checkReview(invalid, context), /Missing documentation disposition/, file);
    }
  }
});

test('final review needs every named release evidence reference', () => {
  const { context, review } = reviewFixture();
  context.release = true;
  assert.throws(() => checkReview(review, context), /Missing final release evidence/);
  review.release = Object.fromEntries(releaseAreas.map(name => [name, `synthetic-${name}.txt`]));
  assert.doesNotThrow(() => checkReview(review, context));
  for (const name of releaseAreas) {
    const incomplete = structuredClone(review);
    delete incomplete.release[name];
    assert.throws(
      () => checkReview(incomplete, context),
      new RegExp(`Missing final release evidence: ${name}`)
    );
  }
});

// This is a control-flow test, not a scanner/security result. Every external scanner and
// alternate-runtime command is a named synthetic fixture. The real gate must still refuse
// release after all review references and those fixture stages report success.
test(
  'release gate stays closed: final-artifacts is a pending F release obligation, not a stage',
  { timeout: 30000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const base = temporary(t, 'orbit-gate-release-fixture-');
    const root = path.join(base, 'repository');
    const bin = path.join(base, 'bin');
    fs.mkdirSync(root);
    fs.mkdirSync(bin);
    const write = (file, source, mode = 0o644) => {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, source, { mode });
    };
    const git = (...args) =>
      execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: 'pipe' }).trimEnd();
    git('init', '--quiet');
    for (const file of gateScripts)
      write(
        path.join(root, 'scripts', file),
        fs.readFileSync(path.join(repository, 'scripts', file))
      );
    write(path.join(root, 'README.md'), '# Synthetic gate fixture\n');
    write(path.join(root, 'CHANGELOG.md'), '# Synthetic fixture changelog\n');
    write(
      path.join(root, 'Dockerfile'),
      `FROM example.invalid/synthetic@sha256:${'0'.repeat(64)}\n`
    );
    write(path.join(root, 'test/setup.mjs'), '// Synthetic test setup.\n');
    const sonarRan = path.join(base, 'sonar-ran');
    write(
      path.join(root, 'scripts/check-sonarqube.mjs'),
      `// Synthetic Sonar control-flow fixture; no real analysis is performed.\nimport fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(sonarRan)}, 'ran');\n`
    );
    write(
      path.join(root, 'test/fixture.test.mjs'),
      "import test from 'node:test'; test('synthetic gate fixture', () => {});\n"
    );
    for (const [file, source] of Object.entries(gateLintFiles))
      write(path.join(root, file), source);
    const rulesCommit = 'a'.repeat(40);
    const rulesDir = path.join(base, `semgrep-rules-${rulesCommit}`);
    fs.mkdirSync(path.join(rulesDir, 'javascript/security'), { recursive: true });
    write(
      path.join(rulesDir, 'javascript/security/synthetic.yaml'),
      '# Synthetic rules fixture.\n'
    );
    const archive = path.join(base, 'synthetic-rules.tar.gz');
    execFileSync('tar', ['-czf', archive, '-C', base, `semgrep-rules-${rulesCommit}`]);
    write(
      path.join(root, 'scripts/security-tools.json'),
      JSON.stringify({
        gitleaks: '0.0.0',
        trivy: '0.0.0',
        actionlint: '0.0.0',
        semgrepImage: 'synthetic-scanner',
        semgrepRulesCommit: rulesCommit,
        semgrepRulesSha256: sha256(fs.readFileSync(archive)),
      })
    );
    const stub = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const name = path.basename(process.argv[1]);
const args = process.argv.slice(2);
if (name === 'curl') fs.copyFileSync(process.env.ORBIT_FIXTURE_ARCHIVE, args[args.indexOf('--output') + 1]);
else if (name === 'orbit-fixture-node24') console.log(args[0] === '--version' ? 'v24.0.0' : ${JSON.stringify(totals({ tests: 1, pass: 1 }))});
else if (args[0] === 'version' || args[0] === '--version') console.log('synthetic tool 0.0.0');
`;
    for (const command of [
      'npm',
      'docker',
      'gitleaks',
      'trivy',
      'actionlint',
      'curl',
      'orbit-fixture-node24',
    ])
      write(path.join(bin, command), stub, 0o755);
    git('add', '.');
    git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      'Synthetic gate fixture'
    );
    const tree = git('rev-parse', 'HEAD^{tree}');
    const review = {
      tree,
      parents: [git('rev-parse', 'HEAD')],
      reviewer: 'Synthetic reviewer',
      reference: 'fixture only; not actual security evidence',
      unresolved: [],
      documents: Object.fromEntries(
        ['README.md', 'CHANGELOG.md'].map(file => [
          file,
          { status: 'checked unchanged', reason: 'Synthetic fixture only.' },
        ])
      ),
      release: Object.fromEntries(releaseAreas.map(name => [name, `synthetic-${name}.txt`])),
    };
    write(path.join(root, '.git/orbit-security/reviews', `${tree}.json`), JSON.stringify(review));
    // gate-draft-r7 (GDR6-REQ-01): this candidate tracks no platform manifest, so it is a
    // maintenance (B35) candidate, whose run now records runtime-identity too. Synthetic identity
    // records for the gate's two runtimes keep it from blocking, so the run stays pending for the
    // release obligations this test is about (its test stages are withheld for want of authority).
    writeRuntimeIdentity(root, [
      { executable: process.execPath, version: process.version },
      { executable: path.join(bin, 'orbit-fixture-node24'), version: 'v24.0.0' },
    ]);
    // Nested Node test processes otherwise inherit the outer runner's reporting context.
    const gateEnvironment = { ...process.env };
    delete gateEnvironment.NODE_TEST_CONTEXT;
    const result = spawnSync(
      process.execPath,
      [path.join(root, 'scripts/security-gate.mjs'), 'release'],
      {
        encoding: 'utf8',
        timeout: 25000,
        env: {
          ...gateEnvironment,
          PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          ORBIT_FIXTURE_ARCHIVE: archive,
          ORBIT_SECURITY_NODE24: path.join(bin, 'orbit-fixture-node24'),
        },
      }
    );
    assert.equal(result.status, 1, result.stdout + result.stderr);
    const evidenceRoot = path.join(root, '.git/orbit-security');
    const run = fs.readdirSync(evidenceRoot).find(name => name.startsWith(`${tree}-release-`));
    assert.ok(run, result.stdout + result.stderr);
    const evidence = JSON.parse(
      fs.readFileSync(path.join(evidenceRoot, run, 'result.json'), 'utf8')
    );
    // final-artifacts is an F release obligation (GATE-CONTRACT v4 C14, C23; the security review of
    // v3), not a stage of a run: the run records it, with the other release-only obligations, as
    // pending, because release finalization does not exist. So the run is pending, exit 1.
    assert.equal(evidence.status, 'pending');
    // SonarQube is the `sonarqube` release obligation of the finalization (v4 C15, C23), which the
    // catalog refuses as a stage name: a release run records no sonarqube-analysis stage
    // (verify-1 of gate-draft-r3), and check-sonarqube.mjs does not run.
    assert.equal(
      evidence.stages.find(stage => stage.name === 'sonarqube-analysis'),
      undefined,
      'sonarqube-analysis is not a stage of a run'
    );
    assert.equal(evidence.releaseObligations.sonarqube.status, 'pending');
    assert.match(evidence.releaseObligations.sonarqube.reason, /the gate runs no SonarQube stage/);
    assert.match(result.stdout, /Pending F release obligation \(blocking\): sonarqube/);
    assert.equal(fs.existsSync(sonarRan), false, 'check-sonarqube.mjs ran');
    assert.equal(
      evidence.stages.find(stage => stage.name === 'independent-review')?.status,
      'pass'
    );
    assert.equal(
      evidence.stages.find(stage => stage.name === 'final-artifacts'),
      undefined,
      'final-artifacts is not a stage of a run'
    );
    assert.deepEqual(
      evidence.stages.filter(stage => stage.status === 'blocked'),
      [],
      JSON.stringify(evidence.stages.map(stage => [stage.name, stage.status]))
    );
    assert.equal(evidence.releaseObligations['final-artifacts'].status, 'pending');
    assert.match(
      evidence.releaseObligations['final-artifacts'].reason,
      /release finalization does not exist/
    );
    assert.match(result.stdout, /Pending F release obligation \(blocking\): final-artifacts/);
    // The rest is pass or pending: what this draft does not implement, or whose authority is
    // pending, is recorded as pending, never as a pass (v3 C23).
    assert.ok(
      evidence.stages.every(stage => ['pass', 'pending'].includes(stage.status)),
      JSON.stringify(evidence.stages.map(stage => [stage.name, stage.status]))
    );
  }
);

// The `scripts` of a 1.5-shaped candidate package.json (it defines both lint scripts) and of a
// maintenance-shaped one (it defines neither). One installed commit guard serves both branches.
const lintScripts = {
  'lint:sql': 'node scripts/sql-lint.mjs',
  'lint:imports': 'node scripts/import-graph.mjs',
};
const developmentScripts = { check: 'node scripts/check.mjs', ...lintScripts };
const maintenanceScripts = { check: 'node scripts/check.mjs' };
// What the maintenance gate records: every stage but the two lint stages.
const withoutLints = allStages.filter(name => !['sql-lint', 'import-lint'].includes(name));

// Approval records are local guardrails, not authenticated attestations. The commit guard
// accepts only a sealed, finalized run (test/security-finalization.test.mjs covers that
// mechanism, including every other mandatory stage). Here one synthetic candidate has clean runs
// with every stage the 1.5 gate records, without one or both lint stages (the maintenance gate
// records neither). `accepts` asks of a run what the guard asks: the lint stages that
// requiredLintStages() names for the candidate's and its parents' scripts (none can do when it
// finds a removal), then the run's checks with exactly those lint stages required. No scanner
// runs.
function lintRuns(t) {
  const root = temporary(t, 'orbit-guard-lint-runs-');
  // The candidate the guard sees, without Git: the run binds these values, not a repository.
  const file = (name, bytes) => ({
    file: name,
    mode: '100644',
    blob: blobId(bytes),
    sha256: sha256(bytes),
  });
  const staged = {
    tree: 'c'.repeat(40),
    parent: 'd'.repeat(40),
    parents: ['d'.repeat(40)],
    refs: `refs/heads/main ${'d'.repeat(40)}`,
    files: [
      file('Dockerfile', '# Synthetic fixture\n'),
      file('example.mjs', 'export const synthetic = true;\n'),
      file('scripts/security-tools.json', securityTools),
    ],
  };
  // With the inputs of its platform judgment: no manifest anywhere (maintenance, B35).
  const current = { ...staged, platform: maintenanceInputs(staged) };
  const now = Date.now();
  const runs = {};
  for (const [name, stages] of Object.entries({
    complete: allStages,
    maintenance: withoutLints,
    noSql: allStages.filter(stage => stage !== 'sql-lint'),
    noImports: allStages.filter(stage => stage !== 'import-lint'),
  })) {
    runs[name] = path.join(root, `${current.tree}-commit-${name}`);
    writeRun(runs[name], current, stages, now);
  }
  const accepts = (run, scripts, parentScripts) => {
    const lintStages = requiredLintStages(scripts, parentScripts);
    return Boolean(lintStages) && inspectRun(runs[run], { ...current, lintStages }, now).eligible;
  };
  return { accepts, inspect: run => inspectRun(runs[run], current, now) };
}

test('the commit guard requires each lint stage the candidate or a parent defines a script for', t => {
  const { accepts, inspect } = lintRuns(t);
  // What the maintenance gate records: no lint stages.
  assert.equal(accepts('maintenance', maintenanceScripts, maintenanceScripts), true);
  assert.equal(accepts('complete', maintenanceScripts, maintenanceScripts), true);
  // A 1.5-shaped candidate refuses a run without either lint stage.
  assert.equal(accepts('complete', developmentScripts, developmentScripts), true);
  assert.equal(accepts('maintenance', developmentScripts, developmentScripts), false);
  assert.equal(accepts('noSql', developmentScripts, developmentScripts), false);
  assert.equal(accepts('noImports', developmentScripts, developmentScripts), false);
  // A candidate that adds the lint scripts (the first 1.5 commit) needs their stages.
  assert.equal(accepts('maintenance', developmentScripts, maintenanceScripts), false);
  assert.equal(accepts('complete', developmentScripts, maintenanceScripts), true);
  // Each script is matched to its own stage.
  const sqlScript = { 'lint:sql': lintScripts['lint:sql'] };
  assert.equal(accepts('noImports', sqlScript, sqlScript), true);
  assert.equal(accepts('noSql', sqlScript, sqlScript), false);
  // Unknown scripts (no readable package.json in the candidate or a parent, or parents the
  // guard cannot read) require both stages: fail closed. A caller that passes no parent
  // scripts gets the same.
  for (const unknown of [undefined, null, 'lint:sql', ['lint:sql', 'lint:imports']]) {
    for (const [scripts, parentScripts] of [
      [unknown, maintenanceScripts],
      [maintenanceScripts, unknown],
    ]) {
      assert.equal(accepts('maintenance', scripts, parentScripts), false, JSON.stringify(unknown));
      assert.equal(accepts('complete', scripts, parentScripts), true, JSON.stringify(unknown));
    }
  }
  assert.equal(accepts('maintenance', maintenanceScripts), false);
  assert.equal(accepts('complete', maintenanceScripts), true);
  // A caller that names no lint stages, as the maintenance finalizer, requires none of them (the
  // 1.5 finalizer names both: test/security-finalization.test.mjs).
  for (const run of ['complete', 'maintenance', 'noSql', 'noImports'])
    assert.deepEqual(inspect(run).blockers, [], run);
});

// The parents define both lints. Without this refusal a candidate could drop one by deleting
// its script together with its gate stage, or by renaming the script while keeping the stage
// and then deleting the stage in the next commit. Removing or renaming a lint script needs a
// reviewed update of the installed checker instead.
test('the commit guard refuses a candidate that removes or renames a lint script a parent defines', t => {
  const { accepts } = lintRuns(t);
  const { 'lint:sql': sql, ...noSql } = developmentScripts;
  const candidates = {
    'delete both scripts': maintenanceScripts,
    'delete lint:sql': noSql,
    'rename lint:sql': { ...noSql, 'lint:sql-legacy': sql },
  };
  for (const [label, scripts] of Object.entries(candidates)) {
    assert.equal(requiredLintStages(scripts, developmentScripts), null, label);
    for (const run of ['complete', 'maintenance'])
      assert.equal(accepts(run, scripts, developmentScripts), false, label);
  }
  // Changing what a lint script runs keeps its stage required (whether the new command still
  // checks anything is for review: the guard sees stage names and results, not scripts).
  const changed = { ...developmentScripts, 'lint:sql': 'node scripts/sql-lint.mjs --strict' };
  assert.deepEqual(requiredLintStages(changed, developmentScripts), ['sql-lint', 'import-lint']);
  assert.equal(accepts('complete', changed, developmentScripts), true);
  assert.equal(accepts('maintenance', changed, developmentScripts), false);
  // Unknown scripts (the canonical reading of a package.json that is not canonical) require both
  // stages here. The guard asks the removal question of what JSON.parse reads instead, in which a
  // package.json that is missing or does not parse defines no script (next test).
  assert.deepEqual(requiredLintStages(undefined, developmentScripts), ['sql-lint', 'import-lint']);
  assert.deepEqual(requiredLintStages(maintenanceScripts, maintenanceScripts), []);
});

// packageScripts() reads a package.json two ways: `scripts` only from the canonical form (anything
// else is unknown, so every lint stage is required) and `parsed` as JSON.parse and npm read it,
// for the removal check. A candidate that drops lint:sql and also changes the file's layout,
// adds a second `scripts` member, breaks the file or deletes it still removes lint:sql.
test('the commit guard judges a removal by what JSON.parse reads, whatever the layout', () => {
  const { 'lint:sql': sql, ...noSql } = developmentScripts;
  const text = (scripts, indent = 2) => `${JSON.stringify({ scripts }, null, indent)}\n`;
  const both = ['sql-lint', 'import-lint'];
  assert.deepEqual(packageScripts(text(developmentScripts)), {
    scripts: developmentScripts,
    parsed: developmentScripts,
  });
  assert.deepEqual(packageScripts(text(noSql)), { scripts: noSql, parsed: noSql });
  const removals = {
    'four-space indentation': text(noSql, 4),
    'an extra final newline': `${text(noSql)}\n`,
    compact: `${JSON.stringify({ scripts: noSql })}\n`,
    'a second scripts member': `{"scripts":${JSON.stringify(developmentScripts)},"scripts":${JSON.stringify(noSql)}}\n`,
    'renamed, four-space indentation': text({ ...noSql, 'lint:sql-legacy': sql }, 4),
    'not valid JSON': '{"scripts":{"lint:imports":"node scripts/import-graph.mjs",}}\n',
    // JSON.parse refuses a byte order mark that npm would skip: refused, the safe side.
    'a byte order mark': `\uFEFF${text(developmentScripts)}`,
    'no scripts object': '{}\n',
    'scripts as an array': text(['lint:sql', 'lint:imports']),
    null: 'null\n',
    'no package.json': undefined,
  };
  for (const [label, file] of Object.entries(removals)) {
    const { scripts, parsed } = packageScripts(file);
    // The canonical reading alone is unknown, which would only require both stages.
    assert.deepEqual(requiredLintStages(scripts, developmentScripts), both, label);
    assert.equal(requiredLintStages(parsed, developmentScripts), null, label);
    // A branch whose history never defined a lint script removes nothing.
    assert.notEqual(requiredLintStages(parsed, maintenanceScripts), null, label);
    assert.deepEqual(requiredLintStages(scripts, maintenanceScripts), both, label);
  }
  // Control: the same layouts keeping both lint scripts remove nothing, and need both stages.
  for (const file of [
    text(developmentScripts, 4),
    `${JSON.stringify({ scripts: developmentScripts })}\n`,
  ]) {
    const { scripts, parsed } = packageScripts(file);
    assert.equal(scripts, undefined, file);
    assert.deepEqual(parsed, developmentScripts, file);
    assert.deepEqual(requiredLintStages(parsed, developmentScripts), both, file);
  }
});

// The installed hook runs one helper from the Git common directory, whichever linked worktree
// is committing (the maintenance and 1.5 worktrees share it). A synthetic repository with a
// maintenance-shaped worktree and a 1.5-shaped linked worktree runs the same helper bytes in
// each, as the hook does. The maintenance checker fails the 1.5 half; a checker that always
// requires the lints fails the maintenance half.
test('one installed commit guard serves a maintenance worktree and a 1.5 worktree', t => {
  if (gitSkip) return t.skip(gitSkip);
  const base = temporary(t, 'orbit-guard-worktrees-');
  const maintenance = path.join(base, 'maintenance');
  const development = path.join(base, 'development');
  const git = (cwd, ...args) =>
    execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', stdio: 'pipe' }).trimEnd();
  const stagePackage = (cwd, scripts, text = `${JSON.stringify({ scripts }, null, 2)}\n`) => {
    fs.writeFileSync(path.join(cwd, 'package.json'), text);
    git(cwd, 'add', 'package.json');
  };
  fs.mkdirSync(maintenance);
  git(maintenance, 'init', '--quiet');
  // A candidate tracks the tool pins its run must match, and a module and a Dockerfile for the
  // synthetic run's clean reports to cover (test/helpers/security-run.mjs).
  fs.mkdirSync(path.join(maintenance, 'scripts'));
  fs.writeFileSync(path.join(maintenance, 'scripts/security-tools.json'), securityTools);
  fs.writeFileSync(path.join(maintenance, 'example.mjs'), 'export const synthetic = true;\n');
  fs.writeFileSync(path.join(maintenance, 'Dockerfile'), '# Synthetic fixture\n');
  git(maintenance, 'add', '.');
  stagePackage(maintenance, maintenanceScripts);
  git(
    maintenance,
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'Synthetic maintenance base'
  );
  git(maintenance, 'worktree', 'add', '--quiet', '-b', 'development', development);
  stagePackage(development, developmentScripts);
  const common = git(development, 'rev-parse', '--path-format=absolute', '--git-common-dir');
  assert.equal(common, git(maintenance, 'rev-parse', '--path-format=absolute', '--git-common-dir'));
  // The helper and the modules it imports, as the installer names them in the hooks directory.
  const hooks = path.join(common, 'hooks');
  const helper = path.join(hooks, 'orbit-security-check.mjs');
  fs.mkdirSync(hooks, { recursive: true });
  for (const [source, target] of [
    ['check-security-approval.mjs', 'orbit-security-check.mjs'],
    ['security-finalization.mjs', 'security-finalization.mjs'],
    ['security-findings.mjs', 'security-findings.mjs'],
    ['security-evidence.mjs', 'security-evidence.mjs'],
    ['security-platform.mjs', 'security-platform.mjs'],
    ['security-catalog.mjs', 'security-catalog.mjs'],
    ['security-catalog.json', 'security-catalog.json'],
    ['security-entries.mjs', 'security-entries.mjs'],
    ['security-gate-identity.mjs', 'security-gate-identity.mjs'],
    ['check-platform-coverage.mjs', 'check-platform-coverage.mjs'],
  ])
    fs.copyFileSync(path.join(repository, 'scripts', source), path.join(hooks, target));

  // A passing, finalized commit run for the worktree's current candidate with the given stages.
  let runs = 0;
  const approve = (cwd, label, names) => {
    const current = candidate(cwd);
    const run = path.join(common, 'orbit-security', `${current.tree}-commit-${label}-${++runs}`);
    finalizedRun(run, current, names);
  };
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  delete environment.NODE_OPTIONS;
  delete environment.GIT_REFLOG_ACTION;
  const guard = (cwd, script = helper, env = {}) =>
    spawnSync(process.execPath, [script], {
      cwd,
      encoding: 'utf8',
      env: { ...environment, ...env },
    });

  approve(maintenance, 'maintenance-gate', withoutLints);
  approve(development, 'maintenance-gate', withoutLints);
  const accepted = guard(maintenance);
  assert.equal(accepted.status, 0, accepted.stderr);

  // A package.json that is not in canonical form cannot be read unambiguously, so the guard
  // requires both lint stages, as for one that does not parse. Here a reader sees the lint
  // scripts in the first of two `scripts` members; JSON.parse and npm take the second, which
  // has none, and Prettier keeps both. A compact file with one member counts the same way.
  const unknownPackage =
    /The lint stages are required because the candidate's package\.json is missing, is not canonical JSON/;
  for (const text of [
    `{"scripts":${JSON.stringify(developmentScripts)},"scripts":${JSON.stringify(maintenanceScripts)}}\n`,
    `${JSON.stringify({ scripts: maintenanceScripts })}\n`,
  ]) {
    assert.deepEqual(JSON.parse(text).scripts, maintenanceScripts);
    stagePackage(maintenance, undefined, text);
    approve(maintenance, 'maintenance-gate', withoutLints);
    const ambiguous = guard(maintenance);
    assert.equal(ambiguous.status, 1, `${text}: ${ambiguous.stderr}`);
    assert.match(ambiguous.stderr, unknownPackage, text);
    approve(maintenance, 'development-gate', allStages);
    const withLints = guard(maintenance);
    assert.equal(withLints.status, 0, `${text}: ${withLints.stderr}`);
  }
  stagePackage(maintenance, maintenanceScripts);
  assert.equal(guard(maintenance).status, 0);
  const refused = guard(development);
  assert.equal(refused.status, 1, refused.stderr);
  assert.match(refused.stderr, /^Commit blocked:/);
  // It names the documented entry point, which starts the gate with node rather than npm.
  assert.match(refused.stderr, /, run node scripts\/security-gate\.mjs commit, /);
  approve(development, 'development-gate', allStages);
  const complete = guard(development);
  assert.equal(complete.status, 0, complete.stderr);

  // Once 1.5 is committed, its next candidate cannot drop a lint script, whatever its record.
  git(
    development,
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'Synthetic 1.5 commit'
  );
  stagePackage(development, maintenanceScripts);
  approve(development, 'maintenance-gate', withoutLints);
  approve(development, 'development-gate', allStages);
  const dropped = guard(development);
  assert.equal(dropped.status, 1, dropped.stderr);
  assert.match(dropped.stderr, /^Commit blocked: the candidate removes lint:sql or lint:imports/);

  // Started through a symlinked directory, the guard still checks (and refuses a candidate
  // with no record) instead of exiting 0 without running. So does a symlinked helper file,
  // even when Node keeps the symlinked path for the entry module: next to links to the modules
  // it imports, it checks; alone, those imports fail and it exits 1 without approving.
  stagePackage(maintenance, { ...maintenanceScripts, start: 'node server.mjs' });
  fs.symlinkSync(path.dirname(helper), path.join(base, 'hooks-link'));
  fs.symlinkSync(helper, path.join(base, 'helper-link.mjs'));
  fs.mkdirSync(path.join(base, 'file-links'));
  for (const name of fs.readdirSync(hooks).filter(file => file.endsWith('.mjs')))
    fs.symlinkSync(
      path.join(hooks, name),
      path.join(base, 'file-links', name === 'orbit-security-check.mjs' ? 'helper-link.mjs' : name)
    );
  const preserveMain = { NODE_OPTIONS: '--preserve-symlinks-main' };
  for (const [script, env, refusal = /^Commit blocked:/] of [
    [path.join(base, 'hooks-link', 'orbit-security-check.mjs'), {}],
    [path.join(base, 'hooks-link', 'orbit-security-check.mjs'), preserveMain],
    [path.join(base, 'helper-link.mjs'), {}],
    [path.join(base, 'helper-link.mjs'), preserveMain, /ERR_MODULE_NOT_FOUND/],
    [path.join(base, 'file-links', 'helper-link.mjs'), {}],
    [path.join(base, 'file-links', 'helper-link.mjs'), preserveMain],
  ]) {
    const linked = guard(maintenance, script, env);
    assert.equal(linked.status, 1, `${script} ${JSON.stringify(env)}: ${linked.stderr}`);
    assert.match(linked.stderr, refusal, `${script} ${JSON.stringify(env)}`);
  }

  // A parent whose package.json is not canonical (committed without the guard) cannot be read
  // either: its next candidate needs both lint stages, even with a canonical package.json.
  stagePackage(
    maintenance,
    undefined,
    `{"scripts":${JSON.stringify(developmentScripts)},"scripts":${JSON.stringify(maintenanceScripts)}}\n`
  );
  git(
    maintenance,
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'Synthetic ambiguous package.json'
  );
  stagePackage(maintenance, maintenanceScripts);
  approve(maintenance, 'maintenance-gate', withoutLints);
  const afterAmbiguous = guard(maintenance);
  assert.equal(afterAmbiguous.status, 1, afterAmbiguous.stderr);
  assert.match(
    afterAmbiguous.stderr,
    /The lint stages are required because the parents of this commit could not be read: a parent's package\.json is missing, is not canonical JSON or has no scripts object/
  );
  assert.doesNotMatch(afterAmbiguous.stderr, unknownPackage);
  approve(maintenance, 'development-gate', allStages);
  assert.equal(guard(maintenance).status, 0);
});

// The guard installed by the installer, run by Git itself: `git commit` runs it as pre-commit
// and an automatic `git merge` as pre-merge-commit. A branch made from maintenance never
// defined the lints, so judging a merge by HEAD alone would let it drop the lints of the 1.5
// branch it joins, and 1.5 could then fast-forward to it. Commits made without the hook (git
// revert, or a merge made elsewhere and fast-forwarded) must not reset the requirement either.
// Runs are synthetic and finalized directly, as above; no gate runs.
//
// guardRepository() makes the disposable repository these hook-level tests use, with an empty
// Git configuration and the fixture's identity; `install()` installs the guard with the real
// installer.
function guardRepository(t, prefix) {
  const base = temporary(t, prefix);
  const root = path.join(base, 'repository');
  const environment = {
    ...process.env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Orbit Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Orbit Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
  };
  for (const name of ['NODE_TEST_CONTEXT', 'NODE_OPTIONS', 'GIT_REFLOG_ACTION'])
    delete environment[name];
  // `run` with these variables added to the environment.
  const runWith = (env, ...args) =>
    spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', env: { ...environment, ...env } });
  const run = (...args) => runWith({}, ...args);
  const git = (...args) => {
    const result = run(...args);
    assert.equal(result.status, 0, `git ${args.join(' ')}: ${result.stderr}`);
    return result.stdout.trimEnd();
  };
  const unguarded = (...args) => git('-c', 'core.hooksPath=/dev/null', ...args);
  let changes = 0;
  // Stage a package.json with these scripts (canonical), or with this exact text, or none for
  // null; and a change to `file` (one file per branch, so merges do not conflict).
  const stagePackage = (scripts, file) => {
    const target = path.join(root, 'package.json');
    fs.rmSync(target, { recursive: true, force: true });
    if (scripts !== null)
      fs.writeFileSync(
        target,
        typeof scripts === 'string' ? scripts : `${JSON.stringify({ scripts }, null, 2)}\n`
      );
    if (file) fs.writeFileSync(path.join(root, file), `change ${++changes}\n`);
    git('add', '-A');
  };
  // A passing, finalized commit run for the staged candidate (or `tree`) and HEAD, with these
  // stages.
  const approve = (names, tree = git('write-tree')) => {
    const current = candidate(root, tree);
    finalizedRun(
      path.join(root, '.git/orbit-security', `${current.tree}-commit-${++changes}`),
      current,
      names
    );
  };
  const install = () => {
    const installer = spawnSync(
      process.execPath,
      [path.join(repository, 'scripts/install-security-hooks.mjs'), root],
      { encoding: 'utf8', env: environment }
    );
    assert.equal(installer.status, 0, installer.stderr);
  };
  fs.mkdirSync(root);
  // Tracked from the first commit on: the tool pins a run must match, and a module and a
  // Dockerfile for the synthetic run's clean reports to cover (test/helpers/security-run.mjs).
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.writeFileSync(path.join(root, 'scripts/security-tools.json'), securityTools);
  fs.writeFileSync(path.join(root, 'example.mjs'), 'export const synthetic = true;\n');
  fs.writeFileSync(path.join(root, 'Dockerfile'), '# Synthetic fixture\n');
  return {
    root,
    run,
    runWith,
    git,
    unguarded,
    stagePackage,
    approve,
    install,
    allStages,
    withoutLints,
  };
}
const removes = /^Commit blocked: the candidate removes lint:sql or lint:imports/;

test(
  'the commit guard counts every parent of a merge and the history behind them',
  { timeout: 60000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const {
      root,
      run,
      runWith,
      git,
      unguarded,
      stagePackage,
      approve,
      install,
      allStages,
      withoutLints,
    } = guardRepository(t, 'orbit-guard-history-');

    git('init', '--quiet', '-b', 'maintenance');
    stagePackage(maintenanceScripts, 'base.txt');
    unguarded('commit', '--quiet', '-m', 'Maintenance base');
    git('checkout', '--quiet', '-b', 'development');
    stagePackage(developmentScripts);
    unguarded('commit', '--quiet', '-m', 'Add the lint scripts');
    const lintsAdded = git('rev-parse', 'HEAD');
    install();

    // Controls: a maintenance commit with the maintenance gate's record, a 1.5 commit with both
    // lint stages, and a maintenance merge concluded with `git commit`, are approved.
    git('checkout', '--quiet', 'maintenance');
    stagePackage(maintenanceScripts, 'maintenance.txt');
    approve(withoutLints);
    git('commit', '--quiet', '-m', 'Maintenance change');
    git('checkout', '--quiet', '-b', 'feature');
    stagePackage(maintenanceScripts, 'feature.txt');
    approve(withoutLints);
    git('commit', '--quiet', '-m', 'Maintenance feature');
    git('checkout', '--quiet', 'maintenance');
    git('merge', '--quiet', '--no-ff', '--no-commit', 'feature');
    approve(withoutLints);
    git('commit', '--quiet', '--no-edit');
    // GIT_REFLOG_ACTION exported (by a shell profile, a wrapper or a Git front end) may mean an
    // automatic merge (see below), so a plain commit with it needs both lint stages; the same
    // commit without it is approved by the maintenance gate's record. A merge concluded with
    // `git commit`, as the guard advises, is still judged by its MERGE_HEAD.
    const exported = { GIT_REFLOG_ACTION: 'custom' };
    stagePackage(maintenanceScripts, 'maintenance.txt');
    approve(withoutLints);
    const plain = runWith(exported, 'commit', '--quiet', '-m', 'Maintenance change 2');
    assert.equal(plain.status, 1, plain.stderr);
    assert.match(plain.stderr, /GIT_REFLOG_ACTION is set while no merge is being concluded/);
    git('commit', '--quiet', '-m', 'Maintenance change 2');
    git('checkout', '--quiet', 'feature');
    stagePackage(maintenanceScripts, 'feature.txt');
    approve(withoutLints);
    git('commit', '--quiet', '-m', 'Maintenance feature 2');
    git('checkout', '--quiet', 'maintenance');
    git('merge', '--quiet', '--no-ff', '--no-commit', 'feature');
    approve(withoutLints);
    const concludedExported = runWith(exported, 'commit', '--quiet', '--no-edit');
    assert.equal(concludedExported.status, 0, concludedExported.stderr);
    git('checkout', '--quiet', 'development');
    stagePackage(developmentScripts, 'development.txt');
    approve(allStages);
    git('commit', '--quiet', '-m', '1.5 change');

    // A merge concluded with `git commit` on a branch from maintenance: MERGE_HEAD (1.5) defines
    // the lints, so dropping them is refused whatever the record says.
    git('checkout', '--quiet', '-b', 'side', 'maintenance');
    git('merge', '--quiet', '--no-ff', '--no-commit', 'development');
    stagePackage(maintenanceScripts, 'side.txt');
    approve(withoutLints);
    approve(allStages);
    const concluded = run('commit', '--quiet', '--no-edit');
    assert.equal(concluded.status, 1, concluded.stderr);
    assert.match(concluded.stderr, removes);
    git('merge', '--abort');

    // An automatic merge runs the guard as pre-merge-commit, before Git writes MERGE_HEAD. The
    // guard cannot see the commit it joins, so its complete parent vector is not known and the
    // merge is refused, whatever the record (GATE-CONTRACT v3 C18; security review GD-R1).
    const side = git('rev-parse', 'HEAD');
    const incomplete =
      /complete parent vector of this commit is not known .*Merge with --no-commit, then run git commit/s;
    approve(withoutLints); // `-s ours` commits exactly this tree.
    const automatic = run('merge', '--quiet', '-s', 'ours', '--no-edit', 'development');
    assert.equal(automatic.status, 1, automatic.stderr);
    assert.match(automatic.stderr, incomplete);
    git('merge', '--abort');
    assert.equal(git('rev-parse', 'HEAD'), side);
    // `git merge` and `git pull` keep a GIT_REFLOG_ACTION already in the environment, whatever
    // its value, so the guard counts any value. Judged by HEAD alone, this merge would need no
    // lint stage, and 1.5 could then fast-forward to a merge that dropped its lints.
    for (const value of ['custom', '']) {
      const preset = runWith(
        { GIT_REFLOG_ACTION: value },
        'merge',
        '--quiet',
        '-s',
        'ours',
        '--no-edit',
        'development'
      );
      assert.equal(
        preset.status,
        1,
        `GIT_REFLOG_ACTION=${JSON.stringify(value)}: ${preset.stderr}`
      );
      assert.match(preset.stderr, incomplete);
      git('merge', '--abort');
      assert.equal(git('rev-parse', 'HEAD'), side);
    }
    // With both lint stages too: an automatic merge is no longer approved by a record bound to
    // HEAD alone (the earlier guard approved this one, which, judged with its complete parents,
    // drops the lint scripts of the 1.5 side).
    approve(allStages);
    const presetBoth = runWith(
      { GIT_REFLOG_ACTION: 'custom' },
      'merge',
      '--quiet',
      '-s',
      'ours',
      '--no-edit',
      'development'
    );
    assert.equal(presetBoth.status, 1, presetBoth.stderr);
    assert.match(presetBoth.stderr, incomplete);
    git('merge', '--abort');
    // Concluded with --no-commit and git commit, the same merge is judged with both parents: it
    // removes the 1.5 side's lint scripts, which no record can excuse.
    git('merge', '--quiet', '-s', 'ours', '--no-commit', 'development');
    approve(allStages);
    const judged = run('commit', '--quiet', '--no-edit');
    assert.equal(judged.status, 1, judged.stderr);
    assert.match(judged.stderr, removes);
    git('merge', '--abort');
    assert.equal(git('rev-parse', 'HEAD'), side);

    // git revert runs no pre-commit hook (a commit made without the guard is modelled the same
    // way), so it can remove the lint scripts unguarded; 1.5's history still defines them.
    git('checkout', '--quiet', 'development');
    unguarded('revert', '--no-edit', lintsAdded);
    assert.deepEqual(JSON.parse(git('show', 'HEAD:package.json')).scripts, maintenanceScripts);
    stagePackage(maintenanceScripts, 'development.txt');
    approve(withoutLints);
    const reverted = run('commit', '--quiet', '-m', 'After the revert');
    assert.equal(reverted.status, 1, reverted.stderr);
    assert.match(reverted.stderr, removes);
    // `git --literal-pathspecs` exports GIT_LITERAL_PATHSPECS to the hook (a front end may set it
    // too). The guard's ':(top)package.json' would then match no commit and the history would
    // define nothing, so the guard drops Git's pathspec variables.
    const literal = run('--literal-pathspecs', 'commit', '--quiet', '-m', 'After the revert');
    assert.equal(literal.status, 1, literal.stderr);
    assert.match(literal.stderr, removes);
    stagePackage(developmentScripts, 'development.txt');
    approve(allStages);
    git('commit', '--quiet', '-m', 'Restore the lint scripts');

    // A merge made without the guard that kept maintenance's package.json, to which 1.5 then
    // fast-forwards (no hook runs). The merge hides 1.5's side from Git's default history
    // simplification; the guard's full history still finds the lint scripts.
    git('checkout', '--quiet', '-b', 'elsewhere', 'maintenance');
    git('merge', '--quiet', '-s', 'ours', '--no-verify', '--no-edit', 'development');
    git('checkout', '--quiet', 'development');
    git('merge', '--quiet', '--ff-only', 'elsewhere');
    assert.deepEqual(JSON.parse(git('show', 'HEAD:package.json')).scripts, maintenanceScripts);
    stagePackage(maintenanceScripts, 'development.txt');
    approve(withoutLints);
    const fastForwarded = run('commit', '--quiet', '-m', 'After the fast-forward');
    assert.equal(fastForwarded.status, 1, fastForwarded.stderr);
    assert.match(fastForwarded.stderr, removes);
    stagePackage(developmentScripts, 'development.txt');
    approve(allStages);
    git('commit', '--quiet', '-m', 'Restore the lint scripts again');

    // Commits made elsewhere: one turns package.json into a directory whose only entry is named
    // like a `git cat-file --batch` header ("blob <size> x"), the next restores package.json
    // without the lint scripts, and 1.5 fast-forwards to them. Read as a header, that tree entry
    // would make the guard skip every older package.json; it skips the tree's content instead.
    // gate-draft-r10 (GDR9-AUTH-OBJECT-01): each version's package.json is now read from its own
    // tree entry, so the crafted entry name changes nothing, and a version that recorded
    // package.json as a directory cannot be judged: the guard refuses every later commit, one
    // that keeps the lint scripts included.
    git('checkout', '--quiet', '-b', 'crafted');
    fs.rmSync(path.join(root, 'package.json'));
    fs.mkdirSync(path.join(root, 'package.json'));
    fs.writeFileSync(path.join(root, 'package.json', 'blob 99999999 x'), 'synthetic\n');
    git('add', '-A');
    unguarded('commit', '--quiet', '-m', 'package.json as a directory');
    fs.rmSync(path.join(root, 'package.json'), { recursive: true });
    stagePackage(maintenanceScripts);
    unguarded('commit', '--quiet', '-m', 'package.json without the lint scripts');
    git('checkout', '--quiet', 'development');
    git('merge', '--quiet', '--ff-only', 'crafted');
    assert.equal(git('cat-file', '-t', 'HEAD~:package.json'), 'tree');
    stagePackage(maintenanceScripts, 'development.txt');
    approve(withoutLints);
    const directory =
      /^Commit blocked: the package\.json of [0-9a-f]+ is a directory \(tree [0-9a-f]+\), not a regular file/;
    const crafted = run('commit', '--quiet', '-m', 'After the crafted history');
    assert.equal(crafted.status, 1, crafted.stderr);
    assert.match(crafted.stderr, directory);
    stagePackage(developmentScripts, 'development.txt');
    approve(allStages);
    const kept = run('commit', '--quiet', '-m', 'Restore the lint scripts once more');
    assert.equal(kept.status, 1, kept.stderr);
    assert.match(kept.stderr, directory);
  }
);

// The removal check, run by Git through the installed hook, whatever the form of package.json.
// Each candidate below drops lint:sql with a record that carries both lint stages, which only a
// changed gate or a forged record gives (the 1.5 gate refuses a package.json that is not
// canonical), so only the removal check stops it. The same holds after a commit made without
// the guard leaves such a package.json (or none, or a directory) at HEAD, and for an automatic
// merge whose other side dropped lint:sql: HEAD's history still defines it.
test(
  'the commit guard refuses a removal whatever the form of the candidate or parent package.json',
  { timeout: 60000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const { root, run, git, unguarded, stagePackage, approve, install, allStages, withoutLints } =
      guardRepository(t, 'orbit-guard-forms-');
    const { 'lint:sql': sql, ...noSql } = developmentScripts;
    const text = (scripts, indent = 2) => `${JSON.stringify({ scripts }, null, indent)}\n`;
    const forms = {
      'four-space indentation': text(noSql, 4),
      'an extra final newline': `${text(noSql)}\n`,
      compact: `${JSON.stringify({ scripts: noSql })}\n`,
      'a second scripts member': `{"scripts":${JSON.stringify(developmentScripts)},"scripts":${JSON.stringify(noSql)}}\n`,
      'renamed, four-space indentation': text({ ...noSql, 'lint:sql-legacy': sql }, 4),
      'no scripts object': '{}\n',
      'no package.json': null,
    };
    // gate-draft-r10 round 2 (check-1 of GDR9-AUTH-OBJECT-01): a package.json that is not valid
    // JSON is malformed content, refused before any removal is judged, as the candidate and as a
    // version at HEAD (the end of this test, on a branch of its own).
    const notJson = '{"scripts":{"lint:imports":"node scripts/import-graph.mjs",}}\n';
    const malformed =
      /^Commit blocked: the package\.json of [0-9a-f]+ \(blob [0-9a-f]+\) is not well-formed JSON, so the lint scripts that version defines cannot be judged/;
    const restore = label => {
      stagePackage(developmentScripts, 'development.txt');
      approve(allStages);
      git('commit', '--quiet', '-m', `Restore the lint scripts after ${label}`);
    };

    git('init', '--quiet', '-b', 'development');
    stagePackage(developmentScripts, 'base.txt');
    unguarded('commit', '--quiet', '-m', 'Add the lint scripts');
    install();

    for (const [label, form] of Object.entries(forms)) {
      stagePackage(form, 'development.txt');
      approve(allStages);
      const candidate = run('commit', '--quiet', '-m', label);
      assert.equal(candidate.status, 1, `${label}: ${candidate.stderr}`);
      assert.match(candidate.stderr, removes, label);
    }
    stagePackage(notJson, 'development.txt');
    approve(allStages);
    const broken = run('commit', '--quiet', '-m', 'not valid JSON');
    assert.equal(broken.status, 1, `not valid JSON: ${broken.stderr}`);
    assert.match(broken.stderr, malformed, 'not valid JSON');
    // Controls: a layout that is not canonical but keeps both lint scripts needs both stages and
    // is not refused as a removal.
    stagePackage(text(developmentScripts, 4), 'development.txt');
    approve(withoutLints);
    const unknown = run('commit', '--quiet', '-m', 'Four-space indentation, lints kept');
    assert.equal(unknown.status, 1, unknown.stderr);
    assert.doesNotMatch(unknown.stderr, removes);
    approve(allStages);
    git('commit', '--quiet', '-m', 'Four-space indentation, lints kept');
    restore('the control');

    // A commit made without the guard leaves package.json at HEAD in one of these forms, without
    // lint:sql. HEAD then cannot be read as canonical, but the history behind it still defines
    // the script: the next guarded commit cannot leave it out, whether it keeps that form or
    // writes a canonical package.json. (A directory at HEAD is the last case of this test:
    // gate-draft-r10 refuses every commit after it.)
    for (const [label, form] of Object.entries(forms)) {
      stagePackage(form);
      unguarded('commit', '--quiet', '-m', `Unguarded: ${label}`);
      for (const candidate of [form, maintenanceScripts]) {
        stagePackage(candidate, 'development.txt');
        approve(allStages);
        const next = run('commit', '--quiet', '-m', `After an unguarded ${label}`);
        assert.equal(next.status, 1, `HEAD with ${label}: ${next.stderr}`);
        assert.match(next.stderr, removes, `HEAD with ${label}`);
      }
      restore(label);
    }

    // An automatic merge cannot show the guard the commit it joins: refused, whatever its record
    // (v3 C18; security review GD-R1). Concluded with --no-commit and git commit, it is judged with every
    // parent: here the other side dropped lint:sql without the guard and the merge takes its
    // package.json, which is refused as a removal; a side that keeps both lint scripts merges.
    const merge = (side, scripts) => {
      git('checkout', '--quiet', '-b', side);
      stagePackage(scripts, `${side}.txt`);
      unguarded('commit', '--quiet', '-m', side);
      git('checkout', '--quiet', 'development');
      stagePackage(developmentScripts, 'development.txt');
      unguarded('commit', '--quiet', '-m', `Before merging ${side}`);
      // The record of the merge result, bound to both of its parents.
      git('merge', '--quiet', '--no-ff', '--no-commit', side);
      approve(allStages);
      git('merge', '--abort');
      const automatic = run('merge', '--quiet', '--no-edit', side);
      assert.equal(automatic.status, 1, automatic.stderr);
      assert.match(automatic.stderr, /complete parent vector of this commit is not known/);
      git('merge', '--abort');
      git('merge', '--quiet', '--no-ff', '--no-commit', side);
      return run('commit', '--quiet', '--no-edit');
    };
    const dropped = merge('dropped', noSql);
    assert.equal(dropped.status, 1, dropped.stderr);
    assert.match(dropped.stderr, removes);
    git('merge', '--abort');
    assert.equal(git('log', '-1', '--format=%s'), 'Before merging dropped');
    // Positive control: a side that keeps both lint scripts merges with both lint stages.
    const kept = merge('kept', { ...developmentScripts, extra: 'node scripts/check.mjs' });
    assert.equal(kept.status, 0, kept.stderr);
    assert.equal(git('log', '-1', '--format=%s'), "Merge branch 'kept' into development");
    assert.match(git('show', 'HEAD:package.json'), /"extra"/);
    // gate-draft-r10 round 2: a commit made without the guard that leaves package.json not valid
    // JSON at HEAD (the guard read that version as defining nothing) can no longer be judged on
    // its branch: every next guarded commit there is refused, one that writes a canonical
    // package.json with both lint scripts included. On a branch of its own, so the cases below
    // still run on development.
    git('checkout', '--quiet', '-b', 'not-json');
    stagePackage(notJson);
    unguarded('commit', '--quiet', '-m', 'Unguarded: not valid JSON');
    for (const candidate of [notJson, maintenanceScripts, developmentScripts]) {
      stagePackage(candidate, 'development.txt');
      approve(allStages);
      const next = run(
        'commit',
        '--quiet',
        '-m',
        'After an unguarded package.json that is not JSON'
      );
      assert.equal(next.status, 1, `HEAD not valid JSON: ${next.stderr}`);
      assert.match(next.stderr, malformed, 'HEAD not valid JSON');
    }
    git('reset', '--quiet', '--hard');
    git('checkout', '--quiet', 'development');
    // gate-draft-r10 (GDR9-AUTH-OBJECT-01): a commit made without the guard that leaves
    // package.json a directory at HEAD (the guard read it as no package.json and judged the next
    // commit by the history alone) can no longer be judged: every next guarded commit is refused,
    // one that writes a canonical package.json with both lint scripts included.
    stagePackage(null);
    fs.mkdirSync(path.join(root, 'package.json'));
    fs.writeFileSync(path.join(root, 'package.json', 'index.json'), '{}\n');
    git('add', '-A');
    unguarded('commit', '--quiet', '-m', 'Unguarded: a directory');
    for (const candidate of [null, maintenanceScripts, developmentScripts]) {
      stagePackage(candidate, 'development.txt');
      approve(allStages);
      const next = run('commit', '--quiet', '-m', 'After an unguarded directory');
      assert.equal(next.status, 1, `HEAD with a directory: ${next.stderr}`);
      assert.match(
        next.stderr,
        /^Commit blocked: the package\.json of [0-9a-f]+ is a directory \(tree [0-9a-f]+\), not a regular file/,
        'HEAD with a directory'
      );
    }
  }
);

// A disposable repository holding the real gate and synthetic stand-ins for every external
// command (as in the release control-flow test above). `tests` is the source of its only test
// file; `files` maps further tracked paths to their contents (the 1.5 lint files by default).
// The returned function runs the gate in one mode and returns that run's evidence. The npm
// stand-in logs each command to ORBIT_FIXTURE_NPM_LOG and, for ORBIT_FIXTURE_NPM_PLANT
// `<command>=<file>`, writes that executable file (relative to the snapshot) when it runs that
// command, as a dependency's bin or a stage's own script could; `<command>=<file>=<mode>` then
// also sets its directory to that octal mode. With ORBIT_FIXTURE_REAL_NPM, it
// passes `npm run check` to that npm. Every stand-in appends its name, NODE_OPTIONS, its
// npm_config_* variable names, the names of the test inputs it sees (TEST_*, UPDATE_GOLDEN and
// NODE_TEST_CONTEXT) and the npm user and global configuration files those name (path and
// content) to ORBIT_FIXTURE_ENV_LOG, as JSON lines. With ORBIT_FIXTURE_GIT_LOG (gate-draft-r11,
// GDR10-AUTH-STAGE-01), every stand-in also appends its name, arguments, folder, GIT_* variables
// and what Git in its folder answers (the git directory it finds, and any orbit.* setting) there,
// and the gitleaks stand-in's `git` command runs the Git command gitleaks runs (git -C <source>
// log -p -U0 <log options>) with the environment it was given, refusing (exit 1) when that fails.
// With ORBIT_FIXTURE_SCAN_INPUT (a folder; gate-draft-r12, GDR11-HISTORY-ATTRS-01 and
// GDR11-AUTH-CONFIG-01), the gitleaks stand-in keeps what the two scans it stands for were given:
// for `git`, the arguments it was started with (history-args.json) and the bytes of the Git command
// gitleaks runs, run with its environment (history.bin; exit 1 when that command fails); for
// `dir` with a folder other than `.`, a copy of every file of that folder (metadata/).
// The returned function's third argument `{ at }` runs the gate of a linked worktree of the
// fixture instead (its own scripts/security-gate.mjs, in that folder).
// `authority` (a list of purposes, or 'all'): the fixture's gate gets a synthetic dispatch
// authority for those (test/helpers/dispatch-authority.mjs) instead of the repository's
// scripts/security-authority.mjs, which gives none; without it, the gate withholds every stage
// that needs one, as it does outside a fixture. `identified` writes synthetic runtime identity
// records for the two runtimes the fixture's gate runs, its own and the Node 24 stand-in
// (test/helpers/runtime-identity.mjs): a test stage starts only once runtime-identity has passed,
// in a maintenance (B35) run as in every other (GDR6-REQ-01), and this fixture's candidate, which
// tracks no platform manifest, is a maintenance candidate.
function commitGateFixture(t, tests, files = {}, { authority = null, identified = false } = {}) {
  const base = temporary(t, 'orbit-gate-commit-fixture-');
  const root = path.join(base, 'repository');
  const bin = path.join(base, 'bin');
  const write = (file, source, mode = 0o644) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, source, { mode });
  };
  const git = (...args) =>
    execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: 'pipe' }).trimEnd();
  fs.mkdirSync(root);
  git('init', '--quiet');
  for (const file of gateScripts)
    write(
      path.join(root, 'scripts', file),
      fs.readFileSync(path.join(repository, 'scripts', file))
    );
  write(path.join(root, 'README.md'), '# Synthetic gate fixture\n');
  write(path.join(root, 'CHANGELOG.md'), '# Synthetic fixture changelog\n');
  write(path.join(root, 'Dockerfile'), `FROM example.invalid/synthetic@sha256:${'0'.repeat(64)}\n`);
  write(path.join(root, 'test/setup.mjs'), '// Synthetic test setup.\n');
  write(path.join(root, 'test/fixture.test.mjs'), tests);
  const rulesCommit = 'b'.repeat(40);
  write(
    path.join(base, `semgrep-rules-${rulesCommit}`, 'javascript/security/synthetic.yaml'),
    '# Synthetic rules fixture.\n'
  );
  const archive = path.join(base, 'synthetic-rules.tar.gz');
  execFileSync('tar', ['-czf', archive, '-C', base, `semgrep-rules-${rulesCommit}`]);
  write(
    path.join(root, 'scripts/security-tools.json'),
    JSON.stringify({
      gitleaks: '0.0.0',
      trivy: '0.0.0',
      actionlint: '0.0.0',
      semgrepImage: 'synthetic-scanner',
      semgrepRulesCommit: rulesCommit,
      semgrepRulesSha256: sha256(fs.readFileSync(archive)),
    })
  );
  const stub = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const name = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const configFile = key => process.env[key] === undefined ? null : { path: process.env[key], content: fs.readFileSync(process.env[key], 'utf8') };
if (process.env.ORBIT_FIXTURE_ENV_LOG)
  fs.appendFileSync(process.env.ORBIT_FIXTURE_ENV_LOG, JSON.stringify({ name, testInputs: Object.keys(process.env).filter(key => /^(?:TEST_|UPDATE_GOLDEN$|NODE_TEST_CONTEXT$)/i.test(key)).sort(), nodeOptions: process.env.NODE_OPTIONS ?? null, npmConfig: Object.keys(process.env).filter(key => /^npm_config_/i.test(key)).sort(), userConfig: configFile('npm_config_userconfig'), globalConfig: configFile('npm_config_globalconfig') }) + '\\n');
if (process.env.ORBIT_FIXTURE_GIT_LOG) {
  const git = list => spawnSync('git', list, { encoding: 'utf8' });
  const entry = { name, args, cwd: process.cwd(), git: Object.fromEntries(Object.entries(process.env).filter(([key]) => /^GIT_/i.test(key))), gitDir: git(['rev-parse', '--absolute-git-dir']).stdout.trim(), config: git(['config', '--get-regexp', '^orbit\\\\.']).stdout.trim() };
  if (name === 'gitleaks' && args[0] === 'git') {
    const options = args.filter(arg => arg.startsWith('--log-opts=')).flatMap(arg => arg.slice(11).split(' ').filter(Boolean));
    entry.scan = spawnSync('git', ['-C', args[args.length - 1], 'log', '-p', '-U0', ...options], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).status;
  }
  fs.appendFileSync(process.env.ORBIT_FIXTURE_GIT_LOG, JSON.stringify(entry) + '\\n');
  if (entry.scan !== undefined && entry.scan !== 0) process.exit(1);
}
if (process.env.ORBIT_FIXTURE_SCAN_INPUT && name === 'gitleaks' && args[0] === 'git') {
  const kept = process.env.ORBIT_FIXTURE_SCAN_INPUT;
  const options = args.filter(arg => arg.startsWith('--log-opts=')).flatMap(arg => arg.slice(11).split(' ').filter(Boolean));
  const shown = spawnSync('git', ['-C', args[args.length - 1], 'log', '-p', '-U0', ...options], { maxBuffer: 256 * 1024 * 1024 });
  fs.writeFileSync(path.join(kept, 'history-args.json'), JSON.stringify(args));
  fs.writeFileSync(path.join(kept, 'history.bin'), shown.stdout ?? Buffer.alloc(0));
  if (shown.status !== 0) process.exit(1);
}
if (process.env.ORBIT_FIXTURE_SCAN_INPUT && name === 'gitleaks' && args[0] === 'dir' && args[args.length - 1] !== '.') {
  const kept = path.join(process.env.ORBIT_FIXTURE_SCAN_INPUT, 'metadata');
  fs.mkdirSync(kept, { recursive: true });
  for (const file of fs.readdirSync(args[args.length - 1])) fs.copyFileSync(path.join(args[args.length - 1], file), path.join(kept, file));
}
if (name === 'npm' && process.env.ORBIT_FIXTURE_REAL_NPM && args.join(' ') === 'run check')
  process.exit(spawnSync(process.env.ORBIT_FIXTURE_REAL_NPM, args, { stdio: 'inherit' }).status ?? 1);
if (name === 'npm') {
  if (process.env.ORBIT_FIXTURE_NPM_LOG) fs.appendFileSync(process.env.ORBIT_FIXTURE_NPM_LOG, args.join(' ') + '\\n');
  const [command, file, mode] = (process.env.ORBIT_FIXTURE_NPM_PLANT || '').split('=');
  if (file && args.join(' ').startsWith(command)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '#!/bin/sh\\nexit 0\\n', { mode: 0o755 });
    if (mode) fs.chmodSync(path.dirname(file), parseInt(mode, 8));
  }
}
if (name === 'curl') fs.copyFileSync(process.env.ORBIT_FIXTURE_ARCHIVE, args[args.indexOf('--output') + 1]);
else if (name === 'orbit-fixture-node24') console.log(args[0] === '--version' ? 'v24.0.0' : ${JSON.stringify(totals({ tests: 1, pass: 1 }))});
else if (args[0] === 'version' || args[0] === '--version') console.log('synthetic tool 0.0.0');
`;
  for (const command of [
    'npm',
    'docker',
    'gitleaks',
    'trivy',
    'actionlint',
    'curl',
    'orbit-fixture-node24',
  ])
    write(path.join(bin, command), stub, 0o755);
  for (const [file, source] of Object.entries({
    ...gateLintFiles,
    ...files,
    ...(authority ? { 'scripts/security-authority.mjs': syntheticAuthority(authority) } : {}),
  }))
    write(path.join(root, file), source);
  git('add', '.');
  git(
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'Synthetic gate fixture'
  );
  // candidate-policy requires every proposed commit to update CHANGELOG.md, so the candidate
  // stages a change to it: without one, candidate-policy is blocked in commit mode, and the
  // pre-dispatch barrier then withholds every candidate-controlled stage. (gate-draft-r4's
  // fixtures staged none, so every commit-mode run here recorded a blocked candidate-policy and
  // went on to run candidate code anyway: the security review's GDR4-01.)
  write(
    path.join(root, 'CHANGELOG.md'),
    '# Synthetic fixture changelog\n\n- A synthetic change.\n'
  );
  git('add', 'CHANGELOG.md');
  if (identified)
    writeRuntimeIdentity(root, [
      { executable: process.execPath, version: process.version },
      { executable: path.join(bin, 'orbit-fixture-node24'), version: 'v24.0.0' },
    ]);
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  // `mode` is the gate's mode, or its arguments as a list (['platform', '<run id>']).
  const runGate = (mode, env = {}, { at } = {}) => {
    const args = Array.isArray(mode) ? mode : [mode];
    const evidenceRoot = path.join(root, '.git/orbit-security');
    const earlier = new Set(fs.existsSync(evidenceRoot) ? fs.readdirSync(evidenceRoot) : []);
    const result = spawnSync(
      process.execPath,
      [path.join(at ?? root, 'scripts/security-gate.mjs'), ...args],
      {
        ...(at ? { cwd: at } : {}),
        encoding: 'utf8',
        timeout: 25000,
        env: {
          ...environment,
          PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          ORBIT_FIXTURE_ARCHIVE: archive,
          ORBIT_SECURITY_NODE24: path.join(bin, 'orbit-fixture-node24'),
          ...env,
        },
      }
    );
    const tree = at
      ? execFileSync('git', ['-C', at, 'write-tree'], { encoding: 'utf8' }).trim()
      : git('write-tree');
    const run = fs
      .readdirSync(evidenceRoot)
      .find(name => name.startsWith(`${tree}-${args[0]}-`) && !earlier.has(name));
    assert.ok(run, result.stdout + result.stderr);
    const evidence = JSON.parse(
      fs.readFileSync(path.join(evidenceRoot, run, 'result.json'), 'utf8')
    );
    const stage = name => evidence.stages.find(item => item.name === name);
    const log = name => fs.readFileSync(path.join(evidenceRoot, run, stage(name).log), 'utf8');
    const file = name => fs.readFileSync(path.join(evidenceRoot, run, name), 'utf8');
    return { result, evidence, stage, log, file, directory: path.join(evidenceRoot, run) };
  };
  return Object.assign(runGate, { root, bin, git });
}

// Control flow only: the scanners are synthetic and the gate is expected to block.
test(
  'the 1.5 commit and scan gates run the SQL/import lints; commit requires capacity and names each skipped test',
  { timeout: 60000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const gate = commitGateFixture(
      t,
      `import test from 'node:test';
import assert from 'node:assert/strict';
test('the gate requires every 1.5 suite', () =>
  assert.equal(process.env.TEST_REQUIRE, 'browser,fixtures,systemd,docker,capacity,git'));
test('synthetic platform-only case', { skip: 'synthetic: runs on another platform only' }, () => {});
`,
      {},
      // A synthetic authority for every withheld operation, so that the test stage runs (the gate
      // withholds it without one; test/security-dispatch.test.mjs), and, since gate-draft-r7
      // (GDR6-REQ-01), identity records for the runtimes of this maintenance candidate's run.
      { authority: 'all', identified: true }
    );
    const { result, evidence, stage, log } = gate('commit');
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.equal(evidence.status, 'blocked');
    assert.equal(stage('runtime-identity')?.status, 'pass', stage('runtime-identity')?.error);
    // This repository's package.json names the commands the gate runs (candidate-policy).
    const own = JSON.parse(fs.readFileSync(path.join(repository, 'package.json'), 'utf8')).scripts;
    assert.deepEqual(
      { 'lint:sql': own['lint:sql'], 'lint:imports': own['lint:imports'] },
      JSON.parse(gateLintFiles['package.json']).scripts
    );
    // Each lint runs the candidate's own lint source with the gate's Node, not through npm,
    // before the dependencies are installed and any other stage runs candidate code. The import
    // lint runs with --disable-sigusr1 (see the SIGUSR1 test below).
    const order = evidence.stages.map(item => item.name);
    for (const [name, file, flags] of [
      ['sql-lint', 'sql-lint.mjs', []],
      ['import-lint', 'import-graph.mjs', ['--disable-sigusr1']],
    ]) {
      assert.deepEqual(stage(name)?.command, [process.execPath, ...flags, `scripts/${file}`], name);
      assert.equal(stage(name).status, 'pass', name);
      assert.match(log(name), new RegExp(`^synthetic ${file.replace('.mjs', '')} ran$`, 'm'));
      assert.ok(order.indexOf(name) < order.indexOf('dependencies-install'), name);
    }
    // The TEST_REQUIRE assertion passed (fail 0) and the skip alone blocks the run, by name.
    const tests = stage('full-tests-current-runtime');
    assert.equal(tests.status, 'blocked');
    assert.match(tests.error, /^Incomplete test coverage: .*"fail":0.*"skipped":1/);
    assert.deepEqual(tests.unexecuted, {
      count: 1,
      tests: [
        {
          test: 'synthetic platform-only case',
          directive: 'SKIP',
          reason: 'synthetic: runs on another platform only',
        },
      ],
    });
    // The gate reports catalog ids (v3 C23), never the earlier names several of which named one
    // id, and records each stage this draft does not implement as pending, with why.
    for (const name of [
      'sast-rules-download',
      'sast-rules-checksum',
      'sast-rules-extract',
      'sast-image-pull',
    ])
      assert.equal(stage(name), undefined, name);
    for (const name of ['sast-rules', 'sast-image', 'gate-implementation'])
      assert.ok(stage(name), `the commit gate records ${name}`);
    // v5 C5 (change 3): neither image build starts while its pre-build authority record is
    // pending, so both builds, container-identity and the two scans of the built image are
    // pending too.
    assert.deepEqual(
      evidence.stages.filter(item => item.status === 'pending').map(item => item.name),
      [
        'gate-identity',
        'gate-import-closure',
        'actionlint-version',
        'pristine-copy',
        'workflow-analysis',
        'image-approval',
        'container-build',
        'container-identity',
        'container-vulnerabilities',
        'container-sbom',
        'systemd-test-image',
      ]
    );
    for (const item of evidence.stages.filter(entry => entry.status === 'pending'))
      assert.ok(item.reason && !item.command, item.name);
    // The local run record's own family (GDR4-02), not a C12 phase record.
    assert.equal(evidence.kind, 'orbit-gate-local-diagnostic-run');
    assert.equal(evidence.kindVersion, 1);
    assert.equal(evidence.schemaVersion, undefined);
    assert.deepEqual(evidence.parents, [gate.git('rev-parse', 'HEAD')]);

    // The scan runs the lints too once its pre-dispatch barrier is open, as here (a candidate
    // whose history never held a platform manifest), so a candidate that breaks them cannot get
    // a green scan. On a CI runner a 1.5 commit's scan keeps the barrier closed and withholds both
    // (test/security-dispatch.test.mjs). (With every scanner synthetic, this scan record may
    // pass; a scan never approves a commit.)
    const scan = gate('scan');
    assert.equal(scan.evidence.mode, 'scan');
    assert.ok(scan.stage('documentation'), scan.result.stdout + scan.result.stderr);
    assert.equal(
      scan.stage('candidate-policy').status,
      'pass',
      scan.stage('candidate-policy').error
    );
    for (const [name, file, flags] of [
      ['sql-lint', 'sql-lint.mjs', []],
      ['import-lint', 'import-graph.mjs', ['--disable-sigusr1']],
    ]) {
      assert.deepEqual(
        scan.stage(name)?.command,
        [process.execPath, ...flags, `scripts/${file}`],
        name
      );
      assert.equal(scan.stage(name).status, 'pass', `scan ${name}`);
    }
  }
);

// A lint that finds a violation blocks the scan and the commit gate, although every npm
// command here (the stand-in) passes: the lint stages do not go through npm, so nothing that
// changes what npm runs (a dependency's `node` bin, an .npmrc an earlier stage wrote, a
// package.json script) can make them pass without running.
test('a failing lint source blocks every mode, whatever npm would do', { timeout: 60000 }, t => {
  if (gitSkip) return t.skip(gitSkip);
  const gate = commitGateFixture(
    t,
    "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
    { 'scripts/sql-lint.mjs': "console.error('synthetic violation');\nprocess.exitCode = 1;\n" }
  );
  for (const mode of ['scan', 'commit']) {
    const { result, evidence, stage, log } = gate(mode);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.equal(evidence.status, 'blocked');
    assert.equal(stage('sql-lint').status, 'blocked', mode);
    assert.equal(stage('sql-lint').exit, 1, mode);
    assert.match(log('sql-lint'), /^synthetic violation$/m);
    assert.equal(stage('import-lint').status, 'pass', mode);
  }
});

// The import lint runs the table registry's modules in a child process, which can still signal
// the lint: SIGUSR1 opens a Node process's inspector, through which a helper could run
// process.exit(0) in the lint with a finding pending. This synthetic lint stands in for that
// child: it signals the lint, and if the inspector opens it exits 0, as the helper would make
// it; otherwise it reports its violation. A busy inspector port shows in the log instead.
test('a child of the import lint cannot open its inspector', { timeout: 60000 }, t => {
  if (gitSkip) return t.skip(gitSkip);
  const gate = commitGateFixture(
    t,
    "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
    {
      'scripts/import-graph.mjs': `import { spawnSync } from 'node:child_process';
import inspector from 'node:inspector';
spawnSync(process.execPath, ['-e', 'process.kill(process.ppid, "SIGUSR1")']);
for (let waited = 0; waited < 2000 && !inspector.url(); waited += 50)
  await new Promise(resolve => setTimeout(resolve, 50));
if (inspector.url()) {
  console.log('synthetic inspector opened');
  process.exit(0);
}
console.error('synthetic violation');
process.exitCode = 1;
`,
    }
  );
  const { result, stage, log } = gate('scan');
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.deepEqual(
    { status: stage('import-lint').status, exit: stage('import-lint').exit },
    { status: 'blocked', exit: 1 },
    log('import-lint')
  );
  assert.match(log('import-lint'), /^synthetic violation$/m);
  assert.doesNotMatch(log('import-lint'), /inspector|debugger/i);
});

// npm searches node_modules/.bin from the snapshot's real path up to the file-system root
// before PATH for `npm run`, and reads the snapshot's .npmrc in every npm command. A
// dependency can link a `node` there and a stage's own script can write either (untracked,
// so candidate-unchanged does not see them): the next npm stage would then pass without
// running its script. Each npm stage looks again first and refuses to run.
test(
  'each npm stage refuses an .npmrc or a node_modules/.bin command that an earlier step left',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    // With a synthetic authority for every withheld operation, so that the npm stages run.
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      {},
      { authority: 'all' }
    );
    const after = (...names) => [
      ...names,
      'dependencies-all',
      'dependencies-production',
      'registry-signatures',
    ];
    for (const [plant, refused, error] of [
      [
        'ci=node_modules/.bin/node',
        after('format', 'syntax-manifest', 'documentation'),
        /\/source\/node_modules\/\.bin\/node would replace node in an npm stage$/,
      ],
      [
        'ci=node_modules/.bin/sh',
        after('format', 'syntax-manifest', 'documentation'),
        /\/source\/node_modules\/\.bin\/sh would replace sh in an npm stage$/,
      ],
      [
        'run check=.npmrc',
        after('documentation'),
        /^An \.npmrc in the snapshot can change what an npm stage runs$/,
      ],
      [
        'run check=../node_modules/.bin/sh',
        after('documentation'),
        /\/orbit-security-[^/]+\/node_modules\/\.bin\/sh would replace sh in an npm stage$/,
      ],
      [
        'run format:check=node_modules/.bin/npx',
        after('syntax-manifest', 'documentation'),
        /\/source\/node_modules\/\.bin\/npx would replace npx in an npm stage$/,
      ],
      // Commands the stages' scripts start by name: check.mjs runs `bash -n` on the installer
      // and the documentation check runs `git`. Any bin that PATH also provides is refused.
      [
        'ci=node_modules/.bin/bash',
        after('format', 'syntax-manifest', 'documentation'),
        /\/source\/node_modules\/\.bin\/bash would replace bash in an npm stage$/,
      ],
      [
        'run check=node_modules/.bin/git',
        after('documentation'),
        /\/source\/node_modules\/\.bin\/git would replace git in an npm stage$/,
      ],
    ]) {
      const npmLog = path.join(temporary(t, 'orbit-gate-npm-log-'), 'npm.log');
      const { result, evidence, stage } = gate('scan', {
        ORBIT_FIXTURE_NPM_PLANT: plant,
        ORBIT_FIXTURE_NPM_LOG: npmLog,
      });
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(evidence.status, 'blocked', plant);
      const blocked = evidence.stages.filter(item => item.status === 'blocked');
      assert.deepEqual(
        blocked.map(item => item.name),
        refused,
        `${plant}: ${JSON.stringify(blocked)}`
      );
      for (const item of blocked) assert.match(item.error, error, `${plant} ${item.name}`);
      // None of the refused stages ran npm; the lints ran first, without it.
      const ran = fs.readFileSync(npmLog, 'utf8').trim().split('\n');
      const commands = {
        format: 'run format:check',
        'syntax-manifest': 'run check',
        documentation: 'run docs:check',
      };
      for (const name of refused)
        if (commands[name]) assert.ok(!ran.includes(commands[name]), `${plant}: ${name} ran`);
      assert.ok(!ran.some(command => command.startsWith('audit')), plant);
      assert.equal(stage('sql-lint').status, 'pass', plant);
      assert.equal(stage('candidate-unchanged').status, 'pass', plant);
    }
    // Positive control: a bin that no command on PATH has (as `prettier` is for the real
    // dependencies) is what the scripts mean to run, and every npm stage runs.
    const npmLog = path.join(temporary(t, 'orbit-gate-npm-log-'), 'npm.log');
    const { evidence } = gate('scan', {
      ORBIT_FIXTURE_NPM_PLANT: 'ci=node_modules/.bin/orbit-fixture-formatter',
      ORBIT_FIXTURE_NPM_LOG: npmLog,
    });
    const npmStages = evidence.stages.filter(item => item.command?.[0] === 'npm');
    assert.deepEqual(
      npmStages.map(item => `${item.name}:${item.status}`),
      [
        'npm-version',
        'dependencies-install',
        'format',
        'syntax-manifest',
        'documentation',
        'dependencies-all',
        'dependencies-production',
        'registry-signatures',
      ].map(name => `${name}:pass`)
    );
    assert.ok(fs.readFileSync(npmLog, 'utf8').includes('\nrun docs:check\n'));
  }
);

// The shell runs a command from a directory it may search but not list, so code an earlier stage
// runs could make a node_modules/.bin that npm searches execute-only (mode 0111) and hide a
// `bash` there from the check above. Each npm stage refuses a .bin it cannot list. The gate
// gives its scratch area's directories back to itself, so it still removes them and records the
// run; one above the scratch area (in TMPDIR) stays, and later runs refuse until it is removed.
test(
  'each npm stage refuses a node_modules/.bin it cannot list, also one an earlier run left',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    // With a synthetic authority for every withheld operation, so that the npm stages run.
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      {},
      { authority: 'all' }
    );
    // The gate's TMPDIR. Every directory under it is given back to this process before it is
    // removed, so what a run left there can be removed too.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-gate-tmpdir-'));
    const restore = () => {
      for (const pending = [tmp]; pending.length; ) {
        const directory = pending.pop();
        fs.chmodSync(directory, 0o700);
        for (const entry of fs.readdirSync(directory, { withFileTypes: true }))
          if (entry.isDirectory()) pending.push(path.join(directory, entry.name));
      }
    };
    t.after(() => {
      restore();
      fs.rmSync(tmp, { recursive: true, force: true });
    });
    // A process that may bypass permissions (root, usually) lists the .bin anyway, and the
    // check above refuses the `bash` in it by name.
    const probe = path.join(tmp, 'probe');
    fs.mkdirSync(probe, { mode: 0o111 });
    let listable = true;
    try {
      fs.readdirSync(probe);
    } catch {
      listable = false;
    }
    fs.rmdirSync(probe);
    const logs = temporary(t, 'orbit-gate-npm-log-');
    let runs = 0;
    const run = (plant, refused, error) => {
      const npmLog = path.join(logs, `npm-${++runs}.log`);
      const { result, evidence } = gate('scan', {
        TMPDIR: tmp,
        ORBIT_FIXTURE_NPM_PLANT: plant,
        ORBIT_FIXTURE_NPM_LOG: npmLog,
      });
      const blocked = evidence.stages.filter(item => item.status === 'blocked');
      assert.deepEqual(
        blocked.map(item => item.name),
        refused,
        `${plant}: ${JSON.stringify(blocked)}\n${result.stderr}`
      );
      for (const item of blocked) assert.match(item.error, error, `${plant} ${item.name}`);
      // A pending stage (the pinned Actionlint, the stages this draft does not implement) is
      // never a pass: the scan exits 1 either way, blocked or pending.
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(evidence.status, refused.length ? 'blocked' : 'pending', plant);
      // The gate removed its scratch area, the execute-only .bin in the snapshot included.
      assert.deepEqual(
        fs.readdirSync(tmp).filter(name => name.startsWith('orbit-security-')),
        [],
        plant
      );
      // The npm commands that ran (none, when the npm stages were all refused).
      return fs.existsSync(npmLog) ? fs.readFileSync(npmLog, 'utf8').trim().split('\n') : [];
    };
    const unlisted = (bin, name = 'bash') =>
      listable
        ? new RegExp(`${bin}/${name} would replace ${name} in an npm stage$`)
        : new RegExp(
            `${bin} cannot be listed \\(EACCES\\), so a command there could replace one in an npm stage$`
          );
    const ran = run(
      'run format:check=node_modules/.bin/bash=111',
      [
        'syntax-manifest',
        'documentation',
        'dependencies-all',
        'dependencies-production',
        'registry-signatures',
      ],
      unlisted('/source/node_modules/\\.bin')
    );
    assert.ok(!ran.includes('run check') && !ran.includes('run docs:check'), ran.join(', '));
    // In TMPDIR, above the scratch area: this run and every later one refuses.
    const above = unlisted('/orbit-gate-tmpdir-[^/]+/node_modules/\\.bin');
    run(
      'run check=../../node_modules/.bin/bash=111',
      ['documentation', 'dependencies-all', 'dependencies-production', 'registry-signatures'],
      above
    );
    assert.deepEqual(run('', ['npm-version', 'dependencies-install'], above), []);
    // Removed, every npm stage runs again.
    restore();
    fs.rmSync(path.join(tmp, 'node_modules'), { recursive: true });
    assert.ok(run('', [], /^$/).includes('run docs:check'));
  }
);

// `npm run security:commit` starts the gate with npm's PATH, which puts every node_modules/.bin
// from the worktree up first, and with NODE_OPTIONS from an .npmrc's node-options (the
// worktree's or the user's) and npm_config_* variables. A dependency installed in the worktree
// could then supply the `gitleaks` a stage starts, and node-options could end a lint with exit 0
// before it checks anything. The gate drops all three before any stage runs. Here they are set
// as npm would set them (the documented entry point is node, which sets none of them).
test(
  'no stage gets the node_modules/.bin PATH entries, NODE_OPTIONS or npm_config_* the gate started with',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    // With a synthetic authority for every withheld operation, so that every stage's command
    // (npm, gitleaks, trivy, docker, ...) starts and can be checked, and (gate-draft-r7,
    // GDR6-REQ-01) identity records for this maintenance candidate's runtimes, so that its test
    // stages start too, as they did before a maintenance run had to identify them.
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      { 'scripts/sql-lint.mjs': "console.error('synthetic violation');\nprocess.exitCode = 1;\n" },
      { authority: 'all', identified: true }
    );
    // An untracked worktree bin (the snapshot never has it) that passes and leaves a marker.
    const marker = path.join(temporary(t, 'orbit-gate-marker-'), 'ran');
    fs.mkdirSync(path.join(gate.root, 'node_modules/.bin'), { recursive: true });
    fs.writeFileSync(
      path.join(gate.root, 'node_modules/.bin/gitleaks'),
      `#!/bin/sh\necho "synthetic tool 0.0.0"\ntouch '${marker}'\nexit 0\n`,
      { mode: 0o755 }
    );
    const environmentLog = path.join(temporary(t, 'orbit-gate-env-log-'), 'env.log');
    for (const mode of ['scan', 'commit']) {
      const { result, evidence, stage, log } = gate(mode, {
        PATH: [
          path.join(gate.root, 'node_modules/.bin'),
          path.join(path.dirname(gate.root), 'node_modules/.bin'),
          gate.bin,
          process.env.PATH,
        ].join(path.delimiter),
        NODE_OPTIONS:
          "--import=data:text/javascript,if(/(sql-lint|import-graph)[.]mjs$/.test(process.argv[1]||''))process.exit(0)",
        npm_config_script_shell: '/usr/bin/true',
        NPM_CONFIG_AUDIT_LEVEL: 'critical',
        ORBIT_FIXTURE_ENV_LOG: environmentLog,
      });
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(evidence.status, 'blocked', mode);
      // The lint ran and found the violation: NODE_OPTIONS did not reach it.
      assert.deepEqual(
        { status: stage('sql-lint').status, exit: stage('sql-lint').exit },
        { status: 'blocked', exit: 1 },
        mode
      );
      assert.match(log('sql-lint'), /^synthetic violation$/m, mode);
      // The fixture's gitleaks ran, not the worktree's.
      for (const name of ['gitleaks-version', 'secrets-source', 'secrets-metadata'])
        assert.equal(stage(name).status, 'pass', `${mode} ${name}`);
      assert.doesNotMatch(log('secrets-source'), /synthetic tool/, mode);
      assert.equal(fs.existsSync(marker), false, `${mode}: the worktree's gitleaks ran`);
      // The test stages' commands started too, so their environment is checked below.
      if (mode === 'commit')
        for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime'])
          assert.ok(stage(name).command, `${name} started`);
    }
    // No stage's command (npm, gitleaks, trivy, docker, ...) got NODE_OPTIONS or the
    // npm_config_* the gate started with. npm stages get only the gate's own two: empty user
    // and global configuration files (separate, as npm requires), not ~/.npmrc or npm's global
    // npmrc, which npm would otherwise read itself.
    const started = fs
      .readFileSync(environmentLog, 'utf8')
      .trim()
      .split('\n')
      .map(line => JSON.parse(line));
    assert.ok(started.some(item => item.name === 'npm'));
    assert.ok(started.some(item => item.name === 'gitleaks'));
    for (const item of started) {
      const npm = item.name === 'npm';
      assert.deepEqual(
        {
          nodeOptions: item.nodeOptions,
          npmConfig: item.npmConfig,
          userConfig: item.userConfig?.content ?? null,
          globalConfig: item.globalConfig?.content ?? null,
        },
        {
          nodeOptions: null,
          npmConfig: npm ? ['npm_config_globalconfig', 'npm_config_userconfig'] : [],
          userConfig: npm ? '' : null,
          globalConfig: npm ? '' : null,
        },
        item.name
      );
      if (npm) assert.notEqual(item.userConfig.path, item.globalConfig.path);
    }
  }
);

// npm reads the user's .npmrc (and its global npmrc) itself, whatever the environment, so
// dropping npm_config_* is not enough: a script-shell there made every `npm run` stage pass
// without running its script, while its log still named the script. Here the real npm runs the
// syntax-manifest stage's `npm run check` (the other npm commands stay synthetic) with a HOME
// whose .npmrc names /usr/bin/true as the shell. CI=1 keeps npm's update check offline.
test("npm stages do not read the user's .npmrc", { timeout: 120000 }, t => {
  if (gitSkip) return t.skip(gitSkip);
  let npm;
  for (const entry of (process.env.PATH ?? '').split(path.delimiter)) {
    try {
      fs.accessSync(path.join(entry, 'npm'), fs.constants.X_OK);
      npm = path.join(entry, 'npm');
      break;
    } catch {
      /* Not in this PATH entry. */
    }
  }
  assert.ok(npm, 'npm is on PATH');
  const home = temporary(t, 'orbit-gate-home-');
  fs.writeFileSync(path.join(home, '.npmrc'), 'script-shell=/usr/bin/true\n');
  for (const [label, check, status, output] of [
    [
      'a failing check',
      "console.error('synthetic check violation');\nprocess.exitCode = 1;\n",
      'blocked',
      /^synthetic check violation$/m,
    ],
    ['a passing check', "console.log('synthetic check ran');\n", 'pass', /^synthetic check ran$/m],
  ]) {
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      {
        'package.json': `${JSON.stringify(
          { scripts: { check: 'node scripts/check.mjs', ...lintScripts } },
          null,
          2
        )}\n`,
        'scripts/check.mjs': check,
      },
      // With a synthetic authority for every withheld operation, so that the npm stages run.
      { authority: 'all' }
    );
    const { stage, log } = gate('scan', { HOME: home, CI: '1', ORBIT_FIXTURE_REAL_NPM: npm });
    assert.equal(stage('syntax-manifest').status, status, `${label}: ${log('syntax-manifest')}`);
    assert.match(log('syntax-manifest'), output, label);
  }
});

// The lint stages run the lint files directly; package.json must name the same commands, so
// `npm run lint:sql` and `npm run lint:imports` cannot quietly run something else (or nothing).
test(
  'candidate-policy refuses lint scripts other than the commands the gate runs',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    for (const [label, scripts, message] of [
      [
        'a no-op lint:sql',
        { 'lint:sql': 'true', 'lint:imports': 'node scripts/import-graph.mjs' },
        'lint:sql must be "node scripts/sql-lint.mjs"',
      ],
      [
        'no lint:imports',
        { 'lint:sql': 'node scripts/sql-lint.mjs' },
        'lint:imports must be "node scripts/import-graph.mjs"',
      ],
      ['no scripts', undefined, 'lint:sql must be "node scripts/sql-lint.mjs"'],
    ]) {
      const gate = commitGateFixture(
        t,
        "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
        { 'package.json': `${JSON.stringify({ scripts }, null, 2)}\n` }
      );
      const { result, stage } = gate('scan');
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.deepEqual(
        { status: stage('candidate-policy').status, error: stage('candidate-policy').error },
        { status: 'blocked', error: `package.json ${message}, the command the gate runs` },
        label
      );
    }
  }
);

// JSON.parse and npm take the last of two members with one name, and Prettier keeps both, so a
// package.json with a second `scripts` or `lint:sql` reads one way to a reviewer and another to
// the gate. candidate-policy accepts only the canonical form (what Prettier writes for
// package.json), which cannot hold a duplicate. Each text below would pass the lint-script
// check on its own; the fixture's canonical package.json, which passes, is the control.
test(
  'candidate-policy refuses a package.json that is not in canonical form',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const canonical = JSON.stringify({ scripts: lintScripts }, null, 2);
    for (const [label, text] of [
      [
        'two scripts members',
        `{"scripts":{"lint:sql":"true","lint:imports":"true"},"scripts":${JSON.stringify(lintScripts)}}\n`,
      ],
      [
        'two lint:sql keys',
        `${canonical.replace('"lint:sql"', '"lint:sql": "true",\n    "lint:sql"')}\n`,
      ],
      ['compact', `${JSON.stringify({ scripts: lintScripts })}\n`],
      ['no final newline', canonical],
    ]) {
      assert.deepEqual(JSON.parse(text).scripts, lintScripts, label);
      const gate = commitGateFixture(
        t,
        "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
        { 'package.json': text }
      );
      const { result, stage } = gate('scan');
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.deepEqual(
        { status: stage('candidate-policy').status, error: stage('candidate-policy').error },
        {
          status: 'blocked',
          error:
            'package.json must be in canonical form (two-space JSON.stringify and a final newline), so no duplicate member can make it ambiguous',
        },
        label
      );
    }
  }
);

// npm reads a tracked .npmrc in every npm stage: with script-shell=/usr/bin/true, each
// `npm run` stage (the lints among them) would pass without running its script while its log
// still names the script. Control flow only: the scanners are synthetic.
test(
  'the gate refuses a tracked .npmrc in any directory or letter case',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    for (const file of ['.npmrc', 'docs/.NPMRC']) {
      const gate = commitGateFixture(
        t,
        "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
        { [file]: 'script-shell=/usr/bin/true\n' }
      );
      for (const mode of ['scan', 'commit']) {
        const { result, evidence, stage } = gate(mode);
        assert.equal(result.status, 1, result.stdout + result.stderr);
        assert.equal(evidence.status, 'blocked');
        assert.deepEqual(
          { status: stage('candidate-policy').status, error: stage('candidate-policy').error },
          {
            status: 'blocked',
            error: `A tracked .npmrc can change what every npm stage runs: ${file}`,
          },
          `${mode} ${file}`
        );
      }
    }
  }
);

// The gate's side of the platform contract (scripts/security-platform.mjs), on the same synthetic
// gate as above: no scanner runs for real, and no test here needs Docker or a browser.

// No stage inherits a test input: the test stages get only the gate's own TEST_REQUIRE, records
// folder and run code, whatever the caller exported, malicious or by accident, in any letter case.
test(
  "no stage inherits TEST_*, UPDATE_GOLDEN or NODE_TEST_CONTEXT; the test stages get the gate's own",
  { timeout: 60000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const gate = commitGateFixture(
      t,
      `import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
// node --test sets NODE_TEST_CONTEXT itself in the processes it starts for the test files, so it
// is not looked at here; the gate's own record and the stand-in tools show it was not inherited.
test('the gate decides every test input', () => {
  const seen = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => /^(?:TEST_|UPDATE_GOLDEN$)/i.test(name))
  );
  assert.deepEqual(Object.keys(seen).sort(), ['TEST_PLATFORM_RECORDS', 'TEST_PLATFORM_RUN', 'TEST_REQUIRE']);
  assert.equal(seen.TEST_REQUIRE, 'browser,fixtures,systemd,docker,capacity,git');
  assert.match(seen.TEST_PLATFORM_RUN, /^[0-9a-f]{64}$/);
  assert.notEqual(seen.TEST_PLATFORM_RUN, 'e'.repeat(64));
  assert.notEqual(seen.TEST_PLATFORM_RECORDS, process.env.ORBIT_FIXTURE_FORGED);
  assert.equal(fs.lstatSync(seen.TEST_PLATFORM_RECORDS).mode & 0o777, 0o700);
  assert.deepEqual(fs.readdirSync(seen.TEST_PLATFORM_RECORDS), []);
  // Everything else is inherited, as the gate records: here the browser it was given.
  assert.equal(process.env.CHROME_PATH, '/synthetic/elsewhere/fake-chrome');
});
`,
      {},
      // With a synthetic authority for every withheld operation, so that the test stages run, and
      // (gate-draft-r7, GDR6-REQ-01) identity records for this maintenance candidate's runtimes.
      { authority: 'all', identified: true }
    );
    const forged = temporary(t, 'orbit-forged-records-');
    const forgedRecord = '1234-0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d.jsonl';
    fs.writeFileSync(path.join(forged, forgedRecord), '{"kind":"result"}\n');
    const environmentLog = path.join(temporary(t, 'orbit-gate-env-'), 'environment.jsonl');
    const inherited = {
      TEST_REQUIRE: '',
      TEST_T8_DIR: '/',
      TEST_T8_RUN: 'f'.repeat(64),
      TEST_TAG_TREES: forged,
      // The private history input (test/upgrade/history.mjs) is a test input like the others.
      TEST_HISTORY: forged,
      TEST_PLATFORM_RECORDS: forged,
      TEST_PLATFORM_RUN: 'e'.repeat(64),
      UPDATE_GOLDEN: '1',
      update_golden: '1',
      test_require: 'browser',
      NODE_TEST_CONTEXT: 'child',
      TEST_FUTURE_SWITCH: 'a value\nwith a line break',
    };
    const { evidence, stage, log } = gate('commit', {
      ...inherited,
      ORBIT_FIXTURE_FORGED: forged,
      ORBIT_FIXTURE_ENV_LOG: environmentLog,
      CHROME_PATH: '/synthetic/elsewhere/fake-chrome',
      DOCKER_HOST: 'unix:///synthetic/elsewhere/docker.sock',
    });
    const tests = stage('full-tests-current-runtime');
    assert.equal(tests.status, 'pass', `${tests.error}\n${log('full-tests-current-runtime')}`);
    assert.deepEqual(tests.tests, {
      tests: 1,
      pass: 1,
      fail: 0,
      cancelled: 0,
      skipped: 0,
      todo: 0,
    });
    // The record names what was removed, never a value.
    assert.deepEqual(evidence.inheritedTestInputs, {
      count: 12,
      names: Object.keys(inherited).sort(),
    });
    assert.doesNotMatch(JSON.stringify(evidence), /line break|child"/);
    // What every stage inherits instead is recorded (verifier, round 1: the docs said the gate took
    // only two inputs from the caller): every name, and the values of the variables that choose a
    // tool the tests use, such as the browser and the Docker daemon.
    const kept = evidence.inheritedEnvironment;
    assert.ok(kept.names.includes('CHROME_PATH') && kept.names.includes('DOCKER_HOST'));
    assert.ok(!kept.names.some(name => /^(?:TEST_|UPDATE_GOLDEN$|NODE_TEST_CONTEXT$)/i.test(name)));
    assert.equal(kept.values.CHROME_PATH, '/synthetic/elsewhere/fake-chrome');
    assert.equal(kept.values.DOCKER_HOST, 'unix:///synthetic/elsewhere/docker.sock');
    assert.equal(kept.count, kept.names.length);
    // No stand-in tool (npm, docker, the scanners) saw one either; the Node 24 stand-in, which runs
    // the minimum-runtime test stage, saw only the gate's three.
    const started = fs
      .readFileSync(environmentLog, 'utf8')
      .trim()
      .split('\n')
      .map(line => JSON.parse(line));
    assert.ok(started.length > 5);
    for (const item of started)
      assert.deepEqual(
        item.testInputs,
        item.name === 'orbit-fixture-node24' && item.testInputs.length
          ? ['TEST_PLATFORM_RECORDS', 'TEST_PLATFORM_RUN', 'TEST_REQUIRE']
          : [],
        item.name
      );
    assert.ok(started.some(item => item.name === 'orbit-fixture-node24' && item.testInputs.length));
    // The forged records folder was neither used nor changed.
    assert.deepEqual(fs.readdirSync(forged), [forgedRecord]);
  }
);

// A synthetic platform manifest for this host and the other platform, with a test file whose
// tests record what they ran as the platform test helper does (test/helpers/platform.mjs).
const hostPlatform = process.platform;
const otherPlatform = hostPlatform === 'darwin' ? 'linux' : 'darwin';
// `pinned` gives the container run a pinned image for each runtime (the fixture images of
// test/helpers/platform-run.mjs), each with a driver test of its own. `runtimes` are the runs' and
// entries' runtimes: the real matrix, Node 24 and 26, unless a test gives the route a gate started
// on this runtime covers (gateRuntimes, test/helpers/runtime-identity.mjs; GD5-CARRY-01).
function gateManifest({ container = false, pinned = null, runtimes = ['24', '26'] } = {}) {
  const runs = {
    [`${hostPlatform}-full`]: {
      platform: hostPlatform,
      runtimes,
      files: 'all',
      requiredFor: ['commit'],
    },
    [`${hostPlatform}-platform`]: {
      platform: hostPlatform,
      runtimes,
      files: ['test/fixture.test.mjs'],
      requiredFor: ['commit'],
    },
    [`${otherPlatform}-full`]: {
      platform: otherPlatform,
      runtimes,
      files: 'all',
      requiredFor: ['commit'],
    },
  };
  const entry = (id, name, platform, evidence) => ({
    id,
    file: 'test/fixture.test.mjs',
    name: [name],
    platforms: [platform],
    runtimes,
    prerequisites: [],
    evidence,
  });
  const entries = [
    entry('synthetic.here', 'synthetic platform test here', hostPlatform, [
      `${hostPlatform}-full`,
      `${hostPlatform}-platform`,
    ]),
    entry('synthetic.there', 'synthetic platform test there', otherPlatform, [
      `${otherPlatform}-full`,
    ]),
  ];
  if (container || pinned) {
    runs['synthetic-container'] = {
      platform: 'container',
      runtimes,
      files: ['test/fixture.test.mjs'],
      requiredFor: ['commit'],
      images: pinned
        ? Object.fromEntries(
            runtimes.map(runtime => [
              runtime,
              { image: pinned[runtime], driver: `synthetic.driver${runtime}` },
            ])
          )
        : Object.fromEntries(runtimes.map(runtime => [runtime, null])),
      hostRuns: [`${hostPlatform}-full`],
    };
    entries.push(
      entry('synthetic.inner', 'synthetic inner test', 'container', ['synthetic-container'])
    );
    if (pinned)
      for (const runtime of runtimes)
        entries.push({
          ...entry(`synthetic.driver${runtime}`, `synthetic driver ${runtime}`, hostPlatform, [
            `${hostPlatform}-full`,
          ]),
          prerequisites: ['docker'],
        });
  }
  return `${JSON.stringify({ schemaVersion: 1, runs, entries }, null, 2)}\n`;
}
const recordingTests = body => `import test from 'node:test';
import fs from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
const manifest = createHash('sha256').update(fs.readFileSync('test/platform-manifest.json')).digest('hex');
const record = (id, name) =>
  fs.appendFileSync(
    \`\${process.env.TEST_PLATFORM_RECORDS}/\${process.pid}-\${randomUUID()}.jsonl\`,
    JSON.stringify({ kind: 'result', id, file: 'test/fixture.test.mjs', name: [name], platform: process.platform, node: process.version, result: 'completed', run: process.env.TEST_PLATFORM_RUN, manifest }) + '\\n'
  );
${body}
`;
const here =
  "test('synthetic platform test here', () => record('synthetic.here', 'synthetic platform test here'));";
// gate-draft-r6 (GD5-CARRY-01): a test stage starts only once test-host and runtime-identity have
// passed in its run. This writes synthetic runtime identity records for the two runtimes a fixture's
// gate runs, its own and the Node 24 stand-in (test/helpers/runtime-identity.mjs), so that a run of
// the manifest route a gate on this runtime covers (gateRuntimes) passes runtime-identity.
const identify = gate =>
  writeRuntimeIdentity(gate.root, [
    { executable: process.execPath, version: process.version },
    { executable: path.join(gate.bin, 'orbit-fixture-node24'), version: 'v24.0.0' },
  ]);
// The fixture with the manifest staged (not committed): the candidate introduces it. `authority`
// as in commitGateFixture; `identified` writes the runtime identity records (identify); the other
// options are gateManifest's.
function platformGate(t, body, { authority = null, identified = false, ...options } = {}) {
  const gate = commitGateFixture(
    t,
    recordingTests(body),
    {
      'test/other.test.mjs':
        "import test from 'node:test';\ntest('a test of another file', () => {});\n",
    },
    { authority }
  );
  fs.writeFileSync(path.join(gate.root, 'test/platform-manifest.json'), gateManifest(options));
  gate.git('add', '-A');
  if (identified) identify(gate);
  return gate;
}

test(
  "each full-test stage's coverage of this host's full run is checked, and blocks on a missing, unrecorded or other-platform test",
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const runtime = process.versions.node.split('.')[0];
    // With a synthetic authority for every withheld operation, so that the test stages run.
    const authority = 'all';
    // No runtime identity record, and the real matrix (Node 24 and 26): runtime-identity blocks, by
    // name, and since gate-draft-r6 (GD5-CARRY-01) no test stage starts, authority or not.
    const unidentified = platformGate(t, here, { authority })('commit');
    assert.equal(unidentified.stage('test-host').status, 'pass');
    assert.equal(unidentified.stage('runtime-identity').status, 'blocked');
    assert.match(
      unidentified.stage('runtime-identity').error,
      /no runtime identity record for Node v/
    );
    // Its runtimes: on Node 26 the gate's own stage and the Node 24 stand-in's cover both of the
    // run's. Started on Node 24, the gate runs Node 24 twice, and the run lacks Node 26: the gate
    // blocks there itself (verifier, round 1: it passed and could then never be finalized). The
    // stage runs before the test stages now (v5 C23 O), on the runtimes they will run.
    const gap = new RegExp(
      `run ${hostPlatform}-full needs Node 26, which no test stage of this run runs: start the gate with Node 26`
    );
    if (runtime === '24') assert.match(unidentified.stage('runtime-identity').error, gap);
    else
      assert.doesNotMatch(
        unidentified.stage('runtime-identity').error,
        /which no test stage of this run runs/
      );
    for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime']) {
      const withheld = unidentified.stage(name);
      assert.equal(withheld.status, 'pending', name);
      assert.equal(withheld.command, undefined, name);
      assert.match(
        withheld.reason,
        /runtime-identity is blocked \((?:no runtime identity record for Node v|run \S+ needs Node 26)/,
        name
      );
      assert.match(
        unidentified.stage(name.replace('full-tests-', 'platform-coverage-')).reason,
        /was withheld before dispatch, so there is no run of it to check/
      );
    }
    const unidentifiedNames = unidentified.evidence.stages.map(stage => stage.name);
    assert.ok(
      unidentifiedNames.indexOf('runtime-identity') <
        unidentifiedNames.indexOf('full-tests-current-runtime'),
      JSON.stringify(unidentifiedNames)
    );
    // A valid host and runtime combination: identity records for both runtimes, and the route a
    // gate started on this runtime covers (on Node 24, Node 24 alone). Both pass, the test stages
    // run, and each one's coverage is checked.
    const runtimes = gateRuntimes();
    const passing = platformGate(t, here, { authority, identified: true, runtimes })('commit');
    assert.equal(
      passing.stage('platform-manifest').status,
      'pass',
      passing.stage('platform-manifest').error
    );
    assert.equal(passing.evidence.platform.kind, 'introduction');
    assert.equal(passing.stage('test-host').status, 'pass', passing.stage('test-host').error);
    assert.equal(
      passing.stage('runtime-identity').status,
      'pass',
      passing.stage('runtime-identity').error
    );
    const coverage = passing.stage('platform-coverage-current-runtime');
    assert.equal(coverage.status, 'pass', coverage.error);
    assert.deepEqual(
      { of: coverage.of, run: coverage.run, runtime: coverage.runtime },
      { of: 'full-tests-current-runtime', run: `${hostPlatform}-full`, runtime }
    );
    const report = JSON.parse(passing.file(coverage.report));
    assert.deepEqual(
      report.coverage.map(item => [item.id, item.status]),
      [
        ['synthetic.here', 'required'],
        ['synthetic.there', 'absent'],
      ]
    );
    // The stage's records are sealed beside its log; its runtime and run code are recorded.
    const tested = passing.stage('full-tests-current-runtime');
    assert.match(tested.platformRun, /^[0-9a-f]{64}$/);
    assert.equal(tested.runtime.version, process.version);
    assert.match(tested.runtime.sha256, /^[0-9a-f]{64}$/);
    assert.equal(JSON.parse(passing.file(tested.records)).files.length, 1);
    // runtime-identity identified the stage's own binary.
    assert.ok(
      passing
        .stage('runtime-identity')
        .runtimes.some(
          item => item.sha256 === tested.runtime.sha256 && item.version === process.version
        )
    );
    const names = passing.evidence.stages.map(stage => stage.name);
    assert.ok(
      names.indexOf('runtime-identity') < names.indexOf('full-tests-current-runtime'),
      JSON.stringify(names)
    );
    for (const [label, body, pattern] of [
      [
        'an unrecorded test',
        "test('synthetic platform test here', () => {});",
        /synthetic\.here .* has 0 records in this run, not one/,
      ],
      [
        'a missing test',
        "test('another test', () => {});",
        /synthetic\.here .* has 0 result lines in this run, not one: absence is not a pass/,
      ],
      [
        'a test of the other platform',
        `${here}\ntest('synthetic platform test there', () => {});`,
        new RegExp(
          `synthetic\\.there .* belongs to ${otherPlatform}, not ${hostPlatform}, but TAP line`
        ),
      ],
      [
        'a skipped platform test',
        "test('synthetic platform test here', { skip: 'synthetic' }, () => {});",
        /synthetic\.here .* did not pass|directive SKIP/,
      ],
    ]) {
      const blocked = platformGate(t, body, { authority, identified: true, runtimes })(
        'commit'
      ).stage('platform-coverage-current-runtime');
      assert.equal(blocked.status, 'blocked', label);
      assert.match(blocked.error, pattern, label);
    }
    // A container run's tests are absent from a host run at any depth, and its evidence is
    // required by name (here no image is pinned, so there is none).
    const inner = platformGate(t, `${here}\ntest('synthetic inner test', () => {});`, {
      container: true,
      authority,
      identified: true,
      runtimes,
    })('commit');
    const innerCoverage = inner.stage('platform-coverage-current-runtime');
    assert.equal(innerCoverage.status, 'blocked');
    assert.match(
      innerCoverage.error,
      new RegExp(`synthetic\\.inner .* belongs to container, not ${hostPlatform}, but TAP line`)
    );
    assert.match(
      innerCoverage.error,
      /no T8 container evidence for Node 24: synthetic-container\.images\.24 is null/
    );
  }
);

test(
  'the gate refuses a candidate that deletes or weakens a committed manifest, unless reviewed dispositions bound to it excuse the loss',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const manifest = gateManifest();
    const gate = commitGateFixture(t, recordingTests(here), {
      'test/platform-manifest.json': manifest,
    });
    const root = gate.git('rev-parse', 'HEAD');
    fs.rmSync(path.join(gate.root, 'test/platform-manifest.json'));
    gate.git('add', '-A');
    const deleted = gate('commit').stage('platform-manifest');
    assert.equal(deleted.status, 'blocked');
    assert.match(
      deleted.error,
      /has no test\/platform-manifest\.json, which a commit behind it holds/
    );
    // Weakened: the host entry no longer required of the host's platform run.
    const weak = JSON.parse(manifest);
    const old = weak.entries[0];
    weak.entries[0] = { ...old, evidence: [`${hostPlatform}-full`] };
    fs.writeFileSync(
      path.join(gate.root, 'test/platform-manifest.json'),
      `${JSON.stringify(weak, null, 2)}\n`
    );
    gate.git('add', '-A');
    const weakened = gate('commit').stage('platform-manifest');
    assert.equal(weakened.status, 'blocked');
    assert.match(weakened.error, /no reviewed manifest can be established/);
    // The reviewed dispositions file: the committed manifest as a baseline, and the loss.
    const tree = gate.git('write-tree');
    // Bound to the tree and the complete ordered parent vector (v3 C18).
    const binding = { tree, parents: [root] };
    const review = {
      reason: 'synthetic',
      reviewer: 'Synthetic reviewer',
      reference: 'synthetic review',
      ...binding,
    };
    const dispositions = {
      schemaVersion: 2,
      ...binding,
      dispositions: [
        {
          baseline: root,
          manifestSha256: createHash('sha256').update(manifest).digest('hex'),
          ...review,
        },
        {
          loss: `entry:synthetic.here:evidence:${hostPlatform}-platform`,
          old,
          replacement: null,
          ...review,
        },
      ],
    };
    const file = path.join(gate.root, '.git/orbit-security/coverage', `${tree}.json`);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify(dispositions), { mode: 0o600 });
    const excused = gate('commit');
    assert.equal(
      excused.stage('platform-manifest').status,
      'pass',
      excused.stage('platform-manifest').error
    );
    assert.equal(excused.evidence.platform.kind, 'manifest');
    // The exact file is sealed with the run, so the finalization review binds it.
    assert.equal(excused.file('coverage-dispositions.json'), fs.readFileSync(file, 'utf8'));
    // Bound to another tree: refused.
    fs.writeFileSync(file, JSON.stringify({ ...dispositions, tree: 'b'.repeat(40) }), {
      mode: 0o600,
    });
    assert.match(
      gate('commit').stage('platform-manifest').error,
      /not bound to this candidate's tree and complete ordered parent vector/
    );
    // Bound to the same tree and another, or an added, parent: refused.
    for (const parents of [['b'.repeat(40)], [root, 'b'.repeat(40)]]) {
      fs.writeFileSync(file, JSON.stringify({ ...dispositions, parents }), { mode: 0o600 });
      assert.match(
        gate('commit').stage('platform-manifest').error,
        /not bound to this candidate's tree and complete ordered parent vector/
      );
    }
    // The earlier form, bound to a single parent, gives no authority.
    const { parents: vector, ...rest } = dispositions;
    fs.writeFileSync(file, JSON.stringify({ ...rest, schemaVersion: 1, parent: vector[0] }), {
      mode: 0o600,
    });
    assert.match(
      gate('commit').stage('platform-manifest').error,
      /version 1, bound to a single parent, which gives no authority/
    );
  }
);

test(
  'the gate judges the history as its commits hold it: an exported GIT_GRAFT_FILE cannot hide a deleted manifest, and a grafts file or a shallow repository is refused',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const gate = commitGateFixture(t, recordingTests(here), {
      'test/platform-manifest.json': gateManifest(),
    });
    // A commit made without the guard deletes the manifest; the candidate comes after it.
    fs.rmSync(path.join(gate.root, 'test/platform-manifest.json'));
    gate.git('add', '-A');
    gate.git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      'Deletes the manifest without the guard'
    );
    const deleted = gate.git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(gate.root, 'README.md'), '# Synthetic gate fixture, changed\n');
    gate.git('add', '-A');
    const grafts = path.join(temporary(t, 'orbit-gate-grafts-'), 'grafts');
    fs.writeFileSync(grafts, `${deleted}\n`);
    // With the grafts file exported first, then without: the gate finds the deletion either way.
    for (const env of [{ GIT_GRAFT_FILE: grafts }, {}]) {
      const run = gate('commit', env);
      const judged = run.stage('platform-manifest');
      assert.equal(judged.status, 'blocked', JSON.stringify(env));
      assert.match(
        judged.error,
        /has no test\/platform-manifest\.json, which a commit behind it holds/,
        JSON.stringify(env)
      );
      // The name of the variable the gate replaced is recorded, never its value.
      assert.deepEqual(run.evidence.inheritedHistoryInputs, Object.keys(env));
      assert.ok(!JSON.stringify(run.evidence).includes(grafts));
    }
    // A grafts file in the repository, or a shallow boundary, is refused before any stage.
    const environment = { ...process.env, PATH: `${gate.bin}${path.delimiter}${process.env.PATH}` };
    delete environment.NODE_TEST_CONTEXT;
    const started = file => {
      const result = spawnSync(
        process.execPath,
        [path.join(gate.root, 'scripts/security-gate.mjs'), 'commit'],
        {
          cwd: gate.root,
          encoding: 'utf8',
          timeout: 20000,
          env: environment,
        }
      );
      fs.rmSync(file);
      return result;
    };
    const infoGrafts = path.join(gate.root, '.git/info/grafts');
    fs.mkdirSync(path.dirname(infoGrafts), { recursive: true });
    fs.writeFileSync(infoGrafts, `${deleted}\n`);
    const graftsRefused = started(infoGrafts);
    assert.notEqual(graftsRefused.status, 0);
    assert.match(graftsRefused.stderr, /The history cannot be judged: .*info\/grafts exists/);
    const shallow = path.join(gate.root, '.git/shallow');
    fs.writeFileSync(shallow, `${deleted}\n`);
    const shallowRefused = started(shallow);
    assert.notEqual(shallowRefused.status, 0);
    assert.match(shallowRefused.stderr, /Full history is required/);
  }
);

test(
  'the platform mode runs one companion run of the manifest on this host, and seals it',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    // With a synthetic authority for every withheld operation and a valid host and runtime
    // combination (gate-draft-r6, GD5-CARRY-01: identity records for both runtimes and the route a
    // gate on this runtime covers), so that the test stages run.
    const gate = platformGate(t, here, {
      authority: 'all',
      identified: true,
      runtimes: gateRuntimes(),
    });
    const companion = gate(['platform', `${hostPlatform}-platform`]);
    assert.equal(companion.evidence.mode, 'platform');
    assert.equal(companion.evidence.platformRun, `${hostPlatform}-platform`);
    assert.equal(companion.evidence.host.uid, process.getuid());
    for (const name of ['test-host', 'runtime-identity'])
      assert.equal(companion.stage(name).status, 'pass', companion.stage(name).error);
    const tested = companion.stage('platform-tests-current-runtime');
    assert.equal(tested.status, 'pass', tested.error);
    assert.equal(tested.command.at(-1), 'test/fixture.test.mjs');
    assert.doesNotMatch(companion.log('platform-tests-current-runtime'), /a test of another file/);
    assert.equal(companion.stage('platform-coverage-current-runtime').status, 'pass');
    // A companion runs no scanner, and its evidence is sealed like a commit run's.
    assert.equal(companion.stage('secrets-source'), undefined);
    assert.equal(companion.stage('independent-review'), undefined);
    assert.ok(fs.existsSync(path.join(companion.directory, 'run-manifest.json')));
    // A run of another platform, or one the manifest does not have, is refused here.
    for (const [id, pattern] of [
      [
        `${otherPlatform}-full`,
        new RegExp(`runs on ${otherPlatform}, not on this ${hostPlatform} host`),
      ],
      ['no-such-run', /is not a run of the platform manifest that a host runs/],
    ]) {
      const refused = gate(['platform', id]).stage('platform-manifest');
      assert.equal(refused.status, 'blocked', id);
      assert.match(refused.error, pattern, id);
    }
    for (const args of [
      ['platform'],
      ['platform', 'Not_A_Run'],
      ['platform', 'a', 'b'],
      ['commit', 'extra'],
    ]) {
      const usage = spawnSync(
        process.execPath,
        [path.join(gate.root, 'scripts/security-gate.mjs'), ...args],
        {
          cwd: gate.root,
          encoding: 'utf8',
          timeout: 20000,
        }
      );
      assert.notEqual(usage.status, 0, args.join(' '));
      assert.match(
        usage.stderr,
        /Usage: node scripts\/security-gate\.mjs commit\|release\|scan, or platform <run-id>/
      );
    }
  }
);

// Security review GD-R2: a candidate's .github/actionlint.yaml or .yml could silence the bare `actionlint`
// the earlier gate started from PATH; the gate refuses a candidate configuration before anything
// is installed. Maintainer decision 8: Actionlint may run only as the qualified golden-tool manifest of
// the trusted gate export binds it, which this draft does not have, so both stages are pending and
// blocking. verify-1 of gate-draft-r3 found that a local golden-tool record under
// <git common dir>/orbit-security/golden-tools/ passed both stages, even one that pinned the
// `actionlint` first on PATH by the hash observed at run time: such a record is a local file that
// nothing authenticates. The gate now neither reads it nor runs what it names. Stand-ins only: no
// real Actionlint runs.
test(
  'decision 8 and GD-R2: a candidate Actionlint configuration is refused, and a local golden-tool record gives no authority: nothing it names or on PATH runs',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const platform = await import('../scripts/security-platform.mjs');
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      {
        '.github/workflows/synthetic.yml':
          'on: push\njobs:\n  synthetic:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo ${{ env.UNDEFINED_SYNTHETIC }}\n',
        '.github/actionlint.yaml':
          "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n      - '.*'\n",
      }
    );
    const base = path.dirname(gate.root);
    const environmentLog = path.join(base, 'environment.log');
    const pinnedLog = path.join(base, 'pinned.log');
    const pinned = path.join(base, 'pinned', 'actionlint');
    fs.mkdirSync(path.dirname(pinned));
    fs.writeFileSync(
      pinned,
      `#!/bin/sh\nprintf '%s\\n' "$*" >> '${pinnedLog}'\ncase "$1" in -version) echo '0.0.0';; esac\nexit 0\n`,
      { mode: 0o755 }
    );
    const pathActionlintRan = () =>
      fs.existsSync(environmentLog) &&
      fs
        .readFileSync(environmentLog, 'utf8')
        .split('\n')
        .filter(Boolean)
        .some(line => JSON.parse(line).name === 'actionlint');
    const scan = () => gate('scan', { ORBIT_FIXTURE_ENV_LOG: environmentLog });
    const recordFile = path.join(
      gate.root,
      '.git/orbit-security/golden-tools',
      `actionlint-${process.platform}-${process.arch}.json`
    );
    const golden = binary => ({
      schemaVersion: 2,
      tool: 'actionlint',
      platform: process.platform,
      arch: process.arch,
      path: binary,
      version: '0.0.0',
      sha256: sha256(fs.readFileSync(binary)),
      provenance: {
        source: 'synthetic golden-tool fixture',
        archive: 'none',
        archiveSha256: '0'.repeat(64),
        verification: 'synthetic: not a verified tool',
      },
      dependencyClosure: [],
      reviewer: 'Synthetic reviewer',
      reference: 'synthetic review',
      reviewedAt: new Date(Date.now() - 60000).toISOString(),
    });
    const writeRecord = value => {
      fs.mkdirSync(path.dirname(recordFile), { recursive: true, mode: 0o700 });
      fs.writeFileSync(recordFile, JSON.stringify(value), { mode: 0o600 });
    };
    const expected = run =>
      platform.missingToolPin({
        tool: 'actionlint',
        version: JSON.parse(run.file('tool-config.json')).actionlint,
        platform: process.platform,
        arch: process.arch,
      });
    const unpinned = (run, label, local) => {
      assert.equal(run.result.status, 1, label);
      assert.notEqual(run.evidence.status, 'pass', label);
      for (const name of ['actionlint-version', 'workflow-analysis']) {
        const stage = run.stage(name);
        assert.equal(stage.status, 'pending', `${label}: ${name}`);
        assert.deepEqual(stage.missingPin, expected(run), `${label}: ${name}`);
        assert.match(stage.reason, /^BLOCKING: no qualified Actionlint pin/, `${label}: ${name}`);
        assert.equal(stage.command, undefined, `${label}: ${name}`);
        assert.equal(stage.tool, undefined, `${label}: ${name}`);
        if (local)
          assert.match(
            stage.reason,
            /A local golden-tool record exists at .*: it gives no authority, so it was not read and nothing it names ran/,
            `${label}: ${name}`
          );
        else assert.doesNotMatch(stage.reason, /local golden-tool record exists/, label);
      }
      // Nothing of the record is sealed, and no Actionlint configuration is written.
      assert.ok(
        !fs.readdirSync(run.directory).some(name => /^golden-tool-|^actionlint-/.test(name)),
        `${label}: ${fs.readdirSync(run.directory)}`
      );
      assert.equal(fs.existsSync(pinnedLog), false, `${label}: the recorded binary ran`);
      assert.equal(pathActionlintRan(), false, `${label}: an actionlint on PATH ran`);
    };
    // No record, and a candidate configuration: candidate-policy refuses it; Actionlint pending.
    const configured = scan();
    assert.equal(configured.stage('candidate-policy').status, 'blocked');
    assert.match(
      configured.stage('candidate-policy').error,
      /A tracked Actionlint configuration can silence workflow findings: \.github\/actionlint\.yaml/
    );
    unpinned(configured, 'no record', false);
    // The candidate configuration removed; a well-formed local record pinning a stand-in.
    gate.git('rm', '--quiet', '.github/actionlint.yaml');
    gate.git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      'Without the configuration'
    );
    writeRecord(golden(pinned));
    const recorded = scan();
    assert.equal(
      recorded.stage('candidate-policy').status,
      'pass',
      recorded.stage('candidate-policy').error
    );
    unpinned(recorded, 'a local record pinning a stand-in', true);
    // A local record that pins the `actionlint` first on PATH by its observed hash.
    writeRecord(golden(path.join(gate.bin, 'actionlint')));
    unpinned(scan(), 'a local record pinning the PATH binary by its observed hash', true);
    // A malformed record (version 1, no closure) is not read either.
    const { dependencyClosure: _none, ...version1 } = { ...golden(pinned), schemaVersion: 1 };
    writeRecord(version1);
    unpinned(scan(), 'a version 1 record', true);
  }
);

// GATE-CONTRACT v3 (a draft) C18 and C23, as the gate records them: a run is bound to the
// candidate's complete ordered parent vector and its candidate identity, never HEAD alone, and
// reports the catalog's stage ids, each stage this draft does not implement recorded as pending.
test(
  'the gate binds its run to the complete parent vector, the candidate identity and the catalog, and reports pending stages',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const platform = await import('../scripts/security-platform.mjs');
    const catalog = await import('../scripts/security-catalog.mjs');
    // With a synthetic authority for every withheld operation, so that the Semgrep rules stage and
    // the image check run.
    const gate = platformGate(t, here, { authority: 'all' });
    const head = gate.git('rev-parse', 'HEAD');
    const run = gate('commit');
    const { evidence } = run;
    assert.equal(evidence.kind, platform.LOCAL_RUN_KIND);
    assert.equal(evidence.kindVersion, platform.LOCAL_RUN_KIND_VERSION);
    assert.deepEqual(evidence.parents, [head]);
    assert.equal(evidence.parent, undefined);
    const identity = platform.candidateIdentity({
      tree: evidence.tree,
      parents: [head],
      files: JSON.parse(run.file('source-manifest.json')),
      platformManifest: {
        sha256: createHash('sha256').update(gateManifest()).digest('hex'),
        state: 'valid',
      },
    });
    assert.deepEqual(evidence.candidate, identity.record);
    assert.equal(evidence.candidateIdentitySha256, identity.sha256);
    assert.deepEqual(evidence.catalog, {
      sha256: catalog.installedCatalog().sha256,
      mode: 'commit',
      profile: catalog.mainProfileFor(hostPlatform),
    });
    const pending = evidence.stages.filter(stage => stage.status === 'pending');
    for (const name of [
      'gate-identity',
      'gate-import-closure',
      'pristine-copy',
      'image-approval',
      'actionlint-version',
      'workflow-analysis',
      't8-image-identity',
      't8-image-authenticity',
    ])
      assert.ok(
        pending.some(stage => stage.name === name && stage.reason && !stage.command),
        `${name} pending`
      );
    for (const name of Object.keys(catalog.refusedNames))
      assert.equal(run.stage(name), undefined, name);
    assert.ok(
      run.stage('sast-rules') && run.stage('sast-image') && run.stage('gate-implementation')
    );
    assert.deepEqual(
      run.stage('sast-rules').steps.map(step => step.name),
      ['sast-rules-download', 'sast-rules-extract']
    );
    assert.deepEqual(run.stage('sast-image').command.slice(0, 3), ['docker', 'image', 'inspect']);
    assert.notEqual(evidence.status, 'pass');
    // A merge being concluded: the run is bound to HEAD and the MERGE_HEAD commit, in order.
    const side = gate.git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      'commit-tree',
      `${head}^{tree}`,
      '-p',
      head,
      '-m',
      'side'
    );
    const mergeHead = path.join(gate.root, '.git/MERGE_HEAD');
    fs.writeFileSync(mergeHead, `${side}\n`);
    assert.deepEqual(gate('commit').evidence.parents, [head, side]);
    // A MERGE_HEAD that names a commit twice: no run is made at all.
    fs.writeFileSync(mergeHead, `${side}\n${side}\n`);
    const refused = spawnSync(
      process.execPath,
      [path.join(gate.root, 'scripts/security-gate.mjs'), 'commit'],
      {
        encoding: 'utf8',
        timeout: 25000,
        env: { ...process.env, PATH: `${gate.bin}${path.delimiter}${process.env.PATH}` },
      }
    );
    assert.equal(refused.status, 1, refused.stderr);
    assert.match(refused.stderr, /complete parent vector of the candidate is not known/);
    fs.rmSync(mergeHead);
  }
);

// Maintainer decision 8: with no reviewed Actionlint pin the run is pending AND blocking (exit 1). Both
// Actionlint stages name the missing pin and the evidence it needs; nothing named actionlint on
// PATH runs; the other stages still run, and none of them is an Actionlint pass. Stand-ins only.
test(
  'decision 8: a missing reviewed Actionlint pin is pending and blocking, names the missing pin, and nothing falls back to PATH',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const platform = await import('../scripts/security-platform.mjs');
    // With a synthetic authority for every withheld operation, so that the other stages run.
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic passes', () => {});\n",
      {
        '.github/workflows/synthetic.yml':
          'on: push\njobs:\n  synthetic:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo synthetic\n',
      },
      { authority: 'all' }
    );
    const environmentLog = path.join(path.dirname(gate.root), 'environment.log');
    const run = gate('scan', { ORBIT_FIXTURE_ENV_LOG: environmentLog });
    assert.equal(run.result.status, 1, run.result.stdout + run.result.stderr);
    assert.equal(run.evidence.status, 'pending');
    const tools = JSON.parse(run.file('tool-config.json'));
    const expected = platform.missingToolPin({
      tool: 'actionlint',
      version: tools.actionlint,
      platform: process.platform,
      arch: process.arch,
    });
    for (const name of ['actionlint-version', 'workflow-analysis']) {
      const stage = run.stage(name);
      assert.equal(stage.status, 'pending', name);
      assert.deepEqual(stage.missingPin, expected, name);
      assert.match(stage.reason, /^BLOCKING: no qualified Actionlint pin/, name);
      assert.match(stage.reason, /qualified golden-tool manifest/, name);
      assert.match(stage.reason, /dependencyClosure/, name);
      assert.equal(stage.command, undefined, name);
      assert.match(run.result.stdout, new RegExp(`Pending \\(blocking\\): ${name}: BLOCKING`));
    }
    // Nothing named actionlint on PATH ran, and no other stage stood in for it.
    const ran = fs.existsSync(environmentLog)
      ? fs
          .readFileSync(environmentLog, 'utf8')
          .split('\n')
          .filter(Boolean)
          .map(line => JSON.parse(line).name)
      : [];
    assert.ok(!ran.includes('actionlint'), JSON.stringify(ran));
    // The other checks continued; none is an Actionlint pass.
    for (const name of ['sql-lint', 'import-lint', 'format', 'syntax-manifest', 'documentation'])
      assert.equal(run.stage(name)?.status, 'pass', name);
    assert.ok(
      run.evidence.stages.every(
        stage =>
          !['actionlint-version', 'workflow-analysis'].includes(stage.name) ||
          stage.status === 'pending'
      )
    );
  }
);

// GATE-CONTRACT v5 (C3, C5, C23; changes 2, 3, 4, 18 and 19, change 19 as the maintainer
// confirmed it): the gate's own record keeps every order rule the finalizer checks (orderProblems)
// on its recorded intervals. The T8 identity and authenticity stages (N) come before both image
// builds, one after the other; t8-image-activation (O) comes after them and before any candidate
// code; runtime-identity comes before the full-test stages; platform-manifest and candidate-policy
// end before either build would start and before any candidate code (round 2); and neither image
// build starts, since its pre-build authority record is pending (no test of this fixture builds an
// image either). Stand-ins only; no Docker runs.
test(
  'v5: the gate records every stage in v5 order, the three T8 stages pending, and starts neither image build',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const platform = await import('../scripts/security-platform.mjs');
    // With a synthetic authority for every withheld operation, so that every stage the order
    // rules name has run (test/security-dispatch.test.mjs checks the order without one), and,
    // since gate-draft-r6 (GD5-CARRY-01), a valid host and runtime combination, so that the test
    // stages do run.
    const gate = platformGate(t, here, {
      authority: 'all',
      identified: true,
      runtimes: gateRuntimes(),
    });
    const environmentLog = path.join(path.dirname(gate.root), 'environment.log');
    const run = gate('commit', { ORBIT_FIXTURE_ENV_LOG: environmentLog });
    assert.ok(run.stage('full-tests-current-runtime').command, 'the test stage ran');
    assert.deepEqual(platform.orderProblems(run.evidence, { prefix: 'full-tests-' }), []);
    const names = run.evidence.stages.map(stage => stage.name);
    const at = name => names.indexOf(name);
    const ends = name => Date.parse(run.stage(name).finished);
    const starts = name => Date.parse(run.stage(name).started);
    // The three T8 stages: pending, with why, running nothing (no pinned image here).
    for (const name of ['t8-image-identity', 't8-image-authenticity', 't8-image-activation']) {
      assert.equal(run.stage(name)?.status, 'pending', name);
      assert.ok(run.stage(name).reason && !run.stage(name).command, name);
    }
    assert.ok(at('t8-image-identity') < at('t8-image-authenticity'), JSON.stringify(names));
    assert.ok(ends('t8-image-identity') <= starts('t8-image-authenticity'));
    assert.ok(at('t8-image-authenticity') < at('t8-image-activation'));
    for (const later of [
      'sql-lint',
      'import-lint',
      'format',
      'full-tests-current-runtime',
      'container-build',
      'systemd-test-image',
    ]) {
      assert.ok(at(later) > at('t8-image-activation'), `${later} after the T8 stages: ${names}`);
      assert.ok(starts(later) >= ends('t8-image-activation'), later);
    }
    // v5 change 19: platform-manifest ends before either build would start.
    for (const build of ['container-build', 'systemd-test-image'])
      assert.ok(ends('platform-manifest') <= starts(build), build);
    // Change 19 and the phase-N static checks, in this one-record run (round 2): platform-manifest
    // and candidate-policy end before every stage that runs candidate code, the test stage included.
    for (const later of ['sql-lint', 'import-lint', 'format', 'full-tests-current-runtime'])
      for (const first of ['candidate-policy', 'platform-manifest'])
        assert.ok(ends(first) <= starts(later), `${first} before ${later}`);
    // v5 C23 O: test-host and runtime-identity before the full-test stages.
    for (const first of ['test-host', 'runtime-identity'])
      assert.ok(ends(first) <= starts('full-tests-current-runtime'), first);
    // Neither image build starts: both builds, container-identity and the scans of the built
    // image are pending without a command, and no stand-in saw a docker build.
    for (const name of [
      'container-build',
      'container-identity',
      'container-vulnerabilities',
      'container-sbom',
      'systemd-test-image',
    ]) {
      assert.equal(run.stage(name)?.status, 'pending', name);
      assert.equal(run.stage(name).command, undefined, name);
    }
    assert.match(run.stage('container-build').reason, /pre-build authority/);
    assert.match(run.stage('systemd-test-image').reason, /isolation hold/);
    const dockerStages = run.evidence.stages.filter(stage => stage.command?.[0] === 'docker');
    assert.ok(
      dockerStages.every(stage => stage.command[1] !== 'build'),
      JSON.stringify(dockerStages.map(stage => stage.command))
    );
    const dockerCalls = fs
      .readFileSync(environmentLog, 'utf8')
      .split('\n')
      .filter(Boolean)
      .filter(line => JSON.parse(line).name === 'docker').length;
    assert.equal(dockerCalls, dockerStages.length, 'every docker call is a recorded stage');
    assert.equal(run.result.status, 1);
    assert.notEqual(run.evidence.status, 'pass');
  }
);

// The same with a pinned T8 image for each runtime: t8-image-identity runs its local read-only
// `docker image inspect` (a stand-in answers) and stays pending; t8-image-authenticity checks the
// image authenticity records and stays pending; t8-image-activation seals its binding of the two
// (a proposed form), which F rebuilds from the sealed run and finds equal (t8ActivationProblems).
// Stand-ins only; no Docker runs.
test(
  'v5: with pinned T8 images, the gate seals the activation binding that F rebuilds from the sealed run',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const platform = await import('../scripts/security-platform.mjs');
    const finalization = await import('../scripts/security-finalization.mjs');
    const catalog = await import('../scripts/security-catalog.mjs');
    const fixture = await import('./helpers/platform-run.mjs');
    const pinned = { 24: fixture.imageOf[24], 26: fixture.imageOf[26] };
    // With a synthetic authority for every withheld operation, so that t8-image-identity's
    // inspect is dispatched (to the stand-in); without one it is withheld
    // (test/security-dispatch.test.mjs).
    const gate = commitGateFixture(
      t,
      recordingTests(here),
      {
        'test/other.test.mjs':
          "import test from 'node:test';\ntest('a test of another file', () => {});\n",
      },
      { authority: 'all' }
    );
    const manifest = gateManifest({ pinned });
    fs.writeFileSync(path.join(gate.root, 'test/platform-manifest.json'), manifest);
    gate.git('add', '-A');
    // The docker stand-in answers `docker image inspect --format {{json .}} <image>…` as Docker
    // would for the fixture images on linux/arm64/v8 (fixture.inspection), and nothing else.
    fs.writeFileSync(
      path.join(gate.bin, 'docker'),
      `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'image' && args[1] === 'inspect' && args[2] === '--format' && args[3] === '{{json .}}') {
  for (const image of args.slice(4)) {
    const digest = image.split('@')[1];
    console.log(JSON.stringify({ Id: digest, RepoDigests: ['node@' + digest], Os: 'linux', Architecture: 'arm64', Variant: 'v8' }));
  }
  process.exit(0);
}
if (args[0] === 'version') console.log('synthetic tool 0.0.0');
`,
      { mode: 0o755 }
    );
    assert.deepEqual(fixture.inspection(pinned[24]), {
      Id: pinned[24].split('@')[1],
      RepoDigests: [`node@${pinned[24].split('@')[1]}`],
      Os: 'linux',
      Architecture: 'arm64',
      Variant: 'v8',
    });
    const records = path.join(gate.root, '.git/orbit-security/image-authenticity');
    fs.mkdirSync(records, { recursive: true, mode: 0o700 });
    for (const image of Object.values(pinned))
      fs.writeFileSync(
        path.join(
          records,
          platform.imageRecordName(image, { os: 'linux', architecture: 'arm64', variant: 'v8' })
        ),
        JSON.stringify(fixture.imageRecord(image, Date.now())),
        { mode: 0o600 }
      );
    const run = gate('commit');
    assert.deepEqual(platform.orderProblems(run.evidence, { prefix: 'full-tests-' }), []);
    const identity = run.stage('t8-image-identity');
    assert.equal(identity.status, 'pending', identity.error);
    assert.deepEqual(identity.command, platform.t8InspectCommand(Object.values(pinned).sort()));
    assert.equal(identity.exit, 0);
    const authenticity = run.stage('t8-image-authenticity');
    assert.equal(authenticity.status, 'pending', authenticity.error);
    assert.match(authenticity.reason, /an authenticity record is evidence, not authority/);
    const activation = run.stage('t8-image-activation');
    assert.equal(activation.status, 'pending', activation.error);
    assert.equal(activation.binding, platform.activationBindingFile);
    assert.ok(Date.parse(identity.finished) <= Date.parse(authenticity.started));
    assert.ok(Date.parse(authenticity.finished) <= Date.parse(activation.started));
    assert.ok(Date.parse(activation.finished) <= Date.parse(run.stage('sql-lint').started));
    // F rebuilds the binding from the sealed run and finds it equal: the same run, candidate,
    // catalog, platform, consumer and purpose, and exactly N's sealed records.
    const sealed = finalization.readSealedRun(run.directory);
    const binding = JSON.parse(run.file(platform.activationBindingFile));
    assert.equal(binding.run, path.basename(run.directory));
    assert.equal(binding.candidateIdentitySha256, run.evidence.candidateIdentitySha256);
    assert.equal(binding.catalogSha256, catalog.installedCatalog().sha256);
    assert.equal(binding.result, null);
    assert.deepEqual(
      binding.images.map(item => item.image),
      Object.values(pinned).sort()
    );
    assert.deepEqual(
      platform.t8ActivationProblems(sealed, {
        manifest: JSON.parse(manifest),
        runId: `${hostPlatform}-full`,
        catalogSha256: catalog.installedCatalog().sha256,
      }),
      []
    );
    // Both builds still never started.
    for (const name of ['container-build', 'systemd-test-image'])
      assert.equal(run.stage(name).command, undefined, name);
  }
);

// ---------------------------------------------------------------------------------------------
// gate-draft-r11, GDR10-AUTH-STAGE-01 (review finding, Medium/P2; maintainer note 20261019T073253967039Z
// item 1 and 20261019T083721636234Z item 2), at the real stage-dispatch boundary. The tenth round
// bound the gate's own Git runner, but startStage() still gave every stage process.env: the
// snapshot clone, its read-tree and checkout-index, the history secret scan and the npm, test and
// documentation stages inherited every Git selector the binding admits for the gate's own reads
// (this repository's own GIT_DIR, GIT_INDEX_FILE, GIT_WORK_TREE or quarantine), injected
// configuration (GIT_CONFIG_COUNT, GIT_CONFIG_PARAMETERS, GIT_CONFIG, GIT_TEMPLATE_DIR) and no
// GIT_NO_LAZY_FETCH, so read-tree wrote this repository's index instead of the snapshot's, the
// snapshot and every later stage read injected settings, and in a partial clone the history scan
// started the promisor remote. Each stage now gets one deliberate environment
// (stageGitEnvironment): the clone has it alone, the snapshot's own steps are bound to the
// snapshot by a binding of their own, the history scan reads this repository as the gate's binding
// validated it, and every other stage finds the snapshot from the folder it runs in. The real gate
// runs here in throwaway fixtures with stand-in tools; a logging `git` first on PATH records what
// every Git process received, the stand-ins and the candidate's own test record what Git in their
// folder finds, and the gitleaks stand-in runs the Git command gitleaks runs. No real scanner,
// fetch or network: the promisor remote is a local logging helper that refuses. Round 2 of
// gate-draft-r11 (check-1 R11C1-STAGE-CONF-CLONE, -HISTORY, -RECORD-ENV): the stage environment
// also names no configuration file the caller's environment chooses (GIT_CONFIG_GLOBAL and
// GIT_CONFIG_SYSTEM are /dev/null, GIT_CONFIG_NOSYSTEM=1, and stageSettings sets no attributes and
// no ignore file), and the run record names the caller's own Git variables, not the gate's.
// gate-draft-r12 (GDR11-AUTH-CONFIG-01): the gate's own reads, through the repository binding,
// follow the same one policy, so every Git process of a run has the stage settings (and a bound
// read that compares the commit-graph appends its one setting); the settings also switch off every
// fsmonitor, and no system attributes file is read (GIT_ATTR_NOSYSTEM=1).
const historySettings = "'core.commitgraph=false' 'core.usereplacerefs=false'";
// What every stage's Git is given in GIT_CONFIG_PARAMETERS (STAGE_GIT_SETTINGS, then the history
// settings), and the configuration-file variables every stage gets.
const stageSettings = `'core.attributesfile=/dev/null' 'core.excludesfile=/dev/null' 'core.fsmonitor=false' 'i18n.logoutputencoding=UTF-8' 'log.showsignature=false' ${historySettings}`;
// What a read of the repository binding is given (round 2 of gate-draft-r12, R12C1-HOOK-01): the
// stage settings with the binding's own after them (no hooks folder), for every bound read but
// `git rev-parse`, which has the stage settings alone.
const boundSettings = `'core.attributesfile=/dev/null' 'core.excludesfile=/dev/null' 'core.fsmonitor=false' 'i18n.logoutputencoding=UTF-8' 'log.showsignature=false' 'core.hookspath=/dev/null' ${historySettings}`;
const stageConfigFiles = {
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_ATTR_NOSYSTEM: '1',
};
// The Git variables a stage may get (STAGE_GIT_VARIABLES in scripts/security-platform.mjs).
const stageGitNames = new Set([
  'GIT_NO_LAZY_FETCH',
  'GIT_CONFIG_PARAMETERS',
  'GIT_GRAFT_FILE',
  'GIT_NO_REPLACE_OBJECTS',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_SYSTEM',
  'GIT_CONFIG_NOSYSTEM',
  'GIT_ATTR_NOSYSTEM',
  'GIT_EXEC_PATH',
  'GIT_AUTHOR_NAME',
  'GIT_AUTHOR_EMAIL',
  'GIT_AUTHOR_DATE',
  'GIT_COMMITTER_NAME',
  'GIT_COMMITTER_EMAIL',
  'GIT_COMMITTER_DATE',
]);
const selectorNames = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_COMMON_DIR',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_QUARANTINE_PATH',
  'GIT_NAMESPACE',
];

/** A logging `git` first on PATH: each call's folder, arguments and GIT_* variables, then Git. */
function gitRecorder(t) {
  const folder = fs.realpathSync(temporary(t, 'orbit-r11-git-'));
  const log = path.join(folder, 'git.log');
  fs.writeFileSync(log, '');
  const real = (process.env.PATH ?? '')
    .split(path.delimiter)
    .filter(Boolean)
    .map(entry => path.join(entry, 'git'))
    .find(file => fs.statSync(file, { throwIfNoEntry: false })?.isFile());
  assert.ok(real, 'a git on PATH');
  const bin = path.join(folder, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, 'git'),
    `#!/bin/sh\nrec=$(env | grep '^GIT_' | LC_ALL=C sort | tr '\\n' '\\036')\nprintf '%s\\t%s\\t%s\\n' "$PWD" "$*" "$rec" >> '${log}'\nexec '${real}' "$@"\n`,
    { mode: 0o755 }
  );
  const calls = () =>
    fs
      .readFileSync(log, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => {
        const [cwd, args, record = ''] = line.split('\t');
        return {
          cwd,
          args: args.split(' '),
          env: Object.fromEntries(
            record
              .split('\u001e')
              .filter(Boolean)
              .map(item => [item.slice(0, item.indexOf('=')), item.slice(item.indexOf('=') + 1)])
          ),
        };
      });
  return { bin, calls, reset: () => fs.writeFileSync(log, '') };
}
const jsonLines = file =>
  fs.existsSync(file)
    ? fs
        .readFileSync(file, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line))
    : [];
// The canonical path of a folder the gate has removed by now: its parent's real path, and its name.
const canonicalOf = file =>
  path.join(
    fs.realpathSync(path.dirname(path.dirname(file))),
    path.basename(path.dirname(file)),
    path.basename(file)
  );
// The candidate's own test: what Git finds in the folder the test stage runs it in.
const stageProbeTest = `import test from 'node:test';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
test('synthetic stage-environment probe', () => {
  const git = list => spawnSync('git', list, { encoding: 'utf8' });
  if (process.env.ORBIT_FIXTURE_GIT_LOG)
    fs.appendFileSync(process.env.ORBIT_FIXTURE_GIT_LOG, JSON.stringify({ name: 'test-stage', args: [], cwd: process.cwd(), git: Object.fromEntries(Object.entries(process.env).filter(([key]) => /^GIT_/i.test(key))), gitDir: git(['rev-parse', '--absolute-git-dir']).stdout.trim(), config: git(['config', '--get-regexp', '^orbit\\\\.']).stdout.trim() }) + '\\n');
});
`;

test(
  "GDR10-AUTH-STAGE-01: through the real gate, every stage gets an environment with no inherited Git selector, no injected configuration, no configuration file chosen by the caller's environment and GIT_NO_LAZY_FETCH=1: the snapshot is cloned with it alone and its own steps are bound to the snapshot, the history scan reads the validated root, the npm, test and documentation stages find the snapshot; accepted selectors (this repository, its linked worktree, its own quarantine) and injected configuration change none of that, the run record names the caller's Git variables, a promisor remote is never started, and a foreign selector or an active alternates record refuses before any stage",
  { timeout: 300000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const recorder = gitRecorder(t);
    const probe = path.join(fs.realpathSync(temporary(t, 'orbit-r11-probe-')), 'probe.log');
    const gate = commitGateFixture(t, stageProbeTest, {}, { authority: 'all', identified: true });
    const rootGit = fs.realpathSync(path.join(gate.root, '.git'));
    const top = fs.realpathSync(gate.root);
    const objects = path.join(rootGit, 'objects');
    // The candidate's tree object is in this repository's own store before any run.
    gate.git('write-tree');
    const pathWith = `${recorder.bin}${path.delimiter}${gate.bin}${path.delimiter}${process.env.PATH}`;
    const indexOf = gitDir => sha256(fs.readFileSync(path.join(gitDir, 'index')));
    const run = (label, env = {}, { at, gitDir = rootGit } = {}) => {
      recorder.reset();
      fs.writeFileSync(probe, '');
      const before = indexOf(gitDir);
      const outcome = gate(
        'commit',
        { PATH: pathWith, ORBIT_FIXTURE_GIT_LOG: probe, ...env },
        { at }
      );
      return {
        ...outcome,
        label,
        indexChanged: before !== indexOf(gitDir),
        calls: recorder.calls(),
        probes: jsonLines(probe),
        // The Git variables the gate was started with (runGate's environment: this process's, then
        // the run's own; an undefined value is not passed on).
        callerGit: Object.entries({ ...process.env, ...env })
          .filter(([name, value]) => /^GIT_/i.test(name) && value !== undefined)
          .map(([name]) => name)
          .sort(),
      };
    };
    // What every run must show, whatever was inherited.
    const judged = (outcome, history) => {
      const { label, stage, evidence, calls, probes, callerGit } = outcome;
      for (const name of [
        'snapshot-clone',
        'snapshot-index',
        'snapshot-files',
        'gate-implementation',
        'syntax-manifest',
        'documentation',
        'secrets-source',
        'full-tests-current-runtime',
      ])
        assert.equal(stage(name)?.status, 'pass', `${label}: ${name}: ${stage(name)?.error}`);
      assert.equal(
        outcome.indexChanged,
        false,
        `${label}: the index of the repository is unchanged`
      );
      // Every Git process of the run, the gate's own reads included: no lazy fetch, the stage
      // settings as the only configuration in the environment (a bound read that compares the
      // commit-graph appends its one setting; since gate-draft-r12 the gate's own reads have the
      // stage settings too, and since its round 2 a bound read but rev-parse the binding's own
      // after them), no configuration file of the caller's, no injected configuration entry.
      assert.ok(calls.length > 10, `${label}: ${calls.length} Git calls`);
      for (const call of calls) {
        const what = `${label}: git ${call.args[0]} in ${call.cwd}`;
        assert.equal(call.env.GIT_NO_LAZY_FETCH, '1', what);
        assert.ok(
          [stageSettings, boundSettings]
            .flatMap(settings => [settings, `${settings} 'core.commitgraph=true'`])
            .includes(call.env.GIT_CONFIG_PARAMETERS),
          `${what}: ${call.env.GIT_CONFIG_PARAMETERS}`
        );
        for (const [name, value] of Object.entries(stageConfigFiles))
          assert.equal(call.env[name], value, `${what}: ${name}`);
        for (const name of Object.keys(call.env))
          assert.doesNotMatch(name, /^GIT_CONFIG(?:_COUNT|_KEY_\d+|_VALUE_\d+)?$/, what);
      }
      // The snapshot: cloned with no selector and no configuration file; its own two steps bound to
      // it, in it, with no configuration file either.
      const clone = calls.find(call => call.args[0] === 'clone');
      assert.deepEqual(clone.args.slice(0, 3), ['clone', '--no-checkout', '--quiet'], label);
      const snapshot = canonicalOf(clone.args[4]);
      for (const name of selectorNames)
        assert.equal(clone.env[name], undefined, `${label}: clone ${name}`);
      for (const command of ['clone', 'read-tree', 'checkout-index']) {
        const step = calls.find(call => call.args[0] === command);
        for (const [name, value] of Object.entries(stageConfigFiles))
          assert.equal(step.env[name], value, `${label}: ${command} ${name}`);
        assert.equal(step.env.GIT_CONFIG_PARAMETERS, stageSettings, `${label}: ${command}`);
      }
      for (const command of ['read-tree', 'checkout-index']) {
        const step = calls.find(call => call.args[0] === command);
        assert.deepEqual(
          { cwd: step.cwd, GIT_DIR: step.env.GIT_DIR, GIT_WORK_TREE: step.env.GIT_WORK_TREE },
          { cwd: snapshot, GIT_DIR: path.join(snapshot, '.git'), GIT_WORK_TREE: snapshot },
          `${label}: ${command}`
        );
        for (const name of selectorNames.filter(
          item => !['GIT_DIR', 'GIT_WORK_TREE'].includes(item)
        ))
          assert.equal(step.env[name], undefined, `${label}: ${command} ${name}`);
      }
      // Every stage process that runs in the snapshot, the npm, documentation and test stages
      // among them, finds the snapshot itself, with nothing injected and only the stage variables.
      const inSnapshot = probes.filter(
        item => item.cwd === snapshot && !(item.name === 'gitleaks' && item.args[0] === 'git')
      );
      for (const [name, args] of [
        ['npm', 'run check'],
        ['npm', 'run docs:check'],
        ['gitleaks', 'dir'],
        ['test-stage', ''],
      ])
        assert.ok(
          inSnapshot.some(item => item.name === name && item.args.join(' ').startsWith(args)),
          `${label}: ${name} ${args} ran in the snapshot`
        );
      for (const item of inSnapshot) {
        const what = `${label}: ${item.name} ${item.args.join(' ')}`;
        assert.equal(item.gitDir, path.join(snapshot, '.git'), what);
        assert.equal(item.config, '', what);
        assert.deepEqual(
          Object.keys(item.git).filter(name => !stageGitNames.has(name)),
          [],
          what
        );
        assert.equal(item.git.GIT_NO_LAZY_FETCH, '1', what);
        assert.equal(item.git.GIT_CONFIG_PARAMETERS, stageSettings, what);
        for (const [name, value] of Object.entries(stageConfigFiles))
          assert.equal(item.git[name], value, `${what}: ${name}`);
      }
      // The history scan reads the repository the gate's binding validated, and nothing else.
      const scan = probes.find(item => item.name === 'gitleaks' && item.args[0] === 'git');
      const named = Object.fromEntries(
        Object.entries(scan.git).filter(([name]) => selectorNames.includes(name))
      );
      assert.deepEqual(named, history, `${label}: the history scan's repository`);
      assert.deepEqual(
        Object.keys(scan.git).filter(
          name => !stageGitNames.has(name) && !selectorNames.includes(name)
        ),
        [],
        `${label}: the history scan's variables`
      );
      assert.equal(scan.git.GIT_NO_LAZY_FETCH, '1', label);
      assert.equal(scan.git.GIT_CONFIG_PARAMETERS, stageSettings, label);
      for (const [name, value] of Object.entries(stageConfigFiles))
        assert.equal(scan.git[name], value, `${label}: the history scan's ${name}`);
      assert.equal(scan.config, '', label);
      // The record names the Git variables the caller's environment carried, those no stage gets
      // among them, and none the gate set itself (round 2, check-1 R11C1-RECORD-ENV).
      assert.deepEqual(
        evidence.inheritedEnvironment.names.filter(name => /^GIT_/i.test(name)).sort(),
        callerGit,
        `${label}: the record's inherited Git variables`
      );
      return { snapshot, scan };
    };
    const own = { GIT_DIR: rootGit, GIT_WORK_TREE: top };

    // A clean environment.
    const clean = run('a clean environment');
    assert.equal(judged(clean, own).scan.scan, 0);

    // This repository's own selectors, which the binding admits for the gate's own reads, and
    // injected configuration of every kind.
    const configFolder = fs.realpathSync(temporary(t, 'orbit-r11-config-'));
    const template = path.join(configFolder, 'template');
    fs.mkdirSync(template);
    fs.writeFileSync(path.join(template, 'config'), '[orbit]\n\ttemplate = injected\n');
    fs.writeFileSync(path.join(configFolder, 'config'), '[orbit]\n\tfile = injected\n');
    const hostile = {
      GIT_DIR: rootGit,
      GIT_INDEX_FILE: path.join(rootGit, 'index'),
      GIT_COMMON_DIR: rootGit,
      GIT_NAMESPACE: '',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'orbit.injected',
      GIT_CONFIG_VALUE_0: 'count',
      GIT_CONFIG_PARAMETERS: "'orbit.parameter=yes'",
      GIT_CONFIG: path.join(configFolder, 'config'),
      GIT_TEMPLATE_DIR: template,
      GIT_NO_LAZY_FETCH: '0',
      GIT_LITERAL_PATHSPECS: '1',
      GIT_ICASE_PATHSPECS: '1',
      GIT_CEILING_DIRECTORIES: path.dirname(top),
      GIT_DISCOVERY_ACROSS_FILESYSTEM: '1',
      GIT_ATTR_SOURCE: 'HEAD',
      GIT_EXTERNAL_DIFF: '/usr/bin/false',
      GIT_DEFAULT_HASH: 'sha1',
    };
    judged(
      run('own GIT_DIR, GIT_INDEX_FILE and GIT_COMMON_DIR, with injected configuration', hostile),
      own
    );
    // Its own GIT_DIR and GIT_WORK_TREE (the clone refused to start in an existing working tree).
    judged(run('own GIT_DIR and GIT_WORK_TREE', { GIT_DIR: rootGit, GIT_WORK_TREE: top }), own);

    // Its own quarantine, as receive-pack gives it: the clone writes nothing into it and the
    // snapshot steps get none of it; the history scan reads through it, as the gate's own runner.
    const quarantine = path.join(objects, 'tmp_objdir-incoming-S11abc');
    fs.mkdirSync(quarantine);
    const ownQuarantine = {
      GIT_QUARANTINE_PATH: quarantine,
      GIT_OBJECT_DIRECTORY: quarantine,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: objects,
    };
    judged(run("this repository's own quarantine", ownQuarantine), { ...own, ...ownQuarantine });
    assert.deepEqual(fs.readdirSync(quarantine), [], 'nothing was written into the quarantine');
    fs.rmdirSync(quarantine);

    // A linked worktree, with GIT_DIR its own git directory, as Git runs that worktree's hooks: the
    // snapshot is the worktree's staged tree, the worktree's index is unchanged, and the history
    // scan reads the worktree's repository.
    const linked = path.join(fs.realpathSync(temporary(t, 'orbit-r11-linked-')), 'linked');
    gate.git('worktree', 'add', '--quiet', '--detach', linked, 'HEAD');
    fs.writeFileSync(
      path.join(linked, 'CHANGELOG.md'),
      '# Synthetic fixture changelog\n\n- A change made in a linked worktree.\n'
    );
    execFileSync('git', ['-C', linked, 'add', 'CHANGELOG.md']);
    // As for the main worktree above: the gate's own write-tree then finds its index's cache tree
    // complete and rewrites nothing.
    execFileSync('git', ['-C', linked, 'write-tree']);
    const linkedGit = fs.realpathSync(path.join(rootGit, 'worktrees', 'linked'));
    const mainIndex = indexOf(rootGit);
    const inWorktree = run(
      'a linked worktree, GIT_DIR its own git directory',
      { GIT_DIR: linkedGit },
      { at: linked, gitDir: linkedGit }
    );
    judged(inWorktree, { GIT_DIR: linkedGit, GIT_WORK_TREE: linked });
    assert.equal(
      inWorktree.evidence.tree,
      execFileSync('git', ['-C', linked, 'write-tree'], { encoding: 'utf8' }).trim()
    );
    assert.equal(indexOf(rootGit), mainIndex, 'the index of the main worktree is unchanged too');

    // A foreign selector refuses before any stage starts: no run folder, no stage, no snapshot.
    const other = fs.realpathSync(temporary(t, 'orbit-r11-other-'));
    execFileSync('git', ['init', '--quiet', other]);
    const store = fs.realpathSync(temporary(t, 'orbit-r11-store-'));
    const environment = { ...process.env, PATH: pathWith, ORBIT_FIXTURE_GIT_LOG: probe };
    delete environment.NODE_TEST_CONTEXT;
    const refusedBefore = (label, env, pattern) => {
      recorder.reset();
      fs.writeFileSync(probe, '');
      const evidenceRoot = path.join(rootGit, 'orbit-security');
      const earlier = fs.readdirSync(evidenceRoot).sort();
      const result = spawnSync(
        process.execPath,
        [path.join(gate.root, 'scripts/security-gate.mjs'), 'commit'],
        { cwd: gate.root, encoding: 'utf8', timeout: 25000, env: { ...environment, ...env } }
      );
      assert.notEqual(result.status, 0, `${label}: ${result.stdout}`);
      assert.match(result.stderr, pattern, label);
      assert.deepEqual(fs.readdirSync(evidenceRoot).sort(), earlier, `${label}: no run folder`);
      assert.deepEqual(jsonLines(probe), [], `${label}: no stage started`);
      assert.ok(!recorder.calls().some(call => call.args[0] === 'clone'), `${label}: no snapshot`);
    };
    const foreignSelector = /cannot be bound: the inherited GIT_\w+.* \(GDR9-AUTH-ROOT-01\)/;
    for (const [label, env] of [
      ['GIT_DIR naming another repository', { GIT_DIR: path.join(other, '.git') }],
      ['GIT_WORK_TREE naming another working tree', { GIT_WORK_TREE: other }],
      ['GIT_COMMON_DIR naming another repository', { GIT_COMMON_DIR: path.join(other, '.git') }],
      ['GIT_INDEX_FILE naming another index', { GIT_INDEX_FILE: path.join(store, 'index') }],
      ['GIT_OBJECT_DIRECTORY naming another store', { GIT_OBJECT_DIRECTORY: store }],
      [
        'GIT_ALTERNATE_OBJECT_DIRECTORIES naming another store',
        { GIT_ALTERNATE_OBJECT_DIRECTORIES: store },
      ],
      ['a GIT_NAMESPACE', { GIT_NAMESPACE: 'elsewhere' }],
    ])
      refusedBefore(label, env, foreignSelector);

    // An active alternates record (GDR10-ALT-PARSE-01) at the gate: HEAD's commit object only in a
    // foreign store, which ` #foreign` names. Git reads HEAD through it; the gate refuses before it
    // reads anything.
    const head = gate.git('rev-parse', 'HEAD');
    const moved = path.join(store, head.slice(0, 2), head.slice(2));
    fs.mkdirSync(path.dirname(moved), { recursive: true });
    fs.renameSync(path.join(objects, head.slice(0, 2), head.slice(2)), moved);
    const alternates = path.join(objects, 'info', 'alternates');
    const link = path.join(objects, ' #foreign');
    fs.writeFileSync(alternates, ' #foreign\n');
    fs.symlinkSync(path.relative(objects, store), link);
    assert.equal(gate.git('cat-file', '-t', head), 'commit', 'Git reads HEAD through the record');
    refusedBefore(
      "an alternates record ' #foreign' naming the store that holds HEAD's commit",
      {},
      /cannot be bound: the info\/alternates file of the repository's object directory .* names another object store .*GDR10-ALT-PARSE-01/
    );
    fs.rmSync(link);
    fs.rmSync(alternates);
    fs.renameSync(moved, path.join(objects, head.slice(0, 2), head.slice(2)));

    // A partial clone whose history needs a blob that is missing, with a logging promisor helper on
    // PATH: the history scan fails closed (secrets-history blocked) and no Git process of the run
    // starts the helper; plain Git without GIT_NO_LAZY_FETCH does start it (the harness).
    const helpers = fs.realpathSync(temporary(t, 'orbit-r11-helper-'));
    const helperLog = path.join(helpers, 'calls.log');
    fs.writeFileSync(helperLog, '');
    fs.writeFileSync(
      path.join(helpers, 'git-remote-orbitlog'),
      `#!/bin/sh\nprintf '%s\\n' "orbitlog $*" >> '${helperLog}'\necho 'orbitlog: refused, no network' >&2\nexit 1\n`,
      { mode: 0o755 }
    );
    const helperCalls = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean).length;
    const partial = commitGateFixture(
      t,
      stageProbeTest,
      { 'history.txt': 'an old history version\n' },
      { authority: 'all', identified: true }
    );
    const old = partial.git('rev-parse', 'HEAD:history.txt');
    fs.writeFileSync(path.join(partial.root, 'history.txt'), 'a newer history version\n');
    partial.git('add', '-A');
    partial.git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      'The history changes'
    );
    fs.writeFileSync(
      path.join(partial.root, 'CHANGELOG.md'),
      '# Synthetic fixture changelog\n\n- A synthetic change.\n- Another.\n'
    );
    partial.git('add', 'CHANGELOG.md');
    partial.git('write-tree');
    const partialObjects = path.join(partial.root, '.git', 'objects');
    fs.mkdirSync(path.join(partial.root, '.git', 'aside'));
    fs.renameSync(
      path.join(partialObjects, old.slice(0, 2), old.slice(2)),
      path.join(partial.root, '.git', 'aside', old)
    );
    for (const [key, value] of [
      ['core.repositoryformatversion', '1'],
      ['extensions.partialClone', 'origin'],
      ['remote.origin.url', 'orbitlog::synthetic-promisor'],
      ['remote.origin.promisor', 'true'],
      ['remote.origin.partialclonefilter', 'blob:none'],
    ])
      partial.git('config', key, value);
    const plain = spawnSync('git', ['-C', partial.root, 'log', '-p', '-U0', '--all'], {
      env: {
        ...environment,
        PATH: `${helpers}${path.delimiter}${process.env.PATH}`,
        GIT_NO_LAZY_FETCH: undefined,
      },
    });
    assert.notEqual(plain.status, 0);
    assert.ok(
      helperCalls() > 0,
      'the harness: without GIT_NO_LAZY_FETCH, Git starts the promisor helper'
    );
    const before = helperCalls();
    recorder.reset();
    fs.writeFileSync(probe, '');
    const promisor = partial('commit', {
      PATH: `${recorder.bin}${path.delimiter}${helpers}${path.delimiter}${partial.bin}${path.delimiter}${process.env.PATH}`,
      ORBIT_FIXTURE_GIT_LOG: probe,
    });
    assert.equal(
      helperCalls(),
      before,
      'no Git process of the gate run started the promisor helper'
    );
    for (const name of ['snapshot-clone', 'snapshot-index', 'snapshot-files'])
      assert.equal(promisor.stage(name)?.status, 'pass', `${name}: ${promisor.stage(name)?.error}`);
    assert.equal(
      promisor.stage('secrets-history').status,
      'blocked',
      'the history scan fails closed'
    );
    const scanned = jsonLines(probe).find(
      item => item.name === 'gitleaks' && item.args[0] === 'git'
    );
    assert.equal(scanned.git.GIT_NO_LAZY_FETCH, '1');
    assert.equal(scanned.git.GIT_DIR, fs.realpathSync(path.join(partial.root, '.git')));
    assert.notEqual(scanned.scan, 0);
    for (const call of recorder.calls())
      assert.equal(call.env.GIT_NO_LAZY_FETCH, '1', `promisor: git ${call.args[0]} in ${call.cwd}`);

    // The table the stage environment follows (scripts/security-platform.mjs).
    return import('../scripts/security-platform.mjs').then(platform => {
      assert.deepEqual(
        Object.entries(platform.STAGE_GIT_VARIABLES)
          .filter(([, treatment]) => treatment !== 'removed')
          .map(([name]) => name)
          .sort(),
        [...stageGitNames].sort()
      );
      assert.deepEqual(
        Object.entries(platform.STAGE_GIT_VARIABLES).filter(
          ([, treatment]) => treatment === 'removed'
        ),
        [['GIT_<any other name>', 'removed']]
      );
      // Round 2: the configuration-file variables are set by the gate, not admitted.
      for (const name of Object.keys(stageConfigFiles))
        assert.equal(platform.STAGE_GIT_VARIABLES[name], 'overridden', name);
      assert.equal(`${platform.STAGE_GIT_SETTINGS} ${historySettings}`, stageSettings);
    });
  }
);

// ---------------------------------------------------------------------------------------------
// Round 2 of gate-draft-r11: check-1 R11C1-STAGE-CONF-CLONE, R11C1-STAGE-CONF-HISTORY and
// R11C1-RECORD-ENV, on review finding GDR10-AUTH-STAGE-01 (maintainer note 20261019T083721636234Z item 2:
// "local snapshot cloning uses a clean environment", zero remote-helper invocation, and
// secrets-history inheriting the safe environment). Round 1's stage environment still admitted
// GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM, and HOME and XDG_CONFIG_HOME passed on, so a Git
// configuration file the caller's environment chose reached every stage: url.<foreign>.insteadOf
// =<root> made the snapshot a clone of another repository (and every stage passed), a
// url."<helper>::".insteadOf=<root> rewrite started a remote helper, a setting there was read by
// the stages, and an attributes file (named by core.attributesFile, or Git's default one under
// HOME/.config/git/ or XDG_CONFIG_HOME/git/) with `* -diff` hid history content from the secret
// scan's Git command and with an eol rule changed the snapshot's files. The run record named the
// stage environment, so it lost the caller's own Git variables and named the gate's settings as
// inherited. Each case runs the real gate of the fixture with its stand-ins, a logging `git`, a
// refusing logging remote helper and a gitleaks wrapper that counts the planted marker in what the
// history scan's Git command shows; a plain-Git harness shows first that each file has its effect
// outside the gate. Every case is judged, and the failures are reported together.
const roundTwoProbeTest = `import test from 'node:test';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
test('synthetic round-2 stage probe', () => {
  const git = list => spawnSync('git', list, { encoding: 'utf8' });
  if (process.env.ORBIT_FIXTURE_GIT_LOG)
    fs.appendFileSync(process.env.ORBIT_FIXTURE_GIT_LOG, JSON.stringify({ name: 'test-stage', args: [], cwd: process.cwd(), git: Object.fromEntries(Object.entries(process.env).filter(([key]) => /^GIT_/i.test(key))), gitDir: git(['rev-parse', '--absolute-git-dir']).stdout.trim(), config: git(['config', '--get-regexp', '^orbit\\\\.']).stdout.trim(), tags: git(['tag', '-l']).stdout.trim(), foreign: git(['cat-file', '-e', process.env.ORBIT_R2_FOREIGN]).status === 0, carriageReturns: fs.readFileSync('README.md', 'utf8').includes('\\r') }) + '\\n');
});
`;

test(
  "GDR10-AUTH-STAGE-01, round 2 (check-1 R11C1-STAGE-CONF-CLONE, -HISTORY and -RECORD-ENV): through the real gate, no Git configuration, attributes or ignore file that the caller's environment chooses (GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, HOME, XDG_CONFIG_HOME) reaches a stage: it cannot point the snapshot clone at another repository or start a remote helper, put a setting in front of a stage, hide history content from the secret scan or change the snapshot's files; the run record names the caller's own Git variables and not the gate's",
  { timeout: 300000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const recorder = gitRecorder(t);
    const probe = path.join(fs.realpathSync(temporary(t, 'orbit-r11r2-probe-')), 'probe.log');
    const work = fs.realpathSync(temporary(t, 'orbit-r11r2-work-'));
    const file = (name, text) => {
      const target = path.join(work, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, text);
      return target;
    };
    const gate = commitGateFixture(
      t,
      roundTwoProbeTest,
      {},
      { authority: 'all', identified: true }
    );
    const top = fs.realpathSync(gate.root);
    const commitOnly = (message, ...paths) =>
      gate.git(
        '-c',
        'user.name=Orbit Fixture',
        '-c',
        'user.email=fixture@example.com',
        '-c',
        'commit.gpgsign=false',
        '-c',
        'core.hooksPath=/dev/null',
        'commit',
        '--quiet',
        '-m',
        message,
        '--',
        ...paths
      );
    // A marker in the history (the staged CHANGELOG.md stays staged), for the history scan.
    fs.writeFileSync(path.join(top, 'planted.txt'), 'R2-PLANTED-MARKER\n');
    gate.git('add', 'planted.txt');
    commitOnly('A planted history marker', 'planted.txt');
    gate.git('write-tree');
    // A foreign repository: a local clone of the fixture (it holds the candidate's tree, as a local
    // clone copies the objects) with one commit and one tag of its own.
    const foreign = path.join(work, 'foreign');
    execFileSync('git', ['clone', '--quiet', top, foreign]);
    fs.writeFileSync(path.join(foreign, 'foreign-only.txt'), 'foreign\n');
    const inForeign = (...args) =>
      execFileSync('git', ['-C', foreign, ...args], { encoding: 'utf8' }).trim();
    inForeign('add', '-A');
    inForeign(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      'foreign-only'
    );
    inForeign('tag', 'r2-foreign-only');
    const foreignCommit = inForeign('rev-parse', 'HEAD');
    // A refusing, logging remote helper, and a gitleaks wrapper that counts the planted marker in
    // what the history scan's Git command (git -C <root> log -p -U0 --all, with the environment the
    // gate gives the stage) shows, then hands over to the fixture's own stand-in.
    const helpers = path.join(work, 'helpers');
    fs.mkdirSync(helpers);
    const helperLog = file('helper.log', '');
    fs.writeFileSync(
      path.join(helpers, 'git-remote-orbitr2'),
      `#!/bin/sh\nprintf 'started %s\\n' "$*" >> '${helperLog}'\necho 'orbitr2: refused, no network' >&2\nexit 1\n`,
      { mode: 0o755 }
    );
    const helperCalls = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean).length;
    const markerLog = file('marker.log', '');
    const wrapped = path.join(work, 'wrapped');
    fs.mkdirSync(wrapped);
    fs.writeFileSync(
      path.join(wrapped, 'gitleaks'),
      `#!/bin/sh\nif [ "$1" = git ]; then\n  for last; do :; done\n  n=$(git -C "$last" log -p -U0 --all 2>/dev/null | grep -c '^+R2-PLANTED-MARKER')\n  printf '%s\\n' "$n" >> '${markerLog}'\nfi\nexec '${path.join(gate.bin, 'gitleaks')}' "$@"\n`,
      { mode: 0o755 }
    );
    // The files a caller's environment can choose. Git reads HOME/.config/git/ only while
    // XDG_CONFIG_HOME is unset (a GitHub runner sets it), so each HOME case unsets it.
    const settingFile = file('setting.gitconfig', '[orbit]\n\tglobal = injected\n');
    const systemFile = file('system.gitconfig', '[orbit]\n\tsystem = injected\n');
    const homeSetting = path.join(work, 'home-setting');
    file('home-setting/.gitconfig', '[orbit]\n\thome = injected\n');
    const xdgSetting = path.join(work, 'xdg-setting');
    file('xdg-setting/git/config', '[orbit]\n\txdg = injected\n');
    const redirect = file('redirect.gitconfig', `[url "${foreign}"]\n\tinsteadOf = ${top}\n`);
    const toHelper = file('helper.gitconfig', `[url "orbitr2::synthetic"]\n\tinsteadOf = ${top}\n`);
    const hidden = file('hide.attributes', '* -diff\n');
    const hideGlobal = file('hide.gitconfig', `[core]\n\tattributesFile = ${hidden}\n`);
    // Git's default attributes files (no configuration names them): one that hides every diff,
    // under HOME and under XDG_CONFIG_HOME, and one with an eol rule for Markdown files under HOME.
    const homeHide = path.join(work, 'home-hide');
    file('home-hide/.config/git/attributes', '* -diff\n');
    const xdgHide = path.join(work, 'xdg-hide');
    file('xdg-hide/git/attributes', '* -diff\n');
    const homeEol = path.join(work, 'home-eol');
    file('home-eol/.config/git/attributes', '*.md text eol=crlf\n');

    // The harness: outside the gate, plain Git with each file has its effect.
    const plainEnv = extra => ({
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name))),
      PATH: `${helpers}${path.delimiter}${process.env.PATH}`,
      ...extra,
    });
    const plain = (extra, args, cwd = top) =>
      spawnSync('git', args, { cwd, env: plainEnv(extra), encoding: 'utf8' });
    const plainMarkers = extra =>
      plain(extra, ['log', '-p', '-U0', '--all'])
        .stdout.split('\n')
        .filter(line => line.startsWith('+R2-PLANTED-MARKER')).length;
    const plainClone = (label, extra) => {
      const target = path.join(work, `plain-${label}`);
      const clone = plain(extra, ['clone', '--no-checkout', '--quiet', top, target], work);
      if (clone.status === 0) {
        plain(extra, ['read-tree', 'HEAD'], target);
        plain(extra, ['checkout-index', '--all'], target);
      }
      return { clone, target };
    };
    assert.equal(plainMarkers({}), 1, 'the harness: plain Git shows the planted marker');
    for (const [label, extra] of [
      ['GIT_CONFIG_GLOBAL core.attributesFile', { GIT_CONFIG_GLOBAL: hideGlobal }],
      ['HOME/.config/git/attributes', { HOME: homeHide, XDG_CONFIG_HOME: undefined }],
      ['XDG_CONFIG_HOME/git/attributes', { XDG_CONFIG_HOME: xdgHide }],
    ])
      assert.equal(plainMarkers(extra), 0, `the harness: ${label} hides the marker from plain Git`);
    for (const [label, extra] of [
      ['GIT_CONFIG_GLOBAL', { GIT_CONFIG_GLOBAL: settingFile }],
      ['GIT_CONFIG_SYSTEM', { GIT_CONFIG_SYSTEM: systemFile }],
      ['HOME/.gitconfig', { HOME: homeSetting, XDG_CONFIG_HOME: undefined }],
      ['XDG_CONFIG_HOME/git/config', { XDG_CONFIG_HOME: xdgSetting }],
    ])
      assert.notEqual(
        plain(extra, ['config', '--get-regexp', '^orbit\\.']).stdout.trim(),
        '',
        `the harness: plain Git reads the setting from ${label}`
      );
    const redirected = plainClone('redirect', { GIT_CONFIG_GLOBAL: redirect });
    assert.equal(
      plain({}, ['cat-file', '-e', foreignCommit], redirected.target).status,
      0,
      'the harness: the rewrite makes a plain clone of the foreign repository'
    );
    const helpersBefore = helperCalls();
    assert.notEqual(plainClone('helper', { GIT_CONFIG_GLOBAL: toHelper }).clone.status, 0);
    assert.ok(helperCalls() > helpersBefore, 'the harness: the rewrite starts the remote helper');
    const converted = plainClone('eol', { HOME: homeEol, XDG_CONFIG_HOME: undefined });
    assert.match(
      fs.readFileSync(path.join(converted.target, 'README.md'), 'utf8'),
      /\r/,
      'the harness: the eol rule under HOME changes the checked-out README.md'
    );

    // The gate.
    const pathWith = [recorder.bin, wrapped, helpers, gate.bin, process.env.PATH].join(
      path.delimiter
    );
    const run = (label, env) => {
      recorder.reset();
      fs.writeFileSync(probe, '');
      fs.writeFileSync(markerLog, '');
      const before = helperCalls();
      const outcome = gate('commit', {
        PATH: pathWith,
        ORBIT_FIXTURE_GIT_LOG: probe,
        ORBIT_R2_FOREIGN: foreignCommit,
        ...env,
      });
      const probes = jsonLines(probe);
      return {
        ...outcome,
        label,
        probes,
        calls: recorder.calls(),
        helperStarts: helperCalls() - before,
        markers: fs.readFileSync(markerLog, 'utf8').split('\n').filter(Boolean).map(Number),
        testStage: probes.find(item => item.name === 'test-stage'),
        callerGit: Object.entries({ ...process.env, ...env })
          .filter(([name, value]) => /^GIT_/i.test(name) && value !== undefined)
          .map(([name]) => name)
          .sort(),
      };
    };
    const judged = outcome => {
      const { label, stage, evidence, probes, calls, testStage } = outcome;
      for (const name of [
        'snapshot-clone',
        'snapshot-index',
        'snapshot-files',
        'gate-implementation',
        'documentation',
        'secrets-source',
        'secrets-history',
        'full-tests-current-runtime',
      ])
        assert.equal(
          stage(name)?.status,
          'pass',
          `${name}: ${stage(name)?.status ?? 'not recorded'}${stage(name)?.error ? ` (${stage(name).error})` : ''}; the gate's last words: ${
            outcome.result.stderr.split('\n').filter(Boolean).slice(-1)[0] ?? ''
          }`
        );
      // No remote helper started; the snapshot is a clone of this repository, its files the tree's.
      assert.equal(outcome.helperStarts, 0, `remote helper starts: ${outcome.helperStarts}`);
      assert.ok(testStage, "the candidate's test ran in the snapshot");
      assert.equal(testStage.foreign, false, 'the snapshot holds the foreign-only commit');
      assert.doesNotMatch(testStage.tags, /r2-foreign-only/, 'the snapshot has the foreign tag');
      assert.equal(testStage.carriageReturns, false, "the snapshot's README.md is not the tree's");
      // No stage process reads a setting.
      const seen = probes
        .filter(item => item.config)
        .map(item => `${item.name} ${item.args.slice(0, 2).join(' ')}`.trim());
      assert.deepEqual(
        seen,
        [],
        `${seen.length} stage processes read a setting: ${seen.join(', ')}`
      );
      // The history scan's Git command shows the planted marker.
      assert.deepEqual(
        outcome.markers,
        [1],
        `marker lines the history scan saw: ${JSON.stringify(outcome.markers)}`
      );
      // The record names the caller's Git variables, and not the gate's own settings.
      const recorded = evidence.inheritedEnvironment.names
        .filter(name => /^GIT_/i.test(name))
        .sort();
      assert.deepEqual(
        recorded,
        outcome.callerGit,
        `the record's inherited Git variables ${JSON.stringify(recorded)}, the caller's ${JSON.stringify(outcome.callerGit)}`
      );
      // Last, the means: every stage process and the clone have no configuration file.
      for (const item of probes)
        for (const [name, value] of Object.entries(stageConfigFiles))
          assert.equal(
            item.git[name],
            value,
            `${item.name} ${item.args.slice(0, 2).join(' ')}: ${name}`
          );
      const clone = calls.find(call => call.args[0] === 'clone');
      for (const [name, value] of Object.entries(stageConfigFiles))
        assert.equal(clone.env[name], value, `the clone's ${name}`);
      assert.equal(clone.env.GIT_CONFIG_PARAMETERS, stageSettings, "the clone's settings");
    };
    const failures = [];
    const own = path.join(top, '.git');
    for (const [label, env] of [
      ['a clean environment', {}],
      ['GIT_CONFIG_GLOBAL with an orbit.* setting', { GIT_CONFIG_GLOBAL: settingFile }],
      [
        'GIT_CONFIG_SYSTEM with an orbit.* setting, GIT_CONFIG_NOSYSTEM=0',
        { GIT_CONFIG_SYSTEM: systemFile, GIT_CONFIG_NOSYSTEM: '0' },
      ],
      ['HOME with a .gitconfig orbit.* setting', { HOME: homeSetting, XDG_CONFIG_HOME: undefined }],
      ['XDG_CONFIG_HOME with a git/config orbit.* setting', { XDG_CONFIG_HOME: xdgSetting }],
      ['GIT_CONFIG_GLOBAL with url.<foreign>.insteadOf=<root>', { GIT_CONFIG_GLOBAL: redirect }],
      [
        'GIT_CONFIG_GLOBAL with url."orbitr2::synthetic".insteadOf=<root>',
        { GIT_CONFIG_GLOBAL: toHelper },
      ],
      ['GIT_CONFIG_GLOBAL with core.attributesFile "* -diff"', { GIT_CONFIG_GLOBAL: hideGlobal }],
      [
        'HOME with .config/git/attributes "* -diff"',
        { HOME: homeHide, XDG_CONFIG_HOME: undefined },
      ],
      ['XDG_CONFIG_HOME with git/attributes "* -diff"', { XDG_CONFIG_HOME: xdgHide }],
      [
        'HOME with .config/git/attributes "*.md text eol=crlf"',
        { HOME: homeEol, XDG_CONFIG_HOME: undefined },
      ],
      [
        'own GIT_DIR and an injected GIT_CONFIG_COUNT setting (the record names both)',
        {
          GIT_DIR: own,
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'orbit.count',
          GIT_CONFIG_VALUE_0: 'injected',
        },
      ],
    ]) {
      const outcome = run(label, env);
      try {
        judged(outcome);
      } catch (error) {
        failures.push(`${label}: ${error.message.split('\n')[0]}`);
      }
    }
    assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
  }
);

// ---------------------------------------------------------------------------------------------
// gate-draft-r12: the security review of the eleventh round (REVISE BEFORE INTEGRATION), at the gate's
// stage-dispatch boundary. GDR11-HISTORY-ATTRS-01 (Medium/P2): the history secret scan's Git
// command (gitleaks runs `git -C <root> log -p -U0 <log options>`) was given `--all` alone, so a
// committed or untracked .gitattributes or info/attributes with `* -diff`, a diff driver with
// `binary=true` and a textconv driver left history content out while Git exited 0, and the textconv
// program ran. GDR11-AUTH-CONFIG-01 (Medium/P2): the repository binding admitted the caller's Git
// configuration files, so the metadata scan's `git log --all --format=%H%n%B` came out as UTF-16
// (NUL bytes, no ASCII marker) with `i18n.logOutputEncoding=UTF-16` in a caller's file or in the
// repository's own .git/config (global and system files /dev/null and GIT_CONFIG=/dev/null did not
// stop the local one), and a core.fsmonitor there ran on the gate's own reads of the index. The
// repository's own configuration also changed the history command's output (`color.diff=always`
// coloured every added line, `log.showRoot=false` dropped the root commit's patch). Each case
// below runs the real gate of the fixture with its stand-ins; the gitleaks stand-in keeps what the
// two scans were started with and given (ORBIT_FIXTURE_SCAN_INPUT): the exact arguments, the bytes
// of the history scan's Git command run with the stage's environment, and the metadata files.
// Each is compared with a clean oracle made in the same repository with no configuration and no
// attributes at all (plain `git log -p -U0 --all`, and every commit and tag read one by one with
// `cat-file <type> <id>`); a plain-Git harness shows first that each hostile input has its effect
// outside the gate. A logging helper stands for every configured program (fsmonitor, textconv,
// external diff, gpg): none may start in a Git process of the gate (one with GIT_NO_LAZY_FETCH=1,
// which the gate sets for its own reads and every stage, and the harness never sets). These are
// the Git command's input and the files given to the scanner, not a scanner result: the pinned
// Gitleaks 8.30.1 is not run, and its qualification with these inputs stays pending.
const r12LogOptions =
  '--all --root --text --no-textconv --no-ext-diff --no-color --encoding=UTF-8 --pretty=medium --date=default --no-decorate --no-abbrev-commit --no-show-signature --no-notes --src-prefix=a/ --dst-prefix=b/';
const r12Count = (bytes, text) => bytes.toString('latin1').split(text).length - 1;
// Whether `bytes` is a sequence of `<id> <type> <size>\n<content>\n` frames (cat-file --batch's
// form) whose ids are the hash of their content, and the ids it holds.
function r12Frames(bytes) {
  const ids = [];
  let at = 0;
  while (at < bytes.length) {
    const end = bytes.indexOf(0x0a, at);
    if (end < 0) return { valid: false, ids };
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) (commit|tag) (\d+)$/.exec(
      bytes.subarray(at, end).toString('latin1')
    );
    if (!match) return { valid: false, ids };
    const size = Number(match[3]);
    const content = bytes.subarray(end + 1, end + 1 + size);
    const id = createHash(match[1].length === 40 ? 'sha1' : 'sha256')
      .update(`${match[2]} ${size}\0`)
      .update(content)
      .digest('hex');
    if (id !== match[1] || bytes[end + 1 + size] !== 0x0a) return { valid: false, ids };
    ids.push(id);
    at = end + 2 + size;
  }
  return { valid: true, ids };
}

test(
  'GDR11-HISTORY-ATTRS-01 and GDR11-AUTH-CONFIG-01: through the real gate, the history scan is started with the attribute-, driver- and configuration-independent log options, and what its Git command shows and the raw commit and tag metadata given to the metadata scan equal a clean oracle byte for byte, with every planted marker, under hostile global, system, HOME, XDG and repository configuration and committed, untracked and info attributes; no configured helper starts; metadata that cannot be read completely blocks the scan rather than shrinking its input',
  { timeout: 300000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const work = fs.realpathSync(temporary(t, 'orbit-r12-work-'));
    const kept = path.join(work, 'kept');
    const file = (name, text, mode = 0o644) => {
      const target = path.join(work, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, text, { mode });
      return target;
    };
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic r12 candidate test', () => {});\n",
      { 'root-marker.txt': 'R12-ROOT-MARKER in the root commit\n' },
      { authority: 'all', identified: true }
    );
    const top = fs.realpathSync(gate.root);
    // Explicit synthetic identities (never the user's own).
    const as = name => [
      '-c',
      `user.name=${name}`,
      '-c',
      'user.email=fixture@example.invalid',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'tag.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
    ];
    const commitOnly = (message, name, ...paths) =>
      gate.git(...as(name), 'commit', '--quiet', '-m', message, '--', ...paths);
    // Markers only history holds: one in the root commit's file, one in a later file, each removed
    // again (the staged CHANGELOG.md stays staged); one in a commit message, one in an author name,
    // one in an annotated tag and one in a tag of that tag; and a commit that looks signed.
    gate.git('rm', '--quiet', 'root-marker.txt');
    commitOnly('The root marker leaves the tree', 'Orbit Fixture', 'root-marker.txt');
    fs.writeFileSync(path.join(top, 'prior.txt'), 'R12-PRIOR-MARKER in prior history\n');
    gate.git('add', 'prior.txt');
    commitOnly(
      'A commit with R12-MESSAGE-MARKER in its message',
      'Orbit Fixture R12-AUTHOR-MARKER',
      'prior.txt'
    );
    gate.git('rm', '--quiet', 'prior.txt');
    commitOnly('The prior marker leaves the tree', 'Orbit Fixture', 'prior.txt');
    gate.git(
      ...as('Orbit Fixture'),
      'tag',
      '-a',
      'r12-tag',
      '-m',
      'An annotated tag with R12-TAG-MARKER'
    );
    gate.git(
      ...as('Orbit Fixture'),
      'tag',
      '-a',
      'r12-nested',
      'r12-tag',
      '-m',
      'A tag of a tag with R12-NESTED-TAG-MARKER'
    );
    const head = gate.git('rev-parse', 'HEAD');
    const fixtureLine = 'Orbit Fixture <fixture@example.invalid> 1767225600 +0000';
    const signed = execFileSync(
      'git',
      ['-C', top, 'hash-object', '-t', 'commit', '-w', '--stdin'],
      {
        input: `tree ${gate.git('rev-parse', 'HEAD^{tree}')}\nparent ${head}\nauthor ${fixtureLine}\ncommitter ${fixtureLine}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEESyntheticSyntheticSyntheticSyntheticAAoJEAAAAAAAAAAA\n =AAAA\n -----END PGP SIGNATURE-----\n\nA synthetic commit that looks signed\n`,
        encoding: 'utf8',
      }
    ).trim();
    gate.git('update-ref', 'refs/heads/r12-signed', signed);
    gate.git('write-tree');

    // A program that logs each start, with whether a Git process of the gate started it.
    const helperLog = file('helpers.log', '');
    const helper = file(
      'helper.sh',
      `#!/bin/sh\nprintf '%s\\t%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" "$0 $*" >> '${helperLog}'\nexit 1\n`,
      0o755
    );
    // A clean filter that logs each start the same way and gives its input back.
    const filterHelper = file(
      'filter.sh',
      `#!/bin/sh\nprintf '%s\\t%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" "$0" >> '${helperLog}'\ncat\n`,
      0o755
    );
    // The index's own time set back, so every entry it records is racily clean (as for a file
    // changed in the second the index was written) and Git checks its content, through a filter if
    // one applies.
    const stale = () =>
      fs.utimesSync(
        path.join(top, '.git', 'index'),
        new Date('2020-01-01T00:00:00Z'),
        new Date('2020-01-01T00:00:00Z')
      );
    const helperStarts = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean);
    const gateStarts = () => helperStarts().filter(line => line.startsWith('1\t'));
    // A configuration a caller's environment can name: every setting the measured defects used.
    const hide = file('hide.attributes', '* -diff\n');
    const hostileConfig = attributes =>
      `[i18n]\n\tlogOutputEncoding = UTF-16\n[core]\n\tfsmonitor = ${helper}\n${attributes ? `\tattributesFile = ${hide}\n` : ''}[color]\n\tdiff = always\n\tui = always\n[log]\n\tshowRoot = false\n\tshowSignature = true\n[gpg]\n\tprogram = ${helper}\n[orbit]\n\tinjected = yes\n`;
    const hostileGlobal = file('global.gitconfig', hostileConfig(true));
    const hostileSystem = file('system.gitconfig', hostileConfig(true));
    const hostileHome = path.join(work, 'home');
    file('home/.gitconfig', hostileConfig(false));
    file('home/.config/git/attributes', '* -diff\n');
    const hostileXdg = path.join(work, 'xdg');
    file('xdg/git/config', hostileConfig(false));
    file('xdg/git/attributes', '* -diff\n');
    const local = (pairs, extra = {}) => ({
      setup: () => pairs.forEach(([key, value]) => gate.git('config', key, value)),
      teardown: () => pairs.forEach(([key]) => gate.git('config', '--unset-all', key)),
      ...extra,
    });
    const attributes = (relative, text, pairs = []) => ({
      setup: () => {
        fs.writeFileSync(path.join(top, relative), text);
        pairs.forEach(([key, value]) => gate.git('config', key, value));
      },
      teardown: () => {
        fs.rmSync(path.join(top, relative));
        pairs.forEach(([key]) => gate.git('config', '--unset-all', key));
      },
    });
    const cases = [
      ['a clean environment (control)', {}],
      [
        'GIT_CONFIG_GLOBAL naming every hostile setting',
        { env: { GIT_CONFIG_GLOBAL: hostileGlobal } },
      ],
      [
        'GIT_CONFIG_SYSTEM naming every hostile setting, GIT_CONFIG_NOSYSTEM=0',
        { env: { GIT_CONFIG_SYSTEM: hostileSystem, GIT_CONFIG_NOSYSTEM: '0' } },
      ],
      [
        'HOME with .gitconfig and .config/git/attributes',
        { env: { HOME: hostileHome, GIT_CONFIG_GLOBAL: undefined, XDG_CONFIG_HOME: undefined } },
      ],
      [
        'XDG_CONFIG_HOME with git/config and git/attributes',
        { env: { XDG_CONFIG_HOME: hostileXdg, GIT_CONFIG_GLOBAL: undefined } },
      ],
      [
        "the repository's .git/config i18n.logOutputEncoding=UTF-16, with GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM /dev/null, GIT_CONFIG_NOSYSTEM=1 and GIT_CONFIG=/dev/null (the security review's counterexample)",
        local([['i18n.logOutputEncoding', 'UTF-16']], {
          env: {
            GIT_CONFIG_GLOBAL: '/dev/null',
            GIT_CONFIG_SYSTEM: '/dev/null',
            GIT_CONFIG_NOSYSTEM: '1',
            GIT_CONFIG: '/dev/null',
          },
        }),
      ],
      ["the repository's core.fsmonitor=<helper>", local([['core.fsmonitor', helper]])],
      ["the repository's color.diff=always", local([['color.diff', 'always']])],
      ["the repository's color.ui=always", local([['color.ui', 'always']])],
      ["the repository's log.showRoot=false", local([['log.showRoot', 'false']])],
      [
        "the repository's log.showSignature=true with gpg.program=<helper>",
        local([
          ['log.showSignature', 'true'],
          ['gpg.program', helper],
        ]),
      ],
      [
        "the repository's format.pretty, log.decorate, log.abbrevCommit, log.date, diff.noprefix and core.bigFileThreshold",
        local([
          ['format.pretty', 'oneline'],
          ['log.decorate', 'full'],
          ['log.abbrevCommit', 'true'],
          ['log.date', 'relative'],
          ['diff.noprefix', 'true'],
          ['core.bigFileThreshold', '1'],
        ]),
      ],
      ['an untracked .gitattributes "* -diff"', attributes('.gitattributes', '* -diff\n')],
      ['.git/info/attributes "* -diff"', attributes('.git/info/attributes', '* -diff\n')],
      [
        'a diff driver with binary=true (info/attributes)',
        attributes('.git/info/attributes', '* diff=orbitbin\n', [['diff.orbitbin.binary', 'true']]),
      ],
      [
        'a textconv driver (info/attributes, diff.orbittc.textconv=<helper>)',
        attributes('.git/info/attributes', '* diff=orbittc\n', [['diff.orbittc.textconv', helper]]),
      ],
      [
        'an external diff (info/attributes diff.orbitext.command=<helper>, diff.external=<helper>)',
        attributes('.git/info/attributes', '* diff=orbitext\n', [
          ['diff.orbitext.command', helper],
          ['diff.external', helper],
        ]),
      ],
      [
        'a filter driver the repository defines (info/attributes filter=orbitf, filter.orbitf.clean=<helper>, required), every index entry racily clean',
        {
          ...attributes('.git/info/attributes', '* filter=orbitf\n', [
            ['filter.orbitf.clean', filterHelper],
            ['filter.orbitf.required', 'true'],
          ]),
          before: stale,
        },
      ],
      [
        'a committed .gitattributes "* -diff"',
        {
          history: () => {
            fs.writeFileSync(path.join(top, '.gitattributes'), '* -diff\n');
            gate.git('add', '.gitattributes');
            commitOnly('Attributes that hide every diff', 'Orbit Fixture', '.gitattributes');
            gate.git('write-tree');
          },
        },
      ],
    ];

    // The clean oracle: the same repository with no configuration file, no attributes (none from
    // the user, the system or the working tree: GIT_ATTR_SOURCE names the empty tree) and nothing
    // the gate sets.
    const emptyTree = gate.git('hash-object', '-t', 'tree', '/dev/null');
    const withoutGit = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name))
    );
    const cleanEnv = {
      ...withoutGit,
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_ATTR_NOSYSTEM: '1',
      GIT_ATTR_SOURCE: emptyTree,
    };
    const clean = args =>
      execFileSync('git', ['-C', top, '-c', 'core.attributesFile=/dev/null', ...args], {
        env: cleanEnv,
        maxBuffer: 256 * 1024 ** 2,
      });
    const frame = (id, type) => {
      const content = clean(['cat-file', type, id]);
      return Buffer.concat([
        Buffer.from(`${id} ${type} ${content.length}\n`),
        content,
        Buffer.from('\n'),
      ]);
    };
    const oracle = () => ({
      history: clean(['log', '-p', '-U0', '--all']),
      metadata: {
        'history-messages.txt': Buffer.concat(
          clean(['rev-list', '--all'])
            .toString()
            .trim()
            .split('\n')
            .map(id => frame(id, 'commit'))
        ),
        'tag-messages.txt': Buffer.concat(
          ['r12-tag', 'r12-nested']
            .map(name =>
              clean(['rev-parse', `refs/tags/${name}`])
                .toString()
                .trim()
            )
            .sort()
            .map(id => frame(id, 'tag'))
        ),
      },
    });

    // The harness: plain Git with each hostile input (its environment, as the caller's, and no
    // option or setting of the gate) shows another history or other metadata, or starts a helper.
    const plainEnv = extra => {
      const env = { ...withoutGit, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
      for (const [name, value] of Object.entries(extra))
        if (value === undefined) delete env[name];
        else env[name] = value;
      return env;
    };
    const plain = (extra, args) =>
      spawnSync('git', ['-C', top, ...args], {
        env: plainEnv(extra),
        maxBuffer: 256 * 1024 ** 2,
      });
    const effects = (extra, expected) => {
      fs.writeFileSync(helperLog, '');
      const found = [];
      if (!plain(extra, ['log', '-p', '-U0', '--all']).stdout.equals(expected.history))
        found.push('plain git log -p -U0 --all differs from the oracle');
      const messages = plain(extra, ['log', '--all', '--format=%H%n%B']).stdout;
      if (messages.includes(0) || !r12Count(messages, 'R12-MESSAGE-MARKER'))
        found.push('plain git log --format=%B is not the plain message text');
      plain(extra, ['write-tree']);
      // Git on Linux checks no racily clean entry in write-tree (Apple Git does); a refresh of the
      // index does on both, so a filter driver the repository defines starts there too.
      plain(extra, ['update-index', '-q', '--refresh']);
      plain(extra, ['diff', 'HEAD~1', 'HEAD']);
      if (helperStarts().length)
        found.push(`a configured helper started ${helperStarts().length} times`);
      return found;
    };

    const failures = [];
    // Every check of one run, each judged on its own (so a failing run names every defect it
    // shows): first what the scans were given and what started, then the means.
    const judged = (outcome, expected) => {
      const problems = [];
      const check = fn => {
        try {
          fn();
        } catch (error) {
          problems.push(error.message.split('\n')[0]);
        }
      };
      const read = file => fs.readFileSync(path.join(kept, file));
      check(() =>
        assert.deepEqual(
          gateStarts(),
          [],
          'a configured helper started in a Git process of the gate'
        )
      );
      // What the history scan's Git command showed: the clean oracle, every marker in it.
      check(() => {
        const history = read('history.bin');
        assert.equal(r12Count(history, '\n+R12-ROOT-MARKER'), 1, 'the root-commit marker line');
        assert.equal(r12Count(history, '\n+R12-PRIOR-MARKER'), 1, 'the prior-history marker line');
        assert.ok(
          history.equals(expected.history),
          `the history input (${history.length} bytes) is not the clean oracle (${expected.history.length} bytes)`
        );
      });
      // The metadata files: the clean oracle, raw objects whose ids are their hash, every marker.
      check(() => {
        const folder = path.join(kept, 'metadata');
        assert.deepEqual(fs.readdirSync(folder).sort(), [
          'history-messages.txt',
          'tag-messages.txt',
        ]);
        const given = Object.fromEntries(
          ['history-messages.txt', 'tag-messages.txt'].map(name => [
            name,
            fs.readFileSync(path.join(folder, name)),
          ])
        );
        const all = Buffer.concat(Object.values(given));
        for (const marker of [
          'R12-MESSAGE-MARKER',
          'R12-AUTHOR-MARKER',
          'R12-TAG-MARKER',
          'R12-NESTED-TAG-MARKER',
          'BEGIN PGP SIGNATURE',
        ])
          assert.ok(r12Count(all, marker) >= 1, `the metadata lacks ${marker}`);
        for (const [name, bytes] of Object.entries(given)) {
          assert.equal(bytes.includes(0), false, `${name} holds a NUL byte`);
          assert.equal(r12Frames(bytes).valid, true, `${name} is not raw objects`);
          assert.ok(bytes.equals(expected.metadata[name]), `${name} is not the clean oracle`);
        }
      });
      for (const name of ['secrets-history', 'secrets-metadata'])
        check(() =>
          assert.equal(
            outcome.stage(name)?.status,
            'pass',
            `${name}: ${outcome.stage(name)?.status ?? 'not recorded'} ${outcome.stage(name)?.error ?? ''}`
          )
        );
      // The dispatch boundary: the recorded command is what the stand-in was started with, its log
      // options exactly these, on the validated root.
      check(() => {
        const record = outcome.stage('secrets-history');
        assert.deepEqual(
          record.command.filter(arg => arg.startsWith('--log-opts=')),
          [`--log-opts=${r12LogOptions}`],
          'the history scan is not started with the hardened log options'
        );
        const started = JSON.parse(read('history-args.json').toString('utf8'));
        assert.deepEqual(['gitleaks', ...started], record.command, 'not started as recorded');
        assert.equal(started[started.length - 1], top, 'not on the validated root');
      });
      if (problems.length) throw new Error(problems.join('; '));
    };
    for (const [label, { env = {}, setup, teardown, history, before }] of cases) {
      history?.();
      const expected = oracle();
      setup?.();
      try {
        before?.();
        const found = effects(env, expected);
        if (label.endsWith('(control)'))
          assert.deepEqual(found, [], 'the harness: the control is the oracle');
        else assert.notDeepEqual(found, [], `the harness: ${label} changes nothing for plain Git`);
        fs.rmSync(kept, { recursive: true, force: true });
        fs.mkdirSync(kept);
        fs.writeFileSync(helperLog, '');
        before?.();
        judged(gate('commit', { ORBIT_FIXTURE_SCAN_INPUT: kept, ...env }), expected);
      } catch (error) {
        failures.push(`${label}: ${error.message.split('\n')[0]}`);
      } finally {
        teardown?.();
      }
    }

    // Metadata the gate cannot read completely: the metadata scan is blocked, with why, and never
    // started on part of it. A commit object holding a NUL byte and a commit object that is
    // missing, each named by a ref outside refs/heads and refs/tags (which the snapshot clone does
    // not copy, so the run reaches the metadata scan).
    const refused = (label, pattern, also = () => {}) => {
      fs.rmSync(kept, { recursive: true, force: true });
      fs.mkdirSync(kept);
      const outcome = gate('commit', { ORBIT_FIXTURE_SCAN_INPUT: kept });
      try {
        const record = outcome.stage('secrets-metadata');
        assert.equal(record?.status, 'blocked', `${record?.status} ${record?.error ?? ''}`);
        assert.match(record.error, pattern);
        assert.equal(record.command, undefined, 'no command was started');
        assert.equal(fs.existsSync(path.join(kept, 'metadata')), false, 'no scan input');
        also(outcome);
      } catch (error) {
        failures.push(`${label}: ${error.message.split('\n')[0]}`);
      }
    };
    const nul = execFileSync(
      'git',
      ['-C', top, 'hash-object', '-t', 'commit', '-w', '--literally', '--stdin'],
      {
        input: Buffer.concat([
          Buffer.from(
            `tree ${gate.git('rev-parse', 'HEAD^{tree}')}\nparent ${head}\nauthor ${fixtureLine}\ncommitter ${fixtureLine}\nencoding UTF-16\n\n`
          ),
          Buffer.from('R\0-\0M\0A\0R\0K\0E\0R\0\n\0'),
        ]),
        encoding: 'utf8',
      }
    ).trim();
    gate.git('update-ref', 'refs/orbit-r12/nul', nul);
    refused(
      'a commit holding a NUL byte',
      new RegExp(`cannot be given to the secret scan complete: the commit ${nul} holds a NUL byte`),
      outcome =>
        assert.equal(
          outcome.stage('secrets-history')?.status,
          'pass',
          'the history scan still runs'
        )
    );
    gate.git('update-ref', '-d', 'refs/orbit-r12/nul');
    const lost = execFileSync(
      'git',
      ['-C', top, 'commit-tree', '-p', head, '-m', 'lost', `${head}^{tree}`],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          GIT_AUTHOR_NAME: 'Orbit Fixture',
          GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
          GIT_COMMITTER_NAME: 'Orbit Fixture',
          GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
        },
      }
    ).trim();
    gate.git('update-ref', 'refs/orbit-r12/lost', lost);
    const objects = path.join(top, '.git', 'objects');
    const aside = path.join(work, 'aside');
    fs.mkdirSync(aside);
    fs.renameSync(path.join(objects, lost.slice(0, 2), lost.slice(2)), path.join(aside, lost));
    refused('a ref whose commit object is missing', /cannot be given to the secret scan complete/);
    fs.renameSync(path.join(aside, lost), path.join(objects, lost.slice(0, 2), lost.slice(2)));
    gate.git('update-ref', '-d', 'refs/orbit-r12/lost');

    assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
    return import('../scripts/security-platform.mjs').then(platform =>
      assert.equal(platform.HISTORY_LOG_OPTIONS.join(' '), r12LogOptions)
    );
  }
);

// Round 2 of gate-draft-r12 (check-1 of its first round), at the gate's own reads and its metadata
// scan's dispatch. R12C1-META-ENC-01 (a regression of round 1): a commit whose `encoding` header
// named UTF-7 reached the metadata scan raw, its ASCII text held in other bytes, and the stage
// passed, although Git shows that text decoded; it now blocks the metadata scan, as ISO-2022-JP and
// HZ commits do, while ISO-8859-1 and windows-1252 commits reach it whole. R12C1-FILTER-EQ-01: the
// switch-off of the repository's filter drivers, given in Git's 'key=value' form, missed a driver
// named with `=` (its clean program started 21 times in one gate run), and a driver with an empty
// name was not switched off at all. R12C1-HOOK-01: a post-index-change hook, in .git/hooks or in the
// repository's own core.hooksPath, and a hook its configuration defines (`hook.<name>.command`, Git
// 2.54), started when write-tree, the gate's first read, wrote the index. Each case runs the real
// gate of the fixture with its stand-ins; the harness shows first, with plain Git and no
// configuration file, that the case has its effect (Git shows a marker the raw commit lacks, or the
// helper starts); a start in a Git process of the gate is one with GIT_NO_LAZY_FETCH=1, which only
// the gate sets here. Explicit synthetic identity only.
test(
  "R12C1-META-ENC-01, R12C1-FILTER-EQ-01 and R12C1-HOOK-01: through the real gate, a commit whose encoding header names UTF-7, ISO-2022-JP or HZ blocks the metadata scan instead of reaching it raw, ISO-8859-1 and windows-1252 commits reach it whole, and no filter driver (named with =, with an empty name or plainly) and no hook (in .git/hooks, in the repository's core.hooksPath or defined in its configuration) starts in a Git process of the gate",
  { timeout: 300000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const work = fs.realpathSync(temporary(t, 'orbit-r12r2-work-'));
    const kept = path.join(work, 'kept');
    const gate = commitGateFixture(
      t,
      "import test from 'node:test';\ntest('synthetic r12 round-2 candidate test', () => {});\n",
      {},
      { authority: 'all', identified: true }
    );
    const top = fs.realpathSync(gate.root);
    const head = gate.git('rev-parse', 'HEAD');
    const tree = gate.git('rev-parse', 'HEAD^{tree}');
    const helperLog = path.join(work, 'helpers.log');
    fs.writeFileSync(helperLog, '');
    // Logs each start, with whether a Git process of the gate started it, and gives its input back
    // (as a clean filter must).
    const helper = path.join(work, 'helper.sh');
    fs.writeFileSync(
      helper,
      `#!/bin/sh\nprintf '%s\\t%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" "$0" >> '${helperLog}'\ncat\n`,
      { mode: 0o755 }
    );
    const starts = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean);
    const gateStarts = () => starts().filter(line => line.startsWith('1\t'));
    const cleanEnv = {
      ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name))),
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
    };
    const plain = args =>
      execFileSync('git', ['-C', top, ...args], { env: cleanEnv, maxBuffer: 64 * 1024 ** 2 });
    const run = () => {
      fs.rmSync(kept, { recursive: true, force: true });
      fs.mkdirSync(kept);
      fs.writeFileSync(helperLog, '');
      return gate('commit', { ORBIT_FIXTURE_SCAN_INPUT: kept });
    };
    const config = path.join(top, '.git', 'config');
    const original = fs.readFileSync(config);
    const failures = [];
    const each = (label, fn) => {
      try {
        fn();
      } catch (error) {
        failures.push(`${label}: ${error.message.split('\n')[0]}`);
      } finally {
        fs.writeFileSync(config, original);
      }
    };

    // 1. Commit encodings, each commit on a ref outside refs/heads and refs/tags (which the
    // snapshot clone does not copy, so the run reaches the metadata scan).
    const marker = 'R12R2GATEMARKER';
    const person = 'Orbit Fixture <fixture@example.invalid> 1767225600 -0000';
    const utf7 = `+${Buffer.from(marker, 'utf16le').swap16().toString('base64').replace(/=+$/, '')}-`;
    for (const [encoding, body, blocked] of [
      ['UTF-7', utf7, true],
      ['ISO-2022-JP', `${marker.slice(0, 6)}\x1b(B${marker.slice(6)}`, true],
      ['HZ-GB-2312', `${marker.slice(0, 6)}~\n${marker.slice(6)}`, true],
      ['ISO-8859-1', `${marker} caf\xe9`, false],
      ['windows-1252', `${marker} \x80`, false],
    ])
      each(`a commit with encoding ${encoding}`, () => {
        const id = execFileSync(
          'git',
          ['-C', top, 'hash-object', '-t', 'commit', '-w', '--stdin'],
          {
            input: Buffer.from(
              `tree ${tree}\nparent ${head}\nauthor ${person}\ncommitter ${person}\nencoding ${encoding}\n\nA message ${body}\n`,
              'latin1'
            ),
            env: cleanEnv,
            encoding: 'utf8',
          }
        ).trim();
        gate.git('update-ref', 'refs/orbit-r12r2/encoded', id);
        try {
          const raw = plain(['cat-file', 'commit', id]);
          const shown = plain(['log', '-1', '--format=%B', id]);
          // glibc's iconv has no HZ converter, so Git on Linux shows an HZ message as its raw
          // bytes and the hidden marker cannot be shown there; the gate must block it all the same.
          if (encoding === 'HZ-GB-2312' && shown.includes(Buffer.from(body, 'latin1')))
            assert.equal(shown.includes(marker), false, 'the harness: Git leaves HZ unconverted');
          else assert.ok(shown.includes(marker), 'the harness: Git shows the marker');
          assert.equal(raw.includes(0), false, 'the harness: no NUL byte');
          assert.equal(
            raw.includes(marker),
            !blocked,
            'the harness: the raw commit holds the marker'
          );
          const outcome = run();
          const record = outcome.stage('secrets-metadata');
          assert.equal(
            outcome.stage('secrets-history')?.status,
            'pass',
            'the history scan still runs'
          );
          if (blocked) {
            assert.equal(record?.status, 'blocked', `${record?.status} ${record?.error ?? ''}`);
            assert.match(
              record.error,
              new RegExp(
                `cannot be given to the secret scan complete: the commit ${id} names the encoding "${encoding}"`
              )
            );
            assert.equal(record.command, undefined, 'no command was started');
            assert.equal(fs.existsSync(path.join(kept, 'metadata')), false, 'no scan input');
          } else {
            assert.equal(record?.status, 'pass', `${record?.status} ${record?.error ?? ''}`);
            const given = fs.readFileSync(path.join(kept, 'metadata', 'history-messages.txt'));
            assert.ok(given.includes(raw), 'the raw commit is in the scan input');
            assert.ok(given.includes(marker), 'the marker is in the scan input');
          }
        } finally {
          gate.git('update-ref', '-d', 'refs/orbit-r12r2/encoded');
        }
      });

    // 2. Filter drivers the repository defines, every index entry racily clean (the index's own
    // time set back, so Git checks each file's content, through the filter).
    const info = path.join(top, '.git', 'info', 'attributes');
    const stale = () =>
      fs.utimesSync(
        path.join(top, '.git', 'index'),
        new Date('2020-01-01T00:00:00Z'),
        new Date('2020-01-01T00:00:00Z')
      );
    for (const name of ['orbitf', 'a=b', '', 'e=', '=f'])
      each(`a filter driver named ${JSON.stringify(name)}`, () => {
        fs.appendFileSync(config, `[filter "${name}"]\n\tclean = ${helper}\n\trequired = true\n`);
        fs.writeFileSync(info, `* filter=${name}\n`);
        try {
          fs.writeFileSync(helperLog, '');
          stale();
          plain(['write-tree']);
          // Git on Linux checks no racily clean entry in write-tree (Apple Git does); a refresh of
          // the index does on both.
          if (!starts().length) plain(['update-index', '-q', '--refresh']);
          assert.ok(
            starts().length > 0,
            'the harness: plain write-tree, or where it checks no racily clean entry (Git on Linux) update-index --refresh, starts the filter'
          );
          stale();
          const outcome = run();
          assert.deepEqual(gateStarts(), [], 'the filter started in a Git process of the gate');
          assert.equal(outcome.evidence.tree, gate.git('write-tree'), 'the candidate tree');
        } finally {
          fs.rmSync(info, { force: true });
        }
      });

    // 3. Hooks: the cache-tree made invalid before each write-tree (an entry added and removed
    // again, the index's content unchanged), so write-tree writes the index.
    const invalidate = () => {
      const blob = execFileSync('git', ['-C', top, 'hash-object', '-w', '--stdin'], {
        input: 'r12 round 2\n',
        env: cleanEnv,
        encoding: 'utf8',
      }).trim();
      plain(['update-index', '--add', '--cacheinfo', `100644,${blob},r12r2-probe.txt`]);
      plain(['update-index', '--force-remove', 'r12r2-probe.txt']);
    };
    const hooksFolder = path.join(work, 'hooks');
    fs.mkdirSync(hooksFolder);
    for (const [label, setup, teardown] of [
      [
        'a post-index-change hook in .git/hooks',
        () => fs.copyFileSync(helper, path.join(top, '.git', 'hooks', 'post-index-change')),
        () => fs.rmSync(path.join(top, '.git', 'hooks', 'post-index-change')),
      ],
      [
        "a post-index-change hook in the repository's own core.hooksPath",
        () => {
          fs.copyFileSync(helper, path.join(hooksFolder, 'post-index-change'));
          fs.appendFileSync(config, `[core]\n\thooksPath = ${hooksFolder}\n`);
        },
        () => fs.rmSync(path.join(hooksFolder, 'post-index-change')),
      ],
      [
        "a hook the repository's configuration defines (hook.orbitr2.command, event post-index-change)",
        () =>
          fs.appendFileSync(
            config,
            `[hook "orbitr2"]\n\tcommand = ${helper}\n\tevent = post-index-change\n`
          ),
        () => {},
      ],
      [
        'a configured hook named with = (hook.q=x.command)',
        () =>
          fs.appendFileSync(
            config,
            `[hook "q=x"]\n\tcommand = ${helper}\n\tevent = post-index-change\n`
          ),
        () => {},
      ],
    ])
      each(label, () => {
        setup();
        try {
          invalidate();
          fs.writeFileSync(helperLog, '');
          plain(['write-tree']);
          assert.ok(starts().length > 0, 'the harness: plain write-tree starts the hook');
          invalidate();
          run();
          assert.deepEqual(gateStarts(), [], 'the hook started in a Git process of the gate');
        } finally {
          teardown();
        }
      });

    assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
  }
);
