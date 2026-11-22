// Synthetic scanner output exercises the policy boundary, never claims a real scan pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../scripts/security-evidence.mjs';
import { findingReports, reportFindings } from '../scripts/security-findings.mjs';
import {
  currentCandidate,
  platformInputs,
  requiredStages,
  lintStageNames,
  sealRun,
  inspectRun,
  finalizeRun,
  validateFinalization,
  readEvidence,
} from '../scripts/security-finalization.mjs';
import { declareGit } from './helpers/git.mjs';
import {
  asIfFinalizedByF,
  identityOf,
  maintenanceBinary,
  maintenanceInputs,
  maintenanceReleaseKeys,
  maintenanceRuntime,
  maintenanceRuntimeRecord,
  pinActionlint,
  reviewBinding,
  writeRun,
} from './helpers/security-run.mjs';

// 1.5: every fixture() is a Git repository.
const gitSkip = declareGit();

const toolsBytes = fs.readFileSync(new URL('../scripts/security-tools.json', import.meta.url));
const tools = JSON.parse(toolsBytes);
const image = `sha256:${'a'.repeat(64)}`;
const tap = '# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
const totals = { tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
// gate-draft-r9 (GDR8-AUTH-LINT-01): recordedApproval and maintenanceEvidenceProblems take the
// lint stages a commit requires and have no default. A direct call here names none explicitly;
// the requirement verifyCommit derives from the exact commit is tested at the entry points
// (test/security-parents.test.mjs).
const noLint = Object.freeze({ lintStages: Object.freeze([]) });
const requirements = new Set([
  'candidate-policy',
  'sast-rules-checksum',
  'gitleaks-version',
  'trivy-version',
  'actionlint-version',
  'minimum-runtime-available',
  'independent-review',
  'candidate-unchanged',
  // The host and runtime prerequisites of the test stages (GDR6-REQ-01): requirements too.
  'test-host',
  'runtime-identity',
]);
const repository = fileURLToPath(new URL('..', import.meta.url));
// 1.5: the candidate is 1.5-shaped. Its package.json defines both lint scripts, in the canonical
// form the gate's candidate-policy requires, and its run records both lint stages, which the
// commit guard then requires (scripts/check-security-approval.mjs), as does the 1.5 finalizer.
// Both name them as `current.lintStages`, as the fixture's `current` does.
const packageJson = `${JSON.stringify(
  {
    scripts: {
      'lint:sql': 'node scripts/sql-lint.mjs',
      'lint:imports': 'node scripts/import-graph.mjs',
    },
  },
  null,
  2
)}\n`;

function fixture(t, change = () => {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-finalization-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (file, value) => {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      file,
      typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value),
      { mode: 0o600 }
    );
  };
  const git = (...args) =>
    execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: 'pipe' }).trimEnd();
  git('init', '--quiet');
  write(path.join(root, 'scripts/security-tools.json'), toolsBytes);
  write(path.join(root, 'example.mjs'), 'export const synthetic = true;\n');
  write(path.join(root, 'test/canary.mjs'), 'export const testCanary = true;\n');
  write(path.join(root, 'README.md'), '# Synthetic fixture\n');
  write(path.join(root, 'Dockerfile'), '# Synthetic fixture\n');
  write(path.join(root, 'package.json'), packageJson);
  git('add', '.');
  git(
    '-c',
    'user.name=Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'core.hooksPath=/dev/null',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '--quiet',
    '-m',
    'Synthetic fixture only'
  );
  // The candidate as the commit guard sees it: its complete ordered parent vector and the inputs
  // of its platform judgment (no manifest anywhere: maintenance, B35).
  const staged = currentCandidate(root);
  const current = {
    ...staged,
    lintStages: lintStageNames,
    platform: platformInputs(root, staged.tree, {
      heads: staged.parents,
      complete: true,
      reason: '',
    }),
  };
  const run = path.join(root, '.git/orbit-security', `${current.tree}-commit-synthetic`);
  fs.mkdirSync(run, { recursive: true, mode: 0o700 });
  const now = Date.now(),
    started = new Date(now - 2000).toISOString(),
    finished = new Date(now - 1000).toISOString();
  const identity = identityOf(current);
  const record = {
    kind: 'orbit-gate-local-diagnostic-run',
    kindVersion: 1,
    mode: 'commit',
    status: 'blocked',
    tree: current.tree,
    parents: current.parents,
    refs: current.refs,
    candidate: identity.record,
    candidateIdentitySha256: identity.sha256,
    started,
    finished,
    tools,
    // The maintenance gate's four members (gate-draft-r11, GDR10-HOST-PRODUCER-01).
    host: { platform: 'linux', arch: 'arm64', release: 'synthetic', node: 'v24.21.0' },
    stages: [],
  };
  const reports = {
    'secrets-source.json': [
      {
        RuleID: 'synthetic-key',
        File: 'example.mjs',
        StartLine: 1,
        EndLine: 1,
        Fingerprint: 'synthetic:1',
        Secret: 'REDACTED',
      },
    ],
    'secrets-history.json': [],
    'secrets-metadata.json': [],
    'source-analysis.json': {
      version: '1.176.0',
      results: [],
      errors: [],
      skipped_rules: [],
      paths: { scanned: ['example.mjs', 'test/canary.mjs'] },
    },
    'container-configuration.json': {
      SchemaVersion: 2,
      Trivy: { Version: tools.trivy },
      ArtifactID: image,
      ArtifactName: '.',
      Results: [
        {
          Target: 'Dockerfile',
          Class: 'config',
          Type: 'dockerfile',
          MisconfSummary: { Successes: 1, Failures: 0 },
        },
      ],
    },
    'container-security.json': {
      SchemaVersion: 2,
      Trivy: { Version: tools.trivy },
      ArtifactID: image,
      ArtifactName: 'synthetic:tag',
      Metadata: { ImageID: image },
      Results: [
        { Target: 'synthetic OS', Class: 'os-pkgs', Vulnerabilities: [] },
        { Target: 'Node.js', Class: 'lang-pkgs', Vulnerabilities: [] },
        { Target: 'synthetic:tag', Class: 'config', MisconfSummary: { Successes: 1, Failures: 0 } },
      ],
    },
  };
  for (const name of [...requiredStages, ...lintStageNames]) {
    const stage = {
      name,
      started,
      finished,
      status: name === 'independent-review' ? 'blocked' : 'pass',
    };
    if (!requirements.has(name)) {
      stage.command = ['synthetic-fixture'];
      stage.exit = 0;
      stage.signal = null;
      stage.log = `${name}.log`;
    }
    if (name.startsWith('full-tests-')) stage.tests = totals;
    if (name === 'source-analysis')
      stage.command.push(tools.semgrepImage, '--no-git-ignore', '--project-root', '/scan');
    if (name === 'container-vulnerabilities') stage.command.push('synthetic:tag');
    if (name === 'secrets-source') {
      stage.exit = 10;
      stage.status = 'blocked';
    }
    record.stages.push(stage);
  }
  const logs = Object.fromEntries(
    record.stages
      .filter(s => s.log)
      .map(s => [
        s.log,
        s.name.startsWith('full-tests-')
          ? tap
          : s.name.startsWith('secrets-')
            ? 'INF scanned ~100 bytes in 1ms\n'
            : 'Synthetic completed command\n',
      ])
  );
  logs['container-identity.log'] = JSON.stringify([{ Id: image }]);
  logs['scanner-database.log'] = JSON.stringify({
    Version: tools.trivy,
    VulnerabilityDB: {
      UpdatedAt: new Date(now - 60000).toISOString(),
      DownloadedAt: new Date(now - 30000).toISOString(),
      NextUpdate: new Date(now + 3600000).toISOString(),
    },
  });
  // The pinned Actionlint of a reviewed golden-tool record (security review GD-R2): synthetic.
  Object.assign(logs, pinActionlint(record, run, now));
  // The maintenance run's host and runtime evidence (GDR6-REQ-01): synthetic.
  Object.assign(logs, maintenanceRuntime(record, now));
  change({ record, reports, logs, current, root });
  write(path.join(run, 'result.json'), record);
  write(path.join(run, 'source-manifest.json'), current.files);
  write(path.join(run, 'tool-config.json'), toolsBytes);
  write(path.join(run, 'semgrepignore'), '');
  // gate-draft-r10 (GDR9-AUTH-SCAN-02): a scanner's fixed report only for a scanner stage that
  // ran, as the gate creates one only when it starts the scanner.
  const ran = new Set(
    record.stages
      .filter(stage => findingReports[stage.name] && stage.status !== 'pending')
      .map(stage => findingReports[stage.name])
  );
  for (const [name, body] of Object.entries(reports))
    if (ran.has(name)) write(path.join(run, name), body);
  for (const [name, body] of Object.entries(logs)) write(path.join(run, name), body);
  sealRun(run);
  const inventory = inspectRun(run, current, now);
  const supporting = path.join(root, 'supporting-evidence.txt');
  write(supporting, 'Synthetic analysis proving this one fixture contains no live credential.');
  const review = {
    ...reviewBinding(inventory),
    reviewer: 'Independent synthetic reviewer',
    reference: 'Synthetic code review',
    reviewedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 3600000).toISOString(),
    unresolved: [],
    documents: { 'README.md': { status: 'checked unchanged', reason: 'Synthetic fixture only' } },
    dispositions: inventory.findings.map(item => ({
      id: item.id,
      status: 'false-positive',
      reason: 'Synthetic isolated fixture',
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic evidence',
      evidenceFile: supporting,
      evidenceSha256: sha256(fs.readFileSync(supporting)),
    })),
  };
  const reviewFile = path.join(root, 'review.json');
  const save = () => write(reviewFile, review);
  save();
  return {
    root,
    git,
    run,
    current,
    now,
    record,
    review,
    reviewFile,
    save,
    write,
    inventory,
    supporting,
  };
}

test('an exact reviewed finding finalizes without rewriting raw results; hook checks copied evidence', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  assert.equal(f.inventory.eligible, true, f.inventory.blockers.join('; '));
  const before = fs.readFileSync(path.join(f.run, 'result.json'));
  // This module's finalization of a maintenance (B35) candidate is pending: the qualified binding
  // of its pinned Actionlint is an F obligation (actionlint-pin; maintainer decision 8).
  const finalized = finalizeRun(f.run, f.reviewFile, f.current, f.now);
  assert.equal(finalized.status, 'pending');
  assert.deepEqual(finalized.obligations, { 'actionlint-pin': 'pending' });
  assert.equal(finalized.pending.length, 1);
  assert.match(finalized.pending[0], /^F obligation actionlint-pin: the qualified golden-tool/);
  assert.deepEqual(fs.readFileSync(path.join(f.run, 'result.json')), before);
  assert.equal(JSON.parse(before).stages.find(s => s.name === 'secrets-source').exit, 10);
  fs.unlinkSync(f.supporting);
  // The commit guard refuses it, as a hook too.
  assert.throws(
    () => validateFinalization(f.run, f.current, f.now),
    /Finalization is "pending", not pass: F obligation actionlint-pin/
  );
  const hook = () =>
    spawnSync(process.execPath, [path.join(repository, 'scripts/check-security-approval.mjs')], {
      cwd: f.root,
      encoding: 'utf8',
    });
  const refused = hook();
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /maintenance candidate .*actionlint-pin; maintainer decision 8/);
  // As F would write it once the qualified manifest bound the pin (a stand-in: no F exists).
  asIfFinalizedByF(f.run);
  assert.equal(validateFinalization(f.run, f.current, f.now).findings, 1);
  const accepted = hook();
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.throws(() => finalizeRun(f.run, f.reviewFile, f.current, f.now));
});

test('raw pass flags alone cannot authorize the real hook', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  const result = spawnSync(
    process.execPath,
    [path.join(repository, 'scripts/check-security-approval.mjs')],
    { cwd: f.root, encoding: 'utf8' }
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /No fresh verified finalization/);
});

for (const [name, change] of Object.entries({
  'missing stage': x => {
    x.record.stages = x.record.stages.filter(s => s.name !== 'workflow-analysis');
  },
  'duplicate stage': x => {
    x.record.stages.push({ ...x.record.stages[0] });
  },
  'missing scanner command': x => {
    delete x.record.stages.find(s => s.name === 'source-analysis').command;
  },
  'missing non-scanner command': x => {
    delete x.record.stages.find(s => s.name === 'dependencies-all').command;
  },
  'unsupported dependency findings': x => {
    Object.assign(
      x.record.stages.find(s => s.name === 'dependencies-all'),
      { exit: 1, status: 'blocked' }
    );
  },
  'scanner execution error': x => {
    x.record.stages.find(s => s.name === 'secrets-source').error = 'ETIMEDOUT';
  },
  'wrong finding exit': x => {
    x.record.stages.find(s => s.name === 'secrets-source').exit = 1;
  },
  'missing finding with nonzero exit': x => {
    x.reports['secrets-source.json'] = [];
  },
  'failed test hidden in totals': x => {
    x.logs['full-tests-current-runtime.log'] = tap.replace('# fail 0', '# fail 1');
  },
  'skipped test': x => {
    x.logs['full-tests-current-runtime.log'] = tap.replace('# skipped 0', '# skipped 1');
  },
  'missing minimum runtime': x => {
    x.record.host.node = 'v26.5.1';
  },
  'recorded tool differs from candidate': x => {
    x.record.tools = { ...tools, trivy: '0.0.0' };
  },
  'wrong scanner image invocation': x => {
    x.record.stages.find(s => s.name === 'source-analysis').command = ['unreviewed-image'];
  },
  'wrong scanned image': x => {
    x.reports['container-security.json'].Metadata.ImageID = `sha256:${'b'.repeat(64)}`;
  },
  'stale database': x => {
    const d = JSON.parse(x.logs['scanner-database.log']);
    d.VulnerabilityDB.NextUpdate = '2000-01-01';
    x.logs['scanner-database.log'] = JSON.stringify(d);
  },
  'missing JS scan coverage': x => {
    x.reports['source-analysis.json'].paths.scanned = ['other.mjs'];
  },
  'Semgrep default test-directory omission': x => {
    x.reports['source-analysis.json'].paths.scanned = ['example.mjs'];
  },
  'partial Semgrep errors': x => {
    x.reports['source-analysis.json'].errors = [{ message: 'synthetic parsing error' }];
  },
  'ignored Semgrep rules': x => {
    x.reports['source-analysis.json'].skipped_rules = ['synthetic-rule'];
  },
  'secret scan did not finish': x => {
    x.logs['secrets-source.log'] = 'ERR synthetic incomplete scan';
  },
  'legacy unsealed schema': x => {
    // A record that names no record family (GDR4-02), as the earliest records named no schema.
    delete x.record.kind;
    delete x.record.kindVersion;
  },
  // 1.5: the lint stages, and scan or release runs, which never approve a commit.
  'missing sql-lint stage': x => {
    x.record.stages = x.record.stages.filter(s => s.name !== 'sql-lint');
  },
  'missing import-lint stage': x => {
    x.record.stages = x.record.stages.filter(s => s.name !== 'import-lint');
  },
  'failed lint stage': x => {
    Object.assign(
      x.record.stages.find(s => s.name === 'import-lint'),
      { exit: 1, status: 'blocked' }
    );
  },
  // verify-1: GD-R2 holds for maintenance (B35) runs too. This fixture is one (no manifest
  // anywhere), and its Actionlint stages are pinned (test/helpers/security-run.mjs).
  'B35: workflow-analysis from a bare actionlint on PATH': x => {
    x.record.stages.find(s => s.name === 'workflow-analysis').command = ['actionlint'];
  },
  'B35: actionlint-version without a sealed golden-tool record': x => {
    delete x.record.stages.find(s => s.name === 'actionlint-version').tool;
  },
  'B35: a gate configuration that is not empty': x => {
    x.logs['actionlint-config.yaml'] = 'paths: {}\n';
  },
  'B35: no sha256 of the binary right before and after it ran': x => {
    delete x.record.stages.find(s => s.name === 'workflow-analysis').binarySha256;
  },
  'B35: the binary changed before workflow-analysis ran it': x => {
    x.record.stages.find(s => s.name === 'workflow-analysis').binarySha256.before = '0'.repeat(64);
  },
  'B35: the binary changed while workflow-analysis ran it': x => {
    x.record.stages.find(s => s.name === 'workflow-analysis').binarySha256.after = '0'.repeat(64);
  },
  'scan run': x => {
    x.record.mode = 'scan';
  },
  'release run': x => {
    x.record.mode = 'release';
  },
}))
  test(`finalization blocks ${name}`, t => {
    if (gitSkip) return t.skip(gitSkip);
    if (['legacy unsealed schema', 'scan run', 'release run'].includes(name)) {
      // A record that names no record family is refused before any other member is read
      // (GDR4-02): no family is assumed or inferred; a scan or release run is not a commit run.
      assert.throws(
        () => fixture(t, change),
        name === 'legacy unsealed schema'
          ? /The record names no record family: none is assumed or inferred from its members/
          : /Only sealed local runs \(orbit-gate-local-diagnostic-run version 1\) of mode commit/
      );
      return;
    }
    const f = fixture(t, change);
    assert.equal(f.inventory.eligible, false);
    if (name.startsWith('B35: ')) assert.match(f.inventory.blockers.join('\n'), /^Actionlint: /m);
    assert.throws(() => finalizeRun(f.run, f.reviewFile, f.current, f.now));
  });

// verify-1: a candidate that tracks an Actionlint configuration is refused by the finalizer as well,
// for maintenance (B35) runs too, in any letter case, whatever gate wrote the run (the 1.5 gate
// refuses it in candidate-policy). No Git is needed.
test('a candidate that tracks an Actionlint configuration is refused for every run', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-finalization-actionlint-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const now = Date.now();
  const clean = syntheticCandidate();
  const control = path.join(root, 'control');
  writeRun(control, clean, [...requiredStages, ...lintStageNames], now);
  assert.deepEqual(inspectRun(control, { ...clean, lintStages: lintStageNames }, now).blockers, []);
  for (const file of [
    '.github/actionlint.yaml',
    '.github/actionlint.yml',
    '.GitHub/ActionLint.YML',
  ]) {
    const current = {
      ...clean,
      files: [
        ...clean.files,
        { file, mode: '100644', blob: '1'.repeat(40), sha256: '2'.repeat(64) },
      ],
    };
    const run = path.join(root, `tracked-${file.length}-${file.charCodeAt(1)}`);
    writeRun(run, current, [...requiredStages, ...lintStageNames], now);
    const inventory = inspectRun(run, { ...current, lintStages: lintStageNames }, now);
    assert.equal(inventory.eligible, false, file);
    assert.match(
      inventory.blockers.join('\n'),
      /A tracked Actionlint configuration can silence workflow findings/,
      file
    );
  }
});

// A synthetic candidate (tree, HEAD, complete parent vector, refs and files) for runs that need
// no Git, with the inputs of its platform judgment (maintenance: no manifest anywhere).
function syntheticCandidate() {
  const entry = (file, bytes) => ({
    file,
    mode: '100644',
    blob: createHash('sha1')
      .update(`blob ${Buffer.byteLength(bytes)}\0`)
      .update(bytes)
      .digest('hex'),
    sha256: sha256(bytes),
  });
  const current = {
    tree: 'c'.repeat(40),
    parent: 'd'.repeat(40),
    parents: ['d'.repeat(40)],
    refs: `refs/heads/main ${'d'.repeat(40)}`,
    files: [
      entry('Dockerfile', '# Synthetic fixture\n'),
      entry('example.mjs', 'export const synthetic = true;\n'),
      entry('scripts/security-tools.json', toolsBytes),
    ],
  };
  return { ...current, platform: maintenanceInputs(current) };
}

// 1.5: every mandatory stage, the lint stages included when the caller names them (as the
// commit guard and the 1.5 finalizer do), must be recorded and must have passed, and only a
// commit run counts. The run is for a synthetic candidate, so this needs no Git and also runs
// where there is none. Each record is changed and sealed again, as a forged run would be.
test('each mandatory stage, the lint stages included, is required and must pass', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-finalization-stages-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = syntheticCandidate();
  const now = Date.now();
  const run = path.join(root, `${current.tree}-commit-synthetic`);
  writeRun(run, current, [...requiredStages, ...lintStageNames], now);
  const original = fs.readFileSync(path.join(run, 'result.json'), 'utf8');
  const reseal = change => {
    const record = JSON.parse(original);
    change(record);
    fs.writeFileSync(path.join(run, 'result.json'), JSON.stringify(record), { mode: 0o600 });
    fs.unlinkSync(path.join(run, 'run-manifest.json'));
    sealRun(run);
    return inspectRun(run, { ...current, lintStages: lintStageNames }, now);
  };
  assert.equal(reseal(() => {}).eligible, true);
  for (const name of [...requiredStages, ...lintStageNames]) {
    const missing = reseal(record => {
      record.stages = record.stages.filter(s => s.name !== name);
    });
    assert.equal(missing.eligible, false, `missing ${name}`);
    if (name === 'independent-review') continue; // The exact review replaces its record.
    const blocked = reseal(record => {
      Object.assign(
        record.stages.find(s => s.name === name),
        { exit: 1, status: 'blocked' }
      );
    });
    assert.equal(blocked.eligible, false, `blocked ${name}`);
  }
  // A run on a newer runtime also needs the separate minimum-runtime test stage, passing. Each
  // test stage runs its slot's Node, identified by runtime-identity (GDR6-REQ-01): the gate's own
  // Node 26 in the current-runtime stage, and Node 24 in the minimum-runtime stage.
  const newer = (status, exit) => record => {
    record.host.node = 'v26.5.1';
    const tests = record.stages.find(s => s.name === 'full-tests-current-runtime');
    const node24 = { ...tests.runtime };
    const node26 = maintenanceBinary('v26.5.1');
    tests.runtime = {
      path: '/synthetic/maintenance/node-v26.5.1',
      version: 'v26.5.1',
      sha256: node26,
    };
    record.stages
      .find(s => s.name === 'runtime-identity')
      .runtimes.push({ ...tests.runtime, record: `runtime-identity-${node26}.json` });
    fs.writeFileSync(
      path.join(run, `runtime-identity-${node26}.json`),
      JSON.stringify(
        maintenanceRuntimeRecord({
          version: 'v26.5.1',
          sha256: node26,
          platform: 'linux',
          arch: 'arm64',
          now,
        })
      ),
      { mode: 0o600 }
    );
    if (!status) return;
    record.stages.push({
      ...tests,
      name: 'full-tests-minimum-runtime',
      status,
      exit,
      runtime: node24,
    });
  };
  assert.equal(reseal(newer()).eligible, false);
  assert.equal(reseal(newer('pass', 0)).eligible, true);
  assert.equal(reseal(newer('blocked', 1)).eligible, false);
  // A scan or release run never finalizes a commit, whatever it recorded.
  for (const mode of ['scan', 'release', undefined])
    assert.throws(
      () =>
        reseal(record => {
          record.mode = mode;
        }),
      /Only sealed local runs \(orbit-gate-local-diagnostic-run version 1\) of mode commit/,
      String(mode)
    );
});

// One installed commit guard serves the maintenance and 1.5 worktrees only if both carry the
// same helper modules, this one among them, and the maintenance finalizer (the maintenance
// scripts/finalize-security.mjs) passes currentCandidate() as it is, naming no lint stages. So a
// caller that names none requires none, and every other mandatory stage as before: the
// maintenance finalizer still finalizes its own runs, which record no lint stage, with this
// module. Anything but a list of lint stage names blocks. No Git is needed.
test('a caller that names no lint stages, as the maintenance finalizer, requires none', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-finalization-maintenance-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = syntheticCandidate();
  const now = Date.now();
  const write = (name, stages) => {
    const run = path.join(root, `${current.tree}-commit-${name}`);
    writeRun(run, current, stages, now);
    return run;
  };
  const maintenance = write('maintenance', requiredStages);
  assert.deepEqual(inspectRun(maintenance, current, now).blockers, []);
  // A caller that names no platform inputs cannot establish the candidate identity, whose state
  // of the reserved manifest path comes from the judgment (v3 C18, C19): it approves nothing.
  const { platform, ...uninformed } = current;
  assert.equal(platform.heads.length, 1);
  assert.match(
    inspectRun(maintenance, uninformed, now).blockers[0],
    /needs the platform-manifest judgment/
  );
  assert.deepEqual(inspectRun(maintenance, { ...current, lintStages: [] }, now).blockers, []);
  assert.deepEqual(
    inspectRun(maintenance, { ...current, lintStages: lintStageNames }, now).blockers,
    ['A mandatory stage is missing']
  );
  for (const lintStages of [null, 'sql-lint', {}, ['lint:sql'], ['sql-lint', 'other'], [1]])
    assert.deepEqual(
      inspectRun(maintenance, { ...current, lintStages }, now).blockers,
      ['Invalid lint stage requirement'],
      JSON.stringify(lintStages)
    );
  for (const name of requiredStages) {
    const run = write(
      `without-${name}`,
      requiredStages.filter(stage => stage !== name)
    );
    assert.equal(inspectRun(run, current, now).eligible, false, name);
  }
  // The maintenance finalizer's own calls: finalize, then the check its guard makes.
  const inventory = inspectRun(maintenance, current, now);
  assert.deepEqual([inventory.findings, inventory.eligible, inventory.blockers], [[], true, []]);
  const binding = reviewBinding(inventory);
  const review = path.join(root, 'review.json');
  fs.writeFileSync(
    review,
    JSON.stringify({
      ...binding,
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(),
      unresolved: [],
      documents: {},
      dispositions: [],
    }),
    { mode: 0o600 }
  );
  // This module's finalization is pending (actionlint-pin is F's; maintainer decision 8), and the guard
  // refuses it; as F would write it, the guard accepts it.
  assert.equal(finalizeRun(maintenance, review, current, now).status, 'pending');
  assert.throws(
    () => validateFinalization(maintenance, current, now),
    /Finalization is "pending", not pass: F obligation actionlint-pin/
  );
  asIfFinalizedByF(maintenance);
  assert.equal(validateFinalization(maintenance, current, now).status, 'pass');
});

// gate-draft-r7, GDR6-REQ-01 (the security review of gate-draft-r6; a required correction under the maintainer's
// explicit B35 clarification of 20261017T140102522864Z, not a newly introduced r6 regression): the
// maintenance (B35) finalizer kept the earlier gate's stage list, without test-host or
// runtime-identity, and the platform evidence check returned early for maintenance without
// looking at any host or runtime evidence. Now a maintenance run needs both, passed, before its
// test stages, and the identity of every Node binary its test stages ran, checked against its
// sealed record: legacy evidence without them is refused on that basis, as is identity material
// that does not hold, whichever caller asks (the maintenance finalizer names no lint stage) and
// also through checkPlatformEvidence's early maintenance return itself. No Git is needed.
test('GDR6-REQ-01: maintenance finalization refuses legacy evidence without test-host or runtime-identity, and every invalid host or runtime record it consumes; the early B35 return passes none of it', async t => {
  const platform = await import('../scripts/security-platform.mjs');
  const { readSealedRun } = await import('../scripts/security-finalization.mjs');
  const { installedCatalog } = await import('../scripts/security-catalog.mjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-finalization-gdr6-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = syntheticCandidate();
  const now = Date.now();
  const prerequisites = ['test-host', 'runtime-identity'];
  // The earlier gate's list, as gate-draft-r6 kept it, and the maintenance list with both
  // prerequisites before the test stages (built here, so the same runs can be made of either tree).
  const legacyStages = requiredStages.filter(name => !prerequisites.includes(name));
  const at = legacyStages.indexOf('full-tests-current-runtime');
  const maintenanceStages = [
    ...legacyStages.slice(0, at),
    ...prerequisites,
    ...legacyStages.slice(at),
  ];
  let count = 0;
  const write = (stages, options = {}) => {
    const run = path.join(root, `${current.tree}-commit-gdr6-${(count += 1)}`);
    writeRun(run, current, stages, now, options);
    return run;
  };
  const catalog = () => {
    const installed = installedCatalog();
    return { catalog: installed.catalog, catalogSha256: installed.sha256 };
  };
  // Legacy evidence, as the earlier gate (and gate-draft-r6's maintenance route) wrote it: refused
  // because it lacks test-host or runtime-identity, for the maintenance finalizer (no lint stage
  // named) and the 1.5 one. gate-draft-r6 found it eligible.
  const legacy = [
    ['neither prerequisite (the earlier gate list)', legacyStages, prerequisites],
    [
      'no runtime-identity',
      maintenanceStages.filter(name => name !== 'runtime-identity'),
      ['runtime-identity'],
    ],
    ['no test-host', maintenanceStages.filter(name => name !== 'test-host'), ['test-host']],
  ].map(([label, stages, missing]) => [label, write(stages), missing]);
  for (const [label, run, missing] of legacy)
    for (const lintStages of [undefined, []]) {
      const inventory = inspectRun(run, { ...current, lintStages }, now);
      assert.equal(inventory.eligible, false, label);
      assert.equal(inventory.blockers.length, 1, label);
      assert.match(
        inventory.blockers[0],
        /^Maintenance \(B35\) host and runtime evidence: /,
        label
      );
      for (const name of missing)
        assert.match(
          inventory.blockers[0],
          new RegExp(
            `${name} is absent: a maintenance \\(B35\\) run must record test-host and runtime-identity, each passed, before its test stages \\(GDR6-REQ-01\\), so evidence without it is refused`
          ),
          `${label}: ${name}`
        );
    }
  // The positive control: a maintenance run with valid host and runtime evidence is eligible.
  const valid = write(maintenanceStages);
  assert.deepEqual(inspectRun(valid, current, now).blockers, []);
  assert.equal(inspectRun(valid, current, now).eligible, true);
  // The maintenance list names both, before the test stages, and the check behind the early
  // maintenance return passes the valid run and refuses each legacy one by itself.
  assert.deepEqual(platform.MAINTENANCE_TEST_PREREQUISITES, prerequisites);
  assert.deepEqual(requiredStages, maintenanceStages);
  assert.deepEqual(platform.maintenanceRuntimeProblems(readSealedRun(valid)), []);
  assert.doesNotThrow(() =>
    platform.checkPlatformEvidence({
      main: readSealedRun(valid),
      companions: [],
      current,
      now,
      catalog: catalog(),
    })
  );
  for (const [label, run] of legacy)
    assert.throws(
      () =>
        platform.checkPlatformEvidence({
          main: readSealedRun(run),
          companions: [],
          current,
          now,
          catalog: catalog(),
        }),
      /^Error: Maintenance \(B35\) host and runtime evidence: .* is absent/,
      label
    );
  // Every invalid record the consumer reads: [label, writeRun options, problem].
  const identity = record => record.stages.find(stage => stage.name === 'runtime-identity');
  const host = record => record.stages.find(stage => stage.name === 'test-host');
  const tests = record => record.stages.find(stage => stage.name === 'full-tests-current-runtime');
  const binary = maintenanceBinary('v24.21.0');
  const recordFile = `runtime-identity-${binary}.json`;
  const runtimeRecord = change =>
    JSON.stringify({
      ...maintenanceRuntimeRecord({
        version: 'v24.21.0',
        sha256: binary,
        platform: 'linux',
        arch: 'arm64',
        now,
      }),
      ...change,
    });
  const cases = [
    [
      'runtime-identity pending',
      { pending: ['runtime-identity'] },
      /runtime-identity is "pending", not pass/,
    ],
    [
      'runtime-identity blocked',
      { record: r => Object.assign(identity(r), { status: 'blocked', error: 'synthetic' }) },
      /runtime-identity is "blocked", not pass/,
    ],
    [
      'test-host failed',
      { record: r => (host(r).status = 'fail') },
      /test-host is "fail", not pass/,
    ],
    [
      'runtime-identity recorded twice',
      { record: r => r.stages.splice(r.stages.indexOf(identity(r)), 0, { ...identity(r) }) },
      /runtime-identity is recorded 2 times, so it has no one result/,
    ],
    // The run's own time check (runTimeProblems) refuses these two first; the early return's own
    // check refuses them too.
    [
      'runtime-identity with no valid recorded end',
      { record: r => delete identity(r).finished },
      /runtime-identity has no recorded start and end, present and well formed/,
      /^Run times: runtime-identity records no start and finish time/,
    ],
    [
      'stale: runtime-identity begun before the run',
      { record: r => (identity(r).started = new Date(now - 5000).toISOString()) },
      /runtime-identity has an interval outside its record's window/,
      /^Run times: runtime-identity is outside the run's times/,
    ],
    [
      'runtime-identity ending after the test stage started',
      { record: r => (identity(r).finished = r.finished) },
      /runtime-identity must end before full-tests-current-runtime starts, and be recorded before it/,
    ],
    [
      'runtime-identity recorded after the test stage',
      {
        record: r => {
          const stage = identity(r);
          r.stages.splice(r.stages.indexOf(stage), 1);
          r.stages.splice(r.stages.indexOf(tests(r)) + 1, 0, stage);
        },
      },
      /runtime-identity must end before full-tests-current-runtime starts, and be recorded before it/,
    ],
    [
      'test-host for another platform',
      { record: r => (host(r).host.platform = 'darwin') },
      /test-host does not apply to this run: it names the platform "darwin", not "linux"/,
    ],
    [
      'test-host as root',
      { record: r => (host(r).host.uid = 0) },
      /test-host records root, or no user/,
    ],
    [
      'no runtime identified',
      { record: r => (identity(r).runtimes = []) },
      /runtime-identity identifies no runtime/,
    ],
    [
      'a runtime entry that is not { version, sha256, record }',
      { record: r => (identity(r).runtimes[0].version = 'v24') },
      /runtime-identity lists a runtime that is not \{ version, sha256, record \}/,
    ],
    [
      'a binary listed twice',
      { record: r => identity(r).runtimes.push({ ...identity(r).runtimes[0] }) },
      /runtime-identity lists the binary [0-9a-f]{64} twice/,
    ],
    [
      'another binary than the test stage ran',
      { record: r => (tests(r).runtime.sha256 = 'b'.repeat(64)) },
      /full-tests-current-runtime: runtime-identity does not identify its Node binary \(Node v24\.21\.0, sha256 b{64}\)/,
    ],
    [
      'another version of the binary',
      { record: r => (identity(r).runtimes[0].version = 'v24.20.0') },
      /full-tests-current-runtime: runtime-identity does not identify its Node binary/,
    ],
    [
      'a test stage that records no runtime',
      { record: r => delete tests(r).runtime },
      /full-tests-current-runtime records no Node version and binary sha256/,
    ],
    [
      'its identity record not sealed',
      { record: r => (identity(r).runtimes[0].record = 'runtime-identity-missing.json') },
      /its identity record "runtime-identity-missing\.json" is not sealed with the run/,
    ],
    [
      'an identity record for another binary',
      { files: { [recordFile]: runtimeRecord({ binarySha256: 'c'.repeat(64) }) } },
      /the runtime identity record is for the binary "c{64}"/,
    ],
    [
      'an identity record for another platform',
      { files: { [recordFile]: runtimeRecord({ platform: 'darwin' }) } },
      /the runtime identity record is for "darwin"\/"arm64", not linux\/arm64/,
    ],
    [
      'an identity record whose signed check was not verified',
      {
        files: {
          [recordFile]: runtimeRecord({
            release: {
              ...JSON.parse(runtimeRecord({})).release,
              outcome: 'invalid',
            },
          }),
        },
      },
      /the signed SHASUMS check is invalid, not verified/,
    ],
    [
      'an identity record that is not JSON',
      { files: { [recordFile]: '{"schemaVersion": 1,' } },
      /runtime-identity, Node v24\.21\.0 \([0-9a-f]{64}\): /,
    ],
    [
      'a signer that is not a reviewed release key',
      {
        files: {
          'runtime-release-keys.json': JSON.stringify({
            ...maintenanceReleaseKeys(now),
            fingerprints: ['B'.repeat(40)],
          }),
        },
      },
      /release\.signer [0-9A-F]{40} is not one of the reviewed Node release keys/,
    ],
    [
      'no reviewed release keys sealed',
      { record: r => delete identity(r).releaseKeys },
      /there is no reviewed list of Node release keys to check its signer/,
    ],
    [
      'release keys named but not sealed',
      { record: r => (identity(r).releaseKeys = 'runtime-release-keys-missing.json') },
      /runtime-identity: runtime-identity names reviewed release keys it did not seal/,
    ],
    [
      'the current-runtime slot on another Node than the gate ran',
      { record: r => (r.host.node = 'v24.20.0') },
      /full-tests-current-runtime ran Node v24\.21\.0, not the gate's own Node "v24\.20\.0", its approved slot/,
    ],
    [
      'the minimum-runtime slot on Node 26',
      {
        record: r => {
          const stage = tests(r);
          r.stages.splice(r.stages.indexOf(stage) + 1, 0, {
            ...stage,
            name: 'full-tests-minimum-runtime',
            log: 'full-tests-minimum-runtime.log',
            runtime: { ...stage.runtime, version: 'v26.5.1' },
          });
        },
      },
      /full-tests-minimum-runtime ran Node v26\.5\.1, not Node 24, its approved slot/,
    ],
  ];
  for (const [label, options, problem, first] of cases) {
    const run = write(maintenanceStages, options);
    const inventory = inspectRun(run, current, now);
    assert.equal(inventory.eligible, false, label);
    if (first) assert.match(inventory.blockers[0] ?? '', first, label);
    else {
      assert.match(
        inventory.blockers[0] ?? '',
        /^Maintenance \(B35\) host and runtime evidence: /,
        label
      );
      assert.match(inventory.blockers[0], problem, `${label}: ${inventory.blockers[0]}`);
    }
    assert.throws(
      () =>
        platform.checkPlatformEvidence({
          main: readSealedRun(run),
          companions: [],
          current,
          now,
          catalog: catalog(),
        }),
      problem,
      label
    );
  }
  assert.ok(cases.length >= 25, String(cases.length));
  // A test stage withheld before dispatch ran nothing, so it needs no identity of its own (the run
  // is still refused: a maintenance finalization takes no pending stage).
  const withheldTest = write(maintenanceStages, {
    record: r => {
      const stage = tests(r);
      for (const key of Object.keys(stage))
        if (!['name', 'started', 'finished'].includes(key)) delete stage[key];
      Object.assign(stage, {
        status: 'pending',
        reason: 'withheld before dispatch, nothing ran: synthetic',
      });
    },
  });
  assert.deepEqual(platform.maintenanceRuntimeProblems(readSealedRun(withheldTest)), []);
  assert.deepEqual(inspectRun(withheldTest, current, now).blockers, [
    'A required stage is pending: full-tests-current-runtime',
  ]);
});

// gate-draft-r8, GDR7-FIN-01 (the security review of gate-draft-r7: a carried downstream-consumer
// defect, not a regression of GDR6-REQ-01's closure; the maintainer's decision 1 of
// 20261018T051017695655Z): the maintenance consumer required the plan's names but did not enforce
// the plan itself, and bound a runtime only to stages named full-tests-*. An extra executed
// platform-tests-current-runtime on an unidentified binary, any other unique executed stage, and a
// command on the record-only test-host were all eligible. Now one approved B35 plan
// (MAINTENANCE_PLAN) binds each stage name to its execution class, every stage of a maintenance
// run must be one of its names and of its class, and the host and runtime binding applies to every
// test execution the record shows, by the plan's class and the record's own evidence. The
// legitimate runs stay eligible: one slot on a Node 24 gate, two slots on a newer gate, two
// distinct Node 24 executables on a Node 24 gate, the lint stages, the informational records and a
// withheld stage of its class. No Git is needed.
const R7_REQUIRED_STAGES = [
  'snapshot-clone',
  'snapshot-index',
  'snapshot-files',
  'gitleaks-version',
  'trivy-version',
  'actionlint-version',
  'docker-version',
  'npm-version',
  'sast-rules-download',
  'sast-rules-checksum',
  'sast-rules-extract',
  'sast-image-pull',
  'candidate-policy',
  'dependencies-install',
  'format',
  'syntax-manifest',
  'documentation',
  'dependencies-all',
  'dependencies-production',
  'registry-signatures',
  'workflow-analysis',
  'secrets-source',
  'secrets-history',
  'secrets-metadata',
  'source-analysis',
  'container-configuration',
  'container-build',
  'container-identity',
  'container-vulnerabilities',
  'container-sbom',
  'scanner-database',
  'systemd-test-image',
  'test-host',
  'runtime-identity',
  'full-tests-current-runtime',
  'minimum-runtime-available',
  'independent-review',
  'candidate-unchanged',
];

/** A maintenance-run maker for GDR7's tests: synthetic sealed runs of one synthetic candidate. */
async function maintenanceRuns(t, label) {
  const platform = await import('../scripts/security-platform.mjs');
  const finalization = await import('../scripts/security-finalization.mjs');
  const helpers = await import('./helpers/security-run.mjs');
  const { installedCatalog } = await import('../scripts/security-catalog.mjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `orbit-finalization-${label}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = syntheticCandidate();
  const now = Date.now();
  let count = 0;
  const write = (stages, options = {}) => {
    const run = path.join(root, `${current.tree}-commit-${label}-${(count += 1)}`);
    writeRun(run, current, stages, now, options);
    return run;
  };
  const installed = installedCatalog();
  const early = run => () =>
    platform.checkPlatformEvidence({
      main: finalization.readSealedRun(run),
      companions: [],
      current,
      now,
      catalog: { catalog: installed.catalog, catalogSha256: installed.sha256 },
    });
  const stage = (record, name) => record.stages.find(item => item.name === name);
  // A copy of `name`'s record as another stage, sealed with its own log, inserted after it.
  const extra = (record, name, as, change = {}) => {
    const source = stage(record, name);
    record.stages.splice(record.stages.indexOf(source) + 1, 0, {
      ...structuredClone(source),
      name: as,
      ...(source.log ? { log: `${as}.log` } : {}),
      ...change,
    });
  };
  // The two-slot list of a newer gate, and the same list as a Node 24 gate with a distinct
  // configured Node 24 executable records it.
  const twoSlot = [...requiredStages];
  twoSlot.splice(
    twoSlot.indexOf('full-tests-current-runtime') + 1,
    0,
    'full-tests-minimum-runtime'
  );
  // Options of a run on a gate whose own Node is Node 26: both slots, each identified.
  const node26 = (change = () => {}) => {
    const files = {};
    return {
      files,
      record: record => {
        record.host.node = 'v26.5.1';
        Object.assign(files, helpers.maintenanceRuntime(record, now));
        change(record, files);
      },
    };
  };
  // Options of a run on a gate whose own Node is Node 24, with its configured Node 24 slot on a
  // second, distinct Node 24 executable (`version`: the same version as the gate's, or another).
  const distinct24 = (version, change = () => {}) => {
    const files = {};
    return {
      files,
      record: record => {
        Object.assign(files, helpers.distinctNode24Slot(record, now, { version }));
        change(record, files);
      },
    };
  };
  return {
    root,
    platform,
    finalization,
    helpers,
    current,
    now,
    write,
    early,
    stage,
    extra,
    twoSlot,
    node26,
    distinct24,
  };
}

test('GDR7-FIN-01: one approved B35 plan binds each stage to its execution class; an executed stage outside it, a command on a record-only stage and an unbound test execution are refused, by inspectRun and by the early B35 return', async t => {
  const m = await maintenanceRuns(t, 'gdr7-plan');
  const { platform, current, now, write, early, stage, extra, twoSlot } = m;
  // The plan: requiredStages is its `always` part, the same names in the same order as r7's list;
  // each stage has one class; the configured Node 24 slot, the lint stages and two informational
  // records are its only other names.
  const plan = platform.MAINTENANCE_PLAN;
  assert.ok(Array.isArray(plan) && Object.isFrozen(plan), 'MAINTENANCE_PLAN is a frozen list');
  assert.deepEqual(requiredStages, R7_REQUIRED_STAGES);
  assert.deepEqual(
    plan.filter(entry => entry.required === 'always').map(entry => entry.name),
    R7_REQUIRED_STAGES
  );
  assert.equal(new Set(plan.map(entry => entry.name)).size, plan.length);
  const classOf = Object.fromEntries(plan.map(entry => [entry.name, entry.execution]));
  for (const name of R7_REQUIRED_STAGES)
    assert.equal(
      classOf[name],
      name.startsWith('full-tests-') ? 'test' : requirements.has(name) ? 'record' : 'execute',
      name
    );
  assert.deepEqual(
    plan
      .filter(entry => entry.required !== 'always')
      .map(({ name, execution, required, slot }) => [name, execution, required, slot]),
    [
      ['full-tests-minimum-runtime', 'test', 'newer-node', 'minimum-runtime'],
      ['sql-lint', 'lint', 'named', undefined],
      ['import-lint', 'lint', 'named', undefined],
      ['gate-implementation', 'record', 'optional', undefined],
      ['platform-manifest', 'record', 'optional', undefined],
    ]
  );
  assert.deepEqual(
    plan.filter(entry => entry.execution === 'test').map(entry => [entry.name, entry.slot]),
    [
      ['full-tests-current-runtime', 'current-runtime'],
      ['full-tests-minimum-runtime', 'minimum-runtime'],
    ]
  );
  // What the plan requires of a run: the configured Node 24 slot only of a gate not on Node 24,
  // and a lint stage only when the caller names it.
  const required = (node, lintStages) =>
    platform.maintenanceRequiredStages({ host: { node } }, lintStages);
  assert.deepEqual(required('v24.21.0'), R7_REQUIRED_STAGES);
  assert.deepEqual(required('v26.5.1'), twoSlot);
  assert.deepEqual(required('v24.21.0', ['sql-lint']), [...R7_REQUIRED_STAGES, 'sql-lint']);
  assert.deepEqual(required(undefined), twoSlot);

  // The legitimate maintenance runs stay eligible, and their evidence passes every shared check.
  const valid = [
    ['one slot on a Node 24 gate', write(requiredStages)],
    ['two slots on a Node 26 gate', write(twoSlot, m.node26())],
    [
      'two distinct Node 24 executables of one version on a Node 24 gate',
      write(twoSlot, m.distinct24('v24.21.0')),
    ],
    [
      'two distinct Node 24 executables of two versions on a Node 24 gate',
      write(twoSlot, m.distinct24('v24.20.0')),
    ],
    [
      'the lint stages, which the plan permits as executed stages',
      write([...requiredStages, ...lintStageNames]),
      lintStageNames,
    ],
    [
      'the two informational records, passed without a command',
      write([...requiredStages, 'gate-implementation', 'platform-manifest']),
    ],
  ];
  for (const [label, run, lintStages] of valid) {
    assert.deepEqual(inspectRun(run, { ...current, lintStages }, now).blockers, [], label);
    assert.doesNotThrow(early(run), label);
    const sealed = m.finalization.readSealedRun(run);
    assert.deepEqual(platform.maintenancePlanProblems(sealed.record), [], label);
    assert.deepEqual(
      platform.maintenanceEvidenceProblems(sealed, { lintStages: lintStages ?? [] }),
      [],
      label
    );
  }
  // Two distinct Node 24 executables: runtime-identity lists both binaries.
  const distinct = m.finalization.readSealedRun(valid[2][1]).record;
  assert.equal(stage(distinct, 'runtime-identity').runtimes.length, 2);
  assert.notEqual(
    stage(distinct, 'full-tests-current-runtime').runtime.sha256,
    stage(distinct, 'full-tests-minimum-runtime').runtime.sha256
  );
  // A withheld test stage is of its class, and needs no identity: the run is refused only as
  // pending, as before.
  const withheld = write(twoSlot, {
    record: record => {
      const item = stage(record, 'full-tests-minimum-runtime');
      for (const key of Object.keys(item))
        if (!['name', 'started', 'finished'].includes(key)) delete item[key];
      Object.assign(item, { status: 'pending', reason: 'withheld before dispatch: synthetic' });
    },
  });
  const withheldSealed = m.finalization.readSealedRun(withheld);
  assert.deepEqual(platform.maintenancePlanProblems(withheldSealed.record), []);
  assert.deepEqual(platform.maintenanceRuntimeProblems(withheldSealed), []);
  assert.deepEqual(inspectRun(withheld, current, now).blockers, [
    'A required stage is pending: full-tests-minimum-runtime',
  ]);

  // Each refused shape: [label, stages, writeRun options, problem]. Every other input passes.
  const unidentified = {
    path: '/synthetic/unidentified/node',
    version: 'v26.5.1',
    sha256: 'f'.repeat(64),
  };
  const recordOnly = R7_REQUIRED_STAGES.filter(name => requirements.has(name));
  const cases = [
    // The security review's probe: an executed platform-tests-* stage on a binary runtime-identity does not list.
    [
      'an executed platform-tests-current-runtime on an unidentified binary',
      requiredStages,
      {
        record: r =>
          extra(r, 'full-tests-current-runtime', 'platform-tests-current-runtime', {
            runtime: unidentified,
          }),
      },
      /platform-tests-current-runtime is not a test stage of a maintenance run: the approved B35 plan has no such test slot/,
    ],
    // The same stage on the binary runtime-identity does list: still no approved slot.
    [
      'an executed platform-tests-current-runtime on an identified binary',
      requiredStages,
      { record: r => extra(r, 'full-tests-current-runtime', 'platform-tests-current-runtime') },
      /platform-tests-current-runtime is not a test stage of a maintenance run/,
    ],
    [
      'an executed full-tests-other-runtime',
      requiredStages,
      { record: r => extra(r, 'full-tests-current-runtime', 'full-tests-other-runtime') },
      /full-tests-other-runtime is not a test stage of a maintenance run/,
    ],
    // An arbitrary unique executed stage: a passing command with a sealed safe-name log, exit 0.
    [
      'an arbitrary executed stage',
      requiredStages,
      { record: r => extra(r, 'format', 'synthetic-extra-step') },
      /synthetic-extra-step is an executed stage outside the approved B35 plan \(it carries command, log, exit, signal\): no maintenance run may execute it/,
    ],
    [
      'an arbitrary executed stage that ran tests on an unidentified binary',
      requiredStages,
      {
        record: r =>
          extra(r, 'full-tests-current-runtime', 'synthetic-extra-tests', {
            runtime: unidentified,
          }),
      },
      /synthetic-extra-tests is not a test stage of a maintenance run/,
    ],
    [
      'a record outside the plan, passed without a command',
      requiredStages,
      { record: r => extra(r, 'candidate-policy', 'synthetic-unlisted-record') },
      /synthetic-unlisted-record is not a stage of the approved B35 plan/,
    ],
    [
      'an executed stage of the plan recorded twice',
      requiredStages,
      { record: r => extra(r, 'format', 'format', { log: 'format-again.log' }) },
      /format is recorded 2 times: the approved B35 plan has it once/,
    ],
    [
      'test totals and a runtime on an execute stage',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'format'), {
            tests: { tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0 },
            runtime: unidentified,
          }),
      },
      /format is not a test stage of a maintenance run|format is of the execution class execute in the approved B35 plan, not a test slot/,
    ],
    // The security review's inline probe, and each other record-only stage: a command under its name.
    ...recordOnly.map(name => [
      `a command on the record-only ${name}`,
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, name), {
            command: ['synthetic-fixture'],
            exit: 0,
            signal: null,
            log: `${name}.log`,
          }),
        logs: { [name]: 'Synthetic completed command\n' },
      },
      new RegExp(
        `${name} is a record-only stage of the approved B35 plan, but it carries command, log, exit, signal: nothing may execute under its name`
      ),
    ]),
    [
      'a command on an informational record',
      [...requiredStages, 'platform-manifest'],
      {
        record: r =>
          Object.assign(stage(r, 'platform-manifest'), {
            command: ['synthetic-fixture'],
            exit: 0,
            log: 'platform-manifest.log',
          }),
        logs: { 'platform-manifest': 'Synthetic completed command\n' },
      },
      /platform-manifest is a record-only stage of the approved B35 plan, but it carries command, log, exit/,
    ],
  ];
  for (const [label, stages, options, problem] of cases) {
    const run = write(stages, options);
    const inventory = inspectRun(run, current, now);
    assert.equal(inventory.eligible, false, label);
    assert.match(
      inventory.blockers[0] ?? '',
      /^Maintenance \(B35\) (?:host and runtime evidence|execution plan): /,
      label
    );
    assert.match(inventory.blockers[0], problem, `${label}: ${inventory.blockers[0]}`);
    assert.throws(early(run), problem, label);
    assert.match(
      platform.maintenanceEvidenceProblems(m.finalization.readSealedRun(run), noLint).join('\n'),
      problem,
      label
    );
  }
  assert.ok(cases.length >= 18, String(cases.length));
  // The plan check by itself also names test evidence on a stage that is no test slot, and a
  // stage record without a name.
  assert.match(
    platform
      .maintenancePlanProblems({
        stages: [
          { name: 'format', command: ['synthetic-fixture'], tests: totals },
          { status: 'pass' },
        ],
      })
      .join('\n'),
    /format is of the execution class execute in the approved B35 plan, not a test slot, but it carries tests: no test execution may run under its name[\s\S]*a stage record has no name/
  );
});

// gate-draft-r8, round 2 (GDR7-FIN-01; the internal check of the eighth round): the plan and the
// runtime check read only a stage record's own members, so an execution recorded inside a stage's
// record escaped both: in `steps`, the 1.5 gate's composite form (prepared-inputs and sast-rules
// hold the step records they ran there), under a record-only stage, a test slot or an execute
// stage, as did a member no producer writes (`argv`, `exitCode`). Now each stage record holds only
// its class's record form and its own data, nothing shaped as a stage record is nested anywhere in
// it, and a nested test execution is no approved slot. The legitimate runs of the first round's
// test stay accepted (that test is unchanged), and so does a run with every member the forms permit.
/** A Node binary runtime-identity does not list. */
const unidentifiedRuntime = {
  path: '/synthetic/unidentified/node',
  version: 'v26.5.1',
  sha256: 'f'.repeat(64),
};
/** An executed step record, as a stage that ran its command records it, with its sealed log. */
const executedStep = (name, change = {}, at = new Date().toISOString()) => ({
  name,
  command: ['synthetic-fixture'],
  started: at,
  log: `${name}.nested.log`,
  finished: at,
  exit: 0,
  signal: null,
  status: 'pass',
  ...change,
});
/** The nested step's log, sealed with the run as the gate seals every log. */
const stepLog = name => ({ [`${name}.nested.log`]: tap });
test('GDR7-FIN-01, round 2: a maintenance stage record holds only its record form; an execution nested in its steps or anywhere in it, and a member no producer writes, are refused by inspectRun, the early B35 return and the shared check', async t => {
  const m = await maintenanceRuns(t, 'gdr7-forms');
  const { platform, current, now, write, early, stage, twoSlot } = m;
  // The record forms: every record its name, status, interval and reason or error; a command its
  // command, log, exit, signal and dispatch authority; a test slot also its test evidence.
  const forms = platform.MAINTENANCE_RECORD_FORMS;
  const base = ['name', 'status', 'started', 'finished', 'reason', 'error'];
  const command = [...base, 'command', 'log', 'exit', 'signal', 'authority'];
  assert.ok(Object.isFrozen(forms) && Object.values(forms).every(Object.isFrozen));
  assert.deepEqual(forms, {
    record: base,
    execute: command,
    lint: command,
    test: [...command, 'tests', 'records', 'platformRun', 'runtime', 'unexecuted'],
  });
  assert.deepEqual(
    new Set(platform.MAINTENANCE_PLAN.map(entry => entry.execution)),
    new Set(Object.keys(forms))
  );
  assert.ok(Object.isFrozen(platform.MAINTENANCE_STAGE_DATA));
  for (const [name, members] of Object.entries(platform.MAINTENANCE_STAGE_DATA)) {
    assert.ok(
      platform.MAINTENANCE_PLAN.some(entry => entry.name === name),
      `${name} is a stage of the plan`
    );
    assert.ok(Object.isFrozen(members), name);
  }

  // A run with every member the forms permit, as scripts/security-gate.mjs records them: a test
  // slot with its dispatch authority, its unexecuted tests, run code and sealed records, the gate
  // files and the platform judgment. Accepted by every check, on a Node 26 gate with two slots.
  const permitted = write(
    [...twoSlot, 'gate-implementation', 'platform-manifest'],
    m.node26((record, files) => {
      for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime']) {
        Object.assign(stage(record, name), {
          authority: [
            { purpose: 'test-image-builds', reference: 'synthetic', source: 'synthetic' },
          ],
          unexecuted: { count: 0, tests: [] },
          platformRun: '7'.repeat(64),
          records: `${name}.records.json`,
        });
        files[`${name}.records.json`] = '[]';
      }
      stage(record, 'gate-implementation').files = ['scripts/security-gate.mjs'];
      stage(record, 'platform-manifest').judgment = 'platform-judgment.json';
      files['platform-judgment.json'] = '{}';
    })
  );
  assert.deepEqual(inspectRun(permitted, current, now).blockers, []);
  assert.doesNotThrow(early(permitted));
  const permittedSealed = m.finalization.readSealedRun(permitted);
  assert.deepEqual(platform.maintenancePlanProblems(permittedSealed.record), []);
  assert.deepEqual(platform.maintenanceRuntimeProblems(permittedSealed), []);
  assert.deepEqual(platform.maintenanceEvidenceProblems(permittedSealed, noLint), []);

  // Each refused shape: [label, stages, writeRun options, the problem named first (the host and
  // runtime check reports before the plan check), the plan check's problem or null]. check-1's
  // N1 to N5 first; every other input passes.
  const testStep = name => executedStep(name, { tests: totals, runtime: unidentifiedRuntime });
  const nested = (name, step, where = 'steps') => ({
    record: r => {
      const item = stage(r, name);
      if (where === 'steps') item.steps = [step];
      else where(item, step);
    },
    files: stepLog(step.name),
  });
  const cases = [
    [
      'N1: record-only test-host carrying a nested executed test step on an unidentified binary',
      requiredStages,
      nested('test-host', testStep('platform-tests-current-runtime')),
      /host and runtime evidence: test-host holds a test execution at steps\[0\] \("platform-tests-current-runtime"\): no approved test slot of the B35 plan is nested/,
      /test-host carries "steps", which the record form of its class \(record\) in the approved B35 plan does not have: steps is the composite record form[\s\S]*test-host holds a stage record at steps\[0\] \("platform-tests-current-runtime"\): an execution recorded inside another stage's record is outside the approved B35 plan/,
    ],
    [
      'N2: record-only candidate-unchanged carrying a nested executed step',
      requiredStages,
      nested('candidate-unchanged', executedStep('synthetic-step')),
      /execution plan: candidate-unchanged carries "steps", which the record form of its class \(record\)[\s\S]*candidate-unchanged holds a stage record at steps\[0\] \("synthetic-step"\)/,
      /candidate-unchanged holds a stage record at steps\[0\] \("synthetic-step"\)/,
    ],
    [
      'N3: test slot carrying a nested second test execution on an unidentified binary',
      requiredStages,
      nested('full-tests-current-runtime', testStep('full-tests-current-runtime')),
      /host and runtime evidence: full-tests-current-runtime holds a test execution at steps\[0\] \("full-tests-current-runtime"\)/,
      /full-tests-current-runtime carries "steps", which the record form of its class \(test\)/,
    ],
    [
      'N4: execute-class format carrying a nested test execution on an unidentified binary',
      requiredStages,
      nested('format', testStep('synthetic-tests')),
      /host and runtime evidence: format holds a test execution at steps\[0\] \("synthetic-tests"\)/,
      /format carries "steps", which the record form of its class \(execute\)/,
    ],
    [
      'N5: record-only candidate-unchanged carrying unknown members argv and exitCode',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'candidate-unchanged'), {
            argv: ['synthetic-fixture'],
            exitCode: 0,
          }),
      },
      /execution plan: candidate-unchanged carries "argv", "exitCode", which the record form of its class \(record\) in the approved B35 plan does not have \(GDR7-FIN-01\)/,
      /candidate-unchanged carries "argv", "exitCode"/,
    ],
    [
      'a withheld test slot (pending, nothing ran at its own level) holding an executed test step',
      twoSlot,
      m.node26(record => {
        const item = stage(record, 'full-tests-minimum-runtime');
        for (const key of Object.keys(item))
          if (!['name', 'started', 'finished'].includes(key)) delete item[key];
        Object.assign(item, {
          status: 'pending',
          reason: 'withheld before dispatch: synthetic',
          steps: [testStep('full-tests-minimum-runtime')],
        });
      }),
      /host and runtime evidence: full-tests-minimum-runtime holds a test execution at steps\[0\]/,
      /full-tests-minimum-runtime carries "steps"/,
    ],
    [
      "an executed step nested in an allowed datum (test-host's host)",
      requiredStages,
      nested('test-host', executedStep('synthetic-probe'), (item, step) => {
        item.host.probe = step;
      }),
      /execution plan: test-host holds a stage record at host\.probe \("synthetic-probe"\)/,
      /test-host holds a stage record at host\.probe/,
    ],
    [
      "a test execution nested in an allowed list (runtime-identity's runtimes)",
      requiredStages,
      nested('runtime-identity', testStep('platform-tests-current-runtime'), (item, step) => {
        item.runtimes[0].steps = [step];
      }),
      /host and runtime evidence: runtime-identity holds a test execution at runtimes\[0\]\.steps\[0\]/,
      /runtime-identity holds a stage record at runtimes\[0\]\.steps\[0\]/,
    ],
    [
      'a T8 member on an execute stage',
      requiredStages,
      { record: r => (stage(r, 'format').images = [image]) },
      /execution plan: format carries "images", which the record form of its class \(execute\)/,
      /format carries "images"/,
    ],
    [
      'an unknown member on a test slot',
      requiredStages,
      { record: r => (stage(r, 'full-tests-current-runtime').argv = ['synthetic-fixture']) },
      /execution plan: full-tests-current-runtime carries "argv", which the record form of its class \(test\)/,
      /full-tests-current-runtime carries "argv"/,
    ],
    [
      'an empty steps list on an execute stage',
      requiredStages,
      { record: r => (stage(r, 'sast-rules-extract').steps = []) },
      /execution plan: sast-rules-extract carries "steps", which the record form of its class \(execute\) in the approved B35 plan does not have: steps is the composite record form/,
      /sast-rules-extract carries "steps"/,
    ],
    [
      'a stage record nesting more values than can be judged',
      requiredStages,
      { record: r => (stage(r, 'test-host').host.deep = Array.from({ length: 10001 }, () => 0)) },
      /execution plan: test-host nests more than 10000 values, too many to judge/,
      /test-host nests more than 10000 values/,
    ],
  ];
  for (const [label, stages, options, problem, planProblem] of cases) {
    const run = write(stages, options);
    const inventory = inspectRun(run, current, now);
    assert.equal(inventory.eligible, false, label);
    assert.match(
      inventory.blockers[0] ?? '',
      /^Maintenance \(B35\) (?:host and runtime evidence|execution plan): /,
      label
    );
    assert.match(inventory.blockers[0], problem, `${label}: ${inventory.blockers[0]}`);
    assert.throws(early(run), problem, label);
    const sealed = m.finalization.readSealedRun(run);
    assert.match(platform.maintenanceEvidenceProblems(sealed, noLint).join('\n'), problem, label);
    assert.match(platform.maintenancePlanProblems(sealed.record).join('\n'), planProblem, label);
  }
  // The plan check alone also names a nested stage record that has no name.
  assert.match(
    platform
      .maintenancePlanProblems({
        stages: [
          {
            ...executedStep('format'),
            log: 'format.log',
            authority: [{ purpose: 'synthetic', reference: 'x', source: 'x', exit: 0 }],
          },
        ],
      })
      .join('\n'),
    /format holds a stage record at authority\[0\]: an execution recorded inside another stage's record/
  );
});

// gate-draft-r8, GDR7-AUTH-01 (the security review of gate-draft-r7: a carried downstream-consumer
// defect; the maintainer's decision 2 of 20261018T051017695655Z): recordedApproval(), the reader behind
// --verify-commit and the reference-transaction hook, accepted a recorded maintenance (B35)
// approval of a run that validateFinalization refuses, such as a legacy run without test-host or
// runtime-identity. Now it applies the same moment-independent B35 plan and host and runtime
// checks again whenever a recorded approval would give authority: an approval recorded under
// earlier rules for a run the current rules refuse gives none, and its raw evidence is left as it
// is. A current valid one stays accepted, including two distinct Node 24 executables. The CLI and
// hook entry points are tested in test/security-parents.test.mjs. No Git is needed here.
test('GDR7-AUTH-01: recordedApproval gives no authority to a recorded maintenance approval of a run the current B35 rules refuse (legacy, missing, duplicate, stale or inapplicable identity, an extra executed stage), and keeps accepting a current valid one', async t => {
  const m = await maintenanceRuns(t, 'gdr7-auth');
  const { finalization, helpers, current, now, write, stage, extra, twoSlot } = m;
  const prerequisites = ['test-host', 'runtime-identity'];
  const legacyStages = requiredStages.filter(name => !prerequisites.includes(name));
  const identity = record => stage(record, 'runtime-identity');
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  // Each refused shape, finalized as an earlier finalizer and F would have recorded it.
  const cases = [
    [
      'legacy: neither prerequisite (the earlier gate list)',
      legacyStages,
      {},
      /host and runtime evidence: test-host is absent.*runtime-identity is absent/,
    ],
    [
      'legacy: no runtime-identity',
      requiredStages.filter(name => name !== 'runtime-identity'),
      {},
      /host and runtime evidence: runtime-identity is absent/,
    ],
    [
      'legacy: no test-host',
      requiredStages.filter(name => name !== 'test-host'),
      {},
      /host and runtime evidence: test-host is absent/,
    ],
    [
      'missing: runtime-identity identifies no runtime',
      requiredStages,
      { record: r => (identity(r).runtimes = []) },
      /runtime-identity identifies no runtime/,
    ],
    [
      'missing: the test binary is not identified',
      requiredStages,
      {
        record: r => (stage(r, 'full-tests-current-runtime').runtime.sha256 = 'b'.repeat(64)),
      },
      /full-tests-current-runtime: runtime-identity does not identify its Node binary/,
    ],
    [
      'missing: its identity record is not sealed',
      requiredStages,
      { record: r => (identity(r).runtimes[0].record = 'runtime-identity-missing.json') },
      /is not sealed with the run/,
    ],
    [
      'duplicate: runtime-identity recorded twice',
      requiredStages,
      { record: r => r.stages.splice(r.stages.indexOf(identity(r)), 0, { ...identity(r) }) },
      /runtime-identity is recorded 2 times, so it has no one result/,
    ],
    [
      'duplicate: a binary listed twice',
      requiredStages,
      { record: r => identity(r).runtimes.push({ ...identity(r).runtimes[0] }) },
      /runtime-identity lists the binary [0-9a-f]{64} twice/,
    ],
    [
      'stale: runtime-identity begun before the run',
      requiredStages,
      { record: r => (identity(r).started = new Date(now - 5000).toISOString()) },
      /runtime-identity has an interval outside its record's window/,
    ],
    [
      'stale: runtime-identity ending after the test stage started',
      requiredStages,
      { record: r => (identity(r).finished = r.finished) },
      /runtime-identity must end before full-tests-current-runtime starts/,
    ],
    [
      'inapplicable: test-host for another platform',
      requiredStages,
      { record: r => (stage(r, 'test-host').host.platform = 'darwin') },
      /test-host does not apply to this run/,
    ],
    [
      'inapplicable: an identity record for another platform',
      requiredStages,
      {
        files: {
          [`runtime-identity-${helpers.maintenanceBinary('v24.21.0')}.json`]: JSON.stringify(
            helpers.maintenanceRuntimeRecord({
              version: 'v24.21.0',
              sha256: helpers.maintenanceBinary('v24.21.0'),
              platform: 'darwin',
              arch: 'arm64',
              now,
            })
          ),
        },
      },
      /the runtime identity record is for "darwin"\/"arm64", not linux\/arm64/,
    ],
    [
      'inapplicable: the minimum slot on Node 26',
      twoSlot,
      {
        record: r => {
          const tests = stage(r, 'full-tests-minimum-runtime');
          tests.runtime = { ...stage(r, 'full-tests-current-runtime').runtime, version: 'v26.5.1' };
        },
      },
      /full-tests-minimum-runtime ran Node v26\.5\.1, not Node 24, its approved slot/,
    ],
    [
      'extra: an executed platform-tests-current-runtime on an unidentified binary',
      requiredStages,
      {
        record: r =>
          extra(r, 'full-tests-current-runtime', 'platform-tests-current-runtime', {
            runtime: { path: '/x', version: 'v26.5.1', sha256: 'f'.repeat(64) },
          }),
      },
      /platform-tests-current-runtime is not a test stage of a maintenance run/,
    ],
    [
      'extra: an arbitrary executed stage',
      requiredStages,
      { record: r => extra(r, 'format', 'synthetic-extra-step') },
      /execution plan: synthetic-extra-step is an executed stage outside the approved B35 plan/,
    ],
    [
      'extra: a command on the record-only test-host',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'test-host'), {
            command: ['synthetic-fixture'],
            exit: 0,
            log: 'test-host.log',
          }),
        logs: { 'test-host': 'Synthetic completed command\n' },
      },
      /execution plan: test-host is a record-only stage of the approved B35 plan, but it carries command, log, exit/,
    ],
    [
      'missing: the configured Node 24 slot of a Node 26 gate',
      requiredStages,
      m.node26(),
      /execution plan: full-tests-minimum-runtime is required of this run by the approved B35 plan and is missing/,
    ],
  ];
  for (const [label, stages, options, problem] of cases) {
    const run = write(stages, options);
    helpers.recordedFinalization(run, current, now);
    const files = [
      'result.json',
      'run-manifest.json',
      'finalization/approval.json',
      'finalization/review.json',
    ];
    const before = files.map(file => fs.readFileSync(path.join(run, file)));
    // The current finalizer and commit guard refuse it ...
    assert.throws(() => validateFinalization(run, current, now), /./, label);
    // ... and so does the recorded-approval reader now, naming why.
    assert.throws(
      () => finalization.recordedApproval(run, noLint),
      error => refusal.test(error.message) && problem.test(error.message),
      label
    );
    // Its raw evidence stays as it was: nothing is rewritten, removed or relabelled.
    assert.deepEqual(
      files.map(file => fs.readFileSync(path.join(run, file))),
      before,
      label
    );
  }
  assert.ok(cases.length >= 15, String(cases.length));
  // A current valid maintenance approval stays accepted, finalized by this tree and passed as F
  // would, for one slot, two slots on a newer gate and two distinct Node 24 executables.
  for (const [label, stages, options] of [
    ['one slot on a Node 24 gate', requiredStages, {}],
    ['two slots on a Node 26 gate', twoSlot, m.node26()],
    ['two distinct Node 24 executables of one version', twoSlot, m.distinct24('v24.21.0')],
    ['two distinct Node 24 executables of two versions', twoSlot, m.distinct24('v24.20.0')],
  ]) {
    const run = path.join(m.root, `${current.tree}-commit-valid-${label.length}-${stages.length}`);
    helpers.finalizedRun(run, current, stages, now, options);
    assert.equal(validateFinalization(run, current, now).status, 'pass', label);
    const recorded = finalization.recordedApproval(run, noLint);
    assert.equal(recorded.approval.status, 'pass', label);
    assert.match(recorded.approvalSha256, /^[0-9a-f]{64}$/, label);
    // The same valid run with a finalization recorded the earlier way is accepted too.
    const again = write(stages, options);
    helpers.recordedFinalization(again, current, now);
    assert.equal(finalization.recordedApproval(again, noLint).approval.status, 'pass', label);
  }
  // The checks it applies again are moment-independent: a valid maintenance run sealed and
  // approved 48 hours ago, which the commit guard would now refuse as stale, still verifies once
  // its commit exists (freshness is not asked again).
  const earlier = now - 48 * 3600000;
  const old = path.join(m.root, `${current.tree}-commit-valid-earlier`);
  writeRun(old, current, requiredStages, earlier);
  helpers.recordedFinalization(old, current, earlier);
  assert.throws(() => validateFinalization(old, current, now), /stale/);
  assert.equal(finalization.recordedApproval(old, noLint).approval.status, 'pass');
});

// gate-draft-r8, round 2 (GDR7-AUTH-01; the internal check of the eighth round): recordedApproval
// accepted a recorded maintenance approval of a run with an execution nested in a stage's record
// (check-1's AN1 to AN3), and of a run whose stage results the finalizer refuses (O2, a withheld
// test stage; O3, a failed one), since neither the plan check nor any check it applied read them.
// Now it applies the record forms with the plan, and the stage results checkRun requires that read
// only the sealed run. A current valid approval stays accepted, and so does one of a run whose
// scanner exited with its finding exit (its findings are the retained review's to dispose of).
test('GDR7-AUTH-01, round 2: recordedApproval gives no authority to a recorded maintenance approval of a run with a nested execution, a member no producer writes or stage results the finalizer refuses, and keeps accepting a current valid one', async t => {
  const m = await maintenanceRuns(t, 'gdr7-auth-r2');
  const { finalization, helpers, current, now, write, stage, twoSlot } = m;
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  const testStep = name => executedStep(name, { tests: totals, runtime: unidentifiedRuntime });
  const nested = (name, step) => ({
    record: r => (stage(r, name).steps = [step]),
    files: stepLog(step.name),
  });
  const cases = [
    [
      'AN1: record-only test-host carrying a nested executed test step on an unidentified binary',
      requiredStages,
      nested('test-host', testStep('platform-tests-current-runtime')),
      /host and runtime evidence: test-host holds a test execution at steps\[0\] \("platform-tests-current-runtime"\)[\s\S]*execution plan: test-host carries "steps"/,
    ],
    [
      'AN2: record-only candidate-unchanged carrying a nested executed step',
      requiredStages,
      nested('candidate-unchanged', executedStep('synthetic-step')),
      /execution plan: candidate-unchanged carries "steps"[\s\S]*execution plan: candidate-unchanged holds a stage record at steps\[0\] \("synthetic-step"\)/,
    ],
    [
      'AN3: test slot carrying a nested second test execution on an unidentified binary',
      requiredStages,
      nested('full-tests-current-runtime', testStep('full-tests-current-runtime')),
      /host and runtime evidence: full-tests-current-runtime holds a test execution at steps\[0\]/,
    ],
    [
      'N5: unknown members argv and exitCode on record-only candidate-unchanged',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'candidate-unchanged'), {
            argv: ['synthetic-fixture'],
            exitCode: 0,
          }),
      },
      /execution plan: candidate-unchanged carries "argv", "exitCode"/,
    ],
    [
      'O2: full-tests-current-runtime withheld (pending, nothing ran)',
      requiredStages,
      {
        record: r => {
          const item = stage(r, 'full-tests-current-runtime');
          for (const key of Object.keys(item))
            if (!['name', 'started', 'finished'].includes(key)) delete item[key];
          Object.assign(item, { status: 'pending', reason: 'withheld before dispatch: synthetic' });
        },
      },
      /stage results: full-tests-current-runtime is pending: a maintenance \(B35\) run has no pending stage/,
    ],
    [
      'O3: full-tests-current-runtime failed (exit 1)',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'full-tests-current-runtime'), { status: 'blocked', exit: 1 }),
      },
      /stage results: full-tests-current-runtime did not pass: its status is "blocked" and its exit 1/,
    ],
    [
      'a blocked execute stage',
      requiredStages,
      { record: r => Object.assign(stage(r, 'format'), { status: 'blocked', exit: 1 }) },
      /stage results: format did not pass: its status is "blocked" and its exit 1/,
    ],
    [
      'a stage that failed to execute',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'documentation'), { status: 'blocked', error: 'ENOENT' }),
      },
      /stage results: documentation failed to execute/,
    ],
    [
      'an execute stage without its command',
      requiredStages,
      {
        record: r => {
          const item = stage(r, 'syntax-manifest');
          for (const key of ['command', 'log', 'exit', 'signal']) delete item[key];
        },
      },
      /stage results: syntax-manifest is an executable stage of the approved B35 plan without its command/,
    ],
    [
      'a record-only stage that did not pass',
      requiredStages,
      { record: r => (stage(r, 'candidate-unchanged').status = 'blocked') },
      /stage results: candidate-unchanged did not pass: its status is "blocked"(?! and)/,
    ],
    [
      'a scanner that exited with neither 0 nor its finding exit',
      requiredStages,
      { record: r => Object.assign(stage(r, 'secrets-source'), { status: 'blocked', exit: 2 }) },
      /stage results: secrets-source exited 2, neither 0 nor its finding exit 10/,
    ],
    [
      "a test stage whose totals are not its sealed log's",
      requiredStages,
      {
        record: r =>
          (stage(r, 'full-tests-current-runtime').tests = { ...totals, tests: 2, pass: 2 }),
      },
      /stage results: full-tests-current-runtime's test totals are not those of its sealed log/,
    ],
    [
      'the configured Node 24 slot of a Node 26 gate failed',
      twoSlot,
      m.node26(record =>
        Object.assign(stage(record, 'full-tests-minimum-runtime'), { status: 'blocked', exit: 1 })
      ),
      /stage results: full-tests-minimum-runtime did not pass/,
    ],
  ];
  for (const [label, stages, options, problem] of cases) {
    const run = write(stages, options);
    helpers.recordedFinalization(run, current, now);
    const files = [
      'result.json',
      'run-manifest.json',
      'finalization/approval.json',
      'finalization/review.json',
    ];
    const before = files.map(file => fs.readFileSync(path.join(run, file)));
    // The current finalizer and commit guard refuse it ...
    assert.throws(() => validateFinalization(run, current, now), /./, label);
    // ... and so does the recorded-approval reader, naming why.
    assert.throws(
      () => finalization.recordedApproval(run, noLint),
      error => refusal.test(error.message) && problem.test(error.message),
      label
    );
    // Its raw evidence stays as it was.
    assert.deepEqual(
      files.map(file => fs.readFileSync(path.join(run, file))),
      before,
      label
    );
  }
  // Still accepted: a current valid approval, finalized by this tree and passed as F would; the
  // same run recorded the earlier way; a run with every member the record forms permit; and a run
  // whose scanner reported a real finding and exited with its finding exit (status blocked), with
  // one complete retained disposition of that finding. (gate-draft-r8 accepted here a scanner that
  // exited 10 over an empty report, which the finalizer refuses: GDR8-AUTH-SCAN-01. That shape is
  // now refused; see the GDR8-AUTH-SCAN-01 test below.)
  const valid = path.join(m.root, `${current.tree}-commit-valid-round-2`);
  helpers.finalizedRun(valid, current, twoSlot, now, m.node26());
  assert.equal(validateFinalization(valid, current, now).status, 'pass');
  assert.equal(finalization.recordedApproval(valid, noLint).approval.status, 'pass');
  for (const [label, stages, options, recorded = {}] of [
    ['one slot, recorded the earlier way', requiredStages, {}],
    [
      'every member the record forms permit',
      requiredStages,
      {
        record: r =>
          Object.assign(stage(r, 'full-tests-current-runtime'), {
            authority: [{ purpose: 'test-image-builds', reference: 'synthetic', source: 'x' }],
            unexecuted: { count: 0, tests: [] },
            platformRun: '7'.repeat(64),
          }),
      },
    ],
    [
      'a scanner with a real finding that exited with its finding exit, the finding disposed of',
      requiredStages,
      {
        record: r => Object.assign(stage(r, 'secrets-history'), { status: 'blocked', exit: 10 }),
        files: { 'secrets-history.json': JSON.stringify([helpers.historyFinding()]) },
      },
      { dispose: findings => findings },
    ],
  ]) {
    const run = write(stages, options);
    helpers.recordedFinalization(run, current, now, recorded);
    assert.equal(finalization.recordedApproval(run, noLint).approval.status, 'pass', label);
  }
});

// gate-draft-r9, GDR8-AUTH-SCAN-01 (the security review of gate-draft-r8, probe P2): the
// recorded-approval reader judged a scanner stage by its exit alone (0 or the finding exit) and
// trusted the approval's and the review's finding count, so a recorded maintenance approval of a
// run whose empty report contradicts a finding exit, which the finalizer refuses, gave authority.
// It now applies the finalizer's own sealed scanner-result judgment (scannerResult): the fixed
// report sealed and parsed, the findings derived from it, and report, findings, exit and status in
// agreement; and the derived finding set, not the claimed count, must be what the approval counts
// and what the retained review disposes of, one complete disposition each. Each case is refused by
// the finalizer (validateFinalization) and by the reader, naming why, with its evidence unchanged;
// the genuine positives stay accepted by both. The CLI and hook entry points are in
// test/security-parents.test.mjs. No Git is needed here.
test("GDR8-AUTH-SCAN-01: recordedApproval applies the finalizer's sealed scanner-result judgment and binds the derived finding set to the approval and the retained dispositions; a missing, malformed, empty or nonempty report that disagrees with its exit or status, or a disposition mismatch, gives no authority", async t => {
  const m = await maintenanceRuns(t, 'gdr8-scan');
  const { finalization, helpers, current, now, write, stage } = m;
  const maintenanceRefusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  const finding = helpers.historyFinding;
  const blocked = name => r => Object.assign(stage(r, name), { status: 'blocked', exit: 10 });
  const report = rows => ({ 'secrets-history.json': JSON.stringify(rows) });
  const semgrep = {
    'source-analysis.json': JSON.stringify({
      version: '1.176.0',
      results: [
        {
          check_id: 'synthetic-rule',
          path: 'example.mjs',
          start: { line: 1 },
          end: { line: 1 },
          extra: { severity: 'ERROR' },
        },
      ],
      errors: [],
      skipped_rules: [],
      paths: { scanned: ['example.mjs'] },
    }),
  };
  // [label, writeRun options, recordedFinalization options, the reader's problem]
  const cases = [
    [
      "P2 (the security review's probe, and gate-draft-r8's former positive): an empty report, the stage blocked with exit 10, no finding or disposition",
      { record: blocked('secrets-history') },
      {},
      /scanner results: secrets-history: Scanner exit and findings disagree/,
    ],
    [
      'a missing report: secrets-history.json not sealed',
      { omit: ['secrets-history.json'] },
      {},
      /scanner results: secrets-history: Scanner report is missing: secrets-history sealed no secrets-history\.json/,
    ],
    [
      'a malformed report',
      { files: { 'secrets-history.json': '{"not": "closed"' } },
      {},
      /scanner results: secrets-history: Cannot parse scanner report/,
    ],
    [
      'an empty (zero-byte) report, as the gate precreates it',
      { files: { 'secrets-history.json': '' } },
      {},
      /scanner results: secrets-history: Cannot parse scanner report/,
    ],
    [
      'a report of another shape (an object, not the Gitleaks list)',
      { files: { 'secrets-history.json': '{}' } },
      {},
      /scanner results: secrets-history: Incomplete or unsupported scanner report/,
    ],
    [
      'a nonempty report with exit 0 and status pass',
      { files: report([finding()]) },
      { dispose: findings => findings },
      /scanner results: secrets-history: Scanner exit and findings disagree/,
    ],
    [
      'a nonempty report with the finding exit but status pass',
      {
        record: r => Object.assign(stage(r, 'secrets-history'), { status: 'pass', exit: 10 }),
        files: report([finding()]),
      },
      { dispose: findings => findings },
      /scanner results: secrets-history: Scanner status and findings disagree: secrets-history is "pass" with 1 finding/,
    ],
    [
      'an empty report with exit 0 but status blocked',
      { record: r => Object.assign(stage(r, 'secrets-history'), { status: 'blocked', exit: 0 }) },
      {},
      /scanner results: secrets-history: Scanner status and findings disagree: secrets-history is "blocked" with 0 findings/,
    ],
    [
      "Semgrep's finding with Gitleaks' finding exit (10, not 1)",
      {
        record: r => Object.assign(stage(r, 'source-analysis'), { status: 'blocked', exit: 10 }),
        files: semgrep,
      },
      { dispose: findings => findings },
      /scanner results: source-analysis: Scanner exit and findings disagree/,
    ],
    [
      "an image report of another image than container-identity's",
      {
        files: {
          'container-security.json': JSON.stringify({
            SchemaVersion: 2,
            Trivy: { Version: tools.trivy },
            ArtifactID: `sha256:${'a'.repeat(64)}`,
            ArtifactName: 'synthetic:tag',
            Metadata: { ImageID: `sha256:${'b'.repeat(64)}` },
            Results: [
              { Target: 'synthetic OS', Class: 'os-pkgs', Vulnerabilities: [] },
              { Target: 'Node.js', Class: 'lang-pkgs', Vulnerabilities: [] },
              {
                Target: 'synthetic:tag',
                Class: 'config',
                MisconfSummary: { Successes: 1, Failures: 0 },
              },
            ],
          }),
        },
      },
      {},
      /scanner results: container-vulnerabilities: Image report does not match the inspected image and invocation/,
    ],
    [
      'a secret scan whose log does not show it completed',
      { logs: { 'secrets-history': 'ERR synthetic incomplete scan\n' } },
      {},
      /scanner results: secrets-history: Secret scan completion is not established/,
    ],
  ];
  // Binding cases: the scanner results agree, but the approval and the review do not dispose of
  // exactly the findings the sealed reports give.
  const bindings = [
    [
      'a real finding, the approval counting none and the review disposing of none',
      { record: blocked('secrets-history'), files: report([finding()]) },
      {},
      /The recorded approval counts 0 findings, but its sealed scanner reports give 1, so it gives no authority \(GDR8-AUTH-SCAN-01\)/,
    ],
    [
      'a real finding, its disposition naming another finding',
      { record: blocked('secrets-history'), files: report([finding()]) },
      { dispose: () => [{ id: '0'.repeat(64) }] },
      /The retained review does not dispose of exactly the findings the sealed scanner reports give, so the recorded approval gives no authority \(GDR8-AUTH-SCAN-01\): Unknown, duplicate or unsupported finding disposition/,
    ],
    [
      'two real findings, the first disposed of twice and the second not at all',
      { record: blocked('secrets-history'), files: report([finding(0), finding(1)]) },
      { dispose: findings => [findings[0], findings[0]] },
      /does not dispose of exactly the findings the sealed scanner reports give.*Unknown, duplicate or unsupported finding disposition/,
    ],
    [
      'a real finding disposed of as an accepted risk',
      { record: blocked('secrets-history'), files: report([finding()]) },
      {
        dispose: findings =>
          findings.map(item => ({ id: item.id, with: { status: 'accepted-risk' } })),
      },
      /does not dispose of exactly the findings the sealed scanner reports give.*Unknown, duplicate or unsupported finding disposition/,
    ],
    [
      'a clean report, the approval and the review claiming one finding',
      {},
      { dispose: () => [{ id: '0'.repeat(64) }] },
      /The recorded approval counts 1 finding, but its sealed scanner reports give 0/,
    ],
  ];
  for (const [label, options, recorded, problem] of [...cases, ...bindings]) {
    const run = write(requiredStages, options);
    helpers.recordedFinalization(run, current, now, recorded);
    const files = [
      'result.json',
      'run-manifest.json',
      'finalization/approval.json',
      'finalization/review.json',
    ];
    const before = files.map(file => fs.readFileSync(path.join(run, file)));
    // The finalizer and the commit guard refuse it ...
    assert.throws(() => validateFinalization(run, current, now), /./, label);
    // ... and so does the recorded-approval reader, naming why.
    assert.throws(
      () => finalization.recordedApproval(run, noLint),
      error =>
        problem.test(error.message) &&
        (cases.some(item => item[0] === label) ? maintenanceRefusal.test(error.message) : true),
      label
    );
    assert.deepEqual(
      files.map(file => fs.readFileSync(path.join(run, file))),
      before,
      label
    );
  }
  assert.ok(cases.length + bindings.length >= 16, String(cases.length + bindings.length));
  // Still accepted by the finalizer and by the reader: genuine findings, each scanner's finding
  // exit and status blocked, every finding with one complete retained disposition, recorded the
  // earlier way and finalized by this tree (passed as F would).
  for (const [label, options] of [
    [
      'one Gitleaks history finding',
      { record: blocked('secrets-history'), files: report([finding()]) },
    ],
    [
      'two Gitleaks history findings and a Semgrep finding (exit 1)',
      {
        record: r => {
          blocked('secrets-history')(r);
          Object.assign(stage(r, 'source-analysis'), { status: 'blocked', exit: 1 });
        },
        files: { ...report([finding(0), finding(1)]), ...semgrep },
      },
    ],
  ]) {
    const run = write(requiredStages, options);
    const approval = helpers.recordedFinalization(run, current, now, {
      dispose: findings => findings,
    });
    assert.ok(approval.findings >= 1, label);
    assert.equal(validateFinalization(run, current, now).status, 'pass', label);
    assert.equal(finalization.recordedApproval(run, noLint).approval.status, 'pass', label);
    const finalized = path.join(m.root, `${current.tree}-commit-finalized-${approval.findings}`);
    helpers.finalizedRun(finalized, current, requiredStages, now, { ...options, dispose: true });
    assert.equal(validateFinalization(finalized, current, now).findings, approval.findings, label);
    assert.equal(finalization.recordedApproval(finalized, noLint).approval.status, 'pass', label);
  }
});

// gate-draft-r9, GDR8-SCHEMA-01 (the security review of gate-draft-r8, probe P3; the maintainer's decision 3):
// the record forms closed only a maintenance stage record's own members, and what
// a permitted member held stayed open, so `test-host.host.probe = { argv, exitCode }` was accepted
// by every check (the probe showed invalid schema acceptance, not an execution of that object).
// Now each member's value has a closed schema at every depth (MAINTENANCE_MEMBER_SCHEMAS,
// MAINTENANCE_STAGE_DATA_SCHEMAS): an unknown scalar, object or list member nested anywhere, and a
// value of another shape, is refused whatever its spelling, by the finalizer (inspectRun, the early
// B35 return, the plan and shared checks) and by the recorded-approval reader. The exact producer
// forms stay accepted (test-host's host is exactly { platform, uid, setfacl }). This is a PROPOSED
// shared interface, not an accepted one; the maintenance producer must still be shown to match it.
test('GDR8-SCHEMA-01: every structured member of a maintenance stage record has a closed schema at every depth; an unknown nested member or another shape is refused by the finalizer and the recorded-approval reader, and the exact producer forms are accepted', async t => {
  const m = await maintenanceRuns(t, 'gdr8-schema');
  const { platform, finalization, helpers, current, now, write, early, stage, twoSlot } = m;
  const members = platform.MAINTENANCE_MEMBER_SCHEMAS;
  const data = platform.MAINTENANCE_STAGE_DATA_SCHEMAS;
  // The schema tables: frozen, one schema for every member of every record form, and the data
  // schemas of exactly the stages and members of MAINTENANCE_STAGE_DATA.
  assert.ok(Object.isFrozen(members) && Object.isFrozen(data));
  for (const [execution, form] of Object.entries(platform.MAINTENANCE_RECORD_FORMS))
    for (const member of form)
      assert.ok(Object.hasOwn(members, member), `${execution}: ${member} has a schema`);
  assert.deepEqual(
    Object.keys(members).sort(),
    [...new Set(Object.values(platform.MAINTENANCE_RECORD_FORMS).flat())].sort()
  );
  assert.deepEqual(
    Object.fromEntries(Object.entries(data).map(([name, schema]) => [name, Object.keys(schema)])),
    Object.fromEntries(
      Object.entries(platform.MAINTENANCE_STAGE_DATA).map(([name, list]) => [name, [...list]])
    )
  );
  for (const schema of [...Object.values(members), ...Object.values(data)])
    assert.ok(Object.isFrozen(schema));
  assert.deepEqual(Object.keys(data['test-host'].host.object), ['platform', 'uid', 'setfacl']);

  // The exact producer forms, accepted member by member: test-host's host on macOS and on Linux,
  // a pending Actionlint stage naming its missing pin (missingToolPin), a test slot as
  // startStage records it with its authority, unexecuted tests (a SKIP among them), totals, run
  // code and records, runtime-identity's runtimes and release keys, the gate files and the
  // platform judgment.
  const pin = platform.missingToolPin({
    tool: 'actionlint',
    version: '1.7.12',
    platform: 'darwin',
    arch: 'arm64',
  });
  for (const record of [
    { name: 'test-host', status: 'pass', host: { platform: 'darwin', uid: 1000, setfacl: null } },
    { name: 'test-host', status: 'pass', host: { platform: 'linux', uid: 1000, setfacl: true } },
    {
      name: 'test-host',
      status: 'blocked',
      error: 'x',
      host: { platform: 'linux', uid: 1000, setfacl: false },
    },
    { name: 'actionlint-version', status: 'pending', reason: 'x', missingPin: pin },
    { name: 'workflow-analysis', status: 'pending', reason: 'x', missingPin: pin },
    {
      name: 'full-tests-current-runtime',
      command: ['/synthetic/node', '--test'],
      started: new Date(now).toISOString(),
      log: '30-full-tests-current-runtime.log',
      runtime: { path: '/synthetic/node', version: 'v24.21.0', sha256: 'a'.repeat(64) },
      platformRun: '7'.repeat(64),
      authority: [{ purpose: 'test-image-builds', source: 'synthetic', reference: 'synthetic' }],
      finished: new Date(now).toISOString(),
      exit: 0,
      signal: null,
      status: 'pass',
      unexecuted: { count: 1, tests: [{ test: 'a skipped test', directive: 'SKIP', reason: '' }] },
      tests: totals,
      records: '30-full-tests-current-runtime.records.json',
    },
    {
      name: 'format',
      command: ['npm', 'run', 'format:check'],
      log: 'x.log',
      exit: null,
      signal: 'SIGKILL',
      status: 'blocked',
      error: 'ETIMEDOUT',
    },
    {
      name: 'runtime-identity',
      status: 'pass',
      runtimes: [
        { path: '/synthetic/node', version: 'v24.21.0', sha256: 'a'.repeat(64), record: 'r.json' },
      ],
      releaseKeys: 'runtime-release-keys.json',
    },
    { name: 'gate-implementation', status: 'pass', files: ['scripts/security-gate.mjs'] },
    {
      name: 'platform-manifest',
      status: 'pass',
      judgment: 'platform-judgment.json',
      dispositions: 'coverage-dispositions.json',
    },
  ])
    assert.deepEqual(platform.maintenanceStageSchemaProblems(record), [], record.name);

  // Each refused shape, on an otherwise valid run: [label, writeRun options, problem]. Every
  // other input passes; none trips the host and runtime check, so the plan check names it first.
  const alias = { argv: ['node', '--test'], exitCode: 0 };
  const cases = [
    [
      "P3 (the security review's probe): test-host.host.probe = { argv, exitCode }",
      { record: r => (stage(r, 'test-host').host.probe = alias) },
      /test-host\.host holds "probe", which its closed schema does not have \(GDR8-SCHEMA-01\)/,
    ],
    [
      'the same alias two levels down, in a list: runtime-identity.runtimes[0].probe',
      { record: r => (stage(r, 'runtime-identity').runtimes[0].probe = alias) },
      /runtime-identity\.runtimes\[0\] holds "probe", which its closed schema does not have/,
    ],
    [
      'an alias of other names in a test slot: runtime.exec = { cmd, rc }',
      {
        record: r =>
          (stage(r, 'full-tests-current-runtime').runtime.exec = { cmd: ['node'], rc: 0 }),
      },
      /full-tests-current-runtime\.runtime holds "exec", which its closed schema does not have/,
    ],
    [
      'an unknown scalar: test-host.host.extra',
      { record: r => (stage(r, 'test-host').host.extra = 'synthetic') },
      /test-host\.host holds "extra"/,
    ],
    [
      'an unknown list: test-host.host.steps = []',
      { record: r => (stage(r, 'test-host').host.steps = []) },
      /test-host\.host holds "steps"/,
    ],
    [
      'a producer form left incomplete: test-host.host without setfacl',
      { record: r => delete stage(r, 'test-host').host.setfacl },
      /test-host\.host lacks setfacl, which its closed schema requires/,
    ],
    [
      'an unknown member of the totals',
      { record: r => (stage(r, 'full-tests-current-runtime').tests.argv = ['node']) },
      /full-tests-current-runtime\.tests holds "argv"/,
    ],
    [
      'an alias deep in the unexecuted tests',
      {
        record: r =>
          (stage(r, 'full-tests-current-runtime').unexecuted = {
            count: 1,
            tests: [{ test: 'x', directive: 'SKIP', reason: '', ...alias }],
          }),
      },
      /full-tests-current-runtime\.unexecuted\.tests\[0\] holds "argv"[\s\S]*holds "exitCode"/,
    ],
    [
      'an unknown member beside the unexecuted tests',
      {
        record: r =>
          (stage(r, 'full-tests-current-runtime').unexecuted = {
            count: 0,
            tests: [],
            probe: alias,
          }),
      },
      /full-tests-current-runtime\.unexecuted holds "probe"/,
    ],
    [
      'an authority with a member besides purpose, reference and source',
      {
        record: r =>
          (stage(r, 'format').authority = [
            { purpose: 'synthetic', reference: 'x', source: 'x', argv: ['node'] },
          ]),
      },
      /format\.authority\[0\] holds "argv"/,
    ],
    [
      "workflow-analysis's binary hashes with a third member",
      {
        record: r => (stage(r, 'workflow-analysis').binarySha256.during = 'f'.repeat(64)),
      },
      /workflow-analysis\.binarySha256 holds "during"/,
    ],
    [
      "actionlint-version's tool with an alias",
      { record: r => (stage(r, 'actionlint-version').tool.argv = ['actionlint']) },
      /actionlint-version\.tool holds "argv"/,
    ],
    [
      'an object where a gate file name belongs',
      {
        stages: [...requiredStages, 'gate-implementation'],
        record: r => (stage(r, 'gate-implementation').files = [alias]),
      },
      /gate-implementation\.files\[0\] is an object, not a string/,
    ],
    [
      'an object where the platform judgment file belongs',
      {
        stages: [...requiredStages, 'platform-manifest'],
        record: r => (stage(r, 'platform-manifest').judgment = alias),
      },
      /platform-manifest\.judgment is an object, not a string/,
    ],
    [
      "an execution description in a record-only stage's reason",
      { record: r => (stage(r, 'candidate-unchanged').reason = alias) },
      /candidate-unchanged\.reason is an object, not a string/,
    ],
    [
      'a command holding a list, and an exit that is text',
      {
        record: r =>
          Object.assign(stage(r, 'format'), { command: [['node', '--test']], exit: '0' }),
      },
      /format\.command\[0\] is a list, not a string[\s\S]*format\.exit is "0", not an integer or null/,
    ],
  ];
  for (const [label, { stages = requiredStages, ...options }, problem] of cases) {
    const run = write(stages, options);
    const inventory = inspectRun(run, current, now);
    assert.equal(inventory.eligible, false, label);
    assert.match(inventory.blockers[0] ?? '', /^Maintenance \(B35\) execution plan: /, label);
    assert.match(inventory.blockers[0], problem, `${label}: ${inventory.blockers[0]}`);
    assert.throws(early(run), problem, label);
    const sealed = finalization.readSealedRun(run);
    assert.match(platform.maintenancePlanProblems(sealed.record).join('\n'), problem, label);
    assert.match(platform.maintenanceEvidenceProblems(sealed, noLint).join('\n'), problem, label);
    // The recorded-approval reader refuses the earlier approval of it, with its evidence unchanged.
    helpers.recordedFinalization(run, current, now);
    const result = fs.readFileSync(path.join(run, 'result.json'));
    assert.throws(() => validateFinalization(run, current, now), /./, label);
    assert.throws(
      () => finalization.recordedApproval(run, noLint),
      error =>
        /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse/.test(
          error.message
        ) && problem.test(error.message),
      label
    );
    assert.deepEqual(fs.readFileSync(path.join(run, 'result.json')), result, label);
  }
  assert.ok(cases.length >= 15, String(cases.length));
  // A value of another shape in a member that the host and runtime check also reads is named by
  // both checks (the runtime check first in the early return): an execution description as
  // runtime-identity's release keys, a status outside the producers' three, a uid as text.
  const keys = write(requiredStages, {
    record: r => (stage(r, 'runtime-identity').releaseKeys = alias),
  });
  const keysSealed = finalization.readSealedRun(keys);
  assert.match(
    platform.maintenanceRuntimeProblems(keysSealed).join('\n'),
    /runtime-identity names reviewed release keys it did not seal/
  );
  assert.match(
    platform.maintenancePlanProblems(keysSealed.record).join('\n'),
    /runtime-identity\.releaseKeys is an object, not a string \(GDR8-SCHEMA-01\)/
  );
  assert.match(
    platform
      .maintenanceStageSchemaProblems({
        name: 'test-host',
        status: 'passed',
        host: { platform: 'linux', uid: '1000', setfacl: null },
      })
      .join('\n'),
    /test-host\.status is "passed", not one of "pass", "blocked", "pending"[\s\S]*test-host\.host\.uid is "1000", not an integer/
  );
  // The legitimate runs of the earlier rounds stay accepted, with every permitted member.
  for (const run of [write(requiredStages), write(twoSlot, m.node26())]) {
    assert.deepEqual(inspectRun(run, current, now).blockers, []);
    const sealed = finalization.readSealedRun(run);
    for (const item of sealed.record.stages)
      assert.deepEqual(platform.maintenanceStageSchemaProblems(item), [], item.name);
  }
});

// 1.5: the 1.5 finalizer names both lint stages, which every 1.5 commit run records, so it
// neither inspects as eligible nor finalizes a run that lacks one.
test('the 1.5 finalizer requires both lint stages', t => {
  if (gitSkip) return t.skip(gitSkip);
  for (const name of lintStageNames) {
    const f = fixture(t, x => {
      x.record.stages = x.record.stages.filter(s => s.name !== name);
    });
    const cli = (...args) =>
      spawnSync(
        process.execPath,
        [path.join(repository, 'scripts/finalize-security.mjs'), ...args],
        {
          cwd: f.root,
          encoding: 'utf8',
          timeout: 10000,
        }
      );
    const inspected = cli('inspect', f.run);
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.deepEqual(JSON.parse(inspected.stdout).blockers, ['A mandatory stage is missing'], name);
    const finalized = cli('finalize', f.run, f.reviewFile);
    assert.equal(finalized.status, 1, name);
    assert.match(finalized.stderr, /Security finalization blocked: A mandatory stage is missing/);
    assert.equal(fs.existsSync(path.join(f.run, 'finalization')), false, name);
  }
});

// 1.5: the commit guard derives the lint stages a candidate needs and requires them in the
// finalized run, so one finalized as the maintenance finalizer would (naming none) does not
// approve this 1.5-shaped candidate.
test('the hook refuses a finalized run without the lint stages its candidate needs', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, x => {
    x.record.stages = x.record.stages.filter(s => !lintStageNames.includes(s.name));
  });
  const { lintStages, ...maintenance } = f.current;
  assert.deepEqual(lintStages, lintStageNames);
  finalizeRun(f.run, f.reviewFile, maintenance, f.now);
  asIfFinalizedByF(f.run);
  assert.equal(validateFinalization(f.run, maintenance, f.now).status, 'pass');
  assert.throws(() => validateFinalization(f.run, f.current, f.now), /mandatory stage is missing/);
  const hook = spawnSync(
    process.execPath,
    [path.join(repository, 'scripts/check-security-approval.mjs')],
    { cwd: f.root, encoding: 'utf8' }
  );
  assert.equal(hook.status, 1, hook.stderr);
  assert.match(hook.stderr, /No fresh verified finalization/);
});

test('a blocked dependency still exposes the independently readable finding queue', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, x => {
    x.record.stages.find(s => s.name === 'dependencies-all').exit = 1;
  });
  assert.equal(f.inventory.eligible, false);
  assert.equal(f.inventory.findings.length, 1);
});

for (const [name, change] of Object.entries({
  'unknown finding': r => {
    r.dispositions[0].id = '0'.repeat(64);
  },
  'missing finding': r => {
    r.dispositions = [];
  },
  'duplicate disposition': r => {
    r.dispositions.push(r.dispositions[0]);
  },
  'risk acceptance': r => {
    r.dispositions[0].status = 'accepted-risk';
  },
  'blank reason': r => {
    r.dispositions[0].reason = ' ';
  },
  'blank reviewer': r => {
    r.dispositions[0].reviewer = '';
  },
  'invented evidence digest': r => {
    r.dispositions[0].evidenceSha256 = '0'.repeat(64);
  },
  'missing evidence': r => {
    r.dispositions[0].evidenceFile += '.missing';
  },
  'wrong report binding': r => {
    r.runSha256 = '0'.repeat(64);
  },
  'wrong tool binding': r => {
    r.toolsSha256 = '0'.repeat(64);
  },
  'wrong refs binding': r => {
    r.refsSha256 = '0'.repeat(64);
  },
  'expired review': r => {
    r.expiresAt = '2000-01-01';
  },
  'future review': r => {
    r.reviewedAt = '2100-01-01';
  },
  'missing document review': r => {
    r.documents = {};
  },
  'unresolved independent issue': r => {
    r.unresolved = ['synthetic unresolved issue'];
  },
}))
  test(`review rejects ${name}`, t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t);
    change(f.review);
    f.save();
    assert.throws(() => finalizeRun(f.run, f.reviewFile, f.current, f.now));
  });

for (const file of [
  'result.json',
  'secrets-source.json',
  'full-tests-current-runtime.log',
  'source-manifest.json',
  'tool-config.json',
])
  test(`hook rejects modified sealed ${file}`, t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t);
    finalizeRun(f.run, f.reviewFile, f.current, f.now);
    fs.appendFileSync(path.join(f.run, file), ' ');
    assert.throws(() => validateFinalization(f.run, f.current, f.now), /Run evidence changed/);
  });

test('hook rejects changed supporting evidence, review, stale run and source identities', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  finalizeRun(f.run, f.reviewFile, f.current, f.now);
  asIfFinalizedByF(f.run);
  for (const key of ['tree', 'refs'])
    assert.throws(() => validateFinalization(f.run, { ...f.current, [key]: 'changed' }, f.now));
  // The complete ordered parent vector, not HEAD alone: another or an added parent is refused.
  for (const parents of [['e'.repeat(40)], [...f.current.parents, 'e'.repeat(40)]])
    assert.throws(
      () => validateFinalization(f.run, { ...f.current, parents }, f.now),
      /complete ordered parent vector/
    );
  assert.throws(() => validateFinalization(f.run, f.current, f.now + 25 * 60 * 60 * 1000), /stale/);
  assert.throws(
    () => validateFinalization(f.run, { ...f.current, files: [] }, f.now),
    /files changed/
  );
  const evidence = path.join(
    f.run,
    'finalization',
    `${f.review.dispositions[0].evidenceSha256}.evidence`
  );
  fs.appendFileSync(evidence, 'changed');
  assert.throws(() => validateFinalization(f.run, f.current, f.now), /evidence digest/);
});

test('currentCandidate refuses unstaged tracked byte changes', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  fs.appendFileSync(path.join(f.root, 'example.mjs'), '// changed\n');
  assert.throws(() => currentCandidate(f.root), /differs from the index/);
});

test('private evidence readers refuse public files, symlinks, FIFOs and oversized files', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t),
    p = path.join(f.root, 'unsafe');
  f.write(p, 'x');
  fs.chmodSync(p, 0o644);
  assert.throws(() => readEvidence(p));
  fs.unlinkSync(p);
  fs.symlinkSync(f.supporting, p);
  assert.throws(() => readEvidence(p));
  fs.unlinkSync(p);
  execFileSync('mkfifo', [p]);
  assert.throws(() => readEvidence(p));
  fs.unlinkSync(p);
  const fd = fs.openSync(p, 'wx', 0o600);
  fs.ftruncateSync(fd, 64 * 1024 * 1024 + 1);
  fs.closeSync(fd);
  assert.throws(() => readEvidence(p));
});

test('finding identity changes with raw location, history commit, package or report context', () => {
  const files = [{ file: 'example.mjs' }];
  const row = {
    RuleID: 'synthetic',
    File: 'example.mjs',
    StartLine: 1,
    EndLine: 1,
    Fingerprint: 'synthetic',
    Commit: 'a'.repeat(40),
  };
  const parse = rows =>
    reportFindings('secrets-history', Buffer.from(JSON.stringify(rows)), { tools, files });
  const original = parse([row])[0].id;
  for (const changed of [
    { ...row, StartLine: 2, EndLine: 2 },
    { ...row, Commit: 'b'.repeat(40) },
    { ...row, File: 'other.mjs' },
  ])
    assert.notEqual(parse([changed])[0].id, original);
  assert.notEqual(parse([row, row])[0].id, original);
  assert.notEqual(parse([row, row])[0].id, parse([row, row])[1].id);
});

test('a vulnerability database published and downloaded during the run is fresh', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, x => {
    const database = JSON.parse(x.logs['scanner-database.log']);
    const started = Date.parse(x.record.started);
    database.VulnerabilityDB.UpdatedAt = new Date(started + 100).toISOString();
    database.VulnerabilityDB.DownloadedAt = new Date(started + 200).toISOString();
    x.logs['scanner-database.log'] = JSON.stringify(database);
  });
  assert.equal(f.inventory.eligible, true, f.inventory.blockers.join('; '));
  // Pending only for the F obligation of its pinned Actionlint (maintainer decision 8).
  const finalized = finalizeRun(f.run, f.reviewFile, f.current, f.now);
  assert.equal(finalized.status, 'pending');
  assert.deepEqual(finalized.obligations, { 'actionlint-pin': 'pending' });
  assert.equal(finalized.pending.length, 1);
});

test('exact Semgrep and image not-affected dispositions join the source finding', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, x => {
    x.reports['source-analysis.json'].results = [
      {
        check_id: 'synthetic-rule',
        path: 'test/canary.mjs',
        start: { line: 1 },
        end: { line: 1 },
        extra: { severity: 'ERROR' },
      },
    ];
    Object.assign(
      x.record.stages.find(s => s.name === 'source-analysis'),
      { exit: 1, status: 'blocked' }
    );
    x.reports['container-security.json'].Results[0].Vulnerabilities = [
      {
        VulnerabilityID: 'CVE-SYNTHETIC',
        PkgName: 'fixture',
        InstalledVersion: '1',
        FixedVersion: '2',
        Severity: 'HIGH',
      },
    ];
    Object.assign(
      x.record.stages.find(s => s.name === 'container-vulnerabilities'),
      { exit: 10, status: 'blocked' }
    );
  });
  assert.equal(f.inventory.findings.length, 3);
  f.review.dispositions[2].status = 'not-affected';
  f.save();
  assert.equal(finalizeRun(f.run, f.reviewFile, f.current, f.now).findings, 3);
});

test('a clean complete run still needs independent review and can finalize without dispositions', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, x => {
    x.reports['secrets-source.json'] = [];
    Object.assign(
      x.record.stages.find(s => s.name === 'secrets-source'),
      { exit: 0, status: 'pass' }
    );
  });
  assert.equal(f.review.dispositions.length, 0);
  assert.equal(finalizeRun(f.run, f.reviewFile, f.current, f.now).findings, 0);
});

test('hook rejects modified retained review and missing sealed reports', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  finalizeRun(f.run, f.reviewFile, f.current, f.now);
  asIfFinalizedByF(f.run);
  const reviewPath = path.join(f.run, 'finalization/review.json');
  const original = fs.readFileSync(reviewPath);
  fs.appendFileSync(reviewPath, ' ');
  assert.throws(() => validateFinalization(f.run, f.current, f.now), /Finalization does not match/);
  fs.writeFileSync(reviewPath, original);
  fs.unlinkSync(path.join(f.run, 'secrets-history.json'));
  assert.throws(() => validateFinalization(f.run, f.current, f.now));
});

for (const flags of [[], ['--preserve-symlinks-main']]) {
  const mode = flags.length ? 'preserved' : 'resolved';
  test(`the ${mode} symlinked checker enforces its real decision`, t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t);
    const alias = path.join(f.root, 'linked-tools');
    fs.symlinkSync(path.join(repository, 'scripts'), alias, 'dir');
    const run = () =>
      spawnSync(process.execPath, [...flags, path.join(alias, 'check-security-approval.mjs')], {
        cwd: f.root,
        encoding: 'utf8',
        timeout: 10000,
      });
    const blocked = run();
    assert.equal(blocked.status, 1, 'an alias cannot silently skip the checker');
    assert.match(blocked.stderr, /No fresh verified finalization/);
    finalizeRun(f.run, f.reviewFile, f.current, f.now);
    // This module's finalization is pending (actionlint-pin; maintainer decision 8): still blocked.
    assert.equal(run().status, 1, 'a pending finalization does not approve through the alias');
    asIfFinalizedByF(f.run);
    const approved = run();
    assert.equal(approved.status, 0, approved.stderr);
    fs.appendFileSync(path.join(f.run, 'secrets-source.json'), ' ');
    assert.equal(run().status, 1, 'changed evidence still blocks through the alias');
  });
  test(`the ${mode} symlinked finalizer executes validation and inspection`, t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t);
    const alias = path.join(f.root, 'linked-tools');
    fs.symlinkSync(path.join(repository, 'scripts'), alias, 'dir');
    const run = (...args) =>
      spawnSync(process.execPath, [...flags, path.join(alias, 'finalize-security.mjs'), ...args], {
        cwd: f.root,
        encoding: 'utf8',
        timeout: 10000,
      });
    const invalid = run();
    assert.equal(invalid.status, 1, 'an alias cannot silently skip argument validation');
    assert.match(invalid.stderr, /Usage: node scripts\/finalize-security/);
    const inspected = run('inspect', f.run);
    assert.equal(inspected.status, 0, inspected.stderr);
    assert.equal(JSON.parse(inspected.stdout).tree, f.current.tree);
    // The finalizer writes a pending finalization (its F obligation actionlint-pin; maintainer
    // decision 8), says so and exits 1.
    const finalized = run('finalize', f.run, f.reviewFile);
    assert.equal(finalized.status, 1, finalized.stderr);
    assert.equal(JSON.parse(finalized.stdout).status, 'pending');
    assert.match(
      finalized.stderr,
      /Security finalization is pending, not pass: the commit guard will not accept it\. F obligation actionlint-pin/
    );
    asIfFinalizedByF(f.run);
    assert.equal(validateFinalization(f.run, f.current).status, 'pass');
  });
}

for (const script of ['check-security-approval.mjs', 'finalize-security.mjs']) {
  for (const mode of ['stdin', 'eval']) {
    test(`${script} stays inert when imported through ${mode} with a non-file argument`, () => {
      const code = `await import(${JSON.stringify(new URL(`../scripts/${script}`, import.meta.url).href)});`;
      const args =
        mode === 'stdin'
          ? ['--input-type=module', '-']
          : ['--input-type=module', '--eval', code, 'not-a-script-file'];
      const result = spawnSync(process.execPath, args, {
        cwd: repository,
        input: mode === 'stdin' ? code : undefined,
        encoding: 'utf8',
        timeout: 10000,
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, '');
    });
  }
}

// gate-draft-r9, round 2 (check-1 of gate-draft-r9, SCHEMA-INFO2; an example of the broad
// finalizer and authority-reader parity that stays a carried obligation): the finalizer reads a
// maintenance run's sealed coverage-dispositions.json (checkPlatformEvidence) and refuses one that
// is not the reviewed dispositions file bound to the candidate's tree and complete ordered parent
// vector, or that holds a disposition, since the history of a maintenance candidate never held the
// manifest and nothing can be lost; the recorded-approval reader accepted each of them. It now reads
// that file as the finalizer does (maintenanceCoverageProblems). One named example, not broad
// parity. A run without the file, or with a bound file that holds no disposition, stays accepted.
test("Finalizer and reader parity (a carried obligation), round 2 (check-1 SCHEMA-INFO2): recordedApproval reads a maintenance run's sealed coverage dispositions as the finalizer does", async t => {
  const m = await maintenanceRuns(t, 'gdr9-coverage');
  const { finalization, helpers, current, now, write } = m;
  const sealed = value => ({
    files: {
      'coverage-dispositions.json': typeof value === 'string' ? value : JSON.stringify(value),
    },
  });
  const bound = dispositions => ({
    schemaVersion: 2,
    tree: current.tree,
    parents: [...current.parents],
    dispositions,
  });
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): .*coverage dispositions: /;
  // [label, the sealed file, the finalizer's refusal, the reader's]
  for (const [label, value, finalizer, reader] of [
    [
      'not JSON',
      '{',
      /the coverage dispositions file is not JSON/,
      /coverage dispositions: the coverage dispositions file is not JSON/,
    ],
    [
      'a list, not the dispositions object',
      [],
      /the coverage dispositions file is not an object/,
      /coverage dispositions: the coverage dispositions file is not an object/,
    ],
    [
      'version 1, bound to a single parent',
      { schemaVersion: 1, tree: current.tree, parent: current.parents[0], dispositions: [] },
      /the coverage dispositions file is version 1, bound to a single parent/,
      /coverage dispositions: the coverage dispositions file is version 1, bound to a single parent/,
    ],
    [
      'bound to another tree',
      { ...bound([]), tree: 'f'.repeat(40) },
      /the coverage dispositions file is not bound to this candidate's tree and complete ordered parent vector/,
      /coverage dispositions: the coverage dispositions file is not bound to this candidate's tree/,
    ],
    [
      'an unknown member',
      { ...bound([]), argv: ['node', '--test'] },
      /the coverage dispositions file has the unknown field/,
      /coverage dispositions: the coverage dispositions file has the unknown field/,
    ],
    [
      'one disposition, which a maintenance candidate cannot use',
      bound([{ synthetic: true }]),
      /Platform coverage contract: dispositions were given, but no commit behind the candidate holds a manifest: nothing can be lost/,
      /coverage dispositions: the coverage dispositions file gives 1 disposition, but no commit behind a maintenance candidate holds a manifest: nothing can be lost/,
    ],
  ]) {
    const run = write(requiredStages, sealed(value));
    helpers.recordedFinalization(run, current, now);
    const files = [
      'result.json',
      'run-manifest.json',
      'coverage-dispositions.json',
      'finalization/approval.json',
      'finalization/review.json',
    ];
    const before = files.map(file => fs.readFileSync(path.join(run, file)));
    // The finalizer refuses it ...
    const inventory = inspectRun(run, current, now);
    assert.equal(inventory.eligible, false, label);
    assert.match(inventory.blockers[0], finalizer, label);
    assert.throws(() => validateFinalization(run, current, now), finalizer, label);
    // ... and so does the recorded-approval reader now, naming why.
    assert.throws(
      () => finalization.recordedApproval(run, noLint),
      error => refusal.test(error.message) && reader.test(error.message),
      label
    );
    assert.deepEqual(
      files.map(file => fs.readFileSync(path.join(run, file))),
      before,
      label
    );
  }
  // Still accepted by both: a run without the file, and one whose bound file holds no disposition.
  for (const [label, options] of [
    ['no coverage-dispositions.json', {}],
    ['a bound coverage-dispositions.json with no disposition', sealed(bound([]))],
  ]) {
    const run = write(requiredStages, options);
    helpers.recordedFinalization(run, current, now);
    assert.equal(inspectRun(run, current, now).eligible, true, label);
    assert.equal(validateFinalization(run, current, now).status, 'pass', label);
    assert.equal(finalization.recordedApproval(run, noLint).approval.status, 'pass', label);
  }
});

// gate-draft-r10, GDR9-HOST-SCHEMA-01 (review finding, Low/P3, integration-blocking; the maintainer's GATE
// decision 5; a PROPOSED shared interface, not an accepted one): parseRunRecord closed the run
// record's top-level members but checked only that `host` was an object, so host.probe = { argv,
// exitCode } (check-1's SCHEMA-INFO, the security review's P5) was accepted. The host is now one of two
// closed, typed variants, told apart by their exact member sets: the 1.5 gate's five members
// { platform, arch, release, node, uid } and the maintenance form; every member of a variant is
// required with its type, and anything else is refused, at the record reader every consumer uses
// (the finalizer, the commit guard and the recorded-approval reader read a sealed run through it).
// gate-draft-r11, GDR10-HOST-PRODUCER-01 (changed, following the maintainer's decision 073253 item 2): the
// maintenance form is the maintenance producer's own four members { platform, arch, release, node }
// (blob 40bc87be), not the three-member { node, platform, arch } that only synthetic fixtures
// wrote; those three are now refused like any other member set.
test('GDR9-HOST-SCHEMA-01: the run record host is one of two closed, typed producer forms, the 1.5 gate five members and the maintenance gate four; an unknown, nested or mistyped member is refused by parseRunRecord, the finalizer, the commit guard and the recorded-approval reader', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const finalization = await import('../scripts/security-finalization.mjs');
  const { parseRunRecord, runHostProblems, RUN_HOST_FORMS, recordedApproval } = finalization;
  assert.deepEqual(RUN_HOST_FORMS, {
    'gate-1.5': { platform: 'name', arch: 'name', release: 'text', node: 'node', uid: 'uid' },
    maintenance: { platform: 'name', arch: 'name', release: 'text', node: 'node' },
  });
  const four = { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0' };
  const five = {
    platform: 'darwin',
    arch: 'arm64',
    release: 'synthetic-27.0.0',
    node: 'v26.5.1',
    uid: 4242,
  };
  assert.deepEqual(runHostProblems(four), { variant: 'maintenance', problems: [] });
  assert.deepEqual(runHostProblems(five), { variant: 'gate-1.5', problems: [] });
  assert.deepEqual(runHostProblems({ ...five, uid: 0 }).problems, []);
  const f = fixture(t);
  const record = JSON.parse(fs.readFileSync(path.join(f.run, 'result.json'), 'utf8'));
  const parse = host => () => parseRunRecord(Buffer.from(JSON.stringify({ ...record, host })));
  for (const host of [four, five]) assert.doesNotThrow(parse(host), JSON.stringify(host));
  const closed =
    /run record's host is not one of its closed producer forms \(GDR9-HOST-SCHEMA-01\): /;
  for (const [label, host, problem] of [
    [
      "The security review's P5: host.probe = { argv, exitCode }",
      { ...four, probe: { argv: ['node', '--test'], exitCode: 0 } },
      /the host has the members \["arch", "node", "platform", "probe", "release"\], which are neither/,
    ],
    ['an unknown scalar member', { ...four, extra: 'x' }, /which are neither/],
    ['an unknown list member', { ...four, steps: [] }, /which are neither/],
    ['an unknown null member', { ...five, setfacl: null }, /which are neither/],
    [
      "the three members of gate-draft-r10's synthetic fixtures, which no producer writes",
      { node: 'v24.21.0', platform: 'linux', arch: 'arm64' },
      /the host has the members \["arch", "node", "platform"\], which are neither the 1\.5 gate's \[platform, arch, release, node, uid\] nor the maintenance gate's \[platform, arch, release, node\]/,
    ],
    ['two members, no arch', { node: 'v24.21.0', platform: 'linux' }, /which are neither/],
    [
      'the four members with release a number',
      { ...four, release: 6 },
      /host\.release is 6, not a nonempty printable string/,
    ],
    ['uid as text', { ...five, uid: '4242' }, /host\.uid is "4242", not a nonnegative integer/],
    ['a negative uid', { ...five, uid: -1 }, /host\.uid is -1, not a nonnegative integer/],
    ['a fractional uid', { ...five, uid: 1.5 }, /host\.uid is 1\.5, not a nonnegative integer/],
    ['node as a number', { ...four, node: 24 }, /host\.node is 24, not a Node version/],
    [
      'node not a version',
      { ...four, node: 'banana' },
      /host\.node is "banana", not a Node version/,
    ],
    [
      'platform an object',
      { ...four, platform: { name: 'linux' } },
      /host\.platform is \{"name":"linux"\}, not a platform or architecture name/,
    ],
    [
      'arch a list',
      { ...four, arch: ['arm64'] },
      /host\.arch is \["arm64"\], not a platform or architecture name/,
    ],
    [
      'release empty',
      { ...five, release: '' },
      /host\.release is "", not a nonempty printable string/,
    ],
    [
      'release an object',
      { ...five, release: { kernel: '6.0' } },
      /host\.release is \{"kernel":"6\.0"\}, not a nonempty printable string/,
    ],
    ['release over 256 characters', { ...five, release: 'r'.repeat(257) }, /host\.release is "r+/],
    ['release with a line break', { ...five, release: 'a\nb' }, /host\.release is "a\\nb"/],
    [
      'host a list',
      [four],
      /its parents, stages, host or candidate identity record is not of its form/,
    ],
  ])
    assert.throws(
      parse(host),
      error =>
        (closed.test(error.message) || /GDR4-02/.test(error.message)) &&
        problem.test(error.message),
      label
    );
  // The consumers of a sealed run: P5 sealed in the fixture's run, its review rebound to it.
  const rehost = host => {
    fs.chmodSync(path.join(f.run, 'result.json'), 0o600);
    fs.writeFileSync(path.join(f.run, 'result.json'), JSON.stringify({ ...record, host }), {
      mode: 0o600,
    });
    fs.rmSync(path.join(f.run, 'run-manifest.json'));
    sealRun(f.run);
  };
  // The 1.5 gate's form, with the fixture run's own platform, architecture and Node.
  rehost({
    platform: 'linux',
    arch: 'arm64',
    release: 'synthetic-6.0',
    node: 'v24.21.0',
    uid: 4242,
  });
  const inventory = inspectRun(f.run, f.current, f.now);
  assert.equal(inventory.eligible, true, inventory.blockers.join('; '));
  rehost({ ...four, probe: { argv: ['node', '--test'], exitCode: 0 } });
  assert.throws(() => inspectRun(f.run, f.current, f.now), closed);
  assert.throws(() => finalizeRun(f.run, f.reviewFile, f.current, f.now), closed);
  assert.throws(() => validateFinalization(f.run, f.current, f.now), closed);
  assert.throws(() => recordedApproval(f.run, noLint), closed);
});

// gate-draft-r10 round 2, GDR9-HOST-SCHEMA-01 (check-1: a mixed variant; the maintainer's GATE decision 5:
// each producer form "with their required fields"; a PROPOSED shared interface): the variant was
// chosen by its member set alone, so a contract record whose host had the maintenance form's three
// members was read, and the 1.5 form's release and uid were in effect optional for 1.5 records.
// The forms a record may carry now follow from its kind, by the producers that write it: a
// contract commit record and a companion record, which only the 1.5 gate writes, carry its five
// members; a maintenance commit record, which the 1.5 gate (for a B35 candidate) and the
// maintenance producer write, either form. gate-draft-r11 (GDR10-HOST-PRODUCER-01; changed,
// following the maintainer's decision 073253 item 2): the maintenance form is the maintenance gate's four
// members { platform, arch, release, node }.
test('GDR9-HOST-SCHEMA-01, round 2: the host form follows the record kind; a contract or companion record carries the 1.5 gate five members, a maintenance record either form', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const finalization = await import('../scripts/security-finalization.mjs');
  const { parseRunRecord, runHostProblems, RUN_HOST_FORMS_BY_RECORD } = finalization;
  assert.deepEqual(RUN_HOST_FORMS_BY_RECORD, {
    contract: ['gate-1.5'],
    platform: ['gate-1.5'],
    maintenance: ['gate-1.5', 'maintenance'],
  });
  const four = { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0' };
  const five = {
    platform: 'linux',
    arch: 'arm64',
    release: 'synthetic-6.0',
    node: 'v26.5.1',
    uid: 4242,
  };
  // Without a kind, every variant (as before); with one, only its forms.
  assert.deepEqual(runHostProblems(four).problems, []);
  assert.deepEqual(runHostProblems(four, { forms: ['gate-1.5'] }).variant, 'maintenance');
  assert.match(
    runHostProblems(four, { forms: ['gate-1.5'] }).problems[0],
    /^the host is the maintenance form \[platform, arch, release, node\], which this kind of record does not carry: it carries only the gate-1\.5 form \[platform, arch, release, node, uid\], every member required/
  );
  const f = fixture(t);
  const record = JSON.parse(fs.readFileSync(path.join(f.run, 'result.json'), 'utf8'));
  assert.deepEqual(record.candidate.platformManifest, { state: 'never-held' });
  const contract = {
    ...record,
    candidate: {
      ...record.candidate,
      platformManifest: { sha256: 'a'.repeat(64), state: 'valid' },
    },
    catalog: { mode: 'commit', profile: 'linux-full', sha256: 'b'.repeat(64) },
    platform: { kind: 'manifest', manifestSha256: 'a'.repeat(64) },
  };
  const companion = { ...contract, mode: 'platform', platformRun: 'darwin-platform' };
  const parse =
    (value, host, mode = 'commit') =>
    () =>
      parseRunRecord(Buffer.from(JSON.stringify({ ...value, host })), { mode });
  const mixed = what =>
    new RegExp(
      `run record's host is not one of its closed producer forms \\(GDR9-HOST-SCHEMA-01\\): the host is the maintenance form \\[platform, arch, release, node\\], which ${what}, which only the 1\\.5 gate writes, does not carry: it carries only the gate-1\\.5 form \\[platform, arch, release, node, uid\\]`
    );
  // A maintenance record: either form.
  for (const host of [four, five]) assert.doesNotThrow(parse(record, host), JSON.stringify(host));
  // A contract commit record and a companion record: the five members only.
  assert.doesNotThrow(parse(contract, five));
  assert.throws(
    parse(contract, four),
    mixed('a contract commit record \\(its candidate has the platform contract\\)')
  );
  assert.doesNotThrow(parse(companion, five, 'platform'));
  assert.throws(
    parse(companion, four, 'platform'),
    mixed('a companion \\(platform mode\\) record')
  );
  // The 1.5 form's members stay typed for each kind: a five-member host of the wrong types is
  // refused by its types, not by its kind.
  assert.throws(
    parse(contract, { ...five, uid: '4242' }),
    /host\.uid is "4242", not a nonnegative integer/
  );
  assert.throws(
    parse(companion, { ...five, release: '' }, 'platform'),
    /host\.release is "", not a nonempty printable string/
  );
});
