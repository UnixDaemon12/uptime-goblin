// Codex decision 8 of 2026-10-14: a missing reviewed Actionlint pin means pending AND a nonzero,
// blocking result. The gate names the missing pin and its evidence; nothing falls back to PATH, a
// download (latest or pinned), an observed hash, a local golden-tool record, an optional skip or
// continue-on-error; no finalization can pass until the qualified golden-tool manifest binds the
// exact path, version, digest, platform, provenance and dependency closure, which only F can
// establish (actionlint-pin). The gate-level cases (the run's exit, neither a recorded binary nor
// the PATH stand-in run, the other stages continuing) are in test/security-evidence.test.mjs.
// Every record here is synthetic; no Actionlint runs and nothing is downloaded.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const repositoryFile = name => fs.readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const load = async () => ({
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  catalog: await import('../scripts/security-catalog.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
  securityRun: await import('./helpers/security-run.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

const tools = JSON.parse(repositoryFile('scripts/security-tools.json'));

test('a missing pin names the tool, its version, the platform, the record and every piece of evidence it needs', async () => {
  const { platform } = await load();
  const missing = platform.missingToolPin({
    tool: 'actionlint',
    version: tools.actionlint,
    platform: 'linux',
    arch: 'arm64',
  });
  assert.deepEqual(
    { ...missing, evidence: undefined },
    {
      tool: 'actionlint',
      version: tools.actionlint,
      platform: 'linux',
      arch: 'arm64',
      record: 'actionlint-linux-arm64.json',
      evidence: undefined,
    }
  );
  assert.deepEqual(
    missing.evidence.map(item => item.split(':')[0]),
    [
      'path',
      'version',
      'sha256',
      'platform',
      'provenance',
      'dependencyClosure',
      'review',
      'binding',
    ]
  );
  assert.match(
    missing.evidence.at(-1),
    /qualified golden-tool manifest .*toolPinsSha256 and toolPaths/
  );
});

/** A Linux gate run with its companion, whose Actionlint stages `change` sets. */
async function scenario(t, change) {
  const modules = await load();
  const security = temporary(t, 'orbit-actionlint-pin-');
  const candidate = modules.fixture.platformCandidate();
  const now = Date.now();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { now, change: { record: change } });
  const companions = [modules.fixture.writeCompanion(security, candidate, { now })];
  const inspect = () =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions }, now);
  return { ...modules, inspect };
}
// Each replaced stage keeps its own recorded interval, so the run's order holds (v5 C23).
const unpinned = (r, missingPin, names = ['actionlint-version', 'workflow-analysis']) => {
  for (const name of names) {
    const index = r.stages.findIndex(x => x.name === name);
    const { started, finished } = r.stages[index];
    r.stages.splice(index, 1, {
      name,
      status: 'pending',
      reason: 'synthetic: no reviewed golden-tool record',
      ...(missingPin === undefined ? {} : { missingPin }),
      started,
      finished,
    });
  }
};

test('decision 8: a pending Actionlint stage must name the missing pin and its evidence; it stays pending and blocks', async t => {
  const { platform } = await load();
  const expected = r =>
    platform.missingToolPin({
      tool: 'actionlint',
      version: r.tools.actionlint,
      platform: r.host.platform,
      arch: r.host.arch,
    });
  // Named exactly: nothing local is wrong, and the verdict is pending, never pass.
  const named = await scenario(t, r => unpinned(r, expected(r)));
  const inventory = named.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.verdict, 'pending');
  assert.match(inventory.pending.join('\n'), /actionlint-version is pending/);
  assert.match(inventory.pending.join('\n'), /workflow-analysis is pending/);
  // A vague pending, or one naming another pin, is refused.
  for (const [label, change] of [
    ['no missingPin', r => unpinned(r)],
    ['another version', r => unpinned(r, { ...expected(r), version: '1.0.0' })],
    ['another platform', r => unpinned(r, { ...expected(r), platform: 'darwin' })],
    [
      'evidence left out',
      r => unpinned(r, { ...expected(r), evidence: expected(r).evidence.slice(0, 5) }),
    ],
    [
      'workflow-analysis naming nothing',
      r => {
        unpinned(r, expected(r));
        delete r.stages.find(x => x.name === 'workflow-analysis').missingPin;
      },
    ],
  ]) {
    const s = await scenario(t, change);
    assert.match(
      s.inspect().blockers.join('\n'),
      /a pending Actionlint stage does not name the missing pin and its evidence \(Codex decision 8\)/,
      label
    );
  }
});

test('decision 8: no reviewed pin means no maintenance (B35) pass either: a pending Actionlint stage is refused there', async t => {
  const { securityRun, finalization } = await load();
  const root = temporary(t, 'orbit-actionlint-b35-');
  const current = {
    tree: 'c'.repeat(40),
    parent: 'd'.repeat(40),
    parents: ['d'.repeat(40)],
    refs: `refs/heads/main ${'d'.repeat(40)}`,
    files: [
      {
        file: 'scripts/security-tools.json',
        mode: '100644',
        blob: '1'.repeat(40),
        sha256: sha(Buffer.from(repositoryFile('scripts/security-tools.json'))),
      },
    ],
  };
  const run = path.join(root, `${current.tree}-commit-b35`);
  securityRun.writeRun(run, current, securityRun.allStages, Date.now(), {
    pending: ['actionlint-version', 'workflow-analysis'],
  });
  const inventory = finalization.inspectRun(
    run,
    { ...current, platform: securityRun.maintenanceInputs(current) },
    Date.now()
  );
  assert.match(inventory.blockers.join('\n'), /A required stage is pending: actionlint-version/);
});

// verify-1 of gate-draft-r3: a golden-tool record is a local file that nothing authenticates, and
// with a well-formed one the maintenance (B35) path finalized `pass`. Codex decision 8: no
// finalization until the qualified golden-tool manifest binds the pin, and no self-authorising
// observed hash. This module has no qualified manifest, so a consistent pin leaves an F obligation
// (actionlint-pin) pending: its finalization is pending and the commit guard refuses it. Only a
// pass as F would write it, with exactly that obligation passed, is accepted (a stand-in: no F).
test('decision 8: a maintenance (B35) finalization with a well-formed golden-tool record is pending, never pass; only F can pass its actionlint-pin obligation', async t => {
  const { securityRun, finalization } = await load();
  const root = temporary(t, 'orbit-actionlint-b35-pin-');
  const entry = (file, bytes) => ({
    file,
    mode: '100644',
    blob: createHash('sha1')
      .update(`blob ${Buffer.byteLength(bytes)}\0`)
      .update(bytes)
      .digest('hex'),
    sha256: sha(bytes),
  });
  const current = {
    tree: 'c'.repeat(40),
    parent: 'd'.repeat(40),
    parents: ['d'.repeat(40)],
    refs: `refs/heads/main ${'d'.repeat(40)}`,
    files: [
      entry('Dockerfile', '# Synthetic fixture\n'),
      entry('example.mjs', 'export const synthetic = true;\n'),
      entry('scripts/security-tools.json', securityRun.securityTools),
    ],
  };
  const now = Date.now();
  const run = path.join(root, `${current.tree}-commit-b35`);
  const approval = securityRun.finalizedRun(run, current, securityRun.allStages, now, {
    byF: false,
  });
  assert.equal(approval.status, 'pending');
  assert.deepEqual(approval.obligations, { 'actionlint-pin': 'pending' });
  assert.deepEqual(finalization.maintenanceObligations, ['actionlint-pin']);
  assert.equal(approval.pending.length, 1);
  assert.match(
    approval.pending[0],
    /^F obligation actionlint-pin: the qualified golden-tool manifest .*local file that nothing here authenticates.*only F can establish the binding \(Codex decision 8; v4 C4, C7\)$/
  );
  const inputs = { ...current, platform: securityRun.maintenanceInputs(current) };
  assert.throws(
    () => finalization.validateFinalization(run, inputs, now),
    /Finalization is "pending", not pass: F obligation actionlint-pin/
  );
  assert.throws(
    () => finalization.recordedApproval(run, { lintStages: finalization.lintStageNames }),
    /Finalization is "pending"/
  );
  // As F would write it: accepted, by the guard and once the commit exists.
  securityRun.asIfFinalizedByF(run);
  const file = path.join(run, 'finalization', 'approval.json');
  const passed = fs.readFileSync(file, 'utf8');
  assert.equal(finalization.validateFinalization(run, inputs, now).status, 'pass');
  assert.equal(
    finalization.recordedApproval(run, { lintStages: finalization.lintStageNames }).approval.status,
    'pass'
  );
  // A pass without exactly that obligation passed is refused by both.
  for (const [label, change] of [
    ['no obligations', a => delete a.obligations],
    ['the obligation pending', a => (a.obligations = { 'actionlint-pin': 'pending' })],
    ['no obligation', a => (a.obligations = {})],
    [
      'another obligation besides',
      a => (a.obligations = { 'actionlint-pin': 'pass', 'review-approval': 'pass' }),
    ],
    ['the obligation as true', a => (a.obligations = { 'actionlint-pin': true })],
  ]) {
    const value = JSON.parse(passed);
    change(value);
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    assert.throws(
      () => finalization.validateFinalization(run, inputs, now),
      /a maintenance \(B35\) finalization needs its pinned Actionlint bound by the qualified golden-tool manifest/,
      label
    );
    assert.throws(
      () => finalization.recordedApproval(run, { lintStages: finalization.lintStageNames }),
      /exactly its one F obligation passed: the qualified binding of its pinned Actionlint/,
      label
    );
  }
  fs.writeFileSync(file, passed, { mode: 0o600 });
  assert.equal(finalization.validateFinalization(run, inputs, now).status, 'pass');
});

// The same for a candidate with the platform contract: a passing Actionlint is checked against
// its sealed record and then left pending (actionlint-version, workflow-analysis and the
// actionlint-pin item), and a recorded gate identity must name the pinned path as its
// toolPaths.actionlint.
test('decision 8: a passing Actionlint of a candidate with the platform contract stays pending here, and must be at the path its gate identity names', async t => {
  const control = await scenario(t, () => {});
  const inventory = control.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.verdict, 'pending');
  const pending = inventory.pending.join('\n');
  assert.match(pending, /actionlint-version is pending/);
  assert.match(pending, /workflow-analysis is pending/);
  assert.match(pending, /^actionlint-pin: the qualified golden-tool manifest/m);
  assert.equal(inventory.obligations['required-catalogs'].status, 'pending');
  const moved = await scenario(t, r => {
    r.stages.find(x => x.name === 'gate-identity').gateIdentity.toolPaths.actionlint =
      '/synthetic/elsewhere/actionlint';
  });
  assert.match(
    moved.inspect().blockers.join('\n'),
    /the pinned Actionlint \/synthetic\/golden\/actionlint is not at the path the run's gate identity names for it/
  );
});

test('decision 8: a golden-tool record binds the dependency closure; version 1 has none and is refused, with no fallback', async () => {
  const { platform, securityRun } = await load();
  const good = securityRun.goldenActionlint('linux', Date.now());
  const read = value =>
    platform.parseGoldenTool(Buffer.from(JSON.stringify(value)), {
      tool: 'actionlint',
      platform: 'linux',
      arch: 'arm64',
      version: tools.actionlint,
    });
  assert.equal(read(good).schemaVersion, 2);
  const withClosure = {
    ...good,
    dependencyClosure: [
      { path: '/synthetic/lib/a.so', sha256: 'a'.repeat(64) },
      { path: '/synthetic/lib/b.so', sha256: 'b'.repeat(64) },
    ],
  };
  assert.deepEqual(read(withClosure).dependencyClosure, withClosure.dependencyClosure);
  const { dependencyClosure: _none, ...version1 } = { ...good, schemaVersion: 1 };
  for (const [label, value, pattern] of [
    [
      'version 1',
      version1,
      /is version 1, which binds no dependency closure: no reader falls back to it/,
    ],
    ['version 1 with a closure', { ...good, schemaVersion: 1 }, /is version 1/],
    ['no closure', (({ dependencyClosure: _c, ...rest }) => rest)(good), /lacks dependencyClosure/],
    ['a closure that is not a list', { ...good, dependencyClosure: {} }, /not a list/],
    [
      'a relative closure file',
      { ...good, dependencyClosure: [{ path: 'lib/a.so', sha256: 'a'.repeat(64) }] },
      /absolute files other than the binary/,
    ],
    [
      'the binary in its own closure',
      { ...good, dependencyClosure: [{ path: good.path, sha256: good.sha256 }] },
      /other than the binary/,
    ],
    [
      'an unsorted closure',
      { ...withClosure, dependencyClosure: [...withClosure.dependencyClosure].reverse() },
      /sorted/,
    ],
    [
      'a repeated closure file',
      {
        ...withClosure,
        dependencyClosure: [withClosure.dependencyClosure[0], withClosure.dependencyClosure[0]],
      },
      /each once/,
    ],
    [
      'a closure file without a digest',
      { ...good, dependencyClosure: [{ path: '/synthetic/lib/a.so' }] },
      /lacks sha256/,
    ],
    [
      '65 closure files',
      {
        ...good,
        dependencyClosure: Array.from({ length: 65 }, (_, i) => ({
          path: `/synthetic/lib/${String(i).padStart(3, '0')}.so`,
          sha256: 'a'.repeat(64),
        })),
      },
      /at most 64 files/,
    ],
  ])
    assert.throws(() => read(value), pattern, label);
});

test('decision 8: workflow-analysis counts only when the pinned dependency closure was unchanged immediately before and after it ran', async t => {
  const { securityRun } = await load();
  const pinned = securityRun.actionlintClosureSha256;
  const control = await scenario(t, () => {});
  assert.deepEqual(control.inspect().blockers, []);
  for (const [label, change, pattern] of [
    [
      'no closure digests',
      r => delete r.stages.find(x => x.name === 'workflow-analysis').dependencyClosureSha256,
      /dependency closure it ran with was the pinned one/,
    ],
    [
      'another closure before',
      r =>
        (r.stages.find(x => x.name === 'workflow-analysis').dependencyClosureSha256 = {
          before: '0'.repeat(64),
          after: pinned,
        }),
      /dependency closure it ran with/,
    ],
    [
      'another closure after',
      r =>
        (r.stages.find(x => x.name === 'workflow-analysis').dependencyClosureSha256 = {
          before: pinned,
          after: '0'.repeat(64),
        }),
      /dependency closure it ran with/,
    ],
    [
      'digests in lists',
      r =>
        (r.stages.find(x => x.name === 'workflow-analysis').dependencyClosureSha256 = {
          before: [pinned],
          after: [pinned],
        }),
      /dependency closure it ran with/,
    ],
    [
      'actionlint-version without the closure',
      r => delete r.stages.find(x => x.name === 'actionlint-version').tool.dependencyClosureSha256,
      /did not observe the dependency closure its golden-tool record pins/,
    ],
  ]) {
    const s = await scenario(t, change);
    assert.match(s.inspect().blockers.join('\n'), pattern, label);
  }
});

test('decision 8: no fallback anywhere: the CI security job has no continue-on-error, nothing downloads a latest Actionlint, and the gate never starts one from PATH', () => {
  const workflows = fs
    .readdirSync(new URL('../.github/workflows/', import.meta.url))
    .filter(name => /\.ya?ml$/.test(name))
    .map(name => ({ name, text: repositoryFile(`.github/workflows/${name}`) }));
  assert.ok(workflows.length);
  for (const { name, text } of workflows) {
    assert.doesNotMatch(text, /continue-on-error/i, name);
    assert.doesNotMatch(text, /actionlint/i, `${name} runs or downloads no Actionlint of its own`);
    // No download of a latest release. (`runs-on: ubuntu-latest`, the runner label ci.yml uses,
    // is not a download and is not checked here.)
    assert.doesNotMatch(text, /@latest\b|\/latest\/download|releases\/latest/i, name);
  }
  // The security job runs the gate as its last step, whose exit decides the job.
  const security = repositoryFile('.github/workflows/security.yml');
  assert.match(security, /run: node scripts\/security-gate\.mjs scan\s*$/);
  // The CI tool installer fetches one pinned Actionlint with a pinned sha256 for the CI scan; it
  // is not a qualified pin, and the gate does not use it: the stages are pending.
  const installer = repositoryFile('scripts/install-security-tools.mjs');
  assert.match(installer, /actionlint\/releases\/download\/v1\.7\.12\//);
  assert.doesNotMatch(installer, /latest/i);
  assert.doesNotMatch(installer, /golden-tools/);
  // The gate starts no Actionlint at all, by name or by a path: workflow-analysis is a pending
  // requirement, never a stage with a command, and the gate reads no golden-tool record.
  const gate = repositoryFile('scripts/security-gate.mjs');
  assert.doesNotMatch(gate, /spawnSync\(\s*'actionlint'/);
  assert.doesNotMatch(gate, /stage\(\s*'workflow-analysis'/);
  assert.doesNotMatch(gate, /parseGoldenTool|actionlintArguments\(/);
  assert.match(gate, /requirement\('workflow-analysis'/);
  assert.match(gate, /record\.missingPin = missingActionlint;/);
});
