// The complete ordered parent vector of GATE-CONTRACT v3 C18 (a draft, not reviewed), and the security review's
// gate-draft findings GD-01 and GD-R1: a candidate is its tree with every parent in order (HEAD,
// then each MERGE_HEAD), bound and compared everywhere, never by tree and first parent; nothing is
// approved for an incomplete vector; and after a commit exists its vector is recomputed from its
// own object. Throwaway Git repositories with commits are made in the temporary folder. Runs and
// finalizations are synthetic (test/helpers/security-run.mjs, platform-run.mjs): test evidence for
// the checks, never a test or scan result.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { declareGit } from './helpers/git.mjs';

const gitSkip = declareGit();
const repositoryRoot = fileURLToPath(new URL('..', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
// gate-draft-r9 (GDR8-AUTH-LINT-01): a direct recordedApproval call names the lint stages its
// commit requires; the fixture repository's package.json defines no lint script, in canonical form.
const noLint = Object.freeze({ lintStages: Object.freeze([]) });

const load = async () => ({
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  catalog: await import('../scripts/security-catalog.mjs'),
  securityRun: await import('./helpers/security-run.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
  gateIdentity: await import('../scripts/security-gate-identity.mjs'),
});

const gitEnv = { ...process.env };
for (const name of ['NODE_TEST_CONTEXT', 'NODE_OPTIONS', 'GIT_REFLOG_ACTION']) delete gitEnv[name];
Object.assign(gitEnv, {
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Orbit Fixture',
  GIT_AUTHOR_EMAIL: 'fixture@example.com',
  GIT_COMMITTER_NAME: 'Orbit Fixture',
  GIT_COMMITTER_EMAIL: 'fixture@example.com',
});

/** A throwaway repository with an empty Git configuration, and the commit guard as Git runs it. */
function repository(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-parents-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) =>
    execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', env: gitEnv, stdio: 'pipe' })
      .toString()
      .trimEnd();
  const run = (env, ...args) =>
    spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', env: { ...gitEnv, ...env } });
  const write = (file, text) => {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  };
  const commit = message => {
    git('add', '-A');
    git('-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '--allow-empty', '-m', message);
    return git('rev-parse', 'HEAD');
  };
  const guard = (...args) =>
    spawnSync(
      process.execPath,
      [path.join(repositoryRoot, 'scripts/check-security-approval.mjs'), ...args],
      { cwd: root, encoding: 'utf8', env: gitEnv }
    );
  git('init', '--quiet', '-b', 'main');
  const security = path.join(root, '.git', 'orbit-security');
  fs.mkdirSync(security, { mode: 0o700 });
  write(
    'scripts/security-tools.json',
    fs.readFileSync(path.join(repositoryRoot, 'scripts/security-tools.json'))
  );
  write('example.mjs', 'export const synthetic = 0;\n');
  write('Dockerfile', '# Synthetic fixture\n');
  write('package.json', `${JSON.stringify({ scripts: {} }, null, 2)}\n`);
  return { root, git, run, write, commit, guard, security };
}

let approvals = 0;
/** A maintenance-shaped run (no lint stages) finalized for the staged candidate of `r`. */
function approveStaged(m, r) {
  const current = m.securityRun.candidate(r.root);
  const stages = m.securityRun.allStages.filter(
    name => !['sql-lint', 'import-lint'].includes(name)
  );
  const run = path.join(r.security, `${current.tree}-commit-${++approvals}`);
  return { run, approval: m.securityRun.finalizedRun(run, current, stages), current };
}

/**
 * A finalization of the identity (`tree`, `parents`) with the judged manifest bytes `manifest`, as
 * F would write it once every F obligation passed (synthetic: no F exists).
 */
function fApproval(m, r, label, tree, parents, manifest) {
  const run = path.join(r.security, `${tree}-commit-${label}`);
  const manifestSha256 = sha(manifest);
  m.securityRun.writeRun(
    run,
    { tree, parents, refs: '', files: m.securityRun.treeFiles(r.root, tree) },
    ['candidate-policy', 'gate-identity'],
    Date.now(),
    {
      platformManifest: { sha256: manifestSha256, state: 'valid' },
      // A run of a candidate with the platform contract binds its catalog, as the gate writes it;
      // a local run record of that kind without one is incomplete (GDR4-02).
      catalog: {
        mode: 'commit',
        profile: 'linux-full',
        sha256: m.catalog.installedCatalog().sha256,
      },
      record: record => {
        record.platform = { kind: 'manifest', manifestSha256 };
        // The version 3 gate identity F binds (GATE-CONTRACT v4 C1; synthetic).
        record.stages.find(stage => stage.name === 'gate-identity').gateIdentity =
          m.fixture.syntheticGateIdentity();
      },
    }
  );
  const record = JSON.parse(fs.readFileSync(path.join(run, 'result.json'), 'utf8'));
  const summary = { kind: 'manifest', manifestSha256 };
  const platformSha256 = sha(JSON.stringify(summary));
  const review = Buffer.from(JSON.stringify({ platformSha256 }));
  const installed = m.catalog.installedCatalog();
  const approval = {
    schemaVersion: 2,
    status: 'pass',
    mode: 'commit',
    tree,
    parents,
    candidateIdentitySha256: record.candidateIdentitySha256,
    runSha256: sha(fs.readFileSync(path.join(run, 'run-manifest.json'))),
    reviewSha256: sha(review),
    catalogSha256: installed.sha256,
    gateIdentity: m.gateIdentity.gateIdentityBinding(m.fixture.syntheticGateIdentity()),
    obligations: Object.fromEntries(installed.catalog.finalization.commit.map(id => [id, 'pass'])),
    platform: summary,
    platformSha256,
  };
  fs.mkdirSync(path.join(run, 'finalization'), { mode: 0o700 });
  fs.writeFileSync(path.join(run, 'finalization/approval.json'), JSON.stringify(approval), {
    mode: 0o600,
  });
  fs.writeFileSync(path.join(run, 'finalization/review.json'), review, { mode: 0o600 });
  return { run, approval };
}

// ---------------------------------------------------------------------------------------------
// The candidate identity

test('the candidate identity holds the complete ordered parent vector, and refuses an incomplete one', async () => {
  const { platform } = await load();
  const files = [{ file: 'a', mode: '100644', blob: '1'.repeat(40), sha256: '2'.repeat(64) }];
  const state = { state: 'never-held' };
  const identity = parents =>
    platform.candidateIdentity({ tree: 'c'.repeat(40), parents, files, platformManifest: state });
  const one = identity(['a'.repeat(40), 'b'.repeat(40)]);
  assert.deepEqual(one.record, {
    filesSha256: sha(
      '[{"blob":"1111111111111111111111111111111111111111","file":"a","mode":"100644","sha256":"2222222222222222222222222222222222222222222222222222222222222222"}]'
    ),
    parents: ['a'.repeat(40), 'b'.repeat(40)],
    platformManifest: state,
    tree: 'c'.repeat(40),
    version: 1,
  });
  // Another order, another or a missing parent: another identity.
  for (const parents of [
    ['b'.repeat(40), 'a'.repeat(40)],
    ['a'.repeat(40), 'd'.repeat(40)],
    ['a'.repeat(40)],
  ])
    assert.notEqual(identity(parents).sha256, one.sha256, JSON.stringify(parents));
  // Empty, repeated, not ids, a list inside: refused (Orbit work always has a nonempty vector).
  for (const parents of [
    [],
    undefined,
    ['a'.repeat(40), 'a'.repeat(40)],
    ['A'.repeat(40)],
    [['a'.repeat(40)]],
    Array.from({ length: 17 }, (_, index) => index.toString(16).padStart(40, '0')),
  ])
    assert.throws(() => identity(parents), /candidate identity/, JSON.stringify(parents));
  assert.throws(
    () =>
      platform.candidateIdentity({
        tree: 'c'.repeat(40),
        parents: ['a'.repeat(40)],
        files,
        platformManifest: null,
      }),
    /must be judged first/
  );
  assert.deepEqual(platform.platformManifestState({ kind: 'maintenance', problems: [] }), state);
  assert.deepEqual(
    platform.platformManifestState({
      kind: 'manifest',
      manifestSha256: 'e'.repeat(64),
      problems: [],
    }),
    { sha256: 'e'.repeat(64), state: 'valid' }
  );
  for (const judged of [
    null,
    { kind: 'manifest', manifestSha256: 'e'.repeat(64), problems: ['x'] },
    { kind: 'manifest', manifestSha256: ['e'.repeat(64)], problems: [] },
  ])
    assert.equal(platform.platformManifestState(judged), null);
});

test("a merge's parents are HEAD and every MERGE_HEAD, in order; a repeated or unreadable one leaves the vector incomplete", async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { finalization } = await load();
  const r = repository(t);
  const first = r.commit('first');
  r.git('checkout', '--quiet', '-b', 'one');
  r.write('one.txt', '1\n');
  const one = r.commit('one');
  r.git('checkout', '--quiet', '-b', 'two', first);
  r.write('two.txt', '2\n');
  const two = r.commit('two');
  r.git('checkout', '--quiet', 'main');
  r.write('main.txt', 'main\n');
  const head = r.commit('main');
  r.git('merge', '--quiet', '--no-commit', '--no-ff', 'one', 'two');
  assert.deepEqual(finalization.candidateParents(r.root), {
    heads: [head, one, two],
    complete: true,
    reason: '',
  });
  const mergeHead = path.join(r.root, '.git/MERGE_HEAD');
  fs.writeFileSync(mergeHead, `${one}\n${one}\n`);
  assert.deepEqual(finalization.candidateParents(r.root).complete, false);
  assert.match(finalization.candidateParents(r.root).reason, /names a parent twice/);
  fs.writeFileSync(mergeHead, 'not a commit\n');
  assert.match(finalization.candidateParents(r.root).reason, /MERGE_HEAD could not be read/);
  fs.writeFileSync(mergeHead, `${head}\n`);
  assert.equal(finalization.candidateParents(r.root).complete, false, 'HEAD named again');
  fs.rmSync(mergeHead);
  assert.deepEqual(finalization.candidateParents(r.root).heads, [head]);
  assert.equal(
    finalization.candidateParents(r.root, { automaticMerge: true }).complete,
    false,
    'an automatic merge, before Git writes MERGE_HEAD'
  );
});

// ---------------------------------------------------------------------------------------------
// GD-01: the reviewed-baseline cache

test('GD-01: a reviewed baseline is matched by its tree with its complete ordered parent vector, never by tree and first parent', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  for (const file of m.fixture.testFiles) r.write(file, `// Synthetic ${file}\n`);
  const R0 = r.commit('without a manifest');
  const base = m.fixture.syntheticManifest();
  const M = m.fixture.manifestText(base);
  r.write('test/platform-manifest.json', M);
  const P1 = r.commit('the manifest');
  const T = r.git('rev-parse', 'HEAD^{tree}');
  r.git('checkout', '--quiet', '-b', 'p2');
  r.write('p2.txt', 'p2\n');
  const P2 = r.commit('P2');
  r.git('checkout', '--quiet', '-b', 'p3', P1);
  const stronger = structuredClone(base);
  stronger.entries.push({
    id: 'linux.extra',
    file: 'test/linux.test.mjs',
    name: ['the extra Linux test'],
    platforms: ['linux'],
    runtimes: ['24', '26'],
    prerequisites: [],
    evidence: ['linux-full'],
  });
  r.write('test/platform-manifest.json', m.fixture.manifestText(stronger));
  r.write('p3.txt', 'p3\n');
  const P3 = r.commit('P3 strengthens the manifest');
  // Two merges with the same tree and first parent and another second parent.
  const A = r.git('commit-tree', T, '-p', P1, '-p', P2, '-m', 'A');
  const B = r.git('commit-tree', T, '-p', P1, '-p', P3, '-m', 'B');
  r.git('checkout', '--quiet', '-B', 'candidate', B);
  r.write('example.mjs', 'export const synthetic = 1;\n');
  r.git('add', '-A');
  const tree = r.git('write-tree');
  fApproval(m, r, 'p1', T, [R0], M);
  const a = fApproval(m, r, 'a', T, [P1, P2], M);
  const judge = () => {
    const inputs = m.finalization.platformInputs(r.root, tree, {
      heads: [B],
      complete: true,
      reason: '',
    });
    const reviewed = commit => inputs.history.find(node => node.commit === commit).reviewed;
    const judged = m.platform.judgePlatformManifest({ ...inputs, binding: { tree, parents: [B] } });
    return { reviewed, problems: judged.problems.join('\n') };
  };
  // A's approval does not make B reviewed: the walk reaches P3 and finds the loss.
  const collision = judge();
  assert.equal(collision.reviewed(B), null);
  assert.deepEqual(collision.reviewed(P1), { manifestSha256: sha(M) });
  assert.match(collision.problems, /a loss no reviewed disposition excuses: .*entry:linux\.extra/);
  // The earlier key, "<tree> <first parent>", matched B here. The same check through the
  // approvals the cache finds: only A's exact vector is approved.
  const found = m.finalization.approvedManifests(
    r.security,
    new Set([m.platform.identityKey(T, [P1, P3]), m.platform.identityKey(T, [P1, P2])])
  );
  assert.deepEqual([...found.keys()], [m.platform.identityKey(T, [P1, P2])]);
  // Control: an approval of B's own complete vector makes B reviewed, and only B.
  fs.rmSync(a.run, { recursive: true, force: true });
  fApproval(m, r, 'b', T, [P1, P3], M);
  const exact = judge();
  assert.deepEqual(exact.reviewed(B), { manifestSha256: sha(M) });
  assert.equal(exact.problems, '');
  // A reordered vector is another identity.
  assert.equal(
    m.finalization.approvedManifests(r.security, new Set([m.platform.identityKey(T, [P3, P1])]))
      .size,
    0
  );
});

test('a legacy single-parent finalization gives no authority, as a reviewed baseline or to the guard, even for one parent', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const first = r.commit('first');
  r.write('example.mjs', 'export const synthetic = 2;\n');
  r.git('add', '-A');
  const { run } = approveStaged(m, r);
  assert.equal(r.guard().status, 0, r.guard().stderr);
  const file = path.join(run, 'finalization/approval.json');
  const approval = JSON.parse(fs.readFileSync(file, 'utf8'));
  // Rewritten as the earlier form: schema 1, with one parent.
  const { parents, candidateIdentitySha256, ...rest } = approval;
  fs.writeFileSync(file, JSON.stringify({ ...rest, schemaVersion: 1, parent: parents[0] }), {
    mode: 0o600,
  });
  assert.deepEqual(parents, [first]);
  const refused = r.guard();
  assert.equal(refused.status, 1, refused.stderr);
  assert.match(refused.stderr, /No fresh verified finalization/);
  const current = {
    ...m.securityRun.candidate(r.root),
    platform: m.securityRun.maintenanceInputs(m.securityRun.candidate(r.root)),
  };
  assert.throws(() => m.finalization.validateFinalization(run, current), /not schema 2/);
  // The same file kept as schema 2 but with a single `parent`: refused too.
  fs.writeFileSync(file, JSON.stringify({ ...rest, parent: parents[0] }), { mode: 0o600 });
  assert.throws(
    () => m.finalization.validateFinalization(run, current),
    /complete candidate identity/
  );
});

// ---------------------------------------------------------------------------------------------
// GD-R1: the actual commit guard

test('GD-R1: after a finalized candidate, a same-tree merge that adds a parent is refused by the actual guard', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  r.write('x.txt', 'x\n');
  r.git('add', '-A');
  approveStaged(m, r);
  const before = r.guard();
  assert.equal(before.status, 0, before.stderr);
  // A side history the run never saw, referenced by no ref (the refs the run binds stay the
  // same): a commit that adds a file, then one that ends at the candidate tree.
  const candidateTree = r.git('write-tree');
  r.git('reset', '--quiet');
  fs.rmSync(path.join(r.root, 'x.txt'));
  r.write('unseen.txt', 'unseen\n');
  r.git('add', '-A');
  const unseenTree = r.git('write-tree');
  r.git('reset', '--quiet');
  fs.rmSync(path.join(r.root, 'unseen.txt'));
  const S1 = r.git('commit-tree', unseenTree, '-p', C0, '-m', 'unseen side change');
  const S2 = r.git('commit-tree', candidateTree, '-p', S1, '-m', 'side ends at the candidate');
  r.git('merge', '--quiet', '--no-ff', '--no-commit', S2);
  assert.equal(r.git('write-tree'), candidateTree);
  const after = r.guard();
  assert.equal(after.status, 1, after.stderr);
  assert.match(after.stderr, /No fresh verified finalization/);
  // A run bound to the merge's complete vector is accepted, and committing it records exactly that.
  const { current } = approveStaged(m, r);
  assert.deepEqual(current.parents, [C0, S2]);
  assert.equal(r.guard().status, 0);
  const committed = r.run({}, 'commit', '--quiet', '--no-edit');
  assert.equal(committed.status, 0, committed.stderr);
  assert.deepEqual(r.git('rev-list', '--parents', '-n', '1', 'HEAD').split(' ').slice(1), [C0, S2]);
});

test('GD-R1: an automatic merge is refused for every candidate, and the same merge concluded with --no-commit is judged with every parent', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  r.commit('first');
  // The side the main line never saw introduced the manifest, then deleted it.
  r.git('checkout', '--quiet', '-b', 'side');
  r.write('test/platform-manifest.json', m.fixture.manifestText(m.fixture.syntheticManifest()));
  r.commit('side adds the manifest');
  fs.rmSync(path.join(r.root, 'test/platform-manifest.json'));
  r.commit('side deletes the manifest');
  r.git('checkout', '--quiet', 'main');
  r.write('main.txt', 'main\n');
  const head = r.commit('main moves on');
  // A run of the merge result bound to HEAD alone, as the earlier guard accepted for it.
  r.git('merge', '--quiet', '--no-ff', '--no-commit', 'side');
  const resultTree = r.git('write-tree');
  r.git('merge', '--abort');
  const current = m.securityRun.candidate(r.root, resultTree);
  assert.deepEqual(current.parents, [head]);
  m.securityRun.finalizedRun(
    path.join(r.security, `${resultTree}-commit-automatic`),
    current,
    m.securityRun.allStages
  );
  const installer = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'scripts/install-security-hooks.mjs'), r.root],
    { encoding: 'utf8', env: gitEnv }
  );
  assert.equal(installer.status, 0, installer.stderr);
  const automatic = r.run({}, 'merge', '--quiet', '--no-edit', 'side');
  assert.equal(automatic.status, 1, automatic.stderr);
  assert.match(automatic.stderr, /complete parent vector of this commit is not known/);
  assert.equal(r.git('rev-parse', 'HEAD'), head);
  r.git('merge', '--abort');
  // Concluded with --no-commit and git commit: the unseen side's history held the manifest, so the
  // result without one is refused, whatever the run.
  r.git('merge', '--quiet', '--no-ff', '--no-commit', 'side');
  m.securityRun.finalizedRun(
    path.join(r.security, `${resultTree}-commit-complete`),
    m.securityRun.candidate(r.root),
    m.securityRun.allStages
  );
  const concluded = r.run({}, 'commit', '--quiet', '--no-edit');
  assert.equal(concluded.status, 1, concluded.stderr);
  assert.match(
    concluded.stderr,
    /has no test\/platform-manifest\.json, which a commit behind it holds/
  );
  assert.equal(r.git('rev-parse', 'HEAD'), head);
});

// ---------------------------------------------------------------------------------------------
// After a commit exists (the C18 clarification): recompute and compare

test('after a commit exists, its tree and complete ordered parent vector are recomputed from its object and compared with the approved ones', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  r.git('checkout', '--quiet', '-b', 'side');
  r.write('side.txt', 'side\n');
  const S = r.commit('side');
  r.git('checkout', '--quiet', 'main');
  r.git('merge', '--quiet', '--no-ff', '--no-commit', S);
  const T = r.git('write-tree');
  approveStaged(m, r);
  r.git('merge', '--abort');
  // The approved commit: exactly the approved tree and vector.
  const exact = r.git('commit-tree', T, '-p', C0, '-p', S, '-m', 'as approved');
  const verified = r.guard('--verify-commit', exact);
  assert.equal(verified.status, 0, verified.stderr);
  // The same tree with a missing, reordered or other parent vector.
  const missing = r.git('commit-tree', T, '-p', C0, '-m', 'a parent missing');
  const reordered = r.git('commit-tree', T, '-p', S, '-p', C0, '-m', 'reordered');
  r.write('other.txt', 'other\n');
  const other = r.commit('other');
  const another = r.git('commit-tree', T, '-p', C0, '-p', other, '-m', 'another parent');
  for (const [label, commit] of [
    ['missing', missing],
    ['reordered', reordered],
    ['another', another],
  ]) {
    const refused = r.guard('--verify-commit', commit);
    assert.equal(refused.status, 1, `${label}: ${refused.stderr}`);
    assert.match(
      refused.stderr,
      /no finalization with status pass approved that tree with that complete ordered parent vector/,
      label
    );
  }
  // committedIdentityProblems compares exactly, in order.
  const git = (args, input) => execFileSync('git', ['-C', r.root, ...args], { input });
  const intended = { tree: T, parents: [C0, S] };
  assert.deepEqual(m.platform.committedIdentityProblems({ git, commit: exact, intended }), []);
  assert.match(
    m.platform.committedIdentityProblems({ git, commit: reordered, intended }).join('\n'),
    /not the intended complete ordered vector/
  );
  assert.match(
    m.platform.committedIdentityProblems({ git, commit: other, intended }).join('\n'),
    /has the tree .* not the intended/
  );
  // Replacement ambiguity: a replace ref for the commit is refused rather than one view chosen.
  r.git('replace', exact, missing);
  const replaced = r.guard('--verify-commit', exact);
  assert.equal(replaced.status, 1, replaced.stderr);
  assert.match(replaced.stderr, /a ref is named after .* as a replace ref is/);
  r.git('replace', '-d', exact);
  assert.equal(r.guard('--verify-commit', exact).status, 0);
});

test('a forged commit-graph or a replace ref that changes the parents Git shows refuses the candidate', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const first = r.commit('first');
  r.write('second.txt', 'second\n');
  const second = r.commit('second');
  r.write('example.mjs', 'export const synthetic = 3;\n');
  r.git('add', '-A');
  const tree = r.git('write-tree');
  const inputs = () =>
    m.finalization.platformInputs(r.root, tree, { heads: [second], complete: true, reason: '' });
  assert.deepEqual(inputs().refused, []);
  // A commit-graph that says `second` has no parents (Git would use it without checking).
  const graph = path.join(r.root, '.git/objects/info/commit-graph');
  fs.mkdirSync(path.dirname(graph), { recursive: true });
  const id = Buffer.from(second, 'hex');
  const fanout = Buffer.alloc(256 * 4);
  for (let byte = 0; byte < 256; byte++) fanout.writeUInt32BE(byte >= id[0] ? 1 : 0, byte * 4);
  const data = Buffer.alloc(36);
  Buffer.from(r.git('rev-parse', `${second}^{tree}`), 'hex').copy(data, 0);
  data.writeUInt32BE(0x70000000, 20);
  data.writeUInt32BE(0x70000000, 24);
  const time = Number(r.git('log', '-1', '--format=%ct', second));
  data.writeUInt32BE(((1 << 2) | Math.floor(time / 2 ** 32)) >>> 0, 28);
  data.writeUInt32BE(time % 2 ** 32, 32);
  const chunks = [
    ['OIDF', fanout],
    ['OIDL', id],
    ['CDAT', data],
  ];
  const header = Buffer.from([0x43, 0x47, 0x50, 0x48, 1, 1, chunks.length, 0]);
  const table = Buffer.alloc((chunks.length + 1) * 12);
  let offset = header.length + table.length;
  chunks.forEach(([name, bytes], index) => {
    table.write(name, index * 12, 'ascii');
    table.writeBigUInt64BE(BigInt(offset), index * 12 + 4);
    offset += bytes.length;
  });
  table.writeBigUInt64BE(BigInt(offset), chunks.length * 12 + 4);
  const body = Buffer.concat([header, table, ...chunks.map(([, bytes]) => bytes)]);
  fs.writeFileSync(graph, Buffer.concat([body, createHash('sha1').update(body).digest()]));
  assert.match(inputs().refused.join('\n'), /commit-graph gives commit .* other parents/);
  fs.rmSync(graph);
  // A replace ref for the parent of a candidate.
  r.git('replace', '--graft', second);
  assert.match(inputs().refused.join('\n'), /a ref is named after .* as a replace ref is/);
  const judged = m.platform.judgePlatformManifest({
    ...inputs(),
    binding: { tree, parents: [second] },
  });
  assert.match(judged.problems.join('\n'), /as a replace ref is/);
  r.git('replace', '-d', second);
  assert.deepEqual(inputs().refused, []);
  assert.ok(first);
});

// ---------------------------------------------------------------------------------------------
// verify-1 (gate-draft-r2 round 2): `git commit --amend` through the installed hooks. Git runs the
// guard before it decides the parents, and an amend gives the new commit HEAD's parents, not HEAD;
// the installed reference-transaction hook compares the commit Git made with what the guard
// approved before HEAD moves (scripts/check-security-approval.mjs).

const guardScript = path.join(repositoryRoot, 'scripts/check-security-approval.mjs');
const parentsOf = (r, commit) =>
  r.git('rev-list', '--parents', '-n', '1', commit).split(' ').slice(1);
function installHooks(r) {
  const installer = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'scripts/install-security-hooks.mjs'), r.root],
    { encoding: 'utf8', env: gitEnv }
  );
  assert.equal(installer.status, 0, installer.stderr);
}
const intentsOf = r => {
  const folder = path.join(r.security, 'commit-intents');
  return fs.existsSync(folder) ? fs.readdirSync(folder) : [];
};

test('GD-R1: git commit --amend through the installed hooks is refused before HEAD moves, for a one-parent commit and for a merge', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  r.write('one.txt', 'one\n');
  const C1 = r.commit('second');
  installHooks(r);
  const head = () => r.git('rev-parse', 'HEAD');
  const refusedAmend = /in 'prepared' phase, update aborted by the reference-transaction hook/;
  // Control: an amend that nothing approved is refused by the guard itself.
  r.write('two.txt', 'two\n');
  r.git('add', '-A');
  const unapproved = r.run({}, 'commit', '--quiet', '--amend', '--no-edit');
  assert.equal(unapproved.status, 1, unapproved.stderr);
  assert.match(unapproved.stderr, /Commit blocked: stage the complete change/);
  assert.equal(head(), C1);
  // The guard approves the staged tree on [C1]; Git would give the amended commit [C0]. An
  // approval of [C0] as well changes nothing: the guard approved [C1] for this commit.
  const { current } = approveStaged(m, r);
  assert.deepEqual(current.parents, [C1]);
  const stages = m.securityRun.allStages.filter(
    name => !['sql-lint', 'import-lint'].includes(name)
  );
  m.securityRun.finalizedRun(
    path.join(r.security, `${current.tree}-commit-real-amend-vector`),
    { ...current, parent: C0, parents: [C0] },
    stages
  );
  const amended = r.run({}, 'commit', '--quiet', '--amend', '--no-edit');
  assert.equal(amended.status, 128, amended.stderr);
  assert.match(amended.stderr, refusedAmend);
  assert.match(
    amended.stderr,
    new RegExp(
      `has the tree ${current.tree} and the parents \\[${C0}\\], not the tree ${current.tree} and the complete ordered parent vector \\[${C1}\\] that the commit guard approved`
    )
  );
  assert.equal(head(), C1);
  assert.deepEqual(intentsOf(r), []);
  // Control: the same change as a new commit, through the same hooks, records exactly [C1].
  const made = r.run({}, 'commit', '--quiet', '-m', 'third');
  assert.equal(made.status, 0, made.stderr);
  const C2 = head();
  assert.deepEqual(parentsOf(r, C2), [C1]);
  assert.deepEqual(intentsOf(r), []);
  // A merge concluded with git commit through the hooks records exactly [C2, S].
  r.git('checkout', '--quiet', '-b', 'side', C0);
  r.write('side.txt', 'side\n');
  const S = r.commit('side');
  r.git('checkout', '--quiet', 'main');
  r.git('merge', '--quiet', '--no-ff', '--no-commit', S);
  approveStaged(m, r);
  const merged = r.run({}, 'commit', '--quiet', '--no-edit');
  assert.equal(merged.status, 0, merged.stderr);
  const M = head();
  assert.deepEqual(parentsOf(r, M), [C2, S]);
  // Amending the merge: the guard approves [M] (one parent); Git would make a merge of [C2, S].
  r.write('three.txt', 'three\n');
  r.git('add', '-A');
  const merge = approveStaged(m, r);
  assert.deepEqual(merge.current.parents, [M]);
  const amendedMerge = r.run({}, 'commit', '--quiet', '--amend', '--no-edit');
  assert.equal(amendedMerge.status, 128, amendedMerge.stderr);
  assert.match(amendedMerge.stderr, refusedAmend);
  assert.match(
    amendedMerge.stderr,
    new RegExp(`the parents \\[${C2}, ${S}\\], not the tree .* vector \\[${M}\\]`)
  );
  assert.equal(head(), M);
  // On a detached HEAD the same: the amend is refused, a new commit is made with exactly [M].
  r.git('checkout', '--quiet', '--detach');
  const detached = r.run({}, 'commit', '--quiet', '--amend', '--no-edit');
  assert.equal(detached.status, 128, detached.stderr);
  assert.match(detached.stderr, refusedAmend);
  assert.equal(head(), M);
  const onDetached = r.run({}, 'commit', '--quiet', '-m', 'on a detached HEAD');
  assert.equal(onDetached.status, 0, onDetached.stderr);
  assert.deepEqual(parentsOf(r, head()), [M]);
  assert.deepEqual(intentsOf(r), []);
  // git am runs the guard as pre-applypatch in the Git process that then moves HEAD: the same
  // record and check apply, and a patch applied as approved is committed with exactly [HEAD].
  r.git('checkout', '--quiet', 'main');
  r.write('patched.txt', 'patched\n');
  const P = r.commit('a patch');
  const patch = `${r.git('format-patch', '-1', '--stdout', P)}\n`;
  r.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', 'HEAD~1');
  assert.equal(head(), M);
  m.securityRun.finalizedRun(
    path.join(r.security, `${r.git('rev-parse', `${P}^{tree}`)}-commit-am`),
    m.securityRun.candidate(r.root, r.git('rev-parse', `${P}^{tree}`)),
    stages
  );
  const applied = spawnSync('git', ['-C', r.root, 'am', '--quiet'], {
    input: patch,
    encoding: 'utf8',
    env: gitEnv,
  });
  assert.equal(applied.status, 0, applied.stderr);
  assert.deepEqual(parentsOf(r, head()), [M]);
  assert.equal(r.git('rev-parse', 'HEAD^{tree}'), r.git('rev-parse', `${P}^{tree}`));
  assert.deepEqual(intentsOf(r), []);
});

test('as a hook, the guard approves nothing unless the reference-transaction hook is installed', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  installHooks(r);
  r.write('x.txt', 'x\n');
  r.git('add', '-A');
  approveStaged(m, r);
  const hook = path.join(r.root, '.git', 'hooks', 'reference-transaction');
  const installed = fs.readFileSync(hook);
  for (const [label, change] of [
    ['missing', () => fs.rmSync(hook)],
    ['changed', () => fs.writeFileSync(hook, '#!/bin/sh\nexit 0\n', { mode: 0o700 })],
    ['not executable', () => fs.chmodSync(hook, 0o600)],
  ]) {
    change();
    const refused = r.run({}, 'commit', '--quiet', '-m', label);
    assert.equal(refused.status, 1, `${label}: ${refused.stderr}`);
    assert.match(
      refused.stderr,
      /the reference-transaction hook that checks the commit Git makes before HEAD moves is not installed/,
      label
    );
    assert.equal(r.git('rev-parse', 'HEAD'), C0, label);
    fs.rmSync(hook, { force: true });
    fs.writeFileSync(hook, installed, { mode: 0o700 });
  }
  // Run by hand (not as a hook), the guard still only answers whether a commit would be approved.
  assert.equal(r.guard().status, 0);
  const committed = r.run({}, 'commit', '--quiet', '-m', 'with every hook');
  assert.equal(committed.status, 0, committed.stderr);
  assert.deepEqual(parentsOf(r, 'HEAD'), [C0]);
});

test('the reference-transaction check acts only on the ref the approved commit moves, for the Git process the guard ran in', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  r.write('x.txt', 'x\n');
  r.git('add', '-A');
  const { run } = approveStaged(m, r);
  const tree = r.git('write-tree');
  const exact = r.git('commit-tree', tree, '-p', C0, '-m', 'as approved');
  const rootCommit = r.git('commit-tree', tree, '-m', 'no parent');
  const folder = path.join(r.security, 'commit-intents');
  fs.mkdirSync(folder, { mode: 0o700 });
  // Spawned from this test, the check's parent process is this one, as a hook's is Git.
  const file = path.join(folder, `${process.pid}.json`);
  const intent = {
    schemaVersion: 1,
    pid: process.pid,
    head: C0,
    ref: 'refs/heads/main',
    tree,
    parents: [C0],
    approval: path.basename(run),
    approvalSha256: sha(fs.readFileSync(path.join(run, 'finalization/approval.json'))),
    writtenAt: new Date().toISOString(),
  };
  const place = (value = intent) =>
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value), {
      mode: 0o600,
    });
  const transaction = (state, input) =>
    spawnSync(process.execPath, [guardScript, '--reference-transaction', state], {
      cwd: r.root,
      input,
      encoding: 'utf8',
      env: gitEnv,
    });
  const line = (from, to, ref = 'refs/heads/main') => `${from} ${to} ${ref}\n`;
  const zero = '0'.repeat(40);
  // No record for this process: any update passes, one that would fail the check too.
  assert.equal(transaction('prepared', line(C0, rootCommit)).status, 0);
  // Other refs of the same process (ORIG_HEAD, AUTO_MERGE, a tag): they pass and the record stays
  // for the commit's own update.
  place();
  const others = transaction(
    'prepared',
    line(zero, C0, 'ORIG_HEAD') + line(zero, zero, 'AUTO_MERGE') + line(zero, C0, 'refs/tags/other')
  );
  assert.equal(others.status, 0, others.stderr);
  assert.equal(fs.existsSync(file), true);
  // The approved commit passes, and the record is removed.
  const passed = transaction('prepared', line(C0, exact));
  assert.equal(passed.status, 0, passed.stderr);
  assert.equal(fs.existsSync(file), false);
  for (const [label, value, input, pattern] of [
    [
      'other parents',
      intent,
      line(C0, rootCommit),
      new RegExp(
        `the parents \\[\\], not the tree ${tree} and the complete ordered parent vector \\[${C0}\\]`
      ),
    ],
    ['HEAD itself', intent, line(C0, rootCommit, 'HEAD'), /the parents \[\], not the tree/],
    [
      'another old value',
      intent,
      line(rootCommit, exact),
      /would move from .*, not from .*the record was stale/,
    ],
    [
      'another branch',
      intent,
      line(C0, exact, 'refs/heads/other'),
      /refs\/heads\/other would move, not refs\/heads\/main/,
    ],
    ['a new branch', intent, line(zero, exact, 'refs/heads/new'), /refs\/heads\/new would move/],
    ['a deletion', intent, line(C0, zero), /would not name a commit/],
    ['an unreadable record', 'not JSON', line(C0, exact), /cannot be read .*not JSON/],
    [
      'a record of another process',
      { ...intent, pid: process.pid + 1 },
      line(C0, exact),
      /cannot be read/,
    ],
    [
      'a tree given as a one-item list',
      { ...intent, tree: [tree] },
      line(C0, exact),
      /cannot be read/,
    ],
    ['an extra field', { ...intent, extra: true }, line(C0, exact), /cannot be read/],
    [
      'a finalization changed since the guard accepted it',
      { ...intent, approvalSha256: '0'.repeat(64) },
      line(C0, exact),
      /no longer verifies unchanged/,
    ],
  ]) {
    place(value);
    const refused = transaction('prepared', input);
    assert.equal(refused.status, 1, `${label}: ${refused.stderr}`);
    assert.match(refused.stderr, pattern, label);
    assert.equal(fs.existsSync(file), false, label);
  }
  // Committed or aborted: nothing is checked, and the record of that commit is removed.
  for (const state of ['committed', 'aborted']) {
    place();
    assert.equal(transaction(state, line(C0, rootCommit)).status, 0, state);
    assert.equal(fs.existsSync(file), false, state);
  }
  // A record folder that others can read is refused, whatever the update.
  place();
  fs.chmodSync(folder, 0o755);
  const shared = transaction('prepared', line(C0, exact));
  assert.equal(shared.status, 1, shared.stderr);
  assert.match(shared.stderr, /must be a private folder/);
  fs.chmodSync(folder, 0o700);
});

test('--verify-commit accepts only a recorded approval that still verifies: its catalog binding, its F obligations and its retained review', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  r.write('x.txt', 'x\n');
  r.git('add', '-A');
  const { run } = approveStaged(m, r);
  const tree = r.git('write-tree');
  const exact = r.git('commit-tree', tree, '-p', C0, '-m', 'as approved');
  const verified = r.guard('--verify-commit', exact);
  assert.equal(verified.status, 0, verified.stderr);
  const installed = m.catalog.installedCatalog();
  const file = path.join(run, 'finalization', 'approval.json');
  const original = fs.readFileSync(file);
  const everyObligation = Object.fromEntries(
    installed.catalog.finalization.commit.map(id => [id, 'pass'])
  );
  for (const [label, change] of [
    // verify-1's case: a foreign catalog sha256 with an unrelated obligation.
    [
      'a foreign catalog binding',
      a => ({
        ...a,
        catalogSha256: 'not-the-installed-catalog',
        obligations: { anything: 'pass' },
      }),
    ],
    // The installed catalog with every obligation passed, on a candidate whose history never held
    // the manifest: only F could write that, and only for a candidate with a platform contract.
    [
      'the installed catalog on a maintenance candidate',
      a => ({
        ...a,
        catalogSha256: installed.sha256,
        profile: 'linux-full',
        obligations: everyObligation,
      }),
    ],
    ['obligations without a catalog binding', a => ({ ...a, obligations: everyObligation })],
    ['status pending', a => ({ ...a, status: 'pending' })],
    ['another review', a => ({ ...a, reviewSha256: '0'.repeat(64) })],
    ['other refs', a => ({ ...a, refs: '' })],
    ['another run', a => ({ ...a, runSha256: '0'.repeat(64) })],
    ['a single parent field', a => ({ ...a, parents: undefined, parent: C0 })],
  ]) {
    fs.writeFileSync(file, JSON.stringify(change(JSON.parse(original))), { mode: 0o600 });
    const refused = r.guard('--verify-commit', exact);
    assert.equal(refused.status, 1, `${label}: ${refused.stderr}`);
    assert.match(
      refused.stderr,
      /no finalization with status pass approved that tree with that complete ordered parent vector/,
      label
    );
  }
  fs.writeFileSync(file, original, { mode: 0o600 });
  assert.equal(r.guard('--verify-commit', exact).status, 0);
  // A retained review bound to another run, with the approval naming its digest: refused.
  const reviewFile = path.join(run, 'finalization', 'review.json');
  const review = JSON.parse(fs.readFileSync(reviewFile, 'utf8'));
  const forged = Buffer.from(JSON.stringify({ ...review, runSha256: '0'.repeat(64) }));
  fs.writeFileSync(reviewFile, forged, { mode: 0o600 });
  fs.writeFileSync(file, JSON.stringify({ ...JSON.parse(original), reviewSha256: sha(forged) }), {
    mode: 0o600,
  });
  const reviewed = r.guard('--verify-commit', exact);
  assert.equal(reviewed.status, 1, reviewed.stderr);
  assert.throws(() => m.finalization.recordedApproval(run, noLint), /retained review is not bound/);
});

// gate-draft-r8, GDR7-AUTH-01 at the entry points that give a recorded approval authority (the security review's
// review of gate-draft-r7: a carried downstream-consumer defect; the maintainer's decision 2 of
// 20261018T051017695655Z): `--verify-commit` and the reference-transaction hook both reach
// recordedApproval() through verifyCommit(), which accepted a recorded maintenance (B35) approval
// of a run that validateFinalization refuses. Each case below is its own staged tree on C0, with a
// sealed maintenance run and the finalization an earlier finalizer and F would have recorded for it
// (synthetic), and the commit Git would make of exactly that tree and vector. A run the current B35
// rules refuse approves nothing at either entry point, and HEAD would not move; a current valid
// approval, two distinct Node 24 executables included, is still accepted at both.
test('GDR7-AUTH-01: --verify-commit and the reference-transaction hook give no authority to a recorded maintenance approval of a run the current B35 rules refuse, and keep accepting a current valid one, two distinct Node 24 executables included', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  const now = Date.now();
  const { requiredStages } = m.finalization;
  const prerequisites = ['test-host', 'runtime-identity'];
  const twoSlot = [...requiredStages];
  twoSlot.splice(
    twoSlot.indexOf('full-tests-current-runtime') + 1,
    0,
    'full-tests-minimum-runtime'
  );
  const stage = (record, name) => record.stages.find(item => item.name === name);
  const extra = (record, name, as, change = {}) => {
    const source = stage(record, name);
    record.stages.splice(record.stages.indexOf(source) + 1, 0, {
      ...structuredClone(source),
      name: as,
      log: `${as}.log`,
      ...change,
    });
  };
  const folder = path.join(r.security, 'commit-intents');
  fs.mkdirSync(folder, { mode: 0o700 });
  const intentFile = path.join(folder, `${process.pid}.json`);
  let count = 0;
  // A case's staged tree, sealed run and finalization (recorded the earlier way, or `finalized` by
  // this tree and passed as F would), and the commit of exactly that tree on [C0].
  const make = (label, stages, options = {}, { finalized = false } = {}) => {
    r.write(`gdr7-case-${(count += 1)}.txt`, `${label}\n`);
    r.git('add', '-A');
    const current = m.securityRun.candidate(r.root);
    const run = path.join(r.security, `${current.tree}-commit-gdr7-${count}`);
    if (finalized) m.securityRun.finalizedRun(run, current, stages, now, options);
    else {
      m.securityRun.writeRun(run, current, stages, now, options);
      m.securityRun.recordedFinalization(run, current, now);
    }
    const exact = r.git('commit-tree', current.tree, '-p', C0, '-m', label);
    return { run, current, exact };
  };
  // Both entry points for one case: `--verify-commit <commit>`, and the reference-transaction
  // hook's prepared check of the update to that commit, with the intent the guard records.
  const enter = ({ run, current, exact }) => {
    const verified = r.guard('--verify-commit', exact);
    fs.writeFileSync(
      intentFile,
      JSON.stringify({
        schemaVersion: 1,
        pid: process.pid,
        head: C0,
        ref: 'refs/heads/main',
        tree: current.tree,
        parents: [C0],
        approval: path.basename(run),
        approvalSha256: sha(fs.readFileSync(path.join(run, 'finalization', 'approval.json'))),
        writtenAt: new Date().toISOString(),
      }),
      { mode: 0o600 }
    );
    const hooked = spawnSync(
      process.execPath,
      [guardScript, '--reference-transaction', 'prepared'],
      { cwd: r.root, input: `${C0} ${exact} refs/heads/main\n`, encoding: 'utf8', env: gitEnv }
    );
    return { verified, hooked, intentLeft: fs.existsSync(intentFile) };
  };
  const refusedHere =
    /no finalization with status pass approved that tree with that complete ordered parent vector/;
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  for (const [label, stages, options, problem] of [
    [
      'legacy: neither test-host nor runtime-identity (the earlier gate list)',
      requiredStages.filter(name => !prerequisites.includes(name)),
      {},
      /test-host is absent.*runtime-identity is absent/,
    ],
    [
      'missing: the test binary is not identified',
      requiredStages,
      { record: x => (stage(x, 'full-tests-current-runtime').runtime.sha256 = 'b'.repeat(64)) },
      /runtime-identity does not identify its Node binary/,
    ],
    [
      'duplicate: runtime-identity recorded twice',
      requiredStages,
      {
        record: x => {
          const item = stage(x, 'runtime-identity');
          x.stages.splice(x.stages.indexOf(item), 0, { ...item });
        },
      },
      /runtime-identity is recorded 2 times/,
    ],
    [
      'stale: runtime-identity begun before the run',
      requiredStages,
      {
        record: x => (stage(x, 'runtime-identity').started = new Date(now - 5000).toISOString()),
      },
      /runtime-identity has an interval outside its record's window/,
    ],
    [
      'inapplicable: test-host for another platform',
      requiredStages,
      { record: x => (stage(x, 'test-host').host.platform = 'darwin') },
      /test-host does not apply to this run/,
    ],
    [
      'extra: an executed platform-tests-current-runtime on an unidentified binary',
      requiredStages,
      {
        record: x =>
          extra(x, 'full-tests-current-runtime', 'platform-tests-current-runtime', {
            runtime: { path: '/x', version: 'v26.5.1', sha256: 'f'.repeat(64) },
          }),
      },
      /platform-tests-current-runtime is not a test stage of a maintenance run/,
    ],
    [
      'extra: an arbitrary executed stage',
      requiredStages,
      { record: x => extra(x, 'format', 'synthetic-extra-step') },
      /synthetic-extra-step is an executed stage outside the approved B35 plan/,
    ],
    [
      'extra: a command on the record-only test-host',
      requiredStages,
      {
        record: x =>
          Object.assign(stage(x, 'test-host'), {
            command: ['synthetic-fixture'],
            exit: 0,
            log: 'test-host.log',
          }),
        logs: { 'test-host': 'Synthetic completed command\n' },
      },
      /test-host is a record-only stage of the approved B35 plan, but it carries command, log, exit/,
    ],
  ]) {
    const made = make(label, stages, options);
    assert.throws(
      () => m.finalization.recordedApproval(made.run, noLint),
      error => refusal.test(error.message) && problem.test(error.message),
      label
    );
    const { verified, hooked, intentLeft } = enter(made);
    assert.equal(verified.status, 1, `${label}: --verify-commit: ${verified.stderr}`);
    assert.match(verified.stderr, refusedHere, label);
    assert.equal(hooked.status, 1, `${label}: reference-transaction: ${hooked.stderr}`);
    assert.match(hooked.stderr, refusedHere, label);
    assert.equal(intentLeft, false, label);
  }
  // A current valid maintenance approval is still accepted at both entry points: one slot,
  // finalized by this tree and passed as F would; two distinct Node 24 executables on a Node 24
  // gate (the configured Node 24 slot on another binary); and a valid run whose finalization was
  // recorded the earlier way.
  const files = {};
  const distinct = {
    files,
    record: x => Object.assign(files, m.securityRun.distinctNode24Slot(x, now)),
  };
  const valid = [
    ['one slot, finalized now', make('valid one slot', requiredStages, {}, { finalized: true })],
    [
      'two distinct Node 24 executables, finalized now',
      make('valid two Node 24 executables', twoSlot, distinct, { finalized: true }),
    ],
    ['one slot, recorded the earlier way', make('valid recorded earlier', requiredStages)],
  ];
  for (const [label, made] of valid) {
    assert.equal(m.finalization.recordedApproval(made.run, noLint).approval.status, 'pass', label);
    const { verified, hooked, intentLeft } = enter(made);
    assert.equal(verified.status, 0, `${label}: --verify-commit: ${verified.stderr}`);
    assert.match(
      verified.stdout,
      /has the tree and complete ordered parent vector its finalization approved/,
      label
    );
    assert.equal(hooked.status, 0, `${label}: reference-transaction: ${hooked.stderr}`);
    assert.equal(intentLeft, false, label);
  }
  const executables = m.finalization.readSealedRun(valid[1][1].run).record;
  assert.deepEqual(
    stage(executables, 'runtime-identity').runtimes.map(item => item.version),
    ['v24.21.0', 'v24.21.0']
  );
  assert.notEqual(
    stage(executables, 'full-tests-current-runtime').runtime.sha256,
    stage(executables, 'full-tests-minimum-runtime').runtime.sha256
  );
});

// gate-draft-r8, round 2 (GDR7-FIN-01 and GDR7-AUTH-01; the internal check of the eighth round,
// check-1's EN1 and EN3, O2 and O3): at both entry points, a recorded maintenance approval of a run
// with an execution nested in a stage's `steps`, or with a withheld or failed test stage, approves
// nothing, and HEAD would not move; a current valid approval is still accepted at both. Each case
// is its own staged tree on C0, as in the test above.
test('GDR7-AUTH-01, round 2: --verify-commit and the reference-transaction hook give no authority to a recorded maintenance approval of a run with an execution nested in a stage record or a withheld or failed test stage', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('first');
  const now = Date.now();
  const { requiredStages } = m.finalization;
  const stage = (record, name) => record.stages.find(item => item.name === name);
  const at = new Date(now - 1500).toISOString();
  const step = (name, change = {}) => ({
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
  const unidentified = { path: '/x', version: 'v26.5.1', sha256: 'f'.repeat(64) };
  const totals = { tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const nestedTest = name => ({
    record: x =>
      (stage(x, name).steps = [
        step('platform-tests-current-runtime', { tests: totals, runtime: unidentified }),
      ]),
    files: { 'platform-tests-current-runtime.nested.log': 'Synthetic completed command\n' },
  });
  const folder = path.join(r.security, 'commit-intents');
  fs.mkdirSync(folder, { mode: 0o700 });
  const intentFile = path.join(folder, `${process.pid}.json`);
  let count = 0;
  const make = (label, stages, options = {}, { finalized = false } = {}) => {
    r.write(`gdr7-round-2-case-${(count += 1)}.txt`, `${label}\n`);
    r.git('add', '-A');
    const current = m.securityRun.candidate(r.root);
    const run = path.join(r.security, `${current.tree}-commit-gdr7-round-2-${count}`);
    if (finalized) m.securityRun.finalizedRun(run, current, stages, now, options);
    else {
      m.securityRun.writeRun(run, current, stages, now, options);
      m.securityRun.recordedFinalization(run, current, now);
    }
    const exact = r.git('commit-tree', current.tree, '-p', C0, '-m', label);
    return { run, current, exact };
  };
  const enter = ({ run, current, exact }) => {
    const verified = r.guard('--verify-commit', exact);
    fs.writeFileSync(
      intentFile,
      JSON.stringify({
        schemaVersion: 1,
        pid: process.pid,
        head: C0,
        ref: 'refs/heads/main',
        tree: current.tree,
        parents: [C0],
        approval: path.basename(run),
        approvalSha256: sha(fs.readFileSync(path.join(run, 'finalization', 'approval.json'))),
        writtenAt: new Date().toISOString(),
      }),
      { mode: 0o600 }
    );
    const hooked = spawnSync(
      process.execPath,
      [guardScript, '--reference-transaction', 'prepared'],
      { cwd: r.root, input: `${C0} ${exact} refs/heads/main\n`, encoding: 'utf8', env: gitEnv }
    );
    return { verified, hooked, intentLeft: fs.existsSync(intentFile) };
  };
  const refusedHere =
    /no finalization with status pass approved that tree with that complete ordered parent vector/;
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  const head = r.git('rev-parse', 'HEAD');
  for (const [label, stages, options, problem] of [
    [
      'EN1: record-only test-host carrying a nested executed test step on an unidentified binary',
      requiredStages,
      nestedTest('test-host'),
      /test-host holds a test execution at steps\[0\]/,
    ],
    [
      'EN3: test slot carrying a nested second test execution on an unidentified binary',
      requiredStages,
      nestedTest('full-tests-current-runtime'),
      /full-tests-current-runtime holds a test execution at steps\[0\]/,
    ],
    [
      'O2: full-tests-current-runtime withheld (pending, nothing ran)',
      requiredStages,
      {
        record: x => {
          const item = stage(x, 'full-tests-current-runtime');
          for (const key of Object.keys(item))
            if (!['name', 'started', 'finished'].includes(key)) delete item[key];
          Object.assign(item, { status: 'pending', reason: 'withheld before dispatch: synthetic' });
        },
      },
      /stage results: full-tests-current-runtime is pending/,
    ],
    [
      'O3: full-tests-current-runtime failed (exit 1)',
      requiredStages,
      {
        record: x =>
          Object.assign(stage(x, 'full-tests-current-runtime'), { status: 'blocked', exit: 1 }),
      },
      /stage results: full-tests-current-runtime did not pass/,
    ],
  ]) {
    const made = make(label, stages, options);
    assert.throws(
      () => m.finalization.recordedApproval(made.run, noLint),
      error => refusal.test(error.message) && problem.test(error.message),
      label
    );
    const { verified, hooked, intentLeft } = enter(made);
    assert.equal(verified.status, 1, `${label}: --verify-commit: ${verified.stderr}`);
    assert.match(verified.stderr, refusedHere, label);
    assert.equal(hooked.status, 1, `${label}: reference-transaction: ${hooked.stderr}`);
    assert.match(hooked.stderr, refusedHere, label);
    assert.equal(intentLeft, false, label);
    assert.equal(r.git('rev-parse', 'HEAD'), head, `${label}: HEAD has not moved`);
  }
  // A current valid maintenance approval is still accepted at both entry points.
  const made = make('valid one slot, round 2', requiredStages, {}, { finalized: true });
  assert.equal(m.finalization.recordedApproval(made.run, noLint).approval.status, 'pass');
  const { verified, hooked, intentLeft } = enter(made);
  assert.equal(verified.status, 0, `--verify-commit: ${verified.stderr}`);
  assert.match(
    verified.stdout,
    /has the tree and complete ordered parent vector its finalization approved/
  );
  assert.equal(hooked.status, 0, `reference-transaction: ${hooked.stderr}`);
  assert.equal(intentLeft, false);
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r9 at the authority entry points: programmatic verifyCommit(), `--verify-commit` and
// the reference-transaction hook's prepared check. Each case is a commit object made with
// commit-tree on the parents it names, with a sealed maintenance run and its finalization in the
// fixture repository's orbit-security folder; none moves a ref.

/** The three authority entry points for one commit of `r`, with the intent the guard records. */
async function authorityEntryPoints(r, { run, tree, parents, commit }, env = {}) {
  const checker = await import('../scripts/check-security-approval.mjs');
  const saved = {};
  for (const [name, value] of Object.entries(env)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  let programmatic;
  try {
    checker.verifyCommit(commit, r.root);
    programmatic = { accepted: true, message: '' };
  } catch (error) {
    programmatic = { accepted: false, message: error.message };
  } finally {
    for (const [name, value] of Object.entries(saved))
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  }
  const cli = spawnSync(process.execPath, [guardScript, '--verify-commit', commit], {
    cwd: r.root,
    encoding: 'utf8',
    env: { ...gitEnv, ...env },
  });
  const folder = path.join(r.security, 'commit-intents');
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const intentFile = path.join(folder, `${process.pid}.json`);
  fs.writeFileSync(
    intentFile,
    JSON.stringify({
      schemaVersion: 1,
      pid: process.pid,
      head: parents[0],
      ref: 'refs/heads/main',
      tree,
      parents,
      approval: path.basename(run),
      approvalSha256: sha(fs.readFileSync(path.join(run, 'finalization', 'approval.json'))),
      writtenAt: new Date().toISOString(),
    }),
    { mode: 0o600 }
  );
  const hook = spawnSync(process.execPath, [guardScript, '--reference-transaction', 'prepared'], {
    cwd: r.root,
    input: `${parents[0]} ${commit} refs/heads/main\n`,
    encoding: 'utf8',
    env: { ...gitEnv, ...env },
  });
  return { programmatic, cli, hook, intentLeft: fs.existsSync(intentFile) };
}

let indexes = 0;
/**
 * A commit on `parents` whose tree is the first parent's with `files` written (path -> text, null
 * to remove, { gitlink: <commit id> } for a submodule entry, or { link: <target> } for a symbolic
 * link entry, gate-draft-r10; { bytes: <Buffer> } for a regular file of exactly those bytes,
 * round 2), built in a temporary index of its
 * own, so the checkout, its index, HEAD and MERGE_HEAD are untouched. Returns { tree, commit, parents }.
 */
function commitOn(r, parents, files, message) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-parents-index-'));
  const env = { ...gitEnv, GIT_INDEX_FILE: path.join(folder, `index-${(indexes += 1)}`) };
  const git = (args, input) =>
    execFileSync('git', ['-C', r.root, ...args], { env, input, encoding: 'utf8' }).trim();
  try {
    git(['read-tree', parents[0]]);
    for (const [file, text] of Object.entries(files)) {
      if (text === null) git(['update-index', '--force-remove', file]);
      else if (typeof text === 'object' && text.bytes !== undefined)
        git([
          'update-index',
          '--add',
          '--cacheinfo',
          `100644,${git(['hash-object', '-w', '--stdin'], text.bytes)},${file}`,
        ]);
      else if (typeof text === 'object' && text.link !== undefined)
        git([
          'update-index',
          '--add',
          '--cacheinfo',
          `120000,${git(['hash-object', '-w', '--stdin'], text.link)},${file}`,
        ]);
      else if (typeof text === 'object')
        git(['update-index', '--add', '--cacheinfo', `160000,${text.gitlink},${file}`]);
      else
        git([
          'update-index',
          '--add',
          '--cacheinfo',
          `100644,${git(['hash-object', '-w', '--stdin'], text)},${file}`,
        ]);
    }
    const tree = git(['write-tree']);
    return {
      tree,
      parents,
      commit: git(['commit-tree', tree, ...parents.flatMap(item => ['-p', item]), '-m', message]),
    };
  } finally {
    fs.rmSync(folder, { recursive: true, force: true });
  }
}

// The regular files of `tree`, as sourceManifest lists them (gate-draft-r10: a subject can hold a
// gitlink or a symbolic link at package.json, which is not a file of a run's source manifest).
function regularFiles(r, tree) {
  return execFileSync('git', ['-C', r.root, 'ls-tree', '-rz', '--full-tree', tree], {
    encoding: 'utf8',
    env: gitEnv,
  })
    .split('\0')
    .filter(Boolean)
    .map(entry => /^(100644|100755) blob ([0-9a-f]+)\t(.+)$/s.exec(entry))
    .filter(Boolean)
    .map(([, mode, blob, file]) => ({
      file,
      mode,
      blob,
      sha256: sha(
        execFileSync('git', ['-C', r.root, 'cat-file', 'blob', blob], {
          env: gitEnv,
          maxBuffer: 64 * 1024 ** 2,
        })
      ),
    }));
}
const canonicalPackage = scripts => `${JSON.stringify({ scripts }, null, 2)}\n`;
const sqlScript = { 'lint:sql': 'node scripts/sql-lint.mjs' };
const importScript = { 'lint:imports': 'node scripts/import-graph.mjs' };
const bothLint = ['sql-lint', 'import-lint'];
const refusedAtEntry =
  /no finalization with status pass approved that tree with that complete ordered parent vector/;

/** A subject maker for one fixture repository: its commit, its sealed run and the three answers. */
function subjects(m, r, now) {
  let count = 0;
  return async (parents, files, stages, { finalized = true, env, run: change = {} } = {}) => {
    const made = commitOn(
      r,
      parents,
      { ...files, [`case-${(count += 1)}.txt`]: `${count}\n` },
      `case ${count}`
    );
    const current = {
      tree: made.tree,
      parent: parents[0],
      parents,
      refs: r.git('for-each-ref', '--format=%(refname) %(objectname)'),
      files: regularFiles(r, made.tree),
    };
    const run = path.join(r.security, `${made.tree}-commit-r9-${count}`);
    if (finalized) m.securityRun.finalizedRun(run, current, stages, now, change.options ?? {});
    else {
      m.securityRun.writeRun(run, current, stages, now, change.options ?? {});
      m.securityRun.recordedFinalization(run, current, now, change.recorded ?? {});
    }
    return { ...made, run, current, ...(await authorityEntryPoints(r, { ...made, run }, env)) };
  };
}

/** Asserts that all three entry points accepted the commit. */
function acceptedAtEntry(label, outcome) {
  assert.equal(
    outcome.programmatic.accepted,
    true,
    `${label}: verifyCommit: ${outcome.programmatic.message}`
  );
  assert.equal(outcome.cli.status, 0, `${label}: --verify-commit: ${outcome.cli.stderr}`);
  assert.match(
    outcome.cli.stdout,
    /has the tree and complete ordered parent vector its finalization approved/,
    label
  );
  assert.equal(outcome.hook.status, 0, `${label}: reference-transaction: ${outcome.hook.stderr}`);
  assert.equal(outcome.intentLeft, false, label);
}

/** Asserts that all three entry points refused the commit, each naming `pattern`. */
function refusedAtEntryPoints(label, outcome, pattern) {
  assert.equal(outcome.programmatic.accepted, false, `${label}: verifyCommit accepted it`);
  assert.match(outcome.programmatic.message, pattern, `${label}: verifyCommit`);
  assert.equal(outcome.cli.status, 1, `${label}: --verify-commit: ${outcome.cli.stderr}`);
  assert.match(outcome.cli.stderr, pattern, `${label}: --verify-commit`);
  assert.equal(outcome.hook.status, 1, `${label}: reference-transaction: ${outcome.hook.stderr}`);
  assert.match(outcome.hook.stderr, pattern, `${label}: reference-transaction`);
  assert.equal(outcome.intentLeft, false, label);
}

// gate-draft-r9, GDR8-AUTH-LINT-01 (a carried obligation; the maintainer's decision 1): the
// pre-commit guard derives the lint stages a candidate requires from its package.json and its
// parents' history, but verifyCommit, behind `--verify-commit` and the reference-transaction hook,
// derived none, so a recorded maintenance approval of a run without `sql-lint` gave authority to a
// commit whose own package.json defines `lint:sql` (check-1's O5). verifyCommit now derives the
// requirement from the exact commit, its complete ordered parents and their history, with its
// root-bound hardened Git runner (commitLintStages), and gives only that to recordedApproval. The
// checkout here is made to disagree with every subject: HEAD is a commit that defines both lint
// scripts, MERGE_HEAD names another, and the staged and working package.json define both, so a
// requirement read from the checkout would refuse every no-lint positive below. The guard's
// semantics are kept: removal and rename, a noncanonical package.json, an unreadable history and
// a merge's other parent (a malformed package.json refuses since round 2 of gate-draft-r10). Every fixture package.json that a case needs a lint script
// in defines it in the scripts object, as the real 1.5 package.json does.
test('GDR8-AUTH-LINT-01: verifyCommit, --verify-commit and the reference-transaction hook derive the lint stages from the exact commit, its ordered parents and their history, never from the checkout, HEAD, MERGE_HEAD, process.cwd() or a caller', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const r = repository(t);
  const C0 = r.commit('C0: package.json defines no lint script');
  const now = Date.now();
  const { requiredStages } = m.finalization;
  const withLint = names => [...requiredStages, ...names];
  const both = { ...sqlScript, ...importScript };
  // Parents and histories, none checked out.
  const sqlParent = commitOn(r, [C0], { 'package.json': canonicalPackage(sqlScript) }, 'P1');
  const importParent = commitOn(r, [C0], { 'package.json': canonicalPackage(importScript) }, 'P2');
  const plain = commitOn(r, [C0], { 'plain.txt': 'plain\n' }, 'Q: no lint script');
  const defined = commitOn(r, [C0], { 'package.json': canonicalPackage(importScript) }, 'H');
  const dropped = commitOn(
    r,
    [defined.commit],
    { 'package.json': canonicalPackage({}) },
    'P: drops lint:imports without the guard'
  );
  const compact = commitOn(r, [C0], { 'package.json': '{"scripts":{}}\n' }, 'P: noncanonical');
  // The misleading checkout: HEAD defines both lint scripts, MERGE_HEAD names another commit that
  // defines both, and the working and staged package.json define both.
  const misleading = commitOn(r, [C0], { 'package.json': canonicalPackage(both) }, 'HEAD: both');
  r.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', misleading.commit);
  const merging = commitOn(
    r,
    [C0],
    { 'package.json': canonicalPackage(both), 'm.txt': 'm\n' },
    'MERGE_HEAD: both'
  );
  fs.writeFileSync(path.join(r.root, '.git', 'MERGE_HEAD'), `${merging.commit}\n`);
  r.write('package.json', `${canonicalPackage(both)}`);
  r.write('staged.txt', 'staged\n');
  r.git('add', '-A');
  const subject = subjects(m, r, now);
  const git = (args, input) =>
    execFileSync('git', args, {
      cwd: r.root,
      env: m.platform.gitHistoryEnvironment(gitEnv),
      input,
      stdio: 'pipe',
      maxBuffer: 64 * 1024 ** 2,
    });
  const derive = made => checker.commitLintStages(git, { tree: made.tree, parents: made.parents });
  const removal =
    /Commit check refused: the commit removes lint:sql or lint:imports, which a parent of it or their history defines.*\(GDR8-AUTH-LINT-01\)/;

  // Legitimate positives: no lint anywhere; matching lint stages for what the subject defines; a
  // parent's lint script kept with its stage; a merge's other parent's lint script kept with its
  // stage. Each the requirement commitLintStages derives, and no more.
  for (const [label, parents, files, stages, derived, options] of [
    ['no lint script anywhere, a run without lint stages', [C0], {}, requiredStages, []],
    [
      'no lint script anywhere, recorded the earlier way',
      [C0],
      {},
      requiredStages,
      [],
      { finalized: false },
    ],
    [
      'the subject defines both lint scripts, the run has both lint stages',
      [C0],
      { 'package.json': canonicalPackage(both) },
      withLint(bothLint),
      bothLint,
    ],
    [
      "a parent's lint:sql kept, the run has sql-lint only",
      [sqlParent.commit],
      {},
      withLint(['sql-lint']),
      ['sql-lint'],
    ],
    [
      "a merge's other parent's lint:imports kept, the run has import-lint only",
      [plain.commit, importParent.commit],
      { 'package.json': canonicalPackage(importScript) },
      withLint(['import-lint']),
      ['import-lint'],
    ],
  ]) {
    const outcome = await subject(parents, files, stages, options);
    assert.deepEqual(derive(outcome), derived, `${label}: derived`);
    acceptedAtEntry(label, outcome);
  }

  // Refused: a stage the derived requirement names is missing from the run.
  const missing = [
    [
      'candidate-defined (check-1 O5): both lint scripts, no lint stage',
      [C0],
      { 'package.json': canonicalPackage(both) },
      requiredStages,
      bothLint,
    ],
    [
      'candidate-defined: both lint scripts, sql-lint only',
      [C0],
      { 'package.json': canonicalPackage(both) },
      withLint(['sql-lint']),
      bothLint,
    ],
    [
      "parent-defined: a parent's lint:sql kept, no sql-lint stage",
      [sqlParent.commit],
      {},
      requiredStages,
      ['sql-lint'],
    ],
    [
      "merge-other-parent: the other parent's lint:imports kept, no import-lint stage",
      [plain.commit, importParent.commit],
      { 'package.json': canonicalPackage(importScript) },
      requiredStages,
      ['import-lint'],
    ],
    [
      'a noncanonical package.json in the subject: every lint stage is required',
      [C0],
      { 'package.json': '{"scripts":{}}\n' },
      requiredStages,
      bothLint,
    ],
    ['no package.json in the subject', [C0], { 'package.json': null }, requiredStages, bothLint],
    [
      "a parent's noncanonical package.json: every lint stage is required",
      [compact.commit],
      { 'package.json': canonicalPackage({}) },
      requiredStages,
      bothLint,
    ],
  ];
  let o5;
  for (const [label, parents, files, stages, derived] of missing) {
    const outcome = await subject(parents, files, stages);
    o5 ??= outcome;
    assert.deepEqual(derive(outcome), derived, `${label}: derived`);
    refusedAtEntryPoints(label, outcome, refusedAtEntry);
    // The reason, from the reader the entry points use: a required lint stage is missing.
    assert.throws(
      () => m.finalization.recordedApproval(outcome.run, { lintStages: derived }),
      /execution plan: (?:sql|import)-lint is required of this run by the approved B35 plan and is missing/,
      label
    );
  }
  // The same approval, read for a commit that requires no lint stage, verifies: it is the
  // derived requirement that refuses it.
  assert.equal(m.finalization.recordedApproval(o5.run, noLint).approval.status, 'pass');
  // gate-draft-r10 round 2 (check-1 of GDR9-AUTH-OBJECT-01): a package.json in the subject that
  // does not parse is malformed content and refuses, even with both lint stages (it was read as
  // unknown, requiring both, and approved with them).
  const notParsing = await subject([C0], { 'package.json': '{"scripts":' }, withLint(bothLint));
  assert.throws(() => derive(notParsing), /is not well-formed JSON/);
  refusedAtEntryPoints(
    'a package.json in the subject that does not parse, the run has both lint stages',
    notParsing,
    /Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history \(Commit blocked: the package\.json of [0-9a-f]+ \(blob [0-9a-f]+\) is not well-formed JSON/
  );

  // Refused outright: a removal or a rename of a lint script that a parent or their history
  // defines, whatever the run, with a pathspec variable in the environment too.
  for (const [label, parents, files, stages, options] of [
    [
      'history-defined removal: an ancestor defined lint:imports, the parent dropped it',
      [dropped.commit],
      {},
      withLint(['import-lint']),
    ],
    [
      'the same removal with GIT_LITERAL_PATHSPECS=1 in the environment',
      [dropped.commit],
      {},
      requiredStages,
      { env: { GIT_LITERAL_PATHSPECS: '1' } },
    ],
    [
      "merge-other-parent removal: the merge drops the other parent's lint:imports",
      [plain.commit, importParent.commit],
      {},
      requiredStages,
    ],
    [
      "a rename of a parent's lint:sql",
      [sqlParent.commit],
      { 'package.json': canonicalPackage({ 'lint:sql-renamed': 'node scripts/sql-lint.mjs' }) },
      requiredStages,
    ],
    [
      "a parent's lint:sql removed through a noncanonical package.json",
      [sqlParent.commit],
      { 'package.json': '{"scripts":{}}' },
      requiredStages,
    ],
  ]) {
    const outcome = await subject(parents, files, stages, options);
    assert.throws(() => derive(outcome), removal, label);
    refusedAtEntryPoints(label, outcome, removal);
  }

  // No caller can choose the requirement: verifyCommit takes no lint option, and a recorded
  // approval cannot be read without one.
  assert.throws(() => checker.verifyCommit(o5.commit, r.root, { lintStages: [] }), refusedAtEntry);
  assert.throws(
    () => m.finalization.recordedApproval(o5.run),
    /needs the lint stages the commit requires.*\(GDR8-AUTH-LINT-01\)/
  );

  // Root different from process.cwd(): started in another repository, whose checkout defines no
  // lint script and holds none of these commits, verifyCommit(commit, root) judges root's commit.
  const other = repository(t);
  other.commit('another repository');
  const elsewhere = commit =>
    spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '--eval',
        `const m = await import(${JSON.stringify(new URL('../scripts/check-security-approval.mjs', import.meta.url).href)}); try { m.verifyCommit(${JSON.stringify(commit)}, ${JSON.stringify(r.root)}); console.log('accepted'); } catch (error) { console.log('refused: ' + error.message); }`,
      ],
      { cwd: other.root, encoding: 'utf8', env: gitEnv }
    ).stdout.trim();
  const plainSubject = await subject([C0], {}, requiredStages);
  assert.equal(elsewhere(plainSubject.commit), 'accepted');
  assert.match(elsewhere(o5.commit), /^refused: .*no finalization with status pass approved/);
  const removed = await subject([dropped.commit], {}, requiredStages);
  assert.match(elsewhere(removed.commit), /^refused: Commit check refused: the commit removes/);

  // An unreadable history: an ancestor's commit object is gone, so the walk cannot read it and
  // nothing is approved (last: it breaks the history of this repository).
  const lost = commitOn(r, [C0], { 'lost.txt': 'lost\n' }, 'L: its object will be lost');
  const afterLost = commitOn(r, [lost.commit], {}, 'P: on the lost commit');
  const unreadable = await subject([afterLost.commit], {}, requiredStages);
  assert.deepEqual(derive(unreadable), []);
  acceptedAtEntry('control: the history before its ancestor is lost', unreadable);
  fs.rmSync(path.join(r.root, '.git', 'objects', lost.commit.slice(0, 2), lost.commit.slice(2)));
  assert.throws(() => derive(unreadable));
  refusedAtEntryPoints(
    'an unreadable history: an ancestor commit object is missing',
    await authorityEntryPoints(r, unreadable),
    /Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history .*\(GDR8-AUTH-LINT-01\)/
  );
});

// gate-draft-r9, GDR8-AUTH-SCAN-01 and GDR8-SCHEMA-01 at the authority entry points (the security review's
// probes P2 and P3 on gate-draft-r8): a recorded maintenance approval of a run whose sealed scanner
// results the finalizer refuses (an empty report under a finding exit, a missing or malformed
// report, a real finding the approval does not count), or whose stage record holds a member its
// closed schema does not have (`test-host.host.probe = { argv, exitCode }`), approves nothing at
// verifyCommit, `--verify-commit` or the reference-transaction hook; a genuine finding with its
// finding exit and a complete retained disposition is still accepted at all three.
test('GDR8-AUTH-SCAN-01 and GDR8-SCHEMA-01: verifyCommit, --verify-commit and the reference-transaction hook refuse a recorded approval whose sealed scanner results or nested record members the finalizer refuses, and accept a genuine disposed finding', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('C0: package.json defines no lint script');
  const now = Date.now();
  const { requiredStages } = m.finalization;
  const subject = subjects(m, r, now);
  const stage = (record, name) => record.stages.find(item => item.name === name);
  const blocked = record =>
    Object.assign(stage(record, 'secrets-history'), { status: 'blocked', exit: 10 });
  const finding = JSON.stringify([m.securityRun.historyFinding()]);
  const earlier = (options, recorded = {}) => ({ finalized: false, run: { options, recorded } });
  const refusal =
    /^The recorded maintenance \(B35\) approval is of a run the current B35 rules refuse, so it gives no authority now \(GDR7-AUTH-01\): /;
  for (const [label, options, problem] of [
    [
      "P2 (the security review's probe): an empty report, the stage blocked with exit 10",
      earlier({ record: blocked }),
      /scanner results: secrets-history: Scanner exit and findings disagree/,
    ],
    [
      'a missing report',
      earlier({ omit: ['secrets-history.json'] }),
      /scanner results: secrets-history: Scanner report is missing/,
    ],
    [
      'a malformed report',
      earlier({ files: { 'secrets-history.json': '[{' } }),
      /scanner results: secrets-history: Cannot parse scanner report/,
    ],
    [
      'a real finding with the finding exit but status pass, disposed of',
      earlier(
        {
          record: x => Object.assign(stage(x, 'secrets-history'), { status: 'pass', exit: 10 }),
          files: { 'secrets-history.json': finding },
        },
        { dispose: findings => findings }
      ),
      /scanner results: secrets-history: Scanner status and findings disagree/,
    ],
    [
      'a real finding the approval counts as none',
      earlier({ record: blocked, files: { 'secrets-history.json': finding } }),
      /The recorded approval counts 0 findings, but its sealed scanner reports give 1/,
    ],
    [
      'a real finding disposed of under another id',
      earlier(
        { record: blocked, files: { 'secrets-history.json': finding } },
        { dispose: () => [{ id: '0'.repeat(64) }] }
      ),
      /The retained review does not dispose of exactly the findings the sealed scanner reports give/,
    ],
    [
      "P3 (the security review's probe): test-host.host.probe = { argv, exitCode }",
      earlier({
        record: x => (stage(x, 'test-host').host.probe = { argv: ['node', '--test'], exitCode: 0 }),
      }),
      /test-host\.host holds "probe", which its closed schema does not have \(GDR8-SCHEMA-01\)/,
    ],
  ]) {
    const outcome = await subject([C0], {}, requiredStages, options);
    assert.throws(
      () => m.finalization.recordedApproval(outcome.run, noLint),
      error =>
        problem.test(error.message) &&
        (refusal.test(error.message) || /\(GDR8-AUTH-SCAN-01\)/.test(error.message)),
      label
    );
    refusedAtEntryPoints(label, outcome, refusedAtEntry);
    assert.equal(r.git('rev-parse', 'HEAD'), C0, `${label}: HEAD has not moved`);
  }
  // Still accepted at all three: a real finding with Gitleaks' finding exit and status blocked,
  // with one complete retained disposition, recorded the earlier way and finalized by this tree.
  for (const [label, options] of [
    [
      'a disposed finding, recorded the earlier way',
      earlier(
        { record: blocked, files: { 'secrets-history.json': finding } },
        { dispose: findings => findings }
      ),
    ],
    [
      'a disposed finding, finalized by this tree and passed as F would',
      {
        run: {
          options: { record: blocked, files: { 'secrets-history.json': finding }, dispose: true },
        },
      },
    ],
  ]) {
    const outcome = await subject([C0], {}, requiredStages, options);
    assert.equal(m.finalization.recordedApproval(outcome.run, noLint).approval.findings, 1, label);
    acceptedAtEntry(label, outcome);
  }
});

// gate-draft-r9, round 2 (check-1 of gate-draft-r9, LINT-U1; GDR8-AUTH-LINT-01): the history
// parser that the pre-commit guard and verifyCommit share (historyLintScripts) read Git's
// "<commit>:package.json missing" answer as a version without package.json, also when the commit's
// tree names a package.json whose object is not in the repository (a partial or damaged clone). So
// when the only version that defined lint:sql had lost its object, the lint requirement and the
// removal refusal both disappeared: verifyCommit, --verify-commit and the reference-transaction
// hook accepted a removal with no lint stage, and the pre-commit guard accepted the candidate the
// same way. Now each "missing" answer is looked up in its commit's tree: a version without the
// file still defines nothing; an entry whose object cannot be read refuses at every entry point,
// and once the object is back the removal is refused as before. Each object is moved aside and
// back, never deleted.
test('GDR8-AUTH-LINT-01, round 2 (check-1 LINT-U1): a history version whose package.json object is missing from the repository refuses, at verifyCommit, --verify-commit, the reference-transaction hook and the pre-commit guard, instead of reading as a version without package.json', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const r = repository(t);
  const C0 = r.commit('C0: package.json defines no lint script');
  const now = Date.now();
  const { requiredStages } = m.finalization;
  const withLint = names => [...requiredStages, ...names];
  const subject = subjects(m, r, now);
  const git = (args, input) =>
    execFileSync('git', args, {
      cwd: r.root,
      env: m.platform.gitHistoryEnvironment(gitEnv),
      input,
      stdio: 'pipe',
      maxBuffer: 64 * 1024 ** 2,
    });
  const derive = made => checker.commitLintStages(git, { tree: made.tree, parents: made.parents });
  const removal =
    /Commit check refused: the commit removes lint:sql or lint:imports, which a parent of it or their history defines.*\(GDR8-AUTH-LINT-01\)/;
  const unreadableVersion =
    'the package\\.json of [0-9a-f]+ \\(blob [0-9a-f]+\\) cannot be read from this repository, so the lint scripts that version defines cannot be judged; fetch or repair the missing objects first';
  const lost = new RegExp(
    `Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history \\(Commit blocked: ${unreadableVersion}\\), so nothing is approved for it \\(GDR8-AUTH-LINT-01\\)\\.`
  );
  // The loose object of `root`'s package.json at `commit`, moved aside while `action` runs.
  const aside = async (root, commit, action) => {
    const blob = execFileSync('git', ['-C', root, 'rev-parse', `${commit}:package.json`], {
      encoding: 'utf8',
      env: gitEnv,
    }).trim();
    const file = path.join(root, '.git', 'objects', blob.slice(0, 2), blob.slice(2));
    assert.ok(fs.statSync(file).isFile(), 'the version is a loose object');
    fs.renameSync(file, `${file}.aside`);
    try {
      return await action();
    } finally {
      fs.renameSync(`${file}.aside`, file);
    }
  };
  // The only version of package.json that defines lint:sql (its bytes are no other version's).
  const only = commitOn(
    r,
    [C0],
    { 'package.json': canonicalPackage({ ...sqlScript, note: 'the only version, verifyCommit' }) },
    'H: the only version that defines lint:sql'
  );
  const dropped = commitOn(
    r,
    [only.commit],
    { 'package.json': canonicalPackage({}) },
    'P: drops lint:sql without the guard'
  );

  for (const [label, parents, files, stages] of [
    [
      "LINT-U1: an ancestor's lint:sql removed by the parent, the run without lint stages",
      [dropped.commit],
      {},
      requiredStages,
    ],
    [
      "the subject removes its parent's lint:sql, the run with both lint stages",
      [only.commit],
      { 'package.json': canonicalPackage({}) },
      withLint(bothLint),
    ],
  ]) {
    const outcome = await subject(parents, files, stages);
    // With the object present: the removal is refused outright.
    assert.throws(() => derive(outcome), removal, `${label}: control`);
    refusedAtEntryPoints(`${label}: control`, outcome, removal);
    // With it missing: refused, never read as a version without package.json.
    await aside(r.root, only.commit, async () => {
      assert.throws(() => derive(outcome), new RegExp(unreadableVersion), label);
      refusedAtEntryPoints(label, await authorityEntryPoints(r, outcome), lost);
    });
    // Back again: the removal, as before.
    refusedAtEntryPoints(`${label}: object back`, await authorityEntryPoints(r, outcome), removal);
  }

  // Still accepted: a history version without package.json, and a parent without one, define
  // nothing, as before; only a package.json that cannot be read refuses.
  const without = commitOn(r, [C0], { 'package.json': null }, 'D: removes package.json');
  const again = commitOn(
    r,
    [without.commit],
    { 'package.json': canonicalPackage({}) },
    'E: package.json again, no lint script'
  );
  for (const [label, parents, stages, derived] of [
    [
      'a history version without package.json, the run without lint stages',
      [again.commit],
      requiredStages,
      [],
    ],
    [
      'a parent without package.json (every lint stage required), the run with both',
      [without.commit],
      withLint(bothLint),
      bothLint,
    ],
  ]) {
    const outcome = await subject(parents, {}, stages);
    assert.deepEqual(derive(outcome), derived, `${label}: derived`);
    acceptedAtEntry(label, outcome);
  }
  // Refused, as before this round (fail closed): a submodule at package.json in the history,
  // whose content this repository never holds. gate-draft-r10 (GDR9-AUTH-OBJECT-01): the typed
  // lookup reads the entry from the version's own tree, so it is refused as a submodule whatever
  // `<commit>:package.json` would answer (the readable-gitlink case is in the GDR9 test below).
  const submodule = commitOn(
    r,
    [C0],
    { 'package.json': { gitlink: 'b'.repeat(40) } },
    'G: a submodule at package.json'
  );
  const afterSubmodule = commitOn(
    r,
    [submodule.commit],
    { 'package.json': canonicalPackage({}) },
    'F: package.json again after the submodule'
  );
  const gitlinked = await subject([afterSubmodule.commit], {}, requiredStages);
  assert.throws(
    () => derive(gitlinked),
    /the package\.json of [0-9a-f]+ is a submodule \(gitlink to commit b{40}\), not a regular file/
  );
  refusedAtEntryPoints(
    'a history version with a submodule at package.json',
    gitlinked,
    /Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history \(Commit blocked: the package\.json of [0-9a-f]+ is a submodule \(gitlink to commit b{40}\), not a regular file/
  );

  // The pre-commit guard (the checker with no option, as the hooks run it) shares the parser.
  const p = repository(t);
  p.commit('C0: package.json defines no lint script');
  p.write('package.json', canonicalPackage({ ...sqlScript, note: 'the only version, guard' }));
  const definer = p.commit('H: the only version that defines lint:sql');
  p.write('package.json', canonicalPackage({}));
  p.commit('P: drops lint:sql without the guard');
  const removes = /^Commit blocked: the candidate removes lint:sql or lint:imports/;
  const unreadable = new RegExp(`^Commit blocked: ${unreadableVersion}`);
  const judged = (label, pattern) => {
    const result = p.guard();
    assert.equal(result.status, 1, `${label}: ${result.stderr}`);
    assert.match(result.stderr, pattern, label);
  };
  // An ancestor's lint:sql removed by HEAD; the candidate approved by a run without lint stages.
  p.write('candidate.txt', 'candidate\n');
  p.git('add', '-A');
  approveStaged(m, p);
  judged('pre-commit, LINT-U1 shape: control', removes);
  await aside(p.root, definer, () => judged('pre-commit, LINT-U1 shape', unreadable));
  judged('pre-commit, LINT-U1 shape: object back', removes);
  // HEAD defines lint:sql and the candidate removes it; the run has both lint stages.
  p.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', definer);
  p.write('package.json', canonicalPackage({}));
  p.write('candidate-2.txt', 'candidate 2\n');
  p.git('add', '-A');
  const staged = m.securityRun.candidate(p.root);
  m.securityRun.finalizedRun(
    path.join(p.security, `${staged.tree}-commit-both`),
    staged,
    m.securityRun.allStages
  );
  judged("pre-commit, the candidate removes HEAD's lint:sql: control", removes);
  await aside(p.root, definer, () =>
    judged("pre-commit, the candidate removes HEAD's lint:sql", unreadable)
  );
  judged("pre-commit, the candidate removes HEAD's lint:sql: object back", removes);
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r10: the security review of gate-draft-r9 (GDR9-AUTH-ROOT-01, GDR9-AUTH-OBJECT-01,
// GDR9-AUTH-SCAN-02 and GDR9-HOST-SCHEMA-01, review findings) at the authority entry points.

/**
 * The three authority entry points for `made` ({ commit, tree, parents, run }) with `root` the
 * explicit root, started in `cwd` with `env` added to the environment (and `prefix` before PATH),
 * the reference-transaction record placed in the git common folder `intents`, where the hook
 * script, run with the same environment, would find it. The record is removed afterwards whatever
 * the hook did. Returns { programmatic, cli, hook }.
 */
async function boundEntryPoints(made, { root, cwd = root, env = {}, intents, prefix } = {}) {
  const checker = await import('../scripts/check-security-approval.mjs');
  const extra = { ...env, ...(prefix ? { PATH: `${prefix}${path.delimiter}${gitEnv.PATH}` } : {}) };
  const saved = {};
  for (const [name, value] of Object.entries(extra)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  const before = process.cwd();
  let programmatic;
  try {
    process.chdir(cwd);
    checker.verifyCommit(made.commit, root);
    programmatic = { accepted: true, message: '' };
  } catch (error) {
    programmatic = { accepted: false, message: error.message };
  } finally {
    process.chdir(before);
    for (const [name, value] of Object.entries(saved))
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  }
  const childEnv = { ...gitEnv, ...extra };
  const cli = spawnSync(process.execPath, [guardScript, '--verify-commit', made.commit], {
    cwd,
    encoding: 'utf8',
    env: childEnv,
  });
  const folder = path.join(intents, 'orbit-security', 'commit-intents');
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const intentFile = path.join(folder, `${process.pid}.json`);
  fs.writeFileSync(
    intentFile,
    JSON.stringify({
      schemaVersion: 1,
      pid: process.pid,
      head: made.parents[0],
      ref: 'refs/heads/main',
      tree: made.tree,
      parents: made.parents,
      approval: path.basename(made.run),
      approvalSha256: sha(fs.readFileSync(path.join(made.run, 'finalization', 'approval.json'))),
      writtenAt: new Date().toISOString(),
    }),
    { mode: 0o600 }
  );
  const hook = spawnSync(process.execPath, [guardScript, '--reference-transaction', 'prepared'], {
    cwd,
    input: `${made.parents[0]} ${made.commit} refs/heads/main\n`,
    encoding: 'utf8',
    env: childEnv,
  });
  fs.rmSync(intentFile, { force: true });
  return { programmatic, cli, hook };
}
function acceptedEverywhere(label, outcome) {
  assert.equal(
    outcome.programmatic.accepted,
    true,
    `${label}: verifyCommit: ${outcome.programmatic.message}`
  );
  assert.equal(outcome.cli.status, 0, `${label}: --verify-commit: ${outcome.cli.stderr}`);
  assert.equal(outcome.hook.status, 0, `${label}: reference-transaction: ${outcome.hook.stderr}`);
}
function refusedEverywhere(label, outcome, pattern) {
  assert.equal(outcome.programmatic.accepted, false, `${label}: verifyCommit accepted it`);
  assert.match(outcome.programmatic.message, pattern, `${label}: verifyCommit`);
  assert.equal(outcome.cli.status, 1, `${label}: --verify-commit: ${outcome.cli.stderr}`);
  assert.match(outcome.cli.stderr, pattern, `${label}: --verify-commit`);
  assert.equal(outcome.hook.status, 1, `${label}: reference-transaction: ${outcome.hook.stderr}`);
  assert.match(outcome.hook.stderr, pattern, `${label}: reference-transaction`);
}
// Moves the loose object `id` of the git directory `gitDir` to `to` (a folder holding objects),
// and returns the function that moves it back.
function moveObject(gitDir, id, to) {
  const from = path.join(gitDir, 'objects', id.slice(0, 2), id.slice(2));
  const target = path.join(to, id.slice(0, 2), id.slice(2));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.renameSync(from, target);
  return () => fs.renameSync(target, from);
}

// GDR9-AUTH-ROOT-01 (review finding): verifyCommit(commit, root) copied process.env and ran Git
// with cwd: root, so an inherited GIT_DIR and GIT_WORK_TREE selected another repository, whose
// approved commit it accepted (the security review's P1), and checkReferenceTransaction found its common
// folder with the ambient Git. Every authority read now goes through one runner bound to the
// canonical root (bindRepository): an inherited selector naming another repository, working tree
// or common directory, an object source other than the repository's own quarantine and a
// GIT_NAMESPACE refuse at all three entry points; one naming the bound repository itself, a
// linked worktree (as Git runs its hooks there) and the repository's own receive-pack quarantine
// are accepted; and commits made through the installed hooks in a linked worktree, with commit -a
// and with commit <paths> still go through.
test('GDR9-AUTH-ROOT-01: one runner bound to the explicit root reads every authority input; an inherited selector naming another repository, a foreign object source or GIT_NAMESPACE refuses at verifyCommit, --verify-commit and the reference-transaction hook, and a linked worktree, the bound repository itself and its own quarantine stay accepted', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const { requiredStages } = m.finalization;
  const a = repository(t);
  a.commit('A: C0');
  const b = repository(t);
  const b0 = b.commit('B: C0');
  const made = await subjects(m, b, Date.now())([b0], {}, requiredStages);
  acceptedAtEntry("control: B's approved commit, root B, a clean environment", made);
  const authoritySubdirectory = path.join(b.root, 'authority-subdirectory');
  fs.mkdirSync(authoritySubdirectory);
  acceptedEverywhere(
    'a subdirectory of B still binds B, with no inherited selector',
    await boundEntryPoints(made, {
      root: authoritySubdirectory,
      intents: path.join(b.root, '.git'),
    })
  );
  const aGit = path.join(a.root, '.git');
  const bGit = path.join(b.root, '.git');
  const selector =
    /cannot be bound: the inherited (?:GIT_DIR|GIT_WORK_TREE|GIT_COMMON_DIR) names .*an inherited selector cannot choose another repository, working tree or common directory for the authority \(GDR9-AUTH-ROOT-01\)/;
  for (const [label, env] of [
    [
      "The security review's P1: root A, inherited GIT_DIR and GIT_WORK_TREE select B",
      { GIT_DIR: bGit, GIT_WORK_TREE: b.root },
    ],
    ['root A, an inherited GIT_DIR alone selects B', { GIT_DIR: bGit }],
    ['root A, an inherited GIT_COMMON_DIR alone selects B', { GIT_COMMON_DIR: bGit }],
    ["root A, an inherited GIT_WORK_TREE names B's working tree", { GIT_WORK_TREE: b.root }],
  ])
    refusedEverywhere(
      label,
      await boundEntryPoints(made, { root: a.root, env, intents: bGit }),
      selector
    );
  // The bound repository named by an inherited selector, absolute or relative: accepted.
  acceptedEverywhere(
    'root B, an inherited GIT_DIR naming B',
    await boundEntryPoints(made, { root: b.root, env: { GIT_DIR: bGit }, intents: bGit })
  );
  acceptedEverywhere(
    'root B, an inherited relative GIT_DIR=.git and GIT_WORK_TREE=. from B',
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_DIR: '.git', GIT_WORK_TREE: '.' },
      intents: bGit,
    })
  );
  // A linked worktree of B: Git gives its hooks GIT_DIR, the worktree's own git directory.
  const worktree = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-worktree-')));
  fs.rmdirSync(worktree);
  t.after(() => fs.rmSync(worktree, { recursive: true, force: true }));
  b.git('worktree', 'add', '--quiet', '--detach', worktree, b0);
  const linked = fs.realpathSync(path.join(bGit, 'worktrees', path.basename(worktree)));
  acceptedEverywhere(
    'root a linked worktree of B, a clean environment',
    await boundEntryPoints(made, { root: worktree, intents: bGit })
  );
  acceptedEverywhere(
    "root a linked worktree of B, GIT_DIR its own git directory, as Git runs the worktree's hooks",
    await boundEntryPoints(made, { root: worktree, env: { GIT_DIR: linked }, intents: bGit })
  );
  refusedEverywhere(
    "root a linked worktree of B, GIT_DIR the main worktree's git directory",
    await boundEntryPoints(made, { root: worktree, env: { GIT_DIR: bGit }, intents: bGit }),
    selector
  );
  // The object source. The commit object moved out of B is not readable from B: refused.
  const objectSource =
    /cannot be bound: the inherited (?:GIT_\w+(?:, )?)+ names? an object source other than the repository's own object directory .* \(GDR9-AUTH-ROOT-01\)/;
  const foreign = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-store-')));
  t.after(() => fs.rmSync(foreign, { recursive: true, force: true }));
  const back = moveObject(bGit, made.commit, foreign);
  refusedEverywhere(
    'control: the commit object is not in B',
    await boundEntryPoints(made, { root: b.root, intents: bGit }),
    /rev-parse --verify/
  );
  refusedEverywhere(
    'an inherited GIT_ALTERNATE_OBJECT_DIRECTORIES supplies the commit object from a store outside B',
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_ALTERNATE_OBJECT_DIRECTORIES: foreign },
      intents: bGit,
    }),
    objectSource
  );
  refusedEverywhere(
    'an inherited GIT_OBJECT_DIRECTORY without a quarantine',
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_OBJECT_DIRECTORY: foreign },
      intents: bGit,
    }),
    objectSource
  );
  back();
  // B's own quarantine, as receive-pack gives it (tmp_objdir-incoming-*, B's object folder as its
  // one alternate), holds the commit object: accepted.
  const quarantine = path.join(bGit, 'objects', 'tmp_objdir-incoming-Q10abc');
  const ownQuarantine = {
    GIT_QUARANTINE_PATH: quarantine,
    GIT_OBJECT_DIRECTORY: quarantine,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(bGit, '.', 'objects'),
  };
  const backFromQuarantine = moveObject(bGit, made.commit, quarantine);
  acceptedEverywhere(
    "B's own quarantine holds the commit object",
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_DIR: bGit, ...ownQuarantine },
      intents: bGit,
    })
  );
  const fromGitDirectory = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      `const m = await import(${JSON.stringify(new URL('../scripts/check-security-approval.mjs', import.meta.url).href)}); try { m.verifyCommit(${JSON.stringify(made.commit)}, ${JSON.stringify(b.root)}); console.log('accepted'); } catch (error) { console.log('refused: ' + error.message); }`,
    ],
    { cwd: bGit, encoding: 'utf8', env: { ...gitEnv, GIT_DIR: '.', ...ownQuarantine } }
  );
  assert.equal(
    fromGitDirectory.stdout.trim(),
    'accepted',
    "verifyCommit(commit, top level) from B's git directory with GIT_DIR=., as in a pre-receive hook"
  );
  refusedEverywhere(
    "B's quarantine with a second alternate object folder",
    await boundEntryPoints(made, {
      root: b.root,
      env: {
        ...ownQuarantine,
        GIT_ALTERNATE_OBJECT_DIRECTORIES: `${path.join(bGit, 'objects')}${path.delimiter}${foreign}`,
      },
      intents: bGit,
    }),
    objectSource
  );
  backFromQuarantine();
  // A quarantine inside A's object folder holds B's commit object: refused.
  const theirs = path.join(aGit, 'objects', 'tmp_objdir-incoming-Q10xyz');
  const backFromTheirs = moveObject(bGit, made.commit, theirs);
  refusedEverywhere(
    "a quarantine inside A's object folder supplies B's commit object",
    await boundEntryPoints(made, {
      root: b.root,
      env: {
        GIT_QUARANTINE_PATH: theirs,
        GIT_OBJECT_DIRECTORY: theirs,
        GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(bGit, 'objects'),
      },
      intents: bGit,
    }),
    objectSource
  );
  backFromTheirs();
  refusedEverywhere(
    'an inherited GIT_NAMESPACE',
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_NAMESPACE: 'elsewhere' },
      intents: bGit,
    }),
    /cannot be bound: the inherited GIT_NAMESPACE "elsewhere" selects another ref namespace/
  );
  // A root that is no working tree of a repository.
  const nowhere = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-nowhere-')));
  t.after(() => fs.rmSync(nowhere, { recursive: true, force: true }));
  // TMPDIR may be inside a checkout. An explicit invalid gitdir prevents Git from
  // discovering that ancestor, so this fixture has no repository on either host layout.
  fs.writeFileSync(path.join(nowhere, '.git'), 'gitdir: ./missing-git-dir\n');
  const checker = await import('../scripts/check-security-approval.mjs');
  assert.throws(
    () => checker.verifyCommit(made.commit, nowhere),
    /Commit check refused: the repository at .* cannot be bound: Git finds no working tree of a repository there/
  );

  // Commits through the installed hooks, as Git runs them: in a linked worktree (GIT_DIR exported
  // to the hooks), with commit -a (GIT_INDEX_FILE=.git/index.lock) and with commit <paths>
  // (GIT_INDEX_FILE=.git/next-index-<pid>.lock).
  installHooks(b);
  const throughHooks = (cwd, ...args) =>
    spawnSync('git', ['-C', cwd, ...args], { encoding: 'utf8', env: gitEnv });
  fs.writeFileSync(path.join(worktree, 'in-worktree.txt'), 'worktree\n');
  throughHooks(worktree, 'add', '-A');
  approveStaged(m, { root: worktree, security: b.security });
  const inWorktree = throughHooks(worktree, 'commit', '--quiet', '-m', 'in the linked worktree');
  assert.equal(inWorktree.status, 0, inWorktree.stderr);
  assert.deepEqual(
    throughHooks(worktree, 'rev-list', '--parents', '-n', '1', 'HEAD')
      .stdout.trim()
      .split(' ')
      .slice(1),
    [b0]
  );
  b.write('example.mjs', 'export const synthetic = 1;\n');
  b.git('add', '-A');
  approveStaged(m, b);
  const all = throughHooks(b.root, 'commit', '--quiet', '-a', '-m', 'commit -a');
  assert.equal(all.status, 0, all.stderr);
  b.write('example.mjs', 'export const synthetic = 2;\n');
  b.git('add', '-A');
  approveStaged(m, b);
  const only = throughHooks(
    b.root,
    'commit',
    '--quiet',
    '-m',
    'commit <paths>',
    '--',
    'example.mjs'
  );
  assert.equal(only.status, 0, only.stderr);
  assert.deepEqual(intentsOf(b), []);
  // The guard refuses an index other than its git directory's own.
  const index = path.join(
    fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-index-'))),
    'index'
  );
  t.after(() => fs.rmSync(path.dirname(index), { recursive: true, force: true }));
  fs.copyFileSync(path.join(bGit, 'index'), index);
  const otherIndex = spawnSync(process.execPath, [guardScript], {
    cwd: b.root,
    encoding: 'utf8',
    env: { ...gitEnv, GIT_INDEX_FILE: index },
  });
  assert.equal(otherIndex.status, 1, otherIndex.stderr);
  assert.match(
    otherIndex.stderr,
    /Commit blocked: the repository at .* cannot be bound: the inherited GIT_INDEX_FILE names .*, not the index, index\.lock or next-index-<pid>\.lock of the git directory/
  );
});

// What the bound runner does with each variable of BOUND_GIT_VARIABLES, checked one by one.
test('GDR9-AUTH-ROOT-01: the bound runner treats every repository-selecting, ref-namespace, configuration-injecting, index and object-source variable as its table says', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { platform } = await load();
  const r = repository(t);
  r.commit('C0');
  const other = repository(t);
  other.commit('another');
  const gitDir = fs.realpathSync(path.join(r.root, '.git'));
  const bind = (env, options = {}) =>
    platform.bindRepository(r.root, { env: { ...gitEnv, ...env }, ...options });
  const checked = new Set();
  const expect = (name, disposition) => {
    assert.equal(platform.BOUND_GIT_VARIABLES[name], disposition, name);
    checked.add(name);
  };
  const plain = bind({});
  assert.equal(plain.gitDir, gitDir);
  assert.equal(plain.commonDir, gitDir);
  assert.equal(plain.top, r.root);
  assert.equal(plain.env.GIT_DIR, gitDir);
  assert.equal(plain.env.GIT_WORK_TREE, r.root);
  // bound
  for (const [name, own, foreign] of [
    ['GIT_DIR', gitDir, path.join(other.root, '.git')],
    ['GIT_WORK_TREE', r.root, other.root],
    ['GIT_COMMON_DIR', gitDir, path.join(other.root, '.git')],
  ]) {
    expect(name, 'bound');
    assert.doesNotThrow(() => bind({ [name]: own }), name);
    assert.throws(() => bind({ [name]: foreign }), new RegExp(`the inherited ${name} names`), name);
  }
  assert.equal(bind({ GIT_COMMON_DIR: gitDir }).env.GIT_COMMON_DIR, undefined);
  // refused
  expect('GIT_NAMESPACE', 'refused');
  assert.throws(
    () => bind({ GIT_NAMESPACE: 'x' }),
    /GIT_NAMESPACE "x" selects another ref namespace/
  );
  assert.equal(bind({ GIT_NAMESPACE: '' }).env.GIT_NAMESPACE, undefined);
  // quarantine: only the three together, naming the repository's own quarantine
  const quarantine = path.join(gitDir, 'objects', 'tmp_objdir-incoming-T10abc');
  fs.mkdirSync(quarantine);
  const own = {
    GIT_QUARANTINE_PATH: quarantine,
    GIT_OBJECT_DIRECTORY: quarantine,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(gitDir, 'objects'),
  };
  for (const name of Object.keys(own)) {
    expect(name, 'quarantine');
    assert.throws(
      () => bind({ [name]: own[name] }),
      /an object source other than/,
      `${name} alone`
    );
  }
  assert.deepEqual(
    Object.fromEntries(Object.keys(own).map(name => [name, bind(own).env[name]])),
    own
  );
  const notQuarantine = path.join(gitDir, 'objects', 'pack');
  assert.throws(
    () => bind({ ...own, GIT_QUARANTINE_PATH: notQuarantine, GIT_OBJECT_DIRECTORY: notQuarantine }),
    /an object source other than/
  );
  // index
  expect('GIT_INDEX_FILE', 'index');
  const foreignIndex = path.join(other.root, '.git', 'index');
  assert.equal(bind({ GIT_INDEX_FILE: foreignIndex }).env.GIT_INDEX_FILE, undefined);
  assert.throws(
    () => bind({ GIT_INDEX_FILE: foreignIndex }, { index: true }),
    /GIT_INDEX_FILE names/
  );
  assert.equal(
    bind({ GIT_INDEX_FILE: path.join(r.root, '.git', 'index') }, { index: true }).env
      .GIT_INDEX_FILE,
    path.join(gitDir, 'index')
  );
  // overridden (since gate-draft-r12, GDR11-AUTH-CONFIG-01, the configuration files too: the one
  // authority configuration policy, the stage environment's)
  for (const [name, value, bound] of [
    [
      'GIT_CONFIG_PARAMETERS',
      "'core.commitgraph=true' 'orbit.injected=yes'",
      "'core.attributesfile=/dev/null' 'core.excludesfile=/dev/null' 'core.fsmonitor=false' 'i18n.logoutputencoding=UTF-8' 'log.showsignature=false' 'core.hookspath=/dev/null' 'core.commitgraph=false' 'core.usereplacerefs=false'",
    ],
    ['GIT_NO_LAZY_FETCH', '0', '1'],
    ['GIT_GRAFT_FILE', path.join(r.root, 'grafts'), '/dev/null/orbit-no-grafts'],
    ['GIT_NO_REPLACE_OBJECTS', '0', '1'],
    ['GIT_CONFIG_GLOBAL', path.join(r.root, 'global.gitconfig'), '/dev/null'],
    ['GIT_CONFIG_SYSTEM', path.join(r.root, 'system.gitconfig'), '/dev/null'],
    ['GIT_CONFIG_NOSYSTEM', '0', '1'],
    ['GIT_ATTR_NOSYSTEM', '0', '1'],
  ]) {
    expect(name, 'overridden');
    assert.equal(bind({ [name]: value }).env[name], bound, name);
  }
  // The binding's own settings after the stage's (round 2 of gate-draft-r12, R12C1-HOOK-01), and
  // a HOME that names no folder (R12C1-HOME-INCLUDE-01).
  assert.equal(
    plain.env.GIT_CONFIG_PARAMETERS,
    `${platform.STAGE_GIT_SETTINGS} ${platform.BOUND_GIT_SETTINGS} 'core.commitgraph=false' 'core.usereplacerefs=false'`
  );
  assert.equal(platform.BOUND_GIT_SETTINGS, "'core.hookspath=/dev/null'");
  assert.equal(plain.env.HOME, '/dev/null/orbit-no-home');
  assert.equal(bind({ HOME: r.root }).env.HOME, platform.NO_HOME);
  // Each filter driver and hook the repository's configuration defines is switched off in Git's
  // 'key'='value' form, whatever its name holds (R12C1-FILTER-EQ-01): `=`, a quote, a dot, a
  // blank, or nothing.
  const gitConfig = path.join(gitDir, 'config');
  const before = fs.readFileSync(gitConfig);
  try {
    fs.appendFileSync(
      gitConfig,
      `[filter "a=b"]\n\tclean = cat\n[filter ""]\n\tclean = cat\n[filter "q'x.y z"]\n\tprocess = cat\n[hook "h=k"]\n\tcommand = true\n\tevent = post-index-change\n`
    );
    assert.equal(
      bind({}).env.GIT_CONFIG_PARAMETERS,
      `${platform.STAGE_GIT_SETTINGS} ${platform.BOUND_GIT_SETTINGS} 'filter..clean'='' 'filter..smudge'='' 'filter..process'='' 'filter..required'='false' 'filter.a=b.clean'='' 'filter.a=b.smudge'='' 'filter.a=b.process'='' 'filter.a=b.required'='false' 'filter.q'\\''x.y z.clean'='' 'filter.q'\\''x.y z.smudge'='' 'filter.q'\\''x.y z.process'='' 'filter.q'\\''x.y z.required'='false' 'hook.h=k.enabled'='false' 'core.commitgraph=false' 'core.usereplacerefs=false'`
    );
    const switched = bind({});
    for (const [key, value] of [
      ['filter.a=b.clean', ''],
      ['filter..clean', ''],
      ["filter.q'x.y z.process", ''],
      ['hook.h=k.enabled', 'false'],
    ])
      assert.equal(
        switched.run(['config', '--get', key]).toString().replace(/\n$/, ''),
        value,
        key
      );
    assert.throws(
      () => switched.run(['config', '--get', 'filter.a']),
      /Command failed/,
      'filter.a is set (the key=value form split at its first =)'
    );
  } finally {
    fs.writeFileSync(gitConfig, before);
  }
  // removed
  const removed = {
    GIT_REPLACE_REF_BASE: 'refs/elsewhere/',
    GIT_SHALLOW_FILE: path.join(r.root, 'shallow'),
    GIT_CONFIG: path.join(r.root, 'config'),
    GIT_CONFIG_COUNT: '1',
    'GIT_CONFIG_KEY_<n>': ['GIT_CONFIG_KEY_0', 'orbit.injected'],
    'GIT_CONFIG_VALUE_<n>': ['GIT_CONFIG_VALUE_0', 'yes'],
    GIT_CEILING_DIRECTORIES: path.dirname(r.root),
    GIT_DISCOVERY_ACROSS_FILESYSTEM: '1',
    GIT_LITERAL_PATHSPECS: '1',
    GIT_GLOB_PATHSPECS: '1',
    GIT_NOGLOB_PATHSPECS: '1',
    GIT_ICASE_PATHSPECS: '1',
  };
  const inherited = Object.fromEntries(
    Object.entries(removed).map(([key, value]) => (Array.isArray(value) ? value : [key, value]))
  );
  const stripped = bind(inherited);
  for (const [key, value] of Object.entries(removed)) {
    expect(key, 'removed');
    const name = Array.isArray(value) ? value[0] : key;
    assert.equal(stripped.env[name], undefined, name);
  }
  // An injected setting does not reach Git: GIT_CONFIG_COUNT and GIT_CONFIG_PARAMETERS.
  const injected = bind({ ...inherited, GIT_CONFIG_PARAMETERS: "'orbit.parameter=yes'" });
  for (const key of ['orbit.injected', 'orbit.parameter'])
    assert.throws(() => injected.run(['config', '--get', key]), /Command failed/, key);
  // admitted: the folder of Git's own programs and the identity a commit is written with, as the
  // stage environment admits them (gate-draft-r12)
  for (const [name, value] of [
    ['GIT_EXEC_PATH', execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim()],
    ['GIT_AUTHOR_NAME', 'Orbit Fixture'],
    ['GIT_AUTHOR_EMAIL', 'fixture@example.invalid'],
    ['GIT_AUTHOR_DATE', '2026-01-01T00:00:00Z'],
    ['GIT_COMMITTER_NAME', 'Orbit Fixture'],
    ['GIT_COMMITTER_EMAIL', 'fixture@example.invalid'],
    ['GIT_COMMITTER_DATE', '2026-01-01T00:00:00Z'],
  ]) {
    expect(name, 'admitted');
    assert.equal(bind({ [name]: value }).env[name], value, name);
  }
  // Every other Git variable is removed, whatever its name (gate-draft-r12): an external diff, an
  // attribute source, a trace file, a pager, a Git test switch and a name Git may add later.
  expect('GIT_<any other name>', 'removed');
  const others = {
    GIT_EXTERNAL_DIFF: '/usr/bin/false',
    GIT_ATTR_SOURCE: 'HEAD',
    GIT_TRACE: path.join(r.root, 'trace'),
    GIT_PAGER: 'cat',
    GIT_TEST_ASSUME_DIFFERENT_OWNER: '1',
    GIT_ORBIT_FUTURE_SWITCH: 'yes',
  };
  const withOthers = bind(others);
  for (const name of Object.keys(others)) assert.equal(withOthers.env[name], undefined, name);
  assert.deepEqual(
    Object.keys(withOthers.env)
      .filter(name => /^GIT_/i.test(name))
      .filter(name => !Object.hasOwn(platform.BOUND_GIT_VARIABLES, name))
      .sort(),
    [],
    'the bound environment holds only the Git variables its table names'
  );
  assert.deepEqual([...checked].sort(), Object.keys(platform.BOUND_GIT_VARIABLES).sort());
});

// GDR9-AUTH-OBJECT-01 (review finding): readPackageWith() read <tree>:package.json as a blob and
// turned every failure into absence, and the history parser skipped every non-blob answer. So a
// finalized subject whose own package.json blob was missing was accepted with both lint stages
// (the security review's P2), and a history version whose package.json was a gitlink to a readable commit
// defined nothing (P3). Each version is now read entry first and typed (packageVersions): only a
// tree with no package.json entry is absence; a missing or unreadable object, a directory, a
// submodule (readable or not), a symbolic link, an oversized file and any lookup error refuse, at
// commitLintStages, the three entry points and the pre-commit guard.
test('GDR9-AUTH-OBJECT-01: package.json is read entry first and typed for the subject, its parents and their history; a missing blob, a readable gitlink, a directory, a link, an oversized file or a lookup error refuses at commitLintStages, verifyCommit, --verify-commit, the reference-transaction hook and the pre-commit guard, and only a genuinely absent entry is absence', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const r = repository(t);
  const C0 = r.commit('C0: package.json defines no lint script');
  const { requiredStages } = m.finalization;
  const withBoth = [...requiredStages, ...bothLint];
  const both = { ...sqlScript, ...importScript };
  const subject = subjects(m, r, Date.now());
  const git = (args, input) =>
    execFileSync('git', args, {
      cwd: r.root,
      env: { ...m.platform.gitHistoryEnvironment(gitEnv), GIT_NO_LAZY_FETCH: '1' },
      input,
      stdio: 'pipe',
      maxBuffer: 64 * 1024 ** 2,
    });
  const derive = made => checker.commitLintStages(git, { tree: made.tree, parents: made.parents });
  const derived = text =>
    new RegExp(
      `Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history \\(Commit blocked: ${text}`
    );
  const notRegular = kind =>
    `the package\\.json of [0-9a-f]+ is ${kind}, not a regular file, so the lint scripts that version defines cannot be judged`;
  // The security review's P2: the subject's own package.json blob is missing; the run has both lint stages.
  const p2 = await subject(
    [C0],
    { 'package.json': canonicalPackage({ ...both, note: 'the subject alone' }) },
    withBoth
  );
  acceptedAtEntry('control: the subject defines both lint scripts, the run has both', p2);
  const blob = r.git('rev-parse', `${p2.commit}:package.json`);
  const missing = `the package\\.json of ${p2.tree} \\(blob ${blob}\\) cannot be read from this repository`;
  const back = moveObject(path.join(r.root, '.git'), blob, path.join(r.root, '.git', 'aside'));
  assert.throws(() => derive(p2), new RegExp(missing));
  refusedAtEntryPoints(
    "The security review's P2: the subject's package.json blob is missing",
    await authorityEntryPoints(r, p2),
    derived(missing)
  );
  back();
  // The security review's P3: a history version's package.json is a gitlink to a readable commit.
  const gitlinked = commitOn(r, [C0], { 'package.json': { gitlink: C0 } }, 'H: a gitlink to C0');
  const after = commitOn(
    r,
    [gitlinked.commit],
    { 'package.json': canonicalPackage({}) },
    'F: package.json again'
  );
  const submodule = notRegular(`a submodule \\(gitlink to commit ${C0}\\)`);
  const p3 = await subject([after.commit], {}, requiredStages);
  assert.throws(() => derive(p3), new RegExp(submodule));
  refusedAtEntryPoints(
    "The security review's P3: a history version's package.json is a readable gitlink",
    p3,
    derived(submodule)
  );
  // The subject's and a parent's package.json that are not regular files, a history directory,
  // an oversized file and an unreadable history tree.
  const folder = commitOn(
    r,
    [C0],
    { 'package.json': null, 'package.json/index.json': '{}\n' },
    'H: package.json is a folder'
  );
  const afterFolder = commitOn(
    r,
    [folder.commit],
    { 'package.json/index.json': null, 'package.json': canonicalPackage({}) },
    'F: a file again'
  );
  const gitlinkParent = commitOn(
    r,
    [C0],
    { 'package.json': { gitlink: C0 } },
    'P: a gitlink parent'
  );
  for (const [label, parents, files, stages, pattern] of [
    [
      "the subject's package.json is a readable gitlink, the run has both",
      [C0],
      { 'package.json': { gitlink: C0 } },
      withBoth,
      submodule,
    ],
    [
      "the subject's package.json is a folder, the run has both",
      [C0],
      { 'package.json': null, 'package.json/index.json': '{}\n' },
      withBoth,
      notRegular('a directory \\(tree [0-9a-f]+\\)'),
    ],
    [
      "the subject's package.json is a symbolic link, the run has both",
      [C0],
      { 'package.json': { link: 'elsewhere/package.json' } },
      withBoth,
      notRegular('a symbolic link \\(blob [0-9a-f]+\\)'),
    ],
    [
      "a parent's package.json is a readable gitlink, the run has both",
      [gitlinkParent.commit],
      { 'package.json': canonicalPackage({}) },
      withBoth,
      submodule,
    ],
    [
      "a history version's package.json is a folder, the run without lint stages",
      [afterFolder.commit],
      {},
      requiredStages,
      notRegular('a directory \\(tree [0-9a-f]+\\)'),
    ],
    [
      "the subject's package.json is over 16 MiB, the run has both",
      [C0],
      {
        'package.json': `${JSON.stringify({ scripts: {}, padding: 'x'.repeat(16 * 1024 ** 2 + 16) }, null, 2)}\n`,
      },
      withBoth,
      'the package\\.json of [0-9a-f]+ \\(blob [0-9a-f]+\\) has \\d+ bytes, more than the 16 MiB whose lint scripts are judged',
    ],
  ]) {
    const outcome = await subject(parents, files, stages);
    assert.throws(() => derive(outcome), new RegExp(pattern), label);
    refusedAtEntryPoints(label, outcome, derived(pattern));
  }
  const unreadableTree = await subject([C0], {}, requiredStages);
  const backTree = moveObject(
    path.join(r.root, '.git'),
    unreadableTree.tree,
    path.join(r.root, '.git', 'aside')
  );
  const treeMissing = `the tree of ${unreadableTree.tree} cannot be read from this repository`;
  assert.throws(() => derive(unreadableTree), new RegExp(treeMissing));
  refusedAtEntryPoints(
    'a history version whose tree object is missing',
    await authorityEntryPoints(r, unreadableTree),
    derived(treeMissing)
  );
  backTree();
  // Any lookup error refuses, never the conservative two-lint answer: a runner whose first
  // cat-file (the subject's package.json) throws, as one over its 64 MiB output bound does.
  let calls = 0;
  assert.throws(
    () =>
      checker.commitLintStages(
        (args, input) => {
          if (args[0] === 'cat-file' && (calls += 1) === 1) {
            const error = new Error('spawnSync git ENOBUFS');
            error.code = 'ENOBUFS';
            throw error;
          }
          return git(args, input);
        },
        { tree: p2.tree, parents: p2.parents }
      ),
    /ENOBUFS/
  );
  // Still accepted: a subject with no package.json entry (every lint stage required) and an
  // ordinary one.
  for (const [label, files, stages, expected] of [
    [
      'a subject without package.json, the run has both',
      { 'package.json': null },
      withBoth,
      bothLint,
    ],
    ['an ordinary subject, the run without lint stages', {}, requiredStages, []],
  ]) {
    const outcome = await subject([C0], files, stages);
    assert.deepEqual(derive(outcome), expected, label);
    acceptedAtEntry(label, outcome);
  }

  // The pre-commit guard shares the typed reader.
  const p = repository(t);
  const P0 = p.commit('C0: package.json defines no lint script');
  const guarded = (label, pattern) => {
    const result = p.guard();
    assert.equal(result.status, 1, `${label}: ${result.stderr}`);
    assert.match(result.stderr, pattern, label);
  };
  // A candidate whose package.json is a folder, with a run that has both lint stages (the guard
  // read it as no package.json, requiring both, and approved it).
  fs.rmSync(path.join(p.root, 'package.json'));
  p.write('package.json/index.json', '{}\n');
  p.git('add', '-A');
  const staged = m.securityRun.candidate(p.root);
  m.securityRun.finalizedRun(
    path.join(p.security, `${staged.tree}-commit-folder`),
    staged,
    m.securityRun.allStages
  );
  guarded(
    "pre-commit: the candidate's package.json is a folder",
    /^Commit blocked: the package\.json of [0-9a-f]+ is a directory \(tree [0-9a-f]+\), not a regular file/
  );
  // Control: the guard approves a candidate with no package.json entry (both stages required).
  p.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', P0);
  p.git('rm', '--quiet', 'package.json');
  p.write('candidate-0.txt', 'candidate 0\n');
  p.git('add', '-A');
  const without = m.securityRun.candidate(p.root);
  m.securityRun.finalizedRun(
    path.join(p.security, `${without.tree}-commit-without`),
    without,
    m.securityRun.allStages
  );
  const approved = p.guard();
  assert.equal(approved.status, 0, `pre-commit control: no package.json entry: ${approved.stderr}`);
  // HEAD's history holds a package.json gitlink to a readable commit; the candidate is approved
  // by a run without lint stages (the guard skipped that version and approved it).
  const H = commitOn(p, [P0], { 'package.json': { gitlink: P0 } }, 'H: a gitlink to C0');
  const F = commitOn(
    p,
    [H.commit],
    { 'package.json': canonicalPackage({}) },
    'F: package.json again'
  );
  p.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', F.commit);
  p.write('candidate.txt', 'candidate\n');
  p.git('add', '-A');
  approveStaged(m, p);
  guarded(
    'pre-commit: a history version is a readable gitlink',
    new RegExp(`^Commit blocked: ${notRegular(`a submodule \\(gitlink to commit ${P0}\\)`)}`)
  );
});

// GDR9-AUTH-OBJECT-01 (review finding), the implicit fetch: authority reads did not set
// GIT_NO_LAZY_FETCH, so in a partial clone a missing object made Git start its promisor remote.
// Contained, with no network: a scratch repository marked as a partial clone whose promisor remote
// is a local logging remote helper that refuses. The harness shows a fetch without the variable;
// with the binding no authority entry point starts the helper, and each refuses the missing object.
test('GDR9-AUTH-OBJECT-01: no authority read starts a promisor remote helper (GIT_NO_LAZY_FETCH): the harness detects a fetch without it, and verifyCommit, --verify-commit, the reference-transaction hook, the pre-commit guard and the bound runner start none', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('C0');
  const helpers = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-helper-')));
  t.after(() => fs.rmSync(helpers, { recursive: true, force: true }));
  const log = path.join(helpers, 'calls.log');
  fs.writeFileSync(log, '');
  fs.writeFileSync(
    path.join(helpers, 'git-remote-orbitlog'),
    `#!/bin/sh\nprintf '%s\\n' "orbitlog $*" >> '${log}'\necho 'orbitlog: refused, no network' >&2\nexit 1\n`,
    { mode: 0o755 }
  );
  const calls = () => fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).length;
  for (const [key, value] of [
    ['core.repositoryformatversion', '1'],
    ['extensions.partialClone', 'origin'],
    ['remote.origin.url', 'orbitlog::synthetic-promisor'],
    ['remote.origin.promisor', 'true'],
    ['remote.origin.partialclonefilter', 'blob:none'],
  ])
    r.git('config', key, value);
  const both = { ...sqlScript, ...importScript };
  const made = await subjects(m, r, Date.now())(
    [C0],
    { 'package.json': canonicalPackage({ ...both, note: 'the promisor subject' }) },
    [...m.finalization.requiredStages, ...bothLint]
  );
  acceptedAtEntry('control: the blob present', made);
  const blob = r.git('rev-parse', `${made.commit}:package.json`);
  const gitDir = path.join(r.root, '.git');
  let back = moveObject(gitDir, blob, path.join(gitDir, 'aside'));
  const plain = extra =>
    spawnSync('git', ['-C', r.root, 'cat-file', '-t', blob], {
      encoding: 'utf8',
      env: { ...gitEnv, PATH: `${helpers}${path.delimiter}${gitEnv.PATH}`, ...extra },
    });
  let before = calls();
  assert.notEqual(plain({}).status, 0);
  assert.ok(
    calls() > before,
    'the harness: without GIT_NO_LAZY_FETCH, Git started the promisor helper'
  );
  before = calls();
  assert.notEqual(plain({ GIT_NO_LAZY_FETCH: '1' }).status, 0);
  assert.equal(calls(), before, 'the harness: with GIT_NO_LAZY_FETCH=1, no helper');
  before = calls();
  const outcome = await boundEntryPoints(made, { root: r.root, intents: gitDir, prefix: helpers });
  refusedEverywhere(
    "the subject's package.json blob is missing in a partial clone",
    outcome,
    new RegExp(
      `the package\\.json of ${made.tree} \\(blob ${blob}\\) cannot be read from this repository`
    )
  );
  assert.equal(calls(), before, 'no authority entry point started the promisor helper');
  // The bound runner itself.
  const saved = process.env.PATH;
  process.env.PATH = `${helpers}${path.delimiter}${saved}`;
  try {
    const bound = m.platform.bindRepository(r.root);
    assert.equal(bound.env.GIT_NO_LAZY_FETCH, '1');
    assert.throws(() => bound.run(['cat-file', '-t', blob]));
  } finally {
    process.env.PATH = saved;
  }
  assert.equal(calls(), before, 'the bound runner started no promisor helper');
  // The pre-commit guard: HEAD's package.json blob is missing (the candidate's own package.json is
  // another blob, so its index can still be written as a tree).
  back();
  r.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', made.commit);
  r.write('package.json', canonicalPackage({ ...both, note: 'the candidate' }));
  r.write('candidate.txt', 'candidate\n');
  r.git('add', '-A');
  back = moveObject(gitDir, blob, path.join(gitDir, 'aside'));
  before = calls();
  const guard = spawnSync(process.execPath, [guardScript], {
    cwd: r.root,
    encoding: 'utf8',
    env: { ...gitEnv, PATH: `${helpers}${path.delimiter}${gitEnv.PATH}` },
  });
  assert.equal(guard.status, 1, guard.stderr);
  assert.match(
    guard.stderr,
    /^Commit blocked: the package\.json of [0-9a-f]+ \(blob [0-9a-f]+\) cannot be read from this repository/
  );
  assert.equal(calls(), before, 'the pre-commit guard started no promisor helper');
  back();
  // The gate's Git runner reads through the same binding (scripts/security-gate.mjs).
  const gate = fs.readFileSync(path.join(repositoryRoot, 'scripts/security-gate.mjs'), 'utf8');
  assert.match(gate, /const gitBinding = bindRepository\(root, \{ index: true \}\);/);
  assert.match(gate, /spawnSync\('git', args, \{\n\s*cwd: root,\n\s*env: gitBinding\.env,/);
});

// GDR9-AUTH-OBJECT-01 and GDR9-AUTH-ROOT-01 for the gate's Git runner: started with an inherited
// GIT_DIR naming another repository, the gate refuses before its first read, and writes nothing.
test('GDR9-AUTH-ROOT-01: the gate refuses an inherited GIT_DIR naming another repository before it reads anything', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const empty = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10-empty-')));
  t.after(() => fs.rmSync(empty, { recursive: true, force: true }));
  execFileSync('git', ['init', '--quiet', empty], { env: gitEnv });
  const gate = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'scripts/security-gate.mjs'), 'commit'],
    {
      cwd: empty,
      encoding: 'utf8',
      env: { ...gitEnv, GIT_DIR: path.join(empty, '.git') },
    }
  );
  assert.notEqual(gate.status, 0, gate.stdout);
  assert.match(gate.stderr, /cannot be bound: the inherited GIT_DIR names .*\(GDR9-AUTH-ROOT-01\)/);
  assert.equal(fs.existsSync(path.join(empty, '.git', 'orbit-security')), false);
  assert.deepEqual(
    execFileSync('git', ['-C', empty, 'count-objects'], { encoding: 'utf8', env: gitEnv }).trim(),
    '0 objects, 0 kilobytes'
  );
});

// GDR9-AUTH-SCAN-02 (review finding) at the authority entry points: a contract approval of a real
// commit whose run withholds a scanner and seals its fixed report anyway (the security review's P4,
// CONTRACT-R2-6, a finding in it; or an empty, empty-list or malformed report), or seals a report
// with no scanner stage at all, was accepted with no finding at verifyCommit, --verify-commit and
// the reference-transaction hook, as by the finalizer and recordedApproval. Each twin below is a
// run of the commit's candidate, with the clean run's F-passed approval rebound to it (as an earlier
// finalizer could have written it); only one twin at a time is named as the commit's.
test('GDR9-AUTH-SCAN-02: a contract approval whose run seals a report beside a withheld scanner, or a report with no scanner stage, gives no authority at the finalizer, recordedApproval, verifyCommit, --verify-commit or the reference-transaction hook; a genuinely withheld scanner without a report is accepted', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('C0: no lint script');
  const made = commitOn(r, [C0], { 'subject.txt': 'subject\n' }, 'X: the subject');
  const candidate = m.fixture.platformCandidate({ tree: made.tree, parents: [C0] });
  const now = Date.now();
  const companion = m.fixture.writeCompanion(r.security, candidate, { now });
  const current = { ...candidate.current, companions: [companion] };
  // The clean run, finalized and passed as F would, under a name no commit reads.
  const template = path.join(r.security, `${made.tree}-template`);
  m.fixture.writeMainRun(template, candidate, { platform: 'linux', now });
  const inventory = m.finalization.inspectRun(template, current, now);
  assert.deepEqual(inventory.blockers, []);
  const reviewFile = path.join(r.root, '.git', 'review-input.json');
  const { platform, ...binding } = m.fixture.reviewBinding(inventory);
  assert.ok(platform);
  fs.writeFileSync(
    reviewFile,
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
  m.finalization.finalizeRun(template, reviewFile, current, now);
  m.fixture.asIfFinalizedByF(template);
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
  const stageOf = (result, name) => result.stages.find(item => item.name === name);
  const withheld = result => {
    const stage = stageOf(result, 'secrets-source');
    for (const key of ['command', 'log', 'exit', 'signal']) delete stage[key];
    Object.assign(stage, { status: 'pending', reason: 'synthetic: withheld before dispatch' });
  };
  let twins = 0;
  const twin = change => {
    const run = path.join(r.security, `${made.tree}-commit-twin-${(twins += 1)}`);
    m.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: { record: change } });
    const finalized = path.join(run, 'finalization');
    fs.mkdirSync(finalized, { mode: 0o700 });
    const runSha256 = sha(fs.readFileSync(path.join(run, 'run-manifest.json')));
    const review = JSON.parse(
      fs.readFileSync(path.join(template, 'finalization', 'review.json'), 'utf8')
    );
    review.runSha256 = runSha256;
    const reviewBytes = Buffer.from(JSON.stringify(review));
    fs.writeFileSync(path.join(finalized, 'review.json'), reviewBytes, { mode: 0o600 });
    const approval = JSON.parse(
      fs.readFileSync(path.join(template, 'finalization', 'approval.json'), 'utf8')
    );
    Object.assign(approval, { runSha256, reviewSha256: sha(reviewBytes), findings: 0 });
    fs.writeFileSync(path.join(finalized, 'approval.json'), JSON.stringify(approval), {
      mode: 0o600,
    });
    return { ...made, run };
  };
  // One twin at a time is the commit's: the others are renamed out of the way.
  const retire = item =>
    fs.renameSync(item.run, item.run.replace('-commit-twin-', '-retired-twin-'));
  const lint = { lintStages: [] };
  for (const [label, change] of [
    ['an unchanged twin', () => {}],
    ['secrets-source withheld as the gate withholds it, with no report', withheld],
  ]) {
    const item = twin(change);
    assert.deepEqual(m.finalization.inspectRun(item.run, current, now).blockers, [], label);
    assert.equal(m.finalization.recordedApproval(item.run, lint).approval.findings, 0, label);
    acceptedEverywhere(
      label,
      await boundEntryPoints(item, { root: r.root, intents: path.join(r.root, '.git') })
    );
    retire(item);
  }
  const pendingReport =
    /secrets-source is recorded as pending \(withheld, nothing run\), but its fixed report secrets-source\.json is sealed with the run: a scanner that did not run has no report, empty or not, so the run gives no result \(GDR9-AUTH-SCAN-02\)/;
  const orphan =
    /secrets-source\.json is sealed with the run, but no secrets-source stage is recorded: a report that belongs to no scanner stage gives no result/;
  for (const [label, change, pattern, finalizerPattern] of [
    [
      "The security review's P4 (CONTRACT-R2-6): withheld, its sealed report holds one finding",
      (result, files) => {
        withheld(result);
        files['secrets-source.json'] = finding;
      },
      pendingReport,
    ],
    [
      'withheld, a zero-byte report beside it',
      (result, files) => {
        withheld(result);
        files['secrets-source.json'] = '';
      },
      pendingReport,
    ],
    [
      'withheld, an empty-list report beside it',
      (result, files) => {
        withheld(result);
        files['secrets-source.json'] = '[]';
      },
      pendingReport,
    ],
    [
      'withheld, a malformed report beside it',
      (result, files) => {
        withheld(result);
        files['secrets-source.json'] = '[{';
      },
      pendingReport,
    ],
    [
      'no secrets-source stage at all, its report sealed with a finding',
      (result, files) => {
        result.stages = result.stages.filter(item => item.name !== 'secrets-source');
        files['secrets-source.json'] = finding;
      },
      orphan,
      /Catalog: secrets-source is missing/,
    ],
  ]) {
    const item = twin(change);
    const judged = m.finalization.inspectRun(item.run, current, now);
    assert.equal(judged.eligible, false, label);
    assert.match(judged.blockers[0], finalizerPattern ?? pattern, label);
    assert.throws(() => m.finalization.recordedApproval(item.run, lint), pattern, label);
    refusedEverywhere(
      label,
      await boundEntryPoints(item, { root: r.root, intents: path.join(r.root, '.git') }),
      refusedAtEntry
    );
    retire(item);
  }
});

// GDR9-HOST-SCHEMA-01 (review finding, Low/P3, integration-blocking) at the authority entry points:
// a recorded maintenance approval whose run's own host is not one of its closed producer forms
// (the security review's P5: host.probe = { argv, exitCode }; an unknown scalar or list; the three-member form
// no producer writes; a member of the wrong type) gives no authority at the finalizer,
// recordedApproval, verifyCommit, --verify-commit or the reference-transaction hook; the
// maintenance gate's four-member form and the 1.5 gate's five-member form are accepted.
// gate-draft-r11, GDR10-HOST-PRODUCER-01 (changed, following the maintainer's decision 073253 item 2): the
// maintenance form is the maintenance producer's four members { platform, arch, release, node }
// (blob 40bc87be), which this test refused before; the synthetic three-member form is refused.
test('GDR9-HOST-SCHEMA-01: a recorded approval whose run host is not one of the closed producer forms gives no authority at the finalizer, recordedApproval, verifyCommit, --verify-commit or the reference-transaction hook; the maintenance gate four-member and the 1.5 gate five-member forms are accepted', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('C0: no lint script');
  const { requiredStages } = m.finalization;
  const subject = subjects(m, r, Date.now());
  // The host of `made`'s sealed run replaced, the run sealed again and its approval and review
  // rebound to it, as an earlier finalizer could have written them.
  const rehost = (made, host) => {
    const result = JSON.parse(fs.readFileSync(path.join(made.run, 'result.json'), 'utf8'));
    result.host = host;
    fs.writeFileSync(path.join(made.run, 'result.json'), JSON.stringify(result), { mode: 0o600 });
    fs.rmSync(path.join(made.run, 'run-manifest.json'));
    const aside = `${made.run}.finalization`;
    fs.renameSync(path.join(made.run, 'finalization'), aside);
    m.finalization.sealRun(made.run);
    fs.renameSync(aside, path.join(made.run, 'finalization'));
    const runSha256 = sha(fs.readFileSync(path.join(made.run, 'run-manifest.json')));
    const reviewFile = path.join(made.run, 'finalization', 'review.json');
    const review = { ...JSON.parse(fs.readFileSync(reviewFile, 'utf8')), runSha256 };
    const reviewBytes = Buffer.from(JSON.stringify(review));
    fs.writeFileSync(reviewFile, reviewBytes, { mode: 0o600 });
    const approvalFile = path.join(made.run, 'finalization', 'approval.json');
    const approval = {
      ...JSON.parse(fs.readFileSync(approvalFile, 'utf8')),
      runSha256,
      reviewSha256: sha(reviewBytes),
    };
    fs.writeFileSync(approvalFile, JSON.stringify(approval), { mode: 0o600 });
  };
  const earlier = { finalized: false };
  const judge = made => {
    const current = {
      ...made.current,
      lintStages: [],
      platform: m.securityRun.maintenanceInputs(made.current),
    };
    return () => {
      const inventory = m.finalization.inspectRun(made.run, current, Date.now());
      if (!inventory.eligible) throw new Error(inventory.blockers[0]);
    };
  };
  for (const [label, host] of [
    ["the maintenance gate's four-member form (the fixture's own)", null],
    [
      "the maintenance gate's four-member form as the producer writes it (os.release() text)",
      { platform: 'linux', arch: 'arm64', release: '6.8.0-45-synthetic', node: 'v24.21.0' },
    ],
    [
      "the 1.5 gate's five-member form",
      { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0', uid: 4242 },
    ],
  ]) {
    const made = await subject([C0], {}, requiredStages, earlier);
    if (host) rehost(made, host);
    assert.doesNotThrow(judge(made), label);
    assert.equal(m.finalization.recordedApproval(made.run, noLint).approval.status, 'pass', label);
    acceptedEverywhere(
      label,
      await boundEntryPoints(made, { root: r.root, intents: path.join(r.root, '.git') })
    );
  }
  const closed =
    /run record's host is not one of its closed producer forms \(GDR9-HOST-SCHEMA-01\)/;
  for (const [label, host] of [
    [
      "The security review's P5: host.probe = { argv, exitCode }",
      {
        platform: 'linux',
        arch: 'arm64',
        release: 'synthetic-6.0',
        node: 'v24.21.0',
        probe: { argv: ['node', '--test'], exitCode: 0 },
      },
    ],
    [
      'an unknown scalar member',
      { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0', extra: 'x' },
    ],
    [
      'an unknown list member',
      { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0', steps: [] },
    ],
    [
      'the three members no producer writes (no release)',
      { node: 'v24.21.0', platform: 'linux', arch: 'arm64' },
    ],
    [
      'four members, release a number',
      { platform: 'linux', arch: 'arm64', release: 6, node: 'v24.21.0' },
    ],
    [
      'five members, uid as text',
      { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v24.21.0', uid: '4242' },
    ],
    [
      'five members, release an object',
      { platform: 'linux', arch: 'arm64', release: { kernel: '6.0' }, node: 'v24.21.0', uid: 4242 },
    ],
  ]) {
    const made = await subject([C0], {}, requiredStages, earlier);
    rehost(made, host);
    assert.throws(judge(made), closed, label);
    assert.throws(() => m.finalization.recordedApproval(made.run, noLint), closed, label);
    refusedEverywhere(
      label,
      await boundEntryPoints(made, { root: r.root, intents: path.join(r.root, '.git') }),
      refusedAtEntry
    );
  }
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r10 round 2: check-1 of the tenth round (two holes and two low items of
// GDR9-AUTH-OBJECT-01, GDR9-HOST-SCHEMA-01 and GDR9-AUTH-ROOT-01, review findings) at the
// authority entry points.

// GDR9-AUTH-OBJECT-01, round 2 (check-1: malformed package.json content; maintainer note 153201 criterion 2
// lists "malformed content" among what refuses authority). A readable package.json whose content
// is not well formed still gave authority: the subject's or a parent's was read as unknown, which
// both lint stages satisfy, and a history version that did not parse defined nothing, so one that
// named a lint script hid it. Each now refuses, as an unreadable one does: not UTF-8 text, not
// JSON, not a JSON object, or a `scripts` member that is not an object, for the subject, a parent
// and a history version, at commitLintStages, verifyCommit, --verify-commit, the
// reference-transaction hook and the pre-commit guard. A well-formed file that is not in
// canonical form keeps the reviewed rule (every lint stage required).
test('GDR9-AUTH-OBJECT-01, round 2: a package.json that can be read but is not well formed (not UTF-8, not JSON, not an object, a scripts member that is not an object) refuses for the subject, a parent and a history version at commitLintStages, verifyCommit, --verify-commit, the reference-transaction hook and the pre-commit guard; a well-formed noncanonical one keeps the two-lint rule', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const r = repository(t);
  const C0 = r.commit('C0: package.json defines no lint script');
  const { requiredStages } = m.finalization;
  const withBoth = [...requiredStages, ...bothLint];
  const subject = subjects(m, r, Date.now());
  const git = (args, input) =>
    execFileSync('git', args, {
      cwd: r.root,
      env: { ...m.platform.gitHistoryEnvironment(gitEnv), GIT_NO_LAZY_FETCH: '1' },
      input,
      stdio: 'pipe',
      maxBuffer: 64 * 1024 ** 2,
    });
  const derive = made => checker.commitLintStages(git, { tree: made.tree, parents: made.parents });
  const malformed = why =>
    `the package\\.json of [0-9a-f]+ \\(blob [0-9a-f]+\\) ${why}, so the lint scripts that version defines cannot be judged; nothing is approved for it \\(GDR9-AUTH-OBJECT-01\\)`;
  const derived = text =>
    new RegExp(
      `Commit check refused: the lint stages commit [0-9a-f]+ requires cannot be derived from it, its parents and their history \\(Commit blocked: ${text}`
    );
  const notJson = malformed('is not well-formed JSON');
  // Canonical layout, with two bytes that are not UTF-8 inside a string: read as UTF-8 with
  // replacement characters, the file was canonical and defined no lint script.
  const notUtf8 = Buffer.concat([
    Buffer.from('{\n  "scripts": {},\n  "note": "'),
    Buffer.from([0xff, 0xfe]),
    Buffer.from('"\n}\n'),
  ]);
  const badParent = commitOn(
    r,
    [C0],
    { 'package.json': '{ "scripts": { "lint:sql": "node scripts/sql-lint.mjs" ' },
    'P: a parent whose package.json is not JSON'
  );
  const badHistory = commitOn(
    r,
    [C0],
    { 'package.json': '{ "scripts": { "lint:sql": "x" ' },
    'H: a version that names lint:sql and does not parse'
  );
  const fixedHistory = commitOn(
    r,
    [badHistory.commit],
    { 'package.json': canonicalPackage({}) },
    'H2: canonical again, no lint script'
  );
  for (const [label, parents, files, stages, pattern] of [
    [
      "check-1's OBJECT-SUBJ-MALFORMED-JSON-BOTH-LINT: the subject's package.json is truncated JSON, the run has both lint stages",
      [C0],
      { 'package.json': '{ "scripts": { "lint:sql": ' },
      withBoth,
      notJson,
    ],
    [
      "the subject's package.json, canonical in layout, holds bytes that are not UTF-8, the run without lint stages",
      [C0],
      { 'package.json': { bytes: notUtf8 } },
      requiredStages,
      malformed('is not UTF-8 text'),
    ],
    [
      "the subject's package.json is a byte order mark and canonical JSON, the run has both lint stages",
      [C0],
      { 'package.json': `﻿${canonicalPackage({})}` },
      withBoth,
      notJson,
    ],
    [
      "the subject's package.json is a JSON list, the run has both lint stages",
      [C0],
      { 'package.json': '[]\n' },
      withBoth,
      malformed('is not a JSON object'),
    ],
    [
      "the subject's package.json has a scripts member that is text, in canonical layout, the run has both lint stages",
      [C0],
      { 'package.json': `${JSON.stringify({ scripts: 'lint:sql' }, null, 2)}\n` },
      withBoth,
      malformed('has a scripts member that is not an object'),
    ],
    [
      "a parent's package.json is not JSON (it names lint:sql), the run has both lint stages",
      [badParent.commit],
      { 'package.json': canonicalPackage({}) },
      withBoth,
      notJson,
    ],
    [
      "check-1's OBJECT-HIST-MALFORMED-JSON-NO-LINT: a history version that names lint:sql does not parse, the run without lint stages",
      [fixedHistory.commit],
      {},
      requiredStages,
      notJson,
    ],
  ]) {
    const outcome = await subject(parents, files, stages);
    assert.throws(() => derive(outcome), new RegExp(pattern), label);
    refusedAtEntryPoints(label, outcome, derived(pattern));
  }
  // Still accepted: a well-formed package.json that is not in canonical form (every lint stage
  // required), one with no scripts member (the same), and an ordinary one.
  for (const [label, files, stages, expected] of [
    [
      'a compact, well-formed package.json, the run has both lint stages',
      { 'package.json': '{"scripts":{}}\n' },
      withBoth,
      bothLint,
    ],
    [
      'a canonical package.json with no scripts member, the run has both lint stages',
      { 'package.json': '{}\n' },
      withBoth,
      bothLint,
    ],
    ['an ordinary subject, the run without lint stages', {}, requiredStages, []],
  ]) {
    const outcome = await subject([C0], files, stages);
    assert.deepEqual(derive(outcome), expected, label);
    acceptedAtEntry(label, outcome);
  }

  // The pre-commit guard shares the typed reader: the candidate's package.json is not JSON, with a
  // run that has both lint stages; and HEAD's history holds a version that names lint:sql and does
  // not parse, with a run without lint stages (the guard read that version as defining nothing
  // and approved it).
  const p = repository(t);
  const P0 = p.commit('C0: package.json defines no lint script');
  const guarded = (label, pattern) => {
    const result = p.guard();
    assert.equal(result.status, 1, `${label}: ${result.stderr}`);
    assert.match(result.stderr, pattern, label);
  };
  p.write('package.json', '{ "scripts": { "lint:sql": ');
  p.git('add', '-A');
  const staged = m.securityRun.candidate(p.root);
  m.securityRun.finalizedRun(
    path.join(p.security, `${staged.tree}-commit-not-json`),
    staged,
    m.securityRun.allStages
  );
  guarded(
    "pre-commit: the candidate's package.json is not JSON",
    new RegExp(`^Commit blocked: ${notJson}`)
  );
  const H = commitOn(p, [P0], { 'package.json': '{ "scripts": { "lint:sql": "x" ' }, 'H: not JSON');
  const F = commitOn(p, [H.commit], { 'package.json': canonicalPackage({}) }, 'F: canonical again');
  p.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', F.commit);
  p.write('candidate.txt', 'candidate\n');
  p.git('add', '-A');
  approveStaged(m, p);
  guarded(
    'pre-commit: a history version that names lint:sql does not parse',
    new RegExp(`^Commit blocked: ${notJson}`)
  );
  // Control: the same candidate on a history without that version is approved.
  p.git('-c', 'core.hooksPath=/dev/null', 'reset', '--quiet', '--hard', P0);
  p.write('candidate.txt', 'candidate\n');
  p.git('add', '-A');
  approveStaged(m, p);
  const approved = p.guard();
  assert.equal(approved.status, 0, `pre-commit control: ${approved.stderr}`);
});

// GDR9-HOST-SCHEMA-01, round 2 (check-1: a mixed variant). The host variant was chosen by its member
// set alone, so a contract run (a candidate with the platform contract, which only the 1.5 gate
// writes, with a catalog) whose host had only the maintenance form's three members was accepted at
// the finalizer, recordedApproval and the three entry points: the 1.5 form's release and uid were
// in effect optional. The form a record may carry now follows from its kind
// (RUN_HOST_FORMS_BY_RECORD): a contract or companion run carries the 1.5 gate's five members; a
// maintenance run, which both gates write, either form (test GDR9-HOST-SCHEMA-01 above).
// gate-draft-r11, GDR10-HOST-PRODUCER-01 (changed, following the maintainer's decision 073253 item 2):
// the maintenance form is the maintenance gate's four members { platform, arch, release, node }.
test('GDR9-HOST-SCHEMA-01, round 2: a contract run, or a companion run, whose host is the four-member maintenance form gives no authority at the finalizer, recordedApproval, verifyCommit, --verify-commit or the reference-transaction hook; the five-member form stays accepted', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const r = repository(t);
  const C0 = r.commit('C0: no lint script');
  const made = commitOn(r, [C0], { 'subject.txt': 'subject\n' }, 'X: the subject');
  const candidate = m.fixture.platformCandidate({ tree: made.tree, parents: [C0] });
  const now = Date.now();
  const companion = m.fixture.writeCompanion(r.security, candidate, { now });
  const current = { ...candidate.current, companions: [companion] };
  // The clean run, finalized and passed as F would, under a name no commit reads.
  const template = path.join(r.security, `${made.tree}-template`);
  m.fixture.writeMainRun(template, candidate, { platform: 'linux', now });
  const inventory = m.finalization.inspectRun(template, current, now);
  assert.deepEqual(inventory.blockers, []);
  const reviewFile = path.join(r.root, '.git', 'review-input.json');
  const { platform, ...binding } = m.fixture.reviewBinding(inventory);
  assert.ok(platform);
  fs.writeFileSync(
    reviewFile,
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
  m.finalization.finalizeRun(template, reviewFile, current, now);
  m.fixture.asIfFinalizedByF(template);
  let twins = 0;
  const twin = change => {
    const run = path.join(r.security, `${made.tree}-commit-host-twin-${(twins += 1)}`);
    m.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: { record: change } });
    const finalized = path.join(run, 'finalization');
    fs.mkdirSync(finalized, { mode: 0o700 });
    const runSha256 = sha(fs.readFileSync(path.join(run, 'run-manifest.json')));
    const review = JSON.parse(
      fs.readFileSync(path.join(template, 'finalization', 'review.json'), 'utf8')
    );
    review.runSha256 = runSha256;
    const reviewBytes = Buffer.from(JSON.stringify(review));
    fs.writeFileSync(path.join(finalized, 'review.json'), reviewBytes, { mode: 0o600 });
    const approval = JSON.parse(
      fs.readFileSync(path.join(template, 'finalization', 'approval.json'), 'utf8')
    );
    Object.assign(approval, { runSha256, reviewSha256: sha(reviewBytes) });
    fs.writeFileSync(path.join(finalized, 'approval.json'), JSON.stringify(approval), {
      mode: 0o600,
    });
    return { ...made, run };
  };
  const retire = item =>
    fs.renameSync(item.run, item.run.replace('-commit-host-twin-', '-retired-host-twin-'));
  const lint = { lintStages: [] };
  const four = { platform: 'linux', arch: 'arm64', release: 'synthetic-6.0', node: 'v26.5.1' };
  // The finalizer's answer: its blockers, or what it throws (a record it cannot read).
  const finalizerRefuses = (run, judgedCurrent, pattern, label) => {
    let message;
    try {
      const judged = m.finalization.inspectRun(run, judgedCurrent, now);
      assert.equal(judged.eligible, false, label);
      message = judged.blockers.join('\n');
    } catch (error) {
      message = error.message;
    }
    assert.match(message, pattern, label);
  };
  // Control: an unchanged twin, the 1.5 gate's five members.
  const kept = twin(() => {});
  const sealed = JSON.parse(fs.readFileSync(path.join(kept.run, 'result.json'), 'utf8'));
  assert.deepEqual(Object.keys(sealed.host).sort(), ['arch', 'node', 'platform', 'release', 'uid']);
  assert.deepEqual(m.finalization.inspectRun(kept.run, current, now).blockers, []);
  assert.equal(m.finalization.recordedApproval(kept.run, lint).approval.status, 'pass');
  acceptedEverywhere(
    'control: a contract run with the 1.5 gate host form',
    await boundEntryPoints(kept, { root: r.root, intents: path.join(r.root, '.git') })
  );
  retire(kept);
  // check-1's HOST-CONTRACT-WITH-MAINTENANCE-3.
  const mixed =
    /run record's host is not one of its closed producer forms \(GDR9-HOST-SCHEMA-01\): the host is the maintenance form \[platform, arch, release, node\], which a contract commit record \(its candidate has the platform contract\), which only the 1\.5 gate writes, does not carry: it carries only the gate-1\.5 form \[platform, arch, release, node, uid\]/;
  const item = twin(result => {
    result.host = { ...four };
  });
  finalizerRefuses(
    item.run,
    current,
    mixed,
    'the finalizer: a contract run with the maintenance form'
  );
  assert.throws(() => m.finalization.recordedApproval(item.run, lint), mixed);
  refusedEverywhere(
    "check-1's HOST-CONTRACT-WITH-MAINTENANCE-3: a contract run whose host is the maintenance form",
    await boundEntryPoints(item, { root: r.root, intents: path.join(r.root, '.git') }),
    refusedAtEntry
  );
  retire(item);
  // A companion (platform mode) run whose host is the maintenance form: refused by the record
  // reader and so by the finalizer that judges the main run with it.
  const fourCompanion = m.fixture.writeCompanion(r.security, candidate, {
    now,
    change: {
      record: record => {
        record.host = { ...four };
      },
    },
  });
  const companionPattern =
    /the host is the maintenance form \[platform, arch, release, node\], which a companion \(platform mode\) record, which only the 1\.5 gate writes, does not carry: it carries only the gate-1\.5 form/;
  assert.throws(
    () =>
      m.finalization.parseRunRecord(fs.readFileSync(path.join(fourCompanion, 'result.json')), {
        mode: 'platform',
      }),
    companionPattern
  );
  finalizerRefuses(
    template,
    { ...candidate.current, companions: [fourCompanion] },
    companionPattern,
    'the finalizer: a companion run with the maintenance form'
  );
});

// GDR9-AUTH-ROOT-01, round 2 (check-1's two low items). (1) An object store is chosen by a file
// too: an info/alternates file in the bound repository's own object directory, or in its
// quarantine (where receive-pack writes none), brought a commit object in from a foreign store,
// and all three entry points accepted it (ROOT-QUAR-INFO-ALTERNATES, ROOT-REPO-OWN-ALTERNATES-FILE).
// An alternates file that names a store now refuses; one that names none (empty, or comments
// only) is admitted. (2) A root spelled in another letter case on a case-insensitive file system
// was refused by programmatic verifyCommit and accepted by the CLI and the hook
// (ROOT-CASE-ROOT); the root is now canonicalized with the operating system's realpath, which
// gives the file system's own case, so all three agree.
test('GDR9-AUTH-ROOT-01, round 2: an alternates file naming another object store, in the bound object directory or its quarantine, refuses at verifyCommit, --verify-commit and the reference-transaction hook, one naming none is admitted, and a root in another letter case is judged alike at all three', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const { requiredStages } = m.finalization;
  const b = repository(t);
  const b0 = b.commit('B: C0');
  const made = await subjects(m, b, Date.now())([b0], {}, requiredStages);
  acceptedAtEntry("control: B's approved commit, root B, a clean environment", made);
  const bGit = path.join(b.root, '.git');
  const foreign = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r10r2-store-')));
  t.after(() => fs.rmSync(foreign, { recursive: true, force: true }));
  const alternatesFile =
    /names another object store .*: the authority reads only the repository's own objects \(GDR9-AUTH-ROOT-01\)/;
  const info = path.join(bGit, 'objects', 'info');
  fs.mkdirSync(info, { recursive: true });
  const own = path.join(info, 'alternates');
  // B's own alternates file names the foreign store, which holds B's commit object.
  const back = moveObject(bGit, made.commit, foreign);
  fs.writeFileSync(own, `${foreign}\n`);
  refusedEverywhere(
    "check-1's ROOT-REPO-OWN-ALTERNATES-FILE: B's own objects/info/alternates names a foreign store holding the commit",
    await boundEntryPoints(made, { root: b.root, intents: bGit }),
    new RegExp(
      `cannot be bound: the info/alternates file of the repository's object directory .*${alternatesFile.source}`
    )
  );
  fs.writeFileSync(own, '# no store\n\n');
  refusedEverywhere(
    'control: an alternates file that names no store, the commit object still elsewhere',
    await boundEntryPoints(made, { root: b.root, intents: bGit }),
    /rev-parse --verify/
  );
  back();
  acceptedEverywhere(
    'an alternates file that names no store (comments and blank lines only), the commit in B',
    await boundEntryPoints(made, { root: b.root, intents: bGit })
  );
  fs.rmSync(own);
  // B's own quarantine, as receive-pack gives it, whose own info/alternates names the foreign store.
  const quarantine = path.join(bGit, 'objects', 'tmp_objdir-incoming-R2abc');
  const ownQuarantine = {
    GIT_QUARANTINE_PATH: quarantine,
    GIT_OBJECT_DIRECTORY: quarantine,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(bGit, 'objects'),
  };
  const backFromB = moveObject(bGit, made.commit, foreign);
  fs.mkdirSync(path.join(quarantine, 'info'), { recursive: true });
  fs.writeFileSync(path.join(quarantine, 'info', 'alternates'), `${foreign}\n`);
  refusedEverywhere(
    "check-1's ROOT-QUAR-INFO-ALTERNATES: B's quarantine's own info/alternates names a foreign store holding the commit",
    await boundEntryPoints(made, { root: b.root, env: ownQuarantine, intents: bGit }),
    new RegExp(
      `cannot be bound: the info/alternates file of its quarantine .*${alternatesFile.source}`
    )
  );
  fs.rmSync(path.join(quarantine, 'info'), { recursive: true, force: true });
  backFromB();
  // The root in another letter case (check-1's ROOT-CASE-ROOT). On a case-insensitive file
  // system it names B, and all three entry points accept B's commit; on a case-sensitive one it
  // names nothing, and verifyCommit refuses it (the CLI and the hook cannot start there).
  const upper = path.join(path.dirname(b.root), path.basename(b.root).toUpperCase());
  assert.notEqual(upper, b.root);
  if (fs.existsSync(upper)) {
    t.diagnostic('case-insensitive file system: the other-case root names B');
    acceptedEverywhere(
      "check-1's ROOT-CASE-ROOT: root B in another letter case, on a case-insensitive file system",
      await boundEntryPoints(made, { root: upper, cwd: upper, intents: bGit })
    );
    const checker = await import('../scripts/check-security-approval.mjs');
    assert.deepEqual(
      checker.verifyCommit(made.commit, upper),
      { commit: made.commit, tree: made.tree, parents: made.parents },
      'verifyCommit judges B'
    );
  } else {
    t.diagnostic('case-sensitive file system: the other-case root names nothing');
    const checker = await import('../scripts/check-security-approval.mjs');
    assert.throws(
      () => checker.verifyCommit(made.commit, upper),
      /cannot be bound: the root folder does not exist/
    );
  }
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r11: the security review of the tenth round (REVISE BEFORE INTEGRATION), at the
// authority entry points.

// GDR10-ALT-PARSE-01 (review finding, Medium/P2; maintainer note 20261019T083721636234Z item 1). The tenth
// round read an objects/info/alternates file with trim() before it looked for comments, so the
// record ` #foreign` (a leading blank), which Git reads as the relative path ` #foreign`, was
// discarded as a comment: the binding accepted the repository and its bound runner read an object
// only the foreign store held (the security review's two isolated reproductions). Records are now read byte
// for byte as Git reads them (activeAlternateRecords): only an empty record and one whose first
// byte is `#` name no store, and every other record refuses, before any bound read can resolve an
// object through it. Each case below first shows that plain Git reads B's approved commit object,
// which only a foreign store holds, through that record (so a runner bound with the file in place
// would read it), then that bindRepository builds no runner at all and that verifyCommit,
// --verify-commit and the reference-transaction hook refuse at the binding, not at a missing
// object; in the repository, in a linked worktree of it and in its own quarantine. Exact-column
// comments, a commented CRLF record, blank records and an empty file stay admitted, and the
// repository, its linked worktree and its own quarantine keep working with them in place.
test('GDR10-ALT-PARSE-01: an alternates file is read byte for byte as Git reads it; a leading blank or tab before #, a blank-only path, a quoted path or a carriage return names a store and refuses before any bound read, at bindRepository, verifyCommit, --verify-commit and the reference-transaction hook, in the repository, a linked worktree and its quarantine; only empty and exact-column # records name none', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const { requiredStages } = m.finalization;
  // The grammar (Git's parse_alt_odb_entry): split at newline bytes only, nothing trimmed.
  const records = bytes => m.platform.activeAlternateRecords(Buffer.from(bytes));
  for (const [bytes, expected] of [
    ['', []],
    ['\n', []],
    ['\n\n\n', []],
    ['#foreign\n', []],
    ['#', []],
    ['# a note\r\n', []],
    ['# no store\n\n#\n', []],
    [' #foreign\n', [' #foreign']],
    ['\t#foreign\n', ['\t#foreign']],
    [' \n', [' ']],
    ['\t\n', ['\t']],
    ['   ', ['   ']],
    ['\r\n', ['\r']],
    ['/store\r\n', ['/store\r']],
    ['"/store"\n', ['"/store"']],
    ['""\n', ['""']],
    ['#a\n/b\n\n#c\n /d', ['/b', ' /d']],
  ])
    assert.deepEqual(records(bytes), expected, JSON.stringify(bytes));
  for (const bytes of ['/store\0\n', '\0/store\n', '#\0'])
    assert.throws(() => records(bytes), /NUL byte/, JSON.stringify(bytes));

  const b = repository(t);
  const b0 = b.commit('B: C0');
  const made = await subjects(m, b, Date.now())([b0], {}, requiredStages);
  acceptedAtEntry("control: B's approved commit, root B, a clean environment", made);
  const bGit = path.join(b.root, '.git');
  const objects = fs.realpathSync(path.join(bGit, 'objects'));
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r11-alternates-')));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  // The foreign store: from here on only it holds B's approved commit object.
  const foreign = path.join(base, 'foreign-objects');
  fs.mkdirSync(foreign);
  const back = moveObject(bGit, made.commit, foreign);
  const reads = (env = {}) =>
    spawnSync('git', ['-C', b.root, 'cat-file', '-e', made.commit], {
      env: { ...gitEnv, ...env },
    }).status === 0;
  assert.equal(reads(), false, 'control: B alone does not hold the commit object');
  const named = where =>
    new RegExp(
      `cannot be bound: the info/alternates file of ${where} .*names another object store \\(.*; Git reads every record but an empty one and one whose first byte is #, GDR10-ALT-PARSE-01\\): the authority reads only the repository's own objects \\(GDR9-AUTH-ROOT-01\\)`
    );
  // A linked worktree of B (its object directory is B's) and B's own quarantine, as receive-pack
  // gives it.
  const worktree = path.join(base, 'linked');
  b.git('worktree', 'add', '--quiet', '--detach', worktree, b0);
  const quarantine = path.join(objects, 'tmp_objdir-incoming-R11abc');
  fs.mkdirSync(quarantine);
  const ownQuarantine = {
    GIT_QUARANTINE_PATH: quarantine,
    GIT_OBJECT_DIRECTORY: quarantine,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: objects,
  };
  // One active record: `bytes` written as the alternates file of `store`, with `links` (a path and
  // the store it leads to) making Git read the foreign store through it.
  const active = async (label, store, bytes, links, env = {}) => {
    const file = path.join(store, 'info', 'alternates');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
    for (const [link, target] of links) fs.symlinkSync(target, link);
    try {
      assert.equal(
        reads(env),
        true,
        `${label}: plain Git reads the foreign-only object through it`
      );
      const where = store === objects ? "the repository's object directory" : 'its quarantine';
      // The bound consumer: no runner is built, so nothing can read the foreign-only object.
      let bound;
      assert.throws(
        () => {
          bound = m.platform.bindRepository(b.root, { env: { ...gitEnv, ...env } });
        },
        named(where),
        `${label}: bindRepository`
      );
      assert.equal(bound, undefined, `${label}: no bound runner exists`);
      refusedEverywhere(
        label,
        await boundEntryPoints(made, { root: b.root, env, intents: bGit }),
        named(where)
      );
      if (store === objects) {
        refusedEverywhere(
          `${label}, from a linked worktree of B`,
          await boundEntryPoints(made, { root: worktree, intents: bGit }),
          named(where)
        );
        // The pre-commit guard and the finalizer's candidate read bind the same way.
        const guarded = b.guard();
        assert.equal(guarded.status, 1, `${label}: the pre-commit guard: ${guarded.stderr}`);
        assert.match(guarded.stderr, named(where), `${label}: the pre-commit guard`);
        assert.throws(
          () => m.finalization.currentCandidate(b.root),
          named(where),
          `${label}: the finalizer's candidate`
        );
      }
    } finally {
      for (const [link] of links) fs.rmSync(link, { force: true });
      fs.rmSync(file, { force: true });
    }
  };
  const to = (from, target) => path.relative(path.dirname(from), target);
  // The security review's exact reproducer: the bytes 20 23 66 6f 72 65 69 67 6e 0a, with the relative path
  // ` #foreign` a link to the foreign store.
  assert.equal(Buffer.from(' #foreign\n').toString('hex'), '2023666f726569676e0a');
  for (const [label, record] of [
    ["The security review's reproducer: ' #foreign' (a leading blank)", ' #foreign'],
    ["a leading tab: '\\t#foreign'", '\t#foreign'],
    ["a blank-only path: ' '", ' '],
    ["a tab-only path: '\\t'", '\t'],
    ['a CRLF record: the relative path CR', '\r'],
  ]) {
    const link = path.join(objects, record);
    await active(label, objects, `${record}\n`, [[link, to(link, foreign)]]);
  }
  // A quoted path, a quoted path with a C escape, and an absolute path ending in CR.
  await active('a C-quoted absolute path', objects, `"${foreign}"\n`, []);
  const tabbed = path.join(base, 'tab\there');
  await active(
    'a C-quoted path whose \\t escape Git unquotes to a tab',
    objects,
    `"${path.join(base, 'tab\\there')}"\n`,
    [[tabbed, foreign]]
  );
  const returned = path.join(base, 'store\r');
  await active(
    'an absolute path in a CRLF record (its CR is part of the path)',
    objects,
    `${path.join(base, 'store')}\r\n`,
    [[returned, foreign]]
  );
  // The same in B's own quarantine, whose own info/alternates Git also follows.
  for (const [label, record] of [
    ["the quarantine's own ' #foreign'", ' #foreign'],
    ["the quarantine's own '\\t#foreign'", '\t#foreign'],
  ]) {
    const link = path.join(quarantine, record);
    await active(label, quarantine, `${record}\n`, [[link, to(link, foreign)]], ownQuarantine);
  }

  // Exact-column comments, a commented CRLF record, blank records and an empty file name no
  // store: Git does not read the foreign store through them (even with a link at `#foreign`), the
  // binding admits them, and the entry points refuse only because the commit object is missing.
  const commentLink = path.join(objects, '#foreign');
  fs.symlinkSync(to(commentLink, foreign), commentLink);
  const file = path.join(objects, 'info', 'alternates');
  for (const bytes of ['#foreign\n', '# a note\r\n\n#\n', '\n\n', '']) {
    fs.writeFileSync(file, bytes);
    assert.equal(reads(), false, `${JSON.stringify(bytes)}: Git reads no store`);
    assert.doesNotThrow(
      () => m.platform.bindRepository(b.root, { env: gitEnv }),
      JSON.stringify(bytes)
    );
    refusedEverywhere(
      `${JSON.stringify(bytes)}: names no store, the commit object still only in the foreign store`,
      await boundEntryPoints(made, { root: b.root, intents: bGit }),
      /rev-parse --verify/
    );
  }
  // With the object back in B: the repository, its linked worktree and its own quarantine (the
  // commit object moved into it) are accepted with such a file in place.
  back();
  fs.writeFileSync(file, '#foreign\n# a note\r\n\n');
  acceptedEverywhere(
    "an exact-column comment, a CRLF comment and a blank record: B's own objects",
    await boundEntryPoints(made, { root: b.root, intents: bGit })
  );
  acceptedEverywhere(
    'the same file, from a linked worktree of B',
    await boundEntryPoints(made, { root: worktree, intents: bGit })
  );
  fs.mkdirSync(path.join(quarantine, 'info'), { recursive: true });
  fs.writeFileSync(path.join(quarantine, 'info', 'alternates'), '#foreign\n');
  const backFromQuarantine = moveObject(bGit, made.commit, quarantine);
  acceptedEverywhere(
    "B's own quarantine, holding the commit object, with an exact-column comment in its own alternates file",
    await boundEntryPoints(made, {
      root: b.root,
      env: { GIT_DIR: bGit, ...ownQuarantine },
      intents: bGit,
    })
  );
  backFromQuarantine();
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r12: the security review of the eleventh round (REVISE BEFORE INTEGRATION), at the
// authority entry points.

// GDR11-AUTH-CONFIG-01 (review finding, Medium/P2; the maintainer's r12 scope items 1 and 4): the repository
// binding admitted the caller's Git configuration files (GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM and
// GIT_CONFIG_NOSYSTEM, with HOME and XDG_CONFIG_HOME passed on), so a setting there reached every
// bound read of the commit guard, verifyCommit, --verify-commit, the reference-transaction hook and
// the finalizer: `i18n.logOutputEncoding=UTF-16` re-encoded their formatted reads (the history walk
// and the commit-graph comparison), which then refused an approved commit, and a core.fsmonitor ran
// its program on every bound read of the index (write-tree, as the guard and the finalizer make).
// The repository's own .git/config did the same, and its `log.showSignature=true` made the
// commit-graph comparison start gpg.program for a signed commit. The binding now follows the one
// authority configuration policy (the stage environment's): no configuration file the caller's
// environment names, and command-line settings that win over the repository's own configuration
// (`core.fsmonitor=false`, `i18n.logOutputEncoding=UTF-8`, `log.showSignature=false`). Each case
// first shows with plain Git that the file or setting has its effect (a harness, with no Git
// variable inherited), then runs every entry point with it, each step judged on its own: the
// binding and the finalizer's reads (currentCandidate, platformInputs) directly, verifyCommit,
// --verify-commit and the reference-transaction hook as boundEntryPoints does, and the guard
// through `git commit` with the installed hooks. Each still accepts its approved commit, no bound
// read sees a caller's setting, and the logging helper never starts in a bound read (one with
// GIT_NO_LAZY_FETCH=1, which only the binding sets here: `git commit` itself is run without it).
// Explicit synthetic identity only (gitEnv); no ownership is changed: a repository another user
// owns is refused by Git's own check, which this policy makes no exception to, and is unmeasured.
test("GDR11-AUTH-CONFIG-01: the commit guard through git commit and its hooks, verifyCommit, --verify-commit, the reference-transaction hook and the finalizer's reads follow the one authority configuration policy: no configuration file named by GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, HOME or XDG_CONFIG_HOME reaches a bound read, no fsmonitor or signature program of the caller's or the repository's own starts for one, the repository's own output encoding changes none of them, and each still accepts its approved commit", async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const { requiredStages } = m.finalization;
  const r = repository(t);
  const c0 = r.commit('C0');
  const made = await subjects(m, r, Date.now())([c0], {}, requiredStages);
  acceptedAtEntry('control: the approved commit, a clean environment', made);
  installHooks(r);
  const rGit = fs.realpathSync(path.join(r.root, '.git'));
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r12-config-')));
  t.after(() => fs.rmSync(work, { recursive: true, force: true }));
  const write = (name, text, mode = 0o644) => {
    const target = path.join(work, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text, { mode });
    return target;
  };
  const helperLog = write('helper.log', '');
  const helper = write(
    'helper.sh',
    `#!/bin/sh\nprintf '%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" >> '${helperLog}'\nexit 1\n`,
    0o755
  );
  // A clean filter that logs each start the same way and gives its input back.
  const filterHelper = write(
    'filter.sh',
    `#!/bin/sh\nprintf '%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" >> '${helperLog}'\ncat\n`,
    0o755
  );
  const starts = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean);
  const boundStarts = () => starts().filter(line => line === '1').length;
  // The index's own time set back, so every entry it records is racily clean (as for a file
  // changed in the second the index was written) and Git checks its content, through a filter if
  // one applies.
  const stale = () =>
    fs.utimesSync(
      path.join(r.root, '.git', 'index'),
      new Date('2020-01-01T00:00:00Z'),
      new Date('2020-01-01T00:00:00Z')
    );
  // A commit object that looks signed, on a ref of its own (for the signature program).
  const signed = execFileSync(
    'git',
    ['-C', r.root, 'hash-object', '-t', 'commit', '-w', '--stdin'],
    {
      input: `tree ${r.git('rev-parse', `${c0}^{tree}`)}\nparent ${c0}\nauthor Orbit Fixture <fixture@example.invalid> 1767225600 +0000\ncommitter Orbit Fixture <fixture@example.invalid> 1767225600 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEESyntheticSyntheticSyntheticAAoJEAAAAAAAAAAA\n =AAAA\n -----END PGP SIGNATURE-----\n\nA synthetic commit that looks signed\n`,
      encoding: 'utf8',
      env: gitEnv,
    }
  ).trim();
  r.git('update-ref', 'refs/orbit-r12/signed', signed);
  const hostile = `[core]\n\tfsmonitor = ${helper}\n[orbit]\n\tinjected = yes\n[i18n]\n\tlogOutputEncoding = UTF-16\n[log]\n\tshowSignature = true\n[gpg]\n\tprogram = ${helper}\n`;
  const globalFile = write('global.gitconfig', hostile);
  const systemFile = write('system.gitconfig', hostile);
  const home = path.dirname(write('home/.gitconfig', hostile));
  const xdg = path.dirname(path.dirname(write('xdg/git/config', hostile)));
  // `extra` on top of gitEnv; an undefined value removes the variable.
  const environment = extra => {
    const env = { ...gitEnv };
    for (const [name, value] of Object.entries(extra))
      if (value === undefined) delete env[name];
      else env[name] = value;
    return env;
  };
  // The harness's plain Git: no Git variable inherited (a gate's test stage sets some), then
  // `extra`.
  const plainEnv = extra =>
    environment({
      ...Object.fromEntries(
        Object.keys(gitEnv)
          .filter(name => /^GIT_/i.test(name))
          .map(name => [name, undefined])
      ),
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      ...extra,
    });
  // verifyCommit, --verify-commit and the reference-transaction hook with `extra` (as
  // boundEntryPoints, with a removal honoured in this process's environment too).
  const entryPoints = extra => {
    const saved = {};
    for (const [name, value] of Object.entries(extra)) {
      saved[name] = process.env[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    let programmatic;
    try {
      checker.verifyCommit(made.commit, r.root);
      programmatic = { accepted: true, message: '' };
    } catch (error) {
      programmatic = { accepted: false, message: error.message };
    } finally {
      for (const [name, value] of Object.entries(saved))
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    }
    const env = environment(extra);
    const cli = spawnSync(process.execPath, [guardScript, '--verify-commit', made.commit], {
      cwd: r.root,
      encoding: 'utf8',
      env,
    });
    const folder = path.join(rGit, 'orbit-security', 'commit-intents');
    fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
    const intentFile = path.join(folder, `${process.pid}.json`);
    fs.writeFileSync(
      intentFile,
      JSON.stringify({
        schemaVersion: 1,
        pid: process.pid,
        head: made.parents[0],
        ref: 'refs/heads/main',
        tree: made.tree,
        parents: made.parents,
        approval: path.basename(made.run),
        approvalSha256: sha(fs.readFileSync(path.join(made.run, 'finalization', 'approval.json'))),
        writtenAt: new Date().toISOString(),
      }),
      { mode: 0o600 }
    );
    const hook = spawnSync(process.execPath, [guardScript, '--reference-transaction', 'prepared'], {
      cwd: r.root,
      input: `${made.parents[0]} ${made.commit} refs/heads/main\n`,
      encoding: 'utf8',
      env,
    });
    fs.rmSync(intentFile, { force: true });
    return { programmatic, cli, hook };
  };
  const failures = [];
  let count = 0;
  for (const [label, extra, local = [], attributes] of [
    ['GIT_CONFIG_GLOBAL', { GIT_CONFIG_GLOBAL: globalFile }],
    [
      'GIT_CONFIG_SYSTEM with GIT_CONFIG_NOSYSTEM=0',
      { GIT_CONFIG_SYSTEM: systemFile, GIT_CONFIG_NOSYSTEM: '0' },
    ],
    ['HOME/.gitconfig', { HOME: home, GIT_CONFIG_GLOBAL: undefined }],
    ['XDG_CONFIG_HOME/git/config', { XDG_CONFIG_HOME: xdg, GIT_CONFIG_GLOBAL: undefined }],
    ["the repository's own core.fsmonitor", {}, [['core.fsmonitor', helper]]],
    [
      "the repository's own i18n.logOutputEncoding=UTF-16 and log.showSignature=true with gpg.program",
      {},
      [
        ['i18n.logOutputEncoding', 'UTF-16'],
        ['log.showSignature', 'true'],
        ['gpg.program', helper],
      ],
    ],
    [
      "the repository's own filter driver (info/attributes filter=orbitf, filter.orbitf.clean=<helper>, required), every index entry racily clean",
      {},
      [
        ['filter.orbitf.clean', filterHelper],
        ['filter.orbitf.required', 'true'],
      ],
      '* filter=orbitf\n',
    ],
  ]) {
    try {
      for (const [key, value] of local) r.git('config', key, value);
      if (attributes) fs.writeFileSync(path.join(rGit, 'info', 'attributes'), attributes);
      const env = environment(extra);
      // The harness: plain Git reads the setting, starts a helper and re-encodes its output.
      fs.writeFileSync(helperLog, '');
      stale();
      const plain = args =>
        spawnSync('git', ['-C', r.root, ...args], { env: plainEnv(extra), encoding: 'latin1' });
      const plainSeen = plain(['config', '--get-regexp', '^orbit\\.']).stdout.trim();
      plain(['write-tree']);
      // Git on Linux checks no racily clean entry in write-tree (Apple Git does); a refresh of the
      // index does on both, so the repository's own filter driver starts there too.
      plain(['update-index', '-q', '--refresh']);
      plain(['log', '-1', '--no-walk', '--format=%T %P', signed, '--']);
      const plainWalk = plain(['rev-list', '--format=%H %T %P', c0]).stdout;
      if (!local.length)
        assert.equal(plainSeen, 'orbit.injected yes', 'the harness: plain Git reads it');
      assert.ok(starts().length > 0, 'the harness: plain Git starts a helper');
      if (
        extra.GIT_CONFIG_GLOBAL ||
        extra.GIT_CONFIG_SYSTEM ||
        extra.HOME ||
        extra.XDG_CONFIG_HOME ||
        local.some(([key]) => key === 'i18n.logOutputEncoding')
      )
        assert.ok(plainWalk.includes('\0'), 'the harness: plain Git re-encodes rev-list --format');
      // Each entry point on its own, so a failing case names every defect it shows: what a bound
      // read sees and starts first, then the means.
      const problems = [];
      const step = (what, fn) => {
        fs.writeFileSync(helperLog, '');
        stale();
        try {
          fn();
          assert.equal(boundStarts(), 0, `a configured helper started ${boundStarts()} times`);
        } catch (error) {
          problems.push(`${what}: ${error.message.split('\n')[0]}`);
        }
      };
      const binding = m.platform.bindRepository(r.root, { env, index: true });
      const git = (args, input) => binding.run(args, input);
      const graphGit = (args, input) =>
        binding.run(args, input, { config: "'core.commitgraph=true'" });
      step('the binding', () => {
        assert.throws(
          () => binding.run(['config', '--get-regexp', '^orbit\\.']),
          /Command failed/,
          'a bound read sees a setting of the caller'
        );
        binding.run(['write-tree']);
        assert.deepEqual(
          m.platform.parentAmbiguityProblems({ git, graphGit, commits: [signed] }),
          [],
          'the commit-graph comparison of the signed-looking commit'
        );
        assert.deepEqual(
          m.platform.readHistory(git, [c0]).map(node => node.commit),
          [c0],
          'the history walk'
        );
      });
      step("the finalizer's reads", () => {
        const current = m.finalization.currentCandidate(r.root, { binding });
        assert.equal(current.parent, r.git('rev-parse', 'HEAD'), 'not this repository');
        m.finalization.platformInputs(
          r.root,
          current.tree,
          { heads: current.parents, complete: true, reason: '' },
          { binding }
        );
      });
      step('verifyCommit, --verify-commit and the reference-transaction hook', () =>
        acceptedEverywhere(label, entryPoints(extra))
      );
      // The guard, through git commit and its installed hooks (git commit without
      // GIT_NO_LAZY_FETCH, so a start in a bound read is told from Git's own).
      step('the commit guard through git commit', () => {
        r.write(`r12-${(count += 1)}.txt`, `${count}\n`);
        r.git('add', '-A');
        approveStaged(m, r);
        const committed = spawnSync(
          'git',
          ['-C', r.root, 'commit', '--quiet', '-m', `r12 ${count}`],
          {
            encoding: 'utf8',
            env: { ...env, GIT_NO_LAZY_FETCH: undefined },
          }
        );
        assert.equal(committed.status, 0, `git commit through the hooks: ${committed.stderr}`);
        assert.deepEqual(intentsOf(r), [], 'the reference-transaction hook left its record');
      });
      step('the means', () => {
        for (const [name, value] of Object.entries({
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_CONFIG_SYSTEM: '/dev/null',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_ATTR_NOSYSTEM: '1',
        }))
          assert.equal(binding.env[name], value, `the bound ${name}`);
      });
      if (problems.length) throw new Error(problems.join('; '));
    } catch (error) {
      failures.push(`${label}: ${error.message.split('\n')[0]}`);
    } finally {
      for (const [key] of local) r.git('config', '--unset', key);
      if (attributes) fs.rmSync(path.join(rGit, 'info', 'attributes'));
    }
  }
  assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
});

// Round 2 of gate-draft-r12 (check-1 of its first round; the maintainer's r12 scope items 1 and 4), at every
// authority entry point the shared binding serves. R12C1-FILTER-EQ-01: the binding switched each of
// the repository's filter drivers off in Git's 'key=value' form, which Git splits at the first `=`,
// so a driver named `a=b` stayed on, and one with an empty name was not listed; their clean program
// started in bound reads (write-tree in the guard and the finalizer). R12C1-HOOK-01: a
// post-index-change hook in .git/hooks, and a hook the repository's configuration defines
// (`hook.<name>.command`), started when a bound write-tree wrote the index. R12C1-HOME-INCLUDE-01:
// a `~/` include in the repository's own configuration was resolved against the caller's HOME, so
// the caller's environment chose a file that bound reads read (its setting was visible to them, and
// a hook it defined started). Each case first shows with plain Git that it has its effect, then runs
// the binding and the finalizer's reads directly, verifyCommit, --verify-commit and the
// reference-transaction hook, and the guard through `git commit` with the installed hooks, each step
// judged on its own; before each, every index entry is made racily clean and the cache-tree invalid
// (an entry added and removed again), so a bound write-tree checks content and writes the index. A
// start in a bound read is one with GIT_NO_LAZY_FETCH=1, which only the binding sets here.
test("R12C1-FILTER-EQ-01, R12C1-HOOK-01 and R12C1-HOME-INCLUDE-01: the commit guard through git commit, verifyCommit, --verify-commit, the reference-transaction hook and the finalizer's reads start no filter driver named with = or with an empty name, no hook in .git/hooks or defined in the repository's configuration, and read no file that a ~/ include names through the caller's HOME; each still accepts its approved commit", async t => {
  if (gitSkip) return t.skip(gitSkip);
  const m = await load();
  const checker = await import('../scripts/check-security-approval.mjs');
  const { requiredStages } = m.finalization;
  const r = repository(t);
  const c0 = r.commit('C0');
  const made = await subjects(m, r, Date.now())([c0], {}, requiredStages);
  installHooks(r);
  const rGit = fs.realpathSync(path.join(r.root, '.git'));
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-r12r2-config-')));
  t.after(() => fs.rmSync(work, { recursive: true, force: true }));
  const helperLog = path.join(work, 'helper.log');
  fs.writeFileSync(helperLog, '');
  // Logs each start, with whether a bound read started it, and gives its input back.
  const helper = path.join(work, 'helper.sh');
  fs.writeFileSync(
    helper,
    `#!/bin/sh\nprintf '%s\\n' "\${GIT_NO_LAZY_FETCH:-unset}" >> '${helperLog}'\ncat\n`,
    { mode: 0o755 }
  );
  const starts = () => fs.readFileSync(helperLog, 'utf8').split('\n').filter(Boolean);
  const boundStarts = () => starts().filter(line => line === '1').length;
  const home = path.join(work, 'home');
  fs.mkdirSync(home);
  fs.writeFileSync(
    path.join(home, 'inc.config'),
    `[orbit]\n\tinjected = yes\n[hook "fromhome"]\n\tcommand = ${helper}\n\tevent = post-index-change\n`
  );
  const config = path.join(rGit, 'config');
  const original = fs.readFileSync(config);
  const plainEnv = extra => {
    const env = Object.fromEntries(Object.entries(gitEnv).filter(([name]) => !/^GIT_/i.test(name)));
    Object.assign(env, { GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', ...extra });
    return env;
  };
  // Every index entry racily clean and the cache-tree invalid, the index's content unchanged.
  const prepare = () => {
    const blob = r.git('hash-object', '-w', '--no-filters', '--stdin');
    r.git('update-index', '--add', '--cacheinfo', `100644,${blob},r12r2-probe.txt`);
    r.git('update-index', '--force-remove', 'r12r2-probe.txt');
    fs.utimesSync(
      path.join(rGit, 'index'),
      new Date('2020-01-01T00:00:00Z'),
      new Date('2020-01-01T00:00:00Z')
    );
  };
  const entryPoints = extra => {
    const saved = {};
    for (const [name, value] of Object.entries(extra)) {
      saved[name] = process.env[name];
      process.env[name] = value;
    }
    let programmatic;
    try {
      checker.verifyCommit(made.commit, r.root);
      programmatic = { accepted: true, message: '' };
    } catch (error) {
      programmatic = { accepted: false, message: error.message };
    } finally {
      for (const [name, value] of Object.entries(saved))
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    }
    const env = { ...gitEnv, ...extra };
    const cli = spawnSync(process.execPath, [guardScript, '--verify-commit', made.commit], {
      cwd: r.root,
      encoding: 'utf8',
      env,
    });
    const folder = path.join(rGit, 'orbit-security', 'commit-intents');
    fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
    const intentFile = path.join(folder, `${process.pid}.json`);
    fs.writeFileSync(
      intentFile,
      JSON.stringify({
        schemaVersion: 1,
        pid: process.pid,
        head: made.parents[0],
        ref: 'refs/heads/main',
        tree: made.tree,
        parents: made.parents,
        approval: path.basename(made.run),
        approvalSha256: sha(fs.readFileSync(path.join(made.run, 'finalization', 'approval.json'))),
        writtenAt: new Date().toISOString(),
      }),
      { mode: 0o600 }
    );
    const hook = spawnSync(process.execPath, [guardScript, '--reference-transaction', 'prepared'], {
      cwd: r.root,
      input: `${made.parents[0]} ${made.commit} refs/heads/main\n`,
      encoding: 'utf8',
      env,
    });
    fs.rmSync(intentFile, { force: true });
    return { programmatic, cli, hook };
  };
  const postIndexChange = path.join(rGit, 'hooks', 'post-index-change');
  const failures = [];
  let count = 0;
  for (const [label, setup, teardown = () => {}, extra = {}] of [
    [
      "the repository's filter driver named a=b (info/attributes filter=a=b, required)",
      () => {
        fs.appendFileSync(config, `[filter "a=b"]\n\tclean = ${helper}\n\trequired = true\n`);
        fs.writeFileSync(path.join(rGit, 'info', 'attributes'), '* filter=a=b\n');
      },
      () => fs.rmSync(path.join(rGit, 'info', 'attributes')),
    ],
    [
      "the repository's filter driver with an empty name (info/attributes filter=, required)",
      () => {
        fs.appendFileSync(config, `[filter ""]\n\tclean = ${helper}\n\trequired = true\n`);
        fs.writeFileSync(path.join(rGit, 'info', 'attributes'), '* filter=\n');
      },
      () => fs.rmSync(path.join(rGit, 'info', 'attributes')),
    ],
    [
      'a post-index-change hook in .git/hooks',
      () => fs.copyFileSync(helper, postIndexChange),
      () => fs.rmSync(postIndexChange),
    ],
    [
      "a hook the repository's configuration defines (hook.orbitr2.command, event post-index-change)",
      () =>
        fs.appendFileSync(
          config,
          `[hook "orbitr2"]\n\tcommand = ${helper}\n\tevent = post-index-change\n`
        ),
    ],
    [
      "the repository's include.path=~/inc.config, HOME naming a file with a setting and a hook",
      () => fs.appendFileSync(config, '[include]\n\tpath = ~/inc.config\n'),
      () => {},
      { HOME: home },
    ],
  ]) {
    try {
      setup();
      // The harness: plain Git starts the helper (and, for the include, reads the setting).
      prepare();
      fs.writeFileSync(helperLog, '');
      const plain = spawnSync('git', ['-C', r.root, 'write-tree'], { env: plainEnv(extra) });
      assert.equal(plain.status, 0, `the harness: plain write-tree: ${plain.stderr}`);
      assert.ok(starts().length > 0, 'the harness: plain Git starts the helper');
      if (extra.HOME)
        assert.equal(
          spawnSync('git', ['-C', r.root, 'config', '--get', 'orbit.injected'], {
            env: plainEnv(extra),
            encoding: 'utf8',
          }).stdout.trim(),
          'yes',
          'the harness: plain Git reads the included file'
        );
      const problems = [];
      // `before` runs before the log is cleared (its own Git is not a bound read, but may carry
      // GIT_NO_LAZY_FETCH from a gate's test stage).
      const step = (what, fn, before = () => {}) => {
        try {
          before();
          prepare();
          fs.writeFileSync(helperLog, '');
          fn();
          assert.equal(boundStarts(), 0, `a configured helper started ${boundStarts()} times`);
        } catch (error) {
          problems.push(`${what}: ${error.message.split('\n')[0]}`);
        }
      };
      const binding = m.platform.bindRepository(r.root, {
        env: { ...gitEnv, ...extra },
        index: true,
      });
      step('the binding', () => {
        assert.throws(
          () => binding.run(['config', '--get', 'orbit.injected']),
          /Command failed/,
          'a bound read sees a setting a file of the caller names'
        );
        binding.run(['write-tree']);
        assert.equal(binding.env.HOME, m.platform.NO_HOME, 'the bound HOME');
      });
      step("the finalizer's reads", () => {
        const current = m.finalization.currentCandidate(r.root, { binding });
        assert.equal(current.parent, r.git('rev-parse', 'HEAD'), 'not this repository');
        m.finalization.platformInputs(
          r.root,
          current.tree,
          { heads: current.parents, complete: true, reason: '' },
          { binding }
        );
      });
      step('verifyCommit, --verify-commit and the reference-transaction hook', () =>
        acceptedEverywhere(label, entryPoints(extra))
      );
      step(
        'the commit guard through git commit',
        () => {
          const committed = spawnSync(
            'git',
            ['-C', r.root, 'commit', '--quiet', '-m', `r12r2 ${count}`],
            { encoding: 'utf8', env: { ...gitEnv, ...extra, GIT_NO_LAZY_FETCH: undefined } }
          );
          assert.equal(committed.status, 0, `git commit through the hooks: ${committed.stderr}`);
          assert.deepEqual(intentsOf(r), [], 'the reference-transaction hook left its record');
        },
        () => {
          r.write(`r12r2-${(count += 1)}.txt`, `${count}\n`);
          r.git('add', '-A');
          approveStaged(m, r);
        }
      );
      if (problems.length) throw new Error(problems.join('; '));
    } catch (error) {
      failures.push(`${label}: ${error.message.split('\n')[0]}`);
    } finally {
      teardown();
      fs.writeFileSync(config, original);
    }
  }
  assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
});
