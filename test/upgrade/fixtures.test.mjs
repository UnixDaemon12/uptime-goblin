import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { gzip, readTar, writeTar } from './tar.mjs';
import {
  checkRecordedCommit,
  fixtures,
  formatSums,
  gitTag,
  history,
  historyRequired,
  installRelease,
  nodemailer,
  nodemailerTarball,
  pins,
  parseRewrites,
  readHistory,
  releaseFiles,
  releaseFixture,
  root,
  runtimeFile,
  sha256,
  skipWithoutFixtures,
  versions,
} from './fixtures.mjs';
import { historySchema } from './history.mjs';
import { temporary } from './harness.mjs';

// The 1.4.2 fixture was built from the commit its tag named then. Which commit that was, and the
// reviewed rewrite of it after a history rewrite that changed commit ids but no tree, are in the
// private history input (TEST_HISTORY, history.mjs), and so is the repository holding the tag.
// The tag v1.4.2 there has to name that commit, or its listed rewrite with the listed source tree
// (checkRecordedCommit() in fixtures.mjs), and hold exactly the fixture's runtime files. The
// recorded commit object need not be in that repository.

// The history and the commit its v1.4.2 tag names. Only a missing history input, a missing git,
// a repository that is not one or that has no such tag may skip the calling test, and
// TEST_REQUIRE=history makes those fail too; a wrong history input or a broken Git throws, which
// fails the test whatever TEST_REQUIRE says.
function taggedCommit142(t) {
  const input = history();
  const found = input.unavailable ? null : gitTag('v1.4.2', input.repository);
  const unavailable = input.unavailable ?? found.unavailable;
  if (!unavailable) return { input, commit: found.commit };
  if (historyRequired())
    assert.fail(`no git checkout with the v1.4.2 tag: ${unavailable} (TEST_REQUIRE=history)`);
  t.skip(`no git checkout with the v1.4.2 tag: ${unavailable}`);
  return null;
}

test('every fixture is pinned, and the pins cover nothing else', t => {
  if (skipWithoutFixtures(t)) return;
  const expected = [nodemailer.file, ...versions.map(releaseFixture)].sort(),
    present = ['releases', 'npm'].flatMap(dir =>
      fs.readdirSync(path.join(fixtures, dir)).map(file => `${dir}/${file}`)
    );
  assert.deepEqual([...pins().keys()].sort(), expected);
  assert.deepEqual(present.sort(), expected, 'no unpinned files next to the fixtures');
  for (const [file, hash] of pins())
    assert.equal(sha256(fs.readFileSync(path.join(fixtures, file))), hash, file);
});

test('each release fixture holds exactly its runtime files, as its SHA256SUMS lists them', t => {
  if (skipWithoutFixtures(t)) return;
  for (const version of versions) {
    const { files, sums, provenance } = releaseFiles(version);
    assert.deepEqual(
      [...files.keys()].sort(),
      [...sums.keys()].filter(runtimeFile).sort(),
      version
    );
    assert.ok(files.has('server.mjs') && files.has('lib/store.mjs') && files.has('public/app.js'));
    assert.match(provenance.source.sha256, /^[a-f0-9]{64}$/);
    // Every release since 1.1.0 locks the vendored nodemailer by the same integrity hash.
    const lock = JSON.parse(files.get('package-lock.json'));
    assert.deepEqual(
      {
        version: lock.packages['node_modules/nodemailer'].version,
        integrity: lock.packages['node_modules/nodemailer'].integrity,
      },
      { version: nodemailer.version, integrity: nodemailer.integrity },
      version
    );
  }
});

test('a changed fixture, or a changed file inside one, is refused before anything runs', t => {
  if (skipWithoutFixtures(t)) return;
  // A copy of the fixtures, so tests running in parallel keep reading the real ones.
  const copy = temporary(t),
    fixture = releaseFixture('1.4.2'),
    original = fs.readFileSync(path.join(fixtures, fixture));
  fs.mkdirSync(path.join(copy, 'releases'));
  fs.copyFileSync(path.join(fixtures, 'SHA256SUMS'), path.join(copy, 'SHA256SUMS'));
  const write = (entries, repin = false) => {
    const bytes = gzip(writeTar(entries));
    fs.writeFileSync(path.join(copy, fixture), bytes);
    if (repin)
      fs.writeFileSync(
        path.join(copy, 'SHA256SUMS'),
        formatSums(new Map([...pins(), [fixture, sha256(bytes)]]))
      );
  };
  fs.writeFileSync(path.join(copy, fixture), original);
  assert.equal(releaseFiles('1.4.2', copy).files.size, 16);
  // A file changed inside the archive and re-packed: the pin catches it.
  const entries = readTar(original),
    changed = entries.map(e =>
      e.path === 'server.mjs' ? { ...e, data: Buffer.concat([e.data, Buffer.from('\n')]) } : e
    );
  write(changed);
  assert.throws(() => releaseFiles('1.4.2', copy), /does not match its pinned SHA-256/);
  // Re-pinned too: the release's own SHA256SUMS still catches it.
  write(changed, true);
  assert.throws(
    () => releaseFiles('1.4.2', copy),
    /server.mjs does not match the release SHA256SUMS/
  );
  // A runtime file left out, or an extra file added.
  write(
    entries.filter(e => e.path !== 'lib/auth.mjs'),
    true
  );
  assert.throws(() => releaseFiles('1.4.2', copy), /missing lib\/auth.mjs/);
  write([...entries, { path: 'lib/extra.mjs', data: Buffer.from('') }], true);
  assert.throws(() => releaseFiles('1.4.2', copy), /lib\/extra.mjs does not match/);
  write([...entries, { path: 'docs/extra.md', data: Buffer.from('') }], true);
  assert.throws(() => releaseFiles('1.4.2', copy), /unexpected fixture file docs\/extra.md/);
});

test('the vendored nodemailer matches npm integrity and installs with each release', t => {
  if (skipWithoutFixtures(t)) return;
  assert.equal(nodemailerTarball().length > 0, true);
  const directory = temporary(t),
    app = installRelease('1.1.0', path.join(directory, 'app'));
  assert.equal(app, fs.realpathSync(app));
  const installed = JSON.parse(
    fs.readFileSync(path.join(app, 'node_modules', 'nodemailer', 'package.json'), 'utf8')
  );
  assert.equal(installed.version, nodemailer.version);
  assert.equal(JSON.parse(fs.readFileSync(path.join(app, 'package.json'))).version, '1.1.0');
});

test('each release fixture records only its version and source archive, and no commit', t => {
  if (skipWithoutFixtures(t)) return;
  for (const version of versions) {
    const { provenance } = releaseFiles(version);
    assert.deepEqual(Object.keys(provenance).sort(), ['source', 'version'], version);
    assert.deepEqual(Object.keys(provenance.source).sort(), ['file', 'sha256'], version);
    assert.equal(provenance.source.file, `orbit-homelab-${version}.tar.gz`);
  }
});

test('the 1.4.2 fixture matches the tagged commit v1.4.2', t => {
  if (skipWithoutFixtures(t)) return;
  const found = taggedCommit142(t);
  if (!found) return;
  const { input, commit } = found;
  const recorded = input.fixtures['1.4.2'];
  assert.ok(recorded, 'the private history records the commit the 1.4.2 fixture was built from');
  const { files } = releaseFiles('1.4.2');
  // Everything below reads the commit gitTag() found, not the tag again.
  const git = (...args) =>
    execFileSync('git', ['-C', input.repository, ...args], { maxBuffer: 64 * 2 ** 20 });
  const tree = git('rev-parse', '--verify', `${commit}^{tree}`).toString('utf8').trim();
  const how = checkRecordedCommit(
    { tag: recorded.tag, recorded: recorded.commit, commit, tree },
    input.rewrites
  );
  t.diagnostic(`v1.4.2 names ${commit}, the ${how} commit, with tree ${tree}`);
  const tagged = git('ls-tree', '-r', '--name-only', commit)
    .toString('utf8')
    .split('\n')
    .filter(runtimeFile);
  assert.deepEqual(tagged.sort(), [...files.keys()].sort(), 'the runtime files of the tag');
  for (const [file, data] of files) assert.ok(git('show', `${commit}:${file}`).equals(data), file);
});

// The 1.4.2 fixture test in a runner of its own, from this checkout, with `env` added to an
// environment without the caller's test switches.
function runFixtureTest(env) {
  const base = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) =>
        !['NODE_TEST_CONTEXT', 'TEST_REQUIRE', 'TEST_HISTORY', 'TEST_TAG_TREES'].includes(name)
    )
  );
  const result = spawnSync(
    process.execPath,
    [
      '--test',
      '--test-reporter=tap',
      '--test-name-pattern=^the 1\\.4\\.2 fixture matches',
      path.join(root, 'test/upgrade/fixtures.test.mjs'),
    ],
    { cwd: root, encoding: 'utf8', env: { ...base, ...env } }
  );
  return {
    status: result.status,
    output: `${result.error?.message ?? ''}${result.stdout}${result.stderr}`,
  };
}

// Git for the synthetic histories below: skips without it, unless TEST_REQUIRE lists git.
function needsGit(t) {
  const result = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (result.error?.code !== 'ENOENT') return false;
  if (
    (process.env.TEST_REQUIRE ?? '')
      .split(',')
      .map(s => s.trim())
      .includes('git')
  )
    assert.fail('TEST_REQUIRE lists git, but git is not installed');
  t.skip('git is not installed (TEST_REQUIRE=git makes this fail)');
  return true;
}

/**
 * A synthetic history in a new folder: a Git repository whose commit `recorded` holds exactly the
 * 1.4.2 fixture's runtime files (tree `tree`), two more commits of that tree (`rewritten` and
 * `unrelated`), another tree (`otherTree`, the empty one), tag(commit) to point v1.4.2 at a
 * commit, and writeHistory() for a history input naming it (by default: the 1.4.2 fixture built
 * from `recorded`, no rewrites). passes() and fails() run the 1.4.2 fixture test with it and
 * TEST_REQUIRE=fixtures,history. No commit of this project's history is used or needed.
 */
function syntheticHistory(t) {
  const base = temporary(t, 'goblin-synthetic-history-');
  const repository = path.join(base, 'repository');
  fs.mkdirSync(repository);
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([n]) => !n.startsWith('GIT_'))),
    GIT_AUTHOR_NAME: 'Synthetic Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z',
    GIT_COMMITTER_NAME: 'Synthetic Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: path.join(base, 'no-global-config'),
  };
  const git = (args, input) =>
    execFileSync(
      'git',
      ['-C', repository, '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', ...args],
      { encoding: 'utf8', env, input, stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
  git(['init', '--quiet']);
  for (const [file, data] of releaseFiles('1.4.2').files) {
    fs.mkdirSync(path.dirname(path.join(repository, file)), { recursive: true });
    fs.writeFileSync(path.join(repository, file), data);
  }
  git(['add', '--all']);
  git(['commit', '--quiet', '-m', 'Synthetic 1.4.2']);
  const recorded = git(['rev-parse', 'HEAD']);
  const tree = git(['rev-parse', 'HEAD^{tree}']);
  const rewritten = git(['commit-tree', tree, '-m', 'Synthetic 1.4.2, rewritten']);
  const unrelated = git(['commit-tree', tree, '-m', 'Unrelated synthetic commit']);
  const otherTree = git(['mktree'], '');
  assert.equal(new Set([recorded, rewritten, unrelated]).size, 3);
  assert.notEqual(otherTree, tree);
  const tag = commit => git(['tag', '--force', 'v1.4.2', commit]);
  const file = path.join(base, 'history.json');
  const writeHistory = (change = {}) =>
    fs.writeFileSync(
      file,
      JSON.stringify({
        schema: historySchema,
        repository: 'repository',
        milestones: { '1.5.0-dev.0': recorded, '1.5.0-dev.1': recorded },
        fixtures: { '1.4.2': { tag: 'v1.4.2', commit: recorded } },
        rewrites: [],
        ...change,
      })
    );
  const run = () => runFixtureTest({ TEST_REQUIRE: 'fixtures,history', TEST_HISTORY: file });
  const passes = (what, how) => {
    const { status, output } = run();
    assert.equal(status, 0, `${what}\n${output}`);
    assert.match(output, /^# pass 1$/m, what);
    assert.match(output, new RegExp(`the ${how} commit`), what);
  };
  const fails = (what, says) => {
    const { status, output } = run();
    assert.notEqual(status, 0, `${what}\n${output}`);
    assert.match(output, /^# fail 1$/m, what);
    assert.match(output, says, what);
  };
  return {
    repository,
    file,
    git,
    recorded,
    rewritten,
    unrelated,
    tree,
    otherTree,
    tag,
    writeHistory,
    passes,
    fails,
  };
}

test('a synthetic history: the 1.4.2 fixture test takes the recorded commit, or its listed rewrite with the listed tree', t => {
  if (skipWithoutFixtures(t) || needsGit(t)) return;
  const h = syntheticHistory(t);
  h.tag(h.recorded);
  h.writeHistory();
  h.passes('the exact recorded commit, with no rewrites', 'recorded');
  h.tag(h.rewritten);
  h.writeHistory({ rewrites: [{ old: h.recorded, new: h.rewritten, tree: h.tree }] });
  h.passes('the listed rewrite with the listed tree', 'rewritten');
  // A bundle of the same history is read as the repository is.
  const bundle = path.join(path.dirname(h.file), 'history.bundle');
  h.git(['bundle', 'create', '--quiet', bundle, '--all']);
  h.writeHistory({
    repository: 'history.bundle',
    rewrites: [{ old: h.recorded, new: h.rewritten, tree: h.tree }],
  });
  h.passes('the listed rewrite, from a bundle', 'rewritten');
});

test('a synthetic history: the 1.4.2 fixture test refuses a missing mapping, a wrong commit and a wrong tree', t => {
  if (skipWithoutFixtures(t) || needsGit(t)) return;
  const h = syntheticHistory(t);
  const notRecorded = `v1\\.4\\.2 names ${h.rewritten}, not the recorded commit ${h.recorded}`;
  h.tag(h.rewritten);
  // Missing mapping: an empty list, or a rewrite the other way round, is no rewrite of it.
  h.writeHistory();
  h.fails(
    'no rewrites',
    new RegExp(`${notRecorded}, and the private history lists no rewrite of it`)
  );
  // The other way round names the tag's commit as an old id, which no fixture records.
  h.writeHistory({ rewrites: [{ old: h.rewritten, new: h.recorded, tree: h.tree }] });
  h.fails('a rewrite the other way round', /is in no fixture's provenance/);
  // Wrong commit: a commit of the same tree that the list does not give.
  h.tag(h.unrelated);
  h.writeHistory({ rewrites: [{ old: h.recorded, new: h.rewritten, tree: h.tree }] });
  h.fails(
    'another commit of the same tree',
    new RegExp(
      `v1\\.4\\.2 names ${h.unrelated}, not the recorded commit ${h.recorded} or its reviewed rewrite ${h.rewritten}`
    )
  );
  // Wrong tree: the listed rewrite, but the list gives another tree.
  h.tag(h.rewritten);
  h.writeHistory({ rewrites: [{ old: h.recorded, new: h.rewritten, tree: h.otherTree }] });
  h.fails(
    'the listed rewrite with another tree',
    new RegExp(`its tree ${h.tree} is not the reviewed tree ${h.otherTree}`)
  );
  // A tag whose files differ from the fixture's, recorded exactly: the file check refuses it.
  fs.appendFileSync(path.join(h.repository, 'server.mjs'), '\n');
  h.git(['commit', '--quiet', '--all', '-m', 'Changed']);
  const changed = h.git(['rev-parse', 'HEAD']);
  h.tag(changed);
  h.writeHistory({ fixtures: { '1.4.2': { tag: 'v1.4.2', commit: changed } } });
  h.fails('a tag whose server.mjs differs', /server\.mjs/);
  h.writeHistory({ rewrites: [{ old: h.recorded.slice(0, 12), new: h.rewritten, tree: h.tree }] });
  h.fails('an abbreviated id', /not a rewrite \{old, new, tree\} of full ids/);
});

test('a required private history that is missing, unreadable or wrong fails the 1.4.2 fixture test; only an optional missing one skips it', t => {
  if (skipWithoutFixtures(t) || needsGit(t)) return;
  const h = syntheticHistory(t);
  h.tag(h.recorded);
  const skipped = runFixtureTest({ TEST_REQUIRE: 'fixtures' });
  assert.equal(skipped.status, 0, skipped.output);
  assert.match(skipped.output, /^# skipped 1$/m);
  assert.match(
    skipped.output,
    /# SKIP no git checkout with the v1\.4\.2 tag: TEST_HISTORY is not set/
  );
  const required = runFixtureTest({ TEST_REQUIRE: 'fixtures,history' });
  assert.notEqual(required.status, 0, required.output);
  assert.match(required.output, /^# fail 1$/m);
  assert.match(required.output, /TEST_HISTORY is not set[^\n]*TEST_REQUIRE=history/);
  // A wrong input fails whatever TEST_REQUIRE says.
  const missing = path.join(path.dirname(h.file), 'absent.json');
  for (const [what, env, says] of [
    ['a TEST_HISTORY naming no file', { TEST_HISTORY: missing }, /ENOENT[^\n]*absent\.json/],
    ['a history input that is not JSON', { TEST_HISTORY: h.file, write: '{' }, /SyntaxError|JSON/],
    [
      'a history input of another schema',
      { TEST_HISTORY: h.file, write: { schema: 'other' } },
      /the schema is not uptime-goblin\.private-history\.v1/,
    ],
  ]) {
    if (env.write !== undefined)
      typeof env.write === 'string'
        ? fs.writeFileSync(h.file, env.write)
        : h.writeHistory(env.write);
    const outcome = runFixtureTest({ TEST_REQUIRE: 'fixtures', TEST_HISTORY: env.TEST_HISTORY });
    assert.notEqual(outcome.status, 0, `${what}\n${outcome.output}`);
    assert.match(outcome.output, /^# fail 1$/m, what);
    assert.match(outcome.output, says, what);
  }
  // A repository without the tag: a skip only while the history is optional.
  h.git(['tag', '--delete', 'v1.4.2']);
  h.writeHistory();
  const untagged = runFixtureTest({ TEST_REQUIRE: 'fixtures,history', TEST_HISTORY: h.file });
  assert.notEqual(untagged.status, 0, untagged.output);
  assert.match(untagged.output, /the repository has no v1\.4\.2 \(TEST_REQUIRE=history\)/);
});

test('checkRecordedCommit() takes the recorded commit, or its listed rewrite with the listed tree, and nothing else', () => {
  const [recorded, rewritten, other, tree, otherTree] = ['1', '2', '3', '4', '5'].map(c =>
    c.repeat(40)
  );
  const listed = new Map([[recorded, { commit: rewritten, tree }]]);
  const check = (commit, commitTree, rewrites = listed) =>
    checkRecordedCommit({ tag: 'v1.4.2', recorded, commit, tree: commitTree }, rewrites);
  // The recorded commit itself needs no list.
  assert.equal(check(recorded, tree, new Map()), 'recorded');
  assert.equal(check(recorded, tree, undefined), 'recorded');
  assert.equal(check(rewritten, tree), 'rewritten');
  assert.throws(() => check(rewritten, otherTree), /its tree 5{40} is not the reviewed tree 4{40}/);
  assert.throws(
    () => check(other, tree),
    /names 3{40}, not the recorded commit 1{40} or its reviewed rewrite 2{40}/
  );
  assert.throws(() => check(rewritten, tree, new Map()), /lists no rewrite of it/);
  // Without a list of reviewed rewrites, only the recorded commit itself passes.
  assert.throws(
    () => checkRecordedCommit({ tag: 'v1.4.2', recorded, commit: rewritten, tree }),
    /no list of reviewed rewrites/
  );
  // A rewrite listed for another commit, or the other way round, is no rewrite of this one.
  assert.throws(
    () => check(rewritten, tree, new Map([[other, { commit: rewritten, tree }]])),
    /lists no rewrite of it/
  );
  assert.throws(
    () => check(rewritten, tree, new Map([[rewritten, { commit: recorded, tree }]])),
    /lists no rewrite of it/
  );
  // A provenance without a full commit id matches nothing, not even the same value.
  for (const bad of [undefined, null, '', '1'.repeat(7), 'A'.repeat(40)])
    assert.throws(
      () => checkRecordedCommit({ tag: 'v1.4.2', recorded: bad, commit: bad, tree }, listed),
      /v1\.4\.2: the recorded commit is not a full id/
    );
});

test('parseRewrites() reads only a list of distinct rewrites of full ids', () => {
  const [a, b, c] = ['a', 'b', 'c'].map(x => x.repeat(40));
  assert.deepEqual(
    parseRewrites([{ old: a, new: b, tree: c }], 'list'),
    new Map([[a, { commit: b, tree: c }]])
  );
  assert.deepEqual(parseRewrites([], 'list'), new Map());
  for (const bad of [
    null,
    {},
    [null],
    [{ old: a, new: b }],
    [{ old: a, new: b, tree: c, also: a }],
    [{ old: a.slice(0, 7), new: b, tree: c }],
    [{ old: a, new: b.toUpperCase(), tree: c }],
    [{ old: a, new: b, tree: [c] }],
    [{ old: a, new: a, tree: c }],
    [
      { old: a, new: b, tree: c },
      { old: a, new: c, tree: c },
    ],
  ])
    assert.throws(
      () => parseRewrites(bad, 'list'),
      /no "rewrites" list|not a rewrite \{old, new, tree\} of full ids|is listed twice/,
      JSON.stringify(bad)
    );
});

test('readHistory() reads only a history input of exactly its form', t => {
  const base = temporary(t, 'goblin-history-input-');
  fs.mkdirSync(path.join(base, 'repository'));
  const file = path.join(base, 'history.json');
  const [a, b, c, d] = ['a', 'b', 'c', 'd'].map(x => x.repeat(40));
  const good = {
    $comment: 'synthetic',
    schema: historySchema,
    repository: 'repository',
    milestones: { '1.5.0-dev.0': a, '1.5.0-dev.1': b },
    fixtures: { '1.4.2': { tag: 'v1.4.2', commit: c } },
    rewrites: [{ old: c, new: d, tree: a }],
  };
  const read = content => {
    fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
    return readHistory(file);
  };
  const parsed = read(good);
  assert.equal(parsed.location, path.join(base, 'repository'));
  assert.deepEqual(parsed.milestones, good.milestones);
  assert.deepEqual(parsed.fixtures, good.fixtures);
  assert.deepEqual(parsed.rewrites, new Map([[c, { commit: d, tree: a }]]));
  const { $comment, ...plain } = good;
  assert.ok(read(plain));
  for (const [what, change, says] of [
    ['another schema', { schema: 'v0' }, /the schema is not/],
    ['an extra member', { extra: 1 }, /not a history input/],
    ['no rewrites member', { rewrites: undefined }, /not a history input/],
    ['a missing repository', { repository: 'absent' }, /does not exist/],
    ['an empty repository path', { repository: '' }, /is not a path/],
    ['one milestone', { milestones: { '1.5.0-dev.0': a } }, /must give exactly/],
    [
      'an extra milestone',
      { milestones: { ...good.milestones, '1.5.0-dev.2': a } },
      /must give exactly/,
    ],
    [
      'an abbreviated milestone',
      { milestones: { '1.5.0-dev.0': a.slice(0, 7), '1.5.0-dev.1': b } },
      /must give exactly/,
    ],
    [
      'a fixture of another tag',
      { fixtures: { '1.4.2': { tag: 'v1.4.3', commit: c } } },
      /is not \{tag/,
    ],
    [
      'a fixture with an abbreviated commit',
      { fixtures: { '1.4.2': { tag: 'v1.4.2', commit: 'c'.repeat(7) } } },
      /is not \{tag/,
    ],
    [
      'a rewrite of a commit no fixture records',
      { rewrites: [{ old: b, new: d, tree: a }] },
      /is in no fixture's provenance/,
    ],
  ]) {
    const value = { ...good, ...change };
    for (const key of Object.keys(change)) if (change[key] === undefined) delete value[key];
    assert.throws(() => read(value), says, what);
  }
  assert.throws(() => read('{'), SyntaxError);
  assert.throws(() => read('[]'), /not a history input/);
});
