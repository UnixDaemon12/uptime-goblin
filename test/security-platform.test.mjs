// The gate's side of the platform coverage contract (scripts/security-platform.mjs and its use
// in scripts/security-finalization.mjs): the environment of a test stage, the sealed records of a
// test stage, the history a candidate's manifest is judged against, the runtime identity, image
// authenticity and network records, and the finalization of a gate run with its companion runs.
// Every run here is synthetic (test/helpers/platform-run.mjs): test evidence for the checks, never
// a test result. No Docker, browser or network is used. Each test loads the modules itself, so a
// tree without them fails each test by name.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { declareGit } from './helpers/git.mjs';

// The history tests make throwaway Git repositories (with commits) in the temporary folder.
const gitSkip = declareGit();

const load = async () => ({
  platform: await import('../scripts/security-platform.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  coverage: await import('../scripts/check-platform-coverage.mjs'),
  evidence: await import('../scripts/security-evidence.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// ---------------------------------------------------------------------------------------------
// The environment of a test stage

test('the gate removes every inherited test input, in any letter case, and records only names', async () => {
  const { platform } = await load();
  const env = {
    PATH: '/usr/bin',
    ORBIT_SECURITY_NODE24: '/opt/node24/bin/node',
    TESTER: 'kept: not a TEST_ variable',
    MY_TEST_VALUE: 'kept',
    // Malicious: each would change what the test stages check or where they look.
    TEST_REQUIRE: '',
    TEST_T8_DIR: '/',
    TEST_T8_RUN: 'f'.repeat(64),
    TEST_TAG_TREES: '/tmp/forged-release-trees',
    TEST_PLATFORM_RECORDS: '/tmp/forged-records',
    TEST_PLATFORM_RUN: 'e'.repeat(64),
    UPDATE_GOLDEN: '1',
    NODE_TEST_CONTEXT: 'child-v8',
    // Accidental: other spellings and switches added later.
    test_require: 'browser',
    Update_Golden: '1',
    node_test_context: 'child',
    TEST_FUTURE_SWITCH: 'line one\nline two',
  };
  const removed = platform.removeTestInputs(env);
  assert.deepEqual(Object.keys(env).sort(), [
    'MY_TEST_VALUE',
    'ORBIT_SECURITY_NODE24',
    'PATH',
    'TESTER',
  ]);
  assert.equal(removed.count, 12);
  assert.deepEqual(removed.names, [
    'NODE_TEST_CONTEXT',
    'TEST_FUTURE_SWITCH',
    'TEST_PLATFORM_RECORDS',
    'TEST_PLATFORM_RUN',
    'TEST_REQUIRE',
    'TEST_T8_DIR',
    'TEST_T8_RUN',
    'TEST_TAG_TREES',
    'UPDATE_GOLDEN',
    'Update_Golden',
    'node_test_context',
    'test_require',
  ]);
  // Names only: no value reaches the record.
  assert.doesNotMatch(JSON.stringify(removed), /forged|child-v8|line one/);
});

test("a test stage's environment has the gate's three controls and refuses malformed ones", async t => {
  const { platform } = await load();
  const parent = temporary(t, 'orbit-stage-environment-');
  const controls = platform.testControls(parent, 'current-runtime');
  assert.match(controls.run, /^[0-9a-f]{64}$/);
  assert.equal(fs.statSync(controls.records).mode & 0o777, 0o700);
  const inherited = {
    PATH: '/usr/bin',
    TEST_REQUIRE: 'fixtures',
    test_t8_dir: '/',
    TEST_PLATFORM_RECORDS: '/tmp/forged',
    UPDATE_GOLDEN: '1',
    NODE_TEST_CONTEXT: 'child',
  };
  const env = platform.testEnvironment(inherited, controls);
  assert.deepEqual(env, {
    PATH: '/usr/bin',
    TEST_REQUIRE: 'browser,fixtures,systemd,docker,capacity,git',
    TEST_PLATFORM_RECORDS: controls.records,
    TEST_PLATFORM_RUN: controls.run,
  });
  const refused = (label, records, run = controls.run) =>
    assert.throws(() => platform.testEnvironment({}, { records, run }), Error, label);
  refused('a relative folder', 'records');
  refused('a control character', `${controls.records}\n`);
  refused('a missing folder', path.join(parent, 'missing'));
  assert.throws(() => platform.testEnvironment({}, { records: controls.records }), /run code/);
  const link = path.join(parent, 'link');
  fs.symlinkSync(controls.records, link);
  refused('a link', link);
  const open = fs.mkdtempSync(path.join(parent, 'open-'));
  fs.chmodSync(open, 0o755);
  refused('a folder others may read', open);
  const used = platform.testControls(parent, 'used');
  fs.writeFileSync(path.join(used.records, 'forged.jsonl'), '{}\n');
  refused('a folder that is not empty', used.records);
  for (const run of ['', 'E'.repeat(64), 'e'.repeat(63), `${'e'.repeat(64)}\n`, null])
    refused(`the run code ${JSON.stringify(run)}`, controls.records, run);
});

test('what every stage inherits is recorded: every name, and the values of the variables that choose a tool', async () => {
  const { platform } = await load();
  const env = {
    PATH: '/usr/bin',
    CHROME_PATH: '/elsewhere/fake-chrome',
    DOCKER_HOST: 'unix:///elsewhere/docker.sock',
    HOME: '/Users/synthetic',
    SECRET_TOKEN: 'never recorded',
  };
  const recorded = platform.inheritedEnvironment(env);
  assert.deepEqual(recorded, {
    count: 5,
    names: ['CHROME_PATH', 'DOCKER_HOST', 'HOME', 'PATH', 'SECRET_TOKEN'],
    values: {
      PATH: '/usr/bin',
      CHROME_PATH: '/elsewhere/fake-chrome',
      DOCKER_HOST: 'unix:///elsewhere/docker.sock',
      DOCKER_CONTEXT: null,
      DOCKER_CONFIG: null,
      HOME: '/Users/synthetic',
      TMPDIR: null,
    },
  });
  // Only the variables that choose a tool have their values recorded.
  assert.doesNotMatch(JSON.stringify(recorded), /never recorded/);
  // A test stage gets exactly that environment, plus the gate's three controls: these are not
  // removed, so the review sees them in the record instead.
  const many = Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`V${i}`, 'x']));
  assert.equal(platform.inheritedEnvironment(many).names.length, 500);
  assert.equal(platform.inheritedEnvironment(many).count, 600);
});

// ---------------------------------------------------------------------------------------------
// The sealed records of a test stage

test("a stage's records are sealed as one file and come back byte for byte", async t => {
  const { platform, coverage } = await load();
  const folder = temporary(t, 'orbit-pack-');
  const file = '1234-0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d.jsonl';
  fs.writeFileSync(path.join(folder, file), '{"kind":"result"}\n');
  fs.mkdirSync(path.join(folder, 't8-container-24-AbC123', 'records'), { recursive: true });
  fs.writeFileSync(path.join(folder, 't8-container-24-AbC123', 'inner.tap'), 'TAP version 13\n');
  fs.writeFileSync(path.join(folder, 't8-container-24-AbC123', 'records', file), '{"a":1}\n');
  const pack = platform.packRecords(folder);
  const before = coverage.readRecords(path.join(folder, 't8-container-24-AbC123', 'records'), {
    containers: false,
  });
  platform.withUnpackedRecords(pack, into => {
    assert.equal(fs.readFileSync(path.join(into, file), 'utf8'), '{"kind":"result"}\n');
    assert.equal(
      fs.readFileSync(path.join(into, 't8-container-24-AbC123', 'inner.tap'), 'utf8'),
      'TAP version 13\n'
    );
    // The digest a container record binds is the same after unpacking.
    const after = coverage.readRecords(path.join(into, 't8-container-24-AbC123', 'records'), {
      containers: false,
    });
    assert.equal(after.digest, before.digest);
  });
});

test('packing refuses what the harness does not write, and unpacking refuses tampering', async t => {
  const { platform } = await load();
  const folder = temporary(t, 'orbit-pack-refuse-');
  const record = '1234-0a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d.jsonl';
  for (const [label, plant] of [
    ['another file', dir => fs.writeFileSync(path.join(dir, 'notes.txt'), 'x')],
    ['a link', dir => fs.symlinkSync('/etc/hosts', path.join(dir, record))],
    ['a folder of another name', dir => fs.mkdirSync(path.join(dir, 'records'))],
    [
      'another file in a container folder',
      dir => {
        fs.mkdirSync(path.join(dir, 't8-container-26-ZzZ999'));
        fs.writeFileSync(path.join(dir, 't8-container-26-ZzZ999', 'extra.tap'), 'x');
      },
    ],
  ]) {
    const dir = fs.mkdtempSync(path.join(folder, 'case-'));
    plant(dir);
    assert.throws(
      () => platform.packRecords(dir),
      /not a file or folder the harness writes/,
      label
    );
  }
  const good = fs.mkdtempSync(path.join(folder, 'good-'));
  fs.writeFileSync(path.join(good, record), '{}\n');
  const pack = JSON.parse(platform.packRecords(good));
  const tampered = change => {
    const copy = structuredClone(pack);
    change(copy);
    return Buffer.from(`${JSON.stringify(copy)}\n`);
  };
  for (const [label, bytes] of [
    ['not canonical', Buffer.from(`${JSON.stringify(pack, null, 2)}\n`)],
    ['a changed byte', tampered(p => (p.files[0].base64 = Buffer.from('{}\r').toString('base64')))],
    ['a path out of the folder', tampered(p => (p.files[0].path = `../${record}`))],
    [
      'a file in an unlisted folder',
      tampered(p => (p.files[0].path = `t8-container-24-AbC123/inner.tap`)),
    ],
    ['a file twice', tampered(p => p.files.push(p.files[0]))],
    ['an unknown field', tampered(p => (p.extra = true))],
  ])
    assert.throws(() => platform.withUnpackedRecords(bytes, () => {}), Error, label);
});

test("a run of every file is checked against the candidate's tracked test files, not a folder's", async t => {
  const { coverage, fixture, evidence } = await load();
  const root = temporary(t, 'orbit-all-files-');
  fs.mkdirSync(path.join(root, 'test'));
  for (const file of [...fixture.testFiles, 'test/stray.test.mjs'])
    fs.writeFileSync(path.join(root, file), '// synthetic\n');
  const manifest = fixture.syntheticManifest();
  const manifestSha256 = evidence.sha256(fixture.manifestText(manifest));
  const nonce = 'a'.repeat(64);
  const { tap, containers } = fixture.stageEvidence({
    manifest,
    manifestSha256,
    runId: 'linux-full',
    runtime: '26',
    nonce,
  });
  const check = allFiles =>
    coverage
      .checkCoverage({
        manifest,
        manifestSha256,
        runId: 'linux-full',
        runtime: '26',
        tap,
        records: [],
        nonce,
        files: fixture.testFiles,
        root,
        allFiles,
      })
      .problems.filter(problem => /the run's files/.test(problem));
  assert.equal(containers.length, 2);
  // An untracked file in the folder (here test/stray.test.mjs) is not one the run had to run.
  assert.deepEqual(check(fixture.testFiles), []);
  assert.deepEqual(check(undefined), [
    "the run's files are not run linux-full's: missing test/stray.test.mjs",
  ]);
});

// ---------------------------------------------------------------------------------------------
// The history and the judgment of the manifest

function repository(t) {
  const root = temporary(t, 'orbit-platform-history-');
  const git = (...args) =>
    execFileSync('git', ['-C', root, ...args], {
      encoding: 'utf8',
      stdio: 'pipe',
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_AUTHOR_NAME: 'Orbit Fixture',
        GIT_AUTHOR_EMAIL: 'fixture@example.com',
        GIT_COMMITTER_NAME: 'Orbit Fixture',
        GIT_COMMITTER_EMAIL: 'fixture@example.com',
      },
    }).trimEnd();
  git('init', '--quiet');
  const commit = message => {
    git('add', '-A');
    git(
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '--allow-empty',
      '-m',
      message
    );
    return git('rev-parse', 'HEAD');
  };
  const runGit = (args, input) =>
    execFileSync('git', ['-C', root, ...args], { input, maxBuffer: 64 * 1024 ** 2 });
  return { root, git, commit, runGit };
}

test('the history gives each commit the bytes at the manifest path, and only regular files count', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { platform, fixture } = await load();
  const r = repository(t);
  const manifest = fixture.manifestText(fixture.syntheticManifest());
  fs.writeFileSync(path.join(r.root, 'README.md'), 'synthetic\n');
  const none = r.commit('no manifest');
  fs.mkdirSync(path.join(r.root, 'test'));
  fs.writeFileSync(path.join(r.root, 'test/platform-manifest.json'), manifest);
  const held = r.commit('the manifest');
  fs.rmSync(path.join(r.root, 'test/platform-manifest.json'));
  fs.symlinkSync('../README.md', path.join(r.root, 'test/platform-manifest.json'));
  const linked = r.commit('a link at the manifest path');
  fs.rmSync(path.join(r.root, 'test/platform-manifest.json'));
  fs.mkdirSync(path.join(r.root, 'test/platform-manifest.json'));
  fs.writeFileSync(path.join(r.root, 'test/platform-manifest.json/x'), 'x');
  const folder = r.commit('a folder at the manifest path');
  // A submodule there (a gitlink): one whose commit this repository lacks, and one whose commit
  // it has. Git prints "<id> submodule" for the first, whatever the format asks (verifier, round
  // 1: that line made the reader throw, and the guard refuse every commit).
  const gitlink = (id, message) => {
    r.git('rm', '-r', '--cached', '--quiet', 'test/platform-manifest.json');
    fs.rmSync(path.join(r.root, 'test/platform-manifest.json'), { recursive: true, force: true });
    r.git('update-index', '--add', '--cacheinfo', `160000,${id},test/platform-manifest.json`);
    r.git(
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      message
    );
    return r.git('rev-parse', 'HEAD');
  };
  const absentModule = gitlink('1'.repeat(40), 'a submodule whose commit is elsewhere');
  const presentModule = gitlink(held, 'a submodule whose commit is here');
  for (const commit of [absentModule, presentModule]) {
    const treeOf = r.git('rev-parse', `${commit}^{tree}`);
    assert.equal(platform.manifestsAt(r.runGit, [treeOf]).get(treeOf).length, 0, commit);
  }
  const tree = r.git('rev-parse', `${held}^{tree}`);
  const history = platform.readHistory(
    r.runGit,
    [presentModule],
    new Map([[`${tree} ${none}`, 'f'.repeat(64)]])
  );
  const at = commit => history.find(node => node.commit === commit);
  assert.deepEqual(
    history.map(node => node.commit),
    [presentModule, absentModule, folder, linked, held, none]
  );
  assert.equal(at(absentModule).manifest.length, 0);
  assert.equal(at(presentModule).manifest.length, 0);
  assert.equal(at(none).manifest, null);
  assert.deepEqual(at(none).parents, []);
  assert.equal(at(held).manifest.toString(), manifest);
  assert.deepEqual(at(held).reviewed, { manifestSha256: 'f'.repeat(64) });
  assert.equal(at(linked).reviewed, null);
  // A link or a folder is something that cannot validate, never "no manifest".
  assert.equal(at(linked).manifest.length, 0);
  assert.equal(at(folder).manifest.length, 0);
  assert.throws(() => platform.readHistory(r.runGit, ['not-a-commit']), /not commit ids/);
});

/** Runs `use()` with `values` set in process.env, then puts process.env back. */
function withEnvironment(values, use) {
  const saved = Object.fromEntries(Object.keys(values).map(name => [name, process.env[name]]));
  Object.assign(process.env, values);
  try {
    return use();
  } finally {
    for (const [name, value] of Object.entries(saved))
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  }
}

// Git's own settings for reading another history, as a gate stage may already have set them.
const historySettings = [
  'GIT_GRAFT_FILE',
  'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE',
  'GIT_NO_REPLACE_OBJECTS',
  'GIT_CONFIG_PARAMETERS',
];
/** `env` (default process.env) without them, plus `extra`: what plain Git would see. */
function unhardened(extra = {}, env = process.env) {
  const copy = { ...env };
  for (const name of historySettings) delete copy[name];
  return { ...copy, ...extra };
}
/** Plain Git in `root`, with `extra` in its environment. */
const plainGit = (root, args, extra = {}) =>
  execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    stdio: 'pipe',
    env: unhardened({ GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', ...extra }),
  }).trim();

/**
 * Writes a commit-graph file into the repository at `root` that claims `commit` (with its real
 * tree and commit time) has no parents. Git uses a commit-graph's parents and trees without
 * checking them against the commits; the file has the format's three required chunks and its
 * checksum.
 */
function forgeCommitGraph(root, commit) {
  const git = (...args) => plainGit(root, args);
  const tree = git('rev-parse', `${commit}^{tree}`);
  const time = Number(git('log', '-1', '--format=%ct', commit));
  const id = Buffer.from(commit, 'hex');
  const fanout = Buffer.alloc(256 * 4);
  for (let byte = 0; byte < 256; byte++) fanout.writeUInt32BE(byte >= id[0] ? 1 : 0, byte * 4);
  const data = Buffer.alloc(36);
  Buffer.from(tree, 'hex').copy(data, 0);
  data.writeUInt32BE(0x70000000, 20); // no first parent
  data.writeUInt32BE(0x70000000, 24); // no second parent
  data.writeUInt32BE(((1 << 2) | Math.floor(time / 2 ** 32)) >>> 0, 28); // generation 1
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
  const graph = path.join(root, '.git/objects/info/commit-graph');
  fs.mkdirSync(path.dirname(graph), { recursive: true });
  fs.writeFileSync(graph, Buffer.concat([body, createHash('sha1').update(body).digest()]));
  return graph;
}

/**
 * The ways Git can show another history, each hiding commit `hidden` of the repository `r`
 * (making it a root commit): returns the environment it needs, and an undo.
 */
function historyAttacks(t, r, hidden) {
  const listing = path.join(path.dirname(r.root), `${path.basename(r.root)}-${Math.random()}.list`);
  fs.writeFileSync(listing, `${hidden}\n`);
  t.after(() => fs.rmSync(listing, { force: true }));
  const gitDirectory = path.join(r.root, '.git');
  return [
    ['an exported GIT_GRAFT_FILE', () => ({ env: { GIT_GRAFT_FILE: listing }, undo() {} })],
    ['an exported GIT_SHALLOW_FILE', () => ({ env: { GIT_SHALLOW_FILE: listing }, undo() {} })],
    [
      'a replace ref (git replace --graft)',
      () => {
        plainGit(r.root, ['replace', '--graft', hidden]);
        return { env: {}, undo: () => plainGit(r.root, ['replace', '-d', hidden]) };
      },
    ],
    [
      'GIT_REPLACE_REF_BASE and a ref of its own',
      () => {
        const orphan = plainGit(r.root, ['commit-tree', `${hidden}^{tree}`, '-m', 'orphan'], {
          GIT_AUTHOR_NAME: 'Orbit Fixture',
          GIT_AUTHOR_EMAIL: 'fixture@example.com',
          GIT_COMMITTER_NAME: 'Orbit Fixture',
          GIT_COMMITTER_EMAIL: 'fixture@example.com',
        });
        plainGit(r.root, ['update-ref', `refs/elsewhere/${hidden}`, orphan]);
        return {
          env: { GIT_REPLACE_REF_BASE: 'refs/elsewhere/' },
          undo: () => plainGit(r.root, ['update-ref', '-d', `refs/elsewhere/${hidden}`]),
        };
      },
    ],
    [
      'a forged commit-graph',
      () => {
        const graph = forgeCommitGraph(r.root, hidden);
        return { env: {}, undo: () => fs.rmSync(graph) };
      },
    ],
    [
      'a forged commit-graph with core.commitGraph=true exported',
      () => {
        const graph = forgeCommitGraph(r.root, hidden);
        return {
          env: { GIT_CONFIG_PARAMETERS: "'core.commitgraph=true'" },
          undo: () => fs.rmSync(graph),
        };
      },
    ],
    [
      'an info/grafts file',
      () => {
        const file = path.join(gitDirectory, 'info/grafts');
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, `${hidden}\n`);
        return { env: {}, refused: /info\/grafts exists/, undo: () => fs.rmSync(file) };
      },
    ],
    [
      'a shallow file',
      () => {
        const file = path.join(gitDirectory, 'shallow');
        fs.writeFileSync(file, `${hidden}\n`);
        return { env: {}, refused: /repository is shallow/, undo: () => fs.rmSync(file) };
      },
    ],
  ];
}

test('grafts, replace refs, a shallow boundary or the commit-graph cannot hide a commit that deleted the manifest', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { platform, finalization, fixture } = await load();
  const r = repository(t);
  fs.writeFileSync(path.join(r.root, 'README.md'), 'synthetic\n');
  r.commit('root');
  fs.mkdirSync(path.join(r.root, 'test'));
  fs.writeFileSync(
    path.join(r.root, 'test/platform-manifest.json'),
    fixture.manifestText(fixture.syntheticManifest())
  );
  r.commit('adds the manifest');
  fs.rmSync(path.join(r.root, 'test/platform-manifest.json'));
  const deleted = r.commit('deletes the manifest without the guard');
  fs.writeFileSync(path.join(r.root, 'README.md'), 'synthetic, changed\n');
  r.git('add', '-A');
  const judged = (env = {}) =>
    withEnvironment(env, () => {
      const tree = r.git('write-tree');
      const parent = r.git('rev-parse', 'HEAD');
      const inputs = finalization.platformInputs(
        r.root,
        tree,
        finalization.candidateParents(r.root)
      );
      return {
        history: inputs.history.length,
        ...platform.judgePlatformManifest({ ...inputs, binding: { tree, parent } }),
      };
    });
  const deletion = /has no test\/platform-manifest\.json, which a commit behind it holds/;
  // Without any of them, the deletion is found.
  assert.equal(plainGit(r.root, ['rev-list', '--count', 'HEAD']), '3');
  const control = judged();
  assert.equal(control.kind, 'manifest');
  assert.equal(control.history, 3);
  assert.match(control.problems.join('\n'), deletion);
  for (const [label, attack] of historyAttacks(t, r, deleted)) {
    const { env, refused, undo } = attack();
    try {
      // Each hides the commits behind the deletion from plain Git...
      assert.equal(plainGit(r.root, ['rev-list', '--count', 'HEAD'], env), '1', label);
      // ...and not from the judgment, or the repository is refused outright.
      if (refused) assert.throws(() => judged(env), refused, label);
      else {
        const result = judged(env);
        assert.equal(result.kind, 'manifest', label);
        assert.equal(result.history, 3, label);
        assert.match(result.problems.join('\n'), deletion, label);
      }
    } finally {
      undo();
    }
  }
  // What the gate, the finalizer and the guard set: the names replaced, never their values.
  const env = {
    PATH: '/usr/bin',
    GIT_GRAFT_FILE: '/elsewhere/grafts',
    GIT_REPLACE_REF_BASE: 'refs/elsewhere/',
    GIT_SHALLOW_FILE: '/elsewhere/shallow',
    GIT_NO_REPLACE_OBJECTS: '0',
    GIT_CONFIG_PARAMETERS: "'core.commitgraph=true'",
  };
  assert.deepEqual(platform.hardenGitHistory(env), [
    'GIT_GRAFT_FILE',
    'GIT_NO_REPLACE_OBJECTS',
    'GIT_REPLACE_REF_BASE',
    'GIT_SHALLOW_FILE',
  ]);
  const hardened = {
    PATH: '/usr/bin',
    GIT_GRAFT_FILE: '/dev/null/orbit-no-grafts',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_CONFIG_PARAMETERS:
      "'core.commitgraph=true' 'core.commitgraph=false' 'core.usereplacerefs=false'",
  };
  assert.deepEqual(env, hardened);
  // Again: nothing more to replace, and nothing added twice.
  assert.deepEqual(platform.hardenGitHistory(env), []);
  assert.deepEqual(env, hardened);
});

test('a submodule at the manifest path counts as a manifest that cannot validate, in the candidate and in its history', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { platform, finalization } = await load();
  const r = repository(t);
  fs.writeFileSync(path.join(r.root, 'README.md'), 'synthetic\n');
  r.commit('root, with no manifest');
  r.git(
    'update-index',
    '--add',
    '--cacheinfo',
    `160000,${'1'.repeat(40)},test/platform-manifest.json`
  );
  const judged = () => {
    const tree = r.git('write-tree');
    const parent = r.git('rev-parse', 'HEAD');
    const inputs = finalization.platformInputs(r.root, tree, finalization.candidateParents(r.root));
    return platform.judgePlatformManifest({ ...inputs, binding: { tree, parent } });
  };
  // The candidate: a manifest that cannot validate (introduced, and refused).
  const candidate = judged();
  assert.equal(candidate.kind, 'introduction');
  assert.match(candidate.problems.join('\n'), /not JSON|not usable|schemaVersion/);
  r.git(
    '-c',
    'commit.gpgsign=false',
    '-c',
    'core.hooksPath=/dev/null',
    'commit',
    '--quiet',
    '-m',
    'a submodule there, without the guard'
  );
  // In the history: the branch has a platform contract from then on, and a candidate without a
  // valid manifest and a reviewed baseline is refused, by name rather than by a parse error.
  r.git('rm', '--cached', '--quiet', 'test/platform-manifest.json');
  const history = judged();
  assert.equal(history.kind, 'manifest');
  assert.match(
    history.problems.join('\n'),
    /has no test\/platform-manifest\.json, which a commit behind it holds/
  );
  assert.match(history.problems.join('\n'), /no reviewed manifest can be established/);
});

test('a deleted or weakened committed manifest is refused unless an exact disposition bound to the candidate excuses the loss', async () => {
  const { platform, fixture, evidence } = await load();
  const base = fixture.syntheticManifest();
  const baseBytes = Buffer.from(fixture.manifestText(base));
  const approved = 'a'.repeat(40);
  const binding = { tree: 'c'.repeat(40), parents: [approved] };
  const history = [
    {
      commit: approved,
      parents: [],
      manifest: baseBytes,
      reviewed: { manifestSha256: evidence.sha256(baseBytes) },
    },
  ];
  const judge = (candidate, dispositions = [], extra = {}) =>
    platform.judgePlatformManifest({
      candidate,
      heads: [approved],
      history,
      dispositions,
      binding,
      ...extra,
    });
  assert.deepEqual(judge(baseBytes).problems, []);
  assert.equal(judge(baseBytes).kind, 'manifest');
  // Deleted, emptied or broken: refused, and no disposition excuses it.
  for (const candidate of [
    null,
    Buffer.alloc(0),
    Buffer.from('{"schemaVersion":1,"runs":{},"entries":[]}\n'),
  ])
    assert.match(judge(candidate).problems.join('\n'), /test\/platform-manifest\.json/);
  // Weakened: the Linux entry no longer required of linux-full.
  const weak = structuredClone(base);
  weak.entries.find(entry => entry.id === 'linux.acl').evidence = [];
  weak.runs['linux-full'].requiredFor = ['release'];
  const weakBytes = Buffer.from(fixture.manifestText(weak));
  assert.ok(judge(weakBytes).problems.length >= 1);
  assert.match(judge(weakBytes).problems.join('\n'), /no reviewed disposition excuses/);
  // Removing the Linux entry and adding a replacement: the new test excuses nothing...
  const replaced = structuredClone(base);
  const old = replaced.entries.find(entry => entry.id === 'linux.acl');
  replaced.entries = replaced.entries.filter(entry => entry !== old);
  replaced.entries.push({ ...old, id: 'linux.acl-v2', name: ['the Linux access list, again'] });
  const replacedBytes = Buffer.from(fixture.manifestText(replaced));
  assert.match(judge(replacedBytes).problems.join('\n'), /entry linux\.acl was removed/);
  // ...an exact old-to-new disposition bound to this candidate does...
  const disposition = {
    loss: 'entry:linux.acl',
    old,
    replacement: 'linux.acl-v2',
    reason: 'synthetic: renamed',
    reviewer: 'Synthetic reviewer',
    reference: 'synthetic review',
    ...binding,
  };
  assert.deepEqual(judge(replacedBytes, [disposition]).problems, []);
  // ...but not one bound to another tree or parent vector, one naming another old entry, or two.
  assert.match(
    judge(replacedBytes, [{ ...disposition, tree: 'b'.repeat(40) }]).problems.join('\n'),
    /not bound/
  );
  assert.match(
    judge(replacedBytes, [{ ...disposition, parents: ['b'.repeat(40)] }]).problems.join('\n'),
    /not bound/
  );
  assert.match(
    judge(replacedBytes, [{ ...disposition, parents: [approved, 'b'.repeat(40)] }]).problems.join(
      '\n'
    ),
    /not bound/
  );
  assert.match(
    judge(replacedBytes, [
      { ...disposition, old: { ...old, file: 'test/other.test.mjs' } },
    ]).problems.join('\n'),
    /not the baseline's/
  );
  assert.match(
    judge(replacedBytes, [disposition, disposition]).problems.join('\n'),
    /already has a disposition/
  );
  // Parents that are not all known (an automatic merge): refused while a manifest is involved...
  assert.match(
    judge(baseBytes, [], { complete: false, reason: 'synthetic' }).problems.join('\n'),
    /not all known \(synthetic\): merge with --no-commit/
  );
  // ...and, since v3 C18 and Daybreak GD-R1, also when neither the candidate nor its known
  // history has one: an incomplete parent vector approves nothing, for any candidate.
  const maintenance = platform.judgePlatformManifest({
    candidate: null,
    heads: [approved],
    history: [{ commit: approved, parents: [], manifest: null, reviewed: null }],
    binding,
    complete: false,
    reason: 'synthetic',
  });
  assert.equal(maintenance.kind, 'maintenance');
  assert.match(maintenance.problems.join('\n'), /not all known \(synthetic\)/);
  // What makes the parents Git shows ambiguous (a replace ref, a commit-graph) refuses too.
  assert.match(
    judge(baseBytes, [], { refused: ['synthetic ambiguity'] }).problems.join('\n'),
    /synthetic ambiguity/
  );
});

test('the dispositions file is strict and bound to the candidate', async () => {
  const { platform } = await load();
  const binding = { tree: 'c'.repeat(40), parents: ['d'.repeat(40), 'e'.repeat(40)] };
  const file = value => Buffer.from(JSON.stringify(value));
  const good = { schemaVersion: 2, ...binding, dispositions: [] };
  assert.deepEqual(platform.parseCoverageDispositions(file(good), binding), []);
  for (const [label, bytes, pattern] of [
    ['another tree', file({ ...good, tree: 'b'.repeat(40) }), /not bound/],
    ['another parent', file({ ...good, parents: ['d'.repeat(40), 'b'.repeat(40)] }), /not bound/],
    [
      'reordered parents',
      file({ ...good, parents: ['e'.repeat(40), 'd'.repeat(40)] }),
      /not bound/,
    ],
    ['a missing parent', file({ ...good, parents: ['d'.repeat(40)] }), /not bound/],
    [
      'version 1, bound to a single parent',
      file({ schemaVersion: 1, tree: binding.tree, parent: 'd'.repeat(40), dispositions: [] }),
      /version 1, bound to a single parent, which gives no authority/,
    ],
    ['an unknown field', file({ ...good, blanket: true }), /unknown field "blanket"/],
    [
      'a member twice',
      Buffer.from(
        `{"schemaVersion":2,"tree":"${binding.tree}","tree":"${binding.tree}","parents":${JSON.stringify(binding.parents)},"dispositions":[]}`
      ),
      /twice/,
    ],
    ['too many', file({ ...good, dispositions: Array(501).fill({}) }), /at most 500/],
    ['another schema', file({ ...good, schemaVersion: 3 }), /schema version/],
    ['not UTF-8', Buffer.from([0xff, 0xfe]), /UTF-8/],
  ])
    assert.throws(() => platform.parseCoverageDispositions(bytes, binding), pattern, label);
});

// ---------------------------------------------------------------------------------------------
// Runtime identity, image authenticity and the network record

test('a runtime counts only with an identity record bound to its binary sha256', async () => {
  const { platform, fixture } = await load();
  const now = Date.now();
  const observed = (os, runtime) => ({
    sha256: fixture.binaryOf(os, runtime),
    version: fixture.versionOf[runtime],
    platform: os,
    arch: 'arm64',
  });
  const keys = platform.parseReleaseKeys(Buffer.from(JSON.stringify(fixture.releaseKeys(now))));
  // A verified Node release (Linux), signed by a reviewed release key, and a reviewed Homebrew
  // build (macOS) both pass.
  for (const os of ['linux', 'darwin'])
    assert.deepEqual(
      platform.runtimeIdentityProblems(
        fixture.runtimeRecord(os, '26', now),
        observed(os, '26'),
        keys
      ),
      []
    );
  const problem = (os, change, pattern, reviewedKeys = keys) => {
    const record = fixture.runtimeRecord(os, '24', now);
    change(record);
    assert.match(
      platform.runtimeIdentityProblems(record, observed(os, '24'), reviewedKeys).join('\n'),
      pattern
    );
  };
  problem('linux', r => (r.binarySha256 = '0'.repeat(64)), /is for the binary/);
  problem('linux', r => (r.version = 'v24.20.0'), /is for Node "v24\.20\.0"/);
  problem('linux', r => (r.arch = 'x64'), /not linux\/arm64/);
  problem(
    'linux',
    r => (r.release.outcome = 'unavailable'),
    /signed SHASUMS check is unavailable, not verified/
  );
  problem('linux', r => (r.release.outcome = 'invalid'), /is invalid, not verified/);
  problem('linux', r => (r.release.signer = 'self-chosen'), /not a key fingerprint/);
  problem('linux', r => (r.distribution = 'somewhere'), /distribution "somewhere" is unknown/);
  // The record's other fields are bound to the binary too (verifier, round 1): the archive of
  // another version, platform or architecture, a signer that is not a reviewed release key, or
  // another keyring, is refused...
  for (const archive of [
    'node-v24.0.0-linux-arm64.tar.xz',
    'node-v24.21.0-win-x64.tar.gz',
    'node-v24.21.0-linux-x64.tar.xz',
    'node-v24.21.0-darwin-arm64.tar.gz',
    'node-v24.21.0-linux-arm64.zip',
  ])
    problem(
      'linux',
      r => (r.release.archive = archive),
      /is not the Node v24\.21\.0 release archive for linux\/arm64/
    );
  problem(
    'linux',
    r => (r.release.signer = '0'.repeat(40)),
    /signer 0{40} is not one of the reviewed Node release keys/
  );
  problem(
    'linux',
    r => (r.release.keyringSha256 = '0'.repeat(64)),
    /keyringSha256 is not the keyring of the reviewed Node release keys/
  );
  // ...and without a reviewed list of release keys, no signer counts.
  problem('linux', () => {}, /no reviewed list of Node release keys/, null);
  for (const [label, change] of [
    ['no fingerprint', k => (k.fingerprints = [])],
    ['a lower-case fingerprint', k => (k.fingerprints = ['c'.repeat(40)])],
    ['a fingerprint twice', k => (k.fingerprints = ['B'.repeat(40), 'B'.repeat(40)])],
    ['no reviewer', k => (k.reviewer = '')],
    ['an unknown field', k => (k.trustAll = true)],
  ]) {
    const value = fixture.releaseKeys(now);
    change(value);
    assert.throws(
      () => platform.parseReleaseKeys(Buffer.from(JSON.stringify(value))),
      /reviewed Node release keys/,
      label
    );
  }
  // A Homebrew record of another formula or version is refused.
  problem(
    'darwin',
    r => (r.homebrew.formula = 'node@26'),
    /formula "node@26" is not node or node@24/
  );
  problem(
    'darwin',
    r => (r.homebrew.version = '24.0.0'),
    /version "24\.0\.0" is not the formula version of Node v24\.21\.0/
  );
  assert.deepEqual(
    platform.runtimeIdentityProblems(
      {
        ...fixture.runtimeRecord('darwin', '24', now),
        homebrew: { formula: 'node@24', version: '24.21.0_1', bottleSha256: null },
      },
      observed('darwin', '24')
    ),
    []
  );
  // A Homebrew build never claims an upstream signature, and needs its reviewed exception.
  problem(
    'darwin',
    r => (r.release = fixture.runtimeRecord('linux', '24', now).release),
    /has no release signature check/
  );
  problem('darwin', r => delete r.exception, /counts only through a reviewed exception/);
  problem('darwin', r => (r.exception.reviewer = ''), /reviewer is not a non-empty line/);
  problem('linux', r => (r.surplus = true), /unknown field "surplus"/);
});

test('T8 evidence counts only for an image whose authenticity record binds its digest and platform', async () => {
  const { platform, fixture } = await load();
  const now = Date.now();
  const image = fixture.imageOf[24];
  const used = { image, imageId: image.split('@')[1] };
  const [seen] = platform.parseImageInspection(JSON.stringify(fixture.inspection(image)), [image]);
  const check = (change = () => {}, usedNow = used, seenNow = seen) => {
    const record = fixture.imageRecord(image, now);
    change(record);
    return platform.imageAuthenticityProblems(record, usedNow, seenNow).join('\n');
  };
  assert.equal(check(), '');
  // The classic image store reports the config digest as the image ID: that is accepted too.
  const parts = fixture.imageParts('24');
  const config = parts.configDigest;
  assert.equal(check(undefined, { image, imageId: config }, { ...seen, id: config }), '');
  // The platform manifest and config digests are worked out from the bytes the record carries
  // (verifier, round 1: any digest there passed). Another platform's manifest, any other digest,
  // a config the manifest does not name, or bytes that do not hash to the digests are refused,
  // with either image store.
  for (const ids of [
    [used, seen],
    [
      { image, imageId: config },
      { ...seen, id: config },
    ],
  ]) {
    const refused = (change, pattern, label) => assert.match(check(change, ...ids), pattern, label);
    refused(
      r => (r.platformManifestDigest = parts.otherDigest),
      /platformManifestDigest is not the image manifest its index gives that platform/,
      "the amd64 manifest's digest"
    );
    refused(
      r => (r.platformManifestDigest = `sha256:${'8'.repeat(64)}`),
      /platformManifestDigest is not the image manifest its index gives that platform/,
      'any digest'
    );
    refused(
      r => {
        r.platformManifestDigest = parts.otherDigest;
        r.platformManifestBase64 = parts.other.toString('base64');
        r.configDigest = JSON.parse(parts.other).config.digest;
      },
      /platformManifestDigest is not the image manifest its index gives that platform/,
      "the amd64 manifest's bytes and config"
    );
    refused(
      r => (r.configDigest = `sha256:${'9'.repeat(64)}`),
      /configDigest is not the config its platform manifest names/,
      'another config digest'
    );
    refused(
      r => (r.platformManifestBase64 = parts.other.toString('base64')),
      /platform manifest it carries does not hash to platformManifestDigest/,
      'the bytes of another manifest'
    );
    refused(
      r => (r.indexBase64 = Buffer.from('{"schemaVersion":2,"manifests":[]}').toString('base64')),
      /index it carries does not hash to its index digest/,
      'the bytes of another index'
    );
    refused(r => delete r.indexBase64, /lacks indexBase64/, 'no index bytes');
    refused(
      r => (r.indexBase64 = 'not base64!'),
      /indexBase64 is not the base64 bytes/,
      'not base64'
    );
  }
  // An index whose entries for the platform are not exactly one, or not an image manifest.
  const forged = index => {
    const bytes = Buffer.from(JSON.stringify(index));
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    const forgedImage = `node:24-bookworm-slim@${digest}`;
    const record = fixture.imageRecord(image, now);
    Object.assign(record, {
      image: forgedImage,
      indexDigest: digest,
      indexBase64: bytes.toString('base64'),
    });
    return platform
      .imageAuthenticityProblems(
        record,
        { image: forgedImage, imageId: digest },
        { ...seen, image: forgedImage, id: digest, repoDigests: [`node@${digest}`] }
      )
      .join('\n');
  };
  const original = JSON.parse(parts.index);
  const arm = original.manifests[1];
  assert.equal(forged(original), '');
  assert.match(
    forged({ ...original, manifests: [...original.manifests, arm] }),
    /its index has 2 entries for .* not one/
  );
  assert.match(
    forged({ ...original, manifests: [original.manifests[0]] }),
    /its index has 0 entries for .* not one/
  );
  assert.match(
    forged({
      ...original,
      manifests: [{ ...arm, mediaType: 'application/vnd.oci.image.index.v1+json' }],
    }),
    /is not the image manifest its index gives that platform/
  );
  assert.match(
    forged({ ...original, mediaType: 'application/vnd.oci.image.manifest.v1+json' }),
    /the index it carries is not an OCI or Docker image index/
  );
  assert.match(
    check(r => (r.indexDigest = `sha256:${'0'.repeat(64)}`)),
    /binds the digest/
  );
  assert.match(
    check(r => (r.platform.architecture = 'amd64')),
    /not the platform Docker ran/
  );
  assert.match(
    check(r => (r.image = fixture.imageOf[26])),
    /is for another image/
  );
  assert.match(
    check(undefined, { image, imageId: `sha256:${'5'.repeat(64)}` }),
    /neither its index digest nor its config digest/
  );
  assert.match(
    check(undefined, used, { ...seen, id: `sha256:${'5'.repeat(64)}` }),
    /not the driver's/
  );
  assert.match(
    check(undefined, used, { ...seen, repoDigests: [] }),
    /does not list the pinned digest/
  );
  for (const outcome of ['absent', 'invalid', 'unavailable'])
    assert.match(
      check(r => (r.outcome = outcome)),
      new RegExp(`is ${outcome}, which blocks use`)
    );
  assert.match(
    check(r => {
      r.outcome = 'exception';
      delete r.verification;
      r.exception = {
        disposition: 'synthetic',
        reason: 'synthetic',
        reviewer: '',
        reference: 'x',
        reviewedAt: new Date(now).toISOString(),
        evidenceSha256: 'a'.repeat(64),
      };
    }),
    /reviewer is not a non-empty line/
  );
  assert.equal(
    check(r => {
      r.outcome = 'exception';
      delete r.verification;
      r.exception = {
        disposition: 'reviewed by Codex',
        reason: 'no publisher signature',
        reviewer: 'Codex',
        reference: 'synthetic',
        reviewedAt: new Date(now).toISOString(),
        evidenceSha256: 'a'.repeat(64),
      };
    }),
    ''
  );
  // Missing record: the gate cannot find one by the observed platform's name.
  assert.equal(
    platform.imageRecordName(image, seen.platform),
    `${parts.indexDigest.slice(7)}-linux-arm64-v8.json`
  );
  assert.throws(() => platform.parseImageInspection('', [image]), /described 0 images, not 1/);
  assert.throws(() => platform.parseImageInspection('{"Id":"x"}', [image]), /lacks an image id/);
});

test('the network record shows the reviewed policy, outside the guest, around each test stage', async () => {
  const { platform, fixture } = await load();
  const now = Date.now();
  const stage = {
    name: 'full-tests-current-runtime',
    started: new Date(now - 10000).toISOString(),
    finished: new Date(now - 5000).toISOString(),
  };
  const at = ms => new Date(now + ms).toISOString();
  const json = value => Buffer.from(JSON.stringify(value));
  const check = (change = {}) => {
    const before = fixture.networkState(at(-10500), change.before);
    const after = fixture.networkState(at(-4900), {
      counters: {
        'egress-drop': { packets: 9, bytes: 900 },
        'egress-allow': { packets: 0, bytes: 0 },
      },
      ...change.after,
    });
    const policy = { ...fixture.networkPolicy(now), ...change.policy };
    return platform
      .networkProblems({
        stage,
        before: { bytes: json(before), readAt: change.beforeReadAt ?? at(-10200) },
        after: { bytes: json(after), readAt: change.afterReadAt ?? at(-4800) },
        policy: json(policy),
      })
      .join('\n');
  };
  assert.equal(check(), '');
  assert.match(check({ after: { phase: 'prepare' } }), /after phase is prepare, not test/);
  assert.match(check({ before: { enforcement: 'in-guest' } }), /not outside-guest/);
  assert.match(check({ after: { policySha256: 'c'.repeat(64) } }), /policy changed during it/);
  assert.match(check({ after: { epoch: 'synthetic-epoch-2' } }), /counters were reset/);
  assert.match(
    check({
      after: {
        counters: {
          'egress-drop': { packets: 1, bytes: 9 },
          'egress-allow': { packets: 0, bytes: 0 },
        },
      },
    }),
    /counter egress-drop went down/
  );
  assert.match(
    check({ after: { counters: { 'egress-drop': { packets: 9, bytes: 900 } } } }),
    /counters before and after differ/
  );
  assert.match(
    check({ beforeReadAt: at(-9000) }),
    /before snapshot was not observed before the stage started/
  );
  assert.match(
    check({ after: { observedAt: at(-6000) } }),
    /after snapshot was not observed after the stage finished/
  );
  assert.match(
    check({ afterReadAt: at(-4950) }),
    /after snapshot was not observed after the stage finished/
  );
  assert.match(check({ policy: { sha256: 'c'.repeat(64) } }), /has no reviewed policy record/);
  assert.match(check({ policy: { reviewer: '' } }), /has no reviewed policy record/);
  assert.match(check({ before: { counters: {} } }), /no counters/);
});

test('a run needs a test stage on each runtime the manifest names for it', async () => {
  const { platform, fixture } = await load();
  const manifest = fixture.syntheticManifest();
  assert.deepEqual(platform.runtimeGaps(manifest, 'linux-full', ['v26.5.1', 'v24.21.0']), []);
  // A gate started on Node 24 runs one test stage: its run lacks Node 26.
  assert.deepEqual(platform.runtimeGaps(manifest, 'linux-full', ['v24.21.0']), ['26']);
  assert.deepEqual(platform.runtimeGaps(manifest, 'linux-full', ['v24.21.0', 'v24.0.0']), ['26']);
  assert.deepEqual(platform.runtimeGaps(manifest, 'linux-full', []), ['24', '26']);
  assert.deepEqual(platform.runtimeGaps(manifest, 'linux-full', ['not a version']), ['24', '26']);
});

// ---------------------------------------------------------------------------------------------
// Finalization of a gate run with its companion runs (synthetic sealed runs)

/**
 * A gate run on Linux and companion runs for one synthetic candidate in a new private
 * orbit-security folder. `main` and `companion` change them (see test/helpers/platform-run.mjs).
 */
async function scenario(t, { main = {}, companion = {}, companions, now = Date.now() } = {}) {
  const modules = await load();
  const { fixture } = modules;
  const security = temporary(t, 'orbit-platform-runs-');
  const candidate = fixture.platformCandidate(main.candidate);
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  fixture.writeMainRun(run, candidate, {
    platform: main.platform ?? 'linux',
    now,
    change: main.change,
  });
  const made = (companions ?? [{}]).map(options =>
    fixture.writeCompanion(security, candidate, {
      now,
      ...options,
      change: options.change ?? companion.change,
      runId: options.runId ?? companion.runId,
    })
  );
  const inspect = (extra = {}, at = now) =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions: made, ...extra }, at);
  return { ...modules, security, candidate, run, companions: made, inspect, now };
}
const blockers = inventory => inventory.blockers.join('\n');

test('a gate run and the companion runs its manifest needs finalize, with each run kept separate', async t => {
  const s = await scenario(t);
  const inventory = s.inspect();
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.eligible, true);
  // Nothing local is wrong, and the finalization would still be pending: the F obligations of
  // the catalog that only F on the Mac can establish (v3 C13, C14, C23), the T8 images' missing
  // activation records (IP-01) and the companion's trusted intervals (v3 C22).
  assert.equal(inventory.verdict, 'pending');
  const owned = Object.keys(s.finalization.fObligationsOwnedByF);
  assert.deepEqual(
    Object.entries(inventory.obligations)
      .filter(([, item]) => item.status === 'pending')
      .map(([id]) => id)
      .sort(),
    [...owned, 'companion-evidence', 'required-catalogs', 'review-approval'].sort()
  );
  assert.equal(inventory.obligations['candidate-identity'].status, 'pass');
  assert.match(inventory.pending.join('\n'), /t8-image-authenticity|no reviewed activation record/);
  const { platform } = inventory;
  assert.equal(platform.kind, 'introduction');
  assert.equal(platform.run, 'linux-full');
  assert.deepEqual(
    platform.stages.map(stage => [stage.name, stage.runtime]),
    [
      ['full-tests-current-runtime', 'v26.5.1'],
      ['full-tests-minimum-runtime', 'v24.21.0'],
    ]
  );
  assert.equal(platform.companions.length, 1);
  assert.equal(platform.companions[0].run, 'darwin-platform');
  assert.equal(platform.companions[0].host.platform, 'darwin');
  // Which runtime produced which T8 evidence: a Node 24 run inside a Node 26 stage covers 24 only.
  assert.deepEqual(
    platform.stages[0].containers.map(item => [item.runtime, item.node]),
    [
      ['24', 'v24.21.0'],
      ['26', 'v26.5.1'],
    ]
  );
  assert.deepEqual(
    platform.stages[0].coverage.map(item => [item.id, item.status]),
    [
      ['mac.acl', 'absent'],
      ['linux.acl', 'required'],
      ['t8.environment', 'absent'],
      ['t8.part-b', 'absent'],
      ['t8.driver.node24', 'required'],
      ['t8.driver.node26', 'required'],
    ]
  );
  // Totals stay each stage's own: the Linux run's 4 tests are not added to the macOS run's 1.
  assert.deepEqual(
    platform.stages.map(stage => stage.tests.tests),
    [4, 4]
  );
  assert.deepEqual(
    platform.companions[0].stages.map(stage => stage.tests.tests),
    [1, 1]
  );
  assert.equal(inventory.platformSha256, s.evidence.sha256(JSON.stringify(platform)));
  // The review binds the platform evidence: without platformSha256 it is refused.
  const review = (extra = {}) => {
    const { platform: summary, ...binding } = s.fixture.reviewBinding(inventory);
    const file = path.join(s.security, `review-${Math.random()}.json`);
    fs.writeFileSync(
      file,
      JSON.stringify({
        ...binding,
        reviewer: 'Independent synthetic reviewer',
        reference: 'Synthetic code review',
        reviewedAt: new Date(s.now).toISOString(),
        expiresAt: new Date(s.now + 3600000).toISOString(),
        unresolved: [],
        documents: {},
        dispositions: [],
        ...extra,
      }),
      { mode: 0o600 }
    );
    return file;
  };
  const current = { ...s.candidate.current, companions: s.companions };
  assert.throws(
    () => s.finalization.finalizeRun(s.run, review({ platformSha256: undefined }), current, s.now),
    /not bound to this exact platform evidence/
  );
  const approval = s.finalization.finalizeRun(s.run, review(), current, s.now);
  assert.deepEqual(approval.platform, platform);
  assert.equal(approval.platformSha256, inventory.platformSha256);
  // This draft's finalization is pending, never pass: the guard refuses it.
  assert.equal(approval.status, 'pending');
  assert.equal(approval.obligations['review-approval'], 'pass');
  assert.equal(approval.obligations['controller-completion'], 'pending');
  const guard = { ...s.candidate.current, companions: undefined };
  assert.throws(
    () => s.finalization.validateFinalization(s.run, guard, s.now),
    /Finalization is "pending", not pass/
  );
  // As F would write it (synthetic: no F exists), the guard's check: the companions are named by
  // the approval and checked again now.
  s.fixture.asIfFinalizedByF(s.run);
  assert.equal(s.finalization.validateFinalization(s.run, guard, s.now).status, 'pass');
  // A day later, the companion (and the run) is stale.
  assert.throws(() => s.finalization.validateFinalization(s.run, guard, s.now + 25 * 3600000));
  // A companion deleted after finalization no longer approves.
  fs.rmSync(s.companions[0], { recursive: true, force: true });
  assert.throws(() => s.finalization.validateFinalization(s.run, guard, s.now));
});

test('absence is never a pass: a missing, unneeded or repeated companion run is refused', async t => {
  const none = await scenario(t, { companions: [] });
  assert.match(
    blockers(none.inspect()),
    /No companion run covers darwin-platform for this candidate/
  );
  // A macOS full run also covers darwin-platform, by the manifest's rule; a second one covers nothing.
  const full = await scenario(t, { companions: [{ runId: 'darwin-full' }] });
  assert.deepEqual(full.inspect().blockers, []);
  const twice = await scenario(t, { companions: [{}, {}] });
  assert.match(blockers(twice.inspect()), /covers no run this candidate still needs/);
  const same = await scenario(t);
  assert.match(
    blockers(same.inspect({ companions: [same.companions[0], same.companions[0]] })),
    /given twice/
  );
  // A companion that is not a platform run (here the gate run itself) is refused.
  assert.match(
    blockers(same.inspect({ companions: [same.run] })),
    /Only sealed local runs \(orbit-gate-local-diagnostic-run version 1\) of mode platform/
  );
});

test('a companion of another tree, parent or file manifest is refused', async t => {
  for (const [label, change, pattern] of [
    ['tree', r => (r.tree = 'b'.repeat(40)), /another tree or complete ordered parent vector/],
    [
      'parent',
      r => (r.parents = ['b'.repeat(40)]),
      /another tree or complete ordered parent vector/,
    ],
    [
      'an additional parent',
      r => r.parents.push('b'.repeat(40)),
      /another tree or complete ordered parent vector/,
    ],
    ['identity', r => (r.candidateIdentitySha256 = 'b'.repeat(64)), /another candidate identity/],
    ['platform', r => (r.host.platform = 'linux'), /ran on "linux", not darwin/],
    ['root', r => (r.host.uid = 0), /ran as root/],
    [
      'tools',
      r => (r.tools = { ...r.tools, trivy: '0.0.1' }),
      /tool configuration is not the candidate's/,
    ],
    [
      'status',
      r => (r.status = 'blocked'),
      /not a companion run \(an orbit-gate-local-diagnostic-run record, version 1, of platform mode\)/,
    ],
    [
      'a stage',
      r => (r.stages.find(item => item.name === 'test-host').status = 'blocked'),
      /test-host did not pass/,
    ],
    [
      'a mandatory stage',
      r => (r.stages = r.stages.filter(item => item.name !== 'runtime-identity')),
      /runtime-identity is missing/,
    ],
  ]) {
    const s = await scenario(t, { companion: { change: { record: change } } });
    assert.match(blockers(s.inspect()), pattern, label);
  }
  // A companion run of the same tree id whose file manifest differs (another staged edit).
  const files = await scenario(t, {
    companion: {
      change: {
        record: (r, f) => {
          const list = JSON.parse(f['source-manifest.json']);
          list.find(item => item.file === 'example.mjs').sha256 = '0'.repeat(64);
          f['source-manifest.json'] = JSON.stringify(list);
        },
      },
    },
  });
  assert.match(blockers(files.inspect()), /its file manifest is not the candidate's/);
});

test('expired companion evidence is refused: started over 24 hours ago or finishing in the future', async t => {
  const old = await scenario(t, {
    companion: {
      change: {
        record: r => {
          r.started = new Date(Date.now() - 25 * 3600000).toISOString();
          for (const stage of r.stages)
            stage.started = new Date(Date.now() - 24.9 * 3600000).toISOString();
        },
      },
    },
  });
  assert.match(blockers(old.inspect()), /stale: it started more than 24 hours ago/);
  const future = await scenario(t, {
    companion: {
      change: { record: r => (r.finished = new Date(Date.now() + 3600000).toISOString()) },
    },
  });
  assert.match(blockers(future.inspect()), /finishes later than now/);
});

test('late or changed logs are refused: a changed sealed file, a file added after sealing, a stage outside its run', async t => {
  const changed = await scenario(t);
  fs.appendFileSync(
    path.join(changed.companions[0], 'platform-tests-current-runtime.log'),
    'ok 99 - late\n'
  );
  assert.match(blockers(changed.inspect()), /Run evidence changed/);
  const added = await scenario(t);
  fs.writeFileSync(path.join(added.companions[0], 'late.log'), 'ok 1 - late\n', { mode: 0o600 });
  assert.match(blockers(added.inspect()), /added after sealing: .*late\.log/);
  const outside = await scenario(t, {
    companion: {
      change: {
        record: r =>
          (r.stages.find(item => item.name === 'platform-tests-current-runtime').finished =
            new Date(Date.now() + 1000).toISOString()),
      },
    },
  });
  assert.match(
    blockers(outside.inspect()),
    /platform-tests-current-runtime is outside the run's times/
  );
  // A stage that started before its run did (verifier, round 1: only the late finish was tested).
  const early = await scenario(t, {
    companion: {
      change: {
        record: r =>
          (r.stages.find(item => item.name === 'platform-tests-minimum-runtime').started = new Date(
            Date.parse(r.started) - 1000
          ).toISOString()),
      },
    },
  });
  assert.match(
    blockers(early.inspect()),
    /platform-tests-minimum-runtime is outside the run's times/
  );
  // A companion whose recorded totals are not its sealed log's (verifier, round 1: untested).
  const totals = await scenario(t, {
    companion: {
      change: {
        record: r => {
          const stage = r.stages.find(item => item.name === 'platform-tests-current-runtime');
          stage.tests = {
            ...stage.tests,
            tests: stage.tests.tests + 1,
            pass: stage.tests.pass + 1,
          };
        },
      },
    },
  });
  assert.match(
    blockers(totals.inspect()),
    /platform-tests-current-runtime: its test totals disagree with its log/
  );
  // The gate run's own sealed test log and records: the run cannot even be read as sealed.
  const log = await scenario(t);
  fs.appendFileSync(path.join(log.run, 'full-tests-current-runtime.log'), '# extra\n');
  assert.throws(() => log.inspect(), /Run evidence changed/);
  const records = await scenario(t);
  fs.appendFileSync(path.join(records.run, 'full-tests-minimum-runtime.records.json'), ' ');
  assert.throws(() => records.inspect(), /Run evidence changed/);
});

test('altered or absent manifests are refused: another judged manifest, a changed sealed copy, none sealed', async t => {
  const other = await scenario(t, {
    companion: {
      change: {
        record: r => (r.platform = { kind: 'introduction', manifestSha256: 'f'.repeat(64) }),
      },
    },
  });
  assert.match(blockers(other.inspect()), /judged another manifest/);
  const main = await scenario(t, {
    main: {
      change: {
        record: r => (r.platform = { kind: 'introduction', manifestSha256: 'f'.repeat(64) }),
      },
    },
  });
  assert.match(blockers(main.inspect()), /judged another platform manifest/);
  const copy = await scenario(t, {
    main: {
      change: { record: (r, files) => (files['platform-manifest.json'] = Buffer.from('{}\n')) },
    },
  });
  assert.match(blockers(copy.inspect()), /sealed platform manifest is not the candidate's/);
  const absent = await scenario(t, {
    main: { change: { record: (r, files) => delete files['platform-manifest.json'] } },
  });
  assert.match(blockers(absent.inspect()), /sealed platform manifest is not the candidate's/);
  // A candidate that deletes a manifest its history holds: refused before any run is looked at.
  const deleted = await scenario(t);
  const { history } = deleted.candidate.current.platform;
  const inputs = {
    candidate: null,
    heads: history.map(node => node.commit),
    complete: true,
    history: history.map(node => ({ ...node, manifest: deleted.candidate.manifestBytes })),
  };
  assert.match(
    blockers(deleted.inspect({ platform: inputs })),
    /has no test\/platform-manifest\.json, which a commit behind it holds/
  );
});

test('T8 container evidence with the wrong inner runtime or code, or inner skipped, todo or missing tests, is refused', async t => {
  for (const [label, inner, pattern] of [
    [
      'Node 24 inside for Node 26',
      (runtime, parts) => runtime === '26' && (parts.node = 'v24.21.0'),
      /the run inside was Node v24\.21\.0, not Node 26/,
    ],
    [
      'records of another run inside',
      (runtime, parts) =>
        runtime === '24' && parts.records.forEach(record => (record.run = 'f'.repeat(64))),
      /is from another run/,
    ],
    [
      'another code',
      (runtime, parts) => runtime === '24' && (parts.code = 'f'.repeat(64)),
      /is from another run/,
    ],
    [
      'part B skipped',
      (runtime, parts) =>
        runtime === '24' &&
        (parts.results.find(r => r.name === 'T8 part B').directive = 'SKIP synthetic'),
      /directive SKIP|has 1 skipped/,
    ],
    [
      'part B todo',
      (runtime, parts) =>
        runtime === '24' &&
        (parts.results.find(r => r.name === 'T8 part B').directive = 'TODO synthetic'),
      /directive TODO|has 1 todo/,
    ],
    [
      'part B missing',
      (runtime, parts) => {
        if (runtime !== '24') return;
        parts.results = parts.results.filter(r => r.name !== 'T8 part B');
        parts.records = parts.records.filter(r => r.id !== 't8.part-b');
      },
      /t8\.part-b .* has 0 result lines in this run, not one: absence is not a pass/,
    ],
    [
      'another image',
      (runtime, parts) =>
        runtime === '24' &&
        (parts.container.image = `node:24-bookworm-slim@sha256:${'0'.repeat(64)}`),
      /ran node:24-bookworm-slim@sha256:0+, not/,
    ],
  ]) {
    const s = await scenario(t, { main: { change: { inner } } });
    assert.match(blockers(s.inspect()), pattern, label);
  }
});

test("the gate run's coverage is checked again: the driver's ok line required, inner names absent, Linux entries present", async t => {
  for (const [label, host, pattern] of [
    [
      'no driver ok line',
      parts => {
        parts.results = parts.results.filter(r => r.name !== 'T8 driver on Node 24');
        parts.records = parts.records.filter(r => r.id !== 't8.driver.node24');
      },
      /t8\.driver\.node24 .* has 0 result lines/,
    ],
    [
      'an inner test named on the host',
      parts => parts.results.push({ name: 'T8 part B' }),
      /t8\.part-b .* belongs to container, not linux, but TAP line/,
    ],
    [
      'the Linux entry missing',
      parts => {
        parts.results = parts.results.filter(r => r.name !== 'the Linux access list');
        parts.records = parts.records.filter(r => r.id !== 'linux.acl');
      },
      /linux\.acl .* has 0 result lines in this run, not one: absence is not a pass/,
    ],
    // A skip blocks on the totals alone; with totals forged to hide it, the coverage check still
    // finds the line, by name, at any directive.
    [
      'the macOS entry as a skip on Linux',
      parts => parts.results.push({ name: 'the macOS access list', directive: 'SKIP not macOS' }),
      /Incomplete test coverage: .*"skipped":1/,
    ],
    [
      'the macOS entry as a skip on Linux, totals forged',
      parts => {
        parts.results.push({ name: 'the macOS access list', directive: 'SKIP not macOS' });
        parts.totals = { pass: parts.results.length, skipped: 0 };
      },
      /mac\.acl .* belongs to darwin, not linux, but TAP line/,
    ],
    [
      'a record of another run',
      parts => (parts.records[0].run = 'f'.repeat(64)),
      /is from another run/,
    ],
  ]) {
    const s = await scenario(t, { main: { change: { host } } });
    assert.match(blockers(s.inspect()), pattern, label);
  }
});

test("each runtime's identity, the T8 images' authenticity and the network record are checked again from the sealed copies", async t => {
  for (const [label, change, pattern] of [
    [
      'a record for another binary',
      { runtime: r => (r.binarySha256 = '0'.repeat(64)) },
      /is for the binary/,
    ],
    ['a Homebrew build claiming a release signature', null, /has no release signature check/],
    [
      'an image record of another platform',
      { image: r => (r.platform.architecture = 'amd64') },
      /not the platform Docker ran/,
    ],
    [
      'an unavailable signature',
      { image: r => (r.outcome = 'unavailable') },
      /is unavailable, which blocks use/,
    ],
    [
      'a counter that went down',
      { network: ({ after }) => (after.counters['egress-drop'].packets = 0) },
      /counter egress-drop went down/,
    ],
    [
      'an unreviewed policy',
      { policy: p => (p.sha256 = 'c'.repeat(64)) },
      /has no reviewed policy record/,
    ],
  ]) {
    const options = change
      ? { main: { change } }
      : {
          companion: {
            change: {
              runtime: (r, os) =>
                os === 'darwin' &&
                (r.release = {
                  archive: 'node-v24.21.0-darwin-arm64.tar.gz',
                  archiveSha256: '3'.repeat(64),
                  shasumsSha256: '4'.repeat(64),
                  signatureSha256: '5'.repeat(64),
                  signer: 'A'.repeat(40),
                  keyringSha256: '6'.repeat(64),
                  outcome: 'verified',
                }),
            },
          },
        };
    const s = await scenario(t, options);
    assert.match(blockers(s.inspect()), pattern, label);
  }
});

test('B35: a candidate whose history never held the manifest needs no platform evidence, and a caller that names no platform inputs approves nothing', async t => {
  const s = await scenario(t, { companions: [] });
  const maintenance = {
    candidate: null,
    heads: [...s.candidate.current.parents],
    complete: true,
    reason: '',
    refused: [],
    history: [{ commit: s.candidate.current.parent, parents: [], manifest: null, reviewed: null }],
  };
  // A maintenance-shaped candidate (no manifest anywhere) and a run without platform stages.
  const files = s.candidate.current.files.filter(
    item => item.file !== 'test/platform-manifest.json'
  );
  const run = path.join(s.security, `${s.candidate.current.tree}-commit-maintenance`);
  const { platformCandidate } = s.fixture;
  const { current } = platformCandidate();
  const { writeRun, allStages } = await import('./helpers/security-run.mjs');
  const plain = {
    tree: current.tree,
    parent: current.parent,
    parents: current.parents,
    refs: current.refs,
    files,
  };
  writeRun(run, plain, [...allStages], s.now);
  const guard = { ...plain, lintStages: s.finalization.lintStageNames, platform: maintenance };
  const inventory = s.finalization.inspectRun(run, guard, s.now);
  assert.deepEqual(inventory.blockers, []);
  assert.equal('platform' in inventory, false);
  assert.equal('platformSha256' in inventory, false);
  // Companion runs for such a candidate are refused rather than ignored.
  assert.match(
    blockers(s.finalization.inspectRun(run, { ...guard, companions: [s.run] }, s.now)),
    /Only sealed local runs \(orbit-gate-local-diagnostic-run version 1\) of mode platform|no platform contract/
  );
  // A caller that names no platform inputs cannot establish the candidate identity, whose state
  // of the reserved manifest path the judgment gives (v3 C18, C19): it approves nothing, for the
  // maintenance run as for the 1.5 gate run.
  for (const [where, current] of [
    [run, { ...plain, lintStages: s.finalization.lintStageNames }],
    [s.run, { ...s.candidate.current, platform: undefined }],
  ])
    assert.match(
      blockers(s.finalization.inspectRun(where, current, s.now)),
      /needs the platform-manifest judgment/
    );
});

// ---------------------------------------------------------------------------------------------
// The commit guard, on throwaway Git repositories (with commits) in the temporary folder

const repositoryRoot = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const lintScripts = {
  'lint:sql': 'node scripts/sql-lint.mjs',
  'lint:imports': 'node scripts/import-graph.mjs',
};

/**
 * A repository with one commit and no manifest (1.5-shaped: its package.json defines both lint
 * scripts, unless `scripts` says otherwise), and the guard as Git would run it.
 */
async function guarded(t, scripts = lintScripts) {
  const modules = await load();
  const r = repository(t);
  const write = (file, text) => {
    fs.mkdirSync(path.dirname(path.join(r.root, file)), { recursive: true });
    fs.writeFileSync(path.join(r.root, file), text);
  };
  write('package.json', `${JSON.stringify({ scripts }, null, 2)}\n`);
  write(
    'scripts/security-tools.json',
    fs.readFileSync(path.join(repositoryRoot, 'scripts/security-tools.json'))
  );
  write('example.mjs', 'export const synthetic = true;\n');
  write('Dockerfile', '# Synthetic fixture\n');
  for (const file of modules.fixture.testFiles) write(file, `// Synthetic ${file}\n`);
  const first = r.commit('a 1.5-shaped commit without the manifest');
  const security = path.join(r.root, '.git', 'orbit-security');
  fs.mkdirSync(security, { mode: 0o700 });
  const environment = { ...process.env };
  for (const name of ['NODE_TEST_CONTEXT', 'NODE_OPTIONS', 'GIT_REFLOG_ACTION'])
    delete environment[name];
  const guard = (script = path.join(repositoryRoot, 'scripts/check-security-approval.mjs')) =>
    spawnSync(process.execPath, [script], { cwd: r.root, encoding: 'utf8', env: environment });
  const stageManifest = manifest => {
    write('test/platform-manifest.json', modules.fixture.manifestText(manifest));
    r.git('add', '-A');
  };
  return { ...modules, ...r, write, first, security, guard, stageManifest, environment };
}

test('the commit guard requires the platform evidence of a candidate with a manifest, and checks it again', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const g = await guarded(t);
  g.stageManifest(g.fixture.syntheticManifest());
  const candidate = g.fixture.repositoryCandidate(g.root);
  assert.equal(candidate.current.platform.history.length, 1);
  // A run finalized without platform evidence (as the maintenance finalizer would) is refused.
  const { finalizedRun, allStages } = await import('./helpers/security-run.mjs');
  const { platform: inputs, companions, ...plain } = candidate.current;
  finalizedRun(path.join(g.security, `${plain.tree}-commit-plain`), plain, allStages);
  const plainOnly = g.guard();
  assert.equal(plainOnly.status, 1, plainOnly.stderr);
  assert.match(plainOnly.stderr, /No fresh verified finalization/);
  assert.match(
    plainOnly.stderr,
    /The candidate has a platform contract \(test\/platform-manifest\.json\)/
  );
  // The finalizer's command line names the companion runs after the run.
  const now = Date.now();
  const { run, companions: made } = g.fixture.finalizePlatformRun(g.security, candidate, { now });
  const cli = (...args) =>
    spawnSync(
      process.execPath,
      [path.join(repositoryRoot, 'scripts/finalize-security.mjs'), ...args],
      {
        cwd: g.root,
        encoding: 'utf8',
        env: g.environment,
      }
    );
  const withCompanion = cli('inspect', run, made[0]);
  assert.equal(withCompanion.status, 0, withCompanion.stderr);
  assert.deepEqual(JSON.parse(withCompanion.stdout).blockers, []);
  assert.match(
    JSON.parse(cli('inspect', run).stdout).blockers.join('\n'),
    /No companion run covers darwin-platform/
  );
  // This draft's finalization is pending (F's obligations are F's, on the Mac): not accepted.
  const pending = g.guard();
  assert.equal(pending.status, 1, pending.stderr);
  assert.match(pending.stderr, /only F on the Mac can pass its finalization obligations/);
  // As F would write it (synthetic), the guard accepts it.
  g.fixture.asIfFinalizedByF(run);
  const accepted = g.guard();
  assert.equal(accepted.status, 0, accepted.stderr);
  // The guard reads the companion again: changed, it no longer approves.
  fs.appendFileSync(path.join(made[0], 'platform-tests-minimum-runtime.log'), '# late\n');
  const changed = g.guard();
  assert.equal(changed.status, 1, changed.stderr);
});

test('the commit guard reads each commit as it is: grafts, replace refs, a shallow boundary or the commit-graph cannot hide a deleted manifest or a removed lint script', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { finalizedRun, allStages, candidate } = await import('./helpers/security-run.mjs');
  const withoutLints = allStages.filter(name => !['sql-lint', 'import-lint'].includes(name));
  for (const [label, scripts, change, refusal] of [
    [
      'a deleted manifest',
      {},
      g => {
        g.stageManifest(g.fixture.syntheticManifest());
        g.commit('adds the manifest');
        fs.rmSync(path.join(g.root, 'test/platform-manifest.json'));
      },
      /The candidate has a platform contract/,
    ],
    [
      'a removed lint script',
      lintScripts,
      g => g.write('package.json', `${JSON.stringify({ scripts: {} }, null, 2)}\n`),
      /removes lint:sql or lint:imports/,
    ],
  ]) {
    const g = await guarded(t, scripts);
    // A commit made without the guard (--no-verify) removes it; the candidate comes after.
    change(g);
    const removing = g.commit(`removes ${label} without the guard`);
    g.write('example.mjs', 'export const synthetic = 4;\n');
    g.git('add', '-A');
    // A maintenance-shaped run (no lint or platform stages), finalized for the candidate as it
    // stands: what the guard would accept if the history behind the removal were hidden.
    const environment = unhardened({}, g.environment);
    const guard = env =>
      spawnSync(
        process.execPath,
        [path.join(repositoryRoot, 'scripts/check-security-approval.mjs')],
        {
          cwd: g.root,
          encoding: 'utf8',
          env: { ...environment, ...env },
        }
      );
    const finalize = name => {
      const plain = candidate(g.root);
      finalizedRun(path.join(g.security, `${plain.tree}-commit-${name}`), plain, withoutLints);
    };
    finalize('control');
    const control = guard();
    assert.equal(control.status, 1, `${label}: ${control.stderr}`);
    assert.match(control.stderr, refusal, label);
    for (const [attackLabel, attack] of historyAttacks(t, g, removing)) {
      const { env, refused, undo } = attack();
      try {
        // Its refs may have changed (a replace ref is a ref): a run of the candidate as it now is.
        finalize(`${attackLabel.replace(/[^a-z]+/gi, '-')}-${Math.random().toString(16).slice(2)}`);
        assert.equal(plainGit(g.root, ['rev-list', '--count', 'HEAD'], env), '1', attackLabel);
        const result = guard(env);
        assert.equal(result.status, 1, `${label}, ${attackLabel}: ${result.stderr}`);
        assert.match(result.stderr, refused ?? refusal, `${label}, ${attackLabel}`);
      } finally {
        undo();
      }
    }
  }
});

test("an approved commit's manifest becomes a reviewed baseline: deleting or weakening it is refused, and a new parent needs new evidence", async t => {
  if (gitSkip) return t.skip(gitSkip);
  const g = await guarded(t);
  const manifest = g.fixture.syntheticManifest();
  g.stageManifest(manifest);
  const introduced = g.fixture.repositoryCandidate(g.root);
  const now = Date.now();
  const { run: oldRun } = g.fixture.finalizePlatformRun(g.security, introduced, { now });
  assert.equal(g.guard().status, 1, 'a pending finalization approves nothing');
  g.fixture.asIfFinalizedByF(oldRun);
  assert.equal(g.guard().status, 0);
  const approved = g.commit('adds the platform manifest');
  // The next candidate keeps the manifest: its history marks the approved commit reviewed.
  g.write('example.mjs', 'export const synthetic = 2;\n');
  g.git('add', '-A');
  const next = g.fixture.repositoryCandidate(g.root, 'manifest');
  assert.deepEqual(next.current.platform.history.find(node => node.commit === approved).reviewed, {
    manifestSha256: introduced.manifestSha256,
  });
  // The old evidence is of another tree and parent: refused.
  const stale = g.guard();
  assert.equal(stale.status, 1, stale.stderr);
  assert.throws(
    () => g.finalization.validateFinalization(oldRun, next.current, now),
    /no longer matches/
  );
  g.fixture.asIfFinalizedByF(g.fixture.finalizePlatformRun(g.security, next, { now }).run);
  assert.equal(g.guard().status, 0);
  // The same evidence, but Git may be running the guard for an automatic merge whose other parent
  // it cannot see yet: refused, as for every candidate (v3 C18; Daybreak GD-R1).
  const automatic = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'scripts/check-security-approval.mjs')],
    {
      cwd: g.root,
      encoding: 'utf8',
      env: { ...g.environment, GIT_REFLOG_ACTION: 'merge' },
    }
  );
  assert.equal(automatic.status, 1, automatic.stderr);
  assert.match(
    automatic.stderr,
    /complete parent vector of this commit is not known .*Merge with --no-commit/s
  );
  // What the guard asks of any run for these candidates (the judgment comes before the runs).
  const judged = current =>
    g.platform
      .judgePlatformManifest({
        ...current.platform,
        binding: { tree: current.tree, parents: current.parents },
      })
      .problems.join('\n');
  // Deleted: refused whatever the run.
  fs.rmSync(path.join(g.root, 'test/platform-manifest.json'));
  g.git('add', '-A');
  const deleted = g.fixture.repositoryCandidate(g.root, 'manifest');
  assert.equal(deleted.current.platform.candidate, null);
  assert.match(
    judged(deleted.current),
    /has no test\/platform-manifest\.json, which a commit behind it holds/
  );
  assert.equal(g.guard().status, 1);
  // Weakened: the Linux entry removed.
  const weak = structuredClone(manifest);
  weak.entries = weak.entries.filter(entry => entry.id !== 'linux.acl');
  g.stageManifest(weak);
  assert.match(
    judged(g.fixture.repositoryCandidate(g.root, 'manifest').current),
    /entry linux\.acl was removed/
  );
  // Without the approval, no reviewed baseline can be established.
  g.stageManifest(manifest);
  for (const name of fs.readdirSync(g.security))
    if (name.startsWith(`${g.git('rev-parse', `${approved}^{tree}`)}-commit-`))
      fs.renameSync(
        path.join(g.security, name, 'finalization'),
        path.join(g.security, name, 'withdrawn')
      );
  const unreviewed = g.fixture.repositoryCandidate(g.root, 'manifest');
  assert.equal(
    unreviewed.current.platform.history.find(node => node.commit === approved).reviewed,
    null
  );
  assert.match(judged(unreviewed.current), /no reviewed manifest can be established/);
});

test('B35: the installed guard serves a maintenance worktree without platform evidence and a 1.5 worktree with it', async t => {
  if (gitSkip) return t.skip(gitSkip);
  // The first commit is maintenance-shaped: no lint scripts and no manifest anywhere.
  const g = await guarded(t, {});
  const maintenance = path.join(path.dirname(g.root), `${path.basename(g.root)}-maintenance`);
  t.after(() => fs.rmSync(maintenance, { recursive: true, force: true }));
  g.git('worktree', 'add', '--quiet', '-b', 'maintenance', maintenance, g.first);
  fs.writeFileSync(path.join(maintenance, 'example.mjs'), 'export const synthetic = 3;\n');
  execFileSync('git', ['-C', maintenance, 'add', '-A']);
  // The 1.5 worktree (the repository's own) adds both lint scripts.
  g.write('package.json', `${JSON.stringify({ scripts: lintScripts }, null, 2)}\n`);
  const installer = spawnSync(
    process.execPath,
    [path.join(repositoryRoot, 'scripts/install-security-hooks.mjs'), g.root],
    {
      encoding: 'utf8',
      env: { ...g.environment, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
    }
  );
  assert.equal(installer.status, 0, installer.stderr);
  const hooks = path.join(g.root, '.git', 'hooks');
  for (const name of [
    'security-platform.mjs',
    'security-catalog.mjs',
    'security-catalog.json',
    'security-entries.mjs',
    'security-gate-identity.mjs',
    'check-platform-coverage.mjs',
  ])
    assert.deepEqual(
      fs.readFileSync(path.join(hooks, name)),
      fs.readFileSync(path.join(repositoryRoot, 'scripts', name))
    );
  const helper = path.join(hooks, 'orbit-security-check.mjs');
  const run = cwd =>
    spawnSync(process.execPath, [helper], { cwd, encoding: 'utf8', env: g.environment });
  const { finalizedRun, allStages, candidate } = await import('./helpers/security-run.mjs');
  const withoutLints = allStages.filter(name => !['sql-lint', 'import-lint'].includes(name));
  // Maintenance: a maintenance run, without lint or platform stages, is accepted.
  const plain = candidate(maintenance);
  finalizedRun(path.join(g.security, `${plain.tree}-commit-maintenance`), plain, withoutLints);
  const kept = run(maintenance);
  assert.equal(kept.status, 0, kept.stderr);
  // 1.5: adding the manifest needs its platform evidence, from the same installed guard.
  g.stageManifest(g.fixture.syntheticManifest());
  const development = candidate(g.root);
  finalizedRun(path.join(g.security, `${development.tree}-commit-plain`), development, allStages);
  assert.equal(run(g.root).status, 1);
  const { run: platformRun } = g.fixture.finalizePlatformRun(
    g.security,
    g.fixture.repositoryCandidate(g.root)
  );
  assert.equal(run(g.root).status, 1, 'a pending finalization approves nothing');
  g.fixture.asIfFinalizedByF(platformRun);
  const complete = run(g.root);
  assert.equal(complete.status, 0, complete.stderr);
  // And the maintenance worktree still needs nothing more.
  assert.equal(run(maintenance).status, 0);
});

// ---------------------------------------------------------------------------------------------
// gate-draft-r12 (GDR11-AUTH-CONFIG-01): the metadata secret scan's input, read raw

// metadataScanInput takes every commit reachable from a ref or HEAD and every tag object reachable
// from a ref, as Git stores them, with `cat-file --batch`, and checks each answer and the whole
// enumeration. A synthetic runner gives exact Git-shaped answers here, so each refusal can be made
// on its own: a list or answer that is not complete, a duplicate, a missing object, another type,
// bytes that are not the object, more output than was asked for, a parent or a commit a ref names
// that the list leaves out, a NUL byte in a commit or a tag, and tags nested too deep. A real
// repository then shows the positive control: the bytes are cat-file's own, nested tags followed,
// and a tag of a blob counted as no metadata.
test('GDR11-AUTH-CONFIG-01: the metadata scan input is every commit and tag object read raw, each checked by type, size and hash, with an enumeration closed under parents, refs, HEAD and tags; anything incomplete, unreadable or holding a NUL byte refuses', async t => {
  const { platform } = await load();
  const make = (type, text) => {
    const content = Buffer.from(text, 'latin1');
    const id = createHash('sha1')
      .update(`${type} ${content.length}\0`)
      .update(content)
      .digest('hex');
    return { id, type, content };
  };
  const tree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
  const person = 'Orbit Fixture <fixture@example.invalid> 1767225600 +0000';
  const root = make('commit', `tree ${tree}\nauthor ${person}\ncommitter ${person}\n\nroot\n`);
  const child = make(
    'commit',
    `tree ${tree}\nparent ${root.id}\nauthor ${person}\ncommitter ${person}\n\nchild\n`
  );
  const tag = make('tag', `object ${child.id}\ntype commit\ntag t\ntagger ${person}\n\ntag\n`);
  const nested = make('tag', `object ${tag.id}\ntype tag\ntag n\ntagger ${person}\n\nnested\n`);
  const store = new Map([root, child, tag, nested].map(object => [object.id, object]));
  const frame = object =>
    Buffer.concat([
      Buffer.from(`${object.id} ${object.type} ${object.content.length}\n`),
      object.content,
      Buffer.from('\n'),
    ]);
  // A runner answering as Git does, with `change` replacing any of its answers.
  const runner = (change = {}) => {
    const answers = {
      revList: `${child.id}\n${root.id}\n`,
      refs: `${child.id} commit refs/heads/main\n${nested.id} tag refs/tags/n\n`,
      batch: ids =>
        Buffer.concat(
          ids.map(id => (store.has(id) ? frame(store.get(id)) : Buffer.from(`${id} missing\n`)))
        ),
      ...change,
    };
    return (args, input) => {
      if (args[0] === 'rev-list') return Buffer.from(answers.revList);
      if (args[0] === 'for-each-ref') return Buffer.from(answers.refs);
      if (args[0] === 'cat-file') return answers.batch(input.split('\n').filter(Boolean));
      throw new Error(`unexpected ${args.join(' ')}`);
    };
  };
  const read = platform.metadataScanInput(runner(), { head: child.id });
  assert.ok(read.commits.equals(Buffer.concat([frame(child), frame(root)])));
  assert.ok(
    read.tags.equals(Buffer.concat([tag, nested].sort((a, b) => (a.id < b.id ? -1 : 1)).map(frame)))
  );
  assert.deepEqual(read.counts, { commits: 2, tags: 2, otherTargets: 0 });
  const original = ids => runner()(['cat-file', '--batch'], ids.map(id => `${id}\n`).join(''));
  for (const [label, change, pattern, options = {}] of [
    [
      'a commit list without its last newline',
      { revList: `${child.id}\n${root.id}` },
      /list of commits is not complete/,
    ],
    [
      'a commit listed twice',
      { revList: `${child.id}\n${child.id}\n${root.id}\n` },
      /names an object twice/,
    ],
    [
      'a line that is no object id',
      { revList: `${child.id}\nHEAD\n` },
      /list of commits holds "HEAD"/,
    ],
    [
      'a parent the list leaves out',
      { revList: `${child.id}\n` },
      /parent .* is not in the list of commits/,
    ],
    [
      'a ref list without its last newline',
      { refs: `${child.id} commit refs/heads/main` },
      /list of refs is not complete/,
    ],
    [
      'a ref naming a commit the list leaves out',
      { refs: `${'f'.repeat(40)} commit refs/heads/other\n` },
      /refs\/heads\/other names the commit f+, which the list of commits leaves out/,
    ],
    [
      'HEAD naming a commit the list leaves out',
      {},
      /HEAD names the commit e+/,
      { head: 'e'.repeat(40) },
    ],
    [
      'a ref naming an object of an unknown type',
      { refs: `${child.id} weird refs/heads/w\n` },
      /of the type "weird"/,
    ],
    [
      'a missing object',
      { batch: ids => Buffer.concat([Buffer.from(`${ids[0]} missing\n`), original(ids.slice(1))]) },
      /cannot be read \(Git answers ".* missing"\)/,
    ],
    [
      'another type',
      {
        batch: ids =>
          Buffer.from(
            original(ids).toString('latin1').replace(`${ids[0]} commit`, `${ids[0]} tree`),
            'latin1'
          ),
      },
      /is a tree, not a commit/,
    ],
    [
      'an answer cut short',
      { batch: ids => original(ids).subarray(0, original(ids).length - 3) },
      /shorter than its \d+ bytes/,
    ],
    [
      'an answer that ends before an object',
      { batch: ids => original(ids.slice(0, 1)) },
      /ends before the object/,
    ],
    [
      'more than was asked for',
      { batch: ids => Buffer.concat([original(ids), Buffer.from('extra')]) },
      /more than the objects asked for/,
    ],
    [
      'bytes that are not the object',
      {
        batch: ids =>
          Buffer.from(
            original(ids).toString('latin1').replace('\n\nchild\n', '\n\nchilD\n'),
            'latin1'
          ),
      },
      /are not that object/,
    ],
    ['answers in another order', { batch: ids => original([...ids].reverse()) }, /cannot be read/],
  ])
    assert.throws(
      () => platform.metadataScanInput(runner(change), { head: child.id, ...options }),
      pattern,
      label
    );
  // NUL bytes in a commit or a tag (an encoding such as UTF-16): refused, never left out.
  const wide = make(
    'commit',
    `tree ${tree}\nauthor ${person}\ncommitter ${person}\nencoding UTF-16\n\nR\0!\0\n\0`
  );
  store.set(wide.id, wide);
  assert.throws(
    () =>
      platform.metadataScanInput(
        runner({ revList: `${wide.id}\n`, refs: `${wide.id} commit refs/heads/wide\n` })
      ),
    new RegExp(`the commit ${wide.id} holds a NUL byte`)
  );
  const wideTag = make(
    'tag',
    `object ${child.id}\ntype commit\ntag w\ntagger ${person}\n\nR\0!\0\n`
  );
  store.set(wideTag.id, wideTag);
  assert.throws(
    () => platform.metadataScanInput(runner({ refs: `${wideTag.id} tag refs/tags/w\n` })),
    new RegExp(`the tag ${wideTag.id} holds a NUL byte`)
  );
  // Tags of tags more than 64 deep.
  let deepest = child;
  let deepType = 'commit';
  for (let level = 0; level < 66; level += 1) {
    deepest = make(
      'tag',
      `object ${deepest.id}\ntype ${deepType}\ntag d${level}\ntagger ${person}\n\nd\n`
    );
    deepType = 'tag';
    store.set(deepest.id, deepest);
  }
  assert.throws(
    () => platform.metadataScanInput(runner({ refs: `${deepest.id} tag refs/tags/deep\n` })),
    /more than 64 deep/
  );

  // A real repository: the bytes are cat-file's own, a nested tag is followed, a tag of a blob is
  // counted as no metadata, and a missing object refuses (no lazy fetch is possible: none is set
  // up, and the binding sets GIT_NO_LAZY_FETCH=1).
  if (gitSkip) return t.skip(gitSkip);
  const r = repository(t);
  fs.writeFileSync(path.join(r.root, 'a.txt'), 'a\n');
  const c1 = r.commit('first');
  fs.writeFileSync(path.join(r.root, 'b.txt'), 'b\n');
  const c2 = r.commit('second R12-UNIT-MARKER');
  const tagged = [
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.invalid',
    '-c',
    'tag.gpgsign=false',
  ];
  r.git(...tagged, 'tag', '-a', 'v1', '-m', 'tag R12-UNIT-TAG');
  r.git(...tagged, 'tag', '-a', 'v1-again', 'v1', '-m', 'nested R12-UNIT-NESTED');
  const blob = r.git('rev-parse', 'HEAD:a.txt');
  r.git(...tagged, 'tag', '-a', 'blob-tag', blob, '-m', 'a tag of a blob');
  const binding = platform.bindRepository(r.root, {
    env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
  });
  const run = (args, input) => binding.run(args, input, { maxBuffer: 64 * 1024 ** 2 });
  const real = platform.metadataScanInput(run, { head: c2 });
  assert.deepEqual(real.counts, { commits: 2, tags: 3, otherTargets: 1 });
  assert.ok(real.commits.equals(r.runGit(['cat-file', '--batch'], `${c2}\n${c1}\n`)));
  const tagIds = ['v1', 'v1-again', 'blob-tag']
    .map(name => r.git('rev-parse', `refs/tags/${name}`))
    .sort();
  assert.ok(
    real.tags.equals(r.runGit(['cat-file', '--batch'], tagIds.map(id => `${id}\n`).join('')))
  );
  for (const marker of ['R12-UNIT-MARKER', 'R12-UNIT-TAG', 'R12-UNIT-NESTED'])
    assert.ok(Buffer.concat([real.commits, real.tags]).includes(marker), marker);
  const objects = path.join(r.root, '.git', 'objects');
  const aside = temporary(t, 'orbit-r12-aside-');
  fs.renameSync(path.join(objects, c1.slice(0, 2), c1.slice(2)), path.join(aside, c1));
  assert.throws(
    () => platform.metadataScanInput(run, { head: c2 }),
    /Command failed|cannot be read/
  );
});

// Round 2 of gate-draft-r12 (check-1 R12C1-META-ENC-01, a regression of round 1): the metadata
// input refused only a commit holding a NUL byte. A commit whose `encoding` header names UTF-7 is
// valid (fsck --strict passes it) and holds no NUL byte, so it was given to the scan raw, its ASCII
// text held in other bytes (`+AFIAMQAy...-`) where no pattern can match it, while Git shows that
// text decoded, and the eleventh round's formatted input (UTF-8) held it. Each `encoding` header must
// now name UTF-8, US-ASCII, ISO-8859-1 to -16 or Windows-1250 to -1258, in which ASCII text is its own
// bytes; any other refuses the input, never leaves the commit out. The harness shows with plain Git
// (no configuration file) that each refused case shows a marker its raw object does not hold (UTF-7;
// ISO-2022-JP with an escape sequence between two letters; HZ with `~` and a newline), and that
// each admitted case holds the marker Git shows (no header, UTF-8, utf8, US-ASCII, ISO-8859-1,
// latin1, ISO-8859-15, windows-1252, CP1252).
test('R12C1-META-ENC-01: a commit whose encoding header names an encoding in which the text Git shows need not be its own ASCII bytes (UTF-7, ISO-2022-JP, HZ, or any name outside UTF-8, US-ASCII, ISO-8859 and Windows-125x) refuses the metadata input, never left out or given raw; the admitted encodings hold the shown marker in their raw bytes', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const { platform } = await load();
  const r = repository(t);
  fs.writeFileSync(path.join(r.root, 'a.txt'), 'a\n');
  const c1 = r.commit('first');
  const tree = r.git('rev-parse', `${c1}^{tree}`);
  const marker = 'R12R2ENCODINGMARKER';
  // Explicit synthetic identity; a time zone without `+`, which UTF-7 would read as a shift.
  const person = 'Orbit Fixture <fixture@example.invalid> 1767225600 -0000';
  const cleanEnv = {
    ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name))),
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
  };
  const plain = args => execFileSync('git', ['-C', r.root, ...args], { env: cleanEnv });
  const commitWith = (encoding, body) =>
    execFileSync('git', ['-C', r.root, 'hash-object', '-t', 'commit', '-w', '--stdin'], {
      input: Buffer.concat([
        Buffer.from(
          `tree ${tree}\nparent ${c1}\nauthor ${person}\ncommitter ${person}\n${encoding === null ? '' : `encoding ${encoding}\n`}\nA message `,
          'latin1'
        ),
        body,
        Buffer.from('\n'),
      ]),
      env: cleanEnv,
      encoding: 'utf8',
    }).trim();
  const utf7 = Buffer.from(
    `+${Buffer.from(marker, 'utf16le').swap16().toString('base64').replace(/=+$/, '')}-`
  );
  const split = between =>
    Buffer.from(`${marker.slice(0, 7)}${between}${marker.slice(7)}`, 'latin1');
  const refused = [
    ['UTF-7', utf7],
    ['utf-7', utf7],
    ['ISO-2022-JP', split('\x1b(B')],
    ['HZ-GB-2312', split('~\n')],
  ];
  const admitted = [
    [null, Buffer.from(marker)],
    ['UTF-8', Buffer.from(marker)],
    ['utf8', Buffer.from(marker)],
    ['US-ASCII', Buffer.from(marker)],
    ['ISO-8859-1', Buffer.from(`${marker} caf\xe9`, 'latin1')],
    ['latin1', Buffer.from(marker)],
    ['ISO-8859-15', Buffer.from(marker)],
    ['windows-1252', Buffer.from(`${marker} \x80`, 'latin1')],
    ['CP1252', Buffer.from(marker)],
  ];
  const failures = [];
  const binding = platform.bindRepository(r.root, { env: cleanEnv });
  const run = (args, input) => binding.run(args, input, { maxBuffer: 64 * 1024 ** 2 });
  for (const [encoding, body] of [...refused, ...admitted]) {
    const label = encoding ?? 'no encoding header';
    try {
      const id = commitWith(encoding, body);
      r.git('update-ref', 'refs/heads/main', id);
      const raw = plain(['cat-file', 'commit', id]);
      const shown = plain(['log', '-1', '--format=%B', id]);
      assert.equal(plain(['fsck', '--strict', '--no-dangling']).toString(), '', 'fsck --strict');
      assert.equal(raw.includes(0), false, 'the harness: no NUL byte');
      assert.ok(shown.includes(marker), 'the harness: Git shows the marker');
      if (refused.some(([name]) => name === encoding)) {
        assert.equal(raw.includes(marker), false, 'the harness: the raw object lacks the marker');
        assert.throws(
          () => platform.metadataScanInput(run, { head: id }),
          new RegExp(
            `the commit ${id} names the encoding "${encoding}", in which the text Git shows need not be the ASCII bytes the scan's patterns match .*: it is refused, not left out`
          )
        );
      } else {
        assert.ok(raw.includes(marker), 'the harness: the raw object holds the marker');
        const read = platform.metadataScanInput(run, { head: id });
        assert.ok(read.commits.includes(raw), 'the raw commit is in the input');
        assert.ok(read.commits.includes(marker), 'the marker is in the input');
      }
    } catch (error) {
      failures.push(`${label}: ${error.message.split('\n')[0]}`);
    }
  }
  r.git('update-ref', 'refs/heads/main', c1);
  // A second header naming another encoding refuses too (Git reads the first; the input is held
  // to every one), as does a spelling outside the list.
  const spelled = (headers, name) => {
    const id = execFileSync('git', ['-C', r.root, 'hash-object', '-t', 'commit', '-w', '--stdin'], {
      input: `tree ${tree}\nparent ${c1}\nauthor ${person}\ncommitter ${person}\n${headers}\nmessage\n`,
      env: cleanEnv,
      encoding: 'utf8',
    }).trim();
    r.git('update-ref', 'refs/heads/main', id);
    try {
      assert.throws(
        () => platform.metadataScanInput(run, { head: id }),
        new RegExp(`names the encoding "${name}"`),
        headers
      );
    } catch (error) {
      failures.push(`${headers.trim()}: ${error.message.split('\n')[0]}`);
    }
  };
  spelled('encoding UTF-8\nencoding UTF-7\n', 'UTF-7');
  spelled('encoding UTF-8 \n', 'UTF-8 ');
  spelled('encoding EBCDIC-US\n', 'EBCDIC-US');
  r.git('update-ref', 'refs/heads/main', c1);
  assert.deepEqual(failures, [], `cases that failed:\n${failures.join('\n')}`);
});
