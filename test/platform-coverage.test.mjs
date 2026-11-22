// The platform coverage check (scripts/check-platform-coverage.mjs) on synthetic runs: the
// adversarial cases Codex listed on 2026-10-11 that belong to the harness. Missing, duplicate and
// wrong-platform names; skipped, todo and failing tests; records from another run or manifest, of
// another runtime or platform, or of no entry; changed container evidence and the wrong inner
// runtime or code; removed or narrowed entries and runs, and the dispositions that may excuse
// them. Each case starts from a passing run and changes one thing.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  allTestFiles,
  checkContainerEvidence,
  checkCoverage,
  coverageLoss,
  judgeCandidateManifest,
  parseArguments,
  parseManifest,
  readRecords,
  sha256,
  tapResults,
  tapTotals,
} from '../scripts/check-platform-coverage.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
const script = path.join(repository, 'scripts', 'check-platform-coverage.mjs');
const temporary = t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-coverage-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
};
const digest = character => `node:24-bookworm-slim@sha256:${character.repeat(64)}`;
// A synthetic Node 26 reference: a fixture only, never configured or pulled.
const digest26 = `node:26-bookworm-slim@sha256:${'26'.repeat(32)}`;

const fixture = () => ({
  schemaVersion: 1,
  runs: {
    'darwin-platform': {
      platform: 'darwin',
      runtimes: ['24', '26'],
      files: ['test/a.test.mjs', 'test/b.test.mjs'],
      requiredFor: ['commit'],
    },
    'linux-full': {
      platform: 'linux',
      runtimes: ['24', '26'],
      files: ['test/a.test.mjs', 'test/b.test.mjs', 'test/c.test.mjs'],
      requiredFor: ['commit', 'release'],
    },
    't8-container': {
      platform: 'container',
      runtimes: ['24', '26'],
      files: ['test/c.test.mjs'],
      requiredFor: ['commit'],
      images: { 24: { image: digest('a'), driver: 'c.driver' }, 26: null },
      hostRuns: ['linux-full'],
    },
  },
  entries: [
    entry('a.linux', 'test/a.test.mjs', ['A on Linux'], ['linux'], ['linux-full']),
    entry('a.darwin', 'test/a.test.mjs', ['A on macOS'], ['darwin'], ['darwin-platform']),
    entry('b.linux', 'test/b.test.mjs', ['B', 'B on Linux'], ['linux'], ['linux-full']),
    entry('c.inner', 'test/c.test.mjs', ['C inside'], ['container'], ['t8-container']),
    {
      ...entry('c.driver', 'test/c.test.mjs', ['C driver'], ['darwin', 'linux'], ['linux-full']),
      prerequisites: ['docker'],
    },
  ],
});
function entry(id, file, name, platforms, evidence) {
  return { id, file, name, platforms, runtimes: ['24', '26'], prerequisites: [], evidence };
}

const nonce = 'a'.repeat(64);
const code = 'c'.repeat(64);
function prepared(change = () => {}) {
  const manifest = fixture();
  change(manifest);
  const text = JSON.stringify(manifest);
  const parsed = parseManifest(text);
  assert.deepEqual(parsed.problems, []);
  return { manifest: parsed.manifest, manifestSha256: parsed.sha256 };
}

/**
 * TAP as node's reporter writes it: `nodes` are { name, ok, directive, children, yaml } with
 * yaml lines placed inside the test's YAML block; `extra` lines go before the totals.
 */
function tapOf(nodes, { totals, extra = [] } = {}) {
  const lines = ['TAP version 13'];
  const count = { tests: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const emit = (list, depth) =>
    list.forEach((node, index) => {
      const pad = '    '.repeat(depth);
      lines.push(`${pad}# Subtest: ${node.name}`);
      if (node.children?.length) {
        emit(node.children, depth + 1);
        lines.push(`${pad}    1..${node.children.length}`);
      }
      const ok = node.ok !== false;
      lines.push(
        `${pad}${ok ? 'ok' : 'not ok'} ${index + 1} - ${node.name}${node.directive ? ` # ${node.directive}` : ''}`
      );
      lines.push(`${pad}  ---`, `${pad}  duration_ms: 1.5`);
      for (const line of node.yaml ?? []) lines.push(`${pad}  ${line}`);
      lines.push(`${pad}  ...`);
      count.tests++;
      if (/^SKIP/.test(node.directive ?? '')) count.skipped++;
      else if (/^TODO/.test(node.directive ?? '')) count.todo++;
      else if (ok) count.pass++;
      else count.fail++;
    });
  emit(nodes, 0);
  lines.push(...extra, `1..${nodes.length}`);
  for (const [name, value] of Object.entries({ ...count, ...totals }))
    if (value !== null) lines.push(`# ${name} ${value}`);
  return `${lines.join('\n')}\n`;
}

const linuxNodes = () => [
  { name: 'unrelated test' },
  { name: 'A on Linux' },
  { name: 'B', children: [{ name: 'B before' }, { name: 'B on Linux' }] },
  { name: 'C driver' },
];
const record = (manifest, manifestSha256, id, overrides = {}) => {
  const item = manifest.entries.find(candidate => candidate.id === id);
  return {
    kind: 'result',
    run: nonce,
    manifest: manifestSha256,
    id,
    file: item.file,
    name: item.name,
    platform: 'linux',
    node: 'v26.5.1',
    result: 'completed',
    source: `1-${'0'.repeat(8)}-0000-0000-0000-${'0'.repeat(12)}.jsonl:1`,
    ...overrides,
  };
};
const linuxRecords = (manifest, manifestSha256) =>
  ['a.linux', 'b.linux', 'c.driver'].map(id => record(manifest, manifestSha256, id));

function linuxCheck({
  nodes = linuxNodes(),
  records,
  change,
  tapChange = tap => tap,
  ...rest
} = {}) {
  const { manifest, manifestSha256 } = prepared(change);
  return checkCoverage({
    manifest,
    manifestSha256,
    runId: 'linux-full',
    runtime: '26',
    tap: tapChange(tapOf(nodes)),
    records: records ? records(manifest, manifestSha256) : linuxRecords(manifest, manifestSha256),
    nonce,
    ...rest,
  }).problems.join('\n');
}

test('coverage: a run that executed each required entry once, passing, and no other platform’s, passes, and its coverage map names each entry', () => {
  assert.equal(linuxCheck(), '');
  const { manifest, manifestSha256 } = prepared();
  const result = checkCoverage({
    manifest,
    manifestSha256,
    runId: 'linux-full',
    runtime: '26',
    tap: tapOf(linuxNodes()),
    records: linuxRecords(manifest, manifestSha256),
    nonce,
  });
  assert.deepEqual(
    result.coverage.map(item => [item.id, item.status]),
    [
      ['a.linux', 'required'],
      ['a.darwin', 'absent'],
      ['b.linux', 'required'],
      ['c.inner', 'absent'],
      ['c.driver', 'required'],
    ]
  );
  assert.deepEqual(result.totals, {
    tests: 6,
    pass: 6,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  });
});

test('coverage: missing, duplicate and wrong-platform names, and skipped, todo or failing tests, are refused', () => {
  const without = name => linuxNodes().filter(node => node.name !== name);
  // Missing: absence is not a pass, also with totals that agree.
  assert.match(
    linuxCheck({
      nodes: without('A on Linux'),
      records: (m, h) => linuxRecords(m, h).filter(item => item.id !== 'a.linux'),
    }),
    /a\.linux \("A on Linux"\) has 0 result lines in this run, not one: absence is not a pass[^]*a\.linux .* has 0 records/
  );
  // A subtest under another parent is not the entry.
  assert.match(
    linuxCheck({
      nodes: [...without('B'), { name: 'B on Linux' }],
    }),
    /b\.linux \("B > B on Linux"\) has 0 result lines/
  );
  // Duplicate: a test of the same name elsewhere (another file) makes it ambiguous.
  assert.match(
    linuxCheck({ nodes: [...linuxNodes(), { name: 'A on Linux' }] }),
    /a\.linux .* has 2 result lines in this run, not one \(TAP lines \d+, \d+\)/
  );
  // Another platform's test in this run, passing or as a skip.
  assert.match(
    linuxCheck({ nodes: [...linuxNodes(), { name: 'A on macOS' }] }),
    /a\.darwin \("A on macOS"\) belongs to darwin, not linux, but TAP line \d+ names it/
  );
  const skipped = linuxCheck({
    nodes: [...linuxNodes(), { name: 'A on macOS', directive: 'SKIP macOS only' }],
  });
  assert.match(skipped, /"A on macOS" has the directive SKIP/);
  assert.match(skipped, /a\.darwin .* belongs to darwin, not linux/);
  assert.match(skipped, /the run has 1 skipped/);
  // Another platform's test is absent at any depth: also under a parent of its own (verify-1).
  assert.match(
    linuxCheck({
      nodes: [...linuxNodes(), { name: 'wrapper', children: [{ name: 'A on macOS' }] }],
    }),
    /a\.darwin \("A on macOS"\) belongs to darwin, not linux, but TAP line \d+ names it \(under "wrapper"\)/
  );
  // The T8 container's own test in a host run.
  assert.match(
    linuxCheck({ nodes: [...linuxNodes(), { name: 'C inside' }] }),
    /c\.inner \("C inside"\) belongs to container, not linux/
  );
  // Skipped, todo or failing: never a pass, whatever the totals say.
  for (const [change, expected] of [
    [
      { directive: 'SKIP no setfacl' },
      /"A on Linux" has the directive SKIP[^]*a\.linux .* did not pass/,
    ],
    [{ directive: 'TODO later' }, /the run has 1 todo[^]*"A on Linux" has the directive TODO/],
    [{ ok: false }, /the run has 1 fail[^]*a\.linux .* did not pass: TAP line \d+/],
  ])
    assert.match(
      linuxCheck({
        nodes: linuxNodes().map(node =>
          node.name === 'A on Linux' ? { ...node, ...change } : node
        ),
      }),
      expected
    );
  // A skipped or todo test that is no entry at all still blocks.
  assert.match(
    linuxCheck({
      nodes: [...linuxNodes(), { name: 'needs curl', directive: 'SKIP curl is not installed' }],
    }),
    /"needs curl" has the directive SKIP/
  );
  assert.match(
    linuxCheck({
      nodes: linuxNodes().map(node =>
        node.name === 'B'
          ? {
              ...node,
              children: [{ name: 'B before', directive: 'TODO soon' }, { name: 'B on Linux' }],
            }
          : node
      ),
    }),
    /"B > B before" has the directive TODO/
  );
});

test('coverage: lines a test printed, a failing test’s error text and the T8 driver’s diagnostics are never results', () => {
  // Without A on Linux, but with its result line forged in three places.
  const nodes = linuxNodes().filter(node => node.name !== 'A on Linux');
  nodes[0] = {
    ...nodes[0],
    ok: false,
    yaml: ['error: |-', '  ok 1 - A on Linux', "  location: 'x'"],
  };
  const tap = tapOf(nodes, {
    extra: ['# ok 2 - A on Linux', '# T8 driver: the results inside:\\nok 3 - A on Linux'],
  });
  const { results } = tapResults(tap);
  assert.ok(!results.some(result => result.path.join() === 'A on Linux'));
  const problems = linuxCheck({
    nodes,
    tapChange: () => tap,
  });
  assert.match(problems, /a\.linux .* has 0 result lines/);
  // The parser: nesting, escapes, directives and its own refusals.
  const parsed = tapResults(
    [
      '    ok 1 - child \\# one',
      '    1..1',
      'ok 1 - parent',
      'ok 2 - with \\\\ back # SKIP why not',
      '  ok 3 - two spaces',
      '  ---',
    ].join('\n')
  );
  assert.deepEqual(
    parsed.results.map(item => [item.path, item.directive, item.reason]),
    [
      [['parent', 'child # one'], null, ''],
      [['parent'], null, ''],
      [['with \\ back'], 'SKIP', 'why not'],
    ]
  );
  assert.match(parsed.problems.join('\n'), /a result line indented by 2 spaces/);
  assert.match(
    tapResults('ok 1 - a\n  ---\n  error: x').problems.join(),
    /ends inside a YAML block/
  );
  assert.match(tapResults('    ok 1 - orphan').problems.join(), /have no parent result line/);
});

// verify-1: node's TAP reporter does not escape the keys of a failing assertion's values, so a
// failing test can end its own YAML block early and print a line that reads as a result (seen on
// Node 26.5.1 and 24.21.0). The parser takes the block as the reporter delimits it; the run still
// carries that failure in its totals and is refused.
test('coverage: a failing test that ends its YAML block early to forge a result line still fails the run', () => {
  const nodes = linuxNodes().filter(node => node.name !== 'A on Linux');
  nodes[0] = { ...nodes[0], ok: false, yaml: ['actual:', '  k', 'FORGED'] };
  const tap = tapOf(nodes).replace(
    '  FORGED',
    '  ...\nok 77 - A on Linux\n  ---\n  z: 1\n  operator: deepStrictEqual'
  );
  assert.ok(tapResults(tap).results.some(result => result.path.join() === 'A on Linux'));
  const problems = linuxCheck({ nodes, tapChange: () => tap });
  assert.match(problems, /the run passed 4 of 5 tests/);
  assert.match(problems, /the run has 1 fail/);
});

test('coverage: totals must each appear once and agree, with no failure, cancellation, skip or todo', () => {
  assert.deepEqual(tapTotals(tapOf([{ name: 'a' }])).problems, []);
  for (const [totals, expected] of [
    [{ tests: null }, /0 "# tests" totals, not one/],
    [{ pass: 0 }, /passed 0 of 1 tests/],
    [{ tests: 0, pass: 0 }, /passed 0 of 0 tests/],
    [{ cancelled: 1 }, /has 1 cancelled/],
  ])
    assert.match(tapTotals(tapOf([{ name: 'a' }], { totals })).problems.join('\n'), expected);
  assert.match(
    tapTotals(`${tapOf([{ name: 'a' }])}# todo 0\n`).problems.join(),
    /2 "# todo" totals, not one/
  );
});

test('coverage: records from another run or manifest, of another runtime or platform, failed, of no entry, or of a file the run did not run are refused', () => {
  const changed = (id, overrides) => (m, h) =>
    linuxRecords(m, h).map(item => (item.id === id ? { ...item, ...overrides } : item));
  const cases = [
    [
      changed('a.linux', { run: 'b'.repeat(64) }),
      /a\.linux .* is from another run \(bbbbbbbbbbbb…\)/,
    ],
    [
      changed('a.linux', { manifest: 'd'.repeat(64) }),
      /a\.linux .* was written with another manifest/,
    ],
    [changed('a.linux', { node: 'v24.21.0' }), /a\.linux .* ran on Node v24\.21\.0, not Node 26/],
    [changed('a.linux', { platform: 'darwin' }), /a\.linux .* ran on darwin, not linux/],
    [changed('a.linux', { platform: 'container' }), /a\.linux .* ran on container, not linux/],
    [changed('a.linux', { result: 'skipped' }), /a\.linux .* says skipped/],
    [changed('a.linux', { result: 'failed' }), /a\.linux .* says failed/],
    [
      changed('a.linux', { file: 'test/b.test.mjs' }),
      /a\.linux .* names the file test\/b\.test\.mjs/,
    ],
    [changed('a.linux', { name: ['B'] }), /a\.linux .* names another test/],
    [
      (m, h) => [...linuxRecords(m, h), record(m, h, 'a.linux')],
      /a\.linux .* has 2 records in this run, not one/,
    ],
    [
      (m, h) => [...linuxRecords(m, h), { ...record(m, h, 'a.linux'), id: 'z.extra' }],
      /records "z\.extra", which the manifest does not list/,
    ],
    [
      (m, h) => [...linuxRecords(m, h), record(m, h, 'a.darwin', { platform: 'darwin' })],
      /a\.darwin .* belongs to darwin, not linux, but .* records it/,
    ],
  ];
  for (const [records, expected] of cases)
    assert.match(linuxCheck({ records }), expected, `${expected}`);
  // An entry of a file this run does not run must not appear, as a result or a record.
  const { manifest, manifestSha256 } = prepared();
  const darwin = checkCoverage({
    manifest,
    manifestSha256,
    runId: 'darwin-platform',
    runtime: '24',
    tap: tapOf([{ name: 'A on macOS' }, { name: 'C driver' }]),
    records: [
      record(manifest, manifestSha256, 'a.darwin', { platform: 'darwin', node: 'v24.21.0' }),
      record(manifest, manifestSha256, 'c.driver', { platform: 'darwin', node: 'v24.21.0' }),
    ],
    nonce,
  }).problems.join('\n');
  assert.match(
    darwin,
    /c\.driver .* TAP line \d+ names it, but this run does not run test\/c\.test\.mjs/
  );
  assert.match(darwin, /c\.driver .* records it, but this run does not run test\/c\.test\.mjs/);
  assert.doesNotMatch(darwin, /a\.darwin/);
});

test('coverage: the run, runtime, nonce and files must be the manifest’s', () => {
  const { manifest, manifestSha256 } = prepared();
  const base = {
    manifest,
    manifestSha256,
    runId: 'linux-full',
    runtime: '26',
    tap: tapOf(linuxNodes()),
    records: linuxRecords(manifest, manifestSha256),
    nonce,
  };
  const problems = overrides => checkCoverage({ ...base, ...overrides }).problems.join('\n');
  assert.match(problems({ runId: 'linux-nightly' }), /the manifest has no run "linux-nightly"/);
  // A name Object.prototype has is no run either, not a lookup that throws (verify-1).
  for (const runId of ['constructor', 'toString', '__proto__', 'hasOwnProperty'])
    assert.equal(problems({ runId }), `the manifest has no run "${runId}"`);
  assert.match(problems({ runtime: '25' }), /run linux-full is not run on Node 25/);
  assert.match(problems({ nonce: 'A'.repeat(64) }), /the run nonce is not 64 lowercase hex digits/);
  assert.match(
    problems({ files: ['test/a.test.mjs', 'test/c.test.mjs', 'test/d.test.mjs'] }),
    /the run's files are not run linux-full's: missing test\/b\.test\.mjs, extra test\/d\.test\.mjs/
  );
  assert.equal(problems({ files: ['test/c.test.mjs', 'test/a.test.mjs', 'test/b.test.mjs'] }), '');
  // "all": every test file under the root, as the glob test/**/*.test.mjs finds them.
  const all = prepared(m => (m.runs['linux-full'].files = 'all'));
  const files = allTestFiles(repository);
  assert.ok(files.length > 100 && files.includes('test/platform-coverage.test.mjs'));
  assert.match(
    checkCoverage({ ...base, ...all, files: files.slice(1) }).problems.join('\n'),
    new RegExp(`missing ${files[0].replace(/[./]/g, '\\$&')}`)
  );
});

/** A records directory with host records, and T8 container evidence for each of `runtimes`. */
function containerSetup(t, manifest, manifestSha256, runtimes, { inner = {}, host = {} } = {}) {
  const directory = temporary(t);
  const lines = [];
  for (const runtime of runtimes) {
    const folder = `t8-container-${runtime}-ab${runtime}xy`;
    fs.mkdirSync(path.join(directory, folder, 'records'), { recursive: true });
    const node = inner.node?.[runtime] ?? (runtime === '24' ? 'v24.21.0' : 'v26.5.1');
    const tap = inner.tap?.[runtime] ?? tapOf([{ name: 'helper test' }, { name: 'C inside' }]);
    fs.writeFileSync(path.join(directory, folder, 'inner.tap'), tap);
    const innerRecord = {
      kind: 'result',
      run: inner.run ?? code,
      manifest: manifestSha256,
      id: 'c.inner',
      file: 'test/c.test.mjs',
      name: ['C inside'],
      platform: 'container',
      node,
      result: 'completed',
    };
    fs.writeFileSync(
      path.join(
        directory,
        folder,
        'records',
        `12-${'1'.repeat(8)}-1111-1111-1111-${'1'.repeat(12)}.jsonl`
      ),
      `${JSON.stringify(innerRecord)}\n`
    );
    const read = readRecords(path.join(directory, folder, 'records'), { containers: false });
    lines.push({
      kind: 'container',
      run: nonce,
      manifest: manifestSha256,
      id: manifest.runs['t8-container'].images[runtime]?.driver ?? 'c.driver',
      runtime,
      image: manifest.runs['t8-container'].images[runtime]?.image ?? digest26,
      imageId: `sha256:${'e'.repeat(64)}`,
      code,
      node,
      evidence: folder,
      tapSha256: sha256(tap),
      recordsSha256: read.digest,
      ...host,
    });
  }
  fs.writeFileSync(
    path.join(directory, `7-${'2'.repeat(8)}-2222-2222-2222-${'2'.repeat(12)}.jsonl`),
    lines.map(line => `${JSON.stringify(line)}\n`).join('')
  );
  return directory;
}
const evidence = (manifest, manifestSha256, directory) => {
  const read = readRecords(directory);
  assert.deepEqual(read.problems, []);
  return checkContainerEvidence({
    manifest,
    manifestSha256,
    runId: 'linux-full',
    runtime: '26',
    records: read.records,
    nonce,
    directory,
  });
};

// Codex 2026-10-11 items 3 and 6: container evidence is validated separately, per runtime, from
// the driver's saved inner TAP and records; a Node 24 run does not cover Node 26.
test('container evidence: each runtime of the T8 run needs its own passing inner run; Node 26 is reported missing while it has no image', t => {
  // As tracked today: Node 26 has no approved image, so a host run cannot cover it.
  const today = prepared();
  const directory = containerSetup(t, today.manifest, today.manifestSha256, ['24']);
  assert.deepEqual(evidence(today.manifest, today.manifestSha256, directory).problems, [
    'no T8 container evidence for Node 26: t8-container.images.26 is null (no approved pinned image)',
  ]);
  // A fixture with a synthetic Node 26 image and its own driver: both runtimes covered.
  const both = prepared(m => {
    m.runs['t8-container'].images['26'] = { image: digest26, driver: 'c.driver26' };
    m.entries.push({
      ...entry(
        'c.driver26',
        'test/c.test.mjs',
        ['C driver 26'],
        ['darwin', 'linux'],
        ['linux-full']
      ),
      prerequisites: ['docker'],
    });
  });
  const covered = containerSetup(t, both.manifest, both.manifestSha256, ['24', '26']);
  const result = evidence(both.manifest, both.manifestSha256, covered);
  assert.deepEqual(result.problems, []);
  assert.deepEqual(
    result.evidence.map(item => [item.runtime, item.node, item.image]),
    [
      ['24', 'v24.21.0', digest('a')],
      ['26', 'v26.5.1', digest26],
    ]
  );
  // Node 24 evidence filed as Node 26: a Node 24 child of a Node 26 host does not cover Node 26.
  const mislabelled = containerSetup(t, both.manifest, both.manifestSha256, ['24', '26'], {
    inner: { node: { 26: 'v24.21.0' } },
  });
  const wrong = evidence(both.manifest, both.manifestSha256, mislabelled).problems.join('\n');
  assert.match(wrong, /Node 26 .*: the run inside was Node v24\.21\.0, not Node 26/);
  assert.match(wrong, /Node 26 .*c\.inner .* ran on Node v24\.21\.0, not Node 26/);
  // Only one runtime's evidence.
  const one = containerSetup(t, both.manifest, both.manifestSha256, ['24']);
  assert.match(
    evidence(both.manifest, both.manifestSha256, one).problems.join(),
    /0 T8 container records for Node 26, not one/
  );
});

test('container evidence: a changed inner log or record, another run’s code, the wrong image, and an inner skip, todo or missing test are refused', t => {
  const { manifest, manifestSha256 } = prepared();
  const check = directory => evidence(manifest, manifestSha256, directory).problems.join('\n');
  // Late or changed: the inner TAP or a record edited after the driver recorded their hashes.
  const late = containerSetup(t, manifest, manifestSha256, ['24']);
  const folder = path.join(late, 't8-container-24-ab24xy');
  fs.appendFileSync(path.join(folder, 'inner.tap'), '# added later\n');
  assert.match(check(late), /inner\.tap changed after the driver recorded it/);
  const edited = containerSetup(t, manifest, manifestSha256, ['24']);
  const recordFile = fs.readdirSync(path.join(edited, 't8-container-24-ab24xy', 'records'))[0];
  fs.appendFileSync(path.join(edited, 't8-container-24-ab24xy', 'records', recordFile), '\n');
  assert.match(check(edited), /its records changed after the driver recorded them/);
  // The inner run reported another code than the driver's.
  assert.match(
    check(containerSetup(t, manifest, manifestSha256, ['24'], { inner: { run: 'f'.repeat(64) } })),
    /c\.inner .* is from another run/
  );
  // The host record: another host run, another image, another driver, or the evidence gone.
  assert.match(
    check(containerSetup(t, manifest, manifestSha256, ['24'], { host: { run: 'b'.repeat(64) } })),
    /Node 24 .* is from another run/
  );
  assert.match(
    check(containerSetup(t, manifest, manifestSha256, ['24'], { host: { image: digest('b') } })),
    /ran node:24-bookworm-slim@sha256:b{64}, not node:24-bookworm-slim@sha256:a{64}/
  );
  assert.match(
    check(containerSetup(t, manifest, manifestSha256, ['24'], { host: { id: 'a.linux' } })),
    /names the driver a\.linux, not c\.driver/
  );
  const gone = containerSetup(t, manifest, manifestSha256, ['24']);
  fs.rmSync(path.join(gone, 't8-container-24-ab24xy'), { recursive: true });
  assert.match(check(gone), /its evidence cannot be read \(ENOENT\)/);
  // The run inside: part B's stand-in skipped, todo or missing.
  for (const [nodes, expected] of [
    [
      [{ name: 'helper test' }, { name: 'C inside', directive: 'SKIP no tmpfs' }],
      /"C inside" has the directive SKIP/,
    ],
    [
      [{ name: 'helper test' }, { name: 'C inside', directive: 'TODO' }],
      /"C inside" has the directive TODO/,
    ],
    [[{ name: 'helper test' }], /c\.inner .* has 0 result lines/],
    [
      [{ name: 'helper test' }, { name: 'C inside' }, { name: 'C driver' }],
      /c\.driver .* belongs to darwin, linux, not container/,
    ],
  ])
    assert.match(
      check(
        containerSetup(t, manifest, manifestSha256, ['24'], {
          inner: { tap: { 24: tapOf(nodes) } },
        })
      ),
      expected
    );
  // Two records for one runtime.
  const twice = containerSetup(t, manifest, manifestSha256, ['24']);
  const hostFile = fs.readdirSync(twice).find(name => name.endsWith('.jsonl'));
  fs.appendFileSync(path.join(twice, hostFile), fs.readFileSync(path.join(twice, hostFile)));
  assert.match(check(twice), /2 T8 container records for Node 24, not one/);
});

test('records: only bounded <pid>-<uuid>.jsonl regular files of known records, and the driver’s evidence folders, are read', t => {
  const { manifest, manifestSha256 } = prepared();
  const good = JSON.stringify({
    ...record(manifest, manifestSha256, 'a.linux'),
    source: undefined,
  });
  const name = `9-${'3'.repeat(8)}-3333-3333-3333-${'3'.repeat(12)}.jsonl`;
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, name), `${good}\n`);
  fs.mkdirSync(path.join(directory, 't8-container-24-abcdef'));
  const read = readRecords(directory);
  assert.deepEqual(read.problems, []);
  assert.equal(read.records.length, 1);
  assert.match(read.digest, /^[0-9a-f]{64}$/);
  const problems = (setup, options) => {
    const where = temporary(t);
    setup(where);
    return readRecords(where, options).problems.join('\n');
  };
  assert.match(
    problems(where => fs.writeFileSync(path.join(where, 'notes.txt'), '')),
    /holds "notes\.txt", which is not a record file/
  );
  assert.match(
    problems(where => fs.symlinkSync('/etc/hosts', path.join(where, name))),
    /which is not a record file/
  );
  assert.match(
    problems(where => fs.mkdirSync(path.join(where, 't8-container-24-abcdef')), {
      containers: false,
    }),
    /which is not a record file/
  );
  assert.match(
    problems(where => fs.mkdirSync(path.join(where, 'evil'))),
    /holds "evil"/
  );
  const line = text => problems(where => fs.writeFileSync(path.join(where, name), text));
  assert.match(line(`${good}`), /its last line is incomplete/);
  assert.match(line('not json\n'), /:1: not JSON/);
  assert.match(line(`${good.slice(0, -1)},"id":"a.linux"}\n`), /names "id" twice/);
  assert.match(line(`${good.slice(0, -1)},"extra":1}\n`), /unknown field "extra"/);
  assert.match(line(`${JSON.stringify({ kind: 'note' })}\n`), /has the kind "note"/);
  for (const [field, value, expected] of [
    ['run', 'x', /run that is not 64 lowercase hex digits/],
    ['manifest', 'x', /manifest hash that is not a sha256/],
    ['id', 'A B', /invalid id/],
    ['node', '26.5.1', /invalid node version/],
    ['file', '../x.test.mjs', /invalid file/],
    ['name', ['a # b'], /invalid name path/],
    ['platform', 'windows', /unknown platform/],
    ['result', 'passed', /unknown result/],
  ])
    assert.match(
      line(`${JSON.stringify({ ...JSON.parse(good), [field]: value })}\n`),
      expected,
      field
    );
  assert.match(line(`${'x'.repeat(65 * 1024)}\n`), /longer than 65536 bytes/);
  assert.match(line('x'.repeat(1024 * 1024 + 1)), /larger than 1048576 bytes/);
  const container = {
    kind: 'container',
    run: nonce,
    manifest: manifestSha256,
    id: 'c.driver',
    runtime: '24',
    image: digest('a'),
    imageId: `sha256:${'e'.repeat(64)}`,
    code,
    node: 'v24.21.0',
    evidence: 't8-container-24-abcdef',
    tapSha256: 'a'.repeat(64),
    recordsSha256: 'b'.repeat(64),
  };
  assert.equal(line(`${JSON.stringify(container)}\n`), '');
  for (const [field, value, expected] of [
    ['runtime', '25', /unknown runtime/],
    ['image', 'node:24-bookworm-slim', /image that is not pinned/],
    ['imageId', 'e'.repeat(64), /invalid image id/],
    ['code', 'C'.repeat(64), /code that is not 64 lowercase hex digits/],
    ['evidence', '../elsewhere', /invalid evidence folder/],
    ['tapSha256', 'x', /invalid sha256/],
  ])
    assert.match(line(`${JSON.stringify({ ...container, [field]: value })}\n`), expected, field);
  // Not a directory, or a link to one.
  const link = path.join(temporary(t), 'link');
  fs.symlinkSync(directory, link);
  assert.match(readRecords(link).problems.join(), /not a directory \(or is a link\)/);
  assert.match(readRecords(path.join(directory, 'gone')).problems.join(), /cannot be read: ENOENT/);
});

// Codex 2026-10-11 item 4: a removed or narrowed entry or run is a loss that only an exact, bound
// disposition excuses. coverageLoss judges against one baseline, which must exist: a missing
// parent manifest is not a maintenance branch (verify-1's hole; judgeCandidateManifest below).
test('coverage loss: removed or narrowed entries and runs, another pinned image or driver, and a dropped prerequisite are losses; additions are not; a deleted manifest loses everything', () => {
  const parent = prepared().manifest;
  const losses = change => {
    const candidate = structuredClone(parent);
    change(candidate);
    return coverageLoss(parent, candidate).losses.map(loss => loss.key);
  };
  assert.deepEqual(
    losses(() => {}),
    []
  );
  const find = (manifest, id) => manifest.entries.find(item => item.id === id);
  const cases = [
    [m => (m.entries = m.entries.filter(item => item.id !== 'a.linux')), ['entry:a.linux']],
    [m => (find(m, 'a.linux').file = 'test/b.test.mjs'), ['entry:a.linux:file']],
    [m => (find(m, 'a.linux').name = ['A on Linux, renamed']), ['entry:a.linux:name']],
    [m => (find(m, 'c.driver').platforms = ['linux']), ['entry:c.driver:platform:darwin']],
    [m => (find(m, 'a.linux').runtimes = ['26']), ['entry:a.linux:runtime:24']],
    [m => (find(m, 'a.darwin').evidence = []), ['entry:a.darwin:evidence:darwin-platform']],
    [m => (find(m, 'c.driver').prerequisites = []), ['entry:c.driver:prerequisite:docker']],
    [m => delete m.runs['darwin-platform'], ['run:darwin-platform']],
    [m => (m.runs['linux-full'].platform = 'darwin'), ['run:linux-full:platform']],
    [m => (m.runs['linux-full'].runtimes = ['26']), ['run:linux-full:runtime:24']],
    [m => (m.runs['linux-full'].requiredFor = ['commit']), ['run:linux-full:requiredFor:release']],
    [
      m => (m.runs['linux-full'].files = ['test/a.test.mjs', 'test/b.test.mjs']),
      ['run:linux-full:file:test/c.test.mjs'],
    ],
    [m => (m.runs['t8-container'].images['24'] = null), ['run:t8-container:image:24']],
    // verify-1: another digest, or another driver, is not the reviewed evidence.
    [m => (m.runs['t8-container'].images['24'].image = digest('b')), ['run:t8-container:image:24']],
    [m => (m.runs['t8-container'].images['24'].driver = 'a.linux'), ['run:t8-container:image:24']],
    [m => (m.runs['t8-container'].hostRuns = []), ['run:t8-container:hostRun:linux-full']],
  ];
  for (const [change, expected] of cases)
    assert.deepEqual(losses(change), expected, expected.join());
  const everything = structuredClone(parent);
  everything.runs['linux-full'].files = 'all';
  const narrowed = structuredClone(everything);
  narrowed.runs['linux-full'].files = ['test/a.test.mjs'];
  assert.deepEqual(
    coverageLoss(everything, narrowed).losses.map(loss => loss.key),
    ['run:linux-full:files']
  );
  // Additions lose nothing: a platform, a runtime, an evidence run, a prerequisite, a new entry
  // or run, "all", an image where there was none.
  assert.deepEqual(
    losses(m => {
      find(m, 'a.linux').platforms = ['darwin', 'linux'];
      find(m, 'a.linux').evidence = ['darwin-platform', 'linux-full'];
      find(m, 'a.linux').prerequisites = ['non-root'];
      m.entries.push(entry('a.new', 'test/a.test.mjs', ['A new'], ['linux'], ['linux-full']));
      m.runs['linux-full'].files = 'all';
      m.runs['t8-container'].images['26'] = { image: digest26, driver: 'c.driver26' };
    }),
    []
  );
  // A candidate whose manifest is deleted (or unusable, so read as none) loses everything, and
  // no disposition excuses that.
  const deleted = coverageLoss(parent, null, [{ loss: 'run:darwin-platform' }]);
  assert.deepEqual(
    deleted.losses.map(loss => loss.key),
    [
      'run:darwin-platform',
      'run:linux-full',
      'run:t8-container',
      'entry:a.linux',
      'entry:a.darwin',
      'entry:b.linux',
      'entry:c.inner',
      'entry:c.driver',
    ]
  );
  assert.ok(deleted.losses.every(loss => !loss.excused));
  assert.deepEqual(deleted.problems, [
    'the candidate has no usable manifest: it loses every entry and run, and no disposition excuses that',
  ]);
  // verify-1's hole: a parent whose manifest a commit made without the guard deleted gave "no
  // loss". A missing baseline is now a problem, never "nothing to lose".
  for (const candidate of [null, parent])
    assert.deepEqual(coverageLoss(null, candidate), {
      losses: [],
      problems: [
        'there is no baseline manifest to judge the candidate against: a parent without one is not a maintenance branch (judgeCandidateManifest decides that from the history)',
      ],
    });
});

test('coverage loss: only one exact disposition per loss, bound to the candidate’s tree and complete ordered parent vector, excuses it; a new test excuses nothing', () => {
  const parent = prepared().manifest;
  const candidate = structuredClone(parent);
  candidate.entries = candidate.entries.filter(item => item.id !== 'a.linux');
  candidate.entries.push(
    entry('a.replacement', 'test/a.test.mjs', ['A on Linux, rewritten'], ['linux'], ['linux-full'])
  );
  // The candidate's tree and complete ordered parent vector (GATE-CONTRACT v3 C18).
  const binding = { tree: '1'.repeat(40), parents: ['2'.repeat(40), '4'.repeat(40)] };
  const old = parent.entries.find(item => item.id === 'a.linux');
  const disposition = {
    loss: 'entry:a.linux',
    old,
    replacement: 'a.replacement',
    reason: 'rewritten as a.replacement, which checks the same files',
    reviewer: 'Codex',
    reference: 'room message 20261012T000000Z',
    ...binding,
  };
  // A new test alone does not excuse the removal.
  assert.deepEqual(coverageLoss(parent, candidate, [], binding).losses, [
    { key: 'entry:a.linux', old, what: 'entry a.linux was removed', excused: false },
  ]);
  const excused = coverageLoss(parent, candidate, [disposition], binding);
  assert.deepEqual(excused.problems, []);
  assert.equal(excused.losses[0].excused, true);
  const refused = (change, expected) => {
    const result = coverageLoss(parent, candidate, [change(structuredClone(disposition))], binding);
    assert.equal(result.losses[0].excused, false, `${expected}`);
    assert.match(result.problems.join('\n'), expected);
  };
  const unbound = /not bound to this candidate's tree and complete ordered parent vector/;
  refused(d => ({ ...d, tree: '3'.repeat(40) }), unbound);
  // The same tree and first parent with another additional parent, a reordered, shorter or
  // longer vector: each is another candidate.
  refused(d => ({ ...d, parents: ['2'.repeat(40), '3'.repeat(40)] }), unbound);
  refused(d => ({ ...d, parents: ['4'.repeat(40), '2'.repeat(40)] }), unbound);
  refused(d => ({ ...d, parents: ['2'.repeat(40)] }), unbound);
  refused(d => ({ ...d, parents: [...d.parents, '3'.repeat(40)] }), unbound);
  refused(d => ({ ...d, parents: [['2'.repeat(40)], '4'.repeat(40)] }), unbound);
  // A disposition bound to a single parent is the earlier form, which gives no authority.
  refused(({ parents, ...d }) => ({ ...d, parent: parents[0] }), /has the unknown field "parent"/);
  refused(d => ({ ...d, reviewer: ' ' }), /needs a reason, a reviewer and an evidence reference/);
  refused(d => ({ ...d, reason: 'x\ny' }), /needs a reason, a reviewer and an evidence reference/);
  refused(
    d => ({ ...d, loss: 'entry:a.darwin' }),
    /names "entry:a\.darwin", which this candidate does not lose/
  );
  refused(d => ({ ...d, loss: '*' }), /names "\*", which this candidate does not lose/);
  refused(d => ({ ...d, old: { ...d.old, evidence: [] } }), /its old entry is not the baseline's/);
  refused(
    d => ({ ...d, replacement: 'a.nothing' }),
    /its replacement "a\.nothing" is not an entry of the candidate/
  );
  refused(d => ({ ...d, approved: true }), /has the unknown field "approved"/);
  refused(d => {
    delete d.tree;
    return d;
  }, /lacks tree/);
  // Without a binding (the gate did not give the tree and parents) nothing is excused, and a
  // binding with a single parent is no binding.
  assert.match(coverageLoss(parent, candidate, [disposition], {}).problems.join(), /not bound/);
  assert.match(
    coverageLoss(parent, candidate, [disposition], {
      tree: binding.tree,
      parent: '2'.repeat(40),
    }).problems.join(),
    /not bound/
  );
  // A second disposition for the same loss, and more than 500, are refused.
  assert.match(
    coverageLoss(parent, candidate, [disposition, disposition], binding).problems.join(),
    /entry:a\.linux already has a disposition/
  );
  assert.match(
    coverageLoss(parent, candidate, Array(501).fill(disposition), binding).problems.join(),
    /at most 500/
  );
});

// verify-1's hole and its repair: the candidate is judged against the manifests of its history,
// back to the last commit the gate approved on each path, so a commit made without the guard
// (--no-verify, or git revert, cherry-pick or rebase, which run no pre-commit hook) can neither
// delete nor weaken the manifest unnoticed. B35: a branch whose history never held a manifest
// (maintenance) still loses nothing and needs no platform run.
const commitId = n => n.toString(16).padStart(40, '0');
/**
 * A linear history, oldest first: each item { manifest: text or null, reviewed: true, false or
 * 'other' (a finalization that judged another manifest) }. Returns { heads, history }.
 */
function linear(...items) {
  const history = items.map(({ manifest = null, reviewed = false }, index) => ({
    commit: commitId(index + 1),
    parents: index ? [commitId(index)] : [],
    manifest,
    reviewed:
      reviewed === true
        ? { manifestSha256: manifest === null ? null : sha256(manifest) }
        : reviewed === 'other'
          ? { manifestSha256: 'f'.repeat(64) }
          : null,
  }));
  return { heads: [commitId(items.length)], history };
}
const manifestText = (change = () => {}) => {
  const manifest = fixture();
  change(manifest);
  return JSON.stringify(manifest, null, 2);
};
const withoutALinux = m => (m.entries = m.entries.filter(item => item.id !== 'a.linux'));
const judgeBinding = { tree: '1'.repeat(40), parents: [commitId(2)] };

test('history: a maintenance branch (no manifest anywhere behind it) loses nothing and needs no platform run; the first manifest loses nothing', () => {
  const maintenance = linear({ reviewed: true }, {});
  assert.deepEqual(judgeCandidateManifest({ candidate: null, ...maintenance }), {
    kind: 'maintenance',
    manifest: null,
    sha256: null,
    baselines: [],
    losses: [],
    problems: [],
  });
  // A root commit: no parents, no history.
  assert.equal(judgeCandidateManifest({ heads: [], history: [] }).kind, 'maintenance');
  assert.match(
    judgeCandidateManifest({ candidate: null, ...maintenance, dispositions: [{}] }).problems.join(),
    /no commit behind the candidate holds a manifest: nothing can be lost/
  );
  const introduction = judgeCandidateManifest({ candidate: manifestText(), ...maintenance });
  assert.equal(introduction.kind, 'introduction');
  assert.deepEqual(introduction.problems, []);
  assert.equal(introduction.sha256, sha256(manifestText()));
  assert.match(
    judgeCandidateManifest({ candidate: '{"schemaVersion": 1', ...maintenance }).problems.join(),
    /the manifest is not JSON/
  );
});

test('history: a manifest deleted, broken or weakened by a commit made without the guard is judged against the last approved one', () => {
  const full = manifestText();
  const weak = manifestText(withoutALinux);
  const judge = (parentManifest, candidate, extra = {}) =>
    judgeCandidateManifest({
      candidate,
      ...linear({ manifest: full, reviewed: true }, { manifest: parentManifest }),
      binding: judgeBinding,
      ...extra,
    });
  // Deleted: the candidate without a manifest is refused, whatever its dispositions say.
  for (const parentManifest of [null, '{"schemaVersion": 1', ''])
    for (const dispositions of [[], [{ loss: 'run:linux-full' }]]) {
      const deleted = judge(parentManifest, null, { dispositions });
      assert.equal(deleted.kind, 'manifest');
      assert.match(
        deleted.problems.join('\n'),
        /the candidate has no test\/platform-manifest\.json, which a commit behind it holds: that removes every platform run, and no disposition excuses it/
      );
      assert.ok(deleted.losses.length > 0 && deleted.losses.every(loss => !loss.excused));
    }
  // An unusable candidate manifest is refused the same way.
  assert.match(
    judge(null, '[]').problems.join('\n'),
    /the candidate's test\/platform-manifest\.json is not usable, and a commit behind it holds one/
  );
  // The approved manifest restored: nothing lost, and the approved commit is the baseline.
  const restored = judge(null, full);
  assert.deepEqual(restored.problems, []);
  assert.deepEqual(restored.losses, []);
  assert.deepEqual(restored.baselines, [
    { sha256: sha256(full), commits: [commitId(1)], reviewed: true, sources: ['reviewed'] },
  ]);
  // Weakened by the parent (valid, but without a.linux): the loss against the approved manifest
  // stands, and only a bound disposition excuses it.
  const weakened = judge(weak, weak);
  assert.deepEqual(weakened.problems, []);
  assert.deepEqual(
    weakened.losses.map(loss => [loss.key, loss.baselines, loss.excused]),
    [['entry:a.linux', [sha256(full)], false]]
  );
  const old = fixture().entries.find(item => item.id === 'a.linux');
  const disposition = {
    loss: 'entry:a.linux',
    old,
    replacement: null,
    reason: 'the Linux behaviour is covered elsewhere',
    reviewer: 'Codex',
    reference: 'room message 20261012T000000Z',
    ...judgeBinding,
  };
  const excused = judge(weak, weak, { dispositions: [disposition] });
  assert.deepEqual(excused.problems, []);
  assert.deepEqual(
    excused.losses.map(loss => loss.excused),
    [true]
  );
  // The parent is a baseline too: what it added must be kept.
  const added = manifestText(m =>
    m.entries.push(entry('a.extra', 'test/a.test.mjs', ['A extra'], ['linux'], ['linux-full']))
  );
  assert.deepEqual(
    judge(added, full).losses.map(loss => loss.key),
    ['entry:a.extra']
  );
});

test('history: without a manifest the gate approved, or a baseline disposition, nothing is established and the candidate is refused', () => {
  const full = manifestText();
  const unreviewed = linear({ manifest: full }, { manifest: full });
  const none = judgeCandidateManifest({ candidate: full, ...unreviewed, binding: judgeBinding });
  assert.match(
    none.problems.join('\n'),
    /no reviewed manifest can be established for this candidate/
  );
  // A finalization that judged another manifest does not count, and is a problem itself.
  const other = judgeCandidateManifest({
    candidate: full,
    ...linear({ manifest: full, reviewed: 'other' }, { manifest: full }),
    binding: judgeBinding,
  });
  assert.match(other.problems.join('\n'), /commit 0{39}1: its approval judged the manifest f{64}/);
  assert.match(other.problems.join('\n'), /no reviewed manifest can be established/);
  // A baseline disposition names a commit behind the candidate and its manifest's sha256.
  const baseline = {
    baseline: commitId(1),
    manifestSha256: sha256(full),
    reason: 'the manifest was added in a commit made without the guard; reviewed as it is',
    reviewer: 'Codex',
    reference: 'room message 20261012T000000Z',
    ...judgeBinding,
  };
  const established = judgeCandidateManifest({
    candidate: full,
    ...unreviewed,
    dispositions: [baseline],
    binding: judgeBinding,
  });
  assert.deepEqual(established.problems, []);
  assert.deepEqual(established.baselines, [
    {
      sha256: sha256(full),
      commits: [commitId(2), commitId(1)],
      reviewed: true,
      sources: ['history', 'disposition'],
    },
  ]);
  // A baseline disposition adds a baseline and never removes one: the loss stands.
  assert.deepEqual(
    judgeCandidateManifest({
      candidate: manifestText(withoutALinux),
      ...unreviewed,
      dispositions: [baseline],
      binding: judgeBinding,
    }).losses.map(loss => [loss.key, loss.excused]),
    [['entry:a.linux', false]]
  );
  for (const [change, expected] of [
    [d => ({ ...d, baseline: commitId(9) }), /names "0{39}9", which is not a commit behind/],
    [d => ({ ...d, manifestSha256: 'e'.repeat(64) }), /holds no valid manifest with the sha256/],
    [
      d => ({ ...d, tree: '3'.repeat(40) }),
      /not bound to this candidate's tree and complete ordered parent vector/,
    ],
    [
      d => ({ ...d, parents: [commitId(2), commitId(9)] }),
      /not bound to this candidate's tree and complete ordered parent vector/,
    ],
    [d => ({ ...d, reviewer: '' }), /needs a reason, a reviewer and an evidence reference/],
    [d => ({ ...d, approved: true }), /has the unknown field "approved"/],
  ]) {
    const refused = judgeCandidateManifest({
      candidate: full,
      ...unreviewed,
      dispositions: [change(baseline)],
      binding: judgeBinding,
    }).problems.join('\n');
    assert.match(refused, expected);
    assert.match(refused, /no reviewed manifest can be established/);
  }
  assert.match(
    judgeCandidateManifest({
      candidate: full,
      ...unreviewed,
      dispositions: [baseline, baseline],
      binding: judgeBinding,
    }).problems.join('\n'),
    /already has a baseline disposition/
  );
  // A commit with no manifest cannot be named as a baseline.
  assert.match(
    judgeCandidateManifest({
      candidate: full,
      ...linear({}, { manifest: full }),
      dispositions: [{ ...baseline, baseline: commitId(1) }],
      binding: judgeBinding,
    }).problems.join('\n'),
    /commit 0{39}1 holds no valid manifest/
  );
});

test('history: an approved commit ends its path, every parent of a merge counts, and malformed or incomplete history is refused', () => {
  const full = manifestText();
  const extra = manifestText(m =>
    m.entries.push(entry('a.extra', 'test/a.test.mjs', ['A extra'], ['linux'], ['linux-full']))
  );
  // Behind an approved commit nothing counts: its approval judged that history.
  const behind = judgeCandidateManifest({
    candidate: full,
    ...linear({ manifest: extra }, { manifest: full, reviewed: true }),
  });
  assert.deepEqual(behind.problems, []);
  assert.deepEqual(behind.losses, []);
  // A merge: each parent's history counts, so the candidate keeps both sides' coverage.
  const history = [
    {
      commit: commitId(1),
      parents: [],
      manifest: full,
      reviewed: { manifestSha256: sha256(full) },
    },
    {
      commit: commitId(2),
      parents: [commitId(1)],
      manifest: extra,
      reviewed: { manifestSha256: sha256(extra) },
    },
    {
      commit: commitId(3),
      parents: [commitId(1)],
      manifest: full,
      reviewed: { manifestSha256: sha256(full) },
    },
  ];
  const merge = judgeCandidateManifest({
    candidate: full,
    heads: [commitId(3), commitId(2)],
    history,
  });
  assert.deepEqual(
    merge.losses.map(loss => [loss.key, loss.baselines]),
    [['entry:a.extra', [sha256(extra)]]]
  );
  // The same loss against two baselines that hold the same old entry is one loss.
  const twice = manifestText(m => (m.runs['darwin-platform'].requiredFor = ['commit', 'release']));
  const shared = judgeCandidateManifest({
    candidate: manifestText(withoutALinux),
    ...linear({ manifest: full, reviewed: true }, { manifest: twice }),
  });
  assert.equal(shared.baselines.length, 2);
  assert.deepEqual(
    shared.losses.filter(loss => loss.key === 'entry:a.linux').map(loss => loss.baselines.length),
    [2]
  );
  // Malformed input fails closed.
  const node = history[0];
  for (const [input, expected] of [
    [{ heads: ['HEAD'], history }, /heads is not a list of at most 16 distinct commit ids/],
    [{ heads: [commitId(1), commitId(1)], history }, /heads is not a list/],
    [{ heads: [commitId(1)], history: {} }, /history is not a list/],
    [{ heads: [commitId(1)], history, dispositions: {} }, /dispositions is not a list/],
    [{ heads: [commitId(1)], history, candidate: {} }, /neither bytes nor null/],
    [{ heads: [commitId(1)], history: [node, node] }, /commit 0{39}1 is given twice/],
    [{ heads: [commitId(1)], history: [{ ...node, note: 1 }] }, /unknown field "note"/],
    [{ heads: [commitId(1)], history: [{ ...node, parents: ['x'] }] }, /parents is not a list/],
    [{ heads: [commitId(1)], history: [{ ...node, manifest: 7 }] }, /manifest is neither/],
    [
      { heads: [commitId(1)], history: [{ ...node, reviewed: true }] },
      /reviewed is neither null nor/,
    ],
    [
      { heads: [commitId(1)], history: [{ ...node, reviewed: { manifestSha256: 'x' } }] },
      /reviewed is neither null nor/,
    ],
  ])
    assert.match(
      judgeCandidateManifest({ candidate: full, ...input }).problems.join('\n'),
      expected,
      `${expected}`
    );
  // A commit the parents reach but the history lacks: refused, also on what looks like
  // maintenance.
  for (const manifest of [full, null])
    assert.match(
      judgeCandidateManifest({
        candidate: manifest,
        heads: [commitId(2)],
        history: [{ ...node, commit: commitId(2), parents: [commitId(1)], manifest }],
      }).problems.join('\n'),
      /the history lacks commit 0{39}1, which the candidate's parents reach/
    );
});

test('the command line: exit 0 for a covering run, 1 with every problem for one that is not, 2 for a usage error', t => {
  const directory = temporary(t);
  const { manifest, manifestSha256 } = prepared();
  const manifestFile = path.join(directory, 'platform-manifest.json');
  fs.writeFileSync(manifestFile, JSON.stringify(fixture()));
  assert.equal(sha256(fs.readFileSync(manifestFile)), manifestSha256);
  const records = path.join(directory, 'records');
  fs.mkdirSync(records);
  fs.writeFileSync(
    path.join(records, `5-${'4'.repeat(8)}-4444-4444-4444-${'4'.repeat(12)}.jsonl`),
    linuxRecords(manifest, manifestSha256)
      .map(({ source, ...item }) => `${JSON.stringify(item)}\n`)
      .join('')
  );
  // The container evidence the driver leaves (Node 24 only: Node 26 has no image here).
  const tap = path.join(directory, 'run.tap');
  fs.writeFileSync(tap, tapOf(linuxNodes()));
  const run = (...extra) =>
    spawnSync(
      process.execPath,
      [
        script,
        '--manifest',
        manifestFile,
        '--run',
        'linux-full',
        '--runtime',
        '26',
        '--tap',
        tap,
        '--records',
        records,
        '--nonce',
        nonce,
        ...extra,
      ],
      { encoding: 'utf8', timeout: 30000 }
    );
  const missing = run('--json');
  assert.equal(missing.status, 1, missing.stderr);
  const report = JSON.parse(missing.stdout);
  assert.deepEqual(report.problems, [
    '0 T8 container records for Node 24, not one',
    'no T8 container evidence for Node 26: t8-container.images.26 is null (no approved pinned image)',
  ]);
  assert.equal(report.manifestSha256, manifestSha256);
  // With no container run in the contract the same run covers it.
  const plain = fixture();
  delete plain.runs['t8-container'];
  plain.entries = plain.entries.filter(item => item.id !== 'c.inner');
  fs.writeFileSync(manifestFile, JSON.stringify(plain));
  fs.writeFileSync(
    path.join(records, `5-${'4'.repeat(8)}-4444-4444-4444-${'4'.repeat(12)}.jsonl`),
    linuxRecords(manifest, sha256(fs.readFileSync(manifestFile)))
      .map(({ source, ...item }) => `${JSON.stringify(item)}\n`)
      .join('')
  );
  const passing = run();
  assert.equal(passing.status, 0, passing.stderr);
  assert.match(
    passing.stdout,
    /^✔ run linux-full on Node 26 covers the platform contract \(3 required entries\)/
  );
  const failing = run('--runtime-x');
  assert.equal(failing.status, 2);
  for (const argv of [
    [],
    ['--run'],
    ['--run', 'a', '--run', 'b'],
    ['--json', '--json'],
    ['--tap', 'x'],
  ])
    assert.throws(() => parseArguments(argv), /required|unexpected argument/, JSON.stringify(argv));
  assert.deepEqual(
    parseArguments([
      '--run',
      'r',
      '--runtime',
      '24',
      '--tap',
      't',
      '--records',
      'd',
      '--nonce',
      'n',
      '--json',
    ]),
    { json: true, run: 'r', runtime: '24', tap: 't', records: 'd', nonce: 'n' }
  );
  // A missing TAP file is a problem, not a pass.
  const gone = spawnSync(
    process.execPath,
    [
      script,
      '--manifest',
      manifestFile,
      '--run',
      'linux-full',
      '--runtime',
      '26',
      '--tap',
      path.join(directory, 'gone.tap'),
      '--records',
      records,
      '--nonce',
      nonce,
    ],
    { encoding: 'utf8', timeout: 30000 }
  );
  assert.equal(gone.status, 1);
  assert.match(gone.stderr, /ENOENT/);
});
