import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkDocumentation, requiredDocuments } from '../scripts/check-documentation.mjs';
import { declareGit } from './helpers/git.mjs';

// The fixture of most tests here is a Git repository.
const gitSkip = declareGit();

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-documentation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { stdio: 'pipe' });
  const write = (file, source) => {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), source);
  };
  git('init', '--quiet');
  for (const file of requiredDocuments) write(file, '# Documentation\n');
  write('package.json', JSON.stringify({ version: '1.4.3' }));
  write('CHANGELOG.md', '# Changelog\n\n## 1.4.3 — 2026-09-29\n\nRelease notes.\n');
  write('LICENSE', 'Synthetic test license text.\n');
  git('add', '.');
  git(
    '-c',
    'user.name=Uptime Goblin Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '--quiet',
    '-m',
    'Synthetic documentation fixture'
  );
  git('tag', 'v1.4.3');
  return { root, git, write, check: () => checkDocumentation(root) };
}

test('documentation checks tracked candidate links, images, references, encoding and fragments', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, git, check } = fixture(t);
  write('docs/a guide (draft).md', '# Guide\n');
  write('docs/diagram.svg', '<svg/>');
  write(
    'README.md',
    [
      '# Uptime Goblin',
      '[Security](docs/security.md#policy)',
      '[Wrapped](\n  docs/configuration.md)',
      '[Guide](<docs/a guide (draft).md> "Guide title")',
      '[Encoded](docs/a%20guide%20%28draft%29.md)',
      '[Balanced](docs/a\\ guide\\ (draft).md)',
      '![Diagram](docs/diagram.svg)',
      '[Reference][install]',
      '[install]: docs/installation.md#setup "Install"',
      '[External](https://example.com/absent.md)',
      '[Mail](mailto:security@example.com)',
      '[Protocol relative](//example.com/absent.md)',
      '[Section](#not-checked)',
    ].join('\n')
  );
  write('docs/configuration.md', '[Home](../README.md)\n[License](../LICENSE)\n');
  git('add', '.');
  assert.deepEqual(check().problems, []);
  assert.equal(check().releaseTags, 1);
});

test('documentation ignores fenced and inline examples but checks links after the closing fence', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, check } = fixture(t);
  write(
    'README.md',
    [
      '# Uptime Goblin',
      '```md',
      '[Example](does-not-exist.md)',
      '```',
      '~~~~ markdown',
      '[Another](also-missing.md)',
      '~~~',
      '[Still fenced](still-missing.md)',
      '~~~~',
      '`[Inline](inline-missing.md)` and ``[Backtick ` example](missing.md)``',
      '[Real](docs/security.md)',
    ].join('\n')
  );
  assert.deepEqual(check().problems, []);
  write('README.md', '```md\n[Example](ignored.md)\n```\n[Real](missing.md)\n');
  assert.deepEqual(check().problems, [
    'README.md:4: local link target "missing.md" is missing or untracked.',
  ]);
});

test('documentation includes contributor instructions and nested example guides', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, git, check } = fixture(t);
  for (const file of ['AGENTS.md', 'SECURITY.md', 'examples/nested/README.md'])
    write(file, '[Missing](absent.md)\n');
  git('add', '.');
  const problems = check().problems;
  assert.equal(problems.length, 3);
  for (const file of ['AGENTS.md', 'SECURITY.md', 'examples/nested/README.md'])
    assert.ok(problems.some(problem => problem.startsWith(file + ':1:')));
});

test('documentation detects missing, untracked and removed local files in candidate contents', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, git, root, check } = fixture(t);
  write('docs/new.md', '# New\n');
  write('README.md', '[New](docs/new.md)\n');
  assert.match(check().problems.join('\n'), /docs\/new\.md.*missing or untracked/);
  git('add', 'docs/new.md');
  assert.deepEqual(check().problems, []);
  fs.unlinkSync(path.join(root, 'docs/new.md'));
  assert.match(check().problems.join('\n'), /docs\/new\.md.*missing or untracked/);
  write('README.md', '[Not committed yet](absent.md)\n');
  assert.match(check().problems.join('\n'), /absent\.md.*missing or untracked/);
});

test('documentation refuses escapes and tracked symlinks out of the source tree', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, git, root, check } = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-doc-outside-'));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  fs.writeFileSync(path.join(outside, 'private.txt'), 'Synthetic fixture.');
  fs.symlinkSync(path.join(outside, 'private.txt'), path.join(root, 'outside.txt'));
  git('add', 'outside.txt');
  write(
    'README.md',
    '[Escape](../private.txt)\n[Absolute](/private.txt)\n[Symlink](outside.txt)\n[Encoded](%2E%2E/private.txt)\n'
  );
  const problems = check().problems;
  assert.equal(problems.length, 4);
  assert.equal(problems.filter(problem => problem.includes('outside the source tree')).length, 3);
  assert.match(problems.join('\n'), /outside\.txt.*missing or untracked/);
});

test('all actual semver release tags need headings, including annotated and prerelease tags', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, git, check } = fixture(t);
  git(
    '-c',
    'user.name=Uptime Goblin Fixture',
    '-c',
    'user.email=fixture@example.com',
    'tag',
    '-a',
    'v1.4.2',
    '-m',
    'Earlier release'
  );
  git('tag', '1.3.0');
  git('tag', 'v1.5.0-rc.1');
  git('tag', 'not-a-release');
  assert.equal(check().problems.length, 3);
  assert.match(check().problems.join('\n'), /release tag v1\.4\.2 has no version heading/);
  write('CHANGELOG.md', '# Changelog\n## 1.4.3\n## [v1.4.2] — date\n## 1.3.0\n## 1.5.0-rc.1\n');
  assert.deepEqual(check().problems, []);
  assert.equal(check().releaseTags, 4);
});

test('a release version mention or fenced heading does not replace its changelog heading', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, check } = fixture(t);
  write('CHANGELOG.md', '# Changelog\nCurrent version 1.4.3.\n```md\n## 1.4.3\n```\n');
  const problems = check().problems;
  assert.equal(problems.length, 2);
  assert.match(problems.join('\n'), /release tag v1\.4\.3 has no version heading/);
  assert.match(problems.join('\n'), /package version 1\.4\.3 has no version heading/);
});

test('a new package version must be documented before it has a release tag', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, check } = fixture(t);
  write('package.json', JSON.stringify({ version: '1.4.4' }));
  assert.deepEqual(check().problems, [
    'CHANGELOG.md: package version 1.4.4 has no version heading.',
  ]);
});

test('development versions can be documented under Unreleased without inventing release headings', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { write, check } = fixture(t);
  write('package.json', JSON.stringify({ version: '1.5.0-dev.2' }));
  assert.match(
    check().problems.join('\n'),
    /development package version 1\.5\.0-dev\.2 is not documented/
  );
  write(
    'CHANGELOG.md',
    '# Changelog\n## Unreleased\nDevelopment package: `1.5.0-dev.2`.\n## 1.4.3\n'
  );
  assert.deepEqual(check().problems, []);
  write(
    'CHANGELOG.md',
    '# Changelog\n## Unreleased\nDevelopment package: 1.5.0-dev.2.\n## 1.4.3\n'
  );
  assert.deepEqual(check().problems, []);
  write(
    'CHANGELOG.md',
    '# Changelog\n## Unreleased\nDevelopment package: 1.5.0-dev.20.\n## 1.4.3\n'
  );
  assert.match(check().problems.join('\n'), /development package version/);
});

test('required documents must be tracked, present and nonempty', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { root, write, git, check } = fixture(t);
  write('SECURITY.md', ' \n\t');
  fs.unlinkSync(path.join(root, 'docs/installation.md'));
  git('rm', '--cached', 'CONTRIBUTING.md');
  const problems = check().problems;
  assert.equal(problems.length, 3);
  assert.ok(problems.includes('SECURITY.md: document is empty.'));
  assert.ok(
    problems.includes('docs/installation.md: document is missing or is not a regular file.')
  );
  assert.ok(
    problems.includes('CONTRIBUTING.md: required document is not tracked in the candidate.')
  );
});

test('documentation CLI fails for a shallow checkout and returns nonzero for broken links', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { root, write, git } = fixture(t);
  const script = fileURLToPath(new URL('../scripts/check-documentation.mjs', import.meta.url));
  const run = () => spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
  assert.equal(run().status, 0);
  write('.git/shallow', git('rev-parse', 'HEAD').toString());
  let result = run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires full local Git history/);
  fs.unlinkSync(path.join(root, '.git/shallow'));
  write('README.md', '[Broken](gone.md)\n');
  result = run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gone\.md/);
});

// Node loads the entry module by its real path (or, with --preserve-symlinks-main, by the path
// it was given), so a checker started through a symlink must still compare equal and check.
test('documentation CLI still checks when started through a symlinked directory or file', t => {
  if (gitSkip) return t.skip(gitSkip);
  const { root, write } = fixture(t);
  write('README.md', '[Broken](gone.md)\n');
  const links = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-documentation-links-'));
  t.after(() => fs.rmSync(links, { recursive: true, force: true }));
  const script = fileURLToPath(new URL('../scripts/check-documentation.mjs', import.meta.url));
  fs.symlinkSync(path.dirname(script), path.join(links, 'scripts'), 'dir');
  fs.symlinkSync(script, path.join(links, 'check-documentation.mjs'));
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  delete environment.NODE_OPTIONS;
  for (const linked of [
    path.join(links, 'scripts', 'check-documentation.mjs'),
    path.join(links, 'check-documentation.mjs'),
  ]) {
    for (const options of [{}, { NODE_OPTIONS: '--preserve-symlinks-main' }]) {
      const result = spawnSync(process.execPath, [linked, '--root', root], {
        encoding: 'utf8',
        env: { ...environment, ...options },
      });
      assert.equal(result.status, 1, `${linked} ${JSON.stringify(options)}: ${result.stderr}`);
      assert.match(result.stderr, /gone\.md/);
    }
  }
});

// Imported, the checker does nothing: also through stdin or --eval with an argument that is not
// a file, where a bare real-path comparison of that argument would throw.
for (const mode of ['stdin', 'eval'])
  test(`the documentation check stays inert when imported through ${mode} with a non-file argument`, () => {
    const code = `await import(${JSON.stringify(new URL('../scripts/check-documentation.mjs', import.meta.url).href)});`;
    const environment = { ...process.env };
    delete environment.NODE_TEST_CONTEXT;
    delete environment.NODE_OPTIONS;
    const result = spawnSync(
      process.execPath,
      mode === 'stdin'
        ? ['--input-type=module', '-']
        : ['--input-type=module', '--eval', code, 'not-a-script-file'],
      {
        cwd: os.tmpdir(),
        input: mode === 'stdin' ? code : undefined,
        encoding: 'utf8',
        env: environment,
        timeout: 10000,
      }
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, '');
  });

test('every guide this tree ships or keeps in docs/ is a required document', () => {
  const repository = fileURLToPath(new URL('..', import.meta.url));
  // The in-app guides the installer, Docker image and release install (1.5 adds two).
  const installed = fs
    .readFileSync(path.join(repository, 'deploy/manifest.txt'), 'utf8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => /^docs\/[^/]+\.md$/.test(line));
  assert.ok(installed.includes('docs/authentication.md'));
  assert.ok(installed.includes('docs/notifications.md'));
  const kept = fs
    .readdirSync(path.join(repository, 'docs'))
    .filter(name => name.endsWith('.md'))
    .map(name => `docs/${name}`);
  for (const file of new Set([...installed, ...kept]))
    assert.ok(requiredDocuments.includes(file), `${file} is required`);
});

// The rule inventory says how many of its hash-bound maintenance evidence files differ in this
// tree, in the matrix and in the JSON. Any change to one of those files changes the count, so
// recount here rather than trust the sentence.
test('the rule inventory states how many hash-bound evidence files differ in this tree', () => {
  const repository = fileURLToPath(new URL('..', import.meta.url));
  const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
  const coverage = JSON.parse(read('scripts/security-rule-coverage.json'));
  assert.equal(coverage.schema, 'orbit.security-guidance-documentation.v1');
  const guidance = coverage.guidance;
  assert.equal(guidance.schema, 'orbit.netxeo-guidance-rule.v2');
  assert.equal(guidance.file, 'scripts/security-rule-coverage.rules.jsonl');
  const bytes = fs.readFileSync(path.join(repository, guidance.file));
  assert.equal(bytes.length, guidance.bytes);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), guidance.sha256);
  const rules = bytes.toString('utf8').trimEnd().split('\n').map(JSON.parse);
  assert.equal(rules.length, 1228);
  assert.equal(guidance.rules, rules.length);
  assert.equal(new Set(rules.map(rule => rule.ref)).size, rules.length);
  const holds = {
    candidateApplicability: 'UNASSESSED',
    candidateCompliance: 'UNASSESSED',
    canonicalMapping: 'PENDING',
    runtimeStatus: 'UNASSESSED',
  };
  assert.deepEqual(guidance.statusHolds, holds);
  const dispositions = {};
  const occurrences = [];
  for (const rule of rules) {
    assert.equal(rule.schema, guidance.schema, rule.ref);
    assert.match(rule.ref, /^NXGL2-\d{6}$/);
    assert.equal(rule.fileSha256, undefined, rule.ref);
    for (const [key, value] of Object.entries(holds)) assert.equal(rule[key], value, rule.ref);
    dispositions[rule.disposition] = (dispositions[rule.disposition] ?? 0) + 1;
    occurrences.push(...rule.occurrences.map(occurrence => occurrence.occurrenceId));
  }
  assert.equal(occurrences.length, 1414);
  assert.equal(guidance.occurrences, occurrences.length);
  assert.equal(new Set(occurrences).size, occurrences.length);
  assert.deepEqual(dispositions, {
    EXTRACTED_UNASSESSED: 850,
    ADAPTED_DOCUMENTARY: 298,
    CONFLICT_RETAINED_NOT_AUTHORIZED: 74,
    SOURCE_CONTRADICTION_RECORDED: 6,
  });
  assert.deepEqual(guidance.dispositions, dispositions);
  // Candidate documentation hashes are separate from immutable guidance rows.
  const bound = Object.entries(coverage.documentationAssertions.fileSha256);
  assert.deepEqual(bound.map(([file]) => file).sort(), [
    '.github/dependabot.yml',
    'compose.yaml',
    'docs/security-rule-matrix.md',
    'scripts/security-rule-coverage.rules.jsonl',
  ]);
  // A file this tree no longer has differs too.
  const differ = bound.filter(([file, recorded]) => {
    const absolute = path.join(repository, file);
    if (!fs.existsSync(absolute)) return true;
    return createHash('sha256').update(fs.readFileSync(absolute)).digest('hex') !== recorded;
  });
  const count = `${differ.length} of the ${bound.length} hash-bound documentary evidence files differ`;
  const fix = `update docs/security-rule-matrix.md and documentationAssertions.evidenceDrift: ${count}`;
  const matrix = read('docs/security-rule-matrix.md').replace(/\s+/g, ' ');
  assert.ok(matrix.includes(`Here ${count} from their recorded hashes`), fix);
  assert.ok(
    coverage.documentationAssertions.evidenceDrift.includes(
      `In this tree ${count} from their recorded SHA-256`
    ),
    fix
  );
});

// The inventory was recorded against the maintenance Compose (memory=1g, CPU=2 and PID=256). In
// 1.5 its gaps list and E-CONTAINER said "Current working Compose" sets those, beside a
// compose.yaml with one CPU and uid 1000. They now state what this tree's compose.yaml sets, read
// from the file here, and name the maintenance values as the maintenance Compose's.
test('the rule inventory states the limits and user compose.yaml sets in this tree', () => {
  const repository = fileURLToPath(new URL('..', import.meta.url));
  const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
  const compose = read('compose.yaml');
  const key = name => new RegExp(`^ {4}${name}: '?([0-9][0-9a-z.:]*)'?$`, 'm').exec(compose)?.[1];
  const [memory, cpus, pids, user] = ['mem_limit', 'cpus', 'pids_limit', 'user'].map(key);
  assert.ok(memory && cpus && pids && user, 'compose.yaml names its limits and user');
  assert.equal(key('memswap_limit'), memory, 'no swap on top');
  const sentence = `In this tree \`compose.yaml\` sets memory=${memory} with no swap, CPU=${cpus} and PID=${pids} and runs as \`${user}\``;
  const matrix = read('docs/security-rule-matrix.md').replace(/\s+/g, ' ');
  // Once in the gaps list and once in historical E-CONTAINER; the fresh manifest is separate.
  assert.equal(matrix.split(sentence).length - 1, 2, sentence);
  const scope = JSON.parse(read('scripts/security-rule-coverage.json')).documentationAssertions
    .compose.current;
  assert.ok(scope.includes(sentence), sentence);
  for (const text of [matrix, scope]) assert.doesNotMatch(text, /Current working Compose/);
});

// The gaps list said automated dependency-update configuration was "absent at this snapshot"
// (the maintenance inventory's text, which tooling ported). This tree, 801796a and both HEADs the
// inventory names carry the same .github/dependabot.yml, and the 1.5 column's Dependabot items say
// 1.5 has it. The gaps list now names the file and what it updates, read from the file here.
test('the rule inventory names the dependency-update configuration this tree has', () => {
  const repository = fileURLToPath(new URL('..', import.meta.url));
  const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
  const names = { npm: 'npm', 'github-actions': 'GitHub Actions', docker: 'the Docker base image' };
  const updates = read('.github/dependabot.yml')
    .split(/^ {2}- /m)
    .slice(1);
  assert.deepEqual(
    updates.map(update => /^package-ecosystem: (\S+)$/m.exec(update)?.[1]),
    Object.keys(names)
  );
  for (const update of updates) {
    assert.match(update, /^ {6}interval: weekly$/m);
    assert.match(update, /^ {4}cooldown:$/m);
  }
  const list = Object.values(names);
  const sentence = `This tree has automated dependency-update configuration, \`.github/dependabot.yml\` (${list.slice(0, -1).join(', ')} and ${list.at(-1)}, weekly, with cooldowns)`;
  const matrix = read('docs/security-rule-matrix.md').replace(/\s+/g, ' ');
  assert.equal(matrix.split(sentence).length - 1, 1, sentence);
  assert.doesNotMatch(matrix, /absent at this snapshot/);
  const assertions = JSON.parse(
    read('scripts/security-rule-coverage.json')
  ).documentationAssertions;
  assert.equal(assertions.dependencyUpdates.current, sentence);
  const maintenance =
    "The maintenance column's Dependabot items say no configuration was present in the maintenance candidate inspected; that disposition is maintenance's and is not changed here.";
  assert.equal(assertions.dependencyUpdates.maintenance, maintenance);
  assert.ok(matrix.includes(maintenance), maintenance);
  assert.notEqual(assertions.dependencyUpdates.current, assertions.dependencyUpdates.maintenance);
});

test("the full gate's requirements name the private history input only once the gate passes it", async () => {
  const { testRequire } = await import('../scripts/security-platform.mjs');
  const repository = fileURLToPath(new URL('..', import.meta.url));
  const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
  const guide = read('docs/engineering-quality.md').replace(/\s+/g, ' ');
  const needs = guide.match(/The full gate therefore needs ([^.]*)\./);
  assert.ok(needs, 'docs/engineering-quality.md states what the full gate needs');
  const gatePassesHistory = testRequire.split(',').includes('history');
  // Today the gate strips TEST_HISTORY and does not list history, so its test stages cannot
  // receive the input: the requirement list must not name it, and the guide must say so.
  assert.equal(needs[1].includes('private history input'), gatePassesHistory, needs[1]);
  if (!gatePassesHistory) {
    assert.ok(guide.includes('Passing that input to the gate is not implemented yet'));
    assert.ok(guide.includes("with `history` added to the gate's `TEST_REQUIRE`"));
  }
});
