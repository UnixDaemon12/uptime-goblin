import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { declareGit } from './helpers/git.mjs';
import { syntheticAuthority } from './helpers/dispatch-authority.mjs';

// The fixture is a Git repository, and the gate runs Git.
const gitSkip = declareGit();

test('the gate isolates Trivy from inherited preferences and candidate suppression files', t => {
  if (gitSkip) return t.skip(gitSkip);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-scanner-isolation-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const repository = path.join(scratch, 'repository'),
    bin = path.join(scratch, 'bin'),
    capture = path.join(scratch, 'calls.jsonl');
  fs.mkdirSync(repository);
  fs.mkdirSync(bin);
  const write = (file, contents, mode = 0o644) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents, { mode });
  };
  const git = (...args) =>
    execFileSync('git', ['-C', repository, ...args], { encoding: 'utf8', stdio: 'pipe' }).trim();
  git('init', '--quiet');
  for (const name of [
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
  ])
    write(
      path.join(repository, 'scripts', name),
      fs.readFileSync(fileURLToPath(new URL(`../scripts/${name}`, import.meta.url)))
    );
  // The scan builds and scans the candidate's image only with the pre-dispatch barrier open (so
  // candidate-policy must pass: a canonical package.json with the lint commands) and with a
  // synthetic authority for the build, which replaces the repository's
  // scripts/security-authority.mjs (it gives none) in this throwaway fixture. Without them the scan
  // dispatches no Docker command at all (test/security-dispatch.test.mjs).
  write(
    path.join(repository, 'package.json'),
    `${JSON.stringify(
      {
        scripts: {
          'lint:sql': 'node scripts/sql-lint.mjs',
          'lint:imports': 'node scripts/import-graph.mjs',
        },
      },
      null,
      2
    )}\n`
  );
  write(path.join(repository, 'scripts/security-authority.mjs'), syntheticAuthority('all'));
  write(path.join(repository, 'Dockerfile'), `FROM synthetic@sha256:${'0'.repeat(64)}\n`);
  write(path.join(repository, 'trivy.yaml'), 'severity: [UNKNOWN]\n');
  write(path.join(repository, '.trivyignore'), 'DS-0002\n');
  write(path.join(repository, 'trivy-secret.yaml'), 'enable-builtin-rules: [synthetic-only]\n');
  write(
    path.join(repository, 'scripts/security-tools.json'),
    JSON.stringify({
      gitleaks: '0.0.0',
      trivy: '0.0.0',
      actionlint: '0.0.0',
      semgrepRulesCommit: 'a'.repeat(40),
      semgrepRulesSha256: 'b'.repeat(64),
    })
  );
  // CLI fixtures record the real gate's process boundary; they are not security scanners.
  // The rules download fails deliberately: this is never a passing security-gate record.
  const cli = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const command = path.basename(process.argv[1]);
const args = process.argv.slice(2);
if (command === 'curl') process.exit(1);
if (command === 'trivy') {
  const policies = {};
  for (const flag of ['--config', '--ignorefile', '--secret-config']) {
    const at = args.indexOf(flag);
    if (at !== -1) policies[flag] = { path: args[at + 1], contents: fs.readFileSync(args[at + 1], 'utf8') };
  }
  fs.appendFileSync(process.env.ORBIT_SCANNER_CAPTURE, JSON.stringify({
    args, policies, cwd: process.cwd(),
    preferences: Object.keys(process.env).filter(key => key.toUpperCase().startsWith('TRIVY_')),
  }) + '\\n');
}
if (args.includes('--version') || args[0] === 'version') console.log('0.0.0');
`;
  for (const name of ['npm', 'docker', 'gitleaks', 'trivy', 'actionlint', 'curl'])
    write(path.join(bin, name), cli, 0o755);
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
    'Synthetic scanner isolation fixture'
  );
  const env = {
    ...process.env,
    PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    ORBIT_SCANNER_CAPTURE: capture,
    TRIVY_SEVERITY: 'UNKNOWN',
    TRIVY_SKIP_FILES: 'Dockerfile',
    TRIVY_CONFIG: path.join(repository, 'trivy.yaml'),
    TRIVY_SECRET_CONFIG: path.join(repository, 'trivy-secret.yaml'),
    TRIVY_IGNORE_UNFIXED: 'true',
  };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['scripts/security-gate.mjs', 'scan'], {
    cwd: repository,
    encoding: 'utf8',
    timeout: 20000,
    env,
  });
  assert.equal(result.status, 1, 'fixture download failure must never create an approval');
  assert.match(result.stdout, /Security scan: blocked/);
  const calls = fs.readFileSync(capture, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 5, 'version, config, image, SBOM and database metadata are checked');
  for (const call of calls) {
    assert.deepEqual(call.preferences, [], 'ambient Trivy settings cannot narrow a scan');
    const config = call.policies['--config'];
    assert.ok(config, 'every invocation explicitly selects the trusted general configuration');
    assert.equal(config.contents, '{}\n');
    assert.ok(
      fs
        .realpathSync(config.path)
        .startsWith(fs.realpathSync(path.join(repository, '.git/orbit-security')) + path.sep),
      'policy stays in private gate evidence, outside the candidate'
    );
    if (!['config', 'image'].includes(call.args[0])) continue;
    const ignored = call.policies['--ignorefile'];
    assert.ok(ignored);
    assert.equal(ignored.contents, '');
    assert.ok(!ignored.path.startsWith(call.cwd + path.sep));
    assert.equal(
      call.args[call.args.indexOf('--severity') + 1],
      'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL'
    );
    if (call.args[0] === 'image') {
      const secrets = call.policies['--secret-config'];
      assert.ok(secrets);
      assert.equal(secrets.contents, '{}\n', 'empty secret policy retains all built-in rules');
      assert.ok(!secrets.path.startsWith(call.cwd + path.sep));
    }
  }
  const image = calls.find(call => call.args.includes('--scanners'));
  assert.equal(image.args[image.args.indexOf('--scanners') + 1], 'vuln,secret');
  assert.equal(image.args[image.args.indexOf('--image-config-scanners') + 1], 'misconfig,secret');

  // An empty external ignore policy does not disable source-level Trivy directives.
  // Check the actual candidate-policy result, not the deliberately blocked download stage.
  for (const file of ['Dockerfile', 'deployment.yaml']) {
    const original = file === 'Dockerfile' ? fs.readFileSync(path.join(repository, file)) : null;
    write(
      path.join(repository, file),
      file === 'Dockerfile'
        ? `FROM synthetic@sha256:${'0'.repeat(64)}\n#trivy:ignore:AVD-DS-0002\nUSER root\n`
        : '# trivy:ignore:KSV018\nkind: Pod\n'
    );
    git('add', file);
    const blocked = spawnSync(process.execPath, ['scripts/security-gate.mjs', 'scan'], {
      cwd: repository,
      encoding: 'utf8',
      timeout: 20000,
      env,
    });
    assert.equal(blocked.status, 1);
    const tree = git('write-tree'),
      evidenceDirectory = path.join(repository, '.git/orbit-security'),
      run = fs.readdirSync(evidenceDirectory).find(name => name.startsWith(`${tree}-scan-`)),
      evidence = JSON.parse(fs.readFileSync(path.join(evidenceDirectory, run, 'result.json'))),
      policy = evidence.stages.find(stage => stage.name === 'candidate-policy');
    assert.equal(policy.status, 'blocked', 'inline suppression must block the candidate policy');
    assert.match(policy.error, /Inline Trivy suppression/);
    if (original) fs.writeFileSync(path.join(repository, file), original);
    else fs.unlinkSync(path.join(repository, file));
    git('add', '--all');
  }
});
