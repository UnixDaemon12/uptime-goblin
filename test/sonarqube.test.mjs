import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  apiRequest,
  checkSonarQube,
  passesQualityGate,
  readTask,
  readToken,
  scannerImage,
} from '../scripts/check-sonarqube.mjs';
import { declareGit } from './helpers/git.mjs';

// Every fixture() is a Git repository.
const gitSkip = declareGit();

const token = 'synthetic_sonar_fixture_token_only';
const passingGate = () => ({
  status: 'OK',
  ignoredConditions: false,
  conditions: [
    {
      status: 'OK',
      metricKey: 'vulnerabilities',
      comparator: 'GT',
      errorThreshold: '0',
      actualValue: '0',
    },
    { status: 'OK', metricKey: 'bugs', comparator: 'GT', errorThreshold: '0', actualValue: '0' },
    {
      status: 'OK',
      metricKey: 'security_hotspots_reviewed',
      comparator: 'LT',
      errorThreshold: '100',
      actualValue: '100.0',
    },
    {
      status: 'OK',
      metricKey: 'security_rating',
      comparator: 'GT',
      errorThreshold: '1',
      actualValue: '1.0',
    },
    {
      status: 'OK',
      metricKey: 'reliability_rating',
      comparator: 'GT',
      errorThreshold: '1',
      actualValue: '1',
    },
  ],
});
function fixture(t, options = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-sonar-test-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const root = path.join(fs.realpathSync(temporary), 'source');
  const evidenceDirectory = path.join(fs.realpathSync(temporary), 'evidence');
  const tokenFile = path.join(fs.realpathSync(temporary), 'token');
  fs.mkdirSync(root);
  fs.mkdirSync(evidenceDirectory, { mode: 0o700 });
  fs.writeFileSync(tokenFile, token + '\n', { mode: 0o600 });
  fs.writeFileSync(path.join(root, 'server.mjs'), '// Synthetic source, never run.\n');
  fs.copyFileSync(
    new URL('../sonar-project.properties', import.meta.url),
    path.join(root, 'sonar-project.properties')
  );
  const git = (...args) => {
    const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
    // A Git that cannot start leaves stderr empty; its error says why.
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    return result.stdout.trim();
  };
  git('init', '--quiet');
  git('add', '.');
  git(
    '-c',
    'core.hooksPath=/dev/null',
    '-c',
    'user.name=Orbit Fixture',
    '-c',
    'user.email=fixture@example.com',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '--quiet',
    '-m',
    'Synthetic source'
  );
  const calls = [];
  const run = (command, args, settings) => {
    if (command === 'git') return spawnSync(command, args, { encoding: 'utf8' });
    assert.equal(command, 'docker');
    if (args[0] === 'network')
      return { status: 0, stdout: options.networkInternal === false ? 'false' : 'true' };
    calls.push({ args, settings });
    if (args[0] === 'rm') return { status: 0, stdout: '', stderr: '' };
    if (options.scanThrow) throw new Error(token);
    const directory = path.join(evidenceDirectory, 'sonarqube');
    if (options.produceTask !== false)
      fs.writeFileSync(
        path.join(directory, 'report-task.txt'),
        options.taskText ??
          'projectKey=orbit-homelab\nserverUrl=http://sonarqube:9000\nceTaskId=task-fixture\n'
      );
    options.mutate?.(root);
    return {
      status: options.scanExit ?? 0,
      error: options.scanError,
      stdout: 'scanner output ' + token + '\n',
      stderr: 'Basic ' + Buffer.from(token + ':').toString('base64') + '\n',
    };
  };
  const requests = [];
  const request = async (endpoint, suppliedToken) => {
    assert.equal(suppliedToken, token);
    requests.push(endpoint);
    if (options.requestThrow) throw new Error(token);
    if (endpoint === '/api/system/status')
      return options.system ?? { status: 'UP', version: '26.9.0.1' };
    if (endpoint === '/api/ce/task?id=task-fixture')
      return {
        task: options.task ?? {
          id: 'task-fixture',
          componentKey: 'orbit-homelab',
          status: 'SUCCESS',
          analysisId: 'analysis-fixture',
        },
      };
    assert.equal(endpoint, '/api/qualitygates/project_status?analysisId=analysis-fixture');
    return {
      projectStatus: options.quality ?? passingGate(),
    };
  };
  return {
    root,
    evidenceDirectory,
    tokenFile,
    calls,
    requests,
    git,
    check: () => checkSonarQube({ root, evidenceDirectory, tokenFile, run, request }),
  };
}

test('SonarQube binds exact analysis to source identity and keeps credentials out of arguments/evidence', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  const result = await f.check();
  assert.equal(result.status, 'pass');
  assert.equal(result.source.tree, f.git('write-tree'));
  assert.equal(result.source.parent, f.git('rev-parse', 'HEAD'));
  assert.deepEqual(result.sourceAfter, result.source);
  assert.equal(result.analysisId, 'analysis-fixture');
  assert.equal(result.computation.status, 'SUCCESS');
  assert.equal(result.qualityGate.conditions[0].actualValue, '0');
  assert.equal(result.scannerImage, scannerImage);
  const scan = f.calls[0];
  assert.equal(scan.settings.env.SONAR_TOKEN, token);
  assert.ok(scan.args.includes('SONAR_TOKEN'));
  assert.ok(!JSON.stringify(scan.args).includes(token));
  for (const required of [
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--memory=3g',
    '--cpus=2',
    '--pids-limit=512',
    'orbit-quality',
    'linux/amd64',
  ])
    assert.ok(scan.args.includes(required), required);
  assert.ok(scan.args.includes(`type=bind,src=${f.root},dst=/usr/src,readonly`));
  assert.ok(scan.args.includes('SONAR_USER_HOME=/tmp/sonar'));
  assert.deepEqual(f.calls[1].args.slice(0, 2), ['rm', '--force']);
  for (const file of ['result.json', 'scanner.log']) {
    const output = fs.readFileSync(path.join(result.directory, file), 'utf8');
    assert.ok(!output.includes(token));
    assert.ok(!output.includes(Buffer.from(token + ':').toString('base64')));
    assert.equal(fs.statSync(path.join(result.directory, file)).mode & 0o077, 0);
  }
});

for (const [name, options, reason] of [
  ['server is starting', { system: { status: 'STARTING', version: '26.9' } }, /not ready/],
  [
    'scanner network permits external access',
    { networkInternal: false },
    /must exist and be internal/,
  ],
  ['server version is absent', { system: { status: 'UP' } }, /not ready/],
  ['server errors contain credentials', { requestThrow: true }, /could not complete safely/],
  ['scanner omits its task', { produceTask: false }, /analysis metadata/],
  ['scanner fails despite a green server result', { scanExit: 1 }, /scanner did not exit/],
  [
    'scanner times out despite complete metadata',
    { scanError: { code: 'ETIMEDOUT' } },
    /scanner did not exit/,
  ],
  ['scanner throws', { scanThrow: true }, /could not complete safely/],
  [
    'computation fails',
    { task: { id: 'task-fixture', componentKey: 'orbit-homelab', status: 'FAILED' } },
    /computation/,
  ],
  [
    'computation is pending',
    { task: { id: 'task-fixture', componentKey: 'orbit-homelab', status: 'PENDING' } },
    /computation/,
  ],
  [
    'analysis ID is missing',
    { task: { id: 'task-fixture', componentKey: 'orbit-homelab', status: 'SUCCESS' } },
    /computation/,
  ],
  [
    'analysis names another project',
    {
      task: {
        id: 'task-fixture',
        componentKey: 'other',
        status: 'SUCCESS',
        analysisId: 'analysis-fixture',
      },
    },
    /computation/,
  ],
  [
    'quality gate fails',
    {
      quality: {
        status: 'ERROR',
        conditions: [{ status: 'ERROR', metricKey: 'vulnerabilities', actualValue: '1' }],
      },
    },
    /quality gate/,
  ],
  ['quality gate is absent', { quality: { status: 'NONE', conditions: [] } }, /quality gate/],
  ['quality gate omits conditions', { quality: { status: 'OK' } }, /quality gate/],
  [
    'quality gate ignores conditions',
    {
      quality: {
        status: 'OK',
        ignoredConditions: true,
        conditions: [{ status: 'OK', metricKey: 'vulnerabilities' }],
      },
    },
    /quality gate/,
  ],
  [
    'green summary contradicts a failed condition',
    { quality: { status: 'OK', conditions: [{ status: 'ERROR', metricKey: 'vulnerabilities' }] } },
    /quality gate/,
  ],
])
  test(`SonarQube refuses when ${name}`, async t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t, options);
    const result = await f.check();
    assert.equal(result.status, 'blocked');
    assert.match(result.reason, reason);
    assert.ok(!JSON.stringify(result).includes(token));
    if (options.scanThrow) assert.equal(f.calls.at(-1).args[0], 'rm');
    if (options.quality) assert.deepEqual(result.qualityGate, options.quality);
  });

test('SonarQube refuses task metadata for another server, duplicate IDs and symlinks', async t => {
  if (gitSkip) return t.skip(gitSkip);
  for (const taskText of [
    'projectKey=orbit-homelab\nserverUrl=https://example.com\nceTaskId=task-fixture\n',
    'projectKey=orbit-homelab\nserverUrl=http://sonarqube:9000\nceTaskId=task-fixture\nceTaskId=other\n',
  ]) {
    const f = fixture(t, { taskText });
    assert.equal((await f.check()).status, 'blocked');
    assert.deepEqual(f.requests, ['/api/system/status']);
  }
  const f = fixture(t, {
    mutate: root => {
      const directory = path.join(path.dirname(root), 'evidence/sonarqube');
      fs.unlinkSync(path.join(directory, 'report-task.txt'));
      fs.symlinkSync(path.join(root, 'server.mjs'), path.join(directory, 'report-task.txt'));
    },
  });
  assert.equal((await f.check()).status, 'blocked');
});

test('SonarQube rejects a numeric analysis identifier without querying its quality gate', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t, {
    task: { id: 'task-fixture', componentKey: 'orbit-homelab', status: 'SUCCESS', analysisId: 123 },
  });
  const result = await f.check();
  assert.equal(result.status, 'blocked');
  assert.match(result.reason, /computation/);
  assert.equal(f.requests.length, 2);
});

test('SonarQube refuses changed source and ignored private files instead of claiming the index was scanned', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const changed = fixture(t, {
    mutate: root => fs.appendFileSync(path.join(root, 'server.mjs'), '// Changed\n'),
  });
  assert.equal((await changed.check()).status, 'blocked');
  const extra = fixture(t);
  fs.writeFileSync(path.join(extra.root, '.gitignore'), '*.private\n');
  extra.git('add', '.gitignore');
  fs.writeFileSync(path.join(extra.root, 'secret.private'), 'Synthetic private file\n');
  assert.equal((await extra.check()).status, 'blocked');
  assert.equal(extra.calls.length, 0);
});

test('SonarQube requires private external evidence and refuses stale reports', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  fs.chmodSync(f.evidenceDirectory, 0o755);
  await assert.rejects(f.check(), /private/);
  fs.chmodSync(f.evidenceDirectory, 0o700);
  await f.check();
  await assert.rejects(f.check());
  await assert.rejects(
    checkSonarQube({ root: f.root, evidenceDirectory: path.join(f.root, 'reports') }),
    /outside source/
  );
});

test('SonarQube token rejects permissive modes, symlinks, oversized and malformed input', t => {
  if (gitSkip) return t.skip(gitSkip);
  const f = fixture(t);
  assert.equal(readToken(f.tokenFile), token);
  fs.chmodSync(f.tokenFile, 0o644);
  assert.throws(() => readToken(f.tokenFile), /private regular file/);
  fs.chmodSync(f.tokenFile, 0o600);
  const link = f.tokenFile + '-link';
  fs.symlinkSync(f.tokenFile, link);
  assert.throws(() => readToken(link), /safely/);
  for (const content of ['short', token + '\nsecond-line', 'x'.repeat(5000)]) {
    fs.writeFileSync(f.tokenFile, content);
    assert.throws(() => readToken(f.tokenFile));
  }
  assert.throws(() => readToken(undefined), /ORBIT_SONAR_TOKEN_FILE/);
});

test('SonarQube refuses a green but weakened server quality policy', async t => {
  if (gitSkip) return t.skip(gitSkip);
  const weak = {
    status: 'OK',
    ignoredConditions: false,
    conditions: [
      {
        status: 'OK',
        metricKey: 'lines',
        comparator: 'GT',
        errorThreshold: '0',
        actualValue: '100',
      },
    ],
  };
  const f = fixture(t, { quality: weak });
  const result = await f.check();
  assert.equal(result.status, 'blocked');
  assert.match(result.reason, /complete overall-code security policy/);
  assert.deepEqual(result.qualityGate, weak);
  assert.equal(passesQualityGate(passingGate()), true);
  for (const change of [
    gate => gate.conditions.pop(),
    gate => {
      gate.conditions[1] = { ...gate.conditions[0] };
    },
    gate => {
      gate.conditions[0].errorThreshold = '10';
    },
    gate => {
      gate.conditions[0].errorThreshold = 0;
    },
    gate => {
      gate.conditions[0].comparator = 'LT';
    },
    gate => {
      gate.conditions[0].actualValue = '1';
    },
    gate => {
      gate.conditions[0].actualValue = 0;
    },
    gate => {
      gate.conditions[0].actualValue = '-1';
    },
    gate => {
      gate.conditions[0].metricKey = 'new_vulnerabilities';
    },
    gate => {
      gate.conditions[0].periodIndex = 1;
    },
    gate => {
      gate.conditions[2].actualValue = '99.9';
    },
    gate => {
      gate.conditions[3].actualValue = '0';
    },
    gate => {
      gate.conditions[4] = null;
    },
    gate => {
      gate.ignoredConditions = 'false';
    },
    gate => {
      delete gate.ignoredConditions;
    },
  ]) {
    const gate = passingGate();
    change(gate);
    assert.equal(passesQualityGate(gate), false, JSON.stringify(gate));
  }
});

for (const [name, limit, reader] of [
  ['token', 4096, readToken],
  ['task', 16384, readTask],
])
  test(`SonarQube bounds a ${name} file that grows after its stat check`, t => {
    if (gitSkip) return t.skip(gitSkip);
    const f = fixture(t);
    const originalStat = fs.fstatSync;
    const originalRead = fs.readSync;
    let bytesRead = 0;
    t.mock.method(fs, 'fstatSync', descriptor => {
      const stat = originalStat(descriptor);
      fs.writeFileSync(f.tokenFile, 'x'.repeat(limit * 4));
      return stat;
    });
    t.mock.method(fs, 'readSync', (...args) => {
      assert.ok(args[1].length <= limit + 1);
      const count = originalRead(...args);
      bytesRead += count;
      return count;
    });
    assert.throws(() => reader(f.tokenFile), /size limit/);
    assert.equal(bytesRead, limit + 1);
  });

test('SonarQube API rejects redirects, oversized or malformed responses without leaking errors', async t => {
  const calls = [];
  let response = new Response('{"status":"UP","version":"26.9"}');
  t.mock.method(globalThis, 'fetch', async (url, settings) => {
    calls.push({ url, settings });
    if (response instanceof Error) throw response;
    return response;
  });
  assert.equal((await apiRequest('/api/system/status', token)).status, 'UP');
  assert.equal(calls[0].url, 'http://127.0.0.1:19000/api/system/status');
  assert.equal(calls[0].settings.redirect, 'error');
  assert.equal(calls[0].settings.headers.Authorization, `Bearer ${token}`);
  for (const value of [
    new Response('not JSON'),
    new Response('x'.repeat(1024 * 1024 + 1)),
    new Response('', { status: 401 }),
    new Error(token),
  ]) {
    response = value;
    await assert.rejects(
      apiRequest('/api/system/status', token),
      error => !error.message.includes(token)
    );
  }
});
