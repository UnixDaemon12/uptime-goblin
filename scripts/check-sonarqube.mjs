// Run only against an immutable Git-index snapshot. Evidence and credentials stay outside it.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { sourceManifest, sha256 } from './security-evidence.mjs';

export const scannerImage =
  'sonarsource/sonar-scanner-cli@sha256:a3f4215076706c95a17a68c19322ee916e40a3acd081a8c1a1e839e0194afa57';
const apiOrigin = 'http://127.0.0.1:19000';
const scannerOrigin = 'http://sonarqube:9000';
const projectKey = 'orbit-homelab';
const rootDirectory = fileURLToPath(new URL('..', import.meta.url));
const scannerTimeoutMs = 15 * 60 * 1000;
const maximumResponseBytes = 1024 * 1024;

class CheckError extends Error {}
const refuse = message => {
  throw new CheckError(message);
};
const inside = (directory, file) => file === directory || file.startsWith(directory + path.sep);

function boundedText(descriptor, limit) {
  // Read a sentinel byte too: a regular file can grow after fstat().
  const bytes = Buffer.alloc(limit + 1);
  let size = 0;
  while (size < bytes.length) {
    const count = fs.readSync(descriptor, bytes, size, bytes.length - size, null);
    if (!count) break;
    size += count;
  }
  if (size > limit) refuse('A SonarQube input file exceeded its size limit.');
  return bytes.subarray(0, size).toString('utf8');
}

export function readToken(file, uid = process.getuid()) {
  let descriptor;
  try {
    if (!file) refuse('Set ORBIT_SONAR_TOKEN_FILE to a private token file.');
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.uid !== uid || stat.mode & 0o077 || stat.size > 4096)
      refuse('The SonarQube token must be a private regular file owned by the current user.');
    const token = boundedText(descriptor, 4096).replace(/\r?\n$/, '');
    if (!/^[A-Za-z0-9_-]{20,512}$/.test(token))
      refuse('The SonarQube token file has invalid contents.');
    return token;
  } catch (error) {
    if (error instanceof CheckError) throw error;
    refuse('The SonarQube token file could not be read safely.');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function redact(text, token) {
  let safe = String(text ?? '');
  if (token)
    for (const secret of [
      token,
      Buffer.from(token).toString('base64'),
      Buffer.from(token + ':').toString('base64'),
    ])
      safe = safe.replaceAll(secret, '[REDACTED]');
  return safe;
}

// Never follow a URL returned by a server or scanner: all API reads use the local instance.
export async function apiRequest(endpoint, token) {
  let response;
  try {
    response = await fetch(apiOrigin + endpoint, {
      headers: { Authorization: `Bearer ${token}` },
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) refuse('SonarQube API refused a required request.');
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maximumResponseBytes) refuse('SonarQube API response exceeded its size limit.');
      chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (error) {
    if (error instanceof CheckError) throw error;
    refuse('SonarQube API did not return a valid response before the deadline.');
  } finally {
    await response?.body?.cancel().catch(() => {});
  }
}

function execute(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30000,
    ...options,
  });
}

export function snapshotIdentity(root, run = execute) {
  const git = (...args) => {
    const result = run('git', ['-C', root, ...args]);
    if (result.status !== 0 || result.error) refuse('Cannot identify the Git snapshot.');
    return result.stdout.trimEnd();
  };
  const tree = git('write-tree');
  const parent = git('rev-parse', 'HEAD');
  if (![tree, parent].every(value => /^[0-9a-f]{40,64}$/.test(value)))
    refuse('The Git snapshot identity is invalid.');
  const files = sourceManifest(root, git('ls-tree', '-rz', '--full-tree', tree));
  // A standalone invocation must not analyze ignored/untracked local files accidentally.
  const extra = git('ls-files', '--others', '-z').split('\0').filter(Boolean);
  if (extra.some(file => !file.startsWith('node_modules/')))
    refuse('The source snapshot contains untracked files outside installed dependencies.');
  const required = ['sonar-project.properties', 'server.mjs'];
  if (required.some(file => !files.some(entry => entry.file === file)))
    refuse('The snapshot is missing required SonarQube source files.');
  return { tree, parent, manifestSha256: sha256(JSON.stringify(files)) };
}

export function scannerArguments(root, directory, name, uid, gid) {
  return [
    'run',
    '--rm',
    '--name',
    name,
    '--platform',
    'linux/amd64',
    '--network',
    'orbit-quality',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--read-only',
    '--memory=3g',
    '--cpus=2',
    '--pids-limit=512',
    '--tmpfs',
    // The analyzer provisions its JRE/Node here; a noexec tmpfs prevents analysis.
    '/tmp:rw,exec,nosuid,nodev,size=1g',
    '--user',
    `${uid}:${gid}`,
    '--mount',
    `type=bind,src=${root},dst=/usr/src,readonly`,
    '--mount',
    `type=bind,src=${directory},dst=/orbit-report`,
    '--workdir',
    '/usr/src',
    '--env',
    'SONAR_TOKEN',
    '--env',
    'SONAR_HOST_URL=' + scannerOrigin,
    '--env',
    'SONAR_USER_HOME=/tmp/sonar',
    scannerImage,
    '-Dsonar.projectKey=' + projectKey,
    '-Dsonar.working.directory=/orbit-report/work',
    '-Dsonar.scanner.metadataFilePath=/orbit-report/report-task.txt',
    '-Dsonar.qualitygate.wait=true',
    '-Dsonar.qualitygate.timeout=300',
  ];
}

export function readTask(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 16384) refuse('SonarQube scanner metadata is invalid.');
    const fields = new Map();
    for (const line of boundedText(descriptor, 16384).split(/\r?\n/)) {
      if (!line) continue;
      const match = /^([A-Za-z][A-Za-z0-9]*)=(.*)$/.exec(line);
      if (!match || fields.has(match[1])) refuse('SonarQube scanner metadata is invalid.');
      fields.set(match[1], match[2]);
    }
    if (
      fields.get('projectKey') !== projectKey ||
      fields.get('serverUrl') !== scannerOrigin ||
      !/^[A-Za-z0-9_-]{1,200}$/.test(fields.get('ceTaskId') ?? '')
    )
      refuse('SonarQube scanner metadata does not identify this project and server.');
    return { ceTaskId: fields.get('ceTaskId') };
  } catch (error) {
    if (error instanceof CheckError) throw error;
    refuse('SonarQube scanner did not produce readable analysis metadata.');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

export function passesQualityGate(gate) {
  // Require the configured overall-code policy, not merely a green arbitrary server gate.
  const required = new Map([
    ['vulnerabilities', ['GT', '0']],
    ['bugs', ['GT', '0']],
    ['security_hotspots_reviewed', ['LT', '100']],
    ['security_rating', ['GT', '1']],
    ['reliability_rating', ['GT', '1']],
  ]);
  if (
    gate?.status !== 'OK' ||
    gate.ignoredConditions !== false ||
    !Array.isArray(gate.conditions) ||
    gate.conditions.length !== required.size
  )
    return false;
  for (const condition of gate.conditions) {
    if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return false;
    const expected = required.get(condition.metricKey);
    if (
      !expected ||
      condition.status !== 'OK' ||
      condition.comparator !== expected[0] ||
      condition.errorThreshold !== expected[1] ||
      condition.periodIndex !== undefined ||
      typeof condition.actualValue !== 'string' ||
      condition.actualValue.length > 32 ||
      !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(condition.actualValue)
    )
      return false;
    const value = Number(condition.actualValue);
    if (!Number.isFinite(value)) return false;
    if (condition.metricKey === 'security_hotspots_reviewed') {
      if (value !== 100) return false;
    } else if (!Number.isInteger(value) || value !== Number(expected[1])) return false;
    required.delete(condition.metricKey); // A duplicate cannot replace a missing condition.
  }
  return required.size === 0;
}

export async function checkSonarQube({
  root = rootDirectory,
  evidenceDirectory,
  tokenFile = process.env.ORBIT_SONAR_TOKEN_FILE,
  run = execute,
  request = apiRequest,
  uid = process.getuid(),
  gid = process.getgid(),
} = {}) {
  root = fs.realpathSync(root);
  if (!evidenceDirectory) refuse('Provide a private evidence directory.');
  fs.mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(evidenceDirectory);
  if (!stat.isDirectory() || stat.uid !== uid || stat.mode & 0o077)
    refuse('The evidence directory must be private and owned by the current user.');
  evidenceDirectory = fs.realpathSync(evidenceDirectory);
  if (inside(root, evidenceDirectory)) refuse('SonarQube evidence must stay outside source.');
  if ([root, evidenceDirectory].some(value => /[,\r\n]/.test(value)))
    refuse('Source and evidence paths cannot contain Docker mount separators.');
  const directory = path.join(evidenceDirectory, 'sonarqube');
  fs.mkdirSync(directory, { mode: 0o700 }); // Refuse old evidence instead of trusting a stale task ID.
  const record = {
    status: 'blocked',
    started: new Date().toISOString(),
    scannerImage,
    apiOrigin,
    scannerOrigin,
    projectKey,
  };
  let token;
  const save = () =>
    fs.writeFileSync(
      path.join(directory, 'result.json'),
      redact(JSON.stringify(record, null, 2) + '\n', token),
      { mode: 0o600 }
    );
  try {
    if (tokenFile && inside(root, fs.realpathSync(tokenFile)))
      refuse('The SonarQube token must stay outside source.');
    token = readToken(tokenFile, uid);
    record.source = snapshotIdentity(root, run);
    const system = await request('/api/system/status', token);
    if (
      system?.status !== 'UP' ||
      typeof system.version !== 'string' ||
      !system.version ||
      system.version.length > 100
    )
      refuse('SonarQube is not ready or its version is missing.');
    record.serverVersion = system.version;
    const network = run('docker', [
      'network',
      'inspect',
      'orbit-quality',
      '--format',
      '{{json .Internal}}',
    ]);
    if (network.status !== 0 || network.error || network.stdout.trim() !== 'true')
      refuse('The orbit-quality Docker network must exist and be internal.');
    record.networkInternal = true;
    const name = 'orbit-sonar-' + randomUUID();
    const args = scannerArguments(root, directory, name, uid, gid);
    record.command = ['docker', ...args];
    let scan;
    try {
      scan = run('docker', args, {
        env: { ...process.env, SONAR_TOKEN: token },
        timeout: scannerTimeoutMs,
      });
    } finally {
      // Killing a timed-out Docker CLI does not necessarily stop its container.
      run('docker', ['rm', '--force', name], { timeout: 30000 });
    }
    fs.writeFileSync(
      path.join(directory, 'scanner.log'),
      redact((scan.stdout ?? '') + (scan.stderr ?? ''), token),
      { mode: 0o600 }
    );
    record.scannerExit = scan.status;
    record.scannerSignal = scan.signal ?? null;
    record.scannerExecutionError = Boolean(scan.error);
    record.sourceAfter = snapshotIdentity(root, run);
    if (JSON.stringify(record.sourceAfter) !== JSON.stringify(record.source))
      refuse('Source changed during SonarQube analysis.');
    const { ceTaskId } = readTask(path.join(directory, 'report-task.txt'));
    record.ceTaskId = ceTaskId;
    const computation = await request('/api/ce/task?id=' + encodeURIComponent(ceTaskId), token);
    record.computation = computation?.task;
    const task = computation?.task;
    if (
      task?.id !== ceTaskId ||
      task.componentKey !== projectKey ||
      task.status !== 'SUCCESS' ||
      typeof task.analysisId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,200}$/.test(task.analysisId ?? '')
    )
      refuse('SonarQube analysis computation did not complete successfully for this project.');
    record.analysisId = task.analysisId;
    const quality = await request(
      '/api/qualitygates/project_status?analysisId=' + encodeURIComponent(task.analysisId),
      token
    );
    record.qualityGate = quality?.projectStatus;
    if (!passesQualityGate(record.qualityGate))
      refuse(
        'SonarQube quality gate failed or did not enforce the complete overall-code security policy.'
      );
    if (scan.status !== 0 || scan.error) refuse('SonarQube scanner did not exit successfully.');
    record.status = 'pass';
  } catch (error) {
    record.reason =
      error instanceof CheckError
        ? error.message
        : 'SonarQube validation could not complete safely.';
  } finally {
    record.finished = new Date().toISOString();
    save();
  }
  return { ...JSON.parse(redact(JSON.stringify(record), token)), directory };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3)
      refuse('Usage: node scripts/check-sonarqube.mjs <private-evidence-directory>');
    const result = await checkSonarQube({ evidenceDirectory: process.argv[2] });
    console.log(`SonarQube: ${result.status}. Private evidence: ${result.directory}`);
    if (result.status !== 'pass') {
      console.error(result.reason);
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(
      error instanceof CheckError ? error.message : 'SonarQube validation could not start safely.'
    );
    process.exitCode = 1;
  }
}
