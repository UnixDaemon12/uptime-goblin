import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { listenPort } from './environment.mjs';
import { readRunStatusFile } from './saved-data.mjs';
import { productName } from './legacy-names.mjs';

// Readiness and upgrade verification for Docker's HEALTHCHECK and the native installer.
//
// `/health` needs no sign-in and answers exactly 200 {"status":"ok"}; nothing else (in
// particular not the 401 sign-in challenge of Orbit 1.4.2 and earlier) counts as ready.
// `/health?instance=<nonce>` adds "instance": "match" | "mismatch" and never echoes the nonce.
// node:http is used because fetch cannot override Host: Uptime Goblin always accepts localhost:<port>,
// whatever address it listens on or which hosts are allowed.

const statusLimit = 64 * 1024;

// What a release writes into run/status.json: a release version and a build id (the first hex
// digits of computeBuild). The uptime-goblin account owns the file and root's installer prints these
// two, so anything else (a terminal escape such as OSC 52, which writes the clipboard, a line
// break, a screen clear) makes the record no record instead of reaching root's terminal.
const releaseVersion =
  /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z-]{1,40}(?:\.[0-9A-Za-z-]{1,40})*)?$/;
const buildId = /^[0-9a-f]{1,64}$/;

function target(host) {
  return ['0.0.0.0', '::', '[::]', ''].includes(host) ? '127.0.0.1' : host.replace(/^\[|\]$/g, '');
}

// One request to /health. Resolves {ready, reason} and never rejects: a PORT the server would
// refuse (`abc`, `99999`, a line break) is a failed probe with that reason, as is any address
// http.request refuses to use, instead of an exception and a stack trace in the installer.
export function probe({
  host = process.env.HOST || '127.0.0.1',
  port = process.env.PORT,
  timeoutMs = 2000,
  instance,
} = {}) {
  const query = instance === undefined ? '' : `?instance=${encodeURIComponent(instance)}`;
  try {
    port = listenPort(port);
  } catch (error) {
    return Promise.resolve({ ready: false, reason: error.message.replace(/\.$/, '') });
  }
  return new Promise(resolve => {
    let settled = false;
    let deadline;
    const finish = (ready, reason) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve({ ready, reason });
    };
    let request;
    try {
      request = http.request(
        {
          host: target(String(host)),
          port,
          path: '/health' + query,
          method: 'GET',
          headers: { Host: `localhost:${port}`, Accept: 'application/json' },
          agent: false,
        },
        response => {
          let text = '';
          response.setEncoding('utf8');
          response.on('data', chunk => {
            text += chunk;
            if (text.length > 4096) {
              request.destroy();
              finish(false, '/health sent an oversized response');
            }
          });
          response.on('end', () => {
            let body;
            try {
              body = JSON.parse(text);
            } catch {
              return finish(false, `/health answered ${response.statusCode} without JSON`);
            }
            if (response.statusCode !== 200 || body?.status !== 'ok')
              return finish(false, `/health answered ${response.statusCode}`);
            if (instance !== undefined && body.instance !== 'match')
              return finish(
                false,
                body.instance === 'mismatch'
                  ? 'a different Uptime Goblin process is answering on this port'
                  : '/health did not confirm the instance'
              );
            finish(true, 'ready');
          });
          response.on('error', () => finish(false, '/health response failed'));
        }
      );
    } catch (error) {
      // http.request validates the address and the Host header synchronously.
      return finish(false, `invalid HOST or PORT (${error.code || 'error'})`);
    }
    // A socket timeout only bounds inactivity: DNS lookup and a response that keeps
    // trickling bytes can otherwise hold up upgrade verification indefinitely.
    deadline = setTimeout(() => {
      request.destroy();
      finish(false, '/health did not answer in time');
    }, timeoutMs);
    request.on('error', error =>
      finish(false, `cannot reach Uptime Goblin (${error.code || 'error'})`)
    );
    request.end();
  });
}

export async function isReady(options) {
  return (await probe(options)).ready;
}

// C1: the first 12 hex digits of
//   sha256(version "\n" + for each file sorted by path: path "\n" sha256hex(bytes) "\n")
// over server.mjs, every *.mjs file under lib/ and every file under public/ (both recursively),
// with paths relative to the application directory, "/" separators and dot files and dot
// directories skipped. readRelease() in lib/http/static.mjs computes the same value at startup
// (test/healthcheck.test.mjs keeps the two in step).
//
// Since 1.5 the server's code lives in lib/http/, lib/db/ and so on, so lib/ is walked: a
// change there must be a new build, or the installer's same-release check, --expect-build and
// X-Orbit-Build cannot tell two releases apart. The *.mjs filter is the one lib/*.mjs always
// had, so a tree without lib/ subdirectories (every release up to 1.4.x) keeps exactly the
// build it had before: rollback verification computes an old release's build with this code.
export function computeBuild(root) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  const files = ['server.mjs'];
  // Dirent types do not follow symlinks, so a symlink is neither walked nor hashed.
  const walk = (relative, keep) => {
    for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const item = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(item, keep);
      else if (entry.isFile() && keep(entry.name)) files.push(item);
    }
  };
  walk('lib', name => name.endsWith('.mjs'));
  walk('public', () => true);
  const hash = createHash('sha256').update(`${version}\n`);
  for (const file of files.sort()) {
    const digest = createHash('sha256')
      .update(fs.readFileSync(path.join(root, file)))
      .digest('hex');
    hash.update(`${file}\n${digest}\n`);
  }
  return hash.digest('hex').slice(0, 12);
}

// C3: <dataDir>/run/status.json, written by the server once it listens. Returns null while it
// is missing, unreadable or not (yet) a complete record, and for a version or build that no
// release writes (see releaseVersion), so neither is ever printed.
export function readStatus(dataDir) {
  try {
    // Never through a symbolic link, run/ itself included, without waiting for a FIFO writer,
    // checked on the descriptor it reads (readRunStatusFile): the installer runs this as root.
    const bytes = readRunStatusFile(dataDir, statusLimit);
    if (bytes === undefined) return null;
    const status = JSON.parse(bytes.toString('utf8'));
    if (
      typeof status?.version !== 'string' ||
      !releaseVersion.test(status.version) ||
      typeof status.build !== 'string' ||
      !buildId.test(status.build) ||
      !Number.isSafeInteger(status.pid) ||
      status.pid <= 0 ||
      typeof status.nonce !== 'string' ||
      !/^[0-9a-f]{32}$/.test(status.nonce)
    )
      return null;
    return status;
  } catch {
    return null;
  }
}

// systemd's view of the unit: MainPID is 0 while no process runs.
export function systemdState(unit) {
  return new Promise(resolve => {
    execFile(
      'systemctl',
      ['show', '--property=MainPID', '--property=ActiveState', '--property=Result', unit],
      { timeout: 10000, encoding: 'utf8' },
      (error, stdout) => {
        if (error) return resolve({ mainPid: 0, activeState: 'unknown', result: '' });
        const values = Object.fromEntries(
          stdout
            .split('\n')
            .filter(line => line.includes('='))
            .map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)])
        );
        resolve({
          mainPid: Number(values.MainPID) || 0,
          activeState: values.ActiveState || 'unknown',
          result: values.Result || '',
        });
      }
    );
  });
}

// C5: proves that the process systemd started for `unit` (or the process `pid`) runs the
// expected version and build and is the one answering /health. Waits up to timeoutMs; fails at
// once when the unit has failed or the right process reports the wrong version or build.
export async function verifyInstance({
  host,
  port,
  dataDir,
  expectVersion,
  expectBuild,
  unit,
  pid,
  timeoutMs = 120000,
  intervalMs = 500,
  state = systemdState,
  now = Date.now,
}) {
  const deadline = now() + timeoutMs;
  let reason = 'Uptime Goblin has not written run/status.json yet';
  for (;;) {
    let mainPid = pid;
    if (unit) {
      const current = await state(unit);
      if (current.activeState === 'failed')
        return {
          ok: false,
          reason: `${unit} failed${current.result ? ` (${current.result})` : ''} and systemd will not restart it`,
        };
      mainPid = current.mainPid;
    }
    const status = readStatus(dataDir);
    // Only a record written by the service's own process is conclusive; any other one may be
    // left over from an earlier start, so keep waiting for the current process to write its own.
    const confirmed = Boolean(status && mainPid && status.pid === mainPid);
    let mismatch;
    if (status && expectVersion !== undefined && status.version !== expectVersion)
      mismatch = `the service runs ${productName(status.version)} ${status.version}, expected ${expectVersion}`;
    else if (status && expectBuild !== undefined && status.build !== expectBuild)
      mismatch = `the service runs build ${status.build}, expected ${expectBuild}`;
    if (!status) reason = 'Uptime Goblin has not written run/status.json yet';
    else if (unit && !mainPid) reason = `${unit} has no running process`;
    else if (mainPid && !confirmed)
      reason = `run/status.json belongs to process ${status.pid}, not the service's process ${mainPid}`;
    else if (mismatch && confirmed) return { ok: false, reason: mismatch };
    else if (mismatch) reason = mismatch;
    else {
      const result = await probe({ host, port, instance: status.nonce });
      if (result.ready) return { ok: true, status };
      reason = result.reason;
    }
    if (now() >= deadline) return { ok: false, reason };
    await delay(Math.max(0, Math.min(intervalMs, deadline - now())));
  }
}

export function parseArguments(argv) {
  const options = { wait: false };
  const valued = {
    '--timeout': 'timeout',
    '--instance': 'instance',
    '--data-dir': 'dataDir',
    '--expect-version': 'expectVersion',
    '--expect-build': 'expectBuild',
    '--unit': 'unit',
    '--pid': 'pid',
    '--print-build': 'printBuild',
  };
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i];
    if (name === '--wait') options.wait = true;
    else if (Object.hasOwn(valued, name) && i + 1 < argv.length) options[valued[name]] = argv[++i];
    else throw new Error(`Unknown or incomplete option: ${name}`);
  }
  if (options.timeout !== undefined) {
    if (!/^\d{1,4}$/.test(options.timeout) || +options.timeout < 1 || +options.timeout > 1800)
      throw new Error('--timeout takes 1 to 1800 seconds');
    options.timeout = +options.timeout;
  }
  if (options.pid !== undefined) {
    if (!/^[1-9]\d{0,9}$/.test(options.pid)) throw new Error('--pid takes a process id');
    options.pid = +options.pid;
  }
  if (options.unit !== undefined && !/^[A-Za-z0-9@._-]+\.service$/.test(options.unit))
    throw new Error('--unit takes a systemd service name');
  const verifying = ['expectVersion', 'expectBuild', 'unit', 'pid'].some(key => key in options);
  if (verifying && !options.dataDir)
    throw new Error('--expect-version, --expect-build, --unit and --pid need --data-dir');
  return options;
}

const usage = `Usage: node lib/healthcheck.mjs [--wait] [--timeout <seconds>] [--instance <nonce>]
       node lib/healthcheck.mjs --wait --data-dir <dir> [--expect-version <v>]
            [--expect-build <b>] [--unit <name>.service | --pid <pid>] [--timeout <seconds>]
       node lib/healthcheck.mjs --print-build <application directory>
HOST and PORT come from the environment (use node --env-file=/etc/uptime-goblin.env).`;

// Compare real paths so a symlinked install path still runs the check (see server.mjs).
const isMain = () => {
  try {
    return (
      Boolean(process.argv[1]) &&
      fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
};
if (isMain()) {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`${error.message}\n${usage}`);
    process.exit(2);
  }
  if (options.printBuild !== undefined) {
    console.log(computeBuild(path.resolve(options.printBuild)));
  } else if (options.dataDir) {
    const result = await verifyInstance({
      dataDir: options.dataDir,
      expectVersion: options.expectVersion,
      expectBuild: options.expectBuild,
      unit: options.unit,
      pid: options.pid,
      timeoutMs: (options.wait ? (options.timeout ?? 120) : 0) * 1000,
    });
    if (result.ok)
      console.log(
        `${productName(result.status.version)} ${result.status.version} (build ${result.status.build}) is serving as process ${result.status.pid}.`
      );
    else console.error(`Uptime Goblin is not verified: ${result.reason}.`);
    process.exitCode = result.ok ? 0 : 1;
  } else {
    const deadline = Date.now() + (options.wait ? (options.timeout ?? 120) : 0) * 1000;
    let result;
    for (;;) {
      result = await probe({ instance: options.instance });
      if (result.ready || Date.now() >= deadline) break;
      await delay(500);
    }
    if (!result.ready) console.error(`Uptime Goblin did not become ready: ${result.reason}.`);
    process.exitCode = result.ready ? 0 : 1;
  }
}
