// goblin-admin status: is Uptime Goblin running, in which phase, on which schema, and can systemd start
// it (roadmap §2.9 "goblin-admin status", G8), and whether a snapshot restore was interrupted
// (its journal, and the temporary copies it left in the data directory). Read-only; takes no
// lock (it only probes goblin.lock, see orbitState).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { controlExists, interruptedRestoreMessage, openControl } from '../../db/control.mjs';
import { isLocked } from '../../db/lock.mjs';
import { interruptedRestore, isPre15, listSnapshots } from '../../db/snapshot.mjs';
import {
  readRunStatus,
  orbitProcessAlive,
  orbitServerProcess,
  formatBytes,
  formatTime,
} from '../common.mjs';
import { printable, readRegularFile } from '../../saved-data.mjs';
import { leftoverEntries } from './snapshots.mjs';
import { productName } from '../../legacy-names.mjs';

export const summary =
  'Show whether Uptime Goblin runs, its phase, the data schema and the service binary.';
export const usage = '[--data-dir <dir>] [--unit <file>] [--json]';
export const kind = 'read';
export const options = { unit: { type: 'string' } };
const defaultUnit = '/etc/systemd/system/uptime-goblin.service';
// A unit file is a few kilobytes; a larger one is not Uptime Goblin's.
const unitLimit = 64 * 1024;

// The path root may run for `file`: `file` with every symbolic link resolved, when that file and
// every directory above it, up to /, belong to root and no group or other user can change them;
// otherwise null. Root then runs that resolved path, never `file` itself: a link (or any
// directory on the way) another user controls could be pointed at their own program between
// this check and the run. --unit names any file, and status may run as root.
function rootRunnable(file, lstat = fs.lstatSync) {
  try {
    const real = fs.realpathSync(file);
    for (let item = real; ; item = path.dirname(item)) {
      const stat = lstat(item);
      if (stat.uid !== 0 || stat.mode & 0o022) return null;
      if (path.dirname(item) === item) return real;
    }
  } catch {
    return null;
  }
}

/**
 * The first ExecStart= binary of a systemd unit, whether it exists and runs, and its Node
 * major version (Uptime Goblin needs 24 or later). The unit is read as a regular file of at most
 * 64 KiB without waiting (a FIFO given as --unit held the command). Run as root (`uid` 0), the
 * binary is run only when root and nobody else can change it or a directory above it, and by
 * its resolved path (see rootRunnable): the unit file may be anyone's, and --version is still a
 * program run as root. `run` is what runs it and `lstat` what reads an owner and mode (tests:
 * which path was run, and owners a test cannot make).
 */
export function checkUnit(
  unitFile,
  { uid = null, run: runProgram = spawnSync, lstat = fs.lstatSync } = {}
) {
  let text;
  try {
    const bytes = readRegularFile(unitFile, { limit: unitLimit });
    if (bytes === undefined) return { unit: unitFile, found: false };
    text = bytes.toString('utf8');
  } catch (error) {
    if (error?.code !== 'file_unusable') return { unit: unitFile, found: false };
    return { unit: unitFile, found: true, execStart: null, ok: false, problem: error.message };
  }
  const line = text.split('\n').find(item => /^ExecStart=/.test(item.trim()));
  const binary = line
    ?.trim()
    .slice('ExecStart='.length)
    .replace(/^[-@:+!]+/, '')
    .trim()
    .split(/\s+/)[0];
  if (!binary)
    return { unit: unitFile, found: true, execStart: null, ok: false, problem: 'no ExecStart=' };
  const result = { unit: unitFile, found: true, execStart: binary };
  if (!path.isAbsolute(binary))
    return { ...result, ok: false, problem: 'ExecStart does not name an absolute path' };
  try {
    fs.accessSync(binary, fs.constants.X_OK);
  } catch {
    return { ...result, ok: false, problem: `${binary} does not exist or is not executable` };
  }
  const runnable = uid === 0 ? rootRunnable(binary, lstat) : binary;
  if (!runnable)
    return {
      ...result,
      ok: false,
      problem: `${binary} was not run as root: it or a directory above it is not root's alone (another user could change it)`,
    };
  const run = runProgram(runnable, ['--version'], { encoding: 'utf8', timeout: 5000 });
  const version = /^v(\d+)\.\d+\.\d+/.exec((run.stdout || '').trim());
  if (!version)
    return { ...result, ok: false, problem: `${binary} --version did not report a Node version` };
  const major = Number(version[1]);
  return {
    ...result,
    // Only the version itself: whatever else the program printed is not shown.
    version: version[0],
    ok: major >= 24,
    ...(major >= 24
      ? {}
      : { problem: `${binary} is Node ${major}; Uptime Goblin needs 24 or later` }),
  };
}

/**
 * Whether Uptime Goblin runs, by the rules offline commands refuse on (runningOrbit in ../common.mjs):
 * {running: true | false | null, uncertain?: why it cannot be told, unrecorded?: {pid, version}
 * of an Uptime Goblin found by its process, stale?: true when the Uptime Goblin the record names is not
 * running}. `status` is run/status.json.
 *
 * Uptime Goblin 1.5 and later hold goblin.lock while they run, which is seen from any container on the
 * same data directory, while the process id in the record is one of Uptime Goblin's own container: from
 * `docker compose run`, or the kept 1.5 image after a Compose rollback, it may be missing or be
 * any process here (this one included, under --init). So a 1.5 record, or none, is answered by
 * probing the lock (isLocked holds it for an instant: a start racing that instant exits 75 and
 * its service manager starts it again). A lock held with no record is a start that is not yet
 * serving, or an offline goblin-admin command. A record of a release before 1.5 (which takes no
 * lock) is checked by its process natively; in a container it cannot be, so it may be running.
 *
 * None of that sees 1.4.2 and earlier, which keep no record and take no lock: after a rollback
 * to 1.4.2 (supported) the answer was "not running" while it served. So "not running" is said
 * only once no Uptime Goblin runs on the directory by its process either (orbitServerProcess, natively
 * on Linux); where that cannot be looked at (a container, no /proc, another user's process),
 * Uptime Goblin may be running.
 */
function orbitState(dataDir, status, { container, proc }) {
  if (!status || !isPre15(status.version ?? null)) {
    let held;
    try {
      held = isLocked(dataDir);
    } catch (error) {
      return {
        running: null,
        uncertain: `goblin.lock could not be checked: ${error.code || error.message}`,
      };
    }
    if (held)
      return status
        ? { running: true }
        : {
            running: null,
            uncertain:
              'goblin.lock is held but there is no run/status.json: Uptime Goblin is starting, or a goblin-admin command is changing the data directory',
          };
  } else if (container)
    return { running: null, uncertain: "another container's processes cannot be seen from here" };
  else if (orbitProcessAlive(status.pid)) return { running: true };
  // Nothing recorded runs. An Uptime Goblin that records nothing may.
  const stale = status ? { stale: true } : {};
  const found = container
    ? { unknown: "another container's processes cannot be seen from here" }
    : orbitServerProcess(dataDir, { proc });
  if (!found) return { running: false, ...stale };
  if (found.pid)
    return { running: true, unrecorded: { pid: found.pid, version: found.version }, ...stale };
  return {
    running: null,
    uncertain: `Orbit 1.4.2 and earlier keep no run/status.json and take no orbit.lock, and ${found.unknown}`,
    ...stale,
  };
}

export async function run(context) {
  const { dataDir, release } = context;
  const report = { release, dataDir, dataDirExists: fs.existsSync(dataDir) };
  const status = readRunStatus(dataDir);
  const orbit = orbitState(dataDir, status, context);
  report.process = status ? { ...status, ...orbit } : { ...orbit, statusFile: 'absent' };
  if (controlExists(dataDir)) {
    const control = openControl(dataDir, { readOnly: true, release, env: {} });
    try {
      const state = await control.inspect();
      let meta = {};
      try {
        meta = await control.meta.all();
      } catch {}
      report.control = {
        applied: state.applied.length,
        pending: state.pending.map(step => step.id),
        unknown: state.unknown.map(row => row.id),
        fences: state.fences.map(({ name, min_release }) => ({ name, minRelease: min_release })),
        refusal: state.refusal?.message ?? null,
        instanceId: meta.instance_id ?? null,
        createdByRelease: meta.created_by_release ?? null,
        lastVersion: meta.last_version ?? null,
        keyring: await control.keyringExists().catch(() => false),
      };
    } finally {
      control.close();
    }
  } else report.control = null;
  // A snapshots/ that is not a directory (a link to an unmounted volume, a loop of links, a
  // file) is reported as the start refuses it: read as absent it gave "Snapshots: 0", and a loop
  // an interrupted restore. The restore's journal is in it, so whether one was interrupted
  // cannot be told then (restore.unknown).
  let snapshots = [],
    snapshotsProblem = null;
  try {
    snapshots = listSnapshots(dataDir);
  } catch (error) {
    if (error?.code !== 'snapshots_not_directory') throw error;
    snapshotsProblem = error.message;
  }
  report.snapshots = {
    count: snapshotsProblem ? null : snapshots.length,
    pinned: snapshots.filter(item => item.pinned).map(item => item.id),
    newest: snapshots[0]?.id ?? null,
    ...(snapshotsProblem ? { problem: snapshotsProblem } : {}),
  };
  let journal = null;
  if (!snapshotsProblem)
    try {
      journal = interruptedRestore(dataDir);
    } catch {
      // There, but unreadable (permissions): a start refuses on it all the same.
      journal = { snapshot: null, aside: null, files: [], keepHistory: false };
    }
  const leftovers = leftoverEntries(dataDir);
  report.restore = {
    interrupted: journal,
    ...(snapshotsProblem ? { unknown: true } : {}),
    leftovers: leftovers.map(({ id, names, bytes, needed, problem }) => ({
      id,
      names,
      bytes,
      needed,
      problem,
    })),
    leftoverBytes: leftovers.reduce((sum, item) => sum + item.bytes, 0),
  };
  const unit = context.options.unit ?? defaultUnit;
  report.service = checkUnit(unit, { uid: context.uid });

  context.report(report, value => {
    const lines = [
      `goblin-admin ${value.release}`,
      `Data directory: ${value.dataDir}${value.dataDirExists ? '' : ' (missing)'}`,
    ];
    const p = value.process;
    const running =
      p.running === null
        ? `may be running (${p.uncertain})`
        : p.running
          ? 'running'
          : 'not running';
    // The Uptime Goblin the record names, when it is not the answer: it is not running.
    const left =
      p.statusFile === 'absent'
        ? ''
        : `run/status.json is left by ${productName(p.version)} ${p.version ?? '?'} build ${p.build ?? '?'}, pid ${p.pid ?? '?'}, started ${formatTime(p.startedAt)}, which is not running`;
    // Each line is labelled with the name of the release it is about: Orbit for one before 1.5,
    // whose record this is or which is found by its process alone (it keeps no record: before
    // 1.4.3), and Uptime Goblin where no version is known.
    if (p.unrecorded)
      lines.push(
        `${p.unrecorded.version ? productName(p.unrecorded.version) : 'Orbit'}: running, version ${p.unrecorded.version ?? '?'}, pid ${p.unrecorded.pid}, found by its process (it keeps no run/status.json, as Orbit 1.4.2 and earlier do not)${left ? `; ${left}` : ''}`
      );
    else if (p.statusFile === 'absent')
      lines.push(
        `Uptime Goblin: ${p.running === null ? running : 'not running (no run/status.json)'}`
      );
    else if (p.stale && p.running === null) lines.push(`Uptime Goblin: ${running}; ${left}`);
    else
      lines.push(
        `${productName(p.version)}: ${running}, version ${p.version ?? '?'} build ${p.build ?? '?'}, pid ${p.pid ?? '?'}, phase ${p.phase ?? (p.running === null ? 'unknown' : p.running ? 'ready' : 'stopped')}, started ${formatTime(p.startedAt)}`
      );
    if (p.reason) lines.push(`Last reason: ${p.reason}`);
    // What control.sqlite holds is saved text (meta values, fence rows, and the refusal built
    // from them): shown without control characters, each value one bounded line.
    const c = value.control;
    if (!c) lines.push('Control database: none yet (created by the first start of 1.5 or later)');
    else {
      lines.push(
        `Control database: ${c.applied} steps applied, ${c.pending.length} pending${c.unknown.length ? `, ${c.unknown.length} from a newer release` : ''}; created by ${c.createdByRelease === null ? 'an upgrade from before 1.5' : printable(c.createdByRelease, 64)}; last run by ${c.lastVersion === null ? 'unknown' : printable(c.lastVersion, 64)}`
      );
      if (c.pending.length) lines.push(`Pending: ${c.pending.join(', ')}`);
      if (c.fences.length)
        lines.push(
          `Fences: ${printable(c.fences.map(f => `${printable(f.name, 64)} ≥ ${printable(f.minRelease, 64)}`).join(', '), 1000)}`
        );
      if (c.refusal) lines.push(`Refused: ${printable(c.refusal, 1000)}`);
      // Every start creates the keyring once there is a control database (delivery spec D6).
      lines.push(`Keyring: ${c.keyring ? 'present' : 'none yet'}`);
    }
    if (value.snapshots.problem)
      lines.push(
        `Snapshots: PROBLEM: ${printable(value.snapshots.problem, 1000)}`,
        'Restore interrupted: cannot be told (a restore keeps its record in snapshots/).'
      );
    else
      lines.push(
        `Snapshots: ${value.snapshots.count}${value.snapshots.pinned.length ? ` (pinned: ${value.snapshots.pinned.map(id => printable(id, 100)).join(', ')})` : ''}`
      );
    const r = value.restore;
    if (r.interrupted)
      lines.push(`Restore interrupted: ${interruptedRestoreMessage(r.interrupted)}`);
    for (const item of r.leftovers)
      lines.push(
        `Restore leftover: ${item.names.join(', ')} in the data directory (${formatBytes(item.bytes)}). ${item.problem}`
      );
    const s = value.service;
    if (!s.found) lines.push(`Service unit: ${s.unit} not found`);
    else if (s.ok) lines.push(`Service binary: ${printable(s.execStart, 300)} (${s.version})`);
    else lines.push(`Service binary: PROBLEM: ${printable(s.problem, 300)}`);
    return lines;
  });
  // A data directory that does not exist is reported, never taken for a stopped Uptime Goblin's.
  return report.dataDirExists ? 0 : 1;
}
