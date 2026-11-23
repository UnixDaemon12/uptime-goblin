// Helpers shared by goblin-admin commands.
import fs from 'node:fs';
import { inContainer } from '../container.mjs';
export { inContainer } from '../container.mjs';
import path from 'node:path';
import { acquireLock } from '../db/lock.mjs';
import { isPre15 } from '../db/snapshot.mjs';
import { parseRelease } from '../db/migrate.mjs';
import { printable, readRegularFile, readRunStatusFile } from '../saved-data.mjs';
import { adoptLegacyDataMount, productName } from '../legacy-names.mjs';
import { nativeLayout, releaseLayout } from '../admin-command.mjs';

const statusLimit = 64 * 1024;

// unverified (3): goblin-admin verify-audit found nothing changed but could not check everything
// (no key, entries a lost-key reset or a newer Uptime Goblin signed, journal lines from before a restore).
export const exitCodes = Object.freeze({
  ok: 0,
  failed: 1,
  usage: 2,
  unverified: 3,
  locked: 75,
  refused: 78,
});

/**
 * An error a command reports with a chosen exit status and no stack trace. `command`, when
 * given, is a command line to run instead, which goblin-admin prints alone on the line after the
 * message, so that it can be copied whole.
 */
export class CommandError extends Error {
  constructor(message, exitCode = exitCodes.failed, { command } = {}) {
    super(message);
    this.name = 'CommandError';
    this.exitCode = exitCode;
    if (command !== undefined) this.command = command;
  }
}

// A text field of run/status.json as it may be shown: Uptime Goblin writes short ones (a version, a
// build, a phase), so anything else is cut, and never carries control characters to a terminal.
const statusText = value => (typeof value === 'string' ? printable(value, 100) : undefined);

/**
 * `value` when it is a release version as releases write them (x.y.z, maybe with a pre-release,
 * at most 64 characters), else undefined. The version in run/status.json and in the package.json
 * beside a process found by /proc is anyone's text (the uptime-goblin account's, or any local user's):
 * one that is not a version is shown as unknown, never printed or compared (compareReleases
 * threw on it, which stopped goblin-admin status as a whole).
 */
export function releaseText(value) {
  if (typeof value !== 'string' || value.length > 64) return undefined;
  try {
    parseRelease(value);
    return value;
  } catch {
    return undefined;
  }
}

/**
 * run/status.json as Uptime Goblin wrote it, or null: only the fields a release writes (never the
 * nonce), each of its type, text fields through printable(). The uptime-goblin account owns run/, and
 * read commands may run as root, so the file is read as healthcheck.mjs reads it
 * (readRunStatusFile): never through a symbolic link, run/ itself included (either could name
 * any file root can read), without waiting for a FIFO, at most 64 KiB, and with nothing else of
 * it shown.
 */
export function readRunStatus(dataDir) {
  let value;
  try {
    const bytes = readRunStatusFile(dataDir, statusLimit);
    if (bytes === undefined) return null;
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    return null;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const whole = number => (Number.isSafeInteger(number) ? number : undefined);
  const forwardedProto = value.observed?.forwardedProto;
  const shown = {
    version: releaseText(value.version),
    build: statusText(value.build),
    pid: whole(value.pid),
    phase: statusText(value.phase),
    startedAt: whole(value.startedAt),
    reason: statusText(value.reason),
    ...(value.listen && typeof value.listen === 'object'
      ? { listen: { host: statusText(value.listen.host), port: whole(value.listen.port) } }
      : {}),
    ...(value.observed && typeof value.observed === 'object'
      ? {
          observed: {
            forwardedProto: ['http', 'https'].includes(forwardedProto) ? forwardedProto : null,
          },
        }
      : {}),
  };
  // Fields the file does not have stay absent, as before.
  return Object.fromEntries(Object.entries(shown).filter(([, field]) => field !== undefined));
}

/** Whether a process with this id exists (EPERM: it exists but belongs to someone else). */
export function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

/**
 * The running Uptime Goblin run/status.json names, or one found by its process; else null. Every
 * release since 1.4.3 writes that record while it runs and removes it when it stops, so one left
 * by a crash names a process that is gone. Where /proc shows command lines (Linux), a live
 * process that is not Uptime Goblin's server.mjs (its id reused after a reboot) does not count.
 *
 * 1.4.2 and earlier write no record and take no orbit.lock (a rollback to 1.4.2 is supported),
 * so natively, when no live process is recorded, the Uptime Goblin on this data directory is looked for
 * by its process (orbitServerProcess, `proc` its /proc): {pid, version, unrecorded: true}. Where
 * that cannot be told (no /proc, another user's process) nothing is refused, as before: the
 * docs say to stop 1.4.2 first.
 *
 * In a container (`container`, default inContainer()) the process id cannot be checked (another
 * container's Uptime Goblin has ids of its own), so a record of a release before 1.5, which takes no
 * goblin.lock, counts as running: `docker compose run` beside a 1.4.x container on the same volume
 * must not change the data under it. Stopping it removes the record; one left by a crash is
 * removed by hand. A record of 1.5 or later is left to goblin.lock, which every such release
 * holds while it runs (the caller holds it now, so that Uptime Goblin is not running).
 */
export function runningOrbit(dataDir, { container = inContainer(), proc = '/proc' } = {}) {
  const status = readRunStatus(dataDir);
  if (container) return status && isPre15(status.version ?? null) ? status : null;
  if (orbitProcessAlive(status?.pid)) return status;
  const found = orbitServerProcess(dataDir, { proc });
  return found?.pid ? { pid: found.pid, version: found.version, unrecorded: true } : null;
}

// A directory's real path, or its absolute path while it does not exist.
function realDirectory(directory) {
  try {
    return fs.realpathSync(directory);
  } catch {
    return path.resolve(directory);
  }
}

/**
 * The Uptime Goblin server running on `dataDir`, found by its process natively on Linux: a process
 * whose command line runs a server.mjs and whose data directory, resolved as every release
 * resolves it (GOBLIN_DATA_DIR from its environment, else data/ beside server.mjs, relative paths
 * from its working directory), is this one. This is how an Uptime Goblin that keeps no run/status.json
 * and takes no goblin.lock (1.4.2 and earlier) can be seen at all. The environment is the one it
 * was started with: systemd's (EnvironmentFile=/etc/uptime-goblin.env and the unit's GOBLIN_DATA_DIR);
 * a GOBLIN_DATA_DIR that Node loads itself from --env-file is not seen.
 *
 * Returns {pid, version} (version from the package.json beside that server.mjs, or null), null
 * when no such process runs, or {unknown: why} when that cannot be told: there is no /proc
 * (macOS), or a server.mjs process's environment cannot be read (another user's, read by a
 * user that is neither root nor that user). `proc` is the /proc to read (tests give their own).
 */
export function orbitServerProcess(dataDir, { proc = '/proc' } = {}) {
  let entries;
  try {
    entries = fs.readdirSync(proc);
  } catch {
    return { unknown: 'there is no /proc here to look for one by its process' };
  }
  const target = realDirectory(dataDir);
  let hidden = null;
  for (const name of entries) {
    if (!/^[1-9][0-9]*$/.test(name) || Number(name) === process.pid) continue;
    const base = path.join(proc, name);
    let argv;
    try {
      argv = fs.readFileSync(path.join(base, 'cmdline'), 'utf8').split('\0');
    } catch {
      continue; // Gone since the listing.
    }
    const script = argv.slice(1).find(arg => path.basename(arg) === 'server.mjs');
    if (!script) continue;
    let cwd, environment;
    try {
      cwd = fs.readlinkSync(path.join(base, 'cwd'));
      environment = fs.readFileSync(path.join(base, 'environ'), 'utf8').split('\0');
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ESRCH') hidden ??= Number(name);
      continue;
    }
    // As getenv() reads it: the first assignment; an empty one means the default, as `||` does.
    // GOBLIN_DATA_DIR, else ORBIT_DATA_DIR: a release before 1.5 (Orbit) reads only that, and
    // Uptime Goblin takes it while GOBLIN_DATA_DIR is unset (lib/legacy-names.mjs).
    const assigned = name =>
      environment.find(item => item.startsWith(`${name}=`))?.slice(name.length + 1);
    let configured = assigned('GOBLIN_DATA_DIR') ?? assigned('ORBIT_DATA_DIR');
    const file = path.resolve(cwd, script);
    // In the container image, a data volume mounted only where Orbit's image had it, as the
    // server takes it (adoptLegacyDataMount; a refusal there means no server runs on it).
    try {
      const mounted = { GOBLIN_DATA_DIR: configured };
      adoptLegacyDataMount(mounted, { appRoot: path.dirname(file) });
      configured = mounted.GOBLIN_DATA_DIR;
    } catch {}
    const directory = configured
      ? path.resolve(cwd, configured)
      : path.join(path.dirname(file), 'data');
    if (realDirectory(directory) !== target) continue;
    let version = null;
    try {
      // Any local user can start a server.mjs naming this data directory: its version is shown
      // to root only when it is one (releaseText), and read from a regular file of at most
      // 64 KiB, never waiting for a FIFO.
      const bytes = readRegularFile(path.join(path.dirname(file), 'package.json'), {
        limit: 64 * 1024,
      });
      version = releaseText(bytes && JSON.parse(bytes.toString('utf8'))?.version) ?? null;
    } catch {}
    return { pid: Number(name), version };
  }
  return hidden
    ? {
        unknown: `process ${hidden} runs a server.mjs as another user, whose data directory cannot be read from here (run this as the user Uptime Goblin runs as, or as root)`,
      }
    : null;
}

/**
 * Whether `pid` (from run/status.json, natively: not in a container) is a live Uptime Goblin: alive, not
 * this process, and, where /proc shows command lines (Linux), running server.mjs (a process id
 * reused after a reboot is not Uptime Goblin).
 */
export function orbitProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid === process.pid || !processAlive(pid)) return false;
  try {
    if (!fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').includes('server.mjs')) return false;
  } catch {
    // No /proc (macOS), or not readable: the live process is taken for Uptime Goblin.
  }
  return true;
}

/**
 * Runs `task(lock)` holding goblin.lock (Uptime Goblin stopped); the lock is released afterwards.
 * Uptime Goblin 1.5 holds goblin.lock while it runs, but 1.4.x never takes it: a 1.4.x left running
 * (after the documented code rollback, say) keeps its settings and password in memory and
 * would write them back over what the command changed. So a live process named by
 * run/status.json also refuses the command, exit 75 as for the lock; in a container, any
 * 1.4.x record does (see runningOrbit). 1.4.2 writes no record: natively it refuses when its
 * process is found (runningOrbit); otherwise it must be stopped first, as the docs say. `where`
 * is the data directory, or the command's context ({dataDir, container, proc}: main() decides
 * whether it runs in a container).
 */
export async function withLock(where, purpose, task) {
  const {
    dataDir,
    container = inContainer(),
    proc = '/proc',
  } = typeof where === 'string' ? { dataDir: where } : where;
  if (!fs.existsSync(dataDir))
    throw Object.assign(new Error(`${dataDir} does not exist`), { exitCode: 1 });
  const lock = acquireLock(dataDir, { purpose });
  try {
    const running = runningOrbit(dataDir, { container, proc });
    if (running) {
      // One found by its process alone keeps no record: a release before 1.4.3, so Orbit.
      const who =
        typeof running.version === 'string'
          ? `${productName(running.version)} ${running.version}`
          : running.unrecorded
            ? 'Orbit'
            : 'Uptime Goblin';
      // The unit to stop natively: orbit.service for a release before 1.5 (found by its record,
      // or as 1.4.2 by its process), which reads only the Orbit layout, else the one of the layout
      // this data directory belongs to.
      const orbit =
        running.unrecorded ||
        (typeof running.version === 'string' && productName(running.version) === 'Orbit');
      const { product, unit } = orbit ? releaseLayout('Orbit') : nativeLayout(dataDir);
      const stop = `Stop ${product} first: sudo systemctl stop ${unit.replace(/\.service$/, '')}.`;
      const record = path.join(dataDir, 'run', 'status.json');
      throw new CommandError(
        container
          ? `${who} may be running on ${dataDir}: run/status.json names it, and from inside a container goblin-admin cannot see another container's processes. Stop it first (docker compose stop uptime-goblin). If no Uptime Goblin runs (the record is left from a crash), remove ${record} and run this command again.`
          : running.unrecorded
            ? `${who} is running on ${dataDir} (process ${running.pid}, found by its process: it keeps no run/status.json, as Orbit 1.4.2 and earlier do not). ${stop}`
            : `${who} is running on ${dataDir} (process ${running.pid}, named by run/status.json). ${stop} If no ${product} runs (the record is left from a crash), remove ${record} and run this command again.`,
        exitCodes.locked
      );
    }
    return await task(lock);
  } finally {
    lock.release();
  }
}

export const formatBytes = bytes =>
  bytes >= 2 ** 30
    ? `${(bytes / 2 ** 30).toFixed(1)} GiB`
    : bytes >= 2 ** 20
      ? `${(bytes / 2 ** 20).toFixed(1)} MiB`
      : bytes >= 1024
        ? `${(bytes / 1024).toFixed(1)} KiB`
        : `${bytes} B`;

// A time read from saved data may be any number: one past the year 275760 has no date at all.
export const formatTime = ms =>
  Number.isFinite(ms) && Number.isFinite(new Date(ms).getTime())
    ? new Date(ms)
        .toISOString()
        .replace('T', ' ')
        .replace(/\.\d{3}Z$/, ' UTC')
    : 'unknown';
