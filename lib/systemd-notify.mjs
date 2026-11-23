// Readiness for systemd (deploy/uptime-goblin.service, Type=notify): READY=1 once Uptime Goblin
// listens and has written run/status.json, so "active" means serving. systemd names its socket in
// NOTIFY_SOCKET, a datagram unix socket (a path, or an abstract name written with a leading @).
// Node cannot send a unix datagram (node:dgram has udp4 and udp6 only, node:net unix streams
// only), and a native module or a dependency is not worth one message, so systemd's own
// systemd-notify(1) sends it: started by absolute path (under ProtectSystem=strict nothing can
// replace it), with fixed arguments, no shell and an environment of NOTIFY_SOCKET alone (never
// the password or any other setting), bounded in time. Its message comes from a child process,
// so the unit has NotifyAccess=all: any process in Uptime Goblin's cgroup may notify, and Uptime
// Goblin starts no other program there, so that grants nothing a process of the service could
// not already do as the service. systemd-notify waits until systemd has read the message, so the
// message is not lost when it exits at once.
import fs from 'node:fs';
import { execFile } from 'node:child_process';

/** Where systemd-notify may be: Debian and its derivatives, and distributions with /bin merged. */
export const NOTIFY_PROGRAMS = Object.freeze(['/usr/bin/systemd-notify', '/bin/systemd-notify']);
// A sockaddr_un path holds 108 bytes with its NUL; an abstract name has a NUL instead of the @.
const SOCKET_BYTES = 107;

/**
 * The notification socket systemd gave (NOTIFY_SOCKET), or null when there is none, or when it is
 * not one systemd writes: an absolute path or an @ name, at most 107 bytes, no control character.
 */
export function notifySocket(env = process.env) {
  const value = env.NOTIFY_SOCKET;
  if (typeof value !== 'string' || value.length < 2) return null;
  if (value[0] !== '/' && value[0] !== '@') return null;
  if (Buffer.byteLength(value) > SOCKET_BYTES || /[\x00-\x1f\x7f]/.test(value)) return null;
  return value;
}

/**
 * Tells systemd that Uptime Goblin is ready (READY=1), when it runs under a unit that asked
 * (NOTIFY_SOCKET set). Resolves true once systemd-notify reported success, false when there was
 * nothing to tell or it failed (logged: systemd then keeps the unit activating, and the
 * installer's verification still decides whether it serves). Never rejects.
 */
export function notifyReady({
  env = process.env,
  run = execFile,
  exists = file => fs.existsSync(file),
  logger = console,
  timeoutMs = 10000,
} = {}) {
  if (env.NOTIFY_SOCKET === undefined) return Promise.resolve(false);
  const socket = notifySocket(env);
  if (!socket) {
    logger.error(
      'NOTIFY_SOCKET is not a socket systemd names; Uptime Goblin cannot report that it is ready.'
    );
    return Promise.resolve(false);
  }
  const program = NOTIFY_PROGRAMS.find(file => exists(file));
  if (!program) {
    logger.error(
      `systemd-notify was not found (${NOTIFY_PROGRAMS.join(' or ')}), so Uptime Goblin cannot tell systemd that it is ready: the unit stays activating although Uptime Goblin serves. Install systemd, or give the unit Type=simple in a drop-in (sudo systemctl edit uptime-goblin).`
    );
    return Promise.resolve(false);
  }
  return new Promise(resolve => {
    try {
      run(
        program,
        ['--ready'],
        { env: { NOTIFY_SOCKET: socket }, timeout: timeoutMs, windowsHide: true, shell: false },
        error => {
          if (error)
            logger.error(
              `systemd-notify --ready failed (${error.code ?? error.signal ?? 'error'}), so the unit stays activating although Uptime Goblin serves.`
            );
          resolve(!error);
        }
      );
    } catch (error) {
      logger.error(`systemd-notify could not be started (${error.code ?? error.name}).`);
      resolve(false);
    }
  });
}
