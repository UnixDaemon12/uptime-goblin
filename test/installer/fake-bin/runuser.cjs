// Installer tests run unprivileged and cannot become the uptime-goblin account (orbit before the
// migration), and the fake chown gives nothing away: every file stays the test user's. This
// models the one call the installer makes, `runuser -u uptime-goblin -- test -r <file>`, on a host
// where those files are root's with that group (as the installer's chown makes them): the account
// reads a file whose group or other read bit is set, through directories (below
// GOBLIN_INSTALL_ROOT) whose group or other search bit is set. So a key file at 0600 is root's
// alone, as on a real host. The data directory (var/lib/uptime-goblin, or var/lib/orbit) and what
// is in it are the account's own, as the installer and Uptime Goblin make them: there the
// owner's bits count. A path listed in $FAKE_SYSTEMD_DIR/root-owned (one absolute path a line) is
// root:root instead, as a file copied in by root is: only its other bits count. Each call is
// logged, one line per call, in $FAKE_SYSTEMD_DIR/runuser.log.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.FAKE_SYSTEMD_DIR, 'runuser.log'), `${args.join(' ')}\n`);
const [flag, user, separator, command, test, file, ...rest] = args;
if (
  flag !== '-u' ||
  !['uptime-goblin', 'orbit'].includes(user) ||
  separator !== '--' ||
  command !== 'test' ||
  test !== '-r' ||
  !file ||
  rest.length
) {
  console.error(`fake runuser: unsupported call: runuser ${args.join(' ')}`);
  process.exit(125);
}
// A failure of runuser itself, before or instead of running test (a PAM session it cannot open,
// a test it cannot run, a signal): while $FAKE_SYSTEMD_DIR/runuser-fails holds {path, status,
// stderr, signal}, a call for that path (any, without one) writes `stderr` and exits with
// `status`, or is killed by `signal`.
let fails = null;
try {
  fails = JSON.parse(
    fs.readFileSync(path.join(process.env.FAKE_SYSTEMD_DIR, 'runuser-fails'), 'utf8')
  );
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (fails && (!fails.path || fails.path === file)) {
  if (fails.stderr) process.stderr.write(`${fails.stderr}\n`);
  if (fails.signal) {
    process.kill(process.pid, fails.signal);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5000);
  }
  process.exit(fails.status ?? 1);
}
const root = process.env.GOBLIN_INSTALL_ROOT || process.env.ORBIT_INSTALL_ROOT;
const data = path.join(root, user === 'orbit' ? 'var/lib/orbit' : 'var/lib/uptime-goblin');
let rootOwned = [];
try {
  rootOwned = fs
    .readFileSync(path.join(process.env.FAKE_SYSTEMD_DIR, 'root-owned'), 'utf8')
    .split('\n')
    .filter(Boolean);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
// Whether the account has `bit` (4 read, 1 search) on `at`, whose stat is `stat`.
const allowed = (at, stat, bit) => {
  if (rootOwned.includes(at)) return Boolean(stat.mode & bit);
  if (at === data || at.startsWith(data + path.sep)) return Boolean(stat.mode & (bit << 6));
  return Boolean(stat.mode & ((bit << 3) | bit));
};
// /var and /var/lib are root's, mode 0755, on every host; here a test, or the installer's
// install -d under its umask 077, may have made them 0700 first. Every account searches them.
const system = new Set([path.join(root, 'var'), path.join(root, 'var/lib')]);
let stat;
try {
  stat = fs.statSync(file);
} catch {
  process.exit(1);
}
if (!allowed(file, stat, 4)) process.exit(1);
for (let directory = path.dirname(file); directory.startsWith(root + path.sep); ) {
  if (!system.has(directory) && !allowed(directory, fs.statSync(directory), 1)) process.exit(1);
  directory = path.dirname(directory);
}
process.exit(0);
