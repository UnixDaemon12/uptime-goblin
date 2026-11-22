// A stand-in for util-linux flock in the installer tests, for the one form the installer uses:
// `flock -n FD`. Node cannot take a flock(2) lock, so the lock is a file in $FAKE_SYSTEMD_DIR
// named after the device and inode of the file open on FD, holding the process ID of the process
// that ran flock (the installer's shell, which holds the descriptor). As with flock(2), the lock
// is free again once that process is gone: a file naming a process that no longer runs is taken
// over. Each call is noted in flock.calls.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const directory = process.env.FAKE_SYSTEMD_DIR;
const [flag, fd] = process.argv.slice(2);
if (!directory || flag !== '-n' || !/^\d+$/.test(fd ?? '')) {
  console.error('fake flock: only `flock -n FD` with FAKE_SYSTEMD_DIR set is modelled');
  process.exit(64);
}
const { dev, ino } = fs.fstatSync(Number(fd));
const lock = path.join(directory, `flock-${dev}-${ino}`);
const holder = process.ppid;
fs.appendFileSync(path.join(directory, 'flock.calls'), `${holder}\n`);
const alive = pid => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
};
try {
  fs.writeFileSync(lock, String(holder), { flag: 'wx' });
  process.exit(0);
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
}
const held = Number(fs.readFileSync(lock, 'utf8'));
if (held !== holder && alive(held)) process.exit(1);
fs.writeFileSync(lock, String(holder));
