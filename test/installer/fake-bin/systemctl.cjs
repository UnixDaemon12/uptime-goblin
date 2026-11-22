// A small model of systemd for installer tests. It runs uptime-goblin.service, and orbit.service
// (the unit from before the rename, which the installer migrates), from the unit file under
// GOBLIN_INSTALL_ROOT (ORBIT_INSTALL_ROOT, the old name, too), mapping /opt/uptime-goblin,
// /var/lib/uptime-goblin, /etc/uptime-goblin.env and /etc/uptime-goblin/ and their Orbit names
// into that root, also in the environment file's values, with the unit's
// Environment=/EnvironmentFile= settings, WorkingDirectory=, Restart=always,
// RestartPreventExitStatus=, LoadCredential= and SetCredential= (unit and <unit>.d drop-ins: the
// files, or the values, are put in $FAKE_SYSTEMD_DIR/credentials, named by
// CREDENTIALS_DIRECTORY; a value stands in for a file that is not there). `systemctl cat`
// prints the unit and its drop-ins. enable and disable keep enabled-<unit> files, which
// is-enabled reads. The service's environment is systemd's own (PATH and the
// lines of manager.env), then Environment=, then each EnvironmentFile= (an empty assignment
// clears either list; one named with "-" may be missing), less what UnsetEnvironment= lists (a
// name, or NAME=value for that value only); `systemctl show-environment` prints systemd's own.
// `systemctl show` gives MainPID, ActiveState, Result, LoadState (not-found without the unit),
// DropInPaths (the drop-ins on disk, none without the unit, as systemd lists none for a unit it
// has not loaded) and NeedDaemonReload. While need-daemon-reload exists, which daemon-reload
// removes, NeedDaemonReload is yes and DropInPaths is what that file holds, the drop-ins systemd
// read last. A detached supervisor process plays systemd's part; its state is kept in
// FAKE_SYSTEMD_DIR (each unit's state in a file of its own; need-daemon-reload is for
// uptime-goblin.service):
//   main.json           uptime-goblin.service: {supervisor, pid, exited, code, signal, stopping,
//                       restarts}; orbit.main.json holds orbit.service's
//   journal.log         the service's output plus systemd-style lines (read by the fake journalctl)
//   journal.times       "<ms> <length>" lines: the time (a test may fix it: FAKE_JOURNAL_MS) and
//                       journal.log's length before each line logged and each start of the
//                       service (the fake journalctl's --since=@)
//   calls.log           every systemctl invocation
//   manager.env         systemd's own environment besides PATH, NAME=value lines (a test writes it)
//   need-daemon-reload  a test writes it for unit files changed since the last daemon-reload
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const root = process.env.GOBLIN_INSTALL_ROOT || process.env.ORBIT_INSTALL_ROOT;
const directory = process.env.FAKE_SYSTEMD_DIR;
if (!root || !directory) {
  console.error('fake systemctl: GOBLIN_INSTALL_ROOT and FAKE_SYSTEMD_DIR are required');
  process.exit(1);
}
const units = ['uptime-goblin.service', 'orbit.service'];
// The unit a call names (the last word that is one of the two), else uptime-goblin.service.
const unitName =
  process.argv[2] === '__supervise'
    ? process.argv[3]
    : [...process.argv.slice(2)].reverse().find(word => units.includes(word)) ||
      'uptime-goblin.service';
const mainFile = path.join(
  directory,
  unitName === 'orbit.service' ? 'orbit.main.json' : 'main.json'
);
const journalFile = path.join(directory, 'journal.log');
const timesFile = path.join(directory, 'journal.times');
const managerFile = path.join(directory, 'manager.env');
const reloadFile = path.join(directory, 'need-daemon-reload');
const unitFile = path.join(root, 'etc/systemd/system', unitName);
const enabledFile = path.join(directory, `enabled-${unitName}`);
const restartDelay = Number(process.env.FAKE_SYSTEMD_RESTART_MS || 300);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const read = () => {
  try {
    return JSON.parse(fs.readFileSync(mainFile, 'utf8'));
  } catch {
    return null;
  }
};
const write = state => {
  fs.writeFileSync(mainFile + '.tmp', JSON.stringify(state));
  fs.renameSync(mainFile + '.tmp', mainFile);
};
// What follows in journal.log was logged at this time or later: the fake journalctl's --since.
// The time is taken before the length, so nothing after that length was written before it. A
// test can fix the time (FAKE_JOURNAL_MS, whole milliseconds) to put the entries of two starts in
// one second, which a whole-second --since cannot tell apart. The installer reads neither a time
// window nor a position: after a failed start it shows the last 50 lines (fake-bin/journalctl).
const fixedTime = process.env.FAKE_JOURNAL_MS;
if (fixedTime !== undefined && !/^\d{1,15}$/.test(fixedTime)) {
  console.error(`fake systemctl: FAKE_JOURNAL_MS takes whole milliseconds, not "${fixedTime}"`);
  process.exit(1);
}
const mark = () => {
  const at = fixedTime === undefined ? Date.now() : Number(fixedTime);
  let length = 0;
  try {
    length = fs.statSync(journalFile).size;
  } catch {}
  fs.appendFileSync(timesFile, `${at} ${length}\n`);
};
const log = line => {
  mark();
  fs.appendFileSync(journalFile, `systemd: ${line}\n`);
};
const alive = pid => {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const mapped = value =>
  value
    .replace(
      /(^|\s|=|:)(\/opt\/(?:orbit|uptime-goblin)|\/var\/lib\/(?:orbit|uptime-goblin)|\/etc\/(?:orbit|uptime-goblin)\.env)(?=\/|\s|$)/g,
      `$1${root}$2`
    )
    .replace(/(^|\s|=|:)(\/etc\/(?:orbit|uptime-goblin))(?=\/)/g, `$1${root}$2`);
const dropIns = () => {
  const directory = `${unitFile}.d`;
  try {
    return fs
      .readdirSync(directory)
      .filter(name => name.endsWith('.conf'))
      .sort()
      .map(name => path.join(directory, name));
  } catch {
    return [];
  }
};

function parseUnit() {
  const unit = {
    environment: {},
    files: [],
    unset: [],
    restart: 'no',
    prevent: [],
    credentials: {},
    values: {},
  };
  const text = [unitFile, ...dropIns()].map(file => fs.readFileSync(file, 'utf8')).join('\n');
  for (const line of text.split('\n')) {
    const match = /^([A-Za-z]+)=(.*)$/.exec(line.trim());
    if (!match) continue;
    const [, key, value] = match;
    if (key === 'LoadCredential') {
      if (!value) unit.credentials = {};
      else {
        // Every absolute path of the test host is under the scratch root.
        const at = value.indexOf(':'),
          file = value.slice(at + 1);
        unit.credentials[value.slice(0, at)] = file.startsWith('/') ? root + file : file;
      }
      continue;
    }
    // A list of its own, which an empty assignment clears; the value as written (no escapes).
    if (key === 'SetCredential') {
      if (!value) unit.values = {};
      else unit.values[value.slice(0, value.indexOf(':'))] = value.slice(value.indexOf(':') + 1);
      continue;
    }
    if (key === 'ExecStart') unit.exec = value.split(/\s+/).map(mapped);
    else if (key === 'WorkingDirectory') unit.cwd = mapped(value);
    else if (key === 'Environment') {
      if (!value) unit.environment = {};
      else {
        const at = value.indexOf('=');
        unit.environment[value.slice(0, at)] = mapped(value.slice(at + 1));
      }
    } else if (key === 'EnvironmentFile') {
      if (!value) unit.files = [];
      else unit.files.push({ file: mapped(value.replace(/^-/, '')), optional: value[0] === '-' });
    } else if (key === 'UnsetEnvironment') {
      if (!value) unit.unset = [];
      else unit.unset.push(...value.split(/\s+/).filter(Boolean));
    } else if (key === 'Restart') unit.restart = value;
    else if (key === 'RestartPreventExitStatus') unit.prevent = value.split(/\s+/).map(Number);
  }
  return unit;
}

// systemd's own environment: PATH, then manager.env.
function managerEnvironment() {
  const env = { PATH: process.env.PATH };
  let text = '';
  try {
    text = fs.readFileSync(managerFile, 'utf8');
  } catch {}
  for (const line of text.split('\n')) {
    const at = line.indexOf('=');
    if (at > 0) env[line.slice(0, at)] = line.slice(at + 1);
  }
  return env;
}

function environment(unit) {
  const env = { ...managerEnvironment(), ...unit.environment };
  // A line ends at LF, CR or CRLF, as systemd reads an environment file. One named with "-" may
  // be missing.
  for (const { file, optional } of unit.files)
    for (const line of (optional && !fs.existsSync(file)
      ? ''
      : fs.readFileSync(file, 'utf8')
    ).split(/\r\n|\r|\n/)) {
      const at = line.indexOf('=');
      if (at > 0 && !line.startsWith('#')) env[line.slice(0, at)] = mapped(line.slice(at + 1));
    }
  // LoadCredential=: copies the files where the service finds them, as systemd does; a
  // SetCredential= value of the same name is used only when the file is not there.
  const names = [...new Set([...Object.keys(unit.credentials), ...Object.keys(unit.values)])];
  if (names.length) {
    const credentials = path.join(directory, 'credentials');
    fs.rmSync(credentials, { recursive: true, force: true });
    fs.mkdirSync(credentials, { mode: 0o700 });
    for (const name of names) {
      const file = unit.credentials[name];
      if (name in unit.values && !(file && fs.existsSync(file)))
        fs.writeFileSync(path.join(credentials, name), unit.values[name]);
      else fs.copyFileSync(file, path.join(credentials, name));
    }
    env.CREDENTIALS_DIRECTORY = credentials;
  }
  // A name, or NAME=value for that value only.
  for (const entry of unit.unset) {
    const at = entry.indexOf('=');
    if (at < 0) delete env[entry];
    else if (env[entry.slice(0, at)] === entry.slice(at + 1)) delete env[entry.slice(0, at)];
  }
  return env;
}

function activeState(state) {
  if (!state) return { active: 'inactive', result: 'success', pid: 0 };
  if (!state.exited && alive(state.pid))
    return { active: 'active', result: 'success', pid: state.pid };
  if (!state.exited && alive(state.supervisor))
    return { active: 'activating', result: 'exit-code', pid: 0 };
  if (state.stopping || (state.exited && state.code === 0 && !state.failed))
    return { active: 'inactive', result: 'success', pid: 0 };
  return { active: 'failed', result: state.signal ? 'signal' : 'exit-code', pid: 0 };
}

// The detached supervisor: starts ExecStart, restarts it like systemd would, records state.
async function supervise() {
  const unit = parseUnit();
  let restarts = 0;
  write({ ...read(), supervisor: process.pid });
  for (;;) {
    // The service's own output follows: from now on.
    mark();
    const journal = fs.openSync(journalFile, 'a');
    const child = spawn(unit.exec[0], unit.exec.slice(1), {
      cwd: unit.cwd,
      env: environment(unit),
      stdio: ['ignore', journal, journal],
    });
    fs.closeSync(journal);
    const exit = new Promise(resolve => {
      child.on('error', error =>
        resolve({ code: error.code === 'ENOENT' ? 203 : 1, signal: null })
      );
      child.on('exit', (code, signal) => resolve({ code, signal }));
    });
    if (child.pid) {
      write({ ...read(), supervisor: process.pid, pid: child.pid, exited: false, restarts });
      log(`Started ${unitName} (process ${child.pid}).`);
    }
    const { code, signal } = await exit;
    const state = read() || {};
    log(
      `${unitName}: Main process exited, ${signal ? `signal=${signal}` : `code=exited, status=${code}`}`
    );
    const again =
      !state.stopping &&
      (unit.restart === 'always' || (unit.restart === 'on-failure' && (code !== 0 || signal))) &&
      !(code !== null && unit.prevent.includes(code));
    write({
      ...state,
      pid: 0,
      exited: !again,
      code,
      signal,
      failed: !state.stopping && !again && code !== 0,
    });
    if (!again) return;
    restarts++;
    log(`${unitName}: Scheduled restart job, restart counter is at ${restarts}.`);
    await sleep(restartDelay);
    if (read()?.stopping) return;
  }
}

// Like systemd: SIGTERM to the main process, SIGKILL after a grace period, no restart.
async function stop() {
  if (!read()) return;
  write({ ...read(), stopping: true });
  const running = () => [read()?.pid, read()?.supervisor].filter(alive);
  for (const pid of [read()?.pid].filter(alive)) process.kill(pid, 'SIGTERM');
  for (let i = 0; i < 100 && running().length; i++) await sleep(100);
  for (const pid of running()) process.kill(pid, 'SIGKILL');
  write({ ...read(), pid: 0, exited: true, stopping: true });
  log(`Stopped ${unitName}.`);
}

async function start() {
  if (!fs.existsSync(unitFile)) {
    console.error(`Failed to start ${unitName}: Unit ${unitName} not found.`);
    process.exit(5);
  }
  if (activeState(read()).active === 'active') return;
  write({ supervisor: 0, pid: 0, exited: false });
  spawn(process.execPath, [__filename, '__supervise', unitName], {
    detached: true,
    stdio: 'ignore',
    env: process.env,
  }).unref();
  for (let i = 0; i < 100; i++) {
    const state = read();
    if (state?.pid || state?.exited) return;
    await sleep(50);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === '__supervise') return supervise();
  fs.appendFileSync(path.join(directory, 'calls.log'), argv.join(' ') + '\n');
  const quiet = argv.includes('--quiet') || argv.includes('-q');
  const words = argv.filter(arg => !arg.startsWith('-'));
  const properties = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '-p') properties.push(...argv[++i].split(','));
    else if (argv[i].startsWith('--property='))
      properties.push(...argv[i].slice('--property='.length).split(','));
  }
  const [command] = words;
  // Model transient or persistent management failures without changing service state.
  const failure = path.join(directory, `failed-${command}`);
  if (
    process.env.FAKE_SYSTEMD_FAIL_ALWAYS === command ||
    (process.env.FAKE_SYSTEMD_FAIL_ONCE === command && !fs.existsSync(failure))
  ) {
    fs.writeFileSync(failure, 'failed');
    console.error(`fake systemctl: simulated ${command} failure`);
    process.exitCode = 1;
    return;
  }
  const now = activeState(read());
  switch (command) {
    case 'daemon-reload':
      fs.rmSync(reloadFile, { force: true });
      return;
    // The installer clears a failed state before its --no-block restart; nothing to clear here.
    case 'reset-failed':
      return;
    case 'enable':
      if (!fs.existsSync(unitFile)) {
        console.error(`Failed to enable unit: Unit file ${unitName} does not exist.`);
        process.exitCode = 1;
        return;
      }
      fs.writeFileSync(enabledFile, '');
      return;
    case 'disable':
      fs.rmSync(enabledFile, { force: true });
      return;
    case 'is-enabled': {
      const enabled = fs.existsSync(unitFile) && fs.existsSync(enabledFile);
      if (!quiet)
        console.log(enabled ? 'enabled' : fs.existsSync(unitFile) ? 'disabled' : 'not-found');
      process.exitCode = enabled ? 0 : 1;
      return;
    }
    case 'show-environment':
      for (const [name, value] of Object.entries(managerEnvironment()))
        console.log(`${name}=${value}`);
      return;
    case 'cat': {
      if (!fs.existsSync(unitFile)) {
        console.error(`No files found for ${unitName}.`);
        process.exitCode = 1;
        return;
      }
      for (const file of [unitFile, ...dropIns()])
        process.stdout.write(
          `# ${file.slice(root.length)}\n${fs.readFileSync(file, 'utf8').replace(/\n?$/, '\n')}\n`
        );
      return;
    }
    case 'is-active':
      if (!quiet) console.log(now.active);
      process.exitCode = now.active === 'active' ? 0 : 3;
      return;
    case 'stop':
      return stop();
    case 'start':
      return start();
    case 'restart':
      await stop();
      return start();
    case 'show': {
      const needReload = unitName === 'uptime-goblin.service' && fs.existsSync(reloadFile);
      const values = {
        MainPID: now.pid,
        ActiveState: now.active,
        Result: now.result,
        LoadState: fs.existsSync(unitFile) ? 'loaded' : 'not-found',
        DropInPaths: needReload
          ? fs.readFileSync(reloadFile, 'utf8').trim()
          : fs.existsSync(unitFile)
            ? dropIns()
                .map(file => file.slice(root.length))
                .join(' ')
            : '',
        NeedDaemonReload: needReload ? 'yes' : 'no',
      };
      for (const name of properties)
        console.log(argv.includes('--value') ? values[name] : `${name}=${values[name]}`);
      return;
    }
    case 'status':
      console.log(`● ${unitName} - fake\n     Active: ${now.active}\n   Main PID: ${now.pid}`);
      process.exitCode = now.active === 'active' ? 0 : 3;
      return;
    default:
      console.error(`fake systemctl: unsupported command ${argv.join(' ')}`);
      process.exitCode = 1;
  }
}
main().catch(error => {
  console.error(`fake systemctl: ${error.stack}`);
  process.exit(1);
});
