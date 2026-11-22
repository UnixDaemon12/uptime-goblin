// The environment as input (lib/environment.mjs and the modules that own a variable): HOST,
// PORT, GOBLIN_DATA_DIR and GOBLIN_ALLOWED_HOSTS refuse what cannot work before anything is
// written; the yes/no flags share one parser; values Uptime Goblin does not use are said once at the
// start, escaped and bounded, never silently taken for something else.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.mjs';
import {
  allowedHostList,
  composeDefault,
  displaySessionLimits,
  envFileWarnings,
  flagValue,
  insecureHttpSessionsSetting,
  jsonText,
  knownVariables,
  listenHost,
  listenPort,
  loopbackPublished,
  namesProxy,
  plainHttpWarning,
  quoted,
  unusedVariableWarnings,
} from '../lib/environment.mjs';
import { createFeatures } from '../lib/features.mjs';
import { trustedProxies } from '../lib/throttle.mjs';
import { COMPOSE_LEGACY_PREFIX, currentVariableName } from '../lib/legacy-names.mjs';
import { configureDestinations, destinationProblem } from '../lib/destinations.mjs';
import { probe, readStatus } from '../lib/healthcheck.mjs';
import { freePortSync } from './helpers/net.mjs';
import { supervisedEnv } from './helpers/supervised.mjs';

const serverFile = fileURLToPath(new URL('../server.mjs', import.meta.url));
const repository = fileURLToPath(new URL('../', import.meta.url));
// A test value for these throwaway data directories only.
const password = 'environment-test-password';
// Control and line-break characters that must never reach a log line raw.
const unsafe = /[\u0000-\u001f\u007f-\u009f]/;

function temporary(t, prefix = 'orbit-environment-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// Runs `task` with these variables in process.env (undefined removes one) and console.warn
// captured; restores both. Resolves {result, warnings}.
async function withEnvironment(variables, task) {
  const saved = Object.fromEntries(Object.keys(variables).map(name => [name, process.env[name]]));
  const warn = console.warn,
    warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  for (const [name, value] of Object.entries(variables))
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  try {
    return { result: await task(), warnings };
  } finally {
    console.warn = warn;
    for (const [name, value] of Object.entries(saved))
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  }
}

// `node server.mjs` (`file`, this repository's by default) with a clean environment, stopped
// with SIGTERM once ready unless `stay`; resolves {code, stdout, stderr}.
function runServer(env, args = [], { stay = false, cwd = repository, file = serverFile } = {}) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [...args, file], {
      cwd,
      env: { PATH: process.env.PATH, HOST: '127.0.0.1', PORT: freePortSync(), ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (!stay && /Uptime Goblin is ready at/.test(stdout)) child.kill('SIGTERM');
    });
    child.stderr.on('data', chunk => (stderr += chunk));
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
  });
}

test('PORT and HOST: a port from 1 to 65535 and an address or host name, nothing else', () => {
  assert.equal(listenPort(undefined), 4317);
  assert.equal(listenPort(''), 4317);
  for (const [value, port] of [
    ['4317', 4317],
    ['1', 1],
    ['65535', 65535],
    [8080, 8080],
    // createApp's own `port` may be 0, for a free port the system chooses (the tests).
    [0, 0],
  ])
    assert.equal(listenPort(value), port, String(value));
  // Number() took each of these: as NaN, out of range, a fraction, hex or an exponent. 0 from
  // the environment served on a port nobody chose, and a leading zero is not how a port is
  // written (a script that meant an octal 010 would get 10).
  for (const value of [
    'abc',
    '70000',
    '-1',
    '4317.5',
    ' 0x0 ',
    '0x10',
    '1e3',
    ' 4317',
    '4317 ',
    '0',
    '00000',
    '04317',
    1.5,
    -1,
    65536,
  ])
    assert.throws(
      () => listenPort(value),
      error =>
        error.refusal === true &&
        /^PORT must be a whole number from 1 to 65535/.test(error.message),
      JSON.stringify(value)
    );
  // The refusal names the rule a well-formed number breaks: 04317 is 4317, a whole number from
  // 1 to 65535 (1.4.x read it as that), refused only for how it is written.
  for (const value of ['04317', '+4317', '4317.0', '0x10DD'])
    assert.throws(() => listenPort(value), {
      message: `PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is ${quoted(value)}.`,
    });
  assert.equal(listenHost(undefined), '127.0.0.1');
  for (const value of [
    '127.0.0.1',
    '0.0.0.0',
    '::',
    '::1',
    'localhost',
    'orbit-host.lan',
    'fe80::1%eth0',
  ])
    assert.equal(listenHost(value), value);
  for (const value of [' 127.0.0.1', '[::1]', 'a b', '127.0.0.1:4317', 'host\nname', 'a..b', '-x'])
    assert.throws(
      () => listenHost(value),
      error =>
        error.refusal === true && /^HOST must be an IP address or a host name/.test(error.message),
      JSON.stringify(value)
    );
  // The value is shown escaped and cut, never raw.
  assert.throws(
    () => listenPort('1\u001b[2J\n' + '9'.repeat(100)),
    // 93 characters of rule, then at most 40 of the value, escaped.
    error => !unsafe.test(error.message) && error.message.length < 150
  );
});

test('an invalid PORT, HOST or GOBLIN_DATA_DIR refuses the start (78) before goblin.lock or any file exists', async t => {
  const base = temporary(t);
  const cases = [
    ['PORT', { PORT: 'abc' }],
    ['PORT', { PORT: '70000' }],
    ['PORT', { PORT: '4317.5' }],
    ['PORT', { PORT: ' 0x0 ' }],
    ['PORT', { PORT: '1e3' }],
    ['PORT', { PORT: '0' }],
    ['PORT', { PORT: '00000' }],
    ['HOST', { HOST: ' 127.0.0.1' }],
    ['HOST', { HOST: '[::1]' }],
  ];
  for (const [index, [name, env]] of cases.entries()) {
    const directory = path.join(base, `data-${index}`);
    const started = await withEnvironment({ ...env }, () =>
      createApp({ directory, password, startScheduler: false }).then(
        app => app.close().then(() => null),
        error => error
      )
    );
    const error = started.result;
    assert.ok(error?.refusal, `${JSON.stringify(env)}: ${error?.message}`);
    assert.match(error.message, new RegExp(`^${name} must be`));
    assert.equal(fs.existsSync(directory), false, `${JSON.stringify(env)} created the directory`);
  }
  // A data directory with a line break or an escape: never created, never put in a log line.
  const linebreak = path.join(base, 'data\n[orbit] FORGED');
  // A start that is not refused is closed, so the failure is reported instead of a hang.
  const refused = await createApp({ directory: linebreak, password, startScheduler: false }).then(
    app => app.close().then(() => null),
    error => error
  );
  assert.ok(refused?.refusal, refused?.message ?? 'the start was not refused');
  assert.match(
    refused.message,
    /^GOBLIN_DATA_DIR must not contain a control character, .* \(it holds U\+000A\); it is "/
  );
  assert.ok(!unsafe.test(refused.message));
  assert.equal(fs.existsSync(linebreak), false);

  // node server.mjs: exit status 78, at once, and the data directory is never made.
  const data = path.join(base, 'from-main');
  const result = await runServer({
    GOBLIN_DATA_DIR: data,
    GOBLIN_PASSWORD: password,
    PORT: '70000',
  });
  assert.equal(result.code, 78, result.stderr);
  assert.match(
    result.stderr,
    /PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is "70000"\./
  );
  assert.match(result.stderr, /Uptime Goblin refused to start \(exit status 78\)/);
  assert.equal(fs.existsSync(data), false);
});

// GOBLIN_DATA_DIR refused only the C0 and C1 controls and DEL, while the key path rule that reads
// <data>/secret.key also refuses the line and paragraph separators and the text-direction
// embeddings, overrides and isolates: with U+202E in GOBLIN_DATA_DIR the first start ran, printed
// the U+202E raw in its "Encryption key: a new .../secret.key" lines, and every later start
// refused (78). One rule now refuses it at the first start, before anything is written.
test('GOBLIN_DATA_DIR with a line or paragraph separator or a direction override refuses the first start (78), naming the code point', async t => {
  const base = temporary(t);
  const shown = /[\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
  for (const point of [0x2028, 0x2029, 0x202a, 0x202e, 0x2066, 0x2069, 0x85]) {
    const name = `U+${point.toString(16).toUpperCase().padStart(4, '0')}`;
    const directory = path.join(base, `x${String.fromCodePoint(point)}data`);
    const refused = await createApp({ directory, password, startScheduler: false }).then(
      app => app.close().then(() => null),
      error => error
    );
    assert.ok(refused?.refusal, `${name}: ${refused?.message ?? 'the start was not refused'}`);
    assert.equal(
      refused.message,
      `GOBLIN_DATA_DIR must not contain a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (it holds ${name}); it is ${quoted(directory, 80)}.`
    );
    assert.ok(!unsafe.test(refused.message) && !shown.test(refused.message), name);
    assert.equal(fs.existsSync(directory), false, `${name}: the directory was made`);
  }
  // node server.mjs: the first start exits 78 and makes nothing (it ran, then refused the next).
  const data = path.join(base, 'from-main\u202edata');
  const result = await runServer({ GOBLIN_DATA_DIR: data, GOBLIN_PASSWORD: password });
  assert.equal(result.code, 78, result.stdout + result.stderr);
  assert.match(
    result.stderr,
    /^GOBLIN_DATA_DIR must not contain a control character, .* \(it holds U\+202E\); it is "[^"\n]*"\.$/m
  );
  assert.doesNotMatch(result.stdout, /Uptime Goblin is ready at|Encryption key/);
  assert.ok(!shown.test(result.stdout + result.stderr), 'U+202E is printed escaped');
  assert.equal(fs.existsSync(data), false);
});

// Review round 3: the check read GOBLIN_DATA_DIR as given, before path.resolve, so a relative
// one (data, which every release resolves against the working directory) passed while the
// working directory's own path held a line break, U+2028 or U+202E. The first start ran, made
// <data>/secret.key and printed the path raw in its "Encryption key" lines (a line break wrote a
// line of its own); every later start refused that key's path (78). A relative
// GOBLIN_SECRET_KEY_FILE was checked as given too, and its resolved path reached a start warning's
// command line raw. Both are checked as resolved now, at the first start: GOBLIN_DATA_DIR with the
// environment's other settings, before anything is written; GOBLIN_SECRET_KEY_FILE as the start
// reads the key, before it opens the file but after it took goblin.lock (making the data
// directory), as for any refusal of the key, so nothing else is written.
test('a relative GOBLIN_DATA_DIR or GOBLIN_SECRET_KEY_FILE under a working directory holding a line break or U+202E refuses the first start (78), writing nothing (GOBLIN_DATA_DIR) or nothing but goblin.lock (GOBLIN_SECRET_KEY_FILE)', async t => {
  const base = temporary(t);
  const shown = /[\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u;
  for (const [name, character] of [
    ['U+000A', '\n'],
    ['U+202E', '\u{202e}'],
    ['U+2028', '\u{2028}'],
  ]) {
    const cwd = path.join(base, `w${character}[orbit] FORGED`);
    fs.mkdirSync(cwd);
    for (const run of [1, 2]) {
      const result = await runServer({ GOBLIN_DATA_DIR: 'data', GOBLIN_PASSWORD: password }, [], {
        cwd,
      });
      const what = `${name}, start ${run}`;
      assert.equal(result.code, 78, `${what}: ${result.stdout}${result.stderr}`);
      assert.match(
        result.stderr,
        new RegExp(
          `^GOBLIN_DATA_DIR must not contain a control character, .* \\(it holds U\\+${name.slice(2)}\\); it is "data", resolved against the working directory to "[^"\\n]*"\\.$`,
          'm'
        ),
        what
      );
      assert.doesNotMatch(result.stdout, /Uptime Goblin is ready at|Encryption key/, what);
      const output = result.stdout + result.stderr;
      assert.ok(!output.split('\n').some(line => line.startsWith('[orbit] FORGED')), what);
      assert.ok(!unsafe.test(output.replaceAll('\n', '')) && !shown.test(output), what);
      assert.deepEqual(fs.readdirSync(cwd), [], `${what}: nothing was made`);
    }
  }
  // The key file, relative, under such a working directory; the data directory is absolute.
  const cwd = path.join(base, 'k\n[orbit] FORGED-KEY');
  fs.mkdirSync(cwd);
  fs.writeFileSync(path.join(cwd, 'key'), `${'0123456789abcdef'.repeat(4)}\n`, { mode: 0o600 });
  const data = path.join(base, 'key-data');
  const result = await runServer(
    { GOBLIN_DATA_DIR: data, GOBLIN_SECRET_KEY_FILE: 'key', GOBLIN_PASSWORD: password },
    [],
    { cwd }
  );
  assert.equal(result.code, 78, result.stdout + result.stderr);
  assert.match(
    result.stderr,
    /^GOBLIN_SECRET_KEY_FILE must be a path without a control character, .* \(it holds U\+000A\); it is "key", resolved against the working directory to "[^"\n]*"\.$/m
  );
  assert.ok(
    !(result.stdout + result.stderr).split('\n').some(line => line.startsWith('[orbit] FORGED'))
  );
  // No secret.key, no control.sqlite: the data directory holds nothing but goblin.lock, and
  // nothing was made beside the key file.
  const written = fs.existsSync(data) ? fs.readdirSync(data) : [];
  assert.deepEqual(
    written.filter(name => name !== 'goblin.lock' && name !== 'orbit.lock'),
    [],
    `written: ${written.join(', ')}`
  );
  assert.deepEqual(fs.readdirSync(cwd), ['key']);
});

// With GOBLIN_DATA_DIR unset a start uses data/ beside server.mjs, an absolute path checked by
// the same rule: Uptime Goblin installed under a path holding a line break or U+202E refuses the first
// start (78) and makes no data/. The refusal names GOBLIN_DATA_DIR all the same, as
// docs/troubleshooting.md says (goblin-admin names it "The data directory beside Uptime Goblin").
test('Uptime Goblin installed under a path with a line break or U+202E refuses its default data directory (78), writing nothing', async t => {
  const base = temporary(t);
  for (const [name, character] of [
    ['U+000A', '\n'],
    ['U+202E', '\u{202e}'],
  ]) {
    const copy = path.join(base, `orbit${character}[orbit] FORGED`);
    fs.mkdirSync(copy);
    for (const entry of ['server.mjs', 'package.json', 'lib', 'public'])
      fs.cpSync(path.join(repository, entry), path.join(copy, entry), { recursive: true });
    fs.symlinkSync(
      fs.realpathSync(path.join(repository, 'node_modules')),
      path.join(copy, 'node_modules')
    );
    const result = await runServer({ GOBLIN_PASSWORD: password }, [], {
      cwd: base,
      file: path.join(copy, 'server.mjs'),
    });
    assert.equal(result.code, 78, `${name}: ${result.stdout}${result.stderr}`);
    assert.match(
      result.stderr,
      new RegExp(
        `^GOBLIN_DATA_DIR must not contain a control character, .* \\(it holds U\\+${name.slice(2)}\\); it is "[^"\\n]*"\\.$`,
        'm'
      ),
      name
    );
    assert.doesNotMatch(result.stdout, /Uptime Goblin is ready at|Encryption key/, name);
    const output = result.stdout + result.stderr;
    assert.ok(!output.split('\n').some(line => line.startsWith('[orbit] FORGED')), name);
    assert.ok(!unsafe.test(output.replaceAll('\n', '')) && !/\u{202e}/u.test(output), name);
    assert.equal(fs.existsSync(path.join(copy, 'data')), false, `${name}: data/ was made`);
  }
});

test('yes/no flags share one parser: GOBLIN_ALLOW_LOOPBACK=on is on, and a typo warns instead of passing for off', async t => {
  assert.deepEqual(
    ['1', 'true', 'YES', 'on', '0', 'false', 'No', 'OFF', '', undefined, ' 1', 'maybe'].map(
      flagValue
    ),
    [true, true, true, true, false, false, false, false, null, null, undefined, undefined]
  );
  const loopback = 'http://127.0.0.1:9100/metrics';
  try {
    for (const [value, allowed, warned] of [
      ['on', true, false],
      ['1', true, false],
      ['maybe', false, true],
      ['', false, false],
    ]) {
      const directory = temporary(t);
      const { warnings } = await withEnvironment({ GOBLIN_ALLOW_LOOPBACK: value }, async () => {
        const app = await createApp({ directory, password, startScheduler: false });
        await app.close();
      });
      assert.equal((await destinationProblem(loopback)) === null, allowed, value);
      assert.equal(
        warnings.includes(
          `GOBLIN_ALLOW_LOOPBACK=${JSON.stringify(value)} is not 1 or 0; the default applies.`
        ),
        warned,
        warnings.join('\n')
      );
    }
  } finally {
    configureDestinations({ allowLoopback: false });
  }
});

test('GOBLIN_SUPERVISED=on supervises like 1; a value that is neither yes nor no refuses the start', async t => {
  const exitZero = [
    '--import',
    `data:text/javascript,${encodeURIComponent('setTimeout(() => process.exit(0), 1500)')}`,
  ];
  const env = value => ({
    GOBLIN_DATA_DIR: path.join(temporary(t), 'data'),
    GOBLIN_PASSWORD: password,
    // Supervised, the start refuses where this machine does not hold Uptime Goblin's limits
    // (helpers/supervised.mjs).
    GOBLIN_ALLOW_UNLIMITED: supervisedEnv().GOBLIN_ALLOW_UNLIMITED,
    GOBLIN_SUPERVISED: value,
  });
  const supervised = await runServer(env('on'), exitZero, { stay: true });
  assert.equal(supervised.code, 1, 'an exit no stop signal caused is a failure under supervision');
  assert.match(supervised.stderr, /no stop signal/);
  // A typo was taken for off (a warning, then an unsupervised start without the limits check).
  // It turns a security check on, so a typo now refuses the start (78), as a malformed
  // GOBLIN_ALLOW_UNLIMITED does, in the main block before createApp().
  const typo = await runServer(env('maybe'), exitZero, { stay: true });
  assert.equal(typo.code, 78, typo.stdout + typo.stderr);
  assert.deepEqual(typo.stderr.trimEnd().split('\n'), [
    'GOBLIN_SUPERVISED must be 1 or 0 (true, yes or on; false, no or off), or empty; it is "maybe".',
    'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.',
  ]);
  assert.doesNotMatch(typo.stderr, /the default applies/);
});

test('capability flags and GOBLIN_EXPERIMENTAL: names and values are escaped and bounded, unavailable variables are named without their value', () => {
  const forged = 'x\u001b[2Jcleared\nFAKE LOG LINE';
  const features = createFeatures({
    env: {
      GOBLIN_EXPERIMENTAL: [
        forged,
        'y'.repeat(5000),
        ...Array.from({ length: 30 }, (_, i) => `e${i}`),
      ].join(','),
      GOBLIN_INSECURE_HTTP_SESSIONS: 'maybe\u001b]52;c;cHduZWQ=\u0007' + 'z'.repeat(5000),
      // 1.7 and 1.8 capabilities: set, but this release does not have them.
      GOBLIN_DATABASE_URL: 'postgres://orbit:SYNTHETIC-DB-SECRET@db.example/orbit',
      GOBLIN_FORWARD_AUTH_HEADER: 'X-SYNTHETIC-HEADER',
      GOBLIN_STATUS_LISTEN: '0.0.0.0:9000',
    },
    release: '1.5.0',
  });
  const text = features.warnings.join('\n');
  for (const warning of features.warnings) {
    assert.ok(!unsafe.test(warning), JSON.stringify(warning));
    assert.ok(warning.length < 300, `${warning.length} characters`);
  }
  assert.ok(features.warnings.length <= 22, `${features.warnings.length} warnings`);
  assert.ok(
    features.warnings.includes(
      'GOBLIN_EXPERIMENTAL names "x\\u001b[2Jcleared\\nFAKE LOG LINE", which this release does not have; it is ignored.'
    )
  );
  assert.ok(
    features.warnings.includes(
      'GOBLIN_EXPERIMENTAL names 16 more experiments this release does not have; they are ignored.'
    )
  );
  assert.match(
    text,
    /^GOBLIN_INSECURE_HTTP_SESSIONS="maybe\\u001b\]52;c;cHduZWQ=\\u0007z+…" is not 1 or 0; the default applies\.$/m
  );
  for (const name of ['GOBLIN_DATABASE_URL', 'GOBLIN_FORWARD_AUTH_HEADER', 'GOBLIN_STATUS_LISTEN'])
    assert.match(
      text,
      new RegExp(
        `^${name} is set, but this release does not have that feature \\(it comes with 1\\.\\d\\.\\d\\); it is ignored\\.$`,
        'm'
      )
    );
  assert.ok(!text.includes('SYNTHETIC-DB-SECRET') && !text.includes('X-SYNTHETIC-HEADER'));
});

test('unknown GOBLIN_ variables and GOBLIN_COLLECTION_MEMORY_MB are said at the start, by name only', async t => {
  const warnings = unusedVariableWarnings({
    GOBLIN_TRUST_PROXIES: '10.0.0.1',
    'GOBLIN_X\u001b[2J\nFAKE': 'SYNTHETIC-VALUE',
    GOBLIN_COLLECTION_MEMORY_MB: '384',
    GOBLIN_PASSWORD: 'SYNTHETIC-PASSWORD',
    HOME: '/home/someone',
  });
  assert.deepEqual(warnings, [
    'GOBLIN_TRUST_PROXIES is not a setting this release reads; it is ignored (check its spelling).',
    '"GOBLIN_X\\u001b[2J\\nFAKE" is not a setting this release reads; it is ignored (check its spelling).',
    'GOBLIN_COLLECTION_MEMORY_MB is set, but this release does not limit collection memory with it yet; it is ignored.',
  ]);
  const many = Object.fromEntries(
    Array.from({ length: 20 }, (_, i) => [`GOBLIN_UNKNOWN_${i}`, 'x'])
  );
  assert.equal(unusedVariableWarnings(many).length, 9);
  // Through a start.
  const directory = temporary(t);
  const { warnings: started } = await withEnvironment(
    { GOBLIN_TRUST_PROXIES: '10.0.0.1' },
    async () => {
      await (await createApp({ directory, password, startScheduler: false })).close();
    }
  );
  assert.ok(started.includes(warnings[0]), started.join('\n'));
});

// A setting as the deployment files and docs may name it while they move to the new names: its
// GOBLIN_ name, or its ORBIT_ name from before the rename (lib/legacy-names.mjs), as a pattern.
const deployedName = name => `(?:${name}|${name.replace(/^GOBLIN_/, 'ORBIT_')})`;
// compose.yaml passes a setting from .env under its GOBLIN_ name, else its ORBIT_ one (empty
// when neither is set): the line, as a pattern.
// An empty GOBLIN_ value counts as set (`-`), so it never falls back to the ORBIT_ one.
const composeLine = name =>
  `^ {6}${name}: \\$\\{${name}-\\$\\{${name.replace(/^GOBLIN_/, 'ORBIT_')}-\\}\\}$`;

test('every GOBLIN_ variable (or ORBIT_ one, its name before the rename) the documentation and the deployment files name is one Uptime Goblin knows', () => {
  const files = [
    'docs/configuration.md',
    'docs/installation.md',
    'docs/authentication.md',
    'docs/security.md',
    'docs/troubleshooting.md',
    '.env.example',
    'compose.yaml',
    'compose.secret.yaml',
    'Dockerfile',
    'deploy/uptime-goblin.service',
    'deploy/install.sh',
  ];
  const named = new Set(
    files
      .flatMap(
        file =>
          fs
            .readFileSync(path.join(repository, file), 'utf8')
            .match(/\b(?:GOBLIN|ORBIT)_[A-Z0-9_]+/g) ?? []
      )
      .map(name => currentVariableName(name) ?? name)
      // compose.yaml passes each ORBIT_ name of .env under GOBLIN_COMPOSE_LEGACY_ too, which
      // Uptime Goblin only compares with the setting it stands for (lib/legacy-names.mjs).
      .filter(name => name !== COMPOSE_LEGACY_PREFIX)
      .map(name => name.replace(COMPOSE_LEGACY_PREFIX, 'GOBLIN_'))
  );
  const unknown = [...named].filter(name => !knownVariables.includes(name));
  assert.deepEqual(unknown, []);
});

test('GOBLIN_ALLOWED_HOSTS: entries no Host can match are named and ignored; more than 64 refuse', async t => {
  const { hosts, warnings } = allowedHostList(
    ' Goblin.Example ,goblin.example:8443,[::1]:4317,192.0.2.10,*,https://goblin.example,goblin.example/,::1,goblin.example:0,goblin.example:70000,goblin.example,'
  );
  assert.deepEqual(hosts, ['goblin.example', 'goblin.example:8443', '[::1]:4317', '192.0.2.10']);
  assert.deepEqual(
    warnings.map(
      warning => /^GOBLIN_ALLOWED_HOSTS entry (".*?") is not a host name/.exec(warning)?.[1]
    ),
    [
      '"*"',
      '"https://goblin.example"',
      '"goblin.example/"',
      '"::1"',
      '"goblin.example:0"',
      '"goblin.example:70000"',
    ]
  );
  assert.ok(!unsafe.test(allowedHostList('a\u001b[2J\nb').warnings[0]));
  assert.throws(
    () => allowedHostList(Array.from({ length: 65 }, (_, i) => `h${i}.example`).join(',')),
    error => error.refusal === true && /lists 65 hosts; at most 64/.test(error.message)
  );
  // Through a start: the warning, and a request with Host: * is refused (it was allowed). On a
  // free port: 4317, the default, may be held by an Uptime Goblin run with its defaults.
  const directory = temporary(t);
  const { result: app, warnings: said } = await withEnvironment({}, () =>
    createApp({
      directory,
      password,
      port: 0,
      allowedHosts: '*,goblin.example',
      startScheduler: false,
    })
  );
  t.after(() => app.close());
  assert.ok(
    said.some(line => line.startsWith('GOBLIN_ALLOWED_HOSTS entry "*" is not')),
    said.join('\n')
  );
  const { port } = await app.listen();
  const status = host =>
    new Promise((resolve, reject) => {
      import('node:http').then(({ default: http }) =>
        http
          .get({ host: '127.0.0.1', port, path: '/health', headers: { Host: host } }, res => {
            res.resume();
            resolve(res.statusCode);
          })
          .on('error', reject)
      );
    });
  assert.equal(await status('goblin.example'), 200);
  assert.notEqual(await status('*'), 200);
});

test('GOBLIN_TRUST_PROXY refuses ranges wider than /8 or /32, the IPv4-mapped, NAT64, IPv4-translated and IPv4-compatible ones too, and warns on ranges wider than /24 or /64', () => {
  for (const value of [
    '0.0.0.0/0',
    '::/0',
    '10.0.0.1/0',
    '128.0.0.0/1',
    '::ffff:0:0/96',
    '::/80',
    '::ffff:10.0.0.0/100',
    'fc00::/7',
    '2000::/3',
    '192.0.2.10,0.0.0.0/0',
    // NAT64: a gateway connects from 64:ff9b::a.b.c.d for the IPv4 client a.b.c.d, so the
    // prefix, and every range that holds it, is the whole IPv4 internet; inside it, a range is
    // the IPv4 range it stands for (/100 is an IPv4 /4). The local-use 64:ff9b:1::/96 too.
    '64:ff9b::/96',
    '64:ff9b::/64',
    '64:ff9b::/33',
    '64:ff9b::/32',
    '64:ff9b::/100',
    '64:ff9b:1::/96',
    '64:ff9b:1::/48',
    '192.0.2.10,64:ff9b::/96',
    // The other /96 forms lib/destinations.mjs reads: SIIT's IPv4-translated ::ffff:0:a.b.c.d
    // and the deprecated IPv4-compatible ::a.b.c.d, each the IPv4 address in its last 32 bits.
    '::ffff:0:0:0/96',
    '::ffff:0:0:0/100',
    '::/96',
    '::/100',
    '::/64',
    // 6to4 as a whole is a /16 of IPv6: wider than /32.
    '2002::/16',
  ])
    assert.throws(
      () => trustedProxies(value),
      error => error.refusal === true && /trusts too many addresses/.test(error.message),
      value
    );
  assert.throws(
    () => trustedProxies('64:ff9b::/96'),
    error =>
      error.message.startsWith(
        'GOBLIN_TRUST_PROXY entry 64:ff9b::/96 trusts too many addresses (it holds the NAT64 prefix 64:ff9b::/96, which stands for every IPv4 address): every client in a trusted range chooses'
      )
  );
  assert.throws(
    () => trustedProxies('64:ff9b::/100'),
    /trusts too many addresses \(inside the NAT64 prefix 64:ff9b::\/96 it stands for an IPv4 \/4\)/
  );
  for (const [value, name] of [
    ['::ffff:0:0:0/96', 'the IPv4-translated prefix ::ffff:0:0:0/96'],
    ['::/96', 'the IPv4-compatible prefix ::/96'],
  ])
    assert.throws(
      () => trustedProxies(value),
      error =>
        error.message.startsWith(
          `GOBLIN_TRUST_PROXY entry ${value} trusts too many addresses (it holds ${name}, which stands for every IPv4 address): every client in a trusted range chooses`
        ),
      value
    );
  assert.throws(
    () => trustedProxies('::/100'),
    /\(inside the IPv4-compatible prefix ::\/96 it stands for an IPv4 \/4\)/
  );
  // A range that holds more than one: the first it holds is named.
  assert.throws(() => trustedProxies('::/80'), /it holds the IPv4-mapped prefix ::ffff:0:0\/96/);
  // Wider than a /24 of IPv4 or one /64 network of IPv6: a start warning.
  for (const value of [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '192.0.2.0/23',
    '::ffff:10.0.0.0/104',
    '::ffff:192.0.2.0/119',
    '2001:db8::/32',
    '2001:db8::/40',
    '2001:db8::/48',
    '2001:db8::/63',
    '64:ff9b::a00:0/104',
    '64:ff9b::c000:200/119',
    '::ffff:0:a00:0/104',
    '::a00:0/104',
    // A 6to4 range is an IPv6 network, held to the IPv6 widths.
    '2002:c000:201::/48',
  ]) {
    const check = trustedProxies(value);
    assert.equal(check.warnings.length, 1, value);
    assert.match(check.warnings[0], /trusts a wide range/);
  }
  for (const value of [
    'loopback',
    '127.0.0.0/8',
    '192.168.1.0/24',
    '192.0.2.10',
    '2001:db8::/64',
    '2001:db8:0:1::/96',
    '::1',
    '::ffff:127.0.0.0/104',
    '::ffff:192.0.2.0/120',
    '64:ff9b::c000:200/120',
    '64:ff9b::c000:201',
    '::ffff:0:c000:201',
    '::c000:201',
    '::',
    '2002:c000:201::/64',
  ])
    assert.deepEqual(trustedProxies(value).warnings, [], value);
  // A NAT64 address is the IPv4 client it stands for, never loopback.
  assert.equal(trustedProxies('64:ff9b::c000:201')('64:ff9b::c000:201'), true);
  assert.equal(trustedProxies('64:ff9b::c000:201')('192.0.2.1'), false);
  // The parser still trusts what it was given.
  assert.equal(trustedProxies('10.0.0.0/8')('10.1.2.3'), true);
  assert.equal(trustedProxies('10.0.0.0/8')('198.51.100.7'), false);
  // Many ranges, each within the limit, trusted every client as 0.0.0.0/0 does: together they
  // may cover at most two /8 (or /32) ranges, and the list holds at most 64 entries.
  const slash8 = Array.from({ length: 256 }, (_, i) => `${i}.0.0.0/8`);
  for (const value of [
    slash8.slice(10, 13).join(','),
    Array.from({ length: 3 }, (_, i) => `::ffff:${i + 10}.0.0.0/104`).join(','),
    Array.from({ length: 3 }, (_, i) => `64:ff9b::${i + 10}.0.0.0/104`).join(','),
    '10.0.0.0/8,11.0.0.0/8,64:ff9b::c000:201',
    '10.0.0.0/8,11.0.0.0/8,::ffff:0:c000:201',
    // ::2 is IPv4-compatible: 0.0.0.2, one more IPv4 address.
    '10.0.0.0/8,11.0.0.0/8,::2',
    '2001:db8::/32,2001:db9::/32,2001:dba::/32',
  ])
    assert.throws(
      () => trustedProxies(value),
      error => error.refusal === true && /trusts too many addresses in all/.test(error.message),
      value
    );
  const many = Array.from({ length: 65 }, (_, i) => `192.0.2.${i}`).join(',');
  assert.throws(
    () => trustedProxies(many),
    error => error.refusal === true && /has 65 entries; at most 64 are allowed/.test(error.message)
  );
  assert.throws(() => trustedProxies(slash8.join(',')), /has 256 entries/);
  // What a homelab names stays allowed: the private ranges and CGNAT together, loopback beside
  // them (not counted: no other host connects from it), and 64 single addresses.
  const lan = trustedProxies('loopback,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10');
  assert.equal(lan('100.64.1.2'), true);
  assert.equal(lan('203.0.113.9'), false);
  assert.equal(trustedProxies(many.split(',').slice(0, 64).join(','))('192.0.2.63'), true);
  // Loopback written as an address or a range is not counted either: each list below is at or
  // over the limit only if it were (10.0.0.0/8 and 11.0.0.0/8 are the two /8 ranges allowed).
  for (const value of [
    '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10',
    '10.0.0.0/8,11.0.0.0/8,127.0.0.1',
    '::ffff:127.0.0.0/104,10.0.0.0/8,11.0.0.0/8',
    '10.0.0.0/8,11.0.0.0/8,::ffff:127.0.0.1',
    '2001:db8::/32,2001:db9::/32,::1',
    // ::1 and :: alone are IPv6 (loopback, unspecified), not the IPv4-compatible 0.0.0.1 and
    // 0.0.0.0: neither counts against the IPv4 ranges (::1, loopback, counts nowhere).
    '10.0.0.0/8,11.0.0.0/8,::1',
    '10.0.0.0/8,11.0.0.0/8,::1/128',
    '10.0.0.0/8,11.0.0.0/8,::',
  ])
    assert.equal(typeof trustedProxies(value), 'function', value);
  for (const value of ['::1', '::1/128']) {
    assert.deepEqual(trustedProxies(value).warnings, [], value);
    assert.equal(trustedProxies(value)('::1'), true, value);
    assert.equal(trustedProxies(value)('0.0.0.1'), false, value);
  }
  // Only loopback: one more address anywhere else is over the limit.
  for (const value of [
    '10.0.0.0/8,11.0.0.0/8,126.0.0.1',
    '2001:db8::/32,2001:db9::/32,2001:dba::1',
  ])
    assert.throws(() => trustedProxies(value), /trusts too many addresses in all/, value);
});

test('a start with GOBLIN_TRUST_PROXY=0.0.0.0/0 refuses (78); a wide range starts with its warning', async t => {
  const result = await runServer({
    GOBLIN_DATA_DIR: path.join(temporary(t), 'data'),
    GOBLIN_PASSWORD: password,
    GOBLIN_TRUST_PROXY: '0.0.0.0/0,::/0',
  });
  assert.equal(result.code, 78, result.stderr);
  assert.match(result.stderr, /GOBLIN_TRUST_PROXY entry 0\.0\.0\.0\/0 trusts too many addresses/);
  const directory = temporary(t);
  const { warnings } = await withEnvironment({}, async () => {
    await (
      await createApp({ directory, password, trustProxy: '172.16.0.0/12', startScheduler: false })
    ).close();
  });
  assert.ok(
    warnings.some(line =>
      line.startsWith('GOBLIN_TRUST_PROXY entry 172.16.0.0/12 trusts a wide range')
    ),
    warnings.join('\n')
  );
});

// The NAT64 prefix (every IPv4 address) and a per-client connection share that cannot work are
// refused like the other environment settings: at the start, before anything is written.
test('GOBLIN_TRUST_PROXY=64:ff9b::/96 or an invalid GOBLIN_MAX_CONNECTIONS_PER_CLIENT refuses the start before any file exists', async t => {
  const base = temporary(t);
  const cases = [
    [
      'GOBLIN_TRUST_PROXY entry 64:ff9b::/96 trusts too many addresses',
      { GOBLIN_TRUST_PROXY: '64:ff9b::/96' },
    ],
    [
      'GOBLIN_TRUST_PROXY entry 64:ff9b::/64 trusts too many addresses',
      { GOBLIN_TRUST_PROXY: 'loopback,64:ff9b::/64' },
    ],
    ['GOBLIN_MAX_CONNECTIONS_PER_CLIENT must be', { GOBLIN_MAX_CONNECTIONS_PER_CLIENT: '0' }],
    ['GOBLIN_MAX_CONNECTIONS_PER_CLIENT must be', { GOBLIN_MAX_CONNECTIONS_PER_CLIENT: '1000' }],
    ['GOBLIN_MAX_CONNECTIONS_PER_CLIENT must be', { GOBLIN_MAX_CONNECTIONS_PER_CLIENT: 'many' }],
    ['GOBLIN_DISPLAY_SESSION_DAYS must be', { GOBLIN_DISPLAY_SESSION_DAYS: '31' }],
    ['GOBLIN_DISPLAY_IDLE_DAYS must be', { GOBLIN_DISPLAY_IDLE_DAYS: '14' }],
  ];
  for (const [index, [start, env]] of cases.entries()) {
    const directory = path.join(base, `data-${index}`);
    const started = await withEnvironment({ ...env }, () =>
      createApp({ directory, password, startScheduler: false }).then(
        app => app.close().then(() => null),
        error => error
      )
    );
    const error = started.result;
    assert.ok(error?.refusal, `${JSON.stringify(env)}: ${error?.message}`);
    assert.ok(error.message.startsWith(start), error.message);
    assert.equal(fs.existsSync(directory), false, `${JSON.stringify(env)} created the directory`);
  }
  // Set and valid, it starts without a word about it; the documentation names it (knownVariables).
  const directory = path.join(base, 'valid');
  const { warnings } = await withEnvironment(
    { GOBLIN_MAX_CONNECTIONS_PER_CLIENT: '64' },
    async () => {
      await (await createApp({ directory, password, startScheduler: false })).close();
    }
  );
  assert.deepEqual(
    warnings.filter(line => line.includes('GOBLIN_MAX_CONNECTIONS_PER_CLIENT')),
    []
  );
  assert.ok(knownVariables.includes('GOBLIN_MAX_CONNECTIONS_PER_CLIENT'));
  // Docker Compose passes only the variables it lists: it passes this one from .env, empty (the
  // default) unless set there, and .env.example names it.
  assert.match(
    fs.readFileSync(path.join(repository, 'compose.yaml'), 'utf8'),
    new RegExp(composeLine('GOBLIN_MAX_CONNECTIONS_PER_CLIENT'), 'm')
  );
  assert.match(
    fs.readFileSync(path.join(repository, '.env.example'), 'utf8'),
    new RegExp(`^# ${deployedName('GOBLIN_MAX_CONNECTIONS_PER_CLIENT')}=32$`, 'm')
  );
});

test('GOBLIN_DISPLAY_SESSION_DAYS and GOBLIN_DISPLAY_IDLE_DAYS: whole days in range, idle never past the limit', () => {
  const day = 86400e3;
  assert.deepEqual(displaySessionLimits({}), { absoluteMs: 30 * day, idleMs: 7 * day });
  assert.deepEqual(
    displaySessionLimits({ GOBLIN_DISPLAY_SESSION_DAYS: '', GOBLIN_DISPLAY_IDLE_DAYS: '' }),
    { absoluteMs: 30 * day, idleMs: 7 * day }
  );
  assert.deepEqual(
    displaySessionLimits({ GOBLIN_DISPLAY_SESSION_DAYS: '14', GOBLIN_DISPLAY_IDLE_DAYS: '1' }),
    { absoluteMs: 14 * day, idleMs: day }
  );
  // The idle limit never outlasts the session's.
  assert.deepEqual(
    displaySessionLimits({ GOBLIN_DISPLAY_SESSION_DAYS: '3', GOBLIN_DISPLAY_IDLE_DAYS: '7' }),
    { absoluteMs: 3 * day, idleMs: 3 * day }
  );
  for (const [name, value] of [
    ['GOBLIN_DISPLAY_SESSION_DAYS', '0'],
    ['GOBLIN_DISPLAY_SESSION_DAYS', '31'],
    ['GOBLIN_DISPLAY_SESSION_DAYS', '30.5'],
    ['GOBLIN_DISPLAY_SESSION_DAYS', ' 30'],
    ['GOBLIN_DISPLAY_SESSION_DAYS', '1e1'],
    ['GOBLIN_DISPLAY_IDLE_DAYS', '0'],
    ['GOBLIN_DISPLAY_IDLE_DAYS', '8'],
    ['GOBLIN_DISPLAY_IDLE_DAYS', '30'],
    ['GOBLIN_DISPLAY_IDLE_DAYS', 'week'],
  ])
    assert.throws(
      () => displaySessionLimits({ [name]: value }),
      error => error.refusal === true && error.message.startsWith(`${name} must be a whole number`),
      `${name}=${value}`
    );
  for (const name of ['GOBLIN_DISPLAY_SESSION_DAYS', 'GOBLIN_DISPLAY_IDLE_DAYS']) {
    assert.ok(knownVariables.includes(name), name);
    assert.match(
      fs.readFileSync(path.join(repository, 'compose.yaml'), 'utf8'),
      new RegExp(composeLine(name), 'm')
    );
  }
});

test('plain-HTTP sign-in on an address the network reaches is said at every start; Compose names where it publishes', async t => {
  assert.equal(plainHttpWarning({ insecureHttpSessions: false, host: '0.0.0.0' }), null);
  assert.equal(plainHttpWarning({ insecureHttpSessions: true, host: '127.0.0.1' }), null);
  assert.equal(
    plainHttpWarning({ insecureHttpSessions: true, host: '0.0.0.0', published: '127.0.0.1' }),
    null
  );
  assert.equal(
    plainHttpWarning({ insecureHttpSessions: true, host: '0.0.0.0', published: '[::1]' }),
    null
  );
  assert.match(
    plainHttpWarning({ insecureHttpSessions: true, host: '0.0.0.0', published: '0.0.0.0' }),
    /^Plain-HTTP sign-in is allowed \(GOBLIN_INSECURE_HTTP_SESSIONS\) and Docker Compose publishes Uptime Goblin on "0\.0\.0\.0" \(GOBLIN_BIND_ADDRESS\)/
  );
  assert.match(
    plainHttpWarning({ insecureHttpSessions: true, host: '192.0.2.5' }),
    /and Uptime Goblin listens on "192\.0\.2\.5" \(HOST\)/
  );
  // The same opt-in admits legacy Basic on plain HTTP: while Basic is on, the warning names the
  // password every such script sends too.
  assert.equal(
    plainHttpWarning({ insecureHttpSessions: true, legacyBasic: true, host: '192.0.2.5' }),
    'Plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS) and Uptime Goblin listens on "192.0.2.5" (HOST), so the password at each sign-in, the password each script sends with HTTP Basic (GOBLIN_LEGACY_BASIC) and the sign-in cookie cross that network unencrypted. Serve Uptime Goblin through an HTTPS proxy and set GOBLIN_INSECURE_HTTP_SESSIONS=0, or keep it on a network you trust.'
  );
  assert.doesNotMatch(
    plainHttpWarning({ insecureHttpSessions: true, legacyBasic: false, host: '192.0.2.5' }),
    /HTTP Basic/
  );
  assert.equal(
    plainHttpWarning({ insecureHttpSessions: true, legacyBasic: true, host: '127.0.0.1' }),
    null
  );
  // Through a start, as Compose passes it.
  const directory = temporary(t);
  const { warnings } = await withEnvironment({ GOBLIN_PUBLISHED_ADDRESS: '0.0.0.0' }, async () => {
    await (
      await createApp({ directory, password, insecureHttpSessions: true, startScheduler: false })
    ).close();
  });
  assert.ok(
    warnings.some(line => line.startsWith('Plain-HTTP sign-in is allowed')),
    warnings.join('\n')
  );
});

// The maintainer's decision of 2026-11-12: the 1.5 upgrade never turns plain-HTTP sign-in on silently.
// compose.yaml passes compose-default while .env does not set GOBLIN_INSECURE_HTTP_SESSIONS (it
// passed 1): on only where the network cannot see it (a loopback publish), off behind a proxy
// GOBLIN_TRUST_PROXY names, and otherwise a refusal. One rule for the start and the features.
test('GOBLIN_INSECURE_HTTP_SESSIONS=compose-default: on for a loopback publish, off behind a trusted proxy, otherwise a refusal; yes and no decide as written; outside Compose it is no yes or no', async () => {
  assert.equal(composeDefault, 'compose-default');
  const setting = (value, published, trust) =>
    insecureHttpSessionsSetting({
      GOBLIN_INSECURE_HTTP_SESSIONS: value,
      GOBLIN_PUBLISHED_ADDRESS: published,
      GOBLIN_TRUST_PROXY: trust,
    });
  // The features agree, never throw, and warn only about a value that is no yes or no.
  const features = (value, published, trust) =>
    createFeatures({
      env: Object.fromEntries(
        Object.entries({
          GOBLIN_INSECURE_HTTP_SESSIONS: value,
          GOBLIN_PUBLISHED_ADDRESS: published,
          GOBLIN_TRUST_PROXY: trust,
        }).filter(([, text]) => text !== undefined)
      ),
      release: '1.5.0',
    });
  const agrees = async (value, published, trust) => {
    const decided = setting(value, published, trust);
    const flags = features(value, published, trust);
    assert.equal(await flags.enabled('insecureHttpSessions'), decided.enabled);
    const row = (await flags.list()).find(entry => entry.name === 'insecureHttpSessions');
    assert.deepEqual([row.enabled, row.source], [decided.enabled, decided.source]);
    assert.deepEqual(flags.warnings, decided.warning ? [decided.warning] : []);
    return decided;
  };

  // Published on loopback (the Compose default, which only the Docker host reaches): on, with
  // or without a proxy.
  for (const published of ['127.0.0.1', '127.8.9.10', '::1', '[::1]', '0:0:0:0:0:0:0:1'])
    for (const trust of [undefined, '', '172.17.0.1'])
      assert.deepEqual(await agrees(composeDefault, published, trust), {
        enabled: true,
        source: 'compose',
      });
  // Anywhere else, a malformed address included (fail closed): off behind a trusted proxy …
  const elsewhere = [
    '0.0.0.0',
    '192.0.2.5',
    '::',
    '[2001:db8::1]',
    'localhost',
    ' 127.0.0.1',
    '127.0.0.1 ',
    '127.1',
    '127.0.0.256',
    '::ffff:127.0.0.1',
    '127.0.0.1:4317',
    'x\u001b[2J\nFAKE LOG LINE',
  ];
  for (const published of elsewhere) {
    for (const trust of ['192.0.2.1', 'loopback', '1', '10.0.0.0/24, 192.0.2.1'])
      assert.deepEqual(await agrees(composeDefault, published, trust), {
        enabled: false,
        source: 'compose',
      });
    // … and a refusal without one, that says where and the three ways on.
    for (const trust of [undefined, '', '0', 'off', 'No', ' , '])
      assert.match(
        (await agrees(composeDefault, published, trust)).refusal,
        /^Docker Compose publishes Uptime Goblin on ".*" \(GOBLIN_BIND_ADDRESS\), which is not a loopback address, with no reverse proxy Uptime Goblin trusts \(GOBLIN_TRUST_PROXY\)/
      );
    const { refusal } = setting(composeDefault, published, '');
    assert.ok(refusal.includes(quoted(published, 64)), refusal);
    assert.ok(!unsafe.test(refusal), JSON.stringify(refusal));
  }
  assert.equal(
    setting(composeDefault, '192.0.2.5', '').refusal,
    'Docker Compose publishes Uptime Goblin on "192.0.2.5" (GOBLIN_BIND_ADDRESS), which is not a loopback address, with no reverse proxy Uptime Goblin trusts (GOBLIN_TRUST_PROXY), so browsers and scripts would sign in over plain HTTP and the network would see each password and sign-in cookie. Uptime Goblin allows that only when you choose it. In .env, either serve Uptime Goblin over HTTPS through a reverse proxy and set GOBLIN_TRUST_PROXY to the address it connects from (it must send X-Forwarded-Proto; nginx: proxy_set_header X-Forwarded-Proto $scheme;), or set GOBLIN_INSECURE_HTTP_SESSIONS=1 to keep sign-in over plain HTTP on that network (the password and the sign-in cookie cross it unencrypted), or set GOBLIN_INSECURE_HTTP_SESSIONS=0 to refuse it. Then run docker compose up -d.'
  );

  // 1 and 0 (and the other yes/no spellings) decide as written, wherever the port is published
  // and whatever GOBLIN_TRUST_PROXY says; an empty or unset value is off.
  for (const published of [undefined, '', '127.0.0.1', '192.0.2.5'])
    for (const trust of [undefined, '192.0.2.1']) {
      for (const on of ['1', 'true', 'YES', 'On'])
        assert.deepEqual(await agrees(on, published, trust), { enabled: true, source: 'env' });
      for (const off of ['0', 'false', 'no', 'OFF'])
        assert.deepEqual(await agrees(off, published, trust), { enabled: false, source: 'env' });
      for (const unset of [undefined, ''])
        assert.deepEqual(await agrees(unset, published, trust), {
          enabled: false,
          source: 'default',
        });
    }
  // compose-default without GOBLIN_PUBLISHED_ADDRESS (outside Compose), and anything only like
  // it, is a value that is neither yes nor no: a warning, and off.
  for (const [value, published] of [
    [composeDefault, undefined],
    [composeDefault, ''],
    ['Compose-Default', '127.0.0.1'],
    [' compose-default', '127.0.0.1'],
    ['compose-default ', '127.0.0.1'],
  ])
    assert.deepEqual(await agrees(value, published, undefined), {
      enabled: false,
      source: 'default',
      warning: `GOBLIN_INSECURE_HTTP_SESSIONS=${quoted(value)} is not 1 or 0; the default applies.`,
    });

  // The two helpers it is made of.
  for (const address of ['127.0.0.1', '127.255.255.255', '::1', '[::1]', '0::1'])
    assert.equal(loopbackPublished(address), true, address);
  for (const address of [undefined, '', '0.0.0.0', '128.0.0.1', 'localhost', '[127.0.0.1]', '::2'])
    assert.equal(loopbackPublished(address), false, String(address));
  for (const value of [true, 'loopback', '1', '192.0.2.1', ' 192.0.2.1 ', ',192.0.2.1'])
    assert.equal(namesProxy(value), true, String(value));
  for (const value of [undefined, null, false, '', '0', 'false', 'NO', ' off ', ',', ' , '])
    assert.equal(namesProxy(value), false, String(value));
});

test('plain-HTTP sign-in on loopback is said at the start too while a proxy or a host beyond loopback could relay plain HTTP; the Compose loopback default stays quiet', async t => {
  const loopbackWarning = (on, reasons, basic = '') =>
    `Plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS). ${on} on loopback only, but ${reasons}: a sign-in that a proxy relays without telling Uptime Goblin it used HTTPS (X-Forwarded-Proto) is accepted as plain HTTP, so where that proxy takes plain HTTP from the network, the password at each sign-in${basic} and the sign-in cookie cross it unencrypted. Make the proxy serve HTTPS and send X-Forwarded-Proto (GOBLIN_TRUST_PROXY must name it), then set GOBLIN_INSECURE_HTTP_SESSIONS=0.`;
  const compose = { host: '0.0.0.0', published: '127.0.0.1' };
  // Quiet: Compose's loopback default with no proxy and no other host, natively on loopback
  // alike, and with GOBLIN_TRUST_PROXY off or empty.
  for (const where of [compose, { host: '127.0.0.1' }, { host: '::1' }, { host: 'localhost' }])
    for (const trustProxy of [undefined, '', '0', 'off', ' , '])
      for (const allowedHosts of [
        undefined,
        [],
        ['localhost:4317'],
        ['localhost', '127.0.0.1:4317', '127.0.0.2', '[::1]:4317'],
      ])
        assert.equal(
          plainHttpWarning({ insecureHttpSessions: true, ...where, trustProxy, allowedHosts }),
          null,
          JSON.stringify({ where, trustProxy, allowedHosts })
        );
  // A proxy that GOBLIN_TRUST_PROXY names, a host beyond loopback, or both.
  assert.equal(
    plainHttpWarning({ insecureHttpSessions: true, ...compose, trustProxy: '172.17.0.1' }),
    loopbackWarning(
      'Docker Compose publishes Uptime Goblin',
      'GOBLIN_TRUST_PROXY names a reverse proxy'
    )
  );
  assert.equal(
    plainHttpWarning({
      insecureHttpSessions: true,
      host: '127.0.0.1',
      allowedHosts: ['localhost:4317', 'goblin.example'],
    }),
    loopbackWarning('Uptime Goblin listens', 'GOBLIN_ALLOWED_HOSTS names "goblin.example"')
  );
  assert.equal(
    plainHttpWarning({
      insecureHttpSessions: true,
      legacyBasic: true,
      host: '127.0.0.1',
      trustProxy: 'loopback',
      allowedHosts: ['[2001:db8::1]:4317'],
    }),
    loopbackWarning(
      'Uptime Goblin listens',
      'GOBLIN_TRUST_PROXY names a reverse proxy and GOBLIN_ALLOWED_HOSTS names "[2001:db8::1]:4317"',
      ', the password each script sends with HTTP Basic (GOBLIN_LEGACY_BASIC)'
    )
  );
  for (const host of ['192.0.2.5', '127.0.0.1.nip.io', 'localhost.', '127.999.0.1'])
    assert.match(
      plainHttpWarning({ insecureHttpSessions: true, ...compose, allowedHosts: [host] }),
      /^Plain-HTTP sign-in is allowed \(GOBLIN_INSECURE_HTTP_SESSIONS\)\. Docker Compose publishes Uptime Goblin on loopback only, but GOBLIN_ALLOWED_HOSTS names /,
      host
    );
  // Off: no warning, whatever the proxy and hosts.
  assert.equal(
    plainHttpWarning({
      insecureHttpSessions: false,
      host: '127.0.0.1',
      trustProxy: 'loopback',
      allowedHosts: ['goblin.example'],
    }),
    null
  );
  // A published address that is not a loopback IP address is the network warning.
  assert.match(
    plainHttpWarning({ insecureHttpSessions: true, host: '0.0.0.0', published: 'localhost' }),
    /^Plain-HTTP sign-in is allowed \(GOBLIN_INSECURE_HTTP_SESSIONS\) and Docker Compose publishes Uptime Goblin on "localhost" \(GOBLIN_BIND_ADDRESS\)/
  );
  // It quotes the published address as it was judged: untrimmed (" 127.0.0.1" is not loopback)
  // and with its brackets.
  for (const published of [' 127.0.0.1', '127.0.0.1 ', '[2001:db8::1]']) {
    const warning = plainHttpWarning({ insecureHttpSessions: true, host: '0.0.0.0', published });
    assert.ok(
      warning.startsWith(
        `Plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS) and Docker Compose publishes Uptime Goblin on ${quoted(published, 64)} (GOBLIN_BIND_ADDRESS), `
      ),
      warning
    );
  }
  // Through a start, as Compose runs it: quiet by default, the warning with a trusted proxy;
  // plain-HTTP sign-in is on in both (the start line says so).
  const directory = temporary(t);
  const log = t.mock.method(console, 'log', () => {});
  const started = options =>
    withEnvironment(
      {
        GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1',
        GOBLIN_INSECURE_HTTP_SESSIONS: composeDefault,
        GOBLIN_TRUST_PROXY: undefined,
      },
      async () => {
        const app = await createApp({
          directory,
          password,
          host: '0.0.0.0',
          port: 0,
          startScheduler: false,
          allowedHosts: 'localhost:4317',
          legacyBasic: false,
          ...options,
        });
        await app.close();
      }
    );
  const quiet = await started({ trustProxy: '' });
  assert.ok(
    !quiet.warnings.some(line => line.startsWith('Plain-HTTP sign-in is allowed')),
    quiet.warnings.join('\n')
  );
  const proxied = await started({ trustProxy: '172.17.0.1' });
  assert.ok(
    proxied.warnings.includes(
      loopbackWarning(
        'Docker Compose publishes Uptime Goblin',
        'GOBLIN_TRUST_PROXY names a reverse proxy'
      )
    ),
    proxied.warnings.join('\n')
  );
  const lines = log.mock.calls.map(call => String(call.arguments[0]));
  assert.equal(
    lines.filter(line => / · plain-HTTP sessions: allowed$/.test(line)).length,
    2,
    lines.join('\n')
  );
});

// createApp reads GOBLIN_INSECURE_HTTP_SESSIONS once, with the published address and trusted
// proxies it was given: the refusal and the flag the start uses come from the same values, also
// when a caller passes them instead of the environment (review of change C, G3.1).
test('the start takes plain-HTTP sign-in from the published address and proxy it was given, the values its refusal reads', async t => {
  const directory = temporary(t);
  const log = t.mock.method(console, 'log', () => {});
  const startLine = async (environment, options) => {
    const before = log.mock.callCount();
    const { warnings } = await withEnvironment(
      {
        GOBLIN_INSECURE_HTTP_SESSIONS: composeDefault,
        GOBLIN_TRUST_PROXY: undefined,
        ...environment,
      },
      async () => {
        const app = await createApp({
          directory,
          password,
          host: '0.0.0.0',
          port: 0,
          startScheduler: false,
          allowedHosts: 'localhost:4317',
          legacyBasic: false,
          ...options,
        });
        await app.close();
      }
    );
    const lines = log.mock.calls.slice(before).map(call => String(call.arguments[0]));
    return { line: lines.find(text => text.startsWith('Sign-in:')), warnings };
  };
  // The environment says loopback (on), the call a LAN address behind a trusted proxy (off).
  const proxied = await startLine(
    { GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1' },
    { publishedAddress: '192.0.2.5', trustProxy: '192.0.2.1' }
  );
  assert.match(proxied.line, / · plain-HTTP sessions: refused$/);
  // The environment says a LAN address with no proxy (a refusal), the call loopback (on).
  const loopback = await startLine(
    { GOBLIN_PUBLISHED_ADDRESS: '192.0.2.5' },
    { publishedAddress: '127.0.0.1', trustProxy: '' }
  );
  assert.match(loopback.line, / · plain-HTTP sessions: allowed$/);
  assert.ok(
    !loopback.warnings.some(line => line.startsWith('Plain-HTTP sign-in is allowed')),
    loopback.warnings.join('\n')
  );
  // `insecureHttpSessions`, when given, still decides the flag.
  const given = await startLine(
    { GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1' },
    { insecureHttpSessions: false, trustProxy: '' }
  );
  assert.match(given.line, / · plain-HTTP sessions: refused$/);
});

test('an environment file Node loaded that others can read is warned about, with the command that fixes it', t => {
  const directory = temporary(t);
  const file = path.join(directory, 'my env');
  fs.writeFileSync(file, "GOBLIN_PASSWORD='synthetic'\n", { mode: 0o644 });
  fs.chmodSync(file, 0o644);
  for (const execArgv of [
    ['--env-file-if-exists=my env'],
    ['--env-file', 'my env'],
    [`--env-file=${file}`],
  ])
    assert.deepEqual(envFileWarnings({ execArgv, cwd: directory }), [
      `${file} (mode 0644) can be read by other users of this computer, and it holds GOBLIN_PASSWORD: make it private with chmod 600 '${file}'.`,
    ]);
  fs.chmodSync(file, 0o600);
  assert.deepEqual(envFileWarnings({ execArgv: [`--env-file=${file}`], cwd: directory }), []);
  assert.deepEqual(envFileWarnings({ execArgv: ['--env-file=missing'], cwd: directory }), []);
});

// The file is resolved against the working directory: a line break or an escape in that path
// was printed raw, twice (the path and the chmod command), each writing a line of its own.
test('an environment file warning shows a path holding a control character or U+202E escaped, with no command to paste', t => {
  const base = temporary(t);
  for (const [name, character] of [
    ['U+000A', '\n'],
    ['U+202E', '\u{202e}'],
  ]) {
    const directory = path.join(base, `w${character}[orbit] FORGED`);
    fs.mkdirSync(directory);
    const file = path.join(directory, '.env');
    fs.writeFileSync(file, "GOBLIN_PASSWORD='synthetic'\n", { mode: 0o644 });
    fs.chmodSync(file, 0o644);
    const warnings = envFileWarnings({ execArgv: ['--env-file-if-exists=.env'], cwd: directory });
    assert.deepEqual(warnings, [
      `${quoted(file, 200)} (mode 0644) can be read by other users of this computer, and it holds GOBLIN_PASSWORD: make it private with chmod 600 (its path, shown escaped, holds a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (it holds ${name})).`,
    ]);
    assert.ok(!warnings[0].includes(character), name);
  }
});

// goblin-admin --json: the C1 controls, DEL, U+2028, U+2029 and the direction embeddings,
// overrides and isolates, which JSON.stringify writes as they are, become \u escapes; the JSON
// still parses back to exactly the value.
test('jsonText escapes what JSON.stringify leaves raw and parses back to the same value', () => {
  const raw =
    /[\u0000-\u0009\u000b-\u001f\u{7f}-\u{9f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u;
  const text = Array.from({ length: 0x2100 }, (_, point) =>
    point >= 0xd800 && point <= 0xdfff ? '' : String.fromCodePoint(point)
  ).join('');
  const value = { text, list: [text, { [text.slice(0x80, 0xa0)]: 'key' }], n: 1, none: null };
  for (const space of [2, 0]) {
    const json = jsonText(value, space);
    assert.ok(!raw.test(json), `space ${space}`);
    assert.deepEqual(JSON.parse(json), value);
  }
  assert.equal(jsonText({ a: 'x\u{202e}y\u009b' }, 0), '{"a":"x\\u202ey\\u009b"}');
  // The direction marks stay: they override nothing (as in quoted and unprintableProblem).
  assert.equal(jsonText('\u{200e}', 0), '"\u{200e}"');
});

test('npm start: a .env others can read is warned about at the start', async t => {
  const directory = temporary(t);
  const file = path.join(directory, '.env');
  fs.writeFileSync(file, `GOBLIN_PASSWORD='${password}'\n`);
  fs.chmodSync(file, 0o644);
  const result = await runServer({ GOBLIN_DATA_DIR: path.join(directory, 'data') }, [
    `--env-file-if-exists=${file}`,
  ]);
  assert.match(result.stdout, /Uptime Goblin is ready at/, result.stderr);
  assert.ok(
    result.stderr.includes(`${file} (mode 0644) can be read by other users of this computer`),
    result.stderr
  );
  assert.ok(!result.stderr.includes(password));
});

test('.env.example keeps GOBLIN_PASSWORD in single quotes and says why', () => {
  const example = fs.readFileSync(path.join(repository, '.env.example'), 'utf8');
  assert.match(example, new RegExp(`^${deployedName('GOBLIN_PASSWORD')}=''$`, 'm'));
  assert.match(example.replace(/\n# ?/g, ' '), /npm start would end an unquoted value at a #/);
});

test('the healthcheck: an invalid PORT is a failed probe with a reason, never an exception', async t => {
  // 0 included: listenPort gives a number, and http.request takes the number 0 for its default
  // port, 80, so it would probe whatever answers there (1.4.3 passed the text "0", which it
  // tried as port 0, and reported Uptime Goblin unreachable).
  for (const port of ['abc', '99999', '-1', '4317\r\nX-Injected: 1', '0', '00000', '04317'])
    assert.deepEqual(await probe({ host: '127.0.0.1', port }), {
      ready: false,
      reason: `PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is ${quoted(port)}`,
    });
  // An address http.request itself refuses at once (it throws, before any lookup) is a failed
  // probe too, with the reason it gives.
  const odd = await probe({ host: '127.0.0.1\u0000', port: '4317', timeoutMs: 500 });
  assert.deepEqual(odd, { ready: false, reason: 'invalid HOST or PORT (ERR_INVALID_ARG_VALUE)' });
});

test('the healthcheck: a status record whose version or build no release writes is no record, and never printed', t => {
  const directory = temporary(t);
  fs.mkdirSync(path.join(directory, 'run'));
  const write = fields =>
    fs.writeFileSync(
      path.join(directory, 'run', 'status.json'),
      JSON.stringify({
        version: '1.5.0',
        build: 'abcdef123456',
        pid: 4242,
        nonce: 'a'.repeat(32),
        ...fields,
      })
    );
  write({});
  assert.equal(readStatus(directory)?.version, '1.5.0');
  for (const fields of [
    { version: '1.5.0\u001b]52;c;cHduZWQ=\u0007\u001b[2J' },
    { version: '1.5.0\n[orbit] FORGED' },
    { version: 'banana' },
    { build: 'abc\u001b[2J' },
    { build: 'not-hex' },
  ]) {
    write(fields);
    assert.equal(readStatus(directory), null, JSON.stringify(fields));
  }
});
