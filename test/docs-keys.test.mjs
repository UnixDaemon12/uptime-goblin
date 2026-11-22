// The encryption key docs against the code and the commands they print (1.5 docs audit, area
// "keys", and release blocker B13: key files private from their first byte, what to do when the
// key or a copy of the data leaks, the systemd credential advice). Each test reads the texts and
// runs what they describe, so a change to either that makes the docs wrong fails here.
import { currentNames, isDeploymentFile } from './helpers/deployed-names.mjs';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { main, commands, exitCodes } from '../lib/cli/goblin-admin.mjs';
import { keyHooks } from '../lib/cli/commands/key.mjs';
import { reportLines } from '../lib/cli/commands/verify-audit.mjs';
import { acquireLock } from '../lib/db/lock.mjs';
import { interruptedRestoreMessage, startControl } from '../lib/db/control.mjs';
import { createApp } from '../server.mjs';
import { keyFingerprint, resolveKey } from '../lib/keyring.mjs';
import { dataDirectory, dataDirectoryProblem } from '../lib/environment.mjs';
import { AUDIT_TEXTS } from '../lib/audit/actions.mjs';
import { Store } from '../lib/store.mjs';
import { platformSubtest } from './helpers/platform.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
const script = path.join(repository, 'lib/cli/goblin-admin.mjs');
// Deployment files with their names from before the rename read as the current ones
// (test/helpers/deployed-names.mjs).
const read = file => {
  const text = fs.readFileSync(path.join(repository, file), 'utf8');
  return isDeploymentFile(file) ? currentNames(text) : text;
};
const flat = text => text.replace(/\s+/g, ' ').trim();
const release = JSON.parse(read('package.json')).version;
// The CHANGELOG's notes for the 1.5 branch: everything above the 1.4.3 release.
const unreleased = () => read('CHANGELOG.md').split('\n## 1.4.3')[0];
// A `## heading` (or deeper) section of a Markdown file, up to the next heading of that level.
function section(text, heading, level = 2) {
  const marks = '#'.repeat(level);
  const start = text.indexOf(`\n${marks} ${heading}\n`);
  assert.notEqual(start, -1, `section "${heading}"`);
  const end = text.indexOf(`\n${marks} `, start + 1);
  return text.slice(start, end === -1 ? undefined : end);
}
const temporary = (t, prefix) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
};
// A /proc in which no process runs, so offline commands find no Uptime Goblin by its process.
const noProcesses = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-keys-proc-'));
after(() => fs.rmSync(noProcesses, { recursive: true, force: true }));
const keyA = 'a1'.repeat(16) + 'b2'.repeat(16),
  keyB = 'c3'.repeat(16) + 'd4'.repeat(16),
  keyC = 'e5'.repeat(16) + 'f6'.repeat(16);
const print = hex => keyFingerprint(Buffer.from(hex, 'hex'));
const writeKey = (file, hex) => fs.writeFileSync(file, `${hex}\n`, { mode: 0o600 });

// goblin-admin in-process, as a native install runs it (uid 1000, no systemd credential, no
// Compose secret): {code, out, err}.
async function admin(args, { env = {}, uid = 1000, directory, root } = {}) {
  let out = '',
    err = '';
  const code = await main(args, {
    env,
    uid,
    ...(root ? { root } : {}),
    container: false,
    proc: noProcesses,
    stdout: text => (out += text),
    stderr: text => (err += text),
    keySources: {
      credentialsDirectory: path.join(directory ?? noProcesses, 'no-credentials'),
      secretsDirectory: path.join(directory ?? noProcesses, 'no-secrets'),
    },
  });
  return { code, out, err };
}

// A data directory a 1.5 start sealed: with the key in `env`, or generating <data>/secret.key.
async function started(t, env = {}) {
  const base = temporary(t, 'orbit-docs-keys-');
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = acquireLock(directory);
  try {
    const result = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release,
      env: { ...env },
      keySources: {
        credentialsDirectory: path.join(base, 'no-credentials'),
        secretsDirectory: path.join(base, 'no-secrets'),
      },
    });
    result.control.close();
  } finally {
    lock.release();
  }
  return { base, directory };
}

// B13: a stand-in `openssl` that records the mode of the file its output goes to, at the moment
// it writes: under the usual umask 022, `openssl rand -hex 32 > file && chmod …` left the key
// readable by every local account until the chmod ran.
function standInOpenssl(t) {
  const bin = temporary(t, 'orbit-docs-keys-bin-');
  const modes = path.join(bin, 'modes');
  fs.writeFileSync(
    path.join(bin, 'openssl.mjs'),
    `import fs from 'node:fs';
fs.appendFileSync(process.env.KEY_MODES, (fs.fstatSync(1).mode & 0o777).toString(8) + '\\n');
process.stdout.write('${'d4'.repeat(32)}\\n');
`
  );
  fs.writeFileSync(
    path.join(bin, 'openssl'),
    `#!/bin/sh\nexec '${process.execPath}' '${path.join(bin, 'openssl.mjs')}' "$@"\n`,
    { mode: 0o755 }
  );
  return {
    run(line, { cwd, home }) {
      fs.writeFileSync(modes, '');
      const result = spawnSync('sh', ['-c', `umask 022; ${line}`], {
        cwd,
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          HOME: home,
          KEY_MODES: modes,
        },
      });
      return { ...result, modes: fs.readFileSync(modes, 'utf8').split('\n').filter(Boolean) };
    },
  };
}

// The files a reader copies key commands from.
const keyTexts = () => [
  ...fs
    .readdirSync(path.join(repository, 'docs'))
    .filter(name => name.endsWith('.md'))
    .map(name => `docs/${name}`),
  'README.md',
  'SECURITY.md',
  'CHANGELOG.md',
  'compose.secret.yaml',
  '.env.example',
];

test('B13: every key the docs make is written under umask 077, private from its first byte', t => {
  // Every `openssl rand -hex 32 > file` runs inside `(umask 077 && …)`, and every key piped to a
  // file goes through `install -m 0440`, which makes the file private before it writes (measured
  // with GNU coreutils: mode 0600, root's, while it writes).
  let made = 0;
  for (const name of keyTexts()) {
    const text = read(name);
    const redirected = text.match(/openssl rand -hex 32 >/g)?.length ?? 0;
    const private_ = text.match(/\(umask 077 && openssl rand -hex 32 > [^)]+\)/g)?.length ?? 0;
    assert.equal(private_, redirected, `${name}: a key made under the shell's umask`);
    for (const match of text.matchAll(/openssl rand -hex 32 \|([^`\n]*)/g))
      assert.match(match[1], /^ sudo install -o root -g uptime-goblin -m 0440 \/dev\/stdin /, name);
    made += redirected;
  }
  assert.ok(made >= 6, `${made} key lines`);

  // Each line as printed, under umask 022: the key file is 0600 while the key is written.
  const installation = read('docs/installation.md');
  const found = (text, pattern, label) => {
    const match = pattern.exec(text);
    assert.ok(match, label);
    return match[1] ?? match[0];
  };
  const lines = [
    [
      'installation.md, the new-key recipe',
      found(
        installation,
        /^test -e orbit_secret_key && echo 'orbit_secret_key exists: keep it'.*$/m
      ),
      'orbit_secret_key',
      0o400,
    ],
    [
      'compose.secret.yaml, the new-key recipe',
      found(
        read('compose.secret.yaml'),
        /^# {3}(test -e orbit_secret_key && echo 'orbit_secret_key exists: keep it'.*)$/m
      ),
      'orbit_secret_key',
      0o400,
    ],
    [
      'installation.md, a new orbit_secret_key for a key change',
      found(installation, /^test -e orbit_secret_key\.new && .*$/m),
      'orbit_secret_key.new',
      0o600,
    ],
    [
      'installation.md, npm start',
      found(
        installation,
        /^test -e ~\/\.orbit-secret\.key && echo '\.orbit-secret\.key exists: keep it'.*$/m
      ),
      'HOME/.orbit-secret.key',
      0o600,
    ],
    [
      'troubleshooting.md, lost key under Compose',
      found(
        read('docs/troubleshooting.md'),
        /`(\(umask 077 && openssl rand -hex 32 > orbit_secret_key\) && chmod 0400 orbit_secret_key)`/
      ),
      'orbit_secret_key',
      0o400,
    ],
    [
      '.env.example',
      found(
        read('.env.example'),
        /^# {3}(test -e ~\/\.orbit-secret\.key && echo '\.orbit-secret\.key exists: keep it' \|\| \(umask 077 && openssl rand -hex 32 > ~\/\.orbit-secret\.key\))$/m
      ),
      'HOME/.orbit-secret.key',
      0o600,
    ],
  ];
  const openssl = standInOpenssl(t);
  for (const [label, line, file, mode] of lines) {
    const cwd = temporary(t, 'orbit-docs-keys-cwd-');
    const home = temporary(t, 'orbit-docs-keys-home-');
    const result = openssl.run(line, { cwd, home });
    assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    assert.deepEqual(
      result.modes,
      ['600'],
      `${label}: the key file's mode while the key is written`
    );
    const target = file.startsWith('HOME/') ? path.join(home, file.slice(5)) : path.join(cwd, file);
    assert.equal(fs.statSync(target).mode & 0o777, mode, label);
    assert.equal(fs.readFileSync(target, 'utf8'), `${'d4'.repeat(32)}\n`, label);
  }
  assert.match(
    flat(section(installation, 'Encryption key')),
    /under `umask 077`, so the file is private from its first byte \(made under the usual umask 022 and then given `chmod`, every local account could read it until the `chmod` ran\)/
  );
});

// B13: the recipes that check the volume's key write it to /tmp inside a one-shot container,
// under umask 077 there too, so the file is private from its first byte (the image's umask is
// 0022).
test('B13: a key written inside a container is written under umask 077', () => {
  let written = 0;
  for (const name of ['docs/installation.md', 'compose.secret.yaml']) {
    const text = read(name);
    const all = text.match(/cat > \/tmp\//g)?.length ?? 0;
    const private_ = text.match(/'umask 077 && cat > \/tmp\//g)?.length ?? 0;
    assert.equal(private_, all, `${name}: a key written under the container's umask`);
    written += all;
  }
  assert.ok(written >= 5, `${written} lines`);
});

test('npm start: the key Orbit generated moves out of the data directory, never over a file, and goblin-admin reads .env only through --env-file-if-exists', async t => {
  const { base, directory } = await started(t);
  const own = path.join(directory, 'secret.key');
  const generated = fs.readFileSync(own, 'utf8');
  const home = temporary(t, 'orbit-docs-keys-home-');
  // The project directory, with the data directory as data/ (npm start's default).
  const project = path.join(base, 'project');
  fs.mkdirSync(project);
  fs.symlinkSync(directory, path.join(project, 'data'));
  const installation = read('docs/installation.md');
  const moveOut =
    /^test -e ~\/\.orbit-secret\.key && echo '\.orbit-secret\.key exists: not replaced' \|\| install -m 600 data\/secret\.key ~\/\.orbit-secret\.key$/m.exec(
      installation
    )?.[0];
  assert.ok(moveOut, 'installation.md moves an existing key out');
  const sh = line =>
    spawnSync('sh', ['-c', line], {
      cwd: project,
      encoding: 'utf8',
      env: { ...process.env, HOME: home },
    });
  const keyFile = path.join(home, '.orbit-secret.key');
  assert.equal(sh(moveOut).status, 0);
  assert.equal(fs.readFileSync(keyFile, 'utf8'), generated, 'the same key, byte for byte');
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
  const again = sh(moveOut);
  assert.equal(again.stdout, '.orbit-secret.key exists: not replaced\n');
  assert.equal(fs.readFileSync(keyFile, 'utf8'), generated);
  // goblin-admin with .env (here naming the data directory, which npm start would find as data/):
  // the line the docs give deletes the data directory's copy once Uptime Goblin's key is the file.
  fs.writeFileSync(
    path.join(project, '.env'),
    `GOBLIN_DATA_DIR=${directory}\nORBIT_SECRET_KEY_FILE=${keyFile}\n`,
    { mode: 0o600 }
  );
  assert.ok(
    installation.includes(
      '`node --env-file-if-exists=.env lib/cli/goblin-admin.mjs key remove-data-copy`'
    )
  );
  const withEnv = spawnSync(
    process.execPath,
    [
      '--env-file-if-exists=.env',
      '--input-type=module',
      '-e',
      `import { main } from ${JSON.stringify(script)};
process.exitCode = await main(['key', 'remove-data-copy'], { uid: 1000, container: false, proc: ${JSON.stringify(noProcesses)}, keySources: { credentialsDirectory: ${JSON.stringify(path.join(base, 'none'))}, secretsDirectory: ${JSON.stringify(path.join(base, 'none'))} } });`,
    ],
    { cwd: project, encoding: 'utf8', env: { PATH: process.env.PATH } }
  );
  assert.equal(withEnv.status, 0, withEnv.stderr);
  assert.match(
    withEnv.stdout,
    new RegExp(`^Deleted ${own.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: GOBLIN_SECRET_KEY_FILE \\(`)
  );
  assert.equal(fs.existsSync(own), false);
  // Without .env the key does not reach it.
  const without = await admin(['key', 'status', '--data-dir', directory], { directory: base });
  assert.equal(without.code, 1);
  assert.match(without.out, /^Master key: not found by this command\./m);
  const admin15 = flat(section(installation, 'goblin-admin', 3));
  assert.match(
    admin15,
    /With `npm start`, `goblin-admin` does not read `\.env`, which `npm start` loads for Uptime Goblin\./
  );
  assert.match(
    flat(installation),
    /name it in `\.env` by its full path, since `\.env` does not expand `~`/
  );
  // .env.example gives the same guarded lines: run where ~/.orbit-secret.key exists already (a
  // second checkout, an earlier attempt), neither may replace it (docs audit, keys).
  const example = read('.env.example');
  assert.ok(
    example.includes(`\n#   ${moveOut}\n`),
    '.env.example moves the key out as the docs do'
  );
  const makeNew =
    /^# {3}(test -e ~\/\.orbit-secret\.key && echo '\.orbit-secret\.key exists: keep it' \|\| .*)$/m.exec(
      example
    )?.[1];
  assert.ok(makeNew, '.env.example makes a new key only where none is');
  const kept = sh(makeNew);
  assert.equal(kept.stdout, '.orbit-secret.key exists: keep it\n');
  assert.equal(fs.readFileSync(keyFile, 'utf8'), generated, 'the existing key is kept');
  assert.doesNotMatch(example, /^# {3}install -m 600 data\/secret\.key ~\/\.orbit-secret\.key$/m);
  assert.doesNotMatch(
    example,
    /^# {3}\(umask 077 && openssl rand -hex 32 > ~\/\.orbit-secret\.key\)$/m
  );
  assert.doesNotMatch(example, /chmod 600 ~\/\.orbit-secret\.key/);
  assert.match(
    flat(section(installation, 'Encryption key')),
    /with `GOBLIN_DATA_DIR` set in `\.env`, put that directory's `secret\.key` in place of `data\/secret\.key`/
  );
});

test('a key change, as the docs describe it: rotate re-seals nothing and prints no checkpoint, a snapshot from before opens only with the old key, and the messages name the key as the start line does', async t => {
  const keys = temporary(t, 'orbit-docs-keys-files-');
  const [a, b, c] = ['a', 'b', 'c'].map(name => path.join(keys, name));
  writeKey(a, keyA);
  writeKey(b, keyB);
  writeKey(c, keyC);
  const data = await started(t, { GOBLIN_SECRET_KEY_FILE: a });
  const dir = data.directory;
  const run = (args, env) => admin([...args, '--data-dir', dir], { env, directory: data.base });

  // key status names the source as the start line does (docs audit, keys 23).
  const status = await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: a });
  assert.equal(status.code, 0, status.err);
  assert.match(
    status.out,
    new RegExp(
      `^Master key: GOBLIN_SECRET_KEY_FILE \\(${a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\), fingerprint ${print(keyA)}$`,
      'm'
    )
  );

  const snapshot = await run(['snapshot'], {});
  assert.equal(snapshot.code, 0, snapshot.err);
  const id = /^Snapshot (\S+) /.exec(snapshot.out)?.[1];
  assert.ok(id, snapshot.out);
  // Restored before any key change, the same keyring comes back: no word of an older key. On a
  // copy of the data directory: a restore that Uptime Goblin has not started on yet leaves a keyring that
  // does not stand for Uptime Goblin's key, and the restore below must replace one Uptime Goblin ran with.
  const copy = path.join(data.base, 'copy');
  fs.cpSync(dir, copy, {
    recursive: true,
    filter: source => path.basename(source) !== 'goblin.lock',
  });
  const same = await admin(['restore-snapshot', id, '--data-dir', copy], { directory: data.base });
  assert.equal(same.code, 0, same.err);
  assert.doesNotMatch(same.out, /older key/);

  // key rotate with the old key as the previous one: new data keys, nothing re-sealed (no
  // component registers a hook in this release), and no checkpoint line (keys 1, 13, 17).
  assert.deepEqual(keyHooks.components, [], 'a component re-seals on rotate: say so in the docs');
  const rotated = await run(['key', 'rotate'], {
    GOBLIN_SECRET_KEY_FILE: b,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: a,
  });
  assert.equal(rotated.code, 0, rotated.err);
  assert.match(
    rotated.out,
    /^New data keys for seal, sessions, login, audit; retired .* \(they still open older values\)\.$/m
  );
  assert.match(
    rotated.out,
    /^No component re-seals its values in this release; they are re-sealed when next written\.$/m
  );
  assert.doesNotMatch(rotated.out + rotated.err, /audit\.checkpoint/);
  // The old key opens nothing of the live data now.
  assert.equal((await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: a })).code, 1);
  assert.match(
    (await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: b })).out,
    /^The key opens every data key\.$/m
  );

  // The snapshot from before the change opens only with the old key (keys 9), and the restore,
  // given the current key, says so: that key opens the keyring the restore replaced and not the
  // one it brought back (review OPS-801-2: wrapped bytes alone do not tell).
  const restored = await run(['restore-snapshot', id], { GOBLIN_SECRET_KEY_FILE: b });
  assert.equal(restored.code, 0, restored.err);
  assert.ok(
    restored.out.includes(
      `The restored control.sqlite holds the keyring of the snapshot's time, which the encryption key changed after (key rotate, key rewrap or key reset): it opens only with the older key, and Uptime Goblin refuses to start with the current key (key_mismatch) unless it is also given the older key as GOBLIN_SECRET_KEY_PREVIOUS_FILE. The key this command was given, GOBLIN_SECRET_KEY_FILE (${b}) (fingerprint ${print(keyB)}), opens the keyring this restore replaced, and not the restored one.`
    ),
    restored.out
  );
  const mismatch = await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: b });
  assert.equal(mismatch.code, 1);
  assert.match(
    mismatch.out,
    /^PROBLEM: The encryption key \(fingerprint [0-9a-f]{16}\) does not match this data\./m
  );
  // With the old key as the previous one, key status names the same command line as Uptime Goblin's start
  // warning, with both files (keys 20), and key rewrap brings the data to the new key.
  const stale = await run(['key', 'status'], {
    GOBLIN_SECRET_KEY_FILE: b,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: a,
  });
  assert.equal(stale.code, 0, stale.err);
  assert.ok(
    stale.out.includes(
      `only through the previous key: run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${b} GOBLIN_SECRET_KEY_PREVIOUS_FILE=${a} node ${script} key rotate --data-dir ${dir} (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).`
    ),
    stale.out
  );
  assert.doesNotMatch(stale.out, /run goblin-admin key rewrap/);
  const rewrapped = await run(['key', 'rewrap'], {
    GOBLIN_SECRET_KEY_FILE: b,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: a,
  });
  assert.equal(rewrapped.code, 0, rewrapped.err);
  assert.match(
    (await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: b })).out,
    /^The key opens every data key\.$/m
  );

  // key reset names the key as the start line does (keys 23).
  const reset = await run(['key', 'reset', '--confirm-lost-key'], { GOBLIN_SECRET_KEY_FILE: c });
  assert.equal(reset.code, 0, reset.err);
  assert.ok(
    reset.out.includes(
      `new keys are wrapped by the key from GOBLIN_SECRET_KEY_FILE (${c}), fingerprint ${print(keyC)}.`
    ),
    reset.out
  );

  // What the docs say of it.
  const installation = read('docs/installation.md');
  const changing = flat(section(installation, 'Changing the key', 4));
  assert.match(
    changing,
    /In 1\.5 neither seals a stored value again: the webhook's private signing key stays sealed under its old data key until it is replaced \(\*\*Replace signing key\*\*\)\./
  );
  assert.match(
    changing,
    /`key rotate` also makes new data keys, for all four purposes \(`seal`, `sessions`, `login`, `audit`\) or for those `--purpose` names, and keeps the old ones, retired/
  );
  assert.match(
    changing,
    /keep the old key only with the backups and \[snapshots\]\(#snapshots\) made before the change, which open only with it/
  );
  const snapshots = flat(section(installation, 'Snapshots', 4));
  // When it says so for certain: only of a keyring Uptime Goblin has started on, and only when a previous
  // key file it was given can be read (review F2v2, round 7: the sentence named neither, while the
  // same paragraph's hedges name a restore Uptime Goblin has not started on, and a previous key file it
  // cannot read beside a key that opens the keyring it replaced and not the restored one).
  assert.ok(
    snapshots.includes(
      'it says so when Uptime Goblin has started on the keyring it replaced, that key alone opens that keyring and not the restored one, and any previous key file it was given can be read ("The restored control.sqlite holds the keyring of the snapshot\'s time, which the encryption key changed after …"), and names the previous key it was given when that one opens the rest (Uptime Goblin then starts only while given it too).'
    ),
    snapshots
  );
  assert.doesNotMatch(snapshots, /it says so when that key alone opens the keyring it replaced/);
  assert.match(
    snapshots,
    /A snapshot taken before a key change \(`key rotate`, `key rewrap`\) opens only with the older key: after restoring one, Uptime Goblin refuses to start \(exit status 78, `key_mismatch`\) until you run `key rewrap` with that key as `GOBLIN_SECRET_KEY_PREVIOUS_FILE`/
  );
  assert.match(
    flat(section(installation, 'goblin-admin', 3)),
    /They print no checkpoint line: their entry is covered by the checkpoint of Uptime Goblin's next entry, such as its start/
  );
  const security = read('docs/security.md');
  assert.match(
    flat(security),
    /The `goblin-admin` key commands print none: their entries are covered only by the checkpoint of Uptime Goblin's next entry/
  );
  const leaked = flat(section(security, 'A leaked key', 3));
  assert.match(
    leaked,
    /press \*\*Replace signing key\*\* under \*\*Configure → Notifications\*\* twice: after the first press the old key keeps signing for 24 hours, and the second press stops it at once/
  );
  assert.match(
    leaked,
    /In 1\.5 it seals nothing again: until you replace it, the webhook signing key is the one the old key opens\./
  );
  assert.match(leaked, /change the admin password too \(which signs every other session out\)/);
  assert.match(
    leaked,
    /In 1\.5 `config\.json` holds the source and SMTP passwords and API keys in plain text/
  );
  assert.match(
    flat(security),
    /Replace it whenever the private key may have been exposed: the encryption key together with a copy of the data directory \(\[a leaked key\]\(#a-leaked-key\)\)\./
  );
  assert.match(
    read('docs/troubleshooting.md'),
    /Moving to a new key on purpose, or after restoring a \[snapshot\]\(installation\.md#snapshots\) taken before a key change:/
  );
  // The refusal names the key files the start read (lib/db/control.mjs passes them), and the
  // row says so (docs audit, keys 19).
  assert.match(
    read('lib/db/control.mjs'),
    /keyFile: found\.source === 'file' \? path\.resolve\(found\.file\) : null,/
  );
  assert.ok(
    read('docs/troubleshooting.md').includes(
      '(the message names the files Uptime Goblin was started with, `GOBLIN_SECRET_KEY_FILE` and `GOBLIN_SECRET_KEY_PREVIOUS_FILE`; without them, `/etc/uptime-goblin/secret.key` and `OLD_KEY_FILE`, to replace)'
    )
  );
  assert.doesNotMatch(read('docs/troubleshooting.md'), /whatever file Uptime Goblin was given/);
  assert.match(
    read('docs/configuration.md'),
    /\| `GOBLIN_SECRET_KEY_PREVIOUS` \| The previous encryption key, while moving to a new one: `goblin-admin key rewrap` or `key rotate` \(Uptime Goblin stopped\) needs it/
  );
});

// Review OPS-801-2: every key rewrap wraps the data keys anew (a fresh IV each time), so a key
// changed and changed back (A to B, then B to A) leaves the snapshot of A's time wrapped
// differently from the live keyring although A opens it. restore-snapshot said "it opens only
// with the older key, and Uptime Goblin refuses to start with the current one" from the bytes alone. Now
// it says that only when the key it is given opens the keyring it replaced and not the restored
// one; without a key that can tell (none, or one that does not open the replaced keyring, such as
// an older key), it says the key may have changed and gives the key status line to check with.
// The replaced keyring tells only when Uptime Goblin has run on it: undoing a restore before Uptime Goblin starts
// (its pre-restore snapshot put back over it) replaces the keyring that restore brought back, which
// an older key opens, so the undo said for certain that Uptime Goblin would refuse to start when Uptime Goblin's
// own key opened the data. Now it says the key may have changed, whatever key it is given.
test('restore-snapshot tells an older key by the key it is given, not by the wrapped bytes: A to B to A needs none, A to B does, without that key it says to check, and an undo before Orbit starts never claims an older key (review OPS-801-2)', async t => {
  const keys = temporary(t, 'orbit-docs-keys-roundtrip-');
  const [a, b] = ['a', 'b'].map(name => path.join(keys, name));
  writeKey(a, keyA);
  writeKey(b, keyB);
  // A data directory sealed with A, its snapshot of A's time, then the key changes `changes`
  // ([new, old] pairs) made with key rewrap, as the docs make them, and `dataKey` left in the data
  // directory's secret.key, as an older key can be after a key change. The snapshot is restored
  // with `env`, and then that restore is undone with the pre-restore snapshot it names, before
  // Uptime Goblin starts, as the docs offer. Both run with --json, and for their words on a copy of the
  // data directory made before the first restore (`dir`), where they find the same.
  const restoreAfter = async (changes, env, { dataKey = null } = {}) => {
    const data = await started(t, { GOBLIN_SECRET_KEY_FILE: a });
    const run = (args, given = {}, directory = data.directory) =>
      admin([...args, '--data-dir', directory], { env: given, directory: data.base });
    const snapshot = await run(['snapshot']);
    assert.equal(snapshot.code, 0, snapshot.err);
    const id = /^Snapshot (\S+) /.exec(snapshot.out)?.[1];
    assert.ok(id, snapshot.out);
    for (const [next, old] of changes) {
      const rewrapped = await run(['key', 'rewrap'], {
        GOBLIN_SECRET_KEY_FILE: next,
        GOBLIN_SECRET_KEY_PREVIOUS_FILE: old,
      });
      assert.equal(rewrapped.code, 0, rewrapped.err);
    }
    if (dataKey) writeKey(path.join(data.directory, 'secret.key'), dataKey);
    // goblin.lock is left out: nothing holds it now, and a copy of it is no lock.
    const twin = path.join(data.base, 'twin');
    fs.cpSync(data.directory, twin, {
      recursive: true,
      filter: source => path.basename(source) !== 'goblin.lock',
    });
    const json = await run(['restore-snapshot', id, '--json'], { ...env });
    assert.equal(json.code, 0, json.err);
    const report = JSON.parse(json.out);
    const human = await run(['restore-snapshot', id], { ...env }, twin);
    assert.equal(human.code, 0, human.err);
    // What the key Uptime Goblin now uses says of the restored data, as the start's keycheck would.
    const current = changes.at(-1)?.[0] ?? a;
    const status = await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: current });
    // The undo, with the same environment, before Uptime Goblin starts.
    const undoJson = await run(['restore-snapshot', report.aside, '--json'], { ...env });
    assert.equal(undoJson.code, 0, undoJson.err);
    const twinAside = /The replaced files are in snapshot (\S+); restore it to undo\./.exec(
      human.out
    )?.[1];
    assert.ok(twinAside, human.out);
    const undoHuman = await run(['restore-snapshot', twinAside], { ...env }, twin);
    assert.equal(undoHuman.code, 0, undoHuman.err);
    const undoStatus = await run(['key', 'status'], { GOBLIN_SECRET_KEY_FILE: current });
    return {
      report,
      out: human.out,
      status,
      dir: twin,
      undo: JSON.parse(undoJson.out),
      undoOut: undoHuman.out,
      undoStatus,
    };
  };
  const certain = 'which the encryption key changed after (key rotate, key rewrap or key reset)';
  const unsure =
    "The restored control.sqlite holds the keyring of the snapshot's time, wrapped differently from the keyring it replaced: the encryption key may have changed since (key rotate, key rewrap or key reset), and then it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch); a key changed and then changed back wraps it anew too, and then it opens as before.";
  const unstarted =
    'Uptime Goblin has not started on the control.sqlite this restore replaced since a restore or a copy put it in place (such as a restore this one undoes), so its keyring does not show which key Uptime Goblin uses.';
  const statusLine = dir =>
    `Before you start Uptime Goblin, check it with the key Uptime Goblin uses: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key status --data-dir ${dir} (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).`;
  const keyOf = (file, hex) => ({ source: 'file', file, fingerprint: print(hex) });
  const named = (file, hex) => `GOBLIN_SECRET_KEY_FILE (${file}) (fingerprint ${print(hex)})`;
  const opensAll = /^The key opens every data key\.$/m;
  // An undo before Uptime Goblin starts: whatever the key opens, the restore says only that the key may
  // have changed, never that Uptime Goblin refuses to start, and gives the installer's key status line.
  const undoneUnsure = (result, reason, key, hex) => {
    assert.equal(result.undo.olderKey, false, reason);
    assert.deepEqual(result.undo.keyCheck, {
      state: 'unchecked',
      key: keyOf(key, hex),
      reason,
      problem: null,
      previousProblem: null,
      replaced: 'unstarted',
      wrapping: 'different',
    });
    assert.ok(!result.undoOut.includes(certain), result.undoOut);
    const opens =
      reason === 'unconfirmed_opens'
        ? 'opens the restored keyring, but it may not be the key Uptime Goblin uses.'
        : 'does not open the restored keyring, and it may not be the key Uptime Goblin uses.';
    assert.ok(
      result.undoOut.includes(
        `${unsure} ${unstarted} The key this command was given, ${named(key, hex)}, ${opens} ${statusLine(result.dir)}`
      ),
      result.undoOut
    );
  };

  // A to B to A, restored with A, the key Uptime Goblin uses: A opens it, and nothing is said of a key.
  const back = await restoreAfter(
    [
      [b, a],
      [a, b],
    ],
    { GOBLIN_SECRET_KEY_FILE: a }
  );
  assert.match(back.status.out, opensAll);
  assert.equal(back.report.olderKey, false);
  assert.deepEqual(back.report.keyCheck, {
    state: 'opens',
    key: keyOf(a, keyA),
    reason: null,
    problem: null,
    previousProblem: null,
    replaced: 'ran',
    wrapping: 'different',
  });
  assert.doesNotMatch(back.out, /older key|wrapped differently|key status/, back.out);
  // Undone, A opens the keyring put back, but the one it replaced is the restore's: unsure.
  assert.match(back.undoStatus.out, opensAll);
  undoneUnsure(back, 'unconfirmed_opens', a, keyA);

  // A to B to A without a key in its environment, as Codex's probe ran it: no claim that Uptime Goblin
  // refuses to start, only that the key may have changed, and the line that tells.
  const backUnseen = await restoreAfter(
    [
      [b, a],
      [a, b],
    ],
    {}
  );
  assert.match(backUnseen.status.out, opensAll);
  assert.equal(backUnseen.report.olderKey, false);
  const noKey = replaced => ({
    state: 'unchecked',
    key: null,
    reason: 'no_key',
    problem: null,
    previousProblem: null,
    replaced,
    wrapping: 'different',
  });
  assert.deepEqual(backUnseen.report.keyCheck, noKey('ran'));
  assert.ok(!backUnseen.out.includes(certain), backUnseen.out);
  assert.ok(
    backUnseen.out.includes(
      `${unsure} No encryption key reached this command to tell which (it reads the key from its own environment, as the key commands do). ${statusLine(backUnseen.dir)}`
    ),
    backUnseen.out
  );
  assert.equal(backUnseen.undo.olderKey, false);
  assert.deepEqual(backUnseen.undo.keyCheck, noKey('unstarted'));

  // A to B only, restored with B, the key Uptime Goblin uses: B opens the keyring it replaced and not the
  // restored one, so Uptime Goblin refuses to start with it, and the restore says so for certain.
  const changed = await restoreAfter([[b, a]], { GOBLIN_SECRET_KEY_FILE: b });
  assert.match(
    changed.status.out,
    /^PROBLEM: The encryption key \(fingerprint [0-9a-f]{16}\) does not match this data\./m
  );
  assert.equal(changed.report.olderKey, true);
  assert.deepEqual(changed.report.keyCheck, {
    state: 'older',
    key: keyOf(b, keyB),
    reason: null,
    problem: null,
    previousProblem: null,
    replaced: 'ran',
    wrapping: 'different',
  });
  assert.ok(
    changed.out.includes(
      `The restored control.sqlite holds the keyring of the snapshot's time, ${certain}: it opens only with the older key, and Uptime Goblin refuses to start with the current key (key_mismatch) unless it is also given the older key as GOBLIN_SECRET_KEY_PREVIOUS_FILE. The key this command was given, ${named(b, keyB)}, opens the keyring this restore replaced, and not the restored one.`
    ),
    changed.out
  );
  assert.ok(!changed.out.includes(unsure), changed.out);
  // Undone with B: B opens the data put back, which the restore cannot know for Uptime Goblin's key, and
  // it no longer calls B "an older key, not the one Uptime Goblin uses".
  assert.match(changed.undoStatus.out, opensAll);
  undoneUnsure(changed, 'unconfirmed_opens', b, keyB);
  assert.doesNotMatch(changed.undoOut, /may be an older key/, changed.undoOut);

  // A to B only, without a key: the same advice as for A to B to A, since the bytes cannot tell.
  const changedUnseen = await restoreAfter([[b, a]], {});
  assert.equal(changedUnseen.report.olderKey, false);
  assert.equal(changedUnseen.report.keyCheck.state, 'unchecked');
  assert.ok(changedUnseen.out.includes(`${unsure} No encryption key reached`), changedUnseen.out);
  assert.ok(changedUnseen.out.includes(statusLine(changedUnseen.dir)), changedUnseen.out);
  assert.deepEqual(changedUnseen.undo.keyCheck, noKey('unstarted'));

  // A to B only, restored with the older key A: A opens the restored keyring but not the one
  // Uptime Goblin last ran with, so it is no proof that the data opens; the key status line names the
  // installer's key file, not A.
  const older = await restoreAfter([[b, a]], { GOBLIN_SECRET_KEY_FILE: a });
  assert.equal(older.report.olderKey, false);
  assert.deepEqual(older.report.keyCheck, {
    state: 'unchecked',
    key: keyOf(a, keyA),
    reason: 'opens_restored_only',
    problem: null,
    previousProblem: null,
    replaced: 'ran',
    wrapping: 'different',
  });
  assert.ok(
    older.out.includes(
      `${unsure} The key this command was given, ${named(a, keyA)}, opens it but not the keyring this restore replaced, so it may not be the key Uptime Goblin uses: it may be an older key. Or it is Uptime Goblin's, and Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not, or the control.sqlite this restore replaced is a copy written in place over the one Uptime Goblin last started on, or a rolled-back file-system snapshot, which passes for that file to this command as to Uptime Goblin. ${statusLine(older.dir)}`
    ),
    older.out
  );
  // Undone with A: A opens the keyring the undo replaced (the restore's) and not the one it put
  // back, which B, Uptime Goblin's key, opens. That is no older key: the undo must not say Uptime Goblin refuses
  // to start (it did, and told the admin to start Uptime Goblin with A, which would refuse).
  assert.match(older.undoStatus.out, opensAll);
  undoneUnsure(older, 'unconfirmed_refuses', a, keyA);

  // The same with A left in the data directory and no key in the environment, as the documented
  // native restore line runs after a key change: the restore finds A there.
  const leftOver = await restoreAfter([[b, a]], {}, { dataKey: keyA });
  const dataDirectoryKey = leftOver.report.keyCheck.key;
  assert.equal(dataDirectoryKey?.fingerprint, print(keyA));
  assert.equal(leftOver.report.keyCheck.reason, 'opens_restored_only');
  assert.equal(leftOver.undo.olderKey, false);
  assert.deepEqual(leftOver.undo.keyCheck, {
    state: 'unchecked',
    key: dataDirectoryKey,
    reason: 'unconfirmed_refuses',
    problem: null,
    previousProblem: null,
    replaced: 'unstarted',
    wrapping: 'different',
  });
  assert.ok(!leftOver.undoOut.includes(certain), leftOver.undoOut);
  assert.ok(leftOver.undoOut.includes(`${unsure} ${unstarted}`), leftOver.undoOut);
  assert.match(leftOver.undoStatus.out, opensAll);

  // The docs quote this message as the restore prints it (the other is pinned in the test above),
  // say when the replaced keyring cannot tell, and that a key changed back opens the snapshot
  // again.
  const snapshots = flat(section(read('docs/installation.md'), 'Snapshots', 4));
  assert.ok(
    snapshots.includes(
      "The keyring it replaced stands for the key Uptime Goblin uses only when Uptime Goblin has started on that `control.sqlite` since a restore or a copy put it in place: not after a restore that Uptime Goblin has not started on yet, such as one you undo with the pre-restore snapshot it names, and not when what Uptime Goblin's starts recorded in it cannot be read."
    ),
    snapshots
  );
  // When it says nothing of the key (review F2v2, round 4: the paragraph said "only when that
  // keyring is wrapped as the one it replaced", and then that it says nothing when the key opens
  // both, wrapped differently), and when it gives the key status line.
  assert.ok(
    snapshots.includes(
      'It says nothing of the key only when Uptime Goblin has started on the keyring it replaced and either the restored keyring is wrapped as that one and the key it finds, if any, opens it (with the previous key it was given), or a key it was given, not one it found in the data directory, opens both keyrings, the one it replaced alone (a key changed and changed back, or a snapshot holding data keys rotated after the keyring it replaced).'
    ),
    snapshots
  );
  assert.doesNotMatch(snapshots, /says nothing of the key only when that keyring is wrapped as/);
  assert.ok(
    snapshots.includes(
      "Uptime Goblin's start also accepts a data key that only its previous key opens, so a key that opens the keyring it replaced only with the previous key it was given does not show which of the two Uptime Goblin uses as its key, and a key that does not open that keyring may still be Uptime Goblin's, with a previous key this command was not given."
    ),
    snapshots
  );
  // A copy put in place that Uptime Goblin has not started on, and start records it cannot read, are
  // hedged too (review F2v2, round 7: the list named only a restore Uptime Goblin had not started on).
  assert.ok(
    snapshots.includes(
      'In every other case it says the key may have changed and gives the `key status` line to check with before you start Uptime Goblin, to which you add `GOBLIN_SECRET_KEY_PREVIOUS_FILE` when Uptime Goblin is given one ("The restored control.sqlite holds the keyring of the snapshot\'s time, wrapped differently from the keyring it replaced …", or, after a restore wrapped as the one before it, "The restored control.sqlite holds a keyring wrapped as the keyring it replaced …"): for a keyring wrapped differently from the one it replaced, without a key or with one it cannot read, with one that does not open the keyring it replaced alone, with one it found in the data directory, or with a previous key file it cannot read beside a key that opens the keyring it replaced and not the restored one; for a keyring wrapped as the one it replaced, with a key it cannot read or one that does not open it; after a restore or a copy that Uptime Goblin has not started on, or when what Uptime Goblin\'s starts recorded in the `control.sqlite` it replaced cannot be read; and with no keyring replaced to compare with (no `control.sqlite`, or a damaged one).'
    ),
    snapshots
  );
  // A previous key file it cannot read is left out, not the key (review F2v2, round 6).
  assert.ok(
    snapshots.includes(
      'A previous key file it cannot read (a mistyped `GOBLIN_SECRET_KEY_PREVIOUS_FILE`, say) is left out, not the key: it checks with the key alone, and when it gives the `key status` line it also says that the previous key could not be read, and why.'
    ),
    snapshots
  );
  assert.ok(
    flat(read('CHANGELOG.md')).includes(
      '`restore-snapshot` checks the keyring it brings back with that key file (and `GOBLIN_SECRET_KEY_PREVIOUS_FILE` when given; a previous key file it cannot read is left out, not the key),'
    )
  );
  assert.match(
    snapshots,
    /Once the key has been changed back to the one the snapshot was taken with \(`key rewrap` from A to B, then from B to A\), the snapshot opens with the current key again\./
  );
});

// Review OPS-801-2, as Uptime Goblin runs: a start on restored data records the restore it handled and
// which file control.sqlite is, so the keyring a later restore replaces stands for Uptime Goblin's key
// again once Uptime Goblin has started on it, and a control.sqlite put back as a copy stands for it only
// after a start too. Uptime Goblin itself runs here, with its key in GOBLIN_SECRET_KEY_FILE.
test('restore-snapshot takes the keyring it replaced for Orbit’s only once Orbit has started on it: after an undo, after a start, after a copy put back (review OPS-801-2)', async t => {
  const keys = temporary(t, 'orbit-docs-keys-started-');
  const [a, b] = ['a', 'b'].map(name => path.join(keys, name));
  writeKey(a, keyA);
  writeKey(b, keyB);
  const base = temporary(t, 'orbit-docs-keys-');
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const keySources = {
    credentialsDirectory: path.join(base, 'no-credentials'),
    secretsDirectory: path.join(base, 'no-secrets'),
  };
  // Uptime Goblin started and stopped with `keyFile`, as the service runs it: its key in the environment.
  const startOrbit = async keyFile => {
    const before = process.env.GOBLIN_SECRET_KEY_FILE;
    process.env.GOBLIN_SECRET_KEY_FILE = keyFile;
    try {
      const app = await createApp({
        directory,
        host: '127.0.0.1',
        port: 0,
        password: 'docs-keys-password-0001',
        allowedHosts: '',
        trustProxy: '',
        startScheduler: false,
        legacyBasic: false,
        webhook: '',
        keySources,
      });
      await app.listen();
      await app.close();
    } finally {
      if (before === undefined) delete process.env.GOBLIN_SECRET_KEY_FILE;
      else process.env.GOBLIN_SECRET_KEY_FILE = before;
    }
  };
  const run = (args, env = {}) =>
    admin([...args, '--data-dir', directory], { env, directory: base });
  const restore = async (id, keyFile) => {
    const result = await run(['restore-snapshot', id, '--json'], {
      GOBLIN_SECRET_KEY_FILE: keyFile,
    });
    assert.equal(result.code, 0, result.err);
    return JSON.parse(result.out);
  };
  // Uptime Goblin's own start lines are not what this test reads.
  for (const level of ['log', 'info', 'warn']) t.mock.method(console, level, () => {});

  // Sealed with A by Uptime Goblin's first start, its snapshot of A's time, then the key changed to B
  // and Uptime Goblin started with B.
  await startOrbit(a);
  const snapshot = await run(['snapshot']);
  assert.equal(snapshot.code, 0, snapshot.err);
  const id = /^Snapshot (\S+) /.exec(snapshot.out)?.[1];
  assert.ok(id, snapshot.out);
  const rewrapped = await run(['key', 'rewrap'], {
    GOBLIN_SECRET_KEY_FILE: b,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: a,
  });
  assert.equal(rewrapped.code, 0, rewrapped.err);
  await startOrbit(b);

  // Restored with B: Uptime Goblin last ran on the keyring it replaced, so this is certain.
  const first = await restore(id, b);
  assert.equal(first.olderKey, true);
  assert.equal(first.keyCheck.state, 'older');
  // Undone with A before Uptime Goblin starts: A opens the keyring the undo replaced, the restore's, and
  // not the one it put back; Uptime Goblin's key B does, and Uptime Goblin starts with it.
  const undo = await restore(first.aside, a);
  assert.equal(undo.olderKey, false);
  assert.equal(undo.keyCheck.reason, 'unconfirmed_refuses');
  await startOrbit(b);
  // Once Uptime Goblin has started on it, the keyring put back stands for Uptime Goblin's key again.
  const again = await restore(id, b);
  assert.equal(again.olderKey, true);
  assert.equal(again.keyCheck.state, 'older');
  const undoAgain = await restore(again.aside, b);
  assert.equal(undoAgain.keyCheck.reason, 'unconfirmed_opens');
  await startOrbit(b);

  // A control.sqlite put back as a copy (a backup, a move) is another file than the one Uptime Goblin
  // recorded at its last start, so it does not stand for Uptime Goblin's key until Uptime Goblin starts on it.
  const live = path.join(directory, 'control.sqlite');
  const copy = path.join(directory, 'control.sqlite.copy');
  fs.copyFileSync(live, copy);
  fs.renameSync(copy, live);
  const fromCopy = await restore(id, b);
  assert.equal(fromCopy.olderKey, false);
  assert.equal(fromCopy.keyCheck.reason, 'unconfirmed_refuses');
  await restore(fromCopy.aside, b);
  await startOrbit(b);
  const afterStart = await restore(id, b);
  assert.equal(afterStart.olderKey, true);
});

// Review F2v2, round 3: the restore's key line against what Uptime Goblin then does with its own key, in
// the sequences that gave a certain line Uptime Goblin disproved, or no line while Uptime Goblin refused to start.
// Uptime Goblin runs here (createApp) with its key in GOBLIN_SECRET_KEY_FILE, as the service does. Each
// restore runs twice: in words on a twin of the data directory whose files are hard links (the
// same files, so the twin's control.sqlite is the one Uptime Goblin ran on exactly when the real one is),
// then with --json on the data directory itself. What a restore must never do: say "which the
// encryption key changed after" while Uptime Goblin, started as it is set up, opens the data; or say
// nothing of the key while Uptime Goblin refuses to start (key_mismatch).
test('restore-snapshot never claims an older key that Orbit opens, nor says nothing when Orbit refuses: unreadable start records, a second restore of the same key’s time, a previous key, a copy over control.sqlite in place, no control.sqlite (review F2v2)', async t => {
  const keys = temporary(t, 'orbit-docs-keys-f2v2-');
  const file = { A: path.join(keys, 'a'), B: path.join(keys, 'b'), C: path.join(keys, 'c') };
  writeKey(file.A, keyA);
  writeKey(file.B, keyB);
  writeKey(file.C, keyC);
  const onlyA = { GOBLIN_SECRET_KEY_FILE: file.A },
    onlyB = { GOBLIN_SECRET_KEY_FILE: file.B },
    bAndA = { GOBLIN_SECRET_KEY_FILE: file.B, GOBLIN_SECRET_KEY_PREVIOUS_FILE: file.A };
  // Uptime Goblin's own start lines are not what this test reads.
  for (const level of ['log', 'info', 'warn']) t.mock.method(console, level, () => {});
  const certain = 'which the encryption key changed after';
  const statusLine = dir =>
    `Before you start Uptime Goblin, check it with the key Uptime Goblin uses: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key status --data-dir ${dir} (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).`;
  const named = hex => `(fingerprint ${print(hex)})`;

  // A data directory Uptime Goblin sealed with A, `count` snapshots of A's time, then the key changed to B
  // with key rewrap and Uptime Goblin started with `service` (B, as the docs change it). `changes`, [new,
  // old] key files, replaces that key change; with `rotated`, a data key is rotated with A, and
  // Uptime Goblin started on it, between the snapshots.
  const setup = async ({
    count = 1,
    service = onlyB,
    changes = [[file.B, file.A]],
    rotated = false,
  } = {}) => {
    const base = temporary(t, 'orbit-docs-keys-f2v2-data-');
    const directory = path.join(base, 'data');
    fs.mkdirSync(directory, { mode: 0o700 });
    fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
    const keySources = {
      credentialsDirectory: path.join(base, 'no-credentials'),
      secretsDirectory: path.join(base, 'no-secrets'),
    };
    // Uptime Goblin started and stopped with `env` as its service environment, on `on` (the data
    // directory, or a copy of it): 'started', or the code it refused with.
    const startOrbit = async (env, on = directory) => {
      const names = ['GOBLIN_SECRET_KEY_FILE', 'GOBLIN_SECRET_KEY_PREVIOUS_FILE'];
      const before = Object.fromEntries(names.map(name => [name, process.env[name]]));
      for (const name of names)
        if (env[name]) process.env[name] = env[name];
        else delete process.env[name];
      try {
        const app = await createApp({
          directory: on,
          host: '127.0.0.1',
          port: 0,
          password: 'docs-keys-password-0001',
          allowedHosts: '',
          trustProxy: '',
          startScheduler: false,
          legacyBasic: false,
          webhook: '',
          keySources,
        });
        await app.listen();
        await app.close();
        return 'started';
      } catch (error) {
        return error?.code ?? String(error);
      } finally {
        for (const name of names)
          if (before[name] === undefined) delete process.env[name];
          else process.env[name] = before[name];
      }
    };
    // What Uptime Goblin does on the data as it is now, tried on a copy so that nothing changes here.
    const orbitWith = async env => {
      const copy = path.join(base, `try-${Math.random().toString(36).slice(2)}`);
      fs.cpSync(directory, copy, {
        recursive: true,
        filter: source => path.basename(source) !== 'goblin.lock',
      });
      return startOrbit(env, copy);
    };
    const run = (args, env = {}, dir = directory) =>
      admin([...args, '--data-dir', dir], { env, directory: base });
    // A twin of the data directory made of hard links to its files.
    const linkTree = (from, to) => {
      fs.mkdirSync(to, { mode: 0o700 });
      for (const entry of fs.readdirSync(from, { withFileTypes: true }))
        if (entry.name === 'goblin.lock') continue;
        else if (entry.isDirectory())
          linkTree(path.join(from, entry.name), path.join(to, entry.name));
        else if (entry.isFile())
          fs.linkSync(path.join(from, entry.name), path.join(to, entry.name));
    };
    const restore = async (id, env = {}) => {
      const twin = path.join(base, `twin-${Math.random().toString(36).slice(2)}`);
      linkTree(directory, twin);
      const human = await run(['restore-snapshot', id], env, twin);
      assert.equal(human.code, 0, human.err);
      const json = await run(['restore-snapshot', id, '--json'], env);
      assert.equal(json.code, 0, json.err);
      const report = JSON.parse(json.out);
      const lines = human.out.split('\n').filter(line => /keyring/.test(line));
      return { report, check: report.keyCheck, out: human.out, lines, twin };
    };
    assert.equal(await startOrbit(onlyA), 'started');
    const ids = [];
    for (let i = 0; i < count; i++) {
      if (i && rotated) {
        const rotation = await run(['key', 'rotate', '--purpose', 'audit'], onlyA);
        assert.equal(rotation.code, 0, rotation.err);
        assert.equal(await startOrbit(onlyA), 'started');
      }
      const snapshot = await run(['snapshot']);
      assert.equal(snapshot.code, 0, snapshot.err);
      ids.push(/^Snapshot (\S+) /.exec(snapshot.out)?.[1]);
    }
    for (const [next, old] of changes) {
      const rewrapped = await run(['key', 'rewrap'], {
        GOBLIN_SECRET_KEY_FILE: next,
        GOBLIN_SECRET_KEY_PREVIOUS_FILE: old,
      });
      assert.equal(rewrapped.code, 0, rewrapped.err);
    }
    assert.equal(await startOrbit(service), 'started');
    return { base, directory, ids, run, restore, orbitWith, start: startOrbit };
  };
  // One hedged line: the key may have changed, with the key status line.
  const hedged = (result, ...parts) => {
    assert.equal(result.report.olderKey, false);
    assert.equal(result.check.state, 'unchecked');
    assert.equal(result.lines.length, 1, result.out);
    assert.ok(!result.out.includes(certain), result.out);
    for (const part of [...parts, statusLine(result.twin)])
      assert.ok(result.lines[0].includes(part), `${part}\n${result.out}`);
  };

  // 1. What Uptime Goblin's starts recorded in the control.sqlite a restore replaces cannot be read (its
  // identity_settings page damaged, or a column renamed), while its keyring can: the restore said
  // nothing of the key at all, and Uptime Goblin, with B, refused to start.
  for (const spoil of ['damaged', 'renamed']) {
    const s = await setup();
    const live = path.join(s.directory, 'control.sqlite');
    const db = new DatabaseSync(live);
    const pageSize = db.prepare('PRAGMA page_size').get().page_size;
    const root = db
      .prepare("SELECT rootpage FROM sqlite_master WHERE name = 'identity_settings'")
      .get().rootpage;
    if (spoil === 'renamed')
      db.exec('ALTER TABLE identity_settings RENAME COLUMN value TO value_renamed');
    db.close();
    if (spoil === 'damaged') {
      const handle = fs.openSync(live, 'r+');
      fs.writeSync(handle, Buffer.alloc(pageSize, 0x5a), 0, pageSize, (root - 1) * pageSize);
      fs.closeSync(handle);
    }
    const result = await s.restore(s.ids[0], onlyB);
    assert.equal(result.check.replaced, 'unrecorded', spoil);
    assert.equal(result.check.reason, 'unconfirmed_refuses', spoil);
    hedged(
      result,
      "What Uptime Goblin's starts recorded in the control.sqlite this restore replaced could not be read, so its keyring does not show which key Uptime Goblin uses.",
      named(keyB)
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch', spoil);
  }

  // 2. A second restore of the same key's time before Uptime Goblin starts: its keyring is wrapped as the
  // one it replaces, which the first restore brought back and Uptime Goblin never ran on. It said nothing,
  // and Uptime Goblin, with B, refused to start. So with B, and with no key at all.
  for (const env of [onlyB, {}]) {
    const s = await setup({ count: 2 });
    const first = await s.restore(s.ids[0], env);
    assert.equal(first.check.replaced, 'ran');
    assert.equal(first.lines.length, 1, first.out);
    const second = await s.restore(s.ids[1], env);
    assert.equal(second.check.wrapping, 'same');
    assert.equal(second.check.replaced, 'unstarted');
    assert.equal(
      second.check.reason,
      env.GOBLIN_SECRET_KEY_FILE ? 'unconfirmed_refuses' : 'no_key'
    );
    hedged(
      second,
      'The restored control.sqlite holds a keyring wrapped as the keyring it replaced, which opens with the same key, but that one is not a keyring Uptime Goblin is known to have started on',
      'Uptime Goblin has not started on the control.sqlite this restore replaced since a restore or a copy put it in place'
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }

  // 3. A previous key: Uptime Goblin's start accepts a data key that only its previous key opens. Given B
  // and A as the previous key, the restore said Uptime Goblin refuses to start with the current key, and
  // Uptime Goblin with that same environment started. Now it names the previous key; and given B alone,
  // while Uptime Goblin's service has A as its previous key, it says Uptime Goblin starts with the older key given.
  {
    const s = await setup();
    const result = await s.restore(s.ids[0], bAndA);
    assert.equal(result.report.olderKey, false);
    assert.equal(result.check.state, 'previous');
    assert.equal(result.lines.length, 1, result.out);
    assert.ok(
      result.lines[0].includes(
        `opens the keyring this restore replaced and not all of the restored one, which opens only with the previous key it was given too. Uptime Goblin starts on it only while that previous key is given to it as well (GOBLIN_SECRET_KEY_PREVIOUS_FILE), and refuses to start with the current key alone (key_mismatch).`
      ),
      result.out
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
    assert.equal(await s.orbitWith(bAndA), 'started');
  }
  {
    const s = await setup({ service: bAndA });
    const result = await s.restore(s.ids[0], onlyB);
    assert.equal(result.check.state, 'older');
    assert.ok(
      result.lines[0].includes(
        'it opens only with the older key, and Uptime Goblin refuses to start with the current key (key_mismatch) unless it is also given the older key as GOBLIN_SECRET_KEY_PREVIOUS_FILE.'
      ),
      result.out
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
    assert.equal(await s.orbitWith(bAndA), 'started');
  }

  // 4. A backup of control.sqlite of A's time copied over it in place (the same file: neither Uptime Goblin
  // nor restore-snapshot can tell), A left in the data directory, and the restore of a snapshot of
  // B's time run without a key, as the native restore line was documented: it took A for Uptime Goblin's
  // key and said Uptime Goblin would refuse to start with it. Uptime Goblin, with B, starts. Given B, it never said
  // so; with the data directory's key it no longer does either.
  for (const env of [{}, onlyB]) {
    const s = await setup();
    const live = path.join(s.directory, 'control.sqlite');
    // The backup: this data directory's control.sqlite of A's time, as its snapshot holds it.
    const backup = path.join(s.directory, 'snapshots', s.ids[0], 'control.sqlite');
    const snapshot = await s.run(['snapshot']);
    assert.equal(snapshot.code, 0, snapshot.err);
    const ofB = /^Snapshot (\S+) /.exec(snapshot.out)?.[1];
    const inode = fs.statSync(live).ino;
    fs.writeFileSync(live, fs.readFileSync(backup));
    assert.equal(fs.statSync(live).ino, inode, 'copied in place');
    writeKey(path.join(s.directory, 'secret.key'), keyA);
    const result = await s.restore(ofB, env);
    assert.equal(result.check.replaced, 'ran', 'the copy passes for the file Uptime Goblin ran on');
    hedged(result);
    assert.equal(
      result.check.reason,
      env.GOBLIN_SECRET_KEY_FILE ? 'opens_restored_only' : 'data_directory_key'
    );
    if (!env.GOBLIN_SECRET_KEY_FILE)
      assert.ok(
        result.lines[0].includes(
          `The key this command found in the data directory, ${path.join(result.twin, 'secret.key')} ${named(keyA)}, opens the keyring this restore replaced and not the restored one, but an older key can be left there after a key change`
        ),
        result.out
      );
    assert.equal(await s.orbitWith(onlyB), 'started');
  }

  // 5. No keyring replaced to compare with: no control.sqlite in the data directory (deleted), or
  // one whose keyring cannot be read. The restore said nothing, and Uptime Goblin, with B, refused.
  for (const spoil of ['missing', 'unreadable']) {
    const s = await setup();
    const live = path.join(s.directory, 'control.sqlite');
    if (spoil === 'missing') fs.rmSync(live);
    else {
      const db = new DatabaseSync(live);
      const pageSize = db.prepare('PRAGMA page_size').get().page_size;
      const root = db
        .prepare("SELECT rootpage FROM sqlite_master WHERE name = 'keyring'")
        .get().rootpage;
      db.close();
      const handle = fs.openSync(live, 'r+');
      fs.writeSync(handle, Buffer.alloc(pageSize, 0x5a), 0, pageSize, (root - 1) * pageSize);
      fs.closeSync(handle);
    }
    const result = await s.restore(s.ids[0], onlyB);
    assert.equal(result.check.replaced, spoil);
    assert.equal(result.check.wrapping, null);
    assert.equal(result.check.reason, 'unconfirmed_refuses');
    hedged(
      result,
      spoil === 'missing'
        ? "The restored control.sqlite holds the keyring of the snapshot's time, and the data directory held no keyring before this restore to compare it with"
        : "The restored control.sqlite holds the keyring of the snapshot's time, and the keyring of the control.sqlite this restore replaced could not be read to compare it with"
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }
  // Review F2v2, round 4. The key status line's addition for an Uptime Goblin given a previous key too.
  const previousHint =
    "If Uptime Goblin is also given a previous key, add GOBLIN_SECRET_KEY_PREVIOUS_FILE with that key's file after the key file in that line, since Uptime Goblin's start opens with it too.";
  const copyInPlace = (s, id) => {
    const live = path.join(s.directory, 'control.sqlite');
    const inode = fs.statSync(live).ino;
    fs.writeFileSync(
      live,
      fs.readFileSync(path.join(s.directory, 'snapshots', id, 'control.sqlite'))
    );
    assert.equal(fs.statSync(live).ino, inode, 'copied in place');
  };

  // 6. The documented recovery after restoring a snapshot of A's time: Uptime Goblin started with B and A
  // as its previous key, then the restore undone with the pre-restore snapshot, given B and A, or
  // B alone as the docs' line gives it. The keyring the undo replaced is the restored one, which
  // Uptime Goblin started on with B and its previous key A, and which B does not open alone: the undo
  // called B "an older key, not the one Uptime Goblin uses". Uptime Goblin, with B, starts on what it put back.
  for (const env of [bAndA, onlyB]) {
    const s = await setup();
    const first = await s.restore(s.ids[0], onlyB);
    assert.equal(first.check.state, 'older');
    assert.equal(await s.start(bAndA), 'started');
    const undo = await s.restore(first.report.aside, env);
    assert.equal(undo.check.replaced, 'ran');
    assert.equal(
      undo.check.reason,
      env === bAndA ? 'replaced_needs_previous' : 'opens_restored_only'
    );
    hedged(undo, named(keyB), previousHint);
    assert.doesNotMatch(undo.out, /an older key, not the one Uptime Goblin uses/, undo.out);
    assert.ok(
      undo.lines[0].includes(
        env === bAndA
          ? "opens the keyring this restore replaced only with the previous key it was given too, as Uptime Goblin's start accepts, so it does not show which of the two Uptime Goblin uses as its key."
          : "opens it but not the keyring this restore replaced, so it may not be the key Uptime Goblin uses: it may be an older key. Or it is Uptime Goblin's, and Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not"
      ),
      undo.out
    );
    assert.equal(await s.orbitWith(onlyB), 'started');
    assert.equal(await s.orbitWith(bAndA), 'started');
  }

  // 7. Uptime Goblin's service runs with B and A as its previous key on a keyring A wrapped anew (A to C to
  // A), and a snapshot of A's time is restored: B opens neither keyring, and the restore said B "is
  // not the key Uptime Goblin last ran with", while Uptime Goblin, with B and A, starts on what it brought back.
  for (const env of [onlyB, bAndA]) {
    const s = await setup({
      changes: [
        [file.C, file.A],
        [file.A, file.C],
      ],
      service: bAndA,
    });
    const result = await s.restore(s.ids[0], env);
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'different');
    assert.equal(result.check.reason, env === bAndA ? 'replaced_needs_previous' : 'opens_neither');
    hedged(result, named(keyB), previousHint);
    assert.doesNotMatch(
      result.out,
      /so it is not the key Uptime Goblin last ran with\./,
      result.out
    );
    if (env === onlyB)
      assert.ok(
        result.lines[0].includes(
          'opens neither it nor the keyring this restore replaced, so it is not the key Uptime Goblin last started with, unless Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not'
        ),
        result.out
      );
    assert.equal(await s.orbitWith(bAndA), 'started');
  }
  // Why a key that opens the keyring Uptime Goblin started on only with the previous key it was given is
  // no proof either way: here Uptime Goblin runs with A alone on an A-wrapped keyring, the command is given
  // B and A, and a snapshot of B's time does not open with A. Saying nothing would miss that.
  {
    const s = await setup();
    const snapshot = await s.run(['snapshot']);
    assert.equal(snapshot.code, 0, snapshot.err);
    const ofB = /^Snapshot (\S+) /.exec(snapshot.out)?.[1];
    const back = await s.run(['key', 'rewrap'], {
      GOBLIN_SECRET_KEY_FILE: file.A,
      GOBLIN_SECRET_KEY_PREVIOUS_FILE: file.B,
    });
    assert.equal(back.code, 0, back.err);
    assert.equal(await s.start(onlyA), 'started');
    const result = await s.restore(ofB, bAndA);
    assert.equal(result.check.reason, 'replaced_needs_previous');
    hedged(result, named(keyB), previousHint);
    assert.equal(await s.orbitWith(onlyA), 'key_mismatch');
  }

  // 8. A copy of control.sqlite of A's time written over it in place (it passes for the file Uptime Goblin
  // ran on), then a restore of the snapshot it was copied from, wrapped as it: the restore read no
  // key and said nothing, although the key it was given, Uptime Goblin's B, does not open what it brought
  // back, and Uptime Goblin refuses to start. Without a key there is nothing to check it with, and nothing
  // is said, as before: Uptime Goblin refused to start on the copy before the restore too.
  for (const env of [onlyB, {}]) {
    const s = await setup();
    copyInPlace(s, s.ids[0]);
    assert.equal(
      await s.orbitWith(onlyB),
      'key_mismatch',
      'Uptime Goblin refuses the copy already'
    );
    const result = await s.restore(s.ids[0], env);
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'same');
    if (env.GOBLIN_SECRET_KEY_FILE) {
      assert.equal(result.check.reason, 'same_refuses');
      hedged(
        result,
        "The restored control.sqlite holds a keyring wrapped as the keyring it replaced, which Uptime Goblin's starts record as the one it last started on, so a key that opened that one opens it too.",
        `${named(keyB)}, does not open it: either that is not the key Uptime Goblin uses, or Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not, or the control.sqlite this restore replaced is a copy written in place over the one Uptime Goblin last started on`,
        previousHint
      );
    } else {
      assert.equal(result.check.state, 'unchanged');
      assert.equal(result.lines.length, 0, result.out);
    }
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }

  // 8b. Review F2v2, round 5: the same copy in place, restored with a key file it cannot read. It
  // said nothing, as for no key at all; Uptime Goblin, with B, refuses to start. Now it says why it could
  // not check, as in every other state. Its key status line names the installer's key file: the
  // one it could not read fails as printed.
  const missing = path.join(keys, 'secret.kye');
  const sameRanOpening =
    "The restored control.sqlite holds a keyring wrapped as the keyring it replaced, which Uptime Goblin's starts record as the one it last started on, so a key that opened that one opens it too.";
  {
    const s = await setup();
    copyInPlace(s, s.ids[0]);
    const result = await s.restore(s.ids[0], { GOBLIN_SECRET_KEY_FILE: missing });
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'same');
    assert.equal(result.check.reason, 'key_unreadable', result.out);
    assert.equal(result.check.key, null);
    assert.equal(result.check.previousProblem, null);
    hedged(
      result,
      `${sameRanOpening} The key this command reads could not be used to check that: GOBLIN_SECRET_KEY_FILE (${missing}) cannot be read: ENOENT. Wrapped as the keyring Uptime Goblin last started on, it may still not open with the key Uptime Goblin uses: a copy written over control.sqlite in place since Uptime Goblin last started passes for the file Uptime Goblin ran on, to this command as to Uptime Goblin. Before you start Uptime Goblin`
    );
    assert.ok(!result.out.includes(`GOBLIN_SECRET_KEY_FILE=${missing}`), result.out);
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }
  // 8c. Review F2v2, rounds 5 and 6: the same copy in place, restored with B and a previous key
  // file it cannot read. It said nothing (round 5), then that it could not check at all (round 6:
  // the previous key file, read first, failed the whole check), never checking B, which it could
  // read, and with a key status line that left out the previous key. Now it leaves out only the
  // previous key, says so, checks B (which does not open what it brought back), and gives the
  // line B alone gets, with the previous key's addition.
  const previousProblems = [
    [missing, `GOBLIN_SECRET_KEY_PREVIOUS_FILE (${missing}) cannot be read: ENOENT.`],
    [keys, `GOBLIN_SECRET_KEY_PREVIOUS_FILE (${keys}) is not a file.`],
  ];
  const leftOut = problem =>
    `The previous key this command was given could not be read, so it was left out: ${problem}`;
  const sameRefuses = `${named(keyB)}, does not open it: either that is not the key Uptime Goblin uses, or Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not, or the control.sqlite this restore replaced is a copy written in place over the one Uptime Goblin last started on`;
  for (const [previous, problem] of previousProblems) {
    const s = await setup();
    copyInPlace(s, s.ids[0]);
    const result = await s.restore(s.ids[0], {
      ...onlyB,
      GOBLIN_SECRET_KEY_PREVIOUS_FILE: previous,
    });
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'same');
    assert.equal(result.check.reason, 'same_refuses', result.out);
    assert.deepEqual(result.check.key, { source: 'file', file: file.B, fingerprint: print(keyB) });
    assert.equal(result.check.previousProblem, problem);
    hedged(result, sameRanOpening, sameRefuses, leftOut(problem), previousHint);
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }
  // 8d. Review F2v2, round 6: the documented recovery. After a restore of a snapshot of A's time,
  // Uptime Goblin started with B and A as its previous key; a snapshot of that is restored with B and a
  // mistyped previous key file. The restore said it could not check, with a key status line that
  // has neither key file and no word of the previous key, and run as printed that says the key
  // does not match; Uptime Goblin, with its own B and A, starts. Now it says what B alone gets, which
  // names the previous key and how to add it to that line, and that the previous key was left out.
  const recovered = async () => {
    const s = await setup();
    const first = await s.restore(s.ids[0], onlyB);
    assert.equal(first.check.state, 'older');
    assert.equal(await s.start(bAndA), 'started');
    const snapshot = await s.run(['snapshot']);
    assert.equal(snapshot.code, 0, snapshot.err);
    return { s, id: /^Snapshot (\S+) /.exec(snapshot.out)?.[1] };
  };
  for (const [previous, problem] of previousProblems) {
    const { s, id } = await recovered();
    const result = await s.restore(id, { ...onlyB, GOBLIN_SECRET_KEY_PREVIOUS_FILE: previous });
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'same');
    assert.equal(result.check.reason, 'same_refuses', result.out);
    assert.equal(result.check.previousProblem, problem);
    hedged(result, sameRanOpening, sameRefuses, leftOut(problem), previousHint);
    assert.equal(await s.orbitWith(bAndA), 'started');
  }
  // Given B and A as Uptime Goblin has them, nothing is said, as before.
  {
    const { s, id } = await recovered();
    const given = await s.restore(id, bAndA);
    assert.equal(given.check.state, 'unchanged');
    assert.equal(given.check.previousProblem, null);
    assert.equal(given.lines.length, 0, given.out);
    assert.equal(await s.orbitWith(bAndA), 'started');
  }
  // 8e. Review F2v2, round 6: wrapped differently (a snapshot of A's time, B Uptime Goblin's key), with B
  // and a previous key file it cannot read: B opens the keyring Uptime Goblin ran on and not the restored
  // one, and the previous key would tell whether Uptime Goblin starts while given it too. Its key status
  // line named the installer's key file (round 5), not B's, which it read: on an install with its
  // own key file that line fails as printed. Now it names B's file and adds the previous key.
  for (const [previous, problem] of previousProblems) {
    const s = await setup();
    const result = await s.restore(s.ids[0], {
      ...onlyB,
      GOBLIN_SECRET_KEY_PREVIOUS_FILE: previous,
    });
    assert.equal(result.report.olderKey, false);
    assert.equal(result.check.state, 'unchecked');
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'different');
    assert.equal(result.check.reason, 'previous_unreadable', result.out);
    assert.deepEqual(result.check.key, { source: 'file', file: file.B, fingerprint: print(keyB) });
    assert.equal(result.check.previousProblem, problem);
    assert.equal(result.lines.length, 1, result.out);
    assert.ok(!result.out.includes(certain), result.out);
    for (const part of [
      `The key this command was given, GOBLIN_SECRET_KEY_FILE (${file.B}) ${named(keyB)}, opens the keyring this restore replaced and not the restored one by itself, and the previous key it was given, which may open the rest as Uptime Goblin's start accepts, could not be read: ${problem} Before you start Uptime Goblin, check it with the key Uptime Goblin uses: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${file.B} node ${script} key status --data-dir ${result.twin} (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin). ${previousHint}`,
    ])
      assert.ok(result.lines[0].includes(part), `${part}\n${result.out}`);
    assert.ok(!result.out.includes(leftOut(problem)), 'said once');
    assert.ok(!result.out.includes(`GOBLIN_SECRET_KEY_PREVIOUS_FILE=${previous}`), result.out);
    // The line as printed says B does not match; with the previous key added, as it says, it
    // opens. Uptime Goblin refuses with B alone and starts with A as its previous key.
    const status = await s.run(['key', 'status'], onlyB);
    assert.match(
      status.out,
      /^PROBLEM: The encryption key \(fingerprint [0-9a-f]{16}\) does not match this data\./m
    );
    const withPrevious = await s.run(['key', 'status'], bAndA);
    assert.equal(withPrevious.code, 0, withPrevious.out);
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
    assert.equal(await s.orbitWith(bAndA), 'started');
  }
  // And wrapped differently (a snapshot of A's time, B Uptime Goblin's key): the key status line named the
  // key file it could not read, which fails as printed (review F2v2, round 5).
  {
    const s = await setup();
    const result = await s.restore(s.ids[0], { GOBLIN_SECRET_KEY_FILE: missing });
    assert.equal(result.check.wrapping, 'different');
    assert.equal(result.check.reason, 'key_unreadable');
    hedged(
      result,
      `The key this command reads could not be used to tell which: GOBLIN_SECRET_KEY_FILE (${missing}) cannot be read: ENOENT. Before you start Uptime Goblin`
    );
    assert.ok(!result.out.includes(`GOBLIN_SECRET_KEY_FILE=${missing}`), result.out);
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }
  // With a previous key file it cannot read beside a key file it cannot read, or beside no key,
  // that too is said, and the previous key's addition to the key status line given (review F2v2,
  // round 6: the previous key file's error stood in for the key's, and no line said to add one).
  for (const [env, reason, because] of [
    [
      { GOBLIN_SECRET_KEY_FILE: missing, GOBLIN_SECRET_KEY_PREVIOUS_FILE: missing },
      'key_unreadable',
      `The key this command reads could not be used to tell which: GOBLIN_SECRET_KEY_FILE (${missing}) cannot be read: ENOENT.`,
    ],
    [
      { GOBLIN_SECRET_KEY_PREVIOUS_FILE: missing },
      'no_key',
      'No encryption key reached this command to tell which (it reads the key from its own environment, as the key commands do).',
    ],
  ]) {
    const s = await setup();
    const result = await s.restore(s.ids[0], env);
    assert.equal(result.check.wrapping, 'different');
    assert.equal(result.check.reason, reason);
    assert.equal(result.check.key, null);
    assert.equal(result.check.previousProblem, previousProblems[0][1]);
    hedged(
      result,
      `${because} ${leftOut(previousProblems[0][1])} Before you start Uptime Goblin`,
      previousHint
    );
    assert.ok(!result.out.includes(`GOBLIN_SECRET_KEY_FILE=${missing}`), result.out);
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }

  // 9. The same copy in place, A left in the data directory, and a restore without a key of a
  // snapshot of A's time taken after a data key was rotated: wrapped differently, and A opens both
  // keyrings. It said nothing, and Uptime Goblin, with B, refuses to start: a key found in the data
  // directory no longer makes it say nothing of a keyring wrapped differently.
  {
    const s = await setup({ count: 2, rotated: true });
    copyInPlace(s, s.ids[0]);
    writeKey(path.join(s.directory, 'secret.key'), keyA);
    const result = await s.restore(s.ids[1], {});
    assert.equal(result.check.replaced, 'ran');
    assert.equal(result.check.wrapping, 'different');
    assert.equal(result.check.reason, 'data_directory_opens');
    hedged(
      result,
      `The key this command found in the data directory, ${path.join(result.twin, 'secret.key')} ${named(keyA)}, opens it and the keyring this restore replaced, but an older key can be left there after a key change`
    );
    assert.equal(await s.orbitWith(onlyB), 'key_mismatch');
  }

  // 10. What stays silent: a snapshot of the current key's time, restored with that key (alone,
  // with a previous key, or with a previous key file it cannot read, which this key does not need:
  // review F2v2, round 6), or without one: wrapped as the keyring Uptime Goblin started on, which the key
  // opens.
  for (const env of [onlyB, bAndA, { ...onlyB, GOBLIN_SECRET_KEY_PREVIOUS_FILE: missing }, {}]) {
    const s = await setup();
    const snapshot = await s.run(['snapshot']);
    assert.equal(snapshot.code, 0, snapshot.err);
    const result = await s.restore(/^Snapshot (\S+) /.exec(snapshot.out)?.[1], env);
    assert.equal(result.check.state, 'unchanged');
    assert.deepEqual(
      result.check.key,
      env.GOBLIN_SECRET_KEY_FILE ? { source: 'file', file: file.B, fingerprint: print(keyB) } : null
    );
    assert.equal(
      result.check.previousProblem,
      env.GOBLIN_SECRET_KEY_PREVIOUS_FILE === missing
        ? `GOBLIN_SECRET_KEY_PREVIOUS_FILE (${missing}) cannot be read: ENOENT.`
        : null
    );
    assert.equal(result.lines.length, 0, result.out);
    assert.equal(await s.orbitWith(onlyB), 'started');
  }

  // The row for a damaged control.sqlite says so, as the restore it sends you to does.
  assert.ok(
    flat(read('docs/troubleshooting.md')).includes(
      'A damaged `control.sqlite` leaves no keyring to compare the restored one with, so the restore gives the `key status` line to check the key with before you start Uptime Goblin ([snapshots](installation.md#snapshots)).'
    )
  );
});

// Review F2v2: restore-snapshot checks a keyring it brings back with the key in its own
// environment, so every native restore-snapshot line names the key file, as the key commands' do.
// The documented lines and those Uptime Goblin printed named none: run as printed, the check found no key,
// or an older key left in the data directory, which it took for Uptime Goblin's.
test('every native restore-snapshot line the docs and Orbit print names the key file (review F2v2)', async t => {
  // Also the template lines ("goblin-admin.mjs … --data-dir"), which stood for a restore (review
  // F2v2, round 4: the kept copy's lines after a code rollback named no key file).
  const restoreLine =
    /sudo -u uptime-goblin (?:env (\S+=\S+ )+)?node \S*goblin-admin\.mjs (?:restore-snapshot|…) /g;
  for (const name of [
    'docs/installation.md',
    'docs/authentication.md',
    'CHANGELOG.md',
    'README.md',
  ]) {
    const lines = [...read(name).matchAll(restoreLine)].map(match => match[0]);
    if (name !== 'README.md' && name !== 'CHANGELOG.md') assert.ok(lines.length, name);
    for (const line of lines)
      assert.match(
        line,
        /^sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node /,
        `${name}: ${line}`
      );
  }
  assert.ok(
    flat(read('docs/installation.md')).includes(
      '`restore-snapshot` checks a keyring it brings back with the key in its own environment, so it is given the key Uptime Goblin uses, as the key commands below are'
    )
  );
  // Under Compose, the kept 1.5 image's restore (after a code rollback) is given the key file
  // compose.secret.yaml gives Uptime Goblin, as its Compose secret (review F2v2, round 4: it mounted the
  // volume alone, so the check found no key, or an older one left in the volume).
  const keptImage = [
    ...read('docs/installation.md').matchAll(/^docker run [^\n]*restore-snapshot[^\n]*$/gm),
  ].map(match => match[0]);
  assert.equal(keptImage.length, 1, 'the kept image restore line');
  assert.ok(
    keptImage[0].includes(
      ' --mount type=bind,source="$PWD/orbit_secret_key",target=/run/secrets/orbit_secret_key,readonly '
    ),
    keptImage[0]
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      "Run it in the project directory: its `--mount` gives the restore the key file `compose.secret.yaml` gives Uptime Goblin, as the Compose secret, so that it checks the keyring it brings back with the key Uptime Goblin uses ([snapshots](#snapshots)). Without `compose.secret.yaml` (the key is the volume's `secret.key`), leave the `--mount` out; with it, a missing `orbit_secret_key` stops the line before anything changes:"
    )
  );
  assert.match(
    unreleased(),
    /with the data directory named and, for the key commands and `restore-snapshot`, the key file in its own environment/
  );
  // Uptime Goblin's refusal to start on an interrupted restore names the key file it was started with, as
  // its key lines do; without one, the installer's. goblin-admin's own (status, migrate --apply)
  // name the file it was given (adminCommand).
  assert.match(
    interruptedRestoreMessage({ snapshot: 'manual-1.5.0-20260101T000000Z' }),
    /: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \/opt\/uptime-goblin\/lib\/cli\/goblin-admin\.mjs restore-snapshot manual-1\.5\.0-20260101T000000Z --data-dir \/var\/lib\/uptime-goblin \(the native install;/
  );
  const base = temporary(t, 'orbit-docs-keys-journal-');
  const directory = path.join(base, 'data');
  fs.mkdirSync(path.join(directory, 'snapshots'), { recursive: true });
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(
    path.join(directory, 'snapshots', '.restore-in-progress.json'),
    JSON.stringify({
      snapshot: 'manual-1.5.0-20260101T000000Z',
      aside: 'pre-restore-1.5.0-20260101T000001Z',
      files: ['config.json'],
    })
  );
  const keyFile = path.join(base, "orbit's key");
  const lock = acquireLock(directory);
  try {
    await assert.rejects(
      startControl(directory, {
        lock,
        credentialConfigured: true,
        release,
        env: { GOBLIN_SECRET_KEY_FILE: keyFile },
      }),
      error => {
        assert.equal(error.code, 'restore_interrupted');
        assert.ok(
          error.message.includes(
            `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE='${keyFile.replaceAll("'", `'\\''`)}' node /opt/uptime-goblin/lib/cli/goblin-admin.mjs restore-snapshot manual-1.5.0-20260101T000000Z --data-dir /var/lib/uptime-goblin`
          ),
          error.message
        );
        return true;
      }
    );
  } finally {
    lock.release();
  }
  // The root refusal's line keeps a previous key file it was given, quoted: the shell reads it
  // back unchanged.
  const previous = path.join(base, "old key's");
  const refused = await admin(['restore-snapshot', 'ID', '--data-dir', '/var/lib/uptime-goblin'], {
    uid: 0,
    env: { GOBLIN_SECRET_KEY_FILE: keyFile, GOBLIN_SECRET_KEY_PREVIOUS_FILE: previous },
  });
  const words = /sudo -u uptime-goblin (env .*) node /.exec(refused.err)?.[1];
  assert.ok(words, refused.err);
  const echoed = spawnSync(
    'sh',
    [
      '-c',
      `${words} sh -c 'printf "%s\\n" "$GOBLIN_SECRET_KEY_FILE" "$GOBLIN_SECRET_KEY_PREVIOUS_FILE"'`,
    ],
    {
      encoding: 'utf8',
      env: { PATH: process.env.PATH },
    }
  );
  assert.equal(echoed.stdout, `${keyFile}\n${previous}\n`, echoed.stderr);
});

test('the docs give goblin-admin’s exit statuses as it returns them', async t => {
  assert.deepEqual(
    Object.values(exitCodes).sort((x, y) => x - y),
    [0, 1, 2, 3, 75, 78]
  );
  const row = read('docs/troubleshooting.md')
    .split('\n')
    .find(line => line.startsWith('| `goblin-admin`: what its exit status means |'));
  assert.ok(row, 'troubleshooting.md has the goblin-admin row');
  for (const status of [0, 1, 2, 3, 75, 78]) assert.ok(row.includes(` ${status}: `), `${status}`);
  const keys = temporary(t, 'orbit-docs-keys-files-');
  const good = path.join(keys, 'good'),
    other = path.join(keys, 'other'),
    bad = path.join(keys, 'bad');
  writeKey(good, keyA);
  writeKey(other, keyB);
  fs.writeFileSync(bad, 'not a key\n', { mode: 0o600 });
  const { base, directory } = await started(t, { GOBLIN_SECRET_KEY_FILE: good });
  const run = (args, env = {}) =>
    admin([...args, '--data-dir', directory], { env, directory: base });
  for (const [args, env, code] of [
    [['key', 'status'], { GOBLIN_SECRET_KEY_FILE: bad }, 1],
    [['verify-audit'], { GOBLIN_SECRET_KEY_FILE: bad }, 1],
    [['key', 'rotate', '--purpose', 'bogus'], { GOBLIN_SECRET_KEY_FILE: good }, 2],
    [['key', 'reset', '--confirm-lost-key'], {}, 2],
    [
      ['verify-audit', '--checkpoints', path.join(keys, 'missing')],
      { GOBLIN_SECRET_KEY_FILE: good },
      2,
    ],
    [['key', 'rotate'], { GOBLIN_SECRET_KEY_FILE: bad }, 78],
    [['key', 'rewrap'], { GOBLIN_SECRET_KEY_FILE: path.join(keys, 'missing') }, 78],
    [['key', 'reset', '--confirm-lost-key'], { GOBLIN_SECRET_KEY_FILE: bad }, 78],
    [
      ['key', 'reset', '--confirm-lost-key'],
      { GOBLIN_SECRET_KEY_FILE: path.join(keys, 'missing') },
      78,
    ],
    // A reset given the key that opens the data: nothing is lost (1). Given another key: the
    // lost-key case, which goes ahead (0); last, since it changes the data.
    [['key', 'reset', '--confirm-lost-key'], { GOBLIN_SECRET_KEY_FILE: good }, 1],
    [['key', 'reset', '--confirm-lost-key'], { GOBLIN_SECRET_KEY_FILE: other }, 0],
  ]) {
    const result = await run(args, env);
    assert.equal(result.code, code, `${args.join(' ')}: ${result.err}`);
  }
  assert.ok(
    row.includes(
      '`verify-audit` CHANGED, or `key reset` given a key that already opens the data (nothing is lost: use `key rotate`).'
    )
  );
  assert.ok(
    row.includes(
      '78: refused, as Uptime Goblin refuses to start: data from a newer Uptime Goblin, a restore that must be finished first (`migrate --apply`), a key given to `key rotate` or `key rewrap` that does not open the data, a key given to any of the three key commands that is not a key or cannot be read (the `key_…` rows above), a `snapshots/` that is not a directory or a link to one (`snapshots`, `snapshot`, `migrate --apply`, `restore-snapshot`), or a `history.sqlite` (or its `-journal`, `-wal` or `-shm`) that is not a regular file or a link to one (`check-data`). `key reset --confirm-lost-key` with a key that does not open the data is the lost-key case: it goes ahead and exits 0.'
    )
  );
  assert.match(
    row,
    /2: usage \(an unknown command, option or `--purpose`\), run as root, a `key reset` that found no key or only the data directory's, a `--checkpoints` file it cannot read, or a data directory \(`--data-dir`, `GOBLIN_DATA_DIR`\) or key file \(`GOBLIN_SECRET_KEY_FILE`, `GOBLIN_SECRET_KEY_PREVIOUS_FILE`\) whose path, as given or resolved against the working directory, holds a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate\./
  );
  // The 2 and 78 this round added, as the row gives them: a key file path holding a line break,
  // a snapshots/ that is a link to nothing, a history.sqlite that is a loop of links.
  assert.equal((await run(['status'], { GOBLIN_SECRET_KEY_FILE: `${good}\n` })).code, 2);
  const unusable = temporary(t, 'orbit-docs-keys-links-');
  fs.symlinkSync(path.join(unusable, 'missing'), path.join(unusable, 'snapshots'));
  fs.symlinkSync(path.join(unusable, 'history.sqlite'), path.join(unusable, 'history.sqlite'));
  for (const args of [['snapshots'], ['snapshot'], ['migrate', '--apply'], ['check-data']])
    assert.equal(
      (await admin([...args, '--data-dir', unusable], { directory: base })).code,
      78,
      args.join(' ')
    );
  assert.match(row, /`verify-audit` with a key file that is not a key or cannot be read/);
});

test('the goblin-admin table names every command and option, and which only read', async () => {
  const installation = read('docs/installation.md');
  const start = installation.indexOf('| Command | What it does |');
  assert.ok(start > 0);
  const table = installation.slice(start, installation.indexOf('\n\n', start));
  const rows = table.split('\n').slice(2);
  const readOnly = rows[0];
  for (const [name, load] of Object.entries(commands)) {
    const command = await load();
    assert.ok(table.includes(`\`${name}`), name);
    for (const option of command.usage.match(/--[a-z-]+/g) ?? [])
      if (!['--data-dir', '--json'].includes(option))
        assert.ok(table.includes(option), `${name} ${option}`);
    const subcommands =
      name === 'key'
        ? ['status', 'compose-check', 'remove-data-copy', 'rewrap', 'rotate', 'reset']
        : [null];
    for (const sub of subcommands) {
      const kind =
        typeof command.kindFor === 'function'
          ? command.kindFor({}, sub ? [sub] : [])
          : command.kind;
      const words = sub ? `\`key ${sub}` : `\`${name}`;
      if (kind === 'read') assert.ok(readOnly.includes(words), `${words} is read-only`);
      else
        assert.ok(
          !readOnly.includes(`${words}\``) && !readOnly.includes(`${words} `),
          `${words} changes the data`
        );
    }
  }
  assert.match(readOnly, /Only read, also while Uptime Goblin runs\./);
});

test('run as root, every key command that changes something, and restore-snapshot, refuses (2) and names the key file it needs', async () => {
  for (const args of [
    ['key', 'remove-data-copy'],
    ['key', 'remove-data-copy', '--unused'],
    ['key', 'rotate'],
    ['key', 'rewrap'],
    ['key', 'reset', '--confirm-lost-key'],
  ]) {
    const result = await admin([...args, '--data-dir', '/var/lib/uptime-goblin'], { uid: 0 });
    assert.equal(result.code, exitCodes.usage, args.join(' '));
    assert.match(
      result.err,
      /must not run as root .*: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key /,
      args.join(' ')
    );
    // A line to paste holds no < or >: the previous key's placeholder was <old-key-file>, which
    // a shell reads as redirections (key rewrap's line).
    assert.doesNotMatch(result.err, /[<>]/, args.join(' '));
  }
  // restore-snapshot checks a keyring it brings back with the key in its own environment (review
  // OPS-801-2), so its line keeps the key file it was given, else the installer's: without it the
  // printed line checks with no key, or with an older one left in the data directory. It reads a
  // previous key too, which opens what the key does not as at Uptime Goblin's start, so a previous key file
  // it was given stays in the line (review F2v2), and no placeholder is added without one.
  for (const [env, words] of [
    [
      { GOBLIN_SECRET_KEY_FILE: '/srv/keys/orbit.key' },
      'GOBLIN_SECRET_KEY_FILE=/srv/keys/orbit.key',
    ],
    [{}, 'GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key'],
    [
      {
        GOBLIN_SECRET_KEY_FILE: '/srv/keys/orbit.key',
        GOBLIN_SECRET_KEY_PREVIOUS_FILE: "/srv/old key's",
      },
      `GOBLIN_SECRET_KEY_FILE=/srv/keys/orbit.key GOBLIN_SECRET_KEY_PREVIOUS_FILE='/srv/old key'\\''s'`,
    ],
  ]) {
    const result = await admin(['restore-snapshot', 'ID', '--data-dir', '/var/lib/uptime-goblin'], {
      uid: 0,
      env,
    });
    assert.equal(result.code, exitCodes.usage);
    assert.equal(
      result.err.slice(result.err.indexOf('sudo -u uptime-goblin ')),
      `sudo -u uptime-goblin env ${words} node ${script} restore-snapshot ID --data-dir /var/lib/uptime-goblin\n`
    );
  }
  // The previous key file: key rewrap names a placeholder without one, the others only one given.
  const rewrap = await admin(['key', 'rewrap', '--data-dir', '/var/lib/uptime-goblin'], { uid: 0 });
  assert.match(
    rewrap.err,
    /: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /
  );
  assert.match(
    rewrap.err,
    / GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node .* key rewrap --data-dir \/var\/lib\/uptime-goblin\n$/
  );
  const rotate = await admin(['key', 'rotate', '--data-dir', '/var/lib/uptime-goblin'], {
    uid: 0,
    env: { GOBLIN_SECRET_KEY_PREVIOUS_FILE: '/srv/old.key' },
  });
  assert.match(
    rotate.err,
    /: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=\/srv\/old\.key node /
  );
  // The CHANGELOG's line on how to run goblin-admin says so too (review F2v2, round 5: it gave the
  // form without the key file as the one to run, and as the one a root refusal prints).
  const notes = flat(unreleased());
  assert.doesNotMatch(notes, /a command that changes the data directory prints that form\./);
  for (const sentence of [
    'Until the installer adds a `goblin-admin` command, run it as `sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs COMMAND --data-dir /var/lib/uptime-goblin`, with `env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key` before `node` for the key commands and `restore-snapshot`, since `sudo -u uptime-goblin` starts a clean environment',
    'run as root, a command that changes the data directory prints that form, naming the key file it was given, else `/etc/uptime-goblin/secret.key`, and the previous key file it was given (`key rewrap`: else a placeholder).',
  ])
    assert.ok(notes.includes(sentence), sentence);
  assert.match(
    flat(read('docs/installation.md')),
    /Run as root, a command that changes the data directory refuses \(exit status 2\) and prints the command to use instead \(none when an argument holds a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate: it names that argument escaped instead\)\. For a key command that changes something \(`key rotate`, `key rewrap`, `key reset`, `key remove-data-copy`\), that line names in `env` the key files the command was given, else `\/etc\/uptime-goblin\/secret\.key`, as above, since `sudo -u uptime-goblin` starts a clean environment\. For `restore-snapshot`, which checks a keyring it brings back with the key \(\[snapshots\]\(#snapshots\)\), it names `GOBLIN_SECRET_KEY_FILE` the same way, and `GOBLIN_SECRET_KEY_PREVIOUS_FILE` when it was given one\./
  );
});

test('the 1.5 CHANGELOG describes the release, not the development builds, and introduces goblin-admin', async () => {
  const notes = unreleased();
  for (const history of [
    /it printed the key/,
    /waited for good on a FIFO/,
    /deleted the only (copy of the key|key that opened the data)/,
    /which as printed before failed/,
    /it replaces `docker compose exec uptime-goblin rm/,
    /where it only said to delete the file/,
    /phase stopped/,
    /said "not running \(no run\/status\.json\)"/,
    /before, only a start that succeeded named it/,
    /whose copy over that file had left Uptime Goblin refusing to start/,
    // The installer's development history (docs audit, keys 4): 1.5's preflight and
    // plain-HTTP sessions never shipped before, so no release behaved that way.
    /it read the first, so an appended `HOST=0\.0\.0\.0` was taken for loopback/,
    /the message blamed nginx/,
    // Fixes to sign-in, sessions and the user menu between 1.5 development builds.
    /it answered as failed and signed you out/,
    /was refused \(`multiple_credentials`\) while the page said it had signed out/,
    /before, the cookie had expired/,
    /so it took two/,
    /it was some 370 px past the visible edge/,
    /is no longer a click "elsewhere"/,
    /no longer closes the menu, which then hid that error/,
    /polling on and drawing the notice again every 15 seconds/,
  ])
    assert.doesNotMatch(notes, history);
  const bullet = notes.split('\n').find(line => line.startsWith('- **`goblin-admin`** (new):'));
  assert.ok(bullet, 'a goblin-admin bullet');
  for (const name of Object.keys(commands)) assert.ok(bullet.includes(`\`${name}`), name);
  for (const word of [
    'key rotate',
    'key rewrap',
    'key reset',
    'key status',
    'key compose-check',
    'key remove-data-copy',
    'migrate --plan',
    'migrate --apply',
  ])
    assert.ok(bullet.includes(word), word);
  assert.match(bullet, /`node --env-file-if-exists=\.env lib\/cli\/goblin-admin\.mjs COMMAND`/);
  assert.match(bullet, /Snapshots are never deleted automatically/);
});

test('Orbit 1.5 deletes no snapshot by itself, as the docs say, and the docs say how to delete one', () => {
  // deleteSnapshot only from goblin-admin snapshots --delete (offline, asked for); pruneSnapshots
  // from nowhere.
  const callers = { pruneSnapshots: [], deleteSnapshot: [] };
  const walk = directory => {
    for (const entry of fs.readdirSync(path.join(repository, directory), { withFileTypes: true })) {
      const file = `${directory}/${entry.name}`;
      if (entry.isDirectory()) walk(file);
      else if (file.endsWith('.mjs') && file !== 'lib/db/snapshot.mjs')
        for (const name of Object.keys(callers))
          if (new RegExp(`\\b${name}\\(`).test(read(file))) callers[name].push(file);
    }
  };
  walk('lib');
  for (const name of Object.keys(callers))
    if (new RegExp(`\\b${name}\\(`).test(read('server.mjs'))) callers[name].push('server.mjs');
  assert.deepEqual(
    callers,
    { pruneSnapshots: [], deleteSnapshot: ['lib/cli/commands/snapshots.mjs'] },
    'snapshots are deleted otherwise now: update docs/installation.md#snapshots'
  );
  const snapshots = section(read('docs/installation.md'), 'Snapshots', 4);
  assert.match(
    flat(snapshots),
    /Uptime Goblin 1\.5 never deletes a snapshot by itself: `goblin-admin snapshots --delete <id>` deletes one\./
  );
  assert.doesNotMatch(snapshots, /\brm -r\b/);
  assert.ok(
    snapshots.includes(
      '\n```sh\nsudo systemctl stop uptime-goblin.service\nsudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs snapshots --data-dir /var/lib/uptime-goblin --delete <id>\nsudo systemctl start uptime-goblin.service\n```\n'
    )
  );
  assert.ok(
    snapshots.includes(
      '\n```sh\ndocker compose stop uptime-goblin\ndocker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs snapshots --delete <id>\ndocker compose start uptime-goblin\n```\n'
    )
  );
  assert.match(flat(snapshots), /\*\*not an off-host backup\*\*/);
  assert.match(flat(snapshots), /Never delete `snapshots\/\.restore-in-progress\.json`/);
  assert.match(read('lib/db/snapshot.mjs'), /nothing calls it in 1\.5: every snapshot stays/);
});

test('a systemd credential: the docs never make it readable by orbit, and give the transient-service form', () => {
  const installation = read('docs/installation.md');
  assert.doesNotMatch(installation, /readable by the `uptime-goblin` user\)/);
  const block =
    '\n```sh\nsudo systemd-run --quiet --pipe --wait --collect --uid=uptime-goblin --gid=uptime-goblin -p LoadCredential=orbit-secret-key:/etc/credstore/orbit-secret-key "$(command -v node)" /opt/uptime-goblin/lib/cli/goblin-admin.mjs key status --data-dir /var/lib/uptime-goblin\n```\n';
  assert.ok(installation.includes(block));
  assert.match(
    flat(installation),
    /Do not make that file readable by `uptime-goblin`, and do not put the key on a command line\./
  );
  assert.match(
    flat(installation),
    /This form has not been run on a host for this release: run `key status` with it first, which changes nothing/
  );
  // The three texts give one way for SetCredentialEncrypted=, which has no file: encrypt the
  // key to a file and load that (docs audit, keys).
  const security = flat(read('docs/security.md'));
  assert.match(
    security,
    /the `goblin-admin` key commands then run in a transient service that loads the same file/
  );
  assert.match(
    security,
    /`SetCredentialEncrypted=` works for Uptime Goblin too, but has no file for that way: encrypt the key to a file instead\./
  );
  assert.doesNotMatch(security, /\(`LoadCredentialEncrypted=`, `SetCredentialEncrypted=`\)/);
  assert.match(
    flat(installation),
    /`SetCredentialEncrypted=` works for Uptime Goblin too \(`sudo systemd-creds encrypt -p --name=orbit-secret-key KEY_FILE -` prints the line\), but it has no file, and the documented way to run the `goblin-admin` key commands loads the credential from one \(\[with a systemd credential\]\(#goblin-admin\)\): encrypt the key to a file and use `LoadCredentialEncrypted=` instead\./
  );
  assert.match(
    flat(installation),
    /a `SetCredentialEncrypted=` value has no file, so save the key encrypted to one first/
  );
  // The command's own hint names the transient service too, not only the key file.
  assert.match(
    read('lib/cli/commands/key.mjs'),
    /run the command in a transient service that loads the same credential instead/
  );
});

// The code spans and code-block lines of the texts a reader copies key commands from (every
// line, for a file that is not Markdown).
function commandLines() {
  const found = [];
  for (const name of keyTexts()) {
    let fenced = false;
    read(name)
      .split('\n')
      .forEach((line, index) => {
        const where = `${name}:${index + 1}`;
        if (!name.endsWith('.md')) return found.push({ where, line });
        if (/^\s*```/.test(line)) return void (fenced = !fenced);
        if (fenced) return found.push({ where, line });
        for (const match of line.matchAll(/`([^`]+)`/g)) found.push({ where, line: match[1] });
      });
  }
  return found;
}

// A line that writes a key file, or sets its owner, is pasted as root. Its placeholder was
// `<backup>` (`<key file>` for systemd-creds), which a shell reads as redirections: in a folder
// holding a file named backup, `sudo install -o root -g uptime-goblin -m 0440 <backup>
// /etc/uptime-goblin/secret.key` became `sudo install … 0440` with its output going to the key file,
// which the shell emptied before sudo ran. Its placeholders are plain words now, which reach the
// command as they are.
test('a key line holds no < or >: run as printed, its placeholder reaches the command as a word and no key file changes', t => {
  const lines = commandLines().filter(({ line }) =>
    /\b(install -o root -g uptime-goblin|systemd-creds encrypt|chown root:uptime-goblin)\b/.test(
      line
    )
  );
  assert.ok(lines.length >= 10, `${lines.length} key lines`);
  const placeholders = lines.filter(({ line }) => /KEY_BACKUP_FILE|KEY_FILE|<[^>]*>/.test(line));
  assert.ok(placeholders.length >= 7, `${placeholders.length} key lines with a placeholder`);
  const base = temporary(t, 'orbit-docs-keys-paste-');
  const bin = path.join(base, 'bin');
  fs.mkdirSync(bin);
  // A stand-in sudo: it records its words and writes nothing.
  fs.writeFileSync(path.join(bin, 'sudo'), '#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$SUDO_WORDS"\n', {
    mode: 0o755,
  });
  for (const [index, { where, line }] of placeholders.entries()) {
    const run = path.join(base, String(index));
    const cwd = path.join(run, 'cwd');
    fs.mkdirSync(cwd, { recursive: true });
    // The words the old placeholders redirected from, and the placeholders themselves.
    const present = ['backup', 'key', 'file', 'KEY_BACKUP_FILE', 'KEY_FILE'];
    for (const word of present) fs.writeFileSync(path.join(cwd, word), '');
    // Each /etc file the line names, in a folder of the test's own, holding a key.
    const files = new Map();
    const mapped = line.replace(/\/etc\/[^\s`'")]+/g, file => {
      const own = path.join(run, file);
      fs.mkdirSync(path.dirname(own), { recursive: true });
      fs.writeFileSync(own, `${keyA}\n`, { mode: 0o600 });
      files.set(own, `${keyA}\n`);
      return `'${own}'`;
    });
    const words = path.join(run, 'sudo-words');
    const ran = spawnSync('sh', ['-c', mapped], {
      cwd,
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, SUDO_WORDS: words },
    });
    for (const [own, content] of files)
      assert.equal(fs.readFileSync(own, 'utf8'), content, `${where}: ${own} is as it was`);
    assert.deepEqual(fs.readdirSync(cwd).sort(), present.sort(), `${where}: no file made`);
    assert.equal(ran.status, 0, `${where}: ${ran.stderr}`);
    const said = fs.readFileSync(words, 'utf8');
    assert.match(said, /^(KEY_BACKUP_FILE|KEY_FILE)$/m, `${where}: the placeholder is a word`);
  }
  for (const { where, line } of lines) assert.doesNotMatch(line, /[<>]/, `${where}: ${line}`);
});

// OLD_KEY_FILE is a plain word too: pasted as printed, the key command looks for a file of that
// name in its working directory, which `sudo -u uptime-goblin` keeps. The docs said it stops with
// ENOENT; from a directory the uptime-goblin account cannot enter, such as one only root can enter, it
// is EACCES.
test('OLD_KEY_FILE pasted as it is: the key command reads that file in its working directory and stops with 78, ENOENT or EACCES, as the docs say', async t => {
  const { base, directory } = await started(t, { GOBLIN_SECRET_KEY: keyA });
  const keyFile = path.join(base, 'secret.key');
  writeKey(keyFile, keyA);
  const line = commandLines().find(
    ({ where, line }) =>
      where.startsWith('docs/configuration.md:') &&
      line.includes(' GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE ')
  )?.line;
  assert.ok(line, 'configuration.md gives the line with OLD_KEY_FILE');
  const mapped = line
    .replace(/^sudo -u uptime-goblin /, '')
    .replaceAll('/opt/uptime-goblin/', `${repository.replace(/\/$/, '')}/`)
    .replaceAll('/var/lib/uptime-goblin', `'${directory}'`)
    .replaceAll('/etc/uptime-goblin/secret.key', `'${keyFile}'`);
  assert.doesNotMatch(mapped, /\/etc\/orbit|\/var\/lib|\/opt\/uptime-goblin/, mapped);
  const env = {
    PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH}`,
    HOME: base,
  };
  const none = spawnSync('sh', ['-c', mapped], {
    cwd: temporary(t, 'orbit-docs-keys-cwd-'),
    encoding: 'utf8',
    env,
  });
  assert.equal(none.status, 78, none.stdout + none.stderr);
  assert.ok(
    none.stderr.includes('GOBLIN_SECRET_KEY_PREVIOUS_FILE (OLD_KEY_FILE) cannot be read: ENOENT.'),
    none.stderr
  );
  assert.match(
    flat(read('docs/installation.md')),
    /A shell passes the placeholder on as a plain word: pasted without replacing it, the command looks for the old key in a file named `OLD_KEY_FILE` in its working directory, which `sudo -u uptime-goblin` keeps from the shell, and where it cannot read one there it stops with exit status 78: "GOBLIN_SECRET_KEY_PREVIOUS_FILE \(OLD_KEY_FILE\) cannot be read: ENOENT\." where there is none, and "… cannot be read: EACCES\." where the `uptime-goblin` account cannot enter that directory, such as a directory only root can enter\./
  );
  // A working directory the command cannot enter. On macOS, Node cannot find its working
  // directory then and stops before the read; the native install is Linux. So it is Linux's
  // alone (test/platform-manifest.json), and needs a user other than root, who enters every
  // directory (its prerequisite non-root fails it as root).
  await platformSubtest(
    t,
    import.meta.url,
    'docs-keys.old-key-file.eacces',
    'from a working directory it cannot enter: EACCES',
    {},
    t => {
      const closed = temporary(t, 'orbit-docs-keys-closed-');
      let result;
      try {
        result = spawnSync(
          'sh',
          ['-c', 'cd "$1" && chmod 000 . && sh -c "$2"', 'sh', closed, mapped],
          {
            encoding: 'utf8',
            env,
          }
        );
      } finally {
        fs.chmodSync(closed, 0o700);
      }
      assert.equal(result.status, 78, result.stdout + result.stderr);
      assert.ok(
        result.stderr.includes(
          'GOBLIN_SECRET_KEY_PREVIOUS_FILE (OLD_KEY_FILE) cannot be read: EACCES.'
        ),
        result.stderr
      );
    }
  );
});

test('a lost key: the key file that does not open the data is kept, and the new one never replaces it', t => {
  const steps = read('docs/troubleshooting.md');
  const aside =
    /`(test -e orbit_secret_key\.lost && echo 'orbit_secret_key\.lost exists: choose another name' \|\| \{ cp -p orbit_secret_key orbit_secret_key\.lost && rm -f orbit_secret_key; \})`/.exec(
      steps
    )?.[1];
  assert.ok(aside, 'troubleshooting.md sets the Compose key aside');
  const make =
    '(umask 077 && openssl rand -hex 32 > orbit_secret_key) && chmod 0400 orbit_secret_key';
  const directory = temporary(t, 'orbit-docs-keys-lost-');
  fs.writeFileSync(path.join(directory, 'orbit_secret_key'), 'the key that does not open\n', {
    mode: 0o400,
  });
  const sh = line => spawnSync('sh', ['-c', line], { cwd: directory, encoding: 'utf8' });
  // Over the old file the new-key command fails and changes nothing (the docs say so).
  if (process.getuid?.() !== 0) {
    const over = sh(make);
    assert.notEqual(over.status, 0);
    assert.equal(
      fs.readFileSync(path.join(directory, 'orbit_secret_key'), 'utf8'),
      'the key that does not open\n'
    );
  }
  assert.equal(sh(aside).status, 0);
  assert.equal(
    fs.readFileSync(path.join(directory, 'orbit_secret_key.lost'), 'utf8'),
    'the key that does not open\n'
  );
  assert.equal(fs.existsSync(path.join(directory, 'orbit_secret_key')), false);
  assert.equal(sh(aside).stdout, 'orbit_secret_key.lost exists: choose another name\n');
  assert.match(
    steps,
    /`sudo test -e \/etc\/uptime-goblin\/secret\.key\.lost && echo 'secret\.key\.lost exists: choose another name' \|\| sudo mv \/etc\/uptime-goblin\/secret\.key \/etc\/uptime-goblin\/secret\.key\.lost`/
  );
  assert.match(
    steps,
    /5\. Start Uptime Goblin\. With a webhook set \(`GOBLIN_WEBHOOK_URL`\), it makes a new webhook signing key/
  );
});

test('verify-audit with a key that does not open the data says so, and names no development build', async t => {
  const keys = temporary(t, 'orbit-docs-keys-files-');
  const good = path.join(keys, 'good'),
    wrong = path.join(keys, 'wrong');
  writeKey(good, keyA);
  writeKey(wrong, keyB);
  const { base, directory } = await started(t, { GOBLIN_SECRET_KEY_FILE: good });
  // An entry to check: key rotate writes its own.
  const rotated = await admin(['key', 'rotate', '--data-dir', directory], {
    env: { GOBLIN_SECRET_KEY_FILE: good },
    directory: base,
  });
  assert.equal(rotated.code, 0, rotated.err);
  const result = await admin(['verify-audit', '--data-dir', directory], {
    env: { GOBLIN_SECRET_KEY_FILE: wrong },
    directory: base,
  });
  assert.equal(result.code, exitCodes.unverified, result.err);
  assert.match(result.err, /does not open this data \(key_mismatch\)/);
  assert.ok(
    result.out.includes(
      `The key this command was given (fingerprint ${print(keyB)}) does not open this data, so the signatures were not checked (only the links between entries).`
    ),
    result.out
  );
  assert.doesNotMatch(result.out, /No encryption key reached this command/);
  // --json keeps the contract's reason.
  const json = await admin(['verify-audit', '--json', '--data-dir', directory], {
    env: { GOBLIN_SECRET_KEY_FILE: wrong },
    directory: base,
  });
  assert.deepEqual(JSON.parse(json.out).unverifiable, [{ reason: 'no_key' }]);
  // Without a key it is still "no key".
  assert.match(
    reportLines({
      result: 'incomplete',
      rows: {},
      unverifiable: [{ reason: 'no_key' }],
      anchors: [],
    }).join('\n'),
    /^No encryption key reached this command/m
  );
  assert.doesNotMatch(read('lib/cli/commands/verify-audit.mjs'), /\d+\.\d+\.\d+-dev\.\d+/);
  assert.match(
    read('docs/troubleshooting.md'),
    /- \*\*The key given does not open this data\*\* \(`key_mismatch`, for example the old key after a `key rotate`\): only the links between entries were checked\./
  );
});

test('check-data says history.sqlite was not opened by 1.5 only while its events table lacks the columns 1.5 adds', async t => {
  const { directory } = await started(t);
  // A history.sqlite as 1.5 leaves it: no schema_migrations table there, the three columns.
  new Store(directory).close();
  const opened = await admin(['check-data', '--data-dir', directory], { directory });
  assert.equal(opened.code, 0, opened.out + opened.err);
  assert.equal(opened.out, 'No drift found.\n');
  // As 1.4.x left it: events without since, uid and relayed.
  const db = new DatabaseSync(path.join(directory, 'history.sqlite'));
  db.exec(
    'DROP INDEX events_unrelayed; ALTER TABLE events DROP COLUMN relayed; ALTER TABLE events DROP COLUMN uid; ALTER TABLE events DROP COLUMN since;'
  );
  db.close();
  const earlier = await admin(['check-data', '--data-dir', directory], { directory });
  assert.equal(earlier.code, 0, earlier.out + earlier.err);
  assert.equal(
    earlier.out,
    'history.sqlite has not been opened by Uptime Goblin 1.5 or later yet (its events table lacks the columns 1.5 adds).\nNo drift found.\n'
  );
});
test('the audit log names what key remove-data-copy --unused deleted: an older key, not a copy', () => {
  const rules = AUDIT_TEXTS['key.remove-data-copy'].texts.map(([when, text]) => [when, text]);
  assert.deepEqual(rules[0], [
    'ok unused=true',
    'goblin-admin deleted an older encryption key, which Uptime Goblin no longer used, from the data directory',
  ]);
  assert.deepEqual(rules[1], [
    'ok',
    'goblin-admin deleted the copy of the encryption key in the data directory',
  ]);
  // The page's copy is the server's (test/ui.test.mjs compares them in a browser too).
  const page = read('public/modules/configure/audit.js');
  assert.ok(
    page.includes(`'${rules[0][0]}',\n        '${rules[0][1]}',`),
    'public/modules/configure/audit.js'
  );
});

test('the Compose key change replaces orbit_secret_key only after key rotate, keeping the old one byte for byte', t => {
  const installation = read('docs/installation.md');
  const changing = section(installation, 'Changing the key', 4);
  const rotate =
    "docker compose run --rm --no-deps -T uptime-goblin sh -c 'umask 077 && cat > /tmp/new && GOBLIN_SECRET_KEY_FILE=/tmp/new GOBLIN_SECRET_KEY_PREVIOUS_FILE=/run/secrets/orbit_secret_key node lib/cli/goblin-admin.mjs key rotate' < orbit_secret_key.new";
  const swap =
    "test -e orbit_secret_key.old && echo 'orbit_secret_key.old exists: choose another name' || { cp -p orbit_secret_key orbit_secret_key.old && rm -f orbit_secret_key && cp orbit_secret_key.new orbit_secret_key && chmod 0400 orbit_secret_key && rm -f orbit_secret_key.new; }";
  assert.ok(
    changing.includes(`\ndocker compose stop uptime-goblin\n${rotate}\n`),
    'stop, then rotate'
  );
  assert.ok(changing.indexOf(rotate) < changing.indexOf(swap), 'the swap comes after the rotate');
  assert.ok(
    changing.includes(
      '\ndocker compose stop uptime-goblin\ndocker compose run --rm --no-deps --env GOBLIN_SECRET_KEY_PREVIOUS_FILE=/var/lib/uptime-goblin/secret.key uptime-goblin node lib/cli/goblin-admin.mjs key rotate\ndocker compose up -d --force-recreate\n'
    )
  );
  assert.match(flat(changing), /These Compose lines were measured on OrbStack/);
  const directory = temporary(t, 'orbit-docs-keys-swap-');
  fs.writeFileSync(path.join(directory, 'orbit_secret_key'), 'old\n', { mode: 0o400 });
  fs.writeFileSync(path.join(directory, 'orbit_secret_key.new'), 'new\n', { mode: 0o600 });
  const sh = () => spawnSync('sh', ['-c', swap], { cwd: directory, encoding: 'utf8' });
  assert.equal(sh().status, 0);
  const at = name => path.join(directory, name);
  assert.equal(fs.readFileSync(at('orbit_secret_key'), 'utf8'), 'new\n');
  assert.equal(fs.statSync(at('orbit_secret_key')).mode & 0o777, 0o400);
  assert.equal(fs.readFileSync(at('orbit_secret_key.old'), 'utf8'), 'old\n');
  assert.equal(fs.existsSync(at('orbit_secret_key.new')), false);
  assert.equal(sh().stdout, 'orbit_secret_key.old exists: choose another name\n');
  assert.equal(fs.readFileSync(at('orbit_secret_key.old'), 'utf8'), 'old\n');
});

// A key file path with a control character refuses the start (key_file_unreadable) before the
// file is opened. configuration.md documented the refusal only for GOBLIN_DATA_DIR, and the
// troubleshooting rows for key_file_unreadable named only ENOENT, EACCES and "is not a file".
test('docs: a key file path with a control character refuses the start, and configuration and troubleshooting say so', t => {
  const directory = temporary(t, 'orbit-docs-keys-path-');
  const forged = '/etc/uptime-goblin/secret.key\n[orbit] FORGED \u001b[2J \u202e';
  const messages = {};
  for (const variable of ['GOBLIN_SECRET_KEY_FILE', 'GOBLIN_SECRET_KEY_PREVIOUS_FILE'])
    assert.throws(
      () =>
        resolveKey({
          env: { GOBLIN_SECRET_KEY_FILE: path.join(directory, 'absent.key'), [variable]: forged },
          directory,
          credentialsDirectory: '',
          secretsDirectory: path.join(directory, 'no-secrets'),
          generate: false,
        }),
      error => {
        messages[variable] = error.message;
        return error.code === 'key_file_unreadable';
      },
      variable
    );
  // The configuration rows of both variables name the refusal.
  const configuration = read('docs/configuration.md').split('\n');
  for (const variable of Object.keys(messages)) {
    const row = configuration.find(line => line.startsWith(`| \`${variable}\` |`));
    assert.ok(row, `configuration.md has a row for ${variable}`);
    assert.match(row, /a control character[^|]*refuses the start/, variable);
  }
  // A troubleshooting row quotes the message ('…' where the path goes) and names both variables.
  const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rows = read('docs/troubleshooting.md')
    .split('\n')
    .filter(line => line.startsWith('| 78, "') && line.includes('key_file_unreadable'));
  for (const [variable, message] of Object.entries(messages)) {
    const covering = rows.find(line => {
      const cell = line.slice(2, line.indexOf(' | '));
      const quoted = /"([^"]+)"/.exec(cell)?.[1] ?? '';
      const pattern = new RegExp(
        `^${quoted.replace('GOBLIN_SECRET_KEY_FILE', variable).split('…').map(escape).join('.*')}$`
      );
      return cell.includes(variable) && pattern.test(message);
    });
    assert.ok(covering, `troubleshooting.md has a row for: ${message.slice(0, 80)}`);
  }
});

// What the docs say a key path or a data directory may not hold is what Uptime Goblin refuses, and no
// more: both docs said a "direction mark" refused the start, but a key file whose path holds
// U+061C, U+200E or U+200F is read. And GOBLIN_DATA_DIR, refused for fewer characters than a key
// path, started once with U+202E and then refused its own secret.key at every start, with no
// troubleshooting row for its refusal.
test('docs: a key path and a data directory may not hold exactly the characters the docs name, and troubleshooting quotes both refusals', async t => {
  const directory = temporary(t, 'orbit-docs-keys-characters-');
  const everyPoint = function* () {
    for (let point = 0; point <= 0x10ffff; point++)
      if (point < 0xd800 || point > 0xdfff) yield point;
  };
  const keyPathRefuses = point => {
    try {
      resolveKey({
        env: { GOBLIN_SECRET_KEY_FILE: path.join(directory, `k${String.fromCodePoint(point)}ey`) },
        directory,
        credentialsDirectory: '',
        secretsDirectory: path.join(directory, 'no-secrets'),
        generate: false,
      });
    } catch (error) {
      return /^GOBLIN_SECRET_KEY_FILE must be a path without /.test(error.message);
    }
    return false;
  };
  // What Uptime Goblin refuses, at every code point: the data directory's rule, which key paths share.
  const refused = [...everyPoint()].filter(point =>
    dataDirectoryProblem(`/x${String.fromCodePoint(point)}`)
  );
  for (const point of refused)
    assert.ok(keyPathRefuses(point), `a key path refuses U+${point.toString(16)}`);
  for (const mark of [0x061c, 0x200e, 0x200f])
    assert.ok(!refused.includes(mark) && !keyPathRefuses(mark), `U+${mark.toString(16)} is read`);
  // What a row names: a control character (Unicode's Cc), a Unicode line or paragraph separator
  // (U+2028, U+2029), and the embeddings, overrides and isolates by the ranges it lists.
  const controls = [...everyPoint()].filter(point => /\p{Cc}/u.test(String.fromCodePoint(point)));
  const kinds =
    'a control character (a line break, a tab, an escape), a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (';
  const named = (name, row) => {
    assert.ok(row, `${name} has a row`);
    const text = flat(row);
    assert.doesNotMatch(
      text,
      /direction mark/,
      `${name}: Uptime Goblin reads a path with a direction mark`
    );
    assert.ok(text.includes(kinds), `${name} names the three kinds`);
    const list = text.slice(text.indexOf(kinds) + kinds.length).split(')')[0];
    const range = /U\+([0-9A-F]{4})\u2013U\+([0-9A-F]{4})/;
    assert.match(list, new RegExp(`^${range.source}(, ${range.source})*$`), name);
    const points = [...controls, 0x2028, 0x2029];
    for (const [, from, to] of list.matchAll(new RegExp(range.source, 'g')))
      for (let point = parseInt(from, 16); point <= parseInt(to, 16); point++) points.push(point);
    return points.sort((a, b) => a - b);
  };
  const configuration = read('docs/configuration.md').split('\n');
  const troubleshooting = read('docs/troubleshooting.md').split('\n');
  const rows = {
    'configuration.md GOBLIN_DATA_DIR': configuration.find(line =>
      line.startsWith('| `GOBLIN_DATA_DIR` |')
    ),
    'configuration.md GOBLIN_SECRET_KEY_FILE': configuration.find(line =>
      line.startsWith('| `GOBLIN_SECRET_KEY_FILE` |')
    ),
    'troubleshooting.md GOBLIN_DATA_DIR': troubleshooting.find(line =>
      line.startsWith('| 78, "GOBLIN_DATA_DIR must not contain ')
    ),
    'troubleshooting.md GOBLIN_SECRET_KEY_FILE': troubleshooting.find(line =>
      line.startsWith('| 78, "GOBLIN_SECRET_KEY_FILE must be a path without ')
    ),
  };
  for (const [name, row] of Object.entries(rows)) assert.deepEqual(named(name, row), refused, name);
  // GOBLIN_SECRET_KEY_PREVIOUS_FILE's row names the same three kinds, and no direction mark.
  const previous = configuration.find(line =>
    line.startsWith('| `GOBLIN_SECRET_KEY_PREVIOUS_FILE` |')
  );
  assert.match(
    previous,
    /a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate refuses the start, as for `GOBLIN_SECRET_KEY_FILE`/
  );
  assert.doesNotMatch(previous, /direction mark/);
  // The data directory's troubleshooting row quotes the refusal of a start and of goblin-admin
  // ('\u2026' where it varies), each matched against the real text.
  const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = quote => new RegExp(quote.split('\u2026').map(escape).join('.*'));
  const row = rows['troubleshooting.md GOBLIN_DATA_DIR'];
  const quotes = [...row.slice(2, row.indexOf(' | ')).matchAll(/"([^"]+)"/g)].map(
    found => found[1]
  );
  const odd = path.join(directory, 'x\u202edata');
  let refusal = '';
  try {
    dataDirectory(odd);
  } catch (error) {
    refusal = error.message;
  }
  assert.match(refusal, new RegExp(`^${pattern(quotes[0]).source}$`));
  const fromOption = await admin(['status', '--data-dir', odd]);
  const fromEnvironment = await admin(['status'], { env: { GOBLIN_DATA_DIR: odd } });
  assert.deepEqual([fromOption.code, fromEnvironment.code], [exitCodes.usage, exitCodes.usage]);
  assert.equal(exitCodes.usage, 2, 'the row says exit status 2');
  assert.match(fromEnvironment.err, pattern(quotes[1]));
  assert.match(fromOption.err, pattern(quotes[2]));
  // Neither given: data/ beside Uptime Goblin, under the path Uptime Goblin is installed in.
  const beside = await admin(['status'], { root: path.join(directory, 'x\u202eorbit') });
  assert.equal(beside.code, exitCodes.usage);
  assert.match(beside.err, pattern(quotes[3]));
  assert.deepEqual(quotes.slice(1), [
    'GOBLIN_DATA_DIR must not contain \u2026',
    '--data-dir must not contain \u2026',
    'The data directory beside Uptime Goblin must not contain \u2026',
  ]);
});
