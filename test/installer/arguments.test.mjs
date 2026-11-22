// deploy/install.sh's own input: its options (exact, each once, a missing value a usage
// error), --trust-proxy off and --allow-insecure-http, --listen and --allowed-hosts on an install
// that has /etc/uptime-goblin.env, the test-only GOBLIN_INSTALL_ROOT, and the command lines it prints to
// paste.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { makeFreshHost, makeHost, makeSource, temporary } from './helpers.mjs';

const ok = result => `installer exited ${result.status}:\n${result.output}`;
const envOf = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');

test('installer options: a missing value, a repeat or a value Uptime Goblin would refuse exits 2 before anything changes', async t => {
  const host = await makeHost(t);
  const source = makeSource(t, { mode: 'ok' });
  const before = envOf(host);
  const refused = async (args, pattern, env) => {
    const result = await host.install(source, args, env);
    assert.equal(result.status, 2, `${JSON.stringify(args)}: ${ok(result)}`);
    assert.match(result.stderr, pattern, JSON.stringify(args));
    assert.equal(host.calls(), '', 'systemctl was not called');
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
    assert.ok(!fs.existsSync(host.path('var/lib/uptime-goblin')));
    assert.equal(envOf(host), before);
    return result;
  };
  // ${2:?} exited 1, as a failed install does.
  await refused(['--listen'], /^--listen needs a value: the address Uptime Goblin listens on/m);
  await refused(['--trust-proxy', ''], /^--trust-proxy needs a value/m);
  await refused(['--verify-timeout', '--allow-loopback'], /^--verify-timeout needs a value/m);
  // The last of two silently won.
  await refused(
    ['--trust-proxy', 'loopback', '--trust-proxy', '10.0.0.1'],
    /^--trust-proxy is given more than once\.$/m
  );
  await refused(
    ['--allow-loopback', '--allow-loopback'],
    /^--allow-loopback is given more than once\.$/m
  );
  await refused(
    ['--allow-insecure-http', '--allow-insecure-http'],
    /^--allow-insecure-http is given more than once\.$/m
  );
  await refused(
    ['--allow-downgrade', '--allow-downgrade'],
    /^--allow-downgrade is given more than once\.$/m
  );
  await refused(
    ['--restore-orbit-layout', '--restore-orbit-layout'],
    /^--restore-orbit-layout is given more than once\.$/m
  );
  // Going back to Orbit installs nothing: an install option beside it is a usage error.
  await refused(
    ['--restore-orbit-layout', '--allow-loopback'],
    /^--restore-orbit-layout takes no other option but --verify-timeout: it installs nothing\.$/m
  );
  // It takes no value; an unknown option names the options there are.
  const valued = await refused(
    ['--allow-insecure-http=1'],
    /^Unknown option: --allow-insecure-http=1$/m
  );
  assert.match(
    valued.stderr,
    /^Options: --listen <address>, --allowed-hosts <names>, --trust-proxy <proxies>, --allow-loopback, --allow-insecure-http, --proxy-proto-checked, --verify-timeout <seconds>, --allow-downgrade, --restore-orbit-layout \(see the start of deploy\/install\.sh\)\.$/m
  );
  // A range that trusts every client, by Uptime Goblin's own parser.
  await refused(
    ['--trust-proxy', '0.0.0.0/0'],
    /trusts too many addresses[\s\S]*Invalid --trust-proxy value/
  );
  // Host entries no request can match, by Uptime Goblin's own rule (a port out of range here).
  await refused(
    ['--allowed-hosts', 'goblin.example:70000'],
    /GOBLIN_ALLOWED_HOSTS entry "goblin\.example:70000" is not a host name[\s\S]*Invalid --listen or --allowed-hosts value/
  );
  // Decimal with leading zeros (bash read 0010 as 8 and 08 as an error): 08 passes to the
  // next check, 0000 is 0.
  await refused(
    ['--verify-timeout', '08', '--allowed-hosts', 'goblin.example:70000'],
    /Invalid --listen or --allowed-hosts value/
  );
  await refused(['--verify-timeout', '0000'], /--verify-timeout takes 1 to 1800 seconds/);
  // An unknown option is shown quoted for the shell.
  const odd = await refused(['--\u001b[31mred'], /^Unknown option: \$'--\\E\[31mred'$/m);
  assert.ok(!odd.stderr.includes('\u001b'));
});

test('GOBLIN_INSTALL_ROOT without the test guard is refused before anything changes', async t => {
  const host = await makeHost(t);
  const result = await host.install(makeSource(t, { mode: 'ok' }), [], {
    GOBLIN_INSTALLER_TEST: '',
  });
  assert.equal(result.status, 2, ok(result));
  assert.match(
    result.stderr,
    /^GOBLIN_INSTALL_ROOT is set, but it is only for the installer tests\./m
  );
  assert.equal(host.calls(), '');
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
});

test('printed recovery commands quote a key file path with a space or shell characters', async t => {
  const host = await makeHost(t);
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const file = "/srv/orbit keys/it's.key";
  const quoted = `'/srv/orbit keys/it'\\''s.key'`;
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), `GOBLIN_SECRET_KEY_FILE=${file}\n`);
  // Missing: the restore line.
  const missing = await host.install(source);
  assert.equal(missing.status, 1, ok(missing));
  // Pasted as printed, the line's placeholder reaches install as a word. As <backup>, a shell
  // in a folder holding a file named backup read it as `sudo install … 0440` with its output
  // going to the key file, which the shell emptied before sudo ran.
  const restore = /\((sudo install -o root -g uptime-goblin -m 0440 [^,)]+)/.exec(
    missing.stderr
  )?.[1];
  assert.ok(restore?.endsWith(` ${quoted}`), missing.stderr);
  const paste = temporary(t, 'orbit-paste-');
  const bin = path.join(paste, 'bin');
  const cwd = path.join(paste, 'cwd');
  fs.mkdirSync(bin);
  fs.mkdirSync(cwd);
  for (const word of ['backup', 'KEY_BACKUP_FILE']) fs.writeFileSync(path.join(cwd, word), '');
  const words = path.join(paste, 'sudo-words');
  // A stand-in sudo: it records its words and writes nothing.
  fs.writeFileSync(path.join(bin, 'sudo'), '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$SUDO_WORDS"\n', {
    mode: 0o755,
  });
  const keyFile = path.join(paste, "the orbit key's file");
  const key = 'a1b2'.repeat(16) + '\n';
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  const ran = spawnSync(
    'sh',
    ['-c', restore.replace(` ${quoted}`, ` '${keyFile.replaceAll("'", "'\\''")}'`)],
    {
      cwd,
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, SUDO_WORDS: words },
    }
  );
  assert.equal(fs.readFileSync(keyFile, 'utf8'), key, 'the key file is as it was');
  assert.equal(ran.status, 0, ran.stderr);
  assert.deepEqual(fs.readFileSync(words, 'utf8').split('\n').slice(0, -1), [
    'install',
    '-o',
    'root',
    '-g',
    'uptime-goblin',
    '-m',
    '0440',
    'KEY_BACKUP_FILE',
    keyFile,
  ]);
  assert.deepEqual(fs.readdirSync(cwd).sort(), ['KEY_BACKUP_FILE', 'backup']);
  assert.ok(
    missing.stderr.includes(
      `(sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE ${quoted}, with KEY_BACKUP_FILE replaced by the path of your backup)`
    ),
    missing.stderr
  );
  assert.doesNotMatch(missing.stderr, /[<>]/);
  // There, but the uptime-goblin account cannot read it: the chown and chmod line.
  fs.mkdirSync(host.path('srv/orbit keys'), { recursive: true, mode: 0o755 });
  fs.writeFileSync(host.path(file.slice(1)), 'a1b2'.repeat(16) + '\n', { mode: 0o600 });
  const unreadable = await host.install(source);
  assert.equal(unreadable.status, 1, ok(unreadable));
  assert.ok(
    unreadable.stderr.includes(
      `sudo chown root:uptime-goblin ${quoted} && sudo chmod 0440 ${quoted},`
    ),
    unreadable.stderr
  );
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
});

test('--trust-proxy off turns proxy trust off: on the network that needs --allow-insecure-http; --listen on an existing install says it was not applied', async t => {
  // The service refuses to start (exit 78): nothing listens on 0.0.0.0 during the test.
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const host = await makeHost(t);
  const text =
    envOf(host).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + 'GOBLIN_TRUST_PROXY=loopback\n';
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), text);
  const args = [
    '--trust-proxy',
    'off',
    '--listen',
    '192.0.2.5',
    // Decimal however it is written (bash read 0010 as octal 8).
    '--verify-timeout',
    '0002',
  ];
  // Uptime Goblin reads off as no proxy, and so does the installer: Uptime Goblin on 0.0.0.0 without one would
  // sign in over plain HTTP, which only the operator may choose. Nothing changes.
  const stopped = await host.install(source, args);
  assert.equal(stopped.status, 1, ok(stopped));
  assert.match(
    stopped.stderr,
    /^Uptime Goblin would listen on 0\.0\.0\.0 \(HOST in \/etc\/uptime-goblin\.env\) with no reverse proxy it trusts/
  );
  assert.equal(envOf(host), text);
  const result = await host.install(source, [...args, '--allow-insecure-http']);
  const env = envOf(host);
  assert.match(env, /^GOBLIN_TRUST_PROXY=$/m);
  assert.match(env, /^GOBLIN_INSECURE_HTTP_SESSIONS=1$/m);
  assert.match(
    result.stdout,
    /Updated GOBLIN_TRUST_PROXY and GOBLIN_INSECURE_HTTP_SESSIONS in \/etc\/uptime-goblin\.env\./
  );
  assert.match(
    result.stderr,
    /^WARNING: --allow-insecure-http added GOBLIN_INSECURE_HTTP_SESSIONS=1/m
  );
  assert.match(
    result.stderr,
    /^Not applied: --listen and --allowed-hosts only fill in a new \/etc\/uptime-goblin\.env\./m
  );
  assert.match(env, /^HOST=0\.0\.0\.0$/m, 'HOST kept');
});

test('--allowed-hosts takes a bracketed IPv6 host value', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const host = await makeFreshHost(t);
  const result = await host.install(source, [
    '--allowed-hosts',
    `[::1]:4317,localhost:${host.port}`,
  ]);
  assert.equal(result.status, 0, ok(result));
  assert.ok(host.wroteDefaultPort(), 'the installer wrote PORT=4317');
  assert.match(result.stdout, /Created private settings in \/etc\/uptime-goblin\.env/, ok(result));
  assert.match(
    envOf(host),
    new RegExp(`^GOBLIN_ALLOWED_HOSTS=\\[::1\\]:4317,localhost:${host.port}$`, 'm')
  );
});
