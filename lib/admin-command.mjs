// How a refusal names a goblin-admin command. Until installer v2's wrapper there is no
// `goblin-admin` on the PATH (the LXC install answers "command not found"), so a bare
// "goblin-admin <command>" in a message cannot be run as printed. Messages give the native
// install's whole command line, which works there as printed, and send Docker Compose and
// other installs to docs/installation.md#goblin-admin, which has their form. The CLI's own
// refusal to run as root prints the command for the directories it was given instead.
//
// A message built while goblin-admin itself runs natively names that copy and data directory
// instead (main() in lib/cli/goblin-admin.mjs runs each command inside asAdminCopy). After the
// documented code rollback the 1.5 copy is kept beside the installed code (.previous or .failed)
// and the installed code is 1.4.x, which has no goblin-admin, so its command line fails with
// "Cannot find module" exactly when the kept copy sends the operator there (an interrupted
// restore, a refused migration, a key it cannot open). The messages come from lib/db and
// lib/keyring.mjs, below the CLI, so the copy reaches them through an AsyncLocalStorage rather
// than as an argument through every layer. The server never sets it: its messages keep the
// installed copy's form, which is right natively and is translated for Compose by the docs.
import path from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';

// Where the native installer puts the code, the data and the encryption key.
const installedRoot = '/opt/uptime-goblin';
const installedData = '/var/lib/uptime-goblin';
export const installedKeyFile = '/etc/uptime-goblin/secret.key';

// The two native layouts a command line can be for: Uptime Goblin's, and Orbit's (releases before
// 1.5), which a host has again after the installer rolled the upgrade from Orbit back, or went
// back to Orbit (deploy/install.sh --restore-orbit-layout). 1.4.x reads only the Orbit names and
// paths, so it runs only there: as orbit.service, under the account orbit, on /var/lib/orbit,
// with /etc/orbit/secret.key, while the 1.5 copy is kept in /opt/uptime-goblin.failed.
const goblinLayout = Object.freeze({
  product: 'Uptime Goblin',
  account: 'uptime-goblin',
  unit: 'uptime-goblin.service',
  dataDir: installedData,
  keyFile: installedKeyFile,
});
const orbitLayout = Object.freeze({
  product: 'Orbit',
  account: 'orbit',
  unit: 'orbit.service',
  dataDir: '/var/lib/orbit',
  keyFile: '/etc/orbit/secret.key',
});

/**
 * The native layout of data directory `dataDir`: Orbit's for a /var/lib/orbit (the directory
 * itself, also below another root, as an install root of the installer tests puts it), else
 * Uptime Goblin's, an unknown one included.
 */
export function nativeLayout(dataDir) {
  const resolved = typeof dataDir === 'string' && dataDir ? path.resolve(dataDir) : installedData;
  return resolved === orbitLayout.dataDir || resolved.endsWith(orbitLayout.dataDir)
    ? orbitLayout
    : goblinLayout;
}

/** The native layout of the release `version` runs as: Orbit's for one before 1.5. */
export const releaseLayout = product => (product === 'Orbit' ? orbitLayout : goblinLayout);

const running = new AsyncLocalStorage();

/** A word as the shell reads it back unchanged. */
export const shellWord = word =>
  /^[A-Za-z0-9._/:=@%+,-]+$/.test(word) ? word : `'${word.replaceAll("'", `'\\''`)}'`;

/**
 * Runs `task` with the messages it builds naming goblin-admin as `copy` ({root, dataDir, keyFile,
 * previousFile}: the code directory the CLI runs from, the data directory it was given, and the
 * key files it was given, if any), or as the installed copy when `copy` is null (in a container,
 * where the CLI's own paths are the image's).
 */
export function asAdminCopy(copy, task) {
  return running.run(copy ?? null, task);
}

/**
 * True while goblin-admin runs natively from a copy other than /opt/uptime-goblin: after a rollback
 * to Orbit that is the 1.5 copy kept beside the installed 1.4.x (/opt/uptime-goblin.failed), whose
 * service the docs disable until a restore has finished (1.4.x does not check for an interrupted
 * one).
 */
export function fromKeptCopy() {
  const copy = running.getStore();
  return Boolean(copy) && path.resolve(copy.root) !== installedRoot;
}

/** The native layout of the data directory the running goblin-admin was given (nativeLayout). */
export function runningLayout() {
  return nativeLayout(running.getStore()?.dataDir);
}

/**
 * `goblin-admin <args>` as a message names it: the native install's command line (run as the
 * uptime-goblin user, with its data directory), then where the other installs' form is. Inside
 * asAdminCopy, the copy that runs and its data directory, and, on the Orbit layout (nativeLayout),
 * the orbit account and /etc/orbit/secret.key.
 *
 * A key command (`key: true`) also names the key file. goblin-admin finds the master key only in
 * its own environment, and natively that is never the service's: systemd reads /etc/uptime-goblin.env
 * (root's alone) for Uptime Goblin, while `sudo -u uptime-goblin` starts a clean environment. Without the file
 * the command cannot see the key Uptime Goblin uses: `key status` cannot check it, `key rotate` stops,
 * and a reset would make a key Uptime Goblin does not use. The file is `keyFile` (the one the server
 * runs with), else the one goblin-admin was given, else the installer's. `previous: true` adds
 * GOBLIN_SECRET_KEY_PREVIOUS_FILE (a file, so the old key stays out of the command line and the
 * shell's history): `previousFile` (the one the server runs with), else the file goblin-admin was
 * given, else a placeholder to replace.
 */
export function adminCommand(args, options = {}) {
  return `${adminLine(args, options)} (${nativeInstallNote})`;
}

/** Which install adminCommand()'s line is for, and where the other installs' form is. */
export const nativeInstallNote =
  'the native install; Docker Compose and other installs: docs/installation.md#goblin-admin';

/**
 * adminCommand()'s command line alone, for a message that gives it as a line to copy and run:
 * the message says which install it is for (nativeInstallNote) before it, in its own words.
 * Copied whole, a line that ends in that note fails in sh and zsh (the parenthesis is a syntax
 * error), and a `#` comment is no way out: interactive zsh reads it as words unless
 * interactivecomments is set.
 */
export function adminLine(
  args,
  { key = false, previous = false, keyFile = null, previousFile = null } = {}
) {
  const copy = running.getStore();
  const layout = nativeLayout(copy?.dataDir);
  const script = path.join(copy?.root ?? installedRoot, 'lib', 'cli', 'goblin-admin.mjs');
  const env = key
    ? keyEnvironment({
        keyFile: keyFile ?? copy?.keyFile ?? layout.keyFile,
        previous,
        previousFile: previousFile ?? copy?.previousFile,
      })
    : [];
  return `sudo -u ${layout.account} ${[...env, 'node', shellWord(script)].join(' ')} ${args} --data-dir ${shellWord(copy?.dataDir ?? installedData)}`;
}

// The previous key file's placeholder in a printed command line. A shell takes it as a plain
// word, so the line, pasted as it is, passes it on: goblin-admin then looks for a file of that name
// in the working directory and, finding none, stops (78, the key file cannot be read). It was
// <old-key-file>, which a shell reads as redirections: pasted in a folder holding a file named
// old-key-file, the line ran env with GOBLIN_SECRET_KEY_PREVIOUS_FILE empty and the script as the
// program, its words shifted, and wrote its output to a new file named node.
const previousKeyPlaceholder = 'OLD_KEY_FILE';

/**
 * The words a native key command line gives `env` (adminCommand, and goblin-admin's own refusal
 * to run as root): GOBLIN_SECRET_KEY_FILE (`keyFile`, else the installer's), and with `previous`
 * GOBLIN_SECRET_KEY_PREVIOUS_FILE (`previousFile`, else previousKeyPlaceholder, to replace).
 * Shell words.
 */
export function keyEnvironment({ keyFile = null, previous = false, previousFile = null } = {}) {
  return [
    'env',
    `GOBLIN_SECRET_KEY_FILE=${shellWord(keyFile ?? installedKeyFile)}`,
    ...(previous
      ? [
          `GOBLIN_SECRET_KEY_PREVIOUS_FILE=${previousFile ? shellWord(previousFile) : previousKeyPlaceholder}`,
        ]
      : []),
  ];
}
