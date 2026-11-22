// goblin-admin: Uptime Goblin's administration command line (roadmap §2.11). The core in 1.5 wave 1:
//
//   node lib/cli/goblin-admin.mjs <command> [options]      (--data-dir, --json, --help)
//
// Commands live in lib/cli/commands/<name>.mjs and declare their kind:
//   read     works while Uptime Goblin runs and takes no lock (status, snapshots, check-data,
//            verify-audit, migrate --plan)
//   online   changes while Uptime Goblin runs, taking no lock: short control-database transactions;
//            identity writes bump meta.session_seq (users, revoke … arrive with identity in
//            wave 2); key remove-data-copy deletes <data>/secret.key once it is only a copy
//   offline  takes goblin.lock, so Uptime Goblin must be stopped (migrate --apply, snapshot,
//            restore-snapshot, key rewrap | rotate | reset)
// A command whose kind depends on its arguments exports kindFor(options, args) (migrate --plan,
// key status and key compose-check are read-only, key remove-data-copy is online).
//
// Exit status: 0 done, 1 failed, 2 usage, 3 not fully checked (verify-audit), 75 Uptime Goblin is running
// (goblin.lock held), 78 refused (the data needs a newer Uptime Goblin). Write commands refuse to run as root: files they create
// must stay owned by the uptime-goblin user (the native wrapper /usr/local/sbin/goblin-admin, from
// installer v2, will drop to it). Until that wrapper exists there is no goblin-admin command
// on the PATH, so the refusal prints the whole command that works: sudo -u uptime-goblin node <this
// script> … --data-dir <dir> (for a key command with env GOBLIN_SECRET_KEY_FILE=… first, as
// below; with an argument it cannot print as a shell word, no command: see asOrbitUser). The
// key commands read the master key from this process's own
// environment, never from /etc/uptime-goblin.env (root's, read only by systemd for the service), so
// natively they run as sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node …
// (lib/cli/commands/key.mjs).
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { asAdminCopy, keyEnvironment, nativeLayout, shellWord } from '../admin-command.mjs';
import {
  dataDirectoryProblem,
  jsonText,
  quoted,
  resolvedDataDirectoryProblem,
  unprintableProblem,
} from '../environment.mjs';
import { CommandError, exitCodes, inContainer } from './common.mjs';
import { printable } from '../saved-data.mjs';
import {
  adoptLegacyDataMount,
  adoptLegacyEnvironment,
  legacyEnvironmentNotice,
} from '../legacy-names.mjs';

export { CommandError, exitCodes };

export const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

/** The command registry (lane P). Each loads on demand. */
export const commands = Object.freeze({
  status: () => import('./commands/status.mjs'),
  migrate: () => import('./commands/migrate.mjs'),
  snapshot: () => import('./commands/snapshot.mjs'),
  snapshots: () => import('./commands/snapshots.mjs'),
  'restore-snapshot': () => import('./commands/restore-snapshot.mjs'),
  'check-data': () => import('./commands/check-data.mjs'),
  key: () => import('./commands/key.mjs'),
  display: () => import('./commands/display.mjs'),
  'verify-audit': () => import('./commands/verify-audit.mjs'),
});

const kinds = new Set(['read', 'online', 'offline']);

// An argument as an error message may show it: Node's parseArgs quotes an unknown option raw,
// so `--\e[31m…` reached the terminal as an escape sequence.
const escaped = text =>
  String(text).replace(
    /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`
  );

/**
 * What is wrong with the arguments as parsed, or null (exit status 2 for each): an option that
 * takes one value given twice (the last silently won, so `--data-dir a --data-dir b` worked on
 * b), an empty or unusable --data-dir (an empty one fell back to $GOBLIN_DATA_DIR or ./data),
 * and more positional arguments than the command takes (they were ignored).
 */
function argumentProblem(name, command, { tokens, values, positionals }) {
  const options = { ...globalOptions, ...(command.options ?? {}) };
  const seen = new Set();
  for (const token of tokens) {
    if (token.kind !== 'option' || options[token.name]?.multiple) continue;
    if (seen.has(token.name)) return `--${token.name} is given more than once.`;
    seen.add(token.name);
  }
  if (values['data-dir'] !== undefined) {
    if (values['data-dir'] === '') return '--data-dir needs a directory.';
    const problem = dataDirectoryProblem(values['data-dir']);
    if (problem) return `--data-dir ${problem}.`;
  }
  const most = command.maxPositionals ?? 0;
  if (positionals.length > most)
    return `${most ? `goblin-admin ${name} takes at most ${most} argument${most === 1 ? '' : 's'}` : `goblin-admin ${name} takes no arguments`}; ${quoted(positionals[most], 60)} is one too many.`;
  return null;
}

const globalOptions = {
  'data-dir': { type: 'string' },
  json: { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
};

// {line}: the same command run as the uptime-goblin user, with the data directory named: sudo resets the
// environment, so GOBLIN_DATA_DIR would not reach it, nor the key files a key command needs
// (`environment`: keyEnvironment()'s words, already quoted for the shell). Or {held}, below.
//
// shellWord quotes a word for the shell, not for the terminal that shows the line: an argument
// holding a line break, an escape or a direction override (the refusal comes before a command
// checks its arguments, such as restore-snapshot's id) wrote a line or a terminal command of its
// own. With such a word (by the rule of lib/environment.mjs) no line is printed (`held` names
// each such word instead, its text escaped and cut). A placeholder in its place (<argument-2>, as
// it was) is a shell redirection: pasted in a folder holding a file of that name, the line ran
// with its words shifted and its output went to a file named by the next word.
const asOrbitUser = (root, argv, dataDir, environment = [], account = 'uptime-goblin') => {
  const words = [
    { word: 'node' },
    {
      word: path.join(root, 'lib', 'cli', 'goblin-admin.mjs'),
      what: 'the path of goblin-admin.mjs',
    },
    ...argv.map((word, index) => ({ word, what: `argument ${index + 1} given to goblin-admin` })),
    ...(dataDir ? [{ word: '--data-dir' }, { word: dataDir, what: 'the data directory' }] : []),
  ];
  const held = words.flatMap(({ word, what }) => {
    const problem = unprintableProblem(word);
    return problem
      ? [
          `${what[0].toUpperCase()}${what.slice(1)} holds ${problem}; escaped, it is ${quoted(word, 80)}.`,
        ]
      : [];
  });
  return held.length
    ? { held }
    : {
        line: [
          'sudo',
          '-u',
          account,
          ...environment,
          ...words.map(({ word }) => shellWord(word)),
        ].join(' '),
      };
};

function isDirectory(directory) {
  try {
    return fs.statSync(directory).isDirectory();
  } catch {
    return false;
  }
}

function releaseOf(root) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

async function usage(write) {
  const lines = ['Usage: goblin-admin <command> [options]', '', 'Commands:'];
  for (const [name, load] of Object.entries(commands)) {
    const command = await load();
    lines.push(`  ${name.padEnd(18)} ${command.summary}`);
  }
  lines.push(
    '',
    'Options for every command:',
    '  --data-dir <dir>   the data directory (default: $GOBLIN_DATA_DIR, else ./data beside Uptime Goblin)',
    '  --json             machine-readable output',
    '  -h, --help         help for a command'
  );
  write(lines.join('\n') + '\n');
}

/**
 * Runs goblin-admin with `argv` (without node and the script). Returns the exit status; never
 * calls process.exit. io: {env, stdout(text), stderr(text), stdin, uid, clock, root, keySources,
 * container, proc} (stdin: what verify-audit --checkpoints - reads, process.stdin by default;
 * keySources: resolveKey's credentialsDirectory / secretsDirectory, for tests; container:
 * whether this runs in a Docker or Podman container, see inContainer(); proc: the /proc in which
 * an Uptime Goblin that keeps no run/status.json is looked for, see orbitServerProcess).
 */
export async function main(argv, io = {}) {
  const {
    env = process.env,
    stdout = text => process.stdout.write(text),
    stderr = text => process.stderr.write(text),
    stdin = process.stdin,
    uid = typeof process.getuid === 'function' ? process.getuid() : null,
    clock = Date.now,
    root = appRoot,
    keySources = {},
    container = inContainer(),
    proc = '/proc',
    outputStat,
  } = io;
  const [name, ...rest] = argv;
  if (!name || name === 'help' || name === '--help' || name === '-h') {
    await usage(stdout);
    return name ? exitCodes.ok : exitCodes.usage;
  }
  if (!Object.hasOwn(commands, name)) {
    // quoted, not JSON.stringify, which leaves the C1 controls and direction overrides raw.
    stderr(`goblin-admin: unknown command ${quoted(name, 80)}. Run goblin-admin help.\n`);
    return exitCodes.usage;
  }
  // The settings' names from before the rename (ORBIT_*), as a start takes them: each becomes its
  // GOBLIN_ name while that is unset, and both set to different values refuses (78).
  try {
    const notice = legacyEnvironmentNotice(adoptLegacyEnvironment(env));
    if (notice) stderr(`goblin-admin ${name}: ${notice}\n`);
    // In the container image, the data volume where a start finds it (server.mjs does the same).
    const mount = adoptLegacyDataMount(env, { appRoot: root, container });
    if (mount) stderr(`goblin-admin ${name}: ${mount}\n`);
  } catch (error) {
    stderr(`goblin-admin ${name}: ${printable(error.message, 8000)}\n`);
    return exitCodes.refused;
  }
  const command = await commands[name]();
  if (!kinds.has(command.kind) || typeof command.run !== 'function')
    throw new Error(`lib/cli/commands/${name}.mjs is not a valid command`);
  let parsed;
  try {
    parsed = parseArgs({
      args: rest,
      options: { ...globalOptions, ...(command.options ?? {}) },
      allowPositionals: true,
      strict: true,
      tokens: true,
    });
  } catch (error) {
    stderr(
      `goblin-admin ${name}: ${escaped(error.message)}\nUsage: goblin-admin ${name} ${command.usage ?? ''}\n`
    );
    return exitCodes.usage;
  }
  const { values, positionals } = parsed;
  const problem = argumentProblem(name, command, parsed);
  if (problem) {
    stderr(
      `goblin-admin ${name}: ${problem}\nUsage: goblin-admin ${name} ${command.usage ?? ''}\n`
    );
    return exitCodes.usage;
  }
  // The options given on the command line (parseArgs fills in defaults too), for a command's
  // optionProblem(): one that does not apply to what it was asked to do is refused, as it was
  // ignored before (key status --confirm-lost-key, migrate --plan --no-snapshot).
  const givenOptions = new Set(
    parsed.tokens.filter(token => token.kind === 'option').map(token => token.name)
  );
  if (values.help) {
    stdout(
      `Usage: goblin-admin ${name} ${command.usage ?? ''}\n\n${command.summary}\n${command.help ? `\n${command.help}\n` : ''}`
    );
    return exitCodes.ok;
  }
  if (!values['data-dir'] && env.GOBLIN_DATA_DIR && dataDirectoryProblem(env.GOBLIN_DATA_DIR)) {
    stderr(`goblin-admin ${name}: GOBLIN_DATA_DIR ${dataDirectoryProblem(env.GOBLIN_DATA_DIR)}.\n`);
    return exitCodes.usage;
  }
  const source = values['data-dir'] ? '--data-dir' : env.GOBLIN_DATA_DIR ? 'GOBLIN_DATA_DIR' : null;
  const dataDir = path.resolve(
    values['data-dir'] || env.GOBLIN_DATA_DIR || path.join(root, 'data')
  );
  // The checks above read the value as given: a relative one (data) names a directory below the
  // working directory, whose own path may hold such a character too, as a start checks (see
  // dataDirectory). status printed it raw, and the key commands refused <data>/secret.key.
  const resolvedProblem = source
    ? resolvedDataDirectoryProblem(values['data-dir'] || env.GOBLIN_DATA_DIR, dataDir)
    : dataDirectoryProblem(dataDir) &&
      `${dataDirectoryProblem(dataDir)}; it is ${quoted(dataDir, 80)}`;
  if (resolvedProblem) {
    stderr(
      `goblin-admin ${name}: ${source ?? 'The data directory beside Uptime Goblin'} ${resolvedProblem}.\n`
    );
    return exitCodes.usage;
  }
  const kind =
    typeof command.kindFor === 'function' ? command.kindFor(values, positionals) : command.kind;
  const optionProblem = command.optionProblem?.(givenOptions, values, positionals) ?? null;
  if (optionProblem) {
    stderr(`goblin-admin ${name}: ${optionProblem}\n`);
    return exitCodes.usage;
  }
  // A key file given to this command, as an absolute path (the key itself is never printed).
  const given = variable => (env[variable] ? path.resolve(env[variable]) : null);
  // Those paths are printed in command lines (the refusal to run as root below, and messages that
  // name a key command), before lib/keyring.mjs reads the file by its rule for key paths: one
  // that rule refuses, as given or resolved against the working directory, wrote its line break
  // or escape raw. Refused here by the same rule.
  for (const variable of ['GOBLIN_SECRET_KEY_FILE', 'GOBLIN_SECRET_KEY_PREVIOUS_FILE']) {
    if (!env[variable]) continue;
    const problem = unprintableProblem(env[variable]) ?? unprintableProblem(given(variable));
    if (problem) {
      stderr(
        `goblin-admin ${name}: ${variable} must be a path without ${problem}; it is ${quoted(env[variable], 80)}${path.isAbsolute(env[variable]) ? '' : `, resolved against the working directory to ${quoted(given(variable), 80)}`}.\n`
      );
      return exitCodes.usage;
    }
  }
  if (kind !== 'read' && uid === 0) {
    // A key command finds the master key only in its own environment, and sudo -u uptime-goblin starts a
    // clean one, so the line names the key files this one was given, else the installer's, as
    // every key command line goblin-admin prints does (A7 item 1). Without them the printed line
    // was refused again ("No encryption key reached this command"), and a reset with
    // --use-data-dir-key would have made <data>/secret.key the key, one Uptime Goblin does not read.
    // restore-snapshot checks a keyring it brings back with the key in its own environment
    // (docs/installation.md#snapshots), so its line names the key file too: without it the check
    // finds no key, or an older one left in the data directory, and cannot tell. It reads a
    // previous key too, which can open what the key does not, as at Uptime Goblin's start, so a previous
    // key file it was given stays in the line.
    // On the Orbit layout (a rollback to 1.4.x put it back: nativeLayout), its account and key file.
    const layout = nativeLayout(dataDir);
    const environment =
      name === 'key' || name === 'display'
        ? keyEnvironment({
            keyFile: given('GOBLIN_SECRET_KEY_FILE') ?? layout.keyFile,
            previous:
              positionals[0] === 'rewrap' || Boolean(given('GOBLIN_SECRET_KEY_PREVIOUS_FILE')),
            previousFile: given('GOBLIN_SECRET_KEY_PREVIOUS_FILE'),
          })
        : name === 'restore-snapshot'
          ? keyEnvironment({
              keyFile: given('GOBLIN_SECRET_KEY_FILE') ?? layout.keyFile,
              previous: Boolean(given('GOBLIN_SECRET_KEY_PREVIOUS_FILE')),
              previousFile: given('GOBLIN_SECRET_KEY_PREVIOUS_FILE'),
            })
          : [];
    const { line, held } = asOrbitUser(
      root,
      argv,
      values['data-dir'] ? null : dataDir,
      environment,
      layout.account
    );
    const head =
      layout.account === 'orbit'
        ? `goblin-admin ${name} changes the data directory, so it must not run as root (files would become root's). Run it as the user Orbit runs as on this layout (orbit)`
        : `goblin-admin ${name} changes the data directory, so it must not run as root (files would become root's). Run it as the user Uptime Goblin runs as (uptime-goblin for the native install)`;
    return (
      stderr(
        line
          ? `${head}: ${line}\n`
          : `${head}, with sudo -u ${layout.account}. No command line is printed here: it would hold a word that cannot be shown as a shell word.\n${held.join('\n')}\n`
      ),
      exitCodes.usage
    );
  }
  // A data directory that does not exist is never reported clean: check-data said "No drift
  // found." and snapshots "No snapshots." for a mistyped --data-dir. status reports it (and
  // the service binary) and exits 1 itself; every other command stops here.
  if (name !== 'status' && !isDirectory(dataDir)) {
    stderr(
      `goblin-admin ${name}: ${dataDir} ${fs.existsSync(dataDir) ? 'is not a directory' : 'does not exist'}.\n`
    );
    return exitCodes.failed;
  }
  const context = {
    name,
    kind,
    dataDir,
    uid,
    stdin,
    given: givenOptions,
    release: releaseOf(root),
    root,
    options: values,
    args: positionals,
    env,
    clock,
    keySources,
    container,
    proc,
    outputStat,
    json: values.json,
    out: text => stdout(text.endsWith('\n') ? text : text + '\n'),
    err: text => stderr(text.endsWith('\n') ? text : text + '\n'),
    /**
     * Prints `value` as JSON with --json, otherwise the lines `human()` returns. Those print
     * saved text printable (cut, without control characters). The JSON holds `value` as it is:
     * saved text a command puts in a field of its own is whole there, while a field it already
     * made printable (run/status.json's, a sentence such as a problem or a refusal) stays so.
     * Either way jsonText writes those characters as escapes: JSON.stringify left the C1
     * controls, U+2028, U+2029 and the direction overrides raw, so a crafted key id reached the
     * terminal.
     */
    report(value, human) {
      if (values.json) stdout(jsonText(value) + '\n');
      else stdout([human(value)].flat().join('\n') + '\n');
    },
  };
  try {
    // Messages built while the command runs (lib/db, lib/keyring.mjs) name this copy and data
    // directory when they print a goblin-admin command line: after a code rollback this is the
    // kept 1.5 copy, and /opt/uptime-goblin holds 1.4.x, which has none (admin-command.mjs). In a
    // container the paths are the image's, so they keep the native form and the docs pointer.
    // A key command line names the key files this one was given (adminCommand).
    const code = await asAdminCopy(
      container
        ? null
        : {
            root,
            dataDir,
            keyFile: given('GOBLIN_SECRET_KEY_FILE'),
            previousFile: given('GOBLIN_SECRET_KEY_PREVIOUS_FILE'),
          },
      () => command.run(context)
    );
    return Number.isInteger(code) ? code : exitCodes.ok;
  } catch (error) {
    const code =
      error?.name === 'LockHeldError'
        ? exitCodes.locked
        : error?.refusal === true || error?.exitCode === 78
          ? exitCodes.refused
          : Number.isInteger(error?.exitCode)
            ? error.exitCode
            : exitCodes.failed;
    // In a container (the Compose form, `docker compose run --rm --no-deps uptime-goblin …`) there is
    // no systemctl: Uptime Goblin runs in a container of its own, which Compose stops.
    const message =
      error?.name === 'LockHeldError'
        ? `Uptime Goblin (or another goblin-admin command) is using ${dataDir}. ${container ? 'Stop it first (docker compose stop uptime-goblin)' : nativeLayout(dataDir).account === 'orbit' ? 'Stop it first: sudo systemctl stop orbit' : 'Stop Uptime Goblin first: sudo systemctl stop uptime-goblin'}`
        : error?.message || String(error);
    // One line without control characters: a failure's text can quote saved data, as SQLite's
    // does a damaged database's own schema names (malformed database schema (<name>)), which
    // every command that opens it printed as they were, escape sequences and line breaks
    // included. Uptime Goblin's own messages are well under the cut. A command line to run instead
    // (CommandError's `command`) goes alone on the next line, so that it can be copied whole.
    const command =
      error instanceof CommandError && typeof error.command === 'string'
        ? `\n${printable(error.command, 8000)}`
        : '';
    stderr(`goblin-admin ${name}: ${printable(message, 8000)}${command}\n`);
    if (
      !(error instanceof CommandError) &&
      ![exitCodes.locked, exitCodes.refused].includes(code) &&
      env.GOBLIN_ADMIN_DEBUG
    )
      stderr(`${error?.stack ?? ''}\n`);
    return code;
  }
}

const isMain = () => {
  try {
    return (
      Boolean(process.argv[1]) &&
      fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
};
if (isMain()) {
  process.umask(0o077);
  process.exitCode = await main(process.argv.slice(2));
}
