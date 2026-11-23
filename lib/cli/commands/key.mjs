// goblin-admin key status | compose-check | remove-data-copy [--unused] | rewrap | rotate | reset
// --confirm-lost-key (roadmap §2.8).
//
//   status   read-only: where the master key comes from, its fingerprint, and whether it opens
//            every data key of the keyring (never generates a key)
//   compose-check
//            read-only, the check of compose.secret.yaml: compares the Compose secret (mounted
//            when orbit_secret_key exists) and <data>/secret.key with the keyring and prints
//            which key recipe the volume takes, NEW, KEEP, COPY, MOVE or RESTORE, then why, and
//            after KEEP beside a <data>/secret.key Uptime Goblin does not use, the line that deletes it
//            (composeKeyChoice in lib/keyring.mjs)
//   remove-data-copy
//            online (no lock: it runs beside a live Uptime Goblin, in its container under Compose):
//            deletes <data>/secret.key only while the key this command is given, Uptime Goblin's own
//            when it runs through docker compose exec, comes from another file (or
//            GOBLIN_SECRET_KEY), is the same key byte for byte and opens the data; otherwise it says why and deletes nothing
//            (removeDataKeyCopy in lib/keyring.mjs, A66). The last line of the Compose copy and
//            MOVE recipes, in place of docker compose exec uptime-goblin rm /app/data/secret.key, which a
//            recipe pasted whole ran after a step that had stopped, deleting the only key that
//            opened the data. With --unused (A67) it deletes an older key instead, one the data
//            moved from with key rewrap, which it keeps otherwise: only while the key it is given
//            comes from another source and opens every data key, and that file holds another key
//            that opens none of them. Neither deletes the file GOBLIN_SECRET_KEY_PREVIOUS_FILE
//            names, which Uptime Goblin reads at every start
//   rewrap   offline: after the master key changed (new key in place, the old one in
//            GOBLIN_SECRET_KEY_PREVIOUS or GOBLIN_SECRET_KEY_PREVIOUS_FILE), wrap every data key
//            with the new one
//   rotate   offline: new data keys (all purposes, or --purpose …); the old ones are retired
//            and still open what they sealed. Component hooks re-seal their values.
//   reset    offline, for a lost master key only (--confirm-lost-key): forget every data key
//            and make new ones under the key configured for this command. Values sealed under
//            the old keys can no longer be read; each component's reset hook drops them, and
//            settings secrets read as unset until set again.
//
// The master key comes from this command's own environment, in Uptime Goblin's order (resolveKey), and
// that is not Uptime Goblin's environment: natively systemd gives the service /etc/uptime-goblin.env, which is
// root's alone, while `sudo -u uptime-goblin` starts a clean one; under Compose the secret is mounted
// only with compose.secret.yaml. So the documented command lines name the key file
// (sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node …, adminCommand), and a
// command that finds no key never takes that for a lost key: status says the key did not reach
// it, rotate and rewrap say how to give it, and reset will not make <data>/secret.key the key
// (finding it, or generating it) without --use-data-dir-key. Otherwise a reset run without the
// key on a healthy install made a key the service never reads: its next start refused
// (key_mismatch) and the webhook signing key was gone.
//
// Every start of Uptime Goblin opens the keyring, and creates it once identity has accepted the start
// (startControl keyring 'deferred', delivery spec D6): with the key from GOBLIN_SECRET_KEY_FILE or
// another configured source, or a <data>/secret.key it generates. Until that first start there
// is no keyring, so rotate and rewrap have nothing to work on; the texts below say so.
//
// The audit log (audit spec §7.2, D17, D20): rewrap, rotate and remove-data-copy each append
// their entry under the keyring they opened, inside the command (before the key is wiped); one
// that cannot be written is said on stderr and leaves the exit status as it is, so a break-glass
// command still works on a damaged or full disk. reset writes key.reset in the same unit as the
// new keys (Keyring.reset's inUnit), signed by the new audit key: it names the keys whose
// entries can no longer be checked, so a reset that cannot write it leaves the keyring as it was
// (a <data>/secret.key it generated for --use-data-dir-key stays, and its message says so). No
// component hook is registered in this release.
import os from 'node:os';
import path from 'node:path';
import { controlExists, openControl } from '../../db/control.mjs';
import {
  Keyring,
  KeyError,
  KeyHooks,
  composeKeyChoice,
  keyPurposes,
  keySourceLabel,
  removalNote,
  removeDataKeyCopy,
  removeDataKeyLine,
  resolveKey,
  secretKeyFile,
} from '../../keyring.mjs';
import { adminCommand, installedKeyFile } from '../../admin-command.mjs';
import { quoted } from '../../environment.mjs';
import { appendDirect, recordWith } from '../../audit/writer.mjs';
import { printable } from '../../saved-data.mjs';
import { CommandError, exitCodes, withLock, formatTime } from '../common.mjs';

export const summary =
  "Show, check, rewrap, rotate or reset the encryption keys, or remove the data directory's copy (status and compose-check are read-only).";
export const usage =
  'status | compose-check | remove-data-copy [--unused] | rewrap | rotate [--purpose <p>]… | reset --confirm-lost-key [--use-data-dir-key] [--data-dir <dir>] [--json]';
export const kind = 'offline';
const actions = ['status', 'compose-check', 'remove-data-copy', 'rewrap', 'rotate', 'reset'];
const readOnly = new Set(['status', 'compose-check']);
// remove-data-copy deletes one file while Uptime Goblin runs, and takes no lock: online.
export const kindFor = (options, args = []) =>
  readOnly.has(args[0]) ? 'read' : args[0] === 'remove-data-copy' ? 'online' : 'offline';
export const options = {
  purpose: { type: 'string', multiple: true },
  'confirm-lost-key': { type: 'boolean', default: false },
  'use-data-dir-key': { type: 'boolean', default: false },
  unused: { type: 'boolean', default: false },
};
// The action, nothing more.
export const maxPositionals = 1;
// The options each action takes; any other refuses the command (exit status 2) before a key is
// read or goblin.lock is taken.
const actionOptions = {
  status: [],
  'compose-check': [],
  'remove-data-copy': ['unused'],
  rewrap: [],
  rotate: ['purpose'],
  reset: ['confirm-lost-key', 'use-data-dir-key'],
};
/**
 * Why the options given (`given`, their names) do not fit the action, or null (goblin-admin.mjs
 * main() refuses with exit status 2). Checked before the lock: an option the action does not
 * take was ignored (key status --confirm-lost-key), an unknown --purpose was refused only once
 * the database was open, and a repeated one made two new keys of which one was never retired.
 */
export function optionProblem(given, values, args = []) {
  const allowed = actionOptions[args[0]];
  if (!allowed) return null; // run() prints the usage.
  for (const name of Object.keys(options))
    if (given.has(name) && !allowed.includes(name)) {
      const actions = Object.keys(actionOptions).filter(action =>
        actionOptions[action].includes(name)
      );
      return `--${name} applies to key ${actions.join(' and ')} only.`;
    }
  const purposes = values.purpose ?? [];
  for (const purpose of purposes)
    if (!keyPurposes.includes(purpose))
      return `Unknown key purpose ${quoted(purpose)} (one of ${keyPurposes.join(', ')}).`;
  const repeated = purposes.find((purpose, index) => purposes.indexOf(purpose) !== index);
  if (repeated) return `--purpose ${repeated} is given more than once.`;
  return null;
}
export const help = [
  'status   where the master key comes from and whether it opens the keyring',
  'compose-check',
  '         Docker Compose: which key recipe of compose.secret.yaml this volume takes (it',
  '         compares orbit_secret_key and secret.key with the keyring and changes nothing)',
  'remove-data-copy',
  '         delete secret.key in the data directory, only while the key this command is given',
  "         (Uptime Goblin's own under Docker Compose: docker compose exec uptime-goblin …) comes from another",
  '         file or GOBLIN_SECRET_KEY, is the same key and opens the data; otherwise it says why',
  '         and deletes nothing. With --unused: delete an older key there instead (after key',
  '         rewrap), only while the key this command is given opens every data key and that',
  '         file opens none',
  'rewrap   after changing the master key: set the new key, put the old one in',
  '         GOBLIN_SECRET_KEY_PREVIOUS (or GOBLIN_SECRET_KEY_PREVIOUS_FILE), then run this',
  `rotate   new data keys for every purpose (${keyPurposes.join(', ')}) or --purpose …`,
  'reset    only when the master key is lost: every sealed value is given up. The new key is',
  '         the one this command is given; --use-data-dir-key lets it be secret.key in the',
  '         data directory (generated when missing), only for an Uptime Goblin with no other key source',
  '',
  "The key comes from this command's environment, not from /etc/uptime-goblin.env (systemd reads that",
  'for the service alone). Natively, name the key file Uptime Goblin uses:',
  `  sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${installedKeyFile} node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key status --data-dir /var/lib/uptime-goblin`,
].join('\n');

/** Hooks components register for rotate and reset (none in this release; wave 2 adds them). */
export const keyHooks = new KeyHooks();

// The audit actor of a key command (audit spec D25): cli:<os user>, or the user sudo names when it
// looks like one (as sudo reports it, not proof of identity: write commands run as uptime-goblin or node,
// so the sudo caller is the only informative name).
const plausibleUser = /^[a-z_][a-z0-9_.-]{0,31}$/;
export function cliActorName(env = process.env) {
  let user;
  try {
    user = os.userInfo().username;
  } catch {}
  if (!user) user = `uid:${typeof process.getuid === 'function' ? process.getuid() : 'unknown'}`;
  const sudo = env.SUDO_USER;
  return typeof sudo === 'string' && plausibleUser.test(sudo)
    ? `cli:${sudo} (sudo as ${user})`
    : `cli:${user}`;
}
/** A key command's audit event (§7.2): the CLI actor, the command's clock. */
export const cliEvent = (context, fields) => ({
  actor: { type: 'cli', id: null, name: cliActorName(context.env), via: 'cli', sessionId: null },
  at: context.clock(),
  ...fields,
});
// An error's code as a row's detail.code: an Uptime Goblin code or a storage class, never free text.
const codeOf = error => {
  const code = error?.class ?? error?.code;
  return typeof code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : 'failed';
};
// Appends a key command's row under the keyring it opened. A row that cannot be written is one
// stderr line; the command's own outcome and exit status stay as they are (§7.2, §13 M4).
async function auditRow(context, { db, keyring, subcommand, succeeded }, fields) {
  try {
    await appendDirect(
      { db, keyring, clock: context.clock, release: context.release },
      cliEvent(context, fields)
    );
  } catch (error) {
    context.err(
      `goblin-admin key ${subcommand}: the audit entry for this command could not be written (${codeOf(error)}); the command itself ${succeeded ? 'succeeded' : 'failed'}.`
    );
  }
}
const keyringTarget = Object.freeze({ type: 'keyring', id: null, name: null });

// Why this command found no key, and how to give it the one Uptime Goblin uses. It cannot tell whether
// Uptime Goblin has the key, so it never says the key is lost. Nor can it tell a key file from a systemd
// credential, which `sudo -u uptime-goblin` never reaches (the credential's file is root's, or holds the
// key encrypted): natively it names both ways (docs audit, keys 2).
export function keyNotHere(context, action, checked, command = 'key') {
  const secretOutput = command === 'display' && action === 'code';
  const how = context.container
    ? secretOutput
      ? "Run it in Uptime Goblin's running container: docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs display code --name <name> (add -T with --json). Never use docker compose run: Docker keeps that container's output in its log."
      : 'Under Docker Compose with compose.secret.yaml, run it with that file too (docker compose -f compose.yaml -f compose.secret.yaml run …, or COMPOSE_FILE=compose.yaml:compose.secret.yaml in .env).'
    : `Run it with the key file Uptime Goblin uses (GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env): ${adminCommand(`${command} ${action}`, { key: true, previous: action === 'rewrap' })}. If Uptime Goblin loads the key as a systemd credential (LoadCredential=orbit-secret-key:…), run the command in a transient service that loads the same credential instead (sudo systemd-run ${secretOutput ? '--pipe ' : ''}… -p LoadCredential=…: docs/installation.md#goblin-admin); never make the credential's file readable by uptime-goblin.`;
  return `No encryption key reached this command (checked ${checked.join(', ')}). goblin-admin reads the key from its own environment, not from /etc/uptime-goblin.env, which only systemd reads for Uptime Goblin. ${how}`;
}

// resolveKey without generating, for a command that must not take "not here" for "lost": the
// found key, or null with the sources it checked.
export function lookForKey(context) {
  try {
    return {
      found: resolveKey({
        env: context.env,
        directory: context.dataDir,
        keyringExists: true,
        generate: false,
        ...context.keySources,
      }),
      checked: null,
    };
  } catch (error) {
    if (error?.code !== 'key_missing') throw error;
    return { found: null, checked: error.checked };
  }
}

// Opens the migrated control database of `dataDir` read-write, or explains why not.
async function openMigrated(context) {
  if (!controlExists(context.dataDir))
    throw new CommandError(
      'There is no control database yet: start Uptime Goblin 1.5 or later once.'
    );
  const control = openControl(context.dataDir, {
    release: context.release,
    env: {},
    clock: context.clock,
  });
  try {
    const state = await control.inspect();
    if (state.refusal) throw state.refusal;
    if (state.pending.some(step => step.kind !== 'data'))
      throw new CommandError(
        'The control database has pending migrations: run goblin-admin migrate --apply first.'
      );
    return control;
  } catch (error) {
    control.close();
    throw error;
  }
}

// The keyring's rows, read only ([] without a control database or a keyring).
async function keyringRows(context) {
  if (!controlExists(context.dataDir)) return [];
  const control = openControl(context.dataDir, {
    readOnly: true,
    release: context.release,
    env: {},
  });
  try {
    return (await control.keyringExists()) ? await control.keyringStore.list() : [];
  } finally {
    control.close();
  }
}

// The check of compose.secret.yaml: the verdict on the first line, why on the next, and a line to
// run after that when there is one (KEEP beside a <data>/secret.key Uptime Goblin does not use: the line
// alone, so that it is copied whole). A key file it cannot read is a failure (exit status 1)
// that names it, with nothing compared.
async function composeCheck(context) {
  let choice;
  try {
    choice = await composeKeyChoice({
      directory: context.dataDir,
      secretsDirectory: context.keySources.secretsDirectory,
      rows: await keyringRows(context),
    });
  } catch (error) {
    if (error instanceof KeyError) throw new CommandError(error.message);
    throw error;
  }
  context.report(choice, value => [
    value.verdict,
    value.reason,
    ...(value.command ? [value.command] : []),
  ]);
  return 0;
}

// Why remove-data-copy kept <data>/secret.key, per removeDataKeyCopy()'s code (`unused`: run
// with --unused, for an older key): `text`, and `command`, the line to run instead, if any. Under
// Docker Compose the way on is the check of compose.secret.yaml; natively, the key file Uptime Goblin
// uses. Where the other form of the command is the one to run, the message gives its line, which
// removeDataCopy prints alone on the last line: inside a sentence it would end in a full stop or
// in prose, and copied whole the shell would take those as part of the command.
function keptBecause(context, result, found, checked, unused) {
  const own = result.file;
  const label = found ? keySourceLabel(found, context.dataDir) : null;
  const Label = label && label[0].toUpperCase() + label.slice(1);
  // Which install the line is for (nothing under Docker Compose, whose line says so itself).
  const note = removalNote(context.container);
  const withLine = (text, older) => ({
    text,
    command: removeDataKeyLine({ compose: context.container, unused: older }),
  });
  const check =
    'Run the check of compose.secret.yaml (docs/installation.md#encryption-key) and take what it says.';
  const giveKey = context.container
    ? `Under Docker Compose, Uptime Goblin has the Compose secret only once it runs with compose.secret.yaml (COMPOSE_FILE=compose.yaml:compose.secret.yaml in .env, then docker compose up -d), and this command must run in its container: the line below.`
    : `Give this command the key file Uptime Goblin uses, as the line below does${note}.`;
  switch (result.code) {
    case 'none':
      return `There is no ${own}.`;
    case 'not_a_file':
      return `${own} is not a regular file, so it is no key Uptime Goblin generated.`;
    case 'data_directory':
      return withLine(
        `The key this command is given is ${own} itself: no other key source reached it (checked ${(found?.checked ?? checked ?? []).join(', ')}), so that file is ${unused ? 'the key in use, not an older one' : 'not a copy'}. ${giveKey}`,
        unused
      );
    case 'same_file':
      return `${Label} is ${own} itself (its path, a link or a mount of that file), so deleting it would delete the key Uptime Goblin reads. Copy the key to a file outside the data directory and make that the key's source first.`;
    case 'credential':
      return `${Label} is a copy systemd makes at each start, and this command cannot see whether LoadCredential= loads it from ${own}. Once the credential no longer comes from ${own} and Uptime Goblin has started with it, delete ${own} by hand.`;
    case 'gone':
      return `${Label} is a file that was deleted after it was opened or mounted, so it is no lasting copy of the key.${context.container ? ' Put orbit_secret_key back, start Uptime Goblin again (docker compose up -d), then run this command again.' : ''}`;
    // The key's own file, not <data>/secret.key: in a container on an OrbStack host, a Compose
    // secret deleted on the host still shows in a stat while opening it fails.
    case 'source_changed':
      return `${Label} changed while this command checked it (it was deleted, replaced or given another key, or can no longer be read), so it is no lasting copy of the key.${context.container ? ' Put orbit_secret_key back if it was removed, start Uptime Goblin again (docker compose up -d), then run this command again.' : ' Run this command again once that file holds the key Uptime Goblin uses.'}`;
    case 'previous_changed':
      return `${result.source}, the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names, cannot be found or read, and Uptime Goblin reads it at every start: put it back, then run this command again.`;
    case 'previous_file':
      return `${own} is the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names (its path, a link or a mount of that file), which Uptime Goblin reads at every start, so deleting it would stop Uptime Goblin from starting. Once every data key opens with ${label} (goblin-admin key rewrap), remove GOBLIN_SECRET_KEY_PREVIOUS_FILE, start Uptime Goblin again, then run this command again.`;
    case 'no_keyring':
      return `This data has no keyring yet, so this command cannot check that ${label} opens it. Start Uptime Goblin with that key once, then run this command again.`;
    case 'not_opening':
      return unused
        ? `${Label} (fingerprint ${result.fingerprint}) does not open every data key, so ${own} may be the key that opens some of them. ${context.container ? check : 'Give this command the key file Uptime Goblin uses, and finish a key change with goblin-admin key rewrap first (docs/installation.md#goblin-admin).'}`
        : `${Label} (fingerprint ${result.fingerprint}) does not open this data, so ${own} may be the only key that does. ${context.container ? check : 'Restore the key the data was sealed with (docs/troubleshooting.md#exit-statuses, key_mismatch).'}`;
    case 'unreadable':
      return `${result.message} It may be the only key that opens this data.`;
    case 'different': {
      const text = `${own} (fingerprint ${result.theirs}) is not a copy of the key this command is given, ${label} (fingerprint ${result.fingerprint}): it deletes only a copy of that key.`;
      return result.opensNone
        ? withLine(
            `${text} ${own} opens none of this data's keys, which ${label} opens: it is an older key, which Uptime Goblin does not use. Delete it with the line below${note}.`,
            true
          )
        : `${text}${context.container ? ` ${check}` : ''}`;
    }
    case 'copy':
      return withLine(
        `${own} holds the same key as ${label} (fingerprint ${result.fingerprint}): it is a copy of that key, not an older one, and --unused deletes only an older key. Delete a copy with the line below${note}.`,
        false
      );
    case 'opening':
      return `${own} (fingerprint ${result.theirs}) opens ${result.opened} of this data's keys, so it is no unused key: keep it.${context.container ? ` ${check}` : ''}`;
    default:
      return `${own} changed while this command checked it: run it again.`;
  }
}

// key.remove-data-copy's row, once the file is deleted (§7.2): Uptime Goblin may be running, so the
// control database is opened as it is (no migration), and an install without the audit tables
// yet writes nothing. A keyring that does not open is the stderr line, never a failure.
async function removalRow(context, found, unused) {
  let control;
  try {
    control = openControl(context.dataDir, {
      release: context.release,
      env: {},
      clock: context.clock,
    });
  } catch (error) {
    return context.err(
      `goblin-admin key remove-data-copy: the audit entry for this command could not be written (${codeOf(error)}); the command itself succeeded.`
    );
  }
  try {
    const { tables } = await control.db.catalog();
    if (!tables.includes('audit_log')) return;
    let keyring;
    try {
      keyring = await Keyring.open(control.keyringStore, {
        key: found.key,
        previous: found.previous,
        create: false,
      });
    } catch (error) {
      return context.err(
        `goblin-admin key remove-data-copy: the audit entry for this command could not be written (${codeOf(error)}); the command itself succeeded.`
      );
    }
    await auditRow(
      context,
      { db: control.db, keyring, subcommand: 'remove-data-copy', succeeded: true },
      {
        action: 'key.remove-data-copy',
        outcome: 'ok',
        target: { type: 'file', id: 'secret.key', name: null },
        detail: { unused: Boolean(unused) },
      }
    );
  } catch (error) {
    context.err(
      `goblin-admin key remove-data-copy: the audit entry for this command could not be written (${codeOf(error)}); the command itself succeeded.`
    );
  } finally {
    control.close();
  }
}

// Deletes <data>/secret.key only while it is a copy of the key this command is given (A66), or
// with --unused only while it is an older key that opens none of the data keys (A67).
async function removeDataCopy(context) {
  const unused = context.options.unused;
  const { found, checked } = (() => {
    try {
      return lookForKey(context);
    } catch (error) {
      if (error instanceof KeyError)
        throw new CommandError(`${error.message} Nothing was deleted.`);
      throw error;
    }
  })();
  try {
    const result = await removeDataKeyCopy({
      directory: context.dataDir,
      found,
      rows: await keyringRows(context),
      unused,
      previousFile: context.env.GOBLIN_SECRET_KEY_PREVIOUS_FILE ?? null,
    });
    if (!result.deleted) {
      const kept = keptBecause(context, result, found, checked, unused);
      const { text, command } = typeof kept === 'string' ? { text: kept } : kept;
      // The line to run goes alone on the last line, so it can be copied whole (keptBecause).
      throw new CommandError(`${text} Nothing was deleted.`, exitCodes.failed, { command });
    }
    await removalRow(context, found, unused);
    const value = {
      deleted: result.file,
      source: found.source,
      file: found.file ?? null,
      fingerprint: result.fingerprint,
      ...(unused ? { deletedFingerprint: result.theirs } : {}),
    };
    const label = keySourceLabel(found, context.dataDir);
    context.report(value, v =>
      unused
        ? `Deleted ${v.deleted}, an older key (fingerprint ${v.deletedFingerprint}) that opens none of this data's keys: ${label} (fingerprint ${v.fingerprint}) opens them all. A backup or a snapshot (goblin-admin snapshots) of the data from before the key changed still needs that older key. Keep a backup of the key Uptime Goblin uses apart from the data.`
        : `Deleted ${v.deleted}: ${label} holds the same key (fingerprint ${v.fingerprint}) and opens this data. Keep a backup of that key apart from the data.`
    );
    return 0;
  } finally {
    found?.key.fill(0);
    found?.previous?.fill(0);
  }
}

async function status(context) {
  const report = { dataDir: context.dataDir, keyring: null, key: null, matches: null };
  const rows = await keyringRows(context);
  report.keyring = rows
    .map(row => ({
      kid: row.kid,
      purpose: row.purpose,
      createdAt: row.created_at,
      retiredAt: row.retired_at ?? null,
    }))
    .sort((a, b) => a.createdAt - b.createdAt || (a.kid < b.kid ? -1 : 1));
  let problem = null;
  report.notFound = null;
  try {
    const { found, checked } = lookForKey(context);
    // With a keyring, no key here is not a lost key: Uptime Goblin may have one this command cannot see.
    if (!found && rows.length)
      report.notFound = { checked, hint: keyNotHere(context, 'status', checked) };
    if (found) {
      report.key = {
        source: found.source,
        file: found.file ?? null,
        fingerprint: found.fingerprint,
        previous: Boolean(found.previous),
        warnings: found.warnings,
      };
      if (rows.length) {
        const { stale } = await Keyring.check(
          { list: async () => rows },
          { key: found.key, previous: found.previous }
        );
        report.matches = true;
        report.stale = stale;
      }
      found.key.fill(0);
      found.previous?.fill(0);
    }
  } catch (error) {
    if (!error?.code?.startsWith?.('key')) throw error;
    problem = error.message;
    report.matches = false;
  }
  report.problem = problem;
  context.report(report, value => {
    const lines = [];
    if (!value.keyring.length)
      lines.push(
        'Keyring: none yet. Uptime Goblin creates it at its next start, with the key from GOBLIN_SECRET_KEY_FILE or another configured source, or a new secret.key in the data directory.'
      );
    else {
      lines.push(`Keyring: ${value.keyring.length} data keys`);
      // Each row's kid and purpose are saved data, listed before the key is checked: printable,
      // so a hand-edited or crafted row cannot write an escape sequence or a line of its own.
      for (const item of value.keyring)
        lines.push(
          `  ${printable(item.kid, 100)}  ${printable(item.purpose, 40).padEnd(8)}  created ${formatTime(item.createdAt)}${item.retiredAt ? `, retired ${formatTime(item.retiredAt)}` : ''}`
        );
    }
    if (value.key)
      lines.push(
        `Master key: ${keySourceLabel(value.key, value.dataDir)}, fingerprint ${value.key.fingerprint}`,
        ...value.key.warnings.map(warning => `Warning: ${warning}`)
      );
    else if (value.notFound)
      lines.push(
        `Master key: not found by this command. ${value.notFound.hint}`,
        'Not checked: whether the key opens the keyring. If Uptime Goblin itself refuses to start with "The encryption key is missing", see docs/troubleshooting.md#lost-encryption-key.'
      );
    // Without a keyring, the next start makes one, with Uptime Goblin's own key when it has one.
    else if (!value.problem)
      lines.push(
        `Master key: none in this command's environment. Unless Uptime Goblin has one of its own (natively GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env, which this command does not read), its next start generates ${path.join(value.dataDir, secretKeyFile)}; set GOBLIN_SECRET_KEY_FILE to keep the key outside the data directory.`
      );
    if (value.problem) lines.push(`PROBLEM: ${value.problem}`);
    else if (value.matches)
      lines.push(
        value.stale?.length
          ? `The key opens the keyring, ${value.stale.length} data key(s) only through the previous key: run, with Uptime Goblin stopped: ${adminCommand('key rotate', { key: true, previous: true })}.`
          : 'The key opens every data key.'
      );
    return lines;
  });
  return problem || report.notFound ? 1 : 0;
}

async function change(context, action) {
  return withLock(context, `goblin-admin key ${action}`, async () => {
    const control = await openMigrated(context);
    try {
      const exists = await control.keyringExists();
      if (!exists && action !== 'reset')
        throw new CommandError('There is no keyring yet: start Uptime Goblin once first.');
      if (action === 'reset') {
        // The key configured for this command becomes the key. <data>/secret.key (found, or
        // generated now) only with --use-data-dir-key: Uptime Goblin reads it only when it has no other
        // source, and this command cannot see every source Uptime Goblin may have.
        let { found, checked } = lookForKey(context);
        const own = path.join(context.dataDir, secretKeyFile);
        try {
          if (found && exists) {
            const opens = await Keyring.check(control.keyringStore, { key: found.key }).then(
              () => true,
              () => false
            );
            if (opens)
              throw new CommandError(
                found.source === 'data-directory'
                  ? `The key in ${own} opens this keyring, so nothing is lost: give Uptime Goblin that key (natively, copy it to ${installedKeyFile}, root:uptime-goblin 0440, which GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env names), or use goblin-admin key rotate.`
                  : 'The configured key opens this keyring, so nothing is lost: use goblin-admin key rotate instead.'
              );
          }
          if (
            (!found || found.source === 'data-directory') &&
            !context.options['use-data-dir-key']
          ) {
            const head = found
              ? `The only key that reached this command is ${own}, in the data directory.`
              : `No encryption key reached this command (checked ${checked.join(', ')}), so a reset would generate ${own} and make it the key.`;
            throw new CommandError(
              `${head} Uptime Goblin may read its key from a source this command cannot see: natively GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env, which only systemd reads; under Docker Compose the secret of compose.secret.yaml. A reset under another key leaves Uptime Goblin refusing to start. Put the new key in place and give it to this command: ${context.container ? 'docker compose -f compose.yaml -f compose.secret.yaml run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs key reset --confirm-lost-key' : adminCommand('key reset --confirm-lost-key', { key: true })}. Only for an Uptime Goblin that has no other key source (Docker Compose without compose.secret.yaml, npm start without GOBLIN_SECRET_KEY_FILE), add --use-data-dir-key to make ${own} the key. No key was written and the keyring was not changed.`,
              exitCodes.usage
            );
          }
          found ??= resolveKey({
            env: context.env,
            directory: context.dataDir,
            keyringExists: false,
            ...context.keySources,
          });
          // The audit keys this reset makes lost: their entries can no longer be checked, and
          // key.reset, written in the reset's own unit, says so (D17).
          const kidsBefore = async () =>
            exists
              ? (await control.keyringStore.list()).map(row => `${row.purpose}:${row.kid}`).sort()
              : [];
          const before = await kidsBefore();
          const lostKeyIds = before
            .filter(entry => entry.startsWith('audit:'))
            .map(entry => entry.slice('audit:'.length));
          let result;
          try {
            result = await Keyring.reset(control.keyringStore, {
              key: found.key,
              confirmLostKey: true,
              hooks: keyHooks,
              clock: context.clock,
              inUnit: (tx, { kid, mac }) =>
                recordWith(
                  tx,
                  { kid, mac },
                  cliEvent(context, {
                    action: 'key.reset',
                    outcome: 'ok',
                    target: keyringTarget,
                    detail: { lostKeyIds },
                  }),
                  { clock: context.clock }
                ),
            });
          } catch (error) {
            // The keys and key.reset commit together: when the keys are as they were, the
            // failure left the keyring unchanged, and the message says so. A <data>/secret.key
            // generated above for --use-data-dir-key is written before the reset and stays: the
            // message names it (a reset run again finds it and uses it).
            const unchanged = await kidsBefore().then(
              now => now.join() === before.join(),
              () => false
            );
            if (!unchanged) throw error;
            throw new CommandError(
              `${error?.message ?? String(error)} The keyring was not changed: the keys and their audit entry are saved together.${found.source === 'generated' ? ` ${found.file ?? own}, which this reset generated, stays; a reset run again with --use-data-dir-key uses it.` : ''}`
            );
          }
          const value = {
            action,
            discarded: result.discarded,
            fingerprint: result.keyring.fingerprint,
            source: found.source,
            file: found.file ?? null,
            hooks: result.hooks,
          };
          context.report(value, v => [
            `Discarded ${v.discarded} data key(s); new keys are wrapped by the key from ${keySourceLabel(v, context.dataDir)}, fingerprint ${v.fingerprint}.`,
            'Values sealed under the old keys can no longer be read: set secret settings again.',
            'From now on Uptime Goblin needs this key at every start.',
          ]);
          return 0;
        } finally {
          found?.key.fill(0);
          found?.previous?.fill(0);
        }
      }
      const { found, checked } = lookForKey(context);
      if (!found) throw new CommandError(keyNotHere(context, action, checked));
      const purposes = context.options.purpose?.length ? context.options.purpose : keyPurposes;
      for (const purpose of purposes)
        if (!keyPurposes.includes(purpose))
          throw new CommandError(
            `Unknown key purpose ${purpose} (one of ${keyPurposes.join(', ')})`,
            2
          );
      try {
        const keyring = await Keyring.open(control.keyringStore, {
          key: found.key,
          previous: found.previous,
          clock: context.clock,
        });
        // From here on the command has the key: its entry is written whatever happens, a
        // failure as `failed` with its code (§7.2). Before here it writes nothing.
        const row = (outcome, detail) =>
          auditRow(
            context,
            { db: control.db, keyring, subcommand: action, succeeded: outcome === 'ok' },
            { action: `key.${action}`, outcome, target: keyringTarget, detail }
          );
        let done;
        try {
          if (action === 'rewrap') {
            const stale = keyring.needsRewrap;
            done = stale ? await keyring.rewrap() : { rewrapped: 0, wereStale: 0 };
          } else done = await keyring.rotate({ purposes, hooks: keyHooks });
        } catch (error) {
          await row('failed', { code: codeOf(error) });
          throw error;
        }
        await row(
          'ok',
          action === 'rewrap'
            ? { rewrapped: done.rewrapped }
            : { purposes, retired: done.retired, active: done.active }
        );
        if (action === 'rewrap') {
          context.report({ action, ...done, fingerprint: keyring.fingerprint }, v =>
            v.wereStale
              ? `Rewrapped ${v.rewrapped} data key(s) with the key ${v.fingerprint}; the previous key is no longer needed.`
              : `Every data key is already wrapped by the key ${v.fingerprint}; nothing to do.`
          );
          return 0;
        }
        const result = done;
        // The retired kids come from keyring rows (saved data): printable, as in key status.
        context.report({ action, ...result }, v => [
          `New data keys for ${purposes.join(', ')}; retired ${v.retired.map(kid => printable(kid, 100)).join(', ') || 'none'} (they still open older values).`,
          v.hooks.length
            ? `Re-sealed by: ${v.hooks.join(', ')}.`
            : 'No component re-seals its values in this release; they are re-sealed when next written.',
        ]);
        return 0;
      } finally {
        found.key.fill(0);
        found.previous?.fill(0);
      }
    } finally {
      control.close();
    }
  });
}

export async function run(context) {
  const [action, ...extra] = context.args;
  if (!actions.includes(action) || extra.length)
    throw new CommandError(`Usage: goblin-admin key ${usage}`, 2);
  if (action !== 'reset' && context.options['use-data-dir-key'])
    throw new CommandError('--use-data-dir-key applies to key reset only.', 2);
  if (action !== 'remove-data-copy' && context.options.unused)
    throw new CommandError('--unused applies to key remove-data-copy only.', 2);
  if (action === 'status') return status(context);
  if (action === 'compose-check') return composeCheck(context);
  if (action === 'remove-data-copy') return removeDataCopy(context);
  if (action === 'reset' && !context.options['confirm-lost-key'])
    throw new CommandError(
      'key reset gives up every sealed value. It is only for a lost key; repeat with --confirm-lost-key.',
      2
    );
  if (action !== 'rotate' && context.options.purpose?.length)
    throw new CommandError('--purpose applies to key rotate only.', 2);
  return change(context, action);
}
