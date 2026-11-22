// goblin-admin display: one-time codes that sign a wall display in, read-only (B6 design §7.3).
//
//   display code --name <name> [--json]     a code, valid once for 10 minutes
//   display list [--json]                    the codes still kept, never a code or its hash
//   display cancel <id> | --all              cancel waiting codes
//
// All run while Uptime Goblin runs (online: short control-database transactions, no lock). `list`
// reads only and needs no key. `code`
// needs the master key: its row and its audit entry commit in one unit, audited or not created.
// `cancel` works without the key, so a code can always be stopped: the cancellation then owes
// its audit entry, which Uptime Goblin writes at its next hourly pass. The code itself is printed once,
// to stdout, and is never stored, logged or audited: only its SHA-256 is kept.
import fs from 'node:fs';
import { controlExists, openControl, readStartRecords } from '../../db/control.mjs';
import { keys as startKeys, credentialsPlacedSinceLastStart } from '../../identity/bootstrap.mjs';
import { Keyring } from '../../keyring.mjs';
import { recordWith } from '../../audit/writer.mjs';
import { identityOps } from '../../repo/identity.mjs';
import { newDisplayCode, isDisplayId } from '../../identity/secrets.mjs';
import { quoted, unprintableProblem } from '../../environment.mjs';
import { printable } from '../../saved-data.mjs';
import { CommandError, exitCodes, formatTime, orbitServerProcess } from '../common.mjs';
import { cliActorName, cliEvent, keyNotHere, lookForKey } from './key.mjs';

export const summary =
  'Create a one-time code that signs a wall display in, read-only, list codes, or cancel waiting ones.';
export const usage = 'code --name <name> [--json] | list [--json] | cancel <id> | cancel --all';
export const kind = 'online';
export const options = {
  name: { type: 'string' },
  all: { type: 'boolean', default: false },
};
// The action and, for cancel, the id.
export const maxPositionals = 2;
export const help = [
  'code     a code for the wall display <name>, valid once for 10 minutes. On the display,',
  "         open Uptime Goblin's address with ?kiosk=1 (its HTTPS address when it has one) and type",
  '         the code under "Set up this wall display". The display can then only read the',
  '         dashboard. Needs the encryption key, like the key commands.',
  'list     the codes Uptime Goblin still keeps, newest first: waiting, used (and the session each',
  '         became) and cancelled. Never shows a code. Needs no key.',
  'cancel   cancel the waiting code <id>, or every waiting code with --all. Works without',
  '         the key.',
].join('\n');

/** The longest name, and the most codes that may wait at once (B6 design §7.2, §16). */
export const maxName = 64;
export const maxWaiting = 10;
/** The most rows display list shows. */
const listLimit = 50;
/** How long a code stays valid. */
export const codeLifetimeMs = 10 * 60e3;

export function optionProblem(given, values, args = []) {
  const [action] = args;
  if (action === 'code') {
    if (given.has('all')) return '--all applies to display cancel only.';
    if (args.length > 1) return 'display code takes no argument besides --name.';
  }
  if (action === 'cancel' && given.has('name')) return '--name applies to display code only.';
  if (action === 'list') {
    if (given.has('name')) return '--name applies to display code only.';
    if (given.has('all')) return '--all applies to display cancel only.';
    if (args.length > 1) return 'display list takes no argument.';
  }
  return null;
}

// Why `name` cannot name a display, or null: 1 to 64 characters, nothing a terminal or the
// audit page would show as something else.
function nameProblem(name) {
  if (typeof name !== 'string' || !name.trim()) return 'display code needs --name <name>.';
  if ([...name].length > maxName) return `--name must be at most ${maxName} characters.`;
  const problem = unprintableProblem(name);
  return problem ? `--name must not hold ${problem}.` : null;
}

/**
 * Why the code must not be printed where stdout goes, or null: the journal (a systemd service's
 * stdout, JOURNAL_STREAM) and a socket keep what they are sent, beyond this terminal (§6.8).
 */
export function outputProblem(env, stat) {
  if (!stat) return null;
  if (typeof stat.isSocket === 'function' && stat.isSocket())
    return 'Its standard output is a socket, which may keep the code. Run it in a terminal, or with its output to a pipe.';
  const journal = typeof env.JOURNAL_STREAM === 'string' ? env.JOURNAL_STREAM : '';
  if (journal && journal === `${stat.dev}:${stat.ino}`)
    return "Its standard output is systemd's journal, which keeps the code. Run it in a terminal.";
  return null;
}

// The control database of `dataDir`, migrated and with the displays table, or why not.
async function openDisplays(context) {
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
        'The control database has pending migrations: start this Uptime Goblin release once (or run goblin-admin migrate --apply with Uptime Goblin stopped).'
      );
    const { tables } = await control.db.catalog();
    if (!tables.includes('displays'))
      throw new CommandError(
        'This data directory has no wall display codes yet: start this Uptime Goblin release once.'
      );
    return control;
  } catch (error) {
    control.close();
    throw error;
  }
}

// The keyring under the key this command was given, or null with the sources it checked.
async function openKeyring(context, control) {
  const { found, checked } = lookForKey(context);
  if (!found) return { keyring: null, checked };
  try {
    return {
      keyring: await Keyring.open(control.keyringStore, {
        key: found.key,
        previous: found.previous,
        clock: context.clock,
        create: false,
      }),
      checked: null,
    };
  } finally {
    found.key.fill(0);
    found.previous?.fill(0);
  }
}

// What recordWith needs to sign a row in the command's own unit.
const signer = keyring => {
  const kid = keyring.activeKid('audit');
  return { kid, mac: data => keyring.hmac('audit', data, kid).mac };
};

async function create(context) {
  const name = context.options.name;
  const problem = nameProblem(name);
  if (problem) throw new CommandError(problem, exitCodes.usage);
  if (context.container) {
    const server = orbitServerProcess(context.dataDir, { proc: context.proc });
    if (!server || server.unknown)
      throw new CommandError(
        'display code refused. Run it in the running Uptime Goblin container with docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs display code --name <name> (add -T with --json). Never use docker compose run: Docker keeps that container output in its log.'
      );
  }
  const guarded = outputProblem(context.env, (context.outputStat ?? stdoutStat)());
  if (guarded) throw new CommandError(`display code refused. ${guarded}`);
  const control = await openDisplays(context);
  try {
    const records = await readStartRecords(control.file, [
      startKeys.restoreSeen,
      startKeys.controlFile,
      startKeys.credentialsAnchor,
    ]);
    const hasCredentials = await control.db.read(tx => identityOps.listDisplays(tx, 1).length > 0);
    if (credentialsPlacedSinceLastStart(control.file, records, { hasCredentials }))
      throw new CommandError(
        'Start Uptime Goblin once after the restore or copied data directory, then create the display code.'
      );
    const { keyring, checked } = await openKeyring(context, control);
    if (!keyring) throw new CommandError(keyNotHere(context, 'code', checked, 'display'));
    const { id, code, codeHash } = newDisplayCode();
    const now = context.clock();
    const expiresAt = now + codeLifetimeMs;
    const sign = signer(keyring);
    await control.db.write(tx => {
      if (identityOps.waitingDisplays(tx, now) >= maxWaiting)
        throw new CommandError(
          `${maxWaiting} display codes are already waiting. Use one, let them expire (10 minutes), or cancel them with goblin-admin display cancel --all.`
        );
      identityOps.insertDisplay(tx, {
        id,
        name,
        codeHash,
        codeExpiresAt: expiresAt,
        origin: 'cli',
        createdAt: now,
        createdBy: cliActorName(context.env),
      });
      recordWith(
        tx,
        sign,
        cliEvent(context, {
          action: 'display.code.created',
          outcome: 'ok',
          target: { type: 'display', id, name },
          detail: { expiresAt },
        }),
        { clock: context.clock }
      );
    });
    context.report({ id, name, expiresAt, code }, v => [
      `Display code ${v.id} for ${quoted(printable(v.name, maxName), maxName + 2)}, valid once until ${formatTime(v.expiresAt)} (10 minutes):`,
      v.code,
      'On the wall display, open Uptime Goblin\'s address with ?kiosk=1 (its HTTPS address when it has one, for example https://goblin.example.com/?kiosk=1) and type the code under "Set up this wall display".',
      `Uptime Goblin keeps only its hash. Cancel it with: goblin-admin display cancel ${v.id}`,
    ]);
    return exitCodes.ok;
  } finally {
    control.close();
  }
}

// What display list shows of a row: never its hash.
const listed = row => ({
  id: row.id,
  name: row.name,
  origin: row.origin,
  state: row.state,
  createdAt: row.createdAt,
  createdBy: row.createdBy,
  expiresAt: row.codeExpiresAt,
  redeemedAt: row.redeemedAt,
  redeemedClient: row.redeemedClient,
  sessionId: row.sessionId,
  cancelledAt: row.cancelledAt,
  cancelCause: row.cancelCause,
});

async function list(context) {
  const control = await openDisplays(context);
  try {
    const now = context.clock();
    const rows = (await control.db.read(tx => identityOps.listDisplays(tx, listLimit))).map(listed);
    const line = row => {
      const name = quoted(printable(row.name, maxName), maxName + 2);
      const made = `created ${formatTime(row.createdAt)} by ${printable(row.createdBy, 128)} (${row.origin})`;
      if (row.state === 'redeemed')
        return `${row.id}  ${name}  used ${formatTime(row.redeemedAt)} from ${row.redeemedClient ?? 'an unknown address'}, became session ${row.sessionId ?? '(none)'}; ${made}`;
      if (row.state === 'cancelled')
        return `${row.id}  ${name}  cancelled ${formatTime(row.cancelledAt)} (${row.cancelCause ?? 'cancelled'}); ${made}`;
      return row.expiresAt > now
        ? `${row.id}  ${name}  waiting until ${formatTime(row.expiresAt)}; ${made}`
        : `${row.id}  ${name}  expired ${formatTime(row.expiresAt)}; ${made}`;
    };
    context.report({ displays: rows, now }, v =>
      v.displays.length ? v.displays.map(line) : ['No display codes are kept.']
    );
    return exitCodes.ok;
  } finally {
    control.close();
  }
}

async function cancel(context) {
  const [, id] = context.args;
  const all = context.options.all;
  if (all === Boolean(id))
    throw new CommandError('display cancel needs one display id, or --all.', exitCodes.usage);
  if (id && !isDisplayId(id))
    throw new CommandError(`No waiting display code has the id ${quoted(id, 40)}.`);
  const control = await openDisplays(context);
  try {
    let keyring = null;
    try {
      ({ keyring } = await openKeyring(context, control));
    } catch {}
    const now = context.clock();
    const ids = all ? null : [id];
    const cancelUnit = recorded => tx => {
      const rows = identityOps.cancelDisplays(tx, { ids, cause: 'cancelled', now, recorded });
      if (recorded && rows.length) {
        const sign = signer(keyring);
        const event = fields =>
          cliEvent(context, { action: 'display.code.cancelled', outcome: 'ok', ...fields });
        if (all)
          recordWith(
            tx,
            sign,
            event({
              target: { type: 'account', id: 'u_admin', name: null },
              detail: { cause: 'cancelled', count: rows.length },
            }),
            { clock: context.clock }
          );
        else
          recordWith(
            tx,
            sign,
            event({ target: { type: 'display', ...rows[0] }, detail: { cause: 'cancelled' } }),
            { clock: context.clock }
          );
      }
      return rows;
    };
    let rows,
      owed = false;
    if (keyring)
      try {
        rows = await control.db.write(cancelUnit(true));
      } catch (error) {
        if (error instanceof CommandError) throw error;
        owed = true;
      }
    else owed = true;
    if (owed) rows = await control.db.write(cancelUnit(false));
    if (!rows.length) {
      if (all) {
        context.report({ cancelled: [] }, () => 'No display code was waiting.');
        return exitCodes.ok;
      }
      throw new CommandError(`No waiting display code has the id ${id}.`);
    }
    if (owed)
      context.err(
        `goblin-admin display cancel: ${keyring ? 'the audit entry could not be written' : 'no encryption key reached this command'}, so Uptime Goblin writes the audit entry for this cancellation when it next tidies up (within an hour). The code is cancelled.`
      );
    context.report({ cancelled: rows.map(row => row.id) }, v =>
      v.cancelled.length === 1
        ? `Cancelled display code ${v.cancelled[0]}.`
        : `Cancelled ${v.cancelled.length} waiting display codes.`
    );
    return exitCodes.ok;
  } finally {
    control.close();
  }
}

export async function run(context) {
  const [action] = context.args;
  if (action === 'code') return create(context);
  if (action === 'list') return list(context);
  if (action === 'cancel') return cancel(context);
  throw new CommandError(`Usage: goblin-admin display ${usage}`, exitCodes.usage);
}

// The descriptor of stdout, for outputProblem (goblin-admin main passes its own in tests).
export const stdoutStat = () => {
  try {
    return fs.fstatSync(1);
  } catch {
    return null;
  }
};
