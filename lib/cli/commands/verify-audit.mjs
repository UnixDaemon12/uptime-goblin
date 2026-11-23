// goblin-admin verify-audit [--checkpoints <file> | -] [--json] (audit spec §7.1, D20): checks the
// audit log of control.sqlite, read-only, also while Uptime Goblin runs (kind `read`: no lock, nothing
// written). It walks the whole chain in one read unit (lib/audit/verify.mjs) and, with
// --checkpoints, compares the checkpoint lines Uptime Goblin printed to its journal: only those detect
// entries removed from the end together with the head. `-` reads the journal from stdin, so the
// check runs inside Uptime Goblin's own container, whose file system is read-only:
//
//   docker compose logs --no-log-prefix uptime-goblin | docker compose exec -T uptime-goblin node lib/cli/goblin-admin.mjs verify-audit --checkpoints -
//
// The key is found as key status finds it (never generated, never taken for lost); without one
// the links between entries are checked, not their signatures, and the result is at best "not
// fully checked". Exit status: 0 intact (or empty), 1 CHANGED or the check could not run (no
// control database or audit log yet, a key file it cannot read, a read error), 2 usage (also a
// --checkpoints file it cannot read), 3 not fully checked (docs audit, audit 8).
import fs from 'node:fs';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { controlExists, openControl } from '../../db/control.mjs';
import { Keyring, resolveKey } from '../../keyring.mjs';
import { adminCommand } from '../../admin-command.mjs';
import { jsonText } from '../../environment.mjs';
import { auditTime } from '../../audit/actions.mjs';
import { anchorLines, grouped, unverifiableText, verifyAudit } from '../../audit/verify.mjs';
import { CommandError, exitCodes } from '../common.mjs';

export const summary =
  "Check that the audit log is intact, also against the checkpoints in Uptime Goblin's log (read-only; also while Uptime Goblin runs).";
export const usage = '[--checkpoints <file> | -] [--data-dir <dir>] [--json]';
export const kind = 'read';
export const options = { checkpoints: { type: 'string' } };
export const help = [
  'Checks every audit entry against the one before it and its signature, and lists every',
  'restore, upgrade and key reset the log records. With --checkpoints, the checkpoint lines',
  'Uptime Goblin printed to its log are compared too: they show entries removed from the end. Pipe',
  'that log in with --checkpoints -, so that no copy of it is written (it can hold more than',
  'checkpoints). Natively, one root shell reads the journal and runs this command as the uptime-goblin',
  'user:',
  "  sudo sh -c 'journalctl -u uptime-goblin -o cat | sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs verify-audit --checkpoints - --data-dir /var/lib/uptime-goblin'",
  'Under Docker Compose, pipe in docker compose logs --no-log-prefix uptime-goblin the same way',
  '(docs/installation.md#goblin-admin).',
  'Exit status: 0 intact or empty, 1 changed or the check could not run, 2 usage error,',
  '3 not fully checked.',
].join('\n');

// How much of a journal is read at most, and the longest line that can be a checkpoint line
// (Uptime Goblin prints them a few hundred bytes long, with a log prefix at most).
const journalLimit = 512 * 2 ** 20;
const lineLimit = 64 * 1024;
const checkpointMark = '"orbit":"audit.checkpoint"';

/**
 * Collects the lines of a journal that can be checkpoint lines, chunk by chunk: memory holds
 * those lines only, not the whole export (a journal larger than V8's longest string crashed the
 * command), and at most 512 MiB is read, so a stream that never ends stops.
 */
function checkpointCollector(source) {
  const decoder = new StringDecoder('utf8'),
    kept = [];
  let partial = '',
    skipping = false,
    total = 0;
  const take = text => {
    const pieces = (partial + text).split('\n');
    partial = pieces.pop();
    for (const piece of pieces) {
      if (skipping)
        skipping = false; // The end of a line too long to be a checkpoint.
      else if (piece.includes(checkpointMark)) kept.push(piece);
    }
    if (partial.length > lineLimit) {
      partial = '';
      skipping = true;
    }
  };
  return {
    push(chunk) {
      total += chunk.length;
      if (total > journalLimit)
        throw new CommandError(
          `the journal ${source} is larger than ${journalLimit / 2 ** 20} MiB. Export only the part the audit log covers (journalctl -u uptime-goblin -o cat --since …).`,
          exitCodes.usage
        );
      take(decoder.write(chunk));
    },
    end() {
      take(decoder.end() + '\n');
      return kept.join('\n');
    },
  };
}

// The journal's checkpoint lines: from a file, read as a regular file without waiting (a FIFO
// named by --checkpoints held the command), or from stdin (`-`).
async function readJournal(context, source) {
  const collected = checkpointCollector(source === '-' ? 'on standard input' : source);
  if (source === '-') {
    for await (const chunk of context.stdin ?? process.stdin)
      collected.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    return collected.end();
  }
  let descriptor;
  try {
    descriptor = fs.openSync(path.resolve(source), fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    if (!fs.fstatSync(descriptor).isFile())
      throw Object.assign(new Error('not a regular file'), { code: 'not a regular file' });
    const buffer = Buffer.alloc(2 ** 20);
    for (let read; (read = fs.readSync(descriptor, buffer, 0, buffer.length, null)) > 0; )
      collected.push(buffer.subarray(0, read));
    return collected.end();
  } catch (error) {
    if (error instanceof CommandError) throw error;
    throw new CommandError(
      `could not read the journal ${source} (${error?.code ?? error?.name ?? 'error'}).`,
      exitCodes.usage
    );
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

// The key as key status finds it (lib/cli/commands/key.mjs): from this command's environment,
// never generated. Null when none reached it.
function findKey(context) {
  try {
    return resolveKey({
      env: context.env,
      directory: context.dataDir,
      keyringExists: true,
      generate: false,
      ...context.keySources,
    });
  } catch (error) {
    if (error?.code === 'key_missing') return null;
    throw new CommandError(error?.message ?? String(error));
  }
}

// The command line that gives this command the key Uptime Goblin uses (A7), for the no_key text.
const keyLine = context =>
  context.container
    ? 'docker compose exec -T uptime-goblin node lib/cli/goblin-admin.mjs verify-audit'
    : adminCommand('verify-audit', { key: true });

// The line for a key that reached this command but does not open the data (docs audit, keys 7):
// its no_key item (verifyAudit had no keyring) is no "no key reached it", which would send the
// reader to run it again with that same key. --json keeps the reason no_key (the contract's).
const mismatchText = fingerprint =>
  `The key this command was given (fingerprint ${fingerprint}) does not open this data, so the signatures were not checked (only the links between entries). Run it with the key Uptime Goblin uses: its fingerprint is in Uptime Goblin's start line ("Encryption key: … · fingerprint …").`;

/**
 * The human lines of a result (§7.1). `mismatch`: the fingerprint of a key that was given but
 * does not open the data (its no_key item then says so).
 */
export function reportLines(result, { line = '', mismatch = null } = {}) {
  const lines = [];
  const { rows, problem } = result;
  if (result.result === 'broken')
    lines.push(
      `Audit log: CHANGED at entry #${grouped(problem.seq)}${problem.time === null ? '' : ` (${auditTime(problem.time)})`}. ${problem.message} ${problem.consequence}`
    );
  else if (result.result === 'incomplete') {
    lines.push('Audit log: not fully checked.');
    for (const item of result.unverifiable)
      lines.push(
        item.reason === 'no_key' && mismatch
          ? mismatchText(mismatch)
          : unverifiableText(item, { line })
      );
  } else if (!rows.checked) lines.push('Audit log: empty. There is nothing to check yet.');
  else
    lines.push(
      `Audit log: intact. ${grouped(rows.checked)} entries checked (#${grouped(rows.first.seq)}, ${auditTime(rows.first.time)}, to #${grouped(rows.last.seq)}, ${auditTime(rows.last.time)}).`
    );
  if (result.journal) {
    const { lines: count, matched, unchecked, foreign, coveredTo } = result.journal;
    lines.push(
      `Journal: ${grouped(count)} checkpoint lines; ${grouped(matched)} match; ${grouped(unchecked)} could not be checked because of a restore; ${grouped(foreign)} not written by this Uptime Goblin (--json lists them).`
    );
    if (!matched || coveredTo === null) lines.push('No journal checkpoint covers this log.');
    else if (rows.last && coveredTo < rows.last.seq)
      lines.push(
        `Entries after #${grouped(coveredTo)} (${auditTime(result.coveredTime)}) are covered by no journal checkpoint.`
      );
    else lines.push('Every entry is covered by a journal checkpoint.');
  }
  for (const anchor of result.anchors) lines.push(...anchorLines(anchor));
  return lines;
}

export async function run(context) {
  if (context.args.length)
    throw new CommandError(`Usage: goblin-admin verify-audit ${usage}`, exitCodes.usage);
  const source = context.options.checkpoints;
  if (source === '')
    throw new CommandError('--checkpoints needs a file, or - for stdin.', exitCodes.usage);
  const journal = source === undefined ? null : await readJournal(context, source);
  if (!controlExists(context.dataDir))
    throw new CommandError(
      'There is no control database yet: start Uptime Goblin 1.5 or later once.'
    );
  const control = openControl(context.dataDir, {
    readOnly: true,
    release: context.release,
    env: {},
  });
  let found = null;
  try {
    const { tables } = await control.db.catalog();
    if (!tables.includes('audit_log'))
      throw new CommandError(
        `This control database has no audit log yet: start Uptime Goblin ${context.release} on it once.`
      );
    found = findKey(context);
    let keyring = null,
      mismatch = null;
    // Review round 2: every key the keyring holds is used, whether or not each purpose has an
    // active one: someone with the database but not the key can retire or delete keyring rows
    // (the wrap binds neither), and refusing such a keyring blinded the check to every entry
    // they rewrote. An entry whose key is gone reads as one (key_lost), as at Uptime Goblin's start; an
    // empty keyring holds no key at all.
    if (found)
      try {
        keyring = await Keyring.open(control.keyringStore, {
          key: found.key,
          previous: found.previous,
          create: false,
          complete: false,
        });
      } catch (error) {
        // A key that does not open this data checks nothing: the links are still compared.
        if (error?.code === 'key_mismatch') mismatch = found.fingerprint;
        context.err(
          error?.code === 'key_mismatch'
            ? 'goblin-admin verify-audit: the key this command was given does not open this data (key_mismatch), so signatures are not checked.'
            : `goblin-admin verify-audit: the keyring could not be read (${error?.class ?? error?.code ?? error?.name ?? 'error'}), so signatures are not checked.`
        );
      }
    let result;
    try {
      result = await verifyAudit(control.db, {
        keyring,
        journal,
        clock: context.clock,
        oneUnit: true,
      });
    } catch (error) {
      throw new CommandError(
        `could not read the audit log (${error?.class ?? error?.code ?? error?.name ?? 'error'}).`
      );
    }
    // As context.report prints it: saved text whole, its control characters escaped.
    if (context.json) context.out(jsonText(result));
    else context.out(reportLines(result, { line: keyLine(context), mismatch }).join('\n'));
    return result.result === 'intact'
      ? exitCodes.ok
      : result.result === 'broken'
        ? exitCodes.failed
        : exitCodes.unverified;
  } finally {
    found?.key.fill(0);
    found?.previous?.fill(0);
    control.close();
  }
}
