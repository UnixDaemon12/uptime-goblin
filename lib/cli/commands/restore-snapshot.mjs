// goblin-admin restore-snapshot <id>: put a snapshot's files back (offline: Uptime Goblin stopped). The
// files it replaces are moved into a pre-restore snapshot first, so a restore can be undone. Run
// again after an interruption, it keeps the files that changed in between (Orbit 1.4.x ignores
// an interrupted restore) in a snapshot of their own, and says which. A restored control.sqlite's
// keyring, and the one it replaced, are checked with the key in this command's own environment,
// as the key commands find it, before it says anything of an older key, or nothing at all
// (keyringCheck).
import fs from 'node:fs';
import path from 'node:path';
import { adminCommand, installedKeyFile } from '../../admin-command.mjs';
import { controlFile, readKeyringRows, readStartRecords } from '../../db/control.mjs';
import { restoreSnapshot, snapshotsDirectory } from '../../db/snapshot.mjs';
import { keys as startKeys, placedSinceLastStart } from '../../identity/bootstrap.mjs';
import { Keyring, keySourceLabel, resolveKey } from '../../keyring.mjs';
import { printable } from '../../saved-data.mjs';
import { CommandError, formatBytes, withLock } from '../common.mjs';

export const summary =
  'Restore a snapshot (Uptime Goblin stopped); the replaced files are kept aside.';
export const usage = '<id> [--keep-history] [--data-dir <dir>] [--json]';
export const kind = 'offline';
export const options = { 'keep-history': { type: 'boolean', default: false } };
// The snapshot's id.
export const maxPositionals = 1;

// What a restore that removed control.sqlite says it took away with it. The audit log goes too
// (docs audit, audit 9): the next start begins a new, empty log that lists no restore, since
// both restore detectors live in that file, so the old log survives only in the pre-restore
// snapshot the next line names.
const removedControlLine =
  "control.sqlite held Uptime Goblin 1.5's audit log, its sessions, its waiting notifications, its delivery history and the webhook signing key. The audit log starts again, empty, at the next start, and Check integrity will list no restore: the old log is kept only in the pre-restore snapshot named below. Those notifications will not be sent. With a webhook set, Uptime Goblin 1.5 makes a new signing key when it next starts. Give its public key (Configure → Notifications → Show public key) to receivers that check X-Goblin-Signature: until they have it, they reject every request.";

// The opening every certain key line shares (the docs quote it): the restored keyring is of a
// time before the key changed.
const changedAfter =
  "The restored control.sqlite holds the keyring of the snapshot's time, which the encryption key changed after (key rotate, key rewrap or key reset)";

// What a restore says when the key it was given shows that the keyring it brought back was
// wrapped by an encryption key that has changed since (docs audit, keys 9): a key rotate or
// rewrap after a key change, or a key reset, came after the snapshot, so the restored data opens
// only with the older key, and the next start with the current one refuses (key_mismatch, exit
// status 78), unless Uptime Goblin is given the older key as its previous key too (review F2v2: the
// start accepts a data key that only its previous key opens). `checked` names that key. The
// first sentence is the one the docs quote.
const olderKeyLine = checked =>
  `${changedAfter}: it opens only with the older key, and Uptime Goblin refuses to start with the current key (key_mismatch) unless it is also given the older key as GOBLIN_SECRET_KEY_PREVIOUS_FILE. The key this command was given, ${checked}, opens the keyring this restore replaced, and not the restored one. Start Uptime Goblin with the older key, or move this data to the current key with key rotate, the older key given as GOBLIN_SECRET_KEY_PREVIOUS_FILE (docs/installation.md#snapshots). Keep the older key until you have.`;

// The same when the previous key this command was given opens what the key does not (review
// F2v2): Uptime Goblin's start accepts a data key that only its previous key opens (and warns until a
// rewrap or rotate has run), so it starts on the restored data while given that previous key too,
// and refuses with the current key alone.
const previousKeyLine = checked =>
  `${changedAfter}: the key this command was given, ${checked}, opens the keyring this restore replaced and not all of the restored one, which opens only with the previous key it was given too. Uptime Goblin starts on it only while that previous key is given to it as well (GOBLIN_SECRET_KEY_PREVIOUS_FILE), and refuses to start with the current key alone (key_mismatch). Move this data to the current key with key rotate, the previous key given as GOBLIN_SECRET_KEY_PREVIOUS_FILE, before you remove it (docs/installation.md#snapshots).`;

// The key a restore checked with, as its messages name it (never the key itself).
const checkedKey = key => `${keySourceLabel(key)} (fingerprint ${key.fingerprint})`;

// How a message names the key it checked with: one this command was given (its environment, a
// systemd credential, a Compose secret), or one it found in the data directory, which may be an
// older key left there.
const whose = key =>
  `${key?.source === 'data-directory' ? 'The key this command found in the data directory' : 'The key this command was given'}, ${checkedKey(key)},`;

// Why a key that does not open the keyring a restore replaced, or the restored one wrapped as it,
// can still be Uptime Goblin's (review F2v2, round 4): Uptime Goblin's start also accepts a data key that only its
// previous key opens, and a copy written over control.sqlite in place keeps the file's identity,
// so neither Uptime Goblin nor this command can tell it from the file Uptime Goblin ran on.
const previousAlternative =
  'Uptime Goblin is also given a previous key (GOBLIN_SECRET_KEY_PREVIOUS_FILE) that opens what it does not';
const inPlaceAlternative =
  'the control.sqlite this restore replaced is a copy written in place over the one Uptime Goblin last started on, or a rolled-back file-system snapshot, which passes for that file to this command as to Uptime Goblin';

// Why the keyring a restore replaced shows nothing of the key Uptime Goblin uses (keyringCheck's
// `replaced`), when it holds one: Uptime Goblin has not started on that control.sqlite since it was put
// in place, as after a restore undone before Uptime Goblin starts again (the pre-restore snapshot put back
// over the restored one), so a key that opens it need not be Uptime Goblin's (review OPS-801-2); or what
// Uptime Goblin's starts recorded in it could not be read (a damaged or odd control.sqlite, review F2v2).
const replacedLines = {
  unstarted:
    'Uptime Goblin has not started on the control.sqlite this restore replaced since a restore or a copy put it in place (such as a restore this one undoes), so its keyring does not show which key Uptime Goblin uses.',
  unrecorded:
    "What Uptime Goblin's starts recorded in the control.sqlite this restore replaced could not be read, so its keyring does not show which key Uptime Goblin uses.",
};

// The opening of the line a restore gives when it cannot tell whether the key Uptime Goblin uses opens the
// keyring it brought back: wrapped differently from the one it replaced; wrapped as that one, which
// shows nothing of Uptime Goblin's key (review F2v2: a second restore of the same key's time said nothing,
// and Uptime Goblin refused to start); wrapped as the one Uptime Goblin last started on, which the key it was
// given does not open (review F2v2, round 4: a copy written over control.sqlite in place passes
// for that file); or with no keyring replaced to compare it with (review F2v2: no control.sqlite
// in the data directory, or a damaged one, said nothing either).
const openings = {
  different:
    "The restored control.sqlite holds the keyring of the snapshot's time, wrapped differently from the keyring it replaced: the encryption key may have changed since (key rotate, key rewrap or key reset), and then it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch); a key changed and then changed back wraps it anew too, and then it opens as before.",
  same: 'The restored control.sqlite holds a keyring wrapped as the keyring it replaced, which opens with the same key, but that one is not a keyring Uptime Goblin is known to have started on: one an earlier restore brought back may be of the time before a key change (key rotate, key rewrap or key reset), and then it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch).',
  sameRan:
    "The restored control.sqlite holds a keyring wrapped as the keyring it replaced, which Uptime Goblin's starts record as the one it last started on, so a key that opened that one opens it too.",
  missing:
    "The restored control.sqlite holds the keyring of the snapshot's time, and the data directory held no keyring before this restore to compare it with: if the encryption key changed since (key rotate, key rewrap or key reset), it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch).",
  unreadable:
    "The restored control.sqlite holds the keyring of the snapshot's time, and the keyring of the control.sqlite this restore replaced could not be read to compare it with: if the encryption key changed since (key rotate, key rewrap or key reset), it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch).",
};

// A problem's text as a sentence: a key error ends in a full stop, another error need not.
const sentence = text => (/[.!?]$/.test(String(text)) ? String(text) : `${text}.`);

// Why a restore could not tell which key opens the keyring it brought back (keyringCheck's
// `reason`), as the sentence its message gives.
const uncheckedBecause = ({ reason, problem, previousProblem, key, replaced, wrapping }) => {
  const checked = key ? checkedKey(key) : null;
  const named = key ? whose(key) : null;
  // A copy written over control.sqlite in place, or a rolled-back file-system snapshot, keeps the
  // file's identity, so neither Uptime Goblin nor this command can tell it from the file Uptime Goblin ran on.
  const inPlace =
    'a copy written over control.sqlite in place since Uptime Goblin last started passes for the file Uptime Goblin ran on, to this command as to Uptime Goblin';
  return {
    no_key:
      'No encryption key reached this command to tell which (it reads the key from its own environment, as the key commands do).',
    // Wrapped as the keyring Uptime Goblin last started on (openings.sameRan), there is no "which" to
    // tell, only whether the key opens it, which an in-place copy makes worth checking (review
    // F2v2, round 5). `problem` names the key source that failed: one given, or the data
    // directory's own.
    key_unreadable:
      wrapping === 'same' && replaced === 'ran'
        ? `The key this command reads could not be used to check that: ${sentence(problem)} Wrapped as the keyring Uptime Goblin last started on, it may still not open with the key Uptime Goblin uses: ${inPlace}.`
        : `The key this command reads could not be used to tell which: ${sentence(problem)}`,
    opens_restored_only: `${named} opens it but not the keyring this restore replaced, so it may not be the key Uptime Goblin uses: it may be an older key. Or it is Uptime Goblin's, and ${previousAlternative}, or ${inPlaceAlternative}.`,
    opens_neither: `${named} opens neither it nor the keyring this restore replaced, so it is not the key Uptime Goblin last started with, unless ${previousAlternative}, or ${inPlaceAlternative}.`,
    replaced_needs_previous: `${named} opens the keyring this restore replaced only with the previous key it was given too, as Uptime Goblin's start accepts, so it does not show which of the two Uptime Goblin uses as its key.`,
    data_directory_key: `The key this command found in the data directory, ${checked}, opens the keyring this restore replaced and not the restored one, but an older key can be left there after a key change, and ${inPlace}: it may not be the key Uptime Goblin uses.`,
    data_directory_opens: `The key this command found in the data directory, ${checked}, opens it and the keyring this restore replaced, but an older key can be left there after a key change, and ${inPlace}: it may not be the key Uptime Goblin uses.`,
    same_refuses: `${named} does not open it: either that is not the key Uptime Goblin uses, or ${previousAlternative}, or ${inPlaceAlternative}, and then Uptime Goblin refuses to start with that key (key_mismatch) on the restored one as it would have on the one it replaced.`,
    // As older or previous, but the previous key it was given, which tells the two apart, could
    // not be read (review F2v2, round 6).
    previous_unreadable: `${named} opens the keyring this restore replaced and not the restored one by itself, and the previous key it was given, which may open the rest as Uptime Goblin's start accepts, could not be read: ${sentence(previousProblem)}`,
    unconfirmed_opens: `${named} opens the restored keyring, but it may not be the key Uptime Goblin uses.`,
    unconfirmed_refuses: `${named} does not open the restored keyring, and it may not be the key Uptime Goblin uses.`,
  }[reason];
};

// The reasons whose key need not be Uptime Goblin's: one that does not open the keyring Uptime Goblin last ran
// with alone, or not the restored one wrapped as that keyring, need not be; one found in the data
// directory may be an older key left there; and when the replaced keyring is not one Uptime Goblin ran on
// nothing shows whether it is.
const notOrbits = new Set([
  'opens_restored_only',
  'opens_neither',
  'replaced_needs_previous',
  'data_directory_key',
  'data_directory_opens',
  'same_refuses',
  'unconfirmed_opens',
  'unconfirmed_refuses',
]);

// The reasons that leave open that Uptime Goblin uses a previous key too: its key status line then needs
// that key's file as well, since Uptime Goblin's start opens with it. So does every line of a restore
// given a previous key it could not read (`previousProblem`), which shows that Uptime Goblin may use one.
const previousMayMatter = new Set([
  'opens_restored_only',
  'opens_neither',
  'replaced_needs_previous',
  'same_refuses',
  'previous_unreadable',
]);

// What a restore says when it cannot tell whether the key Uptime Goblin uses opens the keyring it brought
// back. Every key rewrap wraps the data keys anew, a change back to an earlier key too (A to B,
// then B to A: the snapshot of A's time opens with A again), so the bytes alone never prove that
// the current key refuses it (review OPS-801-2). Key status with the key Uptime Goblin uses tells, before
// Uptime Goblin starts. Its line names the key file this command was given only when it read that key
// (`check.key`) and the key could be Uptime Goblin's as far as this command can tell (notOrbits);
// otherwise the installer's file, as for no key at all: a key file it could not read fails that
// line the same way (review F2v2, round 5: key_unreadable named the very file that could not be
// read). A previous key file it could not read is left out of the check, not the key (round 6),
// and the line says so.
const mayNeedOlderKeyLine = check => {
  const status = adminCommand('key status', {
    key: true,
    ...(!check.key || notOrbits.has(check.reason) ? { keyFile: installedKeyFile } : {}),
  });
  const opening =
    check.wrapping === 'same'
      ? check.replaced === 'ran'
        ? openings.sameRan
        : openings.same
      : (openings[check.replaced] ?? openings.different);
  return [
    opening,
    replacedLines[check.replaced],
    uncheckedBecause(check),
    check.previousProblem && check.reason !== 'previous_unreadable'
      ? `The previous key this command was given could not be read, so it was left out: ${sentence(check.previousProblem)}`
      : null,
    `Before you start Uptime Goblin, check it with the key Uptime Goblin uses: ${status}.`,
    previousMayMatter.has(check.reason) || check.previousProblem
      ? "If Uptime Goblin is also given a previous key, add GOBLIN_SECRET_KEY_PREVIOUS_FILE with that key's file after the key file in that line, since Uptime Goblin's start opens with it too."
      : null,
    'If that says the key does not match this data, start Uptime Goblin with the older key, or move this data to the current key with key rotate, the older key given as GOBLIN_SECRET_KEY_PREVIOUS_FILE (docs/installation.md#snapshots).',
  ]
    .filter(Boolean)
    .join(' ');
};

// Whether `key` (with `previous`, when given) opens every data key of `rows`, as the start's
// keycheck needs it to: Keyring.check, writing nothing. A data key that only `previous` opens
// counts, as it does at the start (which then warns until a rewrap or rotate has run).
async function opensAll(rows, key, previous = null) {
  try {
    await Keyring.check({ list: async () => rows }, { key, previous });
    return true;
  } catch (error) {
    if (error?.code !== 'key_mismatch') throw error;
    return false;
  }
}

// The keyring rows of the control.sqlite this restore replaced (in the pre-restore snapshot), and
// whether Uptime Goblin has started on that file since it was put in place: {rows, replaced}, with
// `replaced` 'ran', 'unstarted' or 'unrecorded' (what the starts recorded could not be read), or
// 'missing' (no control.sqlite, or no keyring in it) or 'unreadable' with no rows. Never throws:
// a damaged control.sqlite is a common reason to restore, and its keyring may still be read when
// its start records cannot (review F2v2: one failed read silenced the whole check).
async function replacedKeyring(file) {
  if (!fs.existsSync(file)) return { rows: [], replaced: 'missing' };
  let rows;
  try {
    rows = await readKeyringRows(file);
  } catch {
    return { rows: [], replaced: 'unreadable' };
  }
  if (!rows.length) return { rows, replaced: 'missing' };
  try {
    const records = await readStartRecords(file, [startKeys.restoreSeen, startKeys.controlFile]);
    return { rows, replaced: placedSinceLastStart(file, records) ? 'unstarted' : 'ran' };
  } catch {
    return { rows, replaced: 'unrecorded' };
  }
}

/**
 * What the keyring the restore brought back (control.sqlite now) means for the encryption key,
 * against the keyring it replaced (in the pre-restore snapshot `aside`). Resolves null only when
 * the restored control.sqlite has no keyring or cannot be read (the next start says what it
 * finds), else {state, key, reason, problem, previousProblem, replaced, wrapping}. A previous key
 * it was given and cannot read (`previousProblem`: why) is left out, and the key checked alone
 * (review F2v2, round 6). `replaced` is what the keyring it replaced shows of the key Uptime Goblin uses
 * (replacedKeyring): only one Uptime Goblin has started on since it was put in place ('ran') stands for
 * it. `wrapping` is 'same' when every restored data key is in that keyring, wrapped the same,
 * 'different' otherwise, null without a keyring to compare.
 *   unchanged  wrapped the same as a keyring Uptime Goblin ran on: it opens as that one did, and the key
 *              this command found, if any, opens it (with the previous key it was given); with no
 *              key at all there is nothing to check it with (review F2v2, round 4). A key it cannot
 *              read is key_unreadable, as in every state (round 5).
 *   opens      wrapped differently, and the key this command was given (not one it found in the
 *              data directory) opens every data key of both, the replaced one by itself: a key
 *              changed and changed back since the snapshot (A to B to A), or newer data keys.
 *   older      wrapped differently, and that key opens the keyring Uptime Goblin last ran with by itself,
 *              and not the restored one, nor with the previous key this command was given: Uptime Goblin
 *              refuses to start with it (key_mismatch).
 *   previous   as older, but the previous key this command was given opens the rest: Uptime Goblin starts
 *              on it only while given that previous key too (review F2v2).
 *   unchecked  this command cannot tell whether the key Uptime Goblin uses opens it: `reason` no_key,
 *              key_unreadable (`problem`: why), opens_restored_only or opens_neither (its key does
 *              not open the keyring Uptime Goblin ran on, so it need not be Uptime Goblin's, unless Uptime Goblin has a
 *              previous key that opens the rest), replaced_needs_previous (it opens that keyring
 *              only with the previous key it was given: either of the two may be Uptime Goblin's key,
 *              review F2v2 round 4), data_directory_key or data_directory_opens (as older or
 *              previous, or as opens, but with the data directory's own secret.key, which may be
 *              an older key left there, review F2v2), same_refuses (wrapped as the keyring Uptime Goblin
 *              ran on, which its key does not open: it need not be Uptime Goblin's, or that control.sqlite
 *              was a copy written over it in place, review F2v2 round 4), previous_unreadable (as
 *              older or previous, which the previous key it could not read would tell apart, round
 *              6), or unconfirmed_opens or unconfirmed_refuses (whether its key opens the restored
 *              keyring) when the replaced keyring is not one Uptime Goblin ran on, also when it is wrapped
 *              the same (review F2v2).
 * The replaced keyring stands for the key Uptime Goblin uses only when Uptime Goblin has started on that
 * control.sqlite since a restore or a copy put it in place (placedSinceLastStart): after a restore
 * that Uptime Goblin has not started on yet, such as one undone with its pre-restore snapshot, it is that
 * restore's keyring, which an older key may open while Uptime Goblin's own key opens the data put back
 * (review OPS-801-2). Neither Uptime Goblin nor this command can tell a copy written over control.sqlite in
 * place, so the certain lines, and the silence of `opens`, are given only for a key named to this
 * command (its environment, a systemd credential, a Compose secret), never for one it found in the
 * data directory, and only when that key opens the keyring Uptime Goblin ran on by itself: Uptime Goblin's start
 * also accepts a data key that only its previous key opens, so a key that needs the previous key
 * there does not show which of the two Uptime Goblin uses as its key (review F2v2, round 4).
 * Ciphertext alone is never taken for a key change: rewrapping uses a fresh IV each time, so even
 * a change back to the snapshot's own key leaves different bytes (review OPS-801-2). `key` is the
 * checked key's {source, file, fingerprint}, never the key; both keys are wiped after the check.
 * The restore has already happened, so nothing here throws: a key problem is reported instead.
 */
async function keyringCheck(context, aside) {
  let restored;
  try {
    restored = await readKeyringRows(path.join(context.dataDir, controlFile));
  } catch {
    return null;
  }
  if (!restored.length) return null;
  const { rows: before, replaced } = await replacedKeyring(
    path.join(context.dataDir, snapshotsDirectory, aside, controlFile)
  );
  // Compared as stored (text), so an odd row (no wrapped value, a number) is no error: it differs.
  const wrapped = new Map(before.map(row => [row.kid, row.wrapped]));
  const wrapping = !before.length
    ? null
    : restored.every(row => typeof row.wrapped === 'string' && wrapped.get(row.kid) === row.wrapped)
      ? 'same'
      : 'different';
  // A previous key it was given and could not read: why it was left out.
  let previousProblem = null;
  const result = (state, extra = {}) => ({
    state,
    key: null,
    reason: null,
    problem: null,
    previousProblem,
    replaced,
    wrapping,
    ...extra,
  });
  // Wrapped as the keyring Uptime Goblin last started on, the restored one opens as that one did, but a
  // copy written over control.sqlite in place passes for that file (review F2v2, round 4): the key
  // this command has, if any, is checked against it too.
  const unchanged = wrapping === 'same' && replaced === 'ran';
  let found;
  try {
    // As the key commands look for it: never generated, and none found is no lost key. A previous
    // key file it cannot read is left out, not the key it can read (review F2v2, round 6: the
    // previous key file, read first, failed the whole check, and the documented recovery's own
    // environment with a mistyped previous key file got a key status line without either file).
    found = resolveKey({
      env: context.env,
      directory: context.dataDir,
      keyringExists: true,
      generate: false,
      ...context.keySources,
      onPreviousError: error => {
        previousProblem = error.message;
      },
    });
  } catch (error) {
    // Only no key at all leaves a keyring wrapped as the one Uptime Goblin ran on unchecked and unsaid: a
    // key it cannot read is said, as in every other state (review F2v2, round 5: an unreadable
    // key file silenced the check of the restore). A previous key alone checks nothing.
    if (error?.code === 'key_missing')
      return unchanged ? result('unchanged') : result('unchecked', { reason: 'no_key' });
    return result('unchecked', {
      reason: 'key_unreadable',
      problem: error?.message ?? String(error),
    });
  }
  if (!found)
    return result(unchanged ? 'unchanged' : 'unchecked', unchanged ? {} : { reason: 'no_key' });
  const key = { source: found.source, file: found.file ?? null, fingerprint: found.fingerprint };
  try {
    const opensRestored = await opensAll(restored, found.key);
    const opensRestoredWithPrevious =
      opensRestored ||
      Boolean(found.previous && (await opensAll(restored, found.key, found.previous)));
    if (unchanged)
      return opensRestoredWithPrevious
        ? result('unchanged', { key })
        : result('unchecked', { key, reason: 'same_refuses' });
    if (replaced !== 'ran')
      return result('unchecked', {
        key,
        reason: opensRestored ? 'unconfirmed_opens' : 'unconfirmed_refuses',
      });
    // The keyring Uptime Goblin last started on shows the key Uptime Goblin uses only when that key opens it by
    // itself. Uptime Goblin's start also accepts a data key that only its previous key opens, so a key
    // that opens it only with the previous key may be either of the two Uptime Goblin uses as its key, and
    // one that does not open it may be Uptime Goblin's own with a previous key this command was not given
    // (review F2v2, round 4: after the documented start with the current key and the older one as
    // the previous key, an undo with Uptime Goblin's own key called it an older key).
    if (!(await opensAll(before, found.key)))
      return result('unchecked', {
        key,
        reason:
          found.previous && (await opensAll(before, found.key, found.previous))
            ? 'replaced_needs_previous'
            : opensRestored
              ? 'opens_restored_only'
              : 'opens_neither',
      });
    if (found.source === 'data-directory')
      return result('unchecked', {
        key,
        reason: opensRestored ? 'data_directory_opens' : 'data_directory_key',
      });
    if (opensRestored) return result('opens', { key });
    if (opensRestoredWithPrevious) return result('previous', { key });
    // Whether Uptime Goblin starts on it given its previous key too (previous) or not (older), the previous
    // key this command could not read would tell (review F2v2, round 6).
    return previousProblem
      ? result('unchecked', { key, reason: 'previous_unreadable' })
      : result('older', { key });
  } catch (error) {
    return result('unchecked', {
      key,
      reason: 'key_unreadable',
      problem: error?.message ?? String(error),
    });
  } finally {
    found.key.fill(0);
    found.previous?.fill(0);
  }
}

/**
 * What a restore says of a snapshot that keeps the files which had changed since it was
 * interrupted (`kept` from restoreSnapshot): they were set aside, not deleted. Its file names
 * come from that snapshot's manifest when an earlier attempt finished it: saved data, printed
 * without control characters.
 */
export function keptLine({ id, files, damaged = [] }) {
  const one = files.length === 1;
  const names = list => list.map(name => printable(name, 100)).join(', ');
  return `${names(files)} had changed since this restore was interrupted (Orbit 1.4.x, which does not check for an interrupted restore, may have run on the data directory meanwhile), so ${one ? 'it was' : 'they were'} kept, not deleted: snapshot ${id} holds ${one ? 'it' : 'them'}. ${
    damaged.length
      ? `It cannot be restored as a whole, because ${damaged.map(item => printable(item.name, 100)).join(' and ')} in it ${damaged.length === 1 ? 'is' : 'are'} damaged; copy its other files back by hand if you need them.`
      : `Restore that snapshot to put ${one ? 'it' : 'them'} back.`
  }`;
}

export async function run(context) {
  const [id, ...extra] = context.args;
  if (!id || extra.length)
    throw new CommandError(`Usage: goblin-admin restore-snapshot ${usage}`, 2);
  return withLock(context, 'goblin-admin restore-snapshot', async lock => {
    const result = await restoreSnapshot(context.dataDir, id, {
      lock,
      history: !context.options['keep-history'],
      release: context.release,
      clock: context.clock,
    });
    const keyCheck =
      result.restored.includes(controlFile) && result.aside
        ? await keyringCheck(context, result.aside)
        : null;
    // olderKey only when the key this command was given shows that Uptime Goblin refuses to start with
    // it (keyringCheck 'older'), not when the previous key it was given opens the rest ('previous').
    const olderKey = keyCheck?.state === 'older';
    context.report({ ...result, olderKey, keyCheck }, value => [
      `Restored ${value.restored.join(', ') || 'nothing'} from ${id}.`,
      ...(value.removed.length
        ? [`Removed (absent in the snapshot): ${value.removed.join(', ')}.`]
        : []),
      // A snapshot without control.sqlite is one taken before 1.5 first ran (the pinned
      // pre-upgrade one): restoring it takes the outbox and the sealed signing key away with
      // that file, and the next start makes a new key whose public key receivers do not have.
      ...(value.removed.includes('control.sqlite') ? [removedControlLine] : []),
      // A damaged file it replaced first: the key line may say that its keyring could not be read.
      // SQLite's reason quotes the damaged database's own schema names (malformed database
      // schema (<name>)): saved data, printed without control characters on one line.
      ...(value.damaged ?? []).map(
        item =>
          `${item.name} could not be opened (${printable(item.problem, 300)}), so it was moved aside as it was, with any -wal and -shm files beside it.`
      ),
      ...(value.olderKey ? [olderKeyLine(checkedKey(value.keyCheck.key))] : []),
      ...(value.keyCheck?.state === 'previous'
        ? [previousKeyLine(checkedKey(value.keyCheck.key))]
        : []),
      ...(value.keyCheck?.state === 'unchecked' ? [mayNeedOlderKeyLine(value.keyCheck)] : []),
      value.damaged?.length
        ? `The replaced files are in snapshot ${value.aside}. It cannot be restored as a whole, because ${value.damaged.map(item => item.name).join(' and ')} in it ${value.damaged.length === 1 ? 'is' : 'are'} damaged; copy its other files back by hand if you need them.`
        : `The replaced files are in snapshot ${value.aside}; restore it to undo.`,
      ...(value.kept ?? []).map(item => keptLine(item)),
      ...(value.leftovers?.length
        ? [
            `Removed ${value.leftovers.flatMap(item => item.names).join(', ')} (${formatBytes(value.leftovers.reduce((sum, item) => sum + item.bytes, 0))}): temporary copies that an earlier restore, stopped by a crash, left in the data directory.`,
          ]
        : []),
      ...(value.unfinished
        ? [
            `An earlier restore${value.unfinished.snapshot ? ` of ${value.unfinished.snapshot}` : ''} was interrupted and also replaced ${value.unfinished.files.join(', ')}, which this restore left as they are. Uptime Goblin 1.5 and later will not start until it is finished (Orbit 1.4.x does not check: keep it stopped too): run that restore again.`,
          ]
        : []),
    ]);
    return 0;
  });
}
