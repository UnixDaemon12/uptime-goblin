// Configure → Audit log (#configure/audit): who changed what, and when (audit spec §8). The page
// checks the log's integrity (GET /api/audit/verify), lists its entries newest first
// (GET /api/audit) with filters, Refresh, Load more and each entry's details with what changed,
// and exports what the filters select (GET /api/audit/export) as CSV or NDJSON. Nothing on it
// polls: the list is read when the page opens, on Refresh, on a filter change and on Load more,
// and the check runs only when asked for.
//
// The texts below are a copy of lib/audit/actions.mjs (the web app cannot import lib/), which
// test/ui.test.mjs compares with the server's: change them there, then here. Uptime Goblin sends rows and
// verification results as data; the page puts them into words itself, with times in the page's
// time zone, so an entry, a restore and a problem read the same as the CLI's apart from the time.
import { api, testTimeoutMs } from '../core/api.js';
import { $, esc, toast } from '../core/dom.js';
import { dateTime, format } from '../core/format.js';
import { focusable, holdFocus, selectField } from '../core/forms.js';
import { page } from '../core/page.js';
import { patchHtml } from '../core/patch.js';
import { deviceName } from '../identity/account.js';
import { downloadFile } from './exports.js';
import { unavailableText } from './notifications.js';

// --- The texts (a copy of lib/audit/actions.mjs) ----------------------------------------------

/** An entry's summary sentence by action: the first `texts` rule that holds, then every `suffixes` rule that holds (see entrySentence()). */
export const AUDIT_TEXTS = Object.freeze({
  'session.login': {
    texts: [
      ['ok kind=kiosk', 'Wall display {display} signed in with a display code'],
      ['ok', 'Signed in'],
      ['summary', '{count} more refused sign-ins: {codes}'],
      ['failed|denied', 'Sign-in refused: {code}'],
    ],
    suffixes: [],
  },
  'session.logout': {
    texts: [
      ['ok cause=signout', 'Signed out'],
      ['ok cause=presented', 'Signed out a session this browser presented'],
      ['ok cause=ended', 'Signed out a session that had already ended elsewhere'],
      ['failed', 'Sign-out could not be saved: {code}'],
    ],
    suffixes: [],
  },
  'session.revoked': {
    texts: [
      ['cause=by_user', 'Signed out another device'],
      ['cause=insecure_cookie', "Signed out this browser's plain-HTTP session"],
      [
        'cause=insecure_http_off',
        'Signed out {count} plain-HTTP sessions: plain-HTTP sign-in was switched off',
      ],
      ['cause=retried', 'Removed {count} signed-out sessions that could not be removed before'],
      [
        'cause=ended_part_way',
        'Removed {count} sessions signed out by a session that ended before it could save that',
      ],
    ],
    suffixes: [],
  },
  'session.revoked-others': { texts: [['*', 'Signed out {count} other devices']], suffixes: [] },
  'session.revoked-restore': {
    texts: [
      [
        'cause=credentials_anchor',
        'Removed {displayCodes} display credentials: the credential restore boundary changed',
      ],
      ['cause=snapshot', 'Signed everyone out: the data was restored from snapshot {snapshot}'],
      [
        'cause=control_file',
        'Signed everyone out: control.sqlite was restored from a backup, copied or moved',
      ],
    ],
    suffixes: [],
  },
  'account.password.changed': {
    texts: [
      ['ok', 'Changed the admin password'],
      ['summary', '{count} more refused password changes: {codes}'],
      ['failed|denied', 'Password change refused: {code}'],
    ],
    suffixes: [],
  },
  'account.password.changed-outside': {
    texts: [
      ['source=auth.json', 'The admin password was changed outside Uptime Goblin (auth.json)'],
      ['source=env', 'The admin password was changed outside Uptime Goblin (GOBLIN_PASSWORD)'],
      [
        'source=control.sqlite',
        'The admin password was changed by an earlier Uptime Goblin 1.5 build',
      ],
    ],
    suffixes: [],
  },
  'account.bootstrap': {
    texts: [
      ['source=auth.json', 'Set up the admin account with the password from auth.json'],
      ['source=env', 'Set up the admin account with GOBLIN_PASSWORD'],
      // Only in entries of earlier 1.5 builds: Uptime Goblin no longer starts without a password.
      ['source=none', 'Set up the admin account without a password (local preview)'],
    ],
    suffixes: [],
  },
  'account.claimed': {
    texts: [['*', 'Kept the admin account carried in this database and wrote it to auth.json']],
    suffixes: [],
  },
  'identity.mirror.failed': { texts: [['*', 'Could not update auth.json: {code}']], suffixes: [] },
  'display.code.created': {
    texts: [['*', 'Created a display code for wall display {name}']],
    suffixes: [],
  },
  'display.code.cancelled': {
    texts: [
      ['cause=plain_http', 'Cancelled display code {name}: it was sent over plain HTTP'],
      [
        'cause=password_change',
        'Cancelled {count} waiting display codes: the admin password changed',
      ],
      ['count', 'Cancelled {count} waiting display codes'],
      ['*', 'Cancelled display code {name}'],
    ],
    suffixes: [['late', ' (recorded when Uptime Goblin next ran)']],
  },
  'auth.basic.failed': {
    texts: [
      ['summary', '{count} more refused script sign-ins: {codes}'],
      ['*', 'Script sign-in refused: {code}'],
    ],
    suffixes: [],
  },
  'auth.step-up': {
    texts: [
      ['summary', '{count} more requests refused by step-up or lockdown: {codes}'],
      ['*', 'Request refused by step-up or lockdown: {code}'],
    ],
    suffixes: [],
  },
  'auth.forbidden': {
    texts: [
      ['summary', '{count} more requests refused by authorization: {codes}'],
      ['*', 'Request refused by authorization: {code}'],
    ],
    suffixes: [],
  },
  'auth.basic.used': {
    texts: [
      ['summary', 'Scripts signed in with the password {count} more times'],
      ['*', 'A script signed in with the password'],
    ],
    suffixes: [],
  },
  'settings.update': {
    texts: [
      ['ok', 'Changed workspace settings'],
      ['attempt', 'Change of workspace settings: in progress'],
      ['unknown', 'Change of workspace settings: outcome unknown'],
      ['conflict', 'Change of workspace settings: refused, changed elsewhere first'],
      ['denied', 'Change of workspace settings: refused ({code})'],
      ['failed code', 'Change of workspace settings: failed ({code})'],
      ['failed', 'Change of workspace settings: failed'],
    ],
    suffixes: [],
  },
  'source.create': {
    texts: [
      ['ok', 'Added source {name}'],
      ['attempt', 'Adding source {name}: in progress'],
      ['unknown', 'Adding source {name}: outcome unknown'],
      ['conflict', 'Adding source {name}: refused, changed elsewhere first'],
      ['denied', 'Adding source {name}: refused ({code})'],
      ['failed code', 'Adding source {name}: failed ({code})'],
      ['failed', 'Adding source {name}: failed'],
    ],
    suffixes: [],
  },
  'source.update': {
    texts: [
      ['ok', 'Changed source {name}'],
      ['attempt', 'Change of source {name}: in progress'],
      ['unknown', 'Change of source {name}: outcome unknown'],
      ['conflict', 'Change of source {name}: refused, changed elsewhere first'],
      ['denied', 'Change of source {name}: refused ({code})'],
      ['failed code', 'Change of source {name}: failed ({code})'],
      ['failed', 'Change of source {name}: failed'],
    ],
    suffixes: [],
  },
  'source.delete': {
    texts: [
      ['ok', 'Deleted source {name}'],
      ['attempt', 'Deleting source {name}: in progress'],
      ['unknown', 'Deleting source {name}: outcome unknown'],
      ['conflict', 'Deleting source {name}: refused, changed elsewhere first'],
      ['denied', 'Deleting source {name}: refused ({code})'],
      ['failed code', 'Deleting source {name}: failed ({code})'],
      ['failed', 'Deleting source {name}: failed'],
    ],
    suffixes: [],
  },
  'source.test': {
    texts: [
      ['ok', 'Tested the connection to {name}: connected'],
      ['failed result=timeout', 'Tested the connection to {name}: it timed out'],
      ['failed', 'Tested the connection to {name}: it failed'],
      ['denied', 'Connection test of {name} refused ({code})'],
    ],
    suffixes: [],
  },
  'email.test': {
    texts: [
      ['ok', 'Sent a test email: the mail server accepted it'],
      ['failed', 'Sent a test email: the mail server refused it'],
      ['denied', 'Test email refused ({code})'],
      ['conflict', 'Test email not sent: the email settings changed first'],
    ],
    suffixes: [],
  },
  'sources.refresh': {
    texts: [
      ['ok', 'Asked every source for new readings'],
      ['denied', 'Refresh refused ({code})'],
      ['failed', 'Refresh failed ({code})'],
    ],
    suffixes: [],
  },
  'sources.import': {
    texts: [
      ['ok', 'Imported from Uptime Kuma: {added} added, {changed} changed, {skipped} skipped'],
      ['attempt', 'Import from Uptime Kuma: in progress'],
      ['unknown', 'Import from Uptime Kuma: outcome unknown'],
      ['conflict', 'Import from Uptime Kuma: refused, changed elsewhere first'],
      ['denied', 'Import from Uptime Kuma: refused ({code})'],
      ['failed code', 'Import from Uptime Kuma: failed ({code})'],
      ['failed', 'Import from Uptime Kuma: failed'],
    ],
    suffixes: [],
  },
  'delivery.retry': {
    texts: [
      ['ok', 'Retried a notification ({retried} queued again)'],
      ['attempt', 'Retry of a notification: in progress'],
      ['unknown', 'Retry of a notification: outcome unknown'],
      ['denied', 'Retry of a notification: refused ({code})'],
      ['failed code', 'Retry of a notification: failed ({code})'],
      ['failed', 'Retry of a notification: failed'],
    ],
    suffixes: [],
  },
  'channel.resume': {
    texts: [
      ['ok', 'Resumed the {id} channel ({released} released)'],
      ['attempt', 'Resuming the {id} channel: in progress'],
      ['unknown', 'Resuming the {id} channel: outcome unknown'],
      ['denied', 'Resuming the {id} channel: refused ({code})'],
      ['failed code', 'Resuming the {id} channel: failed ({code})'],
      ['failed', 'Resuming the {id} channel: failed'],
    ],
    suffixes: [],
  },
  'channel.settings': { texts: [['*', 'Changed the {id} channel settings']], suffixes: [] },
  'channel.test': {
    texts: [
      ['ok', 'Sent a test notification on {id}: it was accepted'],
      ['failed', 'Sent a test notification on {id}: it was not accepted'],
      ['denied', 'Test notification on {id} refused ({code})'],
      ['conflict', 'Test notification on {id} not sent ({code})'],
    ],
    suffixes: [],
  },
  'signing.reveal': {
    texts: [
      ['ok', 'Showed the webhook signing secret'],
      ['attempt', 'Showing the webhook signing secret: in progress'],
      ['unknown', 'Showing the webhook signing secret: outcome unknown'],
      ['denied', 'Showing the webhook signing secret: refused ({code})'],
      ['failed code', 'Showing the webhook signing secret: failed ({code})'],
      ['failed', 'Showing the webhook signing secret: failed'],
    ],
    suffixes: [],
  },
  'signing.rotate': { texts: [['*', 'Replaced the webhook signing key']], suffixes: [] },
  'signing.created': {
    texts: [
      ['replaced', 'Created a new webhook signing key: the old one could not be read'],
      ['*', 'Created the webhook signing key'],
    ],
    suffixes: [],
  },
  'channel.paused': { texts: [['*', 'Paused the {id} channel: {reason}']], suffixes: [] },
  'channel.working': { texts: [['*', 'The {id} channel works again']], suffixes: [] },
  'notifications.unsaved': {
    texts: [['*', 'Uptime Goblin keeps notifications in memory only: it cannot save them']],
    suffixes: [],
  },
  'notifications.saved': {
    texts: [['*', 'Uptime Goblin saves notifications again']],
    suffixes: [],
  },
  'config.export': { texts: [['*', 'Exported the configuration (without secrets)']], suffixes: [] },
  'audit.export': { texts: [['*', 'Exported {rows} audit entries ({format})']], suffixes: [] },
  'config.changed-outside': {
    texts: [
      [
        'repaired',
        'Settings were changed outside Uptime Goblin or repaired at start (config.json)',
      ],
      ['*', 'Settings were changed outside Uptime Goblin (config.json)'],
    ],
    suffixes: [],
  },
  'system.start': {
    texts: [
      ['first', 'Uptime Goblin {version} started for the first time'],
      [
        '!cleanStop',
        'Uptime Goblin {version} started; its previous stop was not recorded (a crash, or a stop while the disk was full)',
      ],
      ['*', 'Uptime Goblin {version} started'],
    ],
    suffixes: [['securityChanged', '; security settings from the environment changed: {names}']],
  },
  'system.stop': { texts: [['*', 'Uptime Goblin stopped']], suffixes: [] },
  'system.upgrade': {
    texts: [
      ['own', 'Uptime Goblin {release} opened this data'],
      ['*', 'Uptime Goblin {release} found that {n} releases opened this data: {list}'],
    ],
    suffixes: [['markerLost', ' (some may be missing)']],
  },
  'system.restore': {
    texts: [
      ['cause=snapshot', "Uptime Goblin's data was restored from snapshot {snapshot}"],
      [
        'cause=control_file',
        'control.sqlite was replaced: a restore from a backup, a copy or a move',
      ],
    ],
    suffixes: [],
  },
  'data.snapshot': {
    texts: [['*', 'Snapshot {id} was taken ({reason})']],
    suffixes: [['more', ' and {more} older ones']],
  },
  'audit.gap': {
    texts: [
      ['reason=head-mismatch', 'Uptime Goblin found its audit log cut or changed at the end'],
      [
        'reason=inbox-discarded',
        'Uptime Goblin discarded {count} entries left in the audit inbox by an earlier start',
      ],
    ],
    suffixes: [],
  },
  'audit.pruned': {
    texts: [
      ['reason=age', 'Removed {deleted} audit entries older than the retention period'],
      [
        'reason=both',
        'Removed {deleted} audit entries older than the retention period and to stay within 250,000',
      ],
      ['*', 'Removed {deleted} audit entries to stay within 250,000'],
    ],
    suffixes: [],
  },
  'key.rewrap': {
    texts: [
      [
        'ok rewrapped=0',
        'goblin-admin key rewrap found every data key already wrapped under the current encryption key; nothing changed',
      ],
      ['ok', 'goblin-admin re-wrapped the data keys under the current encryption key'],
      ['failed', 'goblin-admin {command} failed ({code})'],
    ],
    suffixes: [],
  },
  'key.rotate': {
    texts: [
      ['ok', 'goblin-admin rotated the data keys'],
      ['failed', 'goblin-admin {command} failed ({code})'],
    ],
    suffixes: [],
  },
  'key.reset': {
    texts: [['ok', 'goblin-admin reset the keys after the encryption key was lost']],
    suffixes: [],
  },
  'key.remove-data-copy': {
    texts: [
      [
        'ok unused=true',
        'goblin-admin deleted an older encryption key, which Uptime Goblin no longer used, from the data directory',
      ],
      ['ok', 'goblin-admin deleted the copy of the encryption key in the data directory'],
      ['failed', 'goblin-admin {command} failed ({code})'],
    ],
    suffixes: [],
  },
});
/** The words of an error code in a summary sentence; any other code reads "Uptime Goblin error {code}". */
export const CODE_WORDS = Object.freeze({
  invalid_credentials: 'wrong name or password',
  current_password_incorrect: 'the current password was wrong',
  locked: 'too many failed attempts',
  busy: 'too many sign-ins at once',
  https_required: 'plain HTTP is not allowed',
  proxy_proto_missing: 'the proxy did not say the browser uses HTTPS',
  proxy_proto_mismatch: 'the proxy claimed HTTPS for a plain-HTTP page',
  cross_origin: "the page address did not match Uptime Goblin's",
  // Only in entries of earlier 1.5 builds, which refused sign-in without a password.
  signin_unavailable: 'no admin password is set',
  invalid_request: 'the request was incomplete',
  password_invalid: 'the new password does not meet the rules',
  password_mismatch: 'the new password and its confirmation differ',
  change_in_progress: 'another password change was in progress',
  multiple_credentials: 'more than one credential was sent',
  basic_disabled: 'script sign-in is turned off',
  retired_password: 'an old password was used',
  signin_required: 'the request was not signed in',
  session_expired: 'the session had ended',
  session_newer: 'that session signed in after this one',
  storage_full: 'the disk is full',
  client_closed: 'the browser closed the request',
  // auth.forbidden and auth.step-up (the request pipeline's authorization, lockdown and step-up).
  forbidden: 'the account may not do this',
  step_up_required: 'the password was not entered again',
  step_up_failed: 'the password entered again was wrong',
  step_up_unavailable: 'this sign-in cannot confirm with the password',
  admin_ui_locked: 'the action is turned off in the web app (GOBLIN_ADMIN_UI_LOCK)',
});
/** What Check integrity says about the first problem it found: its message, then its consequence. */
export const PROBLEM_TEXTS = Object.freeze({
  start_missing: {
    message: 'Entries before #{seq} are missing, and no prune recorded their removal.',
    consequence: 'The entries that remain were checked; the removed ones cannot be.',
  },
  link_broken: {
    message:
      'Entry #{seq} does not follow the entry before it: an entry was changed, inserted or removed.',
    consequence: 'Entries from #{seq} on cannot be trusted.',
  },
  seq_gap: {
    message: 'Entries #{from}–#{to} are missing.',
    consequence: 'The entries around them were checked; the removed ones cannot be.',
  },
  hash_mismatch: {
    message: 'Entry #{seq} does not match its signature: it was changed.',
    consequence: 'Entry #{seq} cannot be trusted; the others were checked.',
  },
  head_mismatch: {
    message:
      'The log ends at entry #{seq}, but Uptime Goblin last wrote entry #{head}: entries were removed from the end.',
    consequence: 'Entries after #{seq} are gone; the rest were checked.',
  },
  checkpoint_mismatch: {
    message: 'Checkpoint #{seq} does not match the entry it names.',
    consequence: 'The checkpoint or entry #{seq} was changed.',
  },
  checkpoint_mac: {
    message: 'Checkpoint #{seq} is not signed by this Uptime Goblin.',
    consequence:
      'A checkpoint was changed, or the key that signed it was removed without a recorded reset.',
  },
  journal_mismatch: {
    message: 'Entry #{seq} differs from the checkpoint Uptime Goblin printed on {lineTime}.',
    consequence:
      'Entry #{seq} or an entry before it was changed after Uptime Goblin printed the checkpoint.',
  },
  journal_ahead: {
    message: 'Uptime Goblin printed checkpoint #{seq} on {lineTime}, but the log ends at #{head}.',
    consequence:
      'Entries after #{head} were removed from the end, or this is an older copy of the data.',
  },
  log_truncated: {
    message:
      'On {time} Uptime Goblin found its audit log cut or changed at the end: it had last written entry #{head}, and the log ended at entry #{lastSeq}.',
    consequence:
      'Entries Uptime Goblin wrote after #{lastSeq} are missing or were changed; the entries before were checked.',
    whenNull: { head: 'an unknown entry', lastSeq: 'no entry' },
  },
  key_lost: {
    message:
      'Entry #{seq} is signed with a key that is not in the keyring, and no key reset recorded its loss.',
    consequence: 'Entries signed with that key cannot be trusted.',
  },
  unreadable: {
    message: 'Entries from #{seq} could not be read: a stored value is out of range.',
    consequence: 'They were not checked; the entries before them were.',
  },
});
/** One line per part of the log that could not be checked (and the two restore causes' words). */
export const UNVERIFIABLE_TEXTS = Object.freeze({
  no_key:
    'No encryption key reached this command, so the signatures were not checked (only the links between entries). Run it with the key file Uptime Goblin uses: {line}.',
  key_reset:
    'Entries #{from}–#{to} were signed with keys that goblin-admin key reset removed on {at}; their links were checked.',
  newer_format:
    'Entries #{from}–#{to} were written by a newer Uptime Goblin; their links were checked.',
  restore_unchecked:
    "{lines} checkpoint lines that Uptime Goblin printed before {restore words} on {at} could not be checked against the restored log. Check only the part of Uptime Goblin's log printed after the restore to get a full result.",
  unknown_key:
    "{lines} checkpoint lines are signed with keys the keyring does not hold, and no key reset recorded their loss, so they could not be checked: they are another Uptime Goblin's, this Uptime Goblin's from before a restore of older data or the removal of control.sqlite (which takes the whole audit log with it), or this Uptime Goblin's signed with a key since removed from the keyring, perhaps together with the entries it signed.",
  'restore.snapshot': 'the data was restored from snapshot {snapshot}',
  'restore.control_file': 'control.sqlite was replaced (a restore from a backup, a copy or a move)',
});
/** One line per restore, upgrade, gap and key reset that Check integrity lists. */
export const ANCHOR_TEXTS = Object.freeze({
  'system.restore.snapshot':
    'Restored from snapshot {snapshot} on {at}; the log continues from entry #{restoredHead.seq}.',
  'system.restore.snapshot.empty':
    'Restored from snapshot {snapshot} on {at}; the restored data held no audit entries.',
  'system.restore.control_file':
    'control.sqlite was replaced on {time} (a restore from a backup, a copy or a move); the log continues from entry #{restoredHead.seq}.',
  'system.restore.control_file.empty':
    'control.sqlite was replaced on {time} (a restore from a backup, a copy or a move); the restored data held no audit entries.',
  'system.upgrade': 'Uptime Goblin {to} opened this data on {at}.',
  'system.upgrade.other': 'Uptime Goblin {to} opened this data on {at} and wrote no audit entries.',
  'system.upgrade.markerLost':
    'Uptime Goblin could not tell which releases opened this data before {time}: its record of the last one was missing.',
  'audit.gap.head-mismatch':
    'On {time} Uptime Goblin found its audit log cut or changed at the end (entry #{seq}).',
  'audit.gap.inbox-discarded':
    'On {time} Uptime Goblin discarded {count} entries left in the audit inbox by an earlier start that could not sign them.',
  'key.reset':
    'goblin-admin key reset on {time} replaced the keys that signed entries up to #{head.seq}.',
  'key.reset.empty': 'goblin-admin key reset on {time} replaced the keys when the log was empty.',
});

// --- Words ---------------------------------------------------------------------------------------

/** An entry's outcome as the page says it ("unknown" and "attempt" are attempts without a result). */
const outcomeWords = Object.freeze({
  ok: 'Succeeded',
  denied: 'Refused',
  failed: 'Failed',
  conflict: 'Changed elsewhere',
  info: 'Recorded',
  unknown: 'Outcome unknown',
  attempt: 'In progress',
});
const outcomeWord = outcome =>
  Object.hasOwn(outcomeWords, outcome) ? outcomeWords[outcome] : String(outcome ?? '—');
/** A count or an entry number as the CLI writes it ("5,123"), whatever the browser's language. */
const grouped = n => (Number.isFinite(n) ? n.toLocaleString('en-US') : String(n ?? '—'));
const plural = (n, one, many = `${one}s`) => `${grouped(n)} ${n === 1 ? one : many}`;
/**
 * A detail value in a sentence: a missing one or an empty list reads "—", never "undefined",
 * "null" or nothing.
 */
function textOf(value) {
  if (value === undefined || value === null || value === '') return '—';
  if (typeof value === 'number') return grouped(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (Array.isArray(value)) return value.length ? value.map(textOf).join(', ') : '—';
  return JSON.stringify(value);
}
const own = (object, key) =>
  object && typeof object === 'object' && Object.hasOwn(object, key) ? object[key] : undefined;
const codeWords = code =>
  typeof code !== 'string' || !code
    ? '—'
    : Object.hasOwn(CODE_WORDS, code)
      ? CODE_WORDS[code]
      : `Uptime Goblin error ${code}`;

// --- An entry's summary sentence (AUDIT_TEXTS' rules, lib/audit/actions.mjs) ---------------------

const outcomeTerms = new Set([...Object.keys(outcomeWords)]);
/** "Set": true, a non-empty text or list, or a number other than 0. */
const isSet = value =>
  value === true ||
  (typeof value === 'string' && value !== '') ||
  (Array.isArray(value) && value.length > 0) ||
  (typeof value === 'number' && value !== 0);
/** An aggregated summary row: its detail counts the refusals by code. */
const isSummary = entry => {
  const codes = own(entry?.detail, 'codes');
  return !!codes && typeof codes === 'object' && !Array.isArray(codes);
};
function holds(term, entry) {
  const detail = entry.detail;
  if (term === '*') return true;
  if (term === 'summary') return isSummary(entry);
  if (term === 'own') {
    const entries = own(detail, 'entries');
    return (
      Array.isArray(entries) && entries.length === 1 && entries[0]?.to === own(detail, 'release')
    );
  }
  if (term.startsWith('!')) return !isSet(own(detail, term.slice(1)));
  const equals = term.indexOf('=');
  if (equals > 0) {
    const value = own(detail, term.slice(0, equals));
    return value !== undefined && value !== null && String(value) === term.slice(equals + 1);
  }
  const outcomes = term.split('|');
  if (outcomes.every(outcome => outcomeTerms.has(outcome))) return outcomes.includes(entry.outcome);
  return isSet(own(detail, term));
}
const applies = (when, entry) => when.split(' ').every(term => holds(term, entry));
function placeholder(key, entry) {
  const detail = entry.detail;
  switch (key) {
    case 'name':
      return entry.target?.name ?? entry.target?.id;
    case 'id':
      return entry.target?.id;
    case 'code':
      return codeWords(own(detail, 'code'));
    case 'codes': {
      const codes = own(detail, 'codes');
      return codes && typeof codes === 'object'
        ? Object.entries(codes)
            .map(([code, n]) => `${codeWords(code)} (${textOf(n)})`)
            .join(', ')
        : undefined;
    }
    case 'count':
      return own(detail, 'count') ?? entry.count;
    case 'n': {
      const entries = own(detail, 'entries');
      return Array.isArray(entries) ? entries.length : undefined;
    }
    case 'list': {
      const entries = own(detail, 'entries');
      return Array.isArray(entries) ? entries.map(e => textOf(e?.to)).join(', ') : undefined;
    }
    case 'names': {
      const names = own(detail, 'securityChanged');
      return Array.isArray(names) ? names.join(', ') : undefined;
    }
    case 'command':
      return String(entry.action).replace('.', ' ');
    default:
      return own(detail, key);
  }
}
const fill = (template, entry) =>
  template.replace(/\{([A-Za-z]+)\}/g, (_, key) => textOf(placeholder(key, entry)));
/**
 * The sentence that says what an entry records: the first of its action's texts whose rule holds,
 * followed by every suffix whose rule holds. An action this release does not know (written by a
 * later one), or a row no rule describes, reads "Recorded: {action}".
 */
export function entrySentence(entry) {
  const rules = Object.hasOwn(AUDIT_TEXTS, entry?.action) ? AUDIT_TEXTS[entry.action] : null;
  const found = rules?.texts.find(([when]) => applies(when, entry));
  if (!found) return `Recorded: ${textOf(entry?.action)}`;
  return (
    fill(found[1], entry) +
    rules.suffixes
      .filter(([when]) => applies(when, entry))
      .map(([, text]) => fill(text, entry))
      .join('')
  );
}

// --- Verification texts (PROBLEM_TEXTS, UNVERIFIABLE_TEXTS, ANCHOR_TEXTS) ------------------------

const timeKeys = new Set(['time', 'at', 'lineTime']);
/**
 * A verification text with `values` in its {placeholders}: entry numbers grouped after their "#",
 * times through dateTime(), a dotted name read inside an object ({restoredHead.seq}). `whenNull`
 * names what "#{name}" reads when the value is null (log_truncated's head and lastSeq, and
 * head_mismatch's head): "an unknown entry" and "no entry" stand for the entry itself, so an
 * "entry " before them goes too ("it had last written an unknown entry", not "entry an unknown
 * entry").
 */
function verifyText(template, values, whenNull = {}) {
  return template.replace(/(entry )?(#?)\{([A-Za-z. ]+)\}/g, (_, entry = '', hash, name) => {
    const value = name.split('.').reduce((v, key) => own(v, key), values);
    if ((value === null || value === undefined) && Object.hasOwn(whenNull, name))
      return whenNull[name];
    if (timeKeys.has(name)) return `${entry}${Number.isFinite(value) ? dateTime(value) : '—'}`;
    return `${entry}${hash}${textOf(value)}`;
  });
}
/** The first problem found, in words; one this page does not know reads as Uptime Goblin wrote it. */
function problemText(problem) {
  const texts = Object.hasOwn(PROBLEM_TEXTS, problem?.code) ? PROBLEM_TEXTS[problem.code] : null;
  if (!texts)
    return (
      [problem?.message, problem?.consequence]
        .filter(text => typeof text === 'string' && text)
        .join(' ') || `Uptime Goblin found a problem at entry #${textOf(problem?.seq)}.`
    );
  // A head_mismatch has no head when the log holds rows but Uptime Goblin's head is gone: its "#{head}"
  // reads as log_truncated's does ("an unknown entry"), as goblin-admin verify-audit words it.
  const whenNull =
    texts.whenNull ??
    (problem.code === 'head_mismatch' ? PROBLEM_TEXTS.log_truncated.whenNull : {});
  return `${verifyText(texts.message, problem, whenNull)} ${verifyText(texts.consequence, problem, whenNull)}`;
}
function unverifiableText(item) {
  const reason = item?.reason;
  if (reason === 'restore_unchecked') {
    const words = own(UNVERIFIABLE_TEXTS, `restore.${item.cause}`);
    return verifyText(UNVERIFIABLE_TEXTS.restore_unchecked, {
      ...item,
      'restore words': words ? verifyText(words, item) : 'a restore',
    });
  }
  return typeof reason === 'string' &&
    !reason.startsWith('restore.') &&
    Object.hasOwn(UNVERIFIABLE_TEXTS, reason)
    ? verifyText(UNVERIFIABLE_TEXTS[reason], item)
    : 'Some entries could not be checked.';
}
/** The lines of one anchor: a system.upgrade gives one per release that opened the data. */
function anchorLines(anchor) {
  const text = key =>
    Object.hasOwn(ANCHOR_TEXTS, key) ? verifyText(ANCHOR_TEXTS[key], anchor) : null;
  let lines = [];
  if (anchor?.action === 'system.restore')
    lines = [text(`system.restore.${anchor.cause}${anchor.restoredHead ? '' : '.empty'}`)];
  else if (anchor?.action === 'audit.gap') lines = [text(`audit.gap.${anchor.reason}`)];
  else if (anchor?.action === 'key.reset')
    lines = [text(anchor.head ? 'key.reset' : 'key.reset.empty')];
  else if (anchor?.action === 'system.upgrade')
    lines = [
      ...(anchor.markerLost ? [text('system.upgrade.markerLost')] : []),
      ...(Array.isArray(anchor.entries) ? anchor.entries : []).map(entry =>
        verifyText(
          ANCHOR_TEXTS[entry?.to === anchor.release ? 'system.upgrade' : 'system.upgrade.other'],
          entry ?? {}
        )
      ),
    ];
  lines = lines.filter(Boolean);
  // A kind or cause of a later release is still listed: every restore and upgrade must show.
  return lines.length
    ? lines
    : [
        `Entry #${textOf(anchor?.seq)} (${verifyText('{time}', anchor ?? {})}): ${textOf(anchor?.action)}.`,
      ];
}

// --- The page ------------------------------------------------------------------------------------

const day = 86400000;
const periods = Object.freeze([
  ['24h', 'Last 24 hours', day],
  ['7d', 'Last 7 days', 7 * day],
  ['30d', 'Last 30 days', 30 * day],
  ['90d', 'Last 90 days', 90 * day],
  ['all', 'All kept entries', null],
]);
// Each Kind is an `action` list (exact names, or starts ending in a dot); together they reach
// every action of the catalogue, which test/ui.test.mjs checks. "Scripts with a password" is the
// legacy-Basic usage report (spec D31) the System page links to.
const kinds = Object.freeze([
  ['', 'All'],
  ['session.,display.', 'Sign-in and sessions'],
  ['account.,identity.', 'Account and password'],
  ['auth.basic.', 'Scripts with a password'],
  ['auth.step-up,auth.forbidden', 'Refused requests'],
  ['settings.update', 'Workspace settings'],
  ['source.,sources.', 'Sources'],
  ['config.changed-outside', 'Changed outside Uptime Goblin'],
  ['email.test', 'Email test'],
  ['delivery.,channel.,notifications.', 'Notifications'],
  ['signing.', 'Webhook signing key'],
  ['config.export,audit.export', 'Exports'],
  ['system.,data.', 'Uptime Goblin itself'],
  ['key.', 'goblin-admin'],
  ['audit.', 'Audit log'],
]);
const outcomeFilters = Object.freeze([
  ['', 'Any'],
  ['ok', 'Succeeded'],
  ['denied', 'Refused'],
  ['failed', 'Failed'],
  ['conflict', 'Changed elsewhere'],
  ['info', 'Recorded'],
  ['unknown', 'Outcome unknown'],
]);
const actorFilters = Object.freeze([
  ['', 'Anyone'],
  ['user', 'The admin'],
  ['anonymous', 'Not signed in'],
  ['system', 'Uptime Goblin'],
  ['cli', 'goblin-admin'],
]);
const defaultFilters = () => ({ period: '7d', kind: '', outcome: '', actor: '' });
const view = {
  filters: defaultFilters(),
  entries: [],
  nextCursor: null,
  // The query of the first page shown (without its cursor): Load more reads the same entries on.
  query: '',
  problem: null,
  loaded: false,
  unwritten: null,
  retention: null,
  // The entries whose details are open (by seq), kept while the list is drawn again.
  expanded: new Set(),
  // Each read gets a number; an answer to an older one (a filter changed meanwhile) is dropped.
  generation: 0,
  // The number of the first-page read on its way, if any: Load more waits for it.
  reading: 0,
};
// The integrity check on its way: one at a time; a second press joins it.
let verifying = null;
const busy = new Set();
const pageShown = () => page.configurationSection === 'audit' && !!$('#audit-page');

/** The page, drawn at once; loadAudit() then reads the entries. */
export function auditPage() {
  // The System page's link opens the page with Kind "Scripts with a password" (page.auditKind,
  // configure/events.js); otherwise every filter starts at its default.
  const kind = kinds.some(([value]) => value === page.auditKind) ? page.auditKind : '';
  page.auditKind = null;
  Object.assign(view, {
    filters: { ...defaultFilters(), kind },
    entries: [],
    nextCursor: null,
    query: '',
    problem: null,
    loaded: false,
    unwritten: null,
    retention: null,
    expanded: new Set(),
    reading: 0,
  });
  view.generation++;
  const f = view.filters;
  const options = list => list.map(([value, label]) => [value, label]);
  return `<div id="audit-page"><section class="settings-block" aria-labelledby="audit-integrity-title"><div class="settings-block-heading"><h3 id="audit-integrity-title" tabindex="-1">Integrity</h3><p>Each entry is signed together with the one before it, so a change or a removal shows. Uptime Goblin also prints a checkpoint to its log each time it records something; keep that log to detect entries removed from the end (goblin-admin verify-audit --checkpoints). Under Docker, the container's log is kept only up to 10 MB and is lost when the container is recreated: export it first (<a class="text-link" href="#configure/help" data-help="installation">docs/installation.md</a>).</p></div><div class="inline-actions audit-actions"><button class="button" type="button" id="audit-verify">Check integrity</button></div><div id="audit-verify-result" class="audit-verify-result" role="status">${verifying ? verifyHtml({ running: true }) : ''}</div></section><section class="settings-block" aria-labelledby="audit-title"><div class="settings-block-heading"><h3 id="audit-title" tabindex="-1">Entries</h3><p>Newest first. Secrets and passwords are never recorded: a changed password or key shows only as changed.</p></div><div class="audit-toolbar"><button class="button" type="button" id="audit-refresh">Refresh</button></div><div class="history-filters audit-filters">${selectField('audit-period', 'Period', f.period, options(periods))}${selectField('audit-kind', 'Kind', f.kind, kinds)}${selectField('audit-outcome', 'Outcome', f.outcome, outcomeFilters)}${selectField('audit-actor', 'Who', f.actor, actorFilters)}</div><ul id="audit-list" class="audit-list" aria-labelledby="audit-title">${entryItems()}</ul><p id="audit-unwritten" class="settings-info audit-note" hidden></p><p id="audit-retention" class="settings-info audit-note"></p><p id="audit-more-result" class="account-result failed" role="status" hidden></p><button class="button" type="button" id="audit-more" hidden>Load more</button></section><section class="settings-block" aria-labelledby="audit-export-title"><div class="settings-block-heading"><h3 id="audit-export-title" tabindex="-1">Export</h3><p>The entries the filters above select, up to the newest 50,000, with their signatures. Exporting is recorded in the audit log too.</p></div><div class="inline-actions audit-actions"><button class="button" type="button" id="audit-export-csv">Export CSV</button><button class="button" type="button" id="audit-export-ndjson">Export NDJSON</button></div></section></div>`;
}

/** Reads the first page of entries (the page opened, Refresh, a filter, or signed in again). */
export async function loadAudit() {
  if (!pageShown()) return;
  await loadEntries();
}

/** The list's query for the filters chosen: `from` is counted back from now at each read. */
function filterQuery() {
  const f = view.filters,
    query = new URLSearchParams(),
    span = periods.find(([key]) => key === f.period)?.[2];
  if (span) query.set('from', String(Math.max(0, Math.floor(Date.now() - span))));
  if (f.kind) query.set('action', f.kind);
  if (f.outcome) query.set('outcome', f.outcome);
  if (f.actor) query.set('actor', f.actor);
  return query;
}
/**
 * The first page (`more`: the next one, appended). The rows are de-duplicated by seq, as one
 * written between two reads moves the next page on by one. A failed Load more keeps the rows and
 * the cursor and says so beside the button; a failed first page says why in the list. Resolves to
 * the entries added (an answer dropped as stale adds none).
 */
async function loadEntries({ more = false } = {}) {
  const generation = ++view.generation;
  const query = more ? new URLSearchParams(view.query) : filterQuery();
  if (more) query.set('cursor', view.nextCursor);
  else view.reading = generation;
  let answer = null,
    problem = null;
  try {
    answer = await api(`/api/audit?${query}`);
    if (!Array.isArray(answer?.entries))
      throw new Error('Uptime Goblin sent an unexpected list of audit entries.');
  } catch (error) {
    problem = error;
  }
  if (view.reading === generation) view.reading = 0;
  if (generation !== view.generation || !pageShown()) return [];
  let added = [];
  if (problem && more) view.problem = problem;
  else if (problem)
    Object.assign(view, {
      entries: [],
      nextCursor: null,
      problem,
      loaded: true,
      unwritten: null,
      retention: null,
    });
  else {
    const known = new Set(more ? view.entries.map(entry => entry.seq) : []);
    added = answer.entries.filter(entry => {
      if (!entry || typeof entry !== 'object' || known.has(entry.seq)) return false;
      known.add(entry.seq);
      return true;
    });
    if (!more) {
      // Details stay open for the entries still listed.
      const listed = new Set(added.map(entry => entryKey(entry)));
      view.expanded = new Set([...view.expanded].filter(key => listed.has(key)));
    }
    Object.assign(view, {
      entries: more ? [...view.entries, ...added] : added,
      nextCursor:
        typeof answer.nextCursor === 'string' && answer.nextCursor ? answer.nextCursor : null,
      query: more ? view.query : String(query),
      problem: null,
      loaded: true,
      unwritten: answer.unwritten ?? null,
      retention: answer.retention ?? null,
    });
  }
  renderEntries();
  return added;
}

/** What a read that failed says: Uptime Goblin's own words, or that it did not answer. */
const readFailure = error =>
  error?.status === undefined ? unavailableText(error, 'The audit log') : error.message;
const listMessage = text => `<li class="audit-empty">${esc(text)}</li>`;
function entryItems() {
  if (view.problem && !view.entries.length) return listMessage(readFailure(view.problem));
  if (!view.loaded) return listMessage('Reading the audit log…');
  if (!view.entries.length) {
    // "Yet" only when the log holds nothing at all: a log whose entries are older than the
    // period chosen has entries, none of which matches.
    const rows = view.retention?.rows;
    const empty =
      rows === 0 ||
      (!Number.isFinite(rows) &&
        view.filters.period === 'all' &&
        !view.filters.kind &&
        !view.filters.outcome &&
        !view.filters.actor);
    return listMessage(empty ? 'No entries yet.' : 'No entry matches these filters.');
  }
  return view.entries.map(entryItem).join('');
}
function renderEntries() {
  patchHtml($('#audit-list'), entryItems());
  const say = (selector, text) => {
    const element = $(selector);
    element.hidden = !text;
    if (element.textContent !== text) element.textContent = text;
  };
  say('#audit-unwritten', unwrittenText(view.unwritten));
  say('#audit-retention', retentionText(view.retention));
  // A Load more that failed keeps the rows shown and its cursor; it says so beside the button, in
  // a status region, so the older entries are never silently missing (delivery A16).
  say(
    '#audit-more-result',
    view.problem && view.entries.length
      ? `${readFailure(view.problem)} Older entries were not read: press Load more to try again.`
      : ''
  );
  $('#audit-more').hidden = !view.nextCursor;
}
/** Spec D6: entries this Uptime Goblin could not write since it started went to its log instead. */
function unwrittenText(unwritten) {
  const count = Number(unwritten?.count);
  if (!unwritten || !Number.isFinite(count) || count < 1) return '';
  return `Uptime Goblin could not write ${plural(count, 'audit entry', 'audit entries')} since ${dateTime(unwritten.since)}. Uptime Goblin's log holds them, in lines that start with {"orbit":"audit.unwritten"}; a change among them shows "Outcome unknown".`;
}
function retentionText(retention) {
  if (!retention || !Number.isFinite(retention.days)) return '';
  const kept = `Entries are kept for ${plural(retention.days, 'day')}, at most ${grouped(retention.maxRows ?? 250000)}.`;
  return retention.oldest
    ? `${kept} The oldest kept entry is from ${dateTime(retention.oldest.time)}.`
    : `${kept} There are no entries yet.`;
}

// One entry.
const entryKey = entry => String(entry?.seq ?? '').replace(/[^0-9A-Za-z_-]/g, '');
const fact = (label, value) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`;
/** Who acted, as the page names them (spec §8.2). */
function who(actor) {
  const name = actor?.name;
  switch (actor?.type) {
    case 'user':
      // Entries of earlier 1.5 builds' passwordless local preview.
      if (actor.via === 'local') return 'Local preview';
      if (actor.via === 'basic') return `${name ?? 'admin'} (script with a password)`;
      if (actor.via === 'kiosk') return 'A wall display (signed in with a display code)';
      return `${name ?? 'admin'} (signed in)`;
    case 'anonymous':
      return 'Not signed in';
    case 'system':
      return 'Uptime Goblin';
    case 'cli':
      return `goblin-admin as ${String(name ?? 'an unknown user').replace(/^cli:/, '')}`;
    default:
      return textOf(name ?? actor?.type);
  }
}
const fromText = actor =>
  [actor?.client, actor?.userAgent ? deviceName(actor.userAgent) : null].filter(Boolean).join(', ');
function targetText(target) {
  if (!target) return '';
  const { type, id, name } = target;
  return [type, name ?? id, name && id && name !== id ? `(${id})` : null]
    .filter(part => part !== null && part !== undefined && part !== '')
    .join(' ');
}
const statusText = status => (Number.isFinite(status) ? ` (HTTP ${status})` : '');
/** A summary row's count: how many, over which time, and from how many clients. */
function countText(entry) {
  const detail = entry.detail;
  if (!isSummary(entry)) return Number(entry.count) > 1 ? plural(entry.count, 'time') : '';
  const span = `${plural(Number(entry.count), 'time')} between ${dateTime(own(detail, 'from'))} and ${dateTime(own(detail, 'to'))}`;
  const clients = Number(own(detail, 'clients'));
  if (own(detail, 'more') === true) return `${span}, from more than 1,000 different clients`;
  if (clients === 1) return `${span}, from 1 client`;
  return clients > 1 ? `${span}, from ${grouped(clients)} different clients` : span;
}
function entryItem(entry) {
  const key = entryKey(entry),
    base = `audit-${key}`,
    open = view.expanded.has(key),
    from = fromText(entry.actor),
    target = targetText(entry.target),
    count = countText(entry),
    time = Number.isFinite(entry.time) && Math.abs(entry.time) <= 8.64e15 ? entry.time : null;
  const facts = [
    fact('Who', who(entry.actor)),
    ...(from ? [fact('From', from)] : []),
    ...(entry.requestId ? [fact('Request', entry.requestId)] : []),
    ...(target ? [fact('Target', target)] : []),
    fact('Outcome', `${outcomeWord(entry.outcome)}${statusText(entry.status)}`),
    ...(count ? [fact('Count', count)] : []),
  ].join('');
  return `<li class="audit-entry" data-id="${esc(key)}" data-outcome="${esc(entry.outcome)}" tabindex="-1" aria-labelledby="${base}-head"><p class="audit-entry-head" id="${base}-head">${time === null ? '<span class="audit-time">—</span>' : `<time class="audit-time" datetime="${new Date(time).toISOString()}">${esc(dateTime(time))}</time>`} <strong class="audit-summary">${esc(entrySentence(entry))}</strong> <span class="audit-outcome" data-outcome="${esc(entry.outcome)}">${esc(outcomeWord(entry.outcome))}</span></p><dl class="system-facts audit-facts">${facts}</dl><button class="quiet-button audit-toggle" type="button" id="${base}-toggle" data-audit-details="${esc(key)}" aria-expanded="${open}" aria-controls="${base}-details">${open ? 'Hide details' : 'Show details'}</button><div class="audit-details" id="${base}-details"${open ? '' : ' hidden'}>${detailsHtml(entry)}</div></li>`;
}

// An entry's details: what changed, the clients of a summary, and every other fact it holds.
const diffValue = value =>
  value === null || value === undefined
    ? '(none)'
    : value === ''
      ? '(empty)'
      : typeof value === 'string'
        ? value
        : JSON.stringify(value);
function diffHtml(detail) {
  const diff = own(detail, 'diff');
  const lines = diff
    .filter(change => change && typeof change === 'object')
    .map(change =>
      // A secret shows only whether it was set, changed or cleared (spec D11).
      Object.hasOwn(change, 'change')
        ? `${textOf(change.path)}: ${textOf(change.change)}`
        : `${textOf(change.path)}: ${diffValue(change.from)} → ${diffValue(change.to)}`
    );
  const changes = Number(own(detail, 'changes'));
  const note =
    own(detail, 'truncated') === true
      ? `Only the first ${grouped(lines.length)} of ${Number.isFinite(changes) ? grouped(changes) : 'more'} changes are shown.`
      : '';
  return `<p class="audit-details-label">What changed</p>${lines.length ? `<ul class="audit-diff">${lines.map(line => `<li>${esc(line)}</li>`).join('')}</ul>` : '<p class="audit-diff-note">Nothing changed.</p>'}${note ? `<p class="audit-diff-note">${esc(note)}</p>` : ''}`;
}
const labels = Object.freeze({
  code: 'Reason',
  login: 'Login name',
  ifMatch: 'Based on the version shown (If-Match)',
  configRevision: 'Configuration revision',
  // Shown in s, m, h or d (detailValue), never in milliseconds.
  uptimeMs: 'Uptime',
});
const labelOf = key =>
  (Object.hasOwn(labels, key) ? labels[key] : null) ??
  String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/^./, first => first.toUpperCase());
function detailValue(key, value) {
  if (key === 'code' && typeof value === 'string') return `${codeWords(value)} (${value})`;
  // Only the class of a login name is ever stored (spec D9).
  if (key === 'login')
    return value === 'admin' ? 'admin' : value === 'other' ? 'another name' : textOf(value);
  if ((key === 'at' || /At$/.test(key)) && Number.isFinite(value)) return dateTime(value);
  if (key === 'uptimeMs' && Number.isFinite(value)) return format(value / 1000, 'seconds');
  if ((key === 'head' || key === 'restoredHead') && value && typeof value === 'object')
    return `entry #${textOf(value.seq)}`;
  if (key === 'entries' && Array.isArray(value))
    return value
      .map(e => `${textOf(e?.to)}${Number.isFinite(e?.at) ? ` on ${dateTime(e.at)}` : ''}`)
      .join(', ');
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return textOf(value);
}
const summaryKeys = new Set(['codes', 'clients', 'more', 'sample', 'from', 'to']);
const diffKeys = new Set(['diff', 'truncated', 'changes']);
function detailsHtml(entry) {
  const detail = entry.detail && typeof entry.detail === 'object' ? entry.detail : {},
    summary = isSummary(entry),
    sample = own(detail, 'sample');
  const facts = [
    fact('Entry', `#${textOf(entry.seq)}`),
    ...(entry.actor?.sessionId ? [fact('Session', entry.actor.sessionId)] : []),
    ...(entry.actor?.userAgent ? [fact('Browser', entry.actor.userAgent)] : []),
    ...(entry.ref !== null && entry.ref !== undefined
      ? [fact('Attempt', `entry #${textOf(entry.ref)}`)]
      : []),
    ...(entry.result && typeof entry.result === 'object'
      ? [
          fact(
            'Result',
            `${outcomeWord(entry.result.outcome)}${statusText(entry.result.status)}, entry #${textOf(entry.result.seq)}, ${dateTime(entry.result.time)}`
          ),
        ]
      : []),
    ...(Number.isFinite(entry.configRevision)
      ? [fact('Configuration revision', grouped(entry.configRevision))]
      : []),
    ...Object.entries(detail)
      // An empty list names nothing: a start whose security settings did not change stores
      // `securityChanged: []`, which is not shown as an empty fact.
      .filter(
        ([key, value]) =>
          !diffKeys.has(key) &&
          !(summary && summaryKeys.has(key)) &&
          !(Array.isArray(value) && value.length === 0)
      )
      .map(([key, value]) => fact(labelOf(key), detailValue(key, value))),
  ].join('');
  return `${Array.isArray(own(detail, 'diff')) ? diffHtml(detail) : ''}${summary && Array.isArray(sample) && sample.length ? `<p class="audit-details-label">Clients (up to 10 of them)</p><ul class="audit-sample">${sample.map(client => `<li>${esc(textOf(client))}</li>`).join('')}</ul>` : ''}<dl class="system-facts audit-facts">${facts}</dl>`;
}
function toggleDetails(button) {
  const key = button.dataset.auditDetails;
  if (view.expanded.has(key)) view.expanded.delete(key);
  else view.expanded.add(key);
  const open = view.expanded.has(key);
  button.setAttribute('aria-expanded', String(open));
  button.textContent = open ? 'Hide details' : 'Show details';
  document.getElementById(button.getAttribute('aria-controls'))?.toggleAttribute('hidden', !open);
}

// --- Check integrity --------------------------------------------------------------------------

const list = lines =>
  lines.length ? `<ul>${lines.map(line => `<li>${esc(line)}</li>`).join('')}</ul>` : '';
function verifyHtml({ running = false, result = null, problem = null }) {
  if (running) return `<p>${esc('Checking the audit log… A large log can take a minute.')}</p>`;
  if (problem)
    return `<p class="field-error">${esc(
      problem.timeout
        ? 'Uptime Goblin did not finish the check in time. Try again; a check of a very large log can take longer than the page waits.'
        : readFailure(problem)
    )}</p>`;
  if (!result || typeof result !== 'object') return '';
  const anchors = (Array.isArray(result.anchors) ? result.anchors : []).flatMap(anchorLines);
  const rows = result.rows ?? {};
  let head;
  if (result.result === 'broken')
    head = `The audit log was changed. ${problemText(result.problem)} Compare it with Uptime Goblin's log using goblin-admin verify-audit --checkpoints.`;
  else if (result.result === 'incomplete')
    return `<p>${esc('Nothing was found changed, but not everything could be checked:')}</p>${list((Array.isArray(result.unverifiable) ? result.unverifiable : []).map(unverifiableText))}${list(anchors)}`;
  else if (result.result === 'intact' && (!rows.checked || !rows.first))
    head = 'The audit log is empty: there is nothing to check yet.';
  else if (result.result === 'intact')
    head = `The audit log is intact: ${plural(rows.checked, 'entry', 'entries')} checked, from #${textOf(rows.first.seq)} (${dateTime(rows.first.time)}) to #${textOf(rows.last?.seq)} (${dateTime(rows.last?.time)}).`;
  else
    head = `Uptime Goblin answered the check with a result this page does not know (${textOf(result.result)}).`;
  return `<p${result.result === 'broken' ? ' class="field-error"' : ''}>${esc(head)}</p>${list(anchors)}`;
}
function showVerify(state) {
  const target = $('#audit-verify-result');
  if (target && pageShown()) patchHtml(target, verifyHtml(state));
}
/**
 * Check integrity. The button stays enabled and keeps the focus (a sign-in dialog the request
 * opens gives it back); a second press while a check runs joins it. A large log takes a while,
 * so the request waits as long as a connection test (150 s, at least twice the measured check of
 * 250,000 entries, spec §9.3).
 */
async function checkIntegrity(button) {
  const release = holdFocus(button);
  if (!verifying) {
    showVerify({ running: true });
    verifying = api('/api/audit/verify', { timeout: testTimeoutMs })
      .then(
        result => ({ result }),
        problem => ({ problem })
      )
      .finally(() => (verifying = null));
  }
  const outcome = await verifying;
  showVerify(outcome);
  release();
}

// --- Export -------------------------------------------------------------------------------------

/**
 * Downloads what the filters select, as Uptime Goblin wrote it: the bytes, never text, so the CSV keeps
 * its byte order mark (spec §8.3). Uptime Goblin says how many entries it holds and whether older ones
 * were left out; for none, nothing is downloaded.
 */
async function exportEntries(button, formatName) {
  if (busy.has(button.id)) return;
  busy.add(button.id);
  const release = holdFocus(button);
  button.disabled = true;
  try {
    const query = filterQuery();
    query.set('format', formatName);
    const file = await api(`/api/audit/export?${query}`, { as: 'bytes', timeout: testTimeoutMs });
    const counted = file.headers.get('X-Goblin-Export-Rows'),
      rows = counted === null ? null : Number(counted),
      more = file.headers.get('X-Goblin-Export-More') === 'true';
    if (rows === 0) {
      toast('There are no entries to export for these filters.');
      return;
    }
    downloadFile(file.filename || `uptime-goblin-audit.${formatName}`, file.bytes, file.type);
    toast(
      rows === null || !Number.isFinite(rows)
        ? 'Exported the audit entries.'
        : more
          ? // Every Period counts back from now, so a shorter one only exports fewer of the
            // newest entries: the older ones need a narrower Kind, Outcome or Who, or `to`.
            `Exported the newest ${plural(rows, 'entry', 'entries')}; older ones were left out. Narrow Kind, Outcome or Who to reach further back, or export them from a script with to= (docs/architecture.md).`
          : `Exported ${plural(rows, 'entry', 'entries')}.`
    );
  } catch (error) {
    toast(readFailure(error));
  } finally {
    button.disabled = false;
    busy.delete(button.id);
    release();
  }
}

/**
 * Registers this module’s event handlers. main.js calls it once, after the other configuration
 * pages' handlers.
 */
export function install() {
  document.addEventListener('click', async e => {
    const toggle = e.target.closest('[data-audit-details]');
    if (toggle) {
      toggleDetails(toggle);
      return;
    }
    const verify = e.target.closest('#audit-verify');
    if (verify) {
      await checkIntegrity(verify);
      return;
    }
    // Refresh keeps its focus: it stays enabled, and the list is patched below it.
    if (e.target.closest('#audit-refresh')) {
      await loadEntries();
      return;
    }
    const exportButton = e.target.closest('#audit-export-csv, #audit-export-ndjson');
    if (exportButton) {
      await exportEntries(exportButton, exportButton.id === 'audit-export-csv' ? 'csv' : 'ndjson');
      return;
    }
    const more = e.target.closest('#audit-more');
    // A first page on its way (a filter changed) replaces the list: Load more waits for it.
    if (more && !busy.has('more') && !view.reading) {
      busy.add('more');
      const release = holdFocus(more);
      more.disabled = true;
      let added = [];
      try {
        added = await loadEntries({ more: true });
      } finally {
        more.disabled = false;
        busy.delete('more');
        release();
      }
      // The last page: Load more goes, and the focus moves to the first entry it added, or, when
      // it added none (older entries were pruned meanwhile), to the last entry, else to the
      // "Entries" heading: never to <body> (delivery A13).
      if (
        more.hidden &&
        (document.activeElement === document.body || !focusable(document.activeElement))
      )
        (added.length
          ? $(`#audit-list > [data-id="${CSS.escape(entryKey(added[0]))}"]`)
          : ($('#audit-list > li.audit-entry:last-child') ?? $('#audit-title'))
        )?.focus({ preventScroll: true });
    }
  });
  document.addEventListener('change', async e => {
    if (!['audit-period', 'audit-kind', 'audit-outcome', 'audit-actor'].includes(e.target.id))
      return;
    view.filters = {
      period: $('#audit-period').value,
      kind: $('#audit-kind').value,
      outcome: $('#audit-outcome').value,
      actor: $('#audit-actor').value,
    };
    await loadEntries();
  });
}
