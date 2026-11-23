// The audit catalogue (audit spec §5.8, Phase 0; frozen data): every action Uptime Goblin records, how
// it is recorded, its target, outcomes and detail keys; the texts the CLI, the API and the web
// app show for rows and verification results (§7.1, §8.2); the limits of §4.1; and the event
// type with eventFrom(). The writer (lane O) validates every event against ACTIONS before it
// writes anything (§4.1), so a detail key not listed here is a defect, never a stored value.
//
// public/modules/configure/audit.js keeps a copy of AUDIT_TEXTS, CODE_WORDS, PROBLEM_TEXTS,
// UNVERIFIABLE_TEXTS and ANCHOR_TEXTS (the web app cannot import lib/), which test/ui.test.mjs
// compares with these, so all five are plain data. This module imports nothing from lib/cli
// (auditTime() repeats formatTime's format instead).

// ---------------------------------------------------------------------------------------------
// Value domains (§3.1, D18, D25).

/** Row outcomes. `attempt` is an attempt row's own outcome; "unknown" is only ever shown. */
export const OUTCOMES = Object.freeze(['attempt', 'ok', 'denied', 'failed', 'conflict', 'info']);
/** actor_type (D25). */
export const ACTOR_TYPES = Object.freeze(['user', 'anonymous', 'system', 'cli']);
/**
 * via (§3.1). 'local' is the passwordless local preview of earlier 1.5 builds: Uptime Goblin no longer
 * starts without a password, so none is recorded now, but the rows those builds made still read.
 */
export const VIAS = Object.freeze(['session', 'basic', 'local', 'cli', 'system', 'kiosk']);
/** route.audit, a closed list the router validates (D18). */
export const AUDIT_KINDS = Object.freeze([
  'none',
  'identity',
  'config',
  'delivery',
  'channel',
  'secret',
  'operation',
  'export',
]);
/** The only `meta` keys an event may carry (§3.4); the writer applies them in the row's unit. */
export const META_KEYS = Object.freeze([
  'config_revision_seen',
  'audit_config_public',
  'audit_config_secrets',
  'audit_release_marker',
  'audit_snapshot_seen',
  'audit_restore_seen',
  'audit_password_changed_at',
  'audit_security_seen',
]);

// ---------------------------------------------------------------------------------------------
// Limits (§4.1).

export const DETAIL_MAX_BYTES = 16384;
export const VALUE_MAX_CHARS = 200;
export const LIST_MAX = 500;
export const LIST_DEFAULT = 50;
export const EXPORT_MAX_ROWS = 50000;
export const EXPORT_MAX_BYTES = 16 * 1024 * 1024;
export const EXPORT_UNIT_ROWS = 2000;
export const VERIFY_CHUNK = 1000;
export const AGG_CLIENTS_TRACKED = 1000;
export const AGG_SAMPLE = 10;
export const SNAPSHOT_ROWS_MAX = 20;
export const MAINTAIN_RUN_MS = 30000;
export const CLOCK_STEP_MS = 3600000;
// 90 days is the maintainer's decision (OD7, D14), not the roadmap's 400: the log holds client addresses,
// browser names and session ids, so it keeps them no longer than that unless he sets more.
export const RETENTION_DEFAULT_DAYS = 90;
export const RETENTION_MIN_DAYS = 30;
export const RETENTION_MAX_DAYS = 3650;
export const MAX_ROWS = 250000;
export const CLOSE_MS = 2000;

// ---------------------------------------------------------------------------------------------
// The catalogue (§5.8).
//
// ACTIONS[action] = {modes, targetType, outcomes, detail, inbox}:
// - modes: how its rows are written: U in-unit, P attempt/result, S single before the answer,
//   O one row after (operation), A aggregated, Y system (best effort), D direct by goblin-admin
//   under the key, `writer` written by the writer itself (an anchor or a gap);
// - targetType: the target types its rows carry (two for an action on two kinds of rows);
// - outcomes and detail: every outcome and detail key its rows may hold. An action on two rows
//   (session.login, account.password.changed) has one entry with the union of both;
// - inbox: whether identity and the start may record it before a keyring exists (D8); no other
//   action is ever taken from the inbox.
// Every detail is secret-free: ids, counts, codes, booleans, times, names the admin gave, snapshot ids
// and reasons, release names, and diffs per D11; configuration values appear only inside `diff`.

const action = (modes, targetType, outcomes, detail = [], inbox = false) =>
  Object.freeze({
    modes: Object.freeze(modes),
    targetType: Object.freeze(targetType),
    outcomes: Object.freeze(outcomes),
    detail: Object.freeze(detail),
    inbox,
  });
const attemptOutcomes = ['attempt', 'ok', 'conflict', 'failed', 'denied'];
const aggregateDetail = ['codes', 'clients', 'more', 'sample', 'from', 'to'];
const configDetail = ['ifMatch', 'diff', 'truncated', 'changes'];

export const ACTIONS = Object.freeze({
  'session.login': action(
    ['U', 'A'],
    ['session', 'account'],
    ['ok', 'failed', 'denied'],
    ['persistent', 'transport', 'ended', 'kind', 'display', 'code', 'login', ...aggregateDetail]
  ),
  'session.logout': action(['U', 'Y'], ['session'], ['ok', 'failed'], ['cause', 'code']),
  'session.revoked': action(['U'], ['session'], ['ok', 'info'], ['cause', 'count'], true),
  'session.revoked-others': action(['U'], ['account'], ['ok'], ['count', 'kept']),
  'session.revoked-restore': action(
    ['U'],
    ['account'],
    ['info'],
    ['cause', 'snapshot', 'displayCodes'],
    true
  ),
  'account.password.changed': action(
    ['U', 'A'],
    ['account'],
    ['ok', 'failed', 'denied'],
    ['revokedOtherSessions', 'newSessionId', 'code', ...aggregateDetail]
  ),
  'account.password.changed-outside': action(['U', 'Y'], ['account'], ['info'], ['source'], true),
  'account.bootstrap': action(['U'], ['account'], ['info'], ['source'], true),
  'account.claimed': action(['U'], ['account'], ['info'], [], true),
  'identity.mirror.failed': action(['Y'], ['file'], ['failed'], ['code'], true),
  // Wall display codes (B6 design §12): created by goblin-admin in the unit of the code's row;
  // cancelled by goblin-admin, by a sign-in refused for its transport (anonymous), by a password
  // change, or recorded late by Uptime Goblin for a goblin-admin cancel that had no key (`late`).
  'display.code.created': action(['D'], ['display'], ['ok'], ['expiresAt']),
  'display.code.cancelled': action(
    ['D', 'U'],
    ['display', 'account'],
    ['ok', 'info'],
    ['cause', 'count', 'late']
  ),
  'auth.basic.failed': action(
    ['A'],
    ['account'],
    ['failed', 'denied'],
    ['code', 'login', ...aggregateDetail]
  ),
  'auth.step-up': action(['A'], ['account'], ['denied'], ['code', ...aggregateDetail]),
  'auth.forbidden': action(['A'], ['account'], ['denied'], ['code', ...aggregateDetail]),
  'auth.basic.used': action(['A'], ['account'], ['ok'], aggregateDetail),
  'settings.update': action(['P'], ['settings'], attemptOutcomes, [...configDetail, 'code']),
  'source.create': action(['P'], ['source'], attemptOutcomes, [...configDetail, 'code']),
  'source.update': action(['P'], ['source'], attemptOutcomes, [
    ...configDetail,
    'credentialsCleared',
    'code',
  ]),
  'source.delete': action(['P'], ['source'], attemptOutcomes, [
    ...configDetail,
    'historyDeleted',
    'code',
  ]),
  'source.test': action(
    ['O'],
    ['source'],
    ['ok', 'failed', 'denied'],
    ['type', 'savedCredentials', 'result', 'credentialsCleared', 'code']
  ),
  'email.test': action(
    ['O'],
    ['channel'],
    ['ok', 'failed', 'denied', 'conflict'],
    ['accepted', 'code']
  ),
  'sources.refresh': action(['O'], ['sources'], ['ok', 'failed', 'denied'], ['code']),
  // An Uptime Kuma import (lib/http/routes/import.mjs): one configuration change, with how many
  // monitors the plan added, changed and skipped.
  'sources.import': action(['P'], ['sources'], attemptOutcomes, [
    ...configDetail,
    'added',
    'changed',
    'skipped',
    'code',
  ]),
  'delivery.retry': action(
    ['P'],
    ['delivery'],
    ['attempt', 'ok', 'denied', 'failed'],
    ['retried', 'code']
  ),
  'channel.resume': action(
    ['P'],
    ['channel'],
    ['attempt', 'ok', 'denied', 'failed'],
    ['released', 'code']
  ),
  // The ntfy and Gotify settings (in the settings store's unit, with the change: its diff gives
  // tokens, passwords and the ntfy topic only as set, changed or cleared) and their test.
  'channel.settings': action(['U'], ['channel'], ['ok'], ['diff']),
  'channel.test': action(
    ['O'],
    ['channel'],
    ['ok', 'failed', 'denied', 'conflict'],
    ['accepted', 'code']
  ),
  // Recorded by the signing-secret reveal of pre-release builds, which 1.5's public keys replaced
  // (2026-11-12): no route records it now, and its rows still read.
  'signing.reveal': action(
    ['P'],
    ['secret'],
    ['attempt', 'ok', 'denied', 'failed'],
    ['shown', 'code']
  ),
  'signing.rotate': action(['U'], ['secret'], ['ok'], ['diff']),
  'signing.created': action(['Y'], ['secret'], ['info'], ['replaced']),
  'channel.paused': action(['Y'], ['channel'], ['info'], ['reason', 'transient']),
  'channel.working': action(['Y'], ['channel'], ['info']),
  'notifications.unsaved': action(['Y'], ['outbox'], ['info']),
  'notifications.saved': action(['Y'], ['outbox'], ['info']),
  'config.export': action(['S'], ['config'], ['ok'], ['sources', 'bytes']),
  'audit.export': action(['S'], ['audit'], ['ok'], ['format', 'rows', 'more', 'filters']),
  'config.changed-outside': action(
    ['Y'],
    ['config'],
    ['info'],
    ['from', 'to', 'diff', 'truncated', 'changes', 'repaired']
  ),
  'system.start': action(
    ['Y'],
    ['orbit'],
    ['info'],
    ['version', 'build', 'first', 'cleanStop', 'configRevision', 'security', 'securityChanged']
  ),
  'system.stop': action(['Y'], ['orbit'], ['info'], ['uptimeMs']),
  'system.upgrade': action(['Y'], ['orbit'], ['info'], ['release', 'entries', 'markerLost']),
  'system.restore': action(
    ['U', 'writer'],
    ['orbit'],
    ['info'],
    ['cause', 'snapshot', 'at', 'restoredHead'],
    true
  ),
  'data.snapshot': action(['Y'], ['snapshot'], ['info'], ['reason', 'createdAt', 'more']),
  'audit.gap': action(['writer'], ['audit'], ['info'], ['reason', 'head', 'lastSeq', 'count']),
  'audit.pruned': action(['Y'], ['audit'], ['info'], ['through', 'deleted', 'reason']),
  'key.rewrap': action(['D'], ['keyring'], ['ok', 'failed'], ['rewrapped', 'code']),
  'key.rotate': action(
    ['D'],
    ['keyring'],
    ['ok', 'failed'],
    ['purposes', 'retired', 'active', 'code']
  ),
  'key.reset': action(['D'], ['keyring'], ['ok'], ['lostKeyIds', 'head']),
  'key.remove-data-copy': action(['D'], ['file'], ['ok', 'failed'], ['unused', 'code']),
});

// ---------------------------------------------------------------------------------------------
// Row texts (§8.2).
//
// AUDIT_TEXTS[action] = {texts: [[when, text], …], suffixes: [[when, text], …]}: the summary
// sentence of a row. The first `texts` entry whose `when` holds gives the sentence; then every
// `suffixes` entry whose `when` holds is appended. `when` is a space-separated list of terms,
// all of which must hold:
//   ok, denied, … (several joined by |)  the row's outcome as listed: ok, denied, failed,
//                 conflict or info, or for an attempt row `attempt` (in progress) or `unknown`
//   summary       an aggregated summary row (its detail has `codes`)
//   field=value   detail[field] is that value (compared as text)
//   field         detail[field] is set: true, a non-empty text or list, or a number other than 0
//   !field        detail[field] is not set
//   own           system.upgrade: detail.entries is one entry, whose `to` is detail.release
//   *             always
// Placeholders: {name} the target's name, else its id; {id} the target's id; {code} the words of
// detail.code (CODE_WORDS, else "Uptime Goblin error {code}"); {codes} a summary's detail.codes as
// "{words} ({n})" joined by ", "; {count} detail.count, else the row's count; {n} the number of
// detail.entries and {list} their `to` joined by ", "; {names} detail.securityChanged joined by
// ", "; {command} the action with its first dot as a space ("key rotate"); any other {field} that
// detail field. An action not here, or a row no entry matches, reads "Recorded: {action}".

const texts = (list, suffixes = []) =>
  Object.freeze({
    texts: Object.freeze(list.map(pair => Object.freeze(pair))),
    suffixes: Object.freeze(suffixes.map(pair => Object.freeze(pair))),
  });
// An attempt/result action (P): its success text, and the subject its other outcomes share
// (only those of its outcomes: Retry, Resume and the reveal are never `conflict`).
const attempted = (action, ok, subject) =>
  texts(
    [
      ['ok', ok],
      ['attempt', `${subject}: in progress`],
      ['unknown', `${subject}: outcome unknown`],
      ['conflict', `${subject}: refused, changed elsewhere first`],
      ['denied', `${subject}: refused ({code})`],
      ['failed code', `${subject}: failed ({code})`],
      ['failed', `${subject}: failed`],
    ].filter(
      ([when]) =>
        when.startsWith('unknown') || ACTIONS[action].outcomes.includes(when.split(' ')[0])
    )
  );
const keyCommand = ok =>
  texts([
    ['ok', ok],
    ['failed', 'goblin-admin {command} failed ({code})'],
  ]);

export const AUDIT_TEXTS = Object.freeze({
  'session.login': texts([
    ['ok kind=kiosk', 'Wall display {display} signed in with a display code'],
    ['ok', 'Signed in'],
    ['summary', '{count} more refused sign-ins: {codes}'],
    ['failed|denied', 'Sign-in refused: {code}'],
  ]),
  'session.logout': texts([
    ['ok cause=signout', 'Signed out'],
    ['ok cause=presented', 'Signed out a session this browser presented'],
    ['ok cause=ended', 'Signed out a session that had already ended elsewhere'],
    ['failed', 'Sign-out could not be saved: {code}'],
  ]),
  'session.revoked': texts([
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
  ]),
  'session.revoked-others': texts([['*', 'Signed out {count} other devices']]),
  'session.revoked-restore': texts([
    [
      'cause=credentials_anchor',
      'Removed {displayCodes} display credentials: the credential restore boundary changed',
    ],
    ['cause=snapshot', 'Signed everyone out: the data was restored from snapshot {snapshot}'],
    [
      'cause=control_file',
      'Signed everyone out: control.sqlite was restored from a backup, copied or moved',
    ],
  ]),
  'account.password.changed': texts([
    ['ok', 'Changed the admin password'],
    ['summary', '{count} more refused password changes: {codes}'],
    ['failed|denied', 'Password change refused: {code}'],
  ]),
  'account.password.changed-outside': texts([
    ['source=auth.json', 'The admin password was changed outside Uptime Goblin (auth.json)'],
    ['source=env', 'The admin password was changed outside Uptime Goblin (GOBLIN_PASSWORD)'],
    [
      'source=control.sqlite',
      'The admin password was changed by an earlier Uptime Goblin 1.5 build',
    ],
  ]),
  'account.bootstrap': texts([
    ['source=auth.json', 'Set up the admin account with the password from auth.json'],
    ['source=env', 'Set up the admin account with GOBLIN_PASSWORD'],
    // Only in rows of earlier 1.5 builds: Uptime Goblin no longer starts without a password.
    ['source=none', 'Set up the admin account without a password (local preview)'],
  ]),
  'account.claimed': texts([
    ['*', 'Kept the admin account carried in this database and wrote it to auth.json'],
  ]),
  'identity.mirror.failed': texts([['*', 'Could not update auth.json: {code}']]),
  'display.code.created': texts([['*', 'Created a display code for wall display {name}']]),
  'display.code.cancelled': texts(
    [
      ['cause=plain_http', 'Cancelled display code {name}: it was sent over plain HTTP'],
      [
        'cause=password_change',
        'Cancelled {count} waiting display codes: the admin password changed',
      ],
      ['count', 'Cancelled {count} waiting display codes'],
      ['*', 'Cancelled display code {name}'],
    ],
    [['late', ' (recorded when Uptime Goblin next ran)']]
  ),
  'auth.basic.failed': texts([
    ['summary', '{count} more refused script sign-ins: {codes}'],
    ['*', 'Script sign-in refused: {code}'],
  ]),
  'auth.step-up': texts([
    ['summary', '{count} more requests refused by step-up or lockdown: {codes}'],
    ['*', 'Request refused by step-up or lockdown: {code}'],
  ]),
  'auth.forbidden': texts([
    ['summary', '{count} more requests refused by authorization: {codes}'],
    ['*', 'Request refused by authorization: {code}'],
  ]),
  'auth.basic.used': texts([
    ['summary', 'Scripts signed in with the password {count} more times'],
    ['*', 'A script signed in with the password'],
  ]),
  'settings.update': attempted(
    'settings.update',
    'Changed workspace settings',
    'Change of workspace settings'
  ),
  'source.create': attempted('source.create', 'Added source {name}', 'Adding source {name}'),
  'source.update': attempted('source.update', 'Changed source {name}', 'Change of source {name}'),
  'source.delete': attempted('source.delete', 'Deleted source {name}', 'Deleting source {name}'),
  'source.test': texts([
    ['ok', 'Tested the connection to {name}: connected'],
    ['failed result=timeout', 'Tested the connection to {name}: it timed out'],
    ['failed', 'Tested the connection to {name}: it failed'],
    ['denied', 'Connection test of {name} refused ({code})'],
  ]),
  'email.test': texts([
    ['ok', 'Sent a test email: the mail server accepted it'],
    ['failed', 'Sent a test email: the mail server refused it'],
    ['denied', 'Test email refused ({code})'],
    ['conflict', 'Test email not sent: the email settings changed first'],
  ]),
  'sources.refresh': texts([
    ['ok', 'Asked every source for new readings'],
    ['denied', 'Refresh refused ({code})'],
    ['failed', 'Refresh failed ({code})'],
  ]),
  'sources.import': attempted(
    'sources.import',
    'Imported from Uptime Kuma: {added} added, {changed} changed, {skipped} skipped',
    'Import from Uptime Kuma'
  ),
  'delivery.retry': attempted(
    'delivery.retry',
    'Retried a notification ({retried} queued again)',
    'Retry of a notification'
  ),
  'channel.resume': attempted(
    'channel.resume',
    'Resumed the {id} channel ({released} released)',
    'Resuming the {id} channel'
  ),
  'channel.settings': texts([['*', 'Changed the {id} channel settings']]),
  'channel.test': texts([
    ['ok', 'Sent a test notification on {id}: it was accepted'],
    ['failed', 'Sent a test notification on {id}: it was not accepted'],
    ['denied', 'Test notification on {id} refused ({code})'],
    ['conflict', 'Test notification on {id} not sent ({code})'],
  ]),
  'signing.reveal': attempted(
    'signing.reveal',
    'Showed the webhook signing secret',
    'Showing the webhook signing secret'
  ),
  'signing.rotate': texts([['*', 'Replaced the webhook signing key']]),
  'signing.created': texts([
    ['replaced', 'Created a new webhook signing key: the old one could not be read'],
    ['*', 'Created the webhook signing key'],
  ]),
  'channel.paused': texts([['*', 'Paused the {id} channel: {reason}']]),
  'channel.working': texts([['*', 'The {id} channel works again']]),
  'notifications.unsaved': texts([
    ['*', 'Uptime Goblin keeps notifications in memory only: it cannot save them'],
  ]),
  'notifications.saved': texts([['*', 'Uptime Goblin saves notifications again']]),
  'config.export': texts([['*', 'Exported the configuration (without secrets)']]),
  'audit.export': texts([['*', 'Exported {rows} audit entries ({format})']]),
  'config.changed-outside': texts([
    ['repaired', 'Settings were changed outside Uptime Goblin or repaired at start (config.json)'],
    ['*', 'Settings were changed outside Uptime Goblin (config.json)'],
  ]),
  'system.start': texts(
    [
      ['first', 'Uptime Goblin {version} started for the first time'],
      [
        '!cleanStop',
        'Uptime Goblin {version} started; its previous stop was not recorded (a crash, or a stop while the disk was full)',
      ],
      ['*', 'Uptime Goblin {version} started'],
    ],
    [['securityChanged', '; security settings from the environment changed: {names}']]
  ),
  'system.stop': texts([['*', 'Uptime Goblin stopped']]),
  'system.upgrade': texts(
    [
      ['own', 'Uptime Goblin {release} opened this data'],
      ['*', 'Uptime Goblin {release} found that {n} releases opened this data: {list}'],
    ],
    [['markerLost', ' (some may be missing)']]
  ),
  'system.restore': texts([
    ['cause=snapshot', "Uptime Goblin's data was restored from snapshot {snapshot}"],
    [
      'cause=control_file',
      'control.sqlite was replaced: a restore from a backup, a copy or a move',
    ],
  ]),
  'data.snapshot': texts(
    [['*', 'Snapshot {id} was taken ({reason})']],
    [['more', ' and {more} older ones']]
  ),
  'audit.gap': texts([
    ['reason=head-mismatch', 'Uptime Goblin found its audit log cut or changed at the end'],
    [
      'reason=inbox-discarded',
      'Uptime Goblin discarded {count} entries left in the audit inbox by an earlier start',
    ],
  ]),
  'audit.pruned': texts([
    ['reason=age', 'Removed {deleted} audit entries older than the retention period'],
    [
      'reason=both',
      'Removed {deleted} audit entries older than the retention period and to stay within 250,000',
    ],
    ['*', 'Removed {deleted} audit entries to stay within 250,000'],
  ]),
  // A rewrap with nothing to do still writes its entry, as {rewrapped: 0}: it says so rather
  // than claim a re-wrap that did not happen (docs audit, audit 23).
  'key.rewrap': texts([
    [
      'ok rewrapped=0',
      'goblin-admin key rewrap found every data key already wrapped under the current encryption key; nothing changed',
    ],
    ['ok', 'goblin-admin re-wrapped the data keys under the current encryption key'],
    ['failed', 'goblin-admin {command} failed ({code})'],
  ]),
  'key.rotate': keyCommand('goblin-admin rotated the data keys'),
  'key.reset': texts([['ok', 'goblin-admin reset the keys after the encryption key was lost']]),
  // --unused deletes an older key, not a copy of the one in use (docs audit, keys 21).
  'key.remove-data-copy': texts([
    [
      'ok unused=true',
      'goblin-admin deleted an older encryption key, which Uptime Goblin no longer used, from the data directory',
    ],
    ['ok', 'goblin-admin deleted the copy of the encryption key in the data directory'],
    ['failed', 'goblin-admin {command} failed ({code})'],
  ]),
});

/**
 * The words of an error code in a row's text (§8.2). Any other code (a delivery or storage
 * code) reads "Uptime Goblin error {code}".
 */
export const CODE_WORDS = Object.freeze({
  invalid_credentials: 'wrong name or password',
  current_password_incorrect: 'the current password was wrong',
  locked: 'too many failed attempts',
  busy: 'too many sign-ins at once',
  https_required: 'plain HTTP is not allowed',
  proxy_proto_missing: 'the proxy did not say the browser uses HTTPS',
  proxy_proto_mismatch: 'the proxy claimed HTTPS for a plain-HTTP page',
  cross_origin: "the page address did not match Uptime Goblin's",
  // Only in rows of earlier 1.5 builds, which refused sign-in without a password.
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

// ---------------------------------------------------------------------------------------------
// Verification texts (§7.1), shared by goblin-admin verify-audit, GET /api/audit/verify and the
// Audit log page. Placeholders: {seq}, {from}, {to}, {head}, {lastSeq} entry numbers (with
// thousands separators); {time}, {lineTime}, {at} times as auditTime() gives them.

/**
 * PROBLEM_TEXTS[code] = {message, consequence}. In log_truncated, `whenNull` gives what "#{head}"
 * reads when the head was missing and what "#{lastSeq}" reads when the log was empty.
 */
export const PROBLEM_TEXTS = Object.freeze({
  start_missing: Object.freeze({
    message: 'Entries before #{seq} are missing, and no prune recorded their removal.',
    consequence: 'The entries that remain were checked; the removed ones cannot be.',
  }),
  link_broken: Object.freeze({
    message:
      'Entry #{seq} does not follow the entry before it: an entry was changed, inserted or removed.',
    consequence: 'Entries from #{seq} on cannot be trusted.',
  }),
  seq_gap: Object.freeze({
    message: 'Entries #{from}–#{to} are missing.',
    consequence: 'The entries around them were checked; the removed ones cannot be.',
  }),
  hash_mismatch: Object.freeze({
    message: 'Entry #{seq} does not match its signature: it was changed.',
    consequence: 'Entry #{seq} cannot be trusted; the others were checked.',
  }),
  head_mismatch: Object.freeze({
    message:
      'The log ends at entry #{seq}, but Uptime Goblin last wrote entry #{head}: entries were removed from the end.',
    consequence: 'Entries after #{seq} are gone; the rest were checked.',
  }),
  checkpoint_mismatch: Object.freeze({
    message: 'Checkpoint #{seq} does not match the entry it names.',
    consequence: 'The checkpoint or entry #{seq} was changed.',
  }),
  checkpoint_mac: Object.freeze({
    message: 'Checkpoint #{seq} is not signed by this Uptime Goblin.',
    consequence:
      'A checkpoint was changed, or the key that signed it was removed without a recorded reset.',
  }),
  journal_mismatch: Object.freeze({
    message: 'Entry #{seq} differs from the checkpoint Uptime Goblin printed on {lineTime}.',
    consequence:
      'Entry #{seq} or an entry before it was changed after Uptime Goblin printed the checkpoint.',
  }),
  journal_ahead: Object.freeze({
    message: 'Uptime Goblin printed checkpoint #{seq} on {lineTime}, but the log ends at #{head}.',
    consequence:
      'Entries after #{head} were removed from the end, or this is an older copy of the data.',
  }),
  log_truncated: Object.freeze({
    message:
      'On {time} Uptime Goblin found its audit log cut or changed at the end: it had last written entry #{head}, and the log ended at entry #{lastSeq}.',
    consequence:
      'Entries Uptime Goblin wrote after #{lastSeq} are missing or were changed; the entries before were checked.',
    whenNull: Object.freeze({ head: 'an unknown entry', lastSeq: 'no entry' }),
  }),
  key_lost: Object.freeze({
    message:
      'Entry #{seq} is signed with a key that is not in the keyring, and no key reset recorded its loss.',
    consequence: 'Entries signed with that key cannot be trusted.',
  }),
  unreadable: Object.freeze({
    message: 'Entries from #{seq} could not be read: a stored value is out of range.',
    consequence: 'They were not checked; the entries before them were.',
  }),
});

/**
 * UNVERIFIABLE_TEXTS[reason]: one line per unverifiable item. In restore_unchecked, {restore
 * words} is `restore.<cause>` below; {at} is the snapshot cause's `at`, else the anchor row's
 * time; {line} (no_key) is `key status`'s line for the key. unknown_key (journal lines under a
 * key the keyring does not hold, which no reset removed) was added at integration: CLI only.
 */
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

/**
 * ANCHOR_TEXTS: one line per anchor (CLI and page). `.empty` is the text when the anchor's
 * restoredHead (system.restore) or head (key.reset) is null; system.upgrade gives one line per
 * entry (`system.upgrade` for this release's own entry, `system.upgrade.other` for the others),
 * preceded by `system.upgrade.markerLost` when the marker was lost.
 */
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

// ---------------------------------------------------------------------------------------------
// Events (§4.1, verbatim).

/**
 * An audit event, as identity, the pipeline, delivery and the CLI hand it to the writer.
 * @typedef {object} AuditEvent
 * @property {string} action            an ACTIONS key                                  → action
 * @property {string} outcome           one of that action's outcomes                   → outcome
 * @property {number} [at]              ms; default clock()                             → time
 * @property {{type: string, id: string|null, name: string|null, via: string|null,
 *   sessionId: string|null}} [actor]   default {type: 'system', id: null, name: 'orbit',
 *                                      via: 'system', sessionId: null}
 *                                      → actor_type, actor_id, actor_name, via, session_id
 * @property {string|null} [client]     the client key                                  → client_key
 * @property {string|null} [userAgent]                                                   → user_agent
 * @property {string|null} [requestId]                                                   → request_id
 * @property {{type: string, id: string|null, name: string|null}} [target]
 *                                                                → target_type, target_id, target_name
 * @property {number|null} [status]                                                      → status
 * @property {number} [count]           default 1                                       → count
 * @property {number|null} [ref]        the attempt's seq                               → ref
 * @property {object|null} [detail]                                                      → detail
 * @property {number|null} [configRevision]                                              → config_revision
 * @property {Record<string, string>} [meta]  §3.4 keys only, applied in the row's unit
 * @property {string|null} [login]      count() only: reduced to its class at once, never kept (D9)
 */
export const eventFrom = (request, fields) => ({
  actor: request?.actor,
  client: request?.client ?? null,
  userAgent: request?.userAgent ?? null,
  requestId: request?.requestId ?? null,
  ...fields,
});

/**
 * A time as the CLI shows it (lib/cli/common.mjs formatTime): "2026-10-03 12:00:00 UTC". A stored
 * time is any safe integer, so one a Date cannot hold reads "unknown" rather than throwing.
 */
const maxDateMs = 8.64e15;
export const auditTime = ms =>
  Number.isFinite(ms) && Math.abs(ms) <= maxDateMs
    ? new Date(ms)
        .toISOString()
        .replace('T', ' ')
        .replace(/\.\d{3}Z$/, ' UTC')
    : 'unknown';
