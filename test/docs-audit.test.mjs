// The audit log docs against the code and what it does (1.5 docs audit, area "audit"): what a
// removed control.sqlite takes with it, the key commands' unchecked window, verify-audit's exit
// statuses, the retention's limits, what Uptime Goblin's own log can hold, the refusal lines, and the
// script export. Each test reads the texts and runs what they describe where it can, so a change
// to either that makes the docs wrong fails here.
import { currentNames, isDeploymentFile } from './helpers/deployed-names.mjs';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createApp } from '../server.mjs';
import { main } from '../lib/cli/goblin-admin.mjs';
import { help as verifyHelp, reportLines } from '../lib/cli/commands/verify-audit.mjs';
import { AUDIT_TEXTS, UNVERIFIABLE_TEXTS } from '../lib/audit/actions.mjs';
import { AUDIT_ERRORS } from '../lib/audit/errors.mjs';
import { retentionSetting } from '../lib/audit/index.mjs';
import { mirrorLine } from '../lib/audit/writer.mjs';
import { csvLine } from '../lib/audit/export.mjs';
import { windowOf } from '../lib/audit/aggregate.mjs';
import { listSnapshots } from '../lib/db/snapshot.mjs';
import { signIn, sessionCall } from './helpers/session.mjs';
import { platformTest } from './helpers/platform.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
// Deployment files with their names from before the rename read as the current ones
// (test/helpers/deployed-names.mjs).
const read = file => {
  const text = fs.readFileSync(path.join(repository, file), 'utf8');
  return isDeploymentFile(file) ? currentNames(text) : text;
};
const flat = text => text.replace(/\s+/g, ' ').trim();
// The comment text of a YAML or .env file, its `#` markers removed, as one line.
const comments = text => flat(text.replace(/^[ \t]*# ?/gm, ''));
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
// GitHub's heading anchors, for the links these docs add.
const anchors = file =>
  new Set(
    [...read(file).matchAll(/^#{1,6} (.+)$/gm)].map(([, title]) =>
      title
        .toLowerCase()
        .replace(/[^\p{L}\p{N} _-]/gu, '')
        .replace(/ /g, '-')
    )
  );
function assertLink(file, target) {
  const [linked, anchor] = target.split('#');
  const into = linked ? path.join(path.dirname(file), linked) : file;
  assert.ok(anchors(into).has(anchor), `${file} links to ${target}, a heading of ${into}`);
  assert.ok(read(file).includes(`(${target})`), `${file} links to ${target}`);
}
const temporary = (t, prefix) => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
};
// A /proc in which no process runs, so offline commands find no Uptime Goblin by its process.
const noProcesses = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-audit-proc-'));
after(() => fs.rmSync(noProcesses, { recursive: true, force: true }));
const keySources = {
  credentialsDirectory: path.join(noProcesses, 'no-credentials'),
  secretsDirectory: path.join(noProcesses, 'no-secrets'),
};
// Throwaway values for these data directories only.
const password = 'docs-audit-password-0001';

// goblin-admin in-process, as a native install runs it: {code, out, err}.
async function admin(args, env = {}) {
  let out = '',
    err = '';
  const code = await main(args, {
    env,
    uid: 1000,
    container: false,
    proc: noProcesses,
    stdout: text => (out += text),
    stderr: text => (err += text),
    keySources,
  });
  return { code, out, err };
}

// Uptime Goblin's own log while a test runs: the lines it prints (checkpoints, unwritten entries).
function capture(t) {
  const lines = [];
  for (const level of ['log', 'info', 'warn', 'error'])
    t.mock.method(console, level, (...args) => lines.push(args.join(' ')));
  return {
    lines,
    of: kind => lines.filter(line => line.startsWith(`{"orbit":"${kind}"`)),
  };
}

// Uptime Goblin on `directory`, as a 1.5 install runs it (no legacy Basic), listening on loopback.
async function startOrbit(t, directory, options = {}) {
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    legacyBasic: false,
    webhook: '',
    keySources,
    ...options,
  });
  let closed = false;
  const close = async () => {
    if (!closed) await app.close();
    closed = true;
  };
  t.after(close);
  const { port } = await app.listen();
  return { app, base: `http://127.0.0.1:${port}`, close };
}

// A data directory as 1.4.x left it (config.json only), so the first 1.5 start pins a snapshot.
function oldData(t) {
  const base = temporary(t, 'orbit-docs-audit-');
  const directory = path.join(base, 'data');
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  return { base, directory };
}

const auditRows = directory => {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db
      .prepare('SELECT seq, action, outcome, detail, hash, key_id FROM audit_log ORDER BY seq')
      .all()
      .map(row => ({ ...row, detail: row.detail === null ? null : JSON.parse(row.detail) }));
  } finally {
    db.close();
  }
};

// The sentence the Audit log page gives an entry: the first AUDIT_TEXTS rule whose terms all
// hold (an outcome, `field=value` on the detail, or `*`), as entrySentence() picks it.
function sentence(row) {
  const holds = term => {
    if (term === '*') return true;
    const equals = term.indexOf('=');
    if (equals > 0) return String(row.detail?.[term.slice(0, equals)]) === term.slice(equals + 1);
    return term.split('|').includes(row.outcome);
  };
  return AUDIT_TEXTS[row.action].texts.find(([when]) => when.split(' ').every(holds))?.[1];
}

// Docs audit 1, 4, 5, 9, 10: restoring the pinned pre-1.5 snapshot, or deleting control.sqlite,
// takes the whole audit log with it. Both restore detectors live in that file, so the next start
// begins a log that checks intact and lists no restore; only the kept journal shows it, as "not
// fully checked", never CHANGED.
test('a restore without control.sqlite, or deleting it, starts a new log that lists no restore, as the docs say', async t => {
  const output = capture(t);
  const { base, directory } = oldData(t);
  await (await startOrbit(t, directory)).close();
  const pinned = listSnapshots(directory).find(item => item.pinned);
  assert.ok(pinned, 'the first 1.5 start pinned the data as 1.4.x left it');
  const firstInstance = JSON.parse(output.of('audit.checkpoint')[0]).instance;

  // The restore says what went with control.sqlite: the audit log first.
  const restored = await admin(['restore-snapshot', pinned.id, '--data-dir', directory]);
  assert.equal(restored.code, 0, restored.err);
  const lines = restored.out.trimEnd().split('\n');
  const removed = lines.findIndex(line => line.startsWith('Removed (absent in the snapshot): '));
  assert.match(lines[removed], /control\.sqlite/);
  const said = lines[removed + 1];
  assert.match(
    said,
    /^control\.sqlite held Uptime Goblin 1\.5's audit log, its sessions, its waiting notifications, its delivery history and the webhook signing key\. The audit log starts again, empty, at the next start, and Check integrity will list no restore: the old log is kept only in the pre-restore snapshot named below\./
  );
  assert.match(
    restored.out,
    /The replaced files are in snapshot pre-restore-\S+; restore it to undo\./
  );

  await (await startOrbit(t, directory)).close();
  const checked = await admin(['verify-audit', '--data-dir', directory]);
  assert.equal(checked.code, 0, checked.out + checked.err);
  assert.match(checked.out, /^Audit log: intact\./);
  assert.doesNotMatch(checked.out, /Restored from snapshot|control\.sqlite was replaced/);
  const rows = auditRows(directory);
  assert.deepEqual(
    rows.slice(0, 3).map(row => row.action),
    ['account.bootstrap', 'system.upgrade', 'system.start']
  );
  assert.equal(
    rows.some(row => row.action === 'system.restore'),
    false
  );
  // The first entries as security.md quotes them.
  assert.match(sentence(rows[0]), /^Set up the admin account /);
  assert.equal(rows[2].detail.first, true);
  assert.match(AUDIT_TEXTS['system.start'].texts[0][1], / started for the first time$/);
  assert.match(AUDIT_TEXTS['system.upgrade'].texts[0][1], / opened this data$/);
  // Against the kept journal: not fully checked (3), never CHANGED, with the lines from before
  // under another instance.
  const journal = path.join(base, 'journal.txt');
  fs.writeFileSync(journal, output.of('audit.checkpoint').join('\n') + '\n');
  const instances = new Set(output.of('audit.checkpoint').map(line => JSON.parse(line).instance));
  assert.equal(instances.size, 2);
  assert.ok(instances.has(firstInstance));
  const against = await admin(['verify-audit', '--checkpoints', journal, '--data-dir', directory]);
  assert.equal(against.code, 3, against.out + against.err);
  assert.match(against.out, /^Audit log: not fully checked\./);
  assert.ok(
    against.out.includes(
      "this Uptime Goblin's from before a restore of older data or the removal of control.sqlite (which takes the whole audit log with it)"
    ),
    against.out
  );
  assert.match(against.out, /^Every entry is covered by a journal checkpoint\.$/m);
  assert.ok(UNVERIFIABLE_TEXTS.unknown_key.includes('the removal of control.sqlite'));
  assert.ok(
    read('public/modules/configure/audit.js').includes(UNVERIFIABLE_TEXTS.unknown_key),
    "the page's copy"
  );

  // Deleting control.sqlite does the same; a copy moved aside still checks with the same key.
  const aside = path.join(base, 'aside');
  fs.mkdirSync(aside, { mode: 0o700 });
  for (const name of fs.readdirSync(directory).filter(name => name.startsWith('control.sqlite')))
    fs.renameSync(path.join(directory, name), path.join(aside, name));
  await (await startOrbit(t, directory)).close();
  const after = await admin(['verify-audit', '--data-dir', directory]);
  assert.equal(after.code, 0, after.out + after.err);
  assert.doesNotMatch(after.out, /Restored from snapshot|control\.sqlite was replaced/);
  assert.equal(auditRows(directory)[2].detail.first, true);
  const kept = await admin(['verify-audit', '--data-dir', aside], {
    GOBLIN_SECRET_KEY_FILE: path.join(directory, 'secret.key'),
  });
  assert.equal(kept.code, 0, kept.out + kept.err);
  assert.match(kept.out, /^Audit log: intact\./);

  // The docs say so wherever they send the admin to remove or replace control.sqlite.
  const security = flat(read('docs/security.md'));
  for (const text of [
    'or remove the whole log. Deleting `control.sqlite`, or restoring a snapshot or a copy without one (the pinned pre-1.5 snapshot, a backup from before the upgrade), leaves Uptime Goblin no trace of the old log: the next start begins a new log that checks intact and lists no restore.',
    'Its first entries read "Set up the admin account …", "Uptime Goblin … opened this data" and "Uptime Goblin … started for the first time", and its checkpoint lines name a new `instance`.',
    'never as CHANGED.',
  ])
    assert.ok(security.includes(text), text);
  assert.doesNotMatch(security, /cannot hide that a restore happened/);
  assert.ok(
    flat(read('docs/troubleshooting.md')).includes(
      "Or they are this Uptime Goblin's from before `control.sqlite` was deleted, or before a snapshot or a copy without one was restored"
    )
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      "; this Uptime Goblin's from before `control.sqlite` was deleted, or before a snapshot or a copy without one was restored, which removed the whole audit log;"
    )
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      'the webhook signing key and the [audit log](security.md#audit-log): the next 1.5 start begins a new, empty log, which lists no restore'
    )
  );
  const guard = flat(section(read('docs/authentication.md'), 'A password is always required'));
  assert.ok(guard.includes('Either way also removes the [audit log](security.md#audit-log)'));
  assert.ok(
    guard.includes('`goblin-admin verify-audit --data-dir <that folder>`, with the same key')
  );
  assert.ok(
    flat(read('docs/authentication.md')).includes(
      'and removes the [audit log](security.md#audit-log) (export it first'
    )
  );
  assert.ok(
    flat(read('docs/notifications.md')).includes(
      'the webhook signing key and the [audit log](security.md#audit-log) (the next start begins a new, empty one: export it first)'
    )
  );
  const changelog = flat(unreleased());
  assert.ok(changelog.includes('Every restore Uptime Goblin can see and every upgrade is listed'));
  assert.doesNotMatch(changelog, /Every restore and upgrade is listed/);
  assert.ok(
    changelog.includes('and so does the audit log (the next start begins a new, empty one')
  );
});

// Docs audit 2 and 23: the key commands print no checkpoint line, so until Uptime Goblin's next entry
// their entry can be removed from the end with nothing to show it; and a rewrap with nothing to
// do says so on the page.
test('a key command prints no checkpoint: its entry can be cut unseen until Orbit records again, and a no-op rewrap reads as one', async t => {
  const output = capture(t);
  const { base, directory } = oldData(t);
  await (await startOrbit(t, directory)).close();
  const journal = path.join(base, 'journal.txt');
  fs.writeFileSync(journal, output.of('audit.checkpoint').join('\n') + '\n');
  const before = output.lines.length;
  const key = { GOBLIN_SECRET_KEY_FILE: path.join(directory, 'secret.key') };
  const rewrap = await admin(['key', 'rewrap', '--data-dir', directory], key);
  assert.equal(rewrap.code, 0, rewrap.err);
  assert.match(rewrap.out, /nothing to do\.$/m);
  assert.doesNotMatch(
    rewrap.out + rewrap.err + output.lines.slice(before).join('\n'),
    /audit\.checkpoint/
  );
  const rows = auditRows(directory);
  const last = rows.at(-1);
  assert.equal(last.action, 'key.rewrap');
  assert.deepEqual(last.detail, { rewrapped: 0 });
  assert.equal(
    sentence(last),
    'goblin-admin key rewrap found every data key already wrapped under the current encryption key; nothing changed'
  );
  assert.equal(
    sentence({ ...last, detail: { rewrapped: 2 } }),
    'goblin-admin re-wrapped the data keys under the current encryption key'
  );
  assert.ok(
    read('public/modules/configure/audit.js').includes(
      "'goblin-admin key rewrap found every data key already wrapped under the current encryption key; nothing changed'"
    ),
    "the page's copy"
  );
  // While the entry is there, the journal check says only that it is not covered.
  const uncovered = await admin(
    ['verify-audit', '--checkpoints', journal, '--data-dir', directory],
    key
  );
  assert.equal(uncovered.code, 0, uncovered.out);
  assert.match(
    uncovered.out,
    new RegExp(
      `^Entries after #${rows.at(-2).seq} \\(.*\\) are covered by no journal checkpoint\\.$`,
      'm'
    )
  );
  // Cut from the end with the head set back: nothing shows it, not even the journal.
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  try {
    const previous = rows.at(-2);
    db.prepare('DELETE FROM audit_log WHERE seq = ?').run(last.seq);
    db.prepare('UPDATE audit_head SET seq = ?, hash = ?, key_id = ?').run(
      previous.seq,
      previous.hash,
      previous.key_id
    );
  } finally {
    db.close();
  }
  const cut = await admin(['verify-audit', '--checkpoints', journal, '--data-dir', directory], key);
  assert.equal(cut.code, 0, cut.out);
  assert.match(cut.out, /^Audit log: intact\./);
  assert.match(cut.out, /^Every entry is covered by a journal checkpoint\.$/m);

  const security = flat(read('docs/security.md'));
  assert.ok(
    security.includes(
      'Until then, someone who can write `control.sqlite` can remove those entries from the end, and no check shows it, not even against Uptime Goblin\'s log: while they are there, `verify-audit --checkpoints` says only "Entries after #… are covered by no journal checkpoint"; once they are removed, it reads intact'
    )
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      'until then, someone who can write `control.sqlite` can remove that entry unseen'
    )
  );
  assert.ok(flat(unreleased()).includes('The `goblin-admin` key commands print none'));
});

// key remove-data-copy runs beside a running Uptime Goblin, so no start follows it: its entry stays
// uncovered until Uptime Goblin records something, and a sign-in afterwards covers it, as the docs say
// (docs audit, audit: "start Uptime Goblin after a key command" did not fit it).
test('key remove-data-copy beside a running Orbit: its entry is covered once Orbit records a sign-in', async t => {
  const output = capture(t);
  const { base, directory } = oldData(t);
  const orbit = await startOrbit(t, directory);
  // The key moved out of the data directory, so the copy there can go.
  const keyFile = path.join(base, 'secret.key');
  fs.copyFileSync(path.join(directory, 'secret.key'), keyFile);
  fs.chmodSync(keyFile, 0o600);
  const key = { GOBLIN_SECRET_KEY_FILE: keyFile };
  const removed = await admin(['key', 'remove-data-copy', '--data-dir', directory], key);
  assert.equal(removed.code, 0, removed.out + removed.err);
  assert.equal(auditRows(directory).at(-1).action, 'key.remove-data-copy');
  const journal = path.join(base, 'journal.txt');
  const check = async () => {
    fs.writeFileSync(journal, output.of('audit.checkpoint').join('\n') + '\n');
    return admin(['verify-audit', '--checkpoints', journal, '--data-dir', directory], key);
  };
  assert.match((await check()).out, /are covered by no journal checkpoint\.$/m);
  await signIn(orbit.base, password);
  const covered = await check();
  assert.equal(covered.code, 0, covered.out);
  assert.match(covered.out, /^Every entry is covered by a journal checkpoint\.$/m);
  assert.ok(
    flat(read('docs/security.md')).includes(
      "`key remove-data-copy` runs beside a running Uptime Goblin, so no start follows it: sign in once afterwards, and keep that sign-in's line."
    )
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      '(`key remove-data-copy` runs beside a running Uptime Goblin, so no start follows it: sign in once afterwards, and keep that line)'
    )
  );
  assert.ok(
    flat(unreleased()).includes(
      'start Uptime Goblin after one (after `key remove-data-copy`, which runs beside a running Uptime Goblin, sign in once)'
    )
  );
});

// A restore that removed control.sqlite is listed nowhere, and the old log lives on only in older
// copies of that file: the docs no longer say every restore is listed, or that only the
// pre-restore snapshot holds the old file (docs audit, audit 1).
test('the docs list only the restores the log can see, and every place the old log survives', () => {
  const security = flat(read('docs/security.md'));
  assert.ok(
    security.includes(
      'A snapshot removed before that start is not recorded, and neither is a restore that removed `control.sqlite` (of the pinned pre-1.5 snapshot): that start begins a new log, which lists no restore.'
    )
  );
  const troubleshooting = flat(read('docs/troubleshooting.md'));
  assert.ok(
    troubleshooting.includes(
      'Every restore that kept `control.sqlite` is listed: make sure each was yours. A restore that removed it is not (the next bullet).'
    )
  );
  assert.ok(
    troubleshooting.includes(
      'The old log is then only in older copies of `control.sqlite`, each as it was when made: the pre-restore snapshot that `restore-snapshot` made (deleting the file leaves none), a copy you moved aside, and earlier snapshots and backups.'
    )
  );
  assert.doesNotMatch(troubleshooting, /Every restore is listed/);
  assert.doesNotMatch(troubleshooting, /Only the pre-restore snapshot, or a copy you moved aside/);
  // installation.md gives the same reasons for unknown checkpoint keys as troubleshooting.md.
  assert.ok(
    flat(read('docs/installation.md')).includes(
      "or this Uptime Goblin's under a key that was then removed from the keyring by hand, which can hide entries removed with it)"
    )
  );
});

// Docs audit 8: verify-audit's exit statuses, also when the check did not run.
test('verify-audit exits 0 intact or empty, 1 changed or not run, 2 for usage, 3 not fully checked, as the docs say', async t => {
  const empty = temporary(t, 'orbit-docs-audit-empty-');
  const none = await admin(['verify-audit', '--data-dir', empty]);
  assert.equal(none.code, 1);
  assert.equal(
    none.err,
    'goblin-admin verify-audit: There is no control database yet: start Uptime Goblin 1.5 or later once.\n'
  );
  const journal = await admin([
    'verify-audit',
    '--checkpoints',
    path.join(empty, 'missing.txt'),
    '--data-dir',
    empty,
  ]);
  assert.equal(journal.code, 2);
  assert.match(
    journal.err,
    /^goblin-admin verify-audit: could not read the journal .* \(ENOENT\)\.\n$/
  );
  const nothing = reportLines({
    result: 'intact',
    rows: { checked: 0, first: null, last: null },
    anchors: [],
    unverifiable: [],
    journal: null,
    problem: null,
  });
  assert.deepEqual(nothing, ['Audit log: empty. There is nothing to check yet.']);
  assert.match(
    flat(verifyHelp),
    /Exit status: 0 intact or empty, 1 changed or the check could not run, 2 usage error, 3 not fully checked\./
  );

  const installation = flat(read('docs/installation.md'));
  assert.ok(installation.includes(`\`${nothing[0]}\``));
  assert.ok(
    installation.includes(
      'Its exit status is 0 (intact or empty), 1 (CHANGED, or the check could not run: a line starting `goblin-admin verify-audit:` instead of `Audit log:` says why), 2 (a usage error, such as a `--checkpoints` file it cannot read) or 3 (not fully checked)'
    )
  );
  const rows = read('docs/troubleshooting.md').split('\n');
  const notRun = rows.find(row =>
    row.startsWith('| `goblin-admin verify-audit`: 1, a line starting `goblin-admin verify-audit:`')
  );
  assert.ok(notRun, 'troubleshooting.md has the row for a check that did not run');
  for (const text of [
    '"There is no control database yet…"',
    '"This control database has no audit log yet…"',
    '"GOBLIN_SECRET_KEY_FILE (…) cannot be read: …"',
    '"could not read the audit log (…)"',
  ])
    assert.ok(notRun.includes(text), text);
  assert.ok(none.err.includes(notRun.match(/"(There is no control database yet)…"/)[1]));
  assert.ok(
    rows.some(row =>
      row.startsWith('| `goblin-admin verify-audit`: 2, "could not read the journal … (…)" |')
    )
  );
  assert.ok(
    flat(unreleased()).includes(
      '(exit 0 intact or empty, 1 changed or the check could not run, 2 a usage error, 3 not fully checked)'
    )
  );
});

// Docs audit 3, 11 and 21: what Uptime Goblin's own log holds beyond the checkpoint lines. An entry it
// could not write is printed in full whatever GOBLIN_AUDIT_LOG says, and a copied entry carries
// the address, the browser and the session id.
test('Orbit prints an unwritten entry in full whatever GOBLIN_AUDIT_LOG says, and a copied entry carries address, browser and session id', async t => {
  const output = capture(t);
  const seam = { failing: false };
  const full = () =>
    Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' });
  const wrapDb = (db, purpose) =>
    purpose === 'result'
      ? new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'write')
              return (...args) =>
                seam.failing ? Promise.reject(full()) : value.apply(target, args);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        })
      : db;
  const { directory } = oldData(t);
  const orbit = await startOrbit(t, directory, { auditLog: '', audit: { wrapDb } });
  const call = sessionCall(orbit.base, (await signIn(orbit.base, password)).cookie);
  seam.failing = true;
  assert.equal((await call('/api/settings', 'PATCH', { title: 'Docs audit' })).status, 200);
  const [lost] = output.of('audit.unwritten').map(line => JSON.parse(line));
  assert.ok(lost, 'one audit.unwritten line');
  assert.equal(lost.row.action, 'settings.update');
  assert.equal(lost.row.actor.client, 'loopback');
  assert.match(lost.row.actor.sessionId, /^s_/);
  assert.equal(typeof lost.row.actor.userAgent, 'string');
  assert.ok(lost.row.detail.diff.some(change => change.path === 'title'));
  assert.deepEqual(
    output.lines.filter(line => line.startsWith('{"orbit":"audit",')),
    [],
    'GOBLIN_AUDIT_LOG is off: no entry is copied'
  );
  const listed = await call('/api/audit?outcome=unknown');
  assert.equal(listed.body.unwritten.count, 1);
  await orbit.close();
  // A copied entry (stdout) carries who, the address, the browser and the session id.
  const copied = JSON.parse(
    mirrorLine(
      {
        seq: 1,
        time: 0,
        actor_type: 'user',
        actor_id: 'u_admin',
        actor_name: 'admin',
        via: 'session',
        session_id: 's_docsaudit',
        client_key: '192.0.2.10',
        user_agent: 'Docs/1.0',
        action: 'session.login',
        outcome: 'ok',
        detail: { secretless: true },
        hash: 'h',
      },
      { instance: 'i' }
    )
  );
  assert.deepEqual(
    [copied.actor.client, copied.actor.userAgent, copied.actor.sessionId, copied.detail],
    ['192.0.2.10', 'Docs/1.0', 's_docsaudit', undefined]
  );

  const keeping = flat(section(read('docs/installation.md'), "Keeping Uptime Goblin's log", 3));
  assert.ok(
    keeping.includes(
      'An entry Uptime Goblin could not write is printed in full, as a line starting `{"orbit":"audit.unwritten"`, whatever `GOBLIN_AUDIT_LOG` says: who, the client address and browser, the session id and what changed (never a secret).'
    )
  );
  assert.doesNotMatch(keeping, /unless `GOBLIN_AUDIT_LOG` copies the entries/);
  assert.ok(
    flat(read('docs/security.md')).includes(
      'An entry Uptime Goblin could not write is printed to its log (stderr) in full, whatever `GOBLIN_AUDIT_LOG` says'
    )
  );
  assert.match(
    comments(read('.env.example')),
    /GOBLIN_AUDIT_LOG copies every entry there too, with who, from which address and browser, and the session id: off \(the default\), stdout, or stdout-full \(also what changed; never a secret\)\. Keep that log as private as the data\./
  );
  // test/installer/docker.test.mjs reads these on one line.
  assert.match(read('.env.example'), /off \(the default\), stdout, or stdout-full/);
  assert.match(read('.env.example'), /30 to 3650 \(90 when empty\)/);
  assert.match(
    comments(read('compose.yaml')),
    /GOBLIN_AUDIT_LOG copies each entry, with client addresses, browser names and session ids, to this container's log too/
  );
  assert.ok(
    flat(read('docs/configuration.md')).includes(
      'The checkpoint lines, and the entries Uptime Goblin could not write, are printed whatever it says.'
    )
  );
  const changelog = flat(unreleased());
  for (const text of [
    'goes to Uptime Goblin\'s log as a line starting `{"orbit":"audit.unwritten"`, in full, whatever `GOBLIN_AUDIT_LOG` says; the change then reads "Outcome unknown", the Audit log page says how many there were since Uptime Goblin started, and no alert is sent for it.',
    `**If Uptime Goblin cannot write its audit log**, settings and source changes, **Retry**, **Resume** and both exports are refused until the disk is fixed, with "${AUDIT_ERRORS.audit_unavailable[1]()}" (503 \`audit_unavailable\`).`,
  ])
    assert.ok(changelog.includes(text), text);
  assert.ok(
    flat(read('docs/installation.md')).includes(`"${AUDIT_ERRORS.audit_unavailable[1]()}"`)
  );
});

// Docs audit 6, 13, 17 and 18: the retention's limits and the log lines that say the prune held
// back, as the code has them.
test('the retention docs give the prune thresholds, its held-back lines and the setting as the code has them', () => {
  assert.deepEqual(retentionSetting('10').days, 30);
  assert.match(retentionSetting('10').warning, /must be from 30 to 3650 days; it is 10/);
  assert.equal(retentionSetting('4000').days, 3650);
  for (const value of ['-5', '30.5', 'ninety']) {
    assert.equal(retentionSetting(value).days, 90, value);
    assert.match(retentionSetting(value).warning, /must be a whole number of days/, value);
  }
  assert.deepEqual(retentionSetting(' 45 '), { days: 45, warning: null });
  const index = read('lib/audit/index.mjs');
  assert.match(index, /const needAge = first\.time < now - window - DAY;/);
  assert.match(index, /const needCap = last\.seq - first\.seq \+ 1 > kept\.maxRows \+ 1000;/);
  assert.match(index, /if \(full\(\)\) return;\n\s+await exclusively\(\(\) => prune\(ctx\)\);/);
  const clockLine =
    "Uptime Goblin's clock is behind its newest audit entry, so it did not remove audit entries older than ${kept.days} days this time. Check the time of the Uptime Goblin host.";
  const stoppedLine =
    'Uptime Goblin did not remove old audit entries, because entry #${grouped(checked.unchecked)} does not check: use Check integrity on the Audit log page.';
  assert.ok(index.includes(clockLine) && index.includes(stoppedLine));

  const troubleshooting = flat(read('docs/troubleshooting.md'));
  const held = flat(
    section(read('docs/troubleshooting.md'), "Uptime Goblin's log mentions old audit entries")
  );
  assert.ok(held.includes(`"${clockLine.replace('${kept.days}', '…')}"`));
  assert.ok(held.includes(`"${stoppedLine.replace('${grouped(checked.unchecked)}', '…')}"`));
  assert.ok(held.includes('neither by age nor by the 250,000 cap'));
  assert.ok(held.includes('1.5 has no command that resumes the prune.'));
  assert.ok(
    troubleshooting.includes(
      "[Uptime Goblin's log mentions old audit entries](#uptime-goblins-log-mentions-old-audit-entries)"
    )
  );
  const security = flat(read('docs/security.md'));
  for (const text of [
    'An hourly job removes older entries once the oldest is a day past the retention, or the log is 1,000 entries over the cap, so an entry can stay up to about a day longer.',
    "It removes none while the disk is full, and none by age while the host's clock is more than an hour behind the newest entry",
    `"${stoppedLine.replace('${grouped(checked.unchecked)}', '…')}" once a day`,
    '1.5 has no command that resumes the prune',
  ])
    assert.ok(security.includes(text), text);
  assert.ok(
    flat(read('docs/configuration.md')).includes(
      'A whole number outside the range is replaced by the nearest end (`10` keeps 30 days). Anything else (a negative or decimal number, a word) is replaced by 90.'
    )
  );
  assert.ok(
    flat(read('docs/architecture.md')).includes(
      'pruned hourly once the oldest entry is a day past the retention or the log is 1,000 entries over the cap'
    )
  );
});

// Docs audit 13 and 22: the refusal lines and answers when the log cannot be written or read.
test('the docs quote the audit refusals, their log lines and the verify answer as the code gives them', () => {
  const [writeStatus, writeText] = AUDIT_ERRORS.audit_unavailable;
  const [readStatus, readText, readRetry] = AUDIT_ERRORS.audit_read_unavailable;
  assert.deepEqual([writeStatus, readStatus, readRetry], [503, 503, 15]);
  assert.equal(readText(), 'Uptime Goblin could not read its audit log. Try again in a moment.');
  const pipeline = read('lib/http/pipeline.mjs');
  assert.ok(
    pipeline.includes(
      "`Request refused: ${e.code === 'audit_read_unavailable' ? 'Uptime Goblin could not read its audit log' : 'Uptime Goblin could not write its audit log'}:`"
    )
  );
  assert.match(pipeline, /cause\?\.code \|\| cause\?\.class/);
  // A SQLite failure, a full database included, has the code the docs name.
  const db = new DatabaseSync(':memory:');
  let code = null;
  try {
    db.exec('PRAGMA max_page_count = 3; CREATE TABLE t (x)');
    for (let i = 0; i < 100; i++) db.prepare('INSERT INTO t VALUES (?)').run('x'.repeat(4000));
  } catch (error) {
    code = error.code;
  } finally {
    db.close();
  }
  assert.equal(code, 'ERR_SQLITE_ERROR');
  const cannot = flat(
    section(read('docs/troubleshooting.md'), 'Uptime Goblin cannot write its audit log')
  );
  assert.ok(cannot.includes(`"${writeText()}"`));
  assert.ok(
    cannot.includes(
      '`Request refused: Uptime Goblin could not write its audit log: <code> (request <id>)`'
    )
  );
  assert.ok(cannot.includes('a SQLite failure names `ERR_SQLITE_ERROR` whatever its cause'));
  assert.ok(cannot.includes(`**"${readText()}"** (503 \`audit_read_unavailable\``));
  assert.ok(
    flat(read('docs/architecture.md')).includes(
      '(200 for each; 503 `audit_read_unavailable` with `Retry-After: 15` when the log cannot be read)'
    )
  );
  assert.doesNotMatch(read('docs/architecture.md'), /\(always 200\)/);
  assert.match(
    read('lib/audit/index.mjs'),
    /throw auditError\('audit_read_unavailable', \{ cause: error \}\);\n\s+\}\n\s+\);\n\s+if \(journal === null\)/
  );
});

// Docs audit 15: the System page's link opens the page at Last 7 days, and the scripts' days and
// the refusals' hours are UTC ones.
test('the scripts report opens at Last 7 days and counts by UTC days and hours, as the docs say', () => {
  const page = read('public/modules/configure/audit.js');
  assert.match(
    page,
    /const defaultFilters = \(\) => \(\{ period: '7d', kind: '', outcome: '', actor: '' \}\);/
  );
  assert.match(page, /filters: \{ \.\.\.defaultFilters\(\), kind \},/);
  for (const label of [
    "['7d', 'Last 7 days'",
    "['90d', 'Last 90 days'",
    "['all', 'All kept entries'",
  ])
    assert.ok(page.includes(label), label);
  assert.ok(read('public/modules/configure/system.js').includes('data-audit-kind="auth.basic."'));
  const at = Date.UTC(2026, 9, 4, 13, 45, 12);
  assert.deepEqual(windowOf('auth.basic.used', at), {
    start: Date.UTC(2026, 9, 4),
    end: Date.UTC(2026, 9, 5),
  });
  assert.deepEqual(windowOf('auth.basic.failed', at), {
    start: Date.UTC(2026, 9, 4, 13),
    end: Date.UTC(2026, 9, 4, 14),
  });
  const scripts = flat(read('docs/authentication.md'));
  assert.ok(
    scripts.includes(
      'The page opens at **Last 7 days**, also from that link: set **Period** to **Last 90 days** or **All kept entries** to see scripts that run less often.'
    )
  );
  assert.ok(scripts.includes('These days and hours are UTC ones.'));
  assert.ok(
    flat(read('docs/configuration.md')).includes(
      "the page opens at **Last 7 days**, also from the System page's link"
    )
  );
});

// Docs audit 19: without legacy Basic a script signs in for a session; the documented lines run
// as printed (only the host, the time and the typed password filled in) against a real Uptime Goblin.
test('the script export of configuration.md signs in, exports privately and signs out as printed', async t => {
  capture(t);
  if (spawnSync('curl', ['--version']).status !== 0) {
    t.skip('curl is not installed');
    return;
  }
  const text = section(read('docs/configuration.md'), 'Exporting from a script', 3);
  const blocks = [...text.matchAll(/```sh\n([\s\S]*?)```/g)].map(match => match[1]);
  assert.equal(blocks.length, 2);
  for (const block of blocks)
    assert.doesNotMatch(block, /#/, 'no comments in a block the admin pastes');
  const { directory } = oldData(t);
  const orbit = await startOrbit(t, directory);
  const work = temporary(t, 'orbit-docs-audit-script-');
  const script = (blocks[0] + blocks[1])
    .replaceAll('https://HOST_NAME', orbit.base)
    .replaceAll('TIME_MS', String(Date.now() + 60000));
  const result = await new Promise((resolve, reject) => {
    const child = spawn('sh', ['-c', `umask 022\n${script}`], {
      cwd: work,
      env: { PATH: process.env.PATH, HOME: work },
    });
    let stdout = '',
      stderr = '';
    child.stdout.on('data', chunk => (stdout += chunk));
    child.stderr.on('data', chunk => (stderr += chunk));
    child.on('error', reject);
    child.on('close', status => resolve({ status, stdout, stderr }));
    child.stdin.end(`{"login":"admin","password":"${password}"}\n`);
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '200\n204\n');
  const files = fs.readdirSync(work);
  const exported = files.filter(name => /^uptime-goblin-audit-\d{8}-\d{6}Z\.ndjson$/.test(name));
  assert.equal(exported.length, 1, files.join(' '));
  assert.equal(fs.statSync(path.join(work, exported[0])).mode & 0o777, 0o600);
  assert.ok(
    !files.includes('uptime-goblin-jar') && !files.includes('signin.json'),
    files.join(' ')
  );
  await orbit.close();
  const rows = auditRows(directory);
  for (const action of ['session.login', 'audit.export', 'session.logout'])
    assert.ok(
      rows.some(row => row.action === action && row.outcome === 'ok'),
      `${action} is recorded`
    );
  assert.ok(text.includes('The sign-in prints `200` and the sign-out `204`'));
  // The umask holds only inside each block's parentheses, so the admin's shell keeps its own; the
  // text says what typing the line shows and needs, and how a CSV export's time becomes the
  // milliseconds `to=` takes (docs audit, audit).
  assert.equal(blocks[0], '(umask 077 && cat > signin.json)\n');
  assert.ok(blocks[1].startsWith('(\numask 077\n') && blocks[1].endsWith('\n)\n'), blocks[1]);
  const flatText = flat(text);
  assert.ok(flatText.includes('What you type shows on the screen.'));
  assert.ok(
    flatText.includes(
      'The line is JSON: in the password, write a `"` as `\\"` and a `\\` as `\\\\`.'
    )
  );
  assert.ok(
    flatText.includes(
      'A CSV export gives `time` as a date and time instead: `node -p "Date.parse(\'<time>\')"` turns it into milliseconds.'
    )
  );
  const ms = Date.UTC(2026, 9, 4, 6, 43, 8, 237);
  const csvTime = csvLine({ seq: 1, time: ms }).split(',')[1].replace(/^"|"$/g, '');
  assert.match(csvTime, /^2026-10-04T06:43:08\.237Z$/);
  assert.equal(Date.parse(csvTime), ms);
});

// The documented lines that keep Uptime Goblin's log (docs/installation.md, Keeping Uptime Goblin's log) and the
// native check, which pipes the journal in so that no copy of it is written.
const KEEP_NATIVE =
  'sudo sh -c \'umask 077 && f=/secure-backups/uptime-goblin-journal.txt && test ! -L "$f" && touch "$f" && test -f "$f" && n=$(mktemp "$f.XXXXXX") && { cat "$f" >> "$n" && mv -f "$n" "$f" || { rm -f "$n"; false; }; } && journalctl -u uptime-goblin -o cat >> "$f"\' || { echo "Uptime Goblin\'s log was not kept"; false; }';
const KEEP_DOCKER =
  '(umask 077 && f=~/uptime-goblin-journal.txt && test ! -L "$f" && touch "$f" && test -f "$f" && n=$(mktemp "$f.XXXXXX") && { cat "$f" >> "$n" && mv -f "$n" "$f" || { rm -f "$n"; false; }; } && docker compose logs --no-log-prefix uptime-goblin >> "$f") || { echo "Uptime Goblin\'s log was not kept"; false; }';
const CHECK_NATIVE =
  "sudo sh -c 'journalctl -u uptime-goblin -o cat | sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs verify-audit --checkpoints - --data-dir /var/lib/uptime-goblin'";

// Runs those lines as the admin's shell would, under the usual umask 022, with stand-ins: docker and
// journalctl print a checkpoint line, sudo runs its command (as the user it names, here the
// same one), and node prints what the check was given; `extra` adds or replaces stand-ins. Each
// run gets a home of its own.
function logKeeping(t, extra = {}) {
  const bin = temporary(t, 'orbit-docs-audit-bin-');
  const stand = (name, body) =>
    fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  stand('docker', `echo '{"orbit":"audit.checkpoint","seq":1}'`);
  stand('journalctl', `echo '{"orbit":"audit.checkpoint","seq":2}'`);
  stand('sudo', 'if [ "$1" = -u ]; then shift 2; fi\nexec "$@"');
  stand('node', 'echo "node $* (key $GOBLIN_SECRET_KEY_FILE)"\nexec cat');
  for (const [name, body] of Object.entries(extra)) stand(name, body);
  const home = () => temporary(t, 'orbit-docs-audit-home-');
  const env = cwd => ({ PATH: `${bin}${path.delimiter}${process.env.PATH}`, HOME: cwd });
  const run = (line, cwd) =>
    spawnSync('sh', ['-c', `umask 022; ${line}`], { cwd, encoding: 'utf8', env: env(cwd) });
  // The two lines as installation.md prints them. The native one keeps the log in
  // /secure-backups; here, in the run's own home.
  const keeping = section(read('docs/installation.md'), "Keeping Uptime Goblin's log", 3);
  const lines = [...keeping.matchAll(/```sh\n([\s\S]*?)```/g)].map(match => match[1].trim());
  const native = cwd => lines[0].replace('/secure-backups/', `${cwd}/native-`);
  return { home, env, run, lines, native, docker: () => lines[1] };
}

// A check of those lines that needs macOS or Linux is a test of its own, registered through
// platformTest (test/helpers/platform.mjs) only on that platform and listed in
// test/platform-manifest.json, whose coverage check requires a passing run of it there: elsewhere
// it is absent, never counted as passed. What it needs beyond the platform (a user other than
// root, setfacl, a temporary folder that takes access lists) is a prerequisite there, and fails
// the test where it is missing. A check that needs only a user other than root is skipped as root
// with this reason. No other test asks which platform or user it runs as (the last test of these
// says so).
const rootSkip =
  process.getuid?.() === 0 ? 'root reads any file, whatever its mode or access list' : false;

// Docs audit 3 and 12: the commands that keep Uptime Goblin's log make the file private before anything
// is added, the native check writes no copy of the journal, and the update and rollback steps
// keep the log before they recreate the container.
test('keeping Orbit’s log: the export lines make a private file, and every documented recreate keeps the log first', t => {
  const { home, run, lines, native, docker } = logKeeping(t);
  const installation = read('docs/installation.md');
  assert.deepEqual(lines, [KEEP_NATIVE, KEEP_DOCKER]);
  const work = home();
  const kept = run(native(work), work);
  assert.equal(kept.status, 0, kept.stderr);
  const appended = run(docker(), work);
  assert.equal(appended.status, 0, appended.stderr);
  for (const name of ['native-uptime-goblin-journal.txt', 'uptime-goblin-journal.txt']) {
    const file = path.join(work, name);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600, name);
    assert.match(fs.readFileSync(file, 'utf8'), /^\{"orbit":"audit\.checkpoint"/);
  }
  // The native check: one root shell pipes the journal into verify-audit, run as the orbit
  // user with Uptime Goblin's key, and nothing is written beside it.
  const orbitAdmin = section(installation, 'goblin-admin', 3);
  assert.ok(orbitAdmin.includes(`\`\`\`sh\n${CHECK_NATIVE}\n\`\`\``), 'the native check');
  const empty = home();
  const check = run(CHECK_NATIVE, empty);
  assert.equal(check.status, 0, check.stderr);
  assert.equal(
    check.stdout,
    'node /opt/uptime-goblin/lib/cli/goblin-admin.mjs verify-audit --checkpoints - --data-dir /var/lib/uptime-goblin (key /etc/uptime-goblin/secret.key)\n{"orbit":"audit.checkpoint","seq":2}\n'
  );
  assert.deepEqual(fs.readdirSync(empty), []);
  assert.ok(
    flat(installation).includes(
      "Natively, one root shell pipes the journal into the check, which runs as the `uptime-goblin` user, so no copy of the journal is written anywhere (it can hold more than checkpoints: [keeping Uptime Goblin's log](#keeping-uptime-goblins-log)):"
    )
  );
  // Every documented recreate under Docker keeps the log first.
  const exportLine = `\`${KEEP_DOCKER}\``;
  const updates = flat(section(installation, 'Updates and rollback'));
  const step = updates.slice(updates.indexOf('4. For native LXC'));
  assert.ok(
    step.indexOf('`docker compose build --pull`') < step.indexOf(exportLine) &&
      step.indexOf(exportLine) < step.indexOf('`docker compose up -d --no-build`'),
    step.slice(0, 900)
  );
  // The rollback to 1.4.3 under Compose keeps the log before the command that recreates the
  // container (the documented override's up -d).
  const rollback = flat(section(installation, 'Rolling back 1.5 to 1.4.3', 3));
  assert.ok(
    rollback.indexOf(exportLine) > 0 &&
      rollback.indexOf('before any command that recreates the container append its log') > 0 &&
      rollback.indexOf('before any command that recreates the container append its log') <
        rollback.indexOf(exportLine) &&
      rollback.indexOf(exportLine) < rollback.indexOf('docker compose up -d --no-build')
  );
  const compose = read('compose.yaml');
  assert.match(
    compose,
    /# This log holds the audit log's checkpoint lines, and Docker discards it when the container\n\s+# is recreated: append it to a file outside the volume before each docker compose up -d\n\s+# \(docs\/installation\.md, Keeping Uptime Goblin's log\)\.\n\s+logging:/
  );
  // compose.secret.yaml says so before its first up -d, with the export line as a command.
  const overrideText = read('compose.secret.yaml');
  const override = comments(overrideText);
  const keepDocker = KEEP_DOCKER;
  const note = override.indexOf(
    `Every up -d in these notes recreates a running Uptime Goblin's container, and Docker discards its log, which holds the audit log's checkpoint lines: keep it first, appending it to a private file outside the volume with this line (docs/installation.md, Keeping Uptime Goblin's log). It copies a file that is there already into a new one only you can open before it adds to it (a program that opened the old one while it was readable reads nothing added), and never writes through a link. On a Mac, an access list entry the folder hands down to new files (file_inherit in ls -led) reaches the new one too: keep the file in a folder with none. When it prints "Uptime Goblin's log was not kept", it kept nothing, or only part of the log: run up -d only once it is kept. ${keepDocker}`
  );
  assert.ok(note > 0 && note < override.indexOf('docker compose up -d'), override.slice(0, 900));
  assert.ok(overrideText.includes(`\n#   ${keepDocker}\n`), 'a command line of its own');
  // So does installation.md before every start that recreates a running Uptime Goblin's container in
  // the key recipes and the key changes (docs audit, audit 12).
  const key = flat(section(installation, 'Encryption key'));
  assert.ok(
    key.includes(
      `Then keep Uptime Goblin's log, ${exportLine}, since the start recreates the container. Name the override in \`.env\` first, since every command after it needs it, and start Uptime Goblin.`
    )
  );
  assert.ok(
    key.includes(
      `a plain \`docker compose up -d\` could keep it. Keep Uptime Goblin's log first, ${exportLine}, since Docker discards it with that container.`
    )
  );
  const changing = flat(section(installation, 'Changing the key', 4));
  for (const before of [
    'since the start below recreates the container; then:',
    'since this start recreates the container, and start Uptime Goblin; its start line must name the Compose secret with the new key',
  ])
    assert.ok(
      changing
        .toLowerCase()
        .includes(`keep uptime goblin's log, ${exportLine}, ${before}`.toLowerCase()),
      before
    );
  // verify-audit's help gives the same native check, and Docker's pipe.
  assert.ok(verifyHelp.includes(`\n  ${CHECK_NATIVE}\n`), verifyHelp);
  assert.match(
    flat(verifyHelp),
    /Pipe that log in with --checkpoints -, so that no copy of it is written \(it can hold more than checkpoints\)\. Natively, one root shell reads the journal and runs this command as the uptime-goblin user:/
  );
  assert.match(
    flat(verifyHelp),
    /Under Docker Compose, pipe in docker compose logs --no-log-prefix uptime-goblin the same way/
  );
});

// Review of checkpoint 2 (OPS-801-1): umask 077 makes only a new file private, and a file that
// is there already keeps its mode, such as a journal an earlier export made under umask 022.
// Making that file private where it is would not do either: a file's permissions are checked
// only when it is opened, so a reader that opened it while it was readable (another account's
// `tail -f`) goes on reading every line added after a chmod, and on macOS an access list can
// still let others read it. The lines copy it into a new file only its owner can open, put that
// in its place and only then add to it, keeping what it held; they never write through a link,
// symbolic or hard, or to anything but a regular file, leave no copy behind when they fail (a
// run cut short can: the next test) and say when they kept nothing. And no other place writes a
// journal export straight into a file.
test('keeping Orbit’s log: a file an earlier export left readable is replaced by a private copy before anything is added, its lines kept and nothing new reaching a reader that opened it before; a link or a directory is never written to', t => {
  const { home, run, native, docker } = logKeeping(t);
  const older = 'older-export\n';
  // What a run left beside the journal: its temporary copy would be named after it.
  const copies = (directory, name) =>
    fs.readdirSync(directory).filter(entry => entry.startsWith(`${name}.`));
  for (const [name, line] of [
    ['native-uptime-goblin-journal.txt', native],
    ['uptime-goblin-journal.txt', docker],
  ]) {
    const readable = home();
    const file = path.join(readable, name);
    fs.writeFileSync(file, older);
    fs.chmodSync(file, 0o644);
    // A reader that opened the file while it was readable and has read what it held. (An access
    // list on the file, which a chmod leaves in place: the macOS and Linux tests below.)
    const reader = fs.openSync(file, 'r');
    try {
      const result = run(line(readable), readable);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600, `${name}: private before the export`);
      const text = fs.readFileSync(file, 'utf8');
      assert.ok(text.startsWith(older), `${name}: the lines kept before stay`);
      assert.match(text.slice(older.length), /^\{"orbit":"audit\.checkpoint"/);
      const added = Buffer.alloc(4096);
      assert.equal(
        fs.readSync(reader, added, 0, added.length, older.length),
        0,
        `${name}: the reader that opened it before reads nothing added`
      );
    } finally {
      fs.closeSync(reader);
    }
    assert.deepEqual(copies(readable, name), [], `${name}: no copy left behind`);

    // A link, to a file or to nothing, is not followed: the file it names stays as it was, and
    // a missing one is not made.
    for (const target of ['elsewhere.txt', 'missing.txt']) {
      const linked = home();
      const to = path.join(linked, target);
      if (target === 'elsewhere.txt') {
        fs.writeFileSync(to, 'not a journal\n');
        fs.chmodSync(to, 0o644);
      }
      fs.symlinkSync(to, path.join(linked, name));
      const refused = run(line(linked), linked);
      assert.notEqual(refused.status, 0, `${name} -> ${target}`);
      assert.equal(refused.stdout, "Uptime Goblin's log was not kept\n");
      assert.ok(fs.lstatSync(path.join(linked, name)).isSymbolicLink());
      if (target === 'elsewhere.txt') {
        assert.equal(fs.readFileSync(to, 'utf8'), 'not a journal\n');
        assert.equal(fs.statSync(to).mode & 0o777, 0o644);
      } else assert.equal(fs.existsSync(to), false, 'the missing file is not made');
      assert.deepEqual(copies(linked, name), [], `${name} -> ${target}: no copy left behind`);
    }

    // A hard link is not written through either: the other name keeps its lines and its mode,
    // and the journal becomes a private file of its own.
    const hard = home();
    const shared = path.join(hard, 'elsewhere.txt');
    fs.writeFileSync(shared, 'not a journal\n');
    fs.chmodSync(shared, 0o644);
    fs.linkSync(shared, path.join(hard, name));
    const unshared = run(line(hard), hard);
    assert.equal(unshared.status, 0, unshared.stderr);
    assert.equal(fs.readFileSync(shared, 'utf8'), 'not a journal\n');
    assert.equal(fs.statSync(shared).mode & 0o777, 0o644);
    assert.equal(fs.statSync(path.join(hard, name)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(hard, name)).nlink, 1, `${name}: a file of its own`);

    // Nor is anything but a regular file, whose mode stays as it was.
    const other = home();
    fs.mkdirSync(path.join(other, name), { mode: 0o755 });
    fs.chmodSync(path.join(other, name), 0o755);
    const directory = run(line(other), other);
    assert.notEqual(directory.status, 0, name);
    assert.equal(directory.stdout, "Uptime Goblin's log was not kept\n");
    assert.equal(fs.statSync(path.join(other, name)).mode & 0o777, 0o755);
    // (A copy that fails: a test of its own below, since root reads any file.)
  }
  // Every Docker recreate in the docs uses the same line, and nothing writes a journal export
  // into a file without it (the earlier `>> ~/uptime-goblin-journal.txt` and `> uptime-goblin-journal.txt`).
  const installation = read('docs/installation.md');
  assert.equal(installation.split(KEEP_DOCKER).length - 1, 8);
  for (const [name, text] of [
    ['docs/installation.md', installation],
    ['compose.secret.yaml', read('compose.secret.yaml')],
    ['verify-audit help', verifyHelp],
  ])
    assert.doesNotMatch(text, />>?\s*[^\s"]*orbit-journal/, name);
  assert.ok(
    flat(section(installation, "Keeping Uptime Goblin's log", 3)).includes(
      "The two lines that keep the log add only to a file that no one else can open, unless its folder hands an access list down to new files (below). `umask 077` makes a new file private from its first byte, but leaves a file that is there already as it was, such as one an export without `umask 077` left readable to every local account. `chmod 600` would not make that one private: a program that opened it while it was readable, such as another account's `tail -f`, goes on reading everything added to it, since a file's permissions are checked only when it is opened, and on macOS an access list (`ls -le`) can let others read a file whatever its mode. So each line first copies what the file holds into a new file beside it that only you can open (`mktemp`), puts that one in its place and only then adds to it: what the old file held may have been read already, but nothing added from then on can be. On macOS a new file also takes the access list entries its folder hands down to new files, and they can let others read it whatever its mode: if `ls -led` on the folder lists one with `file_inherit`, keep the file in a folder that hands none down. Your home folder hands none down as macOS sets it up (its one entry, `group:everyone deny delete`, has no `file_inherit`); on Linux a folder's default access list does not open the copy: `mktemp` makes it with mode 0600, and that mode masks the entries it hands down. Each run needs room for a second copy of the file while it copies, and a run cut short meanwhile, such as by Ctrl-C, can leave that copy beside the file, named `uptime-goblin-journal.txt.` and six more characters: it holds nothing the file does not, so delete it. Neither line writes through a link, or to anything but a regular file. When one prints \"Uptime Goblin's log was not kept\", the file is a link, is not a regular file or is not yours to change (`touch` then says why), or the copy or the export failed: it added nothing, or only what the export printed before it failed (a line kept twice does no harm, so run it again once the cause is fixed). Under Docker Compose, do not recreate the container until the log is kept."
    )
  );
});

// Review of checkpoint 2, F1 round 2: the limits of those lines hold as the docs give them. A
// run cut short between the copy and its move (Ctrl-C sends SIGINT to every process of the run)
// leaves that copy beside the file, private and holding nothing the file does not, and a later
// run does not remove it. An export that prints lines and then fails prints "Uptime Goblin's log was not
// kept", having added those lines. (What a folder's access list does to the new file: the macOS
// and Linux tests below, each registered only on its platform.)
test('keeping Orbit’s log: a run cut short leaves its copy, and a failed export may have added lines, as the docs say', async t => {
  const keeping = flat(section(read('docs/installation.md'), "Keeping Uptime Goblin's log", 3));
  assert.ok(
    keeping.includes(
      'On macOS a new file also takes the access list entries its folder hands down to new files, and they can let others read it whatever its mode: if `ls -led` on the folder lists one with `file_inherit`, keep the file in a folder that hands none down.'
    )
  );
  assert.ok(
    keeping.includes(
      'a run cut short meanwhile, such as by Ctrl-C, can leave that copy beside the file, named `uptime-goblin-journal.txt.` and six more characters: it holds nothing the file does not, so delete it.'
    )
  );
  assert.ok(
    keeping.includes(
      'or the copy or the export failed: it added nothing, or only what the export printed before it failed'
    )
  );
  const { home, run, native, docker } = logKeeping(t);
  // The run is a process group of its own (its shell's id is the group's), and an mv stand-in
  // sends SIGINT to that group once the copy is made, before anything is moved, as Ctrl-C would.
  // A group that is not the run's is not there, so nothing else is signalled.
  const cut = logKeeping(t, { mv: 'kill -s INT -- "-$RUN_GROUP"\nexit 1' });
  const cutShort = (line, cwd) =>
    new Promise((resolve, reject) => {
      const child = spawn('sh', ['-c', `RUN_GROUP=$$; export RUN_GROUP; umask 022; ${line}`], {
        cwd,
        env: cut.env(cwd),
        detached: true,
        stdio: 'ignore',
      });
      child.on('error', reject);
      child.on('exit', (code, signal) => resolve({ code, signal }));
    });
  // An export that prints a checkpoint line and then fails.
  const failing = logKeeping(t, {
    docker: `echo '{"orbit":"audit.checkpoint","seq":9}'\nexit 1`,
    journalctl: `echo '{"orbit":"audit.checkpoint","seq":9}'\nexit 1`,
  });
  const older = 'older-export\n';
  const copies = (directory, name) =>
    fs.readdirSync(directory).filter(entry => entry.startsWith(`${name}.`));
  for (const [name, line] of [
    ['native-uptime-goblin-journal.txt', native],
    ['uptime-goblin-journal.txt', docker],
  ]) {
    // A run cut short after the copy and before its move: the file stays as it was, and the
    // copy stays beside it, private, holding what the file holds.
    const interrupted = home();
    const file = path.join(interrupted, name);
    fs.writeFileSync(file, older);
    fs.chmodSync(file, 0o644);
    const end = await cutShort(line(interrupted), interrupted);
    assert.ok(end.code !== 0, `${name}: cut short (${end.code}, ${end.signal})`);
    assert.equal(fs.readFileSync(file, 'utf8'), older);
    assert.equal(fs.statSync(file).mode & 0o777, 0o644);
    const left = copies(interrupted, name);
    assert.equal(left.length, 1, `${name}: ${left}`);
    assert.equal(left[0].length, name.length + 7, `${name}: named after it with six more: ${left}`);
    const copy = path.join(interrupted, left[0]);
    assert.equal(fs.statSync(copy).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(copy, 'utf8'), older);
    // A later run keeps the log and leaves that copy where it is: it is for you to delete.
    const later = run(line(interrupted), interrupted);
    assert.equal(later.status, 0, later.stderr);
    assert.match(fs.readFileSync(file, 'utf8'), /^older-export\n\{"orbit":"audit\.checkpoint"/);
    assert.deepEqual(copies(interrupted, name), left);

    // An export that fails after printing a line: "not kept", and that line is added after the
    // lines the file held, in the private copy.
    const partial = home();
    const journal = path.join(partial, name);
    fs.writeFileSync(journal, older);
    fs.chmodSync(journal, 0o644);
    const failed = failing.run(line(partial), partial);
    assert.notEqual(failed.status, 0, name);
    assert.equal(failed.stdout, "Uptime Goblin's log was not kept\n");
    assert.equal(
      fs.readFileSync(journal, 'utf8'),
      `${older}{"orbit":"audit.checkpoint","seq":9}\n`
    );
    assert.equal(fs.statSync(journal).mode & 0o777, 0o600);
    assert.deepEqual(copies(partial, name), [], `${name}: no copy left after a failed export`);
  }
});

// A copy that fails, here because the file's owner cannot read it, adds nothing, leaves the file
// as it was and no copy beside it, and says so. Root reads any file, so this needs another user.
test(
  'keeping Orbit’s log: a copy that fails adds nothing and leaves the file as it was, with no copy beside it',
  { skip: rootSkip },
  t => {
    const { home, run, native, docker } = logKeeping(t);
    const older = 'older-export\n';
    for (const [name, line] of [
      ['native-uptime-goblin-journal.txt', native],
      ['uptime-goblin-journal.txt', docker],
    ]) {
      const unreadable = home();
      const locked = path.join(unreadable, name);
      fs.writeFileSync(locked, older);
      fs.chmodSync(locked, 0o200);
      const failed = run(line(unreadable), unreadable);
      assert.notEqual(failed.status, 0, name);
      assert.equal(failed.stdout, "Uptime Goblin's log was not kept\n");
      assert.equal(fs.statSync(locked).mode & 0o777, 0o200);
      fs.chmodSync(locked, 0o600);
      assert.equal(fs.readFileSync(locked, 'utf8'), older);
      assert.deepEqual(fs.readdirSync(unreadable), [name], `${name}: no copy left behind`);
    }
  }
);

// On macOS an access list on a file (`ls -le`) can let others read it whatever its mode, and a
// chmod leaves it in place. The new file the lines put in the old one's place does not take it:
// no entry lets others read it, neither its own nor one handed down (this home hands none down;
// a folder that does is the next test's).
platformTest(
  import.meta.url,
  'docs-audit.log-acl.darwin-file',
  'keeping Orbit’s log on macOS: an access list that lets everyone read a file an earlier export left does not reach the private copy',
  {},
  t => {
    const { home, run, native, docker } = logKeeping(t);
    const older = 'older-export\n';
    const entries = file => spawnSync('ls', ['-le', file], { encoding: 'utf8' }).stdout;
    for (const [name, line] of [
      ['native-uptime-goblin-journal.txt', native],
      ['uptime-goblin-journal.txt', docker],
    ]) {
      const readable = home();
      const file = path.join(readable, name);
      fs.writeFileSync(file, older);
      fs.chmodSync(file, 0o644);
      const added = spawnSync('chmod', ['+a', 'everyone allow read', file], { encoding: 'utf8' });
      assert.equal(added.status, 0, added.stderr);
      assert.match(entries(file), /\beveryone allow read\b/, `${name}: the old file has it`);
      const result = run(line(readable), readable);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600, name);
      assert.match(fs.readFileSync(file, 'utf8'), /^older-export\n\{"orbit":"audit\.checkpoint"/);
      assert.doesNotMatch(
        entries(file),
        /\ballow\b[^\n]*\bread\b/,
        `${name}: no access list lets others read it`
      );
      assert.deepEqual(fs.readdirSync(readable), [name], `${name}: no copy left behind`);
    }
  }
);

// On macOS a new file takes the access list entries its folder hands down (file_inherit), and
// they let others read it whatever its mode, so the copy is private only in a folder that hands
// none down; `ls -led` on the folder shows them. Root reads any file anyway, so this needs
// another user.
platformTest(
  import.meta.url,
  'docs-audit.log-acl.darwin-inherited',
  'keeping Orbit’s log on macOS: an access list entry the folder hands down reaches the new file and lets others read it whatever its mode, as the docs say',
  {},
  t => {
    assert.ok(
      flat(section(read('docs/installation.md'), "Keeping Uptime Goblin's log", 3)).includes(
        'On macOS a new file also takes the access list entries its folder hands down to new files, and they can let others read it whatever its mode: if `ls -led` on the folder lists one with `file_inherit`, keep the file in a folder that hands none down.'
      )
    );
    const { home, run, native, docker } = logKeeping(t);
    const older = 'older-export\n';
    const ls = (flags, file) => spawnSync('ls', [flags, file], { encoding: 'utf8' }).stdout;
    for (const [name, line] of [
      ['native-uptime-goblin-journal.txt', native],
      ['uptime-goblin-journal.txt', docker],
    ]) {
      const handing = home();
      const added = spawnSync('chmod', ['+a', 'everyone allow read,file_inherit', handing], {
        encoding: 'utf8',
      });
      assert.equal(added.status, 0, added.stderr);
      assert.match(ls('-led', handing), /\bfile_inherit\b/, 'the check the docs give shows it');
      const file = path.join(handing, name);
      fs.writeFileSync(file, older);
      fs.chmodSync(file, 0o644);
      const kept = run(line(handing), handing);
      assert.equal(kept.status, 0, kept.stderr);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600, name);
      assert.match(ls('-le', file), /\beveryone inherited allow read\b/, name);
      // That entry opens it whatever its mode: with none, it is still read, and only without
      // the entry is it refused.
      fs.chmodSync(file, 0);
      try {
        assert.match(fs.readFileSync(file, 'utf8'), /^older-export\n\{"orbit":"audit\.checkpoint"/);
        assert.equal(spawnSync('chmod', ['-N', file]).status, 0);
        assert.throws(() => fs.readFileSync(file), { code: 'EACCES' }, name);
      } finally {
        fs.chmodSync(file, 0o600);
      }
      assert.deepEqual(fs.readdirSync(handing), [name], `${name}: no copy left behind`);
    }
  }
);

// On Linux a folder's default access list hands its entries down to a new file too, and a file
// made the usual way (opened with mode 0666) gets them open whatever the umask: there `umask 077`
// does not hold. mktemp makes its file with mode 0600, and on a file with an access list the
// group bits of the mode are its mask, so every entry handed down is masked to nothing and the
// copy stays private. An access list on the old file does not reach the copy at all.
platformTest(
  import.meta.url,
  'docs-audit.log-acl.linux',
  'keeping Orbit’s log on Linux: the entries a folder’s default access list hands down reach the new file masked by its mode 0600, and an access list on the old file does not reach it, as the docs say',
  {},
  t => {
    assert.ok(
      flat(section(read('docs/installation.md'), "Keeping Uptime Goblin's log", 3)).includes(
        "on Linux a folder's default access list does not open the copy: `mktemp` makes it with mode 0600, and that mode masks the entries it hands down."
      )
    );
    const { home, run, native, docker } = logKeeping(t);
    const older = 'older-export\n';
    const setfacl = (...args) => spawnSync('setfacl', args, { encoding: 'utf8' });
    const getfacl = file => {
      const shown = spawnSync('getfacl', ['-c', '-n', file], { encoding: 'utf8' });
      assert.equal(shown.status, 0, shown.stderr);
      return shown.stdout;
    };
    // Read and write for another user (65534) and read for everyone, handed down to new files.
    const handDown = folder => setfacl('-d', '-m', 'u::rw,u:65534:rw,g::r,m::rw,o::r', folder);
    // Its prerequisite acl-tmpdir: a temporary folder that takes access lists. Without one this
    // fails, naming the cause (it was a skip).
    const probe = handDown(home());
    assert.equal(
      probe.status,
      0,
      `the temporary folder's file system must take access lists (acl-tmpdir): ${probe.stderr.trim()}`
    );
    for (const [name, line] of [
      ['native-uptime-goblin-journal.txt', native],
      ['uptime-goblin-journal.txt', docker],
    ]) {
      // With a file an earlier export left there, and with none.
      for (const before of [older, '']) {
        const handing = home();
        const handed = handDown(handing);
        assert.equal(handed.status, 0, handed.stderr);
        // A file made the usual way there gets the entries, open, under umask 077.
        const usual = path.join(handing, 'usual.txt');
        const made = spawnSync('sh', ['-c', 'umask 077 && : > usual.txt'], { cwd: handing });
        assert.equal(made.status, 0);
        assert.equal(fs.statSync(usual).mode & 0o777, 0o664, 'the umask does not hold');
        assert.match(getfacl(usual), /^user:65534:rw-$/m);
        const file = path.join(handing, name);
        if (before) {
          fs.writeFileSync(file, before);
          fs.chmodSync(file, 0o644);
        }
        const kept = run(line(handing), handing);
        assert.equal(kept.status, 0, kept.stderr);
        assert.equal(fs.statSync(file).mode & 0o777, 0o600, name);
        const entries = getfacl(file);
        assert.match(entries, /^user:65534:rw-/m, `${name}: the entry is handed down`);
        assert.match(entries, /^mask::---$/m, `${name}: and masked to nothing`);
        assert.match(entries, /^other::---$/m, name);
        assert.ok(fs.readFileSync(file, 'utf8').startsWith(`${before}{"orbit":"audit.checkpoint"`));
        assert.deepEqual(fs.readdirSync(handing).sort(), [name, 'usual.txt'].sort(), 'no copy');
      }
      // An access list that lets another user read a file an earlier export left, in a folder
      // that hands none down: the copy has no such entry.
      const plain = home();
      const file = path.join(plain, name);
      fs.writeFileSync(file, older);
      fs.chmodSync(file, 0o644);
      const added = setfacl('-m', 'u::rw,u:65534:r,g::r,m::r,o::r', file);
      assert.equal(added.status, 0, added.stderr);
      assert.match(getfacl(file), /^user:65534:r--$/m, `${name}: the old file has it`);
      const kept = run(line(plain), plain);
      assert.equal(kept.status, 0, kept.stderr);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600, name);
      assert.doesNotMatch(getfacl(file), /^user:65534/m, `${name}: the entry is not carried over`);
      assert.ok(fs.readFileSync(file, 'utf8').startsWith(`${older}{"orbit":"audit.checkpoint"`));
      assert.deepEqual(fs.readdirSync(plain), [name], `${name}: no copy left behind`);
    }
  }
);

// Review of checkpoint 2, F1 round 2: under Linux, where CI runs, the macOS checks of the lines
// that keep Uptime Goblin's log were left out inside tests that still passed, with nothing to say so. In
// this file no test asks which platform it runs on: the platform's tests are registered through
// platformTest with an entry of test/platform-manifest.json each, so the coverage check requires
// a passing run of each on its platform. Only rootSkip asks which user runs it, and it is a skip.
test('no check in this file is left out by platform or user without the manifest or a skip saying so', () => {
  const source = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const lines = source.split('\n');
  const asking = lines.flatMap((text, at) =>
    /process\.(platform|getuid)|os\.platform\(/.test(text.replace(/\/\/.*$/, '')) ? [at] : []
  );
  assert.ok(asking.length >= 1, 'rootSkip asks');
  for (const at of asking) {
    let start = at;
    while (start > 0 && /^\s/.test(lines[start])) start--;
    assert.match(
      lines[start],
      /^const rootSkip =/,
      `line ${at + 1} asks outside rootSkip: ${lines[at].trim()}`
    );
  }
  assert.deepEqual(
    [...source.matchAll(/^const (\w+Skip) =/gm)].map(match => match[1]),
    ['rootSkip']
  );
  assert.match(source, /\{ skip: rootSkip \}/, 'rootSkip is a skip');
  // Each platform test of this file in the manifest is registered through platformTest once.
  const manifest = JSON.parse(read('test/platform-manifest.json'));
  const ids = manifest.entries
    .filter(entry => entry.file === 'test/docs-audit.test.mjs')
    .map(entry => entry.id);
  assert.deepEqual(ids, [
    'docs-audit.log-acl.darwin-file',
    'docs-audit.log-acl.darwin-inherited',
    'docs-audit.log-acl.linux',
  ]);
  for (const id of ids)
    assert.equal(
      [...source.matchAll(/platformTest\(\s*import\.meta\.url,\s*'([^']+)'/g)].filter(
        match => match[1] === id
      ).length,
      1,
      id
    );
});

// Docs audit 14 and 20: the README introduces the audit log, security.md lists what Uptime Goblin
// records about the account and the log itself, and the links the audit docs add resolve.
test('the README and security.md name the audit log and what it records, and every link added resolves', () => {
  const readme = flat(read('README.md'));
  assert.ok(readme.includes('**Configure → Audit log** records sign-ins and sign-outs'));
  assert.ok(readme.includes('[the audit log](docs/security.md#audit-log)'));
  assert.ok(
    readme.includes(
      '| [Security](docs/security.md) | Trust boundaries, secrets, the audit log and its limits,'
    )
  );
  for (const action of [
    'account.bootstrap',
    'account.claimed',
    'identity.mirror.failed',
    'audit.pruned',
    'audit.gap',
  ])
    assert.ok(AUDIT_TEXTS[action], action);
  const recorded = flat(read('docs/security.md'));
  assert.ok(
    recorded.includes(
      'how the admin account was set up (from `GOBLIN_PASSWORD`, from `auth.json`, or kept from `control.sqlite` and written to `auth.json`; entries of earlier 1.5 pre-releases can also say without a password, for their local preview) and each failure to update `auth.json`;'
    )
  );
  assert.ok(recorded.includes("the log's own prunes and the gaps Uptime Goblin finds in it;"));
  for (const [file, target] of [
    ['README.md', 'docs/security.md#audit-log'],
    ['docs/security.md', 'troubleshooting.md#uptime-goblins-log-mentions-old-audit-entries'],
    ['docs/troubleshooting.md', '#uptime-goblins-log-mentions-old-audit-entries'],
    ['docs/troubleshooting.md', '#uptime-goblin-cannot-write-its-audit-log'],
    ['docs/troubleshooting.md', 'installation.md#goblin-admin'],
    ['docs/configuration.md', '#exporting-from-a-script'],
    ['docs/configuration.md', 'security.md#audit-log'],
    ['docs/installation.md', '#keeping-uptime-goblins-log'],
    ['docs/installation.md', 'security.md#audit-log'],
    ['docs/authentication.md', 'security.md#audit-log'],
    ['docs/notifications.md', 'security.md#audit-log'],
    ['docs/architecture.md', 'security.md#audit-log'],
    ['CHANGELOG.md', 'docs/security.md#audit-log'],
  ])
    assertLink(file, target);
});

// An audit.pruned entry whose prune removed expired entries and entries beyond the 250,000 cap
// together (reason 'both') says both. It read as cap-only, although security.md lists the log's
// own prunes among what Uptime Goblin records.
test('a prune by age and by the cap together reads as both on the Audit log page', () => {
  const read = reason =>
    sentence({ action: 'audit.pruned', outcome: 'info', detail: { reason, deleted: 100 } });
  assert.equal(read('age'), 'Removed {deleted} audit entries older than the retention period');
  assert.equal(read('cap'), 'Removed {deleted} audit entries to stay within 250,000');
  assert.equal(
    read('both'),
    'Removed {deleted} audit entries older than the retention period and to stay within 250,000'
  );
});
