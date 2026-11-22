// goblin-admin display code / list / cancel (B6 design §7.3).
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { main } from '../../lib/cli/goblin-admin.mjs';
import { acquireLock } from '../../lib/db/lock.mjs';
import { startControl } from '../../lib/db/control.mjs';
import { controlFileIdentity } from '../../lib/identity/bootstrap.mjs';
import { identityOps } from '../../lib/repo/identity.mjs';
import { displayCodeHash } from '../../lib/identity/secrets.mjs';
import { outputProblem } from '../../lib/cli/commands/display.mjs';
import { temporary } from './helpers.mjs';

const release = JSON.parse(
  fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')
).version;
const hexKey = 'a1'.repeat(16) + 'b2'.repeat(16);
const now = Date.UTC(2026, 8, 29, 12);
const noProcesses = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-no-proc-'));
after(() => fs.rmSync(noProcesses, { recursive: true, force: true }));
const terminal = () => ({ isSocket: () => false, dev: 1, ino: 2 });

async function admin(
  args,
  { directory, key = true, outputStat = terminal, container = false, proc = noProcesses } = {}
) {
  let out = '',
    err = '';
  const code = await main([...args, '--data-dir', directory], {
    env: key ? { GOBLIN_SECRET_KEY: hexKey } : {},
    uid: 1000,
    container,
    proc,
    outputStat,
    stdout: text => (out += text),
    stderr: text => (err += text),
    clock: () => now,
    keySources: {
      credentialsDirectory: path.join(directory, 'no-credentials'),
      secretsDirectory: path.join(directory, 'no-secrets'),
    },
  });
  return { code, out, err, json: () => JSON.parse(out) };
}

async function started(t) {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = acquireLock(directory);
  try {
    const result = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release,
      env: { GOBLIN_SECRET_KEY: hexKey },
      keySources: {
        credentialsDirectory: path.join(directory, 'no-credentials'),
        secretsDirectory: path.join(directory, 'no-secrets'),
      },
    });
    // This fixture represents a completed credential-aware startup, not just schema setup.
    await result.control.db.write(tx =>
      identityOps.setSetting(
        tx,
        'tokens.anchor',
        JSON.stringify({
          controlFile: controlFileIdentity(result.control.file),
          restoreSeen: null,
        }),
        now
      )
    );
    result.control.close();
  } finally {
    lock.release();
  }
  return directory;
}

function query(directory, text, ...params) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db.prepare(text).all(...params);
  } finally {
    db.close();
  }
}

test('display code prints a code once, stores only its hash, and audits its creation', async t => {
  const directory = await started(t);
  const made = await admin(['display', 'code', '--name', 'Lobby TV', '--json'], { directory });
  assert.equal(made.code, 0, made.err);
  const { id, name, code, expiresAt } = made.json();
  assert.match(id, /^d_/);
  assert.equal(name, 'Lobby TV');
  assert.equal(expiresAt, now + 10 * 60e3);
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){4}-[0-9A-HJKMNP-TV-Z]$/);
  const [row] = query(directory, 'SELECT * FROM displays WHERE id = ?', id);
  assert.equal(row.state, 'waiting');
  assert.equal(row.origin, 'cli');
  assert.equal(row.created_session, null);
  assert.equal(row.code_hash, displayCodeHash(code));
  assert.equal(row.code_expires_at, expiresAt);
  const raw = fs.readFileSync(path.join(directory, 'control.sqlite'));
  assert.equal(raw.includes(code.replaceAll('-', '')), false, 'the code is not stored');
  const audited = query(
    directory,
    "SELECT * FROM audit_log WHERE action = 'display.code.created' AND target_id = ?",
    id
  );
  assert.equal(audited.length, 1);
  assert.equal(JSON.stringify(audited).includes(code.replaceAll('-', '').slice(0, 25)), false);

  const text = await admin(['display', 'code', '--name', 'Hall'], { directory });
  assert.equal(text.code, 0, text.err);
  assert.match(text.out, /valid once until/);
  assert.match(text.out, /\?kiosk=1/);
  assert.match(text.out, /goblin-admin display cancel d_/);
});

test('display code needs the key, a name, and a terminal; it caps waiting codes', async t => {
  const directory = await started(t);
  const nameless = await admin(['display', 'code'], { directory });
  assert.equal(nameless.code, 2);
  assert.match(nameless.err, /needs --name/);
  const long = await admin(['display', 'code', '--name', 'x'.repeat(65)], { directory });
  assert.equal(long.code, 2);
  const control = await admin(['display', 'code', '--name', 'a\u001b[2Jb'], { directory });
  assert.equal(control.code, 2);
  const keyless = await admin(['display', 'code', '--name', 'Lobby'], { directory, key: false });
  assert.equal(keyless.code, 1);
  assert.match(keyless.err, /No encryption key reached this command/);
  assert.match(keyless.err, /display code/);
  const socket = await admin(['display', 'code', '--name', 'Lobby'], {
    directory,
    outputStat: () => ({ isSocket: () => true }),
  });
  assert.equal(socket.code, 1);
  assert.match(socket.err, /socket/);
  assert.equal(query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n, 0);

  for (let i = 0; i < 10; i++)
    assert.equal((await admin(['display', 'code', '--name', `D${i}`], { directory })).code, 0);
  const capped = await admin(['display', 'code', '--name', 'One more'], { directory });
  assert.equal(capped.code, 1);
  assert.match(capped.err, /10 display codes are already waiting/);
});

test('outputProblem refuses the systemd journal and sockets, not pipes or terminals', () => {
  assert.equal(outputProblem({}, null), null);
  assert.equal(outputProblem({}, terminal()), null);
  assert.match(outputProblem({ JOURNAL_STREAM: '1:2' }, terminal()), /journal/);
  assert.equal(outputProblem({ JOURNAL_STREAM: '1:3' }, terminal()), null);
  assert.match(outputProblem({}, { isSocket: () => true }), /socket/);
});

test('display cancel stops one code or every waiting code, with or without the key', async t => {
  const directory = await started(t);
  const ids = [];
  for (const name of ['A', 'B', 'C'])
    ids.push((await admin(['display', 'code', '--name', name, '--json'], { directory })).json().id);

  const one = await admin(['display', 'cancel', ids[0]], { directory });
  assert.equal(one.code, 0, one.err);
  assert.match(one.out, new RegExp(`Cancelled display code ${ids[0]}`));
  const again = await admin(['display', 'cancel', ids[0]], { directory });
  assert.equal(again.code, 1);
  assert.match(again.err, /No waiting display code/);
  const bogus = await admin(['display', 'cancel', 'nope'], { directory });
  assert.equal(bogus.code, 1);
  assert.equal((await admin(['display', 'cancel'], { directory })).code, 2);
  assert.equal((await admin(['display', 'cancel', ids[1], '--all'], { directory })).code, 2);

  const keyless = await admin(['display', 'cancel', '--all'], { directory, key: false });
  assert.equal(keyless.code, 0, keyless.err);
  assert.match(keyless.out, /Cancelled 2 waiting display codes/);
  assert.match(keyless.err, /writes the audit entry for this cancellation/);
  const rows = query(directory, 'SELECT id, state, cancel_cause FROM displays ORDER BY id');
  assert.ok(rows.every(row => row.state === 'cancelled' && row.cancel_cause === 'cancelled'));

  const audited = query(
    directory,
    "SELECT target_id FROM audit_log WHERE action = 'display.code.cancelled'"
  );
  assert.deepEqual(
    audited.map(row => row.target_id),
    [ids[0]],
    'the keyless cancel owes its entry to Uptime Goblin'
  );
  const none = await admin(['display', 'cancel', '--all'], { directory });
  assert.equal(none.code, 0);
  assert.match(none.out, /No display code was waiting/);
});

test('display list shows every kept code without a code or its hash, and needs no key', async t => {
  const directory = await started(t);
  const empty = await admin(['display', 'list'], { directory, key: false });
  assert.equal(empty.code, 0, empty.err);
  assert.match(empty.out, /No display codes are kept/);
  const made = [];
  for (const name of ['Lobby', 'Hall'])
    made.push((await admin(['display', 'code', '--name', name, '--json'], { directory })).json());
  assert.equal((await admin(['display', 'cancel', made[0].id], { directory })).code, 0);

  const listed = await admin(['display', 'list', '--json'], { directory, key: false });
  assert.equal(listed.code, 0, listed.err);
  const { displays } = listed.json();
  // Both were made at the test's one clock time, so their order is not the point here.
  assert.deepEqual(
    displays
      .map(row => [row.name, row.origin, row.state, row.cancelCause])
      .sort(([a], [b]) => a.localeCompare(b)),
    [
      ['Hall', 'cli', 'waiting', null],
      ['Lobby', 'cli', 'cancelled', 'cancelled'],
    ]
  );
  assert.deepEqual(Object.keys(displays[0]).sort(), [
    'cancelCause',
    'cancelledAt',
    'createdAt',
    'createdBy',
    'expiresAt',
    'id',
    'name',
    'origin',
    'redeemedAt',
    'redeemedClient',
    'sessionId',
    'state',
  ]);
  for (const secret of made.map(m => m.code.replaceAll('-', '').slice(0, 25)))
    assert.equal(listed.out.includes(secret), false);
  for (const row of query(directory, 'SELECT code_hash FROM displays'))
    assert.equal(listed.out.includes(row.code_hash), false);
  const text = await admin(['display', 'list'], { directory, key: false });
  assert.match(text.out, /"Hall" {2}waiting until/);
  assert.match(text.out, /"Lobby" {2}cancelled .*\(cancelled\)/);
  assert.equal((await admin(['display', 'list', '--all'], { directory })).code, 2);
  assert.equal((await admin(['display', 'list', 'extra'], { directory })).code, 2);
});

function serverProc(t, directory) {
  const proc = temporary(t),
    pid = path.join(proc, '4242');
  fs.mkdirSync(pid);
  fs.writeFileSync(path.join(pid, 'cmdline'), ['node', '/app/server.mjs', ''].join('\0'));
  fs.writeFileSync(path.join(pid, 'environ'), [`GOBLIN_DATA_DIR=${directory}`, ''].join('\0'));
  fs.symlinkSync(directory, path.join(pid, 'cwd'));
  return proc;
}

test('container display code refuses retained run output; exec with a matching server is allowed', async t => {
  const directory = await started(t);
  for (const proc of [noProcesses, path.join(directory, 'missing-proc')]) {
    const denied = await admin(['display', 'code', '--name', 'Fixture', '--json'], {
      directory,
      container: true,
      proc,
    });
    assert.equal(denied.code, 1, denied.err);
    assert.equal(denied.out, '');
    assert.match(denied.err, /docker compose exec/);
    assert.equal(query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n, 0);
  }
  const proc = serverProc(t, directory);
  const allowed = await admin(['display', 'code', '--name', 'Fixture', '--json'], {
    directory,
    container: true,
    proc,
  });
  assert.equal(allowed.code, 0, allowed.err);
  assert.ok(allowed.json().code);
  const keyless = await admin(['display', 'code', '--name', 'Fixture'], {
    directory,
    container: true,
    proc,
    key: false,
  });
  assert.equal(keyless.code, 1);
  assert.match(keyless.err, /docker compose exec/);
  assert.doesNotMatch(keyless.err, /compose\.secret\.yaml run/);
});

test('display code refuses a restore marker not processed by a server start', async t => {
  const directory = await started(t);
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  try {
    db.prepare('INSERT OR REPLACE INTO meta(key,value,updated_at) VALUES (?,?,?)').run(
      'restored',
      '{"snapshot":"fixture"}',
      now
    );
  } finally {
    db.close();
  }
  const denied = await admin(['display', 'code', '--name', 'Fixture', '--json'], { directory });
  assert.equal(denied.code, 1, denied.err);
  assert.equal(denied.out, '');
  assert.match(denied.err, /Start Uptime Goblin once/);
  assert.equal(query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n, 0);
});

test('display code accepts a processed restore but refuses a subsequently copied control file', async t => {
  const { controlFileIdentity } = await import('../../lib/identity/bootstrap.mjs');
  const directory = await started(t),
    file = path.join(directory, 'control.sqlite');
  const marker = '{"snapshot":"fixture-processed"}';
  const db = new DatabaseSync(file);
  try {
    db.prepare('INSERT OR REPLACE INTO meta(key,value,updated_at) VALUES (?,?,?)').run(
      'restored',
      marker,
      now
    );
    for (const [key, value] of [
      ['builtin.restoreSeen', marker],
      ['builtin.controlFile', controlFileIdentity(file)],
      [
        'tokens.anchor',
        JSON.stringify({ controlFile: controlFileIdentity(file), restoreSeen: marker }),
      ],
    ])
      db.prepare(
        'INSERT OR REPLACE INTO identity_settings(key,value,updated_at) VALUES (?,?,?)'
      ).run(key, value, now);
  } finally {
    db.close();
  }
  const allowed = await admin(['display', 'code', '--name', 'Fixture'], { directory });
  assert.equal(allowed.code, 0, allowed.err);
  const count = query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n;
  fs.copyFileSync(file, file + '.replacement');
  fs.renameSync(file + '.replacement', file);
  const denied = await admin(['display', 'code', '--name', 'Fixture'], { directory });
  assert.equal(denied.code, 1, denied.err);
  assert.equal(denied.out, '');
  assert.match(denied.err, /Start Uptime Goblin once/);
  assert.equal(query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n, count);
});

test('display code refuses a stale or missing credential anchor even when builtin markers are current', async t => {
  for (const mode of ['missing', 'malformed', 'stale']) {
    const directory = await started(t),
      file = path.join(directory, 'control.sqlite');
    const made = await admin(['display', 'code', '--name', 'Fixture'], { directory });
    assert.equal(made.code, 0, made.err);
    const db = new DatabaseSync(file);
    try {
      if (mode === 'missing')
        db.prepare("DELETE FROM identity_settings WHERE key='tokens.anchor'").run();
      else
        db.prepare("UPDATE identity_settings SET value=? WHERE key='tokens.anchor'").run(
          mode === 'malformed'
            ? '{'
            : JSON.stringify({ controlFile: '{"ino":"old-file"}', restoreSeen: null })
        );
    } finally {
      db.close();
    }
    const denied = await admin(['display', 'code', '--name', 'Fixture'], { directory });
    assert.equal(denied.code, 1);
    assert.equal(denied.out, '');
    assert.match(denied.err, /Start Uptime Goblin once/);
    assert.equal(query(directory, 'SELECT COUNT(*) AS n FROM displays')[0].n, 1);
  }
});
