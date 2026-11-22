// The audit milestone's Phase 0 contract data (audit spec §2.1 items 11 and 16): the catalogue of
// lib/audit/actions.mjs, test/contract/audit-bodies.json and the canary helper. Every lane builds
// on these, so their shape is checked here once: the bodies hold every entry §6.6 names, with the
// frozen texts, and the catalogue's texts name only what its rows hold.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  ACTIONS,
  ACTOR_TYPES,
  ANCHOR_TEXTS,
  AUDIT_KINDS,
  AUDIT_TEXTS,
  CODE_WORDS,
  MAX_ROWS,
  META_KEYS,
  OUTCOMES,
  PROBLEM_TEXTS,
  RETENTION_DEFAULT_DAYS,
  UNVERIFIABLE_TEXTS,
  VIAS,
  auditTime,
  eventFrom,
} from '../../lib/audit/actions.mjs';
import { auditError, QUERY_RULES } from '../../lib/audit/errors.mjs';
import { formatTime } from '../../lib/cli/common.mjs';
import {
  auditBody,
  bodyMismatches,
  bodyNow,
  concreteBody,
  matchesBody,
} from '../helpers/fake-audit.mjs';
import { auditSentinels, findSentinels } from '../helpers/audit-sentinels.mjs';

const brokenCodes = [
  'start_missing',
  'link_broken',
  'seq_gap',
  'hash_mismatch',
  'head_mismatch',
  'checkpoint_mismatch',
  'checkpoint_mac',
  'journal_mismatch',
  'journal_ahead',
  'log_truncated',
  'key_lost',
  'unreadable',
];

test('the catalogue: 49 actions, each with its modes, targets, outcomes, detail keys and inbox flag', () => {
  assert.equal(Object.keys(ACTIONS).length, 49);
  assert.deepEqual(OUTCOMES, ['attempt', 'ok', 'denied', 'failed', 'conflict', 'info']);
  assert.deepEqual(ACTOR_TYPES, ['user', 'anonymous', 'system', 'cli']);
  assert.deepEqual(VIAS, ['session', 'basic', 'local', 'cli', 'system', 'kiosk']);
  assert.deepEqual(AUDIT_KINDS, [
    'none',
    'identity',
    'config',
    'delivery',
    'channel',
    'secret',
    'operation',
    'export',
  ]);
  assert.equal(META_KEYS.length, 8);
  for (const [action, entry] of Object.entries(ACTIONS)) {
    assert.match(action, /^[a-z][a-z0-9.-]{0,63}$/, action);
    assert.ok(Object.isFrozen(entry) && Object.isFrozen(entry.detail), action);
    assert.ok(entry.modes.length, action);
    for (const mode of entry.modes)
      assert.ok(['U', 'P', 'S', 'O', 'A', 'Y', 'D', 'writer'].includes(mode), `${action} ${mode}`);
    assert.ok(
      entry.targetType.length && entry.targetType.every(type => /^[a-z]{1,32}$/.test(type))
    );
    assert.ok(
      entry.outcomes.every(outcome => OUTCOMES.includes(outcome)),
      action
    );
    assert.equal(new Set(entry.detail).size, entry.detail.length, `${action}: unique detail keys`);
    // Only attempt/result actions have attempt rows.
    assert.equal(entry.outcomes.includes('attempt'), entry.modes.includes('P'), action);
    assert.equal(typeof entry.inbox, 'boolean');
  }
  assert.deepEqual(
    Object.keys(ACTIONS).filter(action => ACTIONS[action].inbox),
    [
      'session.revoked',
      'session.revoked-restore',
      'account.password.changed-outside',
      'account.bootstrap',
      'account.claimed',
      'identity.mirror.failed',
      'system.restore',
    ]
  );
  // An action on two rows has one entry with the union of both.
  assert.deepEqual(ACTIONS['session.login'].modes, ['U', 'A']);
  assert.deepEqual(ACTIONS['session.login'].outcomes, ['ok', 'failed', 'denied']);
  assert.ok(ACTIONS['session.login'].detail.includes('persistent'));
  assert.ok(ACTIONS['session.login'].detail.includes('sample'));
});

test("the row texts: one entry per action, conditions on the row's own fields, every outcome covered", () => {
  assert.deepEqual(Object.keys(AUDIT_TEXTS), Object.keys(ACTIONS));
  const computed = new Set([
    'name',
    'id',
    'code',
    'codes',
    'count',
    'n',
    'list',
    'names',
    'command',
  ]);
  for (const [action, { texts, suffixes }] of Object.entries(AUDIT_TEXTS)) {
    const entry = ACTIONS[action];
    const shown = entry.modes.includes('P') ? [...entry.outcomes, 'unknown'] : entry.outcomes;
    const covered = new Set();
    for (const [when, text] of [...texts, ...suffixes]) {
      let outcomes = null;
      for (const term of when.split(' ')) {
        if (term === '*') continue;
        if (term === 'summary') assert.ok(entry.modes.includes('A'), `${action}: ${term}`);
        else if (term === 'own') assert.equal(action, 'system.upgrade');
        else if (
          /^[a-z|]+$/.test(term) &&
          term.split('|').every(word => OUTCOMES.includes(word) || word === 'unknown')
        ) {
          outcomes = term.split('|');
          for (const outcome of outcomes)
            assert.ok(shown.includes(outcome), `${action}: ${outcome}`);
        } else {
          const field = term.replace(/^!/, '').split('=')[0];
          assert.ok(entry.detail.includes(field), `${action}: ${term} names a detail key`);
        }
      }
      if (texts.some(pair => pair[1] === text))
        for (const outcome of outcomes ?? shown) covered.add(outcome);
      for (const [, name] of text.matchAll(/\{([a-zA-Z]+)\}/g))
        assert.ok(computed.has(name) || entry.detail.includes(name), `${action}: {${name}}`);
    }
    for (const outcome of shown)
      assert.ok(covered.has(outcome), `${action} has a text for ${outcome}`);
  }
  // Every code the routes and the pipeline count (§5.2) has its words.
  for (const code of [
    'invalid_credentials',
    'locked',
    'busy',
    'https_required',
    'proxy_proto_missing',
    'proxy_proto_mismatch',
    'cross_origin',
    'invalid_request',
    'storage_full',
    'current_password_incorrect',
    'password_invalid',
    'password_mismatch',
    'change_in_progress',
    'signin_required',
    'session_expired',
    'session_newer',
    'retired_password',
    'basic_disabled',
    'multiple_credentials',
    'client_closed',
    // auth.forbidden and auth.step-up.
    'forbidden',
    'step_up_required',
    'step_up_failed',
    'step_up_unavailable',
    'admin_ui_locked',
  ])
    assert.equal(typeof CODE_WORDS[code], 'string', code);
  // Counted only by earlier 1.5 builds (a sign-in without an admin password): the rows they
  // recorded still read.
  assert.equal(CODE_WORDS.signin_unavailable, 'no admin password is set');
  assert.deepEqual(Object.keys(PROBLEM_TEXTS), brokenCodes);
  assert.deepEqual(Object.keys(UNVERIFIABLE_TEXTS), [
    'no_key',
    'key_reset',
    'newer_format',
    'restore_unchecked',
    'unknown_key',
    'restore.snapshot',
    'restore.control_file',
  ]);
  assert.equal(Object.keys(ANCHOR_TEXTS).length, 11);
});

test('eventFrom takes the request facts, which the fields override; auditTime is the CLI format', () => {
  const actor = { type: 'user', id: 'u_admin', name: 'admin', via: 'basic', sessionId: null };
  const request = { requestId: 'r', route: 'POST /x', client: '192.0.2.1', userAgent: 'ua', actor };
  assert.deepEqual(eventFrom(request, { action: 'sources.refresh', outcome: 'ok' }), {
    actor,
    client: '192.0.2.1',
    userAgent: 'ua',
    requestId: 'r',
    action: 'sources.refresh',
    outcome: 'ok',
  });
  assert.deepEqual(eventFrom(request, { client: null, actor: null }).client, null);
  assert.deepEqual(eventFrom(undefined, { action: 'x' }), {
    actor: undefined,
    client: null,
    userAgent: null,
    requestId: null,
    action: 'x',
  });
  for (const ms of [0, Date.UTC(2026, 9, 3, 12), Date.UTC(2026, 8, 20, 8, 12, 0, 999)])
    assert.equal(auditTime(ms), formatTime(ms));
  assert.equal(auditTime(Date.UTC(2026, 9, 3, 12)), '2026-10-03 12:00:00 UTC');
  for (const value of [NaN, Infinity, null, '1', 2 ** 53 - 1])
    assert.equal(auditTime(value), 'unknown');
  // lib/audit never imports the CLI (its own copy of the format above).
  for (const file of fs.readdirSync(new URL('../../lib/audit/', import.meta.url)))
    assert.doesNotMatch(
      fs.readFileSync(new URL(`../../lib/audit/${file}`, import.meta.url), 'utf8'),
      /from '\.\.\/cli\//,
      file
    );
});

// Every entry §6.6 names, by its path in audit-bodies.json.
const entryNames = [
  'list.empty',
  'list.entries',
  'list.more',
  'list.unwritten',
  'export.csv',
  'export.ndjson',
  'verify.empty',
  'verify.intact',
  'verify.anchors',
  ...['key_reset', 'newer_format', 'restore_unchecked', 'no_key', 'unknown_key'].map(
    r => `verify.incomplete.${r}`
  ),
  ...brokenCodes.map(code => `verify.broken.${code}`),
  'error.audit_unavailable',
  'error.audit_read_unavailable',
  ...[
    'from',
    'to',
    'to/order',
    'limit',
    'cursor',
    'action',
    'actor',
    'target',
    'outcome',
    'format',
    'repeated',
  ].map(name => `error.audit_query_invalid.${name}`),
  'error.cross_origin.read',
];

test('audit-bodies.json holds every entry of §6.6', () => {
  for (const name of entryNames) assert.ok(auditBody(name), name);
  // The list: every outcome, an operation row, an aggregated pair, a diff with a secret and a
  // cut, and an action this release does not know.
  const { entries } = auditBody('list.entries');
  assert.deepEqual([...new Set(entries.map(entry => entry.outcome))].sort(), [
    'attempt',
    'conflict',
    'denied',
    'failed',
    'info',
    'ok',
    'unknown',
  ]);
  assert.ok(entries.some(entry => ACTIONS[entry.action]?.modes.includes('O')));
  assert.ok(entries.some(entry => entry.detail?.codes && entry.count > 1));
  assert.ok(entries.some(entry => entry.detail?.code && entry.detail?.login));
  assert.ok(
    entries.some(entry => entry.detail?.diff?.some(item => item.change) && entry.detail.truncated)
  );
  assert.ok(entries.some(entry => !Object.hasOwn(ACTIONS, entry.action)));
  for (const entry of entries)
    assert.deepEqual(Object.keys(entry), [
      'seq',
      'time',
      'action',
      'outcome',
      'status',
      'count',
      'actor',
      'requestId',
      'target',
      'ref',
      'result',
      'configRevision',
      'detail',
    ]);
  assert.equal(auditBody('list.more').nextCursor, '<seq>');
  assert.deepEqual(auditBody('list.unwritten').unwritten, { since: '<ms>', count: 1 });
  assert.equal(auditBody('list.empty').retention.oldest, null);
  // The maintainer's retention decision (OD7, D14): 90 days, at most 250,000 entries.
  for (const name of ['list.empty', 'list.entries', 'list.more', 'list.unwritten'])
    assert.deepEqual(
      [auditBody(name).retention.days, auditBody(name).retention.maxRows],
      [RETENTION_DEFAULT_DAYS, MAX_ROWS],
      name
    );
  assert.equal(RETENTION_DEFAULT_DAYS, 90);
});

test('audit-bodies.json: the exports, the verification texts and the error bodies are the frozen ones', () => {
  const csv = auditBody('export.csv');
  assert.ok(
    csv.body.startsWith(
      '﻿seq,time,actor_type,actor_id,actor_name,via,session_id,client,user_agent,request_id,action,target_type,target_id,target_name,outcome,status,count,ref,config_revision,detail,v,key_id,prev_hash,hash\r\n'
    )
  );
  assert.ok(csv.body.endsWith('\r\n'));
  assert.equal(csv.body.split('\r\n').length, 4, 'the header, two rows and the final line end');
  assert.match(csv.body, /"'=SUM\(A1:A2\)"/, 'the formula guard');
  assert.equal(csv.headers['x-goblin-export-rows'], String(csv.rows));
  const ndjson = auditBody('export.ndjson');
  const lines = ndjson.body.split('\n');
  assert.equal(lines.length, 4);
  assert.deepEqual(JSON.parse(lines[0]), {
    orbit: 'audit.export',
    v: 1,
    instance: '<id>',
    exportedAt: '<ms>',
    rows: 2,
    more: false,
  });
  // Verification: each problem's texts are PROBLEM_TEXTS with the values in place.
  const filled = template =>
    new RegExp(
      `^${template.replace(/[.*+?^$()[\]\\|]/g, '\\$&').replace(/\{\w+\}/g, '<(seq|time)>')}$`
    );
  for (const code of brokenCodes) {
    const body = auditBody(`verify.broken.${code}`);
    assert.equal(body.result, 'broken', code);
    assert.equal(body.problem.code, code);
    assert.match(body.problem.message, filled(PROBLEM_TEXTS[code].message), code);
    assert.match(body.problem.consequence, filled(PROBLEM_TEXTS[code].consequence), code);
  }
  assert.equal(auditBody('verify.intact').result, 'intact');
  assert.deepEqual(auditBody('verify.anchors').unverifiable, []);
  for (const reason of [
    'key_reset',
    'newer_format',
    'restore_unchecked',
    'no_key',
    'unknown_key',
  ]) {
    const body = auditBody(`verify.incomplete.${reason}`);
    assert.deepEqual([body.result, body.unverifiable[0].reason], ['incomplete', reason]);
  }
  assert.equal(auditBody('verify.incomplete.no_key').keyChecked, false);
  // Errors: the bodies auditError() answers, Retry-After on a 503.
  const answer = (error, headers) => ({ status: error.status, headers, body: error.body });
  assert.deepEqual(
    auditBody('error.audit_unavailable'),
    answer(auditError('audit_unavailable'), { 'retry-after': '30' })
  );
  assert.deepEqual(
    auditBody('error.audit_read_unavailable'),
    answer(auditError('audit_read_unavailable'), { 'retry-after': '15' })
  );
  for (const [name, parameter, rule] of [
    ['from', 'from', 'from'],
    ['to', 'to', 'to'],
    ['to/order', 'to', 'order'],
    ['limit', 'limit', 'limit'],
    ['cursor', 'cursor', 'cursor'],
    ['action', 'action', 'action'],
    ['actor', 'actor', 'actor'],
    ['target', 'target', 'target'],
    ['outcome', 'outcome', 'outcome'],
    ['format', 'format', 'format'],
    ['repeated', 'action', 'repeated'],
  ])
    assert.deepEqual(
      auditBody(`error.audit_query_invalid.${name}`),
      answer(auditError('audit_query_invalid', { parameter, rule: QUERY_RULES[rule] }), {}),
      name
    );
  assert.deepEqual(auditBody('error.cross_origin.read').body, {
    error: 'Requests from other sites cannot use your Uptime Goblin session.',
    code: 'cross_origin',
  });
});

test('the canary sentinels are distinct and found in every form a leak could take', () => {
  const sentinels = auditSentinels();
  const values = Object.values(sentinels);
  assert.equal(new Set(values).size, values.length);
  for (const [name, value] of Object.entries(sentinels)) {
    assert.ok(value.length >= 12, name);
    for (const other of values) if (other !== value) assert.ok(!other.includes(value), name);
  }
  assert.match(sentinels.secretKey, /^[0-9a-f]{64}$/);
  assert.notEqual(auditSentinels().adminPassword, sentinels.adminPassword, 'new for every call');
  const secret = sentinels.smtpPassword;
  const bytes = Buffer.from(secret);
  // Each form is found (a base64 without + or / is its base64url too, so only the name is
  // compared).
  for (const [form, text] of [
    ['text', `a line ${secret} here`],
    ['hex', `x${bytes.toString('hex')}x`],
    ['HEX', bytes.toString('hex').toUpperCase()],
    ['base64', bytes.toString('base64')],
    ['base64url', bytes.toString('base64url')],
    ['utf16', Buffer.from(`x${secret}`, 'utf16le').subarray(2)],
    ['Basic', `Authorization: Basic ${Buffer.from(`admin:${secret}`).toString('base64')}`],
  ])
    assert.deepEqual(
      findSentinels(text, sentinels).map(found => found.name),
      ['smtpPassword'],
      form
    );
  assert.deepEqual(findSentinels(Buffer.from(secret, 'utf16le'), sentinels), [
    { name: 'smtpPassword', form: 'utf16' },
  ]);
  // Encoded inside a larger blob: after a prefix of any length and before any suffix, the
  // value's base64 characters change with its alignment, and each one is still found.
  for (const encoding of ['base64', 'base64url'])
    for (let before = 0; before <= 4; before++)
      for (let after = 0; after <= 2; after++) {
        const blob = Buffer.concat([Buffer.alloc(before, 0x41), bytes, Buffer.alloc(after, 0x7a)]);
        assert.deepEqual(
          findSentinels(`data:${blob.toString(encoding)};`, sentinels).map(found => found.name),
          ['smtpPassword'],
          `${encoding}, ${before} bytes before, ${after} after`
        );
      }
  assert.deepEqual(findSentinels('nothing planted here', sentinels), []);
  assert.deepEqual(findSentinels(Buffer.from(`${secret}`), [secret]), [
    { name: '0', form: 'text' },
  ]);
});

// The placeholders of audit-bodies.json are read one way by every lane: concreteBody() fills them
// with values of their kind, and matchesBody() takes any value of its kind where one stands.
test('concreteBody and matchesBody: one reading of the placeholders for every lane', () => {
  for (const name of entryNames) {
    assert.deepEqual(bodyMismatches(concreteBody(name), name), [], name);
    const raw = auditBody(name);
    if (/<(seq|ms|hash|id|time|iso|stamp)>/.test(JSON.stringify(raw)))
      assert.equal(matchesBody(raw, name), false, `${name}: a placeholder is not a value`);
    else assert.ok(matchesBody(raw, name), name);
  }
  // A list: distinct entries, newest first; a result's ref below it; the cursor (text) and the
  // oldest entry below every entry; real times.
  const list = concreteBody('list.more', { firstSeq: 100, now: bodyNow });
  const more = concreteBody('list.entries', { firstSeq: 90 });
  const seqs = [...list.entries, ...more.entries].map(entry => entry.seq);
  assert.equal(new Set(seqs).size, seqs.length, 'two pages share no seq');
  assert.deepEqual(
    seqs,
    [...seqs].sort((a, b) => b - a),
    'newest first'
  );
  assert.ok(Number(list.nextCursor) < list.entries.at(-1).seq && /^\d+$/.test(list.nextCursor));
  assert.ok(list.retention.oldest.seq < Number(list.nextCursor), 'the oldest entry is the lowest');
  for (const entry of more.entries) {
    assert.equal(entry.time, bodyNow);
    if (entry.ref !== null) assert.ok(entry.ref < entry.seq, 'a result follows its attempt');
  }
  // Verification and exports run in seq order: first ≤ last, from ≤ to, refs below the rows.
  const gap = concreteBody('verify.broken.seq_gap', { firstSeq: 1000 });
  assert.ok(gap.problem.from <= gap.problem.to);
  assert.match(gap.problem.message, /^Entries #1,\d{3}–#1,\d{3} are missing\.$/);
  const intact = concreteBody('verify.intact');
  assert.ok(intact.rows.first.seq <= intact.rows.last.seq);
  assert.equal(intact.durationMs, 840);
  const ndjson = concreteBody('export.ndjson', { firstSeq: 7 });
  const [head, first, second] = ndjson.body
    .trimEnd()
    .split('\n')
    .map(line => JSON.parse(line));
  assert.equal(head.exportedAt, bodyNow, 'a number, not the quoted placeholder');
  assert.deepEqual([first.seq, second.seq, second.ref], [7, 8, 6]);
  assert.match(first.hash, /^[0-9a-f]{64}$/);
  assert.notEqual(first.hash, second.hash);
  const csv = concreteBody('export.csv');
  assert.ok(csv.body.startsWith('\ufeffseq,time,'));
  assert.match(csv.body, /\r\n"5000","2026-10-03T12:00:00\.000Z","user"/);
  assert.equal(csv.filename, 'uptime-goblin-audit-20261003-120000Z.csv');
  assert.equal(csv.headers['content-disposition'], `attachment; filename="${csv.filename}"`);

  // What a real answer may hold where a placeholder stands, and what it may not.
  const real = concreteBody('list.entries');
  assert.ok(matchesBody(real, 'list.entries'));
  const broken = (change, name = 'list.entries') => {
    const body = concreteBody(name);
    change(body);
    return bodyMismatches(body, name);
  };
  assert.deepEqual(
    broken(body => (body.entries[0].seq = '5000')),
    ['list.entries.entries[0].seq: expected <seq>, got "5000"']
  );
  assert.match(broken(body => (body.entries[0].time = 1.5))[0], /time: expected <ms>/);
  assert.match(
    broken(body => (body.entries[0].actor.sessionId = ''))[0],
    /sessionId: expected <id>/
  );
  assert.match(broken(body => delete body.entries[0].detail)[0], /\.detail: missing$/);
  assert.match(broken(body => (body.entries[0].extra = 1))[0], /\.extra: not expected$/);
  assert.match(broken(body => body.entries.pop())[0], /expected 11 items, got 10/);
  assert.match(
    broken(body => (body.entries[0].outcome = 'denied'))[0],
    /expected "ok", got "denied"/
  );
  assert.deepEqual(
    broken(body => (body.nextCursor = '12'), 'list.more'),
    []
  );
  assert.match(
    broken(body => (body.nextCursor = 12), 'list.more')[0],
    /nextCursor: expected <seq>/
  );
  assert.match(
    broken(body => (body.anchors[3].restoredHead.hash = 'f'.repeat(63)), 'verify.anchors')[0],
    /hash: expected <hash>/
  );
  // Inside texts: numbers with or without separators, and the time format of auditTime().
  assert.deepEqual(
    broken(
      body => (body.problem.message = 'Entries #4–#1,234,567 are missing.'),
      'verify.broken.seq_gap'
    ),
    []
  );
  assert.match(
    broken(
      body => (body.problem.message = 'Entries #4 to #5 are missing.'),
      'verify.broken.seq_gap'
    )[0],
    /does not match/
  );
  assert.match(
    broken(
      body => (body.problem.message = body.problem.message.replace(' UTC', 'Z')),
      'verify.broken.journal_ahead'
    )[0],
    /does not match/
  );
  // An NDJSON body line by line: numbers must be numbers there.
  assert.match(
    broken(
      body => (body.body = body.body.replace(/"seq":(\d+)/, '"seq":"$1"')),
      'export.ndjson'
    )[0],
    /line 2\.seq: expected <seq>, got "\d+"/
  );
  assert.match(
    broken(body => (body.body = body.body.replace('\n{', '\n{x')), 'export.ndjson')[0],
    /line 2: not JSON/
  );
});
