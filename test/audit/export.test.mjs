// Audit exports (lib/audit/export.mjs, audit spec §6.3): CSV with the BOM, \r\n, every cell quoted
// and the formula guard; NDJSON with its header line; the newest rows written oldest first; the
// 50,000-row and 16 MiB caps with `more`; reads in units of 2,000 rows.
import test from 'node:test';
import assert from 'node:assert/strict';
import { auditOps } from '../../lib/repo/audit.mjs';
import { exportAudit, csvCell, CSV_HEADER } from '../../lib/audit/export.mjs';
import { GENESIS } from '../../lib/audit/chain.mjs';
import { adminRequest, auditFixture, migratedControl } from './helpers.mjs';

const at = Date.UTC(2026, 9, 3, 12);
const plainRow = (seq, fields = {}) => ({
  seq,
  v: 1,
  time: at + seq,
  ref: null,
  actor_type: 'system',
  actor_id: null,
  actor_name: 'orbit',
  via: 'system',
  session_id: null,
  client_key: null,
  user_agent: null,
  request_id: null,
  action: 'system.stop',
  target_type: 'orbit',
  target_id: null,
  target_name: null,
  outcome: 'info',
  status: null,
  count: 1,
  detail: { uptimeMs: seq },
  detailText: `{"uptimeMs":${seq}}`,
  config_revision: null,
  key_id: 'k1',
  prev_hash: GENESIS,
  hash: String(seq).padStart(64, '0'),
  ...fields,
});
async function filled(t, count, fields = () => ({})) {
  const { db } = await migratedControl(t);
  for (let start = 1; start <= count; start += 5000)
    await db.write(tx => {
      for (let seq = start; seq < Math.min(start + 5000, count + 1); seq++)
        auditOps.insertRow(tx, plainRow(seq, fields(seq)));
      auditOps.setHead(tx, {
        seq: Math.min(start + 4999, count),
        hash: 'h',
        key_id: 'k1',
        updated_at: 1,
      });
    });
  return db;
}
const csv = (db, options = {}) =>
  exportAudit(db, { format: 'csv' }, { clock: () => at, instance: 'inst-1', ...options });

test('CSV: the BOM, the header, \\r\\n, every cell quoted, ISO times, and the formula guard', async t => {
  const { audit, db, clock } = await auditFixture(t, { clock: () => at });
  await audit.single(adminRequest(), {
    action: 'config.export',
    target: { type: 'config', id: null, name: null },
    detail: { sources: 2, bytes: 10 },
  });
  const change = await audit.begin(adminRequest(), {
    action: 'source.create',
    target: { type: 'source', id: null, name: '=SUM(A1:A2)' },
    detail: { ifMatch: false },
  });
  await change.end({ status: 201, outcome: 'ok' });
  const result = await audit.export({ format: 'csv' }, 'csv');
  assert.deepEqual([...result.body.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  const text = result.body.toString('utf8').slice(1);
  assert.ok(text.endsWith('\r\n'));
  const lines = text.split('\r\n');
  assert.equal(lines.pop(), '');
  assert.equal(lines[0], CSV_HEADER);
  assert.equal(lines.length, 4, 'every row, attempts included');
  assert.equal(result.rows, 3);
  assert.equal(result.more, false);
  assert.equal(result.contentType, 'text/csv; charset=utf-8');
  assert.equal(result.filename, 'uptime-goblin-audit-20261003-120000Z.csv');
  const cells = lines[3].match(/"(?:[^"]|"")*"/g);
  assert.equal(cells.length, 24);
  assert.equal(cells[0], '"3"');
  assert.equal(cells[1], `"${new Date(at).toISOString()}"`);
  assert.equal(cells[13], `"'=SUM(A1:A2)"`, 'the formula guard on the name');
  assert.equal(cells[19], '"{""ifMatch"":false}"');
  for (const [value, cell] of [
    ['=1', `"'=1"`],
    ['+1', `"'+1"`],
    ['@1', `"'@1"`],
    ['-1', `"'-1"`],
    ['\t1', `"'\t1"`],
    ['\r1', `"'\r1"`],
    ['a"b', '"a""b"'],
    [null, '""'],
    [5, '"5"'],
  ])
    assert.equal(csvCell(value), cell, JSON.stringify(value));
  assert.ok(clock);
  const none = await audit.export(
    { format: 'csv', actions: [{ name: 'key.', prefix: true }] },
    'csv'
  );
  assert.equal(none.body.toString('utf8'), `﻿${CSV_HEADER}\r\n`, '0 rows: the BOM and the header');
  assert.equal(none.rows, 0);
  assert.ok(db);
});

// Review round 2: the CSV wrote the stored text, which may hold a forged duplicate key that the
// hash (over the detail parsed) never covered.
test('CSV: the detail cell is the canonical JSON of the stored detail, never another text of it', async t => {
  const forged = '{"diff":[{"from":"a","path":"email.host","to":"evil"}],"diff":[]}';
  const db = await filled(t, 3, seq =>
    seq === 2 ? { detailText: forged } : seq === 3 ? { detailText: ' {"uptimeMs" : 3} ' } : {}
  );
  const result = await csv(db);
  const lines = result.body.toString('utf8').split('\r\n');
  const detailOf = line => line.match(/"(?:[^"]|"")*"/g)[19];
  assert.equal(detailOf(lines[1]), '"{""uptimeMs"":1}"');
  assert.equal(detailOf(lines[2]), '"{""diff"":[]}"', 'the value the hash covers');
  assert.equal(detailOf(lines[3]), '"{""uptimeMs"":3}"');
  assert.ok(!result.body.toString('utf8').includes('evil'));
});

test('NDJSON: the header line, then the rows as stored with detail parsed, oldest first', async t => {
  const db = await filled(t, 3);
  const result = await exportAudit(
    db,
    { format: 'ndjson' },
    { clock: () => at, instance: 'inst-1' }
  );
  const lines = result.body.toString('utf8').split('\n');
  assert.equal(lines.pop(), '');
  assert.deepEqual(JSON.parse(lines[0]), {
    orbit: 'audit.export',
    v: 1,
    instance: 'inst-1',
    exportedAt: at,
    rows: 3,
    more: false,
  });
  const rows = lines.slice(1).map(line => JSON.parse(line));
  assert.deepEqual(
    rows.map(row => row.seq),
    [1, 2, 3]
  );
  assert.deepEqual(Object.keys(rows[0]), [
    'seq',
    'v',
    'time',
    'ref',
    'actor_type',
    'actor_id',
    'actor_name',
    'via',
    'session_id',
    'client_key',
    'user_agent',
    'request_id',
    'action',
    'target_type',
    'target_id',
    'target_name',
    'outcome',
    'status',
    'count',
    'detail',
    'config_revision',
    'key_id',
    'prev_hash',
    'hash',
  ]);
  assert.deepEqual(rows[0].detail, { uptimeMs: 1 });
  assert.equal(result.contentType, 'application/x-ndjson; charset=utf-8');
  assert.equal(result.filename, 'uptime-goblin-audit-20261003-120000Z.ndjson');
});

// A stored name may hold characters a reader takes for a line end (U+2028, U+2029, U+0085: rows
// written before names refused them, or restored) or that reorder what a viewer shows (U+202E).
// NDJSON writes them as \u escapes, so a reader splitting lines the Unicode way (Python's
// str.splitlines) keeps each row whole and parses the same value; CSV drops the direction
// controls, before the formula guard.
test('NDJSON keeps a row on one line for every reader; CSV shows a name in its own order', async t => {
  const name = 'Plex\u2028{"forged":true}\u2029\u0085\u202egnp.exe\u2066=1';
  const db = await filled(t, 2, seq => (seq === 2 ? { target_name: name } : {}));
  const ndjson = (
    await exportAudit(db, { format: 'ndjson' }, { clock: () => at, instance: 'inst-1' })
  ).body.toString('utf8');
  // str.splitlines' line ends, beyond \n.
  const unicodeLines = ndjson.split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/);
  assert.equal(unicodeLines.pop(), '');
  assert.equal(unicodeLines.length, 3, 'the header and two rows, each on one line');
  assert.equal(JSON.parse(unicodeLines[2]).target_name, name, 'the same value, escaped');
  assert.doesNotMatch(ndjson, /[\u0085\u2028\u2029\u202a-\u202e\u2066-\u2069]/);
  const text = (await csv(db)).body.toString('utf8');
  const cell = text.split('\r\n')[2].match(/"(?:[^"]|"")*"/g)[13];
  assert.equal(cell, '"Plex\u2028{""forged"":true}\u2029\u0085gnp.exe=1"');
  assert.doesNotMatch(text, /[\u202a-\u202e\u2066-\u2069]/);
  // A direction control cannot hide a formula from the guard.
  assert.equal(csvCell('\u202e=HYPERLINK("x")'), `"'=HYPERLINK(""x"")"`);
});

test('caps: at most 50,000 rows, the newest, with more; read in units of 2,000 (a counting reader)', async t => {
  const db = await filled(t, 50010);
  let reads = 0;
  const counting = { read: fn => (reads++, db.read(fn)) };
  const result = await csv(counting);
  assert.equal(result.rows, 50000);
  assert.equal(result.more, true);
  const lines = result.body.toString('utf8').split('\r\n');
  assert.ok(lines[1].startsWith('"11",'), 'the newest 50,000, oldest first');
  assert.ok(lines.at(-2).startsWith('"50010",'));
  // The head, 25 units of 2,000, and one row more to know there is more.
  assert.equal(reads, 1 + 25 + 1);
  const exact = await csv(counting, { maxRows: 50010 });
  assert.equal(exact.more, false);
});

test('caps: at most 16 MiB, the newest rows that fit, with more', async t => {
  const big = 'x'.repeat(16000);
  const db = await filled(t, 1200, seq => ({
    detail: { reason: big },
    detailText: `{"reason":"${big}","n":${seq}}`,
  }));
  const result = await csv(db);
  assert.ok(result.body.length <= 16 * 1024 * 1024, `${result.body.length}`);
  assert.ok(result.body.length > 15 * 1024 * 1024);
  assert.equal(result.more, true);
  assert.ok(result.rows < 1200);
  const lines = result.body.toString('utf8').split('\r\n');
  assert.ok(lines.at(-2).startsWith('"1200",'), 'the newest kept');
  const small = await csv(db, { maxBytes: 100000 });
  assert.ok(small.body.length <= 100000);
  assert.equal(small.more, true);
});

test('filters and the head: no row hidden, only rows up to the head when the export began', async t => {
  const { audit } = await auditFixture(t, { clock: () => at });
  const change = await audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
  });
  await change.end({ status: 200, outcome: 'ok' });
  await audit.append({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: 1 } });
  const all = await audit.export({ format: 'ndjson' }, 'ndjson');
  assert.equal(all.rows, 3);
  const attempts = await audit.export({ format: 'ndjson', outcome: 'attempt' }, 'ndjson');
  assert.equal(attempts.rows, 1);
  const settings = await audit.export(
    { format: 'ndjson', actions: [{ name: 'settings.update', prefix: false }] },
    'ndjson'
  );
  assert.equal(settings.rows, 2);
});
