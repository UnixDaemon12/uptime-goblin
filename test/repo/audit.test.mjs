// The audit trail's SQL (lib/repo/audit.mjs, audit spec §4.3, §6.2, §4.7) over a real, migrated
// control.sqlite: round trips, explicit seqs, the query plan of every list filter (no table
// scan), the prune targets (only the leading run of expired rows), chunked deletes, two
// connections appending through BEGIN IMMEDIATE, and a value out of range.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql } from '../../lib/db/sql.mjs';
import { auditOps } from '../../lib/repo/audit.mjs';
import { drainChunks } from '../../lib/repo/chunks.mjs';
import { openControl } from '../../lib/db/control.mjs';
import { appendDirect } from '../../lib/audit/writer.mjs';
import { GENESIS } from '../../lib/audit/chain.mjs';
import {
  auditFixture,
  migratedControl,
  openKeyring,
  release,
  storedRows,
} from '../audit/helpers.mjs';

// A stored row as insertRow takes it (no chain: these tests are about the SQL, not the hashes).
const plainRow = (seq, fields = {}) => ({
  seq,
  v: 1,
  time: 1000 + seq,
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
  detail: null,
  detailText: null,
  config_revision: null,
  key_id: 'k1',
  prev_hash: GENESIS,
  hash: `${seq}`.padStart(64, '0'),
  ...fields,
});

test('auditOps round trip: rows with explicit seqs, the head, checkpoints, the inbox and meta', async t => {
  const { db } = await migratedControl(t);
  await db.write(tx => {
    assert.equal(auditOps.head(tx), null);
    assert.equal(auditOps.last(tx), null);
    assert.equal(auditOps.first(tx), null);
    auditOps.insertRow(tx, plainRow(7, { detail: { a: 1 }, detailText: '{"a":1}', status: 200 }));
    auditOps.insertRow(tx, plainRow(9, { action: 'audit.gap', ref: 7 }));
    auditOps.setHead(tx, { seq: 9, hash: plainRow(9).hash, key_id: 'k1', updated_at: 5 });
    auditOps.setHead(tx, { seq: 9, hash: plainRow(9).hash, key_id: 'k2', updated_at: 6 });
    auditOps.insertCheckpoint(tx, {
      seq: 7,
      time: 1007,
      hash: plainRow(7).hash,
      key_id: 'k1',
      reason: 'prune',
      mac: 'f'.repeat(64),
    });
    auditOps.setMeta(tx, 'audit_restore_seen', 'x', 1);
  });
  const read = await db.read(tx => ({
    head: auditOps.head(tx),
    last: auditOps.last(tx),
    first: auditOps.first(tx),
    row: auditOps.rowAt(tx, 7),
    missing: auditOps.rowAt(tx, 8),
    checkpoints: auditOps.checkpoints(tx),
    has: [auditOps.hasCheckpoint(tx, 7), auditOps.hasCheckpoint(tx, 9)],
    restore: auditOps.restoreState(tx),
  }));
  assert.deepEqual(read.head, { seq: 9, hash: plainRow(9).hash, keyId: 'k2' });
  assert.deepEqual(read.last, { seq: 9, hash: plainRow(9).hash, action: 'audit.gap' });
  assert.deepEqual(read.first, { seq: 7, time: 1007, prevHash: GENESIS });
  assert.equal(read.row.seq, 7, 'the seq given, not one the table chose');
  assert.deepEqual(read.row.detail, { a: 1 });
  assert.equal(read.row.detailText, '{"a":1}');
  assert.equal(read.row.status, 200);
  assert.equal(read.missing, null);
  assert.deepEqual(read.checkpoints, [
    {
      seq: 7,
      time: 1007,
      hash: plainRow(7).hash,
      key_id: 'k1',
      reason: 'prune',
      mac: 'f'.repeat(64),
    },
  ]);
  assert.deepEqual(read.has, [true, false]);
  assert.deepEqual(read.restore, { restored: null, seen: 'x' });
  // The inbox: ids in order, events parsed, deletes by id and all at once.
  const ids = await db.write(tx => [
    auditOps.inboxInsert(tx, { time: 1, source: 'start', event: { action: 'a' } }),
    auditOps.inboxInsert(tx, { time: 2, source: 'start', event: { action: 'b' } }),
    auditOps.inboxInsert(tx, { time: 3, source: 'start', event: { action: 'c' } }),
  ]);
  assert.deepEqual(
    await db.read(tx => auditOps.inboxAll(tx).map(row => [row.id, row.time, row.event.action])),
    [
      [ids[0], 1, 'a'],
      [ids[1], 2, 'b'],
      [ids[2], 3, 'c'],
    ]
  );
  assert.equal(await db.write(tx => auditOps.inboxDelete(tx, [ids[1]])), 1);
  assert.equal(await db.write(tx => auditOps.inboxClear(tx)), 2);
  assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
  // Checkpoints below a seq go; the ones at or above stay.
  await db.write(tx =>
    auditOps.insertCheckpoint(tx, {
      seq: 9,
      time: 1009,
      hash: plainRow(9).hash,
      key_id: 'k1',
      reason: 'prune',
      mac: 'e'.repeat(64),
    })
  );
  assert.equal(await db.write(tx => auditOps.deleteCheckpointsBefore(tx, 9)), 1);
  assert.deepEqual(
    (await db.read(tx => auditOps.checkpoints(tx))).map(c => c.seq),
    [9]
  );
});

// Runs `fn(tx)` with a transaction whose reads also collect their EXPLAIN QUERY PLAN lines.
async function plansOf(db, fn) {
  const plans = [];
  await db.read(tx => {
    const explain = query =>
      plans.push(tx.all(sql`EXPLAIN QUERY PLAN ${query}`).map(row => row.detail));
    fn({
      dialect: tx.dialect,
      all: query => (explain(query), tx.all(query)),
      get: query => (explain(query), tx.get(query)),
    });
  });
  return plans;
}

test('EXPLAIN: every list filter, alone and with a period, and the results lookup read through an index, never a scan of audit_log', async t => {
  const { audit, db } = await auditFixture(t);
  for (let i = 0; i < 30; i++)
    await audit.system({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: i } });
  const filters = {
    none: {},
    cursor: { cursor: 10 },
    'actor type': { actor: { type: 'user' } },
    'actor name': { actor: { name: 'admin' } },
    'actor cli name': { actor: { name: 'cli:dana' } },
    action: { actions: [{ name: 'session.login', prefix: false }] },
    'action prefix': { actions: [{ name: 'session.', prefix: true }] },
    'action list': {
      actions: [
        { name: 'session.', prefix: true },
        { name: 'settings.update', prefix: false },
        { name: 'auth.basic.', prefix: true },
      ],
    },
    'target type': { target: { type: 'session', id: null } },
    'target id': { target: { type: 'session', id: 's_1' } },
    ...Object.fromEntries(
      ['ok', 'denied', 'failed', 'conflict', 'info', 'attempt', 'unknown'].map(outcome => [
        `outcome ${outcome}`,
        { outcome },
      ])
    ),
  };
  const expected = {
    'actor type': 'audit_log_actor',
    'actor name': 'audit_log_actor',
    'actor cli name': 'audit_log_actor',
    action: 'audit_log_action',
    'action prefix': 'audit_log_action',
    'action list': 'audit_log_action',
    'target type': 'audit_log_target',
    'target id': 'audit_log_target',
  };
  const scan = /^SCAN audit_log\b/;
  for (const [name, filter] of Object.entries(filters))
    for (const period of [{}, { from: 1 }, { from: 1, to: 9e12 }, { to: 9e12 }]) {
      const query = { ...filter, ...period };
      const [plan] = await plansOf(db, tx => auditOps.page(tx, query, { open: [3, 4], limit: 50 }));
      const label = `${name} ${JSON.stringify(period)}: ${plan.join(' | ')}`;
      assert.ok(!plan.some(line => scan.test(line)), label);
      assert.ok(
        plan.some(line => /^SEARCH audit_log\b/.test(line)),
        label
      );
      // Alone, each filter reads through its own index (the outcome filters through
      // audit_log_outcome, the rest as named; a period alone through audit_log_time).
      if (!Object.keys(period).length) {
        const index = name.startsWith('outcome')
          ? 'audit_log_outcome'
          : (expected[name] ?? 'INTEGER PRIMARY KEY');
        assert.ok(
          plan.some(line => line.includes(index)),
          label
        );
      }
      // The hiding condition and the unknown outcome look results up through audit_log_ref.
      if (!filter.outcome || filter.outcome === 'unknown')
        assert.ok(
          plan.some(line => /^SEARCH r USING INDEX audit_log_ref/.test(line)),
          label
        );
    }
  const [periodOnly] = await plansOf(db, tx =>
    auditOps.page(tx, { from: 1, to: 2 }, { open: [], limit: 5 })
  );
  assert.ok(
    periodOnly.some(line => line.includes('audit_log_time')),
    periodOnly.join(' | ')
  );
  const [results] = await plansOf(db, tx => auditOps.results(tx, [1, 2, 3]));
  assert.ok(!results.some(line => /^SCAN/.test(line)), results.join(' | '));
  assert.ok(
    results.some(line => line.includes('audit_log_ref')),
    results.join(' | ')
  );
  // The export reads the same way (its units are bounded by the head).
  const [exported] = await plansOf(db, tx =>
    auditOps.exportRows(
      tx,
      { actions: [{ name: 'session.', prefix: true }] },
      { toSeq: 30, limit: 10 }
    )
  );
  assert.ok(!exported.some(line => scan.test(line)), exported.join(' | '));
});

test('page: newest first, LIMIT + 1, the cursor, and the attempt rows a result hides', async t => {
  const { db } = await migratedControl(t);
  await db.write(tx => {
    auditOps.insertRow(tx, plainRow(1, { action: 'settings.update', outcome: 'attempt' }));
    auditOps.insertRow(tx, plainRow(2, { action: 'settings.update', outcome: 'ok', ref: 1 }));
    auditOps.insertRow(tx, plainRow(3, { action: 'delivery.retry', outcome: 'attempt' }));
    // A result of another action does not hide the attempt (§6.2).
    auditOps.insertRow(tx, plainRow(4, { action: 'channel.resume', outcome: 'ok', ref: 3 }));
    auditOps.insertRow(tx, plainRow(5, { action: 'session.login', outcome: 'failed' }));
  });
  const seqs = async (query, options = { open: [], limit: 50 }) =>
    (await db.read(tx => auditOps.page(tx, query, options))).map(row => row.seq);
  assert.deepEqual(await seqs({}), [5, 4, 3, 2]);
  assert.deepEqual(await seqs({}, { open: [], limit: 2 }), [5, 4, 3], 'LIMIT + 1');
  assert.deepEqual(await seqs({ cursor: 4 }), [3, 2]);
  assert.deepEqual(await seqs({ outcome: 'attempt' }), [3, 1]);
  assert.deepEqual(await seqs({ outcome: 'unknown' }), [3]);
  assert.deepEqual(await seqs({ outcome: 'unknown' }, { open: [3], limit: 50 }), []);
  assert.deepEqual(await seqs({ actions: [{ name: 'settings.', prefix: true }] }), [2]);
  assert.deepEqual(await db.read(tx => auditOps.results(tx, [1, 3])), [
    { ref: 1, seq: 2, outcome: 'ok', status: null, time: 1002 },
  ]);
});

test('leading run: pruneTarget takes only the expired rows before the first recent one', async t => {
  const { db } = await migratedControl(t);
  await db.write(tx => {
    for (let seq = 1; seq <= 20; seq++)
      auditOps.insertRow(tx, plainRow(seq, { time: seq <= 10 ? 100 : 10000 + seq }));
  });
  const target = cutoff => db.read(tx => auditOps.pruneTarget(tx, { cutoff, maxRows: 15 }));
  assert.deepEqual(await target(5000), { age: 10, cap: 5 });
  // One row with a wrong time near the head (time 0) moves nothing: it is not part of the
  // leading run, and the lowest recent seq is still 11.
  await db.write(tx =>
    tx.run(tx.dialect.update('audit_log', { time: 0 }, sql`${sql.id('seq')} = ${18}`))
  );
  assert.deepEqual(await target(5000), { age: 10, cap: 5 });
  // No row as recent as the cutoff: no age target (the caller takes the head's seq − 1).
  assert.equal((await target(1e9)).age, null);
  assert.equal((await db.read(tx => auditOps.pruneTarget(tx, { cutoff: 1, maxRows: 100 }))).cap, 0);
});

test('atOrBelow across a seq jump, and deleteThrough with drainChunks', async t => {
  const { db } = await migratedControl(t);
  await db.write(tx => {
    for (let seq = 1; seq <= 5; seq++) auditOps.insertRow(tx, plainRow(seq));
    for (let seq = 10; seq <= 300; seq++) auditOps.insertRow(tx, plainRow(seq));
  });
  assert.equal(await db.read(tx => auditOps.atOrBelow(tx, 8)), 5);
  assert.equal(await db.read(tx => auditOps.atOrBelow(tx, 10)), 10);
  assert.equal(await db.read(tx => auditOps.atOrBelow(tx, 0)), null);
  const deleted = await drainChunks(db, auditOps.deleteThrough(db.dialect, 250), {
    dialect: db.dialect,
    max: 40,
  });
  assert.equal(deleted, 5 + 241);
  assert.equal((await db.read(tx => auditOps.first(tx))).seq, 251);
  assert.equal((await db.read(tx => auditOps.last(tx))).seq, 300);
});

test('two connections appending 500 rows each through BEGIN IMMEDIATE give 1,000 contiguous, linked rows', async t => {
  const { directory, control } = await migratedControl(t);
  const keyring = await openKeyring(control);
  const other = openControl(directory, { release, env: {} });
  t.after(() => other.close());
  const append = (db, n) =>
    appendDirect(
      { db, keyring },
      { action: 'system.stop', outcome: 'info', detail: { uptimeMs: n } }
    );
  // Interleaved: each connection awaits between its units, so they alternate.
  await Promise.all(
    [control.db, other.db].map(async db => {
      for (let n = 0; n < 500; n++) await append(db, n);
    })
  );
  const rows = await storedRows(control.db);
  assert.equal(rows.length, 1000);
  rows.forEach((row, index) => {
    assert.equal(row.seq, index + 1);
    assert.equal(row.prev_hash, index ? rows[index - 1].hash : GENESIS, `seq ${row.seq}`);
  });
  assert.equal(new Set(rows.map(row => row.prev_hash)).size, 1000);
  assert.deepEqual(await control.db.read(tx => auditOps.head(tx).seq), 1000);
});

test('out of range: a row whose time is 2^53 + 1 makes rowsFrom throw an error of class poison', async t => {
  const { db } = await migratedControl(t);
  await db.write(tx => {
    for (let seq = 1; seq <= 3; seq++) auditOps.insertRow(tx, plainRow(seq));
    tx.run(tx.dialect.update('audit_log', { time: 2n ** 53n + 1n }, sql`${sql.id('seq')} = ${2}`));
  });
  await assert.rejects(
    db.read(tx => auditOps.rowsFrom(tx, { afterSeq: 0, toSeq: 10, limit: 10 })),
    error => error.class === 'poison'
  );
  // Reading only seq and hash (what the writer reads before it appends) still works.
  assert.equal((await db.read(tx => auditOps.last(tx))).seq, 3);
});
