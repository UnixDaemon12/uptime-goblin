// Verification (lib/audit/verify.mjs, audit spec §6.4, D16, D17, D27, D28): the tamper matrix,
// each change found with its code and seq, and the legitimate cases that must stay intact or be
// reported as not fully checked, never as changed. Logs are written by the real service over a
// real control.sqlite, then edited by hand as someone with the database but not the key would.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql } from '../../lib/db/sql.mjs';
import { auditOps } from '../../lib/repo/audit.mjs';
import {
  anchorLines,
  grouped,
  journalLines,
  problemTexts,
  unverifiableText,
  verifyAudit,
} from '../../lib/audit/verify.mjs';
import { parseAuditQuery } from '../../lib/audit/view.mjs';
import { checkpointMac, rowHash } from '../../lib/audit/chain.mjs';
import { createAudit } from '../../lib/audit/index.mjs';
import { buildRow, recordWith } from '../../lib/audit/writer.mjs';
import { Keyring } from '../../lib/keyring.mjs';
import {
  auditFixture,
  keyA,
  keyB,
  linesOf,
  manualClock,
  recordIn,
  storedRows,
} from './helpers.mjs';

const stop = n => ({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: n } });
const seqIs = seq => sql`${sql.id('seq')} = ${seq}`;
// A log of `n` rows, a second apart, each printed with its checkpoint line.
async function logOf(t, n, options = {}) {
  const fixture = await auditFixture(t, options);
  for (let i = 1; i <= n; i++) {
    await fixture.audit.append(stop(i));
    fixture.clock.advance(1000);
  }
  return fixture;
}
const check = (fixture, options = {}) =>
  verifyAudit(fixture.db, { keyring: fixture.keyring, clock: fixture.clock, ...options });
const journalOf = fixture => fixture.out.join('\n');
const edit = (db, table, set, where) =>
  db.write(tx => tx.run(tx.dialect.update(table, set, where)));
const remove = (db, table, where) => db.write(tx => tx.run(tx.dialect.deleteFrom(table, where)));
function assertProblem(result, code, seq) {
  assert.equal(result.result, 'broken', JSON.stringify(result.problem));
  assert.equal(result.problem.code, code, JSON.stringify(result.problem));
  assert.equal(result.problem.seq, seq, JSON.stringify(result.problem));
  assert.equal(typeof result.problem.message, 'string');
  assert.equal(typeof result.problem.consequence, 'string');
}
// A checkpoint line as Uptime Goblin prints it, signed with the fixture's key (what only Uptime Goblin can do).
function signedLine(fixture, fields) {
  const kid = fixture.keyring.activeKid('audit');
  const line = { instance: 'i', reason: 'commit', key_id: kid, ...fields };
  const mac = checkpointMac(data => fixture.keyring.hmac('audit', data, line.key_id).mac, line);
  return JSON.stringify({ orbit: 'audit.checkpoint', v: 1, ...line, mac });
}
const cliActor = { type: 'cli', id: null, name: 'cli:dana', via: 'cli', sessionId: null };
const resetEvent = (lostKeyIds, head) => ({
  action: 'key.reset',
  outcome: 'ok',
  actor: cliActor,
  target: { type: 'keyring', id: null, name: null },
  detail: { lostKeyIds, head },
});
// A row put straight into the table and made the head, as someone with the database would:
// chained onto `prev`, its hash made up, or signed under `kid` with the fixture's keyring when
// `signed` (what only someone with the key can do).
async function insertForged(f, event, { seq, kid, prev, hash = null, v = 1, signed = false }) {
  const row = { ...buildRow(event, f.clock), v, seq, key_id: kid, prev_hash: prev };
  row.hash = signed ? rowHash(data => f.keyring.hmac('audit', data, kid).mac, prev, row) : hash;
  await f.db.write(tx => {
    auditOps.insertRow(tx, row);
    auditOps.setHead(tx, { seq, hash: row.hash, key_id: kid, updated_at: 1 });
  });
  return row;
}
// goblin-admin key reset --confirm-lost-key with `key`: the keyring reset and its key.reset row in
// one unit, signed by the new audit key (§7.2). Resolves {keyring, lost}.
async function resetLostKey(f, key) {
  const lost = (await f.control.keyringStore.list())
    .filter(row => row.purpose === 'audit')
    .map(row => row.kid);
  const { keyring } = await Keyring.reset(f.control.keyringStore, {
    key,
    confirmLostKey: true,
    inUnit: (tx, signer) => recordWith(tx, signer, resetEvent(lost), { clock: f.clock }),
  });
  return { keyring, lost };
}

test('an intact log, an empty one, and the journal lines that match it', async t => {
  const fixture = await logOf(t, 5);
  const result = await check(fixture);
  assert.equal(result.result, 'intact');
  assert.deepEqual(result.rows, {
    checked: 5,
    first: { seq: 1, time: result.rows.first.time },
    last: { seq: 5, time: result.rows.last.time },
  });
  const withJournal = await check(fixture, { journal: `noise\nprefix: ${journalOf(fixture)}\n` });
  assert.equal(withJournal.result, 'intact');
  assert.deepEqual(withJournal.journal, {
    lines: 5,
    matched: 5,
    unchecked: 0,
    foreign: 0,
    coveredTo: 5,
    foreignLines: [],
  });
  const empty = await auditFixture(t);
  const none = await check(empty);
  assert.equal(none.result, 'intact');
  assert.deepEqual(none.rows, { checked: 0, first: null, last: null });
});

test('tamper matrix: each change is found with its code and seq', async t => {
  await t.test('detail edited → hash_mismatch', async t => {
    const f = await logOf(t, 6);
    await edit(f.db, 'audit_log', { detail: '{"uptimeMs":999}' }, seqIs(4));
    assertProblem(await check(f), 'hash_mismatch', 4);
  });
  // Review round 2: the hash covers the detail parsed. A stored text that parses to the same
  // value (a forged duplicate key first, which JSON.parse drops; padding) showed something never
  // signed in the CSV export, and read intact, also against the whole journal.
  await t.test(
    'detail stored as another text of the same value (a duplicate key, padding) → hash_mismatch',
    async t => {
      for (const text of [
        '{"uptimeMs":999,"uptimeMs":4}',
        ' {"uptimeMs" : 4}  ',
        '{"uptimeMs":4.0}',
      ]) {
        const f = await logOf(t, 6);
        await edit(f.db, 'audit_log', { detail: text }, seqIs(4));
        assert.deepEqual((await storedRows(f.db))[3].detail, { uptimeMs: 4 }, text);
        assertProblem(await check(f), 'hash_mismatch', 4);
        assertProblem(await check(f, { journal: journalOf(f) }), 'hash_mismatch', 4);
      }
    }
  );
  await t.test('middle row deleted → seq_gap', async t => {
    const f = await logOf(t, 6);
    await remove(f.db, 'audit_log', seqIs(3));
    const result = await check(f);
    assertProblem(result, 'seq_gap', 3);
    assert.equal(result.problem.from, 3);
    assert.equal(result.problem.to, 3);
  });
  await t.test('tail deleted, head kept → head_mismatch', async t => {
    const f = await logOf(t, 6);
    await remove(f.db, 'audit_log', sql`${sql.id('seq')} > ${4}`);
    const result = await check(f);
    assertProblem(result, 'head_mismatch', 4);
    assert.equal(result.problem.head, 6);
  });
  await t.test(
    'tail deleted, head rewritten → intact without a journal, journal_ahead with one',
    async t => {
      const f = await logOf(t, 6);
      const rows = await storedRows(f.db);
      await remove(f.db, 'audit_log', sql`${sql.id('seq')} > ${4}`);
      await f.db.write(tx =>
        auditOps.setHead(tx, { seq: 4, hash: rows[3].hash, key_id: rows[3].key_id, updated_at: 1 })
      );
      assert.equal((await check(f)).result, 'intact');
      const result = await check(f, { journal: journalOf(f) });
      assertProblem(result, 'journal_ahead', 5);
      assert.equal(result.problem.head, 4);
      assert.equal(result.problem.time, null);
      assert.equal(result.journal.matched, 4);
    }
  );
  await t.test('first rows deleted (no prune) → start_missing', async t => {
    const f = await logOf(t, 6);
    await remove(f.db, 'audit_log', sql`${sql.id('seq')} < ${3}`);
    assertProblem(await check(f), 'start_missing', 3);
  });
  await t.test('row inserted → link_broken', async t => {
    const f = await logOf(t, 6);
    // A copy of row 3 put in at seq 3, the rows from 3 on moved up one (seq is the key).
    const rows = await storedRows(f.db);
    await f.db.write(tx => {
      for (const row of rows.slice(2).reverse())
        tx.run(tx.dialect.update('audit_log', { seq: row.seq + 1 }, seqIs(row.seq)));
      auditOps.insertRow(tx, rows[2]);
      auditOps.setHead(tx, { seq: 7, hash: rows[5].hash, key_id: rows[5].key_id, updated_at: 1 });
    });
    assertProblem(await check(f), 'link_broken', 4);
  });
  await t.test('rows swapped → link_broken', async t => {
    const f = await logOf(t, 6);
    await f.db.write(tx => {
      tx.run(tx.dialect.update('audit_log', { seq: 100 }, seqIs(3)));
      tx.run(tx.dialect.update('audit_log', { seq: 3 }, seqIs(4)));
      tx.run(tx.dialect.update('audit_log', { seq: 4 }, seqIs(100)));
    });
    assertProblem(await check(f), 'link_broken', 3);
  });
  await t.test('prune checkpoint edited → checkpoint_mac', async t => {
    const f = await logOf(t, 6);
    await pruneThrough(f, 2);
    assert.equal((await check(f)).result, 'intact');
    await edit(f.db, 'audit_checkpoints', { time: 1 }, sql`${sql.id('seq')} = ${2}`);
    assertProblem(await check(f), 'checkpoint_mac', 2);
  });
  await t.test(
    'forged journal line → counted not written by this Uptime Goblin, and listed',
    async t => {
      const f = await logOf(t, 3);
      const rows = await storedRows(f.db);
      const forged = JSON.stringify({
        orbit: 'audit.checkpoint',
        v: 1,
        instance: 'i',
        seq: 3,
        time: rows[2].time,
        hash: rows[2].hash,
        key_id: rows[2].key_id,
        reason: 'commit',
        mac: 'f'.repeat(64),
      });
      const result = await check(f, {
        journal: `${journalOf(f)}\n${forged}\n{"orbit":"audit.checkpoint","v":1}\n{"orbit":"audit.checkpoint","broken`,
      });
      assert.equal(result.result, 'intact');
      assert.equal(result.journal.foreign, 2);
      assert.deepEqual(result.journal.foreignLines[0], { seq: 3, time: rows[2].time });
    }
  );
  await t.test('made-up kid → key_lost', async t => {
    const f = await logOf(t, 4);
    await edit(f.db, 'audit_log', { key_id: 'madeup123456' }, seqIs(2));
    assertProblem(await check(f), 'key_lost', 2);
  });
  await t.test('keyring audit rows deleted (a new audit key made at start) → key_lost', async t => {
    const f = await logOf(t, 3);
    await remove(f.db, 'keyring', sql`${sql.id('purpose')} = ${'audit'}`);
    const keyring = await Keyring.open(f.control.keyringStore, { key: Buffer.alloc(32, 0xa1) });
    assertProblem(await verifyAudit(f.db, { keyring }), 'key_lost', 1);
  });
  await t.test('checkpoint with a made-up kid → checkpoint_mac', async t => {
    const f = await logOf(t, 6);
    await pruneThrough(f, 2);
    await edit(f.db, 'audit_checkpoints', { key_id: 'madeup123456' }, sql`${sql.id('seq')} = ${2}`);
    assertProblem(await check(f), 'checkpoint_mac', 2);
  });
  // A key.reset excuses a kid only when it is signed (SEC-1): someone with the database but not
  // the key cannot make the rows they wrote under a made-up kid "not fully checked".
  await t.test(
    'forged key reset under a made-up kid → key_lost at the row it was to excuse',
    async t => {
      const f = await logOf(t, 4);
      const rows = await storedRows(f.db);
      await edit(f.db, 'audit_log', { key_id: 'madeup123456' }, seqIs(2));
      await insertForged(f, resetEvent(['madeup123456'], { seq: 4, hash: rows[3].hash }), {
        seq: 5,
        kid: 'madeup123456',
        prev: rows[3].hash,
        hash: 'a'.repeat(64),
      });
      const result = await check(f);
      assertProblem(result, 'key_lost', 2);
      assert.deepEqual(result.unverifiable, []);
    }
  );
  await t.test('forged key reset written as v 2 (not checkable) → key_lost', async t => {
    const f = await logOf(t, 4);
    const rows = await storedRows(f.db);
    await edit(f.db, 'audit_log', { key_id: 'madeup123456' }, seqIs(2));
    await insertForged(f, resetEvent(['madeup123456'], { seq: 4, hash: rows[3].hash }), {
      seq: 5,
      kid: f.keyring.activeKid('audit'),
      prev: rows[3].hash,
      hash: 'a'.repeat(64),
      v: 2,
    });
    assertProblem(await check(f), 'key_lost', 2);
  });
  await t.test('forged key reset naming a forged row after it as its head → key_lost', async t => {
    const f = await logOf(t, 4);
    const rows = await storedRows(f.db);
    const forgedHash = 'b'.repeat(64);
    await insertForged(f, resetEvent(['madeup123456'], { seq: 6, hash: forgedHash }), {
      seq: 5,
      kid: 'madeup123456',
      prev: rows[3].hash,
      hash: 'a'.repeat(64),
    });
    await insertForged(
      f,
      {
        action: 'session.login',
        outcome: 'ok',
        actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_x1' },
        target: { type: 'session', id: 's_x1', name: null },
        detail: { persistent: false, transport: 'https', ended: 0 },
      },
      { seq: 6, kid: 'madeup123456', prev: 'a'.repeat(64), hash: forgedHash }
    );
    assertProblem(await check(f), 'key_lost', 5);
  });
  await t.test('a signed reset whose head is not before it excuses nothing after it', async t => {
    // Only a writer with the key could make this; a real reset names the head it followed.
    const f = await logOf(t, 4);
    const rows = await storedRows(f.db);
    const reset = await insertForged(
      f,
      resetEvent(['lost00000001'], { seq: 6, hash: 'b'.repeat(64) }),
      { seq: 5, kid: f.keyring.activeKid('audit'), prev: rows[3].hash, signed: true }
    );
    await insertForged(f, stop(6), {
      seq: 6,
      kid: 'lost00000001',
      prev: reset.hash,
      hash: 'b'.repeat(64),
    });
    assertProblem(await check(f), 'key_lost', 6);
  });
  await t.test('rows deleted after a completed prune → start_missing', async t => {
    const f = await logOf(t, 6);
    await pruneThrough(f, 2);
    await remove(f.db, 'audit_log', sql`${sql.id('seq')} <= ${4}`);
    assertProblem(await check(f), 'start_missing', 5);
  });
  // Review round 1: Uptime Goblin prints a commit checkpoint after every unit, signed as a prune one is.
  // Someone with the journal (docker logs, journald) and the database but not the key stores one
  // as a checkpoint and deletes the entries up to it: only a prune checkpoint explains a start.
  await t.test(
    'a commit line from the journal stored as a checkpoint, the entries up to it deleted → start_missing',
    async t => {
      const f = await logOf(t, 10);
      const journal = journalOf(f);
      const line = linesOf(f.out, 'audit.checkpoint').find(item => item.seq === 8);
      assert.equal(line.reason, 'commit');
      const { orbit, v, instance, ...stored } = line;
      await f.db.write(tx => auditOps.insertCheckpoint(tx, stored));
      const kept = await check(f, { journal });
      assert.equal(kept.result, 'intact', 'stored alone, it changes nothing');
      assert.deepEqual(kept.checkpoints, { checked: 0, matched: 0 }, 'and it is not read');
      await remove(f.db, 'audit_log', sql`${sql.id('seq')} <= ${8}`);
      assertProblem(await check(f), 'start_missing', 9);
      const withJournal = await check(f, { journal });
      assertProblem(withJournal, 'start_missing', 9);
      assert.equal(withJournal.journal.matched, 2, 'only the lines of #9 and #10');
    }
  );
  await t.test(
    'no key: rows deleted after a completed prune, the next relinked to its checkpoint → start_missing from the journal',
    async t => {
      // Without the key the relinked row's hash is not checked; the journal lines of the rows
      // deleted below it, which no stored checkpoint covers, still show the start is missing.
      const f = await logOf(t, 6);
      const rows = await storedRows(f.db);
      await pruneThrough(f, 3);
      await remove(f.db, 'audit_log', sql`${sql.id('seq')} <= ${5}`);
      await edit(f.db, 'audit_log', { prev_hash: rows[2].hash }, seqIs(6));
      assert.equal((await verifyAudit(f.db, { keyring: null })).result, 'incomplete');
      const result = await verifyAudit(f.db, { keyring: null, journal: journalOf(f) });
      assertProblem(result, 'start_missing', 6);
      assert.equal(result.journal.matched, 4, 'lines 1–3 (the checkpoint) and 6');
    }
  );
  await t.test('a gap row that does not follow the row before it → seq_gap', async t => {
    const f = await logOf(t, 3);
    const rows = await storedRows(f.db);
    // The head ahead of the rows: the next unit writes audit.gap at 6, linked to row 3.
    await f.db.write(tx =>
      auditOps.setHead(tx, { seq: 5, hash: rows[2].hash, key_id: rows[2].key_id, updated_at: 1 })
    );
    await f.audit.append(stop(9));
    assertProblem(await check(f), 'log_truncated', 6);
    await edit(f.db, 'audit_log', { prev_hash: 'a'.repeat(64) }, seqIs(6));
    const result = await check(f);
    assertProblem(result, 'seq_gap', 4);
    assert.deepEqual([result.problem.from, result.problem.to], [4, 5]);
  });
  await t.test('gap row → log_truncated', async t => {
    const f = await logOf(t, 3);
    await f.db.write(tx =>
      tx.run(tx.dialect.deleteFrom('audit_head', sql`${sql.id('id')} = ${1}`))
    );
    await f.audit.append(stop(9));
    const result = await check(f);
    assertProblem(result, 'log_truncated', 4);
    assert.equal(result.problem.head, null);
    assert.equal(result.problem.lastSeq, 3);
    assert.match(
      result.problem.message,
      /it had last written an unknown entry, and the log ended at entry #3\./
    );
  });
  await t.test('Infinity detail → hash_mismatch at its seq, no crash', async t => {
    const f = await logOf(t, 3);
    await edit(f.db, 'audit_log', { detail: '{"uptimeMs":1e400}' }, seqIs(2));
    assertProblem(await check(f), 'hash_mismatch', 2);
  });
  await t.test('out of range → unreadable at the first seq of the unit that failed', async t => {
    const f = await logOf(t, 12);
    await edit(f.db, 'audit_log', { time: 2n ** 53n + 1n }, seqIs(7));
    const result = await check(f, { chunk: 5 });
    assertProblem(result, 'unreadable', 6);
    assert.equal(result.rows.checked, 5);
    assert.equal(result.problem.time, null);
    const cli = await check(f, { oneUnit: true, chunk: 5 });
    assertProblem(cli, 'unreadable', 6);
  });
  await t.test('newer format: a v 2 row anywhere → newer_format, incomplete', async t => {
    const f = await logOf(t, 5);
    await edit(f.db, 'audit_log', { v: 2 }, seqIs(3));
    const result = await check(f);
    assert.equal(result.result, 'incomplete');
    assert.deepEqual(result.unverifiable, [{ reason: 'newer_format', from: 3, to: 3, v: 2 }]);
  });
  await t.test('instance changed: journal lines still match by their MAC', async t => {
    const f = await logOf(t, 3);
    await edit(
      f.db,
      'meta',
      { value: 'another-instance' },
      sql`${sql.id('key')} = ${'instance_id'}`
    );
    const result = await check(f, { journal: journalOf(f) });
    assert.equal(result.result, 'intact');
    assert.equal(result.journal.matched, 3);
  });
});

// The prune's own steps (§4.7): the checkpoint first, then the rows through `seq`.
async function pruneThrough(f, seq, { deleteRows = true } = {}) {
  const row = (await storedRows(f.db)).find(r => r.seq === seq);
  const kid = f.keyring.activeKid('audit');
  const instance = await f.control.meta.instanceId();
  const checkpoint = { seq, time: row.time, hash: row.hash, key_id: kid, reason: 'prune' };
  const mac = checkpointMac(data => f.keyring.hmac('audit', data, kid).mac, {
    ...checkpoint,
    instance,
  });
  await f.db.write(tx => auditOps.insertCheckpoint(tx, { ...checkpoint, mac }));
  if (deleteRows) await remove(f.db, 'audit_log', sql`${sql.id('seq')} <= ${seq}`);
}

test("legitimate: a prune complete and a prune interrupted are intact; a prune below a checkpoint's row is not compared", async t => {
  const complete = await logOf(t, 8);
  await pruneThrough(complete, 3);
  const done = await check(complete, { journal: journalOf(complete) });
  assert.equal(done.result, 'intact');
  assert.deepEqual(done.checkpoints, { checked: 1, matched: 1 });
  assert.equal(
    done.journal.matched,
    8,
    'lines below the first row are covered by the prune checkpoint'
  );
  // Interrupted: the checkpoint stored, some of the rows through it still there.
  const interrupted = await logOf(t, 8);
  await pruneThrough(interrupted, 4, { deleteRows: false });
  await remove(interrupted.db, 'audit_log', sql`${sql.id('seq')} <= ${2}`);
  assert.equal((await check(interrupted)).result, 'intact');
  // Deleting before the checkpoint is stored leaves the start unexplained.
  const early = await logOf(t, 8);
  await remove(early.db, 'audit_log', sql`${sql.id('seq')} <= ${2}`);
  assertProblem(await check(early), 'start_missing', 3);
});

test('legitimate: a key rotation verifies intact; a lost-key reset is incomplete, its rows and checkpoints unverifiable, their links still checked', async t => {
  const f = await logOf(t, 3);
  await f.keyring.rotate({ purposes: ['audit'] });
  for (let n = 0; n < 2; n++) await f.audit.append(stop(n));
  assert.notEqual((await storedRows(f.db))[4].key_id, (await storedRows(f.db))[0].key_id);
  assert.equal((await check(f, { journal: journalOf(f) })).result, 'intact');

  // A lost key: the reset writes key.reset in its own unit, signed by the new audit key.
  const g = await logOf(t, 4);
  await pruneThrough(g, 1);
  const lost = (await g.control.keyringStore.list())
    .filter(row => row.purpose === 'audit')
    .map(row => row.kid);
  const { keyring } = await Keyring.reset(g.control.keyringStore, {
    key: keyB,
    confirmLostKey: true,
    inUnit: (tx, signer) =>
      recordWith(
        tx,
        signer,
        {
          action: 'key.reset',
          outcome: 'ok',
          actor: { type: 'cli', id: null, name: 'cli:dana', via: 'cli', sessionId: null },
          target: { type: 'keyring', id: null, name: null },
          detail: { lostKeyIds: lost },
        },
        { clock: g.clock }
      ),
  });
  const after = createAudit({ db: g.db, clock: g.clock, out: line => g.out.push(line), err() {} });
  t.after(() => after.close());
  await after.attach({ keyring, instanceId: await g.control.meta.instanceId() });
  await after.append(stop(9));
  const result = await verifyAudit(g.db, { keyring, journal: g.out.join('\n') });
  assert.equal(result.result, 'incomplete', JSON.stringify(result.problem));
  assert.deepEqual(result.unverifiable, [
    { reason: 'key_reset', from: 2, to: 4, keyIds: lost, anchorSeq: 5, at: result.anchors[0].time },
  ]);
  assert.deepEqual(
    result.anchors.map(a => [a.action, a.head?.seq]),
    [['key.reset', 4]]
  );
  assert.equal(result.journal.foreign, 0, 'lines signed by the lost key are compared, not foreign');
  assert.equal(result.journal.matched, journalLines(g.out.join('\n')).length);
  // A reset whose head names another hash than the row stored there excuses nothing: the prune
  // checkpoint and the rows signed by the lost key are breaks (the first by seq is the stored
  // checkpoint at #1; the edit also breaks the reset row's own hash).
  const [anchor] = (await storedRows(g.db)).filter(row => row.action === 'key.reset');
  const forged = { ...anchor.detail, head: { ...anchor.detail.head, hash: 'b'.repeat(64) } };
  await edit(g.db, 'audit_log', { detail: JSON.stringify(forged) }, seqIs(anchor.seq));
  const excused = await verifyAudit(g.db, { keyring });
  assertProblem(excused, 'checkpoint_mac', 1);
  assert.deepEqual(excused.unverifiable, []);
  await edit(g.db, 'audit_log', { detail: anchor.detailText }, seqIs(anchor.seq));
  // A reset covers the rows up to its head only: a row after it under a lost kid is a break.
  const [later] = (await storedRows(g.db)).filter(row => row.seq === 6);
  await edit(g.db, 'audit_log', { key_id: lost[0] }, seqIs(6));
  assertProblem(await verifyAudit(g.db, { keyring }), 'key_lost', 6);
  await edit(g.db, 'audit_log', { key_id: later.key_id }, seqIs(6));
  // Their links are still checked: an edited link under the lost key is broken.
  await edit(g.db, 'audit_log', { prev_hash: 'c'.repeat(64) }, seqIs(3));
  assertProblem(await verifyAudit(g.db, { keyring }), 'link_broken', 3);
});

test('legitimate: a second lost-key reset keeps the first one: both ranges are unverifiable, never key_lost', async t => {
  const g = await logOf(t, 3);
  const first = await resetLostKey(g, keyB);
  const between = createAudit({ db: g.db, clock: g.clock, out() {}, err() {} });
  t.after(() => between.close());
  await between.attach({ keyring: first.keyring, instanceId: 'i' });
  for (let n = 0; n < 2; n++) await between.append(stop(n));
  // The second key is lost too: the first reset's own row is now signed by a lost key.
  const second = await resetLostKey(g, Buffer.alloc(32, 0xc3));
  const after = createAudit({ db: g.db, clock: g.clock, out() {}, err() {} });
  t.after(() => after.close());
  await after.attach({ keyring: second.keyring, instanceId: 'i' });
  await after.append(stop(9));
  const result = await verifyAudit(g.db, { keyring: second.keyring });
  assert.equal(result.result, 'incomplete', JSON.stringify(result.problem));
  const at = seq => result.anchors.find(anchor => anchor.seq === seq).time;
  assert.deepEqual(result.unverifiable, [
    { reason: 'key_reset', from: 1, to: 3, keyIds: first.lost, anchorSeq: 4, at: at(4) },
    { reason: 'key_reset', from: 4, to: 6, keyIds: second.lost, anchorSeq: 7, at: at(7) },
  ]);
  assert.deepEqual(
    result.anchors.map(a => [a.seq, a.head?.seq]),
    [
      [4, 3],
      [7, 6],
    ]
  );
});

test('legitimate: a snapshot restore is intact without a journal, not fully checked with lines from before it, intact with only the lines after', async t => {
  const f = await logOf(t, 6);
  const rows = await storedRows(f.db);
  const linesBefore = journalOf(f);
  // The snapshot was taken at row 4; restoring it brings back rows 1–4 and the head of then,
  // and restore-snapshot stamps meta.restored.
  await f.db.write(tx => {
    tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} > ${4}`));
    auditOps.setHead(tx, { seq: 4, hash: rows[3].hash, key_id: rows[3].key_id, updated_at: 1 });
    auditOps.setMeta(tx, 'restored', JSON.stringify({ snapshot: 'manual-1', at: f.clock() }), 1);
  });
  f.clock.advance(60000);
  const restarted = createAudit({
    db: f.db,
    clock: f.clock,
    out: line => afterLines.push(line),
    err() {},
  });
  const afterLines = [];
  t.after(() => restarted.close());
  await restarted.attach({ keyring: f.keyring, instanceId: await f.control.meta.instanceId() });
  await recordIn(f.db, restarted, stop(7));
  await restarted.append(stop(8));
  const alone = await check(f);
  assert.equal(alone.result, 'intact');
  assert.deepEqual(
    alone.anchors.map(a => [a.action, a.cause, a.restoredHead?.seq]),
    [['system.restore', 'snapshot', 4]]
  );
  const whole = await check(f, { journal: `${linesBefore}\n${afterLines.join('\n')}` });
  assert.equal(whole.result, 'incomplete');
  assert.deepEqual(whole.unverifiable, [
    {
      reason: 'restore_unchecked',
      lines: 2,
      anchorSeq: 5,
      at: alone.anchors[0].at,
      cause: 'snapshot',
      snapshot: 'manual-1',
    },
  ]);
  assert.deepEqual(whole.journal, {
    lines: 8,
    matched: 6,
    unchecked: 2,
    foreign: 0,
    coveredTo: 7,
    foreignLines: [],
  });
  const after = await check(f, { journal: afterLines.join('\n') });
  assert.equal(after.result, 'intact');
  // A restore excuses only lines printed before it: one printed after it that names another
  // hash at a stored seq is a break.
  const late = signedLine(f, { seq: 6, time: f.clock() + 1000, hash: 'a'.repeat(64) });
  const changed = await check(f, { journal: `${afterLines.join('\n')}\n${late}` });
  assertProblem(changed, 'journal_mismatch', 6);
});

test('forged restore: a tail cut with a forged meta.restored, anchored at the next start, against a journal from before is incomplete, never intact', async t => {
  const f = await logOf(t, 6);
  const rows = await storedRows(f.db);
  const linesBefore = journalOf(f);
  await f.db.write(tx => {
    tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} > ${3}`));
    auditOps.setHead(tx, { seq: 3, hash: rows[2].hash, key_id: rows[2].key_id, updated_at: 1 });
    auditOps.setMeta(tx, 'restored', JSON.stringify({ snapshot: 'made-up', at: 1 }), 1);
  });
  f.clock.advance(60000);
  const next = createAudit({ db: f.db, clock: f.clock, out() {}, err() {} });
  t.after(() => next.close());
  await next.attach({ keyring: f.keyring, instanceId: 'i' });
  await next.append(stop(9));
  const result = await check(f, { journal: linesBefore });
  assert.equal(result.result, 'incomplete');
  assert.equal(result.unverifiable[0].reason, 'restore_unchecked');
  assert.equal(result.unverifiable[0].lines, 3);
  assert.equal(result.anchors[0].snapshot, 'made-up', 'every restore is listed');
});

// Review round 1: the hourly prune deletes the restore and key.reset rows like any other entry,
// while the journal the admin keeps still holds the lines they explained. Lines printed before the
// entry the newest prune checkpoint names, or under a lost key at or below it, are covered by
// that checkpoint: a restore never turns into CHANGED, nor a lost-key reset into unknown keys.
test('legitimate: a snapshot restore, then the prune removes its anchor: never CHANGED against the whole journal', async t => {
  const DAY = 86400000;
  const f = await auditFixture(t, { retention: { days: 30, maxRows: 250000 } });
  for (let n = 1; n <= 10; n++) {
    await f.audit.append(stop(n));
    f.clock.advance(1000);
  }
  await f.audit.close();
  // restore-snapshot of a snapshot taken at #3: rows 1–3, their head, meta.restored stamped.
  const third = (await storedRows(f.db)).find(row => row.seq === 3);
  await f.db.write(tx => {
    tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} > ${3}`));
    auditOps.setHead(tx, { seq: 3, hash: third.hash, key_id: third.key_id, updated_at: 1 });
    auditOps.setMeta(tx, 'restored', JSON.stringify({ snapshot: 'manual-1', at: f.clock() }), 1);
  });
  f.clock.advance(3600000);
  const out = [...f.out];
  const next = createAudit({
    db: f.db,
    clock: f.clock,
    retention: { days: 30, maxRows: 250000 },
    out: line => out.push(line),
    err() {},
    log: { warn() {} },
  });
  t.after(() => next.close());
  await next.attach({ keyring: f.keyring, instanceId: await f.control.meta.instanceId() });
  // The anchor (#4) and a row on the day of the restore; six rows 20 days later, past #10.
  await next.append(stop(100));
  f.clock.advance(20 * DAY);
  for (let n = 0; n < 6; n++) {
    await next.append(stop(200 + n));
    f.clock.advance(1000);
  }
  const before = await check(f, { journal: out.join('\n') });
  assert.equal(before.result, 'incomplete', JSON.stringify(before.problem));
  assert.equal(before.unverifiable[0].reason, 'restore_unchecked');
  // 45 days after the restore the prune removes the rows of that day, the anchor among them.
  f.clock.advance(25 * DAY);
  await next.append(stop(300));
  await next.maintain({});
  await next.idle();
  const left = await storedRows(f.db);
  assert.ok(left[0].seq > 5, `the anchor was pruned (first #${left[0].seq})`);
  assert.ok(
    left.some(row => row.seq <= 10),
    'rows the restore replaced still share seqs with lines'
  );
  const after = await check(f, { journal: out.join('\n') });
  assert.equal(after.result, 'intact', JSON.stringify(after.problem));
  assert.equal(after.journal.foreign, 0);
  assert.equal(after.journal.matched, after.journal.lines);
  // A line printed after that prune's entry still counts: another hash at a stored seq is a
  // break, as it is before any prune.
  const late = signedLine(f, { seq: left[1].seq, time: f.clock(), hash: 'a'.repeat(64) });
  assertProblem(
    await check(f, { journal: `${out.join('\n')}\n${late}` }),
    'journal_mismatch',
    left[1].seq
  );
});

test('legitimate: a lost-key reset, then the prune removes the rows and the reset: pruned, and no unknown keys against the whole journal', async t => {
  const DAY = 86400000;
  const f = await auditFixture(t, { retention: { days: 30, maxRows: 250000 } });
  for (let n = 1; n <= 4; n++) {
    await f.audit.append(stop(n));
    f.clock.advance(1000);
  }
  const { keyring, lost } = await resetLostKey(f, keyB);
  const out = [...f.out];
  const after = createAudit({
    db: f.db,
    clock: f.clock,
    retention: { days: 30, maxRows: 250000 },
    out: line => out.push(line),
    err() {},
    log: { warn() {} },
  });
  t.after(() => after.close());
  await after.attach({ keyring, instanceId: await f.control.meta.instanceId() });
  await after.append(stop(9));
  const before = await verifyAudit(f.db, { keyring, journal: out.join('\n') });
  assert.equal(before.result, 'incomplete');
  assert.deepEqual(
    before.unverifiable.map(item => [item.reason, item.from, item.to, item.keyIds]),
    [['key_reset', 1, 4, lost]]
  );
  f.clock.advance(40 * DAY);
  for (let n = 0; n < 3; n++) await after.append(stop(100 + n));
  // The rows the lost key signed expire too: the prune checks them under the reset.
  await after.maintain({});
  await after.idle();
  const left = await storedRows(f.db);
  assert.ok(
    left.every(row => row.action !== 'key.reset' && !lost.includes(row.key_id)),
    'the rows the lost key signed, and the reset, were pruned'
  );
  const result = await verifyAudit(f.db, { keyring, journal: out.join('\n') });
  assert.equal(result.result, 'intact', JSON.stringify(result.unverifiable));
  assert.equal(result.journal.foreign, 0);
  assert.equal(result.journal.matched, result.journal.lines);
});

// Review round 1: the texts take values from stored rows, which someone with the database can set
// to anything, and goblin-admin verify-audit prints them to a terminal.
test('texts: stored values lose control and format characters and are cut to 200 characters; entry numbers that are not whole numbers read as unknown; a snapshot name is never a placeholder', () => {
  const at = Date.UTC(2026, 9, 3, 12);
  const words = unverifiableText({
    reason: 'restore_unchecked',
    lines: 2,
    anchorSeq: 5,
    at,
    cause: 'snapshot',
    snapshot: "\u001b[2K{lines} $' #{anchorSeq}\u202e",
  });
  assert.equal(
    words,
    "2 checkpoint lines that Uptime Goblin printed before the data was restored from snapshot [2K{lines} $' #{anchorSeq} on 2026-10-03 12:00:00 UTC could not be checked against the restored log. Check only the part of Uptime Goblin's log printed after the restore to get a full result."
  );
  const [restore] = anchorLines({
    seq: 4,
    time: at,
    action: 'system.restore',
    cause: 'snapshot',
    snapshot: `\u0007${'x'.repeat(300)}`,
    at,
    restoredHead: { seq: '3\u001b[1A', hash: 'a' },
  });
  assert.equal(
    restore,
    `Restored from snapshot ${'x'.repeat(200)} on 2026-10-03 12:00:00 UTC; the log continues from entry #?.`
  );
  assert.deepEqual(
    problemTexts('log_truncated', { seq: 6, time: at, head: { seq: 1 }, lastSeq: '\u001b[2K5' }),
    {
      message:
        'On 2026-10-03 12:00:00 UTC Uptime Goblin found its audit log cut or changed at the end: it had last written an unknown entry, and the log ended at no entry.',
      consequence:
        'Entries Uptime Goblin wrote after no entry are missing or were changed; the entries before were checked.',
    }
  );
});

test('chunked while appending: a route-style check reads up to the newest row of its first unit; rows appended meanwhile are outside it', async t => {
  const f = await logOf(t, 50);
  let appended = 0;
  const result = await verifyAudit(f.db, {
    keyring: f.keyring,
    chunk: 10,
    onUnit: () => {
      appended += 1;
      void f.audit.append(stop(100 + appended));
    },
  });
  await f.audit.idle();
  assert.equal(result.result, 'intact', JSON.stringify(result.problem));
  assert.equal(result.rows.checked, 50);
  assert.ok(appended >= 5);
  assert.ok((await storedRows(f.db)).length > 50);
});

test('no key: links, seqs and hashes only; at best incomplete (no_key)', async t => {
  const f = await logOf(t, 4);
  const result = await verifyAudit(f.db, { keyring: null, journal: journalOf(f) });
  assert.equal(result.result, 'incomplete');
  assert.equal(result.keyChecked, false);
  assert.deepEqual(result.unverifiable, [{ reason: 'no_key' }]);
  assert.equal(result.journal.matched, 4);
  // A link edit is still found without the key; a detail edit is not (that needs the MAC).
  await edit(f.db, 'audit_log', { prev_hash: 'd'.repeat(64) }, seqIs(2));
  assertProblem(await verifyAudit(f.db, { keyring: null }), 'link_broken', 2);
  const empty = await auditFixture(t);
  assert.equal(
    (await verifyAudit(empty.db, { keyring: null })).result,
    'intact',
    'nothing to check'
  );
});

test('stored checkpoint names a row with another hash → checkpoint_mismatch; a line with a valid MAC and another hash → journal_mismatch', async t => {
  const f = await logOf(t, 6);
  const rows = await storedRows(f.db);
  const kid = f.keyring.activeKid('audit');
  const instance = await f.control.meta.instanceId();
  const checkpoint = {
    seq: 4,
    time: rows[3].time,
    hash: 'e'.repeat(64),
    key_id: kid,
    reason: 'prune',
  };
  const mac = checkpointMac(data => f.keyring.hmac('audit', data, kid).mac, {
    ...checkpoint,
    instance,
  });
  await f.db.write(tx => auditOps.insertCheckpoint(tx, { ...checkpoint, mac }));
  const result = await check(f);
  assertProblem(result, 'checkpoint_mismatch', 4);
  assert.deepEqual(result.checkpoints, { checked: 1, matched: 0 });
  const g = await logOf(t, 4);
  const journal = `${journalOf(g)}\n${signedLine(g, { seq: 2, time: 5, hash: 'a'.repeat(64) })}`;
  const mismatch = await check(g, { journal });
  assertProblem(mismatch, 'journal_mismatch', 2);
  assert.equal(mismatch.problem.lineTime, 5);
  assert.equal(linesOf(g.out, 'audit.checkpoint').length, 4);
});

// Integration (the independent check's finding 1): journal lines signed with a key the keyring
// does not hold, which no recorded reset removed, can be this Uptime Goblin's, so they never leave the
// result intact. Someone with the database but not the key cuts the entries a rotated audit key
// signed, puts the head back on the newest entry left, deletes that key from the keyring and
// makes the older one active again: the database alone is intact (as for any cut whose head is
// rewritten), and the journal lines of the cut entries would otherwise read as another Uptime Goblin's.
test('journal lines under a key the keyring does not hold (and no reset removed) leave the result incomplete, never intact', async t => {
  const f = await logOf(t, 3);
  const older = f.keyring.activeKid('audit');
  await f.keyring.rotate({ purposes: ['audit'] });
  const rotated = f.keyring.activeKid('audit');
  assert.notEqual(rotated, older);
  for (let n = 4; n <= 6; n++) await f.audit.append(stop(n));
  const journal = journalOf(f);
  assert.equal((await check(f, { journal })).result, 'intact', 'before the cut');
  await remove(f.db, 'audit_log', sql`${sql.id('key_id')} = ${rotated}`);
  const last = (await storedRows(f.db)).at(-1);
  await f.db.write(tx =>
    auditOps.setHead(tx, { seq: last.seq, hash: last.hash, key_id: older, updated_at: 1 })
  );
  await remove(f.db, 'keyring', sql`${sql.id('kid')} = ${rotated}`);
  await edit(f.db, 'keyring', { retired_at: null }, sql`${sql.id('kid')} = ${older}`);
  const keyring = await Keyring.open(f.control.keyringStore, { key: keyA, create: false });
  assert.equal((await verifyAudit(f.db, { keyring })).result, 'intact', 'the database alone');
  const result = await verifyAudit(f.db, { keyring, journal });
  assert.equal(result.result, 'incomplete', JSON.stringify(result));
  assert.equal(result.problem, null);
  assert.deepEqual(result.unverifiable, [{ reason: 'unknown_key', lines: 3, keyIds: [rotated] }]);
  assert.equal(result.journal.matched, 3);
  assert.equal(result.journal.foreign, 3, 'still counted not written by this Uptime Goblin');
  assert.deepEqual(
    result.journal.foreignLines.map(line => line.seq),
    [4, 5, 6]
  );
  // Another Uptime Goblin's lines (a keyring of its own) read the same: nothing tells them apart.
  const other = await logOf(t, 2, { key: keyB });
  const mixed = await verifyAudit(f.db, { keyring, journal: journalOf(other) });
  assert.equal(mixed.result, 'incomplete');
  assert.deepEqual(mixed.unverifiable, [
    { reason: 'unknown_key', lines: 2, keyIds: [other.keyring.activeKid('audit')] },
  ]);
  // A line under a key the keyring holds whose signature does not verify stays only foreign.
  const forged = JSON.stringify({ ...JSON.parse(f.out[0]), mac: 'f'.repeat(64) });
  const held = await verifyAudit(f.db, {
    keyring,
    journal: f.out.slice(0, 3).concat(forged).join('\n'),
  });
  assert.equal(held.result, 'intact');
  assert.equal(held.journal.foreign, 1);
});

// Review round 2: the same cut once a prune checkpoint is stored, which every install has after
// its first prune. A prune covers a line under a key the keyring does not hold only when the line
// names an entry below the first one left (with a prune checkpoint at or above it) or was
// printed before the newest prune checkpoint (review round 1); the cut entries are newer than
// both. Until the next prune signs a checkpoint with the rotated key, the newest stored one is
// still the older key's, so only unknown_key finds the cut.
test('journal lines under a key the keyring does not hold, after a prune: lines newer than the newest prune checkpoint are still unknown_key, never matched or intact', async t => {
  const DAY = 86400000;
  const f = await auditFixture(t, { retention: { days: 30, maxRows: 250000 } });
  for (let n = 1; n <= 3; n++) {
    await f.audit.append(stop(n));
    f.clock.advance(1000);
  }
  f.clock.advance(40 * DAY);
  for (let n = 4; n <= 6; n++) {
    await f.audit.append(stop(n));
    f.clock.advance(1000);
  }
  await f.audit.maintain({});
  await f.audit.idle();
  const pruned = (await f.db.read(tx => auditOps.checkpoints(tx))).filter(
    c => c.reason === 'prune'
  );
  assert.equal(pruned.length, 1, 'a prune checkpoint is stored');
  const older = f.keyring.activeKid('audit');
  assert.equal(pruned[0].key_id, older);
  f.clock.advance(1000);
  await f.keyring.rotate({ purposes: ['audit'] });
  const rotated = f.keyring.activeKid('audit');
  assert.notEqual(rotated, older);
  for (let n = 7; n <= 9; n++) {
    await f.audit.append(stop(n));
    f.clock.advance(1000);
  }
  const journal = journalOf(f);
  const before = await check(f, { journal });
  assert.equal(before.result, 'intact', JSON.stringify(before.problem));
  assert.equal(before.journal.matched, before.journal.lines);
  const cut = (await storedRows(f.db)).filter(row => row.key_id === rotated);
  assert.equal(cut.length, 3);
  const first = (await storedRows(f.db))[0];
  assert.ok(first.seq > 1, 'the prune removed the oldest entries');
  for (const row of cut)
    assert.ok(row.seq >= first.seq && row.time > pruned[0].time, 'newer than the prune');
  await remove(f.db, 'audit_log', sql`${sql.id('key_id')} = ${rotated}`);
  const last = (await storedRows(f.db)).at(-1);
  await f.db.write(tx =>
    auditOps.setHead(tx, { seq: last.seq, hash: last.hash, key_id: older, updated_at: 1 })
  );
  await remove(f.db, 'keyring', sql`${sql.id('kid')} = ${rotated}`);
  await edit(f.db, 'keyring', { retired_at: null }, sql`${sql.id('kid')} = ${older}`);
  const keyring = await Keyring.open(f.control.keyringStore, { key: keyA, create: false });
  const alone = await verifyAudit(f.db, { keyring });
  assert.equal(alone.result, 'intact', 'the database alone');
  assert.deepEqual(alone.checkpoints, { checked: 1, matched: 1 });
  const result = await verifyAudit(f.db, { keyring, journal });
  assert.equal(result.result, 'incomplete', JSON.stringify(result));
  assert.equal(result.problem, null);
  assert.deepEqual(result.unverifiable, [
    { reason: 'unknown_key', lines: cut.length, keyIds: [rotated] },
  ]);
  assert.equal(result.journal.matched, result.journal.lines - cut.length);
  assert.equal(result.journal.foreign, cut.length);
  assert.deepEqual(
    result.journal.foreignLines.map(line => line.seq),
    cut.map(row => row.seq)
  );
});

// Codex review A1: Uptime Goblin numbers its entries from 1 (D27), and the walk started after seq 0. Someone
// with the database but not the key copied a row to seq 0 or -1 with another detail and a made-up
// hash: it was listed and exported while both modes, against every genuine journal line, read
// intact. The first unit now reads the lowest stored seq, the walk starts at the lowest stored
// row, and a row outside 1…Number.MAX_SAFE_INTEGER is link_broken at its own seq.
const rawSeqs = db =>
  db.read(tx =>
    tx
      .all(sql`SELECT ${sql.id('seq')} FROM ${sql.id('audit_log')} ORDER BY ${sql.id('seq')}`)
      .map(row => Number(row.seq))
  );
async function forgeAt(f, seq, { signed = false } = {}) {
  const [legitimate] = await storedRows(f.db);
  const forged = {
    ...legitimate,
    seq,
    detail: { uptimeMs: 999 },
    detailText: '{"uptimeMs":999}',
    hash: 'f'.repeat(64),
  };
  if (signed)
    forged.hash = rowHash(
      data => f.keyring.hmac('audit', data, forged.key_id).mac,
      forged.prev_hash,
      forged
    );
  await f.db.write(tx => auditOps.insertRow(tx, forged));
  return forged;
}

test('Codex review A1: a row at seq 0 or below is link_broken at its seq in both modes, with and without the key or the journal; the rows from 1 on are still checked; list and export still show it', async t => {
  for (const seq of [0, -1, -1234, Number.MIN_SAFE_INTEGER])
    await t.test(`a forged copy at seq ${seq}`, async t => {
      const f = await logOf(t, 3);
      const journal = journalOf(f);
      assert.equal((await check(f, { journal })).result, 'intact');
      const forged = await forgeAt(f, seq);
      for (const options of [
        {},
        { oneUnit: true },
        { chunk: 1 },
        { journal },
        { oneUnit: true, journal },
        { chunk: 1, journal },
      ]) {
        const result = await check(f, options);
        assertProblem(result, 'link_broken', seq);
        assert.equal(result.problem.time, forged.time);
        assert.equal(
          result.problem.message,
          `Entry #${grouped(seq)} does not follow the entry before it: an entry was changed, inserted or removed.`
        );
        assert.deepEqual(result.rows, {
          checked: 4,
          first: { seq, time: forged.time },
          last: { seq: 3, time: result.rows.last.time },
        });
        if (options.journal)
          assert.equal(result.journal.matched, 3, 'the genuine lines still match their rows');
      }
      // Without the key (goblin-admin with no key): the seq alone tells.
      const nokey = await verifyAudit(f.db, { keyring: null, journal, oneUnit: true });
      assertProblem(nokey, 'link_broken', seq);
      // Nothing is hidden: the list and the export still show the row verification names.
      const list = await f.audit.list(parseAuditQuery(new URLSearchParams(), 'list'));
      assert.ok(list.entries.some(entry => entry.seq === seq && entry.detail.uptimeMs === 999));
      const exported = await f.audit.export(
        parseAuditQuery(new URLSearchParams('format=ndjson'), 'export')
      );
      const sent = exported.body
        .toString()
        .trim()
        .split('\n')
        .map(line => JSON.parse(line))
        .filter(line => line.seq === seq);
      assert.equal(sent.length, 1);
      // Without it, the rows from seq 1 on read intact again.
      await remove(f.db, 'audit_log', seqIs(seq));
      assert.equal((await check(f, { journal })).result, 'intact');
    });
  await t.test(
    'signed with the key at seq 0 (what only someone with the key could do): still link_broken',
    async t => {
      const f = await logOf(t, 2);
      await forgeAt(f, 0, { signed: true });
      assertProblem(await check(f), 'link_broken', 0);
      assertProblem(await check(f, { oneUnit: true }), 'link_broken', 0);
    }
  );
  await t.test(
    'several rows at 0 and below, and a genuine log after them: the lowest is reported, each row read once',
    async t => {
      const f = await logOf(t, 3);
      for (const seq of [0, -1, -2]) await forgeAt(f, seq);
      for (const options of [{}, { oneUnit: true }, { chunk: 1 }, { chunk: 2 }]) {
        const result = await check(f, options);
        assertProblem(result, 'link_broken', -2);
        assert.equal(result.rows.checked, 6);
      }
    }
  );
  await t.test('only rows at 0 and below (the head among them or gone): never intact', async t => {
    const f = await logOf(t, 2);
    const rows = await storedRows(f.db);
    await edit(f.db, 'audit_log', { seq: -5 }, seqIs(1));
    await edit(f.db, 'audit_log', { seq: -4 }, seqIs(2));
    await f.db.write(tx =>
      auditOps.setHead(tx, { seq: -4, hash: rows[1].hash, key_id: rows[1].key_id, updated_at: 1 })
    );
    assertProblem(await check(f), 'link_broken', -5);
    assertProblem(await check(f, { oneUnit: true }), 'link_broken', -5);
    await remove(f.db, 'audit_head', sql`${sql.id('id')} = ${1}`);
    assertProblem(await check(f, { journal: journalOf(f) }), 'link_broken', -5);
    // The list and the export still show them: the export hides no row (§6.3).
    const list = await f.audit.list(parseAuditQuery(new URLSearchParams(), 'list'));
    assert.deepEqual(
      list.entries.map(entry => entry.seq),
      [-4, -5]
    );
    const exported = await f.audit.export(
      parseAuditQuery(new URLSearchParams('format=ndjson'), 'export')
    );
    assert.equal(exported.rows, 2);
    assert.deepEqual(
      exported.body
        .toString()
        .trim()
        .split('\n')
        .slice(1)
        .map(line => JSON.parse(line).seq),
      [-5, -4]
    );
  });
  await t.test(
    'the lowest stored seq is read in the first unit: a row at seq 0 removed before the walk reaches it still reads broken',
    async t => {
      const f = await logOf(t, 3);
      await forgeAt(f, 0);
      let reads = 0;
      // The route reads the start in its own unit; the row goes before the first unit of rows.
      const racing = {
        dialect: f.db.dialect,
        async read(fn) {
          reads += 1;
          if (reads === 2) await remove(f.db, 'audit_log', seqIs(0));
          return f.db.read(fn);
        },
      };
      const result = await verifyAudit(racing, { keyring: f.keyring });
      assertProblem(result, 'link_broken', 0);
      assert.deepEqual(await rawSeqs(f.db), [1, 2, 3]);
    }
  );
  // Controls (these read broken before the fix too): a seq beyond the safe range cannot be read
  // (unreadable, D28), and a head at seq 0 or below is not the newest row (head_mismatch).
  await t.test('beyond the safe range, above or below: unreadable, never intact', async t => {
    for (const seq of [2n ** 53n + 1n, -(2n ** 53n) - 1n]) {
      const f = await logOf(t, 3);
      await edit(f.db, 'audit_log', { seq }, seqIs(2));
      assertProblem(await check(f), 'unreadable', 1);
      assertProblem(await check(f, { oneUnit: true }), 'unreadable', 1);
    }
  });
  await t.test('a head at seq 0 or below: head_mismatch, never intact', async t => {
    const f = await logOf(t, 3);
    await f.db.write(tx =>
      auditOps.setHead(tx, { seq: 0, hash: 'a'.repeat(64), key_id: 'x', updated_at: 1 })
    );
    assertProblem(await check(f), 'head_mismatch', 3);
    const empty = await auditFixture(t);
    await empty.db.write(tx =>
      auditOps.setHead(tx, { seq: -1, hash: 'a'.repeat(64), key_id: 'x', updated_at: 1 })
    );
    assertProblem(await check(empty), 'head_mismatch', 0);
  });
});
