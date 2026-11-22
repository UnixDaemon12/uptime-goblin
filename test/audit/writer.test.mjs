// The audit writer and service (lib/audit/writer.mjs, lib/audit/index.mjs; audit spec §4.1, §4.3,
// §4.6–§4.8, §5.6, D4, D7, D8, D15, D16, D27, D32) over a real, migrated control.sqlite and a real
// keyring: the chain from genesis, the head check, restore anchors, the inbox, validation, what a
// failure does inside another component's unit, retried units, the lines, lost result rows, the
// full disk, the start rows, the configuration keys, the prune, close() and the method names.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { sql } from '../../lib/db/sql.mjs';
import { auditOps, rowOf } from '../../lib/repo/audit.mjs';
import { createAudit } from '../../lib/audit/index.mjs';
import { noopAudit } from '../../lib/audit/noop.mjs';
import { AUDIT_TEXTS } from '../../lib/audit/actions.mjs';
import { GENESIS, checkpointMac } from '../../lib/audit/chain.mjs';
import { appendDirect, planUnit, writePlan } from '../../lib/audit/writer.mjs';
import { checkPrune, verifyAudit } from '../../lib/audit/verify.mjs';
import { ConfigStore } from '../../lib/config.mjs';
import { retryOnce } from '../helpers/retry-once.mjs';
import { auditSentinels, findSentinels } from '../helpers/audit-sentinels.mjs';
import {
  adminRequest,
  auditFixture,
  linesOf,
  manualClock,
  migratedControl,
  openKeyring,
  recordIn,
  release,
  storedRows,
  temporary,
} from './helpers.mjs';

const stop = (uptimeMs = 1) => ({ action: 'system.stop', outcome: 'info', detail: { uptimeMs } });
const login = (sessionId = 's_new1') => ({
  action: 'session.login',
  outcome: 'ok',
  actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId },
  target: { type: 'session', id: sessionId, name: null },
  detail: { persistent: false, transport: 'https', ended: 0 },
});
const actionsOf = rows => rows.map(row => row.action);
const meta = (db, key) => db.read(tx => auditOps.meta(tx, key));
const setMeta = (db, key, value) => db.write(tx => auditOps.setMeta(tx, key, value, 1));
// A guard whose state the test sets.
const fakeGuard = () => {
  const guard = { full: false, state: () => ({ full: guard.full }) };
  return guard;
};
// wrapDb that records each own unit's purpose, and can fail chosen purposes.
function countingWrap({
  fail = new Set(),
  error = () => Object.assign(new Error('disk full'), { class: 'full' }),
} = {}) {
  const seen = [];
  const wrap = (db, purpose) => {
    seen.push(purpose);
    if (!fail.has(purpose)) return db;
    return {
      dialect: db.dialect,
      read: (...args) => db.read(...args),
      write: async () => {
        throw error();
      },
    };
  };
  wrap.seen = seen;
  return wrap;
}

test('genesis: the first row has seq 1 and prev_hash GENESIS, the next follows it', async t => {
  const { audit, db } = await auditFixture(t);
  assert.deepEqual(await audit.append(stop(1)), { seq: 1 });
  assert.deepEqual(await audit.append(stop(2)), { seq: 2 });
  const rows = await storedRows(db);
  assert.equal(rows[0].seq, 1);
  assert.equal(rows[0].prev_hash, GENESIS);
  assert.equal(rows[1].prev_hash, rows[0].hash);
  assert.deepEqual(await db.read(tx => auditOps.head(tx)), {
    seq: 2,
    hash: rows[1].hash,
    keyId: rows[1].key_id,
  });
});

test('head check: every disagreement writes one audit.gap and continues after the newest row, in an own unit and through record()', async t => {
  // Each case damages the head or the rows, then appends: the unit's first row is the gap, at
  // the higher seq + 1, linked to the newest row; no UNIQUE error.
  const cases = {
    'a head without rows': async db => {
      await db.write(tx =>
        tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} > ${0}`))
      );
      return { head: { seq: 3 }, lastSeq: null, nextSeq: 4, prev: GENESIS };
    },
    'rows without a head': async (db, rows) => {
      await db.write(tx =>
        tx.run(tx.dialect.deleteFrom('audit_head', sql`${sql.id('id')} = ${1}`))
      );
      return { head: null, lastSeq: 3, nextSeq: 4, prev: rows[2].hash };
    },
    'the head behind': async (db, rows) => {
      await db.write(tx =>
        auditOps.setHead(tx, { seq: 2, hash: rows[1].hash, key_id: 'x', updated_at: 1 })
      );
      return { head: { seq: 2 }, lastSeq: 3, nextSeq: 4, prev: rows[2].hash };
    },
    'the head ahead': async (db, rows) => {
      await db.write(tx =>
        auditOps.setHead(tx, { seq: 9, hash: 'a'.repeat(64), key_id: 'x', updated_at: 1 })
      );
      return { head: { seq: 9 }, lastSeq: 3, nextSeq: 10, prev: rows[2].hash };
    },
    'the same seq with another hash': async (db, rows) => {
      await db.write(tx =>
        auditOps.setHead(tx, { seq: 3, hash: 'b'.repeat(64), key_id: 'x', updated_at: 1 })
      );
      return { head: { seq: 3 }, lastSeq: 3, nextSeq: 4, prev: rows[2].hash };
    },
  };
  for (const [name, damage] of Object.entries(cases))
    for (const way of ['own unit', 'record()']) {
      await t.test(`${name}, ${way}`, async t => {
        const { audit, db } = await auditFixture(t);
        for (let n = 1; n <= 3; n++) await audit.append(stop(n));
        const expected = await damage(db, await storedRows(db));
        if (way === 'own unit') await audit.append(stop(9));
        else await recordIn(db, audit, login());
        const rows = await storedRows(db);
        const gap = rows.find(row => row.action === 'audit.gap');
        assert.ok(gap, 'a gap row');
        assert.equal(rows.filter(row => row.action === 'audit.gap').length, 1);
        assert.equal(gap.seq, expected.nextSeq);
        assert.equal(gap.prev_hash, expected.prev);
        assert.equal(gap.detail.reason, 'head-mismatch');
        assert.equal(gap.detail.head?.seq ?? null, expected.head?.seq ?? null);
        assert.equal(gap.detail.lastSeq, expected.lastSeq);
        const after = rows.at(-1);
        assert.equal(after.seq, gap.seq + 1);
        assert.equal(after.prev_hash, gap.hash);
        assert.deepEqual(await db.read(tx => auditOps.head(tx).seq), after.seq);
        // The next unit agrees with the head again: no second gap.
        await audit.append(stop(10));
        assert.equal((await storedRows(db)).filter(row => row.action === 'audit.gap').length, 1);
      });
    }
});

// Codex review A1: Uptime Goblin numbers its entries from 1 (D27). With the newest stored row moved to seq
// 0 or below by someone with the database, the next seq was that seq + 1: Uptime Goblin signed its own
// entries at -2, -1 and 0, rows verification now reads as never numbered by Uptime Goblin, and linked its
// rows to the moved one. The unit now starts the chain at seq 1 from GENESIS, as in an empty log
// (with the gap row first when the head disagrees), and the moved rows alone read link_broken.
const allSeqs = db =>
  db.read(tx =>
    tx
      .all(sql`SELECT ${sql.id('seq')} FROM ${sql.id('audit_log')} ORDER BY ${sql.id('seq')}`)
      .map(row => Number(row.seq))
  );
const rowsFromAll = db =>
  db.read(tx =>
    tx
      .all(sql`SELECT * FROM ${sql.id('audit_log')} ORDER BY ${sql.id('seq')}`)
      .map(raw => rowOf(raw))
  );
test('Codex review A1: head check: with the newest stored row at seq 0 or below, the unit starts the chain at seq 1 from GENESIS; Uptime Goblin never signs a row numbered 0 or below', async t => {
  const cases = {
    'the head and the newest row agree at seq -3': async (db, rows) => {
      await db.write(tx =>
        auditOps.setHead(tx, { seq: -3, hash: rows[1].hash, key_id: rows[1].key_id, updated_at: 1 })
      );
      return { gap: null, firstSeq: 1 };
    },
    'no head': async db => {
      await db.write(tx =>
        tx.run(tx.dialect.deleteFrom('audit_head', sql`${sql.id('id')} = ${1}`))
      );
      return { gap: { head: null, lastSeq: -3 }, firstSeq: 1 };
    },
    'the head ahead at seq 7': async db => {
      await db.write(tx =>
        auditOps.setHead(tx, { seq: 7, hash: 'a'.repeat(64), key_id: 'x', updated_at: 1 })
      );
      return { gap: { head: 7, lastSeq: -3 }, firstSeq: 8 };
    },
  };
  for (const [name, damage] of Object.entries(cases))
    for (const way of ['own unit', 'record()']) {
      await t.test(`${name}, ${way}`, async t => {
        const { audit, db, keyring } = await auditFixture(t);
        for (let n = 1; n <= 2; n++) await audit.append(stop(n));
        const rows = await storedRows(db);
        await db.write(tx => {
          tx.run(tx.dialect.update('audit_log', { seq: -4 }, sql`${sql.id('seq')} = ${1}`));
          tx.run(tx.dialect.update('audit_log', { seq: -3 }, sql`${sql.id('seq')} = ${2}`));
        });
        const expected = await damage(db, rows);
        if (way === 'own unit') await audit.append(stop(9));
        else await recordIn(db, audit, login());
        const written = (await rowsFromAll(db)).filter(row => row.seq >= 1);
        assert.deepEqual(await allSeqs(db), [-4, -3, ...written.map(row => row.seq)]);
        assert.equal(written[0].seq, expected.firstSeq, 'Uptime Goblin numbers from 1');
        assert.equal(
          written[0].prev_hash,
          GENESIS,
          'never linked to a row Uptime Goblin did not number'
        );
        if (expected.gap) {
          assert.equal(written[0].action, 'audit.gap');
          assert.equal(written[0].detail.head?.seq ?? null, expected.gap.head);
          assert.equal(written[0].detail.lastSeq, expected.gap.lastSeq);
          assert.equal(written.length, 2);
        } else
          assert.deepEqual(actionsOf(written), [
            way === 'own unit' ? 'system.stop' : 'session.login',
          ]);
        assert.equal(written.at(-1).prev_hash, written.length > 1 ? written[0].hash : GENESIS);
        assert.equal(await db.read(tx => auditOps.head(tx).seq), written.at(-1).seq);
        const result = await verifyAudit(db, { keyring });
        assert.equal(result.problem?.code, 'link_broken', JSON.stringify(result.problem));
        assert.equal(result.problem.seq, -4);
        // The rows Uptime Goblin wrote are a chain of their own: without the moved rows they check.
        if (!expected.gap) {
          await db.write(tx =>
            tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} < ${1}`))
          );
          assert.equal((await verifyAudit(db, { keyring })).result, 'intact');
        }
      });
    }
});

test('no false gap: a first start whose identity rows went to the inbox (meta applied) and were chained by attach() verifies intact', async t => {
  const clock = manualClock();
  const { db, control } = await migratedControl(t, { clock });
  const out = [],
    err = [];
  const audit = createAudit({
    db,
    clock,
    release: { version: release, build: 't' },
    out: line => out.push(line),
    err: line => err.push(line),
  });
  t.after(() => audit.close());
  // Identity's first-start unit, before the keyring exists: the bootstrap row and its meta key.
  await recordIn(db, audit, {
    action: 'account.bootstrap',
    outcome: 'info',
    target: { type: 'account', id: 'u_admin', name: null },
    detail: { source: 'env' },
    meta: { audit_password_changed_at: '123' },
  });
  assert.deepEqual(await storedRows(db), [], 'nothing chained before the keyring exists');
  assert.equal((await db.read(tx => auditOps.inboxAll(tx))).length, 1);
  assert.equal(await meta(db, 'audit_password_changed_at'), '123', 'meta in the inbox unit');
  const keyring = await openKeyring(control);
  await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
  const rows = await storedRows(db);
  assert.deepEqual(actionsOf(rows), ['account.bootstrap']);
  assert.equal(rows[0].prev_hash, GENESIS);
  assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
  assert.equal((await verifyAudit(db, { keyring })).result, 'intact');
  assert.deepEqual(err, []);
});

test('restore anchor: a waiting snapshot restore is the first row of the next unit, once; bad stamps anchor with nulls; appendDirect writes it too', async t => {
  await t.test('own unit, then record()', async t => {
    const { audit, db, control, keyring } = await auditFixture(t, { attach: false });
    await appendDirect({ db, keyring }, stop(1));
    const before = await storedRows(db);
    const stamp = JSON.stringify({
      snapshot: 'manual-1.5.0-dev.2-20260920T081200Z',
      at: 1758355920000,
    });
    await setMeta(db, 'restored', stamp);
    await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
    await recordIn(db, audit, login());
    const rows = await storedRows(db);
    assert.deepEqual(actionsOf(rows), ['system.stop', 'system.restore', 'session.login']);
    assert.deepEqual(rows[1].detail, {
      cause: 'snapshot',
      snapshot: 'manual-1.5.0-dev.2-20260920T081200Z',
      at: 1758355920000,
      restoredHead: { seq: 1, hash: before[0].hash },
    });
    assert.equal(await meta(db, 'audit_restore_seen'), stamp);
    await audit.append(stop(2));
    assert.equal((await storedRows(db)).filter(row => row.action === 'system.restore').length, 1);
  });
  await t.test('an empty log, and stamps that are not JSON or hold a long id', async t => {
    for (const [stamp, expected] of [
      ['not json', { snapshot: null, at: null }],
      [JSON.stringify({ snapshot: 'x'.repeat(201), at: 5 }), { snapshot: null, at: 5 }],
      [JSON.stringify({ snapshot: 'ok-id', at: 1.5 }), { snapshot: 'ok-id', at: null }],
    ]) {
      const { audit, db, control, keyring } = await auditFixture(t, { attach: false });
      await setMeta(db, 'restored', stamp);
      await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
      await audit.append(stop());
      const [anchor] = await storedRows(db);
      assert.equal(anchor.action, 'system.restore');
      assert.deepEqual(anchor.detail, { cause: 'snapshot', ...expected, restoredHead: null });
    }
  });
  await t.test('appendDirect (goblin-admin) looks for one always', async t => {
    const { db, keyring } = await auditFixture(t, { attach: false });
    await appendDirect({ db, keyring }, stop());
    await setMeta(db, 'restored', JSON.stringify({ snapshot: 's', at: 1 }));
    await appendDirect({ db, keyring }, stop());
    await appendDirect({ db, keyring }, stop());
    assert.deepEqual(actionsOf(await storedRows(db)), [
      'system.stop',
      'system.restore',
      'system.stop',
      'system.stop',
    ]);
  });
  await t.test(
    'control_file: the writer fills restoredHead of the anchor identity records',
    async t => {
      const { audit, db } = await auditFixture(t);
      await audit.append(stop());
      await recordIn(db, audit, {
        action: 'system.restore',
        outcome: 'info',
        target: { type: 'orbit', id: null, name: null },
        detail: { cause: 'control_file', restoredHead: { seq: 99, hash: 'forged' } },
      });
      const rows = await storedRows(db);
      assert.deepEqual(rows[1].detail, {
        cause: 'control_file',
        restoredHead: { seq: 1, hash: rows[0].hash },
      });
    }
  );
});

test("inbox: before the keyring the caller's unit holds the row; attach() chains this process's rows, and a few of an empty log's; anything else is discarded with one gap", async t => {
  const inboxEvent = n => ({
    action: 'session.revoked',
    outcome: 'info',
    target: { type: 'session', id: null, name: null },
    detail: { cause: 'insecure_http_off', count: n },
  });
  await t.test("this process's rows, in order, with their recorded time", async t => {
    const clock = manualClock();
    const { db, control } = await migratedControl(t, { clock });
    const audit = createAudit({ db, clock, out() {}, err() {} });
    t.after(() => audit.close());
    await recordIn(db, audit, inboxEvent(1));
    clock.advance(5);
    await recordIn(db, audit, inboxEvent(2));
    // A row of another process into a log that is not empty is discarded: here the log is
    // empty, so it is chained too (a first start that stopped before its keyring), dated no
    // earlier than this process's start (review round 2).
    await db.write(tx =>
      auditOps.inboxInsert(tx, { time: 7, source: 'start', event: inboxEvent(3) })
    );
    // An action identity may not record before a keyring exists is discarded.
    await recordIn(db, audit, stop());
    clock.advance(5);
    await audit.attach({ keyring: await openKeyring(control), instanceId: 'i' });
    const rows = await storedRows(db);
    assert.deepEqual(actionsOf(rows), [
      'session.revoked',
      'session.revoked',
      'session.revoked',
      'audit.gap',
    ]);
    assert.deepEqual(
      rows.slice(0, 3).map(row => row.detail.count),
      [1, 2, 3]
    );
    assert.deepEqual(
      rows.slice(0, 3).map(row => row.time),
      [clock() - 10, clock() - 5, clock() - 10]
    );
    assert.deepEqual(rows[3].detail, { reason: 'inbox-discarded', count: 1 });
    assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
  });
  await t.test(
    'more than 100 rows of another process into an empty log are all deleted and counted (review round 2)',
    async t => {
      const clock = manualClock();
      const { db, control } = await migratedControl(t, { clock });
      const audit = createAudit({ db, clock, out() {}, err() {} });
      t.after(() => audit.close());
      await recordIn(db, audit, inboxEvent(1));
      await db.write(tx => {
        for (let n = 0; n < 101; n++)
          auditOps.inboxInsert(tx, { time: 7, source: 'start', event: inboxEvent(2) });
      });
      await audit.attach({ keyring: await openKeyring(control), instanceId: 'i' });
      const rows = await storedRows(db);
      assert.deepEqual(actionsOf(rows), ['session.revoked', 'audit.gap']);
      assert.equal(rows[0].detail.count, 1, "this process's own row is chained");
      assert.deepEqual(rows[1].detail, { reason: 'inbox-discarded', count: 101 });
      assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
    }
  );
  await t.test(
    "another process's rows into a log that is not empty are deleted and counted",
    async t => {
      const { audit, db, control, keyring } = await auditFixture(t, { attach: false });
      await appendDirect({ db, keyring }, stop());
      await db.write(tx => {
        auditOps.inboxInsert(tx, { time: 1, source: 'start', event: inboxEvent(1) });
        auditOps.inboxInsert(tx, { time: 2, source: 'start', event: { not: 'an event' } });
      });
      await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
      const rows = await storedRows(db);
      assert.deepEqual(actionsOf(rows), ['system.stop', 'audit.gap']);
      assert.deepEqual(rows[1].detail, { reason: 'inbox-discarded', count: 2 });
      assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
    }
  );
  await t.test(
    'no drain while the guard is full; maintain() drains once it clears; a failed drain is retried',
    async t => {
      const guard = fakeGuard();
      const wrap = countingWrap();
      const clock = manualClock();
      const { db, control } = await migratedControl(t, { clock });
      const audit = createAudit({ db, clock, guard, wrapDb: wrap, out() {}, err() {} });
      t.after(() => audit.close());
      await recordIn(db, audit, inboxEvent(1));
      guard.full = true;
      await audit.attach({ keyring: await openKeyring(control), instanceId: 'i' });
      assert.ok(!wrap.seen.includes('inbox'), 'not attempted while full');
      assert.equal((await db.read(tx => auditOps.inboxAll(tx))).length, 1);
      guard.full = false;
      await audit.maintain({});
      assert.deepEqual(actionsOf(await storedRows(db)), ['session.revoked']);
    }
  );
  await t.test('a drain that fails leaves the rows; maintain() tries again', async t => {
    const fail = new Set(['inbox']);
    const wrap = countingWrap({ fail });
    const clock = manualClock();
    const { db, control } = await migratedControl(t, { clock });
    const audit = createAudit({ db, clock, wrapDb: wrap, out() {}, err() {} });
    t.after(() => audit.close());
    await recordIn(db, audit, inboxEvent(1));
    await audit.attach({ keyring: await openKeyring(control), instanceId: 'i' });
    assert.ok(wrap.seen.includes('inbox'));
    assert.equal((await db.read(tx => auditOps.inboxAll(tx))).length, 1);
    fail.clear();
    await audit.maintain({});
    assert.deepEqual(actionsOf(await storedRows(db)), ['session.revoked']);
    assert.deepEqual(await db.read(tx => auditOps.inboxAll(tx)), []);
  });
});

// Review round 2: drain() signed every inbox row while the log was empty, with the time stored in
// the row. Someone with the database but not the key emptied the log and planted inbox rows dated
// 1970: Uptime Goblin signed them at its next start, the next prune removed them as expired under a
// checkpoint it signed, and the whole journal then read intact (every old line below the prune,
// or printed before it). Planting more rows than the cap leaves did the same through the cap.
test('inbox: a database writer who empties the log and plants inbox rows gets nothing that verifies intact against the whole journal', async t => {
  const planted = {
    action: 'session.revoked',
    outcome: 'info',
    at: 0,
    target: { type: 'session', id: null, name: null },
    detail: { cause: 'insecure_http_off', count: 1 },
  };
  const quiet = { warn() {}, info() {}, error() {} };
  const cases = [
    {
      name: 'rows dated 1970 are chained, dated from this start, so no prune removes them',
      rows: 21,
      retention: { days: 30, maxRows: 250000 },
    },
    {
      name: 'more rows than the cap leaves are discarded with one gap row, so no cap prune signs over them',
      rows: 1100,
      retention: { days: 30, maxRows: 10 },
    },
  ];
  for (const { name, rows: count, retention } of cases)
    await t.test(name, async t => {
      const clock = manualClock(Date.UTC(2026, 9, 3, 12));
      const f = await auditFixture(t, { clock, retention });
      for (let n = 1; n <= 20; n++) {
        await f.audit.append(stop(n));
        clock.advance(1000);
      }
      const before = f.out.join('\n');
      assert.equal(
        (await verifyAudit(f.db, { keyring: f.keyring, journal: before })).result,
        'intact'
      );
      await f.audit.close();
      await f.db.write(tx => {
        tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} IS NOT NULL`));
        tx.run(tx.dialect.deleteFrom('audit_head', sql`${sql.id('id')} IS NOT NULL`));
        tx.run(tx.dialect.deleteFrom('audit_checkpoints', sql`${sql.id('seq')} IS NOT NULL`));
        for (let n = 0; n < count; n++)
          auditOps.inboxInsert(tx, { time: 0, source: 'start', event: planted });
      });
      // The next start, with the keyring that exists (attach() before identity).
      const out = [];
      const next = createAudit({
        db: f.db,
        clock,
        release: { version: release, build: 't' },
        retention,
        out: line => out.push(line),
        err() {},
        log: quiet,
      });
      t.after(() => next.close());
      const startedAt = clock();
      await next.attach({ keyring: f.keyring, instanceId: await f.control.meta.instanceId() });
      await next.started({});
      // audit.maintain's first run.
      clock.advance(61000);
      await next.maintain({});
      await next.idle();
      const result = await verifyAudit(f.db, {
        keyring: f.keyring,
        journal: [before, ...out].join('\n'),
        clock,
        oneUnit: true,
      });
      assert.equal(result.result, 'broken');
      assert.equal(result.problem.code, 'journal_mismatch');
      assert.equal(result.problem.seq, 1);
      assert.deepEqual(await f.db.read(tx => auditOps.checkpoints(tx)), [], 'nothing pruned');
      const rows = await storedRows(f.db);
      if (count <= 100) {
        assert.deepEqual(actionsOf(rows), [
          ...Array(count).fill('session.revoked'),
          'system.start',
        ]);
        assert.ok(
          rows.every(row => row.time >= startedAt),
          'no row is dated before this start'
        );
      } else {
        assert.deepEqual(actionsOf(rows), ['audit.gap', 'system.start']);
        assert.deepEqual(rows[0].detail, { reason: 'inbox-discarded', count });
      }
    });
});

test('validation: an unknown detail key makes append reject audit_unavailable and system print one audit.unwritten line', async t => {
  const { audit, db, err } = await auditFixture(t);
  const bad = { ...stop(), detail: { uptimeMs: 1, password: 'nope' } };
  await assert.rejects(audit.append(bad), error => {
    assert.equal(error.code, 'audit_unavailable');
    assert.equal(error.status, 503);
    assert.match(error.cause.message, /has no detail key password/);
    return true;
  });
  await audit.system(bad);
  const lines = linesOf(err, 'audit.unwritten');
  assert.equal(lines.length, 1);
  assert.equal(lines[0].error, 'audit_defect');
  assert.equal(lines[0].row.action, 'system.stop');
  assert.deepEqual(await storedRows(db), []);
  assert.deepEqual(audit.state().unwritten?.count, 1);
  // Other refusals: an unknown action, an outcome the action lacks, a meta key outside §3.4, a
  // number that is not a safe integer, a non-plain detail, a long session id.
  for (const event of [
    { action: 'users.created', outcome: 'ok' },
    { action: 'system.stop', outcome: 'ok' },
    { ...stop(), meta: { anything: '1' } },
    { ...stop(), detail: { uptimeMs: 1.5 } },
    { ...stop(), detail: { uptimeMs: new Date() } },
    {
      ...stop(),
      actor: {
        type: 'user',
        id: 'u_admin',
        name: 'admin',
        via: 'session',
        sessionId: 's'.repeat(33),
      },
    },
    { ...stop(), actor: { type: 'robot' } },
  ])
    await assert.rejects(audit.append(event), { code: 'audit_unavailable' });
  // What is cleaned rather than refused: control characters, lone surrogates, long texts.
  await audit.append({
    ...login(),
    userAgent: `Agent\u0000\u0007 ${'x'.repeat(300)}`,
    client: `192.0.2.${'9'.repeat(100)}`,
    target: { type: 'session', id: 's_1', name: '\ud800name' },
  });
  const [row] = await storedRows(db);
  assert.equal(row.user_agent.length, 200);
  assert.ok(row.user_agent.startsWith('Agent x'));
  assert.equal(row.client_key.length, 64);
  assert.equal(row.target_name, '�name');
});

test("refused: an audit.unwritten line of a refused event holds what a row of its action could, never the refused key's value", async t => {
  const { audit, err } = await auditFixture(t);
  const sentinels = auditSentinels();
  await audit.system({
    ...stop(7),
    detail: { uptimeMs: 7, password: sentinels.smtpPassword, ignored: undefined },
    client: `192.0.2.1\u0007${'9'.repeat(100)}`,
    userAgent: `Agent\u0000 ${'x'.repeat(300)}`,
    target: { type: 'orbit', id: null, name: '\ud800orbit' },
  });
  // A refused key in an operation, beside a value that is not plain data in an allowed key
  // (dropped) and one that is (kept); and an action outside the catalogue.
  await audit
    .operation(adminRequest(), {
      action: 'email.test',
      target: { type: 'channel', id: 'email', name: null },
      detail: { accepted: new Date(), code: 'smtp_auth', apiKey: sentinels.sourceApiKey },
    })
    .end({ status: 502, outcome: 'failed' });
  await audit.system({
    action: 'not.an.action',
    outcome: 'ok',
    detail: { token: sentinels.urlToken },
  });
  const lines = linesOf(err, 'audit.unwritten');
  assert.equal(lines.length, 3);
  assert.deepEqual(findSentinels(err.join('\n'), sentinels), []);
  const [refused, operation, unknown] = lines;
  assert.deepEqual(operation.row.detail, { code: 'smtp_auth' });
  assert.equal(operation.row.actor.sessionId, 's_test1');
  assert.equal(refused.error, 'audit_defect');
  assert.deepEqual(refused.row.detail, { uptimeMs: 7 });
  assert.equal(refused.row.actor.client.length, 64);
  assert.ok(!/\p{Cc}/u.test(refused.row.actor.client + refused.row.actor.userAgent));
  assert.equal(refused.row.actor.userAgent.length, 200);
  assert.deepEqual(refused.row.target, { type: 'orbit', id: null, name: '�orbit' });
  assert.equal(unknown.row.action, 'not.an.action');
  assert.equal(unknown.row.detail, null, 'an action outside the catalogue keeps no detail');
});

test('D32: inside another unit a defect or a damaged log writes nothing, the change commits, and one line follows the commit (none after a rollback); a storage error is thrown', async t => {
  const caller = tx =>
    tx.run(
      tx.dialect.upsert('meta', ['key'], ['key', 'value', 'updated_at'], [['caller', 'done', 1]])
    );
  await t.test('a defect', async t => {
    const { audit, db, err } = await auditFixture(t);
    await recordIn(db, audit, { ...login(), detail: { secret: 'x' } }, { before: caller });
    assert.equal(await meta(db, 'caller'), 'done');
    assert.deepEqual(await storedRows(db), []);
    assert.equal(linesOf(err, 'audit.unwritten').length, 1);
    // A unit that rolls back prints nothing.
    await assert.rejects(
      recordIn(
        db,
        audit,
        { ...login(), detail: { secret: 'x' } },
        {
          after: () => {
            throw new Error('caller failed');
          },
        }
      ),
      /caller failed/
    );
    assert.equal(linesOf(err, 'audit.unwritten').length, 1);
  });
  await t.test('a damaged log (the newest seq beyond the safe range)', async t => {
    const { audit, db, err } = await auditFixture(t);
    await audit.append(stop());
    await db.write(tx =>
      tx.run(tx.dialect.update('audit_log', { seq: 2n ** 53n + 1n }, sql`${sql.id('seq')} = ${1}`))
    );
    await recordIn(db, audit, login(), { before: caller });
    assert.equal(await meta(db, 'caller'), 'done', 'the sign-in commits');
    const lines = linesOf(err, 'audit.unwritten');
    assert.equal(lines.length, 1);
    assert.equal(lines[0].error, 'poison');
    assert.equal(lines[0].row.action, 'session.login');
  });
  await t.test("a storage error is thrown into the caller's unit", async t => {
    const { audit, db, err } = await auditFixture(t);
    let failing = false;
    await assert.rejects(
      db.write(tx => {
        caller(tx);
        failing = true;
        const wrapped = {
          dialect: tx.dialect,
          get: query => tx.get(query),
          all: query => tx.all(query),
          onCommit: fn => tx.onCommit(fn),
          run: query => {
            if (failing)
              throw Object.assign(new Error('database or disk is full'), { class: 'full' });
            return tx.run(query);
          },
        };
        audit.record(wrapped, login());
      }),
      error => error.class === 'full'
    );
    assert.equal(await meta(db, 'caller'), null, 'the caller rolled back');
    assert.deepEqual(err, []);
  });
});

test('retry once: an own unit retried after its callback ran writes one row and prints one checkpoint and one mirror line', async t => {
  const { audit, db, out } = await auditFixture(t, {
    mirror: 'stdout',
    wrapDb: (db, purpose) => (purpose === 'read' ? db : retryOnce(db)),
  });
  await audit.append(stop());
  assert.equal((await storedRows(db)).length, 1);
  assert.equal(linesOf(out, 'audit.checkpoint').length, 1);
  assert.equal(linesOf(out, 'audit').length, 1);
  // record() inside a retried unit of another component records once too.
  await retryOnce(db).write(tx => audit.record(tx, login()));
  assert.equal((await storedRows(db)).length, 2);
  assert.equal(linesOf(out, 'audit.checkpoint').length, 2);
});

test('lines: the mirror follows GOBLIN_AUDIT_LOG; one checkpoint per unit for its newest row, always, with a valid MAC; appendDirect prints nothing', async t => {
  for (const mirror of ['off', 'stdout', 'stdout-full']) {
    const { audit, db, out, keyring, control } = await auditFixture(t, { mirror });
    await audit.system({ ...stop(7) });
    // One unit, two rows (a gap and the event): one checkpoint, for the newest.
    await db.write(tx => tx.run(tx.dialect.deleteFrom('audit_head', sql`${sql.id('id')} = ${1}`)));
    await audit.append(stop(8));
    const rows = await storedRows(db);
    assert.equal(rows.length, 3);
    const checkpoints = linesOf(out, 'audit.checkpoint');
    assert.deepEqual(
      checkpoints.map(line => line.seq),
      [1, 3],
      mirror
    );
    const instance = await control.meta.instanceId();
    for (const line of checkpoints) {
      const row = rows.find(r => r.seq === line.seq);
      assert.equal(line.hash, row.hash);
      assert.equal(line.time, row.time);
      assert.equal(line.instance, instance);
      assert.equal(line.reason, 'commit');
      assert.equal(line.key_id, row.key_id);
      assert.equal(
        line.mac,
        checkpointMac(data => keyring.hmac('audit', data, line.key_id).mac, line)
      );
    }
    const mirrored = linesOf(out, 'audit');
    if (mirror === 'off') assert.equal(mirrored.length, 0);
    else {
      assert.deepEqual(
        mirrored.map(line => line.seq),
        [1, 2, 3]
      );
      assert.equal('detail' in mirrored[0], mirror === 'stdout-full');
      if (mirror === 'stdout-full') assert.deepEqual(mirrored[0].detail, { uptimeMs: 7 });
      assert.equal(mirrored[0].hash, rows[0].hash);
      assert.deepEqual(Object.keys(mirrored[0].actor), [
        'type',
        'id',
        'name',
        'via',
        'sessionId',
        'client',
        'userAgent',
      ]);
    }
    const printed = out.length;
    await appendDirect({ db, keyring }, stop());
    assert.equal(out.length, printed, 'appendDirect prints nothing');
  }
});

// Integration (the independent check's finding 4): identity records one row per event in its
// unit (a sign-out of several sessions, a whole-file restore's anchor and sign-out), and D12
// gives every unit one checkpoint line, for its newest row.
test('lines: several record() calls in one unit print every mirror line and one checkpoint line, for the newest row; a retried unit too', async t => {
  const { audit, db, out, keyring } = await auditFixture(t, { mirror: 'stdout' });
  const ended = id => ({
    action: 'session.logout',
    outcome: 'ok',
    target: { type: 'session', id, name: null },
    detail: { cause: 'presented' },
  });
  await audit.append(stop());
  let printed = out.length;
  await db.write(tx => {
    audit.record(tx, ended('s_one'));
    audit.record(tx, ended('s_two'));
    audit.record(tx, ended('s_three'));
  });
  let rows = await storedRows(db);
  let lines = out.slice(printed).map(line => JSON.parse(line));
  assert.deepEqual(
    lines.map(line => [line.orbit, line.seq]),
    [
      ['audit', 2],
      ['audit', 3],
      ['audit', 4],
      ['audit.checkpoint', 4],
    ]
  );
  assert.equal(lines.at(-1).hash, rows.at(-1).hash);
  // A unit run again after a retry: the rolled-back attempt's rows print nothing.
  printed = out.length;
  await retryOnce(db).write(tx => {
    audit.record(tx, ended('s_four'));
    audit.record(tx, ended('s_five'));
  });
  rows = await storedRows(db);
  assert.equal(rows.length, 6);
  lines = out.slice(printed).map(line => JSON.parse(line));
  assert.deepEqual(
    lines.map(line => [line.orbit, line.seq]),
    [
      ['audit', 5],
      ['audit', 6],
      ['audit.checkpoint', 6],
    ]
  );
  assert.equal(lines.at(-1).hash, rows.at(-1).hash);
  const checked = await verifyAudit(db, { keyring, journal: out.join('\n') });
  assert.deepEqual([checked.result, checked.journal.matched], ['intact', 3]);
});

test('result lost: a result row that cannot be written is one stderr line at once, counted, its attempt listed unknown, and never written later', async t => {
  const fail = new Set(['result']);
  const { audit, db, err } = await auditFixture(t, { wrapDb: countingWrap({ fail }) });
  const change = await audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: true },
  });
  const before = {
    revision: 1,
    public: { title: 'Uptime Goblin' },
    secrets: { key_id: 'k', macs: {} },
  };
  const after = { revision: 2, public: { title: 'Lab' }, secrets: { key_id: 'k', macs: {} } };
  change.note({ applied: true, before, after, configRevision: 2 });
  assert.equal((await audit.list({})).entries[0].outcome, 'attempt', 'in progress while open');
  await change.end({ status: 200, outcome: 'ok' });
  const lines = linesOf(err, 'audit.unwritten');
  assert.equal(lines.length, 1);
  assert.equal(lines[0].error, 'full');
  assert.equal(lines[0].row.outcome, 'ok');
  assert.equal(lines[0].row.ref, change.seq);
  assert.deepEqual(lines[0].row.detail.diff, [{ path: 'title', from: 'Uptime Goblin', to: 'Lab' }]);
  assert.equal(lines[0].row.configRevision, 2);
  assert.ok(!('seq' in lines[0].row) && !('hash' in lines[0].row));
  assert.deepEqual(audit.state().unwritten, { since: lines[0].time, count: 1 });
  const listed = await audit.list({ outcome: 'unknown' });
  assert.deepEqual(
    listed.entries.map(entry => [entry.seq, entry.outcome]),
    [[change.seq, 'unknown']]
  );
  assert.deepEqual(listed.unwritten, { since: lines[0].time, count: 1 });
  assert.equal(await meta(db, 'config_revision_seen'), null, 'the configuration keys did not move');
  // A later unit that works writes only its own rows.
  fail.clear();
  await audit.append(stop());
  assert.deepEqual(actionsOf(await storedRows(db)), ['settings.update', 'system.stop']);
});

test('guard full: system, operation, aggregate, inbox, start and prune units are not tried and print their lines; append, begin, end and single are', async t => {
  const guard = fakeGuard();
  const wrap = countingWrap();
  const { audit, db, err, clock } = await auditFixture(t, { guard, wrapDb: wrap });
  guard.full = true;
  wrap.seen.length = 0;
  await audit.system(stop());
  const op = audit.operation(adminRequest(), {
    action: 'sources.refresh',
    target: { type: 'sources', id: '*', name: null },
  });
  await op.end({ status: 200, outcome: 'ok' });
  audit.count({
    action: 'session.login',
    outcome: 'failed',
    client: '192.0.2.9',
    login: 'admin',
    detail: { code: 'invalid_credentials' },
  });
  await audit.start({ config: null, passwordChangedAt: null });
  await audit.started({ security: {} });
  clock.advance(400 * 86400000);
  await audit.maintain({});
  await audit.idle();
  for (const purpose of ['system', 'operation', 'aggregate', 'inbox', 'start', 'prune'])
    assert.ok(!wrap.seen.includes(purpose), `${purpose} not tried`);
  assert.deepEqual(
    linesOf(err, 'audit.unwritten').map(line => [line.row.action, line.error]),
    [
      ['system.stop', 'storage_full'],
      ['sources.refresh', 'storage_full'],
      // The migration recorded this release in upgrade_history: start()'s first row.
      ['system.upgrade', 'storage_full'],
      ['system.start', 'storage_full'],
    ]
  );
  await audit.append(stop());
  const change = await audit.begin(adminRequest(), {
    action: 'delivery.retry',
    target: { type: 'delivery', id: 'd1', name: null },
  });
  await change.end({ status: 200, outcome: 'ok' });
  await audit.single(adminRequest(), {
    action: 'config.export',
    target: { type: 'config', id: null, name: null },
    detail: { sources: 1, bytes: 2 },
  });
  for (const purpose of ['append', 'attempt', 'result', 'single'])
    assert.ok(wrap.seen.includes(purpose), purpose);
  assert.deepEqual(actionsOf(await storedRows(db)), [
    'system.stop',
    'delivery.retry',
    'delivery.retry',
    'config.export',
  ]);
});

// ---- start rows (§5.6) -----------------------------------------------------------------------

const history = entries => JSON.stringify(entries);
const entry = (from, to, at) => ({ from, to, at });

test('start rows: system.upgrade lists the entries after the marker; only the newest without one; every entry with markerLost; the marker moves once', async t => {
  await t.test('no marker: only the newest entry (the older ones predate the log)', async t => {
    const { audit, db } = await auditFixture(t);
    await setMeta(
      db,
      'upgrade_history',
      history([
        entry(null, '1.5.0-dev.0', 1),
        entry('1.5.0-dev.0', '1.5.0-dev.1', 2),
        entry('1.5.0-dev.1', release, 3),
      ])
    );
    await audit.start({});
    const rows = await storedRows(db);
    assert.deepEqual(actionsOf(rows), ['system.upgrade']);
    assert.deepEqual(rows[0].detail, {
      release,
      entries: [entry('1.5.0-dev.1', release, 3)],
      markerLost: false,
    });
    assert.equal(await meta(db, 'audit_release_marker'), JSON.stringify({ at: 3, to: release }));
    await audit.start({});
    assert.equal((await storedRows(db)).length, 1, 'the marker moved: no second row');
  });
  await t.test(
    'a marker: the entries after it (an older build that opened the data meanwhile)',
    async t => {
      const { audit, db } = await auditFixture(t);
      await setMeta(
        db,
        'upgrade_history',
        history([
          entry(null, release, 1),
          entry(release, '1.5.0-dev.1', 2),
          entry('1.5.0-dev.1', release, 3),
        ])
      );
      await setMeta(db, 'audit_release_marker', JSON.stringify({ to: release, at: 1 }));
      await audit.start({});
      const [row] = await storedRows(db);
      assert.deepEqual(row.detail.entries, [
        entry(release, '1.5.0-dev.1', 2),
        entry('1.5.0-dev.1', release, 3),
      ]);
      assert.equal(row.detail.markerLost, false);
    }
  );
  await t.test('a marker not found: every entry, markerLost', async t => {
    const { audit, db } = await auditFixture(t);
    await setMeta(
      db,
      'upgrade_history',
      history([entry(null, '1.5.0-dev.1', 1), entry('1.5.0-dev.1', release, 2)])
    );
    await setMeta(db, 'audit_release_marker', JSON.stringify({ to: 'gone', at: 0 }));
    await audit.start({});
    const [row] = await storedRows(db);
    assert.equal(row.detail.entries.length, 2);
    assert.equal(row.detail.markerLost, true);
  });
});

test('crash after start rows: a start stopped after system.upgrade and started again writes no second system.upgrade', async t => {
  const { audit, db, control, keyring, clock } = await auditFixture(t);
  await setMeta(db, 'upgrade_history', history([entry(null, release, 1)]));
  await audit.start({});
  // The process dies here (no system.start); a new one starts on the same data.
  const again = createAudit({ db, clock, out() {}, err() {} });
  t.after(() => again.close());
  await again.attach({ keyring, instanceId: await control.meta.instanceId() });
  await again.start({});
  await again.started({ security: {} });
  assert.deepEqual(actionsOf(await storedRows(db)), ['system.upgrade', 'system.start']);
});

// A snapshot manifest as createSnapshot writes it (only what listSnapshots reads).
function manifest(directory, { id, reason = 'manual', createdAt }) {
  const folder = path.join(directory, 'snapshots', id);
  fs.mkdirSync(folder, { recursive: true });
  fs.writeFileSync(
    path.join(folder, 'manifest.json'),
    JSON.stringify({
      format: 1,
      id,
      reason,
      release,
      fromRelease: null,
      createdAt,
      pinned: false,
      files: [],
    })
  );
}

test('start rows: data.snapshot for manifests newer than the marker (20 at most, `more` on the last); without a marker only the baseline', async t => {
  const { audit, db, directory } = await auditFixture(t);
  for (let n = 1; n <= 3; n++) manifest(directory, { id: `manual-${n}`, createdAt: n * 1000 });
  const snapshotRows = async () =>
    (await storedRows(db)).filter(row => row.action === 'data.snapshot');
  await audit.start({});
  assert.deepEqual(await snapshotRows(), [], 'the first audited start only sets the marker');
  assert.equal(
    await meta(db, 'audit_snapshot_seen'),
    JSON.stringify({ createdAt: 3000, id: 'manual-3' })
  );
  for (let n = 4; n <= 28; n++)
    manifest(directory, {
      id: `pre-restore-${String(n).padStart(2, '0')}`,
      reason: 'pre-restore',
      createdAt: n * 1000,
    });
  // An invalid manifest is no snapshot.
  fs.mkdirSync(path.join(directory, 'snapshots', 'broken'));
  fs.writeFileSync(path.join(directory, 'snapshots', 'broken', 'manifest.json'), '{');
  await audit.start({});
  const rows = await snapshotRows();
  assert.equal(rows.length, 20);
  assert.deepEqual(
    rows.map(row => row.target_id),
    Array.from({ length: 20 }, (_, i) => `pre-restore-${String(i + 9).padStart(2, '0')}`)
  );
  assert.deepEqual(rows[0].detail, { reason: 'pre-restore', createdAt: 9000 });
  assert.deepEqual(rows[19].detail, { reason: 'pre-restore', createdAt: 28000, more: 5 });
  await audit.start({});
  assert.equal((await snapshotRows()).length, 20, 'the marker moved');
});

// Integration (CHECKER-REPORTS.md check:H): with no snapshot at the first audited start the marker
// was never set, so the next start took the first snapshot taken since for one that predates the
// log and recorded nothing.
test('start rows: a first audited start with no snapshot sets the baseline, so the first snapshot taken after it gets its data.snapshot row', async t => {
  const { audit, db, directory } = await auditFixture(t);
  const snapshotRows = async () =>
    (await storedRows(db)).filter(row => row.action === 'data.snapshot');
  await audit.start({});
  assert.equal(
    await meta(db, 'audit_snapshot_seen'),
    JSON.stringify({ createdAt: 0, id: '' }),
    'the baseline is before every snapshot'
  );
  assert.deepEqual(await snapshotRows(), []);
  manifest(directory, { id: 'manual-1', createdAt: 1000 });
  await audit.start({});
  assert.deepEqual(
    (await snapshotRows()).map(row => [row.target_id, row.detail]),
    [['manual-1', { reason: 'manual', createdAt: 1000 }]]
  );
  assert.equal(
    await meta(db, 'audit_snapshot_seen'),
    JSON.stringify({ createdAt: 1000, id: 'manual-1' })
  );
  await audit.start({});
  assert.equal((await snapshotRows()).length, 1, 'the marker moved');
});

// Review round 2 (D6): a later change's result row moved the configuration keys to its own
// after-snapshot, which already held the change whose result was lost, so no start recorded it.
test('config meta after a lost result: a later change recorded in the same run leaves the keys, so the next start records the lost change as config.changed-outside', async t => {
  const fail = new Set();
  const f = await auditFixture(t, { wrapDb: countingWrap({ fail }) });
  const config = new ConfigStore(f.directory);
  await f.audit.start({ config, passwordChangedAt: 5 });
  await f.audit.started({ security: {} });
  const baseline = await meta(f.db, 'audit_config_public');
  const change = async (edit, { lose = false } = {}) => {
    const begun = await f.audit.begin(adminRequest(), {
      action: 'settings.update',
      target: { type: 'settings', id: 'workspace', name: null },
    });
    const before = f.audit.configSnapshot(config.value);
    edit(config.value);
    config.save();
    begun.note({ applied: true, before, after: f.audit.configSnapshot(config.value) });
    if (lose) fail.add('result');
    await begun.end({ status: 200 });
    fail.delete('result');
  };
  await change(value => (value.title = 'Changed by A'), { lose: true });
  assert.equal(linesOf(f.err, 'audit.unwritten').length, 1, 'the result of A is lost');
  await change(value => (value.pollSeconds = value.pollSeconds === 120 ? 180 : 120));
  const results = (await storedRows(f.db)).filter(row => row.ref !== null);
  assert.equal(results.length, 1, 'the result of B is written');
  assert.ok(!results[0].detail.diff.some(item => item.path === 'title'));
  assert.equal(await meta(f.db, 'audit_config_public'), baseline, 'the keys stayed');
  await f.audit.close();
  // The next start.
  const next = createAudit({ db: f.db, clock: f.clock, out() {}, err() {} });
  t.after(() => next.close());
  await next.attach({ keyring: f.keyring, instanceId: 'i' });
  await next.start({ config: new ConfigStore(f.directory), passwordChangedAt: 5 });
  await next.started({ security: {} });
  const outside = (await storedRows(f.db)).filter(row => row.action === 'config.changed-outside');
  assert.equal(outside.length, 1);
  const paths = outside[0].detail.diff.map(item => item.path);
  assert.ok(paths.includes('title'), paths.join());
  assert.ok(paths.includes('pollSeconds'), paths.join());
  assert.deepEqual(
    outside[0].detail.diff.find(item => item.path === 'title'),
    { path: 'title', from: 'Uptime Goblin', to: 'Changed by A' }
  );
});

// Codex review A3: the keys were held back only once an earlier result had failed. A later
// result written while the earlier one was still unsettled (its unit sleeping between SQLite
// retries, or its settle not reached yet: exclusive() releases its turn before settle writes
// the result) moved them to its after-snapshot, which already held the earlier change; when
// that result was then lost, its change was in neither a result row nor the next start's drift.
const configChanges =
  (f, config) =>
  async (edit, { end = true } = {}) => {
    const begun = await f.audit.begin(adminRequest(), {
      action: 'settings.update',
      target: { type: 'settings', id: 'workspace', name: null },
    });
    const before = f.audit.configSnapshot(config.value);
    edit(config.value);
    config.save();
    const after = f.audit.configSnapshot(config.value);
    begun.note({ applied: true, before, after });
    return { begun, after, ended: end ? begun.end({ status: 200 }) : null };
  };
const configKeys = async db => ({
  revision: await meta(db, 'config_revision_seen'),
  public: await meta(db, 'audit_config_public'),
  secrets: await meta(db, 'audit_config_secrets'),
});
const keysOfSnapshot = snapshot => ({
  revision: String(snapshot.revision),
  public: JSON.parse(JSON.stringify(snapshot.public)),
  secrets: JSON.parse(JSON.stringify(snapshot.secrets)),
});
const parsedKeys = keys => ({
  revision: keys.revision,
  public: JSON.parse(keys.public),
  secrets: JSON.parse(keys.secrets),
});
const nextStartDrift = async (t, f) => {
  await f.audit.close();
  const next = createAudit({ db: f.db, clock: f.clock, out() {}, err() {} });
  t.after(() => next.close());
  await next.attach({ keyring: f.keyring, instanceId: 'i' });
  await next.start({ config: new ConfigStore(f.directory), passwordChangedAt: 5 });
  await next.started({ security: {} });
  return (await storedRows(f.db)).filter(row => row.action === 'config.changed-outside');
};
const pathsOf = row => row.detail.diff.map(item => item.path).sort();

test('Codex review A3: a result still retrying when a later one is written keeps the configuration keys; lost, its change is in the config.changed-outside of the next start; written, the keys follow the later one', async t => {
  for (const [name, times] of [
    ['lost after its retries', 4],
    ['written at its third attempt', 2],
  ])
    await t.test(name, async t => {
      let first = true;
      const f = await auditFixture(t, {
        // The real Db's retry loop: the attempt runs and is rolled back `times` times, sleeping
        // between attempts (3 retries by default, so 4 is a failure).
        wrapDb(db, purpose) {
          if (purpose !== 'result' || !first) return db;
          first = false;
          return retryOnce(db, { times });
        },
      });
      const config = new ConfigStore(f.directory);
      await f.audit.start({ config, passwordChangedAt: 5 });
      await f.audit.started({ security: {} });
      const baseline = await configKeys(f.db);
      const change = configChanges(f, config);
      const a = await change(value => (value.title = 'Changed by A'));
      const b = await change(value => (value.pollSeconds = value.pollSeconds === 120 ? 180 : 120));
      await b.ended;
      let results = (await storedRows(f.db)).filter(row => row.ref !== null);
      assert.deepEqual(
        results.map(row => row.ref),
        [b.begun.seq],
        'B is written while A sleeps between retries'
      );
      assert.deepEqual(await configKeys(f.db), baseline, 'B does not move the keys past A');
      await a.ended;
      results = (await storedRows(f.db)).filter(row => row.ref !== null);
      if (times === 4) {
        assert.equal(linesOf(f.err, 'audit.unwritten').length, 1, 'the result of A is lost');
        assert.deepEqual(
          results.map(row => row.ref),
          [b.begun.seq]
        );
        assert.deepEqual(await configKeys(f.db), baseline, 'the keys stayed');
        const outside = await nextStartDrift(t, f);
        assert.equal(outside.length, 1);
        assert.deepEqual(pathsOf(outside[0]), ['pollSeconds', 'title']);
        assert.deepEqual(
          outside[0].detail.diff.find(item => item.path === 'title'),
          { path: 'title', from: 'Uptime Goblin', to: 'Changed by A' }
        );
      } else {
        assert.equal(linesOf(f.err, 'audit.unwritten').length, 0);
        assert.deepEqual(
          results.map(row => row.ref),
          [b.begun.seq, a.begun.seq]
        );
        assert.deepEqual(results.map(pathsOf), [['pollSeconds'], ['title']]);
        assert.deepEqual(
          parsedKeys(await configKeys(f.db)),
          keysOfSnapshot(b.after),
          'A, settled last, publishes the newer after-snapshot B held back (forward only)'
        );
        assert.deepEqual(await nextStartDrift(t, f), [], 'both changes have results');
      }
    });
});

test('Codex review A3: a change noted but not yet ended holds the keys below it; the result that settles it publishes the newest snapshot below the next unsettled change, and a lost one is drift at the next start', async t => {
  const fail = new Set();
  const f = await auditFixture(t, { wrapDb: countingWrap({ fail }) });
  const config = new ConfigStore(f.directory);
  await f.audit.start({ config, passwordChangedAt: 5 });
  await f.audit.started({ security: {} });
  const baseline = await configKeys(f.db);
  const change = configChanges(f, config);
  // A and C are noted inside their turns but not settled yet; B and D are written meanwhile.
  const a = await change(value => (value.title = 'Changed by A'), { end: false });
  const b = await change(value => (value.pollSeconds = value.pollSeconds === 120 ? 180 : 120));
  await b.ended;
  assert.deepEqual(await configKeys(f.db), baseline, 'held back by A');
  const c = await change(value => (value.subtitle = 'Changed by C'), { end: false });
  const d = await change(value => (value.retentionDays = value.retentionDays === 30 ? 45 : 30));
  await d.ended;
  assert.deepEqual(await configKeys(f.db), baseline, 'held back by A and C');
  assert.ok(a.after.revision < b.after.revision && b.after.revision < c.after.revision);
  assert.ok(c.after.revision < d.after.revision);
  await a.begun.end({ status: 200 });
  assert.deepEqual(
    parsedKeys(await configKeys(f.db)),
    keysOfSnapshot(b.after),
    "A's result publishes B's held-back snapshot, not D's (C is not settled)"
  );
  fail.add('result');
  await c.begun.end({ status: 200 });
  fail.delete('result');
  assert.equal(linesOf(f.err, 'audit.unwritten').length, 1, 'the result of C is lost');
  assert.deepEqual(parsedKeys(await configKeys(f.db)), keysOfSnapshot(b.after), 'the keys stayed');
  // A later change, written: past the lost C, so it leaves the keys too.
  const e = await change(value => (value.title = 'Changed by E'));
  await e.ended;
  assert.deepEqual(parsedKeys(await configKeys(f.db)), keysOfSnapshot(b.after));
  const results = (await storedRows(f.db)).filter(row => row.ref !== null);
  assert.deepEqual(
    results.map(row => row.ref),
    [b.begun.seq, d.begun.seq, a.begun.seq, e.begun.seq]
  );
  const outside = await nextStartDrift(t, f);
  assert.equal(outside.length, 1);
  assert.equal(outside[0].detail.from, b.after.revision);
  assert.deepEqual(pathsOf(outside[0]), ['retentionDays', 'subtitle', 'title']);
  assert.deepEqual(
    outside[0].detail.diff.find(item => item.path === 'subtitle'),
    { path: 'subtitle', from: 'a little clarity for your homelab', to: 'Changed by C' }
  );
});

// Review round 2: config.json may hold a lone surrogate (1.4.x took the JSON escape \ud800),
// which canonical JSON refuses: every result row of a configuration change, the drift check and
// system.start then failed for as long as the value stayed. ConfigStore now makes such text
// whole when it loads the file; the value in memory here still holds one, and so does the hand
// edit below until it is loaded.
test('a configuration value with a lone surrogate: results, system.start, system.stop and a later hand edit are all still recorded', async t => {
  const f = await auditFixture(t);
  const config = new ConfigStore(f.directory);
  config.value.title = 'Bad \ud800 title';
  config.save();
  assert.match(fs.readFileSync(path.join(f.directory, 'config.json'), 'utf8'), /\\ud800/);
  await f.audit.start({ config, passwordChangedAt: 5 });
  await f.audit.started({ security: {} });
  const begun = await f.audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
  });
  const before = f.audit.configSnapshot(config.value);
  config.value.pollSeconds = config.value.pollSeconds === 120 ? 180 : 120;
  config.save();
  begun.note({ applied: true, before, after: f.audit.configSnapshot(config.value) });
  await begun.end({ status: 200 });
  await f.audit.close();
  // A hand edit while stopped.
  const file = path.join(f.directory, 'config.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  saved.title = 'Bad \ud800 title, edited';
  fs.writeFileSync(file, JSON.stringify(saved));
  const err = [];
  const next = createAudit({ db: f.db, clock: f.clock, out() {}, err: line => err.push(line) });
  t.after(() => next.close());
  await next.attach({ keyring: f.keyring, instanceId: 'i' });
  await next.start({ config: new ConfigStore(f.directory), passwordChangedAt: 5 });
  await next.started({ security: {} });
  const rows = (await storedRows(f.db)).filter(row => row.action !== 'system.upgrade');
  assert.deepEqual(actionsOf(rows), [
    'system.start',
    'settings.update',
    'settings.update',
    'system.stop',
    'config.changed-outside',
    'system.start',
  ]);
  assert.equal(rows[2].ref, rows[1].seq, 'the result row');
  assert.deepEqual(
    rows[4].detail.diff.map(item => [item.path, item.to]),
    [['title', 'Bad � title, edited']]
  );
  assert.deepEqual([...linesOf(f.err, 'audit.unwritten'), ...linesOf(err, 'audit.unwritten')], []);
});

test('start rows: config.changed-outside for a hand edit that kept the revision, with repaired, a stripped url, and secrets as changes', async t => {
  const { audit, db, directory } = await auditFixture(t);
  const config = new ConfigStore(directory);
  config.value.email.password = 'first-secret';
  config.save();
  // The first audited start records the baseline.
  await audit.start({ config: new ConfigStore(directory), passwordChangedAt: 5 });
  await audit.started({ security: {} });
  assert.equal(await meta(db, 'config_revision_seen'), String(config.value.revision));
  assert.notEqual(await meta(db, 'audit_config_public'), null);
  assert.equal(await meta(db, 'audit_password_changed_at'), '5');
  // A hand edit while stopped that keeps `revision`: the title, a destination with a token in
  // its query (parseConfig repairs it, the diff never holds it), and the SMTP password.
  const file = path.join(directory, 'config.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  const revision = saved.revision;
  saved.title = 'Edited by hand';
  saved.email.password = 'second-secret';
  saved.services[0].url = 'https://example.com/?token=SENTINEL-url&view=1';
  fs.writeFileSync(file, JSON.stringify(saved));
  const warned = [];
  const original = console.warn;
  console.warn = (...args) => warned.push(args.join(' '));
  let edited;
  try {
    edited = new ConfigStore(directory);
  } finally {
    console.warn = original;
  }
  assert.equal(edited.repaired, true);
  await audit.start({ config: edited, passwordChangedAt: 5 });
  const rows = await storedRows(db);
  const row = rows.find(r => r.action === 'config.changed-outside');
  assert.ok(row, actionsOf(rows).join());
  assert.equal(row.detail.from, revision);
  assert.equal(row.detail.to, edited.value.revision);
  assert.equal(row.detail.repaired, true);
  const paths = Object.fromEntries(row.detail.diff.map(change => [change.path, change]));
  assert.deepEqual(paths.title, { path: 'title', from: 'Uptime Goblin', to: 'Edited by hand' });
  assert.deepEqual(paths['email.password'], { path: 'email.password', change: 'changed' });
  const url = paths[`services.${saved.services[0].id}.url`];
  assert.deepEqual(url, {
    path: `services.${saved.services[0].id}.url`,
    from: '',
    to: 'https://example.com/?view=1',
  });
  assert.doesNotMatch(JSON.stringify(row.detail), /SENTINEL|second-secret|first-secret/);
  assert.ok(warned.some(line => /destination of/.test(line)));
  // The keys moved with the row: the next start finds nothing.
  await audit.start({ config: new ConfigStore(directory), passwordChangedAt: 5 });
  assert.equal((await storedRows(db)).filter(r => r.action === 'config.changed-outside').length, 1);
});

test('start rows: a password changed by an older build, and system.start with first, cleanStop, security and securityChanged', async t => {
  const { audit, db, control, keyring, clock } = await auditFixture(t);
  await audit.start({ passwordChangedAt: null });
  await audit.started({
    security: {
      legacyBasic: true,
      allowedHosts: ['b.example', 'a.example'],
      keySource: 'file',
      trustProxy: 'loopback',
    },
  });
  // The migration's own release entry is start()'s system.upgrade: set aside here.
  const startRows = async () =>
    (await storedRows(db)).filter(row => row.action !== 'system.upgrade');
  let rows = await startRows();
  assert.deepEqual(actionsOf(rows), ['system.start']);
  assert.deepEqual(rows[0].detail, {
    version: release,
    build: 'test',
    first: true,
    cleanStop: false,
    configRevision: null,
    security: {
      legacyBasic: true,
      insecureHttpSessions: false,
      trustProxy: 'loopback',
      allowedHosts: ['a.example', 'b.example'],
      webhook: false,
      keySource: 'file',
    },
  });
  assert.equal(await meta(db, 'audit_password_changed_at'), '');
  await audit.close();
  // The next start: a clean stop before it, the password changed meanwhile by an older build,
  // and legacy Basic switched off.
  const next = createAudit({
    db,
    clock,
    release: { version: release, build: 'test' },
    out() {},
    err() {},
  });
  t.after(() => next.close());
  await next.attach({ keyring, instanceId: await control.meta.instanceId() });
  await next.start({ passwordChangedAt: 42 });
  await next.started({
    security: {
      legacyBasic: false,
      allowedHosts: ['a.example', 'b.example'],
      keySource: 'file',
      trustProxy: 'loopback',
    },
  });
  rows = await startRows();
  assert.deepEqual(actionsOf(rows), [
    'system.start',
    'system.stop',
    'account.password.changed-outside',
    'system.start',
  ]);
  assert.deepEqual(rows[2].detail, { source: 'control.sqlite' });
  assert.equal(await meta(db, 'audit_password_changed_at'), '42');
  assert.equal(rows[3].detail.first, false);
  assert.equal(rows[3].detail.cleanStop, true);
  assert.deepEqual(rows[3].detail.securityChanged, ['legacyBasic']);
});

// Integration (the independent check's findings 2 and 3): a start after earlier ones. Each
// call starts a new service on the same database, as the next start of Uptime Goblin does.
function nextStarts(fixture) {
  return async security => {
    const next = createAudit({
      db: fixture.db,
      clock: fixture.clock,
      release: { version: release, build: 'test' },
      out() {},
      err() {},
    });
    await next.attach({
      keyring: fixture.keyring,
      instanceId: await fixture.control.meta.instanceId(),
    });
    await next.start({});
    await next.started({ security });
    const starts = (await storedRows(fixture.db)).filter(row => row.action === 'system.start');
    return { next, detail: starts.at(-1).detail };
  };
}
const cliRow = (action, detail) => ({
  action,
  outcome: 'ok',
  actor: { type: 'cli', id: null, name: 'cli:dana', via: 'cli', sessionId: null },
  target: { type: 'keyring', id: null, name: null },
  detail,
});

test('start rows: a goblin-admin key command after a clean stop leaves cleanStop true; after an end without system.stop it stays false', async t => {
  const fixture = await auditFixture(t);
  const { audit, db, keyring, clock } = fixture;
  const startNext = nextStarts(fixture);
  const rotate = cliRow('key.rotate', { purposes: ['audit'], retired: [], active: [] });
  await audit.start({});
  await audit.started({});
  await audit.close();
  // goblin-admin key rotate and key rewrap need Uptime Goblin stopped: their rows follow system.stop.
  await appendDirect({ db, keyring, clock }, rotate);
  await appendDirect({ db, keyring, clock }, cliRow('key.rewrap', { rewrapped: 4 }));
  const second = await startNext({});
  assert.equal(second.detail.cleanStop, true, 'stopped cleanly before the key commands');
  // Uptime Goblin ends without its system.stop (killed), then a key command: not a clean stop.
  await second.next.append(login());
  await appendDirect({ db, keyring, clock }, rotate);
  const third = await startNext({});
  assert.equal(third.detail.cleanStop, false);
  await third.next.close();
  await second.next.close();
});

// Review round 2: the restore anchor or head-mismatch gap that goblin-admin's own unit adds
// carried Uptime Goblin's actor, so it was read as Uptime Goblin's newest row and the start said its previous
// stop was not recorded.
test("start rows: a key command that anchors a waiting restore or a stale head leaves cleanStop true; those rows name the command's actor", async t => {
  for (const kind of ['restore', 'stale head'])
    await t.test(kind, async t => {
      const fixture = await auditFixture(t);
      const { audit, db, keyring, clock } = fixture;
      const startNext = nextStarts(fixture);
      await audit.start({});
      await audit.started({});
      await audit.close();
      if (kind === 'restore')
        // As goblin-admin restore-snapshot stamps it.
        await setMeta(db, 'restored', JSON.stringify({ snapshot: 's1', at: 5 }));
      else
        await db.write(tx =>
          auditOps.setHead(tx, { seq: 99, hash: 'f'.repeat(64), key_id: 'k', updated_at: 1 })
        );
      await appendDirect(
        { db, keyring, clock },
        cliRow('key.rotate', { purposes: ['audit'], retired: [], active: [] })
      );
      const added = (await storedRows(db)).slice(-2);
      assert.deepEqual(actionsOf(added), [
        kind === 'restore' ? 'system.restore' : 'audit.gap',
        'key.rotate',
      ]);
      assert.deepEqual(
        added.map(row => [row.actor_type, row.actor_name, row.via]),
        [
          ['cli', 'cli:dana', 'cli'],
          ['cli', 'cli:dana', 'cli'],
        ]
      );
      const next = await startNext({});
      assert.equal(next.detail.cleanStop, true, 'Uptime Goblin stopped cleanly before the command');
      await next.next.close();
    });
});

test('start rows: a key generated at the last start is read from the data directory now, which is no security change; another source is', async t => {
  const fixture = await auditFixture(t);
  const startNext = nextStarts(fixture);
  await fixture.audit.start({});
  await fixture.audit.started({ security: { keySource: 'generated' } });
  await fixture.audit.close();
  const second = await startNext({ keySource: 'data-directory' });
  const firstStart = (await storedRows(fixture.db)).find(row => row.action === 'system.start');
  assert.equal(firstStart.detail.security.keySource, 'generated', 'the first start says so');
  assert.deepEqual(second.detail.securityChanged, []);
  await second.next.close();
  const third = await startNext({ keySource: 'file' });
  assert.deepEqual(third.detail.securityChanged, ['keySource']);
  await third.next.close();
});

test('config meta forward: result rows of revisions 5 and then 4 leave config_revision_seen at 5', async t => {
  const { audit, db } = await auditFixture(t);
  const snapshot = (revision, title) => ({
    revision,
    public: { title },
    secrets: { key_id: 'k', macs: {} },
  });
  const write = async (revision, title) => {
    const change = await audit.begin(adminRequest(), {
      action: 'settings.update',
      target: { type: 'settings', id: 'workspace', name: null },
    });
    return { change, before: snapshot(revision - 1, 'old'), after: snapshot(revision, title) };
  };
  const five = await write(5, 'five');
  const four = await write(4, 'four');
  five.change.note({ applied: true, before: five.before, after: five.after });
  four.change.note({ applied: true, before: four.before, after: four.after });
  await five.change.end({ status: 200 });
  await four.change.end({ status: 200 });
  assert.equal(await meta(db, 'config_revision_seen'), '5');
  assert.equal(await meta(db, 'audit_config_public'), JSON.stringify({ title: 'five' }));
  // A change that did not apply moves nothing.
  const six = await write(6, 'six');
  six.change.note({ applied: false, before: six.before, after: six.after });
  await six.change.end({ status: 409, outcome: 'conflict' });
  assert.equal(await meta(db, 'config_revision_seen'), '5');
});

test('prune below a gap: a target inside a seq jump moves down to the greatest stored seq; the prune completes, and only the gap is broken', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const { audit, db, out, keyring } = await auditFixture(t, {
    clock,
    retention: { days: 30, maxRows: 250000 },
  });
  for (let n = 1; n <= 5; n++) await audit.append(stop(n));
  // The head ahead of the rows: the next unit writes a gap at seq 10 and continues at 11.
  const rows = await storedRows(db);
  await db.write(tx =>
    auditOps.setHead(tx, { seq: 9, hash: rows[4].hash, key_id: rows[4].key_id, updated_at: 1 })
  );
  clock.advance(40 * 86400000);
  for (let n = 1; n <= 3; n++) await audit.append(stop(n));
  // Rows 1–5 expired and the gap (10) is the first recent row: P_age is 9, which no row holds,
  // so the prune goes to 5.
  await audit.maintain({});
  await audit.idle();
  const left = await storedRows(db);
  assert.deepEqual(
    left.map(row => row.seq),
    [10, 11, 12, 13, 14]
  );
  assert.deepEqual(left.at(-1).detail, { through: 5, deleted: 5, reason: 'age' });
  const checkpoints = await db.read(tx => auditOps.checkpoints(tx));
  assert.deepEqual(
    checkpoints.map(c => [c.seq, c.reason]),
    [[5, 'prune']]
  );
  const printed = linesOf(out, 'audit.checkpoint').filter(line => line.reason === 'prune');
  assert.deepEqual(
    printed.map(line => line.seq),
    [5]
  );
  const result = await verifyAudit(db, { keyring });
  assert.equal(result.result, 'broken');
  assert.equal(result.problem.code, 'log_truncated');
  assert.equal(result.problem.seq, 10);
});

// `n` system.stop rows at `time`, chained in one unit (a shortcut for n own units).
async function appendMany({ db, keyring }, n, time) {
  const kid = keyring.activeKid('audit');
  const mac = data => keyring.hmac('audit', data, kid).mac;
  await db.write(tx => {
    const events = Array.from({ length: n }, (_, index) => ({ ...stop(index + 1), at: time }));
    writePlan(tx, planUnit(tx, events, { kid, mac, now: time, clock: () => time }), time);
  });
}
const prunedRows = async db =>
  (await storedRows(db)).filter(row => row.action === 'audit.pruned').map(row => row.detail);

test('prune targets: once a prune runs both targets apply; the cap alone starts one above maxRows + 1,000; the reason names what removed rows', async t => {
  await t.test(
    'expired rows start it, and the cap applies below maxRows + 1,000: both',
    async t => {
      const clock = manualClock(Date.UTC(2026, 0, 1));
      const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 5 } });
      await appendMany(f, 3, clock());
      clock.advance(40 * 86400000);
      await appendMany(f, 17, clock());
      await f.audit.maintain({});
      await f.audit.idle();
      // P_age is 3; P_cap is the 6th newest row, 15.
      assert.deepEqual(await prunedRows(f.db), [{ through: 15, deleted: 15, reason: 'both' }]);
      assert.equal((await verifyAudit(f.db, { keyring: f.keyring })).result, 'intact');
      // Later, the cap alone (1,016 rows, none expired): its reason is the cap, not both.
      await appendMany(f, 1010, clock());
      await f.audit.maintain({});
      await f.audit.idle();
      // (The first audit.pruned row, seq 21, is among the rows this prune removed.)
      assert.deepEqual(await prunedRows(f.db), [{ through: 1026, deleted: 1011, reason: 'cap' }]);
      assert.equal((await verifyAudit(f.db, { keyring: f.keyring })).result, 'intact');
    }
  );
  await t.test('a cap below the expired rows leaves the reason age', async t => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 5 } });
    await appendMany(f, 10, clock());
    clock.advance(40 * 86400000);
    await appendMany(f, 3, clock());
    await f.audit.maintain({});
    await f.audit.idle();
    assert.deepEqual(await prunedRows(f.db), [{ through: 10, deleted: 10, reason: 'age' }]);
  });
});

// Review round 1: the entries a prune removes are checked first. Their time chose them, but it
// is not what signs them: someone with the database but not the key sets the oldest entries'
// time back (each one now a hash_mismatch), and the hourly prune signed a checkpoint over the
// last of them and deleted them all, and what remained read intact, also against the journal.
test('prune: entries that do not check are never pruned: nothing signed or deleted, one warning a day, and the log still reads changed', async t => {
  await t.test('times edited back: rows whose time is 0', async t => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
    for (let n = 1; n <= 10; n++) {
      await f.audit.append(stop(n));
      clock.advance(1000);
    }
    await f.db.write(tx =>
      tx.run(tx.dialect.update('audit_log', { time: 0 }, sql`${sql.id('seq')} < ${10}`))
    );
    await f.audit.maintain({});
    await f.audit.maintain({});
    await f.audit.idle();
    assert.deepEqual(
      (await storedRows(f.db)).map(row => row.seq),
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    assert.deepEqual(await f.db.read(tx => auditOps.checkpoints(tx)), []);
    assert.deepEqual(
      linesOf(f.out, 'audit.checkpoint').filter(line => line.reason === 'prune'),
      []
    );
    const warning =
      'Uptime Goblin did not remove old audit entries, because entry #1 does not check: use Check integrity on the Audit log page.';
    assert.deepEqual(f.warnings, [warning], 'once a UTC day');
    const result = await verifyAudit(f.db, { keyring: f.keyring, journal: f.out.join('\n') });
    assert.equal(result.problem?.code, 'hash_mismatch', JSON.stringify(result.problem));
    assert.equal(result.problem.seq, 1);
    clock.advance(86400000);
    await f.audit.maintain({});
    assert.deepEqual(f.warnings, [warning, warning], 'again the next day');
    assert.equal((await storedRows(f.db)).length, 10);
  });
  await t.test('an entry of a newer format among them', async t => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
    for (let n = 1; n <= 4; n++) await f.audit.append(stop(n));
    await f.db.write(tx =>
      tx.run(tx.dialect.update('audit_log', { v: 2, time: 0 }, sql`${sql.id('seq')} = ${2}`))
    );
    clock.advance(40 * 86400000);
    await f.audit.append(stop(5));
    await f.audit.maintain({});
    await f.audit.idle();
    assert.equal((await storedRows(f.db)).length, 5, 'nothing deleted');
    assert.match(f.warnings[0], /because entry #2 does not check/);
    assert.equal((await verifyAudit(f.db, { keyring: f.keyring })).result, 'incomplete');
  });
  await t.test('the entry it signs changed after the check: nothing deleted', async t => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    let edited = false;
    const f = await auditFixture(t, {
      clock,
      retention: { days: 30, maxRows: 250000 },
      // Before the prune's first write unit (its checkpoint), row 6's time is set back.
      wrapDb: (db, purpose) =>
        purpose !== 'prune' || edited
          ? db
          : {
              dialect: db.dialect,
              read: (...args) => db.read(...args),
              async write(fn) {
                edited = true;
                await db.write(tx =>
                  tx.run(tx.dialect.update('audit_log', { time: 0 }, sql`${sql.id('seq')} = ${6}`))
                );
                return db.write(fn);
              },
            },
    });
    for (let n = 1; n <= 6; n++) await f.audit.append(stop(n));
    clock.advance(40 * 86400000);
    for (let n = 1; n <= 2; n++) await f.audit.append(stop(n));
    await f.audit.maintain({});
    await f.audit.idle();
    assert.ok(edited);
    assert.equal((await storedRows(f.db)).length, 8, 'nothing deleted');
    assert.deepEqual(await f.db.read(tx => auditOps.checkpoints(tx)), []);
    const result = await verifyAudit(f.db, { keyring: f.keyring });
    assert.equal(result.problem?.code, 'hash_mismatch');
    assert.equal(result.problem.seq, 6);
  });
  await t.test(
    'a commit line stored at the target is not a prune checkpoint: the prune stores its own',
    async t => {
      const clock = manualClock(Date.UTC(2026, 0, 1));
      const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
      for (let n = 1; n <= 6; n++) await f.audit.append(stop(n));
      const line = linesOf(f.out, 'audit.checkpoint').find(item => item.seq === 6);
      const { orbit, v, instance, ...stored } = line;
      await f.db.write(tx => auditOps.insertCheckpoint(tx, stored));
      clock.advance(40 * 86400000);
      for (let n = 1; n <= 2; n++) await f.audit.append(stop(n));
      await f.audit.maintain({});
      await f.audit.idle();
      assert.deepEqual(
        (await f.db.read(tx => auditOps.checkpoints(tx))).map(c => [c.seq, c.reason]),
        [
          [6, 'commit'],
          [6, 'prune'],
        ]
      );
      assert.deepEqual(actionsOf(await storedRows(f.db)), [
        'system.stop',
        'system.stop',
        'audit.pruned',
      ]);
      assert.equal((await verifyAudit(f.db, { keyring: f.keyring })).result, 'intact');
    }
  );
});

// Codex review A1: the prune's check read the rows after seq 0 only, so a row someone with the
// database put at seq 0 or below was never checked, and the prune signed a checkpoint and deleted
// it with the expired rows; what remained read intact. The check now reads from the lowest stored
// row, and such a row stops the prune like any entry that does not check.
test('Codex review A1: prune: a row at seq 0 or below stops the prune: nothing signed or deleted, the warning names it, and the log reads changed', async t => {
  for (const seq of [0, -1]) {
    await t.test(`at seq ${seq}`, async t => {
      const clock = manualClock(Date.UTC(2026, 0, 1));
      const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
      for (let n = 1; n <= 6; n++) {
        await f.audit.append(stop(n));
        clock.advance(1000);
      }
      // A copy of the oldest row, as old as it, with another detail and a made-up hash.
      const [oldest] = await storedRows(f.db);
      await f.db.write(tx =>
        auditOps.insertRow(tx, {
          ...oldest,
          seq,
          detail: { uptimeMs: 999 },
          detailText: '{"uptimeMs":999}',
          hash: 'f'.repeat(64),
        })
      );
      clock.advance(40 * 86400000);
      for (let n = 1; n <= 2; n++) await f.audit.append(stop(n));
      assert.equal(
        (await checkPrune(f.db, { keyring: f.keyring, through: 6 })).unchecked,
        seq,
        'the check names it'
      );
      await f.audit.maintain({});
      await f.audit.idle();
      assert.deepEqual(await allSeqs(f.db), [seq, 1, 2, 3, 4, 5, 6, 7, 8], 'nothing deleted');
      assert.deepEqual(await f.db.read(tx => auditOps.checkpoints(tx)), []);
      assert.deepEqual(
        linesOf(f.out, 'audit.checkpoint').filter(line => line.reason === 'prune'),
        []
      );
      assert.deepEqual(f.warnings, [
        `Uptime Goblin did not remove old audit entries, because entry #${seq} does not check: use Check integrity on the Audit log page.`,
      ]);
      const result = await verifyAudit(f.db, { keyring: f.keyring, journal: f.out.join('\n') });
      assert.equal(result.problem?.code, 'link_broken', JSON.stringify(result.problem));
      assert.equal(result.problem.seq, seq);
    });
  }
});

test('prune with the head ahead of the rows (a cut end): the newest stored row stays, so the start is still explained and the cut is log_truncated', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
  for (let n = 1; n <= 4; n++) await f.audit.append(stop(n));
  const rows = await storedRows(f.db);
  await f.db.write(tx =>
    auditOps.setHead(tx, { seq: 9, hash: rows[3].hash, key_id: rows[3].key_id, updated_at: 1 })
  );
  clock.advance(40 * 86400000);
  await f.audit.maintain({});
  await f.audit.idle();
  assert.deepEqual(
    (await storedRows(f.db)).map(row => [row.seq, row.action]),
    [
      [4, 'system.stop'],
      [10, 'audit.gap'],
      [11, 'audit.pruned'],
    ]
  );
  const result = await verifyAudit(f.db, { keyring: f.keyring });
  assert.equal(result.problem?.code, 'log_truncated', JSON.stringify(result.problem));
  assert.equal(result.problem.seq, 10);
});

test('prune checkpoints: a continued prune stores its checkpoint once; a later prune keeps only the newest', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const f = await auditFixture(t, { clock, retention: { days: 30, maxRows: 250000 } });
  await appendMany(f, 150, clock());
  clock.advance(40 * 86400000);
  await appendMany(f, 2, clock());
  // Stopped after the first chunk (100 rows): the next run continues to the same target.
  const stopped = new AbortController();
  await f.audit.maintain({ signal: stopped.signal, shouldYield: () => (stopped.abort(), false) });
  await f.audit.idle();
  assert.deepEqual(await prunedRows(f.db), [{ through: 150, deleted: 100, reason: 'age' }]);
  await f.audit.maintain({});
  await f.audit.idle();
  assert.deepEqual((await prunedRows(f.db))[1], { through: 150, deleted: 50, reason: 'age' });
  const checkpoints = () => f.db.read(tx => auditOps.checkpoints(tx));
  assert.deepEqual(
    (await checkpoints()).map(c => c.seq),
    [150]
  );
  // A later prune: the checkpoint of the earlier one verifies nothing that remains.
  clock.advance(40 * 86400000);
  await f.audit.append(stop(9));
  await f.audit.maintain({});
  await f.audit.idle();
  assert.deepEqual(
    (await checkpoints()).map(c => c.seq),
    [154]
  );
  assert.equal((await verifyAudit(f.db, { keyring: f.keyring })).result, 'intact');
});

test('start rows: after an audit-key rotation an unchanged configuration is compared under the stored key: no row; a secret changed later reads changed', async t => {
  const { audit, db, directory, keyring } = await auditFixture(t);
  const config = new ConfigStore(directory);
  config.value.email.password = 'first-secret';
  config.save();
  await audit.start({ config: new ConfigStore(directory), passwordChangedAt: 5 });
  await audit.started({ security: {} });
  await keyring.rotate({ purposes: ['audit'] });
  await audit.start({ config: new ConfigStore(directory), passwordChangedAt: 5 });
  const outside = async () =>
    (await storedRows(db)).filter(row => row.action === 'config.changed-outside');
  assert.deepEqual(await outside(), []);
  const file = path.join(directory, 'config.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  saved.email.password = 'second-secret';
  fs.writeFileSync(file, JSON.stringify(saved));
  await audit.start({ config: new ConfigStore(directory), passwordChangedAt: 5 });
  const [row] = await outside();
  assert.deepEqual(row.detail.diff, [{ path: 'email.password', change: 'changed' }]);
});

test('started(): when only the revision moved, no config.changed-outside, and system.start moves config_revision_seen', async t => {
  const { audit, db, directory } = await auditFixture(t);
  const config = new ConfigStore(directory);
  await audit.start({ config, passwordChangedAt: 5 });
  await audit.started({ security: {} });
  const first = config.value.revision;
  assert.equal(await meta(db, 'config_revision_seen'), String(first));
  config.save(); // the same content under the next revision
  const next = new ConfigStore(directory);
  assert.equal(next.value.revision, first + 1);
  await audit.start({ config: next, passwordChangedAt: 5 });
  await audit.started({ security: {} });
  assert.equal(
    (await storedRows(db)).filter(row => row.action === 'config.changed-outside').length,
    0
  );
  assert.equal(await meta(db, 'config_revision_seen'), String(first + 1));
});

test('close(): the waiting summaries and system.stop; while the guard is full nothing, and the lines', async t => {
  const guard = fakeGuard();
  const { audit, db, err, clock } = await auditFixture(t, { guard });
  await audit.started({ security: {} });
  const refusal = client => ({
    action: 'session.login',
    outcome: 'failed',
    client,
    login: 'x',
    detail: { code: 'invalid_credentials' },
  });
  audit.count(refusal('192.0.2.1'));
  audit.count(refusal('192.0.2.2'));
  audit.count(refusal('192.0.2.3'));
  await audit.idle();
  clock.advance(1000);
  await audit.close();
  const rows = await storedRows(db);
  assert.deepEqual(actionsOf(rows), [
    'system.start',
    'session.login',
    'session.login',
    'system.stop',
  ]);
  assert.equal(rows[2].count, 2);
  assert.deepEqual(rows[2].detail.codes, { invalid_credentials: 2 });
  assert.deepEqual(rows[3].detail, { uptimeMs: 1000 });
  assert.deepEqual(err, []);

  const second = await auditFixture(t, { guard });
  await second.audit.started({ security: {} });
  second.audit.count(refusal('192.0.2.1'));
  await second.audit.idle();
  second.audit.count(refusal('192.0.2.2'));
  guard.full = true;
  await second.audit.close();
  assert.deepEqual(actionsOf(await storedRows(second.db)), ['system.start', 'session.login']);
  const lines = linesOf(second.err, 'audit.unwritten');
  assert.deepEqual(
    lines.map(line => (line.counts ? 'counts' : line.row.action)),
    ['counts', 'system.stop']
  );
  assert.deepEqual(lines[0].counts['session.login'].count, 1);
  guard.full = false;
});

// Review round 1: a clean stop while the disk is full (the admin stops Uptime Goblin to free space, T8)
// writes no system.stop (D7), so the next start has no cleanStop: its sentence must not claim a
// crash that did not happen.
test('a stop while the guard is full, then a start: cleanStop false, and the sentence says the stop was not recorded, never that Uptime Goblin crashed', async t => {
  const guard = fakeGuard();
  const first = await auditFixture(t, { guard });
  await first.audit.started({ security: {} });
  guard.full = true;
  await first.audit.close();
  guard.full = false;
  const next = createAudit({
    db: first.db,
    clock: first.clock,
    release: { version: release, build: 'test' },
    out() {},
    err() {},
  });
  t.after(() => next.close());
  await next.attach({ keyring: first.keyring, instanceId: 'i' });
  await next.started({ security: {} });
  const starts = (await storedRows(first.db)).filter(row => row.action === 'system.start');
  assert.equal(starts.length, 2);
  const { detail } = starts[1];
  assert.equal(detail.cleanStop, false);
  // The first rule of the catalogue that holds for this row (the page's entrySentence()).
  const holds = when =>
    when === '*' || (when.startsWith('!') ? !detail[when.slice(1)] : Boolean(detail[when]));
  const [, text] = AUDIT_TEXTS['system.start'].texts.find(([when]) => holds(when));
  assert.equal(
    text.replace('{version}', detail.version),
    `Uptime Goblin ${release} started; its previous stop was not recorded (a crash, or a stop while the disk was full)`
  );
});

test('same names: createAudit() has exactly the methods of noopAudit(), in order', async t => {
  const { db } = await migratedControl(t);
  const audit = createAudit({ db });
  assert.deepEqual(Object.keys(audit), Object.keys(noopAudit()));
  assert.throws(() => createAudit({}), /control database/);
  await audit.close();
});

test('before attach(): append, begin, single and operation refuse (no request is served yet); state() says not ready', async t => {
  const { db } = await migratedControl(t);
  const audit = createAudit({ db, out() {}, err() {} });
  t.after(() => audit.close());
  await assert.rejects(audit.append(stop()), TypeError);
  await assert.rejects(audit.begin(adminRequest(), { action: 'settings.update' }), TypeError);
  await assert.rejects(audit.single(adminRequest(), { action: 'config.export' }), TypeError);
  assert.throws(() => audit.operation(adminRequest(), { action: 'sources.refresh' }), TypeError);
  assert.throws(() => audit.configSnapshot({ services: [] }), TypeError);
  assert.deepEqual(audit.state(), {
    ready: false,
    unwritten: null,
    retention: { days: 90, maxRows: 250000 },
  });
  // A keyless attach() changes nothing and never rejects.
  await audit.attach({});
  assert.equal(audit.state().ready, false);
});

test('fromDelivery: actorless system records become system rows; records with an actor and unknown ones are ignored', async t => {
  const { audit, db } = await auditFixture(t);
  audit.fromDelivery({
    at: 5,
    action: 'signing.created',
    outcome: 'ok',
    target: 'env-webhook',
    detail: { replaced: true },
  });
  audit.fromDelivery({
    at: 6,
    action: 'channel.paused',
    outcome: 'ok',
    target: 'email',
    detail: { reason: 'r'.repeat(300), transient: 1 },
  });
  audit.fromDelivery({ at: 7, action: 'channel.working', outcome: 'ok', target: 'email' });
  audit.fromDelivery({ at: 8, action: 'notifications.unsaved', outcome: 'ok', target: 'outbox' });
  audit.fromDelivery({ at: 9, action: 'notifications.saved', outcome: 'ok', target: 'outbox' });
  audit.fromDelivery({
    at: 10,
    action: 'delivery.retry',
    outcome: 'ok',
    actor: 'admin',
    target: 'u1',
  });
  audit.fromDelivery({ at: 11, action: 'signing.rotate', outcome: 'ok', actor: undefined });
  audit.fromDelivery({ at: 12, action: 'something.else', outcome: 'ok' });
  audit.fromDelivery(null);
  await audit.idle();
  const rows = await storedRows(db);
  assert.deepEqual(
    rows.map(row => [
      row.action,
      row.outcome,
      row.actor_type,
      row.target_type,
      row.target_id,
      row.time,
    ]),
    [
      ['signing.created', 'info', 'system', 'secret', 'env-webhook', 5],
      ['channel.paused', 'info', 'system', 'channel', 'email', 6],
      ['channel.working', 'info', 'system', 'channel', 'email', 7],
      ['notifications.unsaved', 'info', 'system', 'outbox', null, 8],
      ['notifications.saved', 'info', 'system', 'outbox', null, 9],
    ]
  );
  assert.deepEqual(rows[0].detail, { replaced: true });
  assert.equal(rows[1].detail.reason.length, 200);
  assert.equal(rows[1].detail.transient, true);
});

test('operations: one row after the action with the noted outcome and the code settle gives', async t => {
  const { audit, db } = await auditFixture(t);
  const op = audit.operation(adminRequest(), {
    action: 'source.test',
    target: { type: 'source', id: 'plex-1', name: 'Plex' },
    detail: { type: 'plex', savedCredentials: true },
  });
  assert.deepEqual(await storedRows(db), [], 'nothing when it is made');
  op.note({ outcome: 'failed', detail: { result: 'timeout' } });
  await op.end({ status: null, outcome: 'failed', code: 'client_closed' });
  await op.end({ status: 200 });
  const rows = await storedRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].outcome, 'failed');
  assert.equal(rows[0].status, null);
  assert.deepEqual(rows[0].detail, {
    type: 'plex',
    savedCredentials: true,
    result: 'timeout',
    code: 'client_closed',
  });
  assert.equal(rows[0].client_key, '192.0.2.10');
});

test('environment: GOBLIN_AUDIT_LOG and GOBLIN_AUDIT_RETENTION_DAYS with D13 and D14 warnings, verbatim', async () => {
  const { auditLogSetting, retentionSetting, securitySnapshot } = await import(
    '../../lib/audit/index.mjs'
  );
  for (const value of [undefined, '', 'off'])
    assert.deepEqual(auditLogSetting(value), { mirror: 'off', warning: null });
  assert.deepEqual(auditLogSetting('stdout'), { mirror: 'stdout', warning: null });
  assert.deepEqual(auditLogSetting('stdout-full'), { mirror: 'stdout-full', warning: null });
  for (const value of ['STDOUT', ' stdout '])
    assert.deepEqual(auditLogSetting(value), {
      mirror: 'off',
      warning: `GOBLIN_AUDIT_LOG must be off, stdout or stdout-full; it is set to ${value}, so the audit log is not copied to Uptime Goblin's log.`,
    });
  assert.deepEqual(auditLogSetting(`journal\u0007${'x'.repeat(60)}`), {
    mirror: 'off',
    warning: `GOBLIN_AUDIT_LOG must be off, stdout or stdout-full; it is set to journal${'x'.repeat(33)}, so the audit log is not copied to Uptime Goblin's log.`,
  });
  assert.deepEqual(retentionSetting(undefined), { days: 90, warning: null });
  assert.deepEqual(retentionSetting('400'), { days: 400, warning: null });
  assert.deepEqual(retentionSetting('10'), {
    days: 30,
    warning:
      'GOBLIN_AUDIT_RETENTION_DAYS must be from 30 to 3650 days; it is 10, so Uptime Goblin keeps audit entries for 30 days.',
  });
  assert.deepEqual(retentionSetting('9999'), {
    days: 3650,
    warning:
      'GOBLIN_AUDIT_RETENTION_DAYS must be from 30 to 3650 days; it is 9999, so Uptime Goblin keeps audit entries for 3650 days.',
  });
  for (const value of ['abc', '1.5', '-3', '30 days'])
    assert.deepEqual(retentionSetting(value), {
      days: 90,
      warning: `GOBLIN_AUDIT_RETENTION_DAYS must be a whole number of days from 30 to 3650; it is set to ${value}, so Uptime Goblin keeps audit entries for 90 days.`,
    });
  assert.deepEqual(
    securitySnapshot({
      legacyBasic: 1,
      allowedHosts: Array.from({ length: 25 }, (_, n) => `h${String(n).padStart(2, '0')}.example`),
      webhook: 'https://hooks.example.com/t/SECRET',
      trustProxy: '',
    }),
    {
      legacyBasic: true,
      insecureHttpSessions: false,
      trustProxy: null,
      allowedHosts: Array.from({ length: 20 }, (_, n) => `h${String(n).padStart(2, '0')}.example`),
      webhook: true,
      keySource: null,
    }
  );
});

test('prune interrupted: when its checkpoint cannot be stored nothing is deleted and the log verifies; the next run prunes', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const { audit, db, keyring, control } = await auditFixture(t, {
    clock,
    retention: { days: 30, maxRows: 250000 },
  });
  for (let n = 1; n <= 6; n++) await audit.append(stop(n));
  clock.advance(40 * 86400000);
  for (let n = 1; n <= 2; n++) await audit.append(stop(n));
  // The checkpoint's insert is refused (a trigger stands in for a failing write).
  const raw = new DatabaseSync(control.file);
  raw.exec(
    "CREATE TRIGGER refuse_checkpoint BEFORE INSERT ON audit_checkpoints BEGIN SELECT RAISE(ABORT, 'refused'); END"
  );
  await audit.maintain({});
  assert.equal((await storedRows(db)).length, 8, 'nothing deleted');
  assert.deepEqual(await db.read(tx => auditOps.checkpoints(tx)), []);
  assert.equal((await verifyAudit(db, { keyring })).result, 'intact');
  raw.exec('DROP TRIGGER refuse_checkpoint');
  raw.close();
  await audit.maintain({});
  await audit.idle();
  assert.deepEqual(actionsOf(await storedRows(db)), ['system.stop', 'system.stop', 'audit.pruned']);
  assert.deepEqual(
    (await db.read(tx => auditOps.checkpoints(tx))).map(c => c.seq),
    [6]
  );
  assert.equal((await verifyAudit(db, { keyring })).result, 'intact');
});

test('clock behind: the age prune waits while the clock is more than an hour behind the newest row, with one warning a day', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const { audit, db, warnings } = await auditFixture(t, {
    clock,
    retention: { days: 30, maxRows: 250000 },
  });
  await audit.append(stop(1));
  clock.advance(60 * 86400000);
  await audit.append(stop(2));
  // A clock that went back two hours: row 1 is long expired, but nothing is removed.
  clock.advance(-2 * 3600000);
  await audit.maintain({});
  await audit.maintain({});
  assert.equal((await storedRows(db)).length, 2);
  assert.deepEqual(warnings, [
    "Uptime Goblin's clock is behind its newest audit entry, so it did not remove audit entries older than 30 days this time. Check the time of the Uptime Goblin host.",
  ]);
  clock.advance(3 * 3600000);
  await audit.maintain({});
  await audit.idle();
  assert.deepEqual(actionsOf(await storedRows(db)), ['system.stop', 'audit.pruned']);
});

test('start() and started() never reject: rows that cannot be written go to stderr and their markers stay', async t => {
  const fail = new Set(['start']);
  const { audit, db, err } = await auditFixture(t, { wrapDb: countingWrap({ fail }) });
  await audit.start({ passwordChangedAt: null });
  await audit.started({ security: {} });
  assert.deepEqual(
    linesOf(err, 'audit.unwritten').map(line => line.row.action),
    ['system.upgrade', 'system.start']
  );
  assert.equal(await meta(db, 'audit_release_marker'), null);
  fail.clear();
  await audit.start({ passwordChangedAt: null });
  assert.deepEqual(
    actionsOf(await storedRows(db)),
    ['system.upgrade'],
    'written at the next start'
  );
});

test('verify join and exclusion: two checks at once share one run; a prune waits for a running check', async t => {
  let reads = 0,
    hold = null;
  const { audit, clock, db } = await auditFixture(t, {
    clock: manualClock(Date.UTC(2026, 0, 1)),
    retention: { days: 30, maxRows: 250000 },
    wrapDb: (target, purpose) =>
      purpose === 'read'
        ? {
            dialect: target.dialect,
            // The next read waits for `hold` when one is set (a check that takes long).
            async read(fn) {
              reads++;
              const gate = hold;
              hold = null;
              if (gate) await gate;
              return target.read(fn);
            },
            write: (...args) => target.write(...args),
          }
        : target,
  });
  for (let n = 1; n <= 3; n++) await audit.append(stop(n));
  reads = 0;
  const [a, b] = await Promise.all([audit.verify(), audit.verify()]);
  assert.equal(a, b);
  assert.equal(reads, 2, 'one run: its first unit and one unit of rows');
  // A prune asked for while a check runs waits for it, then runs in the same maintain().
  clock.advance(40 * 86400000);
  await audit.append(stop(4));
  let release;
  hold = new Promise(resolve => (release = resolve));
  const order = [];
  const checking = audit.verify().then(() => order.push('verify'));
  const pruning = audit.maintain({}).then(() => order.push('prune'));
  for (let n = 0; n < 20; n++) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(order, [], 'the prune waits while the check is held');
  assert.equal((await storedRows(db)).length, 4, 'nothing pruned yet');
  release();
  await Promise.all([checking, pruning]);
  assert.deepEqual(order, ['verify', 'prune']);
  await audit.idle();
  assert.ok((await storedRows(db)).some(row => row.action === 'audit.pruned'));
});

test('a stored prune checkpoint is signed with meta.instance_id, so it verifies whatever instance the service was given', async t => {
  const clock = manualClock(Date.UTC(2026, 0, 1));
  const { audit, db, keyring, out } = await auditFixture(t, {
    clock,
    attach: false,
    retention: { days: 30, maxRows: 250000 },
  });
  await audit.attach({ keyring, instanceId: 'not-the-stored-one' });
  for (let n = 1; n <= 3; n++) await audit.append(stop(n));
  clock.advance(40 * 86400000);
  await audit.append(stop(4));
  await audit.maintain({});
  await audit.idle();
  assert.equal((await db.read(tx => auditOps.checkpoints(tx))).length, 1);
  const pruneLines = out.filter(line => line.includes('"reason":"prune"'));
  assert.equal(pruneLines.length, 1);
  const result = await verifyAudit(db, { keyring, journal: pruneLines.join('\n') });
  assert.equal(result.result, 'intact', JSON.stringify(result.problem));
  assert.deepEqual(result.checkpoints, { checked: 1, matched: 1 });
  assert.equal(result.journal.matched, 1);
});

test('start rows: a damaged upgrade_history reaches system.upgrade only as its newest 50 well-formed entries', async t => {
  const { audit, db } = await auditFixture(t);
  await setMeta(
    db,
    'upgrade_history',
    history([
      entry('1.5.0-dev.1', 'x\u001b[2J\n[orbit] FORGED', 1),
      { from: null, to: 'y'.repeat(100000), at: 2 },
      ...Array.from({ length: 60 }, (_, n) => entry('1.5.0-dev.1', release, 10 + n)),
    ])
  );
  await setMeta(db, 'audit_release_marker', JSON.stringify({ to: 'gone', at: 0 }));
  await audit.start({});
  const [row] = await storedRows(db);
  assert.equal(row.action, 'system.upgrade');
  assert.equal(row.detail.entries.length, 50);
  assert.ok(row.detail.entries.every(item => item.to === release && item.from === '1.5.0-dev.1'));
  assert.equal(row.detail.markerLost, true);
});
