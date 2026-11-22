import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { identityOps } from '../../lib/repo/identity.mjs';
import { metaOps } from '../../lib/db/control.mjs';
import { newDisplayCode } from '../../lib/identity/secrets.mjs';
import { temporary, startIdentity, adminPassword, writeAuthJson, fakeRecord } from './helpers.mjs';

async function waiting(context) {
  const made = newDisplayCode(),
    now = context.clock();
  await context.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: made.id,
      name: 'Fixture display',
      codeHash: made.codeHash,
      codeExpiresAt: now + 600000,
      createdAt: now,
      createdBy: 'cli:test',
    })
  );
  return made;
}
const redeem = (identity, code) =>
  identity.redeemDisplayCode({
    code,
    client: '192.0.2.50',
    userAgent: 'fixture',
    transport: 'loopback',
  });
for (const mode of ['restart', 'env-import', 'auth-import', 'restore-marker', 'control-replaced']) {
  test(`waiting display codes across ${mode}`, async t => {
    const directory = temporary(t);
    const first = await startIdentity(t, directory, { password: adminPassword });
    const made = await waiting(first);
    if (mode === 'restore-marker')
      await first.db.write(tx =>
        metaOps.set(tx, 'restored', '{"snapshot":"fixture-restore","at":1}', 1)
      );
    first.stop();
    if (mode === 'auth-import') writeAuthJson(directory, fakeRecord('fixture-new-password'));
    if (mode === 'control-replaced') {
      const file = path.join(directory, 'control.sqlite');
      fs.copyFileSync(file, file + '.replacement');
      fs.renameSync(file + '.replacement', file);
    }
    const next = await startIdentity(t, directory, {
      password: mode === 'env-import' ? 'fixture-new-password' : adminPassword,
    });
    if (mode === 'restart') {
      assert.equal((await redeem(next.identity, made.code)).access.kind, 'kiosk');
    } else {
      await assert.rejects(
        redeem(next.identity, made.code),
        error => error.code === 'display_code_invalid'
      );
      const row = await next.db.read(tx => identityOps.display(tx, made.id));
      if (mode.endsWith('import')) {
        assert.equal(row.state, 'cancelled');
        assert.equal(row.cancelCause, 'password_change');
        assert.equal(row.cancelRecorded, false, 'cancellation retains its audit obligation');
        await next.identity.prune();
        assert.equal(
          (await next.db.read(tx => identityOps.display(tx, made.id))).cancelRecorded,
          true
        );
        assert.equal(
          next.events.filter(event => event.action === 'display.code.cancelled').length,
          1
        );
        await next.identity.prune();
        assert.equal(
          next.events.filter(event => event.action === 'display.code.cancelled').length,
          1,
          'no duplicate receipt'
        );
      } else {
        assert.equal(row, null, 'restore removes every display row');
        assert.equal(
          next.events.find(event => event.action === 'session.revoked-restore').detail.displayCodes,
          1
        );
      }
    }
  });
}

test('restoring a waiting-code snapshot cannot revive codes redeemed or cancelled afterwards', async t => {
  const directory = temporary(t),
    backup = temporary(t);
  const first = await startIdentity(t, directory, { password: adminPassword });
  const used = await waiting(first),
    cancelled = await waiting(first);
  first.stop();
  fs.copyFileSync(path.join(directory, 'control.sqlite'), path.join(backup, 'control.sqlite'));
  const second = await startIdentity(t, directory, { password: adminPassword });
  await redeem(second.identity, used.code);
  await second.db.write(tx =>
    identityOps.cancelDisplays(tx, { ids: [cancelled.id], cause: 'cancelled', now: second.clock() })
  );
  second.stop();
  const file = path.join(directory, 'control.sqlite');
  fs.copyFileSync(path.join(backup, 'control.sqlite'), file + '.replacement');
  fs.renameSync(file + '.replacement', file);
  const restored = await startIdentity(t, directory, { password: adminPassword });
  assert.equal(restored.identity.status().restoredAtStart, true);
  for (const made of [used, cancelled])
    await assert.rejects(
      redeem(restored.identity, made.code),
      error => error.code === 'display_code_invalid'
    );
});

for (const restore of [false, true])
  test(`cancellation stays fail-closed when startup audit is full: restore=${restore}`, async t => {
    const { fakeAudit } = await import('../helpers/fake-audit.mjs');
    const directory = temporary(t);
    const first = await startIdentity(t, directory, { password: adminPassword });
    const made = await waiting(first);
    if (restore)
      await first.db.write(tx =>
        metaOps.set(tx, 'restored', '{"snapshot":"fixture-full","at":2}', 2)
      );
    first.stop();
    const audit = fakeAudit();
    audit.setFailing('record', Object.assign(new Error('fixture full'), { class: 'full' }));
    const next = await startIdentity(t, directory, {
      password: restore ? adminPassword : 'fixture-changed-password',
      audit,
    });
    await assert.rejects(
      redeem(next.identity, made.code),
      error => error.code === 'display_code_invalid'
    );
    assert.ok(audit.unrecorded.calls.length > 0, 'startup fallback was exercised');
    if (restore) {
      assert.equal(await next.db.read(tx => identityOps.display(tx, made.id)), null);
      assert.equal(
        audit.unrecorded.calls.find(call => call.event.action === 'session.revoked-restore').event
          .detail.displayCodes,
        1
      );
    } else {
      await next.identity.prune();
      assert.equal(
        (await next.db.read(tx => identityOps.display(tx, made.id))).cancelRecorded,
        false,
        'failed receipt remains owed'
      );
      audit.setFailing('record', null);
      await next.identity.prune();
      assert.equal(
        (await next.db.read(tx => identityOps.display(tx, made.id))).cancelRecorded,
        true
      );
      assert.equal(audit.rows.filter(row => row.action === 'display.code.cancelled').length, 1);
    }
  });

test('real audit normalization retains the restore display count', async () => {
  const { buildRow } = await import('../../lib/audit/writer.mjs');
  const row = buildRow(
    {
      action: 'session.revoked-restore',
      outcome: 'info',
      target: { type: 'account', id: 'u_admin', name: null },
      detail: { cause: 'snapshot', snapshot: 'fixture', displayCodes: 3 },
    },
    () => 1
  );
  assert.equal(row.detail.displayCodes, 3);
});
