import test from 'node:test';
import assert from 'node:assert/strict';
import { identityOps } from '../../lib/repo/identity.mjs';
import { metaOps } from '../../lib/db/control.mjs';
import { newDisplayCode } from '../../lib/identity/secrets.mjs';
import {
  credentialAnchorChanged,
  credentialsPlacedSinceLastStart,
  keys,
  controlFileIdentity,
} from '../../lib/identity/bootstrap.mjs';
import { temporary, startIdentity, adminPassword } from './helpers.mjs';
import { buildRow } from '../../lib/audit/writer.mjs';

for (const mode of [
  'absent',
  'malformed',
  'shape',
  'older-build-marker',
  'older-build-file',
  'unknown-file',
  'unchanged',
]) {
  test(`credential anchor ${mode} does not resurrect codes or unnecessarily revoke interactive sessions`, async t => {
    const directory = temporary(t);
    const first = await startIdentity(t, directory, { password: adminPassword });
    const session = await first.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.3',
      transport: 'loopback',
    });
    const code = newDisplayCode();
    await first.db.write(tx => {
      identityOps.insertDisplay(tx, {
        id: code.id,
        name: 'Fixture',
        codeHash: code.codeHash,
        codeExpiresAt: first.clock() + 600000,
        createdAt: first.clock(),
        createdBy: 'cli:test',
      });
      const anchor = JSON.parse(identityOps.settings(tx)[keys.credentialsAnchor]);
      if (mode === 'absent') identityOps.deleteSetting(tx, keys.credentialsAnchor);
      if (mode === 'malformed')
        identityOps.setSetting(tx, keys.credentialsAnchor, '{', first.clock());
      if (mode === 'shape') identityOps.setSetting(tx, keys.credentialsAnchor, '{}', first.clock());
      if (mode === 'older-build-marker') {
        const marker = '{"snapshot":"fixture","at":1}';
        metaOps.set(tx, 'restored', marker, first.clock());
        // An older build has already handled its builtin marker, not the credential anchor.
        identityOps.setSetting(tx, keys.restoreSeen, marker, first.clock());
      }
      if (mode === 'unknown-file') {
        anchor.controlFile = null;
        identityOps.setSetting(tx, keys.credentialsAnchor, JSON.stringify(anchor), first.clock());
      }
      if (mode === 'older-build-file') {
        anchor.controlFile = '{"ino":"not-this-file"}';
        identityOps.setSetting(tx, keys.credentialsAnchor, JSON.stringify(anchor), first.clock());
      }
    });
    first.stop();
    const next = await startIdentity(t, directory, { password: adminPassword });
    assert.ok(
      await next.identity.authenticateSession(session.issue.value, { transport: 'loopback' }),
      'anchor alone does not revoke interactive sessions'
    );
    assert.equal(next.identity.status().restoredAtStart, false);
    const row = await next.db.read(tx => identityOps.display(tx, code.id));
    if (mode === 'unchanged') assert.equal(row.state, 'waiting');
    else {
      assert.equal(row, null);
      const receipt = next.events.find(e => e.action === 'session.revoked-restore');
      assert.equal(receipt.detail.cause, 'credentials_anchor');
      assert.equal(receipt.detail.displayCodes, 1);
      assert.equal(buildRow(receipt, next.clock).detail.displayCodes, 1);
    }
    const settings = await next.db.read(tx => identityOps.settings(tx));
    const restored = await next.db.read(tx => identityOps.meta(tx, 'restored'));
    assert.deepEqual(JSON.parse(settings[keys.credentialsAnchor]), {
      controlFile: controlFileIdentity(next.control.file),
      restoreSeen: restored,
    });
    assert.equal(
      credentialsPlacedSinceLastStart(
        next.control.file,
        { settings, restored },
        { hasCredentials: true }
      ),
      false
    );
  });
}

test('anchor parsing fail-closes only when credentials exist and detects independent boundaries', () => {
  const current = '{"ino":"1"}';
  for (const anchor of [null, '{', '{}', '[]', '{"controlFile":12,"restoreSeen":null}']) {
    assert.equal(
      credentialAnchorChanged({
        anchor,
        restored: null,
        controlFile: current,
        hasCredentials: true,
      }),
      true
    );
    assert.equal(
      credentialAnchorChanged({
        anchor,
        restored: null,
        controlFile: current,
        hasCredentials: false,
      }),
      false
    );
  }
  const anchor = JSON.stringify({ controlFile: current, restoreSeen: null });
  assert.equal(
    credentialAnchorChanged({ anchor, restored: null, controlFile: null, hasCredentials: true }),
    true
  );
  assert.equal(
    credentialAnchorChanged({
      anchor: JSON.stringify({ controlFile: null, restoreSeen: null }),
      restored: null,
      controlFile: current,
      hasCredentials: true,
    }),
    true
  );
  assert.equal(
    credentialAnchorChanged({ anchor, restored: null, controlFile: current, hasCredentials: true }),
    false
  );
  assert.equal(
    credentialAnchorChanged({
      anchor,
      restored: 'new',
      controlFile: current,
      hasCredentials: false,
    }),
    true
  );
  assert.equal(
    credentialAnchorChanged({
      anchor,
      restored: null,
      controlFile: '{"ino":"2"}',
      hasCredentials: false,
    }),
    true
  );
});

test('anchor deletion and stamping survive audit-full fallback together', async t => {
  const { fakeAudit } = await import('../helpers/fake-audit.mjs');
  const directory = temporary(t);
  const first = await startIdentity(t, directory, { password: adminPassword });
  const code = newDisplayCode();
  await first.db.write(tx => {
    identityOps.insertDisplay(tx, {
      id: code.id,
      name: 'Fixture',
      codeHash: code.codeHash,
      codeExpiresAt: first.clock() + 600000,
      createdAt: first.clock(),
      createdBy: 'cli:test',
    });
    identityOps.deleteSetting(tx, keys.credentialsAnchor);
  });
  first.stop();
  const audit = fakeAudit();
  audit.setFailing('record', Object.assign(new Error('fixture full'), { class: 'full' }));
  const next = await startIdentity(t, directory, { password: adminPassword, audit });
  assert.equal(await next.db.read(tx => identityOps.display(tx, code.id)), null);
  assert.ok(await next.db.read(tx => identityOps.settings(tx)[keys.credentialsAnchor]));
  assert.equal(
    audit.unrecorded.calls.filter(c => c.event.action === 'session.revoked-restore').length,
    1
  );
});

for (const full of [false, true])
  test(`first-account startup clears anomalous preexisting codes atomically, audit-full=${full}`, async t => {
    const { fakeAudit } = await import('../helpers/fake-audit.mjs');
    const directory = temporary(t),
      first = await startIdentity(t, directory, { password: adminPassword });
    const code = newDisplayCode();
    await first.db.write(tx => {
      identityOps.insertDisplay(tx, {
        id: code.id,
        name: 'Fixture',
        codeHash: code.codeHash,
        codeExpiresAt: first.clock() + 600000,
        createdAt: first.clock(),
        createdBy: 'cli:test',
      });
      identityOps.deleteSetting(tx, keys.credentialsAnchor);
    });
    first.stop();
    const { DatabaseSync } = await import('node:sqlite');
    const db = new DatabaseSync(first.control.file);
    db.exec("DELETE FROM users WHERE id='u_admin'");
    db.close();
    const audit = fakeAudit();
    if (full)
      audit.setFailing('record', Object.assign(new Error('fixture full'), { class: 'full' }));
    const next = await startIdentity(t, directory, { password: adminPassword, audit });
    assert.equal(await next.db.read(tx => identityOps.display(tx, code.id)), null);
    await assert.rejects(
      next.identity.redeemDisplayCode({
        code: code.code,
        client: '192.0.2.3',
        transport: 'loopback',
      }),
      e => e.code === 'display_code_invalid'
    );
    assert.ok(await next.db.read(tx => identityOps.settings(tx)[keys.credentialsAnchor]));
    if (full)
      assert.equal(
        audit.unrecorded.calls.filter(c => c.event.action === 'session.revoked-restore').length,
        1
      );
    if (!full)
      assert.equal(
        next.events.find(e => e.action === 'session.revoked-restore').detail.displayCodes,
        1
      );
  });

test('a code arriving after startup snapshot is included in the atomic anchor decision', async t => {
  const directory = temporary(t),
    first = await startIdentity(t, directory, { password: adminPassword });
  await first.db.write(tx => identityOps.deleteSetting(tx, keys.credentialsAnchor));
  first.stop();
  const code = newDisplayCode();
  let inserted = false;
  const next = await startIdentity(t, directory, {
    password: adminPassword,
    wrap: control => ({
      ...control,
      db: new Proxy(control.db, {
        get(target, key) {
          if (key === 'write')
            return callback =>
              target.write(tx => {
                if (!inserted) {
                  inserted = true;
                  identityOps.insertDisplay(tx, {
                    id: code.id,
                    name: 'Fixture concurrent CLI',
                    codeHash: code.codeHash,
                    codeExpiresAt: Date.now() + 600000,
                    createdAt: Date.now(),
                    createdBy: 'cli:test',
                  });
                }
                return callback(tx);
              });
          const value = Reflect.get(target, key);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }),
    }),
  });
  assert.equal(inserted, true);
  assert.equal(await next.db.read(tx => identityOps.display(tx, code.id)), null);
  assert.equal(
    next.events.find(e => e.action === 'session.revoked-restore').detail.displayCodes,
    1
  );
});
