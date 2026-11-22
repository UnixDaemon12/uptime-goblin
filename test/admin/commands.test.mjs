import { inContainer as sharedContainer } from '../../lib/container.mjs';
import { inContainer as cliContainer } from '../../lib/cli/common.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { adminUiCommand } from '../../lib/admin/commands.mjs';
import { ADMIN_ACTIONS } from '../../lib/admin/actions.mjs';
import { asAdminCopy } from '../../lib/admin-command.mjs';

test('Compose separates running-server commands from offline recovery', () => {
  assert.equal(
    adminUiCommand(['display', 'code', '--name', '<name>'], { container: true }),
    "docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs display code --name '<name>'"
  );
  assert.equal(
    adminUiCommand(['snapshot', 'delete', '<id>'], { container: true, offline: true }),
    "docker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs snapshot delete '<id>'"
  );
  for (const action of ADMIN_ACTIONS) {
    const line = adminUiCommand(action.command, { container: true, offline: action.offline });
    assert.ok(
      line.startsWith(
        action.offline
          ? 'docker compose run --rm --no-deps uptime-goblin '
          : 'docker compose exec uptime-goblin '
      )
    );
  }
});

test('native supervised lines use configured key file and existing native formatter', () => {
  const line = adminUiCommand(['key', 'remove-data-copy'], {
    container: false,
    supervised: true,
    key: true,
    keyFile: '/etc/uptime-goblin/example key',
  });
  assert.equal(
    line,
    "sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE='/etc/uptime-goblin/example key' node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key remove-data-copy --data-dir /var/lib/uptime-goblin"
  );
  assert.equal(
    adminUiCommand(['status'], { container: false, supervised: true }),
    'sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs status --data-dir /var/lib/uptime-goblin'
  );
});

test('manual installations keep the documented env-file form', () => {
  assert.equal(
    adminUiCommand(['audit', 'accept', '<entry>', '--confirm', '<code>'], { container: false }),
    "node --env-file-if-exists=.env lib/cli/goblin-admin.mjs audit accept '<entry>' --confirm '<code>'"
  );
});

test('shell metacharacters and install paths remain single quoted words', () => {
  const line = asAdminCopy({ root: "/opt/uptime-goblin's copy", dataDir: '/srv/orbit data' }, () =>
    adminUiCommand(['display', 'code', '--name', '$(echo BAD); `echo BAD`'], {
      container: false,
      supervised: true,
    })
  );
  assert.ok(line.includes("'/opt/uptime-goblin'\\''s copy/lib/cli/goblin-admin.mjs'"));
  assert.ok(line.includes("'$(echo BAD); `echo BAD`'"));
  assert.ok(line.endsWith("--data-dir '/srv/orbit data'"));
});

test('malformed arguments and nonboolean configuration fail without echoing input', () => {
  for (const args of [null, 'status', [], [''], [1], ['status\nBAD'], ['\u202eBAD']])
    assert.throws(() => adminUiCommand(args, { container: false }), TypeError);
  for (const flag of ['key', 'offline', 'container', 'supervised'])
    assert.throws(
      () => adminUiCommand(['status'], { container: false, [flag]: 'false' }),
      TypeError
    );
  for (const keyFile of ['', 1, '/etc/x\nBAD', '/etc/\u200bBAD'])
    assert.throws(() => adminUiCommand(['status'], { container: false, keyFile }), TypeError);
});

test('CLI compatibility export uses the same shared container detector', () => {
  assert.equal(cliContainer, sharedContainer);
  assert.equal(typeof sharedContainer(), 'boolean');
  assert.equal(
    adminUiCommand(['status']),
    adminUiCommand(['status'], { container: sharedContainer() })
  );
});
