import test from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_ERRORS, AdminError, adminError } from '../../lib/admin/errors.mjs';
import { LOCK_NAMES } from '../../lib/admin/actions.mjs';
import { answerStatus } from '../../lib/http/pipeline.mjs';

test('step-up errors have frozen status/text and no arbitrary field leakage', () => {
  for (const code of ['step_up_required', 'step_up_failed', 'step_up_unavailable']) {
    const error = adminError(code, {
      variant: code === 'step_up_unavailable' ? 'local' : undefined,
      password: 'DO_NOT_ECHO',
      message: 'DO_NOT_ECHO',
      facts: { password: 'DO_NOT_ECHO' },
      command: 'DO_NOT_ECHO',
    });
    assert.ok(error instanceof AdminError);
    assert.equal(answerStatus(error), 403);
    assert.deepEqual(Object.keys(error.body), ['error', 'code']);
    assert.equal(JSON.stringify(error).includes('DO_NOT_ECHO'), false);
    assert.throws(() => {
      error.body.error = 'DO_NOT_ECHO';
    }, TypeError);
    assert.throws(() => {
      error.status = 200;
    }, TypeError);
  }
  assert.equal(
    ADMIN_ERRORS.step_up_required.messages.default,
    'Enter your Uptime Goblin password to confirm this action.'
  );
  assert.equal(adminError('step_up_unavailable', { variant: 'basic' }).status, 403);
});

test('all ten lock errors derive static commands and offline policy from registry', () => {
  for (const lock of LOCK_NAMES) {
    const error = adminError('admin_ui_locked', {
      lock,
      command: 'DO_NOT_ECHO',
      stopFirst: true,
      deployment: { container: true, offline: true, key: true },
    });
    assert.equal(error.status, 403);
    assert.deepEqual(Object.keys(error.body), ['error', 'code', 'lock', 'command', 'stopFirst']);
    assert.equal(JSON.stringify(error).includes('DO_NOT_ECHO'), false);
    if (lock === 'logging') {
      assert.equal(error.body.command, null);
      assert.equal(error.body.stopFirst, false);
    } else {
      const offline = ['snapshot-delete', 'audit-accept'].includes(lock);
      assert.equal(error.body.stopFirst, offline);
      assert.ok(
        error.body.command.startsWith(
          offline
            ? 'docker compose run --rm --no-deps uptime-goblin '
            : 'docker compose exec uptime-goblin '
        )
      );
    }
  }
});

test('unknown codes, locks and variants refuse without echoing supplied values', () => {
  for (const make of [
    () => adminError('DO_NOT_ECHO'),
    () => adminError('toString'),
    () => adminError('admin_ui_locked', { lock: 'DO_NOT_ECHO' }),
    () => adminError('step_up_unavailable', { variant: 'DO_NOT_ECHO' }),
  ])
    assert.throws(
      make,
      error => error instanceof TypeError && !error.message.includes('DO_NOT_ECHO')
    );
  const busy = adminError('admin_busy');
  assert.equal(busy.status, 409);
  assert.equal(busy.retryAfter, 5);
});

test('native locked mutations retain captured master-key file for credential creation and audit', () => {
  for (const lock of LOCK_NAMES.filter(name => name !== 'logging')) {
    const error = adminError('admin_ui_locked', {
      lock,
      deployment: {
        container: false,
        supervised: true,
        keyFile: '/etc/uptime-goblin/example key',
        key: false,
      },
    });
    assert.ok(
      error.body.command.startsWith(
        "sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE='/etc/uptime-goblin/example key' node "
      )
    );
  }
  const display = adminError('admin_ui_locked', {
    lock: 'display-code',
    deployment: { container: false, supervised: true },
  });
  assert.ok(display.body.command.includes('GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key'));
  assert.ok(display.body.command.includes("display code --name '<name>'"));
});
