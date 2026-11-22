// Readiness under systemd's Type=notify unit (lib/systemd-notify.mjs): systemd-notify --ready, by
// absolute path, with NOTIFY_SOCKET alone in its environment, only when systemd gave a socket of
// its own form. The real exchange with systemd is in test/installer/systemd.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { notifyReady, notifySocket, NOTIFY_PROGRAMS } from '../lib/systemd-notify.mjs';

function harness({ present = NOTIFY_PROGRAMS, fail = null, throws = null } = {}) {
  const calls = [],
    errors = [];
  return {
    calls,
    errors,
    options: {
      exists: file => present.includes(file),
      logger: { error: line => errors.push(line) },
      run: (program, args, options, done) => {
        if (throws) throw throws;
        calls.push({ program, args, options });
        setImmediate(() => done(fail));
      },
    },
  };
}

test('without NOTIFY_SOCKET nothing is started (Docker, a shell, the tests)', async () => {
  const { calls, errors, options } = harness();
  assert.equal(await notifyReady({ ...options, env: {} }), false);
  assert.deepEqual(calls, []);
  assert.deepEqual(errors, []);
});

test('systemd-notify --ready gets NOTIFY_SOCKET and nothing else of the environment', async () => {
  for (const socket of ['/run/systemd/notify', '@/org/freedesktop/systemd1/notify/4242']) {
    const { calls, errors, options } = harness();
    const env = {
      NOTIFY_SOCKET: socket,
      GOBLIN_PASSWORD: 'canary-notify-password',
      PATH: '/tmp/elsewhere',
      NODE_OPTIONS: '--require=/tmp/x.cjs',
    };
    assert.equal(await notifyReady({ ...options, env }), true);
    assert.deepEqual(errors, []);
    assert.equal(calls.length, 1);
    const [{ program, args, options: given }] = calls;
    assert.equal(program, '/usr/bin/systemd-notify');
    assert.deepEqual(args, ['--ready']);
    assert.deepEqual(given.env, { NOTIFY_SOCKET: socket });
    assert.equal(given.shell, false);
    assert.equal(given.timeout, 10000);
  }
  // /bin when /usr/bin has none.
  const { calls, options } = harness({ present: ['/bin/systemd-notify'] });
  assert.equal(
    await notifyReady({ ...options, env: { NOTIFY_SOCKET: '/run/systemd/notify' } }),
    true
  );
  assert.equal(calls[0].program, '/bin/systemd-notify');
});

test('a socket systemd would not name is refused, and nothing is started', async () => {
  for (const socket of [
    '',
    '/',
    'run/systemd/notify',
    'vsock:2:1234',
    `/${'x'.repeat(107)}`,
    '/run/systemd/notify\n',
    '@\u0000name',
  ]) {
    assert.equal(notifySocket({ NOTIFY_SOCKET: socket }), null, JSON.stringify(socket));
    const { calls, errors, options } = harness();
    assert.equal(await notifyReady({ ...options, env: { NOTIFY_SOCKET: socket } }), false);
    assert.deepEqual(calls, []);
    assert.match(errors[0], /NOTIFY_SOCKET is not a socket systemd names/);
  }
  assert.equal(notifySocket({ NOTIFY_SOCKET: `/${'x'.repeat(106)}` }), `/${'x'.repeat(106)}`);
});

test('a missing or failing systemd-notify is logged and answers false, never throws', async () => {
  const env = { NOTIFY_SOCKET: '/run/systemd/notify' };
  {
    const { calls, errors, options } = harness({ present: [] });
    assert.equal(await notifyReady({ ...options, env }), false);
    assert.deepEqual(calls, []);
    assert.match(errors[0], /systemd-notify was not found .* Type=simple in a drop-in/);
  }
  {
    const { errors, options } = harness({ fail: Object.assign(new Error('x'), { code: 1 }) });
    assert.equal(await notifyReady({ ...options, env }), false);
    assert.match(errors[0], /systemd-notify --ready failed \(1\)/);
  }
  {
    const { errors, options } = harness({
      throws: Object.assign(new Error('x'), { code: 'EAGAIN' }),
    });
    assert.equal(await notifyReady({ ...options, env }), false);
    assert.match(errors[0], /could not be started \(EAGAIN\)/);
  }
});

test('the unit waits for that message, and the server sends it once it serves', () => {
  const unit = fs.readFileSync(new URL('../deploy/uptime-goblin.service', import.meta.url), 'utf8');
  for (const line of ['Type=notify', 'NotifyAccess=all', 'TimeoutStartSec=infinity'])
    assert.match(unit, new RegExp(`^${line}$`, 'm'));
  // The sandbox lets systemd-notify reach the socket.
  assert.match(unit, /^RestrictAddressFamilies=.*\bAF_UNIX\b/m);
  const server = fs.readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
  const listened = server.indexOf('listening = app.listen();'),
    ready = server.indexOf('await notifyReady();');
  assert.ok(
    listened > 0 && ready > listened,
    'READY=1 follows the listen that writes run/status.json'
  );
});
