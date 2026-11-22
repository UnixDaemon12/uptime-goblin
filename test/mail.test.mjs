import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { createApp } from '../server.mjs';
import { ConfigStore, validateEmail } from '../lib/config.mjs';
import { defaults, emailDefaults, publicConfig } from '../lib/catalog.mjs';
import nodemailer from 'nodemailer';
import { EmailNotifier, mailMessage } from '../lib/mail.mjs';
import { configureDestinations } from '../lib/destinations.mjs';

// SMTP hosts are checked against the destination policy; resolve them instantly.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
// Delivery starts after an asynchronous destination check, so wait for it.
const until = async condition => {
  for (let i = 0; i < 200 && !condition(); i++) await new Promise(r => setImmediate(r));
  assert.ok(condition(), 'condition was not reached');
};

const settings = () => ({
  ...emailDefaults(),
  enabled: true,
  from: 'sender@example.test',
  to: 'recipient@example.test',
  password: 'private-mail-fixture',
});
const event = {
  name: 'Test source',
  kind: 'firing',
  message: 'CPU is above its threshold',
  time: 1800000000000,
};
const accepted = () => ({ accepted: ['recipient@example.test'], rejected: [] });
const temp = t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-mail-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
};
async function appFor(t, options = {}) {
  const directory = temp(t),
    password = options.password ?? 'orbit-fixture';
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    password,
    allowedHosts: '',
    webhook: '',
    port: 0,
    startScheduler: false,
    mailTransportFactory: () => {
      throw new Error('Unexpected mail attempt');
    },
    ...options,
  });
  const address = await app.listen();
  t.after(() => app.close());
  const base = `http://127.0.0.1:${address.port}`;
  const call = async (route, method = 'GET', value, headers = {}) => {
    const res = await fetch(base + route, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: value === undefined ? undefined : JSON.stringify(value),
    });
    return { status: res.status, headers: res.headers, body: await res.json() };
  };
  return { app, directory, call, base };
}

// Test-only key and self-signed certificate for 127.0.0.1 and localhost (valid 2020-2120).
const testKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghuGBHo0qfEiG0qZ1
EsibliVvmhsX4HOqrbKWT9I84NihRANCAAQFjmoJU3qtkYtb00on5KP9bpoFlf8H
xhoJwnjJau0QU348mW4qa6XxYIbHzJJy0vW0NNfzq0a0tFCNjbJPs0L6
-----END PRIVATE KEY-----
`;
const testCert = `-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUZjM1lW7gob7f6mZeyEs5LrM/JI0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPT3JiaXQgdGVzdCBTTVRQMCAXDTIwMDEwMTAwMDAwMFoYDzIx
MjAwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9PcmJpdCB0ZXN0IFNNVFAwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQFjmoJU3qtkYtb00on5KP9bpoFlf8HxhoJwnjJ
au0QU348mW4qa6XxYIbHzJJy0vW0NNfzq0a0tFCNjbJPs0L6o28wbTAdBgNVHQ4E
FgQUJ8Me3qSp90BFQ89KOn3yz1GK2rwwHwYDVR0jBBgwFoAUJ8Me3qSp90BFQ89K
On3yz1GK2rwwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh
bGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIhAIuTWtjk3wtDnvEzcRn9MX04ahwYWDFo
Qj8kCcYZv68YAiB252dfaXIjquMafoDOouciNR0KkHAS4Px0N9PvCxSpXA==
-----END CERTIFICATE-----
`;
// The real nodemailer transport with Uptime Goblin's options, trusting only the test certificate.
const trustingTransport = options =>
  nodemailer.createTransport({ ...options, tls: { ...options.tls, ca: testCert } });
const allowLoopback = t => {
  configureDestinations({ allowLoopback: true });
  t.after(() =>
    configureDestinations({ allowLoopback: false, lookup: async () => [{ address: '192.0.2.1' }] })
  );
};
// A minimal SMTP server on 127.0.0.1: implicit TLS by default, plain TCP with secure: false.
// onConnection replaces the SMTP dialogue for connection-level tests.
async function smtpServer(
  t,
  { secure = true, rcpt = '250 OK', onConnection, host = '127.0.0.1' } = {}
) {
  const received = [],
    sockets = new Set();
  let connections = 0;
  const handle = socket => {
    connections++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    if (onConnection) return onConnection(socket);
    const reply = line => socket.write(line + '\r\n');
    let buffer = '',
      data = null;
    reply('220 orbit-test ESMTP');
    socket.on('data', chunk => {
      buffer += chunk;
      for (let end; (end = buffer.indexOf('\r\n')) >= 0; ) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (data !== null) {
          if (line !== '.') data += line + '\n';
          else {
            received.push(data);
            data = null;
            reply('250 OK queued');
          }
        } else if (/^EHLO/i.test(line)) reply('250-orbit-test\r\n250 AUTH PLAIN');
        else if (/^AUTH/i.test(line)) reply('235 Authenticated');
        else if (/^RCPT/i.test(line)) reply(rcpt);
        else if (/^DATA/i.test(line)) {
          data = '';
          reply('354 Go ahead');
        } else if (/^QUIT/i.test(line)) {
          reply('221 Bye');
          socket.end();
        } else reply('250 OK');
      }
    });
  };
  const server = secure
    ? tls.createServer({ key: testKey, cert: testCert }, handle)
    : net.createServer(handle);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    return new Promise(resolve => server.close(resolve));
  });
  return {
    port: server.address().port,
    received,
    get connections() {
      return connections;
    },
  };
}
const smtpSettings = (server, secure = true) => ({
  ...settings(),
  host: '127.0.0.1',
  port: server.port,
  secure,
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('email defaults are disabled and older configuration gains safe defaults', t => {
  const directory = temp(t),
    old = defaults();
  delete old.email;
  fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify(old));
  const config = new ConfigStore(directory);
  assert.deepEqual(config.value.email, emailDefaults());
  assert.equal(config.value.email.enabled, false);
});

test('email settings preserve blank passwords, redact responses and persist privately', async t => {
  const { app, directory, call } = await appFor(t);
  assert.equal((await call('/api/settings', 'PATCH', { email: settings() })).status, 200);
  assert.equal(
    (await call('/api/settings', 'PATCH', { email: { password: '', to: 'other@example.test' } }))
      .status,
    200
  );
  assert.equal(app.config.value.email.password, settings().password);
  const dashboard = await call('/api/dashboard');
  assert.equal(dashboard.body.config.email.passwordConfigured, true);
  assert.equal(dashboard.body.config.email.password, undefined);
  assert.ok(!JSON.stringify(dashboard.body).includes(settings().password));
  assert.equal(new ConfigStore(directory).value.email.password, settings().password);
  assert.equal(fs.statSync(path.join(directory, 'config.json')).mode & 0o777, 0o600);
  assert.equal(publicConfig({ ...defaults(), email: settings() }).email.password, undefined);
});

test('email validation rejects header injection and incomplete enabling without echoing secrets', () => {
  for (const input of [
    { from: 'sender@example.test\r\nBcc: victim@example.test' },
    { to: 'a@example.test,b@example.test' },
    { host: 'smtp://user:private-mail-fixture@example.test' },
    { host: 'host/path' },
    { port: 0 },
    { port: 65536 },
    { secure: 'false' },
    { enabled: 'true' },
    { password: 'private-mail-fixture\nX' },
    { clearPassword: 'true' },
    [],
  ]) {
    assert.throws(
      () => validateEmail(input),
      error => !error.message.includes('private-mail-fixture')
    );
  }
  assert.throws(() => validateEmail({ enabled: true }), /sender, recipient and app password/);
  assert.equal(validateEmail({ password: 'abcd efgh ijkl mnop' }).password, 'abcdefghijklmnop');
  assert.equal(
    validateEmail({ host: 'smtp.example.test', password: 'keep spaces' }).password,
    'keep spaces'
  );
});

test('changing SMTP identity cannot forward an existing password to another endpoint', () => {
  const old = settings();
  assert.throws(() => validateEmail({ host: 'other.example.test' }, old), /app password/);
  assert.equal(old.password, settings().password);
  // Even with alerts off, a new server needs the password re-entered or explicitly cleared.
  assert.throws(
    () => validateEmail({ enabled: false, host: 'other.example.test' }, old),
    /app password/
  );
  const next = validateEmail(
    { enabled: false, host: 'other.example.test', clearPassword: true },
    old
  );
  assert.equal(next.password, '');
  assert.equal(
    validateEmail({ host: 'other.example.test', password: 'replacement' }, old).password,
    'replacement'
  );
  assert.equal(validateEmail({ enabled: false, clearPassword: true }, old).password, '');
  assert.throws(() => validateEmail({ clearPassword: true }, old), /Turn off email alerts/);
});

test('message rendering escapes source content, bounds subjects and restricts content access', () => {
  const message = mailMessage(settings(), {
    ...event,
    name: '<img src=x onerror=alert(1)>\r\nBcc: no@example.test',
    message: '<script>bad()</script> & "quoted"',
  });
  assert.ok(!message.html.includes('<script>'));
  assert.match(message.html, /&lt;script&gt;/);
  assert.ok(!/[\r\n]/.test(message.subject));
  assert.equal(message.disableFileAccess, true);
  assert.equal(message.disableUrlAccess, true);
  assert.deepEqual(message.envelope.to, ['recipient@example.test']);
  assert.equal(message.attachments, undefined);
  assert.match(mailMessage(settings(), { ...event, kind: 'resolved' }).subject, /Recovered/);
});

test('a bidi override in an upstream label does not reach the email text', () => {
  // A mountpoint or device label from a source's API, as an alert message carries it: an RLO
  // would show "/data/report\u202egpj.exe" as "/data/reportexe.jpg", and C1 controls, NEL and the
  // line and paragraph separators could start a line of their own in some clients.
  const label = '/data/report\u202egpj.exe\u2066x\u2069\u0085NEL\u2028LS\u2029PS\u009bC1';
  for (const message of [
    mailMessage(settings(), { ...event, name: `Host\u202e1`, message: `${label} is 99 %` }),
    mailMessage(settings(), {
      digest: [{ ...event, name: `Host\u202e1`, message: `${label} is 99 %` }],
      time: event.time,
    }),
  ]) {
    for (const part of [message.subject, message.text, message.html])
      assert.doesNotMatch(
        part,
        /[\u0080-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/,
        JSON.stringify(part)
      );
    assert.match(message.text, /\/data\/reportgpj\.exex NEL LS PS C1 is 99 %/);
    assert.match(message.html, /Host1/);
  }
});

test('a source name saved with direction marks keeps them in email, as config keeps them', () => {
  // lib/config.mjs accepts the marks (U+061C, U+200E, U+200F) in a name: a right-to-left name
  // may need one to show as saved ("2" after the Hebrew here), and a mark cannot turn letters
  // round. Email text removed them all the same, so the name the admin saved read differently in
  // every email. A label from a source's API carries none (lib/collectors.mjs removes them).
  for (const name of ['\u05e9\u05e8\u05ea 2\u200f', 'Host\u061c1', 'a\u200eb']) {
    for (const message of [
      mailMessage(settings(), { ...event, name, message: `${name} is unavailable` }),
      mailMessage(settings(), {
        digest: [{ ...event, name, message: `${name} is unavailable` }],
        time: event.time,
      }),
    ]) {
      assert.ok(message.subject.includes(name), JSON.stringify(message.subject));
      assert.ok(message.text.includes(`${name} is unavailable`), JSON.stringify(message.text));
      assert.ok(message.html.includes(name), JSON.stringify(message.html));
    }
  }
});

// Digest lines carry upstream-supplied labels (storage, device and mountpoint names).
test('digest emails escape and flatten source content like single alerts', () => {
  const link = '<a href="https://phish.example/login">Proxmox storage</a>';
  const message = mailMessage(settings(), {
    digest: [
      { ...event, name: `${link}\r\nBcc: no@example.test`, message: `Used ${link} is 'high'` },
      { ...event, kind: 'resolved', message: '<script>bad()</script>\r\nX-Injected: 1' },
    ],
    time: event.time,
  });
  assert.match(message.subject, /^\[Uptime Goblin\] 1 alert, 1 recovered · /);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(message.subject));
  for (const raw of ['<a href', '<script', '"https:', "'high'"])
    assert.ok(!message.html.includes(raw), raw);
  assert.match(message.html, /&lt;a href=&quot;https:\/\/phish\.example\/login&quot;&gt;/);
  assert.match(message.html, /&#39;high&#39;/);
  assert.match(message.html, /&lt;script&gt;bad\(\)&lt;\/script&gt;/);
  // Line breaks inside a source's content cannot start a new line in the text body.
  assert.ok(!message.text.includes('\r'));
  assert.ok(!/^(Bcc|X-Injected):/m.test(message.text));
  assert.equal(
    message.text.split('\n').filter(line => /^(Alert|Recovered) — /.test(line)).length,
    2
  );
  assert.equal(message.disableFileAccess, true);
  assert.equal(message.disableUrlAccess, true);
});

test('SMTP transport always verifies TLS and only confirms accepted recipients', async () => {
  for (const secure of [true, false]) {
    const config = { ...settings(), secure, port: secure ? 465 : 587 };
    let options,
      closes = 0;
    const notifier = new EmailNotifier({
      getSettings: () => config,
      transportFactory: o => {
        options = o;
        return {
          sendMail: async () => accepted(),
          close() {
            closes++;
          },
        };
      },
    });
    assert.equal((await notifier.send(event)).accepted, true);
    assert.equal(options.tls.rejectUnauthorized, true);
    assert.equal(options.tls.minVersion, 'TLSv1.2');
    assert.equal(options.requireTLS, !secure);
    assert.equal(options.ignoreTLS, false);
    assert.equal(options.opportunisticTLS, false);
    assert.equal(options.disableFileAccess, true);
    assert.equal(options.disableUrlAccess, true);
    assert.equal(options.maxRecipients, 1);
    assert.equal(options.maxConnections, 1);
    assert.equal(options.auth.pass, config.password);
    assert.equal(options.logger, false);
    assert.equal(options.debug, false);
    assert.equal(options.transactionLog, false);
    assert.equal(options.tls.servername, config.host);
    // Uptime Goblin does not retry; the pool must not silently reconnect and resend either.
    assert.equal(options.maxRequeues, 0);
    assert.ok(closes);
    await notifier.close();
  }
  const notifier = new EmailNotifier({
    getSettings: settings,
    transportFactory: () => ({
      sendMail: async () => ({ accepted: [], rejected: ['recipient@example.test'] }),
      close() {},
    }),
  });
  await assert.rejects(notifier.send(event), /did not accept/);
  assert.equal(notifier.status().lastAccepted, null);
  await notifier.close();
});

test('automatic email is disabled by default while an explicit test can use saved credentials', async () => {
  let calls = 0;
  const notifier = new EmailNotifier({
    getSettings: () => ({ ...settings(), enabled: false }),
    transportFactory: () => ({
      sendMail: async () => {
        calls++;
        return accepted();
      },
      close() {},
    }),
  });
  assert.deepEqual(await notifier.send(event), { skipped: true });
  assert.equal(calls, 0);
  assert.equal((await notifier.send(event, { test: true })).accepted, true);
  assert.equal(calls, 1);
  assert.equal(notifier.status().enabled, false);
  assert.equal(notifier.status().state, 'disabled');
  await notifier.close();
});

test('email queue is bounded and sends only one message at a time', async () => {
  const releases = [];
  let active = 0,
    maxActive = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    maxPending: 2,
    transportFactory: () => ({
      sendMail: () => {
        active++;
        maxActive = Math.max(maxActive, active);
        return new Promise(resolve =>
          releases.push(() => {
            active--;
            resolve(accepted());
          })
        );
      },
      close() {},
    }),
  });
  const first = notifier.send(event);
  await until(() => releases.length === 1);
  const second = notifier.send(event);
  await assert.rejects(notifier.send(event), /queue is full/);
  assert.equal(notifier.status().pending, 2);
  releases.shift()();
  await first;
  await until(() => releases.length === 1);
  releases.shift()();
  await second;
  assert.equal(maxActive, 1);
  assert.equal(notifier.status().failedCount, 1);
  await notifier.close();
});

test('overall SMTP deadline closes a stuck transport and reports acceptance as unknown', async () => {
  let closes = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    timeoutMs: 10,
    transportFactory: () => ({
      sendMail: () => new Promise(() => {}),
      close() {
        closes++;
      },
    }),
  });
  await assert.rejects(notifier.send(event), /acceptance is unknown/);
  assert.ok(closes);
  assert.equal(notifier.status().pending, 0);
  assert.equal(notifier.status().lastAccepted, null);
  await notifier.close();
});

test('changing settings cancels active delivery and drops queued messages', async () => {
  let calls = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    transportFactory: () => ({
      sendMail: () => {
        calls++;
        return new Promise(() => {});
      },
      close() {},
    }),
  });
  const first = notifier.send(event);
  const failed = assert.rejects(first, /settings changed/);
  await until(() => calls === 1);
  const second = notifier.send(event);
  notifier.reconfigure();
  await failed;
  assert.deepEqual(await second, { skipped: true });
  assert.equal(calls, 1);
  assert.equal(notifier.status().lastError, null);
  await notifier.close();
});

test('test email requires Uptime Goblin authentication, saved settings, CSRF checks and rate limiting', async t => {
  let calls = 0;
  const { app, call } = await appFor(t, {
    mailTransportFactory: () => ({
      sendMail: async () => {
        calls++;
        return accepted();
      },
      close() {},
    }),
  });
  assert.equal((await call('/api/email/test', 'POST', {}, { Authorization: '' })).status, 401);
  assert.equal((await call('/api/email/test', 'POST', {})).status, 400);
  await call('/api/settings', 'PATCH', { email: { ...settings(), enabled: false } });
  const before = JSON.stringify(app.config.value);
  assert.equal(
    (await call('/api/email/test', 'POST', {}, { Origin: 'https://elsewhere.example' })).status,
    403
  );
  assert.equal(
    (await call('/api/email/test', 'POST', { password: 'private-mail-fixture' })).status,
    400
  );
  const result = await call('/api/email/test', 'POST', {});
  assert.equal(result.status, 200);
  assert.equal(result.body.accepted, true);
  assert.match(result.body.message, /accepted/);
  assert.equal(JSON.stringify(app.config.value), before);
  assert.deepEqual(app.dashboard().events, []);
  const again = await call('/api/email/test', 'POST', {});
  assert.equal(again.status, 429);
  assert.ok(Number(again.headers.get('retry-after')) > 0);
  assert.equal(calls, 1);
});

test('loopback without a credential cannot send test mail (no passwordless preview any more)', async t => {
  let sent = 0;
  const { call, base } = await appFor(t, {
    mailTransportFactory: () => ({
      sendMail: async () => {
        sent++;
        return { accepted: ['to@example.test'], rejected: [] };
      },
    }),
  });
  await call('/api/settings', 'PATCH', { email: { ...settings(), enabled: false } });
  const bare = await fetch(base + '/api/email/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1' },
    body: '{}',
  });
  assert.equal(bare.status, 401);
  assert.equal((await bare.json()).code, 'signin_required');
  assert.equal(sent, 0);
});

test('SMTP errors never expose credentials or raw provider responses', async t => {
  const { call } = await appFor(t, {
    mailTransportFactory: () => ({
      sendMail: async () => {
        throw Object.assign(new Error('AUTH private-mail-fixture server response'), {
          code: 'EAUTH',
        });
      },
      close() {},
    }),
  });
  await call('/api/settings', 'PATCH', { email: settings() });
  const result = await call('/api/email/test', 'POST', {});
  assert.equal(result.status, 422);
  assert.match(result.body.error, /sign-in failed/);
  assert.ok(!JSON.stringify(result).includes('private-mail-fixture'));
  const dashboard = await call('/api/dashboard');
  assert.ok(!JSON.stringify(dashboard).includes('private-mail-fixture'));
  assert.equal(dashboard.body.notifications.email.state, 'error');
  assert.equal(dashboard.body.notifications.email.lastAccepted, null);
});

/**
 * A clock for the delivery service ({now, wall, setTimeout, clearTimeout}, as lib/jobs.mjs's
 * systemClock): time moves only through advance(ms), which runs the timers due on the way.
 */
function fakeClock(start = Date.now()) {
  let elapsed = 0,
    sequence = 0;
  const timers = new Map();
  return {
    now: () => elapsed,
    wall: () => start + elapsed,
    setTimeout(fn, ms) {
      const id = ++sequence;
      timers.set(id, { at: elapsed + Math.max(0, Number(ms) || 0), fn });
      return id;
    },
    clearTimeout: id => void timers.delete(id),
    async advance(ms) {
      const target = elapsed + ms;
      for (;;) {
        let next = null;
        for (const [id, timer] of timers)
          if (timer.at <= target && (!next || timer.at < next.timer.at)) next = { id, timer };
        if (!next) break;
        timers.delete(next.id);
        elapsed = Math.max(elapsed, next.timer.at);
        next.timer.fn();
        await sleep(5);
      }
      elapsed = target;
      await sleep(5);
    },
  };
}

// 1.5 (delivery spec §8.3): the webhook's recovery waits behind its failing alert (order per
// alert), so the receiver sees the alert retried and never the recovery, while email, a
// separate channel, delivers both. On a fake clock, exactly three attempts happen.
test('alert and recovery emails work independently of a failing webhook', async t => {
  const messages = [];
  let value = 95;
  const webhooks = [];
  const receiver = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    webhooks.push(JSON.parse(body));
    res.writeHead(500);
    res.end();
  });
  await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => receiver.close(resolve)));
  const clock = fakeClock();
  const { app, call } = await appFor(t, {
    webhook: `http://127.0.0.1:${receiver.address().port}`,
    collector: async () => [{ key: 'cpu', label: 'CPU', value, unit: '%' }],
    mailTransportFactory: () => ({
      sendMail: async message => {
        messages.push(message);
        return accepted();
      },
      close() {},
    }),
    // rng 1, the top of the backoff's U(0.5, 1): every retry waits exactly 1 s. With the jitter
    // (0.5 to 1 s), two retries could fall in one fake second and make four attempts.
    delivery: { clock, rng: () => 1, policy: { baseMs: 1000, capMs: 1000 } },
  });
  t.mock.method(console, 'warn', () => {});
  await call('/api/settings', 'PATCH', {
    email: settings(),
    monitoring: { recoverySuccesses: 1, recoverySeconds: 0 },
  });
  await call('/api/services/linux', 'PATCH', {
    apiUrl: 'http://fixture.invalid',
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 0 }],
  });
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  await until(() => webhooks.length === 1);
  // Each retry waits 1 s on the fake clock from the moment the attempt before it failed, so
  // that failure is recorded (flushNotifications waits for the send in flight) before the clock
  // moves on: a slow answer would otherwise time the next retry from later in that second.
  for (const attempts of [2, 3]) {
    await clock.advance(1000);
    for (let i = 0; i < 400 && webhooks.length < attempts; i++)
      await new Promise(resolve => setTimeout(resolve, 5));
    await app.flushNotifications();
    assert.equal(webhooks.length, attempts);
  }
  value = 10;
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.equal(messages.length, 2);
  assert.match(messages[0].subject, /Alert/);
  assert.match(messages[1].subject, /Recovered/);
  assert.deepEqual(
    webhooks.map(e => e.kind),
    ['firing', 'firing', 'firing']
  );
  assert.ok(app.dashboard().notifications.webhook.lastError);
  assert.ok(app.dashboard().notifications.email.lastAccepted);
  assert.equal(app.dashboard().notifications.email.failedCount, 0);
});

test('webhook still delivers when email sign-in fails', async t => {
  const received = [];
  const receiver = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    received.push(JSON.parse(body));
    res.end('{}');
  });
  await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => receiver.close(resolve)));
  const { app, call } = await appFor(t, {
    webhook: `http://127.0.0.1:${receiver.address().port}`,
    collector: async () => [{ key: 'cpu', label: 'CPU', value: 95, unit: '%' }],
    mailTransportFactory: () => ({
      sendMail: async () => {
        throw Object.assign(new Error('secret'), { code: 'EAUTH' });
      },
      close() {},
    }),
  });
  await call('/api/settings', 'PATCH', {
    email: settings(),
    monitoring: { recoverySuccesses: 1, recoverySeconds: 0 },
  });
  await call('/api/services/linux', 'PATCH', {
    apiUrl: 'http://fixture.invalid',
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 0 }],
  });
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  // 1.5 (delivery spec D28): the refused sign-in pauses email, and the pause is told to the
  // webhook, the other channel, once (queued when the pause is recorded, so flushed again).
  await app.flushNotifications();
  assert.deepEqual(
    received.map(event => [event.service, event.rule, event.kind]),
    [
      ['linux', 'cpu', 'firing'],
      ['orbit', '__channel_email', 'firing'],
    ]
  );
  assert.match(received[1].message, /^Email notifications are paused: Email sign-in failed\./);
  assert.equal(app.dashboard().notifications.webhook.lastError, null);
  assert.equal(app.dashboard().notifications.email.failedCount, 1);
  assert.equal(app.dashboard().alerts.length, 1);
});

test('cancelling delivery also closes a pooled connection that is mid-conversation', async () => {
  const closed = [];
  let calls = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    transportFactory: () => ({
      transporter: {
        _connections: [
          { available: false, close: () => closed.push('busy') },
          { available: true, close: () => closed.push('idle') },
        ],
      },
      sendMail: () => {
        calls++;
        return new Promise(() => {});
      },
      close: () => closed.push('transport'),
    }),
  });
  const first = notifier.send(event);
  const failed = assert.rejects(first, /settings changed/);
  await until(() => calls === 1);
  notifier.reconfigure();
  await failed;
  assert.ok(closed.includes('busy'));
  await notifier.close();
});

test('SMTP hosts follow the outbound destination policy', async t => {
  t.after(() =>
    configureDestinations({ allowLoopback: false, lookup: async () => [{ address: '192.0.2.1' }] })
  );
  let calls = 0;
  for (const host of ['127.0.0.1', '169.254.169.254', 'localhost']) {
    configureDestinations({ allowLoopback: false });
    const notifier = new EmailNotifier({
      getSettings: () => ({ ...settings(), host }),
      transportFactory: () => {
        calls++;
        return { sendMail: async () => accepted(), close() {} };
      },
    });
    await assert.rejects(notifier.send(event), /SMTP server address is not allowed/);
    await notifier.close();
  }
  assert.equal(calls, 0);
  configureDestinations({ allowLoopback: true });
  const local = new EmailNotifier({
    getSettings: () => ({ ...settings(), host: '127.0.0.1' }),
    transportFactory: () => ({ sendMail: async () => accepted(), close() {} }),
  });
  assert.equal((await local.send(event)).accepted, true);
  await local.close();
});

test('a failed SMTP lookup stops before creating a transport and confirms nothing was sent', async t => {
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  configureDestinations({
    lookup: async () => {
      throw Object.assign(new Error('private DNS fixture detail'), { code: 'ENOTFOUND' });
    },
  });
  let transports = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    transportFactory: () => {
      transports++;
      return { sendMail: async () => accepted(), close() {} };
    },
  });
  t.after(() => notifier.close());
  await assert.rejects(
    notifier.send(event),
    error => /DNS.*Nothing was sent/.test(error.message) && !error.message.includes('private')
  );
  assert.equal(transports, 0);
  assert.equal(notifier.status().lastAccepted, null);
});

test('SMTP connects only to policy-checked IPs without a second DNS resolver', async t => {
  const server = await smtpServer(t);
  allowLoopback(t);
  // Nodemailer's raw DNS resolver disagrees with the checked OS/localhost addresses.
  // Every address in this fixture stays on loopback, including the wrong answer.
  let rawDnsCalls = 0;
  for (const family of [4, 6])
    t.mock.method(dns.Resolver.prototype, 'resolve' + family, (_host, callback) => {
      rawDnsCalls++;
      callback(null, family === 4 ? ['127.0.0.2'] : []);
    });
  const notifier = new EmailNotifier({
    getSettings: () => ({ ...smtpSettings(server), host: 'localhost' }),
    transportFactory: trustingTransport,
    timeoutMs: 2000,
  });
  t.after(() => notifier.close());
  assert.equal((await notifier.send(event)).accepted, true);
  assert.equal(rawDnsCalls, 0);
  assert.equal(server.received.length, 1);
});

test('SMTP falls back between checked addresses while verifying the original TLS hostname', async t => {
  let server;
  try {
    server = await smtpServer(t, { host: '::1' });
  } catch (error) {
    if (['EAFNOSUPPORT', 'EADDRNOTAVAIL'].includes(error.code))
      return t.skip('IPv6 loopback is unavailable');
    throw error;
  }
  allowLoopback(t);
  const notifier = new EmailNotifier({
    // The policy returns IPv4 first, but this fixture listens only on IPv6.
    getSettings: () => ({ ...smtpSettings(server), host: 'localhost' }),
    transportFactory: trustingTransport,
    timeoutMs: 2000,
  });
  t.after(() => notifier.close());
  assert.equal((await notifier.send(event)).accepted, true);
  assert.equal(server.received.length, 1);
});

function pendingSmtpConnections(t, addresses, timeoutMs = 20000) {
  configureDestinations({ lookup: async () => addresses.map(address => ({ address })) });
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  const attempts = [];
  let winner;
  t.mock.method(net, 'connect', options => {
    const socket = new net.Socket();
    attempts.push({ options, socket });
    return socket;
  });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const notifier = new EmailNotifier({
    getSettings: settings,
    timeoutMs,
    transportFactory: options => ({
      sendMail: () =>
        new Promise((resolve, reject) => {
          options.getSocket({}, (error, result) => {
            if (error) return reject(error);
            winner = result.connection;
            assert.equal(winner.isPaused(), true, 'the greeting waits for the mail transport');
            resolve(accepted());
          });
        }),
      close() {
        winner?.destroy();
      },
    }),
  });
  t.after(() => notifier.close());
  const delivery = notifier.send(event);
  // A failed assertion still cancels the pending delivery during cleanup.
  delivery.catch(() => {});
  return { attempts, notifier, delivery, winner: () => winner };
}

test('a fast failed SMTP fallback does not discard a slower viable first address', async t => {
  const { attempts, delivery, winner } = pendingSmtpConnections(t, ['192.0.2.1', '192.0.2.2']);
  await until(() => attempts.length === 1);
  t.mock.timers.tick(250);
  assert.equal(attempts.length, 2, 'a fallback starts while the first TCP handshake is pending');
  attempts[1].socket.emit(
    'error',
    Object.assign(new Error('fixture refusal'), { code: 'ECONNREFUSED' })
  );
  t.mock.timers.tick(850);
  assert.equal(attempts[0].socket.destroyed, false, 'the earlier address keeps its full budget');
  attempts[0].socket.emit('connect');
  assert.equal((await delivery).accepted, true);
  assert.equal(winner(), attempts[0].socket);
  assert.equal(attempts[1].socket.destroyed, true);
});

test('four stalled SMTP addresses do not starve a working fifth approved address', async t => {
  const addresses = Array.from({ length: 5 }, (_, index) => `192.0.2.${index + 1}`);
  const { attempts, delivery, winner } = pendingSmtpConnections(t, addresses);
  await until(() => attempts.length === 1);
  for (let i = 0; i < 4; i++) t.mock.timers.tick(250);
  assert.equal(attempts.length, 5);
  assert.deepEqual(
    attempts.map(attempt => attempt.options.host),
    addresses
  );
  for (const { options } of attempts) {
    assert.equal(options.family, 4);
    assert.equal(options.autoSelectFamily, false);
  }
  attempts[4].socket.emit('connect');
  assert.equal((await delivery).accepted, true);
  assert.equal(winner(), attempts[4].socket);
  for (const { socket } of attempts.slice(0, 4)) {
    assert.equal(socket.destroyed, true);
    assert.equal(socket.listenerCount('connect'), 0);
    socket.emit('connect');
    socket.emit('error', new Error('late losing attempt'));
  }
  assert.equal(winner(), attempts[4].socket, 'a late loser cannot replace the winner');
});

test('SMTP attempts alternate approved families without filtering usable interfaces', async t => {
  const { attempts, notifier, delivery } = pendingSmtpConnections(t, [
    '192.0.2.1',
    '192.0.2.2',
    '2001:db8::1',
    '2001:db8::2',
  ]);
  await until(() => attempts.length === 1);
  for (let i = 0; i < 3; i++) t.mock.timers.tick(250);
  assert.deepEqual(
    attempts.map(attempt => attempt.options.host),
    ['192.0.2.1', '2001:db8::1', '192.0.2.2', '2001:db8::2']
  );
  notifier.reconfigure();
  await assert.rejects(delivery, /Nothing was sent/);
  assert.ok(attempts.every(({ socket }) => socket.destroyed));
});

test('all pending SMTP attempts share one eight-second connection deadline', async t => {
  const { attempts, delivery } = pendingSmtpConnections(
    t,
    Array.from({ length: 40 }, (_, index) => `192.0.2.${index + 1}`)
  );
  await until(() => attempts.length === 1);
  for (let i = 0; i < 31; i++) t.mock.timers.tick(250);
  assert.equal(attempts.length, 32, 'fan-out stays bounded while attempts are pending');
  t.mock.timers.tick(250);
  await assert.rejects(delivery, /connection timed out.*Nothing was sent/);
  assert.equal(attempts.length, 32);
  assert.ok(attempts.every(({ socket }) => socket.destroyed && !socket.listenerCount('connect')));
});

test('checked SMTP addresses do not replace TLS certificate hostname verification', async t => {
  const server = await smtpServer(t);
  allowLoopback(t);
  configureDestinations({ lookup: async () => [{ address: '127.0.0.1' }] });
  const notifier = new EmailNotifier({
    // The trusted certificate names localhost, not this requested hostname.
    getSettings: () => ({ ...smtpSettings(server), host: 'smtp.example.test' }),
    transportFactory: trustingTransport,
    timeoutMs: 2000,
  });
  t.after(() => notifier.close());
  await assert.rejects(notifier.send(event), /not confirmed/);
  assert.equal(server.received.length, 0);
});

test('a checked plain SMTP socket never authenticates when STARTTLS is refused', async t => {
  const commands = [];
  const server = await smtpServer(t, {
    secure: false,
    onConnection: socket => {
      socket.write('220 orbit-test ESMTP\r\n');
      let buffer = '';
      socket.on('data', chunk => {
        buffer += chunk;
        for (let end; (end = buffer.indexOf('\r\n')) >= 0; ) {
          const line = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          commands.push(line.split(' ')[0]);
          socket.write(
            /^EHLO/.test(line) ? '250-orbit-test\r\n250 AUTH PLAIN\r\n' : '502 TLS unavailable\r\n'
          );
        }
      });
    },
  });
  allowLoopback(t);
  const notifier = new EmailNotifier({ getSettings: () => smtpSettings(server, false) });
  t.after(() => notifier.close());
  await assert.rejects(notifier.send(event), /not confirmed/);
  assert.ok(commands.includes('STARTTLS'));
  assert.ok(!commands.some(command => ['AUTH', 'MAIL', 'RCPT', 'DATA'].includes(command)));
});

test('cancellation and deadlines close an SMTP socket before the pool owns it', async t => {
  for (const mode of ['cancel', 'overall deadline', 'connection deadline']) {
    await t.test(mode, async t => {
      let socket;
      t.mock.method(net, 'connect', () => (socket = new net.Socket()));
      t.mock.timers.enable({ apis: ['setTimeout'] });
      const notifier = new EmailNotifier({
        getSettings: settings,
        timeoutMs: mode === 'overall deadline' ? 1000 : 20000,
      });
      t.after(() => notifier.close());
      const outcome = notifier.send(event).catch(error => error);
      await until(() => Boolean(socket));
      if (mode === 'cancel') notifier.reconfigure();
      else t.mock.timers.tick(mode === 'connection deadline' ? 8000 : 1000);
      const error = await outcome;
      assert.match(error.message, /Nothing was sent/);
      assert.equal(socket.destroyed, true);
      assert.equal(socket.listenerCount('connect'), 0);
      assert.equal(notifier.status().lastAccepted, null);
      assert.equal(notifier.status().pending, 0);
      // Late callbacks from a cancelled connection cannot hand it to the pool or throw.
      socket.emit('connect');
      socket.emit('error', new Error('late fixture teardown'));
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(socket.destroyed, true);
    });
  }
});

test('a settings change during the SMTP address check sends nothing with the old settings', async t => {
  let release,
    transports = 0;
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  configureDestinations({
    lookup: () => new Promise(resolve => (release = () => resolve([{ address: '192.0.2.1' }]))),
  });
  const notifier = new EmailNotifier({
    getSettings: settings,
    transportFactory: () => {
      transports++;
      return { sendMail: async () => accepted(), close() {} };
    },
  });
  const pending = notifier.send(event);
  await until(() => typeof release === 'function');
  notifier.reconfigure();
  release();
  const outcome = await pending.catch(error => error);
  assert.ok(outcome.skipped || /Nothing was sent/.test(outcome.message));
  assert.equal(transports, 0);
  await notifier.close();
});

// Cancelling a delivery closes busy pool connections through nodemailer's pool internals;
// fail loudly if an upgrade changes that shape rather than silently losing the fix.
test('the nodemailer pool still exposes the connection list that cancellation closes', () => {
  const transport = nodemailer.createTransport({ pool: true, host: '192.0.2.1', port: 465 });
  try {
    assert.ok(Array.isArray(transport.transporter._connections));
  } finally {
    transport.close();
  }
});

test('alerts arriving together are sent as one email; a lone alert is sent as before', async t => {
  const sent = [];
  const { app } = await appFor(t, {
    emailBatchMs: 60000,
    collector: async service => {
      throw new Error(`${service.id} is down`);
    },
    mailTransportFactory: () => ({
      sendMail: async message => {
        sent.push(message);
        return accepted();
      },
      close() {},
    }),
  });
  app.config.updateGlobal({
    monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    email: { ...settings(), host: 'smtp.example.test' },
  });
  for (const id of ['plex', 'sonarr', 'radarr'])
    app.config.update(id, { apiUrl: `https://${id}.example.test`, apiKey: 'fixture-key' });
  for (const id of ['plex', 'sonarr', 'radarr']) await app.poll(app.config.get(id));
  await app.flushNotifications();
  assert.equal(sent.length, 1);
  assert.match(sent[0].subject, /^\[Uptime Goblin\] 3 alerts · Plex, Sonarr, Radarr$/);
  for (const name of ['Plex', 'Sonarr', 'Radarr'])
    assert.match(sent[0].text, new RegExp(`Alert — ${name}: Source is unavailable`));
  assert.match(sent[0].html, /<li><strong>Alert — Plex<\/strong>/);
  app.config.update('tautulli', { apiUrl: 'https://tautulli.example.test', apiKey: 'fixture-key' });
  await app.poll(app.config.get('tautulli'));
  await app.flushNotifications();
  assert.equal(sent.length, 2);
  assert.match(sent[1].subject, /Connection check · Tautulli/);
});

test('a burst spread over longer than the quiet period is still one email, capped in total', async t => {
  const sent = [];
  const { app } = await appFor(t, {
    emailBatchMs: 500,
    collector: async service => {
      throw new Error(`${service.id} is down`);
    },
    mailTransportFactory: () => ({
      sendMail: async message => {
        sent.push(message);
        return accepted();
      },
      close() {},
    }),
  });
  app.config.updateGlobal({
    monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    email: { ...settings(), host: 'smtp.example.test' },
  });
  const ids = ['plex', 'sonarr', 'radarr', 'tautulli'];
  for (const id of ids)
    app.config.update(id, { apiUrl: `https://${id}.example.test`, apiKey: 'fixture-key' });
  // Each alert arrives 250 ms after the previous one: 750 ms in total, beyond any fixed window.
  // (1.5: a poll now also saves its notification rows, so the gap keeps 250 ms of margin below
  // the 500 ms quiet period even on a busy machine.)
  for (const id of ids) {
    await app.poll(app.config.get(id));
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  await new Promise(resolve => setTimeout(resolve, 1600));
  await app.flushNotifications();
  // The cap (3 x 500 ms) may split a very long burst, but never into one email per source.
  assert.ok(sent.length >= 1 && sent.length <= 2, String(sent.length));
  const text = sent.map(message => message.text).join('\n');
  for (const name of ['Plex', 'Sonarr', 'Radarr', 'Tautulli']) assert.match(text, new RegExp(name));
});

test('alerts batched just before shutdown are still sent', async t => {
  const sent = [];
  const directory = temp(t);
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    password: 'orbit-fixture',
    port: 0,
    startScheduler: false,
    emailBatchMs: 60000,
    collector: async () => {
      throw new Error('down');
    },
    mailTransportFactory: () => ({
      sendMail: async message => {
        sent.push(message);
        return accepted();
      },
      close() {},
    }),
  });
  await app.listen();
  app.config.updateGlobal({
    monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    email: { ...settings(), host: 'smtp.example.test' },
  });
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  await app.poll(app.config.get('plex'));
  assert.equal(sent.length, 0);
  await app.close();
  assert.equal(sent.length, 1);
  assert.match(sent[0].subject, /Connection check · Plex/);
});

test('an IP-address SMTP host delivers over TLS that is still verified', async t => {
  const server = await smtpServer(t);
  allowLoopback(t);
  let options;
  const notifier = new EmailNotifier({
    getSettings: () => smtpSettings(server),
    transportFactory: o => trustingTransport((options = o)),
  });
  t.after(() => notifier.close());
  // Node refuses an IP address as the TLS server name, so none may be set for one.
  assert.equal((await notifier.send(event)).accepted, true);
  assert.equal(options.tls.servername, undefined);
  assert.equal(server.received.length, 1);
  // The certificate is still checked against the IP address and a trusted CA.
  const untrusted = new EmailNotifier({ getSettings: () => smtpSettings(server) });
  t.after(() => untrusted.close());
  await assert.rejects(untrusted.send(event), /not confirmed/);
  assert.equal(server.received.length, 1);
});

test('a recipient the mail server rejects is reported as a recipient problem', async t => {
  const server = await smtpServer(t, { rcpt: '550 5.1.1 private-mailbox-detail unknown' });
  allowLoopback(t);
  const notifier = new EmailNotifier({
    getSettings: () => smtpSettings(server),
    transportFactory: trustingTransport,
  });
  t.after(() => notifier.close());
  const error = await notifier.send(event).catch(e => e);
  assert.match(error.message, /did not accept the recipient/);
  assert.ok(!error.message.includes('private-mailbox-detail'));
  assert.equal(server.received.length, 0);
});

test('delivery errors say whether the message could have been accepted', async () => {
  for (const [failure, expected] of [
    [{ code: 'EENVELOPE', command: 'RCPT TO' }, /did not accept the recipient/],
    [{ code: 'EENVELOPE', command: 'MAIL FROM' }, /did not accept the sender/],
    // Timeouts before any mail command: nothing can have been accepted.
    [{ code: 'ETIMEDOUT', command: 'CONN', message: 'Connection timeout' }, /Nothing was sent/],
    [
      { code: 'ETIMEDOUT', command: 'CONN', message: 'Greeting never received' },
      /Nothing was sent/,
    ],
    // An idle socket timeout can happen after the message was transmitted.
    [{ code: 'ETIMEDOUT', command: 'CONN', message: 'Timeout' }, /acceptance is unknown/],
  ]) {
    const notifier = new EmailNotifier({
      getSettings: settings,
      transportFactory: () => ({
        sendMail: async () => {
          throw Object.assign(new Error(failure.message ?? 'raw 5xx response'), failure);
        },
        close() {},
      }),
    });
    const error = await notifier.send(event).catch(e => e);
    assert.match(error.message, expected, JSON.stringify(failure));
    await notifier.close();
  }
});

test('a server that closes before its greeting is tried once, not reconnected until the deadline', async t => {
  const server = await smtpServer(t, { secure: false, onConnection: socket => socket.end() });
  allowLoopback(t);
  const notifier = new EmailNotifier({
    getSettings: () => smtpSettings(server, false),
    timeoutMs: 2000,
  });
  t.after(() => notifier.close());
  const started = performance.now();
  const error = await notifier.send(event).catch(e => e);
  assert.ok(performance.now() - started < 1500, 'failed only at the deadline');
  assert.doesNotMatch(error.message, /acceptance is unknown/);
  await sleep(300);
  assert.equal(server.connections, 1);
});

test('an SMTP server that never ends its greeting or reply is dropped at the reply limit and reported with fixed text', async t => {
  allowLoopback(t);
  // One endless greeting line, or endless continuation lines of one reply: a broken server, or
  // a man in the middle before STARTTLS. Uptime Goblin sets the reply limit itself (64 KiB) instead of
  // relying on nodemailer's internal default, which an update could change or remove.
  for (const shape of ['one line', 'continuation lines']) {
    let pushed = 0;
    const server = await smtpServer(t, {
      secure: false,
      onConnection: socket => {
        const chunk =
          shape === 'one line'
            ? Buffer.alloc(16384, 'A')
            : Buffer.from(`220-${'A'.repeat(60)}SYNTHETIC-REPLY-CANARY\r\n`.repeat(200));
        if (shape === 'one line') socket.write('220 ');
        const pump = () => {
          while (!socket.destroyed && pushed < 16 * 1024 * 1024) {
            pushed += chunk.length;
            if (!socket.write(chunk)) break;
          }
        };
        socket.on('drain', pump);
        pump();
      },
    });
    let options;
    const notifier = new EmailNotifier({
      getSettings: () => smtpSettings(server, false),
      transportFactory: o => nodemailer.createTransport((options = o)),
    });
    t.after(() => notifier.close());
    const started = performance.now();
    const error = await notifier.send(event).catch(e => e);
    assert.equal(options.maxResponseSize, 64 * 1024, shape);
    assert.ok(performance.now() - started < 5000, `${shape}: dropped well before the deadline`);
    assert.equal(
      error.message,
      'Email was not confirmed by the mail server. Check SMTP settings, credentials, TLS trust and network access.',
      shape
    );
    assert.doesNotMatch(String(error.stack), /SYNTHETIC-REPLY-CANARY|AAAAAAAA/, shape);
    // Far below what the server would send: it was cut off, not drained.
    assert.ok(pushed < 16 * 1024 * 1024, `${shape}: ${pushed} bytes pushed`);
    assert.equal(notifier.status().lastAccepted, null);
  }
});

test('cancelling in the loop turn the pool opens its connection sends nothing', async t => {
  const server = await smtpServer(t, { secure: false });
  allowLoopback(t);
  const notifier = new EmailNotifier({
    getSettings: () => smtpSettings(server, false),
    transportFactory: options => {
      const transport = nodemailer.createTransport(options),
        pool = transport.transporter,
        create = pool._createConnection;
      assert.equal(typeof create, 'function');
      // A settings save handled in the turn after the pool creates its connection,
      // before that connection has a socket that closing the pool could end.
      pool._createConnection = function () {
        setImmediate(() => notifier.reconfigure());
        return create.call(this);
      };
      return transport;
    },
  });
  t.after(() => notifier.close());
  await assert.rejects(notifier.send(event), /settings changed/);
  await sleep(200);
  assert.equal(server.connections, 0);
});

test('the overall deadline and cancellation also cover the SMTP address check', async t => {
  let release;
  t.after(() => {
    release?.();
    configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
  });
  // A DNS lookup that stalls, as during a resolver outage.
  configureDestinations({
    lookup: () => new Promise(resolve => (release = () => resolve([{ address: '192.0.2.1' }]))),
  });
  let transports = 0;
  const notifier = new EmailNotifier({
    getSettings: settings,
    timeoutMs: 50,
    transportFactory: () => {
      transports++;
      return { sendMail: async () => accepted(), close() {} };
    },
  });
  const within = (promise, ms) =>
    Promise.race([promise, sleep(ms).then(() => 'still pending after ' + ms + ' ms')]);
  const first = notifier.send(event).catch(e => e);
  const timedOut = await within(first, 1000);
  assert.match(String(timedOut?.message ?? timedOut), /timed out.*Nothing was sent/);
  assert.equal(notifier.status().pending, 0);
  // Shutdown does not wait for the stalled lookup either.
  const stopped = notifier.send(event).catch(e => e);
  await until(() => notifier.status().pending === 1);
  const closing = notifier.close().then(() => 'closed');
  assert.equal(await within(closing, 1000), 'closed');
  assert.match(String((await within(stopped, 1000))?.message), /Nothing was sent/);
  assert.equal(transports, 0);
});
