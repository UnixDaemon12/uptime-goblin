// The delivery test helpers (delivery spec §2.1 items 9 and 10): the webhook receiver, the SMTP
// server and the fake delivery service behave as their users rely on, and the fake's answers
// have exactly the shapes of test/contract/notifications-bodies.json.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import nodemailer from 'nodemailer';
import { webhookReceiver } from '../helpers/webhook-receiver.mjs';
import { smtpServer } from '../helpers/smtp.mjs';
import { fakeAlerting } from '../helpers/fake-alerting.mjs';
import { DeliveryError } from '../../lib/alerting/errors.mjs';
import { fakeClock } from '../alerting/fake-clock.mjs';

const bodies = JSON.parse(
  fs.readFileSync(new URL('../contract/notifications-bodies.json', import.meta.url), 'utf8')
);
const keys = value => Object.keys(value).sort();
const post = (url, body = '{}') =>
  fetch(url, { method: 'POST', body, headers: { 'Content-Type': 'application/json' } });

test('webhookReceiver records requests and answers as told, including delays and holds', async t => {
  const hook = await webhookReceiver(t, {
    respond: (request, n) =>
      n === 1
        ? 500
        : n === 2
          ? { status: 429, headers: { 'Retry-After': '30' } }
          : n === 3
            ? { status: 200, afterMs: 150 }
            : n === 4
              ? 'hold'
              : 204,
  });
  assert.match(hook.url, /^http:\/\/127\.0\.0\.1:\d+\/hook$/);
  assert.equal((await post(hook.url, '{"a":1}')).status, 500);
  const limited = await post(hook.url);
  assert.deepEqual([limited.status, limited.headers.get('retry-after')], [429, '30']);
  const started = Date.now();
  assert.equal((await post(hook.url)).status, 200);
  assert.ok(Date.now() - started >= 140);
  const held = post(hook.url);
  await hook.waitFor(4);
  assert.equal(hook.held, 1);
  hook.release(202);
  assert.equal((await held).status, 202);
  assert.equal((await post(hook.url)).status, 204);
  assert.deepEqual(hook.bodies()[0], { a: 1 });
  assert.equal(hook.requests.length, 5);
  assert.equal(typeof hook.requests[0].receivedAt, 'number');
  await assert.rejects(hook.waitFor(9, { timeoutMs: 50 }), /got 5 of 9/);
});

test('smtpServer speaks implicit TLS SMTP to nodemailer and records each message', async t => {
  const smtp = await smtpServer(t);
  const transport = options =>
    nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: true,
      auth: { user: 'orbit@example.test', pass: 'app-password' },
      tls: { ca: smtp.cert, servername: 'localhost' },
      ...options,
    });
  const info = await transport().sendMail({
    from: 'orbit@example.test',
    to: 'dana@example.test',
    subject: '[Uptime Goblin] Alert',
    text: 'Plex is down.\n.leading dot',
    messageId: '<orbit.g_abc@example.test>',
  });
  assert.deepEqual(info.accepted, ['dana@example.test']);
  const [message] = smtp.messages;
  assert.equal(message.messageId, '<orbit.g_abc@example.test>');
  assert.equal(message.subject, '[Uptime Goblin] Alert');
  assert.deepEqual(message.envelope, { from: 'orbit@example.test', to: ['dana@example.test'] });
  assert.deepEqual(message.auth, { user: 'orbit@example.test' });
  assert.match(message.body, /\.leading dot/);
  assert.ok(fs.readFileSync(smtp.caFile, 'utf8').includes('BEGIN CERTIFICATE'));
  // AUTH LOGIN works too.
  await transport({ authMethod: 'LOGIN' }).sendMail({
    from: 'orbit@example.test',
    to: 'dana@example.test',
    text: 'x',
  });
  assert.equal(smtp.messages.length, 2);
  assert.ok(smtp.sessions.at(-1).commands.some(command => /^AUTH LOGIN/i.test(command)));
  assert.ok(smtp.sessions[0].commands.some(command => /^AUTH PLAIN \*\*\*$/i.test(command)));
  // The commands never record the credentials; the session keeps them for tests to check.
  assert.ok(!JSON.stringify(smtp.sessions.map(session => session.commands)).includes('app'));
  assert.deepEqual(smtp.sessions[0].auth, { user: 'orbit@example.test', pass: 'app-password' });
});

test('smtpServer refuses sign-in or recipients, and can hold a message unanswered', async t => {
  const refusing = await smtpServer(t, { authFails: true });
  const send = (server, options = {}) =>
    nodemailer
      .createTransport({
        host: server.host,
        port: server.port,
        secure: true,
        auth: { user: 'orbit@example.test', pass: 'wrong' },
        tls: { ca: server.cert, servername: 'localhost' },
        ...options,
      })
      .sendMail({ from: 'orbit@example.test', to: 'dana@example.test', text: 'x' });
  await assert.rejects(send(refusing), { code: 'EAUTH' });
  const noRecipient = await smtpServer(t, { rcptRefused: true });
  await assert.rejects(send(noRecipient), { code: 'EENVELOPE' });
  const holding = await smtpServer(t, { holdAfterData: true });
  const pending = send(holding);
  for (let i = 0; i < 100 && !holding.held; i++)
    await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(holding.held, 1);
  assert.equal(holding.messages.length, 1);
  holding.release();
  assert.deepEqual((await pending).accepted, ['dana@example.test']);
});

test('fakeAlerting implements the service interface with the contract’s shapes', async () => {
  const clock = fakeClock();
  const fake = fakeAlerting({ clock });
  for (const name of [
    'start',
    'transitions',
    'enqueueDirect',
    'forgetSource',
    'diskChanged',
    'storageChanged',
    'storageCarried',
    'emailChanged',
    'flush',
    'stop',
    'snapshot',
    'refresh',
    'legacy',
    'deliveries',
    'retry',
    'resume',
    'emailSending',
    'recordTest',
  ])
    assert.equal(typeof fake[name], 'function', name);
  for (const name of ['describe', 'publicKeys', 'rotate'])
    assert.equal(typeof fake.signing[name], 'function', name);
  const status = fake.snapshot();
  assert.deepEqual(keys(status), keys(bodies.answers.status));
  for (const [index, channel] of status.channels.entries())
    assert.deepEqual(keys(channel), keys(bodies.answers.status.channels[index]));
  fake.add({ status: 'failed', lastStatus: 422 });
  fake.add({ channel: 'email', status: 'delivered', batch: 'g_abcdefghijklmnopqrstuvwxyz' });
  const page = await fake.deliveries({});
  assert.deepEqual(keys(page), keys(bodies.answers.deliveries));
  assert.deepEqual(keys(page.deliveries[0]), keys(bodies.answers.deliveries.deliveries[0]));
  assert.match(page.deliveries[0].uid, /^d_[a-z2-7]{26}$/);
  const dashboard = fake.dashboard();
  assert.deepEqual(keys(dashboard), keys(bodies.answers.dashboard.notifications));
  assert.deepEqual(keys(dashboard.email), keys(bodies.answers.dashboard.notifications.email));
  assert.deepEqual(keys(await fake.signing.publicKeys()), keys(bodies.answers.publicKey));
  assert.deepEqual(keys(await fake.signing.rotate()), keys(bodies.answers.rotate));
  // After a rotation the previous public key is listed too, with exactly the contract's keys.
  const rotated = await fake.signing.publicKeys();
  assert.deepEqual(keys(rotated.previous), keys(bodies.answers.publicKey.previous));
  assert.notEqual(rotated.keyId, rotated.previous.keyId);
});

test('fakeAlerting decides Retry, Resume and paging like the service, and its public key never carries the private one', async () => {
  const clock = fakeClock();
  const fake = fakeAlerting({ clock });
  const failed = fake.add({ status: 'failed', alert: { service: 'sonarr', rule: 'queue' } });
  const waiting = fake.add({ status: 'waiting' });
  const delivered = fake.add({ status: 'delivered' });
  const refused = async (uid, code) => {
    const error = await fake.retry(uid).catch(caught => caught);
    assert.ok(error instanceof DeliveryError, uid);
    assert.equal(error.code, code);
    return error;
  };
  await refused('d_zzzzzzzzzzzzzzzzzzzzzzzzzz', 'delivery_not_found');
  assert.match((await refused(waiting.uid, 'delivery_not_retryable')).message, /first attempt/);
  assert.match((await refused(delivered.uid, 'delivery_not_retryable')).message, /Only failed/);
  // A later delivered row of the same alert: outdated.
  const fresh = fake.add({ status: 'failed', alert: { service: 'nas' } });
  fake.add({ status: 'delivered', alert: { service: 'nas' } });
  await refused(fresh.uid, 'delivery_outdated');
  // Paused: refused with the reason; Resume releases the held rows.
  fake.setChannel('env-webhook', { state: 'paused', pausedReason: 'The webhook answered 401.' });
  fake.add({ status: 'paused' });
  assert.match(
    (await refused(failed.uid, 'channel_paused')).message,
    /^Webhook notifications are paused: The webhook answered 401\. Resume the channel/
  );
  const resumed = await fake.resume('env-webhook');
  assert.equal(resumed.released, 1);
  assert.equal(resumed.channel.state, 'ok');
  assert.deepEqual(await fake.retry(failed.uid).then(result => result.retried), 1);
  await assert.rejects(fake.resume('slack'), { code: 'channel_unknown' });
  // Paging (A30): newest first; the memory rows first, page by page (an m:<n> cursor), then
  // the saved ones filling the page, never more than `limit` rows; `unsaved` counts them all.
  fake.setSaving(false);
  await fake.transitions([{ service: 'plex', kind: 'firing', rule: '__availability' }]);
  const first = await fake.deliveries({ limit: 2 });
  assert.deepEqual(
    first.deliveries.map(item => item.saved),
    [false, false]
  );
  assert.equal(first.unsaved, 2);
  assert.match(first.nextCursor, /^m:[1-9][0-9]*$/);
  const second = await fake.deliveries({ limit: 2, cursor: first.nextCursor });
  assert.deepEqual(
    second.deliveries.map(item => item.saved),
    [true, true]
  );
  assert.match(second.nextCursor, /^[1-9][0-9]*$/);
  const third = await fake.deliveries({ limit: 2, cursor: second.nextCursor });
  assert.ok(third.deliveries.length && third.deliveries.every(item => item.saved));
  await assert.rejects(fake.deliveries({ cursor: 'x' }), { code: 'invalid_request' });
  // Unavailable: reads refuse; the snapshot keeps its figures with available false.
  fake.setAvailable(false);
  await assert.rejects(fake.deliveries({}), { code: 'delivery_status_unavailable' });
  assert.equal(fake.snapshot().available, false);
  fake.setAvailable(true);
  // The public key, as often as asked: public material only, never the private key.
  for (let n = 0; n < 12; n++) {
    const answer = await fake.signing.publicKeys();
    assert.equal(answer.algorithm, 'Ed25519');
    assert.doesNotMatch(JSON.stringify(answer), /PRIVATE KEY/);
  }
  // fail(): the next call throws what the test chose.
  fake.fail('emailChanged', new Error('boom'));
  await assert.rejects(fake.emailChanged(), /boom/);
  await fake.emailChanged();
  assert.ok(fake.calls.some(([name]) => name === 'emailChanged'));
});
