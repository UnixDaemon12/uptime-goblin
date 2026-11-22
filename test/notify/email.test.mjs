// The built-in email channel over lib/mail.mjs, with fake transports (no mail is ever sent).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createEmailChannel,
  classifyMailError,
  mailPayload,
} from '../../lib/notify/channels/email.mjs';
import { emailDefaults } from '../../lib/catalog.mjs';
import { EmailNotifier, mailMessage, orbitMessageId } from '../../lib/mail.mjs';
import { createOutbox, digestKeyFor } from '../../lib/notify/outbox.mjs';
import { createMemoryOutboxStore } from '../../lib/notify/memory-store.mjs';
import { fakeClock, quietLogger, settle } from '../alerting/fake-clock.mjs';

// An IP literal (TEST-NET-1) as the SMTP host: the destination check needs no DNS.
const settings = (overrides = {}) => ({
  ...emailDefaults(),
  host: '192.0.2.25',
  enabled: true,
  from: 'sender@example.test',
  to: 'recipient@example.test',
  password: 'private-mail-fixture',
  ...overrides,
});
const accepted = to => ({ accepted: [to ?? 'recipient@example.test'], rejected: [] });
const firing = {
  service: 'plex',
  name: 'Plex',
  kind: 'firing',
  category: 'availability',
  rule: '__availability',
  message: 'Source is unavailable',
  time: 1800000000000,
};
const resolved = { ...firing, kind: 'resolved', message: 'Recovered', time: 1800000060000 };
const message = (events = [firing]) => ({
  uid: 'g_batch',
  channelId: 'email',
  target: '',
  kind: events.length > 1 ? 'digest' : (events[0]?.kind ?? 'firing'),
  attempt: 1,
  digest: events.length > 1,
  events,
});
// A transport factory whose sendMail is `send(mail)`; records messages and closes.
function transport(send = async () => accepted()) {
  const sent = [];
  let closes = 0;
  return {
    sent,
    get closes() {
      return closes;
    },
    factory: () => ({
      sendMail: async mail => {
        sent.push(mail);
        return send(mail);
      },
      close() {
        closes++;
      },
    }),
  };
}
const channel = (options = {}) =>
  createEmailChannel({
    getSettings: () => settings(),
    destinationCheck: async () => null,
    ...options,
  });

test('one event is one 1.4.2 message; several are one digest', async () => {
  const fake = transport();
  const email = channel({ transportFactory: fake.factory });
  assert.equal(email.name, 'email');
  assert.deepEqual(email.digest, { windowMs: 60000, maxFactor: 3 });
  assert.deepEqual(email.unknown, { resendAfterMs: 300000, maxResends: 1 });
  assert.equal((await email.send(message())).type, 'accepted');
  assert.match(fake.sent[0].subject, /^\[Uptime Goblin\] Alert · Connection check · Plex$/);
  assert.equal((await email.send(message([firing, resolved]))).type, 'accepted');
  assert.match(fake.sent[1].subject, /^\[Uptime Goblin\] 1 alert, 1 recovered · Plex$/);
  assert.ok(fake.closes >= 2);
  assert.deepEqual(mailPayload([firing]), firing);
  assert.deepEqual(mailPayload([firing, resolved]), {
    digest: [firing, resolved],
    time: firing.time,
  });
});

test('settings are read when sending, so a change no longer drops queued mail', async () => {
  let current = settings({ to: 'old@example.test' });
  const fake = transport(mail => accepted(mail.to[0].address));
  const email = channel({ getSettings: () => current, transportFactory: fake.factory });
  current = settings({ to: 'new@example.test' });
  assert.equal((await email.send(message())).type, 'accepted');
  assert.equal(fake.sent[0].to[0].address, 'new@example.test');
});

test('switched off, unconfigured or refused addresses send nothing', async () => {
  const fake = transport();
  const off = channel({
    getSettings: () => settings({ enabled: false }),
    transportFactory: fake.factory,
  });
  assert.equal((await off.send(message())).type, 'skipped');
  const unset = channel({
    getSettings: () => settings({ password: '' }),
    transportFactory: fake.factory,
  });
  assert.equal((await unset.send(message())).type, 'pause');
  const refused = channel({
    transportFactory: fake.factory,
    destinationCheck: async () => 'Uptime Goblin does not collect from link-local addresses.',
  });
  const outcome = await refused.send(message());
  assert.equal(outcome.type, 'pause');
  assert.match(outcome.reason, /^The SMTP server address is not allowed\./);
  assert.equal(
    (await channel({ transportFactory: fake.factory }).send(message([]))).type,
    'failed'
  );
  assert.equal(fake.sent.length, 0);
  assert.throws(() => createEmailChannel({}), /getSettings/);
});

test('SMTP failures become retry, unknown, pause or failed', async () => {
  const fail = (code, extra = {}) =>
    Object.assign(new Error(extra.message ?? code), { code, ...extra });
  const table = [
    [fail('EAUTH'), 'pause', /sign-in failed/],
    [fail('EENVELOPE', { command: 'RCPT TO', responseCode: 550 }), 'failed', /recipient/],
    [fail('EENVELOPE', { command: 'MAIL FROM' }), 'pause', /sender/],
    [fail('ETIMEDOUT', { message: 'Greeting never received' }), 'retry', /Nothing was sent/],
    [fail('ETIMEDOUT', { message: 'Connection timeout' }), 'retry', /Nothing was sent/],
    [fail('ETIMEDOUT', { message: 'Timeout' }), 'unknown', /unknown/],
    [fail('EMESSAGE', { responseCode: 421 }), 'retry', /try later \(421\)/],
    [fail('EMESSAGE', { responseCode: 554 }), 'failed', /refused the message \(554\)/],
    [fail('ECONNECTION'), 'retry', /could not connect/],
    [fail('ESOCKET', { message: 'self-signed certificate in certificate chain' }), 'pause', /TLS/],
    [fail('ETLS'), 'pause', /TLS/],
    [fail('ESTRANGE'), 'retry', /not confirmed/],
  ];
  for (const [error, type, reason] of table) {
    const direct = classifyMailError(error);
    assert.equal(direct.type, type, error.code + ' ' + error.message);
    assert.match(direct.reason, reason);
    // The same through the channel, with the raw error from the transport.
    const email = channel({
      transportFactory: transport(async () => Promise.reject(error)).factory,
    });
    assert.equal((await email.send(message())).type, type, `channel: ${error.code}`);
  }
  // Answered without accepting the recipient: the recipient was refused.
  const notAccepted = channel({
    transportFactory: transport(async () => ({
      accepted: [],
      rejected: ['recipient@example.test'],
    })).factory,
  });
  assert.equal((await notAccepted.send(message())).type, 'failed');
});

test('the 20 s deadline and cancellation tell "nothing sent" from "acceptance unknown"', async () => {
  // Stuck inside the SMTP conversation: the deadline fires and acceptance is unknown.
  const stuck = channel({
    timeoutMs: 30,
    transportFactory: transport(() => new Promise(() => {})).factory,
  });
  const outcome = await stuck.send(message());
  assert.equal(outcome.type, 'unknown');
  assert.match(outcome.reason, /acceptance is unknown/);
  // Cancelled during the conversation (Uptime Goblin stopping): unknown.
  const controller = new AbortController();
  let started;
  const started$ = new Promise(resolve => (started = resolve));
  const slow = channel({
    transportFactory: transport(() => {
      started();
      return new Promise(() => {});
    }).factory,
  });
  const pending = slow.send(message(), { signal: controller.signal });
  await started$;
  controller.abort();
  assert.equal((await pending).type, 'unknown');
  // Cancelled before any connection: nothing was sent, so it is retried.
  const early = new AbortController();
  early.abort();
  const fake = transport();
  assert.equal(
    (await channel({ transportFactory: fake.factory }).send(message(), { signal: early.signal }))
      .type,
    'retry'
  );
  // Cancelled while the address is being checked.
  let release;
  const checking = new AbortController();
  const waiting = channel({
    transportFactory: fake.factory,
    destinationCheck: () => new Promise(resolve => (release = resolve)),
  }).send(message(), { signal: checking.signal });
  await new Promise(resolve => setImmediate(resolve));
  checking.abort();
  release(null);
  assert.equal((await waiting).type, 'retry');
  assert.equal(fake.sent.length, 0);
});

test('orbitMessageId is <orbit.{delivery id}@{sender domain}>, lower-cased', () => {
  assert.equal(
    orbitMessageId('g_abcdefghijklmnopqrstuvwxyz', 'Alerts@Mail.Example.TEST'),
    '<orbit.g_abcdefghijklmnopqrstuvwxyz@mail.example.test>'
  );
  assert.equal(orbitMessageId('d_x', 'a.b@c@example.test'), '<orbit.d_x@example.test>');
  for (const [id, from] of [
    ['', 'a@example.test'],
    ['has space', 'a@example.test'],
    ['x'.repeat(65), 'a@example.test'],
    ['g_ok', 'no-domain'],
    ['g_ok', 'a@'],
    ['g_ok', 'a@bad domain'],
  ])
    assert.throws(() => orbitMessageId(id, from), TypeError, `${id} ${from}`);
});

test('mailMessage sets messageId for alerts and digests, never for a test email', () => {
  const s = settings();
  const id = '<orbit.g_batch@example.test>';
  assert.equal(mailMessage(s, firing, { messageId: id }).messageId, id);
  assert.equal(mailMessage(s, { digest: [firing, resolved] }, { messageId: id }).messageId, id);
  assert.equal('messageId' in mailMessage(s, firing), false);
  assert.equal('messageId' in mailMessage(s, { digest: [firing, resolved] }), false);
  // A test email keeps nodemailer's own Message-ID even when one is passed.
  assert.equal('messageId' in mailMessage(s, {}, { test: true, messageId: id }), false);
});

test('EmailNotifier passes messageId through to the transport; test emails keep their own', async () => {
  const fake = transport();
  const notifier = new EmailNotifier({
    getSettings: () => settings(),
    transportFactory: fake.factory,
  });
  await notifier.send(firing, { messageId: '<orbit.g_one@example.test>' });
  await notifier.send(firing, { test: true, messageId: '<orbit.g_two@example.test>' });
  await notifier.send(firing);
  assert.deepEqual(
    fake.sent.map(mail => mail.messageId),
    ['<orbit.g_one@example.test>', undefined, undefined]
  );
  await notifier.close();
});

test('TLS trust pauses are transient; sign-in, sender and setup pauses are not', async () => {
  const fail = (code, extra = {}) =>
    Object.assign(new Error(extra.message ?? code), { code, ...extra });
  assert.equal(classifyMailError(fail('ETLS')).transient, true);
  assert.equal(
    classifyMailError(fail('ESOCKET', { message: 'unable to verify the first certificate' }))
      .transient,
    true
  );
  for (const error of [
    fail('EAUTH'),
    fail('ENOAUTH'),
    fail('EOAUTH2'),
    fail('EENVELOPE', { command: 'MAIL FROM' }),
  ]) {
    const outcome = classifyMailError(error);
    assert.deepEqual([outcome.type, outcome.transient], ['pause', false], error.code);
  }
  const unset = await channel({ getSettings: () => settings({ password: '' }) }).send(message());
  assert.deepEqual([unset.type, unset.transient], ['pause', false]);
  const badSender = await channel({ getSettings: () => settings({ from: 'nobody' }) }).send(
    message()
  );
  assert.deepEqual([badSender.type, badSender.transient], ['pause', false]);
});

test('one batch keeps its Message-ID across a retry and an unknown resend', async t => {
  const clock = fakeClock();
  const answers = [
    () => Promise.reject(Object.assign(new Error('connect'), { code: 'ECONNECTION' })),
    () => Promise.reject(Object.assign(new Error('Timeout'), { code: 'ETIMEDOUT' })),
  ];
  const fake = transport(async () => (answers.length ? answers.shift()() : accepted()));
  const email = createEmailChannel({
    getSettings: () => settings({ from: 'Uptime Goblin@Example.TEST' }),
    destinationCheck: async () => null,
    transportFactory: fake.factory,
    digestWindowMs: 1000,
  });
  const store = createMemoryOutboxStore();
  const outbox = createOutbox({
    store,
    clock,
    rng: () => 1,
    logger: quietLogger(),
    channels: [email],
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  const entry = eventUid => ({
    eventUid,
    channelId: 'email',
    kind: 'firing',
    orderKey: `${eventUid}\n__availability`,
    event: { ...firing, service: eventUid },
  });
  await outbox.enqueue([entry('plex'), entry('nas')]);
  const pass = async () => {
    await outbox.pump();
    await settle(30);
  };
  await clock.advance(1000);
  await pass(); // ECONNECTION: nothing was sent, retried after the backoff
  await clock.advance(30000);
  await pass(); // timed out mid-conversation: acceptance unknown, resent after 5 minutes
  await clock.advance(5 * 60 * 1000);
  await pass(); // accepted
  const rows = await store.list({ channelId: 'email', limit: 10 });
  assert.deepEqual(
    rows.map(row => row.state),
    ['delivered', 'delivered']
  );
  const batch = digestKeyFor(rows.map(row => row.uid));
  assert.equal(rows[0].digestKey, batch);
  assert.equal(fake.sent.length, 3);
  for (const mail of fake.sent) {
    assert.equal(mail.messageId, `<orbit.${batch}@example.test>`);
    assert.match(mail.subject, /^\[Uptime Goblin\] 2 alerts/);
  }
});
