import test from 'node:test';
import assert from 'node:assert/strict';
import { mailMessage } from '../lib/mail.mjs';

test('notification subjects distinguish check failures from metric warnings without implying a healthy service is down', () => {
  const settings = { from: 'sender@example.test', to: 'recipient@example.test' };
  const event = {
    name: 'Fixture service',
    kind: 'firing',
    message: 'Memory is 91% (above 90)',
    time: 1800000000000,
  };
  const metric = mailMessage(settings, { ...event, category: 'measurement' });
  assert.match(metric.subject, /Alert · Metric warning · Fixture service/);
  assert.match(metric.text, /may still be responding normally/);
  const connection = mailMessage(settings, {
    ...event,
    category: 'availability',
    message: 'Monitoring check failed',
  });
  assert.match(connection.subject, /Alert · Connection check · Fixture service/);
  assert.match(connection.text, /network path, API or website response/);
  const recovery = mailMessage(settings, { ...event, kind: 'resolved', category: 'availability' });
  assert.match(recovery.subject, /Recovered · Connection check/);
  assert.match(recovery.text, /Recovery met the configured confirmation/);
  const preview = mailMessage(settings, { ...event, category: 'availability' }, { test: true });
  assert.equal(preview.subject, '[Uptime Goblin] Test email');
  assert.doesNotMatch(preview.text, /could not complete/);
});

// Review round 3: every 'system' notice that went out alone carried the history-storage text,
// so the email saying the webhook paused (or works again) told the admin that readings were not
// saved and to free disk space. The explanation now goes by the notice's rule.
test("Uptime Goblin's own notices explain by their rule: only history writes speak of readings, a full disk of disk space, a channel of held notifications", () => {
  const settings = { from: 'sender@example.test', to: 'recipient@example.test' };
  const notice = (rule, kind, message) =>
    mailMessage(settings, {
      service: 'orbit',
      name: 'Uptime Goblin',
      kind,
      category: 'system',
      rule,
      message,
      time: 1800000000000,
    });
  const readings = /new readings are not saved|saving readings again/;
  const disk = /Free disk space/;
  const body = (text, explanation) =>
    `${text}${explanation ? `\n\n${explanation}` : ''}\n\nTime: 2027-01-15T08:00:00.000Z\n\nOpen your Uptime Goblin dashboard for current status.`;
  // History writes failing and working again: the 1.4.x texts, unchanged.
  const storage = notice('__storage', 'firing', 'Uptime Goblin cannot write its history database.');
  assert.equal(storage.subject, '[Uptime Goblin] Alert · Uptime Goblin health · Uptime Goblin');
  assert.equal(
    storage.text,
    `Alert — Uptime Goblin\n\n${body(
      'Uptime Goblin cannot write its history database.',
      'Uptime Goblin keeps collecting and alerting, but new readings are not saved. Free disk space on the Uptime Goblin host; lowering retention does not free disk space by itself.'
    )}`
  );
  assert.match(
    notice('__storage', 'resolved', 'Uptime Goblin can write its history database again.').text,
    /\n\nUptime Goblin is saving readings again\.\n\n/
  );
  // A full disk: free disk space, said once (its message already says readings are paused).
  const full = notice('__disk', 'firing', "The Uptime Goblin host's disk is full.");
  assert.equal(
    full.text,
    `Alert — Uptime Goblin\n\n${body(
      "The Uptime Goblin host's disk is full.",
      'Free disk space on the Uptime Goblin host; lowering retention does not free disk space by itself.'
    )}`
  );
  assert.doesNotMatch(full.text, readings);
  const free = notice('__disk', 'resolved', "The Uptime Goblin host's disk has free space again.");
  assert.equal(
    free.text,
    `Recovered — Uptime Goblin\n\n${body("The Uptime Goblin host's disk has free space again.", '')}`
  );
  // A channel that pauses, and works again: nothing about readings or disk space.
  const paused = notice(
    '__channel_env-webhook',
    'firing',
    'Webhook notifications are paused: The webhook answered 404.'
  );
  assert.equal(paused.subject, '[Uptime Goblin] Alert · Uptime Goblin health · Uptime Goblin');
  assert.equal(
    paused.text,
    `Alert — Uptime Goblin\n\n${body(
      'Webhook notifications are paused: The webhook answered 404.',
      'Its notifications are held until it works again (each for at most 24 hours); this channel keeps sending. Configure → Notifications in Uptime Goblin says why; once the cause is fixed, Resume there sends them.'
    )}`
  );
  assert.ok(paused.html.includes('<p>Its notifications are held until it works again'));
  const working = notice('__channel_email', 'resolved', 'Email notifications are working again.');
  assert.equal(
    working.text,
    `Recovered — Uptime Goblin\n\n${body('Email notifications are working again.', '')}`
  );
  for (const message of [paused, working, free]) {
    assert.doesNotMatch(message.text, readings);
    assert.doesNotMatch(message.html, readings);
  }
  assert.doesNotMatch(paused.text, disk);
  // A system notice whose rule this release does not know (or none) gets no explanation.
  for (const rule of [undefined, '__other'])
    assert.equal(
      notice(rule, 'firing', 'Something about Uptime Goblin.').text,
      `Alert — Uptime Goblin\n\n${body('Something about Uptime Goblin.', '')}`
    );
});
