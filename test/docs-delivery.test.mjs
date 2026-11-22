// The alert delivery docs against the code they describe (1.5 docs audit, area "delivery").
// Each test reads the texts and the code that decides the behaviour, so a change to either that
// makes the docs wrong fails here.
import { currentNames, isDeploymentFile } from './helpers/deployed-names.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { legacyAllows, legacyEntries, legacySnapshot } from '../lib/alerting/policy.mjs';
import { createEnvWebhookChannel } from '../lib/notify/channels/webhook.mjs';
import { parseWebhookUrl, WebhookUrlError } from '../lib/notify/address-policy.mjs';
import { safeReason } from '../lib/notify/channel.mjs';
import { createOutbox, deliveryUid } from '../lib/notify/outbox.mjs';
import { DELIVERY_POLICY } from '../lib/notify/retry.mjs';
import { post } from '../lib/notify/http.mjs';
import { failedSinceOf } from '../lib/alerting/view.mjs';
import { DELIVERY_ERRORS, deliveryError } from '../lib/alerting/errors.mjs';
import { createSigning, SIGNING_HOLD_REASON } from '../lib/alerting/signing.mjs';
import { generateSigningKey } from '../lib/notify/sign.mjs';
import { STALE_REASON } from '../lib/alerting/service.mjs';
import { AUDIT_ERRORS } from '../lib/audit/errors.mjs';
import { CLOSE_MS } from '../lib/audit/actions.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
// Deployment files with their names from before the rename read as the current ones
// (test/helpers/deployed-names.mjs).
const read = file => {
  const text = fs.readFileSync(path.join(repository, file), 'utf8');
  return isDeploymentFile(file) ? currentNames(text) : text;
};
// What a reader sees of a Markdown paragraph: runs of blanks as one space.
const flat = text => text.replace(/\s+/g, ' ').trim();
// A section of a Markdown file from its heading (any level) to the next heading of that level
// or above.
function section(text, heading) {
  const level = /^#+/.exec(heading)[0].length;
  const start = text.indexOf(`\n${heading}\n`);
  assert.notEqual(start, -1, `section "${heading}"`);
  const next = new RegExp(`\\n#{1,${level}} `, 'g');
  next.lastIndex = start + heading.length + 1;
  const end = next.exec(text)?.index;
  return text.slice(start, end);
}
// The CHANGELOG's notes for the 1.5 branch: everything above the 1.4.3 release.
const unreleased = () => read('CHANGELOG.md').split('\n## 1.4.3')[0];
const bullet = start =>
  unreleased()
    .split('\n')
    .find(line => line.startsWith(`- **${start}`)) ?? `(no bullet ${start})`;
// GitHub's heading anchors, for the links these docs add.
const anchors = file =>
  new Set(
    [...read(file).matchAll(/^#{1,6} (.+)$/gm)].map(([, title]) =>
      title
        .toLowerCase()
        .replace(/[^\p{L}\p{N} _-]/gu, '')
        .replace(/ /g, '-')
    )
  );
function assertLink(file, target) {
  const [linked, anchor] = target.split('#');
  const into = linked ? path.join(path.dirname(file), linked) : file;
  assert.ok(anchors(into).has(anchor), `${file} links to ${target}, a heading of ${into}`);
  assert.ok(read(file).includes(`(${target})`), `${file} links to ${target}`);
}

const example = {
  service: 'linux-1',
  name: 'Example host',
  kind: 'firing',
  category: 'measurement',
  rule: 'cpu',
  message: 'CPU is 95 % (above 80)',
  time: 1800000000000,
};

// What the webhook channel posts for one event, with a fake transport.
async function sent(event, { url = 'https://receiver.example.test/hook' } = {}) {
  const posts = [];
  const channel = createEnvWebhookChannel({
    url,
    signingKeys: () => [generateSigningKey()],
    addressPolicy: async () => null,
    post: async (target, body, options) => {
      posts.push({ target: String(target), body, headers: options.headers });
      return { status: 200, headers: {} };
    },
  });
  const outcome = await channel.send({ uid: 'd_abcdefghijklmnopqrstuvwxyz', events: [event] });
  return { outcome, posts };
}

test('docs: the webhook body example is what Orbit posts, with category and rule, and every header is listed', async () => {
  // The snapshot drops what the history row adds (uid, since), as the outbox does.
  const { posts } = await sent(legacySnapshot({ ...example, uid: 'e_x', since: 1 }));
  assert.equal(posts.length, 1);
  const body = posts[0].body;
  const guide = read('docs/notifications.md');
  const webhook = section(guide, '## The webhook');
  const json = file => /```json\n(.*)\n```/.exec(file)?.[1];
  assert.equal(json(webhook), body, 'notifications.md shows the body Uptime Goblin sends');
  assert.equal(
    json(section(read('docs/configuration.md'), '## Webhook')),
    body,
    'configuration.md shows the body Uptime Goblin sends'
  );
  // The fields a receiver needs to pair a recovery with its alert, and the values of each.
  assert.match(
    flat(webhook),
    /`category` is `availability` \(the connection check\), `measurement` \(a metric threshold\) or `system` \(Uptime Goblin's own notices\)/
  );
  for (const rule of ['__availability', '__disk', '__storage'])
    assert.ok(webhook.includes(`\`${rule}\``), `notifications.md names the rule ${rule}`);
  for (const id of ['email', 'env-webhook'])
    assert.ok(webhook.includes(`\`__channel_${id}\``), `notifications.md names __channel_${id}`);
  assert.match(flat(webhook), /A recovery has the same `service` and `rule` as its alert/);
  // The rules named are the ones the code uses.
  const service = read('lib/alerting/service.mjs');
  assert.match(service, /rule: '__disk'/);
  assert.match(service, /rule: '__storage'/);
  assert.match(service, /rule: `__channel_\$\{channelId\}`/);
  assert.match(service, /category: 'system'/);
  assert.match(read('lib/store.mjs'), /key: '__availability'/);
  // The header table lists exactly the headers sent, and User-Agent's value.
  const listed = [...webhook.matchAll(/^\| `([A-Za-z-]+)` \|/gm)].map(match => match[1]);
  assert.deepEqual(listed.sort(), Object.keys(posts[0].headers).sort());
  assert.equal(posts[0].headers['User-Agent'], 'Uptime-Goblin');
  assert.match(webhook, /^\| `User-Agent` \| `Uptime-Goblin` \|$/m);
  // 1.4.x sent Node's default User-Agent: the CHANGELOG says what changed for receivers.
  assert.match(bullet('Signed webhooks.'), /send `User-Agent: Uptime-Goblin`/);
  assert.match(bullet('Webhook receivers:'), /send `User-Agent: Uptime-Goblin`/);
});

test('docs: queued notifications follow a changed receiver, and removing the URL skips them', async () => {
  // A row is per event and channel: nothing of the address is in it or in its delivery id.
  const entries = legacyEntries(
    { ...example, uid: 'e_1' },
    {
      eventUid: 'e_1',
      settings: { enabled: true, notifyOnAlert: true, notifyOnRecovery: true },
      webhookConfigured: true,
    }
  );
  assert.equal(entries.length, 1);
  assert.equal(entries[0].target, undefined, 'no receiver address in the row');
  assert.equal(
    deliveryUid('e_1', 'env-webhook'),
    deliveryUid('e_1', 'env-webhook', ''),
    'the delivery id does not depend on the address'
  );
  // The channel sends to the URL it was started with, under the row's delivery id.
  for (const url of ['https://receiver-a.example.test/hook', 'https://receiver-b.example.test/h']) {
    const { posts } = await sent(legacySnapshot(example), { url });
    assert.equal(posts[0].target, url);
    assert.equal(posts[0].headers['X-Goblin-Delivery'], 'd_abcdefghijklmnopqrstuvwxyz');
  }
  // Without GOBLIN_WEBHOOK_URL a row is skipped at its next attempt, which is at most an hour
  // away (a Retry-After hold); a backoff and the circuit wait at most 15 minutes.
  const { outcome, posts } = await sent(legacySnapshot(example), { url: '' });
  assert.equal(posts.length, 0);
  assert.equal(outcome.type, 'skipped');
  assert.ok(
    Math.max(
      DELIVERY_POLICY.capMs,
      DELIVERY_POLICY.circuitCapMs,
      DELIVERY_POLICY.retryAfterCapMs
    ) <=
      60 * 60 * 1000
  );
  assert.match(
    read('public/modules/configure/notifications.js'),
    /^ {2}skipped: 'Skipped: not sent',$/m
  );
  const guide = flat(section(read('docs/notifications.md'), '## The webhook'));
  assert.match(
    guide,
    /\*\*Changing the receiver\.\*\* Notifications are queued per channel, not per address\./
  );
  assert.match(
    guide,
    /with the same `X-Goblin-Delivery`, and \*\*Retry\*\* sends failed ones there too/
  );
  assert.match(guide, /The signing key stays the same, also while `GOBLIN_WEBHOOK_URL` is unset/);
  assert.match(guide, /ends as "Skipped: not sent" at its next attempt, within an hour/);
  assert.match(
    guide,
    /Receivers hold only the public key, which cannot sign, so the old receiver cannot make a request the new one accepts\./
  );
  // Email: 1.4.x's reconfigure() dropped waiting mail; 1.5 sends it with the new settings.
  assert.match(
    read('lib/notify/outbox.mjs'),
    /Replaces 1\.4\.2's email\.reconfigure\(\), which dropped queued mail/
  );
  assert.match(
    flat(section(read('docs/configuration.md'), '## Email')),
    /Email still waiting or held when you save goes out with the new settings, to the new recipient\./
  );
  const durable = bullet('Durable alert delivery.');
  assert.match(durable, /Saving email settings no longer drops alert email that was waiting/);
  assert.match(
    durable,
    /go to a changed `GOBLIN_WEBHOOK_URL` after the restart, signed with the same key/
  );
  assertLink('CHANGELOG.md', 'docs/notifications.md#the-webhook');
});

test('docs: a different control.sqlite file is in the CHANGELOG, quoting the reason the history shows', () => {
  const prefix = "Not sent: Uptime Goblin's control database is a different file than before";
  assert.ok(STALE_REASON.startsWith(prefix));
  assert.ok(bullet('Durable alert delivery.').includes(`("${prefix}…")`));
  assert.ok(read('docs/notifications.md').includes(`("${prefix}…")`));
});

test("docs: Orbit's own notices follow three of the alert switches, not the categories", () => {
  const all = {
    enabled: true,
    notifyOnAlert: true,
    notifyOnRecovery: true,
    notifyAvailability: true,
    notifyMeasurements: true,
  };
  const notice = kind => ({ service: 'orbit', kind, category: 'system', rule: '__disk' });
  assert.equal(legacyAllows({ ...all, enabled: false }, undefined, notice('firing')), false);
  assert.equal(legacyAllows({ ...all, notifyOnAlert: false }, undefined, notice('firing')), false);
  assert.equal(
    legacyAllows({ ...all, notifyOnRecovery: false }, undefined, notice('resolved')),
    false
  );
  assert.equal(
    legacyAllows(
      { ...all, notifyAvailability: false, notifyMeasurements: false },
      { notifyAvailability: false, notifyMeasurements: false },
      notice('firing')
    ),
    true,
    'the category switches and overrides do not apply'
  );
  const guide = flat(read('docs/notifications.md'));
  assert.match(
    guide,
    /They follow \*\*Evaluate alerts\*\*, \*\*Notify when an alert begins\*\* and \*\*Notify when a source recovers\*\*, but not \*\*Connection notifications\*\*, \*\*Metric notifications\*\* or a source's overrides\./
  );
  assert.match(
    guide,
    /While \*\*Notify when a source recovers\*\* is on, a recovery always follows its notice/
  );
  assert.doesNotMatch(guide, /\. A recovery always follows its notice/);
  const disk = flat(section(read('docs/troubleshooting.md'), '## A full disk'));
  assert.match(
    disk,
    /a notice is sent on your channels \(while \*\*Evaluate alerts\*\* and \*\*Notify when an alert begins\*\* are on\)/
  );
  assert.match(
    disk,
    /free space again \(while \*\*Evaluate alerts\*\* and \*\*Notify when a source recovers\*\* are on\)/
  );
  const full = bullet('A full disk.');
  assert.match(full, /Uptime Goblin's own notices follow \*\*Evaluate alerts\*\*/);
  assert.match(
    full,
    /its recovery after the next start \(while \*\*Notify when a source recovers\*\* is on\)/
  );
  // The switch names are the page's.
  const pages = read('public/modules/configure/pages.js');
  for (const [id, label, key] of [
    ['alerts-enabled', 'Evaluate alerts', 'enabled'],
    ['alerts-start', 'Notify when an alert begins', 'notifyOnAlert'],
    ['alerts-recovery', 'Notify when a source recovers', 'notifyOnRecovery'],
    ['alerts-availability', 'Connection notifications', 'notifyAvailability'],
    ['alerts-measurements', 'Metric notifications', 'notifyMeasurements'],
  ])
    assert.ok(pages.includes(`switchField('${id}', '${label}', alerts.${key} !== false`), label);
});

test('docs: Resume and Retry are refused while the control database cannot be written', () => {
  // The routes record the attempt before they act: no audit row, no Resume or Retry.
  const routes = read('lib/http/routes/notifications.mjs');
  for (const [action, call] of [
    ['delivery.retry', 'app.alerting.retry('],
    ['channel.resume', 'app.alerting.resume('],
  ]) {
    const begin = routes.indexOf(`action: '${action}'`);
    assert.ok(begin > 0 && routes.lastIndexOf('audit.begin(', begin) > 0, action);
    assert.ok(routes.indexOf(call, begin) > begin, `${action} is recorded before ${call}`);
  }
  const [status, message] = AUDIT_ERRORS.audit_unavailable;
  assert.equal(status, 503);
  const quoted = 'Uptime Goblin cannot write its audit log, so nothing was changed';
  assert.ok(message().startsWith(quoted));
  const disk = flat(section(read('docs/notifications.md'), '## A full disk'));
  assert.ok(
    disk.includes(
      `**Resume** and **Retry** are refused then (503 \`audit_unavailable\`, "${quoted}…")`
    )
  );
  assert.match(disk, /Only a test email that the mail server accepts still resumes paused email/);
  assert.match(
    flat(read('docs/troubleshooting.md')),
    /\*\*Resume\*\* and \*\*Retry\*\* answer `audit_unavailable` until Uptime Goblin can write again\./
  );
  assert.match(
    bullet('A full disk.'),
    /\(\*\*Resume\*\* and \*\*Retry\*\* answer 503 `audit_unavailable` until Uptime Goblin can record them\)/
  );
  for (const file of ['docs/notifications.md', 'docs/troubleshooting.md', 'CHANGELOG.md'])
    assert.doesNotMatch(
      flat(read(file)),
      /\*\*Resume\*\* and an accepted test email still resume|A channel resumed meanwhile shows as working/,
      file
    );
});

test('docs: who can read the public key, that it is neither limited nor recorded, and that the private key is never shown', async () => {
  let failing = false;
  const key = generateSigningKey();
  const signing = createSigning({
    configured: true,
    logger: { warn() {}, info() {}, error() {} },
    settings: {
      async get() {
        if (failing) throw Object.assign(new Error('read failed'), { code: 'EIO' });
        return { value: { signingKey: key, createdAt: 1 }, schema: 2, version: 1, unreadable: [] };
      },
    },
  });
  // A read that fails is signing_unavailable; otherwise any number of reads answer, each with
  // public material only.
  failing = true;
  await assert.rejects(signing.publicKeys(), { code: 'signing_unavailable' });
  failing = false;
  const answers = await Promise.all(Array.from({ length: 20 }, () => signing.publicKeys()));
  assert.equal(answers.length, 20);
  for (const answer of answers) {
    assert.deepEqual(Object.keys(answer).sort(), [
      'algorithm',
      'createdAt',
      'keyId',
      'previous',
      'previousUntil',
      'publicKey',
      'publicKeyRaw',
    ]);
    assert.ok(!JSON.stringify(answer).includes(key.split('\n')[1]));
  }
  assert.equal(DELIVERY_ERRORS.reveal_rate_limited, undefined);
  // The route: a read of notifications, unrecorded, with the session checked after the read.
  const routes = read('lib/http/routes/notifications.mjs');
  const route = routes.slice(routes.indexOf("'/api/notifications/webhook/public-key'"));
  assert.ok(route.indexOf('app.alerting.signing.publicKeys()') > 0);
  assert.ok(
    route.indexOf('assertCurrent();', route.indexOf('app.alerting.signing.publicKeys()')) > 0,
    'the session is checked again after the read'
  );
  assert.doesNotMatch(routes, /signing-secret\/reveal|signing\.reveal/);
  // Replace signing key shows the new public key right after, and says when it could not.
  const page = read('public/modules/configure/notifications.js');
  assert.ok(
    page.includes('`Uptime Goblin replaced the signing key, but could not show its public key: ')
  );
  assert.ok(page.includes('await navigator.clipboard.writeText(field.value);'));
  assert.ok(page.includes("api('/api/notifications/webhook/public-key')"));
  assert.ok(
    read('lib/alerting/signing.mjs').includes(
      '`The webhook signing key was replaced by ${login}; receivers that check X-Goblin-Signature need the new public key'
    )
  );
  const who = flat(
    /\*\*Who can see it\.\*\*[^\n]*/.exec(read('docs/notifications.md'))?.[0] ?? '(none)'
  );
  assert.match(who, /The public key is not a secret: any signed-in admin can show it/);
  assert.match(who, /so can a script with the admin password while \[legacy Basic\]/);
  assert.match(who, /Uptime Goblin neither limits nor records reading it\./);
  assert.match(
    who,
    /The private key is never shown: no page, API answer, export, log line or \[audit log\]\(security\.md#audit-log\) entry holds it/
  );
  assert.match(who, /logged \("The webhook signing key was replaced by admin…"\)/);
  assert.match(
    who,
    /\*\*Replace signing key\*\* is refused while the disk is full \(503 `storage_full`\)/
  );
  assert.match(who, /\*\*Copy\*\* puts the public key on your computer's clipboard/);
  assertLink('docs/notifications.md', 'authentication.md#scripts-and-legacy-basic');
  assertLink('docs/notifications.md', 'security.md#audit-log');
});

test('docs: the webhook URL errors survive safeReason(), and the docs name each of them', () => {
  const texts = new Set();
  for (const bad of [
    'ftp://example.test/hook',
    'https://user:pw@example.test/hook',
    'https://user@example.test/hook',
    'not a url',
  ]) {
    let error;
    try {
      parseWebhookUrl(bad);
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error instanceof WebhookUrlError, bad);
    // The reason is stored and shown through safeReason(), which replaces anything that looks
    // like a URL with [url]: "or https://." became "or [url]".
    assert.equal(safeReason(error.message), error.message, bad);
    texts.add(error.message);
  }
  assert.deepEqual([...texts].sort(), [
    'GOBLIN_WEBHOOK_URL is not a valid URL.',
    'GOBLIN_WEBHOOK_URL must be an http: or https: address.',
    'GOBLIN_WEBHOOK_URL must not contain a user name or password.',
  ]);
  assert.match(
    read('docs/notifications.md'),
    /^\| Webhook \| The address is not allowed \(below\); `GOBLIN_WEBHOOK_URL` is not a valid `http:` or `https:` URL, or contains a user name or password; a new signing key that receivers may not have \(\[held for Resume\]\(#a-new-signing-key-waits-for-resume\)\) \|/m
  );
  assert.match(
    read('docs/troubleshooting.md'),
    /or a `GOBLIN_WEBHOOK_URL` that is not a valid `http:` or `https:` URL or contains a user name or password \(put a token in the path or query instead\)/
  );
  assert.match(
    flat(section(read('docs/configuration.md'), '## Webhook')),
    /link-local, multicast and reserved addresses, and a URL with a user name or password, are refused \(the webhook pauses\)/
  );
});

test('docs: .env.example says what GOBLIN_WEBHOOK_URL needs', () => {
  const example = read('.env.example');
  const comment = flat(
    /((?:^#[^\n]*\n)+)GOBLIN_WEBHOOK_URL=$/m.exec(example)?.[1].replace(/^# ?/gm, '') ?? ''
  );
  assert.match(comment, /restart (?:Orbit|Uptime Goblin) after editing/);
  assert.match(
    comment,
    /Requests are signed \(X-Goblin-Signature, Ed25519\): receivers verify them with the public key under Configure → Notifications → Show public key\./
  );
  assert.match(
    comment,
    /Link-local, multicast and reserved addresses, and a user name or password in the URL, are refused\./
  );
  assert.match(
    comment,
    /Under Docker Compose 127\.0\.0\.1 is the container itself: use the receiver's LAN address\./
  );
  assert.match(comment, /Treat a URL that carries a token like a password\./);
  // compose.yaml passes it into the container, where loopback is the container.
  assert.match(
    read('compose.yaml'),
    /^ {6}GOBLIN_WEBHOOK_URL: \$\{GOBLIN_WEBHOOK_URL-\$\{ORBIT_WEBHOOK_URL-\}\}$/m
  );
});

test('docs: the 8-second webhook deadline starts before the name is looked up', async t => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => setTimeout(() => response.end('ok'), 350));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const send = delayMs =>
    post(`http://receiver.example.test:${port}/hook`, '{}', {
      timeoutMs: 700,
      addressPolicy: async () => null,
      lookup: (host, options, callback) =>
        setTimeout(() => callback(null, [{ address: '127.0.0.1', family: 4 }]), delayMs),
    });
  assert.equal((await send(0)).status, 200, 'an answer after 350 ms is in time');
  // The same answer after a 500 ms lookup comes too late: the deadline covers the lookup, and the
  // whole request was sent, so the outcome is "unknown" (sent once more after 2 minutes).
  await assert.rejects(send(500), error => error.code === 'ETIMEDOUT' && error.sent === true);
  const guide = flat(read('docs/notifications.md'));
  assert.match(
    guide,
    /the whole request was sent, but the receiver had not started its answer when the request's 8-second deadline ran out \(the 8 seconds count from the start of the request, so looking up and connecting to the receiver use part of them\)/
  );
  assert.match(guide, /A receiver that takes about 8 seconds or longer to answer/);
  assert.match(read('lib/notify/channels/webhook.mjs'), /timeoutMs = 8000,/);
});

test('docs: the delivery history retention, its row caps, and the failed window are as the code keeps them', async () => {
  let rule;
  const outbox = createOutbox({
    store: {
      async prune(options) {
        rule = options;
        return 0;
      },
    },
  });
  await outbox.prune();
  const day = 24 * 60 * 60 * 1000;
  assert.deepEqual(
    [
      rule.finished.maxAgeMs / day,
      rule.finished.maxRows,
      rule.dead.maxAgeMs / day,
      rule.dead.maxRows,
    ],
    [7, 50000, 30, 5000]
  );
  // The hourly job prunes it.
  assert.match(read('lib/alerting/service.mjs'), /jobs\.every\('notify\.prune', 60 \* 60 \* 1000,/);
  const guide = flat(read('docs/notifications.md'));
  assert.match(
    guide,
    /Finished notifications \(delivered, or ended without a send\) are kept for 7 days after they finished, at most the newest 50,000\./
  );
  assert.match(
    guide,
    /Failed, expired and unconfirmed ones \(\*\*May have arrived\*\*\) are kept for 30 days, at most the newest 5,000\. An hourly clean-up removes the oldest first/
  );
  const page = read('public/modules/configure/notifications.js');
  assert.ok(
    page.includes(
      '<p>Newest first. Notifications that finished are kept for 7 days (at most 50,000), failed ones for 30 days (at most 5,000).</p>'
    )
  );
  assert.match(
    read('docs/troubleshooting.md'),
    /the history keeps them 30 days, at most the newest 5,000\./
  );
  assert.match(
    bullet('Configure → Notifications'),
    /the history keeps finished notifications 7 days \(at most 50,000\) and failed ones 30 days \(at most 5,000\)/
  );
  // Failed counts and Needs attention: since the last success, at most the last 24 hours (D29).
  const now = 1800000000000;
  assert.equal(failedSinceOf({ lastSuccess: 0 }, now), now - day);
  assert.equal(failedSinceOf({ lastSuccess: now - 1000 }, now), now - 1000);
  assert.ok(
    page.includes(
      '<p>Notifications waiting to retry, held while their channel is paused, or failed since the channel last delivered one (within the last 24 hours).</p>'
    )
  );
  assert.match(
    guide,
    /failed since the channel last delivered one, within the last 24 hours: the card says since when/
  );
  assert.match(
    guide,
    /or failed since their channel last delivered one \(within the last 24 hours\)/
  );
  assert.match(page, /`Failed since \$\{dateTime\(c\.failedSince\)\}`/);
});

test('docs: Retry is refused while a later notification of the alert is delivered or being sent', () => {
  assert.match(read('lib/notify/outbox.mjs'), /states: \['delivered', 'sending'\],/);
  assert.match(DELIVERY_ERRORS.delivery_outdated[1](), /already delivered or is being sent/);
  assert.match(
    flat(read('docs/notifications.md')),
    /Uptime Goblin refuses it when a later notification of the same alert was already delivered, or is being sent, on that channel/
  );
});

test('docs: the HTTP API lists every error the delivery actions answer', () => {
  const guide = read('docs/architecture.md');
  const row = (route, method = 'POST') =>
    guide.split('\n').find(line => line.startsWith(`| \`${method} ${route}\` |`)) ??
    `(no row ${method} ${route})`;
  const codes = {
    '/api/notifications/deliveries/:uid/retry': [
      'delivery_not_retryable',
      'delivery_outdated',
      'channel_paused',
      'channel_not_set_up',
      'delivery_not_found',
      'delivery_status_unavailable',
      'invalid_request',
    ],
    '/api/notifications/channels/:id/resume': [
      'signing_conflict',
      'signing_unavailable',
      'signing_compatibility',
      'storage_full',
      'channel_unknown',
      'delivery_status_unavailable',
      'invalid_request',
    ],
    // ntfy and Gotify's test notification.
    '/api/notifications/channels/:id/test': [
      'channel_unknown',
      'channel_not_set_up',
      'test_rate_limited',
      'invalid_request',
    ],
    '/api/notifications/webhook/signing-secret': [
      'signing_compatibility',
      'signing_conflict',
      'webhook_not_configured',
      'storage_full',
      'signing_unavailable',
      'invalid_request',
    ],
  };
  for (const [route, list] of Object.entries(codes)) {
    const text = row(route);
    for (const code of list) {
      assert.ok(text.includes(`\`${code}\``), `${route}: ${code}`);
      const [status, , retryAfter] = DELIVERY_ERRORS[code];
      assert.ok(text.includes(String(status)), `${route}: ${status} for ${code}`);
      if (retryAfter && code !== 'storage_full')
        assert.ok(text.includes(`Retry-After: ${retryAfter}`), `${route}: Retry-After of ${code}`);
    }
  }
  // Each of these routes takes only {} (400 invalid_request otherwise).
  assert.equal(
    (read('lib/http/routes/notifications.mjs').match(/emptyBody\(await body\(\)\);/g) ?? []).length,
    4
  );
  // Only JSON other than {} gets the code: the body reader refuses no body and a body that is
  // not JSON (400), and one over the routes' 1 KiB limit (413), before the route sees it, without
  // a code.
  const routes = read('lib/http/routes/notifications.mjs');
  assert.match(routes, /bodyLimit: 1024,/);
  assert.match(
    read('lib/http/body.mjs'),
    /super\('Request is too large'\);\n    this\.status = 413;/
  );
  for (const route of Object.keys(codes))
    assert.ok(
      row(route).includes(
        '400 `invalid_request` for JSON other than `{}` (400 without a code for no body or a body that is not JSON, 413 for one over 1 KiB; 415 without `Content-Type: application/json`)'
      ),
      route
    );
  // Read-only compatibility is a stable, state-neutral public error.
  const compatibility = deliveryError('signing_compatibility');
  const reason =
    'A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.';
  assert.equal(compatibility.status, 409);
  assert.equal(compatibility.message, reason);
  assert.equal(compatibility.retryAfter, undefined);
  for (const route of [
    '/api/notifications/channels/:id/resume',
    '/api/notifications/webhook/signing-secret',
  ]) {
    assert.ok(row(route).includes('409 `signing_compatibility`'));
    assert.ok(row(route).includes('no `Retry-After`'));
    assert.ok(row(route).includes(reason));
  }
  assert.ok(flat(read('docs/notifications.md')).includes(reason));
  assert.equal(deliveryError('signing_unavailable').status, 503);
  assert.equal(deliveryError('signing_unavailable').retryAfter, 60);
  assert.equal(deliveryError('signing_conflict').status, 409);
  assert.equal(deliveryError('signing_conflict').retryAfter, undefined);
  // The public key's read: its errors, and no secret in its answer.
  const publicKey = row('/api/notifications/webhook/public-key', 'GET');
  for (const code of ['webhook_not_configured', 'signing_unavailable']) {
    const [status, , retryAfter] = DELIVERY_ERRORS[code];
    assert.ok(publicKey.includes(`${status} \`${code}\``), code);
    if (retryAfter) assert.ok(publicKey.includes(`Retry-After: ${retryAfter}`), code);
  }
  assert.match(publicKey, /public material only/);
  assert.match(publicKey, /never a private key/);
  assert.match(publicKey, /Needs `notifications:read`; not recorded\./);
  assert.ok(!guide.includes('/api/notifications/webhook/signing-secret/reveal'));
});

test('docs: how long a stop can take is the sum of its bounded steps, in every place that says it', () => {
  const server = read('server.mjs');
  const number = pattern => {
    const match = pattern.exec(server);
    assert.ok(match, String(pattern));
    return Number(match[1]);
  };
  const flushMs = number(/const flushMs = Math\.min\(emailTimeoutMs, (\d+)\);/);
  const steps = [
    flushMs + number(/bounded\(alerting\.flush\(\{ timeoutMs: flushMs \}\), flushMs \+ (\d+)\)/),
    number(/bounded\(alerting\.stop\(\{ timeoutMs: \d+ \}\), (\d+)\)/),
    number(/jobs\.stop\(\{ timeoutMs: (\d+) \}\)/),
    number(/forced = setTimeout\(resolve, (\d+)\)/),
    number(/flushTimer = setTimeout\(resolve, (\d+)\)/),
    CLOSE_MS + number(/CLOSE_MS \+ (\d+)/),
  ];
  const total = steps.reduce((sum, ms) => sum + ms, 0) / 1000;
  assert.equal(Math.round(total), 36, `${steps.join(' + ')} ms`);
  assert.match(
    server,
    /The stop takes at most about 36 s \(delivery spec §6\.2\): notifications 9 s, the delivery\n {2}\/\/ service 7 s, jobs 2 s, open requests 10 s, sign-outs 5 s, the audit log 2\.5 s\./
  );
  assert.match(
    flat(read('docs/architecture.md')),
    /closes the audit log \(up to 2\.5 seconds\): about 36 seconds at most\./
  );
  assert.match(
    read('docs/installation.md'),
    new RegExp(
      `Uptime Goblin can take up to about 36 seconds to stop \\(up to ${flushMs / 1000} of them sending notifications still due`
    )
  );
  const compose = read('compose.yaml');
  assert.match(
    flat(compose),
    /Uptime Goblin sends waiting notifications \(up to 8 s\) and finishes open requests before it # stops, up to about 36 s in all/
  );
  // Compose's grace period, and systemd's default of 90 s, leave room for it.
  const grace = Number(/^ {4}stop_grace_period: (\d+)s$/m.exec(compose)?.[1]);
  assert.ok(grace > total, `stop_grace_period ${grace}s > ${total}s`);
  assert.doesNotMatch(read('deploy/uptime-goblin.service'), /TimeoutStopSec/);
  for (const file of ['docs/architecture.md', 'docs/installation.md', 'compose.yaml'])
    assert.doesNotMatch(read(file), /about 3[0-3] (seconds|s)\b/, file);
  assertLink('docs/installation.md', 'architecture.md#process-lifecycle');
});

// Docs audit, delivery 4: a channel's pause and its recovery are told on the other channel only
// as the alert switches allow (legacyAllows: Evaluate alerts, then Notify when an alert begins
// for the pause and Notify when a source recovers for the recovery). No text says it always is.
test('docs: the other channel hears of a pause and a recovery only as the alert switches allow', () => {
  const policy = read('lib/alerting/policy.mjs');
  assert.match(policy, /!settings\.enabled \|\|/);
  assert.match(policy, /\(event\.kind === 'firing' && !settings\.notifyOnAlert\)/);
  assert.match(policy, /\(event\.kind === 'resolved' && !settings\.notifyOnRecovery\)/);
  assert.ok(
    read('docs/troubleshooting.md').includes(
      'The other channel tells you when one pauses (while **Evaluate alerts** and **Notify when an alert begins** are on) and when it works again (while **Notify when a source recovers** is on too).'
    )
  );
  assert.ok(
    read('docs/configuration.md').includes(
      'when one pauses, the other tells you, and again when it works again, as those switches allow'
    )
  );
  const recovered =
    'hears that it works again (while **Evaluate alerts** and **Notify when a source recovers** are on)';
  assert.ok(read('docs/notifications.md').includes(recovered));
  const changelog = read('CHANGELOG.md');
  assert.ok(changelog.includes(recovered));
  assert.ok(changelog.includes('the other channel says so while the alert switches allow it'));
  for (const file of [
    'docs/troubleshooting.md',
    'docs/configuration.md',
    'docs/notifications.md',
    'CHANGELOG.md',
  ]) {
    const text = read(file);
    assert.doesNotMatch(
      text,
      /The other channel tells you when one pauses and when it works again\./,
      file
    );
    assert.doesNotMatch(text, /when one pauses, the other tells you\. /, file);
    assert.doesNotMatch(text, /hears that it works again\./, file);
  }
});

// Docs audit, delivery 2: security.md says who can read the signing key as the user guide does:
// the public-key route takes a session, which legacy Basic satisfies; the private key is never
// shown to anyone.
test('docs: security.md names legacy Basic among those who can read the public key, and says the private key is never shown', () => {
  const routes = read('lib/http/routes/notifications.mjs');
  assert.match(routes, /'\/api\/notifications\/webhook\/public-key'/);
  const security = flat(read('docs/security.md'));
  assert.ok(
    security.includes(
      '**Configure → Notifications → Show public key** shows it to any signed-in admin, and its API (`GET /api/notifications/webhook/public-key`, with the right to read notifications) to a script with the admin password while [legacy Basic](authentication.md#scripts-and-legacy-basic) is on.'
    )
  );
  assert.ok(
    security.includes(
      'The private key is sealed with the key and never leaves Uptime Goblin: no page, API answer, export, log line, audit entry or error holds it.'
    )
  );
  assert.ok(
    read('docs/notifications.md').includes(
      'so can a script with the admin password while [legacy Basic](authentication.md#scripts-and-legacy-basic) is on'
    )
  );
});

// Review F2: a key pair made in place of signing material holds the webhook until Resume. The
// docs quote the pause reason and the log line as the code has them, say that no probe ends that
// pause, and every page that tells what to do after the new key links to the section.
test('docs: a new signing key holds the webhook until Resume, quoted as the code says it, and every page links there', () => {
  const held = flat(
    section(read('docs/notifications.md'), '#### A new signing key waits for Resume')
  );
  assert.ok(held.includes(`pauses the webhook with "${SIGNING_HOLD_REASON}"`));
  const unsaved =
    'The new webhook signing key could not be saved (${reason}); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds.';
  assert.ok(read('lib/alerting/signing.mjs').includes(unsaved));
  assert.ok(held.includes(`("${unsaved.replace('${reason}', '…')}")`));
  assert.ok(held.includes('No probe ends this pause, also not at a restart'));
  assert.ok(
    held.includes(
      'press **Resume** (`POST /api/notifications/channels/env-webhook/resume` for scripts)'
    )
  );
  assert.match(
    read('lib/http/routes/notifications.mjs'),
    /'\/api\/notifications\/channels\/:id\/resume'/
  );
  assert.ok(
    flat(read('docs/notifications.md')).includes(
      'at every start Uptime Goblin sends one probe on each paused channel, whatever the cause, so a fix made while Uptime Goblin was stopped is found at once (except a webhook held for a new signing key, which only **Resume** ends: [below](#a-new-signing-key-waits-for-resume));'
    )
  );
  assert.ok(
    read('docs/troubleshooting.md').includes(
      `| "Webhook is paused: ${SIGNING_HOLD_REASON.split(' may not have')[0]} may not have…" |`
    )
  );
  for (const file of ['docs/troubleshooting.md', 'docs/security.md'])
    assertLink(file, 'notifications.md#a-new-signing-key-waits-for-resume');
  assertLink('CHANGELOG.md', 'docs/notifications.md#a-new-signing-key-waits-for-resume');
  assertLink('docs/notifications.md', '#a-new-signing-key-waits-for-resume');
});

// Review SEC-2: the installer's rollback fence stops only a 1.5 pre-release build that signs with
// an HMAC secret (or cannot be told apart from one); a 1.5 pre-release build that already signs
// with Ed25519 (the public-key route, no reveal route) is restored and started as any earlier
// release. On data this release saved in its form (schema 2), such a build reads the signing
// settings read-only and sends webhooks unsigned. The notes said the rollback never starts any
// earlier pre-release build; they now name both cases.
test('docs: the rollback fence keeps only HMAC pre-release builds stopped; an Ed25519 one is restored and sends webhooks unsigned on this release’s data (SEC-2)', () => {
  // The fence lets through, to the ordinary rollback, a build with the public-key route and
  // without the reveal route.
  const installer = read('deploy/install.sh');
  assert.ok(installer.includes('if(publicKey&&!reveal)process.exit(0);'));
  assert.ok(
    installer.includes(`publicKey||=text.includes("'/api/notifications/webhook/public-key'");`)
  );
  const texts = {
    'CHANGELOG.md (1.5)': flat(unreleased()),
    'docs/installation.md': flat(read('docs/installation.md')),
    'docs/notifications.md': flat(read('docs/notifications.md')),
  };
  for (const [name, text] of Object.entries(texts)) {
    // No text says the rollback never starts any earlier 1.5 pre-release build.
    assert.doesNotMatch(
      text,
      /rollback never starts such a build, with or without|An earlier 1\.5 pre-release build is never started by the rollback/,
      name
    );
    assert.ok(text.includes('pre-release build that already signs with Ed25519'), name);
    assert.match(
      text,
      /pre-release build that already signs with Ed25519[^.]*?sends webhooks unsigned[^]*?until this release runs again or the data from before the upgrade is restored/,
      name
    );
  }
  assert.ok(
    texts['docs/installation.md'].includes(
      '**An earlier 1.5 pre-release build that signs webhooks with an HMAC secret is never started by the rollback, with or without a webhook.**'
    )
  );
  // The log line the restored build prints, as the Ed25519 pre-release builds print it.
  assert.ok(
    texts['docs/installation.md'].includes(
      '"The webhook signing key could not be saved (…); alerts are sent unsigned until it can be."'
    )
  );
  assertLink('docs/notifications.md', 'installation.md#verification-and-automatic-rollback');
});
