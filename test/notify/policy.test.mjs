// The channel contract, retry/backoff and dead-letter policy, and webhook signing.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { historyFiles, root } from '../upgrade/fixtures.mjs';
import {
  accepted,
  retry,
  failed,
  unknown,
  pause,
  skipped,
  normaliseOutcome,
  defineChannel,
  safeReason,
  OUTCOME_TYPES,
} from '../../lib/notify/channel.mjs';
import {
  DELIVERY_POLICY,
  backoffMs,
  parseRetryAfter,
  retryDelayMs,
  circuitDelayMs,
  maxAgeMs,
} from '../../lib/notify/retry.mjs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import {
  signWebhook,
  signWebhookAll,
  verifyWebhookSignature,
  validateSigningKey,
  isSigningKey,
  normalizeSigningKey,
  generateSigningKey,
  publicSigningKey,
} from '../../lib/notify/sign.mjs';

// The test vector of docs/notifications.md: the first test key of RFC 8032 (section 7.1), a
// published key nobody uses for anything real, as the PKCS#8 PEM Uptime Goblin seals.
const rfc8032 = createPrivateKey({
  key: {
    kty: 'OKP',
    crv: 'Ed25519',
    d: Buffer.from(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      'hex'
    ).toString('base64url'),
    x: Buffer.from(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      'hex'
    ).toString('base64url'),
  },
  format: 'jwk',
}).export({ type: 'pkcs8', format: 'pem' });
const vector = {
  publicKey:
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n',
  publicKeyRaw: '11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
  keyId: '21fe31dfa154a261',
  header:
    't=1800000000,v1a=21fe31dfa154a261:e6bd05a7d32a1aa5280efe20ea563ffa5c98a9fc98110f1fd524c8384eb7781014e2badde775f0ed86e8b6be2f6715161a21fe471875dcdd5c1b564116eb8a0a',
};

test('outcomes are the C-JOB set plus unknown, pause and skipped, with safe reasons', () => {
  assert.deepEqual(OUTCOME_TYPES, ['accepted', 'retry', 'failed', 'unknown', 'pause', 'skipped']);
  assert.deepEqual(accepted({ status: 202, externalRef: 'INC0012345' }), {
    type: 'accepted',
    status: 202,
    externalRef: 'INC0012345',
  });
  assert.deepEqual(retry(1500.4, 'busy', { status: 503 }), {
    type: 'retry',
    afterMs: 1500,
    reason: 'busy',
    status: 503,
  });
  assert.equal(retry(-1).afterMs, null);
  assert.equal(retry(NaN).afterMs, null);
  assert.equal(failed('no', { status: 99 }).status, null);
  for (const make of [failed, unknown, pause, skipped]) assert.equal(make('x').reason, 'x');
  // Reasons never carry URLs (webhook paths hold secrets), control characters or bidi overrides.
  assert.equal(
    safeReason('POST https://hooks.slack.com/services/T/B/secret\r\nfailed \u202e now'),
    'POST [url] failed now'
  );
  assert.equal(safeReason('x'.repeat(500)).length, 300);
  // The outbox refuses text it cannot store (an unpaired surrogate, a NUL) at bind: a cut
  // between the halves of a pair, half a pair in the text and a NUL in a reference are made
  // storable instead, so the completion that records them is never refused.
  assert.equal(safeReason('a' + '😀'.repeat(200)), 'a' + '😀'.repeat(149) + '\ufffd');
  assert.equal(safeReason('half \ud800 pair'), 'half \ufffd pair');
  assert.equal(accepted({ externalRef: 'ref\u0000\udc00' }).externalRef, 'ref\ufffd');
  assert.equal(accepted({ externalRef: '😀'.repeat(150) }).externalRef, '😀'.repeat(100));
  assert.equal(accepted({ externalRef: 'x' + '😀'.repeat(150) }).externalRef.isWellFormed(), true);
  // Whatever a channel returns becomes a valid outcome; anything unknown is a retry.
  assert.deepEqual(normaliseOutcome({ type: 'accepted' }), accepted());
  assert.equal(normaliseOutcome({ type: 'retry', afterMs: 5 }).afterMs, 5);
  assert.equal(
    normaliseOutcome({ type: 'pause', reason: '' }).reason,
    'The channel needs attention.'
  );
  for (const odd of [undefined, null, 'ok', { type: 'delivered' }, { ok: true }])
    assert.equal(normaliseOutcome(odd).type, 'retry', JSON.stringify(odd));
  // A pause says whether its cause may clear by itself (D10); normalising keeps it, a boolean.
  assert.deepEqual(pause('401', { status: 401, transient: true }), {
    type: 'pause',
    reason: '401',
    status: 401,
    transient: true,
  });
  assert.equal(pause('EAUTH').transient, false);
  assert.equal(normaliseOutcome({ type: 'pause', reason: 'x', transient: true }).transient, true);
  assert.equal(normaliseOutcome({ type: 'pause', reason: 'x', transient: 'yes' }).transient, false);
});

test('defineChannel validates the channel contract', () => {
  const send = async () => accepted();
  assert.equal(defineChannel({ name: 'email', send }).concurrency, 1);
  assert.throws(() => defineChannel({ name: 'Bad Name', send }), /name/);
  assert.throws(() => defineChannel({ name: 'x' }), /send/);
  assert.throws(() => defineChannel({ name: 'x', send, concurrency: 5 }), /concurrency/);
  assert.throws(() => defineChannel({ name: 'x', send, digest: { windowMs: 0 } }), /digest/);
  assert.throws(
    () => defineChannel({ name: 'x', send, unknown: { resendAfterMs: 1, maxResends: 1.5 } }),
    /unknown/
  );
  assert.throws(() => defineChannel({ name: 'x', send, maxAgeMs: -1 }), /maxAgeMs/);
  assert.ok(Object.isFrozen(defineChannel({ name: 'x', send })));
});

test('backoff is min(15 min, 30 s × 2^(n−1)) × U(0.5, 1)', () => {
  const low = () => 0,
    high = () => 1;
  assert.equal(DELIVERY_POLICY.baseMs, 30000);
  assert.deepEqual(
    [1, 2, 3, 4, 5, 6, 7].map(n => backoffMs(n, { rng: high })),
    [30000, 60000, 120000, 240000, 480000, 900000, 900000]
  );
  assert.deepEqual(
    [1, 2, 6].map(n => backoffMs(n, { rng: low })),
    [15000, 30000, 450000]
  );
  // Bounds hold for any draw, including a broken random source.
  for (let n = 1; n < 60; n++) {
    const value = backoffMs(n);
    const ceiling = Math.min(900000, 30000 * 2 ** (n - 1));
    assert.ok(value >= ceiling / 2 && value <= ceiling, `attempt ${n}: ${value}`);
  }
  assert.equal(backoffMs(0, { rng: high }), 30000);
  assert.equal(backoffMs(3, { rng: () => 7 }), 120000);
  assert.equal(backoffMs(3, { rng: () => NaN }), 60000);
});

test('Retry-After is read in every form and wins only when longer, up to an hour', () => {
  const now = Date.parse('2027-01-15T10:00:00Z');
  assert.equal(parseRetryAfter('120', now), 120000);
  assert.equal(parseRetryAfter(' 7 ', now), 7000);
  assert.equal(parseRetryAfter('1.25', now), 1250); // Discord's float
  assert.equal(parseRetryAfter(3, now), 3000); // Telegram's retry_after
  assert.equal(parseRetryAfter(['30'], now), 30000);
  assert.equal(parseRetryAfter('Fri, 15 Jan 2027 10:02:00 GMT', now), 120000);
  assert.equal(parseRetryAfter('Fri, 15 Jan 2027 09:00:00 GMT', now), 0);
  for (const bad of [undefined, null, '', '-5', 'soon', '1e3', 'NaN', -1, Infinity, '2027-01-15'])
    assert.equal(parseRetryAfter(bad, now), null, String(bad));

  const high = () => 1;
  assert.equal(retryDelayMs({ attempt: 1, rng: high }), 30000);
  assert.equal(retryDelayMs({ attempt: 1, afterMs: 5000, rng: high }), 30000);
  assert.equal(retryDelayMs({ attempt: 1, afterMs: 120000, rng: high }), 120000);
  assert.equal(retryDelayMs({ attempt: 1, afterMs: 24 * 3600000, rng: high }), 3600000);
  assert.equal(retryDelayMs({ attempt: 7, afterMs: 60000, rng: high }), 900000);
});

test('the circuit opens after 5 consecutive failures, doubling from 60 s up to 15 min', () => {
  assert.deepEqual(
    [0, 4, 5, 6, 7, 8, 9, 10, 50].map(n => circuitDelayMs(n)),
    [0, 0, 60000, 120000, 240000, 480000, 900000, 900000, 900000]
  );
  assert.equal(circuitDelayMs(2, { circuitAfter: 2, circuitBaseMs: 10 }), 10);
});

test('the maximum age is 1-168 hours, 24 by default', () => {
  assert.equal(maxAgeMs(), 24 * 3600000);
  assert.equal(maxAgeMs(1), 3600000);
  assert.equal(maxAgeMs(168), 168 * 3600000);
  for (const bad of [0, 169, 1.5, '24', null]) assert.throws(() => maxAgeMs(bad), RangeError);
});

test('webhook signatures follow t=<unix>,v1a=<key id>:Ed25519(private key, "<delivery id>.<t>.<body>")', () => {
  const deliveryId = 'd_abcdefghijklmnopqrstuvwxyz',
    body = '{"source":"orbit","kind":"firing"}',
    nowMs = 1800000000000;
  // Ed25519 signatures are deterministic: the documented vector, with the RFC 8032 key.
  assert.deepEqual(publicSigningKey(rfc8032), {
    algorithm: 'Ed25519',
    keyId: vector.keyId,
    publicKey: vector.publicKey,
    publicKeyRaw: vector.publicKeyRaw,
  });
  const header = signWebhook(rfc8032, body, { nowMs, deliveryId });
  assert.equal(header, vector.header);
  const publicKey = vector.publicKey;
  const check = (options = {}) => ({ nowMs, deliveryId, ...options });
  // The public key as PEM, as a KeyObject or as its raw 32 bytes.
  for (const key of [
    publicKey,
    createPublicKey(publicKey),
    Buffer.from(vector.publicKeyRaw, 'base64'),
  ])
    assert.deepEqual(verifyWebhookSignature(key, body, header, check()), { ok: true });
  assert.deepEqual(verifyWebhookSignature(publicKey, Buffer.from(body), header, check()), {
    ok: true,
  });
  // The delivery id is signed: the same signature under another id is a mismatch, so a replay
  // under a new X-Goblin-Delivery cannot pass a receiver that drops repeats (D7).
  assert.equal(
    verifyWebhookSignature(
      publicKey,
      body,
      header,
      check({ deliveryId: 'd_bbcdefghijklmnopqrstuvwxyz' })
    ).reason,
    'mismatch'
  );
  // Receivers reject a changed body, another key, and anything over 5 minutes old or ahead.
  assert.equal(verifyWebhookSignature(publicKey, body + ' ', header, check()).reason, 'mismatch');
  const another = publicSigningKey(generateSigningKey()).publicKey;
  assert.equal(verifyWebhookSignature(another, body, header, check()).reason, 'mismatch');
  // A signature under this key id but changed in one digit is a mismatch too.
  const flipped = header.replace(/.$/, c => (c === '0' ? '1' : '0'));
  assert.equal(verifyWebhookSignature(publicKey, body, flipped, check()).reason, 'mismatch');
  assert.equal(
    verifyWebhookSignature(publicKey, body, header, check({ nowMs: nowMs + 300001 })).reason,
    'expired'
  );
  assert.equal(
    verifyWebhookSignature(publicKey, body, header, check({ nowMs: nowMs - 300001 })).reason,
    'expired'
  );
  assert.equal(
    verifyWebhookSignature(publicKey, body, header, check({ nowMs: nowMs + 300000 })).ok,
    true
  );
  for (const bad of ['', 'v1a=abc', 't=1,t=2,v1a=00', 't=x,v1a=00', 't=1800000000'])
    assert.equal(verifyWebhookSignature(publicKey, body, bad, check()).reason, 'malformed', bad);
  // The HMAC form of earlier pre-release builds is no signature at all now.
  assert.equal(
    verifyWebhookSignature(publicKey, body, `t=1800000000,v1=${'0'.repeat(64)}`, check()).reason,
    'malformed'
  );
  // A missing or malformed delivery id: signing refuses, verifying says malformed.
  for (const id of [undefined, '', 'has space', 'x'.repeat(65), 'd_abc.def']) {
    assert.throws(
      () => signWebhook(rfc8032, body, { nowMs, deliveryId: id }),
      TypeError,
      String(id)
    );
    assert.equal(
      verifyWebhookSignature(publicKey, body, header, { nowMs, deliveryId: id }).reason,
      'malformed',
      String(id)
    );
  }
  // During a rotation a sender includes signatures made with the old and the new key; values
  // that are not a key id and a signature are passed over.
  const old = signWebhook(generateSigningKey(), body, { nowMs, deliveryId }).split(',')[1];
  assert.equal(verifyWebhookSignature(publicKey, body, `${header},${old}`, check()).ok, true);
  assert.equal(
    verifyWebhookSignature(publicKey, body, `t=1800000000,v1a=zz,${header.split(',')[1]}`, check())
      .ok,
    true
  );
  // Verifying needs an Ed25519 public key.
  assert.throws(
    () => verifyWebhookSignature('orbit-test-signing-secret-0001', body, header, check()),
    TypeError
  );
});

test('signWebhookAll signs with every key, the current one first, each with its key id', () => {
  const body = '{"source":"orbit","kind":"resolved"}',
    nowMs = 1800000123456,
    deliveryId = 'd_abcdefghijklmnopqrstuvwxyz';
  const current = generateSigningKey(),
    previous = generateSigningKey();
  const one = signWebhookAll([current], body, { nowMs, deliveryId });
  assert.equal(one, signWebhook(current, body, { nowMs, deliveryId }));
  const two = signWebhookAll([current, previous], body, { nowMs, deliveryId });
  const [t, first, second] = two.split(',');
  assert.equal(t, 't=1800000123');
  assert.equal(`${t},${first}`, one);
  assert.equal(second, signWebhook(previous, body, { nowMs, deliveryId }).split(',')[1]);
  assert.equal(first.slice(4, 20), publicSigningKey(current).keyId);
  assert.equal(second.slice(4, 20), publicSigningKey(previous).keyId);
  // A receiver with either public key verifies; one with neither does not.
  for (const key of [current, previous])
    assert.deepEqual(
      verifyWebhookSignature(publicSigningKey(key).publicKey, body, two, { nowMs, deliveryId }),
      { ok: true }
    );
  assert.equal(
    verifyWebhookSignature(publicSigningKey(generateSigningKey()).publicKey, body, two, {
      nowMs,
      deliveryId,
    }).reason,
    'mismatch'
  );
  assert.throws(() => signWebhookAll([], body, { nowMs, deliveryId }), RangeError);
  assert.throws(() => signWebhookAll(['a'.repeat(64)], body, { nowMs, deliveryId }), RangeError);
});

test('signing keys are Ed25519 private keys as PKCS#8 PEM, and the refusal never quotes one', () => {
  const pem = generateSigningKey();
  assert.match(
    pem,
    /^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=]{64}\n-----END PRIVATE KEY-----\n$/
  );
  assert.equal(validateSigningKey(pem).asymmetricKeyType, 'ed25519');
  assert.equal(isSigningKey(pem), true);
  const { privateKey: rsa } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  for (const bad of [
    '',
    'a'.repeat(64), // the HMAC secret of an earlier pre-release build
    `${pem}\n`,
    ` ${pem}`,
    publicSigningKey(pem).publicKey,
    rsa.export({ type: 'pkcs8', format: 'pem' }),
    null,
    undefined,
    42,
  ]) {
    assert.equal(isSigningKey(bad), false, String(bad));
    assert.throws(
      () => validateSigningKey(bad),
      error =>
        error instanceof RangeError &&
        error.message === 'The webhook signing key must be an Ed25519 private key (PKCS#8 PEM).'
    );
  }
  assert.throws(() => signWebhook('short', 'body', { deliveryId: 'd_x' }), RangeError);
});

// A stored Ed25519 key in another PEM form is the same key: Uptime Goblin rewrites it in its own form and
// keeps it (lib/alerting/signing.mjs). Anything else is no signing key, and nothing quotes it.
test('normalizeSigningKey rewrites an Ed25519 private key in another PEM form, and refuses everything else', () => {
  const pem = generateSigningKey();
  for (const form of [
    pem,
    `${pem}\n\n`,
    ` ${pem}`,
    `\t${pem}  `,
    pem.replace(/\n/g, '\r\n'),
    pem.trimEnd(),
  ])
    assert.equal(normalizeSigningKey(form), pem, JSON.stringify(form.slice(0, 3)));
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey;
  const encrypted = createPrivateKey(pem).export({
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'orbit-test',
  });
  for (const bad of [
    'a'.repeat(64), // the HMAC secret of an earlier pre-release build
    'not a key',
    '',
    publicSigningKey(pem).publicKey,
    rsa.export({ type: 'pkcs8', format: 'pem' }),
    encrypted,
    `${pem}${' '.repeat(16384)}`,
    createPrivateKey(pem),
    null,
    undefined,
    42,
  ])
    assert.equal(
      normalizeSigningKey(bad),
      null,
      typeof bad === 'string' ? bad.slice(0, 40) : String(bad)
    );
});

// docs/notifications.md tells webhook receivers to check X-Goblin-Signature, with a verifier that
// rejects a request without it. 1.4.x sends its webhooks without X-Goblin-Delivery and
// X-Goblin-Signature, once, never retrying (the upgrade suite's F3 sees this from the real
// v1.4.3), so during a rollback such a receiver rejects every alert and each is lost. The
// rollback docs must say so before the rollback, not leave "needs no preparation".
test('the documented verifier rejects the unsigned requests of 1.4.x, and the rollback docs say to accept them first', async t => {
  const read = name => fs.readFileSync(path.join(root, name), 'utf8');
  const guide = read('docs/notifications.md');
  const code = /```js\n([\s\S]*?export function verifyUptimeGoblin[\s\S]*?)```/.exec(guide)?.[1];
  assert.ok(code, 'docs/notifications.md has the Node.js verifier');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-verifier-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'verify.mjs'), code);
  const { verifyUptimeGoblin } = await import(
    pathToFileURL(path.join(directory, 'verify.mjs')).href
  );
  const deliveryId = 'd_abcdefghijklmnopqrstuvwxyz',
    nowMs = 1800000000000,
    body = JSON.stringify({ source: 'orbit', service: 'linux-1', kind: 'firing', time: nowMs });
  const current = generateSigningKey(),
    previous = generateSigningKey();
  const keysOf = (...privateKeys) =>
    Object.fromEntries(
      privateKeys.map(key => [publicSigningKey(key).keyId, publicSigningKey(key).publicKey])
    );
  const signed = (privateKeys, text = body) => ({
    'content-type': 'application/json',
    'x-goblin-delivery': deliveryId,
    'x-goblin-signature': signWebhookAll(privateKeys, text, { nowMs, deliveryId }),
  });
  assert.equal(
    verifyUptimeGoblin(keysOf(current), signed([current]), body, nowMs),
    true,
    '1.5 passes'
  );
  assert.equal(
    verifyUptimeGoblin(keysOf(current), signed([current]), Buffer.from(body), nowMs),
    true
  );
  // During a rotation: a receiver with either public key passes; one with neither does not.
  for (const key of [current, previous])
    assert.equal(verifyUptimeGoblin(keysOf(key), signed([current, previous]), body, nowMs), true);
  assert.equal(
    verifyUptimeGoblin(keysOf(generateSigningKey()), signed([current, previous]), body, nowMs),
    false
  );
  assert.equal(verifyUptimeGoblin(keysOf(current), signed([current]), `${body} `, nowMs), false);
  assert.equal(verifyUptimeGoblin(keysOf(current), signed([current]), body, nowMs + 300001), false);
  // The documented test vector.
  assert.equal(
    verifyUptimeGoblin(
      { [vector.keyId]: vector.publicKey },
      { 'x-goblin-delivery': deliveryId, 'x-goblin-signature': vector.header },
      '{"source":"orbit","kind":"firing"}',
      nowMs
    ),
    true
  );
  assert.ok(guide.includes(`the header is \`${vector.header}\``));
  assert.ok(guide.includes(`its key id is \`${vector.keyId}\``));
  assert.ok(guide.includes(`\`${vector.publicKeyRaw}\` (raw, base64)`));
  assert.ok(guide.includes(vector.publicKey.split('\n')[1]));
  assert.equal(
    verifyUptimeGoblin(keysOf(current), { 'content-type': 'application/json' }, body, nowMs),
    false,
    "1.4.x's request (the same body, no Uptime Goblin headers) is rejected"
  );
  // What v1.4.3 sends, from its own source where the private history has the tag.
  const tagged = historyFiles('v1.4.3');
  if (tagged) {
    const server = tagged.files.get('server.mjs').toString('utf8');
    const sender = server.slice(server.indexOf('async function notifyWebhook'));
    assert.match(sender.slice(0, 600), /headers: \{ 'Content-Type': 'application\/json' \}/);
    assert.doesNotMatch(server, /X-Goblin-Signature|X-Goblin-Delivery/);
  }

  const section = (text, heading) => {
    const start = text.indexOf(heading);
    assert.ok(start >= 0, heading);
    const end = text.indexOf('\n## ', start + heading.length);
    const next = text.indexOf('\n### ', start + heading.length);
    return text.slice(start, Math.min(...[end, next].filter(at => at > 0), text.length));
  };
  const said = [
    [
      'docs/installation.md',
      section(read('docs/installation.md'), '### Rolling back 1.5 to 1.4.3'),
    ],
    ['docs/notifications.md', section(guide, '## Rolling back to 1.4.x and upgrading again')],
    [
      'CHANGELOG.md',
      /^- \*\*Rolling back to 1\.4\.3 or 1\.4\.2 needs no preparation of the data, but webhook receivers.*$/m.exec(
        read('CHANGELOG.md')
      )?.[0] ?? '',
    ],
  ];
  for (const [name, text] of said) {
    assert.match(text, /without `X-Goblin-Delivery` and `X-Goblin-Signature`/, name);
    assert.match(
      text,
      /accept (Uptime Goblin's )?unsigned requests|accept requests without them/,
      name
    );
    assert.match(text, /never retr(y|ies)/, name);
    assert.match(text, /turn the check back on/i, name);
  }
  // The bullets that said "needs no preparation" now say what does need it.
  assert.doesNotMatch(read('CHANGELOG.md'), /needs no preparation\.\*\*/);
  assert.doesNotMatch(read('docs/installation.md'), /1\.4\.2 needs no preparation and/);
});

// Receivers copy the Python verifier as written. It checked t with str.isdigit(), which is true
// for "¹", "²" and "³" (what a WSGI or ASGI server makes of the bytes 0xB9, 0xB2 and 0xB3, as it
// decodes headers as Latin-1), but int() refuses them: anyone who could reach the receiver made
// it raise ValueError (a 500, or a crashed script) without the secret. Python 3.11 and later
// also refuse int() of more than 4300 digits (delivery spec A49).
// It also took each public key as raw bytes in base64, while Show public key shows only the PEM:
// given what the page shows, it raised an error on every request (review SIGN-2). It takes the PEM
// now, as the Node.js example does, and a PEM that holds another kind of key never verifies.
test('the documented Python verifier takes the PEM Show public key shows, answers False, never an error, for a t that is not ASCII digits, and passes the test vector', async t => {
  const guide = fs.readFileSync(path.join(root, 'docs/notifications.md'), 'utf8');
  const code = /```python\n([\s\S]*?def verify_uptime_goblin[\s\S]*?)```/.exec(guide)?.[1];
  assert.ok(code, 'docs/notifications.md has the Python verifier');
  // Checked here wherever the tests run, python3 or not: t must be ASCII digits, and few enough.
  assert.doesNotMatch(code, /\bt\.is(digit|decimal|numeric)\(/);
  assert.match(code, /not re\.fullmatch\(r"\[0-9\]\{1,12\}", t\)/);
  // The keys are PEM text, as the page shows them, and only an Ed25519 key is used.
  assert.match(code, /serialization\.load_pem_public_key\(keys\[entry\.group\(1\)\]\.encode\(\)\)/);
  assert.match(code, /if not isinstance\(public_key, Ed25519PublicKey\):/);
  assert.doesNotMatch(code, /b64decode|from_public_bytes/);
  assert.match(code, /keys: \{key id: public key PEM \(str\)\}, as Show public key gives them/);
  // The guide says which form each example takes, and where the other form is.
  assert.ok(
    guide.includes(
      "Both examples take each public key as PEM text, the form **Show public key** shows and `publicKey` in the answer of `GET /api/notifications/webhook/public-key` (below). That answer's `publicKeyRaw` is the same key as its raw 32 bytes in base64, for a library that wants that form."
    )
  );
  assert.match(
    guide,
    /\*\*Show public key\*\* on the webhook's card shows it \(PEM\) with its key id/
  );
  // load_pem_public_key() without a backend argument needs cryptography 3.1 or later (2.6 to 3.0
  // have Ed25519 but require the argument, so the example would raise on every signed request).
  assert.ok(guide.includes('Python (with the `cryptography` package, 3.1 or later):'));

  // Run under python3 with the cryptography package the guide names, or, where that package is
  // not installed, with a stand-in for it that accepts exactly the (public key, signature,
  // signed bytes) triples Node's Ed25519 verify accepted: the guide's own parsing, choice of key
  // and signed bytes run either way, and only the curve arithmetic is Node's then.
  const python = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  const realPackage =
    python.status === 0 &&
    spawnSync('python3', ['-c', 'import cryptography'], { encoding: 'utf8' }).status === 0;
  await t.test(
    `under python3 (${realPackage ? 'the cryptography package' : 'a stand-in for the cryptography package'})`,
    { skip: python.status === 0 ? false : 'no python3' },
    s => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-verifier-py-'));
      s.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      const deliveryId = 'd_abcdefghijklmnopqrstuvwxyz',
        now = 1800000000;
      const current = generateSigningKey(),
        previous = generateSigningKey();
      // The public keys as Show public key shows them (and the API's `publicKey`): PEM.
      const pemKeys = (...privateKeys) =>
        Object.fromEntries(
          privateKeys.map(key => [publicSigningKey(key).keyId, publicSigningKey(key).publicKey])
        );
      const sample = (keys, signature, body = '{"source":"orbit","kind":"firing"}') => ({
        keys,
        headers: { 'X-Goblin-Delivery': deliveryId, 'X-Goblin-Signature': signature },
        body,
        now,
      });
      const vectorKeys = { [vector.keyId]: vector.publicKey };
      const zeros = `v1a=${vector.keyId}:${'0'.repeat(128)}`;
      const signedBy = (privateKeys, body) =>
        signWebhookAll(privateKeys, body, { nowMs: now * 1000, deliveryId });
      const rsaPublic = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({
        type: 'spki',
        format: 'pem',
      });
      const cases = [
        // The documented test vector, and requests Uptime Goblin signs (one key, and two in a rotation
        // for a receiver that has only the previous public key).
        sample(vectorKeys, vector.header),
        sample(pemKeys(current), signedBy([current], '{"kind":"resolved"}'), '{"kind":"resolved"}'),
        sample(pemKeys(previous), signedBy([current, previous], '{"a":1}'), '{"a":1}'),
        // Refused: another key, a changed body, a changed signature, the HMAC form.
        sample(pemKeys(generateSigningKey()), signedBy([current], '{"a":1}'), '{"a":1}'),
        sample(pemKeys(current), signedBy([current], '{"a":1}'), '{"a":2}'),
        sample(
          vectorKeys,
          vector.header.replace(/.$/, c => (c === '0' ? '1' : '0'))
        ),
        sample(vectorKeys, `t=1800000000,v1=${'0'.repeat(64)}`),
        // A PEM that holds another kind of key (RSA) under the key id: refused, not an error.
        sample({ [vector.keyId]: rsaPublic }, vector.header),
        // Forged: Latin-1 superscripts, other Unicode digits, too many digits, spaces, nothing.
        ...['¹', '²', '³', '1²', '①', '٣', '1'.repeat(5000), ' 1800000000', ''].map(value =>
          sample(vectorKeys, `t=${value},${zeros}`)
        ),
      ];
      const expected = [true, true, true, ...Array(cases.length - 3).fill(false)];
      fs.writeFileSync(path.join(directory, 'cases.json'), JSON.stringify(cases));
      fs.writeFileSync(
        path.join(directory, 'verify.py'),
        `${code}
import json, sys
results = []
for case in json.load(open(sys.argv[1], encoding="utf-8")):
    try:
        results.append(verify_uptime_goblin(case["keys"], case["headers"], case["body"].encode(), case["now"]))
    except Exception as error:
        results.append(f"raised {type(error).__name__}: {error}")
print(json.dumps(results))
`
      );
      const env = { ...process.env };
      if (!realPackage) {
        // The triples Node accepts, for the stand-in: each v1a of each case, with its own key.
        const valid = [];
        for (const item of cases) {
          const header = item.headers['X-Goblin-Signature'];
          const t = /(?:^|,)t=(\d{1,12})(?:,|$)/.exec(header)?.[1];
          if (!t) continue;
          const data = Buffer.from(`${deliveryId}.${t}.${item.body}`);
          for (const [, keyId, signature] of header.matchAll(
            /v1a=([0-9a-f]{16}):([0-9a-f]{128})/g
          )) {
            if (!item.keys[keyId]) continue;
            const key = createPublicKey(item.keys[keyId]);
            if (key.asymmetricKeyType !== 'ed25519') continue;
            const raw = Buffer.from(key.export({ format: 'jwk' }).x, 'base64url');
            if (verify(null, data, key, Buffer.from(signature, 'hex')))
              valid.push([raw.toString('hex'), signature, data.toString('hex')]);
          }
        }
        assert.equal(valid.length, 3, 'Node accepts the three signed requests');
        fs.writeFileSync(path.join(directory, 'valid.json'), JSON.stringify(valid));
        const stub = path.join(directory, 'stub');
        const primitives = path.join(stub, 'cryptography', 'hazmat', 'primitives');
        const asymmetric = path.join(primitives, 'asymmetric');
        fs.mkdirSync(asymmetric, { recursive: true });
        for (const dir of ['', 'hazmat', 'hazmat/primitives', 'hazmat/primitives/asymmetric'])
          fs.writeFileSync(path.join(stub, 'cryptography', dir, '__init__.py'), '');
        fs.writeFileSync(
          path.join(stub, 'cryptography', 'exceptions.py'),
          'class InvalidSignature(Exception):\n    pass\n'
        );
        fs.writeFileSync(
          path.join(asymmetric, 'ed25519.py'),
          `import json
from cryptography.exceptions import InvalidSignature
VALID = {tuple(item) for item in json.load(open(${JSON.stringify(path.join(directory, 'valid.json'))}))}

class Ed25519PublicKey:
    def __init__(self, raw):
        self.raw = raw

    @classmethod
    def from_public_bytes(cls, data):
        if len(data) != 32:
            raise ValueError("An Ed25519 public key is 32 bytes long.")
        return cls(bytes(data))

    def verify(self, signature, data):
        if (self.raw.hex(), signature.hex(), data.hex()) not in VALID:
            raise InvalidSignature()
`
        );
        // load_pem_public_key as the package has it from 3.1 (the backend argument optional; the
        // guide names that version): bytes only (str is a TypeError), one PEM
        // public key (SubjectPublicKeyInfo), an Ed25519PublicKey for an Ed25519 key, another
        // object for another kind of key (whose verify, like RSA's, needs more arguments), and a
        // ValueError for anything else (such as the raw key in base64).
        fs.writeFileSync(
          path.join(primitives, 'serialization.py'),
          `import base64, re
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")

class OtherPublicKey:
    def verify(self, signature, data, padding, algorithm):
        raise AssertionError("never called with an Ed25519 signature")

def load_pem_public_key(data, backend=None):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes")
    found = re.fullmatch(
        rb"\\s*-----BEGIN PUBLIC KEY-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END PUBLIC KEY-----\\s*",
        bytes(data),
    )
    if not found:
        raise ValueError("Could not deserialize key data.")
    der = base64.b64decode(found.group(1), validate=False)
    if der.startswith(ED25519_SPKI) and len(der) == len(ED25519_SPKI) + 32:
        return Ed25519PublicKey(der[len(ED25519_SPKI):])
    if der[:1] == b"\\x30":
        return OtherPublicKey()
    raise ValueError("Could not deserialize key data.")
`
        );
        env.PYTHONPATH = stub;
      }
      const run = spawnSync(
        'python3',
        [path.join(directory, 'verify.py'), path.join(directory, 'cases.json')],
        { encoding: 'utf8', env }
      );
      assert.equal(run.status, 0, run.stderr);
      assert.deepEqual(JSON.parse(run.stdout), expected);
    }
  );
});

// The pinned pre-upgrade snapshot, which the rollback docs restore for the data of before the
// upgrade, was taken before 1.5 created control.sqlite; restoring it (or a deploy tarball of
// that time) removes control.sqlite, so the waiting notifications are never sent nor listed, and
// the next start makes a new signing key (test/upgrade/delivery.test.mjs P1 shows it with
// real releases). The docs had promised those notifications after upgrading again, and said to
// turn the receivers' check back on, which the old public key then fails (review round 2).
test('the rollback docs say that restoring the data from before the upgrade takes the waiting notifications and the signing key', () => {
  const read = name => fs.readFileSync(path.join(root, name), 'utf8');
  const section = (text, heading) => {
    const start = text.indexOf(heading);
    assert.ok(start >= 0, heading);
    const ends = ['\n## ', '\n### ']
      .map(mark => text.indexOf(mark, start + heading.length))
      .filter(at => at > 0);
    return text.slice(start, Math.min(...ends, text.length));
  };
  const changelog = read('CHANGELOG.md');
  const bullet = start =>
    changelog.split('\n').find(line => line.startsWith(`- **${start}`)) ?? `(no bullet ${start})`;
  const said = {
    'docs/installation.md': section(read('docs/installation.md'), '### Rolling back 1.5 to 1.4.3'),
    'docs/notifications.md': section(
      read('docs/notifications.md'),
      '## Rolling back to 1.4.x and upgrading again'
    ),
    'CHANGELOG.md (rolling back)': bullet('Rolling back to 1.4.3 or 1.4.2 uses the current'),
    'CHANGELOG.md (receivers)': bullet('Rolling back to 1.4.3 or 1.4.2 needs no preparation'),
  };
  for (const [name, text] of Object.entries(said)) {
    assert.match(text, /new (webhook )?signing key/, name);
    assert.match(text, /removes? (it|`control\.sqlite`)|removed them/, name);
  }
  for (const name of [
    'docs/installation.md',
    'docs/notifications.md',
    'CHANGELOG.md (rolling back)',
  ])
    assert.match(said[name], /tarball/, `${name}: a copy of the data from before the upgrade too`);
  assert.match(said['docs/notifications.md'], /never sent, and not listed as not sent/);
  // Each place that promises the waiting notifications after upgrading again says when not.
  for (const name of ['docs/installation.md', 'CHANGELOG.md (receivers)'])
    assert.match(said[name], /unless (you restored |)the data from before the upgrade/, name);
});

// The signing start work and the pre-release warning (G4): the log lines the docs quote are the
// ones lib/alerting/signing.mjs prints, the header format is said to be Uptime Goblin's own, and every
// place that tells how to roll back warns against starting the data with an earlier 1.5
// pre-release build: on data this release has run on it shows no signing secret (the keys are in
// fields it never opens), and on data that 1.5 builds before this release left it took the private
// key for its HMAC secret and showed it under Show signing secret, with the remedy where it is
// told: Replace signing key twice, with GOBLIN_WEBHOOK_URL set.
test('the signing docs quote the start lines as Uptime Goblin logs them, and every rollback place warns against an earlier 1.5 pre-release build', () => {
  const read = name => fs.readFileSync(path.join(root, name), 'utf8');
  const code = read('lib/alerting/signing.mjs');
  const section = (text, heading) => {
    const start = text.indexOf(heading);
    assert.ok(start >= 0, heading);
    const ends = ['\n## ', '\n### ']
      .map(mark => text.indexOf(mark, start + heading.length))
      .filter(at => at > 0);
    return text.slice(start, Math.min(...ends, text.length));
  };
  const changelog = read('CHANGELOG.md');
  const bullet = start =>
    changelog.split('\n').find(line => line.startsWith(`- **${start}`)) ?? `(no bullet ${start})`;
  const guide = read('docs/notifications.md');
  const verifying = section(guide, '### Verifying signatures');
  const signed = bullet('Signed webhooks.');
  // Each quoted line, cut at its ellipses, is printed as it stands (with the example login
  // "admin" where the code names the actor).
  let quoted = 0;
  for (const [name, text] of [
    ['docs/notifications.md', verifying],
    ['CHANGELOG.md', signed],
  ])
    for (const [, quote] of text.matchAll(/\("([^"]*?…)"\)/g))
      for (const part of quote.split('…').filter(Boolean)) {
        quoted++;
        assert.ok(
          code.includes(part) || code.includes(part.replace(/ by admin$/, ' by ${login}')),
          `${name} quotes "${part}", which signing.mjs prints`
        );
      }
  assert.ok(quoted >= 4, `${quoted} quoted parts`);
  for (const line of [
    "Uptime Goblin replaced the alert webhook's HMAC signing secret (from a pre-release build) with an Ed25519 signing key",
    "Uptime Goblin removed the alert webhook's HMAC signing secret (from a pre-release build)",
    'A stored signing key of the alert webhook could not be read as an Ed25519 key',
  ])
    assert.ok(verifying.includes(`("${line}…")`), line);
  assert.match(
    verifying,
    /Private keys from formerly revealable HMAC fields are treated as potentially disclosed, even when they are Ed25519 keys in another PEM form\. They are never adopted or kept for overlap\./
  );
  assert.doesNotMatch(verifying, /\(white space around it, CRLF line ends\) is kept/);
  // The header format is Uptime Goblin's own.
  assert.ok(
    verifying.includes(
      "but the header format is Uptime Goblin's own (`X-Goblin-Signature`, with `t=` and `v1a=` pairs, and each signature in hexadecimal after a key id): Standard Webhooks libraries do not verify it, so use the examples below."
    )
  );
  assert.ok(
    signed.includes(
      "`X-Goblin-Signature` is Uptime Goblin's own format: Standard Webhooks libraries do not verify it."
    )
  );
  // The warning, with the remedy where it is told.
  const remedy = [
    /\*\*Replace signing key\*\* twice/,
    /with `GOBLIN_WEBHOOK_URL` set \(set it again first if it was removed: without it the key cannot be replaced/,
    /give receivers the new public key/,
  ];
  const installation = read('docs/installation.md');
  const places = {
    'CHANGELOG.md (rolling back to 1.4.x)': [
      bullet('Rolling back to 1.4.3 or 1.4.2 needs no'),
      remedy,
    ],
    'docs/installation.md (rolling back 1.5 to 1.4.3)': [
      section(installation, '### Rolling back 1.5 to 1.4.3'),
      remedy,
    ],
    'docs/notifications.md (rolling back)': [
      section(guide, '## Rolling back to 1.4.x and upgrading again'),
      remedy,
    ],
    'docs/security.md': [
      read('docs/security.md')
        .split('\n')
        .find(line => line.startsWith('**The webhook signing key**')) ?? '',
      [/\*\*Replace signing key\*\* twice, as in step 2 of \[a leaked key\]\(#a-leaked-key\)/],
    ],
    // The audit log's rollback to an earlier 1.5 build points to the remedy.
    'CHANGELOG.md (audit log)': [
      bullet('Rolling back the audit log'),
      [/\(docs\/notifications\.md#rolling-back-to-14x-and-upgrading-again\)/],
    ],
    'docs/installation.md (audit log)': [
      installation.split('\n').find(line => line.startsWith('- **Rolling back the audit log')) ??
        '',
      [/\(#rolling-back-15-to-143\)/],
    ],
  };
  for (const [name, [text, musts]] of Object.entries(places)) {
    assert.match(text, /with an earlier 1\.5 pre-release build|with such a build/, name);
    assert.match(text, /shows no signing secret/, name);
    assert.match(
      text,
      /took the (?:private signing )?key for its HMAC secret, signed with its text and showed it under \*\*Show signing secret\*\*/,
      name
    );
    for (const must of musts) assert.match(text, must, name);
  }
  // A start without a webhook cannot replace the key: rotate() refuses there.
  assert.match(
    code,
    /async function rotate[^]*?if \(!configured\) throw deliveryError\('webhook_not_configured'\)/
  );
  // The step-2 remedy of a leaked key needs a webhook too.
  assert.match(
    read('docs/security.md'),
    /2\. Start Uptime Goblin\. With a webhook set, press \*\*Replace signing key\*\*/
  );
});

// Review SIGN-1: notifications.md advised one Replace signing key after an exposure, and its
// Node.js example told receivers to keep the previous key while it signs, so the exposed key
// stayed trusted for 24 hours (or for good). It now sends the reader to every step of a leaked
// key in docs/security.md: first `goblin-admin key rotate` with a new encryption key (until then
// a new signing key is sealed with a data key the leaked key opens: seal() uses the active data
// key, and key rotate makes new ones); then, with GOBLIN_WEBHOOK_URL set (without it rotate()
// answers webhook_not_configured, and a start without one keeps an Ed25519 key, as
// test/alerting/signing.test.mjs shows, which the next start with one signs with), press Replace
// twice, so the exposed key stops signing at once (Uptime Goblin keeps only one previous key;
// signing.test.mjs shows it), and have receivers keep only the new public key: one held from a
// planned replacement less than 24 hours before is exposed too. The example keeps the previous key only in a planned replacement.
test('after a suspected exposure the webhook docs say to rotate the encryption key, replace the signing key twice with the webhook set and keep only the new public key, with a link to a leaked key (review SIGN-1)', () => {
  const read = name => fs.readFileSync(path.join(root, name), 'utf8');
  const guide = read('docs/notifications.md');
  const replacing = /^\*\*Replacing the signing key\.\*\*.*$/m.exec(guide)?.[0] ?? '(none)';
  assert.ok(
    replacing.includes(
      'When the private key may have been exposed (a copy of the data directory together with its encryption key), follow every step of [a leaked key](security.md#a-leaked-key) instead. First, with Uptime Goblin stopped, put a new encryption key in place and run `goblin-admin key rotate`: a signing key made before that is sealed with a data key the leaked key opens. Then, with `GOBLIN_WEBHOOK_URL` set (set it again first if it was removed: without it the key cannot be replaced, and the exposed key signs again once it is set), press **Replace signing key** twice, so the exposed key stops signing at once (after one press it would sign for 24 hours more). Give receivers the new public key and have them keep only that one, dropping every public key they held before.'
    ),
    replacing
  );
  assert.doesNotMatch(guide, /Replace it whenever the private key may have been exposed \(/);
  // Not the summary that skipped the encryption key and the webhook, or dropped only one key.
  assert.doesNotMatch(guide, /a-leaked-key\) instead: press/);
  assert.doesNotMatch(guide, /drop the old public key at once/);
  // The link's target is a heading of docs/security.md (GitHub's anchor for "A leaked key"), and
  // that section says the same.
  const security = read('docs/security.md');
  const anchors = [...security.matchAll(/^#{1,6} (.+)$/gm)].map(([, title]) =>
    title
      .toLowerCase()
      .replace(/[^\p{L}\p{N} _-]/gu, '')
      .replace(/ /g, '-')
  );
  assert.ok(anchors.includes('a-leaked-key'));
  assert.match(
    security,
    /1\. Stop Uptime Goblin, put a new key in place and run `goblin-admin key rotate`[^\n]*until you replace it, the webhook signing key is the one the old key opens\./
  );
  assert.match(
    security,
    /press \*\*Replace signing key\*\* under \*\*Configure → Notifications\*\* twice: after the first press the old key keeps signing for 24 hours, and the second press stops it at once\. Then give receivers the new public key and have them drop the old one\./
  );
  // The Node.js example keeps the previous key only during a planned replacement.
  const node =
    /```js\n([\s\S]*?export function verifyUptimeGoblin[\s\S]*?)```/.exec(guide)?.[1] ?? '';
  const comment = node
    .split('\n')
    .filter(line => line.startsWith('//'))
    .map(line => line.replace(/^\/\/ ?/, ''))
    .join(' ');
  assert.ok(
    comment.includes(
      'During a planned replacement, add the previous key while it still signs, if the receiver had it; never after a suspected exposure of the private key (then keep only the new key).'
    ),
    comment
  );
  assert.doesNotMatch(
    comment,
    /\(add the previous key while it still signs, if the receiver had it\)/
  );
});
