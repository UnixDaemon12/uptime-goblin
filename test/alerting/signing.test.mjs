// The webhook signing key (lib/alerting/signing.mjs; delivery spec §5.7, amendment A61; Ed25519
// since 2026-11-12) over the real control database: after a rotation that answered success,
// Uptime Goblin signs with the saved key, and the replaced one stops signing after 24 hours, whatever the
// reads around it do; receivers verify with the public keys publicKeys() gives; an HMAC secret
// of an earlier pre-release build is cleared at every start (replaced with a webhook, removed
// without one) and never signs again; a stored value that is not an Ed25519 key is replaced, and
// an Ed25519 key in another PEM form is kept. The keys live in fields the pre-release builds never
// open (schema 2), so such a build started on the data obtains none.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {
  randomBytes,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  verify,
} from 'node:crypto';
import { openControl, createSettingsStore } from '../../lib/db/control.mjs';
import { Keyring, memoryKeyringStore } from '../../lib/keyring.mjs';
import { createSettings, defineSetting, validators } from '../../lib/settings.mjs';
import { notifySettings } from '../../lib/alerting/settings.mjs';
import { createSigning } from '../../lib/alerting/signing.mjs';
import { createEnvWebhookChannel } from '../../lib/notify/channels/webhook.mjs';
import {
  verifyWebhookSignature,
  publicSigningKey,
  generateSigningKey,
} from '../../lib/notify/sign.mjs';
import { fakeClock, quietLogger } from './fake-clock.mjs';

const day = 24 * 60 * 60 * 1000;

// Writes `values` into notify/envWebhook as an earlier build did: the key fields sealed, whatever
// they hold (the settings definition of this release would refuse most of them).
async function writeAsEarlierBuild({ control, keyring }, values, schema = 1) {
  const earlier = createSettings({
    store: createSettingsStore(control.db),
    keyring,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema,
        fields: {
          signingSecret: { secret: true, validate: value => value },
          previousSigningSecret: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
  });
  const { version } = await control.settings.get('notify', 'envWebhook');
  await earlier.update('notify', 'envWebhook', values, { ifVersion: version, by: 'orbit' });
}

// The settings document and the signing of the earlier pre-release builds that signed with an
// HMAC secret, as their lib/alerting/settings.mjs and lib/alerting/signing.mjs had them, over this
// release's lib/settings.mjs (which they share unchanged): the definition (schema 1, the secret
// checked only when saved), what counted as a secret in use (any value that opens), what Show
// signing secret answered, what signed (as the HMAC secret) and what their start with a webhook
// saved when no secret was in use.
function prereleaseBuild({ control, keyring }) {
  const hex64 = value => {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))
      throw new Error('must be 64 hexadecimal digits');
    return value;
  };
  const time = value => {
    if (value !== null && !(Number.isSafeInteger(value) && value >= 0))
      throw new Error('must be a time or null');
    return value;
  };
  const settings = createSettings({
    store: createSettingsStore(control.db),
    keyring,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 1,
        fields: {
          signingSecret: { secret: true, validate: hex64 },
          previousSigningSecret: { secret: true, validate: hex64 },
          previousUntil: { default: null, validate: time },
          createdAt: { default: null, validate: time },
        },
      }),
    ],
  });
  const read = () => settings.get('notify', 'envWebhook');
  const usable = doc =>
    Boolean(doc?.value?.signingSecret) && !doc.unreadable?.includes('signingSecret');
  return {
    read,
    // Show signing secret: the secret, or null where it answered signing_unavailable.
    async reveal() {
      const doc = await read();
      return usable(doc) ? doc.value.signingSecret : null;
    },
    // What signed at `now`: the current secret, then the previous one while it lasted.
    async keys(now) {
      const { value } = await read();
      return [
        value.signingSecret,
        value.previousUntil > now ? value.previousSigningSecret : null,
      ].filter(Boolean);
    },
    // Its start with a webhook, where no secret was in use: a new HMAC secret.
    async create(now) {
      const doc = await read();
      return settings.update(
        'notify',
        'envWebhook',
        {
          signingSecret: randomBytes(32).toString('hex'),
          previousSigningSecret: null,
          previousUntil: null,
          createdAt: now,
        },
        { ifVersion: doc.version, by: 'orbit' }
      );
    },
  };
}

// The forms in which a private key could be read: its PEM text, a line of it, its 32-byte seed
// (base64url, base64, hexadecimal).
const privateForms = privateKey => {
  const seed = createPrivateKey(privateKey).export({ format: 'jwk' }).d;
  return [
    privateKey,
    privateKey.split('\n')[1],
    seed,
    Buffer.from(seed, 'base64url').toString('base64'),
    Buffer.from(seed, 'base64url').toString('hex'),
  ];
};

// control.sqlite in a temporary directory with a signing key already created (unless `start` is
// false: no start work has run). Reads can be made to fail (`failReadAfterNextWrite`: the first
// read after the next write that commits) or held (`holdNextRead`: the next read runs at once,
// its answer waits for `release()`).
async function fixture(t, { before = null, configured = true, start = true } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-signing-'));
  const clock = fakeClock();
  const keyring = await Keyring.open(memoryKeyringStore(), { key: randomBytes(32) });
  const control = openControl(directory, {
    env: {},
    clock: () => clock.wall(),
    settingsDefinitions: [notifySettings],
    keyring,
  });
  t.after(() => {
    control.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  await control.migrate();
  // What an earlier build left in the document, written as it wrote it.
  if (before) await before({ control, keyring, clock });
  const read = control.db.read.bind(control.db),
    write = control.db.write.bind(control.db);
  const faults = { armed: false, failNextRead: false, failed: 0, hold: null };
  control.db.write = async (...args) => {
    const answer = await write(...args);
    if (faults.armed) Object.assign(faults, { armed: false, failNextRead: true });
    return answer;
  };
  control.db.read = (...args) => {
    if (faults.failNextRead) {
      faults.failNextRead = false;
      faults.failed++;
      return Promise.reject(
        Object.assign(new Error('disk I/O error'), { code: 'SQLITE_IOERR', class: 'fatal' })
      );
    }
    if (faults.hold) {
      const held = faults.hold;
      faults.hold = null;
      held.answer = read(...args);
      return held.answer.then(value => held.gate.then(() => value));
    }
    return read(...args);
  };
  const logger = quietLogger(),
    events = [];
  const signing = createSigning({
    settings: control.settings,
    configured,
    clock,
    logger,
    onEvent: record => events.push(record),
  });
  if (start) assert.equal(await signing.ensure(), true);
  const stored = async () => (await control.settings.get('notify', 'envWebhook')).value;
  return {
    clock,
    control,
    keyring,
    signing,
    faults,
    stored,
    logger,
    events,
    original: (await stored()).signingKey,
    failReadAfterNextWrite() {
      faults.armed = true;
    },
    holdNextRead() {
      let release;
      const held = { gate: new Promise(resolve => (release = resolve)), answer: null, release };
      faults.hold = held;
      return held;
    },
  };
}

// One firing, signed by Uptime Goblin's channel with signing.keys(), to a receiver on 127.0.0.1 that
// accepts it only when the public key `keys.expected` verifies (else 403): which public keys
// (SPKI PEM) verify, the outcome.
async function sendSigned(t, { signing, clock }, keys) {
  let verified = null;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks),
      options = { deliveryId: req.headers['x-goblin-delivery'], nowMs: clock.wall() };
    verified = Object.fromEntries(
      Object.entries(keys).map(([name, key]) => [
        name,
        verifyWebhookSignature(key, body, req.headers['x-goblin-signature'], options).ok,
      ])
    );
    res.writeHead(verified.expected ? 200 : 403);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const channel = createEnvWebhookChannel({
    url: `http://127.0.0.1:${server.address().port}/hook`,
    signingKeys: () => signing.keys(),
    hold: () => (signing.held ? 'Signing authority held' : null),
    now: () => clock.wall(),
  });
  const outcome = await channel.send({
    uid: 'd_signing_rotation',
    events: [{ kind: 'firing', service: 'plex', message: 'down' }],
  });
  return { verified, outcome: outcome.kind ?? outcome.type };
}

const publicOf = privateKey => publicSigningKey(privateKey).publicKey;

for (const failReadBack of [false, true])
  test(`A61: a rotation that answered success signs with the saved key, the replaced one only for 24 hours (read-back fails: ${failReadBack})`, async t => {
    const f = await fixture(t);
    if (failReadBack) f.failReadAfterNextWrite();
    f.clock.burn(1000);
    const rotated = await f.signing.rotate({ actor: { login: 'dana' } });
    // The read after the commit failed (or, in the control, nothing failed).
    assert.equal(f.faults.failed, Number(failReadBack));
    const saved = await f.stored();
    assert.notEqual(saved.signingKey, f.original);
    assert.equal(saved.previousSigningKey, f.original);
    assert.deepEqual(rotated, { createdAt: saved.createdAt, previousUntil: saved.previousUntil });
    // In use at once: the new key first, the replaced one beside it.
    assert.deepEqual(f.signing.describe(), {
      configured: true,
      saved: !failReadBack,
      createdAt: saved.createdAt,
      previousUntil: saved.previousUntil,
    });
    assert.equal(f.signing.pending, failReadBack);
    assert.deepEqual(f.signing.keys(), [saved.signingKey, f.original]);
    // A day later only the new key signs: a receiver that expects it accepts the firing.
    f.clock.burn(day + 1);
    assert.deepEqual(f.signing.keys(), [saved.signingKey]);
    assert.deepEqual(
      await sendSigned(t, f, {
        expected: publicOf(saved.signingKey),
        replaced: publicOf(f.original),
      }),
      { verified: { expected: true, replaced: false }, outcome: 'accepted' }
    );
  });

test('A61: a public-key read that read the document before a rotation saved does not bring the replaced key back', async t => {
  const f = await fixture(t);
  // The read reads the document now; its answer arrives after the rotation below.
  const held = f.holdNextRead();
  const read = f.signing.publicKeys();
  await held.answer;
  f.clock.burn(1000);
  await f.signing.rotate({ actor: { login: 'dana' } });
  const saved = await f.stored();
  held.release();
  // It answers what it read; signing keeps the saved key.
  assert.equal((await read).publicKey, publicOf(f.original));
  assert.equal(f.signing.describe().createdAt, saved.createdAt);
  assert.deepEqual(f.signing.keys(), [saved.signingKey, f.original]);
  f.clock.burn(day + 1);
  assert.deepEqual(f.signing.keys(), [saved.signingKey]);
  assert.deepEqual(
    await sendSigned(t, f, {
      expected: publicOf(saved.signingKey),
      replaced: publicOf(f.original),
    }),
    { verified: { expected: true, replaced: false }, outcome: 'accepted' }
  );
});

test('the public keys: what receivers verify with, the previous one until previousUntil, never a private key', async t => {
  const f = await fixture(t);
  const first = await f.signing.publicKeys();
  const own = publicSigningKey(f.original);
  assert.deepEqual(first, {
    algorithm: 'Ed25519',
    keyId: own.keyId,
    publicKey: own.publicKey,
    publicKeyRaw: own.publicKeyRaw,
    createdAt: (await f.stored()).createdAt,
    previousUntil: null,
    previous: null,
  });
  // A request Uptime Goblin signs verifies with node:crypto and the answer's public key, as PEM and as
  // the raw 32 bytes; the header names the key by its id.
  const delivered = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    delivered.push({ headers: req.headers, body: Buffer.concat(chunks) });
    res.writeHead(200);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const channel = createEnvWebhookChannel({
    url: `http://127.0.0.1:${server.address().port}/hook`,
    signingKeys: () => f.signing.keys(),
    now: () => f.clock.wall(),
  });
  const send = async uid =>
    (await channel.send({ uid, events: [{ kind: 'firing', service: 'plex', message: 'down' }] }))
      .type;
  // Every v1a whose key id is the given public key's verifies with crypto.verify().
  const verifies = (request, answer) => {
    const header = request.headers['x-goblin-signature'];
    const t = /^t=(\d+),/.exec(header)[1];
    const data = Buffer.concat([
      Buffer.from(`${request.headers['x-goblin-delivery']}.${t}.`),
      request.body,
    ]);
    const raw = createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(answer.publicKeyRaw, 'base64').toString('base64url'),
      },
      format: 'jwk',
    });
    const mine = [...header.matchAll(/v1a=([0-9a-f]{16}):([0-9a-f]{128})/g)].filter(
      ([, keyId]) => keyId === answer.keyId
    );
    return (
      mine.length === 1 &&
      verify(null, data, answer.publicKey, Buffer.from(mine[0][2], 'hex')) &&
      verify(null, data, raw, Buffer.from(mine[0][2], 'hex'))
    );
  };
  assert.equal(await send('d_signing_public_key_0'), 'accepted');
  assert.equal(verifies(delivered[0], first), true);
  // Replaced: the new key signs first, and the previous one beside it until previousUntil;
  // the answer lists the previous public key for exactly that long.
  f.clock.burn(1000);
  await f.signing.rotate({ actor: { login: 'dana' } });
  const second = await f.signing.publicKeys();
  assert.notEqual(second.keyId, first.keyId);
  assert.equal(second.previousUntil, (await f.stored()).previousUntil);
  assert.equal(second.previousUntil, f.clock.wall() + day);
  assert.deepEqual(second.previous, {
    keyId: first.keyId,
    publicKey: first.publicKey,
    publicKeyRaw: first.publicKeyRaw,
  });
  assert.equal(await send('d_signing_public_key_1'), 'accepted');
  assert.equal(verifies(delivered[1], second), true, 'the new public key verifies');
  assert.equal(verifies(delivered[1], first), true, 'the previous one too, during the overlap');
  // One millisecond before previousUntil the previous key still signs; at it, no more.
  f.clock.burn(day - 1);
  assert.equal(await send('d_signing_public_key_2'), 'accepted');
  assert.equal(verifies(delivered[2], first), true);
  assert.deepEqual((await f.signing.publicKeys()).previous, second.previous);
  f.clock.burn(1);
  assert.equal(await send('d_signing_public_key_3'), 'accepted');
  assert.equal(verifies(delivered[3], second), true);
  assert.equal(verifies(delivered[3], first), false, 'the previous key no longer signs');
  assert.deepEqual(
    [(await f.signing.publicKeys()).previous, (await f.signing.publicKeys()).previousUntil],
    [null, null]
  );
  // No answer holds a private key, in any form.
  const saved = await f.stored();
  const answers = JSON.stringify([first, second, await f.signing.publicKeys()]);
  for (const privateKey of [f.original, saved.signingKey]) {
    const seed = createPrivateKey(privateKey).export({ format: 'jwk' }).d;
    for (const form of [
      privateKey,
      privateKey.split('\n')[1],
      seed,
      Buffer.from(seed, 'base64url').toString('base64'),
      Buffer.from(seed, 'base64url').toString('hex'),
    ])
      assert.equal(answers.includes(form), false);
  }
  assert.doesNotMatch(answers, /PRIVATE KEY/);
});

// Requirement 4 of the change to public keys: a document an earlier pre-release build saved holds
// HMAC secrets (64 hexadecimal digits). The start replaces them with a new Ed25519 key pair,
// logs one line saying so, and nothing ever signs with them again.
test('an HMAC signing secret of a pre-release build is replaced by an Ed25519 key pair at the start, with one log line, and never signs again', async t => {
  const hmac = 'c0ffee'.repeat(10) + 'beef',
    previousHmac = 'f00d'.repeat(16);
  const f = await fixture(t, {
    async before({ control, keyring, clock }) {
      // The settings document as the pre-release builds defined it.
      const legacy = createSettings({
        store: createSettingsStore(control.db),
        keyring,
        definitions: [
          defineSetting({
            component: 'notify',
            key: 'envWebhook',
            schema: 1,
            fields: {
              signingSecret: { secret: true, validate: validators.secret(64) },
              previousSigningSecret: { secret: true, validate: validators.secret(64) },
              previousUntil: { default: null, validate: value => value },
              createdAt: { default: null, validate: value => value },
            },
          }),
        ],
      });
      await legacy.update(
        'notify',
        'envWebhook',
        {
          signingSecret: hmac,
          previousSigningSecret: previousHmac,
          previousUntil: clock.wall() + day,
          createdAt: clock.wall() - 1000,
        },
        { ifVersion: 0, by: 'orbit' }
      );
      // This release reads them, and would not save them.
      const read = (await control.settings.get('notify', 'envWebhook')).value;
      assert.deepEqual([read.signingSecret, read.previousSigningSecret], [hmac, previousHmac]);
    },
  });
  const saved = await f.stored();
  // Both HMAC secrets are gone from the document: a new key pair, no previous key.
  assert.match(saved.signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.equal(saved.previousSigningKey, null);
  assert.equal(saved.previousUntil, null);
  assert.deepEqual([saved.signingSecret, saved.previousSigningSecret], [null, null]);
  const doc = await f.control.settings.get('notify', 'envWebhook');
  assert.equal(doc.schema, 2);
  // Held (review F2), in the write that made the key: the pre-release build's one, then this.
  assert.deepEqual([saved.heldSince, doc.version, f.signing.held], [f.clock.wall(), 2, true]);
  assert.deepEqual(f.signing.keys(), [saved.signingKey]);
  assert.equal(f.signing.describe().previousUntil, null);
  // One line says so, and only that line.
  assert.deepEqual(
    f.logger.lines.warn.filter(line => line.includes('signing')),
    [
      "Uptime Goblin replaced the alert webhook's HMAC signing secret (from a pre-release build) with an Ed25519 signing key; receivers that check X-Goblin-Signature need its public key (Configure → Notifications).",
    ]
  );
  assert.deepEqual(
    f.events.map(({ action, detail }) => [action, detail]),
    [['signing.created', { replaced: false }]]
  );
  // A request now carries only the Ed25519 signature: no v1 that the old secret would verify.
  let header = null;
  const server = http.createServer(async (req, res) => {
    for await (const chunk of req) void chunk;
    header = req.headers['x-goblin-signature'];
    res.writeHead(200);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const channel = createEnvWebhookChannel({
    url: `http://127.0.0.1:${server.address().port}/hook`,
    signingKeys: () => f.signing.keys(),
    now: () => f.clock.wall(),
  });
  await channel.send({ uid: 'd_signing_hmac_gone', events: [{ kind: 'firing', service: 'x' }] });
  assert.match(header, /^t=\d+,v1a=[0-9a-f]{16}:[0-9a-f]{128}$/);
  assert.doesNotMatch(header, /v1=/);
  // A second start finds the key pair and changes nothing.
  const again = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await again.ensure(), true);
  assert.equal((await f.stored()).signingKey, saved.signingKey);
});

// Review F3 (mutant B6): with a webhook, an HMAC secret of a pre-release build that sits only in
// previousSigningSecret, beside an Ed25519 current key, is cleared as one in the current field
// is. review() replaces the document for an HMAC secret in either field, so the start makes a new
// key pair and keeps neither old value: the HMAC secret is gone from the document (and from the
// sealed row), the old current key no longer signs, and one line says so. Uptime Goblin's own transitions
// never make this state (create() writes no previous key, rotate() keeps only a usable one).
test('with a webhook, an HMAC secret only in previousSigningSecret beside an Ed25519 key is replaced with the pair: a new key, no previous key, one line', async t => {
  const kept = generateSigningKey(),
    hmac = 'f00d'.repeat(16);
  const f = await fixture(t, {
    async before({ control, keyring, clock }) {
      await writeAsEarlierBuild(
        { control, keyring },
        {
          signingSecret: kept,
          previousSigningSecret: hmac,
          previousUntil: clock.wall() + day,
          createdAt: clock.wall() - 1000,
        }
      );
      // This release reads them so (the start below has not run yet).
      const read = (await control.settings.get('notify', 'envWebhook')).value;
      assert.deepEqual([read.signingSecret, read.previousSigningSecret], [kept, hmac]);
    },
  });
  const saved = await f.stored();
  assert.match(saved.signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.notEqual(saved.signingKey, kept);
  assert.deepEqual([saved.previousSigningKey, saved.previousUntil], [null, null]);
  const row = JSON.parse(
    (await createSettingsStore(f.control.db).get('notify', 'envWebhook')).value
  );
  assert.equal(
    Object.hasOwn(row, 'previousSigningSecret'),
    false,
    'the sealed HMAC secret is gone'
  );
  assert.equal(
    Object.hasOwn(row, 'signingSecret'),
    false,
    'the old key left the pre-release field'
  );
  assert.deepEqual(f.signing.keys(), [saved.signingKey]);
  assert.equal(f.signing.describe().previousUntil, null);
  const shown = await f.signing.publicKeys();
  assert.equal(shown.keyId, publicSigningKey(saved.signingKey).keyId);
  assert.deepEqual([shown.previous, shown.previousUntil], [null, null]);
  assert.deepEqual(
    f.logger.lines.warn.filter(line => line.includes('signing')),
    [
      "Uptime Goblin replaced the alert webhook's HMAC signing secret (from a pre-release build) with an Ed25519 signing key; receivers that check X-Goblin-Signature need its public key (Configure → Notifications).",
    ]
  );
  assert.deepEqual(f.logger.lines.error, []);
  assert.deepEqual(
    f.events.map(({ action, detail }) => [action, detail]),
    [['signing.created', { replaced: false }]]
  );
  // A request carries only the new key's signature: a receiver with the old key rejects it.
  assert.equal(f.signing.held, true);
  await f.signing.releaseHold({ actor: 'admin' });
  assert.deepEqual(
    await sendSigned(t, f, { expected: publicOf(saved.signingKey), old: publicOf(kept) }),
    { verified: { expected: true, old: false }, outcome: 'accepted' }
  );
  // A second start finds the key pair and changes nothing.
  const { version } = await f.control.settings.get('notify', 'envWebhook');
  const again = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await again.ensure(), true);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, version);
});

// docs/notifications.md and step 2 of a leaked key in docs/security.md tell admins to press
// Replace signing key twice after a suspected exposure, so the exposed key stops signing at once
// (review SIGN-1). That holds because Uptime Goblin keeps only one previous key: the second replacement
// within the 24 hours drops the first replaced key, and only the two new keys sign.
test('two replacements within 24 hours stop the first replaced key signing at once: only the two new keys sign', async t => {
  const f = await fixture(t);
  const exposed = f.original;
  f.clock.burn(1000);
  await f.signing.rotate({ actor: { login: 'dana' } });
  const first = (await f.stored()).signingKey;
  assert.deepEqual(
    f.signing.keys(),
    [first, exposed],
    'after one press the exposed key still signs'
  );
  f.clock.burn(1000);
  await f.signing.rotate({ actor: { login: 'dana' } });
  const saved = await f.stored();
  assert.deepEqual([saved.previousSigningKey], [first]);
  assert.deepEqual(f.signing.keys(), [saved.signingKey, first]);
  const shown = await f.signing.publicKeys();
  assert.equal(shown.keyId, publicSigningKey(saved.signingKey).keyId);
  assert.equal(shown.previous.keyId, publicSigningKey(first).keyId);
  // At once, not after 24 hours: a receiver that kept only the exposed key rejects the request.
  assert.deepEqual(
    await sendSigned(t, f, {
      expected: publicOf(saved.signingKey),
      exposed: publicOf(exposed),
    }),
    { verified: { expected: true, exposed: false }, outcome: 'accepted' }
  );
});

const REMOVED_LINE =
  "Uptime Goblin removed the alert webhook's HMAC signing secret (from a pre-release build); GOBLIN_WEBHOOK_URL is not set, so it made no signing key in its place.";
const UNREADABLE_LINE =
  'A stored signing key of the alert webhook could not be read as an Ed25519 key; Uptime Goblin replaced it with a new Ed25519 signing key, and receivers that check X-Goblin-Signature need its public key (Configure → Notifications).';

// Without a webhook (GOBLIN_WEBHOOK_URL unset) every start still clears the HMAC secrets of an
// earlier pre-release build: both fields go, with their times, no key pair is made, one line
// says so, and the sealed values are gone from the stored row.
test('without a webhook, a start removes a pre-release HMAC secret and the previous one, makes no key, and logs one line', async t => {
  const f = await fixture(t, {
    configured: false,
    async before({ control, keyring, clock }) {
      await writeAsEarlierBuild(
        { control, keyring },
        {
          signingSecret: 'c0ffee'.repeat(10) + 'beef',
          previousSigningSecret: 'f00d'.repeat(16),
          previousUntil: clock.wall() + day,
          createdAt: clock.wall() - 1000,
        }
      );
    },
  });
  assert.deepEqual(await f.stored(), {
    signingKey: null,
    previousSigningKey: null,
    previousUntil: null,
    createdAt: null,
    heldSince: null,
    signingSecret: null,
    previousSigningSecret: null,
  });
  const stored = await createSettingsStore(f.control.db).get('notify', 'envWebhook');
  const row = JSON.parse(stored.value);
  assert.equal(Object.hasOwn(row, 'signingSecret'), false);
  assert.equal(Object.hasOwn(row, 'previousSigningSecret'), false);
  assert.equal(stored.schema, 2, "saved in this release's form");
  assert.deepEqual(f.logger.lines.warn, [REMOVED_LINE]);
  assert.deepEqual(f.logger.lines.error, []);
  assert.deepEqual(f.events, []);
  assert.deepEqual(f.signing.keys(), []);
  assert.equal(f.signing.describe(), null);
  // A second start without a webhook finds nothing to remove and writes nothing.
  const { version } = await f.control.settings.get('notify', 'envWebhook');
  const quiet = quietLogger();
  const again = createSigning({ settings: f.control.settings, clock: f.clock, logger: quiet });
  assert.equal(await again.ensure(), true);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, version);
  assert.deepEqual(quiet.lines, { error: [], warn: [], info: [] });
  // The first start with a webhook makes the key pair with the line of data that never had one,
  // but held (review F2): a receiver may still check the removed HMAC secret.
  const later = quietLogger();
  const withWebhook = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: later,
  });
  assert.equal(await withWebhook.ensure(), true);
  assert.match((await f.stored()).signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.equal((await f.stored()).heldSince, f.clock.wall());
  assert.equal(withWebhook.held, true);
  assert.deepEqual(later.lines.warn, [
    'Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key (Configure → Notifications).',
  ]);
});

// Builds before schema 2 kept the Ed25519 keys in signingSecret and previousSigningSecret. A start
// without a webhook keeps them (and their overlap), moved to signingKey and previousSigningKey.
test('without a webhook, a start clears all retired authority without creating keys, including an Ed25519 key beside an HMAC secret', async t => {
  const current = generateSigningKey(),
    previous = generateSigningKey();
  let written;
  const f = await fixture(t, {
    configured: false,
    async before({ control, keyring, clock }) {
      written = {
        signingSecret: current,
        previousSigningSecret: previous,
        previousUntil: clock.wall() + day,
        createdAt: clock.wall() - 1000,
      };
      await writeAsEarlierBuild({ control, keyring }, written);
    },
  });
  assert.deepEqual(await f.stored(), {
    signingKey: null,
    previousSigningKey: null,
    previousUntil: null,
    createdAt: null,
    heldSince: null,
    signingSecret: null,
    previousSigningSecret: null,
  });
  const doc = await f.control.settings.get('notify', 'envWebhook');
  assert.deepEqual([doc.version, doc.schema], [2, 2]);
  assert.deepEqual(f.logger.lines, { error: [], warn: [], info: [] });
  assert.deepEqual(f.events, []);
  // A second start without a webhook writes nothing.
  const again = createSigning({
    settings: f.control.settings,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await again.ensure(), true);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, 2);

  // An Ed25519 key beside an HMAC secret (a pre-release build that replaced this release's key):
  // both revealable values go; neither is an active authority.
  const g = await fixture(t, {
    configured: false,
    async before({ control, keyring, clock }) {
      await writeAsEarlierBuild(
        { control, keyring },
        {
          signingSecret: current,
          previousSigningSecret: 'f00d'.repeat(16),
          previousUntil: clock.wall() + day,
          createdAt: clock.wall() - 1000,
        }
      );
    },
  });
  assert.deepEqual(await g.stored(), {
    signingKey: null,
    previousSigningKey: null,
    previousUntil: null,
    createdAt: null,
    heldSince: null,
    signingSecret: null,
    previousSigningSecret: null,
  });
  assert.deepEqual(g.logger.lines.warn, [REMOVED_LINE]);
});

// Only the exact form of a pre-release HMAC secret (64 lower-case hexadecimal digits) counts as
// one. An Ed25519 private key in another PEM form is rewritten in Uptime Goblin's form and kept (moved out
// of the pre-release fields), so it keeps signing (and its previous key keeps its overlap).
test('retired Ed25519 authority in another PEM form is replaced, with no overlap and a persisted hold', async t => {
  const current = generateSigningKey(),
    previous = generateSigningKey();
  let previousUntil, createdAt;
  const f = await fixture(t, {
    async before({ control, keyring, clock }) {
      previousUntil = clock.wall() + day;
      createdAt = clock.wall() - 1000;
      await writeAsEarlierBuild(
        { control, keyring },
        {
          signingSecret: ` ${current}\n  \n`,
          previousSigningSecret: previous.replace(/\n/g, '\r\n'),
          previousUntil,
          createdAt,
        }
      );
    },
  });
  const saved = await f.stored();
  assert.notEqual(saved.signingKey, current);
  assert.notEqual(saved.signingKey, previous);
  assert.deepEqual(
    [
      saved.previousSigningKey,
      saved.previousUntil,
      saved.signingSecret,
      saved.previousSigningSecret,
      saved.heldSince,
    ],
    [null, null, null, null, f.clock.wall()]
  );
  assert.deepEqual(f.signing.keys(), [saved.signingKey]);
  assert.equal(f.signing.held, true);
  const shown = await f.signing.publicKeys();
  assert.equal(shown.keyId, publicSigningKey(saved.signingKey).keyId);
  assert.equal(shown.previous, null);
  assert.equal(shown.previousUntil, null);
});

// Anything else in either field is replaced as an HMAC secret is (a new key pair, no previous
// key), with a line of its own that never holds the value.
test('a stored value that is neither a pre-release HMAC secret nor an Ed25519 key is replaced, with a line of its own that never quotes it', async t => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });
  const values = {
    'upper-case hexadecimal (not the pre-release form)': 'C0FFEE'.repeat(10) + 'BEEF',
    '63 hexadecimal digits': 'c0ffee'.repeat(10) + 'bee',
    'other text': 'not-a-signing-key-canary-4471',
    'an RSA private key': rsa,
    'an Ed25519 public key': publicSigningKey(generateSigningKey()).publicKey,
  };
  for (const [name, value] of Object.entries(values))
    for (const field of ['signingSecret', 'previousSigningSecret'])
      await t.test(`${name}, as ${field}`, async s => {
        const kept = generateSigningKey();
        const f = await fixture(s, {
          async before({ control, keyring, clock }) {
            await writeAsEarlierBuild(
              { control, keyring },
              field === 'signingSecret'
                ? { signingSecret: value, createdAt: clock.wall() - 1000 }
                : {
                    signingSecret: kept,
                    previousSigningSecret: value,
                    previousUntil: clock.wall() + day,
                    createdAt: clock.wall() - 1000,
                  }
            );
          },
        });
        const saved = await f.stored();
        assert.match(saved.signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
        assert.notEqual(saved.signingKey, kept);
        assert.deepEqual([saved.previousSigningKey, saved.previousUntil], [null, null]);
        // The value is cleared from the pre-release field with the replacement, explicitly.
        assert.deepEqual([saved.signingSecret, saved.previousSigningSecret], [null, null]);
        assert.deepEqual(f.signing.keys(), [saved.signingKey]);
        assert.deepEqual(f.logger.lines.warn, [UNREADABLE_LINE]);
        assert.deepEqual(f.logger.lines.error, []);
        // The audit row says the old key could not be read (the catalogue's text for replaced).
        assert.deepEqual(
          f.events.map(({ action, detail }) => [action, detail]),
          [['signing.created', { replaced: true }]]
        );
        const logged = JSON.stringify(f.logger.lines);
        for (const part of value.split('\n').filter(line => line.length >= 8))
          assert.equal(logged.includes(part), false);
      });
});

// Audit spec §5.3: the rotation's audit row is written by the route's recorder inside the
// settings unit that saves the new key, once its compare-and-swap succeeded.
test('rotate audit: the recorder runs once, inside the unit that saves the key, with the path-form diff; a conflict never calls it', async t => {
  const f = await fixture(t);
  f.clock.burn(1000);
  const recorded = [];
  const audit = (tx, { diff }) => {
    // A write unit of control.sqlite: what the recorder writes commits with the key.
    assert.equal(typeof tx?.onCommit, 'function');
    recorded.push(diff);
  };
  const before = await f.stored();
  await f.signing.rotate({ actor: { login: 'dana' }, audit });
  const after = await f.stored();
  assert.equal(recorded.length, 1);
  // Private keys only as set or changed; the times as they were and are. Never a key.
  assert.deepEqual(Object.fromEntries(recorded[0].map(({ path, ...change }) => [path, change])), {
    signingKey: { change: 'changed' },
    previousSigningKey: { change: 'set' },
    previousUntil: { from: null, to: after.previousUntil },
    createdAt: { from: before.createdAt, to: after.createdAt },
  });
  for (const key of [f.original, after.signingKey])
    assert.equal(JSON.stringify(recorded).includes(key.split('\n')[1]), false);

  // A recorder that throws rolls the rotation back: the key and its row commit together.
  await assert.rejects(
    f.signing.rotate({
      actor: { login: 'dana' },
      audit: () => {
        throw Object.assign(new Error('audit insert failed'), { class: 'full' });
      },
    })
  );
  assert.equal((await f.stored()).signingKey, after.signingKey);

  // Two rotations from the same version: the one that loses the swap is a conflict, and its
  // recorder is never called.
  const held = f.holdNextRead();
  const late = f.signing.rotate({ actor: { login: 'dana' }, audit });
  await held.answer;
  await f.signing.rotate({ actor: { login: 'dana' }, audit });
  held.release();
  await assert.rejects(late, error => error.code === 'signing_conflict');
  assert.equal(recorded.length, 2, 'only the rotation that won');
});

// AUTH-REMEDIATION F1/F3: earlier pre-release builds open signingSecret and previousSigningSecret
// without checking what they hold, take whatever opens for their HMAC secret, sign with its text
// and show it under Show signing secret. So this release keeps the private keys in signingKey and
// previousSigningKey (schema 2), which those builds never open, and leaves the pre-release fields
// empty; a build that knows only schema 1 reads the document as read-only, so it cannot save a
// secret of its own there either (it sends webhooks unsigned). That holds with or without a
// webhook: keys a build before schema 2 left in the pre-release fields are moved at a start
// without GOBLIN_WEBHOOK_URL too (the data a failed upgrade's start leaves for a rollback).
test('an earlier pre-release build started on data this release has run on obtains no private key: the document is read-only to it, its pre-release fields empty', async t => {
  const cases = {
    'a key pair this release made, then replaced': async s => {
      const f = await fixture(s);
      f.clock.burn(1000);
      await f.signing.rotate({ actor: { login: 'admin' } });
      return { f, keys: [(await f.stored()).signingKey, f.original], safe: true };
    },
  };
  for (const configured of [false, true])
    cases[
      `keys in the pre-release fields (builds before schema 2), a start ${configured ? 'with' : 'without'} a webhook`
    ] = async s => {
      const keys = [generateSigningKey(), generateSigningKey()];
      const f = await fixture(s, {
        configured,
        async before({ control, keyring, clock }) {
          await writeAsEarlierBuild(
            { control, keyring },
            {
              signingSecret: keys[0],
              previousSigningSecret: keys[1],
              previousUntil: clock.wall() + day,
              createdAt: clock.wall() - 1000,
            }
          );
        },
      });
      return { f, keys };
    };
  for (const [name, make] of Object.entries(cases))
    await t.test(name, async s => {
      const { f, keys, safe = false } = await make(s);
      const earlier = prereleaseBuild(f);
      const doc = await earlier.read();
      assert.deepEqual([doc.schema, doc.readOnly], [2, true]);
      assert.deepEqual([doc.value.signingSecret, doc.value.previousSigningSecret], [null, null]);
      assert.deepEqual(doc.unreadable, []);
      // Show signing secret answers signing_unavailable, and nothing signs.
      assert.equal(await earlier.reveal(), null);
      assert.deepEqual(await earlier.keys(f.clock.wall()), []);
      const seen = JSON.stringify([doc, await earlier.keys(f.clock.wall())]);
      for (const key of keys)
        for (const form of privateForms(key)) assert.equal(seen.includes(form), false);
      assert.doesNotMatch(seen, /PRIVATE KEY/);
      // Its start with a webhook cannot save an HMAC secret: the document stays as it is.
      await assert.rejects(earlier.create(f.clock.wall()), { code: 'settings_newer' });
      assert.equal((await earlier.read()).version, doc.version);
      // This release, started again with a webhook, signs with the same keys.
      const again = createSigning({
        settings: f.control.settings,
        configured: true,
        clock: f.clock,
        logger: quietLogger(),
      });
      assert.equal(await again.ensure(), true);
      if (safe) {
        assert.deepEqual(again.keys(), keys);
        assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, doc.version);
      } else {
        assert.equal(
          again.keys().some(key => keys.includes(key)),
          false
        );
        assert.equal(again.keys().length, 1);
        assert.equal(again.held, true);
      }
    });
});

// What the encryption key cannot open stays as it is: a start without a webhook moves nothing it
// cannot read (the document is saved as schema 2 all the same), and nothing opens it; a start with
// a webhook replaces the key pair, clears the pre-release fields with it, and says the previous key
// could not be opened. A value that opens but is neither an HMAC secret nor an Ed25519 key is left
// where it is without a webhook (never signed with), and replaced, with its own line and audit
// row, at a start with one.
test('without a webhook, a pre-release field the encryption key cannot open, or one holding an unknown value, is cleared; enabling the webhook creates fresh held authority', async t => {
  const other = await Keyring.open(memoryKeyringStore(), { key: randomBytes(32) });
  const lost = generateSigningKey();
  const cases = [
    [
      'unreadable',
      ({ control }) =>
        writeAsEarlierBuild({ control, keyring: other }, { signingSecret: lost, createdAt: 1000 }),
      'Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key (Configure → Notifications). The previous key could not be opened with the current encryption key.',
    ],
    [
      'unknown',
      ({ control, keyring }) =>
        writeAsEarlierBuild(
          { control, keyring },
          { signingSecret: 'not-a-signing-key-canary-5209', createdAt: 1000 }
        ),
      UNREADABLE_LINE,
    ],
  ];
  for (const [kind, write, line] of cases)
    await t.test(kind, async s => {
      let sealed;
      const f = await fixture(s, {
        configured: false,
        async before(context) {
          await write(context);
          const { value } = await createSettingsStore(context.control.db).get(
            'notify',
            'envWebhook'
          );
          sealed = JSON.parse(value).signingSecret;
        },
      });
      const rows = createSettingsStore(f.control.db);
      const row = await rows.get('notify', 'envWebhook');
      assert.equal(row.schema, 2);
      assert.equal(
        Object.hasOwn(JSON.parse(row.value), 'signingSecret'),
        false,
        'retired authority removed'
      );
      const doc = await f.control.settings.get('notify', 'envWebhook');
      assert.deepEqual(doc.unreadable, []);
      assert.equal(doc.value.signingKey, null, 'nothing moved');
      assert.equal(doc.value.signingSecret, null);
      assert.deepEqual(f.logger.lines, { error: [], warn: [], info: [] });
      assert.deepEqual(f.events, []);
      // The pre-release build cannot open the unreadable value either.
      if (kind === 'unreadable') {
        const earlier = prereleaseBuild(f);
        assert.equal(await earlier.reveal(), null);
        assert.deepEqual(await earlier.keys(f.clock.wall()), []);
      }
      // A start with a webhook: a new pair, the pre-release field cleared, a line and a row.
      const logger = quietLogger(),
        events = [];
      const withWebhook = createSigning({
        settings: f.control.settings,
        configured: true,
        clock: f.clock,
        logger,
        onEvent: record => events.push(record),
      });
      assert.equal(await withWebhook.ensure(), true);
      const after = JSON.parse((await rows.get('notify', 'envWebhook')).value);
      assert.equal(Object.hasOwn(after, 'signingSecret'), false);
      assert.match((await f.stored()).signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
      assert.deepEqual([after.heldSince, withWebhook.held], [f.clock.wall(), true]);
      assert.deepEqual(logger.lines.warn, [
        'Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key (Configure → Notifications).',
      ]);
      assert.deepEqual(
        events.map(({ action, detail }) => [action, detail]),
        [['signing.created', { replaced: false }]]
      );
    });
});

// A rotation while the start work has not yet saved the document in this release's form (a full
// disk at the start, say) keeps a key still in the pre-release field signing beside the new one
// for 24 hours, moved to previousSigningKey, as any rotation keeps the current key (review SIGN-2:
// it was dropped, so receivers that held its public key refused every alert at once), and
// clears the pre-release field; its audit diff says so. Nothing is held: a key is kept.
test('a rotation replaces retired authority without overlap and persists a hold, clears the field, and its audit diff says so', async t => {
  const left = generateSigningKey();
  const f = await fixture(t, {
    start: false,
    async before({ control, keyring, clock }) {
      await writeAsEarlierBuild(
        { control, keyring },
        { signingSecret: left, createdAt: clock.wall() - 1000 }
      );
    },
  });
  const recorded = [];
  f.clock.burn(1000);
  const now = f.clock.wall();
  const answer = await f.signing.rotate({
    actor: { login: 'admin' },
    audit: (tx, { diff }) => recorded.push(diff),
  });
  assert.deepEqual(answer, { createdAt: now, previousUntil: null });
  const saved = await f.stored();
  assert.match(saved.signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.deepEqual(
    [saved.previousSigningKey, saved.previousUntil, saved.heldSince],
    [null, null, now]
  );
  assert.deepEqual([saved.signingSecret, saved.previousSigningSecret], [null, null]);
  assert.deepEqual(
    recorded[0].filter(entry => entry.change).map(({ path, change }) => [path, change]),
    [
      ['signingKey', 'set'],
      ['signingSecret', 'cleared'],
    ]
  );
  // Both sign; the public keys name the kept one as the previous key until it stops.
  assert.deepEqual(f.signing.keys(), [saved.signingKey]);
  const shown = await f.signing.publicKeys();
  assert.deepEqual([shown.previous, shown.previousUntil], [null, null]);
  assert.equal(f.signing.held, true);
  await f.signing.releaseHold({ actor: 'admin' });
  assert.deepEqual(
    await sendSigned(t, f, { expected: publicOf(saved.signingKey), kept: publicOf(left) }),
    { verified: { expected: true, kept: false }, outcome: 'accepted' }
  );
  // The start's next try finds the document in this release's form: no write, no hold.
  const { version } = await f.control.settings.get('notify', 'envWebhook');
  assert.equal(await f.signing.ensure(), true);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, version);
  assert.deepEqual([f.signing.held, f.signing.keys()], [false, [saved.signingKey]]);
  const earlier = prereleaseBuild(f);
  assert.equal(await earlier.reveal(), null);
  assert.doesNotMatch(JSON.stringify(await earlier.read()), /PRIVATE KEY/);
});

// Review F2: a key pair that replaces signing material receivers may check (a pre-release HMAC
// secret, a key the encryption key no longer opens, a value removed earlier) cannot sign beside
// it, so the webhook holds its alerts (heldSince, saved with the new key) until an admin resumes
// it. The first key of a document never saved is not held: nothing was ever signed for it.
const prereleaseHmac = ({ control, keyring, clock }) =>
  writeAsEarlierBuild(
    { control, keyring },
    { signingSecret: 'c0ffee'.repeat(10) + 'beef', createdAt: clock.wall() - 1000 }
  );

test('review F2: a first key pair is not held; one that replaces an HMAC secret is held until releaseHold(), through a rotation and a restart', async t => {
  const fresh = await fixture(t);
  assert.deepEqual([fresh.signing.held, (await fresh.stored()).heldSince], [false, null]);
  // Nothing to release: no write.
  await fresh.signing.releaseHold({ actor: 'admin' });
  assert.equal((await fresh.control.settings.get('notify', 'envWebhook')).version, 1);

  const f = await fixture(t, { before: prereleaseHmac });
  const heldSince = (await f.stored()).heldSince;
  assert.deepEqual([f.signing.held, heldSince], [true, f.clock.wall()]);
  // The public key is there to give receivers while the webhook is held.
  assert.equal((await f.signing.publicKeys()).keyId, publicSigningKey(f.original).keyId);
  // A rotation keeps the hold; so does a restart, which makes no new key.
  await f.clock.advance(1000);
  await f.signing.rotate({ actor: 'admin' });
  assert.deepEqual([f.signing.held, (await f.stored()).heldSince], [true, heldSince]);
  const rotated = await f.stored();
  const restart = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await restart.ensure(), true);
  assert.equal(restart.held, true);
  assert.equal((await f.stored()).signingKey, rotated.signingKey);
  // A session that ended while the document was read: its check throws inside the write, and
  // the hold stays.
  const ended = new Error('the session ended');
  await assert.rejects(
    f.signing.releaseHold({
      actor: 'admin',
      check: () => {
        throw ended;
      },
    }),
    error => error === ended
  );
  assert.deepEqual([f.signing.held, (await f.stored()).heldSince], [true, heldSince]);
  // Released: cleared in one write that ran the check, the keys and their overlap as they were.
  const { version } = await f.control.settings.get('notify', 'envWebhook');
  let checks = 0;
  await f.signing.releaseHold({ actor: 'admin', check: () => checks++ });
  const released = await f.stored();
  assert.equal(checks, 1);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, version + 1);
  assert.deepEqual([f.signing.held, released.heldSince], [false, null]);
  assert.deepEqual({ ...released, heldSince: heldSince }, rotated);
  assert.deepEqual(f.signing.keys(), [rotated.signingKey, rotated.previousSigningKey]);
  // A later start finds no hold and writes nothing.
  const later = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await later.ensure(), true);
  assert.equal(later.held, false);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, version + 1);
  // Without a webhook nothing is held, and nothing is released.
  const none = await fixture(t, { configured: false, before: prereleaseHmac });
  assert.equal(none.signing.held, false);
  const noneVersion = (await none.control.settings.get('notify', 'envWebhook')).version;
  await none.signing.releaseHold({ actor: 'admin' });
  assert.equal((await none.control.settings.get('notify', 'envWebhook')).version, noneVersion);
});

test('review F2: the hold is known from the read on, also while the new key cannot be saved; releaseHold() cannot end it before the key is saved', async t => {
  const f = await fixture(t, { start: false, before: prereleaseHmac });
  const write = f.control.db.write;
  f.control.db.write = () =>
    Promise.reject(
      Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' })
    );
  assert.equal(await f.signing.ensure(), false);
  assert.equal(f.signing.held, true);
  assert.deepEqual(f.signing.keys(), []);
  assert.deepEqual(f.logger.lines.error, [
    'The new webhook signing key could not be saved (the disk is full); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds.',
  ]);
  // Review SEC-1: no key saved, so no public key receivers could have and nothing to sign
  // with: Resume's releaseHold() is refused and the hold stays, also once writes work again
  // and before the next ensure() saved the key. (Before, it was forgotten, and Resume sent the
  // held alerts unsigned.)
  const before = await f.control.settings.get('notify', 'envWebhook');
  let checks = 0;
  await assert.rejects(f.signing.releaseHold({ actor: 'admin', check: () => checks++ }), {
    code: 'signing_unavailable',
    status: 503,
  });
  assert.deepEqual([f.signing.held, f.signing.keys()], [true, []]);
  f.control.db.write = write;
  await assert.rejects(f.signing.releaseHold({ actor: 'admin', check: () => checks++ }), {
    code: 'signing_unavailable',
  });
  assert.equal(f.signing.held, true);
  assert.equal(checks, 0);
  assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, before.version);
  // The next start work saves the key pair with the hold; then releaseHold() ends it.
  assert.equal(await f.signing.ensure(), true);
  assert.deepEqual([f.signing.held, (await f.stored()).heldSince], [true, f.clock.wall()]);
  await f.signing.releaseHold({ actor: 'admin', check: () => checks++ });
  assert.deepEqual([checks, f.signing.held, (await f.stored()).heldSince], [1, false, null]);
});

test('review SEC-1: a rotation while the new key could not be saved yet saves the hold, so a restart still holds', async t => {
  const f = await fixture(t, { start: false, before: prereleaseHmac });
  const write = f.control.db.write;
  f.control.db.write = () =>
    Promise.reject(
      Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' })
    );
  assert.equal(await f.signing.ensure(), false);
  assert.equal(f.signing.held, true);
  // Writes work again before the next ensure(): an admin replaces the signing key.
  f.control.db.write = write;
  await f.clock.advance(1000);
  await f.signing.rotate({ actor: 'admin' });
  const rotated = await f.stored();
  // Saved with the hold (before, heldSince stayed null and the HMAC secret was cleared, so a
  // restart sent the alerts signed with a key receivers did not have).
  assert.deepEqual(
    [rotated.heldSince, rotated.signingSecret, f.signing.held],
    [f.clock.wall(), null, true]
  );
  const restart = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await restart.ensure(), true);
  assert.equal(restart.held, true);
  assert.equal((await f.stored()).signingKey, rotated.signingKey);
  // A rotation of a document whose hold is saved keeps that time; without a hold, none is set.
  await f.clock.advance(1000);
  await f.signing.rotate({ actor: 'admin' });
  assert.equal((await f.stored()).heldSince, rotated.heldSince);
  await f.signing.releaseHold({ actor: 'admin' });
  await f.signing.rotate({ actor: 'admin' });
  assert.deepEqual([(await f.stored()).heldSince, f.signing.held], [null, false]);
});

// Review SIGN-1: a 1.5 pre-release build that already signed with Ed25519 kept its keys in the
// pre-release fields. When the start cannot save them moved to this release's fields (a full
// disk), those keys still sign, as they did before the upgrade (before, every alert went out
// unsigned until the write succeeded, and receivers that verify refused it): describe() says
// Signed, publicKeys() shows them, `pending` stays and the next try moves them. A document that
// also holds an HMAC secret or an unknown value never signs with anything meanwhile.
const diskFull = () =>
  Promise.reject(
    Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' })
  );

test('review SIGN-1: retired keys never sign when replacement cannot be saved; recovery persists fresh held authority', async t => {
  const current = generateSigningKey(),
    previous = generateSigningKey();
  for (const form of ['orbit', 'another PEM form'])
    await t.test(form, async s => {
      let previousUntil, createdAt;
      const f = await fixture(s, {
        start: false,
        async before({ control, keyring, clock }) {
          previousUntil = clock.wall() + day;
          createdAt = clock.wall() - 1000;
          await writeAsEarlierBuild(
            { control, keyring },
            {
              signingSecret: form === 'orbit' ? current : ` ${current.replace(/\n/g, '\r\n')}\n`,
              previousSigningSecret: previous,
              previousUntil,
              createdAt,
            }
          );
        },
      });
      const write = f.control.db.write;
      f.control.db.write = diskFull;
      assert.equal(await f.signing.ensure(), false);
      assert.deepEqual([f.signing.keys(), f.signing.held, f.signing.pending], [[], true, true]);
      assert.deepEqual(f.signing.describe(), {
        configured: true,
        saved: false,
        createdAt: null,
        previousUntil: null,
      });
      assert.deepEqual(f.logger.lines.error, [
        'The new webhook signing key could not be saved (the disk is full); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds.',
      ]);
      await assert.rejects(f.signing.publicKeys(), { code: 'signing_unavailable' });
      assert.equal(f.signing.pending, true);
      assert.deepEqual(
        await sendSigned(t, f, { expected: publicOf(current), previous: publicOf(previous) }),
        { verified: null, outcome: 'pause' }
      );
      // Nothing was written: the keys are where the earlier build left them.
      const left = await f.control.settings.get('notify', 'envWebhook');
      assert.deepEqual([left.schema, left.version, left.value.signingKey], [1, 1, null]);
      // Writes work again: the next try moves them, and the same keys sign.
      f.control.db.write = write;
      assert.equal(await f.signing.ensure(), true);
      const moved = await f.control.settings.get('notify', 'envWebhook');
      assert.deepEqual(
        [moved.schema, moved.value.signingKey, moved.value.previousSigningKey],
        [2, moved.value.signingKey, null]
      );
      assert.deepEqual(
        [moved.value.signingSecret, moved.value.previousSigningSecret],
        [null, null]
      );
      assert.notEqual(moved.value.signingKey, current);
      assert.notEqual(moved.value.signingKey, previous);
      assert.deepEqual(
        [f.signing.keys(), f.signing.pending, f.signing.held],
        [[moved.value.signingKey], false, true]
      );
      assert.equal(f.logger.lines.warn.length, 1);
    });
  // Beside an HMAC secret or an unknown value, the start makes a new pair (held): until it is
  // saved nothing signs, and Show public key has nothing to show.
  for (const [name, beside] of [
    ['an HMAC secret', 'c0ffee'.repeat(10) + 'beef'],
    ['an unknown value', 'not-a-signing-key-canary-7311'],
  ])
    await t.test(`beside ${name}`, async s => {
      const f = await fixture(s, {
        start: false,
        before: ({ control, keyring, clock }) =>
          writeAsEarlierBuild(
            { control, keyring },
            {
              signingSecret: current,
              previousSigningSecret: beside,
              previousUntil: clock.wall() + day,
              createdAt: clock.wall() - 1000,
            }
          ),
      });
      f.control.db.write = diskFull;
      assert.equal(await f.signing.ensure(), false);
      assert.deepEqual([f.signing.keys(), f.signing.held], [[], true]);
      assert.equal(f.signing.describe().saved, false);
      await assert.rejects(f.signing.publicKeys(), { code: 'signing_unavailable' });
    });
});

// Review SIGN-2: a rotation that keeps no key (the pre-release field held an HMAC secret, an
// unknown value or a key the encryption key no longer opens) in a document saved before is held,
// as the start's new key pair would be, also when the start could not read the document (so it
// knew of no hold): before, it saved no hold, the start's next try found a ready, unheld
// document, and the alerts went signed with a key receivers did not have.
test('review SIGN-2: a rotation that keeps no key from a document saved before saves the hold, also when the start could not read it', async t => {
  const other = await Keyring.open(memoryKeyringStore(), { key: randomBytes(32) });
  const cases = {
    'an HMAC secret': prereleaseHmac,
    'an unknown value': ({ control, keyring, clock }) =>
      writeAsEarlierBuild(
        { control, keyring },
        { signingSecret: 'not-a-signing-key-canary-4417', createdAt: clock.wall() - 1000 }
      ),
    'a key the encryption key does not open': ({ control, clock }) =>
      writeAsEarlierBuild(
        { control, keyring: other },
        { signingSecret: generateSigningKey(), createdAt: clock.wall() - 1000 }
      ),
  };
  for (const [name, before] of Object.entries(cases))
    await t.test(name, async s => {
      const f = await fixture(s, { start: false, before });
      const raw = async () =>
        JSON.parse((await createSettingsStore(f.control.db).get('notify', 'envWebhook')).value);
      assert.equal(typeof (await raw()).signingSecret?.$sealed, 'string');
      f.faults.failNextRead = true;
      assert.equal(await f.signing.ensure(), false);
      assert.equal(f.signing.held, true, 'an unreadable authority cannot permit delivery');
      f.clock.burn(1000);
      const now = f.clock.wall();
      const recorded = [];
      const answer = await f.signing.rotate({
        actor: 'admin',
        audit: (tx, { diff }) => recorded.push(diff),
      });
      assert.deepEqual(answer, { createdAt: now, previousUntil: null });
      const saved = await f.stored();
      assert.deepEqual(
        [saved.heldSince, saved.previousSigningKey, saved.signingSecret],
        [now, null, null]
      );
      assert.ok(recorded[0].some(entry => entry.path === 'heldSince' && entry.to === now));
      // The pre-release value is removed, also one the encryption key does not open, and the
      // audit diff says so (review TD-1: that one was removed with no entry of its own).
      assert.equal((await raw()).signingSecret, undefined);
      assert.deepEqual(
        recorded[0].filter(entry => entry.change).map(({ path, change }) => [path, change]),
        [
          ['signingKey', 'set'],
          ['signingSecret', 'cleared'],
        ]
      );
      assert.equal(f.signing.held, true);
      // The start's next try keeps that key and the hold; so does a restart.
      assert.equal(await f.signing.ensure(), true);
      assert.deepEqual([f.signing.held, (await f.stored()).signingKey], [true, saved.signingKey]);
      const restart = createSigning({
        settings: f.control.settings,
        configured: true,
        clock: f.clock,
        logger: quietLogger(),
      });
      assert.equal(await restart.ensure(), true);
      assert.equal(restart.held, true);
      // Resume ends it.
      await f.signing.releaseHold({ actor: 'admin' });
      assert.deepEqual([f.signing.held, (await f.stored()).heldSince], [false, null]);
    });
  // A document never saved has no material receivers could check: its first key is not held.
  const fresh = await fixture(t, { start: false });
  await fresh.signing.rotate({ actor: 'admin' });
  assert.deepEqual([fresh.signing.held, (await fresh.stored()).heldSince], [false, null]);
});

// Writes `values` into notify/envWebhook as a newer release might (schema 3), which this release
// reads as read-only: the fields of this release, plus a key field of its own.
async function writeAsNewerBuild({ control, keyring }, values) {
  const newer = createSettings({
    store: createSettingsStore(control.db),
    keyring,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 3,
        fields: {
          signingKey: { secret: true, validate: value => value },
          previousSigningKey: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
          heldSince: { default: null, validate: value => value },
          signingKeyV3: { secret: true, validate: value => value },
        },
      }),
    ],
  });
  const { version } = await control.settings.get('notify', 'envWebhook');
  await newer.update('notify', 'envWebhook', values, { ifVersion: version, by: 'orbit' });
}

// Newer settings remain read-only: usable unheld current keys may sign, but missing
// authority and immutable saved holds cannot be bypassed or cleared by this release.

test('review SIGN-3: newer settings preserve holds and refuse unsigned fallback while unheld usable current keys continue', async t => {
  const cases = {
    'its key in a field of its own': () => ({
      signingKey: null,
      signingKeyV3: generateSigningKey(),
    }),
    'its key in a field of its own, held': clock => ({
      signingKey: null,
      signingKeyV3: generateSigningKey(),
      heldSince: clock.wall(),
    }),
    'a usable key, held': clock => ({ heldSince: clock.wall() }),
    // Review RO-USABLE-1: only the current key counts. A value this release does not know in
    // another key field (another key format, an HMAC secret) never signs, is not shown as a
    // previous key, and, unlike in a document this release can write, does not stop the
    // current key signing: such a document cannot be written, so it never got a new pair.
    'a usable key, beside a previous key this release does not know': clock => ({
      previousSigningKey: '{"kty":"OKP","crv":"Ed448","d":"canary-5521"}',
      previousUntil: clock.wall() + day,
    }),
    'a usable key, beside a previous key this release does not know, held': clock => ({
      previousSigningKey: '{"kty":"OKP","crv":"Ed448","d":"canary-5521"}',
      previousUntil: clock.wall() + day,
      heldSince: clock.wall(),
    }),
    'a usable key, beside an HMAC secret as the previous key': clock => ({
      previousSigningKey: randomBytes(32).toString('hex'),
      previousUntil: clock.wall() + day,
    }),
  };
  for (const [name, values] of Object.entries(cases))
    await t.test(name, async s => {
      const f = await fixture(s);
      await writeAsNewerBuild(f, values(f.clock));
      const doc = await f.control.settings.get('notify', 'envWebhook');
      assert.deepEqual([doc.schema, doc.readOnly], [3, true]);
      const logger = quietLogger();
      const signing = createSigning({
        settings: f.control.settings,
        configured: true,
        clock: f.clock,
        logger,
      });
      const usable = doc.value.signingKey !== null;
      const held = !usable || doc.value.heldSince != null;
      const passes = [];
      for (let i = 0; i < 3; i++) passes.push(await signing.ensure());
      assert.deepEqual(passes, Array(3).fill(usable));
      assert.equal(signing.held, held);
      assert.equal(signing.describe().saved, usable);
      // Resume has no hold to end, and writes nothing.
      if (!held) await signing.releaseHold({ actor: 'admin' });
      else
        await assert.rejects(signing.releaseHold({ actor: 'admin' }), {
          code: 'signing_compatibility',
        });
      assert.equal(signing.held, held);
      // Replace signing key is refused with the reason, as a delivery error the pipeline answers
      // with its own status (review ROTATE-RO-500: the SettingsError answered 500).
      await assert.rejects(signing.rotate({ actor: 'admin' }), {
        name: 'DeliveryError',
        status: 409,
        code: 'signing_compatibility',
        message:
          'A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.',
      });
      assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, doc.version);
      if (usable) {
        // Its key signs, with no Resume, and alone; Show public key shows it, and no previous key.
        assert.deepEqual(signing.keys(), [f.original]);
        const shown = await signing.publicKeys();
        assert.deepEqual(
          [shown.keyId, shown.previous, shown.previousUntil, signing.describe().previousUntil],
          [publicSigningKey(f.original).keyId, null, null, null]
        );
        assert.deepEqual(
          await sendSigned(t, { signing, clock: f.clock }, { expected: publicOf(f.original) }),
          held
            ? { verified: null, outcome: 'pause' }
            : { verified: { expected: true }, outcome: 'accepted' }
        );
        assert.deepEqual(logger.lines.error, []);
      } else {
        // No usable signing authority: no delivery, with the warning once.
        assert.deepEqual(signing.keys(), []);
        await assert.rejects(signing.publicKeys(), { code: 'signing_unavailable' });
        assert.equal(logger.lines.error.length, 1);
        assert.match(
          logger.lines.error[0],
          /^The new webhook signing key could not be saved \(.*newer Uptime Goblin.*\); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds\.$/
        );
      }
    });
});

test('security F01: revealable retired Ed25519 authority is replaced without overlap and held', async t => {
  const retired = generateSigningKey();
  const f = await fixture(t, {
    before: context =>
      writeAsEarlierBuild(context, {
        signingSecret: retired,
        previousSigningSecret: retired,
        createdAt: context.clock.wall(),
        previousUntil: context.clock.wall() + day,
      }),
  });
  const saved = await f.stored();
  assert.notEqual(saved.signingKey, retired);
  assert.equal(saved.previousSigningKey, null);
  assert.equal(saved.signingSecret, null);
  assert.equal(saved.previousSigningSecret, null);
  assert.equal(saved.heldSince, f.clock.wall());
  assert.equal(f.signing.held, true);
  assert.equal(f.signing.describe().saved, true);
  await f.signing.releaseHold({ actor: 'admin' });
  assert.equal(f.signing.held, false);
});

test('security F01: URL-unset cleanup never moves retired private keys into active fields', async t => {
  const retired = generateSigningKey();
  const f = await fixture(t, {
    configured: false,
    before: context =>
      writeAsEarlierBuild(context, {
        signingSecret: retired,
        previousSigningSecret: retired,
        createdAt: context.clock.wall(),
        previousUntil: context.clock.wall() + day,
      }),
  });
  const saved = await f.stored();
  assert.equal(saved.signingKey, null);
  assert.equal(saved.previousSigningKey, null);
  assert.equal(saved.signingSecret, null);
  assert.equal(saved.previousSigningSecret, null);
  const enabled = createSigning({
    settings: f.control.settings,
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
  });
  assert.equal(await enabled.ensure(), true);
  assert.equal(enabled.held, true);
  assert.notEqual((await f.stored()).signingKey, retired);
});

test('security F02/F06: newer saved holds and missing current keys stay held with zero POST', async t => {
  for (const values of [
    clock => ({ heldSince: clock.wall() }),
    () => ({
      signingKey: null,
      previousSigningKey: generateSigningKey(),
      previousUntil: 9999999999999,
    }),
  ])
    await t.test('immutable compatibility hold', async s => {
      const f = await fixture(s);
      await writeAsNewerBuild(f, values(f.clock));
      const before = await f.control.settings.get('notify', 'envWebhook');
      const signing = createSigning({
        settings: f.control.settings,
        configured: true,
        clock: f.clock,
        logger: quietLogger(),
      });
      await signing.ensure();
      assert.equal(signing.held, true);
      let posts = 0;
      const channel = createEnvWebhookChannel({
        url: 'http://127.0.0.1:1/hook',
        signingKeys: () => signing.keys(),
        hold: () => (signing.held ? 'held' : null),
        post: async () => {
          posts++;
          return { status: 200 };
        },
      });
      assert.equal(
        (await channel.send({ uid: 'held', events: [{ kind: 'firing' }] })).type,
        'pause'
      );
      assert.equal(posts, 0);
      await assert.rejects(signing.releaseHold({ actor: 'admin' }), {
        code: 'signing_compatibility',
        status: 409,
      });
      await assert.rejects(signing.rotate({ actor: 'admin' }), {
        code: 'signing_compatibility',
        status: 409,
      });
      assert.equal((await f.control.settings.get('notify', 'envWebhook')).version, before.version);
      assert.equal(signing.held, true);
    });
});

test('security F01/F03: failed migration writes retain retired bytes without signing or saved credit', async t => {
  const retired = generateSigningKey();
  const f = await fixture(t, {
    start: false,
    before: context =>
      writeAsEarlierBuild(context, {
        signingSecret: retired,
        createdAt: context.clock.wall(),
      }),
  });
  const before = await f.control.settings.get('notify', 'envWebhook');
  const signing = createSigning({
    configured: true,
    clock: f.clock,
    logger: quietLogger(),
    settings: {
      get: (...args) => f.control.settings.get(...args),
      update: async () => {
        throw Object.assign(new Error('disk full'), { code: 'SQLITE_FULL' });
      },
    },
  });
  assert.equal(await signing.ensure(), false);
  assert.equal(signing.describe().saved, false);
  assert.equal(signing.held, true);
  assert.deepEqual(signing.keys(), []);
  assert.deepEqual(await f.control.settings.get('notify', 'envWebhook'), before);
});

test('security F02: configured webhook refuses empty signing keys before transport', async () => {
  let posts = 0;
  const channel = createEnvWebhookChannel({
    url: 'http://127.0.0.1:1/hook',
    post: async () => {
      posts++;
      return { status: 200 };
    },
  });
  assert.equal((await channel.send({ uid: 'no-key', events: [{ kind: 'firing' }] })).type, 'pause');
  assert.equal(posts, 0);
});

test('security F01/F03: current-format continuity excludes copied retired authority', async t => {
  for (const copied of [false, true])
    await t.test(
      copied ? 'copied current key is replaced' : 'distinct current key stays',
      async s => {
        const current = generateSigningKey(),
          retired = copied ? current : generateSigningKey();
        const f = await fixture(s, {
          before: async context => {
            await context.control.settings.update(
              'notify',
              'envWebhook',
              {
                signingKey: current,
                previousSigningKey: retired,
                previousUntil: context.clock.wall() + day,
                createdAt: context.clock.wall() - 1000,
              },
              { ifVersion: 0, by: 'orbit' }
            );
            await writeAsEarlierBuild(context, { signingSecret: retired }, 2);
          },
        });
        const saved = await f.stored();
        assert.equal(saved.signingKey === current, !copied);
        assert.equal(saved.previousSigningKey, null);
        assert.equal(saved.previousUntil, null);
        assert.equal(saved.signingSecret, null);
        assert.equal(f.signing.held, copied);
        assert.equal(f.signing.describe().saved, true);
        assert.deepEqual(f.signing.keys(), [saved.signingKey]);
      }
    );
  await t.test('safe signability does not imply a failed upgrade was saved', async s => {
    const current = generateSigningKey(),
      retired = generateSigningKey();
    const f = await fixture(s, {
      start: false,
      before: async context => {
        await context.control.settings.update(
          'notify',
          'envWebhook',
          {
            signingKey: current,
            createdAt: context.clock.wall(),
          },
          { ifVersion: 0, by: 'orbit' }
        );
        await writeAsEarlierBuild(context, { signingSecret: retired }, 2);
      },
    });
    const before = await f.control.settings.get('notify', 'envWebhook');
    f.control.db.write = diskFull;
    assert.equal(await f.signing.ensure(), false);
    assert.equal(f.signing.describe().saved, false);
    assert.deepEqual(f.signing.keys(), [current]);
    assert.equal(f.signing.held, false);
    assert.deepEqual(await f.control.settings.get('notify', 'envWebhook'), before);
  });
});

for (const reader of ['publicKeys', 'ensure', 'releaseHold'])
  test(`security D02: stale ${reader} cannot clear a newer rotation read-back failure`, async t => {
    const f = await fixture(t);
    const held = f.holdNextRead();
    const reading = f.signing[reader]();
    await held.answer;
    f.failReadAfterNextWrite();
    f.clock.burn(1000);
    await f.signing.rotate({ actor: { login: 'dana' } });
    const committed = await f.stored();
    assert.equal(f.signing.pending, true);
    held.release();
    await reading;
    assert.equal(f.signing.pending, true);
    assert.equal(f.signing.describe().saved, false);
    assert.equal(f.signing.describe().createdAt, committed.createdAt);
    assert.deepEqual(f.signing.keys(), [committed.signingKey, f.original]);
    assert.equal(await f.signing.ensure(), true);
    assert.equal(f.signing.pending, false);
  });

for (const field of ['signingSecret', 'previousSigningSecret'])
  for (const operation of ['ensure', 'rotate', 'unset'])
    test(`security D01: unreadable ${field} taints both active keys during ${operation}`, async t => {
      const current = generateSigningKey(),
        previous = generateSigningKey();
      const other = await Keyring.open(memoryKeyringStore(), { key: randomBytes(32) });
      const f = await fixture(t, {
        start: false,
        configured: operation !== 'unset',
        before: async context => {
          await context.control.settings.update(
            'notify',
            'envWebhook',
            {
              signingKey: current,
              previousSigningKey: previous,
              previousUntil: context.clock.wall() + day,
              createdAt: context.clock.wall(),
            },
            { ifVersion: 0, by: 'orbit' }
          );
          await writeAsEarlierBuild(
            { control: context.control, keyring: other },
            { [field]: (field === 'signingSecret' ? current : previous).replace(/\n/g, '\r\n') },
            2
          );
        },
      });
      const before = await f.control.settings.get('notify', 'envWebhook');
      assert.ok(before.unreadable.includes(field));
      assert.equal(before.value.signingKey, current);
      const write = f.control.db.write;
      f.control.db.write = diskFull;
      if (operation === 'rotate') await assert.rejects(f.signing.rotate(), { code: 'SQLITE_FULL' });
      else assert.equal(await f.signing.ensure(), false);
      assert.deepEqual(await f.control.settings.get('notify', 'envWebhook'), before);
      assert.deepEqual(f.signing.keys(), []);
      f.control.db.write = write;
      if (operation === 'rotate') await f.signing.rotate();
      else assert.equal(await f.signing.ensure(), true);
      const saved = await f.stored();
      assert.equal(saved.previousSigningKey, null);
      assert.equal(saved.previousUntil, null);
      assert.equal(saved[field], null);
      assert.notEqual(saved.signingKey, current);
      assert.notEqual(saved.signingKey, previous);
      if (operation === 'unset') {
        assert.equal(saved.signingKey, null);
        const enabled = createSigning({
          settings: f.control.settings,
          configured: true,
          clock: f.clock,
        });
        assert.equal(await enabled.ensure(), true);
        assert.equal(enabled.held, true);
        assert.notEqual(enabled.keys()[0], current);
      } else {
        assert.equal(f.signing.held, true);
        assert.deepEqual(f.signing.keys(), [saved.signingKey]);
      }
    });
