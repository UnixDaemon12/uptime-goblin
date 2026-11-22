// The delivery routes (delivery spec §6.4) through the real pipeline, over a stand-in for the
// delivery service and the storage guard: permissions, CSRF, body limits, query and path
// validation, the contract bodies (test/contract/notifications-bodies.json), Retry-After, the
// webhook's public key (public material only: no route reveals a secret), and fail()'s
// disk-full answers and reports (§6.8).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { serveAuth, raw, login, browserWrite, basic } from './harness.mjs';
import {
  notificationRoutes,
  deliveriesQuery,
  actorOf,
  invalidRequest,
} from '../../lib/http/routes/notifications.mjs';
import { fail, settledOutcome, storageFullMessage } from '../../lib/http/pipeline.mjs';
import { replay } from '../../lib/http/body.mjs';
import { deliveryError, DeliveryError } from '../../lib/alerting/errors.mjs';
import { StorageFullError } from '../../lib/storage-guard.mjs';
import { identityError } from '../../lib/identity/errors.mjs';
import { fakeAlerting } from '../helpers/fake-alerting.mjs';
import { generateSigningKey, publicSigningKey } from '../../lib/notify/sign.mjs';
import { Keyring, memoryKeyringStore } from '../../lib/keyring.mjs';
import { createSettings, defineSetting, memorySettingsStore } from '../../lib/settings.mjs';
import { notifySettings } from '../../lib/alerting/settings.mjs';
import { createSigning } from '../../lib/alerting/signing.mjs';

const bodies = JSON.parse(
  fs.readFileSync(new URL('../contract/notifications-bodies.json', import.meta.url), 'utf8')
);
const { answers, errors } = bodies;
const uid = 'd_abcdefghijklmnopqrstuvwxyz';
const paths = {
  status: '/api/notifications',
  deliveries: '/api/notifications/deliveries',
  retry: `/api/notifications/deliveries/${uid}/retry`,
  resume: '/api/notifications/channels/env-webhook/resume',
  publicKey: '/api/notifications/webhook/public-key',
  rotate: '/api/notifications/webhook/signing-secret',
};
const copy = value => structuredClone(value);
// The stub's two signing keys (private, as Uptime Goblin seals them), and its public-key answer.
const stubKeys = [generateSigningKey(), generateSigningKey()];
const publicPart = key => {
  const { keyId, publicKey, publicKeyRaw } = publicSigningKey(key);
  return { keyId, publicKey, publicKeyRaw };
};
const publicAnswer = (current, previous = null) => ({
  ...publicSigningKey(current),
  createdAt: 1,
  previousUntil: previous ? 86400001 : null,
  previous: previous ? publicPart(previous) : null,
});
/** Whether `text` holds either stub private key, as PEM or as its PEM's body. */
const holdsPrivateKey = text =>
  stubKeys.some(key => text.includes(key) || text.includes(key.split('\n')[1]));

/**
 * A stand-in for the delivery service (delivery spec §5.5), for the routes only: it answers
 * the contract bodies and records every call. `state.fail[method]` makes a method throw that
 * error once; `state.gate[method]` (a promise) holds the method until it resolves.
 */
function stubAlerting() {
  const calls = [];
  const state = {
    status: copy(answers.status),
    page: copy(answers.deliveries),
    key: 0,
    rotated: false,
    signing: { configured: true, saved: true, createdAt: 1, previousUntil: null },
    fail: {},
    gate: {},
  };
  const run = async (name, args, answer) => {
    calls.push([name, ...args]);
    if (state.gate[name]) await state.gate[name];
    const error = state.fail[name];
    if (error) {
      delete state.fail[name];
      throw error;
    }
    return copy(answer());
  };
  const alerting = {
    refresh: () => run('refresh', [], () => undefined),
    snapshot: () => copy(state.status),
    deliveries: query => run('deliveries', [query], () => state.page),
    retry: (id, options) => run('retry', [id, options], () => answers.retry),
    resume: (id, options) => run('resume', [id, options], () => answers.resume),
    signing: {
      describe: () => (state.signing ? copy(state.signing) : null),
      publicKeys: (...args) =>
        run('publicKeys', args, () =>
          publicAnswer(stubKeys[state.key], state.rotated ? stubKeys[1 - state.key] : null)
        ),
      rotate: options =>
        run('rotate', [options], () => {
          state.key = 1 - state.key;
          state.rotated = true;
          return answers.rotate;
        }),
    },
  };
  return { alerting, calls, state, names: () => calls.map(([name]) => name) };
}

/** A stand-in storage guard: full or not, and every error fail() and the routes report. */
function stubGuard() {
  const noted = [];
  let full = false;
  return {
    noted,
    setFull: value => (full = value),
    admitConfigWrite() {
      if (full) throw new StorageFullError();
    },
    noteWriteError(error) {
      noted.push(error);
      return true;
    },
  };
}

async function serve(t, options = {}) {
  const service = stubAlerting(),
    guard = stubGuard();
  const served = await serveAuth(t, {
    routes: [
      ...notificationRoutes({ alerting: service.alerting, guard }),
      ...(options.routes ?? []),
    ],
    guard,
    ...options,
  });
  return { ...served, ...service, guard };
}

// A script's request with Basic (legacy CSRF rule: X-Goblin-Request and JSON for writes).
const get = (port, path, lines = []) =>
  raw(port, [`GET ${path} HTTP/1.1`, `Authorization: ${basic()}`, ...lines]);
const post = (port, path, body = '{}', lines = []) =>
  raw(
    port,
    [
      `POST ${path} HTTP/1.1`,
      `Authorization: ${basic()}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      ...lines,
    ],
    body
  );

// The answer as the contract file writes it: the status, the headers it lists, and the body.
function assertError(answer, name, { retryAfter } = {}) {
  const expected = errors[name];
  assert.ok(expected, name);
  assert.equal(answer.status, expected.status, `${name}: ${answer.body}`);
  assert.deepEqual(answer.json, expected.body, name);
  if (expected.headers['retry-after'] === '<seconds>')
    assert.equal(answer.headers['retry-after'], String(retryAfter), name);
  else assert.equal(answer.headers['retry-after'], expected.headers['retry-after'], name);
  assert.equal(answer.headers['cache-control'], 'no-store', name);
}

test('the delivery routes answer the contract bodies and pass what was asked to the service', async t => {
  const { port, calls, names } = await serve(t);
  const status = await get(port, paths.status);
  assert.equal(status.status, 200);
  assert.deepEqual(status.json, answers.status);
  assert.equal(status.headers['cache-control'], 'no-store');
  // The status is read again before it is answered (the page polls it).
  assert.deepEqual(names(), ['refresh']);

  const page = await get(port, paths.deliveries);
  assert.equal(page.status, 200);
  assert.deepEqual(page.json, answers.deliveries);
  assert.deepEqual(calls.at(-1), [
    'deliveries',
    { filter: 'all', channel: null, cursor: null, limit: 50 },
  ]);
  await get(port, `${paths.deliveries}?filter=problems&channel=env-webhook&cursor=42&limit=10`);
  assert.deepEqual(calls.at(-1), [
    'deliveries',
    { filter: 'problems', channel: 'env-webhook', cursor: 42, limit: 10 },
  ]);
  // Other names are ignored, as on every Uptime Goblin route (a widget's cache-buster).
  assert.equal((await get(port, `${paths.deliveries}?_=1759149296000`)).status, 200);
  assert.equal((await get(port, `${paths.status}?_=1759149296000`)).status, 200);

  const retried = await post(port, paths.retry);
  assert.equal(retried.status, 200);
  assert.deepEqual(retried.json, answers.retry);
  // The route hands the service its re-check of the session, run right before the requeue.
  const [, , { check: retryCheck, ...retryOptions }] = calls.at(-1);
  assert.deepEqual([...calls.at(-1).slice(0, 2), retryOptions], ['retry', uid, { actor: 'admin' }]);
  assert.equal(typeof retryCheck, 'function');

  const resumed = await post(port, paths.resume);
  assert.equal(resumed.status, 200);
  assert.deepEqual(resumed.json, answers.resume);
  const [, , { check: resumeCheck, ...resumeOptions }] = calls.at(-1);
  assert.deepEqual(
    [...calls.at(-1).slice(0, 2), resumeOptions],
    ['resume', 'env-webhook', { actor: 'admin' }]
  );
  assert.equal(typeof resumeCheck, 'function');
  assert.equal(
    (await post(port, '/api/notifications/channels/email/resume')).status,
    200,
    'both built-in channels can be resumed'
  );

  // The public key: a read, public material only, exactly what the service answered.
  const keys = await get(port, paths.publicKey);
  assert.equal(keys.status, 200);
  assert.deepEqual(keys.json, publicAnswer(stubKeys[0]));
  assert.deepEqual(calls.at(-1), ['publicKeys']);
  assert.equal(keys.headers['cache-control'], 'no-store');
  assert.equal(holdsPrivateKey(keys.body), false, 'never a private key');

  const rotated = await post(port, paths.rotate);
  assert.equal(rotated.status, 200);
  assert.deepEqual(rotated.json, answers.rotate);
  assert.equal(holdsPrivateKey(rotated.body), false, 'never a private key');
  // The rotation's audit row is written by the settings store, in the unit that saves the new
  // key (audit spec §5.3): the route hands the service its recorder.
  const [rotate, { audit: recorder, check: rotateCheck, ...rotation }] = calls.at(-1);
  assert.deepEqual([rotate, rotation], ['rotate', { actor: 'admin' }]);
  assert.equal(typeof recorder, 'function');
  // And the re-check of the session the settings store runs first in that unit.
  assert.equal(typeof rotateCheck, 'function');
  // After it, the previous public key is listed beside the new one.
  const after = await get(port, paths.publicKey);
  assert.deepEqual(after.json, publicAnswer(stubKeys[1], stubKeys[0]));
  assert.equal(holdsPrivateKey(after.body), false);
});

test('every delivery route needs its own permission', async t => {
  let denied = null;
  const { port, names } = await serve(t, {
    permitted: (access, permission) => permission !== denied && access.permissions.has(permission),
  });
  const routes = [
    ['notifications:read', () => get(port, paths.status)],
    ['notifications:read', () => get(port, paths.deliveries)],
    ['notifications:operate', () => post(port, paths.retry)],
    ['notifications:operate', () => post(port, paths.resume)],
    ['notifications:read', () => get(port, paths.publicKey)],
    ['channels:write', () => post(port, paths.rotate)],
  ];
  for (const [permission, send] of routes) {
    denied = permission;
    const answer = await send();
    assert.equal(answer.status, 403, permission);
    assert.equal(answer.json.code, 'forbidden', permission);
  }
  assert.deepEqual(names(), [], 'a refused request reaches no service method');
  // Each needs only its own: denying another permission refuses none of them.
  denied = 'settings:write';
  for (const [permission, send] of routes) assert.equal((await send()).status, 200, permission);
});

test('the delivery actions keep the CSRF rules and need JSON', async t => {
  const { port, names } = await serve(t);
  // A script's Basic write without X-Goblin-Request is refused (1.4.3's rule).
  for (const path of [paths.retry, paths.resume, paths.rotate]) {
    const refused = await raw(
      port,
      [`POST ${path} HTTP/1.1`, `Authorization: ${basic()}`, 'Content-Type: application/json'],
      '{}'
    );
    assert.equal(refused.status, 403, path);
    assert.equal(refused.json.code, 'cross_origin', path);
    const plain = await raw(
      port,
      [
        `POST ${path} HTTP/1.1`,
        `Authorization: ${basic()}`,
        'X-Goblin-Request: 1',
        'Content-Type: text/plain',
      ],
      '{}'
    );
    assert.equal(plain.status, 415, path);
  }
  // A session cookie's write must prove it comes from Uptime Goblin's page (Origin, fetch metadata).
  const origin = `http://127.0.0.1:${port}`;
  const { cookie } = await login(port);
  assert.ok(cookie);
  for (const path of [paths.retry, paths.resume, paths.rotate]) {
    const noOrigin = await raw(
      port,
      [
        `POST ${path} HTTP/1.1`,
        'X-Goblin-Request: 1',
        'Content-Type: application/json',
        `Cookie: ${cookie}`,
      ],
      '{}'
    );
    assert.equal(noOrigin.status, 403, path);
    assert.equal(noOrigin.json.code, 'cross_origin', path);
    const crossSite = await raw(
      port,
      [`POST ${path} HTTP/1.1`, ...browserWrite('https://elsewhere.example'), `Cookie: ${cookie}`],
      '{}'
    );
    assert.equal(crossSite.status, 403, path);
  }
  assert.deepEqual(names(), []);
  for (const path of [paths.retry, paths.resume, paths.rotate]) {
    const allowed = await raw(
      port,
      [`POST ${path} HTTP/1.1`, ...browserWrite(origin), `Cookie: ${cookie}`],
      '{}'
    );
    assert.equal(allowed.status, 200, path);
  }
  // Reads need no CSRF headers (a widget's or the page's GET), the public key's included.
  const read = await raw(port, [`GET ${paths.status} HTTP/1.1`, `Cookie: ${cookie}`]);
  assert.equal(read.status, 200);
  const publicKey = await raw(port, [`GET ${paths.publicKey} HTTP/1.1`, `Cookie: ${cookie}`]);
  assert.equal(publicKey.status, 200);
});

test('the actions take {} of at most 1 KiB, and nothing else', async t => {
  const { port, names } = await serve(t);
  for (const path of [paths.retry, paths.resume, paths.rotate]) {
    const large = await post(port, path, JSON.stringify({ pad: 'x'.repeat(1100) }));
    assert.equal(large.status, 413, path);
    assert.equal(large.json.error, 'Request is too large', path);
    for (const body of ['{"force":true}', '[]', 'null', '"x"', '1']) {
      const refused = await post(port, path, body);
      assert.equal(refused.status, 400, `${path} ${body}`);
      assert.deepEqual(refused.json, {
        error: 'This request is not valid: send an empty JSON object ({}).',
        code: 'invalid_request',
      });
    }
    const broken = await post(port, path, '{');
    assert.equal(broken.status, 400, path);
  }
  assert.deepEqual(names(), [], 'no refused body reaches the service');
  // Exactly 1024 bytes of an empty object (JSON allows the spaces) is still accepted.
  const padded = '{' + ' '.repeat(1022) + '}';
  assert.equal(Buffer.byteLength(padded), 1024);
  assert.equal((await post(port, paths.retry, padded)).status, 200);
});

test('query parameters are validated: an unknown value is 400 invalid_request', async t => {
  const { port, names } = await serve(t);
  // The contract's own example.
  assertError(await get(port, `${paths.deliveries}?cursor=abc`), 'invalid_request');
  const refused = [
    'cursor=0',
    'cursor=007',
    'cursor=-1',
    'cursor=1.5',
    'cursor=1e3',
    'cursor=12345678901234567',
    'cursor=9007199254740992',
    'cursor=',
    // m:<n> names a row kept in memory (A30), with the same number rules.
    'cursor=m:0',
    'cursor=m:007',
    'cursor=m:',
    'cursor=m:-1',
    'cursor=m:9007199254740992',
    'cursor=M:1',
    'cursor=m1',
    'cursor=n:1',
    'filter=everything',
    'filter=',
    'filter=All',
    'channel=slack',
    'channel=',
    'channel=EMAIL',
    'limit=0',
    'limit=101',
    'limit=abc',
    'limit=1.5',
    'limit=-5',
    'limit=',
    'limit=0100',
    'filter=all&filter=problems',
    'cursor=5&cursor=6',
  ];
  for (const query of refused) {
    const answer = await get(port, `${paths.deliveries}?${query}`);
    assert.equal(answer.status, 400, query);
    assert.equal(answer.json.code, 'invalid_request', query);
    assert.match(answer.json.error, /^This request is not valid: .+\.$/, query);
  }
  assert.deepEqual(names(), [], 'an invalid query reaches no service method');
  for (const query of [
    'cursor=1',
    'cursor=9007199254740991',
    'cursor=m:1',
    'cursor=m:9007199254740991',
    'limit=1',
    'limit=100',
    'filter=active',
    'filter=delivered',
    'channel=email',
  ])
    assert.equal((await get(port, `${paths.deliveries}?${query}`)).status, 200, query);
});

test('deliveriesQuery() and actorOf() as the routes use them', () => {
  const url = query => new URL(`http://x${paths.deliveries}${query}`);
  assert.deepEqual(deliveriesQuery(url('')), {
    filter: 'all',
    channel: null,
    cursor: null,
    limit: 50,
  });
  assert.deepEqual(deliveriesQuery(url('?cursor=9007199254740991&limit=100')), {
    filter: 'all',
    channel: null,
    cursor: Number.MAX_SAFE_INTEGER,
    limit: 100,
  });
  assert.throws(() => deliveriesQuery(url('?cursor=9999999999999999')), DeliveryError);
  // A row kept in memory: the cursor as given (A30).
  assert.deepEqual(deliveriesQuery(url('?cursor=m%3A12&limit=5')), {
    filter: 'all',
    channel: null,
    cursor: 'm:12',
    limit: 5,
  });
  assert.throws(() => deliveriesQuery(url('?cursor=m:9999999999999999')), DeliveryError);
  assert.throws(() => deliveriesQuery(url('?limit=101')), DeliveryError);
  const error = invalidRequest('this is the detail');
  assert.ok(error instanceof DeliveryError);
  assert.equal(error.status, 400);
  assert.equal(error.code, 'invalid_request');
  assert.equal(error.message, 'This request is not valid: this is the detail.');
  assert.equal(actorOf({ via: 'session', principal: { login: 'admin' } }), 'admin');
  assert.equal(actorOf({ via: 'basic', principal: { login: 'admin' } }), 'admin');
  // No access is named 'local' any more (the passwordless local preview is gone).
  assert.equal(actorOf({ via: 'local', principal: { login: null } }), 'unknown');
  assert.equal(actorOf(null), 'unknown');
});

test('an unknown delivery id or channel is a 404 that reaches no service method', async t => {
  const { port, names } = await serve(t);
  for (const id of [
    'd_ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd_abcdefghijklmnopqrstuvwxy',
    'd_abcdefghijklmnopqrstuvwxyz0',
    'd_abcdefghijklmnopqrstuvwx18',
    'g_abcdefghijklmnopqrstuvwxyz',
    'm-1',
  ])
    assertError(
      await post(port, `/api/notifications/deliveries/${id}/retry`),
      'delivery_not_found'
    );
  for (const id of ['slack', 'Email', 'webhook', 'env_webhook'])
    assertError(await post(port, `/api/notifications/channels/${id}/resume`), 'channel_unknown');
  assert.deepEqual(names(), []);
  // Another method on a known path is a 405 naming the one that exists.
  const wrong = await get(port, paths.retry);
  assert.equal(wrong.status, 405);
  assert.equal(wrong.headers.allow, 'POST');
  assert.equal((await post(port, paths.status)).headers.allow, 'GET');
});

test("the service's refusals are answered with the contract bodies and Retry-After", async t => {
  const { port, state, guard, names } = await serve(t);
  const refuse = (method, code, options) => (state.fail[method] = deliveryError(code, options));

  refuse('retry', 'delivery_not_found');
  assertError(await post(port, paths.retry), 'delivery_not_found');
  // Every variant: the row's own state, what the send-time recheck would skip (D24), and another
  // notification of its email digest, which is retried or refused as a whole.
  const notRetryable = [
    'sending',
    'waiting',
    'finished',
    'source_deleted',
    'switched_off',
    'digest_source_deleted',
    'digest_switched_off',
    'digest_other',
  ];
  for (const variant of notRetryable) {
    refuse('retry', 'delivery_not_retryable', { variant });
    assertError(await post(port, paths.retry), `delivery_not_retryable/${variant}`);
  }
  refuse('retry', 'delivery_outdated');
  assertError(await post(port, paths.retry), 'delivery_outdated');
  refuse('retry', 'delivery_outdated', { variant: 'digest' });
  assertError(await post(port, paths.retry), 'delivery_outdated/digest');
  // And the contract holds no other variant of these two codes that nothing here answers.
  assert.deepEqual(
    Object.keys(errors).filter(name => /^delivery_(not_retryable|outdated)\//.test(name)),
    [
      ...notRetryable.map(variant => `delivery_not_retryable/${variant}`),
      'delivery_outdated/digest',
    ]
  );
  refuse('retry', 'channel_paused', {
    name: 'Webhook',
    reason:
      'The webhook answered 401. Check GOBLIN_WEBHOOK_URL and the receiver; queued alerts wait until it is fixed.',
  });
  assertError(await post(port, paths.retry), 'channel_paused');
  // A45: a channel that is not set up (or switched off) would only skip the row.
  for (const variant of ['env-webhook', 'email', 'email-off']) {
    refuse('retry', 'channel_not_set_up', { variant });
    assertError(await post(port, paths.retry), `channel_not_set_up/${variant}`);
  }
  refuse('resume', 'channel_unknown');
  assertError(await post(port, paths.resume), 'channel_unknown');

  refuse('publicKeys', 'signing_unavailable');
  assertError(await get(port, paths.publicKey), 'signing_unavailable');
  assert.equal(errors.reveal_rate_limited, undefined, 'nothing is limited to reveal any more');
  refuse('rotate', 'signing_conflict');
  assertError(await post(port, paths.rotate), 'signing_conflict');

  refuse('deliveries', 'delivery_status_unavailable');
  assertError(await get(port, paths.deliveries), 'delivery_status_unavailable');
  // A status the service could not read is never answered as current.
  state.status = { ...state.status, available: false };
  assertError(await get(port, paths.status), 'delivery_status_unavailable');

  // Without GOBLIN_WEBHOOK_URL there is no signing key to show or replace.
  state.signing = null;
  const before = names().length;
  assertError(await get(port, paths.publicKey), 'webhook_not_configured');
  assertError(await post(port, paths.rotate), 'webhook_not_configured');
  assert.equal(names().length, before, 'neither reached the service');
  state.signing = { configured: true, saved: true, createdAt: 1, previousUntil: null };

  // A rotation is a configuration write: refused while the disk is full, nothing rotated.
  guard.setFull(true);
  assertError(await post(port, paths.rotate), 'storage_full');
  assert.equal(names().includes('rotate'), true, 'only the earlier refused rotation');
  assert.equal(names().filter(name => name === 'rotate').length, 1);
  assert.ok(guard.noted.at(-1) instanceof StorageFullError, 'the guard was told');
  // Retry and resume help alerts out and write little, and the public key is a read: allowed
  // while full.
  assert.equal((await post(port, paths.retry)).status, 200);
  assert.equal((await post(port, paths.resume)).status, 200);
  assert.equal((await get(port, paths.publicKey)).status, 200);
  guard.setFull(false);
  assert.equal((await post(port, paths.rotate)).status, 200);
});

// Review ROTATE-RO-500: settings a newer Uptime Goblin saved (this release started on its data again, a
// rollback) are read-only here, yet a usable key there signs and the card offers Replace signing
// key. That answered 500 ("Uptime Goblin could not complete this request", logged as a server fault):
// the settings store's SettingsError reached the pipeline. Through the real signing module it is
// now 409 signing_compatibility with the neutral catalogue message, and nothing is written.
test('signing compatibility refusals use 409 without Retry-After and audit as denied', async t => {
  const { port, state } = await serve(t);
  for (const [method, path] of [
    ['rotate', paths.rotate],
    ['resume', paths.resume],
  ]) {
    const error = deliveryError('signing_compatibility');
    state.fail[method] = error;
    const answer = await post(port, path);
    assertError(answer, 'signing_compatibility');
    assert.equal(settledOutcome(answer.status, error), 'denied');
  }
  assert.equal(settledOutcome(409, deliveryError('signing_conflict')), 'conflict');
});

test('Replace signing key on settings a newer Uptime Goblin saved: 409 signing_compatibility with the reason, nothing changed', async t => {
  const store = memorySettingsStore(),
    keyring = await Keyring.open(memoryKeyringStore(), { key: randomBytes(32) }),
    quiet = { warn() {}, error() {} };
  const settings = createSettings({ store, keyring, env: {}, definitions: [notifySettings] });
  const signing = createSigning({ settings, configured: true, logger: quiet });
  assert.equal(await signing.ensure(), true);
  // A newer release saves the settings in its own form (schema 3), the key kept.
  const newer = createSettings({
    store,
    keyring,
    env: {},
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 3,
        fields: {
          signingKey: { secret: true, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
  });
  const { version } = await settings.get('notify', 'envWebhook');
  await newer.update('notify', 'envWebhook', { createdAt: 2 }, { ifVersion: version });
  assert.equal(await signing.ensure(), true, 'its key signs');
  assert.equal(signing.describe().saved, true, 'so the card offers Replace signing key');
  const before = JSON.stringify(await store.get('notify', 'envWebhook'));
  const { port, alerting } = await serve(t);
  alerting.signing.rotate = options => signing.rotate(options);
  const answer = await post(port, paths.rotate);
  assert.equal(answer.status, 409, answer.body);
  assert.equal(answer.headers['retry-after'], undefined);
  assert.deepEqual(answer.json, {
    error:
      'A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.',
    code: 'signing_compatibility',
  });
  assert.equal(JSON.stringify(await store.get('notify', 'envWebhook')), before, 'nothing written');
});

test('the reveal route is gone: its path answers as any unknown route does, for every method', async t => {
  const { port, names } = await serve(t);
  const origin = `http://127.0.0.1:${port}`;
  const { cookie } = await login(port);
  const unknown = '/api/notifications/webhook/no-such-route';
  const ask = (method, path) =>
    method === 'GET'
      ? get(port, path)
      : raw(
          port,
          [
            `${method} ${path} HTTP/1.1`,
            `Authorization: ${basic()}`,
            'X-Goblin-Request: 1',
            'Content-Type: application/json',
          ],
          '{}'
        );
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    const gone = await ask(method, '/api/notifications/webhook/signing-secret/reveal');
    const other = await ask(method, unknown);
    assert.equal(gone.status, 404, method);
    assert.deepEqual(
      [gone.status, gone.json, gone.headers.allow],
      [other.status, other.json, other.headers.allow],
      method
    );
  }
  // As a browser would send it, with its session and CSRF headers: the same 404.
  const browser = await raw(
    port,
    [
      'POST /api/notifications/webhook/signing-secret/reveal HTTP/1.1',
      ...browserWrite(origin),
      `Cookie: ${cookie}`,
    ],
    '{}'
  );
  const browserOther = await raw(
    port,
    [`POST ${unknown} HTTP/1.1`, ...browserWrite(origin), `Cookie: ${cookie}`],
    '{}'
  );
  assert.deepEqual([browser.status, browser.json], [browserOther.status, browserOther.json]);
  assert.deepEqual(names(), [], 'nothing reached the service');
});

test('the public key is a read: never kept by the replay store, and the current one after a rotation', async t => {
  // Keyed writes replayed as server.mjs's idempotency does: the first answer per key and scope.
  const replies = new Map();
  let ran = 0;
  const idempotency = async (req, res, { key, scope }, run) => {
    const id = `${scope}\n${key}`;
    if (replies.has(id)) {
      replay(res, replies.get(id));
      return;
    }
    ran++;
    try {
      await run();
    } catch (error) {
      fail(res, error);
    }
    replies.set(id, res.orbitResponse);
  };
  const { port, names } = await serve(t, { idempotency });
  const key = ['Idempotency-Key: public-key-0001'];
  const first = await get(port, paths.publicKey, key);
  assert.equal(first.status, 200);
  // The rotation, keyed, does go through it (the read's exemption is what differs).
  assert.equal(
    (await post(port, paths.rotate, '{}', ['Idempotency-Key: rotate-key-0001'])).status,
    200
  );
  const second = await get(port, paths.publicKey, key);
  assert.equal(second.status, 200);
  assert.equal(second.headers['idempotent-replayed'], undefined);
  assert.notEqual(second.json.keyId, first.json.keyId, 'the current key, not a stored answer');
  assert.equal(second.json.previous.keyId, first.json.keyId);
  assert.equal(ran, 1, 'only the rotation went through the replay store');
  assert.deepEqual(
    names().filter(name => name === 'publicKeys'),
    ['publicKeys', 'publicKeys']
  );
});

test('a session that ends while the service works never receives its answer', async t => {
  const { port, state, calls } = await serve(t);
  const origin = `http://127.0.0.1:${port}`;
  const { cookie } = await login(port);
  let release;
  state.gate.publicKeys = new Promise(resolve => (release = resolve));
  const pending = raw(port, [
    `GET ${paths.publicKey} HTTP/1.1`,
    'Sec-Fetch-Site: same-origin',
    `Cookie: ${cookie}`,
  ]);
  // Real time, not loop turns: the request crosses a socket first.
  for (let i = 0; i < 500 && !calls.some(([name]) => name === 'publicKeys'); i++)
    await new Promise(resolve => setTimeout(resolve, 10));
  assert.ok(
    calls.some(([name]) => name === 'publicKeys'),
    'the read is running'
  );
  const signedOut = await raw(
    port,
    ['POST /api/auth/logout HTTP/1.1', ...browserWrite(origin), `Cookie: ${cookie}`],
    '{}'
  );
  assert.equal(signedOut.status, 204);
  release();
  const answer = await pending;
  assert.equal(answer.status, 401);
  assert.equal(answer.json.code, 'session_expired');
  assert.equal(answer.body.includes('PUBLIC KEY'), false, 'nothing for an ended session');
});

// The reads re-check the session after the service answered: a session signed out meanwhile
// gets 401, and none of the channels, counts or deliveries that were read.
test('signed out while the delivery status or history was read: 401, and nothing of it is sent', async t => {
  for (const [method, path] of [
    ['refresh', paths.status],
    ['deliveries', paths.deliveries],
  ])
    await t.test(path, async t => {
      const { port, state, calls } = await serve(t);
      const origin = `http://127.0.0.1:${port}`;
      const { cookie } = await login(port);
      let release;
      state.gate[method] = new Promise(resolve => (release = resolve));
      const pending = raw(port, [
        `GET ${path} HTTP/1.1`,
        'Sec-Fetch-Site: same-origin',
        `Cookie: ${cookie}`,
      ]);
      for (let i = 0; i < 500 && !calls.some(([name]) => name === method); i++)
        await new Promise(resolve => setTimeout(resolve, 10));
      const signedOut = await raw(
        port,
        ['POST /api/auth/logout HTTP/1.1', ...browserWrite(origin), `Cookie: ${cookie}`],
        '{}'
      );
      assert.equal(signedOut.status, 204);
      release();
      const answer = await pending;
      assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired']);
      assert.deepEqual(Object.keys(answer.json).sort(), ['code', 'error', 'transport']);
    });
});

test("fail() reports every disk-full error to the pipeline's storage guard and answers 503", async t => {
  const throwing = (path, error) => ({
    method: 'POST',
    path,
    auth: 'session',
    permission: 'settings:write',
    summary: 'throws',
    handler: () => {
      throw error;
    },
  });
  const identityFull = identityError('storage_full'),
    enospc = Object.assign(new Error('ENOSPC: no space left on device, write'), {
      code: 'ENOSPC',
    }),
    edquot = Object.assign(new Error('EDQUOT: disk quota exceeded'), { code: 'EDQUOT' }),
    controlFull = Object.assign(new Error('database or disk is full'), {
      class: 'full',
      code: 'SQLITE_FULL',
    }),
    guardFull = new StorageFullError(),
    // History (lib/store.mjs) is capped and recycles itself: its SQLITE_FULL carries no class
    // and says nothing about the disk.
    historyFull = Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' }),
    deliveryFull = deliveryError('delivery_status_unavailable');
  const { port, guard } = await serve(t, {
    routes: [
      throwing('/api/identity-full', identityFull),
      throwing('/api/enospc', enospc),
      throwing('/api/edquot', edquot),
      throwing('/api/control-full', controlFull),
      throwing('/api/guard-full', guardFull),
      throwing('/api/history-full', historyFull),
      throwing('/api/delivery', deliveryFull),
    ],
  });
  const errorsLogged = t.mock.method(console, 'error', () => {});
  // Identity's own storage_full keeps its answer (its text and Retry-After).
  const identity = await post(port, '/api/identity-full');
  assert.equal(identity.status, 503);
  assert.deepEqual(identity.json, { error: identityFull.message, code: 'storage_full' });
  assert.equal(identity.headers['retry-after'], '30');
  for (const path of ['/api/enospc', '/api/edquot', '/api/control-full', '/api/guard-full']) {
    const answer = await post(port, path);
    assert.equal(answer.status, 503, path);
    assert.deepEqual(answer.json, { error: storageFullMessage, code: 'storage_full' }, path);
    assert.equal(answer.headers['retry-after'], '60', path);
  }
  assert.deepEqual(errorsLogged.mock.calls.length, 3, 'one line for each raw disk-full error');
  for (const call of errorsLogged.mock.calls)
    assert.match(
      call.arguments.join(' '),
      /disk of the Uptime Goblin host is full.*\(request [\w-]+\)/
    );
  assert.deepEqual(guard.noted, [identityFull, enospc, edquot, controlFull, guardFull]);
  // Not a disk-full error: answered as before, and the guard is not told.
  const history = await post(port, '/api/history-full');
  assert.equal(history.status, 500);
  assert.equal((await post(port, '/api/delivery')).status, 503);
  assert.equal(guard.noted.length, 5);
  assert.deepEqual(errors.storage_full.body.error, storageFullMessage);
});

test('fail() without a pipeline guard still answers a full disk', () => {
  const answered = {};
  const res = {
    headersSent: false,
    getHeader: () => undefined,
    setHeader: (name, value) => (answered[name.toLowerCase()] = value),
    hasHeader: name => name.toLowerCase() in answered,
    writeHead: status => (answered.status = status),
    end: text => (answered.body = JSON.parse(text)),
  };
  const errorsLogged = [];
  const original = console.error;
  console.error = (...args) => errorsLogged.push(args.join(' '));
  try {
    fail(res, Object.assign(new Error('no space'), { code: 'ENOSPC' }));
  } finally {
    console.error = original;
  }
  assert.equal(answered.status, 503);
  assert.deepEqual(answered.body, { error: storageFullMessage, code: 'storage_full' });
  assert.equal(answered['retry-after'], '60');
  assert.equal(errorsLogged.length, 1);
  // json() records the answer, as for every answer (a 503 is never kept for a replay).
  assert.equal(res.orbitResponse.status, 503);
});

// ---------------------------------------------------------------------------------------------
// The same routes over fakeAlerting (test/helpers/fake-alerting.mjs): the service's own rules
// and views, deterministically and without a database.

// The keys and kinds of `actual` follow the contract example `expected` ("<ms>" is a time or
// null, "<uid>" a delivery id, "<id>" a row id, "<keyId>" 16 hex digits, "<publicKey>" an Ed25519
// public key as PEM, "<publicKeyRaw>" its 32 bytes in base64).
function sameShape(actual, expected, where = 'body') {
  if (expected === '<ms>')
    return assert.ok(actual === null || Number.isSafeInteger(actual), `${where}: ${actual}`);
  if (expected === '<uid>') return assert.match(actual, /^d_[a-z2-7]{26}$/, where);
  if (expected === '<id>')
    return assert.ok(actual === null || /^[1-9][0-9]*$/.test(actual), `${where}: ${actual}`);
  if (expected === '<keyId>') return assert.match(actual, /^[0-9a-f]{16}$/, where);
  if (expected === '<publicKey>')
    return assert.match(
      actual,
      /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/]{59}=\n-----END PUBLIC KEY-----\n$/,
      where
    );
  if (expected === '<publicKeyRaw>') return assert.match(actual, /^[A-Za-z0-9+/]{43}=$/, where);
  if (Array.isArray(expected)) {
    assert.ok(Array.isArray(actual), `${where}: a list`);
    if (expected.length)
      for (const [i, item] of actual.entries()) sameShape(item, expected[0], `${where}[${i}]`);
    return;
  }
  if (expected && typeof expected === 'object') {
    if (actual === null) return; // a nullable object (lastError, signing, alert time…)
    assert.deepEqual(Object.keys(actual).sort(), Object.keys(expected).sort(), where);
    for (const key of Object.keys(expected))
      sameShape(actual[key], expected[key], `${where}.${key}`);
    return;
  }
  if (expected === null) return; // the example's null: the value may be set
  assert.ok(
    actual === null || typeof actual === typeof expected,
    `${where}: ${typeof actual} for ${typeof expected}`
  );
}

async function serveFake(t, options = {}) {
  const fake = fakeAlerting(options),
    guard = stubGuard();
  const served = await serveAuth(t, {
    routes: notificationRoutes({ alerting: fake, guard }),
    guard,
  });
  return { ...served, fake, guard };
}

test('over fakeAlerting, every answer has the contract shape', async t => {
  const { port, fake } = await serveFake(t);
  fake.add({ channel: 'env-webhook', status: 'failed', lastStatus: 422, lastError: 'Refused.' });
  fake.add({ channel: 'email', status: 'delivered', batch: 'g_abcdefghijklmnopqrstuvwxyz' });
  fake.add({ channel: 'env-webhook', status: 'retrying', alert: { service: 'sonarr' } });
  const status = await get(port, paths.status);
  assert.equal(status.status, 200);
  sameShape(status.json, answers.status, 'status');
  const page = await get(port, paths.deliveries);
  assert.equal(page.status, 200);
  sameShape(page.json, { ...answers.deliveries, nextCursor: null }, 'deliveries');
  assert.equal(page.json.deliveries.length, 3);
  const failed = page.json.deliveries.find(row => row.status === 'failed');
  const retried = await post(port, `/api/notifications/deliveries/${failed.uid}/retry`);
  assert.equal(retried.status, 200, retried.body);
  sameShape(retried.json, answers.retry, 'retry');
  fake.setChannel('env-webhook', { state: 'paused', pausedReason: 'The webhook answered 401.' });
  const resumed = await post(port, paths.resume);
  assert.equal(resumed.status, 200);
  sameShape(resumed.json, answers.resume, 'resume');
  const keys = await get(port, paths.publicKey);
  assert.equal(keys.status, 200);
  sameShape(keys.json, answers.publicKey, 'publicKey');
  const rotated = await post(port, paths.rotate);
  assert.equal(rotated.status, 200);
  sameShape(rotated.json, answers.rotate, 'rotate');
  const after = await get(port, paths.publicKey);
  assert.ok(after.json.previous, 'the previous key, while it still signs');
  sameShape(after.json, answers.publicKey, 'publicKey after a rotation');
  assert.doesNotMatch(keys.body + after.body, /PRIVATE KEY/);
  // The dashboard's notifications field, as the server builds it from the same views.
  sameShape(fake.dashboard(), answers.dashboard.notifications, 'dashboard');
});

test('over fakeAlerting, Retry refuses what §6.4 refuses, with the contract bodies', async t => {
  const { port, fake } = await serveFake(t);
  const retry = uid => post(port, `/api/notifications/deliveries/${uid}/retry`);
  const sending = fake.add({ status: 'sending', alert: { service: 'radarr' } });
  assertError(await retry(sending.uid), 'delivery_not_retryable/sending');
  const waiting = fake.add({ status: 'waiting', alert: { service: 'lidarr' } });
  assertError(await retry(waiting.uid), 'delivery_not_retryable/waiting');
  const delivered = fake.add({ status: 'delivered', alert: { service: 'bazarr' } });
  assertError(await retry(delivered.uid), 'delivery_not_retryable/finished');
  // A failed firing whose recovery was delivered after it is outdated.
  const old = fake.add({ status: 'failed', alert: { service: 'sonarr' } });
  fake.add({ status: 'delivered', kind: 'resolved', alert: { service: 'sonarr' } });
  assertError(await retry(old.uid), 'delivery_outdated');
  // A digest is retried as a whole: one row that may not be retried refuses the batch.
  const batch = 'g_bbbbbbbbbbbbbbbbbbbbbbbbbb';
  const first = fake.add({ channel: 'email', status: 'failed', batch, alert: { service: 'a' } });
  fake.add({ channel: 'email', status: 'sending', batch, alert: { service: 'b' } });
  assertError(await retry(first.uid), 'delivery_not_retryable/sending');
  // A paused channel's row: Resume first.
  const held = fake.add({ status: 'paused', alert: { service: 'tautulli' } });
  fake.setChannel('env-webhook', {
    state: 'paused',
    pausedReason:
      'The webhook answered 401. Check GOBLIN_WEBHOOK_URL and the receiver; queued alerts wait until it is fixed.',
  });
  assertError(await retry(held.uid), 'channel_paused');
  assertError(await retry('d_' + 'z'.repeat(26)), 'delivery_not_found');
  // A45: a channel that is not set up or is switched off: Retry is neither offered nor taken,
  // a pause included (Resume could not send it either).
  fake.setChannel('env-webhook', { configured: false, enabled: false, state: 'not-configured' });
  assertError(await retry(held.uid), 'channel_not_set_up/env-webhook');
  const stranded = fake.add({ status: 'failed', alert: { service: 'whisparr' } });
  assertError(await retry(stranded.uid), 'channel_not_set_up/env-webhook');
  const listed = await get(port, `${paths.deliveries}?filter=problems&channel=env-webhook`);
  assert.equal(
    listed.json.deliveries.find(row => row.uid === stranded.uid).retryable,
    false,
    'no Retry offered'
  );
  const mailed = fake.add({ channel: 'email', status: 'failed', alert: { service: 'readarr' } });
  fake.setChannel('email', { enabled: false, state: 'off' });
  assertError(await retry(mailed.uid), 'channel_not_set_up/email-off');
  fake.setChannel('email', { configured: false, state: 'not-configured' });
  assertError(await retry(mailed.uid), 'channel_not_set_up/email');
  fake.setChannel('email', { configured: true, enabled: true, state: 'ok' });
  // A failed row with nothing later is requeued, and the answer says how many rows.
  fake.setChannel('env-webhook', {
    configured: true,
    enabled: true,
    state: 'ok',
    pausedReason: null,
  });
  const lone = fake.add({ status: 'failed', alert: { service: 'prowlarr' } });
  const ok = await retry(lone.uid);
  assert.equal(ok.status, 200);
  assert.equal(ok.json.retried, 1);
  assert.equal(ok.json.delivery.status, 'retrying');
});

test('over fakeAlerting, history pages follow nextCursor and list unsaved rows first', async t => {
  const { port, fake } = await serveFake(t);
  for (let i = 0; i < 5; i++) fake.add({ status: 'delivered', alert: { service: `s${i}` } });
  for (let i = 0; i < 3; i++)
    fake.add({ status: 'retrying', saved: false, alert: { service: `memory${i}` } });
  const seen = [],
    cursors = [];
  let cursor = null,
    first = null;
  for (let page = 0; page < 8; page++) {
    const answer = await get(
      port,
      `${paths.deliveries}?limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
    );
    assert.equal(answer.status, 200);
    first ??= answer.json;
    assert.ok(answer.json.deliveries.length <= 2, 'never more than limit rows');
    seen.push(...answer.json.deliveries.map(row => row.alert.service));
    cursor = answer.json.nextCursor;
    cursors.push(cursor);
    if (!cursor) break;
  }
  // The memory rows first, page by page (an m:<n> cursor, A30), then the saved ones, newest
  // first; each page holds at most `limit` rows in all.
  assert.equal(first.unsaved, 3);
  assert.deepEqual(first.deliveries[0].saved, false);
  assert.deepEqual(seen, ['memory2', 'memory1', 'memory0', 's4', 's3', 's2', 's1', 's0']);
  assert.match(cursors[0], /^m:[1-9][0-9]*$/);
  assert.match(cursors[1], /^[1-9][0-9]*$/);
  assert.equal(cursors.at(-1), null);
  const problems = await get(port, `${paths.deliveries}?filter=problems&channel=env-webhook`);
  assert.deepEqual(
    problems.json.deliveries.map(row => row.alert.service),
    ['memory2', 'memory1', 'memory0']
  );
});

test('over fakeAlerting, unavailable status, the public key read without a limit, and a missing webhook', async t => {
  const { port, fake } = await serveFake(t);
  fake.setAvailable(false);
  assertError(await get(port, paths.status), 'delivery_status_unavailable');
  assertError(await get(port, paths.deliveries), 'delivery_status_unavailable');
  fake.setAvailable(true);
  assert.equal((await get(port, paths.status)).status, 200);
  const one = await get(port, paths.publicKey);
  for (let n = 0; n < 12; n++) assert.equal((await get(port, paths.publicKey)).status, 200);
  // A rotation, and the next read shows the new public key with the previous one.
  assert.equal((await post(port, paths.rotate)).status, 200);
  const next = await get(port, paths.publicKey);
  assert.notEqual(next.json.keyId, one.json.keyId);
  assert.equal(next.json.previous.keyId, one.json.keyId);
  fake.setSigning({ configured: false });
  assertError(await get(port, paths.publicKey), 'webhook_not_configured');
  assertError(await post(port, paths.rotate), 'webhook_not_configured');
  assert.match(one.json.publicKey, /^-----BEGIN PUBLIC KEY-----\n/);
  // Resume of a channel that is not paused releases nothing.
  const resumed = await post(port, '/api/notifications/channels/email/resume');
  assert.equal(resumed.status, 200);
  assert.equal(resumed.json.released, 0);
});

test('security F05: fake Resume follows real held-row and signing-release partitions', async t => {
  await t.test('unpaused channel with held rows', async s => {
    const { port, fake } = await serveFake(s);
    fake.add({ channel: 'env-webhook', status: 'paused' });
    const resumed = await post(port, paths.resume);
    assert.equal(resumed.status, 200);
    assert.equal(resumed.json.released, 1);
    assert.equal(resumed.json.channel.state, 'ok');
  });
  await t.test('signing hold releases before outbox rows', async s => {
    const { port, fake } = await serveFake(s);
    fake.setSigning({ heldSince: 1 });
    fake.add({ channel: 'env-webhook', status: 'paused' });
    const resumed = await post(port, paths.resume);
    assert.equal(resumed.status, 200);
    assert.equal(resumed.json.released, 1);
    assert.equal(fake.signing.held, false);
    const names = fake.calls.map(call => call[0]);
    assert.ok(names.indexOf('signing.releaseHold') < names.indexOf('outbox.resume'));
  });
  await t.test('immutable newer hold refuses unchanged', async s => {
    const { port, fake } = await serveFake(s);
    fake.setSigning({ heldSince: 1, readOnly: true });
    fake.add({ channel: 'env-webhook', status: 'paused' });
    const resumed = await post(port, paths.resume);
    assert.equal(resumed.status, 409);
    assert.equal(resumed.json.code, 'signing_compatibility');
    assert.equal(fake.signing.held, true);
    assert.equal(
      fake.calls.some(call => call[0] === 'outbox.resume'),
      false
    );
  });
  await t.test('failed signing release does not release rows', async s => {
    const { port, fake } = await serveFake(s);
    fake.setSigning({ heldSince: 1 });
    fake.add({ channel: 'env-webhook', status: 'paused' });
    fake.fail('signing.releaseHold', deliveryError('storage_full'));
    const resumed = await post(port, paths.resume);
    assert.equal(resumed.status, 503);
    assert.equal(fake.signing.held, true);
    assert.equal(
      fake.calls.some(call => call[0] === 'outbox.resume'),
      false
    );
  });
  await t.test('missing key and ended sessions preserve holds', async () => {
    const fake = fakeAlerting();
    fake.setSigning({ heldSince: 1, saved: false, key: null });
    await assert.rejects(fake.resume('env-webhook'), { code: 'signing_unavailable' });
    assert.equal(fake.signing.held, true);
    assert.equal(
      fake.calls.some(call => call[0] === 'outbox.resume'),
      false
    );
    const held = fakeAlerting();
    held.setSigning({ heldSince: 1 });
    const ended = new Error('fixture session ended');
    let checks = 0;
    await assert.rejects(
      held.resume('env-webhook', {
        check: () => {
          if (++checks === 2) throw ended;
        },
      }),
      e => e === ended
    );
    assert.equal(checks, 2, 'the first check passes and the check in releaseHold fails');
    assert.equal(held.signing.held, true);
    assert.equal(
      held.calls.some(call => call[0] === 'outbox.resume'),
      false
    );
  });
});

test('security D03: fake durability is separate from a usable unheld current key', async () => {
  const fake = fakeAlerting();
  const createdAt = fake.signing.describe().createdAt;
  fake.setSigning({ saved: false, heldSince: null });
  assert.equal((await fake.signing.publicKeys()).createdAt, createdAt);
  assert.equal(fake.signing.describe().createdAt, createdAt);
  assert.equal(fake.signing.describe().saved, false);
  assert.equal(fake.signing.held, false);
  fake.add({ channel: 'env-webhook', status: 'paused' });
  assert.equal((await fake.resume('env-webhook')).released, 1);
  assert.equal(
    fake.calls.some(call => call[0] === 'signing.releaseHold'),
    false
  );
});
