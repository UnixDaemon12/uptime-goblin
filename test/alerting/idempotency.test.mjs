import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  createIdempotency,
  memoryIdempotencyStore,
  validIdempotencyKey,
  IdempotencyKeyError,
  INVALID_KEY_MESSAGE,
  CONFLICT_MESSAGE,
  createIdempotencyHandler,
} from '../../lib/http/idempotency.mjs';
import http from 'node:http';
import { InputError } from '../../lib/config.mjs';
import { AuthError } from '../../lib/auth.mjs';
import { json } from '../../lib/http/body.mjs';
import { fail } from '../../lib/http/pipeline.mjs';
import { settle } from './fake-clock.mjs';
import { serveAuth, raw, login, browserWrite, password } from '../http-pipeline/harness.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';

const scope = ['7', 'POST', '/api/services'],
  key = 'b1f2a3c4-0000-4000-8000-000000000001';
const answer = (status = 201, body = '{"ok":true}', headers = {}) => ({ status, body, headers });

function fixture(options = {}) {
  let time = 1000;
  const idempotency = createIdempotency({ now: () => time, ...options });
  return { idempotency, advance: ms => (time += ms), now: () => time };
}

test('a keyed write is executed once; the same request again is answered from it', async () => {
  const { idempotency } = fixture();
  let calls = 0;
  const execute = async () => {
    calls++;
    return answer(201, '{"id":"once"}', { 'retry-after': '5' });
  };
  const first = await idempotency.run({ key, scope, body: '{"name":"Once"}', execute });
  assert.equal(first.outcome, 'executed');
  assert.equal(first.kept, true);
  const again = await idempotency.run({ key, scope, body: '{"name":"Once"}', execute });
  assert.deepEqual(again, {
    outcome: 'replayed',
    response: { status: 201, body: '{"id":"once"}', headers: { 'retry-after': '5' } },
  });
  assert.equal(calls, 1);
  // Another body under the same key is refused; another route or credential is its own scope.
  assert.deepEqual(await idempotency.run({ key, scope, body: '{"name":"Other"}', execute }), {
    outcome: 'conflict',
  });
  assert.equal(calls, 1);
  const other = await idempotency.run({
    key,
    scope: ['7', 'PATCH', '/api/settings'],
    body: '{"name":"Once"}',
    execute,
  });
  assert.equal(other.outcome, 'executed');
  assert.equal(
    (await idempotency.run({ key, scope: ['8', ...scope.slice(1)], body: '', execute })).outcome,
    'executed'
  );
  assert.equal(calls, 3);
  assert.equal(CONFLICT_MESSAGE, 'This Idempotency-Key was already used for a different request.');
});

test('keys are validated exactly as in 1.4.3', async () => {
  const { idempotency } = fixture();
  for (const good of ['abcdefgh', 'x'.repeat(128), 'A_b-9_______'])
    assert.equal(validIdempotencyKey(good), true, good);
  for (const bad of [
    'short',
    'has space in it',
    'x'.repeat(129),
    'é-not-ascii',
    undefined,
    12345678,
  ])
    await assert.rejects(
      idempotency.run({ key: bad, scope, body: '', execute: async () => answer() }),
      error => {
        assert.ok(error instanceof IdempotencyKeyError);
        assert.equal(error.status, 400);
        assert.equal(error.message, INVALID_KEY_MESSAGE);
        return true;
      },
      String(bad)
    );
});

test('answers are kept for ten minutes, then the key is forgotten', async () => {
  const { idempotency, advance } = fixture();
  let calls = 0;
  const execute = async () => answer(201, String(++calls));
  await idempotency.run({ key, scope, body: 'a', execute });
  advance(10 * 60 * 1000 - 1);
  assert.equal((await idempotency.run({ key, scope, body: 'a', execute })).outcome, 'replayed');
  advance(2);
  const later = await idempotency.run({ key, scope, body: 'a', execute });
  assert.equal(later.outcome, 'executed');
  assert.equal(later.response.body, '2');
});

test('a retry arriving while the first attempt runs waits for its answer', async () => {
  // In one process the retry joins the running attempt directly; it never polls the store.
  const { idempotency } = fixture({
    sleep: async () => assert.fail('a retry in the same process polled instead of joining'),
  });
  let calls = 0,
    release;
  const execute = async () => {
    calls++;
    await new Promise(resolve => (release = resolve));
    return answer(200, '{"tested":true}');
  };
  const first = idempotency.run({ key, scope, body: 'x', execute });
  await settle();
  const second = idempotency.run({ key, scope, body: 'x', execute });
  // A different body is refused at once, without waiting for the first attempt.
  assert.equal((await idempotency.run({ key, scope, body: 'y', execute })).outcome, 'conflict');
  await settle();
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.equal(a.outcome, 'executed');
  assert.deepEqual(b, { outcome: 'replayed', response: a.response });
});

test('refusals that applied nothing, oversized answers and failures are not kept', async () => {
  const { idempotency } = fixture();
  let calls = 0;
  // 401 and 403 too (sessions spec D22, as server.mjs): a retry after signing in again must run
  // or join, never replay a refusal.
  for (const response of [
    answer(503),
    answer(429),
    answer(401),
    answer(403),
    answer(200, 'x'.repeat(65537)),
    null,
  ]) {
    const before = calls;
    const execute = async () => {
      calls++;
      return response;
    };
    const result = await idempotency.run({ key, scope, body: 'b', execute });
    assert.equal(result.kept, false);
    await idempotency.run({ key, scope, body: 'b', execute });
    assert.equal(calls, before + 2, `${response?.status} ran again`);
  }
  // A 64 KiB answer is still kept.
  const edge = await idempotency.run({
    key: 'edge-of-limit-0001',
    scope,
    body: 'b',
    execute: async () => answer(200, 'x'.repeat(65536)),
  });
  assert.equal(edge.kept, true);
  // A handler that throws leaves nothing behind, and a retry that waited on it runs itself.
  let release;
  const failing = idempotency.run({
    key: 'throws-first-0001',
    scope,
    body: 'c',
    execute: async () => {
      await new Promise(resolve => (release = resolve));
      throw new Error('boom');
    },
  });
  await settle();
  const retry = idempotency.run({
    key: 'throws-first-0001',
    scope,
    body: 'c',
    execute: async () => answer(200, 'second'),
  });
  await settle();
  release();
  await assert.rejects(failing, /boom/);
  assert.equal((await retry).outcome, 'executed');
  assert.equal((await retry).response.body, 'second');
});

test('the memory store keeps 1.4.3 limits: 1,000 entries and 4 MiB, oldest answers first', async () => {
  const store = memoryIdempotencyStore({ maxEntries: 3, maxBytes: 10 });
  const { idempotency } = fixture({ store });
  const run = (k, body = 'ab') =>
    idempotency.run({
      key: `key-${k}-000000`,
      scope,
      body: '',
      execute: async () => answer(200, body),
    });
  for (const k of [1, 2, 3]) await run(k);
  assert.deepEqual(store.stats(), { entries: 3, bytes: 6 });
  await run(4);
  // The oldest answer made room for the fourth.
  assert.equal(store.stats().entries, 3);
  assert.equal((await run(1)).outcome, 'executed');
  assert.equal((await run(4)).outcome, 'replayed');
  // Bytes: one large answer pushes the oldest ones out.
  await run(5, 'xxxxxxxx');
  assert.ok(store.stats().bytes <= 10);
  assert.equal((await run(5)).outcome, 'replayed');
  // An entry still running is never dropped, whatever the limits.
  const tiny = memoryIdempotencyStore({ maxEntries: 0, maxBytes: 0 });
  await tiny.begin('pending', { digest: 'd', leaseUntil: 9e15 });
  assert.equal(await tiny.prune(0), 0);
  assert.equal((await tiny.begin('pending', { digest: 'd', leaseUntil: 0 })).entry.response, null);
});

test('stored entries hold a keyed digest, never the body or its plain hash', async () => {
  const store = memoryIdempotencyStore();
  const seen = [];
  const spy = {
    ...store,
    begin: async (scopeKey, fields) => {
      seen.push(JSON.stringify(fields));
      return store.begin(scopeKey, fields);
    },
  };
  const body = '{"password":"orbit-fixture-secret"}';
  const a = createIdempotency({ store: spy, now: () => 0 });
  await a.run({ key, scope, body, execute: async () => answer() });
  const text = seen.join('\n');
  assert.ok(!text.includes('orbit-fixture-secret'));
  assert.ok(!text.includes(createHash('sha256').update(body).digest('hex')));
  // A different process secret gives a different digest.
  const b = createIdempotency({ now: () => 0 });
  assert.notEqual(a.digest(body), b.digest(body));
  assert.equal(a.digest(body), a.digest(Buffer.from(body)));
});

test('a persistent store: another process running the key is waited for; a dead one is taken over', async () => {
  // Shared by two "processes" (two coordinators), as a control-database adapter would be.
  const store = memoryIdempotencyStore();
  let time = 0;
  const now = () => time;
  const sleep = async ms => {
    time += ms;
    await settle(2);
  };
  // Processes sharing a store must share the digest secret (a keyring subkey in wave 2).
  const secret = Buffer.alloc(32, 7);
  const other = createIdempotency({ store, now, sleep, secret, leaseMs: 60000, pollMs: 250 });
  const self = createIdempotency({ store, now, sleep, secret, leaseMs: 60000, pollMs: 250 });
  let release;
  const running = other.run({
    key,
    scope,
    body: 'p',
    execute: async () => {
      await new Promise(resolve => (release = resolve));
      return answer(201, 'from-other');
    },
  });
  await settle();
  let calls = 0;
  const waiting = self.run({
    key,
    scope,
    body: 'p',
    execute: async () => {
      calls++;
      return answer(201, 'from-self');
    },
  });
  await settle(5);
  release();
  await running;
  const joined = await waiting;
  assert.equal(calls, 0);
  assert.deepEqual(joined, { outcome: 'replayed', response: answer(201, 'from-other') });

  // A crashed process leaves a pending entry: it is taken over once its lease has ended.
  await store.begin(['7', 'POST', '/api/services', 'crashed-key-0001'].join('\n'), {
    digest: self.digest('q'),
    leaseUntil: time + 60000,
  });
  const started = time;
  const taken = await self.run({
    key: 'crashed-key-0001',
    scope,
    body: 'q',
    execute: async () => answer(201, 'recovered'),
  });
  assert.equal(taken.outcome, 'executed');
  assert.ok(time - started >= 60000, 'waited for the lease');
});

test('a failing store never fails the request that already ran', async () => {
  const store = memoryIdempotencyStore();
  const broken = {
    ...store,
    finish: async () => {
      throw Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' });
    },
  };
  const { idempotency } = fixture({ store: broken });
  const result = await idempotency.run({ key, scope, body: 'z', execute: async () => answer() });
  assert.equal(result.outcome, 'executed');
  assert.equal(result.kept, false);
  assert.deepEqual(idempotency.status(), {
    running: 0,
    storeErrors: 1,
    degradedRuns: 0,
    lastStoreError: 'SQLITE_FULL',
  });
});

test('an invalid key is an InputError, so the pipeline answers 400 with its message', () => {
  const error = new IdempotencyKeyError();
  assert.ok(error instanceof InputError);
  assert.equal(error.message, INVALID_KEY_MESSAGE);
});

test('a store is given the scope and key as parts, for a database adapter', async () => {
  const store = memoryIdempotencyStore();
  const calls = [];
  const spy = Object.fromEntries(
    Object.entries(store).map(([name, fn]) => [
      name,
      typeof fn === 'function'
        ? async (...args) => {
            calls.push([name, args]);
            return fn(...args);
          }
        : fn,
    ])
  );
  const { idempotency } = fixture({ store: spy });
  await idempotency.run({ key, scope, body: 'x', execute: async () => answer() });
  const begin = calls.find(([name]) => name === 'begin')[1];
  assert.equal(begin[0], [...scope, key].join('\n'));
  assert.deepEqual(begin[1].parts, { scope, key });
  const finish = calls.find(([name]) => name === 'finish')[1];
  assert.deepEqual(finish[1].parts, { scope, key });
  // A plain string scope (what the pipeline passes) is one part.
  await idempotency.run({
    key,
    scope: '7\nPOST\n/api/other',
    body: 'x',
    execute: async () => answer(),
  });
  assert.deepEqual(calls.filter(([name]) => name === 'begin')[1][1][1].parts, {
    scope: ['7\nPOST\n/api/other'],
    key,
  });
});

test('a store that cannot be written never fails a request: it falls back to memory', async () => {
  const store = memoryIdempotencyStore();
  let broken = true;
  const fullDisk = () => {
    throw Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' });
  };
  const failing = {
    kind: 'control',
    begin: async (...args) => (broken ? fullDisk() : store.begin(...args)),
    takeOver: async (...args) => (broken ? fullDisk() : store.takeOver(...args)),
    finish: async (...args) => (broken ? fullDisk() : store.finish(...args)),
    abandon: async (...args) => (broken ? fullDisk() : store.abandon(...args)),
    prune: async (...args) => (broken ? fullDisk() : store.prune(...args)),
  };
  const { idempotency } = fixture({ store: failing });
  assert.equal(idempotency.fallback.kind, 'memory');
  let calls = 0;
  const execute = async () => answer(201, `run ${++calls}`);
  const first = await idempotency.run({ key, scope, body: 'b', execute });
  assert.deepEqual([first.outcome, first.kept], ['executed', true]);
  // The retry is answered from memory, as in 1.4.3, while the store is still failing …
  assert.equal((await idempotency.run({ key, scope, body: 'b', execute })).outcome, 'replayed');
  assert.equal((await idempotency.run({ key, scope, body: 'c', execute })).outcome, 'conflict');
  // … and after it works again: the answer kept in memory is not run a second time.
  broken = false;
  const later = await idempotency.run({ key, scope, body: 'b', execute });
  assert.deepEqual(later, { outcome: 'replayed', response: answer(201, 'run 1') });
  assert.equal(calls, 1);
  // Only the first request needed the fallback; the others were answered from what it kept.
  const status = idempotency.status();
  assert.equal(status.degradedRuns, 1);
  assert.equal(status.lastStoreError, 'SQLITE_FULL');
  // New keys go to the store again.
  await idempotency.run({ key: 'fresh-key-0001', scope, body: 'b', execute });
  assert.equal(store.stats().entries, 1);
  // The memory store itself has no fallback: its errors are real bugs.
  assert.equal(createIdempotency().fallback, null);
});

test('the pipeline handler answers exactly as server.mjs 1.4.3 did', async t => {
  const idempotency = createIdempotency();
  const handler = createIdempotencyHandler(idempotency, { fail });
  assert.throws(() => createIdempotencyHandler(idempotency, {}), TypeError);
  let runs = 0;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    try {
      await handler(
        req,
        res,
        { key: req.headers['idempotency-key'], scope: ['7', req.method, req.url].join('\n'), body },
        async () => {
          runs++;
          if (req.url === '/refuse') throw new InputError('Name is required');
          res.setHeader('Retry-After', '3');
          json(res, 201, { id: `created-${runs}` });
        }
      );
    } catch (error) {
      fail(res, error);
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const send = async (path, idempotencyKey, body) => {
    const response = await fetch(base + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body,
    });
    return {
      status: response.status,
      body: await response.json(),
      replayed: response.headers.get('idempotent-replayed'),
      retryAfter: response.headers.get('retry-after'),
    };
  };
  assert.deepEqual(await send('/create', key, '{"a":1}'), {
    status: 201,
    body: { id: 'created-1' },
    replayed: null,
    retryAfter: '3',
  });
  assert.deepEqual(await send('/create', key, '{"a":1}'), {
    status: 201,
    body: { id: 'created-1' },
    replayed: 'true',
    retryAfter: '3',
  });
  assert.deepEqual(await send('/create', key, '{"a":2}'), {
    status: 422,
    body: { error: CONFLICT_MESSAGE },
    replayed: null,
    retryAfter: null,
  });
  assert.deepEqual(await send('/create', 'short', '{"a":1}'), {
    status: 400,
    body: { error: INVALID_KEY_MESSAGE },
    replayed: null,
    retryAfter: null,
  });
  // A refused write is kept too (only 401, 403, 429 and 503 are not), and replayed.
  assert.equal((await send('/refuse', key, '{}')).status, 400);
  const again = await send('/refuse', key, '{}');
  assert.deepEqual(
    [again.status, again.body, again.replayed],
    [400, { error: 'Name is required' }, 'true']
  );
  assert.equal(runs, 2);
});

// PasswordAuth#assertCurrent in miniature: a request keeps the credential revision it arrived
// with, and a password change moves the revision on, so every older request is refused (401).
// request() is the check() one request passes to run(), as createIdempotencyHandler builds it.
function passwords() {
  let revision = 1;
  const auth = {
    checks: 0,
    request() {
      const access = { revision };
      return () => {
        auth.checks++;
        if (access.revision !== revision) throw new AuthError('Sign in to Uptime Goblin', 401);
      };
    },
    change: () => revision++,
  };
  return auth;
}
const signIn = error => error instanceof AuthError && error.status === 401;

// A database store as wave 2's SQLite adapter behaves under contention: begin(), takeOver() and
// peek() back off on a timer (SQLITE_BUSY, with jitter there) before they act. `during[name]`
// runs once, halfway through the next such wait, which is where a password change lands in the
// race these tests pin; a name in `failing` then throws SQLITE_FULL instead of acting, which
// sends the request to the fallback store.
function busyStore({ kind = 'control', inner = memoryIdempotencyStore() } = {}) {
  const store = { kind, inner, during: {}, failing: new Set() };
  const busy =
    name =>
    async (...args) => {
      await delay(5);
      const during = store.during[name];
      delete store.during[name];
      during?.();
      await delay(5);
      if (store.failing.has(name))
        throw Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' });
      return inner[name](...args);
    };
  for (const name of ['begin', 'takeOver', 'peek']) store[name] = busy(name);
  for (const name of ['finish', 'abandon', 'prune'])
    store[name] = (...args) => inner[name](...args);
  return store;
}

test('a password change while the store is busy stops a replay: the last check follows the wait', async () => {
  const auth = passwords();
  const store = busyStore();
  const { idempotency } = fixture({ store });
  let calls = 0;
  const execute = async () => answer(201, `run ${++calls}`);
  const send = (body = 'r', to = idempotency) =>
    to.run({ key, scope, body, execute, check: auth.request() });
  assert.equal((await send()).outcome, 'executed');
  // The retry passes the check at the top of the pass, then waits on the busy store while the
  // password changes: it is refused (the pipeline answers 401), not answered from the reply …
  store.during.begin = auth.change;
  await assert.rejects(send(), signIn);
  // … and a retry with another body is refused too, rather than told the key was used.
  store.during.begin = auth.change;
  await assert.rejects(send('other'), signIn);
  assert.equal(calls, 1);
  // Signed in again, the retry is answered from what was kept: the refusals changed nothing.
  assert.deepEqual(await send(), { outcome: 'replayed', response: answer(201, 'run 1') });
  assert.deepEqual(await send('other'), { outcome: 'conflict' });

  // An answer kept in memory while the store was failing is rechecked after reading it too.
  const failing = busyStore();
  failing.failing.add('begin');
  const fallback = busyStore({ kind: 'memory' });
  const degraded = fixture({ store: failing, fallback }).idempotency;
  assert.equal((await send('f', degraded)).outcome, 'executed');
  fallback.during.peek = auth.change;
  await assert.rejects(send('f', degraded), signIn);
  assert.equal(calls, 2);
  assert.deepEqual(await send('f', degraded), {
    outcome: 'replayed',
    response: answer(201, 'run 2'),
  });
});

test('a password change while the store is busy stops the run, and releases the key it claimed', async () => {
  const auth = passwords();
  const store = busyStore();
  // A retry never waits: each refusal below leaves no pending entry of its own behind.
  const { idempotency } = fixture({
    store,
    sleep: async () => assert.fail('a retry waited on a key that a refused request claimed'),
  });
  let calls = 0;
  const execute = async () => answer(201, `run ${++calls}`);
  const send = k => idempotency.run({ key: k, scope, body: 's', execute, check: auth.request() });
  const crashed = async k =>
    store.inner.begin([...scope, k].join('\n'), {
      digest: idempotency.digest('s'),
      leaseUntil: 0,
    });
  const cases = [
    // begin() claims a new key.
    ['fresh-key-0001', async () => (store.during.begin = auth.change)],
    // takeOver() claims the key of a process that died (its lease ended).
    [
      'crashed-key-0001',
      async k => {
        await crashed(k);
        store.during.takeOver = auth.change;
      },
    ],
    // begin() fails after its wait: the fallback claims the key.
    [
      'failing-key-0001',
      async () => {
        store.during.begin = auth.change;
        store.failing.add('begin');
      },
    ],
    // takeOver() fails after its wait: the fallback claims the key.
    [
      'failing-take-0001',
      async k => {
        await crashed(k);
        store.during.takeOver = auth.change;
        store.failing.add('takeOver');
      },
    ],
  ];
  for (const [k, prepare] of cases) {
    await prepare(k);
    await assert.rejects(send(k), signIn, k);
    assert.equal(calls, 0, `${k}: execute() was not called`);
    store.failing.clear();
    // Signed in again, the retry runs once, at once.
    const retry = await send(k);
    assert.deepEqual([retry.outcome, retry.response.body], ['executed', 'run 1'], k);
    calls = 0;
  }
  assert.equal(idempotency.status().running, 0);
});

test('the credential is checked on every pass over the key, before the store is touched again', async () => {
  const auth = passwords();
  // Another process holds the key; this one polls the shared store until it has finished.
  const store = memoryIdempotencyStore();
  let time = 0,
    begins = 0,
    onPoll = () => {};
  const polls = [];
  const sleep = async ms => {
    time += ms;
    polls.push(auth.checks);
    onPoll(polls.length);
    await settle(2);
  };
  const secret = Buffer.alloc(32, 7);
  const other = createIdempotency({ store, now: () => time, sleep, secret });
  const counted = {
    ...store,
    begin: async (...args) => {
      begins++;
      return store.begin(...args);
    },
  };
  const self = createIdempotency({ store: counted, now: () => time, sleep, secret });
  const hold = (k, body) => {
    let release;
    const done = other.run({
      key: k,
      scope,
      body,
      execute: () => new Promise(resolve => (release = resolve)).then(() => answer(201, body)),
    });
    return { done, release: () => release() };
  };
  const never = async () => assert.fail('a retry ran what another process was running');

  let held = hold(key, 'p');
  await settle();
  onPoll = n => n === 3 && held.release();
  const polled = await self.run({ key, scope, body: 'p', execute: never, check: auth.request() });
  assert.deepEqual(polled, { outcome: 'replayed', response: answer(201, 'p') });
  // One check at the top of each of the three passes that polled, before the store was read;
  // the fourth pass read the answer, and was checked at least once as well.
  assert.deepEqual(polls, [1, 2, 3]);
  assert.ok(auth.checks >= 4, `${auth.checks} checks over 4 passes`);
  await held.done;

  // The password changes while this process waits between polls: the next pass is refused
  // before it reads the store again.
  polls.length = begins = 0;
  held = hold('held-key-0001', 'q');
  await settle();
  onPoll = n => n === 2 && auth.change();
  await assert.rejects(
    self.run({ key: 'held-key-0001', scope, body: 'q', execute: never, check: auth.request() }),
    signIn
  );
  assert.equal(polls.length, 2);
  assert.equal(begins, 2, 'the third pass never reached the store');
  held.release();
  assert.equal((await held.done).outcome, 'executed');

  // In one process, a retry joined to the running attempt is checked again once it finished.
  const { idempotency } = fixture();
  let release;
  const first = idempotency.run({
    key,
    scope,
    body: 'j',
    check: auth.request(),
    execute: () => new Promise(resolve => (release = resolve)).then(() => answer()),
  });
  await settle();
  const joined = idempotency.run({ key, scope, body: 'j', execute: never, check: auth.request() });
  await settle();
  auth.change();
  release();
  // The first attempt was current when it started, and ran; the one waiting on it is refused.
  assert.equal((await first).outcome, 'executed');
  await assert.rejects(joined, signIn);
});

test('a retry that a failing store held is rechecked when the fallback answers it', async () => {
  // The first attempt changes the password (it is the password change, or lands just before
  // one). Its retry carries the old credential and reaches the fallback only after that: it is
  // refused, neither replayed nor told of a conflict. Both wait on the same busy store; the
  // first attempt's wait ends first.
  const cases = [
    ['begin', 'a'],
    ['begin', 'b'],
    // A key another process left behind: takeOver() is the call that fails.
    ['takeOver', 'a'],
  ];
  for (const [failing, body] of cases) {
    const auth = passwords();
    const store = busyStore();
    store.failing.add(failing);
    const { idempotency } = fixture({ store, sleep: async () => assert.fail('polled') });
    if (failing === 'takeOver')
      await store.inner.begin([...scope, key].join('\n'), {
        digest: idempotency.digest('a'),
        leaseUntil: 0,
      });
    let calls = 0;
    const first = idempotency.run({
      key,
      scope,
      body: 'a',
      check: auth.request(),
      execute: async () => {
        calls++;
        auth.change();
        return answer(200, 'changed');
      },
    });
    const retry = idempotency.run({
      key,
      scope,
      body,
      check: auth.request(),
      execute: async () => assert.fail('a retry ran again'),
    });
    assert.equal((await first).outcome, 'executed');
    await assert.rejects(retry, signIn, `${failing} fails, body ${body}`);
    assert.equal(calls, 1);
    assert.equal(idempotency.status().degradedRuns, 2, 'both went to the fallback');
  }
});

// Codex's control for the adapter's own await (review of fbc6362): run() checks and resolves,
// but the HTTP adapter resumes one microtask later, and a password change can land there.
// The stored answer and a conflict must then be refused; an answer this call produced is not.
function adapterResponse() {
  const headers = new Map();
  return {
    headers,
    headersSent: false,
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    getHeader: name => headers.get(name.toLowerCase()),
    hasHeader: name => headers.has(name.toLowerCase()),
    removeHeader: name => headers.delete(name.toLowerCase()),
    writeHead(status, head = {}) {
      this.status = status;
      this.headersSent = true;
      for (const [name, value] of Object.entries(head)) this.setHeader(name, value);
    },
    end(text) {
      this.text = text;
      this.writableEnded = true;
    },
  };
}
test('the adapter checks the credential again after run() resolves, before a stored answer or a conflict', async () => {
  for (const outcome of ['replayed', 'conflict']) {
    const store = memoryIdempotencyStore();
    const idempotency = createIdempotency({ store });
    const scope = ['1', 'POST', '/api/services'],
      key = `boundary-${outcome}`;
    await idempotency.run({
      key,
      scope,
      body: Buffer.from('{"a":1}'),
      execute: () => ({ status: 201, body: '{"saved":"previous response"}', headers: {} }),
    });
    let revision = 1;
    const assertCurrent = access => {
      if (access.revision !== revision) throw new AuthError('Sign in to Uptime Goblin', 401);
    };
    const entry = await store.peek([...scope, key].join('\n'));
    // The change becomes runnable after begin() returns: after run()'s last check, before the
    // awaiting adapter resumes.
    store.begin = async () => {
      queueMicrotask(() => queueMicrotask(() => revision++));
      return { entry };
    };
    const res = adapterResponse();
    const handler = createIdempotencyHandler(idempotency, { fail, assertCurrent });
    const body = Buffer.from(outcome === 'replayed' ? '{"a":1}' : '{"a":2}');
    try {
      await handler({}, res, { key, scope, body, access: { revision: 1 } }, () =>
        assert.fail('a stored answer must not run the handler')
      );
    } catch (error) {
      fail(res, error);
    }
    assert.equal(revision, 2, outcome);
    assert.equal(res.status, 401, `${outcome}: a credential retired before the answer is refused`);
    assert.equal(res.headers.get('idempotent-replayed'), undefined, outcome);
  }
  // An answer this call executed is sent even if the password changed while it ran.
  const idempotency = createIdempotency({ store: memoryIdempotencyStore() });
  let revision = 1;
  const handler = createIdempotencyHandler(idempotency, {
    fail,
    assertCurrent: access => {
      if (access.revision !== revision) throw new AuthError('Sign in to Uptime Goblin', 401);
    },
  });
  const res = adapterResponse();
  await handler(
    {},
    res,
    {
      key: 'boundary-executed',
      scope: ['1', 'POST', '/api/auth/password'],
      body: Buffer.from('{}'),
      access: { revision: 1 },
    },
    async () => {
      revision++;
      json(res, 200, { ok: true });
    }
  );
  assert.equal(res.status, 200);
});

// Delivery spec A62, which the adapter must keep before it is wired in: a write applied as its
// session ended is answered 401, but its key keeps the outcome the handler recorded with
// committed(), so the Sign in again dialog's retry with the same key replays it and the write
// runs once. The adapter answers inside the real pipeline (committed(), fail(), the sign-in,
// sign-out and session routes) over the in-memory identity, as server.mjs's idempotent() does
// in test/http-pipeline/sessions.test.mjs.
async function adapterServer(t) {
  const identity = fakeIdentity({ password });
  const writes = { applied: 0 };
  writes.running = new Promise(resolve => (writes.entered = resolve));
  writes.held = new Promise(resolve => (writes.release = resolve));
  t.after(() => writes.release());
  const route = {
    method: 'POST',
    path: '/api/held-write',
    auth: 'session',
    permission: 'sources:write',
    idempotent: true,
    summary: 'A write held until the test releases it',
    async handler({ body, assertCurrent, committed }) {
      const { checkFirst } = await body();
      writes.entered();
      await writes.held;
      // A handler that checks the session after its wait applies nothing for one that ended.
      if (checkFirst) assertCurrent();
      writes.applied++;
      committed(200, { applied: writes.applied });
    },
  };
  const idempotency = createIdempotency();
  // Counts the requests that reached the key, so a test knows when a retry waits on the first.
  const run = idempotency.run;
  let looked = 0;
  idempotency.run = options => {
    looked++;
    return run(options);
  };
  const handler = createIdempotencyHandler(idempotency, {
    fail,
    assertCurrent: access => identity.assertCurrent(access),
  });
  const { port } = await serveAuth(t, { identity, routes: [route], idempotency: handler });
  const send = (cookie, method, path, body, lines = []) =>
    raw(
      port,
      [
        `${method} ${path} HTTP/1.1`,
        `Cookie: ${cookie}`,
        ...browserWrite(`http://127.0.0.1:${port}`),
        ...lines,
      ],
      body === undefined ? '' : JSON.stringify(body)
    );
  const keyed = (cookie, body = {}) =>
    send(cookie, 'POST', '/api/held-write', body, ['Idempotency-Key: fixture-adapter-0001']);
  const lookedAt = async count => {
    while (looked < count) await delay(5);
  };
  // Ends `cookie`'s session as `ending` says; resolves to the cookie of a current session.
  const end = async (ending, cookie) => {
    if (ending === 'signed out') {
      assert.equal((await send(cookie, 'POST', '/api/auth/logout')).status, 204);
      return (await login(port)).cookie;
    }
    const other = (await login(port)).cookie;
    const list = await raw(port, [
      'GET /api/account/sessions HTTP/1.1',
      `Cookie: ${other}`,
      'Sec-Fetch-Site: same-origin',
    ]);
    const target = list.json.sessions.find(view => !view.current).id;
    assert.equal((await send(other, 'DELETE', `/api/account/sessions/${target}`)).status, 204);
    return other;
  };
  return { writes, keyed, lookedAt, end, port };
}

const refusedWithoutOutcome = (answer, message) => {
  assert.equal(answer.status, 401, `${message}: ${answer.body}`);
  assert.equal(answer.json.code, 'session_expired', message);
  assert.equal(answer.headers['idempotent-replayed'], undefined, message);
  assert.equal(answer.body.includes('applied'), false, `${message}: no outcome`);
};

test('the adapter keeps a write applied as its session ended: the retry signed in again replays it, an ended session never gets it', async t => {
  for (const ending of ['signed out', 'revoked'])
    for (const timing of ['after its 401', 'while it runs'])
      await t.test(`${ending}, retried ${timing}`, async t => {
        const { writes, keyed, lookedAt, end, port } = await adapterServer(t);
        const { cookie } = await login(port);
        const first = keyed(cookie);
        await writes.running;
        // While it runs, a retry from the same session joins it before that session ends.
        const staleJoined = timing === 'while it runs' ? keyed(cookie) : null;
        if (staleJoined) await lookedAt(2);
        const again = await end(ending, cookie);
        // The dialog signs in again and retries with the same key, joining the first attempt.
        const joined = staleJoined ? keyed(again) : null;
        if (joined) await lookedAt(3);
        writes.release();
        refusedWithoutOutcome(await first, 'the write whose session ended');
        if (staleJoined)
          refusedWithoutOutcome(await staleJoined, 'the ended session’s retry that waited on it');
        refusedWithoutOutcome(await keyed(cookie), 'the ended session’s retry');
        // Signed in again, the same key is answered with what was applied, once.
        const retried = joined ? await joined : await keyed(again);
        assert.equal(retried.status, 200, retried.body);
        assert.equal(retried.headers['idempotent-replayed'], 'true');
        assert.deepEqual(retried.json, { applied: 1 });
        assert.equal(writes.applied, 1, 'applied once');
        const later = await keyed(again);
        assert.equal(later.headers['idempotent-replayed'], 'true');
        assert.deepEqual(later.json, { applied: 1 });
        assert.equal(writes.applied, 1);
      });
});

test('the adapter keeps no 401 for a write that applied nothing: the retry signed in again runs it', async t => {
  for (const ending of ['signed out', 'revoked'])
    await t.test(ending, async t => {
      const { writes, keyed, end, port } = await adapterServer(t);
      const { cookie } = await login(port);
      const body = { checkFirst: true };
      const first = keyed(cookie, body);
      await writes.running;
      const again = await end(ending, cookie);
      writes.release();
      refusedWithoutOutcome(await first, 'the write whose session ended');
      assert.equal(writes.applied, 0, 'nothing applied');
      const retried = await keyed(again, body);
      assert.equal(retried.status, 200, retried.body);
      assert.equal(retried.headers['idempotent-replayed'], undefined, 'run, not replayed');
      assert.deepEqual(retried.json, { applied: 1 });
      const later = await keyed(again, body);
      assert.equal(later.headers['idempotent-replayed'], 'true');
      assert.deepEqual(later.json, { applied: 1 });
      assert.equal(writes.applied, 1);
    });
});
