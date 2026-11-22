// A wall display's history answers draw on a per-session budget of event-loop time (DOS-1,
// lib/http/history-budget.mjs): a stolen display cookie that keeps asking for 30-day charts gets
// 429 with Retry-After once its budget is spent, instead of holding the loop (and /health) for
// every other request. The admin's reads and other displays are not affected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { newDisplayCode } from '../../lib/identity/secrets.mjs';
import { identityOps } from '../../lib/repo/identity.mjs';
import { historyBudget, historyBudgetDefaults } from '../../lib/http/history-budget.mjs';
import { basic, browserWrite, cookieFrom, raw, startReal } from './harness.mjs';

async function displayCookie(app, port, name) {
  const made = newDisplayCode();
  const now = Date.now();
  await app.control.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: made.id,
      name,
      codeHash: made.codeHash,
      codeExpiresAt: now + 10 * 60e3,
      createdAt: now,
      createdBy: 'cli:test',
    })
  );
  const answer = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...browserWrite(`http://127.0.0.1:${port}`)],
    JSON.stringify({ code: made.code, display: true })
  );
  assert.equal(answer.json?.kind, 'kiosk', answer.body);
  return cookieFrom(answer);
}
const get = (port, route, cookie) =>
  raw(port, [`GET ${route} HTTP/1.1`, `Cookie: ${cookie}`, 'Sec-Fetch-Site: same-origin']);
const admin = (port, method, route, body) =>
  raw(
    port,
    [
      `${method} ${route} HTTP/1.1`,
      `Authorization: ${basic()}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
    ],
    body === undefined ? '' : JSON.stringify(body)
  );

test('a display that keeps asking for history is answered 429 once its budget is spent', async t => {
  // A budget of 3 ms that does not refill within the test: every answer costs at least 1 ms.
  const { app, port } = await startReal(t, {
    historyBudget: { burstMs: 3, refillPerSecond: 0.001 },
  });
  const added = await admin(port, 'POST', '/api/services', {
    type: 'link',
    name: 'NAS',
    group: 'Storage',
    url: 'https://nas.example/admin',
  });
  assert.equal(added.status, 201, added.body);
  const id = added.json.service.id;
  const cookie = await displayCookie(app, port, 'Lobby TV');

  const statuses = [];
  let limited;
  for (let i = 0; i < 10; i++) {
    const answer = await get(port, `/api/history/${id}?range=30d`, cookie);
    statuses.push(answer.status);
    if (answer.status === 429) limited = answer;
  }
  assert.equal(statuses[0], 200, 'the first answer is served');
  // Three answers spend it (a fourth may start on what refilled in the meantime).
  assert.deepEqual(statuses.slice(4), Array(6).fill(429), statuses.join(','));
  assert.equal(limited.json.code, 'history_limited');
  assert.match(limited.headers['retry-after'], /^[1-9]\d*$/);

  // The rest of the dashboard still answers that display.
  assert.equal((await get(port, '/api/dashboard', cookie)).status, 200);
  // Another display has its own budget.
  const other = await displayCookie(app, port, 'Kitchen TV');
  assert.equal((await get(port, `/api/history/${id}?range=30d`, other)).status, 200);
  // The admin's history reads are not budgeted.
  for (let i = 0; i < 10; i++)
    assert.equal((await admin(port, 'GET', `/api/history/${id}?range=30d`)).status, 200);
});

test('a history budget refills at its rate, up to its burst, and says when to try again', () => {
  let now = 0;
  const budget = historyBudget({ burstMs: 1, refillPerSecond: 2, now: () => now });
  let runs = 0;
  const work = () => ++runs;
  assert.deepEqual(budget.run('a', work), { value: 1 });
  // At least 1 ms was charged: the budget is spent until it refills above zero.
  const refused = budget.run('a', work);
  assert.equal(runs, 1, 'refused work does not run');
  assert.ok(Number.isInteger(refused.retryAfter) && refused.retryAfter >= 1, refused.retryAfter);
  // Other keys are separate.
  assert.deepEqual(budget.run('b', work), { value: 2 });
  now += refused.retryAfter * 1000;
  assert.deepEqual(budget.run('a', work), { value: 3 });
  // A long pause refills only up to the burst.
  now += 3600e3;
  assert.ok('value' in budget.run('a', work));
  assert.ok('retryAfter' in budget.run('a', work));
  // A failing answer still costs what it took.
  now += 3600e3;
  assert.throws(() =>
    budget.run('a', () => {
      throw new Error('boom');
    })
  );
  assert.ok('retryAfter' in budget.run('a', work));
});

test('the default budget keeps one display under a tenth of the event loop after its burst', () => {
  assert.deepEqual({ ...historyBudgetDefaults }, { burstMs: 2000, refillPerSecond: 100 });
  let now = 0;
  const budget = historyBudget({ now: () => now });
  // Answers of 25 ms each, asked for every 10 ms of simulated time.
  let served = 0;
  const busy = () => {
    const until = performance.now() + 25;
    while (performance.now() < until);
    served++;
  };
  for (let step = 0; step < 500; step++, now += 10) budget.run('display', busy);
  // 5 s: at most the 2 s burst plus 100 ms for each second, plus one answer of overdraft.
  assert.ok(served * 25 <= 2000 + 5 * 100 + 25, `${served} answers`);
  assert.ok(served >= 2000 / 30, `${served} answers`);
});
