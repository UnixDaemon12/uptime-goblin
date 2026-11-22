import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  expiredSessionCookie,
  readCookies,
  sessionCookie,
  sessionCookieName,
} from '../../lib/http/cookies.mjs';
import { raw, startReal } from './harness.mjs';

const value = 'v1.' + 'A'.repeat(42) + 'Q';

test('readCookies returns every value of exactly one name, in order, across Cookie headers', () => {
  const cookies = readCookies([
    'theme=dark; goblin_session=first; Orbit_Session=other-case',
    'goblin_session=second;orbit_session_x=nope',
  ]);
  assert.deepEqual(cookies.all('goblin_session'), ['first', 'second']);
  assert.deepEqual(cookies.all('Orbit_Session'), ['other-case']);
  assert.deepEqual(cookies.all('theme'), ['dark']);
  assert.deepEqual(cookies.all('missing'), []);
  // The returned list is a copy: changing it changes nothing.
  cookies.all('goblin_session').push('x');
  assert.deepEqual(cookies.all('goblin_session'), ['first', 'second']);
  assert.deepEqual(readCookies(undefined).all('goblin_session'), []);
  assert.deepEqual(readCookies('goblin_session=single').all('goblin_session'), ['single']);
});

test('readCookies skips malformed pieces and names that are not tokens, never failing', () => {
  const cookies = readCookies([
    ' ; ;=novalue; noequals; \t goblin_session=kept \t; bad name=1; (x)=2; a"b=3; é=4; =; ok=',
  ]);
  assert.deepEqual(cookies.all('goblin_session'), ['kept']);
  assert.deepEqual(cookies.all('ok'), ['']);
  for (const name of ['bad name', '(x)', 'a"b', 'é', '', 'noequals'])
    assert.deepEqual(cookies.all(name), [], name);
  // Token characters other than letters and digits are allowed in names.
  assert.deepEqual(readCookies(["!#$%&'*+-.^_`|~=x"]).all("!#$%&'*+-.^_`|~"), ['x']);
});

test('readCookies strips one pair of surrounding quotes and keeps = inside values', () => {
  const cookies = readCookies(['a="quoted"; b=""; c="only-left; d=x=y==; e=""double""']);
  assert.deepEqual(cookies.all('a'), ['quoted']);
  assert.deepEqual(cookies.all('b'), ['']);
  assert.deepEqual(cookies.all('c'), ['"only-left']);
  assert.deepEqual(cookies.all('d'), ['x=y==']);
  assert.deepEqual(cookies.all('e'), ['"double"']);
});

test('a 6 KiB header of unrelated, partly malformed cookies still yields the one session value (D23)', () => {
  const unrelated = [];
  for (let i = 0; unrelated.join('; ').length < 6 * 1024; i++)
    unrelated.push(
      i % 7 === 0 ? `broken piece ${i}` : `CF_Authorization_${i}=${randomBytes(24).toString('hex')}`
    );
  const header = [
    ...unrelated.slice(0, 40),
    `__Host-goblin_session=${value}`,
    ...unrelated.slice(40),
  ].join('; ');
  assert.ok(header.length > 6 * 1024);
  const cookies = readCookies([header]);
  assert.deepEqual(cookies.all('__Host-goblin_session'), [value]);
  assert.deepEqual(cookies.all('goblin_session'), []);
});

test('readCookies is linear in runs of blanks inside a piece (no quadratic trim)', () => {
  // 64 KiB of blanks before a value: a backtracking trim takes seconds here, a linear one well
  // under a millisecond. Leading, inner and trailing runs, of spaces and of tabs.
  const run = n => ' \t'.repeat(n / 2);
  const n = 64 * 1024;
  for (const [header, name, expected] of [
    ['a=' + ' '.repeat(n) + 'x', 'a', ' '.repeat(n) + 'x'],
    ['a=' + '\t'.repeat(n) + 'x', 'a', '\t'.repeat(n) + 'x'],
    ['a=' + run(n) + 'x; goblin_session=kept', 'goblin_session', 'kept'],
    [' '.repeat(n) + 'goblin_session=kept' + '\t'.repeat(n), 'goblin_session', 'kept'],
    ['x' + ' '.repeat(n) + 'y=1; goblin_session=kept', 'goblin_session', 'kept'],
  ]) {
    const started = performance.now();
    const cookies = readCookies([header]);
    const ms = performance.now() - started;
    assert.deepEqual(cookies.all(name), [expected]);
    assert.ok(ms < 250, `parsing ${header.length} characters took ${ms.toFixed(1)} ms`);
  }
});

test('requests with a Cookie header of blanks do not stall Uptime Goblin (createApp)', async t => {
  // A piece of ~16,000 spaces (Node's default header limit is 16 KiB) took about 240 ms to
  // parse with a backtracking trim, and the pipeline parses cookies before any sign-in, on
  // /health too: a few dozen such requests held an honest /health for seconds.
  const { port } = await startReal(t);
  const attack = path => raw(port, [`GET ${path} HTTP/1.1`, `Cookie: a=${' '.repeat(16000)}x`]);
  assert.equal((await attack('/health')).status, 200);
  const inFlight = Array.from({ length: 40 }, (_, i) => attack(i % 2 ? '/health' : '/'));
  const honest = performance.now();
  assert.equal((await raw(port, ['GET /health HTTP/1.1'])).status, 200);
  const honestMs = performance.now() - honest;
  for (const answer of await Promise.all(inFlight)) assert.equal(answer.status, 200);
  assert.ok(honestMs < 1000, `/health took ${honestMs.toFixed(1)} ms during the requests`);
});

test('readCookies never throws on random bytes', () => {
  for (let i = 0; i < 2000; i++) {
    const header = randomBytes(1 + (i % 300)).toString('latin1');
    const cookies = readCookies([header, header.split('').reverse().join('')]);
    assert.ok(Array.isArray(cookies.all('goblin_session')));
  }
  for (const values of [[undefined], [null], [42], [{}], null, 42])
    assert.deepEqual(readCookies(values).all('goblin_session'), []);
});

test('the session cookie name depends on the transport: __Host- only on https', () => {
  assert.equal(sessionCookieName('https'), '__Host-goblin_session');
  assert.equal(sessionCookieName('loopback'), 'goblin_session');
  assert.equal(sessionCookieName('http'), 'goblin_session');
});

test('Set-Cookie strings are exact per transport, with and without Max-Age', () => {
  assert.equal(
    sessionCookie({ kind: 'https', value }),
    `__Host-goblin_session=${value}; Path=/; Secure; HttpOnly; SameSite=Strict`
  );
  assert.equal(
    sessionCookie({ kind: 'https', value, maxAgeSeconds: 2592000 }),
    `__Host-goblin_session=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000`
  );
  for (const kind of ['loopback', 'http']) {
    assert.equal(
      sessionCookie({ kind, value, maxAgeSeconds: null }),
      `goblin_session=${value}; Path=/; HttpOnly; SameSite=Strict`
    );
    assert.equal(
      sessionCookie({ kind, value, maxAgeSeconds: 604799 }),
      `goblin_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604799`
    );
  }
});

test('expired cookies have the same name and attributes, an empty value and Max-Age=0', () => {
  assert.equal(
    expiredSessionCookie('https'),
    '__Host-goblin_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'
  );
  assert.equal(
    expiredSessionCookie('http'),
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
  );
  assert.equal(expiredSessionCookie('loopback'), expiredSessionCookie('http'));
});
