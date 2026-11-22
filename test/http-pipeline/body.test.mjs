import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { Readable } from 'node:stream';
import {
  bodyLimit,
  readBody,
  parseJson,
  forbiddenKey,
  json,
  maxJsonDepth,
  TooLargeError,
} from '../../lib/http/body.mjs';
import { answerClosing, jsonRequest, serverLimits } from '../../lib/http/pipeline.mjs';
import { InputError } from '../../lib/config.mjs';
import { startReal, raw, basic, password, browserWrite, cookieFrom } from './harness.mjs';

const refused = (text, pattern) =>
  assert.throws(
    () => parseJson(Buffer.from(text)),
    error => error instanceof InputError && pattern.test(error.message),
    text
  );

test('__proto__ and constructor.prototype are refused at any depth; their text as values is fine', () => {
  // The two shapes a key-by-key copy or merge follows to a prototype (X9).
  for (const text of [
    '{"__proto__":{"polluted":true}}',
    '{"monitoring":{"__proto__":1}}',
    '{"rules":[{"key":"cpu"},{"__proto__":{"x":1}}]}',
    '[[[{"a":{"__proto__":null}}]]]',
    // Inside a 'constructor' that is itself allowed (a 1.4.x label name, see below).
    '{"metrics":[{"labels":{"constructor":{"__proto__":{"x":1}}}}]}',
  ])
    refused(text, /^Field name __proto__ is not allowed$/);
  for (const text of [
    '{"constructor":{"prototype":{"polluted":true}}}',
    '{"monitoring":{"constructor":{"prototype":{}}}}',
    '{"rules":[{"key":"cpu"},{"constructor":{"prototype":{"x":1}}}]}',
    '[[[{"a":{"constructor":{"prototype":null}}}]]]',
    // Whatever the value, and wherever 'prototype' sits among the constructor's keys.
    '{"constructor":{"a":1,"prototype":1}}',
    '{"metrics":[{"labels":{"constructor":{"prototype":"y"}}}]}',
  ])
    refused(text, /^Field name constructor\.prototype is not allowed$/);
  // Values, and keys that merely contain the words, are ordinary data.
  assert.deepEqual(
    parseJson(Buffer.from('{"path":"nested.constructor.length","doc":"__proto__"}')),
    {
      path: 'nested.constructor.length',
      doc: '__proto__',
    }
  );
  assert.deepEqual(parseJson(Buffer.from('{"prototypes":1,"my_constructor":2}')), {
    prototypes: 1,
    my_constructor: 2,
  });
  // Nothing leaked onto Object.prototype while checking.
  assert.equal({}.polluted, undefined);
  // Deep nesting is walked without recursion.
  let deep = '1';
  for (let i = 0; i < 5000; i++) deep = `{"a":${deep}}`;
  assert.equal(forbiddenKey(JSON.parse(deep)), null);
  assert.equal(forbiddenKey(null), null);
  assert.equal(forbiddenKey('text'), null);
  // A deep constructor.prototype is still found without recursion.
  assert.equal(
    forbiddenKey(JSON.parse(deep.replace('1', '{"constructor":{"prototype":1}}'))),
    'constructor.prototype'
  );
});

// Until the 1.5 refusal (X9) was narrowed, 'constructor' and 'prototype' were refused as
// names on their own. Orbit 1.4.x accepts any \w+ metric label name (lib/config.mjs), so an
// upgraded Prometheus source with such a label could no longer be saved or tested: the source
// drawer sends the whole metrics array back. On their own they reach no prototype.
test('constructor and prototype on their own are ordinary names, such as 1.4.x metric labels', () => {
  const labels =
    '{"metrics":[{"key":"m","path":"p","labels":{"constructor":"x","prototype":"y"}}]}';
  const parsed = parseJson(Buffer.from(labels));
  assert.deepEqual(parsed, {
    metrics: [{ key: 'm', path: 'p', labels: { constructor: 'x', prototype: 'y' } }],
  });
  // Own data properties; the object's prototype is untouched.
  assert.ok(Object.hasOwn(parsed.metrics[0].labels, 'constructor'));
  assert.equal(Object.getPrototypeOf(parsed.metrics[0].labels), Object.prototype);
  for (const text of [
    '{"constructor":1}',
    '{"prototype":{"polluted":true}}',
    '{"a":[{"constructor":{}}]}',
    '{"monitoring":{"prototype":1,"constructor":"x"}}',
    // Only 'prototype' directly inside 'constructor' is the chain to Object.prototype.
    '{"prototype":{"constructor":1}}',
    '{"constructor":{"a":{"prototype":1}}}',
    '{"constructor":[{"prototype":1}]}',
    '{"constructor":"prototype","prototype":"constructor"}',
  ]) {
    assert.deepEqual(parseJson(Buffer.from(text)), JSON.parse(text), text);
    assert.equal(forbiddenKey(JSON.parse(text)), null, text);
  }
  assert.equal({}.polluted, undefined);
  assert.equal(Object.polluted, undefined);
});

test('invalid JSON is the client’s mistake', () => {
  refused('{', /Expected valid JSON/);
  refused('', /Expected valid JSON/);
});

test('bodies over the limit are refused as too large', async () => {
  const body = parts => Readable.from(parts.map(part => Buffer.from(part)));
  assert.equal((await readBody(body(['ab', 'cd']), 4)).toString(), 'abcd');
  await assert.rejects(
    readBody(body(['ab', 'cde']), 4),
    error =>
      error instanceof TooLargeError && error.status === 413 && /too large/.test(error.message)
  );
  assert.equal((await readBody(body([]))).length, 0);
  // An announced length over the limit is refused before a byte is read.
  const announced = Object.assign(body(['ab']), { headers: { 'content-length': '5' } });
  await assert.rejects(readBody(announced, 4), TooLargeError);
  assert.equal(announced.readableDidRead, false);
});

test('duplicate member names and excessive depth are refused at any level', () => {
  for (const text of [
    '{"a":1,"a":2}',
    '{"x":{"a":1,"b":2,"a":3}}',
    '[{"a":1},{"b":{"c":[{"a":1,"a":1}]}}]',
    // Compared decoded: an escape spells the same name.
    '{"a":1,"\\u0061":2}',
    '{"login":"someone","login":"admin","password":"x"}',
  ])
    refused(text, /^Field name (a|login) is given twice$/);
  // The name is cleaned of control characters and cut to 60 characters in the answer.
  const long = `${'n'.repeat(80)}\\n`;
  refused(`{"${long}":1,"${long}":2}`, new RegExp(`^Field name ${'n'.repeat(60)} is given twice$`));
  // The same name in different objects, or as a value, is ordinary.
  for (const text of [
    '{"a":{"a":{"a":1}}}',
    '[{"a":1},{"a":2}]',
    '{"a":"a","b":["a","a"]}',
    '{"a\\"":1,"a":2}',
    '{}',
    '[]',
  ])
    assert.deepEqual(parseJson(Buffer.from(text)), JSON.parse(text), text);
  // Nesting: maxJsonDepth levels of objects and arrays, not one more.
  const nested = depth => '['.repeat(depth - 1) + '{"a":1}' + ']'.repeat(depth - 1);
  assert.deepEqual(parseJson(Buffer.from(nested(maxJsonDepth))).flat(Infinity), [{ a: 1 }]);
  refused(nested(maxJsonDepth + 1), /^Request bodies may nest at most 64 levels$/);
  refused('{"a":'.repeat(5000) + '1' + '}'.repeat(5000), /nest at most/);
});

test('invalid UTF-8 and non-UTF-8 charsets are refused', () => {
  const bytes = (...parts) => Buffer.concat(parts.map(part => Buffer.from(part)));
  for (const body of [
    bytes('{"title":"Probe', [0xff, 0xfe], '"}'),
    bytes('{"title":"caf', [0xe9], '"}'),
    // An overlong encoding of '"' and a lone surrogate (CESU-8) are not UTF-8 either.
    bytes('{"title":"a', [0xc0, 0xa2], '"}'),
    bytes('{"title":"', [0xed, 0xa0, 0x80], '"}'),
  ])
    assert.throws(
      () => parseJson(body),
      error => error instanceof InputError && error.message === 'Request bodies must be UTF-8 JSON'
    );
  assert.deepEqual(parseJson(Buffer.from('{"title":"café 🛰"}')), { title: 'café 🛰' });
  // Valid UTF-8 can still escape half a surrogate pair, in a value or a member name, at any
  // depth: text that is not Unicode, which would become U+FFFD when saved or sent.
  for (const text of [
    '{"title":"Probe\\udcff"}',
    '{"title":"\\ud800"}',
    '{"title":"a\\uDBFFb"}',
    '{"rules":[{"key":"disk\\ud800"}]}',
    '{"x\\udc00":1}',
    '[1,[2,["\\ud83d"]]]',
  ])
    refused(text, /^Request bodies must be UTF-8 JSON$/);
  // A whole pair, escaped or not, and an escaped backslash before "ud800", are fine.
  assert.deepEqual(parseJson(Buffer.from('{"t":"\\ud83d\\ude00 🛰"}')), { t: '😀 🛰' });
  assert.deepEqual(parseJson(Buffer.from('{"t":"\\\\ud800"}')), { t: '\\ud800' });
  const request = type => ({ headers: type === undefined ? {} : { 'content-type': type } });
  for (const type of [
    'application/json',
    'Application/JSON; Charset=UTF-8',
    ' application/json ;charset=utf-8',
    'application/json; charset="utf-8"',
    'application/json; charset=utf8',
    'application/json; boundary=x',
  ])
    assert.equal(jsonRequest(request(type)), true, type);
  for (const type of [
    undefined,
    'text/plain',
    'application/jsonx',
    'application/json; charset=iso-8859-1',
    'application/json; charset=latin1',
    'application/json; charset=utf-16',
    'application/json; charset=utf-8; charset=latin1',
  ])
    assert.equal(jsonRequest(request(type)), false, String(type));
});

// A raw connection to Uptime Goblin: sends `head` (the request line and headers, without the blank
// line) and `body`, then up to `bodyBytes` more (chunked when asked) as fast as Uptime Goblin takes it,
// until Uptime Goblin closes the connection or `deadlineMs` passes. Resolves to {status, head, data,
// closed, sent}: the final answer's status and header block, everything received, whether
// Uptime Goblin closed the connection, and the generated body bytes the socket accepted.
function stream(port, head, { body = '', bodyBytes = 0, chunked = false, deadlineMs = 3000 } = {}) {
  return new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1');
    let data = '',
      closed = false,
      sent = 0,
      done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      const final = data.split('\r\n').find(line => /^HTTP\/1\.1 [2-5]/.test(line));
      const head = final === undefined ? '' : data.slice(data.indexOf(final)).split('\r\n\r\n')[0];
      resolve({ status: Number(final?.split(' ')[1]), head, data, closed, sent });
    };
    const timer = setTimeout(finish, deadlineMs);
    socket.on('data', chunk => (data += chunk));
    socket.on('error', () => {});
    socket.on('close', () => {
      closed = true;
      finish();
    });
    socket.on('connect', async () => {
      socket.write(`${head}\r\n\r\n`);
      if (body) socket.write(body);
      const chunk = Buffer.alloc(64 * 1024, 0x20);
      while (sent < bodyBytes && !closed && !socket.destroyed) {
        const frame = chunked
          ? Buffer.concat([
              Buffer.from(`${chunk.length.toString(16)}\r\n`),
              chunk,
              Buffer.from('\r\n'),
            ])
          : chunk;
        const flushed = socket.write(frame);
        sent += chunk.length;
        if (!flushed)
          await new Promise(next => {
            const go = () => {
              socket.off('drain', go);
              socket.off('close', go);
              next();
            };
            socket.on('drain', go);
            socket.on('close', go);
          });
      }
    });
  });
}

test('unread and oversized bodies get 413 and a closed connection', async t => {
  const { app, port } = await startReal(t);
  const MiB = 1024 * 1024;
  const host = `Host: 127.0.0.1:${port}`;
  const json = 'Content-Type: application/json';
  // The listener's own limits: request time limits far below Node's 300 s, and a connection cap.
  assert.equal(app.server.requestTimeout, serverLimits.requestTimeoutMs);
  assert.equal(app.server.headersTimeout, serverLimits.headersTimeoutMs);
  assert.equal(app.server.maxConnections, serverLimits.maxConnections);
  assert.ok(serverLimits.requestTimeoutMs <= 30000 && serverLimits.headersTimeoutMs <= 20000);
  // How much of a connection Uptime Goblin read: the server side of the last one opened. The client's
  // own count also holds what waits in the two kernel buffers, which Uptime Goblin never read.
  let connection;
  app.server.on('connection', socket => (connection = socket));
  const taken = () => connection.bytesRead;

  // Without a credential: 413 before the credential is checked, and Uptime Goblin stops reading within
  // 1 MiB.
  const announced = await stream(
    port,
    `POST /api/services HTTP/1.1\r\n${host}\r\n${json}\r\nX-Orbit-Request: 1\r\nContent-Length: ${200 * MiB}`,
    { bodyBytes: 16 * MiB }
  );
  assert.equal(announced.closed, true, 'the connection is closed');
  assert.ok(taken() <= MiB, `Uptime Goblin read ${taken()} bytes`);
  if (announced.data) assert.equal(announced.status, 413);
  // A chunked body (no length announced) to a route that takes none: 401, then closed.
  const chunked = await stream(
    port,
    `POST /api/refresh HTTP/1.1\r\n${host}\r\n${json}\r\nX-Orbit-Request: 1\r\nTransfer-Encoding: chunked`,
    { bodyBytes: 16 * MiB, chunked: true }
  );
  assert.equal(chunked.closed, true);
  assert.ok(taken() <= MiB, `Uptime Goblin read ${taken()} bytes`);
  if (chunked.data) assert.equal(chunked.status, 401);
  // A Host outside the allowlist: 403, then closed.
  for (const length of [`Content-Length: ${50 * MiB}`, 'Transfer-Encoding: chunked']) {
    const wrongHost = await stream(
      port,
      `POST /api/services HTTP/1.1\r\nHost: evil.example\r\n${json}\r\n${length}`,
      { bodyBytes: 16 * MiB, chunked: length.startsWith('Transfer') }
    );
    assert.equal(wrongHost.closed, true, length);
    assert.ok(taken() <= MiB, `${length}: Uptime Goblin read ${taken()} bytes`);
    if (wrongHost.data) assert.equal(wrongHost.status, 403, length);
  }
  // A read takes no body at all.
  const read = await raw(port, ['GET /api/version HTTP/1.1', `Authorization: ${basic()}`], 'x');
  assert.equal(read.status, 413);

  // 100 Continue only once a handler reads the body: never without a credential or over the
  // limit, so a refused client is never invited to send it.
  for (const [what, lines] of [
    ['no credential', [`Content-Length: 20`]],
    ['over the limit', [`Authorization: ${basic()}`, `Content-Length: ${20 * MiB}`]],
    ['a wrong Host', [`Content-Length: 20`]],
  ]) {
    const asked = await stream(
      port,
      [
        'PATCH /api/settings HTTP/1.1',
        what === 'a wrong Host' ? 'Host: evil.example' : host,
        json,
        'X-Goblin-Request: 1',
        'Expect: 100-continue',
        ...lines,
      ].join('\r\n'),
      { deadlineMs: 1000 }
    );
    assert.doesNotMatch(asked.data, /^HTTP\/1\.1 100/, what);
    assert.equal(
      asked.status,
      { 'no credential': 401, 'over the limit': 413, 'a wrong Host': 403 }[what],
      what
    );
    assert.match(asked.head, /\r\nConnection: close/i, what);
  }
  // Signed in and within the limit: 100 Continue, then the body is read and saved.
  const body = JSON.stringify({ title: 'Continued' });
  const allowed = await new Promise(resolve => {
    const socket = net.connect(port, '127.0.0.1', () =>
      socket.write(
        [
          'PATCH /api/settings HTTP/1.1',
          host,
          json,
          'X-Goblin-Request: 1',
          `Authorization: ${basic()}`,
          'Expect: 100-continue',
          `Content-Length: ${body.length}`,
          'Connection: close',
          '',
          '',
        ].join('\r\n')
      )
    );
    let data = '';
    socket.on('data', chunk => {
      data += chunk;
      if (/^HTTP\/1\.1 100 Continue\r\n\r\n$/.test(data)) socket.write(body);
    });
    socket.on('close', () => resolve(data));
  });
  assert.match(allowed, /^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 200 /);
  assert.equal(app.config.value.title, 'Continued');

  // Signed in and over the limit: 413 with Connection: close, announced or while read.
  const oversized = await stream(
    port,
    `PATCH /api/settings HTTP/1.1\r\n${host}\r\n${json}\r\nX-Orbit-Request: 1\r\nAuthorization: ${basic()}\r\nContent-Length: ${20 * MiB}`,
    { deadlineMs: 1000 }
  );
  assert.equal(oversized.status, 413);
  assert.match(oversized.head, /\r\nConnection: close/i);
  assert.match(oversized.data, /"error":"Request is too large"/);
  assert.equal(oversized.closed, true);
  const overflowing = await stream(
    port,
    `PATCH /api/settings HTTP/1.1\r\n${host}\r\n${json}\r\nX-Orbit-Request: 1\r\nAuthorization: ${basic()}\r\nTransfer-Encoding: chunked`,
    { bodyBytes: 16 * MiB, chunked: true }
  );
  assert.equal(overflowing.closed, true);
  assert.ok(taken() <= MiB, `Uptime Goblin read ${taken()} bytes`);
  if (overflowing.data) {
    assert.equal(overflowing.status, 413);
    assert.match(overflowing.head, /\r\nConnection: close/i);
  }
  assert.equal(app.config.value.title, 'Continued', 'nothing oversized was saved');

  // A body within the route's limit that Uptime Goblin answers without reading is still read to its
  // end, so the connection can be used again: no Connection: close. Decided by a second request
  // on the same connection (answered: kept open), not by how long the answer took.
  const smallBody = JSON.stringify({ type: 'link', name: 'n', group: 'g', pad: 'x'.repeat(1000) });
  const small = await answerThenProbe(
    port,
    `POST /api/services HTTP/1.1\r\n${host}\r\n${json}\r\nX-Orbit-Request: 1\r\nContent-Length: ${smallBody.length}`,
    smallBody,
    `GET /health HTTP/1.1\r\n${host}\r\n\r\n`
  );
  assert.match(small.head, /^HTTP\/1\.1 401 /);
  assert.doesNotMatch(small.head, /\r\nConnection: close/i);
  assert.equal(small.closed, false);
});

test('the 413 for a body over its route’s limit comes where docs/architecture.md says', async t => {
  // After the Host and request-target checks; before the credential only when the length is
  // announced over the default limit (every request without a credential is held to it, a
  // public route to its own); the route's own limit (a read takes none) once the credential
  // signed in; a chunked body to a write is refused when read, after the credential. Nothing is
  // sent that Uptime Goblin leaves unread, so every answer arrives before the close.
  const { port } = await startReal(t);
  const host = `Host: 127.0.0.1:${port}`;
  const json = 'Content-Type: application/json\r\nX-Orbit-Request: 1';
  const announced = 'Content-Length: 52428800';
  const chunked = 'Transfer-Encoding: chunked';
  // One byte more than the route takes, in one chunk Uptime Goblin reads to its end.
  const over = `${(bodyLimit + 1).toString(16)}\r\n${' '.repeat(bodyLimit + 1)}`;
  const services = 'POST /api/services HTTP/1.1';
  for (const [what, head, status, body = ''] of [
    ['two Host lines', `${services}\r\n${host}\r\n${host}\r\n${json}\r\n${announced}`, 400],
    ['a wrong Host', `${services}\r\nHost: evil.example\r\n${json}\r\n${announced}`, 403],
    [
      'a target that is not a path',
      `POST //x/api/services HTTP/1.1\r\n${host}\r\n${json}\r\n${announced}`,
      400,
    ],
    [
      'an announced length, no credential',
      `${services}\r\n${host}\r\n${json}\r\n${announced}`,
      413,
    ],
    ['chunked to a read, no credential', `GET /api/version HTTP/1.1\r\n${host}\r\n${chunked}`, 401],
    [
      'chunked to a read, signed in',
      `GET /api/version HTTP/1.1\r\n${host}\r\nAuthorization: ${basic()}\r\n${chunked}`,
      413,
    ],
    ['chunked to a public read', `GET /health HTTP/1.1\r\n${host}\r\n${chunked}`, 413],
    ['chunked to a write, no credential', `${services}\r\n${host}\r\n${json}\r\n${chunked}`, 401],
    [
      'chunked to a write, signed in',
      `${services}\r\n${host}\r\n${json}\r\nAuthorization: ${basic()}\r\n${chunked}`,
      413,
      over,
    ],
  ]) {
    const answer = await stream(port, head, { body });
    assert.equal(answer.status, status, what);
    assert.equal(answer.closed, true, what);
  }
});

// The body of an answer whose head is `text`, from `rest` (the bytes after the head), by its
// Content-Length or its chunks (without trailers): {body, after} once it has all arrived, else
// null.
function wholeBody(text, rest) {
  const length = /\r\ncontent-length: *(\d+)/i.exec(text)?.[1];
  if (length !== undefined)
    return rest.length < Number(length)
      ? null
      : { body: rest.subarray(0, Number(length)), after: rest.subarray(Number(length)) };
  if (!/\r\ntransfer-encoding: *chunked/i.test(text)) throw new Error(`no body length: ${text}`);
  const parts = [];
  for (let at = 0; ; ) {
    const line = rest.indexOf('\r\n', at);
    if (line < 0) return null;
    const size = parseInt(rest.subarray(at, line).toString('latin1'), 16);
    if (!Number.isSafeInteger(size)) throw new Error(`a malformed chunk: ${text}`);
    const end = line + 2 + size + 2;
    if (rest.length < end) return null;
    if (size === 0) return { body: Buffer.concat(parts), after: rest.subarray(end) };
    parts.push(rest.subarray(line + 2, line + 2 + size));
    at = end;
  }
}

// Sends `head` and `body` on a new connection and reads the whole answer, then sends `probe`,
// another request, on the same connection: the connection was kept open when the probe is
// answered, and closed when it ends first. Resolves to {head, body, closed} (head and body of
// the first answer). No deadline decides anything: `deadlineMs` only fails a test that would
// otherwise hang.
function answerThenProbe(port, head, body, probe, { deadlineMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    let data = Buffer.alloc(0),
      first = null,
      done = false;
    const finish = (error, closed) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve({ ...first, closed });
    };
    const timer = setTimeout(
      () => finish(new Error(`no answer and no close within ${deadlineMs} ms: ${head}`)),
      deadlineMs
    );
    socket.on('data', chunk => {
      data = Buffer.concat([data, chunk]);
      if (!first) {
        const end = data.indexOf('\r\n\r\n');
        if (end < 0) return;
        const text = data.subarray(0, end).toString('latin1');
        let whole;
        try {
          whole = wholeBody(text, data.subarray(end + 4));
        } catch (error) {
          finish(error);
          return;
        }
        if (!whole) return;
        first = { head: text, body: whole.body.toString('utf8') };
        data = whole.after;
        socket.write(probe);
      }
      if (/^HTTP\/1\.1 \d{3} /.test(data.toString('latin1'))) finish(null, false);
    });
    socket.on('error', () => {});
    socket.on('close', () =>
      first ? finish(null, true) : finish(new Error(`closed before a whole answer: ${head}`))
    );
    socket.on('connect', () => {
      socket.write(`${head}\r\n\r\n`);
      if (body) socket.write(body);
    });
  });
}

// Before a credential signed in, a 413 must not tell which paths exist or what they take: every
// request without one is held to the same default limit, so a known route (a read takes no body,
// the password change at most 4,096 bytes), an unknown path and a wrong method answer alike,
// down to whether the connection stays open. Only a public route keeps its own limit.
test('without a credential, a known route, an unknown path and a wrong method answer a body alike', async t => {
  const { port } = await startReal(t);
  const host = `Host: 127.0.0.1:${port}`;
  // The status line and headers but the per-request ones, the body, and whether Uptime Goblin closed
  // the connection (it keeps it open after reading a body it allows): decided by a second
  // request on the same connection, not by how long the answer took.
  const answer = async (request, body) => {
    const head = `${request} HTTP/1.1\r\n${host}\r\nContent-Length: ${body.length}`;
    const got = await answerThenProbe(port, head, body, `GET /health HTTP/1.1\r\n${host}\r\n\r\n`);
    const [line, ...headers] = got.head.split('\r\n');
    return {
      line,
      headers: headers.filter(header => !/^(?:date|x-request-id):/i.test(header)).sort(),
      body: got.body,
      closed: got.closed,
    };
  };
  for (const body of ['x', 'x'.repeat(5000)]) {
    const answers = await Promise.all(
      [
        'GET /api/dashboard',
        'GET /api/version',
        'POST /api/account/password',
        'GET /api/no-such-route',
        'DELETE /api/dashboard',
        'PUT /api/account/password',
      ].map(async request => [request, await answer(request, body)])
    );
    const [first] = answers;
    assert.match(first[1].line, /^HTTP\/1\.1 401 /, `${body.length} bytes`);
    assert.equal(first[1].closed, false);
    for (const [request, got] of answers.slice(1))
      assert.deepEqual(got, first[1], `${request} (${body.length} bytes) vs ${first[0]}`);
  }
  // A public route is public anyway: /health takes no body, the sign-in at most 4,096 bytes.
  // Each is closed: the probe on its connection is never answered.
  for (const [request, body] of [
    ['GET /health', 'x'],
    ['POST /api/auth/login', 'x'.repeat(5000)],
  ]) {
    const got = await answer(request, body);
    assert.match(got.line, /^HTTP\/1\.1 413 /, request);
    assert.equal(got.closed, true, request);
  }
});

test('a request past its time limit gets 408 and is closed within a second of the limit', async t => {
  const { app, port } = await startReal(t);
  // Node looks for requests past their limits every connectionsCheckingInterval, given when the
  // server is created (its default, 30 s, closed them up to 30 s late), and reads both limits
  // at each look: they are shortened here to keep the test short.
  assert.equal(serverLimits.checkIntervalMs, 1000);
  app.server.headersTimeout = 1500;
  app.server.requestTimeout = 2500;
  // The check interval, and room for a busy host.
  const late = serverLimits.checkIntervalMs + 1500;
  // Sends `head`, then `trickle` every 200 ms; resolves {ms, status} once Uptime Goblin closes, or
  // {ms, status: null} when it has not closed by well after the limit.
  const slow = (head, trickle, limit) =>
    new Promise(resolve => {
      const started = performance.now();
      const socket = net.connect(port, '127.0.0.1');
      let data = '',
        timer;
      const deadline = setTimeout(() => socket.destroy(), limit + late + 2000);
      socket.on('connect', () => {
        socket.write(head);
        timer = setInterval(() => socket.write(trickle), 200);
      });
      socket.on('data', chunk => (data += chunk));
      socket.on('error', () => {});
      socket.on('close', () => {
        clearInterval(timer);
        clearTimeout(deadline);
        const status = /^HTTP\/1\.1 (\d{3})/.exec(data)?.[1];
        resolve({ ms: performance.now() - started, status: status ? Number(status) : null });
      });
    });
  const host = `Host: 127.0.0.1:${port}`;
  // Headers sent a line at a time.
  const headers = await slow(`GET /api/version HTTP/1.1\r\n${host}\r\n`, 'X-Slow: 1\r\n', 1500);
  assert.equal(headers.status, 408, `closed after ${Math.round(headers.ms)} ms`);
  assert.ok(headers.ms >= 1400 && headers.ms < 1500 + late, `${Math.round(headers.ms)} ms`);
  // A signed-in write whose body comes a byte at a time.
  const body = await slow(
    [
      'PATCH /api/settings HTTP/1.1',
      host,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
      `Authorization: ${basic()}`,
      'Content-Length: 1000',
      '',
      '',
    ].join('\r\n'),
    ' ',
    2500
  );
  assert.equal(body.status, 408, `closed after ${Math.round(body.ms)} ms`);
  assert.ok(body.ms >= 2400 && body.ms < 2500 + late, `${Math.round(body.ms)} ms`);
});

test('an answer that closes the connection reads nothing more of the body', async t => {
  // The test above bounds what Uptime Goblin reads, but how much is ready to read when it answers
  // depends on timing. Here the reading pauses until the client's sending has filled the
  // buffers between the two, and the answer is given while a read is handled, as readBody's
  // 413 is. Connection: close alone then went on reading in that same turn of the event loop,
  // and until Node's side of the connection had closed: up to 2 MiB more.
  const MiB = 1024 * 1024;
  let socket, atAnswer;
  const server = http.createServer((req, res) => {
    answerClosing(req, res, () => 1024);
    socket = req.socket;
    req.pause();
    setTimeout(() => {
      const paused = socket.bytesRead;
      req.on('data', () => {
        // Chunks Node had buffered come first; answer on one read from the socket now.
        if (atAnswer !== undefined || socket.bytesRead === paused) return;
        atAnswer = socket.bytesRead;
        res.writeHead(413, { 'Content-Type': 'application/json' }).end('{}');
      });
      req.resume();
    }, 300);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const answered = await stream(
    port,
    `POST /x HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Length: ${200 * MiB}`,
    { bodyBytes: 64 * MiB }
  );
  assert.equal(answered.closed, true);
  await new Promise(resolve => (socket.destroyed ? resolve() : socket.once('close', resolve)));
  assert.ok(atAnswer > 0, 'the body had started to arrive');
  assert.equal(socket.bytesRead - atAnswer, 0, 'bytes read after the answer');
});

test('duplicate member names are refused before sign-in and before a change', async t => {
  const { app, port } = await startReal(t);
  const origin = `http://127.0.0.1:${port}`;
  const signIn = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...browserWrite(origin)],
    `{"login":"someone-else","login":"admin","password":"wrong","password":${JSON.stringify(password)}}`
  );
  assert.equal(signIn.status, 400);
  assert.equal(signIn.json.error, 'Field name login is given twice');
  assert.equal(cookieFrom(signIn), null, 'not signed in');
  const before = JSON.stringify(app.config.value);
  const settings = await raw(
    port,
    [
      'PATCH /api/settings HTTP/1.1',
      `Authorization: ${basic()}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
    ],
    '{"title":"First","appearance":{"timezone":"UTC","timezone":"Europe/London"}}'
  );
  assert.equal(settings.status, 400);
  assert.equal(settings.json.error, 'Field name timezone is given twice');
  assert.equal(JSON.stringify(app.config.value), before);
});

test('bodies that are not UTF-8, or declared in another charset, change nothing', async t => {
  const { app, port } = await startReal(t);
  const before = JSON.stringify(app.config.value);
  const patch = (type, body) =>
    raw(
      port,
      [
        'PATCH /api/settings HTTP/1.1',
        `Authorization: ${basic()}`,
        'X-Goblin-Request: 1',
        `Content-Type: ${type}`,
      ],
      body
    );
  const invalid = await patch(
    'application/json',
    Buffer.concat([Buffer.from('{"title":"Probe'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')])
  );
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json.error, 'Request bodies must be UTF-8 JSON');
  const latin1 = await patch(
    'application/json; charset=iso-8859-1',
    Buffer.concat([Buffer.from('{"title":"caf'), Buffer.from([0xe9]), Buffer.from('"}')])
  );
  assert.equal(latin1.status, 415);
  assert.equal(latin1.json.error, 'Request bodies must be UTF-8 JSON');
  // Half a surrogate pair written as an escape: was saved, and became U+FFFD when written out.
  const escaped = await patch('application/json', '{"title":"Probe\\udcff"}');
  assert.equal(escaped.status, 400);
  assert.equal(escaped.json.error, 'Request bodies must be UTF-8 JSON');
  assert.equal(JSON.stringify(app.config.value), before);
  const utf8 = await patch('application/json; charset="UTF-8"', '{"title":"Café"}');
  assert.equal(utf8.status, 200);
  assert.equal(app.config.value.title, 'Café');
});

test('a JSON answer is not cached and is recorded for replay with the headers that matter', () => {
  const headers = new Map([
    ['retry-after', '5'],
    ['x-other', 'no'],
  ]);
  const written = {};
  const res = {
    hasHeader: name => headers.has(name),
    getHeader: name => headers.get(name),
    writeHead: (status, head) => Object.assign(written, { status, head }),
    end: text => (written.text = text),
  };
  json(res, 429, { error: 'wait' });
  assert.equal(written.status, 429);
  assert.equal(written.head['Cache-Control'], 'no-store');
  assert.equal(written.text, '{"error":"wait"}');
  assert.deepEqual(res.orbitResponse, {
    status: 429,
    body: '{"error":"wait"}',
    headers: { 'retry-after': '5' },
  });
});
