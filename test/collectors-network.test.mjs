import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import zlib from 'node:zlib';
import { newService } from '../lib/catalog.mjs';
import { CollectionError, collect, request, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { fetchPinned } from '../lib/net/outbound.mjs';
import { silentServer } from './helpers/net.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const source = (type = 'json', overrides = {}) => ({
  ...newService(type, 'network-' + type),
  apiUrl: 'https://network.example.com',
  ...overrides,
});
const values = metrics => Object.fromEntries(metrics.map(m => [m.key, m.value]));

test('a connection dropped while the body is read is a retryable interruption', async t => {
  // Headers and part of a large list arrive, then the source restarts mid-response: the body
  // falls short of its length, its chunked framing is cut off, or the socket is reset.
  let drop;
  const server = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      ...(drop === 'length' && { 'Content-Length': '100000' }),
    });
    res.write('[1,2,3,');
    setTimeout(() => (drop === 'reset' ? res.socket.resetAndDestroy() : res.destroy()), 20);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const service = source('json', { apiUrl: `http://127.0.0.1:${server.address().port}` });
  const interrupted = error =>
    error instanceof CollectionError &&
    /Connection was interrupted/.test(error.message) &&
    error.retryable === true;
  for (drop of ['length', 'chunked', 'reset']) {
    await assert.rejects(request(service, '/list'), interrupted, drop);
    await assert.rejects(request(service, '/list', { each: () => {} }), interrupted, drop);
  }
});

test('a body that breaks the same way on every attempt is a malformed response, not retried', async t => {
  // Headers arrive, then the body cannot be read: invalid chunked framing, a plain body
  // labelled gzip or brotli, or a corrupt gzip stream.
  const json = JSON.stringify(Array.from({ length: 2000 }, (_, id) => ({ id, name: 'item' })));
  const corrupt = zlib.gzipSync(json);
  for (let i = 200; i < 260; i++) corrupt[i] ^= 0xff;
  const encoded = (encoding, body) => socket =>
    socket.end(
      Buffer.concat([
        Buffer.from(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: ${encoding}\r\n` +
            `Content-Length: ${body.length}\r\nConnection: close\r\n\r\n`
        ),
        body,
      ])
    );
  const replies = {
    chunked: socket =>
      socket.end(
        'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n' +
          '3\r\n[1,\r\nZZ\r\n'
      ),
    'plain gzip': encoded('gzip', Buffer.from(json)),
    'plain brotli': encoded('br', Buffer.from(json)),
    'corrupt gzip': encoded('gzip', corrupt),
  };
  let reply;
  const server = net.createServer(socket => {
    socket.on('error', () => {});
    socket.once('data', () => reply(socket));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const service = source('json', { apiUrl: `http://127.0.0.1:${server.address().port}` });
  // The parser or decoder detail stays out of the message.
  const malformed = error =>
    error instanceof CollectionError &&
    /^Source sent a malformed response/.test(error.message) &&
    !/chunk size|header check|distance|Decompression|HPE_|Z_/i.test(error.message) &&
    error.retryable === false;
  for (const [name, respond] of Object.entries(replies)) {
    reply = respond;
    await assert.rejects(request(service, '/list'), malformed, name);
    await assert.rejects(request(service, '/list', { each: () => {} }), malformed, name);
  }
});

test('the pinned client speaks HTTP as fetch did: headers, bodies, compression, redirects, bad ports and stalls', async t => {
  const json = JSON.stringify({ a: { b: 2 } });
  const encoded = {
    gzip: zlib.gzipSync(json),
    'x-gzip': zlib.gzipSync(json),
    deflate: zlib.deflateSync(json),
    'deflate (raw)': zlib.deflateRawSync(json),
    br: zlib.brotliCompressSync(json),
    'gzip, br': zlib.brotliCompressSync(zlib.gzipSync(json)),
    ...(zlib.zstdCompressSync && { zstd: zlib.zstdCompressSync(json) }),
  };
  const seen = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    seen.push({ method: req.method, url: req.url, headers: req.headers, body });
    const [, route, name] = req.url.split('/').map(decodeURIComponent);
    if (route === 'encoded') {
      res.writeHead(200, { 'Content-Encoding': name.replace(' (raw)', '') });
      return res.end(encoded[name]);
    }
    if (route === 'redirect') {
      res.writeHead(Number(name), { Location: 'http://192.0.2.1/elsewhere' });
      return res.end();
    }
    if (route === 'stall') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.write('[1,');
    }
    res.end(json);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const apiUrl = `http://127.0.0.1:${server.address().port}`;
  const service = source('json', { apiUrl, apiKey: 'fixture-key' });
  // The headers fetch sent, the caller's own, and a request body with its length.
  await request(service, '/plain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': 'fixture-key' },
    body: '{"q":1}',
  });
  const { headers, method, body } = seen.at(-1);
  assert.deepEqual(
    {
      method,
      body,
      accept: headers.accept,
      language: headers['accept-language'],
      mode: headers['sec-fetch-mode'],
      agent: headers['user-agent'],
      encoding: headers['accept-encoding'],
      key: headers['x-api-key'],
      length: headers['content-length'],
      host: headers.host,
    },
    {
      method: 'POST',
      body: '{"q":1}',
      accept: 'application/json',
      language: '*',
      mode: 'cors',
      agent: 'node',
      encoding: 'gzip, deflate',
      key: 'fixture-key',
      length: '7',
      host: `127.0.0.1:${server.address().port}`,
    }
  );
  // Compressed bodies, also nested, decoded.
  for (const name of Object.keys(encoded))
    assert.deepEqual(
      await request(service, `/encoded/${encodeURIComponent(name)}`),
      { a: { b: 2 } },
      name
    );
  // A redirect is an error for API reads and a status for Website checks (which may accept it).
  for (const status of [301, 302, 303, 307, 308]) {
    await assert.rejects(
      request(service, `/redirect/${status}`),
      error => error.message === 'The source redirected. Use its final API address.',
      String(status)
    );
    const website = await collect(source('http', { apiUrl: `${apiUrl}/redirect/${status}` }));
    assert.equal(website.find(m => m.key === 'http_status').value, status);
  }
  assert.ok(!seen.some(entry => entry.url === '/elsewhere'));
  // A HEAD check has no body to read.
  await collect(source('http', { apiUrl: `${apiUrl}/plain`, httpMethod: 'HEAD' }));
  assert.equal(seen.at(-1).method, 'HEAD');
  // The Fetch standard's bad ports stay refused, before any connection.
  await assert.rejects(
    request(source('json', { apiUrl: 'http://127.0.0.1:6000' }), '/api'),
    /Invalid source address or request configuration/
  );
  // A body that stops arriving ends at the request's time limit, as a timeout.
  await assert.rejects(
    request(source('json', { apiUrl, requestTimeoutMs: 1000 }), '/stall'),
    error => error.message === 'Source timed out after 1 seconds' && error.retryable === true
  );
  // 101 Switching Protocols (Node gives it as an upgrade, never a response) and a connection
  // closed before any answer: an interrupted connection at once, as with fetch, not a wait to
  // the time limit blamed on the source; without a signal the request waited for ever.
  let answer;
  const connections = new Set();
  const raw = net.createServer(socket => {
    connections.add(socket);
    socket.on('close', () => connections.delete(socket));
    socket.on('error', () => {});
    socket.once('data', () => socket.end(answer));
  });
  await new Promise(resolve => raw.listen(0, '127.0.0.1', resolve));
  // Closed whatever the outcome, so a failure ends this file instead of holding it open.
  t.after(() => {
    for (const socket of connections) socket.destroy();
    return new Promise(resolve => raw.close(resolve));
  });
  const rawUrl = `http://127.0.0.1:${raw.address().port}`;
  for (answer of [
    'HTTP/1.1 101 Switching Protocols\r\nUpgrade: synthetic\r\nConnection: Upgrade\r\n\r\n',
    '',
  ]) {
    const began = Date.now();
    await assert.rejects(
      request(source('json', { apiUrl: rawUrl, requestTimeoutMs: 1500 }), '/api'),
      error =>
        error instanceof CollectionError &&
        /^Connection was interrupted/.test(error.message) &&
        error.retryable === true,
      JSON.stringify(answer)
    );
    assert.ok(Date.now() - began < 1000, `${JSON.stringify(answer)}: answered at once`);
    await assert.rejects(
      collect(source('http', { apiUrl: rawUrl, requestTimeoutMs: 1500 })),
      /Connection was interrupted/,
      JSON.stringify(answer)
    );
    const settled = await Promise.race([
      fetchPinned(new URL(`${rawUrl}/api`), {}, ['127.0.0.1']).then(
        () => 'resolved',
        () => 'rejected'
      ),
      new Promise(resolve => setTimeout(() => resolve('pending'), 2000)),
    ]);
    assert.equal(settled, 'rejected', `${JSON.stringify(answer)}: without a signal`);
  }
});

test('oversized response headers are reported as such and not retried', async t => {
  // One header of 80,000 characters, or 2,000 Set-Cookie headers: a misbehaving source or
  // proxy, not a connection or TLS problem, and the same on every attempt.
  let shape;
  const server = http.createServer((req, res) => {
    if (shape === 'one large header') res.setHeader('x-big', 'a'.repeat(80000));
    else
      res.setHeader(
        'set-cookie',
        Array.from({ length: 2000 }, (_, i) => `c${i}=SYNTHETIC-COOKIE-CANARY`)
      );
    res.end('{"a":1}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const apiUrl = `http://127.0.0.1:${server.address().port}`;
  const oversized = error =>
    error instanceof CollectionError &&
    error.message ===
      'Source sent HTTP headers larger than Uptime Goblin accepts. Check any proxy in front of the source.' &&
    error.retryable === false;
  for (shape of ['one large header', 'many cookies']) {
    await assert.rejects(request(source('json', { apiUrl }), '/api'), oversized, shape);
    await assert.rejects(collect(source('http', { apiUrl })), oversized, shape);
  }
});

test('mid-body failures are retried unless the body itself is malformed', async t => {
  let cause;
  t.mock.method(
    transport,
    'fetch',
    async () =>
      new Response(
        new ReadableStream({ pull: body => body.error(new TypeError('terminated', { cause })) })
      )
  );
  const failure = (code, name = 'Error') =>
    Object.assign(new Error('secret-detail https://private.invalid'), { code, name });
  for (const [reason, pattern, retryable] of [
    [failure('UND_ERR_SOCKET', 'SocketError'), /interrupted/, true],
    [failure('UND_ERR_RES_CONTENT_LENGTH_MISMATCH'), /interrupted/, true],
    [failure('ECONNRESET'), /interrupted/, true],
    [failure('ECONNABORTED'), /interrupted/, true],
    [failure('EPIPE'), /interrupted/, true],
    [failure('ERR_SSL_DECRYPTION_FAILED_OR_BAD_RECORD_MAC'), /interrupted/, true],
    [failure('UND_ERR_BODY_TIMEOUT'), /timed out/, true],
    // HTTP/2 resets, a premature end of stream and unknown causes are dropped connections.
    [failure('ERR_HTTP2_STREAM_ERROR'), /interrupted/, true],
    [failure('ERR_HTTP2_SESSION_ERROR'), /interrupted/, true],
    [failure('HPE_INVALID_EOF_STATE', 'HTTPParserError'), /interrupted/, true],
    [
      Object.assign(new Error('Invalid EOF state'), { name: 'HTTPParserError' }),
      /interrupted/,
      true,
    ],
    [failure(undefined), /interrupted/, true],
    // Node's HTTP parser errors often have no code.
    [failure(undefined, 'HTTPParserError'), /malformed response/, false],
    [failure('HPE_INVALID_CHUNK_SIZE', 'HTTPParserError'), /malformed response/, false],
    [failure('Z_DATA_ERROR'), /malformed response/, false],
    [failure('Z_BUF_ERROR'), /malformed response/, false],
    [failure('ERR__ERROR_FORMAT_PADDING_1'), /malformed response/, false],
    [failure('ZSTD_error_prefix_unknown'), /malformed response/, false],
  ]) {
    cause = reason;
    await assert.rejects(
      request(source(), '/list'),
      error =>
        error instanceof CollectionError &&
        pattern.test(error.message) &&
        error.retryable === retryable &&
        !/secret-detail|private\.invalid/.test(error.message),
      reason.code ?? reason.name
    );
  }
});

test('connection setup (TCP and TLS) is bounded by the request time limit, not a fixed connect timeout', async t => {
  // A host that accepts the connection and never completes the TLS handshake. fetch gave up
  // after its own fixed 10 seconds whatever the limit; the request's time limit now covers it.
  const silent = await silentServer();
  t.after(() => silent.close());
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const apiUrl = `https://127.0.0.1:${silent.port}`;
  for (const type of ['json', 'http']) {
    const started = performance.now();
    await assert.rejects(
      collect(source(type, { apiUrl, requestTimeoutMs: 1000 })),
      error => /timed out after 1 seconds/.test(error.message) && error.retryable === true,
      type
    );
    assert.ok(performance.now() - started < 5000, type);
  }
  // A connect timeout that the network layer reports itself is a retried connection timeout.
  t.mock.method(transport, 'fetch', async () => {
    throw new TypeError('fetch failed', {
      cause: Object.assign(new Error('Connect Timeout Error'), { code: 'UND_ERR_CONNECT_TIMEOUT' }),
    });
  });
  for (const run of [() => request(source(), '/api'), () => collect(source('http'))])
    await assert.rejects(
      run(),
      error => /^Connection timed out/.test(error.message) && error.retryable === true
    );
});

test('a response that is ready when the request timer expires is still used', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  // The response becomes ready in the same event-loop turn as the expired limit, as when a
  // stall (a slow history query) outlasts the limit while the answer is already waiting.
  t.mock.method(
    transport,
    'fetch',
    (_, options) =>
      new Promise((resolve, reject) => {
        options.signal.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true }
        );
        setTimeout(() => resolve(Response.json({ ready: 1 }, { status: 200 })), 12000);
      })
  );
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const api = request(source(), '/api');
  await settle();
  t.mock.timers.tick(12000);
  assert.deepEqual(await api, { ready: 1 });
  const website = collect(source('http'));
  await settle();
  t.mock.timers.tick(12000);
  assert.equal(values(await website).available, 1);
});

test('Prometheus scrapes ask for the text format; JSON reads and caller headers are kept', async t => {
  const accepts = [];
  t.mock.method(transport, 'fetch', async (url, options) => {
    accepts.push(options.headers.Accept);
    return new Response(url.endsWith('/metrics') ? 'node_load1 0.5\n' : '{"a":1}');
  });
  await collect(source('linux'));
  await request(source(), '/api');
  await request(source(), '/metrics', { text: true, headers: { Accept: 'text/plain' } });
  assert.match(accepts[0], /^text\/plain;version=0\.0\.4/);
  assert.equal(accepts[1], 'application/json');
  assert.equal(accepts[2], 'text/plain');
});

test('a UTF-8 byte order mark before JSON or exporter text is ignored', async t => {
  let body;
  t.mock.method(transport, 'fetch', async () => new Response(body));
  body = '﻿{"a":{"b":2}}';
  const metrics = await collect({
    ...source(),
    metrics: [{ key: 'b', label: 'B', path: 'a.b' }],
  });
  assert.deepEqual(values(metrics), { b: 2 });
  body = '﻿[1,2,3]';
  assert.equal(await request(source(), '/list', { each: () => {} }), 3);
  body = '﻿node_load1 0.5\n';
  assert.equal(values(await collect(source('linux'))).load1, 0.5);
});
