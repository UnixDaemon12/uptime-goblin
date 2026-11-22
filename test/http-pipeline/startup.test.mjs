import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createStartupHandler, switchableHandler } from '../../lib/http/startup.mjs';
import { json } from '../../lib/http/body.mjs';
import { requestIdPattern } from '../../lib/http/pipeline.mjs';

async function listen(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { port } = server.address();
  const get = async (route, { method = 'GET', host } = {}) => {
    const response = await new Promise((resolve, reject) =>
      http
        .request(
          { host: '127.0.0.1', port, path: route, method, headers: host ? { Host: host } : {} },
          resolve
        )
        .on('error', reject)
        .end()
    );
    let text = '';
    for await (const chunk of response) text += chunk;
    return { status: response.statusCode, headers: response.headers, text };
  };
  return { get };
}

test('while starting, /health and /health/ready say so and everything else waits', async t => {
  let phase = 'migrating';
  const nonce = 'a'.repeat(32);
  const { get } = await listen(
    t,
    createStartupHandler({
      build: 'b2b2b2b2b2b2',
      nonce,
      allowedHost: host => /^127\.0\.0\.1:\d+$/.test(host ?? ''),
      phase: () => phase,
    })
  );
  const health = await get('/health');
  assert.equal(health.status, 503);
  assert.deepEqual(JSON.parse(health.text), { status: 'starting' });
  assert.deepEqual(JSON.parse((await get(`/health?instance=${nonce}`)).text), {
    status: 'starting',
    instance: 'match',
  });
  const other = await get('/health?instance=' + 'b'.repeat(32));
  assert.deepEqual(JSON.parse(other.text), { status: 'starting', instance: 'mismatch' });
  assert.ok(!other.text.includes(nonce));
  assert.equal((await get('/health', { method: 'HEAD' })).status, 503);
  const ready = await get('/health/ready');
  assert.equal(ready.status, 503);
  assert.deepEqual(JSON.parse(ready.text), { status: 'starting' });
  for (const [route, method] of [
    ['/api/dashboard', 'GET'],
    ['/', 'GET'],
    ['/api/settings', 'PATCH'],
    ['/health', 'POST'],
  ]) {
    const answer = await get(route, { method });
    assert.equal(answer.status, 503, route);
    assert.equal(answer.headers['retry-after'], '5', route);
    assert.equal(JSON.parse(answer.text).code, 'starting', route);
  }
  for (const answer of [health, ready]) {
    assert.equal(answer.headers['x-goblin-build'], 'b2b2b2b2b2b2');
    assert.match(answer.headers['x-request-id'], requestIdPattern);
    assert.match(answer.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(answer.headers['cache-control'], 'no-store');
  }
  assert.equal((await get('/health', { host: 'evil.test' })).status, 403);
  phase = 'stopping';
  assert.deepEqual(JSON.parse((await get('/health')).text), { status: 'stopping' });
  assert.equal(JSON.parse((await get('/api/dashboard')).text).code, 'stopping');
});

// One request on its own connection, written byte for byte; resolves to the status line and
// the head of the answer.
async function rawRequest(port, text) {
  const socket = net.connect(port, '127.0.0.1');
  socket.on('error', () => {});
  await new Promise(resolve => socket.once('connect', resolve));
  socket.write(text);
  let data = '';
  for await (const chunk of socket) data += chunk;
  return { status: Number(data.split(' ')[1]), head: data.split('\r\n\r\n')[0] };
}

test('while starting, an address that is not origin-form, several Host lines or a repeated instance get 400', async t => {
  const server = http.createServer(
    createStartupHandler({
      build: 'b2b2b2b2b2b2',
      nonce: 'a'.repeat(32),
      allowedHost: host => /^127\.0\.0\.1:\d+$/.test(host ?? ''),
    })
  );
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { port } = server.address();
  const host = `Host: 127.0.0.1:${port}`;
  const get = (target, headers = [host]) =>
    rawRequest(
      port,
      [`GET ${target} HTTP/1.1`, ...headers, 'Connection: close', '', ''].join('\r\n')
    );
  // The URL parser would read these as another authority and answer for /health.
  for (const target of ['//x/health', '/\\x/health', 'http://evil.example/health', '*'])
    assert.equal((await get(target)).status, 400, target);
  assert.equal((await get('/health')).status, 503);
  assert.equal((await get('/health', [host, 'Host: evil.example'])).status, 400);
  assert.equal((await get('/health', ['Host: evil.example', host])).status, 400);
  assert.equal((await get('/health?instance=a&instance=b')).status, 400);
  // Nothing here reads a body: an answer given while one is still arriving closes the connection.
  const posted = await rawRequest(
    port,
    `POST /api/settings HTTP/1.1\r\n${host}\r\nContent-Length: 1048576\r\n\r\n{}`
  );
  assert.equal(posted.status, 503);
  assert.match(posted.head, /\r\nConnection: close/i);
});

test('the listener switches from startup mode to the full pipeline without rebinding', async t => {
  const handler = switchableHandler(createStartupHandler({ build: 'b2b2b2b2b2b2' }));
  const { get } = await listen(t, handler);
  assert.equal((await get('/api/version')).status, 503);
  handler.use((req, res) => json(res, 200, { ready: true }));
  const after = await get('/api/version');
  assert.equal(after.status, 200);
  assert.deepEqual(JSON.parse(after.text), { ready: true });
  assert.throws(() => handler.use(null), TypeError);
});
