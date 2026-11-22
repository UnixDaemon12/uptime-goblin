import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { newService, collectorType } from '../lib/catalog.mjs';
import { validateService } from '../lib/config.mjs';
import { collect, request, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const source = overrides => ({
  ...newService('http', 'test-website'),
  apiUrl: 'https://website.example.com',
  ...overrides,
});
const values = metrics => Object.fromEntries(metrics.map(m => [m.key, m.value]));

test('HTTP options validate bounded status lists/ranges and safe methods for every source type', () => {
  assert.equal(newService('docker').httpExpectedStatus, '200-399');
  assert.equal(newService('docker').httpMethod, 'GET');
  assert.equal(collectorType(newService('http')), 'http');
  const service = validateService(
    { collector: 'http', httpExpectedStatus: '200-299, 401,403', httpMethod: 'HEAD' },
    newService('docker')
  );
  assert.equal(service.httpExpectedStatus, '200-299,401,403');
  assert.equal(collectorType(service), 'http');
  assert.equal(service.httpMethod, 'HEAD');
  for (const value of ['100', '599', '100-599', '200,301,401,403', '200-200'])
    assert.ok(validateService({ httpExpectedStatus: value }, newService('http')));
  for (const value of [
    '',
    null,
    200,
    '99',
    '600',
    '099-200',
    '200-600',
    '399-200',
    '200,',
    '200,,204',
    'twohundred',
    '200\nsecret',
    '200-299;401',
    Array(22).join('200,') + '200',
    'x'.repeat(201),
  ])
    assert.throws(
      () => validateService({ httpExpectedStatus: value }, newService('http')),
      error => !error.message.includes('secret')
    );
  for (const httpMethod of ['POST', 'DELETE', 'get', '', null])
    assert.throws(() => validateService({ httpMethod }, newService('http')), /method/);
});

test('HTTP accepts configured success and redirect codes without following Location or forwarding credentials', async t => {
  const calls = [];
  let status = 200;
  t.mock.method(transport, 'fetch', async (url, options) => {
    calls.push({ url, options });
    return new Response(null, {
      status,
      headers: { Location: 'https://other.example.com/private' },
    });
  });
  for (const code of [200, 204, 302, 304, 399]) {
    status = code;
    const metrics = await collect(
        source({
          apiKey: 'private-key',
          username: 'private-user',
          password: 'private-password',
          httpMethod: code === 204 ? 'HEAD' : 'GET',
          metricPath: '/ready',
        })
      ),
      v = values(metrics);
    assert.equal(v.available, 1);
    assert.equal(v.http_status, code);
    assert.ok(v.response >= 0);
    assert.equal(metrics.find(m => m.key === 'response').unit, 'ms');
  }
  assert.equal(calls.length, 5);
  for (const { url, options } of calls) {
    assert.equal(url, 'https://website.example.com/ready');
    assert.equal(options.redirect, 'manual');
    assert.equal(options.credentials, 'omit');
    assert.deepEqual(options.headers, { Accept: '*/*' });
    assert.equal(options.body, undefined);
    assert.equal(options.dispatcher, undefined);
    assert.ok(!JSON.stringify(options).includes('private-'));
  }
  assert.equal(calls[1].options.method, 'HEAD');
});

test('HTTP protected login pages require explicit expected 401 or 403 and errors expose only the status', async t => {
  let status = 401;
  t.mock.method(
    transport,
    'fetch',
    async () => new Response('private-provider-response', { status })
  );
  for (const code of [401, 403]) {
    status = code;
    await assert.rejects(
      collect(source()),
      error => error.message === 'Website returned unexpected HTTP ' + code
    );
    assert.equal(
      values(await collect(source({ httpExpectedStatus: '200-299,401,403' }))).http_status,
      code
    );
  }
  status = 503;
  await assert.rejects(
    collect(source()),
    error => error.message === 'Website returned unexpected HTTP 503'
  );
});

test('HTTP cancels bodies immediately without reading or waiting for a streaming body', async t => {
  let cancelled = 0;
  const signals = [];
  t.mock.method(transport, 'fetch', async (_, options) => {
    signals.push(options.signal);
    return {
      status: 200,
      body: {
        cancel() {
          cancelled++;
          return new Promise(() => {});
        },
        getReader() {
          throw new Error('Response body must not be read');
        },
      },
    };
  });
  assert.equal(values(await collect(source())).available, 1);
  assert.equal(cancelled, 1);
  assert.equal(signals[0].aborted, true);
});

test('HTTP source cancellation aborts active probes and does not start already-cancelled work', async t => {
  const controller = new AbortController();
  let entered;
  const ready = new Promise(resolve => (entered = resolve));
  const mock = t.mock.method(
    transport,
    'fetch',
    (_, options) =>
      new Promise((_, reject) => {
        entered();
        options.signal.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true }
        );
      })
  );
  const pending = collect(source({ signal: controller.signal }));
  await ready;
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  await assert.rejects(collect(source({ signal: controller.signal })), { name: 'AbortError' });
  assert.equal(mock.mock.callCount(), 1);
});

test('HTTP request deadline aborts a server that never returns headers', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let signal;
  t.mock.method(
    transport,
    'fetch',
    (_, options) =>
      new Promise((_, reject) => {
        signal = options.signal;
        signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), {
          once: true,
        });
      })
  );
  const pending = collect(source());
  // Let the destination check finish so the request is actually waiting on headers.
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(12000);
  await assert.rejects(pending, /timed out after 12 seconds/);
  assert.equal(signal.aborted, true);
});

test('HTTP TLS/network failures are safe and general API requests still reject redirects', async t => {
  t.mock.method(transport, 'fetch', async () => {
    throw new TypeError('fetch failed', { cause: new Error('private TLS details') });
  });
  await assert.rejects(
    collect(source()),
    error => /TLS certificate/.test(error.message) && !error.message.includes('private TLS details')
  );
  t.mock.restoreAll();
  let redirect;
  t.mock.method(transport, 'fetch', async (_, options) => {
    redirect = options.redirect;
    throw new Error('unexpected redirect');
  });
  await assert.rejects(request(source(), '/api'), /source redirected/);
  assert.equal(redirect, 'error');
});

test('HTTP check paths replace a card URL query and fragment instead of landing inside them', async t => {
  const urls = [];
  t.mock.method(transport, 'fetch', async url => {
    urls.push(url);
    return new Response(null, { status: 200 });
  });
  for (const [apiUrl, metricPath] of [
    ['https://portainer.example.com:9443/#!/home', '/api/health'],
    ['https://grafana.example.com/d/abc?orgId=1', '/api/health'],
    ['https://grafana.example.com/d/abc/?orgId=1#panel', '/api/health'],
    ['https://grafana.example.com/d/abc?orgId=1#panel', null],
    ['https://portainer.example.com:9443/#!/home', ''],
  ])
    await collect(source({ apiUrl, metricPath }));
  assert.deepEqual(urls, [
    'https://portainer.example.com:9443/api/health',
    'https://grafana.example.com/d/abc/api/health',
    'https://grafana.example.com/d/abc/api/health',
    'https://grafana.example.com/d/abc?orgId=1',
    'https://portainer.example.com:9443',
  ]);
});

test('HTTPS to a plain-HTTP port is reported as a scheme mismatch, not a certificate failure', async t => {
  const server = http.createServer((req, res) => res.end('{}'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
  const mismatch = error =>
    /did not answer with TLS/.test(error.message) &&
    /http:\/\/ or https:\/\//.test(error.message) &&
    !/certificate/.test(error.message) &&
    error.retryable === false;
  const apiUrl = `https://127.0.0.1:${server.address().port}`;
  await assert.rejects(collect(source({ apiUrl })), mismatch);
  await assert.rejects(request({ ...newService('docker'), apiUrl }, '/containers/json'), mismatch);
  t.mock.method(transport, 'fetch', async () => {
    throw new TypeError('fetch failed', {
      cause: Object.assign(new Error('private details'), {
        code: 'ERR_SSL_PACKET_LENGTH_TOO_LONG',
      }),
    });
  });
  await assert.rejects(collect(source()), mismatch);
});

test('HTTP response time is measured on a monotonic clock', async t => {
  // The system clock steps back a second while the check waits for headers.
  let clock = Date.UTC(2031, 0, 1);
  t.mock.method(Date, 'now', () => (clock -= 1000));
  t.mock.method(transport, 'fetch', async () => new Response(null, { status: 200 }));
  const response = values(await collect(source())).response;
  assert.ok(response >= 0 && response < 1000, `response time ${response} ms`);
});
