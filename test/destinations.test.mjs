import test from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import {
  checkDestination,
  configureDestinations,
  destinationProblem,
  embeddedIPv4,
  resolvedDestination,
} from '../lib/destinations.mjs';
import { envWebhookAddressProblem, ENV_WEBHOOK_REFUSED } from '../lib/notify/address-policy.mjs';
import { collect, transport } from '../lib/collectors.mjs';
import { newService } from '../lib/catalog.mjs';
import { selfSignedCertificate } from './helpers/tls.mjs';

const resolving = map => async host => {
  if (!Object.hasOwn(map, host)) throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
  return map[host].map(address => ({ address }));
};

test('resolved destinations return a checked address snapshot and reject lookup failures', async t => {
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  configureDestinations({
    allowLoopback: false,
    lookup: resolving({
      'mail.example.test': ['192.0.2.1', '2001:db8::1'],
      'blocked.example.test': ['192.0.2.1', '169.254.169.254'],
      'empty.example.test': [],
      'invalid.example.test': ['not-an-address'],
    }),
  });
  const first = await resolvedDestination('smtp://mail.example.test');
  assert.deepEqual(first, { addresses: ['192.0.2.1', '2001:db8::1'], problem: null });
  first.addresses[0] = '127.0.0.1';
  assert.equal((await resolvedDestination('smtp://mail.example.test')).addresses[0], '192.0.2.1');
  assert.match((await resolvedDestination('smtp://blocked.example.test')).problem, /link-local/);
  for (const host of ['missing', 'empty', 'invalid'])
    await assert.rejects(resolvedDestination(`smtp://${host}.example.test`));
  assert.equal(await destinationProblem('smtp://missing.example.test'), null);
  await assert.rejects(checkDestination('smtp://missing.example.test'), { code: 'ENOTFOUND' });
});

test('link-local, metadata, multicast and reserved destinations are always refused', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  configureDestinations({ allowLoopback: true });
  for (const url of [
    'http://169.254.169.254/latest/meta-data',
    'http://[fe80::1]/',
    'http://[fd00:ec2::254]/',
    'http://0.0.0.0:9100/',
    'http://224.0.0.1/',
    'http://255.255.255.255/',
    'http://[::ffff:169.254.169.254]/',
  ])
    assert.match(await destinationProblem(url), /link-local/, url);
});

test('loopback is refused by default in every spelling and allowed only by opt-in', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  configureDestinations({
    allowLoopback: false,
    lookup: resolving({ 'rebind.example.com': ['192.168.1.5', '127.0.0.1'] }),
  });
  for (const url of [
    'http://127.0.0.1:9100/metrics',
    'http://127.8.9.10/',
    'http://localhost:22/',
    'http://app.localhost/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://2130706433/',
    'http://0x7f.1/',
    'http://rebind.example.com/',
  ])
    assert.match(await destinationProblem(url), /GOBLIN_ALLOW_LOOPBACK/, url);
  configureDestinations({ allowLoopback: true });
  assert.equal(await destinationProblem('http://127.0.0.1:9100/metrics'), null);
});

test('private homelab addresses and unresolvable names are allowed through', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  configureDestinations({
    allowLoopback: false,
    lookup: resolving({ 'nas.home.example': ['192.168.200.10', 'fd12:3456::10'] }),
  });
  for (const url of [
    'https://192.168.200.1/',
    'http://10.0.0.5:8006/',
    'http://172.16.0.2/',
    'http://[fd12:3456::1]/',
    'https://nas.home.example/',
    'https://missing.example/',
  ])
    assert.equal(await destinationProblem(url), null, url);
});

test('an IPv4 address embedded in NAT64, IPv4-compatible, IPv4-translated or 6to4 addresses follows the IPv4 rules', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  // Probe P6: each of these reaches the metadata service through a gateway; so does the
  // local-use NAT64 prefix of RFC 8215 (64:ff9b:1::/96), and the IPv4-translated form of
  // RFC 2765 (::ffff:0:a.b.c.d) gets the same rules (review round 2).
  const metadata = [
    '64:ff9b::a9fe:a9fe',
    '::a9fe:a9fe',
    '2002:a9fe:a9fe::1',
    '64:ff9b:1::a9fe:a9fe',
    '64:ff9b:1::169.254.169.254',
    '::ffff:0:a9fe:a9fe',
    '::ffff:0:169.254.169.254',
  ];
  // The same embedding of a private LAN address is allowed, as the plain address is.
  const lan = [
    '64:ff9b::c0a8:105',
    '64:ff9b::192.168.1.5',
    '2002:c0a8:105::1',
    '::10.0.0.5',
    '64:ff9b:1::c0a8:105',
    '::ffff:0:10.0.0.5',
  ];
  // Embedding 127.0.0.1 is treated as loopback.
  const loop = [
    '64:ff9b::7f00:1',
    '::127.0.0.1',
    '2002:7f00:1::1',
    '64:ff9b:1::7f00:1',
    '::ffff:0:127.0.0.1',
  ];
  for (const allowLoopback of [false, true]) {
    configureDestinations({ allowLoopback });
    for (const address of metadata) {
      assert.match(await destinationProblem(`http://[${address}]/`), /link-local/, address);
      assert.equal(await envWebhookAddressProblem(address), ENV_WEBHOOK_REFUSED, address);
    }
    for (const address of lan) {
      assert.equal(await destinationProblem(`http://[${address}]/`), null, address);
      assert.equal(await envWebhookAddressProblem(address), null, address);
    }
    for (const address of loop) {
      const reason = await destinationProblem(`http://[${address}]/`);
      if (allowLoopback) assert.equal(reason, null, address);
      else assert.match(reason, /GOBLIN_ALLOW_LOOPBACK/, address);
      // The env webhook keeps loopback, as 1.4.2 did.
      assert.equal(await envWebhookAddressProblem(address), null, address);
    }
  }
  // A name that resolves to an embedded refused address is refused like the address itself.
  configureDestinations({
    allowLoopback: false,
    lookup: resolving({ 'nat64.example.test': ['64:ff9b::a9fe:a9fe'] }),
  });
  assert.match(await destinationProblem('http://nat64.example.test/'), /link-local/);
  // What counts as embedded, and what does not.
  assert.equal(embeddedIPv4('64:ff9b::a9fe:a9fe'), '169.254.169.254');
  assert.equal(embeddedIPv4('64:ff9b::169.254.169.254'), '169.254.169.254');
  assert.equal(embeddedIPv4('2002:a9fe:a9fe::1'), '169.254.169.254');
  assert.equal(embeddedIPv4('::a9fe:a9fe'), '169.254.169.254');
  assert.equal(embeddedIPv4('64:ff9b:1::a9fe:a9fe'), '169.254.169.254');
  assert.equal(embeddedIPv4('::ffff:0:a9fe:a9fe'), '169.254.169.254');
  assert.equal(embeddedIPv4('::ffff:0:169.254.169.254'), '169.254.169.254');
  for (const address of [
    '::',
    '::1',
    '::ffff:169.254.169.254', // IPv4-mapped: net.BlockList matches it itself
    // Another layout of the local-use /48 cannot be told from an ordinary address (documented).
    '64:ff9b:1:1::a9fe:a9fe',
    '::ffff:1:a9fe:a9fe', // neither IPv4-mapped nor IPv4-translated
    '2001:db8::a9fe:a9fe',
    'fd00::a9fe:a9fe',
    '169.254.169.254',
    'not an address',
  ])
    assert.equal(embeddedIPv4(address), null, address);
  // Every plain vector of the earlier tests is unchanged.
  assert.match(await destinationProblem('http://[::ffff:169.254.169.254]/'), /link-local/);
  assert.equal(await destinationProblem('http://[fd12:3456::1]/'), null);
});

test('collectors refuse a blocked destination before connecting', async t => {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: false });
  const apiUrl = `http://127.0.0.1:${server.address().port}`;
  for (const type of ['json', 'http'])
    await assert.rejects(
      collect({ ...newService(type), apiUrl, metrics: [{ key: 'a', label: 'A', path: 'a' }] }),
      error => /loopback/.test(error.message) && error.retryable === false
    );
  assert.equal(hits, 0);
});

// Answers like dns.lookup with `address` for every name, counting the calls: the resolver a
// connection would use if it resolved the source's host name again after the check.
const secondAnswer = (t, address) =>
  t.mock.method(dns, 'lookup', (_host, options, callback) => {
    if (typeof options === 'function') callback = options;
    const family = address.includes(':') ? 6 : 4;
    process.nextTick(() =>
      options?.all ? callback(null, [{ address, family }]) : callback(null, address, family)
    );
  });

test('collectors and Website checks connect only to policy-checked addresses: a second DNS answer cannot swap in another address', async t => {
  // The destination check approves 127.0.0.1 (loopback is allowed here, so no packet leaves this
  // host). The resolver a connection would use answers ::1 instead, where a second listener
  // stands for what a short-lived or hostile DNS answer swaps in after the check: a service
  // that listens only on the Uptime Goblin host, or 169.254.169.254. fetch resolved the name again and
  // connected there, with the source's credentials.
  const hits = { checked: 0, swapped: 0 };
  const listen = (host, port, name) =>
    new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        hits[name]++;
        res.end(req.url === '/metrics' ? 'secret_value 42\n' : '{"secretValue":42}');
      });
      server.once('error', reject);
      server.listen(port, host, () => resolve(server));
    });
  const checked = await listen('127.0.0.1', 0, 'checked'),
    port = checked.address().port;
  t.after(() => new Promise(resolve => checked.close(resolve)));
  // Without IPv6 loopback the resolver count below still shows that no second answer is used.
  const swapped = await listen('::1', port, 'swapped').catch(() => null);
  if (swapped) t.after(() => new Promise(resolve => swapped.close(resolve)));
  configureDestinations({ allowLoopback: true, lookup: async () => [{ address: '127.0.0.1' }] });
  t.after(() =>
    configureDestinations({ allowLoopback: false, lookup: async () => [{ address: '192.0.2.1' }] })
  );
  const resolver = secondAnswer(t, '::1');
  const apiUrl = `http://rebind.test:${port}`,
    mapping = path => [{ key: 'v', label: 'V', path }];
  for (const service of [
    { ...newService('json', 'rebind-json'), apiUrl, metrics: mapping('secretValue') },
    { ...newService('linux', 'rebind-linux'), apiUrl, metrics: mapping('secret_value') },
    { ...newService('http', 'rebind-http'), apiUrl },
  ]) {
    const before = hits.checked,
      metrics = await collect(service);
    assert.ok(metrics.length > 0, service.type);
    assert.equal(hits.checked, before + 1, service.type);
  }
  assert.equal(hits.swapped, 0);
  assert.equal(resolver.mock.callCount(), 0, 'the host name is never resolved again');
});

test('a collector connection to a checked address still verifies TLS for the host name', async t => {
  // HTTPS to the checked address keeps SNI and certificate checks on the configured host name:
  // a certificate this host does not trust is refused, and the server is asked for the name.
  const { cert, key } = selfSignedCertificate({ hosts: ['rebind.test'] });
  const names = [];
  const server = https.createServer(
    {
      cert,
      key,
      SNICallback: (name, callback) => {
        names.push(name);
        callback(null, null);
      },
    },
    (req, res) => res.end('{}')
  );
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  configureDestinations({ allowLoopback: true, lookup: async () => [{ address: '127.0.0.1' }] });
  t.after(() =>
    configureDestinations({ allowLoopback: false, lookup: async () => [{ address: '192.0.2.1' }] })
  );
  secondAnswer(t, '127.0.0.1');
  const apiUrl = `https://rebind.test:${server.address().port}`;
  for (const type of ['json', 'http'])
    await assert.rejects(
      collect({ ...newService(type), apiUrl, metrics: [{ key: 'a', label: 'A', path: 'a' }] }),
      error => /^TLS certificate verification failed/.test(error.message),
      type
    );
  assert.deepEqual(names, ['rebind.test', 'rebind.test']);
  // With the certificate trusted (NODE_EXTRA_CA_CERTS, read at start, so in a child process)
  // the same request succeeds: verified against rebind.test, connected to 127.0.0.1.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-pinned-tls-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'ca.pem'), cert);
  const lib = file => JSON.stringify(new URL(`../lib/${file}`, import.meta.url).href);
  const script = `
    import dns from 'node:dns';
    import { collect } from ${lib('collectors.mjs')};
    import { configureDestinations } from ${lib('destinations.mjs')};
    import { newService } from ${lib('catalog.mjs')};
    let resolved = 0;
    dns.lookup = (host, options, callback) => {
      resolved++;
      (callback ?? options)(Object.assign(new Error('not here'), { code: 'ENOTFOUND' }));
    };
    configureDestinations({ allowLoopback: true, lookup: async () => [{ address: '127.0.0.1' }] });
    const metrics = await collect({ ...newService('http'), apiUrl: ${JSON.stringify(apiUrl)} });
    console.log(JSON.stringify({ status: metrics.find(m => m.key === 'http_status').value, resolved }));
  `;
  // Asynchronously: this process serves the HTTPS answer meanwhile.
  const child = await new Promise(resolve =>
    execFile(
      process.execPath,
      ['--input-type=module', '-e', script],
      {
        env: { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: path.join(directory, 'ca.pem') },
        timeout: 20000,
      },
      (error, stdout, stderr) => resolve({ error, stdout, stderr })
    )
  );
  assert.equal(child.error, null, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { status: 200, resolved: 0 });
});

test('a slow destination lookup is cancelled by the request deadline and blamed on DNS', async t => {
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  configureDestinations({ lookup: () => new Promise(() => {}) });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const fetch = t.mock.method(transport, 'fetch', async () => new Response('{}'));
  // A stalled resolver is reported as DNS, not as a slow website or API.
  const dns = error =>
    error.message ===
      'DNS lookup timed out after 12 seconds. Check the source hostname and DNS server.' &&
    error.retryable === true;
  for (const type of ['http', 'json']) {
    const pending = collect({
      ...newService(type),
      apiUrl: 'https://slow-dns.example',
      metrics: [{ key: 'a', label: 'A', path: 'a' }],
    });
    t.mock.timers.tick(12000);
    await assert.rejects(pending, dns);
  }
  assert.equal(fetch.mock.callCount(), 0);
});

test('concurrent checks share one lookup per name and reuse the answer briefly', async t => {
  t.after(() =>
    configureDestinations({
      lookup: async () => [{ address: '192.0.2.1' }],
      now: () => performance.now(),
    })
  );
  let now = 1000000;
  const hosts = [],
    waiting = [];
  const answer = addresses => waiting.splice(0).forEach(resolve => resolve(addresses));
  configureDestinations({
    now: () => now,
    lookup: host => {
      hosts.push(host);
      return new Promise(resolve => waiting.push(resolve));
    },
  });
  const checks = Array.from({ length: 4 }, () => destinationProblem('https://nas.example/'));
  answer([{ address: '192.168.1.20' }]);
  assert.deepEqual(await Promise.all(checks), [null, null, null, null]);
  assert.deepEqual(hosts, ['nas.example']);
  assert.equal(await destinationProblem('https://nas.example:8443/other'), null);
  assert.equal(hosts.length, 1);
  // Parallel collector requests (Sonarr/Radarr send four) share the same answer.
  t.mock.method(transport, 'fetch', async url =>
    Response.json(url.endsWith('/queue/status') ? { totalCount: 0 } : [])
  );
  await collect({ ...newService('sonarr'), apiUrl: 'https://nas.example' });
  assert.equal(hosts.length, 1);
  now += 31000;
  const again = destinationProblem('https://nas.example/');
  answer([{ address: '192.168.1.20' }]);
  assert.equal(await again, null);
  assert.equal(hosts.length, 2);
});

test('a failed lookup fails collectors fast with the DNS message and is not repeated at once', async t => {
  t.after(() =>
    configureDestinations({
      lookup: async () => [{ address: '192.0.2.1' }],
      now: () => performance.now(),
    })
  );
  let now = 1000000;
  let lookups = 0;
  configureDestinations({
    now: () => now,
    lookup: async () => {
      lookups++;
      now += 5000; // the resolver hung for 5 s before giving up
      throw Object.assign(new Error('getaddrinfo EAI_AGAIN dead.example'), { code: 'EAI_AGAIN' });
    },
  });
  const fetch = t.mock.method(transport, 'fetch', async () => Response.json({ value: 1 }));
  const source = {
    ...newService('json'),
    apiUrl: 'https://dead.example',
    metrics: [{ key: 'value', label: 'Value', path: 'value' }],
  };
  const dns = error =>
    error.message === 'DNS lookup failed. Check the source hostname and DNS server.' &&
    error.retryable === true;
  await assert.rejects(collect(source), dns);
  await assert.rejects(collect({ ...newService('http'), apiUrl: 'https://dead.example' }), dns);
  // Mail and other callers keep the lenient contract: an unresolvable name is not a refusal.
  assert.equal(await destinationProblem('https://dead.example/'), null);
  assert.equal(fetch.mock.callCount(), 0);
  assert.equal(lookups, 1);
  now += 11000;
  await assert.rejects(collect(source), dns);
  assert.equal(lookups, 2);
  // Reconfiguring drops remembered answers, so an injected lookup applies immediately.
  configureDestinations({ lookup: async () => [{ address: '192.168.1.30' }] });
  assert.deepEqual(
    (await collect(source)).map(m => [m.key, m.value]),
    [['value', 1]]
  );
});

test('a definite "not found" is not remembered, so a retry looks the name up again', async t => {
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  let lookups = 0;
  configureDestinations({
    lookup: async () => {
      lookups++;
      throw Object.assign(new Error('getaddrinfo ENOTFOUND new.example'), { code: 'ENOTFOUND' });
    },
  });
  for (let i = 0; i < 2; i++)
    await assert.rejects(collect({ ...newService('http'), apiUrl: 'https://new.example' }), /DNS/);
  assert.equal(lookups, 2);
});

test('a quick temporary DNS failure is not remembered, so a retry can succeed', async t => {
  t.after(() => configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] }));
  let lookups = 0;
  configureDestinations({
    lookup: async () => {
      if (++lookups === 1)
        throw Object.assign(new Error('getaddrinfo EAI_AGAIN blip.example'), { code: 'EAI_AGAIN' });
      return [{ address: '192.0.2.44' }];
    },
  });
  await assert.rejects(
    collect({ ...newService('http'), apiUrl: 'https://blip.example' }),
    /DNS lookup failed/
  );
  assert.equal(await checkDestination('https://blip.example/'), null);
  assert.equal(lookups, 2);
});
