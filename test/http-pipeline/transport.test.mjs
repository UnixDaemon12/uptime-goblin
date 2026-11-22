import test from 'node:test';
import assert from 'node:assert/strict';
import { trustedProxies } from '../../lib/throttle.mjs';
import {
  browserContext,
  decideTransport,
  isLoopbackHost,
  forwardingHeaders,
  isLoopbackPeer,
  originHost,
  originScheme,
} from '../../lib/http/transport.mjs';

const loopbackProxy = trustedProxies('loopback');
const lanProxy = trustedProxies('192.0.2.10');

test('decideTransport: a trusted proxy that says https makes the transport https', () => {
  for (const [peer, trusted] of [
    ['127.0.0.1', loopbackProxy],
    ['::1', loopbackProxy],
    ['::ffff:127.0.0.1', loopbackProxy],
    ['192.0.2.10', lanProxy],
  ])
    assert.deepEqual(
      decideTransport({
        peer,
        trusted,
        headers: { 'x-forwarded-for': '198.51.100.7', 'x-forwarded-proto': 'https' },
      }),
      { kind: 'https', forwardedProto: 'https', proxied: true },
      peer
    );
  // Case and spaces do not matter; a header naming only the protocol is still a proxy's.
  assert.equal(
    decideTransport({
      peer: '127.0.0.1',
      trusted: loopbackProxy,
      headers: { 'x-forwarded-proto': ' HTTPS ' },
    }).kind,
    'https'
  );
});

test('decideTransport: http, missing or unknown protocols from a trusted proxy are http', () => {
  const trusted = loopbackProxy,
    peer = '127.0.0.1';
  for (const headers of [
    { 'x-forwarded-for': '198.51.100.7', 'x-forwarded-proto': 'http' },
    { 'x-forwarded-for': '198.51.100.7' },
    { 'x-forwarded-for': '198.51.100.7', 'x-forwarded-proto': 'wss' },
    { 'x-forwarded-for': '198.51.100.7', 'x-forwarded-proto': '' },
    { 'x-real-ip': '198.51.100.7' },
    { 'x-forwarded-host': 'goblin.example' },
  ]) {
    const decided = decideTransport({ peer, trusted, headers });
    assert.equal(decided.kind, 'http', JSON.stringify(headers));
    assert.equal(decided.proxied, true);
    assert.ok([null, 'http'].includes(decided.forwardedProto));
  }
  assert.equal(
    decideTransport({ peer, trusted, headers: { 'x-forwarded-proto': 'http' } }).forwardedProto,
    'http'
  );
});

test('decideTransport: only the last X-Forwarded-Proto element (the nearest proxy) counts', () => {
  const decide = value =>
    decideTransport({
      peer: '127.0.0.1',
      trusted: loopbackProxy,
      headers: { 'x-forwarded-proto': value },
    });
  // A client may send its own X-Forwarded-Proto: https; the proxy appends the real one.
  assert.equal(decide('https, http').kind, 'http');
  assert.equal(decide('http, https').kind, 'https');
  assert.equal(decide('https,http').forwardedProto, 'http');
  // Node hands repeated headers over joined; an array (headersDistinct) works the same.
  assert.equal(decide(['https', 'http']).kind, 'http');
});

test('decideTransport: Forwarded proto= is used only without X-Forwarded-Proto', () => {
  const decide = headers => decideTransport({ peer: '127.0.0.1', trusted: loopbackProxy, headers });
  assert.equal(decide({ forwarded: 'for=198.51.100.7;proto=https' }).kind, 'https');
  assert.equal(decide({ forwarded: 'for=198.51.100.7;Proto="HTTPS"' }).kind, 'https');
  assert.equal(decide({ forwarded: 'proto=https, for=198.51.100.7;proto=http' }).kind, 'http');
  // A last element without proto keeps the earlier one: the last proto= wins.
  assert.equal(decide({ forwarded: 'for=a;proto=https, for=b' }).kind, 'https');
  assert.equal(decide({ forwarded: 'for=198.51.100.7' }).kind, 'http');
  assert.equal(
    decide({ forwarded: 'for=198.51.100.7;proto=https', 'x-forwarded-proto': 'http' }).kind,
    'http',
    'X-Forwarded-Proto wins when both are present'
  );
});

test('decideTransport: a spoofed protocol from an untrusted peer is not believed', () => {
  for (const [peer, trusted] of [
    ['198.51.100.7', null],
    ['198.51.100.7', loopbackProxy],
    ['127.0.0.1', null],
    ['127.0.0.1', lanProxy],
  ]) {
    const decided = decideTransport({
      peer,
      trusted,
      headers: { 'x-forwarded-proto': 'https', forwarded: 'proto=https' },
    });
    assert.deepEqual(decided, { kind: 'http', forwardedProto: null, proxied: true }, peer);
  }
});

test('decideTransport: loopback needs a loopback peer, no proxy headers and a loopback Host', () => {
  // A LAN client naming localhost is still plain HTTP on the network: the Host never makes a
  // request loopback.
  assert.equal(
    decideTransport({ peer: '192.0.2.44', headers: { host: 'localhost:4317' } }).kind,
    'http'
  );
  for (const peer of ['127.0.0.1', '127.8.9.10', '::1', '::ffff:127.0.0.1', '0:0:0:0:0:0:0:1'])
    for (const host of ['127.0.0.1:4317', 'localhost:4317', 'LOCALHOST', '[::1]:4317', '127.9.0.1'])
      assert.deepEqual(
        decideTransport({ peer, headers: { host } }),
        { kind: 'loopback', forwardedProto: null, proxied: false },
        `${peer} ${host}`
      );
  // It can only take loopback away: a loopback peer asking for another name is a proxy on this
  // host that sends no forwarding headers (nginx with proxy_set_header Host $host; and nothing
  // else), relaying browsers from anywhere.
  for (const peer of ['127.0.0.1', '::1', '::ffff:127.0.0.1'])
    for (const host of ['goblin.example', 'goblin.example:443', '192.0.2.10:4317', undefined, ''])
      assert.deepEqual(
        decideTransport({ peer, headers: { host } }),
        { kind: 'http', forwardedProto: null, proxied: false },
        `${peer} ${host}`
      );
  // A proxy on the same host is not the owner's own browser, trusted or not.
  for (const name of forwardingHeaders)
    for (const trusted of [null, loopbackProxy])
      assert.equal(
        decideTransport({ peer: '127.0.0.1', trusted, headers: { [name]: 'x' } }).kind,
        'http',
        name
      );
  assert.equal(decideTransport({ peer: undefined, headers: {} }).kind, 'http');
});

test('isLoopbackHost covers localhost, 127.0.0.0/8 and [::1], with or without a port', () => {
  for (const host of [
    'localhost',
    'LocalHost:4317',
    '127.0.0.1',
    '127.1.2.3:80',
    '[::1]',
    '[::1]:4317',
  ])
    assert.equal(isLoopbackHost(host), true, host);
  for (const host of [
    'goblin.example',
    'localhost.example',
    'example.localhost:4317',
    '128.0.0.1:4317',
    '127.0.0.1.example',
    '::1',
    '[::2]:4317',
    '127.0.0.1:',
    '',
    undefined,
    null,
    4317,
  ])
    assert.equal(isLoopbackHost(host), false, String(host));
});

test('isLoopbackPeer covers 127.0.0.0/8, ::1 and IPv4-mapped loopback only', () => {
  for (const peer of ['127.0.0.1', '127.255.255.254', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1'])
    assert.equal(isLoopbackPeer(peer), true, peer);
  for (const peer of [
    '128.0.0.1',
    '10.0.0.1',
    '::2',
    '::ffff:10.0.0.1',
    'fe80::1%lo0',
    'localhost',
    '',
    null,
    undefined,
    42,
  ])
    assert.equal(isLoopbackPeer(peer), false, String(peer));
});

test('originHost and originScheme read an Origin header, or give null', () => {
  assert.equal(originHost('https://Goblin.Example'), 'goblin.example');
  assert.equal(originHost('http://127.0.0.1:4317'), '127.0.0.1:4317');
  assert.equal(originHost('https://goblin.example:443'), 'goblin.example', 'default port dropped');
  assert.equal(originHost('http://[::1]:4317'), '[::1]:4317');
  for (const bad of ['null', '', 'not a url', undefined, null, 7]) {
    assert.equal(originHost(bad), null, String(bad));
    assert.equal(originScheme(bad), null, String(bad));
  }
  assert.equal(originScheme('https://goblin.example'), 'https:');
  assert.equal(originScheme('HTTP://goblin.example'), 'http:');
});

test('browserContext: Sec-Fetch-Site or X-Goblin-Client, never Sec-Fetch-Mode alone', () => {
  assert.equal(browserContext({ 'sec-fetch-site': 'same-origin' }), true);
  assert.equal(browserContext({ 'sec-fetch-site': 'cross-site' }), true);
  assert.equal(browserContext({ 'x-goblin-client': 'web/abc' }), true);
  assert.equal(browserContext({ 'x-goblin-client': '' }), true);
  // Node's fetch sends sec-fetch-mode; scripts use Node's fetch.
  assert.equal(browserContext({ 'sec-fetch-mode': 'cors' }), false);
  assert.equal(browserContext({}), false);
  assert.equal(browserContext(), false);
});
