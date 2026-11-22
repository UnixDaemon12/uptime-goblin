import test from 'node:test';
import assert from 'node:assert/strict';
import { credentialSafe } from '../../lib/admin/credential-safe.mjs';
const req = (headers, peer = '127.0.0.1') => ({ headers, socket: { remoteAddress: peer } });
const interactive = transport => ({ kind: 'interactive', session: { transport } });
const basic = { kind: 'basic' };
const local = { host: 'localhost:4317', origin: 'http://localhost:4317' };
const secure = {
  host: 'goblin.example',
  origin: 'https://goblin.example',
  'x-forwarded-proto': 'https',
};

test('safe loopback and trusted HTTPS admit Basic without inventing a session transport', () => {
  for (const access of [basic, interactive('loopback'), interactive('https')])
    assert.equal(credentialSafe({ req: req(local), access }), true);
  for (const access of [basic, interactive('https')])
    assert.equal(
      credentialSafe({ req: req(secure), access, trusted: peer => peer === '127.0.0.1' }),
      true
    );
  assert.equal(credentialSafe({ req: req(secure), access: basic }), false);
});

test('plain HTTP and unverified Compose/private-path claims never allow creation', () => {
  for (const access of [basic, interactive('http'), interactive('https')]) {
    for (const peer of ['192.0.2.4', '198.51.100.1'])
      assert.equal(
        credentialSafe({
          req: req(local, peer),
          access,
          plainHttp: { source: 'compose' },
          credentialSafe: true,
        }),
        false
      );
    assert.equal(
      credentialSafe({
        req: req({ host: 'goblin.example', origin: 'http://goblin.example' }),
        access,
      }),
      false
    );
  }
});

test('headerless relays, contradictory protocols and nonloopback pages fail closed', () => {
  for (const headers of [
    { ...local, origin: 'http://goblin.example' },
    { ...secure, origin: 'http://goblin.example' },
    { ...secure, forwarded: 'proto=http' },
    { ...secure, forwarded: 'proto=https' },
    { ...local, 'x-forwarded-for': '192.0.2.1' },
    { ...local, origin: 'https://evil.example' },
  ])
    assert.equal(
      credentialSafe({
        req: req(headers),
        access: basic,
        trusted: () => true,
        configuredHosts: new Set(['goblin.example']),
      }),
      false
    );
});

test('interactive creation requires safe recorded session transport; other principals denied', () => {
  for (const access of [
    interactive('http'),
    interactive(undefined),
    { kind: 'kiosk' },
    { kind: 'token' },
    null,
  ]) {
    assert.equal(credentialSafe({ req: req(local), access }), false);
    assert.equal(credentialSafe({ req: req(secure), access, trusted: () => true }), false);
  }
});

test('missing, malformed and noncanonical Origin values are not safe evidence', () => {
  for (const origin of [
    undefined,
    '',
    'null',
    'file://localhost',
    'http://localhost:4317/path',
    'http://a@localhost:4317',
    'http://localhost:4317#x',
    ['http://localhost:4317'],
  ])
    assert.equal(credentialSafe({ req: req({ ...local, origin }), access: basic }), false);
});
