// test/helpers/tls.mjs encodes certificates by hand. A certificate OpenSSL refuses fails
// https.createServer() in whichever suite drew it (signin's nginx tests, the SMTP fake), so a
// rare encoding bug shows up as a flaky failure somewhere unrelated; this file catches it here.
import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import { selfSignedCertificate } from './helpers/tls.mjs';

test('selfSignedCertificate serials are positive, minimal DER that OpenSSL accepts', () => {
  // The serial is random, so one draw proves little. The pattern check fails on the first few
  // draws if the first byte leaves 0x40-0x7f; the createServer() check covers any other
  // encoding OpenSSL refuses (the old mask's one in 256 would get through 3000 draws fewer than
  // once in 100,000 runs).
  for (let i = 0; i < 3000; i++) {
    const pair = selfSignedCertificate();
    assert.doesNotThrow(() => https.createServer(pair), `certificate ${i}`);
    assert.match(new X509Certificate(pair.cert).serialNumber, /^[4-7][0-9A-F]{23}$/);
  }
});
