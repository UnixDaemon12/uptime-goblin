// A throwaway self-signed TLS certificate for tests that need an HTTPS endpoint (a reverse proxy
// that ends TLS in front of Uptime Goblin, as nginx does on the owner's host), built with node:crypto
// only: no openssl binary and no npm package. The key pair is generated per call and never
// written to disk, so no private key is committed to the repository.
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';

// DER encoding (X.690) of the few ASN.1 types a certificate needs.
function length(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let value = n; value > 0; value >>= 8) bytes.unshift(value & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, ...content) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const sequence = (...items) => tlv(0x30, ...items);
const set = (...items) => tlv(0x31, ...items);
function integer(bytes) {
  // Positive: a leading 0 when the top bit is set.
  return tlv(0x02, bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
}
function oid(dotted) {
  const [first, second, ...rest] = dotted.split('.').map(Number);
  const bytes = [40 * first + second];
  for (const value of rest) {
    const chunk = [value & 0x7f];
    for (let v = value >> 7; v > 0; v >>= 7) chunk.unshift(0x80 | (v & 0x7f));
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}
const utf8 = text => tlv(0x0c, Buffer.from(text, 'utf8'));
// UTCTime (YYMMDDHHMMSSZ): valid for dates before 2050, which these certificates never reach.
const time = date =>
  tlv(0x17, Buffer.from(date.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z', 'ascii'));
const bitString = bytes => tlv(0x03, Buffer.from([0]), bytes);
const octetString = bytes => tlv(0x04, bytes);
const explicit = (number, content) => tlv(0xa0 | number, content);

const ecdsaWithSha256 = sequence(oid('1.2.840.10045.4.3.2'));
const name = commonName => sequence(set(sequence(oid('2.5.4.3'), utf8(commonName))));
const pem = (label, der) =>
  `-----BEGIN ${label}-----\n${der
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;

/**
 * A self-signed P-256 certificate for `hosts` (DNS names; IPv4 literals become IP addresses),
 * valid from an hour ago for `days` days. Resolves `{cert, key}` as PEM strings, the form
 * `https.createServer()` takes. Browsers do not trust it: a test that opens it in Chrome tells
 * the browser to ignore certificate errors (Security.setIgnoreCertificateErrors).
 */
export function selfSignedCertificate({ hosts = ['localhost', '127.0.0.1'], days = 2 } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serial = randomBytes(12);
  // Positive and minimally encoded: a first byte of 0x40-0x7f is never zero and never has its
  // top bit set. A zero first byte before one below 0x80 is non-minimal DER, which OpenSSL
  // refuses as illegal padding; the old mask (& 0x7f) drew one about once in 256 certificates.
  serial[0] = (serial[0] & 0x3f) | 0x40;
  const now = Date.now();
  const alternativeNames = hosts.map(host =>
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
      ? tlv(0x87, Buffer.from(host.split('.').map(Number)))
      : tlv(0x82, Buffer.from(host, 'ascii'))
  );
  const extensions = explicit(
    3,
    sequence(
      // subjectAltName: what a browser matches the address against.
      sequence(oid('2.5.29.17'), octetString(sequence(...alternativeNames))),
      // basicConstraints: an end-entity certificate, not a CA.
      sequence(oid('2.5.29.19'), octetString(sequence()))
    )
  );
  const tbs = sequence(
    explicit(0, integer(Buffer.from([2]))),
    integer(serial),
    ecdsaWithSha256,
    name(hosts[0]),
    sequence(time(new Date(now - 3600e3)), time(new Date(now + days * 86400e3))),
    name(hosts[0]),
    publicKey.export({ type: 'spki', format: 'der' }),
    extensions
  );
  const signature = sign('sha256', tbs, privateKey);
  const certificate = sequence(tbs, ecdsaWithSha256, bitString(signature));
  return {
    cert: pem('CERTIFICATE', certificate),
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}
