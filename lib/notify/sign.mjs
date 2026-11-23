// Webhook signing (roadmap §2.10, G5; delivery spec D7, §5.4; public keys by the maintainer's decision of
// 2026-11-12, suite design D8). Each request carries
//   X-Goblin-Signature: t=<unix seconds>,v1a=<key id>:<hex Ed25519 signature of
//                      "<delivery id>.<t>.<body>">
// where the delivery id is the request's X-Goblin-Delivery value and the body is the exact bytes
// sent. Signing the delivery id too means a captured request cannot be replayed under a new id to
// get past a receiver that drops repeats by X-Goblin-Delivery (Standard Webhooks signs
// id.timestamp.body the same way, and names its Ed25519 signatures v1a). Receivers should reject
// a timestamp more than 5 minutes from their own clock (verifyWebhookSignature does). During a
// rotation a request carries one v1a per key, the current one first.
//
// Uptime Goblin keeps the private key (PKCS#8 PEM, sealed with the keyring); receivers verify with the
// public key, which is not a secret. The key id is the first 16 hexadecimal digits of the
// SHA-256 of the raw 32-byte public key, so a receiver that holds two public keys during a
// rotation can pick the right one.
import {
  KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';

export const SIGNATURE_HEADER = 'X-Goblin-Signature';
export const DELIVERY_HEADER = 'X-Goblin-Delivery';
// Their names before the rename to Uptime Goblin (lib/legacy-names.mjs): each request carries them
// too, with the same values, in 1.5 and 1.6, so receivers written for Orbit keep verifying.
export const LEGACY_SIGNATURE_HEADER = 'X-Orbit-Signature';
export const LEGACY_DELIVERY_HEADER = 'X-Orbit-Delivery';
export const SIGNATURE_TOLERANCE_MS = 5 * 60 * 1000;
/** The signature's name in X-Goblin-Signature: Ed25519 (Standard Webhooks' asymmetric v1a). */
export const SIGNATURE_SCHEME = 'v1a';
export const SIGNING_ALGORITHM = 'Ed25519';

const DELIVERY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const ENTRY = /^([0-9a-f]{16}):([0-9a-f]{128})$/;

/** A new signing key: an Ed25519 private key as PKCS#8 PEM text (what Uptime Goblin seals). */
export function generateSigningKey() {
  return generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
}

/**
 * The private KeyObject of `key`: a KeyObject, or the PKCS#8 PEM text generateSigningKey() makes
 * (exactly, with nothing around it). Anything else (an HMAC secret of an earlier pre-release, a
 * public key, another algorithm) is refused with a RangeError that never quotes the value.
 */
export function validateSigningKey(key) {
  let object = null;
  try {
    if (key instanceof KeyObject) object = key;
    else if (typeof key === 'string' && key.length <= 1024) {
      object = createPrivateKey({ key, format: 'pem' });
      if (object.export({ type: 'pkcs8', format: 'pem' }) !== key) object = null;
    }
  } catch {
    object = null;
  }
  if (object?.type !== 'private' || object.asymmetricKeyType !== 'ed25519')
    throw new RangeError('The webhook signing key must be an Ed25519 private key (PKCS#8 PEM).');
  return object;
}

/** Whether `key` is a signing key validateSigningKey() accepts. */
export function isSigningKey(key) {
  try {
    validateSigningKey(key);
    return true;
  } catch {
    return false;
  }
}

/**
 * `text` rewritten as generateSigningKey() writes it, when it is PEM text that node:crypto reads
 * as an Ed25519 private key in another form (white space around it, CRLF line ends): the same
 * key. Null for anything else (an HMAC secret, a public key, another algorithm, text over 16 KiB);
 * never throws, and never quotes the value.
 */
export function normalizeSigningKey(text) {
  if (typeof text !== 'string' || text === '' || text.length > 16384) return null;
  try {
    const object = createPrivateKey({ key: text.trim(), format: 'pem' });
    if (object.type !== 'private' || object.asymmetricKeyType !== 'ed25519') return null;
    return object.export({ type: 'pkcs8', format: 'pem' });
  } catch {
    return null;
  }
}

const rawPublicKey = publicKey => Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
const keyIdOfRaw = raw => createHash('sha256').update(raw).digest('hex').slice(0, 16);

/**
 * The public half of a signing key, all of it public material:
 * {algorithm: 'Ed25519', keyId, publicKey (SPKI PEM), publicKeyRaw (base64 of the 32 bytes)}.
 */
export function publicSigningKey(privateKey) {
  const publicKey = createPublicKey(validateSigningKey(privateKey));
  const raw = rawPublicKey(publicKey);
  return {
    algorithm: SIGNING_ALGORITHM,
    keyId: keyIdOfRaw(raw),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    publicKeyRaw: raw.toString('base64'),
  };
}

// A receiver's public key: a KeyObject (a private one gives its public half), SPKI PEM text, or
// the raw 32 bytes (a Buffer). Throws TypeError for anything that is not an Ed25519 key.
function verifyingKey(key) {
  let object;
  try {
    if (key instanceof KeyObject) object = key.type === 'public' ? key : createPublicKey(key);
    else if (Buffer.isBuffer(key) && key.length === 32)
      object = createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: key.toString('base64url') },
        format: 'jwk',
      });
    else object = createPublicKey(key);
  } catch {
    object = null;
  }
  if (object?.asymmetricKeyType !== 'ed25519')
    throw new TypeError('Verifying a webhook signature needs the Ed25519 public key.');
  return object;
}

function deliveryIdOf(deliveryId) {
  if (typeof deliveryId !== 'string' || !DELIVERY_ID.test(deliveryId))
    throw new TypeError('A webhook signature needs the delivery id: 1-64 of A-Z, a-z, 0-9, _ or -');
  return deliveryId;
}

// The signed bytes: "<delivery id>.<t>." and the body exactly as sent.
const signedBytes = (deliveryId, timestamp, body) =>
  Buffer.concat([
    Buffer.from(`${deliveryId}.${timestamp}.`, 'utf8'),
    Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'),
  ]);

/** The X-Goblin-Signature value for `body` (the exact bytes sent) at `nowMs`. */
export function signWebhook(privateKey, body, { nowMs = Date.now(), deliveryId } = {}) {
  return signWebhookAll([privateKey], body, { nowMs, deliveryId });
}

/**
 * The X-Goblin-Signature value with one v1a per private key (the current one first): during a
 * rotation a receiver that still has only the previous public key keeps verifying.
 */
export function signWebhookAll(privateKeys, body, { nowMs = Date.now(), deliveryId } = {}) {
  const id = deliveryIdOf(deliveryId);
  const keys = [...(privateKeys ?? [])].map(validateSigningKey);
  if (!keys.length) throw new RangeError('At least one signing key is needed.');
  const timestamp = Math.floor(nowMs / 1000);
  const data = signedBytes(id, timestamp, body);
  return [
    `t=${timestamp}`,
    ...keys.map(key => {
      const keyId = keyIdOfRaw(rawPublicKey(createPublicKey(key)));
      return `${SIGNATURE_SCHEME}=${keyId}:${sign(null, data, key).toString('hex')}`;
    }),
  ].join(',');
}

/**
 * For receivers and tests: {ok: true} when `header` holds a v1a signature of `body` and
 * `deliveryId` made with the private half of `publicKey` (SPKI PEM, a KeyObject or the raw 32
 * bytes) within `toleranceMs` of `nowMs`, otherwise {ok: false, reason} (malformed, expired or
 * mismatch). Only the v1a values whose key id is this key's are checked, so a request signed
 * with an old and a new key during a rotation verifies with either public key.
 */
export function verifyWebhookSignature(
  publicKey,
  body,
  header,
  { deliveryId, nowMs = Date.now(), toleranceMs = SIGNATURE_TOLERANCE_MS } = {}
) {
  const key = verifyingKey(publicKey);
  if (typeof deliveryId !== 'string' || !DELIVERY_ID.test(deliveryId))
    return { ok: false, reason: 'malformed' };
  const parts = String(header ?? '')
    .split(',')
    .map(part => {
      const at = part.indexOf('=');
      return at < 1 ? [] : [part.slice(0, at).trim(), part.slice(at + 1).trim()];
    })
    .filter(pair => pair.length === 2);
  const stamps = parts.filter(([k]) => k === 't').map(([, v]) => v);
  const signatures = parts.filter(([k]) => k === SIGNATURE_SCHEME).map(([, v]) => v);
  if (stamps.length !== 1 || !/^\d{1,12}$/.test(stamps[0]) || !signatures.length)
    return { ok: false, reason: 'malformed' };
  const timestamp = Number(stamps[0]);
  if (Math.abs(nowMs - timestamp * 1000) > toleranceMs) return { ok: false, reason: 'expired' };
  const keyId = keyIdOfRaw(rawPublicKey(key)),
    data = signedBytes(deliveryId, timestamp, body);
  for (const signature of signatures) {
    const entry = ENTRY.exec(signature);
    if (!entry || entry[1] !== keyId) continue;
    if (verify(null, data, key, Buffer.from(entry[2], 'hex'))) return { ok: true };
  }
  return { ok: false, reason: 'mismatch' };
}
