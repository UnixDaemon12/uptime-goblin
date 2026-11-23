// Session secrets and ids (sessions spec §5.9).
//
// - The cookie value is `v1.` + 32 random bytes in base64url without padding (43 characters).
//   Only the SHA-256 of those bytes is stored (sessions.token_hash): a copy of control.sqlite or
//   of a snapshot signs nobody in. A slow hash is not needed: the secret has 256 bits.
// - The public id, `s_` + 12 random bytes (16 characters), names a session in the API and the
//   sessions list; it is generated only here, so a client can never choose its own session
//   (fixation).
import { randomBytes, randomInt, createHash } from 'node:crypto';
import { displayAlphabet, checkSymbol } from './display-code.mjs';

const valuePattern = /^v1\.[A-Za-z0-9_-]{43}$/;
const idPattern = /^s_[A-Za-z0-9_-]{16}$/;

const digest = bytes => createHash('sha256').update(bytes).digest('hex');

/** A new session: {id, value (the cookie value, secret), tokenHash (what is stored)}. */
export function newSession() {
  const secret = randomBytes(32);
  try {
    return {
      id: 's_' + randomBytes(12).toString('base64url'),
      value: 'v1.' + secret.toString('base64url'),
      tokenHash: digest(secret),
    };
  } finally {
    secret.fill(0);
  }
}

/**
 * The stored hash of a cookie value, or null for anything that is not exactly a value
 * newSession() could have made (a canonical encoding of 32 bytes), so a malformed cookie never
 * reaches the database.
 */
export function sessionTokenHash(value) {
  if (typeof value !== 'string' || !valuePattern.test(value)) return null;
  const encoded = value.slice(3);
  const bytes = Buffer.from(encoded, 'base64url');
  try {
    // 43 characters carry 258 bits; only the encoding whose last 2 bits are zero is canonical.
    if (bytes.length !== 32 || bytes.toString('base64url') !== encoded) return null;
    return digest(bytes);
  } finally {
    bytes.fill(0);
  }
}

/** Whether `id` has the shape of a public session id (checked before any lookup). */
export const isSessionId = id => typeof id === 'string' && idPattern.test(id);

// One-time display codes (B6 design §7.1). 25 symbols of Crockford base32 (125 bits) and a check
// symbol, printed as five groups of five and the check: 7KQ4M-2XH9D-RT6WN-PB3CZ-F8YJ0-K. Only
// the SHA-256 of the 25 data symbols is stored; the code itself lives in goblin-admin's memory
// and on its stdout.
export { displayAlphabet };
const displaySymbols = 25;
const displayIdPattern = /^d_[A-Za-z0-9_-]{16}$/;
const maxDisplayInput = 64;

const displayDigest = data =>
  createHash('sha256').update(`orbit-display-code-v1\0${data}`).digest('hex');

/** A new display code: {id, code (printed form, secret), codeHash (what is stored)}. */
export function newDisplayCode() {
  let data = '';
  for (let i = 0; i < displaySymbols; i++) data += displayAlphabet[randomInt(0, 32)];
  const symbols = data + checkSymbol(data);
  return {
    id: 'd_' + randomBytes(12).toString('base64url'),
    code: symbols.match(/.{1,5}/g).join('-'),
    codeHash: displayDigest(data),
  };
}

/**
 * The stored hash of a typed display code, or null for anything that is not one: at most 64
 * characters; NFKC and upper case; spaces and hyphens dropped; I and L read as 1, O as 0; then
 * exactly 26 symbols whose last is the check symbol of the others. The page runs the same check.
 */
export function displayCodeHash(input) {
  if (typeof input !== 'string' || input.length > maxDisplayInput) return null;
  const symbols = input
    .normalize('NFKC')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
  if (symbols.length !== displaySymbols + 1) return null;
  for (const symbol of symbols) if (!displayAlphabet.includes(symbol)) return null;
  const data = symbols.slice(0, displaySymbols);
  return checkSymbol(data) === symbols[displaySymbols] ? displayDigest(data) : null;
}

/** Whether `id` has the shape of a display id (d_ and 12 random bytes). */
export const isDisplayId = id => typeof id === 'string' && displayIdPattern.test(id);
