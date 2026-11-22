// What the HTTP layer and identity share about credentials: the error every sign-in refusal is,
// and the 1.4.3 parser for a legacy HTTP Basic header. Passwords, sessions and their storage
// live in lib/identity/ (1.5); this file keeps no state.

/**
 * A refusal the client can act on: `status` is the HTTP status and `code` (1.5) names the case
 * for the web app and scripts (lib/identity/errors.mjs lists every code). Errors created
 * without a code (older call sites) are answered with their message only.
 */
export class AuthError extends Error {
  constructor(message, status = 400, code) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    if (code !== undefined) this.code = code;
  }
}

/**
 * The credential bytes of an `Authorization: Basic` header for the built-in admin, or null.
 * Only `admin:<password>` in canonical base64 of valid UTF-8, at most 1024 password bytes, is
 * accepted, exactly as 1.4.3 did, so a script that signed in then signs in now. The caller owns
 * the returned buffer and zero-fills it when done; a refused value is zero-filled here.
 */
export function credential(header) {
  if (
    typeof header !== 'string' ||
    header.length > 2048 ||
    !/^Basic [A-Za-z0-9+/]+={0,2}$/i.test(header)
  )
    return null;
  const encoded = header.slice(6),
    decoded = Buffer.from(encoded, 'base64');
  if (
    decoded.toString('base64') !== encoded ||
    decoded.length > 1030 ||
    decoded.subarray(0, 6).toString() !== 'admin:'
  ) {
    decoded.fill(0);
    return null;
  }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(decoded);
  } catch {
    decoded.fill(0);
    return null;
  }
  return decoded;
}
