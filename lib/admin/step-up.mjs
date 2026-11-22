// Same-request password envelope ownership for future ordered pipeline integration.
// This does not authorize a route, implement lockout, or replace identity.verifyPassword.
import { InputError } from '../config.mjs';
import { parseJson } from '../http/body.mjs';
import { adminError } from './errors.mjs';
import { maxPasswordBytes } from '../identity/password.mjs';

/**
 * Consume a bounded request Buffer, remove stepUp from the parsed handler body, and lend its
 * password bytes to one awaited operation. Raw bytes are cleared immediately after parsing;
 * password bytes are cleared on every exit. The operation must not retain/copy the password.
 * JavaScript strings cannot be zeroed; no promise is made to erase engine-internal copies.
 * The reader still owns/clears earlier input chunks, including oversize/disconnect paths.
 * Authentication, CSRF, permission, locks and credential-safe gates MUST run before calling.
 */
export async function withStepUpPassword(raw, operation) {
  if (!Buffer.isBuffer(raw)) throw new TypeError('Step-up requires a request buffer');
  if (typeof operation !== 'function') {
    raw.fill(0);
    throw new TypeError('Step-up requires an operation');
  }
  let passwordBytes;
  try {
    let body;
    try {
      try {
        body = parseJson(raw);
      } catch (error) {
        // General parser diagnostics can echo member names. A password-bearing body
        // gets no request-derived diagnostic text, even if a secret was used as a key.
        if (error instanceof InputError) throw new InputError('Expected valid JSON');
        throw error;
      }
    } finally {
      raw.fill(0);
    }
    const envelope =
      body !== null && typeof body === 'object' && !Array.isArray(body) ? body.stepUp : undefined;
    if (body !== null && typeof body === 'object') delete body.stepUp;
    const password =
      envelope !== null && typeof envelope === 'object' && !Array.isArray(envelope)
        ? envelope.password
        : undefined;
    if (
      typeof password !== 'string' ||
      !password.isWellFormed() ||
      Buffer.byteLength(password, 'utf8') < 1 ||
      Buffer.byteLength(password, 'utf8') > maxPasswordBytes
    )
      throw adminError('step_up_required');
    passwordBytes = Buffer.from(password, 'utf8');
    return await operation(passwordBytes, body);
  } finally {
    passwordBytes?.fill(0);
    raw.fill(0);
  }
}
