// Every refusal identity, the HTTP layer and the web app share (sessions spec §5.3). Each is an
// AuthError with an HTTP `status` and a stable `code`: the web app picks its own longer text by
// code, scripts branch on it, and the message is what a client without that knowledge shows.
//
//   throw identityError('invalid_credentials', { variant: 'login' });
//   throw identityError('busy', { scope: 'queue' });            // counted by http only for 'client'
//   throw identityError('locked', { retryAfter: 42 });           // seconds, sent as Retry-After
//
// No message contains a password, hash, salt, cookie value or path. This file is a Phase 0
// contract (frozen): lanes change it only together, through the integrator.
import { AuthError } from '../auth.mjs';

const code = (status, messages, retryAfter) =>
  Object.freeze({
    status,
    messages: Object.freeze(typeof messages === 'string' ? { default: messages } : messages),
    ...(retryAfter === undefined ? {} : { retryAfter }),
  });

/** code → {status, messages: {variant: text}, retryAfter?} (seconds, for 429 and 503). */
export const errorCodes = Object.freeze({
  signin_required: code(401, 'Sign in to Uptime Goblin.'),
  session_expired: code(401, 'Your session has ended. Sign in again.'),
  invalid_credentials: code(401, {
    login: 'The login name or password is incorrect.',
    basic: 'Sign in to Uptime Goblin.',
  }),
  multiple_credentials: code(401, 'Send one credential per request.'),
  basic_disabled: code(401, 'HTTP Basic sign-in is turned off (GOBLIN_LEGACY_BASIC=0).'),
  // `display_code`: a wall display's sign-in, whose code Uptime Goblin cancelled (B6 design §7.4).
  https_required: code(403, {
    default:
      'Sign-in needs HTTPS, or a browser on this computer. Open Uptime Goblin through its HTTPS address. GOBLIN_INSECURE_HTTP_SESSIONS=1 allows sign-in over plain HTTP, but the password and the sign-in cookie then cross the network unencrypted: set it only on a network you trust.',
    display_code:
      "A wall display signs in over HTTPS, or on the Uptime Goblin computer. If this was a valid display code, it crossed the network unencrypted and Uptime Goblin cancelled it: open Uptime Goblin's HTTPS address on this display and ask for a new code.",
  }),
  proxy_proto_missing: code(403, {
    default:
      'Your browser uses HTTPS, but the reverse proxy does not tell Uptime Goblin so. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.',
    display_code:
      'Your browser uses HTTPS, but the reverse proxy does not tell Uptime Goblin so. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed. If this was a valid display code, Uptime Goblin cancelled it: create a new one once the proxy is fixed.',
  }),
  proxy_proto_mismatch: code(403, {
    default:
      "Your browser uses plain HTTP (http://), but the reverse proxy tells Uptime Goblin the connection is HTTPS, so the browser would drop Uptime Goblin's secure sign-in cookie. Make the proxy send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;), or open Uptime Goblin at its https:// address.",
    display_code:
      "Your browser uses plain HTTP (http://), but the reverse proxy tells Uptime Goblin the connection is HTTPS, so the browser would drop Uptime Goblin's secure sign-in cookie. Make the proxy send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;), or open Uptime Goblin at its https:// address. If this was a valid display code, Uptime Goblin cancelled it: create a new one once the proxy is fixed.",
  }),
  // A display code that redeems nothing: unknown, expired, used or cancelled (B6 design §7.4).
  display_code_invalid: code(
    401,
    'The display code is not valid. It may have expired (a code lasts 10 minutes), been used already, been cancelled, or been mistyped. Ask an admin for a new one: goblin-admin display code on the Uptime Goblin host. If you typed it correctly and this display did not sign in, look for a wall display you do not recognise under Configure → Account → Sessions.'
  ),
  // The 1.4.x text, unchanged: scripts and the old web app match it. `read`: a session cookie
  // another site's page made the browser send with a read (the pipeline refuses it unread).
  cross_origin: code(403, {
    default: 'Cross-origin changes are not allowed',
    read: 'Requests from other sites cannot use your Uptime Goblin session.',
  }),
  forbidden: code(403, 'You do not have permission to do this.'),
  current_password_incorrect: code(403, 'The current password is incorrect.'),
  // A session cannot end one that signed in after it: a cookie (from a lost device, or copied)
  // must not be able to end the sign-ins that prove the password again.
  session_newer: code(
    403,
    'That session signed in after this one, so only a newer sign-in can end it. If you do not recognise it, change your password, which signs out every other session; otherwise sign out here and sign in again first.'
  ),
  invalid_request: code(400, {
    login: 'Enter your login name and password.',
    change: 'Enter your current password, a new password and its confirmation.',
    display:
      'A wall display signs in with a display code only: send code and display: true, without a login name, password or remember.',
    display_code: 'That is not a display code. Check it and type it again.',
  }),
  password_invalid: code(
    400,
    'Use at least 12 characters and at most 1024 UTF-8 bytes for the new password.'
  ),
  password_mismatch: code(400, 'The password and confirmation do not match.'),
  not_found: code(404, 'Session not found'),
  // http passes the seconds left; 60 is the global lock's answer.
  locked: code(429, 'Too many failed sign-in attempts. Wait before trying again.', 60),
  busy: code(
    429,
    {
      client: 'Too many sign-in attempts at once. Wait before trying again.',
      queue: 'Sign-in is busy. Please wait a moment and try again.',
    },
    5
  ),
  change_in_progress: code(
    429,
    'A password change is already in progress. Please wait and try again.',
    5
  ),
  // `signout`: a sign-out (or "Sign out other devices") whose delete failed. The sessions are
  // refused at once, but only until Uptime Goblin restarts, so the answer must not look like success.
  // Trying again deletes them, for the browser's own Sign out too, which keeps its cookie for
  // that (§20 H1), as for a session's Sign out and "Sign out other devices".
  storage_full: code(
    503,
    {
      default:
        "Uptime Goblin's disk is full, so it cannot save your sign-in or password change. Anyone already signed in stays signed in. Free some space on the Uptime Goblin host, then try again.",
      signout:
        "Uptime Goblin's disk is full, so it could not record this sign-out. Uptime Goblin refuses the signed-out sessions now and keeps trying to remove them, but a restart before it succeeds would accept them again. Free some space on the Uptime Goblin host, then try again.",
    },
    30
  ),
});

/**
 * The AuthError for `code`. `extra.variant` picks the message where a code has several (for
 * `busy`, `extra.scope` does); `extra.retryAfter` overrides the table's default and
 * `extra.scope` stays on the error (http counts only `busy` with scope 'client').
 */
export function identityError(name, extra = {}) {
  const entry = errorCodes[name];
  if (!entry) throw new TypeError(`Unknown identity error code ${JSON.stringify(name)}`);
  const { variant, ...kept } = extra;
  const key = variant ?? (name === 'busy' ? extra.scope : undefined);
  const messages = entry.messages;
  const message = (key !== undefined && messages[key]) || Object.values(messages)[0];
  return Object.assign(
    new AuthError(message, entry.status, name),
    entry.retryAfter === undefined ? {} : { retryAfter: entry.retryAfter },
    kept
  );
}
