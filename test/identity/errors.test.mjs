// The shared error codes (lib/identity/errors.mjs, sessions spec §5.3).
import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthError } from '../../lib/auth.mjs';
import { errorCodes, identityError } from '../../lib/identity/errors.mjs';

test('every §5.3 code has its status, messages and Retry-After default', () => {
  const table = {
    signin_required: [401, ['Sign in to Uptime Goblin.']],
    session_expired: [401, ['Your session has ended. Sign in again.']],
    invalid_credentials: [
      401,
      ['The login name or password is incorrect.', 'Sign in to Uptime Goblin.'],
    ],
    multiple_credentials: [401, ['Send one credential per request.']],
    basic_disabled: [401, ['HTTP Basic sign-in is turned off (GOBLIN_LEGACY_BASIC=0).']],
    https_required: [403],
    proxy_proto_missing: [403],
    proxy_proto_mismatch: [403],
    cross_origin: [
      403,
      [
        'Cross-origin changes are not allowed',
        'Requests from other sites cannot use your Uptime Goblin session.',
      ],
    ],
    forbidden: [403, ['You do not have permission to do this.']],
    current_password_incorrect: [403, ['The current password is incorrect.']],
    session_newer: [
      403,
      [
        'That session signed in after this one, so only a newer sign-in can end it. If you do not recognise it, change your password, which signs out every other session; otherwise sign out here and sign in again first.',
      ],
    ],
    invalid_request: [
      400,
      [
        'Enter your login name and password.',
        'Enter your current password, a new password and its confirmation.',
        'A wall display signs in with a display code only: send code and display: true, without a login name, password or remember.',
        'That is not a display code. Check it and type it again.',
      ],
    ],
    display_code_invalid: [401],
    password_invalid: [
      400,
      ['Use at least 12 characters and at most 1024 UTF-8 bytes for the new password.'],
    ],
    password_mismatch: [400, ['The password and confirmation do not match.']],
    not_found: [404, ['Session not found']],
    locked: [429, ['Too many failed sign-in attempts. Wait before trying again.'], 60],
    busy: [
      429,
      [
        'Too many sign-in attempts at once. Wait before trying again.',
        'Sign-in is busy. Please wait a moment and try again.',
      ],
      5,
    ],
    change_in_progress: [
      429,
      ['A password change is already in progress. Please wait and try again.'],
      5,
    ],
    storage_full: [503, undefined, 30],
  };
  assert.deepEqual(Object.keys(errorCodes).sort(), Object.keys(table).sort());
  for (const [code, [status, messages, retryAfter]] of Object.entries(table)) {
    const entry = errorCodes[code];
    assert.equal(entry.status, status, code);
    if (messages) assert.deepEqual(Object.values(entry.messages), messages, code);
    assert.equal(entry.retryAfter, retryAfter, code);
    assert.ok(Object.isFrozen(entry) && Object.isFrozen(entry.messages), code);
    // No message carries a placeholder, a secret or a path.
    for (const message of Object.values(entry.messages))
      assert.doesNotMatch(message, /<|\$\{|\/var\/|\/etc\/|auth\.json\b/, code);
  }
  assert.match(errorCodes.https_required.messages.default, /^Sign-in needs HTTPS/);
  assert.match(errorCodes.proxy_proto_missing.messages.default, /X-Forwarded-Proto \$scheme/);
  assert.match(errorCodes.proxy_proto_mismatch.messages.default, /plain HTTP \(http:\/\/\)/);
  assert.match(errorCodes.storage_full.messages.default, /^Uptime Goblin's disk is full/);
  // A wall display's refusals for its transport say that its code was cancelled (B6 design §7.4).
  for (const name of ['https_required', 'proxy_proto_missing', 'proxy_proto_mismatch'])
    assert.match(errorCodes[name].messages.display_code, /Uptime Goblin cancelled it/, name);
  assert.match(errorCodes.display_code_invalid.messages.default, /goblin-admin display code/);
  assert.ok(Object.isFrozen(errorCodes));
  // signin_unavailable answered a sign-in while no admin password was set; Uptime Goblin no longer
  // starts without one, so no code says so.
  assert.equal('signin_unavailable' in errorCodes, false);
  assert.throws(() => identityError('signin_unavailable'), TypeError);
});

test('identityError picks the variant, keeps scope and retryAfter, and is an AuthError', () => {
  const login = identityError('invalid_credentials', { variant: 'login' });
  assert.ok(login instanceof AuthError);
  assert.equal(login.status, 401);
  assert.equal(login.code, 'invalid_credentials');
  assert.equal(login.message, 'The login name or password is incorrect.');
  assert.equal(login.retryAfter, undefined);
  assert.equal('variant' in login, false);
  assert.equal(
    identityError('invalid_credentials', { variant: 'basic' }).message,
    'Sign in to Uptime Goblin.'
  );
  // Without a variant, the first message.
  assert.equal(
    identityError('invalid_credentials').message,
    errorCodes.invalid_credentials.messages.login
  );

  const client = identityError('busy', { scope: 'client' });
  assert.equal(client.message, 'Too many sign-in attempts at once. Wait before trying again.');
  assert.equal(client.scope, 'client');
  assert.equal(client.retryAfter, 5);
  const queue = identityError('busy', { scope: 'queue' });
  assert.equal(queue.message, 'Sign-in is busy. Please wait a moment and try again.');
  assert.equal(queue.scope, 'queue');

  assert.equal(identityError('locked').retryAfter, 60);
  assert.equal(identityError('locked', { retryAfter: 42 }).retryAfter, 42);
  assert.equal(identityError('storage_full').retryAfter, 30);
  assert.equal(identityError('storage_full').status, 503);
  assert.throws(() => identityError('no_such_code'), TypeError);
});
