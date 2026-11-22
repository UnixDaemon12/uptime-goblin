// The signed-in person's own account: their password and their sessions (sessions spec §6.10).
// Until accounts exist (1.6) that is the built-in admin.
import { identityError } from '../../identity/errors.mjs';
import { json } from '../body.mjs';
import { expiredLegacySessionCookies, readCookies, sessionCookie } from '../cookies.mjs';
import { globallyLocked } from '../pipeline.mjs';
import { signOut } from './auth.mjs';

/** The members of a password change request (lib/identity/password.mjs checkNewPassword). */
const passwordChangeFields = Object.freeze(['currentPassword', 'password', 'confirmPassword']);

/** `app` (see createApp in server.mjs): identity, loginThrottle and optionally log. */
export function accountRoutes(app) {
  const { identity, loginThrottle } = app;
  const log = app.log ?? console;
  const changePassword = {
    method: 'POST',
    path: '/api/account/password',
    auth: 'session',
    permission: 'account:self',
    // Never answered from a stored reply: the page handles a lost answer itself.
    idempotent: false,
    audit: 'identity',
    // Every refusal is counted into the aggregated account.password.changed row (audit spec
    // §5.2); the change itself is recorded by identity, in its own unit.
    refusals: 'account.password.changed',
    bodyLimit: 4096,
    summary: 'Change your password (needs the current one); signs out your other sessions',
    async handler({ req, res, client, access, transport, body, audit }) {
      const input = await body();
      // Only the three fields of a change (1.4.3's page sends exactly these): one with others is
      // refused as malformed, never with their values.
      if (
        input !== null &&
        typeof input === 'object' &&
        !Array.isArray(input) &&
        Object.keys(input).some(key => !passwordChangeFields.includes(key))
      )
        throw identityError('invalid_request', { variant: 'change' });
      // The sign-in lockout, as for signing in (§6.10), re-checked after the body arrives:
      // held requests must not outlive a lockout (1.4.3). The current password is checked
      // here, so a session (borrowed, or from a lost device) must not become a way around
      // the global lock: only a client that proved the password recently may try during a
      // many-address attack, or the Uptime Goblin host itself (the loopback transport). The `loopback`
      // key off the loopback transport (a proxy on this host that GOBLIN_TRUST_PROXY does not
      // name) never may, whatever password any request with that key proved, through the ssh
      // tunnel or the proxy (globallyLocked()).
      if (globallyLocked(loginThrottle, client, transport))
        throw identityError('locked', { retryAfter: 60 });
      const locked = loginThrottle.retryAfter(client);
      if (locked) throw identityError('locked', { retryAfter: Math.ceil(locked / 1000) });
      let result;
      try {
        result = await identity.changePassword(access, input, {
          client,
          userAgent:
            typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
          request: audit.request,
        });
      } catch (error) {
        // A wrong current password counts like a failed sign-in: a borrowed session must not
        // become a free password oracle. Busy, a change in progress and a full disk do not.
        if (error?.code === 'current_password_incorrect') loginThrottle.failure(client);
        throw error;
      }
      loginThrottle.success(client);
      // A session is rotated by the change (new id, new secret): the browser gets the new one.
      if (result.issue)
        res.setHeader('Set-Cookie', [
          sessionCookie({
            kind: transport.kind,
            value: result.issue.value,
            maxAgeSeconds: result.issue.maxAgeSeconds,
          }),
          ...expiredLegacySessionCookies(readCookies(req.headersDistinct?.cookie)),
        ]);
      json(res, 200, {
        ok: true,
        revokedOtherSessions: result.revokedOtherSessions,
        mirrorPending: result.mirrorPending,
        // A script using Basic must sign in with the new password from now on.
        reauthenticate: access.via === 'basic',
      });
    },
  };
  return [
    changePassword,
    {
      ...changePassword,
      path: '/api/auth/password',
      // The 1.4.x address, kept for scripts and 1.4.x pages; its answers carry Deprecation.
      deprecated: '2026-10-01',
      summary: 'Deprecated alias of POST /api/account/password',
    },
    {
      method: 'GET',
      path: '/api/account/sessions',
      auth: 'session',
      permission: 'account:self',
      summary: 'Your sessions',
      async handler({ res, access, assertCurrent }) {
        const sessions = await identity.listSessions(access);
        // A session ended while the list was read learns nothing more about the others.
        assertCurrent();
        json(res, 200, { sessions });
      },
    },
    {
      method: 'DELETE',
      path: '/api/account/sessions',
      auth: 'session',
      permission: 'account:self',
      idempotent: false,
      audit: 'identity',
      body: 'empty',
      summary: 'Sign out your other sessions',
      async handler({ res, access, assertCurrent, audit }) {
        // `kept`: sessions that signed in after this one, which only a newer sign-in ends. A
        // session that ended meanwhile gets 401 (the service refuses one that ended before the
        // call, while its body was awaited, say, or before its delete; this, one that ended
        // since), never a count of the devices.
        const { revoked, kept } = await identity.revokeOtherSessions(access, {
          request: audit.request,
        });
        assertCurrent();
        json(res, 200, { revoked, kept });
      },
    },
    {
      method: 'DELETE',
      path: '/api/account/sessions/:id',
      auth: 'session',
      permission: 'account:self',
      idempotent: false,
      audit: 'identity',
      body: 'empty',
      summary: 'Sign out one session',
      async handler(context) {
        const { res, access, params, assertCurrent, audit } = context;
        // Signing out this very session is a sign-out, exactly as POST /api/auth/logout: the
        // browser forgets its cookie, and on https its plain-HTTP session ends too.
        if (access?.via === 'session' && params.id === access.sessionId) {
          await signOut({ identity, log }, context);
          return;
        }
        const { found } = await identity.revokeSession(access, params.id, {
          request: audit.request,
        });
        if (!found) throw identityError('not_found');
        // As Sign out other devices: a session that ended meanwhile gets 401.
        assertCurrent();
        res.writeHead(204, { 'Cache-Control': 'no-store' });
        res.end();
      },
    },
  ];
}
