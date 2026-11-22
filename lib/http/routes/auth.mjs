// Signing in and out, and who is signed in (sessions spec §6.10, §6.11). Identity checks the
// password and keeps the sessions; this module decides what HTTP needs: whether this connection
// may carry a session cookie at all (the transport rule), the sign-in lockout, and the cookies.
import { identityError } from '../../identity/errors.mjs';
import { json } from '../body.mjs';
import {
  expiredLegacySessionCookies,
  expiredSessionCookie,
  readCookies,
  sessionCookie,
  sessionCookieName,
} from '../cookies.mjs';
import { isLoopbackHost, isLoopbackPeer, originHost, originScheme } from '../transport.mjs';
import { createDiagnostics, globallyLocked, logOrigin, logValue } from '../pipeline.mjs';
import { setHeaderPair } from '../../legacy-names.mjs';

/**
 * The members of a sign-in request (POST /api/auth/login): the admin's three, or a wall
 * display's exact {code, display: true} (B6 design §7.4). A display never takes a password, and
 * the password path never makes a display.
 */
const loginFields = Object.freeze(['login', 'password', 'remember', 'code', 'display']);
const displayFields = ['code', 'display'];

/**
 * The `GET /api/session` answer for an access (§6.11): identity's part (user, how they signed
 * in, permissions, the session's times, whether auth.json still owes the current password)
 * plus what only HTTP knows: the transport, whether scripts may use Basic, and the build.
 * `insecure` (the plain-HTTP banner) is true on the `http` transport, and for a session signed
 * in over it whatever way its later requests arrive (a proxy on this host that sends no
 * forwarding headers can make them look like `loopback`).
 */
export function sessionBody(
  { identity, legacyBasic, insecureHttpSessions, release },
  access,
  transport
) {
  const described = identity.describe(access);
  // A wall display (B6 design §7.5): what it is, what it may do, its session and transport.
  if (described.kind === 'kiosk')
    return {
      via: 'session',
      kind: 'kiosk',
      permissions: described.permissions,
      session: described.session,
      transport: {
        kind: transport.kind,
        https: transport.kind === 'https',
        insecure: transport.kind === 'http' || access.session?.transport === 'http',
      },
      build: release.build,
    };
  return {
    kind: described.kind,
    user: described.user,
    via: described.via,
    permissions: described.permissions,
    session: described.session,
    transport: {
      kind: transport.kind,
      https: transport.kind === 'https',
      // Only reachable with GOBLIN_INSECURE_HTTP_SESSIONS=1: the page shows a banner.
      insecure: transport.kind === 'http' || access.session?.transport === 'http',
      insecureAllowed: Boolean(insecureHttpSessions),
    },
    legacyBasic: Boolean(legacyBasic),
    mirrorPending: described.mirrorPending,
    build: release.build,
  };
}

// True when an https request still carries the cookie a plain-HTTP sign-in left: signing in or
// out over https removes it, so it cannot linger once Uptime Goblin is served over HTTPS.
const carriesInsecureCookie = (req, transport) =>
  transport.kind === 'https' &&
  readCookies(req.headersDistinct?.cookie).all(sessionCookieName('http')).length > 0;

/**
 * Signs the browser out (logout, and DELETE of its own session): identity ends the session and,
 * on https, the plain-HTTP session the browser still presents (every `orbit_session` value, so a
 * cookie another site set beside it cannot keep it out, §19 G1), whose secret crossed the
 * network in clear, so expiring its cookie alone would leave it usable by anyone who captured
 * it. Then endSession().
 *
 * A failed delete leaves the browser's cookies as they are. Both ids stay refused in this
 * process (identity revokes them before the write), but the rows are still in control.sqlite
 * until something deletes them, and a restart before that would accept them again. The cookie
 * is the only way the browser can name its session: expired, it would leave nothing to finish
 * the sign-out with, since a retry would come without a session (§20 H1). Kept, pressing Sign
 * out again deletes the rows (the logout route's endedSession, signOutEnded()), and so does
 * signing in again (rotation). So the answer is not a 204: the error (503 storage_full on a full
 * disk, else 500) lets the page say that Uptime Goblin did not record the sign-out, and keep Sign out.
 */
export async function signOut(
  { identity, log },
  { req, res, access, transport, insecureCookies, audit }
) {
  try {
    // The request's facts name who signed out, from where, in the audit row identity writes in
    // the same unit as the delete (audit spec §5.1).
    await identity.logout(access, { also: insecureCookies, request: audit.request });
  } catch (error) {
    throw signOutFailed({ log }, res, error);
  }
  endSession(req, res, transport);
}

/**
 * A sign-out sent with one session cookie that no longer signs in (the logout route's
 * endedSession, §20 H1): above all a sign-out whose delete failed, pressed again. Identity
 * refuses that session in this process, but its row is still in control.sqlite, and a restart
 * before the hourly prune or the stop deletes it would accept it again, so the retry must be
 * able to delete it. As in signOutPresented(), holding a session's secret is enough to end that
 * session, and no other can be reached: every u_admin session among the cookies the request
 * carries ends (on https with every plain-HTTP cookie too), and the answer is the sign-out's
 * (204, the cookies expired). When none of them is stored any more the answer is the 401
 * session_expired the request got before, which the page takes as already signed out. A failed
 * delete answers as signOut()'s does.
 */
export async function signOutEnded(
  { identity, log },
  { req, res, transport, presentedSessions, insecureCookies, audit }
) {
  let ended;
  try {
    // Recorded as a sign-out of a session that had already ended elsewhere (audit spec §5.1).
    ended = await identity.revokePresented([...presentedSessions, ...insecureCookies], {
      cause: 'ended',
      request: audit.request,
    });
  } catch (error) {
    throw signOutFailed({ log }, res, error);
  }
  if (!ended) throw identityError('session_expired');
  endSession(req, res, transport);
}

/** The text of a sign-out that ended the browser's sessions but left another site's cookie. */
export const otherCookieText =
  "Signed out. This browser also sent an Uptime Goblin sign-in cookie that another site set, which Uptime Goblin cannot remove: remove this site's cookies in the browser before signing in again.";

/**
 * A sign-out sent with two or more cookies of Uptime Goblin's session name (the logout route's
 * multipleSessions, §19 G1): one is the browser's own, another was set by another site (another
 * port of this host, a parent domain, or an injection over plain HTTP), and nothing tells them
 * apart, so the request is not signed in. Every one of them that is a session of u_admin's ends
 * (holding its secret is enough; no other session can be reached), on https with every
 * plain-HTTP cookie too, and the browser's side ends as for any sign-out: Uptime Goblin's own cookie
 * (host-only, Path=/) expires and the cache is cleared. The other site's cookie stays (Uptime Goblin
 * cannot know its domain or path), so the answer is 200 `{signedOut: true, code:
 * 'multiple_credentials', message}` rather than 204: the page says to remove this site's
 * cookies before signing in again, which would otherwise fail without a word of why. A failed
 * delete answers as signOut()'s does: the cookies stay, so the same sign-out sent again (both
 * cookies come again) finishes it.
 */
export async function signOutPresented(
  { identity, log },
  { req, res, transport, presentedSessions, insecureCookies, audit }
) {
  try {
    // Recorded as a sign-out of each session this browser presented (audit spec §5.1).
    await identity.revokePresented([...presentedSessions, ...insecureCookies], {
      cause: 'presented',
      request: audit.request,
    });
  } catch (error) {
    throw signOutFailed({ log }, res, error);
  }
  endSession(req, res, transport, {
    answer: { signedOut: true, code: 'multiple_credentials', message: otherCookieText },
  });
}

// A sign-out whose delete failed: logged, and answered as the error (the caller throws what
// this returns; fail() answers it). The cookies are not expired: they are what a retry from
// this browser names its sessions with (see signOut()). The cache is cleared all the same: the
// browser asked to sign out, and Uptime Goblin refuses the sessions from now on.
function signOutFailed({ log }, res, error) {
  log.error(
    'Signing out could not be saved: the session is refused until Uptime Goblin restarts, and Uptime Goblin retries removing it hourly and when it stops:',
    error?.code || error?.class || error?.name
  );
  res.setHeader('Clear-Site-Data', '"cache"');
  res.setHeader('Cache-Control', 'no-store');
  return error;
}

/**
 * Ends the browser's side of a session: the session cookie expired (and on https the
 * plain-HTTP one too), and the browser's cache of Uptime Goblin's answers cleared, so Back cannot show
 * signed-in pages. Answers 204, or 200 with the JSON `answer` when one is given. Used by
 * signOut(), signOutEnded() and signOutPresented(), only once the delete is recorded.
 */
export function endSession(req, res, transport, { answer = null } = {}) {
  const cookies = [expiredSessionCookie(transport.kind)];
  if (carriesInsecureCookie(req, transport)) cookies.push(expiredSessionCookie('http'));
  cookies.push(...expiredLegacySessionCookies(readCookies(req.headersDistinct?.cookie)));
  const headers = {
    'Set-Cookie': cookies,
    'Clear-Site-Data': '"cache"',
    'Cache-Control': 'no-store',
  };
  if (answer) {
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    json(res, 200, answer);
    return;
  }
  res.writeHead(204, headers);
  res.end();
}

/**
 * `app` (see createApp in server.mjs): identity, loginThrottle, legacyBasic,
 * insecureHttpSessions, release {version, build}, trusted (the trusted-proxy check, for the
 * journal line that says why a proxy's claim was not believed) and optionally log.
 */
export function authRoutes(app) {
  const { identity, loginThrottle, insecureHttpSessions, release, trusted = null } = app;
  const log = app.log ?? console;
  const diagnose = createDiagnostics({ log });

  // A session cookie is only as private as the connection it travels on (§6.2). Returns the
  // transport the session is signed in over (its cookie, and what identity records), or throws
  // the refusal. The browser's Origin can make Uptime Goblin refuse, never weaken the cookie (D19).
  function sessionTransport(req, transport) {
    const origin = req.headers.origin,
      scheme = originScheme(origin),
      shown = logOrigin(origin),
      address = req.socket?.remoteAddress,
      peer = logValue(address);
    // A page on this computer. A loopback request from a page served under another name (an
    // GOBLIN_ALLOWED_HOSTS entry: the sign-in check accepts those, D20) came through a proxy on
    // this host that sends no forwarding headers, from a browser anywhere: plain HTTP below.
    if (transport.kind === 'loopback' && isLoopbackHost(originHost(origin))) return 'loopback';
    if (transport.kind === 'https') {
      if (scheme === 'https:') return 'https';
      // A proxy that hard-codes X-Forwarded-Proto: https for plain-HTTP traffic: a Secure
      // cookie would be dropped by the browser, whatever GOBLIN_INSECURE_HTTP_SESSIONS says.
      diagnose(
        'proxy_proto_mismatch',
        `Sign-in refused: the browser used http:// (Origin ${shown}) but the trusted proxy ${peer} sent X-Forwarded-Proto: https. Make it send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;).`
      );
      throw identityError('proxy_proto_mismatch');
    }
    // Plain HTTP: allowed only with the explicit, bannered opt-in (D8).
    if (insecureHttpSessions) return 'http';
    // A proxy on this host that sends no forwarding headers at all: Uptime Goblin cannot tell where
    // the browser is or what it used.
    const headerless = isLoopbackPeer(address) && !transport.proxied;
    if (scheme === 'https:') {
      const reason = headerless
        ? 'comes from a proxy on this host that sends no forwarding headers'
        : typeof trusted === 'function' && trusted(address)
          ? 'carries no X-Forwarded-Proto: https'
          : 'comes from a proxy that GOBLIN_TRUST_PROXY does not trust';
      diagnose(
        'proxy_proto_missing',
        `Sign-in refused: the browser used HTTPS (Origin ${shown}) but the request from ${peer} ${reason}. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.`
      );
      throw identityError('proxy_proto_missing');
    }
    if (headerless)
      diagnose(
        'https_required',
        `Sign-in refused: the browser used plain HTTP (Origin ${shown}) through a proxy on this host that sends no forwarding headers (Host ${logValue(req.headers.host)}). Serve Uptime Goblin over HTTPS through the proxy and make it send X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;) with GOBLIN_TRUST_PROXY=loopback, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 on a trusted network.`
      );
    throw identityError('https_required');
  }

  /**
   * A wall display's sign-in (B6 design §7.4), after the transport rule and the lockout: the
   * body must be exactly {code: <text>, display: true}, and the code must have a display code's
   * shape (neither is looked up or counted). A code no row knows is counted as a wrong password
   * is; a known one that is expired, used or cancelled is refused the same way but not counted,
   * since it proves no guessing (and behind Compose every browser shares one lockout key). A
   * redemption never clears failures or trusts the client: no password was checked.
   */
  async function redeem({ req, res, client, transport, kind, input, audit, replacing }) {
    const keys = Object.keys(input);
    if (
      keys.length !== 2 ||
      !displayFields.every(key => keys.includes(key)) ||
      input.display !== true ||
      typeof input.code !== 'string'
    )
      throw identityError('invalid_request', { variant: 'display' });
    const releaseCheck = loginThrottle.begin(client);
    if (!releaseCheck) {
      loginThrottle.failure(client);
      throw identityError('busy', { scope: 'client' });
    }
    let result;
    try {
      result = await identity.redeemDisplayCode(
        {
          code: input.code,
          client,
          userAgent:
            typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
          replacing,
          transport: kind,
        },
        { request: audit.request }
      );
    } catch (error) {
      if (error?.code === 'display_code_invalid' && !error.stale) loginThrottle.failure(client);
      throw error;
    } finally {
      releaseCheck();
    }
    const cookies = [
      sessionCookie({ kind, value: result.issue.value, maxAgeSeconds: result.issue.maxAgeSeconds }),
    ];
    if (carriesInsecureCookie(req, transport)) cookies.push(expiredSessionCookie('http'));
    cookies.push(...expiredLegacySessionCookies(readCookies(req.headersDistinct?.cookie)));
    res.setHeader('Set-Cookie', cookies);
    setHeaderPair(res, 'Version', release.version);
    json(res, 200, sessionBody(app, result.access, transport));
  }

  return [
    {
      method: 'POST',
      path: '/api/auth/login',
      auth: 'public',
      permission: null,
      idempotent: false,
      audit: 'identity',
      // Every refusal is counted into the aggregated session.login row (audit spec §5.2, D9).
      refusals: 'session.login',
      bodyLimit: 4096,
      summary: 'Sign in as the built-in admin; sets the session cookie',
      async handler({
        req,
        res,
        client,
        transport,
        presentedSessions,
        insecureCookies,
        body,
        audit,
      }) {
        const input = await body();
        // The name it gave, for its refusal's row: kept only as admin or another name, since a
        // client may type its password into the name field (D9). A display gives none.
        audit.loginGiven(input?.login);
        const shape = input !== null && typeof input === 'object' && !Array.isArray(input);
        const asDisplay =
          shape && (Object.hasOwn(input, 'code') || Object.hasOwn(input, 'display'));
        let kind;
        try {
          kind = sessionTransport(req, transport);
        } catch (error) {
          // A display code that reached Uptime Goblin in a way it refuses may have crossed a network in
          // clear: it is cancelled (best effort, R2A-6), and the refusal says so.
          if (!asDisplay) throw error;
          await identity.cancelDisplayCode(
            input.code,
            { cause: 'plain_http' },
            { request: audit.request }
          );
          throw identityError(error.code, { variant: 'display_code' });
        }
        // The same lockout as a script's Basic sign-in (§6.5 step 6), checked before any
        // password work. The global lock never applies to the loopback transport (D18), which
        // the page address never chooses and a sign-in through a proxy that sends forwarding
        // headers never is (one that sends none cannot always be told apart: §16 C1). The key is
        // requestClient()'s (pipeline.mjs): the Uptime Goblin host's own (loopbackClient) also through a
        // proxy that connects from a loopback address and that GOBLIN_TRUST_PROXY does not name,
        // whatever headers it sends; off the loopback transport, the global lock always holds it.
        if (globallyLocked(loginThrottle, client, transport))
          throw identityError('locked', { retryAfter: 60 });
        const locked = loginThrottle.retryAfter(client);
        if (locked) throw identityError('locked', { retryAfter: Math.ceil(locked / 1000) });
        // Only the fields a sign-in has: a script that sends others (a misspelt `remmeber`)
        // learns it instead of being signed in without them. Nothing is echoed.
        if (shape && Object.keys(input).some(key => !loginFields.includes(key)))
          throw identityError('invalid_request', { variant: 'login' });
        if (asDisplay)
          return redeem({
            req,
            res,
            client,
            transport,
            kind,
            input,
            audit,
            replacing: [...presentedSessions, ...insecureCookies],
          });
        let result;
        try {
          result = await identity.login(
            {
              login: shape ? input.login : undefined,
              password: shape ? input.password : undefined,
              remember: shape ? input.remember : undefined,
              client,
              userAgent:
                typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
              // Rotation at sign-in: the sessions this browser presented end now, so a session
              // id planted before sign-in (fixation) never becomes a signed-in one. Every value
              // under either name: a cookie another site set beside the browser's own must not
              // keep the old session alive (§19 G1).
              replacing: [...presentedSessions, ...insecureCookies],
              transport: kind,
              // At most a few checks per client at once (1.4.3): a parallel burst gets no more
              // guesses than a sequential one, and its refusals count.
              admit: () => {
                const releaseCheck = loginThrottle.begin(client);
                if (!releaseCheck) throw identityError('busy', { scope: 'client' });
                return releaseCheck;
              },
            },
            // Identity writes the sign-in's row in the unit that stores the session.
            { request: audit.request }
          );
        } catch (error) {
          // A wrong password, and this client's own parallel burst, count as guesses. A full
          // queue (other clients' checks), a full disk and malformed input do not: no
          // password of this client was checked.
          if (
            error?.code === 'invalid_credentials' ||
            (error?.code === 'busy' && error.scope === 'client')
          )
            loginThrottle.failure(client);
          throw error;
        }
        loginThrottle.success(client);
        const cookies = [
          sessionCookie({
            kind,
            value: result.issue.value,
            maxAgeSeconds: result.issue.maxAgeSeconds,
          }),
        ];
        if (carriesInsecureCookie(req, transport)) cookies.push(expiredSessionCookie('http'));
        cookies.push(...expiredLegacySessionCookies(readCookies(req.headersDistinct?.cookie)));
        res.setHeader('Set-Cookie', cookies);
        setHeaderPair(res, 'Version', release.version);
        json(res, 200, sessionBody(app, result.access, transport));
      },
    },
    {
      method: 'POST',
      path: '/api/auth/logout',
      auth: 'session',
      permission: 'session:self',
      idempotent: false,
      audit: 'identity',
      // Nothing or {}: the sessions it ends are the cookies' (also for its two hooks below).
      body: 'empty',
      summary: 'Sign out this session',
      handler: context => signOut({ identity, log }, context),
      // Sent with two or more session cookies (one of them another site's): still a sign-out.
      multipleSessions: context => signOutPresented({ identity, log }, context),
      // Sent with a session cookie that no longer signs in (a sign-out whose delete failed,
      // pressed again): its row, while stored, is deleted.
      endedSession: context => signOutEnded({ identity, log }, context),
    },
    {
      method: 'GET',
      path: '/api/session',
      auth: 'session',
      permission: 'session:self',
      summary: 'Who is signed in, how, and until when',
      handler({ res, access, transport }) {
        json(res, 200, sessionBody(app, access, transport));
      },
    },
  ];
}
