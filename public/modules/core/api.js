// Uptime Goblin's API: time limits, Idempotency-Key and If-Match, signing in again when a session
// ends, and this tab's queue of configuration writes.
import { load } from './load.js';
import { kiosk, page, pageBuild } from './page.js';
import { requireSignIn } from '../identity/session.js';
import { noticeBuild } from '../update/update.js';

// Every request has a time limit, so one connection that never answers (a restart, a
// dropped network) cannot freeze the page. Uptime Goblin allows a connection test 120 s.
const readTimeoutMs = 30000,
  writeTimeoutMs = 60000;
export const testTimeoutMs = 150000,
  // A dashboard load running this long is stuck (three polls): the watchdog starts again.
  stuckLoadMs = 45000,
  // Hidden tabs do not poll; they ask for Uptime Goblin's version this often instead.
  versionProbeMs = 300000;
// The 401 codes that mean "this browser has no usable session": signing in again helps. Any
// other 401 (two cookies, a wrong password) would only fail the same way after signing in.
const signInCodes = new Set(['signin_required', 'session_expired']);
// AbortSignal.any needs Safari 17.4 or later; older wall-mounted iPads still run Uptime Goblin.
function eitherSignal(a, b) {
  if (AbortSignal.any) return AbortSignal.any([a, b]);
  const both = new AbortController();
  for (const signal of [a, b]) {
    if (signal.aborted) both.abort(signal.reason);
    else signal.addEventListener('abort', () => both.abort(signal.reason), { once: true });
  }
  return both.signal;
}
/** A random UUID. crypto.randomUUID needs HTTPS, and Uptime Goblin is often opened over plain HTTP. */
function requestKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
/** Settles when `signal` aborts (rejecting with its reason); never settles otherwise. */
function whenAborted(signal) {
  return new Promise((resolve, reject) => {
    if (!signal) return;
    if (signal.aborted) reject(signal.reason);
    else signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
}
/**
 * Calls Uptime Goblin's API. Options are fetch's, plus `timeout` (ms; reads 30 s and writes 60 s by
 * default), `idempotencyKey` (a write's retry reuses its key, so Uptime Goblin applies it once),
 * `background` (a request no person made: it does not keep the session from ending when
 * idle; kiosk reads are always background, while writes are always foreground), `signIn`
 * (false: a 401 is thrown as it is, without asking the user to sign in) and
 * `as: 'bytes'` (a download: a 2xx answer resolves to `{bytes, type, filename, headers}`, its
 * body read as an ArrayBuffer, never as text, which would drop a CSV's byte order mark; any other
 * answer is handled as for JSON).
 * An error without `status` means Uptime Goblin did not answer; `timeout` is set when the time limit
 * ended the request. An error with `status` carries Uptime Goblin's `code` when it sent one.
 *
 * When the session has ended (401 signin_required or session_expired), the user is asked to
 * sign in again over whatever is open, and the request is sent once more with the same
 * options, the same Idempotency-Key and If-Match included: Uptime Goblin keeps a write's reply for the
 * signed-in person rather than for one session, so the retry joins or replays a first attempt
 * that ran, and never applies it twice. Cancelling the sign-in throws the original 401.
 */
export async function api(url, options = {}) {
  const { timeout, idempotencyKey, background, signIn = true, as, ...request } = options,
    write = !['GET', 'HEAD'].includes((request.method || 'GET').toUpperCase()),
    // One key for both attempts, chosen before the first is sent.
    key = write ? idempotencyKey || requestKey() : null,
    send = () =>
      attempt(url, request, {
        write,
        key,
        background: !write && (kiosk || background),
        as,
        timeout: timeout ?? (write ? writeTimeoutMs : readTimeoutMs),
      });
  if (write) page.writesPending++;
  try {
    try {
      return await send();
    } catch (error) {
      if (signIn === false || error.status !== 401 || !signInCodes.has(error.code)) throw error;
      try {
        // A caller that gives up (the dashboard watchdog, a closed drawer) stops waiting.
        await Promise.race([requireSignIn({ reason: error }), whenAborted(request.signal)]);
      } catch {
        // This request's own 401: when Uptime Goblin refuses any sign-in from this page, requireSignIn()
        // has made it say so, whichever caller asked first; when a release before 1.5 answered
        // instead (Uptime Goblin was rolled back), it reads as that release's 401, without a code.
        throw error;
      }
      // Signed in again. A second 401 is thrown: it would only ask again.
      return await send();
    }
  } finally {
    if (write) page.writesPending--;
  }
}
/** One request to Uptime Goblin, with its own time limit. */
async function attempt(url, request, { write, key, background, as, timeout }) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);
  try {
    let res, body;
    try {
      const headers = new Headers({
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        // Marks the request as the web app's: Uptime Goblin then ignores any HTTP Basic credentials
        // the browser still sends from 1.4.x, and names the build on the System page.
        'X-Goblin-Client': pageBuild ? `web/${pageBuild}` : 'web',
        ...(write ? { 'Idempotency-Key': key } : {}),
      });
      for (const [name, value] of new Headers(request.headers)) headers.set(name, value);
      // Activity is decided here, never by caller headers (header names are case-insensitive).
      // In particular a write cannot opt out of foreground activity, even in kiosk mode.
      // The server reads X-Orbit-Activity (its name before 1.5) when X-Goblin-Activity is absent,
      // so a caller's header of either name is removed.
      headers.delete('X-Goblin-Activity');
      headers.delete('X-Orbit-Activity');
      if (background) headers.set('X-Goblin-Activity', 'background');
      res = await fetch(url, {
        ...request,
        signal: request.signal
          ? eitherSignal(request.signal, controller.signal)
          : controller.signal,
        headers,
      });
      body = as === 'bytes' && res.ok ? await res.arrayBuffer() : await res.text();
    } catch (error) {
      if (!timedOut) throw error;
      const late = new Error(
        write
          ? 'Uptime Goblin did not answer in time, so this change may or may not have been saved.'
          : 'Uptime Goblin did not answer in time.'
      );
      late.timeout = true;
      throw late;
    }
    // Uptime Goblin names its build on every answer, refusals included, so a page left open across an
    // upgrade finds the new release even when its session ended with the upgrade.
    const serverBuild = res.headers.get('X-Goblin-Build');
    // Sign out and session removals answer 204 without a body.
    if (res.status === 204) {
      noticeBuild(serverBuild, true);
      return null;
    }
    if (as === 'bytes' && res.ok) {
      noticeBuild(serverBuild, true);
      return {
        bytes: body,
        type: res.headers.get('Content-Type') || '',
        filename: attachmentName(res.headers.get('Content-Disposition')),
        headers: res.headers,
      };
    }
    let content;
    try {
      content = JSON.parse(body);
    } catch {
      noticeBuild(serverBuild, false);
      // Not Uptime Goblin's JSON, e.g. a reverse proxy's 502/504 page. `status` stays unset so
      // callers treat the outcome as unknown.
      throw new Error(
        `Uptime Goblin returned an unexpected response (HTTP ${res.status}). Check the reverse proxy.`
      );
    }
    noticeBuild(serverBuild, res.ok);
    if (!res.ok) {
      const error = new Error(content?.error || 'Could not complete that request');
      error.status = res.status;
      if (typeof content?.code === 'string') error.code = content.code;
      // 401 answers say how this browser reaches Uptime Goblin, for the sign-in view's notices.
      if (content?.transport && typeof content.transport === 'object')
        error.transport = content.transport;
      error.retryAfter = Number(res.headers.get('Retry-After')) || 0;
      // Every 401 from Uptime Goblin 1.5 on names its code. One without comes from an older release
      // (Uptime Goblin was rolled back), which signs browsers in its own way: signing in here could
      // not help, so the page reloads into that release when nothing would be lost.
      if (res.status === 401 && error.code === undefined) noticeBuild('unknown', true);
      throw error;
    }
    return content;
  } finally {
    clearTimeout(timer);
  }
}
/** The file name a download's Content-Disposition gives (`attachment; filename="…"`), or null. */
const attachmentName = header => /\bfilename="([^"\\]+)"/.exec(header ?? '')?.[1] ?? null;
// Configuration writes name the revision they were based on, so the server refuses (409)
// a write that would silently revert a change saved meanwhile on another device or tab.
const ifMatch = revision => (Number.isInteger(revision) ? { 'If-Match': String(revision) } : {});
export const conflictMessage =
  'This was changed on another device or tab, so your change was not saved.';
// This tab's configuration writes go out one at a time, each naming the revision current when
// it is sent, and a success is applied here at once rather than when load() returns. A quick
// second action then builds on the first instead of being refused as a conflict.
let configWrites = Promise.resolve();
/**
 * Sends a configuration write based on `revision()`, read when it is sent (`conditional:
 * false` sends no If-Match). `apply(config, result)` brings this tab's copy of the
 * configuration up to the written revision; `source` is the source the write changed.
 */
export function writeConfig(url, options, { revision, apply, source = null, conditional = true }) {
  // One key for this change, kept by its retry, so Uptime Goblin never applies it twice.
  const key = requestKey();
  const write = configWrites.then(async () => {
    const based = revision(),
      send = () =>
        api(url, { ...options, idempotencyKey: key, headers: conditional ? ifMatch(based) : {} });
    let result;
    try {
      result = await send();
    } catch (error) {
      if (error.status !== undefined) throw error;
      // No answer (the time limit, a dropped connection, a restart): the change may or may
      // not have been saved, perhaps by a process that has since restarted and forgotten
      // the key. Retry only when Uptime Goblin's configuration is provably unchanged since this
      // write was based on it; the retry also names that revision, so it cannot apply twice.
      page.writeUnknown = true;
      if (!conditional || !(await load()) || page.data.config.revision !== based)
        throw unconfirmedWrite();
      try {
        result = await send();
      } catch (retryError) {
        if (retryError.status === undefined) {
          page.writeUnknown = true;
          throw unconfirmedWrite();
        }
        throw retryError;
      }
    }
    // A newer write of this tab explains any older snapshot still on its way, so the count
    // of skipped snapshots (meant for a server whose configuration went back) starts again.
    if (Number.isInteger(result.revision) && result.revision > page.writtenRevision) {
      page.writtenRevision = result.revision;
      page.staleSnapshots = 0;
    }
    adoptWrite(based, result.revision, config => apply(config, result), source);
    return result;
  });
  configWrites = write.catch(() => {});
  return write;
}
function unconfirmedWrite() {
  const error = new Error(
    'Uptime Goblin did not confirm this change, and it may have been saved. The latest settings are shown now; check them before trying again.'
  );
  error.unconfirmed = true;
  return error;
}
/**
 * Moves the copies drawn from revision `based` to `revision`, which this tab's write created.
 * Only a write that was the sole change since `based` qualifies; anything else is left to
 * load(), so a change saved on another device is never skipped over.
 */
function adoptWrite(based, revision, apply, source) {
  if (!Number.isInteger(based) || revision !== based + 1) return;
  if (page.data.config.revision === based) {
    apply(page.data.config);
    page.data.config.revision = revision;
  }
  // Settings forms show no source fields, and a settings save came from the form itself.
  if (page.pageRevision === based) page.pageRevision = revision;
  // A drawer open on the source this write changed still shows it as it was.
  if (page.drawerRevision === based && page.settingsId !== source) page.drawerRevision = revision;
}
export const replaceService = (config, { service }) => {
  config.services = config.services.map(s => (s.id === service.id ? service : s));
};
/** Settings as this tab saved them; the next load() brings the server's normalized copy. */
export function mergeSettings(config, input) {
  for (const [key, value] of Object.entries(input))
    config[key] = value && typeof value === 'object' ? { ...config[key], ...value } : value;
}
