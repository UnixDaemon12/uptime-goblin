// The sign-in form. The sign-in view (#signin-form, before the web app starts) and the sign-in
// dialog (#reauth-form, when a session ends while the app is open) share it: one attempt is
// POST /api/auth/login, then GET /api/session to see that the browser kept the cookie.
//
// Both forms are <form method="post"> and their submit handler cancels the native submission
// first. Should a script fail before that, the browser posts to the page's own address, which
// Uptime Goblin refuses without reading the body, so the password never reaches a URL, the browser
// history or a proxy log.
import { api } from '../core/api.js';
import { $ } from '../core/dom.js';
import { olderReleaseText } from '../core/load.js';
import { signedIn } from './session.js';

// The sign-in view is shown before sign-in, when Uptime Goblin's Help page (/api/docs) cannot be read,
// so these texts name the guide's file instead. `code` marks configuration to type as it is.
const guide = '(see docs/authentication.md)';
export const signInTexts = Object.freeze({
  invalid_credentials: 'The login name or password is incorrect.',
  https_required: `Sign-in needs HTTPS, or a browser on the Uptime Goblin computer itself. Open Uptime Goblin at its https:// address. You can allow plain HTTP on a network you trust, but your password and sign-in cookie then cross it unencrypted: set GOBLIN_INSECURE_HTTP_SESSIONS=1 in Uptime Goblin’s environment and restart Uptime Goblin (Docker: in .env, then docker compose up -d) ${guide}.`,
  proxy_proto_missing: `Your browser uses HTTPS, but the reverse proxy in front of Uptime Goblin does not tell Uptime Goblin so. In nginx add \`proxy_set_header X-Forwarded-Proto $scheme;\` to Uptime Goblin’s location and reload nginx; GOBLIN_TRUST_PROXY must name the proxy (loopback when it runs on the same computer). Until then GOBLIN_INSECURE_HTTP_SESSIONS=1 lets you sign in ${guide}.`,
  proxy_proto_mismatch: `This page uses plain HTTP (http://), but the reverse proxy in front of Uptime Goblin tells Uptime Goblin the connection is HTTPS, so your browser would drop the sign-in cookie. In nginx use \`proxy_set_header X-Forwarded-Proto $scheme;\` instead of a fixed https and reload nginx, or open Uptime Goblin at its https:// address ${guide}.`,
  cross_origin: `Uptime Goblin refused this sign-in because this page’s address does not match what the reverse proxy tells Uptime Goblin. In nginx add \`proxy_set_header Host $http_host;\` to Uptime Goblin’s location, or add this hostname to GOBLIN_ALLOWED_HOSTS and restart Uptime Goblin ${guide}.`,
  multiple_credentials:
    'Your browser sent two Uptime Goblin sign-in cookies. Remove this site’s cookies, then sign in.',
  // After a sign-out that ended this browser's sessions but not another site's cookie of
  // Uptime Goblin's name (identity/session.js): signing in again would fail as above.
  signed_out_other_cookie:
    'You are signed out, but this browser still has an Uptime Goblin sign-in cookie that another site set. Remove this site’s cookies in the browser before you sign in again.',
  session_expired: 'Your session has ended. Sign in again.',
  // Uptime Goblin allows sign-in over plain HTTP (GOBLIN_INSECURE_HTTP_SESSIONS) and this page reaches it
  // over the network: shown above the form (plainHttpWarning()).
  plain_http:
    'This page uses plain HTTP, so your password crosses the network unencrypted when you sign in (GOBLIN_INSECURE_HTTP_SESSIONS allows it). Sign in only on a network you trust, and serve Uptime Goblin over HTTPS.',
  cookie_not_stored:
    'You signed in, but this browser did not keep Uptime Goblin’s sign-in cookie. If this address starts with http://, open the https:// address instead.',
  network: 'Uptime Goblin is not answering. Try again in a moment.',
  again: 'You can try again now.',
  // The code form of a wall display (?kiosk=1), checked here before it is sent.
  display_code_shape:
    'That is not a display code. A display code has 26 letters and digits, in groups of five, as goblin-admin display code printed it.',
  display_code_check:
    'That code has a typo: its last character does not match the others. Check it and type it again.',
  // The code form's own texts where the password form's speak of a password (B6 design §7.7).
  display_https_required:
    "A wall display signs in over HTTPS, or on the Uptime Goblin computer. Open Uptime Goblin's HTTPS address on this display, followed by /?kiosk=1.",
  display_plain_http:
    'This address is not HTTPS, so the code crosses the network unencrypted. Uptime Goblin accepts it because plain-HTTP sign-in is turned on for this server.',
});
const lockedText = seconds => `Too many attempts. You can try again in ${seconds} s.`;

// The names Uptime Goblin counts as this computer in a Host header (isLoopbackHost() in
// lib/http/transport.mjs): localhost, 127.0.0.0/8 and [::1], with or without a port.
const loopbackHost = host =>
  typeof host === 'string' &&
  /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?$/i.test(host);

/**
 * True when Uptime Goblin treats this browser as plain HTTP (`http`). So does a `loopback` answer to a
 * page whose own address (`host`) is not a loopback name: Uptime Goblin saw a loopback Host, so the
 * request came through a proxy on the Uptime Goblin host that sends no forwarding headers and keeps a
 * loopback Host (nginx's default with a bare proxy_pass), and the login route treats it as
 * plain HTTP (sessionTransport() in lib/http/routes/auth.mjs).
 */
function plainTransport(transport, host) {
  return transport.kind === 'http' || (transport.kind === 'loopback' && !loopbackHost(host));
}

/**
 * The code Uptime Goblin will refuse any sign-in from this browser with, from the `transport` of
 * Uptime Goblin's 401, or null. The fix depends on what the browser itself uses (`protocol` and `host`,
 * this page's by default).
 */
function transportRefusal(transport, protocol = location.protocol, host = location.host) {
  if (!transport || typeof transport !== 'object') return null;
  if (plainTransport(transport, host) && !transport.insecureAllowed)
    return protocol === 'https:' ? 'proxy_proto_missing' : 'https_required';
  if (transport.kind === 'https' && protocol === 'http:') return 'proxy_proto_mismatch';
  return null;
}

/** What the sign-in view says before any attempt when Uptime Goblin will refuse (transportRefusal()). */
export function transportNotice(transport, protocol = location.protocol, host = location.host) {
  const code = transportRefusal(transport, protocol, host);
  return code ? signInTexts[code] : '';
}

/**
 * The refusal when this page itself is plain HTTP (https_required, proxy_proto_mismatch), or
 * null. Uptime Goblin refuses the sign-in only after it has the password, which has then crossed the
 * network unencrypted, so no form asks for it: neither the sign-in view nor the sign-in dialog.
 * Behind a proxy that does not say the browser uses HTTPS (proxy_proto_missing), the browser's
 * own connection is encrypted, and the form stays to show the refusal.
 */
export function refusedInClear(transport, protocol = location.protocol, host = location.host) {
  const code = transportRefusal(transport, protocol, host);
  return code === 'https_required' || code === 'proxy_proto_mismatch' ? code : null;
}

/**
 * What the sign-in view says above the form when Uptime Goblin allows sign-in over plain HTTP
 * (GOBLIN_INSECURE_HTTP_SESSIONS) and this page reaches it that way over the network: the
 * password is about to cross it unencrypted. A page at a loopback name is warned of nothing:
 * the browser reaches Uptime Goblin on its own computer, directly, through Docker Compose's published
 * port (which Uptime Goblin sees as `http`) or through an ssh tunnel, which encrypts.
 */
export function plainHttpWarning(transport, protocol = location.protocol, host = location.host) {
  if (!transport || typeof transport !== 'object' || !transport.insecureAllowed) return '';
  return protocol === 'http:' && !loopbackHost(host) && plainTransport(transport, host)
    ? signInTexts.plain_http
    : '';
}

/** transportNotice() for the code form of a wall display. */
export function displayTransportNotice(transport) {
  const code = transportRefusal(transport);
  if (!code) return '';
  return code === 'https_required' ? signInTexts.display_https_required : signInTexts[code];
}

/** plainHttpWarning() for the code form of a wall display. */
export function displayPlainHttpWarning(transport) {
  return plainHttpWarning(transport) ? signInTexts.display_plain_http : '';
}

/** `text` as it reads where it is shown as it is (textContent): its `quoted` parts unquoted. */
export const plainText = text => String(text).replaceAll('`', '');

/** Puts `text` into `element`, showing `quoted` parts as code. Nothing is parsed as HTML. */
export function showText(element, text) {
  element.replaceChildren(
    ...String(text)
      .split('`')
      .map((part, index) => {
        if (index % 2 === 0) return document.createTextNode(part);
        const code = document.createElement('code');
        code.textContent = part;
        return code;
      })
  );
}

// The two password forms, and the wall display's code form (`display`, on ?kiosk=1).
const prefixes = { view: 'signin', dialog: 'reauth', display: 'display' };
/** The elements of one of the forms. */
function parts(kind) {
  const at = name => $(`#${prefixes[kind]}-${name}`);
  return {
    form: at('form'),
    login: at('login'),
    password: at('password'),
    remember: at('remember'),
    code: at('code'),
    error: at('error'),
    countdown: at('countdown'),
    submit: at('submit'),
  };
}
// Per form: an attempt on its way, and a lockout countdown.
const pending = { view: false, dialog: false, display: false };
const lockouts = { view: null, dialog: null, display: null };

// A display code (B6 design §7.1): 25 symbols of Crockford base32 and a check symbol. Typed as
// printed or not: letter case, spaces and hyphens do not matter, and I and L read as 1, O as 0,
// as Uptime Goblin reads them (displayCodeHash() in lib/identity/secrets.mjs). The check is the copy of
// lib/identity/display-code.mjs: plain arithmetic, so it runs on plain HTTP too.
const displayAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** Multiplication in GF(2^5) with x^5 + x^2 + 1. */
function times(a, b) {
  let product = 0;
  for (; b; b >>= 1) {
    if (b & 1) product ^= a;
    a <<= 1;
    if (a & 32) a ^= 0b100101;
  }
  return product;
}
/** The check symbol of 25 data symbols: Σ α^(i+1)·d_i with α = x. */
export function checkSymbol(data) {
  let sum = 0,
    weight = 1;
  for (const symbol of data) {
    weight = times(weight, 2);
    sum ^= times(weight, displayAlphabet.indexOf(symbol));
  }
  return displayAlphabet[sum];
}
/** The 26 symbols of `input`, or null when it cannot be a display code. */
export function displaySymbols(input) {
  if (typeof input !== 'string' || input.length > 64) return null;
  const symbols = input
    .normalize('NFKC')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
  if (symbols.length !== 26 || [...symbols].some(c => !displayAlphabet.includes(c))) return null;
  return symbols;
}
/** Why `input` is not a display code (a text of signInTexts), or ''. */
export function displayCodeProblem(input) {
  const symbols = displaySymbols(input);
  if (!symbols) return signInTexts.display_code_shape;
  return checkSymbol(symbols.slice(0, 25)) === symbols[25] ? '' : signInTexts.display_code_check;
}

function showError(f, text) {
  showText(f.error, text);
  f.error.hidden = !text;
}

/**
 * Readies a form before it is shown: the error and the password are cleared, and `login` and
 * `remember` filled in. A lockout still counting down keeps its countdown.
 */
export function prepareForm(kind, { login = '', remember = false } = {}) {
  const f = parts(kind);
  if (!lockouts[kind]) showError(f, '');
  f.login.value = login;
  f.password.value = '';
  f.remember.checked = remember;
}

/**
 * Refuses attempts for `seconds`: the alert says so once, and a countdown outside it (not
 * announced every second) counts down until the Sign in button works again.
 */
function lockOut(kind, seconds) {
  const f = parts(kind);
  clearInterval(lockouts[kind]?.timer);
  const until = Date.now() + seconds * 1000;
  showError(f, lockedText(seconds));
  f.submit.disabled = true;
  const tick = () => {
    const left = Math.ceil((until - Date.now()) / 1000);
    if (left > 0) {
      f.countdown.textContent = `You can try again in ${left} s.`;
      f.countdown.hidden = false;
      return;
    }
    clearInterval(lockouts[kind]?.timer);
    lockouts[kind] = null;
    f.countdown.hidden = true;
    f.countdown.textContent = '';
    f.submit.disabled = false;
    // Focus stays where it is (the password field): only the alert changes.
    showError(f, signInTexts.again);
  };
  lockouts[kind] = { timer: setInterval(tick, 1000) };
  tick();
}

/** The text for a failed attempt. */
function failureText(error) {
  if (error.status === undefined) return signInTexts.network;
  // A 401 without a code: Uptime Goblin was rolled back to a release before 1.5, which cannot sign this
  // page in whatever the password, and its own words ("Sign in to Uptime Goblin") would read as a wrong
  // one. api() reported the change of release; reloading is the way in.
  if (error.status === 401 && error.code === undefined) return olderReleaseText;
  // Uptime Goblin's own messages for a busy sign-in or a full disk say what to do; so do others.
  return signInTexts[error.code] ?? error.message;
}

async function submit(kind, event) {
  // First, before anything that could fail: the browser must never submit the form itself.
  event.preventDefault();
  const f = parts(kind);
  if (pending[kind] || lockouts[kind]) return;
  pending[kind] = true;
  f.submit.disabled = true;
  showError(f, '');
  let body = null,
    failure = null;
  try {
    await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        login: f.login.value,
        password: f.password.value,
        remember: f.remember.checked,
      }),
      signIn: false,
    });
    // Uptime Goblin set the cookie. Whether the browser kept it shows only in the next answer: a
    // Secure cookie on a plain-HTTP page, or a browser that blocks cookies, drops it.
    try {
      body = await api('/api/session', { signIn: false });
    } catch (error) {
      failure =
        error.status === 401 && ['signin_required', 'session_expired'].includes(error.code)
          ? { text: signInTexts.cookie_not_stored }
          : { text: failureText(error), error };
    }
  } catch (error) {
    failure = { text: failureText(error), error };
  } finally {
    pending[kind] = false;
    f.submit.disabled = false;
  }
  // The password is no longer needed, unless Uptime Goblin did not answer and it may be sent again.
  if (!(failure?.error && failure.error.status === undefined)) f.password.value = '';
  if (body) {
    signedIn(kind, body);
    return;
  }
  if (failure.error?.code === 'locked') lockOut(kind, failure.error.retryAfter || 60);
  else showError(f, failure.text);
  f.password.focus();
}

// Refusals of a display code whose text Uptime Goblin's answer carries: the transport ones say that
// Uptime Goblin cancelled the code, which the password form's texts for those codes do not.
const codeRefusals = new Set([
  'display_code_invalid',
  'https_required',
  'proxy_proto_missing',
  'proxy_proto_mismatch',
  'invalid_request',
]);

/**
 * Signs this browser in as a wall display with the code typed into the code form: one attempt
 * is POST /api/auth/login with {code, display: true}, then GET /api/session, as for a password.
 */
async function submitCode(event) {
  event.preventDefault();
  const f = parts('display');
  if (pending.display || lockouts.display) return;
  pending.display = true;
  f.submit.disabled = true;
  showError(f, '');
  let body = null,
    failure = null;
  try {
    const problem = displayCodeProblem(f.code.value);
    if (problem) failure = { text: problem };
    else {
      await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ code: f.code.value, display: true }),
        signIn: false,
      });
      try {
        body = await api('/api/session', { signIn: false });
      } catch (error) {
        failure =
          error.status === 401 && ['signin_required', 'session_expired'].includes(error.code)
            ? { text: signInTexts.cookie_not_stored }
            : { text: failureText(error), error };
      }
    }
  } catch (error) {
    failure = {
      text: codeRefusals.has(error.code) && error.message ? error.message : failureText(error),
      error,
    };
  } finally {
    pending.display = false;
    f.submit.disabled = false;
  }
  if (body) {
    f.code.value = '';
    signedIn('view', body);
    return;
  }
  // A code Uptime Goblin refused is used up, expired or cancelled: it is no use typing it again. One
  // that did not reach Uptime Goblin, or that this page found mistyped, stays to be corrected.
  if (failure.error && failure.error.status !== undefined && failure.error.code !== 'locked')
    f.code.value = '';
  if (failure.error?.code === 'locked') lockOut('display', failure.error.retryAfter || 60);
  else showError(f, failure.text);
  f.code.focus();
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  for (const kind of ['view', 'dialog'])
    parts(kind).form.addEventListener('submit', event => submit(kind, event));
  parts('display').form.addEventListener('submit', submitCode);
}
