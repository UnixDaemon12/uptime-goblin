// Signing in to a real Uptime Goblin as the web app does (sessions spec §8.1): the same-origin browser
// headers a page sends, and the session cookie from the answer. Node's fetch sends no
// Sec-Fetch-Site of its own, so these helpers add it (and X-Goblin-Client): without them a
// request is a script's, whose Basic credential is evaluated and whose cookie writes need the
// Origin rules below just the same.
import assert from 'node:assert/strict';

/**
 * The headers Uptime Goblin's own page sends from `baseUrl` (a same-origin JSON request). `client`
 * is the X-Goblin-Client value (`web/<build>` in the real page).
 */
export function browserHeaders(baseUrl, { client = 'web/test' } = {}) {
  return {
    Origin: new URL(baseUrl).origin,
    'Sec-Fetch-Site': 'same-origin',
    'X-Goblin-Request': '1',
    'X-Goblin-Client': client,
    'Content-Type': 'application/json',
  };
}

/** The `name=value` pair of the session cookie among Set-Cookie values, or null. */
export function sessionPair(setCookies) {
  for (const line of setCookies ?? []) {
    const pair = line.split(';')[0];
    const name = pair.slice(0, pair.indexOf('='));
    if (
      (name === 'goblin_session' || name === '__Host-goblin_session') &&
      pair.length > name.length + 1
    )
      return pair;
  }
  return null;
}

/**
 * Signs in at `baseUrl` with `password` (login `admin`) and resolves to `{cookie, body,
 * setCookie}`: `cookie` is the `name=value` pair to send back, `body` the GET /api/session
 * JSON the login answered with. A refused sign-in fails the calling test with its answer.
 */
export async function signIn(
  baseUrl,
  password,
  { remember = false, headers = {}, login = 'admin' } = {}
) {
  const response = await fetch(new URL('/api/auth/login', baseUrl), {
    method: 'POST',
    headers: { ...browserHeaders(baseUrl), ...headers },
    body: JSON.stringify({ login, password, ...(remember ? { remember: true } : {}) }),
  });
  const text = await response.text();
  assert.equal(response.status, 200, `sign-in refused: ${response.status} ${text}`);
  const setCookie = response.headers.getSetCookie();
  const cookie = sessionPair(setCookie);
  assert.ok(cookie, `sign-in set no session cookie: ${JSON.stringify(setCookie)}`);
  return { cookie, body: JSON.parse(text), setCookie };
}

/**
 * A caller of Uptime Goblin's API as a signed-in page: `(route, method = 'GET', body, headers = {})`
 * resolves to `{status, headers, body}` (the body parsed when it is JSON). Every request carries
 * `cookie` and the browser headers of browserHeaders().
 */
export function sessionCall(baseUrl, cookie) {
  return async (route, method = 'GET', body, headers = {}) => {
    const response = await fetch(new URL(route, baseUrl), {
      method,
      headers: {
        ...browserHeaders(baseUrl),
        ...(cookie ? { Cookie: cookie } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let value = text;
    try {
      value = JSON.parse(text);
    } catch {}
    return { status: response.status, headers: response.headers, body: value };
  };
}
