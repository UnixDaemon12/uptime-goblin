// The admin password of the tests that start a whole Uptime Goblin (createApp, startOrbit or
// `node server.mjs`). Uptime Goblin always requires one (it refuses to start without auth.json or
// GOBLIN_PASSWORD), so these tests give it this one, and their requests sign in with it as a
// script does: legacy Basic, which test/setup.mjs turns on (GOBLIN_LEGACY_BASIC=1).

/** A fixture password, never a real one: 12 characters or more, as GOBLIN_PASSWORD needs. */
export const adminPassword = 'fixture-admin-password';

/** The Authorization value that signs a script in as `admin` with `password`. */
export const basicAuth = (password = adminPassword) =>
  'Basic ' + Buffer.from(`admin:${password}`).toString('base64');

/** The headers of a script signed in as the admin. */
export const adminHeaders = (password = adminPassword) => ({ Authorization: basicAuth(password) });

/**
 * fetch() as a script signed in as the admin: the Authorization header is added unless
 * `init.headers` gives its own.
 */
export const adminFetch = (url, init = {}) =>
  fetch(url, { ...init, headers: { ...adminHeaders(), ...init.headers } });
