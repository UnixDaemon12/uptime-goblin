// Uptime Kuma 1.x backups (Settings → Backup → Export JSON), shared by the browser
// (public/modules/configure/kuma-import.js) and the server (lib/import/uptime-kuma.mjs), so
// both read a backup the same way. No DOM, no eval, nothing fetched.
//
// readKumaBackup() checks a parsed backup strictly and returns its monitors as plain values;
// reduceKumaBackup() keeps only the fields the import reads, in the backup's own shape, with
// every credential value replaced by "redacted" and an address's credentials removed (marked
// `goblinAddressCredentials: true`). The web app sends the reduced backup, so no password,
// header, certificate or address credential of a monitor leaves the browser, and a backup of
// hundreds of monitors fits the API's request limit. A backup and its reduction give the same
// plan (test/kuma-import.test.mjs).
import { withoutCredentials } from './url-credentials.js';

/** A backup file the web app reads at most (it sends only the reduced backup). */
export const KUMA_FILE_MAX_BYTES = 8 * 1024 * 1024;
/** The most monitors (groups included) one backup may list. */
export const KUMA_MONITORS_MAX = 1000;
// The longest texts a monitor may hold; a monitor with a longer one is skipped as malformed.
const NAME_MAX = 1000,
  URL_MAX = 4096,
  KEYWORD_MAX = 1000,
  TYPE_MAX = 64,
  METHOD_MAX = 16,
  STATUSES_MAX = 50,
  STATUS_MAX = 20;

/** A backup that cannot be imported at all; its message is fixed text, safe to show. */
export class KumaBackupError extends Error {}

// The monitor fields that can hold a credential, or a request part that may carry one (headers,
// a body, client certificates, OAuth). None is ever read for its value.
export const KUMA_CREDENTIAL_FIELDS = Object.freeze([
  'basic_auth_user',
  'basic_auth_pass',
  'authDomain',
  'authWorkstation',
  'headers',
  'body',
  'oauth_client_id',
  'oauth_client_secret',
  'tlsCert',
  'tlsKey',
  'tlsCa',
]);
// Secrets a monitor sends whatever its authMethod says, so each marks the monitor when it holds
// anything.
const SECRET_FIELDS = ['basic_auth_pass', 'oauth_client_secret', 'tlsKey', 'headers', 'body'];
// Kuma's authMethod values, each with the fields it sends. authMethod only selects a mode, and
// Kuma's editor saves defaults for modes a monitor does not use (oauth_auth_method
// "client_secret_basic" on every monitor since 1.23), so a field marks the monitor only in its
// own mode. oauth_auth_method, oauth_token_url and oauth_scopes select or describe; they hold no
// secret and are never read.
const AUTH_MODES = Object.freeze({
  basic: ['basic_auth_user', 'basic_auth_pass'],
  ntlm: ['basic_auth_user', 'basic_auth_pass', 'authDomain', 'authWorkstation'],
  mtls: ['tlsCert', 'tlsKey', 'tlsCa'],
  'oauth2-cc': ['oauth_client_id', 'oauth_client_secret'],
});
// Before authMethod (Kuma releases that do not save it, or save it as null), Kuma sent HTTP basic
// authentication whenever basic_auth_user held a name, so then a user name alone marks a monitor.
const LEGACY_AUTH_FIELDS = ['basic_auth_user'];
/** A Kuma authMethod value Uptime Goblin knows, or null (none, absent or unknown). */
const authMode = value =>
  typeof value === 'string' && Object.hasOwn(AUTH_MODES, value) ? value : null;
// The other fields the import reads.
const readFields = [
  'id',
  'name',
  'type',
  'url',
  'method',
  'interval',
  'active',
  'parent',
  'accepted_statuscodes',
  'keyword',
  'invertKeyword',
  'maxredirects',
  'ignoreTls',
  'upsideDown',
  'proxyId',
];

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);
const absent = value => value === undefined || value === null;
// Kuma's SQLite flags arrive as true/false or 1/0.
const flag = value =>
  absent(value)
    ? false
    : value === true || value === 1
      ? true
      : value === false || value === 0
        ? false
        : null;

// Names JSON.parse keeps as ordinary members but a later copy would follow to a prototype: no
// Kuma backup has them, so one that does is refused.
function refuseForbidden(object, where) {
  for (const key of Object.keys(object))
    if (['__proto__', 'constructor', 'prototype'].includes(key))
      throw new KumaBackupError(`The backup has a field named ${key} in ${where}.`);
}

/**
 * An HTTP(S) address without credentials: `{url, stripped}`, where `stripped` says whether a user
 * name, password or credential-like parameter (?token=, #access_token=) was removed (the address
 * is then normalized); null for text that is not an HTTP(S) URL.
 */
export function cleanAddress(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(u.protocol)) return null;
  let stripped = false;
  if (u.username || u.password) {
    u.username = '';
    u.password = '';
    stripped = true;
  }
  const url = stripped ? u.href : raw,
    clean = withoutCredentials(url);
  return clean !== new URL(url).href ? { url: clean, stripped: true } : { url, stripped };
}

/** Whether a credential field holds something (any non-empty value). */
function present(value) {
  if (absent(value) || value === false) return false;
  if (typeof value === 'string') return value.trim() !== '' && value.trim() !== '{}';
  if (Array.isArray(value)) return value.length > 0;
  if (plain(value)) return Object.keys(value).length > 0;
  return true;
}

/** One monitor as plain values, or with `problem` saying why it cannot be read. */
function readMonitor(entry, index) {
  const monitor = {
    id: null,
    name: '',
    type: '',
    url: '',
    method: 'GET',
    interval: null,
    active: true,
    parent: null,
    accepted: [],
    keyword: false,
    maxRedirects: 10,
    ignoreTls: false,
    upsideDown: false,
    proxied: false,
    credentials: false,
    addressCredentials: false,
    problem: null,
  };
  const fail = problem => Object.assign(monitor, { problem });
  if (!plain(entry)) return fail(`Entry ${index + 1} is not a monitor`);
  refuseForbidden(entry, `monitor ${index + 1}`);
  const id = own(entry, 'id');
  if (!Number.isSafeInteger(id) || id < 1) return fail('It has no valid id');
  monitor.id = id;
  const name = own(entry, 'name');
  if (typeof name !== 'string') return fail('It has no name');
  if (name.length > NAME_MAX) {
    monitor.name = name.slice(0, 200);
    return fail(`Its name is longer than ${NAME_MAX} characters`);
  }
  monitor.name = name;
  const type = own(entry, 'type');
  if (typeof type !== 'string' || !type || type.length > TYPE_MAX) return fail('It has no type');
  monitor.type = type;
  const url = own(entry, 'url');
  if (!absent(url)) {
    if (typeof url !== 'string') return fail('Its address is not text');
    if (url.length > URL_MAX) return fail(`Its address is longer than ${URL_MAX} characters`);
    monitor.url = url.trim();
  }
  const method = own(entry, 'method');
  if (!absent(method)) {
    if (typeof method !== 'string' || method.length > METHOD_MAX)
      return fail('Its HTTP method is not valid');
    monitor.method = method.trim().toUpperCase() || 'GET';
  }
  const interval = own(entry, 'interval');
  if (!absent(interval)) {
    if (typeof interval !== 'number' || !Number.isFinite(interval))
      return fail('Its interval is not a number');
    monitor.interval = interval;
  }
  const parent = own(entry, 'parent');
  if (!absent(parent)) {
    if (!Number.isSafeInteger(parent) || parent < 1) return fail('Its group is not valid');
    monitor.parent = parent;
  }
  const accepted = own(entry, 'accepted_statuscodes');
  if (!absent(accepted)) {
    if (
      !Array.isArray(accepted) ||
      accepted.length > STATUSES_MAX ||
      accepted.some(code => typeof code !== 'string' || code.length > STATUS_MAX)
    )
      return fail('Its accepted status codes are not valid');
    monitor.accepted = accepted.map(code => code.trim());
  }
  const keyword = own(entry, 'keyword');
  if (!absent(keyword)) {
    if (typeof keyword !== 'string' || keyword.length > KEYWORD_MAX)
      return fail('Its keyword is not valid');
    monitor.keyword = keyword !== '';
  }
  const redirects = own(entry, 'maxredirects');
  if (!absent(redirects)) {
    if (!Number.isSafeInteger(redirects) || redirects < 0)
      return fail('Its redirect limit is not valid');
    monitor.maxRedirects = redirects;
  }
  const proxy = own(entry, 'proxyId');
  if (!absent(proxy)) {
    if (!Number.isSafeInteger(proxy) || proxy < 0) return fail('Its proxy is not valid');
    monitor.proxied = proxy > 0;
  }
  for (const [field, key] of [
    ['active', 'active'],
    ['ignoreTls', 'ignoreTls'],
    ['upsideDown', 'upsideDown'],
  ]) {
    const value = flag(own(entry, field));
    if (value === null) return fail(`Its ${field} setting is not valid`);
    // A monitor without `active` is one Kuma runs.
    monitor[key] = field === 'active' && absent(own(entry, field)) ? true : value;
  }
  if (flag(own(entry, 'invertKeyword')) === null)
    return fail('Its invertKeyword setting is not valid');
  // Set by reduceKumaBackup() on an address it removed credentials from.
  monitor.addressCredentials = own(entry, 'goblinAddressCredentials') === true;
  const mode = authMode(own(entry, 'authMethod'));
  monitor.credentials =
    SECRET_FIELDS.some(field => present(own(entry, field))) ||
    (mode !== null && AUTH_MODES[mode].some(field => present(own(entry, field)))) ||
    (absent(own(entry, 'authMethod')) &&
      LEGACY_AUTH_FIELDS.some(field => present(own(entry, field))));
  return monitor;
}

/**
 * Checks a parsed Uptime Kuma 1.x backup and returns `{version, monitors}`, every monitor of
 * `monitorList` in order (one that cannot be read carries `problem`). Throws KumaBackupError
 * when the value is not such a backup: not an object, no 1.x `version`, no `monitorList`
 * array, more than KUMA_MONITORS_MAX monitors, a field that reaches a prototype, or two
 * monitors with one id.
 */
export function readKumaBackup(value) {
  if (!plain(value)) throw new KumaBackupError('This is not an Uptime Kuma backup.');
  refuseForbidden(value, 'the backup');
  const version = own(value, 'version');
  if (typeof version !== 'string')
    throw new KumaBackupError('This is not an Uptime Kuma backup: it names no version.');
  if (!/^1\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.-]{1,40})?$/.test(version))
    throw new KumaBackupError(
      /^[0-9A-Za-z.+-]{1,40}$/.test(version)
        ? `Only Uptime Kuma 1.x backups can be imported; this one is from version ${version}.`
        : 'Only Uptime Kuma 1.x backups can be imported.'
    );
  const list = own(value, 'monitorList');
  if (!Array.isArray(list))
    throw new KumaBackupError('This is not an Uptime Kuma backup: it has no monitor list.');
  if (list.length > KUMA_MONITORS_MAX)
    throw new KumaBackupError(
      `The backup lists ${list.length} monitors; at most ${KUMA_MONITORS_MAX} can be imported at once.`
    );
  const monitors = list.map(readMonitor),
    ids = new Set();
  for (const monitor of monitors) {
    if (monitor.id === null) continue;
    if (ids.has(monitor.id))
      throw new KumaBackupError(`The backup lists monitor id ${monitor.id} twice.`);
    ids.add(monitor.id);
  }
  return { version, monitors };
}

/**
 * The backup with only what readKumaBackup() reads: its version and, for each monitor, the read
 * fields as they are (a text longer than its limit cut to one character more, so it is still
 * refused as too long), a known authMethod, and "redacted" for each credential field that holds
 * anything. Throws
 * KumaBackupError as readKumaBackup() does.
 */
export function reduceKumaBackup(value) {
  readKumaBackup(value);
  const limits = {
    name: NAME_MAX,
    url: URL_MAX,
    keyword: KEYWORD_MAX,
    type: TYPE_MAX,
    method: METHOD_MAX,
  };
  // A value of the wrong kind keeps its kind, not its size: still refused, for the same reason.
  const small = (item, limit) =>
    typeof item === 'string'
      ? item.slice(0, limit + 1)
      : Array.isArray(item)
        ? []
        : plain(item)
          ? {}
          : item;
  const cut = (field, item) =>
    field === 'accepted_statuscodes' && Array.isArray(item)
      ? item.slice(0, STATUSES_MAX + 1).map(code => small(code, STATUS_MAX))
      : small(item, limits[field] ?? 0);
  return {
    version: value.version,
    monitorList: value.monitorList.map(entry => {
      if (!plain(entry)) return null;
      const reduced = {};
      for (const field of readFields)
        if (Object.hasOwn(entry, field)) reduced[field] = cut(field, entry[field]);
      if (typeof reduced.url === 'string') {
        // Only what the import needs of an address, so none of its credentials is sent: one
        // too long, or not an HTTP(S) URL, keeps only what decides its reason.
        const raw = reduced.url.trim(),
          address = raw && reduced.url.length <= URL_MAX ? cleanAddress(raw) : null;
        if (reduced.url.length > URL_MAX) reduced.url = 'x'.repeat(URL_MAX + 1);
        else if (address) {
          reduced.url = address.url;
          if (address.stripped) reduced.goblinAddressCredentials = true;
        } else if (raw) reduced.url = /^[a-z][a-z0-9+.-]*:/i.exec(raw)?.[0] ?? 'invalid';
      }
      if (entry.goblinAddressCredentials === true) reduced.goblinAddressCredentials = true;
      // The mode is kept (it holds no secret and decides which fields count); an unknown one is
      // sent as "unknown", read as no mode, and an absent or null one stays absent (a user name
      // alone then counts).
      const mode = authMode(own(entry, 'authMethod'));
      if (mode !== null) reduced.authMethod = mode;
      else if (!absent(own(entry, 'authMethod'))) reduced.authMethod = 'unknown';
      for (const field of KUMA_CREDENTIAL_FIELDS)
        if (Object.hasOwn(entry, field) && present(entry[field])) reduced[field] = 'redacted';
      return reduced;
    }),
  };
}
