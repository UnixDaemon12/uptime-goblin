// Configuration diffs (audit spec D11): what a config.json write or a hand edit changed, by leaf
// path, with no secret in it.
//
// A snapshot is built from publicConfig(config.value): the parsed and repaired value (never the
// raw file), without its secrets. Its leaves are paths (`title`, `email.host`,
// `services.<id>.url`: sources by id, never by index; arrays are one leaf, compared whole),
// without `revision`, `sourceCounters` and the *Configured flags. Every text that parses as a URL
// is stripped of its user info and of the parameters parseConfig counts as credentials
// (withoutCredentials, secretName) before it is compared or stored, so a hand edit that put a
// token in a URL never reaches the log. The secrets (email.password, each source's apiKey and
// password, and any other leaf whose name looks like one) are kept only as HMACs under the audit
// key, so a change from one secret to another shows as `changed` although publicConfig shows
// both as "configured", and the diff names them only as {path, change}.
//
//   const before = configSnapshot(config.value, {kid, mac});   // {revision, public, secrets}
//   … the write …
//   const diff = configDiff(before, configSnapshot(config.value, {kid, mac}));
//
// config.json holds those secrets in plain text already, so a keyed HMAC of them adds no exposure;
// the first 32 hex digits are kept (meta.audit_config_secrets, §3.4).
import { publicConfig } from '../catalog.mjs';
import { withoutCredentials } from '../config.mjs';
import { VALUE_MAX_CHARS } from './actions.mjs';
import { canonicalJSON } from './chain.mjs';

/** Leaf names that hold a secret, besides publicConfig's own (D11). */
export const secretLeaf =
  /pass|secret|token|apikey|api_key|credential|private|webhook|cookie|session|bearer/i;
// The secrets publicConfig removes: the raw values come from config.value itself.
const rawSecrets = value => {
  const found = {};
  if (value?.email && typeof value.email === 'object')
    found['email.password'] = value.email.password;
  for (const service of Array.isArray(value?.services) ? value.services : []) {
    if (!service || typeof service !== 'object' || typeof service.id !== 'string') continue;
    found[`services.${service.id}.apiKey`] = service.apiKey;
    found[`services.${service.id}.password`] = service.password;
  }
  return found;
};
const leftOutTop = new Set(['revision', 'sourceCounters']);

/**
 * `text` without credentials when it is a URL that carries some (user info, or parameters and
 * fragment pairs whose names look like credentials); otherwise `text` unchanged, so a value that
 * merely parses as a URL (a time zone such as UTC+05:30) keeps its spelling.
 */
export function withoutUrlCredentials(text) {
  let url;
  try {
    url = new URL(text);
  } catch {
    return text;
  }
  let changed = false;
  if (url.username || url.password) {
    url.username = '';
    url.password = '';
    changed = true;
  }
  let href = url.href;
  try {
    const stripped = withoutCredentials(href);
    if (stripped !== href) {
      href = stripped;
      changed = true;
    }
  } catch {}
  return changed ? href : text;
}

// A leaf value as the snapshot keeps it: plain JSON data that canonical JSON accepts. URLs are
// stripped (also inside a list), a number that is not a safe integer (a threshold such as 85.5)
// is kept as its JSON text, and text is made well-formed (review round 2): config.json may hold
// a lone surrogate (the JSON escape \ud800 passes its validation), which canonical JSON refuses,
// and every snapshot is canonicalised (the drift keys, the start's comparison).
function leafValue(value) {
  if (value === undefined) return null;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return withoutUrlCredentials(value).toWellFormed();
  if (typeof value === 'number') return Number.isSafeInteger(value) ? value : JSON.stringify(value);
  if (Array.isArray(value)) return value.map(leafValue);
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort())
      if (value[key] !== undefined) out[key] = leafValue(value[key]);
    return out;
  }
  return String(value);
}
const isEmptySecret = value => value === undefined || value === null || value === '';
const secretText = value => (typeof value === 'string' ? value : canonicalJSON(leafValue(value)));

/**
 * The snapshot of a configuration value: {revision, public: {path: value}, secrets: {key_id,
 * macs: {path: 32 hex}}}. `kid` and `mac(data)` are the audit key's (data => keyring.hmac('audit',
 * data, kid).mac); a secret's MAC covers "config-secret\n<path>\n<value>", so equal values at
 * different paths do not compare equal. Only non-empty secrets get a MAC.
 */
export function configSnapshot(value, { kid, mac }) {
  const pub = {},
    secrets = {};
  const visit = (node, path) => {
    for (const key of Object.keys(node)) {
      const item = node[key];
      if (item === undefined || key.endsWith('Configured')) continue;
      const at = path ? `${path}.${key}` : key;
      if (secretLeaf.test(key)) secrets[at] = item;
      else if (item !== null && typeof item === 'object' && !Array.isArray(item)) visit(item, at);
      else pub[at] = leafValue(item);
    }
  };
  const shown = publicConfig(value ?? { services: [] });
  for (const key of Object.keys(shown)) {
    if (leftOutTop.has(key) || key.endsWith('Configured')) continue;
    const item = shown[key];
    if (key === 'services' && Array.isArray(item)) {
      for (const service of item)
        if (service && typeof service === 'object' && typeof service.id === 'string')
          visit(service, `services.${service.id}`);
    } else if (secretLeaf.test(key)) secrets[key] = item;
    else if (item !== null && typeof item === 'object' && !Array.isArray(item)) visit(item, key);
    else if (item !== undefined) pub[key] = leafValue(item);
  }
  Object.assign(secrets, rawSecrets(value));
  const macs = {};
  for (const path of Object.keys(secrets).sort())
    if (!isEmptySecret(secrets[path]))
      macs[path] = mac(`config-secret\n${path}\n${secretText(secrets[path])}`).slice(0, 32);
  const sorted = {};
  for (const path of Object.keys(pub).sort()) sorted[path] = pub[path];
  return {
    revision: Number.isSafeInteger(value?.revision) ? value.revision : null,
    public: sorted,
    secrets: { key_id: kid, macs },
  };
}

// A value as a diff shows it: at most 200 characters, its JSON text when it is not text, "…"
// marking a cut (199 characters and the mark, so the writer's own cut at 200 keeps the mark).
function shownValue(value) {
  if (value === undefined) return null;
  const cut = text => {
    const points = Array.from(text);
    return points.length <= VALUE_MAX_CHARS
      ? text
      : `${points.slice(0, VALUE_MAX_CHARS - 1).join('')}…`;
  };
  if (typeof value === 'string') return cut(value);
  if (value === null || typeof value !== 'object') return value;
  const text = canonicalJSON(value);
  return Array.from(text).length <= VALUE_MAX_CHARS ? value : cut(text);
}

/**
 * The changes from snapshot `before` to `after`, sorted by path: {path, from, to} for public
 * leaves (null for a leaf one side lacks), {path, change: set | changed | cleared} for secrets,
 * or `unknown` where both sides hold a secret signed by different keys and the earlier key is
 * gone (a lost-key reset), so the two cannot be compared.
 */
export function configDiff(before, after, { comparable = true } = {}) {
  const changes = [];
  const was = before?.public ?? {},
    now = after?.public ?? {};
  for (const path of new Set([...Object.keys(was), ...Object.keys(now)])) {
    const from = was[path],
      to = now[path];
    if (canonicalJSON(from ?? null) === canonicalJSON(to ?? null)) continue;
    changes.push({ path, from: shownValue(from), to: shownValue(to) });
  }
  const wasMacs = before?.secrets?.macs ?? {},
    nowMacs = after?.secrets?.macs ?? {};
  const sameKey =
    comparable && (before?.secrets?.key_id ?? null) === (after?.secrets?.key_id ?? null);
  for (const path of new Set([...Object.keys(wasMacs), ...Object.keys(nowMacs)])) {
    const from = wasMacs[path],
      to = nowMacs[path];
    if (from && !to) changes.push({ path, change: 'cleared' });
    else if (!from && to) changes.push({ path, change: 'set' });
    else if (!sameKey) changes.push({ path, change: 'unknown' });
    else if (from !== to) changes.push({ path, change: 'changed' });
  }
  return changes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Whether two snapshots hold the same content (the revision aside). */
export const sameContent = (a, b) =>
  canonicalJSON(a?.public ?? {}) === canonicalJSON(b?.public ?? {}) &&
  (a?.secrets?.key_id ?? null) === (b?.secrets?.key_id ?? null) &&
  canonicalJSON(a?.secrets?.macs ?? {}) === canonicalJSON(b?.secrets?.macs ?? {});
