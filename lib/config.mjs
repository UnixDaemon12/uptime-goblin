import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  defaults,
  newService,
  definitions,
  emailDefaults,
  appearanceDefaults,
  monitoringDefaults,
  alertDefaults,
  collectorType,
  configured,
} from './catalog.mjs';
import { normalizeTimeZone } from './time.mjs';
import { printable } from './saved-data.mjs';
import { credentialParams, withoutCredentials } from '../public/shared/url-credentials.js';
// Shared with the browser (the Uptime Kuma import cleans addresses there before sending them).
export { secretName, withoutCredentials } from '../public/shared/url-credentials.js';
export class InputError extends Error {}
function text(value, key, max = 200) {
  if (typeof value !== 'string' || value.length > max || value.includes('\u0000'))
    throw new InputError(`Invalid ${key}`);
  return value;
}
// What one line of display text never holds: control characters (C0, DEL, C1), the line and
// paragraph separators, and the bidi embeddings, overrides and isolates (U+202A-U+202E,
// U+2066-U+2069). Names and labels reach emails, webhooks, the audit log and the page, where a
// line break forges a line and a direction override makes a source name read as another.
const notOneLine = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
/** text() for a single line of display text (see notOneLine). */
function line(value, key, max = 200) {
  if (notOneLine.test(text(value, key, max)))
    throw new InputError(
      `Invalid ${key}: use one line without control or text-direction characters`
    );
  return value;
}
/**
 * A saved single-line text without what notOneLine refuses: line breaks and other controls
 * become a space, direction controls are removed (they have no visible form of their own).
 */
function oneLine(value) {
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '');
}
/**
 * Makes every text value inside `saved` (objects and arrays, walked without recursion) whole:
 * half of a surrogate pair becomes U+FFFD, as it does wherever Uptime Goblin writes the text out as
 * UTF-8. Returns the places changed (services[0].rules[1].key), a level at a time; a member
 * name is shown only when it is a plain word. Member names are left as they are: one holding
 * such text names no setting (it is dropped or refused when the configuration is checked).
 */
function wholeTexts(saved) {
  const changed = [];
  const queue = [[saved, '']];
  for (let i = 0; i < queue.length; i++) {
    const [holder, where] = queue[i];
    const list = Array.isArray(holder);
    for (const [key, item] of Object.entries(holder)) {
      // JSON.parse keeps "__proto__" as a member no setting reads; assigning it would not.
      if (key === '__proto__') continue;
      const name = /^[\w-]{1,64}$/.test(key) ? key : '(field)';
      const place = list ? `${where}[${key}]` : where ? `${where}.${name}` : name;
      if (typeof item === 'string') {
        if (item.isWellFormed()) continue;
        holder[key] = item.toWellFormed();
        changed.push(place);
      } else if (item && typeof item === 'object') queue.push([item, place]);
    }
  }
  return changed;
}
function object(value, key) {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new InputError(`Expected ${key} settings`);
  return value;
}
function integer(value, key, min, max) {
  if (!Number.isInteger(value) || value < min || value > max)
    throw new InputError(`${key} must be ${min}–${max}`);
  return value;
}
function switches(input, out, keys) {
  for (const key of keys)
    if (input[key] !== undefined) {
      if (typeof input[key] !== 'boolean') throw new InputError(`${key} must be true or false`);
      out[key] = input[key];
    }
}
export function validateAppearance(input, old = appearanceDefaults()) {
  object(input, 'appearance');
  const out = { ...old };
  const enums = {
    accent: ['cyan', 'orange', 'blue', 'violet', 'amber', 'pink', 'green'],
    density: ['comfortable', 'compact'],
    columns: ['auto', '2', '3', '4'],
    defaultRange: ['1h', '6h', '24h', '7d', '30d'],
    sortBy: ['manual', 'name', 'status'],
    timeFormat: ['auto', '12h', '24h'],
  };
  for (const [key, values] of Object.entries(enums))
    if (input[key] !== undefined) {
      if (!values.includes(input[key])) throw new InputError(`Invalid ${key}`);
      out[key] = input[key];
    }
  switches(input, out, [
    'showSummary',
    'showPaused',
    'showUnconfigured',
    'openInNewTab',
    'reduceMotion',
  ]);
  if (input.timezone !== undefined) {
    // Only 'local', 'UTC', fixed offsets written UTC±HH:MM and region-based IANA names
    // (Europe/London): public/shared/timezone.js shows each of them in every browser engine.
    // ICU also accepts abbreviations (BST resolves to Dhaka, IST to Kolkata), bare offsets
    // and legacy aliases that Firefox or Safari reject, which blanked the dashboard.
    // UTC+00:00 is saved as UTC, which Orbit 1.4.2 also accepts.
    const timezone = normalizeTimeZone(text(input.timezone, 'time zone', 100).trim());
    if (!timezone)
      throw new InputError(
        'Choose local, UTC, an offset such as UTC+05:30 or UTC-08:00 (minutes 00, 15, 30 or 45), or a region-based IANA time zone such as Europe/London or America/Chicago'
      );
    out.timezone = timezone;
  }
  return out;
}
const monitoringRanges = [
  ['concurrency', 1, 8],
  ['timeoutSeconds', 5, 120],
  ['retryCount', 0, 3],
  ['retryDelaySeconds', 1, 30],
  ['availabilityFailures', 1, 10],
  ['availabilitySeconds', 0, 3600],
  ['recoverySuccesses', 1, 10],
  ['recoverySeconds', 0, 3600],
];
export function validateMonitoring(input, old = monitoringDefaults()) {
  object(input, 'monitoring');
  const out = { ...old };
  for (const [key, min, max] of monitoringRanges)
    if (input[key] !== undefined) out[key] = integer(input[key], key, min, max);
  return out;
}
export function validateAlerts(input, old = alertDefaults()) {
  object(input, 'alert');
  const out = { ...old };
  switches(input, out, [
    'enabled',
    'notifyOnAlert',
    'notifyOnRecovery',
    'notifyAvailability',
    'notifyMeasurements',
  ]);
  return out;
}
function sourceMonitoring(input, old = {}) {
  object(input, 'source monitoring');
  const out = { ...old };
  for (const [key, min, max] of monitoringRanges) {
    if (key === 'concurrency' || input[key] === undefined) continue;
    if (input[key] === null) delete out[key];
    else out[key] = integer(input[key], key, min, max);
  }
  return out;
}
function sourceAlerts(input, old = {}) {
  object(input, 'source notifications');
  const out = { ...old };
  for (const key of ['notifyAvailability', 'notifyMeasurements']) {
    if (input[key] === null) delete out[key];
    else switches(input, out, [key]);
  }
  return out;
}
export function safeUrl(value, key = 'URL') {
  text(value, key, 2048);
  if (!value) return '';
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new InputError(`${key} must be a complete HTTP or HTTPS URL`);
  }
  // Checked on the raw text too: a bare '?' or '#' leaves search and hash empty but still
  // breaks every request path built from the address.
  if (
    !['http:', 'https:'].includes(u.protocol) ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    /[?#]/.test(value)
  )
    throw new InputError(
      `${key} must use HTTP or HTTPS, without credentials, query parameters, or fragments`
    );
  return value.replace(/\/$/, '');
}
export function launchUrl(value) {
  text(value, 'destination', 2048);
  if (!value) return '';
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new InputError('Destination must be a complete HTTP or HTTPS URL');
  }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password)
    throw new InputError('Destination must use HTTP or HTTPS without embedded credentials');
  if (credentialParams(u)) throw new InputError('Keep credentials out of destination URLs');
  return value;
}
export function parseHttpExpectedStatus(value) {
  const parts = text(value, 'expected HTTP statuses', 200).trim().split(',');
  if (parts.length > 20) throw new InputError('Provide at most 20 HTTP status entries');
  return parts.map(part => {
    const match = part.trim().match(/^(\d{3})(?:-(\d{3}))?$/);
    if (!match)
      throw new InputError(
        'Expected HTTP statuses must be comma-separated codes or ranges, such as 200-399,401'
      );
    const start = Number(match[1]),
      end = Number(match[2] ?? match[1]);
    if (start < 100 || end > 599 || start > end)
      throw new InputError('HTTP statuses must be 100–599 and ranges must be ordered');
    return [start, end];
  });
}
export function validateEmail(input, old = emailDefaults()) {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new InputError('Expected email settings');
  const out = { ...emailDefaults(), ...old };
  for (const key of ['enabled', 'secure'])
    if (input[key] !== undefined) {
      if (typeof input[key] !== 'boolean')
        throw new InputError('Email switches must be true or false');
      out[key] = input[key];
    }
  if (input.host !== undefined) {
    out.host = text(input.host, 'SMTP host', 253).trim().toLowerCase();
    if (
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
        out.host
      )
    )
      throw new InputError('SMTP host must be a hostname without a URL or credentials');
  }
  if (input.port !== undefined) {
    if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535)
      throw new InputError('SMTP port must be between 1 and 65535');
    out.port = input.port;
  }
  for (const key of ['from', 'to'])
    if (input[key] !== undefined) {
      out[key] = text(
        input[key],
        key === 'from' ? 'sender address' : 'recipient address',
        254
      ).trim();
      if (
        out[key] &&
        !/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(
          out[key]
        )
      )
        throw new InputError('Enter one plain email address for the sender and recipient');
    }
  let supplied = '';
  if (input.password !== undefined) {
    supplied = text(input.password, 'email password', 1024);
    if (/[\r\n]/.test(supplied)) throw new InputError('Email passwords cannot contain line breaks');
    if (out.host === 'smtp.gmail.com') supplied = supplied.replace(/ /g, '');
  }
  // Never forward a saved secret to a different SMTP server or account: a change there needs
  // the app password re-entered (or cleared) in the same save, instead of silently losing it.
  if (['host', 'port', 'secure', 'from'].some(key => out[key] !== old[key])) {
    if (old.password && !supplied && input.clearPassword !== true)
      throw new InputError(
        'Re-enter the app password when changing the SMTP server, port, security or sender'
      );
    out.password = '';
  }
  if (supplied) out.password = supplied;
  if (input.clearPassword !== undefined) {
    if (typeof input.clearPassword !== 'boolean')
      throw new InputError('Clear password must be true or false');
    if (input.clearPassword) {
      if (out.enabled)
        throw new InputError('Turn off email alerts before clearing the saved app password');
      out.password = '';
    }
  }
  if (out.enabled && (!out.from || !out.to || !out.password))
    throw new InputError('Enter a sender, recipient and app password before enabling email alerts');
  return out;
}
const origin = value => {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
};
/**
 * outcome.credentialsCleared is set when saved credentials were dropped because a
 * Website check or Bookmark moved to a different server.
 */
export function validateService(input, old, outcome = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new InputError('Expected source settings');
  if (!old && !input.type) throw new InputError('Choose a source type');
  if (input.type !== undefined && !definitions.some(d => d[0] === input.type))
    throw new InputError('Unknown source type');
  const out = { ...(old || newService(input.type, input.id)) };
  if (input.type !== undefined && input.type !== out.type) {
    const appearance = newService(input.type, out.id, out.name);
    Object.assign(out, {
      type: appearance.type,
      icon: appearance.icon,
      labels: appearance.labels,
      color: appearance.color,
    });
  }
  for (const key of ['name', 'group', 'username', 'siteId'])
    if (input[key] !== undefined)
      out[key] = line(input[key], key, key === 'username' ? 200 : 100).trim();
  // A UniFi site: an Integration API site UUID or a local site name, the forms the collectors
  // use (lib/collectors.mjs), or empty. A value saved before this check that it keeps unchanged
  // still loads (parseConfig passes it as the previous one); its collection reports the problem.
  if (
    input.siteId !== undefined &&
    out.siteId &&
    !/^[a-zA-Z0-9_-]{1,100}$/.test(out.siteId) &&
    out.siteId !== old?.siteId
  )
    throw new InputError(
      'UniFi site must be a site UUID or a local site name (letters, digits, hyphens and underscores)'
    );
  if (input.monitoring !== undefined)
    out.monitoring = sourceMonitoring(input.monitoring, old?.monitoring);
  if (input.alerts !== undefined) out.alerts = sourceAlerts(input.alerts, old?.alerts);
  if (input.nodeName !== undefined) {
    out.nodeName = text(input.nodeName, 'Proxmox node name', 63).trim();
    if (out.nodeName && !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(out.nodeName))
      throw new InputError(
        'Proxmox node name must be 1–63 letters, digits or hyphens, starting and ending with a letter or digit'
      );
  }
  if (input.httpExpectedStatus !== undefined)
    out.httpExpectedStatus = parseHttpExpectedStatus(input.httpExpectedStatus)
      .map(([start, end]) => (start === end ? String(start) : start + '-' + end))
      .join(',');
  if (input.httpMethod !== undefined) {
    if (!['GET', 'HEAD'].includes(input.httpMethod))
      throw new InputError('Website check method must be GET or HEAD');
    out.httpMethod = input.httpMethod;
  }
  if (!out.name || !out.group) throw new InputError('Name and group are required');
  for (const key of ['apiKey', 'password'])
    if (input[key] !== undefined) {
      out[key] = text(input[key], key, 8192);
      if (/[\r\n]/.test(out[key])) throw new InputError('Credentials cannot contain line breaks');
    }
  if (input.url !== undefined) out.url = launchUrl(input.url);
  if (input.apiUrl !== undefined) out.apiUrl = safeUrl(input.apiUrl, 'API address');
  if (input.enabled !== undefined) {
    if (typeof input.enabled !== 'boolean') throw new InputError('Enabled must be true or false');
    out.enabled = input.enabled;
  }
  if (input.showOnDashboard !== undefined) {
    if (typeof input.showOnDashboard !== 'boolean')
      throw new InputError('Dashboard visibility must be true or false');
    out.showOnDashboard = input.showOnDashboard;
  }
  if (input.pollSeconds !== undefined) {
    out.pollSeconds = integer(input.pollSeconds, 'Source interval', 0, 3600);
    if (out.pollSeconds > 0 && out.pollSeconds < 15)
      throw new InputError('Source interval must be 0 for the default or 15–3600 seconds');
  }
  if (input.color !== undefined) {
    if (!['orange', 'cyan', 'blue', 'violet', 'amber', 'pink', 'green'].includes(input.color))
      throw new InputError('Invalid accent color');
    out.color = input.color;
  }
  if (input.collector !== undefined) {
    if (
      !['native', 'none', 'http', 'linux', 'windows', 'prometheus', 'json'].includes(
        input.collector
      )
    )
      throw new InputError('Unknown collector');
    out.collector = input.collector;
  }
  if (input.metricPath !== undefined) {
    out.metricPath = text(input.metricPath, 'metric path', 500);
    if (out.metricPath && (!out.metricPath.startsWith('/') || /[?#\\]/.test(out.metricPath)))
      throw new InputError(
        'Metric path must start with / and contain no query, fragment, or backslash'
      );
  }
  if (input.metrics !== undefined) {
    if (!Array.isArray(input.metrics) || input.metrics.length > 100)
      throw new InputError('Provide at most 100 metric mappings');
    const seen = new Set();
    out.metrics = input.metrics.map(m => {
      if (!m || typeof m !== 'object') throw new InputError('Invalid metric mapping');
      const key = text(m.key, 'metric key', 100);
      if (!/^[a-zA-Z0-9_.:/-]+$/.test(key) || seen.has(key))
        throw new InputError('Metric keys must be unique identifiers');
      // Mappings saved before this rule keep working (the built-in reading wins at runtime).
      if (
        reservedKey(out, key) &&
        !(Array.isArray(old?.metrics) && old.metrics.some(saved => saved?.key === key))
      )
        throw new InputError(
          `Metric key "${key}" is already used by a built-in ${out.type} reading; choose another key`
        );
      seen.add(key);
      // A blank path was accepted by older releases, so saved configurations keep loading.
      if (typeof m.path !== 'string') throw new InputError(`Metric mapping "${key}" needs a path`);
      if (m.path.split('.').some(part => ['__proto__', 'constructor', 'prototype'].includes(part)))
        throw new InputError(`Metric mapping "${key}" has an unsupported path`);
      const map = {
        key,
        label: line(m.label || key, 'metric label', 100),
        path: text(m.path, 'mapping path', 200),
        unit: line(m.unit || '', 'metric unit', 30),
        scale: m.scale ?? 1,
      };
      if (!Number.isFinite(map.scale)) throw new InputError('Metric scale must be finite');
      if (m.labels !== undefined) {
        if (
          !m.labels ||
          Array.isArray(m.labels) ||
          typeof m.labels !== 'object' ||
          Object.keys(m.labels).length > 20
        )
          throw new InputError('Metric labels must be an object');
        map.labels = {};
        for (const [k, v] of Object.entries(m.labels)) {
          // A label name, as Prometheus names them: never longer than 100 characters.
          if (!/^\w{1,100}$/.test(k)) throw new InputError('Invalid label key');
          // A label value is a filter, never shown as a line of text: it must equal the
          // exporter's value (mappedSamples() in lib/collectors.mjs), which may hold a line
          // break (an escaped \n) or a direction control. Only NUL is refused, as for a rule key.
          map.labels[k] = text(v, 'label value', 200);
        }
      }
      return map;
    });
  }
  if (input.rules !== undefined) {
    if (!Array.isArray(input.rules) || input.rules.length > 30)
      throw new InputError('Provide at most 30 alert rules');
    const seen = new Set();
    out.rules = input.rules.map(r => {
      if (
        !r ||
        typeof r !== 'object' ||
        !['gt', 'lt'].includes(r.operator) ||
        !Number.isFinite(r.threshold)
      )
        throw new InputError('Invalid alert rule');
      const key = text(r.key, 'rule metric', 150);
      if (key.startsWith('__'))
        throw new InputError('Measurement keys beginning with __ are reserved');
      if (seen.has(key)) throw new InputError('Only one rule per measurement');
      seen.add(key);
      const forSeconds = r.forSeconds ?? 120;
      if (!Number.isInteger(forSeconds) || forSeconds < 0 || forSeconds > 86400)
        throw new InputError('Alert duration must be between 0 and 86400 seconds');
      const recoveryThreshold = r.recoveryThreshold ?? null;
      if (
        recoveryThreshold !== null &&
        (!Number.isFinite(recoveryThreshold) ||
          (r.operator === 'gt' ? recoveryThreshold > r.threshold : recoveryThreshold < r.threshold))
      )
        throw new InputError(
          'Recovery boundary must be finite and on the healthy side of the alert threshold'
        );
      return { key, operator: r.operator, threshold: r.threshold, forSeconds, recoveryThreshold };
    });
  }
  // Never forward a saved secret to a different server: a new collection origin needs
  // the credential re-entered (or cleared) in the same change. Website checks and
  // bookmarks never send credentials, so for them the stale secrets are simply dropped.
  if (
    old &&
    (old.apiKey || old.password) &&
    out.apiUrl &&
    origin(out.apiUrl) !== origin(old.apiUrl)
  ) {
    const stale = ['apiKey', 'password'].filter(key => old[key] && input[key] === undefined);
    if (stale.length && ['http', 'none'].includes(collectorType(out))) {
      for (const key of stale) out[key] = '';
      outcome.credentialsCleared = true;
    } else if (stale.length)
      throw new InputError(
        'Re-enter or clear the saved credentials when changing the collection address to a different server'
      );
  }
  return out;
}
// Keys the native Linux and Windows collectors always report; a new mapping cannot reuse
// them. (Per-disk keys are not reserved: filtered mounts have no built-in reading.) Cards
// using the JSON, website or bookmark method report only their mappings.
const builtInKeys = {
  linux: ['cpu', 'memory', 'memory_used', 'memory_total', 'load1', 'uptime', 'receive', 'transmit'],
  windows: ['cpu', 'memory', 'memory_total', 'memory_free', 'received', 'sent'],
};
function reservedKey(service, key) {
  return (
    collectorType(service) === service.type && Boolean(builtInKeys[service.type]?.includes(key))
  );
}
// Values accepted by older releases but refused by today's validation are repaired on load,
// so an upgrade never stops Uptime Goblin from starting. `warn` reports each repair.
function migrate(saved, warn = console.warn) {
  let changed = false;
  const fix = (what, from, to) => {
    changed = true;
    warn(`Configuration: ${what} "${from}" was replaced by "${to}".`);
  };
  // Text holding half of a surrogate pair (a \u escape that 1.4.x wrote, or a hand edit) is
  // made whole first. The web app sends saved values back as they are (the dashboard name with
  // every Appearance save, a source's rules with every source save), and request bodies refuse
  // such text, so those saves failed. Named by place only, never by text, ten at most. Rule keys
  // (Store.evaluate), label filters and JSON mapping paths (mappedSamples() in
  // lib/collectors.mjs) keep matching the source's own text, which is compared made whole too.
  // Which half a filter or path held is lost, though: a source that also sends U+FFFD itself, or
  // another half, at that place gives another reading or none, which the log says once.
  // A UniFi site ID is still compared as the controller sends it: a site UUID.
  const savedRuleKeys = saved.services.map(service =>
    Array.isArray(service?.rules) ? service.rules.map(rule => rule?.key) : null
  );
  const halves = wholeTexts(saved);
  for (const where of halves.slice(0, 10))
    fix(where, '(hidden)', 'the same text with U+FFFD in place of half a surrogate pair');
  if (halves.length > 10)
    warn(
      `Configuration: ${halves.length - 10} more texts holding half a surrogate pair were made whole the same way.`
    );
  const matchers = halves.filter(where =>
    /^services\[\d+\]\.metrics\[\d+\]\.(?:path$|labels\.)/.test(where)
  ).length;
  if (matchers)
    warn(
      `Configuration: ${matchers} of these texts ${matchers === 1 ? 'is a mapping label filter or path' : 'are mapping label filters or paths'}. Which half such a filter or path held is lost: when nothing matches it as the source sends it, it is compared with the source's text with any half read as U+FFFD. It reads as before while the source sends neither U+FFFD itself nor another half there; with U+FFFD there, that series or member is read instead, and with two different halves, nothing (the source shows a note).`
    );
  // Two rule keys of one source that differed only in half a surrogate pair (disk_x\ud800 and
  // disk_x\udbff, which 1.4.3 loaded) are one key once made whole, and a measurement takes one
  // rule: the start was refused. The first rule of that key is kept, as Store.evaluate keeps it,
  // and the later ones are removed, named by place. A key saved twice as the same text is still
  // refused, as 1.4.3 refused it.
  for (const [index, service] of saved.services.entries()) {
    const savedKeys = savedRuleKeys[index];
    if (!savedKeys) continue;
    const savedTexts = new Set(),
      first = new Map();
    service.rules = service.rules.filter((rule, position) => {
      const key = rule?.key,
        savedKey = savedKeys[position];
      if (typeof key !== 'string' || typeof savedKey !== 'string') return true;
      const repeated = savedTexts.has(savedKey);
      savedTexts.add(savedKey);
      if (repeated || !first.has(key)) {
        if (!first.has(key)) first.set(key, position);
        return true;
      }
      changed = true;
      warn(
        `Configuration: alert rule ${position + 1} of source ${index + 1} was removed: made whole, its measurement key is that of rule ${first.get(key) + 1}, and a measurement takes one rule.`
      );
      return false;
    });
  }
  // Offsets (UTC+05:30) are kept. Orbit 1.4.2 and older replace them with 'local', so after
  // a rollback and upgrade the owner sets the offset again. A zone saved in another spelling
  // (UTC+00:00, or UTC−05:00 with a minus sign) is saved again in its canonical one.
  const timezone = saved.appearance?.timezone;
  if (typeof timezone === 'string') {
    let canonical = null;
    try {
      canonical = validateAppearance({ timezone }).timezone;
    } catch {}
    if (canonical !== timezone) {
      // Named only while it looks like a time zone (Europe/London, UTC+05:30, UTC−05:00): it is
      // saved text, and the warning reaches the log at every start until the repair is saved.
      const shown = /^[A-Za-z0-9_+\-\u2212/:.]{1,64}$/.test(timezone) ? timezone : '(hidden)';
      fix(canonical ? 'time zone' : 'unsupported time zone', shown, canonical || 'local');
      saved.appearance.timezone = canonical || 'local';
    }
  }
  // Single-line texts saved before control and text-direction characters were refused
  // (notOneLine) are repaired rather than refusing the start. The warning names the field and
  // the source by its position, never a value: either may be crafted for a terminal.
  const repairLine = (holder, key, what, fallback) => {
    if (typeof holder?.[key] !== 'string' || !notOneLine.test(holder[key])) return;
    const repaired = oneLine(holder[key]).trim();
    holder[key] = repaired || fallback;
    fix(what, '(hidden)', 'the same text without control or text-direction characters');
  };
  repairLine(saved, 'title', 'dashboard name', defaults().title);
  repairLine(saved, 'subtitle', 'subtitle', '');
  for (const [index, service] of saved.services.entries()) {
    if (!service || typeof service !== 'object') continue;
    const where = `of source ${index + 1}`;
    const known = definitions.find(d => d[0] === service.type);
    repairLine(service, 'name', `name ${where}`, known?.[1] ?? 'Source');
    repairLine(service, 'group', `group ${where}`, known?.[2] ?? 'Sources');
    repairLine(service, 'username', `username ${where}`, '');
    repairLine(service, 'siteId', `UniFi site ${where}`, '');
    if (Array.isArray(service.metrics))
      for (const mapping of service.metrics) {
        if (!mapping || typeof mapping !== 'object') continue;
        // A mapping's label values (`labels`) are filters matched exactly against what the
        // exporter sends, not display text, and are kept as saved.
        repairLine(mapping, 'label', `metric label ${where}`, '');
        repairLine(mapping, 'unit', `metric unit ${where}`, '');
      }
  }
  for (const [index, service] of saved.services.entries()) {
    if (!service || typeof service !== 'object') continue;
    // The ID is saved text, checked only after this: named only when it is a valid one.
    const source =
      typeof service.id === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(service.id)
        ? service.id
        : `source ${index + 1}`;
    // Older releases accepted a bare '?' or '#' (also followed by spaces or control
    // characters, which URL parsing drops); rebuild the address without them.
    if (typeof service.apiUrl === 'string' && /[?#]/.test(service.apiUrl)) {
      let cleaned = '';
      try {
        const u = new URL(service.apiUrl);
        if (!u.search && !u.hash) {
          u.search = '';
          u.hash = '';
          cleaned = u.href;
        }
      } catch {}
      // Neither address is named, as for a destination below: the warning reaches the log, and
      // a token or password may sit in the query, the fragment, the user info or the path that
      // a bare '?' or '#' repair keeps (independent review A4, as maintenance 27f81dd).
      fix(
        `collection address of ${source}`,
        '(hidden)',
        cleaned ? 'the same address without its empty query or fragment markers' : ''
      );
      service.apiUrl = cleaned;
    }
    // A destination carrying credentials keeps its address; only those parameters go, so a
    // Website check that uses the destination keeps running.
    if (typeof service.url === 'string' && service.url)
      try {
        launchUrl(service.url);
      } catch {
        let repaired = '';
        try {
          repaired = launchUrl(withoutCredentials(service.url));
        } catch {}
        fix(
          `destination of ${source}`,
          '(hidden)',
          repaired ? 'the same link without its credential parameters' : ''
        );
        service.url = repaired;
      }
  }
  return changed;
}
// Highest numbered ID ever used per source type, from the saved counters and current IDs.
function counters(saved, services) {
  const out = {};
  const remember = (type, n) => {
    if (definitions.some(d => d[0] === type) && Number.isInteger(n) && n > 0)
      out[type] = Math.max(out[type] ?? 0, Math.min(n, Number.MAX_SAFE_INTEGER));
  };
  if (saved && typeof saved === 'object' && !Array.isArray(saved))
    for (const [type, n] of Object.entries(saved)) remember(type, n);
  for (const s of services) {
    const match = s.id.match(/^(.+)-(\d+)$/);
    if (match) remember(match[1], Number(match[2]));
  }
  return out;
}
/**
 * The member names of `text` (valid JSON) given twice in one object, and those named __proto__,
 * as [{where, kind: 'duplicate' | 'proto'}], at most `limit` of them; `where` is the member's
 * path (services[0].name), cleaned for one log line. One pass over the text, without recursion,
 * names compared decoded ("a" and "\u0061" are the same name).
 */
function memberNotes(text, limit = 5) {
  const notes = [];
  // One frame per open object ({names, at: its current member}) or array ({at: its index}).
  const open = [];
  const where = () =>
    printable(
      open
        .map((frame, index) => (frame.names ? `${index ? '.' : ''}${frame.at}` : `[${frame.at}]`))
        .join('')
    );
  // Whether the next string is a member name: after '{' and after ',' inside an object.
  let nameNext = false;
  for (let i = 0; i < text.length && notes.length < limit; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      let end = i + 1;
      while (text.charCodeAt(end) !== 0x22) end += text.charCodeAt(end) === 0x5c ? 2 : 1;
      if (nameNext) {
        const raw = text.slice(i + 1, end);
        const name = raw.includes('\\') ? JSON.parse(text.slice(i, end + 1)) : raw;
        const frame = open.at(-1);
        frame.at = name;
        if (frame.names.has(name)) notes.push({ where: where(), kind: 'duplicate' });
        else if (name === '__proto__') notes.push({ where: where(), kind: 'proto' });
        frame.names.add(name);
        nameNext = false;
      }
      i = end;
    } else if (c === 0x7b || c === 0x5b) {
      open.push(c === 0x7b ? { names: new Set(), at: '' } : { names: null, at: 0 });
      nameNext = c === 0x7b;
    } else if (c === 0x7d || c === 0x5d) {
      open.pop();
      nameNext = false;
    } else if (c === 0x2c) {
      const frame = open.at(-1);
      if (frame.names) nameNext = true;
      else frame.at += 1;
    }
  }
  return notes;
}
function jsonProblem(error) {
  // V8 sometimes quotes configuration contents. Keep only trailing numeric locations,
  // never the original message or cause; unfamiliar formats remain generic.
  const line = /\(line ([1-9]\d*) column ([1-9]\d*)\)$/.exec(error.message),
    position = /at position (\d+)(?: \(line [1-9]\d* column [1-9]\d*\))?$/.exec(error.message),
    location = {};
  if (line && Number.isSafeInteger(+line[1]) && Number.isSafeInteger(+line[2])) {
    location.line = +line[1];
    location.column = +line[2];
  }
  if (position && Number.isSafeInteger(+position[1])) location.position = +position[1];
  const where = location.line
    ? ` at line ${location.line}, column ${location.column}`
    : location.position !== undefined
      ? ` at position ${location.position}`
      : '';
  return Object.assign(new InputError('Expected valid JSON' + where), location);
}
/**
 * Parses and validates the text of a saved config.json, as the ConfigStore constructor loads it:
 * resolves {value, repaired}, where `repaired` says that values older releases accepted were
 * repaired (the constructor saves them once). Anything wrong with the contents throws a refusal
 * (exit 78) naming `file`. The constructor and checkConfigFile() both call this, so what they
 * accept and the texts they refuse with cannot diverge. `warn` receives each repair line.
 */
export function parseConfig(text, file, { warn = console.warn } = {}) {
  try {
    const saved = JSON.parse(text);
    // JSON.parse keeps the last of two equal member names, and keeps __proto__ as a name that
    // no setting reads: both said once, by their place in the file, and saved away as a repair.
    const members = memberNotes(text);
    for (const { where, kind } of members)
      warn(
        kind === 'duplicate'
          ? `Configuration: ${where} is given more than once in config.json; the last one is used.`
          : `Configuration: ${where} in config.json is not a setting and is ignored.`
      );
    if (
      !saved ||
      typeof saved !== 'object' ||
      !Array.isArray(saved.services) ||
      saved.services.length > 200
    )
      throw new InputError('it must be an object with a list of at most 200 sources');
    const repaired = migrate(saved, warn) || members.length > 0;
    const ids = new Set();
    const services = saved.services.map((s, i) => {
      if (!s || typeof s !== 'object' || Array.isArray(s))
        throw new InputError(`source ${i + 1} is not an object`);
      if (typeof s.id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(s.id) || ids.has(s.id))
        throw new InputError(`source ${i + 1} has a duplicate or invalid ID`);
      // Named by its ID (checked above), never by the saved type: that is arbitrary file text,
      // and this message and its cause reach the journal.
      if (!definitions.some(d => d[0] === s.type))
        throw new InputError(
          `source ${s.id} has a type this version of Uptime Goblin does not support; it may come from a newer release`
        );
      ids.add(s.id);
      // Saved mappings are passed as the previous state, so rules added since they were
      // saved (such as reserved keys) do not stop Uptime Goblin from starting.
      return validateService(s, {
        ...newService(s.type, s.id),
        metrics: s.metrics,
        siteId: s.siteId,
      });
    });
    // globalCandidate and validateGlobal read no instance state.
    const globalSettings = ConfigStore.prototype.globalCandidate.call(
      ConfigStore.prototype,
      saved,
      defaults()
    );
    return {
      value: {
        ...globalSettings,
        services,
        revision: Number.isSafeInteger(saved.revision) && saved.revision > 0 ? saved.revision : 0,
        sourceCounters: counters(saved.sourceCounters, services),
      },
      repaired,
    };
  } catch (error) {
    // JSON.parse may quote the input near an invalid token, including a credential.
    // Keep that excerpt out of both the public startup message and nested causes.
    const problem = error instanceof SyntaxError ? jsonProblem(error) : error;
    throw Object.assign(
      new Error(
        `Invalid configuration file ${file}: ${problem.message}. Correct it or restore a backup, then start Uptime Goblin again.`
      ),
      { refusal: true, cause: problem }
    );
  }
}

// config.json combines up to 200 sources, each edited through 150,000-byte request bodies, so
// 128 MiB leaves ample room for credentials, mappings, UTF-8 and pretty-printed older files while
// bounding what a start reads before parsing (as Orbit 1.4.x maintenance does). A file limit, not
// a request limit.
const configByteLimit = 128 * 1024 * 1024;
function fileRefusal(file, message) {
  const problem = new InputError(message);
  return Object.assign(
    new Error(
      `Invalid configuration file ${file}: ${message}. Correct it or restore a backup, then start Uptime Goblin again.`
    ),
    { refusal: true, cause: problem }
  );
}
/**
 * The text of config.json, or undefined when there is none. Opened without waiting (a FIFO in
 * its place would otherwise hold the start, and goblin.lock, until something writes to it) and
 * checked on the descriptor it reads: a regular file of at most configByteLimit bytes, a symlink
 * to one included (1.4.x accepts those). At most the checked size and one byte more is read, so a
 * file that grows meanwhile is refused instead of read without bound. A file that is not one, or
 * too large, is a refusal (exit 78); any other read error is rethrown (the start is retried).
 */
function readConfigText(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // A symbolic link to a file that is not there (on a volume that is not mounted, say) is
      // not a data directory without settings: starting would save the defaults over the link
      // and leave the real file behind.
      if (isSymbolicLink(file))
        throw fileRefusal(
          file,
          'it is a symbolic link to a file that does not exist; mount or restore that file, or put the file itself in place of the link'
        );
      return undefined;
    }
    // A socket, or a link that cannot be followed: no retry reads it either.
    if (['ELOOP', 'ENXIO', 'EOPNOTSUPP'].includes(error.code))
      throw fileRefusal(file, 'it must be a regular file');
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw fileRefusal(file, 'it must be a regular file');
    if (stat.size > configByteLimit) throw fileRefusal(file, 'it must be no larger than 128 MiB');
    const buffer = Buffer.allocUnsafe(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, length);
      if (!read) break;
      length += read;
    }
    if (length > stat.size) throw fileRefusal(file, 'it changed while it was read; start again');
    // Strictly: bytes that are not UTF-8 would become U+FFFD inside the values that hold them,
    // and a credential changed that way fails without saying why.
    try {
      return strictUtf8.decode(buffer.subarray(0, length));
    } catch {
      throw fileRefusal(file, 'it is not valid UTF-8 text; save it as UTF-8');
    }
  } finally {
    fs.closeSync(descriptor);
  }
}
// A byte order mark stays a character, which JSON refuses, as before.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const isSymbolicLink = file => {
  try {
    return fs.lstatSync(file).isSymbolicLink();
  } catch {
    return false;
  }
};

/**
 * Sets config.json's mode to 0600 when others may read it (a hand edit or a copy can leave it
 * 0644). Not through a symbolic link (O_NOFOLLOW: its target is the operator's choice), and only
 * for a regular file. Housekeeping: a read-only disk must not stop a valid configuration, so a
 * failure is a warning naming only the error code.
 */
function tightenConfigFile(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    const stat = fs.fstatSync(descriptor);
    if (stat.isFile() && stat.mode & 0o077) fs.fchmodSync(descriptor, 0o600);
  } catch (error) {
    if (error.code !== 'ELOOP' && error.code !== 'ENOENT')
      console.warn('config.json permissions could not be tightened:', error.code || error.name);
  } finally {
    if (descriptor !== undefined)
      try {
        fs.closeSync(descriptor);
      } catch {}
  }
}

/**
 * The start's read-only check of <directory>/config.json (sessions spec §3.11), run under
 * goblin.lock before control.sqlite, the pre-upgrade snapshot or the password import exist, so a
 * corrupt file refuses (exit 78) with the directory unchanged. It applies exactly the
 * constructor's parse and validation and throws the same refusal, but creates nothing (not even
 * the directory) and writes nothing: repairs are saved by the constructor only. Something other
 * than a regular file of at most 128 MiB in its place is a refusal too (readConfigText); a read
 * error other than ENOENT is rethrown unchanged (exit 1, the start is retried). Returns whether
 * the file exists.
 */
export function checkConfigFile(directory) {
  const file = path.join(directory, 'config.json');
  const text = readConfigText(file);
  if (text === undefined) return false;
  parseConfig(text, file, { warn: () => {} });
  return true;
}

export class ConfigStore {
  // Sources by ID for one services array. Every change saves a new array (nothing edits one in
  // place), so the index is rebuilt only when the array it describes is replaced.
  #index = null;
  #indexed = null;
  // Collection-cycle figures, kept for the configuration value and timeout function they
  // were computed from (see cycleStatistics).
  #cycle = null;
  constructor(directory) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    this.file = path.join(directory, 'config.json');
    // Reading may fail on a full, read-only or failing disk: that error is passed on and the
    // start retried. A file that is not a regular one of at most 128 MiB, or anything wrong with
    // the contents, is a refusal that says what.
    const text = readConfigText(this.file);
    if (text !== undefined) {
      const { value, repaired } = parseConfig(text, this.file);
      // Only a file that loads: a refused one is left exactly as it was.
      tightenConfigFile(this.file);
      this.value = value;
      // Whether the value differs from the file because a repair was made (saved below, or kept
      // in memory when that save fails): the audit's start rows say a change may be a repair.
      this.repaired = repaired;
      // Save repairs once, so they are not logged again at every start. A failed save (a
      // full disk) is not fatal: the repaired settings are used and saved with the next change.
      if (repaired)
        try {
          this.save();
        } catch (error) {
          console.warn('Configuration repairs could not be saved yet:', error.code || error.name);
        }
    } else {
      this.value = defaults();
      this.repaired = false;
      this.save();
    }
  }
  // Every save gets a new revision, so a browser editing an older copy can be told (409)
  // instead of silently overwriting another device's changes.
  save(candidate = this.value) {
    candidate = { ...candidate, revision: (this.value?.revision ?? 0) + 1 };
    // Never reuse a stale temporary file or follow a pre-existing link while writing secrets.
    const tmp = this.file + '.' + randomUUID() + '.tmp';
    let descriptor,
      created = false;
    try {
      descriptor = fs.openSync(tmp, 'wx', 0o600);
      created = true;
      fs.writeFileSync(descriptor, JSON.stringify(candidate, null, 2) + '\n');
      fs.fsyncSync(descriptor);
      // close() can report an error after releasing the number for another open file.
      const closing = descriptor;
      descriptor = undefined;
      fs.closeSync(closing);
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, this.file);
    } catch (error) {
      if (descriptor !== undefined)
        try {
          fs.closeSync(descriptor);
        } catch {}
      // An exclusive-create failure means this path belongs to someone else.
      if (created)
        try {
          fs.unlinkSync(tmp);
        } catch {}
      throw error;
    }
    this.value = candidate;
  }
  validateGlobal(v) {
    if (!Number.isInteger(v.pollSeconds) || v.pollSeconds < 15 || v.pollSeconds > 3600)
      throw new InputError('Collection interval must be 15–3600 seconds');
    if (!Number.isInteger(v.retentionDays) || v.retentionDays < 1 || v.retentionDays > 365)
      throw new InputError('History retention must be 1–365 days');
  }
  globalCandidate(v, old) {
    object(v, 'preferences');
    const next = {
      ...old,
      pollSeconds: v.pollSeconds === undefined ? old.pollSeconds : v.pollSeconds,
      retentionDays: v.retentionDays === undefined ? old.retentionDays : v.retentionDays,
    };
    for (const [key, max] of [
      ['title', 80],
      ['subtitle', 160],
    ])
      if (v[key] !== undefined) next[key] = line(v[key], key, max).trim();
    if (!next.title) throw new InputError('Dashboard name is required');
    for (const [key, validator] of [
      ['email', validateEmail],
      ['appearance', validateAppearance],
      ['monitoring', validateMonitoring],
      ['alerts', validateAlerts],
    ])
      if (v[key] !== undefined) next[key] = validator(v[key], old[key]);
    this.validateGlobal(next);
    return next;
  }
  updateGlobal(v) {
    this.save(this.globalCandidate(v, this.value));
  }
  // O(1): the scheduler, the dashboard and every source route look sources up by ID. Like
  // the linear search it replaces, the first source with the ID wins (IDs are unique anyway).
  get(id) {
    const services = this.value.services;
    if (this.#indexed !== services) {
      const index = new Map();
      for (const service of services) if (!index.has(service?.id)) index.set(service?.id, service);
      this.#index = index;
      this.#indexed = services;
    }
    return this.#index.get(id);
  }
  // How many sources are collected, and the longest time limit among them, as
  // {active, slowestMs}. The figures depend only on the saved configuration and on
  // `timeoutMs` (a source's collection time limit in ms), so they are computed once per saved
  // configuration instead of once for every source on every dashboard (which was O(n²)).
  // slowestMs is -Infinity when no source is collected. See cycleSeconds below.
  cycleStatistics(timeoutMs) {
    const value = this.value;
    if (this.#cycle?.value !== value || this.#cycle.timeoutMs !== timeoutMs) {
      let active = 0,
        slowestMs = -Infinity;
      for (const service of value.services)
        if (service.enabled && configured(service)) {
          active++;
          slowestMs = Math.max(slowestMs, timeoutMs(service));
        }
      this.#cycle = { value, timeoutMs, result: Object.freeze({ active, slowestMs }) };
    }
    return this.#cycle.result;
  }
  /**
   * The source update() would save, without saving it: the routes check a change with it before
   * the write takes its turn, and update() saves what it returns. A saved source keeps its type:
   * the editor locks it, and a new type would keep metrics and credentials checked against the
   * old one (reserved reading keys, the collector the credentials were entered for).
   */
  updateCandidate(id, input, outcome = {}) {
    const old = this.get(id);
    if (!old) throw new InputError('Source not found');
    if (input && typeof input === 'object' && input.type !== undefined && input.type !== old.type)
      throw new InputError('A saved source keeps its service type; add a new source instead');
    return validateService(input, old, outcome);
  }
  update(id, input, outcome = {}) {
    const next = this.updateCandidate(id, input, outcome);
    this.save({ ...this.value, services: this.value.services.map(s => (s.id === id ? next : s)) });
    return next;
  }
  /**
   * What add() checks before it picks an ID, as the source it would add: the routes check a new
   * source with it before the write takes its turn.
   */
  checkNew(input) {
    if (!input || typeof input !== 'object') throw new InputError('Expected source settings');
    if (this.value.services.length >= 200)
      throw new InputError('At most 200 sources are supported');
    if (!definitions.some(d => d[0] === input.type)) throw new InputError('Choose a source type');
    return validateService(input, newService(input.type, `${input.type}-new`));
  }
  add(input) {
    this.checkNew(input);
    const type = input.type;
    // IDs are never reused: a browser still showing a deleted source must not be able to
    // edit or remove a newer source that inherited its ID.
    const sourceCounters = counters(this.value.sourceCounters, this.value.services);
    let n = (sourceCounters[type] ?? 0) + 1;
    while (Number.isSafeInteger(n) && this.get(type + '-' + n)) n++;
    // Above 2^53, n++ can equal n forever. Preserve large imported IDs and use UUIDs
    // once the numeric range is exhausted; the saturated counter survives removals.
    let id = type + '-' + n;
    if (!Number.isSafeInteger(n)) {
      do id = type + '-' + randomUUID();
      while (this.get(id));
      n = Number.MAX_SAFE_INTEGER;
    }
    const next = validateService(input, newService(type, id));
    this.save({
      ...this.value,
      sourceCounters: { ...sourceCounters, [type]: n },
      services: [...this.value.services, next],
    });
    return next;
  }
  /**
   * Adds the sources `add` (settings, as add() takes them) and changes the saved sources of
   * `change` ([id, settings] pairs, as update() takes them) in one save, so one configuration
   * revision holds all of them, or none when any is refused (the Uptime Kuma import). IDs are
   * picked as add() picks them. Returns {added, changed: [[old, next], …]}.
   */
  importSources({ add = [], change = [] }) {
    if (this.value.services.length + add.length > 200)
      throw new InputError('At most 200 sources are supported');
    const changed = change.map(([id, input]) => [this.get(id), this.updateCandidate(id, input)]);
    const replaced = new Map(changed.map(([old, next]) => [old.id, next]));
    const services = this.value.services.map(s => replaced.get(s.id) ?? s),
      taken = new Set(services.map(s => s?.id)),
      sourceCounters = counters(this.value.sourceCounters, this.value.services),
      added = [];
    for (const input of add) {
      this.checkNew(input);
      const type = input.type;
      let n = (sourceCounters[type] ?? 0) + 1;
      while (Number.isSafeInteger(n) && taken.has(type + '-' + n)) n++;
      let id = type + '-' + n;
      if (!Number.isSafeInteger(n)) {
        do id = type + '-' + randomUUID();
        while (taken.has(id));
        n = Number.MAX_SAFE_INTEGER;
      }
      const next = validateService(input, newService(type, id));
      sourceCounters[type] = n;
      taken.add(id);
      added.push(next);
    }
    this.save({ ...this.value, sourceCounters, services: [...services, ...added] });
    return { added, changed };
  }
  remove(id) {
    if (!this.get(id)) throw new InputError('Source not found');
    // The counters remember the removed ID, so it is never handed out again.
    this.save({
      ...this.value,
      sourceCounters: counters(this.value.sourceCounters, this.value.services),
      services: this.value.services.filter(s => s.id !== id),
    });
  }
}

// One full collection cycle for a source in seconds, allowing for every collected source
// sharing the worker slots: the source's interval plus one slowest time limit for each round
// of `concurrency` sources. Queueing within this is not a gap in monitoring. The same figure
// as server.mjs's cycleSeconds in 1.4.3, in O(1) once the statistics are cached.
// `interval(service)` gives the source's interval in seconds, `timeoutMs(service)` its time
// limit in milliseconds; pass the same timeoutMs function every time so the cache holds.
export function cycleSeconds(config, service, { interval, timeoutMs }) {
  const { active, slowestMs } = config.cycleStatistics(timeoutMs),
    slowest = Math.max(timeoutMs(service), slowestMs) / 1000;
  return (
    interval(service) +
    Math.ceil(Math.max(1, active) / config.value.monitoring.concurrency) * slowest
  );
}

// API requests are checked against these schemas so a misspelled or unsupported field is
// reported instead of silently ignored. Saved files are not checked, so older
// configurations still load after an upgrade.
const appearanceKeys = [
  'accent',
  'density',
  'columns',
  'defaultRange',
  'sortBy',
  'showSummary',
  'showPaused',
  'showUnconfigured',
  'openInNewTab',
  'reduceMotion',
  'timezone',
  'timeFormat',
];
const settingsSchema = {
  title: null,
  subtitle: null,
  pollSeconds: null,
  retentionDays: null,
  email: ['enabled', 'secure', 'host', 'port', 'from', 'to', 'password', 'clearPassword'],
  appearance: appearanceKeys,
  monitoring: monitoringRanges.map(([key]) => key),
  alerts: [
    'enabled',
    'notifyOnAlert',
    'notifyOnRecovery',
    'notifyAvailability',
    'notifyMeasurements',
  ],
};
const sourceSchema = {
  type: null,
  name: null,
  group: null,
  color: null,
  url: null,
  apiUrl: null,
  apiKey: null,
  username: null,
  password: null,
  siteId: null,
  nodeName: null,
  enabled: null,
  showOnDashboard: null,
  pollSeconds: null,
  collector: null,
  metricPath: null,
  httpMethod: null,
  httpExpectedStatus: null,
  monitoring: monitoringRanges.map(([key]) => key).filter(key => key !== 'concurrency'),
  alerts: ['notifyAvailability', 'notifyMeasurements'],
  metrics: ['key', 'label', 'path', 'unit', 'scale', 'labels'],
  rules: ['key', 'operator', 'threshold', 'forSeconds', 'recoveryThreshold'],
};
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
function onlyKnown(input, keys, label) {
  if (!plain(input)) return;
  for (const key of Object.keys(input))
    if (!keys.includes(key)) throw new InputError(`Unknown ${label} field: ${key.slice(0, 60)}`);
}
function checkSchema(input, schema, label) {
  onlyKnown(input, Object.keys(schema), label);
  if (!plain(input)) return;
  for (const [key, nested] of Object.entries(schema)) {
    if (!nested || input[key] === undefined) continue;
    for (const item of Array.isArray(input[key]) ? input[key] : [input[key]])
      onlyKnown(item, nested, `${label} ${key}`);
  }
}
export const assertKnownSettings = input => checkSchema(input, settingsSchema, 'settings');
export const assertKnownSource = input => checkSchema(input, sourceSchema, 'source');
