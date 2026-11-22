// What an Uptime Kuma 1.x backup would add to Uptime Goblin, as Website checks: the plan the import's
// preview shows and its apply saves (lib/http/routes/import.mjs). The backup is read by
// public/shared/uptime-kuma.js, which the web app uses too; nothing is fetched or evaluated.
//
// Only HTTP(S) and keyword monitors become sources, each checked by validateService() as a new
// Website check would be. A keyword is not checked (the Website check tests the status only),
// redirects are never followed, TLS is always verified and no proxy is used, so each of those is
// noted, never imitated. Credentials (basic auth, headers, a body, client certificates, OAuth) and
// notifications are never imported: a monitor that had credentials is marked. Every other
// monitor is skipped with its reason. The plan depends only on the backup and the saved
// sources, so the apply that follows a preview of the same configuration revision saves exactly
// what the preview showed.
import { collectorType, definitions, newService } from '../catalog.mjs';
import { InputError, validateService } from '../config.mjs';
import { cleanAddress, KumaBackupError, readKumaBackup } from '../../public/shared/uptime-kuma.js';

/** Uptime Goblin's limit on sources (ConfigStore.checkNew). */
export const SOURCES_MAX = 200;
const NAME_MAX = 100,
  POLL_MIN = 15,
  POLL_MAX = 3600;
// The settings an import sets on a Website check, and the ones it compares on a name collision.
const changeFields = [
  'url',
  'apiUrl',
  'metricPath',
  'httpMethod',
  'httpExpectedStatus',
  'pollSeconds',
  'group',
];

/** Notes every import carries. */
export const KUMA_IMPORT_NOTES = Object.freeze([
  'Notifications, maintenance windows, status pages, tags and history are not imported.',
  'Uptime Goblin never imports credentials: basic-auth names and passwords, headers, request bodies, client certificates and OAuth settings stay in Uptime Kuma.',
]);

// Display text on one line, as validateService() accepts it: controls become a space, direction
// controls are removed, and it is cut to `max` UTF-16 units without splitting a character.
function displayLine(value, max) {
  let text = value
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const cut = text.length > max;
  if (cut) {
    let out = '';
    for (const character of text) {
      if (out.length + character.length > max) break;
      out += character;
    }
    text = out.trim();
  }
  return { text, cut };
}
const nameKey = name => name.toLowerCase();
const typeName = type => definitions.find(d => d[0] === type)?.[1] ?? type;
// A Kuma type as shown in a reason: its own word when it is a plain one.
const kumaType = type => (/^[a-z0-9-]{1,40}$/.test(type) ? type : 'unknown');
const skipReasons = {
  group: 'A group: its monitors use its name as their Uptime Goblin group.',
  ping: 'Ping monitors are not supported: Uptime Goblin checks websites over HTTP or HTTPS.',
  port: 'TCP port monitors are not supported: Uptime Goblin checks websites over HTTP or HTTPS.',
  dns: 'DNS monitors are not supported.',
  docker: 'Docker container monitors are not supported: add a Docker source instead.',
  push: 'Push monitors are not supported: Uptime Goblin collects, it does not wait for pushes.',
  'json-query': 'JSON query monitors are not supported: a Custom API source can read JSON values.',
};

/** The URL Uptime Goblin would check, without credentials: {url, stripped} or {reason}. */
function checkAddress(monitor) {
  if (!monitor.url) return { reason: 'It has no address.' };
  const address = cleanAddress(monitor.url);
  if (!address)
    return {
      reason:
        /^[a-z][a-z0-9+.-]*:/i.test(monitor.url) && !/^https?:/i.test(monitor.url)
          ? 'Its address does not use HTTP or HTTPS.'
          : 'Its address is not a complete HTTP or HTTPS URL.',
    };
  return { url: address.url, stripped: address.stripped || monitor.addressCredentials };
}

// The accepted statuses as one text (validateService() checks it); Kuma's default is 200-299.
function statuses(accepted) {
  const list = accepted.length ? accepted : ['200-299'];
  return list.join(',');
}
// Whether every 3xx status is accepted (the ranges as validateService() saved them).
function acceptsRedirects(expected) {
  const ranges = expected.split(',').map(part => part.split('-').map(Number));
  for (let status = 300; status <= 399; status++)
    if (!ranges.some(([start, end = start]) => status >= start && status <= end)) return false;
  return true;
}

/**
 * The plan for `backup` (the parsed JSON) against `services` (the saved sources):
 * `{version, add, change, skip, notes}` for the preview, and `inputs` (`add`: source settings for
 * ConfigStore.importSources, `change`: [id, settings] pairs) for the apply. Throws InputError
 * for a backup that cannot be imported at all.
 */
export function planKumaImport(backup, services) {
  let read;
  try {
    read = readKumaBackup(backup);
  } catch (error) {
    if (error instanceof KumaBackupError) throw new InputError(error.message);
    throw error;
  }
  const { version, monitors } = read;
  const groups = new Map(
    monitors.filter(m => !m.problem && m.type === 'group').map(m => [m.id, m])
  );
  const existing = new Map();
  for (const service of services) {
    if (typeof service?.name !== 'string') continue;
    const key = nameKey(service.name.trim());
    existing.set(key, [...(existing.get(key) ?? []), service]);
  }
  const claimed = new Set(),
    plan = { version, add: [], change: [], skip: [], notes: [...KUMA_IMPORT_NOTES] },
    inputs = { add: [], change: [] };
  const skip = (monitor, reason) =>
    plan.skip.push({
      kumaId: monitor.id,
      name: displayLine(monitor.name, NAME_MAX).text || null,
      type: kumaType(monitor.type),
      reason,
    });
  for (const monitor of monitors) {
    if (monitor.problem) {
      skip(monitor, `Malformed entry: ${monitor.problem}.`);
      continue;
    }
    if (!['http', 'keyword'].includes(monitor.type)) {
      skip(
        monitor,
        skipReasons[monitor.type] ??
          `Monitors of type ${kumaType(monitor.type)} are not supported: Uptime Goblin imports HTTP(S) and keyword monitors.`
      );
      continue;
    }
    if (monitor.upsideDown) {
      skip(monitor, 'Upside down mode reverses the result, and Uptime Goblin has no equivalent.');
      continue;
    }
    if (!['GET', 'HEAD'].includes(monitor.method)) {
      skip(
        monitor,
        /^[A-Z]{1,16}$/.test(monitor.method)
          ? `It sends ${monitor.method}; Uptime Goblin's Website check sends GET or HEAD only.`
          : "Its HTTP method is not GET or HEAD, the methods Uptime Goblin's Website check sends."
      );
      continue;
    }
    const address = checkAddress(monitor);
    if (address.reason) {
      skip(monitor, address.reason);
      continue;
    }
    const notes = [];
    const named = displayLine(monitor.name, NAME_MAX);
    let name = named.text || `Uptime Kuma monitor ${monitor.id}`;
    if (named.cut) notes.push(`Name shortened to ${NAME_MAX} characters.`);
    const parent = monitor.parent === null ? null : groups.get(monitor.parent);
    // The group Kuma names, if any: a new check without one gets the Website default, and a
    // saved check keeps its own.
    const kumaGroup = (parent && displayLine(parent.name, NAME_MAX).text) || null;
    const group = kumaGroup ?? newService('http').group;
    let pollSeconds = 0;
    if (monitor.interval === null)
      notes.push("No interval: it uses Uptime Goblin's default interval.");
    else {
      pollSeconds = Math.min(POLL_MAX, Math.max(POLL_MIN, Math.round(monitor.interval)));
      if (pollSeconds !== monitor.interval)
        notes.push(
          `Interval ${pollSeconds > monitor.interval ? 'raised' : 'lowered'} to ${pollSeconds} seconds (Uptime Goblin allows ${POLL_MIN}–${POLL_MAX}).`
        );
    }
    const input = {
      type: 'http',
      name,
      group,
      url: address.url,
      httpMethod: monitor.method,
      httpExpectedStatus: statuses(monitor.accepted),
      pollSeconds,
      enabled: monitor.active,
    };
    let checked;
    try {
      checked = validateService(input, newService('http', 'http-new'));
    } catch (error) {
      if (!(error instanceof InputError)) throw error;
      skip(monitor, `Uptime Goblin cannot check it: ${error.message}.`);
      continue;
    }
    if (monitor.type === 'keyword')
      notes.push(
        "Keyword not checked: Uptime Goblin's Website check tests the HTTP status only, not the page text."
      );
    if (monitor.maxRedirects > 0 && !acceptsRedirects(checked.httpExpectedStatus))
      notes.push(
        'Redirects are not followed: if the address redirects, use the final address or accept 300-399.'
      );
    if (monitor.ignoreTls)
      notes.push(
        'Uptime Goblin always verifies TLS certificates: a self-signed or expired certificate fails the check.'
      );
    if (monitor.proxied)
      notes.push(
        'Uptime Kuma checked it through a proxy; Uptime Goblin connects directly, so the address must be reachable from Uptime Goblin.'
      );
    if (address.stripped) notes.push('Credentials were removed from the address.');
    const needsCredentials = monitor.credentials || address.stripped;
    if (needsCredentials)
      notes.push(
        'Needs credentials re-entered: Uptime Kuma sent credentials or custom headers, and a Website check sends none, so the site may answer 401 or 403.'
      );
    // Names are matched without regard to case. A name another monitor of this backup took
    // gets a number; otherwise a saved Website check of that name is changed.
    let key = nameKey(name);
    if (claimed.has(key)) {
      const base = name;
      for (let n = 2; ; n++) {
        const suffix = ` (${n})`;
        name = displayLine(base, NAME_MAX - suffix.length).text + suffix;
        key = nameKey(name);
        if (!claimed.has(key) && !existing.has(key)) break;
      }
      notes.push('Renamed: another monitor in the backup has the same name.');
      input.name = name;
      checked.name = name;
    } else if (existing.has(key)) {
      const matches = existing.get(key);
      if (matches.length > 1) {
        skip(monitor, `${matches.length} Uptime Goblin sources are already named ${name}.`);
        continue;
      }
      const [saved] = matches;
      if (saved.type !== 'http' || collectorType(saved) !== 'http') {
        skip(monitor, `An Uptime Goblin ${typeName(saved.type)} source is already named ${name}.`);
        continue;
      }
      claimed.add(key);
      // The saved check is pointed at the monitor's address: a separate check address or path
      // would otherwise keep checking somewhere else.
      // Without a Kuma group, the user's own Uptime Goblin group stays.
      const wanted = {
        ...checked,
        apiUrl: '',
        metricPath: '',
        group: kumaGroup ?? saved.group ?? '',
      };
      const fields = changeFields.filter(field => (saved[field] ?? '') !== wanted[field]);
      if (!fields.length) {
        skip(monitor, 'Already in Uptime Goblin with the same settings.');
        continue;
      }
      const change = Object.fromEntries(fields.map(field => [field, wanted[field]]));
      plan.change.push({
        kumaId: monitor.id,
        id: saved.id,
        name: saved.name,
        fields,
        url: checked.url,
        method: checked.httpMethod,
        expectedStatus: checked.httpExpectedStatus,
        pollSeconds: checked.pollSeconds,
        group: wanted.group,
        needsCredentials,
        notes,
      });
      inputs.change.push([saved.id, change]);
      continue;
    }
    if (services.length + plan.add.length >= SOURCES_MAX) {
      skip(monitor, `Uptime Goblin holds at most ${SOURCES_MAX} sources.`);
      continue;
    }
    claimed.add(key);
    plan.add.push({
      kumaId: monitor.id,
      name,
      group: checked.group,
      url: checked.url,
      method: checked.httpMethod,
      expectedStatus: checked.httpExpectedStatus,
      pollSeconds: checked.pollSeconds,
      enabled: checked.enabled,
      needsCredentials,
      notes,
    });
    inputs.add.push(input);
  }
  return { ...plan, inputs };
}

/** The plan as the API shows it: without the settings the apply saves. */
export const publicPlan = ({ inputs, ...plan }) => plan;
