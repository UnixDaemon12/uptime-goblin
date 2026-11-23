// The System page.
import { api } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { dateTime, format, when } from '../core/format.js';
import { settingsBlock } from '../core/forms.js';
import { currentSession } from '../identity/session.js';
import { deliveryTexts } from './notifications.js';

/** Where the encryption key came from, as Uptime Goblin's start line names it (spec §6.7). */
function keySource(keys) {
  const file = keys.file ? ` (${keys.file})` : '';
  switch (keys.source) {
    case 'env':
      return 'GOBLIN_SECRET_KEY';
    case 'file':
      return `GOBLIN_SECRET_KEY_FILE${file}`;
    case 'credentials':
      return `The systemd credential${file}`;
    case 'secrets':
      return `The Compose secret${file}`;
    case 'data-directory':
      return keys.file || 'secret.key in the data directory';
    case 'generated':
      return `A new ${keys.file || 'secret.key in the data directory'} (generated at this start)`;
    default:
      return keys.source ? String(keys.source) : 'Unknown';
  }
}
/** The encryption key (never the key itself: where it comes from and its fingerprint). */
function keyBlock(keys, rows) {
  if (!keys || typeof keys !== 'object')
    return settingsBlock('Encryption key', '', rows([['Key', 'Unknown']]));
  // The server's own warning already says this, with the whole command line (keyLines in
  // server.mjs): the page adds its short sentence only when that warning is missing.
  const given = Array.isArray(keys.warnings) ? keys.warnings : [];
  const rewrap = 'Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS;';
  const warnings = [
    ...given,
    ...(keys.needsRewrap &&
    !given.some(warning => typeof warning === 'string' && warning.startsWith(rewrap))
      ? [`${rewrap} run goblin-admin key rotate with Uptime Goblin stopped.`]
      : []),
  ];
  return settingsBlock(
    'Encryption key',
    'Seals the webhook signing key. Back it up apart from the data directory: a backup of the data cannot be started without it.',
    rows([
      ['Source', keySource(keys)],
      ['Fingerprint', keys.fingerprint || 'Unknown'],
      ...(keys.previous
        ? [['Previous key', typeof keys.previous === 'string' ? keys.previous : 'Configured']]
        : []),
    ]) +
      (warnings.length
        ? `<ul class="system-warnings">${warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul>`
        : '')
  );
}
/** Free space and the reserve Uptime Goblin keeps for sign-in and delivery on a full disk (D14). */
function diskBlock(disk, rows) {
  if (!disk || typeof disk !== 'object')
    return settingsBlock('Disk', '', rows([['Free space', 'Unknown']]));
  const reserve = disk.reserveBytes ? format(disk.reserveBytes, 'bytes') : 'space';
  return settingsBlock(
    'Disk',
    '',
    rows([
      [
        'Free space',
        disk.measurable === false || !Number.isFinite(disk.freeBytes)
          ? 'Unknown: the file system does not report it'
          : format(disk.freeBytes, 'bytes'),
      ],
      ['State', disk.full ? `Full since ${dateTime(disk.since)}` : 'Space available'],
      [
        'Reserve for sign-in and alert delivery',
        disk.reserveHeld
          ? `Held (${reserve})`
          : disk.reserveReleased
            ? disk.freed === false
              ? 'Released, but the file system did not free the space'
              : 'Released while the disk is full'
            : 'Not held',
      ],
      ...(disk.full && disk.nextRecreateAt
        ? [['Next try to keep the reserve again', dateTime(disk.nextRecreateAt)]]
        : []),
    ])
  );
}
/**
 * The memory, CPU and process limits a supervised start found (lib/resource-limits.mjs), and
 * GOBLIN_ALLOW_UNLIMITED, read-only: it lowers a security control, so it is set only in Uptime Goblin's
 * environment and never on a page. An answer without them (an older Uptime Goblin) is Unknown. Every
 * value from the answer goes through rows(), which escapes it; the title and texts are fixed.
 */
function resourceLimitsBlock(limits, rows) {
  const title = 'Resource limits';
  const intro =
    "As Uptime Goblin found them when it started. Under a service manager Uptime Goblin checks them at every start and refuses to start without each limit unless GOBLIN_ALLOW_UNLIMITED names it; a limit lifted while Uptime Goblin runs shows here only after the next start, which then refuses. That setting is read only from Uptime Goblin's environment (/etc/uptime-goblin.env, or .env for Docker Compose); this page cannot change it.";
  if (!limits || typeof limits !== 'object')
    return settingsBlock(title, '', rows([['Limits', 'Unknown']]));
  if (limits.supervised !== true)
    return settingsBlock(
      title,
      '',
      '<p class="settings-info">Not checked: Uptime Goblin was started without supervision (neither --supervised nor GOBLIN_SUPERVISED=1, which the systemd unit and the Docker image give), as by npm start, so it did not check its limits.</p>'
    );
  const shown = limit => {
    const detail = typeof limit?.detail === 'string' && limit.detail ? ` (${limit.detail})` : '';
    if (limit?.state === 'enforced') return `Enforced${detail}`;
    const allowed = limit?.allowed === true ? ': allowed by GOBLIN_ALLOW_UNLIMITED' : '';
    return limit?.state === 'missing'
      ? `Not enforced${allowed}${detail}`
      : `Not verified${allowed}${detail}`;
  };
  const allow = Array.isArray(limits.allowUnlimited)
    ? limits.allowUnlimited.filter(name => ['memory', 'cpu', 'pids'].includes(name))
    : [];
  return settingsBlock(
    title,
    intro,
    rows([
      ['Memory', shown(limits.limits?.memory)],
      ['CPU', shown(limits.limits?.cpu)],
      ['Processes', shown(limits.limits?.pids)],
      ['GOBLIN_ALLOW_UNLIMITED', allow.length ? allow.join(',') : 'Not set'],
    ])
  );
}
/**
 * While legacy Basic is on (the session's `legacyBasic`), which scripts still sign in with the
 * password is the Audit log's "Scripts with a password" view (audit spec D31): this line opens it.
 */
function legacyBasicLine() {
  if (currentSession()?.legacyBasic !== true) return '';
  return '<p id="system-legacy-basic" class="settings-info">Scripts with a password (legacy Basic): allowed. See which scripts use it under <a class="text-link" href="#configure/audit" data-audit-kind="auth.basic.">Configure → Audit log, Kind: Scripts with a password</a>.</p>';
}
/** Waiting, failed and refused notifications, and whether they are being saved. */
function notificationsBlock(n, rows) {
  const link =
    '<p class="settings-info"><a class="text-link" href="#configure/notifications">Delivery history</a></p>';
  // The figures last computed are not shown as current (unavailable information stays so).
  if (n?.available !== true)
    return settingsBlock(
      'Notifications',
      '',
      `<p class="settings-info">${esc(deliveryTexts.unavailable)}</p>${link}`
    );
  const totals = n.totals || {};
  return settingsBlock(
    'Notifications',
    '',
    rows([
      ['Waiting to be sent', totals.waiting ?? 0],
      ['Waiting to retry', totals.retrying ?? 0],
      ['Held while a channel is paused', totals.paused ?? 0],
      ['Failed since the last successful one', totals.failed ?? 0],
      // A46: alerts the backlog cap refused, which the delivery history cannot list.
      ['Not queued since Uptime Goblin started (backlog full)', n.notQueued ?? 0],
      ['Oldest waiting', n.oldestWaitingAt ? dateTime(n.oldestWaitingAt) : 'None'],
      [
        'Saved',
        n.saving === false
          ? 'No: kept in memory until Uptime Goblin can write its control database'
          : 'Yes, in the control database',
      ],
    ]) + link
  );
}

export async function loadSystem() {
  const target = $('#system-details');
  if (!target) return;
  try {
    const s = await api('/api/system');
    if (target !== $('#system-details')) return;
    const rows = entries =>
      `<dl class="system-facts">${entries.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>`;
    target.innerHTML = `<div class="system-status"><span class="system-status-dot" aria-hidden="true"></span><div><h3>Uptime Goblin is online</h3><p>System information as of ${esc(when(Date.now()))}</p></div><button class="button" type="button" id="refresh-system">Refresh</button></div>${settingsBlock(
      'Your installation',
      '',
      rows([
        ['Uptime Goblin version', s.version],
        ...(s.build ? [['Build', s.build]] : []),
        ['Running for', format(s.uptimeSeconds, 'seconds')],
        ['Started', dateTime(s.startedAt)],
        ['Sign-in protection', 'Required'],
      ]) + legacyBasicLine()
    )}${
      Array.isArray(s.clients) && s.clients.length
        ? settingsBlock(
            'Open tabs by version',
            'Uptime Goblin pages that checked in during the last 10 minutes. Pages on an older version update themselves; pages from before 1.4.3 need one manual reload.',
            rows(
              s.clients.map(c => [
                c.current
                  ? `This version (${c.build})`
                  : c.build
                    ? `Older build ${c.build}`
                    : 'Before 1.4.3',
                `Last seen ${when(c.lastSeen)}`,
              ])
            )
          )
        : ''
    }${settingsBlock(
      'Collection right now',
      '',
      rows([
        ['In progress', s.collection.inflight],
        ['Waiting', s.collection.pending],
        ['Concurrency', s.collection.concurrency],
        ['Timeout', s.collection.timeoutSeconds + ' seconds'],
        ['Last successful collection', dateTime(s.collection.lastCollected)],
      ])
    )}${settingsBlock(
      'Local storage',
      '',
      rows([
        ['Database', format(s.data.databaseBytes, 'bytes')],
        ...(Number.isFinite(s.data.controlBytes)
          ? [['Control database', format(s.data.controlBytes, 'bytes')]]
          : []),
        [
          'History writes',
          s.data.writeFailure
            ? `Failing since ${dateTime(s.data.writeFailure.since)} (${s.data.writeFailure.code})`
            : 'Working',
        ],
        ['Configuration', format(s.data.configBytes, 'bytes')],
        ['Saved readings', s.data.samples.toLocaleString()],
        ['Alert events', s.data.events.toLocaleString()],
        ['Active alerts', s.data.activeAlerts],
      ])
    )}${diskBlock(s.disk, rows)}${notificationsBlock(s.notifications, rows)}${keyBlock(s.keys, rows)}${resourceLimitsBlock(s.resourceLimits, rows)}${settingsBlock(
      'Workspace limits',
      '',
      rows([
        ['Sources', s.limits.sources],
        ['Mappings per source', s.limits.mappingsPerSource],
        ['Rules per source', s.limits.rulesPerSource],
      ])
    )}<p class="configuration-footnote">This page is a snapshot. Refresh to read the latest state.</p>`;
  } catch (e) {
    if (target === $('#system-details'))
      target.innerHTML = `<p class="field-error" role="alert">${esc(e.message)}</p><button class="button" type="button" id="refresh-system">Try again</button>`;
  }
}
