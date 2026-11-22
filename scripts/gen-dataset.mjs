#!/usr/bin/env node
// Synthetic history for benchmarks and upgrade rehearsals: a data directory Orbit starts on,
// with SOURCES sources (default 24, a typical homelab mix) and DAYS days (default 30) of
// readings every INTERVAL seconds, in the payload shapes Orbit's collectors record (Proxmox
// with per-guest detail, exporters with disks, UniFi with devices, and so on). Readings include
// failures, a maintenance pause per source, alert events, one firing alert and collector notes.
//
//   node scripts/gen-dataset.mjs --out DIR [--sources 24] [--days 30] [--interval 60]
//                                [--seed 1] [--end 2026-09-01T00:00:00Z] [--force]
//
// With --end, the same arguments always give the same data. The default end is now, so a
// server started on the result shows current readings and keeps them. The defaults write about
// a million readings (roughly 1.6 GB, in seconds); check free space first. Hostnames are
// reserved example names and every credential is a placeholder: nothing here can reach a real
// system, and a server started on the result only reports those sources as unreachable.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { newService } from '../lib/catalog.mjs';
import { ConfigStore, validateService } from '../lib/config.mjs';
import { Store } from '../lib/store.mjs';
import { exposeStoreConnections } from '../lib/store-connections.mjs';

// The generator, usable from tests; the command line is at the end.
export function generate({
  out,
  sources = 24,
  days = 30,
  interval = 60,
  seed = 1,
  end = Date.now(),
  force = false,
  log = () => {},
}) {
  if (!Number.isInteger(sources) || sources < 1 || sources > 200)
    throw new Error('--sources must be 1-200, the most one Orbit 1.4 installation accepts');
  if (!(days > 0 && days <= 365)) throw new Error('--days must be more than 0 and at most 365');
  if (!Number.isInteger(interval) || interval < 15 || interval > 3600)
    throw new Error('--interval must be 15-3600 seconds');
  if (fs.existsSync(out) && fs.readdirSync(out).length) {
    if (!force) throw new Error(`${out} is not empty; pass --force to replace its data`);
    for (const file of [
      'config.json',
      'history.sqlite',
      'history.sqlite-wal',
      'history.sqlite-shm',
    ])
      fs.rmSync(path.join(out, file), { force: true });
  }
  const random = mulberry32(seed),
    specs = Array.from({ length: sources }, (_, i) => {
      const spec = mix[i % mix.length],
        round = Math.floor(i / mix.length);
      return { ...spec, name: round ? `${spec.name} ${round + 1}` : spec.name };
    });

  // Configuration: the sources as the API would save them, with Orbit's own validation.
  const config = new ConfigStore(out),
    counts = {},
    services = specs.map(spec => {
      const n = (counts[spec.type] = (counts[spec.type] ?? 0) + 1),
        id = `${spec.type}-${n}`;
      return validateService(
        {
          type: spec.type,
          name: spec.name,
          apiUrl: `https://${spec.type}-${n}.example.test${spec.port ? ':' + spec.port : ''}`,
          ...(spec.secret ? { apiKey: 'synthetic-placeholder-token' } : {}),
          ...(spec.mappings ? { metrics: spec.mappings } : {}),
        },
        newService(spec.type, id)
      );
    });
  config.save({
    ...config.value,
    title: 'Synthetic homelab',
    // One day more than the history, so the first prune keeps all of it.
    retentionDays: Math.min(365, Math.ceil(days) + 1),
    pollSeconds: interval,
    services,
    sourceCounters: counts,
  });

  // History, written in large transactions straight into the store's own schema. The Store keeps
  // its connection private from server code; this development tool (never shipped) asks for it.
  exposeStoreConnections();
  const store = new Store(out),
    db = store.db,
    step = interval * 1000,
    last = end - (end % step),
    first = last - Math.floor((days * 86400000) / step) * step,
    // One source is down at the end, as a real dashboard usually shows something.
    down = services.length > 1 ? 1 : 0,
    downSince = last - 10 * step;
  db.exec('PRAGMA synchronous=OFF');
  const sql = {
    reading: db.prepare(
      'INSERT OR REPLACE INTO readings(service,time,ok,metrics,error) VALUES (?,?,?,?,?)'
    ),
    event: db.prepare(
      "INSERT INTO events(service,time,kind,message,category,rule) VALUES (?,?,?,?,'availability','__availability')"
    ),
    latest: db.prepare(
      'INSERT OR REPLACE INTO latest(service,attempted,success,metrics,error) VALUES (?,?,?,?,?)'
    ),
    notes: db.prepare('INSERT OR REPLACE INTO latest_notes(service,time,notes) VALUES (?,?,?)'),
    alert: db.prepare(
      "INSERT OR REPLACE INTO alerts(service,rule,state,since,count,message,updated,recovery_since,recovery_count) VALUES (?,'__availability','firing',?,?,?,?,NULL,0)"
    ),
  };
  let readings = 0,
    bytes = 0;
  services.forEach((service, index) => {
    const spec = specs[index],
      metrics = spec.shape(),
      state = metrics.map(x => initial(x.kind, random)),
      // Sources poll at their own offsets, so readings interleave as they do live.
      offset = Math.floor(random() * Math.min(step, 30000)),
      pauseAt = first + Math.floor(random() * (last - first)),
      pauseUntil = pauseAt + 2 * 3600000;
    let latest = { attempted: null, success: null, metrics: '[]', error: null },
      outage = null,
      downFrom = null;
    const counted = () => {
      if (++readings % 20000) return;
      db.exec('COMMIT; BEGIN');
      log(`${readings.toLocaleString('en')} readings`);
    };
    const fail = (time, error) => {
      sql.reading.run(service.id, time, 0, '[]', error);
      latest = { ...latest, attempted: time, error };
      counted();
    };
    db.exec('BEGIN');
    for (let time = first + offset; time <= last; time += step) {
      // A two-hour maintenance pause: a gap marker, then no readings.
      if (time >= pauseAt && time < pauseUntil) {
        if (time - step < pauseAt) sql.reading.run(service.id, time, 0, '[]', '__gap');
        continue;
      }
      if (index === down && time >= downSince) {
        if (downFrom === null) {
          downFrom = time;
          sql.event.run(service.id, time, 'firing', `Source is unavailable: ${errors[0]}`);
        }
        fail(time, errors[0]);
        continue;
      }
      // About one collection in 300 starts a short outage; two failures raise an alert.
      if (!outage && random() < 1 / 300) outage = { left: 1 + Math.floor(random() * 4), failed: 0 };
      if (outage?.left > 0) {
        const error = errors[Math.floor(random() * errors.length)];
        outage.left--;
        if (++outage.failed === 2)
          sql.event.run(service.id, time, 'firing', `Source is unavailable: ${error}`);
        fail(time, error);
        continue;
      }
      if (outage?.failed >= 2)
        sql.event.run(service.id, time, 'resolved', 'Connection restored after 3 min');
      outage = null;
      const json = reading(metrics, state, random, time);
      sql.reading.run(service.id, time, 1, json, null);
      latest = { attempted: time, success: time, metrics: json, error: null };
      bytes += json.length;
      counted();
    }
    sql.latest.run(service.id, latest.attempted, latest.success, latest.metrics, latest.error);
    if (spec.notes && latest.success !== null)
      sql.notes.run(service.id, latest.success, JSON.stringify(spec.notes));
    if (downFrom !== null)
      sql.alert.run(
        service.id,
        downFrom,
        Math.round((latest.attempted - downFrom) / step) + 1,
        `Source is unavailable: ${errors[0]}`,
        latest.attempted
      );
    db.exec('COMMIT');
  });
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  store.close();
  return {
    sources: services.length,
    readings,
    metricBytes: bytes,
    databaseBytes: fs.statSync(path.join(out, 'history.sqlite')).size,
    first,
    last,
  };
}

// A homelab mix, 24 sources, with the reading keys, labels and units the collectors use.
const range = (n, fn) => Array.from({ length: n }, (_, i) => fn(i));
const m = (key, label, unit, kind) => ({ key, label, unit, kind });
const disks = (count, prefix = '/') =>
  range(count, i => {
    const mount = i ? `${prefix}mnt/disk${i}` : '/';
    return [
      m(`disk_${mount}`, `${mount} · Used`, '%', 'percent'),
      m(`disk_free_${mount}`, `${mount} · Free`, 'bytes', 'bytes'),
    ];
  }).flat();
const arrDisks = range(3, i => [
  m(`disk_/data/media${i}`, `/data/media${i} · Used`, '%', 'percent'),
  m(`disk_free_/data/media${i}`, `/data/media${i} · Free`, 'bytes', 'bytes'),
]).flat();
const health = [
  m('health_issues', 'Health issues', '', 'small'),
  m('health_notices', 'Health notices', '', 'small'),
  m('queue_errors', 'Queue has errors', '', 'flag'),
  m('queue_warnings', 'Queue has warnings', '', 'flag'),
];
const mapped = keys => keys.map(([key, label, unit]) => ({ key, label, path: key, unit }));
const synologyKeys = [
  ['cpu', 'CPU', '%'],
  ['memory', 'Memory', '%'],
  ['volume_used', 'Volume used', '%'],
  ['volume_free', 'Volume free', 'bytes'],
  ['temperature', 'Temperature', '°C'],
  ['disk_1_temperature', 'Disk 1 temperature', '°C'],
  ['disk_2_temperature', 'Disk 2 temperature', '°C'],
  ['receive', 'Receive', 'bytes/s'],
  ['transmit', 'Send', 'bytes/s'],
  ['uptime', 'Uptime', 'seconds'],
];
const wireguardKeys = [
  ['peers', 'Peers', ''],
  ['received', 'Received', 'bytes/s'],
  ['sent', 'Sent', 'bytes/s'],
  ...range(5, i => [`peer_${i}_handshake`, `Peer ${i} · Last handshake`, 'seconds']),
];
const jsonKeys = [
  ['temperature', 'Temperature', '°C'],
  ['humidity', 'Humidity', '%'],
  ['power', 'Power', 'W'],
  ['energy_today', 'Energy today', 'kWh'],
  ['battery', 'Battery', '%'],
];
const kinds = { '%': 'percent', bytes: 'bytes', 'bytes/s': 'rate', seconds: 'uptime', ms: 'ms' };
const fromMappings = keys => () =>
  keys.map(([key, label, unit]) => m(key, label, unit, kinds[unit] ?? 'gauge'));
const mix = [
  {
    type: 'proxmox',
    name: 'Proxmox cluster',
    port: 8006,
    secret: true,
    shape: () => [
      m('cpu', 'CPU', '%', 'percent'),
      m('memory', 'Memory', '%', 'percent'),
      m('guests_running', 'Guests', '', 'count'),
      m('nodes_online', 'Nodes online', '', 'fixed'),
      m('nodes_total', 'Nodes', '', 'fixed'),
      m('guests_total', 'Total guests', '', 'fixed'),
      m('memory_used', 'Memory used', 'bytes', 'bytes'),
      m('memory_total', 'Memory total', 'bytes', 'fixed'),
      ...range(3, n =>
        ['local', 'local-lvm', 'nas-backup', 'ceph'].flatMap(s => [
          m(`storage/pve${n + 1}/${s}.used`, `${s} · Used`, 'bytes', 'bytes'),
          m(`storage/pve${n + 1}/${s}.total`, `${s} · Capacity`, 'bytes', 'fixed'),
        ])
      ).flat(),
      ...range(3 + 40, i => {
        const [prefix, name] =
          i < 3
            ? [`node/pve${i + 1}`, `pve${i + 1}`]
            : [`${i % 3 ? 'lxc' : 'qemu'}/${100 + i}`, `guest-${100 + i}`];
        return [
          m(`${prefix}.cpu`, `${name} · CPU`, '%', 'percent'),
          m(`${prefix}.memory`, `${name} · Memory`, 'bytes', 'bytes'),
          m(`${prefix}.uptime`, `${name} · Uptime`, 'seconds', 'uptime'),
        ];
      }).flat(),
    ],
  },
  ...['Docker host', 'Media server'].map(name => ({
    type: 'linux',
    name,
    port: 9100,
    shape: () => [
      m('cpu', 'CPU', '%', 'percent'),
      m('memory', 'Memory', '%', 'percent'),
      ...disks(6),
      m('memory_used', 'Memory used', 'bytes', 'bytes'),
      m('memory_total', 'Memory total', 'bytes', 'fixed'),
      m('load1', 'Load · 1m', '', 'gauge'),
      m('uptime', 'Uptime', 'seconds', 'uptime'),
      m('receive', 'Receive', 'bytes/s', 'rate'),
      m('transmit', 'Send', 'bytes/s', 'rate'),
    ],
  })),
  {
    type: 'windows',
    name: 'Gaming PC',
    port: 9182,
    shape: () => [
      m('cpu', 'CPU', '%', 'percent'),
      m('memory', 'Memory', '%', 'percent'),
      ...['C:', 'D:', 'E:'].flatMap(v => [
        m(`disk_${v}`, `${v} · Used`, '%', 'percent'),
        m(`disk_free_${v}`, `${v} · Free`, 'bytes', 'bytes'),
      ]),
      m('memory_total', 'Memory total', 'bytes', 'fixed'),
      m('memory_free', 'Memory free', 'bytes', 'bytes'),
      m('received', 'Receive', 'bytes/s', 'rate'),
      m('sent', 'Send', 'bytes/s', 'rate'),
    ],
  },
  {
    type: 'unifi',
    name: 'UniFi',
    secret: true,
    shape: () => [
      ...[
        ['devices', 'Devices'],
        ['clients', 'Clients'],
        ['sites', 'Sites'],
        ['devices_online', 'Devices online'],
        ['devices_offline', 'Devices disconnected'],
      ].map(([key, label]) => m(key, label, '', 'count')),
      m('cpu', 'Gateway CPU', '%', 'percent'),
      m('memory', 'Gateway memory', '%', 'percent'),
      m('uptime', 'Gateway uptime', 'seconds', 'uptime'),
      m('wan_receive', 'WAN receive', 'bytes/s', 'rate'),
      m('wan_transmit', 'WAN send', 'bytes/s', 'rate'),
      m('wan_latency', 'Internet latency', 'ms', 'ms'),
      m('clients_wired', 'Wired clients', '', 'count'),
      m('clients_wireless', 'Wireless clients', '', 'count'),
      ...range(12, i => {
        const id = `64f0c2a1b3d4e5f6a7b8c9${String(i).padStart(2, '0')}`,
          name = i < 4 ? `Switch ${i + 1}` : `Access point ${i - 3}`;
        return [
          m(`device_${id}_cpu`, `${name} · CPU`, '%', 'percent'),
          m(`device_${id}_memory`, `${name} · Memory`, '%', 'percent'),
          m(`device_${id}_uptime`, `${name} · Uptime`, 'seconds', 'uptime'),
          m(`device_${id}_rx`, `${name} · Receive`, 'bytes/s', 'rate'),
          m(`device_${id}_tx`, `${name} · Send`, 'bytes/s', 'rate'),
        ];
      }).flat(),
    ],
  },
  {
    type: 'synology',
    name: 'Synology',
    port: 9100,
    mappings: mapped(synologyKeys),
    shape: fromMappings(synologyKeys),
  },
  {
    type: 'docker',
    name: 'Docker',
    port: 2375,
    shape: () => [
      m('running', 'Running', '', 'count'),
      m('stopped', 'Stopped', '', 'small'),
      m('containers', 'Containers', '', 'fixed'),
    ],
  },
  ...['plex', 'tautulli'].map(type => ({
    type,
    name: type === 'plex' ? 'Plex' : 'Tautulli',
    secret: true,
    shape: () => [
      m('streams', 'Streams', '', 'small'),
      m('transcodes', 'Transcodes', '', 'small'),
      m('bandwidth', 'Bandwidth', 'bytes/s', 'rate'),
      m('direct_play', 'Direct play', '', 'small'),
      m('direct_stream', 'Direct stream', '', 'small'),
      m('lan_bandwidth', 'LAN bandwidth', 'bytes/s', 'rate'),
      m('wan_bandwidth', 'WAN bandwidth', 'bytes/s', 'rate'),
    ],
  })),
  {
    type: 'seerr',
    name: 'Seerr',
    secret: true,
    shape: () =>
      ['Pending', 'Approved', 'Available', 'Processing', 'Declined', 'Total'].map(l =>
        m(l.toLowerCase(), l, '', 'count')
      ),
  },
  {
    type: 'sonarr',
    name: 'Sonarr',
    secret: true,
    shape: () => [
      m('series', 'Series', '', 'fixed'),
      m('episodes', 'Episodes', '', 'counter'),
      m('queue', 'Queue', '', 'small'),
      m('missing', 'Missing episodes', '', 'count'),
      ...health,
      ...arrDisks,
    ],
  },
  {
    type: 'radarr',
    name: 'Radarr',
    secret: true,
    // A library over the read limit: its counts are left out and the source says why.
    notes: [
      {
        code: 'arr_library_too_large',
        message:
          'The Radarr library exceeds a reading limit (64 MB total, 200,000 entries, or 1 MB per entry). Library counts are left out; queue, health and disk readings continue.',
      },
    ],
    shape: () => [m('queue', 'Queue', '', 'small'), ...health, ...arrDisks],
  },
  {
    type: 'prowlarr',
    name: 'Prowlarr',
    secret: true,
    shape: () => [
      m('indexers', 'Indexers', '', 'fixed'),
      m('queries_24h', 'Queries · 24h', '', 'count'),
      m('grabs_24h', 'Grabs · 24h', '', 'count'),
      m('failures_24h', 'Failures · 24h', '', 'small'),
      m('health_issues', 'Health issues', '', 'small'),
      m('health_notices', 'Health notices', '', 'small'),
    ],
  },
  ...['sabnzbd', 'nzbget'].map(type => ({
    type,
    name: type === 'sabnzbd' ? 'SABnzbd' : 'NZBGet',
    secret: type === 'sabnzbd',
    shape: () => [
      m('speed', 'Speed', 'bytes/s', 'rate'),
      m('queue', 'Queue', '', 'small'),
      m('remaining', 'Remaining', 'bytes', 'bytes'),
      m('paused', 'Paused', '', 'flag'),
      m('download_disk_free', 'Download disk free', 'bytes', 'bytes'),
      m('complete_disk_free', 'Completed disk free', 'bytes', 'bytes'),
      m('uptime', 'Uptime', 'seconds', 'uptime'),
    ],
  })),
  {
    type: 'crowdsec',
    name: 'CrowdSec',
    port: 8080,
    secret: true,
    shape: () => [
      m('alerts_24h', 'Alerts · 24h (max 1k)', '', 'count'),
      m('decisions', 'Local decisions', '', 'count'),
      m('bans', 'Local bans', '', 'count'),
    ],
  },
  {
    type: 'npm',
    name: 'Nginx Proxy Manager',
    shape: () => [
      m('enabled', 'Enabled', '', 'fixed'),
      m('disabled', 'Disabled', '', 'small'),
      m('hosts', 'Hosts', '', 'fixed'),
    ],
  },
  {
    type: 'adguard',
    name: 'AdGuard Home',
    shape: () => [
      m('queries', 'Queries', '', 'counter'),
      m('blocked', 'Blocked', '', 'counter'),
      m('response', 'Response', 'ms', 'ms'),
      m('blocked_percent', 'Blocked', '%', 'percent'),
      m('safe_browsing', 'Safe browsing', '', 'small'),
      m('parental', 'Parental filtering', '', 'small'),
    ],
  },
  {
    type: 'wireguard',
    name: 'WireGuard',
    port: 9586,
    mappings: mapped(wireguardKeys),
    shape: fromMappings(wireguardKeys),
  },
  {
    type: 'cosmos',
    name: 'Cosmos',
    secret: true,
    shape: () => [
      m('cpu', 'CPU', '%', 'percent'),
      m('memory', 'Memory', '%', 'percent'),
      m('containers', 'Containers', '', 'fixed'),
      m('running', 'Running', '', 'count'),
      m('memory_used', 'Memory used', 'bytes', 'bytes'),
      m('memory_total', 'Memory total', 'bytes', 'fixed'),
      m('receive', 'Receive', 'bytes/s', 'rate'),
      m('transmit', 'Send', 'bytes/s', 'rate'),
    ],
  },
  {
    type: 'amp',
    name: 'AMP',
    shape: () => [
      m('cpu', 'CPU', '%', 'percent'),
      m('memory', 'Memory', 'MB', 'gauge'),
      m('players', 'Players', '', 'small'),
      m('memory_percent', 'Memory used', '%', 'percent'),
      m('players_max', 'Player capacity', '', 'fixed'),
      ...['TPS', 'Uptime', 'Chunks_Loaded', 'Entities', 'Backups'].map(n =>
        m(`amp_${n}`, n.replace('_', ' '), '', 'gauge')
      ),
    ],
  },
  ...['Home Assistant', 'Nextcloud'].map(name => ({
    type: 'http',
    name,
    shape: () => [
      m('response', 'Response', 'ms', 'ms'),
      m('available', 'Available', '', 'one'),
      m('http_status', 'HTTP status', '', 'status'),
    ],
  })),
  {
    type: 'json',
    name: 'Energy monitor',
    mappings: mapped(jsonKeys),
    shape: fromMappings(jsonKeys),
  },
];
const errors = [
  'Connection refused by the source. Check that it is running and the address and port are correct.',
  'Source did not respond within 12 seconds.',
  'Authentication failed. Check the API key.',
  'DNS lookup failed. Check the source hostname and DNS server.',
];

// Values move like real ones: bounded random walks, slowly growing counters, fixed capacities.
function initial(kind, random) {
  switch (kind) {
    case 'percent':
      return 10 + random() * 60;
    case 'bytes':
      return Math.floor(2 ** 30 * (4 + random() * 200));
    case 'rate':
      return random() * 5e6;
    case 'uptime':
      return Math.floor(random() * 3e6);
    case 'counter':
      return Math.floor(random() * 1e5);
    case 'ms':
      return 5 + random() * 50;
    case 'fixed':
      return 1 + Math.floor(random() * 64);
    case 'one':
      return 1;
    case 'status':
      return 200;
    case 'flag':
      return 0;
    default:
      return Math.floor(random() * 20);
  }
}
function next(kind, value, random, seconds) {
  switch (kind) {
    case 'percent':
      return Math.min(100, Math.max(0, value + (random() - 0.5) * 6));
    case 'bytes':
      return Math.max(0, Math.round(value + (random() - 0.5) * 2 ** 26));
    case 'rate':
      return Math.max(0, value * (0.7 + random() * 0.6) + (random() < 0.05 ? random() * 2e7 : 0));
    case 'uptime':
      return value + seconds;
    case 'counter':
      return value + Math.floor(random() * 40);
    case 'ms':
      return Math.max(1, value * (0.8 + random() * 0.4));
    case 'flag':
      return random() < 0.02 ? 1 - value : value;
    case 'fixed':
    case 'one':
    case 'status':
      return value;
    default:
      return Math.max(0, value + Math.round((random() - 0.5) * 3));
  }
}
// JSON built from fixed fragments per reading: the same bytes JSON.stringify gives for
// [{key,label,value,unit}], several times faster for a million readings.
function reading(metrics, state, random, time) {
  metrics.fragments ??= metrics.map(x => [
    `{"key":${JSON.stringify(x.key)},"label":${JSON.stringify(x.label)},"value":`,
    `,"unit":${JSON.stringify(x.unit)}}`,
  ]);
  const seconds = (time - (metrics.at ?? time)) / 1000 || 60;
  metrics.at = time;
  let json = '[';
  for (let i = 0; i < metrics.length; i++) {
    state[i] = next(metrics[i].kind, state[i], random, seconds);
    json += (i ? ',' : '') + metrics.fragments[i][0] + String(state[i]) + metrics.fragments[i][1];
  }
  return json + ']';
}
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const main = () => {
  try {
    return fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};
if (main()) {
  const { values } = parseArgs({
    options: {
      out: { type: 'string' },
      sources: { type: 'string', default: '24' },
      days: { type: 'string', default: '30' },
      interval: { type: 'string', default: '60' },
      seed: { type: 'string', default: '1' },
      end: { type: 'string' },
      force: { type: 'boolean', default: false },
    },
  });
  if (!values.out) {
    console.error(
      'Usage: node scripts/gen-dataset.mjs --out DIR [--sources 24] [--days 30] [--interval 60] [--seed 1] [--end ISO] [--force]'
    );
    process.exit(64);
  }
  const end = values.end === undefined ? undefined : Date.parse(values.end);
  if (Number.isNaN(end)) {
    console.error('--end must be an ISO date');
    process.exit(64);
  }
  const started = performance.now();
  try {
    const result = generate({
      out: path.resolve(values.out),
      sources: Number(values.sources),
      days: Number(values.days),
      interval: Number(values.interval),
      seed: Number(values.seed),
      end,
      force: values.force,
      log: line => process.stderr.isTTY && process.stderr.write(line + '\r'),
    });
    console.log(
      `${result.sources} sources, ${result.readings.toLocaleString('en')} readings from ${new Date(result.first).toISOString()} to ${new Date(result.last).toISOString()}: ` +
        `${(result.databaseBytes / 2 ** 20).toFixed(1)} MiB history in ${((performance.now() - started) / 1000).toFixed(1)} s`
    );
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
