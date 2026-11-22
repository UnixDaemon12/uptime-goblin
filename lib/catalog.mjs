export const definitions = [
  ['proxmox', 'Proxmox', 'Infrastructure', 'orange', 'server', ['CPU', 'Memory', 'Guests']],
  ['linux', 'Linux systems', 'Infrastructure', 'cyan', 'terminal', ['CPU', 'Memory', 'Disk']],
  ['windows', 'Windows systems', 'Infrastructure', 'blue', 'window', ['CPU', 'Memory', 'Disk']],
  [
    'unifi',
    'UniFi Network',
    'Infrastructure',
    'blue',
    'network',
    ['Devices', 'Clients', 'Traffic'],
  ],
  ['synology', 'Synology NAS', 'Infrastructure', 'violet', 'drive', ['CPU', 'Memory', 'Disk']],
  ['docker', 'Docker', 'Infrastructure', 'cyan', 'layers', ['Running', 'Stopped', 'Containers']],
  ['plex', 'Plex', 'Media', 'amber', 'play', ['Streams', 'Transcodes', 'Bandwidth']],
  ['tautulli', 'Tautulli', 'Media', 'orange', 'activity', ['Streams', 'Transcodes', 'Bandwidth']],
  ['seerr', 'Seerr', 'Media', 'violet', 'ticket', ['Pending', 'Approved', 'Available']],
  ['sonarr', 'Sonarr', 'Media', 'blue', 'tv', ['Series', 'Episodes', 'Queue']],
  ['radarr', 'Radarr', 'Media', 'amber', 'film', ['Movies', 'Missing', 'Queue']],
  ['prowlarr', 'Prowlarr', 'Media', 'pink', 'radar', ['Indexers', 'Queries', 'Failures']],
  ['sabnzbd', 'SABnzbd', 'Downloads', 'amber', 'download', ['Speed', 'Queue', 'Remaining']],
  ['nzbget', 'NZBGet', 'Downloads', 'green', 'download', ['Speed', 'Queue', 'Remaining']],
  [
    'crowdsec',
    'CrowdSec',
    'Network & security',
    'orange',
    'shield',
    ['Alerts', 'Decisions', 'Bans'],
  ],
  [
    'npm',
    'Nginx Proxy Manager',
    'Network & security',
    'green',
    'route',
    ['Enabled', 'Disabled', 'Hosts'],
  ],
  [
    'adguard',
    'AdGuard Home',
    'Network & security',
    'green',
    'shield',
    ['Queries', 'Blocked', 'Response'],
  ],
  ['wireguard', 'WireGuard', 'Network & security', 'violet', 'lock', ['Peers', 'Received', 'Sent']],
  ['cosmos', 'Cosmos', 'Utilities', 'violet', 'orbit', ['CPU', 'Memory', 'Containers']],
  ['amp', 'AMP', 'Gaming', 'pink', 'gamepad', ['CPU', 'Memory', 'Players']],
  ['netbox', 'NetBox', 'Utilities', 'cyan', 'grid', []],
  ['prometheus', 'Prometheus exporter', 'Infrastructure', 'orange', 'activity', []],
  ['json', 'Custom API', 'Utilities', 'cyan', 'grid', []],
  ['http', 'Website', 'Utilities', 'blue', 'globe', ['Response', 'Available']],
  ['link', 'Bookmark', 'Utilities', 'violet', 'external', []],
];
export function newService(type, id = type, name) {
  const definition = definitions.find(d => d[0] === type);
  if (!definition) throw new Error('Unknown service type');
  const [, defaultName, group, color, icon, labels] = definition;
  return {
    id,
    type,
    name: name || defaultName,
    group,
    color,
    icon,
    labels,
    enabled: true,
    showOnDashboard: true,
    pollSeconds: 0,
    url: '',
    apiUrl: '',
    apiKey: '',
    username: '',
    password: '',
    siteId: '',
    nodeName: '',
    metricPath: '',
    httpExpectedStatus: '200-399',
    httpMethod: 'GET',
    collector: 'native',
    monitoring: {},
    alerts: {},
    metrics: [],
    rules: [],
  };
}
export function collectorType(service) {
  if (service.collector && service.collector !== 'native') return service.collector;
  return { netbox: 'none', link: 'none' }[service.type] || service.type;
}
// Bookmarks (and cards set to no collector) only link somewhere; nothing is collected.
export const noCollector = service => collectorType(service) === 'none';
// Whether a source has what it needs to be collected: an API address, or the destination of
// a Website check that has none. The same rules as server.mjs, which keeps its own copies
// until the scheduler moves out of it.
export const configured = service =>
  !noCollector(service) &&
  Boolean(service.apiUrl || (collectorType(service) === 'http' && service.url));
export function emailDefaults() {
  return {
    enabled: false,
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    from: '',
    to: '',
    password: '',
  };
}
export function publicEmail(email) {
  const { enabled, host, port, secure, from, to } = email;
  return { enabled, host, port, secure, from, to, passwordConfigured: Boolean(email.password) };
}
export function appearanceDefaults() {
  return {
    accent: 'cyan',
    density: 'comfortable',
    columns: 'auto',
    defaultRange: '24h',
    sortBy: 'manual',
    showSummary: true,
    showPaused: true,
    showUnconfigured: true,
    openInNewTab: true,
    reduceMotion: false,
    timezone: 'local',
    timeFormat: 'auto',
  };
}
export function monitoringDefaults() {
  return {
    concurrency: 4,
    timeoutSeconds: 90,
    retryCount: 2,
    retryDelaySeconds: 2,
    availabilityFailures: 2,
    availabilitySeconds: 60,
    recoverySuccesses: 2,
    recoverySeconds: 60,
  };
}
export function alertDefaults() {
  return {
    enabled: true,
    notifyOnAlert: true,
    notifyOnRecovery: true,
    notifyAvailability: true,
    notifyMeasurements: true,
  };
}
export function defaults() {
  const services = definitions
    .filter(d => !['json', 'prometheus', 'http', 'link'].includes(d[0]))
    .map(([type]) => newService(type));
  const cosmos = services.findIndex(s => s.type === 'cosmos');
  services.splice(
    cosmos,
    1,
    ...[1, 2, 3].map(n => newService('cosmos', `cosmos-${n}`, `Cosmos ${n}`))
  );
  return {
    title: 'Uptime Goblin',
    subtitle: 'a little clarity for your homelab',
    retentionDays: 30,
    pollSeconds: 60,
    appearance: appearanceDefaults(),
    monitoring: monitoringDefaults(),
    alerts: alertDefaults(),
    email: emailDefaults(),
    services,
  };
}
export const secretFields = ['apiKey', 'password'];
export function publicConfig(config) {
  return {
    ...config,
    ...(config.email ? { email: publicEmail(config.email) } : {}),
    services: config.services.map(s => {
      const v = { ...s };
      for (const key of secretFields) {
        v[`${key}Configured`] = Boolean(v[key]);
        delete v[key];
      }
      return v;
    }),
  };
}
