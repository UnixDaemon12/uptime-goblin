// Synthetic Uptime Kuma 1.x backups for the import's tests (test/kuma-import*.test.mjs): the
// shape Kuma 1.23 exports, with documentation addresses only, and planted secrets the tests
// check never reach a plan, a reduced backup, the configuration or the audit log.

/** The secrets planted in mixedBackup(). */
export const kumaSecrets = Object.freeze([
  'kuma-basic-secret',
  'kuma-header-token',
  'kuma-oauth-secret',
  'kuma-url-pw',
]);

/** One monitor as Uptime Kuma 1.23 exports it, with `fields` over its defaults. */
export function kumaMonitor(id, fields = {}) {
  return {
    id,
    name: `Site ${id}`,
    description: null,
    pathName: `Site ${id}`,
    parent: null,
    childrenIDs: [],
    url: `https://site${id}.example.com/`,
    method: 'GET',
    hostname: null,
    port: null,
    maxretries: 0,
    weight: 2000,
    active: true,
    forceInactive: false,
    type: 'http',
    timeout: 48,
    interval: 60,
    retryInterval: 60,
    resendInterval: 0,
    keyword: null,
    invertKeyword: false,
    expiryNotification: false,
    ignoreTls: false,
    upsideDown: false,
    packetSize: 56,
    maxredirects: 10,
    accepted_statuscodes: ['200-299'],
    dns_resolve_type: 'A',
    dns_resolve_server: '192.0.2.53',
    dns_last_result: null,
    docker_container: '',
    docker_host: null,
    proxyId: null,
    notificationIDList: { 1: true },
    tags: [],
    maintenance: false,
    authMethod: null,
    basic_auth_user: null,
    basic_auth_pass: null,
    authDomain: null,
    authWorkstation: null,
    headers: null,
    body: null,
    httpBodyEncoding: 'json',
    // Kuma 1.23's editor saves these defaults on every monitor, whatever its authMethod.
    oauth_client_id: null,
    oauth_client_secret: null,
    oauth_auth_method: 'client_secret_basic',
    oauth_token_url: null,
    oauth_scopes: null,
    kafkaProducerSaslOptions: { mechanism: 'None' },
    mqttUsername: '',
    mqttPassword: '',
    mqttTopic: '',
    mqttSuccessMessage: '',
    tlsCert: null,
    tlsKey: null,
    tlsCa: null,
    includeSensitiveData: true,
    ...fields,
  };
}
/** A Kuma 1.x backup of `monitors`. */
export const kumaBackup = (monitors, version = '1.23.16') => ({
  version,
  notificationList: [
    { id: 1, name: 'Mail', config: '{"smtpPassword":"kuma-basic-secret"}', active: true },
  ],
  proxyList: [],
  monitorList: monitors,
});
/** A backup of every kind of monitor the import handles. */
export function mixedBackup() {
  return kumaBackup([
    kumaMonitor(1, { type: 'group', name: 'Media', url: null }),
    kumaMonitor(2, { parent: 1, name: 'Plex web' }),
    kumaMonitor(3, { type: 'keyword', keyword: 'Welcome', invertKeyword: true, maxredirects: 0 }),
    kumaMonitor(4, { method: 'HEAD', interval: 10, accepted_statuscodes: ['200-299', '300-399'] }),
    kumaMonitor(5, { interval: 86400, ignoreTls: true, active: false }),
    kumaMonitor(6, {
      authMethod: 'basic',
      basic_auth_user: 'admin',
      basic_auth_pass: 'kuma-basic-secret',
      headers: '{"Authorization":"Bearer kuma-header-token"}',
    }),
    kumaMonitor(7, { url: 'https://user:kuma-url-pw@site7.example.com/?api_key=kuma-url-pw&q=1' }),
    kumaMonitor(8, { oauth_client_secret: 'kuma-oauth-secret', authMethod: 'oauth2-cc' }),
    kumaMonitor(9, { type: 'ping', url: null, hostname: '192.0.2.9' }),
    kumaMonitor(10, { type: 'port', url: null, hostname: '192.0.2.10', port: 22 }),
    kumaMonitor(11, { type: 'dns', url: null, hostname: 'example.com' }),
    kumaMonitor(12, { type: 'docker', url: null, docker_container: 'plex' }),
    kumaMonitor(13, { type: 'push', url: null, pushToken: 'kuma-header-token' }),
    kumaMonitor(14, { type: 'json-query' }),
    kumaMonitor(15, { type: 'steam', url: null }),
    kumaMonitor(16, { type: 'real-browser' }),
    kumaMonitor(17, { upsideDown: true }),
    kumaMonitor(18, { method: 'POST', body: '{"token":"kuma-header-token"}' }),
    kumaMonitor(19, { url: 'ftp://site19.example.com/' }),
    kumaMonitor(20, { accepted_statuscodes: ['600-999'] }),
  ]);
}
