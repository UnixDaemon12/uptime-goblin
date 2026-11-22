// What collectors do with answers that are not the shape a source's API documents: a null or
// primitive body, an object where a list belongs, a list entry that is not an object. Each is
// refused with one fixed message, not retried, instead of the TypeError reading it raised
// (shown as "Check the address and credential format"). Also the basic readings of the sources
// that had no reading test (Seerr, SABnzbd, Tautulli).
import test from 'node:test';
import assert from 'node:assert/strict';
import { newService } from '../lib/catalog.mjs';
import { CollectionError, collect, resetCollector, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const unexpected =
  'Source returned an unexpected response. Check the API URL and that the source version is supported.';
const values = metrics => Object.fromEntries(metrics.map(m => [m.key, m.value]));
// Answers each request with respond(path) as JSON (undefined: an empty list).
function serve(t, respond) {
  t.mock.method(transport, 'fetch', async url => {
    const body = respond(new URL(url).pathname);
    return new Response(JSON.stringify(body === undefined ? [] : body));
  });
}
function source(t, type, extra = {}) {
  const service = {
    ...newService(type, 'shapes-' + type),
    apiUrl: 'https://shapes.example.com',
    apiKey: 'fixture-key',
    username: 'fixture-user',
    password: 'fixture-password',
    ...extra,
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  return service;
}
// Well-formed answers, so each case below breaks exactly one part.
const arr = (path, replace = {}) =>
  ({
    '/api/v3/queue/status': { totalCount: 1 },
    '/api/v3/health': [],
    '/api/v3/diskspace': [],
    '/api/v3/wanted/missing': { totalRecords: 0 },
    ...replace,
  })[path];
const prowlarr = (path, replace = {}) =>
  ({
    '/api/v1/indexerstats': { indexers: [] },
    '/api/v1/indexer': [],
    '/api/v1/health': [],
    ...replace,
  })[path];
const cosmos = (path, replace = {}) =>
  ({
    '/cosmos/api/metrics': {
      status: 'OK',
      data: [
        { Key: 'cosmos.system.cpu.0', Values: [{ Date: new Date().toISOString(), Value: 5 }] },
      ],
    },
    '/cosmos/api/servapps': { status: 'OK', data: [] },
    ...replace,
  })[path];
const amp = metrics => path =>
  path.endsWith('/Login') ? { success: true, sessionID: 'amp-session' } : { Metrics: metrics };
const unifi =
  (sites, replace = {}) =>
  path =>
    path.endsWith('/v1/sites') ? sites : (replace[path] ?? { data: [], totalCount: 0 });

const cases = [
  ['proxmox', 'body null', () => null],
  ['proxmox', 'resources [null]', () => ({ data: [null] })],
  ['proxmox', 'a resource that is a number', () => ({ data: [5] })],
  ['proxmox', 'node mode, resources [null]', () => ({ data: [null] }), { nodeName: 'pve' }],
  ['sonarr', 'queue null', path => arr(path, { '/api/v3/queue/status': null })],
  ['sonarr', 'health [null]', path => arr(path, { '/api/v3/health': [null] })],
  ['radarr', 'disk space ["x"]', path => arr(path, { '/api/v3/diskspace': ['x'] })],
  ['radarr', 'health as an object', path => arr(path, { '/api/v3/health': { type: 'error' } })],
  ['prowlarr', 'stats null', path => prowlarr(path, { '/api/v1/indexerstats': null })],
  [
    'prowlarr',
    'indexer stats [null]',
    path => prowlarr(path, { '/api/v1/indexerstats': { indexers: [null] } }),
  ],
  ['prowlarr', 'health [null]', path => prowlarr(path, { '/api/v1/health': [null] })],
  ['seerr', 'body null', () => null],
  ['seerr', 'body a list', () => [{ total: 1 }]],
  ['sabnzbd', 'body null', () => null],
  ['sabnzbd', 'queue a string', () => ({ queue: 'busy' })],
  ['nzbget', 'body null', () => null],
  ['nzbget', 'result a list', () => ({ result: [1] })],
  ['plex', 'body null', () => null],
  ['plex', 'Metadata an object', () => ({ MediaContainer: { size: 1, Metadata: { a: 1 } } })],
  ['plex', 'Metadata [null]', () => ({ MediaContainer: { size: 1, Metadata: [null] } })],
  ['tautulli', 'body null', () => null],
  ['tautulli', 'data null', () => ({ response: { result: 'success', data: null } })],
  ['adguard', 'body null', () => null],
  ['adguard', 'body a string', () => 'stats'],
  ['docker', 'containers [null]', () => [null]],
  ['docker', 'containers an object', () => ({ Id: 'x' })],
  [
    'cosmos',
    'data [null]',
    path => cosmos(path, { '/cosmos/api/metrics': { status: 'OK', data: [null] } }),
  ],
  ['cosmos', 'body null', path => cosmos(path, { '/cosmos/api/servapps': null })],
  [
    'cosmos',
    'Values [null]',
    path =>
      cosmos(path, {
        '/cosmos/api/metrics': {
          status: 'OK',
          data: [{ Key: 'cosmos.system.cpu.0', Values: [null] }],
        },
      }),
  ],
  ['npm', 'sign-in answer null', () => null],
  ['npm', 'proxy hosts [null]', path => (path === '/api/tokens' ? { token: 'jwt.a.b' } : [null])],
  ['crowdsec', 'sign-in answer null', () => null],
  ['amp', 'Metrics {X: null}', amp({ 'CPU Usage': { Percent: 5 }, X: null })],
  ['amp', 'Metrics a number', amp(5)],
  ['unifi', 'sites [null]', unifi({ data: [null], totalCount: 1 }), { username: '' }],
  ['unifi', 'a sites page null', unifi(null), { username: '' }],
  [
    'unifi',
    'devices [5]',
    unifi(
      { data: [{ id: 's1' }], totalCount: 1 },
      { '/proxy/network/integration/v1/sites/s1/devices': { data: [5], totalCount: 1 } }
    ),
    { username: '' },
  ],
];

test('every collector refuses null, primitive and wrongly typed bodies and null list entries with the unexpected-response message', async t => {
  for (const [type, what, respond, extra] of cases) {
    serve(t, respond);
    await assert.rejects(
      collect(source(t, type, extra)),
      error =>
        error instanceof CollectionError &&
        error.message === unexpected &&
        error.retryable === false,
      `${type}: ${what}`
    );
    t.mock.restoreAll();
  }
});

test('Seerr request counts are read as numbers', async t => {
  serve(t, path => {
    assert.equal(path, '/api/v1/request/count');
    return {
      total: 12,
      movie: 7,
      tv: 5,
      pending: 2,
      approved: 3,
      declined: 1,
      processing: 1,
      available: 4,
      completed: 4,
    };
  });
  assert.deepEqual(values(await collect(source(t, 'seerr'))), {
    pending: 2,
    approved: 3,
    available: 4,
    processing: 1,
    declined: 1,
    completed: 4,
    total: 12,
    movie: 7,
    tv: 5,
  });
});

test('SABnzbd queue readings convert its units and keep zero', async t => {
  serve(t, () => ({
    queue: {
      kbpersec: '512.5',
      noofslots_total: 3,
      mbleft: '1.5',
      paused: false,
      diskspace1: '2',
      diskspace2: '0',
    },
  }));
  assert.deepEqual(values(await collect(source(t, 'sabnzbd'))), {
    speed: 524800,
    queue: 3,
    remaining: 1572864,
    paused: 0,
    download_disk_free: 2147483648,
    complete_disk_free: 0,
  });
});

test('Tautulli activity readings convert bandwidth from kbit/s', async t => {
  serve(t, path => {
    assert.equal(path, '/api/v2');
    return {
      response: {
        result: 'success',
        data: {
          stream_count: '3',
          stream_count_transcode: 1,
          stream_count_direct_play: 1,
          stream_count_direct_stream: 1,
          total_bandwidth: 8000,
          lan_bandwidth: 0,
          wan_bandwidth: '8000',
        },
      },
    };
  });
  assert.deepEqual(values(await collect(source(t, 'tautulli'))), {
    streams: 3,
    transcodes: 1,
    bandwidth: 1000000,
    direct_play: 1,
    direct_stream: 1,
    lan_bandwidth: 0,
    wan_bandwidth: 1000000,
  });
});
