import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { newService } from '../lib/catalog.mjs';
import { collect, noteMessages, resetCollector, transport } from '../lib/collectors.mjs';
import { ConfigStore, validateService } from '../lib/config.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const values = metrics => Object.fromEntries(metrics.map(m => [m.key, m.value]));
function serve(t, respond) {
  t.mock.method(transport, 'fetch', async url => {
    const body = respond(new URL(url).pathname);
    return typeof body === 'string' ? new Response(body) : Response.json(body);
  });
}
function exporter(t, type) {
  const service = { ...newService(type, 'net-' + type), apiUrl: 'https://host.example.com' };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  t.mock.timers.enable({ apis: ['Date'], now: 1000000 });
  let text = '';
  serve(t, () => text);
  // A steady reading keeps the first poll (which has no rates yet) a successful one.
  const steady = type === 'linux' ? 'node_load1 0.5\n' : 'windows_cs_physical_memory_bytes 1000\n';
  // Each poll is 10 seconds after the previous one.
  return async counters => {
    t.mock.timers.tick(10000);
    text = steady + counters;
    return values(await collect(service));
  };
}
const linux = devices =>
  Object.entries(devices)
    .map(
      ([device, [rx, tx]]) =>
        `node_network_receive_bytes_total{device="${device}"} ${rx}\n` +
        `node_network_transmit_bytes_total{device="${device}"} ${tx}\n`
    )
    .join('');

test('Linux network rates count each physical interface once and survive interface churn', async t => {
  const poll = exporter(t, 'linux');
  // A Proxmox host: bridged traffic crosses enp3s0, vmbr0 and a guest tap device.
  let v = await poll(
    linux({
      lo: [7000, 7000],
      enp3s0: [1000, 2000],
      enp4s0: [9000, 9000],
      vmbr0: [1000, 2000],
      tap100i0: [1000, 2000],
      veth101i0: [5000000, 5000000],
    })
  );
  assert.equal(v.receive, undefined);
  // 1 MB arrives on enp3s0 and is bridged on; a container stops (its veth goes away),
  // enp4s0's counter resets and a new NIC appears without a baseline.
  v = await poll(
    linux({
      lo: [9000, 9000],
      enp3s0: [1001000, 502000],
      enp4s0: [100, 100],
      eno1: [777, 777],
      vmbr0: [1001000, 502000],
      tap100i0: [1001000, 502000],
    })
  );
  assert.equal(v.receive, 100000);
  assert.equal(v.transmit, 50000);
  v = await poll(
    linux({
      enp3s0: [1501000, 502000],
      enp4s0: [200100, 100],
      eno1: [100777, 777],
      vmbr0: [9001000, 9502000],
    })
  );
  assert.equal(v.receive, 80000);
  assert.equal(v.transmit, 0);
  // With only virtual interfaces reported (a filtered exporter), those are used instead.
  await poll(linux({ lo: [0, 0], vmbr0: [9001000, 9502000] }));
  v = await poll(linux({ lo: [50000, 50000], vmbr0: [9021000, 9512000] }));
  assert.equal(v.receive, 2000);
  assert.equal(v.transmit, 1000);
});

test('Windows network rates leave out Hyper-V and tunnel adapters', async t => {
  const poll = exporter(t, 'windows');
  const nics = counters =>
    Object.entries(counters)
      .map(
        ([nic, [rx, tx]]) =>
          `windows_net_bytes_received_total{nic="${nic}"} ${rx}\n` +
          `windows_net_bytes_sent_total{nic="${nic}"} ${tx}\n`
      )
      .join('');
  await poll(
    nics({
      Intel_R_Ethernet_Connection_I219_V: [0, 0],
      vEthernet_External_: [0, 0],
      Hyper_V_Virtual_Ethernet_Adapter_2: [0, 0],
      'isatap__{4F2A}': [0, 0],
      Teredo_Tunneling_Pseudo_Interface: [0, 0],
    })
  );
  const v = await poll(
    nics({
      Intel_R_Ethernet_Connection_I219_V: [300000, 100000],
      vEthernet_External_: [300000, 100000],
      Hyper_V_Virtual_Ethernet_Adapter_2: [200000, 50000],
      'isatap__{4F2A}': [10, 10],
      Teredo_Tunneling_Pseudo_Interface: [10, 10],
    })
  );
  assert.equal(v.received, 30000);
  assert.equal(v.sent, 10000);
});

test('Sonarr and Radarr disk keys follow the path when the diskspace list changes', async t => {
  const long = '/mnt/' + 'library/'.repeat(30);
  let disks;
  serve(t, route =>
    route.endsWith('/diskspace') ? disks : route.endsWith('/queue/status') ? { totalCount: 0 } : []
  );
  const service = { ...newService('radarr'), apiUrl: 'https://arr.example.com' };
  disks = [
    { path: '/', freeSpace: 1, totalSpace: 10 },
    { path: '/mnt/media', freeSpace: 2000, totalSpace: 4000 },
    { path: long + 'a', freeSpace: 5, totalSpace: 6 },
    { path: long + 'b', freeSpace: 7, totalSpace: 8 },
  ];
  const first = await collect(service);
  // A backup share appears ahead of the media disk, and one entry has no path.
  disks = [
    { path: '/', freeSpace: 1, totalSpace: 10 },
    { path: '/mnt/backup', freeSpace: 10, totalSpace: 20 },
    { path: '/mnt/media', freeSpace: 2000, totalSpace: 4000 },
    { path: long + 'a', freeSpace: 5, totalSpace: 6 },
    { path: long + 'b', freeSpace: 7, totalSpace: 8 },
    { label: 'Unmounted', freeSpace: 3, totalSpace: 4 },
  ];
  const second = await collect(service),
    v = values(second);
  assert.equal(values(first)['disk_free_/mnt/media'], 2000);
  assert.equal(v['disk_free_/mnt/media'], 2000);
  assert.equal(v['disk_total_/mnt/media'], 4000);
  assert.equal(v['disk_free_/mnt/backup'], 10);
  assert.equal(v.disk_5_free, 3);
  assert.equal(second.find(m => m.key === 'disk_5_total').label, 'Unmounted · Capacity');
  // Long paths keep keys short enough for alert rules, stable and distinct.
  const longKeys = second.filter(m => m.key.startsWith('disk_free_/mnt/library'));
  assert.equal(longKeys.length, 2);
  assert.ok(longKeys.every(m => m.key.length <= 150 && m.label.length <= 240));
  assert.notEqual(longKeys[0].key, longKeys[1].key);
  assert.deepEqual(
    longKeys.map(m => m.key),
    first.filter(m => m.key.startsWith('disk_free_/mnt/library')).map(m => m.key)
  );
});

test('Radarr missing counts only monitored, released movies without a file', async t => {
  serve(t, route =>
    route.endsWith('/movie')
      ? [
          { hasFile: true, monitored: true, isAvailable: true },
          { hasFile: false, monitored: true, isAvailable: true },
          { hasFile: false, monitored: false, isAvailable: true },
          { hasFile: false, monitored: true, isAvailable: false },
        ]
      : route.endsWith('/queue/status')
        ? { totalCount: 0 }
        : []
  );
  const v = values(await collect({ ...newService('radarr'), apiUrl: 'https://arr.example.com' }));
  assert.equal(v.movies, 4);
  assert.equal(v.missing, 1);
});

test('JSON mapping paths cannot index into strings or inherited properties', async t => {
  serve(t, () => ({
    apiKey: '3f9a120b7c4d58e6a1b2c3d4e5f60718',
    pin: '1234',
    nested: { count: '7' },
    items: [{ value: 5 }],
    list: [1, 2, 3],
  }));
  const paths = {
    digit: 'apiKey.1',
    length: 'apiKey.length',
    pinLength: 'pin.length',
    inherited: 'nested.constructor.length',
    method: 'nested.toString.length',
    count: 'nested.count',
    indexed: 'items.0.value',
    entries: 'list.length',
  };
  const metrics = await collect({
    ...newService('json'),
    apiUrl: 'https://json.example.com',
    metrics: Object.entries(paths).map(([key, path]) => ({ key, label: key, path })),
  });
  assert.deepEqual(values(metrics), { count: 7, indexed: 5, entries: 3 });
});

test('AMP sessions rejected inside a normal response are renewed once', async t => {
  const service = {
    ...newService('amp', 'amp-rejected'),
    apiUrl: 'https://amp.example.test',
    username: 'viewer',
    password: 'secret',
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  let logins = 0,
    restarted = false;
  t.mock.method(transport, 'fetch', async url => {
    if (url.endsWith('/Core/Login'))
      return Response.json({ success: true, sessionID: 'session-' + ++logins });
    if (restarted && logins === 1)
      return Response.json({ Title: 'Unauthorized Access', Message: 'Session expired' });
    return Response.json({ Metrics: { 'CPU Usage': { Percent: 5, RawValue: 5 } } });
  });
  await collect(service);
  restarted = true;
  const metrics = await collect(service);
  assert.equal(metrics.find(m => m.key === 'cpu').value, 5);
  assert.equal(logins, 2);
});

test('Sonarr missing episodes match its Wanted view, leaving out unmonitored series', async t => {
  let wanted = true;
  const urls = [];
  t.mock.method(transport, 'fetch', async url => {
    urls.push(url);
    const route = new URL(url).pathname;
    if (route.endsWith('/wanted/missing'))
      return wanted
        ? Response.json({ page: 1, pageSize: 1, totalRecords: 2, records: [{ id: 1 }] })
        : new Response('Not found', { status: 404 });
    if (route.endsWith('/series'))
      return Response.json([
        { monitored: true, statistics: { episodeCount: 10, episodeFileCount: 8 } },
        // Unmonitored, but its episodes kept their own monitored flags.
        { monitored: false, statistics: { episodeCount: 50, episodeFileCount: 10 } },
      ]);
    return Response.json(route.endsWith('/queue/status') ? { totalCount: 0 } : []);
  });
  const service = { ...newService('sonarr'), apiUrl: 'https://arr.example.com' };
  let v = values(await collect(service));
  assert.equal(v.series, 2);
  assert.equal(v.episodes, 18);
  assert.equal(v.missing, 2);
  const query = new URL(urls.find(url => url.includes('/wanted/missing'))).searchParams;
  assert.equal(query.get('pageSize'), '1');
  assert.equal(query.get('monitored'), 'true');
  // A server without the Wanted endpoint falls back to monitored series in the library.
  wanted = false;
  v = values(await collect(service));
  assert.equal(v.missing, 2);
});

test('long Linux mountpoints and Windows volume labels keep short keys and labels', async t => {
  const mount =
    '/var/lib/kubelet/pods/' +
    '5f0c6c8e-1b2a-4c3d-9e8f-0a1b2c3d4e5f/volumes/kubernetes.io~csi/pvc-'.repeat(3) +
    '/mount';
  const volume = 'HarddiskVolumeShadowCopy-' + 'long-label-'.repeat(20);
  let text;
  serve(t, () => text);
  const fs = (name, labels, value) => `${name}{${labels}} ${value}\n`;
  text =
    'node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 500\n' +
    [
      ['/', '/dev/sda1'],
      [mount, 'tmpfs-csi'],
    ]
      .map(([mountpoint, device]) => {
        const labels = `mountpoint="${mountpoint}",device="${device}",fstype="ext4"`;
        return (
          fs('node_filesystem_size_bytes', labels, 1000) +
          fs('node_filesystem_avail_bytes', labels, 250)
        );
      })
      .join('');
  const linux = await collect({ ...newService('linux'), apiUrl: 'https://host.example.com' });
  text =
    'windows_cs_physical_memory_bytes 1000\n' +
    ['C:', volume]
      .map(
        v =>
          fs('windows_logical_disk_size_bytes', `volume="${v}"`, 1000) +
          fs('windows_logical_disk_free_bytes', `volume="${v}"`, 250)
      )
      .join('');
  const windows = await collect({ ...newService('windows'), apiUrl: 'https://host.example.com' });
  for (const [metrics, short, long] of [
    [linux, '/', mount],
    [windows, 'C:', volume],
  ]) {
    const v = values(metrics);
    // Short names keep their existing keys (and so their history and rules).
    assert.equal(v['disk_' + short], 75);
    assert.equal(v['disk_free_' + short], 250);
    const disks = metrics.filter(m => m.label.startsWith(long.slice(0, 40)));
    assert.equal(disks.length, 2);
    assert.ok(disks.every(m => m.key.length <= 150 && m.label.length <= 240));
    assert.deepEqual(
      disks.map(m => m.value),
      [75, 250]
    );
  }
});

test('Windows CPU leaves DPC and interrupt time out of the total, as privileged time has them', async t => {
  const poll = exporter(t, 'windows');
  const cpu = modes =>
    Object.entries(modes)
      .map(([mode, value]) => `windows_cpu_time_total{core="0,0",mode="${mode}"} ${value}\n`)
      .join('');
  await poll(cpu({ idle: 100, user: 50, privileged: 50, dpc: 10, interrupt: 5 }));
  // Over 10 s: 8 s idle, 1 s user, 1 s privileged (of which 0.3 s DPC and 0.2 s interrupt).
  const v = await poll(cpu({ idle: 108, user: 51, privileged: 51, dpc: 10.3, interrupt: 5.2 }));
  assert.ok(Math.abs(v.cpu - 20) < 1e-9, `cpu ${v.cpu}`);
});

test('Linux uptime uses the exporter host’s clock and is never negative', async t => {
  const poll = exporter(t, 'linux');
  // Uptime Goblin's clock reads 1010 s here; the host's clock is 90 s ahead and booted 30 s ago.
  let v = await poll('node_time_seconds 1100\nnode_boot_time_seconds 1070\n');
  assert.equal(v.uptime, 30);
  // Without node_time_seconds Uptime Goblin's clock is used, clamped at zero.
  v = await poll('node_boot_time_seconds 1090\n');
  assert.equal(v.uptime, 0);
});

test('Plex transcodes leave out Direct Stream remuxes, which are counted separately', async t => {
  serve(t, () => ({
    MediaContainer: {
      size: 5,
      Metadata: [
        { Player: { state: 'playing' } },
        { TranscodeSession: { videoDecision: 'copy', audioDecision: 'copy' } },
        { TranscodeSession: { videoDecision: 'copy', audioDecision: 'transcode' } },
        { TranscodeSession: { videoDecision: 'transcode', audioDecision: 'copy' } },
        // Older servers without decisions keep counting as transcodes.
        { TranscodeSession: {} },
      ],
    },
  }));
  const v = values(await collect({ ...newService('plex'), apiUrl: 'https://plex.example.com' }));
  assert.equal(v.streams, 5);
  assert.equal(v.transcodes, 3);
  assert.equal(v.direct_stream, 1);
});

test('exporter mappings give way to the built-in Linux readings a host reports', async t => {
  const service = {
    ...newService('linux', 'mapped-linux'),
    apiUrl: 'https://host.example.com',
    metrics: [
      { key: 'cpu', label: 'My CPU', path: 'node_load1' },
      { key: 'load1', label: 'Load x100', path: 'node_load1', scale: 100 },
      { key: 'receive', label: 'My receive', path: 'node_load1' },
      { key: 'custom', label: 'Custom', path: 'node_load1', scale: 2 },
    ],
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  t.mock.timers.enable({ apis: ['Date'], now: 1000000 });
  let idle = 100,
    user = 0;
  serve(
    t,
    () =>
      `node_load1 1.5\nnode_cpu_seconds_total{cpu="0",mode="idle"} ${idle}\n` +
      `node_cpu_seconds_total{cpu="0",mode="user"} ${user}\n`
  );
  // The first poll has no CPU rate yet; the mapping must not stand in for it.
  let metrics = await collect(service);
  assert.equal(values(metrics).cpu, undefined);
  // This host reports no network counters, so the saved mapping is its receive reading.
  assert.equal(values(metrics).receive, 1.5);
  assert.equal(values(metrics).load1, 1.5);
  assert.equal(values(metrics).custom, 3);
  t.mock.timers.tick(10000);
  idle += 5;
  user += 5;
  metrics = await collect(service);
  assert.equal(values(metrics).cpu, 50);
  assert.equal(new Set(metrics.map(m => m.key)).size, metrics.length);
});

test('mapping scale multiplies exporter and JSON values', async t => {
  serve(t, route =>
    route === '/metrics'
      ? 'memory_kib 2\nmemory_kib{zone="b"} 3\nlatency_us 1500\n'
      : { memory: { kib: '2' }, latency: 1500 }
  );
  const mapped = async (type, metrics) =>
    values(await collect({ ...newService(type), apiUrl: 'https://map.example.com', metrics }));
  assert.deepEqual(
    await mapped('prometheus', [
      { key: 'memory', label: 'Memory', path: 'memory_kib', scale: 1024 },
      { key: 'latency', label: 'Latency', path: 'latency_us', scale: 0.001 },
    ]),
    { memory: 5120, latency: 1.5 }
  );
  assert.deepEqual(
    await mapped('json', [
      { key: 'memory', label: 'Memory', path: 'memory.kib', scale: 1024 },
      { key: 'latency', label: 'Latency', path: 'latency', scale: 0.001 },
    ]),
    { memory: 2048, latency: 1.5 }
  );
});

// What an exporter sends with half of a surrogate pair: escapes, as in the exposition format and
// in JSON (\ud83d and \udc00 are halves, \ufffd the replacement character itself).
const halves = {
  exposition:
    'lone{name="\\ud83d"} 5\nlone{name="other"} 100\n' +
    'two{name="\\ud83d"} 1\ntwo{name="\\udc00"} 2\n' +
    'both{name="\\ufffd"} 7\nboth{name="\\ud83d"} 11\n' +
    'zones{name="x\\ud83d",zone="a"} 13\nzones{name="x\\ud83d",zone="b"} 17\n' +
    'plain{name="x\\ud83d"} 19\n',
  document:
    '{"temp\\ud83d": 21, "both\\ufffd": 4, "both\\ud83d": 9, "nested": {"a\\udc00": {"b": 6}},' +
    ' "list\\ud83d": [3], "s\\ud83d": "secret", "x": {"y\\ud83d": 8},' +
    ' "two\\ud83d": 30, "two\\udc00": 40, "deep": {"k\\ud83d": {"v": 1}, "k\\udfff": {"v": 2}}}',
};
const serveHalves = t =>
  serve(t, route => (route === '/metrics' ? halves.exposition : halves.document));

test('a label filter or JSON path step holding U+FFFD matches half of a surrogate pair the exporter sends, after any match as sent', async t => {
  serveHalves(t);
  const mapped = async (type, metrics) => {
    const readings = await collect({
      ...newService(type),
      apiUrl: 'https://half.example.com',
      metrics,
    });
    return { values: values(readings), notes: readings.notes };
  };
  const mapping = (key, path, labels) => ({ key, label: key, path, ...(labels && { labels }) });
  const unclear = omitted => [
    { code: 'mappings_ambiguous', message: noteMessages.mappings_ambiguous({ omitted }), omitted },
  ];
  assert.deepEqual(
    await mapped('prometheus', [
      mapping('lone', 'lone', { name: '\ufffd' }),
      // Two different halves read as one U+FFFD: which one the filter meant is unknown, so the
      // mapping reads nothing (not their sum, 3), and a note says so.
      mapping('two', 'two', { name: '\ufffd' }),
      // A series sending U+FFFD itself matches as sent, so the half's series is not added.
      mapping('both', 'both', { name: '\ufffd' }),
      // Each filter is compared made whole: zone as before, name with its half.
      mapping('zones', 'zones', { name: 'x\ufffd', zone: 'b' }),
      // Series sending the same half are still summed: they differ only in another label.
      mapping('zonesAll', 'zones', { name: 'x\ufffd' }),
      // A filter without U+FFFD matches nothing more: 'x' is not 'x' and a half.
      mapping('plain', 'plain', { name: 'x' }),
    ]),
    { values: { lone: 5, both: 7, zones: 17, zonesAll: 30 }, notes: unclear(1) }
  );
  assert.deepEqual(
    await mapped('json', [
      mapping('temp', 'temp\ufffd'),
      mapping('both', 'both\ufffd'),
      mapping('nested', 'nested.a\ufffd.b'),
      mapping('list', 'list\ufffd.0'),
      mapping('inner', 'x.y\ufffd'),
      // Two members whose names read the same made whole: neither is read (not the first, 30).
      mapping('two', 'two\ufffd'),
      mapping('deep', 'deep.k\ufffd.v'),
      // Strings are still never indexed, and a step without U+FFFD matches nothing more.
      mapping('length', 's\ufffd.length'),
      mapping('bare', 'temp'),
    ]),
    { values: { temp: 21, both: 4, nested: 6, list: 3, inner: 8 }, notes: unclear(2) }
  );
});

test('a 1.4.3 mapping whose filter or path held half of a surrogate pair keeps its reading after the start makes it whole, while no other text there reads the same', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-half-mapping-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const apiUrl = 'https://half.example.com';
  const services = [
    {
      ...newService('prometheus', 'prometheus-1'),
      apiUrl,
      metricPath: '/metrics',
      metrics: [
        { key: 'lone', label: 'Lone', path: 'lone', labels: { name: '\ud83d' } },
        { key: 'zones', label: 'Zones', path: 'zones', labels: { name: 'x\ud83d', zone: 'a' } },
      ],
    },
    {
      ...newService('json', 'json-1'),
      apiUrl,
      metricPath: '/data',
      metrics: [{ key: 'temp', label: 'Temp', path: 'temp\ud83d' }],
    },
  ];
  // Written as 1.4.3 wrote it: JSON.stringify keeps half a pair as a \u escape.
  fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify({ services }));
  assert.match(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'), /\\ud83d/);
  t.mock.method(console, 'warn', () => {});
  const config = new ConfigStore(directory);
  const [prometheus, json] = config.value.services;
  assert.deepEqual(prometheus.metrics[0].labels, { name: '\ufffd' });
  assert.equal(json.metrics[0].path, 'temp\ufffd');
  serveHalves(t);
  for (const service of [prometheus, json]) {
    resetCollector(service.id);
    t.after(() => resetCollector(service.id));
  }
  assert.deepEqual(values(await collect(prometheus)), { lone: 5, zones: 13 });
  assert.deepEqual(values(await collect(json)), { temp: 21 });
});

test('a 1.4.3 mapping whose exporter also sends U+FFFD or another half there reads the U+FFFD series or nothing, never a sum', async t => {
  // On 1.4.3 these read two=1, both=11 (Prometheus) and two=40, both=9 (JSON). The start makes
  // each half U+FFFD and cannot tell which half it was.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-half-mapping-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const apiUrl = 'https://half.example.com';
  const services = [
    {
      ...newService('prometheus', 'prometheus-1'),
      apiUrl,
      metricPath: '/metrics',
      metrics: [
        { key: 'two', label: 'Two', path: 'two', labels: { name: '\ud83d' } },
        { key: 'both', label: 'Both', path: 'both', labels: { name: '\ud83d' } },
      ],
    },
    {
      ...newService('json', 'json-1'),
      apiUrl,
      metricPath: '/data',
      metrics: [
        { key: 'two', label: 'Two', path: 'two\udc00' },
        { key: 'both', label: 'Both', path: 'both\ud83d' },
      ],
    },
  ];
  fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify({ services }));
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const config = new ConfigStore(directory);
  // The start says once what the repair means for these mappings' readings.
  assert.deepEqual(
    warnings.filter(line => /mapping label filter/.test(line)).map(line => line.slice(0, 68)),
    ['Configuration: 4 of these texts are mapping label filters or paths. ']
  );
  serveHalves(t);
  for (const service of config.value.services) {
    resetCollector(service.id);
    t.after(() => resetCollector(service.id));
  }
  for (const service of config.value.services) {
    const readings = await collect(service);
    // 'both' reads the member or series sent with U+FFFD itself; 'two' reads nothing, noted.
    assert.deepEqual(values(readings), { both: service.type === 'json' ? 4 : 7 }, service.type);
    assert.deepEqual(
      readings.notes.map(n => [n.code, n.omitted]),
      [['mappings_ambiguous', 1]],
      service.type
    );
  }
});

test('CrowdSec counts local alerts and decisions only, however many there are', async t => {
  const urls = [];
  let decisions;
  // A busy LAPI: 1,000 alerts carrying their events, over a buffered collection's budget.
  const event = { timestamp: '2031-01-01T00:00:00Z', meta: [{ key: 'service', value: 'http' }] };
  const alerts = JSON.stringify(
    Array.from({ length: 1000 }, (_, id) => ({ id, events: Array(150).fill(event) }))
  );
  t.mock.method(transport, 'fetch', async url => {
    urls.push(new URL(url));
    const route = new URL(url).pathname;
    if (route === '/v1/watchers/login') return Response.json({ token: 'watcher-fixture' });
    if (route === '/v1/alerts') return new Response(alerts);
    return new Response(JSON.stringify(decisions));
  });
  const service = {
    ...newService('crowdsec', 'crowdsec-local'),
    apiUrl: 'https://lapi.example.com',
    username: 'fixture',
    password: 'fixture',
    apiKey: 'bouncer-fixture',
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  decisions = [{ type: 'ban' }, { type: 'ban' }, { type: 'captcha' }];
  let v = values(await collect(service));
  assert.deepEqual(v, { alerts_24h: 1000, decisions: 3, bans: 2 });
  const alertQuery = urls.find(u => u.pathname === '/v1/alerts').searchParams,
    decisionQuery = urls.find(u => u.pathname === '/v1/decisions').searchParams;
  assert.equal(alertQuery.get('include_capi'), 'false');
  assert.deepEqual(decisionQuery.get('origins').split(',').sort(), [
    'console',
    'crowdsec',
    'cscli',
    'cscli-import',
  ]);
  // The LAPI answers null when nothing is active.
  decisions = null;
  v = values(await collect(service));
  assert.equal(v.decisions, 0);
  assert.equal(v.bans, 0);
});

test('CrowdSec counts a bulk-import alert over 1 MB, and keeps decisions if alerts are too large', async t => {
  let alerts;
  t.mock.method(transport, 'fetch', async url => {
    const route = new URL(url).pathname;
    if (route === '/v1/watchers/login') return Response.json({ token: 'watcher-fixture' });
    if (route === '/v1/alerts') return new Response(alerts());
    return Response.json([{ type: 'ban' }, { type: 'captcha' }]);
  });
  const service = {
    ...newService('crowdsec', 'crowdsec-import'),
    apiUrl: 'https://lapi.example.com',
    username: 'fixture',
    password: 'fixture',
    apiKey: 'bouncer-fixture',
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  // `cscli decisions import` puts every imported decision (about 240 bytes each) in one alert.
  const decision = {
    duration: '23h59m58s',
    id: 123456,
    origin: 'cscli-import',
    scenario: 'import list.txt: 5000 IPs',
    scope: 'Ip',
    simulated: false,
    type: 'ban',
    until: '2031-01-02T00:00:00Z',
    uuid: '00000000-0000-4000-8000-000000000000',
    value: '192.0.2.1',
  };
  const bulk = JSON.stringify([
    { id: 1, scenario: 'import list.txt: 5000 IPs', decisions: Array(5000).fill(decision) },
    { id: 2, scenario: 'crowdsecurity/ssh-bf', decisions: [] },
  ]);
  assert.ok(bulk.length > 1024 * 1024, 'the fixture must exceed the 1 MB entry limit');
  alerts = () => bulk;
  assert.deepEqual(values(await collect(service)), { alerts_24h: 2, decisions: 2, bans: 1 });
  // Over the 16 MB response limit only the alert count is left out; the list is streamed, so
  // the 20 MB body is never built.
  const entry = new TextEncoder().encode(JSON.stringify({ events: 'x'.repeat(1024 * 1024) }));
  alerts = () => {
    let sent = 0;
    return new ReadableStream({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode(sent++ ? ',' : '['));
        controller.enqueue(entry);
        if (sent === 20) {
          controller.enqueue(new TextEncoder().encode(']'));
          controller.close();
        }
      },
    });
  };
  const readings = await collect(service);
  assert.deepEqual(values(readings), { decisions: 2, bans: 1 });
  assert.deepEqual(
    readings.notes.map(n => n.code),
    ['crowdsec_alerts_too_large']
  );
  // Without the bouncer key the alert count is the only reading, so the source says why.
  await assert.rejects(
    collect({ ...service, apiKey: '' }),
    error => error.tooLarge === true && /exceeds the 16 MB collection limit/.test(error.message)
  );
});

test('Cosmos sample age is measured on the Cosmos host’s clock', async t => {
  const now = Date.now();
  let offset, age;
  t.mock.method(transport, 'fetch', async url => {
    const host = now + offset,
      headers = { Date: new Date(host).toUTCString() };
    if (url.includes('servapps')) return Response.json({ status: 'OK', data: [] }, { headers });
    const sample = { Date: new Date(host - age).toISOString(), Value: 24 };
    return Response.json(
      { status: 'OK', data: [{ Key: 'cosmos.system.cpu.0', Scale: 1, Values: [sample] }] },
      { headers }
    );
  });
  const service = { ...newService('cosmos'), apiUrl: 'https://cosmos.example.com', apiKey: 'x' };
  // The Cosmos clock is 200 s behind Uptime Goblin's: a 30 s old sample is still current.
  [offset, age] = [-200000, 30000];
  assert.equal(values(await collect(service)).cpu, 24);
  // An hour ahead: a sample 50 minutes old by that clock is stale, not current.
  [offset, age] = [3600000, 3000000];
  await assert.rejects(collect(service), /stale/);
});

test('a saved mapping stands in for a built-in reading the host never reports', async t => {
  // node_exporter on FreeBSD or macOS has no MemTotal/MemAvailable.
  const service = {
    ...newService('linux', 'bsd-linux'),
    apiUrl: 'https://bsd.example.com',
    metrics: [{ key: 'memory_total', label: 'Memory total', path: 'node_memory_size_bytes' }],
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  serve(t, () => 'node_load1 0.5\nnode_memory_size_bytes 8589934592\n');
  assert.equal(values(await collect(service)).memory_total, 8589934592);
});

// Every key a collector produces can carry an alert rule (lib/config.mjs checks rule keys) and is
// one line without control characters or direction embeddings, overrides and isolates; every
// label and unit is one line without the direction marks either. A key keeps the marks, as
// 1.4.3 did, so its history and rules carry over (see 'keys from IDs keep their 1.4.3 key…' and
// 'each key change from 1.4.3 that docs/troubleshooting.md lists…').
const notInKeys = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/,
  notInLabels =
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const ruleReady = (metrics, what) => {
  for (const m of metrics) {
    assert.doesNotThrow(
      () =>
        validateService(
          { rules: [{ key: m.key, operator: 'gt', threshold: 1 }] },
          newService('json')
        ),
      `${what}: ${JSON.stringify(m.key)}`
    );
    assert.ok(m.key.length <= 150 && !m.key.startsWith('__'), `${what}: ${m.key}`);
    assert.ok(m.label.length <= 240, `${what}: ${m.label.length}`);
    assert.ok(m.unit.length <= 30, `${what}: ${m.unit}`);
    assert.doesNotMatch(m.key, notInKeys, `${what}: ${JSON.stringify(m.key)}`);
    for (const text of [m.label, m.unit])
      assert.doesNotMatch(text, notInLabels, `${what}: ${JSON.stringify(text)}`);
  }
};
const unnamed = metrics => metrics.notes.find(n => n.code === 'unnamed_entries_left_out')?.omitted;
function answers(t, type, respond, extra = {}) {
  const service = {
    ...newService(type, 'names-' + type),
    apiUrl: 'https://names.example.com',
    apiKey: 'fixture-key',
    username: 'fixture-user',
    password: 'fixture-password',
    ...extra,
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  t.mock.method(transport, 'fetch', async url => {
    const u = new URL(url),
      body = respond(u.pathname, u);
    return body instanceof Response
      ? body
      : typeof body === 'string'
        ? new Response(body)
        : Response.json(body ?? []);
  });
  return service;
}

test('upstream ids, names and units are normalised: non-strings skipped and noted, controls and bidi removed, long values shortened, never fatal', async t => {
  // Proxmox (cluster and node mode): an object as an ID, a list as a name, storages without an
  // ID, and an ID and a name carrying line breaks, markup, a bell, an escape and an RLO.
  const resources = [
    {
      id: 'node/pve',
      type: 'node',
      node: 'pve',
      name: ['a', 'b'],
      status: 'online',
      cpu: 0.1,
      maxcpu: 2,
    },
    { type: 'storage', node: 'pve', disk: 1, maxdisk: 2 },
    { type: 'storage', node: 'pve', disk: 3, maxdisk: 4 },
    // The Arabic letter mark, a strong right-to-left mark like RLM.
    {
      id: 'storage/pve/a\u061cb',
      storage: 'report\u061c\u202egpj.exe',
      type: 'storage',
      node: 'pve',
      disk: 5,
      maxdisk: 6,
    },
    {
      id: 'st\u000d\u000a<b>x</b>\u202e',
      storage: 'S\u0007\u001b[31mRED',
      type: 'storage',
      node: 'pve',
      disk: 1,
      maxdisk: 2,
    },
    {
      id: { x: 1 },
      type: 'qemu',
      node: 'pve',
      vmid: 101,
      name: 'guest\u2028one',
      status: 'running',
      cpu: 0.5,
    },
    { id: { x: 1 }, type: 'lxc', node: 'pve', vmid: { y: 2 }, status: 'running', cpu: 0.5 },
    {
      id: '__reserved',
      type: 'qemu',
      node: 'pve',
      vmid: 102,
      name: 'r',
      status: 'running',
      cpu: 0.5,
    },
  ];
  for (const nodeName of ['', 'pve']) {
    const metrics = await collect(answers(t, 'proxmox', () => ({ data: resources }), { nodeName }));
    ruleReady(metrics, 'proxmox ' + nodeName);
    const keys = metrics.map(m => m.key);
    assert.ok(!keys.some(key => /object Object|undefined/.test(key)), keys.join());
    assert.ok(keys.includes('st <b>x</b>.used'), keys.join());
    assert.equal(metrics.find(m => m.key === 'st <b>x</b>.used').label, 'S [31mRED · Used');
    // The Arabic letter mark stays in the key, as 1.4.3 kept it, and leaves the label.
    assert.equal(
      metrics.find(m => m.key === 'storage/pve/a\u061cb.used').label,
      'reportgpj.exe · Used'
    );
    // Without a usable ID a guest goes by its VMID; one with neither is left out and noted.
    assert.equal(metrics.find(m => m.key === '101.cpu').label, 'guest one · CPU');
    assert.equal(metrics.find(m => m.key === 'node/pve.cpu').label, 'pve · CPU');
    assert.ok(keys.includes('~__reserved.cpu'), keys.join());
    assert.equal(unnamed(metrics), 3, nodeName);
    t.mock.restoreAll();
  }

  // UniFi local: a 187-character _id and a 231-character name failed the whole source.
  const localDevices = [
    { _id: 'i'.repeat(187), name: 'n'.repeat(231), state: 1, 'system-stats': { cpu: 5 } },
    { _id: { a: 1 }, mac: 'aa:bb', name: { a: 1 }, state: 1, 'system-stats': { cpu: 6 } },
    { state: 1, 'system-stats': { cpu: 7 } },
    { _id: 'd\u202e4', name: 'Hall\u0000\u000away\u2066', state: 1, 'system-stats': { cpu: 8 } },
    // A JSON escape of half a pair: its key was stored (as U+FFFD) unlike the one compared.
    { _id: 'lone\ud800', name: 'Shed\udc00', state: 1, 'system-stats': { cpu: 9 } },
    // Long, with an emoji across the place each is cut: the key and the label ended in half a
    // pair, which brought the mismatched key back.
    {
      _id: 'e'.repeat(129) + '\u{1F600}' + 'b'.repeat(40),
      name: 'n'.repeat(198) + '\u{1F600}' + 'm'.repeat(40),
      state: 1,
      'system-stats': { cpu: 10 },
    },
  ];
  let metrics = await collect(
    answers(
      t,
      'unifi',
      (path, url) => {
        if (path === '/api/auth/login')
          return new Response('{}', { headers: { 'Set-Cookie': 'TOKEN=t; Path=/' } });
        const name = path.split('/').pop();
        return { meta: { rc: 'ok' }, data: name === 'device' ? localDevices : [] };
      },
      { apiUrl: 'https://console.example', apiKey: '' }
    )
  );
  ruleReady(metrics, 'unifi local');
  const long = metrics.find(m => m.value === 5 && m.unit === '%');
  assert.equal(long.label, 'n'.repeat(199) + '… · CPU');
  assert.equal(long.key.length, 150);
  assert.equal(metrics.find(m => m.key === 'device_aa:bb_cpu').label, 'aa:bb · CPU');
  assert.equal(metrics.find(m => m.key === 'device_d4_cpu').label, 'Hall way · CPU');
  assert.equal(metrics.find(m => m.value === 9).key, 'device_lone\ufffd_cpu');
  assert.equal(metrics.find(m => m.value === 9).label, 'Shed\ufffd · CPU');
  const emoji = metrics.find(m => m.value === 10);
  assert.match(emoji.key, new RegExp(`^device_${'e'.repeat(129)}~[0-9a-f]{12}$`));
  assert.equal(emoji.label, 'n'.repeat(198) + '… · CPU');
  assert.ok(metrics.every(m => m.key.isWellFormed() && m.label.isWellFormed()));
  assert.equal(unnamed(metrics), 1);
  t.mock.restoreAll();

  // UniFi Integration API: a name that is an object, an ID that is a number.
  metrics = await collect(
    answers(t, 'unifi', path => {
      if (path.endsWith('/v1/sites')) return { data: [{ id: 's1' }, { id: 7 }], totalCount: 2 };
      if (path.endsWith('/devices'))
        return {
          data: [
            { id: 'd1', name: { a: 1 }, state: 'ONLINE' },
            { id: 5, name: 'numbered', state: 'ONLINE' },
          ],
          totalCount: 2,
        };
      if (path.endsWith('/statistics/latest')) return { cpuUtilizationPct: 5 };
      return { data: [], totalCount: 0 };
    })
  );
  ruleReady(metrics, 'unifi integration');
  assert.equal(metrics.find(m => m.key === 'device_d1_cpu').label, 'd1 · CPU');
  assert.equal(unnamed(metrics), 2, 'the site and the device with a numeric ID');
  t.mock.restoreAll();

  // Prowlarr: a 300-character indexer ID, an object ID, a list as a name.
  metrics = await collect(
    answers(t, 'prowlarr', path =>
      path === '/api/v1/indexerstats'
        ? {
            indexers: [
              { indexerId: 'x'.repeat(300), indexerName: 'Long\u202e', averageResponseTime: 5 },
              { indexerId: { a: 1 }, indexerName: 'Object', averageResponseTime: 6 },
              { indexerId: 7, indexerName: ['x'], averageResponseTime: 3 },
            ],
          }
        : []
    )
  );
  ruleReady(metrics, 'prowlarr');
  assert.equal(metrics.find(m => m.key === 'indexer_7_response').label, '7 · Response');
  assert.equal(metrics.find(m => m.value === 5 && m.unit === 'ms').label, 'Long · Response');
  assert.equal(unnamed(metrics), 1);
  t.mock.restoreAll();

  // AMP: a unit that is a number, one over 30 characters, one with a bell; long and odd names.
  metrics = await collect(
    answers(t, 'amp', path =>
      path.endsWith('/Login')
        ? { success: true, sessionID: 'amp-session' }
        : {
            Metrics: {
              'CPU Usage': { Percent: 5, RawValue: 5 },
              'TPS\u202e': { RawValue: 20, Units: 5 },
              ['Long ' + 'n'.repeat(300)]: { RawValue: 1, Units: 'u'.repeat(31) },
              Mem: { RawValue: 2, Units: 'MB\u0007' },
            },
          }
    )
  );
  ruleReady(metrics, 'amp');
  const amp = Object.fromEntries(metrics.map(m => [m.label.slice(0, 5), m]));
  assert.deepEqual([amp.TPS.unit, amp.TPS.key], ['', 'amp_TPS_']);
  assert.equal(amp['Long '].unit, '');
  assert.equal(amp['Long '].key.length, 150);
  assert.equal(amp.Mem.unit, 'MB');
  t.mock.restoreAll();

  // Linux: a mountpoint with NUL, a line break, markup and an RLO; a filesystem without one.
  metrics = await collect(
    answers(t, 'linux', () =>
      [
        'node_load1 0.5',
        'node_filesystem_size_bytes{mountpoint="/x\\u0000\\n<img src=x>\u202egpj.exe",fstype="ext4"} 100',
        'node_filesystem_avail_bytes{mountpoint="/x\\u0000\\n<img src=x>\u202egpj.exe",fstype="ext4"} 50',
        'node_filesystem_size_bytes{fstype="ext4"} 100',
      ].join('\n')
    )
  );
  ruleReady(metrics, 'linux');
  assert.equal(
    metrics.find(m => m.key === 'disk_/x <img src=x>gpj.exe').label,
    '/x <img src=x>gpj.exe · Used'
  );
  assert.equal(unnamed(metrics), 1);
});

test('keys from IDs keep their 1.4.3 key with white space at either end and direction marks, and entries that share a key are noted', async t => {
  // 1.4.3 used IDs and paths as the source sent them. White space at either end and the
  // direction marks (U+061C, U+200E, U+200F) are safe in a key, so trimming or dropping them
  // only moved a reading to a new key on upgrade: its history started again and its alert rules
  // matched nothing, without a word. Each expected key below is the one 1.4.3 produced.
  const fs = mount => [
    `node_filesystem_size_bytes{mountpoint="${JSON.stringify(mount).slice(1, -1)}",fstype="ext4"} 100`,
    `node_filesystem_avail_bytes{mountpoint="${JSON.stringify(mount).slice(1, -1)}",fstype="ext4"} 40`,
  ];
  const mounts = ['/mnt/data', '/mnt/data ', '/mnt/data\u200f', ' /lead', '/srv/\u200fmedia'];
  // Controls (a run becomes one space), embeddings, overrides and isolates (left out) still change
  // a key, so each pair below gives one key (/x\u202ey and /x\u2066y give /xy, /x\u0007y and
  // /x\ny give /x y); the readings left out are noted rather than dropped unseen.
  const unsafe = ['/x\u202ey', '/x\u2066y', '/x\u0007y', '/x\ny'];
  let metrics = await collect(
    answers(t, 'linux', () => ['node_load1 0.5', ...[...mounts, ...unsafe].flatMap(fs)].join('\n'))
  );
  ruleReady(metrics, 'linux');
  const free = metrics.filter(m => m.key.startsWith('disk_free_'));
  assert.deepEqual(
    free.map(m => m.key),
    [...mounts, '/xy', '/x y'].map(mount => 'disk_free_' + mount)
  );
  assert.deepEqual(
    free.map(m => m.label),
    ['/mnt/data', '/mnt/data', '/mnt/data', '/lead', '/srv/media', '/xy', '/x y'].map(
      name => name + ' · Free'
    )
  );
  const duplicates = metrics.notes.find(n => n.code === 'duplicate_keys_left_out');
  assert.equal(duplicates?.omitted, 4, JSON.stringify(metrics.notes));
  t.mock.restoreAll();

  // Windows volumes, Proxmox nodes and storages, UniFi devices and Prowlarr indexers alike.
  metrics = await collect(
    answers(t, 'windows', () =>
      [
        'windows_cs_physical_memory_bytes 1000',
        ...['C:', 'C:\u200e'].flatMap(volume => [
          `windows_logical_disk_size_bytes{volume="${volume}"} 100`,
          `windows_logical_disk_free_bytes{volume="${volume}"} 25`,
        ]),
      ].join('\n')
    )
  );
  ruleReady(metrics, 'windows');
  assert.deepEqual(
    metrics.filter(m => m.key.startsWith('disk_free_')).map(m => m.key),
    ['disk_free_C:', 'disk_free_C:\u200e']
  );
  t.mock.restoreAll();
  metrics = await collect(
    answers(t, 'proxmox', () => ({
      data: [
        { id: 'node/pve\u200f', type: 'node', node: 'pve', status: 'online', cpu: 0.1 },
        { id: 'storage/pve/local ', storage: 'local', type: 'storage', node: 'pve', disk: 1 },
      ],
    }))
  );
  ruleReady(metrics, 'proxmox');
  assert.equal(metrics.find(m => m.key === 'node/pve\u200f.cpu')?.label, 'pve · CPU');
  assert.equal(metrics.find(m => m.key === 'storage/pve/local .used')?.label, 'local · Used');
  t.mock.restoreAll();
  metrics = await collect(
    answers(
      t,
      'unifi',
      path => {
        if (path === '/api/auth/login')
          return new Response('{}', { headers: { 'Set-Cookie': 'TOKEN=t; Path=/' } });
        const devices = [{ _id: ' a1', state: 1, 'system-stats': { cpu: 5 } }];
        return { meta: { rc: 'ok' }, data: path.endsWith('/device') ? devices : [] };
      },
      { apiUrl: 'https://console.example', apiKey: '' }
    )
  );
  ruleReady(metrics, 'unifi');
  assert.equal(metrics.find(m => m.key === 'device_ a1_cpu')?.label, 'a1 · CPU');
  t.mock.restoreAll();
  metrics = await collect(
    answers(t, 'prowlarr', path =>
      path === '/api/v1/indexerstats'
        ? { indexers: [{ indexerId: 'x\u061c', averageResponseTime: 5 }] }
        : []
    )
  );
  ruleReady(metrics, 'prowlarr');
  assert.equal(metrics.find(m => m.key === 'indexer_x\u061c_response')?.label, 'x · Response');
  t.mock.restoreAll();

  // Sonarr and Radarr: a path listed twice was dropped unseen by the collector itself; it is now
  // left out by the same rule as any other key given twice, and noted.
  metrics = await collect(
    answers(t, 'radarr', path =>
      path.endsWith('/diskspace')
        ? [
            { path: '/mnt/media', freeSpace: 1, totalSpace: 2 },
            { path: '/mnt/media ', freeSpace: 3, totalSpace: 4 },
            { path: '/mnt/media', freeSpace: 5, totalSpace: 6 },
          ]
        : path.endsWith('/queue/status')
          ? { totalCount: 0 }
          : []
    )
  );
  ruleReady(metrics, 'radarr');
  assert.deepEqual(
    metrics.filter(m => m.key.startsWith('disk_')).map(m => [m.key, m.value]),
    [
      ['disk_free_/mnt/media', 1],
      ['disk_total_/mnt/media', 2],
      ['disk_free_/mnt/media ', 3],
      ['disk_total_/mnt/media ', 4],
    ]
  );
  assert.equal(metrics.notes.find(n => n.code === 'duplicate_keys_left_out')?.omitted, 2);
});

// docs/troubleshooting.md, "Measurement keys after an upgrade from 1.4.x", lists the cases in which
// a key differs from the one 1.4.3 made, or the reading is left out, found by running v1.4.3's
// collectors and these on the same answers for every collector that makes a key from a source's
// ID or path; the CHANGELOG's "Source answers" entry and the "No metric alert" row point there.
// The CHANGELOG said a key differs "only when" an ID holds a control character or a direction
// override, is over 150 characters, starts with "__" or was cut inside a character, and the row
// left out the cut and U+2028; blank, non-text and 0 IDs and Proxmox guests without an ID change
// keys too. Each row below is one case of that table: the key 1.4.3 made from the value (measured
// by running v1.4.3's collectors on the same answers; null when 1.4.3 read no such reading) and
// the one 1.5 makes (null: left out).
test('each key change from 1.4.3 that docs/troubleshooting.md lists gives the key it names, and the docs point to that list', async t => {
  const device = id => ({ _id: id, mac: 'aa:bb', state: 1, 'system-stats': { cpu: 5 } });
  const node = { id: 'node/pve', type: 'node', node: 'pve', status: 'online', cpu: 0.1 };
  const guest = id => ({ id, type: 'qemu', node: 'pve', vmid: 101, status: 'running', cpu: 0.5 });
  const storage = id => ({ id, storage: 's', type: 'storage', node: 'pve', disk: 1, maxdisk: 2 });
  const prom = (metric, label, value) =>
    `${metric}{${label}="${JSON.stringify(value).slice(1, -1)}"}`;
  const sites = {
    linux: value => [
      'linux',
      () =>
        `node_load1 0.5\n${prom('node_filesystem_size_bytes', 'mountpoint', value)} 100\n` +
        `${prom('node_filesystem_avail_bytes', 'mountpoint', value)} 40\n`,
      {},
      key => key.startsWith('disk_free_'),
    ],
    windows: value => [
      'windows',
      () =>
        `windows_cs_physical_memory_bytes 1000\n${prom('windows_logical_disk_size_bytes', 'volume', value)} 100\n` +
        `${prom('windows_logical_disk_free_bytes', 'volume', value)} 25\n`,
      {},
      key => key.startsWith('disk_free_'),
    ],
    radarr: value => [
      'radarr',
      p =>
        p.endsWith('/diskspace')
          ? [{ path: value, freeSpace: 1, totalSpace: 2 }]
          : p.endsWith('/queue/status')
            ? { totalCount: 0 }
            : [],
      {},
      key => /^disk_(free_|\d+_free$)/.test(key),
    ],
    amp: value => [
      'amp',
      p =>
        p.endsWith('/Login')
          ? { success: true, sessionID: 'amp-session' }
          : { Metrics: { 'CPU Usage': { Percent: 5, RawValue: 5 }, [value]: { RawValue: 1 } } },
      {},
      key => key.startsWith('amp_'),
    ],
    prowlarr: value => [
      'prowlarr',
      p =>
        p === '/api/v1/indexerstats'
          ? { indexers: [{ indexerId: value, indexerName: 'n', averageResponseTime: 5 }] }
          : [],
      {},
      key => key.startsWith('indexer_'),
    ],
    unifiLocal: value => [
      'unifi',
      p =>
        p === '/api/auth/login'
          ? new Response('{}', { headers: { 'Set-Cookie': 'TOKEN=t; Path=/' } })
          : { meta: { rc: 'ok' }, data: p.endsWith('/device') ? [device(value)] : [] },
      { apiUrl: 'https://console.example', apiKey: '' },
      key => key.startsWith('device_'),
    ],
    // `fields`: the device's _id, mac and device_id (any of them missing).
    unifiLocalFields: fields => [
      'unifi',
      p =>
        p === '/api/auth/login'
          ? new Response('{}', { headers: { 'Set-Cookie': 'TOKEN=t; Path=/' } })
          : {
              meta: { rc: 'ok' },
              data: p.endsWith('/device')
                ? [{ ...fields, state: 1, 'system-stats': { cpu: 5 } }]
                : [],
            },
      { apiUrl: 'https://console.example', apiKey: '' },
      key => key.startsWith('device_'),
    ],
    unifiIntegration: value => [
      'unifi',
      p =>
        p.endsWith('/v1/sites')
          ? { data: [{ id: 's1' }], totalCount: 1 }
          : p.endsWith('/devices')
            ? { data: [{ id: value, name: 'n', state: 'ONLINE' }], totalCount: 1 }
            : p.endsWith('/statistics/latest')
              ? { cpuUtilizationPct: 5 }
              : { data: [], totalCount: 0 },
      {},
      key => key.startsWith('device_'),
    ],
    // A body with a number JSON reads as Infinity, which Response.json() cannot write.
    proxmoxNodeText: text => [
      'proxmox',
      () =>
        new Response(
          `{"data":[{"id":${text},"type":"node","node":"pve","status":"online","cpu":0.1}]}`,
          { headers: { 'Content-Type': 'application/json' } }
        ),
      { nodeName: '' },
      key => key.endsWith('.cpu'),
    ],
  };
  for (const nodeName of ['', 'pve']) {
    const mode = nodeName ? 'Node' : 'Cluster',
      pick = suffix => key =>
        (key.endsWith(suffix) || /~[0-9a-f]{12}$/.test(key)) && key !== 'node/pve.cpu';
    sites['proxmoxNode' + mode] = value => [
      'proxmox',
      () => ({ data: [{ ...node, id: value }] }),
      { nodeName },
      key => key.endsWith('.cpu') || /~[0-9a-f]{12}$/.test(key),
    ];
    sites['proxmoxGuest' + mode] = value => [
      'proxmox',
      () => ({ data: [node, guest(value)] }),
      { nodeName },
      pick('.cpu'),
    ];
    sites['proxmoxStorage' + mode] = value => [
      'proxmox',
      () => ({ data: [node, storage(value)] }),
      { nodeName },
      pick('.used'),
    ];
  }
  const proxmox = (kind, value, before, after) =>
    ['Cluster', 'Node'].map(mode => [`proxmox${kind}${mode}`, value, before, after]);
  const p126 = 'p'.repeat(126),
    emoji = p126 + '\u{1F600}' + 'q'.repeat(30),
    x140 = 'x'.repeat(140);
  const rows = {
    'a control character, U+2028 or U+2029: one space for each run': [
      ['linux', '/mnt/a\u0007b', 'disk_free_/mnt/a\u0007b', 'disk_free_/mnt/a b'],
      ['linux', '/mnt/a\u2028b', 'disk_free_/mnt/a\u2028b', 'disk_free_/mnt/a b'],
      ['radarr', '/mnt/a\u2029\u0085b', 'disk_free_/mnt/a\u2029\u0085b', 'disk_free_/mnt/a b'],
      ['unifiLocal', 'a\nb', 'device_a\nb_cpu', 'device_a b_cpu'],
      ['prowlarr', 'a\u007fb', 'indexer_a\u007fb_response', 'indexer_a b_response'],
    ],
    'a direction embedding, override or isolate: removed': [
      ['windows', 'C:\u202e', 'disk_free_C:\u202e', 'disk_free_C:'],
      ['unifiIntegration', 'a\u2066b', 'device_a\u2066b_cpu', 'device_ab_cpu'],
      ...proxmox('Storage', 's\u202ax', 's\u202ax.used', 'sx.used'),
    ],
    'a disk path cut inside a character: cut before it': [
      ['linux', emoji, `disk_free_${p126}\ud83d~314ce9b14177`, `disk_free_${p126}~314ce9b14177`],
      ['radarr', emoji, `disk_free_${p126}\ud83d~314ce9b14177`, `disk_free_${p126}~314ce9b14177`],
    ],
    'a device, guest, storage, indexer or AMP key over 150 characters: a prefix and a hash': [
      ['prowlarr', x140, `indexer_${x140}_response`, `indexer_${'x'.repeat(129)}~ecceeb8c7560`],
      ['unifiLocal', x140, `device_${x140}_cpu`, `device_${'x'.repeat(130)}~dcff8ab577c5`],
      ['amp', 'a'.repeat(160), `amp_${'a'.repeat(160)}`, `amp_${'a'.repeat(133)}~bf18b43b6165`],
    ],
    'a Proxmox key starting with __: ~ in front': [
      ...proxmox('Node', '__n', '__n.cpu', '~__n.cpu'),
      ...proxmox('Guest', '__g', '__g.cpu', '~__g.cpu'),
      ...proxmox('Storage', '__s', '__s.used', '~__s.used'),
    ],
    'a blank or non-text Proxmox node or guest ID: the node name or the VMID': [
      ...proxmox('Node', '   ', '   .cpu', 'pve.cpu'),
      ...proxmox('Node', { a: 1 }, '[object Object].cpu', 'pve.cpu'),
      ...proxmox('Guest', '\u200f', '\u200f.cpu', '101.cpu'),
      ...proxmox('Guest', true, 'true.cpu', '101.cpu'),
      ...proxmox('Guest', ['a', 'b'], 'a,b.cpu', '101.cpu'),
      ['proxmoxNodeText', '1e999', 'Infinity.cpu', 'pve.cpu'],
    ],
    'a Proxmox guest without an ID: its VMID, not its node name': [
      ...proxmox('Guest', undefined, 'pve.cpu', '101.cpu'),
      ...proxmox('Guest', '', 'pve.cpu', '101.cpu'),
      ...proxmox('Guest', null, 'pve.cpu', '101.cpu'),
      ...proxmox('Guest', false, 'pve.cpu', '101.cpu'),
    ],
    'the number 0 as a Proxmox node or guest ID or a UniFi _id: 0': [
      ...proxmox('Node', 0, 'pve.cpu', '0.cpu'),
      ...proxmox('Guest', 0, 'pve.cpu', '0.cpu'),
      ['unifiLocal', 0, 'device_aa:bb_cpu', 'device_0_cpu'],
    ],
    'a blank UniFi _id: the MAC': [
      ['unifiLocal', '   ', 'device_   _cpu', 'device_aa:bb_cpu'],
      ['unifiLocal', '\ufeff', 'device_\ufeff_cpu', 'device_aa:bb_cpu'],
      ['unifiLocal', '\u200e\u0000', 'device_\u200e\u0000_cpu', 'device_aa:bb_cpu'],
    ],
    'a non-text or non-zero number UniFi _id, which 1.4.3 left out: the MAC or the number': [
      ['unifiLocal', { a: 1 }, null, 'device_aa:bb_cpu'],
      ['unifiLocal', 5, null, 'device_5_cpu'],
    ],
    // 1.4.3 took the first of _id, MAC and device_id that was not missing, empty, 0, false or
    // null, and left the device out, without a note, unless that one was text; 1.5 takes the
    // first that is text and not blank, or a number. The rows above on the UniFi _id are cases
    // of this one, which the table states as one row.
    'a UniFi device keyed by the first of _id, MAC and device_id each takes': [
      ['unifiLocalFields', { mac: 5 }, null, 'device_5_cpu'],
      ['unifiLocalFields', { mac: 0 }, null, 'device_0_cpu'],
      ['unifiLocalFields', { device_id: 7 }, null, 'device_7_cpu'],
      ['unifiLocalFields', { _id: '', mac: 5 }, null, 'device_5_cpu'],
      ['unifiLocalFields', { _id: false, device_id: 9 }, null, 'device_9_cpu'],
      ['unifiLocalFields', { mac: 5, device_id: 'dev1' }, null, 'device_5_cpu'],
      ['unifiLocalFields', { _id: 0, device_id: 'dev1' }, 'device_dev1_cpu', 'device_0_cpu'],
      ['unifiLocalFields', { _id: '  ', mac: 5 }, 'device_  _cpu', 'device_5_cpu'],
      ['unifiLocalFields', { mac: '  ', device_id: 0 }, 'device_  _cpu', 'device_0_cpu'],
      ['unifiLocalFields', { _id: true, mac: 'aa:bb' }, null, 'device_aa:bb_cpu'],
    ],
    'a blank Sonarr or Radarr disk path: its place in the list': [
      ['radarr', '\u00a0', 'disk_free_\u00a0', 'disk_0_free'],
    ],
    'a missing, blank or non-text storage, indexer or UniFi Integration ID: left out': [
      ...proxmox('Storage', undefined, 'undefined.used', null),
      ...proxmox('Storage', null, 'null.used', null),
      ['prowlarr', false, 'indexer_false_response', null],
      ['prowlarr', '\t', 'indexer_\t_response', null],
      ['unifiIntegration', { a: 1 }, 'device_[object Object]_cpu', null],
      ['unifiIntegration', 5, 'device_5_cpu', null],
      ['unifiIntegration', '', 'device__cpu', null],
    ],
    'an empty or blank Linux mountpoint or Windows volume: left out': [
      ['linux', ' ', 'disk_free_ ', null],
      ['windows', '', 'disk_free_', null],
    ],
  };
  for (const [row, cases] of Object.entries(rows))
    for (const [site, value, before, after] of cases) {
      const [type, respond, extra, pick] = sites[site](value);
      const metrics = await collect(answers(t, type, respond, extra));
      t.mock.restoreAll();
      const what = `${row} (${site} ${JSON.stringify(value)})`;
      assert.notEqual(after, before, what);
      assert.deepEqual(metrics.map(m => m.key).filter(pick), after === null ? [] : [after], what);
      if (after === null) assert.equal(unnamed(metrics), 1, what);
    }
  // What both keep, which the table therefore leaves out.
  for (const [site, value, key] of [
    ['linux', '/mnt/a\u200fb', 'disk_free_/mnt/a\u200fb'],
    ['linux', ' /mnt/a\u00a0', 'disk_free_ /mnt/a\u00a0'],
    ['unifiLocal', '\u200b', 'device_\u200b_cpu'],
    ['unifiLocal', null, 'device_aa:bb_cpu'],
    ['unifiLocalFields', { _id: 'abc', mac: 5 }, 'device_abc_cpu'],
    // AMP's key turns each character but an ASCII letter or digit into _, in 1.4.3 as in 1.5:
    // the rows on control characters, direction overrides and half of a pair leave it out.
    ['amp', 'a\tb', 'amp_a_b'],
    ['amp', 'a\u0085b', 'amp_a_b'],
    ['amp', 'a\u2028b', 'amp_a_b'],
    ['amp', 'a\u202eb', 'amp_a_b'],
    ['amp', 'a\ud800b', 'amp_a_b'],
    ['prowlarr', 0, 'indexer_0_response'],
    ['radarr', '', 'disk_0_free'],
    ...proxmox('Node', '', 'pve.cpu', 'pve.cpu').map(([s, v, k]) => [s, v, k]),
    ...proxmox('Storage', 5, '5.used', '5.used').map(([s, v, k]) => [s, v, k]),
  ]) {
    const [type, respond, extra, pick] = sites[site](value);
    const metrics = await collect(answers(t, type, respond, extra));
    t.mock.restoreAll();
    assert.deepEqual(
      metrics.map(m => m.key).filter(pick),
      [key],
      `${site} ${JSON.stringify(value)}`
    );
  }

  // The docs name these cases and say where the full list is, without claiming it is shorter.
  const docs = name => fs.readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
  const troubleshooting = docs('docs/troubleshooting.md'),
    section = troubleshooting.split('\n## Measurement keys after an upgrade from 1.4.x\n')[1];
  assert.ok(section, 'docs/troubleshooting.md has the section');
  // GitHub's anchor for that heading, which both links name.
  assert.equal(
    'Measurement keys after an upgrade from 1.4.x'
      .toLowerCase()
      .replace(/[^\p{L}\p{N} _-]/gu, '')
      .replace(/ /g, '-'),
    'measurement-keys-after-an-upgrade-from-14x'
  );
  const table = section.split('\n## ')[0];
  for (const phrase of [
    'An ID or path holding a control character (C0, DEL or C1), U+2028 or U+2029, other than an AMP metric name',
    '| Kept it | One space for each run of them |',
    'An ID or path holding a direction embedding, override or isolate, other than an AMP metric name | Kept it | Removed |',
    'Half of a surrogate pair in an ID or path, other than an AMP metric name, becomes U+FFFD',
    'with a character such as an emoji across the 137th',
    'A UniFi device, Proxmox node, guest or storage, Prowlarr indexer or AMP key over 150 characters',
    'A Proxmox node, guest or storage key starting with `__`',
    'A Proxmox node or guest ID that is blank or not text',
    "A Proxmox guest ID that is missing, empty, `null` or `false` | The name of the node the guest runs on | The guest's VMID",
    "The number 0 as a Proxmox node or guest ID | The node's name | `0` |",
    'A UniFi device (local controller), keyed by one of its `_id`, MAC and `device_id` | The first of the three that is not missing, empty, 0, `false` or `null`, when that one is text (blank text too); when it is a number such as `5`, `true` or an object, no reading and no note | The first of the three that is text and not blank, or a number (`0` included, `1e999` not); left out with a note when none is.',
    "A blank Sonarr or Radarr disk path | Used it | The disk's place in the list (`disk_0_free`)",
    'A Proxmox storage, Prowlarr indexer or UniFi Integration device ID that is missing, empty, blank, `null`, `false` or not text, and a UniFi Integration device ID that is a number',
    'An empty or blank Linux mountpoint or Windows volume | Used it | Left out with a note |',
  ])
    assert.ok(table.includes(phrase), phrase);
  const noAlert = troubleshooting.split('\n').find(line => line.startsWith('| No metric alert |'));
  assert.match(noAlert, /\(#measurement-keys-after-an-upgrade-from-14x\)/);
  assert.match(noAlert, /U\+2028, U\+2029/);
  assert.match(noAlert, /cut inside a character such as an emoji/);
  const answersEntry = docs('CHANGELOG.md')
    .split('\n')
    .find(line => line.startsWith('- **Source answers (security).**'));
  assert.match(
    answersEntry,
    /\(docs\/troubleshooting\.md#measurement-keys-after-an-upgrade-from-14x\)/
  );
  assert.doesNotMatch(answersEntry, /made only when/);
  assert.match(
    answersEntry,
    /each run of control characters and line or paragraph separators \(U\+2028, U\+2029\) becomes one space/
  );
});

test('percent readings outside 0-100 and negative byte, rate, time and count readings are left out in every collector', async t => {
  // Proxmox cluster: a node reporting -5 for its CPU share and more memory used than it has, a
  // storage with negative usage. The cluster CPU clamps each node's share to 0-1.
  const resources = [
    {
      id: 'node/pve',
      type: 'node',
      node: 'pve',
      status: 'online',
      cpu: -5,
      maxcpu: 2,
      mem: 3,
      maxmem: 2,
      uptime: -1,
    },
    { id: 'storage/pve/local', type: 'storage', node: 'pve', disk: -7, maxdisk: 10 },
  ];
  let v = values(await collect(answers(t, 'proxmox', () => ({ data: resources }))));
  assert.equal(v.cpu, 0);
  for (const key of ['memory', 'node/pve.cpu', 'node/pve.uptime', 'storage/pve/local.used'])
    assert.equal(v[key], undefined, key);
  assert.equal(v.memory_used, 3);
  assert.equal(v['storage/pve/local.total'], 10);
  t.mock.restoreAll();
  // Node mode: memory above its total.
  v = values(
    await collect(answers(t, 'proxmox', () => ({ data: resources }), { nodeName: 'pve' }))
  );
  assert.equal(v.memory, undefined);
  assert.equal(v.memory_used, 3);
  t.mock.restoreAll();

  // UniFi Integration API device statistics.
  v = values(
    await collect(
      answers(t, 'unifi', path => {
        if (path.endsWith('/v1/sites')) return { data: [{ id: 's1' }], totalCount: 1 };
        if (path.endsWith('/devices'))
          return { data: [{ id: 'd1', state: 'ONLINE' }], totalCount: 1 };
        if (path.endsWith('/statistics/latest'))
          return {
            cpuUtilizationPct: 1e300,
            memoryUtilizationPct: -50,
            uptimeSec: -3,
            uplink: { rxRateBps: -8, txRateBps: 80 },
          };
        return { data: [], totalCount: 0 };
      })
    )
  );
  for (const key of ['device_d1_cpu', 'device_d1_memory', 'device_d1_uptime', 'device_d1_rx'])
    assert.equal(v[key], undefined, key);
  assert.equal(v.device_d1_tx, 10);
  t.mock.restoreAll();

  // Linux and Windows memory: a total smaller than what is available or free.
  v = values(
    await collect(
      answers(
        t,
        'linux',
        () => 'node_memory_MemTotal_bytes 1e-300\nnode_memory_MemAvailable_bytes 5\n'
      )
    )
  );
  assert.equal(v.memory, undefined);
  assert.equal(v.memory_used, undefined);
  t.mock.restoreAll();
  v = values(
    await collect(
      answers(
        t,
        'windows',
        () => 'windows_cs_physical_memory_bytes 100\nwindows_os_physical_memory_free_bytes 200\n'
      )
    )
  );
  assert.equal(v.memory, undefined);
  assert.equal(v.memory_total, 100);
  t.mock.restoreAll();

  // NZBGet: a signed low half is read as unsigned; a negative or fractional high half means the
  // single field is used; negative sizes and uptime are left out.
  v = values(
    await collect(
      answers(t, 'nzbget', () => ({
        result: {
          DownloadRateHi: 0,
          DownloadRateLo: -1,
          RemainingSizeHi: -1,
          RemainingSizeLo: 5,
          RemainingSizeMB: 2,
          FreeDiskSpaceHi: 0.5,
          FreeDiskSpaceLo: 1,
          FreeDiskSpaceMB: -5,
          UpTimeSec: -3,
          PostJobCount: 0,
        },
      }))
    )
  );
  assert.equal(v.speed, 4294967295);
  assert.equal(v.remaining, 2 * 1048576);
  assert.equal(v.free_disk, undefined);
  assert.equal(v.uptime, undefined);
  assert.equal(v.post_jobs, 0);
  t.mock.restoreAll();

  // Cosmos: a negative scale and a negative time scale.
  const sample = (Key, Value, extra = {}) => ({
    Key,
    Values: [{ Date: new Date().toISOString(), Value }],
    ...extra,
  });
  v = values(
    await collect(
      answers(t, 'cosmos', path =>
        path === '/cosmos/api/servapps'
          ? { status: 'OK', data: [] }
          : {
              status: 'OK',
              data: [
                sample('cosmos.system.cpu.0', 50, { Scale: -1 }),
                sample('cosmos.system.ram', 10, { Max: 100 }),
                sample('cosmos.system.netRx', 60, { TimeScale: -1 }),
              ],
            }
      )
    )
  );
  assert.equal(v.cpu, undefined);
  assert.equal(v.receive, undefined);
  assert.equal(v.memory, 10);
  t.mock.restoreAll();

  // Custom mappings keep what the source sends: the admin chose what they measure.
  v = values(
    await collect(
      answers(t, 'json', () => ({ change: -5, temperature: -12 }), {
        metrics: [
          { key: 'change', label: 'Change', path: 'change', unit: '%' },
          { key: 'temperature', label: 'Temperature', path: 'temperature', unit: '' },
        ],
      })
    )
  );
  assert.deepEqual(v, { change: -5, temperature: -12 });
  t.mock.restoreAll();
  v = values(
    await collect(
      answers(t, 'prometheus', () => 'offset_seconds -2\n', {
        metrics: [{ key: 'offset', label: 'Offset', path: 'offset_seconds', unit: 'seconds' }],
      })
    )
  );
  assert.deepEqual(v, { offset: -2 });
});
