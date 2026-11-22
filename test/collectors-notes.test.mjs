import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { newService } from '../lib/catalog.mjs';
import { collect, noteMessages, resetCollector, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { displayDashboard } from '../lib/http/display-view.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

// Every cap that leaves readings out says so in a note attached to the readings. The array
// itself is unchanged: the notes property is not enumerable, so it never reaches JSON, and
// readings without a cap carry an empty list.
const values = readings => Object.fromEntries(readings.map(m => [m.key, m.value]));
const codes = readings => readings.notes.map(n => n.code);
const note = (readings, code) => readings.notes.find(n => n.code === code);
function serve(t, respond) {
  t.mock.method(transport, 'fetch', async (url, options) => {
    const body = await respond(new URL(url), options);
    return body instanceof Response
      ? body
      : typeof body === 'string'
        ? new Response(body)
        : Response.json(body);
  });
}
function source(t, type, extra = {}) {
  const service = {
    ...newService(type, 'notes-' + type),
    apiUrl: 'https://notes.example.com',
    ...extra,
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  return service;
}

test('every note message is fixed text within 200 characters, whatever the count', () => {
  // The codes are part of the notes contract: the UI and API consumers may key on them.
  assert.deepEqual(Object.keys(noteMessages).sort(), [
    'arr_library_too_large',
    'crowdsec_alerts_capped',
    'crowdsec_alerts_too_large',
    'duplicate_keys_left_out',
    'filesystems_capped',
    'interfaces_capped',
    'mappings_ambiguous',
    'measurements_capped',
    'proxmox_guests_capped',
    'unifi_devices_capped',
    'unifi_lists_capped',
    'unifi_sites_capped',
    'unnamed_entries_left_out',
  ]);
  for (const [code, message] of Object.entries(noteMessages))
    for (const detail of [
      { omitted: 1, product: 'Sonarr' },
      { omitted: Number.MAX_SAFE_INTEGER, product: 'Radarr' },
    ]) {
      const text = message(detail);
      assert.ok(text.length <= 200, `${code}: ${text.length} characters`);
      assert.match(code, /^[a-z][a-z0-9_]{0,63}$/);
    }
});

test('readings without a cap carry an empty, non-enumerable notes list', async t => {
  serve(t, () => ({ temperature: 21 }));
  const readings = await collect(
    source(t, 'json', {
      metrics: [{ key: 'temperature', label: 'Temperature', path: 'temperature' }],
    })
  );
  assert.deepEqual(values(readings), { temperature: 21 });
  assert.deepEqual(readings.notes, []);
  assert.deepEqual(Object.keys(readings), ['0']);
  assert.equal(JSON.stringify(readings), JSON.stringify([...readings]));
  assert.ok(!JSON.stringify(readings).includes('notes'));
});

test('more than 512 measurements keep the first 512 and say how many were left out', async t => {
  const mappings = Array.from({ length: 600 }, (_, i) => ({
    key: 'm' + i,
    label: 'Measurement ' + i,
    path: 'v' + i,
  }));
  serve(t, () => Object.fromEntries(mappings.map((m, i) => ['v' + i, i])));
  const readings = await collect(source(t, 'json', { metrics: mappings }));
  assert.equal(readings.length, 512);
  assert.equal(readings.at(-1).key, 'm511');
  assert.deepEqual(codes(readings), ['measurements_capped']);
  assert.equal(note(readings, 'measurements_capped').omitted, 88);
  assert.match(note(readings, 'measurements_capped').message, /first 512 and leaves out 88\.$/);
  // Exactly 512 is not a cap.
  const exact = await collect(source(t, 'json', { metrics: mappings.slice(0, 512) }));
  assert.equal(exact.length, 512);
  assert.deepEqual(exact.notes, []);
});

test('Linux and Windows filesystems beyond 200 are noted, with the count left out', async t => {
  const linux = Array.from(
    { length: 250 },
    (_, i) =>
      `node_filesystem_size_bytes{mountpoint="/m${i}",device="d${i}",fstype="ext4"} 100\n` +
      `node_filesystem_avail_bytes{mountpoint="/m${i}",device="d${i}",fstype="ext4"} 50\n`
  ).join('');
  // tmpfs and other pseudo filesystems are not counted towards the cap.
  const pseudo = Array.from(
    { length: 30 },
    (_, i) => `node_filesystem_size_bytes{mountpoint="/run/${i}",fstype="tmpfs"} 1\n`
  ).join('');
  serve(t, () => 'node_load1 0.5\n' + pseudo + linux);
  let readings = await collect(source(t, 'linux'));
  assert.equal(readings.filter(m => m.key.startsWith('disk_free_')).length, 200);
  assert.deepEqual(codes(readings), ['filesystems_capped']);
  assert.equal(note(readings, 'filesystems_capped').omitted, 50);
  const windows = Array.from(
    { length: 210 },
    (_, i) =>
      `windows_logical_disk_size_bytes{volume="V${i}:"} 100\n` +
      `windows_logical_disk_free_bytes{volume="V${i}:"} 25\n`
  ).join('');
  serve(t, () => 'windows_cs_physical_memory_bytes 1000\n' + windows);
  readings = await collect(source(t, 'windows'));
  assert.equal(readings.filter(m => m.key.startsWith('disk_free_')).length, 200);
  assert.equal(note(readings, 'filesystems_capped').omitted, 10);
  // 200 exactly is complete.
  serve(t, () => 'node_load1 0.5\n' + linux.split('\n').slice(0, 400).join('\n') + '\n');
  assert.deepEqual((await collect(source(t, 'linux'))).notes, []);
});

test('readings that share a key are noted, and the note and Troubleshooting say which share one', async t => {
  // A key made from an ID or path (upstreamId) holds one space for each run of control
  // characters, leaves out the direction embeddings, overrides and isolates, and holds U+FFFD for
  // half a surrogate pair. It keeps the direction marks and white space at either end, so a
  // control character that replaces nothing does not make an ID share a key.
  const escaped = mount => JSON.stringify(mount).slice(1, -1);
  for (const [mounts, keys] of [
    [['/x', '/x'], ['/x']],
    [['/x y', '/x\u0007y'], ['/x y']],
    [['/x y', '/x\u0007\u0085\u2028y'], ['/x y']],
    [['/xy', '/x\u202ey'], ['/xy']],
    [['/xy', '/x\u2069y'], ['/xy']],
    [['/x\ud800', '/x\udbff'], ['/x\ufffd']],
    [
      ['/xy', '/x\u0007y'],
      ['/xy', '/x y'],
    ],
    [
      ['/x  y', '/x\u0007y'],
      ['/x  y', '/x y'],
    ],
    [
      ['/x', '/x\u200f'],
      ['/x', '/x\u200f'],
    ],
    [
      ['/x', '/x\u200e'],
      ['/x', '/x\u200e'],
    ],
    [
      ['/x', '/x\u061c'],
      ['/x', '/x\u061c'],
    ],
    [
      ['/x', '/x '],
      ['/x', '/x '],
    ],
    [
      ['/x', ' /x'],
      ['/x', ' /x'],
    ],
  ]) {
    serve(t, () =>
      [
        'node_load1 0.5',
        ...mounts.flatMap(mount => [
          `node_filesystem_size_bytes{mountpoint="${escaped(mount)}",fstype="ext4"} 100`,
          `node_filesystem_avail_bytes{mountpoint="${escaped(mount)}",fstype="ext4"} 40`,
        ]),
      ].join('\n')
    );
    const readings = await collect(source(t, 'linux'));
    const what = JSON.stringify(mounts);
    assert.deepEqual(
      readings.filter(m => m.key.startsWith('disk_free_')).map(m => m.key),
      keys.map(key => 'disk_free_' + key),
      what
    );
    // Each mount gives two readings (used and free).
    assert.deepEqual(
      readings.notes,
      keys.length < mounts.length
        ? [
            {
              code: 'duplicate_keys_left_out',
              message:
                '2 readings have the measurement key of an earlier one (an ID or path listed twice, or two different ones that make one key) and are left out.',
              omitted: 2,
            },
          ]
        : [],
      what
    );
  }
  assert.equal(
    noteMessages.duplicate_keys_left_out({ omitted: 1 }),
    '1 reading has the measurement key of an earlier one (an ID or path listed twice, or two different ones that make one key) and is left out.'
  );
  // The Troubleshooting row the note points to states the same rule.
  const troubleshooting = fs
    .readFileSync(new URL('../docs/troubleshooting.md', import.meta.url), 'utf8')
    .replace(/\s+/g, ' ');
  for (const said of [
    'an ID or path listed twice, or two different ones that make one key: a key made from an ID or path holds one space for each run of control characters and line or paragraph separators (U+2028, U+2029), leaves out the direction embeddings, overrides and isolates, and holds U+FFFD for half a surrogate pair',
    'so `/x y` and `/x` followed by a control character and `y` make one key, while `/xy` and that second path make two, and IDs that differ in a direction mark or in white space at either end make two as well',
  ])
    assert.ok(troubleshooting.includes(said), said);
  assert.doesNotMatch(troubleshooting, /differ only in control or direction characters/);
});

test('network rates beyond 256 interfaces are noted once for receive and send', async t => {
  const nics = n =>
    Array.from(
      { length: n },
      (_, i) =>
        `node_network_receive_bytes_total{device="eth${i}"} 1\n` +
        `node_network_transmit_bytes_total{device="eth${i}"} 1\n`
    ).join('');
  serve(t, () => 'node_load1 0.5\n' + nics(300));
  const readings = await collect(source(t, 'linux'));
  assert.deepEqual(codes(readings), ['interfaces_capped']);
  assert.equal(note(readings, 'interfaces_capped').omitted, 44);
  serve(t, () => 'node_load1 0.5\n' + nics(256));
  assert.deepEqual((await collect(source(t, 'linux'))).notes, []);
});

test('UniFi device detail beyond 64 online devices is noted in both API modes', async t => {
  // Integration API: 70 online and 5 offline devices; offline ones never had detail.
  const integration = [
    ...Array.from({ length: 70 }, (_, i) => ({ id: 'd' + i, state: 'ONLINE' })),
    ...Array.from({ length: 5 }, (_, i) => ({ id: 'off' + i, state: 'OFFLINE' })),
  ];
  serve(t, url => {
    if (url.pathname.endsWith('/v1/sites')) return { data: [{ id: 'site' }], totalCount: 1 };
    if (url.pathname.endsWith('/devices')) return { data: integration, totalCount: 75 };
    if (url.pathname.endsWith('/clients')) return { data: [], totalCount: 0 };
    return { cpuUtilizationPct: 1, memoryUtilizationPct: 2, uptimeSec: 3 };
  });
  let readings = await collect(source(t, 'unifi', { apiKey: 'test-api-key' }));
  assert.equal(values(readings).devices, 75);
  assert.equal(readings.filter(m => /^device_.*_cpu$/.test(m.key)).length, 64);
  assert.deepEqual(codes(readings), ['unifi_devices_capped']);
  assert.equal(note(readings, 'unifi_devices_capped').omitted, 6);
  // Local console login: the same cap on the classic device list.
  const local = Array.from({ length: 66 }, (_, i) => ({
    _id: 'ap' + i,
    state: i < 64 ? 1 : i === 64 ? 0 : 1,
    'system-stats': { cpu: '1', mem: '2' },
  }));
  serve(t, url => {
    if (url.pathname === '/api/auth/login')
      return new Response('{}', {
        headers: { 'Set-Cookie': 'TOKEN=test-session; Path=/; Secure; HttpOnly' },
      });
    const name = url.pathname.split('/').pop();
    return { meta: { rc: 'ok' }, data: name === 'device' ? local : [] };
  });
  readings = await collect(
    source(t, 'unifi', {
      apiUrl: 'https://console.example',
      username: 'viewer',
      password: 'test-password',
    })
  );
  assert.equal(readings.filter(m => /^device_.*_cpu$/.test(m.key)).length, 64);
  assert.equal(note(readings, 'unifi_devices_capped').omitted, 1);
});

test('UniFi lists longer than 20,000 entries are noted, not silently truncated', async t => {
  const page = Array.from({ length: 200 }, () => ({}));
  let requests = 0;
  serve(t, url => {
    requests++;
    if (url.pathname.endsWith('/v1/sites')) return { data: [{ id: 'site' }], totalCount: 1 };
    if (url.pathname.endsWith('/devices')) return { data: [], totalCount: 0 };
    return { data: page, totalCount: 25000 };
  });
  const readings = await collect(source(t, 'unifi', { apiKey: 'test-api-key' }));
  assert.equal(values(readings).clients, 20000);
  assert.ok(requests < 110, 'reading stops at the cap');
  assert.deepEqual(codes(readings), ['unifi_lists_capped']);
});

test('Proxmox guest detail beyond 128 guests is noted with the count left out', async t => {
  const resources = [
    { id: 'node/pve', type: 'node', node: 'pve', status: 'online', cpu: 0.1, maxcpu: 4 },
    ...Array.from({ length: 140 }, (_, i) => ({
      id: 'lxc/' + (100 + i),
      type: 'lxc',
      node: 'pve',
      vmid: 100 + i,
      status: 'running',
      cpu: 0.01,
    })),
  ];
  serve(t, () => ({ data: resources }));
  for (const nodeName of ['', 'pve']) {
    const readings = await collect(source(t, 'proxmox', { apiKey: 'a@pve!b=c', nodeName }));
    assert.equal(values(readings).guests_total, 140);
    assert.deepEqual(codes(readings), ['proxmox_guests_capped'], nodeName);
    assert.equal(note(readings, 'proxmox_guests_capped').omitted, 12);
  }
});

test('CrowdSec alert counts at the 1,000 request limit are noted as possibly higher', async t => {
  let alerts = 1000;
  serve(t, url => {
    if (url.pathname === '/v1/watchers/login') return { token: 'watcher-fixture' };
    if (url.pathname === '/v1/alerts') return Array.from({ length: alerts }, (_, id) => ({ id }));
    return [];
  });
  const service = source(t, 'crowdsec', {
    username: 'fixture',
    password: 'fixture',
    apiKey: 'bouncer-fixture',
  });
  let readings = await collect(service);
  assert.equal(values(readings).alerts_24h, 1000);
  assert.deepEqual(codes(readings), ['crowdsec_alerts_capped']);
  alerts = 999;
  readings = await collect(service);
  assert.deepEqual(readings.notes, []);
});

test('notes never carry upstream text, even when the source sends it', async t => {
  const hostile = 'upstream-secret-<script>';
  const resources = Array.from({ length: 130 }, (_, i) => ({
    id: 'qemu/' + i,
    type: 'qemu',
    node: hostile,
    vmid: i,
    name: hostile,
    status: 'running',
  }));
  serve(t, () => ({
    data: [{ id: 'node/x', type: 'node', node: 'x', status: 'online' }, ...resources],
  }));
  const readings = await collect(source(t, 'proxmox', { apiKey: 'a@pve!b=c' }));
  assert.ok(readings.notes.length > 0);
  assert.ok(!JSON.stringify(readings.notes).includes('upstream-secret'));
});

test('an oversized single library entry reports the per-entry limit without losing other readings', async t => {
  serve(t, url => {
    if (/\/(movie|series)$/.test(url.pathname)) return [{ overview: 'x'.repeat(1024 * 1024) }];
    if (url.pathname.endsWith('/queue/status')) return { totalCount: 2 };
    if (url.pathname.endsWith('/wanted/missing')) return { totalRecords: 4 };
    if (url.pathname.endsWith('/health')) return [{ type: 'warning' }];
    return [];
  });
  for (const type of ['radarr', 'sonarr']) {
    const readings = await collect(source(t, type));
    assert.equal(values(readings).queue, 2);
    assert.equal(values(readings).health_issues, 1);
    assert.equal(values(readings)[type === 'radarr' ? 'movies' : 'series'], undefined);
    assert.match(note(readings, 'arr_library_too_large').message, /1 MB per entry/);
  }
});

test('a wall display drops a stored note whose code names an inherited object member', () => {
  // Stored notes are rebuilt from their code; 'constructor' passes the stored-code format check
  // but is not a note code, so it must not reach the display (nor any other inherited name).
  const full = {
    config: { services: [{ id: 'src-1', type: 'sonarr', name: 'Library' }] },
    catalog: [{ type: 'sonarr', name: 'Sonarr' }],
    services: [
      {
        id: 'src-1',
        metrics: [],
        notes: [
          { code: 'constructor', message: 'x', omitted: 3 },
          { code: 'hasOwnProperty', message: 'x' },
          { code: 'toString', message: 'x' },
          { code: 'arr_library_too_large', message: 'stored text is never shown' },
        ],
      },
    ],
  };
  const [state] = displayDashboard(full).services;
  assert.deepEqual(state.notes, [
    {
      code: 'arr_library_too_large',
      message: noteMessages.arr_library_too_large({ omitted: 0, product: 'Sonarr' }),
    },
  ]);
  for (const name of ['constructor', 'toString', 'hasOwnProperty', '__proto__'])
    assert.equal(Object.hasOwn(noteMessages, name) || name in noteMessages, false, name);
});
