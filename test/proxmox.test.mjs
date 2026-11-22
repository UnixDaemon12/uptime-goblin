import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { newService, publicConfig } from '../lib/catalog.mjs';
import { ConfigStore, validateService } from '../lib/config.mjs';
import { collect, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const names = ['pve-a', 'pve-b', 'pve-c', 'pve-d'];
function inventory() {
  return names.flatMap((node, index) => {
    const n = index + 1;
    return [
      {
        id: 'node/' + node,
        type: 'node',
        node,
        status: 'online',
        cpu: n / 10,
        mem: 100 * n * n,
        maxmem: 1000 * n,
        maxcpu: 4 * n,
        uptime: 10000 * n,
        disk: 20 * n,
        maxdisk: 100 * n,
      },
      ...Array.from({ length: n }, (_, j) => {
        const type = j % 2 ? 'lxc' : 'qemu';
        return {
          id: type + '/' + (n * 100 + j),
          type,
          node,
          vmid: n * 100 + j,
          name: node + '-guest-' + j,
          status: 'running',
          cpu: 0.05 * n,
          mem: 20 * n,
          uptime: 200 * n,
        };
      }),
      {
        id: 'storage/' + node + '/local',
        type: 'storage',
        node,
        storage: node + '-local',
        disk: 50 * n,
        maxdisk: 500 * n,
      },
    ];
  });
}
const source = nodeName => ({
  ...newService('proxmox', 'test-pve'),
  apiUrl: 'https://cluster.example.com:8006',
  apiKey: 'viewer@pve!orbit=test-only-token',
  nodeName,
});
const values = metrics => Object.fromEntries(metrics.map(m => [m.key, m.value]));
function fixture(t, resources = inventory(), status = 200) {
  const calls = [];
  t.mock.method(transport, 'fetch', async (url, options) => {
    calls.push({ url, options });
    assert.equal(url, 'https://cluster.example.com:8006/api2/json/cluster/resources');
    assert.equal(options.redirect, 'error');
    return new Response(
      JSON.stringify(status === 200 ? { data: resources } : { error: 'test-only-token' }),
      { status, headers: { 'Content-Type': 'application/json' } }
    );
  });
  return calls;
}

test('Proxmox node selection isolates all four nodes, guests and storage with distinct metrics', async t => {
  const calls = fixture(t);
  for (const [index, nodeName] of names.entries()) {
    const n = index + 1,
      metrics = await collect(source(nodeName)),
      v = values(metrics);
    assert.equal(v.node_online, 1);
    assert.equal(v.cpu, n * 10);
    assert.equal(v.memory, n * 10);
    assert.equal(v.memory_used, 100 * n * n);
    assert.equal(v.memory_total, 1000 * n);
    assert.equal(v.guests_running, n);
    assert.equal(v.guests_total, n);
    assert.equal(v.cpu_cores, 4 * n);
    assert.equal(v.uptime, 10000 * n);
    assert.equal(v.root_disk_used, 20 * n);
    assert.equal(v.root_disk_total, 100 * n);
    assert.equal(v.root_disk, 20);
    assert.equal(v['storage/' + nodeName + '/local.used'], 50 * n);
    for (const other of names.filter(name => name !== nodeName))
      assert.ok(!JSON.stringify(metrics).includes(other));
    assert.equal(metrics.filter(m => /^(qemu|lxc)\/\d+\.cpu$/.test(m.key)).length, n);
  }
  assert.equal(calls.length, 4);
  assert.ok(
    calls.every(
      call => call.options.headers.Authorization === 'PVEAPIToken=viewer@pve!orbit=test-only-token'
    )
  );
});

test('Proxmox empty node selection preserves whole-cluster values and token prefix support', async t => {
  const calls = fixture(t);
  const metrics = await collect({
      ...source(''),
      apiKey: 'PVEAPIToken=viewer@pve!orbit=test-only-token',
    }),
    v = values(metrics);
  assert.equal(v.cpu, 30);
  assert.equal(v.memory, 30);
  assert.equal(v.guests_running, 10);
  assert.equal(v.guests_total, 10);
  assert.equal(v.nodes_online, 4);
  assert.equal(v.nodes_total, 4);
  assert.equal(v.memory_used, 3000);
  assert.equal(v.memory_total, 10000);
  for (const name of names)
    assert.ok(metrics.some(m => m.key === 'storage/' + name + '/local.used'));
  assert.equal(v.node_online, undefined);
  assert.equal(v.cpu_cores, undefined);
  assert.equal(
    calls[0].options.headers.Authorization,
    'PVEAPIToken=viewer@pve!orbit=test-only-token'
  );
});

test('Proxmox requires the exact selected node resource to be visible', async t => {
  fixture(t);
  await assert.rejects(collect(source('PVE-A')), /exact name and token read permissions/);
  await assert.rejects(collect(source('missing-node')), /not uniquely visible/);
  t.mock.restoreAll();
  fixture(
    t,
    inventory().filter(row => row.type !== 'node')
  );
  await assert.rejects(collect(source('pve-a')), /not uniquely visible/);
  t.mock.restoreAll();
  fixture(t, []);
  await assert.rejects(collect(source('pve-a')), /not uniquely visible/);
});

test('Proxmox offline node exposes status and labeled capacity without stale runtime or guest readings', async t => {
  const resources = inventory();
  resources.find(row => row.type === 'node' && row.node === 'pve-b').status = 'offline';
  fixture(t, resources);
  const metrics = await collect(source('pve-b')),
    v = values(metrics);
  assert.equal(v.node_online, 0);
  assert.equal(v.nodes_online, 0);
  assert.equal(v.nodes_total, 1);
  assert.equal(v.cpu_cores, 8);
  assert.equal(v.memory_total, 2000);
  assert.equal(v.root_disk_total, 200);
  assert.ok(
    metrics
      .filter(m => ['cpu_cores', 'memory_total', 'root_disk_total'].includes(m.key))
      .every(m => m.label.includes('last reported'))
  );
  for (const key of [
    'cpu',
    'memory',
    'memory_used',
    'uptime',
    'root_disk',
    'root_disk_used',
    'guests_running',
    'guests_total',
  ])
    assert.equal(v[key], undefined);
  assert.ok(
    !metrics.some(
      m =>
        m.key.startsWith('qemu/') ||
        m.key.startsWith('lxc/') ||
        m.key.startsWith('storage/') ||
        m.key.startsWith('node/')
    )
  );
});

test('Proxmox unknown node status and missing measurements do not become false offline or zero', async t => {
  const resources = inventory(),
    node = resources.find(row => row.type === 'node' && row.node === 'pve-a');
  node.status = 'unknown';
  fixture(t, resources);
  await assert.rejects(collect(source('pve-a')), /known status/);
  node.status = 'online';
  for (const key of ['cpu', 'mem', 'maxmem', 'maxcpu', 'uptime', 'disk', 'maxdisk'])
    delete node[key];
  const v = values(await collect(source('pve-a')));
  assert.equal(v.node_online, 1);
  for (const key of [
    'cpu',
    'memory',
    'memory_used',
    'memory_total',
    'cpu_cores',
    'uptime',
    'root_disk',
    'root_disk_used',
    'root_disk_total',
  ])
    assert.equal(v[key], undefined);
});

test('Proxmox node selection validates, persists privately and remains safe in public configuration', t => {
  assert.equal(newService('proxmox').nodeName, '');
  for (const nodeName of ['', ...names, 'PVE-1', 'a', 'n'.repeat(63)])
    assert.equal(validateService({ nodeName }, newService('proxmox')).nodeName, nodeName);
  for (const nodeName of [
    '../pve-a',
    'pve/a',
    'pve a',
    '-node',
    'node-',
    'node.example.com',
    'n'.repeat(64),
    null,
    12,
    'node\nsecret',
  ])
    assert.throws(
      () => validateService({ nodeName }, newService('proxmox')),
      error => !error.message.includes('node\nsecret')
    );
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-pve-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = new ConfigStore(dir);
  config.update('proxmox', { nodeName: 'pve-c', apiKey: 'test-only-token' });
  config.update('proxmox', { name: 'Third node' });
  const loaded = new ConfigStore(dir),
    saved = loaded.get('proxmox');
  assert.equal(saved.nodeName, 'pve-c');
  assert.equal(saved.apiKey, 'test-only-token');
  assert.equal(fs.statSync(path.join(dir, 'config.json')).mode & 0o777, 0o600);
  const publicSource = publicConfig(loaded.value).services.find(s => s.id === 'proxmox');
  assert.equal(publicSource.nodeName, 'pve-c');
  assert.equal(publicSource.apiKeyConfigured, true);
  assert.equal(publicSource.apiKey, undefined);
  assert.ok(!JSON.stringify(publicSource).includes('test-only-token'));
  config.update('proxmox', { nodeName: '' });
  assert.equal(new ConfigStore(dir).get('proxmox').nodeName, '');
});

test('Proxmox node login failure does not expose the API token or upstream response', async t => {
  fixture(t, [], 403);
  await assert.rejects(
    collect(source('pve-a')),
    error =>
      /Authentication failed/.test(error.message) && !error.message.includes('test-only-token')
  );
});

test('Proxmox large clusters keep every storage reading and bound per-guest detail', async t => {
  const nodes = ['pve1', 'pve2', 'pve3'],
    resources = [];
  // Guests are listed newest first so the detail cap must pick the lowest VMIDs itself.
  for (let vmid = 359; vmid >= 100; vmid--)
    resources.push({
      id: 'lxc/' + vmid,
      type: 'lxc',
      node: 'pve1',
      vmid,
      name: 'ct' + vmid,
      status: 'running',
      cpu: 0.01,
      mem: 10,
      uptime: 5,
    });
  for (const node of nodes) {
    resources.push({ id: 'node/' + node, type: 'node', node, status: 'online', cpu: 0.1 });
    for (const storage of ['local', 'local-lvm', 'nfs', 'backup'])
      resources.push({
        id: `storage/${node}/${storage}`,
        type: 'storage',
        node,
        storage,
        disk: 1,
        maxdisk: 2,
      });
  }
  fixture(t, resources);
  for (const nodeName of ['', 'pve1']) {
    const metrics = await collect(source(nodeName)),
      v = values(metrics),
      storages = nodeName ? ['pve1'] : nodes;
    assert.ok(metrics.length <= 512);
    for (const node of storages)
      for (const storage of ['local', 'local-lvm', 'nfs', 'backup']) {
        assert.equal(v[`storage/${node}/${storage}.used`], 1);
        assert.equal(v[`storage/${node}/${storage}.total`], 2);
      }
    const guests = metrics.filter(m => /^lxc\/\d+\.cpu$/.test(m.key));
    assert.equal(guests.length, 128);
    assert.ok(v['lxc/100.cpu'] !== undefined && v['lxc/227.cpu'] !== undefined);
    assert.equal(v['lxc/228.cpu'], undefined);
    assert.equal(v.guests_total, 260);
    assert.equal(v['node/pve1.cpu'], 10);
    // The guests left out of per-guest detail are noted, with their count.
    assert.deepEqual(metrics.notes, [
      {
        code: 'proxmox_guests_capped',
        message:
          'Per-guest readings cover the 128 lowest VMIDs; 132 more guests are counted in the totals but not shown individually.',
        omitted: 132,
      },
    ]);
  }
});

test('Proxmox with 100,000 storages keeps 512 readings and notes the cap, never a stack overflow', async t => {
  // Within the response limits (16 MB, 750,000 JSON values), but two readings a storage spread
  // into one push() overflowed the call stack, and the whole source failed.
  const resources = [{ id: 'node/pve', type: 'node', node: 'pve', status: 'online', cpu: 0.1 }];
  for (let i = 0; i < 100000; i++)
    resources.push({ id: `storage/pve/s${i}`, type: 'storage', node: 'pve', disk: 1, maxdisk: 2 });
  fixture(t, resources);
  for (const nodeName of ['', 'pve']) {
    const metrics = await collect(source(nodeName));
    assert.equal(metrics.length, 512, nodeName);
    assert.ok(
      metrics.notes.some(note => note.code === 'measurements_capped'),
      JSON.stringify(metrics.notes)
    );
  }
});

test('Proxmox cluster totals leave out a node that is not online and its stale readings', async t => {
  const resources = inventory();
  // pve-d dropped out of the cluster but still carries its last capacity and usage.
  resources.find(row => row.type === 'node' && row.node === 'pve-d').status = 'offline';
  fixture(t, resources);
  const metrics = await collect(source('')),
    v = values(metrics);
  // Online nodes pve-a..c: 24 cores (5.6 busy), 1400 of 6000 bytes of memory.
  assert.ok(Math.abs(v.cpu - (5.6 / 24) * 100) < 1e-9, `cpu ${v.cpu}`);
  assert.ok(Math.abs(v.memory - (1400 / 6000) * 100) < 1e-9, `memory ${v.memory}`);
  assert.equal(v.memory_used, 1400);
  assert.equal(v.memory_total, 6000);
  assert.equal(v.nodes_online, 3);
  assert.equal(v.nodes_total, 4);
  assert.equal(v.guests_running, 6);
  assert.equal(v.guests_total, 10);
  assert.ok(
    !metrics.some(
      m =>
        m.key.startsWith('node/pve-d.') ||
        m.key.startsWith('storage/pve-d/') ||
        /^(qemu|lxc)\/4\d\d\./.test(m.key)
    )
  );
  assert.equal(v['node/pve-c.cpu'], 30);
  assert.equal(v['storage/pve-c/local.used'], 150);
});
