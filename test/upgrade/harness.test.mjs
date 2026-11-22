// The upgrade harness itself (test/upgrade/harness.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { freePort } from './harness.mjs';

// The range the OS hands out for listen(0) and for outgoing connections, or null when unknown.
function ephemeralRange() {
  try {
    const [low, high] = fs
      .readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8')
      .trim()
      .split(/\s+/)
      .map(Number);
    if (low > 0 && high >= low) return [low, high];
  } catch {}
  const read = name =>
    Number(spawnSync('sysctl', ['-n', name], { encoding: 'utf8' }).stdout?.trim() ?? NaN);
  const low = read('net.inet.ip.portrange.first'),
    high = read('net.inet.ip.portrange.last');
  return low > 0 && high >= low ? [low, high] : null;
}

// Integration (audit milestone): the ports freePort() returned came from listen(0), so another
// test file's outgoing connection could take one between freePort() closing it and the server
// listening, and that start failed with EADDRINUSE (delivery F4 in the Node 24 container).
test('freePort returns free loopback ports outside the range the OS hands out to connections', async t => {
  const range = ephemeralRange();
  if (!range) return t.skip('this OS does not say which ports it hands out');
  for (let i = 0; i < 20; i++) {
    const port = await freePort();
    assert.ok(
      port < range[0] || port > range[1],
      `${port} is in the OS's range ${range.join('-')}, where a connection can take it`
    );
    const server = net.createServer();
    await new Promise((resolve, reject) =>
      server.once('error', reject).listen({ port, host: '127.0.0.1', exclusive: true }, resolve)
    );
    await new Promise(resolve => server.close(resolve));
  }
});
