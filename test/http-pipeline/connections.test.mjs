// Each client's share of the listener's connections (GOBLIN_MAX_CONNECTIONS_PER_CLIENT, 32 by
// default): a client, its peer address (an IPv6 one by its /64), holds at most that many
// connections at once, so one client cannot take all 256 of the listener and lock everyone else
// out. One more is closed at once, unanswered, and the log says so at most once a minute. A proxy
// named in GOBLIN_TRUST_PROXY carries the connections of many clients: it is held only to the
// listener's own cap.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import {
  connectionsPerClient,
  limitConnectionsPerClient,
  serverLimits,
} from '../../lib/http/pipeline.mjs';
import { trustedProxies } from '../../lib/throttle.mjs';
import { startReal } from './harness.mjs';

// Opens a connection to Uptime Goblin and starts a request for /health on it without ending its headers,
// so the connection stays busy: Node closes an idle one after 5 seconds (its keep-alive limit),
// which could free a place before the test asks for one more, but gives a request 20 seconds for
// its headers (serverLimits.headersTimeoutMs). Resolves once connected to {socket, closed(),
// finish()}: finish() ends the headers and resolves true when Uptime Goblin answers 200, false when it
// closed the connection without an answer.
function pending(t, port, address = '127.0.0.1') {
  const host = net.isIPv6(address) ? `[${address}]:${port}` : `${address}:${port}`;
  return new Promise(resolve => {
    const socket = net.connect(port, address);
    t.after(() => socket.destroy());
    let data = '',
      closed = false;
    const answered = new Promise(done => {
      socket.on('data', chunk => {
        data += chunk;
        if (/^HTTP\/1\.1 200 /.test(data)) done(true);
      });
      socket.on('close', () => {
        closed = true;
        done(false);
      });
    });
    socket.on('error', () => {});
    socket.once('connect', () => {
      socket.write(`GET /health HTTP/1.1\r\nHost: ${host}\r\n`);
      resolve({
        socket,
        closed: () => closed,
        finish() {
          if (!closed) socket.write('\r\n');
          return answered;
        },
      });
    });
  });
}

// Opens `count` busy connections one after the other.
async function openMany(t, port, count, address) {
  const held = [];
  for (let i = 0; i < count; i++) held.push(await pending(t, port, address));
  return held;
}

// Each of `held` is still open, then each is answered once its request is ended: all of them
// were accepted and held at once.
async function allHeld(held) {
  assert.deepEqual(
    held.map(entry => entry.closed()),
    Array(held.length).fill(false),
    'every held connection is still open'
  );
  return (await Promise.all(held.map(entry => entry.finish()))).every(Boolean);
}

// Once a held connection is closed, its place is free again as soon as Uptime Goblin has seen the close.
async function freedPlace(t, port, address) {
  const end = Date.now() + 5000;
  for (;;) {
    const answered = await (await pending(t, port, address)).finish();
    if (answered || Date.now() > end) return answered;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

// The line Uptime Goblin writes when the share closed connections (at most one a minute).
const shareLine = (count, limit, client) =>
  `Uptime Goblin closed ${count === 1 ? 'a connection' : `${count} connections`} without an answer since the last such line (or the start) because the client already held ${limit} connections at once, one client's share (GOBLIN_MAX_CONNECTIONS_PER_CLIENT); the last came from ${client}. Where many browsers or scripts reach Uptime Goblin from one address (a reverse proxy, Docker's gateway, this computer), name the proxy in GOBLIN_TRUST_PROXY or raise GOBLIN_MAX_CONNECTIONS_PER_CLIENT.`;

test('one client holds at most 32 connections by default; one more is closed unanswered, and a closed one frees its place', async t => {
  assert.equal(serverLimits.maxConnectionsPerClient, 32);
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const { app, port } = await startReal(t);
  assert.equal(app.server.maxConnections, serverLimits.maxConnections);
  const held = await openMany(t, port, 32);
  const refused = await pending(t, port);
  assert.equal(await refused.finish(), false, 'the 33rd connection is closed without an answer');
  assert.equal(await allHeld(held), true, 'the 32 were held at once and are answered');
  held[0].socket.destroy();
  assert.equal(await freedPlace(t, port), true);
  // The log says why, once, naming the client: never anything the connection sent.
  assert.deepEqual(
    warnings.filter(line => line.startsWith('Uptime Goblin closed')),
    [shareLine(1, 32, '127.0.0.1')]
  );
});

test('GOBLIN_MAX_CONNECTIONS_PER_CLIENT sets the share, also over IPv6; a proxy GOBLIN_TRUST_PROXY names has none', async t => {
  const saved = process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT;
  process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT = '8';
  t.after(() => {
    if (saved === undefined) delete process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT;
    else process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT = saved;
  });
  t.mock.method(console, 'warn', () => {});
  for (const address of ['127.0.0.1', '::1']) {
    const { port } = await startReal(t, { host: address });
    const held = await openMany(t, port, 8, address);
    assert.equal(await (await pending(t, port, address)).finish(), false, address);
    assert.equal(await allHeld(held), true, address);
  }
  // The loopback proxy carries every client behind it: 12 connections from it are all held.
  const { port } = await startReal(t, { trustProxy: 'loopback' });
  assert.equal(await allHeld(await openMany(t, port, 12)), true);
});

// A trusted proxy has no share, but every connection counts toward the listener's own cap
// (serverLimits.maxConnections, 256, which applyServerLimits() sets as server.maxConnections):
// one more than the cap is closed too. A small cap set on the running server stands in for 256.
test('a proxy GOBLIN_TRUST_PROXY names is held to the listener’s cap: one more connection is closed', async t => {
  const saved = process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT;
  process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT = '8';
  t.after(() => {
    if (saved === undefined) delete process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT;
    else process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT = saved;
  });
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const { app, port } = await startReal(t, { trustProxy: 'loopback' });
  assert.equal(app.server.maxConnections, serverLimits.maxConnections);
  app.server.maxConnections = 10;
  // More than its share of 8, up to the cap.
  const held = await openMany(t, port, 10);
  assert.equal(await (await pending(t, port)).finish(), false, 'the 11th is closed');
  assert.equal(await allHeld(held), true);
  held[0].socket.destroy();
  assert.equal(await freedPlace(t, port), true);
  // The share closed nothing, so it wrote nothing.
  assert.deepEqual(
    warnings.filter(line => line.startsWith('Uptime Goblin closed')),
    []
  );
});

// A connection as limitConnectionsPerClient sees it: a peer address, and a close.
class Peer extends EventEmitter {
  constructor(remoteAddress) {
    super();
    this.remoteAddress = remoteAddress;
    this.destroyed = false;
  }
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    process.nextTick(() => this.emit('close'));
  }
}

test('a client is its peer address, an IPv6 one by its /64 and an IPv4-mapped one as IPv4, never a header', async () => {
  const server = new EventEmitter();
  limitConnectionsPerClient(server, { limit: 2, trusted: trustedProxies('192.0.2.1') });
  const connect = address => {
    const peer = new Peer(address);
    server.emit('connection', peer);
    return peer;
  };
  const open = [connect('2001:db8:1:2::1'), connect('2001:db8:1:2::ffff')];
  assert.equal(connect('2001:db8:1:2:abcd::9').destroyed, true, 'the same /64');
  assert.equal(connect('2001:db8:1:3::1').destroyed, false, 'another /64');
  assert.equal(connect('198.51.100.7').destroyed, false);
  assert.equal(connect('::ffff:198.51.100.7').destroyed, false);
  assert.equal(connect('198.51.100.7').destroyed, true, 'IPv4-mapped is the same client');
  // A trusted proxy is held to no share.
  for (let i = 0; i < 5; i++) assert.equal(connect('192.0.2.1').destroyed, false);
  assert.equal(connect('::ffff:192.0.2.1').destroyed, false);
  // A connection whose peer is unknown (it already went) is closed.
  assert.equal(connect(undefined).destroyed, true);
  // A closed connection frees its place once.
  open[0].destroy();
  await new Promise(resolve => process.nextTick(resolve));
  assert.equal(connect('2001:db8:1:2::2').destroyed, false);
  assert.equal(connect('2001:db8:1:2::3').destroyed, true);
});

test('GOBLIN_MAX_CONNECTIONS_PER_CLIENT takes a whole number from 8 to 256; empty is 32; anything else refuses', () => {
  for (const value of [undefined, null, '']) assert.equal(connectionsPerClient(value), 32);
  assert.equal(connectionsPerClient('8'), 8);
  assert.equal(connectionsPerClient('64'), 64);
  assert.equal(connectionsPerClient('256'), serverLimits.maxConnections);
  assert.equal(connectionsPerClient(100), 100);
  for (const value of [
    '0',
    '7',
    '257',
    '1000',
    '032',
    '32.0',
    ' 32',
    '32 ',
    '+32',
    '-1',
    '1e2',
    '0x20',
    'abc',
    'none',
    7,
    257,
    32.5,
  ])
    assert.throws(
      () => connectionsPerClient(value),
      error =>
        error.refusal === true &&
        error.message.startsWith(
          'GOBLIN_MAX_CONNECTIONS_PER_CLIENT must be a whole number from 8 to 256, written in digits without a leading zero (empty for the default, 32); it is "'
        ),
      String(value)
    );
  // Shown escaped and cut, never raw: the value could forge a log line.
  assert.throws(
    () => connectionsPerClient('32\n[orbit] FORGED'),
    error => !/[\u0000-\u001f]/.test(error.message) && /\\n/.test(error.message)
  );
});

// So that a full share can be told from a network fault: one line, at most once a minute for all
// clients together, naming the last client refused and how many connections were closed since
// the previous line.
test('a connection the share closes is logged at most once a minute in all, with the client and the count since the last line', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let now = 1000;
  const lines = [];
  const server = new EventEmitter();
  limitConnectionsPerClient(server, {
    limit: 2,
    trusted: trustedProxies('192.0.2.1'),
    log: { warn: line => lines.push(line) },
    now: () => now,
  });
  const connect = address => {
    const peer = new Peer(address);
    server.emit('connection', peer);
    return peer;
  };
  for (const address of ['198.51.100.7', '198.51.100.7', '2001:db8:1:2::1', '2001:db8:1:2::2'])
    assert.equal(connect(address).destroyed, false);
  assert.equal(connect('198.51.100.7').destroyed, true);
  assert.deepEqual(lines, [shareLine(1, 2, '198.51.100.7')]);
  // Within the minute: closed, counted, not written, whoever it is.
  now += 59e3;
  assert.equal(connect('2001:db8:1:2::3').destroyed, true);
  assert.equal(connect('198.51.100.7').destroyed, true);
  assert.equal(lines.length, 1);
  // A trusted proxy is never refused, so never counted.
  for (let i = 0; i < 5; i++) assert.equal(connect('192.0.2.1').destroyed, false);
  // A minute after the last line: the next refusal writes one, counting itself and the two
  // before it, and naming its own client (an IPv6 one by its /64).
  now += 1e3;
  assert.equal(connect('2001:db8:1:2::4').destroyed, true);
  assert.deepEqual(lines, [
    shareLine(1, 2, '198.51.100.7'),
    shareLine(3, 2, '2001:0db8:0001:0002::/64'),
  ]);
  // That line cleared the timer the two within the minute armed: it writes nothing more.
  t.mock.timers.tick(60e3);
  assert.equal(lines.length, 2);
  // A log that throws does not keep the connection open.
  const quiet = new EventEmitter();
  limitConnectionsPerClient(quiet, {
    limit: 1,
    log: {
      warn() {
        throw new Error('the log is gone');
      },
    },
  });
  quiet.emit('connection', new Peer('203.0.113.9'));
  const refused = new Peer('203.0.113.9');
  quiet.emit('connection', refused);
  assert.equal(refused.destroyed, true);
});

// A burst within the minute after a line, with nothing after it, is still reported: once the
// minute has passed, a timer writes the count, naming the last client refused. A wall-clock step
// plays no part (the clock is monotonic), and a server that closed writes nothing more.
test('connections the share closes within the minute after a line are written once the minute has passed, even when none follows', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let now = 5000;
  const lines = [];
  const server = new EventEmitter();
  limitConnectionsPerClient(server, {
    limit: 1,
    log: { warn: line => lines.push(line) },
    now: () => now,
  });
  const connect = address => {
    const peer = new Peer(address);
    server.emit('connection', peer);
    return peer;
  };
  connect('198.51.100.7');
  connect('203.0.113.9');
  assert.equal(connect('198.51.100.7').destroyed, true);
  assert.deepEqual(lines, [shareLine(1, 1, '198.51.100.7')]);
  now += 10e3;
  t.mock.timers.tick(10e3);
  for (let i = 0; i < 4; i++) assert.equal(connect('198.51.100.7').destroyed, true);
  assert.equal(connect('203.0.113.9').destroyed, true);
  assert.equal(lines.length, 1, 'not within the minute');
  now += 49e3;
  t.mock.timers.tick(49e3);
  assert.equal(lines.length, 1, 'still within the minute');
  now += 1e3;
  t.mock.timers.tick(1e3);
  assert.deepEqual(lines, [shareLine(1, 1, '198.51.100.7'), shareLine(5, 1, '203.0.113.9')]);
  // Nothing more was closed: no further line, however long.
  now += 600e3;
  t.mock.timers.tick(600e3);
  assert.equal(lines.length, 2);
  // Long after the last line, a refusal is written at once; one within the minute after it is
  // counted, and once the server closed it is never written.
  assert.equal(connect('203.0.113.9').destroyed, true);
  assert.equal(lines.length, 3);
  now += 1e3;
  t.mock.timers.tick(1e3);
  assert.equal(connect('203.0.113.9').destroyed, true);
  assert.equal(lines.length, 3);
  server.emit('close');
  now += 60e3;
  t.mock.timers.tick(60e3);
  assert.equal(lines.length, 3);
});

// The minute is measured on a monotonic clock: the wall clock stepping back (NTP) does not hold
// the next line back until it has caught up.
test('the share’s log line keeps its minute when the wall clock steps back', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: Date.UTC(2026, 10, 12, 8) });
  const lines = [];
  const server = new EventEmitter();
  limitConnectionsPerClient(server, { limit: 1, log: { warn: line => lines.push(line) } });
  server.emit('connection', new Peer('198.51.100.7'));
  server.emit('connection', new Peer('198.51.100.7'));
  assert.equal(lines.length, 1);
  t.mock.timers.setTime(Date.UTC(2026, 10, 12, 7));
  server.emit('connection', new Peer('198.51.100.7'));
  t.mock.timers.tick(60e3);
  assert.deepEqual(lines.at(-1), shareLine(1, 1, '198.51.100.7'));
  assert.equal(lines.length, 2);
});
