// Network faults for restart and stall tests, on loopback only.
import http from 'node:http';
import net from 'node:net';
import { spawnSync } from 'node:child_process';

/**
 * A loopback port free at this moment, as PORT for a spawned Uptime Goblin: PORT=0 is refused (only
 * createApp's own `port` option may be 0). Synchronous, so a spawn helper can call it as it
 * builds the environment. Another process could take the port in the moment between, as with
 * any such helper; the system hands out free ports in turn, so a clash is unlikely.
 */
export function freePortSync() {
  const found = spawnSync(
    process.execPath,
    [
      '-e',
      "const s = require('node:net').createServer(); s.listen(0, '127.0.0.1', () => { process.stdout.write(String(s.address().port)); s.close(); });",
    ],
    { encoding: 'utf8', timeout: 10000 }
  );
  if (!/^[1-9][0-9]{0,4}$/.test(found.stdout ?? ''))
    throw new Error(`No free port: ${found.stderr || found.error}`);
  return found.stdout;
}

/**
 * A TCP server that accepts connections and reads requests but never answers, like a host
 * that stopped responding. stopListening() frees the port for a real Uptime Goblin while the
 * connections already open stay open and silent; close() drops them.
 */
export async function silentServer(port = 0) {
  const sockets = new Set(),
    counts = { accepted: 0 };
  const server = net.createServer(socket => {
    counts.accepted++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    socket.resume();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    port: server.address().port,
    sockets,
    /** Connections accepted so far. */
    get accepted() {
      return counts.accepted;
    },
    async stopListening() {
      // close() stops listening at once; its callback would wait for every connection.
      server.close();
      await new Promise(resolve => setImmediate(resolve));
    },
    close() {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

/**
 * An HTTP proxy in front of Uptime Goblin (Uptime Goblin must allow its Host, 127.0.0.1:<proxy port>).
 * Each request is buffered and recorded in `requests` as {method, path, headers, body}, then
 * `decide(request)` chooses: 'forward' (the default), 'hold' (never forwarded, never
 * answered), 'swallow' (forwarded, but Uptime Goblin's answer is never passed on: a lost response),
 * or an object {status, headers, body} to answer without Uptime Goblin. `request.answered` resolves
 * with Uptime Goblin's response once it arrives. `target()` gives Uptime Goblin's port, so Uptime Goblin may restart.
 */
export async function httpProxy({ target, decide = () => 'forward' }) {
  const requests = [],
    held = new Set();
  const keep = res => {
    held.add(res);
    res.on('close', () => held.delete(res));
  };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    let answered;
    const request = {
      method: req.method,
      path: req.url,
      headers: { ...req.headers },
      body: body.toString(),
      answered: new Promise(resolve => (answered = resolve)),
    };
    requests.push(request);
    const decision = (await decide(request)) || 'forward';
    if (typeof decision === 'object') {
      res.writeHead(decision.status ?? 200, decision.headers ?? {});
      res.end(decision.body ?? '');
      return;
    }
    if (decision === 'hold') {
      keep(res);
      return;
    }
    const headers = { ...req.headers };
    for (const name of ['connection', 'keep-alive', 'transfer-encoding']) delete headers[name];
    if (body.length) headers['content-length'] = String(body.length);
    const upstream = http.request(
      {
        host: '127.0.0.1',
        port: target(),
        method: req.method,
        path: req.url,
        headers,
        agent: false,
      },
      response => {
        const parts = [];
        response.on('data', chunk => parts.push(chunk));
        response.on('end', () => {
          const content = Buffer.concat(parts);
          request.response = {
            status: response.statusCode,
            headers: response.headers,
            body: content.toString(),
          };
          answered(request.response);
          if (decision === 'swallow') {
            keep(res);
            return;
          }
          const back = { ...response.headers };
          for (const name of ['connection', 'keep-alive', 'transfer-encoding']) delete back[name];
          back['content-length'] = String(content.length);
          res.writeHead(response.statusCode, back);
          res.end(content);
        });
      }
    );
    upstream.on('error', () => res.destroy());
    upstream.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    close() {
      for (const res of held) res.destroy();
      server.closeAllConnections();
      server.close();
    },
  };
}
