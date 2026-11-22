// A webhook receiver for delivery tests (delivery spec §2.1 item 10; frozen once the lanes use
// it): an HTTP server on 127.0.0.1 that records every request and answers as the test says.
//
//   const hook = await webhookReceiver(t, {respond: (request, n) => (n === 1 ? 500 : 200)});
//   createApp({webhook: hook.url, …});
//   await hook.waitFor(2);
//
// respond(request, n) (n counts from 1) returns, or resolves to:
//   a status (default 200) · {status, headers, body} · {status, afterMs} (answer after a delay,
//   as a receiver that does its work first) · 'hold' (read the body and never answer, until
//   release()).
// Each request is recorded as {method, url, headers, body, receivedAt} (receivedAt: Date.now()).
import http from 'node:http';

export async function webhookReceiver(t, { respond = () => 200, path = '/hook' } = {}) {
  const requests = [],
    held = new Set(),
    sockets = new Set(),
    waiters = [];
  const notify = () => {
    for (const waiter of [...waiters])
      if (requests.length >= waiter.count) {
        waiters.splice(waiters.indexOf(waiter), 1);
        clearTimeout(waiter.timer);
        waiter.resolve(requests.slice(0, waiter.count));
      }
  };
  const answer = (res, { status = 200, headers = {}, body = '' } = {}) => {
    if (res.destroyed || res.headersSent) return;
    res.writeHead(status, headers);
    res.end(body);
  };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    try {
      for await (const chunk of req) chunks.push(chunk);
    } catch {
      return; // the sender gave up mid-body
    }
    const request = {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
      receivedAt: Date.now(),
    };
    requests.push(request);
    let reply;
    try {
      reply = await respond(request, requests.length);
    } catch {
      reply = 500;
    }
    if (reply === 'hold') {
      held.add(res);
      res.on('close', () => held.delete(res));
    }
    // Waiters see the request once its answer is decided (a held one is held by then).
    notify();
    if (reply === 'hold') return;
    const options = typeof reply === 'number' ? { status: reply } : (reply ?? {});
    if (options.afterMs > 0) {
      const timer = setTimeout(() => answer(res, options), options.afterMs);
      res.on('close', () => clearTimeout(timer));
    } else answer(res, options);
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const close = () =>
    new Promise(resolve => {
      for (const waiter of waiters.splice(0)) clearTimeout(waiter.timer);
      for (const socket of sockets) socket.destroy();
      server.close(() => resolve());
    });
  t?.after?.(close);
  return {
    port,
    base: `http://127.0.0.1:${port}`,
    url: `http://127.0.0.1:${port}${path}`,
    requests,
    /** The parsed JSON bodies, in arrival order. */
    bodies: () => requests.map(request => JSON.parse(request.body)),
    /** How many requests carried each X-Goblin-Delivery value (X-Orbit-Delivery from a release before 1.5). */
    deliveries() {
      const counts = new Map();
      for (const request of requests) {
        const id =
          request.headers['x-goblin-delivery'] ?? request.headers['x-orbit-delivery'] ?? null;
        counts.set(id, (counts.get(id) ?? 0) + 1);
      }
      return counts;
    },
    /** Answers every held request (default 200). */
    release(reply = 200) {
      const options = typeof reply === 'number' ? { status: reply } : reply;
      for (const res of [...held]) {
        held.delete(res);
        answer(res, options);
      }
    },
    get held() {
      return held.size;
    },
    /** Resolves with the first `count` requests once they arrived; rejects after timeoutMs. */
    waitFor(count, { timeoutMs = 10000 } = {}) {
      if (requests.length >= count) return Promise.resolve(requests.slice(0, count));
      return new Promise((resolve, reject) => {
        const waiter = { count, resolve };
        waiter.timer = setTimeout(() => {
          waiters.splice(waiters.indexOf(waiter), 1);
          reject(
            new Error(`The webhook receiver got ${requests.length} of ${count} requests in time.`)
          );
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    close,
  };
}
