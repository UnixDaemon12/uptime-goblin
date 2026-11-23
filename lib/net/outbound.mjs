// The collectors' HTTP client (roadmap §2.10 names this module as the shared outbound client;
// notification channels still use lib/notify/http.mjs). It answers like fetch, so the collectors
// keep their limits, deadlines and error reporting, with one difference that matters: it
// connects only to the addresses the destination policy has just checked
// (lib/destinations.mjs), never to a second answer for the same name. fetch resolved the host
// again by itself, so a short-lived or hostile DNS answer could pass the check with an allowed
// address and then send the connection, with the source's credentials, to loopback or to
// 169.254.169.254.
//
// Otherwise it behaves as Node's fetch did for collectors: the same request headers, Node's TLS
// checks against the host name (certificate and SNI) and default minimum version, the codings it
// asks for decoded (gzip, deflate zlib-wrapped or raw, and brotli; never zstd, see decoders()),
// the Fetch standard's bad ports refused,
// redirects either an error or returned as they are, and failures in fetch's shapes:
// TypeError('fetch failed') with the network error as its cause before an answer, a body stream
// that fails with TypeError('terminated') after one, and the signal's reason when it is aborted.
// A connection serves one request and is closed (no pool), so every connection is a checked one.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';
import { Transform, pipeline } from 'node:stream';

// The ports the Fetch standard refuses ("bad ports"), which Node's fetch refused for collectors
// too: a source on one of them keeps the error it had (invalid source address), and Uptime Goblin does
// not speak HTTP to mail, IRC or other services there.
const BAD_PORTS = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102,
  103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465,
  512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993,
  995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668,
  6669, 6679, 6697, 10080,
]);
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
// Statuses whose answers have no body, as for fetch's Response.
const NO_BODY = new Set([101, 103, 204, 205, 304]);
// At most this many content codings are decoded; a longer chain is passed on undecoded. A real
// server applies one; two covers a proxy that compresses again.
const MAX_CODINGS = 2;
// The most bytes one decoder may hand the next in a chain: the collectors' limits count only
// the final output (at most 64 MB, a Sonarr or Radarr library), so without this a layer whose
// output the next one skips (a gzip member's comment) could feed it until the deadline.
// Compressed data is smaller than what it expands to, so no real body comes near it.
const INTERMEDIATE_LIMIT = 64 * 1024 * 1024;

const failed = cause => new TypeError('fetch failed', { cause });
const noAddress = () =>
  Object.assign(new Error('No checked address to connect to'), { code: 'ENOTFOUND' });

/**
 * dns.lookup's signature, answering with `addresses` (IP addresses the caller checked) whatever
 * name it is asked for: the connection cannot reach any other address.
 */
function pinnedLookup(addresses) {
  return (_hostname, options, callback) => {
    const family = options?.family === 4 || options?.family === 6 ? options.family : 0;
    const list = addresses
      .map(address => ({ address, family: net.isIP(address) }))
      .filter(entry => !family || entry.family === family);
    process.nextTick(() => {
      if (!list.length) callback(noAddress());
      else if (options?.all) callback(null, list);
      else callback(null, list[0].address, list[0].family);
    });
  };
}

// "deflate" is meant to be zlib-wrapped, but some servers send raw deflate, which fetch accepts
// too: the first byte says which (a zlib header has compression method 8 in its low four bits).
// The inflater's output is read only while this stream's reader wants more (push() returning
// false stops it until the next read), and a chunk is taken from upstream only once the
// inflater has consumed the last one, which it does only while its own output is being read.
// So a small compressed chunk that expands to megabytes is inflated as it is read, not all at
// once into memory, as for the native gzip and brotli decoders.
// Defence in depth: should that ever fail, more than INFLATE_BUFFERED bytes of unread output
// fail the body instead of growing without bound.
const INFLATE_BUFFERED = 4 * 1024 * 1024;
function inflate(options) {
  let inner = null,
    wanted = true;
  const pump = () => {
    let data;
    while (inner && wanted && (data = inner.read()) !== null) {
      wanted = decoder.push(data);
      if (decoder.readableLength > INFLATE_BUFFERED) {
        decoder.destroy(new RangeError('Decoded output is not being read'));
        return;
      }
    }
  };
  const decoder = new Transform({
    transform(chunk, _encoding, callback) {
      if (!inner) {
        inner =
          (chunk[0] & 0x0f) === 0x08 ? zlib.createInflate(options) : zlib.createInflateRaw(options);
        inner.on('readable', pump);
        inner.once('error', error => decoder.destroy(error));
      }
      inner.write(chunk, () => callback());
    },
    flush(callback) {
      if (!inner) return callback();
      inner.once('end', () => callback());
      inner.end();
    },
    read(size) {
      wanted = true;
      pump();
      Transform.prototype._read.call(this, size);
    },
    destroy(error, callback) {
      inner?.destroy();
      callback(error);
    },
  });
  return decoder;
}

// Counts what one decoder hands the next and fails past INTERMEDIATE_LIMIT, with a code the
// collectors report as a malformed body (not retried).
function intermediateLimit() {
  let total = 0;
  return new Transform({
    transform(chunk, _encoding, callback) {
      total += chunk.length;
      if (total > INTERMEDIATE_LIMIT)
        return callback(
          Object.assign(new RangeError('Content coding expands beyond its limit'), {
            code: 'ERR_CONTENT_CODING_LIMIT',
          })
        );
      callback(null, chunk);
    },
  });
}

// The decoders for a Content-Encoding header, in the order the body passes through them, or []
// when the body is passed on as it is (no coding, identity, an unknown one, or too many).
// Only the codings Accept-Encoding offers are decoded (gzip, deflate and br; fetchPinned never
// offers br over plain HTTP, but brotli's window is at most 16 MB either way): zstd was never
// asked for, and its decoder allocates the window a frame declares, up to 128 MB per layer for a
// few bytes of input, so an answer coded with it is passed on as it is, like any unknown coding.
// Between two decoders sits a counter (intermediateLimit), so the result is not one stream per
// coding. Exported for the decoder tests.
export function decoders(header) {
  const codings = String(header ?? '')
    .toLowerCase()
    .split(',')
    .map(coding => coding.trim())
    .filter(coding => coding && coding !== 'identity');
  if (!codings.length || codings.length > MAX_CODINGS) return [];
  // Lenient at the end, as fetch is: a body its sender cut short decodes as far as it goes.
  const flush = { flush: zlib.constants.Z_SYNC_FLUSH, finishFlush: zlib.constants.Z_SYNC_FLUSH };
  const made = [];
  for (const coding of codings.reverse()) {
    if (coding === 'gzip' || coding === 'x-gzip') made.push(zlib.createGunzip(flush));
    else if (coding === 'deflate') made.push(inflate(flush));
    else if (coding === 'br')
      made.push(
        zlib.createBrotliDecompress({
          flush: zlib.constants.BROTLI_OPERATION_FLUSH,
          finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH,
        })
      );
    else {
      for (const decoder of made) decoder.destroy();
      return [];
    }
  }
  return made.flatMap((decoder, i) => (i ? [intermediateLimit(), decoder] : [decoder]));
}

/**
 * Sends one request, like fetch(url, init), connecting only to `addresses`, the IP addresses
 * the destination policy checked for the URL's host. init: method, headers (an object), body (a
 * string), signal, and redirect: 'error' refuses a redirect status, 'manual' (the default)
 * returns it; one is never followed.
 * Resolves with {status, statusText, ok, headers (Headers), body (a ReadableStream of bytes, or
 * null), bodyUsed}.
 */
export function fetchPinned(url, init = {}, addresses = []) {
  return new Promise((resolve, reject) => {
    const { method = 'GET', headers = {}, body, signal, redirect = 'manual' } = init;
    let target;
    try {
      target = new URL(url);
    } catch (error) {
      return reject(failed(error));
    }
    const secure = target.protocol === 'https:';
    if (!secure && target.protocol !== 'http:')
      return reject(failed(Object.assign(new Error('scheme'), { code: 'ERR_INVALID_URL' })));
    const port = Number(target.port || (secure ? 443 : 80));
    if (BAD_PORTS.has(port)) return reject(failed(new Error('bad port')));
    if (!addresses.length || !addresses.every(address => net.isIP(address)))
      return reject(failed(noAddress()));
    if (signal?.aborted) return reject(signal.reason);
    // Checked here, as fetch did: a line break in a credential is a TypeError, whose message
    // (Node's) names the header but never its value.
    const outgoing = {};
    for (const [name, value] of Object.entries(headers)) {
      http.validateHeaderName(name);
      http.validateHeaderValue(name, String(value));
      outgoing[name] = String(value);
    }
    // What fetch adds when the caller does not say.
    const given = new Set(Object.keys(outgoing).map(name => name.toLowerCase()));
    for (const [name, value] of [
      ['Accept', '*/*'],
      ['Accept-Language', '*'],
      ['Sec-Fetch-Mode', 'cors'],
      ['User-Agent', 'node'],
      ['Accept-Encoding', secure ? 'gzip, deflate, br' : 'gzip, deflate'],
    ])
      if (!given.has(name.toLowerCase())) outgoing[name] = value;
    const payload = body === undefined || body === null ? null : Buffer.from(String(body));
    if (payload) outgoing['Content-Length'] = String(payload.length);

    let request,
      settled = false,
      // Set once the answer has a body: ends that body with an error.
      fail = null;
    const onAbort = () => (fail ? fail(signal.reason) : finish(signal.reason));
    // Settles the promise once; an error before the answer ends the connection too.
    function finish(error, response) {
      if (settled) return;
      settled = true;
      if (!error) return resolve(response);
      signal?.removeEventListener('abort', onAbort);
      request?.destroy();
      reject(error);
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      request = (secure ? https : http).request({
        protocol: target.protocol,
        hostname: target.hostname.replace(/^\[|\]$/g, ''),
        port,
        path: target.pathname + target.search,
        method,
        headers: outgoing,
        agent: false,
        // Asked only for a host name: an IP literal is used as it is (it is what was checked).
        lookup: pinnedLookup(addresses),
      });
    } catch (error) {
      return finish(failed(error));
    }
    request.on('error', error => {
      // Once the answer began, its body fails with this (a parser error mid-body, say), which
      // arrives before the response notices that the connection is gone.
      if (fail) fail(new TypeError('terminated', { cause: error }));
      else finish(failed(error));
    });
    // Node gives a 101 Switching Protocols answer as 'upgrade', never as 'response', and with no
    // listener destroys the socket emitting neither that nor an error: the promise waited for
    // the signal (a time-out blamed on the source, retried until the deadline) or, without one,
    // for ever. fetch failed at once, as an interrupted connection; so does this.
    request.on('upgrade', (response, socket) => {
      socket.destroy();
      finish(failed(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })));
    });
    request.on('response', response => {
      const status = response.statusCode;
      if (redirect === 'error' && REDIRECTS.has(status))
        return finish(failed(new Error('unexpected redirect')));
      let received;
      try {
        received = new Headers();
        const raw = response.rawHeaders;
        for (let i = 0; i + 1 < raw.length; i += 2) received.append(raw[i], raw[i + 1]);
      } catch (error) {
        return finish(failed(error));
      }
      let stream = null;
      if (method === 'HEAD' || NO_BODY.has(status) || status < 200) {
        signal?.removeEventListener('abort', onAbort);
        response.resume();
        response.once('end', () => request.destroy());
      } else stream = bodyStream(response, received.get('content-encoding'));
      finish(null, {
        status,
        statusText: response.statusMessage ?? '',
        ok: status >= 200 && status < 300,
        redirected: false,
        url: target.href,
        headers: received,
        body: stream,
        get bodyUsed() {
          return Boolean(stream?.locked);
        },
      });
    });

    // The body as a ReadableStream of bytes, decoded and read as it is pulled (a paused response
    // holds the sender back). It ends once: complete, or with the first failure (the connection,
    // a decoder, the request's own error or the signal).
    function bodyStream(response, encoding) {
      const chain = decoders(encoding),
        source = chain.length ? pipeline(response, ...chain, () => {}) : response;
      let controller,
        done = false;
      const close = () => {
        signal?.removeEventListener('abort', onAbort);
        for (const part of chain) part.destroy();
        response.destroy();
        request.destroy();
      };
      const terminated = cause => new TypeError('terminated', { cause });
      fail = error => {
        if (done) return;
        done = true;
        close();
        controller.error(signal?.aborted ? signal.reason : error);
      };
      return new ReadableStream({
        start(c) {
          controller = c;
          source.on('data', chunk => {
            if (done) return;
            controller.enqueue(new Uint8Array(chunk));
            if (controller.desiredSize <= 0) source.pause();
          });
          source.once('end', () => {
            if (done) return;
            done = true;
            close();
            controller.close();
          });
          for (const part of new Set([response, ...chain, source]))
            part.on('error', error => fail(terminated(error)));
          // A connection that closes before the whole body arrived, without an error of its own.
          response.once('close', () => {
            if (!response.complete)
              fail(terminated(Object.assign(new Error('aborted'), { code: 'ECONNRESET' })));
          });
        },
        pull() {
          source.resume();
        },
        cancel() {
          done = true;
          close();
        },
      });
    }

    request.end(payload ?? undefined);
  });
}
