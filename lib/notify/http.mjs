// The outbound HTTP client for notification channels (alerting design §6 T1; roadmap §2.10
// names its later home lib/net/outbound.mjs). Every request:
// - applies an address policy to every resolved address inside the connection's `lookup`, and
//   to an IP literal before connecting, so there is no gap between checking and connecting;
// - never follows redirects, uses no shared agent, verifies TLS 1.2+ (private CAs through
//   NODE_EXTRA_CA_CERTS, or `ca` in tests), and caps the request and the response it reads;
// - has one deadline for the whole exchange, and reports the phase it reached, so a caller can
//   tell "nothing was sent" (retry) from "sent, no answer" (acceptance unknown); an answer whose
//   status line arrived counts, however its body ends (cut by the deadline, a cancellation or
//   the connection).
// Errors carry a fixed message by code and never the URL, which may hold a secret.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';

export class OutboundError extends Error {
  constructor(code, message, { phase = 'resolve', cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'OutboundError';
    this.code = code;
    this.phase = phase;
  }
  /** True when the request may have reached the server in full (its acceptance is unknown). */
  get sent() {
    return this.phase === 'await' || this.phase === 'response';
  }
}

const TLS_CODES =
  /^(?:ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|ERR_CERT|HOSTNAME_MISMATCH)/;

export function describeNetworkError(code) {
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_NONAME')
    return 'The host name could not be resolved.';
  if (code === 'ECONNREFUSED') return 'The server refused the connection.';
  if (code === 'ECONNRESET' || code === 'EPIPE') return 'The connection was reset.';
  if (code === 'ETIMEDOUT') return 'The request timed out.';
  if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') return 'The server could not be reached.';
  if (TLS_CODES.test(code ?? ''))
    return "The server's TLS certificate is not trusted. Check the address, or add its CA with NODE_EXTRA_CA_CERTS.";
  return `The request failed${/^[A-Z0-9_]{2,40}$/.test(code ?? '') ? ` (${code})` : ''}.`;
}

export const isTlsError = error => TLS_CODES.test(error?.code ?? '');

/**
 * post(url, body, options) -> Promise<{status, headers, body: Buffer, truncated}>, or rejects
 * with OutboundError. Options: headers, timeoutMs (8 s), signal, addressPolicy(address) ->
 * reason | null (async), lookup (dns.lookup's signature), maxRequestBytes and
 * maxResponseBytes (64 KiB each), ca. Once the status line is in, the deadline and the signal
 * resolve with the answer read so far (`truncated: true`) instead of rejecting.
 */
export function post(url, body, options = {}) {
  const {
    headers = {},
    timeoutMs = 8000,
    signal,
    addressPolicy = async () => null,
    lookup = dns.lookup,
    maxRequestBytes = 65536,
    maxResponseBytes = 65536,
    ca,
  } = options;
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = url instanceof URL ? url : new URL(url);
    } catch {
      return reject(new OutboundError('EURL', 'The URL is not valid.'));
    }
    const secure = target.protocol === 'https:';
    if (!secure && target.protocol !== 'http:')
      return reject(new OutboundError('EURL', 'Only http: and https: URLs are supported.'));
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''), 'utf8');
    if (payload.length > maxRequestBytes)
      return reject(new OutboundError('ETOOLARGE', 'The message is too large to send.'));
    const host = target.hostname.replace(/^\[|\]$/g, '');
    let phase = 'resolve',
      request = null,
      settled = false,
      timer = null,
      // Set once the status line is in: ends the exchange with the answer read so far.
      cutShort = null;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve(value);
    };
    const fail = (code, message, cause) => {
      // The status is known: the deadline, a cancellation or a lost connection while the body is
      // read does not change it. A receiver that answers 200 at once and ends its body later (or
      // never, on a connection it keeps open) has accepted; reporting a timeout instead made the
      // caller resend an alert the receiver already took, and count it as a failure.
      if (cutShort) return cutShort();
      const error =
        cause instanceof OutboundError ? cause : new OutboundError(code, message, { phase, cause });
      request?.destroy();
      finish(error);
    };
    const onAbort = () => fail('EABORTED', 'The request was cancelled.');
    if (signal?.aborted) return fail('EABORTED', 'The request was cancelled.');
    signal?.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(() => fail('ETIMEDOUT', 'The request timed out.'), timeoutMs);

    // Called by net.connect for a host name: every address must pass the policy.
    const guardedLookup = (hostname, lookupOptions, callback) => {
      lookup(hostname, { ...lookupOptions, all: true }, async (error, addresses) => {
        if (error) return callback(error);
        try {
          const list = Array.isArray(addresses) ? addresses : [{ address: addresses }];
          if (!list.length)
            return callback(Object.assign(new Error('no address'), { code: 'ENOTFOUND' }));
          for (const { address } of list) {
            const reason = await addressPolicy(address);
            if (reason) return callback(new OutboundError('EPOLICY', reason, { phase: 'resolve' }));
          }
          const normalised = list.map(({ address, family }) => ({
            address,
            family: family ?? net.isIP(address),
          }));
          if (lookupOptions?.all) callback(null, normalised);
          else callback(null, normalised[0].address, normalised[0].family);
        } catch (policyError) {
          callback(policyError);
        }
      });
    };

    const start = async () => {
      if (net.isIP(host)) {
        const reason = await addressPolicy(host);
        if (reason) return fail('EPOLICY', reason, new OutboundError('EPOLICY', reason));
      }
      if (settled) return;
      request = (secure ? https : http).request({
        protocol: target.protocol,
        hostname: host,
        port: target.port || undefined,
        path: `${target.pathname}${target.search}`,
        method: 'POST',
        headers: { ...headers, 'Content-Length': String(payload.length) },
        agent: false,
        ...(net.isIP(host) ? {} : { lookup: guardedLookup }),
        ...(secure
          ? {
              rejectUnauthorized: true,
              minVersion: 'TLSv1.2',
              ...(net.isIP(host) ? {} : { servername: host }),
              ...(ca ? { ca } : {}),
            }
          : {}),
      });
      request.on('socket', socket => {
        socket.once(secure ? 'secureConnect' : 'connect', () => {
          if (phase === 'resolve' || phase === 'connect') phase = 'send';
        });
        socket.once('lookup', () => {
          if (phase === 'resolve') phase = 'connect';
        });
      });
      // The whole body has been handed to the operating system: from here the server may act on it.
      request.on('finish', () => {
        if (phase !== 'response') phase = 'await';
      });
      request.on('error', error =>
        fail(error?.code ?? 'ENETWORK', describeNetworkError(error?.code), error)
      );
      request.on('response', response => {
        phase = 'response';
        const chunks = [];
        let size = 0,
          truncated = false;
        const done = () => {
          finish(null, {
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks),
            truncated,
          });
          request.destroy();
        };
        cutShort = () => {
          truncated = true;
          done();
        };
        response.on('data', chunk => {
          if (truncated) return;
          const room = maxResponseBytes - size;
          if (chunk.length > room) {
            chunks.push(chunk.subarray(0, room));
            size = maxResponseBytes;
            truncated = true;
            done();
            return;
          }
          chunks.push(chunk);
          size += chunk.length;
        });
        response.on('end', done);
        // The status is known; a connection lost while reading the body does not change it.
        response.on('error', cutShort);
        response.on('aborted', cutShort);
      });
      request.end(payload);
    };
    start().catch(error => fail('ENETWORK', describeNetworkError(error?.code), error));
  });
}
