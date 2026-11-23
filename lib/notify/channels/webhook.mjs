// The built-in environment webhook channel (GOBLIN_WEBHOOK_URL). The body is exactly 1.4.2's
// ({source: 'orbit', ...event}, one POST per event, 8 s deadline, redirects not followed). New
// in 1.5, all additive: X-Goblin-Delivery (stable across retries), X-Goblin-Signature (Ed25519
// over the delivery id, the time and the body, with the private keys `signingKeys()` returns at
// each send),
// the address rule of address-policy.mjs, and a classification the outbox acts on:
//   2xx accepted · 408, 425, 429, 5xx and network errors retry (honouring Retry-After) ·
//   401, 403, 404, 410, redirects and an untrusted certificate pause the channel, transiently
//   (a proxy restarting or a certificate being renewed: probed every 15 minutes) ·
//   a refused address or an invalid GOBLIN_WEBHOOK_URL pause it until it is fixed ·
//   a hold (`hold()`: a new signing key receivers may not have) pauses it, unsent, until Resume ·
//   other 4xx fail the row ·
//   a timeout after the body was sent, before the answer's status arrived, is "unknown": sent
//   once more after 2 minutes, with the same X-Goblin-Delivery (delivery spec D30), then given up
//   as "may have arrived". A status that arrived counts, however long its body takes (http.mjs).
import { post as defaultPost, isTlsError } from '../http.mjs';
import { envWebhookAddressProblem, parseWebhookUrl, WebhookUrlError } from '../address-policy.mjs';
import {
  signWebhookAll,
  SIGNATURE_HEADER,
  DELIVERY_HEADER,
  LEGACY_SIGNATURE_HEADER,
  LEGACY_DELIVERY_HEADER,
} from '../sign.mjs';
import { parseRetryAfter } from '../retry.mjs';
import { accepted, retry, failed, unknown, pause, skipped, defineChannel } from '../channel.mjs';

/** The 1.4.2 request body for one event. */
export const legacyWebhookBody = event => JSON.stringify({ source: 'orbit', ...event });

/** What the env webhook does when acceptance is unknown (D30): one resend, 2 minutes later. */
export const ENV_WEBHOOK_UNKNOWN = Object.freeze({ resendAfterMs: 2 * 60 * 1000, maxResends: 1 });

/** Maps an HTTP answer to an outcome (pure). */
export function classifyWebhookResponse(status, headers = {}, nowMs = Date.now()) {
  if (status >= 200 && status <= 299) return accepted({ status });
  if ([408, 425, 429].includes(status) || status >= 500)
    return retry(
      parseRetryAfter(headers['retry-after'], nowMs),
      `The webhook answered ${status}.`,
      {
        status,
      }
    );
  if ([401, 403, 404, 410].includes(status))
    return pause(
      `The webhook answered ${status}. Check GOBLIN_WEBHOOK_URL and the receiver; queued alerts wait until it is fixed.`,
      { status, transient: true }
    );
  if (status >= 300 && status <= 399)
    return pause(
      `The webhook answered with a redirect (${status}), which Uptime Goblin does not follow. Set GOBLIN_WEBHOOK_URL to the final address.`,
      { status, transient: true }
    );
  return failed(`The webhook refused the alert (${status}).`, { status });
}

/** Maps a transport failure to an outcome (pure). */
export function classifyWebhookError(error) {
  if (error?.code === 'EPOLICY') return pause(error.message);
  if (isTlsError(error)) return pause(error.message, { transient: true });
  if (error?.sent) return unknown(`${error.message} The webhook may have received the alert.`);
  return retry(null, error?.message || 'The webhook could not be reached.');
}

/**
 * createEnvWebhookChannel({url, signingKeys, hold, timeoutMs, post, addressPolicy, now, userAgent,
 * unknown, lookup, ca}). `url` is GOBLIN_WEBHOOK_URL (empty: the channel skips every row).
 * `signingKeys()` is read at each send: no available key holds delivery before transport.
 * `hold()` is read at each send
 * too: null, or why nothing may be sent now (the delivery service's hold for a new signing key,
 * lib/alerting/signing.mjs), which pauses the channel before anything is signed or sent.
 * `unknown` and `lookup` are for tests.
 */
export function createEnvWebhookChannel({
  url = '',
  signingKeys = () => [],
  hold = () => null,
  timeoutMs = 8000,
  post = defaultPost,
  addressPolicy = envWebhookAddressProblem,
  now = Date.now,
  userAgent = 'Uptime-Goblin',
  unknown: unknownRule = ENV_WEBHOOK_UNKNOWN,
  lookup,
  ca,
} = {}) {
  if (typeof signingKeys !== 'function')
    throw new TypeError('signingKeys must be a function returning the keys to sign with');
  if (typeof hold !== 'function')
    throw new TypeError('hold must be a function returning null or the reason to hold');
  let target = null,
    problem = null;
  if (url) {
    try {
      target = parseWebhookUrl(url);
    } catch (error) {
      if (!(error instanceof WebhookUrlError)) throw error;
      problem = error.message;
    }
  }
  return defineChannel({
    name: 'env-webhook',
    configured: Boolean(url),
    unknown: unknownRule,
    async send(message, { signal } = {}) {
      if (!url) return skipped('GOBLIN_WEBHOOK_URL is not set.');
      if (problem) return pause(problem);
      const held = hold();
      if (held) return pause(held);
      const event = message.events?.[0];
      if (!event) return failed('The delivery has no event.');
      const body = legacyWebhookBody(event);
      const headers = {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,
        [DELIVERY_HEADER]: message.uid,
        [LEGACY_DELIVERY_HEADER]: message.uid,
      };
      const keys = signingKeys() ?? [];
      if (!keys.length)
        return pause('The webhook signing key is unavailable; alerts wait until a key is saved.');
      if (keys.length)
        headers[SIGNATURE_HEADER] = headers[LEGACY_SIGNATURE_HEADER] = signWebhookAll(keys, body, {
          nowMs: now(),
          deliveryId: message.uid,
        });
      try {
        const response = await post(target, body, {
          headers,
          timeoutMs,
          signal,
          addressPolicy,
          ca,
          ...(lookup ? { lookup } : {}),
          maxResponseBytes: 4096,
        });
        return classifyWebhookResponse(response.status, response.headers, now());
      } catch (error) {
        return classifyWebhookError(error);
      }
    },
  });
}
