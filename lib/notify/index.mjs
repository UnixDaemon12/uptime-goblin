// Notification delivery (roadmap #15): the channel interface, the outbox and the built-in
// channels. The running server reaches them through lib/alerting/service.mjs.
export {
  OUTCOME_TYPES,
  accepted,
  retry,
  failed,
  unknown,
  pause,
  skipped,
  normaliseOutcome,
  defineChannel,
  safeReason,
} from './channel.mjs';
export {
  DELIVERY_POLICY,
  backoffMs,
  parseRetryAfter,
  retryDelayMs,
  circuitDelayMs,
  maxAgeMs,
} from './retry.mjs';
export {
  STATES,
  ACTIVE_STATES,
  TERMINAL_STATES,
  deliveryUid,
  digestKeyFor,
  newEventUid,
  supersededKinds,
  rowAfterOutcome,
  channelAfterOutcome,
  initialChannelStatus,
  planDigest,
  createOutbox,
} from './outbox.mjs';
export { OUTBOX_LIMITS, SNAPSHOT_LIMIT } from './limits.mjs';
export { createMemoryOutboxStore, createFailoverStore, isStorageError } from './memory-store.mjs';
export {
  signWebhook,
  signWebhookAll,
  verifyWebhookSignature,
  generateSigningKey,
  validateSigningKey,
  publicSigningKey,
  SIGNATURE_HEADER,
  DELIVERY_HEADER,
  LEGACY_SIGNATURE_HEADER,
  LEGACY_DELIVERY_HEADER,
} from './sign.mjs';
export {
  envWebhookAddressProblem,
  pushAddressProblem,
  parseWebhookUrl,
  plainWebhookHost,
  WebhookUrlError,
} from './address-policy.mjs';
export { post, OutboundError } from './http.mjs';
export {
  createEnvWebhookChannel,
  legacyWebhookBody,
  classifyWebhookResponse,
  classifyWebhookError,
  ENV_WEBHOOK_UNKNOWN,
} from './channels/webhook.mjs';
export { createEmailChannel, classifyMailError } from './channels/email.mjs';
export {
  createNtfyChannel,
  ntfyBody,
  ntfyAuthorization,
  ntfySetup,
  checkNtfy,
} from './channels/ntfy.mjs';
export { createGotifyChannel, gotifyBody, gotifySetup, checkGotify } from './channels/gotify.mjs';
export {
  classifyPushResponse,
  classifyPushError,
  parseServerUrl,
  PUSH_LIMITS,
} from './channels/push.mjs';
