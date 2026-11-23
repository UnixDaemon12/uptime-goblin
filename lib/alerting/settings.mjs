// The settings document of durable delivery (delivery spec §3.4, Phase 0): the environment
// webhook's signing keys, sealed with the keyring in control.sqlite's settings.
import { defineSetting } from '../settings.mjs';
import { isSigningKey } from '../notify/sign.mjs';
// An Ed25519 private key as PKCS#8 PEM text (lib/notify/sign.mjs).
const signingKey = value => {
  if (!isSigningKey(value)) throw new Error('must be an Ed25519 private key (PKCS#8 PEM)');
  return value;
};
// signingSecret and previousSigningSecret are the fields in which earlier pre-release builds kept
// their HMAC secrets. Those builds open them without checking what they hold, sign with whatever
// opens and show it under Show signing secret, so this release never saves a value there: it only
// clears them (null needs no validator; any other value is refused).
const retired = () => {
  throw new Error('is a field of pre-release builds, which this release only clears');
};
const time = value => {
  if (value !== null && !(Number.isSafeInteger(value) && value >= 0))
    throw new Error('must be a time or null');
  return value;
};
// The environment webhook's signing keys (D7; public keys since 2026-11-12, suite design D8): the
// private keys, sealed with the keyring and never returned by view() or any route. The previous
// key keeps signing until previousUntil, so receivers can switch to the new public key.
//
// Schema 2 keeps the keys in signingKey and previousSigningKey. A build that does not know those
// fields keeps them as they are and never opens them (lib/settings.mjs), and a build that knows
// only schema 1 (the pre-release builds that signed with an HMAC secret, and the builds that kept
// the Ed25519 key in signingSecret) reads a schema-2 document as read-only: it can neither make
// nor replace a key in it. A start of this release saves a schema-1 document as schema 2, with
// retired material cleared; any replacement key is fresh and held (lib/alerting/signing.mjs).
//
// heldSince is set, in the same write as the new key, when a start makes a key pair in a document
// that was saved before: receivers may hold signing material it replaced (an HMAC secret of a
// pre-release build, a key the encryption key no longer opens), and nothing can sign with both.
// While it is set the webhook sends nothing; an admin's Resume of the webhook clears it.
export const notifySettings = defineSetting({
  component: 'notify',
  key: 'envWebhook',
  schema: 2,
  description:
    'Signing keys (Ed25519 private keys) of the environment webhook (GOBLIN_WEBHOOK_URL).',
  fields: {
    signingKey: { secret: true, validate: signingKey },
    previousSigningKey: { secret: true, validate: signingKey },
    previousUntil: { default: null, validate: time },
    createdAt: { default: null, validate: time },
    heldSince: { default: null, validate: time },
    signingSecret: { secret: true, validate: retired },
    previousSigningSecret: { secret: true, validate: retired },
  },
});
/** The private keys to sign with at `now`: the current one, then the previous while it lasts. */
export const signingKeys = (value, now) =>
  [value?.signingKey, value?.previousUntil > now ? value?.previousSigningKey : null].filter(
    isSigningKey
  );
