// Ed25519 webhook authority is stored only in schema-2 signingKey fields.
// Retired signingSecret fields were revealable by pre-release builds: no key from
// them may sign again or remain as overlap. Migration creates fresh authority and
// holds delivery until an administrator distributes the public key and resumes.
// Saved holds survive rollback. Incompatible read-only settings require restoring
// a compatible backup or upgrading; no missing-key path sends an unsigned POST.
// A failed write/readback stays pending, without claiming current-format saving.
import { systemClock, safeErrorText } from '../jobs.mjs';
import { isStorageError } from '../notify/memory-store.mjs';
import { isDiskFull } from '../storage-guard.mjs';
import {
  generateSigningKey,
  isSigningKey,
  normalizeSigningKey,
  publicSigningKey,
} from '../notify/sign.mjs';
import { notifySettings, signingKeys } from './settings.mjs';
import { deliveryError } from './errors.mjs';

const COMPONENT = notifySettings.component,
  KEY = notifySettings.key,
  SCHEMA = notifySettings.schema,
  OVERLAP_MS = 24 * 60 * 60 * 1000;
// The HMAC secret of an earlier pre-release build, exactly as those builds made and accepted it
// (randomBytes(32) as hexadecimal; their settings refused anything but /^[0-9a-f]{64}$/).
const HMAC_SECRET = /^[0-9a-f]{64}$/;
// This release's key fields (the current key, then the previous one) and, at the same places,
// the pre-release fields beside them.
const KEYS = ['signingKey', 'previousSigningKey'],
  RETIRED = ['signingSecret', 'previousSigningSecret'];
const REMOVED_LINE =
  "Uptime Goblin removed the alert webhook's HMAC signing secret (from a pre-release build); GOBLIN_WEBHOOK_URL is not set, so it made no signing key in its place.";
/** Why the webhook holds its notifications after a new key pair (the channel's pause reason). */
export const SIGNING_HOLD_REASON =
  'Uptime Goblin made a new signing key, which receivers that check X-Goblin-Signature may not have. Give them its public key (Show public key), then press Resume to send what waits.';

/**
 * What a stored key field holds: 'none' (nothing, or a value the encryption key does not open),
 * 'key' (an Ed25519 private key as generateSigningKey() writes it), 'reform' (an Ed25519 private
 * key in another PEM form, rewritten as 'key'), 'hmac' (a pre-release HMAC secret) or 'unknown'
 * (anything else: never signed with, and replaced like an HMAC secret).
 */
const kindOf = stored => {
  if (stored === null || stored === undefined || stored === '') return 'none';
  if (isSigningKey(stored)) return 'key';
  if (typeof stored === 'string' && HMAC_SECRET.test(stored)) return 'hmac';
  return normalizeSigningKey(stored) ? 'reform' : 'unknown';
};
const keyed = kind => kind === 'key' || kind === 'reform';

// A private key copied into any retired field is potentially disclosed, even
// if another field contains the same key in a different PEM representation.
const exposedKeys = doc =>
  RETIRED.map(field => normalizeSigningKey(doc?.value?.[field])).filter(Boolean);
const compromised = (doc, value) => {
  const key = normalizeSigningKey(value);
  return (
    key !== null &&
    (RETIRED.some(field => doc?.unreadable?.includes(field)) || exposedKeys(doc).includes(key))
  );
};
const movesOf = doc => {
  const patch = {};
  const hmac = RETIRED.some(field => kindOf(doc.value?.[field]) === 'hmac');
  KEYS.forEach((field, at) => {
    const own = doc.value?.[field];
    if (compromised(doc, own)) {
      patch[field] = null;
      patch[at ? 'previousUntil' : 'createdAt'] = null;
    } else if (kindOf(own) === 'reform') patch[field] = normalizeSigningKey(own);
    const retired = RETIRED[at];
    if (doc.value?.[retired] != null || doc.unreadable?.includes(retired)) {
      patch[retired] = null;
      if (own == null) patch[at ? 'previousUntil' : 'createdAt'] = null;
    }
  });
  return { patch, hmac };
};
const upgradeOf = doc => {
  if (!doc || doc.readOnly) return null;
  const { patch, hmac } = movesOf(doc);
  const stale = doc.version > 0 && doc.schema < SCHEMA;
  return Object.keys(patch).length || stale ? { patch, hmac } : null;
};

const loginOf = actor =>
  (typeof actor === 'string' ? actor : (actor?.login ?? actor?.name)) || 'an administrator';

/** The public part of a key: {keyId, publicKey, publicKeyRaw} (never the private key). */
const publicPart = privateKey => {
  const { keyId, publicKey, publicKeyRaw } = publicSigningKey(privateKey);
  return { keyId, publicKey, publicKeyRaw };
};

/**
 * createSigning({settings, configured, clock, logger, onStorageError, onEvent}). `settings` is
 * the settings service (lib/settings.mjs) with notifySettings defined and the keyring attached;
 * `configured` is Boolean(GOBLIN_WEBHOOK_URL): without a webhook nothing is created and the routes
 * answer webhook_not_configured.
 */
export function createSigning({
  settings,
  configured = false,
  clock = systemClock,
  logger = console,
  onStorageError = () => {},
  onEvent = () => {},
}) {
  if (!settings) throw new TypeError('createSigning needs the settings service');
  let value = null, // the opened document: {signingKey, previousSigningKey, previousUntil, createdAt, …}
    valueVersion = -1, // its settings version
    pending = Boolean(configured),
    warnedUnsaved = false,
    // A hold read from the document, or one a key pair being made needs (its write may fail).
    holding = false;
  const emit = record => {
    try {
      onEvent({ at: clock.wall(), target: 'env-webhook', ...record });
    } catch {}
  };
  // Only current-format authority counts. Retired material is never a fallback.
  const review = doc => {
    const own = KEYS.map(field => kindOf(doc?.value?.[field]));
    const retired = RETIRED.map(field => kindOf(doc?.value?.[field]));
    const kinds = [...own, ...retired];
    return {
      hmac: kinds.includes('hmac'),
      unknown: kinds.includes('unknown'),
      replace:
        !keyed(own[0]) ||
        compromised(doc, doc?.value?.signingKey) ||
        (!doc?.readOnly && own.some(kind => kind === 'hmac' || kind === 'unknown')),
    };
  };
  const ready = doc => !review(doc).replace && !upgradeOf(doc);
  const openedOf = doc => {
    if (review(doc).replace) return null;
    const opened = { ...doc.value, ...movesOf(doc).patch };
    for (const field of [...KEYS, ...RETIRED])
      if (!isSigningKey(opened[field])) opened[field] = null;
    return opened;
  };
  const currentOf = doc => {
    const own = doc?.value?.signingKey;
    return keyed(kindOf(own)) && !compromised(doc, own) ? normalizeSigningKey(own) : null;
  };
  // The cache only moves forward (amendment A61): a read that began before a rotation committed
  // and answers after it must not put the retired key back.
  const adopt = (opened, version, nextPending = false) => {
    if (version < valueVersion) return false;
    value = opened;
    valueVersion = version;
    holding = !opened || opened.heldSince != null;
    pending = nextPending;
    return true;
  };

  // A new key pair; the previous key and the pre-release fields are cleared. `hold`: the
  // webhook holds its notifications from this write on (heldSince), until an admin resumes it.
  async function create(doc, now, hold) {
    await settings.update(
      COMPONENT,
      KEY,
      {
        signingKey: generateSigningKey(),
        previousSigningKey: null,
        previousUntil: null,
        createdAt: now,
        heldSince: hold ? now : null,
        signingSecret: null,
        previousSigningSecret: null,
      },
      { ifVersion: doc.version, by: 'orbit' }
    );
    return settings.get(COMPONENT, KEY);
  }

  // Saves `change` (upgradeOf(doc)) and resolves the document read back. `at.step` says what
  // failed: 'read', 'remove' (the write clears an HMAC secret) or 'upgrade' (any other write).
  async function upgrade(doc, change, at) {
    if (!change) return doc;
    at.step = change.hmac ? 'remove' : 'upgrade';
    try {
      await settings.update(COMPONENT, KEY, change.patch, { ifVersion: doc.version, by: 'orbit' });
    } catch (error) {
      // Another writer saved first: check what it saved.
      if (error?.code !== 'settings_conflict') throw error;
    }
    const saved = await settings.get(COMPONENT, KEY);
    if (upgradeOf(saved)) throw new Error('another change to these settings was saved first');
    if (change.hmac && !configured) logger.warn?.(REMOVED_LINE);
    return saved;
  }

  // Save/read back a safe current-format document. Replacement of a previously
  // saved authority persists its hold atomically with the new key and retired clears.
  async function ensure() {
    const at = { step: 'read' };
    let observedVersion = valueVersion;
    try {
      let doc = await settings.get(COMPONENT, KEY);
      observedVersion = doc.version;
      if (!configured) {
        await upgrade(doc, upgradeOf(doc), at);
        warnedUnsaved = false;
        return true;
      }
      // Cache value, hold and durability together; an older read cannot alter newer state.
      const found = review(doc);
      if (!found.replace) {
        // Safe current-format keys may stay available while normalization is pending.
        adopt(openedOf(doc), doc.version, Boolean(upgradeOf(doc)));
        doc = await upgrade(doc, upgradeOf(doc), at);
        if (!ready(doc)) throw new Error('The signing key could not be read back.');
      } else {
        // Do not preserve stale authority while replacement is required.
        adopt(null, doc.version, true);
        const replaced = ['signingKey', 'signingSecret'].some(field =>
          doc.unreadable?.includes(field)
        );
        const hold = doc.version > 0;
        // The unavailable cached authority above already keeps delivery held.
        if (doc.readOnly) throw deliveryError('signing_compatibility');
        try {
          doc = await create(doc, clock.wall(), hold);
        } catch (error) {
          // Another writer (a second start racing this one) saved first: use what it saved.
          if (error?.code !== 'settings_conflict') throw error;
          doc = await settings.get(COMPONENT, KEY);
        }
        if (!ready(doc)) throw new Error('The signing key could not be read back.');
        if (found.hmac)
          logger.warn?.(
            "Uptime Goblin replaced the alert webhook's HMAC signing secret (from a pre-release build) with an Ed25519 signing key; receivers that check X-Goblin-Signature need its public key (Configure → Notifications)."
          );
        if (found.unknown)
          logger.warn?.(
            'A stored signing key of the alert webhook could not be read as an Ed25519 key; Uptime Goblin replaced it with a new Ed25519 signing key, and receivers that check X-Goblin-Signature need its public key (Configure → Notifications).'
          );
        if (!found.hmac && !found.unknown)
          logger.warn?.(
            `Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key (Configure → Notifications).${replaced ? ' The previous key could not be opened with the current encryption key.' : ''}`
          );
        emit({
          action: 'signing.created',
          outcome: 'ok',
          // The catalogue's "the old one could not be read": a key the current encryption key
          // does not open, or a stored value that is no Ed25519 key (not an HMAC secret).
          detail: { replaced: Boolean(replaced) || found.unknown },
        });
      }
      adopt(openedOf(doc), doc.version);

      warnedUnsaved = false;
      return !pending;
    } catch (error) {
      if (valueVersion <= observedVersion) adopt(value, valueVersion, true);
      if (isStorageError(error)) onStorageError(error);
      if (!warnedUnsaved) {
        warnedUnsaved = true;
        const reason = isDiskFull(error) ? 'the disk is full' : safeErrorText(error);
        logger.error?.(
          configured
            ? holding
              ? `The new webhook signing key could not be saved (${reason}); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds.`
              : value
                ? `Uptime Goblin could not save the webhook's signing settings in the form that pre-release builds cannot read (${reason}); alerts are signed with the stored key meanwhile, and Uptime Goblin tries again every 10 seconds.`
                : `The webhook signing key could not be saved (${reason}); alerts are held until it can be.`
            : at.step === 'read'
              ? `Uptime Goblin could not read its settings to look for an HMAC signing secret of a pre-release build (${reason}); it tries again every 10 seconds.`
              : at.step === 'remove'
                ? `Uptime Goblin could not remove the HMAC signing secret of a pre-release build from its settings (${reason}); it tries again every 10 seconds.`
                : `Uptime Goblin could not save the webhook's signing settings in the form that pre-release builds cannot read (${reason}); it tries again every 10 seconds.`
        );
      }
      return false;
    }
  }

  /** The private keys to sign with now: the current one, then the previous one while it lasts. */
  const keys = () => (configured && value ? signingKeys(value, clock.wall()) : []);

  // Signability and successful current-format persistence/readback are separate.
  function describe() {
    if (!configured) return null;
    const now = clock.wall();
    return {
      configured: true,
      saved: Boolean(value) && !pending,
      createdAt: value?.createdAt ?? null,
      previousUntil:
        value?.previousSigningKey && value?.previousUntil > now ? value.previousUntil : null,
    };
  }

  /**
   * What receivers verify with, read from the saved document: {algorithm: 'Ed25519', keyId,
   * publicKey (SPKI PEM), publicKeyRaw (base64 of the 32 bytes), createdAt, previousUntil,
   * previous}. `previous` ({keyId, publicKey, publicKeyRaw}) and `previousUntil` are set while
   * the replaced key still signs, else null. Public material only: never a private key. The keys
   * are safe current-format keys (openedOf()); retired fields never supply authority.
   */
  async function publicKeys() {
    if (!configured) throw deliveryError('webhook_not_configured');
    let doc;
    try {
      doc = await settings.get(COMPONENT, KEY);
    } catch (error) {
      if (isStorageError(error)) onStorageError(error);
      throw deliveryError('signing_unavailable', { retryAfter: 60 });
    }
    const opened = openedOf(doc);
    if (!opened) throw deliveryError('signing_unavailable', { retryAfter: 60 });
    adopt(opened, doc.version, Boolean(upgradeOf(doc)));
    const now = clock.wall(),
      overlap = opened.previousUntil > now && isSigningKey(opened.previousSigningKey);
    return {
      ...publicSigningKey(opened.signingKey),
      createdAt: opened.createdAt ?? null,
      previousUntil: overlap ? opened.previousUntil : null,
      previous: overlap ? publicPart(opened.previousSigningKey) : null,
    };
  }

  /**
   * Replaces the key pair: the current private key keeps signing beside the new one for 24
   * hours. Compare-and-swap on the document's version, so two rotations at once cannot both win.
   * `audit` (the route's recorder, audit spec §5.3) is given to the settings update, which runs
   * it inside the unit that saves the new key, once the swap succeeded: the rotation and its
   * audit row commit together, and a conflict or a storage error leaves neither. `check` (the
   * route's re-check of its session) runs first in that unit, after every await: a session that
   * ended while the document was read throws there, and neither the new key nor its row is kept.
   * Rejects with signing_conflict when another write came first, and signing_compatibility
   * (nothing written) for newer settings this release cannot change.
   */
  async function rotate({ actor, audit = null, check = null } = {}) {
    if (!configured) throw deliveryError('webhook_not_configured');
    const login = loginOf(actor);
    const inUnit =
      check === null
        ? audit
        : (tx, change) => {
            check();
            return audit?.(tx, change);
          };
    let doc;
    try {
      doc = await settings.get(COMPONENT, KEY);
    } catch (error) {
      if (isStorageError(error)) onStorageError(error);
      throw deliveryError('signing_unavailable', { retryAfter: 60 });
    }
    if (doc.readOnly) throw deliveryError('signing_compatibility');
    // Only an unexposed current-format key may remain as overlap.
    const now = clock.wall(),
      current = currentOf(doc);
    // A hold stays (only Resume ends it), also one only in memory (the start's key write failed),
    // and a new pair that keeps no key, in a document saved before, is held as ensure() holds it
    // (also when the start could not read the document, so that hold was not known yet): `next`
    // saves it, so a restart after this rotation holds the webhook too.
    const next = {
      signingKey: generateSigningKey(),
      previousSigningKey: current,
      previousUntil: current ? now + OVERLAP_MS : null,
      createdAt: now,
      heldSince: doc.value?.heldSince ?? (holding || (!current && doc.version > 0) ? now : null),
      signingSecret: null,
      previousSigningSecret: null,
    };
    let saved;
    try {
      saved = await settings.update(COMPONENT, KEY, next, {
        ifVersion: doc.version,
        by: login,
        audit: inUnit,
      });
    } catch (error) {
      if (error?.code === 'settings_conflict') throw deliveryError('signing_conflict');
      if (error?.code === 'settings_newer') throw deliveryError('signing_compatibility');
      if (isStorageError(error)) onStorageError(error);
      throw error;
    }
    // Signing switches to the saved document now: the one read back, or, when that read fails
    // (or its key does not open), `next`, which the resolved update saved (it writes every
    // field, so get() would open the same values). Keeping the old value after a failed read
    // left the retired key signing for good while the rotation answered success (A61).
    const stored = await settings.get(COMPONENT, KEY).catch(() => null);
    const readBackReady = stored && stored.version >= saved.version && ready(stored);
    adopt(
      readBackReady ? openedOf(stored) : next,
      readBackReady ? stored.version : saved.version,
      !readBackReady
    );
    logger.warn?.(
      `The webhook signing key was replaced by ${login}; receivers that check X-Goblin-Signature need the new public key${current ? ' within 24 hours' : ''}.`
    );
    emit({ action: 'signing.rotate', outcome: 'ok', actor: login });
    return { createdAt: now, previousUntil: current ? now + OVERLAP_MS : null };
  }

  /**
   * Ends the hold: an admin resumed the webhook, which says receivers have the new public key.
   * heldSince is cleared in one compare-and-swap write, whose unit first runs `check` (the
   * route's re-check of its session, after the read): a session that ended meanwhile throws there
   * and the hold stays. While the saved document has no key to sign with (the start's key write
   * failed, so the hold is only in memory, or the key does not open) there is no public key
   * receivers could have been given and nothing to sign the held notifications with: rejects
   * with signing_unavailable, writes nothing, and the hold stays. Rejects with signing_conflict
   * when the document changed meanwhile (a rotation), storage_full or
   * delivery_status_unavailable when it cannot be read or written; the hold then stays. A newer
   * release's immutable hold is refused with signing_compatibility and remains intact.
   */
  async function releaseHold({ actor, check = () => {} } = {}) {
    if (!configured) return;
    try {
      const doc = await settings.get(COMPONENT, KEY);
      if (doc.readOnly && (doc.value?.heldSince != null || !ready(doc)))
        throw deliveryError('signing_compatibility');
      if (!ready(doc)) throw deliveryError('signing_unavailable', { retryAfter: 60 });
      const opened = openedOf(doc);
      if (opened.heldSince != null) {
        const saved = await settings.update(
          COMPONENT,
          KEY,
          { heldSince: null },
          { ifVersion: doc.version, by: loginOf(actor), audit: () => check() }
        );
        adopt({ ...opened, heldSince: null }, saved.version);
      } else {
        check();
        adopt(opened, doc.version);
      }
    } catch (error) {
      if (error?.code === 'signing_unavailable' || error?.code === 'signing_compatibility')
        throw error;
      if (error?.code === 'settings_conflict') throw deliveryError('signing_conflict');
      if (!isStorageError(error)) throw error;
      onStorageError(error);
      throw deliveryError(isDiskFull(error) ? 'storage_full' : 'delivery_status_unavailable');
    }
  }

  return {
    ensure,
    keys,
    describe,
    publicKeys,
    rotate,
    releaseHold,
    get pending() {
      return pending;
    },
    /** Whether the webhook holds its notifications for a new key pair (until releaseHold()). */
    get held() {
      return Boolean(configured) && (holding || !value || value?.heldSince != null);
    },
  };
}
