// Legacy HTTP Basic verification for scripts (sessions spec §5.11): 1.4.3's
// PasswordAuth.authenticate semantics, moved here unchanged and pointed at the database record.
//
// - A success is cached (an HMAC of the credential under a process-random key, never the
//   password), bound to the password generation: a script polling every 15 s costs one scrypt
//   derivation, not one per request. Failures are never cached, so every guess pays the KDF.
// - Identical credentials arriving together (one script's parallel requests) share one check;
//   `admit` (the http layer's per-client cap on checks in progress) is asked only when a new
//   check starts. The key includes the generation, so a check started before a password change
//   is never joined by a request that arrives after it, and never succeeds after it.
// - Passwords replaced in this process are remembered (at most 4, for `retiredMs`), so a device
//   still using the old password is refused without its requests counting as guesses.
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { verifyRecord, verifyDummy, maxPasswordBytes } from './password.mjs';

const prefix = Buffer.from('admin:');
const maxRetired = 4;
const same = (a, b) => a.length === b.length && timingSafeEqual(a, b);

/**
 * `current()` returns {record, generation}: the admin's record (null while no usable admin
 * account exists, when nothing verifies) and the in-process password generation. `clock` and
 * `retiredMs` bound the retired map.
 */
export function createBasicVerifier({ hasher, current, clock = Date.now, retiredMs }) {
  const key = randomBytes(32);
  const digestOf = bytes => createHmac('sha256', key).update(bytes).digest();
  // The digest of a password as a Basic credential would carry it ('admin:' + password).
  const credentialDigest = password => {
    const bytes = Buffer.concat([prefix, password]);
    try {
      return digestOf(bytes);
    } finally {
      bytes.fill(0);
    }
  };
  let success = null;
  const checks = new Map();
  const retired = new Map(); // hex digest → expiry (epoch ms), oldest first

  function isRetiredDigest(digest) {
    const now = clock();
    for (const [entry, expires] of retired) if (expires <= now) retired.delete(entry);
    for (const entry of retired.keys()) if (same(Buffer.from(entry, 'hex'), digest)) return true;
    return false;
  }

  return Object.freeze({
    /**
     * Checks `bytes` ('admin:<password>', the decoded Basic credential; the caller keeps and
     * zero-fills it). Resolves {generation, verified} on success, where `verified` says a full
     * derivation just succeeded (a cache hit is not verified), or null. May reject with `busy`:
     * scope 'client' when `admit` refuses, scope 'queue' when the hasher is full.
     */
    async check(bytes, { admit } = {}) {
      const { record, generation } = current();
      const digest = digestOf(bytes);
      if (success && success.generation === generation && same(digest, success.digest))
        return { generation, verified: false };
      const name = generation + ':' + digest.toString('hex');
      let check = checks.get(name);
      if (!check) {
        const release = admit?.();
        // Our own copy: the check may outlive the first caller's buffer, which it zero-fills.
        const password = Buffer.from(bytes.subarray(prefix.length));
        const plausible =
          bytes.length >= prefix.length &&
          same(bytes.subarray(0, prefix.length), prefix) &&
          password.length <= maxPasswordBytes;
        // Anything but the admin's name still costs one derivation, as a wrong password does.
        check = (
          plausible && record
            ? verifyRecord(hasher, record, password)
            : verifyDummy(hasher, password)
        ).finally(() => {
          checks.delete(name);
          password.fill(0);
          release?.();
        });
        checks.set(name, check);
      }
      if (!(await check) || generation !== current().generation) return null;
      success = { digest, generation };
      return { generation, verified: true };
    },
    /** True when `bytes` carry a password replaced in this process within `retiredMs`. */
    isRetired(bytes) {
      return isRetiredDigest(digestOf(bytes));
    },
    /**
     * After a committed password change: forget the cached success (the new password's first
     * use is a full check, which also clears that client's failures), retire the previous
     * password unless it is the new one, and never keep the new one retired.
     */
    passwordChanged(previous, next) {
      success = null;
      const old = credentialDigest(previous);
      const fresh = credentialDigest(next);
      for (const entry of retired.keys())
        if (same(Buffer.from(entry, 'hex'), fresh)) retired.delete(entry);
      if (!same(old, fresh)) {
        retired.delete(old.toString('hex'));
        retired.set(old.toString('hex'), clock() + retiredMs);
      }
      while (retired.size > maxRetired) retired.delete(retired.keys().next().value);
    },
  });
}
