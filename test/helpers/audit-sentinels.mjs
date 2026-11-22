// The audit canary's planted secrets (audit spec §9.3, §2.1 item 16): one distinct value per
// secret a test plants, and a search for them in every form a leak could take. Used by the
// canary of test/audit.test.mjs and by test/audit-ui.test.mjs, whose flow plants them.
//
//   const sentinels = auditSentinels();
//   … GOBLIN_PASSWORD = sentinels.adminPassword, an SMTP password = sentinels.smtpPassword …
//   assert.deepEqual(findSentinels(text, sentinels), []);
//
// Each value is new for every call (random), long enough for the password rules (12 characters
// or more), and no value is part of another, so a match names one secret. Values Uptime Goblin makes
// itself (the revealed signing secret, a session cookie) are added by the test that sees them:
// findSentinels takes any {name: value} object or list of values.
//
// This file is a Phase 0 contract (frozen): lanes change it only together, through the
// integrator.
import { randomBytes } from 'node:crypto';

const names = [
  // Passwords: the admin's, its replacement, and the ones typed wrongly or refused.
  'adminPassword',
  'newAdminPassword',
  'wrongPassword',
  'wrongCurrentPassword',
  'refusedNewPassword',
  'loginFieldPassword',
  'basicWrongPassword',
  // Settings and source secrets.
  'smtpPassword',
  'smtpPasswordChanged',
  'sourceApiKey',
  'sourcePassword',
  // Credentials carried in URLs: the webhook's, and a hand-edited config.json's url and apiUrl.
  'webhookToken',
  'urlToken',
  'apiUrlToken',
];

/**
 * The canary's planted values: {adminPassword, newAdminPassword, wrongPassword,
 * wrongCurrentPassword, refusedNewPassword, loginFieldPassword (typed into the login name
 * field), basicWrongPassword, smtpPassword, smtpPasswordChanged, sourceApiKey, sourcePassword,
 * webhookToken, urlToken, apiUrlToken, secretKey (GOBLIN_SECRET_KEY: 64 hex digits),
 * basicAuthorization (the Authorization value of a legacy Basic request with adminPassword)}.
 */
export function auditSentinels() {
  const values = {};
  for (const name of names)
    values[name] =
      `Canary${name[0].toUpperCase()}${name.slice(1)}-${randomBytes(9).toString('hex')}`;
  values.secretKey = randomBytes(32).toString('hex');
  values.basicAuthorization = `Basic ${Buffer.from(`admin:${values.adminPassword}`).toString('base64')}`;
  return Object.freeze(values);
}

// The forms one value could leak in: as it is, its UTF-8 bytes in hex (either case), base64,
// base64url and UTF-16 (a string written as UTF-16LE bytes). base64 turns 3 bytes into 4
// characters, so the characters a value gives depend on where it starts inside the encoded
// bytes: each of the three alignments is searched, taking only the characters that come from the
// value's bytes alone (from ceil(4k/3) to floor(4(k + n)/3) after k bytes before it), so a value
// encoded inside a larger blob, after any prefix and before any suffix, is found too. A Basic
// credential is such a blob ("admin:" before the password).
function forms(value) {
  const bytes = Buffer.from(value, 'utf8');
  // An empty slice (a value of one byte) would match anything, so it is left out.
  const aligned = encoding =>
    [0, 1, 2]
      .map(k =>
        Buffer.from(
          Buffer.concat([Buffer.alloc(k), bytes])
            .toString(encoding)
            .slice(Math.ceil((k * 4) / 3), Math.floor(((k + bytes.length) * 4) / 3))
        )
      )
      .filter(needle => needle.length > 0);
  return [
    ['text', [bytes]],
    ['hex', [Buffer.from(bytes.toString('hex'))]],
    ['HEX', [Buffer.from(bytes.toString('hex').toUpperCase())]],
    ['base64', aligned('base64')],
    ['base64url', aligned('base64url')],
    ['utf16', [Buffer.from(value, 'utf16le')]],
  ];
}

/**
 * The sentinels found in `text` (a string or a Buffer), as [{name, form}] in the order of
 * `sentinels` ({name: value} or a list of values, whose names are their indexes): empty when
 * none leaked.
 */
export function findSentinels(text, sentinels) {
  const haystack = Buffer.isBuffer(text) ? text : Buffer.from(String(text ?? ''), 'utf8');
  const found = [];
  for (const [name, value] of Object.entries(sentinels)) {
    if (typeof value !== 'string' || !value) continue;
    for (const [form, needles] of forms(value))
      if (needles.some(needle => haystack.includes(needle))) {
        found.push({ name, form });
        break;
      }
  }
  return found;
}
