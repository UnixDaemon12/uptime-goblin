// The audit chain (audit spec §4.2, Phase 0; frozen): every row's hash is an HMAC over
// the previous row's hash and the canonical JSON of the row's hashed columns, so a changed,
// inserted, removed or reordered row breaks the chain from that row on. The MAC is supplied by
// the caller, `data => keyring.hmac('audit', data, kid).mac` (UTF-8 input), or the MAC that
// Keyring.reset hands to its inUnit (lib/keyring.mjs); this module holds no key.
//
// A row's format number `v` (a stored, hashed column) decides which columns are hashed: a later
// release that adds a column adds a format, and no format ever changes, so rows written before
// stay verifiable. `detail` is stored as canonicalJSON(detail), so the stored text and the
// hashed bytes are the same.
//
// The code is §4.2's, with one deviation in canonicalJSON: it refuses an array with holes and an
// object that is not plain (a Date, Map, Buffer or class instance). §4.2's text wrote `[,1]` for
// a hole, which is not JSON (json_valid would then fail the insert as a storage error inside the
// caller's unit), and `{}` for a Date or Map, which would store and sign a value other than the
// one recorded. Neither can come from a stored row (detail is parsed from JSON), so every hash
// and pinned vector is the same; only a defect is now refused, as §4.1 asks of the writer.

export const GENESIS = '0'.repeat(64);
/** The hashed columns of each row format. A later release adds a format; none ever changes. */
export const FORMATS = Object.freeze({
  1: Object.freeze([
    'v',
    'seq',
    'time',
    'ref',
    'actor_type',
    'actor_id',
    'actor_name',
    'via',
    'session_id',
    'client_key',
    'user_agent',
    'request_id',
    'action',
    'target_type',
    'target_id',
    'target_name',
    'outcome',
    'status',
    'count',
    'detail',
    'config_revision',
    'key_id',
  ]),
});

/** Deterministic JSON: keys sorted by UTF-16 code units, no spaces, safe integers only. */
export function canonicalJSON(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('Audit values hold safe integers only');
    return String(value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new TypeError('Audit strings must be well-formed');
    return JSON.stringify(value);
  }
  // Array.from visits holes as undefined, which is refused below.
  if (Array.isArray(value)) return `[${Array.from(value, item => canonicalJSON(item)).join(',')}]`;
  if (typeof value === 'object' && isPlainObject(value))
    return `{${Object.keys(value)
      .filter(key => value[key] !== undefined)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`)
      .join(',')}}`;
  const kind =
    typeof value === 'object'
      ? (Object.getPrototypeOf(value)?.constructor?.name ?? 'object')
      : typeof value;
  throw new TypeError(`Audit values cannot hold ${kind}`);
}
// Plain data only: an object literal, JSON.parse's objects, or one made with no prototype.
function isPlainObject(value) {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
/** The hashed object of a stored row: the columns of its format (v), detail parsed. */
export function rowObject(row) {
  const columns = Object.hasOwn(FORMATS, row.v) ? FORMATS[row.v] : null;
  if (!columns) throw new RangeError(`Audit row format ${row.v} is not known to this release`);
  return Object.fromEntries(columns.map(c => [c, row[c] ?? null]));
}
/** hash = HMAC(K_audit[key_id], prev_hash ‖ canonicalJSON(rowObject(row))), hex. */
export const rowHash = (mac, prevHash, row) => mac(prevHash + canonicalJSON(rowObject(row)));
export const checkpointObject = ({ instance, seq, time, hash, reason, key_id }) => ({
  v: 1,
  kind: 'checkpoint',
  instance,
  seq,
  time,
  hash,
  reason,
  key_id,
});
export const checkpointMac = (mac, checkpoint) => mac(canonicalJSON(checkpointObject(checkpoint)));
