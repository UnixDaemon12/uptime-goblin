// The errors of the audit log (audit spec §6.5, Phase 0; texts verbatim, frozen). An AuditError
// carries its HTTP status, a stable code and a message written for the admin; the pipeline answers it
// as {error, code} (plus `parameter` for audit_query_invalid), with Retry-After on a 503.
//
//   throw auditError('audit_unavailable', {cause: error});   // an attempt or export row failed
//   throw auditError('audit_read_unavailable', {cause: error});
//   throw auditError('audit_query_invalid', {parameter: 'limit', rule: QUERY_RULES.limit});
//
// `cause` is the underlying error (a storage failure, which the pipeline reports to the storage
// guard when it is a full disk); it never reaches an answer.

export class AuditError extends Error {
  constructor(status, code, message, { retryAfter, cause, parameter } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'AuditError';
    this.status = status;
    this.code = code;
    if (Number.isFinite(retryAfter) && retryAfter >= 0) this.retryAfter = Math.ceil(retryAfter);
    if (parameter !== undefined) this.parameter = parameter;
  }
  /** The answer's body. */
  get body() {
    return this.parameter === undefined
      ? { error: this.message, code: this.code }
      : { error: this.message, code: this.code, parameter: this.parameter };
  }
}

/**
 * The rule of each query parameter of GET /api/audit and /api/audit/export (§6.2), as the
 * audit_query_invalid message names it: "<parameter> <rule>.". `to` has two rules (a time, and
 * not before `from`); `repeated` is the rule of any parameter given twice.
 */
export const QUERY_RULES = Object.freeze({
  from: 'must be a time in milliseconds since 1970',
  to: 'must be a time in milliseconds since 1970',
  order: 'must not be before from',
  limit: 'must be a whole number from 1 to 500',
  cursor: 'must be the nextCursor of an earlier page',
  action: 'must be up to 8 action names, or starts of them ending in a dot, separated by commas',
  actor: 'must be user, system, cli, anonymous or a name of at most 200 characters',
  target: 'must be a target type, or type:id',
  outcome: 'must be one of ok, denied, failed, conflict, info, unknown, attempt',
  format: 'must be csv or ndjson',
  repeated: 'may be given only once',
});

/** code → [status, message(options), Retry-After in seconds (503 only)]. */
export const AUDIT_ERRORS = Object.freeze({
  audit_unavailable: [
    503,
    () =>
      'Uptime Goblin cannot write its audit log, so nothing was changed. Try again in a moment; if this continues, free up space or increase the disk size of the Uptime Goblin host.',
    30,
  ],
  audit_read_unavailable: [
    503,
    () => 'Uptime Goblin could not read its audit log. Try again in a moment.',
    15,
  ],
  audit_query_invalid: [400, ({ parameter, rule }) => `${parameter} ${rule}.`],
});

/**
 * The AuditError of `code`. Options: cause (the underlying error), and for audit_query_invalid
 * parameter (the query parameter's name) and rule (its QUERY_RULES text).
 */
export function auditError(code, { cause, parameter, rule } = {}) {
  const entry = AUDIT_ERRORS[code];
  if (!entry) throw new TypeError(`Unknown audit error ${code}`);
  const [status, message, retryAfter] = entry;
  if (code === 'audit_query_invalid' && (typeof parameter !== 'string' || typeof rule !== 'string'))
    throw new TypeError('audit_query_invalid needs the parameter and its rule');
  return new AuditError(status, code, message({ parameter, rule }), {
    retryAfter,
    cause,
    parameter: code === 'audit_query_invalid' ? parameter : undefined,
  });
}
