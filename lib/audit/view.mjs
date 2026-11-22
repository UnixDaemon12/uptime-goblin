// Reading the audit log for people (audit spec §6.2, §6.3): the query of GET /api/audit and
// GET /api/audit/export, and the list body. lib/http/routes/audit.mjs (lane H) parses with
// parseAuditQuery() and answers what createAudit().list() resolves.
//
// The list leaves out only an attempt row whose result was written (the result carries all it
// had, D19); aggregated rows carry no `ref` and operation rows are not attempts, so they always
// stay listed. An attempt without a result is "in progress" while its change is open in this
// process and "unknown" otherwise: no clock decides it, so a clock step cannot mislabel one.
import { LIST_DEFAULT, LIST_MAX } from './actions.mjs';
import { QUERY_RULES, auditError } from './errors.mjs';
import { auditOps } from '../repo/audit.mjs';

const OUTCOME_FILTERS = ['ok', 'denied', 'failed', 'conflict', 'info', 'unknown', 'attempt'];
const ACTOR_TYPES = ['user', 'system', 'cli', 'anonymous'];
const actionItem = /^[a-z][a-z0-9.-]{0,63}$/;
const targetPattern = /^[a-z]{1,32}(?::[\x21-\x7e]{1,128})?$/;
const timePattern = /^[0-9]{1,16}$/;
// The parameters of each kind of query, in the order they are checked.
const parameters = {
  list: ['from', 'to', 'actor', 'action', 'target', 'outcome', 'limit', 'cursor'],
  export: ['from', 'to', 'actor', 'action', 'target', 'outcome', 'format'],
};

const invalid = (parameter, rule = parameter) =>
  auditError('audit_query_invalid', { parameter, rule: QUERY_RULES[rule] });

/**
 * The query of a list (`kind` 'list') or an export ('export') from its URLSearchParams (§6.2):
 * {from, to, actor, actions, target, outcome, limit, cursor, format}, every absent value null
 * (limit 50 for a list). Throws auditError('audit_query_invalid', {parameter, rule}) for the
 * first parameter that breaks its rule; a parameter given twice is refused, an unknown one ignored.
 */
export function parseAuditQuery(params, kind) {
  if (!(kind in parameters)) throw new TypeError("parseAuditQuery: kind is 'list' or 'export'");
  const names = parameters[kind];
  for (const name of names) if (params.getAll(name).length > 1) throw invalid(name, 'repeated');
  const value = name => (params.has(name) ? params.get(name) : null);
  const query = {
    from: null,
    to: null,
    actor: null,
    actions: null,
    target: null,
    outcome: null,
    limit: kind === 'list' ? LIST_DEFAULT : null,
    cursor: null,
    format: null,
  };
  for (const name of ['from', 'to']) {
    const text = value(name);
    if (text === null) continue;
    const number = Number(text);
    if (!timePattern.test(text) || !Number.isSafeInteger(number)) throw invalid(name);
    query[name] = number;
  }
  if (query.from !== null && query.to !== null && query.to < query.from)
    throw invalid('to', 'order');
  const actor = value('actor');
  if (actor !== null) {
    if (ACTOR_TYPES.includes(actor)) query.actor = { type: actor };
    else if (actor.length && Array.from(actor).length <= 200 && actor.isWellFormed())
      query.actor = { name: actor };
    else throw invalid('actor');
  }
  const action = value('action');
  if (action !== null) {
    const items = action.split(',');
    if (items.length > 8 || !items.every(item => actionItem.test(item))) throw invalid('action');
    query.actions = items.map(name => ({ name, prefix: name.endsWith('.') }));
  }
  const target = value('target');
  if (target !== null) {
    if (!targetPattern.test(target)) throw invalid('target');
    const colon = target.indexOf(':');
    query.target =
      colon < 0
        ? { type: target, id: null }
        : { type: target.slice(0, colon), id: target.slice(colon + 1) };
  }
  const outcome = value('outcome');
  if (outcome !== null) {
    if (!OUTCOME_FILTERS.includes(outcome)) throw invalid('outcome');
    query.outcome = outcome;
  }
  if (kind === 'list') {
    const limit = value('limit');
    if (limit !== null) {
      if (!/^[1-9][0-9]{0,2}$/.test(limit) || Number(limit) > LIST_MAX) throw invalid('limit');
      query.limit = Number(limit);
    }
    const cursor = value('cursor');
    if (cursor !== null) {
      if (!/^[1-9][0-9]{0,15}$/.test(cursor) || !Number.isSafeInteger(Number(cursor)))
        throw invalid('cursor');
      query.cursor = Number(cursor);
    }
  } else {
    const format = value('format');
    if (format !== 'csv' && format !== 'ndjson') throw invalid('format');
    query.format = format;
  }
  return query;
}

const allNull = object => Object.values(object).every(value => value === null);

/**
 * The list entry of a stored row (§6.3): an attempt row reads `attempt` while its change is open
 * in this process or its result was written (`result` then names it), else `unknown`.
 */
export function entryOf(row, { open, result = null }) {
  const actor = {
    type: row.actor_type,
    id: row.actor_id,
    name: row.actor_name,
    via: row.via,
    sessionId: row.session_id,
    client: row.client_key,
    userAgent: row.user_agent,
  };
  const target = { type: row.target_type, id: row.target_id, name: row.target_name };
  const attempt = row.outcome === 'attempt';
  return {
    seq: row.seq,
    time: row.time,
    action: row.action,
    outcome: attempt ? (open.has(row.seq) || result ? 'attempt' : 'unknown') : row.outcome,
    status: row.status,
    count: row.count,
    actor: allNull(actor) ? null : actor,
    requestId: row.request_id,
    target: allNull(target) ? null : target,
    ref: row.ref,
    result:
      attempt && result
        ? { seq: result.seq, outcome: result.outcome, status: result.status, time: result.time }
        : null,
    configRevision: row.config_revision,
    detail: row.detail,
  };
}

/**
 * One list page and its retention line, in one read unit: one indexed query for the page
 * (LIMIT + 1, so `nextCursor` is set only when an older matching row exists), the results of
 * the attempts it lists, and the first and newest rows (the row count is their distance, D33).
 * `open` is the Set of the seqs of the changes open in this process.
 */
export function readList(tx, query, { open, retention, unwritten }) {
  const limit = query.limit ?? LIST_DEFAULT;
  const rows = auditOps.page(tx, query, { open: [...open], limit });
  const more = rows.length > limit;
  const shown = more ? rows.slice(0, limit) : rows;
  const attempts = shown.filter(row => row.outcome === 'attempt').map(row => row.seq);
  const results = new Map(
    (attempts.length ? auditOps.results(tx, attempts) : []).map(result => [result.ref, result])
  );
  const first = auditOps.first(tx),
    last = auditOps.last(tx);
  return {
    entries: shown.map(row => entryOf(row, { open, result: results.get(row.seq) ?? null })),
    nextCursor: more ? String(shown.at(-1).seq) : null,
    unwritten,
    retention: {
      days: retention.days,
      maxRows: retention.maxRows,
      rows: first && last ? last.seq - first.seq + 1 : 0,
      oldest: first ? { seq: first.seq, time: first.time } : null,
    },
  };
}
