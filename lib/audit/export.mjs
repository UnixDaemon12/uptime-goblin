// Audit exports (audit spec §6.3): GET /api/audit/export?format=csv|ndjson. The newest rows that
// match, at most EXPORT_MAX_ROWS or EXPORT_MAX_BYTES, written oldest first; no row is hidden
// (attempts included). Rows are read in units of EXPORT_UNIT_ROWS, newest first, up to the
// newest row when the export began, with the event loop running between units, so a large export
// never holds a sign-in back for long.
//
// CSV is for spreadsheets: a UTF-8 BOM (so they read it as UTF-8), every cell quoted, and the
// formula guard the web app's history export uses too (csvCell, public/shared/csv.js): a cell
// that starts with =, +, @, -, a tab or a carriage return gets a leading ', so a source named
// "=SUM(A1:A2)" is shown as text, never evaluated. NDJSON is for scripts: a header line, then the
// rows as stored (detail parsed).
import { setImmediate as nextTurn } from 'node:timers/promises';
import { EXPORT_MAX_BYTES, EXPORT_MAX_ROWS, EXPORT_UNIT_ROWS } from './actions.mjs';
import { canonicalJSON } from './chain.mjs';
import { csvCell } from '../../public/shared/csv.js';
import { auditColumns, auditOps } from '../repo/audit.mjs';

export const CSV_HEADER =
  'seq,time,actor_type,actor_id,actor_name,via,session_id,client,user_agent,request_id,action,target_type,target_id,target_name,outcome,status,count,ref,config_revision,detail,v,key_id,prev_hash,hash';
const BOM = '﻿';

// A stored time in ISO 8601 UTC with milliseconds; one a Date cannot hold, as its number.
const isoTime = ms => {
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? String(ms) : date.toISOString();
};

// One CSV cell (public/shared/csv.js), still exported from here for the audit's callers.
export { csvCell };

// The detail as its canonical JSON (§6.3), not the stored text: the hash covers the detail
// parsed, so a stored text with a duplicate key or padding would show what was never signed
// (review round 2; verification reads such a row changed). A text that does not parse, or whose
// value canonical JSON refuses, is written as stored: that row reads changed too.
function detailCell(row) {
  if (row.detailText === null || row.detailText === undefined) return null;
  if (row.detail === row.detailText) return row.detailText;
  try {
    return canonicalJSON(row.detail);
  } catch {
    return row.detailText;
  }
}

/** The CSV line of a stored row (without its line end). */
export function csvLine(row) {
  return [
    row.seq,
    isoTime(row.time),
    row.actor_type,
    row.actor_id,
    row.actor_name,
    row.via,
    row.session_id,
    row.client_key,
    row.user_agent,
    row.request_id,
    row.action,
    row.target_type,
    row.target_id,
    row.target_name,
    row.outcome,
    row.status,
    row.count,
    row.ref,
    row.config_revision,
    detailCell(row),
    row.v,
    row.key_id,
    row.prev_hash,
    row.hash,
  ]
    .map(csvCell)
    .join(',');
}

// What JSON.stringify leaves raw but a reader may not: U+0085 and U+2028/U+2029 end a line for
// readers that split the Unicode way (Python's str.splitlines, many editors), which would cut a
// row in two, and text-direction controls make a viewer show the line in another order. Written
// as their \u escapes instead, the line still parses to the same values.
const unsafeInLine = /[\u0080-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
const escaped = character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;

/** The NDJSON line of a stored row: its columns as stored, `detail` parsed (see unsafeInLine). */
export function ndjsonLine(row) {
  const out = {};
  for (const column of auditColumns) out[column] = row[column] ?? null;
  return JSON.stringify(out).replace(unsafeInLine, escaped);
}

// The file name's stamp: YYYYMMDD-HHMMSS of the export, in UTC.
const stampOf = ms =>
  new Date(ms).toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);

/**
 * Builds an export of the rows of `db` matching `query` (parseAuditQuery's, format included).
 * Options: clock, instance (meta.instance_id), open (seqs of the changes open in this process,
 * for outcome=unknown), maxRows, maxBytes, unitRows. Resolves {body: Buffer, rows, more,
 * filename, contentType}.
 */
export async function exportAudit(
  db,
  query,
  {
    clock = Date.now,
    instance = null,
    open = [],
    maxRows = EXPORT_MAX_ROWS,
    maxBytes = EXPORT_MAX_BYTES,
    unitRows = EXPORT_UNIT_ROWS,
  } = {}
) {
  const format = query.format;
  if (format !== 'csv' && format !== 'ndjson') throw new TypeError('format is csv or ndjson');
  const exportedAt = clock();
  // Null for an empty log. Codex review A1: no row is hidden, so a log whose stored rows are all
  // at seq 0 or below (never Uptime Goblin's: verification reports them) still exports them.
  const toSeq = await db.read(tx => {
    const head = auditOps.head(tx),
      last = auditOps.last(tx);
    return head === null && last === null ? null : Math.max(head?.seq ?? 0, last?.seq ?? 0);
  });
  const render = format === 'csv' ? csvLine : ndjsonLine;
  const end = format === 'csv' ? '\r\n' : '\n';
  // The newest lines first, as read; what the header and the BOM take is set aside first.
  const lines = [];
  let bytes = Buffer.byteLength(format === 'csv' ? `${BOM}${CSV_HEADER}\r\n` : '') + 256,
    more = false,
    before = null;
  while (toSeq !== null) {
    const want = Math.min(unitRows, maxRows - lines.length + 1);
    const rows = await db.read(tx =>
      auditOps.exportRows(tx, query, { open, toSeq, beforeSeq: before, limit: want })
    );
    for (const row of rows) {
      if (lines.length >= maxRows) {
        more = true;
        break;
      }
      const line = render(row) + end;
      const size = Buffer.byteLength(line);
      if (bytes + size > maxBytes) {
        more = true;
        break;
      }
      bytes += size;
      lines.push(line);
    }
    if (more || rows.length < want) break;
    before = rows.at(-1).seq;
    await nextTurn();
  }
  lines.reverse();
  const head =
    format === 'csv'
      ? `${BOM}${CSV_HEADER}\r\n`
      : `${JSON.stringify({ orbit: 'audit.export', v: 1, instance, exportedAt, rows: lines.length, more })}\n`;
  return {
    body: Buffer.from(head + lines.join(''), 'utf8'),
    rows: lines.length,
    more,
    filename: `uptime-goblin-audit-${stampOf(exportedAt)}Z.${format}`,
    contentType:
      format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8',
  };
}
