// The audit log as the admin reads it (audit spec §6): the list, the export and the integrity check.
// Everything comes from the audit service (lib/audit, `app.audit`); this module checks what a
// request may ask for (parseAuditQuery, §6.2) and turns the answers into HTTP. Reading and
// checking are not recorded; an export is (one row before the answer, §5.5), and only Uptime Goblin's own
// page or a script may ask for one (D29, applied by the pipeline to routes whose `audit` is
// `export`). Every answer carries Cache-Control: no-store: the log names clients, browsers and
// sessions.
import { parseAuditQuery } from '../../audit/view.mjs';
import { json } from '../body.mjs';
import { BusyError } from '../exclusive.mjs';
import { headerPairEntries } from '../../legacy-names.mjs';

/**
 * How many audit exports are built and sent at once. Each holds its lines and then one body of
 * up to 16 MiB in memory and reads the log in units: requests beyond this get 503 busy
 * (Retry-After: 5) before anything is read or recorded, so concurrent requests cannot multiply
 * that. A place is held until the request's handler has finished and the answer has gone, or
 * its client has: a client that reads only the headers keeps the whole body referenced by its
 * connection, so a place given back once the body was built let any number of them hold one
 * each; and a build goes on after its client left, so a place given back when the client left
 * let any number of builds run at once.
 */
export const exportConcurrency = 2;

/**
 * How long an export's answer may make no progress (no byte taken by the client) before its
 * connection is closed and its place given back: Uptime Goblin sets no other time limit on sending an
 * answer, so two clients that never read would otherwise hold both places for good.
 */
export const exportIdleMs = 30000;

// A file name the service built, as a quoted-string of a Content-Disposition value: printable
// ASCII only, without the quote and the backslash a quoted-string escapes.
const safeFilename = name =>
  String(name ?? 'uptime-goblin-audit').replace(/[^\x20-\x7e]|["\\]/g, '_');

/**
 * `app` (see createApp in server.mjs): `audit`, the audit service (§4.1 of the audit spec), and
 * `exportIdleMs` (tests only, see exportIdleMs).
 */
export function auditRoutes(app) {
  let exporting = 0;
  const read = (path, summary, handler, extra = {}) => ({
    method: 'GET',
    path,
    auth: 'session',
    permission: 'audit:read',
    summary,
    handler,
    ...extra,
  });
  return [
    read(
      '/api/audit',
      'The audit log, newest first, a page at a time',
      async ({ res, url, assertCurrent }) => {
        const page = await app.audit.list(parseAuditQuery(url.searchParams, 'list'));
        // Signed out while the page was read: nothing of the log for the old session.
        assertCurrent();
        json(res, 200, page);
      }
    ),
    read(
      '/api/audit/export',
      'The audit log as CSV or NDJSON, as a download',
      async ({ res, url, assertCurrent, audit }) => {
        const query = parseAuditQuery(url.searchParams, 'export');
        if (exporting >= exportConcurrency)
          throw new BusyError(
            'Uptime Goblin is already building audit exports. Try again in a moment.'
          );
        let held = true,
          done = false,
          closed = res.destroyed;
        exporting++;
        // Given back once this handler has finished (the build, its row and the start of the
        // answer, or an error) and the answer has gone or the client has (an error answer
        // included). A client that leaves while its export is built does not stop the build
        // (app.audit.export takes no signal), and the handler holds the body until it returns:
        // given back on 'close' alone, a client that left and asked again would start any number
        // of builds at once.
        const release = () => {
          if (!held || !done || !closed) return;
          held = false;
          exporting--;
        };
        res.once('close', () => {
          closed = true;
          release();
        });
        try {
          const exported = await app.audit.export(query, query.format);
          // Signed out while the export was built (up to 50,000 rows, read in units with the
          // event loop between them): 401 and no row, never "exported" for a session that had
          // ended.
          assertCurrent();
          // The export's own row, before anything is sent: when it cannot be written nothing is
          // exported (503 audit_unavailable). It is not part of the export it describes.
          const { format, ...filters } = query;
          await audit.single({
            action: 'audit.export',
            target: { type: 'audit', id: null, name: null },
            detail: { format, rows: exported.rows, more: exported.more, filters },
          });
          assertCurrent();
          // A client that stops taking the body is closed after exportIdleMs (tests shorten it
          // with app.exportIdleMs).
          res.setTimeout(app.exportIdleMs ?? exportIdleMs, () => res.destroy());
          res.writeHead(200, {
            'Content-Type': exported.contentType,
            'Content-Disposition': `attachment; filename="${safeFilename(exported.filename)}"`,
            'Cache-Control': 'no-store',
            ...headerPairEntries('Export-Rows', String(exported.rows)),
            ...headerPairEntries('Export-More', exported.more ? 'true' : 'false'),
          });
          res.end(exported.body);
        } finally {
          done = true;
          release();
        }
      },
      { audit: 'export' }
    ),
    read(
      '/api/audit/verify',
      'Check that no audit entry was changed or removed',
      async ({ res, assertCurrent }) => {
        // Every result is a 200: a broken log is an answer, not a failure of the request.
        const result = await app.audit.verify();
        assertCurrent();
        json(res, 200, result);
      }
    ),
  ];
}
