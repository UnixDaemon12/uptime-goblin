// A render-only Db (the part of roadmap §10.7 item 5c that needs no database server). It has the
// shape of lib/db/sqlite.mjs's Db (read, write, bulkInsert, now, dialect) but executes nothing:
// every statement a unit issues is rendered by the Db's dialect, with the table registry's
// identifier allowlist, and recorded; results come from `respond`. Running a repository's
// operations on it with the PostgreSQL or SQL Server dialect shows whether each statement it
// builds renders on that engine (limit() without orderBy() on SQL Server, a fragment of another
// dialect, an unregistered identifier, too many parameters) and whether it names anything only
// SQLite has. It proves nothing about how a server executes a statement: that is the job of the
// contract suite on a real server (PostgreSQL 1.7, SQL Server non-gating from 1.6).
import { chunkRows } from '../../../lib/db/sql.mjs';

/** Text in a rendered statement that only SQLite understands. */
export const SQLITE_ONLY =
  /\bsqlite_(?:master|schema|sequence|temp_master)\b|\bpragma_\w+\s*\(|^\s*PRAGMA\b|\bINSERT\s+OR\s+\w+|\bAUTOINCREMENT\b|\b(?:julianday|unixepoch|strftime)\s*\(/i;

const defaults = Object.freeze({
  run: () => ({ changes: 1, lastInsertRowid: 1 }),
  get: () => undefined,
  all: () => [],
  iterate: () => [],
});

/**
 * A Db over `dialect` that renders and records. Options: `identifiers` (the registry's names;
 * default: the dialect's own check), `respond({kind, text, params, unit})` returning the result
 * of a call (undefined for the default: no rows, one change), `clock` (for now()).
 * `db.statements` holds {unit, kind, text, params} for each rendered statement and
 * `db.problems` {unit, kind, message, text?} for each statement that did not render or names
 * SQLite-only syntax on a server engine.
 */
export function createRenderDb(dialect, { identifiers, respond = () => undefined, clock } = {}) {
  const statements = [],
    problems = [];
  let unit = null,
    active = false;
  const call = (kind, query) => {
    let rendered;
    try {
      rendered = dialect.render(query, identifiers ? { identifiers } : undefined);
    } catch (error) {
      problems.push({ unit, kind, message: error.message });
      throw error;
    }
    const entry = { unit, kind, text: rendered.text, params: rendered.params };
    statements.push(entry);
    if (dialect.name !== 'sqlite' && SQLITE_ONLY.test(rendered.text))
      problems.push({ unit, kind, message: 'names SQLite-only syntax', text: rendered.text });
    const answer = respond(entry);
    return answer === undefined ? defaults[kind]() : answer;
  };
  const tx = Object.freeze({
    dialect,
    run: query => call('run', query),
    get: query => call('get', query),
    all: query => call('all', query),
    iterate: query => call('iterate', query),
  });
  async function inUnit(kind, fn) {
    if (active) throw new Error('render-db: units do not nest');
    active = true;
    unit = kind;
    try {
      return await fn(tx);
    } finally {
      active = false;
      unit = null;
    }
  }
  return {
    dialect,
    statements,
    problems,
    read: fn => inUnit('read', fn),
    write: fn => inUnit('write', fn),
    async bulkInsert(table, columns, columnBatch, { onConflict = 'error' } = {}) {
      const count = columnBatch[0]?.length ?? 0;
      const rows = Array.from({ length: count }, (_, row) =>
        columnBatch.map(values => values[row])
      );
      return inUnit('write', transaction =>
        chunkRows(rows, columns.length, dialect.caps.maxParams).reduce(
          (sum, chunk) =>
            sum +
            transaction.run(
              onConflict === 'ignore'
                ? dialect.insertIgnore(table, columns, chunk)
                : dialect.insert(table, columns, chunk)
            ).changes,
          0
        )
      );
    },
    now: async () => (clock ?? Date.now)(),
  };
}
