// Picks a dialect. SQLite is imported statically (it is pure and always present); the server
// dialects are reached only through dynamic import(), so SQLite mode never resolves them
// (principle 1 as amended; checked by scripts/import-graph.mjs and test/dialect).
import { createSqliteDialect, sqlite } from './sqlite.mjs';

export { sqlite, createSqliteDialect };

export const DIALECTS = Object.freeze(['sqlite', 'postgres', 'mssql']);

/**
 * The dialect a database URL or path names: `postgres:`/`postgresql:` → postgres,
 * `mssql:`/`sqlserver:` → mssql, anything else (a file path) → sqlite.
 */
export function dialectFor(location) {
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(String(location ?? ''))?.[1]?.toLowerCase();
  if (scheme === 'postgres' || scheme === 'postgresql') return 'postgres';
  if (scheme === 'mssql' || scheme === 'sqlserver') return 'mssql';
  if (scheme && scheme !== 'file') throw new Error(`unsupported database URL scheme ${scheme}:`);
  return 'sqlite';
}

/**
 * Loads a dialect by name. Options go to its factory (`identifiers`, and `clock` for SQLite or
 * `schema` for the server engines). Only SQLite executes in 1.5; the others render only.
 */
export async function loadDialect(name, options = {}) {
  switch (name) {
    case 'sqlite':
      return createSqliteDialect(options);
    case 'postgres': {
      const { createPostgresDialect } = await import('./postgres.mjs');
      return createPostgresDialect(options);
    }
    case 'mssql': {
      const { createMssqlDialect } = await import('./mssql.mjs');
      return createMssqlDialect(options);
    }
    default:
      throw new Error(`unknown dialect ${name}`);
  }
}
