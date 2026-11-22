// Migration steps for the kill -9 test: each creates one table and fills it in the same unit.
// Run as a script (node crash-steps.mjs <file>) it prints "start", migrates that database,
// prints "done <ms>" and exits 0.
import { fileURLToPath } from 'node:url';
import { createRegistry, defineTable, platformTables } from '../../../lib/db/registry.mjs';
import { text, bigint } from '../../../lib/db/dialect/schema.mjs';
import { renderTable } from '../../../lib/db/dialect/schema.mjs';
import { createMigrator } from '../../../lib/db/migrate.mjs';
import { openSqlite } from '../../../lib/db/sqlite.mjs';

export const count = 30;
export const rowsPerStep = 500;
const name = i => `crash_${String(i).padStart(2, '0')}`;
export const tables = Array.from({ length: count }, (_, i) =>
  defineTable(name(i), {
    component: 'crash',
    lane: 'P',
    class: 'control',
    db: 'control',
    backup: 'never',
    since: '1.5.0',
    columns: { n: bigint(), pad: text() },
    primaryKey: ['n'],
  })
);
export const registry = createRegistry([...platformTables, ...tables]);
export const steps = tables.map((table, i) => ({
  id: `crash-${String(i + 1).padStart(3, '0')}-${table.name.replace('_', '-')}`,
  component: 'crash',
  kind: 'expand',
  db: 'control',
  up(tx, context) {
    tx.ddl(renderTable(context.dialect, table));
    const rows = Array.from({ length: rowsPerStep }, (_, n) => [n, 'x'.repeat(512)]);
    for (let start = 0; start < rows.length; start += 50)
      tx.run(tx.dialect.insert(table.name, ['n', 'pad'], rows.slice(start, start + 50)));
  },
}));

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const db = openSqlite(process.argv[2], { registry });
  const migrator = createMigrator({ db, classes: ['control'], steps, release: '1.5.0', registry });
  process.stdout.write('start\n');
  const started = performance.now();
  await migrator.migrate();
  db.close();
  process.stdout.write(`done ${Math.round(performance.now() - started)}\n`);
}
