// goblin-admin check-data: compare the tables in control.sqlite and history.sqlite with the table
// registry (drift), and report migration state (read-only). Exit status 1 when it finds drift.
import fs from 'node:fs';
import path from 'node:path';
import { controlExists, openControl } from '../../db/control.mjs';
import { openSqlite, plantedObjects } from '../../db/sqlite.mjs';
import registry from '../../db/registry.mjs';
import { assertDatabaseFiles, printable } from '../../saved-data.mjs';

export const summary = 'Check the databases against the table registry (read-only).';
export const usage = '[--data-dir <dir>] [--json]';
export const kind = 'read';

// The columns 1.5 adds to history.sqlite's events table (lib/db/registry.mjs).
const historyColumns = ['since', 'uid', 'relayed'];

// Uptime Goblin creates no triggers or views. One in either database was added by something else, and a
// trigger runs inside Uptime Goblin's own writes (it could undo a revocation or rewrite a password), so
// each is a problem, and so is any other catalog row that is not a table or an index as SQLite
// writes one (a trigger whose row says 'TRIGGER' runs too; see catalogKind in lib/db/sqlite.mjs).
// Names are saved data: shown printable.
function schemaObjects(file, catalog, problems) {
  for (const [kind, names] of [
    ['trigger', catalog.triggers],
    ['view', catalog.views],
  ])
    for (const name of names ?? [])
      problems.push(`${file} has a ${kind} Uptime Goblin does not create: ${printable(name, 100)}`);
  for (const entry of plantedObjects({ others: catalog.others }))
    problems.push(`${file} has a ${entry} that Uptime Goblin does not create`);
}

export async function run(context) {
  const { dataDir, release } = context;
  const report = { control: null, history: null, problems: [], notes: [] };
  if (controlExists(dataDir)) {
    const control = openControl(dataDir, { readOnly: true, release, env: {} });
    try {
      const catalog = await control.db.catalog();
      const { tables } = catalog;
      const drift = registry.drift('control', tables);
      const state = await control.inspect();
      report.control = {
        tables,
        ...drift,
        triggers: catalog.triggers,
        views: catalog.views,
        others: catalog.others,
        unknownSteps: state.unknown.map(row => row.id),
      };
      for (const name of drift.unregistered)
        report.problems.push(`control.sqlite has an unregistered table ${printable(name, 100)}`);
      schemaObjects('control.sqlite', catalog, report.problems);
      // Registered tables of steps that have not run yet are pending, not missing.
      const planned = new Set(
        state.pending.flatMap(step =>
          Array.isArray(step.up?.createTables) ? step.up.createTables : []
        )
      );
      for (const name of drift.missing)
        if (!planned.has(name))
          report.problems.push(`control.sqlite lacks the registered table ${name}`);
      if (state.refusal) report.problems.push(state.refusal.message);
    } finally {
      control.close();
    }
  } else report.notes.push('No control database yet.');
  const history = path.join(dataDir, 'history.sqlite');
  // As a start checks it (startControl), before fs.existsSync, which reads a symbolic link to
  // nothing or a loop of links as no file: "No history database yet. No drift found." for data
  // the start refuses. Such a link, a FIFO or a directory refuses here too (exit status 78).
  assertDatabaseFiles(history);
  if (fs.existsSync(history)) {
    const db = openSqlite(history, { readOnly: true });
    try {
      const catalog = await db.catalog();
      const { tables } = catalog;
      const drift = registry.drift('history', tables);
      report.history = {
        tables,
        ...drift,
        triggers: catalog.triggers,
        views: catalog.views,
        others: catalog.others,
      };
      for (const name of drift.unregistered)
        report.problems.push(`history.sqlite has an unregistered table ${printable(name, 100)}`);
      schemaObjects('history.sqlite', catalog, report.problems);
      // 1.5 keeps no migration record in history.sqlite (no schema_migrations there): it adds
      // its columns to events when it opens the file, so those columns tell (docs audit, keys 8).
      const columns = tables.includes('events')
        ? (await db.read(tx => tx.all(tx.dialect.catalog.columns('events')))).map(row => row.name)
        : [];
      if (historyColumns.some(name => !columns.includes(name)))
        report.notes.push(
          'history.sqlite has not been opened by Uptime Goblin 1.5 or later yet (its events table lacks the columns 1.5 adds).'
        );
      for (const name of drift.missing.filter(item => item !== 'schema_migrations'))
        report.problems.push(`history.sqlite lacks the registered table ${name}`);
    } finally {
      db.close();
    }
  } else report.notes.push('No history database yet.');
  context.report(report, value => [
    ...value.notes,
    ...(value.problems.length
      ? value.problems.map(problem => `PROBLEM: ${problem}`)
      : ['No drift found.']),
  ]);
  return report.problems.length ? 1 : 0;
}
