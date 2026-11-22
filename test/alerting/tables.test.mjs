// The delivery tables (lib/alerting/tables.mjs) as lane P will append them: they register beside
// the platform tables, render on every engine, migrate a real control database, and hold every
// field of an outbox row and a channel status.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  alertingTableSpecs,
  alertingSteps,
  OUTBOX_COLUMNS,
  CHANNEL_STATUS_COLUMNS,
} from '../../lib/alerting/tables.mjs';
import {
  defineTable,
  createRegistry,
  platformTables,
  legacyHistoryTables,
} from '../../lib/db/registry.mjs';
import { renderTable } from '../../lib/db/dialect/schema.mjs';
import { loadDialect, DIALECTS } from '../../lib/db/dialect/index.mjs';
import { openControl, platformSteps } from '../../lib/db/control.mjs';
import { defineSteps } from '../../lib/db/migrate.mjs';
import { initialChannelStatus } from '../../lib/notify/outbox.mjs';
import { outboxRow } from '../notify/store-contract.mjs';

const tables = alertingTableSpecs.map(([name, options]) => defineTable(name, options));
const registry = createRegistry([...platformTables, ...tables, ...legacyHistoryTables]);
const camel = name => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

test('the delivery tables register beside the platform tables, owned by lane A', () => {
  for (const name of ['alerting_outbox', 'alerting_channel_status']) {
    const table = registry.table(name);
    assert.deepEqual(
      [table.component, table.lane, table.class, table.db, table.backup, table.since],
      ['alerting', 'A', 'control', 'control', 'never', '1.5.0']
    );
    assert.deepEqual(table.modes, ['single', 'cluster']);
  }
  // Beside alerting's hunks of the 1.x history tables (alerts, events), which stay legacy.
  assert.deepEqual(
    registry
      .forComponent('alerting')
      .filter(table => !table.legacy)
      .map(table => table.name),
    ['alerting_outbox', 'alerting_channel_status']
  );
  // Old notifications never travel in a backup.
  assert.ok(!registry.backupAllowlist('control').includes('alerting_outbox'));
});

test('their DDL renders on SQLite, PostgreSQL and SQL Server', async () => {
  for (const name of DIALECTS) {
    const dialect = await loadDialect(name, { identifiers: registry.identifiers });
    for (const table of tables) {
      const ddl = renderTable(dialect, table).join('\n');
      assert.match(ddl, new RegExp(table.name), `${name} ${table.name}`);
    }
  }
});

test('the columns map one to one onto the outbox row and the channel status', () => {
  const outbox = registry.table('alerting_outbox');
  assert.deepEqual(Object.keys(outbox.columns).sort(), Object.keys(OUTBOX_COLUMNS).sort());
  for (const [column, field] of Object.entries(OUTBOX_COLUMNS)) assert.equal(field, camel(column));
  // Every field of a row as the outbox writes it (plus the id the store assigns).
  assert.deepEqual(
    Object.values(OUTBOX_COLUMNS).sort(),
    [...Object.keys(outboxRow()), 'id'].sort()
  );
  const status = registry.table('alerting_channel_status');
  assert.deepEqual(
    Object.keys(status.columns).sort(),
    [...Object.keys(CHANNEL_STATUS_COLUMNS), 'channel_id', 'updated_at'].sort()
  );
  assert.deepEqual(
    Object.values(CHANNEL_STATUS_COLUMNS).sort(),
    Object.keys(initialChannelStatus()).sort()
  );
});

test('the step migrates a real control database after the platform tables', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-alerting-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const control = openControl(directory, {
    release: '1.5.0',
    env: {},
    registry,
    steps: defineSteps([...platformSteps, ...alertingSteps], { registry }),
  });
  await control.migrate();
  const applied = (await control.inspect()).applied.map(step => step.id ?? step);
  control.close();
  assert.ok(applied.includes('alerting-001-outbox'), JSON.stringify(applied));
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  t.after(() => db.close());
  const columns = name =>
    db
      .prepare(`PRAGMA table_info(${name})`)
      .all()
      .map(column => column.name)
      .sort();
  assert.deepEqual(columns('alerting_outbox'), Object.keys(OUTBOX_COLUMNS).sort());
  assert.ok(columns('alerting_channel_status').includes('delivered_total'));
  const indexes = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'alerting_outbox'`)
    .all()
    .map(row => row.name);
  for (const name of ['alerting_outbox_uid', 'alerting_outbox_due', 'alerting_outbox_order'])
    assert.ok(indexes.includes(name), name);
});
