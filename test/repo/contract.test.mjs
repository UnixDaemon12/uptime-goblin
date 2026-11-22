// The repository contract suite (roadmap §2.1): every repository runs against SQLite, and does
// what lib/store.mjs does for the same calls. PostgreSQL joins when TEST_DATABASE_URL is set
// (1.7); until then every statement the state repositories build must at least render for
// PostgreSQL and SQL Server with registered identifiers, so no 1.5 DAO needs rework later.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import registry from '../../lib/db/registry.mjs';
import { createSqliteDialect } from '../../lib/db/dialect/sqlite.mjs';
import { createPostgresDialect } from '../../lib/db/dialect/postgres.mjs';
import { createMssqlDialect } from '../../lib/db/dialect/mssql.mjs';
import { createRepositories } from '../../lib/repo/index.mjs';
import { createAlerts } from '../../lib/repo/state/alerts.mjs';
import { createEvents } from '../../lib/repo/state/events.mjs';
import { temporary, openHistory, measurements, capped, rows, faultyDb } from './helpers.mjs';
import { Store } from '../../lib/store.mjs';

const base = Date.UTC(2026, 8, 1, 12);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

// Writes the same history into the legacy Store and through the repositories.
async function fill(legacy, repos) {
  const service = id => ({
    id,
    name: id,
    rules: [],
    pollSeconds: 60,
    collectionTimeoutSeconds: 90,
  });
  for (let n = 0; n < 40; n++) {
    const time = base - (40 - n) * 300000;
    for (const id of ['a', 'b']) {
      const error = n % 10 >= 4 && n % 10 <= 7 ? 'Refused' : null;
      legacy.record(id, error ? [] : measurements(n), error, time, n % 3 ? capped(n) : []);
      await repos.series.append({
        service: id,
        time,
        metrics: error ? [] : measurements(n),
        error,
        notes: n % 3 ? capped(n) : [],
      });
      // Alert state and events through the Store on both (the evaluator moves in #8).
      legacy.evaluate(service(id), error ? [] : measurements(n), error, time);
    }
  }
}

test('the repositories do what the Store does: erase, retention and stats', async t => {
  const legacy = new Store(temporary(t)),
    { stores, store: view } = openHistory(t);
  t.after(() => legacy.close());
  // The budget refresh that ends a retention run sees every row it deleted.
  const refreshedWith = [];
  const repos = createRepositories({
    stores,
    budget: {
      afterDelete: () =>
        refreshedWith.push(view.db.prepare('SELECT COUNT(*) AS n FROM events').get().n),
    },
  });
  await fill(legacy, repos);
  // Alert state and events of the twin come from the same evaluations.
  for (const id of ['a', 'b'])
    for (let n = 0; n < 40; n++) {
      const time = base - (40 - n) * 300000,
        error = n % 10 >= 4 && n % 10 <= 7 ? 'Refused' : null;
      view.evaluate(
        { id, name: id, rules: [], pollSeconds: 60, collectionTimeoutSeconds: 90 },
        error ? [] : measurements(n),
        error,
        time
      );
    }
  const same = async label => {
    for (const [table, order] of [
      ['readings', 'service,time'],
      ['latest', 'service'],
      ['latest_notes', 'service'],
      ['alerts', 'service,rule'],
    ])
      assert.deepEqual(
        rows(view.db, table, order),
        rows(legacy.db, table, order),
        `${table} ${label}`
      );
    // Without the uid, random per write (each Store draws its own).
    assert.deepEqual(
      rows(view.db, 'events', 'time,id').map(({ id, uid, ...rest }) => rest),
      rows(legacy.db, 'events', 'time,id').map(({ id, uid, ...rest }) => rest),
      `events ${label}`
    );
    assert.deepEqual(await repos.stats(), legacy.stats(), `stats ${label}`);
  };
  await same('after filling');
  assert.ok(legacy.stats().events > 0);
  await legacy.prune(0.05, base);
  assert.deepEqual(Object.keys(await repos.applyRetention({ retentionDays: 0.05, now: base })), [
    'readings',
    'events',
  ]);
  await same('after retention');
  assert.deepEqual(refreshedWith, [legacy.stats().events]);
  await legacy.forget('a');
  await repos.eraseTarget('a');
  await same('after erasing a source');
  assert.equal(legacy.latest('a').lastAttempt, null);
  const units = repos.units.stats();
  for (const name of ['ingest.append', 'series.retention', 'state.retention', 'state.change'])
    assert.ok(units[name]?.runs > 0, name);
  assert.deepEqual(Object.keys(repos.state), ['alerts', 'events', 'status']);
  assert.equal(Object.isFrozen(repos), true);
});

test('erasure and retention end quietly on a database closed meanwhile, as the Store ends them', async t => {
  const { stores, history } = openHistory(t, { keepStore: false });
  const repos = createRepositories({ stores });
  await repos.series.append({ service: 'a', time: base, metrics: measurements(1) });
  await repos.state.events.append([{ service: 'a', time: base, kind: 'firing', message: 'm' }]);
  history.close();
  // Shutdown closed the database: the work stops and leaves the rest for the next run.
  assert.equal(await repos.eraseTarget('a'), undefined);
  assert.deepEqual(await repos.applyRetention({ retentionDays: 1, now: base + 2 * 86400000 }), {
    readings: 0,
    events: 0,
  });
  // Anything else meets it as unavailable (503).
  await assert.rejects(repos.stats(), { name: 'RepoError', class: 'unavailable' });
  await assert.rejects(repos.state.alerts.clear('a'), { class: 'unavailable' });
  // The Store does the same after close().
  const legacy = new Store(temporary(t));
  legacy.close();
  assert.equal(await legacy.forget('a'), undefined);
  assert.equal(await legacy.prune(1), undefined);
});

test('recycling on a full disk reaches the events only while they share the database', async t => {
  const { stores, control, history, store } = openHistory(t);
  assert.equal(stores.series, stores.state);
  const count = table => store.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
  const seed = async repos => {
    for (let n = 0; n < 20; n++)
      await repos.series.append({ service: 'a', time: base + n, metrics: measurements(n) });
    await repos.state.events.append(
      Array.from({ length: 5 }, (_, n) => ({
        service: 'a',
        time: base - 1 + n,
        kind: 'firing',
        message: 'm',
      }))
    );
  };
  // Shared (SQLite mode): the events older than the history left go in the same transaction.
  const faulty = faultyDb(history);
  const shared = createRepositories({ stores: { ...stores, series: faulty, state: faulty } });
  await seed(shared);
  faulty.script(['full']);
  await shared.series.append({ service: 'a', time: base + 100, metrics: measurements(1) });
  assert.equal(count('readings'), 20 - 2 + 1);
  assert.equal(count('events'), 5 - 3);
  // Apart (as series and state are in a cluster): no transaction spans two databases
  // (invariant 6), so only the readings are recycled.
  store.db.exec('DELETE FROM events');
  const apart = createRepositories({ stores: { ...stores, series: faulty, state: control } });
  await history.write(tx =>
    createEvents({ db: history }).tx.insert(tx, [
      { service: 'a', time: base, kind: 'firing', message: 'old' },
    ])
  );
  faulty.script(['full']);
  await apart.series.append({ service: 'a', time: base + 101, metrics: measurements(1) });
  assert.equal(count('readings'), 19 - 2 + 1);
  assert.equal(count('events'), 1);
});

// A Db that records rendered statements instead of running them.
function capture(dialect) {
  const statements = [];
  const tx = {
    dialect,
    run: query => (statements.push(dialect.render(query)), { changes: 0, lastInsertRowid: 0 }),
    get: query => (statements.push(dialect.render(query)), { count: 0 }),
    all: query => (statements.push(dialect.render(query)), []),
  };
  return {
    dialect,
    statements,
    read: async fn => fn(tx),
    write: async fn => fn(tx),
  };
}

test('every state statement renders for SQLite, PostgreSQL and SQL Server with registered names', async () => {
  const identifiers = registry.identifiers;
  const dialects = [
    createSqliteDialect({ identifiers }),
    createPostgresDialect({ identifiers }),
    createMssqlDialect({ identifiers }),
  ];
  const texts = {};
  for (const dialect of dialects) {
    const db = capture(dialect),
      events = createEvents({ db }),
      alerts = createAlerts({ db, events });
    const row = {
      service: 'a',
      rule: 'cpu',
      state: 'firing',
      since: base,
      count: 2,
      message: 'm',
      updated: base,
    };
    await events.recent();
    await events.count();
    await events.append([{ service: 'a', time: base, kind: 'firing', message: 'm', rule: 'cpu' }]);
    await events.applyRetention({ retentionDays: 1, now: base });
    await events.eraseTarget('a');
    await db.write(tx => events.tx.deleteBefore(tx, base));
    await alerts.firing();
    await alerts.countFiring();
    await alerts.forService('a');
    await db.write(tx => {
      alerts.tx.put(tx, row);
      alerts.tx.remove(tx, 'a', 'cpu');
      alerts.tx.resetRecovery(tx, 'a', 'cpu', base);
      alerts.tx.resetRecovery(tx, 'a', 'cpu');
      alerts.tx.clearService(tx, 'a');
      alerts.tx.clearAll(tx);
    });
    await alerts.transition('a', () => ({ alerts: [row], events: [] }));
    await alerts.reconcileRules('a', [{ key: 'cpu', operator: 'gt', threshold: 1 }], []);
    await alerts.clear('a');
    await alerts.clearAll();
    assert.ok(db.statements.length >= 20, `${dialect.name}: ${db.statements.length}`);
    texts[dialect.name] = db.statements.map(statement => statement.text);
  }
  // Each engine's own placeholders, and SQL Server never sees LIMIT.
  assert.ok(texts.sqlite.every(text => !/\$\d|@p\d/.test(text)));
  assert.ok(texts.postgres.some(text => /\$1/.test(text)));
  assert.ok(texts.mssql.some(text => /@p1/.test(text)));
  assert.ok(texts.mssql.every(text => !/\bLIMIT\b/.test(text)));
  assert.ok(texts.mssql.every(text => !/\bON CONFLICT\b/.test(text)));
});

test('repositories keep to their tables, engines and layers', () => {
  const read = file => fs.readFileSync(path.join(repositoryRoot, file), 'utf8');
  const walk = directory =>
    fs
      .readdirSync(path.join(repositoryRoot, directory), { withFileTypes: true })
      .flatMap(entry =>
        entry.isDirectory()
          ? walk(`${directory}/${entry.name}`)
          : entry.name.endsWith('.mjs')
            ? [`${directory}/${entry.name}`]
            : []
      );
  const files = [...walk('lib/repo'), ...walk('lib/series')];
  assert.ok(files.length >= 10, files.join());
  const named = (source, table) => new RegExp(`id\\('${table}'\\)`).test(source);
  for (const file of files) {
    const source = read(file);
    // No driver, no network, no server dialect loaded statically.
    assert.doesNotMatch(source, /from 'node:sqlite'|from '[^']*lib\/net\//, file);
    assert.doesNotMatch(source, /^import[^;]*dialect\/(?:postgres|mssql)\.mjs/m, file);
    for (const table of ['readings', 'latest_notes'])
      if (named(source, table)) assert.ok(file.startsWith('lib/series/'), `${file} names ${table}`);
    for (const table of ['alerts', 'events'])
      if (named(source, table))
        assert.ok(file.startsWith('lib/repo/state/'), `${file} names ${table}`);
    // `latest` is a state table the series store shares (registry: shared: ['series']).
    if (named(source, 'latest'))
      assert.ok(file.startsWith('lib/series/') || file.startsWith('lib/repo/state/'), file);
  }
  assert.deepEqual(registry.table('latest').shared, ['series']);
  assert.equal(registry.table('readings').class, 'series');
  assert.equal(registry.table('alerts').class, 'state');
});
