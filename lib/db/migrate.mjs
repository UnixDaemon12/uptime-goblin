// The migration runner (roadmap §2.2, amended by §10.5).
//
// A step is {id, component, after, kind, db, modes, up, online, description}:
//   id        <component>-<nnn>-<slug>, numbered contiguously from 001 within its component
//   after     ids this step needs first; with the numbering it forms a DAG, and applied steps
//             are recorded as a set, so the order in which lanes merge does not matter
//   kind      expand   additive; a release that does not know it tolerates it
//             data     a background, idempotent job with progress (runData), run by the leader.
//                      Expand and contract steps run at start and cannot wait for one, so no
//                      such step may follow a data step, through `after` or by numbering: a
//                      data step is the last step of its component (later schema changes for
//                      the same area start a new component)
//             contract breaking; only in a major release, and a release that does not know an
//                      applied one refuses to start
//   db        the store class whose database it changes: control | state | series
//   modes     single and/or cluster (a cluster-only step never runs in SQLite mode)
//   up        {createTables: [registered table names]}   the schema DSL, rendered per engine
//             function (tx, ctx)                           portable: written only with sql`…`
//                                                          and the dialect helpers
//             {sqlite, postgres, mssql}                    one function per engine
//   online    false: only under cluster maintenance mode (server databases)
//
// Each step runs in its own BEGIN IMMEDIATE unit together with its schema_migrations row, so a
// crash at any statement leaves it wholly applied or not at all, and the next run resumes.
//
//   since     the release that introduced the step; required for contract steps (a major release)
//
// Refusal (exit 78, nothing written): an applied contract step this release does not know, or a
// fence in schema_fences naming a newer release. requireRelease() raises a fence inside the
// transaction that first enables a feature older releases would mishandle. runData() checks
// both again in every chunk's unit, as well as the step's prerequisites.
import { randomUUID } from 'node:crypto';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { adminCommand } from '../admin-command.mjs';
import { printable } from '../saved-data.mjs';
import { sql, id } from './sql.mjs';
import { renderTable, requiredDialects } from './dialect/schema.mjs';
import defaultRegistry from './registry.mjs';

export const stepKinds = Object.freeze(['expand', 'data', 'contract']);
const stepDatabases = Object.freeze(['control', 'state', 'series']);
const engines = Object.freeze(['sqlite', 'postgres', 'mssql']);
const idPattern = /^([a-z][a-z0-9]*)-(\d{3})-([a-z0-9]+(?:-[a-z0-9]+)*)$/;
const releasePattern = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

/** A start that must not proceed: exit status 78, and nothing is written. */
export class RefusalError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'RefusalError';
    this.code = code;
    this.refusal = true;
    this.exitCode = 78;
    Object.assign(this, details);
  }
}

/** Steps that break the rules (a programming error caught by tests and the lint). */
export class MigrationError extends Error {
  constructor(message, problems = []) {
    super(problems.length ? `${message}:\n- ${problems.join('\n- ')}` : message);
    this.name = 'MigrationError';
    this.problems = problems;
  }
}

/** Parses x.y.z[-pre] into [major, minor, patch, prerelease identifiers]. */
export function parseRelease(value) {
  const match = releasePattern.exec(String(value ?? ''));
  if (!match) throw new TypeError(`${JSON.stringify(value)} is not a release version (x.y.z)`);
  return [
    Number(match[1]),
    Number(match[2]),
    Number(match[3]),
    match[4] ? match[4].split('.') : [],
  ];
}

/** Semantic-version order: negative when a < b, 0 when equal, positive when a > b. */
export function compareReleases(a, b) {
  const x = parseRelease(a),
    y = parseRelease(b);
  for (let i = 0; i < 3; i += 1) if (x[i] !== y[i]) return x[i] - y[i];
  if (!x[3].length || !y[3].length) return y[3].length - x[3].length; // 1.5.0-rc.1 < 1.5.0
  for (let i = 0; i < Math.max(x[3].length, y[3].length); i += 1) {
    const p = x[3][i],
      q = y[3][i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const numeric = /^\d+$/;
    if (numeric.test(p) && numeric.test(q)) {
      if (Number(p) !== Number(q)) return Number(p) - Number(q);
    } else if (numeric.test(p) !== numeric.test(q)) return numeric.test(p) ? -1 : 1;
    else if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/**
 * x.y.z without its pre-release part. Fences and feature availability compare the core release,
 * so 1.6.0-rc.1 counts as 1.6.0: it may raise a 1.6.0 fence and still open its own data.
 */
export const coreRelease = value => parseRelease(value).slice(0, 3).join('.');

/** A major release (x.0.0 or one of its pre-releases) may carry contract steps. */
export const isMajorRelease = value => {
  const [, minor, patch] = parseRelease(value);
  return minor === 0 && patch === 0;
};

/** How a step's `up` runs on `engine`: a function, or null when it has none there. */
function runnerFor(step, engine, registry) {
  const { up } = step;
  if (typeof up === 'function') return up;
  if (up && Array.isArray(up.createTables))
    return (tx, context) => {
      for (const name of up.createTables) createTable(tx, context, registry.table(name));
    };
  return typeof up?.[engine] === 'function' ? up[engine] : null;
}

// Creates a registered DSL table. A table already present with exactly the registered columns
// is adopted (a release that created it before migrations recorded it); any other is drift.
function createTable(tx, context, table) {
  if (context.engine === 'sqlite') {
    const present = tx
      .all(sql`SELECT name FROM pragma_table_info(${table.name})`)
      .map(row => row.name);
    if (present.length) {
      const expected = Object.keys(table.columns);
      if (present.length === expected.length && expected.every(name => present.includes(name)))
        return;
      throw new MigrationError(
        `${table.name} exists with columns ${present.join(', ')}, not the registered ${expected.join(', ')}`
      );
    }
  }
  tx.ddl(renderTable(context.dialect, table));
}

/** Validates a step list: [] when it follows every rule, otherwise the problems. */
export function validateSteps(steps, { release, registry = defaultRegistry } = {}) {
  const problems = [];
  const byId = new Map();
  const numbers = new Map();
  for (const step of steps) {
    const where = `step ${step?.id ?? '(no id)'}`;
    const match = idPattern.exec(step?.id ?? '');
    if (!match) {
      problems.push(`${where}: the id must be <component>-<nnn>-<slug>`);
      continue;
    }
    if (byId.has(step.id)) problems.push(`${where}: the id is used twice`);
    byId.set(step.id, step);
    if (step.component !== match[1]) problems.push(`${where}: component must be ${match[1]}`);
    if (!numbers.has(match[1])) numbers.set(match[1], []);
    numbers.get(match[1]).push(Number(match[2]));
    if (!stepKinds.includes(step.kind))
      problems.push(`${where}: kind must be ${stepKinds.join('|')}`);
    if (!stepDatabases.includes(step.db))
      problems.push(`${where}: db must be ${stepDatabases.join('|')}`);
    const modes = step.modes ?? ['single', 'cluster'];
    if (
      !Array.isArray(modes) ||
      !modes.length ||
      modes.some(m => !['single', 'cluster'].includes(m))
    )
      problems.push(`${where}: modes must be a non-empty list of single, cluster`);
    if (!Array.isArray(step.after ?? [])) problems.push(`${where}: after must be a list`);
    // A contract step is introduced only in a major release and keeps that release in `since`,
    // so the patch and minor releases after it (2.0.1, 2.1.0) still carry it in their history.
    let since = null;
    if (step.since !== undefined)
      try {
        parseRelease(step.since);
        since = step.since;
      } catch {
        problems.push(`${where}: since must be the release that introduced the step (x.y.z)`);
      }
    if (step.kind === 'contract') {
      if (step.since === undefined)
        problems.push(
          `${where}: a contract step must name the major release that introduced it (since)`
        );
      else if (since && !isMajorRelease(since))
        problems.push(
          `${where}: a contract step cannot be introduced in ${since}, which is not a major release`
        );
      else if (since && release && compareReleases(coreRelease(since), coreRelease(release)) > 0)
        problems.push(`${where}: introduced in ${since}, later than this release (${release})`);
    }
    const { up } = step;
    if (typeof up === 'function') {
      // Portable: runs on every engine.
    } else if (up && Array.isArray(up.createTables)) {
      if (step.kind === 'data') problems.push(`${where}: a data step cannot create tables`);
      for (const name of up.createTables) {
        if (!registry.has(name)) {
          problems.push(`${where}: ${name} is not a registered table`);
          continue;
        }
        const table = registry.table(name);
        if (table.legacy) problems.push(`${where}: ${name} is a hand-written 1.x table`);
        if (table.class !== step.db)
          problems.push(`${where}: ${name} is a ${table.class} table, not ${step.db}`);
        if (modes.some(mode => !table.modes.includes(mode)))
          problems.push(`${where}: ${name} does not exist in every mode the step runs in`);
      }
    } else if (up && typeof up === 'object') {
      for (const key of Object.keys(up))
        if (!engines.includes(key)) problems.push(`${where}: up.${key} is not an engine`);
      const missing = requiredDialects(modes).filter(engine => typeof up[engine] !== 'function');
      if (missing.length) problems.push(`${where}: up has no ${missing.join(', ')} version`);
    } else problems.push(`${where}: up must be {createTables}, a function or per-engine functions`);
  }
  for (const [component, list] of numbers) {
    const sorted = [...list].sort((a, b) => a - b);
    sorted.forEach((number, index) => {
      if (number !== index + 1)
        problems.push(
          `${component}: steps must be numbered 001, 002, … without gaps (found ${String(number).padStart(3, '0')})`
        );
    });
  }
  for (const step of steps)
    for (const dependency of step?.after ?? [])
      if (!byId.has(dependency))
        problems.push(`step ${step.id}: after names unknown step ${dependency}`);
  if (!problems.length) {
    try {
      const ordered = orderSteps(steps);
      // An expand or contract step runs at start; it cannot wait for a background data step,
      // whether it names that step in `after` or follows it within its component. This is the
      // same graph orderSteps() and runData() use.
      const edges = dependencyEdges(steps);
      const dataIds = new Set(ordered.filter(step => step.kind === 'data').map(step => step.id));
      const needs = new Map();
      for (const step of ordered) {
        const all = new Set();
        for (const dependency of edges.get(step.id)) {
          all.add(dependency);
          for (const inner of needs.get(dependency) ?? []) all.add(inner);
        }
        needs.set(step.id, all);
        if (step.kind !== 'data' && [...all].some(item => dataIds.has(item)))
          problems.push(
            `step ${step.id}: ${step.kind === 'expand' ? 'an expand' : 'a contract'} step cannot come after a data step`
          );
      }
    } catch (error) {
      problems.push(error.message);
    }
  }
  return problems;
}

/**
 * The steps each step needs first: its `after` steps and, within its component, the step
 * numbered just before it. Map of id → Set of ids. orderSteps(), validateSteps() and runData()
 * all use this one graph, so start-up validation, ordering and background runs agree.
 */
export function dependencyEdges(steps) {
  const edges = new Map(steps.map(step => [step.id, new Set(step.after ?? [])]));
  const byComponent = new Map();
  for (const step of steps) {
    if (!byComponent.has(step.component)) byComponent.set(step.component, []);
    byComponent.get(step.component).push(step);
  }
  for (const list of byComponent.values()) {
    list.sort((a, b) => (a.id < b.id ? -1 : 1));
    for (let i = 1; i < list.length; i += 1) edges.get(list[i].id).add(list[i - 1].id);
  }
  return edges;
}

/**
 * Orders steps so every step follows its `after` steps and the earlier steps of its own
 * component; ties are broken by id. Throws MigrationError on a cycle.
 */
export function orderSteps(steps) {
  const byId = new Map(steps.map(step => [step.id, step]));
  const edges = dependencyEdges(steps);
  const ordered = [],
    state = new Map();
  const visit = (stepId, trail) => {
    if (state.get(stepId) === 'done') return;
    if (state.get(stepId) === 'visiting')
      throw new MigrationError(`Migration steps form a cycle: ${[...trail, stepId].join(' → ')}`);
    state.set(stepId, 'visiting');
    for (const dependency of [...edges.get(stepId)].sort())
      if (byId.has(dependency)) visit(dependency, [...trail, stepId]);
    state.set(stepId, 'done');
    ordered.push(byId.get(stepId));
  };
  for (const stepId of [...byId.keys()].sort()) visit(stepId, []);
  return ordered;
}

/** Validates and freezes a step list (throws MigrationError with every problem). */
export function defineSteps(steps, options) {
  const problems = validateSteps(steps, options);
  if (problems.length) throw new MigrationError('Invalid migration steps', problems);
  return Object.freeze(
    steps.map(step =>
      Object.freeze({ after: [], modes: ['single', 'cluster'], online: true, ...step })
    )
  );
}

// ---------------------------------------------------------------------------------------------
// Fences.

const fenceName = /^[a-z][a-zA-Z0-9]*(?:\.[a-z][a-zA-Z0-9]*)+$/;

/**
 * Raises the fence `name` to `minRelease` inside the caller's write unit (the one that first
 * enables the feature), so any release older than `minRelease` refuses to open this data. A
 * fence only ever rises. Call it synchronously inside db.write(tx => …).
 */
export function requireRelease(tx, { name, minRelease, reason, now }) {
  if (!fenceName.test(name ?? ''))
    throw new TypeError(`Invalid fence name ${JSON.stringify(name)}`);
  parseRelease(minRelease);
  if (typeof reason !== 'string' || !reason || reason.length > 500)
    throw new TypeError('A fence needs a reason (at most 500 characters)');
  if (!Number.isSafeInteger(now)) throw new TypeError('requireRelease needs now (epoch ms)');
  const current = tx.get(
    sql`SELECT ${id('min_release')} FROM ${id('schema_fences')} WHERE ${id('name')} = ${name}`
  );
  if (!current)
    tx.run(
      tx.dialect.insert(
        'schema_fences',
        ['name', 'min_release', 'reason', 'set_at'],
        [[name, minRelease, reason, now]]
      )
    );
  else if (compareReleases(current.min_release, minRelease) < 0)
    tx.run(
      tx.dialect.update(
        'schema_fences',
        { min_release: minRelease, reason, set_at: now },
        sql`${id('name')} = ${name}`
      )
    );
  else return false;
  return true;
}

// ---------------------------------------------------------------------------------------------
// The runner.

const tableExists = (tx, name) =>
  Boolean(tx.get(sql`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ${name}`));

/**
 * A runner for one database. Options:
 *   db        the Db (lib/db/sqlite.mjs) to migrate
 *   classes   the store classes this database holds (SQLite: ['control'] or ['state', 'series'])
 *   steps     every step of this release (other databases' steps are ignored here)
 *   release   this release's version
 *   mode      'single' (SQLite) or 'cluster'
 *   context   extra values handed to every step as ctx (for example {fresh})
 *   snapshotHint  a snapshot id to name in refusal messages
 */
export function createMigrator({
  db,
  classes,
  steps,
  release,
  registry = defaultRegistry,
  mode = 'single',
  context = {},
  clock = Date.now,
  snapshotHint = null,
}) {
  parseRelease(release);
  const problems = validateSteps(steps, { release, registry });
  if (problems.length) throw new MigrationError('Invalid migration steps', problems);
  const mine = orderSteps(steps).filter(
    step => classes.includes(step.db) && (step.modes ?? ['single', 'cluster']).includes(mode)
  );
  const known = new Map(steps.map(step => [step.id, step]));
  const mineIds = new Set(mine.map(step => step.id));
  // Every step `step` needs first on this database: dependencyEdges() followed transitively,
  // keeping the steps recorded here (steps of other databases or modes are not).
  const edges = dependencyEdges(steps);
  const prerequisitesOf = step => {
    const found = new Set(),
      queue = [step.id];
    while (queue.length)
      for (const next of edges.get(queue.pop()) ?? [])
        if (!found.has(next)) {
          found.add(next);
          queue.push(next);
        }
    return [...found].filter(item => mineIds.has(item)).sort();
  };
  const hasFences = classes.includes('control');
  const engine = db.name;
  // Commands the operator can run as printed (no goblin-admin is on the PATH, admin-command.mjs).
  // The restore-snapshot line names the key file as a key command's does (`keyFile`: the one the
  // start read, else goblin-admin's own or the installer's), since restore-snapshot checks a
  // keyring it brings back with the key in its own environment (review F2v2).
  const restoreHint = (hint, keyFile = null) =>
    hint
      ? `restore snapshot ${hint} with Uptime Goblin stopped: ${adminCommand(`restore-snapshot ${hint}`, { key: true, keyFile })}`
      : `restore the snapshot taken before the upgrade with Uptime Goblin stopped; to list them: ${adminCommand('snapshots')}`;

  function readState(tx) {
    const applied = tableExists(tx, 'schema_migrations')
      ? tx.all(
          sql`SELECT ${id('id')}, ${id('component')}, ${id('kind')}, ${id('release')}, ${id('applied_at')} FROM ${id('schema_migrations')}`
        )
      : [];
    const fences =
      hasFences && tableExists(tx, 'schema_fences')
        ? tx.all(
            sql`SELECT ${id('name')}, ${id('min_release')}, ${id('reason')}, ${id('set_at')} FROM ${id('schema_fences')}`
          )
        : [];
    return { applied, fences };
  }

  function assess({ applied, fences }, hint = snapshotHint, keyFile = null) {
    const done = new Set(applied.map(row => row.id));
    const unknown = applied.filter(row => !known.has(row.id));
    const pending = mine.filter(step => !done.has(step.id));
    let refusal = null;
    // The rows named in a refusal are saved text that the start log and `goblin-admin status`
    // print: shown without control characters and cut, so a damaged or crafted row cannot forge
    // log lines or flood the terminal. The error's fields keep the values as stored.
    const contract = unknown.find(row => row.kind === 'contract');
    if (contract)
      refusal = new RefusalError(
        'data_newer',
        `This data was changed by Uptime Goblin ${printable(contract.release, 64)} (migration ${printable(contract.id, 100)}), which this release (${release}) cannot read. Install ${printable(contract.release, 64)} or newer, or ${restoreHint(hint, keyFile)}.`,
        { minRelease: contract.release, migration: contract.id }
      );
    const newer = fences
      .filter(fence => {
        try {
          return compareReleases(fence.min_release, coreRelease(release)) > 0;
        } catch {
          return true; // a version this release cannot parse is newer by definition
        }
      })
      .sort((a, b) => {
        try {
          return compareReleases(b.min_release, a.min_release);
        } catch {
          return 0;
        }
      });
    if (!refusal && newer.length)
      refusal = new RefusalError(
        'fence',
        `This data needs Uptime Goblin ≥ ${printable(newer[0].min_release, 64)} (${printable(newer[0].reason)}). Install ${printable(newer[0].min_release, 64)} or newer, or ${restoreHint(hint, keyFile)}.`,
        { minRelease: newer[0].min_release, fence: newer[0].name }
      );
    return {
      applied,
      fences,
      unknown,
      pending,
      pendingData: pending.filter(step => step.kind === 'data'),
      refusal,
    };
  }

  const stepContext = extra => ({
    ...context,
    engine,
    dialect: db.dialect,
    release,
    mode,
    registry,
    ...extra,
  });

  function record(tx, step) {
    tx.run(
      tx.dialect.insert(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [[step.id, step.component, step.kind, release, clock()]]
      )
    );
  }

  return Object.freeze({
    steps: mine,
    /** Applied, unknown and pending steps, fences, and the refusal if this release may not run. Reads only. */
    async inspect({ snapshotHint: hint, keyFile } = {}) {
      return assess(await db.read(readState), hint ?? snapshotHint, keyFile);
    },
    /**
     * What migrate() would do: the pending steps with their DDL on this engine (the plan for
     * `goblin-admin migrate --plan` and the installer's preflight). Reads only.
     */
    async plan(options) {
      const state = await this.inspect(options);
      return {
        ...state,
        steps: state.pending.map(step => ({
          id: step.id,
          kind: step.kind,
          db: step.db,
          description: step.description ?? '',
          ddl: Array.isArray(step.up?.createTables)
            ? step.up.createTables.flatMap(name => renderTable(db.dialect, registry.table(name)))
            : [],
        })),
      };
    },
    /**
     * Applies every pending expand and contract step, one unit each, after refusing as
     * inspect() says. Data steps are left for runData(). onProgress({step, index, total}) is
     * called before each step. Resolves to {applied: [ids], pendingData: [ids]}.
     */
    async migrate({ onProgress, snapshotHint: hint, keyFile } = {}) {
      const state = await this.inspect({ snapshotHint: hint, keyFile });
      if (state.refusal) throw state.refusal;
      const run = state.pending.filter(step => step.kind !== 'data');
      const applied = [];
      if (run.length && !(await db.read(tx => tableExists(tx, 'schema_migrations'))))
        await db.write(tx => {
          if (!tableExists(tx, 'schema_migrations'))
            tx.ddl(renderTable(db.dialect, registry.table('schema_migrations')));
        });
      for (const [index, step] of run.entries()) {
        onProgress?.({ step: step.id, index, total: run.length });
        const up = runnerFor(step, engine, registry);
        if (!up) throw new MigrationError(`${step.id} has no ${engine} version`);
        await db.write(tx => {
          // Another process may have applied it meanwhile (goblin.lock prevents that in SQLite
          // mode; server databases hold the migration lock).
          if (
            tx.get(
              sql`SELECT ${id('id')} FROM ${id('schema_migrations')} WHERE ${id('id')} = ${step.id}`
            )
          )
            return;
          const result = up(tx, stepContext({ step: step.id }));
          if (result !== undefined && result !== null && typeof result.then === 'function')
            throw new MigrationError(`${step.id} returned a promise; steps must be synchronous`);
          record(tx, step);
        });
        applied.push(step.id);
      }
      return { applied, pendingData: state.pendingData.map(step => step.id) };
    },
    /**
     * Runs the data step `stepId` in chunks until it reports {done: true}, recording it in the
     * same unit as its last chunk. Each chunk is one write unit: up(tx, ctx) does a bounded
     * amount of work, writes its own checkpoint in the same transaction, and returns
     * {done, progress?}. Stops (resolving {done: false}) when `signal` aborts.
     *
     * Every chunk's unit first checks, as migrate() does, that this release may run (no refusal:
     * an unknown applied contract step or a newer fence, which another process may have added
     * between chunks) and that the step's prerequisites are applied; otherwise it throws
     * RefusalError or MigrationError and writes nothing.
     */
    async runData(stepId, { signal, onProgress, snapshotHint: hint } = {}) {
      const step = mine.find(item => item.id === stepId && item.kind === 'data');
      if (!step) throw new MigrationError(`${stepId} is not a data step of this database`);
      const up = runnerFor(step, engine, registry);
      if (!up) throw new MigrationError(`${step.id} has no ${engine} version`);
      const needs = prerequisitesOf(step);
      for (let chunk = 0; ; chunk += 1) {
        if (signal?.aborted) return { done: false, chunks: chunk };
        const outcome = await db.write(tx => {
          if (!tableExists(tx, 'schema_migrations'))
            tx.ddl(renderTable(db.dialect, registry.table('schema_migrations')));
          const state = assess(readState(tx), hint ?? snapshotHint);
          if (state.refusal) throw state.refusal;
          const done = new Set(state.applied.map(row => row.id));
          if (done.has(step.id)) return { done: true, already: true };
          const missing = needs.filter(item => !done.has(item));
          if (missing.length)
            throw new MigrationError(
              `${step.id} cannot run before ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} applied`
            );
          const result = up(tx, stepContext({ step: step.id, chunk }));
          if (result?.done === true) record(tx, step);
          return result ?? { done: false };
        });
        onProgress?.({ step: step.id, chunk, progress: outcome.progress ?? null });
        if (outcome.done) return { done: true, chunks: chunk + 1 };
        await nextTurn();
      }
    },
  });
}

/** A random instance id (created once per installation and kept through restores). */
export const newInstanceId = () => randomUUID();
