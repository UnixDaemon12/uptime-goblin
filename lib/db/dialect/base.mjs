// What the three dialects share: rendering a Query into text and parameters, identifier checks
// against the table registry, and the statement builders whose syntax differs only in small
// places. Each engine's module (sqlite.mjs, postgres.mjs, mssql.mjs) supplies those places.
// This module imports no driver and performs no I/O.
import {
  Query,
  fragment,
  directive as dialectDirective,
  Identifier,
  Directive,
  JsonValue,
  SqlError,
  ERROR_CLASSES,
  MAX_PARAMS,
  sql,
  id,
  join,
  canonicalFloat,
  checkBigint,
} from '../sql.mjs';

export { SqlError, ERROR_CLASSES };

/** Turns a registry-like value into a membership test, or null for "no registry check". */
export function identifierCheck(identifiers) {
  if (identifiers === undefined || identifiers === null) return null;
  if (typeof identifiers === 'function') return identifiers;
  if (typeof identifiers.has === 'function') return name => identifiers.has(name);
  if (Array.isArray(identifiers)) {
    const names = new Set(identifiers);
    return name => names.has(name);
  }
  throw new SqlError('fatal', 'identifiers must be a Set, an array, a function or have has()');
}

const asIdentifier = name => (name instanceof Identifier ? name : id(name));

/**
 * Text every engine stores as given (§10.4 "Text rules"), or SqlError('poison'). A NUL is
 * refused, as PostgreSQL refuses it: SQLite stores it, but its length() stops there, so a text(n)
 * CHECK let any amount through after one. An unpaired surrogate is refused: it has no UTF-8 form,
 * and node:sqlite silently stored U+FFFD instead, so two different keys became one row and a key
 * never matched its own row again. Callers that bind text from outside Uptime Goblin clean it first
 * (toWellFormed, NUL removed); a refusal names the problem, never the value.
 */
export function storableText(value) {
  if (value.includes('\u0000')) throw new SqlError('poison', 'text contains a NUL character');
  if (!value.isWellFormed()) throw new SqlError('poison', 'text contains an unpaired surrogate');
  return value;
}

/**
 * Rows as arrays in `columns` order. `rows` is an array of rows (each an array in column order or
 * an object keyed by column name), or a single object.
 */
export function rowValues(columns, rows) {
  const list = Array.isArray(rows) ? rows : rows && typeof rows === 'object' ? [rows] : null;
  if (!list?.length) throw new SqlError('fatal', 'at least one row is needed');
  return list.map((row, index) => {
    if (Array.isArray(row)) {
      if (row.length !== columns.length)
        throw new SqlError(
          'fatal',
          `row ${index + 1} has ${row.length} values for ${columns.length} columns`
        );
      return row;
    }
    if (row === null || typeof row !== 'object')
      throw new SqlError('fatal', `row ${index + 1} is not an array or object`);
    return columns.map(column => {
      if (!Object.hasOwn(row, column))
        throw new SqlError('fatal', `row ${index + 1} has no value for ${column}`);
      return row[column];
    });
  });
}

/** Keeps the last row for each key (a batch may not name one key twice: §10.4, R57). */
export function dedupeRows(columns, keys, rows) {
  const positions = keys.map(key => {
    const at = columns.indexOf(key);
    if (at < 0) throw new SqlError('fatal', `key column ${key} is not in the column list`);
    return at;
  });
  const byKey = new Map();
  for (const row of rows) {
    const key = JSON.stringify(
      positions.map(at => {
        const value = row[at];
        return typeof value === 'bigint' ? `${value}n` : value;
      })
    );
    byKey.delete(key);
    byKey.set(key, row);
  }
  return { rows: [...byKey.values()], positions };
}

const compareValues = (a, b) => {
  if (a === b) return 0;
  if (a === null || a === undefined) return -1;
  if (b === null || b === undefined) return 1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'bigint' && typeof b === 'bigint') return a < b ? -1 : 1;
  const x = String(a),
    y = String(b);
  return x < y ? -1 : x > y ? 1 : 0;
};

/** Sorts rows by their key columns, so concurrent writers lock keys in one order. */
export function sortByKey(rows, positions) {
  return [...rows].sort((a, b) => {
    for (const at of positions) {
      const order = compareValues(a[at], b[at]);
      if (order) return order;
    }
    return 0;
  });
}

/**
 * Builds the parts every dialect has. `spec` supplies:
 *   name, caps, quote(name), placeholder(n, value), bind(value) -> driver value,
 *   json(placeholder) -> text, clock() -> Query, limit(n, offset), orderTerm(expr, desc, nulls),
 *   locks: {share: {hint, tail}, claim: {hint, tail}}, returning style ('suffix' | 'output'),
 *   classify(err), and catalog: {tables(), tableExists(name), columns(table), indexes()}.
 */
export function createDialect(spec) {
  const { name } = spec;
  const caps = Object.freeze({ maxParams: MAX_PARAMS, ...spec.caps });
  const tagged = (strings, values = []) => fragment(strings, values, name);
  const directive = (kind, emit) => dialectDirective(name, kind, emit);
  const text = value => tagged([value]);

  function quote(identifier) {
    return identifier.parts.map(part => spec.quote(part)).join('.');
  }
  const registered = identifierCheck(spec.identifiers);

  /**
   * Renders a Query as `{text, params}` (and `types` where the driver needs them). With
   * `identifiers` (the registry's names), every id() must be registered.
   */
  function render(query, options = {}) {
    if (!(query instanceof Query)) throw new SqlError('fatal', 'render() needs a sql`…` query');
    if (query.dialect && query.dialect !== name)
      throw new SqlError('fatal', `a ${query.dialect} fragment cannot be rendered as ${name}`);
    const known = identifierCheck(options.identifiers ?? spec.identifiers);
    const params = [],
      types = [];
    const state = {
      dialect: name,
      seen: new Set(),
      bind(value) {
        const bound = spec.bind(common(value));
        params.push(bound.value);
        types.push(bound.type);
        return spec.placeholder(params.length, bound);
      },
    };
    let out = '';
    query.strings.forEach((part, index) => {
      out += part;
      if (index === query.values.length) return;
      const value = query.values[index];
      if (value instanceof Identifier) {
        if (known && !known(value.name))
          throw new SqlError('fatal', `${value.name} is not in the table registry`);
        out += quote(value);
      } else if (value instanceof Directive) {
        // A directive's text is written verbatim: only this dialect's own are rendered.
        if (value.dialect !== name)
          throw new SqlError('fatal', `a ${value.dialect} fragment cannot be rendered as ${name}`);
        out += value.emit(state, out);
        state.seen.add(value.kind);
      } else if (value instanceof JsonValue) out += spec.json(state.bind(value.text));
      else out += state.bind(value);
    });
    if (params.length > caps.maxParams)
      throw new SqlError(
        'fatal',
        `the statement binds ${params.length} parameters; the limit is ${caps.maxParams}`
      );
    return spec.types ? { text: out, params, types } : { text: out, params };
  }

  // Values every engine binds the same way before its own conversion.
  function common(value) {
    if (typeof value === 'number') return canonicalFloat(value);
    if (typeof value === 'bigint') return checkBigint(value);
    if (typeof value === 'string') return storableText(value);
    if (value === null || typeof value === 'boolean') return value;
    if (value instanceof Uint8Array) return value;
    if (value instanceof Date)
      throw new SqlError('fatal', 'bind times as epoch milliseconds (a number), not a Date');
    throw new SqlError(
      'fatal',
      `cannot bind a ${value?.constructor?.name || typeof value}; use sql.json() for documents`
    );
  }

  const columnsOf = columns => {
    if (!Array.isArray(columns) || !columns.length)
      throw new SqlError('fatal', 'a column list is needed');
    return columns.map(column => (column instanceof Identifier ? column.name : id(column).name));
  };
  const valuesClause = rows => join(rows.map(row => sql`(${join(row)})`));

  /**
   * RETURNING (SQLite, PostgreSQL) or OUTPUT (SQL Server) for the builders' `returning` option.
   * The columns are id() values, so render() checks them against the registry like any other.
   */
  function returning(columns, source = 'inserted') {
    const names = columnsOf(columns);
    if (spec.returning === 'output') {
      if (!['inserted', 'deleted'].includes(source))
        throw new SqlError('fatal', 'returning(): the source is inserted or deleted');
      const prefix = text(`${source}.`);
      return sql`OUTPUT ${join(names.map(column => sql`${prefix}${id(column)}`))}`;
    }
    return sql`RETURNING ${join(names.map(column => id(column)))}`;
  }

  // The registry's columns of each table, when this dialect was given the registry: a builder
  // knows its table, so it refuses a column of another table (render() alone only knows that a
  // name is registered somewhere).
  const tableColumns =
    typeof spec.identifiers?.columnsOf === 'function' ? spec.identifiers.columnsOf : null;
  function checkColumns(table, ...lists) {
    if (!tableColumns) return;
    const name = asIdentifier(table).name;
    const columns = tableColumns(name);
    if (!columns) return; // not a registered table: render() refuses it
    for (const list of lists)
      for (const column of list ?? [])
        if (!columns.includes(column))
          throw new SqlError('fatal', `${column} is not a column of ${name}`);
  }
  const returned = options => (options?.returning ? columnsOf(options.returning) : []);
  const suffix = options =>
    options?.returning && spec.returning !== 'output'
      ? sql` ${returning(options.returning)}`
      : sql``;
  const output = (options, source = 'inserted') =>
    options?.returning && spec.returning === 'output'
      ? sql` ${returning(options.returning, source)}`
      : sql``;

  /** INSERT of one or more rows (arrays in column order, or objects). */
  function insert(table, columns, rows, options = {}) {
    const names = columnsOf(columns);
    checkColumns(table, names, returned(options));
    const values = rowValues(names, rows);
    return sql`INSERT INTO ${asIdentifier(table)} (${join(names.map(n => id(n)))})${output(options)} VALUES ${valuesClause(values)}${suffix(options)}`;
  }

  /** INSERT that skips rows whose key already exists (SQL Server: an IGNORE_DUP_KEY index). */
  function insertIgnore(table, columns, rows, options = {}) {
    checkColumns(
      table,
      columnsOf(columns),
      returned(options),
      options.conflict?.length ? columnsOf(options.conflict) : []
    );
    if (spec.insertIgnore) return spec.insertIgnore({ table, columns, rows, options, insert });
    const target = options.conflict?.length
      ? sql` (${join(columnsOf(options.conflict).map(n => id(n)))})`
      : sql``;
    const names = columnsOf(columns);
    const values = rowValues(names, rows);
    return sql`INSERT INTO ${asIdentifier(table)} (${join(names.map(n => id(n)))}) VALUES ${valuesClause(values)} ON CONFLICT${target} DO NOTHING${suffix(options)}`;
  }

  /**
   * Insert or update by key. Rows naming one key twice keep the last. `options.update` lists the
   * columns to overwrite (default: every non-key column; an empty list keeps existing rows).
   */
  function upsert(table, keys, columns, rows, options = {}) {
    const names = columnsOf(columns),
      keyNames = columnsOf(keys);
    const update = !options.update
      ? names.filter(n => !keyNames.includes(n))
      : options.update.length
        ? columnsOf(options.update)
        : [];
    for (const column of update)
      if (keyNames.includes(column) || !names.includes(column))
        throw new SqlError('fatal', `upsert(): cannot update ${column}`);
    checkColumns(table, names, keyNames, returned(options));
    const deduped = dedupeRows(names, keyNames, rowValues(names, rows));
    if (spec.sortKeys) deduped.rows = sortByKey(deduped.rows, deduped.positions);
    if (spec.upsert)
      return spec.upsert({
        table: asIdentifier(table),
        names,
        keyNames,
        update,
        ...deduped,
        options,
        returning,
      });
    const action = update.length
      ? sql`DO UPDATE SET ${join(update.map(column => sql`${id(column)} = ${text('excluded.')}${id(column)}`))}`
      : sql`DO NOTHING`;
    return sql`INSERT INTO ${asIdentifier(table)} (${join(names.map(n => id(n)))}) VALUES ${valuesClause(deduped.rows)} ON CONFLICT (${join(keyNames.map(n => id(n)))}) ${action}${suffix(options)}`;
  }

  /** UPDATE table SET … WHERE … (where is a sql fragment and is required). */
  function update(table, set, where, options = {}) {
    const entries = Object.entries(set || {});
    if (!entries.length) throw new SqlError('fatal', 'update() needs columns to set');
    checkColumns(
      table,
      entries.map(([column]) => column),
      returned(options)
    );
    if (!(where instanceof Query) || where.isEmpty)
      throw new SqlError('fatal', 'update() needs a WHERE fragment');
    const assignments = join(entries.map(([column, value]) => sql`${id(column)} = ${value}`));
    return sql`UPDATE ${asIdentifier(table)} SET ${assignments}${output(options)} WHERE ${where}${suffix(options)}`;
  }

  /** DELETE FROM table WHERE … (where is required). */
  function deleteFrom(table, where, options = {}) {
    if (!(where instanceof Query) || where.isEmpty)
      throw new SqlError('fatal', 'deleteFrom() needs a WHERE fragment');
    checkColumns(table, returned(options));
    return sql`DELETE FROM ${asIdentifier(table)}${output(options, 'deleted')} WHERE ${where}${suffix(options)}`;
  }

  /** `LIMIT n` in the engine's own form (SQL Server needs an ORDER BY first). */
  function limit(n, offset = 0) {
    for (const [label, value] of [
      ['limit', n],
      ['offset', offset],
    ])
      if (!Number.isSafeInteger(value) || value < (label === 'limit' ? 1 : 0))
        throw new SqlError(
          'fatal',
          `${label} must be ${label === 'limit' ? 'a positive' : 'a non-negative'} integer`
        );
    return tagged(['', ''], [directive('limit', state => spec.limit(state, n, offset))]);
  }

  /**
   * ORDER BY that states NULL ordering for every term (§10.4). A term is
   * `[column, 'asc'|'desc', 'first'|'last'|'not null']`; column is a name, id() or a fragment.
   * 'not null' declares the key never NULL (no NULLS clause is written).
   */
  function orderBy(...terms) {
    if (!terms.length) throw new SqlError('fatal', 'orderBy() needs at least one term');
    const rendered = terms.map((term, index) => {
      if (!Array.isArray(term) || term.length !== 3)
        throw new SqlError(
          'fatal',
          `orderBy() term ${index + 1} must be [column, direction, nulls]`
        );
      const [column, direction, nulls] = term;
      if (!['asc', 'desc'].includes(direction))
        throw new SqlError('fatal', `orderBy() term ${index + 1}: direction is asc or desc`);
      if (!['first', 'last', 'not null'].includes(nulls))
        throw new SqlError(
          'fatal',
          `orderBy() term ${index + 1}: nulls is first, last or 'not null'`
        );
      const expression = column instanceof Query ? column : asIdentifier(column);
      return spec.orderTerm(sql`${expression}`, direction === 'desc', nulls);
    });
    const marker = directive('orderBy', () => '');
    return sql`ORDER BY ${join(rendered)}${marker}`;
  }

  /** The database clock in epoch milliseconds (SQLite: the process clock, bound as a value). */
  const clockMs = () => spec.clock();

  /** Lock helpers: `lock.table(name)` in FROM, `lock.tail` at the end of the SELECT. */
  function lock(kind) {
    const { hint, tail } = spec.locks[kind];
    return Object.freeze({
      table: table =>
        hint ? sql`${asIdentifier(table)}${text(` ${hint}`)}` : sql`${asIdentifier(table)}`,
      tail: tail ? text(` ${tail}`) : sql``,
    });
  }

  function classify(error) {
    if (error && ERROR_CLASSES.includes(error.class)) return error.class;
    if (
      error?.name === 'AbortError' ||
      error?.name === 'TimeoutError' ||
      error?.code === 'ABORT_ERR'
    )
      return 'timeout';
    if (error?.code === 'ENOSPC' || error?.code === 'EDQUOT') return 'full';
    return spec.classify(error);
  }

  /**
   * Catalog queries, the portable way to ask what exists (migrations adopting a table, the
   * §10.5 drift check) instead of naming one engine's catalog: tables() → rows {name} of the
   * Uptime Goblin schema's tables (engine internals and partitions left out), tableExists(name) → one
   * row {present: 1} or none, columns(table) → rows {name} in column order, indexes() → rows
   * {name, table}. Names are bound as values; lists are ordered by name, columns by position.
   */
  const catalog = Object.freeze({
    tables: () => spec.catalog.tables(),
    tableExists(table) {
      if (typeof table !== 'string' || !table) throw new SqlError('fatal', 'catalog: a table name');
      return spec.catalog.tableExists(table);
    },
    columns(table) {
      if (typeof table !== 'string' || !table) throw new SqlError('fatal', 'catalog: a table name');
      return spec.catalog.columns(table);
    },
    indexes: () => spec.catalog.indexes(),
  });

  return Object.freeze({
    name,
    caps,
    executable: Boolean(spec.executable),
    catalog,
    // No `sql` here: a module holding a dialect (every transaction does) could call it as a
    // function with a forged template. Statements are written with the imported tag.
    /** The quoted form of a registered name (for DDL and messages). */
    id(identifier) {
      const value = asIdentifier(identifier);
      if (registered && !registered(value.name))
        throw new SqlError('fatal', `${value.name} is not in the table registry`);
      return quote(value);
    },
    render,
    bindValue: value => spec.bind(common(value)).value,
    insert,
    insertIgnore,
    upsert,
    update,
    deleteFrom,
    returning,
    limit,
    orderBy,
    clockMs,
    nowMs: clockMs,
    forShare: () => lock('share'),
    claim: () => lock('claim'),
    classify,
    ddl: spec.ddl,
  });
}

/** Builds a classify() from a table of codes (see each dialect for its table). */
export function classifier(lookups, fallback = 'fatal') {
  return error => {
    for (const lookup of lookups) {
      const found = lookup(error);
      if (found) return found;
    }
    return fallback;
  };
}
