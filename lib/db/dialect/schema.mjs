// The portable schema DSL (roadmap §10.5): one table definition, DDL for every engine. The table
// registry declares new tables with it; migration steps whose `up` is DSL render through
// renderTable(dialect, table). The hand-written 1.x SQLite tables (readings, latest, alerts,
// events) stay outside it (invariant 1).
//
//   import { table, text, bigint, json } from './schema.mjs';
//   export const settings = table('settings', {
//     class: 'control',
//     columns: { component: text(64), key: text(128), value: json(), version: bigint() },
//     primaryKey: ['component', 'key'],
//   });
//
// Types: id() (an auto-assigned 64-bit key, never reused), text(n) (at most n characters; key
// text uses a binary collation), bigint() (also every time, in epoch milliseconds), double(),
// bool(), bytes() and json(). Columns are NOT NULL unless marked .nullable().
import { SqlError, isIdentifier } from '../sql.mjs';

export const CLASSES = Object.freeze(['control', 'state', 'series']);
export const MODES = Object.freeze(['single', 'cluster']);
/** SQL Server's index key limits (§10.4 "Text rules"): clustered 900 B, nonclustered 1,700 B. */
export const KEY_BYTES = Object.freeze({ clustered: 900, nonclustered: 1700 });
/** The longest bounded text: SQL Server's varchar(4n) must stay within varchar(8000). */
export const MAX_TEXT = 2000;

class Column {
  constructor(type, options = {}) {
    Object.assign(
      this,
      { type, max: null, isKey: false, isNullable: false, defaultValue: undefined },
      options
    );
    Object.freeze(this);
  }
  /** Allows NULL. */
  nullable() {
    return new Column(this.type, { ...this, isNullable: true });
  }
  /** Marks text compared as a key (binary collation), even outside an index. */
  asKey() {
    return new Column(this.type, { ...this, isKey: true });
  }
  /** A literal default (number, string, boolean or null). */
  default(value) {
    if (!['number', 'string', 'boolean'].includes(typeof value) && value !== null)
      throw new SqlError('fatal', 'a default must be a number, string, boolean or null');
    return new Column(this.type, { ...this, defaultValue: value });
  }
}

export const id = () => new Column('id');
export function text(max) {
  if (max !== undefined && (!Number.isInteger(max) || max < 1 || max > MAX_TEXT))
    throw new SqlError('fatal', `text(n): n is 1 to ${MAX_TEXT}, or omitted for unbounded text`);
  return new Column('text', { max: max ?? null });
}
export const bigint = () => new Column('bigint');
export const double = () => new Column('double');
export const bool = () => new Column('bool');
export const bytes = () => new Column('bytes');
export const json = () => new Column('json');

const keyWidth = column => {
  if (column.type === 'text') {
    if (!column.max) return null;
    return column.max * 4;
  }
  if (column.type === 'bool') return 1;
  if (['id', 'bigint', 'double'].includes(column.type)) return 8;
  return null;
};

const fail = (table, message) => {
  throw new SqlError('fatal', `table ${table}: ${message}`);
};

function indexColumns(name, columns, entry, label) {
  if (!Array.isArray(entry) || !entry.length) fail(name, `${label} needs columns`);
  return entry.map(item => {
    const [column, direction = 'asc'] = Array.isArray(item) ? item : [item];
    if (!columns[column]) fail(name, `${label} names unknown column ${column}`);
    if (!['asc', 'desc'].includes(direction)) fail(name, `${label}: ${column} direction`);
    return Object.freeze({ column, desc: direction === 'desc' });
  });
}

function checkKeySize(name, columns, parts, limit, label) {
  let bytes = 0;
  for (const { column } of parts) {
    const width = keyWidth(columns[column]);
    if (width === null)
      fail(name, `${label}: ${column} (${columns[column].type}) cannot be part of a key`);
    bytes += width;
  }
  if (bytes > limit) fail(name, `${label} may need ${bytes} bytes; SQL Server allows ${limit}`);
}

const whereOps = ['=', '<>', 'is null', 'is not null'];

/**
 * Declares a table. Options: class (control | state | series), modes (default both), columns,
 * primaryKey (column list, or {columns, ignoreDuplicates}), unique ([{name?, columns,
 * ignoreDuplicates?}]), indexes ([{name?, columns (name or [name, 'desc']), where?}]; where is
 * [[column, '=' | '<>' | 'is null' | 'is not null', value?]]), withoutRowid (SQLite) and
 * partition ({column, interval: 'hour' | 'day' | 'month'}, server engines only).
 */
export function table(name, options) {
  if (!isIdentifier(name)) fail(name, 'the name is not a valid identifier');
  const { columns: given = {}, modes = MODES } = options;
  if (!CLASSES.includes(options.class)) fail(name, `class must be one of ${CLASSES.join(', ')}`);
  if (!Array.isArray(modes) || !modes.length || modes.some(mode => !MODES.includes(mode)))
    fail(name, `modes must be a non-empty list of ${MODES.join(', ')}`);
  const columns = {};
  for (const [column, type] of Object.entries(given)) {
    if (!isIdentifier(column)) fail(name, `column ${column} is not a valid identifier`);
    if (!(type instanceof Column)) fail(name, `column ${column} needs a DSL type`);
    columns[column] = type;
  }
  if (!Object.keys(columns).length) fail(name, 'a table needs columns');
  const idColumns = Object.keys(columns).filter(column => columns[column].type === 'id');
  if (idColumns.length > 1) fail(name, 'a table has at most one id() column');

  const pkOption = options.primaryKey ?? (idColumns.length ? idColumns : null);
  if (!pkOption) fail(name, 'a table needs a primary key');
  const pk = Array.isArray(pkOption) ? { columns: pkOption } : pkOption;
  const primaryKey = Object.freeze({
    columns: Object.freeze(indexColumns(name, columns, pk.columns, 'the primary key')),
    ignoreDuplicates: Boolean(pk.ignoreDuplicates),
  });
  for (const { column } of primaryKey.columns)
    if (columns[column].isNullable) fail(name, `primary key column ${column} cannot be nullable`);
  if (
    idColumns.length &&
    (primaryKey.columns.length !== 1 || primaryKey.columns[0].column !== idColumns[0])
  )
    fail(name, 'an id() column must be the whole primary key');
  checkKeySize(name, columns, primaryKey.columns, KEY_BYTES.clustered, 'the primary key');

  const names = new Set();
  const indexName = (given, parts, suffix) => {
    const chosen = given ?? `${name}_${parts.map(part => part.column).join('_')}_${suffix}`;
    if (!isIdentifier(chosen)) fail(name, `index name ${chosen} is not a valid identifier`);
    if (names.has(chosen)) fail(name, `index name ${chosen} is used twice`);
    names.add(chosen);
    return chosen;
  };
  const unique = (options.unique ?? []).map(entry => {
    const parts = indexColumns(name, columns, entry.columns, 'a unique index');
    checkKeySize(name, columns, parts, KEY_BYTES.nonclustered, 'a unique index');
    return Object.freeze({
      name: indexName(entry.name, parts, 'key'),
      columns: Object.freeze(parts),
      ignoreDuplicates: Boolean(entry.ignoreDuplicates),
    });
  });
  const indexes = (options.indexes ?? []).map(entry => {
    const parts = indexColumns(name, columns, entry.columns, 'an index');
    checkKeySize(name, columns, parts, KEY_BYTES.nonclustered, 'an index');
    const where = (entry.where ?? []).map(condition => {
      const [column, op, value] = condition;
      if (!columns[column]) fail(name, `index condition names unknown column ${column}`);
      if (!whereOps.includes(op)) fail(name, `index condition operator ${op}`);
      if (
        op.startsWith('is')
          ? condition.length !== 2
          : !['number', 'string', 'boolean'].includes(typeof value)
      )
        fail(name, `index condition on ${column} needs a literal value`);
      return Object.freeze({ column, op, value });
    });
    return Object.freeze({
      name: indexName(entry.name, parts, 'idx'),
      columns: Object.freeze(parts),
      where: Object.freeze(where),
    });
  });
  let partition = null;
  if (options.partition) {
    const { column, interval } = options.partition;
    if (!columns[column] || columns[column].type !== 'bigint')
      fail(name, 'the partition column must be a bigint (epoch milliseconds)');
    if (!['hour', 'day', 'month'].includes(interval)) fail(name, 'partition interval');
    const keys = [primaryKey, ...unique];
    if (keys.some(key => !key.columns.some(part => part.column === column)))
      fail(name, `every key must include the partition column ${column}`);
    partition = Object.freeze({ column, interval });
  }
  if (options.withoutRowid && idColumns.length)
    fail(name, 'withoutRowid tables cannot have an id() column');

  // Text that appears in any key is compared in binary everywhere.
  const keyed = new Set(
    [primaryKey, ...unique, ...indexes].flatMap(key => key.columns.map(part => part.column))
  );
  for (const column of keyed)
    if (columns[column].type === 'text' && !columns[column].isKey)
      columns[column] = columns[column].asKey();

  return Object.freeze({
    name,
    class: options.class,
    modes: Object.freeze([...modes]),
    columns: Object.freeze(columns),
    primaryKey,
    unique: Object.freeze(unique),
    indexes: Object.freeze(indexes),
    withoutRowid: Boolean(options.withoutRowid),
    partition,
  });
}

/** Dialects a migration step must provide for a table with these modes (§10.5 lint). */
export function requiredDialects(modes) {
  return modes.includes('single') ? ['sqlite', 'postgres', 'mssql'] : ['postgres', 'mssql'];
}

/** Every table and column name of these tables, for the registry's identifier allowlist. */
export function identifiersOf(tables) {
  const names = new Set();
  for (const entry of tables) {
    names.add(entry.name);
    for (const column of Object.keys(entry.columns)) names.add(column);
  }
  return names;
}

const literal = (value, booleans) => {
  if (value === null) return 'NULL';
  if (typeof value === 'boolean') return booleans(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new SqlError('fatal', 'a literal must be finite');
    return String(value);
  }
  return `'${String(value).replaceAll("'", "''")}'`;
};

/**
 * DDL statements for `table` in `dialect`'s rules (dialect.ddl). Returned as a list; migrations
 * run them in order inside one step.
 */
export function renderTable(dialect, spec) {
  const rules = dialect.ddl;
  if (!rules) throw new SqlError('fatal', `${dialect.name} has no DDL rules`);
  if (!spec.modes.includes('single') && rules.singleOnly)
    throw new SqlError('fatal', `${spec.name} is cluster-only and never exists in ${dialect.name}`);
  const q = rules.quote,
    value = item => literal(item, rules.boolean);
  const tableName = rules.tableName(spec.name);
  const lines = [];
  for (const [column, type] of Object.entries(spec.columns)) {
    let line = `${q(column)} ${rules.type(type)}`;
    if (type.type === 'id') {
      line = `${q(column)} ${rules.idColumn}`;
      lines.push(line);
      continue;
    }
    if (type.type === 'text' && type.isKey) line += ` ${rules.keyCollation}`;
    if (!type.isNullable) line += ' NOT NULL';
    if (type.defaultValue !== undefined) line += ` DEFAULT ${value(type.defaultValue)}`;
    for (const check of rules.checks(q(column), type)) line += ` CHECK (${check})`;
    lines.push(line);
  }
  const pkColumns = spec.primaryKey.columns;
  if (!(pkColumns.length === 1 && spec.columns[pkColumns[0].column].type === 'id' && rules.idIsKey))
    lines.push(
      rules.primaryKey(
        `${spec.name}_pkey`,
        pkColumns.map(part => q(part.column)),
        spec.primaryKey
      )
    );
  const statements = [rules.createTable(tableName, lines, spec)];
  const keyList = parts =>
    parts.map(part => `${q(part.column)}${part.desc ? ' DESC' : ''}`).join(', ');
  for (const entry of spec.unique)
    statements.push(
      rules.createIndex({
        ...entry,
        unique: true,
        table: tableName,
        keys: keyList(entry.columns),
        where: '',
      })
    );
  for (const entry of spec.indexes) {
    const where = entry.where
      .map(({ column, op, value: item }) =>
        op.startsWith('is')
          ? `${q(column)} ${op.toUpperCase()}`
          : `${q(column)} ${op} ${value(item)}`
      )
      .join(' AND ');
    statements.push(
      rules.createIndex({
        ...entry,
        unique: false,
        ignoreDuplicates: false,
        table: tableName,
        keys: keyList(entry.columns),
        where,
      })
    );
  }
  return statements;
}

/** The DDL for several tables as one script (for golden files and `migrate --plan`). */
export function renderSchema(dialect, tables) {
  return tables
    .filter(spec => !dialect.ddl.singleOnly || spec.modes.includes('single'))
    .map(
      spec =>
        `-- ${spec.name} (${spec.class}; ${spec.modes.join(', ')})\n${renderTable(dialect, spec)
          .map(statement => `${statement};`)
          .join('\n')}\n`
    )
    .join('\n');
}
