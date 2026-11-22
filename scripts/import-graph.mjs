// The import-graph rules of roadmap §2.1 and §10.4, checked over the shipped server code
// (server.mjs, lib/**/*.mjs and every module they reach by a relative import, such as
// public/shared/*.js; serverFiles in scripts/sql-lint.mjs). Usage: node scripts/import-graph.mjs
// [--root <dir>] [--json]
//
// 1. Drivers: only the driver loaders import node:sqlite, postgres or tedious (lib/store.mjs
//    keeps its 1.x connection); oauth4webapi only lib/identity/oidc/client.mjs; the Azure SDKs
//    never (R47: Entra tokens go through oauth4webapi and lib/net/outbound.mjs); node:module,
//    node:vm, node:inspector and node:repl never (a loader, and code made from a string).
// 2. Server-only code is reached only by dynamic import(): the PostgreSQL and SQL Server
//    dialects and loaders, the cluster modules (except the 1.9 lease), series store v2 and its
//    codec, and the server drivers. A static import of them from anything else is refused, so
//    SQLite mode never resolves them. A dynamic import() names one literal path with nothing
//    added to it ('../db/sq' + 'l.mjs' named another module than its first literal).
// 3. Tables: only lib/series/* touches series tables and only lib/repo/state/* touches state
//    tables (classes and shared readers come from the table registry). A table is "touched" when
//    a module names it with id('…') or in SQL text. The 1.x store (lib/store.mjs) is exempt.
// 4. lib/repo never imports lib/net/* (a database token, when needed, comes from
//    lib/db/entra-token.mjs).
// 5. Only the SQL issuers (lib/db, lib/repo, lib/series, lib/store.mjs, lib/cluster/store.mjs)
//    import the query builder, lib/db/sql.mjs. (Dialects and the schema DSL are pure and may be
//    imported to render DDL, for example by `goblin-admin migrate --plan`.)
// 6. Booting in SQLite mode (the server, the healthcheck and the goblin-admin CLI) reaches no
//    server-only module through static imports.
// 7. Some modules have one importer among the server modules (MODULE_IMPORTERS): the switch
//    that opens the 1.x store's connection to tests is lib/store.mjs's alone. A module is named
//    only as the graph resolves it (specifierProblem in scripts/sql-lint.mjs): a plain relative
//    path to a .mjs or .js file, node:<builtin> or a package name. Node reads a %-escape, "\", a
//    space, a query or a fragment in a path as another file, and an absolute path or any URL
//    (file:, data:, which can re-export node:sqlite) can name any module. The file a relative
//    path names exists exactly as spelt, case included (a file system that ignores case loads
//    '../Store-Connections.mjs'), inside the tree and through no symbolic link, and no server
//    module or directory is a link (Node loads a link under its target's name).
// 8. Imports are read as declarations (moduleDeclarations in scripts/sql-lint.mjs): comments
//    inside them and names written as strings ({ 'DatabaseSync' as D }) count, and one of
//    another shape is refused (import-syntax). require(), getBuiltinModule() and createRequire()
//    are imports: called by name with one literal and nothing added to it (also as ?.()) they
//    are dynamic imports of it, and any other use of those names is unresolvable (.call(), a
//    reference taken out of process or imported under another name, a value or a literal with
//    more after it as the argument). So are those names written as a string however it is
//    spelt, process as a value (const p = process), a member of process other than
//    PROCESS_MEMBERS (process.binding('contextify') compiles code), globalThis or global as a
//    value, with a computed member or with their process, eval, Function, global or globalThis
//    (each an alias of the global object), eval, Function, and a function's constructor reached
//    by its name (.constructor, ['constructor'], { constructor: F } = f; the string
//    'constructor' is allowed only compared or looked up in a list of literals): code from a
//    string can import() anything. Code the scanner cannot read as JavaScript does (scan() in
//    scripts/sql-lint.mjs: a "/" after "}" or `of`, a "\" in code) is refused, since it would
//    hide the imports after it. A module name, loader or constructor computed at run time some
//    other way (picked from a list of an object's properties, say), and a worker or a child
//    process running code of its own, are beyond this lint.
//
// The table rule needs the table registry, which is server code; it is loaded in a child process
// (see loadRegistry), so nothing but the lint's own sources runs in this process.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  scan,
  serverFiles,
  isSqlIssuer,
  moduleDeclarations,
  dynamicImports,
  literalValues,
  specifierProblem,
  moduleLinks,
  UNREADABLE_CODE,
} from './sql-lint.mjs';

export const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

/** Packages and the only modules allowed to import them. */
export const PACKAGE_IMPORTERS = Object.freeze({
  'node:sqlite': Object.freeze(['lib/db/sqlite.mjs', 'lib/store.mjs']),
  // Loaders and code from strings: createRequire() and module.register(), and vm, which runs
  // a string as code that can import anything. A built-in is reached without node: too.
  'node:module': Object.freeze([]),
  module: Object.freeze([]),
  'node:vm': Object.freeze([]),
  vm: Object.freeze([]),
  // The inspector's Runtime.evaluate and a REPL's eval run a string as code, as vm does.
  'node:inspector': Object.freeze([]),
  inspector: Object.freeze([]),
  'node:repl': Object.freeze([]),
  repl: Object.freeze([]),
  postgres: Object.freeze(['lib/db/postgres.mjs']),
  tedious: Object.freeze(['lib/db/mssql.mjs']),
  oauth4webapi: Object.freeze(['lib/identity/oidc/client.mjs']),
  pg: Object.freeze([]),
  mssql: Object.freeze([]),
  '@azure/identity': Object.freeze([]),
  '@azure/keyvault-keys': Object.freeze([]),
});

/**
 * Server modules and the only server modules allowed to import them: the switch that opens a
 * Store's raw connection to tests (lib/store-connections.mjs) is lib/store.mjs's alone.
 */
export const MODULE_IMPORTERS = Object.freeze({
  'lib/store-connections.mjs': Object.freeze(['lib/store.mjs']),
});

/** Packages that must be loaded dynamically even by their allowed importer's callers. */
const DYNAMIC_PACKAGES = new Set(['postgres', 'tedious', 'oauth4webapi']);

/** Modules reached only through dynamic import(). */
export const DYNAMIC_ONLY = Object.freeze([
  /^lib\/db\/dialect\/(?:postgres|mssql)\.mjs$/,
  /^lib\/db\/(?:postgres|mssql|entra-token|pool-server)\.mjs$/,
  /^lib\/cluster\/(?!lease\.mjs$).+\.mjs$/,
  /^lib\/series\/v2\/.+\.mjs$/,
  /^lib\/series\/(?:codec|compact|planner)\.mjs$/,
]);
export const isDynamicOnly = file => DYNAMIC_ONLY.some(pattern => pattern.test(file));

/** Entry points that run in SQLite mode; their static imports must reach no server-only code. */
export const BOOT_ENTRIES = Object.freeze([
  'server.mjs',
  'lib/healthcheck.mjs',
  'lib/cli/goblin-admin.mjs',
  // Its name before the rename to Uptime Goblin: a shim that imports goblin-admin.
  'lib/cli/orbit-admin.mjs',
]);

/** Modules exempt from the table rule: the 1.x store predates the store classes. */
export const TABLE_RULE_EXEMPT = Object.freeze(['lib/store.mjs']);

const classHome = {
  series: file => file.startsWith('lib/series/'),
  state: file => file.startsWith('lib/repo/state/'),
  control: () => true,
};

/**
 * Every import in `source`: [{specifier, kind: 'static' | 'dynamic', line}], the lines of
 * loaders the graph cannot follow (`unresolvable`), of import or export declarations it cannot
 * read (`unreadable`, see moduleDeclarations: a name written as a string is read as its value),
 * and of code the scanner cannot read as JavaScript does (`unscannable`: [{line, why}], see
 * scan(), which would hide the imports after it).
 */
export function importsOf(source) {
  const scanned = scan(source);
  const { masked, lineOf } = scanned;
  const found = [],
    unresolvable = [];
  // Static: import … from '…', export … from '…' and import '…', however they are spread over
  // lines, with comments inside or names written as strings.
  const { declarations, unreadable } = moduleDeclarations(source, scanned);
  for (const declaration of declarations)
    found.push({ specifier: declaration.specifier, kind: 'static', line: declaration.line });
  // import() and the other ways to load a module at run time: require(),
  // process.getBuiltinModule() and the require of createRequire() reach node:sqlite as well as
  // import() does. Called by their name with one literal and nothing added to it (also as ?.()),
  // they are dynamic imports of it; any other use (a value or a literal with more after it as
  // the argument, .call(), a reference taken out of process or imported under another name) is
  // unresolvable (dynamicImports).
  const loaded = dynamicImports(source, scanned);
  found.push(...loaded.imports);
  unresolvable.push(...loaded.unresolvable);
  // What else reaches a loader unseen: one named by a string, however it is written
  // ('getBuiltin' + 'Module', `require`, Reflect.get(process, 'require')); process itself as a
  // value (const p = process, { getBuiltinModule: load } = process, process[name]), a member of
  // process that loads code (process.binding('contextify'), process.dlopen()), globalThis or
  // global as a value or with a computed member, and their process, eval, Function, global and
  // globalThis (globalThis.global is globalThis); code made from a string (eval, Function, a
  // function's constructor reached by its name: .constructor, ['constructor'],
  // { constructor } = f), which can import() anything.
  for (const { value, line, start, end } of literalValues(source, scanned))
    if (
      ['getBuiltinModule', 'require', 'createRequire', 'process', 'eval', 'Function'].includes(
        value
      ) ||
      (value === 'constructor' && !comparedOnly(masked, start, end))
    )
      unresolvable.push(line);
  for (const match of masked.matchAll(
    /(?<![\w$#])(?<!\.\s*)process(?![\w$])(?!\s*(?:\?\.|\.)\s*[A-Za-z_$])|(?<![\w$.#])(?:globalThis|global)(?![\w$])(?!\s*(?:\?\.|\.)\s*(?!(?:process|eval|Function|global|globalThis)(?![\w$]))[A-Za-z_$])|(?<![\w$.#])(?:eval|Function)(?![\w$])|(?:\?\.|\.)\s*constructor(?![\w$])(?!\s*(?:\?\.|\.)\s*name(?![\w$]))/g
  ))
    unresolvable.push(lineOf(match.index));
  for (const match of masked.matchAll(
    /(?<![\w$#])(?<!\.\s*)process\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)/g
  ))
    if (!PROCESS_MEMBERS.includes(match[1])) unresolvable.push(lineOf(match.index));
  // The word constructor but in a method's definition: { constructor: F } = () => {} takes the
  // Function constructor without a dot or a string.
  for (const match of masked.matchAll(/(?<![\w$#])(?<!(?:\?\.|\.)\s*)constructor(?![\w$])/g)) {
    const after = match.index + match[0].length;
    const open = after + /^\s*/.exec(masked.slice(after))[0].length;
    const definition =
      /(?:^|[;{},])\s*(?:static\s+)?$/.test(
        masked.slice(Math.max(0, match.index - 40), match.index)
      ) &&
      masked[open] === '(' &&
      /^\s*\{/.test(masked.slice(closingParenthesis(masked, open) + 1));
    if (!definition) unresolvable.push(lineOf(match.index));
  }
  return {
    imports: found,
    unresolvable,
    unreadable,
    unscannable: scanned.unreadable,
  };
}

/** The members of process server code may use; any other (binding, dlopen …) can load code. */
export const PROCESS_MEMBERS = Object.freeze([
  'env',
  'argv',
  'execArgv',
  'execPath',
  'exit',
  'exitCode',
  'pid',
  'ppid',
  'platform',
  'arch',
  'version',
  'versions',
  'on',
  'once',
  'off',
  'removeListener',
  'emitWarning',
  'stdin',
  'stdout',
  'stderr',
  'cwd',
  'umask',
  'getuid',
  'geteuid',
  'getgid',
  'getegid',
  'kill',
  'hrtime',
  'memoryUsage',
  'cpuUsage',
  'resourceUsage',
  'uptime',
  'nextTick',
  'constrainedMemory',
  'availableMemory',
  'getBuiltinModule',
]);

// The index of the ")" that closes the "(" at `open` (the end of the source if none).
function closingParenthesis(masked, open) {
  for (let depth = 0, i = open; i < masked.length; i += 1) {
    if (masked[i] === '(') depth += 1;
    else if (masked[i] === ')' && --depth === 0) return i;
  }
  return masked.length;
}

// Whether the literal at [start, end) is only compared (x === 'constructor') or looked for in an
// array of literals (['__proto__', 'constructor'].includes(key)): its value goes nowhere a
// member could be read with it.
function comparedOnly(masked, start, end) {
  if (
    /[!=]==?\s*$/.test(masked.slice(Math.max(0, start - 10), start)) ||
    /^\s*[!=]==?(?!>)/.test(masked.slice(end, end + 10))
  )
    return true;
  let open = start - 1;
  while (open >= 0 && /[\s,'"]/.test(masked[open])) open -= 1;
  // An array literal, not a computed member (f['a', 'constructor'] is f.constructor).
  if (masked[open] !== '[' || /[\w$)\]'"`]$/.test(masked.slice(0, open).trimEnd())) return false;
  let close = end;
  while (close < masked.length && /[\s,'"]/.test(masked[close])) close += 1;
  return (
    masked[close] === ']' &&
    /^\[(?:\s*(?:'[^']*'|"[^"]*")\s*,)*\s*(?:'[^']*'|"[^"]*")\s*,?\s*\]$/.test(
      masked.slice(open, close + 1)
    ) &&
    /^\s*\.\s*includes\s*\(/.test(masked.slice(close + 1))
  );
}

/** A relative import as a path from the root, a package name, or null for a builtin. */
export function resolve(from, specifier) {
  if (specifier.startsWith('./') || specifier.startsWith('../'))
    return { module: path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier)) };
  // node:inspector/promises is node:inspector's, as fs/promises is fs's.
  if (specifier.startsWith('node:')) return { package: specifier.split('/')[0] };
  const name = specifier.startsWith('@')
    ? specifier.split('/').slice(0, 2).join('/')
    : specifier.split('/')[0];
  return { package: name };
}

/** Table names a module touches: id('…') literals and names after FROM/JOIN/INTO/UPDATE in SQL text. */
export function tablesNamed(source, isTable) {
  const { strings, templates, masked, lineOf } = scan(source);
  const found = [];
  const note = (name, line) => {
    if (isTable(name)) found.push({ table: name, line });
  };
  // id('…') anywhere in code, including inside template expressions (masked keeps those).
  const byStart = new Map(strings.map(item => [item.start, item]));
  for (const match of masked.matchAll(/(?<![\w$])id\(\s*(?=['"])/g)) {
    const literal = byStart.get(match.index + match[0].length);
    if (literal) note(literal.text, lineOf(match.index));
  }
  const texts = [
    ...strings.map(item => ({ text: item.text, line: item.line })),
    ...templates.map(item => ({ text: item.parts.join(' '), line: item.line })),
  ];
  for (const { text, line } of texts)
    if (/\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b/.test(text))
      for (const match of text.matchAll(/\b(?:FROM|JOIN|INTO|UPDATE)\s+["[`]?([a-z_][a-z0-9_]*)/g))
        note(match[1], line);
  return found;
}

// Whether `relative` (a path from the root) is a file whose every step exists with exactly that
// name, case included, and is no symbolic link.
function existsAsSpelt(root, relative) {
  const parts = relative.split('/');
  if (parts.some(part => part === '..' || part === '.' || part === '')) return false;
  let directory = root;
  for (const [index, part] of parts.entries()) {
    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      return false;
    }
    const entry = entries.find(item => item.name === part);
    if (!entry || entry.isSymbolicLink()) return false;
    if (index < parts.length - 1 ? !entry.isDirectory() : !entry.isFile()) return false;
    directory = path.join(directory, part);
  }
  return true;
}

// Run in a child process: import the registry module named by the argument and print its table
// list (null when the module exports no registry).
const registryReader = `
const module = await import(process.argv[1]);
const registry = module.registry ?? module.default ?? null;
const tables = registry && registry.tables.map(table => ({
  name: table.name,
  class: table.class,
  shared: table.shared ?? [],
}));
process.stdout.write(JSON.stringify({ tables }));
`;

// The table registry, for the table rule. lib/db/registry.mjs and the modules it imports
// (lib/db/dialect/schema.mjs, lib/db/sql.mjs, lib/alerting/tables.mjs, lib/notify/limits.mjs
// today) are server code, not lint code: imported into this process, any of them could end it
// with exit 0 before a finding is printed. So a child process imports them and prints only the
// table list. Every source has been read before it starts, and a child that fails, exits early
// or prints anything else is a `table-registry` finding. The child can still report a wrong
// table list, so those modules are in this lint's review scope; the other rules do not use it.
// It also runs as the same user, so it can signal this process: SIGUSR1 would open this
// process's inspector, through which it could end the lint with exit 0, unless Node runs with
// --disable-sigusr1, as the security gate starts it.
function loadRegistry(root) {
  const file = path.join(root, 'lib', 'db', 'registry.mjs');
  if (!fs.existsSync(file)) return null;
  const child = spawnSync(
    process.execPath,
    ['--input-type=module', '--eval', registryReader, pathToFileURL(file).href],
    { encoding: 'utf8', maxBuffer: 16 * 1024 ** 2, timeout: 60000 }
  );
  if (child.error || child.status !== 0) {
    const detail = (child.error?.message ?? child.stderr ?? '').trim().split('\n').slice(0, 5);
    throw new Error(
      `the table registry could not be loaded (${child.signal ?? `exit ${child.status}`}): ${detail.join(' ')}`
    );
  }
  let tables;
  try {
    ({ tables } = JSON.parse(child.stdout));
  } catch {
    tables = undefined;
  }
  if (tables === null) return null;
  const valid = table =>
    typeof table?.name === 'string' &&
    typeof table.class === 'string' &&
    Array.isArray(table.shared) &&
    table.shared.every(storeClass => typeof storeClass === 'string');
  if (!Array.isArray(tables) || !tables.every(valid))
    throw new Error('the table registry did not give a table list');
  const byName = new Map(tables.map(table => [table.name, table]));
  return { has: name => byName.has(name), table: name => byName.get(name) };
}

/** Checks the graph of `files` under `root`. Returns [{file, line, rule, message}]. */
export async function checkGraph(root = repositoryRoot, files = serverFiles(root), options = {}) {
  // Every source is read before the registry's modules run (see loadRegistry), and so are the
  // server modules that are links: a registry module could remove one as it loads.
  const sources = new Map(
    files.map(file => [file, fs.readFileSync(path.join(root, file), 'utf8')])
  );
  const links = moduleLinks(root);
  const findings = [];
  const add = (file, line, rule, message) => findings.push({ file, line, rule, message });
  let registry = options.registry;
  if (registry === undefined) {
    // A registry that cannot be read is a finding; the other rules still run.
    try {
      registry = loadRegistry(root);
    } catch (error) {
      registry = null;
      add('lib/db/registry.mjs', 1, 'table-registry', error.message);
    }
  }
  const known = new Set(files);
  // A linked module is loaded under its target's name, which no rule here sees.
  for (const link of links)
    add(
      link,
      1,
      'module-link',
      "server code is a file or a directory, never a symbolic link: Node loads a link under its target's name"
    );
  for (const file of files) {
    const source = sources.get(file);
    const { imports, unresolvable, unreadable, unscannable } = importsOf(source);
    for (const { line, why } of unscannable)
      add(file, line, 'unreadable-code', UNREADABLE_CODE[why]);
    for (const line of unresolvable)
      add(
        file,
        line,
        'dynamic-import',
        'import() must name a literal path so the graph can be checked, and a loader is called by its name with one'
      );
    for (const line of unreadable)
      add(
        file,
        line,
        'import-syntax',
        "an import or export declaration the graph cannot read: write it as import … from '…'"
      );
    for (const { specifier, kind, line } of imports) {
      // A module is named as the graph resolves it (specifierProblem): an absolute path, a
      // file: or data: URL could reach any module unseen, and a query, a fragment, a %-escape or
      // a "\" loads one under another name.
      const problem = specifierProblem(specifier);
      if (problem) {
        add(file, line, 'module-specifier', problem);
        continue;
      }
      const target = resolve(file, specifier);
      // And the file it names exists exactly as spelt, through no link: a file system that
      // ignores case (macOS) loads '../Store-Connections.mjs' as lib/store-connections.mjs.
      if (target.module !== undefined && !existsAsSpelt(root, target.module)) {
        add(
          file,
          line,
          'module-specifier',
          `${specifier.slice(0, 80)} names no file exactly as spelt (case included), inside the tree and through no symbolic link`
        );
        continue;
      }
      if (target.package) {
        const allowed = PACKAGE_IMPORTERS[target.package];
        if (allowed && !allowed.includes(file))
          add(
            file,
            line,
            'driver-import',
            `${target.package} may be imported only by ${allowed.join(', ') || 'nothing (never)'}`
          );
        if (DYNAMIC_PACKAGES.has(target.package) && kind === 'static' && !isDynamicOnly(file))
          add(
            file,
            line,
            'static-server-import',
            `${target.package} is loaded only by dynamic import()`
          );
        continue;
      }
      const module = target.module;
      const importers = MODULE_IMPORTERS[module];
      if (importers && !importers.includes(file))
        add(
          file,
          line,
          'module-importer',
          `${module} may be imported only by ${importers.join(', ')}`
        );
      if (isDynamicOnly(module) && kind === 'static' && !isDynamicOnly(file))
        add(file, line, 'static-server-import', `${module} is server-only: reach it with import()`);
      if (file.startsWith('lib/repo/') && module.startsWith('lib/net/'))
        add(file, line, 'repo-net', 'lib/repo never imports lib/net (use lib/db/entra-token.mjs)');
      // Dialects and the schema DSL are pure (a CLI may render DDL); the query builder is not.
      if (module === 'lib/db/sql.mjs' && !isSqlIssuer(file) && known.has(module))
        add(
          file,
          line,
          'sql-importer',
          'only lib/db, lib/repo, lib/series and lib/store.mjs build SQL'
        );
    }
    if (!registry || TABLE_RULE_EXEMPT.includes(file) || file.startsWith('lib/db/')) continue;
    const isTable = name => registry.has(name);
    for (const { table, line } of tablesNamed(source, isTable)) {
      const entry = registry.table(table);
      const homes = [entry.class, ...(entry.shared ?? [])];
      if (!homes.some(storeClass => classHome[storeClass]?.(file)))
        add(
          file,
          line,
          'table-class',
          `${table} is a ${entry.class} table: only ${homes
            .map(storeClass =>
              storeClass === 'series'
                ? 'lib/series/*'
                : storeClass === 'state'
                  ? 'lib/repo/state/*'
                  : 'any repository'
            )
            .join(' or ')} may touch it`
        );
    }
  }
  return findings;
}

/** The modules `entries` reach through static imports only (what SQLite mode loads at boot). */
export function staticClosure(root, entries) {
  const reached = new Set(),
    packages = new Set(),
    queue = [...entries];
  while (queue.length) {
    const file = queue.shift();
    if (reached.has(file)) continue;
    reached.add(file);
    const absolute = path.join(root, file);
    if (!fs.existsSync(absolute) || !/\.(?:mjs|js)$/.test(file)) continue;
    for (const { specifier, kind } of importsOf(fs.readFileSync(absolute, 'utf8')).imports) {
      if (kind !== 'static') continue;
      const target = resolve(file, specifier);
      if (target.package) packages.add(target.package);
      else queue.push(target.module);
    }
  }
  return { modules: [...reached].sort(), packages: [...packages].sort() };
}

const isMain = () => {
  try {
    return (
      Boolean(process.argv[1]) &&
      fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
};
if (isMain()) {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');
  const rest = args.filter(arg => arg !== '--json');
  let root = repositoryRoot;
  if (rest[0] === '--root' && rest[1] && rest.length === 2) root = path.resolve(rest[1]);
  else if (rest.length) {
    console.error('Usage: node scripts/import-graph.mjs [--root <dir>] [--json]');
    process.exit(2);
  }
  const files = serverFiles(root);
  // The boot closure is read before checkGraph() starts the registry's child process.
  const entries = BOOT_ENTRIES.filter(file => fs.existsSync(path.join(root, file)));
  const boot = staticClosure(root, entries);
  const findings = await checkGraph(root, files);
  for (const module of boot.modules.filter(isDynamicOnly))
    findings.push({
      file: module,
      line: 1,
      rule: 'boot-resolves-server-code',
      message: `reached by a static import from ${entries.join(', ')}`,
    });
  if (asJson) console.log(JSON.stringify(findings, null, 2));
  else if (findings.length)
    for (const f of findings) console.error(`✖ ${f.file}:${f.line} ${f.rule}: ${f.message}`);
  else
    console.log(
      `✔ ${files.length} server modules follow the import rules; boot loads ${boot.modules.length} modules and no server-only code`
    );
  if (findings.length) process.exitCode = 1;
}
