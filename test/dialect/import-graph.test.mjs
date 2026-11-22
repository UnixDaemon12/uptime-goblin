// The import-graph rules (scripts/import-graph.mjs, roadmap §2.1 and §10.4) on a small tree
// that breaks each one, and on the repository itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  checkGraph,
  importsOf,
  resolve,
  tablesNamed,
  staticClosure,
  isDynamicOnly,
  PACKAGE_IMPORTERS,
  BOOT_ENTRIES,
} from '../../scripts/import-graph.mjs';
import { serverFiles } from '../../scripts/sql-lint.mjs';

const repository = fileURLToPath(new URL('../../', import.meta.url));

function tree(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-graph-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  return root;
}

// A registry double: two series tables, one state table shared with series, one control table.
const registry = {
  entries: {
    readings: { class: 'series' },
    alerts: { class: 'state' },
    latest: { class: 'state', shared: ['series'] },
    meta: { class: 'control' },
  },
  has(name) {
    return Object.hasOwn(this.entries, name);
  },
  table(name) {
    return this.entries[name];
  },
};

test('imports are read from code only: static, dynamic, and non-literal dynamic', () => {
  const source = [
    "import fs from 'node:fs';",
    'import {',
    '  a,',
    "} from './a.mjs';",
    "export * from '../b.mjs';",
    "import './side.mjs';",
    "const lazy = await import('./lazy.mjs');",
    'const bad = await import(name);',
    "// import x from './comment.mjs'; import('./comment2.mjs')",
    'const text = \'import y from "./string.mjs"\';',
    'const meta = import.meta.url;',
    // Other run-time loaders are imports too.
    "const raw = process.getBuiltinModule('node:sqlite');",
    "const viaRequire = createRequire(import.meta.url)('node:sqlite') ?? require('node:sqlite');",
    'const hidden = process.getBuiltinModule(name);',
    // Reached by a computed name: as unresolvable as a computed argument.
    "const keyed = process['getBuiltinModule']('node:sqlite');",
    "const viaReflect = Reflect.get(globalThis.process, 'require');",
    'const anyMember = process[key];',
  ].join('\n');
  const { imports, unresolvable } = importsOf(source);
  assert.deepEqual(
    imports.map(item => `${item.kind}:${item.specifier}`),
    [
      'static:node:fs',
      'static:./a.mjs',
      'static:../b.mjs',
      'static:./side.mjs',
      'dynamic:./lazy.mjs',
      'dynamic:node:sqlite',
      'dynamic:node:sqlite',
    ]
  );
  assert.deepEqual(
    [...unresolvable].sort((a, b) => a - b),
    [8, 13, 14, 15, 15, 16, 16, 17]
  );
  assert.deepEqual(resolve('lib/db/x.mjs', '../repo/y.mjs'), { module: 'lib/repo/y.mjs' });
  assert.deepEqual(resolve('lib/x.mjs', '@azure/identity/lib'), { package: '@azure/identity' });
  assert.deepEqual(resolve('lib/x.mjs', 'node:sqlite'), { package: 'node:sqlite' });
});

test('import declarations are read as declarations: string names, comments, defaults beside names', () => {
  // A name written as a string (ES2022) stopped the old match at its first quote, so these
  // imports were never recorded and node:sqlite or the Store's test seam passed the graph.
  const source = [
    "import { 'DatabaseSync' as Database } from 'node:sqlite';",
    "import { 'exposeStoreConnections' as open } from '../../store-connections.mjs';",
    'import {',
    '  // a comment',
    "  'a' as b, /* another */ c,",
    "} from './c.mjs';",
    "import d, { e } from './d.mjs';",
    "import f, * as g from './f.mjs';",
    "export { 'h' as 'i' } from './h.mjs';",
    "export * as 'j' from './j.mjs';",
    "import k from 'n\\u006fde:sqlite';",
    "const l = 1; import './side.mjs'; export { l };",
  ].join('\n');
  const { imports, unresolvable, unreadable } = importsOf(source);
  assert.deepEqual(
    imports.map(item => `${item.line}:${item.specifier}`),
    [
      '1:node:sqlite',
      '2:../../store-connections.mjs',
      '6:./c.mjs',
      '7:./d.mjs',
      '8:./f.mjs',
      '9:./h.mjs',
      '10:./j.mjs',
      '11:node:sqlite',
      '12:./side.mjs',
    ]
  );
  assert.deepEqual(unresolvable, []);
  assert.deepEqual(unreadable, []);
  // A declaration of another shape is refused, never skipped.
  assert.deepEqual(importsOf("import defer x from './x.mjs';").unreadable, [1]);
  assert.deepEqual(importsOf("import { a b } from './x.mjs';").unreadable, [1]);
  assert.deepEqual(importsOf("import defer * as x from './x.mjs';").unreadable, [1]);
});

test('a loader reached any way but by its name with a literal is unresolvable', () => {
  // Each of these loaded node:sqlite in a route while the graph saw nothing.
  for (const source of [
    "const { getBuiltinModule: builtin } = process;\nbuiltin('node:sqlite');",
    "export const b = () => process.getBuiltinModule.call(process, 'node:sqlite');",
    "import { createRequire as loader } from 'node:module';",
    'const load = createRequire;',
    'const p = process;',
    'f(process);',
    'const q = globalThis.process;',
    "const r = globalThis['process'];",
    "const s = Reflect.get(globalThis, 'pro' + 'cess');",
    "const t = process['getBuiltin' + 'Module'];",
    'const u = x[`require`];',
    'const v = eval(\'import("node:sqlite")\');',
    'const w = new Function(\'return import("node:sqlite")\');',
    'const y = (async () => {}).constructor(\'return import("node:sqlite")\');',
  ])
    assert.ok(importsOf(source).unresolvable.length > 0, source);
  // Called by name with a literal, ?.() included, it is a dynamic import of that module.
  assert.deepEqual(
    importsOf("process.getBuiltinModule?.('node:sqlite');\nrequire?.('node:fs');").imports.map(
      item => `${item.kind}:${item.specifier}`
    ),
    ['dynamic:node:sqlite', 'dynamic:node:fs']
  );
  // process and a constructor's name read as members stay fine.
  assert.deepEqual(
    importsOf(
      'const e = process.env.X ?? process?.argv;\nconst n = value?.constructor?.name;\nreport.process = 1;'
    ).unresolvable,
    []
  );
});

test('a loader call whose argument goes on after its first literal is unresolvable', () => {
  // Each was read as an import of its first literal ('../db/sq', 'node:', ''), and loaded
  // lib/db/sql.mjs, node:sqlite or the Store's test switch unseen.
  for (const source of [
    "const { fragment } = await import('../db/sq' + 'l.mjs');",
    "const m = await import('' || '../db/sql.mjs');",
    "const m = await import('../../store-conn' + 'ections.mjs');",
    "const m = process.getBuiltinModule('node:' + 'sqlite');",
    "const m = process.getBuiltinModule?.('node:sq'.concat('lite'));",
    "const m = require('node:sq' + 'lite');",
  ]) {
    const { imports, unresolvable } = importsOf(source);
    assert.deepEqual(imports, [], source);
    assert.deepEqual(unresolvable, [1], source);
  }
  assert.deepEqual(
    importsOf("const m = await import('./a.mjs', { with: {} });\nrequire('node:fs',);").imports.map(
      item => item.specifier
    ),
    ['./a.mjs', 'node:fs']
  );
});

test('code from a string is unresolvable however the Function constructor or a loader is reached', () => {
  for (const source of [
    "const make = (() => {})['constructor'];",
    "const make = Reflect.get(() => {}, 'construct' + 'or');",
    'const { constructor: make } = () => {};',
    'const pick = ({ constructor }) => constructor;',
    "const F = f['a', 'constructor'].includes(1);",
    'const run = globalThis.eval("import(\'node:sqlite\')");',
    "const F = globalThis.Function('return 1');",
    "const run = globalThis.global.eval('1');",
    "const run = global.globalThis.eval('1');",
    'const g = globalThis;',
    'const g = global;',
    "const c = process.binding('contextify');",
    'const d = process.dlopen;',
    'const l = process._linkedBinding;',
  ])
    assert.ok(importsOf(source).unresolvable.length > 0, source);
  // A class's constructor, a constructor's name, the word compared or looked up in a list of
  // literals, process's ordinary members and globalThis's other members stay fine.
  assert.deepEqual(
    importsOf(
      [
        'class A {\n  constructor(x) {\n    this.x = x;\n  }\n}',
        'const o = { a: 1, constructor() {} };',
        "const bad = k => k === 'constructor' || 'constructor' !== k;",
        "const reserved = k => ['__proto__', 'constructor', 'prototype'].includes(k);",
        'const n = value?.constructor?.name;',
        'const e = process.env.X ?? process.argv[2] ?? process.exitCode;',
        'const t = globalThis.setTimeout;',
      ].join('\n')
    ).unresolvable,
    []
  );
});

test('tables are found through id() literals and SQL text', () => {
  const isTable = name => ['readings', 'alerts'].includes(name);
  const source = [
    "const T = { r: id('readings') };",
    "const q = sql`SELECT 1 FROM ${id('alerts')} WHERE ${id('service')} = ${x}`;",
    "db.prepare('SELECT * FROM readings');",
    "const word = 'readings';",
  ].join('\n');
  assert.deepEqual(
    tablesNamed(source, isTable)
      .map(item => `${item.table}@${item.line}`)
      .sort(),
    ['alerts@2', 'readings@1', 'readings@3']
  );
});

test('each rule reports its violation', async t => {
  const root = tree(t, {
    'server.mjs': [
      "import { DatabaseSync } from 'node:sqlite';",
      "import { createPostgresDialect } from './lib/db/dialect/postgres.mjs';",
      "import { sql } from './lib/db/sql.mjs';",
      "const ok = await import('./lib/db/dialect/mssql.mjs');",
      'const unknown = await import(process.env.X);',
    ].join('\n'),
    'lib/db/sql.mjs': 'export const sql = 1;\n',
    'lib/db/sqlite.mjs': "import { DatabaseSync } from 'node:sqlite';\n",
    'lib/db/postgres.mjs': "import postgres from 'postgres';\n",
    'lib/db/dialect/postgres.mjs': "import { sql } from '../sql.mjs';\n",
    'lib/db/dialect/mssql.mjs': 'export {};\n',
    'lib/db/dialect/index.mjs': "const m = await import('./postgres.mjs');\n",
    'lib/net/outbound.mjs': 'export const request = 1;\n',
    'lib/repo/outbox.mjs': [
      "import { request } from '../net/outbound.mjs';",
      "import tedious from 'tedious';",
      "const q = sql`SELECT 1 FROM ${id('readings')}`;",
    ].join('\n'),
    'lib/repo/state/alerts.mjs':
      "const q = sql`SELECT 1 FROM ${id('alerts')} JOIN ${id('latest')} ON 1 = 1`;\n",
    'lib/series/v1.mjs':
      "const q = sql`SELECT 1 FROM ${id('readings')} JOIN ${id('latest')} ON 1 = 1 JOIN ${id('meta')} ON 1 = 1`;\n",
    'lib/series/v2/head.mjs': "import { x } from './codec.mjs';\n",
    'lib/series/v2/codec.mjs': 'export const x = 1;\n',
    'lib/cluster/roles.mjs': "import { head } from '../series/v2/head.mjs';\n",
    'lib/cluster/lease.mjs': 'export {};\n',
    'lib/jobs.mjs':
      "import { roles } from './cluster/roles.mjs';\nimport { lease } from './cluster/lease.mjs';\nimport '@azure/identity';\n",
    'lib/store.mjs':
      "import { DatabaseSync } from 'node:sqlite';\ndb.prepare('SELECT * FROM readings JOIN alerts');\n",
    // A route reaching a connection without an import statement.
    'lib/http/routes/raw.mjs':
      "const { DatabaseSync } = process.getBuiltinModule('node:sqlite');\nconst r = createRequire(import.meta.url);\n",
    // The Store's test seam is lib/store.mjs's alone, under any spelling of its path; a module
    // named by an absolute path, a file: URL or with a query is not one the graph follows.
    'lib/store-connections.mjs': 'export const exposeStoreConnections = () => {};\n',
    'lib/http/routes/seam.mjs': [
      "import { exposeStoreConnections } from '../../store-connections.mjs';",
      "import * as S from '../../http/../store-connections.mjs';",
      "import { sql } from '/opt/uptime-goblin/lib/db/sql.mjs';",
      "import { x } from 'file:///opt/uptime-goblin/lib/store-connections.mjs';",
      "import { y } from '../../store-connections.mjs?again';",
      "import { 'exposeStoreConnections' as open } from '../../store-connections.mjs';",
      "import { 'DatabaseSync' as D } from 'node:sqlite';",
      "import { createRequire } from 'module';",
      "import vm from 'node:vm';",
      "import defer * as later from './later.mjs';",
    ].join('\n'),
    // Spellings Node reads as another module than the text: a data: URL (re-exporting
    // node:sqlite), %-escapes, "\\", another case (a file system that ignores case loads it),
    // and node:inspector, whose Runtime.evaluate runs a string as code.
    'lib/http/routes/spelt.mjs': [
      'import D from \'data:text/javascript,export{DatabaseSync as default}from"node:sqlite"\';',
      "import { a } from '../../store%2Dconnections.mjs';",
      "import { b } from './..\\\\..\\\\store-connections.mjs';",
      "import { c } from '../../Store-Connections.mjs';",
      "import { Session } from 'node:inspector/promises';",
      "import { d } from '../../linked.mjs';",
      "import { e } from '../../aliased/store-connections.mjs';",
      "import { f } from '../../../public/shared/table.js';",
      "import { g } from './.hidden.mjs';",
    ].join('\n'),
    'lib/http/routes/.hidden.mjs': "import { DatabaseSync } from 'node:sqlite';\n",
    'public/shared/table.js': "export { DatabaseSync as f } from 'node:sqlite';\n",
    // A "/" the scanner cannot read: the import after it was hidden.
    'lib/http/routes/brace.mjs':
      "export const v = {} / `/;\n`; import { DatabaseSync } from 'node:sqlite';\n",
  });
  fs.symlinkSync('store-connections.mjs', path.join(root, 'lib', 'linked.mjs'));
  fs.symlinkSync('.', path.join(root, 'lib', 'aliased'));
  const findings = await checkGraph(root, serverFiles(root), { registry });
  const summary = findings.map(f => `${f.file}:${f.line} ${f.rule}`).sort();
  assert.deepEqual(summary, [
    'lib/aliased:1 module-link',
    'lib/http/routes/.hidden.mjs:1 driver-import',
    'lib/http/routes/brace.mjs:1 unreadable-code',
    'lib/http/routes/raw.mjs:1 driver-import',
    'lib/http/routes/raw.mjs:2 dynamic-import',
    'lib/http/routes/seam.mjs:1 module-importer',
    'lib/http/routes/seam.mjs:10 import-syntax',
    'lib/http/routes/seam.mjs:2 module-importer',
    'lib/http/routes/seam.mjs:3 module-specifier',
    'lib/http/routes/seam.mjs:4 module-specifier',
    'lib/http/routes/seam.mjs:5 module-specifier',
    'lib/http/routes/seam.mjs:6 module-importer',
    'lib/http/routes/seam.mjs:7 driver-import',
    'lib/http/routes/seam.mjs:8 driver-import',
    'lib/http/routes/seam.mjs:8 dynamic-import',
    'lib/http/routes/seam.mjs:9 driver-import',
    'lib/http/routes/spelt.mjs:1 module-specifier',
    'lib/http/routes/spelt.mjs:2 module-specifier',
    'lib/http/routes/spelt.mjs:3 module-specifier',
    'lib/http/routes/spelt.mjs:4 module-specifier',
    'lib/http/routes/spelt.mjs:5 driver-import',
    'lib/http/routes/spelt.mjs:6 module-specifier',
    'lib/http/routes/spelt.mjs:7 module-specifier',
    'lib/jobs.mjs:1 static-server-import',
    'lib/jobs.mjs:3 driver-import',
    'lib/linked.mjs:1 module-link',
    'lib/repo/outbox.mjs:1 repo-net',
    'lib/repo/outbox.mjs:2 driver-import',
    'lib/repo/outbox.mjs:2 static-server-import',
    'lib/repo/outbox.mjs:3 table-class',
    'public/shared/table.js:1 driver-import',
    'server.mjs:1 driver-import',
    'server.mjs:2 static-server-import',
    'server.mjs:3 sql-importer',
    'server.mjs:5 dynamic-import',
  ]);
  const byRule = Object.fromEntries(findings.map(f => [`${f.file} ${f.rule}`, f.message]));
  assert.match(
    byRule['lib/repo/outbox.mjs table-class'],
    /readings is a series table: only lib\/series\/\* may touch it/
  );
  assert.match(
    byRule['server.mjs driver-import'],
    /node:sqlite may be imported only by lib\/db\/sqlite\.mjs, lib\/store\.mjs/
  );
  assert.match(byRule['lib/jobs.mjs driver-import'], /nothing \(never\)/);

  const boot = staticClosure(root, ['server.mjs']);
  assert.ok(boot.modules.includes('lib/db/dialect/postgres.mjs'), 'the static edge is followed');
  assert.ok(!boot.modules.includes('lib/db/dialect/mssql.mjs'), 'the dynamic edge is not');
  assert.deepEqual(boot.packages, ['node:sqlite']);
});

test('the command line checks a tree and the boot closure', t => {
  const script = fileURLToPath(new URL('../../scripts/import-graph.mjs', import.meta.url));
  const root = tree(t, {
    'server.mjs': "import { x } from './lib/a.mjs';\n",
    'lib/a.mjs':
      "export const x = 1;\nexport const load = () => import('./db/dialect/mssql.mjs');\n",
    'lib/db/dialect/mssql.mjs': 'export {};\n',
  });
  let result = spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /3 server modules follow the import rules; boot loads 2 modules and no server-only code/
  );
  fs.writeFileSync(path.join(root, 'lib/a.mjs'), "export { x } from './db/dialect/mssql.mjs';\n");
  result = spawnSync(process.execPath, [script, '--root', root, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.deepEqual(
    JSON.parse(result.stdout)
      .map(f => f.rule)
      .sort(),
    ['boot-resolves-server-code', 'static-server-import']
  );
  // goblin-admin runs in SQLite mode too: its static imports are part of the boot closure.
  fs.writeFileSync(path.join(root, 'lib/a.mjs'), 'export const x = 1;\n');
  fs.mkdirSync(path.join(root, 'lib/cli'));
  fs.writeFileSync(
    path.join(root, 'lib/cli/goblin-admin.mjs'),
    "import { y } from './plan.mjs';\nconst lazy = () => import('../db/dialect/mssql.mjs');\n"
  );
  fs.writeFileSync(
    path.join(root, 'lib/cli/plan.mjs'),
    "export { mssql as y } from '../db/dialect/mssql.mjs';\n"
  );
  result = spawnSync(process.execPath, [script, '--root', root, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  const findings = JSON.parse(result.stdout);
  assert.deepEqual(findings.map(f => `${f.file} ${f.rule}`).sort(), [
    'lib/cli/plan.mjs static-server-import',
    'lib/db/dialect/mssql.mjs boot-resolves-server-code',
  ]);
  assert.match(findings.find(f => f.file === 'lib/db/dialect/mssql.mjs').message, /goblin-admin/);
});

// The table registry (lib/db/registry.mjs and what it imports) is server code. Imported into the
// lint's own process, a registry module that ended it with exit 0 would hide every finding; it
// runs in a child process instead, and a registry that cannot be read is itself a finding.
test('the table registry runs in a child process and cannot hide a finding', t => {
  const script = fileURLToPath(new URL('../../scripts/import-graph.mjs', import.meta.url));
  const run = () =>
    spawnSync(process.execPath, [script, '--root', root, '--json'], { encoding: 'utf8' });
  const rules = result => {
    assert.equal(result.status, 1, result.stderr);
    return JSON.parse(result.stdout)
      .map(f => `${f.file} ${f.rule}`)
      .sort();
  };
  const root = tree(t, {
    'server.mjs': 'export const load = name => import(name);\n',
    'lib/db/registry.mjs': 'process.exit(0);\n',
  });
  assert.deepEqual(rules(run()), [
    'lib/db/registry.mjs table-registry',
    'server.mjs dynamic-import',
  ]);
  const registry = path.join(root, 'lib/db/registry.mjs');
  for (const source of [
    "throw new Error('synthetic registry failure');\n",
    "console.log('not a table list');\nexport const registry = { tables: [] };\n",
    "export const registry = { tables: [{ name: 'readings' }] };\n",
  ]) {
    fs.writeFileSync(registry, source);
    const found = run();
    assert.deepEqual(
      rules(found),
      ['lib/db/registry.mjs table-registry', 'server.mjs dynamic-import'],
      source
    );
  }
  // Positive control: a registry that loads drives the table rule, and none is no finding.
  fs.writeFileSync(
    registry,
    "export const registry = { tables: [{ name: 'readings', class: 'series' }] };\n"
  );
  fs.writeFileSync(
    path.join(root, 'server.mjs'),
    "const q = sql`SELECT 1 FROM ${id('readings')}`;\n"
  );
  assert.deepEqual(rules(run()), ['server.mjs table-class']);
  fs.writeFileSync(registry, 'export const registry = null;\n');
  const none = run();
  assert.equal(none.status, 0, none.stderr);
});

// What the module-link rule reads, the server modules that are links, is read before the
// registry's child process runs, as the sources are: a registry module that removes such a link
// as it loads cannot hide it (integration of the tooling lane's child process with the boundary
// lane's module-link rule).
test('a server module that is a link is reported though the registry removes it as it loads', async t => {
  const root = tree(t, {
    'server.mjs': "import './lib/real.mjs';\n",
    'lib/real.mjs': 'export const value = 1;\n',
    'lib/db/registry.mjs':
      "import fs from 'node:fs';\nfs.rmSync(new URL('../linked.mjs', import.meta.url));\nexport const registry = null;\n",
  });
  const link = path.join(root, 'lib', 'linked.mjs');
  fs.symlinkSync('real.mjs', link);
  const findings = await checkGraph(root);
  assert.equal(fs.lstatSync(link, { throwIfNoEntry: false }), undefined, 'the registry ran');
  assert.deepEqual(
    findings.filter(f => f.rule === 'module-link').map(f => f.file),
    ['lib/linked.mjs']
  );
});

test('server-only modules and driver packages are named once', () => {
  for (const file of [
    'lib/db/dialect/postgres.mjs',
    'lib/db/dialect/mssql.mjs',
    'lib/db/postgres.mjs',
    'lib/db/mssql.mjs',
    'lib/cluster/roles.mjs',
    'lib/series/v2/head.mjs',
    'lib/series/codec.mjs',
  ])
    assert.ok(isDynamicOnly(file), file);
  for (const file of [
    'lib/db/dialect/sqlite.mjs',
    'lib/db/dialect/index.mjs',
    'lib/cluster/lease.mjs',
    'lib/series/v1.mjs',
  ])
    assert.ok(!isDynamicOnly(file), file);
  assert.deepEqual(PACKAGE_IMPORTERS.tedious, ['lib/db/mssql.mjs']);
  assert.deepEqual(PACKAGE_IMPORTERS['@azure/identity'], []);
});

// The gate: the shipped server code follows the import rules, and booting (server.mjs, the
// healthcheck and goblin-admin) statically reaches no server dialect, driver or cluster module.
test('the repository follows the import rules', async () => {
  const findings = await checkGraph(repository);
  assert.deepEqual(
    findings.map(f => `${f.file}:${f.line} ${f.rule}: ${f.message}`),
    [],
    'run node scripts/import-graph.mjs for details'
  );
  assert.deepEqual(BOOT_ENTRIES, [
    'server.mjs',
    'lib/healthcheck.mjs',
    'lib/cli/goblin-admin.mjs',
    'lib/cli/orbit-admin.mjs',
  ]);
  const present = BOOT_ENTRIES.filter(file => fs.existsSync(path.join(repository, file)));
  assert.ok(present.includes('server.mjs') && present.includes('lib/healthcheck.mjs'));
  const boot = staticClosure(repository, present);
  assert.deepEqual(boot.modules.filter(isDynamicOnly), []);
  for (const name of ['postgres', 'tedious', 'oauth4webapi', '@azure/identity'])
    assert.ok(!boot.packages.includes(name), name);
});
