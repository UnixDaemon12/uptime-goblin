// The SQL lint (scripts/sql-lint.mjs, roadmap §10.4 "SQL rules"): its scanner, each rule on
// small sources, the legacy cap on lib/store.mjs, the command line, and the repository itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  scan,
  lintSource,
  lint,
  checkSqlText,
  serverFiles,
  FORBIDDEN,
  LEGACY,
  CONNECTION_HOLDERS,
  DRIVER_VALUES,
  isSqlIssuer,
  looksLikeSql,
  plainTexts,
  statementHash,
  moduleDeclarations,
  specifierProblem,
} from '../../scripts/sql-lint.mjs';

const repository = fileURLToPath(new URL('../../', import.meta.url));
const rules = findings => findings.map(finding => finding.rule);
const bt = '`';
// A repository module that imports the tag (the lint only reads the source).
const repo = body => `import { sql, id } from '../db/sql.mjs';\n${body}\n`;

test('the scanner finds strings, tagged templates and nested expressions, not comments', () => {
  const source = [
    "// const hidden = 'SELECT * FROM comment_only';",
    '/* sql`SELECT * FROM block_comment` */',
    "const a = 'it\\'s', b = \"x\";",
    'const r = /[\'"`]/g, half = total / 2 / 3;',
    "const q = sql`SELECT ${flag ? sql`${id('a')}` : sql`${id('b')}`} FROM ${id('t')}`;",
    'const plain = `text ${`inner ${1}`} end`;',
    'const ok = /re`gex/.test(y);',
  ].join('\n');
  const { strings, templates, masked } = scan(source);
  assert.deepEqual(
    strings.map(item => item.text),
    ["it\\'s", 'x', 'a', 'b', 't']
  );
  const tags = templates.map(item => item.tag);
  assert.deepEqual(tags, ['sql', 'sql', 'sql', null, null]);
  const outer = templates.find(item => item.parts[0] === 'SELECT ');
  assert.deepEqual(outer.parts, ['SELECT ', ' FROM ', '']);
  assert.equal(outer.expressions.length, 2);
  assert.equal(outer.line, 5);
  assert.doesNotMatch(masked, /comment_only|block_comment|SELECT/);
  assert.equal(masked.length, source.length);
  assert.equal(masked.split('\n').length, source.split('\n').length);
});

test('raw SQL is refused outside sql`…`, with advice by module', () => {
  assert.deepEqual(rules(lintSource('server.mjs', "db.prepare('SELECT a FROM readings');")), [
    'raw-sql',
    'raw-connection',
  ]);
  assert.match(
    lintSource('lib/http/x.mjs', "q('DELETE FROM x')")[0].message,
    /only lib\/db, lib\/repo/
  );
  assert.match(lintSource('lib/repo/x.mjs', "q('DELETE FROM x')")[0].message, /write it with sql/);
  assert.match(
    lintSource('lib/repo/x.mjs', `q(${bt}DELETE FROM \${table} WHERE a = 1${bt})`)[0].message,
    /\$\{…\} or \+ in a plain string/
  );
  // English text in upper and lower case is not SQL.
  assert.deepEqual(
    lintSource('server.mjs', "say('Select a source from the list'); say('DELETE')"),
    []
  );
  // The SQLite driver may send connection control, with its own checked settings spliced in.
  assert.deepEqual(
    lintSource(
      'lib/db/sqlite.mjs',
      `db.exec('PRAGMA journal_mode=WAL'); db.exec(${bt}PRAGMA busy_timeout=\${busyTimeoutMs}${bt}); db.exec('BEGIN IMMEDIATE'); db.exec('COMMIT');`
    ),
    []
  );
  // Anything else is raw SQL, and no statement the driver's connection may take.
  assert.deepEqual(
    rules(lintSource('lib/db/sqlite.mjs', "db.exec('INSERT INTO meta VALUES (1)')")),
    ['raw-sql', 'raw-connection']
  );
  // No other module holds a connection: its control statements are raw SQL too.
  assert.deepEqual(rules(lintSource('lib/db/driver.mjs', "db.exec('PRAGMA journal_mode=WAL')")), [
    'raw-sql',
    'raw-connection',
  ]);
  assert.deepEqual(rules(lintSource('lib/db/nested/x.mjs', "db.exec('PRAGMA x=1')")), [
    'raw-sql',
    'raw-connection',
  ]);
  // The dialects write engine text by design.
  assert.deepEqual(
    lintSource(
      'lib/db/dialect/mssql.mjs',
      "const x = 'MERGE INTO t USING s'; sql`ORDER BY x LIMIT 1`"
    ),
    []
  );
  assert.deepEqual(lintSource('lib/db/sql.mjs', "const x = 'SELECT a FROM b';"), []);
});

test('sql`…` is written only by lib/db, lib/repo, lib/series and lib/store.mjs', () => {
  const body = repo(`const q = sql${bt}SELECT \${id('a')} FROM \${id('t')}${bt};`);
  assert.deepEqual(rules(lintSource('lib/http/router.mjs', body)), ['sql-outside-repositories']);
  assert.deepEqual(rules(lintSource('server.mjs', body)), ['sql-outside-repositories']);
  for (const file of [
    'lib/repo/a.mjs',
    'lib/repo/state/b.mjs',
    'lib/series/v1.mjs',
    'lib/db/c.mjs',
    'lib/store.mjs',
  ])
    assert.deepEqual(lintSource(file, body), [], file);
  assert.ok(isSqlIssuer('lib/cluster/store.mjs'));
  assert.ok(!isSqlIssuer('lib/cluster/roles.mjs'));
});

test('each refused construct is reported inside sql`…` text', () => {
  const cases = {
    'bare-limit': ['LIMIT 10', 'OFFSET 5 ROWS', 'FETCH NEXT 1 ROWS ONLY', 'SELECT TOP (5) 1'],
    merge: ['MERGE INTO ${id} USING ${id} ON 1 = 1'],
    'insert-or-replace': [
      'INSERT OR REPLACE INTO ${id} VALUES (1)',
      'REPLACE INTO ${id} VALUES (1)',
      'INSERT OR IGNORE INTO ${id} VALUES (1)',
    ],
    'raw-returning': ['DELETE FROM ${id} RETURNING *', 'OUTPUT INSERTED.*'],
    'raw-upsert': ['INSERT INTO ${id} VALUES (1) ON CONFLICT DO NOTHING'],
    'raw-order-by': ['SELECT 1 FROM ${id} ORDER BY 1'],
    'raw-lock': [
      'SELECT 1 FROM ${id} FOR UPDATE',
      'SELECT 1 FROM ${id} WITH (NOLOCK)',
      'FOR SHARE',
    ],
    clock: [
      'SELECT now()',
      'SELECT GETDATE()',
      'SELECT CURRENT_TIMESTAMP',
      'SELECT clock_timestamp()',
      "SELECT unixepoch('now')",
      'SELECT SYSUTCDATETIME()',
    ],
    datetime: ["SELECT datetime('now')", 'CAST(1 AS datetime2)', "SELECT strftime('%s')"],
    'time-zone': ['SELECT ${id} AT TIME ZONE ${id}'],
    attach: ["ATTACH DATABASE 'x' AS ${id}", 'DETACH ${id}', 'attach ${id} as y'],
    'engine-control': ['PRAGMA writable_schema = 1', 'VACUUM', 'pragma ${id}'],
    'multiple-statements': ['SELECT 1 FROM ${id}; DELETE FROM ${id}', 'SELECT 1;DROP TABLE ${id}'],
  };
  for (const [rule, texts] of Object.entries(cases))
    for (const text of texts) {
      const found = rules(checkSqlText(text.replaceAll('${id}', '\u0001')));
      assert.ok(found.includes(rule), `${rule}: ${text} → ${found.join(', ')}`);
    }
  assert.deepEqual(FORBIDDEN.map(([rule]) => rule).sort(), Object.keys(cases).sort());
  // Words inside '…' literals are data, not SQL.
  assert.deepEqual(checkSqlText("SELECT 1 FROM \u0001 WHERE \u0001 = 'ORDER BY LIMIT now()'"), []);
  // A column that merely contains a keyword is fine.
  assert.deepEqual(checkSqlText('SELECT \u0001 FROM \u0001 WHERE \u0001 = \u0001'), []);
});

test('identifiers come through id(); aliases, CTE names and functions are allowed', () => {
  assert.deepEqual(rules(checkSqlText('SELECT service FROM \u0001')), ['bare-identifier']);
  assert.deepEqual(rules(checkSqlText('SELECT 1 FROM READINGS')), ['bare-table']);
  assert.deepEqual(rules(checkSqlText('SELECT "service" FROM \u0001')), ['quoted-identifier']);
  assert.deepEqual(rules(checkSqlText('SELECT [service] FROM \u0001')), ['quoted-identifier']);
  assert.deepEqual(rules(checkSqlText('SELECT \u0001 AS key FROM \u0001')), ['reserved-alias']);
  assert.deepEqual(rules(checkSqlText('SELECT \u0001 FROM \u0001 AS user')), ['reserved-alias']);
  assert.deepEqual(
    checkSqlText(
      'WITH ordered AS (SELECT \u0001 AS marker FROM \u0001), totals AS (SELECT 1) SELECT b.*, coalesce(\u0001, 0) AS total, COUNT(*) AS n FROM ordered b JOIN totals t ON t.x = b.marker WHERE marker AND \u0001 IS DISTINCT FROM \u0001'
    ),
    []
  );
  assert.deepEqual(rules(checkSqlText('SELECT l.service FROM \u0001 l')), ['bare-identifier']);
  assert.deepEqual(
    checkSqlText('SELECT \u0001 FROM \u0001 l WHERE \u0001 IN (SELECT \u0001 FROM \u0001)'),
    []
  );
});

test('dialect internals and sql(…) calls are refused outside lib/db', () => {
  assert.deepEqual(
    rules(
      lintSource(
        'lib/repo/x.mjs',
        "import { sql, fragment, Query } from '../db/sql.mjs';\nconst q = sql(['SELECT 1']);"
      )
    ),
    ['internal-api', 'internal-api', 'internal-api']
  );
  assert.deepEqual(
    lintSource(
      'lib/repo/x.mjs',
      "import { sql } from '../db/sql.mjs';\nconst mysql = 1; // sql(x) in a comment\n"
    ),
    []
  );
  assert.deepEqual(lintSource('lib/http/x.mjs', 'function sql(x) { return x; }\nsql(1);'), []);
  // fragment() and directive() write any string as SQL text: the dialects alone may use them,
  // not the rest of lib/db.
  const textInternals =
    "import { fragment, directive } from './sql.mjs';\nfragment(['x'], [], 'sqlite');";
  assert.deepEqual(rules(lintSource('lib/db/x.mjs', textInternals)), [
    'internal-api',
    'internal-api',
  ]);
  assert.deepEqual(
    lintSource('lib/db/dialect/x.mjs', "import { fragment } from '../sql.mjs';"),
    []
  );
  // Every spelling of the module's path is the module: './' and '../' steps, a query or a
  // fragment (a second instance of it), an absolute path, a file: URL and another case (which a
  // file system that ignores case loads). A match on the text 'db/sql.mjs' let these through.
  // A spelling other than a plain relative path is refused as well (module-specifier).
  for (const specifier of [
    '../db/./sql.mjs',
    '../http/../db/sql.mjs',
    '../db/SQL.mjs',
    '../db/sql.mjs?again',
    '../db/sql.mjs#x',
    '/opt/uptime-goblin/lib/db/sql.mjs',
    'file:///opt/uptime-goblin/lib/db/sql.mjs',
  ]) {
    const plain = /^\.\.\/[\w./]+$/.test(specifier);
    const found = source => {
      const all = rules(lintSource('lib/repo/x.mjs', source));
      assert.equal(all.includes('module-specifier'), !plain, `${source}: ${all}`);
      return all.filter(rule => rule !== 'module-specifier');
    };
    assert.deepEqual(
      found(`import { fragment, directive } from '${specifier}';`),
      ['internal-api', 'internal-api'],
      specifier
    );
    assert.deepEqual(found(`import { sql as tag } from '${specifier}';\ntag(s);`), [
      'internal-api',
    ]);
    assert.deepEqual(found(`import * as S from '${specifier}';`), ['internal-api'], specifier);
    assert.deepEqual(found(`const S = await import('${specifier}');`), ['internal-api'], specifier);
  }
  // Another module of that name is not it.
  assert.deepEqual(lintSource('lib/repo/x.mjs', "import { fragment } from './sql.mjs';"), []);
  // A declaration is read as one, however it is written: a comment inside the braces, a name
  // written as a string (ES2022), escaped, a default import beside names or a namespace. A
  // match on `import {` and its text found none of these.
  for (const source of [
    "import {\n  // the dialect's helper\n  fragment,\n} from '../db/sql.mjs';",
    "import { /* x */ fragment /* y */ as make } from '../db/sql.mjs';",
    "import { 'fragment' as make } from '../db/sql.mjs';",
    "import { 'fr\\x61gment' as make } from '../db/sql.mjs';",
    "export { 'fragment' as 'make' } from '../db/sql.mjs';",
    "import { sql } from '../db/sql.mjs'; import { fragment } from '../db/sql.mjs';",
  ])
    assert.deepEqual(rules(lintSource('lib/repo/x.mjs', source)), ['internal-api'], source);
  for (const source of [
    "import tag, { id } from '../db/sql.mjs';",
    "import tag, * as S from '../db/sql.mjs';",
    "import tag from '../db/sql.mjs';",
  ])
    assert.ok(rules(lintSource('lib/repo/x.mjs', source)).includes('internal-api'), source);
  // The tag under a string name is still the tag; a call of it on the line of an import too.
  assert.deepEqual(
    rules(lintSource('lib/repo/x.mjs', "import { 'sql' as tag } from '../db/sql.mjs';\ntag(s);")),
    ['internal-api']
  );
  assert.deepEqual(
    rules(lintSource('lib/repo/x.mjs', "import { sql } from '../db/sql.mjs'; sql(s);")),
    ['internal-api']
  );
});

test('the legacy store may not add or change a raw statement, even one without a refused construct', () => {
  const file = 'lib/store.mjs';
  const source = fs.readFileSync(path.join(repository, file), 'utf8');
  assert.deepEqual(lintSource(file, source), [], 'lib/store.mjs keeps its frozen statements');
  // Statements it has, written as it writes them (white space aside), pass.
  const kept = "this.#prepare('DELETE FROM alerts WHERE service=? AND rule=?').run(a, b);";
  assert.deepEqual(lintSource(file, kept), []);
  assert.deepEqual(
    lintSource(file, "this.#prepare(\n  'DELETE FROM alerts   WHERE service=? AND rule=?'\n);"),
    []
  );
  // Anything else is refused: new statements without a refused construct, a changed column,
  // a new or different ${…}, lower case, a statement split over literals, a control statement.
  for (const added of [
    `this.#prepare(${bt}SELECT * FROM readings WHERE service='\${id}'${bt}).all();`,
    `this.#prepare(${bt}delete from readings where service='\${id}'${bt}).run();`,
    "this.#prepare('DELETE FROM alerts WHERE service=? OR rule=?').run(a, b);",
    "this.#prepare('SELECT * FROM users').all();",
    "this.#prepare('DELETE FROM alerts ' + 'WHERE service=' + id).run();",
    `this.#prepare(${bt}PRAGMA \${other}${bt});`,
    "this.#db.exec('PRAGMA writable_schema=1');",
    `this.#db.exec(${bt}DELETE FROM \${table} WHERE service='\${id}'${bt});`,
    // Lower case with no value in it: no "evidence" of SQL, but a statement all the same, and
    // anything handed to a connection is SQL by where it goes.
    "wipe() { this.#db.exec('drop table readings'); }",
    "wipe() { this.#prepare('delete from alerts').run(); }",
    "this.#db.exec('vacuum');",
  ])
    assert.ok(rules(lintSource(file, added)).includes('legacy-sql'), added);
  // A statement passed in a variable is no literal the freeze can see.
  assert.deepEqual(rules(lintSource(file, 'this.#db.exec(statementFromElsewhere);')), [
    'raw-connection',
  ]);
  assert.deepEqual(rules(lintSource(file, 'this.#drain(built, [id]);')), ['raw-connection']);
  // Statements it has, with a value joined on with + (the freeze hashed the literals alone, so
  // a clause built from a rule key passed), or changed by a method called on the literal.
  const clearAlerts =
    "  clearAlerts(id) {\n    this.#prepare('DELETE FROM alerts WHERE service=?').run(id);\n  }";
  assert.ok(source.includes(clearAlerts), 'clearAlerts as the cases below change it');
  for (const changed of [
    "  clearAlerts(id, rule) {\n    const clause = rule ? ` AND rule='${rule}'` : '';\n    this.#prepare('DELETE FROM alerts WHERE service=?' + clause).run(id);\n  }",
    "  clearAlerts(id, prefix) {\n    this.#prepare(prefix + 'DELETE FROM alerts WHERE service=?').run(id);\n  }",
    "  clearAlerts(id, rule) {\n    this.#prepare('DELETE FROM alerts WHERE service=?'.concat(rule)).run(id);\n  }",
    // A statement routed through the names the connection's sites take (text, name), built
    // from words or written in lower case: the variable is bound where no site lists it.
    "  clearAlerts(id) {\n    const text = ['drop', 'table', 'alerts'].join(' ');\n    this.#db.exec(text);\n  }",
    "  clearAlerts(id) {\n    const text = 'vacuum';\n    this.#db.exec(text);\n  }",
    "  clearAlerts(id) {\n    const name = 'writable_schema=1';\n    return this.#pragma(name);\n  }",
    "  clearAlerts(id) {\n    return this.#pragma('writable_schema=1');\n  }",
    // A connection's sink taken as a value, or reached by a computed key.
    "  clearAlerts(id) {\n    const run = this.#db.exec.bind(this.#db);\n    run('DELETE FROM alerts');\n  }",
    "  clearAlerts(id, key) {\n    this.#db[key]('DELETE FROM alerts');\n  }",
  ]) {
    const found = rules(lintSource(file, source.replace(clearAlerts, changed)));
    assert.ok(
      found.length > 0 && found.every(rule => ['legacy-sql', 'raw-connection'].includes(rule)),
      `${changed}: ${found}`
    );
  }
  // The listed sites themselves, their variable bound or changed again there.
  for (const [site, changed] of [
    ['#prepare(text) {\n', '#prepare(text) {\n    text = text + globalThis.extra;\n'],
    ['#prepare(text) {\n', '#prepare(text) {\n    [text] = [globalThis.extra];\n'],
    ['#prepare(text) {\n', '#prepare(text) {\n    const more = text => text;\n'],
    ['#query(query) {\n', '#query(query) {\n    let text;\n'],
  ]) {
    assert.ok(source.includes(site), site);
    assert.deepEqual(
      rules(lintSource(file, source.replace(site, changed))),
      ['raw-connection'],
      changed
    );
  }
  // Every frozen statement is in the file: the list holds nothing it no longer has.
  const hashes = new Set(plainTexts(source).map(item => statementHash(item.code)));
  for (const hash of LEGACY[file]) assert.ok(hashes.has(hash), hash);
});

test('raw SQL in any case, split across literals, or passed to prepare/exec as a variable is refused', () => {
  // Lower case, which the upper-case detection did not see.
  for (const [file, source] of [
    ['lib/http/routes/x.mjs', "export const f = v => q('select * from users where login = ' + v);"],
    [
      'lib/repo/x.mjs',
      `export const f = v => q(${bt}select * from users where login = '\${v}'${bt});`,
    ],
    ['lib/repo/x.mjs', "q('delete from readings where service = ?');"],
    ['lib/repo/x.mjs', "q('Update meta Set value = 1');"],
    // Split over literals, directly or around values.
    ['lib/repo/x.mjs', "export const f = v => q('SELECT * ' + 'FROM users WHERE login = ' + v);"],
    ['lib/repo/x.mjs', "q('SELECT ' + columns + ' FROM ' + table + ' WHERE a = 1');"],
    ['lib/repo/x.mjs', "q(\n  'SELECT *' +\n    ' FROM users' +\n    ' WHERE login = ?'\n);"],
  ])
    assert.ok(rules(lintSource(file, source)).includes('raw-sql'), source);
  assert.deepEqual(looksLikeSql('select name from users where id = ?'), true);
  // Prose in any case is not SQL: no comparison, placeholder, value or IS NULL beside it.
  for (const prose of [
    "say('Select a source from the list'); say('DELETE')",
    "say('Select one from the list, then press Delete.')",
    "say('Update your settings, then insert into the form what you need.')",
    "say('Which source? Select it from the list')",
    "say('Delete from the folder where it was saved')",
  ])
    assert.deepEqual(lintSource('server.mjs', prose), [], prose);
  // A connection is held by lib/db/sqlite.mjs and lib/store.mjs alone. Nothing else prepares a
  // statement, and exec() on something named like a connection is refused, whatever its text.
  for (const source of [
    "const verb = 'DELETE';\nexport const f = (db, t) => db.exec(verb + ' FROM ' + t);",
    'export const f = (store, text) => store.db.exec(text);',
    'export const f = (conn, text) => conn.exec(text);',
    'export const f = (raw, text) => raw.prepare(text).all();',
  ])
    assert.deepEqual(rules(lintSource('lib/repo/x.mjs', source)), ['raw-connection'], source);
  // RegExp#exec is not a connection.
  assert.deepEqual(
    lintSource('lib/http/x.mjs', "const m = /a(b)/.exec(text) ?? pattern.exec(String(v ?? ''));"),
    []
  );
  // The holders pass one literal, or a variable at a site they list, bound there as listed.
  assert.deepEqual(Object.keys(CONNECTION_HOLDERS).sort(), ['lib/db/sqlite.mjs', 'lib/store.mjs']);
  for (const { sites } of Object.values(CONNECTION_HOLDERS))
    for (const site of sites) assert.ok(site.why.length > 0, site.call);
  const sited =
    'class Db {\n  prepare(query) {\n    const { text, params } = this.#dialect.render(query);\n    return this.#db.prepare(text);\n  }\n}';
  assert.deepEqual(lintSource('lib/db/sqlite.mjs', sited), []);
  for (const refused of [
    // The same call outside the site, or the site with its variable from elsewhere.
    'this.#db.prepare(text);',
    'function other(text) {\n  return this.#db.prepare(text);\n}',
    sited.replace('const { text, params }', 'const { text, params, more }'),
    sited.replace('return this.#db', 'text = text + more;\n    return this.#db'),
    sited.replace(
      '    const { text, params } = this.#dialect.render(query);\n',
      '    if (query) {\n      const { text, params } = this.#dialect.render(query);\n    }\n'
    ),
    // The public dialect, which a repository holding the Db could replace.
    sited.replace('this.#dialect.render', 'this.dialect.render'),
    'this.#db.exec(other);',
    "this.#db.exec(a + 'x');",
    "this.#db.exec('PRAGMA foreign_keys=ON' + more);",
  ])
    assert.ok(rules(lintSource('lib/db/sqlite.mjs', refused)).includes('raw-connection'), refused);
});

test("a driver's control-statement exemption covers one allowlisted statement, never a second statement or an interpolated name", () => {
  const driver = source => rules(lintSource('lib/db/sqlite.mjs', source));
  for (const allowed of [
    "db.exec('PRAGMA foreign_keys=ON');",
    "db.exec('PRAGMA wal_checkpoint(TRUNCATE)');",
    `db.exec(${bt}PRAGMA busy_timeout=\${maxBusyTimeoutMs}${bt});`,
    `db.exec(${bt}PRAGMA synchronous=\${synchronous === 'NORMAL' ? 'NORMAL' : 'FULL'}${bt});`,
    `db.prepare(${bt}PRAGMA \${text}${bt}).all();`,
    "db.prepare('SELECT count(*) FROM sqlite_master').get();",
    "db.exec('ROLLBACK');",
  ])
    assert.deepEqual(driver(allowed), [], allowed);
  for (const refused of [
    // A second statement after an allowed one, or behind a catalog read.
    "db.exec('PRAGMA foreign_keys=ON; DELETE FROM users');",
    `db.exec(${bt}SELECT 1 FROM sqlite_master; DELETE FROM users WHERE login='\${v}'${bt});`,
    // A value the driver does not list, a spliced name.
    `db.exec(${bt}PRAGMA \${v}=1${bt});`,
    `db.exec(${bt}PRAGMA busy_timeout=\${userValue}${bt});`,
    `db.exec(${bt}PRAGMA \${v}${bt});`,
    // Engine catalog reads with more than a count.
    "db.prepare('SELECT sql FROM sqlite_master WHERE name = ?');",
  ])
    assert.deepEqual(driver(refused), ['raw-sql', 'raw-connection'], refused);
  assert.ok(Object.keys(DRIVER_VALUES).every(name => DRIVER_VALUES[name].length > 0));
  // A sql`…` catalog read in lib/db may name engine tables, but not run a second statement.
  const catalog = text => rules(lintSource('lib/db/x.mjs', `const q = sql${bt}${text}${bt};`));
  assert.deepEqual(catalog("SELECT type, name FROM sqlite_master WHERE type = 'table'"), []);
  assert.deepEqual(catalog('PRAGMA quick_check'), []);
  assert.deepEqual(catalog('SELECT name FROM sqlite_master; DELETE FROM x'), [
    'multiple-statements',
  ]);
  assert.ok(catalog('PRAGMA writable_schema = 1').includes('engine-control'));
});

test('identifiers in any case come through id(); aliases are only what the statement defines; ATTACH, DETACH and a second statement are refused', () => {
  const M = '\u0001';
  const found = text => rules(checkSqlText(text));
  // Upper-case words are keywords only if they are SQL keywords.
  assert.deepEqual(found(`SELECT PASSWORD FROM ${M}`), ['bare-identifier']);
  assert.deepEqual(found(`SELECT ${M} FROM ${M} WHERE Login = ${M}`), ['bare-identifier']);
  // Short names are no aliases unless the statement defines them (id, v and n are real columns).
  assert.deepEqual(found(`SELECT id, v FROM ${M} WHERE id = ${M}`), [
    'bare-identifier',
    'bare-identifier',
    'bare-identifier',
  ]);
  // An alias may not stand for a registered name used bare (it reads as that column).
  assert.deepEqual(found(`SELECT ${M} AS password, password FROM ${M}`), ['bare-identifier']);
  assert.deepEqual(found(`SELECT ${M} AS total, total FROM ${M}`), []);
  // Aliases of a table named by id() qualify only id() columns; a CTE's or subquery's columns
  // are the statement's own.
  assert.deepEqual(found(`SELECT o.state FROM ${M} o`), ['bare-identifier']);
  assert.deepEqual(found(`SELECT o.* FROM ${M} o LEFT JOIN ${M} c ON ${M} = ${M}`), []);
  assert.deepEqual(found(`SELECT s.anything FROM (SELECT ${M} AS anything FROM ${M}) s`), []);
  assert.deepEqual(found(`SELECT u.x FROM (${M}) AS u`), []);
  assert.deepEqual(found(`SELECT coalesce(${M}, 0) AS total, total.x FROM ${M}`), [
    'bare-identifier',
  ]);
  // The registry decides what is registered (an option, for small cases).
  assert.deepEqual(
    rules(checkSqlText(`SELECT ${M} AS mine, mine FROM ${M}`, { registered: n => n === 'mine' })),
    ['bare-identifier']
  );
  assert.deepEqual(
    found(`ATTACH DATABASE ${M} AS x`).filter(r => r !== 'bare-identifier'),
    ['attach']
  );
  assert.deepEqual(found(`SELECT ${M} FROM ${M}; DELETE FROM ${M}`), ['multiple-statements']);
});

test('sql used as a value (call, apply, alias, Reflect.apply), namespace or dynamic imports of db/sql.mjs and .constructor are refused', () => {
  const head = "import { sql, id } from '../db/sql.mjs';\n";
  for (const body of [
    'export const f = (tx, s) => tx.all(sql(s));',
    'export const f = (tx, s) => tx.all(sql.call(null, s));',
    'export const f = (tx, s) => tx.all(sql.apply(null, [s]));',
    'export const f = (tx, s) => tx.all(sql.bind(null)(s));',
    'const t = sql;\nexport const f = (tx, s) => tx.all(t(s));',
    'export const f = (tx, s) => tx.all(Reflect.apply(sql, null, [s]));',
    'export const tag = { sql };',
    'export const f = (tx, s) => tx.all(new (sql``.constructor)([s], []));',
    'const Q = Object.getPrototypeOf(sql``).constructor;',
    "const I = id('meta').constructor;",
  ])
    assert.ok(rules(lintSource('lib/repo/x.mjs', head + body)).includes('internal-api'), body);
  // An alias of the import is watched the same way.
  assert.deepEqual(
    rules(
      lintSource('lib/repo/x.mjs', "import { sql as q } from '../db/sql.mjs';\nq.call(null, s);")
    ),
    ['internal-api']
  );
  for (const source of [
    "import * as S from '../db/sql.mjs';\nnew S.Query([v], []);",
    "export * from '../db/sql.mjs';",
    "export { fragment } from '../db/sql.mjs';",
    "import { directive } from '../db/sql.mjs';",
    "export const f = async () => (await import('../db/sql.mjs')).Query;",
  ])
    assert.ok(rules(lintSource('lib/repo/x.mjs', source)).includes('internal-api'), source);
  // Tags, helper reads and other objects' sql properties are fine; so is an async check.
  assert.deepEqual(
    lintSource(
      'lib/repo/x.mjs',
      head +
        `export const q = sql${bt}SELECT \${id('a')} FROM \${sql.id('t')} WHERE \${sql.join([1])}${bt};\n` +
        "export const n = dialect.sql;\nconst isAsync = fn => fn?.constructor?.name === 'AsyncFunction';"
    ),
    []
  );
});

test("the Store's connection is for tests only: server code never opens it", () => {
  assert.deepEqual(
    rules(
      lintSource(
        'lib/http/routes/x.mjs',
        "import { exposeStoreConnections } from '../../store.mjs';\nexposeStoreConnections();"
      )
    ),
    ['store-connection', 'store-connection']
  );
  assert.deepEqual(
    rules(
      lintSource('server.mjs', "import * as S from './lib/store.mjs';\nS.exposeStoreConnections();")
    ),
    ['store-connection']
  );
  assert.deepEqual(
    lintSource('lib/store-connections.mjs', 'export function exposeStoreConnections() {}'),
    []
  );
  // By a string key, which hid the name from the check above, and a connection's methods so
  // reached: S['exposeStoreConnections'](), store.db['prepare'](text), process['getBuiltinModule'].
  assert.deepEqual(
    lintSource(
      'lib/http/routes/x.mjs',
      "S['exposeStoreConnections']();\nstore.db['prepare'](text).all();\nconn[\"exec\"](text);\nprocess[ 'getBuiltinModule' ]('node:sqlite');"
    )
      .map(f => `${f.line} ${f.rule}`)
      .sort(),
    [
      '1 store-connection',
      '2 raw-connection',
      '2 raw-connection',
      '3 raw-connection',
      '3 raw-connection',
      '4 raw-connection',
    ]
  );
  // Those words as strings at all, since a string becomes a key (const step = 'prepare'; x[step]).
  assert.deepEqual(rules(lintSource('lib/http/x.mjs', "const step = 'prepare';\nlog('exec');")), [
    'raw-connection',
    'raw-connection',
  ]);
  // Every other way to reach a connection's prepare or exec that the checks above missed: an
  // optional call, a template, escaped or concatenated key, Reflect, a reference called later.
  for (const source of [
    'export const r = (db, t) => db.prepare?.(t);',
    'export const r = (db, t) => db.exec?.(t);',
    'export const r = (db, t) => db[`prepare`](t);',
    "export const r = (db, t) => db['pr\\x65pare'](t);",
    "export const r = (db, t) => db['pr\\u0065pare'](t);",
    "export const r = (db, t) => db['pr\\u{65}pare'](t);",
    "export const r = (x, t) => x['pre' + 'pare'](t);",
    "export const r = (x, t) => x[`ex` + 'ec'](t);",
    "export const r = (db, t) => Reflect.get(db, 'prepare').call(db, t);",
    'export const r = (db, k, t) => Reflect.get(db, k).call(db, t);',
    'export const r = (db, t) => Reflect.apply(Reflect.get(db, k), db, [t]);',
    'export const r = (store, k, t) => store.db[k](t);',
    'export const r = (db, t) => {\n  const p = db.prepare;\n  return p.call(db, t);\n};',
    'export const r = (db, t) => {\n  const e = db.exec;\n  return e.call(db, t);\n};',
    "import { 'exposeStoreConnections' as open } from '../../store-connections.mjs';\nopen();",
  ])
    assert.ok(
      rules(lintSource('lib/http/routes/x.mjs', source)).some(rule =>
        ['raw-connection', 'store-connection'].includes(rule)
      ),
      source
    );
  // RegExp#exec and other objects' exec stay fine.
  assert.deepEqual(
    lintSource('lib/http/x.mjs', 'export const r = t => /a/.exec(t) ?? pattern.exec?.(t);'),
    []
  );
});

// A stretch the scanner misread was invisible to every rule: a regular expression read as a
// division (or the reverse) opened a template literal JavaScript does not see, which hid the
// imports and calls after it, and a comment ended where JavaScript does not end it.
test('the scanner reads a slash, a comment and a name as JavaScript does, or refuses the code', () => {
  const hidden = "import { DatabaseSync } from 'node:sqlite';";
  const seen = source =>
    moduleDeclarations(source).declarations.some(item => item.specifier === 'node:sqlite');
  // After the ")" of if, while, for (await) and with a statement starts: a regular expression.
  for (const lead of [
    "if (process.env.NEVER) /`/.test('');",
    "while (x) /`/.test('');",
    "for (;;) /`/.test('');",
    "for await (const x of y) /`/.test('');",
  ]) {
    const source = `${lead}\n${hidden}\nexport const tick = /${bt}/;\n`;
    assert.ok(seen(source), lead);
    assert.deepEqual(scan(source).unreadable, [], lead);
  }
  // After ++, -- and a property named like a keyword: a division (the backquote opens a template
  // literal that ends before the import).
  for (const lead of ['n++', 'n--', 'x.return', 'x.delete', 'this.#default', 'x?.of']) {
    const source = `export const v = ${lead} / ${bt}/;\n${bt}; ${hidden}\n`;
    assert.ok(seen(source), lead);
    assert.deepEqual(scan(source).unreadable, [], lead);
  }
  // A name in another script divides as an ASCII one does (é read as an operator made the "/"
  // start a regular expression), and a \r\n line continuation stays inside its string.
  for (const source of [
    `const é = 1;\nexport const v = é / ${bt}/${bt};\n${hidden}\nexport const w = ${bt}${bt};\n`,
    `const s = 'x\\\r\n${bt}';\n${hidden}\nexport const t = ${bt}';${bt};\n`,
  ])
    assert.ok(seen(source), JSON.stringify(source));
  // A // comment ends at \r, U+2028 and U+2029 too, and a hashbang line is a comment.
  for (const source of [
    `// note\r${hidden}\n`,
    `// note ${hidden}\n`,
    `// note ${hidden}\n`,
    `#!/usr/bin/env node ${bt}\n${hidden}\n`,
  ])
    assert.ok(seen(source), JSON.stringify(source));
  // Where the tokens before a slash do not tell: refused, as is an escaped name.
  for (const [source, why] of [
    [`export const v = {} / ${bt}/;\n${bt}; ${hidden}\n`, 'slash-after-brace'],
    [`const of = 1;\nexport const v = of / ${bt}/;\n${bt}; ${hidden}\n`, 'slash-after-of'],
    ['export const f = (db, t) => db.pr\\u0065pare(t);', 'escape-in-code'],
  ]) {
    assert.deepEqual(
      scan(source).unreadable.map(item => item.why),
      [why],
      source
    );
    assert.ok(rules(lintSource('lib/http/x.mjs', source)).includes('unreadable-code'), source);
  }
  // Ordinary code reads as before.
  assert.deepEqual(
    scan('const r = (a) / 2 / (b);\nif (/x/.test(s)) f();\nconst k = { a: 1 };\nx = y++ + 1;\n')
      .unreadable,
    []
  );
});

test('import() and the loaders take one literal path with nothing added to it', () => {
  // Each began with a literal and named lib/db/sql.mjs, which the lint read as the first literal.
  for (const source of [
    "const { fragment } = await import('../db/sq' + 'l.mjs');",
    "const m = await import('' || '../db/sql.mjs');",
    "const m = await import('../db/sq'.concat('l.mjs'));",
    "const m = await import('../db/sq' /* a comment */ + 'l.mjs');",
    `const m = await import(${bt}../db/sql.mjs${bt});`,
    "const m = require('../db/sq' + 'l.mjs');",
  ])
    assert.ok(rules(lintSource('lib/repo/x.mjs', source)).includes('dynamic-import'), source);
  // One literal, with options after it, is an import of that path.
  assert.deepEqual(
    rules(lintSource('lib/repo/x.mjs', "const m = await import('./other.mjs', { with: {} });")),
    []
  );
});

test('a module is named by a plain relative path, a node: builtin or a package name', () => {
  // Node reads each of these as another file (or any module) than the text says.
  for (const specifier of [
    '../db/sq%6C.mjs',
    './..\\db\\sql.mjs',
    '../db/sq\tl.mjs',
    './%2e%2e/db/sql.mjs',
    '../db/sql.mjs?x',
    '/opt/uptime-goblin/lib/db/sql.mjs',
    'file:///opt/uptime-goblin/lib/db/sql.mjs',
    'data:text/javascript,export * from "node:sqlite"',
    'https://example.invalid/x.mjs',
    '#internal',
    'nodemailer/../postgres/x.js',
    'NODE:sqlite',
    '../db/registry.json',
  ]) {
    assert.ok(specifierProblem(specifier), specifier);
    assert.ok(
      rules(lintSource('lib/repo/x.mjs', `import x from ${JSON.stringify(specifier)};`)).includes(
        'module-specifier'
      ),
      specifier
    );
  }
  for (const specifier of [
    './a.mjs',
    '../../public/shared/csv.js',
    'node:fs/promises',
    'nodemailer',
    '@azure/identity/lib/x.js',
  ])
    assert.equal(specifierProblem(specifier), null, specifier);
});

// The holders' connections, used other than through a listed sink: each of these ran text the
// lint never saw (a destructured or aliased sink, DatabaseSync's other methods, a connection
// passed on or made another way).
test('a raw connection is used through its sinks alone, in the holders too', () => {
  const store = fs.readFileSync(path.join(repository, 'lib', 'store.mjs'), 'utf8');
  const anchor = '  close() {\n    this.#keepMarks();\n    this.#db.close();\n  }\n';
  assert.equal(store.split(anchor).length, 2);
  for (const method of [
    `  forgetReadings(id) {\n    const { prepare } = this.#db;\n    const verb = 'DELETE';\n    return prepare.call(this.#db, ${bt}\${verb} FROM readings WHERE service='\${id}'${bt}).run().changes;\n  }\n`,
    '  purge(statement) {\n    const { exec: run } = this.#db;\n    run.call(this.#db, statement);\n  }\n',
    '  purge(statement) {\n    return this.#db.createTagStore().run([statement]);\n  }\n',
    '  purge(statement, key) {\n    const c = this.#db;\n    return c[key](statement);\n  }\n',
    '  purge(bytes) {\n    this.#db.deserialize(bytes);\n  }\n',
    '  purge(statement) {\n    return run(this.#db, statement);\n  }\n',
    '  purge(other) {\n    return other.#db;\n  }\n',
    "  purge(statement) {\n    const second = new DatabaseSync(':memory:');\n    const { exec } = second;\n    exec.call(second, statement);\n  }\n",
    "  purge(statement) {\n    return [new DatabaseSync(':memory:')][0].exec(statement);\n  }\n",
  ]) {
    const found = rules(lintSource('lib/store.mjs', store.replace(anchor, method + anchor)));
    assert.ok(
      found.length > 0 && found.every(rule => rule === 'raw-connection'),
      `${method}: ${found}`
    );
  }
  // The test seam hands the connection out only after its check, and nowhere else.
  const seam =
    "  get db() {\n    if (!storeConnectionsExposed())\n      throw new Error('The Store keeps its connection to itself; use its methods.');\n    return this.#db;\n  }";
  assert.equal(store.split(seam).length, 2);
  for (const changed of [
    seam.replace('  get db() {\n', '  get db() {\n    return this.#db;\n'),
    seam.replace(
      '    if (!storeConnectionsExposed())',
      '    if (!storeConnectionsExposed() && false)'
    ),
    seam.replace('get db()', 'get connection()'),
  ]) {
    const found = rules(lintSource('lib/store.mjs', store.replace(seam, changed)));
    assert.ok(found.length > 0 && found.every(rule => rule === 'raw-connection'), changed);
  }
  const driver = fs.readFileSync(path.join(repository, 'lib', 'db', 'sqlite.mjs'), 'utf8');
  const check =
    "  const db = new DatabaseSync(sqlitePath(file), { readOnly: true });\n  try {\n    const rows = db.prepare('PRAGMA quick_check').all();";
  assert.equal(driver.split(check).length, 2);
  const driverImport = "import { DatabaseSync, backup as sqliteBackup } from 'node:sqlite';";
  assert.equal(driver.split(driverImport).length, 2);
  for (const [label, changed] of Object.entries({
    'destructured exec': driver.replace(
      check,
      `${check}\n    const { exec } = db;\n    exec.call(db, file);`
    ),
    alias: driver.replace(check, `${check}\n    const other = db;\n    other.exec(file);`),
    createTagStore: driver.replace(check, `${check}\n    db.createTagStore().all([file]);`),
    'made in an expression': driver.replace(
      check,
      check.replace('const db = new', 'const db = file && new')
    ),
    'namespace import': driver.replace(
      driverImport,
      `${driverImport}\nimport * as sqlite from 'node:sqlite';`
    ),
    'renamed import': driver.replace(
      driverImport,
      "import { DatabaseSync as D, backup as sqliteBackup } from 'node:sqlite';"
    ),
    'another name imported': driver.replace(
      driverImport,
      "import { DatabaseSync, backup as sqliteBackup, StatementSync } from 'node:sqlite';"
    ),
    'run-time import': driver.replace(
      driverImport,
      `${driverImport}\nconst more = await import('node:sqlite');`
    ),
  })) {
    const found = rules(lintSource('lib/db/sqlite.mjs', changed));
    assert.ok(
      found.length > 0 && found.every(rule => rule === 'raw-connection'),
      `${label}: ${found}`
    );
  }
  // Outside the holders, a sink destructured or declared, and those methods by any name.
  for (const source of [
    'export const f = (db, t) => {\n  const { prepare } = db;\n  return prepare.call(db, t);\n};',
    'export const f = (db, t) => {\n  const { exec: run } = db;\n  return run.call(db, t);\n};',
    'export const f = (x, t) => x.createTagStore().run([t]);',
    'export const f = (x, b) => x.deserialize(b);',
    "export const f = (x, t) => x['createTag' + 'Store']().run([t]);",
  ])
    assert.ok(
      rules(lintSource('lib/http/routes/x.mjs', source)).includes('raw-connection'),
      source
    );
});

test('the command line lints a tree and exits 1 on findings', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-sql-lint-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'lib', 'repo'), { recursive: true });
  fs.writeFileSync(path.join(root, 'server.mjs'), "export const ok = 'fine';\n");
  fs.writeFileSync(
    path.join(root, 'lib', 'repo', 'a.mjs'),
    repo(`export const q = sql${bt}SELECT \${id('a')} FROM \${id('t')}${bt};`)
  );
  const script = path.join(repository, 'scripts', 'sql-lint.mjs');
  let result = spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /2 server modules follow the SQL rules/);
  fs.writeFileSync(
    path.join(root, 'lib', 'repo', 'b.mjs'),
    repo(`export const q = sql${bt}SELECT * FROM \${id('t')} LIMIT 1${bt};`)
  );
  result = spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lib\/repo\/b\.mjs:2 bare-limit: use dialect\.limit\(n\)/);
  result = spawnSync(process.execPath, [script, '--root', root, '--json'], { encoding: 'utf8' });
  assert.equal(JSON.parse(result.stdout)[0].rule, 'bare-limit');
  result = spawnSync(process.execPath, [script, '--bogus'], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  // A module linked to lib/db/sql.mjs is that module under a name the lint does not know.
  fs.rmSync(path.join(root, 'lib', 'repo', 'b.mjs'));
  fs.mkdirSync(path.join(root, 'lib', 'db'));
  fs.writeFileSync(path.join(root, 'lib', 'db', 'sql.mjs'), 'export const fragment = 1;\n');
  fs.symlinkSync('../db/sql.mjs', path.join(root, 'lib', 'repo', 'tag.mjs'));
  result = spawnSync(process.execPath, [script, '--root', root, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.deepEqual(
    JSON.parse(result.stdout).map(f => `${f.file} ${f.rule}`),
    ['lib/repo/tag.mjs module-link']
  );
});

// The gate: the shipped server code follows the SQL rules.
test('the repository follows the SQL rules', () => {
  const files = serverFiles(repository);
  assert.ok(
    files.includes('server.mjs') &&
      files.includes('lib/store.mjs') &&
      files.includes('lib/db/sql.mjs')
  );
  const findings = lint(repository, files);
  assert.deepEqual(
    findings.map(f => `${f.file}:${f.line} ${f.rule}: ${f.message}`),
    [],
    'run node scripts/sql-lint.mjs for details'
  );
});
