// The SQL rules of roadmap §10.4 ("the lint, from 1.5"), checked over the shipped server code
// (server.mjs, lib/**/*.mjs and every module they reach by a relative import, such as
// public/shared/*.js; serverFiles). Usage: node scripts/sql-lint.mjs [--root <dir>] [--json]
// [--legacy]. scripts/*.mjs are development tools that are never shipped (deploy/manifest.txt)
// and are not linted: gen-dataset.mjs writes a synthetic history.sqlite with its own statements.
//
// 0. The rules read the source through scan(), a small scanner. Where it cannot read code as
//    JavaScript does, which would hide what follows from every rule, the code is refused
//    (unreadable-code): a "/" after "}" or after `of`, which may be a regular expression or a
//    division, and a "\" in code (an escaped name: pr\u0065pare is prepare).
// 1. SQL is written only in sql`…` templates (lib/db/sql.mjs) and the dialect helpers, and only
//    by lib/db, lib/repo, lib/series and lib/store.mjs. A SQL string anywhere else is refused,
//    in any case and split over literals joined with + ('SELECT * ' + 'FROM t WHERE a = ' + v).
//    lib/db/sqlite.mjs may send connection control (PRAGMA, BEGIN, COMMIT …) as plain strings,
//    one allowlisted statement each, splicing in only the values DRIVER_VALUES names;
//    lib/db/dialect/* writes engine text by design and is not checked.
// 2. Inside sql`…` text these are refused, each with its portable replacement:
//    bare LIMIT/OFFSET/FETCH/TOP (dialect.limit), MERGE and INSERT OR REPLACE (dialect.upsert),
//    raw RETURNING/OUTPUT (the builders' {returning}), raw ON CONFLICT (upsert/insertIgnore),
//    raw ORDER BY (dialect.orderBy, which states NULL ordering), raw lock clauses (claim(),
//    forShare()), database clocks such as now(), GETDATE(), CURRENT_TIMESTAMP (dialect.clockMs),
//    datetime types and functions, AT TIME ZONE (time-zone maths stays in JavaScript), ATTACH
//    and DETACH, PRAGMA and VACUUM (the driver's), and a second statement after a ";".
// 3. Identifiers come through id() (quoted from the registry): SQL keywords are written in upper
//    case (KEYWORDS), and any other word in sql`…` text is a name written by hand, unless the
//    statement defines it (an alias after AS or after what it names, a CTE) and it is not also a
//    registered name, or it is a function before "(". Aliases that SQL Server reserves (key,
//    rule, user …) are refused.
// 4. The tag is only a tag: sql(…), sql.call/apply/bind, an alias of it or passing it on, the
//    dialect-internal exports (fragment, directive, Query, Identifier, Directive, JsonValue),
//    namespace, re-exported and dynamic imports of lib/db/sql.mjs, and .constructor in the SQL
//    issuers are refused outside lib/db (lib/db/sql.mjs refuses such constructions at run time
//    too); fragment() and directive(), which write any string as SQL text, outside
//    lib/db/dialect. The module is recognised however its path is spelt (namesSqlModule: steps,
//    a query, an absolute path, a file: URL, another case), and its import declarations are read
//    as declarations (moduleDeclarations): a comment inside the braces, a name written as a
//    string ({ 'fragment' as f }) and a default import with a namespace or names count. A module
//    is named only by a plain relative path to a .mjs or .js file, node:<builtin> or a package
//    name (specifierProblem: Node reads a %-escape, "\", a space, a query, a URL or an absolute
//    path as another module than the text says), and import() and the loaders take one literal
//    and nothing added to it (dynamicImports: import('../db/sq' + 'l.mjs') named lib/db/sql.mjs).
// 5. Raw connections: only lib/db/sqlite.mjs and lib/store.mjs hold one (import-graph keeps
//    node:sqlite to them). What they hand a connection (CONNECTION_HOLDERS) is one literal as it
//    is, or a variable at a site listed there, bound in that function as listed and nowhere else.
//    Each connection there is made as `name = new DatabaseSync(…);`, node:sqlite is imported by
//    the names listed and nothing is imported at run time, and a connection's name is used only
//    as the receiver of a sink or of close, isOpen and isTransaction: never destructured,
//    aliased, passed on or returned, except at a statement CONNECTION_HOLDERS lists, and never
//    with DatabaseSync's other methods, which run SQL text (createTagStore()) or replace the
//    database (deserialize()). Elsewhere nothing names prepare (called, as ?.(), taken as a value,
//    destructured or declared) or those methods, nothing takes exec from something named like a
//    connection or destructures or declares it, nothing reaches such a value's members by a
//    computed key or Reflect, and the Store's connection is opened to tests only. prepare, exec,
//    those methods, exposeStoreConnections and getBuiltinModule are never written as a string,
//    however it is spelt ('pr\x65pare', `exec`, 'pre' + 'pare'), since a string reaches them by a
//    computed key. A key computed at run time from other values is beyond this lint: those
//    values have no raw connection to reach (store.db throws unless test/setup.mjs opened it).
// The legacy 1.x store (lib/store.mjs) keeps its hand-written SQL (invariant 1) and no other:
// LEGACY freezes each raw statement it has, in any case, every literal its connection is given,
// and refuses a value joined to a statement with +. The values its frozen statements splice in
// with ${…} are what they are written as there (table names from fixed lists, a page count): the
// hash covers the expression's text, not where its value comes from. Not checked here: the
// parameter count (at most 2,000) is enforced when a dialect renders a statement, which also
// keeps every VALUES list under 2,000 rows, below SQL Server's 5,000-lock escalation point. The
// §10.4 rule that an UPDATE or DELETE on a hot state table touches fewer than 5,000 rows depends
// on data, not text; it applies from 2.2, when those tables arrive, and their DAOs keep it by
// batching keys.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import registry from '../lib/db/registry.mjs';

export const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// ---------------------------------------------------------------------------------------------
// A small JavaScript scanner: enough to find strings, template literals (with their tags and
// expressions), comments and regular expressions without a parser dependency.

const keywordsBeforeExpression = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'throw',
  'case',
  'do',
  'else',
  'yield',
  'await',
  'export',
  'default',
  'extends',
]);
// The keywords whose "(" holds a condition or loop head, after whose ")" a statement starts.
const controlKeywords = new Set(['if', 'while', 'for', 'with']);
// What JavaScript ends a line (and a // comment) at.
const lineTerminator = /[\n\r\u2028\u2029]/;
// What a JavaScript name starts with and is made of, in any script.
const identifierStart = /^[\p{ID_Start}$_]$/u;
const identifierPart = /^[\p{ID_Continue}$\u200C\u200D]$/u;

/**
 * Scans JavaScript source. Returns `strings` (quoted literals: {kind: 'string', text, start, end,
 * line}), `templates` ({kind: 'template', tag, parts, expressions, start, end, line}),
 * `masked`: the source with comments and literal text replaced by spaces (quotes, newlines and
 * template expressions kept), so regular expressions over it only see code, and `unreadable`:
 * [{line, why}] for code this scanner cannot read the way JavaScript does, which every rule
 * built on it refuses. `end` is the index just after the closing quote.
 *
 * A "/" that may be a regular expression or a division is the scanner's one guess: read wrong,
 * a quote or backquote inside it opens a literal JavaScript does not see (or the reverse) and
 * hides the code after it. So it is decided as the grammar does where the tokens before it
 * tell (after the ")" of if/while/for/with, a statement and so a regular expression; after a
 * name in any script, a property name such as `.return`, ++ or --, a division), and is
 * unreadable where they do not: after "}" (a block, or an object literal or function in an
 * expression) and after `of` (a keyword in for…of, or a variable). So is a "\" in code (an
 * escaped name such as pr\u0065pare, which is `prepare` to JavaScript). Comments end where
 * JavaScript ends a line (\r, U+2028 and U+2029 too), a \r\n line continuation stays in its
 * string, and a first #! line is a comment.
 */
export function scan(source) {
  const masked = source.split('');
  const strings = [],
    templates = [],
    unreadable = [];
  const lineStarts = [0];
  for (let i = 0; i < source.length; i += 1) if (source[i] === '\n') lineStarts.push(i + 1);
  const lineOf = index => {
    let low = 0,
      high = lineStarts.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if (lineStarts[middle] <= index) low = middle;
      else high = middle - 1;
    }
    return low + 1;
  };
  const blank = (from, to) => {
    for (let j = from; j < to; j += 1) if (masked[j] !== '\n') masked[j] = ' ';
  };
  let i = 0;
  let last = null,
    previous = null;
  // The open parentheses, each with whether a control keyword opened it.
  const parentheses = [];
  const token = next => {
    previous = last;
    last = next;
  };

  // A slash starts a regular expression after an operator, a keyword, the ")" of a control
  // keyword or the start of input, and is division after a name, a property name, a literal,
  // another ")", "]", ++ or --. After "}" or `of` it is unreadable (see above).
  const regexAllowed = () => {
    if (!last) return true;
    if (last.type === 'punct') {
      if (last.value === '}') unreadable.push({ line: lineOf(i), why: 'slash-after-brace' });
      if (last.value === ')') return last.control;
      return !['++', '--', ']'].includes(last.value);
    }
    if (last.type === 'word') {
      if (last.property) return false;
      if (last.value === 'of') unreadable.push({ line: lineOf(i), why: 'slash-after-of' });
      return keywordsBeforeExpression.has(last.value);
    }
    return false;
  };
  // A hashbang line is a comment.
  if (source.startsWith('#!')) {
    const end = source.slice(2).search(lineTerminator);
    const stop = end < 0 ? source.length : end + 2;
    blank(0, stop);
    i = stop;
  }

  function readString(quote) {
    const start = i;
    i += 1;
    while (i < source.length && source[i] !== quote && source[i] !== '\n') {
      // An escape, a line continuation of \r\n (both characters) included.
      if (source[i] === '\\') i += source[i + 1] === '\r' && source[i + 2] === '\n' ? 2 : 1;
      i += 1;
    }
    strings.push({
      kind: 'string',
      text: source.slice(start + 1, i),
      start,
      end: i + 1,
      line: lineOf(start),
    });
    blank(start + 1, i);
    i += 1;
    token({ type: 'string' });
  }

  function readTemplate() {
    const start = i;
    const tag =
      last?.type === 'word' && !keywordsBeforeExpression.has(last.value) ? last.value : null;
    const parts = [],
      expressions = [];
    let partStart = i + 1;
    i += 1;
    while (i < source.length && source[i] !== '`') {
      if (source[i] === '\\') {
        i += 2;
        continue;
      }
      if (source[i] === '$' && source[i + 1] === '{') {
        parts.push(source.slice(partStart, i));
        blank(partStart, i);
        i += 2;
        const expressionStart = i;
        last = null;
        scanCode(true);
        expressions.push(source.slice(expressionStart, i));
        i += 1; // the closing }
        partStart = i;
        continue;
      }
      i += 1;
    }
    parts.push(source.slice(partStart, i));
    blank(partStart, i);
    templates.push({
      kind: 'template',
      tag,
      parts,
      expressions,
      start,
      end: i + 1,
      line: lineOf(start),
    });
    i += 1;
    token({ type: 'template' });
  }

  function readRegex() {
    const start = i;
    let inClass = false;
    i += 1;
    while (i < source.length) {
      const ch = source[i];
      if (lineTerminator.test(ch)) {
        // Not a regular expression after all: treat the slash as division.
        i = start + 1;
        token({ type: 'punct', value: '/' });
        return;
      }
      if (ch === '\\') i += 2;
      else {
        if (ch === '[') inClass = true;
        else if (ch === ']') inClass = false;
        else if (ch === '/' && !inClass) break;
        i += 1;
      }
    }
    blank(start + 1, i);
    i += 1;
    while (/[a-z]/i.test(source[i] ?? '')) i += 1;
    token({ type: 'regex' });
  }

  function scanCode(untilBrace) {
    let depth = 0;
    while (i < source.length) {
      const ch = source[i],
        next = source[i + 1];
      if (ch === '/' && next === '/') {
        // To the end of the line, which \r, U+2028 and U+2029 end as \n does.
        const end = source.slice(i).search(lineTerminator);
        const stop = end < 0 ? source.length : i + end;
        blank(i, stop);
        i = stop;
      } else if (ch === '/' && next === '*') {
        const end = source.indexOf('*/', i + 2);
        const stop = end < 0 ? source.length : end + 2;
        blank(i, stop);
        i = stop;
      } else if (ch === "'" || ch === '"') readString(ch);
      else if (ch === '`') readTemplate();
      else if (ch === '/' && regexAllowed()) readRegex();
      else if (/\s/.test(ch)) i += 1;
      else if (identifierStart.test(String.fromCodePoint(source.codePointAt(i)))) {
        // A name, in any script (é / 2 divides, as x / 2 does).
        const start = i;
        while (i < source.length) {
          const character = String.fromCodePoint(source.codePointAt(i));
          if (!identifierPart.test(character)) break;
          i += character.length;
        }
        // A name after "." or "#" is a property name, never a keyword (x.return / 2).
        const property = last?.type === 'punct' && (last.value === '.' || last.value === '#');
        token({ type: 'word', value: source.slice(start, i), property });
      } else if (/[0-9]/.test(ch)) {
        while (/[\w.]/.test(source[i] ?? '')) i += 1;
        token({ type: 'number' });
      } else if ((ch === '+' || ch === '-') && next === ch) {
        token({ type: 'punct', value: ch + ch });
        i += 2;
      } else {
        if (ch === '\\') unreadable.push({ line: lineOf(i), why: 'escape-in-code' });
        if (ch === '{') depth += 1;
        else if (ch === '}') {
          if (depth === 0 && untilBrace) return;
          depth -= 1;
        }
        let control = false;
        if (ch === '(') {
          const keyword =
            last?.type === 'word' && !last.property
              ? last.value === 'await' && previous?.type === 'word' && previous.value === 'for'
                ? 'for'
                : last.value
              : null;
          parentheses.push(controlKeywords.has(keyword));
        } else if (ch === ')') control = parentheses.pop() ?? false;
        token({ type: 'punct', value: ch, control });
        i += 1;
      }
    }
  }

  scanCode(false);
  return { strings, templates, masked: masked.join(''), lineOf, unreadable };
}

/** Why the scanner refused a stretch of code (scan().unreadable), for a lint's message. */
export const UNREADABLE_CODE = Object.freeze({
  'slash-after-brace':
    'a "/" after "}" may start a regular expression or divide, and the lint cannot tell which: end the statement with ";" or wrap the expression in parentheses',
  'slash-after-of':
    'a "/" after `of` may start a regular expression or divide, and the lint cannot tell which: wrap it in parentheses',
  'escape-in-code':
    'a "\\" in code (an escaped name such as pr\\u0065pare) hides the name from the lint: write the name as it is',
});

/**
 * The value of a string or template literal from its source text: escapes decoded (\x65, e,
 * \u{65}, \n, a line continuation …), so 'pr\x65pare' reads as prepare.
 */
export function decodeLiteral(raw) {
  return raw.replace(
    /\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|(\r\n|[\n\r\u2028\u2029])|([\s\S]))/g,
    (all, hex, braced, unicode, lineBreak, other) => {
      if (hex || unicode) return String.fromCharCode(parseInt(hex || unicode, 16));
      if (braced) {
        const code = parseInt(braced, 16);
        return code <= 0x10ffff ? String.fromCodePoint(code) : all;
      }
      if (lineBreak) return '';
      return { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0' }[other] ?? other;
    }
  );
}

/**
 * The import and export declarations of `source` that name a module, read over the scanned
 * source, so comments anywhere inside one are white space: {declarations: [{keyword, specifier,
 * line (the specifier's), start, end, default, namespace, star, names: [{imported, local}]}],
 * unreadable: [line]}. A name written as a string ({ 'DatabaseSync' as D }, ES2022) is read as
 * its value; a declaration of any other shape (a proposal such as `import defer`) is unreadable,
 * never skipped. `export const …` and an `export { … }` without `from` name no module.
 */
export function moduleDeclarations(source, scanned = scan(source)) {
  const { strings, masked, lineOf } = scanned;
  const byStart = new Map(strings.map(item => [item.start, item]));
  const declarations = [],
    unreadable = [];
  for (const match of masked.matchAll(/(?<![\w$.#])(import|export)(?![\w$])/g)) {
    const keyword = match[1];
    let i = match.index + keyword.length;
    const space = () => {
      while (i < masked.length && /\s/.test(masked[i])) i += 1;
    };
    const word = () => {
      const found = /^[A-Za-z_$][\w$]*/.exec(masked.slice(i, i + 256));
      if (!found) return null;
      i += found[0].length;
      return found[0];
    };
    const literal = () => {
      const item = byStart.get(i);
      if (!item) return null;
      i = item.end;
      return decodeLiteral(item.text);
    };
    const name = () => (masked[i] === "'" || masked[i] === '"' ? literal() : word());
    const list = () => {
      const names = [];
      i += 1; // {
      for (;;) {
        space();
        if (masked[i] === '}') break;
        const imported = name();
        if (imported === null) return null;
        space();
        let local = imported;
        const before = i;
        if (word() === 'as') {
          space();
          local = name();
          if (local === null) return null;
          space();
        } else i = before;
        names.push({ imported, local });
        if (masked[i] === ',') i += 1;
        else if (masked[i] !== '}') return null;
      }
      i += 1; // }
      return names;
    };
    space();
    // import() and import.meta; export const/function/class/default …; a property so named.
    if (keyword === 'import' && /^(?:[(.:]|\?\.)/.test(masked.slice(i, i + 2))) continue;
    if (keyword === 'export' && !/[*{]/.test(masked[i] ?? '')) continue;
    const declaration = {
      keyword,
      specifier: null,
      line: lineOf(match.index),
      start: match.index,
      end: null,
      default: null,
      namespace: null,
      star: false,
      names: [],
    };
    const from = () => {
      space();
      if (word() !== 'from') return false;
      space();
      return true;
    };
    let readable = true;
    if (keyword === 'import' && (masked[i] === "'" || masked[i] === '"')) {
      // import '…' (for its effects)
    } else if (keyword === 'import') {
      if (masked[i] !== '{' && masked[i] !== '*') {
        declaration.default = word();
        space();
        if (declaration.default === null) readable = false;
        else if (masked[i] === ',') {
          i += 1;
          space();
          if (masked[i] !== '{' && masked[i] !== '*') readable = false;
        } else if (masked[i] === '{' || masked[i] === '*') readable = false; // import defer * as …
      }
      if (readable && masked[i] === '*') {
        i += 1;
        space();
        readable = word() === 'as';
        space();
        declaration.namespace = readable ? word() : null;
        readable &&= declaration.namespace !== null;
      } else if (readable && masked[i] === '{') {
        declaration.names = list();
        readable = declaration.names !== null;
      }
      readable &&= from();
    } else if (masked[i] === '*') {
      i += 1;
      space();
      declaration.star = true;
      const before = i;
      if (word() === 'as') {
        space();
        declaration.namespace = name();
        readable = declaration.namespace !== null;
      } else i = before;
      readable &&= from();
    } else {
      declaration.names = list();
      readable = declaration.names !== null;
      if (readable) {
        const before = i;
        if (!from()) {
          i = before;
          continue; // export { a, b }: this module's own names
        }
      }
    }
    const specifierStart = i;
    declaration.specifier = readable ? literal() : null;
    if (declaration.specifier === null) {
      unreadable.push(lineOf(Math.min(specifierStart, masked.length - 1)));
      continue;
    }
    declaration.line = lineOf(specifierStart);
    declaration.end = i;
    declaration.names ??= [];
    declarations.push(declaration);
  }
  return { declarations, unreadable };
}

/**
 * The values of the plain literals of `source` that hold no ${…}: each string and template
 * literal, and literals joined with "+" alone ('pre' + 'pare'), escapes decoded:
 * [{value, line, start, end}].
 */
export function literalValues(source, scanned = scan(source)) {
  const { strings, templates, masked } = scanned;
  const pieces = [
    ...strings.map(item => ({ ...item, value: decodeLiteral(item.text) })),
    ...templates
      .filter(item => item.parts.length === 1)
      .map(item => ({ ...item, value: decodeLiteral(item.parts[0]) })),
  ].sort((a, b) => a.start - b.start);
  const values = pieces.map(({ value, line, start, end }) => ({ value, line, start, end }));
  for (let first = 0; first < pieces.length; first += 1) {
    let joined = pieces[first].value;
    for (let next = first + 1; next < pieces.length; next += 1) {
      if (!/^\s*\+\s*$/.test(masked.slice(pieces[next - 1].end, pieces[next].start))) break;
      joined += pieces[next].value;
      values.push({
        value: joined,
        line: pieces[first].line,
        start: pieces[first].start,
        end: pieces[next].end,
      });
    }
  }
  return values;
}

/**
 * The run-time imports of `source`: import() and the loaders require(), getBuiltinModule() and
 * createRequire(), called by name (also as ?.()) with one quoted literal as the whole argument
 * ({specifier, kind: 'dynamic', line}), and the lines of every other use (`unresolvable`): a
 * computed argument, a literal with more after it ('../db/sq' + 'l.mjs', '' || '…',
 * 'node:sq'.concat('lite'), each naming another module than its first literal), or a loader's
 * name not called (.call(), a reference).
 */
export function dynamicImports(source, scanned = scan(source)) {
  const { strings, masked, lineOf } = scanned;
  const byStart = new Map(strings.map(item => [item.start, item]));
  const imports = [],
    unresolvable = [];
  const argument = (index, line) => {
    const literal = byStart.get(index);
    if (literal && /^\s*[,)]/.test(masked.slice(literal.end, literal.end + 256)))
      imports.push({
        specifier: decodeLiteral(literal.text),
        kind: 'dynamic',
        line: lineOf(index),
      });
    else unresolvable.push(line);
  };
  for (const match of masked.matchAll(/(?<![\w$.])import\s*\(\s*/g))
    argument(match.index + match[0].length, lineOf(match.index));
  for (const match of masked.matchAll(
    /(?<![\w$])(?:require|getBuiltinModule|createRequire)(?![\w$])/g
  )) {
    const call = /^\s*(?:\?\.\s*)?\(\s*/.exec(masked.slice(match.index + match[0].length));
    if (call) argument(match.index + match[0].length + call[0].length, lineOf(match.index));
    else unresolvable.push(lineOf(match.index));
  }
  return { imports, unresolvable };
}

// How a module may be named. Node resolves a relative specifier as a URL against the importing
// module: it decodes %-escapes ('../store%2Dconnections.mjs'), reads "\" as "/", drops tabs and
// newlines and ignores a query or fragment, so any of those names another file than the text
// says. Any other URL scheme (data:, file:, http:) or an absolute path can name any module, a
// data: URL even re-exporting node:sqlite, and "#…" one mapped by package.json.
const relativeSpecifier = /^\.\.?\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.m?js$/;
const builtinSpecifier = /^node:[a-z][a-z0-9_]*(?:\/[a-z][a-z0-9_]*)*$/;
const packageSpecifier =
  /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*(?:\/[A-Za-z0-9_.~@-]+)*$/;

/**
 * Why a module specifier is refused, or null for a plain relative path to a .mjs or .js module
 * (letters, digits, ".", "_" and "-" between its slashes), a node: builtin, or a package name
 * (a package's own path after it, without "." or ".." steps, which could leave the package).
 */
export function specifierProblem(specifier) {
  const text = String(specifier);
  if (relativeSpecifier.test(text) || builtinSpecifier.test(text)) return null;
  if (packageSpecifier.test(text) && !text.split('/').some(part => part === '.' || part === '..'))
    return null;
  return `import ${JSON.stringify(text.slice(0, 80))} by a plain relative path to a .mjs or .js module (letters, digits, ".", "_" and "-"), node:<builtin> or a package name: Node reads %-escapes, "\\", spaces, a query or a fragment in a path, and a URL or an absolute path, as another module than the lint would`;
}

/**
 * The symbolic links among the server code under `root` (server.mjs and anything under lib/):
 * Node loads a linked module under its target's name, a module the rules never see named.
 */
export function moduleLinks(root = repositoryRoot) {
  const links = [];
  const walk = relative => {
    const absolute = path.join(root, relative);
    let entries;
    try {
      entries = fs.readdirSync(absolute, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const item = `${relative}/${entry.name}`;
      if (entry.isSymbolicLink()) links.push(item);
      else if (entry.isDirectory()) walk(item);
    }
  };
  walk('lib');
  try {
    if (fs.lstatSync(path.join(root, 'server.mjs')).isSymbolicLink()) links.push('server.mjs');
  } catch {}
  return links.sort();
}

// ---------------------------------------------------------------------------------------------
// The rules.

const MARK = '\u0001'; // stands for ${…} in joined template text, and for an operand of a +

/** Text that is a SQL statement (keywords in upper case, as Orbit writes them). */
const sqlStatement =
  /\b(?:SELECT\b[\s\S]*\bFROM\b|INSERT\s+(?:OR\s+[A-Z]+\s+)?INTO\b|REPLACE\s+INTO\b|UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b|CREATE\s+(?:UNIQUE\s+|TEMP\s+|TEMPORARY\s+|VIRTUAL\s+)?(?:TABLE|INDEX|VIEW|TRIGGER)\b|ALTER\s+TABLE\b|DROP\s+(?:TABLE|INDEX|VIEW|TRIGGER)\b|PRAGMA\s+\S|MERGE\s+INTO\b|ATTACH\s+(?:DATABASE\s+)?\S|DETACH\s+(?:DATABASE\s+)?\S|WITH\s+\w+\s+AS\s*\()|^\s*(?:BEGIN(?:\s+(?:IMMEDIATE|EXCLUSIVE|DEFERRED|TRANSACTION))?|COMMIT|ROLLBACK(?:\s+TO\s+\S+)?|SAVEPOINT\s+\S+|RELEASE\s+\S+|VACUUM(?:\s+INTO\b.*)?|ANALYZE)\s*;?\s*$/;
// The same statements in any case. English has these shapes too ("Select a source from the
// list"), so text in lower or mixed case counts as SQL only with something prose does not
// have: a comparison, a placeholder, a value spliced in, SELECT *, IS NULL, IN (…) or VALUES (…).
const anyCaseStatement =
  /\b(?:select\b[\s\S]*\bfrom\b|insert\s+(?:or\s+[a-z]+\s+)?into\b|replace\s+into\b|update\s+\S+\s+set\b|delete\s+from\b|create\s+(?:unique\s+|temp\s+|temporary\s+|virtual\s+)?(?:table|index|view|trigger)\b|alter\s+table\b|drop\s+(?:table|index|view|trigger)\b|pragma\s+[a-z_]|attach\s+(?:database\s+)?\S|merge\s+into\b|with\s+\w+\s+as\s*\()/i;
const sqlEvidence =
  /[=<>]|\u0001|\(\s*\?|\?\s*[,)]|\bselect\s+(?:\*|count\s*\()|\bis\s+(?:not\s+)?null\b|\bin\s*\(|\bvalues\s*\(/i;

/** Whether `text` (MARK for each value spliced in) is a SQL statement, in any case. */
export function looksLikeSql(text) {
  return (
    sqlStatement.test(text.replaceAll(MARK, ' x ')) ||
    (anyCaseStatement.test(text) && sqlEvidence.test(text))
  );
}

/** Constructs refused in SQL text, with the replacement each message names. */
export const FORBIDDEN = Object.freeze([
  ['bare-limit', /\b(?:LIMIT|OFFSET|FETCH\s+(?:NEXT|FIRST)|TOP\s*\()/i, 'use dialect.limit(n)'],
  ['merge', /\bMERGE\b/i, 'MERGE is never used; use dialect.upsert()'],
  [
    'insert-or-replace',
    /\bINSERT\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK)\b|\bREPLACE\s+INTO\b/i,
    'use dialect.upsert() or dialect.insertIgnore()',
  ],
  [
    'raw-returning',
    /\bRETURNING\b|\bOUTPUT\s+(?:INSERTED|DELETED)\b/i,
    "use the builders' {returning}",
  ],
  ['raw-upsert', /\bON\s+CONFLICT\b/i, 'use dialect.upsert() or dialect.insertIgnore()'],
  ['raw-order-by', /\bORDER\s+BY\b/i, 'use dialect.orderBy(), which states NULL ordering'],
  [
    'raw-lock',
    /\bFOR\s+(?:UPDATE|SHARE|NO\s+KEY\s+UPDATE|KEY\s+SHARE)\b|\bWITH\s*\(\s*(?:UPDLOCK|HOLDLOCK|READPAST|ROWLOCK|NOLOCK|TABLOCK|SERIALIZABLE)\b/i,
    'use dialect.claim() or dialect.forShare()',
  ],
  [
    'clock',
    /\b(?:now|GETDATE|GETUTCDATE|SYSDATETIME|SYSUTCDATETIME|SYSDATETIMEOFFSET|clock_timestamp|statement_timestamp|transaction_timestamp|unixepoch|julianday)\s*\(|\b(?:CURRENT_TIMESTAMP|CURRENT_DATE|CURRENT_TIME|LOCALTIMESTAMP|LOCALTIME)\b/i,
    'use dialect.clockMs() (times are epoch milliseconds)',
  ],
  [
    'datetime',
    /\b(?:small)?datetime(?:2|offset)?\b|\bstrftime\s*\(/i,
    'times are BIGINT epoch milliseconds; convert in JavaScript',
  ],
  ['time-zone', /\bAT\s+TIME\s+ZONE\b/i, 'time-zone maths stays in JavaScript (lib/time.mjs)'],
  [
    'attach',
    /\b(?:ATTACH|DETACH)\b/i,
    'Orbit never attaches another database: a statement reaches only its own',
  ],
  [
    'engine-control',
    /\b(?:PRAGMA|VACUUM)\b/i,
    'PRAGMA and VACUUM belong to the driver (lib/db/sqlite.mjs), never to a statement',
  ],
  [
    'multiple-statements',
    /;\s*\S/,
    'one statement per sql`…`: a driver runs the first and drops the rest',
  ],
]);

// SQL Server reserved words that Orbit might pick as names (rule and key are real columns).
export const RESERVED = new Set(
  'add all alter and any as asc authorization backup begin between break browse bulk by cascade case check checkpoint close clustered coalesce collate column commit compute constraint contains continue convert create cross current current_user cursor database dbcc deallocate declare default delete deny desc disk distinct distributed double drop dump else end errlvl escape except exec execute exists exit external fetch file fillfactor for foreign freetext from full function goto grant group having holdlock identity if in index inner insert intersect into is join key kill left like lineno load merge national nocheck nonclustered not null nullif of off offsets on open option or order outer over percent pivot plan precision primary print proc procedure public raiserror read readtext reconfigure references replication restore restrict return revert revoke right rollback rowcount rowguidcol rule save schema securityaudit select semantickeyphrasetable session_user set setuser shutdown some statistics system_user table tablesample textsize then to top tran transaction trigger truncate try_convert tsequal union unique unpivot update updatetext use user values varying view waitfor when where while with writetext'.split(
    ' '
  )
);

// The keywords Orbit writes in sql`…` text, in upper case. Any other word in upper or mixed case
// is a name written by hand (SELECT PASSWORD FROM …), so it must come through id() like a lower
// case one. Function names are recognised by the "(" after them instead.
export const KEYWORDS = new Set(
  'ADD ALL ALTER AND AS ASC BETWEEN BIGINT BLOB BY CASE CHECK COLLATE COLUMN CONFLICT CONSTRAINT CREATE CROSS CURRENT DEFAULT DELETE DESC DISTINCT DO DROP ELSE END ESCAPE EXCEPT EXISTS FALSE FILTER FIRST FOLLOWING FROM FULL GLOB GROUP HAVING IF IN INDEX INNER INSERT INTEGER INTERSECT INTO IS JOIN KEY LAST LEFT LIKE NOT NOTHING NULL NULLS NUMERIC OF ON OR OUTER OVER PARTITION PRECEDING PRIMARY RANGE REAL RECURSIVE REFERENCES RIGHT ROW ROWS SELECT SET TABLE TEXT THEN TRUE UNBOUNDED UNION UNIQUE UPDATE USING VALUES WHEN WHERE WINDOW WITH'.split(
    ' '
  )
);

// Replaces '…' literals (data, not SQL) in SQL text.
const withoutLiterals = text => text.replace(/'(?:[^']|'')*'/g, "''");

/**
 * The problems of the text of one sql`…` template (MARK for each ${…}). `registered` tells the
 * registry's names (default: lib/db/registry.mjs): a name the statement defines (an alias, a CTE)
 * may be used bare, but not one that is also a registered table, column or index, which would
 * read as that name to anyone but the engine.
 */
export function checkSqlText(text, { registered = registeredName } = {}) {
  const problems = [];
  const plain = withoutLiterals(text);
  for (const [rule, pattern, advice] of FORBIDDEN)
    if (pattern.test(plain.replaceAll(MARK, ' '))) problems.push({ rule, message: advice });
  const quoted = /"[^"\n]*"|`[^`\n]*`|\[[A-Za-z_][\w ]*\]/g;
  if (quoted.test(plain))
    problems.push({
      rule: 'quoted-identifier',
      message: 'quote identifiers with id(), not by hand',
    });
  const tokens =
    plain
      .replace(quoted, MARK)
      .replaceAll(MARK, ` ${MARK} `)
      .match(/[A-Za-z_][\w$]*|\S/g) ?? [];
  const isWord = token => /^[A-Za-z_]/.test(token);
  const keyword = token => KEYWORDS.has(token);
  // Names the statement defines, with what they stand for: 'table' (an alias of a table named
  // through id()), 'relation' (a CTE, or an alias of a CTE or a subquery, whose columns the
  // statement defines too) or 'output' (a column alias of the select list).
  const defined = new Map(),
    definitions = new Set();
  // Whether tokens[close] is the ")" of a subquery, (SELECT …) or (WITH …), not of a call.
  const subquery = close => {
    if (tokens[close] !== ')') return false;
    for (let depth = 0, at = close; at >= 0; at -= 1) {
      if (tokens[at] === ')') depth += 1;
      else if (tokens[at] === '(' && --depth === 0) {
        const call = isWord(tokens[at - 1] ?? '') && !keyword(tokens[at - 1]);
        return !call && ['SELECT', 'WITH', MARK].includes(tokens[at + 1]);
      }
    }
    return false;
  };
  const define = (index, kind) => {
    definitions.add(index);
    if (!defined.has(tokens[index]) || kind === 'relation') defined.set(tokens[index], kind);
  };
  tokens.forEach((token, index) => {
    if (!isWord(token) || keyword(token)) return;
    const before = tokens[index - 1],
      after = tokens[index + 1];
    if (before === 'AS')
      define(
        index,
        tokens[index - 2] === MARK ? 'table' : subquery(index - 2) ? 'relation' : 'output'
      );
    else if (after === 'AS' && tokens[index + 2] === '(') define(index, 'relation'); // a CTE
  });
  // An alias without AS follows what it names: a table (id()), a subquery's ")" or a CTE.
  tokens.forEach((token, index) => {
    if (!isWord(token) || keyword(token) || definitions.has(index)) return;
    const before = tokens[index - 1];
    if (tokens[index + 1] === '(' || tokens[index + 1] === '.') return;
    if (before === MARK) define(index, 'table');
    else if (before === ')') define(index, subquery(index - 1) ? 'relation' : 'output');
    else if (
      defined.get(before) === 'relation' &&
      /^(?:FROM|JOIN|,)$/.test(tokens[index - 2] ?? '')
    )
      define(index, 'relation');
  });
  tokens.forEach((token, index) => {
    if (!isWord(token)) return;
    const before = tokens[index - 1],
      after = tokens[index + 1];
    const lower = token.toLowerCase();
    if (definitions.has(index)) {
      if (RESERVED.has(lower))
        problems.push({
          rule: 'reserved-alias',
          message: `the alias ${token} is reserved in SQL Server`,
        });
      return;
    }
    if (keyword(token)) return;
    if (after === '(') return; // a function call (COALESCE, NULLIF … are reserved but callable)
    // FROM/JOIN/INTO/UPDATE NAME: reported below as a table named by hand.
    if (!/[a-z]/.test(token) && /^(?:FROM|JOIN|INTO|UPDATE)$/.test(before ?? '')) return;
    // alias.column: the columns of a CTE or subquery are the statement's own.
    if (before === '.') {
      if (defined.get(tokens[index - 2]) === 'relation') return;
    } else if (defined.has(token) && !registered(token)) return;
    problems.push({
      rule: 'bare-identifier',
      message: /[a-z]/.test(token)
        ? `${token} must come through id()`
        : `${token} must come through id() (keywords are written in upper case; it is not one)`,
    });
  });
  // FROM/JOIN/INTO/UPDATE must name their table through id() (or a subquery). Lower-case names
  // were reported above as bare identifiers.
  const tablePosition = /\b(FROM|JOIN|INTO|UPDATE)\s+(?!\(|\u0001)(\S+)/g;
  for (const match of plain.matchAll(tablePosition))
    if (!/[a-z]/.test(match[2]))
      problems.push({
        rule: 'bare-table',
        message: `${match[1]} ${match[2]}: name the table with id()`,
      });
  return problems;
}

// ---------------------------------------------------------------------------------------------
// Where the rules apply.

/**
 * lib/store.mjs, the 1.x store, keeps the hand-written SQL it had (invariant 1), and nothing
 * else: each raw statement (a literal, or literals joined with +, as written in the source with
 * its ${…} expressions, white space collapsed) must be one of these, by SHA-256 (first 16 hex
 * digits). A new or changed statement, even one with no refused construct, fails the lint: new
 * SQL there is written with sql`…`. `node scripts/sql-lint.mjs --legacy` lists the statements and
 * their hashes, for a reviewed change.
 */
export const LEGACY = Object.freeze({
  'lib/store.mjs': Object.freeze(
    new Set([
      '87efacd0f0dcd344',
      'ca70d75892f1291c',
      '0c2156b41645f2ee',
      '9b532957dcbed18d',
      'd2042a3b4f52591c',
      '277eeb9c911fb9c5',
      '529d763faf07e84e',
      '6f9bf92dab014ade',
      '6b7eb7da5c62c2ba',
      '57bce958ff08b590',
      '72169fb0b5e93a70',
      'd4fe37be3f1d5704',
      '10553c9ed5096543',
      'bded1dd16746d87c',
      '32942146ce40175c',
      '3bc40a49d855e0a3',
      '478a36a3c0dd7d3a',
      'aee20218a913d4e9',
      '94445eb18f5a8a4a',
      '9e8da3da28feaaa1',
      '4e9ea4368ddb892d',
      '50c0e09e16cd50c4',
      '24f4c190c9710491',
      'd85257689fe3b093',
      '4a794c4a8c3a68c5',
      '9a366ffbaefff80c',
      '22f3ee16da8b77cf',
      'ba4866ed39882ab4',
      '64e2854dcf38196b',
      'b2d2d55577abad1e',
      '70bd3afe42da6b0e',
      '2152b14e35b34412',
      '69c4602356513a33',
      '62222c6ba20f0a3a',
      '4ba4d16c367a0935',
      'e627c780c40ceb02',
      '677dd0074b420c95',
      '8cd13136d87dd9d4',
      '32486e289a7c9209',
      'fe63ff4015538acd',
      'f800122685a71032',
      'e421720982575535',
      '4ddc562335de47c9',
      'f89eb780fcbeaa08',
    ])
  ),
});

/**
 * The modules that hold a raw node:sqlite connection (import-graph allows node:sqlite in no
 * other), with their sinks (the methods that hand text to it) and the only sites where a sink
 * takes a variable: the call (white space removed), the functions it is in (their headers,
 * outermost first), the variable and how it is bound there: a parameter of the innermost
 * function with no default, or the one declaration named, at the top of that function. The
 * variable may be bound or changed nowhere else in that function. Any other argument is one
 * literal statement alone: a frozen one (LEGACY), one of `literals`, or one of the driver's
 * control statements (driverControl).
 *
 * A connection is made only as `name = new DatabaseSync(…);` (or `const name = …`, or
 * `this.#name = …`), a statement of its own, and node:sqlite is imported by name, `imports`
 * alone. That name (in the function that makes it; `this.#name` in the whole module) is then
 * used only as the receiver of a sink or of one of CONNECTION_MEMBERS, never as a value
 * (destructured, aliased, passed on, returned, reached by a computed key), except in the
 * statements `values` lists, white space removed, with the functions they are in (and, given a
 * `body`, that function's whole body, the text of its literals aside: the test seam's check
 * comes first and nothing else is there). DatabaseSync has other methods that run SQL text
 * (createTagStore(), whose tags take an array) or replace the database (deserialize(),
 * applyChangeset(), loadExtension()); none is a member here.
 */
export const CONNECTION_HOLDERS = Object.freeze({
  'lib/db/sqlite.mjs': Object.freeze({
    sinks: Object.freeze(['prepare', 'exec']),
    literals: Object.freeze({}),
    imports: Object.freeze(['DatabaseSync', 'backup']),
    values: Object.freeze([
      Object.freeze({
        in: 'constructor(db, kind, runDdl)',
        code: 'this.#db = db;',
        why: "Transaction: its #db is the Db (SqliteDb), whose prepare() takes sql`…` queries only; the name is the Db's field's too",
      }),
      Object.freeze({
        in: 'async function backupDatabase(source, destination)',
        code: 'pages = await sqliteBackup(db, sqlitePath(destination));',
        why: "node:sqlite's backup() copies the database to a file; it runs no SQL text",
      }),
    ]),
    sites: Object.freeze([
      Object.freeze({
        in: 'prepare(query)',
        call: 'this.#db.prepare(text)',
        name: 'text',
        from: 'const { text, params } = this.#dialect.render(query)',
        why: 'Db#prepare: rendered by the dialect from a sql`…` query (render() refuses anything else; the dialect is a private field no repository can replace)',
      }),
      Object.freeze({
        in: '#statement(query, writing)',
        call: 'this.#db.prepare(query)',
        name: 'query',
        from: 'parameter',
        why: 'Transaction: its #db is the Db, whose prepare() takes a sql`…` query and refuses anything else',
      }),
      Object.freeze({
        in: '#unit(kind, fn) > statement =>',
        call: 'this.#db.exec(statement)',
        name: 'statement',
        from: 'parameter',
        why: 'Transaction#ddl: one statement isAdditiveDdl accepted',
      }),
      Object.freeze({
        in: '#unit(kind, fn)',
        call: 'this.#db.exec(begin)',
        name: 'begin',
        from: "const begin = kind === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN'",
        why: "a unit's BEGIN or BEGIN IMMEDIATE",
      }),
    ]),
  }),
  'lib/store.mjs': Object.freeze({
    sinks: Object.freeze(['prepare', 'exec', 'drain', 'pragma']),
    literals: Object.freeze({
      // data_version (read only): whether another connection wrote while the Store ran, which
      // decides whether close() may keep the history summaries' coverage marks.
      pragma: Object.freeze(['page_count', 'page_size', 'freelist_count', 'data_version']),
    }),
    imports: Object.freeze(['DatabaseSync']),
    values: Object.freeze([
      Object.freeze({
        in: 'get db()',
        code: 'return this.#db;',
        body: "if (!storeConnectionsExposed()) throw new Error('…'); return this.#db;",
        why: 'the test seam: it throws unless exposeStoreConnections() ran (test/setup.mjs; lib/store-connections.mjs, which import-graph keeps to lib/store.mjs), and is that check and this statement alone',
      }),
    ]),
    sites: Object.freeze([
      Object.freeze({
        in: '#prepare(text)',
        call: 'this.#db.prepare(text)',
        name: 'text',
        from: 'parameter',
        why: "a frozen statement its caller passes (LEGACY), or #query's text",
      }),
      Object.freeze({
        in: 'async #drain(text, parameters, shouldContinue = () => true)',
        call: 'this.#db.prepare(text)',
        name: 'text',
        from: 'parameter',
        why: 'a frozen statement of prune() (LEGACY)',
      }),
      Object.freeze({
        in: '#query(query)',
        call: 'this.#prepare(text)',
        name: 'text',
        from: 'const { text, params } = dialect.render(query)',
        why: 'rendered from a sql`…` query (render() refuses anything else)',
      }),
      Object.freeze({
        in: 'constructor(directory, options = {}) > name =>',
        call: 'this.#pragma(name)',
        name: 'name',
        from: 'parameter',
        why: 'page_count, page_size or freelist_count, asked by lib/series/disk-budget.mjs',
      }),
    ]),
  }),
});

/**
 * What the SQLite driver (lib/db/sqlite.mjs) may send as a plain string: connection control,
 * one statement each, with these values spliced into a PRAGMA. A PRAGMA takes no bound value.
 */
const driverControl = [
  /^PRAGMA [a-z_]+(?:=(?:[A-Za-z0-9_]+|\u0001))?$/,
  /^PRAGMA [a-z_]+\([A-Z]+\)$/,
  /^PRAGMA \u0001$/,
  /^(?:BEGIN(?: IMMEDIATE| EXCLUSIVE| DEFERRED)?|COMMIT|ROLLBACK)$/,
  /^SELECT count\(\*\) FROM sqlite_master$/,
];
export const DRIVER_VALUES = Object.freeze({
  busyTimeoutMs: 'an integer from 0 to 250, checked by the constructor',
  maxBusyTimeoutMs: 'a constant',
  "synchronous === 'NORMAL' ? 'NORMAL' : 'FULL'": 'one of two constants',
  text: 'Db#pragma(): matched the allowedPragma list first',
});
// A sql`…` template in lib/db that reads SQLite's own catalog names engine tables and columns
// (sqlite_master, type, name), which the registry does not hold.
const engineCatalog =
  /^\s*(?:PRAGMA\s+quick_check\s*$|SELECT\b[\s\S]*\bFROM\s+(?:sqlite_master|sqlite_schema|pragma_[a-z_]+\s*\())/;

// The helpers of the tag that are values, not calls of it: sql.id(…), sql.join(…) and so on.
const tagHelpers = new Set(['id', 'ids', 'join', 'list', 'json', 'empty']);
// What lib/db/sql.mjs keeps to lib/db: SQL text written as given, and the constructors. The
// first two turn any string into SQL text, so only the dialects (lib/db/dialect/*) may use them,
// the rest of lib/db included.
const textInternals = ['fragment', 'directive'];
const internals = [...textInternals, 'Query', 'Identifier', 'Directive', 'JsonValue'];

const posix = file => file.split(path.sep).join('/');
const isDialectFile = file => file.startsWith('lib/db/dialect/') || file === 'lib/db/sql.mjs';
const isDriverFile = file => /^lib\/db\/[^/]+\.mjs$/.test(file);
/** Modules that may issue SQL (§2.1, §10.4): the database layer, repositories and the stores. */
export const isSqlIssuer = file =>
  file.startsWith('lib/db/') ||
  file.startsWith('lib/repo/') ||
  file.startsWith('lib/series/') ||
  file === 'lib/cluster/store.mjs' ||
  file === 'lib/store.mjs';

const isSqlTag = tag => tag === 'sql';

/**
 * The shipped server files the rules cover, relative to `root`: server.mjs, each .mjs module
 * under lib/, and every module they reach by a relative import (public/shared/*.js, which runs
 * in the server too, or a hidden lib/.x.mjs), so no module the server loads goes unchecked.
 */
export function serverFiles(root = repositoryRoot) {
  const files = new Set();
  const walk = relative => {
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute)) return;
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const item = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(item);
      else if (entry.name.endsWith('.mjs')) files.add(item);
    }
  };
  walk('lib');
  if (fs.existsSync(path.join(root, 'server.mjs'))) files.add('server.mjs');
  const queue = [...files];
  while (queue.length) {
    const file = queue.shift();
    let source;
    try {
      source = fs.readFileSync(path.join(root, file), 'utf8');
    } catch {
      continue;
    }
    const scanned = scan(source);
    const specifiers = [
      ...moduleDeclarations(source, scanned).declarations.map(item => item.specifier),
      ...dynamicImports(source, scanned).imports.map(item => item.specifier),
    ];
    for (const specifier of specifiers) {
      if (!/^\.\.?\//.test(specifier) || !/\.m?js$/.test(specifier)) continue;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
      if (target.startsWith('../') || files.has(target)) continue;
      try {
        if (!fs.statSync(path.join(root, target)).isFile()) continue;
      } catch {
        continue;
      }
      files.add(target);
      queue.push(target);
    }
  }
  return [...files].sort();
}

const collapse = text => text.replace(/\s+/g, ' ').trim();
/** The SHA-256 (first 16 hex digits) of a legacy statement's collapsed source. */
export const statementHash = code =>
  createHash('sha256').update(collapse(code)).digest('hex').slice(0, 16);

/**
 * The plain (untagged) literals of a source joined into expressions: literals connected by "+",
 * directly or through simple operands (a name, a call, a member), are one text, with MARK for
 * each operand and ${…}. So 'SELECT * ' + 'FROM t WHERE x = ' + v reads as one statement.
 * Returns [{line, text, interpolated, code, start, end}], `code` being the source of the whole.
 */
export function plainTexts(source, scanned = scan(source)) {
  const { strings, templates, masked } = scanned;
  const pieces = [
    ...strings.map(item => ({ ...item, joined: item.text, interpolated: false })),
    ...templates
      .filter(item => !isSqlTag(item.tag))
      .map(item => ({
        ...item,
        joined: item.parts.join(MARK),
        interpolated: item.parts.length > 1,
      })),
  ].sort((a, b) => a.start - b.start);
  const joined = [];
  for (const piece of pieces) {
    const last = joined.at(-1);
    const between = last && piece.start >= last.end ? masked.slice(last.end, piece.start) : null;
    if (between !== null && /^\s*\+\s*$/.test(between)) {
      last.text += piece.joined;
      last.interpolated ||= piece.interpolated;
      last.end = piece.end;
    } else if (between !== null && /^\s*\+[^;{}=,]*\+\s*$/.test(between)) {
      last.text += MARK + piece.joined;
      last.interpolated = true;
      last.end = piece.end;
    } else
      joined.push({
        line: piece.line,
        text: piece.joined,
        interpolated: piece.interpolated,
        start: piece.start,
        end: piece.end,
      });
  }
  // A literal followed or preceded by "+ operand" alone still splices a value into its text
  // (`joinedWithValue`): its `code` holds the literals only, so the legacy freeze refuses it.
  for (const item of joined) {
    if (/^\s*\+/.test(masked.slice(item.end, item.end + 40))) {
      item.text += MARK;
      item.interpolated = item.joinedWithValue = true;
    }
    if (/\+\s*$/.test(masked.slice(Math.max(0, item.start - 40), item.start))) {
      item.text = MARK + item.text;
      item.interpolated = item.joinedWithValue = true;
    }
    item.joinedWithValue ??= false;
    item.code = source.slice(item.start, item.end);
  }
  return joined;
}

/**
 * Whether the module specifier `specifier`, written in `file`, names lib/db/sql.mjs, however it is
 * spelt: '../db/./sql.mjs', '../x/../db/sql.mjs', an absolute path or file: URL, and a query or
 * fragment after any of them (which loads a second instance of it) all reach that module, and a
 * match on the text 'db/sql.mjs' missed most of them.
 */
export function namesSqlModule(file, specifier) {
  let target = String(specifier).replace(/[?#][\s\S]*$/, '');
  if (target.startsWith('file:'))
    try {
      target = fileURLToPath(target);
    } catch {
      return false;
    }
  if (target.startsWith('.'))
    target = path.posix.normalize(path.posix.join(path.posix.dirname(file), target));
  else if (!path.posix.isAbsolute(target)) return false;
  // In any case: a file system that ignores case (macOS by default) loads '../db/SQL.mjs' too.
  target = target.toLowerCase();
  return target === 'lib/db/sql.mjs' || target.endsWith('/lib/db/sql.mjs');
}

// The local names `sql` is imported under from lib/db/sql.mjs, the names imported or re-exported
// from it (`found`, a name written as a string read as its value), the declarations that take
// more than names from it (a namespace, `export *`, a default import), and where its
// declarations are in the source (`spans`).
function sqlImports(file, source, scanned = scan(source)) {
  const names = new Set(),
    found = [],
    wholesale = [],
    spans = [];
  for (const declaration of moduleDeclarations(source, scanned).declarations) {
    if (!namesSqlModule(file, declaration.specifier)) continue;
    spans.push([declaration.start, declaration.end]);
    if (declaration.namespace !== null || declaration.star || declaration.default !== null)
      wholesale.push(declaration);
    for (const { imported, local } of declaration.names) {
      found.push(imported);
      if (imported === 'sql' && declaration.keyword === 'import') names.add(local);
    }
  }
  return { names, found, wholesale, spans };
}

// A receiver named like a connection, ending the text before a member: db, this.#db, store.db,
// connection, conn, sqlite, handle (RegExp#exec is not one).
const connectionLike =
  /(?:^|[^\w$])#?(?:db|database|connection|conn|sqlite|handle)\s*(?:\?\.)?\s*$/i;
// Such a receiver's members by a computed key, or handed to Reflect or Object.
const connectionMember =
  /(?<![\w$])#?(?:db|database|connection|conn|sqlite|handle)\s*(?:\?\.\s*)?\[|\b(?:Reflect\s*\.\s*(?:get|apply|getOwnPropertyDescriptor)|Object\s*\.\s*(?:getOwnPropertyDescriptors?|values|entries))\s*\(\s*(?:[\w$]+\s*\.\s*)*#?(?:db|database|connection|conn|sqlite|handle)\b/gi;

// The index of the bracket that closes the one at `open` in scanned source (its end if none).
function closingBracket(masked, open) {
  for (let depth = 0, i = open; i < masked.length; i += 1) {
    if ('([{'.includes(masked[i])) depth += 1;
    else if (')]}'.includes(masked[i]) && --depth === 0) return i;
  }
  return masked.length;
}
// The index of the bracket that opens the one at `close` (-1 if none).
function openingBracket(masked, close) {
  for (let depth = 0, i = close; i >= 0; i -= 1) {
    if (')]}'.includes(masked[i])) depth += 1;
    else if ('([{'.includes(masked[i]) && --depth === 0) return i;
  }
  return -1;
}
// The bracket that opens the innermost block or group holding `index`, at `from` or after it.
function openingOf(masked, index, from) {
  for (let depth = 0, i = index - 1; i > from; i -= 1) {
    if (')]}'.includes(masked[i])) depth += 1;
    else if ('([{'.includes(masked[i]) && --depth < 0) return i;
  }
  return from;
}
// The receiver before the member at `index`: `this.#db` of this.#db.prepare(…).
const receiverOf = (masked, index) =>
  /(?<![\w$#])(?:[\w$#]+\s*(?:\?\.|\.)\s*)*[\w$#]+\s*(?:\?\.|\.)?\s*$/.exec(
    masked.slice(Math.max(0, index - 200), index)
  )?.[0] ?? '';
// The parameters of a parameter list's text, split at its top-level commas.
function parameterList(text) {
  const parameters = [];
  let depth = 0,
    current = '';
  for (const ch of text) {
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    if (ch === ',' && depth === 0) {
      parameters.push(current.trim());
      current = '';
    } else current += ch;
  }
  if (current.trim()) parameters.push(current.trim());
  return parameters;
}

/**
 * The functions of a scanned source: methods, function declarations and expressions and arrows,
 * as [{header (its collapsed text up to the body: '#prepare(text)', 'name =>'), parameters
 * (their text), parametersStart, parametersEnd, start, bodyStart, end}]. An arrow's expression
 * body ends at the first "," or ";" or unmatched closer at its depth.
 */
export function functionSpans(masked) {
  const functions = [];
  const notCalls = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'return', 'typeof']);
  const arrowParameters = end => {
    // The parameters before "=>" ending at `end`: (a, b) or a single name.
    const before = masked.slice(0, end).trimEnd();
    if (before.endsWith(')')) {
      const open = openingBracket(masked, before.length - 1);
      if (open < 0) return null;
      const start = /(?<![\w$])async\s*$/.exec(masked.slice(Math.max(0, open - 20), open))
        ? open - /async\s*$/.exec(masked.slice(Math.max(0, open - 20), open))[0].length
        : open;
      return { start, parametersStart: open + 1, parametersEnd: before.length - 1 };
    }
    const name = /(?<![\w$#.])(?:async\s+)?([A-Za-z_$][\w$]*)$/.exec(before);
    if (!name) return null;
    const nameStart = before.length - name[1].length;
    return {
      start: before.length - name[0].length,
      parametersStart: nameStart,
      parametersEnd: before.length,
    };
  };
  const add = (head, bodyStart, end, headerEnd) =>
    functions.push({
      header: collapse(masked.slice(head.start, headerEnd)),
      parameters: parameterList(masked.slice(head.parametersStart, head.parametersEnd)),
      parametersStart: head.parametersStart,
      parametersEnd: head.parametersEnd,
      start: head.start,
      bodyStart,
      end,
    });
  for (let i = 0; i < masked.length; i += 1) {
    if (masked[i] === '{') {
      const before = masked.slice(0, i).trimEnd();
      if (before.endsWith('=>')) {
        const head = arrowParameters(before.length - 2);
        if (head) add(head, i, closingBracket(masked, i) + 1, before.length);
      } else if (before.endsWith(')')) {
        const open = openingBracket(masked, before.length - 1);
        const name =
          open < 0
            ? null
            : /(?<![\w$#.])((?:(?:async|static|get|set)\s+)*(?:function\b\s*\*?\s*[\w$]*|\*?#?[\w$]+))\s*$/.exec(
                masked.slice(Math.max(0, open - 200), open)
              );
        const word = name?.[1].replace(/^(?:(?:async|static|get|set)\s+)*/, '');
        if (name && !notCalls.has(word))
          add(
            {
              start: open - name[0].length,
              parametersStart: open + 1,
              parametersEnd: before.length - 1,
            },
            i,
            closingBracket(masked, i) + 1,
            before.length
          );
      }
    } else if (masked[i] === '=' && masked[i + 1] === '>' && !/^\s*\{/.test(masked.slice(i + 2))) {
      const head = arrowParameters(i);
      if (!head) continue;
      let end = i + 2;
      for (let depth = 0; end < masked.length; end += 1) {
        const ch = masked[end];
        if ('([{'.includes(ch)) depth += 1;
        else if (')]}'.includes(ch)) {
          if (depth === 0) break;
          depth -= 1;
        } else if ((ch === ',' || ch === ';') && depth === 0) break;
      }
      add(head, i + 2, end, i + 2);
    }
  }
  return functions.sort((a, b) => a.start - b.start);
}

/**
 * Whether the variable a CONNECTION_HOLDERS site passes is bound there as the site says, and
 * nowhere else in its function: a parameter of it with no default, or the one declaration the
 * site names (ending its statement). Any other declaration, assignment, update, destructuring or
 * parameter of a function inside of that name is refused: `const text = …` before the call is
 * how a statement built from values reached the connection. Returns a problem or null.
 */
function siteBinding(source, masked, functions, fn, site, callAt) {
  const name = site.name;
  const allowed = [];
  if (site.from === 'parameter') {
    const at = fn.parameters.indexOf(name);
    if (at < 0)
      return `${site.call}: ${name} must be a parameter of ${fn.header} without a default value`;
    const found = new RegExp(`(?<![\\w$.#])${name}(?![\\w$])`).exec(
      masked.slice(fn.parametersStart, fn.parametersEnd)
    );
    allowed.push(fn.parametersStart + found.index);
  } else {
    const pattern = new RegExp(
      site.from
        .split(/\s+/)
        .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('\\s*') + '\\s*;',
      'g'
    );
    const matches = [...source.slice(fn.bodyStart, fn.end).matchAll(pattern)];
    if (matches.length !== 1)
      return `${site.call}: ${name} must be declared once in ${fn.header} as ${site.from}`;
    const start = fn.bodyStart + matches[0].index;
    // Before the call, in a block that holds the call too (a declaration in a block of its own
    // is another variable to a call outside that block).
    const block = openingOf(masked, start, fn.bodyStart);
    if (!(start < callAt && callAt < closingBracket(masked, block)))
      return `${site.call}: ${name} must be declared before the call, in a block that holds it, as ${site.from}`;
    for (const match of masked
      .slice(start, start + matches[0][0].length)
      .matchAll(new RegExp(`(?<![\\w$.#])${name}(?![\\w$])`, 'g')))
      allowed.push(start + match.index);
  }
  for (const match of masked
    .slice(fn.start, fn.end)
    .matchAll(new RegExp(`(?<![\\w$.#])${name}(?![\\w$])`, 'g'))) {
    const at = fn.start + match.index;
    if (allowed.includes(at)) continue;
    const before = masked.slice(Math.max(0, at - 40), at),
      after = masked.slice(at + name.length, at + name.length + 40);
    let binding =
      /(?:^|[^\w$])(?:const|let|var|function|class)\s+$/.test(before) ||
      /(?:\+\+|--)\s*$/.test(before) ||
      /^\s*(?:\+\+|--|(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>]))/.test(after) ||
      /^\s*=>/.test(after) ||
      functions.some(
        other => other !== fn && at >= other.parametersStart && at < other.parametersEnd
      );
    // Inside a destructuring pattern ([a, text] = …, const { x: text } = …, for (const [text] of …)).
    for (let inner = at; !binding; ) {
      let open = -1;
      for (let depth = 0, i = inner - 1; i >= fn.start; i -= 1) {
        if (')]}'.includes(masked[i])) depth += 1;
        else if ('([{'.includes(masked[i])) {
          if (depth === 0) {
            open = i;
            break;
          }
          depth -= 1;
        }
      }
      if (open < 0 || masked[open] === '(') break;
      const close = closingBracket(masked, open);
      binding =
        /^\s*=(?![=>])|^\s+(?:of|in)\b/.test(masked.slice(close + 1, close + 20)) ||
        /(?:^|[^\w$])(?:const|let|var)\s*$/.test(masked.slice(Math.max(0, open - 20), open));
      inner = open;
    }
    if (binding)
      return `${site.call}: ${name} is bound or changed again in ${fn.header} (line of the call aside); it may only be ${site.from === 'parameter' ? 'its parameter' : site.from}`;
  }
  return null;
}

/**
 * What a raw connection's name may be followed by in a holder besides a sink: members that run
 * no SQL text. (`dialect` is read through the Transaction's #db, which is the Db.)
 */
export const CONNECTION_MEMBERS = Object.freeze(['close', 'isOpen', 'isTransaction', 'dialect']);
// DatabaseSync methods that run SQL text (createTagStore()'s tags take an array as well as a
// template), replace or extend the database (deserialize(), applyChangeset(), loadExtension()),
// or loosen its guards. No module but the holders names any of them, in code or as a string.
const connectionMethods = [
  'createTagStore',
  'deserialize',
  'applyChangeset',
  'createSession',
  'loadExtension',
  'enableLoadExtension',
  'enableDefensive',
  'setAuthorizer',
];

// Code as it reads in the scanned source, white space removed: the text of each literal blank.
const bare = code => code.replace(/'[^']*'/g, "''").replace(/\s+/g, '');

// The statement holding `index`, white space removed: from just after the ";", "{" or "}"
// before it (outside the brackets it is in) to its ";" (or the bracket that closes it).
function statementAt(masked, index) {
  let start = index;
  for (let depth = 0; start > 0; start -= 1) {
    const ch = masked[start - 1];
    if (ch === ')' || ch === ']') depth += 1;
    else if (ch === '(' || ch === '[') depth = Math.max(0, depth - 1);
    else if (depth === 0 && (ch === ';' || ch === '{' || ch === '}')) break;
  }
  let end = start;
  for (let depth = 0; end < masked.length; end += 1) {
    const ch = masked[end];
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch) && --depth < 0) break;
    else if (ch === ';' && depth === 0) {
      end += 1;
      break;
    }
  }
  return masked.slice(start, end).replace(/\s+/g, '');
}

/**
 * The raw connections of a holder used other than CONNECTION_HOLDERS allows (see there):
 * [{line, message}]. Covers how node:sqlite is imported, how each connection is made, and
 * every use of its name.
 */
function connectionUseProblems(holder, source, scanned, functions) {
  const { masked, lineOf } = scanned;
  const problems = [];
  const refuse = (index, message) => problems.push({ line: lineOf(index), message });
  const chainAt = index =>
    functions
      .filter(fn => fn.bodyStart <= index && index < fn.end)
      .map(fn => fn.header)
      .join(' > ');
  // node:sqlite by name, the holder's `imports` alone; nothing at run time.
  const spans = [];
  for (const declaration of moduleDeclarations(source, scanned).declarations) {
    if (declaration.specifier !== 'node:sqlite') continue;
    spans.push([declaration.start, declaration.end]);
    const names = declaration.names;
    if (
      declaration.keyword !== 'import' ||
      declaration.default !== null ||
      declaration.namespace !== null ||
      declaration.star ||
      names.some(({ imported }) => !holder.imports.includes(imported)) ||
      names.some(({ imported, local }) => imported === 'DatabaseSync' && local !== 'DatabaseSync')
    )
      refuse(
        declaration.start,
        `node:sqlite is imported here as import { ${holder.imports.join(', ')} } from 'node:sqlite', by those names alone`
      );
  }
  const loaded = dynamicImports(source, scanned);
  for (const line of [...loaded.imports.map(item => item.line), ...loaded.unresolvable])
    problems.push({
      line,
      message:
        'a module that holds a raw connection imports nothing at run time (import(), require(), getBuiltinModule()): node:sqlite or a second connection would be reached unseen',
    });
  // Each connection: `name = new DatabaseSync(…);`, a statement of its own.
  const connections = [],
    bindings = new Set();
  for (const match of masked.matchAll(/(?<![\w$.#])(?<!\.\s*)DatabaseSync(?![\w$])/g)) {
    if (spans.some(([start, end]) => match.index >= start && match.index < end)) continue;
    const offset = Math.max(0, match.index - 200);
    const made =
      /(?:(?<![\w$.#])(?:const|let|var)\s+([A-Za-z_$][\w$]*)|(?<![\w$.#])this\s*\.\s*(#[A-Za-z_$][\w$]*)|(?<![\w$.#])([A-Za-z_$][\w$]*))\s*=\s*new\s+$/d.exec(
        masked.slice(offset, match.index)
      );
    const after = match.index + match[0].length;
    const open = after + /^\s*/.exec(masked.slice(after))[0].length;
    const statementStart = made ? offset + made.index : -1;
    if (
      !made ||
      masked[open] !== '(' ||
      !/^\s*;/.test(masked.slice(closingBracket(masked, open) + 1)) ||
      !/(?:^|[;{}])\s*$/.test(masked.slice(Math.max(0, statementStart - 40), statementStart))
    ) {
      refuse(
        match.index,
        'a connection is made only as `name = new DatabaseSync(…);` (or const name, or this.#name), a statement of its own'
      );
      continue;
    }
    const group = made[1] !== undefined ? 1 : made[2] !== undefined ? 2 : 3;
    const name = made[group];
    bindings.add(offset + made.indices[group][0]);
    const fn = functions
      .filter(item => item.bodyStart <= match.index && match.index < item.end)
      .at(-1);
    const scope = name.startsWith('#') || !fn ? [0, masked.length] : [fn.start, fn.end];
    if (!connections.some(item => item.name === name && item.scope[0] === scope[0]))
      connections.push({ name, scope });
  }
  // Each use of a connection's name.
  for (const { name, scope } of connections) {
    const pattern = name.startsWith('#')
      ? new RegExp(`${name}(?![\\w$])`, 'g')
      : new RegExp(`(?<![\\w$.#])(?<!\\.\\s*)${name.replace(/\$/g, '\\$')}(?![\\w$])`, 'g');
    for (const match of masked.slice(0, scope[1]).matchAll(pattern)) {
      const at = match.index;
      if (at < scope[0]) continue;
      const before = masked.slice(Math.max(0, at - 60), at);
      const rest = masked.slice(at + name.length);
      let receiver = at;
      if (name.startsWith('#')) {
        if (/(?:^|[;{}])\s*$/.test(before) && /^\s*;/.test(rest)) continue; // the field's declaration
        const self = /(?<![\w$.#])this\s*(?:\?\.|\.)\s*$/.exec(before);
        if (!self) {
          refuse(at, `${name} is reached through this.${name} alone`);
          continue;
        }
        receiver = at - before.length + self.index;
      }
      const member = /^\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)/.exec(rest)?.[1];
      if (member !== undefined) {
        if (!holder.sinks.includes(member) && !CONNECTION_MEMBERS.includes(member))
          refuse(
            at,
            `${name}.${member}: a connection is used through its sinks (${holder.sinks.join(', ')}) and ${CONNECTION_MEMBERS.join(', ')} alone`
          );
        continue;
      }
      if (bindings.has(at)) continue;
      if (!name.startsWith('#') && /(?<![\w$.#])(?:let|var)\s+$/.test(before) && /^\s*;/.test(rest))
        continue; // let db;
      const statement = statementAt(masked, receiver);
      const within = chainAt(at);
      const fn = functions.filter(item => item.bodyStart <= at && at < item.end).at(-1);
      const body = fn ? masked.slice(fn.bodyStart + 1, fn.end - 1).replace(/\s+/g, '') : null;
      if (
        holder.values.some(
          value =>
            value.in === within &&
            value.code.replace(/\s+/g, '') === statement &&
            (value.body === undefined || bare(value.body) === body)
        )
      )
        continue;
      refuse(
        at,
        `${name} is a raw connection: it is used through its sinks and ${CONNECTION_MEMBERS.join(', ')} alone, never as a value (destructured, aliased, passed on, returned or reached by a computed key) but where CONNECTION_HOLDERS lists it`
      );
    }
  }
  return problems;
}

/** Findings for one file: [{file, line, rule, message}]. */
export function lintSource(file, source, options = {}) {
  file = posix(file);
  if (isDialectFile(file)) return [];
  const findings = [];
  const add = (line, rule, message) => findings.push({ file, line, rule, message });
  const scanned = scan(source);
  const { strings, templates, masked, lineOf } = scanned;
  const legacy = LEGACY[file];
  const holder = CONNECTION_HOLDERS[file];

  // 1. Raw SQL: a plain literal, or literals joined with +, that is a statement in any case.
  const texts = plainTexts(source, scanned);
  // In the legacy store, the literals a connection's prepare()/exec() is given, whatever they
  // look like ('vacuum', 'drop table readings'): each is SQL text by where it goes.
  const sinkStarts = new Set();
  if (legacy && holder)
    for (const match of masked.matchAll(/(?:\.|#)\s*(?:prepare|exec|drain)\s*(?:\?\.\s*)?\(\s*/g))
      sinkStarts.add(match.index + match[0].length);
  for (const item of texts) {
    const { line, text, interpolated } = item;
    if (legacy) {
      // Everything that may be a statement there, in any case and with or without values,
      // control statements included, and anything handed to a connection.
      if (
        !looksLikeSql(text) &&
        !anyCaseStatement.test(text) &&
        !/^\s*PRAGMA\b/i.test(text) &&
        !sinkStarts.has(item.start)
      )
        continue;
      if (item.joinedWithValue)
        add(
          line,
          'legacy-sql',
          `lib/store.mjs never joins a value to a statement with + (${collapse(item.code).slice(0, 80)}): the freeze sees only the literals; write it with sql\`…\``
        );
      else if (!legacy.has(statementHash(item.code)))
        add(
          line,
          'legacy-sql',
          `lib/store.mjs keeps the SQL it has (LEGACY) and no other: this statement is new or changed (${collapse(item.code).slice(0, 80)}); write it with sql\`…\``
        );
      continue;
    }
    if (!looksLikeSql(text)) continue;
    if (file === 'lib/db/sqlite.mjs' && driverStatement(item, templates)) continue;
    add(
      line,
      'raw-sql',
      interpolated
        ? 'SQL built with ${…} or + in a plain string; use sql`…` so values are bound'
        : isSqlIssuer(file)
          ? 'SQL in a plain string; write it with sql`…` and the dialect helpers'
          : 'only lib/db, lib/repo, lib/series and lib/store.mjs issue SQL'
    );
  }

  // 2. sql`…` templates: who writes them, and their text.
  for (const template of templates.filter(item => isSqlTag(item.tag))) {
    if (!isSqlIssuer(file))
      add(
        template.line,
        'sql-outside-repositories',
        'only lib/db, lib/repo, lib/series and lib/store.mjs issue SQL'
      );
    const text = template.parts.join(MARK);
    // lib/db reading SQLite's own catalog names engine tables, not registered ones; its other
    // rules still apply (a PRAGMA there is the quick_check of a copy, one statement).
    if (isDriverFile(file) && engineCatalog.test(text.replaceAll(MARK, ' '))) {
      for (const problem of checkSqlText(text, options))
        if (!['bare-identifier', 'bare-table', 'engine-control'].includes(problem.rule))
          add(template.line, problem.rule, problem.message);
      continue;
    }
    for (const problem of checkSqlText(text, options))
      add(template.line, problem.rule, problem.message);
  }

  // 3. Raw connections. Only the two node:sqlite importers hold one. What they pass to a sink
  //    (prepare(), exec() …) is one literal (checked above: frozen, or a driver statement) or a
  //    variable at a site CONNECTION_HOLDERS lists, bound there as it says and nowhere else in
  //    that function. Elsewhere nothing prepares a statement or takes a connection's exec, called
  //    or not (RegExp#exec is not one: the receiver is named like a connection).
  const functions = holder ? functionSpans(masked) : [];
  for (const match of masked.matchAll(/(?:\?\.|\.|#)\s*(prepare|exec|drain|pragma)(?![\w$])/g)) {
    const sink = match[1];
    const line = lineOf(match.index);
    const call = /^\s*(?:\?\.\s*)?\(/.exec(masked.slice(match.index + match[0].length));
    if (holder) {
      if (!holder.sinks.includes(sink)) continue;
      if (!call) {
        add(line, 'raw-connection', `${sink} is called where it is named, never taken as a value`);
        continue;
      }
      const open = match.index + match[0].length + call[0].length - 1;
      const close = closingBracket(masked, open);
      if (/^\s*\{/.test(masked.slice(close + 1))) continue; // its definition: #prepare(text) { … }
      const at = open + 1 + /^\s*/.exec(masked.slice(open + 1))[0].length;
      if (/^['"`]/.test(masked[at])) {
        // One literal as it is: nothing joined to it or called on it ('…' + clause, '…'.concat(…)).
        const item = texts.find(entry => entry.start === at);
        const allowed = holder.literals[sink];
        if (!item || !/^\s*[,)]/.test(masked.slice(item.end)) || item.joinedWithValue)
          add(line, 'raw-connection', `${sink}() takes one literal statement, nothing added to it`);
        else if (allowed && (item.interpolated || !allowed.includes(decodeLiteral(item.text))))
          add(line, 'raw-connection', `${sink}() takes one of ${allowed.join(', ')}`);
        else if (!allowed && !legacy && !driverStatement(item, templates))
          add(
            line,
            'raw-connection',
            `${sink}() in the driver takes one of its control statements (driverControl)`
          );
        continue;
      }
      const callText = (receiverOf(masked, match.index) + masked.slice(match.index, close + 1))
        .replace(/\s+/g, '')
        .replace(/\?\./g, '.');
      const chain = functions.filter(fn => fn.bodyStart <= match.index && match.index < fn.end);
      const within = chain.map(fn => fn.header).join(' > ');
      const site = holder.sites.find(entry => entry.call === callText && entry.in === within);
      const problem = site
        ? siteBinding(source, masked, functions, chain.at(-1), site, match.index)
        : `${callText} in ${within || 'module code'}: ${sink}() takes one literal statement, or a variable at a site CONNECTION_HOLDERS lists (scripts/sql-lint.mjs)`;
      if (problem) add(line, 'raw-connection', problem);
    } else if (sink === 'drain' || sink === 'pragma') continue;
    else if (sink === 'prepare')
      add(line, 'raw-connection', 'only lib/db/sqlite.mjs and lib/store.mjs prepare statements');
    else if (connectionLike.test(masked.slice(Math.max(0, match.index - 40), match.index)))
      add(
        line,
        'raw-connection',
        'only lib/db/sqlite.mjs and lib/store.mjs run SQL on a connection'
      );
  }
  // In a holder, each connection is made, imported and used only as CONNECTION_HOLDERS allows:
  // a sink taken by destructuring (const { prepare } = this.#db), an alias, or a method that is
  // no sink (createTagStore()) passed the rule above.
  if (holder)
    for (const problem of connectionUseProblems(holder, source, scanned, functions))
      add(problem.line, 'raw-connection', problem.message);
  else
    for (const match of masked.matchAll(/(?<![\w$#])(?<!(?:\?\.|\.)\s*)(prepare|exec)(?![\w$])/g))
      add(
        lineOf(match.index),
        'raw-connection',
        `${match[1]} is a connection's method: only lib/db/sqlite.mjs and lib/store.mjs name it but as a member, never destructured or declared`
      );
  for (const match of masked.matchAll(
    new RegExp(`(?<![\\w$])(?:${connectionMethods.join('|')})(?![\\w$])`, 'g')
  ))
    add(
      lineOf(match.index),
      'raw-connection',
      `${match[0]} runs SQL text or replaces a connection's database: Orbit never uses it`
    );
  // A connection's members reached by a computed key (db[key], Reflect.get(db, …)), which the
  // rule above does not see.
  for (const match of masked.matchAll(connectionMember))
    add(
      lineOf(match.index),
      'raw-connection',
      "a connection's members are reached by their name, never by a computed key or Reflect"
    );
  // A connection's method or the test seam named by a string, however it is written ('pr\x65pare',
  // `prepare`, 'pre' + 'pare'): it is reached by a computed key (x['prepare'](…),
  // Reflect.get(x, 'exec')), which the rules above do not see.
  for (const { value, line } of literalValues(source, scanned))
    if (
      [
        'prepare',
        'exec',
        'exposeStoreConnections',
        'getBuiltinModule',
        ...connectionMethods,
      ].includes(value)
    )
      add(
        line,
        value === 'exposeStoreConnections' ? 'store-connection' : 'raw-connection',
        `${value} is called by its name, never named by a string (a computed key reaches it)`
      );
  // The Store's connection is for tests only (test/setup.mjs).
  if (file !== 'lib/store-connections.mjs')
    for (const match of masked.matchAll(/\bexposeStoreConnections\b/g))
      add(
        lineOf(match.index),
        'store-connection',
        "the Store's connection is for tests only; use the Store's methods"
      );

  // 4. lib/db/sql.mjs internals stay in lib/db (the text-making ones in its dialects), and
  // `sql` is only ever a tag. Every spelling of the module's path counts (namesSqlModule).
  const imported = sqlImports(file, source, scanned);
  {
    const { found, wholesale } = imported;
    const inDb = file.startsWith('lib/db/');
    for (const name of inDb ? textInternals : internals)
      if (found.includes(name))
        add(
          1,
          'internal-api',
          inDb
            ? `${name} writes any string as SQL text, so only lib/db/dialect/* may use it`
            : `${name} is internal to lib/db; build SQL with sql\`…\` and the dialect helpers`
        );
    for (const declaration of wholesale)
      add(
        declaration.line,
        'internal-api',
        'import what you use from lib/db/sql.mjs by name; a namespace reaches its internals'
      );
    // A run-time import names one literal path, so the lint can tell lib/db/sql.mjs from
    // another module: import('../db/sq' + 'l.mjs') began with a literal and named it.
    const loaded = dynamicImports(source, scanned);
    for (const { specifier, line } of loaded.imports)
      if (namesSqlModule(file, specifier))
        add(
          line,
          'internal-api',
          'lib/db/sql.mjs is imported statically and by name, never with import()'
        );
    for (const line of loaded.unresolvable)
      add(
        line,
        'dynamic-import',
        'import() and the loaders (require(), getBuiltinModule(), createRequire()) are called by name with one literal path and nothing added to it, so the lint can tell which module they load'
      );
    // Every module named as Node resolves it: a spelling the lint would read as another path
    // ('../db/sq%6C.mjs', '..\\db\\sql.mjs', a data: URL) is refused.
    for (const { specifier, line } of [
      ...moduleDeclarations(source, scanned).declarations,
      ...loaded.imports,
    ]) {
      const problem = specifierProblem(specifier);
      if (problem) add(line, 'module-specifier', problem);
    }
  }
  // Code the scanner cannot read as JavaScript does hides what follows from every rule above.
  for (const { line, why } of scanned.unreadable)
    add(line, 'unreadable-code', UNREADABLE_CODE[why]);
  if (!file.startsWith('lib/db/')) {
    const { names, spans } = imported;
    // Every use of the tag but as a tag or a helper read (sql.id …): sql(…), sql.call,
    // sql.apply, an alias (const t = sql), passing it on (Reflect.apply(sql, …), f(sql)). Its
    // import declarations name it without using it.
    for (const name of names)
      for (const match of masked.matchAll(
        new RegExp(`(?<![\\w$.#])${name.replace(/\$/g, '\\$')}(?![\\w$])`, 'g')
      )) {
        const line = lineOf(match.index);
        if (spans.some(([start, end]) => match.index >= start && match.index < end)) continue;
        const rest = masked.slice(match.index + name.length);
        if (/^\s*`/.test(rest)) continue;
        const helper = /^\s*\.\s*([\w$]+)/.exec(rest)?.[1];
        if (helper && tagHelpers.has(helper)) continue;
        add(
          line,
          'internal-api',
          `${name} is a template tag: write ${name}\`…\` (or ${name}.id(), ${name}.join() …), never use it as a value`
        );
      }
    // The constructors behind sql`…` and id() values (refused at run time as well).
    if (isSqlIssuer(file))
      for (const match of masked.matchAll(
        /\.\s*constructor\b(?!\s*\??\.\s*name\b)|\bgetPrototypeOf\s*\(/g
      ))
        add(
          lineOf(match.index),
          'internal-api',
          'a query is built with sql`…` and the dialect helpers, never through a constructor'
        );
  }
  return findings;
}

// Whether a plain text in lib/db/sqlite.mjs is one of the driver's control statements, with
// only the values DRIVER_VALUES lists spliced in.
function driverStatement(item, templates) {
  const text = collapse(item.text);
  if (!driverControl.some(shape => shape.test(text))) return false;
  if (!item.interpolated) return true;
  const template = templates.find(entry => entry.start === item.start && entry.end === item.end);
  return Boolean(
    template &&
      template.expressions.every(expression => Object.hasOwn(DRIVER_VALUES, collapse(expression)))
  );
}

// The registry's names (tables, columns, indexes), for checkSqlText().
const registeredName = name => registry.identifiers.has(name);

/** Lints the repository at `root`. */
export function lint(root = repositoryRoot, files = serverFiles(root)) {
  // A link to lib/db/sql.mjs (or a directory linked into lib/) names it under another path.
  const links = moduleLinks(root).map(file => ({
    file,
    line: 1,
    rule: 'module-link',
    message:
      "server code is a file or a directory, never a symbolic link: Node loads a link under its target's name",
  }));
  return [
    ...links,
    ...files.flatMap(file => lintSource(file, fs.readFileSync(path.join(root, file), 'utf8'))),
  ];
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
  let root = repositoryRoot;
  const asJson = args.includes('--json');
  const rest = args.filter(arg => arg !== '--json' && arg !== '--legacy');
  if (rest[0] === '--root' && rest[1] && rest.length === 2) root = path.resolve(rest[1]);
  else if (rest.length) {
    console.error('Usage: node scripts/sql-lint.mjs [--root <dir>] [--json] [--legacy]');
    process.exit(2);
  }
  // --legacy: the raw statements of lib/store.mjs with their hashes, to review a change to LEGACY.
  if (args.includes('--legacy')) {
    const source = fs.readFileSync(path.join(root, 'lib', 'store.mjs'), 'utf8');
    for (const item of plainTexts(source))
      if (looksLikeSql(item.text) || /^\s*PRAGMA\b/i.test(item.text))
        console.log(`${statementHash(item.code)} ${item.line}: ${collapse(item.code)}`);
    process.exit(0);
  }
  const files = serverFiles(root);
  const findings = lint(root, files);
  if (asJson) console.log(JSON.stringify(findings, null, 2));
  else if (findings.length)
    for (const f of findings) console.error(`✖ ${f.file}:${f.line} ${f.rule}: ${f.message}`);
  else console.log(`✔ ${files.length} server modules follow the SQL rules`);
  if (findings.length) process.exitCode = 1;
}
