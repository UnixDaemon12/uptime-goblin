// The static check behind test/docker-limits.test.mjs: every container a test starts gets
// finite memory, CPU and process limits. It reads JavaScript source without running it, with
// a small tokenizer (strings, template literals, regular expressions and comments are told
// apart, so text that only looks like a call is never taken for one; strings, templates and
// names are read as node reads them, escapes included, so '\x64ocker', 'doc\<line end>ker' or
// \u0073pawnSync hide nothing; where node may read a source two ways, such as a `/` after `}`, or
// an escape node refuses, the file cannot be read and fails), and checks:
//
// 1. Every spawn of the docker executable (spawnSync, spawn, execFileSync or execFile whose
//    command names docker in a string or template literal: 'docker', `docker`, a path ending in
//    /docker, in any case, as macOS finds it so, or an expression holding one, such as
//    path.join(bin, 'docker')) passes its arguments as an array literal, or is a wrapper
//    `const name = (...args) => spawnSync('docker', args, …)`, whose calls are checked instead.
//    Anything else (a shell string, arguments built elsewhere) cannot be checked and is refused.
//    Those functions count under any name a module imports them as (`import { spawnSync as sh }`,
//    `const { execFile: run } = require('node:child_process')`), and a function of child_process
//    or a wrapper used other than by calling it (an alias, promisify(execFile), docker.apply,
//    passed on, exported, re-exported) is refused, since its calls could not be followed. Any
//    other call whose first argument names docker and whose second is an array literal (a helper
//    of another module, run('docker', ['run', …])) is checked as a docker call too. A spawn whose
//    program no literal names (a variable, `${dir}/${name}`, a call) could be docker, so it is
//    refused unless the program, as written, is reviewed and listed; a literal, a template ending
//    in `/name`, path.join(…, 'name') and process.execPath name it. A command line handed to a
//    shell (exec, execSync, or a spawn given one with a blank in it) is read as a line of a file
//    that is not JavaScript (rule 4), and one no literal gives is refused unless reviewed.
// 2. A docker call whose subcommand is `run` or `create` (also `container run|create`) gives
//    --memory, --cpus and --pids-limit, each with a finite, nonzero value (memory counted in
//    whole bytes as Docker counts them, so `--memory=0.5` is 0: its 6 MiB minimum, up to int64),
//    right after the subcommand: written out, or spread from an array constant of the same file
//    (`...limits`: a `const` array of string literals, used nowhere else in the file but in such
//    spreads, so nothing can change it). Right after the subcommand, because an option after the
//    image name would go to the container's command instead of to Docker. The words after them
//    are read as Docker reads them, up to the image: a limit given there again is refused,
//    whatever its value, since Docker keeps the last value given (`--memory=1g … --rm -m 0` has
//    no limit). So is a spread there that this check cannot read (`...args`), unless it is
//    reviewed. Where a word cannot be read (a variable, which could hold an option, its value or
//    the image), every reading is kept, and a limit that Docker could read as an option is
//    refused, also one built from a literal (`--memory=${size}`). `docker update`, which changes
//    the limits of a container that runs, is refused unless it is reviewed, and so are, as the
//    guard refuses them, swarm services (`service`, `stack`), which run containers of their own,
//    and `buildx create` or `builder create` (builder is buildx's alias), which can start a
//    builder container, with a buildx or builder call whose next word is an option or cannot be
//    read, which could be create.
// 3. A docker call whose subcommand is not a literal cannot be checked: it is refused unless it is
//    listed in `reviewed` (test/docker-limits.test.mjs), with the reason it never creates a
//    container. A listed call that is no longer there is refused too, so the list cannot rot.
//    A call giving an option before the subcommand (--context, -H, --log-level…) is refused
//    outright: the check does not tell Docker's options from its subcommand. Choose the daemon
//    in the environment instead (DOCKER_CONTEXT, DOCKER_HOST).
// 4. test/docker-limits.test.mjs reads every file below test/ (checkFile), whatever its name,
//    mode or first line, since a test can run any of them: image-layers.test.mjs runs
//    `/bin/sh stand-in-tar`, which has no `#!` line, no .sh name and no executable bit, and the
//    installer tests copy their stand-ins into a PATH directory and make them executable there.
//    A file named .mjs, .cjs or .js is read as JavaScript, as above. Every other text file is
//    read line by line, whatever its first line, since a test may hand it to a shell even when
//    it starts with `#!/usr/bin/env node` (sh takes that line for a comment): a line that
//    mentions docker, in any case and in any form (`docker run`, `$DOCKER`, `/usr/bin/docker`,
//    a comment), is refused unless that line is reviewed and listed (a Dockerfile's own lines,
//    say), since this check cannot read a shell or any other language. The line is read as sh
//    joins and unquotes its words: a line ending in a backslash goes on in the next one, the
//    escapes of $'…' are read as bash reads them (macOS /bin/sh is bash), and quotes and
//    backslashes are dropped, so `d""ocker`, `d\ocker`, `d$''ocker`, $'\x64ocker' or a word split
//    over two lines (`doc\` then `ker run`) mention docker too. Such a file whose first line
//    runs node is also read as JavaScript. A binary file cannot be read and is refused, and so is
//    a symbolic link or anything else that is not a regular file. Passed over are only the
//    release fixture archives that test/fixtures/SHA256SUMS pins, while they hold exactly the
//    pinned bytes (earlier releases' runtime files and the nodemailer package), and the
//    .DS_Store files macOS Finder writes into a folder it shows, by their name and their header
//    (git ignores them, and a release leaves them out); any other file of that name is read as
//    any other. Each of those is still refused where a shell handed it could run docker
//    (shellCommands): dash, Debian's /bin/sh, drops a file's NUL bytes and runs the rest.
// 5. In JavaScript, what reaches docker past the rules above and past the guard, which stands in
//    for docker by name on the PATH test/setup.mjs gives: (a) docker named by a path (a word ending
//    in /docker or \docker, also docker-compose and .exe, in any case) in any string or template
//    literal of the module, wherever it is (the argument of a spawn, a line for sh -c, code for
//    node -e or eval, fork's execPath, a constant used later), read as written, as sh reads its
//    words (rule 4) and with the escapes of a JavaScript string read, as code a string holds reads
//    them, and path.join(…, 'docker') or path.resolve(…, 'docker'); and (b) a literal among the
//    arguments of a call that starts a program or runs code (child_process's functions, fork
//    included, eval, Function, a Worker, node:vm's, import() of a data: URL) that mentions docker
//    in any of those readings, since that program can run docker on a PATH of its own (`sh -c
//    'docker …'` with a PATH the test sets, `env PATH=… docker …`, node -e). Each is refused unless
//    the literal (or the path.join call), as the source writes it, is reviewed and listed; rule 5
//    passes over the program of a spawn (rule 1 reads it) and the argument array of a docker call
//    (rule 2 reads it). A literal path cannot be listed, since the list, a literal too, would name
//    it as well: write it as path.join(dir, 'docker'). As for child_process's functions, eval,
//    Function, Worker and node:vm's functions used as a value other than by calling them by name
//    (an alias, (0, eval), imported as another name) are refused, since what they are handed could
//    not be followed; reading a property of one (Function.prototype) is not.
//
// What this check cannot read, the run-time guard (docker-guard.mjs, which test/setup.mjs installs)
// still refuses before Docker sees it, where docker is found by name on the PATH setup.mjs gives: a
// Compose project whose services lack limits (this check does not read Compose files); a limit
// given again from a variable (`docker('run', ...limits, flag, 'img')` with `flag = '--memory=0'`,
// which this check takes for the image); docker run by a command line, code or arguments that no
// literal of a test module gives (docker.test.mjs reads the documented `docker compose` recipes
// from the docs and hands them to sh); in a file that is not JavaScript, docker named by a word
// built at run time (a variable or a command substitution: `d=dock; "${d}er" run`, `d$(:)ocker`);
// and a file named as JavaScript that a test hands to a shell instead of to node. Neither sees,
// from such a line, code or file, docker run by a path (`"$dir"/docker`, `$(command -v docker)`) or
// by name on a PATH the test sets without the guard's directory, nor a Compose project a test
// starts by name on such a PATH, nor docker under another name (a link a test makes to it at run
// time), nor code run by a function this check cannot see as eval or Function (one reached through
// another function's constructor), nor a container made through Docker's API other than by its
// command.

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const spawners = new Set(['spawnSync', 'spawn', 'execFileSync', 'execFile']);
const shellSpawners = new Set(['execSync', 'exec']);
// child_process's fork, which runs node (or the program its execPath option names).
const forkers = new Set(['fork']);
// What runs code a string gives (rule 5): eval, Function, a Worker given code, node:vm.
const codeRunners = new Set([
  'eval',
  'Function',
  'Worker',
  'runInThisContext',
  'runInNewContext',
  'runInContext',
  'compileFunction',
  'Script',
  'SourceTextModule',
]);
// docker (or docker-compose, which the guard also stands in for) named by a path: a word that
// ends in /docker or \docker, in any case (macOS finds it so), not a directory of that name
// (/docker/0123) nor another file (/var/run/docker.sock).
const dockerPath = /[\\/]docker(?:-compose)?(?:\.exe)?(?![\w.\\/-])/i;
const dockerName = /^docker(?:-compose)?(?:\.exe)?$/i;
const keywordsBeforeRegex = new Set([
  'return',
  'typeof',
  'case',
  'do',
  'else',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'throw',
  'instanceof',
  'yield',
  'await',
]);
// The docker executable, by name or path ('docker', '/usr/local/bin/docker', 'Docker.exe').
const dockerExecutable = /(?:^|[\\/])docker(?:\.exe)?$/i;
const childProcess = /^(?:node:)?child_process$/;
// The options of `docker run` and `docker create` that take no value (Docker 29, as `--help`
// lists them, and --disable-content-trust of older releases), long and as one letter. Every
// other option is taken to take one: wrongly so for an option missing here, which only makes
// the check read one more word as options, and so refuse more.
const flagsWithoutValue = new Set([
  '--detach',
  '--disable-content-trust',
  '--help',
  '--init',
  '--interactive',
  '--no-healthcheck',
  '--oom-kill-disable',
  '--privileged',
  '--publish-all',
  '--quiet',
  '--read-only',
  '--rm',
  '--sig-proxy',
  '--tty',
  '--use-api-socket',
]);
const lettersWithoutValue = new Set(['d', 'i', 'P', 'q', 't']);
// Words before which `(` is not a call.
const notCallees = new Set([
  ...keywordsBeforeRegex,
  'if',
  'for',
  'while',
  'switch',
  'catch',
  'function',
  'with',
]);

// What JavaScript reads as a line terminator, and as the first and later characters of a name.
const lineTerminators = new Set(['\n', '\r', '\u2028', '\u2029']);
const identifierStart = /[\p{ID_Start}$_]/u;
const identifierPart = /[\p{ID_Continue}$\u200c\u200d]/u;
// The statements whose `(…)` head a regular expression can follow: if (x) /re/.test(y).
const statementHeads = new Set(['if', 'while', 'for', 'with']);

/**
 * What the escape sequence at source[j] (a backslash) of a string, template or name stands for,
 * as node reads it: [text, the index after it]. A backslash before a line end stands for nothing.
 * A sequence node refuses throws a SyntaxError, so nothing unread passes: \x or \u without its
 * hex digits, a code point past U+10FFFF and, in a template (`template`), an octal escape or \8
 * and \9, which a string reads in CommonJS ('\144ocker' is 'docker').
 */
function readEscape(source, j, template) {
  const c = source[j + 1];
  if (c === undefined) throw new SyntaxError(`unterminated escape at ${j}`);
  if (c === '\r') return ['', source[j + 2] === '\n' ? j + 3 : j + 2];
  if (lineTerminators.has(c)) return ['', j + 2];
  if (c === 'x') {
    const digits = source.slice(j + 2, j + 4);
    if (!/^[0-9a-f]{2}$/i.test(digits)) throw new SyntaxError(`invalid \\x escape at ${j}`);
    return [String.fromCharCode(parseInt(digits, 16)), j + 4];
  }
  if (c === 'u') {
    if (source[j + 2] === '{') {
      const end = source.indexOf('}', j + 3);
      const digits = end < 0 ? '' : source.slice(j + 3, end);
      if (!/^[0-9a-f]+$/i.test(digits) || parseInt(digits, 16) > 0x10ffff)
        throw new SyntaxError(`invalid \\u{…} escape at ${j}`);
      return [String.fromCodePoint(parseInt(digits, 16)), end + 1];
    }
    const digits = source.slice(j + 2, j + 6);
    if (!/^[0-9a-f]{4}$/i.test(digits)) throw new SyntaxError(`invalid \\u escape at ${j}`);
    return [String.fromCharCode(parseInt(digits, 16)), j + 6];
  }
  if (/[0-9]/.test(c)) {
    if (c === '0' && !/[0-9]/.test(source[j + 2] ?? '')) return ['\0', j + 2];
    if (template) throw new SyntaxError(`octal escape in a template at ${j}`);
    if (c === '8' || c === '9') return [c, j + 2];
    const digits = /^(?:[0-3][0-7]{0,2}|[4-7][0-7]?)/.exec(source.slice(j + 1, j + 4))[0];
    return [String.fromCharCode(parseInt(digits, 8)), j + 1 + digits.length];
  }
  const single = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' }[c];
  if (single !== undefined) return [single, j + 2];
  const character = String.fromCodePoint(source.codePointAt(j + 1));
  return [character, j + 1 + character.length];
}

// The name at source[i], its \u escapes read (spawnSync is spawnSync, and so is a name of
// letters JavaScript allows beyond ASCII), as [name, the index after it], or null.
function readIdentifier(source, i) {
  let name = '',
    j = i;
  for (;;) {
    const allowed = name ? identifierPart : identifierStart;
    let character, next;
    if (source[j] === '\\') {
      if (source[j + 1] !== 'u') throw new SyntaxError(`invalid escape in a name at ${j}`);
      [character, next] = readEscape(source, j, false);
      if (!allowed.test(character)) throw new SyntaxError(`invalid escape in a name at ${j}`);
    } else {
      const point = source.codePointAt(j);
      if (point === undefined) break;
      character = String.fromCodePoint(point);
      next = j + character.length;
      if (!allowed.test(character)) break;
    }
    name += character;
    j = next;
  }
  return name ? [name, j] : null;
}

/**
 * Tokens of `source`: {type: 'str'|'tpl'|'regex'|'id'|'num'|'punc', value, start, level}, and
 * `end` (the index after it) for a string or template. Strings, templates and names are read as
 * node reads them, escapes included. A template literal is one 'tpl' token (value: its text when
 * it has no substitution, else null; text: all its text; tail: its text after the last
 * substitution); the tokens of its substitutions follow it with a higher `level`. Where this cannot tell what node reads, it throws a SyntaxError rather than guess, so
 * that the check fails: a `/` right after `}`, `await`, `yield` or `of` (a regular expression or a
 * division, which read the rest of the line differently), and an HTML-like comment (`<!--`, or
 * `-->` starting a line), which is a comment in CommonJS and code in a module. A `/` after `)`
 * starts a regular expression only when the `(…)` was the head of if, while, for or with.
 */
export function tokenize(source) {
  const tokens = [];
  const substitutions = []; // the brace depth at each open ${
  const parens = []; // for each open (, whether it opens the head of if, while, for or with
  let depth = 0;
  let i = 0;
  let lastEnd = 0; // where the code of the last token ended
  const push = (type, value, start, extra = {}) =>
    tokens.push({ type, value, start, level: substitutions.length, ...extra });
  // Whether the token `back` places from the end is one of `names`, not a property (x.if).
  const named = (back, names) => {
    const token = tokens.at(-back);
    return token?.type === 'id' && names.has(token.value) && tokens.at(-back - 1)?.value !== '.';
  };
  // true, false, or null where node may read either (see above).
  const regexAllowed = () => {
    const previous = tokens.at(-1);
    if (!previous) return true;
    if (previous.type === 'punc') {
      if (previous.value === ')') return previous.head === true;
      if (previous.value === ']') return false;
      if (previous.value === '}') return null;
      // ++ and -- (side by side) end an operand: i++ / 2.
      const before = tokens.at(-2);
      if (
        (previous.value === '+' || previous.value === '-') &&
        before?.type === 'punc' &&
        before.value === previous.value &&
        before.start === previous.start - 1
      )
        return false;
      return true;
    }
    if (previous.type === 'id') {
      if (['await', 'yield', 'of'].includes(previous.value)) return null;
      return keywordsBeforeRegex.has(previous.value);
    }
    return false;
  };
  // Scans template text from `from` up to its closing backtick or next ${. Returns the index after.
  const templateText = (from, token) => {
    let j = from,
      tail = '';
    for (;;) {
      if (j >= source.length) throw new SyntaxError(`unterminated template at ${token.start}`);
      const c = source[j];
      if (c === '\\') {
        const [text, next] = readEscape(source, j, true);
        token.text += text;
        tail += text;
        j = next;
      } else if (c === '`') {
        if (!token.substituted) token.value = token.text;
        token.tail = tail;
        token.end = j + 1;
        return j + 1;
      } else if (c === '$' && source[j + 1] === '{') {
        token.substituted = true;
        token.value = null;
        substitutions.push(depth);
        token.open.push(substitutions.length);
        return j + 2;
      } else {
        token.text += c;
        tail += c;
        j++;
      }
    }
  };
  const openTemplates = [];
  while (i < source.length) {
    const c = source[i];
    const count = tokens.length;
    if (/\s/.test(c)) {
      i++;
    } else if (c === '/' && source[i + 1] === '/') {
      while (i < source.length && !lineTerminators.has(source[i])) i++;
    } else if (c === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end < 0) throw new SyntaxError(`unterminated comment at ${i}`);
      i = end + 2;
    } else if (
      source.startsWith('<!--', i) ||
      (source.startsWith('-->', i) &&
        (!tokens.length || [...source.slice(lastEnd, i)].some(ch => lineTerminators.has(ch))))
    ) {
      throw new SyntaxError(
        `an HTML-like comment at ${i}, which node reads as a comment in CommonJS and as code in a module`
      );
    } else if (c === "'" || c === '"') {
      let j = i + 1,
        value = '';
      while (source[j] !== c) {
        if (j >= source.length || source[j] === '\n' || source[j] === '\r')
          throw new SyntaxError(`unterminated string at ${i}`);
        if (source[j] === '\\') {
          const [text, next] = readEscape(source, j, false);
          value += text;
          j = next;
        } else value += source[j++];
      }
      push('str', value, i, { end: j + 1 });
      i = j + 1;
    } else if (c === '`') {
      push('tpl', null, i);
      const token = tokens.at(-1);
      Object.assign(token, { text: '', substituted: false, open: [] });
      openTemplates.push(token);
      i = templateText(i + 1, token);
      if (!token.substituted) openTemplates.pop();
    } else if (c === '}' && substitutions.length && depth === substitutions.at(-1)) {
      // The end of a ${…}: back to the text of the template it belongs to.
      substitutions.pop();
      const token = openTemplates.at(-1);
      const before = token.open.length;
      i = templateText(i + 1, token);
      if (token.open.length === before) openTemplates.pop();
      lastEnd = i;
    } else if (c === '/') {
      const allowed = regexAllowed();
      if (allowed === null)
        throw new SyntaxError(
          `a / at ${i} after ${tokens.at(-1).value} can start a regular expression or divide, which read the rest of the line differently: this check cannot tell which node reads`
        );
      if (allowed) {
        let j = i + 1,
          inClass = false;
        for (;;) {
          if (j >= source.length || lineTerminators.has(source[j]))
            throw new SyntaxError(`unterminated regular expression at ${i}`);
          if (source[j] === '\\') j += 2;
          else if (source[j] === '[') ((inClass = true), j++);
          else if (source[j] === ']') ((inClass = false), j++);
          else if (source[j] === '/' && !inClass) break;
          else j++;
        }
        j++;
        while (/[a-z]/i.test(source[j] ?? '')) j++;
        push('regex', source.slice(i, j), i);
        i = j;
      } else {
        push('punc', '/', i);
        i++;
      }
    } else if (
      identifierStart.test(String.fromCodePoint(source.codePointAt(i))) ||
      (c === '\\' && source[i + 1] === 'u')
    ) {
      const [name, next] = readIdentifier(source, i);
      push('id', name, i);
      i = next;
    } else if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(source[i + 1] ?? ''))) {
      const match = /^(?:0[xob][\da-f_]+|[\d_]*\.?[\d_]+(?:e[+-]?\d+)?)n?/i.exec(
        source.slice(i, i + 100)
      );
      push('num', match[0], i);
      i += match[0].length;
    } else if (source.startsWith('...', i)) {
      push('punc', '...', i);
      i += 3;
    } else if (source.startsWith('=>', i)) {
      push('punc', '=>', i);
      i += 2;
    } else if (c === '\\' || c.charCodeAt(0) > 0x7e || c.charCodeAt(0) < 0x20) {
      throw new SyntaxError(`a character node does not read as code at ${i}`);
    } else {
      if (c === '{') depth++;
      else if (c === '}') depth--;
      if (c === '(') {
        parens.push(
          named(1, statementHeads) || (named(1, new Set(['await'])) && named(2, new Set(['for'])))
        );
        push('punc', c, i);
      } else if (c === ')') push('punc', c, i, { head: parens.pop() === true });
      else push('punc', c, i);
      i++;
    }
    if (tokens.length > count) lastEnd = i;
  }
  if (substitutions.length || openTemplates.length)
    throw new SyntaxError('unterminated template literal');
  return tokens;
}

const closing = { '(': ')', '[': ']', '{': '}' };

// The index of the token closing the bracket at `open`.
function matching(tokens, open) {
  const stack = [];
  for (let k = open; k < tokens.length; k++) {
    const token = tokens[k];
    if (token.type !== 'punc') continue;
    if (closing[token.value]) stack.push(closing[token.value]);
    else if (Object.values(closing).includes(token.value)) {
      if (stack.pop() !== token.value) throw new SyntaxError(`unbalanced at ${token.start}`);
      if (!stack.length) return k;
    }
  }
  throw new SyntaxError(`unclosed bracket at ${tokens[open].start}`);
}

// The elements between the brackets at `open` and its match, split at their own commas: arrays
// of token index ranges [from, to).
function elements(tokens, open) {
  const close = matching(tokens, open);
  const level = tokens[open].level;
  const parts = [];
  let from = open + 1,
    nested = 0;
  for (let k = open + 1; k < close; k++) {
    const token = tokens[k];
    if (token.type !== 'punc' || token.level !== level) continue;
    if (closing[token.value]) nested++;
    else if (Object.values(closing).includes(token.value)) nested--;
    else if (token.value === ',' && nested === 0) {
      parts.push([from, k]);
      from = k + 1;
    }
  }
  if (from < close) parts.push([from, close]);
  return { parts, close };
}

// Whether the name at token k is an object's key or property ({ limits: 1 }, x.limits), not a
// use of the variable of that name.
const isKey = (tokens, k) =>
  tokens[k - 1]?.value === '.' ||
  (tokens[k + 1]?.value === ':' && ['{', ','].includes(tokens[k - 1]?.value));

/**
 * Array constants of a file that a spread can be trusted to give: name -> values. Only a `const`
 * whose initializer is an array literal of string literals and nothing more, not exported, and
 * whose name occurs nowhere else in the file but in spreads (`...limits`): any other use could
 * change it (limits.push(…), limits.length = 0), bind the name again (a parameter, another
 * declaration) or hand it on.
 */
function arrayConstants(tokens) {
  const constants = new Map();
  const declared = new Map();
  for (let k = 0; k + 3 < tokens.length; k++) {
    const [keyword, name, equals, open] = tokens.slice(k, k + 4);
    if (
      keyword.type !== 'id' ||
      keyword.value !== 'const' ||
      name.type !== 'id' ||
      equals.value !== '=' ||
      open.value !== '['
    )
      continue;
    const { parts, close } = elements(tokens, k + 3);
    const values = parts.map(([from, to]) =>
      to - from === 1 && tokens[from].type === 'str' ? tokens[from].value : null
    );
    const whole = [';', ','].includes(tokens[close + 1]?.value ?? ';');
    const exported = tokens[k - 1]?.value === 'export';
    // The same name declared twice in a file is ambiguous: treat it as unknown.
    if (declared.has(name.value) || !whole || exported || values.includes(null))
      constants.set(name.value, null);
    else constants.set(name.value, values);
    declared.set(name.value, declared.has(name.value) ? -1 : k + 1);
  }
  for (const [name, at] of declared) {
    if (!constants.get(name)) continue;
    for (let k = 0; k < tokens.length; k++) {
      if (k === at || tokens[k].type !== 'id' || tokens[k].value !== name || isKey(tokens, k))
        continue;
      const spread = tokens[k - 1]?.value === '...' && tokens[k - 1].type === 'punc';
      // A rest element binds the name: (...limits) => …, [...limits] = …
      const after = tokens[k + 2]?.value;
      const binds =
        [')', ']', '}'].includes(tokens[k + 1]?.value) && ['=', '=>', '{'].includes(after);
      if (!spread || binds) {
        constants.set(name, null);
        break;
      }
    }
  }
  return constants;
}

// What one argument of a docker call is: [{literal}] for a string (or a spread of an array of
// strings), or [{unknown: text, spread, head}] for anything else (`spread`: any number of words;
// `head`: the text a word starts with when it starts with a string or template literal, as
// `--memory=${size}` or '-m' + size do).
function flatten(tokens, [from, to], constants, source) {
  const text = source.slice(tokens[from].start, tokens[to].start).trim();
  const first = tokens[from];
  const head = first.type === 'str' ? first.value : first.type === 'tpl' ? first.text : undefined;
  if (to - from === 1 && tokens[from].type === 'str') return [{ literal: tokens[from].value }];
  if (to - from === 1 && tokens[from].type === 'tpl' && tokens[from].value !== null)
    return [{ literal: tokens[from].value }];
  if (tokens[from].value === '...' && tokens[from].type === 'punc') {
    if (tokens[from + 1]?.value === '[' && matching(tokens, from + 1) === to - 1)
      return elements(tokens, from + 1).parts.flatMap(part =>
        flatten(tokens, part, constants, source)
      );
    if (to - from === 2 && tokens[from + 1].type === 'id') {
      const values = constants.get(tokens[from + 1].value);
      if (values) return values.map(literal => ({ literal, from: tokens[from + 1].value }));
    }
    return [{ unknown: text, spread: true }];
  }
  return [{ unknown: text, spread: false, head }];
}

// The text of the token range [from, to) when it is one string literal or a template literal with
// no substitution, else null.
function literalText(tokens, [from, to]) {
  if (to - from !== 1) return null;
  const { type, value } = tokens[from];
  return type === 'str' || (type === 'tpl' && value !== null) ? value : null;
}

// Whether the command of a spawn, the token range [from, to) of its first argument, names its
// program by a literal (and so cannot be docker unless namesDocker says so): a string or template
// literal with no substitution, a template whose text after its last substitution is /name
// (`${bin}/tar`), process.execPath, or path.join(…) or path.resolve(…) whose last argument is a
// string. Anything else (a variable, a parameter, a call) could hold docker.
function fixedProgram(tokens, [from, to]) {
  if (literalText(tokens, [from, to]) !== null) return true;
  const first = tokens[from];
  if (
    first.type === 'tpl' &&
    tokens.slice(from + 1, to).every(token => token.level > first.level) &&
    /^[\\/][^\\/]+$/.test(first.tail)
  )
    return true;
  const values = tokens.slice(from, to).map(token => token.value);
  if (values.join(' ') === 'process . execPath') return true;
  if (
    values[0] === 'path' &&
    values[1] === '.' &&
    ['join', 'resolve'].includes(values[2]) &&
    values[3] === '(' &&
    matching(tokens, from + 3) === to - 1
  ) {
    const last = elements(tokens, from + 3).parts.at(-1);
    return Boolean(last) && last[1] - last[0] === 1 && tokens[last[0]].type === 'str';
  }
  return false;
}

// Whether the command of a spawn, the token range [from, to) of its first argument, names the
// docker executable in one of its string or template literals (a template by its text, without
// its substitutions: `${bin}/docker`).
function namesDocker(tokens, [from, to]) {
  for (let k = from; k < to; k++) {
    const { type, value, text } = tokens[k];
    if (type === 'str' && dockerExecutable.test(value)) return true;
    if (type === 'tpl' && dockerExecutable.test(text)) return true;
  }
  return false;
}

// The bytes Docker reads from a --memory value, as its CLI counts them (go-units RAMInBytes): a
// decimal number, then b, k, m or g (powers of 1024, in any case), with the fraction of a byte
// dropped, so `0.5` and `.9b` are 0, which is no limit. NaN for any other form (Docker reads
// more, such as 1kb or 1t; this check refuses them).
function memoryBytes(value) {
  const match = /^(\d+(?:\.\d+)?|\.\d+)([bkmg]?)$/i.exec(value);
  if (!match) return NaN;
  const unit = { '': 1, b: 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[match[2].toLowerCase()];
  return Math.trunc(Number(match[1]) * unit);
}
// Docker's smallest memory limit: its daemon refuses a smaller one but 0, which is no limit. The
// count must fit an int64: past it, Go's conversion is undefined (Docker 29 on arm64 sends the
// largest int64).
const memoryMinimum = 6 * 1024 ** 2;

const finite = {
  memory: value => memoryBytes(value) >= memoryMinimum && memoryBytes(value) < 2 ** 63,
  cpus: value => /^\d*\.?\d+$/.test(value) && Number(value) > 0,
  pids: value => /^[1-9]\d*$/.test(value),
};
const option = {
  memory: /^(?:--memory|-m)$/,
  cpus: /^--cpus$/,
  pids: /^--pids-limit$/,
};

// Which limits the option words at the start of `words` give (each finite), and how many words
// they take (`count`): options and their values only, stopping at the first word that is neither.
function leadingLimits(words) {
  const given = {};
  let k = 0;
  for (; k < words.length; k++) {
    const word = words[k].literal;
    if (word === undefined) break;
    const joined = /^(--memory|--cpus|--pids-limit)=(.*)$/.exec(word);
    const kind = joined
      ? { '--memory': 'memory', '--cpus': 'cpus', '--pids-limit': 'pids' }[joined[1]]
      : Object.keys(option).find(name => option[name].test(word));
    if (!kind) break;
    const value = joined ? joined[2] : words[k + 1]?.literal;
    if (!joined) k++;
    if (value !== undefined && finite[kind](value)) given[kind] = value;
    else given[kind] = null;
  }
  return { given, count: Math.min(k, words.length) };
}

// Whether Docker, reading `word` as an option of run or create, reads a limit: --memory, --cpus
// or --pids-limit (alone or with =value), or -m, also with its value (-m0, -m=0) or after
// letters that take no value (-itm 0).
function isLimitOption(word) {
  if (/^--(?:memory|cpus|pids-limit)(?:=|$)/.test(word)) return true;
  if (!/^-[^-]/.test(word)) return false;
  for (const letter of word.slice(1)) if (!lettersWithoutValue.has(letter)) return letter === 'm';
  return false;
}

// What Docker expects after reading `word` where it expects an option or the image: another
// 'option', the option's 'value', the image after `--` ('end'), or nothing more ('image': the
// rest is the container's command).
function afterOption(word) {
  if (word === '--') return 'end';
  if (word.startsWith('--'))
    return word.includes('=') || flagsWithoutValue.has(word) ? 'option' : 'value';
  if (word.length > 1 && word.startsWith('-')) {
    const letters = word.slice(1);
    for (let i = 0; i < letters.length; i++)
      if (!lettersWithoutValue.has(letters[i])) return i + 1 < letters.length ? 'option' : 'value';
    return 'option';
  }
  return 'image';
}

// Reads the words of a docker run or create from index `from` (after the limits given first) as
// Docker does, up to the image. A word this check cannot read could be an option, its value,
// `--` or the image, and a spread any number of them: every reading is kept. Returns the limit
// options Docker may read there (also where only an option's value is due, in case the option
// before takes none; a word built from one, `--memory=${size}`, counts) and the spreads it cannot
// read where Docker may read options.
function laterOptions(words, from) {
  let states = new Set(['option']);
  const limits = [],
    unread = [];
  for (const word of words.slice(from)) {
    if (states.size === 1 && states.has('image')) break;
    const optionsRead = states.has('option') || states.has('value');
    const next = new Set();
    if (word.literal === undefined) {
      if (word.spread && optionsRead) unread.push(word.unknown);
      if (optionsRead && word.head !== undefined && isLimitOption(word.head))
        limits.push(word.unknown);
      for (const state of states) {
        if (state === 'image') next.add('image');
        else if (state === 'end') {
          next.add('image');
          if (word.spread) next.add('end');
        } else if (state === 'value' && !word.spread) next.add('option');
        else for (const any of ['option', 'value', 'end', 'image']) next.add(any);
      }
    } else {
      if (optionsRead && isLimitOption(word.literal)) limits.push(word.literal);
      for (const state of states) {
        if (state === 'option') next.add(afterOption(word.literal));
        else if (state === 'value') next.add('option');
        else next.add('image');
      }
    }
    states = next;
  }
  return { limits, unread };
}

/**
 * What is wrong with the limits of a `docker run` or `docker create` given `words`, the words
 * Docker is given after its subcommand, each known (the run-time guard, docker-guard.mjs, has
 * them): rule 2, as reasons, empty when the limits are right.
 */
export function runLimitProblems(words) {
  const read = words.map(literal => ({ literal: String(literal) }));
  const { given, count } = leadingLimits(read);
  const missing = ['memory', 'cpus', 'pids'].filter(kind => !given[kind]);
  if (missing.length)
    return [
      `without finite ${missing
        .map(kind => ({ memory: '--memory', cpus: '--cpus', pids: '--pids-limit' })[kind])
        .join(', ')} right after the subcommand`,
    ];
  const later = laterOptions(read, count);
  return later.limits.length
    ? [
        `gives ${later.limits.join(' ')} again where Docker reads it as an option: Docker keeps the last value given, so it would replace the limit given first`,
      ]
    : [];
}

/**
 * How Docker reads a `docker run` or `docker create` given `words`, its words after the
 * subcommand, each known, for the check of the documented commands (B39,
 * test/docs-install-changelog.test.mjs): `limits`, those given finite right after the subcommand
 * (memory in bytes, cpus and pids as numbers; one not given there finite is absent); `options`,
 * the words Docker reads as its options and their values, up to the image; and `image`, undefined
 * where the words end before one.
 */
export function readRun(words) {
  const read = words.map(String);
  const { given } = leadingLimits(read.map(literal => ({ literal })));
  const limits = {};
  if (given.memory) limits.memory = memoryBytes(given.memory);
  if (given.cpus) limits.cpus = Number(given.cpus);
  if (given.pids) limits.pids = Number(given.pids);
  let next = 'option';
  for (const [k, word] of read.entries()) {
    if (next === 'value') next = 'option';
    else {
      if (next === 'option') next = afterOption(word);
      else next = 'image';
      if (next === 'image') return { limits, options: read.slice(0, k), image: word };
    }
  }
  return { limits, options: read, image: undefined };
}

// The names a module gives child_process's functions, from `import … from 'child_process'`,
// `const … = require('child_process')` or `= await import('child_process')` (with or without
// node:): `functions`, local name -> 'array' (spawnSync, spawn, execFileSync, execFile) or
// 'shell' (execSync, exec); `namespaces`, names for the whole module (import * as cp, import cp,
// const cp = require(…)); `own`, the token indexes of those declarations; and `unfollowed`, the
// token indexes of anything else that takes child_process (a re-export, a require handed on).
function childProcessBindings(tokens) {
  const functions = new Map(),
    namespaces = new Set(),
    own = new Set(),
    unfollowed = [];
  const kindOf = name =>
    spawners.has(name)
      ? 'array'
      : shellSpawners.has(name)
        ? 'shell'
        : forkers.has(name)
          ? 'fork'
          : null;
  // The names in `{ a, b as c }` (separator 'as') or `{ a, b: c }` (':') at token `open`.
  const specifiers = (open, separator) => {
    for (const [from, to] of elements(tokens, open).parts) {
      const imported = tokens[from].value;
      const local =
        to - from === 1 && tokens[from].type === 'id'
          ? imported
          : to - from === 3 &&
              tokens[from + 1].value === separator &&
              tokens[from + 2].type === 'id'
            ? tokens[from + 2].value
            : null;
      if (local === null) unfollowed.push(from);
      else if (imported === 'default') namespaces.add(local);
      else if (kindOf(imported)) functions.set(local, kindOf(imported));
    }
    const close = matching(tokens, open);
    for (let j = open; j <= close; j++) own.add(j);
    return close;
  };
  // Whether tokens from k are require('child_process'), import('child_process') or the same
  // after await: returns the index after its `)`, or -1.
  const loads = k => {
    if (tokens[k]?.value === 'await') k++;
    const [callee, open, name, close] = tokens.slice(k, k + 4);
    return ['require', 'import'].includes(callee?.value) &&
      open?.value === '(' &&
      name?.type === 'str' &&
      childProcess.test(name.value) &&
      close?.value === ')'
      ? k + 4
      : -1;
  };
  const taken = new Set();
  for (let k = 0; k < tokens.length; k++) {
    const token = tokens[k];
    if (token.type !== 'id' || tokens[k - 1]?.value === '.') continue;
    if (
      (token.value === 'import' || token.value === 'export') &&
      !['(', '.'].includes(tokens[k + 1]?.value)
    ) {
      // A static import or export: its `from` comes before the statement's end.
      let j = k + 1;
      while (j < tokens.length && tokens[j].value !== ';' && tokens[j].value !== 'from') j++;
      if (tokens[j]?.value !== 'from' || !childProcess.test(tokens[j + 1]?.value ?? '')) continue;
      if (token.value === 'export') {
        unfollowed.push(k);
        continue;
      }
      for (let i = k; i <= j + 1; i++) {
        if (tokens[i].value === '{') i = specifiers(i, 'as');
        else if (tokens[i].value === '*') {
          namespaces.add(tokens[i + 2]?.value);
          own.add(i).add(i + 1);
          i += 2;
        } else if (tokens[i].type === 'id' && i > k && i < j && tokens[i - 1].value !== 'as')
          namespaces.add(tokens[i].value);
        own.add(i);
      }
      k = j + 1;
    } else if (['const', 'let', 'var'].includes(token.value)) {
      const pattern = tokens[k + 1];
      if (pattern?.value === '{') {
        const close = matching(tokens, k + 1);
        if (tokens[close + 1]?.value !== '=' || loads(close + 2) < 0) continue;
        specifiers(k + 1, ':');
        taken.add(close + 2);
      } else if (pattern?.type === 'id' && tokens[k + 2]?.value === '=' && loads(k + 3) >= 0) {
        namespaces.add(pattern.value);
        own.add(k + 1);
        taken.add(k + 3);
      }
    }
  }
  // Every other require or import() of child_process: only a call of one of its functions right
  // away (require('child_process').spawnSync(…)), which is found by name, is followed.
  for (let k = 0; k < tokens.length; k++) {
    const end = loads(k);
    if (end < 0 || tokens[k].value === 'await' || taken.has(k) || taken.has(k - 1)) continue;
    const [dot, name, open] = tokens.slice(end, end + 3);
    if (dot?.value === '.' && kindOf(name?.value) && open?.value === '(') continue;
    unfollowed.push(k);
  }
  return { functions, namespaces, own, unfollowed };
}

// Whether the first argument of a call, the token range [from, to), names the docker executable
// in a string or template literal of its own, not one inside an array or object it builds
// (config.get('docker') does; assert.deepEqual(['linux', 'docker'], …) does not).
function namesDockerAtTop(tokens, [from, to]) {
  let depth = 0;
  for (let k = from; k < to; k++) {
    const { type, value, text } = tokens[k];
    if (type === 'punc' && (value === '[' || value === '{')) depth++;
    else if (type === 'punc' && (value === ']' || value === '}')) depth--;
    else if (depth === 0 && type === 'str' && dockerExecutable.test(value)) return true;
    else if (depth === 0 && type === 'tpl' && dockerExecutable.test(text)) return true;
  }
  return false;
}

/**
 * The docker calls of one file and what is wrong with them. Returns {calls, problems}: each call
 * is {line, text, subcommand, limits}; each problem {line, text, why}.
 */
export function checkSource(source, { file = '<source>', reviewed = [] } = {}) {
  // A first line `#!…` is not JavaScript: blank it, keeping every offset.
  if (source.startsWith('#!'))
    source = source.replace(/^#![^\n]*/, line => ' '.repeat(line.length));
  const tokens = tokenize(source);
  const constants = arrayConstants(tokens);
  const imports = childProcessBindings(tokens);
  const lineOf = index => source.slice(0, index).split('\n').length;
  const textOf = (from, to) =>
    source.slice(tokens[from].start, tokens[to].start + 1).replace(/\s+/g, ' ');
  const lineText = k => source.split('\n')[lineOf(tokens[k].start) - 1].trim();
  const calls = [],
    problems = [];
  const wrappers = new Map();
  const isCall = k =>
    tokens[k].type === 'id' && tokens[k + 1]?.value === '(' && tokens[k - 1]?.value !== '.';
  // What the function called at token k is: 'array' (spawnSync, spawn, execFileSync, execFile),
  // 'shell' (execSync, exec), 'fork' or null. A name the module imports from child_process is
  // what it imports (import { spawnSync as sh }); a property is what its name says (cp.spawnSync).
  const kindOf = k => {
    const name = tokens[k].value;
    if (tokens[k - 1]?.value !== '.' && imports.functions.has(name))
      return imports.functions.get(name);
    return spawners.has(name)
      ? 'array'
      : shellSpawners.has(name)
        ? 'shell'
        : forkers.has(name)
          ? 'fork'
          : null;
  };
  // `const NAME = (...P) =>` right before token k: returns {name, rest, at, exported} (`at`: the
  // index of NAME) or null.
  const arrowBefore = k => {
    const t = tokens.slice(Math.max(0, k - 8), k).map(token => token.value);
    const at = t.length - 8;
    if (
      t[at] === 'const' &&
      t[at + 2] === '=' &&
      t[at + 3] === '(' &&
      t[at + 4] === '...' &&
      t[at + 6] === ')' &&
      t[at + 7] === '=>'
    )
      return {
        name: t[at + 1],
        rest: t[at + 5],
        at: k - 7,
        exported: tokens[k - 9]?.value === 'export',
      };
    return null;
  };

  // The reviewed entries of this file: a call by its text, a spawned program by its text.
  const used = new Set();
  const lookUp = (key, text) => {
    const entry = reviewed.find(entry => entry.file === file && entry[key] === text);
    if (entry) used.add(entry);
    return entry;
  };
  const listed = text => lookUp('call', text);

  // The token indexes of what rules 1 to 3 read, which rule 5 passes over: `programs`, the
  // program of each spawn (rule 1); `pathsRead`, those of them that name docker, whose calls rule
  // 2 checks or rule 1 refuses, and the command lines rule 1 reads as sh reads them, with the
  // docker of a helper's call; `dockerWords`, the argument arrays of those docker calls, which
  // are docker's own words.
  const programs = new Set(),
    pathsRead = new Set(),
    dockerWords = new Set();
  const mark = (set, [from, to]) => {
    for (let j = from; j < to; j++) set.add(j);
  };

  // 1. Spawns: of docker (wrappers, direct calls, and what cannot be checked), and of a program
  // or command line this check cannot read, which could be docker.
  const direct = [];
  for (let k = 0; k < tokens.length; k++) {
    if (tokens[k].type !== 'id' || tokens[k + 1]?.value !== '(') continue;
    const kind = kindOf(k);
    if (!kind || kind === 'fork') continue;
    const { parts, close } = elements(tokens, k + 1);
    const command = parts[0];
    if (!command) continue;
    mark(programs, command);
    const refuse = why =>
      problems.push({ line: lineOf(tokens[k].start), text: textOf(k, close), why });
    const literal = literalText(tokens, command);
    const program = source.slice(tokens[command[0]].start, tokens[command[1]].start).trim();
    // Whether this is surely child_process's function: called by name, or as a property of the
    // module (cp.spawnSync, require('child_process').exec). A method of anything else that has
    // such a name (a regular expression's exec, a database's) is checked only where a literal
    // names docker.
    const owner = tokens[k - 2];
    const surely =
      tokens[k - 1]?.value !== '.' ||
      (owner?.type === 'id' &&
        imports.namespaces.has(owner.value) &&
        tokens[k - 3]?.value !== '.') ||
      (owner?.value === ')' &&
        tokens[k - 3]?.type === 'str' &&
        childProcess.test(tokens[k - 3].value) &&
        tokens[k - 4]?.value === '(' &&
        ['require', 'import'].includes(tokens[k - 5]?.value));
    // A command line, for exec or execSync, or a spawn with `shell: true` (a literal with a blank,
    // a quote or another character sh reads): read as sh reads a line of a file that is not
    // JavaScript (rule 4).
    if (literal !== null && (kind === 'shell' || /[\s"'`$\\;&|<>(){}*?~#]/.test(literal.trim()))) {
      mark(pathsRead, command);
      if (shellLines(literal).some(line => /docker/i.test(line.words)))
        refuse(
          'a shell command line that mentions docker cannot be checked; pass an argument array'
        );
      continue;
    }
    if (kind === 'shell') {
      if (surely && !lookUp('program', program))
        refuse(
          `a shell command line this check cannot read (${program}) could run docker; write it out, or review it and list it`
        );
      continue;
    }
    if (!namesDocker(tokens, command)) {
      if (surely && !fixedProgram(tokens, command) && !lookUp('program', program))
        refuse(
          `the program spawned here (${program}) is not named by a literal, so this check cannot tell whether it is docker; name it in a string, \`\${dir}/name\` or path.join(…, 'name'), or review it and list it`
        );
      continue;
    }
    mark(pathsRead, command);
    const args = parts[1];
    if (args && tokens[args[0]].value === '[' && matching(tokens, args[0]) === args[1] - 1) {
      mark(dockerWords, args);
      direct.push({ k, list: elements(tokens, args[0]).parts, close });
      continue;
    }
    const arrow = arrowBefore(k);
    if (args && args[1] - args[0] === 1 && arrow && tokens[args[0]].value === arrow.rest) {
      wrappers.set(arrow.name, arrow);
      continue;
    }
    problems.push({
      line: lineOf(tokens[k].start),
      text: textOf(k, close),
      why: 'docker is spawned with arguments this check cannot read (use an array literal or a (...args) wrapper)',
    });
  }

  // 2. Calls of the wrappers (and of wrappers that only pass their arguments on), to a fixpoint.
  const sites = direct.map(({ k, list, close }) => ({ k, list, close }));
  const seen = new Set();
  for (let grown = true; grown; ) {
    grown = false;
    for (let k = 0; k < tokens.length; k++) {
      if (seen.has(k) || !isCall(k) || !wrappers.has(tokens[k].value)) continue;
      const before = tokens[k - 1]?.value;
      if (before === 'const' || before === 'let' || before === 'var' || before === 'function')
        continue;
      const { parts, close } = elements(tokens, k + 1);
      const arrow = arrowBefore(k);
      if (
        arrow &&
        parts.length === 1 &&
        tokens[parts[0][0]].value === '...' &&
        tokens[parts[0][0] + 1]?.value === arrow.rest &&
        parts[0][1] - parts[0][0] === 2
      ) {
        if (!wrappers.has(arrow.name)) {
          wrappers.set(arrow.name, arrow);
          grown = true;
        }
        seen.add(k);
        continue;
      }
      seen.add(k);
      sites.push({ k, list: parts, close });
    }
  }

  // Any other call whose first argument names docker and whose second is an array literal: a
  // helper of another module, or a function this check does not know, given docker's arguments.
  for (let p = 1; p < tokens.length; p++) {
    if (tokens[p].type !== 'punc' || tokens[p].value !== '(') continue;
    const callee = tokens[p - 1];
    if (callee.type === 'id') {
      if (notCallees.has(callee.value) || kindOf(p - 1) || seen.has(p - 1)) continue;
      if (wrappers.has(callee.value) && tokens[p - 2]?.value !== '.') continue;
    } else if (callee.type !== 'punc' || ![')', ']'].includes(callee.value)) continue;
    const { parts, close } = elements(tokens, p);
    const [command, args] = parts;
    if (!command || !args || !namesDockerAtTop(tokens, command)) continue;
    if (tokens[args[0]].value !== '[' || matching(tokens, args[0]) !== args[1] - 1) continue;
    mark(pathsRead, command);
    mark(dockerWords, args);
    sites.push({ k: p - 1, list: elements(tokens, args[0]).parts, close });
  }

  // What could run docker unseen: child_process taken in a way this check does not follow, or a
  // function of it or a wrapper used other than by calling it.
  for (const k of imports.unfollowed)
    problems.push({
      line: lineOf(tokens[k].start),
      text: lineText(k),
      why: 'child_process is taken in a way this check does not follow (a re-export, a require handed on, a destructuring it cannot read); import its functions by name and call them',
    });
  for (let k = 0; k < tokens.length; k++) {
    const { type, value } = tokens[k];
    if (type !== 'id' || imports.own.has(k) || isKey(tokens, k)) continue;
    const member = tokens[k + 2];
    const namespaceUse =
      tokens[k + 1]?.value !== '.' ||
      member?.type !== 'id' ||
      ((spawners.has(member.value) || shellSpawners.has(member.value)) &&
        tokens[k + 3]?.value !== '(');
    if (
      (imports.functions.has(value) && tokens[k + 1]?.value !== '(') ||
      (imports.namespaces.has(value) && namespaceUse)
    )
      problems.push({
        line: lineOf(tokens[k].start),
        text: lineText(k),
        why: `${value} (child_process) is used other than by calling ${imports.functions.has(value) ? 'it' : 'its functions'} (an alias, promisify, passed on), so what it runs cannot be checked; call it by name`,
      });
  }
  for (const [name, { at, exported }] of wrappers) {
    if (exported)
      problems.push({
        line: lineOf(tokens[at].start),
        text: lineText(at),
        why: `the docker wrapper ${name} is exported, and this check does not follow its calls in other modules; keep it in the module that calls it`,
      });
    for (let k = 0; k < tokens.length; k++) {
      if (k === at || tokens[k].type !== 'id' || tokens[k].value !== name || isKey(tokens, k))
        continue;
      const before = tokens[k - 1]?.value;
      if (tokens[k + 1]?.value === '(' && !['const', 'let', 'var', 'function'].includes(before))
        continue;
      problems.push({
        line: lineOf(tokens[k].start),
        text: lineText(k),
        why: `the docker wrapper ${name} is used other than by calling it (an alias, .apply, .call, passed on, declared again), so this check cannot follow its calls; call it by name`,
      });
    }
  }

  // 3. Each call: its subcommand, and the limits when it makes a container.
  for (const { k, list, close } of sites.sort((a, b) => a.k - b.k)) {
    const text = textOf(k, close);
    const line = lineOf(tokens[k].start);
    const words = list.flatMap(part => flatten(tokens, part, constants, source));
    // docker with no arguments prints its usage.
    if (!words.length) {
      calls.push({ line, text, subcommand: null });
      continue;
    }
    let at = 0;
    if (words[0]?.literal === 'container') at = 1;
    const subcommand = words[at]?.literal;
    if (subcommand?.startsWith('-')) {
      problems.push({
        line,
        text,
        why: `docker is given an option (${subcommand}) before the subcommand, so this check cannot tell which subcommand runs; choose the daemon with DOCKER_CONTEXT or DOCKER_HOST in the environment instead`,
      });
      calls.push({ line, text, subcommand: null });
      continue;
    }
    if (subcommand === undefined) {
      if (!listed(text))
        problems.push({
          line,
          text,
          why: 'the docker subcommand is not a literal, so this check cannot tell whether it makes a container; write it out, or review it and list it',
        });
      calls.push({ line, text, subcommand: null });
      continue;
    }
    // docker update changes the limits of a container that runs: --memory=0 or --pids-limit=-1
    // would remove them.
    if (subcommand === 'update' && !listed(text))
      problems.push({
        line,
        text,
        why: "docker update can change or remove a running container's limits, which this check does not follow; review it and list it",
      });
    // Swarm services (service, stack) run containers of their own, and `buildx create` (`builder
    // create`: builder is buildx's alias) can start a builder container, none with these limits,
    // as the guard refuses them too. For buildx and builder, the word after them is the
    // subcommand unless it is an option or cannot be read.
    const next = words[at + 1];
    if (at === 0 && (subcommand === 'service' || subcommand === 'stack') && !listed(text))
      problems.push({
        line,
        text,
        why: `docker ${subcommand}: swarm services run containers of their own, which this check does not follow; review it and list it`,
      });
    if (
      at === 0 &&
      (subcommand === 'buildx' || subcommand === 'builder') &&
      next &&
      (next.literal === undefined || next.literal.startsWith('-') || next.literal === 'create') &&
      !listed(text)
    )
      problems.push({
        line,
        text,
        why:
          next.literal === 'create'
            ? `docker ${subcommand} create can start a builder container, which runs without these limits; review it and list it`
            : `docker ${subcommand} ${next.literal ?? next.unknown}: this check cannot tell the subcommand, which could be create (a builder container, without these limits); review it and list it`,
      });
    if (subcommand !== 'run' && subcommand !== 'create') {
      calls.push({ line, text, subcommand });
      continue;
    }
    const { given: limits, count } = leadingLimits(words.slice(at + 1));
    calls.push({ line, text, subcommand, limits });
    const missing = ['memory', 'cpus', 'pids'].filter(kind => !limits[kind]);
    if (missing.length)
      problems.push({
        line,
        text,
        why: `docker ${subcommand} without finite ${missing
          .map(kind => ({ memory: '--memory', cpus: '--cpus', pids: '--pids-limit' })[kind])
          .join(', ')} right after the subcommand`,
      });
    // What follows the limits, once they are all there: a limit again, or what cannot be read.
    const later = laterOptions(words.slice(at + 1), count);
    const reviewedSpread = later.unread.length > 0 && listed(text);
    if (missing.length) continue;
    if (later.limits.length)
      problems.push({
        line,
        text,
        why: `docker ${subcommand} gives ${later.limits.join(' ')} again where Docker may read it as an option: Docker keeps the last value given, so it would replace the limit given first; give each limit once, right after the subcommand`,
      });
    if (later.unread.length && !reviewedSpread)
      problems.push({
        line,
        text,
        why: `docker ${subcommand} spreads ${later.unread.join(', ')} where Docker reads its options, and this check cannot read it: a limit there would replace the one given first; spread an array constant, or review it and list it`,
      });
  }

  // 5. What reaches docker past rules 1 to 3 and past the guard, which stands in for docker by
  // name on the PATH test/setup.mjs gives: (a) docker named by a path, in any string or template
  // literal of the module or as path.join(…, 'docker'), and (b) a literal handed to another
  // program or to code the module runs (the arguments of a child_process function, fork
  // included, of eval, Function, a Worker or node:vm, or a data: URL imported) that mentions
  // docker, which that program could run on a PATH of its own (sh -c '…', env docker …, node -e
  // "…"). Each is refused unless it is reviewed ({file, literal}: the literal, or the path.join
  // call, as the source writes it), except where rules 1 to 3 read it.
  const flagged = new Set();
  const literalProblem = (k, text, why) => {
    flagged.add(k);
    if (lookUp('literal', text)) return;
    problems.push({ line: lineOf(tokens[k].start), text, why });
  };
  const written = k => source.slice(tokens[k].start, tokens[k].end);
  const isLiteral = k => tokens[k].type === 'str' || tokens[k].type === 'tpl';
  const literalOf = k => (tokens[k].type === 'str' ? tokens[k].value : tokens[k].text);
  for (let k = 0; k < tokens.length; k++) {
    if (!isLiteral(k) || pathsRead.has(k) || !readings(literalOf(k)).some(t => dockerPath.test(t)))
      continue;
    literalProblem(
      k,
      written(k),
      'names docker by a path: the guard stands in for docker by name only, so docker run by a path skips it, and this check reads that path only as the program of a spawn; spawn docker by name with an argument array, or review it and list it'
    );
  }
  for (let k = 2; k < tokens.length; k++) {
    const { type, value } = tokens[k];
    if (type !== 'id' || !['join', 'resolve'].includes(value) || tokens[k - 1]?.value !== '.')
      continue;
    if (tokens[k + 1]?.value !== '(' || pathsRead.has(k)) continue;
    const { parts, close } = elements(tokens, k + 1);
    const last = parts.at(-1);
    if (!last || !dockerName.test(literalText(tokens, last) ?? '')) continue;
    let from = k - 2;
    while (tokens[from - 1]?.value === '.' && tokens[from - 2]?.type === 'id') from -= 2;
    flagged.add(last[0]);
    literalProblem(
      k,
      source.slice(tokens[from].start, tokens[close].start + 1),
      'names docker by a path: the guard stands in for docker by name only, so docker run by a path skips it, and this check reads that path only as the program of a spawn; spawn docker by name with an argument array, or review it and list it'
    );
  }
  for (let k = 0; k < tokens.length; k++) {
    if (tokens[k].type !== 'id' || tokens[k + 1]?.value !== '(') continue;
    const name = tokens[k].value;
    const dataImport =
      name === 'import' &&
      k + 2 < tokens.length &&
      isLiteral(k + 2) &&
      /^data:/i.test(literalOf(k + 2));
    if (!kindOf(k) && !codeRunners.has(name) && !dataImport) continue;
    const close = matching(tokens, k + 1);
    for (let j = k + 2; j < close; j++) {
      if (!isLiteral(j) || flagged.has(j) || programs.has(j) || dockerWords.has(j)) continue;
      if (!readings(literalOf(j)).some(t => /docker/i.test(t))) continue;
      literalProblem(
        j,
        written(j),
        `is handed to another program or to code this module runs (${name}), and mentions docker: this check cannot read what that program or code does with it, and the guard does not see docker run by a path or on a PATH the test sets; spawn docker by name with an argument array, or review it and list it`
      );
    }
  }
  // What runs code, used as a value other than by calling it by its name (an alias, (0, eval),
  // a property kept, a name imported as another), is followed no further than child_process's
  // functions are: its calls could be handed such a literal unseen. Refused, but for reading a
  // property of it (Function.prototype) and an import or a destructuring that keeps the name
  // (import { Worker } from 'node:worker_threads').
  for (let k = 0; k < tokens.length; k++) {
    const { type, value } = tokens[k];
    if (type !== 'id' || !codeRunners.has(value) || ['(', '.'].includes(tokens[k + 1]?.value))
      continue;
    // In braces: what opens them (import, a declaration's destructuring, or an object).
    let declares = false;
    if (['{', ','].includes(tokens[k - 1]?.value)) {
      let j = k - 1;
      while (j > 0 && tokens[j].value !== '{') j--;
      const before = tokens[j - 1]?.value;
      declares =
        ['import', 'const', 'let', 'var'].includes(before) ||
        (before === ',' && tokens[j - 3]?.value === 'import');
      // An object's key ({ eval: 1 }), not the name; in a destructuring, a rename.
      if (tokens[k + 1]?.value === ':' && !declares) continue;
      // The name kept: import { Worker } from 'node:worker_threads'.
      if (['}', ','].includes(tokens[k + 1]?.value) && declares) continue;
    }
    problems.push({
      line: lineOf(tokens[k].start),
      text: lineText(k),
      why: `${value}, which runs code, is used as a value other than by calling it by that name (an alias, (0, ${value}), a property kept, imported as another name), so what it is handed cannot be checked; call it by name`,
    });
  }
  for (const entry of reviewed)
    if (entry.file === file && !used.has(entry))
      problems.push({
        line: 0,
        text: entry.call ?? entry.program ?? entry.literal,
        why: 'listed as reviewed, but no longer found',
      });
  return { calls, problems, wrappers: [...wrappers.keys()] };
}

// The first line of a script that node runs: #!/usr/bin/node, #!/usr/bin/env node,
// #!/usr/bin/env -S node --flag. Any other first line (#!/bin/sh, even one that mentions node
// later on) is not JavaScript.
const nodeInterpreter = /^#![ \t]*(?:\S*\/)?(?:env(?:[ \t]+-\S*)*[ \t]+)?node(?:[ \t]|$)/;

// The escapes of $'…' (ANSI-C quoting, which bash reads, macOS /bin/sh among them; dash does
// not), read as bash 5 reads them, so that $'\x64ocker', $'\144ocker' and $'docker' are
// docker.
const ansiLetters = {
  a: '\x07',
  b: '\b',
  e: '\x1b',
  E: '\x1b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
  v: '\v',
};
function ansiC(body) {
  return body.replace(
    /\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c[\s\S]|[\s\S])/g,
    (all, escape) => {
      const kind = escape[0];
      if (kind === 'x') return String.fromCharCode(parseInt(escape.slice(1), 16));
      if (kind === 'u' || kind === 'U') {
        const point = parseInt(escape.slice(1), 16);
        return point <= 0x10ffff ? String.fromCodePoint(point) : '';
      }
      if (/[0-7]/.test(kind)) return String.fromCharCode(parseInt(escape, 8) & 0xff);
      if (kind === 'c' && escape.length === 2)
        return String.fromCharCode(escape.charCodeAt(1) & 0x1f);
      return ansiLetters[kind] ?? kind;
    }
  );
}

// The lines of a text file as sh reads its words (rule 4): [{line, text, words, commands}]. A
// line ending in a backslash goes on in the next, as in sh: `line` is the number of the first,
// `text` those lines as they read, each trimmed, joined by a space, and `words` what sh makes of
// them, the backslash and line end between them taken out, each $'…' read (ansiC), then every
// quote, backtick and backslash (and a $ opening $"…") taken out, so that `d""ocker`, `d\ocker`,
// `doc\`+`ker` and $'\x64ocker' all read docker. `commands` is the same with each backtick made
// a blank, as it ends a word.
function shellLines(text) {
  const physical = text.split('\n');
  const lines = [];
  for (let index = 0; index < physical.length; index++) {
    const first = index,
      parts = [physical[index]];
    while (/\\\r?$/.test(parts.at(-1)) && index + 1 < physical.length)
      parts.push(physical[++index]);
    const read = parts
      .map(part => part.replace(/\\\r?$/, ''))
      .join('')
      .replace(/\$'((?:[^'\\]|\\[\s\S])*)'/g, (all, body) => ansiC(body));
    lines.push({
      line: first + 1,
      text: parts.map(part => part.trim()).join(' '),
      words: read.replace(/\$?["'`]|\\/g, ''),
      commands: read.replace(/`/g, ' ').replace(/\$?["']|\\/g, ''),
    });
  }
  return lines;
}

// The text of a JavaScript string's escapes read (\x64, \u0064, \u{64}, \144, a backslash before
// a line end), as often as they nest, for code a string holds: eval("f('\\x64ocker')").
function jsUnescaped(text) {
  for (let round = 0; round < 8; round++) {
    const read = text.replace(
      /\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|([0-7]{1,3})|(\r\n|[\s\S]))/g,
      (all, hex, braced, unicode, octal, other) => {
        if (hex) return String.fromCharCode(parseInt(hex, 16));
        if (braced) {
          const point = parseInt(braced, 16);
          return point <= 0x10ffff ? String.fromCodePoint(point) : '';
        }
        if (unicode) return String.fromCharCode(parseInt(unicode, 16));
        if (octal) return String.fromCharCode(parseInt(octal, 8) & 0xff);
        return /^(?:\r\n|[\n\r\u2028\u2029])$/.test(other) ? '' : other;
      }
    );
    if (read === text) break;
    text = read;
  }
  return text;
}

// The ways the text of a literal can read (rule 5): as written, each line as sh reads its words
// (shellLines: quotes, backslashes and the escapes of $'…' taken out), and with the escapes of a
// JavaScript string read (jsUnescaped), for code a string holds.
function readings(text) {
  return [text, ...shellLines(text).map(line => line.words), jsUnescaped(text)];
}

// docker as a shell runs it, as a command: docker, or a path ending in /docker, at the start of a
// line or after a blank, ; & | ( ) < >, and before the end of the line or one of those.
const dockerCommand = /(?:^|[ \t;&|()<>])(?:[^ \t;&|()<>]*\/)?docker(?:\.exe)?(?=$|[ \t;&|()<>])/i;

/**
 * The lines of `bytes`, a file passed over unread as text (rule 4: a release fixture archive or a
 * .DS_Store file of Finder), where a shell handed it could run docker: [{line, text}]. A shell
 * runs a file it is handed whatever bytes it holds: dash (Debian's /bin/sh) drops every NUL byte
 * and runs the rest, so each file is read twice as Latin-1 text, once with its NUL bytes dropped
 * and once with each read as a blank, then line by line as shellLines reads it, for docker run as
 * a command (dockerCommand), not merely named: Finder's files hold file names (docker.test.mjs).
 */
export function shellCommands(bytes) {
  const found = new Map();
  for (const text of [
    Buffer.from(bytes.filter(byte => byte !== 0)).toString('latin1'),
    Buffer.from(bytes.map(byte => (byte === 0 ? 0x20 : byte))).toString('latin1'),
  ])
    for (const { line, text: read, commands } of shellLines(text))
      if (dockerCommand.test(commands) && !found.has(line))
        found.set(line, read.replace(/[^\x20-\x7e]/g, ' ').slice(0, 160));
  return [...found].sort(([a], [b]) => a - b).map(([line, text]) => ({ line, text }));
}

// The header macOS Finder's .DS_Store files start with: 1, then the magic "Bud1".
const finderHeader = Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31]);

/**
 * Whether `file` (a path below test/, with / separators) holding `bytes` is a .DS_Store file
 * that macOS Finder wrote: by its name and its header (rule 4). git ignores such files and a
 * release leaves them out, so they are no part of the suite; any other file of that name is
 * checked as any other.
 */
export function isFinderFile(file, bytes) {
  return (
    path.posix.basename(file) === '.DS_Store' &&
    Buffer.isBuffer(bytes) &&
    bytes.subarray(0, finderHeader.length).equals(finderHeader)
  );
}

/**
 * Checks one file below test/ (`file`, its path there; `content`, its bytes or its text) by what
 * it holds, whatever its name, mode or first line, since a test can run any file (rule 4): a
 * file named .mjs, .cjs or .js with checkSource; any other text line by line, as sh reads it
 * (shellLines), where a line that mentions docker, in any case, is refused unless
 * `options.reviewed` lists it ({file, line, why}: the line as it reads, trimmed, with the lines
 * a backslash joins to it), and, when its first line runs node, with checkSource as well; a
 * binary file (a NUL byte, or bytes that are not UTF-8) is refused, since it cannot be read. A
 * listed call or line that is not found is refused too. Returns {kind:
 * 'javascript'|'text'|'binary', calls, problems, wrappers}, as checkSource does.
 */
export function checkFile(file, content, options = {}) {
  const listed = (options.reviewed ?? []).filter(entry => entry.file === file);
  const stale = entry => ({
    line: 0,
    text: entry.call ?? entry.program ?? entry.literal ?? entry.line,
    why: 'listed as reviewed, but no longer found',
  });
  let text = content;
  if (typeof text !== 'string')
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(content);
    } catch {
      text = null;
    }
  if (text === null || text.includes('\0'))
    return {
      kind: 'binary',
      calls: [],
      wrappers: [],
      problems: [
        {
          line: 0,
          text: file,
          why: 'a binary file cannot be checked for docker; keep release archives in test/fixtures/, pinned in its SHA256SUMS',
        },
        ...listed.map(stale),
      ],
    };
  const calls = listed.filter(entry => entry.line === undefined),
    lines = listed.filter(entry => entry.line !== undefined);
  // checkSource, with source it cannot read (a SyntaxError, which names its offset) as a problem.
  const javascript = () => {
    try {
      return checkSource(text, { ...options, file, reviewed: calls });
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      const at = Number(/ at (\d+)/.exec(error.message)?.[1] ?? 0);
      return {
        calls: [],
        wrappers: [],
        problems: [
          {
            line: text.slice(0, at).split('\n').length,
            text: file,
            why: `this check cannot read it as JavaScript (${error.message}), so its docker calls cannot be checked; write it plainly`,
          },
          ...calls.map(stale),
        ],
      };
    }
  };
  if (/\.(?:mjs|cjs|js)$/.test(file)) {
    const result = javascript();
    for (const entry of lines) result.problems.push(stale(entry));
    return { kind: 'javascript', ...result };
  }
  // Not named as JavaScript: read line by line, and also as JavaScript when node runs it.
  const result = nodeInterpreter.test(text.split('\n', 1)[0])
    ? javascript()
    : { calls: [], wrappers: [], problems: calls.map(stale) };
  const used = new Set();
  for (const { line, text: read, words } of shellLines(text)) {
    if (!/docker/i.test(words)) continue;
    const entry = lines.find(candidate => candidate.line === read);
    if (entry) used.add(entry);
    else
      result.problems.push({
        line,
        text: read,
        why: 'a file that is not JavaScript mentions docker: a test may run it (as /bin/sh stand-in-tar is run), and this check cannot read it; start docker from a test module, with an argument array, or review the line and list it',
      });
  }
  for (const entry of lines) if (!used.has(entry)) result.problems.push(stale(entry));
  return { kind: 'text', ...result };
}

/**
 * The files `directory`/fixtures/SHA256SUMS pins (the release fixture archives): a Map of each
 * one's path relative to `directory`, with / separators, to its sha256. Empty without the file.
 */
export function fixturePins(directory) {
  const pinned = new Map();
  const sums = path.join(directory, 'fixtures', 'SHA256SUMS');
  if (fs.existsSync(sums))
    for (const line of fs.readFileSync(sums, 'utf8').split('\n')) {
      const match = /^([0-9a-f]{64}) [ *]([^/].*)$/.exec(line);
      if (match) pinned.set(`fixtures/${match[2]}`, match[1]);
    }
  return pinned;
}

/**
 * Checks every file below `directory` (test/) with checkFile (rule 4). Returns {read, skipped,
 * ignored, problems, containers}: read, [{file, kind}] for each file read, as paths relative to
 * `directory` with / separators; skipped, the release fixture archives passed over, each binary
 * and holding the bytes fixtures/SHA256SUMS pins for it (one that differs is refused as binary,
 * and a pinned text file is read as any other; one that is not there, as in a release, which
 * leaves them out, is neither); ignored, the .DS_Store files of macOS Finder (isFinderFile);
 * problems, [{file, line, text, why}], also for a symbolic link or anything else that is not a
 * regular file or a directory (what a link points to is not read), and for a reviewed entry
 * whose file is not there; containers, a Map of each file to its docker run and create calls.
 */
export function checkTree(directory, { reviewed = [] } = {}) {
  const pinned = fixturePins(directory);
  const read = [],
    skipped = [],
    ignored = [],
    problems = [],
    containers = new Map();
  const entries = fs
    .readdirSync(directory, { recursive: true, withFileTypes: true })
    .map(entry => ({
      entry,
      file: path
        .relative(directory, path.join(entry.parentPath, entry.name))
        .split(path.sep)
        .join('/'),
    }))
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  for (const { entry, file } of entries) {
    if (entry.isDirectory()) continue;
    if (!entry.isFile()) {
      problems.push({
        file,
        line: 0,
        text: file,
        why: 'not a regular file (a symbolic link, say), so what it leads to is not checked; keep the file itself below test/',
      });
      continue;
    }
    const bytes = fs.readFileSync(path.join(directory, file));
    const finder = isFinderFile(file, bytes);
    const checked = finder ? null : checkFile(file, bytes, { reviewed });
    if (
      finder ||
      (checked.kind === 'binary' &&
        pinned.get(file) === createHash('sha256').update(bytes).digest('hex'))
    ) {
      // Passed over unread as text, unless a shell handed it could run docker (shellCommands).
      const commands = shellCommands(bytes);
      if (!commands.length) {
        (finder ? ignored : skipped).push(file);
        continue;
      }
      read.push({ file, kind: 'binary' });
      for (const { line, text } of commands)
        problems.push({
          file,
          line,
          text,
          why: `a shell handed this ${finder ? '.DS_Store file' : 'release archive'} could run docker (dash, Debian's /bin/sh, drops its NUL bytes and runs the rest)${finder ? '; delete it (git ignores .DS_Store files)' : ''}`,
        });
      continue;
    }
    read.push({ file, kind: checked.kind });
    for (const problem of checked.problems) problems.push({ file, ...problem });
    const made = checked.calls.filter(call => call.limits).length;
    if (made) containers.set(file, made);
  }
  for (const entry of reviewed)
    if (!read.some(({ file }) => file === entry.file))
      problems.push({
        file: entry.file,
        line: 0,
        text: entry.call ?? entry.program ?? entry.literal ?? entry.line,
        why: 'listed as reviewed, but the file is not read below test/',
      });
  return { read, skipped, ignored, problems, containers };
}
