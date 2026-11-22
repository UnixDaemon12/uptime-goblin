// The product is Uptime Goblin from 1.5 (it was Orbit before; docs/installation.md, "Renamed from
// Orbit"). This check reads every file a user sees, reads or installs (the documentation, the
// examples, the web app, the server's messages, the installer, the unit and the container files)
// and fails on "Orbit" or "orbit" in any of them outside the allowlist below. Each allowed name or
// passage says why it stays: a compatibility name 1.5 and 1.6 still accept, a stored or
// signed identifier that cannot change without breaking an existing install, history from before
// 1.5, or the passages that explain the rename. In code files only the text of string and
// template literals counts: identifiers and comments are not shown to anyone.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

// What is scanned: these files, and every file under these folders.
const scannedFiles = [
  'README.md',
  'SECURITY.md',
  'CONTRIBUTING.md',
  'AGENTS.md',
  'CHANGELOG.md',
  'server.mjs',
  'package.json',
  'Dockerfile',
  'compose.yaml',
  'compose.secret.yaml',
];
const scannedFolders = ['docs', 'examples', 'public', 'lib', 'deploy'];

// Files left out whole, each with its reason.
export const excludedFiles = new Map([
  ['lib/legacy-names.mjs', 'the compatibility code: it reads the names from before 1.5'],
  ['lib/cli/orbit-admin.mjs', 'the old admin command, kept as a shim that runs goblin-admin'],
  ['deploy/install-lxc.sh', "the old installer's name, kept as a shim that runs install.sh"],
  [
    'docs/documentation-inventory.md',
    'a dated audit of the Orbit tree, which keeps the names and paths of that time',
  ],
  ['public/favicon.svg', 'an image'],
]);

// Not scanned yet, and so named here rather than passed over: the file this step could not open.
export const pendingFiles = new Map([]);

// Passages left out, each with its reason: [file, start, end] where start is how the first line
// of the passage begins and end how the line after it begins ('' for the next blank line; null:
// the end of the file).
export const excludedPassages = [
  [
    'CHANGELOG.md',
    '- **Orbit is now Uptime Goblin.**',
    '- **Nodemailer 10.6.1 (security).**',
    'the 1.5 entries that describe the rename, its compatibility names and the migration',
  ],
  [
    'CHANGELOG.md',
    '_The entries below are for releases before 1.5, made when the product was called Orbit; they keep that name. It was renamed Uptime Goblin in 1.5._',
    null,
    'the entries for releases before 1.5, which keep the name they were released under',
  ],
  [
    'docs/installation.md',
    '### Renamed from Orbit',
    '### Upgrading to 1.5',
    'the section that explains the rename, with the upgrade checklist',
  ],
  [
    'docs/installation.md',
    'Upgrading Orbit to 1.4.3:',
    '',
    'the upgrade note of Orbit 1.4.3, with its names and paths',
  ],
  [
    'deploy/install.sh',
    'const layoutNames=',
    'const layoutPath=',
    "the table that names each Uptime Goblin path, unit and account's Orbit form before the move",
  ],
  [
    'deploy/install.sh',
    'if(!recorder){console.error(`${head} The running Orbit',
    'process.exit(1);',
    'the proxy preflight of the upgrade from Orbit 1.4.x, about the Orbit release running',
  ],
  [
    'deploy/install.sh',
    'goblin_migration_script() {',
    '# Run with every signal ignored',
    'the migration script: it moves the Orbit layout (unit, account, paths) and back, by name',
  ],
  [
    'README.md',
    'Uptime Goblin was called Orbit until 1.4.x.',
    '',
    "the README's note on the rename",
  ],
  [
    'docs/installation.md',
    'An archive made under Orbit with its own backup line',
    '',
    'restoring a backup made under Orbit, with its paths',
  ],
  [
    'docs/installation.md',
    '2. Take a consistent backup and retain the previous source/image',
    '3. ',
    "the upgrade step that keeps Orbit's image under its own tag",
  ],
  [
    'docs/installation.md',
    '- **Docker:** keep the running 1.4.3 image under its own tag first',
    '- **After the upgrade**',
    "the Docker upgrade from Orbit 1.4.3: its image and the old service's container",
  ],
  [
    'docs/installation.md',
    '**After a code rollback to 1.4.x**',
    'Under Docker Compose, with the 1.5 image kept under its own tag',
    'the kept goblin-admin on the Orbit layout, which 1.4.x runs on after a rollback',
  ],
  [
    'docs/installation.md',
    '1.4.x knows nothing of the record that makes 1.5 refuse to start',
    '',
    'an interrupted restore under 1.4.x, on the Orbit layout',
  ],
  [
    'docs/notifications.md',
    '| `X-Orbit-Delivery` |',
    '',
    'the webhook headers sent under their old names too, in 1.5 and 1.6',
  ],
  [
    'docs/troubleshooting.md',
    '| Installer `--restore-orbit-layout`:',
    '| Installer: "The release files do not match SHA256SUMS"',
    "the installer's refusal to go back to the Orbit layout",
  ],
  [
    'docs/troubleshooting.md',
    '| 75 from `goblin-admin`, "Uptime Goblin … is running on …',
    '| 75 from `goblin-admin`, "Uptime Goblin (or another goblin-admin command)',
    'refusals that name a running Orbit release, its lock and its unit',
  ],
  [
    'docs/troubleshooting.md',
    '| 75 from `goblin-admin` under Docker, "Orbit 1.4… may be running on',
    '| `goblin-admin`: "Cannot find module',
    'the refusal that names a running Orbit release under Docker',
  ],
  [
    'docs/troubleshooting.md',
    '| `goblin-admin`: "Cannot find module',
    '| Log "file is not a database"',
    'the kept goblin-admin on the Orbit layout after a rollback to 1.4.x',
  ],
  [
    'docs/installation.md',
    '### Rolling back 1.5 to 1.4.3',
    '### Rolling back 1.4.3 to 1.4.2',
    'going back to Orbit 1.4.3, which reads only the Orbit names and paths',
  ],
  [
    'docs/installation.md',
    '### Rolling back 1.4.3 to 1.4.2',
    null,
    'Orbit releases (1.4.3 to 1.4.2, and older ones), with their names and paths',
  ],
];

// Names and phrases allowed anywhere, each with its reason. An occurrence of orbit (any case)
// passes only when one of these matches around it.
export const allowedNames = [
  // Stored, signed or handed over by name: renaming them would break existing installs.
  [/\borbit_secret_key(?:\.[A-Za-z]+)?\b/g, 'the Compose secret file kept by its name'],
  [/\/run\/secrets\/orbit_secret_key/g, 'where Compose mounts that secret'],
  [/\borbit-secret-key\b/g, 'the systemd credential kept by its name'],
  [/\.orbit-secret\.key\b/g, "the npm start key file of .env.example's examples"],
  [/orbit-data\b/g, 'the Compose volume, kept by its name so the data stays'],
  [/release@orbit-homelab|\borbit-release\b/g, 'the release signing identity and namespace'],
  [/orbit-homelab(?::local|:1\.[0-4](?:\.\d+)?|-1\.[0-4][\w.-]*)/g, "Orbit's image and archives"],
  [/`orbit-homelab` project/g, 'the SonarQube project key of the analysis service'],
  [/realm="Orbit"/g, 'the legacy Basic realm, so remembered 1.4.x logins are not asked again'],
  [/\{"orbit":"audit[\w.]*"/g, "the audit log's lines in the log, which verify-audit reads"],
  [/"orbit":"audit\.checkpoint"/g, 'the checkpoint mark verify-audit looks for'],
  [/"(?:source|service)":"orbit"/g, "the webhook body and Uptime Goblin's own notices"],
  [/<orbit\.(?:g_|\$\{|$)/g, 'the email Message-ID, stable across retries'],
  [/\borbit-config\b/g, 'the configuration export format'],
  [/<meta name="orbit-build"|meta\[name="orbit-build"\]|\borbit-build\b/g, 'the page build tag'],
  [
    /\borbit-(?:update-reloads|update-restore|stale-checks|signout-other-cookie)\b/g,
    'browser storage keys',
  ],
  [
    /\bmini-orbit\b|\bwelcome-orbit\b|\borbit-(?:fade|drawer|dialog|detail)-(?:in|out)\b/g,
    'CSS names',
  ],
  [
    /^orbit$/g,
    'a string that is only orbit: the audit actor and target, the alert service, the icon, the database schema',
  ],
  [
    /^orbit(?:\/|-keyring-v1|-seal-v1|-display-code-v1|\\n|\n)/g,
    'key derivation and sealing labels, and stored keys',
  ],
  [/orbit-security\b/g, "the gate's private evidence folder"],
  [/orbit-gate-local-diagnostic-run/g, "the gate's record family"],
  [/`startOrbit`/g, 'a test helper name'],
  // Releases before 1.5, which were called Orbit.
  [/\bOrbit 1\.[0-4]/g, 'a release before 1.5'],
  [
    /"Orbit: (?:running|may be running|not running)/g,
    "goblin-admin status's line about an Orbit release",
  ],
  [/Upgrading Orbit to 1\.[0-4]/g, 'upgrade notes of a release before 1.5'],
  [/(?:renamed|Renamed) from Orbit|#renamed-from-orbit/g, 'a link to the rename section'],
  [/--restore-orbit-layout\b/g, 'the installer option that goes back to the Orbit layout'],
  [/called Orbit/g, 'the name before 1.5'],
];

// The names from before 1.5 that 1.5 and 1.6 still accept, and the Orbit layout the installer
// migrates and goes back to: allowed only in the files that implement or configure that
// compatibility (compatibilityFiles), in the excluded passages that explain the rename, and in
// the named exceptions below, so that a stale instruction elsewhere (send X-Orbit-Request, the
// paths of /var/lib/orbit) fails.
export const compatibilityNames = [
  // Accepted in 1.5 and 1.6, removed in 1.7 (lib/legacy-names.mjs).
  [/\bORBIT_[A-Z0-9_]*/g, 'the settings names from before 1.5'],
  [/X-Orbit-[A-Za-z-]+/g, 'the header names from before 1.5'],
  [/(?:__Host-)?orbit_session/g, 'the session cookie from before 1.5'],
  [/\borbit\.lock\b/g, 'the lock file from before 1.5, still taken'],
  [/(?:lib\/cli\/)?\borbit-admin(?:\.mjs)?/g, 'the old admin command (a shim until 1.7)'],
  [/deploy\/install-lxc\.sh/g, 'the old installer name (a shim until 1.7)'],
  // The Orbit layout (releases before 1.5), which the installer migrates and goes back to.
  [/(?:[Aa]n|[Tt]he) Orbit layout/g, 'the layout the installer migrates'],
  [
    /under Orbit\b|from Orbit\b|for receivers written for Orbit|where Orbit kept its|Orbit's image|Orbit is now Uptime Goblin|the service `orbit`|The service was called orbit/g,
    'the rename itself',
  ],
  [/var\/lib\/orbit|etc\/orbit(?:\.env)?\b|opt\/orbit\b/g, 'the paths of the Orbit layout'],
  [/the Orbit names/g, 'the names from before 1.5, as a whole'],
  [
    /\/etc\/orbit\.env\.migrated|\/etc\/systemd\/system\/orbit\.service\.migrated/g,
    'the files the migration keeps',
  ],
  [
    /\(orbit\.service, \/opt\/orbit, \/var\/lib\/orbit, \/etc\/orbit\.env\)/g,
    'the Orbit layout named in the install plan',
  ],
  [
    /\borbit\.service\b|\/etc\/orbit\/secret\.key|\bsystemctl stop orbit\b|(?:Stop|start) Orbit\b|\bno Orbit runs\b|the user Orbit runs as on this layout \(orbit\)/g,
    'the unit, account and key file of the Orbit layout, where 1.4.x runs after a rollback',
  ],
  [/^Orbit$/g, 'the name of a release before 1.5, for a message about one'],
];

// The files that implement or configure the compatibility with the names from before 1.5, where
// compatibilityNames are allowed (outside them, only in the excluded passages).
export const compatibilityFiles = new Map([
  ['compose.yaml', "each setting's ORBIT_ name from .env, read where the GOBLIN_ one is unset"],
  ['server.mjs', 'adopts the ORBIT_ settings at the start'],
  ['Dockerfile', "the image reads a volume still mounted where Orbit's image kept its data"],
  ['deploy/install.sh', 'the migration from the Orbit layout and the way back to it'],
  ['deploy/install-plan.sh', 'the read-only plan names the Orbit layout it would migrate'],
  ['deploy/manifest.txt', 'lists lib/cli/orbit-admin.mjs, the shim it installs'],
  ['lib/admin-command.mjs', 'command lines for the Orbit layout after a rollback to 1.4.x'],
  ['lib/cli/common.mjs', 'refusals that name a running Orbit release and its lock'],
  ['lib/cli/commands/status.mjs', 'status lines about Orbit releases and orbit.lock'],
  ['lib/cli/goblin-admin.mjs', 'adopts the ORBIT_ settings; command lines for the Orbit layout'],
  ['lib/db/control.mjs', 'the interrupted-restore message for the Orbit layout'],
  ['lib/db/lock.mjs', 'takes orbit.lock beside goblin.lock'],
  ['lib/healthcheck.mjs', 'reads the X-Orbit-Build of an Orbit release'],
  ['lib/http/cookies.mjs', 'reads and expires the orbit_session cookie'],
  ['lib/http/pipeline.mjs', 'the X-Orbit-Request check and the orbit_session rotation'],
  ['lib/http/routes/auth.mjs', 'signing in or out removes an orbit_session cookie'],
  ['lib/http/startup.mjs', 'sends X-Orbit-Build beside X-Goblin-Build'],
  ['lib/http/transport.mjs', 'reads X-Orbit-Client'],
  ['lib/notify/sign.mjs', 'sends the X-Orbit- webhook headers beside the X-Goblin- ones'],
  ['public/boot.js', 'a tab opened on Orbit reads X-Orbit-Build'],
  ['public/modules/core/api.js', 'sends X-Goblin-Activity, and reads the old name'],
]);

// Names allowed in deploy/install.sh alone, beside compatibilityNames: its own handling of the
// Orbit layout it migrates and goes back to.
export const installerNames = [
  [
    /goblin_layout (?:[!=]=) orbit\b|goblin_layout==='orbit'|goblin_account=orbit\b/g,
    'the layout variable that says the host has the Orbit layout',
  ],
  [
    /run\/orbit-install\.lock|An Orbit installer/g,
    "an Orbit installer's lock, held beside its own",
  ],
  [
    /# Added by the Orbit 1\.5 installer: keeps plain-HTTP sign-in working as in 1\.4\.x\.(?: Set it to 0 once Orbit is served over HTTPS\.)?|an earlier Orbit 1\.5 pre-release installer/g,
    'the comment line earlier 1.5 pre-release installers wrote, which it recognizes',
  ],
  [
    /Going back to Orbit\b|\bOrbit \$goblin_restore_version\b/g,
    'going back to the Orbit release kept (--restore-orbit-layout)',
  ],
];

// Named exceptions, allowed anywhere: old names that keep their name on purpose.
export const namedExceptions = [
  [/\bORBIT_SIGNING_KEY\b/g, 'the release packaging script (scripts/package-release.mjs) reads it'],
  [
    /\bORBIT_SECURITY_[A-Z0-9_]+\b|\bORBIT_SONAR_TOKEN_FILE\b/g,
    "the security gate's own variables (scripts/), which keep their names",
  ],
];

/**
 * The parts of a JavaScript source a user can see: the text of its string and template literals,
 * as [line, text] pairs. Comments, identifiers and regular expressions are left out. A simple
 * scanner, enough for this repository's sources: a slash starts a regular expression after an
 * operator, a bracket or a keyword, and division otherwise.
 */
export function literalTexts(source) {
  const found = [];
  let line = 1;
  let i = 0;
  let previous = '';
  const stack = []; // template nesting: the brace depth at each ${
  let depth = 0;
  const add = (start, text) => found.push([start, text]);
  const regexAllowed = () =>
    previous === '' ||
    /[(,=:[!&|?{};+\-*%<>~^]$/.test(previous) ||
    /\b(?:return|typeof|case|do|else|in|of|void|yield|await)$/.test(previous);
  const readTemplate = () => {
    // i is just past the opening backtick or a closing } of ${…}
    let start = line;
    let text = '';
    while (i < source.length) {
      const c = source[i];
      if (c === '\\') {
        text += source.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (c === '`') {
        i++;
        add(start, text);
        previous = '`';
        return;
      }
      if (c === '$' && source[i + 1] === '{') {
        add(start, text);
        i += 2;
        stack.push(depth);
        depth = 0;
        previous = '{';
        return;
      }
      if (c === '\n') line++;
      text += c;
      i++;
    }
    add(start, text);
  };
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (c === '\n') {
      line++;
      i++;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end < 0 ? source.length : end + 2;
      line += source.slice(i, stop).split('\n').length - 1;
      i = stop;
      continue;
    }
    if (c === "'" || c === '"') {
      const start = line;
      let text = '';
      i++;
      while (i < source.length && source[i] !== c && source[i] !== '\n') {
        if (source[i] === '\\') {
          text += source.slice(i, i + 2);
          i += 2;
          continue;
        }
        text += source[i++];
      }
      i++;
      add(start, text);
      previous = c;
      continue;
    }
    if (c === '`') {
      i++;
      readTemplate();
      continue;
    }
    if (c === '/' && regexAllowed()) {
      let inClass = false;
      i++;
      while (i < source.length && source[i] !== '\n') {
        const r = source[i];
        if (r === '\\') {
          i += 2;
          continue;
        }
        if (r === '[') inClass = true;
        else if (r === ']') inClass = false;
        else if (r === '/' && !inClass) break;
        i++;
      }
      i++;
      while (/[a-z]/.test(source[i] ?? '')) i++;
      previous = '/re';
      continue;
    }
    if (c === '{') depth++;
    if (c === '}') {
      if (depth === 0 && stack.length) {
        depth = stack.pop();
        i++;
        readTemplate();
        continue;
      }
      depth--;
    }
    // A word, a number or one punctuation character.
    const word = /^[A-Za-z_$][\w$]*|^\d[\w.]*/.exec(source.slice(i, i + 64));
    if (word) {
      previous = word[0];
      i += word[0].length;
    } else {
      previous = c;
      i++;
    }
  }
  return found;
}

// The text of a file a user can see, as [line, text] pairs.
function visibleText(file, source) {
  const extension = path.extname(file);
  if (extension === '.mjs' || extension === '.js') return literalTexts(source);
  // A shell script: its lines without the comment lines (a '#' that starts one, or a '//' in the
  // JavaScript of its here-documents), which no one running it sees. What it prints, the paths it
  // uses and its scripts' text all count.
  if (extension === '.sh')
    return source
      .split('\n')
      .map((value, index) => [index + 1, /^\s*(?:#|\/\/)/.test(value) ? '' : value]);
  let text = source;
  if (extension === '.css') text = text.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '));
  if (extension === '.html') text = text.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '));
  const lines = text.split('\n').map((value, index) => [index + 1, value]);
  // CSS: an identifier (a class, an animation name) is no one's to read, but text in quotes (a
  // content: string) is shown, so the lower-case names are left out only outside quotes.
  if (extension === '.css')
    return lines.map(([n, value]) => [
      n,
      value
        .split(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/)
        .map((part, index) =>
          index % 2 ? part : part.replace(/[\w-]*orbit[\w-]*/g, m => (/Orbit/.test(m) ? m : ''))
        )
        .join(''),
    ]);
  return lines;
}

// The lines of a file that the excluded passages leave.
function withoutPassages(file, source) {
  const lines = source.split('\n');
  const keep = lines.map(() => true);
  for (const [name, start, end] of excludedPassages) {
    if (name !== file) continue;
    const from = lines.findIndex(value => value.startsWith(start));
    assert.ok(from >= 0, `${file}: the excluded passage "${start}" is not there any more`);
    const after = lines.slice(from + 1);
    const to =
      end === null
        ? lines.length
        : from + 1 + after.findIndex(value => (end === '' ? value === '' : value.startsWith(end)));
    assert.ok(to > from, `${file}: the passage "${start}" has no end "${end}"`);
    for (let n = from; n < to; n++) keep[n] = false;
  }
  return lines.map((value, index) => (keep[index] ? value : '')).join('\n');
}

/**
 * Each occurrence of orbit (any case) in `text` that no allowed name covers: allowedNames and
 * namedExceptions everywhere, compatibilityNames only with `compatible` (a compatibility file),
 * installerNames only with `installer` (deploy/install.sh).
 */
export function unallowed(text, { compatible = false, installer = false } = {}) {
  const covered = [];
  for (const [pattern] of [
    ...allowedNames,
    ...namedExceptions,
    ...(compatible ? compatibilityNames : []),
    ...(installer ? installerNames : []),
  ])
    for (const match of text.matchAll(
      new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g')
    ))
      covered.push([match.index, match.index + match[0].length]);
  const problems = [];
  for (const match of text.matchAll(/orbit/gi)) {
    const at = match.index;
    if (!covered.some(([from, to]) => at >= from && at + 5 <= to)) problems.push(at);
  }
  return problems;
}

/** The problems in one file: "file:line: …context…". */
export function productNameProblems(file, source) {
  const problems = [];
  const compatible = compatibilityFiles.has(file);
  const installer = file === 'deploy/install.sh';
  for (const [line, text] of visibleText(file, withoutPassages(file, source)))
    for (const at of unallowed(text, { compatible, installer }))
      problems.push(
        `${file}:${line}: …${text.slice(Math.max(0, at - 40), at + 45).replace(/\s+/g, ' ')}…`
      );
  return problems;
}

function scanned() {
  const files = [...scannedFiles];
  const walk = folder => {
    for (const entry of fs.readdirSync(path.join(root, folder), { withFileTypes: true })) {
      const name = `${folder}/${entry.name}`;
      if (entry.isDirectory()) walk(name);
      else if (entry.isFile()) files.push(name);
    }
  };
  for (const folder of scannedFolders) walk(folder);
  return files.filter(file => !excludedFiles.has(file) && !pendingFiles.has(file)).sort();
}

test('no user-facing "Orbit" is left outside the allowlisted compatibility names, history and rename passages', () => {
  const files = scanned();
  assert.ok(files.length > 150, `${files.length} files scanned`);
  for (const file of [
    'docs/installation.md',
    'public/index.html',
    'lib/notify/channels/webhook.mjs',
    'deploy/uptime-goblin.service',
  ])
    assert.ok(files.includes(file), `${file} is scanned`);
  const problems = files.flatMap(file =>
    productNameProblems(file, fs.readFileSync(path.join(root, file), 'utf8'))
  );
  assert.deepEqual(problems, []);
});

test('the product-name check finds the old name where a user would see it, and passes what the allowlist names', () => {
  // Prose, code strings and template text fail; comments, identifiers and regular expressions do not.
  assert.equal(productNameProblems('docs/x.md', 'Restart Orbit after editing.\n').length, 1);
  assert.equal(productNameProblems('docs/x.md', 'Run sudo -u orbit node …\n').length, 1);
  assert.equal(productNameProblems('lib/x.mjs', "const m = 'Orbit refused to start';\n").length, 1);
  assert.equal(
    productNameProblems('lib/x.mjs', 'const m = `see /opt/orbit/${x} now`;\n').length,
    1
  );
  assert.equal(productNameProblems('lib/x.mjs', 'const a = `${`Orbit`}`;\n').length, 1);
  assert.equal(productNameProblems('public/x.html', '<p>Orbit</p>\n').length, 1);
  assert.equal(productNameProblems('public/x.css', '.a::after { content: "Orbit"; }\n').length, 1);
  assert.deepEqual(
    productNameProblems(
      'lib/x.mjs',
      "// Orbit 1.4 did this\n/* Orbit */ const orbitState = x / y; const r = /orbit/i;\nconst s = 'orbit';\n"
    ),
    []
  );
  assert.deepEqual(
    productNameProblems(
      'public/x.css',
      '.mini-orbit { animation: orbit-fade-in 1s; } /* Orbit */\n'
    ),
    []
  );
  // CSS: a lower-case name is an identifier outside quotes, but text in a content: string.
  assert.equal(productNameProblems('public/x.css', '.a::after { content: "orbit"; }\n').length, 1);
  // The allowed names, and only around the occurrence: an allowed name elsewhere on the line
  // does not cover another occurrence.
  assert.deepEqual(
    productNameProblems(
      'docs/x.md',
      'Set `GOBLIN_X`; `orbit_secret_key` and `orbit-data` keep their names. Orbit 1.4.3 did not.\n'
    ),
    []
  );
  // The names 1.5 still accepts are allowed only where the compatibility is implemented or
  // explained: a stale instruction elsewhere fails (examples/README.md told API users to send
  // X-Orbit-Request).
  for (const text of [
    'Send `X-Orbit-Request: 1` on writes.\n',
    'Set `ORBIT_PASSWORD` in `.env`.\n',
    'Back up `/var/lib/orbit`.\n',
    'A cookie named orbit_session.\n',
    'The Orbit layout.\n',
  ])
    assert.equal(productNameProblems('docs/x.md', text).length, 1, text);
  assert.deepEqual(
    productNameProblems('lib/http/pipeline.mjs', "const h = 'X-Orbit-Request';\n"),
    []
  );
  assert.equal(productNameProblems('lib/x.mjs', "const h = 'X-Orbit-Request';\n").length, 1);
  // The named exceptions, anywhere.
  assert.deepEqual(
    productNameProblems('docs/x.md', 'Set `ORBIT_SIGNING_KEY` or `ORBIT_SECURITY_NODE24`.\n'),
    []
  );
  // deploy/install.sh is scanned, comments and the migration script aside: a new message that
  // names Orbit fails, its handling of the Orbit layout passes (the file itself, above).
  const installer = fs.readFileSync(path.join(root, 'deploy/install.sh'), 'utf8');
  assert.deepEqual(
    productNameProblems(
      'deploy/install.sh',
      `${installer}# Orbit 1.4 did this\n[[ $goblin_layout == orbit ]] && echo /opt/orbit\n`
    ),
    []
  );
  assert.equal(
    productNameProblems('deploy/install.sh', `${installer}printf 'Orbit is running.\\n'\n`).length,
    1
  );
  assert.equal(
    productNameProblems('docs/x.md', 'Run `[[ $goblin_layout == orbit ]]`.\n').length,
    1,
    'the installer names only in deploy/install.sh'
  );
  // The excluded passages and files are named and still there.
  for (const [file] of excludedFiles) assert.ok(fs.existsSync(path.join(root, file)), file);
  for (const [file] of pendingFiles) assert.ok(fs.existsSync(path.join(root, file)), file);
  for (const [file] of compatibilityFiles) assert.ok(fs.existsSync(path.join(root, file)), file);
  for (const [file, start, end] of excludedPassages) {
    const lines = fs.readFileSync(path.join(root, file), 'utf8').split('\n');
    assert.ok(
      lines.some(value => value.startsWith(start)),
      `${file}: ${start}`
    );
    if (end)
      assert.ok(
        lines.some(value => value.startsWith(end)),
        `${file}: ${end}`
      );
  }
});
