// The web app's files, checked without a browser: the loader every page runs (public/boot.js),
// the page template, the /app.js shim for pages from before 1.5, and the module graph under
// public/modules/ that /boot.js loads from /assets/<build>/modules/main.js. Browser behaviour is
// in ui.test.mjs (mocked API) and update.test.mjs (a real Uptime Goblin).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { moduleSpecifiers } from '../scripts/check.mjs';

const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
const read = file => fs.readFileSync(path.join(publicDir, file), 'utf8');
function walk(directory, prefix = '') {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (entry.name.startsWith('.')) return [];
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    return entry.isDirectory() ? walk(path.join(directory, entry.name), relative) : [relative];
  });
}

// Every open page, from every release since 1.5 (and older ones through /app.js), runs the
// current copy of this file, and a mistake in it leaves a page with no way to recover. Change it
// only on purpose: check it against pages from 1.4.2, 1.4.3 and each 1.5+ build (see the loader
// tests in ui.test.mjs and update.test.mjs), then update the hash here.
// Last changed (1.5 review): a page still on an older version after the two automatic reloads
// no longer waits for someone to press Reload. It checks in the background (fetch cache 'reload',
// 30 s doubling to 10 minutes, recorded in sessionStorage so a reload never restarts the
// schedule) and reloads once a check gets a current page, so a wall display behind a cache that
// briefly kept the old page opens by itself, as it did in 1.4.x.
// Changed since, copy only (the display name Uptime Goblin, e650158): the three notices' text;
// no statement, condition or timing changed (git diff 0c5b1cb -- public/boot.js).
test('the loader, /boot.js, is the reviewed one', () => {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(path.join(publicDir, 'boot.js')));
  assert.equal(
    hash.digest('hex'),
    '62d4b38131d9395d8d255da900a492c36682533a852add2968e8e362cbac74d6',
    'public/boot.js changed: review it against every older page, then update this hash'
  );
});

test('the loader loads only its page’s build and imports nothing else', () => {
  const boot = read('boot.js');
  assert.deepEqual(moduleSpecifiers(boot), []);
  assert.equal(boot.match(/import\(/g).length, 1);
  assert.ok(boot.includes('import(`/assets/${build}/modules/main.js`)'));
  // Otherwise it asks Uptime Goblin for two things only: its build's main.js (HEAD, after a failed load)
  // and, for a page stuck on an older version, the page itself past the browser's cache.
  assert.deepEqual(
    [...boot.matchAll(/fetch\(([^,]+), (\{[^}]*\})/g)].map(match => match.slice(1)),
    [
      ['location.href', "{ cache: 'reload', signal: controller.signal }"],
      ['`/assets/${build}/modules/main.js`', "{ method: 'HEAD', cache: 'no-store' }"],
    ]
  );
  // It shares the update check's reload allowance and its banner.
  const update = read('modules/update/update.js');
  assert.ok(boot.includes("'orbit-update-reloads'") && update.includes("'orbit-update-reloads'"));
  for (const id of ['update-banner', 'update-text', 'update-reload'])
    assert.ok(boot.includes(`'${id}'`), id);
});

test('index.html loads only /boot.js and the stylesheet, with no inline script', () => {
  const html = read('index.html');
  const scripts = [...html.matchAll(/<script\b[^>]*>/g)].map(match => match[0]);
  assert.deepEqual(scripts, ['<script type="module" src="/boot.js">']);
  assert.match(html, /<script type="module" src="\/boot\.js"><\/script>/);
  // Uptime Goblin adds <meta name="orbit-build"> and serves the stylesheet as /assets/<build>/style.css.
  assert.match(html, /<link rel="stylesheet" href="\/style\.css" \/>/);
  assert.doesNotMatch(html, /orbit-build|\/app\.js|\/modules\//);
  // /boot.js explains a failed load in the update banner.
  for (const id of ['update-banner', 'update-text', 'update-reload'])
    assert.match(html, new RegExp(`id="${id}"`));
});

test('/app.js only hands a page from before 1.5 to the loader', () => {
  const shim = read('app.js');
  assert.deepEqual(moduleSpecifiers(shim), ['./boot.js']);
  assert.equal(
    shim
      .split('\n')
      .filter(line => line && !line.startsWith('//'))
      .join('\n'),
    "import './boot.js';"
  );
});

test('every module is reached from main.js by relative imports that stay in its build', () => {
  const modules = walk(path.join(publicDir, 'modules')).map(file => `modules/${file}`);
  assert.ok(modules.length > 1, 'the web app is split into modules');
  for (const file of modules) assert.ok(file.endsWith('.js'), `${file} is a module`);
  const reached = new Set(),
    queue = ['modules/main.js'];
  while (queue.length) {
    const file = queue.shift();
    if (reached.has(file)) continue;
    reached.add(file);
    const source = read(file);
    // A module loaded from /assets/<build>/ that named a root path (/x.js) or another origin
    // would load a file of whatever build that path serves, mixing two releases in one page.
    assert.doesNotMatch(source, /\bimport\s*\(/, `${file}: no dynamic import`);
    for (const specifier of moduleSpecifiers(source)) {
      assert.match(specifier, /^\.\.?\//, `${file} imports ${specifier} relatively`);
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
      assert.ok(
        target.startsWith('modules/') || target.startsWith('shared/'),
        `${file} imports ${target}, outside the web app`
      );
      assert.ok(fs.existsSync(path.join(publicDir, target)), `${file} imports missing ${target}`);
      queue.push(target);
    }
  }
  for (const file of modules) assert.ok(reached.has(file), `${file} is not imported by anything`);
  assert.ok(reached.has('shared/timezone.js'));
  assert.ok(reached.has('modules/configure/audit.js'));
});

test('every web app module passes node --check', () => {
  const files = [
    'boot.js',
    'app.js',
    ...walk(path.join(publicDir, 'modules')).map(f => `modules/${f}`),
  ];
  for (const file of files) {
    const result = spawnSync(process.execPath, ['--check', path.join(publicDir, file)], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, `${file}: ${result.stderr}`);
  }
});

test('main.js installs every module’s event handlers once', () => {
  const main = read('modules/main.js');
  const withInstall = walk(path.join(publicDir, 'modules'))
    .filter(file => /^export function install\(\)/m.test(read(`modules/${file}`)))
    .map(file => `./${file}`)
    .sort();
  // Each `install as <name>` inside an import's braces, which Prettier may spread over lines.
  const imported = [...main.matchAll(/^import \{([^}]*)\} from '([^']+)';$/gm)].flatMap(
    ([, names, from]) => {
      const name = /\binstall as (\w+)\b/.exec(names)?.[1];
      return name ? [[name, from]] : [];
    }
  );
  assert.deepEqual(imported.map(([, from]) => from).sort(), withInstall);
  // 1.5: Configure → Notifications has handlers of its own (its actions and dialogs), and so has
  // Configure → Audit log (its filters, Load more, details, Check integrity and exports).
  assert.ok(withInstall.includes('./configure/notifications.js'));
  assert.ok(withInstall.includes('./configure/audit.js'));
  for (const [name] of imported)
    assert.equal(main.match(new RegExp(`^${name}\\(\\);$`, 'gm'))?.length, 1, name);
});

// The Help page's renderer runs in Node too: it needs only the escaping helper.
test('the Help page’s Markdown renderer escapes what it does not render', async () => {
  const { renderMarkdown } = await import('../public/modules/docs/markdown.js');
  const html = renderMarkdown(
    [
      '# Title',
      '## Setup <script>alert(1)</script>',
      'See [Security](security.md), [a site](https://example.com/a?b=1&c=2), [bad](javascript:alert(1)) and [creds](https://u:p@example.com).',
      'Also [Notifications](notifications.md#the-webhook).',
      '',
      '- **bold** `a<b`',
      '1. first',
      '',
      '| Key | Value |',
      '| --- | --- |',
      '| a | <b> |',
      '```',
      '<tag> & "quote"',
      '```',
    ].join('\n')
  );
  assert.ok(!html.includes('<script>'), 'raw HTML is escaped');
  assert.ok(html.includes('<h3>Setup &lt;script&gt;alert(1)&lt;/script&gt;</h3>'));
  assert.ok(!html.includes('Title'), 'the page title heading is dropped');
  assert.ok(html.includes('<button class="doc-inline-link" type="button" data-doc="security">'));
  // 1.5: the alerts and notifications guide is one of the bundled guides.
  assert.ok(
    html.includes('<button class="doc-inline-link" type="button" data-doc="notifications">')
  );
  assert.ok(
    html.includes(
      '<a href="https://example.com/a?b=1&amp;c=2" target="_blank" rel="noopener noreferrer">a site</a>'
    )
  );
  assert.ok(!html.includes('javascript:') && html.includes('bad'), 'unsafe links become text');
  assert.ok(!html.includes('u:p@'), 'links with credentials become text');
  assert.ok(html.includes('<li><strong>bold</strong> <code>a&lt;b</code></li>'));
  assert.ok(html.includes('<ol><li>first</li></ol>'));
  assert.ok(html.includes('<td>&lt;b&gt;</td>'));
  assert.ok(html.includes('<pre><code>&lt;tag&gt; &amp; &quot;quote&quot;</code></pre>'));
});

// A small reader of the editors' source, enough for their field() calls: strings and template
// literals (with their ${…}) are skipped, so a bracket or comma in a hint ends nothing.
const closers = { '(': ')', '[': ']', '{': '}' };
function pastQuoted(source, at) {
  const quote = source[at];
  let i = at + 1;
  while (source[i] !== quote) {
    if (i >= source.length) throw new Error(`Unterminated string at ${at}`);
    if (source[i] === '\\') i += 2;
    else if (quote === '`' && source.startsWith('${', i)) i = matching(source, i + 2, '}') + 1;
    else i++;
  }
  return i + 1;
}
/** The index of the `close` that ends what was opened just before `at`. */
function matching(source, at, close) {
  const expected = [close];
  for (let i = at; i < source.length; ) {
    const c = source[i];
    if (c === "'" || c === '"' || c === '`') {
      i = pastQuoted(source, i);
      continue;
    }
    if (closers[c]) expected.push(closers[c]);
    else if (c === expected.at(-1)) {
      expected.pop();
      if (!expected.length) return i;
    }
    i++;
  }
  throw new Error(`Nothing closes what opens at ${at}`);
}
/** `text` split at each `separator` outside strings and brackets. */
function topLevel(text, separator = ',') {
  const parts = [];
  let depth = 0,
    start = 0;
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (c === "'" || c === '"' || c === '`') {
      i = pastQuoted(text, i);
      continue;
    }
    if (closers[c]) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === separator && !depth) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
    i++;
  }
  parts.push(text.slice(start).trim());
  return parts.filter(Boolean);
}
/**
 * Every input of `file`: its field() calls as {id, options} (an id built as 'prefix-' + key is
 * 'prefix-*'; options are the source text of each property) and its own <input> and <textarea>
 * tags as {id, options: {type, maxLength}}.
 */
function editorInputs(file) {
  const source = read(file),
    inputs = [];
  for (const match of source.matchAll(/(?<![\w$.])field\(/g)) {
    const open = match.index + match[0].length;
    const [id, , , options = '{}'] = topLevel(source.slice(open, matching(source, open, ')')));
    const literal = /^'([\w-]+)'(?: \+ \w+)?$/.exec(id);
    assert.ok(literal, `${file}: field(${id}, …)`);
    const properties = topLevel(options.slice(1, -1)).map(property => {
      const at = property.indexOf(':');
      return at < 0
        ? [property, property]
        : [property.slice(0, at).trim(), property.slice(at + 1).trim()];
    });
    inputs.push({
      file,
      id: literal[1] + (id.includes('+') ? '*' : ''),
      options: Object.fromEntries(properties),
    });
  }
  for (const [, , attributes] of source.matchAll(/<(input|textarea)\b([^>]*)>/g)) {
    const attribute = name => new RegExp(`\\b${name}="([^"]*)"`).exec(attributes)?.[1];
    inputs.push({
      file,
      id: attribute('id') ?? attribute('name'),
      options: { type: attribute('type'), maxLength: attribute('maxlength') },
    });
  }
  return inputs;
}

test('every input of the settings and source editors takes what the server takes, and no more', async () => {
  const { ConfigStore, validateEmail, validateService } = await import('../lib/config.mjs');
  const { defaults, newService } = await import('../lib/catalog.mjs');
  const settings = value =>
    ConfigStore.prototype.globalCandidate.call(ConfigStore.prototype, value, defaults());
  const source = (type, value) => validateService(value, newService(type));
  const rule = value =>
    source('linux', { rules: [{ key: 'cpu', operator: 'gt', threshold: 1, ...value }] });
  const chars = n => 'a'.repeat(n);
  const url = n => 'https://example.test/' + chars(n - 21);
  // Labels of at most 63 characters, n characters in all.
  const hostname = n => {
    let name = chars(Math.min(63, n));
    while (name.length < n) name += '.' + chars(Math.min(63, n - name.length - 1));
    return name;
  };
  // Text fields: whether the server accepts a value of `n` characters (one that is valid
  // otherwise, so only the length can refuse it).
  const lengths = {
    'workspace-title': n => settings({ title: chars(n) }),
    'workspace-subtitle': n => settings({ subtitle: chars(n) }),
    'appearance-timezone': n => settings({ appearance: { timezone: 'UTC'.padEnd(n) } }),
    'source-name': n => source('link', { name: chars(n) }),
    'source-group': n => source('link', { group: chars(n) }),
    'source-url': n => source('link', { url: url(n) }),
    'source-api': n => source('linux', { apiUrl: url(n) }),
    'source-http-status': n => source('http', { httpExpectedStatus: '200'.padEnd(n) }),
    'source-node': n => source('proxmox', { nodeName: chars(n) }),
    'metric-path': n => source('prometheus', { metricPath: '/' + chars(n - 1) }),
    'site-id': n => source('unifi', { siteId: chars(n) }),
    'source-username': n => source('unifi', { username: chars(n) }),
    'source-password': n => source('unifi', { password: chars(n) }),
    'source-key': n => source('unifi', { apiKey: chars(n) }),
    'rule-key': n => rule({ key: chars(n) }),
    'email-from': n => validateEmail({ from: chars(n - 12) + '@example.com' }),
    'email-to': n => validateEmail({ to: chars(n - 12) + '@example.com' }),
    'email-password': n => validateEmail({ password: chars(n) }),
    'email-host': n => validateEmail({ host: hostname(n) }),
  };
  // Number fields: whether the server accepts `value`.
  const monitoring = key => value => settings({ monitoring: { [key]: value } });
  const ranges = {
    'source-poll': value => source('linux', { pollSeconds: value }),
    'rule-duration': value => rule({ forSeconds: value }),
    'poll-seconds': value => settings({ pollSeconds: value }),
    'retention-days': value => settings({ retentionDays: value }),
    'monitoring-timeout': monitoring('timeoutSeconds'),
    'monitoring-concurrency': monitoring('concurrency'),
    'monitoring-retries': monitoring('retryCount'),
    'monitoring-retry-delay': monitoring('retryDelaySeconds'),
    'availability-failures': monitoring('availabilityFailures'),
    'availability-seconds': monitoring('availabilitySeconds'),
    'recovery-successes': monitoring('recoverySuccesses'),
    'recovery-seconds': monitoring('recoverySeconds'),
    'email-port': value => validateEmail({ port: value }),
    // One per row of drawer.js's monitoringFields, checked below.
    'source-monitoring-*': null,
  };
  // Nothing to limit: switches and the accent choice, the source list's search (never sent),
  // the mappings' JSON (each mapping's fields have their own limits, the request its size), and
  // a rule's threshold and recovery boundary (any finite number).
  const free = [
    'source-enabled',
    'source-visible',
    'clear-credentials',
    'email-enabled',
    'email-clear-password',
    'appearance-accent',
    'source-search',
    'metric-mappings',
    'rule-threshold',
    'rule-recovery',
  ];
  const inputs = [
    'modules/drawer/drawer.js',
    'modules/configure/pages.js',
    'modules/configure/email.js',
  ].flatMap(editorInputs);
  // Every input is one of the three kinds, and every one named here is still there.
  assert.deepEqual(
    [...new Set(inputs.map(input => input.id))].sort(),
    [...Object.keys(lengths), ...Object.keys(ranges), ...free].sort()
  );
  // A limit the editor lets you type up to is one the server accepts, and not one more: a
  // larger one shows the server's refusal only after Save.
  for (const { file, id, options } of inputs.filter(input => input.id in lengths)) {
    const maxLength = Number(options.maxLength);
    assert.ok(Number.isInteger(maxLength), `${file}: ${id} declares no maxLength`);
    assert.doesNotThrow(() => lengths[id](maxLength), `${id}: ${maxLength} characters`);
    assert.throws(() => lengths[id](maxLength + 1), `${id}: ${maxLength + 1} characters`);
  }
  const range = (id, accepts, min, max) => {
    for (const value of [min, max]) assert.doesNotThrow(() => accepts(value), `${id}: ${value}`);
    for (const value of [min - 1, max + 1]) assert.throws(() => accepts(value), `${id}: ${value}`);
  };
  for (const { file, id, options } of inputs.filter(input => input.id in ranges)) {
    assert.equal(options.type, "'number'", `${file}: ${id}`);
    if (id === 'source-monitoring-*') continue;
    range(id, ranges[id], Number(options.min), Number(options.max));
  }
  // The source's own retry and confirmation overrides take their limits from this table.
  const drawer = read('modules/drawer/drawer.js');
  const table = drawer.indexOf('[', drawer.indexOf('const monitoringFields = ')) + 1;
  const rows = topLevel(drawer.slice(table, matching(drawer, table, ']'))).map(row =>
    topLevel(row.slice(1, -1))
  );
  assert.equal(rows.length, 7);
  for (const [key, , min, max] of rows) {
    const name = key.slice(1, -1);
    range(
      name,
      value => source('linux', { monitoring: { [name]: value } }),
      Number(min),
      Number(max)
    );
  }
});
