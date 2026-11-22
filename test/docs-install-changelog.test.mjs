// The installation docs, the README and the CHANGELOG against the code they describe (1.5 docs
// audit, area "install-changelog", and the docs parts of release blockers B11, B12 and B14). Each
// test reads the texts and the code or command that decides the behaviour, so a change to either
// that makes the docs wrong fails here.
import { currentNames, isDeploymentFile } from './helpers/deployed-names.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.mjs';
import { sessionCall, signIn } from './helpers/session.mjs';
import { readRun } from './helpers/docker-limits.mjs';
import {
  composeFlags,
  composeValues,
  dockerProblems,
  noContainer,
  serviceProblems,
} from './helpers/docker-guard.mjs';
import { checkDestination, configureDestinations, embeddedIPv4 } from '../lib/destinations.mjs';
import { launchUrl, withoutCredentials } from '../lib/config.mjs';
import { trustedProxies } from '../lib/throttle.mjs';
import { allowedHostList, listenHost, listenPort } from '../lib/environment.mjs';
import { basicDeprecation, requestId, requestIdPattern } from '../lib/http/pipeline.mjs';
import { createStartupHandler } from '../lib/http/startup.mjs';
import { CSV_HEADER } from '../lib/audit/export.mjs';
import { notificationRoutes } from '../lib/http/routes/notifications.mjs';
import { auditRoutes } from '../lib/http/routes/audit.mjs';
import { authRoutes } from '../lib/http/routes/auth.mjs';
import { accountRoutes } from '../lib/http/routes/account.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
// Deployment files with their names from before the rename read as the current ones
// (test/helpers/deployed-names.mjs).
const read = file => {
  const text = fs.readFileSync(path.join(repository, file), 'utf8');
  return isDeploymentFile(file) ? currentNames(text) : text;
};
// What a reader sees of a Markdown paragraph: runs of blanks as one space.
const flat = text => text.replace(/\s+/g, ' ').trim();
const release = JSON.parse(read('package.json')).version;
// A `## heading` (or deeper) section of a Markdown file, up to the next heading of that level.
function section(text, heading, level = 2) {
  const marks = '#'.repeat(level);
  const start = text.indexOf(`\n${marks} ${heading}\n`);
  assert.notEqual(start, -1, `section "${heading}"`);
  const end = text.indexOf(`\n${marks} `, start + 1);
  return text.slice(start, end === -1 ? undefined : end);
}
// The CHANGELOG's two unreleased sections: 1.5.0, and the 1.4.x maintenance candidate below it.
const maintenanceHeading = '## Unreleased — 1.4.x maintenance candidate (also in 1.5)';
function changelog() {
  const text = read('CHANGELOG.md');
  const start = text.indexOf('\n## Unreleased — 1.5.0 '),
    middle = text.indexOf(`\n${maintenanceHeading}\n`),
    end = text.indexOf('\n## 1.4.3 ');
  assert.ok(start !== -1 && start < middle && middle < end, 'the two unreleased sections');
  return { release: text.slice(start, middle), maintenance: text.slice(middle, end) };
}
// The shell blocks of a Markdown file.
const shellBlocks = text => [...text.matchAll(/```sh\n([\s\S]*?)```/g)].map(match => match[1]);
// The upgrade notes of the 1.5 section, one bullet each.
const upgradeNotes = () =>
  changelog()
    .release.split('**Upgrade notes (1.4.x → 1.5):**')[1]
    .split('\n')
    .filter(line => line.startsWith('- '));
// Other upgrade notes may precede this one; keep the proxy contract tied to its named note.
const proxyUpgradeNote = () => {
  const note = upgradeNotes().find(line =>
    line.startsWith('- **Check `GOBLIN_TRUST_PROXY` first.**')
  );
  assert.ok(note, 'the named GOBLIN_TRUST_PROXY upgrade note');
  return note;
};

test('docs: Docker builds pull the base image (B14), and no guide still builds without --pull', () => {
  const [, base, digest] = /^FROM ([^\s@]+)@(sha256:[0-9a-f]{64})$/m.exec(read('Dockerfile'));
  assert.equal(base, 'node:24-bookworm-slim');
  assert.ok(digest);
  const installation = read('docs/installation.md');
  // The first build, in the Docker Compose section.
  const compose = section(installation, 'Docker Compose');
  assert.ok(compose.includes('```sh\ndocker compose build --pull\ndocker compose up -d\n```'));
  assert.ok(
    flat(compose).includes(
      `The Dockerfile pins its \`${base}\` base image by digest, so every build uses exactly that image`
    )
  );
  // The update step and the 1.5 upgrade.
  const updates = flat(section(installation, 'Updates and rollback'));
  assert.ok(updates.includes('For Docker, build first with `docker compose build --pull`'));
  assert.ok(
    flat(section(installation, 'Upgrading to 1.5', 3)).includes(
      'Build the 1.5 image with `docker compose build --pull`'
    )
  );
  assert.ok(
    flat(section(read('docs/security.md'), 'Maintenance')).includes(
      `Rebuild the image with \`docker compose build --pull\` at each update: the Dockerfile pins \`${base}\` by digest`
    )
  );
  assert.ok(
    upgradeNotes().some(
      note =>
        note.startsWith('- **Docker: keep the 1.4.3 image, and build with `--pull`.**') &&
        note.includes('then build with `docker compose build --pull`') &&
        note.includes(`1.5's pins the image by digest, so every build of it uses the same one`)
    )
  );
  // With the base pinned, --pull fetches no newer base image: no guide, note or comment says it
  // does (installation.md said "so that the base image is the newest one" three times, and the
  // upgrade note that a plain build missed "newer security fixes", after the pin).
  for (const file of [
    'README.md',
    'docs/installation.md',
    'docs/security.md',
    'compose.secret.yaml',
  ])
    assert.doesNotMatch(
      flat(read(file)),
      /base image is the newest one|without its newer security fixes|uses what(ever)? the Docker host already holds/,
      file
    );
  assert.ok(
    !upgradeNotes().some(note => /already on the host, without its newer security fixes/.test(note))
  );
  // No command a reader pastes builds without --pull. (The 1.4.3 and older release notes are a
  // record of their releases and stay as they were.)
  for (const file of ['README.md', 'docs/installation.md', 'docs/security.md']) {
    for (const block of shellBlocks(read(file))) {
      assert.doesNotMatch(block, /up -d --build/, file);
      for (const line of block.split('\n').filter(line => /docker compose build/.test(line)))
        assert.match(line, /--pull/, `${file}: ${line}`);
    }
  }
  assert.match(
    read('compose.secret.yaml'),
    /With the 1\.5 image built \(docker compose build\n# --pull\)/
  );
});

test('docs: Docker keeps the image it upgrades from under its own version, as the rollback re-tags it', () => {
  const installation = read('docs/installation.md');
  const keep = 'docker image tag orbit-homelab:local orbit-homelab:1.4.3';
  assert.ok(
    flat(section(installation, 'Updates and rollback')).includes(
      `\`${keep}\` before the upgrade from Orbit 1.4.3`
    )
  );
  assert.doesNotMatch(installation, /docker image tag orbit-homelab:local orbit-homelab:1\.4\.2/);
  assert.ok(flat(section(installation, 'Upgrading to 1.5', 3)).includes(`\`${keep}\``));
  assert.ok(upgradeNotes().some(note => note.includes(`\`${keep}\``)));
  // The rollback names what was kept, and runs it with the documented override (a re-tag alone
  // would start 1.4.3 without its settings and data: test/installer/docker.test.mjs runs it).
  const rollback = flat(section(installation, 'Rolling back 1.5 to 1.4.3', 3));
  assert.ok(
    rollback.includes(
      're-tagging the 1.4.3 image under the 1.5 file alone would start 1.4.3 without your settings and data'
    )
  );
  assert.ok(rollback.includes('runs the 1.4.3 image you kept (`orbit-homelab:1.4.3`'));
  assert.ok(rollback.includes('image: orbit-homelab:1.4.3'));
});

test('docs: the kept 1.5 image restores a snapshot with the restrictions compose.yaml gives Orbit, and its key', () => {
  const compose = read('compose.yaml');
  // The key file compose.secret.yaml gives Uptime Goblin as its Compose secret, mounted where the secret
  // is (review F2v2, round 4: the restore checks the keyring it brings back with that key).
  const secret = read('compose.secret.yaml');
  assert.match(secret, /^secrets:\n {2}orbit_secret_key:\n {4}file: \.\/orbit_secret_key$/m);
  // Each flag of the documented line, from the compose.yaml key it repeats.
  const user = /^ {4}user: '(\d+:\d+)'$/m.exec(compose)?.[1];
  assert.ok(user, 'compose.yaml names the user');
  assert.match(compose, /^ {4}read_only: true$/m);
  const tmpfs = /^ {6}- (\/tmp:size=\d+m,mode=1777)$/m.exec(compose)?.[1];
  assert.ok(tmpfs, 'compose.yaml mounts /tmp in memory');
  assert.match(compose, /^ {6}- no-new-privileges:true$/m);
  assert.match(compose, /cap_drop:\n {6}- ALL$/m);
  const limit = key => new RegExp(`^ {4}${key}: ([0-9][0-9a-z.]*)$`, 'm').exec(compose)?.[1];
  const memory = limit('mem_limit'),
    cpus = limit('cpus'),
    pids = limit('pids_limit');
  assert.ok(memory && cpus && pids, 'compose.yaml limits memory, CPUs and processes');
  assert.equal(limit('memswap_limit'), memory, 'no swap on top');
  const nofile = /^ {6}nofile:\n {8}soft: (\d+)\n {8}hard: \1$/m.exec(compose)?.[1];
  assert.ok(nofile, 'compose.yaml limits open files');
  assert.match(compose, /^ {6}core: 0$/m);
  const line = shellBlocks(read('docs/installation.md'))
    .flatMap(block => block.split('\n'))
    .find(text => text.startsWith('docker run ') && text.includes('restore-snapshot'));
  assert.ok(line, 'the documented docker run line');
  assert.equal(
    line,
    `docker run --memory ${memory} --cpus ${cpus} --pids-limit ${pids} --memory-swap ${memory} --pull=never --rm --user ${user} --read-only --tmpfs ${tmpfs} --cap-drop ALL --security-opt no-new-privileges:true --ulimit nofile=${nofile}:${nofile} --ulimit core=0 --network none -v PROJECT_orbit-data:/var/lib/uptime-goblin --mount type=bind,source="$PWD/orbit_secret_key",target=/run/secrets/orbit_secret_key,readonly uptime-goblin:1.5.0 node lib/cli/goblin-admin.mjs restore-snapshot SNAPSHOT_ID`
  );
});

// B39: every docker command the documents give that makes a container has finite memory, CPU and
// process limits (the maintainer's rule for 1.5), as test/docker-limits.test.mjs holds the tests to it.
// dockerDocumentProblems reads every Markdown file outside test/ and node_modules/ (the README,
// CONTRIBUTING, the CHANGELOG, docs/…) in its code: each line of a fenced block (one ending in a
// backslash goes on in the next, as in sh) and each inline code span. It also reads the comments
// of the Compose files and .env.example, where a line that starts with '#' and three blanks is a
// command. It splits each as sh does (quotes and backslashes read, $(…) and backquotes kept whole
// and read again inside, operators and redirections apart) and checks each docker in it:
// - `docker run` and `docker create` (also `container run|create`) give finite --memory, --cpus
//   and --pids-limit right after the subcommand and none again before the image (the guard's
//   dockerProblems, through runLimitProblems of test/helpers/docker-limits.mjs; it also refuses
//   docker update, swarm services and a builder container); give --pull=never before the image,
//   since every image the documents run is local (a tag a build or `docker image tag` made, or one
//   pinned by digest) and Docker would look for a missing one on Docker Hub; and give no more than
//   the 1 GiB, 2 CPUs and 256 processes most test containers get, unless `larger` lists the
//   command with the reason;
// - a Compose command that can make a container (any the guard does not know to make none) reads
//   no file but compose.yaml, compose.secret.yaml and compose.override.yaml, by -f or
//   COMPOSE_FILE: `docker compose run` takes no limit options, and its container has the
//   service's limits. compose.yaml gives each service finite mem_limit, cpus and pids_limit, and
//   compose.secret.yaml and each compose.override.yaml the documents show keep them finite, alone
//   and together (the guard's serviceProblems), and add no service;
// - prose (outside code) gives no `docker run` or `docker create` with an option after it: a
//   command is written as code, where this check reads it.
// A bare name (`docker run`, `docker compose run`) is no command. Other code that is not one is
// listed in `mentions` with the reason. An entry of either list that matches nothing fails.
const composeFileNames = ['compose.yaml', 'compose.secret.yaml', 'compose.override.yaml'];
const standardLimits = { memory: 1024 ** 3, cpus: 2, pids: 256 };
// docker or docker-compose, by name or by a path, in any case (macOS finds it so).
const dockerCommandWord = /^(?:.*[\\/])?docker(?:-compose)?(?:\.exe)?$/i;
const bareDockerNames = new Set([
  '',
  'run',
  'create',
  'container run',
  'container create',
  'update',
  'service',
  'stack',
  'buildx create',
  'builder create',
]);
const dockerMentions = [
  {
    file: 'docs/configuration.md',
    code: 'docker run --env',
    why: 'names the option that leaves GOBLIN_SECRET_KEY visible in docker inspect; no command',
  },
];
const largerContainers = [
  {
    file: 'docs/engineering-quality.md',
    limits: '--memory 4g --cpus 4 --pids-limit 1024',
    most: { memory: 4 * 1024 ** 3, cpus: 4, pids: 1024 },
    why: "the normative audit capacity run measures wall time in the Node 24 gate's container, with its limits (sessions spec §12 item 3)",
  },
];

// The index just after the bracket that closes the one at line[at] ('(' or '{'), past quotes and
// brackets nested in it; the line's length when none does.
function closingBracket(line, at) {
  const open = line[at],
    close = open === '(' ? ')' : '}';
  let depth = 0;
  for (let i = at; i < line.length; i++) {
    const c = line[i];
    if (c === '\\') i++;
    else if (c === "'")
      i = line.indexOf("'", i + 1) === -1 ? line.length : line.indexOf("'", i + 1);
    else if (c === '"') i = doubleQuoteEnd(line, i);
    else if (c === open) depth++;
    else if (c === close && --depth === 0) return i + 1;
  }
  return line.length;
}
// The index of the quote that ends the double-quoted text opening at line[at].
function doubleQuoteEnd(line, at) {
  for (let i = at + 1; i < line.length; i++) {
    if (line[i] === '\\') i++;
    else if (line[i] === '$' && line[i + 1] === '(') i = closingBracket(line, i + 1) - 1;
    else if (line[i] === '"') return i;
  }
  return line.length;
}

// A shell line's words as sh splits them, [{text, inner}], and its operators, [{operator}] (also
// a redirection: its target is the next word). Quotes and backslashes are read; $(…), ${…} and
// `…` stay whole in their word, and `inner` holds the text inside each quote and substitution of
// the word, which can run docker too (sh -c '…', $(…)).
function shellWords(line) {
  const words = [];
  let i = 0;
  while (i < line.length) {
    if (/\s/.test(line[i])) {
      i++;
      continue;
    }
    if (line[i] === '#') break;
    const operator = /^(?:&&|\|\||;;|&>>?|\d*(?:>>|>\||>&|<&|<<<|<<|<>|>|<)|[;&|()])/.exec(
      line.slice(i)
    );
    if (operator) {
      words.push({ operator: operator[0] });
      i += operator[0].length;
      continue;
    }
    let text = '';
    const inner = [];
    while (i < line.length && !/[\s;&|()<>]/.test(line[i])) {
      const c = line[i];
      if (c === '\\') {
        text += line[i + 1] ?? '';
        i += 2;
      } else if (c === "'") {
        const end = line.indexOf("'", i + 1) === -1 ? line.length : line.indexOf("'", i + 1);
        text += line.slice(i + 1, end);
        inner.push(line.slice(i + 1, end));
        i = end + 1;
      } else if (c === '"') {
        const end = doubleQuoteEnd(line, i);
        const body = line.slice(i + 1, end).replace(/\\([\\"$`])/g, '$1');
        text += body;
        inner.push(body);
        i = end + 1;
      } else if (c === '`') {
        const end = line.indexOf('`', i + 1) === -1 ? line.length : line.indexOf('`', i + 1);
        text += line.slice(i, end + 1);
        inner.push(line.slice(i + 1, end));
        i = end + 1;
      } else if (c === '$' && (line[i + 1] === '(' || line[i + 1] === '{')) {
        const end = closingBracket(line, i + 1);
        text += line.slice(i, end);
        inner.push(line.slice(i + 2, end - 1));
        i = end;
      } else {
        text += c;
        i++;
      }
    }
    words.push({ text, inner });
  }
  return words;
}

// Each docker a shell line runs: [{name, words, environment}], with `words` its words up to the
// end of its command (redirections left out) and `environment` the assignments before it. Text
// inside quotes or a substitution is read the same way.
function dockerInvocations(line) {
  const found = [];
  const words = shellWords(line);
  for (const [k, word] of words.entries()) {
    if (word.operator !== undefined) continue;
    for (const text of word.inner) if (/docker/i.test(text)) found.push(...dockerInvocations(text));
    if (!dockerCommandWord.test(word.text)) continue;
    const after = [];
    for (let j = k + 1; j < words.length; j++) {
      const operator = words[j].operator;
      if (operator === undefined) after.push(words[j]);
      else if (/[<>]/.test(operator)) j++;
      else break;
    }
    const environment = [];
    for (let j = k - 1; j >= 0 && words[j].operator === undefined; j--)
      if (/^[A-Za-z_]\w*=/.test(words[j].text)) environment.unshift(words[j].text);
    found.push({ name: word.text, words: after, environment });
  }
  return found;
}

// What is wrong with a documented Compose command: `words`, its words after `docker compose` (or
// docker-compose), and `environment`, the assignments before it. Compose's options are read as
// the guard reads them; a command substitution among them gives the words it echoes.
function composeCommandProblems(words, environment) {
  const files = [];
  for (const assignment of environment) {
    const name = assignment.slice(0, assignment.indexOf('='));
    if (name === 'COMPOSE_FILE') files.push(...assignment.slice(name.length + 1).split(/[:;]/));
    else if (name.startsWith('COMPOSE_'))
      return [`it is given ${name}, which can make Compose read other files`];
  }
  const read = words.flatMap(word => {
    const substitution = /^\$\(([\s\S]*)\)$/.exec(word.text);
    if (!substitution) return [word.text];
    const inner = shellWords(substitution[1]);
    const echo = inner.findIndex(item => item.text === 'echo');
    if (echo === -1) return [word.text];
    const echoed = [];
    for (const item of inner.slice(echo + 1)) {
      if (item.operator !== undefined) break;
      echoed.push(...item.text.split(/\s+/).filter(Boolean));
    }
    return echoed;
  });
  let k = 0;
  for (; k < read.length && read[k].startsWith('-'); k++) {
    const word = read[k];
    const equals = word.startsWith('--') ? word.indexOf('=') : -1;
    const name = equals > 0 ? word.slice(0, equals) : word;
    const attached = /^-[fp]./.test(word);
    if (composeFlags.has(name) && equals < 0) continue;
    let value;
    if (attached) value = word.slice(2).replace(/^=/, '');
    else if (composeValues.has(name) && equals > 0) value = word.slice(equals + 1);
    else if (composeValues.has(name)) value = read[++k];
    else return [`the Compose option ${word} is not known to this check`];
    if (value === undefined) return [`the Compose option ${word} has no value`];
    const option = attached ? word.slice(0, 2) : name;
    if (option === '-f' || option === '--file') files.push(value);
    else if (option === '--project-directory' || option === '--env-file')
      return [`it is given ${option}, which can make Compose read other files`];
  }
  const subcommand = read[k];
  if (subcommand === undefined || noContainer.has(subcommand)) return [];
  if (/[$`]/.test(subcommand)) return [`its subcommand (${subcommand}) cannot be read`];
  const others = files.filter(file => !composeFileNames.includes(file));
  return others.length
    ? [
        `docker compose ${subcommand} reads ${others.join(', ')}, whose limits this check does not read`,
      ]
    : [];
}

// What is wrong with one documented docker command (dockerInvocations) in `file`. Marks the entry
// of `larger` it takes in `used`.
function dockerCommandProblems({ name, words, environment }, file, larger, used) {
  const texts = words.map(word => word.text);
  if (/compose(?:\.exe)?$/i.test(name)) return composeCommandProblems(words, environment);
  if (texts[0] === 'compose') return composeCommandProblems(words.slice(1), environment);
  if (bareDockerNames.has(texts.join(' '))) return [];
  const problems = dockerProblems(texts);
  const at = texts[0] === 'container' ? 1 : 0;
  const subcommand = texts[at];
  if (problems.length || (subcommand !== 'run' && subcommand !== 'create')) return problems;
  const { limits, options, image } = readRun(texts.slice(at + 1));
  const pulls = options.flatMap((word, k) => {
    if (word === '--pull') return [options[k + 1]];
    return word.startsWith('--pull=') ? [word.slice('--pull='.length)] : [];
  });
  if (!pulls.length || pulls.some(value => value !== 'never'))
    problems.push(
      `docker ${subcommand} without --pull=never before the image: Docker would look for a missing ${image ?? 'image'} on Docker Hub`
    );
  const above = Object.keys(standardLimits).filter(kind => limits[kind] > standardLimits[kind]);
  if (above.length) {
    const entry = larger.find(item => item.file === file && texts.join(' ').includes(item.limits));
    if (!entry)
      problems.push(
        `docker ${subcommand} gives more ${above.join(', ')} than the 1 GiB, 2 CPUs and 256 processes most test containers get, and larger lists no reason`
      );
    else {
      used.add(entry);
      const over = above.filter(kind => limits[kind] > entry.most[kind]);
      if (over.length)
        problems.push(`docker ${subcommand} gives more ${over.join(', ')} than larger allows it`);
    }
  }
  return problems;
}

// Lines as sh reads them: one ending in a backslash goes on in the next. [{index, text}].
function shellLines(lines) {
  const joined = [];
  for (let index = 0; index < lines.length; index++) {
    const first = index;
    let text = lines[index];
    while (/\\$/.test(text) && index + 1 < lines.length) text = text.slice(0, -1) + lines[++index];
    joined.push({ index: first, text });
  }
  return joined;
}

// A Markdown file's code and prose: `code`, [{line, text}], each line of a fenced block (shellLines)
// and each inline code span; `fences`, [{line, text}], each fenced block; `prose`, [{line, text}],
// each paragraph with its code spans blanked.
function markdownParts(text) {
  const code = [],
    fences = [],
    prose = [];
  const lines = text.split('\n');
  let paragraph = [];
  const flush = () => {
    if (!paragraph.length) return;
    const joined = paragraph.map(item => item.text).join('\n');
    const lineAt = offset =>
      paragraph[0].line + (joined.slice(0, offset).match(/\n/g)?.length ?? 0);
    let blanked = '';
    for (let i = 0; i < joined.length; ) {
      if (joined[i] !== '`') {
        blanked += joined[i++];
        continue;
      }
      const run = /^`+/.exec(joined.slice(i))[0];
      const closing = new RegExp('(?<!`)' + run + '(?!`)', 'g');
      closing.lastIndex = i + run.length;
      const match = closing.exec(joined);
      if (!match) {
        blanked += run;
        i += run.length;
        continue;
      }
      code.push({
        line: lineAt(i),
        text: joined
          .slice(i + run.length, match.index)
          .replace(/\n/g, ' ')
          .trim(),
      });
      blanked += ' ';
      i = match.index + run.length;
    }
    prose.push({ line: paragraph[0].line, text: blanked });
    paragraph = [];
  };
  for (let index = 0; index < lines.length; index++) {
    const open = /^\s*(`{3,}|~{3,})/.exec(lines[index]);
    if (open) {
      flush();
      const first = index + 2;
      const close = new RegExp(`^\\s*${open[1][0]}{${open[1].length},}\\s*$`);
      const body = [];
      while (++index < lines.length && !close.test(lines[index])) body.push(lines[index]);
      fences.push({ line: first, text: body.join('\n') });
      for (const item of shellLines(body)) code.push({ line: first + item.index, text: item.text });
    } else if (!lines[index].trim()) flush();
    else paragraph.push({ line: index + 1, text: lines[index] });
  }
  flush();
  return { code, fences, prose };
}

// The comment lines of a Compose file or .env.example: [{line, text, command}], a command where
// '#' is followed by three blanks (as compose.secret.yaml says), its text after them.
function commentParts(text) {
  const lines = text.split('\n');
  const comments = [];
  for (let index = 0; index < lines.length; index++) {
    const comment = /^\s*#(.*)$/.exec(lines[index]);
    if (!comment) continue;
    const command = /^ {3}/.test(comment[1]);
    let body = comment[1];
    const first = index;
    while (command && /\\$/.test(body) && /^\s*# {3}/.test(lines[index + 1] ?? ''))
      body = body.slice(0, -1) + /^\s*#(.*)$/.exec(lines[++index])[1];
    comments.push({ line: first + 1, text: body.trim(), command });
  }
  return comments;
}

// The services of a Compose file as this check reads them, {service: {key: value}}: `services:`
// at the top, each service two blanks in and each of its keys four, a value without its quotes or
// a comment after it ('' where it is below its key).
function composeServices(text) {
  const services = {};
  let inServices = false,
    current = null;
  for (const line of text.split('\n')) {
    if (/^\s*(?:#|$)/.test(line)) continue;
    if (/^\S/.test(line)) {
      inServices = /^services:\s*$/.test(line);
      current = null;
      continue;
    }
    if (!inServices) continue;
    const service = /^ {2}([^\s:#]+):\s*$/.exec(line);
    if (service) current = services[service[1]] = {};
    const key = /^ {4}([^\s:#]+):\s*(.*?)\s*$/.exec(line);
    if (key && current)
      current[key[1]] = key[2].replace(/\s+#.*$/, '').replace(/^(['"])(.*)\1$/, '$2');
  }
  return services;
}
// A Compose memory value in bytes, as Compose reads it (1g is 1 GiB); any other form as it is.
function composeBytes(value) {
  const match = /^(\d+(?:\.\d+)?)\s?([bkmgtp]?)i?b?$/i.exec(value);
  if (!match) return value;
  return String(
    Math.trunc(Number(match[1]) * 1024 ** 'bkmgtp'.indexOf(match[2].toLowerCase() || 'b'))
  );
}

// What is wrong with the limits of the Compose files a documented command can read: compose.yaml
// (`compose['compose.yaml']`), with compose.secret.yaml or not, and with each compose.override.yaml
// the documents show (`overrides`, [{file, text}]) or none.
function composeModelProblems(compose, overrides) {
  const problems = [];
  const base = { file: 'compose.yaml', services: composeServices(compose['compose.yaml']) };
  const secret = {
    file: 'compose.secret.yaml',
    services: composeServices(compose['compose.secret.yaml']),
  };
  const shown = overrides.map(({ file, text }) => ({ file, services: composeServices(text) }));
  for (const { file, services } of [base, secret, ...shown])
    for (const [name, keys] of Object.entries(services)) {
      for (const key of ['deploy', 'extends', '<<'])
        if (key in keys)
          problems.push(`${file}: the service ${name} sets ${key}, which this check does not read`);
      if (file !== base.file && !(name in base.services))
        problems.push(`${file}: adds the service ${name}, which compose.yaml does not limit`);
    }
  for (const layers of [[], [secret], ...shown.flatMap(layer => [[layer], [secret, layer]])]) {
    const merged = {};
    for (const { services } of [base, ...layers])
      for (const [name, keys] of Object.entries(services)) {
        merged[name] ??= {};
        for (const key of ['mem_limit', 'cpus', 'pids_limit'])
          if (key in keys)
            merged[name][key] = key === 'mem_limit' ? composeBytes(keys[key]) : keys[key];
      }
    for (const problem of serviceProblems({ services: merged }))
      problems.push(`${[base, ...layers].map(layer => layer.file).join(' + ')}: ${problem}`);
  }
  return problems;
}

/**
 * What is wrong with the docker commands of `markdown` and `comments` ([{file, text}]) and the
 * Compose files `compose` ({'compose.yaml': text, 'compose.secret.yaml': text}), as the comment
 * above says: {problems, commands}, `commands` [{file, line, code}] for each docker command read.
 */
function dockerDocumentProblems({ markdown, comments, compose, mentions = [], larger = [] }) {
  const problems = [],
    commands = [],
    overrides = [];
  const used = new Set();
  const check = (file, line, code) => {
    const mention = mentions.find(item => item.file === file && item.code === code);
    if (mention) return void used.add(mention);
    for (const invocation of dockerInvocations(code)) {
      commands.push({ file, line, code });
      for (const problem of dockerCommandProblems(invocation, file, larger, used))
        problems.push(`${file}:${line}: ${code}: ${problem}`);
    }
  };
  const prose = (file, line, text) => {
    if (/\bdocker\s+(?:container\s+)?(?:run|create)\s+-/i.test(text))
      problems.push(
        `${file}:${line}: prose gives docker run or create with options, which this check does not read: write the command as code`
      );
  };
  for (const { file, text } of markdown) {
    const parts = markdownParts(text);
    for (const { line, text: code } of parts.code) check(file, line, code);
    for (const { line, text: words } of parts.prose) prose(file, line, words);
    for (const fence of parts.fences)
      if (/^services:/m.test(fence.text))
        overrides.push({ file: `${file}:${fence.line}`, text: fence.text });
  }
  for (const { file, text } of comments)
    for (const { line, text: words, command } of commentParts(text))
      (command ? check : prose)(file, line, words);
  problems.push(...composeModelProblems(compose, overrides));
  for (const entry of [...mentions, ...larger])
    if (!used.has(entry))
      problems.push(`${entry.file}: ${entry.code ?? entry.limits} is listed, but no longer there`);
  return { problems, commands };
}

// Every Markdown file of the source outside test/ (docker-limits.test.mjs reads that), the
// dependencies and what a build or a run leaves (release/, data/), and the files with Compose
// comments.
function dockerDocuments() {
  const markdown = [];
  const walk = directory => {
    for (const entry of fs.readdirSync(path.join(repository, directory), { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      if (['node_modules', 'test', 'release', 'data'].includes(entry.name)) continue;
      const name = directory ? `${directory}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(name);
      else if (entry.isFile() && entry.name.endsWith('.md')) markdown.push(name);
    }
  };
  walk('');
  const comments = [
    ...fs
      .readdirSync(repository)
      .filter(name => /^(?:docker-)?compose(?:\.[\w-]+)*\.ya?ml$/.test(name)),
    '.env.example',
  ];
  return {
    markdown: markdown.sort().map(file => ({ file, text: read(file) })),
    comments: comments.sort().map(file => ({ file, text: read(file) })),
    compose: {
      'compose.yaml': read('compose.yaml'),
      'compose.secret.yaml': read('compose.secret.yaml'),
    },
  };
}

test('docs: every documented docker command that makes a container has finite memory, CPU and process limits, and pulls no image (B39)', () => {
  const documents = dockerDocuments();
  for (const file of ['README.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'docs/installation.md'])
    assert.ok(
      documents.markdown.some(item => item.file === file),
      `${file} is read`
    );
  for (const file of ['.env.example', 'compose.secret.yaml', 'compose.yaml'])
    assert.ok(
      documents.comments.some(item => item.file === file),
      `${file} is read`
    );
  const { problems, commands } = dockerDocumentProblems({
    ...documents,
    mentions: dockerMentions,
    larger: largerContainers,
  });
  assert.deepEqual(problems, []);
  // It read the commands it is for: the restore after a code rollback, the capacity run, the
  // Compose runs of installation.md, troubleshooting.md and compose.secret.yaml.
  const counted = (file, pattern) =>
    commands.filter(item => item.file === file && pattern.test(item.code)).length;
  assert.equal(counted('docs/installation.md', /^docker run .* restore-snapshot SNAPSHOT_ID$/), 1);
  assert.equal(counted('docs/engineering-quality.md', /^docker run .*capacity\.test\.mjs$/), 1);
  assert.ok(counted('docs/installation.md', /docker compose (?:-f \S+ )*run /) >= 8);
  assert.ok(counted('docs/troubleshooting.md', /docker compose (?:-f \S+ )*run /) >= 2);
  assert.ok(counted('compose.secret.yaml', /docker compose (?:-f \S+ |\$\(.*\) )*run /) >= 5);
});

test('docs: the check of documented docker commands refuses a command without its limits, wherever the documents give it (B39)', () => {
  const compose = {
    'compose.yaml': 'services:\n  orbit:\n    mem_limit: 1g\n    cpus: 1\n    pids_limit: 256\n',
    'compose.secret.yaml': 'services:\n  orbit:\n    secrets:\n      - orbit_secret_key\n',
  };
  const check = (text, { file = 'docs/x.md', ...rest } = {}) =>
    dockerDocumentProblems({ markdown: [{ file, text }], comments: [], compose, ...rest }).problems;
  const block = line => `Run:\n\n\`\`\`sh\n${line}\n\`\`\`\n`;
  const limits = '--memory 1g --cpus 2 --pids-limit 256';
  // What passes: the limits first, --pull=never before the image; a bare name; Compose commands.
  for (const text of [
    block(`docker run ${limits} --pull=never --rm uptime-goblin:local true`),
    block(`docker container create --memory=512m --cpus=0.5 --pids-limit=64 --pull never img`),
    block(`sudo docker run -m 1g --cpus 1 --pids-limit 1 --pull=never --rm img sh -c 'x > y'`),
    'Neither `docker run`, `docker create`, `docker compose run` nor `docker update` alone.',
    block(
      'docker compose -f compose.yaml -f compose.secret.yaml run --rm --no-deps uptime-goblin true'
    ),
    block(`docker compose -f compose.yaml $(test -e k && echo '-f compose.secret.yaml') run orbit`),
    block('COMPOSE_FILE=compose.yaml:compose.override.yaml docker compose up -d'),
    block('docker compose logs uptime-goblin | docker compose exec -T uptime-goblin true'),
    'Prose may say docker run by name, or that docker create makes a container.',
  ])
    assert.deepEqual(check(text), [], text);
  // What fails, each with what it says.
  const fails = (text, pattern, options) => {
    const problems = check(text, options);
    assert.equal(problems.length, 1, `${text}: ${problems.join('\n')}`);
    assert.match(problems[0], pattern, text);
  };
  // B39 as it stood: no limits at all (the restore line 1.5.0-dev.2 printed).
  fails(
    block('docker run --rm --user node --read-only --network none uptime-goblin:1.5.0 node x'),
    /docs\/x\.md:4: .*without finite --memory, --cpus, --pids-limit right after the subcommand/
  );
  // int-b's restore line: its limits after other options, and no --pull=never.
  fails(
    block('docker run --rm --memory 1g --cpus 1 --pids-limit 256 --pull=never img'),
    /without finite --memory, --cpus, --pids-limit right after the subcommand/
  );
  fails(block(`docker run ${limits} --rm img`), /without --pull=never before the image/);
  fails(block(`docker run ${limits} --pull=missing img`), /without --pull=never/);
  fails(block(`docker run ${limits} --pull=never --pull=always img`), /without --pull=never/);
  fails(block(`docker run --memory 1g --cpus 2 --pull=never img`), /--pids-limit right after/);
  fails(block(`docker run --memory 0 --cpus 2 --pids-limit 256 img`), /without finite --memory/);
  fails(block(`docker run ${limits} --pull=never -m 0 img`), /gives -m again/);
  fails(block(`docker run ${limits} --rm img --pull=never`), /without --pull=never/);
  fails(
    block('docker run --memory 2g --cpus 2 --pids-limit 256 --pull=never img'),
    /gives more memory than .* larger lists no reason/
  );
  fails(
    block('docker run --memory 8g --cpus 4 --pids-limit 1024 --pull=never img'),
    /gives more memory than larger allows it/,
    {
      larger: [
        {
          file: 'docs/x.md',
          limits: '--cpus 4 --pids-limit 1024',
          most: { memory: 4 * 1024 ** 3, cpus: 4, pids: 1024 },
        },
      ],
    }
  );
  // Wherever the documents give it: in a continued line, inline code, sh -c, $(…), a table.
  fails(block('docker run --rm \\\n  img'), /docs\/x\.md:4: docker run --rm {3}img: .*without/);
  fails('Run `docker run --rm img` once.', /docs\/x\.md:1: docker run --rm img: /);
  fails(block("sh -c 'docker run --rm img'"), /without finite/);
  fails(block('id=$(docker container create img)'), /without finite/);
  fails('| a | `docker create --rm img` |', /without finite/);
  fails(block('docker update --memory 0 orbit'), /docker update can change/);
  fails(block('docker --context x run img'), /option \(--context\) before the subcommand/);
  fails('Then docker run -d img in the shell.', /prose gives docker run or create with options/);
  // Compose: a file whose limits it does not read, or a project without them.
  fails(block('docker compose -f other.yaml run orbit'), /reads other\.yaml, whose limits/);
  fails(block('COMPOSE_FILE=other.yaml docker compose up -d'), /reads other\.yaml/);
  fails(block('docker compose --project-directory x up'), /--project-directory/);
  fails(block('docker compose --unknown x run orbit'), /--unknown is not known/);
  for (const [file, text] of [
    ['compose.yaml', 'services:\n  orbit:\n    mem_limit: 1g\n    cpus: 1\n'],
    ['compose.yaml', 'services:\n  orbit:\n    mem_limit: 0\n    cpus: 1\n    pids_limit: 9\n'],
    ['compose.secret.yaml', 'services:\n  orbit:\n    cpus: 0\n'],
  ]) {
    const problems = dockerDocumentProblems({
      markdown: [],
      comments: [],
      compose: { ...compose, [file]: text },
    }).problems;
    assert.ok(problems.length > 0, text);
    assert.match(problems[0], /has no finite (?:mem_limit|cpus|pids_limit)/, text);
  }
  const pids = check('```yaml\nservices:\n  orbit:\n    pids_limit: -1\n```\n');
  assert.ok(pids.length > 0 && pids.every(problem => /docs\/x\.md:2: .*pids_limit/.test(problem)));
  assert.match(
    check('```yaml\nservices:\n  more:\n    image: x\n```\n').join('\n'),
    /docs\/x\.md:2: adds the service more/
  );
  const deploy = '```yaml\nservices:\n  orbit:\n    deploy:\n      resources: {}\n```\n';
  assert.match(check(deploy).join('\n'), /sets deploy, which this check does not read/);
  // The command lines of a Compose file's comments, and its prose.
  const comments = text =>
    dockerDocumentProblems({ markdown: [], comments: [{ file: 'c.yaml', text }], compose })
      .problems;
  assert.match(comments('#   docker run --rm img\n').join(), /c\.yaml:1: docker run --rm img/);
  assert.match(comments('# then docker run -it img\n').join(), /prose gives docker run/);
  assert.deepEqual(comments('# every docker compose command\n#   docker compose up -d\n'), []);
  // A listed entry that matches nothing fails, so neither list can rot.
  fails('No docker here.', /docs\/x\.md: docker run --env is listed, but no longer there/, {
    mentions: [{ file: 'docs/x.md', code: 'docker run --env' }],
  });
  assert.deepEqual(
    check('Name `docker run --env`.', {
      mentions: [{ file: 'docs/x.md', code: 'docker run --env' }],
    }),
    []
  );
});

test('docs: the exit statuses name 75 for a held goblin.lock, as server.mjs and the unit behave', () => {
  const server = read('server.mjs');
  assert.match(server, /if \(error\?\.exitCode === 75\) return 75;/);
  assert.match(read('deploy/uptime-goblin.service'), /^RestartPreventExitStatus=78$/m);
  assert.match(read('deploy/uptime-goblin.service'), /^RestartSec=5$/m);
  assert.ok(
    flat(read('docs/installation.md')).includes(
      '78 when it refuses to start (for example a too-short `GOBLIN_PASSWORD`, or a resource limit that is not in force), 75 while another process (another Uptime Goblin, or a `goblin-admin` command) holds `goblin.lock` in the data directory, and 1 for anything else'
    )
  );
  const security = flat(
    section(read('docs/security.md'), 'Installer, release signing and supervision')
  );
  assert.ok(
    security.includes(
      'A refusal to start (invalid settings or `auth.json`, the password rules, an invalid `GOBLIN_TRUST_PROXY`, an encryption key problem, no admin password, data from a newer release, an interrupted snapshot restore, a resource limit not in force, a malformed `GOBLIN_ALLOW_UNLIMITED`) exits 78.'
    )
  );
  assert.ok(
    security.includes(
      'Another process holding `goblin.lock` in the data directory (another Uptime Goblin, or a `goblin-admin` command) makes a start exit 75, and systemd tries again after 5 seconds'
    )
  );
  // The 78 causes server.mjs names.
  assert.match(
    server,
    /no admin password, a corrupt configuration or authentication file,\n \* data from a newer release, a key problem\)/
  );
});

test('docs: the installer success lines are quoted as deploy/install.sh prints them', () => {
  const installer = read('deploy/install.sh');
  const printed = [
    'Uptime Goblin %s is running and will start automatically after reboot.',
    'The previous version is kept in /opt/uptime-goblin.previous.',
    'Sign in as admin with the same password. Reload Uptime Goblin tabs that were open before this upgrade once.',
    'Encryption key: /etc/uptime-goblin/secret.key. Back it up separately from /var/lib/uptime-goblin.',
    'Open Uptime Goblin tabs now update themselves after an upgrade; tabs opened before 1.4.3 need one manual reload.',
  ];
  for (const line of printed) assert.ok(installer.includes(`printf '${line}\\n'`), line);
  const verification = flat(
    section(read('docs/installation.md'), 'Verification and automatic rollback', 3)
  );
  for (const line of printed)
    assert.ok(verification.includes(`"${line.replace('%s', '<version>')}"`), line);
  assert.doesNotMatch(verification, /"(?:Orbit|Uptime Goblin) 1\.4\.3 is running/);
});

test('docs: the ssh tunnel is offered only where Orbit listens on 127.0.0.1 or every address', () => {
  // server.mjs binds HOST alone; the installer's --listen sets HOST.
  assert.match(read('server.mjs'), /server\.listen\(port, host, /);
  assert.match(read('deploy/install.sh'), /--listen\) goblin_host=/);
  const installer = read('deploy/install.sh');
  // The tunnel's target, by HOST: 127.0.0.1 where Uptime Goblin listens there or everywhere, [::1] or
  // localhost where HOST names that (a tunnel to the loopback is `loopback` to Uptime Goblin).
  assert.ok(
    installer.includes(
      "new Map([['127.0.0.1','127.0.0.1'],['0.0.0.0','127.0.0.1'],['::','127.0.0.1'],['::1','[::1]'],['localhost','localhost']]).get(host)"
    )
  );
  assert.ok(
    flat(read('docs/authentication.md')).includes(
      "With `HOST=::1` or `HOST=localhost`, forward to that name instead: `ssh -L '4317:[::1]:4317' <uptime-goblin-host>` (quoted, or zsh takes the brackets for a file pattern) or `ssh -L 4317:localhost:4317 <uptime-goblin-host>`."
    )
  );
  const caveat =
    'An install made with `--listen <address>` does not listen on 127.0.0.1, and a tunnel to its address is plain HTTP to Uptime Goblin';
  const guide = flat(read('docs/authentication.md'));
  assert.doesNotMatch(guide, /Always available: the ssh tunnel/);
  assert.ok(guide.includes('5. **The ssh tunnel, on a native install that listens on loopback.**'));
  assert.ok(
    guide.includes(
      'An install made with `--listen <address>` listens only on that address: a tunnel to 127.0.0.1 reaches nothing there, and a tunnel to that address arrives from that address, so Uptime Goblin treats it as plain HTTP (`https_required`).'
    )
  );
  assert.ok(flat(section(read('docs/installation.md'), 'Upgrading to 1.5', 3)).includes(caveat));
  assert.ok(upgradeNotes().some(note => note.includes(caveat)));
  for (const [file, text] of [
    ['CHANGELOG.md', changelog().release],
    ['docs/installation.md', read('docs/installation.md')],
  ])
    assert.doesNotMatch(flat(text), /which always works/, file);
  assert.ok(
    flat(read('docs/troubleshooting.md')).includes(
      'on a native install that listens on 127.0.0.1 or on every address, through `ssh -L 4317:127.0.0.1:4317 <uptime-goblin-host>` at <http://localhost:4317> (an install made with `--listen <address>` is not reached that way)'
    )
  );
});

test('docs: a malformed GOBLIN_TRUST_PROXY that 1.4.3 accepted stops 1.5, and the installer checks existing and replacement values', () => {
  const entry = '192.0.2.0/24/extra';
  assert.throws(() => trustedProxies(entry), /GOBLIN_TRUST_PROXY has an invalid entry/);
  assert.equal(typeof trustedProxies('192.0.2.0/24'), 'function');
  // The explicit option uses Uptime Goblin's parser. Existing and effective systemd values are
  // covered by the pre-mutation behavior tests in installer/installer.test.mjs.
  const installer = read('deploy/install.sh');
  const parsed = [
    ...installer.matchAll(
      /trustedProxies\(process\.argv\[2\]\);' "\$goblin_source\/lib\/throttle\.mjs" "([^"]+)"/g
    ),
  ].map(match => match[1]);
  assert.deepEqual(parsed, ['$goblin_trust_proxy']);
  const installation = flat(read('docs/installation.md'));
  assert.ok(
    installation.includes(
      `Proxy configuration validation is stricter from the 1.4.x maintenance candidate on, and so in 1.5: a \`GOBLIN_TRUST_PROXY\` entry with extra slash segments, such as \`${entry}\`, which 1.4.3 accepts, refuses startup with exit status 78.`
    )
  );
  assert.ok(
    installation.includes(
      'The native installer checks a `--trust-proxy` value, and the `GOBLIN_TRUST_PROXY` in `/etc/uptime-goblin.env` (unless `--trust-proxy` replaces it) and as systemd would give it to Uptime Goblin'
    )
  );
  assert.doesNotMatch(installation, /stricter in this maintenance release/);
  const note = proxyUpgradeNote();
  assert.ok(
    note.startsWith('- **Check `GOBLIN_TRUST_PROXY` first.** 1.5 refuses to start (exit status 78)')
  );
  assert.ok(note.includes(`\`${entry}\``));
  assert.ok(
    note.includes(
      'checks the value in `/etc/uptime-goblin.env` (unless `--trust-proxy` replaces it)'
    ) && note.includes('and as systemd would give it to Uptime Goblin, and a `--trust-proxy` value')
  );
});

test('docs: the installer checks HOST and PORT in /etc/uptime-goblin.env before anything changes, and the docs say what it prints', () => {
  // The check: this release's listenHost and listenPort on the values systemd passes.
  const installer = read('deploy/install.sh');
  // HOST/PORT remain first when more validators are added. The installer's behavior tests
  // also assert the exact refusal and an unchanged host before/after an invalid value.
  assert.ok(installer.includes('[[listenHost,env.HOST],[listenPort,env.PORT],'));
  const refusal = 'This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env';
  assert.ok(installer.includes(`${refusal} (exit status 78): `));
  assert.ok(
    flat(read('docs/installation.md')).includes(
      `such as \`PORT=04317\`, which 1.4.x read as 4317, or \`GOBLIN_TRUST_PROXY=0.0.0.0/0\`, which 1.4.3 accepted, ends the install with "${refusal}" and the reason, changing nothing`
    )
  );
  const row = read('docs/troubleshooting.md')
    .split('\n')
    .find(line => line.startsWith('| PORT must be a whole number from 1 to 65535'));
  assert.ok(row.includes(`"${refusal}"`), row);
  assert.ok(
    flat(proxyUpgradeNote()).includes(
      'The native installer checks `HOST` and `PORT` in `/etc/uptime-goblin.env` before it changes anything and refuses the upgrade, changing nothing, with one of those'
    )
  );
  // And where node --env-file, with which the installer checks Uptime Goblin after the start, reads HOST
  // or PORT otherwise than systemd: the installer says so, and the docs say what it prints.
  const differently = 'read /etc/uptime-goblin.env differently: ';
  assert.ok(installer.includes(differently));
  assert.ok(
    flat(read('docs/installation.md')).includes('"… read /etc/uptime-goblin.env differently:"')
  );
  assert.ok(
    read('docs/troubleshooting.md')
      .split('\n')
      .some(line =>
        line.startsWith(
          '| systemd, which starts Uptime Goblin, and node --env-file, … read /etc/uptime-goblin.env differently |'
        )
      )
  );
  // The file is read with systemd's own parser, and the two refusals that come first (a file
  // systemd would not read, and one that runs a setting or a comment on into the next line) are
  // printed as the docs quote them. The docs no longer say that the installer reads lines that
  // systemd joins as lines of their own, or does not decode a backslash.
  assert.ok(installer.includes('const envRead=input=>{'));
  for (const refusal of [
    'systemd would not read /etc/uptime-goblin.env, and so would not start Uptime Goblin',
    '/etc/uptime-goblin.env continues a setting or a comment onto the next line',
  ]) {
    assert.ok(installer.includes(`console.error(\`${refusal}: `), refusal);
    assert.ok(
      read('docs/troubleshooting.md')
        .split('\n')
        .some(line => line.startsWith(`| ${refusal} |`)),
      refusal
    );
  }
  const installation = flat(read('docs/installation.md'));
  assert.ok(installation.includes('("systemd would not read /etc/uptime-goblin.env")'));
  assert.ok(
    installation.includes(
      '("/etc/uptime-goblin.env continues a setting or a comment onto the next line")'
    )
  );
  for (const [text, copy] of [
    [installation, 'with a copy of the parser systemd reads an `EnvironmentFile=` with'],
    [flat(read('CHANGELOG.md')), "with a copy of systemd's own parser for an `EnvironmentFile=`"],
  ]) {
    assert.doesNotMatch(text, /as lines of their own|does not decode a backslash/);
    assert.ok(text.includes(copy), copy);
  }
});

// The installer also compares HOST and PORT as systemd gives them to Uptime Goblin (a drop-in, systemd's
// own environment) with /etc/uptime-goblin.env; the docs said a value from elsewhere "is not compared".
// They quote its four refusals as it prints them. And for HOST or PORT in the installer's own
// environment, the CHANGELOG said only "could not be verified", which a restored 1.4.3 or later
// got; one before 1.4.3 got its legacy health check's "did not pass", or "answered".
test('docs: the installer compares HOST and PORT as systemd gives them with /etc/uptime-goblin.env, and the docs quote what it prints', () => {
  const installer = read('deploy/install.sh'),
    installation = flat(read('docs/installation.md')),
    changelog = flat(read('CHANGELOG.md')),
    rows = read('docs/troubleshooting.md').split('\n');
  for (const [message, end] of [
    [
      'systemd would give Uptime Goblin another HOST or PORT than /etc/uptime-goblin.env gives',
      ', ',
    ],
    ['HOST and PORT as systemd would give them to Uptime Goblin could not be checked', ': '],
    ['systemd would not start Uptime Goblin', ': '],
    ['systemd has not read the drop-ins of uptime-goblin.service as they are now', ' ('],
  ]) {
    assert.ok(installer.includes(`console.error(\`${message}${end}`), message);
    assert.ok(installation.includes(`"${message}"`), message);
    assert.ok(
      rows.some(line => line.startsWith(`| ${message}`)),
      message
    );
  }
  assert.ok(
    changelog.includes(
      '"systemd would give Uptime Goblin another HOST or PORT than /etc/uptime-goblin.env gives"'
    )
  );
  for (const text of [installer, installation, changelog])
    assert.ok(!text.includes('is not compared'));
  for (const said of [
    'reported as "could not be verified" when it was 1.4.3 or later',
    'one before 1.4.3 was reported with "its legacy health check did not pass", or with "its legacy health check answered"',
  ])
    assert.ok(changelog.includes(said), said);
  assert.ok(
    flat(installer.replaceAll('\n# ', ' ')).includes(
      '"could not be verified" (one before 1.4.3: its legacy health check "did not pass", or "answered" without a verified process identity'
    )
  );
});

// A file a drop-in names that the installer does not read (not a regular file, or larger than
// 1 MiB) was skipped when named with "-", though systemd reads it, while these texts said it was
// refused; and a first install read no drop-in, since systemd lists none for a unit it has not
// loaded (round-3 findings). test/installer/installer.test.mjs checks what the installer does;
// here, that the texts say it.
test('docs: a file named with "-" that the installer does not read, and the drop-ins of a first install, are described as the installer handles them', () => {
  const installer = flat(read('deploy/install.sh').replaceAll('\n# ', ' ')),
    installation = flat(read('docs/installation.md')),
    troubleshooting = flat(read('docs/troubleshooting.md')),
    changelog = flat(read('CHANGELOG.md'));
  for (const [text, said] of [
    [
      installer,
      'a file a drop-in names, with a leading "-" or without, that is not a regular file or is larger than 1 MiB',
    ],
    [
      installation,
      'a file a drop-in names, with a leading `-` or without, is not a regular file or is larger than 1 MiB',
    ],
    [
      troubleshooting,
      'a file a drop-in names, with a leading `-` or without, that is not a regular file or is larger than 1 MiB',
    ],
    [
      changelog,
      'a file a drop-in names, with a leading `-` or without, that is not a regular file or is larger than 1 MiB, which it does not read',
    ],
    [
      installer,
      'Where systemd has not loaded uptime-goblin.service (LoadState other than loaded, as on a first install, where it is not-found) it lists no drop-in for it',
    ],
    [
      installation,
      'or, where systemd has not loaded `uptime-goblin.service` (as on a first install, where it lists no drop-in for it), the drop-ins it will find once the unit is written',
    ],
    [
      changelog,
      'It reads the drop-ins on disk then, in the order systemd takes them once the unit is written.',
    ],
    [
      changelog,
      "It refuses as well, changing nothing, where a drop-in (`Environment=`, `EnvironmentFile=`, `PassEnvironment=`, `UnsetEnvironment=`) or systemd's own environment would give Uptime Goblin another `HOST` or `PORT` than `/etc/uptime-goblin.env`, and where it cannot tell which they would give",
    ],
  ])
    assert.ok(text.includes(said), said);
  assert.ok(
    !installer.includes('with no uptime-goblin.service loaded yet, systemd lists no drop-in for it')
  );
});

test('docs: each GOBLIN_TRUST_PROXY value 1.4.3 started with and 1.5 refuses is in the upgrade notes, and each such start refusal has a troubleshooting row', () => {
  // 1.4.3 checked only an entry's form, so it started with each of these.
  const sixtyFive = Array.from({ length: 65 }, (_, i) => `192.0.2.${i}`).join(',');
  const proxyRefusals = [
    ['extra slash segments', '192.0.2.0/24/extra'],
    ['wider than /8', '0.0.0.0/0'],
    ['more than 64 entries', sixtyFive],
    ['together cover more than two /8 (or /32) ranges', '10.0.0.0/8,11.0.0.0/8,12.0.0.0/8'],
  ];
  const note = flat(proxyUpgradeNote());
  const paragraph = start =>
    flat(
      read('docs/installation.md')
        .split('\n\n')
        .find(text => text.startsWith(start)) ?? ''
    );
  const upgrade = paragraph('Proxy configuration validation is stricter');
  const setUp = paragraph('Tell Uptime Goblin which proxy to believe');
  const messages = [];
  const refusal = (run, label) => {
    assert.throws(
      run,
      error => {
        messages.push(error.message);
        return error.refusal === true;
      },
      label
    );
  };
  for (const [phrase, value] of proxyRefusals) {
    refusal(() => trustedProxies(value), phrase);
    assert.ok(note.includes(phrase), `the upgrade note names: ${phrase}`);
    assert.ok(upgrade.includes(phrase), `installation.md (upgrading) names: ${phrase}`);
  }
  for (const [phrase] of proxyRefusals.slice(1))
    assert.ok(setUp.includes(phrase), `installation.md (reverse proxy) names: ${phrase}`);
  // The other start refusals of environment settings new in 1.5.
  refusal(() => allowedHostList(sixtyFive), 'GOBLIN_ALLOWED_HOSTS');
  refusal(() => listenPort('04317'), 'PORT');
  refusal(() => listenHost('[::1]'), 'HOST');
  assert.ok(note.includes('more than 64 `GOBLIN_ALLOWED_HOSTS` entries'));
  assert.ok(note.includes('without a leading zero'));
  // A row's first cell names messages, ' / ' between them and '…' where they vary.
  const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const named = read('docs/troubleshooting.md')
    .split('\n')
    .filter(line => line.startsWith('| '))
    .flatMap(line => line.slice(2, line.indexOf(' | ')).split(' / '))
    .map(cell => new RegExp(`^${cell.split('…').map(escape).join('.*')}`));
  for (const message of messages)
    assert.ok(
      named.some(pattern => pattern.test(message)),
      `troubleshooting.md has a row for: ${message.slice(0, 80)}`
    );
});

// The NAT64 prefix stands for every IPv4 address, so GOBLIN_TRUST_PROXY refuses it (and every
// range that holds it) like 0.0.0.0/0; 1.4.3 started with it. So do the IPv4-translated and the
// IPv4-compatible prefixes. The wide-range warning starts above /24 or /64. Each place that
// lists the refusals names all three, and each refusal has its row.
test('docs: GOBLIN_TRUST_PROXY refuses the NAT64, IPv4-translated and IPv4-compatible prefixes like 0.0.0.0/0 and warns above /24 or /64, where the docs list the refusals', () => {
  const phrases = [
    'the NAT64 prefix `64:ff9b::/96`',
    'the IPv4-translated prefix `::ffff:0:0:0/96`',
    'the IPv4-compatible prefix `::/96`',
  ];
  const listsAll = (text, where) => {
    for (const phrase of phrases) assert.ok(text.includes(phrase), `${where}: ${phrase}`);
  };
  const messages = [];
  for (const value of [
    '64:ff9b::/96',
    '64:ff9b::/64',
    '64:ff9b::/100',
    '::ffff:0:0:0/96',
    '::ffff:0:0:0/100',
    '::/96',
    '::/100',
  ])
    assert.throws(
      () => trustedProxies(value),
      error => {
        messages.push(error.message);
        return error.refusal === true;
      },
      value
    );
  const note = changelog()
    .release.split('\n')
    .find(line => line.startsWith('- **Check `GOBLIN_TRUST_PROXY` first.**'));
  listsAll(note, 'the upgrade note');
  const paragraph = start =>
    flat(
      read('docs/installation.md')
        .split('\n\n')
        .find(text => text.startsWith(start)) ?? ''
    );
  listsAll(paragraph('Proxy configuration validation is stricter'), 'installation.md, upgrading');
  const setUp = paragraph('Tell Uptime Goblin which proxy to believe');
  listsAll(setUp, 'installation.md, the reverse proxy');
  assert.ok(setUp.includes('a range wider than /24 (IPv4) or /64 (IPv6) starts with a warning'));
  const row = read('docs/configuration.md')
    .split('\n')
    .find(line => line.startsWith('| `GOBLIN_TRUST_PROXY` |'));
  listsAll(row, 'configuration.md');
  assert.ok(row.includes('one wider than /24 (IPv4) or /64 (IPv6) starts with a warning'));
  assert.equal(trustedProxies('192.168.0.0/16').warnings.length, 1);
  assert.equal(trustedProxies('2001:db8::/48').warnings.length, 1);
  assert.equal(trustedProxies('192.0.2.0/24,2001:db8::/64').warnings.length, 0);
  listsAll(
    read('docs/troubleshooting.md')
      .split('\n')
      .find(line => line.startsWith('| GOBLIN_TRUST_PROXY entry … trusts too many addresses |')),
    'troubleshooting.md'
  );
  const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const named = read('docs/troubleshooting.md')
    .split('\n')
    .filter(line => line.startsWith('| '))
    .flatMap(line => line.slice(2, line.indexOf(' | ')).split(' / '))
    .map(cell => new RegExp(`^${cell.split('…').map(escape).join('.*')}`));
  for (const message of messages)
    assert.ok(
      named.some(pattern => pattern.test(message)),
      `troubleshooting.md has a row for: ${message.slice(0, 80)}`
    );
});

test('CHANGELOG: the 1.5 section names the pre-release, what still blocks 1.5.0, and the maintenance section its own fixes', () => {
  const { release: notes, maintenance } = changelog();
  assert.ok(notes.startsWith(`\n## Unreleased — 1.5.0 (pre-release ${release})\n`));
  const blockers = notes
    .split('\n')
    .find(line => line.startsWith('- **Not releasable as 1.5.0 yet.**'));
  assert.ok(blockers.includes(`This is pre-release ${release}.`));
  for (const gate of [
    'failed-sign-in counts and trusted clients kept across restarts',
    'device cookies',
    '`session_seq`',
    'installer v2',
    'the SMTP password and source credentials sealed with the encryption key',
    'log levels',
    'an approved review of the audit log',
  ])
    assert.ok(blockers.includes(gate), gate);
  // The gates the code has not closed yet.
  assert.match(read('lib/throttle.mjs'), /Only memory is used; a restart clears it\./);
  // The A2 and A4 fixes ported from the maintenance branch, worded as there; 1.5's stricter
  // fragment check is in the 1.5 section.
  assert.ok(
    maintenance.includes(
      '- Startup warnings for repaired legacy collection addresses identify the source and repair without logging the original or repaired URL, which may contain credentials.'
    )
  );
  assert.ok(
    maintenance.includes(
      '- Destination links reject credential-like parameter names in OAuth-style fragments even beside empty or valueless fields.'
    )
  );
  assert.match(read('lib/config.mjs'), /`collection address of \$\{source\}`,\n\s+'\(hidden\)',/);
  for (const link of [
    '#access_token=x&',
    '#access_token=x&state',
    '#/home&access_token=x',
    '#intro:~:text=a&access_token=x',
  ])
    assert.throws(() => launchUrl(`https://app.example.com/${link}`), /credentials/, link);
  for (const link of ['#state', '#api-key', '#/dashboard?view=1', '#/callback?x=1&access_token=y'])
    assert.equal(launchUrl(`https://app.example.com/${link}`), `https://app.example.com/${link}`);
  assert.equal(
    withoutCredentials('https://app.example.com/#/home&access_token=x'),
    'https://app.example.com/#/home'
  );
  assert.ok(
    notes.includes(
      '1.5 also refuses a credential-like parameter after a route (`#/home&access_token=…`) or in a text directive (`#intro:~:text=…&access_token=…`)'
    )
  );
  // security.md gives the check and its limits as the code has them (the maintenance branch
  // documented them there; docs audit, install-changelog).
  assert.equal(
    withoutCredentials('https://app.example.com/?access_token=harmless&x=1'),
    'https://app.example.com/?x=1'
  );
  assert.ok(
    flat(read('docs/security.md')).includes(
      "- Destination links refuse credential-like query parameters and fragment parameters, also beside empty or valueless fields, after a route (`#/home&access_token=…`) and in a text directive (`#intro:~:text=…&access_token=…`). Startup removes parameters with such names from older saved links without logging them, even if their values are harmless. Ordinary SPA routes and anchors stay allowed, and a route's own query (`#/callback?x=1&access_token=…`) is the application's: it is not checked. This check cannot find every secret in an arbitrary URL."
    )
  );
  // The maintenance branch's download guard is in 1.5 too, and its bullet says so, worded as
  // there.
  assert.ok(
    maintenance.includes(
      "- Browser tests capture export names and contents in the page before Chrome starts a download, preventing temporary export files from passing through the developer's Downloads folder."
    )
  );
  assert.match(
    read('test/helpers/cdp.mjs'),
    /Browser\.setDownloadBehavior|downloadGuard|__exports/
  );
});

test('CHANGELOG: sources, tests and SMTP judge the IPv4 address inside an IPv6 one, as the webhook does', async () => {
  configureDestinations({ allowLoopback: false });
  assert.equal(embeddedIPv4('64:ff9b::a9fe:a9fe'), '169.254.169.254');
  assert.match(
    await checkDestination('http://[64:ff9b::a9fe:a9fe]/'),
    /link-local, multicast or reserved/
  );
  assert.match(
    await checkDestination('http://[2002:a9fe:a9fe::1]/'),
    /link-local, multicast or reserved/
  );
  assert.match(await checkDestination('http://[64:ff9b::7f00:1]/'), /GOBLIN_ALLOW_LOOPBACK=1/);
  assert.equal(await checkDestination('http://[64:ff9b::c0a8:101]/'), null);
  assert.match(read('lib/mail.mjs'), /resolvedDestination\('smtp:\/\/' \+ s\.host\)/);
  // Collectors take the checked addresses from the same policy and connect only to them.
  assert.match(read('lib/collectors.mjs'), /resolvedDestination\(url\)/);
  const notes = changelog().release;
  assert.ok(
    notes.includes(
      '- **Addresses inside IPv6 addresses.** Sources, connection tests and the SMTP server, like the webhook, are now judged by the IPv4 address that a NAT64 (`64:ff9b::/96`, `64:ff9b:1::/96`), IPv4-compatible, IPv4-translated or 6to4 (`2002::/16`) address carries'
    )
  );
  assert.ok(
    upgradeNotes().some(note =>
      note.startsWith('- **Sources and mail servers behind NAT64 or 6to4:**')
    )
  );
});

test('docs: X-Request-Id is on every answer, kept only from a trusted proxy, and named in the log and the audit log', () => {
  assert.equal(String(requestIdPattern), String(/^[A-Za-z0-9._-]{1,64}$/));
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const req = (id, remoteAddress = '127.0.0.1') => ({
    headers: { 'x-request-id': id },
    socket: { remoteAddress },
  });
  const trusted = trustedProxies('loopback');
  assert.equal(requestId(req('nginx.abc-123_x'), trusted), 'nginx.abc-123_x');
  assert.match(requestId(req('nginx.abc-123_x', '192.0.2.9'), trusted), uuid);
  assert.match(requestId(req('nginx.abc-123_x'), trustedProxies('')), uuid);
  assert.match(requestId(req('bad id!'), trusted), uuid);
  assert.match(requestId(req('x'.repeat(65)), trusted), uuid);
  // The answers given while Uptime Goblin starts carry it too.
  const headers = {};
  const res = {
    setHeader: (name, value) => (headers[name.toLowerCase()] = value),
    writeHead() {},
    end() {},
    getHeader: name => headers[name.toLowerCase()],
  };
  try {
    createStartupHandler({ build: '0123456789ab', trusted })(
      { ...req('starting.1'), method: 'GET', url: '/health' },
      res
    );
  } catch {}
  assert.equal(headers['x-request-id'], 'starting.1');
  assert.ok(CSV_HEADER.split(',').includes('request_id'));
  assert.match(read('public/modules/configure/audit.js'), /fact\('Request', entry\.requestId\)/);
  assert.match(read('lib/http/pipeline.mjs'), /request = id \? \[`\(request \$\{id\}\)`\] : \[\]/);
  const architecture = flat(read('docs/architecture.md'));
  assert.ok(
    architecture.includes(
      "Every answer carries `X-Request-Id`, `/health`, refusals and the answers given while Uptime Goblin starts or stops included. It is the id that a proxy named in `GOBLIN_TRUST_PROXY` sent in `X-Request-Id`, when that is 1 to 64 letters, digits, dots, hyphens or underscores; otherwise a new UUID, so a client cannot put text of its own into Uptime Goblin's log."
    )
  );
  assert.ok(architecture.includes('(**Request** on the Audit log page, `request_id` in exports)'));
  assert.ok(
    flat(read('docs/security.md')).includes(
      "An entry that a request made shows that request's id as **Request** (`request_id` in exports): the `X-Request-Id` of Uptime Goblin's answer"
    )
  );
  assert.ok(changelog().release.includes('- **`X-Request-Id`** on every answer'));
});

test('CHANGELOG: the API for scripts lists every new endpoint and the 503 codes of writes', () => {
  const app = { identity: {}, loginThrottle: {}, insecureHttpSessions: false, release: {} };
  const routes = [
    ...authRoutes(app),
    ...accountRoutes(app),
    ...notificationRoutes({}),
    ...auditRoutes({}),
  ];
  const bullet = changelog()
    .release.split('\n')
    .find(line => line.startsWith('- **API for scripts.**'));
  assert.ok(bullet);
  for (const route of routes) {
    const named = route.path.replace(/:(\w+)/g, '<$1>');
    assert.ok(
      bullet.includes(`${route.method} ${named}\``) || bullet.includes(`\`${named}\``),
      `${route.method} ${route.path}`
    );
  }
  assert.ok(
    bullet.includes(
      'Writes can answer 503 `storage_full` (a full disk) or `audit_unavailable` (the audit log cannot be written), with `Retry-After`.'
    )
  );
});

// Docs audit, sessions 11: the deprecated alias answers with `Deprecation`; `Link` comes only on
// answers to legacy Basic, which a session caller (the only kind on a new install) never gets.
// And a body is limited only where a route reads one. Read from a real Uptime Goblin.
test('CHANGELOG: the password alias answers with Deprecation, Link only for Basic, a sign-in body is limited to 4,096 bytes and a sign-out takes none', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-alias-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const password = 'synthetic test password 0001';
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    legacyBasic: true,
    webhook: '',
    keySources: {
      credentialsDirectory: path.join(directory, 'no-credentials'),
      secretsDirectory: path.join(directory, 'no-secrets'),
    },
  });
  t.after(() => app.close());
  const base = `http://127.0.0.1:${(await app.listen()).port}`;
  const call = sessionCall(base, (await signIn(base, password)).cookie);
  const session = await call('/api/auth/password', 'POST', {});
  assert.equal(session.headers.get('deprecation'), basicDeprecation);
  assert.equal(session.headers.get('link'), null);
  const primary = await call('/api/account/password', 'POST', {});
  assert.equal(primary.headers.get('deprecation'), null);
  const basic = await fetch(new URL('/api/auth/password', base), {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`admin:${password}`).toString('base64'),
      'Content-Type': 'application/json',
      'X-Goblin-Request': '1',
    },
    body: '{}',
  });
  await basic.text();
  assert.equal(basic.headers.get('deprecation'), basicDeprecation);
  assert.equal(basic.headers.get('link'), '</api/docs?doc=authentication>; rel="deprecation"');
  // A body over 4,096 bytes: 413 for sign-in; a sign-out takes none at all (64 bytes for {}).
  const large = { login: 'admin', password: 'x'.repeat(5000) };
  const login = await fetch(new URL('/api/auth/login', base), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1', Origin: base },
    body: JSON.stringify(large),
  });
  assert.equal(login.status, 413);
  assert.equal((await login.json()).error, 'Request is too large');
  assert.equal((await call('/api/auth/logout', 'POST', large)).status, 413);
  assert.equal((await call('/api/auth/logout', 'POST', { force: true })).status, 400);
  assert.equal((await call('/api/auth/logout', 'POST', {})).status, 204);

  const bullet = changelog()
    .release.split('\n')
    .find(line => line.startsWith('- **API for scripts.**'));
  assert.ok(
    bullet.includes(
      '`POST /api/auth/password` still works as its deprecated alias and answers with a `Deprecation` header (a script that signs in with legacy Basic also gets the `Link` header every Basic answer carries).'
    )
  );
  assert.ok(
    bullet.includes(
      'the sign-in and password-change bodies are limited to 4,096 bytes (a larger one gets 413), and the sign-outs take no body (none or `{}`)'
    )
  );
  assert.ok(
    flat(read('docs/architecture.md')).includes(
      "A request body is limited to its route's size: 150,000 bytes, 4,096 for sign-in and the password change, 1 KiB for the delivery actions. Writes that take no body (`POST /api/refresh`, `POST /api/auth/logout`, `DELETE /api/services/:id`, `DELETE /api/account/sessions` and `/api/account/sessions/:id`) accept only none or `{}` (400 otherwise), and reads none at all. A larger body gets 413 \"Request is too large\", and the connection is closed. One whose `Content-Length` says so gets it after the `Host` and request-target checks above. Until a credential signs in, every request is held to the default 150,000 bytes, before the credential is checked (a public route, the sign-in, `/health` or the web app's files, to its own), so a request without a credential learns nothing from a 413 about which paths and methods exist or what they take; once it signed in, its route's own limit applies, before the route's own checks (a sign-out whose cookie no longer signs in is held to its own limit too). One sent without a length (chunked) gets it at once on a read once signed in (on `/health` and the web app's files at once), and otherwise when a handler reads past the limit, after the credential and the route's own checks (a request that fails one of those gets that answer instead, and is closed without its body being read)."
    )
  );
});

test('docs: legacy Basic is deprecated since 1 October 2026 and off on upgraded installs from 1.6', () => {
  assert.equal(basicDeprecation, '@1790812800');
  assert.equal(new Date(1790812800 * 1000).toISOString(), '2026-10-01T00:00:00.000Z');
  assert.match(
    read('lib/features.mjs'),
    /enabled: upgraded && compareReleases\(core, '1\.6\.0'\) < 0/
  );
  const guide = flat(section(read('docs/authentication.md'), 'Scripts and legacy Basic'));
  assert.ok(
    guide.includes(
      `Basic answers carry \`Deprecation: ${basicDeprecation}\` (deprecated since 1 October 2026) and \`Link: </api/docs?doc=authentication>; rel="deprecation"\`. From 1.6, Basic is off on upgraded installs too, unless \`GOBLIN_LEGACY_BASIC=1\``
    )
  );
  assert.ok(
    changelog().release.includes(
      'with `Deprecation` and `Link` headers; from 1.6 Basic is off on upgraded installs too, unless `GOBLIN_LEGACY_BASIC=1`.'
    )
  );
});

test('CHANGELOG: refused password changes without a session count into the aggregated audit rows', () => {
  const aggregate = read('lib/audit/aggregate.mjs');
  assert.match(aggregate, /is at most 144 rows a day/);
  assert.ok(
    changelog().release.includes(
      'Refused sign-ins, refused password changes (also those sent without a current session, listed as someone not signed in) and refused script sign-ins are counted rather than listed (the first of each hour at once, the rest in one summary at its end), so clients nobody signed in add at most 144 entries a day'
    )
  );
});

test('docs: plain HTTP only redirects (B11) and a Compose restart reads .env again (B12)', () => {
  const notes = upgradeNotes();
  assert.ok(
    notes.some(note =>
      note.includes(
        "Serve Uptime Goblin's host name over HTTPS only: let plain HTTP do nothing but redirect, and add HSTS once HTTPS works ([the nginx example](docs/installation.md#https-trust-and-network-access))."
      )
    )
  );
  const installation = read('docs/installation.md');
  assert.match(installation, /return 301 https:\/\/\$host\$request_uri;/);
  assert.match(installation, /add_header Strict-Transport-Security "max-age=31536000" always;/);
  const restart =
    'Under Docker Compose that is `docker compose up -d`, which reads `.env` again; `docker compose restart` keeps the values the container was created with.';
  assert.ok(
    notes.some(
      note => note.startsWith('- **Restart Uptime Goblin after changing') && note.includes(restart)
    )
  );
  assert.ok(flat(section(installation, 'Upgrading to 1.5', 3)).includes(restart));
});

// The gate's documented entry point starts it with node. Started by `npm run`, the gate would get
// npm's PATH (the worktree's node_modules/.bin first, where a dependency could put a `node` that
// replaces the gate) and an .npmrc's node-options, before any of its own checks run.
test('the documented gate commands start the gate with node, not through npm', () => {
  for (const file of ['CONTRIBUTING.md', 'docs/engineering-quality.md']) {
    const blocks = shellBlocks(read(file)).join('\n');
    assert.match(blocks, /^node scripts\/security-gate\.mjs commit$/m, file);
    assert.match(blocks, /^node scripts\/security-gate\.mjs release$/m, file);
    assert.doesNotMatch(blocks, /npm run security:/, file);
  }
  const agents = flat(read('AGENTS.md'));
  assert.ok(
    agents.includes('validate the exact staged tree with `node scripts/security-gate.mjs commit`')
  );
  assert.doesNotMatch(agents, /npm run security:/);
  // The README gives the security scan's command too, with node.
  const readme = flat(read('README.md'));
  assert.ok(readme.includes('the security scan (`node scripts/security-gate.mjs scan`'));
  assert.doesNotMatch(readme, /npm run security:/);
  assert.match(
    read('scripts/check-security-approval.mjs'),
    /stage the complete change, run node scripts\/security-gate\.mjs commit, and finalize its exact reviewed findings with node scripts\/finalize-security\.mjs\./
  );
  assert.ok(
    flat(read('docs/engineering-quality.md')).includes(
      'run `node scripts/check-sonarqube.mjs /absolute/private/evidence-directory` (with `node`, not `npm run security:sonarqube`'
    )
  );
});

test('README and CONTRIBUTING: every TEST_REQUIRE name, the capacity run and the two lints', () => {
  const setup = read('test/setup.mjs');
  const known = JSON.parse(
    /const known = (\[[^\]]+\]);/
      .exec(setup)[1]
      .replace(/'/g, '"')
      .replace(/,\s*\]$/, ']')
  );
  assert.deepEqual(known, [
    'browser',
    'fixtures',
    'systemd',
    'docker',
    'postgres',
    'capacity',
    'git',
    'history',
  ]);
  assert.match(
    read('test/audit/capacity.test.mjs'),
    /skip: required \? false : 'needs TEST_REQUIRE=capacity'/
  );
  const scripts = JSON.parse(read('package.json')).scripts;
  assert.ok(scripts['lint:sql'] && scripts['lint:imports']);
  for (const file of ['scripts/check.mjs', '.github/workflows/ci.yml'])
    assert.doesNotMatch(read(file), /lint:sql|lint:imports|sql-lint|import-graph/, file);
  const readme = read('README.md');
  const development = flat(section(readme, 'Development and release status'));
  assert.ok(shellBlocks(readme)[1].includes('npm run lint:sql\nnpm run lint:imports\n'));
  assert.ok(
    development.includes(
      'The 250,000-entry audit log measurement (`test/audit/capacity.test.mjs`) runs only when `TEST_REQUIRE` names `capacity`'
    )
  );
  assert.ok(
    development.includes('`TEST_REQUIRE=browser,fixtures,systemd,docker,capacity,git npm test`')
  );
  // Every name but postgres (no consumer before 1.7) is named, git with its skip reason, and
  // history with the private input it needs.
  assert.ok(development.includes('(`browser`, `fixtures`, `systemd`, `docker`, `git`;'));
  assert.ok(
    development.includes('skip without it and fail without it when `TEST_REQUIRE` names `history`')
  );
  assert.match(
    read('test/helpers/git.mjs'),
    /'git is not installed \(TEST_REQUIRE=git makes this fail\)'/
  );
  // The scan runs both lints only once its pre-dispatch barrier is open, which a CI runner cannot
  // show for a 1.5 commit (verify-1 of gate-draft-r5): the README says so, and no longer says the
  // scan runs them (test/security-dispatch.test.mjs checks the scan on a CI-like checkout).
  assert.ok(
    development.includes(
      'Run them yourself: `npm run check` and the CI test jobs do not run them, and the security scan (`node scripts/security-gate.mjs scan`; start the gate with `node`, as the CI security workflow does, not through npm) runs them only once its `candidate-policy` and `platform-manifest` checks have passed. On a CI runner `platform-manifest` cannot pass for a 1.5 commit, because the gate approvals and reviewed baselines it needs are kept only in a local repository, so CI runs neither lint.'
    )
  );
  assert.ok(!development.includes('not through npm) does.'));
  // The security workflow runs the gate's scan mode, which records both lints (run once the
  // barrier is open, otherwise withheld; test/security-evidence.test.mjs checks the scan's stages).
  // It starts the gate with node, so a tracked .npmrc (which the gate refuses) cannot replace it
  // through npm's script-shell.
  const workflow = read('.github/workflows/security.yml');
  assert.match(workflow, /\n {8}run: node scripts\/security-gate\.mjs scan\n/);
  assert.doesNotMatch(workflow, /run: npm run security:/);
  const contributing = flat(read('CONTRIBUTING.md'));
  assert.ok(
    contributing.includes('`TEST_REQUIRE=browser,fixtures,systemd,docker,capacity,git npm test`')
  );
  assert.ok(
    contributing.includes(
      '`git` does the same for the tests that run Git (the documentation, security gate, commit guard, finalization, SonarQube and packaging tests, and the 1.4.3 web app update test), which skip with the reason `git is not installed (TEST_REQUIRE=git makes this fail)`'
    )
  );
  assert.ok(
    shellBlocks(read('CONTRIBUTING.md'))[0].includes('npm run lint:sql\nnpm run lint:imports\n')
  );
  // The Security row names what security.md covers.
  const security = read('docs/security.md');
  for (const heading of [
    '## Sign-in sessions',
    '## Encryption key and sealed secrets',
    '### A leaked key',
  ])
    assert.ok(security.includes(`\n${heading}\n`), heading);
  assert.ok(
    readme.includes(
      '| [Security](docs/security.md) | Trust boundaries, secrets, the audit log and its limits, sign-in sessions, the encryption key and sealed secrets, a leaked key,'
    )
  );
});

// testenv-2c's export-tag.test.mjs fails, instead of skipping, without Git or the tag when
// TEST_REQUIRE lists history (fixtures before the private history input). Tooling's texts, written for its own tree, said the export test
// skips then whatever TEST_REQUIRE says. At integration docs/engineering-quality.md kept one such
// sentence, beside its own line saying the opposite and pointing to a table row that was removed.
test('the docs say what an unavailable tag does to the export tests, as the test does', () => {
  // needsGit(): fails under TEST_REQUIRE=history, otherwise skips.
  assert.match(
    read('test/upgrade/export-tag.test.mjs'),
    /\n {2}if \(historyRequired\(\)\) assert\.fail\(`\$\{reason\} \(TEST_REQUIRE=history\)`\);\n {2}t\.skip\(reason\);\n/
  );
  for (const file of ['docs/engineering-quality.md', 'CONTRIBUTING.md', 'CHANGELOG.md']) {
    const text = flat(read(file));
    assert.ok(
      text.includes('1.4.3 build, 1.4.2 fixture, export, upgrade, installer and sign-in tests'),
      file
    );
    assert.doesNotMatch(text, /export tests? skips?[^.;]*whatever `TEST_REQUIRE` says/, file);
  }
  const quality = flat(read('docs/engineering-quality.md'));
  for (const text of [
    "The export tool's tests (`test/upgrade/export-tag.test.mjs`) need Git with the private history too, and fail without them under `history`",
    'An unavailable tag skips the 1.4.3 build, 1.4.2 fixture, export, upgrade, installer and sign-in tests unless `TEST_REQUIRE` lists `history`, and the notification policy test leaves its 1.4.3 check out and passes.',
  ])
    assert.ok(quality.includes(text), text);
  // Not in the table of tests that skip for a reason TEST_REQUIRE does not cover.
  assert.doesNotMatch(quality, /\| `test\/upgrade\/export-tag\.test\.mjs`/);
});

// The way to keep the Compose key from host uid 1000 must work with the recipes, which make, read
// and copy files in the project directory: a directory that account cannot enter is one only
// root can work in, so the recipes and docker compose run as root there (measured with Docker
// 27.5.1 on Linux). The advice was a directory uid 1000 cannot enter, with recipes run as the
// user, which then could not run them either.
// Review round 3: that directory was said to keep the key from the account, but it keeps only
// the files from being opened by their paths. Without userns-remap Uptime Goblin's processes run as host
// uid 1000, and a process of that uid read the mounted key through /proc/<pid>/root and
// GOBLIN_PASSWORD through /proc/<pid>/environ (measured with Docker 29.4.0 on OrbStack). The docs
// say so, and name what keeps the key from it: a host where uid 1000 is no one's. Both of the
// container's processes, Docker's init and Node, were read (both uid 1000, no capabilities), and
// the ptrace read check passes only for a dumpable target that holds no capability the reader
// lacks, so the docs name both and those conditions rather than any process of the same uid. A
// key file keeps the key out of /proc/<pid>/environ and docker inspect, not from the account
// Uptime Goblin runs as: security.md said to use one instead, without saying so.
// The check compares group ids too, which "any process of host uid 1000" left out: a reader of
// uid 1000 with gid 1000 read the key, GOBLIN_PASSWORD and a data volume at /app/data (and wrote
// a file there) through /proc/<pid>/root; with gid 100, also with 1000 as an added group, it read
// and wrote none of them (Docker 29.4.0, OrbStack). The docs name the gid and the data volume.
test('docs: keeping the Compose key from host uid 1000 takes a host where that uid is no one’s; a root-only directory keeps only the files, and the recipes then run as root in it', () => {
  const installation = flat(read('docs/installation.md'));
  for (const text of [
    "What keeps the key from that account is a host where uid 1000 is no one's: no person logs in as it, and nothing but Uptime Goblin's containers runs as it.",
    'Root, and every account that can use Docker (`docker compose exec`), can read the key in any case.',
    "Uptime Goblin's processes (Docker's init and Node, which hold no Linux capabilities) run as that same host uid, with gid 1000 (`user: '1000:1000'` in `compose.yaml`).",
    'A Compose project directory that only root can enter does not keep the key from host uid 1000.',
    "any process of host uid 1000 that runs with gid 1000 as well (as the processes of a login whose own group is gid 1000 do: `id` shows it) can read the mounted key through `/proc/<pid>/root/run/secrets/orbit_secret_key` and the `GOBLIN_PASSWORD` the container started with through `/proc/<pid>/environ`, and read and change the files of Uptime Goblin's data volume through `/proc/<pid>/root/var/lib/uptime-goblin` (`/app/data` before 1.5)",
    "where `<pid>` is either process of Uptime Goblin's container: Linux's ptrace read check, which guards these entries, passes for a reader whose user and group ids are both the target's, unless the target holds a capability the reader lacks or has made itself undumpable, and Uptime Goblin's processes have done neither; that path never enters the directory",
    "If you keep the directory root's all the same, mode 0700 with `compose.yaml`, `compose.secret.yaml` and `.env` in it, run every command of these recipes, and every other `docker compose` command for Uptime Goblin, as root in that directory",
    "through the `/proc` entries of both of the container's processes, Docker's init (`--init`, which `init: true` gives) and Node, and read and wrote a file in a data volume mounted at `/app/data`.",
    'Run with gid 100 (`--user 1000:100`), also with 1000 as an added group (`--group-add 1000`), that process could read or write none of these through `/proc`; a member of group 1000 can make gid 1000 its group with `newgrp` (not measured).',
    'Hosts where AppArmor or SELinux confine the containers were not measured.',
  ])
    assert.ok(installation.includes(text), text);
  assert.doesNotMatch(installation, /keep the file in a directory that account cannot enter/);
  assert.doesNotMatch(installation, /To keep the key from that account, keep the whole Compose/);
  assert.doesNotMatch(
    installation,
    /Otherwise run Uptime Goblin's containers on a host where uid 1000/
  );
  assert.doesNotMatch(installation, /where `<pid>` is Uptime Goblin's process/);
  assert.doesNotMatch(installation, /Linux lets a process read these entries of another process/);
  assert.doesNotMatch(
    installation,
    /any process of host uid 1000 can read|of the same uid read them/
  );
  const security = flat(read('docs/security.md'));
  assert.ok(
    security.includes(
      "A key file keeps the key out of those two views, not from the account Uptime Goblin runs as: natively that is the `uptime-goblin` account, which opens the key itself; under Docker Compose without user-namespace remapping it is host uid 1000 with gid 1000, and while Uptime Goblin runs any process of that uid and gid can read the Compose secret through `/proc/<pid>/root`, as it can read `GOBLIN_PASSWORD` through `/proc/<pid>/environ`, and read and change Uptime Goblin's data volume through `/proc/<pid>/root/var/lib/uptime-goblin` (`/app/data` before 1.5)"
    )
  );
  const notes = flat(
    read('compose.secret.yaml')
      .split('\n')
      .filter(line => line.startsWith('#'))
      .map(line => line.replace(/^# ?/, ''))
      .join('\n')
  );
  for (const text of [
    'any process of host uid 1000 that runs with gid 1000 too (as the processes of a login whose own group is gid 1000 do) can read the mounted key through /proc/<pid>/root/run/secrets/orbit_secret_key',
    "read and change Uptime Goblin's data volume through /proc/<pid>/root/var/lib/uptime-goblin (measured with Docker 29.4.0 on OrbStack, at /app/data before 1.5).",
    "Keeping this directory root's (mode 0700) keeps only the files from being opened by their paths. What keeps the key from that account is a host where uid 1000 is no one's",
    'With a root-only directory, run every command here, and every docker compose command, as root in it',
    "Uptime Goblin's processes (Docker's init and Node, which hold no capabilities) run as it, with gid 1000:",
    'root, and every account that can use Docker (docker exec), can read it in any case.',
  ])
    assert.ok(notes.includes(text), text);
  assert.doesNotMatch(notes, /keep the file in a directory that account cannot enter/);
  assert.doesNotMatch(notes, /To keep it from that account, keep this whole directory/);
  assert.doesNotMatch(notes, /any process of host uid 1000 can read/);
  const changelog = flat(read('CHANGELOG.md'));
  assert.ok(
    changelog.includes(
      "A Compose project directory only root can enter keeps only the files from being opened by their paths; what keeps the key from that account is a host where uid 1000 is no one's"
    )
  );
  assert.ok(
    changelog.includes(
      'whose `chown` must then name the remapped uid); root, and every account that can use Docker, can read it in any case.'
    )
  );
  assert.doesNotMatch(changelog, /to keep the key from it, keep the Compose project directory/);
  assert.ok(
    changelog.includes(
      "run as it, with gid 1000: while Uptime Goblin runs, any process of host uid 1000 that runs with gid 1000 too (as the processes of a login whose own group is gid 1000 do) can read the mounted key through `/proc/<pid>/root/run/secrets/orbit_secret_key` and the `GOBLIN_PASSWORD` Uptime Goblin started with through `/proc/<pid>/environ`, and read and change Uptime Goblin's data volume through `/proc/<pid>/root/var/lib/uptime-goblin` (`/app/data` before 1.5)"
    )
  );
  assert.doesNotMatch(changelog, /any process of host uid 1000 can read/);
});

// compose.yaml's limits are its own (packaging.test.mjs checks the file and what Compose makes of
// it): the docs change them with an override file, name the one host where Docker refuses any
// CPU limit, and claim no more than Uptime Goblin's start check does (it reads the limits under cgroup
// v2 only). compose.yaml said one CPU "fits every host"; security.md that Uptime Goblin warns "when
// either is allowed after all", which a cgroup v1 host never heard.
test('docs: the container limits are changed by an override file, the host without CPU limits is named, and the start check claims only what it reads', () => {
  for (const file of ['compose.yaml', '.env.example', 'README.md', 'CHANGELOG.md'].concat(
    fs.readdirSync(path.join(repository, 'docs')).map(name => `docs/${name}`)
  ))
    assert.doesNotMatch(
      read(file),
      /GOBLIN_MEM_LIMIT|GOBLIN_CPUS|GOBLIN_PIDS_LIMIT|fits every host/,
      file
    );
  const compose = flat(section(read('docs/installation.md'), 'Docker Compose'));
  for (const text of [
    'They are written in `compose.yaml` itself, not read from `.env`',
    'To change one, set it in a `compose.override.yaml` beside `compose.yaml`',
    '`COMPOSE_FILE=compose.yaml:compose.secret.yaml:compose.override.yaml`',
    'on a cgroup v1 or hybrid host it cannot verify them, and refuses too',
  ])
    assert.ok(compose.includes(text), text);
  const troubleshooting = read('docs/troubleshooting.md');
  assert.match(
    troubleshooting,
    /^\| `docker compose up` fails: "NanoCPUs can not be set, as your kernel does not support CPU CFS scheduler or the cgroup is not mounted" \| .* limit Uptime Goblin to one CPU with a CPU set instead: put `cpus: 0` and `cpuset: '0'` under `services:` → `uptime-goblin:` in `compose\.override\.yaml`/m
  );
  assert.match(
    troubleshooting,
    /^\| … limit: cannot be verified \(Uptime Goblin reads its limits under cgroup v2 only, which it did not find here \(cgroup v1 or a hybrid layout\)\) … \| /m
  );
  const security = flat(read('docs/security.md'));
  assert.doesNotMatch(security, /warns at every start when either is allowed after all/);
  assert.ok(
    security.includes(
      'on a cgroup v1 or hybrid host it cannot verify its memory, CPU and process limits either, and refuses to start unless `GOBLIN_ALLOW_UNLIMITED` names them'
    )
  );
  assert.ok(
    upgradeNotes().some(
      note =>
        note.startsWith('- **Docker Compose limits the container**') &&
        note.includes('"NanoCPUs can not be set') &&
        note.includes("put `cpus: 0` and `cpuset: '0'` in `compose.override.yaml` there")
    )
  );
});

// B48 (the maintainer's decision of 2026-10-11): a supervised Uptime Goblin refuses to start (78) unless its memory,
// CPU and process limits are in force in its own cgroup, or GOBLIN_ALLOW_UNLIMITED names them, and
// a CPU set counts only where Uptime Goblin verifies at its start that it applies (maintainer decision D21, PU5), every
// CPU it names online (independent review F-01). These checks: every refusal and start line the start
// prints for the decision table's cases, and for
// supervision and the setting, has a row in troubleshooting.md's "Resource limits" whose message
// cell matches it (literal pieces in order, … for what varies, the first piece at its start); the
// setting and supervision are documented where the environment settings are; each place that gives
// the CPU-set form says it counts only as verified; the placement is said as it is (after the
// modules have loaded, before the start sequence), never as "before anything"; Compose's retry of
// a refusal is said; the CHANGELOG names the change and how to check before upgrading; and none of
// the warning lines of before is left. goblin-admin's one-off commands (B48-C) are not part of this
// change, and nothing here promises their check.
test('docs: a row per resource-limits line, GOBLIN_ALLOW_UNLIMITED and --supervised documented, the CPU set verified at start, the placement and the Compose retry as they are (B48)', async t => {
  const { superviseLimits, supervision, supervisedSetting } = await import(
    '../lib/resource-limits.mjs'
  );
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-limits-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  let n = 0;
  // A cgroup as the kernel shows it (see test/resource-limits.test.mjs), and what Uptime Goblin prints.
  const lines = ({
    controllers = 'cpu memory pids',
    files = {},
    online = '0-3',
    membership = '0::/orbit',
    allow,
    platform = 'linux',
  }) => {
    const root = path.join(base, String(n++));
    fs.mkdirSync(path.join(root, 'proc', 'self'), { recursive: true });
    fs.writeFileSync(path.join(root, 'proc', 'self', 'cgroup'), `${membership}\n`);
    fs.mkdirSync(path.join(root, 'sys', 'devices', 'system', 'cpu'), { recursive: true });
    fs.writeFileSync(path.join(root, 'sys', 'devices', 'system', 'cpu', 'online'), `${online}\n`);
    const directory = path.join(root, 'cgroup', 'orbit');
    fs.mkdirSync(directory, { recursive: true });
    if (controllers !== null)
      fs.writeFileSync(path.join(directory, 'cgroup.controllers'), `${controllers}\n`);
    for (const [name, text] of Object.entries({
      'memory.max': '1073741824',
      'pids.max': '256',
      'cpu.max': '100000 100000',
      ...files,
    }))
      if (text !== null) fs.writeFileSync(path.join(directory, name), `${text}\n`);
    const decision = superviseLimits({
      env: allow ? { GOBLIN_ALLOW_UNLIMITED: allow } : {},
      supervised: true,
      proc: path.join(root, 'proc'),
      cgroupRoot: path.join(root, 'cgroup'),
      sys: path.join(root, 'sys'),
      platform,
    });
    return [...(decision.refusal ?? []), ...decision.warnings];
  };
  const cpuSet = (own, effective, online = '0-3') => ({
    controllers: 'cpuset cpu memory pids',
    files: { 'cpu.max': 'max 100000', 'cpuset.cpus': own, 'cpuset.cpus.effective': effective },
    online,
  });
  const printed = [
    ...lines({ files: { 'memory.max': 'max', 'pids.max': 'max', 'cpu.max': 'max 100000' } }),
    ...lines({ controllers: 'cpu', files: { 'memory.max': null, 'pids.max': null } }),
    ...lines({ controllers: 'memory pids', files: { 'cpu.max': null } }),
    ...lines({ files: { 'memory.max': '9223372036854771712' } }),
    ...lines(cpuSet('0', '0', '0')),
    ...lines(cpuSet('', '0-3')),
    ...lines(cpuSet('0-3', '0-3')),
    ...lines(cpuSet('7', '0-3')),
    ...lines(cpuSet('17', '0-3', '0-17')),
    // A set that names CPUs the host does not have online: wholly, and besides one it has.
    ...lines(cpuSet('8', '8')),
    ...lines(cpuSet('0,8', '0')),
    ...lines({ ...cpuSet('0,8', '0'), allow: 'cpu' }),
    ...lines({ controllers: null }),
    ...lines({ platform: 'darwin' }),
    ...lines({ files: { 'memory.max': 'x', 'pids.max': 'x', 'cpu.max': '0 100000' } }),
    ...lines({ files: { 'cpu.max': null } }),
    ...lines({ ...cpuSet('x', '0'), files: { 'cpu.max': 'max 100000', 'cpuset.cpus': 'x' } }),
    ...lines({ files: { 'pids.max': 'max' }, allow: 'pids,cpu' }),
  ];
  for (const attempt of [
    () => superviseLimits({ env: { GOBLIN_ALLOW_UNLIMITED: 'all' } }),
    () => supervisedSetting('bogus'),
    () => supervision({ argv: ['--supervise'], env: {} }),
  ])
    try {
      attempt();
      assert.fail('refused');
    } catch (error) {
      assert.equal(error.refusal, true);
      printed.push(error.message);
    }
  printed.push(
    ...supervision({ argv: ['--supervised'], env: { GOBLIN_SUPERVISED: '0' } }).warnings
  );
  // Each row's message cell: alternatives separated by ", or " (or the whole cell), each literal
  // text with … for what varies.
  const rows = section(read('docs/troubleshooting.md'), 'Resource limits')
    .split('\n')
    .filter(line => line.startsWith('| ') && !line.startsWith('| Message |'));
  const cells = rows.map(line => line.slice(2, line.indexOf(' | ')));
  const alternatives = cells.flatMap(cell => [cell, ...cell.split(', or ')]);
  const matches = (line, alternative) => {
    const pieces = alternative.split('…').map(piece => piece.trim());
    let at = 0;
    for (const [k, piece] of pieces.entries()) {
      if (!piece) continue;
      const found = line.indexOf(piece, at);
      if (found === -1 || (k === 0 && found !== 0)) return false;
      at = found + piece.length;
    }
    return true;
  };
  const unmatched = [...new Set(printed)].filter(
    line => !alternatives.some(alternative => matches(line, alternative))
  );
  assert.ok(printed.length >= 40, printed.length);
  assert.ok(printed.some(line => line.startsWith('Uptime Goblin runs without a process limit')));
  assert.deepEqual(unmatched, []);
  // The rows name the exit status and both ways out.
  const table = flat(section(read('docs/troubleshooting.md'), 'Resource limits'));
  for (const text of [
    'refuses to start (exit status 78)',
    'unless `GOBLIN_ALLOW_UNLIMITED` names it',
    '`GOBLIN_ALLOW_UNLIMITED=cpu`',
    '`GOBLIN_ALLOW_UNLIMITED=memory,cpu,pids`',
    'Docker Compose restarts the container, so the refusal repeats until you stop it',
  ])
    assert.ok(table.includes(text), text);
  // The settings: where they are read, their grammar, no all, read-only in the web app.
  const row = name =>
    flat(
      read('docs/configuration.md')
        .split('\n')
        .find(line => line.startsWith(`| \`${name}\` |`)) ?? ''
    );
  for (const text of [
    '`memory`, `cpu` and `pids`, separated by commas, each at most once, in lower case and without spaces',
    'There is no `all`.',
    'refuses the start (78), also under `npm start`',
    "Read only from Uptime Goblin's environment at its start",
    'never from `config.json` or the web app, where **Configure → System** shows it and the limits it found, read-only',
  ])
    assert.ok(row('GOBLIN_ALLOW_UNLIMITED').includes(text), text);
  for (const text of [
    'which also start Uptime Goblin with `--supervised` on its command line',
    'This setting cannot turn `--supervised` off',
    'refuses the start (78), with `--supervised` or without it',
  ])
    assert.ok(row('GOBLIN_SUPERVISED').includes(text), text);
  const installation = read('docs/installation.md');
  const limits = flat(section(installation, 'Resource limits'));
  for (const text of [
    'refuses to start (exit status 78) while one of them is not in force, unless `GOBLIN_ALLOW_UNLIMITED` names it',
    "after its modules have loaded and its launch setup has run, and before the start sequence takes `goblin.lock` or reads Uptime Goblin's data; it does not say that nothing was read or written before it",
    'Started by hand (`npm start`, `node server.mjs`) it checks no limit, as before',
    '**Supervision.** The systemd unit and the Docker image start Uptime Goblin with `--supervised` on its command line',
    'A value that is neither yes nor no (`bogus`, `enabled`, a space before the `1`) refuses the start (78), with `--supervised` or without it',
    'Only a start without `--supervised` and without `GOBLIN_SUPERVISED=1` is unsupervised and checks nothing',
    'Uptime Goblin checks that each limit is applied, not that it is small',
    'There is no `all`',
    'no page or API sets it, and `config.json` cannot hold it',
    "the CPU set counts as Uptime Goblin's CPU limit only where Uptime Goblin verifies at its start that it applies",
    "Uptime Goblin's own `cpuset.cpus` is not empty, is a CPU list, and every CPU it names is one the host has online (`/sys/devices/system/cpu/online`)",
    'So each set is some, not all, of the CPUs the host has online: holding fewer CPUs than the host is not enough.',
    "A set that names a CPU the host does not have online (an offline CPU, one the host does not have, or one hidden from what Uptime Goblin sees in `/sys`, as LXCFS can hide the host's CPUs in an LXC) cannot be verified, however few CPUs it holds",
    'Uptime Goblin then refuses to start for want of a CPU limit, unless `GOBLIN_ALLOW_UNLIMITED=cpu`',
    "give one of the CPUs that message lists instead, such as `cpuset: '2'`",
    "Under systemd the unit is left failed (`RestartPreventExitStatus=78`), and the installer's verification names the refusal.",
    "Docker Compose's `restart: unless-stopped` restarts the container after a refusal too",
    'this release does not change the values',
    'Not measured for this release:',
  ])
    assert.ok(limits.includes(text), text);
  assert.ok(
    flat(section(installation, 'Docker Compose')).includes(
      "unlike the systemd unit's `RestartPreventExitStatus=78`, Compose retries a refusal (78) too"
    )
  );
  assert.match(read('compose.yaml'), /^ {4}restart: unless-stopped$/m);
  assert.ok(
    flat(read('compose.yaml').replace(/^\s*# ?/gm, '')).includes(
      "unlike the systemd unit's RestartPreventExitStatus=78, Compose retries it"
    )
  );
  const nano = flat(
    read('docs/troubleshooting.md')
      .split('\n')
      .find(line => line.startsWith('| `docker compose up` fails: "NanoCPUs can not be set'))
  );
  assert.ok(
    nano.includes(
      'Uptime Goblin counts that set only where it verifies at its start that the set applies'
    )
  );
  assert.ok(flat(read('docs/security.md')).includes('start Uptime Goblin with `--supervised`'));
  // security.md's summary says what cpuLimit and cpuSet decide (independent review D-01): which CPUs the
  // sets name, not only how many, beside a quota that counts by itself; the placement, the
  // setting and the platforms not qualified stay as they were.
  const securityParagraph = read('docs/security.md')
    .split('\n\n')
    .find(text => text.startsWith('**Resource limits.**'));
  assert.ok(securityParagraph, 'the Resource limits paragraph of docs/security.md');
  const securityLimits = flat(securityParagraph);
  for (const text of [
    'A `cpu.max` quota Uptime Goblin reads as valid (positive, not `max`) is a CPU limit by itself, whatever the CPU set;',
    "its own cgroup's set (`cpuset.cpus`) and the CPUs it runs on (`cpuset.cpus.effective`) are both CPU lists it can read, neither empty",
    'every CPU its own set names is one the host has online (as Uptime Goblin sees `/sys/devices/system/cpu/online`)',
    'the CPUs it runs on are all within its own set',
    'each set is some, not all, of the CPUs the host has online',
    'Holding fewer CPUs than the host is not enough',
    'a set that names a CPU the host does not have online cannot be verified',
    "after its modules have loaded, and before the start sequence takes `goblin.lock` or reads Uptime Goblin's data",
    '`GOBLIN_ALLOW_UNLIMITED` lowers a security control',
    'Docker in an LXC, rootless Docker, cgroup v1, one-CPU hosts and CPU hot-plug are not qualified',
  ])
    assert.ok(securityLimits.includes(text), text);
  assert.doesNotMatch(
    securityLimits,
    /the CPUs it runs on within it, fewer than the host has online/
  );
  assert.ok(
    flat(read('docs/architecture.md')).includes(
      'an argument to `server.mjs` other than `--supervised`'
    )
  );
  // The CHANGELOG: the entries and the upgrade note with the check before upgrading.
  const releaseText = flat(changelog().release);
  for (const text of [
    '- **A supervised Uptime Goblin refuses to start without its memory, CPU and process limits (security; breaking for installs without them).**',
    '- **The limits check cannot be turned off from the environment (security).**',
    'names only CPUs the host has online, holds every CPU Uptime Goblin runs on and has fewer CPUs than the host has online',
    'a set that names a CPU the host does not have online cannot be verified, however few CPUs it holds',
  ])
    assert.ok(releaseText.includes(text), text);
  assert.ok(
    upgradeNotes().some(
      note =>
        note.startsWith(
          '- **Supervised installs need their memory, CPU and process limits in force (breaking).**'
        ) &&
        note.includes(
          'Check before upgrading with the commands in [resource limits](docs/installation.md#resource-limits)'
        ) &&
        note.includes('`grep GOBLIN_SUPERVISED /etc/uptime-goblin.env` before upgrading')
    )
  );
  // Nothing of the warnings of before, no "before anything" for this check, and no promise of
  // goblin-admin's one-off check.
  for (const file of [
    'README.md',
    'CHANGELOG.md',
    '.env.example',
    'compose.yaml',
    'compose.secret.yaml',
    'Dockerfile',
    'deploy/uptime-goblin.service',
    'lib/resource-limits.mjs',
    'server.mjs',
    ...fs.readdirSync(path.join(repository, 'docs')).map(name => `docs/${name}`),
  ])
    for (const pattern of [
      /(?:Orbit|Uptime Goblin) runs with no limit on its/,
      /(?:Orbit|Uptime Goblin) cannot check its memory, process and CPU limits/,
      /another value is said at the start and means off/,
      /names a missing limit at every start/,
      /refuses \(78\) before it reads or writes anything/,
      /Before anything else is read, written or taken/,
      /limits back at every start, before anything else/,
      /goblin-admin limits\b/,
    ])
      assert.doesNotMatch(flat(read(file)), pattern, file);
});

// Independent review F-02-R2 and its disposition: after a failed start the installer shows the status,
// the recent log and the rollback, and recommends no setting from what the journal holds, since it
// does not establish which start wrote a line (test/installer/installer.test.mjs checks what it
// prints). The troubleshooting row and the unreleased CHANGELOG say so, and no text promises again
// a resource-limit paragraph bounded by a journal position or a second.
test('docs: after a failed start the installer shows the status, the log and the rollback, and no text promises a resource-limit paragraph from the journal (F-02-R2)', () => {
  const installer = read('deploy/install.sh');
  for (const removed of [
    '--show-cursor',
    '--after-cursor',
    'refused to start because a memory, CPU or process limit',
    'add GOBLIN_ALLOW_UNLIMITED with the limits the log names',
  ])
    assert.ok(!installer.includes(removed), removed);
  const logLine = '\njournalctl --unit=uptime-goblin.service --lines=50 --no-pager >&2 || true\n';
  assert.equal(installer.split(logLine).length, 2, 'the recent log, read once');
  const row = flat(
    read('docs/troubleshooting.md')
      .split('\n')
      .find(line =>
        line.startsWith('| `uptime-goblin.service failed (…) and systemd will not restart it` |')
      ) ?? ''
  );
  const entry = flat(
    changelog()
      .release.split('\n')
      .find(line =>
        line.startsWith(
          '- **A supervised Uptime Goblin refuses to start without its memory, CPU and process limits'
        )
      ) ?? ''
  );
  for (const [text, said] of [
    [
      row,
      "The installer shows the status and the log lines as the journal returns them, then rolls back: it does not work out from them which start refused or why, and recommends no setting of its own, since a line in that log may be an earlier start's.",
    ],
    [
      entry,
      "After a failed start the native installer shows the service status and the recent log, then rolls back, as after any failed start: it does not infer from the journal which start refused or why, and recommends no `GOBLIN_ALLOW_UNLIMITED` of its own, since a log line may be an earlier start's",
    ],
  ])
    assert.ok(text.includes(said), said);
  for (const [name, text] of [
    ['docs/troubleshooting.md', read('docs/troubleshooting.md')],
    ['docs/installation.md', read('docs/installation.md')],
    ['CHANGELOG.md (1.5)', changelog().release],
  ])
    for (const pattern of [
      /position it (took|takes) just before the restart/,
      /a paragraph that names `GOBLIN_ALLOW_UNLIMITED`/,
      /installer names a refusal for want of a limit/,
      /even in the same second, (does not count|gives no paragraph)/,
    ])
      assert.doesNotMatch(flat(text), pattern, name);
});

// Review round 3: with the limits written in compose.yaml, a host where Docker refuses any CPU
// limit takes cpus: 0 in compose.override.yaml, which Compose reads by itself only for a command
// given no -f while .env sets no COMPOSE_FILE. The key check, the copy and MOVE recipes and the
// key reset pass -f compose.yaml, each recipe appends a COMPOSE_FILE line without the override
// (and the MOVE recipe said a second such line "does no harm"), and the snapshot restore after a
// code rollback passes --cpus 1: on such a host each still gave Docker a CPU limit, and the docs
// said only to put cpus: 0 in the override. Wherever such a command is printed, the docs now say
// what to add or leave out there (packaging.test.mjs checks what Compose makes of it).
test('docs: where Docker refuses any CPU limit, the -f compose.yaml commands, the recipes’ COMPOSE_FILE lines and the --cpus line say how to run them', () => {
  const add = 'add `-f compose.override.yaml` after `-f compose.yaml`';
  const installation = read('docs/installation.md');
  const troubleshooting = read('docs/troubleshooting.md');
  const override = read('compose.secret.yaml');
  const notes = flat(
    override
      .split('\n')
      .filter(line => line.startsWith('#'))
      .map(line => line.replace(/^# ?/, ''))
      .join('\n')
  );
  // Each file that prints a docker compose -f compose.yaml command says to add the override.
  for (const [name, text, phrase] of [
    ['docs/installation.md', flat(installation), add],
    ['docs/troubleshooting.md', flat(troubleshooting), add],
    ['compose.secret.yaml', notes, 'add -f compose.override.yaml after -f compose.yaml'],
  ]) {
    assert.match(read(name), /docker compose -f compose\.yaml/, name);
    assert.ok(text.includes(phrase), `${name}: ${phrase}`);
  }
  const key = flat(section(installation, 'Encryption key'));
  for (const text of [
    'which Compose reads by itself only for a command given no `-f` while `.env` sets no `COMPOSE_FILE`, write `COMPOSE_FILE=compose.yaml:compose.secret.yaml:compose.override.yaml` wherever a recipe below writes `COMPOSE_FILE=compose.yaml:compose.secret.yaml` (the last `COMPOSE_FILE` line in `.env` counts)',
    `${add} in the check and in the copy and \`MOVE\` recipes.`,
    'The `COMPOSE_FILE` line comes first (a second line that names the same files does no harm: the last `COMPOSE_FILE` line counts).',
    'give `-f compose.yaml -f compose.secret.yaml` to every `docker compose` command (and `-f compose.override.yaml` when you have one)',
  ])
    assert.ok(key.includes(text), text);
  // Before the check, the first command that passes -f compose.yaml.
  assert.ok(key.indexOf(add) < key.indexOf('docker compose -f compose.yaml $('));
  const compose = flat(section(installation, 'Docker Compose'));
  assert.ok(
    compose.includes(
      'Compose reads the file by itself only for a command given no `-f` while `.env` sets no `COMPOSE_FILE`'
    )
  );
  for (const [name, text] of [
    ['docs/installation.md', flat(installation)],
    ['compose.secret.yaml', notes],
  ]) {
    assert.doesNotMatch(text, /a second such line in `?\.env`? does no harm/, name);
    assert.doesNotMatch(text, /Compose reads the file by itself only while/, name);
  }
  // Every docker run line with --cpus: the paragraph before its block says to leave it out.
  let lines = 0;
  for (const match of installation.matchAll(/```sh\n([\s\S]*?)```/g))
    for (const line of match[1].split('\n').filter(line => /^docker run .*--cpus /.test(line))) {
      lines += 1;
      const before = installation.slice(
        installation.lastIndexOf('\n\n', match.index - 3),
        match.index
      );
      assert.ok(flat(before).includes('leave out `--cpus 1`'), line);
    }
  assert.equal(lines, 1);
  // The troubleshooting row and the upgrade note.
  const row = flat(
    troubleshooting
      .split('\n')
      .find(line => line.startsWith('| `docker compose up` fails: "NanoCPUs can not be set'))
  );
  for (const text of [
    'Compose reads that file by itself only for a command given no `-f` while `.env` sets no `COMPOSE_FILE`.',
    '`COMPOSE_FILE=compose.yaml:compose.secret.yaml:compose.override.yaml`, also in place of the `COMPOSE_FILE` line each [key recipe](installation.md#encryption-key) writes',
    `${add} in the key check, the copy and \`MOVE\` recipes and the key reset under Compose`,
    'leave `--cpus 1` out of the `docker run` line that restores a snapshot after a code rollback',
  ])
    assert.ok(row.includes(text), text);
  assert.ok(
    flat(troubleshooting).includes(
      `(the \`-f\` pair is what \`COMPOSE_FILE=compose.yaml:compose.secret.yaml\` does; with a \`compose.override.yaml\`, ${add});`
    )
  );
  assert.doesNotMatch(troubleshooting, /\(the `-f` pair is what `COMPOSE_FILE` does\)/);
  assert.ok(
    upgradeNotes().some(
      note =>
        note.startsWith('- **Docker Compose limits the container**') &&
        note.includes(`${add} in the key check, the copy and \`MOVE\` recipes and the key reset`) &&
        note.includes('also in place of the line each key recipe writes') &&
        note.includes('leave `--cpus 1` out of the `docker run` line that restores a snapshot')
    )
  );
  assert.ok(
    notes.includes('Then, with COMPOSE_FILE set as above (the last such line in .env counts)')
  );
  // .env.example's COMPOSE_FILE line, which leaves the override out, says to add it.
  assert.ok(
    flat(read('.env.example').replace(/^# ?/gm, '')).includes(
      "COMPOSE_FILE=compose.yaml:compose.secret.yaml With a compose.override.yaml (it holds cpus: 0 and cpuset: '0' where Docker refuses any limit on CPU time), end that line with :compose.override.yaml"
    )
  );
  // compose.secret.yaml says it before its first such command.
  assert.ok(
    override.indexOf('add -f compose.override.yaml after -f compose.yaml') <
      override.indexOf('#   docker compose -f compose.yaml')
  );
  assert.ok(
    notes.includes(
      'is read by Compose itself only for a command given no -f while .env sets no COMPOSE_FILE. With one, write this line in place of each COMPOSE_FILE line below (the last such line in .env counts): COMPOSE_FILE=compose.yaml:compose.secret.yaml:compose.override.yaml'
    )
  );
});

// A start takes goblin.lock (creating it, and the data directory, where they are missing) before
// it reads the key or finds a trigger or view planted in a database, and on a disk already full
// it deletes its space reserve (run/space-reserve) before that; goblin-admin snapshot, migrate
// --apply, restore-snapshot and key reset take goblin.lock before they check the live files or
// the key. The docs said such a refusal wrote or changed nothing, and the two snapshot refusals
// printed "Nothing was written." and "Nothing was changed.": each now says what was not written,
// or that only goblin.lock (and the reserve) changed. The same held for the key_missing row and
// the key reset texts of docs/troubleshooting.md, the reset whose audit entry fails in
// docs/installation.md, and key reset's two messages (a reset that generated <data>/secret.key
// for --use-data-dir-key, then failed to write its entry, also left that file).
test('docs: a refusal that comes after goblin.lock is taken is not said to write or change nothing', () => {
  const changelog = flat(read('CHANGELOG.md')),
    installation = flat(read('docs/installation.md')),
    architecture = flat(read('docs/architecture.md')),
    troubleshooting = flat(read('docs/troubleshooting.md')),
    key = read('lib/cli/commands/key.mjs');
  for (const [text, stale] of [
    [troubleshooting, 'and set its source again; nothing was written.'],
    [troubleshooting, 'changes nothing without `--use-data-dir-key`'],
    [troubleshooting, 'a reset that cannot record it changes nothing'],
    [installation, 'except `key reset`, which changes nothing then'],
    [key, 'the key. Nothing was changed.`'],
    [key, 'Nothing was changed: the keys and their audit entry are saved together.'],
    [changelog, '`schema_planted`) before anything is written'],
    [changelog, 'so a refused start changes nothing'],
    [installation, '"… cannot be read: EACCES"); nothing is written'],
    [architecture, 'a key refusal exits 78 with nothing changed'],
    [architecture, 'so every refusal leaves the data directory as it was'],
    [changelog, '`key reset` changes nothing rather than generate'],
    [installation, '`key reset` changes nothing (exit status 2)'],
    // Step 4's refusals come after step 2 took goblin.lock (and, on a full disk, after the space
    // reserve went), as the key refusal on the same line says.
    [architecture, 'refuse, still writing nothing'],
  ])
    assert.ok(!text.includes(stale), stale);
  const lockFirst = 'nothing but `goblin.lock`, which it creates where it is missing';
  for (const [text, scoped] of [
    [changelog, `\`schema_planted\`) having written ${lockFirst}`],
    [changelog, 'a key refusal comes after the start took `goblin.lock`, which it creates where'],
    [installation, `"… cannot be read: EACCES"); by then the start has written ${lockFirst}`],
    [
      architecture,
      'a key refusal exits 78, and the data directory then differs only by `goblin.lock`',
    ],
    [
      architecture,
      'or when its data comes from a newer release, each before this step writes anything (exit 78; the data directory then differs only as after a key refusal, below)',
    ],
    [changelog, '`key reset` refuses, writing no key and no keyring, rather than generate'],
    [installation, '`key reset` refuses (exit status 2), writing no key and no keyring'],
    [
      troubleshooting,
      `and set its source again; the refused start wrote ${lockFirst} (on a disk already full it has also deleted its space reserve, \`run/space-reserve\`).`,
    ],
    [
      troubleshooting,
      'refuses without `--use-data-dir-key`, writing no key and leaving the keyring as it was (it has taken `goblin.lock` by then, which it creates where it is missing)',
    ],
    [
      troubleshooting,
      'a reset that cannot record it leaves the keyring as it was (exit status 1). A `secret.key` it generated in the data directory for `--use-data-dir-key` stays there',
    ],
    [
      installation,
      'except `key reset`, which then leaves the keyring as it was (exit status 1; a `secret.key` it generated in the data directory for `--use-data-dir-key` stays)',
    ],
    [key, 'the key. No key was written and the keyring was not changed.`'],
    [key, 'The keyring was not changed: the keys and their audit entry are saved together.'],
    [
      key,
      ', which this reset generated, stays; a reset run again with --use-data-dir-key uses it.',
    ],
  ])
    assert.ok(text.includes(scoped), scoped);
  const snapshot = read('lib/db/snapshot.mjs');
  assert.doesNotMatch(
    snapshot,
    /No snapshot was taken: \$\{error\.message\}\. Nothing was written\./
  );
  assert.doesNotMatch(snapshot, /cannot be set aside\. Nothing was changed\./);
});

// The snapshot id in the restore lines was `<id>`, which a shell reads as redirections: pasted
// as printed by root in a folder holding a file named id, `sudo -u uptime-goblin node …/goblin-admin.mjs
// restore-snapshot <id> --data-dir /var/lib/uptime-goblin` became `restore-snapshot /var/lib/uptime-goblin`
// without --data-dir, with its output going to a file named --data-dir, which the root shell
// created or emptied (round-3 finding, as item 3 found for goblin-admin's own refusal). The
// placeholders of these lines are plain words now (SNAPSHOT_ID, and PROJECT for the Compose
// project), which reach the command as they are.
test('docs: a restore-snapshot command line holds no < or >: pasted as printed, its placeholders reach the command as words and no file is made', t => {
  const lines = [];
  for (const name of [
    'README.md',
    'CHANGELOG.md',
    ...fs.readdirSync(path.join(repository, 'docs')).map(file => `docs/${file}`),
  ].filter(name => name.endsWith('.md'))) {
    let fenced = false;
    read(name)
      .split('\n')
      .forEach((line, index) => {
        const where = `${name}:${index + 1}`;
        if (/^\s*```/.test(line)) return void (fenced = !fenced);
        for (const text of fenced ? [line] : [...line.matchAll(/`([^`]+)`/g)].map(m => m[1]))
          if (/^(sudo|docker) /.test(text) && text.includes(' restore-snapshot '))
            lines.push({ where, line: text });
      });
  }
  // docs/installation.md: native, Compose, native after a rollback, docker run after a
  // rollback; docs/authentication.md: native.
  assert.ok(lines.length >= 5, JSON.stringify(lines));
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-restore-paste-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const bin = path.join(base, 'bin');
  fs.mkdirSync(bin);
  // Stand-ins for sudo and docker: each records its words, one to a line, and writes nothing else.
  for (const command of ['sudo', 'docker'])
    fs.writeFileSync(path.join(bin, command), '#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$WORDS"\n', {
      mode: 0o755,
    });
  for (const [index, { where, line }] of lines.entries()) {
    assert.doesNotMatch(line, /[<>]/, `${where}: ${line}`);
    const cwd = path.join(base, String(index));
    fs.mkdirSync(cwd);
    // The words the old placeholders redirected from, and the snapshot id's placeholder (a file
    // named PROJECT would be project on a file system that ignores case).
    const present = ['id', 'project', 'SNAPSHOT_ID'];
    for (const word of present) fs.writeFileSync(path.join(cwd, word), '');
    const words = path.join(base, `${index}.words`);
    const ran = spawnSync('sh', ['-c', line], {
      cwd,
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, WORDS: words },
    });
    assert.equal(ran.status, 0, `${where}: ${ran.stderr}`);
    assert.deepEqual(fs.readdirSync(cwd).sort(), present.sort(), `${where}: no file made`);
    const said = fs.readFileSync(words, 'utf8').split('\n').slice(0, -1);
    const at = said.indexOf('restore-snapshot');
    assert.equal(said[at + 1], 'SNAPSHOT_ID', `${where}: the snapshot id is a word`);
    // The kept copy's line after a rollback to 1.4.x names the Orbit layout it runs on.
    if (line.startsWith('sudo '))
      assert.deepEqual(
        said.slice(at + 2),
        ['--data-dir', / -u orbit /.test(line) ? '/var/lib/orbit' : '/var/lib/uptime-goblin'],
        where
      );
    else if (line.includes(' -v '))
      assert.equal(
        said[said.indexOf('-v') + 1],
        'PROJECT_orbit-data:/var/lib/uptime-goblin',
        where
      );
  }
  // Left as it is, the placeholder is refused as a snapshot id, as installation.md says.
  const data = path.join(base, 'data');
  fs.mkdirSync(data);
  const refused = spawnSync(
    process.execPath,
    [
      path.join(repository, 'lib/cli/goblin-admin.mjs'),
      'restore-snapshot',
      'SNAPSHOT_ID',
      '--data-dir',
      data,
    ],
    { encoding: 'utf8' }
  );
  assert.equal(refused.status, 1, refused.stderr);
  assert.equal(
    refused.stderr,
    'goblin-admin restore-snapshot: "SNAPSHOT_ID" is not a snapshot id\n'
  );
  assert.ok(
    flat(read('docs/installation.md')).includes(
      'with `SNAPSHOT_ID` replaced by an id that `snapshots` lists (a shell passes the placeholder on as a plain word: left as it is, `restore-snapshot` refuses with `"SNAPSHOT_ID" is not a snapshot id`, exit status 1):'
    )
  );
});

// The command text of the docs: each line of a sh block, and each code span that starts with a
// command. README.md, docs/ and the CHANGELOG's unreleased sections (the released ones stay as
// released).
function documentedCommands() {
  const changelog = read('CHANGELOG.md');
  const texts = [
    ['README.md', read('README.md')],
    ...fs
      .readdirSync(path.join(repository, 'docs'))
      .filter(file => file.endsWith('.md'))
      .map(file => [`docs/${file}`, read(`docs/${file}`)]),
    ['CHANGELOG.md', changelog.slice(0, changelog.indexOf('\n## 1.4.3 '))],
  ];
  const commands = [];
  const command =
    /^(sudo|node|docker|curl|ssh|npm|bash|sh|systemctl|journalctl|env|umask|install|chown|chmod|rm|cp|mv|cat|systemd-creds|systemd-run|openssl|tar|shasum|sha256sum) /;
  for (const [name, text] of texts) {
    let block = null;
    text.split('\n').forEach((line, index) => {
      const where = `${name}:${index + 1}`;
      const fence = /^\s*```(\S*)/.exec(line);
      if (fence) return void (block = block === null ? fence[1] : null);
      if (block !== null) {
        if (['sh', 'bash', 'shell'].includes(block)) commands.push({ where, line });
        return;
      }
      for (const [, span] of line.matchAll(/`([^`]+)`/g))
        if (command.test(span)) commands.push({ where, line: span.replaceAll('\\|', '|') });
    });
  }
  return commands;
}

// The <…> placeholders of a command line that a shell reads as redirections and that more words
// follow: `x <command> --help` reads from a file named command and writes to one named --help, and
// `https://<host>/api/…` writes to /api/… (a placeholder that ends the command is a syntax error
// instead, so nothing runs).
function redirectingPlaceholders(line) {
  const found = [];
  let quote = '';
  for (let p = 0; p < line.length; p++) {
    const c = line[p];
    if (quote) {
      if (c === quote) quote = '';
      else if (quote === '"' && c === '\\') p++;
    } else if (c === "'" || c === '"') quote = c;
    else if (c === '\\') p++;
    else if (c === '<') {
      const placeholder = /^<[^<>\s'"`]*>/.exec(line.slice(p))?.[0];
      if (!placeholder) continue;
      const rest = line.slice(p + placeholder.length);
      if (/^[^\s;|&)]/.test(rest) || /^\s+[^\s;|&)]/.test(rest)) found.push(placeholder);
    }
  }
  return found;
}

// Round 4 made the key and restore lines' placeholders plain words; three documented commands
// still held a <…> placeholder followed by more words (installation.md's `goblin-admin <command>
// --help` and configuration.md's sign-in and sign-out lines, `https://<host>/api/auth/… -o
// /dev/null`), and the CHANGELOG's two `goblin-admin <command> --data-dir /var/lib/uptime-goblin` lines,
// pasted by root, would have created or emptied a file named --data-dir. Their placeholders are
// plain words now (COMMAND, HOST_NAME, TIME_MS), which reach the command as they are.
test('docs: no documented command holds a <…> placeholder that more words follow; pasted as printed, the new placeholders reach the command as words and no file is made', t => {
  const commands = documentedCommands();
  assert.ok(commands.length > 50, String(commands.length));
  // The scan finds the old form, the way a shell reads it.
  assert.deepEqual(redirectingPlaceholders('node lib/cli/goblin-admin.mjs <command> --help'), [
    '<command>',
  ]);
  assert.deepEqual(redirectingPlaceholders("curl -H 'Origin: https://<host>' https://<host>/a"), [
    '<host>',
  ]);
  assert.deepEqual(redirectingPlaceholders('ssh -L 4317:127.0.0.1:4317 <uptime-goblin-host>'), []);
  for (const { where, line } of commands)
    assert.deepEqual(redirectingPlaceholders(line), [], `${where}: ${line}`);
  const pasted = commands.filter(({ line }) => /\b(COMMAND|HOST_NAME|TIME_MS)\b/.test(line));
  // installation.md (1), configuration.md (3), CHANGELOG.md (5).
  assert.equal(pasted.length, 9, JSON.stringify(pasted, null, 1));
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-placeholder-paste-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const bin = path.join(base, 'bin');
  fs.mkdirSync(bin);
  // Stand-ins: each records its words, one to a line, and writes nothing else.
  for (const name of ['sudo', 'docker', 'node', 'curl'])
    fs.writeFileSync(path.join(bin, name), '#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$WORDS"\n', {
      mode: 0o755,
    });
  for (const [index, { where, line }] of pasted.entries()) {
    const cwd = path.join(base, String(index));
    fs.mkdirSync(cwd);
    // The words the old placeholders redirected from, and the new placeholders (on a file system
    // that ignores case, command and COMMAND are one file).
    for (const word of ['command', 'host', 'ms', 'COMMAND', 'HOST_NAME', 'TIME_MS'])
      fs.writeFileSync(path.join(cwd, word), '');
    const present = fs.readdirSync(cwd);
    const words = path.join(base, `${index}.words`);
    const ran = spawnSync('sh', ['-c', line], {
      cwd,
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, WORDS: words },
    });
    assert.equal(ran.status, 0, `${where}: ${ran.stderr}`);
    assert.deepEqual(fs.readdirSync(cwd).sort(), present.sort(), `${where}: no file made`);
    const said = fs.readFileSync(words, 'utf8').split('\n').slice(0, -1);
    if (line.includes(' COMMAND')) {
      const at = said.indexOf('COMMAND');
      assert.notEqual(at, -1, `${where}: COMMAND is a word`);
      if (line.includes(' --data-dir '))
        assert.deepEqual(said.slice(at + 1), ['--data-dir', '/var/lib/uptime-goblin'], where);
      if (line.includes(' --help')) assert.deepEqual(said.slice(at + 1), ['--help'], where);
    } else {
      assert.ok(said.includes('-sS'), where);
      const url = said.find(word => word.startsWith('https://'));
      assert.match(
        url,
        /^https:\/\/HOST_NAME\/api\/(auth\/login|auth\/logout|audit\/export\?format=ndjson&to=TIME_MS)$/,
        where
      );
      if (/\/auth\//.test(url))
        assert.deepEqual(
          said.slice(said.indexOf(url) + 1, said.indexOf(url) + 3),
          ['-o', '/dev/null'],
          where
        );
    }
  }
  // Left as it is, goblin-admin refuses COMMAND as a command, as installation.md says.
  const refused = spawnSync(
    process.execPath,
    [path.join(repository, 'lib/cli/goblin-admin.mjs'), 'COMMAND', '--help'],
    { encoding: 'utf8' }
  );
  assert.equal(refused.status, 2, refused.stderr);
  assert.match(refused.stderr, /^goblin-admin: unknown command "COMMAND"\./);
  const installation = flat(read('docs/installation.md'));
  assert.ok(
    installation.includes(
      '(`node lib/cli/goblin-admin.mjs COMMAND --help`, with `COMMAND` replaced by one of the commands below, gives its options; a shell passes the placeholder on as a plain word: left as it is, goblin-admin answers `unknown command "COMMAND"`, exit status 2)'
    )
  );
  const configuration = flat(read('docs/configuration.md'));
  assert.ok(
    configuration.includes(
      "with `HOST_NAME` replaced by the host name of Uptime Goblin's HTTPS address (with `:port` after it when that is not 443), and `TIME_MS` by the `time` of the oldest entry"
    )
  );
  assert.ok(!configuration.includes('`<host>`') && !configuration.includes('`<ms>`'));
});

// The drop-in reader of the installer's HOST/PORT preflight emulates part of systemd's unit-file
// parser. The installer's comment and docs/installation.md said it read drop-ins "by systemd's
// rules for a unit file (compared with systemd 257)", while systemd 257 read six forms otherwise
// (round-4 verification). The installer now refuses those forms (test/installer/installer.test.mjs
// checks that), and the texts say what it emulates, what it refuses and what it does not emulate.
// Fixer round 1 of the boundary lane: the texts said that systemd reads each refused form
// otherwise, while some inputs of each it reads as the emulation does (/etc/./x, LF CR LF), and the
// installer's comment rested on probes outside the repository. They say now that systemd reads
// some inputs of each form otherwise, and that a form is refused as a whole.
test('docs: the drop-in reader is described as an emulation, with the forms the installer refuses and what it does not emulate', () => {
  const script = read('deploy/install.sh');
  const installer = flat(script.replaceAll('\n# ', ' ')),
    installation = flat(read('docs/installation.md')),
    changelog = flat(read('CHANGELOG.md')),
    row = read('docs/troubleshooting.md')
      .split('\n')
      .find(line =>
        line.startsWith(
          '| HOST and PORT as systemd would give them to Uptime Goblin could not be checked |'
        )
      );
  assert.ok(row);
  assert.ok(!installer.includes("A unit file is read as systemd's config_parse() reads it"));
  assert.ok(
    !installation.includes("read by systemd's rules for a unit file (compared with systemd 257)")
  );
  assert.ok(!installer.includes('boundary review'));
  assert.ok(!installer.includes('six forms which systemd 257 reads otherwise'));
  assert.ok(
    !installation.includes('a form that systemd 257 reads otherwise than the emulation, so the')
  );
  assert.ok(!changelog.includes('a form systemd 257 reads otherwise than'));
  // The forms as the installer prints them, and the same six in each text.
  const forms = Object.fromEntries(
    [...script.matchAll(/^ {2}(nul|bom|lfcr|header|path|pass):'([^']+)',$/gm)].map(m => [
      m[1],
      m[2],
    ])
  );
  assert.deepEqual(Object.keys(forms), ['nul', 'bom', 'lfcr', 'header', 'path', 'pass']);
  assert.ok(
    script.includes(
      'console.error(`HOST and PORT as systemd would give them to Uptime Goblin could not be checked: the drop-in ${named(file)} holds ${forms[form]}, and this installer cannot verify that it reads that form as systemd does. Remove that from the drop-in (sudo systemctl edit uptime-goblin, or edit the file), then run this installer again. ${nothing}`)'
    )
  );
  const plain = text => text.replaceAll('`', '');
  for (const [text, said] of [
    [installation, Object.values(forms).map(form => form.replace(/^an? /, ''))],
    [
      row,
      [
        'NUL character',
        'UTF-8 byte order mark other than at its very start',
        'line feed followed by a carriage return after a line that a backslash continues',
        'section header with a quote, a backslash or a control character in it',
        'EnvironmentFile= path that is not in normal form (a . or .. component, two slashes in a row or a slash at its end) or is longer than systemd takes',
        'PassEnvironment= value with a backslash in it',
      ],
    ],
  ])
    for (const form of said) assert.ok(plain(text).includes(form), form);
  for (const [text, said] of [
    [
      installer,
      "The unit and its drop-ins are read by an emulation of part of systemd's config_parse() (src/shared/conf-parser.c), compared with systemd 257 (Debian 13) on chosen inputs; it is not a copy of systemd's parser, and may read other inputs otherwise.",
    ],
    [
      installer,
      'It refuses ("could not be checked", changing nothing) a drop-in that holds any of six forms. In each, systemd 257 reads some inputs otherwise than this emulation, and with some of those it gave Uptime Goblin another PORT than this emulation found; the form is refused as a whole, also where the two read it alike.',
    ],
    [
      installer,
      '(systemd ignores a value of 4096 bytes or more, its leading - included, once %% is %; it reads /etc//x, /etc/./x, /../etc/x, /etc/x/ and /etc/x/. as /etc/x, as the kernel does for the first three only, and then ignores a path with a .. component or a component over 255 bytes)',
    ],
    [
      installer,
      "It does not emulate the rest of systemd's parser, and in particular not a setting whose own parser rejects its value so that systemd stops reading the rest of that drop-in (ExecStartPre=./x does under systemd 257)",
    ],
    [
      installation,
      "It reads the unit and the drop-ins with an emulation of part of systemd's unit-file parser, checked against systemd 257 (Debian 13) but not a copy of it:",
    ],
    [
      installation,
      'or where a drop-in holds one of six forms, in each of which systemd 257 reads some inputs otherwise than the emulation (the installer refuses the whole form, also an input of it that the two read alike):',
    ],
    [
      installation,
      'The emulation does not cover a setting that systemd rejects in a way that makes it stop reading the rest of that drop-in',
    ],
    [
      changelog,
      "and so too for a drop-in that holds one of six forms, in each of which systemd 257 reads some inputs otherwise than the installer's emulation of its parser",
    ],
    [
      changelog,
      'a `PassEnvironment=` value with a backslash): with an input of each, the check passed while systemd gave Uptime Goblin another `PORT`;',
    ],
  ])
    assert.ok(text.includes(said), said);
});

// Review finding F9: the installer's refusal quotes Uptime Goblin's own message in double quotes, so a
// text that quoted the whole line in double quotes nested them with nothing to tell where
// either ended. Every text renders that line as code, exactly as the installer prints it up to
// the message's end (the rest elided), and the message is the one Uptime Goblin's start refuses with.
// No other quoted message nests its quotes either. And docs/security.md's sentence on what stops
// an install keeps its verb, with "native installer" linking to the native installer's section,
// as every such link does.
test('docs: the installer refusals that quote Orbit’s message are code, nested in no other quotes, and security.md links the native installer to its section (F9)', async t => {
  const { checkBootstrapPassword, readAuthRecord } = await import('../lib/identity/password.mjs');
  const refusedWith = run => {
    try {
      run();
    } catch (error) {
      assert.equal(error.refusal, true);
      return error.message;
    }
    assert.fail('refused');
  };
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docs-quotes-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'auth.json'), '{}');
  const messages = [
    refusedWith(() => checkBootstrapPassword('too short')),
    refusedWith(() => readAuthRecord(directory)),
  ];
  // The installer prints Uptime Goblin's message in double quotes, then a colon and its own text.
  const prefix = 'This release of Uptime Goblin would refuse to start (exit status 78) with "';
  const installer = read('deploy/install.sh');
  assert.equal(installer.split(`${prefix}\${e.message}": `).length - 1, 2, 'the two refusals');

  const texts = {
    'CHANGELOG.md (1.5)': changelog().release,
    'docs/installation.md': read('docs/installation.md'),
    'docs/troubleshooting.md': read('docs/troubleshooting.md'),
    'docs/authentication.md': read('docs/authentication.md'),
    'README.md': read('README.md'),
  };
  const quoted = new Map();
  for (const [name, text] of Object.entries(texts)) {
    const at = [
      ...text.matchAll(
        /This release of Uptime Goblin would refuse to start \(exit status 78\) with "/g
      ),
    ];
    for (const { index } of at) {
      // A code span that opens just before the line and closes after the message's quote.
      assert.equal(text[index - 1], '`', `${name}: code, not a quotation`);
      const end = text.indexOf('`', index);
      const span = text.slice(index, end);
      const match =
        /^This release of Uptime Goblin would refuse to start \(exit status 78\) with "([^"]+)": …$/.exec(
          span
        );
      assert.ok(match, `${name}: ${span}`);
      // The message as Uptime Goblin gives it, or its start before an ellipsis.
      const message = match[1];
      const shown = message.endsWith(' …') ? message.slice(0, -2) : message;
      assert.ok(
        messages.some(full => (message.endsWith(' …') ? full.startsWith(shown) : full === shown)),
        `${name}: ${message}`
      );
      quoted.set(shown, (quoted.get(shown) ?? 0) + 1);
    }
    // No double-quoted text holds another double-quoted message (outside code).
    const prose = text.replace(/```[\s\S]*?```/g, '').replace(/`[^`\n]*`/g, '``');
    assert.doesNotMatch(prose, /"[^"\n]*\bwith "[^"\n]*""/, name);
  }
  // Both refusals are quoted, in the notes, the installation guide and the troubleshooting rows.
  assert.equal(quoted.size, 3, [...quoted.keys()].join('\n'));
  assert.ok(
    [...quoted.keys()].every(shown => messages.some(full => full.startsWith(shown))),
    'each quotes one of the two refusals'
  );

  // docs/security.md: the earlier-installer sentence has its verb, and its link matches its
  // label; every link that says "native installer" goes to the native installer's section.
  const security = flat(read('docs/security.md'));
  assert.ok(
    security.includes(
      'The [native installer](installation.md#native-debian-or-ubuntu-lxc) stops an install that would listen on the network without a trusted proxy until systemd would give Uptime Goblin a yes or no (in `/etc/uptime-goblin.env`, a drop-in or its own environment) or you run it with `--allow-insecure-http`, and it stops every install whose `/etc/uptime-goblin.env` holds the line that earlier 1.5 pre-release installers added by themselves until you decide'
    ),
    security.slice(0, 400)
  );
  for (const name of fs.readdirSync(path.join(repository, 'docs')).filter(n => n.endsWith('.md')))
    for (const link of read(`docs/${name}`).matchAll(/\[(?:the )?native installer\]\(([^)]*)\)/gi))
      assert.equal(
        link[1],
        name === 'installation.md'
          ? '#native-debian-or-ubuntu-lxc'
          : 'installation.md#native-debian-or-ubuntu-lxc',
        `docs/${name}: ${link[0]}`
      );
});

test('docs: an archive backup is restored by commands that undo the backup, check the data with the key and only then start Orbit (BR-3)', () => {
  const text = read('docs/installation.md');
  const backups = section(text, 'Backups');
  const blocks = shellBlocks(backups).map(block => block.trim().split('\n'));
  const find = (what, test) => {
    const found = blocks.filter(lines => lines.some(test));
    assert.equal(found.length, 1, `one ${what} block`);
    return found[0];
  };
  // Native: the archive and the members that the backup writes are the ones extracted.
  const backup = find('native backup', line => line.startsWith('sudo tar -czf '));
  const made = /^sudo tar -czf (\S+) -C \/ (.+)$/.exec(backup.find(l => l.startsWith('sudo tar')));
  assert.ok(made, 'the native backup line');
  const [, archive, members] = made;
  assert.deepEqual(members.split(' '), ['var/lib/uptime-goblin', 'etc/uptime-goblin.env']);
  const restore = find('native restore', line => line.startsWith('sudo tar -xzf '));
  assert.deepEqual(restore, [
    'sudo systemctl stop uptime-goblin.service',
    'sudo mv /var/lib/uptime-goblin /var/lib/uptime-goblin.before-restore',
    'sudo mv /etc/uptime-goblin.env /etc/uptime-goblin.env.before-restore',
    `sudo tar -xzf ${archive} -C / ${members}`,
    'sudo chown -R uptime-goblin:uptime-goblin /var/lib/uptime-goblin',
    'sudo chmod -R u=rwX,go= /var/lib/uptime-goblin',
    'sudo chown root:root /etc/uptime-goblin.env',
    'sudo chmod 600 /etc/uptime-goblin.env',
  ]);
  // The key goes back with the commands the section already gives, then the read-only checks run
  // as the uptime-goblin account, the key status line exactly as the goblin-admin section gives it.
  const prose = flat(backups);
  assert.ok(
    prose.includes('`sudo install -d -o root -g uptime-goblin -m 0750 /etc/uptime-goblin`')
  );
  assert.ok(
    prose.includes(
      '`sudo install -o root -g uptime-goblin -m 0440 /secure-keys/uptime-goblin-secret.key /etc/uptime-goblin/secret.key`'
    )
  );
  assert.ok(prose.includes('with the two `sudo install` commands above'));
  const keyStatus =
    'sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key status --data-dir /var/lib/uptime-goblin';
  assert.ok(
    shellBlocks(section(text, 'goblin-admin', 3)).some(block =>
      block.split('\n').includes(keyStatus)
    ),
    'the goblin-admin section gives the same key status line'
  );
  const checks = find('native check', line => line.includes(' check-data '));
  // Chained with &&: a failing check stops the paste before Uptime Goblin starts.
  assert.deepEqual(checks, [
    `${keyStatus} &&`,
    '  sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs check-data --data-dir /var/lib/uptime-goblin &&',
    '  sudo systemctl start uptime-goblin.service',
  ]);
  assert.ok(blocks.indexOf(restore) < blocks.indexOf(checks), 'the checks follow the extraction');
  // What the prose says the checks print and exit with is what they do, and both only read.
  assert.ok(prose.includes('`key status` should say "The key opens every data key."'));
  assert.ok(read('lib/cli/commands/key.mjs').includes("'The key opens every data key.'"));
  const checkData = read('lib/cli/commands/check-data.mjs');
  assert.ok(
    prose.includes(
      '`check-data` exits with status 1 when the databases are not as this release expects'
    )
  );
  assert.match(checkData, /Exit status 1 when it finds drift/);
  assert.match(checkData, /^export const kind = 'read';$/m);
  // Compose: the volume's current files are kept first, by the backup's own command to another
  // archive; the backup's members are extracted where the backup took them from; then the checks,
  // then the start.
  const composeBackup = find('Compose backup', line =>
    line.includes(' > "$HOME/uptime-goblin-backups/uptime-goblin-data.tar.gz"')
  );
  const saved = composeBackup.find(line =>
    line.includes(" -c 'tar -C /var/lib/uptime-goblin -czf - .' > ")
  );
  assert.ok(saved, 'the Compose backup line');
  const composeArchive = /> "(\$HOME\/uptime-goblin-backups\/[^"]+)"$/.exec(saved)[1];
  const composeRestore = find('Compose restore', line =>
    line.includes('tar -C /var/lib/uptime-goblin -xzf -')
  );
  assert.deepEqual(composeRestore, [
    'umask 077',
    'docker compose stop uptime-goblin',
    saved
      .replace(
        'docker compose run --rm --no-deps --entrypoint',
        'docker compose run --rm --no-deps -T --entrypoint'
      )
      .replace(
        composeArchive,
        '$HOME/uptime-goblin-backups/uptime-goblin-data-before-restore.tar.gz'
      ),
    `docker compose run --rm --no-deps -T --entrypoint sh uptime-goblin -c 'find /var/lib/uptime-goblin -mindepth 1 -delete && tar -C /var/lib/uptime-goblin -xzf - && chmod -R u=rwX,go= /var/lib/uptime-goblin' < "${composeArchive}"`,
    'docker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs key status',
    'docker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs check-data',
    'docker compose start uptime-goblin',
  ]);
});

test('docs: the native installer takes no backup, refuses a downgrade without --allow-downgrade, runs one at a time and survives signals, as deploy/install.sh does (IUR-01, IUR-04 to IUR-06)', () => {
  const installer = read('deploy/install.sh');
  const text = read('docs/installation.md');
  // IUR-01: no backup or snapshot step in the installer, and Uptime Goblin snapshots only a migrating start.
  assert.doesNotMatch(
    installer,
    /goblin-admin(?:\.mjs)? (?:snapshot|migrate)|takeMigrationSnapshot|tar -c/
  );
  assert.match(read('lib/db/control.mjs'), /if \(snapshot && pending\)/);
  const updates = flat(section(text, 'Updates and rollback'));
  assert.ok(
    updates.includes(
      'The installer takes no backup of `/var/lib/uptime-goblin`, and Uptime Goblin snapshots `config.json`, `auth.json` and `control.sqlite` (not `history.sqlite`) only at a start that migrates its databases, so take the backup of step 2 first.'
    )
  );
  assert.match(updates, /^.*2\. Take a consistent backup/);
  // IUR-05: the option, in the installer's usage and in the docs, and the refusal as it prints.
  assert.match(
    installer,
    /^# {3}--allow-downgrade {10}install a release older than the one installed/m
  );
  assert.ok(
    installer.includes(
      '--verify-timeout <seconds>, --allow-downgrade, --restore-orbit-layout (see the start'
    )
  );
  const native = flat(section(text, 'Native Debian or Ubuntu LXC'));
  assert.ok(
    native.includes('`--allow-downgrade` installs the older release anyway, with a warning.')
  );
  assert.ok(
    native.includes(
      '"Uptime Goblin … is installed, and this release, …, is older. Nothing was changed." (compared as Uptime Goblin orders releases: `1.5.0-rc.1` is older than `1.5.0`)'
    )
  );
  assert.ok(
    installer.includes(
      'is installed, and this release, $goblin_new_version, is older. Nothing was changed.'
    )
  );
  assert.ok(installer.includes('compareReleases(next, installed) < 0 ? "older"'));
  // IUR-06: the lock and its message.
  const busy =
    'Another Uptime Goblin installer run is in progress on this host; wait for it to finish, then run this again. Nothing was changed.';
  assert.ok(native.includes(`"${busy}"`));
  assert.ok(installer.includes(`flock -n 9 || goblin_fail '${busy}'`));
  assert.ok(installer.includes('exec 9>"$goblin_root/run/uptime-goblin-install.lock"'));
  assert.ok(native.includes('the lock is `/run/uptime-goblin-install.lock`'));
  // IUR-04: the signals, as the installer handles and prints them.
  const verification = flat(section(text, 'Verification and automatic rollback', 3));
  assert.ok(
    verification.includes('writing the rest of its output to `/run/uptime-goblin-install.log`')
  );
  assert.ok(
    installer.includes('exec >>"$goblin_root/run/uptime-goblin-install.log" 2>&1 </dev/null')
  );
  assert.ok(
    verification.includes('"Uptime Goblin … was not verified: the installer received SIGINT."')
  );
  assert.ok(
    installer.includes("'\\nUptime Goblin %s was not verified: the installer received SIG%s.")
  );
  const ended =
    'The previous code was restored and its service restarted, but a signal ended the check that it serves.';
  assert.ok(verification.includes(`"${ended}"`));
  assert.ok(installer.includes(ended));
  for (const signal of ['HUP', 'INT', 'TERM'])
    assert.ok(installer.includes(`trap 'goblin_on_signal ${signal}' ${signal}`), signal);
});
