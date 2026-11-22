// Structural documentation checks for the current candidate files. This does not verify
// prose, remote URLs or heading anchors. Stage new documents before running the checker.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Every other tracked Markdown file is checked too; these must also exist. 1.5 adds the sign-in
// and notification guides (both installed as in-app guides through deploy/manifest.txt) and the
// engineering policy documents that AGENTS.md, CONTRIBUTING.md and SECURITY.md rely on.
export const requiredDocuments = [
  'README.md',
  'CONTRIBUTING.md',
  'SECURITY.md',
  'CHANGELOG.md',
  'docs/architecture.md',
  'docs/authentication.md',
  'docs/configuration.md',
  'docs/delivery.md',
  'docs/installation.md',
  'docs/integrations.md',
  'docs/notifications.md',
  'docs/security.md',
  'docs/troubleshooting.md',
  'docs/engineering-quality.md',
  'docs/documentation-inventory.md',
  'docs/security-rule-matrix.md',
  'docs/ai-development-security.md',
];
const rootDirectory = fileURLToPath(new URL('..', import.meta.url));
const numeric = '(?:0|[1-9]\\d*)';
const prereleaseIdentifier = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const semver = `${numeric}\\.${numeric}\\.${numeric}(?:-${prereleaseIdentifier}(?:\\.${prereleaseIdentifier})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?`;
const versionPattern = new RegExp(`^v?(${semver})$`);

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

// Keep line breaks so errors can point to the original line. Both fenced examples and
// inline code can contain Markdown syntax that is intended to be shown, not followed.
function proseOnly(source, hideInlineCode = true) {
  let fence = null;
  return source
    .split('\n')
    .map(line => {
      if (fence) {
        if (new RegExp(`^ {0,3}${fence.character}{${fence.length},}\\s*$`).test(line)) fence = null;
        return '';
      }
      const open = /^ {0,3}(`{3,}|~{3,})/.exec(line);
      if (open) {
        fence = { character: open[1][0], length: open[1].length };
        return '';
      }
      return hideInlineCode
        ? line.replace(/(`+)([^`]|(?!\1)`)*?\1/g, match => ' '.repeat(match.length))
        : line;
    })
    .join('\n');
}

function destination(text, start) {
  if (text[start] === '<') {
    const end = text.indexOf('>', start + 1);
    return end < 0 ? null : text.slice(start + 1, end);
  }
  let depth = 0;
  let end = start;
  for (; end < text.length; end++) {
    const character = text[end];
    if (character === '\\' && end + 1 < text.length) {
      end++;
      continue;
    }
    if (/\s/.test(character)) break;
    if (character === '(') depth++;
    if (character === ')') {
      if (depth === 0) break;
      depth--;
    }
  }
  return text.slice(start, end);
}

export function markdownLinks(source) {
  const prose = proseOnly(source);
  const found = [];
  // Inline links/images and reference definitions. A referenced destination needs only
  // one check regardless of how many full, collapsed or shortcut references use it.
  for (const pattern of [/!?\[(?:\\.|[^\]\\\n])*\]\(\s*/g, /^ {0,3}\[[^\]\n]+\]:[ \t]*/gm]) {
    for (const match of prose.matchAll(pattern)) {
      const target = destination(prose, match.index + match[0].length);
      if (target) found.push({ target, line: prose.slice(0, match.index).split('\n').length });
    }
  }
  return found;
}

export function checkDocumentation(root = rootDirectory) {
  root = fs.realpathSync(root);
  const problems = [];
  const tracked = new Set(git(root, 'ls-files', '--cached', '-z').split('\0').filter(Boolean));
  if (git(root, 'rev-parse', '--is-shallow-repository').trim() !== 'false')
    problems.push(
      'Release coverage requires full local Git history; fetch the full history and tags.'
    );
  const documents = [...tracked].filter(file => /\.md$/i.test(file));
  const contents = new Map();
  for (const file of new Set([...requiredDocuments, ...documents])) {
    if (!tracked.has(file)) {
      problems.push(`${file}: required document is not tracked in the candidate.`);
      continue;
    }
    try {
      const absolute = path.join(root, file);
      if (!fs.lstatSync(absolute).isFile()) throw new Error('not a regular file');
      const source = fs.readFileSync(absolute, 'utf8');
      if (!source.trim()) problems.push(`${file}: document is empty.`);
      contents.set(file, source);
    } catch {
      problems.push(`${file}: document is missing or is not a regular file.`);
    }
  }
  for (const [file, source] of contents) {
    for (const { target, line } of markdownLinks(source)) {
      if (/^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/|#)/.test(target)) continue;
      let decoded;
      try {
        decoded = decodeURIComponent(target.split(/[?#]/, 1)[0].replace(/\\([\\()[\]<> ])/g, '$1'));
      } catch {
        problems.push(`${file}:${line}: local link has invalid URL encoding.`);
        continue;
      }
      if (!decoded) continue;
      const relative = path.posix.normalize(path.posix.join(path.posix.dirname(file), decoded));
      if (path.posix.isAbsolute(decoded) || relative === '..' || relative.startsWith('../')) {
        problems.push(`${file}:${line}: local link points outside the source tree.`);
        continue;
      }
      const absolute = path.join(root, relative);
      let present = false;
      try {
        const real = fs.realpathSync(absolute);
        present = real.startsWith(`${root}${path.sep}`) && fs.statSync(real).isFile();
      } catch {
        // A missing candidate file is a broken link even if an older commit has it.
      }
      if (!tracked.has(relative) || !present)
        problems.push(
          `${file}:${line}: local link target ${JSON.stringify(relative)} is missing or untracked.`
        );
    }
  }
  const changelog = proseOnly(contents.get('CHANGELOG.md') || '', false);
  const headings = new Set(
    [...changelog.matchAll(new RegExp(`^##[ \\t]+\\[?v?(${semver})(?=\\]|[ \\t]|$)`, 'gm'))].map(
      match => match[1]
    )
  );
  const releaseTags = git(root, 'tag', '--list')
    .split('\n')
    .filter(tag => versionPattern.test(tag));
  for (const tag of releaseTags) {
    const version = versionPattern.exec(tag)[1];
    if (!headings.has(version))
      problems.push(`CHANGELOG.md: release tag ${tag} has no version heading.`);
  }
  try {
    const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    if (typeof version !== 'string' || !versionPattern.test(version) || version.startsWith('v'))
      problems.push('package.json: version must be a semver version without a v prefix.');
    else if (version.split('+', 1)[0].includes('-')) {
      const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (
        !new RegExp(`(^|[^0-9A-Za-z.+-])${escaped}(?![0-9A-Za-z+-]|\\.[0-9A-Za-z-])`).test(
          changelog
        )
      )
        problems.push(`CHANGELOG.md: development package version ${version} is not documented.`);
    } else if (!headings.has(version)) {
      problems.push(`CHANGELOG.md: package version ${version} has no version heading.`);
    }
  } catch {
    problems.push('package.json: cannot read package version.');
  }
  return { problems, documents: contents.size, releaseTags: releaseTags.length };
}

// The entry check of the commit guard and finalizer (the maintenance tree 66605f10): started through a
// symlinked directory (/tmp on macOS, for example) or a symlinked file, the checker must run,
// not exit 0 without checking; imported, also through stdin or --eval with an argument that is
// not a file, it must do nothing rather than fail.
function isMain() {
  if (!process.argv[1]) return false;
  const entry = path.resolve(process.argv[1]);
  const module = fileURLToPath(import.meta.url);
  if (entry === module) return true;
  try {
    return fs.realpathSync(entry) === fs.realpathSync(module);
  } catch {
    // stdin and eval imports can have a non-file argument in argv[1].
    return false;
  }
}

if (isMain()) {
  const args = process.argv.slice(2);
  if (args.length && !(args.length === 2 && args[0] === '--root')) {
    console.error('Usage: node scripts/check-documentation.mjs [--root <dir>]');
    process.exitCode = 2;
  } else {
    try {
      const result = checkDocumentation(args[1] ? path.resolve(args[1]) : rootDirectory);
      if (result.problems.length) {
        console.error(result.problems.join('\n'));
        process.exitCode = 1;
      } else {
        console.log(
          `Documentation structure passes: ${result.documents} documents, ${result.releaseTags} release tags. Prose, remote URLs and anchors still need review.`
        );
      }
    } catch {
      console.error('Documentation check could not read the candidate files or local Git history.');
      process.exitCode = 1;
    }
  }
}
