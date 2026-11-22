// `npm run check`: syntax-check every JavaScript file Orbit ships and prove the shipped set is
// closed. It reads deploy/manifest.txt, runs `node --check` on each listed module, follows every
// import from there (recursively, including the browser's /-rooted imports under public/) and
// fails when a module imports a file the manifest does not list, a missing file, or a package
// that is not a runtime dependency. A new module therefore cannot be forgotten by the installer,
// the Docker image or the release archive. Usage: node scripts/check.mjs [--root <dir>]
import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const validPath = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const scripts = /\.(?:mjs|cjs|js)$/;

// Returns the listed paths plus any format problems (order, duplicates, unsafe paths).
export function parseManifest(text) {
  const files = [],
    problems = [];
  for (const [index, raw] of text.split('\n').entries()) {
    const line = raw.replace(/\r$/, '');
    if (!line || line.startsWith('#')) continue;
    if (
      !validPath.test(line) ||
      line.split('/').some(part => part === '.' || part === '..') ||
      raw.endsWith('\r')
    ) {
      problems.push(`line ${index + 1}: invalid path ${JSON.stringify(raw)}`);
      continue;
    }
    const previous = files.at(-1);
    if (previous === line) problems.push(`line ${index + 1}: duplicate ${line}`);
    else if (previous !== undefined && previous > line)
      problems.push(`line ${index + 1}: ${line} must sort before ${previous}`);
    files.push(line);
  }
  if (!files.length) problems.push('the manifest lists no files');
  return { files: [...new Set(files)], problems };
}

export function readManifest(root = repositoryRoot) {
  const { files, problems } = parseManifest(
    fs.readFileSync(path.join(root, 'deploy', 'manifest.txt'), 'utf8')
  );
  if (problems.length) throw new Error(`deploy/manifest.txt: ${problems.join('; ')}`);
  return files;
}

// Static `import … from`, `export … from`, bare `import '…'` and literal dynamic `import('…')`.
// Statements are matched only at the start of a line (as Prettier formats them), so an import
// quoted inside a comment or template text in the middle of a line is not mistaken for one.
export function moduleSpecifiers(source) {
  const found = [];
  const patterns = [
    /^[ \t]*(?:import|export)\b[^;'"`]*?\bfrom\s*(['"])([^'"\n]+)\1/gm,
    /^[ \t]*import\s*(['"])([^'"\n]+)\1/gm,
    /\bimport\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g,
  ];
  for (const pattern of patterns)
    for (const match of source.matchAll(pattern)) found.push(match[2]);
  return [...new Set(found)];
}

// Local references in the page shell (script src, stylesheet and icon href).
export function htmlReferences(source) {
  return [...source.matchAll(/\b(?:src|href)\s*=\s*"(\/[^"#?]*)(?:[?#][^"]*)?"/g)].map(
    match => match[1]
  );
}

// Maps an import to a path relative to the root, or returns null for a package or builtin.
export function resolveSpecifier(from, specifier) {
  const bare = specifier.replace(/[?#].*$/, '');
  let target;
  if (bare.startsWith('./') || bare.startsWith('../'))
    target = path.posix.join(path.posix.dirname(from), bare);
  else if (bare.startsWith('/')) {
    // Browser modules resolve '/x.js' against the site root, which serves public/.
    if (!from.startsWith('public/')) return { error: `absolute import ${specifier}` };
    target = path.posix.join('public', bare);
  } else return null;
  target = path.posix.normalize(target);
  if (target.startsWith('../') || target === '..')
    return { error: `${specifier} points outside the application` };
  return { path: target };
}

export function checkClosure(root = repositoryRoot, files = readManifest(root)) {
  const listed = new Set(files),
    problems = [],
    reached = new Set(),
    pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const runtime = new Set(Object.keys(pkg.dependencies || {}));
  const builtins = new Set(builtinModules.flatMap(name => [name, `node:${name}`]));
  const queue = files.filter(file => scripts.test(file) || file.endsWith('.html'));
  for (const file of files)
    if (!fs.existsSync(path.join(root, file)) || !fs.lstatSync(path.join(root, file)).isFile())
      problems.push(`${file} is listed in deploy/manifest.txt but is not a regular file`);
  while (queue.length) {
    const file = queue.shift();
    if (reached.has(file)) continue;
    reached.add(file);
    const absolute = path.join(root, file);
    if (!fs.existsSync(absolute)) continue;
    const source = fs.readFileSync(absolute, 'utf8');
    const references = file.endsWith('.html')
      ? htmlReferences(source).map(href => `.${href.startsWith('/') ? href : '/' + href}`)
      : moduleSpecifiers(source);
    for (const specifier of references) {
      const base = file.endsWith('.html') ? 'public/index.html' : file;
      const resolved = resolveSpecifier(base, specifier);
      if (resolved === null) {
        const name = specifier.startsWith('@')
          ? specifier.split('/').slice(0, 2).join('/')
          : specifier.split('/')[0];
        if (file.startsWith('public/'))
          problems.push(`${file} imports the package ${specifier}, which browsers cannot load`);
        else if (!builtins.has(specifier) && !builtins.has(name) && !runtime.has(name))
          problems.push(`${file} imports ${specifier}, which is not a runtime dependency`);
        continue;
      }
      if (resolved.error) {
        problems.push(`${file}: ${resolved.error}`);
        continue;
      }
      if (!listed.has(resolved.path))
        problems.push(`${file} imports ${resolved.path}, which deploy/manifest.txt does not list`);
      if (!fs.existsSync(path.join(root, resolved.path)))
        problems.push(`${file} imports ${resolved.path}, which does not exist`);
      else if (scripts.test(resolved.path)) queue.push(resolved.path);
    }
  }
  return { problems, modules: [...reached].filter(file => scripts.test(file)).sort() };
}

export function syntaxProblems(root, modules) {
  const problems = [];
  for (const file of modules) {
    const result = spawnSync(process.execPath, ['--check', path.join(root, file)], {
      encoding: 'utf8',
    });
    if (result.status !== 0)
      problems.push(`${file} failed node --check:\n${(result.stderr || '').trim()}`);
  }
  // The installer runs as root on the target; at least make sure bash can parse it, and the shim
  // under its name from before the rename to Uptime Goblin.
  for (const name of ['install.sh', 'install-lxc.sh']) {
    const installer = path.join(root, 'deploy', name);
    if (!fs.existsSync(installer)) continue;
    const result = spawnSync('bash', ['-n', installer], { encoding: 'utf8' });
    if (result.error?.code !== 'ENOENT' && result.status !== 0)
      problems.push(`deploy/${name} failed bash -n:\n${(result.stderr || '').trim()}`);
  }
  return problems;
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
  if (args[0] === '--root' && args[1] && args.length === 2) root = path.resolve(args[1]);
  else if (args.length) {
    console.error('Usage: node scripts/check.mjs [--root <dir>]');
    process.exit(2);
  }
  let problems;
  let modules = [];
  try {
    const closure = checkClosure(root);
    modules = closure.modules;
    problems = [...closure.problems, ...syntaxProblems(root, modules)];
  } catch (error) {
    problems = [error.message];
  }
  if (problems.length) {
    for (const problem of problems) console.error(`✖ ${problem}`);
    process.exitCode = 1;
  } else
    console.log(`✔ ${modules.length} shipped modules pass node --check; every import is listed`);
}
