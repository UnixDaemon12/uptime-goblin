// Opt-in local enforcement for a repository and all of its linked worktrees.
// It does not rewrite history, replace existing hooks, or configure a remote service.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { guardHook, minimumGit, transactionHook } from './check-security-approval.mjs';

const helpers = [
  ['check-security-approval.mjs', 'orbit-security-check.mjs'],
  ['security-finalization.mjs', 'security-finalization.mjs'],
  ['security-findings.mjs', 'security-findings.mjs'],
  ['security-evidence.mjs', 'security-evidence.mjs'],
  ['security-platform.mjs', 'security-platform.mjs'],
  ['security-catalog.mjs', 'security-catalog.mjs'],
  ['security-catalog.json', 'security-catalog.json'],
  ['security-entries.mjs', 'security-entries.mjs'],
  ['security-gate-identity.mjs', 'security-gate-identity.mjs'],
  ['check-platform-coverage.mjs', 'check-platform-coverage.mjs'],
].map(([source, target]) => ({ target, bytes: fs.readFileSync(new URL(source, import.meta.url)) }));
// The guard runs before Git makes a commit; reference-transaction checks the commit Git made
// against what the guard approved before any ref moves (scripts/check-security-approval.mjs).
const hooks = {
  'pre-commit': guardHook,
  'pre-merge-commit': guardHook,
  'pre-applypatch': guardHook,
  'reference-transaction': transactionHook,
};
// Without reference-transaction hooks (Git before 2.28) the commit Git makes could not be
// checked before HEAD moves, and the guard approves nothing as a hook without that check.
const version = spawnSync('git', ['version'], { encoding: 'utf8' });
const [major, minor] = (/^git version (\d+)\.(\d+)/.exec(version.stdout ?? '') ?? [])
  .slice(1)
  .map(Number);
if (
  version.status !== 0 ||
  !Number.isSafeInteger(major) ||
  major < minimumGit[0] ||
  (major === minimumGit[0] && minor < minimumGit[1])
)
  throw new Error(
    `The commit guard needs Git ${minimumGit.join('.')} or later, which runs reference-transaction hooks: ${(version.stdout ?? '').trim() || 'git version unknown'}`
  );
const installed = new Set();
for (const repository of process.argv.slice(2).length ? process.argv.slice(2) : ['.']) {
  const git = (...args) =>
    spawnSync('git', ['-C', path.resolve(repository), ...args], { encoding: 'utf8' });
  const custom = git('config', '--get', 'core.hooksPath');
  if (custom.status !== 1)
    throw new Error(`Review the existing hooks configuration first: ${repository}`);
  const common = git('rev-parse', '--path-format=absolute', '--git-common-dir');
  if (common.status !== 0) throw new Error(`Not a Git repository: ${repository}`);
  const directory = path.join(common.stdout.trim(), 'hooks');
  if (installed.has(directory)) continue;
  fs.mkdirSync(directory, { recursive: true });
  if (fs.lstatSync(directory).isSymbolicLink())
    throw new Error('Refusing a symlinked hooks directory');
  for (const [name, text] of Object.entries(hooks)) {
    const target = path.join(directory, name);
    const stat = fs.lstatSync(target, { throwIfNoEntry: false });
    if (stat && (!stat.isFile() || fs.readFileSync(target, 'utf8') !== text))
      throw new Error(`Preserve and integrate the existing ${name} hook first`);
  }
  for (const { target, bytes } of helpers) {
    const helper = path.join(directory, target);
    const existing = fs.lstatSync(helper, { throwIfNoEntry: false });
    if (existing && (!existing.isFile() || !fs.readFileSync(helper).equals(bytes)))
      throw new Error('An older local guard exists; review its update before replacing it');
  }
  for (const { target, bytes } of helpers)
    fs.writeFileSync(path.join(directory, target), bytes, { mode: 0o600 });
  for (const [name, text] of Object.entries(hooks)) {
    const target = path.join(directory, name);
    fs.writeFileSync(target, text, { mode: 0o700 });
    fs.chmodSync(target, 0o700);
  }
  installed.add(directory);
  console.log(
    `Installed Orbit commit guards for ${path.resolve(repository)} and its linked worktrees`
  );
}
