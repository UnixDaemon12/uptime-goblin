// Local commit guard. Git hooks are bypassable; require protected CI/review on GitHub too.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sha256 } from './security-evidence.mjs';
import {
  currentCandidate,
  platformInputs,
  readEvidence,
  recordedApproval,
  validateFinalization,
} from './security-finalization.mjs';
import {
  PATHSPEC_VARIABLES,
  bindRepository,
  committedIdentityProblems,
  hardenGitHistory,
  historyRewriteProblems,
  judgePlatformManifest,
  parentVectorProblems,
  readCommitObject,
  sameParents,
} from './security-platform.mjs';

// The hooks scripts/install-security-hooks.mjs installs. pre-commit, pre-merge-commit and
// pre-applypatch run this guard before Git makes a commit (`--hook`). That is before Git decides
// the commit's parents: `git commit --amend` gives the new commit HEAD's parents, not HEAD, and
// nothing a pre-commit hook sees says so (verify-1 found the guard approving the vector [HEAD] for
// an amend, and a one-parent approval for an amended two-parent merge). So when the guard approves
// a commit it records what it approved (the tree, the complete ordered parent vector, the HEAD it
// was on and the finalization), keyed by the Git process that runs the hooks, and
// reference-transaction runs it again in the "prepared" state, after Git has written the commit
// object and before any ref moves: it recomputes the commit's tree and parents from that object,
// compares them with what was approved, exactly and in order, and checks the finalization again
// (verifyCommit); any difference aborts the update, so HEAD does not move (GATE-CONTRACT v3 C18,
// a draft, and the maintainer's C18 clarification). Every other ref update (a fetch, a
// checkout, a rebase or cherry-pick, which run no pre-commit hook) finds no record of this Git
// process and passes through unchanged.
export const guardHook = `#!/bin/sh
# Orbit security commit guard
set -eu
orbit_git_dir=$(git rev-parse --path-format=absolute --git-common-dir)
exec node "$orbit_git_dir/hooks/orbit-security-check.mjs" --hook
`;
export const transactionHook = `#!/bin/sh
# Orbit security commit guard: the commit Git made, checked before any ref moves
set -eu
case "\${1-}" in prepared|committed|aborted) ;; *) exit 0 ;; esac
orbit_git_dir=$(git rev-parse --path-format=absolute --git-common-dir)
orbit_intent="$orbit_git_dir/orbit-security/commit-intents/$PPID.json"
if [ ! -e "$orbit_intent" ] && [ ! -L "$orbit_intent" ]; then exit 0; fi
exec node "$orbit_git_dir/hooks/orbit-security-check.mjs" --reference-transaction "$1"
`;
// The oldest Git that runs reference-transaction hooks (2.28).
export const minimumGit = [2, 28];

const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ZERO_ID = /^0+$/;
const INTENT_FIELDS = [
  'approval',
  'approvalSha256',
  'head',
  'parents',
  'pid',
  'ref',
  'schemaVersion',
  'tree',
  'writtenAt',
];

// Lint scripts a branch can define, and the gate stage that must show each one passed.
const lintStages = { 'lint:sql': 'sql-lint', 'lint:imports': 'import-lint' };
const known = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// The lint stages a record must carry. `scripts` is the `scripts` object of the candidate
// tree's package.json (packageScripts below); `parentScripts` has a key for each lint script
// that a parent of the new commit defines or that their history ever defined (see
// parentLintScripts below). One helper
// per Git common directory serves every linked worktree, and those worktrees can hold
// different branches (the maintenance branch has no lint scripts, 1.5 has both), so the
// requirement follows the branch rather than the installed copy. A lint either side defines is
// required, and both are required when either side is unknown: that can refuse a commit,
// never approve one. Null when the candidate removes a lint script the parents define or
// defined: removing or renaming one needs a reviewed update of this checker, because otherwise
// a candidate could drop the script and its gate stage together (or rename the script now and
// drop the stage in the next commit) and still be approved. The guard asks that question of the
// candidate's `parsed` scripts, which are always known, so a candidate whose package.json is not
// canonical or is gone is checked for removals too (one that is not well formed is refused before
// this is asked: wellFormedPackage, gate-draft-r10 round 2).
export function requiredLintStages(scripts, parentScripts) {
  const required = [];
  for (const [script, stage] of Object.entries(lintStages)) {
    const inParents = known(parentScripts) && Object.hasOwn(parentScripts, script);
    const inCandidate = known(scripts) && Object.hasOwn(scripts, script);
    if (inParents && known(scripts) && !inCandidate) return null;
    if (inParents || inCandidate || !known(scripts) || !known(parentScripts)) required.push(stage);
  }
  return required;
}

// A package.json, given as its exact text (undefined when there is none), read two ways.
// `scripts` is its `scripts` only when the file is in canonical form (JSON.stringify with
// two-space indentation and a final newline, as Prettier writes it and the 1.5 gate's
// candidate-policy requires), and undefined otherwise, so requiredLintStages() requires every
// lint stage: a duplicate member, such as a second `scripts` or `lint:sql`, reads one way to a
// reviewer while JSON.parse and npm take the last one. `parsed` is the `scripts` object as
// JSON.parse (and so npm) reads the file whatever its form, or {} when it defines none (no
// package.json, not valid JSON, no scripts object; the typed reader refuses a file that is not
// well formed before this is asked, wellFormedPackage, gate-draft-r10 round 2). The removal
// check uses `parsed`, so a candidate cannot drop a lint script by also changing the file's
// layout, adding a second `scripts` member, breaking the file or deleting it.
export function packageScripts(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { scripts: undefined, parsed: {} };
  }
  const canonical = known(value) && text === `${JSON.stringify(value, null, 2)}\n`;
  return {
    scripts: canonical ? value.scripts : undefined,
    parsed: known(value) && known(value.scripts) ? value.scripts : {},
  };
}

// The largest package.json whose lint scripts are judged: a bigger one refuses (GDR9-AUTH-OBJECT-01).
const PACKAGE_LIMIT = 16 * 1024 ** 2;
const unexpectedOutput = what => new Error(`Commit blocked: unexpected git ${what} output`);

// The entry named package.json in the raw root tree `bytes` of `name` (object ids of `width`
// bytes), parsed from the tree object itself: { mode, id }, or null when the tree has none. A tree
// that does not parse, or names package.json twice, refuses.
function packageEntry(bytes, width, name) {
  let found = null;
  let count = 0;
  for (let offset = 0; offset < bytes.length; ) {
    const space = bytes.indexOf(32, offset);
    const nul = space < 0 ? -1 : bytes.indexOf(0, space);
    const mode = space < 0 ? '' : bytes.toString('latin1', offset, space);
    if (space < 0 || nul < 0 || nul + 1 + width > bytes.length || !/^[0-7]{5,6}$/.test(mode))
      throw new Error(
        `Commit blocked: the tree of ${name} does not parse as a Git tree, so the package.json it holds cannot be judged (GDR9-AUTH-OBJECT-01)`
      );
    if (bytes.toString('latin1', space + 1, nul) === 'package.json') {
      count += 1;
      found = { mode, id: bytes.toString('hex', nul + 1, nul + 1 + width) };
    }
    offset = nul + 1 + width;
  }
  if (count > 1)
    throw new Error(
      `Commit blocked: the tree of ${name} names package.json ${count} times, so which one counts cannot be judged (GDR9-AUTH-OBJECT-01)`
    );
  return found;
}

// What a package.json entry of `mode` is when it is not a regular file.
const entryKinds = {
  40000: 'a directory (tree',
  160000: 'a submodule (gitlink to commit',
  120000: 'a symbolic link (blob',
};

/**
 * The exact text of package.json in each tree-ish of `names` (commits or trees, as full object
 * ids), read entry first and typed with `run(args, input)`, a Git runner bound to one repository
 * (GDR9-AUTH-OBJECT-01): each root tree is read as a tree object and its package.json entry found
 * in it, never asked for as `<name>:package.json`, whose "missing" answer cannot tell an absent
 * entry from an entry whose object is not in the repository. Returns a Map name -> the text, or
 * null when the tree has no package.json entry: only that is absence. Everything else refuses,
 * throwing "Commit blocked: …": a tree or commit that cannot be read, a tree that does not parse,
 * an entry that is not a regular file (a directory, a submodule, readable or not, a symbolic link
 * or any other mode), an entry whose object is missing, unreadable or not a blob, a file over 16
 * MiB, a file whose content is not well formed (not UTF-8 text, not JSON, not a JSON object, or a
 * `scripts` member that is not an object: wellFormedPackage; round 2), unexpected Git output and
 * any error of the runner, its output bound included. Nothing is fetched: the runner reads with
 * GIT_NO_LAZY_FETCH=1.
 */
function packageVersions(run, names) {
  const result = new Map();
  const unique = [...new Set(names)];
  if (!unique.length) return result;
  if (!unique.every(name => OBJECT_ID.test(name))) throw unexpectedOutput('rev-list');
  // Each root tree, as a tree object.
  const trees = run(['cat-file', '--batch'], unique.map(name => `${name}^{tree}\n`).join(''));
  const entries = new Map();
  let offset = 0;
  for (const name of unique) {
    const end = trees.indexOf(10, offset);
    const header = end < 0 ? '' : trees.toString('utf8', offset, end);
    if (header === `${name}^{tree} missing`)
      throw new Error(
        `Commit blocked: the tree of ${name} cannot be read from this repository, so the package.json it holds cannot be judged; fetch or repair the missing objects first (GDR9-AUTH-OBJECT-01)`
      );
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) tree (\d+)$/.exec(header);
    if (!match || match[1].length !== name.length) throw unexpectedOutput('cat-file');
    const size = Number(match[2]);
    const start = end + 1;
    if (!Number.isSafeInteger(size) || trees[start + size] !== 10)
      throw unexpectedOutput('cat-file');
    entries.set(name, packageEntry(trees.subarray(start, start + size), name.length / 2, name));
    offset = start + size + 1;
  }
  if (offset !== trees.length) throw unexpectedOutput('cat-file');
  // Each entry by its type: only a regular file is read.
  const wanted = new Map();
  for (const [name, entry] of entries) {
    if (!entry) {
      result.set(name, null);
      continue;
    }
    if (entry.mode !== '100644' && entry.mode !== '100755')
      throw new Error(
        `Commit blocked: the package.json of ${name} is ${entryKinds[entry.mode] ?? `an entry of mode ${entry.mode} (object`} ${entry.id}), not a regular file, so the lint scripts that version defines cannot be judged; nothing is approved for it (GDR9-AUTH-OBJECT-01)`
      );
    wanted.set(name, entry.id);
  }
  const ids = [...new Set(wanted.values())];
  if (!ids.length) return result;
  const described = run(['cat-file', '--batch-check'], ids.map(id => `${id}\n`).join(''))
    .toString('utf8')
    .split('\n');
  if (described.pop() !== '' || described.length !== ids.length) throw unexpectedOutput('cat-file');
  const sizes = new Map();
  for (const [index, line] of described.entries()) {
    const id = ids[index];
    const holder = [...wanted].find(([, item]) => item === id)[0];
    if (line === `${id} missing`)
      throw new Error(
        `Commit blocked: the package.json of ${holder} (blob ${id}) cannot be read from this repository, so the lint scripts that version defines cannot be judged; fetch or repair the missing objects first`
      );
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) (\S+) (\d+)$/.exec(line);
    if (!match || match[1] !== id) throw unexpectedOutput('cat-file');
    if (match[2] !== 'blob')
      throw new Error(
        `Commit blocked: the package.json of ${holder} names the object ${id}, which is a ${match[2]}, not a blob (GDR9-AUTH-OBJECT-01)`
      );
    if (Number(match[3]) > PACKAGE_LIMIT)
      throw new Error(
        `Commit blocked: the package.json of ${holder} (blob ${id}) has ${match[3]} bytes, more than the 16 MiB whose lint scripts are judged, so nothing is approved for it (GDR9-AUTH-OBJECT-01)`
      );
    sizes.set(id, Number(match[3]));
  }
  const output = run(['cat-file', '--batch'], ids.map(id => `${id}\n`).join(''));
  const texts = new Map();
  offset = 0;
  for (const id of ids) {
    const end = output.indexOf(10, offset);
    const header = end < 0 ? '' : output.toString('utf8', offset, end);
    const start = end + 1;
    const size = sizes.get(id);
    if (header !== `${id} blob ${size}` || output[start + size] !== 10)
      throw unexpectedOutput('cat-file');
    const holder = [...wanted].find(([, item]) => item === id)[0];
    texts.set(id, wellFormedPackage(output.subarray(start, start + size), holder, id));
    offset = start + size + 1;
  }
  if (offset !== output.length) throw unexpectedOutput('cat-file');
  for (const [name, id] of wanted) result.set(name, texts.get(id));
  return result;
}

// The text of a package.json blob `bytes` (of `holder`, blob `id`) when it is well formed: UTF-8
// text (with no byte order mark, which JSON does not allow), a JSON object, and a `scripts` member,
// if it has one, that is an object. Anything else is malformed content and refuses (gate-draft-r10
// round 2, check-1 of GDR9-AUTH-OBJECT-01; maintainer note 153201 criterion 2): it cannot say which lint
// scripts that version defines, so nothing is approved for it, the subject's own, a parent's or a
// history version alike. A well-formed file that is not in canonical form is not malformed: it is
// read as before (packageScripts; requiredLintStages).
function wellFormedPackage(bytes, holder, id) {
  const malformed = why =>
    new Error(
      `Commit blocked: the package.json of ${holder} (blob ${id}) ${why}, so the lint scripts that version defines cannot be judged; nothing is approved for it (GDR9-AUTH-OBJECT-01)`
    );
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw malformed('is not UTF-8 text');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw malformed('is not well-formed JSON');
  }
  if (!known(value)) throw malformed('is not a JSON object');
  if (Object.hasOwn(value, 'scripts') && !known(value.scripts))
    throw malformed('has a scripts member that is not an object');
  return text;
}

// The text of package.json in one tree-ish, read with packageVersions' typed rule: undefined only
// when the tree has no package.json entry; every other failure refuses.
function readPackageWith(run, treeish) {
  return packageVersions(run, [treeish]).get(treeish) ?? undefined;
}

// The lint scripts that any version of package.json in the history of `commits` defined, as the
// keys of an object. Each version was written by a commit that changed the file, so reading the
// file at those commits (and at `commits` themselves) sees every one. --full-history keeps a
// merge that took the other side's package.json from hiding the side that defined a script.
// `run(args, input)` runs Git and returns its output bytes: both the pre-commit guard's and
// verifyCommit's are the runner bound to one repository (bindRepository; GDR9-AUTH-ROOT-01), so
// the walk and the reads go to that repository. Each version is read entry first and typed
// (packageVersions; GDR9-AUTH-OBJECT-01): only a version whose tree has no package.json entry
// defines nothing as absent; a directory, a submodule (whether or not its commit is readable), a
// symbolic link, a missing or unreadable object, a file over 16 MiB, a file whose content is not
// well formed (round 2 of gate-draft-r10: before, an old version that did not parse defined
// nothing, so one that named a lint script hid it) and unexpected output refuse, so nothing is
// approved until the history can be read (check-1 of gate-draft-r9's LINT-U1 is one such case: an
// entry whose object is missing).
function historyLintScripts(run, commits) {
  const changes = run(['rev-list', '--full-history', ...commits, '--', ':(top)package.json'])
    .toString('utf8')
    .trimEnd();
  const names = [...commits, ...changes.split('\n').filter(Boolean)];
  const defined = {};
  for (const content of packageVersions(run, names).values()) {
    if (content === null) continue;
    // A well-formed version (packageVersions refused every other) that is not in canonical form
    // defines what JSON.parse reads; every lint stage is required unless the candidate and its
    // parents are canonical (packageScripts).
    const { scripts } = JSON.parse(content);
    for (const script of Object.keys(lintStages))
      if (known(scripts) && Object.hasOwn(scripts, script)) defined[script] = true;
  }
  return defined;
}

// The lint scripts that the new commit's parents define, or that their history defined (see
// historyLintScripts), as `defined`; `unknown` says why that may leave some out (empty when it
// cannot). The parents are HEAD and, while `git commit` concludes a merge, each MERGE_HEAD
// entry, so a merge cannot drop a lint its other parent defines. History counts because commits
// also arrive without this hook (git revert, cherry-pick and rebase run no pre-commit hook, and
// a fast-forward moves a branch to a commit made on another one): once a branch's history has
// defined a lint script, its next guarded commit cannot leave the script out, whatever such a
// commit left at HEAD's package.json. An automatic `git merge` or `git pull` runs this guard as
// pre-merge-commit before Git writes MERGE_HEAD, so the commit it joins cannot be read there
// (`automaticMerge` says this may be one; see main()); that, a parent whose package.json is not
// canonical (packageScripts) and an unreadable MERGE_HEAD make the answer incomplete, and every
// lint stage is then required. What the readable parents' history defines still cannot be
// removed. `git(...args)` and `run(args, input)` are the guard's runners, both bound to its
// repository (bindRepository; GDR9-AUTH-ROOT-01); each parent's package.json is read with the typed
// rule (packageVersions; GDR9-AUTH-OBJECT-01), so one that is not a readable regular file refuses.
function parentLintScripts(git, head, automaticMerge, run) {
  const mergeHead = git('rev-parse', '--path-format=absolute', '--git-path', 'MERGE_HEAD');
  let merging = '';
  const unknown = [];
  try {
    merging = fs.readFileSync(mergeHead, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') unknown.push('MERGE_HEAD could not be read');
    else if (automaticMerge)
      unknown.push(
        'GIT_REFLOG_ACTION is set while no merge is being concluded, which is how an automatic git merge or git pull runs this guard, without showing it the commit it joins (they keep a GIT_REFLOG_ACTION that is already set, so any value counts), so merge with --no-commit and then run git commit, and leave GIT_REFLOG_ACTION unset for other commits'
      );
  }
  const named = [head, ...merging.split('\n').filter(Boolean)];
  const parents = named.filter(parent => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(parent));
  if (parents.length !== named.length) unknown.push('MERGE_HEAD could not be read');
  if (parents.some(parent => !known(packageScripts(readPackageWith(run, parent)).scripts)))
    unknown.push(
      "a parent's package.json is missing, is not canonical JSON or has no scripts object"
    );
  return { defined: historyLintScripts(run, parents), unknown };
}

/**
 * The lint stages the exact commit `object` ({ tree, parents }, read from its own commit object)
 * requires (GDR8-AUTH-LINT-01, the maintainer's decision 1): what the pre-commit guard
 * derives for its candidate (requiredLintStages), from the commit's own tree, its complete ordered
 * parent vector and their history, never from the checkout, HEAD, MERGE_HEAD, process.cwd() or a
 * caller's assertion. `git(args, input)` is verifyCommit's runner, bound to the repository being
 * verified (bindRepository; GDR9-AUTH-ROOT-01), so every read, the history walk included, goes to
 * that repository, with no lazy fetch. The commit's own package.json, each parent's and every
 * version in their history are read entry first and typed (packageVersions; GDR9-AUTH-OBJECT-01):
 * only a tree with no package.json entry is a commit without one; an entry that is not a readable
 * regular file of at most 16 MiB (a directory, a submodule, readable or not, a symbolic link, a
 * missing or unreadable object, an oversized file), a file whose content is not well formed (not
 * UTF-8 text, not JSON, not a JSON object, or a `scripts` member that is not an object; round 2),
 * a tree that cannot be read and any error of the runner, its 64 MiB output bound included,
 * refuse, never the conservative two-lint answer. The guard's semantics are kept for what can be
 * read: a lint script the commit or any parent's history defines is required; both are required
 * when the commit's package.json or a parent's is absent, well formed but not in canonical form,
 * or has no scripts object; and a commit that removes or renames a lint script that a parent or
 * their history defines is refused outright, judged by what JSON.parse reads in its package.json.
 * A commit with no parent also gets both, a conservative answer that
 * approves nothing: an approval needs a nonempty parent vector, so a root commit is not supported
 * (parentVectorProblems). Returns the stages, or throws.
 */
export function commitLintStages(git, object) {
  const parents = Array.isArray(object.parents) ? object.parents : [];
  const versions = packageVersions(git, [object.tree, ...parents]);
  const candidate = packageScripts(versions.get(object.tree) ?? undefined);
  const unknown =
    !parents.length ||
    parents.some(parent => !known(packageScripts(versions.get(parent) ?? undefined).scripts));
  const defined = parents.length ? historyLintScripts(git, parents) : {};
  const required = requiredLintStages(candidate.scripts, unknown ? undefined : defined);
  if (!requiredLintStages(candidate.parsed, defined) || !required)
    throw new Error(
      'Commit check refused: the commit removes lint:sql or lint:imports, which a parent of it or their history defines (judged by what JSON.parse and npm read in its package.json, whatever its layout; a package.json that is missing or has no scripts object defines neither, and one that is not well formed is refused before this is asked). Removing or renaming a lint script needs a reviewed update of the installed commit guard (docs/engineering-quality.md); nothing is approved for this commit (GDR8-AUTH-LINT-01).'
    );
  return required;
}

// Why the reference-transaction hook that checks the commit Git makes is not in place (null when
// it is): the guard approves nothing as a hook without it, or `git commit --amend` would be
// approved for a parent vector the commit does not have.
function transactionHookProblem(git) {
  const file = git(
    'rev-parse',
    '--path-format=absolute',
    '--git-path',
    'hooks/reference-transaction'
  );
  const stat = fs.lstatSync(file, { throwIfNoEntry: false });
  if (!stat) return `${file} is missing`;
  if (!stat.isFile() || !(stat.mode & 0o100) || fs.readFileSync(file, 'utf8') !== transactionHook)
    return `${file} is not the executable hook the installer writes`;
  return null;
}

// The folder of commit intents: <common>/orbit-security/commit-intents, private.
function intentDirectory(common, create) {
  const folder = path.join(common, 'orbit-security', 'commit-intents');
  if (create) {
    try {
      fs.mkdirSync(folder, { mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
  const stat = fs.lstatSync(folder, { throwIfNoEntry: false });
  if (stat && (!stat.isDirectory() || stat.mode & 0o077 || stat.uid !== process.getuid?.()))
    throw new Error(`${folder} must be a private folder of this user, not a link`);
  return folder;
}

// Whether the process `pid` exists (EPERM: it does, as another user's).
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

// Removes the intents (and unfinished intent files) of Git processes that no longer exist: a
// commit that stopped after its pre-commit hook (an empty message, a failed commit-msg hook) never
// reaches reference-transaction, and its record must not wait for a later process with its pid.
function pruneIntents(folder) {
  for (const name of fs.readdirSync(folder)) {
    const pid = /^\.?(\d+)(?:\.json|-[0-9a-f-]{36}\.tmp)$/.exec(name)?.[1];
    if (pid !== undefined && !alive(Number(pid)))
      fs.rmSync(path.join(folder, name), { force: true });
  }
}

/**
 * The record of what the guard approved for the commit the Git process `pid` is making, parsed
 * strictly: { schemaVersion: 1, pid, head, ref, tree, parents, approval, approvalSha256, writtenAt }.
 * Throws unless it is exactly that, with parents beginning at head.
 */
export function parseIntent(bytes, pid) {
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('the commit intent is not JSON');
  }
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== INTENT_FIELDS.join(',') ||
    value.schemaVersion !== 1 ||
    value.pid !== pid ||
    typeof value.head !== 'string' ||
    !OBJECT_ID.test(value.head) ||
    typeof value.ref !== 'string' ||
    !/^(?:HEAD|refs\/heads\/[^\s\0]+)$/.test(value.ref) ||
    typeof value.tree !== 'string' ||
    !OBJECT_ID.test(value.tree) ||
    parentVectorProblems(value.parents).length ||
    value.parents[0] !== value.head ||
    typeof value.approval !== 'string' ||
    !value.approval.startsWith(`${value.tree}-commit-`) ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value.approval) ||
    typeof value.approvalSha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.approvalSha256) ||
    typeof value.writtenAt !== 'string' ||
    !Number.isFinite(Date.parse(value.writtenAt))
  )
    throw new Error('the commit intent is not a version 1 record of this Git process');
  return value;
}

// The branch HEAD names, or HEAD itself when it is detached: the ref a commit moves. `run` is the
// guard's bound runner (GDR9-AUTH-ROOT-01).
function headRef(run) {
  try {
    return run(['symbolic-ref', '--quiet', 'HEAD']).toString('utf8').trim();
  } catch (error) {
    if (error.status === 1) return 'HEAD';
    throw error;
  }
}

// Records, for the Git process running this hook, what the guard approved (see guardHook).
function writeIntent(common, intent) {
  const folder = intentDirectory(common, true);
  pruneIntents(folder);
  const temporary = path.join(folder, `.${intent.pid}-${randomUUID()}.tmp`);
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(intent)}\n`, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, path.join(folder, `${intent.pid}.json`));
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function main({ hook = false } = {}) {
  // `git --literal-pathspecs commit` exports GIT_LITERAL_PATHSPECS to its hooks, and a front end
  // may set any of these: with it, ':(top)package.json' would match no commit, and the history
  // behind HEAD would define nothing. Pathspecs here mean what they say.
  for (const name of PATHSPEC_VARIABLES) delete process.env[name];
  // Every Git command here, and in the modules it calls, reads each commit as it is: no grafts
  // (an exported GIT_GRAFT_FILE among them), no replace refs and no commit-graph, which could
  // otherwise hide a commit that removed a lint script or the platform manifest. A shallow
  // repository or an info/grafts file is refused outright (scripts/security-platform.mjs).
  hardenGitHistory(process.env);
  // Every Git read the guard makes, in this module and in those it calls, goes to the repository
  // it runs in, bound once from its folder (GDR9-AUTH-ROOT-01): an inherited GIT_DIR, GIT_WORK_TREE
  // or GIT_COMMON_DIR naming another repository, another object source than its own quarantine and
  // an index other than its own refuse, and no read fetches a missing object (bindRepository).
  let binding;
  try {
    binding = bindRepository(process.cwd(), { index: true });
  } catch (error) {
    throw new Error(`Commit blocked: ${error.message}.`);
  }
  const run = (args, input) => binding.run(args, input, { maxBuffer: 256 * 1024 ** 2 });
  const git = (...args) => run(args).toString('utf8').trimEnd();
  const rewritten = historyRewriteProblems(run, binding.commonDir);
  if (rewritten.length)
    throw new Error(`Commit blocked: the history cannot be judged: ${rewritten.join('; ')}.`);
  // As a hook, nothing is approved unless the reference-transaction hook will compare the commit
  // Git makes with what is approved here (see guardHook).
  if (hook) {
    const missing = transactionHookProblem(git);
    if (missing)
      throw new Error(
        `Commit blocked: the reference-transaction hook that checks the commit Git makes before HEAD moves is not installed (${missing}). Install the guard with node scripts/install-security-hooks.mjs.`
      );
  }
  // `git merge` and `git pull` give the hooks they run a GIT_REFLOG_ACTION, but keep one that is
  // already in the environment, whatever its value (empty too), while `git commit` and `git am`
  // give their hooks none. So any GIT_REFLOG_ACTION may mean an automatic merge, and a plain
  // commit made with one exported needs both lint stages as well: that can refuse a commit,
  // never approve one.
  const automaticMerge = process.env.GIT_REFLOG_ACTION !== undefined;
  const current = currentCandidate(process.cwd(), { automaticMerge, binding });
  // The commit's complete ordered parent vector (HEAD, then each MERGE_HEAD; GATE-CONTRACT v3
  // C18). An automatic merge runs this guard before Git writes MERGE_HEAD, so its other parents
  // cannot be read here: nothing is approved for an incomplete vector, for any candidate
  // (security review GD-R1 found that the earlier maintenance exception let a two-parent commit through
  // before its unseen parent was judged).
  if (!current.parentsComplete)
    throw new Error(
      `Commit blocked: the complete parent vector of this commit is not known (${current.parentsReason}). Merge with --no-commit, then run git commit, and leave GIT_REFLOG_ACTION unset for other commits.`
    );
  // The candidate's package.json, read with the typed rule (GDR9-AUTH-OBJECT-01).
  const candidate = packageScripts(readPackageWith(run, current.tree));
  const parents = parentLintScripts(git, current.parent, automaticMerge, run);
  current.scripts = candidate.scripts;
  current.parentScripts = parents.unknown.length ? undefined : parents.defined;
  // The finalized run must carry each lint stage this returns, and each must have passed
  // (validateFinalization, in scripts/security-finalization.mjs). Null, a removal, is refused.
  current.lintStages = requiredLintStages(current.scripts, current.parentScripts);
  // The platform coverage contract (test/platform-manifest.json), worked out for every commit from
  // the candidate's bytes, its parents and the history behind them, as for the lint stages: a
  // candidate whose history never held the manifest (maintenance) needs nothing more; otherwise
  // the finalization must bind the platform evidence and the companion runs the manifest names,
  // which are checked again now (security-finalization.mjs). An automatic merge, whose other
  // parent cannot be read yet, was refused above.
  current.platform = platformInputs(
    process.cwd(),
    current.tree,
    { heads: current.parents, complete: true, reason: '' },
    { binding }
  );
  if (!requiredLintStages(candidate.parsed, parents.defined) || !current.lintStages)
    throw new Error(
      'Commit blocked: the candidate removes lint:sql or lint:imports, which a parent of this commit or its history defines (judged by what JSON.parse and npm read in its package.json, whatever its layout; a package.json that is missing or has no scripts object defines neither, and one that is not well formed is refused before this is asked). Removing or renaming a lint script needs a reviewed update of the installed commit guard (docs/engineering-quality.md), not --no-verify.'
    );
  const common = binding.commonDir;
  const directory = path.join(common, 'orbit-security');
  for (const name of fs.existsSync(directory) ? fs.readdirSync(directory) : []) {
    if (!name.startsWith(`${current.tree}-commit-`)) continue;
    const approvalFile = path.join(directory, name, 'finalization', 'approval.json');
    let approvalBytes;
    try {
      const before = readEvidence(approvalFile);
      validateFinalization(path.join(directory, name), current);
      approvalBytes = readEvidence(approvalFile);
      if (!approvalBytes.equals(before)) continue;
    } catch {
      /* Missing/interrupted evidence is never an approval. */
      continue;
    }
    // Approved. As a hook, record what was approved for the reference-transaction hook, which
    // compares the commit Git then makes with it before HEAD moves (guardHook). The Git process
    // running this hook is this process's parent: the hook script execs Node.
    if (hook)
      writeIntent(common, {
        schemaVersion: 1,
        pid: process.ppid,
        head: current.parent,
        ref: headRef(run),
        tree: current.tree,
        parents: [...current.parents],
        approval: name,
        approvalSha256: sha256(approvalBytes),
        writtenAt: new Date().toISOString(),
      });
    return;
  }
  const unknown = [];
  if (!known(current.scripts))
    unknown.push(
      "the candidate's package.json is missing, is not canonical JSON (two-space JSON.stringify and a final newline, so no duplicate member can make it ambiguous) or has no scripts object"
    );
  if (!current.parentScripts)
    unknown.push(`the parents of this commit could not be read: ${parents.unknown.join('; ')}`);
  // Why the platform contract may refuse, as far as it can be told without a run's dispositions.
  const contract = judgePlatformManifest({
    ...current.platform,
    binding: { tree: current.tree, parents: current.parents },
  });
  const platform =
    contract.kind === 'maintenance'
      ? ' A maintenance candidate (no platform manifest in its history) also needs its pinned Actionlint bound by the qualified golden-tool manifest, an obligation only F on the Mac can pass (actionlint-pin; maintainer decision 8), so no finalization this draft writes for it is a pass either.'
      : ` The candidate has a platform contract (test/platform-manifest.json): the finalization must also bind its coverage and the companion runs its manifest requires (node scripts/security-gate.mjs platform <run-id> on each other platform, named after the run to node scripts/finalize-security.mjs), and under GATE-CONTRACT v3 (a draft) only F on the Mac can pass its finalization obligations, so no finalization this draft writes for it is a pass.${contract.problems.length ? ` Without reviewed dispositions its manifest is refused: ${contract.problems.slice(0, 3).join('; ')}.` : ''}`;
  throw new Error(
    `Commit blocked: stage the complete change, run node scripts/security-gate.mjs commit, and finalize its exact reviewed findings with node scripts/finalize-security.mjs. No fresh verified finalization matches the candidate and evidence.${unknown
      .map(reason => ` The lint stages are required because ${reason}.`)
      .join('')}${platform}`
  );
}

// After a commit exists (GATE-CONTRACT v3 C18, and the maintainer's C18 clarification):
// `--verify-commit [<commit>]` (HEAD by default) recomputes the commit's tree and complete ordered
// parent vector from its own object, finds a finalization of exactly that tree and vector, in
// order, that still verifies as a recorded approval (recordedApproval in
// scripts/security-finalization.mjs: schema 2, status pass, bound to its sealed run and retained
// review, its sealed scanner results and the finding set they give, the lint stages the commit
// requires, and for a candidate with a platform contract to the installed catalog with exactly its F
// obligations, each passed), and refuses any replace or commit-graph ambiguity. It exits nonzero
// when the commit is not what was approved. The installed reference-transaction hook runs the same
// check, with `intended` (what the guard approved before the commit was made), before HEAD moves;
// a check of a commit that already exists (from CI or F) can refuse it but not undo it. The
// pre-commit guard makes the same comparison for every approved commit in the history it judges
// (platformInputs in scripts/security-finalization.mjs). The lint stages the commit requires are
// derived here from the commit's own tree, its complete ordered parent vector and their history,
// with the runner bound to the repository at `root` (commitLintStages; GDR8-AUTH-LINT-01), and
// only that requirement is given to recordedApproval: no option, no checkout, HEAD, MERGE_HEAD or
// process.cwd() decides it, and an inherited pathspec variable cannot hide the history. Every
// read, the first one included, goes through that one runner (bindRepository; GDR9-AUTH-ROOT-01):
// `root` is canonicalized and the repository Git finds there is the one read; an inherited
// GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR naming another repository, another object source than
// its own quarantine, or a GIT_NAMESPACE refuses rather than redirecting the commit read, the
// approvals, the lint derivation or the history; and no read fetches a missing object from a
// promisor remote (GIT_NO_LAZY_FETCH=1; GDR9-AUTH-OBJECT-01).
export function verifyCommit(spec = 'HEAD', root = process.cwd(), { intended } = {}) {
  let binding;
  try {
    binding = bindRepository(root);
  } catch (error) {
    throw new Error(`Commit check refused: ${error.message}.`);
  }
  return verifyBound(spec, binding, { intended });
}

// verifyCommit for the repository `binding` (bindRepository) names: the reference-transaction hook
// gives the binding it found its record with, so one runner reads both.
function verifyBound(spec, binding, { intended } = {}) {
  const git = (args, input) => binding.run(args, input, { maxBuffer: 64 * 1024 ** 2 });
  const graphGit = (args, input) =>
    binding.run(args, input, { maxBuffer: 64 * 1024 ** 2, config: "'core.commitgraph=true'" });
  const common = binding.commonDir;
  const rewritten = historyRewriteProblems(git, common);
  if (rewritten.length)
    throw new Error(`Commit check refused: the history cannot be judged: ${rewritten.join('; ')}.`);
  const commit = git(['rev-parse', '--verify', '--end-of-options', `${spec}^{commit}`], '')
    .toString()
    .trim();
  const object = readCommitObject(git, commit);
  // What the guard approved before Git made the commit: the tree and the complete ordered parent
  // vector, exactly and in order. `git commit --amend` fails here: the guard approved [HEAD], and
  // Git gave the new commit HEAD's parents.
  if (intended && (object.tree !== intended.tree || !sameParents(object.parents, intended.parents)))
    throw new Error(
      `Commit check refused: the commit Git made, ${commit}, has the tree ${object.tree} and the parents [${object.parents.join(', ')}], not the tree ${intended.tree} and the complete ordered parent vector [${intended.parents.join(', ')}] that the commit guard approved before it was made (GATE-CONTRACT v3 C18). git commit --amend ends here: it gives the new commit the parents of HEAD, not HEAD. Make a new commit instead; HEAD has not moved.`
    );
  // What the exact commit requires of its run (GDR8-AUTH-LINT-01).
  let lintStages;
  try {
    lintStages = commitLintStages(git, object);
  } catch (error) {
    if (error.message.startsWith('Commit check refused:')) throw error;
    throw new Error(
      `Commit check refused: the lint stages commit ${commit} requires cannot be derived from it, its parents and their history (${String(error.message).split('\n')[0].slice(0, 300)}), so nothing is approved for it (GDR8-AUTH-LINT-01).`
    );
  }
  const security = path.join(common, 'orbit-security');
  const approved = [];
  const others = [];
  for (const name of fs.existsSync(security) ? fs.readdirSync(security) : []) {
    if (!name.startsWith(`${object.tree}-commit-`)) continue;
    try {
      const recorded = recordedApproval(path.join(security, name), { lintStages });
      if (
        recorded.approval.tree === object.tree &&
        sameParents(recorded.approval.parents, object.parents)
      )
        approved.push({ name, ...recorded });
      else others.push(recorded.approval);
    } catch {
      /* Not a verifiable finalization: it approves nothing. */
    }
  }
  if (!approved.length)
    throw new Error(
      `Commit check refused: commit ${commit} has the tree ${object.tree} and the parents [${object.parents.join(', ')}], and no finalization with status pass approved that tree with that complete ordered parent vector${others.length ? ` (approved: ${others.map(item => `[${item.parents.join(', ')}]`).join('; ')})` : ''}.`
    );
  if (
    intended &&
    !approved.some(
      item => item.name === intended.approval && item.approvalSha256 === intended.approvalSha256
    )
  )
    throw new Error(
      `Commit check refused: the finalization the commit guard accepted before the commit was made (${intended.approval}) no longer verifies unchanged.`
    );
  const problems = committedIdentityProblems({
    git,
    graphGit,
    commit,
    intended: { tree: approved[0].approval.tree, parents: approved[0].approval.parents },
  });
  if (problems.length) throw new Error(`Commit check refused: ${problems.join('; ')}.`);
  return { commit, tree: object.tree, parents: object.parents };
}

/**
 * The reference-transaction hook (see guardHook): `state` is Git's ("prepared", "committed" or
 * "aborted"; the hook script passes no other), `input` its lines "<old> <new> <ref>". It acts only
 * when the guard recorded an approval for the Git process `pid` (the hook's parent), and only on
 * a transaction that moves HEAD or a branch (another transaction of that process, of ORIG_HEAD or
 * AUTO_MERGE, passes and leaves the record). In the prepared state each such update must be the
 * commit's: the branch HEAD named when the guard ran (or HEAD itself), moving from the HEAD the
 * guard approved on to a commit with exactly the approved tree and complete ordered parent vector,
 * whose finalization still verifies (verifyCommit); anything else throws, which makes Git abort
 * the update. The record is removed once such an update is decided, so a record left by a commit
 * that stopped before its update (its Git process gone, the guard prunes it later) can refuse at
 * most one update of a later process that happens to get the same process id. Returns the commits
 * it checked. The common directory that holds the record is found with the same bound runner as
 * every later read (bindRepository; GDR9-AUTH-ROOT-01): a hook whose Git was given another
 * repository than the one at `root` (an inherited GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR that
 * names another) is refused, so HEAD does not move, rather than looked up in either repository.
 */
export function checkReferenceTransaction(
  state,
  input,
  { root = process.cwd(), pid = process.ppid } = {}
) {
  let binding;
  try {
    binding = bindRepository(root);
  } catch (error) {
    throw new Error(`Commit blocked: ${error.message}; HEAD has not moved.`);
  }
  const common = binding.commonDir;
  const folder = intentDirectory(common, false);
  const file = path.join(folder, `${pid}.json`);
  if (!fs.lstatSync(file, { throwIfNoEntry: false })) return [];
  const lines = input
    .split('\n')
    .filter(Boolean)
    .map(line => {
      const [oldValue, newValue, ref, ...rest] = line.split(' ');
      if (!ref || rest.length) {
        fs.rmSync(file, { force: true });
        throw new Error(`Commit blocked: unexpected reference-transaction input: ${line}`);
      }
      return { oldValue, newValue, ref };
    });
  let intent;
  let unreadable;
  try {
    intent = parseIntent(readEvidence(file), pid);
  } catch (error) {
    unreadable = error;
  }
  // Updates of HEAD or a branch: in this process, only the approved commit's.
  const touched = lines.filter(line => line.ref === 'HEAD' || line.ref.startsWith('refs/heads/'));
  // Another transaction of the same Git process (ORIG_HEAD, AUTO_MERGE): not the commit's.
  if (!touched.length) return [];
  try {
    if (state !== 'prepared') return [];
    if (unreadable)
      throw new Error(
        `Commit blocked: the record of what the commit guard approved for this commit cannot be read (${unreadable.message}); HEAD has not moved.`
      );
    const stale =
      ' If this Git process is not concluding the commit the guard approved, the record was stale and is now removed: run the command again.';
    const checked = [];
    for (const line of touched) {
      if (line.ref !== intent.ref && line.ref !== 'HEAD')
        throw new Error(
          `Commit blocked: ${line.ref} would move, not ${intent.ref}, the branch the commit guard approved this commit on; HEAD has not moved.${stale}`
        );
      if (line.oldValue !== intent.head)
        throw new Error(
          `Commit blocked: ${line.ref} would move from ${line.oldValue}, not from ${intent.head}, the HEAD the commit guard approved this commit on; HEAD has not moved.${stale}`
        );
      if (!OBJECT_ID.test(line.newValue) || ZERO_ID.test(line.newValue))
        throw new Error(
          `Commit blocked: ${line.ref} would not name a commit (${line.newValue}); HEAD has not moved.`
        );
      checked.push(verifyBound(line.newValue, binding, { intended: intent }));
    }
    return checked;
  } finally {
    fs.rmSync(file, { force: true });
  }
}

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
  try {
    const [option, spec, ...rest] = process.argv.slice(2);
    if (option === '--verify-commit' && !rest.length) {
      hardenGitHistory(process.env);
      const checked = verifyCommit(spec ?? 'HEAD');
      console.log(
        `Commit ${checked.commit} has the tree and complete ordered parent vector its finalization approved.`
      );
    } else if (
      option === '--reference-transaction' &&
      ['prepared', 'committed', 'aborted'].includes(spec) &&
      !rest.length
    ) {
      hardenGitHistory(process.env);
      const input = fs.readFileSync(0);
      if (input.length > 16 * 1024 ** 2)
        throw new Error('Commit blocked: unexpected reference-transaction input');
      checkReferenceTransaction(spec, input.toString('utf8'));
    } else if (option === '--hook' && spec === undefined) main({ hook: true });
    else if (option !== undefined)
      throw new Error(
        'Usage: node scripts/check-security-approval.mjs [--verify-commit [<commit>]]'
      );
    else main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
