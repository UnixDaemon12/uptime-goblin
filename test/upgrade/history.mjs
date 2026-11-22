// The private input of the historical upgrade qualification.
//
// Some upgrade, installer and sign-in tests start from a release or a development milestone of
// this project's own history: the tags v1.4.2 and v1.4.3 and the milestones 1.5.0-dev.0 and
// 1.5.0-dev.1. The public source tree carries none of that history: no tags, no commit ids and
// no map of how commit ids were rewritten. These tests read it from a private input, a JSON file
// that TEST_HISTORY names (an absolute path, or one relative to the working directory):
//
//   {
//     "schema": "uptime-goblin.private-history.v1",
//     "repository": "<a Git repository directory, or a Git bundle file>",
//     "milestones": { "1.5.0-dev.0": "<full commit id>", "1.5.0-dev.1": "<full commit id>" },
//     "fixtures": { "1.4.2": { "tag": "v1.4.2", "commit": "<full commit id>" } },
//     "rewrites": [ { "old": "<full id>", "new": "<full id>", "tree": "<full id>" } ]
//   }
//
// `repository` is resolved against the file's own folder. `fixtures` names, for each committed
// release fixture whose provenance is checked against the history, the tag and the commit it was
// built from. `rewrites` lists the reviewed rewrites of recorded commits: after a history rewrite
// that changed commit ids but no tree, a tag may name the rewritten commit, which is accepted only
// when the listed tree is its tree (checkRecordedCommit() in fixtures.mjs). "$comment" may say why.
//
// Without TEST_HISTORY these tests skip, naming it, unless TEST_REQUIRE lists `history`: then they
// fail. A TEST_HISTORY that cannot be read or does not have exactly this form fails every test
// that reads it, whatever TEST_REQUIRE says: a wrong input is never a pass and never a skip.
// docs/engineering-quality.md ("The private historical qualification") says how to run it.
//
// This module uses only Node's own modules: tests copy test/upgrade/ without test/helpers/.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export const historySchema = 'uptime-goblin.private-history.v1';
/** The development milestones the upgrade suites start from, by version. */
export const milestoneNames = Object.freeze(['1.5.0-dev.0', '1.5.0-dev.1']);

const commitId = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
export const isCommitId = id => typeof id === 'string' && commitId.test(id);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactly = (value, keys, optional = []) =>
  isObject(value) &&
  keys.every(key => Object.hasOwn(value, key)) &&
  Object.keys(value).every(key => keys.includes(key) || optional.includes(key));

export function historyRequired() {
  return (process.env.TEST_REQUIRE ?? '')
    .split(',')
    .map(s => s.trim())
    .includes('history');
}

/**
 * The reviewed rewrites in `list`, as a Map from each old commit id to `{commit, tree}`. Throws
 * unless every entry is exactly {old, new, tree}, each a full id, old and new differ and no old
 * id is listed twice. `where` names the list in errors.
 */
export function parseRewrites(list, where) {
  if (!Array.isArray(list)) throw new Error(`${where}: no "rewrites" list`);
  const byOld = new Map();
  for (const entry of list) {
    if (
      !exactly(entry, ['old', 'new', 'tree']) ||
      ![entry.old, entry.new, entry.tree].every(isCommitId) ||
      entry.old === entry.new
    )
      throw new Error(
        `${where}: not a rewrite {old, new, tree} of full ids: ${JSON.stringify(entry)}`
      );
    if (byOld.has(entry.old)) throw new Error(`${where}: ${entry.old} is listed twice`);
    byOld.set(entry.old, { commit: entry.new, tree: entry.tree });
  }
  return byOld;
}

/**
 * The private history input in `file`, checked: {file, location, milestones, fixtures,
 * rewrites}, with `location` the repository's absolute path (not opened here). Throws unless the
 * file has exactly the form above, its repository exists, and every rewrite is of a commit a
 * fixture records.
 */
export function readHistory(file) {
  const where = `${file} (TEST_HISTORY)`;
  const pins = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!exactly(pins, ['schema', 'repository', 'milestones', 'fixtures', 'rewrites'], ['$comment']))
    throw new Error(
      `${where}: not a history input {schema, repository, milestones, fixtures, rewrites}`
    );
  if (pins.schema !== historySchema)
    throw new Error(`${where}: the schema is not ${historySchema}`);
  if (typeof pins.repository !== 'string' || !pins.repository)
    throw new Error(`${where}: "repository" is not a path`);
  const location = path.resolve(path.dirname(file), pins.repository);
  if (!fs.statSync(location, { throwIfNoEntry: false }))
    throw new Error(`${where}: the repository ${location} does not exist`);
  if (
    !exactly(pins.milestones, [...milestoneNames]) ||
    !milestoneNames.every(name => isCommitId(pins.milestones[name]))
  )
    throw new Error(
      `${where}: "milestones" must give exactly ${milestoneNames.join(' and ')}, each a full commit id`
    );
  if (!isObject(pins.fixtures)) throw new Error(`${where}: "fixtures" is not an object`);
  for (const [version, fixture] of Object.entries(pins.fixtures))
    if (
      !/^\d+\.\d+\.\d+$/.test(version) ||
      !exactly(fixture, ['tag', 'commit']) ||
      fixture.tag !== `v${version}` ||
      !isCommitId(fixture.commit)
    )
      throw new Error(
        `${where}: fixture ${JSON.stringify(version)} is not {tag: "v<version>", commit: <full id>}`
      );
  const rewrites = parseRewrites(pins.rewrites, where);
  const recorded = new Set(Object.values(pins.fixtures).map(fixture => fixture.commit));
  for (const old of rewrites.keys())
    if (!recorded.has(old)) throw new Error(`${where}: ${old} is in no fixture's provenance`);
  return Object.freeze({
    file,
    location,
    milestones: Object.freeze({ ...pins.milestones }),
    fixtures: Object.freeze(structuredClone(pins.fixtures)),
    rewrites,
  });
}

// A bundle is cloned once per process into a private temporary repository, removed at exit.
function openRepository(location) {
  if (fs.statSync(location).isDirectory()) return location;
  const clone = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'goblin-history-')));
  process.on('exit', () => fs.rmSync(clone, { recursive: true, force: true }));
  const result = spawnSync(
    'git',
    ['clone', '--quiet', '--mirror', location, path.join(clone, 'repository.git')],
    { encoding: 'utf8', env: { ...process.env, LC_ALL: 'C' } }
  );
  if (result.error || result.status !== 0)
    throw new Error(
      `the history bundle ${location} could not be cloned: ${result.error?.message ?? result.stderr.trim().slice(0, 500)}`
    );
  return path.join(clone, 'repository.git');
}

let cached;
/**
 * The private history: `{unavailable}` saying why when TEST_HISTORY is not set, else the checked
 * input with `repository`, the path Git reads (a bundle's clone). Throws for a wrong input.
 */
export function history() {
  if (cached && cached.variable === process.env.TEST_HISTORY) return cached.value;
  const variable = process.env.TEST_HISTORY;
  let value;
  if (!variable)
    value = {
      unavailable:
        'TEST_HISTORY is not set (it names the private history input: docs/engineering-quality.md)',
    };
  else {
    const input = readHistory(path.resolve(variable));
    value = Object.freeze({ ...input, repository: openRepository(input.location) });
  }
  cached = { variable, value };
  return value;
}

/** What Git reads for `name` in the history: a milestone's commit id, else the tag itself. */
export function historyRevision(name, input = history()) {
  return milestoneNames.includes(name) ? input.milestones[name] : name;
}
