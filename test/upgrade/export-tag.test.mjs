// test/upgrade/export-tag.mjs and installTag(): a tagged release exported on a host with git is
// installed where git is missing (the Node 24 container) only when every file matches the
// export's hashes.
//
// export-tag.mjs is the host-side half: it needs git and the private history (TEST_HISTORY,
// test/upgrade/history.mjs), so the two tests that export need them too. Without them they skip,
// naming what is missing, unless TEST_REQUIRE lists history; then they fail, as the fixture
// provenance test in fixtures.test.mjs does (a required check never turns green by skipping). A
// host with git and the history input runs them. So this file is not part of the git-less Node 24
// run, which only consumes the exports through TEST_TAG_TREES (see export-tag.mjs); every install
// there still checks each file against the export's hashes (installTag).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { exportTag } from './export-tag.mjs';
import {
  history,
  historyFiles,
  historyRequired,
  installTag,
  milestoneNames,
  tagUnavailable,
  tagProvenanceFile,
  sha256,
} from './fixtures.mjs';
import { temporary } from './harness.mjs';

const script = fileURLToPath(new URL('./export-tag.mjs', import.meta.url));
const tag = 'v1.4.3';
// The tag's files from the private history, or null when the history, git or the tag is
// unavailable.
const git = historyFiles(tag);

// Without what the export needs: fails under TEST_REQUIRE=history, otherwise skips naming it.
function needsGit(t, missing) {
  if (!missing.length) return false;
  const reason = `git cannot read ${missing.join(', ')} here (export-tag.mjs runs on a host with git and the private history)`;
  if (historyRequired()) assert.fail(`${reason} (TEST_REQUIRE=history)`);
  t.skip(reason);
  return true;
}

test('export-tag writes the tag with hashes; installTag checks every file', t => {
  if (needsGit(t, git ? [] : [tag])) return;
  const directory = temporary(t);
  const provenance = exportTag(tag, directory);
  assert.equal(provenance.tag, tag);
  assert.match(provenance.commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(Object.keys(provenance.files).sort(), [...git.files.keys()].sort());
  const base = path.join(directory, tag);
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(base, tagProvenanceFile), 'utf8')),
    provenance
  );
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(base, 'package.json'), 'utf8')).version,
    '1.4.3'
  );
  assert.throws(() => exportTag(tag, directory), /exists already/);
  assert.throws(() => exportTag('../x', directory), /Not a tag name/);

  const previous = process.env.TEST_TAG_TREES;
  process.env.TEST_TAG_TREES = directory;
  t.after(() =>
    previous === undefined
      ? delete process.env.TEST_TAG_TREES
      : (process.env.TEST_TAG_TREES = previous)
  );
  assert.equal(tagUnavailable(tag), false);
  assert.match(tagUnavailable('v0.0.0-none'), /TEST_TAG_TREES has no export of v0\.0\.0-none/);
  const installed = installTag(tag, path.join(temporary(t), 'app'));
  assert.equal(
    sha256(fs.readFileSync(path.join(installed, 'server.mjs'))),
    sha256(git.files.get('server.mjs'))
  );
  assert.ok(fs.existsSync(path.join(installed, 'node_modules/nodemailer/package.json')));

  // A changed file, or one the export does not list, refuses the tree.
  const server = path.join(base, 'server.mjs');
  const original = fs.readFileSync(server);
  fs.appendFileSync(server, '\n// changed\n');
  assert.throws(
    () => installTag(tag, path.join(temporary(t), 'app')),
    /server\.mjs does not match/
  );
  fs.writeFileSync(server, original);
  fs.writeFileSync(path.join(base, 'lib', 'extra.mjs'), '');
  assert.throws(() => installTag(tag, path.join(temporary(t), 'app')), /lib\/extra\.mjs is not in/);
  fs.rmSync(path.join(base, 'lib', 'extra.mjs'));
  assert.ok(installTag(tag, path.join(temporary(t), 'app')));
});

// The upgrade suites name the 1.5 milestones by version, and the private history gives their full
// commit ids: each exports under its version, installs through TEST_TAG_TREES and is that version.
const unreadable = milestoneNames.filter(name => !historyFiles(name));
test('the 1.5 milestones export and install through TEST_TAG_TREES by their versions', t => {
  if (needsGit(t, unreadable)) return;
  const directory = temporary(t);
  for (const name of milestoneNames)
    assert.equal(exportTag(name, directory).commit, history().milestones[name]);
  const previous = process.env.TEST_TAG_TREES;
  process.env.TEST_TAG_TREES = directory;
  t.after(() =>
    previous === undefined
      ? delete process.env.TEST_TAG_TREES
      : (process.env.TEST_TAG_TREES = previous)
  );
  for (const name of milestoneNames) {
    assert.equal(tagUnavailable(name), false);
    assert.match(tagUnavailable(`${name}x`), /TEST_TAG_TREES has no export of/);
    const installed = installTag(name, path.join(temporary(t), 'app'));
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8')).version,
      name
    );
  }
});

test('export-tag as a program: usage without arguments', () => {
  const result = spawnSync(process.execPath, [script], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage: node test\/upgrade\/export-tag\.mjs <tag> <dir>/);
});
