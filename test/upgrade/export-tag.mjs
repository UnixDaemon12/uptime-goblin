// Exports a release or milestone of the private history for the upgrade tests on hosts without
// git (the Node 24 container):
//
//   TEST_HISTORY=<private history input> node test/upgrade/export-tag.mjs v1.4.3 <dir>
//
// writes `git archive v1.4.3` from the private history repository (test/upgrade/history.mjs) into
// <dir>/v1.4.3/ plus .orbit-tag.json ({tag, commit, files: {path: sha256}}). A 1.5 milestone is
// exported by its version (1.5.0-dev.0, 1.5.0-dev.1), whose commit the history input gives, into
// <dir>/<version>/. Mount <dir> read-only into the container and set TEST_TAG_TREES=<dir>;
// installTag() (test/upgrade/fixtures.mjs) then checks every file against those hashes. The Node
// 24 gate (sessions spec §12 item 3), from a copy of the tree with a real node_modules, with the
// limits every test container gets:
//
//   docker run --rm --network none --memory=4g --cpus=4 --pids-limit=1024 --user node \
//     -e HOME=/tmp -v <tree>:/src -v <dir>:/tags:ro -w /src -e TEST_TAG_TREES=/tags \
//     -e TEST_REQUIRE=fixtures,history node:24-bookworm-slim node --test --test-timeout=300000 \
//     --import ./test/setup.mjs 'test/upgrade/!(export-tag|fixtures).test.mjs'
//
// `--user node`: the image runs as root by default, and orbit-admin (the L rows) rightly refuses
// to change a data directory as root. Two files are left out of that run because they test git
// itself: export-tag.test.mjs exports with this tool, and fixtures.test.mjs compares the release
// fixtures with the v1.4.2 tag. Without git or the history their history tests skip, or fail when
// TEST_REQUIRE lists history (a required check never turns green by skipping), so they run where
// git and the history input are: the host that made <dir>.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { historyFiles, sha256, tagProvenanceFile } from './fixtures.mjs';

/**
 * Writes the export of `tag` (a tag, or a milestone's version) from the private history into
 * `<directory>/<tag>/`; returns its provenance.
 */
export function exportTag(tag, directory) {
  if (!/^[A-Za-z0-9._-]+$/.test(tag ?? '')) throw new Error(`Not a tag name: ${tag}`);
  const found = historyFiles(tag);
  if (!found) throw new Error(`git cannot read ${tag} in the private history (TEST_HISTORY)`);
  const base = path.join(directory, tag);
  if (fs.existsSync(base)) throw new Error(`${base} exists already; remove it or pick another`);
  const provenance = { tag, commit: found.commit, files: {} };
  for (const [file, data] of [...found.files].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const target = path.join(base, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data, { mode: 0o644 });
    provenance.files[file] = sha256(data);
  }
  fs.writeFileSync(path.join(base, tagProvenanceFile), JSON.stringify(provenance, null, 2) + '\n');
  return provenance;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [tag, directory] = process.argv.slice(2);
  if (!tag || !directory) {
    console.error('Usage: node test/upgrade/export-tag.mjs <tag> <dir>');
    process.exit(2);
  }
  const provenance = exportTag(tag, path.resolve(directory));
  console.log(
    `Exported ${tag} (${provenance.commit}): ${Object.keys(provenance.files).length} files in ${path.join(path.resolve(directory), tag)}`
  );
}
