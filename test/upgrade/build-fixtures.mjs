#!/usr/bin/env node
// Builds the upgrade-simulation fixtures from the published release tarballs:
//
//   node test/upgrade/build-fixtures.mjs [--releases DIR] [--nodemailer FILE] [--no-git]
//
// Each release tarball (release/orbit-homelab-<version>.tar.gz by default) is verified against
// its own SHA256SUMS first; 1.4.2 is also compared with the git tag v1.4.2 in the private history
// repository (TEST_HISTORY, test/upgrade/history.mjs; --no-git leaves that out). Only the runtime
// files are kept (see runtimeFile), with the release's SHA256SUMS and a provenance record of the
// version and source archive (never a commit id: the commit the tag named goes into the private
// history input, which this prints), in a deterministic tar, so rebuilding from the same releases
// gives the same content.
// nodemailer 10.0.10 comes from --nodemailer or the npm cache, checked against the integrity
// hash in package-lock.json. test/fixtures/SHA256SUMS pins the results; review its diff.
// Nothing here uses the network.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { gzip, readTar, writeTar } from './tar.mjs';
import {
  fixtures,
  formatSums,
  history,
  nodemailer,
  parseSums,
  provenanceFile,
  releaseFixture,
  root,
  runtimeFile,
  sha256,
  sri,
  versions,
} from './fixtures.mjs';

const { values: options } = parseArgs({
  options: {
    releases: { type: 'string', default: path.join(root, 'release') },
    nodemailer: { type: 'string' },
    'no-git': { type: 'boolean', default: false },
  },
});
const fail = message => {
  console.error(message);
  process.exit(1);
};
const git = (...args) => {
  const input = history();
  if (input.unavailable)
    fail(`${input.unavailable}; pass --no-git to build without the tag check.`);
  return execFileSync('git', ['-C', input.repository, ...args], { maxBuffer: 64 * 2 ** 20 });
};

function verifiedRelease(version) {
  const name = `orbit-homelab-${version}`,
    file = path.join(options.releases, `${name}.tar.gz`),
    archive = fs.readFileSync(file),
    files = new Map();
  for (const entry of readTar(archive)) {
    if (!entry.path.startsWith(name + '/')) fail(`${file}: ${entry.path} is outside ${name}/`);
    files.set(entry.path.slice(name.length + 1), entry.data);
  }
  const sums = parseSums(files.get('SHA256SUMS')?.toString('utf8') ?? '');
  if (!sums.size) fail(`${file}: no SHA256SUMS`);
  for (const [path, data] of files)
    if (path !== 'SHA256SUMS' && sums.get(path) !== sha256(data))
      fail(`${file}: ${path} does not match the release SHA256SUMS`);
  for (const path of sums.keys()) if (!files.has(path)) fail(`${file}: ${path} is missing`);
  return { archive, files };
}
// The tagged commit must hold exactly the released runtime files.
function compareWithTag(version, runtime) {
  const tag = `v${version}`,
    tree = git('ls-tree', '-r', '--name-only', tag)
      .toString('utf8')
      .split('\n')
      .filter(runtimeFile);
  const expected = [...runtime.keys()].sort();
  if (JSON.stringify(tree.sort()) !== JSON.stringify(expected))
    fail(`${tag}: runtime files differ from the release tarball`);
  for (const [file, data] of runtime)
    if (!git('show', `${tag}:${file}`).equals(data))
      fail(`${tag}: ${file} differs from the release`);
  return git('rev-parse', `${tag}^{commit}`).toString('utf8').trim();
}
function findNodemailer() {
  if (options.nodemailer) return fs.readFileSync(options.nodemailer);
  // npm's content-addressed cache stores a tarball under the hex of its integrity hash.
  const cache = process.env.npm_config_cache
      ? path.join(process.env.npm_config_cache, '_cacache')
      : path.join(os.homedir(), '.npm', '_cacache'),
    hex = Buffer.from(nodemailer.integrity.slice('sha512-'.length), 'base64').toString('hex'),
    file = path.join(cache, 'content-v2', 'sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
  if (!fs.existsSync(file))
    fail(`nodemailer ${nodemailer.version} is not in the npm cache; pass --nodemailer <tgz>.`);
  return fs.readFileSync(file);
}
// Keeps an existing fixture when its content is unchanged, so another zlib build cannot
// change the committed bytes (and their pin) without a content change.
function writeFixture(file, tar) {
  const target = path.join(fixtures, file);
  try {
    if (zlib.gunzipSync(fs.readFileSync(target)).equals(tar)) return 'unchanged';
  } catch {}
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, gzip(tar), { mode: 0o644 });
  return 'written';
}

const pins = new Map();
for (const version of versions) {
  const { archive, files } = verifiedRelease(version),
    runtime = new Map([...files].filter(([file]) => runtimeFile(file))),
    lock = JSON.parse(runtime.get('package-lock.json'));
  if (lock.packages?.['node_modules/nodemailer']?.integrity !== nodemailer.integrity)
    fail(`${version}: package-lock.json names another nodemailer`);
  const provenance = {
    version,
    source: { file: `orbit-homelab-${version}.tar.gz`, sha256: sha256(archive) },
  };
  if (version === versions.at(-1) && !options['no-git'])
    console.log(
      `v${version} names ${compareWithTag(version, runtime)} in the private history: record it there`
    );
  const tar = writeTar([
    ...[...runtime].map(([file, data]) => ({ path: file, data })),
    { path: 'SHA256SUMS', data: files.get('SHA256SUMS') },
    { path: provenanceFile, data: Buffer.from(JSON.stringify(provenance, null, 2) + '\n') },
  ]);
  const file = releaseFixture(version);
  console.log(`${file}: ${runtime.size} runtime files, ${writeFixture(file, tar)}`);
  pins.set(file, sha256(fs.readFileSync(path.join(fixtures, file))));
}
const tarball = findNodemailer();
if (sri(tarball) !== nodemailer.integrity) fail('nodemailer tarball does not match its integrity');
fs.mkdirSync(path.join(fixtures, 'npm'), { recursive: true });
fs.writeFileSync(path.join(fixtures, nodemailer.file), tarball, { mode: 0o644 });
pins.set(nodemailer.file, sha256(tarball));
fs.writeFileSync(path.join(fixtures, 'SHA256SUMS'), formatSums(pins));
console.log(`Pinned ${pins.size} fixtures in test/fixtures/SHA256SUMS.`);
