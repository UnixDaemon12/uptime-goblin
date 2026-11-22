// Build a source-only handoff. Never copy the working directory wholesale.
//
// Optional signing: with ORBIT_SIGNING_KEY=<path to an ssh signing key> (or to its .pub file when
// the private key lives in ssh-agent or on a hardware key), SHA256SUMS is signed with
//   ssh-keygen -Y sign -n orbit-release -f <key> SHA256SUMS
// producing SHA256SUMS.sig next to it. Verify an extracted release with a copy of
// deploy/allowed_signers obtained from a trusted place (never the one inside the archive):
//   ssh-keygen -Y verify -f allowed_signers -I release@orbit-homelab -n orbit-release \
//     -s SHA256SUMS.sig < SHA256SUMS && sha256sum -c --strict SHA256SUMS
// (on macOS: shasum -a 256 -c SHA256SUMS).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readManifest } from './check.mjs';

export const signingNamespace = 'orbit-release';
export const signingIdentity = 'release@orbit-homelab';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version))
  throw new Error('Invalid release version');
// The archive is named for the product since the rename to Uptime Goblin (Orbit releases before 1.5
// were orbit-homelab-<version>); the signing namespace and identity below keep their names, so the
// pinned key in deploy/allowed_signers and the verify line stay as they were.
const name = `uptime-goblin-${version}`,
  directory = path.join(root, 'release', name);
if (fs.existsSync(directory))
  throw new Error(`Release already exists: release/${name}. Move it aside before building again.`);
const signingKey = process.env.ORBIT_SIGNING_KEY || '';
if (signingKey && !fs.statSync(signingKey, { throwIfNoEntry: false })?.isFile())
  throw new Error('ORBIT_SIGNING_KEY must name a readable ssh signing key file');
const files = [
  'README.md',
  'LICENSE',
  '.prettierrc.json',
  '.prettierignore',
  'CONTRIBUTING.md',
  'SECURITY.md',
  'CHANGELOG.md',
  '.gitignore',
  '.dockerignore',
  '.env.example',
  'package.json',
  'package-lock.json',
  'server.mjs',
  'Dockerfile',
  'compose.yaml',
  'compose.secret.yaml',
  'sonar-project.properties',
];
const directories = ['lib', 'public', 'deploy', 'docs', 'examples', 'test', 'scripts', '.github'];
// Old-release and npm fixtures are for the upgrade simulation only. Packing them would nest
// every earlier release inside each new one.
const excluded = new Set(['test/fixtures/releases', 'test/fixtures/npm']);
function walk(relative) {
  if (fs.lstatSync(path.join(root, relative)).isSymbolicLink())
    throw new Error(`Symlinks are not allowed in release inputs: ${relative}`);
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    if (entry.name === '.DS_Store') continue;
    const item = path.posix.join(relative, entry.name);
    if (excluded.has(item)) continue;
    if (entry.isSymbolicLink())
      throw new Error(`Symlinks are not allowed in release inputs: ${item}`);
    if (entry.isDirectory()) walk(item);
    else if (entry.isFile()) files.push(item);
  }
}
for (const item of directories) if (fs.existsSync(path.join(root, item))) walk(item);
// Every runtime file must be in the archive, or the installer would refuse the release.
const packed = new Set(files);
const missing = readManifest(root).filter(file => !packed.has(file));
if (missing.length)
  throw new Error(
    `deploy/manifest.txt lists files that would not be packed: ${missing.join(', ')}`
  );
for (const file of files) {
  const absolute = path.join(root, file);
  if (!fs.lstatSync(absolute).isFile())
    throw new Error(`Release input is not a regular file: ${file}`);
  if (
    (/(?:^|\/)\.env(?:\.|$)/.test(file) && file !== '.env.example') ||
    /(?:^|\/)(?:data|node_modules|\.git|\.env)(?:\/|$)|\.(?:sqlite|db|pem|key|p12|pfx|log)(?:$|\.)/i.test(
      file
    ) ||
    /^SHA256SUMS(?:\.sig)?$/.test(file)
  )
    throw new Error(`Private or generated file in release inputs: ${file}`);
}
// Normalize every directory inside the archive too: tar preserves mode 700 from a private
// umask even though the files inside it were made world-readable.
const preparedDirectories = new Set([path.dirname(directory)]);
function prepareDirectory(target) {
  if (preparedDirectories.has(target)) return;
  prepareDirectory(path.dirname(target));
  fs.mkdirSync(target, { recursive: true });
  fs.chmodSync(target, 0o755);
  preparedDirectories.add(target);
}
prepareDirectory(directory);
const manifest = [];
for (const file of files.sort()) {
  const bytes = fs.readFileSync(path.join(root, file));
  const target = path.join(directory, file);
  prepareDirectory(path.dirname(target));
  fs.writeFileSync(target, bytes, { mode: file.endsWith('.sh') ? 0o755 : 0o644 });
  // Explicit modes: the packager's umask must not make the archive unreadable for others.
  fs.chmodSync(target, file.endsWith('.sh') ? 0o755 : 0o644);
  manifest.push(`${createHash('sha256').update(bytes).digest('hex')}  ${file}`);
}
fs.writeFileSync(path.join(directory, 'SHA256SUMS'), manifest.join('\n') + '\n');
fs.chmodSync(path.join(directory, 'SHA256SUMS'), 0o644);
if (signingKey) {
  const sums = path.join(directory, 'SHA256SUMS');
  try {
    execFileSync('ssh-keygen', ['-Y', 'sign', '-n', signingNamespace, '-f', signingKey, sums], {
      stdio: ['inherit', 'ignore', 'inherit'],
    });
    fs.chmodSync(`${sums}.sig`, 0o644);
    // Refuse a signature the pinned key would not accept, once the real key is pinned.
    const allowed = path.join(root, 'deploy', 'allowed_signers');
    const pinned = fs.existsSync(allowed)
      ? fs
          .readFileSync(allowed, 'utf8')
          .split('\n')
          .some(line => line.trim() && !line.trim().startsWith('#'))
      : false;
    const check = pinned
      ? ['-Y', 'verify', '-f', allowed, '-I', signingIdentity, '-n', signingNamespace]
      : ['-Y', 'check-novalidate', '-n', signingNamespace];
    execFileSync('ssh-keygen', [...check, '-s', `${sums}.sig`], {
      input: fs.readFileSync(sums),
      stdio: ['pipe', 'ignore', 'inherit'],
    });
    console.log(
      pinned
        ? 'Signed SHA256SUMS; the signature verifies against deploy/allowed_signers.'
        : 'Signed SHA256SUMS. deploy/allowed_signers has no key yet, so it was not checked against the pinned key.'
    );
  } catch (error) {
    // Leave nothing half-signed behind, so the next attempt can start afresh.
    fs.rmSync(directory, { recursive: true, force: true });
    throw new Error(`Signing SHA256SUMS failed; release/${name} was removed. ${error.message}`);
  }
}
const ownership =
  process.platform === 'darwin'
    ? ['--uid=0', '--gid=0', '--uname=root', '--gname=root']
    : ['--owner=0', '--group=0', '--numeric-owner'];
const metadata =
  process.platform === 'darwin'
    ? ['--no-xattrs', '--no-acls', '--no-fflags', '--no-mac-metadata']
    : ['--no-xattrs', '--no-acls'];
execFileSync(
  'tar',
  [...metadata, ...ownership, '-czf', `${directory}.tar.gz`, '-C', path.dirname(directory), name],
  { env: { ...process.env, COPYFILE_DISABLE: '1' } }
);
console.log(`Prepared ${files.length} source and documentation files in release/${name}`);
console.log(`Archive: release/${name}.tar.gz`);
console.log('Review the source before publishing. No live configuration or history is included.');
