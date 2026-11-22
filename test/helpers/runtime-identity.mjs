// Synthetic runtime identity records for the gate's throwaway fixture repositories. A test stage
// is dispatched only once test-host and runtime-identity have passed in its run and apply to it,
// in a maintenance (B35) run too (scripts/security-dispatch.mjs, testStagePrerequisiteProblems;
// the security review's GD5-CARRY-01 and GDR6-REQ-01, v5 C3), and runtime-identity passes only
// with a record for each runtime the test stages will run. A test that needs such a run's test
// stage to start (with a synthetic dispatch authority, test/helpers/dispatch-authority.mjs) writes
// these records into its fixture repository, where the gate reads them
// (`<git common dir>/orbit-security/runtime-identity/`). Each describes the Node binary as a Node
// release with a verified signed SHASUMS check, as the official runtimes the tests run on are, and
// a reviewed list of release keys beside it. They are synthetic: their hashes, signer and review
// are made up, no signature was checked, and nothing outside a fixture reads them.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const architectures = {
  darwin: { arm64: 'arm64', x64: 'x64' },
  linux: { arm64: 'arm64', x64: 'x64', arm: 'armv7l', ppc64: 'ppc64le', s390x: 's390x' },
};
const signer = 'C0FFEE'.padEnd(40, 'A');
const keyringSha256 = '6'.repeat(64);

/** The sha256 of an executable's real file, as the gate hashes a test stage's runtime. */
export const executableSha256 = executable =>
  createHash('sha256')
    .update(fs.readFileSync(fs.realpathSync(executable)))
    .digest('hex');

/**
 * Writes a runtime identity record for each of `runtimes` ({ executable, version }: a Node
 * executable a test stage will run and the version it reports) and the reviewed release keys they
 * name into `<root>/.git/orbit-security/runtime-identity/`. Returns the sha256 of each executable,
 * in order.
 */
export function writeRuntimeIdentity(root, runtimes, now = Date.now()) {
  const folder = path.join(root, '.git/orbit-security/runtime-identity');
  fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
  const recordedAt = new Date(now - 60000).toISOString();
  const write = (name, value) =>
    fs.writeFileSync(path.join(folder, name), `${JSON.stringify(value, null, 2)}\n`, {
      mode: 0o600,
    });
  const hashes = [];
  for (const { executable, version } of runtimes) {
    const binarySha256 = executableSha256(executable);
    hashes.push(binarySha256);
    write(`${binarySha256}.json`, {
      schemaVersion: 1,
      binarySha256,
      version,
      platform: process.platform,
      arch: process.arch,
      distribution: 'nodejs-release',
      release: {
        archive: `node-${version}-${process.platform}-${architectures[process.platform]?.[process.arch]}.tar.xz`,
        archiveSha256: '3'.repeat(64),
        shasumsSha256: '4'.repeat(64),
        signatureSha256: '5'.repeat(64),
        signer,
        keyringSha256,
        outcome: 'verified',
      },
      recordedAt,
      reference: 'synthetic runtime identity fixture',
    });
  }
  write('release-keys.json', {
    schemaVersion: 1,
    keyringSha256,
    fingerprints: [signer],
    source: 'synthetic release keys fixture',
    sourceSha256: 'd'.repeat(64),
    reviewer: 'Synthetic reviewer',
    reference: 'synthetic release keys review',
    reviewedAt: recordedAt,
  });
  return hashes;
}

/**
 * The runtimes a fixture's platform manifest requires so that a gate started on this runtime,
 * with the fixtures' Node 24 stand-in as ORBIT_SECURITY_NODE24, covers every one: Node 24 and 26 on
 * Node 26 (the real matrix), and on Node 24 the Node 24 route alone. A gate started on Node 24 runs
 * Node 24 in both test stages, so a run that needs Node 26 blocks at runtime-identity there, and
 * the tests show that separately; the repository's own manifest keeps requiring both.
 */
export const gateRuntimes = () => [...new Set(['24', process.versions.node.split('.')[0]])].sort();
