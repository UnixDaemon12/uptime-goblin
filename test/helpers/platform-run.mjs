// Synthetic platform evidence for the tests of the gate's side of the platform contract
// (scripts/security-platform.mjs, scripts/security-finalization.mjs): a small platform manifest,
// the TAP log and records of each test stage with the T8 container evidence inside, each
// runtime's identity record, the T8 images' authenticity records, the network record of a Linux
// run, a sealed gate run (commit mode) carrying all of it and sealed companion runs (platform
// mode). This is test evidence for the checks, never a test result. Each part can be changed
// before it is written, so a test can make exactly one thing wrong.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { sha256 } from '../../scripts/security-evidence.mjs';
import { installedCatalog, profileStages } from '../../scripts/security-catalog.mjs';
import {
  candidateParents,
  finalizeRun,
  inspectRun,
  lintStageNames,
  platformInputs,
  sealRun,
} from '../../scripts/security-finalization.mjs';
import {
  LOCAL_RUN_KIND,
  LOCAL_RUN_KIND_VERSION,
  actionlintArguments,
  actionlintConfigFile,
  activationBinding,
  activationBindingFile,
  builtImageStages,
  imageRecordName,
  packRecords,
  pendingRecordStages,
  t8InspectCommand,
} from '../../scripts/security-platform.mjs';
import {
  actionlintClosureSha256,
  actionlintPath,
  actionlintSha256,
  candidate as stagedCandidate,
  goldenActionlint,
  identityOf,
  reviewBinding,
  securityTools,
  writeRun,
} from './security-run.mjs';
export { reviewBinding } from './security-run.mjs';

const tools = JSON.parse(securityTools);
const catalog = installedCatalog();
/** The catalog's stage ids of a profile, in catalog order (an id in two phases once). */
export const catalogStages = profile => profileStages(catalog.catalog, profile, 'commit').all;
/** A run record's catalog binding for `profile`. */
export const catalogOf = profile => ({ mode: 'commit', profile, sha256: catalog.sha256 });
/**
 * A synthetic version 3 gate identity (GATE-CONTRACT v4 C1) of the installed catalog, as the
 * gate-identity stage of a synthetic run carries it. Synthetic: no trusted bootstrap computed it.
 */
export const syntheticGateIdentity = () => ({
  catalogSha256: catalog.sha256,
  closureSha256: '1'.repeat(64),
  configSha256: '2'.repeat(64),
  entrySha256: '3'.repeat(64),
  runtime: {
    node24: { binarySha256: '4'.repeat(64), runtimeRecordSha256: '5'.repeat(64) },
    node26: { binarySha256: '6'.repeat(64), runtimeRecordSha256: '7'.repeat(64) },
  },
  toolPaths: {
    actionlint: '/synthetic/golden/actionlint',
    gitleaks: '/synthetic/golden/gitleaks',
    node24: '/synthetic/node-v24/bin/node',
    node26: '/synthetic/node-v26/bin/node',
    trivy: '/synthetic/golden/trivy',
  },
  toolPinsSha256: '8'.repeat(64),
  version: 3,
});
/**
 * The order in which the gate (scripts/security-gate.mjs) records the stages of a Linux gate run
 * with the platform contract, which holds both phases' stages in one local run, and of a
 * companion run: every order rule the finalizer checks holds for it (orderProblems in
 * scripts/security-platform.mjs). A synthetic run is written in this order, each stage with an
 * interval of its own, one after another inside the run's window.
 */
export const gateOrder = Object.freeze([
  'gate-identity',
  'gate-import-closure',
  'snapshot-clone',
  'snapshot-index',
  'snapshot-files',
  'gate-implementation',
  'candidate-policy',
  'platform-manifest',
  'gitleaks-version',
  'trivy-version',
  'actionlint-version',
  'docker-version',
  'npm-version',
  't8-image-identity',
  't8-image-authenticity',
  't8-image-activation',
  'sql-lint',
  'import-lint',
  'pristine-copy',
  'dependencies-install',
  'format',
  'syntax-manifest',
  'documentation',
  'dependencies-all',
  'dependencies-production',
  'registry-signatures',
  'workflow-analysis',
  'secrets-source',
  'secrets-history',
  'secrets-metadata',
  'image-approval',
  'sast-rules',
  'sast-image',
  'source-analysis',
  'container-configuration',
  'container-build',
  'container-identity',
  'container-vulnerabilities',
  'container-sbom',
  'scanner-database',
  'systemd-test-image',
  'test-host',
  'minimum-runtime-available',
  'runtime-identity',
  'full-tests-current-runtime',
  'platform-coverage-current-runtime',
  'full-tests-minimum-runtime',
  'platform-coverage-minimum-runtime',
  'network-policy',
  'independent-review',
  'candidate-unchanged',
]);
export const companionOrder = Object.freeze([
  'gate-identity',
  'gate-import-closure',
  'candidate-policy',
  'platform-manifest',
  'test-host',
  'npm-version',
  'prepared-inputs',
  't8-image-identity',
  't8-image-authenticity',
  't8-image-activation',
  'minimum-runtime-available',
  'runtime-identity',
  'platform-tests-current-runtime',
  'platform-coverage-current-runtime',
  'platform-tests-minimum-runtime',
  'platform-coverage-minimum-runtime',
  'network-policy',
  'candidate-unchanged',
]);

/**
 * `stages` in `order` (a name the order does not know keeps its place after those it does), each
 * given its own interval: the stages follow one another, `step` milliseconds apart, from `start`,
 * each lasting half a step, so every order rule the finalizer checks holds on the recorded
 * intervals. Returns them.
 */
export function inOrder(stages, order, start, step) {
  const rank = name => {
    const index = order.indexOf(name);
    return index < 0 ? order.length : index;
  };
  const sorted = stages
    .map((stage, index) => ({ stage, index }))
    .sort((a, b) => rank(a.stage.name) - rank(b.stage.name) || a.index - b.index)
    .map(item => item.stage);
  sorted.forEach((stage, index) => {
    stage.started = new Date(start + index * step).toISOString();
    stage.finished = new Date(start + index * step + Math.floor(step / 2)).toISOString();
  });
  return sorted;
}

/** The reason a synthetic run records for a stage whose record form is pending (v5 C17 item 12). */
const pendingReason = name => `synthetic: ${pendingRecordStages[name]}`;

// The synthetic pinned Actionlint (test/helpers/security-run.mjs), for the tests that use this module.
export { actionlintPath, goldenActionlint } from './security-run.mjs';
const both = ['24', '26'];
const digestOf = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/**
 * The synthetic image of Node `runtime`, as a registry serves it: an OCI index with an image
 * manifest for linux/arm64/v8 and one for linux/amd64 (and an attestation, as Docker Hub adds),
 * the arm64 manifest's exact bytes and the digests of the three. Fixture bytes, not a real image.
 */
export function imageParts(runtime) {
  const descriptor = (mediaType, bytes, extra = {}) => ({
    mediaType,
    digest: digestOf(bytes),
    size: Buffer.byteLength(bytes),
    ...extra,
  });
  const manifestOf = architecture => {
    const config = `synthetic image config of Node ${runtime} on ${architecture}`;
    return Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        config: descriptor('application/vnd.oci.image.config.v1+json', config),
        layers: [],
      })
    );
  };
  const arm64 = manifestOf('arm64');
  const amd64 = manifestOf('amd64');
  const index = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [
        descriptor('application/vnd.oci.image.manifest.v1+json', amd64, {
          platform: { architecture: 'amd64', os: 'linux' },
        }),
        descriptor('application/vnd.oci.image.manifest.v1+json', arm64, {
          platform: { architecture: 'arm64', os: 'linux', variant: 'v8' },
        }),
        descriptor('application/vnd.oci.image.manifest.v1+json', 'synthetic attestation', {
          platform: { architecture: 'unknown', os: 'unknown' },
        }),
      ],
    })
  );
  return {
    index,
    manifest: arm64,
    other: amd64,
    indexDigest: digestOf(index),
    manifestDigest: digestOf(arm64),
    otherDigest: digestOf(amd64),
    configDigest: JSON.parse(arm64).config.digest,
  };
}
export const imageOf = {
  24: `node:24-bookworm-slim@${imageParts('24').indexDigest}`,
  26: `node:26-bookworm-slim@${imageParts('26').indexDigest}`,
};
export const versionOf = { 24: 'v24.21.0', 26: 'v26.5.1' };
export const testFiles = [
  'test/linux.test.mjs',
  'test/mac.test.mjs',
  'test/plain.test.mjs',
  'test/t8.test.mjs',
];
export const plainTest = 'a test that runs everywhere';

/** A small valid platform manifest, shaped like the real one (a fresh object each time). */
export function syntheticManifest() {
  const entry = (id, file, name, platforms, evidence, prerequisites = []) => ({
    id,
    file,
    name: [name],
    platforms,
    runtimes: [...both],
    prerequisites,
    evidence,
  });
  return {
    schemaVersion: 1,
    runs: {
      'darwin-full': {
        platform: 'darwin',
        runtimes: [...both],
        files: 'all',
        requiredFor: ['release'],
      },
      'darwin-platform': {
        platform: 'darwin',
        runtimes: [...both],
        files: ['test/mac.test.mjs'],
        requiredFor: ['commit', 'release'],
      },
      'linux-full': {
        platform: 'linux',
        runtimes: [...both],
        files: 'all',
        requiredFor: ['commit', 'release'],
      },
      't8-container': {
        platform: 'container',
        runtimes: [...both],
        files: ['test/t8.test.mjs'],
        requiredFor: ['commit', 'release'],
        images: {
          24: { image: imageOf[24], driver: 't8.driver.node24' },
          26: { image: imageOf[26], driver: 't8.driver.node26' },
        },
        hostRuns: ['darwin-full', 'linux-full'],
      },
    },
    entries: [
      entry(
        'mac.acl',
        'test/mac.test.mjs',
        'the macOS access list',
        ['darwin'],
        ['darwin-full', 'darwin-platform']
      ),
      entry('linux.acl', 'test/linux.test.mjs', 'the Linux access list', ['linux'], ['linux-full']),
      entry(
        't8.environment',
        'test/t8.test.mjs',
        'T8 environment',
        ['container'],
        ['t8-container']
      ),
      entry('t8.part-b', 'test/t8.test.mjs', 'T8 part B', ['container'], ['t8-container']),
      entry(
        't8.driver.node24',
        'test/t8.test.mjs',
        'T8 driver on Node 24',
        ['darwin', 'linux'],
        ['darwin-full', 'linux-full'],
        ['docker']
      ),
      entry(
        't8.driver.node26',
        'test/t8.test.mjs',
        'T8 driver on Node 26',
        ['darwin', 'linux'],
        ['darwin-full', 'linux-full'],
        ['docker']
      ),
    ],
  };
}
export const manifestText = manifest => `${JSON.stringify(manifest, null, 2)}\n`;

const gitBlob = bytes =>
  createHash('sha1')
    .update(`blob ${Buffer.byteLength(bytes)}\0`)
    .update(bytes)
    .digest('hex');

/** The candidate's files as sourceManifest() lists them, with this manifest (or none). */
export function candidateFiles(manifestBytes) {
  const file = (name, bytes) => ({
    file: name,
    mode: '100644',
    blob: gitBlob(bytes),
    sha256: sha256(bytes),
  });
  const files = [
    file('Dockerfile', '# Synthetic fixture\n'),
    file('example.mjs', 'export const synthetic = true;\n'),
    file('scripts/security-tools.json', securityTools),
    ...testFiles.map(name => file(name, `// Synthetic ${name}\n`)),
  ];
  if (manifestBytes) files.push(file('test/platform-manifest.json', manifestBytes));
  return files.sort((a, b) => (a.file < b.file ? -1 : 1));
}

/** A TAP log of node's reporter: top-level results ({ name, ok = true, directive }) and totals. */
export function tapOf(results, totals = {}) {
  const lines = ['TAP version 13'];
  results.forEach((result, index) =>
    lines.push(
      `${result.ok === false ? 'not ok' : 'ok'} ${index + 1} - ${result.name}${result.directive ? ` # ${result.directive}` : ''}`
    )
  );
  const count = (pick, value) => results.filter(pick).length + (value ?? 0);
  const values = {
    tests: results.length,
    pass: count(item => item.ok !== false && !item.directive),
    fail: count(item => item.ok === false),
    cancelled: 0,
    skipped: count(item => /^SKIP/.test(item.directive ?? '')),
    todo: count(item => /^TODO/.test(item.directive ?? '')),
    ...totals,
  };
  lines.push(`1..${results.length}`);
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'])
    lines.push(`# ${name} ${values[name]}`);
  return `${lines.join('\n')}\n`;
}

const recordFileName = () => `4242-${randomUUID()}.jsonl`;
const jsonl = records => records.map(record => `${JSON.stringify(record)}\n`).join('');

/**
 * The evidence of one test stage of run `runId` on Node `runtime`: its TAP log and its records
 * folder, packed as the gate seals it. `change.host({ results, records, totals })` and
 * `change.inner(runtime, { results, records, code, node, container })` may change the parts first.
 */
export function stageEvidence({ manifest, manifestSha256, runId, runtime, nonce, change = {} }) {
  const run = manifest.runs[runId];
  const files = run.files === 'all' ? testFiles : run.files;
  const registered = manifest.entries.filter(
    entry => entry.platforms.includes(run.platform) && files.includes(entry.file)
  );
  const host = {
    results: registered.map(entry => ({ name: entry.name[0] })),
    records: registered.map(entry => ({
      kind: 'result',
      id: entry.id,
      file: entry.file,
      name: entry.name,
      platform: run.platform,
      node: versionOf[runtime],
      result: 'completed',
      run: nonce,
      manifest: manifestSha256,
    })),
  };
  if (files.includes('test/plain.test.mjs')) host.results.push({ name: plainTest });
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-platform-fixture-'));
  try {
    const containers = [];
    for (const [containerId, container] of Object.entries(manifest.runs)) {
      if (container.platform !== 'container' || !container.hostRuns.includes(runId)) continue;
      for (const inner of container.runtimes) {
        const image = container.images[inner];
        if (!image) continue;
        const code = createHash('sha256').update(`${nonce}-${inner}`).digest('hex');
        const entries = manifest.entries.filter(entry => entry.evidence.includes(containerId));
        const parts = {
          code,
          node: versionOf[inner],
          results: entries.map(entry => ({ name: entry.name[0] })),
          records: entries.map(entry => ({
            kind: 'result',
            id: entry.id,
            file: entry.file,
            name: entry.name,
            platform: 'container',
            node: versionOf[inner],
            result: 'completed',
            run: code,
            manifest: manifestSha256,
          })),
          container: {
            image: image.image,
            imageId: image.image.split('@')[1],
            driver: image.driver,
          },
        };
        change.inner?.(inner, parts);
        const directory = `t8-container-${inner}-${randomUUID().replace(/-/g, '').slice(0, 6)}`;
        fs.mkdirSync(path.join(folder, directory, 'records'), { recursive: true });
        const innerTap = tapOf(parts.results);
        fs.writeFileSync(path.join(folder, directory, 'inner.tap'), innerTap);
        const recordName = recordFileName();
        const recordBytes = jsonl(parts.records);
        fs.writeFileSync(path.join(folder, directory, 'records', recordName), recordBytes);
        containers.push({
          kind: 'container',
          id: parts.container.driver,
          runtime: inner,
          image: parts.container.image,
          imageId: parts.container.imageId,
          code: parts.code,
          node: parts.node,
          evidence: directory,
          tapSha256: sha256(innerTap),
          recordsSha256: createHash('sha256')
            .update(`${recordName}\0${sha256(recordBytes)}\n`)
            .digest('hex'),
          run: nonce,
          manifest: manifestSha256,
        });
      }
    }
    host.records.push(...containers);
    change.host?.(host);
    fs.writeFileSync(path.join(folder, recordFileName()), jsonl(host.records));
    return { tap: tapOf(host.results, host.totals), pack: packRecords(folder), containers };
  } finally {
    fs.rmSync(folder, { recursive: true, force: true });
  }
}

/** The fake sha256 of the Node `runtime` binary on `platform`. */
export const binaryOf = (platform, runtime) =>
  createHash('sha256').update(`synthetic node ${platform} ${runtime}`).digest('hex');

/** A runtime identity record: a verified Node release on Linux, a reviewed Homebrew build on macOS. */
export function runtimeRecord(platform, runtime, now) {
  const recordedAt = new Date(now - 60000).toISOString();
  const common = {
    schemaVersion: 1,
    binarySha256: binaryOf(platform, runtime),
    version: versionOf[runtime],
    platform,
    arch: 'arm64',
    recordedAt,
    reference: 'synthetic runtime identity fixture',
  };
  if (platform === 'linux')
    return {
      ...common,
      distribution: 'nodejs-release',
      release: {
        archive: `node-${versionOf[runtime]}-linux-arm64.tar.xz`,
        archiveSha256: '3'.repeat(64),
        shasumsSha256: '4'.repeat(64),
        signatureSha256: '5'.repeat(64),
        signer: 'C0FFEE'.padEnd(40, 'A'),
        keyringSha256: '6'.repeat(64),
        outcome: 'verified',
      },
    };
  return {
    ...common,
    distribution: 'homebrew',
    homebrew: {
      formula: runtime === '24' ? 'node@24' : 'node',
      version: versionOf[runtime].slice(1),
      bottleSha256: '7'.repeat(64),
    },
    exception: {
      reason: 'synthetic: a Homebrew build, not a Node release binary',
      reviewer: 'Synthetic reviewer',
      reference: 'synthetic exception fixture',
      reviewedAt: recordedAt,
    },
  };
}

/** What Docker reports of an image (one line of docker image inspect --format '{{json .}}'). */
export const inspection = (image, overrides = {}) => ({
  Id: image.split('@')[1],
  RepoDigests: [`node@${image.split('@')[1]}`],
  Os: 'linux',
  Architecture: 'arm64',
  Variant: 'v8',
  ...overrides,
});

/** A verified authenticity record of `image` (one of imageOf) on linux/arm64/v8. */
export function imageRecord(image, now) {
  const parts = imageParts(/^node:(\d+)-/.exec(image)?.[1]);
  return {
    schemaVersion: 1,
    image,
    indexDigest: image.split('@')[1],
    platform: { os: 'linux', architecture: 'arm64', variant: 'v8' },
    platformManifestDigest: parts.manifestDigest,
    configDigest: parts.configDigest,
    indexBase64: parts.index.toString('base64'),
    platformManifestBase64: parts.manifest.toString('base64'),
    outcome: 'verified',
    verification: {
      mechanism: 'synthetic signature check',
      identity: 'synthetic publisher',
      trustRoot: 'synthetic trust root',
      evidenceSha256: 'a'.repeat(64),
    },
    recordedAt: new Date(now - 60000).toISOString(),
  };
}

/** The reviewed list of Node release keys the Linux fixture records name. */
export const releaseKeys = now => ({
  schemaVersion: 1,
  keyringSha256: '6'.repeat(64),
  fingerprints: ['C0FFEE'.padEnd(40, 'A'), 'B'.repeat(40)],
  source: 'synthetic release keys fixture',
  sourceSha256: 'd'.repeat(64),
  reviewer: 'Synthetic reviewer',
  reference: 'synthetic release keys review',
  reviewedAt: new Date(now - 60000).toISOString(),
});

/** A network state snapshot in the test phase. */
export const networkState = (observedAt, overrides = {}) => ({
  schemaVersion: 1,
  phase: 'test',
  policySha256: 'b'.repeat(64),
  enforcement: 'outside-guest',
  epoch: 'synthetic-epoch-1',
  counters: { 'egress-drop': { packets: 3, bytes: 180 }, 'egress-allow': { packets: 0, bytes: 0 } },
  observedAt,
  ...overrides,
});
export const networkPolicy = now => ({
  schemaVersion: 1,
  sha256: 'b'.repeat(64),
  reviewer: 'Synthetic reviewer',
  reference: 'synthetic network policy fixture',
  reviewedAt: new Date(now - 60000).toISOString(),
});

const json = value => `${JSON.stringify(value)}\n`;

/**
 * The platform evidence of the test stages of a run (`prefix` full-tests- or platform-tests-):
 * { stages: changes to the stage records, files, logs }. `change` as in stageEvidence, plus
 * `runtime(record, platform, runtime)`, `releaseKeys(record)`, `image(record, image)`,
 * `inspect(line, image)`, `network(snapshots)` and `policy(record)` to change the other records.
 */
function testEvidence({ manifest, manifestSha256, runId, platform, prefix, now, change = {} }) {
  const files = {};
  const logs = {};
  const stages = {};
  const containers = [];
  const identities = [];
  const snapshots = [];
  for (const [slot, runtime] of [
    ['current-runtime', '26'],
    ['minimum-runtime', '24'],
  ]) {
    const name = `${prefix}${slot}`;
    const nonce = createHash('sha256').update(`${name} ${now} ${platform}`).digest('hex');
    const evidence = stageEvidence({ manifest, manifestSha256, runId, runtime, nonce, change });
    containers.push(...evidence.containers);
    logs[name] = evidence.tap;
    files[`${name}.records.json`] = evidence.pack;
    const sha = binaryOf(platform, runtime);
    const identity = runtimeRecord(platform, runtime, now);
    change.runtime?.(identity, platform, runtime);
    files[`runtime-identity-${sha}.json`] = json(identity);
    identities.push({
      path: `/synthetic/node${runtime}`,
      version: versionOf[runtime],
      sha256: sha,
      record: `runtime-identity-${sha}.json`,
    });
    const totals = Object.fromEntries(
      ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'].map(item => [
        item,
        Number(new RegExp(`^# ${item} (\\d+)$`, 'm').exec(evidence.tap)[1]),
      ])
    );
    stages[name] = {
      tests: totals,
      runtime: { path: `/synthetic/node${runtime}`, version: versionOf[runtime], sha256: sha },
      platformRun: nonce,
      records: `${name}.records.json`,
    };
    stages[`platform-coverage-${slot}`] = {
      of: name,
      run: runId,
      runtime,
      report: `${name}.coverage.json`,
    };
    files[`${name}.coverage.json`] = json({ synthetic: true });
    if (platform === 'linux') {
      const snapshot = {
        stage: name,
        before: { file: `network-${name}-before.json`, readAt: null },
        after: { file: `network-${name}-after.json`, readAt: null },
      };
      snapshots.push(snapshot);
    }
  }
  stages['runtime-identity'] = { runtimes: identities };
  if (platform === 'linux') {
    const keys = releaseKeys(now);
    change.releaseKeys?.(keys);
    files['runtime-release-keys.json'] = json(keys);
    stages['runtime-identity'].releaseKeys = 'runtime-release-keys.json';
  }
  const hosted = Object.values(manifest.runs).some(
    run => run.platform === 'container' && run.hostRuns.includes(runId)
  );
  if (hosted) {
    const images = [...new Set(containers.map(item => item.image))].sort();
    logs['t8-image-identity'] = images
      .map(image => {
        const line = inspection(image);
        change.inspect?.(line, image);
        return JSON.stringify(line);
      })
      .join('\n');
    const records = [];
    for (const image of images) {
      const record = imageRecord(image, now);
      change.image?.(record, image);
      const name = `image-authenticity-${imageRecordName(image, { os: 'linux', architecture: 'arm64', variant: 'v8' })}`;
      files[name] = json(record);
      records.push({ image, file: name });
    }
    // As the gate records them (v5 C5, C17 item 12): t8-image-identity ran its local read-only
    // observation and stays pending; t8-image-authenticity and t8-image-activation are pending
    // requirements, the activation with its binding (written once the run's times are set).
    stages['t8-image-identity'] = {
      command: t8InspectCommand(images),
      images,
      status: 'pending',
      reason: pendingReason('t8-image-identity'),
    };
    stages['t8-image-authenticity'] = {
      records,
      status: 'pending',
      reason: pendingReason('t8-image-authenticity'),
    };
    stages['t8-image-activation'] = {
      status: 'pending',
      reason: pendingReason('t8-image-activation'),
      binding: activationBindingFile,
    };
  }
  if (platform === 'linux') {
    stages['network-policy'] = { snapshots, policy: 'network-policy.json' };
    const policy = networkPolicy(now);
    change.policy?.(policy);
    files['network-policy.json'] = json(policy);
  }
  return { files, logs, stages, snapshots };
}

/** Times inside a run: started, finished, and the network snapshots around each test stage. */
function timeNetwork(snapshots, files, stage, change) {
  for (const snapshot of snapshots.filter(item => item.stage === stage.name)) {
    const started = Date.parse(stage.started),
      finished = Date.parse(stage.finished);
    const before = networkState(new Date(started - 400).toISOString());
    const after = networkState(new Date(finished + 100).toISOString(), {
      counters: {
        'egress-drop': { packets: 5, bytes: 300 },
        'egress-allow': { packets: 0, bytes: 0 },
      },
    });
    snapshot.before.readAt = new Date(started - 200).toISOString();
    snapshot.after.readAt = new Date(finished + 200).toISOString();
    change.network?.({ before, after, snapshot });
    files[snapshot.before.file] = json(before);
    files[snapshot.after.file] = json(after);
  }
}

/**
 * The inputs of the judgment for a candidate whose manifest is new (no commit behind it held one):
 * its kind is introduction.
 */
export function introductionInputs(current, manifestBytes) {
  return {
    candidate: manifestBytes,
    heads: [...current.parents],
    complete: true,
    reason: '',
    refused: [],
    history: current.parents.map((commit, index) => ({
      commit,
      parents: [],
      manifest: null,
      reviewed: null,
      tree: `${'e'.repeat(39)}${index}`,
    })),
  };
}

/**
 * A candidate (`tree`, and `parents`, its complete ordered parent vector, or one `parent`) with
 * this manifest: { current, manifest, manifestBytes, manifestSha256 }. `current` carries the
 * judgment's inputs (an introduction) and no companions.
 */
export function platformCandidate({ manifest = syntheticManifest(), tree, parent, parents } = {}) {
  const manifestBytes = Buffer.from(manifestText(manifest));
  const vector = parents ?? [parent ?? 'd'.repeat(40)];
  const current = {
    tree: tree ?? 'c'.repeat(40),
    parent: vector[0],
    parents: vector,
    refs: `refs/heads/main ${vector[0]}`,
    files: candidateFiles(manifestBytes),
    lintStages: lintStageNames,
  };
  current.platform = introductionInputs(current, manifestBytes);
  current.companions = [];
  return { current, manifest, manifestBytes, manifestSha256: sha256(manifestBytes) };
}

/**
 * Writes and seals a gate run (commit mode) on `platform` for the candidate, with every shared
 * stage and its platform evidence. `change` as in testEvidence, plus `record(record)` last.
 */
export function writeMainRun(
  run,
  candidate,
  { platform = 'linux', now = Date.now(), change = {} } = {}
) {
  const { current, manifest, manifestBytes, manifestSha256 } = candidate;
  const runId = Object.entries(manifest.runs).find(
    ([, item]) => item.platform === platform && item.files === 'all'
  )[0];
  const evidence = testEvidence({
    manifest,
    manifestSha256,
    runId,
    platform,
    prefix: 'full-tests-',
    now,
    change,
  });
  const files = {
    ...evidence.files,
    'platform-manifest.json': manifestBytes,
    'platform-judgment.json': json({ synthetic: true }),
    [`golden-tool-actionlint-${platform}-arm64.json`]: json(goldenActionlint(platform, now)),
    [actionlintConfigFile]: '',
  };
  const { platform: inputs, companions, lintStages, ...plain } = current;
  // Every stage of the catalog's linux-full profile (v5 C23), as a Linux gate run reports them:
  // the two image builds, container-identity and the scans of the built image pending, since no
  // build starts while its pre-build authority record is pending (v5 C5 change 3).
  writeRun(run, plain, catalogStages('linux-full'), now, {
    logs: evidence.logs,
    files,
    catalog: catalogOf(platform === 'linux' ? 'linux-full' : null),
    platformManifest: { sha256: manifestSha256, state: 'valid' },
    pending: ['container-build', 'container-identity', ...builtImageStages, 'systemd-test-image'],
    record: written => {
      const actionlint = written.stages.find(stage => stage.name === 'actionlint-version');
      actionlint.tool = {
        path: actionlintPath,
        sha256: actionlintSha256,
        version: tools.actionlint,
        record: `golden-tool-actionlint-${platform}-arm64.json`,
        dependencyClosureSha256: actionlintClosureSha256,
      };
      const analysis = written.stages.find(stage => stage.name === 'workflow-analysis');
      analysis.command = [actionlintPath, ...actionlintArguments(`${run}/${actionlintConfigFile}`)];
      written.host = {
        platform,
        arch: 'arm64',
        release: 'synthetic',
        node: versionOf[26],
        uid: 501,
      };
      written.platform = { kind: candidate.kind ?? 'introduction', manifestSha256 };
      written.inheritedTestInputs = { count: 0, names: [] };
      for (const stage of written.stages) Object.assign(stage, evidence.stages[stage.name]);
      // The gate's order, each stage with an interval of its own inside the run's window.
      const start = Date.parse(written.started);
      written.stages = inOrder(
        written.stages,
        gateOrder,
        start + 5,
        Math.floor((Date.parse(written.finished) - start - 10) / written.stages.length)
      );
      for (const stage of written.stages) timeNetwork(evidence.snapshots, files, stage, change);
      written.stages.find(stage => stage.name === 'gate-identity').gateIdentity =
        syntheticGateIdentity();
      change.record?.(written, files);
      bindActivation(run, written, files, evidence.logs, change);
    },
  });
}

/**
 * Writes the binding of a synthetic run's t8-image-activation into `files`, as the gate writes it
 * (activationBinding), from the run's record and evidence after `change.record`; then
 * `change.activation(binding, record)` may change it.
 */
function bindActivation(run, record, files, logs, change) {
  const activation = record.stages.find(
    stage => stage.name === 't8-image-activation' && stage.binding === activationBindingFile
  );
  if (!activation) return;
  const logOf = name => record.stages.find(stage => stage.log === name);
  const has = name => Object.hasOwn(files, name) || Boolean(logOf(name));
  const get = name =>
    Buffer.from(
      Object.hasOwn(files, name)
        ? files[name]
        : (logs[logOf(name)?.name] ?? 'Synthetic completed command\n')
    );
  const binding = activationBinding({
    name: path.basename(run),
    record,
    get,
    has,
    catalogSha256: catalog.sha256,
  });
  change.activation?.(binding, record);
  files[activationBindingFile] = json(binding);
}

/**
 * Writes and seals a companion run (platform mode) of run `runId` on its platform for the
 * candidate, in `<security directory>/<tree>-platform-<uuid>`; returns its path. `change` as in
 * writeMainRun.
 */
export function writeCompanion(
  security,
  candidate,
  { runId = 'darwin-platform', now = Date.now(), change = {} } = {}
) {
  const { current, manifest, manifestSha256 } = candidate;
  const platform = manifest.runs[runId].platform;
  const run = path.join(security, `${current.tree}-platform-${randomUUID()}`);
  fs.mkdirSync(run, { recursive: true, mode: 0o700 });
  const evidence = testEvidence({
    manifest,
    manifestSha256,
    runId,
    platform,
    prefix: 'platform-tests-',
    now,
    change,
  });
  const started = new Date(now - 6000).toISOString(),
    finished = new Date(now - 1000).toISOString();
  const stageStarted = new Date(now - 5000).toISOString(),
    stageFinished = new Date(now - 2000).toISOString();
  const { files: candidateFileList } = current;
  const identity = identityOf(current, { sha256: manifestSha256, state: 'valid' });
  const record = {
    kind: LOCAL_RUN_KIND,
    kindVersion: LOCAL_RUN_KIND_VERSION,
    mode: 'platform',
    platformRun: runId,
    tree: current.tree,
    parents: [...current.parents],
    refs: current.refs,
    catalog: catalogOf(runId),
    candidate: identity.record,
    candidateIdentitySha256: identity.sha256,
    started,
    finished,
    host: { platform, arch: 'arm64', release: 'synthetic', node: versionOf[26], uid: 501 },
    tools,
    inheritedTestInputs: { count: 0, names: [] },
    platform: { kind: candidate.kind ?? 'introduction', manifestSha256 },
    status: 'pass',
    stages: [],
  };
  const commands = new Set([
    'npm-version',
    'platform-tests-current-runtime',
    'platform-tests-minimum-runtime',
    't8-image-identity',
  ]);
  // Every stage the gate's companion run reports: the catalog's darwin-platform array (v3 C23).
  // A companion of another run (darwin-full) reports the same stages; the catalog has no reviewed
  // array for it, so the finalizer judges it pending.
  const hosted = Object.values(manifest.runs).some(
    item => item.platform === 'container' && item.hostRuns.includes(runId)
  );
  const names = [
    ...catalogStages('darwin-platform'),
    ...(hosted ? ['t8-image-identity', 't8-image-authenticity', 't8-image-activation'] : []),
    ...(platform === 'linux' ? ['network-policy'] : []),
  ];
  for (const name of names) {
    const stage = { name, started: stageStarted, finished: stageFinished, status: 'pass' };
    if (commands.has(name))
      Object.assign(stage, {
        command: ['synthetic-fixture'],
        exit: 0,
        signal: null,
        log: `${name}.log`,
      });
    Object.assign(stage, evidence.stages[name]);
    record.stages.push(stage);
  }
  const files = {
    'source-manifest.json': json(candidateFileList),
    'tool-config.json': securityTools,
    ...evidence.files,
  };
  // The gate's companion order, each stage with an interval of its own inside the run's window.
  record.stages = inOrder(
    record.stages,
    companionOrder,
    Date.parse(started) + 5,
    Math.floor((Date.parse(finished) - Date.parse(started) - 10) / record.stages.length)
  );
  for (const stage of record.stages) timeNetwork(evidence.snapshots, files, stage, change);
  record.stages.find(stage => stage.name === 'gate-identity').gateIdentity =
    syntheticGateIdentity();
  change.record?.(record, files);
  bindActivation(run, record, files, evidence.logs, change);
  const write = (name, value) =>
    fs.writeFileSync(
      path.join(run, name),
      typeof value === 'string' || Buffer.isBuffer(value) ? value : json(value),
      { flag: 'wx', mode: 0o600 }
    );
  write('result.json', record);
  for (const [name, bytes] of Object.entries(files)) write(name, bytes);
  for (const stage of record.stages.filter(item => item.log))
    write(stage.log, evidence.logs[stage.name] ?? 'Synthetic completed command\n');
  sealRun(run);
  return run;
}

/**
 * The staged candidate of the Git repository at `root`, as the commit guard sees it, with its
 * platform judgment's inputs (platformInputs) and its manifest; `kind` is what the judgment
 * gives (introduction or manifest).
 */
export function repositoryCandidate(root, kind = 'introduction') {
  const current = { ...stagedCandidate(root), lintStages: lintStageNames };
  current.platform = platformInputs(root, current.tree, candidateParents(root));
  current.companions = [];
  const manifestBytes = current.platform.candidate;
  return {
    current,
    kind,
    manifest: manifestBytes ? JSON.parse(manifestBytes) : null,
    manifestBytes,
    manifestSha256: manifestBytes ? sha256(manifestBytes) : null,
  };
}

/**
 * A finalized gate run (on `platform`) with companion runs (`companions`: their options) for
 * the candidate, in the orbit-security folder `security`, as the 1.5 finalizer would make it
 * after an independent review. Returns the run's path and its approval.
 */
export function finalizePlatformRun(
  security,
  candidate,
  { platform = 'linux', now = Date.now(), companions = [{}] } = {}
) {
  const run = path.join(security, `${candidate.current.tree}-commit-${randomUUID()}`);
  writeMainRun(run, candidate, { platform, now });
  const made = companions.map(options => writeCompanion(security, candidate, { now, ...options }));
  const current = { ...candidate.current, companions: made };
  const inventory = inspectRun(run, current, now);
  if (!inventory.eligible)
    throw new Error(`Synthetic run not clean: ${inventory.blockers.join('; ')}`);
  const { platform: summary, ...binding } = reviewBinding(inventory);
  const review = path.join(run, 'review-input.json');
  fs.writeFileSync(
    review,
    JSON.stringify({
      ...binding,
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(),
      unresolved: [],
      documents: Object.fromEntries(
        candidate.current.files
          .filter(({ file }) => /\.(?:md|txt)$/i.test(file) && !file.startsWith('test/'))
          .map(({ file }) => [
            file,
            { status: 'checked unchanged', reason: 'Synthetic fixture only' },
          ])
      ),
      dispositions: [],
    }),
    { flag: 'wx', mode: 0o600 }
  );
  return { run, companions: made, approval: finalizeRun(run, review, current, now) };
}

// Stands in for F on the Mac: test/helpers/security-run.mjs.
export { asIfFinalizedByF } from './security-run.mjs';
