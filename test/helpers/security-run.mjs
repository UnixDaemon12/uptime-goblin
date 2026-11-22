// Synthetic commit-gate runs for the commit guard's tests: a sealed run in which every listed
// stage passed and every scanner report is clean, finalized by a synthetic review. This is test
// evidence for the guard's decision, never a scan result. Only the stage names vary, so a test
// can leave a stage out (the maintenance gate records no lint stages) and see what the guard
// makes of that.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { sha256 } from '../../scripts/security-evidence.mjs';
import { findingReports } from '../../scripts/security-findings.mjs';
import {
  requiredStages,
  lintStageNames,
  sealRun,
  inspectRun,
  finalizeRun,
  candidateParents,
} from '../../scripts/security-finalization.mjs';
import {
  LOCAL_RUN_KIND,
  LOCAL_RUN_KIND_VERSION,
  actionlintArguments,
  actionlintConfig,
  actionlintConfigFile,
  candidateIdentity,
  closureSha256,
} from '../../scripts/security-platform.mjs';

// The tool configuration a candidate must track as scripts/security-tools.json: a run's tool
// pins have to match it.
export const securityTools = fs.readFileSync(
  new URL('../../scripts/security-tools.json', import.meta.url)
);
const tools = JSON.parse(securityTools);

/** A synthetic Actionlint binary path, its sha256 and its golden-tool record on `platform`/`arch`. */
export const actionlintPath = '/synthetic/golden/actionlint';
export const actionlintSha256 = 'f'.repeat(64);
/** The synthetic binary's dependency closure: none (a reviewed record would have to establish it). */
export const actionlintClosure = [];
export const actionlintClosureSha256 = closureSha256(actionlintClosure);
export function goldenActionlint(platform, now, arch = 'arm64') {
  return {
    schemaVersion: 2,
    tool: 'actionlint',
    platform,
    arch,
    path: actionlintPath,
    version: tools.actionlint,
    sha256: actionlintSha256,
    provenance: {
      source: 'synthetic golden-tool fixture',
      archive: 'actionlint_synthetic.tar.gz',
      archiveSha256: 'e'.repeat(64),
      verification: 'synthetic: not a verified tool',
    },
    dependencyClosure: actionlintClosure,
    reviewer: 'Synthetic reviewer',
    reference: 'synthetic golden-tool review',
    reviewedAt: new Date(now - 60000).toISOString(),
  };
}

/**
 * Makes the passing Actionlint stages of `record`, a run to be sealed in the folder `run`, those of
 * a run that ran a pinned Actionlint (Daybreak GD-R2, for every candidate, maintenance included):
 * actionlint-version names the pinned synthetic binary and its sealed golden-tool record (for the
 * record's host), and workflow-analysis ran it with the gate-owned configuration and saw the pinned
 * sha256 immediately before and after it ran. Returns the evidence files that needs, by name.
 * Synthetic: no Actionlint ran, and the gate of this draft runs none (Codex decision 8: it has no
 * qualified golden-tool manifest). The finalizer checks such a run for consistency, and leaves the
 * qualified binding to F (actionlint-pin): the record is a local claim, not authority.
 */
export function pinActionlint(record, run, now) {
  const name = `golden-tool-actionlint-${record.host.platform}-${record.host.arch}.json`;
  const files = {};
  for (const stage of record.stages) {
    if (stage.name === 'actionlint-version' && stage.status === 'pass') {
      stage.tool = {
        path: actionlintPath,
        sha256: actionlintSha256,
        version: tools.actionlint,
        record: name,
        dependencyClosureSha256: actionlintClosureSha256,
      };
      files[name] = JSON.stringify(goldenActionlint(record.host.platform, now, record.host.arch));
    }
    if (stage.name === 'workflow-analysis' && stage.status === 'pass') {
      stage.command = [
        actionlintPath,
        ...actionlintArguments(path.join(run, actionlintConfigFile)),
      ];
      stage.binarySha256 = { before: actionlintSha256, after: actionlintSha256 };
      stage.dependencyClosureSha256 = {
        before: actionlintClosureSha256,
        after: actionlintClosureSha256,
      };
      files[actionlintConfigFile] = actionlintConfig;
    }
  }
  return files;
}
// Every stage the earlier gate records, the lint stages included, and test-host and
// runtime-identity before the test stages (GDR6-REQ-01): what a candidate whose history never held
// the platform manifest (maintenance, B35) is judged by.
export const allStages = [...requiredStages, ...lintStageNames];

// gate-draft-r7 (GDR6-REQ-01, under Codex's B35 decision of 20261017T140102522864Z): a maintenance
// run records test-host and runtime-identity before its test stages, and each test stage the Node
// binary it ran, which runtime-identity lists with its sealed identity record. The synthetic
// binaries, their records and the release keys are made up: no binary was hashed and no signature
// checked.
const releaseArchitectures = { arm64: 'arm64', x64: 'x64' };
const maintenanceSigner = 'C0FFEE'.padEnd(40, 'A');
const maintenanceKeyring = '6'.repeat(64);
/** The sha256 of the synthetic Node binary of `version` a maintenance run's test stage ran. */
export const maintenanceBinary = version => sha256(`synthetic maintenance node ${version}`);
/** The Node version of a maintenance run's test slot: the gate's own (its host Node), or Node 24. */
export const maintenanceSlotVersion = (record, name) =>
  name === 'full-tests-minimum-runtime' ? 'v24.21.0' : record.host.node;
/** A runtime identity record of the synthetic Node `version` binary: a verified Node release. */
export function maintenanceRuntimeRecord({ version, sha256: binarySha256, platform, arch, now }) {
  return {
    schemaVersion: 1,
    binarySha256,
    version,
    platform,
    arch,
    distribution: 'nodejs-release',
    release: {
      archive: `node-${version}-${platform}-${releaseArchitectures[arch] ?? arch}.tar.xz`,
      archiveSha256: '3'.repeat(64),
      shasumsSha256: '4'.repeat(64),
      signatureSha256: '5'.repeat(64),
      signer: maintenanceSigner,
      keyringSha256: maintenanceKeyring,
      outcome: 'verified',
    },
    recordedAt: new Date(now - 60000).toISOString(),
    reference: 'synthetic maintenance runtime identity fixture',
  };
}
/** The reviewed list of Node release keys the maintenance fixture records name. */
export const maintenanceReleaseKeys = now => ({
  schemaVersion: 1,
  keyringSha256: maintenanceKeyring,
  fingerprints: [maintenanceSigner],
  source: 'synthetic release keys fixture',
  sourceSha256: 'd'.repeat(64),
  reviewer: 'Synthetic reviewer',
  reference: 'synthetic release keys review',
  reviewedAt: new Date(now - 60000).toISOString(),
});

/**
 * Gives the maintenance (B35) run `record` its host and runtime evidence, as the gate records it:
 * a passing test-host names the record's platform and a user other than root; each test stage
 * that ran records the Node binary of its slot (maintenanceSlotVersion); a passing
 * runtime-identity lists each binary once with its record and names the sealed release keys; both
 * prerequisites end as the run starts, so before every test stage. Returns the evidence files to
 * seal with the run, by name (the identity records and the release keys).
 */
export function maintenanceRuntime(record, now) {
  const files = {};
  const at = record.started;
  const host = record.stages.find(stage => stage.name === 'test-host');
  if (host?.status === 'pass')
    Object.assign(host, {
      started: at,
      finished: at,
      host: {
        platform: record.host.platform,
        uid: 1000,
        setfacl: record.host.platform === 'linux' ? true : null,
      },
    });
  const runtimes = [];
  for (const stage of record.stages.filter(
    item => item.name.startsWith('full-tests-') && item.command
  )) {
    const version = maintenanceSlotVersion(record, stage.name);
    const binary = maintenanceBinary(version);
    stage.runtime = { path: `/synthetic/maintenance/node-${version}`, version, sha256: binary };
    if (!runtimes.some(item => item.sha256 === binary))
      runtimes.push({ ...stage.runtime, record: `runtime-identity-${binary}.json` });
  }
  const identity = record.stages.find(stage => stage.name === 'runtime-identity');
  if (identity?.status === 'pass') {
    Object.assign(identity, {
      started: at,
      finished: at,
      runtimes,
      releaseKeys: 'runtime-release-keys.json',
    });
    for (const item of runtimes)
      files[item.record] = JSON.stringify(
        maintenanceRuntimeRecord({
          version: item.version,
          sha256: item.sha256,
          platform: record.host.platform,
          arch: record.host.arch,
          now,
        })
      );
    files['runtime-release-keys.json'] = JSON.stringify(maintenanceReleaseKeys(now));
  }
  return files;
}
/** The sha256 of a second, configured Node 24 executable of `version`: another file than the gate's. */
export const configuredNode24Binary = version => sha256(`synthetic configured node24 ${version}`);

/**
 * Gives the maintenance (B35) run `record` of a gate on Node 24 its configured Node 24 slot on a
 * second, distinct Node 24 executable (ORBIT_SECURITY_NODE24 naming another file than the gate's
 * own Node 24), as the gate plans it when the two paths differ: full-tests-minimum-runtime runs
 * that binary (`version`, the gate's own version unless given, with its own sha256), and a passing
 * runtime-identity lists it with its sealed record beside the gate's own. The run must list
 * full-tests-minimum-runtime among its stages. Returns the evidence files to seal with the run.
 */
export function distinctNode24Slot(record, now, { version = record.host.node } = {}) {
  const stage = record.stages.find(item => item.name === 'full-tests-minimum-runtime');
  const binary = configuredNode24Binary(version);
  stage.runtime = { path: `/synthetic/configured/node24-${version}`, version, sha256: binary };
  const file = `runtime-identity-${binary}.json`;
  record.stages
    .find(item => item.name === 'runtime-identity')
    .runtimes.push({ ...stage.runtime, record: file });
  return {
    [file]: JSON.stringify(
      maintenanceRuntimeRecord({
        version,
        sha256: binary,
        platform: record.host.platform,
        arch: record.host.arch,
        now,
      })
    ),
  };
}

/**
 * Writes, beside the sealed maintenance (B35) run `run` of `current`, the finalization an earlier
 * finalizer and F would have recorded for it: a passing schema 2 approval with its one F
 * obligation (actionlint-pin) passed, and the retained review it names, made without this tree's
 * checks of the run. It is the historical evidence that an approval recorded under earlier rules
 * leaves, for a run the current rules may refuse (GDR7-AUTH-01): the readers that would give it
 * authority over a new commit must give it none. Synthetic: no review, finalizer or F ran.
 * gate-draft-r9 (GDR8-AUTH-SCAN-01): `options.dispose(findings)` gives the review's dispositions,
 * each from the finding (or the id) it names, completed with a synthetic status, reviewer, reason,
 * reference and evidence, whose bytes are retained beside the review as the finalizer retains
 * them; `options.findings` is the count the approval claims (by default the number of
 * dispositions). By default the review disposes of nothing and the approval counts no finding, as
 * before. The findings passed to `dispose` are the inventory's: those the run's reports give.
 * Returns the approval.
 */
export function recordedFinalization(run, current, now = Date.now(), options = {}) {
  const inventory = inspectRun(
    run,
    { ...current, platform: current.platform ?? maintenanceInputs(current) },
    now
  );
  const finalized = path.join(run, 'finalization');
  fs.mkdirSync(finalized, { mode: 0o700 });
  // `item.with` replaces members of the complete disposition (an unsupported status, say).
  const dispositions = (options.dispose?.(inventory.findings) ?? []).map(item => ({
    ...syntheticDisposition(item.id, finalized),
    ...(item.with ?? {}),
  }));
  const review = Buffer.from(
    JSON.stringify({
      ...reviewBinding(inventory),
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(),
      unresolved: [],
      documents: {},
      dispositions,
    })
  );
  fs.writeFileSync(path.join(finalized, 'review.json'), review, { flag: 'wx', mode: 0o600 });
  const approval = {
    schemaVersion: 2,
    status: 'pass',
    mode: 'commit',
    tree: current.tree,
    parents: [...current.parents],
    candidateIdentitySha256: inventory.candidateIdentitySha256,
    refs: current.refs,
    runSha256: inventory.runSha256,
    reviewSha256: sha256(review),
    finalizedAt: new Date(now).toISOString(),
    findings: options.findings ?? dispositions.length,
    obligations: { 'actionlint-pin': 'pass' },
  };
  fs.writeFileSync(
    path.join(finalized, 'approval.json'),
    `${JSON.stringify(approval, null, 2)}\n`,
    { flag: 'wx', mode: 0o600 }
  );
  return approval;
}

/** The synthetic evidence a disposition names: one file, the same for every disposition. */
export const dispositionEvidence = Buffer.from(
  'Synthetic analysis: this fixture finding is in a synthetic file and holds no live credential.\n'
);
/**
 * A complete synthetic disposition of the finding `id` (false-positive, with a reviewer, reason,
 * reference and the digest of dispositionEvidence), its evidence written into `directory` as
 * `<sha256>.evidence` (the finalization's retained copy) unless it is there already.
 */
export function syntheticDisposition(id, directory) {
  const evidenceSha256 = sha256(dispositionEvidence);
  const file = path.join(directory, `${evidenceSha256}.evidence`);
  if (!fs.existsSync(file))
    fs.writeFileSync(file, dispositionEvidence, { flag: 'wx', mode: 0o600 });
  return {
    id,
    status: 'false-positive',
    reason: 'Synthetic isolated fixture',
    reviewer: 'Independent synthetic reviewer',
    reference: 'Synthetic evidence',
    evidenceFile: file,
    evidenceSha256,
  };
}

/**
 * A Gitleaks history finding as a secrets-history.json row (synthetic: no secret, no scan): the
 * report row of finding `index`, in the candidate file example.mjs at commit `commit`.
 */
export const historyFinding = (index = 0, commit = 'a'.repeat(40)) => ({
  RuleID: 'synthetic-key',
  File: 'example.mjs',
  StartLine: index + 1,
  EndLine: index + 1,
  Fingerprint: `synthetic:${index}`,
  Commit: commit,
  Secret: 'REDACTED',
});

// The stages the gate records without a command (security-finalization.mjs checks the others
// for one).
const requirements = new Set([
  'candidate-policy',
  'gate-identity',
  'gate-import-closure',
  'gate-implementation',
  'pristine-copy',
  'image-approval',
  'prepared-inputs',
  'sast-rules',
  'sast-rules-checksum',
  'gitleaks-version',
  'trivy-version',
  'actionlint-version',
  'minimum-runtime-available',
  'independent-review',
  'candidate-unchanged',
  // The platform contract's requirements (scripts/security-platform.mjs), for platform runs
  // (test/helpers/platform-run.mjs).
  'platform-manifest',
  'test-host',
  'runtime-identity',
  'platform-coverage-current-runtime',
  'platform-coverage-minimum-runtime',
  't8-image-authenticity',
  't8-image-activation',
  'network-policy',
]);
const image = `sha256:${'a'.repeat(64)}`;
const tap = '# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';

// The candidate tree's files as sourceManifest() lists them, read from Git's objects rather than
// a working tree, so a run can be made for a tree that is not checked out (the result of a merge
// that has not run yet).
export function treeFiles(root, tree) {
  const listing = execFileSync('git', ['-C', root, 'ls-tree', '-rz', '--full-tree', tree], {
    encoding: 'utf8',
  });
  return listing
    .split('\0')
    .filter(Boolean)
    .map(entry => {
      const [, mode, blob, file] = /^(100644|100755) blob ([0-9a-f]+)\t(.+)$/s.exec(entry);
      const bytes = execFileSync('git', ['-C', root, 'cat-file', 'blob', blob], {
        maxBuffer: 64 * 1024 ** 2,
      });
      return { file, mode, blob, sha256: sha256(bytes) };
    });
}

// The candidate (tree, HEAD, complete ordered parent vector, refs and files) a worktree's commit
// guard sees, for `tree` (the staged tree by default).
export function candidate(root, tree) {
  const git = (...args) =>
    execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: 'pipe' }).trimEnd();
  const staged = tree ?? git('write-tree');
  const parents = candidateParents(root);
  return {
    tree: staged,
    parent: git('rev-parse', 'HEAD'),
    parents: parents.heads,
    parentsComplete: parents.complete,
    parentsReason: parents.reason,
    refs: git('for-each-ref', '--format=%(refname) %(objectname)'),
    files: treeFiles(root, staged),
  };
}

/**
 * The inputs of the platform judgment for a candidate whose history never held the manifest
 * (maintenance, B35), without a repository: each parent a root commit without a manifest.
 */
export function maintenanceInputs(current) {
  return {
    candidate: null,
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
 * The candidate identity record and digest a run of `current` names. `platformManifest` is the
 * state of the reserved manifest path: never-held (maintenance) unless given.
 */
export function identityOf(current, platformManifest = { state: 'never-held' }) {
  return candidateIdentity({
    tree: current.tree,
    parents: current.parents,
    files: current.files,
    platformManifest,
  });
}

// Writes and seals, in the new private directory `run`, a commit run for `current` with these
// passing stages. The candidate needs at least one JavaScript module and one Dockerfile, as the
// clean reports below cover them (a scan that saw no file is incomplete). `options` (for the
// platform evidence, test/helpers/platform-run.mjs): `record(record)` changes the record before it
// is written, `logs` gives a stage's log by stage name, `files` adds evidence files, `pending`
// lists stages recorded as pending, `catalog` is the record's catalog binding and
// `platformManifest` the state its candidate identity names. gate-draft-r10 (GDR9-AUTH-SCAN-02): a
// scanner's fixed report is written by default only when its stage is recorded and ran (is not
// pending), as the gate creates a report only when it starts the scanner; withholding a scanner,
// or leaving its stage out, leaves its report out. A report `options.files` names is written
// whatever the stages say, so a test can seal a contradiction on purpose. gate-draft-r10 round 2
// (GDR9-HOST-SCHEMA-01): the run's own host is the form its producer writes: a run of a candidate
// with the platform contract (a `platformManifest` other than never-held), which only the 1.5
// gate writes, gets that gate's five members (synthetic values, uid 4242); a maintenance run gets
// the maintenance gate's four members { platform, arch, release, node } (gate-draft-r11,
// GDR10-HOST-PRODUCER-01: the form the maintenance producer, blob 40bc87be, writes; gate-draft-r10
// wrote a three-member form no producer writes, which is now refused).
export function writeRun(run, current, stages, now = Date.now(), options = {}) {
  fs.mkdirSync(run, { recursive: true, mode: 0o700 });
  // A file `options.files` names replaces the default of the same name (a report with findings);
  // a default file `options.omit` names is left out (a scanner report that is missing).
  const omitted = new Set(options.omit ?? []);
  const write = (name, value) =>
    omitted.has(name) ||
    fs.writeFileSync(
      path.join(run, name),
      options.files && Object.hasOwn(options.files, name)
        ? options.files[name]
        : typeof value === 'string' || Buffer.isBuffer(value)
          ? value
          : JSON.stringify(value),
      { flag: 'wx', mode: 0o600 }
    );
  const started = new Date(now - 2000).toISOString();
  const finished = new Date(now - 1000).toISOString();
  const { files } = current;
  const identity = identityOf(current, options.platformManifest);
  const pending = new Set(options.pending ?? []);
  const record = {
    // The local run record's own family (GDR4-02): a diagnostic record, not a C12 phase record.
    kind: LOCAL_RUN_KIND,
    kindVersion: LOCAL_RUN_KIND_VERSION,
    mode: 'commit',
    status: pending.size ? 'pending' : 'pass',
    tree: current.tree,
    parents: [...current.parents],
    refs: current.refs,
    ...(options.catalog ? { catalog: options.catalog } : {}),
    candidate: identity.record,
    candidateIdentitySha256: identity.sha256,
    started,
    finished,
    tools,
    host:
      options.platformManifest && options.platformManifest.state !== 'never-held'
        ? { platform: 'linux', arch: 'arm64', release: 'synthetic', node: 'v24.21.0', uid: 4242 }
        : { platform: 'linux', arch: 'arm64', release: 'synthetic', node: 'v24.21.0' },
    stages: stages.map(name => {
      if (pending.has(name))
        return { name, started, finished, status: 'pending', reason: 'synthetic pending stage' };
      const stage = { name, started, finished, status: 'pass' };
      if (requirements.has(name)) return stage;
      Object.assign(stage, { command: ['synthetic-fixture'], exit: 0, signal: null });
      stage.log = `${name}.log`;
      if (name.startsWith('full-tests-'))
        stage.tests = { tests: 1, pass: 1, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
      if (name === 'source-analysis')
        stage.command.push(tools.semgrepImage, '--no-git-ignore', '--project-root', '/scan');
      if (name === 'container-vulnerabilities') stage.command.push('synthetic:tag');
      return stage;
    }),
  };
  const pinned = pinActionlint(record, run, now);
  // A maintenance run (no platformManifest given: never-held) carries its host and runtime
  // evidence (GDR6-REQ-01); a run of a candidate with the manifest gets its own from
  // test/helpers/platform-run.mjs.
  const runtimeFiles =
    options.platformManifest === undefined ? maintenanceRuntime(record, now) : {};
  options.record?.(record);
  const scripts = files.filter(({ file }) => /\.(?:mjs|cjs|js)$/.test(file)).map(f => f.file);
  const dockerfiles = files
    .filter(({ file }) => /(?:^|\/)[^/]*dockerfile[^/]*$/i.test(file))
    .map(f => f.file);
  const trivy = { SchemaVersion: 2, Trivy: { Version: tools.trivy }, ArtifactID: image };
  write('result.json', record);
  write('source-manifest.json', files);
  write('tool-config.json', securityTools);
  write('semgrepignore', '');
  const ran = new Set(
    record.stages
      .filter(stage => findingReports[stage.name] && stage.status !== 'pending')
      .map(stage => findingReports[stage.name])
  );
  const report = (name, value) => ran.has(name) && write(name, value);
  report('secrets-source.json', []);
  report('secrets-history.json', []);
  report('secrets-metadata.json', []);
  report('source-analysis.json', {
    version: '1.176.0',
    results: [],
    errors: [],
    skipped_rules: [],
    paths: { scanned: scripts },
  });
  report('container-configuration.json', {
    ...trivy,
    ArtifactName: '.',
    Results: dockerfiles.map(Target => ({
      Target,
      Class: 'config',
      Type: 'dockerfile',
      MisconfSummary: { Successes: 1, Failures: 0 },
    })),
  });
  report('container-security.json', {
    ...trivy,
    ArtifactName: 'synthetic:tag',
    Metadata: { ImageID: image },
    Results: [
      { Target: 'synthetic OS', Class: 'os-pkgs', Vulnerabilities: [] },
      { Target: 'Node.js', Class: 'lang-pkgs', Vulnerabilities: [] },
      { Target: 'synthetic:tag', Class: 'config', MisconfSummary: { Successes: 1, Failures: 0 } },
    ],
  });
  // The golden-tool record and configuration of the pinned Actionlint, unless the record (changed
  // by `options.record`) no longer names them.
  for (const [name, bytes] of Object.entries(pinned))
    if (
      name === actionlintConfigFile ||
      record.stages.some(
        stage => stage.name === 'actionlint-version' && stage.tool?.record === name
      )
    )
      write(name, bytes);
  for (const [name, bytes] of Object.entries(runtimeFiles)) write(name, bytes);
  for (const [name, bytes] of Object.entries(options.files ?? {}))
    if (!fs.existsSync(path.join(run, name))) write(name, bytes);
  for (const stage of record.stages.filter(item => item.log)) {
    if (options.logs && Object.hasOwn(options.logs, stage.name))
      write(stage.log, options.logs[stage.name]);
    else if (stage.name === 'container-identity') write(stage.log, JSON.stringify([{ Id: image }]));
    else if (stage.name === 'scanner-database')
      write(
        stage.log,
        JSON.stringify({
          Version: tools.trivy,
          VulnerabilityDB: {
            UpdatedAt: new Date(now - 60000).toISOString(),
            DownloadedAt: new Date(now - 30000).toISOString(),
            NextUpdate: new Date(now + 3600000).toISOString(),
          },
        })
      );
    else if (stage.name.startsWith('full-tests-')) write(stage.log, tap);
    else if (stage.name.startsWith('secrets-')) write(stage.log, 'INF scanned ~100 bytes in 1ms\n');
    else write(stage.log, 'Synthetic completed command\n');
  }
  sealRun(run);
}

/**
 * Stands in for F on the Mac (GATE-CONTRACT v3 C13, C14), which does not exist yet: rewrites the
 * finalization of `run` as F would write it once every F obligation passed. This module's own
 * finalization is pending for every candidate: the catalog's F obligations for a candidate with a
 * platform contract, and for maintenance (B35) the qualified binding of its pinned Actionlint
 * (actionlint-pin; Codex decision 8). Only this test input lets the commit guard's checks of a
 * passing finalization be tested. Synthetic: no F ran, and no qualified manifest bound anything.
 */
export function asIfFinalizedByF(run) {
  const file = path.join(run, 'finalization', 'approval.json');
  const approval = JSON.parse(fs.readFileSync(file, 'utf8'));
  approval.status = 'pass';
  approval.obligations = Object.fromEntries(
    Object.keys(approval.obligations ?? {}).map(id => [id, 'pass'])
  );
  delete approval.pending;
  fs.writeFileSync(file, `${JSON.stringify(approval, null, 2)}\n`, { mode: 0o600 });
  return approval;
}

/** The binding fields of an inventory, as a review names them (never its verdict or findings). */
export function reviewBinding(inventory) {
  const { findings, eligible, blockers, verdict, pending, obligations, ...binding } = inventory;
  return binding;
}

// A passing, finalized commit run for `current` with these stages, in the new private directory
// `run`, for a candidate whose history never held the platform manifest (maintenance, B35): it is
// finalized with the judgment's inputs of such a candidate and only the lint stages it has (the
// maintenance gate records none), so the commit guard alone decides whether the candidate needs
// more. `options.platform` gives other judgment inputs. The finalization this module writes is
// pending (its F obligation actionlint-pin; Codex decision 8), and that is what this returns;
// unless `options.byF` is false, the folder then holds the finalization as the stand-in for F
// writes it (asIfFinalizedByF), so the commit guard's other checks of a passing one can be tested.
// With `options.dispose`, a run whose reports give findings (with its scanners' finding exits) is
// reviewed with one complete disposition of each (gate-draft-r9, GDR8-AUTH-SCAN-01).
export function finalizedRun(run, current, stages, now = Date.now(), options = {}) {
  writeRun(run, current, stages, now, options);
  const lintStages = lintStageNames.filter(name => stages.includes(name));
  const inputs = {
    ...current,
    lintStages,
    platform: options.platform ?? maintenanceInputs(current),
  };
  const inventory = inspectRun(run, inputs, now);
  // gate-draft-r9 (GDR8-AUTH-SCAN-01): with `options.dispose`, a run whose reports give findings
  // is reviewed with one complete disposition of each, its evidence a private file beside the run.
  if (!inventory.eligible || (inventory.findings.length && !options.dispose))
    throw new Error(`Synthetic run not clean: ${inventory.blockers.join('; ')}`);
  let dispositions = [];
  if (options.dispose) {
    const evidence = fs.mkdtempSync(
      path.join(path.dirname(run), `evidence-${path.basename(run)}-`)
    );
    dispositions = inventory.findings.map(item => syntheticDisposition(item.id, evidence));
  }
  const documents = Object.fromEntries(
    current.files
      .filter(({ file }) => /\.(?:md|txt)$/i.test(file) && !file.startsWith('test/'))
      .map(({ file }) => [file, { status: 'checked unchanged', reason: 'Synthetic fixture only' }])
  );
  const review = path.join(run, 'review-input.json');
  fs.writeFileSync(
    review,
    JSON.stringify({
      ...reviewBinding(inventory),
      reviewer: 'Independent synthetic reviewer',
      reference: 'Synthetic code review',
      reviewedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 3600000).toISOString(),
      unresolved: [],
      documents,
      dispositions,
    }),
    { flag: 'wx', mode: 0o600 }
  );
  const approval = finalizeRun(run, review, inputs, now);
  if (options.byF !== false) asIfFinalizedByF(run);
  return approval;
}
