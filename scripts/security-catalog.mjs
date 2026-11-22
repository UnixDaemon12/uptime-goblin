// The versioned catalog of required stages and finalization obligations (scripts/security-catalog.json).
//
// The arrays are GATE-CONTRACT v5 round 2's C23 arrays, copied exactly (sha256 d0398079…, which
// Daybreak accepted as the design baseline for gate-draft-r4, with v5 change 19 confirmed by the
// coordinator decision the catalog names). A design baseline approves no implementation: these
// arrays are required proof obligations, not a claim that every stage exists. v5 moves
// t8-image-identity and t8-image-authenticity into phase N, before every candidate-controlled
// build, and adds t8-image-activation to phase O (v5 changes 2 and 4; N has 28 entries, O 25).
// The per-entry contracts (evidence paths and types, parser, tool identity, allowed statuses and
// bounds) are pending, and so are the darwin-full array and the exact T8, pre-build authority,
// result and activation record forms (v5 C17 item 12). A rule that rests on a pending part gives
// `pending`, never `pass`.
//
// The catalog names and binds the record-pack entry profile (`recordPack`: its name, version and
// sha256), which every producer and consumer of a pack must use exactly (v5 C21, C24 change 11;
// Codex decision 3). That needs a member the earlier form did not have, so this draft numbers the
// form version 2 and refuses version 1, which named no profile: two incompatible canonical forms
// must never share one version number (the rule v5 C1 states for the gate identity). That format
// change is this draft's proposal, not a v5 requirement: v5 C1 (change 6) says the catalog's format
// does not change, and Codex decides whether the profile is bound here or elsewhere. That the
// profile named here is the installed validator's own is checked in security-platform.mjs, which
// holds the validator's profile, so this module needs no import of it.
//
// The catalog's bytes are canonical JSON (keys sorted at every level, no white space), so one
// sha256 names one catalog. The gate records that sha256 in every run, and the finalizer and the
// commit guard read the catalog only from beside this module (the installed guard carries a copy),
// never from a caller or a run. Like the modules beside it, this one uses only Node's own modules.
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const show = value => JSON.stringify(value)?.slice(0, 200);
const ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * The contract the catalog's arrays come from, and the coordinator decision that confirmed its
 * change 19 after it was frozen (platform-manifest ends before every candidate-controlled build
 * starts). A catalog that names another contract (v3's or v4's arrays, say) is refused: a partial
 * migration is not v5's catalog (v5 C1, C23; v5 change 6).
 */
export const CATALOG_CONTRACT = Object.freeze({
  document: 'GATE-CONTRACT-v5.md',
  sha256: 'd0398079284bd0a707eeb086c5b3461dbbb7b40200a1401dc810a5d64cfaa9d8',
});
export const CHANGE19_DECISION = Object.freeze({
  document: 'GATE-CONTRACT-v5-change19-decision.txt',
  sha256: 'aa2d586322aab80bcc4bbf23669bbaccd2c9ecc81bb235e79d099dc6d062d200',
});
/** The catalog format this module reads: 2, which binds the record-pack profile (a proposal). */
export const CATALOG_VERSION = 2;

/**
 * GATE-CONTRACT v5's seven C23 arrays, exactly as its text gives them (membership, not order of
 * execution). parseCatalog requires the catalog's arrays to be exactly these, in this order, so a
 * catalog that drops, adds or reorders an entry is not read as v5's, even one that keeps every
 * stage the order rules name (defence in depth: only the installed catalog is read, and its sha256
 * is bound into every run, the gate identity and the activation binding).
 */
export const CONTRACT_ARRAYS = Object.freeze({
  'linux-full N': Object.freeze([
    'snapshot-clone',
    'snapshot-index',
    'snapshot-files',
    'gate-identity',
    'gate-import-closure',
    'gate-implementation',
    'candidate-policy',
    'platform-manifest',
    'pristine-copy',
    'gitleaks-version',
    'trivy-version',
    'actionlint-version',
    'docker-version',
    'npm-version',
    'runtime-identity',
    'dependencies-install',
    'dependencies-all',
    'dependencies-production',
    'registry-signatures',
    'sast-rules',
    'sast-image',
    'image-approval',
    't8-image-identity',
    't8-image-authenticity',
    'container-build',
    'container-identity',
    'systemd-test-image',
    'candidate-unchanged',
  ]),
  'linux-full O': Object.freeze([
    'sql-lint',
    'import-lint',
    'format',
    'syntax-manifest',
    'documentation',
    'workflow-analysis',
    'secrets-source',
    'secrets-history',
    'secrets-metadata',
    'source-analysis',
    'container-configuration',
    'container-vulnerabilities',
    'container-sbom',
    'scanner-database',
    'test-host',
    'runtime-identity',
    'network-policy',
    'full-tests-current-runtime',
    'platform-coverage-current-runtime',
    'minimum-runtime-available',
    'full-tests-minimum-runtime',
    'platform-coverage-minimum-runtime',
    't8-image-activation',
    'independent-review',
    'candidate-unchanged',
  ]),
  'darwin-platform': Object.freeze([
    'gate-identity',
    'gate-import-closure',
    'candidate-policy',
    'platform-manifest',
    'prepared-inputs',
    'test-host',
    'npm-version',
    'runtime-identity',
    'platform-tests-current-runtime',
    'platform-coverage-current-runtime',
    'minimum-runtime-available',
    'platform-tests-minimum-runtime',
    'platform-coverage-minimum-runtime',
    'candidate-unchanged',
  ]),
  'finalization commit': Object.freeze([
    'archive-validation',
    'phase-evidence',
    'candidate-identity',
    'required-catalogs',
    'controller-completion',
    'companion-evidence',
    'runtime-approvals',
    'image-approvals',
    'review-approval',
    'freshness',
    'cleanup-evidence',
    'evidence-seal',
  ]),
  'finalization release': Object.freeze([
    'archive-validation',
    'phase-evidence',
    'candidate-identity',
    'required-catalogs',
    'controller-completion',
    'companion-evidence',
    'runtime-approvals',
    'image-approvals',
    'review-approval',
    'freshness',
    'cleanup-evidence',
    'evidence-seal',
    'sonarqube',
    'snyk-dependencies',
    'snyk-code',
    'snyk-container',
    'clair',
    'netxeo-release-review',
    'performance-validation',
    'release-platform-coverage',
    'final-artifacts',
    'signatures-provenance',
  ]),
  'scanners commit': Object.freeze([
    'workflow-analysis',
    'secrets-source',
    'secrets-history',
    'secrets-metadata',
    'source-analysis',
    'container-configuration',
    'container-vulnerabilities',
    'container-sbom',
    'scanner-database',
  ]),
  'scanners release': Object.freeze([
    'workflow-analysis',
    'secrets-source',
    'secrets-history',
    'secrets-metadata',
    'source-analysis',
    'container-configuration',
    'container-vulnerabilities',
    'container-sbom',
    'scanner-database',
    'sonarqube',
    'snyk-dependencies',
    'snyk-code',
    'snyk-container',
    'clair',
  ]),
});

// Where v5 places the stages its order rules name (C3, C23), and the T8 stages it moved: a
// catalog that places one elsewhere, or lacks one, is refused, so a catalog of v4's arrays (the T8
// stages in O, no t8-image-activation) or one that drops a stage an order rule needs cannot be
// read as v5's. `not` lists what a phase must not hold.
const PLACEMENT = Object.freeze({
  N: [
    'candidate-policy',
    'platform-manifest',
    'pristine-copy',
    'dependencies-install',
    'image-approval',
    't8-image-identity',
    't8-image-authenticity',
    'container-build',
    'container-identity',
    'systemd-test-image',
    'candidate-unchanged',
  ],
  O: [
    'sql-lint',
    'import-lint',
    'format',
    'syntax-manifest',
    'documentation',
    'test-host',
    'runtime-identity',
    'full-tests-current-runtime',
    'platform-coverage-current-runtime',
    'full-tests-minimum-runtime',
    'platform-coverage-minimum-runtime',
    't8-image-activation',
    'candidate-unchanged',
  ],
  notN: ['t8-image-activation'],
  notO: ['t8-image-identity', 't8-image-authenticity', 'container-build', 'systemd-test-image'],
});
const T8_STAGES = ['t8-image-identity', 't8-image-authenticity', 't8-image-activation'];

/** Canonical JSON: keys sorted at every level, no white space. Throws on anything JSON cannot hold. */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string')
    return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical JSON holds no non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value))
    return `{${Object.keys(value)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  throw new Error(`canonical JSON cannot hold ${typeof value}`);
}

/** Whether a JSON text names a member twice in one object (JSON.parse keeps the last). */
function duplicateMember(source) {
  // A small JSON scanner: strings are skipped as wholes, so a key inside a string is not one.
  const stack = [];
  let index = 0;
  const readString = () => {
    let end = index + 1;
    while (source[end] !== '"') end += source[end] === '\\' ? 2 : 1;
    const text = JSON.parse(source.slice(index, end + 1));
    index = end + 1;
    return text;
  };
  while (index < source.length) {
    const char = source[index];
    if (char === '"') {
      const text = readString();
      const top = stack.at(-1);
      let next = index;
      while (/\s/.test(source[next] ?? '')) next += 1;
      if (top?.kind === 'object' && source[next] === ':') {
        if (top.keys.has(text)) return text;
        top.keys.add(text);
      }
      continue;
    }
    if (char === '{') stack.push({ kind: 'object', keys: new Set() });
    else if (char === '[') stack.push({ kind: 'array' });
    else if (char === '}' || char === ']') stack.pop();
    index += 1;
  }
  return null;
}

/** Problems with one list of ids: nonempty, ids only (no wildcard), none twice. */
function listProblems(where, list) {
  if (!Array.isArray(list) || !list.length) return [`${where} is not a nonempty list`];
  const problems = [];
  const seen = new Set();
  for (const item of list) {
    if (typeof item !== 'string' || !ID.test(item))
      problems.push(`${where} holds ${show(item)}, which is not a stage id (no wildcard)`);
    else if (seen.has(item)) problems.push(`${where} names ${item} twice`);
    seen.add(item);
  }
  return problems;
}

function exactKeys(where, value, keys) {
  if (!isObject(value)) return [`${where} is not an object`];
  const problems = [];
  for (const key of Object.keys(value))
    if (!keys.includes(key)) problems.push(`${where} has the unknown member ${show(key)}`);
  for (const key of keys) if (!own(value, key)) problems.push(`${where} lacks ${key}`);
  return problems;
}

const TOP = [
  'contract',
  'finalization',
  'pending',
  'profiles',
  'recordPack',
  'scanners',
  'version',
];
export const MODES = Object.freeze(['commit', 'release']);

/** Problems with the phase placement of the stages v5's order rules name (PLACEMENT). */
function placementProblems(catalog) {
  const { N, O } = catalog.profiles['linux-full'];
  const darwin = catalog.profiles['darwin-platform'].platform;
  const problems = [];
  for (const id of PLACEMENT.N)
    if (!N.includes(id)) problems.push(`linux-full N lacks ${id}, which v5 places there (C3, C23)`);
  for (const id of PLACEMENT.O)
    if (!O.includes(id)) problems.push(`linux-full O lacks ${id}, which v5 places there (C3, C23)`);
  for (const id of PLACEMENT.notN)
    if (N.includes(id)) problems.push(`linux-full N holds ${id}, which v5 places in O only (C23)`);
  for (const id of PLACEMENT.notO)
    if (O.includes(id))
      problems.push(
        `linux-full O holds ${id}: v4's placement, which v5 moves to N before every candidate-controlled build (C3, C23; GCV4-01)`
      );
  for (const id of T8_STAGES)
    if (darwin.includes(id))
      problems.push(`darwin-platform holds ${id}, which its reviewed array has no place for (C23)`);
  return problems;
}

/**
 * Parses and checks catalog bytes. Throws unless they are exactly canonical JSON of a version 2
 * catalog: the contract the arrays come from (v5, with the change-19 decision), the two run
 * profiles with their phase arrays in v5's placement, the finalization and scanner arrays for
 * commit and release (release holding every commit item), each of the seven arrays exactly v5's
 * C23 array (CONTRACT_ARRAYS), a list of what is pending, and the record-pack profile it binds.
 * The version is judged first: version 1 is refused, with no fallback. Returns { catalog, sha256 }.
 */
export function parseCatalog(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length > 256 * 1024) throw new Error('the catalog is larger than 256 KiB');
  const source = buffer.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(buffer)) throw new Error('the catalog is not UTF-8');
  let catalog;
  try {
    catalog = JSON.parse(source);
  } catch {
    throw new Error('the catalog is not JSON');
  }
  const twice = duplicateMember(source);
  if (twice !== null) throw new Error(`the catalog names the member ${show(twice)} twice`);
  if (canonicalJson(catalog) !== source)
    throw new Error('the catalog is not canonical JSON (keys sorted, no white space)');
  // The version first and alone: version 1 is the form without the record-pack binding, and gives
  // no authority whatever members it holds; nothing is inferred from the members present.
  if (!isObject(catalog) || !own(catalog, 'version'))
    throw new Error('the catalog names no version: none is assumed');
  if (catalog.version === 1)
    throw new Error(
      'the catalog is version 1, the form that binds no record-pack profile: only version 2 is read, with no fallback (v5 C21, C24)'
    );
  if (catalog.version !== CATALOG_VERSION) throw new Error('the catalog has another version');
  const problems = exactKeys('the catalog', catalog, TOP);
  if (problems.length) throw new Error(problems.join('; '));
  problems.push(
    ...exactKeys('the catalog contract', catalog.contract, [
      'decision',
      'document',
      'sha256',
      'status',
    ])
  );
  if (!problems.length) {
    problems.push(
      ...exactKeys('the catalog contract decision', catalog.contract.decision, [
        'document',
        'sha256',
      ])
    );
    if (
      catalog.contract.document !== CATALOG_CONTRACT.document ||
      catalog.contract.sha256 !== CATALOG_CONTRACT.sha256
    )
      problems.push(
        `the catalog names the contract ${show(catalog.contract.document)} (sha256 ${show(catalog.contract.sha256)}), not v5 (${CATALOG_CONTRACT.sha256}): the arrays of another contract are a partial migration (v5 C1, C23)`
      );
    if (
      isObject(catalog.contract.decision) &&
      (catalog.contract.decision.document !== CHANGE19_DECISION.document ||
        catalog.contract.decision.sha256 !== CHANGE19_DECISION.sha256)
    )
      problems.push(
        `the catalog names another decision than the coordinator's confirmation of v5 change 19 (${CHANGE19_DECISION.sha256})`
      );
    if (typeof catalog.contract.status !== 'string' || !catalog.contract.status.trim())
      problems.push('the catalog contract has no status');
  }
  problems.push(
    ...exactKeys('the record-pack binding', catalog.recordPack, ['name', 'sha256', 'version'])
  );
  if (
    isObject(catalog.recordPack) &&
    (catalog.recordPack.name !== 'record-pack' ||
      catalog.recordPack.version !== 1 ||
      typeof catalog.recordPack.sha256 !== 'string' ||
      !HEX64.test(catalog.recordPack.sha256))
  )
    problems.push(
      `the record-pack binding ${show(catalog.recordPack)} is not record-pack version 1 with a sha256 of 64 lowercase hex digits`
    );
  problems.push(
    ...exactKeys('the catalog profiles', catalog.profiles, ['darwin-platform', 'linux-full'])
  );
  if (!problems.length) {
    problems.push(...exactKeys('linux-full', catalog.profiles['linux-full'], ['N', 'O']));
    problems.push(
      ...exactKeys('darwin-platform', catalog.profiles['darwin-platform'], ['platform'])
    );
  }
  problems.push(...exactKeys('the finalization arrays', catalog.finalization, MODES));
  problems.push(...exactKeys('the scanner arrays', catalog.scanners, MODES));
  if (!isObject(catalog.pending) || !Object.keys(catalog.pending).length)
    problems.push('the catalog names nothing pending, which v3 says is pending');
  if (problems.length) throw new Error(problems.join('; '));
  for (const [where, list] of [
    ['linux-full N', catalog.profiles['linux-full'].N],
    ['linux-full O', catalog.profiles['linux-full'].O],
    ['darwin-platform', catalog.profiles['darwin-platform'].platform],
    ['finalization commit', catalog.finalization.commit],
    ['finalization release', catalog.finalization.release],
    ['scanners commit', catalog.scanners.commit],
    ['scanners release', catalog.scanners.release],
  ])
    problems.push(...listProblems(where, list));
  for (const [what, arrays] of [
    ['finalization', catalog.finalization],
    ['scanner', catalog.scanners],
  ])
    for (const item of arrays.commit ?? [])
      if (!arrays.release?.includes(item))
        problems.push(`the ${what} release array lacks the commit item ${item}`);
  for (const [name, reason] of Object.entries(catalog.pending))
    if (typeof reason !== 'string' || !reason.trim())
      problems.push(`the pending item ${show(name)} has no reason`);
  if (problems.length) throw new Error(problems.join('; '));
  problems.push(...placementProblems(catalog));
  if (problems.length) throw new Error(problems.join('; '));
  // Then each array exactly as v5's C23 gives it (CONTRACT_ARRAYS).
  for (const [where, list] of [
    ['linux-full N', catalog.profiles['linux-full'].N],
    ['linux-full O', catalog.profiles['linux-full'].O],
    ['darwin-platform', catalog.profiles['darwin-platform'].platform],
    ['finalization commit', catalog.finalization.commit],
    ['finalization release', catalog.finalization.release],
    ['scanners commit', catalog.scanners.commit],
    ['scanners release', catalog.scanners.release],
  ])
    if (canonicalJson(list) !== canonicalJson(CONTRACT_ARRAYS[where]))
      problems.push(
        `${where} is not v5 C23's array exactly (${CONTRACT_ARRAYS[where].length} entries, in its order): ${list.length} entries${list.length === CONTRACT_ARRAYS[where].length ? ', another set or order' : ''} is a partial or other catalog (v5 C23)`
      );
  if (problems.length) throw new Error(problems.join('; '));
  return { catalog, sha256: sha256(buffer) };
}

let installed;
/** The catalog beside this module: { catalog, sha256 }, read once. Throws when it is not valid. */
export function installedCatalog() {
  installed ??= parseCatalog(fs.readFileSync(new URL('./security-catalog.json', import.meta.url)));
  return installed;
}

/** The profile a main gate run reports: only a Linux main run has a reviewed array (C23). */
export const mainProfileFor = platform => (platform === 'linux' ? 'linux-full' : null);

/**
 * The platform the finalizer itself binds to each profile of the catalog (v4 C2, C14; Daybreak's
 * review of v3: F chooses the mode, the profile and the catalog, and compares each with what a
 * record names). A candidate's manifest, a run record or a caller can name a platform for a run,
 * but none of them decides the platform of a catalog profile: a manifest that declares one of
 * these runs on another platform is refused. The catalog file names no platform, so this table
 * is the reviewed code's own (a proposed form, until the catalog carries it).
 */
export const PROFILE_PLATFORMS = Object.freeze({
  'darwin-platform': 'darwin',
  'linux-full': 'linux',
});

/**
 * The required stage ids of `profile` in `mode`, phase by phase, from the catalog: { phases, all }.
 * `all` is the union in catalog order (an id in two phases once). Throws for a mode or profile the
 * catalog has no reviewed array for.
 */
export function profileStages(catalog, profile, mode) {
  if (!MODES.includes(mode)) throw new Error(`the catalog has no mode ${show(mode)}`);
  if (typeof profile !== 'string' || !own(catalog.profiles, profile))
    throw new Error(
      `the catalog has no reviewed array for the profile ${show(profile)}${own(catalog.pending, profile) ? ` (pending: ${catalog.pending[profile]})` : ''}`
    );
  const phases = catalog.profiles[profile];
  return { phases, all: [...new Set(Object.values(phases).flat())] };
}

// Names that earlier drafts reported in place of a catalog id. Several names for one id, or a
// name for something the id forbids, are not a one-to-one mapping (C23), so each is refused.
export const refusedNames = Object.freeze({
  'sast-rules-download':
    'one of three names for sast-rules, which is not a one-to-one mapping (C23)',
  'sast-rules-checksum':
    'one of three names for sast-rules, which is not a one-to-one mapping (C23)',
  'sast-rules-extract':
    'one of three names for sast-rules, which is not a one-to-one mapping (C23)',
  'sast-image-pull': 'a pull, which sast-image does not allow (C5, C23)',
  'sonarqube-analysis': 'a release F obligation (sonarqube), not a stage of a run (C23)',
  'final-artifacts': 'a release F obligation, not a stage of a run (C23)',
});

const STATUSES = new Set(['pass', 'pending', 'not-run', 'blocked', 'fail']);

/**
 * Judges the stage records of one run against `required` (profileStages(...).all): every
 * required id reported exactly once, nothing else. Returns { verdict, passed, pending, failed }:
 * `failed` lists a missing, repeated, unknown or refused name and a stage that did not pass and
 * is not pending; `pending` a stage reported pending or not run. The verdict is fail when anything
 * failed, pending when anything is pending, else pass. A caller cannot narrow `required`: the
 * finalizer takes it from the installed catalog for the profile it selects itself.
 */
export function judgeStages(records, required) {
  const failed = [];
  const pending = [];
  const passed = [];
  const seen = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    const name = record?.name;
    if (typeof name !== 'string') {
      failed.push('a stage record has no name');
      continue;
    }
    if (seen.has(name)) {
      failed.push(`${name} is reported twice`);
      continue;
    }
    seen.set(name, record);
    if (own(refusedNames, name)) failed.push(`${name} is reported: ${refusedNames[name]}`);
    else if (!required.includes(name)) failed.push(`${name} is not a stage of this profile`);
  }
  if (!Array.isArray(records)) failed.push('the run lists no stages');
  for (const id of required) {
    const record = seen.get(id);
    if (!record) failed.push(`${id} is missing`);
    else if (!STATUSES.has(record.status))
      failed.push(`${id} has the unknown status ${show(record.status)}`);
    else if (record.status === 'pass') passed.push(id);
    else if (record.status === 'pending' || record.status === 'not-run') pending.push(id);
    else failed.push(`${id} did not pass (${record.status})`);
  }
  return {
    verdict: failed.length ? 'fail' : pending.length ? 'pending' : 'pass',
    passed,
    pending,
    failed,
  };
}
