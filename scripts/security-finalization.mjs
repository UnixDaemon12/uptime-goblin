// A review can finalize a fresh completed run without changing its raw results.
// These are local tamper checks, not signatures or protection from the account owner.
//
// GATE-CONTRACT v3, and v5 after it, move finalization to one Mac-side flow, F, as the only thing
// that issues a pass (C13, C14). This module is not F. For a candidate with a platform contract it
// checks what it can (the run and its companions against the catalog and v5's order rules, the
// T8 activation's binding, the complete candidate identity, the review) and records each F
// obligation of the catalog: those owned by F
// on the Mac stay pending here, so its finalization of such a candidate is `pending`, never
// `pass`. The commit guard accepts only a finalization whose status is `pass` with every F
// obligation passed, which only F can write. A candidate whose history never held the platform
// manifest (maintenance, B35) is checked as before, with the complete parent identity and the
// pinned Actionlint of Daybreak GD-R2, and now also with its host and runtime evidence: test-host
// and runtime-identity passed before its test stages, and the identity of each Node binary they
// ran (GDR6-REQ-01; a run without them is refused), and against the approved B35 plan, which
// binds every stage it may record to its execution class and its class's record form
// (GDR7-FIN-01; an execution outside it, or nested in another stage's record, is refused), with a
// closed schema for what each stage record's members hold (GDR8-SCHEMA-01, a proposed shared
// interface, not an accepted one); the recorded-approval reader applies the plan and the host and
// runtime checks again before a recorded maintenance approval gives authority, with the stage
// results the finalizer requires (GDR7-AUTH-01), the finalizer's own sealed scanner-result
// judgment and the finding set it derives (GDR8-AUTH-SCAN-01, for every approval), after the one
// reconciliation of scanner stages and fixed reports both share (GDR9-AUTH-SCAN-02), and the lint
// stages verifyCommit derives from the exact commit (GDR8-AUTH-LINT-01). Every reader takes the run
// record's own host only in one of its closed producer forms (GDR9-HOST-SCHEMA-01, part of the same
// proposed interface), and reads Git only through the runner bound to its repository
// (bindRepository; GDR9-AUTH-ROOT-01). Its finalization here is
// `pending` too: its pinned Actionlint counts only once the qualified golden-tool manifest binds
// it (Codex decision 8), and a golden-tool record is a local file that nothing here
// authenticates, so that binding is an obligation only F can pass (`actionlint-pin`). So no
// finalization this module writes is a pass.
import fs from 'node:fs';
import path from 'node:path';
import { sha256, sourceManifest, testTotals, checkReview } from './security-evidence.mjs';
import { findingReports, reportFindings } from './security-findings.mjs';
import { canonicalJson, installedCatalog } from './security-catalog.mjs';
import { gateIdentityStage, parseGateIdentityBinding } from './security-gate-identity.mjs';
import {
  actionlintArguments,
  actionlintCandidateConfig,
  actionlintConfig,
  actionlintConfigFile,
  bindRepository,
  catalogJudgment,
  checkPlatformEvidence,
  closureSha256,
  committedIdentityProblems,
  historyRewriteProblems,
  identityKey,
  LOCAL_RUN_KIND,
  LOCAL_RUN_KIND_VERSION,
  MAINTENANCE_PLAN,
  maintenanceEvidenceProblems,
  maintenanceRequiredStages,
  manifestsAt,
  missingToolPin,
  parentAmbiguityProblems,
  parentVectorProblems,
  parseCoverageDispositions,
  parseGoldenTool,
  platformRequirementStages,
  readHistory,
  builtImageStages,
  candidateBuildStages,
  orderProblems,
  pendingRecordStages,
  recordPackBindingProblems,
  recordPackIdentity,
  runTimeProblems,
  sameParents,
  strictJson,
  t8ActivationProblems,
  t8InspectCommand,
} from './security-platform.mjs';

const maxBytes = 64 * 1024 * 1024;
const digest = /^[a-f0-9]{64}$/;
const safeName = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;
// A companion run's folder in orbit-security: <tree>-platform-<uuid>, as the gate names it.
const companionName =
  /^(?:[0-9a-f]{40}|[0-9a-f]{64})-platform-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const fail = message => {
  throw new Error(message);
};
// The run record (result.json): this draft's one local record of a gate run's N and O stages, or of
// a companion run's. It is a diagnostic record of a local run, NOT a phase record of GATE-CONTRACT
// v5 C12: it has no run nonce, controller digest, review-file digest, environment allowlists,
// prepared inputs, grant, per-stage evidence lists or phase, and it is no authority for F. Its
// record family is its own (Daybreak GDR4-02; Codex 014104 item 6c): `kind` names the family
// (LOCAL_RUN_KIND) and `kindVersion` its version within that family (LOCAL_RUN_KIND_VERSION, 1).
// The vocabulary of C12's phase records (`schema`, and its number 3) belongs to the C12 network,
// offline and platform forms only, and this family does not use it.
//
// gate-draft-r4 labelled this local form `schemaVersion: 3` and described reading it as C12's
// phase-record schema 3; that was wrong. A record in that frozen form is historical diagnostic
// evidence: it is not migrated, converted or read as this family. recordFamily() judges the family
// before any other member is used, and reads nothing else: a record naming no family, an unknown
// family, a wrong version, keys of two families, the frozen r4 form, a record pack and a C12 phase
// record are each refused, with no fallback, default, migration or inference from the members
// present. The C12 phase records themselves, their producers in the controller and their readers
// (F, the commit guard) are int-d's work and pending: nothing here reads or writes one, and
// nothing here is evidence of C12 compliance. The record pack's own format (`schemaVersion` 2,
// security-platform.mjs) is a separate series; neither reader takes one for the other.
export { LOCAL_RUN_KIND, LOCAL_RUN_KIND_VERSION };
/** The phase-record schema of v5 C12 and its phases: the C12 forms only, never the local family. */
export const C12_PHASE_SCHEMA = 3;
export const C12_PHASES = Object.freeze(['network', 'offline', 'platform']);
const LOCAL_FAMILY_KEYS = ['kind', 'kindVersion'];

/**
 * The record family of a parsed record `value`, judged from its family members alone, before any
 * other member is read: { family: 'local-run', version } for this draft's local diagnostic run
 * record, or { family: 'c12-phase', schema, phase } for a record that presents itself as a C12
 * phase record. Throws, naming why, for anything else: no family, an unknown family, a wrong or
 * missing version, the keys of two families together, a `schemaVersion` form (the frozen r4 local
 * form, a record pack and every other such form) or a C12 schema other than 3. It validates no
 * other member: the family's own reader does (parseRunRecord for the local family; the C12
 * readers are pending, int-d).
 */
export function recordFamily(value) {
  if (!isRecord(value)) fail('The record is not an object, so it names no record family');
  const local = LOCAL_FAMILY_KEYS.filter(key => Object.hasOwn(value, key));
  const c12 = Object.hasOwn(value, 'schema');
  const legacy = Object.hasOwn(value, 'schemaVersion');
  if ([local.length > 0, c12, legacy].filter(Boolean).length > 1)
    fail(
      `The record names members of more than one record family (${[...local, ...(c12 ? ['schema'] : []), ...(legacy ? ['schemaVersion'] : [])].join(', ')}): a mixed record is refused, and no family is chosen for it (GDR4-02)`
    );
  if (legacy)
    fail(
      `The record names schemaVersion ${JSON.stringify(value.schemaVersion)?.slice(0, 40)}: that is the frozen gate-draft-r4 local form (schemaVersion 3), a record pack or another form, not a record of the local run family, and it is not migrated, converted or read as one (GDR4-02; Codex 014104 item 6c)`
    );
  if (c12) {
    if (value.schema !== C12_PHASE_SCHEMA)
      fail(
        `The record presents itself as a C12 phase record of schema ${JSON.stringify(value.schema)?.slice(0, 40)}: only phase-record schema ${C12_PHASE_SCHEMA} is a C12 form, with no fallback (v5 C12)`
      );
    if (typeof value.phase !== 'string' || !C12_PHASES.includes(value.phase))
      fail(
        `The record presents itself as a C12 phase record without one of the phases ${C12_PHASES.join(', ')} (v5 C12)`
      );
    return { family: 'c12-phase', schema: C12_PHASE_SCHEMA, phase: value.phase };
  }
  if (!Object.hasOwn(value, 'kind'))
    fail(
      local.length
        ? 'The record names a family version but no family (kind): none is assumed (GDR4-02)'
        : 'The record names no record family: none is assumed or inferred from its members (GDR4-02)'
    );
  if (value.kind !== LOCAL_RUN_KIND)
    fail(
      `The record names the unknown record family ${JSON.stringify(value.kind)?.slice(0, 80)}: only ${LOCAL_RUN_KIND} is read here (GDR4-02)`
    );
  if (!Object.hasOwn(value, 'kindVersion'))
    fail(
      `The ${LOCAL_RUN_KIND} record names no kindVersion: no version of the family is assumed (GDR4-02)`
    );
  if (value.kindVersion !== LOCAL_RUN_KIND_VERSION)
    fail(
      `The ${LOCAL_RUN_KIND} record names kindVersion ${JSON.stringify(value.kindVersion)?.slice(0, 40)}: only version ${LOCAL_RUN_KIND_VERSION} of the family is read, with no fallback or migration (GDR4-02)`
    );
  return { family: 'local-run', version: LOCAL_RUN_KIND_VERSION };
}

/**
 * Refuses a record that is not of `family` ('local-run' or 'c12-phase'), before any of its other
 * members is read: a local run record presented as a C12 phase record and a C12 phase record
 * presented as a local run record are both refused. Returns recordFamily's result.
 */
export function expectRecordFamily(value, family) {
  const found = recordFamily(value);
  if (found.family !== family)
    fail(
      found.family === 'local-run'
        ? `The record is an ${LOCAL_RUN_KIND} record (version ${found.version}), a local diagnostic run record: it is not a C12 phase record, and it is not read as one (GDR4-02; Codex 014104 item 6c)`
        : `The record presents itself as a C12 phase record (schema ${found.schema}, phase ${found.phase}): it is not an ${LOCAL_RUN_KIND} record, and this reader reads no C12 record (GDR4-02; v5 C12)`
    );
  return found;
}

// The members of a local run record: those every run has, those a mode or a kind adds, and those
// the gate writes in some runs only (the inherited environment, the release obligations, and the
// catalog and platform judgment of a run that a maintenance gate wrote, which has neither). The
// kind of commit record is the record's own: a commit record whose candidate identity says the
// manifest path never held a manifest ({"state":"never-held"}, maintenance, B35) may lack the
// catalog and the platform judgment; any other commit record, a candidate with the platform
// contract, must hold both, so an incomplete one is refused here, before any stage is read. The
// finalizer later requires the candidate identity to be the candidate's own, so a record cannot
// choose the kind it is.
const RUN_MEMBERS = Object.freeze({
  required: [
    'kind',
    'kindVersion',
    'mode',
    'tree',
    'parents',
    'refs',
    'started',
    'finished',
    'host',
    'status',
    'stages',
    'tools',
    'candidate',
    'candidateIdentitySha256',
  ],
  platform: ['platformRun', 'catalog', 'platform'],
  contract: ['catalog', 'platform'],
  optional: [
    'catalog',
    'platform',
    'inheritedTestInputs',
    'inheritedHistoryInputs',
    'inheritedEnvironment',
    'releaseObligations',
  ],
});

/**
 * The closed, typed forms of a run record's own `host` (GDR9-HOST-SCHEMA-01; Codex's GATE decision
 * 5; part of the PROPOSED shared interface, not an accepted one): one variant for each known
 * producer form, told apart by its exact member set, never one permissive object with optional
 * members. `gate-1.5` is what the 1.5 gate writes (scripts/security-gate.mjs, the run record's
 * `host`): { platform, arch, release, node, uid }. `maintenance` is what the maintenance producer
 * writes (gate-draft-r11, GDR10-HOST-PRODUCER-01; Codex's decision 20261019T073253967039Z item 2,
 * which replaces the earlier three-member instruction): the maintenance gate, blob
 * 40bc87be8ab9be78e538bfdaa4af27d56746f9f5 (sha256 f8fe2857…, scripts/security-gate.mjs of the
 * maintenance tree export 57b02f9d and of orbit-codex's index), writes exactly { platform, arch,
 * release, node }. The three-member { node, platform, arch } that gate-draft-r10 accepted was
 * written by synthetic fixtures only and no producer, and is refused like any other member set.
 * This decides the host form only: that producer's record is still refused as a whole (no record
 * family, a single parent), and record-family and ordered-parent compatibility stay OPEN. Each
 * variant's members are all required, with their types: `platform` and `arch` a Node platform or
 * architecture name (lower case letters and digits), `release` a nonempty printable string of at
 * most 256 characters,
 * `node` a Node version (v<major>.<minor>.<patch>) and `uid` a nonnegative integer. A member of
 * another type, an object or list where a scalar belongs, and any member a variant does not have
 * are refused; a producer that needs another member needs an explicit new variant, with tests.
 * Which variants a record may carry follows from its own kind, by the producers that write it
 * (RUN_HOST_FORMS_BY_RECORD; round 2 of gate-draft-r10): a member set that is one variant is still
 * refused where that variant's producer writes no such record.
 */
export const RUN_HOST_FORMS = Object.freeze({
  'gate-1.5': Object.freeze({
    platform: 'name',
    arch: 'name',
    release: 'text',
    node: 'node',
    uid: 'uid',
  }),
  maintenance: Object.freeze({ platform: 'name', arch: 'name', release: 'text', node: 'node' }),
});
const HOST_TYPES = Object.freeze({
  name: [
    value => typeof value === 'string' && /^[a-z0-9]{1,20}$/.test(value),
    'a platform or architecture name',
  ],
  text: [
    value => typeof value === 'string' && /^[\x20-\x7e]{1,256}$/.test(value),
    'a nonempty printable string of at most 256 characters',
  ],
  node: [
    value => typeof value === 'string' && /^v\d{1,3}\.\d{1,4}\.\d{1,4}$/.test(value),
    'a Node version',
  ],
  uid: [value => Number.isSafeInteger(value) && value >= 0, 'a nonnegative integer'],
});

/**
 * The host forms each kind of run record may carry, by the producers that write that kind
 * (gate-draft-r10 round 2, check-1 of GDR9-HOST-SCHEMA-01: the variant was chosen by its member
 * set alone, so a contract run with the maintenance form's three members was accepted, and the 1.5
 * form's `release` and `uid` were in effect optional). A contract commit record (its candidate has
 * the platform contract, with a catalog) and a companion (`platform` mode) record are written only
 * by the 1.5 gate, so only its five-member form; a maintenance commit record (its candidate's
 * history never held the manifest) is written by the 1.5 gate for a B35 candidate and by the
 * maintenance producer, so either form: the 1.5 gate's five members or the maintenance gate's four
 * (gate-draft-r11). A PROPOSED shared interface, like RUN_HOST_FORMS.
 */
export const RUN_HOST_FORMS_BY_RECORD = Object.freeze({
  contract: Object.freeze(['gate-1.5']),
  platform: Object.freeze(['gate-1.5']),
  maintenance: Object.freeze(['gate-1.5', 'maintenance']),
});

/**
 * Why `host` is not one of the closed run host forms (RUN_HOST_FORMS) that `forms` (the names of
 * the variants its record's kind may carry: RUN_HOST_FORMS_BY_RECORD; every variant when not
 * given) admits: an empty list when it is, with `variant` the form it is. GDR9-HOST-SCHEMA-01.
 */
export function runHostProblems(host, { forms = Object.keys(RUN_HOST_FORMS), record } = {}) {
  if (!isRecord(host)) return { variant: null, problems: ['the host is not an object'] };
  const members = Object.keys(host).sort();
  const variant = Object.keys(RUN_HOST_FORMS).find(
    name => Object.keys(RUN_HOST_FORMS[name]).sort().join(',') === members.join(',')
  );
  if (!variant)
    return {
      variant: null,
      problems: [
        `the host has the members [${members.map(key => JSON.stringify(key).slice(0, 40)).join(', ')}], which are neither the 1.5 gate's [${Object.keys(RUN_HOST_FORMS['gate-1.5']).join(', ')}] nor the maintenance gate's [${Object.keys(RUN_HOST_FORMS.maintenance).join(', ')}]`,
      ],
    };
  if (!forms.includes(variant))
    return {
      variant,
      problems: [
        `the host is the ${variant} form [${Object.keys(RUN_HOST_FORMS[variant]).join(', ')}], which ${record ?? 'this kind of record'} does not carry: it carries only ${forms
          .map(name => `the ${name} form [${Object.keys(RUN_HOST_FORMS[name]).join(', ')}]`)
          .join(' or ')}, every member required, as its producer writes it`,
      ],
    };
  const problems = [];
  for (const [member, type] of Object.entries(RUN_HOST_FORMS[variant])) {
    const [valid, expected] = HOST_TYPES[type];
    if (!valid(host[member]))
      problems.push(
        `host.${member} is ${JSON.stringify(host[member])?.slice(0, 80) ?? 'undefined'}, not ${expected}`
      );
  }
  return { variant, problems };
}

/**
 * Reads a run record's bytes as a record of the local run family: its family and version first and
 * alone (expectRecordFamily, above), then its mode, then exactly the members of that mode's form,
 * then its own `host` against the closed forms its kind's producers write (runHostProblems with
 * RUN_HOST_FORMS_BY_RECORD; GDR9-HOST-SCHEMA-01, round 2). Returns the
 * record; throws with why it is refused. It reads no C12 phase record.
 */
export function parseRunRecord(bytes, { mode = 'commit' } = {}) {
  const record = strictRecord(bytes, 'result.json');
  if (!isRecord(record)) fail('result.json is not a run record');
  expectRecordFamily(record, 'local-run');
  const family = `${LOCAL_RUN_KIND} version ${LOCAL_RUN_KIND_VERSION}`;
  if (record.mode !== mode)
    fail(
      mode === 'commit'
        ? `Only sealed local runs (${family}) of mode commit, which bind the complete parent vector, can be finalized`
        : `Only sealed local runs (${family}) of mode ${mode} can be companion runs`
    );
  // The kind of commit record, from its own candidate identity record (RUN_MEMBERS above).
  const maintenance =
    mode === 'commit' &&
    isRecord(record.candidate) &&
    isRecord(record.candidate.platformManifest) &&
    Object.keys(record.candidate.platformManifest).join() === 'state' &&
    record.candidate.platformManifest.state === 'never-held';
  const required = [
    ...RUN_MEMBERS.required,
    ...(mode === 'platform' ? RUN_MEMBERS.platform : maintenance ? [] : RUN_MEMBERS.contract),
  ];
  const allowed = new Set([...required, ...RUN_MEMBERS.optional]);
  const unknown = Object.keys(record).filter(key => !allowed.has(key));
  if (unknown.length)
    fail(
      `The run record labelled ${family} holds ${unknown.map(key => JSON.stringify(key).slice(0, 40)).join(', ')}, which that form does not have: another form labelled as this family is refused (GDR4-02)`
    );
  const missing = required.filter(key => !Object.hasOwn(record, key));
  if (missing.length)
    fail(`The ${family} run record is incomplete: it lacks ${missing.join(', ')} (GDR4-02)`);
  if (
    !Array.isArray(record.parents) ||
    !Array.isArray(record.stages) ||
    !isRecord(record.host) ||
    !isRecord(record.candidate)
  )
    fail(
      `The ${family} run record is incomplete: its parents, stages, host or candidate identity record is not of its form (GDR4-02)`
    );
  // The host form its kind's producers write (RUN_HOST_FORMS_BY_RECORD; round 2).
  const kind = mode === 'platform' ? 'platform' : maintenance ? 'maintenance' : 'contract';
  const host = runHostProblems(record.host, {
    forms: RUN_HOST_FORMS_BY_RECORD[kind],
    record:
      kind === 'platform'
        ? 'a companion (platform mode) record, which only the 1.5 gate writes,'
        : kind === 'contract'
          ? 'a contract commit record (its candidate has the platform contract), which only the 1.5 gate writes,'
          : 'a maintenance commit record',
  });
  if (host.problems.length)
    fail(
      `The ${family} run record's host is not one of its closed producer forms (GDR9-HOST-SCHEMA-01): ${host.problems.slice(0, 5).join('; ')}`
    );
  return record;
}
// The finalization (approval) version: 2 binds the complete identity. Version 1 named a single
// parent and gives no authority, even for a commit with one parent (COORDINATOR-DECISIONS "C18
// legacy approvals").
export const APPROVAL_SCHEMA = 2;

// The stages the earlier gate recorded (B35 maintenance candidates are still judged by this list:
// the catalog of v3 C23 is for the 1.5 gate, and v3 names no maintenance profile), with, before
// the test stages, test-host and runtime-identity (MAINTENANCE_TEST_PREREQUISITES): GDR6-REQ-01,
// under Codex's B35 decision of 20261017T140102522864Z, requires a maintenance run to identify its
// runtimes before its tests run, as every other run does. A run without them, as the earlier gate
// wrote, is refused on that basis (checkRun, and maintenanceRuntimeProblems through
// checkPlatformEvidence). The list is the `always` part of the approved B35 plan
// (MAINTENANCE_PLAN in security-platform.mjs, GDR7-FIN-01), which also binds each stage to its
// execution class: the same names, in the same order, as before.
export const requiredStages = MAINTENANCE_PLAN.filter(entry => entry.required === 'always').map(
  entry => entry.name
);

// 1.5's SQL and import-graph lint stages, which the 1.5 gate records in its commit, release and
// scan runs (run once the pre-dispatch barrier is open, otherwise withheld and pending). They are
// not in requiredStages because one installed commit guard, with this module beside it, serves
// every linked worktree, and the maintenance gate does not run them. A caller names the lint
// stages a run must carry as `current.lintStages`: the guard passes the ones the candidate and
// its parents need (scripts/check-security-approval.mjs), and the 1.5
// scripts/finalize-security.mjs passes both. A caller that names none requires none here; the
// catalog of a candidate with a platform contract holds both anyway.
export const lintStageNames = ['sql-lint', 'import-lint'];

// Stages recorded without a command: requirements the gate checks itself.
const requirementStages = new Set([
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
  ...platformRequirementStages,
]);

// The F obligations of the catalog (v5 C23) that only F, on the Mac, can establish: this module
// has none of their inputs (the ledger-bound captured archive, the schema 3 N and O phase records
// and their placement, the controller's ledger and monitor, the C20 trust-material records, the
// C5 activation records, the trusted Mac times, the controller's cleanup, F's own sealed record).
// Within image-approvals this module checks the T8 binding it can see (t8ActivationProblems), but
// that check is consistency, and the obligation stays F's.
export const fObligationsOwnedByF = Object.freeze({
  'archive-validation': 'the ledger-bound captured archive (v5 C14, C24)',
  'phase-evidence':
    'the schema 3 N and O phase records with the grant between them, their placement and order (v5 C3, C12, C23)',
  'controller-completion':
    "the controller's ledger, prefetch, negative controls and monitor (v5 C13, C14)",
  'runtime-approvals': 'the reviewed runtime trust-material records (v5 C20, pending)',
  'image-approvals':
    "the reviewed image activation records, and the reconciliation of N's T8 identity and authenticity records (with a locally built T8-related image's sealed result record) with O's t8-image-activation, whose record forms are pending (v5 C5, C14, C17 item 12)",
  freshness: 'trusted Mac times from the preflight to F (v5 C14)',
  'cleanup-evidence': "the controller's cleanup and final sweep (v5 C13)",
  'evidence-seal': "F's own sealed finalization record (v5 C12, C14)",
});

export function readEvidence(file) {
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
  );
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes || stat.mode & 0o077)
      fail('Evidence must be a bounded private regular file');
    const buffer = Buffer.alloc(Math.min(stat.size + 1, maxBytes + 1));
    let used = 0;
    while (used < buffer.length) {
      const count = fs.readSync(fd, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used !== stat.size) fail('Evidence changed size while being read');
    return buffer.subarray(0, used);
  } finally {
    fs.closeSync(fd);
  }
}

function json(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('Invalid evidence JSON');
  }
}
/**
 * A record the gate, the finalizer or a reviewer writes (the run manifest, result.json, the source
 * manifest, the tool configuration, the review and the approval): UTF-8 JSON in which no object
 * names a member twice. JSON.parse keeps the last of two, so readers could disagree about what
 * such a record says; a gate identity whose `version` is named twice is the case verify-1 of
 * gate-draft-r3 showed (GCV3-03). Tool output keeps the plain reader.
 */
function strictRecord(bytes, what) {
  try {
    return strictJson(bytes, what, maxBytes);
  } catch (error) {
    fail(`Invalid evidence JSON: ${error.message}`);
  }
}
function writeNew(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}
function directory(value) {
  const stat = fs.lstatSync(value);
  if (!stat.isDirectory() || stat.mode & 0o077)
    fail('Run directory must be private and not a symlink');
  return fs.realpathSync(value);
}

/**
 * The parents of the commit being made, as its complete ordered parent vector (v3 C18): HEAD and,
 * while `git commit` concludes a merge, each MERGE_HEAD entry, in Git's order. `complete` is false
 * (with the `reason`) when MERGE_HEAD cannot be read or names something that is not a full commit
 * id or a commit twice, or when `automaticMerge` says Git may be running the guard for an automatic
 * merge, before it records the commit it joins. Nothing is approved for an incomplete vector.
 */
export function candidateParents(root = process.cwd(), { automaticMerge = false, binding } = {}) {
  // The repository at `root`, through its bound runner (bindRepository; GDR9-AUTH-ROOT-01).
  const bound = binding ?? bindRepository(root);
  const git = (...args) => bound.run(args).toString('utf8').trimEnd();
  const head = git('rev-parse', 'HEAD');
  const file = git('rev-parse', '--path-format=absolute', '--git-path', 'MERGE_HEAD');
  let merging = '';
  let complete = true;
  let reason = '';
  try {
    merging = fs.readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') {
      complete = false;
      reason = 'MERGE_HEAD could not be read';
    } else if (automaticMerge) {
      complete = false;
      reason =
        'GIT_REFLOG_ACTION is set while no merge is being concluded, as when an automatic git merge or git pull runs this guard before Git records the commit it joins';
    }
  }
  const named = merging.split('\n').filter(Boolean);
  const heads = [head, ...named];
  if (!heads.every(id => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(id))) {
    complete = false;
    reason = 'MERGE_HEAD could not be read';
  } else if (new Set(heads).size !== heads.length) {
    complete = false;
    reason = 'MERGE_HEAD names a parent twice';
  }
  return {
    heads: complete ? heads : heads.filter(id => /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(id)),
    complete,
    reason,
  };
}

/**
 * The candidate the commit guard and the finalizer see in the repository at `root`: its staged
 * tree, HEAD (`parent`, for the lint-script checks), its complete ordered parent vector (`parents`,
 * with `parentsComplete` and `parentsReason`, from candidateParents), its refs and its files. Git
 * runs bound to that repository and its own index (bindRepository with `index`; GDR9-AUTH-ROOT-01;
 * `binding` is the caller's, when it has one), with the history hardened: a replace ref can stand
 * in for any object, the candidate's tree included, so it is read as it is.
 */
export function currentCandidate(root = process.cwd(), { automaticMerge = false, binding } = {}) {
  const bound = binding ?? bindRepository(root, { index: true });
  const git = (...args) => bound.run(args).toString('utf8').trimEnd();
  const tree = git('write-tree');
  const parents = candidateParents(root, { automaticMerge, binding: bound });
  return {
    tree,
    parent: git('rev-parse', 'HEAD'),
    parents: parents.heads,
    parentsComplete: parents.complete,
    parentsReason: parents.reason,
    refs: git('for-each-ref', '--format=%(refname) %(objectname)'),
    files: sourceManifest(root, git('ls-tree', '-rz', '--full-tree', tree)),
  };
}

export function sealRun(runDirectory) {
  const root = directory(runDirectory);
  const entries = fs
    .readdirSync(root)
    .sort()
    .map(file => {
      if (!safeName.test(file)) fail('Unsupported evidence filename');
      const bytes = readEvidence(path.join(root, file));
      return { file, sha256: sha256(bytes), bytes: bytes.length };
    });
  // Exclusive creation prevents accidentally resealing changed evidence.
  writeNew(path.join(root, 'run-manifest.json'), { schemaVersion: 1, files: entries });
}

/**
 * A sealed run: every file its run-manifest.json lists, each unchanged. `mode` is the mode it
 * must have (commit, or platform for a companion run). With `exact`, a file in the directory that
 * the run-manifest does not list (added after sealing: a late file) is refused too; a commit run
 * gains its finalization after sealing, so only companion runs are read that way. Only a record of
 * the local run family (LOCAL_RUN_KIND, version 1), which binds the complete ordered parent
 * vector, is read; it is diagnostic, not a C12 phase record.
 */
export function readSealedRun(runDirectory, { mode = 'commit', exact = false } = {}) {
  const root = directory(runDirectory);
  const manifestBytes = readEvidence(path.join(root, 'run-manifest.json'));
  const manifest = strictRecord(manifestBytes, 'run-manifest.json');
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.files) || !manifest.files.length)
    fail('Missing run evidence manifest');
  const contents = new Map();
  for (const item of manifest.files) {
    if (!safeName.test(item.file) || contents.has(item.file) || !digest.test(item.sha256))
      fail('Invalid or duplicate evidence file');
    const bytes = readEvidence(path.join(root, item.file));
    if (bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail('Run evidence changed');
    contents.set(item.file, bytes);
  }
  if (exact)
    for (const name of fs.readdirSync(root))
      if (name !== 'run-manifest.json' && !contents.has(name))
        fail(`Run evidence was added after sealing: ${path.basename(root)}/${name}`);
  const get = name => contents.get(name) || fail('Required evidence file is missing');
  const has = name => contents.has(name);
  // The record family first and alone, before any other member is used (parseRunRecord).
  const record = parseRunRecord(get('result.json'), { mode });
  const files = strictRecord(get('source-manifest.json'), 'source-manifest.json');
  if (!Array.isArray(files)) fail('The run has no source manifest list');
  return {
    root,
    name: path.basename(root),
    record,
    files,
    get,
    has,
    runSha256: sha256(manifestBytes),
  };
}

function readRun(runDirectory) {
  return readSealedRun(runDirectory);
}

// The obligation of a passing Actionlint that only F can establish (Codex decision 8; v4 C4, C7):
// the qualified golden-tool manifest of the trusted gate export must bind the pin. A golden-tool
// record sealed with a run is a local file that nothing here authenticates, and this module has
// no qualified manifest, so whatever the record says, the binding stays pending here: verify-1 of
// gate-draft-r3 found a maintenance (B35) finalization passing on such a record.
export const ACTIONLINT_PIN = 'actionlint-pin';
const actionlintPinReason =
  'the qualified golden-tool manifest of the trusted gate export must bind the Actionlint the run ran (its exact path, version, sha256, platform, provenance and dependency closure) before any finalization; the golden-tool record sealed with the run is a local file that nothing here authenticates, and this module has no qualified manifest, so only F can establish the binding (Codex decision 8; v4 C4, C7)';
/** The F obligations of a maintenance (B35) finalization: only the Actionlint pin's binding. */
export const maintenanceObligations = Object.freeze([ACTIONLINT_PIN]);

/**
 * Problems with the pinned Actionlint of a run (Daybreak GD-R2), for a candidate with a platform
 * contract and for maintenance (B35) alike: actionlint-version names the binary its sealed
 * golden-tool record pins (path, sha256 and the candidate's reviewed version, on the run's
 * platform), and a passing workflow-analysis ran exactly that binary with the gate-owned
 * configuration sealed beside it, and recorded the binary's sha256 again immediately before and
 * after it ran, both the pinned one: candidate code runs between actionlint-version and
 * workflow-analysis and could otherwise replace a binary the gate's user can write. With a
 * version 3 gate identity recorded (`identity`), the pinned path must be the identity's
 * toolPaths.actionlint. No problem here is still no pass: a sealed record proves nothing about
 * who pinned the binary, and only F can establish the qualified binding (ACTIONLINT_PIN). The
 * gate of this draft runs no Actionlint at all, so its runs carry both stages pending.
 */
function actionlintProblems(run, stages, identity = null) {
  const { record, get, has } = run;
  const version = stages.get('actionlint-version');
  const analysis = stages.get('workflow-analysis');
  if (version?.status !== 'pass') {
    if (analysis?.status === 'pass')
      return [
        'workflow-analysis passed without a pinned Actionlint (actionlint-version did not pass)',
      ];
    // A missing reviewed pin is pending AND blocking (Codex decision 8): both stages must name
    // exactly which pin and which evidence is missing, so a vague pending is refused.
    if (version?.status === 'pending') {
      const expected = JSON.stringify(
        missingToolPin({
          tool: 'actionlint',
          version: record.tools?.actionlint,
          platform: record.host?.platform,
          arch: record.host?.arch,
        })
      );
      if (
        JSON.stringify(version.missingPin) !== expected ||
        (analysis?.status === 'pending' && JSON.stringify(analysis.missingPin) !== expected)
      )
        return [
          'a pending Actionlint stage does not name the missing pin and its evidence (Codex decision 8)',
        ];
    }
    return [];
  }
  const problems = [];
  let pinned;
  try {
    if (typeof version.tool?.record !== 'string' || !has(version.tool.record))
      throw new Error('actionlint-version sealed no golden-tool record');
    pinned = parseGoldenTool(get(version.tool.record), {
      tool: 'actionlint',
      platform: record.host?.platform,
      arch: record.host?.arch,
      version: record.tools?.actionlint,
    });
    if (version.tool.path !== pinned.path || version.tool.sha256 !== pinned.sha256)
      throw new Error(
        'actionlint-version observed another binary than its golden-tool record pins'
      );
    if (version.tool.dependencyClosureSha256 !== closureSha256(pinned.dependencyClosure))
      throw new Error(
        'actionlint-version did not observe the dependency closure its golden-tool record pins (Codex decision 8)'
      );
    if (identity && identity.toolPaths?.actionlint !== pinned.path)
      throw new Error(
        `the pinned Actionlint ${pinned.path} is not at the path the run's gate identity names for it (toolPaths.actionlint; v4 C1, C7)`
      );
  } catch (error) {
    return [error.message];
  }
  if (analysis?.status === 'pass') {
    const configPath = analysis.command?.[2];
    if (
      !Array.isArray(analysis.command) ||
      typeof configPath !== 'string' ||
      JSON.stringify(analysis.command) !==
        JSON.stringify([pinned.path, ...actionlintArguments(configPath)]) ||
      path.basename(configPath) !== actionlintConfigFile ||
      path.basename(path.dirname(configPath)) !== run.name ||
      !has(actionlintConfigFile) ||
      get(actionlintConfigFile).toString('utf8') !== actionlintConfig
    )
      problems.push(
        'workflow-analysis did not run the pinned Actionlint with the gate-owned configuration'
      );
    const observed = analysis.binarySha256;
    if (
      observed === null ||
      typeof observed !== 'object' ||
      Array.isArray(observed) ||
      Object.keys(observed).sort().join(',') !== 'after,before' ||
      observed.before !== pinned.sha256 ||
      observed.after !== pinned.sha256
    )
      problems.push(
        'workflow-analysis did not show that the binary it ran still had the pinned sha256 immediately before and after it ran'
      );
    const closure = analysis.dependencyClosureSha256;
    const pinnedClosure = closureSha256(pinned.dependencyClosure);
    if (
      closure === null ||
      typeof closure !== 'object' ||
      Array.isArray(closure) ||
      Object.keys(closure).sort().join(',') !== 'after,before' ||
      closure.before !== pinnedClosure ||
      closure.after !== pinnedClosure
    )
      problems.push(
        'workflow-analysis did not show that the dependency closure it ran with was the pinned one immediately before and after it ran (Codex decision 8)'
      );
  }
  return problems;
}

/**
 * The F obligations of the catalog's commit array for a candidate with a platform contract:
 * { obligation: { status, reason? } }. This module establishes the candidate identity, the
 * required catalogs (when every run's judgment passed), the companion evidence (only when no
 * companion is needed: a companion's trusted intervals are pending, v3 C22) and, once a review is
 * checked, the review approval. The others belong to F on the Mac and are pending here.
 */
function fObligations(catalog, { catalogVerdict, companions, reviewed }) {
  const result = {};
  for (const id of catalog.finalization.commit) {
    if (Object.hasOwn(fObligationsOwnedByF, id))
      result[id] = {
        status: 'pending',
        reason: `owned by F on the Mac: ${fObligationsOwnedByF[id]}`,
      };
    else if (id === 'candidate-identity') result[id] = { status: 'pass' };
    else if (id === 'required-catalogs')
      result[id] =
        catalogVerdict === 'pass'
          ? { status: 'pass' }
          : { status: 'pending', reason: 'a catalog stage is pending' };
    else if (id === 'companion-evidence')
      result[id] = companions
        ? {
            status: 'pending',
            reason: 'no trusted dispatch, start, end and receipt intervals of a companion (v3 C22)',
          }
        : { status: 'pass' };
    else if (id === 'review-approval')
      result[id] = reviewed
        ? { status: 'pass' }
        : { status: 'pending', reason: 'no independent review is checked yet' };
    else result[id] = { status: 'pending', reason: 'no rule in this draft' };
  }
  return result;
}

/** The exit a scanner gives when it reports findings: 1 for Semgrep, 10 for Gitleaks and Trivy. */
const findingExitOf = name => (name === 'source-analysis' ? 1 : 10);

/**
 * The sealed scanner-result judgment of one scanner stage `stage` of the sealed run `run` that ran
 * its command (`log` is its sealed log's text; `earlier` the run's stages by name so far, for the
 * inspected image), shared by the finalizer (checkRun) and the recorded-approval reader
 * (recordedApproval; GDR8-AUTH-SCAN-01, Daybreak's review of gate-draft-r8): the scanner's fixed
 * report (findingReports) must be sealed with the run and parse as its scanner's report; Semgrep
 * must have run the pinned image with the empty-ignore adapter, and Trivy's image report must be of
 * the inspected image and invocation; the findings are derived from that report, never taken from a
 * claim; and the report, its findings, the exit and the status must agree: no finding, exit 0 and
 * `pass`; findings, the scanner's finding exit and `blocked`, as the gate records a nonzero exit
 * (startStage in scripts/security-gate.mjs). A secret scan's log must show it completed. Everything
 * it reads is sealed with the run, so it does not depend on the moment it is asked. Returns the
 * findings; throws, naming the problem, otherwise.
 */
function scannerResult(run, stage, earlier, log) {
  const { record, files, get, has } = run;
  const report = findingReports[stage.name];
  if (!has(report))
    fail(`Scanner report is missing: ${stage.name} sealed no ${report}, so it gives no findings`);
  if (
    stage.name === 'source-analysis' &&
    (!stage.command.includes(record.tools.semgrepImage) ||
      !stage.command.includes('--no-git-ignore') ||
      stage.command[stage.command.indexOf('--project-root') + 1] !== '/scan' ||
      get('semgrepignore').length !== 0)
  )
    fail('Scanner command does not match the pinned image and empty-ignore adapter');
  const items = reportFindings(stage.name, get(report), { tools: record.tools, files });
  if (stage.name === 'container-vulnerabilities') {
    const parsed = json(get(report));
    const identity = json(get(earlier.get('container-identity')?.log));
    if (
      !Array.isArray(identity) ||
      identity.length !== 1 ||
      identity[0].Id !== parsed.Metadata.ImageID ||
      !stage.command.includes(parsed.ArtifactName)
    )
      fail('Image report does not match the inspected image and invocation');
  }
  if (stage.exit !== (items.length ? findingExitOf(stage.name) : 0))
    fail('Scanner exit and findings disagree');
  if (stage.status !== (items.length ? 'blocked' : 'pass'))
    fail(
      `Scanner status and findings disagree: ${stage.name} is ${JSON.stringify(stage.status)} with ${items.length} finding${items.length === 1 ? '' : 's'} (pass with none, blocked with its finding exit when there are findings)`
    );
  if (
    stage.name.startsWith('secrets-') &&
    (!/\bINF scanned ~[0-9]+ bytes\b/.test(log) || /\b(?:ERR|FTL)\b/.test(log))
  )
    fail('Secret scan completion is not established');
  return items;
}

/**
 * Why the stage `stage` of the sealed run `run`, recorded as pending, is not one (null when it
 * is): a pending stage needs a reason and runs nothing, so it records nothing a command leaves (no
 * command, log, exit, signal or error, as the gate's withhold() and requirement() write it). Only
 * t8-image-identity may have run something while pending: exactly its local read-only observation
 * of the images it names, which exited 0 and sealed its log (v5 C5: the stage stays pending while
 * its record form and the stage policy for the query are pending). Shared by the finalizer
 * (checkRun) and the recorded-approval reader's scanner judgment (sealedScannerFindings), so a
 * scanner recorded as pending although it ran gives no authority at either (check-1 of
 * gate-draft-r9, CONTRACT-T4, GDR8-AUTH-SCAN-01).
 */
function pendingStageProblem(run, stage) {
  const problem = `A pending stage needs a reason and runs nothing: ${stage.name}`;
  if (typeof stage.reason !== 'string' || !stage.reason.trim()) return problem;
  if (stage.name === 't8-image-identity' && stage.command !== undefined)
    return Array.isArray(stage.images) &&
      JSON.stringify(stage.command) === JSON.stringify(t8InspectCommand(stage.images)) &&
      stage.exit === 0 &&
      !stage.signal &&
      !stage.error &&
      safeName.test(stage.log ?? '') &&
      run.has(stage.log)
      ? null
      : problem;
  return ['command', 'log', 'exit', 'signal', 'error'].some(key => stage[key] !== undefined)
    ? problem
    : null;
}

/**
 * The shared stage and report reconciliation of a sealed run's scanners (GDR9-AUTH-SCAN-02;
 * Codex's GATE decision 6), used by the finalizer (checkRun) and the recorded-approval reader
 * (sealedScannerFindings) alike, before any scanner is judged: the fixed reports (findingReports)
 * are inventoried as well as the stages. Each fixed report sealed with the run must belong to
 * exactly one scanner stage that ran: a report beside a scanner withheld or otherwise recorded as
 * pending (nothing run, so no report, as the gate's withhold() leaves it), whether the report is
 * empty, malformed or holds findings, and a report whose scanner has no stage at all (an orphan)
 * are refused, so a sealed report can never carry findings that no consumer reads. A scanner
 * recorded more than once gives no one result either. A scanner that ran is then judged by
 * scannerResult, unchanged, and a genuinely withheld scanner with no report gives no findings.
 * Returns the problems (none when every report reconciles).
 */
function scannerReportProblems(run) {
  const stages = Array.isArray(run.record?.stages) ? run.record.stages : [];
  const problems = [];
  for (const [name, report] of Object.entries(findingReports)) {
    const named = stages.filter(stage => isRecord(stage) && stage.name === name);
    const sealed = run.has(report);
    if (named.length > 1)
      problems.push(`${name} is recorded more than once, so its report gives no one result`);
    else if (!named.length && sealed)
      problems.push(
        `${report} is sealed with the run, but no ${name} stage is recorded: a report that belongs to no scanner stage gives no result, and its findings could be read by no one (GDR9-AUTH-SCAN-02)`
      );
    else if (named.length && named[0].status === 'pending' && sealed)
      problems.push(
        `${name} is recorded as pending (withheld, nothing run), but its fixed report ${report} is sealed with the run: a scanner that did not run has no report, empty or not, so the run gives no result (GDR9-AUTH-SCAN-02)`
      );
  }
  return problems;
}

/**
 * The finding set of a sealed run as the finalizer derives it, for the recorded-approval reader
 * (GDR8-AUTH-SCAN-01): the stages and fixed reports are reconciled first (scannerReportProblems;
 * GDR9-AUTH-SCAN-02), then each scanner stage that ran is judged by scannerResult, in the run's
 * order, and its findings are collected. A scanner stage recorded as pending gives no findings only
 * when it is one by the finalizer's own rule (pendingStageProblem: a reason, and nothing run) and
 * has no report; one recorded twice, one that failed to execute, one without its command or
 * without its sealed log gives no result. Each of those is a problem. Returns { findings, problems }.
 */
function sealedScannerFindings(run) {
  const findings = [];
  const problems = scannerReportProblems(run);
  const earlier = new Map();
  for (const stage of Array.isArray(run.record?.stages) ? run.record.stages : []) {
    if (!isRecord(stage) || typeof stage.name !== 'string') continue;
    const { name } = stage;
    const repeated = earlier.has(name);
    if (!repeated) earlier.set(name, stage);
    if (!findingReports[name]) continue;
    // A repeated scanner: the reconciliation names it.
    if (repeated) continue;
    if (stage.status === 'pending') {
      // The finalizer's own rule (checkRun): a scanner that ran is never pending, so its report is
      // not skipped (check-1 of gate-draft-r9, CONTRACT-T4).
      const pending = pendingStageProblem(run, stage);
      if (pending) problems.push(pending);
      continue;
    }
    if (stage.error || stage.signal) {
      problems.push(`${name} failed to execute, so its report gives no result`);
      continue;
    }
    if (
      !Array.isArray(stage.command) ||
      !stage.command.length ||
      !stage.command.every(value => typeof value === 'string' && value)
    ) {
      problems.push(
        `${name} is a scanner stage without its command, so its report gives no result`
      );
      continue;
    }
    if (!safeName.test(stage.log ?? '') || !run.has(stage.log)) {
      problems.push(`${name} ran without a sealed log, so its report gives no result`);
      continue;
    }
    try {
      findings.push(...scannerResult(run, stage, earlier, run.get(stage.log).toString('utf8')));
    } catch (error) {
      problems.push(`${name}: ${error.message}`);
    }
  }
  return { findings, problems };
}

/**
 * Checks that `dispositions` (a review's) dispose of exactly the findings `findings`, one each:
 * a known finding id, no duplicate, a supported status, a reviewer, reason and reference, and the
 * evidence its digest names (in `evidenceDirectory` when given, the finalization's retained copy;
 * otherwise the disposition's own evidenceFile). Shared by the finalizer's review check and the
 * recorded-approval reader (GDR8-AUTH-SCAN-01). Throws, naming the problem.
 */
function checkDispositions(dispositions, findings, evidenceDirectory) {
  if (!Array.isArray(dispositions) || dispositions.length !== findings.length)
    fail('Every finding needs one exact disposition');
  const expected = new Set(findings.map(item => item.id));
  for (const item of dispositions) {
    if (
      !isRecord(item) ||
      !expected.delete(item.id) ||
      !['false-positive', 'not-affected'].includes(item.status)
    )
      fail('Unknown, duplicate or unsupported finding disposition');
    for (const key of ['reviewer', 'reason', 'reference'])
      if (typeof item[key] !== 'string' || !item[key].trim())
        fail('Disposition needs reviewer, reason and evidence');
    if (!digest.test(item.evidenceSha256)) fail('Disposition needs an evidence digest');
    const evidenceFile = evidenceDirectory
      ? path.join(evidenceDirectory, `${item.evidenceSha256}.evidence`)
      : item.evidenceFile;
    if (typeof evidenceFile !== 'string' || !path.isAbsolute(evidenceFile))
      fail('Disposition needs a private evidence file');
    if (sha256(readEvidence(evidenceFile)) !== item.evidenceSha256)
      fail('Disposition evidence digest does not match');
  }
}

function checkRun(run, current, now) {
  const { record, files, get } = run;
  const vector = parentVectorProblems(current.parents);
  if (current.parentsComplete === false || vector.length)
    fail(
      `The candidate's complete parent vector is not known (${current.parentsReason || vector.join('; ')}): nothing is approved for it (merge with --no-commit, then run git commit)`
    );
  if (
    record.tree !== current.tree ||
    !sameParents(record.parents, current.parents) ||
    record.refs !== current.refs
  )
    fail('Run no longer matches the candidate tree, complete ordered parent vector or refs');
  if (JSON.stringify(files) !== JSON.stringify(current.files)) fail('Candidate files changed');
  // A tracked .github/actionlint.yaml or .yml could silence workflow findings (Daybreak GD-R2).
  // The 1.5 gate refuses one in candidate-policy; it is refused here as well, for every candidate,
  // maintenance (B35) included, whatever gate wrote the run.
  const actionlintFile = files.find(item => actionlintCandidateConfig(item?.file ?? ''));
  if (actionlintFile)
    fail(
      `A tracked Actionlint configuration can silence workflow findings: ${actionlintFile.file}`
    );
  // The run's window, and every stage of it inside that window (Daybreak GD-R3: the main run's
  // stages were not checked, only a companion's).
  const times = runTimeProblems(record, now);
  if (times.length) fail(`Run times: ${times.slice(0, 3).join('; ')}`);
  const finished = Date.parse(record.finished);
  if (!record.tools || !Array.isArray(record.stages)) fail('Missing tool or stage evidence');
  const toolConfig = get('tool-config.json');
  if (
    files.find(item => item.file === 'scripts/security-tools.json')?.sha256 !==
      sha256(toolConfig) ||
    JSON.stringify(strictRecord(toolConfig, 'tool-config.json')) !== JSON.stringify(record.tools)
  )
    fail('Tool configuration does not match the tracked candidate');
  // The candidate identity needs the platform judgment: the manifest path's state is part of it
  // (v3 C18, C19). A caller that names no platform inputs cannot establish it.
  if (current.platform === undefined)
    fail(
      'The candidate identity needs the platform-manifest judgment (v3 C18, C19): this caller names no platform inputs'
    );
  const companions = (current.companions ?? []).map(item =>
    readSealedRun(item, { mode: 'platform', exact: true })
  );
  const installed = installedCatalog();
  const catalog = { catalog: installed.catalog, catalogSha256: installed.sha256 };
  // The catalog names and binds the record-pack profile; every reader of a pack uses exactly it.
  const packBinding = recordPackBindingProblems(installed.catalog);
  if (packBinding.length) fail(`Record packs: ${packBinding.join('; ')}`);
  const evidence = checkPlatformEvidence({ main: run, companions, current, now, catalog });
  if (
    record.candidateIdentitySha256 !== evidence.identity.sha256 ||
    canonicalJson(record.candidate ?? null) !== canonicalJson(evidence.identity.record)
  )
    fail('The run names another candidate identity than the candidate has (v3 C18)');
  const contract = evidence.judged.kind !== 'maintenance';
  // The catalog of v3 C23, for the profile the finalizer selected itself from the installed
  // catalog and the judged manifest (checkPlatformEvidence; never the run's host or its catalog
  // binding): exactly its stages, none missing, extra, repeated or renamed. Checked first, so a
  // stage that is not the catalog's is named as such.
  const profile = evidence.profile;
  if (contract) {
    // Membership only here: each stage's status is judged below and in the full judgment.
    const listed = {
      ...record,
      stages: record.stages.map(stage => ({ ...stage, status: 'pass' })),
    };
    const membership = catalogJudgment(listed, { ...catalog, mode: 'commit', profile });
    if (membership.verdict === 'fail')
      fail(`Catalog: ${membership.failed.slice(0, 10).join('; ')}`);
    // The v5 C23 order rules this run's records can show, on the stages' valid recorded
    // intervals: change 19 against both builds and every stage that executes candidate code, and
    // the T8 rules of change 18 (orderProblems, which names the rules that need records this draft
    // does not make). A stage's place in a catalog array orders nothing.
    const order = orderProblems(record, { prefix: 'full-tests-' });
    if (order.length) fail(`Order: ${order.slice(0, 10).join('; ')}`);
    // The stages whose record forms are pending (v5 C5, C17 item 12): none of them is ever a
    // pass, neither catalog build may have started while its pre-build authority is pending, and
    // nothing uses or scans a result whose record has no qualified producer (v5 C5 change 3; C3,
    // C23 local builds). The test stages' own image builds leave those stages pending
    // (testStageBuilds, through checkPlatformEvidence).
    for (const [name, why] of Object.entries(pendingRecordStages))
      if (record.stages.some(stage => stage?.name === name && stage.status === 'pass'))
        fail(
          `${name} is recorded as passed, but ${why}: no producer is qualified, so it is never a pass`
        );
    for (const name of [...candidateBuildStages, 'container-identity', ...builtImageStages]) {
      const stage = record.stages.find(item => item?.name === name);
      if (
        stage &&
        (stage.command !== undefined || stage.log !== undefined || stage.exit !== undefined)
      )
        fail(
          `${name} ran: no candidate-controlled build may start while its pre-build authority is pending, and nothing may use or scan a build result before its same-run record is sealed and verified (v5 C5 change 3, C23)`
        );
    }
  }
  const stages = new Map();
  const findings = [];
  const pending = [];
  // Scanner stages whose report and exit agree: a scan that completed, with or without findings
  // (its exit is then the finding exit, and the review must dispose of each finding).
  const scanned = new Set();
  // A maintenance (B35) run reaches this loop only once checkPlatformEvidence found every stage of
  // it in the approved B35 plan and of its class (maintenancePlanProblems; GDR7-FIN-01): an
  // executed stage the plan does not name, a command on a stage the plan records without one, a
  // member outside its class's record form or an execution nested in another stage's record (its
  // `steps`, say) is refused there, so a unique extra stage that ran and passed, or one hidden
  // inside a stage this loop accepts, is no longer accepted here.
  for (const stage of record.stages) {
    if (typeof stage.name !== 'string' || stages.has(stage.name))
      fail('Duplicate or invalid stage');
    stages.set(stage.name, stage);
    if (stage.status === 'pending') {
      // A stage this draft does not implement, or whose authority is pending: never a pass. It
      // needs a reason and runs nothing; only t8-image-identity may have run its read-only inspect
      // (pendingStageProblem, shared with the recorded-approval reader).
      if (!contract) fail(`A required stage is pending: ${stage.name}`);
      const pendingProblem = pendingStageProblem(run, stage);
      if (pendingProblem) fail(pendingProblem);
      continue;
    }
    if (stage.name === 'independent-review') continue; // Replaced only by a full exact-tree review below.
    if (stage.error || stage.signal) fail('A stage failed to execute');
    if (
      !requirementStages.has(stage.name) &&
      (!Array.isArray(stage.command) ||
        !stage.command.length ||
        !stage.command.every(value => typeof value === 'string' && value))
    )
      fail('Executable stage is missing its command');
    if (stage.command) {
      if (!safeName.test(stage.log)) fail('Missing stage log');
      const log = get(stage.log).toString('utf8');
      if (findingReports[stage.name]) {
        // The sealed scanner-result judgment, shared with the recorded-approval reader
        // (scannerResult; GDR8-AUTH-SCAN-01).
        findings.push(...scannerResult(run, stage, stages, log));
        scanned.add(stage.name);
      } else if (stage.status !== 'pass' || stage.exit !== 0)
        fail('A required stage remains blocked');
      if (stage.name.startsWith('full-tests-')) {
        if (JSON.stringify(testTotals(log)) !== JSON.stringify(stage.tests))
          fail('Test totals disagree');
      }
    } else if (stage.status !== 'pass' || findingReports[stage.name])
      fail('A required check remains blocked');
  }
  // Each stage is judged; now the scanners' stages and fixed reports are reconciled, as the
  // recorded-approval reader reconciles them (scannerReportProblems; GDR9-AUTH-SCAN-02): a report
  // beside a scanner that did not run, or with no scanner stage at all, refuses the run.
  const reconciled = scannerReportProblems(run);
  if (reconciled.length) fail(`Scanner reports: ${reconciled.slice(0, 3).join('; ')}`);
  // The gate identity, when the gate-identity stage carries one: version 3 with its eight parts
  // only, binding the installed catalog (v4 C1; GCV3-03); a passing stage must carry one. A
  // version 1 or 2 record, or any other form, fails: there is no fallback. A valid record still
  // leaves the stage pending here, because only F compares it with the Mac-side record (v4 C14).
  const gate = contract
    ? gateIdentityStage(stages.get('gate-identity'), { catalogSha256: catalog.catalogSha256 })
    : { problems: [], identity: null, binding: null };
  if (gate.problems.length) fail(`Gate identity: ${gate.problems.join('; ')}`);
  // F's reconciliation of the T8 image's records within image-approvals (v5 C14 change 5): O's
  // t8-image-activation binds exactly N's sealed T8 records of this run, under the same run,
  // candidate, gate identity, catalog, platform, consumer and purpose. Consistent still leaves it
  // pending: the binding's form is a proposal, and image-approvals is F's obligation on the Mac.
  if (contract) {
    const t8 = t8ActivationProblems(run, {
      manifest: evidence.judged.manifest,
      runId: profile,
      catalogSha256: catalog.catalogSha256,
    });
    if (t8.length) fail(`T8 reconciliation (image-approvals): ${t8.slice(0, 5).join('; ')}`);
  }
  const lintStages = current.lintStages === undefined ? [] : current.lintStages;
  if (!Array.isArray(lintStages) || !lintStages.every(name => lintStageNames.includes(name)))
    fail('Invalid lint stage requirement');
  let judgedCatalog = null;
  // The Actionlint stages that passed. A pass is checked against its sealed record below, but it
  // is never a pass here: only F can establish the qualified binding (ACTIONLINT_PIN; Codex
  // decision 8). The gate of this draft runs no Actionlint, so its runs hold neither.
  const actionlintPassed = ['actionlint-version', 'workflow-analysis'].filter(
    name => stages.get(name)?.status === 'pass'
  );
  if (contract) {
    // The same judgment, now with the stages the finalizer itself judged pending (the T8 image
    // authority, a recorded gate identity, a passing Actionlint): each stage passed or pending.
    const completed = {
      ...record,
      stages: record.stages.map(stage =>
        scanned.has(stage.name) ? { ...stage, status: 'pass' } : stage
      ),
    };
    judgedCatalog = catalogJudgment(completed, {
      ...catalog,
      mode: 'commit',
      profile,
      pendingStages: [
        ...evidence.pending.map(item => item.stage),
        ...(gate.identity ? ['gate-identity'] : []),
        ...actionlintPassed,
      ],
    });
    if (judgedCatalog.verdict === 'fail')
      fail(`Catalog: ${judgedCatalog.failed.slice(0, 10).join('; ')}`);
    const pinned = actionlintProblems(run, stages, gate.identity);
    if (pinned.length) fail(`Actionlint: ${pinned.join('; ')}`);
    for (const name of lintStages) if (!stages.has(name)) fail('A mandatory stage is missing');
    if (gate.identity)
      pending.push(
        'gate-identity: a version 3 gate identity is recorded, but only F compares it with the Mac-side record (v4 C1, C14)'
      );
    if (actionlintPassed.length) pending.push(`${ACTIONLINT_PIN}: ${actionlintPinReason}`);
  } else {
    // B35: the earlier gate's list, with no pending stage. It names test-host and runtime-identity
    // too (GDR6-REQ-01), whose evidence checkPlatformEvidence has already judged
    // (maintenanceRuntimeProblems, which refuses a run without them, naming why). The approved B35
    // plan says which stages this run must record (GDR7-FIN-01): requiredStages, the configured
    // Node 24 slot when the run's own Node is not Node 24, and the lint stages the caller names.
    for (const name of maintenanceRequiredStages(record, lintStages))
      if (!stages.has(name)) fail('A mandatory stage is missing');
    // GD-R2 holds on this branch too (verify-1 found that only candidates with a platform contract
    // were checked): actionlint-version and workflow-analysis must have passed (above), so the run
    // must show the pinned binary and the gate-owned configuration. A run whose workflow-analysis
    // ran a bare `actionlint` from PATH, as the earlier gate's did, is refused. Even a consistent
    // pin leaves the finalization pending: the qualified binding is F's (ACTIONLINT_PIN, in
    // inspectRun), so no maintenance finalization this module writes is a pass (Codex decision 8).
    const pinned = actionlintProblems(run, stages);
    if (pinned.length) fail(`Actionlint: ${pinned.join('; ')}`);
  }
  for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime'])
    if (stages.get(name)?.status === 'pass' && !stages.get(name).command)
      fail('Test execution evidence is missing');
  const database = stages.get('scanner-database');
  if (database?.status === 'pass' || !contract) {
    if (!database?.log) fail('Vulnerability database evidence is missing or stale');
    const databaseLog = get(database.log).toString('utf8');
    const values = json(Buffer.from(databaseLog.trim().split('\n').at(-1)));
    const updated = Date.parse(values.VulnerabilityDB?.UpdatedAt);
    const next = Date.parse(values.VulnerabilityDB?.NextUpdate);
    const downloaded = Date.parse(values.VulnerabilityDB?.DownloadedAt);
    if (
      values.Version !== record.tools.trivy ||
      !Number.isFinite(updated) ||
      !Number.isFinite(next) ||
      !Number.isFinite(downloaded) ||
      updated > finished ||
      downloaded > finished ||
      downloaded < updated ||
      next <= now ||
      next <= updated
    )
      fail('Vulnerability database evidence is missing or stale');
  }
  if (judgedCatalog) {
    for (const id of judgedCatalog.pending) pending.push(`${id} is pending`);
    for (const item of evidence.pending) pending.push(item.reason);
  }
  return {
    findings,
    platform: evidence.summary,
    identity: evidence.identity,
    contract,
    catalog: judgedCatalog && {
      catalogSha256: catalog.catalogSha256,
      profile: judgedCatalog.profile,
      verdict: [
        judgedCatalog,
        ...(evidence.summary?.companions ?? []).map(item => item.catalog),
      ].every(item => item.verdict === 'pass')
        ? 'pass'
        : 'pending',
      pending: judgedCatalog.pending,
    },
    companions: (evidence.summary?.companions ?? []).length > 0,
    gateIdentity: gate.binding,
    // A maintenance (B35) candidate's one F obligation: the qualified binding of its pinned
    // Actionlint, which this module cannot establish.
    maintenanceObligations: contract
      ? null
      : { [ACTIONLINT_PIN]: { status: 'pending', reason: actionlintPinReason } },
    pending,
  };
}

/**
 * The inventory of a run for the candidate `current` at `now`: what a review binds (schema 2: the
 * tree, the complete ordered parent vector, the candidate identity digest, the refs, tools and run
 * digests, the catalog for a candidate with a platform contract, and the platform evidence),
 * whether nothing local is wrong (`eligible`, with `blockers`), the findings, and the verdict a
 * finalization would have: `pass`, or `pending` with the reasons (`pending`, and the F
 * obligations, `obligations`: the catalog's for a candidate with a platform contract, and for
 * maintenance, B35, the qualified binding of its pinned Actionlint, ACTIONLINT_PIN). Every
 * eligible inventory is pending here: each kind of candidate has an F obligation this module
 * cannot pass.
 */
export function inspectRun(runDirectory, current, now = Date.now(), { reviewed = false } = {}) {
  const run = readRun(runDirectory);
  let checked;
  let findings;
  const blockers = [];
  try {
    checked = checkRun(run, current, now);
    findings = checked.findings;
  } catch (error) {
    blockers.push(error.message);
    findings = [];
    // A blocked dependency/test does not hide other reports awaiting review.
    for (const [stage, report] of Object.entries(findingReports)) {
      try {
        findings.push(
          ...reportFindings(stage, run.get(report), { tools: run.record.tools, files: run.files })
        );
      } catch {
        blockers.push(`Finding inventory unavailable: ${stage}`);
      }
    }
  }
  const catalog = checked?.catalog;
  const obligations =
    checked?.contract && catalog
      ? fObligations(installedCatalog().catalog, {
          catalogVerdict: catalog.verdict,
          companions: checked.companions,
          reviewed,
        })
      : (checked?.maintenanceObligations ?? undefined);
  const pending = [
    ...(checked?.pending ?? []),
    ...Object.entries(obligations ?? {})
      .filter(([, item]) => item.status !== 'pass')
      .map(([id, item]) => `F obligation ${id}: ${item.reason}`),
  ];
  return {
    schemaVersion: APPROVAL_SCHEMA,
    tree: run.record.tree,
    parents: run.record.parents,
    candidateIdentitySha256: run.record.candidateIdentitySha256,
    refsSha256: sha256(run.record.refs),
    toolsSha256: sha256(JSON.stringify(run.record.tools)),
    runSha256: run.runSha256,
    ...(catalog ? { catalogSha256: catalog.catalogSha256, profile: catalog.profile } : {}),
    // The gate identity the run records, bound with its version (v4 C1; GCV3-03), or null.
    ...(catalog ? { gateIdentity: checked?.gateIdentity ?? null } : {}),
    // Only for a candidate with a platform contract: the runs and totals the approval binds, each
    // run's own (never added together), and the sha256 the review must name.
    ...(checked?.platform
      ? { platform: checked.platform, platformSha256: sha256(JSON.stringify(checked.platform)) }
      : {}),
    eligible: blockers.length === 0,
    blockers,
    verdict: blockers.length === 0 && !pending.length ? 'pass' : 'pending',
    pending,
    ...(obligations ? { obligations } : {}),
    findings,
  };
}

// What a review must name exactly as the inventory does.
const reviewBinding = [
  'schemaVersion',
  'tree',
  'candidateIdentitySha256',
  'refsSha256',
  'toolsSha256',
  'runSha256',
];

function evaluateReview(run, review, current, now, evidenceDirectory) {
  const inventory = inspectRun(run.root, current, now, { reviewed: true });
  if (!inventory.eligible) fail(inventory.blockers[0]);
  for (const name of reviewBinding)
    if (review[name] !== inventory[name]) fail('Review is not bound to this exact run');
  if (!sameParents(review.parents, inventory.parents))
    fail('Review is not bound to this exact complete parent vector');
  // The catalog, the companion runs and the platform coverage are part of what the reviewer approves.
  if (inventory.catalogSha256 !== undefined && review.catalogSha256 !== inventory.catalogSha256)
    fail('Review is not bound to this exact catalog');
  if (inventory.platformSha256 !== undefined && review.platformSha256 !== inventory.platformSha256)
    fail('Review is not bound to this exact platform evidence');
  checkReview(review, { tree: current.tree, parents: current.parents, files: run.files });
  const reviewed = Date.parse(review.reviewedAt),
    expires = Date.parse(review.expiresAt);
  if (
    !Number.isFinite(reviewed) ||
    !Number.isFinite(expires) ||
    reviewed < Date.parse(run.record.finished) ||
    reviewed > now ||
    expires <= now ||
    expires < reviewed
  )
    fail('Review is stale or has invalid timestamps');
  checkDispositions(review.dispositions, inventory.findings, evidenceDirectory);
  return inventory;
}

/**
 * Finalizes a run after its independent review: writes, in a new `finalization` folder beside the
 * raw evidence, the review and the finalization record (approval.json, schema 2). Its status is
 * `pass` only when nothing is pending: for a candidate with a platform contract that needs every F
 * obligation of the catalog, and for maintenance (B35) the qualified binding of its pinned
 * Actionlint (ACTIONLINT_PIN), which only F can establish, so this module's finalization is
 * `pending`, and the commit guard does not accept it.
 */
export function finalizeRun(runDirectory, reviewFile, current, now = Date.now()) {
  const run = readRun(runDirectory);
  // A companion run must sit beside the run, under the name the gate gives it, so that the commit
  // guard can read it again from the name the finalization records.
  for (const item of current.companions ?? [])
    if (
      path.dirname(directory(item)) !== path.dirname(run.root) ||
      !companionName.test(path.basename(item))
    )
      fail(
        'A companion run must be a <tree>-platform-<id> folder beside the run, in the same orbit-security folder'
      );
  const reviewBytes = readEvidence(reviewFile);
  const review = strictRecord(reviewBytes, 'the review');
  const inventory = evaluateReview(run, review, current, now);
  const approval = {
    schemaVersion: APPROVAL_SCHEMA,
    status: inventory.verdict,
    mode: 'commit',
    tree: current.tree,
    parents: [...current.parents],
    candidateIdentitySha256: inventory.candidateIdentitySha256,
    refs: current.refs,
    runSha256: run.runSha256,
    reviewSha256: sha256(reviewBytes),
    finalizedAt: new Date(now).toISOString(),
    findings: inventory.findings.length,
    ...(inventory.catalogSha256 !== undefined
      ? {
          catalogSha256: inventory.catalogSha256,
          profile: inventory.profile,
          ...(inventory.gateIdentity ? { gateIdentity: inventory.gateIdentity } : {}),
          obligations: Object.fromEntries(
            Object.entries(inventory.obligations).map(([id, item]) => [id, item.status])
          ),
        }
      : {
          // Maintenance (B35): its one F obligation, the qualified binding of its pinned
          // Actionlint, which this module leaves pending (Codex decision 8).
          obligations: Object.fromEntries(
            Object.entries(inventory.obligations ?? {}).map(([id, item]) => [id, item.status])
          ),
        }),
    ...(inventory.pending.length ? { pending: inventory.pending } : {}),
    ...(inventory.platform
      ? { platform: inventory.platform, platformSha256: inventory.platformSha256 }
      : {}),
  };
  // A new, atomic directory publishes review and decision together; raw files stay untouched.
  const temporary = fs.mkdtempSync(path.join(run.root, '.finalization-'));
  try {
    fs.writeFileSync(path.join(temporary, 'review.json'), reviewBytes, { flag: 'wx', mode: 0o600 });
    for (const item of review.dispositions) {
      const bytes = readEvidence(item.evidenceFile);
      if (sha256(bytes) !== item.evidenceSha256) fail('Disposition evidence changed');
      const file = path.join(temporary, `${item.evidenceSha256}.evidence`);
      if (!fs.existsSync(file)) fs.writeFileSync(file, bytes, { flag: 'wx', mode: 0o600 });
    }
    writeNew(path.join(temporary, 'approval.json'), approval);
    fs.renameSync(temporary, path.join(run.root, 'finalization'));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  return approval;
}

/**
 * The commit guard's check of a finalization for the candidate `current` at `now`: a schema 2
 * record (schema 1, bound to a single parent, gives no authority), status `pass`, bound to the
 * tree, the complete ordered parent vector in order, the candidate identity, the refs, the run and
 * the review, and with every F obligation passed: the catalog's, bound to the installed catalog,
 * for a candidate with a platform contract, and for maintenance (B35) the qualified binding of
 * its pinned Actionlint (ACTIONLINT_PIN). Everything this module can check is checked again now
 * from the sealed evidence; what is pending here is F's to establish, and only F writes a `pass`
 * that rests on it. Like every record here, an approval is a local file: these are consistency
 * checks, not authentication of who wrote it. Returns the approval, or throws.
 */
export function validateFinalization(runDirectory, current, now = Date.now()) {
  const run = readRun(runDirectory);
  const finalized = directory(path.join(run.root, 'finalization'));
  const approval = strictRecord(
    readEvidence(path.join(finalized, 'approval.json')),
    'approval.json'
  );
  if (approval.schemaVersion !== APPROVAL_SCHEMA)
    fail(
      'Finalization is not schema 2: an approval bound to a single parent gives no authority (COORDINATOR-DECISIONS "C18 legacy approvals")'
    );
  if (approval.status !== 'pass')
    fail(
      `Finalization is ${JSON.stringify(approval.status)}, not pass${Array.isArray(approval.pending) ? `: ${approval.pending.slice(0, 5).join('; ')}` : ''}`
    );
  const reviewBytes = readEvidence(path.join(finalized, 'review.json'));
  // The companion runs the approval names, read again from the same orbit-security folder and
  // checked again now: a stale, changed or missing companion no longer approves.
  let companions = [];
  if (current.platform !== undefined && approval.platform !== undefined) {
    if (
      !Array.isArray(approval.platform?.companions) ||
      !approval.platform.companions.every(item => companionName.test(item?.directory ?? ''))
    )
      fail('Finalization does not match the reviewed evidence');
    companions = approval.platform.companions.map(item =>
      path.join(path.dirname(run.root), item.directory)
    );
  }
  const inventory = evaluateReview(
    run,
    strictRecord(reviewBytes, 'review.json'),
    { ...current, companions },
    now,
    finalized
  );
  if (
    current.platform !== undefined &&
    (JSON.stringify(approval.platform) !== JSON.stringify(inventory.platform) ||
      approval.platformSha256 !== inventory.platformSha256)
  )
    fail('Finalization does not match the reviewed platform evidence');
  if (
    approval.mode !== 'commit' ||
    approval.tree !== current.tree ||
    !sameParents(approval.parents, current.parents) ||
    approval.candidateIdentitySha256 !== inventory.candidateIdentitySha256 ||
    approval.refs !== current.refs ||
    approval.runSha256 !== run.runSha256 ||
    approval.reviewSha256 !== sha256(reviewBytes) ||
    approval.findings !== inventory.findings.length ||
    !Number.isFinite(Date.parse(approval.finalizedAt)) ||
    Date.parse(approval.finalizedAt) > now
  )
    fail('Finalization does not match the reviewed evidence or the complete candidate identity');
  if (inventory.catalogSha256 !== undefined) {
    const commit = installedCatalog().catalog.finalization.commit;
    // A passing approval binds the gate identity as { sha256, version: 3 }, the one its run
    // records: a version 1 or 2 binding, a missing one or another one gives no authority.
    let gateIdentity;
    try {
      gateIdentity = parseGateIdentityBinding(approval.gateIdentity);
    } catch (error) {
      fail(`Finalization does not bind a version 3 gate identity: ${error.message}`);
    }
    if (
      !inventory.gateIdentity ||
      gateIdentity.sha256 !== inventory.gateIdentity.sha256 ||
      gateIdentity.version !== inventory.gateIdentity.version
    )
      fail('Finalization does not bind the gate identity its run records (v4 C1, C12, C14)');
    if (
      approval.catalogSha256 !== inventory.catalogSha256 ||
      approval.profile !== inventory.profile ||
      typeof approval.obligations !== 'object' ||
      approval.obligations === null ||
      Object.keys(approval.obligations).sort().join('\n') !== [...commit].sort().join('\n') ||
      !commit.every(id => approval.obligations[id] === 'pass')
    )
      fail(
        'Finalization does not bind the installed catalog with every F obligation passed (v3 C14, C23)'
      );
  } else {
    // Maintenance (B35): no catalog or gate identity binding, and exactly its F obligation, the
    // qualified binding of its pinned Actionlint, passed (Codex decision 8). Only F can write that
    // pass; this module's own finalization leaves it pending. Nothing else may be pending here.
    const localPending = Object.values(inventory.obligations ?? {}).filter(
      item => item.status !== 'pass'
    ).length;
    if (
      approval.catalogSha256 !== undefined ||
      approval.gateIdentity !== undefined ||
      !isRecord(approval.obligations) ||
      Object.keys(approval.obligations).sort().join('\n') !==
        [...maintenanceObligations].sort().join('\n') ||
      !maintenanceObligations.every(id => approval.obligations[id] === 'pass') ||
      Object.keys(inventory.obligations ?? {})
        .sort()
        .join('\n') !== [...maintenanceObligations].sort().join('\n') ||
      inventory.pending.length !== localPending
    )
      fail(
        'Finalization does not match the reviewed evidence: a maintenance (B35) finalization needs its pinned Actionlint bound by the qualified golden-tool manifest, an obligation only F can pass (actionlint-pin; Codex decision 8)'
      );
  }
  return approval;
}

/**
 * The gate identity binding of a sealed run's gate-identity stage, for the readers of an approval
 * once its commit exists: { sha256, version: 3 }, or throws when the stage carries no valid
 * version 3 record of the installed catalog (v4 C1; GCV3-03).
 */
function sealedGateIdentity(run, catalogSha256) {
  const stage = Array.isArray(run.record.stages)
    ? run.record.stages.find(item => item?.name === 'gate-identity')
    : undefined;
  const gate = gateIdentityStage(stage, { catalogSha256 });
  if (gate.problems.length || !gate.binding)
    fail(
      `The run records no version 3 gate identity for this approval: ${gate.problems.join('; ') || 'none is recorded'}`
    );
  return gate.binding;
}

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The class of each stage of the approved B35 plan (MAINTENANCE_PLAN), by name. */
const maintenanceClasses = new Map(MAINTENANCE_PLAN.map(entry => [entry.name, entry.execution]));

/**
 * Problems with the stage results of the sealed maintenance (B35) run `run`: the results checkRun
 * requires of a maintenance run that read only the sealed run, for the recorded-approval reader
 * (the internal check of gate-draft-r8 found that it accepted a recorded pass of a run whose test
 * stage was withheld or failed, which the finalizer refuses). A B35 run has no pending stage, a
 * withheld one included; no stage failed to execute (an error or a signal); each stage the plan
 * classes as a gate-owned command, a lint stage or a test slot carries its command and its sealed
 * log; each stage other than a scanner and independent-review passed, with exit 0 once it ran a
 * command; a scanner exited 0 or with its finding exit; and a test slot's totals are those of its
 * sealed log. Each scanner's report, findings, exit and status are judged by the finalizer's own
 * sealed scanner-result judgment (scannerResult, through sealedScannerFindings in
 * recordedApproval; GDR8-AUTH-SCAN-01), and the derived findings are bound to the approval and the
 * retained review's dispositions there. Not judged again here: what depends on the candidate or
 * the moment (its files, the tool configuration, the pinned Actionlint, the vulnerability
 * database's freshness, the review's expiry), which the commit guard checked before the commit was
 * made. Returns the problems.
 */
function maintenanceStatusProblems(run) {
  const problems = [];
  for (const stage of Array.isArray(run.record?.stages) ? run.record.stages : []) {
    // A stage record without a name is the plan check's (maintenancePlanProblems).
    if (!isRecord(stage) || typeof stage.name !== 'string') continue;
    const { name } = stage;
    if (stage.status === 'pending') {
      problems.push(`${name} is pending: a maintenance (B35) run has no pending stage`);
      continue;
    }
    // Replaced only by a full exact-tree review (checkRun), which the retained review is.
    if (name === 'independent-review') continue;
    if (stage.error || stage.signal) {
      problems.push(`${name} failed to execute`);
      continue;
    }
    const execution = maintenanceClasses.get(name);
    const command =
      Array.isArray(stage.command) &&
      stage.command.length > 0 &&
      stage.command.every(value => typeof value === 'string' && value);
    if (execution !== undefined && execution !== 'record' && !command) {
      problems.push(`${name} is an executable stage of the approved B35 plan without its command`);
      continue;
    }
    if (stage.command !== undefined && (!safeName.test(stage.log ?? '') || !run.has(stage.log))) {
      problems.push(`${name} ran a command without a sealed log`);
      continue;
    }
    if (findingReports[name]) {
      // The report, its findings and the status are sealedScannerFindings' (GDR8-AUTH-SCAN-01).
      const findingExit = findingExitOf(name);
      if (!command || ![0, findingExit].includes(stage.exit))
        problems.push(
          `${name} exited ${JSON.stringify(stage.exit)}, neither 0 nor its finding exit ${findingExit}`
        );
      continue;
    }
    if (stage.status !== 'pass' || (stage.command !== undefined && stage.exit !== 0)) {
      problems.push(
        `${name} did not pass: its status is ${JSON.stringify(stage.status)}${stage.command !== undefined ? ` and its exit ${JSON.stringify(stage.exit)}` : ''}`
      );
      continue;
    }
    if (execution === 'test') {
      let totals;
      try {
        totals = testTotals(run.get(stage.log).toString('utf8'));
      } catch (error) {
        problems.push(`${name}: its sealed log gives no test totals (${error.message})`);
        continue;
      }
      if (JSON.stringify(totals) !== JSON.stringify(stage.tests))
        problems.push(`${name}'s test totals are not those of its sealed log`);
    }
  }
  return problems;
}

/**
 * Problems with the sealed coverage dispositions of the maintenance (B35) run `run`, as the
 * finalizer reads them (checkPlatformEvidence) for the recorded-approval reader: a sealed
 * coverage-dispositions.json must be the reviewed dispositions file, bound to the run's tree and
 * complete ordered parent vector (parseCoverageDispositions), and since the history of a
 * maintenance candidate never held the platform manifest, nothing can be lost, so it may hold no
 * disposition (judgeCandidateManifest). One named example of the reader's parity with the finalizer
 * (check-1 of gate-draft-r9, SCHEMA-INFO2), not broad parity. Returns the problems.
 */
function maintenanceCoverageProblems(run) {
  if (!run.has('coverage-dispositions.json')) return [];
  let dispositions;
  try {
    dispositions = parseCoverageDispositions(run.get('coverage-dispositions.json'), {
      tree: run.record.tree,
      parents: run.record.parents,
    });
  } catch (error) {
    return [error.message];
  }
  return dispositions.length
    ? [
        `the coverage dispositions file gives ${dispositions.length} disposition${dispositions.length === 1 ? '' : 's'}, but no commit behind a maintenance candidate holds a manifest: nothing can be lost`,
      ]
    : [];
}

/**
 * A finalization read again once its commit exists (v3 C13, C18; the check behind
 * `check-security-approval.mjs --verify-commit` and the commit guard's reference-transaction hook):
 * everything in it that does not depend on the moment the commit was made, checked again from the
 * sealed evidence. It must be schema 2 with status `pass`, bound to its sealed run (tree, complete
 * ordered parent vector, candidate identity and the identity record behind that digest, refs) and
 * to its retained review (the same run, tree, vector, identity, refs and tools, and each finding's
 * retained evidence). A finalization with a catalog binding must name the installed catalog, a
 * profile and exactly the catalog's F obligations, each passed, with the reviewed platform
 * evidence and companion runs that still verify as sealed; only a candidate whose manifest path is
 * valid has one. A finalization without one approves only a candidate whose history never held the
 * platform manifest (B35), binds no profile or platform evidence, and has exactly its one F
 * obligation passed (ACTIONLINT_PIN; Codex decision 8), and its sealed run must still meet the
 * current B35 rules that do not depend on the moment: the approved plan with its record forms and
 * their closed nested schemas (GDR8-SCHEMA-01), the stages it requires always, of the run's Node
 * and of the commit's lint requirement, and the host and runtime evidence validateFinalization
 * requires (maintenanceEvidenceProblems; GDR7-AUTH-01), the stage results the finalizer requires
 * (maintenanceStatusProblems) and its sealed coverage dispositions as the finalizer reads them
 * (maintenanceCoverageProblems), since this reader is what gives a recorded approval authority over
 * a new commit or reference update. For every approval, the scanners' stages and fixed reports
 * are reconciled first, as the finalizer reconciles them (scannerReportProblems; GDR9-AUTH-SCAN-02:
 * no report beside a scanner recorded as pending, none without a scanner stage), and each scanner
 * stage that ran is judged again by the finalizer's own sealed scanner-result judgment
 * (scannerResult): its fixed report
 * sealed and parsed, its findings derived from it, and report, findings, exit and status in
 * agreement; a scanner stage recorded as pending must be one by the finalizer's own rule
 * (pendingStageProblem: a reason, and nothing run); and that derived finding set, never the
 * approval's claimed count, must be what the
 * approval counts and what the retained review disposes of, one disposition each with its retained
 * evidence (GDR8-AUTH-SCAN-01). `lintStages` is required, with no default (GDR8-AUTH-LINT-01): the
 * lint stages the commit requires, which verifyCommit derives from the exact commit, its complete
 * ordered parents and their history; each must be recorded in the sealed run, and passed. An
 * approval recorded under earlier rules for a run they now refuse gives none; its evidence is kept
 * as it is. Not asked again: freshness (the commit guard checked it before the commit was made,
 * and a check after the commit cannot) and what maintenanceStatusProblems leaves to the guard; for
 * a finalization with a catalog binding, the stage results and the catalog judgment beyond the
 * scanner results and the lint stages (broad finalizer and authority-reader parity is not claimed).
 * Like every record here, this is a local consistency check, not authentication of who wrote it.
 * Returns { approval, approvalSha256 }, or throws.
 */
export function recordedApproval(runDirectory, { lintStages } = {}) {
  if (
    !Array.isArray(lintStages) ||
    !lintStages.every(name => lintStageNames.includes(name)) ||
    new Set(lintStages).size !== lintStages.length
  )
    fail(
      'The recorded-approval reader needs the lint stages the commit requires, derived from the exact commit and its parents (GDR8-AUTH-LINT-01): none is assumed'
    );
  const run = readRun(runDirectory);
  const finalized = directory(path.join(run.root, 'finalization'));
  const approvalBytes = readEvidence(path.join(finalized, 'approval.json'));
  const approval = strictRecord(approvalBytes, 'approval.json');
  const reviewBytes = readEvidence(path.join(finalized, 'review.json'));
  const review = strictRecord(reviewBytes, 'review.json');
  const { record } = run;
  if (!isRecord(approval) || approval.schemaVersion !== APPROVAL_SCHEMA)
    fail(
      'Finalization is not schema 2: an approval bound to a single parent gives no authority (COORDINATOR-DECISIONS "C18 legacy approvals")'
    );
  if (approval.status !== 'pass' || approval.mode !== 'commit' || approval.pending !== undefined)
    fail(`Finalization is ${JSON.stringify(approval.status)}, not a commit pass`);
  if (parentVectorProblems(approval.parents).length)
    fail('Finalization does not bind a complete ordered parent vector');
  if (
    record.tree !== approval.tree ||
    !sameParents(record.parents, approval.parents) ||
    record.candidateIdentitySha256 !== approval.candidateIdentitySha256 ||
    approval.runSha256 !== run.runSha256 ||
    approval.reviewSha256 !== sha256(reviewBytes) ||
    typeof record.refs !== 'string' ||
    approval.refs !== record.refs ||
    !Number.isSafeInteger(approval.findings) ||
    !Number.isFinite(Date.parse(approval.finalizedAt))
  )
    fail('Finalization does not match its sealed run or its retained review');
  const identity = record.candidate;
  if (
    !isRecord(identity) ||
    sha256(canonicalJson(identity)) !== record.candidateIdentitySha256 ||
    identity.tree !== approval.tree ||
    !sameParents(identity.parents, approval.parents)
  )
    fail("The run's candidate identity record does not give the identity it names (v3 C18)");
  if (
    !isRecord(review) ||
    review.schemaVersion !== APPROVAL_SCHEMA ||
    review.tree !== approval.tree ||
    !sameParents(review.parents, approval.parents) ||
    review.candidateIdentitySha256 !== approval.candidateIdentitySha256 ||
    review.runSha256 !== approval.runSha256 ||
    review.refsSha256 !== sha256(record.refs) ||
    review.toolsSha256 !== sha256(JSON.stringify(record.tools)) ||
    !Array.isArray(review.dispositions) ||
    review.dispositions.length !== approval.findings
  )
    fail('The retained review is not bound to this exact run');
  for (const item of review.dispositions)
    if (
      !digest.test(item?.evidenceSha256 ?? '') ||
      sha256(readEvidence(path.join(finalized, `${item.evidenceSha256}.evidence`))) !==
        item.evidenceSha256
    )
      fail('A disposition has no retained evidence with its digest');
  // The finalizer's sealed scanner-result judgment, again (GDR8-AUTH-SCAN-01): the findings come
  // from the sealed reports, never from the approval's or the review's count.
  const scanned = sealedScannerFindings(run);
  const state = identity.platformManifest?.state;
  if (approval.catalogSha256 === undefined) {
    if (
      state !== 'never-held' ||
      ['profile', 'platform', 'platformSha256', 'gateIdentity'].some(
        key => approval[key] !== undefined
      ) ||
      !isRecord(approval.obligations) ||
      Object.keys(approval.obligations).sort().join('\n') !==
        [...maintenanceObligations].sort().join('\n') ||
      !maintenanceObligations.every(id => approval.obligations[id] === 'pass') ||
      review.catalogSha256 !== undefined ||
      review.platformSha256 !== undefined
    )
      fail(
        'A finalization without a catalog binding approves only a candidate whose history never held the platform manifest (B35), binds no platform evidence, and has exactly its one F obligation passed: the qualified binding of its pinned Actionlint (actionlint-pin; Codex decision 8)'
      );
    // The current B35 rules, applied again now that this approval would give authority to a new
    // commit or reference update (GDR7-AUTH-01; Codex decision 2 of 20261018T051017695655Z): the
    // same moment-independent checks of the approved plan and of the host and runtime evidence
    // that validateFinalization applies (maintenanceEvidenceProblems). An approval recorded under
    // earlier rules, of a run they refuse (a legacy run without test-host or runtime-identity, an
    // unidentified, duplicate, stale or inapplicable identity, an execution outside the plan or
    // nested in another stage's record), gives no authority now, and neither does one of a run
    // whose stage results the finalizer refuses (maintenanceStatusProblems: a withheld or failed
    // test stage, say), or whose scanner results it refuses (a report that is missing, does not
    // parse, or disagrees with its exit or status; GDR8-AUTH-SCAN-01), or whose sealed coverage
    // dispositions it refuses (check-1 of gate-draft-r9). Its raw evidence stays as
    // it is: nothing here rewrites or removes it. The lint stages are those the commit requires,
    // which verifyCommit derives from the exact commit and its parents' history
    // (GDR8-AUTH-LINT-01), passed in by the caller and never defaulted.
    const refused = [
      ...maintenanceEvidenceProblems(run, { lintStages }),
      ...maintenanceStatusProblems(run).map(item => `stage results: ${item}`),
      ...scanned.problems.map(item => `scanner results: ${item}`),
      ...maintenanceCoverageProblems(run).map(item => `coverage dispositions: ${item}`),
    ];
    if (refused.length)
      fail(
        `The recorded maintenance (B35) approval is of a run the current B35 rules refuse, so it gives no authority now (GDR7-AUTH-01): ${refused.slice(0, 10).join('; ')}`
      );
  } else {
    const installed = installedCatalog();
    const commit = installed.catalog.finalization.commit;
    if (
      state !== 'valid' ||
      approval.catalogSha256 !== installed.sha256 ||
      review.catalogSha256 !== approval.catalogSha256 ||
      record.catalog?.sha256 !== installed.sha256 ||
      record.catalog?.mode !== 'commit' ||
      typeof approval.profile !== 'string' ||
      !isRecord(approval.obligations) ||
      Object.keys(approval.obligations).sort().join('\n') !== [...commit].sort().join('\n') ||
      !commit.every(id => approval.obligations[id] === 'pass')
    )
      fail(
        'Finalization does not bind the installed catalog with every F obligation passed (v3 C14, C23)'
      );
    // The gate identity, as { sha256, version: 3 }, equal to the one the sealed run records.
    let gateIdentity;
    try {
      gateIdentity = parseGateIdentityBinding(approval.gateIdentity);
    } catch (error) {
      fail(`Finalization does not bind a version 3 gate identity: ${error.message}`);
    }
    const sealed = sealedGateIdentity(run, installed.sha256);
    if (gateIdentity.sha256 !== sealed.sha256 || gateIdentity.version !== sealed.version)
      fail('Finalization does not bind the gate identity its run records (v4 C1, C12, C14)');
    if (
      !isRecord(approval.platform) ||
      approval.platform.manifestSha256 !== identity.platformManifest.sha256 ||
      record.platform?.manifestSha256 !== approval.platform.manifestSha256 ||
      approval.platformSha256 !== sha256(JSON.stringify(approval.platform)) ||
      review.platformSha256 !== approval.platformSha256 ||
      !Array.isArray(approval.platform.companions)
    )
      fail('Finalization does not match the reviewed platform evidence');
    // The record-pack entry profile its packs were read with must be this reader's own, and the
    // one the installed catalog binds (Codex decision 3; v5 C21, C24).
    if (
      canonicalJson(approval.platform.recordPack ?? null) !== canonicalJson(recordPackIdentity()) ||
      recordPackBindingProblems(installed.catalog).length
    )
      fail(
        'Finalization binds another record-pack entry profile than the installed validator and catalog (Codex decision 3; v5 C21, C24)'
      );
    for (const item of approval.platform.companions) {
      if (!companionName.test(item?.directory ?? '') || !digest.test(item?.runSha256 ?? ''))
        fail('Finalization does not match the reviewed platform evidence');
      const companion = readSealedRun(path.join(path.dirname(run.root), item.directory), {
        mode: 'platform',
        exact: true,
      });
      if (companion.runSha256 !== item.runSha256)
        fail(`The companion run ${item.directory} changed after it was finalized`);
    }
    // The sealed scanner results (GDR8-AUTH-SCAN-01) and the lint stages the commit requires
    // (GDR8-AUTH-LINT-01), as the finalizer judges them: each required lint stage recorded once,
    // and passed, since a pending one leaves the catalog pending and so no F pass.
    if (scanned.problems.length)
      fail(
        `The recorded approval's sealed scanner results are not those the finalizer accepts, so it gives no authority (GDR8-AUTH-SCAN-01): ${scanned.problems.slice(0, 10).join('; ')}`
      );
    for (const name of lintStages) {
      const named = record.stages.filter(stage => isRecord(stage) && stage.name === name);
      if (named.length !== 1 || named[0].status !== 'pass')
        fail(
          `The commit requires the lint stage ${name}, which its sealed run does not record once as passed, so the recorded approval gives no authority (GDR8-AUTH-LINT-01)`
        );
    }
  }
  // The derived finding set, bound to the approval and to the retained review's dispositions
  // (GDR8-AUTH-SCAN-01): the count the approval and the review claim must be the one the sealed
  // reports give, and each finding needs exactly one disposition with its retained evidence.
  if (approval.findings !== scanned.findings.length)
    fail(
      `The recorded approval counts ${approval.findings} finding${approval.findings === 1 ? '' : 's'}, but its sealed scanner reports give ${scanned.findings.length}, so it gives no authority (GDR8-AUTH-SCAN-01)`
    );
  try {
    checkDispositions(review.dispositions, scanned.findings, finalized);
  } catch (error) {
    fail(
      `The retained review does not dispose of exactly the findings the sealed scanner reports give, so the recorded approval gives no authority (GDR8-AUTH-SCAN-01): ${error.message}`
    );
  }
  return { approval, approvalSha256: sha256(approvalBytes) };
}

/**
 * The commits verified finalizations approved, for the history judgeCandidateManifest() reads: a
 * Map identityKey(tree, complete ordered parents) -> { manifestSha256, tree, parents }, the
 * sha256 of the manifest that finalization's platform check judged and the identity it approved.
 * Only the finalizations of candidates named in `keys` are read. One counts when it is schema 2
 * with status pass and every F obligation passed, its sealed run still hashes as sealed, its
 * approval and retained review name that run, tree, complete parent vector, candidate identity
 * and platform evidence, and it recorded a judged manifest. A single-parent (schema 1)
 * finalization never counts (C18). Freshness is not asked again (a commit is approved once, when
 * it is made). Two that disagree about one candidate count as neither. The caller checks each
 * commit it marks again from the commit's own object (committedIdentityProblems). Like every
 * record here, this is a local consistency check, not authentication of who wrote it.
 */
export function approvedManifests(securityDirectory, keys) {
  const found = new Map();
  const conflicting = new Set();
  let names = [];
  try {
    names = fs.readdirSync(securityDirectory);
  } catch {
    return found;
  }
  for (const name of names) {
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})-commit-/.test(name)) continue;
    try {
      const root = path.join(securityDirectory, name);
      const finalized = path.join(root, 'finalization');
      const approval = strictRecord(
        readEvidence(path.join(finalized, 'approval.json')),
        'approval.json'
      );
      if (
        approval.schemaVersion !== APPROVAL_SCHEMA ||
        approval.status !== 'pass' ||
        approval.mode !== 'commit' ||
        parentVectorProblems(approval.parents).length
      )
        continue;
      const key = identityKey(approval.tree, approval.parents);
      const manifestSha256 = approval.platform?.manifestSha256;
      if (!keys.has(key) || typeof manifestSha256 !== 'string' || !digest.test(manifestSha256))
        continue;
      const obligations = installedCatalog().catalog.finalization.commit;
      const run = readRun(root);
      const reviewBytes = readEvidence(path.join(finalized, 'review.json'));
      if (
        approval.runSha256 !== run.runSha256 ||
        approval.reviewSha256 !== sha256(reviewBytes) ||
        run.record.tree !== approval.tree ||
        !sameParents(run.record.parents, approval.parents) ||
        run.record.candidateIdentitySha256 !== approval.candidateIdentitySha256 ||
        run.record.platform?.manifestSha256 !== manifestSha256 ||
        approval.platformSha256 !== sha256(JSON.stringify(approval.platform)) ||
        strictRecord(reviewBytes, 'review.json').platformSha256 !== approval.platformSha256 ||
        approval.catalogSha256 !== installedCatalog().sha256 ||
        !obligations.every(id => approval.obligations?.[id] === 'pass')
      )
        continue;
      // Only a version 3 gate identity binding, the one the sealed run records, counts.
      const gateIdentity = parseGateIdentityBinding(approval.gateIdentity);
      const sealed = sealedGateIdentity(run, installedCatalog().sha256);
      if (gateIdentity.sha256 !== sealed.sha256) continue;
      if (found.has(key) && found.get(key).manifestSha256 !== manifestSha256) conflicting.add(key);
      found.set(key, { manifestSha256, tree: approval.tree, parents: [...approval.parents] });
    } catch {
      // Not a verified finalization: it approves nothing.
    }
  }
  for (const key of conflicting) found.delete(key);
  return found;
}

/**
 * The inputs of the platform judgment for the staged tree `tree` of the repository at `root`, as
 * checkPlatformEvidence() takes them in `current.platform`: the candidate's manifest bytes (or
 * null), its parents (`parents`, from candidateParents) and every commit behind them, each with
 * its manifest bytes, marked reviewed where a verified finalization approved exactly its tree and
 * complete parent vector and its own commit object, read again, still shows that identity (v3 C18).
 * Git runs with grafts, replace refs and the commit-graph turned off (hardenGitHistory),
 * whatever the caller's environment says, and a shallow repository or an info/grafts file is
 * refused: each could hide a commit that deleted or weakened the manifest. `refused` lists why the
 * parents Git could show for the candidate's parents or a reviewed commit would differ from their
 * objects (a replace ref or a commit-graph that disagrees): each refuses the candidate. Every read
 * goes through the runner bound to the repository at `root` (bindRepository; GDR9-AUTH-ROOT-01;
 * `binding` is the caller's, when it has one), with no lazy fetch (GDR9-AUTH-OBJECT-01).
 */
export function platformInputs(root, tree, parents, { binding } = {}) {
  const bound = binding ?? bindRepository(root);
  const git = (args, input) => bound.run(args, input, { maxBuffer: 1024 ** 3 });
  // The same Git, with the commit-graph on, to compare its parents with the objects' own.
  const graphGit = (args, input) =>
    bound.run(args, input, { maxBuffer: 1024 ** 3, config: "'core.commitgraph=true'" });
  const common = bound.commonDir;
  const rewritten = historyRewriteProblems(git, common);
  if (rewritten.length) fail(`The history cannot be judged: ${rewritten.join('; ')}`);
  const candidate = manifestsAt(git, [tree]).get(tree);
  const nodes = readHistory(git, parents.heads);
  const approvals = approvedManifests(
    path.join(common, 'orbit-security'),
    new Set(
      nodes.filter(node => node.parents.length).map(node => identityKey(node.tree, node.parents))
    )
  );
  const refused = parents.complete
    ? parentAmbiguityProblems({ git, graphGit, commits: parents.heads })
    : [];
  const history = nodes.map(node => {
    const approved = node.parents.length
      ? approvals.get(identityKey(node.tree, node.parents))
      : undefined;
    if (!approved) return { ...node, reviewed: null };
    const problems = committedIdentityProblems({
      git,
      graphGit,
      commit: node.commit,
      intended: approved,
    });
    if (problems.length) {
      refused.push(...problems.map(item => `the approved commit ${node.commit}: ${item}`));
      return { ...node, reviewed: null };
    }
    return { ...node, reviewed: { manifestSha256: approved.manifestSha256 } };
  });
  return {
    candidate,
    heads: parents.heads,
    complete: parents.complete,
    reason: parents.reason,
    refused,
    history,
  };
}
