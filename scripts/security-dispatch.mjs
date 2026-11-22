// What the gate (scripts/security-gate.mjs) may start, decided before it starts it.
//
// The security review of gate-draft-r4 (GDR4-01, P1) found that a prerequisite the gate recorded as
// failed or pending did not stop what came after it: candidate-policy and platform-manifest were
// recorded, and the gate went on to run the candidate's lint sources, `npm ci` and later stages
// whatever their status. A record that says a check failed does not undo code that already ran.
// The maintainer's answers of 20261016T014104832374Z apply the same rule to every operation whose authority
// is missing: nothing is dispatched first and judged later (GATE-CONTRACT v5 C3, C4, C5, C6, C14).
//
// This module holds the two decisions the gate makes before it dispatches anything, and the table
// that says which decision each dispatched stage needs:
//
// - The pre-dispatch barrier (preDispatchBarrier): no candidate-controlled command (the lints, the
//   npm stages, the test stages, a candidate image build) and no dependencies-install starts unless
//   candidate-policy and platform-manifest have each completed in this run with status pass. A
//   prerequisite that is absent, recorded twice, malformed, stale (begun before this run began, or
//   ending after the decision) or not passed keeps the barrier closed.
// - Dispatch authority (decideAuthorities): an operation that needs a qualified external condition
//   (a host listener, an approved image, a reviewed Docker stage policy and endpoint, pre-build
//   authority for the builds the candidate's tests start) is dispatched only when that authority is
//   given. scripts/security-authority.mjs is its one source, and in this draft it gives none: no
//   producer of any of these authorities exists, so each such stage is withheld.
// - The test stages' own prerequisites (testStagePrerequisiteProblems; the security review's GD5-CARRY-01 on
//   gate-draft-r5, the maintainer's decision 3 of 20261017T061149194320Z, v5 C3): gate-draft-r5 recorded
//   test-host and runtime-identity before the test stages but did not consult them, so given an
//   authority a test stage started while either was blocked. A test stage now starts only once
//   each is recorded exactly once in this run, passed, ended by the decision and applies to it,
//   as the barrier judges its two prerequisites. That holds in a maintenance (B35) run too
//   (GDR6-REQ-01, the security review of gate-draft-r6, under the maintainer's B35 decision of
//   20261017T140102522864Z: B35 decides which candidates are judged as maintenance, not that a
//   runtime nobody identified may run): gate-draft-r6 let a maintenance run that recorded no
//   runtime-identity start its test stages on test-host alone, and nothing now does.
//
// A stage that is not dispatched is recorded as pending, with no command, and a reason that says it
// was withheld before dispatch and why; the run is then never a pass. A stage name with no rule in
// DISPATCH_RULES is never dispatched (dispatchDecision). These decisions are a scheduling barrier in
// the gate's own process: they stop the gate from starting the command. They do not contain a
// command the gate does start, or a client that bypasses the gate (a nested Docker client, a direct
// socket): that containment is the environmental prerequisite of v5 C5 (decision 7), still pending.
// The two lints are the candidate code the gate starts today with no authority (only the open
// barrier): they inherit the gate's environment, DOCKER_HOST and the Docker client on PATH among
// it, so they can reach a Docker client or the Docker endpoint themselves (verify-1 of
// gate-draft-r5).
import { isTime } from './security-platform.mjs';

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const show = value => JSON.stringify(value)?.slice(0, 120);

/** The prerequisites of every candidate-controlled dispatch (v5 C3, C4, change 19; maintainer note 014104 item 4). */
export const PRE_DISPATCH_PREREQUISITES = Object.freeze(['candidate-policy', 'platform-manifest']);
const STAGE_STATUSES = new Set(['pass', 'fail', 'blocked', 'pending', 'not-run']);

/**
 * The pre-dispatch barrier of a run, decided once, after its prerequisites and before the first
 * candidate-controlled dispatch. `stages` is the run's stage records as the gate holds them,
 * `runStarted` the run's own start and `now` the time of the decision (UTC times as the gate writes
 * them). Each prerequisite must be recorded exactly once, as a stage record whose status is a stage
 * status and whose valid recorded interval lies within this run up to the decision, with status
 * pass. Returns a frozen { prerequisites, open, problems, decided }: open only with no problem.
 */
export function preDispatchBarrier(stages, { runStarted, now } = {}) {
  const problems = [];
  const timed = isTime(runStarted) && isTime(now) && Date.parse(now) >= Date.parse(runStarted);
  if (!timed)
    problems.push(
      'the run has no valid start and decision time, so no prerequisite can be judged to belong to this run'
    );
  if (!Array.isArray(stages)) problems.push('the run has no list of stage records');
  const list = Array.isArray(stages) ? stages : [];
  if (list.some(stage => !isObject(stage) || typeof stage.name !== 'string'))
    problems.push('the stage list of the run holds an entry that is not a named stage record');
  for (const name of PRE_DISPATCH_PREREQUISITES) {
    const found = list.filter(stage => isObject(stage) && stage.name === name);
    if (!found.length) {
      problems.push(`${name} is absent: it has not completed in this run`);
      continue;
    }
    if (found.length > 1) {
      problems.push(`${name} is recorded ${found.length} times, so it has no one result`);
      continue;
    }
    const [stage] = found;
    if (!STAGE_STATUSES.has(stage.status)) {
      problems.push(`${name} is malformed: its status ${show(stage.status)} is not a stage status`);
      continue;
    }
    if (
      !isTime(stage.started) ||
      !isTime(stage.finished) ||
      Date.parse(stage.finished) < Date.parse(stage.started)
    ) {
      problems.push(`${name} is malformed: it has no valid recorded start and end`);
      continue;
    }
    if (timed && Date.parse(stage.started) < Date.parse(runStarted)) {
      problems.push(
        `${name} is stale: it started before this run did, so it is not a result of this run`
      );
      continue;
    }
    if (timed && Date.parse(stage.finished) > Date.parse(now)) {
      problems.push(
        `${name} is stale: it ends after the barrier was decided, so it had not completed`
      );
      continue;
    }
    if (stage.status !== 'pass') {
      const why =
        typeof (stage.error ?? stage.reason) === 'string' ? (stage.error ?? stage.reason) : '';
      problems.push(`${name} is ${stage.status}${why ? ` (${why.slice(0, 300)})` : ''}`);
    }
  }
  return Object.freeze({
    prerequisites: PRE_DISPATCH_PREREQUISITES,
    open: problems.length === 0,
    problems: Object.freeze(problems),
    decided: isTime(now) ? now : null,
  });
}

/**
 * The stages every test stage needs first (v5 C3: test-host before the full-test stages, and
 * runtime-identity before any test stage uses a runtime; maintainer note 20261017T061149194320Z decision 3;
 * security review GD5-CARRY-01). They are the four test-stage rules' `prerequisites` (DISPATCH_RULES).
 */
export const TEST_STAGE_PREREQUISITES = Object.freeze(['test-host', 'runtime-identity']);
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * What keeps test stage `name` from starting, as far as its prerequisites go (`prerequisites`,
 * TEST_STAGE_PREREQUISITES unless given). `run` is { stages, started, now, platform, runtime }:
 * the run's stage records as the gate holds them, the run's own start, the time of this decision,
 * the platform the gate runs on and the runtime the stage would run ({ sha256, version }, the
 * gate's hash of its executable). Each prerequisite must be recorded exactly once, as a stage
 * record whose status is a stage status, with a valid recorded interval within this run that ends
 * no later than this decision, with status pass, and it must apply to this stage: test-host must
 * name this host's platform, and runtime-identity must list this stage's runtime by its sha256 and
 * version, as the finalizer requires of a test stage that ran. Both apply to every test stage of
 * every run: a commit or release run of a candidate with the platform contract, a companion run,
 * and a maintenance (B35) run alike (GDR6-REQ-01: B35 makes a candidate whose history never held
 * the manifest a maintenance candidate, judged by the earlier gate's stage list, but gives no
 * permission to start a runtime that was never identified; the gate identifies a maintenance run's
 * own approved runtimes, the gate's own Node plus the configured Node 24 executable when that
 * executable is different, as it does a contract run's). No kind of run is exempt, whatever else
 * `run` holds, and an absent record is a problem as a bad one is.
 * Returns the problems, frozen: none when the prerequisites let the stage start.
 */
export function testStagePrerequisiteProblems(name, run, prerequisites = TEST_STAGE_PREREQUISITES) {
  if (!isObject(run))
    return Object.freeze([
      `the run's stage records, start and decision time were not given, so ${prerequisites.join(' and ')} cannot be judged`,
    ]);
  const problems = [];
  const timed =
    isTime(run.started) && isTime(run.now) && Date.parse(run.now) >= Date.parse(run.started);
  if (!timed)
    problems.push(
      'the run has no valid start and decision time, so no prerequisite can be judged to belong to this run'
    );
  if (!Array.isArray(run.stages)) problems.push('the run has no list of stage records');
  const list = Array.isArray(run.stages) ? run.stages : [];
  if (list.some(stage => !isObject(stage) || typeof stage.name !== 'string'))
    problems.push('the stage list of the run holds an entry that is not a named stage record');
  for (const prerequisite of prerequisites) {
    if (!TEST_STAGE_PREREQUISITES.includes(prerequisite)) {
      problems.push(`${prerequisite} is no prerequisite this gate can judge for a test stage`);
      continue;
    }
    const found = list.filter(stage => isObject(stage) && stage.name === prerequisite);
    if (!found.length) {
      problems.push(`${prerequisite} is absent: it has not completed in this run`);
      continue;
    }
    if (found.length > 1) {
      problems.push(`${prerequisite} is recorded ${found.length} times, so it has no one result`);
      continue;
    }
    const [stage] = found;
    if (!STAGE_STATUSES.has(stage.status)) {
      problems.push(
        `${prerequisite} is malformed: its status ${show(stage.status)} is not a stage status`
      );
      continue;
    }
    if (
      !isTime(stage.started) ||
      !isTime(stage.finished) ||
      Date.parse(stage.finished) < Date.parse(stage.started)
    ) {
      problems.push(`${prerequisite} is malformed: it has no valid recorded start and end`);
      continue;
    }
    if (timed && Date.parse(stage.started) < Date.parse(run.started)) {
      problems.push(
        `${prerequisite} is stale: it started before this run did, so it is not a result of this run`
      );
      continue;
    }
    if (timed && Date.parse(stage.finished) > Date.parse(run.now)) {
      problems.push(
        `${prerequisite} is stale: it ends after ${name} was decided, so it had not completed`
      );
      continue;
    }
    if (stage.status !== 'pass') {
      const why =
        typeof (stage.error ?? stage.reason) === 'string' ? (stage.error ?? stage.reason) : '';
      problems.push(`${prerequisite} is ${stage.status}${why ? ` (${why.slice(0, 300)})` : ''}`);
      continue;
    }
    if (prerequisite === 'test-host') {
      if (typeof run.platform !== 'string' || !run.platform)
        problems.push(
          'test-host cannot be judged to apply: the platform the gate runs on was not given'
        );
      else if (!isObject(stage.host) || stage.host.platform !== run.platform)
        problems.push(
          `test-host does not apply to this host: it names the platform ${show(isObject(stage.host) ? stage.host.platform : undefined)}, not ${show(run.platform)}`
        );
    } else {
      const runtime = run.runtime;
      if (
        !isObject(runtime) ||
        typeof runtime.sha256 !== 'string' ||
        !HEX64.test(runtime.sha256) ||
        typeof runtime.version !== 'string' ||
        !runtime.version
      )
        problems.push(
          `runtime-identity cannot be judged to apply: the runtime ${name} would use was not identified`
        );
      else if (
        !Array.isArray(stage.runtimes) ||
        !stage.runtimes.some(
          item =>
            isObject(item) && item.sha256 === runtime.sha256 && item.version === runtime.version
        )
      )
        problems.push(
          `runtime-identity does not apply to ${name}: it does not identify Node ${show(runtime.version)} (sha256 ${runtime.sha256}), the runtime ${name} would use`
        );
    }
  }
  return Object.freeze(problems);
}

/**
 * The authorities a dispatch may need, each with why it is missing in this draft. Every reason
 * names what would have to exist; none of it exists, and none is invented here.
 */
export const DISPATCH_AUTHORITIES = Object.freeze({
  'host-listener':
    'no qualified host listener serves this run from a frozen, authenticated prefetch plan and verified cache, and direct registry or download access is no fallback (v5 C3, C6, C14 change 10; maintainer note 014104, carried item on the five listener stages); the listener and its preconditions belong to gate-network and int-d',
  'test-image-builds':
    "the candidate's tests build images (TEST_REQUIRE includes docker; test/installer/docker.test.mjs builds the candidate's own image and a FROM scratch context), and no reviewed pre-build authority record, Docker stage policy, qualified builder and endpoint, or containment of nested Docker clients and direct endpoints exists (v5 C5 changes 3 and 15, decision 7; maintainer note 014104 item 1)",
  'scan-image-build':
    'no reviewed pre-build authority record (approved staged base images, build context, Dockerfile, arguments, platform, qualified builder and endpoint, stage policy and boundaries) exists for the image build of the scan, so nothing is built or pulled and no cached image stands in (v5 C5 change 3; maintainer note 014104 item 2)',
  'semgrep-image':
    'image-approval is pending: no reviewed activation record approves the Semgrep image for this purpose, consumer and runner, so it is neither inspected nor run, and no host binary stands in (v5 C5; maintainer note 014104 item 3)',
  't8-image-inspect':
    'the reviewed Docker stage policy for docker image inspect and the qualified endpoint are pending, and the T8 operational hold is active, so no docker image inspect is dispatched (v5 C5 decision 7, C17 item 12; maintainer note 014104, carried item on the T8 inspect)',
  'docker-version-query':
    'no reviewed Docker stage policy for docker version and no qualified endpoint exist, so the gate dispatches no Docker command for it (v5 C5 decision 7: an operation is permitted only by a reviewed stage policy on a qualified endpoint)',
});

const AUTHORITY_MEMBERS = ['purpose', 'reference', 'source'];
const text = value =>
  typeof value === 'string' &&
  value.trim().length > 0 &&
  value.length <= 500 &&
  !/[\u0000-\u001f\u007f]/.test(value);

/**
 * Judges what `provide(purpose)` (scripts/security-authority.mjs) gives for each purpose: null
 * grants nothing; an authority is exactly { purpose, reference, source }, its purpose the one asked
 * for and the others bounded text. Anything else grants nothing either. Returns a frozen map
 * purpose → { granted: true, authority } or { granted: false, reason }.
 */
export function decideAuthorities(provide) {
  const decided = {};
  for (const [purpose, missing] of Object.entries(DISPATCH_AUTHORITIES)) {
    let value;
    try {
      value = provide(purpose);
    } catch (error) {
      decided[purpose] = Object.freeze({
        granted: false,
        reason: `its authority could not be read (${String(error?.message ?? error).slice(0, 200)}): ${missing}`,
      });
      continue;
    }
    if (value === null || value === undefined) {
      decided[purpose] = Object.freeze({ granted: false, reason: missing });
      continue;
    }
    const keys = isObject(value) ? Object.keys(value).sort() : null;
    if (
      !keys ||
      keys.join() !== AUTHORITY_MEMBERS.join() ||
      value.purpose !== purpose ||
      !text(value.source) ||
      !text(value.reference)
    ) {
      decided[purpose] = Object.freeze({
        granted: false,
        reason: `the authority given for ${purpose} is malformed (it must be exactly { purpose: ${show(purpose)}, source, reference }), so it grants nothing: ${missing}`,
      });
      continue;
    }
    decided[purpose] = Object.freeze({
      granted: true,
      authority: Object.freeze({
        purpose,
        source: value.source,
        reference: value.reference,
      }),
    });
  }
  return Object.freeze(decided);
}

/**
 * Every stage the gate dispatches with a command, and what it needs first. `barrier`: the
 * pre-dispatch barrier must be open (a candidate-controlled command, or dependencies-install, or a
 * Docker query whose target the candidate's manifest names). `authority`: each purpose must be
 * granted. `install`: dependencies-install must have passed in this run. `prerequisites` (the four
 * test stages only): each stage named must have passed in this run and apply to the test stage
 * (testStagePrerequisiteProblems). A name not listed here is never dispatched. The gate's own
 * commands over its repository and snapshot (Git, Gitleaks, Trivy's configuration and database
 * checks, npm's version, the rules archive's extraction) need neither.
 */
export const DISPATCH_RULES = Object.freeze({
  'snapshot-clone': { barrier: false, authority: [], install: false },
  'snapshot-index': { barrier: false, authority: [], install: false },
  'snapshot-files': { barrier: false, authority: [], install: false },
  'npm-version': { barrier: false, authority: [], install: false },
  'docker-version': { barrier: false, authority: ['docker-version-query'], install: false },
  't8-image-identity': { barrier: true, authority: ['t8-image-inspect'], install: false },
  'sql-lint': { barrier: true, authority: [], install: false },
  'import-lint': { barrier: true, authority: [], install: false },
  'dependencies-install': { barrier: true, authority: ['host-listener'], install: false },
  format: { barrier: true, authority: [], install: true },
  'syntax-manifest': { barrier: true, authority: [], install: true },
  documentation: { barrier: true, authority: [], install: true },
  'dependencies-all': { barrier: true, authority: ['host-listener'], install: true },
  'dependencies-production': { barrier: true, authority: ['host-listener'], install: true },
  'registry-signatures': { barrier: true, authority: ['host-listener'], install: true },
  'secrets-source': { barrier: false, authority: [], install: false },
  'secrets-history': { barrier: false, authority: [], install: false },
  'secrets-metadata': { barrier: false, authority: [], install: false },
  'sast-rules-download': { barrier: false, authority: ['host-listener'], install: false },
  'sast-rules-extract': { barrier: false, authority: [], install: false },
  'sast-image': { barrier: false, authority: ['semgrep-image'], install: false },
  'source-analysis': { barrier: false, authority: ['semgrep-image'], install: false },
  'container-configuration': { barrier: false, authority: [], install: false },
  'scanner-database': { barrier: false, authority: [], install: false },
  // Dispatched only in scan mode (a commit or release run records them pending without asking).
  'container-build': { barrier: true, authority: ['scan-image-build'], install: false },
  'container-identity': { barrier: true, authority: ['scan-image-build'], install: false },
  'container-vulnerabilities': { barrier: true, authority: ['scan-image-build'], install: false },
  'container-sbom': { barrier: true, authority: ['scan-image-build'], install: false },
  // The test stages also need test-host and runtime-identity (GD5-CARRY-01).
  'full-tests-current-runtime': {
    barrier: true,
    authority: ['test-image-builds'],
    install: true,
    prerequisites: [...TEST_STAGE_PREREQUISITES],
  },
  'full-tests-minimum-runtime': {
    barrier: true,
    authority: ['test-image-builds'],
    install: true,
    prerequisites: [...TEST_STAGE_PREREQUISITES],
  },
  'platform-tests-current-runtime': {
    barrier: true,
    authority: ['test-image-builds'],
    install: true,
    prerequisites: [...TEST_STAGE_PREREQUISITES],
  },
  'platform-tests-minimum-runtime': {
    barrier: true,
    authority: ['test-image-builds'],
    install: true,
    prerequisites: [...TEST_STAGE_PREREQUISITES],
  },
});
// Each rule and its lists of purposes and prerequisites are frozen too, so nothing in the gate's
// process can change what a stage needs after this module is loaded (verify-1 of gate-draft-r5
// noted that only the table itself was frozen).
for (const rule of Object.values(DISPATCH_RULES)) {
  Object.freeze(rule.authority);
  if (rule.prerequisites) Object.freeze(rule.prerequisites);
  Object.freeze(rule);
}

/**
 * Whether the gate may dispatch stage `name` now: with `barrier` (preDispatchBarrier, or null while
 * undecided), `authorities` (decideAuthorities, or null while undecided), whether
 * dependencies-install passed (`installed`) and, for a stage whose rule names prerequisites (the
 * test stages), `run` (testStagePrerequisiteProblems; null or missing withholds such a stage).
 * Returns { dispatch: true, authority: [...] } with the authorities it rests on, or
 * { dispatch: false, reasons: [...] } naming every reason it is withheld.
 */
export function dispatchDecision(
  name,
  { barrier = null, authorities = null, installed = false, run = null } = {}
) {
  const rule = Object.hasOwn(DISPATCH_RULES, name) ? DISPATCH_RULES[name] : null;
  if (!rule)
    return {
      dispatch: false,
      reasons: [
        `${name} has no dispatch rule in this gate, and an unclassified command is never dispatched`,
      ],
    };
  const reasons = [];
  if (rule.barrier && !barrier?.open)
    reasons.push(
      barrier
        ? `the pre-dispatch barrier is closed: ${barrier.problems.join('; ')} (candidate-policy and platform-manifest must each pass first; v5 C3, C4, change 19; GDR4-01)`
        : 'the pre-dispatch barrier has not been decided, so nothing candidate-controlled may start (GDR4-01)'
    );
  const authority = [];
  for (const purpose of rule.authority) {
    const decided = authorities?.[purpose];
    if (decided?.granted) authority.push(decided.authority);
    else
      reasons.push(
        `no ${purpose} authority: ${decided ? decided.reason : 'the authorities have not been decided'}`
      );
  }
  if (rule.install && !installed)
    reasons.push(
      'dependencies-install did not pass in this run, so the dependencies it needs are not installed'
    );
  if (rule.prerequisites) {
    const problems = testStagePrerequisiteProblems(name, run, rule.prerequisites);
    if (problems.length)
      reasons.push(
        `${rule.prerequisites.join(' and ')} must each pass in this run and apply to this test stage before it starts (v5 C3; GD5-CARRY-01; GDR6-REQ-01: in a maintenance run as in every other): ${problems.join('; ')}`
      );
  }
  return reasons.length ? { dispatch: false, reasons } : { dispatch: true, authority };
}

/**
 * The reason a withheld stage records: what was withheld, and every reason, as one line of text
 * within the 2000 characters a stage reason may have. The finalizer reads a withheld stage's
 * reason only as such a line (security-platform.mjs, withheldStage), and refuses anything else,
 * which is fail-closed but names the wrong problem. A reason can carry text the candidate chose:
 * a prerequisite's error names a candidate file, whose name may hold a newline (verify-1 of
 * gate-draft-r5). So every control character is written as its \uXXXX escape, and a longer reason
 * is then cut to 2000 characters, the last of them "…".
 */
export const withheldReason = reasons => {
  const reason = `withheld before dispatch, nothing ran: ${reasons.join('; ')}`.replace(
    /[\u0000-\u001f\u007f]/g,
    character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`
  );
  return reason.length <= 2000 ? reason : `${reason.slice(0, 1999)}…`;
};

/**
 * The gate's one dispatch point (scripts/security-gate.mjs routes every stage of its stage runner
 * through it). Only these start directly, without it: the version checks of Gitleaks, Trivy and the
 * Node 24 runtime, the gate's own Git reads, and, in scan mode, the clean-up `docker image rm` of
 * the image a build made, which runs only after that build was dispatched here under its
 * scan-image-build authority. Calls `start(authority)`, which starts the stage's command, only
 * when dispatchDecision allows stage `name` with `state` ({ barrier, authorities, installed, run }),
 * with the authorities it rests on; otherwise calls `withhold(reasons)` and starts nothing.
 * Returns what the one it called returns.
 */
export function dispatchOrWithhold(name, state, { start, withhold }) {
  const decision = dispatchDecision(name, state);
  return decision.dispatch ? start(decision.authority) : withhold(decision.reasons);
}
