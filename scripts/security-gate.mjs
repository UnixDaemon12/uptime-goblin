// Validate the Git index in a disposable checkout. Reports never enter release inputs.
// This is a local guardrail, not an unbypassable trust boundary or a release certificate.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { sourceManifest, sha256, testTotals, checkReview } from './security-evidence.mjs';
import {
  candidateParents,
  platformInputs,
  readEvidence,
  sealRun,
} from './security-finalization.mjs';
import { findingReports } from './security-findings.mjs';
import { installedCatalog, mainProfileFor } from './security-catalog.mjs';
import { GATE_IDENTITY_PARTS, GATE_IDENTITY_VERSION } from './security-gate-identity.mjs';
import { dispatchAuthority } from './security-authority.mjs';
import {
  decideAuthorities,
  dispatchDecision,
  dispatchOrWithhold,
  preDispatchBarrier,
  withheldReason,
} from './security-dispatch.mjs';
import {
  LOCAL_RUN_KIND,
  LOCAL_RUN_KIND_VERSION,
  actionlintCandidateConfig,
  activationBinding,
  activationBindingFile,
  builtImageStages,
  candidateIdentity,
  candidateTestFiles,
  fullRunOf,
  goldenToolName,
  hardenGitHistory,
  historyRewriteProblems,
  hostsImages,
  imageAuthenticityProblems,
  imageAuthorityPending,
  imageRecordName,
  inheritedEnvironment,
  judgePlatformManifest,
  judgmentSummary,
  missingToolPin,
  networkProblems,
  packRecords,
  parseCoverageDispositions,
  parseImageInspection,
  parseNetworkState,
  parseReleaseKeys,
  pendingRecordStages,
  platformManifestState,
  readRegularFile,
  removeTestInputs,
  runtimeGaps,
  runtimeIdentityProblems,
  sameParents,
  stageCoverage,
  strictJson,
  t8InspectCommand,
  testControls,
  testEnvironment,
} from './security-platform.mjs';

process.umask(0o077);
// Started through npm (`npm run security:commit`), the gate inherits npm's PATH, which puts every
// node_modules/.bin from the worktree up first, and NODE_OPTIONS and npm_config_* taken from the
// worktree's and the user's .npmrc. A dependency installed in the worktree could then supply the
// `npm`, `gitleaks` or `git` a stage starts, and a node-options entry could end a lint with exit 0
// before it checks anything. Neither may decide what a stage runs, so no stage gets them,
// however the gate was started. (What npm did before the gate started, such as running a
// worktree `node` in its place, cannot be undone here: start the gate with node.) npm also
// reads the user's and its global .npmrc itself, whatever the environment says, so each npm
// stage gets empty ones instead (see npmStage).
process.env.PATH = (process.env.PATH ?? '')
  .split(path.delimiter)
  .filter(entry => !/(?:^|[\\/])node_modules[\\/]\.bin[\\/]*$/i.test(entry))
  .join(path.delimiter);
for (const name of Object.keys(process.env))
  if (name === 'NODE_OPTIONS' || /^npm_config_/i.test(name)) delete process.env[name];
// No stage inherits the test suite's switches either: every TEST_* variable (TEST_REQUIRE could
// narrow what must run, TEST_T8_DIR make a host run register the T8 tests, TEST_TAG_TREES take
// release trees from a folder instead of Git, TEST_PLATFORM_RECORDS and TEST_PLATFORM_RUN point
// the platform records elsewhere), UPDATE_GOLDEN (the golden test would rewrite tracked files
// rather than compare them) and NODE_TEST_CONTEXT (it changes what node --test prints), in any
// letter case. They go before any stage starts; the test stages get the gate's own values
// (testEnvironment). The names removed are recorded, never their values.
const inheritedTestInputs = removeTestInputs(process.env);
// The caller's environment as the gate received it, after the removals above and before the gate
// sets any Git variable of its own: what the run record names as inherited (round 2 of
// gate-draft-r11, check-1 R11C1-RECORD-ENV: the Git variables the caller carried are named there
// even though no stage gets them, and the gate's own settings are not named as inherited).
const callerEnvironment = { ...process.env };
// Every Git command the gate and its stages run reads each commit as it is: no grafts (an
// exported GIT_GRAFT_FILE among them), no replace refs and no commit-graph, which could hide a
// commit from the platform-manifest judgment and the history secret scan. The inherited variables
// replaced are recorded by name. A shallow repository or an info/grafts file is refused below.
const inheritedHistoryInputs = hardenGitHistory(process.env);
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const mode = process.argv[2];
// `platform <run-id>` runs one companion run of the platform contract (test/platform-manifest.json)
// on this host, for the same staged tree as the gate run it accompanies.
const platformRunId = mode === 'platform' ? process.argv[3] : undefined;
if (
  !(['commit', 'release', 'scan'].includes(mode) && process.argv.length === 3) &&
  !(
    mode === 'platform' &&
    process.argv.length === 4 &&
    /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(platformRunId) &&
    platformRunId.length <= 80
  )
)
  throw new Error(
    'Usage: node scripts/security-gate.mjs commit|release|scan, or platform <run-id>'
  );
// The gate's Git runner reads the repository at `root` only, through the same binding as every
// authority read (bindRepository in scripts/security-platform.mjs; GDR9-AUTH-ROOT-01): an inherited
// GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR naming another repository, another object source than
// its own quarantine, a GIT_NAMESPACE or another index refuses before anything is read, and no read
// of this runner fetches a missing object from a promisor remote (GIT_NO_LAZY_FETCH=1;
// GDR9-AUTH-OBJECT-01). Since gate-draft-r12 (GDR11-AUTH-CONFIG-01) the binding's environment is
// the one authority configuration policy that every stage gets too (stageGitEnvironment, below):
// no Git configuration, attributes or ignore file the caller's environment chooses reaches the
// gate's own reads, and no fsmonitor starts for them; since round 2 no hook and no filter driver
// of the repository's own, whatever its name, and its `~/` includes name no file the caller's HOME
// chooses (BOUND_GIT_SETTINGS, NO_HOME).
// (Imported here, beside the runner, so that the gate's other lines stay as they are.)
const {
  HISTORY_LOG_OPTIONS,
  bindRepository,
  boundStageEnvironment,
  metadataScanInput,
  stageGitEnvironment,
} = await import('./security-platform.mjs');
const gitBinding = bindRepository(root, { index: true });
const git = (...args) => {
  const result = spawnSync('git', args, {
    cwd: root,
    env: gitBinding.env,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 ** 2,
  });
  if (result.status !== 0) throw new Error(`Git failed: ${args[0]}`);
  return result.stdout.trimEnd();
};
// gate-draft-r11, GDR10-AUTH-STAGE-01: every process the gate starts (each stage, the tool queries
// and the image removal) gets one deliberate environment instead of process.env: no inherited Git
// selector (repository, working tree, common directory, index, ref namespace, object directory,
// alternate store or quarantine), no injected configuration, no other Git variable but the few
// STAGE_GIT_VARIABLES admits, the history settings and GIT_NO_LAZY_FETCH=1
// (stageGitEnvironment). Since round 2 (check-1 R11C1-STAGE-CONF-CLONE and -HISTORY) no Git
// configuration file that the caller's environment chooses either: no global or system file
// (GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, HOME, XDG_CONFIG_HOME) and no default attributes or ignore
// file, so none can point the snapshot clone at another repository or a remote helper, put a
// setting in front of a stage or hide history content from the secret scan; a stage's Git reads the
// configuration of the repository it works in and the gate's settings. (Since gate-draft-r12 the
// binding above follows the same policy for the gate's own reads.) An
// inherited selector that names this repository itself, which the binding
// above admits for the gate's own reads, is not passed on either, so it cannot point a step that
// runs inside the snapshot back at this repository, its index or its quarantine. The snapshot is
// cloned with this environment alone; its own steps are bound to the snapshot by a binding of
// their own; the history secret scan is given this repository explicitly, as the binding above
// validated it (boundStageEnvironment); every other stage, the npm, test and documentation stages
// among them, finds the snapshot from the folder it runs in.
const stageEnvironment = stageGitEnvironment(process.env);
const historyEnvironment = boundStageEnvironment(gitBinding, stageEnvironment);
if (git('rev-parse', '--is-shallow-repository') !== 'false')
  throw new Error('Full history is required; fetch every publishable branch and tag first');
const common = path.resolve(root, git('rev-parse', '--git-common-dir'));
const rewritten = historyRewriteProblems(args => git(...args), common);
if (rewritten.length) throw new Error(`The history cannot be judged: ${rewritten.join('; ')}`);
const tree = git('write-tree');
const parent = git('rev-parse', 'HEAD');
// The complete ordered parent vector of the commit the candidate will become: HEAD and, while a
// merge is being concluded, each MERGE_HEAD in order (GATE-CONTRACT v3 C18). A run is bound to
// all of it, never to HEAD alone, and is not made when it cannot be read.
const candidateHeads = candidateParents(root);
if (!candidateHeads.complete || candidateHeads.heads[0] !== parent)
  throw new Error(
    `The complete parent vector of the candidate is not known (${candidateHeads.reason || 'HEAD changed'}): conclude or abort the merge, then rerun`
  );
const parents = candidateHeads.heads;
const refs = git('for-each-ref', '--format=%(refname) %(objectname)');
// The catalog of required stages (scripts/security-catalog.json; v3 C23), and the profile this
// run reports: a companion's own run, or for a gate run the profile of this host (only Linux has
// a reviewed array). The finalizer selects the profile itself and requires the same values.
const catalog = mode === 'scan' ? null : installedCatalog();
const directory = path.join(common, 'orbit-security', `${tree}-${mode}-${randomUUID()}`);
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
const write = (name, value) =>
  fs.writeFileSync(
    path.join(directory, name),
    typeof value === 'string' || Buffer.isBuffer(value)
      ? value
      : `${JSON.stringify(value, null, 2)}\n`,
    { mode: 0o600 }
  );
// The local run record: its own record family and version (security review GDR4-02; maintainer note 014104 item
// 6c), a diagnostic record of this local run, not a C12 phase record (security-finalization.mjs).
const evidence = {
  kind: LOCAL_RUN_KIND,
  kindVersion: LOCAL_RUN_KIND_VERSION,
  mode,
  ...(platformRunId ? { platformRun: platformRunId } : {}),
  tree,
  parents,
  refs,
  ...(catalog
    ? {
        catalog: {
          sha256: catalog.sha256,
          mode: mode === 'platform' ? 'commit' : mode,
          profile: mode === 'platform' ? platformRunId : mainProfileFor(process.platform),
        },
      }
    : {}),
  started: new Date().toISOString(),
  host: {
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    node: process.version,
    uid: process.getuid(),
  },
  inheritedTestInputs,
  inheritedHistoryInputs,
  // What the gate inherits from your environment after the removals above: every name, and the
  // values of the variables that choose a tool the tests use (inheritedEnvironment). Every stage
  // gets these with its Git variables as stageEnvironment sets them, so a Git variable named here
  // may reach no stage; the gate's own Git settings are not named (round 2 of gate-draft-r11,
  // check-1 R11C1-RECORD-ENV: callerEnvironment, above).
  inheritedEnvironment: inheritedEnvironment(callerEnvironment),
  status: 'running',
  stages: [],
};
write('result.json', evidence);
console.log(`Security ${mode}: staged tree ${tree}\nPrivate evidence: ${directory}`);
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-security-'));
const source = path.join(scratch, 'source');
let sequence = 0;
let image;
// Scanner preferences are not reviewed finding dispositions. Keep repository-local policy
// discovery and inherited TRIVY_* settings from silently narrowing the required scans.
const trivyEnvironment = Object.fromEntries(
  Object.entries(stageEnvironment).filter(([name]) => !name.toUpperCase().startsWith('TRIVY_'))
);
const trivyConfig = path.join(directory, 'trivy.yaml'),
  trivyIgnore = path.join(directory, 'trivyignore'),
  trivySecrets = path.join(directory, 'trivy-secret.yaml');
write('trivy.yaml', '{}\n');
write('trivyignore', '');
// No enable/disable/allow overrides: retain all of Trivy's built-in secret rules.
write('trivy-secret.yaml', '{}\n');
write('semgrepignore', '');
const trivyPolicy = [
  '--config',
  trivyConfig,
  '--ignorefile',
  trivyIgnore,
  '--severity',
  'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
];

// The TAP reporter marks a test that did not run with a `# SKIP` or `# TODO` directive after its
// name (a `#` inside a name is escaped as `\#`, so it cannot end the name early). Nested
// subtests are indented. The list is bounded; its total count is kept separately.
function unexecutedTests(tap) {
  const found = [];
  for (const match of tap.matchAll(/^\s*(?:not )?ok \d+ - (.*?) # (SKIP|TODO)\b[ \t]*(.*)$/gim))
    found.push({ test: match[1], directive: match[2].toUpperCase(), reason: match[3].trim() });
  return { count: found.length, tests: found.slice(0, 500) };
}

// What may be dispatched (scripts/security-dispatch.mjs; security review GDR4-01, maintainer note 014104). The
// pre-dispatch barrier is decided once, after candidate-policy and platform-manifest have
// completed, and the dispatch authorities with it (scripts/security-authority.mjs, which gives
// none in this draft). Until then both are null, and anything that needs either is withheld.
// `dependenciesInstalled` is whether dependencies-install passed in this run.
let barrier = null;
let authorities = null;
let dependenciesInstalled = false;
// `run` is what a test stage's rule judges besides (testStagePrerequisiteProblems; the security review's
// GD5-CARRY-01, v5 C3): test-host and runtime-identity must each be recorded once in this run,
// passed, ended by now and apply to the stage, in every kind of run, maintenance (B35) included
// (GDR6-REQ-01). A test stage gives the runtime it would use (testStage); without it a test
// stage's runtime-identity cannot be judged to apply, and it is withheld.
const dispatchState = ({ runtime = null } = {}) => ({
  barrier,
  authorities,
  installed: dependenciesInstalled,
  run: {
    stages: evidence.stages,
    started: evidence.started,
    now: new Date().toISOString(),
    platform: process.platform,
    runtime,
  },
});

// A stage the gate does not dispatch: recorded pending, with every reason it was withheld, and
// with nothing a command leaves (no command, log, exit or output), so it is never a pass and the
// run is blocking. `options.into` collects it as a step of a composite stage, as stage() does.
function withhold(name, reasons, options = {}) {
  const now = new Date().toISOString();
  const record = {
    name,
    started: now,
    finished: now,
    status: 'pending',
    reason: withheldReason(reasons),
  };
  (options.into ?? evidence.stages).push(record);
  write('result.json', evidence);
  console.log(`${name}: pending (withheld before dispatch)`);
  return false;
}

// A stage that cannot be dispatched because an earlier stage did not pass (`why`): withheld, with
// that reason and every reason dispatchDecision gives besides.
function withholdAfter(name, why) {
  const decision = dispatchDecision(name, dispatchState());
  return withhold(name, [why, ...(decision.dispatch ? [] : decision.reasons)]);
}

// The closed pre-dispatch barrier as a reason (none while it is open), for a candidate-controlled
// build a commit or release run never starts: change 19 makes a platform-manifest that did not
// pass stop every candidate-controlled build, and that is said, not only implied.
const closedBarrier = () =>
  barrier?.open
    ? []
    : [
        barrier
          ? `the pre-dispatch barrier is closed: ${barrier.problems.join('; ')}`
          : 'the pre-dispatch barrier has not been decided',
      ];

// `options.environment` is a stage's whole environment (a test stage's testEnvironment, or a
// snapshot step's binding); otherwise a stage gets the stage environment (stageEnvironment, the
// Trivy one for trivy) with `options.env` on top (GDR10-AUTH-STAGE-01); `options.record`
// adds fields to the stage's record, and `options.after(record)` runs before it is recorded.
// `options.pending` is the reason a stage stays pending although its command succeeded: what it
// observed is evidence, and its authority is pending (t8-image-identity, v5 C5, C17 item 12).
// Every stage this runner starts goes through the one dispatch point, dispatchOrWithhold
// (scripts/security-dispatch.mjs): a stage with no dispatch rule, one that needs the pre-dispatch
// barrier while it is closed or undecided, one that needs an authority that is not given and one
// that needs the installed dependencies while dependencies-install has not passed are withheld
// before anything is opened or started. A stage dispatched under an authority records it.
// `options.dispatch` is a test stage's own part of the decision (dispatchState: its runtime).
function stage(name, command, args, options = {}) {
  return dispatchOrWithhold(name, dispatchState(options.dispatch), {
    withhold: reasons => withhold(name, reasons, options),
    start: authority => startStage(name, command, args, options, authority),
  });
}

// Starts a stage's command, once dispatchOrWithhold has allowed it (stage() above).
function startStage(name, command, args, options, authority) {
  const report = findingReports[name] && path.join(directory, findingReports[name]);
  if (report) fs.writeFileSync(report, '', { flag: 'wx', mode: 0o600 });
  const log = `${String(++sequence).padStart(2, '0')}-${name}.log`;
  const fd = fs.openSync(path.join(directory, log), 'wx', 0o600);
  const record = {
    name,
    command: [command, ...args],
    started: new Date().toISOString(),
    log,
    ...options.record,
    ...(authority.length ? { authority } : {}),
  };
  console.log(`Checking ${name}…`);
  const result = spawnSync(command, args, {
    cwd: source,
    env: options.environment ?? {
      ...(command === 'trivy' ? trivyEnvironment : stageEnvironment),
      ...options.env,
    },
    timeout: options.timeout ?? 30 * 60 * 1000,
    stdio: ['ignore', fd, fd],
    ...options.spawn,
  });
  fs.closeSync(fd);
  record.finished = new Date().toISOString();
  record.exit = result.status;
  record.signal = result.signal;
  record.status = result.status === 0 && !result.error ? 'pass' : 'blocked';
  if (result.error) record.error = result.error.code || 'execution failed';
  if (report) {
    // A container writer may replace a precreated report with its own umask. The parent
    // directory remains private throughout; only our own bounded regular output is kept.
    let reportFd;
    try {
      reportFd = fs.openSync(
        report,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
      );
      const stat = fs.fstatSync(reportFd);
      if (!stat.isFile() || stat.size > 64 * 1024 * 1024 || stat.uid !== process.getuid())
        throw new Error('Unsafe scanner output');
      fs.fchmodSync(reportFd, 0o600);
    } catch {
      record.status = 'blocked';
      record.error = 'Scanner output is missing or unsafe';
    } finally {
      if (reportFd !== undefined) fs.closeSync(reportFd);
    }
  }
  if (options.tests) {
    let tap = '';
    try {
      tap = fs.readFileSync(path.join(directory, log), 'utf8');
    } catch (error) {
      record.status = 'blocked';
      record.error = error.message;
    }
    // Name every test that did not execute, so a blocked run says which required coverage is
    // missing (a platform-only test, an absent tool, a test that runs only inside a container).
    // This is accounting, never a waiver: testTotals() below still blocks on any skip or todo.
    record.unexecuted = unexecutedTests(tap);
    if (record.status === 'pass') {
      try {
        record.tests = testTotals(tap);
      } catch (error) {
        record.status = 'blocked';
        record.error = error.message;
      }
    }
  }
  if (options.after) {
    try {
      options.after(record);
    } catch (error) {
      record.status = 'blocked';
      record.error ??= error.message;
    }
  }
  if (options.pending && record.status === 'pass') {
    record.status = 'pending';
    record.reason = options.pending;
  }
  // `options.into` collects the record as a step of a composite stage instead (prepared-inputs).
  (options.into ?? evidence.stages).push(record);
  write('result.json', evidence);
  console.log(`${name}: ${record.status}`);
  return record.status === 'pass';
}

// A stage whose evidence this draft cannot make yet, or whose authority is pending (an F, a
// record or a qualification the contract names but nobody has reviewed): never a pass.
class PendingStage extends Error {}

// `check(record)` may add fields to the record, which are kept when it then throws. A
// PendingStage it throws records the stage as pending, with its message as the reason.
// `options.into` collects the record as a step of a composite stage (prepared-inputs).
function requirement(name, check, options = {}) {
  const record = { name, started: new Date().toISOString() };
  try {
    check(record);
    record.status = 'pass';
  } catch (error) {
    if (error instanceof PendingStage) {
      record.status = 'pending';
      record.reason = error.message;
    } else {
      record.status = 'blocked';
      record.error = error.message;
    }
  }
  record.finished = new Date().toISOString();
  (options.into ?? evidence.stages).push(record);
  write('result.json', evidence);
  console.log(`${name}: ${record.status}`);
  return record.status === 'pass';
}

// A catalog stage (v3 C23) that this draft does not implement: recorded as pending, with why.
function pendingStage(name, reason) {
  return requirement(name, () => {
    throw new PendingStage(reason);
  });
}

// Whether a directory on the gate's PATH has an executable of this name.
function onPath(command) {
  return (process.env.PATH ?? '').split(path.delimiter).some(entry => {
    if (!entry) return false;
    try {
      fs.accessSync(path.join(entry, command), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

// npm puts every node_modules/.bin from the snapshot's real path up to the file-system root
// first on PATH for `npm run`, and reads the snapshot's .npmrc in every npm command. A
// dependency, or the code of an earlier stage, can put either there without changing a tracked
// file: a `node`, `sh`, `bash` or `git` found there (npm runs scripts with `sh`, check.mjs runs
// `bash -n`, the documentation check runs `git`), or an .npmrc script-shell, makes an `npm run`
// stage pass without running its check (its log still names the script), and an .npmrc
// audit-level or registry changes what an audit stage checks. So each npm stage looks again
// first and refuses any entry there that would replace a command: npm's and the shell's own
// names, and every name that PATH also provides (a case-insensitive file system matches any
// case). A bin no system command has, such as `prettier`, is what the scripts mean to run.
// Only a .bin that does not exist (or is not a directory) is empty: the shell runs a command
// from a directory it may search but not list (mode 0111, say), so a .bin the gate cannot list
// for any other reason is refused too.
function npmTampering() {
  if (fs.lstatSync(path.join(source, '.npmrc'), { throwIfNoEntry: false }))
    return 'An .npmrc in the snapshot can change what an npm stage runs';
  for (let directory = fs.realpathSync(source); ; directory = path.dirname(directory)) {
    const bin = path.join(directory, 'node_modules', '.bin');
    let commands = [];
    try {
      commands = fs.readdirSync(bin);
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR')
        return `${bin} cannot be listed (${error.code}), so a command there could replace one in an npm stage`;
    }
    for (const command of commands)
      if (['node', 'sh', 'env', 'npm', 'npx'].includes(command.toLowerCase()) || onPath(command))
        return `${path.join(bin, command)} would replace ${command} in an npm stage`;
    if (path.dirname(directory) === directory) return undefined;
  }
}

// npm reads the user's configuration (~/.npmrc) and its global npmrc in every command, however
// the gate was started: their script-shell or node-options would make an `npm run` stage pass
// without running its check, and their audit-level or registry would change what an audit stage
// checks. So each npm stage names an empty file for each, written just before it starts (two
// files, because npm refuses to load one file as both). npm's built-in npmrc, part of the npm
// installation, still applies.
const npmConfiguration = {
  npm_config_userconfig: path.join(scratch, 'npm-user-config'),
  npm_config_globalconfig: path.join(scratch, 'npm-global-config'),
};

// Withheld before anything is looked at, as stage() would withhold it (dispatchOrWithhold); then
// stage() judges it again, the same way, and starts it.
function npmStage(name, args, options = {}) {
  return dispatchOrWithhold(name, dispatchState(), {
    withhold: reasons => withhold(name, reasons, options),
    start: () => {
      const problem = npmTampering();
      if (problem) {
        if (!options.into)
          return requirement(name, () => {
            throw new Error(problem);
          });
        const now = new Date().toISOString();
        options.into.push({ name, started: now, finished: now, status: 'blocked', error: problem });
        return false;
      }
      for (const file of Object.values(npmConfiguration)) {
        fs.rmSync(file, { force: true });
        fs.writeFileSync(file, '', { flag: 'wx', mode: 0o600 });
      }
      return stage(name, 'npm', args, { env: npmConfiguration, into: options.into });
    },
  });
}

// Code a stage runs can leave a directory in the scratch area that the gate cannot list (mode
// 0111, as above), which a recursive removal cannot delete. Give each directory there back to
// its owner (without following symbolic links) and try again; a scratch area that still cannot
// be removed blocks the run, which is still recorded, rather than ending the gate first.
function removeScratch() {
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
    return;
  } catch {
    // Restore the owner's access below, then try again.
  }
  for (const pending = [scratch]; pending.length; ) {
    const directory = pending.pop();
    try {
      fs.chmodSync(directory, 0o700);
      for (const entry of fs.readdirSync(directory, { withFileTypes: true }))
        if (entry.isDirectory()) pending.push(path.join(directory, entry.name));
    } catch {
      // Not ours, or gone: the second removal reports what is left.
    }
  }
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch (error) {
    const now = new Date().toISOString();
    evidence.stages.push({
      name: 'scratch-cleanup',
      started: now,
      finished: now,
      status: 'blocked',
      error: `${scratch} could not be removed (${error.code || error.message})`,
    });
  }
}

// 1.5's SQL and import-graph rules (roadmap §10.4), as package.json's `lint:sql` and
// `lint:imports` must name them (candidate-policy).
const lintCommands = {
  'lint:sql': 'scripts/sql-lint.mjs',
  'lint:imports': 'scripts/import-graph.mjs',
};

// ---------------------------------------------------------------------------------------------
// The platform coverage contract (test/platform-manifest.json; scripts/security-platform.mjs).

let files;
// The judgment of the candidate's manifest (platform-manifest), once made.
let judged = null;
// Whether the candidate has a platform contract: a manifest, or a commit behind it that held one.
const platformContract = () => Boolean(judged) && judged.kind !== 'maintenance';
const recorded = name => evidence.stages.find(item => item.name === name);
const securityFile = (...parts) => path.join(common, 'orbit-security', ...parts);

// platform-manifest: judges the candidate's manifest against its history (judgeCandidateManifest):
// a removed or weakened entry or run that no reviewed disposition excuses, a deleted or broken
// manifest that a commit behind it held, or parents that are not all known block. The
// dispositions come from <git common dir>/orbit-security/coverage/<tree>.json, outside the
// candidate, and are sealed with the run, so the finalization review binds them.
function judgePlatform() {
  return requirement('platform-manifest', record => {
    const heads = candidateParents(root);
    if (!heads.complete || !sameParents(heads.heads, parents))
      throw new Error('HEAD or MERGE_HEAD changed during validation; rerun');
    const inputs = platformInputs(root, tree, heads);
    const binding = { tree, parents };
    let dispositions = [];
    const dispositionFile = securityFile('coverage', `${tree}.json`);
    if (fs.lstatSync(dispositionFile, { throwIfNoEntry: false })) {
      const bytes = readEvidence(dispositionFile);
      write('coverage-dispositions.json', bytes);
      record.dispositions = 'coverage-dispositions.json';
      dispositions = parseCoverageDispositions(bytes, binding);
    }
    if (inputs.candidate) write('platform-manifest.json', inputs.candidate);
    const result = judgePlatformManifest({ ...inputs, dispositions, binding });
    write('platform-judgment.json', { ...result, manifest: undefined });
    record.judgment = 'platform-judgment.json';
    evidence.platform = judgmentSummary(result);
    judged = result;
    if (result.problems.length) throw new Error(result.problems.slice(0, 5).join('; '));
    // The candidate identity (v3 C18): the tree, the complete ordered parent vector, the file
    // manifest and the state of the reserved manifest path this judgment established (C19).
    const identity = candidateIdentity({
      tree,
      parents,
      files,
      platformManifest: platformManifestState(result),
    });
    evidence.candidate = identity.record;
    evidence.candidateIdentitySha256 = identity.sha256;
    if (mode === 'platform') {
      const run =
        result.manifest && Object.hasOwn(result.manifest.runs, platformRunId)
          ? result.manifest.runs[platformRunId]
          : null;
      if (result.kind === 'maintenance')
        throw new Error('The candidate has no platform manifest, so it needs no companion run');
      if (!run || run.platform === 'container')
        throw new Error(`${platformRunId} is not a run of the platform manifest that a host runs`);
      if (run.platform !== process.platform)
        throw new Error(
          `${platformRunId} runs on ${run.platform}, not on this ${process.platform} host`
        );
    }
  });
}

// test-host: what the platform tests need of the host before any test runs. Every test stage's
// dispatch rule requires it to have passed in this run and to name this host (GD5-CARRY-01), in a
// maintenance (B35) run too.
function testHost() {
  return requirement('test-host', record => {
    record.host = {
      platform: process.platform,
      uid: process.getuid(),
      setfacl: process.platform === 'linux' ? onPath('setfacl') : null,
    };
    if (!['darwin', 'linux'].includes(process.platform))
      throw new Error(`The test stages run on Linux or macOS, not ${process.platform}`);
    if (record.host.uid === 0)
      throw new Error('The test stages must run as a user other than root');
    if (process.platform === 'linux' && !record.host.setfacl)
      throw new Error(
        'setfacl is not installed (the acl package): the Linux access-list test needs it'
      );
  });
}

// Each Node runtime a test stage ran: its real path, version and the sha256 of its executable.
const runtimes = new Map();
function runtimeOf(executable, version) {
  const real = fs.realpathSync(executable);
  if (!runtimes.has(real)) {
    const hash = createHash('sha256');
    const fd = fs.openSync(real, fs.constants.O_RDONLY);
    try {
      const buffer = Buffer.alloc(1024 * 1024);
      for (let count; (count = fs.readSync(fd, buffer, 0, buffer.length, null)); )
        hash.update(buffer.subarray(0, count));
    } finally {
      fs.closeSync(fd);
    }
    runtimes.set(real, { path: real, version, sha256: hash.digest('hex') });
  }
  return runtimes.get(real);
}

// runtime-identity: each runtime's identity record (its distribution, and the signed SHASUMS
// check of a Node release or the reviewed exception of a Homebrew build), from
// <git common dir>/orbit-security/runtime-identity/<binary sha256>.json, sealed with the run, with
// the reviewed list of Node release keys (release-keys.json there) when a record names a Node
// release. It runs before the test stages (v5 C23 O), on the runtimes they will run (`versions`),
// in every run that plans a test stage. With a platform manifest, a run of it that needs a
// runtime no test stage of this run will run blocks here too, since a gate started on Node 24
// runs one test stage, and would otherwise pass and then always fail finalization. A maintenance
// (B35) run has no manifest, so it identifies exactly its own approved runtimes, the gate's own
// Node plus the configured Node 24 executable when that executable is different, and no 1.5
// matrix is asked of it (GDR6-REQ-01; the maintainer's B35 decision of 20261017T140102522864Z). A test
// stage is dispatched only once it has passed and lists that stage's runtime (testStage;
// GD5-CARRY-01).
function runtimeIdentity(runId, versions) {
  return requirement('runtime-identity', record => {
    record.runtimes = [];
    const problems = [];
    if (judged?.manifest && runId)
      for (const missing of runtimeGaps(judged.manifest, runId, versions))
        problems.push(
          `run ${runId} needs Node ${missing}, which no test stage of this run runs: start the gate with Node 26 and set ORBIT_SECURITY_NODE24 to a Node 24 executable`
        );
    let releaseKeys;
    const reviewedKeys = () => {
      if (releaseKeys !== undefined) return releaseKeys;
      releaseKeys = null;
      try {
        const bytes = readEvidence(securityFile('runtime-identity', 'release-keys.json'));
        write('runtime-release-keys.json', bytes);
        record.releaseKeys = 'runtime-release-keys.json';
        releaseKeys = parseReleaseKeys(bytes);
      } catch (error) {
        problems.push(`the reviewed Node release keys: ${error.code || error.message}`);
      }
      return releaseKeys;
    };
    for (const runtime of runtimes.values()) {
      const file = `runtime-identity-${runtime.sha256}.json`;
      record.runtimes.push({ ...runtime, record: file });
      let bytes;
      try {
        bytes = readEvidence(securityFile('runtime-identity', `${runtime.sha256}.json`));
      } catch (error) {
        problems.push(
          `no runtime identity record for Node ${runtime.version} (${runtime.path}, sha256 ${runtime.sha256}): ${error.code || error.message}`
        );
        continue;
      }
      write(file, bytes);
      try {
        const parsed = strictJson(bytes, 'the runtime identity record');
        problems.push(
          ...runtimeIdentityProblems(
            parsed,
            {
              sha256: runtime.sha256,
              version: runtime.version,
              platform: process.platform,
              arch: process.arch,
            },
            parsed?.distribution === 'nodejs-release' ? reviewedKeys() : null
          )
        );
      } catch (error) {
        problems.push(error.message);
      }
    }
    if (!record.runtimes.length)
      problems.push('no test stage will run, so no runtime was identified');
    if (problems.length) throw new Error(problems.join('; '));
  });
}

// The network record of each test stage on Linux: the state file the egress control outside the
// VM keeps (ORBIT_SECURITY_NETWORK_STATE), read right before and right after the stage. After the
// stage it waits up to 60 seconds for a state observed after the stage finished.
const networkSnapshots = [];
function readNetwork(stageName, label, notBefore) {
  const file = `network-${stageName}-${label}.json`;
  const source = process.env.ORBIT_SECURITY_NETWORK_STATE;
  if (
    typeof source !== 'string' ||
    !path.isAbsolute(source) ||
    Buffer.byteLength(source) > 1024 ||
    /[\u0000-\u001f\u007f]/.test(source)
  )
    return { error: 'ORBIT_SECURITY_NETWORK_STATE does not name the network state file' };
  const deadline = Date.now() + 60000;
  for (;;) {
    let bytes;
    try {
      bytes = readRegularFile(source, { max: 64 * 1024, privateOnly: false });
    } catch (error) {
      return { error: `the network state cannot be read: ${error.code || error.message}` };
    }
    const readAt = new Date().toISOString();
    let observed = null;
    try {
      observed = Date.parse(parseNetworkState(bytes).observedAt);
    } catch {
      // Recorded as it is; the network-policy check reports what is wrong with it.
    }
    if (notBefore === undefined || observed >= Date.parse(notBefore) || Date.now() >= deadline) {
      write(file, bytes);
      return { file, readAt };
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
}

// network-policy (Linux): the reviewed policy was in force, enforced outside the guest, in the
// test phase, with its counters before and after each test stage.
function networkPolicy() {
  // No test stage ran (each was withheld before dispatch): there is no network record to judge.
  if (!networkSnapshots.length && withheldTests.length)
    return pendingStage(
      'network-policy',
      `no test stage ran (${withheldTests.join(', ')} withheld before dispatch), so there is no network record to judge`
    );
  return requirement('network-policy', record => {
    // The guest's own reading is diagnostic (v3 C13): it can block, and its pass never stands in
    // for the controller's observations, which are the isolation authority.
    record.authority = 'diagnostic';
    record.snapshots = networkSnapshots;
    const problems = [];
    for (const snapshot of networkSnapshots)
      for (const label of ['before', 'after'])
        if (snapshot[label]?.error)
          problems.push(`${snapshot.stage} ${label}: ${snapshot[label].error}`);
    if (!networkSnapshots.length) problems.push('no test stage has a network record');
    if (problems.length) throw new Error(problems.join('; '));
    const first = parseNetworkState(
      fs.readFileSync(path.join(directory, networkSnapshots[0].before.file))
    );
    write(
      'network-policy.json',
      readEvidence(securityFile('network-policy', `${first.policySha256}.json`))
    );
    record.policy = 'network-policy.json';
    const policy = fs.readFileSync(path.join(directory, 'network-policy.json'));
    for (const snapshot of networkSnapshots)
      problems.push(
        ...networkProblems({
          stage: recorded(snapshot.stage),
          before: {
            bytes: fs.readFileSync(path.join(directory, snapshot.before.file)),
            readAt: snapshot.before.readAt,
          },
          after: {
            bytes: fs.readFileSync(path.join(directory, snapshot.after.file)),
            readAt: snapshot.after.readAt,
          },
          policy,
        })
      );
    if (problems.length) throw new Error(problems.join('; '));
  });
}

// One test stage: the gate's own test environment, a records folder and run code of its own, its
// runtime, and its records sealed as one file beside its log (packRecords). Its tests run with
// TEST_REQUIRE including docker, and some of them build images (test/installer/docker.test.mjs
// builds the candidate's own image and a FROM scratch context): v5 C5 lets no such build start
// without its pre-build authority, and maintainer note 014104 item 1 says it must not start at all. So the
// stage is withheld before dispatch, its records folder never made, while that authority (or the
// barrier, or the installed dependencies) is missing: docker stays in TEST_REQUIRE, the coverage
// stays required, and the stage is pending and blocking (`{ withheld: name }` is returned).
// It is withheld too unless test-host and runtime-identity have passed in this run and apply to it
// (the security review's GD5-CARRY-01; v5 C3), in every kind of run, a maintenance (B35) run included
// (GDR6-REQ-01): its rule judges them with the runtime it would use, as runtimeOf hashed it for
// runtime-identity. A binary that cannot be hashed leaves its runtime unidentified, and the stage
// is withheld.
const withheldTests = [];
function testStage(prefix, slot, executable, version, args) {
  const name = `${prefix}${slot}`;
  let identified = null;
  try {
    const { sha256, version: hashedVersion } = runtimeOf(executable, version);
    identified = { sha256, version: hashedVersion };
  } catch {
    identified = null;
  }
  const own = { runtime: identified };
  return dispatchOrWithhold(name, dispatchState(own), {
    withhold: reasons => {
      withhold(name, reasons);
      withheldTests.push(name);
      return { withheld: name, slot };
    },
    start: () => {
      let controls, environment;
      try {
        controls = testControls(scratch, slot);
        environment = testEnvironment(stageEnvironment, controls);
      } catch (error) {
        requirement(name, () => {
          throw error;
        });
        return null;
      }
      const runtime = runtimeOf(executable, version);
      const network = platformContract() && process.platform === 'linux' ? { stage: name } : null;
      if (network) network.before = readNetwork(name, 'before');
      let tested = null;
      stage(name, executable, args, {
        tests: true,
        dispatch: own,
        environment,
        timeout: 60 * 60 * 1000,
        record: { runtime: { ...runtime }, platformRun: controls.run },
        after: record => {
          tested = record;
          const file = record.log.replace(/\.log$/, '.records.json');
          write(file, packRecords(controls.records));
          record.records = file;
        },
      });
      if (network && tested) {
        network.after = readNetwork(name, 'after', tested.finished);
        networkSnapshots.push(network);
      }
      return tested && { record: tested, controls, slot };
    },
  });
}

// platform-coverage-<slot>: the test stage's coverage of its run (checkCoverage), and of the
// container runs it hosts (checkContainerEvidence). A run of every file is judged with the
// candidate's tracked test files.
function coverageStage(tested, runId) {
  return requirement(`platform-coverage-${tested.slot}`, record => {
    record.of = tested.record.name;
    record.run = runId;
    record.runtime = /^v(\d+)\./.exec(tested.record.runtime.version)?.[1] ?? null;
    if (!judged?.manifest)
      throw new Error('The candidate has no usable platform manifest to check the stage against');
    if (!runId)
      throw new Error(
        `The platform manifest has no single run of every test file on ${process.platform}`
      );
    if (!tested.record.records) throw new Error(`${tested.record.name} sealed no records`);
    const checked = stageCoverage({
      manifest: judged.manifest,
      manifestSha256: judged.manifestSha256,
      runId,
      runtime: record.runtime,
      tap: fs.readFileSync(path.join(directory, tested.record.log), 'utf8'),
      pack: fs.readFileSync(path.join(directory, tested.record.records)),
      nonce: tested.controls.run,
      allFiles: candidateTestFiles(files),
    });
    const report = tested.record.log.replace(/\.log$/, '.coverage.json');
    write(report, {
      run: runId,
      runtime: record.runtime,
      totals: checked.totals,
      coverage: checked.coverage,
      container: checked.container,
      problems: checked.problems,
    });
    record.report = report;
    const containers = checked.records.filter(item => item.kind === 'container');
    // Every T8 container record names an image whose identity and authenticity were checked
    // before any candidate code ran (t8Images), with the image ID Docker reported then.
    for (const container of containers) {
      const seen = t8Observed.find(item => item.image === container.image);
      if (!seen || seen.id !== container.imageId)
        checked.problems.push(
          `a T8 container record names ${container.image} (${container.imageId}), whose identity and authenticity were not checked before candidate code ran`
        );
    }
    if (checked.problems.length) throw new Error(checked.problems.slice(0, 10).join('; '));
  });
}

// The three T8 image stages (GATE-CONTRACT v5 C3, C5, C23). t8-image-identity and
// t8-image-authenticity belong to phase N, before container-build, systemd-test-image and every
// other candidate-controlled build instruction (v5 change 2): for the pinned images of the
// container runs this run hosts, what Docker reports of each (a local, read-only query; nothing is
// pulled) and the authenticity record of each, from
// <git common dir>/orbit-security/image-authenticity/<index digest>-<os>-<architecture>[-<variant>].json.
// t8-image-identity ends before t8-image-authenticity starts (v5 change 18; GDR3-01): the gate
// runs them one after the other. t8-image-activation belongs to phase O, before sql-lint,
// import-lint, every other stage that executes candidate code and the first use of the T8 image
// (v5 change 4): it binds the images to N's two sealed records (activationBinding, a proposed
// form), and is not a second authenticity claim. This draft runs N and O as one local run, so all
// three run here, before any candidate code (sql-lint is the first) and before both builds.
// The exact forms of all three records are pending and no producer is qualified (v5 C17 item 12),
// so each is recorded pending, never pass, also when its check found nothing wrong: what
// t8-image-identity observed is evidence, a consistent authenticity record is evidence and not
// authority to run the image (security review IP-01), and the activation's binding is a proposal. All
// three are required of every Linux gate run (it hosts T8, so they cannot disappear); with no
// pinned image to check they are pending with that reason. After the tests, coverageStage
// requires every T8 container record to name an image observed here, with the image ID Docker
// reported then.
// t8-image-identity's one `docker image inspect` is dispatched only through stage(), so only with
// the pre-dispatch barrier open (the images are named by the candidate's manifest, which
// platform-manifest judges) and with `t8-image-inspect` authority: the reviewed Docker stage
// policy for the query, a qualified endpoint and the operational hold lifted (maintainer note 014104). None
// exists in this draft, so it is withheld and nothing is observed; t8-image-authenticity and
// t8-image-activation then stay pending with nothing to check or bind. The inspect-consistency
// checks stay, for a run in which the inspect was dispatched.
const t8Observed = [];
function t8Images(runId) {
  if (!judged?.manifest || !runId || !hostsImages(judged.manifest, runId)) {
    const reason = judged
      ? `no pinned T8 image is hosted by ${runId ?? 'this run'} to check (v5 C5, C23)`
      : 'the platform-manifest judgment gave no result, so the T8 images this run would host are not known, and nothing is inspected, checked or bound (v5 C5, C23)';
    pendingStage('t8-image-identity', reason);
    pendingStage('t8-image-authenticity', reason);
    pendingStage(
      't8-image-activation',
      judged
        ? `no pinned T8 image is hosted by ${runId ?? 'this run'}, so there is nothing to bind (v5 C5, C23)`
        : reason
    );
    return;
  }
  const images = [
    ...new Set(
      Object.values(judged.manifest.runs)
        .filter(run => run.platform === 'container' && run.hostRuns.includes(runId))
        .flatMap(run => Object.values(run.images).filter(Boolean))
        .map(item => item.image)
    ),
  ].sort();
  const [inspect, ...inspectArgs] = t8InspectCommand(images);
  stage('t8-image-identity', inspect, inspectArgs, {
    record: { images },
    pending: pendingRecordStages['t8-image-identity'],
  });
  const identityWithheld = () => {
    const identity = recorded('t8-image-identity');
    return identity?.status === 'pending' && identity.command === undefined;
  };
  requirement('t8-image-authenticity', record => {
    if (identityWithheld())
      throw new PendingStage(
        `t8-image-identity was withheld before dispatch, so no observation of the T8 images exists to check their authenticity records against; ${pendingRecordStages['t8-image-authenticity']}`
      );
    record.records = [];
    const identity = recorded('t8-image-identity');
    if (identity?.status !== 'pending' || identity.exit !== 0)
      throw new Error('docker image inspect did not describe the T8 images');
    const observed = parseImageInspection(
      fs.readFileSync(path.join(directory, identity.log), 'utf8'),
      images
    );
    const problems = [];
    const pending = [];
    for (const seen of observed) {
      const name = imageRecordName(seen.image, seen.platform);
      if (!name) {
        problems.push(`Docker described ${seen.image} on no usable platform`);
        continue;
      }
      const sealed = `image-authenticity-${name}`;
      try {
        write(sealed, readEvidence(securityFile('image-authenticity', name)));
      } catch (error) {
        problems.push(
          `no authenticity record of ${seen.image} on ${seen.platform.os}/${seen.platform.architecture}: ${error.code || error.message}`
        );
        continue;
      }
      record.records.push({ image: seen.image, file: sealed });
      const imageRecord = strictJson(
        fs.readFileSync(path.join(directory, sealed)),
        'the image authenticity record'
      );
      const used = { image: seen.image, imageId: seen.id };
      const found = imageAuthenticityProblems(imageRecord, used, seen);
      problems.push(...found);
      if (!found.length) pending.push(...imageAuthorityPending(imageRecord, used));
    }
    t8Observed.push(...observed);
    if (problems.length) throw new Error(problems.join('; '));
    throw new PendingStage([...pending, pendingRecordStages['t8-image-authenticity']].join('; '));
  });
  // t8-image-activation: the binding of the images O will use for T8 to N's sealed identity and
  // authenticity records (activationBinding; F rebuilds it from the sealed run and requires the
  // same). It runs nothing and claims no authenticity. A missing or failed N record fails it.
  requirement('t8-image-activation', record => {
    if (identityWithheld())
      throw new PendingStage(
        `nothing to bind: t8-image-identity was withheld before dispatch, so no T8 image was observed; ${pendingRecordStages['t8-image-activation']}`
      );
    for (const name of ['t8-image-identity', 't8-image-authenticity'])
      if (recorded(name)?.status !== 'pending')
        throw new Error(`${name} did not complete, so there is nothing to bind (v5 C5)`);
    const binding = activationBinding({
      name: path.basename(directory),
      record: evidence,
      get: name => readEvidence(path.join(directory, name)),
      has: name =>
        Boolean(fs.lstatSync(path.join(directory, name), { throwIfNoEntry: false })?.isFile()),
      catalogSha256: catalog.sha256,
    });
    write(activationBindingFile, binding);
    record.binding = activationBindingFile;
    throw new PendingStage(pendingRecordStages['t8-image-activation']);
  });
}

// The test stages of a run: the gate's own Node (current-runtime) plus the configured Node 24
// executable (minimum-runtime) when that executable is different, each followed directly by its
// coverage check when the candidate has a platform contract, and then, on Linux, the network
// record. The runtimes the test stages will run are found first
// (minimum-runtime-available) and identified before any test stage starts (runtime-identity):
// v5 C23 puts test-host and runtime-identity before the full-test stages, and each test stage is
// dispatched only once both have passed (testStage; GD5-CARRY-01). A maintenance (B35) run
// identifies its runtimes the same way, exactly the ones planned here, so its test stages can
// start once identified (GDR6-REQ-01). The T8 image stages come before any candidate code
// (t8Images). Each test stage is planned whether or not it may be dispatched; one that is withheld
// (testStage) is recorded pending, and so is its coverage stage. `contract` is whether the run
// records the platform contract's stages (contractStages): only those have coverage and network
// stages.
function runTests(prefix, testFiles, runId, contract = platformContract()) {
  const args = ['--test', '--test-reporter=tap', '--import', './test/setup.mjs', ...testFiles];
  const minimumNode =
    process.env.ORBIT_SECURITY_NODE24 ||
    (process.versions.node.startsWith('24.') ? process.execPath : '');
  let minimumVersion;
  const minimumAvailable = requirement('minimum-runtime-available', () => {
    const version =
      minimumNode &&
      spawnSync(minimumNode, ['--version'], { encoding: 'utf8', env: stageEnvironment });
    if (!version || version.status !== 0 || !/^v24\./.test(version.stdout))
      throw new Error('Set ORBIT_SECURITY_NODE24 to a supported Node 24 executable');
    write('node24-version.txt', version.stdout);
    minimumVersion = version.stdout.trim();
  });
  const planned = [
    {
      slot: 'current-runtime',
      executable: process.execPath,
      version: process.version,
    },
  ];
  if (minimumAvailable && minimumNode !== process.execPath)
    planned.push({ slot: 'minimum-runtime', executable: minimumNode, version: minimumVersion });
  // Each runtime's binary is hashed here, once (runtimeOf), and the test stage records it. In a
  // maintenance run too (GDR6-REQ-01): its `runId` is null, so runtime-identity asks for no
  // runtime of a manifest, only the identity of each planned one.
  for (const item of planned) runtimeOf(item.executable, item.version);
  runtimeIdentity(
    runId,
    planned.map(item => item.version)
  );
  for (const item of planned) {
    const tested = testStage(prefix, item.slot, item.executable, item.version, args);
    if (!contract) continue;
    if (tested?.record) coverageStage(tested, runId);
    else if (tested?.withheld)
      pendingStage(
        `platform-coverage-${item.slot}`,
        `${tested.withheld} was withheld before dispatch, so there is no run of it to check`
      );
  }
  // A gate run always reports the T8 image stages (pending when it hosts no image); a companion
  // only when its run hosts one, as darwin-full does, which has no reviewed catalog array yet.
  if (contract && process.platform === 'linux') networkPolicy();
}

// A companion run (platform mode): the run's files (every test file for "all") on this host,
// on each runtime, with the same test environment and checks as the gate's own test stages. Its
// stages are the catalog's darwin-platform array (v3 C23). That array has one prepared-inputs
// stage where this draft makes its own snapshot and installs dependencies on the companion host:
// those steps are recorded inside it, and it stays pending, because v3's prepared inputs come
// from the gate run's phase N, which this draft does not hand to a companion (v3 C22).
function runCompanion(preparedSteps) {
  const run =
    judged?.manifest && Object.hasOwn(judged.manifest.runs, platformRunId)
      ? judged.manifest.runs[platformRunId]
      : null;
  testHost();
  npmStage('npm-version', ['--version']);
  // Its npm ci needs the barrier and a qualified host listener, as the gate run's does: withheld,
  // never a direct registry fallback (maintainer note 014104).
  dependenciesInstalled = npmStage(
    'dependencies-install',
    ['ci', '--ignore-scripts', '--no-audit', '--no-fund'],
    { into: preparedSteps }
  );
  requirement('prepared-inputs', record => {
    record.steps = preparedSteps;
    const failed = preparedSteps
      .filter(step => !['pass', 'pending'].includes(step.status))
      .map(step => step.name);
    if (failed.length) throw new Error(`the local preparation did not pass: ${failed.join(', ')}`);
    throw new PendingStage(
      [
        ...preparedSteps
          .filter(step => step.status === 'pending')
          .map(step => `${step.name} was withheld before dispatch (its step record says why)`),
        "this companion made its own snapshot and installed its own dependencies; v3's prepared inputs come from the gate run's phase N (v3 C22, C23)",
      ].join('; ')
    );
  });
  // The T8 image stages before any candidate code, for a companion whose run hosts T8 (as
  // darwin-full does).
  if (run && platformContract() && hostsImages(judged.manifest, platformRunId))
    t8Images(platformRunId);
  if (run && platformContract())
    runTests(
      'platform-tests-',
      run.files === 'all' ? ['test/**/*.test.mjs'] : run.files,
      platformRunId
    );
}

// The trusted bootstrap of v3 C1 and C17 item 7, which checks the gate identity and the complete
// import closure before any stage runs, does not exist in this draft: its two stages are pending.
const bootstrapPending = `the trusted bootstrap that checks the gate identity (version ${GATE_IDENTITY_VERSION}, its ${GATE_IDENTITY_PARTS.length} parts; versions 1 and 2 are refused) and its complete import closure before any stage runs is not implemented in this draft (v4 C1, C2, C17 item 7)`;
// In platform mode the snapshot steps are recorded inside prepared-inputs (runCompanion).
const preparedSteps = [];
const companionStep = mode === 'platform' ? { into: preparedSteps } : {};
// The gate files a candidate must carry unchanged (its own copy runs here).
const gateFiles = [
  'scripts/security-gate.mjs',
  'scripts/security-evidence.mjs',
  'scripts/security-findings.mjs',
  'scripts/security-finalization.mjs',
  'scripts/security-platform.mjs',
  'scripts/security-catalog.mjs',
  'scripts/security-catalog.json',
  'scripts/security-entries.mjs',
  'scripts/security-gate-identity.mjs',
  'scripts/security-dispatch.mjs',
  'scripts/security-authority.mjs',
  'scripts/check-platform-coverage.mjs',
];
// Whether the run records the stages of the platform contract: a candidate with one, and, in a
// commit or release run whose platform-manifest judgment gave no result at all, also then (it is
// not known whether the candidate has a contract, so its stages are recorded, pending or withheld,
// rather than left out).
const contractStages = () =>
  platformContract() || (!judged && ['commit', 'release'].includes(mode));

try {
  if (mode !== 'scan') {
    pendingStage('gate-identity', bootstrapPending);
    pendingStage('gate-import-closure', bootstrapPending);
  }
  // GDR10-AUTH-STAGE-01: the clone gets the stage environment alone (no selector of this
  // repository, its index or its quarantine), and the snapshot's own two steps are bound to the
  // snapshot: by a binding of the new clone itself (bindRepository, as every authority read is
  // bound), named explicitly to both, so neither reads nor writes this repository's index, working
  // tree or objects. A clone that does not bind as itself is no snapshot.
  if (
    !stage('snapshot-clone', 'git', ['clone', '--no-checkout', '--quiet', root, source], {
      spawn: { cwd: scratch },
      ...companionStep,
    })
  )
    throw new Error('Cannot construct the candidate snapshot');
  let snapshot;
  try {
    snapshot = bindRepository(source, { env: stageEnvironment });
  } catch (error) {
    throw new Error(`Cannot construct the candidate snapshot: ${error.message}`);
  }
  if (snapshot.top !== fs.realpathSync.native(source))
    throw new Error(
      `Cannot construct the candidate snapshot: Git finds the working tree ${snapshot.top} at the snapshot ${source}`
    );
  const inSnapshot = {
    environment: boundStageEnvironment(snapshot, stageEnvironment),
    ...companionStep,
  };
  if (
    !stage('snapshot-index', 'git', ['read-tree', tree], inSnapshot) ||
    !stage('snapshot-files', 'git', ['checkout-index', '--all'], inSnapshot)
  )
    throw new Error('Cannot construct the candidate snapshot');
  files = sourceManifest(source, git('ls-tree', '-rz', '--full-tree', tree));
  write('source-manifest.json', files);
  // gate-implementation (v3 C3, phase N): the gate that runs is the candidate's own copy. In a
  // companion run, whose catalog has no such stage, it is a step of prepared-inputs.
  if (
    !requirement(
      'gate-implementation',
      record => {
        record.files = gateFiles;
        for (const file of gateFiles)
          if (
            sha256(fs.readFileSync(path.join(root, file))) !==
            sha256(fs.readFileSync(path.join(source, file)))
          )
            throw new Error('Stage the gate implementation before validating its candidate');
      },
      companionStep
    )
  )
    throw new Error('Stage the gate implementation before validating its candidate');
  const pins = JSON.parse(
    fs.readFileSync(path.join(source, 'scripts/security-tools.json'), 'utf8')
  );
  evidence.tools = pins;
  write(
    'tool-config.json',
    fs.readFileSync(path.join(source, 'scripts/security-tools.json'), 'utf8')
  );
  write('refs.txt', refs);
  requirement('candidate-policy', () => {
    // Trivy removes inline-ignored resources before reporting findings, even with an empty
    // external ignore file. No inline exemptions are accepted until reviewed dispositions
    // are implemented; this applies to Docker, Terraform and YAML/Helm scan inputs.
    for (const { file } of files) {
      if (/(?:^|\/)\.semgrepignore$/.test(file))
        throw new Error('Candidate Semgrep ignore files cannot narrow the required scan');
      if (!/(?:^|\/)(?:[^/]*dockerfile[^/]*|[^/]+\.(?:tf|tfvars|hcl|ya?ml))$/i.test(file)) continue;
      if (/^\s*(?:#|\/\/)\s*trivy:ignore:/im.test(fs.readFileSync(path.join(source, file), 'utf8')))
        throw new Error(`Inline Trivy suppression is not a reviewed disposition: ${file}`);
    }
    // npm reads the snapshot's .npmrc for every npm stage below. Its script-shell or
    // node-options can make an `npm run` stage pass without running the check (the log still
    // names the script), and its audit-level decides when an audit stage fails. So no tracked
    // .npmrc is accepted, in any directory or letter case (a case-insensitive file system
    // reads `.NPMRC` as `.npmrc`).
    const npmrc = files.find(({ file }) => /(?:^|\/)\.npmrc$/i.test(file));
    if (npmrc)
      throw new Error(`A tracked .npmrc can change what every npm stage runs: ${npmrc.file}`);
    // Actionlint reads .github/actionlint.yaml or .yml, whose ignore rules silence findings
    // (security review GD-R2). workflow-analysis names the gate-owned configuration with -config-file,
    // and a candidate configuration is refused here too, before anything is installed or run.
    const actionlintFile = files.find(({ file }) => actionlintCandidateConfig(file));
    if (actionlintFile)
      throw new Error(
        `A tracked Actionlint configuration can silence workflow findings: ${actionlintFile.file}`
      );
    // The lint stages run these files directly, so `npm run lint:sql` and `npm run lint:imports`
    // must run the same commands: a script changed to do something else (or nothing) is refused.
    // package.json must be in canonical form (JSON.stringify with two-space indentation and a
    // final newline, which is what Prettier writes for it): text with a duplicate member, such as
    // a second `scripts` or `lint:sql`, reads one way to a reviewer while JSON.parse and npm
    // take the last one, and Prettier keeps it.
    const packageText = fs.readFileSync(path.join(source, 'package.json'), 'utf8');
    const packageJson = JSON.parse(packageText);
    if (packageText !== `${JSON.stringify(packageJson, null, 2)}\n`)
      throw new Error(
        'package.json must be in canonical form (two-space JSON.stringify and a final newline), so no duplicate member can make it ambiguous'
      );
    const { scripts } = packageJson;
    for (const [script, file] of Object.entries(lintCommands))
      if (!Object.hasOwn(scripts ?? {}, script) || scripts[script] !== `node ${file}`)
        throw new Error(`package.json ${script} must be "node ${file}", the command the gate runs`);
    if (
      mode === 'commit' &&
      !git('diff', '--cached', '--name-only', 'HEAD').split('\n').includes('CHANGELOG.md')
    )
      throw new Error('Every proposed commit must update CHANGELOG.md');
    if (
      mode === 'release' &&
      (tree !== git('rev-parse', 'HEAD^{tree}') || git('status', '--porcelain'))
    )
      throw new Error('Release validation requires an unchanged committed source tree');
    const dockerfile = fs.readFileSync(path.join(source, 'Dockerfile'), 'utf8');
    for (const line of dockerfile.split('\n').filter(line => /^\s*FROM\s/i.test(line))) {
      if (!/^\s*FROM\s+\S+@sha256:[a-f0-9]{64}(?:\s+AS\s+\S+)?\s*$/i.test(line))
        throw new Error('Every release base image must be pinned by digest');
    }
  });
  // platform-manifest, in every mode (the CI scan included: its candidate-controlled stages need the
  // same two prerequisites; maintainer note 014104 items 2 and 4). It reads the candidate's manifest and
  // history from Git as objects and runs no candidate code.
  judgePlatform();
  // GDR4-01: the one pre-dispatch barrier, decided here, once, after candidate-policy and
  // platform-manifest have completed and before anything candidate-controlled is dispatched, and
  // the dispatch authorities with it (none in this draft). From here on stage() and npmStage()
  // dispatch a candidate-controlled command, dependencies-install included, only while the barrier
  // is open; a closed barrier withholds each, recorded pending with why, and the run is blocking.
  barrier = preDispatchBarrier(evidence.stages, {
    runStarted: evidence.started,
    now: new Date().toISOString(),
  });
  authorities = decideAuthorities(dispatchAuthority);
  console.log(
    barrier.open
      ? 'Pre-dispatch barrier: open (candidate-policy and platform-manifest passed)'
      : `Pre-dispatch barrier: closed, nothing candidate-controlled is dispatched: ${barrier.problems.join('; ')}`
  );
  if (mode === 'platform') runCompanion(preparedSteps);
  else {
    for (const [tool, flag] of [
      ['gitleaks', 'version'],
      ['trivy', '--version'],
    ]) {
      requirement(`${tool}-version`, () => {
        const version = spawnSync(
          tool,
          tool === 'trivy' ? [flag, '--config', trivyConfig] : [flag],
          {
            encoding: 'utf8',
            env: tool === 'trivy' ? trivyEnvironment : stageEnvironment,
          }
        );
        write(`${tool}-version.txt`, `${version.stdout || ''}${version.stderr || ''}`);
        if (
          version.status !== 0 ||
          !new RegExp(`\\b${pins[tool].replaceAll('.', '\\.')}\\b`).test(version.stdout)
        )
          throw new Error(`Install the reviewed ${tool} version ${pins[tool]}`);
      });
    }
    // actionlint-version: Actionlint may run only by the exact path, version, sha256, platform,
    // provenance and dependency closure that the qualified golden-tool manifest of the trusted
    // gate export binds (maintainer decision 8; v4 C4, C7), never as whatever `actionlint` is first on
    // PATH (security review GD-R2). That manifest does not exist in this draft, and neither does the
    // trusted bootstrap that would give the gate its binding (the gate identity's toolPinsSha256
    // and toolPaths, v4 C1). So this stage, and workflow-analysis with it, is pending AND blocking:
    // the stage names the missing pin and the evidence it needs (missingPin), the run exits
    // nonzero, and nothing runs. Nothing falls back to an `actionlint` on PATH, a download (latest
    // or pinned), a hash of whatever binary is found, a skip or continue-on-error. A golden-tool
    // record under <git common dir>/orbit-security/golden-tools/ is a local file that nothing
    // authenticates: the gate does not read it or run what it names, whatever hash it pins
    // (verify-1 of gate-draft-r3 found a record pinning the PATH binary by its observed hash
    // passing both stages). The other stages still run; none of them is an Actionlint pass.
    const missingActionlint = missingToolPin({
      tool: 'actionlint',
      version: pins.actionlint,
      platform: process.platform,
      arch: process.arch,
    });
    const localActionlintRecord = securityFile(
      'golden-tools',
      goldenToolName('actionlint', process.platform, process.arch)
    );
    const missingActionlintReason = () =>
      `BLOCKING: no qualified Actionlint pin. Missing: the qualified golden-tool manifest's binding of Actionlint ${pins.actionlint} on ${process.platform}/${process.arch}, with ${missingActionlint.evidence.join('; ')}.${fs.lstatSync(localActionlintRecord, { throwIfNoEntry: false }) ? ` A local golden-tool record exists at ${localActionlintRecord}: it gives no authority, so it was not read and nothing it names ran.` : ''} The pin is pending and this run cannot pass (v4 C4, C7; maintainer decision 8)`;
    requirement('actionlint-version', record => {
      record.missingPin = missingActionlint;
      throw new PendingStage(missingActionlintReason());
    });
    // docker-version: `docker version` reaches the Docker endpoint, so it needs the reviewed stage
    // policy for it and a qualified endpoint (v5 C5 decision 7), neither of which exists: withheld,
    // pending (stage(), `docker-version-query`), as every other Docker dispatch of the gate is.
    stage('docker-version', 'docker', ['version']);
    npmStage('npm-version', ['--version']);
    // 1.5's SQL and import-graph rules are separate commands that `npm run check` and the CI test
    // jobs do not run. They are offline and quick, so the commit, release and scan modes run them
    // (a companion run, in platform mode, runs neither), but only once the pre-dispatch barrier is
    // open: they are candidate code. A closed barrier records both pending, withheld before
    // dispatch, so a candidate that breaks them still gets no green scan. On a CI runner the
    // scan's barrier stays closed for a 1.5 commit: its candidate is the checked-out commit's tree
    // on top of that commit, which holds test/platform-manifest.json, and platform-manifest then
    // needs a commit the gate approved or a reviewed baseline disposition, which live only in the
    // local <git common dir>/orbit-security; so the CI scan runs neither lint (verify-1 of
    // gate-draft-r5). No scanner here (Semgrep, SonarQube) implements these rules, so neither
    // replaces them. They run the candidate's own lint sources with this Node, before dependencies
    // are installed or any other stage runs candidate code, not through npm and without
    // NODE_OPTIONS (see the top), so no .npmrc, node_modules/.bin entry or earlier stage can make
    // them pass without running. They need no authority, and nothing contains them: they inherit
    // this environment, DOCKER_HOST and the Docker client on PATH among it, so they can reach a
    // Docker client or the Docker endpoint themselves (v5 C5 decision 7's containment is pending).
    // import-lint also runs the table registry's modules, in a child process whose table list is
    // all it uses (scripts/import-graph.mjs). A process can still signal its parent:
    // --disable-sigusr1 keeps SIGUSR1 from opening the lint's inspector, through which that child
    // could run code in the lint (process.exit(0) with a finding pending). Those modules still run
    // with the developer's privileges, like every candidate script, so review covers them as lint
    // inputs.
    // The T8 image identity and authenticity (N) and the activation that binds them (O), before
    // the first candidate code (sql-lint) and so before both image builds, for the run of the
    // platform manifest this gate run is (v5 C3, C23; t8Images).
    if (mode !== 'scan' && contractStages())
      t8Images(judged?.manifest ? fullRunOf(judged.manifest, process.platform) : null);
    // The first candidate code: dispatched only while the pre-dispatch barrier is open (stage()).
    stage('sql-lint', process.execPath, [lintCommands['lint:sql']]);
    stage('import-lint', process.execPath, ['--disable-sigusr1', lintCommands['lint:imports']]);
    // v3 C3 runs the two lints first in phase O on a read-only pristine copy made in N. This
    // draft runs them here, on the snapshot before anything is installed, and makes no such copy.
    pendingStage(
      'pristine-copy',
      'this draft makes no read-only pristine copy: it runs the lints on the snapshot before installation, in one local run (v3 C3)'
    );
    // dependencies-install and the npm audit stages reach the npm registry: v5 lets them use only
    // a qualified host listener's verified cache, and direct registry access is no fallback (C3,
    // C6, C14 change 10; maintainer note 014104). This draft has no listener (gate-network and int-d own it),
    // so each is withheld, pending, as are the npm script stages, which need what it installs. Each
    // is recorded, withheld or not, so a required stage is never simply missing.
    dependenciesInstalled = npmStage('dependencies-install', [
      'ci',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
    ]);
    npmStage('format', ['run', 'format:check']);
    npmStage('syntax-manifest', ['run', 'check']);
    npmStage('documentation', ['run', 'docs:check']);
    npmStage('dependencies-all', ['audit', '--json']);
    npmStage('dependencies-production', ['audit', '--omit=dev', '--json']);
    npmStage('registry-signatures', ['audit', 'signatures']);
    // workflow-analysis: pending AND blocking with actionlint-version (above), naming the same
    // missing pin: nothing runs until the qualified golden-tool manifest binds Actionlint (maintainer
    // decision 8). Once it does, the gate must run exactly the bound binary with the gate-owned
    // empty configuration and no external shellcheck or pyflakes (actionlintArguments), hash it
    // and its dependency closure immediately before and after, and seal its record; the finalizer
    // already checks a run for that (scripts/security-finalization.mjs, actionlintProblems).
    requirement('workflow-analysis', record => {
      record.missingPin = missingActionlint;
      throw new PendingStage(
        `BLOCKING: no qualified Actionlint pin, so nothing ran (actionlint-version is pending): ${recorded('actionlint-version')?.reason ?? missingActionlintReason()}`
      );
    });
    // Explicit default config prevents repository scanner exclusions from hiding findings.
    const leakConfig = path.join(directory, 'gitleaks.toml');
    write('gitleaks.toml', '[extend]\nuseDefault = true\n');
    const leakArgs = [
      '--config',
      leakConfig,
      '--redact=100',
      '--exit-code',
      '10',
      '--no-banner',
      '--ignore-gitleaks-allow',
      '--gitleaks-ignore-path',
      path.join(directory, 'no-ignored-findings'),
      '--max-archive-depth',
      '4',
      '--max-decode-depth',
      '4',
      '--report-format',
      'json',
    ];
    stage('secrets-source', 'gitleaks', [
      'dir',
      ...leakArgs,
      '--report-path',
      path.join(directory, 'secrets-source.json'),
      '.',
    ]);
    // The history scan's Git reads this repository as the binding above validated it, with no lazy
    // fetch and no injected configuration (historyEnvironment; GDR10-AUTH-STAGE-01), and since round
    // 2 no configuration, attributes or ignore file the caller's environment chooses. Since
    // gate-draft-r12 (GDR11-HISTORY-ATTRS-01) its log options (HISTORY_LOG_OPTIONS) make each patch
    // Git shows show its changes as their own text whatever the repository's attributes, diff
    // drivers, text converters or own configuration say, with no converter or external diff run (a
    // merge shows no patch, and some settings still change header bytes, not content: see
    // HISTORY_LOG_OPTIONS). That is the Git
    // command's input; what the pinned Gitleaks reports with these options is still to be qualified.
    stage(
      'secrets-history',
      'gitleaks',
      [
        'git',
        ...leakArgs,
        `--log-opts=${HISTORY_LOG_OPTIONS.join(' ')}`,
        '--report-path',
        path.join(directory, 'secrets-history.json'),
        root,
      ],
      { environment: historyEnvironment }
    );
    // Git diff scanners do not inspect commit/tag messages; scan those explicitly too. Since
    // gate-draft-r12 (GDR11-AUTH-CONFIG-01) they are every commit and tag object as Git stores it,
    // headers included, read raw and checked object by object and for a complete enumeration
    // (metadataScanInput); nothing formats them, so no configuration can change them. When they
    // cannot be read completely, or as the text Git shows (since round 2 a commit's encoding header
    // must name one whose ASCII text is its own bytes), the scan is not started on part of them: it
    // is blocked, with why.
    let messages;
    try {
      messages = metadataScanInput(
        (args, input) => gitBinding.run(args, input, { maxBuffer: 1024 ** 3 }),
        { head: parent }
      );
    } catch (error) {
      messages = error;
    }
    if (messages instanceof Error)
      requirement('secrets-metadata', () => {
        throw new Error(
          `The commit and tag metadata cannot be given to the secret scan complete: ${messages.message}`
        );
      });
    else {
      write('history-messages.txt', messages.commits);
      write('tag-messages.txt', messages.tags);
      const metadata = path.join(scratch, 'metadata');
      fs.mkdirSync(metadata);
      for (const name of ['history-messages.txt', 'tag-messages.txt'])
        fs.copyFileSync(path.join(directory, name), path.join(metadata, name));
      stage('secrets-metadata', 'gitleaks', [
        'dir',
        ...leakArgs,
        '--report-path',
        path.join(directory, 'secrets-metadata.json'),
        metadata,
      ]);
    }

    // image-approval (v3 C3, C5): every image the run builds from, runs or scans needs a reviewed
    // activation record for that use before it is used. None is defined or reviewed yet, so this
    // is pending. It comes before the Semgrep run, both builds, the scans of the built image and
    // the test stages (v5 C3, C23). Neither the Semgrep image's inspect nor its run is dispatched
    // while it is pending (`semgrep-image`, maintainer note 014104 item 3): source-analysis stays required,
    // pending and blocking, and no host binary stands in. In a commit or release run the builds do
    // not start (below). The image-authority successor owns the Docker, Compose and Buildx
    // enforcement (security review IP-01 to IP-05).
    pendingStage(
      'image-approval',
      'no reviewed activation record exists for the images this run builds from, runs or scans (v3 C5, C17 item 12)'
    );
    // sast-rules (v3 C3, C10, C23): one stage, as the catalog names it, made of three steps that
    // are recorded inside it: the pinned Semgrep rules archive downloaded (until the controller
    // stages it, C10), checked against its pinned sha256, and extracted. The download is one of
    // the five stages v5 serves only from a qualified host listener (C14 change 10), with no direct
    // download as a fallback, so it is withheld and sast-rules is pending (maintainer note 014104).
    const rulesArchive = path.join(scratch, 'rules.tar.gz');
    const ruleSteps = [];
    const verified = requirement('sast-rules', record => {
      const download = dispatchDecision('sast-rules-download', dispatchState());
      if (!download.dispatch) throw new PendingStage(withheldReason(download.reasons));
      record.steps = ruleSteps;
      if (
        !stage(
          'sast-rules-download',
          'curl',
          [
            '--fail',
            '--silent',
            '--show-error',
            '--location',
            '--proto',
            '=https',
            '--proto-redir',
            '=https',
            '--max-time',
            '120',
            '--output',
            rulesArchive,
            `https://codeload.github.com/semgrep/semgrep-rules/tar.gz/${pins.semgrepRulesCommit}`,
          ],
          { into: ruleSteps }
        )
      )
        throw new Error('The Semgrep rules archive could not be downloaded');
      if (sha256(fs.readFileSync(rulesArchive)) !== pins.semgrepRulesSha256)
        throw new Error('Semgrep rules archive checksum mismatch');
      if (
        !stage('sast-rules-extract', 'tar', ['-xzf', rulesArchive, '-C', scratch], {
          into: ruleSteps,
        })
      )
        throw new Error('The Semgrep rules archive could not be extracted');
    });
    if (verified) {
      const rules = path.join(scratch, `semgrep-rules-${pins.semgrepRulesCommit}`);
      // Include every JavaScript security ruleset. Correctness/style rules have separate gates.
      const configs = fs
        .readdirSync(path.join(rules, 'javascript'), { recursive: true, withFileTypes: true })
        .filter(entry => entry.isDirectory() && entry.name === 'security')
        .map(entry => path.relative(rules, path.join(entry.parentPath, entry.name)));
      if (!configs.length) throw new Error('No JavaScript security rules found');
      write('sast-rules.json', configs);
      // The adapter replaces built-in test ignores without adding files to the candidate.
      const adapter = path.join(scratch, 'semgrep-adapter');
      fs.mkdirSync(path.join(adapter, 'source'), { recursive: true, mode: 0o700 });
      fs.copyFileSync(path.join(directory, 'semgrepignore'), path.join(adapter, '.semgrepignore'));
      // sast-image (v3 C3, C5): the pinned Semgrep image must already be in the local image store;
      // nothing is pulled (C5 allows no pull). Its activation record is pending (image-approval),
      // so neither this inspect nor the run below is dispatched (stage(), `semgrep-image`).
      if (
        stage('sast-image', 'docker', [
          'image',
          'inspect',
          '--format',
          '{{json .}}',
          pins.semgrepImage,
        ])
      ) {
        stage('source-analysis', 'docker', [
          'run',
          '--memory=2g',
          '--cpus=2',
          '--pids-limit=256',
          '--rm',
          '--network=none',
          '--cap-drop=ALL',
          '--security-opt=no-new-privileges',
          '--read-only',
          '--tmpfs',
          '/tmp:rw,nosuid,nodev,size=512m',
          '--user',
          `${process.getuid()}:${process.getgid()}`,
          '--env',
          'HOME=/tmp',
          '--mount',
          `type=bind,src=${adapter},dst=/scan,readonly`,
          '--mount',
          `type=bind,src=${source},dst=/scan/source,readonly`,
          '--mount',
          `type=bind,src=${rules},dst=/rules,readonly`,
          '--mount',
          `type=bind,src=${directory},dst=/reports`,
          '--workdir',
          '/scan/source',
          pins.semgrepImage,
          'semgrep',
          'scan',
          ...configs.flatMap(config => ['--config', `/rules/${config}`]),
          '--metrics=off',
          '--disable-version-check',
          '--disable-nosem',
          '--no-git-ignore',
          '--project-root',
          '/scan',
          '--strict',
          '--error',
          '--json',
          '--output',
          '/reports/source-analysis.json',
          '--exclude',
          'node_modules',
          '.',
        ]);
      } else
        withholdAfter(
          'source-analysis',
          `sast-image is ${recorded('sast-image')?.status}, so the pinned Semgrep image is not known to be present`
        );
    } else
      for (const name of ['sast-image', 'source-analysis'])
        withholdAfter(
          name,
          `the Semgrep rules are not staged: sast-rules is ${recorded('sast-rules')?.status}`
        );
    stage('container-configuration', 'trivy', [
      'config',
      ...trivyPolicy,
      '--quiet',
      '--exit-code',
      '10',
      '--format',
      'json',
      '--output',
      path.join(directory, 'container-configuration.json'),
      '.',
    ]);
    // container-build and systemd-test-image run the RUN steps of the candidate's own Dockerfiles:
    // candidate-controlled build instructions (v5 C3). v5 C5 (change 3) lets a build start only
    // once its complete pre-build authority is approved and sealed (its bases, context, Dockerfile,
    // arguments, platform, builder and endpoint, the reviewed stage policy and its boundaries),
    // and its result counts only through a same-run result record sealed as soon as it ends and
    // verified before anything uses it. Both record forms are pending, with no producer (v5 C17
    // item 12), so in a commit or release run neither build starts: each is recorded pending, and
    // so are container-identity, which would verify the result, and the two scans of the image,
    // which has not been built. `FROM scratch` is no exception (v5 change 15). A closed
    // pre-dispatch barrier is named as well: a platform-manifest that did not pass stops every
    // candidate-controlled build (change 19; GDR4-01). The test stages' own image builds start only
    // with the test stages, which are withheld while their authority is missing (testStage).
    //
    // The CI security scan (scan mode) is not a gate run: it has no catalog, phase, T8 stage or
    // finalization, and approves nothing. It builds the candidate's image only with the barrier
    // open and `scan-image-build` authority (pre-build authority for the build: approved staged
    // bases, context, Dockerfile, arguments, platform, qualified builder and endpoint), and never
    // with --pull (v5 C5: no pull anywhere); without that authority it dispatches nothing to Docker
    // (maintainer note 014104 item 2): no build, no pull, and no image already in the store stands in. Its
    // container stages are then pending, and the scan is blocking.
    if (mode !== 'scan') {
      withhold('container-build', [pendingRecordStages['container-build'], ...closedBarrier()]);
      withhold('container-identity', [
        pendingRecordStages['container-identity'],
        ...closedBarrier(),
      ]);
      for (const name of builtImageStages)
        withhold(name, [
          'the image it would scan is not built: container-build is pending, so that build did not start (v5 C5 change 3, C17 item 12)',
          ...closedBarrier(),
        ]);
    } else {
      const candidateImage = `orbit-security:${tree.slice(0, 12)}-${randomUUID().slice(0, 8)}`;
      const built = stage('container-build', 'docker', ['build', '--tag', candidateImage, '.']);
      // Removed afterwards only if the build was dispatched (under its authority).
      if (recorded('container-build')?.command) image = candidateImage;
      if (built) {
        stage('container-identity', 'docker', ['image', 'inspect', image]);
        stage('container-vulnerabilities', 'trivy', [
          'image',
          ...trivyPolicy,
          '--secret-config',
          trivySecrets,
          '--quiet',
          '--exit-code',
          '10',
          '--scanners',
          'vuln,secret',
          '--image-config-scanners',
          'misconfig,secret',
          '--format',
          'json',
          '--output',
          path.join(directory, 'container-security.json'),
          image,
        ]);
        stage('container-sbom', 'trivy', [
          'image',
          ...trivyPolicy,
          '--secret-config',
          trivySecrets,
          '--quiet',
          '--format',
          'cyclonedx',
          '--output',
          path.join(directory, 'container-sbom.json'),
          image,
        ]);
      } else
        for (const name of ['container-identity', ...builtImageStages])
          withholdAfter(
            name,
            `the image it would ${name === 'container-identity' ? 'inspect' : 'scan'} was not built: container-build is ${recorded('container-build')?.status}`
          );
    }
    stage('scanner-database', 'trivy', ['--version', '--config', trivyConfig, '--format', 'json']);
    if (mode !== 'scan') {
      // Pending under the isolation hold, and with no pre-build authority record: not built.
      withhold('systemd-test-image', [
        pendingRecordStages['systemd-test-image'],
        ...closedBarrier(),
      ]);
      // Both full test runs, on this host's full run of the platform manifest. Their environment
      // (testEnvironment) sets every TEST_REQUIRE name that makes a 1.5 suite fail instead of
      // skipping, including the 250,000-row audit capacity measurement and Git, which the
      // documentation, gate, commit guard and SonarQube tests run (test/helpers/git.mjs): a gate
      // without Git fails, never passes them as skips (`testRequire` in security-platform.mjs).
      // Each is withheld before dispatch while its authority is missing, or until test-host and
      // runtime-identity have passed and apply to it (testStage), in a maintenance run too.
      testHost();
      runTests(
        'full-tests-',
        ['test/**/*.test.mjs'],
        judged?.manifest ? fullRunOf(judged.manifest, process.platform) : null,
        contractStages()
      );
      requirement('independent-review', () => {
        const reviewPath = path.join(common, 'orbit-security', 'reviews', `${tree}.json`);
        const review = JSON.parse(fs.readFileSync(reviewPath, 'utf8'));
        checkReview(review, { tree, parents, files, release: mode === 'release' });
        write('independent-review.json', review);
      });
      // A release run records no sonarqube-analysis stage: SonarQube is the `sonarqube` release
      // obligation of the finalization (v4 C15, C23), which the catalog refuses as a stage name,
      // and it is recorded pending with the other release-only obligations below.
    }
  }
  requirement('candidate-unchanged', () => {
    const heads = candidateParents(root);
    if (
      git('write-tree') !== tree ||
      git('rev-parse', 'HEAD') !== parent ||
      !heads.complete ||
      !sameParents(heads.heads, parents) ||
      git('for-each-ref', '--format=%(refname) %(objectname)') !== refs
    )
      throw new Error('Index, parents or refs changed during validation; rerun');
    if (
      JSON.stringify(sourceManifest(source, git('ls-tree', '-rz', '--full-tree', tree))) !==
      JSON.stringify(files)
    )
      throw new Error('A test or tool changed a tracked snapshot file');
  });
} catch (error) {
  const now = new Date().toISOString();
  // A companion whose preparation failed part way still records its steps.
  if (mode === 'platform' && preparedSteps.length && !recorded('prepared-inputs'))
    evidence.stages.push({
      name: 'prepared-inputs',
      started: preparedSteps[0].started ?? now,
      finished: now,
      status: 'blocked',
      steps: preparedSteps,
      error: error.message,
    });
  evidence.stages.push({
    name: 'gate-execution',
    started: now,
    finished: now,
    status: 'blocked',
    error: error.message,
  });
} finally {
  if (image)
    spawnSync('docker', ['image', 'rm', image], {
      stdio: 'ignore',
      timeout: 60000,
      env: stageEnvironment,
    });
  removeScratch();
  evidence.finished = new Date().toISOString();
  // A release run: final-artifacts and the other release-only obligations of the catalog are F's
  // release obligations (v4 C14, C23; the security review of v3 accepts final-artifacts in F's
  // release array), not stages of a run, and release finalization does not exist. They are
  // recorded pending here, so a release run is never a pass: it fails closed, with exit 1.
  if (mode === 'release') {
    const { commit, release } = catalog.catalog.finalization;
    evidence.releaseObligations = Object.fromEntries(
      release
        .filter(id => !commit.includes(id))
        .map(id => [
          id,
          {
            status: 'pending',
            reason:
              id === 'final-artifacts'
                ? 'release finalization does not exist: final artifact, signature and provenance validation are not automated (v4 C14; docs/engineering-quality.md)'
                : id === 'sonarqube'
                  ? 'an F release obligation (the Mac-side SonarQube analysis, v4 C15), and release finalization does not exist; the gate runs no SonarQube stage (scripts/check-sonarqube.mjs is run by hand, docs/engineering-quality.md)'
                  : 'an F release obligation, and release finalization does not exist (v4 C14, C15, C23)',
          },
        ])
    );
  }
  const obligationsPending = Object.values(evidence.releaseObligations ?? {}).some(
    item => item.status !== 'pass'
  );
  // pass only when every stage passed and no release obligation is pending; pending when nothing
  // failed but something is pending (a stage this draft does not implement, or whose authority
  // is pending); otherwise blocked. Only pass exits 0 (v3 C2: a pending or skipped stage is never
  // a pass).
  evidence.status =
    evidence.stages.every(stage => stage.status === 'pass') && !obligationsPending
      ? 'pass'
      : evidence.stages.every(stage => ['pass', 'pending'].includes(stage.status))
        ? 'pending'
        : 'blocked';
  write('result.json', evidence);
  if (mode === 'commit' || mode === 'platform') {
    try {
      sealRun(directory);
      console.log(
        mode === 'platform'
          ? 'Companion evidence sealed. Name it after the gate run when you inspect and finalize that run.'
          : 'Raw evidence sealed. Inspect and finalize this run after independent review.'
      );
    } catch {
      evidence.status = 'blocked';
      const now = new Date().toISOString();
      evidence.stages.push({
        name: 'evidence-seal',
        started: now,
        finished: now,
        status: 'blocked',
        error: 'Cannot seal run evidence',
      });
      write('result.json', evidence);
    }
  }
  // Name what keeps the run from passing: a pending stage is blocking too (exit 1).
  for (const item of evidence.stages.filter(stage => stage.status === 'pending'))
    console.log(`Pending (blocking): ${item.name}: ${item.reason}`);
  for (const [id, item] of Object.entries(evidence.releaseObligations ?? {}))
    if (item.status !== 'pass')
      console.log(`Pending F release obligation (blocking): ${id}: ${item.reason}`);
  console.log(`Security ${mode}: ${evidence.status}. Evidence: ${directory}`);
  process.exitCode = evidence.status === 'pass' ? 0 : 1;
}
