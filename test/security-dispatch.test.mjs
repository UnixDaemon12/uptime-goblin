// gate-draft-r5: what the gate may dispatch, decided before it dispatches it.
//
// - GDR4-01 (the security review of gate-draft-r4, P1; a new defect fixed): candidate-policy and
//   platform-manifest were recorded, and the gate went on to run candidate code whatever their
//   status. Now one pre-dispatch barrier (scripts/security-dispatch.mjs) withholds every
//   candidate-controlled command and dependencies-install unless both completed in this run with
//   status pass, and a platform-manifest that did not pass also stops every candidate-controlled
//   build.
// - The carried blockers the maintainer's answers 20261016T014104832374Z settle: the test stages (whose
//   tests build images), the scan's image build, the Semgrep image's inspect and run, the T8 image
//   inspect and docker version need an authority that no producer gives in this draft
//   (scripts/security-authority.mjs), so each is withheld, recorded pending with why; the five
//   host-listener stages never fall back to direct registry access.
// - gate-draft-r6, GD5-CARRY-01 (the security review of gate-draft-r5; a disclosed carried
//   integration obligation now enforced, not a new r5 regression): test-host and runtime-identity
//   were recorded before the test stages but were no dispatch condition, so given an authority a
//   test stage started while either was blocked. Each of the four test-stage rules now needs both
//   (runtime-identity where the run records it) recorded once in this run, passed, ended by the
//   decision and applying to the stage (maintainer note 20261017T061149194320Z decision 3).
// - gate-draft-r7, GDR6-REQ-01 (the security review of gate-draft-r6; a required correction under
//   the maintainer's explicit B35 clarification of 20261017T140102522864Z, not a newly introduced r6
//   regression): gate-draft-r6 let a maintenance (B35) run start its test stages with test-host
//   alone, recording no runtime-identity. A maintenance run now identifies its own approved
//   runtimes and is held to both prerequisites like every run; the two tests that pinned the
//   exception are replaced by its negatives and by a real maintenance positive control.
//
// The pure decisions are tested here first; then the dispatch point itself, with logging process
// stand-ins that refuse (they run nothing and exit 97), for every kind of prerequisite that must
// stop a dispatch: pending, blocked, failed, not run, absent, recorded twice, malformed and stale;
// then the real gate in throwaway fixture repositories, whose candidate's lint sources and test
// file are canaries that record each time they run, with logging stand-ins for docker, npm, curl
// and the scanners, and a loopback listener standing for a direct Docker endpoint. Every negative
// control shows zero dispatches; each positive control (a synthetic authority written into the
// fixture, test/helpers/dispatch-authority.mjs) shows exactly one through the same gate. No real
// Docker, npm, registry or scanner runs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { declareGit } from './helpers/git.mjs';
import { allPurposes, syntheticAuthority } from './helpers/dispatch-authority.mjs';
import {
  executableSha256,
  gateRuntimes,
  writeRuntimeIdentity,
} from './helpers/runtime-identity.mjs';

const dispatch = await import('../scripts/security-dispatch.mjs');
const production = await import('../scripts/security-authority.mjs');
const platform = await import('../scripts/security-platform.mjs');
const fixtureImages = await import('./helpers/platform-run.mjs');

// The gate fixtures make Git repositories and run the gate, which runs Git.
const gitSkip = declareGit();
const repository = fileURLToPath(new URL('..', import.meta.url));

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// ---------------------------------------------------------------------------------------------
// The pre-dispatch barrier (GDR4-01)

const runStarted = '2026-10-16T10:00:00.000Z';
const decided = '2026-10-16T10:00:10.000Z';
const passed = name => ({
  name,
  started: '2026-10-16T10:00:01.000Z',
  finished: '2026-10-16T10:00:02.000Z',
  status: 'pass',
});
const both = () => dispatch.PRE_DISPATCH_PREREQUISITES.map(passed);
const barrierOf = (stages, times = { runStarted, now: decided }) =>
  dispatch.preDispatchBarrier(stages, times);

// What a test stage's rule judges besides (GD5-CARRY-01): test-host and runtime-identity, each
// recorded once in this run, passed, ended by the decision and applying to the stage (this host's
// platform; the runtime the stage would use, by its sha256 and version).
const stageRuntime = Object.freeze({ sha256: 'a'.repeat(64), version: 'v26.5.1' });
const hostPassed = () => ({
  name: 'test-host',
  started: '2026-10-16T10:00:03.000Z',
  finished: '2026-10-16T10:00:04.000Z',
  status: 'pass',
  host: { platform: process.platform, uid: 1000, setfacl: null },
});
const identityPassed = () => ({
  name: 'runtime-identity',
  started: '2026-10-16T10:00:05.000Z',
  finished: '2026-10-16T10:00:06.000Z',
  status: 'pass',
  runtimes: [
    {
      path: '/synthetic/node26',
      ...stageRuntime,
      record: `runtime-identity-${stageRuntime.sha256}.json`,
    },
  ],
});
// gate-draft-r7 (GDR6-REQ-01): the gate no longer tells the rule whether the run is a maintenance
// run (gate-draft-r6's `contract`), since no kind of run is exempt; a test that adds such a member
// shows it changes nothing.
const testRunOf = (stages = [...both(), hostPassed(), identityPassed()], overrides = {}) => ({
  stages,
  started: runStarted,
  now: decided,
  platform: process.platform,
  runtime: stageRuntime,
  ...overrides,
});

// Each kind of prerequisite that must keep the barrier closed: [label, change of its record (null
// removes it, an array replaces it), the problem the barrier names].
const prerequisiteCases = name => [
  [
    'pending',
    { status: 'pending', reason: 'synthetic pending' },
    new RegExp(`${name} is pending \\(synthetic pending\\)`),
  ],
  [
    'blocked',
    { status: 'blocked', error: 'synthetic refusal' },
    new RegExp(`${name} is blocked \\(synthetic refusal\\)`),
  ],
  ['failed', { status: 'fail' }, new RegExp(`${name} is fail$`)],
  ['not run', { status: 'not-run' }, new RegExp(`${name} is not-run$`)],
  ['absent', null, new RegExp(`${name} is absent: it has not completed in this run`)],
  ['recorded twice', 'twice', new RegExp(`${name} is recorded 2 times, so it has no one result`)],
  [
    'malformed: an unknown status',
    { status: 'passed' },
    new RegExp(`${name} is malformed: its status "passed" is not a stage status`),
  ],
  [
    'malformed: no status',
    { status: undefined },
    new RegExp(`${name} is malformed: its status undefined`),
  ],
  [
    'malformed: no start',
    { started: undefined },
    new RegExp(`${name} is malformed: it has no valid recorded start and end`),
  ],
  [
    'malformed: not a calendar time',
    { finished: '2026-09-31T10:00:02.000Z' },
    new RegExp(`${name} is malformed: it has no valid recorded start and end`),
  ],
  [
    'malformed: an end before its start',
    { finished: '2026-10-16T10:00:00.500Z' },
    new RegExp(`${name} is malformed: it has no valid recorded start and end`),
  ],
  [
    'stale: begun before this run',
    { started: '2026-10-16T09:59:59.999Z' },
    new RegExp(`${name} is stale: it started before this run did`),
  ],
  [
    'stale: ends after the decision',
    { finished: '2026-10-16T10:00:10.001Z' },
    new RegExp(`${name} is stale: it ends after the barrier was decided`),
  ],
];
const withCase = (name, change) => {
  const stages = both();
  const at = stages.findIndex(stage => stage.name === name);
  if (change === null) stages.splice(at, 1);
  else if (change === 'twice') stages.push({ ...stages[at] });
  else {
    stages[at] = { ...stages[at], ...change };
    for (const key of Object.keys(change)) if (change[key] === undefined) delete stages[at][key];
  }
  return stages;
};

test('GDR4-01: the pre-dispatch barrier opens only when candidate-policy and platform-manifest each passed in this run', () => {
  assert.deepEqual(dispatch.PRE_DISPATCH_PREREQUISITES, ['candidate-policy', 'platform-manifest']);
  const open = barrierOf(both());
  assert.equal(open.open, true);
  assert.deepEqual(open.problems, []);
  assert.equal(open.decided, decided);
  assert.ok(Object.isFrozen(open) && Object.isFrozen(open.problems));
  // The exact boundaries: begun at the run's start, ended at the decision.
  const edges = both().map(stage => ({ ...stage, started: runStarted, finished: decided }));
  assert.equal(barrierOf(edges).open, true);
  for (const name of dispatch.PRE_DISPATCH_PREREQUISITES)
    for (const [label, change, pattern] of prerequisiteCases(name)) {
      const closed = barrierOf(withCase(name, change));
      assert.equal(closed.open, false, `${name} ${label}`);
      assert.ok(
        closed.problems.some(problem => pattern.test(problem)),
        `${name} ${label}: ${closed.problems}`
      );
    }
  // Both missing, a list that is not one, an entry that is not a stage, no valid times.
  assert.equal(barrierOf([]).problems.length, 2);
  assert.match(barrierOf(undefined).problems.join('\n'), /the run has no list of stage records/);
  assert.match(
    barrierOf([...both(), null]).problems.join('\n'),
    /holds an entry that is not a named stage record/
  );
  for (const times of [{}, { runStarted, now: 'now' }, { runStarted: decided, now: runStarted }])
    assert.match(
      barrierOf(both(), times).problems.join('\n'),
      /no valid start and decision time/,
      JSON.stringify(times)
    );
});

// ---------------------------------------------------------------------------------------------
// Dispatch authority (maintainer note 014104)

const syntheticGrant = purpose => ({
  purpose,
  source: 'synthetic test authority',
  reference: 'test fixture only',
});

test('the repository gives no dispatch authority: every purpose is null, from a module that reads nothing', () => {
  assert.deepEqual([...allPurposes].sort(), [
    'docker-version-query',
    'host-listener',
    'scan-image-build',
    'semgrep-image',
    't8-image-inspect',
    'test-image-builds',
  ]);
  for (const purpose of allPurposes) assert.equal(production.dispatchAuthority(purpose), null);
  const decided = dispatch.decideAuthorities(production.dispatchAuthority);
  for (const purpose of allPurposes)
    assert.deepEqual(
      decided[purpose],
      { granted: false, reason: dispatch.DISPATCH_AUTHORITIES[purpose] },
      purpose
    );
  // It imports, reads and runs nothing: a local file or variable cannot become authority.
  const source = fs.readFileSync(
    new URL('../scripts/security-authority.mjs', import.meta.url),
    'utf8'
  );
  const code = source.replace(/^\s*\/\/.*$/gm, '');
  assert.doesNotMatch(code, /\bimport\b|\brequire\b|process\.|readFile|\bfs\b|\benv\b/);
  assert.match(code, /export function dispatchAuthority\(\) \{\s*return null;\s*\}/);
});

test('an authority is exactly { purpose, source, reference } for the purpose asked; anything else grants nothing', () => {
  const granted = dispatch.decideAuthorities(syntheticGrant);
  for (const purpose of allPurposes) {
    assert.equal(granted[purpose].granted, true, purpose);
    assert.deepEqual(granted[purpose].authority, syntheticGrant(purpose));
    assert.ok(Object.isFrozen(granted[purpose].authority));
  }
  for (const [label, provide, pattern] of [
    [
      'an extra member',
      purpose => ({ ...syntheticGrant(purpose), qualified: true }),
      /is malformed/,
    ],
    ['no reference', purpose => ({ purpose, source: 'x' }), /is malformed/],
    ['another purpose', () => syntheticGrant('host-listener-x'), /is malformed/],
    ['an empty source', purpose => ({ ...syntheticGrant(purpose), source: ' ' }), /is malformed/],
    [
      'a control character',
      purpose => ({ ...syntheticGrant(purpose), reference: 'a\nb' }),
      /is malformed/,
    ],
    ['true', () => true, /is malformed/],
    ['a list', purpose => [syntheticGrant(purpose)], /is malformed/],
    [
      'a provider that throws',
      () => {
        throw new Error('synthetic');
      },
      /could not be read \(synthetic\)/,
    ],
  ]) {
    const decided = dispatch.decideAuthorities(provide);
    for (const purpose of allPurposes) {
      assert.equal(decided[purpose].granted, false, `${label}: ${purpose}`);
      assert.match(decided[purpose].reason, pattern, `${label}: ${purpose}`);
      assert.ok(decided[purpose].reason.endsWith(dispatch.DISPATCH_AUTHORITIES[purpose]));
    }
  }
});

// The candidate-controlled stages (GDR4-01) and the operations that need an authority (014104).
const candidateControlled = [
  'sql-lint',
  'import-lint',
  'dependencies-install',
  'format',
  'syntax-manifest',
  'documentation',
  'dependencies-all',
  'dependencies-production',
  'registry-signatures',
  'full-tests-current-runtime',
  'full-tests-minimum-runtime',
  'platform-tests-current-runtime',
  'platform-tests-minimum-runtime',
  'container-build',
  'container-identity',
  'container-vulnerabilities',
  'container-sbom',
  't8-image-identity',
];
const needsAuthority = {
  'docker-version': ['docker-version-query'],
  't8-image-identity': ['t8-image-inspect'],
  'dependencies-install': ['host-listener'],
  'dependencies-all': ['host-listener'],
  'dependencies-production': ['host-listener'],
  'registry-signatures': ['host-listener'],
  'sast-rules-download': ['host-listener'],
  'sast-image': ['semgrep-image'],
  'source-analysis': ['semgrep-image'],
  'container-build': ['scan-image-build'],
  'container-identity': ['scan-image-build'],
  'container-vulnerabilities': ['scan-image-build'],
  'container-sbom': ['scan-image-build'],
  'full-tests-current-runtime': ['test-image-builds'],
  'full-tests-minimum-runtime': ['test-image-builds'],
  'platform-tests-current-runtime': ['test-image-builds'],
  'platform-tests-minimum-runtime': ['test-image-builds'],
};

test('every dispatched stage has its rule: candidate-controlled ones need the barrier, Docker, registry and image builds an authority, and an unknown name is never dispatched', () => {
  const rules = dispatch.DISPATCH_RULES;
  for (const name of candidateControlled) assert.equal(rules[name]?.barrier, true, name);
  for (const [name, purposes] of Object.entries(needsAuthority))
    assert.deepEqual(rules[name]?.authority, purposes, name);
  for (const [name, rule] of Object.entries(rules)) {
    if (!candidateControlled.includes(name)) assert.equal(rule.barrier, false, name);
    if (!needsAuthority[name]) assert.deepEqual(rule.authority, [], name);
  }
  // The gate's own commands need neither.
  for (const name of [
    'snapshot-clone',
    'snapshot-index',
    'snapshot-files',
    'npm-version',
    'secrets-source',
    'secrets-history',
    'secrets-metadata',
    'sast-rules-extract',
    'container-configuration',
    'scanner-database',
  ])
    assert.deepEqual(rules[name], { barrier: false, authority: [], install: false }, name);
  const all = dispatch.decideAuthorities(syntheticGrant);
  const open = barrierOf(both());
  for (const name of ['an-unknown-stage', 'workflow-analysis', 'systemd-test-image', 'sonarqube'])
    assert.deepEqual(
      dispatch.dispatchDecision(name, { barrier: open, authorities: all, installed: true }),
      {
        dispatch: false,
        reasons: [
          `${name} has no dispatch rule in this gate, and an unclassified command is never dispatched`,
        ],
      },
      name
    );
  // Undecided barrier and authorities withhold too.
  for (const name of Object.keys(rules).filter(
    item => rules[item].barrier || rules[item].authority.length
  ))
    assert.equal(dispatch.dispatchDecision(name, {}).dispatch, false, name);
  // Every reason is given at once (here with valid test-host and runtime-identity records, which
  // the test stages need too since gate-draft-r6; their own reasons are tested below).
  const none = dispatch.decideAuthorities(production.dispatchAuthority);
  const decision = dispatch.dispatchDecision('full-tests-current-runtime', {
    barrier: barrierOf(withCase('platform-manifest', { status: 'blocked', error: 'x' })),
    authorities: none,
    installed: false,
    run: testRunOf(),
  });
  assert.equal(decision.dispatch, false);
  assert.equal(decision.reasons.length, 3);
  assert.match(
    decision.reasons[0],
    /^the pre-dispatch barrier is closed: platform-manifest is blocked \(x\)/
  );
  assert.match(
    decision.reasons[1],
    /^no test-image-builds authority: the candidate's tests build images/
  );
  assert.match(decision.reasons[2], /^dependencies-install did not pass in this run/);
  assert.match(
    dispatch.withheldReason(decision.reasons),
    /^withheld before dispatch, nothing ran: /
  );
  // A reason stays within the 2000 characters the finalizer reads (platform.withheldStage).
  const long = dispatch.withheldReason(['x'.repeat(5000)]);
  assert.equal(long.length, 2000);
  assert.ok(long.endsWith('…'));
  assert.equal(
    platform.withheldStage({
      name: 'full-tests-current-runtime',
      started: decided,
      finished: decided,
      status: 'pending',
      reason: long,
    }),
    true
  );
});

// verify-1 of gate-draft-r5 (low, a defect of round 1 fixed in round 2): a withheld stage's reason
// copies a prerequisite's error, which can name a candidate file whose name holds a newline. Round
// 1 kept the control character, and the finalizer, which reads a withheld stage's reason only as
// one line of text without control characters, then no longer recognised the stage as withheld
// (fail-closed, but the refusal named the wrong problem).
test('round 2: a withheld reason writes every control character as an escape, so the finalizer still reads the stage as withheld', () => {
  const barrier = barrierOf(
    withCase('candidate-policy', {
      status: 'blocked',
      error: 'Inline Trivy suppression is not a reviewed disposition: deploy/v1d\nname.yaml',
    })
  );
  const decision = dispatch.dispatchDecision('sql-lint', { barrier, authorities: null });
  assert.equal(decision.dispatch, false);
  assert.match(decision.reasons[0], /deploy\/v1d\nname\.yaml/, 'the decision keeps the text');
  const reason = dispatch.withheldReason(decision.reasons);
  assert.doesNotMatch(reason, /[\u0000-\u001f\u007f]/);
  assert.match(reason, /deploy\/v1d\\u000aname\.yaml/);
  const record = {
    name: 'sql-lint',
    started: decided,
    finished: decided,
    status: 'pending',
    reason,
  };
  assert.equal(platform.withheldStage(record), true);
  // Every C0 control character and DEL is escaped; other text, non-ASCII text included, is kept.
  const every = Array.from({ length: 32 }, (_, code) => String.fromCharCode(code)).join('');
  const escaped = dispatch.withheldReason([`a${every}\u007fé`]);
  assert.doesNotMatch(escaped, /[\u0000-\u001f\u007f]/);
  assert.ok(
    escaped.endsWith(
      'a\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\u0008\\u0009\\u000a\\u000b\\u000c\\u000d\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\\u007fé'
    ),
    escaped
  );
  // Escaping comes before the 2000-character cut, so the cut reason is still within the bound.
  const long = dispatch.withheldReason(['\n'.repeat(1500)]);
  assert.equal(long.length, 2000);
  assert.ok(long.endsWith('…'));
  assert.doesNotMatch(long, /[\u0000-\u001f\u007f]/);
  assert.equal(platform.withheldStage({ ...record, reason: long }), true);
  // A reason with no control character is unchanged.
  assert.equal(
    dispatch.withheldReason(['plain', 'text']),
    'withheld before dispatch, nothing ran: plain; text'
  );
});

// verify-1 of gate-draft-r5 (an info item, fixed in round 2): only the table was frozen, not its
// rules. A rule changed in the gate's process after load (a stage made to need no barrier, say)
// would change what is dispatched.
test('round 2: every dispatch rule and its list of purposes is frozen, as the table is', () => {
  assert.ok(Object.isFrozen(dispatch.DISPATCH_RULES));
  for (const [name, rule] of Object.entries(dispatch.DISPATCH_RULES)) {
    assert.ok(Object.isFrozen(rule), name);
    assert.ok(Object.isFrozen(rule.authority), name);
    assert.throws(() => {
      rule.barrier = !rule.barrier;
    }, TypeError);
    assert.throws(() => rule.authority.push('synthetic'), TypeError);
    // gate-draft-r6: the test stages' prerequisites are frozen as well (GD5-CARRY-01).
    if (rule.prerequisites) {
      assert.ok(Object.isFrozen(rule.prerequisites), name);
      assert.throws(() => rule.prerequisites.pop(), TypeError);
    }
  }
  assert.ok(
    Array.isArray(dispatch.TEST_STAGE_PREREQUISITES) &&
      Object.isFrozen(dispatch.TEST_STAGE_PREREQUISITES)
  );
  assert.ok(Object.isFrozen(dispatch.DISPATCH_AUTHORITIES));
  assert.ok(Object.isFrozen(dispatch.PRE_DISPATCH_PREREQUISITES));
  assert.equal(dispatch.DISPATCH_RULES['sql-lint'].barrier, true);
});

// The dispatch point the gate uses for every stage it starts (dispatchOrWithhold), with a logging
// process stand-in that refuses (it runs nothing and exits 97) as the command.
function refusingStandIn(t) {
  const directory = temporary(t, 'orbit-dispatch-standin-');
  const log = path.join(directory, 'calls.log');
  const standIn = path.join(directory, 'stand-in');
  fs.writeFileSync(standIn, `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nexit 97\n`, {
    mode: 0o755,
  });
  const calls = () =>
    fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean) : [];
  const through = (name, state) =>
    dispatch.dispatchOrWithhold(name, state, {
      start: authority => spawnSync(standIn, [name, String(authority.length)]).status,
      withhold: reasons => ({ withheld: reasons }),
    });
  return { calls, through };
}

test('GDR4-01: through the dispatch point, a pending, blocked, failed, absent, twice-recorded, malformed or stale prerequisite starts no candidate-controlled command; valid ones start each exactly once', t => {
  const { calls, through } = refusingStandIn(t);
  const authorities = dispatch.decideAuthorities(syntheticGrant);
  // The test stages' own test-host and runtime-identity records are valid throughout (their
  // non-pass shapes are the GD5-CARRY-01 tests below).
  const run = testRunOf();
  for (const name of dispatch.PRE_DISPATCH_PREREQUISITES)
    for (const [label, change] of prerequisiteCases(name)) {
      const barrier = barrierOf(withCase(name, change));
      for (const stage of candidateControlled) {
        const outcome = through(stage, { barrier, authorities, installed: true, run });
        assert.match(
          outcome.withheld?.[0] ?? '',
          /^the pre-dispatch barrier is closed: /,
          `${name} ${label}: ${stage}`
        );
      }
    }
  // An undecided barrier withholds too.
  for (const stage of candidateControlled)
    assert.ok(through(stage, { barrier: null, authorities, installed: true, run }).withheld, stage);
  assert.deepEqual(calls(), [], 'no stand-in was started');
  // The positive control: both prerequisites passed (and every authority given, the dependencies
  // installed): each candidate-controlled stage starts its command exactly once, with its
  // authorities.
  const barrier = barrierOf(both());
  for (const stage of candidateControlled)
    assert.equal(through(stage, { barrier, authorities, installed: true, run }), 97, stage);
  assert.deepEqual(
    calls(),
    candidateControlled.map(stage => `${stage} ${(needsAuthority[stage] ?? []).length}`)
  );
});

test('Maintainer note 014104: through the dispatch point, a missing or malformed authority starts no Docker, registry or image-building command; a given one starts each exactly once', t => {
  const { calls, through } = refusingStandIn(t);
  const barrier = barrierOf(both());
  // Valid test-host and runtime-identity records throughout, as in the test above.
  const run = testRunOf();
  const malformed = dispatch.decideAuthorities(purpose => ({
    ...syntheticGrant(purpose),
    extra: 1,
  }));
  for (const authorities of [
    dispatch.decideAuthorities(production.dispatchAuthority),
    malformed,
    null,
  ])
    for (const stage of Object.keys(needsAuthority)) {
      const outcome = through(stage, { barrier, authorities, installed: true, run });
      assert.ok(
        outcome.withheld?.some(reason => /^no [a-z0-9-]+ authority: /.test(reason)),
        `${stage}: ${outcome.withheld}`
      );
    }
  assert.deepEqual(calls(), []);
  const authorities = dispatch.decideAuthorities(syntheticGrant);
  for (const stage of Object.keys(needsAuthority))
    assert.equal(through(stage, { barrier, authorities, installed: true, run }), 97, stage);
  assert.deepEqual(
    calls(),
    Object.entries(needsAuthority).map(([stage, purposes]) => `${stage} ${purposes.length}`)
  );
});

// ---------------------------------------------------------------------------------------------
// The test stages' own prerequisites: test-host and runtime-identity (GD5-CARRY-01; v5 C3; maintainer note
// 20261017T061149194320Z decision 3). A disclosed carried integration obligation of
// gate-draft-r5, enforced here; not a newly introduced r5 regression.

const testStages = [
  'full-tests-current-runtime',
  'full-tests-minimum-runtime',
  'platform-tests-current-runtime',
  'platform-tests-minimum-runtime',
];
const otherPlatform = process.platform === 'darwin' ? 'linux' : 'darwin';
// Each shape of a test-host or runtime-identity record that must keep every test stage from
// starting: [label, change of its record (null removes it, 'twice' records it twice, an object
// changes it, an undefined member is removed), the problem named].
const testPrerequisiteCases = (name, stage) => [
  [
    'pending',
    { status: 'pending', reason: 'synthetic pending' },
    new RegExp(`^${name} is pending \\(synthetic pending\\)$`),
  ],
  [
    'blocked',
    { status: 'blocked', error: 'synthetic refusal' },
    new RegExp(`^${name} is blocked \\(synthetic refusal\\)$`),
  ],
  ['failed', { status: 'fail' }, new RegExp(`^${name} is fail$`)],
  ['not run', { status: 'not-run' }, new RegExp(`^${name} is not-run$`)],
  ['absent', null, new RegExp(`^${name} is absent: it has not completed in this run$`)],
  ['recorded twice', 'twice', new RegExp(`^${name} is recorded 2 times, so it has no one result$`)],
  [
    'malformed: an unknown status',
    { status: 'passed' },
    new RegExp(`^${name} is malformed: its status "passed" is not a stage status$`),
  ],
  [
    'malformed: no status',
    { status: undefined },
    new RegExp(`^${name} is malformed: its status undefined is not a stage status$`),
  ],
  [
    'malformed: no start',
    { started: undefined },
    new RegExp(`^${name} is malformed: it has no valid recorded start and end$`),
  ],
  [
    'malformed: no end',
    { finished: undefined },
    new RegExp(`^${name} is malformed: it has no valid recorded start and end$`),
  ],
  [
    'malformed: not a calendar time',
    { finished: '2026-09-31T10:00:07.000Z' },
    new RegExp(`^${name} is malformed: it has no valid recorded start and end$`),
  ],
  [
    'malformed: an end before its start',
    { finished: '2026-10-16T10:00:02.500Z' },
    new RegExp(`^${name} is malformed: it has no valid recorded start and end$`),
  ],
  [
    'stale: begun before this run',
    { started: '2026-10-16T09:59:59.999Z' },
    new RegExp(
      `^${name} is stale: it started before this run did, so it is not a result of this run$`
    ),
  ],
  [
    'stale: ends after the decision',
    { finished: '2026-10-16T10:00:10.001Z' },
    new RegExp(`^${name} is stale: it ends after ${stage} was decided, so it had not completed$`),
  ],
  ...(name === 'test-host'
    ? [
        [
          'not applicable: another host platform',
          { host: { platform: otherPlatform, uid: 1000, setfacl: null } },
          new RegExp(
            `^test-host does not apply to this host: it names the platform "${otherPlatform}", not "${process.platform}"$`
          ),
        ],
        [
          'not applicable: no host recorded',
          { host: undefined },
          /^test-host does not apply to this host: it names the platform undefined, not /,
        ],
      ]
    : [
        [
          'not applicable: another binary',
          { runtimes: [{ ...stageRuntime, sha256: 'b'.repeat(64) }] },
          new RegExp(
            `^runtime-identity does not apply to ${stage}: it does not identify Node "v26\\.5\\.1" \\(sha256 a{64}\\), the runtime ${stage} would use$`
          ),
        ],
        [
          'not applicable: another version',
          { runtimes: [{ ...stageRuntime, version: 'v26.5.0' }] },
          new RegExp(`^runtime-identity does not apply to ${stage}: it does not identify Node`),
        ],
        [
          'not applicable: no runtimes recorded',
          { runtimes: undefined },
          new RegExp(`^runtime-identity does not apply to ${stage}: it does not identify Node`),
        ],
      ]),
];
const withTestCase = (name, change) => {
  const stages = [...both(), hostPassed(), identityPassed()];
  const at = stages.findIndex(stage => stage.name === name);
  if (change === null) stages.splice(at, 1);
  else if (change === 'twice') stages.push({ ...stages[at] });
  else {
    stages[at] = { ...stages[at], ...change };
    for (const key of Object.keys(change)) if (change[key] === undefined) delete stages[at][key];
  }
  return stages;
};
// Shapes of the run itself that keep every test stage from starting: [label, run, problem].
const testRunCases = () => [
  ['no run given', null, /stage records, start and decision time were not given/],
  [
    'no run start',
    testRunOf(undefined, { started: undefined }),
    /no valid start and decision time/,
  ],
  ['no decision time', testRunOf(undefined, { now: 'now' }), /no valid start and decision time/],
  [
    'a decision before the run began',
    testRunOf(undefined, { started: decided, now: runStarted }),
    /no valid start and decision time/,
  ],
  ['no list of stages', testRunOf({}), /the run has no list of stage records/],
  [
    'an entry that is not a named stage',
    testRunOf([...both(), hostPassed(), identityPassed(), null]),
    /holds an entry that is not a named stage record/,
  ],
  [
    'no platform given',
    testRunOf(undefined, { platform: undefined }),
    /^test-host cannot be judged to apply: the platform the gate runs on was not given$/,
  ],
  [
    'no runtime given',
    testRunOf(undefined, { runtime: null }),
    /^runtime-identity cannot be judged to apply: the runtime .* would use was not identified$/,
  ],
  [
    'a runtime whose sha256 is not a lower-case sha256',
    testRunOf(undefined, { runtime: { version: 'v26.5.1', sha256: 'A'.repeat(64) } }),
    /^runtime-identity cannot be judged to apply/,
  ],
  [
    'a runtime without a version',
    testRunOf(undefined, { runtime: { sha256: stageRuntime.sha256 } }),
    /^runtime-identity cannot be judged to apply/,
  ],
];

// The two stages each test stage needs (the module's TEST_STAGE_PREREQUISITES, checked below).
const hostAndRuntime = ['test-host', 'runtime-identity'];

test('GD5-CARRY-01: each test-stage rule needs test-host and runtime-identity, each recorded once in this run, passed, ended by the decision and applying to the stage', () => {
  const authorities = dispatch.decideAuthorities(syntheticGrant);
  const barrier = barrierOf(both());
  const state = run => ({ barrier, authorities, installed: true, run });
  for (const stage of testStages) {
    // Valid records: nothing keeps the stage back, and it is dispatched with its authority.
    assert.deepEqual(dispatch.dispatchDecision(stage, state(testRunOf())), {
      dispatch: true,
      authority: [authorities['test-image-builds'].authority],
    });
    // The exact boundaries: begun at the run's start, ended at the decision.
    const edges = [
      ...both(),
      { ...hostPassed(), started: runStarted, finished: decided },
      { ...identityPassed(), started: runStarted, finished: decided },
    ];
    assert.equal(dispatch.dispatchDecision(stage, state(testRunOf(edges))).dispatch, true, stage);
    // Every non-pass, missing, duplicate, malformed, stale or inapplicable record withholds it,
    // naming why, even with the barrier open, every authority given and the dependencies installed.
    for (const name of hostAndRuntime)
      for (const [label, change, pattern] of testPrerequisiteCases(name, stage)) {
        const run = testRunOf(withTestCase(name, change));
        const decision = dispatch.dispatchDecision(stage, state(run));
        assert.equal(decision.dispatch, false, `${stage}, ${name} ${label}`);
        const problems = dispatch.testStagePrerequisiteProblems(stage, run);
        assert.ok(
          problems.some(problem => pattern.test(problem)),
          `${stage}, ${name} ${label}: ${problems}`
        );
        assert.equal(decision.reasons.length, 1, `${stage}, ${name} ${label}`);
        assert.match(
          decision.reasons[0],
          /^test-host and runtime-identity must each pass in this run and apply to this test stage before it starts \(v5 C3; GD5-CARRY-01; /
        );
        assert.ok(decision.reasons[0].includes(problems.join('; ')));
        // The withheld stage's reason is one line the finalizer reads as withheld.
        assert.equal(
          platform.withheldStage({
            name: stage,
            started: decided,
            finished: decided,
            status: 'pending',
            reason: dispatch.withheldReason(decision.reasons),
          }),
          true,
          `${stage}, ${name} ${label}`
        );
      }
    for (const [label, run, pattern] of testRunCases()) {
      assert.equal(dispatch.dispatchDecision(stage, state(run)).dispatch, false, label);
      const problems = dispatch.testStagePrerequisiteProblems(stage, run);
      assert.ok(
        problems.some(problem => pattern.test(problem)),
        `${stage}, ${label}: ${problems}`
      );
    }
    // An undecided state withholds it too, as before.
    assert.equal(dispatch.dispatchDecision(stage, {}).dispatch, false, stage);
    // With valid records nothing is named, and what is returned is frozen.
    const valid = dispatch.testStagePrerequisiteProblems(stage, testRunOf());
    assert.deepEqual(valid, [], stage);
    assert.ok(Object.isFrozen(valid));
  }
  // The rule table: the four test stages, and only they, name both prerequisites.
  assert.deepEqual(dispatch.TEST_STAGE_PREREQUISITES, hostAndRuntime);
  for (const [name, rule] of Object.entries(dispatch.DISPATCH_RULES))
    if (testStages.includes(name)) assert.deepEqual(rule.prerequisites, hostAndRuntime, name);
    else assert.equal(rule.prerequisites, undefined, name);
  // Nothing else consults them: a stage with no prerequisites ignores the run, as in r5.
  assert.equal(dispatch.dispatchDecision('sql-lint', { barrier, run: null }).dispatch, true);
  // A prerequisite name this gate has no rule for is never judged to have passed.
  assert.match(
    dispatch.testStagePrerequisiteProblems('full-tests-current-runtime', testRunOf(), [
      'synthetic-stage',
    ])[0],
    /^synthetic-stage is no prerequisite this gate can judge for a test stage$/
  );
});

// The pure probe of the security review, inverted: with an open barrier, a synthetic authority and
// installed dependencies, gate-draft-r5 returned dispatch: true for all four test-stage rules while
// test-host and runtime-identity were blocked. Each returns dispatch: false now.
test('GD5-CARRY-01, the pure rule: blocked test-host or runtime-identity records give dispatch false for all four test-stage rules, with every other input passing', () => {
  const state = run => ({
    barrier: barrierOf(both()),
    authorities: dispatch.decideAuthorities(syntheticGrant),
    installed: true,
    run,
  });
  const blocked = (record, error) => ({ ...record, status: 'blocked', error });
  for (const [label, stages] of [
    [
      'both blocked',
      [
        ...both(),
        blocked(hostPassed(), 'synthetic host refusal'),
        blocked(identityPassed(), 'no runtime identity record for Node v26.5.1'),
      ],
    ],
    ['test-host blocked', [...both(), blocked(hostPassed(), 'synthetic'), identityPassed()]],
    [
      'runtime-identity blocked',
      [
        ...both(),
        hostPassed(),
        blocked(
          identityPassed(),
          'run darwin-full needs Node 26, which no test stage of this run runs'
        ),
      ],
    ],
  ])
    for (const stage of testStages) {
      const decision = dispatch.dispatchDecision(stage, state(testRunOf(stages)));
      assert.equal(decision.dispatch, false, `${label}: ${stage}`);
      assert.equal(decision.authority, undefined, `${label}: ${stage}`);
      assert.match(decision.reasons[0], / is blocked \(/, `${label}: ${stage}`);
    }
  // The same records with both passed: each rule dispatches.
  for (const stage of testStages)
    assert.equal(dispatch.dispatchDecision(stage, state(testRunOf())).dispatch, true, stage);
});

// gate-draft-r7, GDR6-REQ-01 (the security review of gate-draft-r6; a required correction under
// the maintainer's explicit B35 clarification of 20261017T140102522864Z, not a newly introduced r6
// regression): gate-draft-r6 let a maintenance (B35) run, which it marked `contract: false`, start
// all four test-stage rules with test-host alone when no runtime-identity was recorded, even with
// no runtime identified (`runtime: null`). B35 decides which candidates are maintenance
// candidates, not that an unidentified runtime may run. A maintenance-shaped run is now judged as
// every run is: whatever the run says of itself (gate-draft-r6's `contract: false`, null, missing
// or true), an absent runtime-identity withholds each rule as a bad one does, and a bad record
// that is present never falls back to an absence rule.
const markings = [
  ['contract: false (gate-draft-r6 maintenance)', { contract: false }],
  ['contract: null', { contract: null }],
  ['contract: true', { contract: true }],
  ['no contract member', {}],
];
test('GDR6-REQ-01: a maintenance (B35) run needs test-host and runtime-identity as every run does: no runtime-identity, or any non-pass, duplicate, malformed, stale or inapplicable one, gives dispatch false for all four test-stage rules with every other input passing', () => {
  const state = run => ({
    barrier: barrierOf(both()),
    authorities: dispatch.decideAuthorities(syntheticGrant),
    installed: true,
    run,
  });
  for (const stage of testStages)
    for (const [marked, marking] of markings) {
      const of = (stages, overrides = {}) =>
        dispatch.dispatchDecision(stage, state(testRunOf(stages, { ...marking, ...overrides })));
      // The security review's counterexample: test-host passed, no runtime-identity, with the stage's runtime
      // identified or not. gate-draft-r6 dispatched both in a run marked contract: false.
      for (const runtime of [stageRuntime, null]) {
        const decision = of([...both(), hostPassed()], { runtime });
        assert.equal(decision.dispatch, false, `${stage}, ${marked}, runtime ${runtime}`);
        assert.equal(decision.authority, undefined);
        assert.match(
          decision.reasons[0],
          /: runtime-identity is absent: it has not completed in this run/,
          `${stage}, ${marked}`
        );
      }
      // Every shape of either prerequisite withholds it, naming the problem.
      for (const name of hostAndRuntime)
        for (const [label, change, pattern] of testPrerequisiteCases(name, stage)) {
          const run = testRunOf(withTestCase(name, change), marking);
          assert.equal(
            dispatch.dispatchDecision(stage, state(run)).dispatch,
            false,
            `${stage}, ${marked}, ${name} ${label}`
          );
          assert.ok(
            dispatch.testStagePrerequisiteProblems(stage, run).some(item => pattern.test(item)),
            `${stage}, ${marked}, ${name} ${label}`
          );
        }
      // A present runtime-identity that is bad is judged as bad, never as absent and excused.
      for (const [label, change] of testPrerequisiteCases('runtime-identity', stage).filter(
        ([label]) => label !== 'absent'
      )) {
        const problems = dispatch.testStagePrerequisiteProblems(
          stage,
          testRunOf(withTestCase('runtime-identity', change), marking)
        );
        assert.ok(problems.length >= 1, `${stage}, ${marked}, ${label}`);
        assert.ok(
          problems.every(item => !/runtime-identity is absent/.test(item)),
          `${stage}, ${marked}, ${label}: ${problems}`
        );
      }
      // Valid, applicable records: dispatched, with its authority, however the run is marked.
      assert.equal(of().dispatch, true, `${stage}, ${marked}`);
    }
  // The rule does not depend on the run's kind: the same records give the same problems.
  for (const stage of testStages) {
    const shapes = [
      [...both(), hostPassed()],
      [...both(), hostPassed(), identityPassed()],
      withTestCase('runtime-identity', { status: 'blocked', error: 'synthetic' }),
    ];
    for (const stages of shapes)
      for (const [, marking] of markings)
        assert.deepEqual(
          dispatch.testStagePrerequisiteProblems(stage, testRunOf(stages, marking)),
          dispatch.testStagePrerequisiteProblems(stage, testRunOf(stages)),
          stage
        );
  }
});

test('GDR6-REQ-01: through the dispatch point, a maintenance-shaped run with no, or a bad, runtime-identity starts none of the four test stages; valid records start each exactly once', t => {
  const { calls, through } = refusingStandIn(t);
  const authorities = dispatch.decideAuthorities(syntheticGrant);
  const barrier = barrierOf(both());
  let refused = 0;
  for (const stage of testStages)
    for (const [marked, marking] of markings) {
      const runs = [
        testRunOf([...both(), hostPassed()], marking),
        testRunOf([...both(), hostPassed()], { ...marking, runtime: null }),
        ...hostAndRuntime.flatMap(name =>
          testPrerequisiteCases(name, stage).map(([, change]) =>
            testRunOf(withTestCase(name, change), marking)
          )
        ),
      ];
      for (const run of runs) {
        const outcome = through(stage, { barrier, authorities, installed: true, run });
        assert.match(
          outcome.withheld?.[0] ?? '',
          /^test-host and runtime-identity must each pass in this run and apply to this test stage before it starts \(v5 C3; GD5-CARRY-01; GDR6-REQ-01: in a maintenance run as in every other\): /,
          `${stage}, ${marked}`
        );
        refused += 1;
      }
    }
  assert.ok(refused > 400, String(refused));
  assert.deepEqual(calls(), [], 'no stand-in was started');
  // The positive control, maintenance-shaped (gate-draft-r6's marking): valid records start each
  // test stage exactly once, with its one authority.
  for (const stage of testStages)
    assert.equal(
      through(stage, {
        barrier,
        authorities,
        installed: true,
        run: testRunOf(undefined, { contract: false }),
      }),
      97,
      stage
    );
  assert.deepEqual(
    calls(),
    testStages.map(stage => `${stage} 1`)
  );
});

test('GD5-CARRY-01: through the dispatch point, every non-pass, missing, duplicate, malformed, stale or inapplicable test-host or runtime-identity record starts none of the four test stages; valid ones start each exactly once', t => {
  const { calls, through } = refusingStandIn(t);
  const authorities = dispatch.decideAuthorities(syntheticGrant);
  const barrier = barrierOf(both());
  let refused = 0;
  for (const stage of testStages) {
    for (const name of hostAndRuntime)
      for (const [label, change] of testPrerequisiteCases(name, stage)) {
        const run = testRunOf(withTestCase(name, change));
        const outcome = through(stage, { barrier, authorities, installed: true, run });
        assert.match(
          outcome.withheld?.[0] ?? '',
          /^test-host and runtime-identity must each pass in this run/,
          `${stage}, ${name} ${label}`
        );
        refused += 1;
      }
    for (const [label, run] of testRunCases()) {
      const outcome = through(stage, { barrier, authorities, installed: true, run });
      assert.ok(outcome.withheld, `${stage}, ${label}`);
      refused += 1;
    }
  }
  assert.ok(refused > 100, String(refused));
  assert.deepEqual(calls(), [], 'no stand-in was started');
  // The positive control: valid records, each test stage once, with its one authority.
  for (const stage of testStages)
    assert.equal(through(stage, { barrier, authorities, installed: true, run: testRunOf() }), 97);
  assert.deepEqual(
    calls(),
    testStages.map(stage => `${stage} 1`)
  );
});

// ---------------------------------------------------------------------------------------------
// The real gate, in throwaway fixture repositories

const gateScripts = [
  'security-gate.mjs',
  'security-evidence.mjs',
  'security-finalization.mjs',
  'security-findings.mjs',
  'security-platform.mjs',
  'security-catalog.mjs',
  'security-catalog.json',
  'security-entries.mjs',
  'security-gate-identity.mjs',
  'security-dispatch.mjs',
  'security-authority.mjs',
  'check-platform-coverage.mjs',
];
const host = process.platform;
const otherHost = host === 'darwin' ? 'linux' : 'darwin';
const pinned = { 24: fixtureImages.imageOf[24], 26: fixtureImages.imageOf[26] };

// A platform manifest for this host with a container run hosted by its full run and pinned images
// (so the run hosts T8), or a weakened one (an entry's evidence on the platform run dropped).
// `runtimes` are the runs' and entries' runtimes: the real matrix, Node 24 and 26, unless a test
// gives the route a gate started on this runtime can cover (gateRuntimes; GD5-CARRY-01).
function manifest({ weakened = false, runtimes = ['24', '26'] } = {}) {
  const entry = (id, name, platforms, evidence, prerequisites = []) => ({
    id,
    file: 'test/fixture.test.mjs',
    name: [name],
    platforms,
    runtimes,
    prerequisites,
    evidence,
  });
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      runs: {
        [`${host}-full`]: { platform: host, runtimes, files: 'all', requiredFor: ['commit'] },
        [`${host}-platform`]: {
          platform: host,
          runtimes,
          files: ['test/fixture.test.mjs'],
          requiredFor: ['commit'],
        },
        [`${otherHost}-full`]: {
          platform: otherHost,
          runtimes,
          files: 'all',
          requiredFor: ['commit'],
        },
        'synthetic-container': {
          platform: 'container',
          runtimes,
          files: ['test/fixture.test.mjs'],
          requiredFor: ['commit'],
          images: Object.fromEntries(
            runtimes.map(runtime => [
              runtime,
              { image: pinned[runtime], driver: `synthetic.driver${runtime}` },
            ])
          ),
          hostRuns: [`${host}-full`],
        },
      },
      entries: [
        entry(
          'synthetic.here',
          'synthetic platform test here',
          [host],
          weakened ? [`${host}-full`] : [`${host}-full`, `${host}-platform`]
        ),
        entry('synthetic.inner', 'synthetic inner test', ['container'], ['synthetic-container']),
        ...runtimes.map(runtime =>
          entry(
            `synthetic.driver${runtime}`,
            `synthetic driver ${runtime}`,
            [host],
            [`${host}-full`],
            ['docker']
          )
        ),
      ],
    },
    null,
    2
  )}\n`;
}

/**
 * A fixture repository whose candidate is a canary: its lint sources and its test file append to
 * `canary.log` each time they run, and its test file also starts a nested `docker build` (a
 * subprocess Docker client) and connects to DOCKER_HOST itself (a direct endpoint, here a loopback
 * listener that counts connections). `bin/` holds logging stand-ins for docker, npm, curl, the
 * scanners and the Node 24 runtime: each appends its name and arguments to `calls.log` and runs
 * nothing real; docker and npm refuse (exit 97) unless the fixture's synthetic authority is in
 * place, in which case they exit 0 as far as a positive control needs. Options: `authority`
 * (purposes, 'all', or null for the repository's own authority module, which gives none),
 * `malformed`, `packageText` (the candidate's package.json), `manifest` ('committed' to commit
 * the manifest and stage a weakened one: platform-manifest then blocks; 'unchanged' to commit it
 * and leave it as it is, as a CI checkout of a 1.5 commit has it; true to stage it new), `files`
 * (further tracked files of the first commit, by path), `runtimes` (the manifest's), `identified`
 * (synthetic runtime identity records for the gate's runtime and the Node 24 stand-in,
 * test/helpers/runtime-identity.mjs, so that runtime-identity can pass) and `patchGate` (a list of
 * [text, replacement] applied to the fixture's own copy of security-gate.mjs, each text found
 * exactly once, so a test can make one stage of that throwaway copy record what it needs).
 */
function gateFixture(
  t,
  {
    authority = null,
    malformed = false,
    packageText,
    manifest: withManifest = true,
    files = {},
    runtimes = ['24', '26'],
    identified = false,
    patchGate = [],
  } = {}
) {
  const base = temporary(t, 'orbit-dispatch-gate-');
  const root = path.join(base, 'repository');
  const bin = path.join(base, 'bin');
  const canary = path.join(base, 'canary.log');
  const calls = path.join(base, 'calls.log');
  fs.mkdirSync(root);
  fs.mkdirSync(bin);
  const write = (file, text, mode = 0o644) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text, { mode });
  };
  const git = (...args) =>
    execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: 'pipe' }).trimEnd();
  const commit = message =>
    git(
      '-c',
      'user.name=Orbit Fixture',
      '-c',
      'user.email=fixture@example.com',
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.hooksPath=/dev/null',
      'commit',
      '--quiet',
      '-m',
      message
    );
  git('init', '--quiet');
  for (const file of gateScripts)
    write(
      path.join(root, 'scripts', file),
      fs.readFileSync(path.join(repository, 'scripts', file))
    );
  if (patchGate.length) {
    const file = path.join(root, 'scripts/security-gate.mjs');
    let text = fs.readFileSync(file, 'utf8');
    for (const [from, to] of patchGate) {
      assert.equal(text.split(from).length, 2, `the fixture's gate holds ${from} exactly once`);
      text = text.replace(from, () => to);
    }
    write(file, text);
  }
  if (authority)
    write(
      path.join(root, 'scripts/security-authority.mjs'),
      syntheticAuthority(authority, { malformed })
    );
  write(path.join(root, 'README.md'), '# Synthetic dispatch fixture\n');
  write(path.join(root, 'CHANGELOG.md'), '# Synthetic fixture changelog\n');
  write(path.join(root, 'Dockerfile'), `FROM example.invalid/synthetic@sha256:${'0'.repeat(64)}\n`);
  write(path.join(root, 'test/setup.mjs'), '// Synthetic test setup.\n');
  write(
    path.join(root, 'package.json'),
    packageText ??
      `${JSON.stringify(
        {
          scripts: {
            'lint:sql': 'node scripts/sql-lint.mjs',
            'lint:imports': 'node scripts/import-graph.mjs',
          },
        },
        null,
        2
      )}\n`
  );
  const ran = label =>
    `import fs from 'node:fs';\nfs.appendFileSync(${JSON.stringify(canary)}, ${JSON.stringify(`${label}\n`)});\n`;
  write(path.join(root, 'scripts/sql-lint.mjs'), ran('sql-lint'));
  write(path.join(root, 'scripts/import-graph.mjs'), ran('import-lint'));
  write(
    path.join(root, 'test/fixture.test.mjs'),
    `import test from 'node:test';
import fs from 'node:fs';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
test('synthetic platform test here', async () => {
  fs.appendFileSync(${JSON.stringify(canary)}, 'test-file\\n');
  // A nested Docker client, as test/installer/docker.test.mjs starts one, and a direct endpoint.
  spawnSync('docker', ['build', '--tag', 'synthetic-nested', '.']);
  const endpoint = /^tcp:\\/\\/127\\.0\\.0\\.1:(\\d+)$/.exec(process.env.DOCKER_HOST ?? '');
  if (endpoint)
    await new Promise(resolve => {
      const socket = net.connect(Number(endpoint[1]), '127.0.0.1', () => socket.end('direct\\n'));
      socket.on('close', resolve);
      socket.on('error', resolve);
      setTimeout(resolve, 3000).unref();
    });
});
`
  );
  const rulesCommit = 'c'.repeat(40);
  write(
    path.join(base, `semgrep-rules-${rulesCommit}`, 'javascript/security/synthetic.yaml'),
    '# Synthetic rules.\n'
  );
  const archive = path.join(base, 'synthetic-rules.tar.gz');
  execFileSync('tar', ['-czf', archive, '-C', base, `semgrep-rules-${rulesCommit}`]);
  write(
    path.join(root, 'scripts/security-tools.json'),
    JSON.stringify({
      gitleaks: '0.0.0',
      trivy: '0.0.0',
      actionlint: '0.0.0',
      semgrepImage: 'synthetic-scanner',
      semgrepRulesCommit: rulesCommit,
      semgrepRulesSha256: createHash('sha256').update(fs.readFileSync(archive)).digest('hex'),
    })
  );
  // One logging stand-in for every tool, by the name it is started as. Nothing real runs.
  const standIn = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
const name = path.basename(process.argv[1]);
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify({ name, args }) + '\\n');
const granted = ${JSON.stringify(Boolean(authority) && !malformed)};
if (args[0] === 'version' || args[0] === '--version') {
  console.log(name === 'orbit-fixture-node24' ? 'v24.0.0' : 'synthetic tool 0.0.0');
  process.exit(0);
}
if (name === 'orbit-fixture-node24') {
  console.log('# tests 1\\n# pass 1\\n# fail 0\\n# cancelled 0\\n# skipped 0\\n# todo 0');
  process.exit(0);
}
if (['gitleaks', 'trivy'].includes(name)) process.exit(0);
if (!granted) { console.error('stand-in ' + name + ': refused'); process.exit(97); }
if (name === 'curl') fs.copyFileSync(${JSON.stringify(archive)}, args[args.indexOf('--output') + 1]);
if (name === 'docker' && args[0] === 'image' && args[1] === 'inspect' && args[2] === '--format')
  for (const image of args.slice(4).filter(item => item.includes('@'))) {
    const digest = image.split('@')[1];
    console.log(JSON.stringify({ Id: digest, RepoDigests: ['node@' + digest], Os: 'linux', Architecture: 'arm64', Variant: 'v8' }));
  }
process.exit(0);
`;
  for (const name of [
    'docker',
    'npm',
    'curl',
    'gitleaks',
    'trivy',
    'actionlint',
    'orbit-fixture-node24',
  ])
    write(path.join(bin, name), standIn, 0o755);
  // The two runtimes the gate's test stages run: its own, and the Node 24 stand-in, which reports
  // v24.0.0 (ORBIT_SECURITY_NODE24 below).
  if (identified)
    writeRuntimeIdentity(root, [
      { executable: process.execPath, version: process.version },
      { executable: path.join(bin, 'orbit-fixture-node24'), version: 'v24.0.0' },
    ]);
  if (withManifest === 'committed' || withManifest === 'unchanged')
    write(path.join(root, 'test/platform-manifest.json'), manifest({ runtimes }));
  for (const [file, text] of Object.entries(files)) write(path.join(root, file), text);
  git('add', '.');
  commit('Synthetic dispatch fixture');
  // A commit candidate updates CHANGELOG.md (candidate-policy), and introduces, or weakens, the
  // platform manifest, or leaves the committed one as it is.
  write(
    path.join(root, 'CHANGELOG.md'),
    '# Synthetic fixture changelog\n\n- A synthetic change.\n'
  );
  if (withManifest && withManifest !== 'unchanged')
    write(
      path.join(root, 'test/platform-manifest.json'),
      manifest({ weakened: withManifest === 'committed', runtimes })
    );
  git('add', '-A');
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  // Runs the gate in `mode` (asynchronously, so the loopback endpoint can count connections):
  // a mode, or the gate's arguments as a list (['platform', '<run id>']). `env` changes the
  // gate's environment (an undefined value removes the variable).
  const run = async (mode, env = {}) => {
    const args = Array.isArray(mode) ? mode : [mode];
    const endpoint = net.createServer(socket => {
      endpoint.connections += 1;
      socket.resume();
      socket.on('error', () => {});
    });
    endpoint.connections = 0;
    await new Promise(resolve => endpoint.listen(0, '127.0.0.1', resolve));
    for (const file of [canary, calls]) fs.rmSync(file, { force: true });
    const evidenceRoot = path.join(root, '.git/orbit-security');
    const earlier = new Set(fs.existsSync(evidenceRoot) ? fs.readdirSync(evidenceRoot) : []);
    const result = await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [path.join(root, 'scripts/security-gate.mjs'), ...args],
        {
          cwd: root,
          env: {
            ...environment,
            PATH: `${bin}${path.delimiter}${process.env.PATH}`,
            ORBIT_SECURITY_NODE24: path.join(bin, 'orbit-fixture-node24'),
            DOCKER_HOST: `tcp://127.0.0.1:${endpoint.address().port}`,
            ...env,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', chunk => (stdout += chunk));
      child.stderr.on('data', chunk => (stderr += chunk));
      const timer = setTimeout(() => child.kill('SIGKILL'), 60000);
      child.on('error', reject);
      child.on('close', status => {
        clearTimeout(timer);
        resolve({ status, stdout, stderr });
      });
    });
    await new Promise(resolve => setTimeout(resolve, 100));
    await new Promise(resolve => endpoint.close(resolve));
    const tree = git('write-tree');
    const name = fs
      .readdirSync(evidenceRoot)
      .find(item => item.startsWith(`${tree}-${args[0]}-`) && !earlier.has(item));
    assert.ok(name, result.stdout + result.stderr);
    const evidence = JSON.parse(
      fs.readFileSync(path.join(evidenceRoot, name, 'result.json'), 'utf8')
    );
    const lines = file =>
      fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean) : [];
    const called = lines(calls).map(line => JSON.parse(line));
    return {
      result,
      evidence,
      // The run's sealed evidence folder (a commit or companion run seals it).
      directory: path.join(evidenceRoot, name),
      stage: id => evidence.stages.find(item => item.name === id),
      canary: lines(canary),
      called,
      // The calls of one stand-in, as argument strings.
      of: tool => called.filter(item => item.name === tool).map(item => item.args.join(' ')),
      connections: endpoint.connections,
    };
  };
  return { run, root, git };
}

// What a negative control may see dispatched at all: the gate's own tool queries.
const gateOwnCalls = run =>
  run.called.every(
    ({ name, args }) =>
      (name === 'npm' && args.join(' ') === '--version') ||
      (name === 'orbit-fixture-node24' && args.join(' ') === '--version') ||
      name === 'gitleaks' ||
      (name === 'trivy' && !args.includes('image'))
  );
const withheld = (run, name, pattern) => {
  const stage = run.stage(name);
  assert.equal(stage?.status, 'pending', `${name}: ${JSON.stringify(stage)}`);
  assert.equal(stage.command, undefined, name);
  assert.equal(stage.log, undefined, name);
  assert.match(stage.reason, /^withheld before dispatch, nothing ran: /, name);
  if (pattern) assert.match(stage.reason, pattern, name);
};

test(
  'GDR4-01: a blocked candidate-policy dispatches no candidate code, no dependency install, no test and no Docker command, with or without authority',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    // A package.json that is not in canonical form: candidate-policy blocks.
    const compact = `${JSON.stringify({ scripts: { 'lint:sql': 'node scripts/sql-lint.mjs', 'lint:imports': 'node scripts/import-graph.mjs' } })}\n`;
    for (const authority of [null, 'all']) {
      const fixture = gateFixture(t, { authority, packageText: compact });
      for (const mode of ['commit', 'scan']) {
        const run = await fixture.run(mode);
        const label = `${mode}, authority ${authority}`;
        assert.equal(run.result.status, 1, label);
        assert.equal(run.evidence.status, 'blocked', label);
        assert.equal(run.stage('candidate-policy').status, 'blocked', label);
        assert.match(
          run.result.stdout,
          /Pre-dispatch barrier: closed, nothing candidate-controlled is dispatched: candidate-policy is blocked \(package\.json must be in canonical form/,
          label
        );
        // Zero candidate code, test or nested client, and no direct endpoint reached.
        assert.deepEqual(run.canary, [], label);
        assert.equal(run.connections, 0, label);
        for (const name of [
          'sql-lint',
          'import-lint',
          'dependencies-install',
          'format',
          'syntax-manifest',
          'documentation',
          'dependencies-all',
          'dependencies-production',
          'registry-signatures',
        ])
          withheld(run, name, /the pre-dispatch barrier is closed: candidate-policy is blocked/);
        assert.ok(
          !run.of('npm').some(args => /^(?:ci|run|audit)\b/.test(args)),
          `${label}: ${run.of('npm')}`
        );
        assert.ok(
          !run.of('docker').some(args => /^build\b/.test(args)),
          `${label}: ${run.of('docker')}`
        );
        if (mode === 'commit')
          for (const name of [
            'full-tests-current-runtime',
            'full-tests-minimum-runtime',
            'container-build',
            'systemd-test-image',
          ])
            assert.match(
              run.stage(name).reason,
              /the pre-dispatch barrier is closed: candidate-policy is blocked/,
              `${label}: ${name}`
            );
        if (mode === 'scan')
          withheld(
            run,
            'container-build',
            /the pre-dispatch barrier is closed: candidate-policy is blocked/
          );
        if (!authority) {
          assert.ok(gateOwnCalls(run), `${label}: ${JSON.stringify(run.called)}`);
          assert.deepEqual(run.of('docker'), [], label);
          assert.deepEqual(run.of('curl'), [], label);
        }
      }
    }
  }
);

test(
  'GDR4-01 and change 19: a blocked platform-manifest dispatches no candidate code, no T8 inspect and no candidate build, even with every authority given',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    // The manifest is committed, and the candidate weakens it: platform-manifest blocks.
    const fixture = gateFixture(t, { authority: 'all', manifest: 'committed' });
    for (const mode of ['commit', 'scan']) {
      const run = await fixture.run(mode);
      assert.equal(run.result.status, 1, mode);
      assert.equal(
        run.stage('candidate-policy').status,
        'pass',
        run.stage('candidate-policy').error
      );
      assert.equal(run.stage('platform-manifest').status, 'blocked', mode);
      assert.match(
        run.result.stdout,
        /Pre-dispatch barrier: closed, nothing candidate-controlled is dispatched: platform-manifest is blocked/
      );
      assert.deepEqual(run.canary, [], mode);
      assert.equal(run.connections, 0, mode);
      assert.ok(
        !run.of('npm').some(args => /^(?:ci|run|audit)\b/.test(args)),
        run.of('npm').join('; ')
      );
      // No candidate-controlled build, in either mode, and no T8 image inspect.
      assert.ok(!run.of('docker').some(args => /^build\b/.test(args)), run.of('docker').join('; '));
      assert.ok(
        !run.of('docker').some(args => args.includes(pinned[24]) || args.includes(pinned[26])),
        mode
      );
      if (mode === 'commit') {
        withheld(
          run,
          't8-image-identity',
          /the pre-dispatch barrier is closed: platform-manifest is blocked/
        );
        assert.equal(run.stage('t8-image-authenticity').status, 'pending');
        assert.match(
          run.stage('t8-image-authenticity').reason,
          /t8-image-identity was withheld before dispatch/
        );
        assert.match(
          run.stage('t8-image-activation').reason,
          /nothing to bind: t8-image-identity was withheld before dispatch/
        );
        for (const name of ['container-build', 'systemd-test-image', 'full-tests-current-runtime'])
          assert.match(
            run.stage(name).reason,
            /the pre-dispatch barrier is closed: platform-manifest is blocked/,
            name
          );
      } else
        withheld(
          run,
          'container-build',
          /the pre-dispatch barrier is closed: platform-manifest is blocked/
        );
    }
  }
);

test(
  'Maintainer note 014104: with both prerequisites passed and no authority, the lints run once each and nothing else candidate-controlled, Docker, registry or download is dispatched; every withheld stage says why',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    for (const [label, options] of [
      ['the repository authority (none)', {}],
      ['a malformed authority', { authority: 'all', malformed: true }],
    ]) {
      const fixture = gateFixture(t, options);
      for (const mode of ['commit', 'scan']) {
        const run = await fixture.run(mode);
        const where = `${label}, ${mode}`;
        assert.equal(run.result.status, 1, where);
        assert.notEqual(run.evidence.status, 'pass', where);
        for (const name of ['candidate-policy', 'platform-manifest'])
          assert.equal(run.stage(name).status, 'pass', `${where}: ${run.stage(name).error}`);
        assert.match(run.result.stdout, /Pre-dispatch barrier: open/, where);
        // The barrier is open: the lints, which need no authority, ran exactly once each.
        assert.deepEqual(run.canary.sort(), ['import-lint', 'sql-lint'], where);
        // Nothing else: no test file, nested client or direct endpoint; no Docker command at all; no
        // npm install, script or audit; no download.
        assert.equal(run.connections, 0, where);
        assert.deepEqual(run.of('docker'), [], where);
        assert.deepEqual(run.of('curl'), [], where);
        assert.ok(gateOwnCalls(run), `${where}: ${JSON.stringify(run.called)}`);
        const authorityReason = purpose =>
          new RegExp(
            `no ${purpose} authority: ${options.malformed ? `the authority given for ${purpose} is malformed` : ''}`
          );
        withheld(run, 'docker-version', authorityReason('docker-version-query'));
        withheld(run, 'dependencies-install', authorityReason('host-listener'));
        for (const name of ['format', 'syntax-manifest', 'documentation'])
          withheld(run, name, /dependencies-install did not pass in this run/);
        for (const name of ['dependencies-all', 'dependencies-production', 'registry-signatures'])
          withheld(run, name, authorityReason('host-listener'));
        assert.equal(run.stage('sast-rules').status, 'pending');
        assert.match(run.stage('sast-rules').reason, authorityReason('host-listener'));
        assert.equal(run.stage('sast-rules').steps, undefined);
        for (const name of ['sast-image', 'source-analysis'])
          withheld(run, name, authorityReason('semgrep-image'));
        if (mode === 'commit') {
          for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime'])
            withheld(run, name, authorityReason('test-image-builds'));
          withheld(run, 't8-image-identity', authorityReason('t8-image-inspect'));
          for (const name of [
            'platform-coverage-current-runtime',
            'platform-coverage-minimum-runtime',
          ]) {
            assert.equal(run.stage(name).status, 'pending', name);
            assert.match(
              run.stage(name).reason,
              /was withheld before dispatch, so there is no run of it to check/
            );
          }
          // Withheld stages keep the gate's v5 order on their recorded times.
          assert.deepEqual(
            platform.orderProblems(run.evidence, { prefix: 'full-tests-' }),
            [],
            where
          );
        } else
          for (const name of [
            'container-build',
            'container-identity',
            'container-vulnerabilities',
            'container-sbom',
          ])
            withheld(run, name, authorityReason('scan-image-build'));
        // Docker stays in the test stages' TEST_REQUIRE: their coverage is withheld, not narrowed.
        assert.match(platform.testRequire, /(?:^|,)docker(?:,|$)/);
      }
    }
  }
);

test(
  'the positive control: with a synthetic authority, the same gate dispatches each withheld command exactly once, nested and direct Docker attempts included, and builds nothing in a commit run',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    // gate-draft-r6 (GD5-CARRY-01): a valid host and runtime combination, which a test stage now
    // needs: runtime identity records for the gate's runtime and the Node 24 stand-in, and the
    // manifest route a gate started on this runtime covers (on Node 24, Node 24 alone).
    const runtimes = gateRuntimes();
    const run = await gateFixture(t, { authority: 'all', runtimes, identified: true }).run(
      'commit'
    );
    assert.equal(run.result.status, 1, 'a commit run is never a pass');
    for (const name of ['candidate-policy', 'platform-manifest', 'test-host', 'runtime-identity'])
      assert.equal(run.stage(name).status, 'pass', run.stage(name).error);
    // The candidate's code: each lint once, and the test file once (in the current runtime's test
    // stage; the Node 24 stage's runtime is a stand-in, started once).
    assert.deepEqual(run.canary.sort(), ['import-lint', 'sql-lint', 'test-file']);
    assert.deepEqual(run.of('orbit-fixture-node24').filter(args => args !== '--version').length, 1);
    // Its nested Docker client and its direct endpoint attempt: once each.
    assert.deepEqual(
      run.of('docker').filter(args => args === 'build --tag synthetic-nested .'),
      ['build --tag synthetic-nested .']
    );
    assert.equal(run.connections, 1);
    // Every npm command once.
    assert.deepEqual(run.of('npm'), [
      '--version',
      'ci --ignore-scripts --no-audit --no-fund',
      'run format:check',
      'run check',
      'run docs:check',
      'audit --json',
      'audit --omit=dev --json',
      'audit signatures',
    ]);
    // The rules download once; docker version, the T8 inspect and the Semgrep inspect and run once
    // each; and no build of the gate's own (only the test file's nested one above).
    assert.equal(run.of('curl').length, 1);
    const docker = run.of('docker').filter(args => args !== 'build --tag synthetic-nested .');
    assert.deepEqual(docker.slice(0, 2), [
      'version',
      platform
        .t8InspectCommand(runtimes.map(runtime => pinned[runtime]).sort())
        .slice(1)
        .join(' '),
    ]);
    assert.deepEqual(docker.slice(2, 3), ['image inspect --format {{json .}} synthetic-scanner']);
    assert.equal(docker.length, 4);
    assert.match(docker[3], /^run .* synthetic-scanner semgrep scan /);
    assert.ok(!docker.some(args => /^build\b/.test(args)));
    for (const name of ['container-build', 'systemd-test-image'])
      assert.equal(run.stage(name).command, undefined, name);
    // Each dispatched stage that needed an authority records the synthetic one it rests on.
    for (const [name, purposes] of Object.entries(needsAuthority).filter(([name]) =>
      [
        'docker-version',
        't8-image-identity',
        'dependencies-install',
        'sast-image',
        'source-analysis',
        'full-tests-current-runtime',
      ].includes(name)
    ))
      assert.deepEqual(
        run.stage(name).authority,
        purposes.map(purpose => ({
          purpose,
          source: 'synthetic test authority',
          reference: 'test fixture only; no reviewed record stands behind it',
        })),
        name
      );
    // A stage that needs no authority records none.
    assert.equal(run.stage('sql-lint').authority, undefined);
  }
);

// GD5-CARRY-01 through the real gate. What a negative control may see of the test stages: none
// dispatched, no test file, nested client or direct endpoint, and the Node 24 stand-in asked only
// for its version.
const noTestDispatch = (run, names, pattern, label) => {
  for (const name of names) {
    withheld(run, name, pattern);
    // Withheld for this reason alone: the barrier is open, the authority given, and the
    // dependencies installed.
    assert.doesNotMatch(
      run.stage(name).reason,
      /pre-dispatch barrier|no test-image-builds authority|dependencies-install did not pass/,
      `${label}: ${name}`
    );
  }
  assert.ok(!run.canary.includes('test-file'), `${label}: ${run.canary}`);
  assert.equal(run.connections, 0, label);
  assert.deepEqual(
    run.of('docker').filter(args => /^build\b/.test(args)),
    [],
    label
  );
  assert.deepEqual(
    run.of('orbit-fixture-node24').filter(args => args !== '--version'),
    [],
    label
  );
};
const fullTests = ['full-tests-current-runtime', 'full-tests-minimum-runtime'];
const platformTests = ['platform-tests-current-runtime', 'platform-tests-minimum-runtime'];
const prerequisiteReason =
  'test-host and runtime-identity must each pass in this run and apply to this test stage before it starts \\(v5 C3; GD5-CARRY-01; [^)]*\\): ';

// The security review's counterexample (GD5-CARRY-01): with a synthetic authority, gate-draft-r5's positive
// control dispatched full-tests-current-runtime, ran the candidate's test and reached its nested
// client and the loopback endpoint, while runtime-identity was blocked for want of an identity
// record. The same fixture now dispatches no test stage, in a commit run and in a companion run.
test(
  'GD5-CARRY-01: with a synthetic authority and no runtime identity record, runtime-identity blocks, and no test stage of a commit or a companion run is dispatched',
  { timeout: 180000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const fixture = gateFixture(t, { authority: 'all' });
    // On Node 24 the real matrix's missing Node 26 is named first (the next test).
    const blockedIdentity = new RegExp(
      `${prerequisiteReason}runtime-identity is blocked \\((?:run \\S+ needs Node 26, which no test stage of this run runs: [^;]*; )?no runtime identity record for Node v`
    );
    const commit = await fixture.run('commit');
    assert.equal(commit.result.status, 1);
    for (const name of [
      'candidate-policy',
      'platform-manifest',
      'test-host',
      'dependencies-install',
    ])
      assert.equal(commit.stage(name).status, 'pass', `${name}: ${commit.stage(name).error}`);
    assert.equal(commit.stage('runtime-identity').status, 'blocked');
    assert.match(commit.stage('runtime-identity').error, /no runtime identity record for Node v/);
    noTestDispatch(commit, fullTests, blockedIdentity, 'commit');
    // The lints still ran, once each: the barrier is open.
    assert.deepEqual(commit.canary.sort(), ['import-lint', 'sql-lint']);
    for (const name of ['platform-coverage-current-runtime', 'platform-coverage-minimum-runtime'])
      assert.match(commit.stage(name).reason, /was withheld before dispatch, so there is no run/);
    const companion = await fixture.run(['platform', `${host}-platform`]);
    assert.equal(companion.result.status, 1);
    assert.equal(companion.evidence.mode, 'platform');
    assert.equal(companion.stage('test-host').status, 'pass', companion.stage('test-host').error);
    assert.equal(companion.stage('runtime-identity').status, 'blocked');
    noTestDispatch(companion, platformTests, blockedIdentity, 'companion');
    assert.deepEqual(companion.canary, [], 'a companion runs no lint and, here, no test');
  }
);

// The maintainer's decision 3: the real matrix stays Node 24 and 26. A gate started on Node 24 runs Node 24
// in both test stages, and one started on Node 26 without its Node 24 runtime runs only Node 26:
// either way the run lacks a runtime its manifest requires, runtime-identity blocks, and no test
// stage is dispatched, although every runtime it does run has its identity record.
test(
  'GD5-CARRY-01: an unmet runtime requirement blocks, Node 26 on a Node 24 gate and Node 24 on a Node 26 gate without its Node 24 runtime: no test stage is dispatched',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const fixture = gateFixture(t, { authority: 'all', identified: true });
    const onNode24 = process.versions.node.split('.')[0] === '24';
    const missing = onNode24 ? '26' : '24';
    const run = onNode24
      ? await fixture.run('commit')
      : await fixture.run('commit', { ORBIT_SECURITY_NODE24: undefined });
    assert.equal(run.result.status, 1);
    assert.equal(run.stage('test-host').status, 'pass', run.stage('test-host').error);
    const identity = run.stage('runtime-identity');
    assert.equal(identity.status, 'blocked');
    assert.match(
      identity.error,
      new RegExp(`^run ${host}-full needs Node ${missing}, which no test stage of this run runs`)
    );
    assert.doesNotMatch(
      identity.error,
      /no runtime identity record/,
      'every runtime it runs is identified'
    );
    const planned = onNode24 ? fullTests : ['full-tests-current-runtime'];
    noTestDispatch(
      run,
      planned,
      new RegExp(
        `${prerequisiteReason}runtime-identity is blocked \\(run ${host}-full needs Node ${missing}`
      ),
      `Node ${missing} missing`
    );
    if (!onNode24) {
      assert.equal(run.stage('minimum-runtime-available').status, 'blocked');
      assert.equal(run.stage('full-tests-minimum-runtime'), undefined);
    }
    assert.deepEqual(run.canary.sort(), ['import-lint', 'sql-lint']);
  }
);

// Patches of the fixture's throwaway gate copy that leave runtime-identity unrecorded, or record it
// twice. They change the function itself, which gate-draft-r6 and gate-draft-r7 define alike, not
// its call (gate-draft-r6 planned it in a contract run only, gate-draft-r7 in every run), so they
// apply to either tree.
const identityHeader = 'function runtimeIdentity(runId, versions) {\n';
const identityAbsent = [identityHeader, `${identityHeader}  return true;\n`];
const identityTwice = [
  identityHeader,
  `${identityHeader}  identifyOnce(runId, versions);\n  return identifyOnce(runId, versions);\n}\nfunction identifyOnce(runId, versions) {\n`,
];

// Each non-pass shape the gate's own recorder can give, made in the fixture's throwaway copy of the
// gate (as the security review's probe made test-host blocked): a blocked, pending, absent or twice-recorded
// test-host, and a pending, absent or twice-recorded runtime-identity. Everything else passes (a
// valid host and runtime combination), so each is the one reason no test stage is dispatched. The
// malformed and stale shapes, which the gate's recorder cannot write, are the pure and
// dispatch-point tests above.
test(
  'GD5-CARRY-01: through the real gate, a blocked, pending, absent or twice-recorded test-host or runtime-identity dispatches no test stage of a contract run',
  { timeout: 300000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const runtimes = gateRuntimes();
    const hostCheck = "  return requirement('test-host', record => {\n";
    const identityCheck = "  return requirement('runtime-identity', record => {\n";
    const hostCall = '      testHost();\n      runTests(\n';
    const blockHost = [
      hostCheck,
      `${hostCheck}    throw new Error('synthetic: test-host forced to block in this fixture');\n`,
    ];
    for (const [label, patchGate, problem] of [
      [
        'test-host blocked',
        [blockHost],
        'test-host is blocked \\(synthetic: test-host forced to block in this fixture\\)',
      ],
      [
        'test-host pending',
        [
          [
            hostCheck,
            `${hostCheck}    throw new PendingStage('synthetic: test-host forced to stay pending in this fixture');\n`,
          ],
        ],
        'test-host is pending \\(synthetic: test-host forced to stay pending in this fixture\\)',
      ],
      [
        'test-host absent',
        [[hostCall, '      runTests(\n']],
        'test-host is absent: it has not completed in this run',
      ],
      [
        'test-host recorded twice',
        [[hostCall, `      testHost();\n${hostCall}`]],
        'test-host is recorded 2 times, so it has no one result',
      ],
      [
        'runtime-identity pending',
        [
          [
            identityCheck,
            `${identityCheck}    throw new PendingStage('synthetic: runtime-identity forced to stay pending in this fixture');\n`,
          ],
        ],
        'runtime-identity is pending \\(synthetic: runtime-identity forced to stay pending in this fixture\\)',
      ],
      [
        'runtime-identity absent in a contract run',
        [identityAbsent],
        'runtime-identity is absent: it has not completed in this run',
      ],
      [
        'runtime-identity recorded twice',
        [identityTwice],
        'runtime-identity is recorded 2 times, so it has no one result',
      ],
    ]) {
      const run = await gateFixture(t, {
        authority: 'all',
        runtimes,
        identified: true,
        patchGate,
      }).run('commit');
      assert.equal(run.result.status, 1, label);
      assert.equal(run.stage('platform-manifest').status, 'pass', label);
      noTestDispatch(run, fullTests, new RegExp(`${prerequisiteReason}${problem}`), label);
      assert.deepEqual(run.canary.sort(), ['import-lint', 'sql-lint'], label);
    }
    // A maintenance (B35) run is judged the same way (GDR6-REQ-01): the test below.
  }
);

// gate-draft-r7, GDR6-REQ-01, through the real gate. A maintenance (B35) candidate, whose history
// never held a platform manifest, is still judged as maintenance: no manifest, no catalog, no
// coverage, T8 or network stage, and its own approved runtimes, the gate's Node and the Node 24
// runtime (here the fixtures' stand-in), with no 1.5 matrix asked of it. Its gate now identifies
// exactly those runtimes before its test stages (the producer gate-draft-r6 lacked), each test
// stage starts only once test-host and runtime-identity passed and apply to it, and the finalizer's
// check of that evidence (maintenanceRuntimeProblems) accepts what the gate sealed. gate-draft-r6
// started both test stages of such a run with no runtime-identity at all.
test(
  'GDR6-REQ-01: through the real gate, a B35 maintenance run identifies exactly its approved runtimes and dispatches each of its test stages exactly once; with no identity record, or a pending, absent, twice-recorded or inapplicable runtime-identity, or a blocked test-host, it dispatches none it does not identify',
  { timeout: 300000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const finalization = await import('../scripts/security-finalization.mjs');
    const stand = fixtureRoot => path.join(path.dirname(fixtureRoot), 'bin/orbit-fixture-node24');
    // The positive control: a true B35-shaped candidate (no manifest anywhere, authority given) with
    // identity records for its two approved runtimes.
    const fixture = gateFixture(t, { authority: 'all', manifest: false, identified: true });
    const run = await fixture.run('commit');
    assert.equal(run.result.status, 1, 'a commit run is never a pass here');
    assert.equal(run.evidence.platform.kind, 'maintenance');
    assert.deepEqual(run.evidence.candidate.platformManifest, { state: 'never-held' });
    for (const name of [
      'platform-coverage-current-runtime',
      'platform-coverage-minimum-runtime',
      't8-image-identity',
      'network-policy',
    ])
      assert.equal(run.stage(name), undefined, `a maintenance run records no ${name}`);
    for (const name of ['candidate-policy', 'platform-manifest', 'test-host', 'runtime-identity'])
      assert.equal(run.stage(name)?.status, 'pass', `${name}: ${run.stage(name)?.error}`);
    // runtime-identity identified exactly the approved runtimes: the gate's own Node and the Node 24
    // runtime, by real path, version and sha256, and nothing of the 1.5 matrix (a Node 24 gate is
    // not asked for Node 26 here, as a contract run would be).
    assert.deepEqual(
      run.stage('runtime-identity').runtimes.map(({ path: real, version, sha256 }) => ({
        real,
        version,
        sha256,
      })),
      [
        {
          real: fs.realpathSync(process.execPath),
          version: process.version,
          sha256: executableSha256(process.execPath),
        },
        {
          real: fs.realpathSync(stand(fixture.root)),
          version: 'v24.0.0',
          sha256: executableSha256(stand(fixture.root)),
        },
      ]
    );
    // Each test stage of the maintenance route dispatched exactly once, on the runtime
    // runtime-identity identified, with its authority, after both prerequisites.
    const names = run.evidence.stages.map(item => item.name);
    for (const name of fullTests) {
      const stage = run.stage(name);
      assert.ok(stage.command, `${name} was dispatched`);
      assert.equal(names.filter(item => item === name).length, 1, name);
      assert.deepEqual(
        stage.authority?.map(item => item.purpose),
        ['test-image-builds'],
        name
      );
      assert.ok(
        run
          .stage('runtime-identity')
          .runtimes.some(
            item => item.sha256 === stage.runtime.sha256 && item.version === stage.runtime.version
          ),
        name
      );
      for (const first of ['test-host', 'runtime-identity'])
        assert.ok(names.indexOf(first) < names.indexOf(name), `${first} before ${name}`);
    }
    assert.deepEqual(run.canary.sort(), ['import-lint', 'sql-lint', 'test-file']);
    assert.equal(run.of('orbit-fixture-node24').filter(args => args !== '--version').length, 1);
    assert.deepEqual(
      run.of('docker').filter(args => args === 'build --tag synthetic-nested .'),
      ['build --tag synthetic-nested .']
    );
    assert.equal(run.connections, 1);
    // The consumer accepts the identity evidence the gate sealed (the check behind the finalizer's
    // early maintenance return), and refuses it once a record it consumes is changed.
    const sealed = finalization.readSealedRun(run.directory);
    assert.deepEqual(platform.maintenanceRuntimeProblems(sealed), []);
    // gate-draft-r10 (GDR9-HOST-SCHEMA-01): the run record's own host the 1.5 gate writes is exactly
    // the closed five-member form, which readSealedRun has just accepted.
    assert.deepEqual(finalization.runHostProblems(sealed.record.host), {
      variant: 'gate-1.5',
      problems: [],
    });
    assert.deepEqual(Object.keys(sealed.record.host).sort(), [
      'arch',
      'node',
      'platform',
      'release',
      'uid',
    ]);
    // gate-draft-r9 (GDR8-SCHEMA-01): every record this gate writes under a name of the approved
    // B35 plan is of its class's record form and of the closed schema of each member, at every
    // depth (test-host's host exactly { platform, uid, setfacl }, runtime-identity's runtimes,
    // a test slot's runtime, authority, unexecuted tests and totals, the pending Actionlint
    // stages' missing pin, the gate files, the platform judgment): these are the exact known
    // producer forms the proposed schema closes. The run as a whole is not a maintenance-plan run
    // (this lane's gate is the 1.5 gate, which also records stages outside the plan and the
    // composite `sast-rules`): the maintenance branch's own producer must still be shown to match.
    const planned = sealed.record.stages.filter(item =>
      platform.MAINTENANCE_PLAN.some(entry => entry.name === item.name)
    );
    assert.ok(planned.length >= 30, String(planned.length));
    for (const name of ['test-host', 'runtime-identity', ...fullTests, 'actionlint-version'])
      assert.ok(
        planned.some(item => item.name === name),
        `the gate recorded ${name}`
      );
    assert.deepEqual(Object.keys(run.stage('test-host').host).sort(), [
      'platform',
      'setfacl',
      'uid',
    ]);
    for (const item of planned) {
      assert.deepEqual(platform.maintenanceStageSchemaProblems(item), [], item.name);
      assert.deepEqual(platform.maintenancePlanProblems({ stages: [item] }), [], item.name);
    }
    const first = sealed.record.stages.find(item => item.name === 'runtime-identity').runtimes[0];
    const forged = {
      ...sealed,
      get: name =>
        name === first.record
          ? Buffer.from(
              JSON.stringify({ ...JSON.parse(sealed.get(name)), binarySha256: 'b'.repeat(64) })
            )
          : sealed.get(name),
    };
    assert.match(
      platform.maintenanceRuntimeProblems(forged).join('\n'),
      /the runtime identity record is for the binary "b{64}"/
    );

    // Negative controls, every other input passing (the barrier open, every authority given, the
    // dependencies installed): no test stage is dispatched.
    const hostCheck = "  return requirement('test-host', record => {\n";
    const identityCheck = "  return requirement('runtime-identity', record => {\n";
    for (const [label, options, problem] of [
      [
        'no runtime identity record',
        {},
        'runtime-identity is blocked \\(no runtime identity record for Node v',
      ],
      [
        'runtime-identity pending',
        {
          identified: true,
          patchGate: [
            [
              identityCheck,
              `${identityCheck}    throw new PendingStage('synthetic: runtime-identity forced to stay pending in this fixture');\n`,
            ],
          ],
        },
        'runtime-identity is pending \\(synthetic: runtime-identity forced to stay pending',
      ],
      [
        'runtime-identity absent',
        { identified: true, patchGate: [identityAbsent] },
        'runtime-identity is absent: it has not completed in this run',
      ],
      [
        'runtime-identity recorded twice',
        { identified: true, patchGate: [identityTwice] },
        'runtime-identity is recorded 2 times, so it has no one result',
      ],
      [
        'test-host blocked',
        {
          identified: true,
          patchGate: [
            [
              hostCheck,
              `${hostCheck}    throw new Error('synthetic: test-host forced to block in this fixture');\n`,
            ],
          ],
        },
        'test-host is blocked \\(synthetic: test-host forced to block in this fixture\\)',
      ],
    ]) {
      const negative = await gateFixture(t, {
        authority: 'all',
        manifest: false,
        ...options,
      }).run('commit');
      assert.equal(negative.result.status, 1, label);
      assert.equal(negative.evidence.platform.kind, 'maintenance', label);
      assert.equal(negative.stage('platform-manifest').status, 'pass', label);
      noTestDispatch(negative, fullTests, new RegExp(`${prerequisiteReason}${problem}`), label);
      assert.deepEqual(negative.canary.sort(), ['import-lint', 'sql-lint'], label);
    }
    // Inapplicable: a runtime-identity that passed without identifying the Node 24 runtime (the
    // fixture's gate made to leave it out of the record) starts the stage it identifies once and
    // withholds the one it does not.
    const partial = await gateFixture(t, {
      authority: 'all',
      manifest: false,
      identified: true,
      patchGate: [
        [
          '      record.runtimes.push({ ...runtime, record: file });\n',
          "      if (runtime.version !== 'v24.0.0') record.runtimes.push({ ...runtime, record: file });\n      else continue;\n",
        ],
      ],
    }).run('commit');
    assert.equal(partial.stage('runtime-identity').status, 'pass');
    assert.ok(partial.stage('full-tests-current-runtime').command);
    withheld(
      partial,
      'full-tests-minimum-runtime',
      new RegExp(
        `${prerequisiteReason}runtime-identity does not apply to full-tests-minimum-runtime: it does not identify Node "v24\\.0\\.0"`
      )
    );
    assert.deepEqual(
      partial.of('orbit-fixture-node24').filter(args => args !== '--version'),
      [],
      'the unidentified Node 24 runtime ran nothing'
    );
  }
);

// The positive control of all four test-stage rules: with a valid host and runtime combination
// (identity records for both runtimes; on Node 24 the manifest's Node 24 route), each test stage
// of a commit run and of a companion run is dispatched exactly once, nested and direct Docker
// attempts included.
test(
  'GD5-CARRY-01, the positive control: with valid host and runtime records each of the four test stages is dispatched exactly once, in a commit run and in a companion run',
  { timeout: 180000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const fixture = gateFixture(t, {
      authority: 'all',
      runtimes: gateRuntimes(),
      identified: true,
    });
    for (const [label, mode, names, canary] of [
      ['commit', 'commit', fullTests, ['import-lint', 'sql-lint', 'test-file']],
      ['companion', ['platform', `${host}-platform`], platformTests, ['test-file']],
    ]) {
      const run = await fixture.run(mode);
      assert.equal(run.result.status, 1, `${label}: never a pass here`);
      for (const name of ['test-host', 'runtime-identity'])
        assert.equal(run.stage(name).status, 'pass', `${label} ${name}: ${run.stage(name).error}`);
      for (const name of names) {
        const stage = run.stage(name);
        assert.ok(stage.command, `${label}: ${name} was dispatched`);
        assert.equal(run.evidence.stages.filter(item => item.name === name).length, 1);
        assert.deepEqual(
          stage.authority?.map(item => item.purpose),
          ['test-image-builds'],
          `${label}: ${name}`
        );
        assert.match(stage.runtime.sha256, /^[0-9a-f]{64}$/);
      }
      // The current runtime's stage ran the candidate's test once; the Node 24 stage's runtime is
      // the stand-in, started once for its tests.
      assert.deepEqual(run.canary.sort(), canary, label);
      assert.equal(
        run.of('orbit-fixture-node24').filter(args => args !== '--version').length,
        1,
        label
      );
      assert.deepEqual(
        run.of('docker').filter(args => args === 'build --tag synthetic-nested .'),
        ['build --tag synthetic-nested .'],
        label
      );
      assert.equal(run.connections, 1, label);
    }
  }
);

test(
  'Maintainer note 014104 item 2: the scan builds nothing and pulls nothing without authority; with it, it builds once without --pull, inspects, scans and removes that image once',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const refused = await gateFixture(t, { manifest: false }).run('scan');
    assert.equal(refused.result.status, 1);
    assert.deepEqual(refused.of('docker'), [], 'no Docker command at all');
    assert.ok(!refused.of('trivy').some(args => args.startsWith('image')));
    for (const name of [
      'container-build',
      'container-identity',
      'container-vulnerabilities',
      'container-sbom',
    ])
      withheld(
        refused,
        name,
        /no scan-image-build authority: no reviewed pre-build authority record/
      );
    assert.match(
      refused.stage('container-identity').reason,
      /the image it would inspect was not built: container-build is pending/
    );
    // With a synthetic authority: exactly one build, from the staged images only (no --pull).
    const built = await gateFixture(t, { authority: 'all', manifest: false }).run('scan');
    const docker = built.of('docker');
    assert.ok(
      docker.every(args => !/--pull/.test(args)),
      docker.join('; ')
    );
    const builds = docker.filter(args => args.startsWith('build '));
    assert.equal(builds.length, 1, docker.join('; '));
    const image = /^build --tag (orbit-security:[0-9a-f]{12}-[0-9a-f]{8}) \.$/.exec(builds[0])?.[1];
    assert.ok(image, builds[0]);
    assert.deepEqual(
      docker.filter(args => args.includes(image)),
      [`build --tag ${image} .`, `image inspect ${image}`, `image rm ${image}`]
    );
    assert.equal(
      built.of('trivy').filter(args => args.startsWith('image') && args.endsWith(image)).length,
      2
    );
  }
);

// verify-1 of gate-draft-r5 (a claim): the documents said the CI security scan runs both lints. In
// a CI checkout of a 1.5 commit the scan's candidate is the checked-out tree on top of a commit that
// holds the manifest, and no gate approval or reviewed baseline exists there (they are kept only in
// the local <git common dir>/orbit-security), so platform-manifest blocks, the barrier stays closed
// and the scan runs neither lint. This pins that behaviour, which the documents now state; with a
// reviewed baseline disposition (the local evidence a CI runner lacks) the same scan runs each lint
// once.
test(
  'round 2: on a CI-like checkout of a 1.5 commit (no gate approval, no baseline) the scan blocks at platform-manifest and runs neither lint; a reviewed baseline opens the barrier',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    for (const authority of [null, 'all']) {
      const fixture = gateFixture(t, { authority, manifest: 'unchanged' });
      const label = `authority ${authority}`;
      const ci = await fixture.run('scan');
      assert.equal(ci.result.status, 1, label);
      assert.equal(ci.evidence.status, 'blocked', label);
      assert.equal(ci.stage('candidate-policy').status, 'pass', ci.stage('candidate-policy').error);
      assert.equal(ci.stage('platform-manifest').status, 'blocked', label);
      assert.match(
        ci.stage('platform-manifest').error,
        /no reviewed manifest can be established for this candidate: no commit behind it that the gate approved holds a valid manifest/,
        label
      );
      assert.deepEqual(ci.canary, [], `${label}: no lint ran`);
      assert.equal(ci.connections, 0, label);
      for (const name of ['sql-lint', 'import-lint'])
        withheld(ci, name, /the pre-dispatch barrier is closed: platform-manifest is blocked/);
      assert.ok(!ci.of('docker').some(args => /^build\b/.test(args)), ci.of('docker').join('; '));
      // The reviewed baseline a developer's repository could hold: the committed manifest, bound
      // to this candidate's tree and parent. platform-manifest passes and the lints run once each.
      const tree = fixture.git('write-tree');
      const head = fixture.git('rev-parse', 'HEAD');
      const review = {
        reason: 'synthetic',
        reviewer: 'Synthetic reviewer',
        reference: 'synthetic review',
        tree,
        parents: [head],
      };
      const file = path.join(fixture.root, '.git/orbit-security/coverage', `${tree}.json`);
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        file,
        JSON.stringify({
          schemaVersion: 2,
          tree,
          parents: [head],
          dispositions: [
            {
              baseline: head,
              manifestSha256: createHash('sha256').update(manifest()).digest('hex'),
              ...review,
            },
          ],
        }),
        { mode: 0o600 }
      );
      const local = await fixture.run('scan');
      assert.equal(
        local.stage('platform-manifest').status,
        'pass',
        `${label}: ${local.stage('platform-manifest').error}`
      );
      assert.match(local.result.stdout, /Pre-dispatch barrier: open/, label);
      assert.deepEqual(local.canary.sort(), ['import-lint', 'sql-lint'], label);
      assert.equal(local.result.status, 1, `${label}: a scan is never a pass here`);
    }
  }
);

// verify-1 of gate-draft-r5 (low, fixed in round 2): through the real gate, a candidate file whose
// name holds a newline and an inline Trivy suppression blocks candidate-policy; the error names the
// file, and every withheld stage's reason is still one line, so the finalizer reads it as withheld.
test(
  'round 2: a candidate file name with a newline in a prerequisite error leaves every withheld reason one line, and nothing is dispatched',
  { timeout: 120000 },
  async t => {
    if (gitSkip) return t.skip(gitSkip);
    const fixture = gateFixture(t, {
      authority: 'all',
      files: { 'deploy/v1d\nname.yaml': '# trivy:ignore:AVD-DS-0002\nkey: value\n' },
    });
    for (const mode of ['commit', 'scan']) {
      const run = await fixture.run(mode);
      assert.equal(run.result.status, 1, mode);
      assert.equal(run.stage('candidate-policy').status, 'blocked', mode);
      assert.match(
        run.stage('candidate-policy').error,
        /^Inline Trivy suppression is not a reviewed disposition: deploy\/v1d\nname\.yaml$/
      );
      assert.deepEqual(run.canary, [], mode);
      assert.equal(run.connections, 0, mode);
      assert.ok(
        !run.of('npm').some(args => /^(?:ci|run|audit)\b/.test(args)),
        run.of('npm').join('; ')
      );
      assert.ok(!run.of('docker').some(args => /^build\b/.test(args)), run.of('docker').join('; '));
      const names = [
        'sql-lint',
        'import-lint',
        'dependencies-install',
        'format',
        'container-build',
      ];
      if (mode === 'commit') names.push('full-tests-current-runtime', 'full-tests-minimum-runtime');
      for (const name of names) {
        withheld(
          run,
          name,
          /candidate-policy is blocked \(Inline Trivy suppression is not a reviewed disposition: deploy\/v1d\\u000aname\.yaml\)/
        );
        assert.equal(platform.withheldStage(run.stage(name)), true, `${mode}: ${name}`);
      }
      for (const stage of run.evidence.stages.filter(item => item.status === 'pending'))
        assert.doesNotMatch(stage.reason, /[\u0000-\u001f\u007f]/, `${mode}: ${stage.name}`);
    }
  }
);

// ---------------------------------------------------------------------------------------------
// The finalizer and withheld stages: pending, never a pass, and no record may claim more

// Makes a stage record of a sealed synthetic run (test/helpers/platform-run.mjs) the record of a
// stage withheld before dispatch, as the gate writes one: its interval kept, nothing a command
// leaves, status pending and the reason.
const withholdRecord = (
  record,
  name,
  reason = 'withheld before dispatch, nothing ran: synthetic'
) => {
  const stage = record.stages.find(item => item.name === name);
  for (const key of Object.keys(stage))
    if (!['name', 'started', 'finished'].includes(key)) delete stage[key];
  Object.assign(stage, { status: 'pending', reason });
};

async function finalizerScenario(t, record) {
  const finalization = await import('../scripts/security-finalization.mjs');
  const security = temporary(t, 'orbit-dispatch-finalizer-');
  const candidate = fixtureImages.platformCandidate();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  fixtureImages.writeMainRun(run, candidate, { platform: 'linux', change: { record } });
  const companions = [fixtureImages.writeCompanion(security, candidate)];
  return finalization.inspectRun(run, { ...candidate.current, companions });
}
const blockersOf = inventory => inventory.blockers.join('\n');

test('the finalizer treats withheld test, coverage, network and T8 stages as pending, never a pass', async t => {
  // Every test stage withheld (the gate's default here), with what depends on it.
  const inventory = await finalizerScenario(t, record => {
    for (const slot of ['current-runtime', 'minimum-runtime']) {
      withholdRecord(record, `full-tests-${slot}`);
      withholdRecord(
        record,
        `platform-coverage-${slot}`,
        `full-tests-${slot} was withheld before dispatch, so there is no run of it to check`
      );
    }
    withholdRecord(record, 'network-policy', 'no test stage ran, so there is no network record');
    withholdRecord(record, 't8-image-identity');
    withholdRecord(
      record,
      't8-image-authenticity',
      't8-image-identity was withheld before dispatch'
    );
    withholdRecord(
      record,
      't8-image-activation',
      'nothing to bind: t8-image-identity was withheld'
    );
  });
  assert.deepEqual(inventory.blockers, []);
  assert.equal(inventory.eligible, true);
  assert.equal(inventory.verdict, 'pending');
  const pending = inventory.pending.join('\n');
  for (const name of ['full-tests-current-runtime', 'full-tests-minimum-runtime', 'network-policy'])
    assert.match(pending, new RegExp(`${name}: `), name);
  assert.match(pending, /is not tested on Node 2[46]: its test stage was withheld before dispatch/);
});

test('the finalizer refuses a coverage pass for a withheld test, a T8 container record whose inspect was withheld, a binding of nothing observed, and a "withheld" stage that ran', async t => {
  // A coverage stage that claims a pass although its test stage was withheld.
  const covered = await finalizerScenario(t, record =>
    withholdRecord(record, 'full-tests-current-runtime')
  );
  assert.match(
    blockersOf(covered),
    /platform-coverage-current-runtime is pass, but full-tests-current-runtime was withheld before dispatch, so there is no run to cover/
  );
  // The test stages ran (their records name the T8 images) but the inspect was withheld.
  const unobserved = await finalizerScenario(t, record => {
    withholdRecord(record, 't8-image-identity');
    withholdRecord(
      record,
      't8-image-authenticity',
      't8-image-identity was withheld before dispatch'
    );
    withholdRecord(record, 't8-image-activation', 'nothing to bind');
  });
  assert.match(
    blockersOf(unobserved),
    /a T8 container record names node:2[46]-bookworm-slim@sha256:[0-9a-f]{64}, but t8-image-identity was withheld before dispatch, so no identity of it was observed before candidate code ran/
  );
  // An activation that binds something (a sealed binding file) although the inspect was withheld.
  const bound = await finalizerScenario(t, (record, files) => {
    for (const slot of ['current-runtime', 'minimum-runtime']) {
      withholdRecord(record, `full-tests-${slot}`);
      withholdRecord(record, `platform-coverage-${slot}`, 'withheld test');
    }
    withholdRecord(record, 'network-policy', 'no test stage ran');
    withholdRecord(record, 't8-image-identity');
    withholdRecord(record, 't8-image-authenticity', 'withheld identity');
    record.stages.find(item => item.name === 't8-image-activation').binding =
      'synthetic-binding.json';
    files['synthetic-binding.json'] = '{"synthetic":true}\n';
  });
  assert.match(blockersOf(bound), /t8-image-activation: t8-image-identity sealed no observation/);
  // A pending test stage that carries what a command leaves is not a withheld one: it ran, and is
  // judged as a test stage that ran (here without its runtime and records), so it is refused.
  const ran = await finalizerScenario(t, record => {
    withholdRecord(record, 'full-tests-current-runtime');
    Object.assign(
      record.stages.find(item => item.name === 'full-tests-current-runtime'),
      { command: ['synthetic-fixture'], exit: 0 }
    );
  });
  assert.match(
    blockersOf(ran),
    /full-tests-current-runtime records no Node version and binary sha256/
  );
});

// ---------------------------------------------------------------------------------------------
// What the documents say the gate starts (verify-1 of gate-draft-r5, wording corrected in round 2)

const repositoryText = file => fs.readFileSync(path.join(repository, file), 'utf8');
// Whitespace, and the line breaks of a comment, read as single spaces.
const flatText = text => text.replace(/\s+/g, ' ');
const flatComments = (text, marker) =>
  flatText(text.replace(new RegExp(`\\n[ \\t]*(?:${marker})[ \\t]?`, 'g'), ' '));

test('round 2: the documents say the CI scan runs neither lint on a CI runner, what the Semgrep stages withhold, what starts directly, and that the lints are not contained', () => {
  const readme = flatText(repositoryText('README.md'));
  const contributing = flatText(repositoryText('CONTRIBUTING.md'));
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  const workflow = flatComments(repositoryText('.github/workflows/security.yml'), '#');
  const gate = flatComments(repositoryText('scripts/security-gate.mjs'), '\\/\\/');
  const dispatchSource = flatComments(repositoryText('scripts/security-dispatch.mjs'), '\\*');
  // The CI scan and the lints: no document says the scan runs them in every mode or on CI.
  for (const [file, text, stale] of [
    ['README.md', readme, 'not through npm) does.'],
    [
      'CONTRIBUTING.md',
      contributing,
      'but the CI security scan and the commit and release gates below do',
    ],
    ['docs/engineering-quality.md', quality, 'in every mode, including the CI security scan'],
    ['docs/engineering-quality.md', quality, 'as the 1.5 gate runs both in every mode'],
    ['CHANGELOG.md', changelog, 'it still ends pending with exit 1'],
    ['scripts/security-gate.mjs', gate, 'so every mode runs them, including the CI scan'],
    ['security.yml', workflow, 'dependency, Semgrep and image stages wait for their authority'],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
  for (const [file, text, current] of [
    ['README.md', readme, 'On a CI runner `platform-manifest` cannot pass for a 1.5 commit'],
    ['README.md', readme, 'so CI runs neither lint'],
    ['CONTRIBUTING.md', contributing, 'but the CI security scan never for a 1.5 commit'],
    [
      'docs/engineering-quality.md',
      quality,
      'The CI scan therefore records `platform-manifest` blocked and both lints withheld, and runs neither, so nothing in CI runs them',
    ],
    ['CHANGELOG.md', changelog, 'so the CI scan also runs neither the SQL nor the import lint'],
    ['security.yml', workflow, 'so here it withholds the lints too'],
    // The workflow's earlier steps are said to be outside the gate.
    [
      'security.yml',
      workflow,
      'The two steps above are not part of the gate and wait for none of its checks',
    ],
    ['scripts/security-gate.mjs', gate, 'so the CI scan runs neither lint'],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The Semgrep paragraph says what is withheld, not that the gate downloads the rules and runs
  // the image.
  assert.ok(
    !quality.includes(
      'The gate downloads checksum-pinned Semgrep rules and runs its digest-pinned image'
    )
  );
  assert.ok(
    quality.includes(
      'The digest-pinned Semgrep image is neither inspected nor run while `image-approval` is pending'
    )
  );
  assert.ok(quality.includes('so `sast-rules` is pending'));
  // Who runs the candidate's code with your privileges: what the gate starts, not more.
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CONTRIBUTING.md', contributing],
  ]) {
    assert.ok(
      !text.includes(
        "The gate runs the candidate's dependencies, scripts and tests with your privileges"
      ),
      file
    );
    assert.ok(
      text.includes('Whatever candidate code the gate starts runs with your privileges'),
      file
    );
  }
  // What starts without the dispatch point: the scan's clean-up `docker image rm` is named.
  assert.ok(
    quality.includes(
      'in scan mode, the clean-up `docker image rm` of the image a build made, which runs only after that build was dispatched under its authority'
    )
  );
  assert.ok(
    dispatchSource.includes(
      'in scan mode, the clean-up `docker image rm` of the image a build made'
    )
  );
  // The lints are named as candidate code the gate starts with no authority and does not contain.
  assert.ok(
    quality.includes(
      'the two lints, the only candidate code it starts today without any authority (they need only the open barrier), inherit the gate'
    )
  );
  // The recorded item: the authority seam. gate-draft-r6 (GD5-CARRY-01): the test stages'
  // prerequisites are consulted now, so the documents no longer name that gap but the rule.
  assert.ok(quality.includes('The authority module is not an authority boundary yet.'));
  assert.ok(
    !quality.includes(
      "a test stage's dispatch rule does not consult `test-host` or `runtime-identity`"
    )
  );
  for (const [file, text, current] of [
    [
      'docs/engineering-quality.md',
      quality,
      'A test stage also starts only once `test-host` and `runtime-identity` have passed',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "`runtime-identity` must list the stage's own Node binary by its sha256 and version",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'A test stage, of a gate run or of a companion run, now starts only once each has been recorded exactly once in that run',
    ],
    ['CHANGELOG.md', changelog, 'The required runtimes stay Node 24 and Node 26'],
    // gate-draft-r7 (GDR6-REQ-01): a maintenance run is held to the same rule, and the
    // runtime-substitution limitation stays named as open.
    [
      'docs/engineering-quality.md',
      quality,
      "A maintenance (B35) run, which is judged by the earlier gate's stage list, needs both as well",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'A maintenance (B35) run, which has no manifest, records `runtime-identity` too, for exactly the runtimes of its approved slots',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'a maintenance run without them, as the earlier gate wrote, is refused',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'so a binary or link replaced between the hash and the start is not caught',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'So a maintenance run now records `runtime-identity` too, before its test stages, for exactly its own approved runtimes',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'The finalizer and the commit guard now refuse a maintenance run that lacks either stage',
    ],
    ['CHANGELOG.md', changelog, 'so a binary replaced in between is not caught'],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The sixth round's maintenance exception is no longer described as the rule.
  for (const [file, text, stale] of [
    [
      'docs/engineering-quality.md',
      quality,
      "A maintenance (B35) run records no `runtime-identity` (it is judged by the earlier gate's stage list), so its test stages need `test-host` alone",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'a maintenance run, which records no `runtime-identity`, needs `test-host` alone',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'A maintenance run, whose history never held a platform manifest and which records no `runtime-identity`, needs `test-host` alone',
    ],
    [
      'scripts/security-dispatch.mjs',
      dispatchSource,
      'a maintenance run, which records no runtime-identity, needs test-host alone',
    ],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
});

// gate-draft-r8 (wording): GDR7-DOC-01, the Node 24 slot is described by the rule the gate
// implements, the gate's own Node plus the configured Node 24 executable when that executable is
// different (so a Node 24 gate may run two distinct Node 24 executables), not by the gate's Node
// major, and the runtime selection itself is unchanged; and the eighth round's plan and
// recorded-approval checks are described where the seventh round's are. (GDR7-HANDOFF-01 concerned
// an internal handoff document that is not part of the public source tree.)
test('GDR7-DOC-01: the documents describe the Node 24 slot by distinct executable, and the eighth round is described', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  const gateSource = repositoryText('scripts/security-gate.mjs');
  const gate = flatComments(gateSource, '\\/\\/');
  const rule =
    "the gate's own Node plus the configured Node 24 executable when that executable is different";
  for (const [file, text, current] of [
    [
      'docs/engineering-quality.md',
      quality,
      `Its gate identifies exactly its own approved runtimes, ${rule}, with no 1.5 runtime matrix`,
    ],
    [
      'docs/engineering-quality.md',
      quality,
      `records \`runtime-identity\` too, for exactly the runtimes of its approved slots, ${rule}, and is asked for no other`,
    ],
    ['CHANGELOG.md', changelog, `for exactly its own approved runtimes (${rule};`],
    [
      'scripts/security-gate.mjs',
      gate,
      "it identifies exactly its own approved runtimes, the gate's own Node plus the configured Node 24 executable when that executable is different, and no 1.5 matrix is asked of it",
    ],
    [
      'scripts/security-gate.mjs',
      gate,
      "The test stages of a run: the gate's own Node (current-runtime) plus the configured Node 24 executable (minimum-runtime) when that executable is different",
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  for (const [file, text, stale] of [
    ['docs/engineering-quality.md', quality, "the gate's Node and Node 24, with no 1.5 runtime"],
    ['docs/engineering-quality.md', quality, 'when that is not Node 24, the Node 24 runtime'],
    ['CHANGELOG.md', changelog, 'when that is not Node 24, the Node 24 runtime'],
    ['scripts/security-gate.mjs', gate, 'when that is not Node 24, the Node 24 runtime'],
    ['scripts/security-gate.mjs', gate, "Node 24 (when the gate's own runtime is not 24)"],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
  // The selection itself is as it was: a second slot whenever the configured Node 24 executable
  // is another file than the gate's own, whatever the gate's own Node is.
  assert.ok(
    gateSource.includes(
      "  if (minimumAvailable && minimumNode !== process.execPath)\n    planned.push({ slot: 'minimum-runtime', executable: minimumNode, version: minimumVersion });"
    )
  );
  // The eighth round, where the seventh is described.
  for (const [file, text, current] of [
    [
      'docs/engineering-quality.md',
      quality,
      'One approved B35 plan (`MAINTENANCE_PLAN` in `scripts/security-platform.mjs`) names every stage a maintenance run may record, with its execution class',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      '`--verify-commit` and the `reference-transaction` hook apply them again before a recorded maintenance approval gives authority over a new commit',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'One approved B35 plan now binds each stage a maintenance run may record to its execution class',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'an approval recorded under earlier rules for a run they refuse gives no authority, while its evidence is kept as it is',
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
});

// gate-draft-r8, round 2 (wording, for the internal check of the eighth round): the record forms,
// the nested executions and the recorded-approval reader's stage results are described where the
// eighth round is, each scoped to what the code does (the reader does not work out the lint stages
// a commit requires); and the one remaining comment that named the Node 24 slot by the gate's Node major
// names it by the rule the gate implements, its code unchanged.
test('GDR7-FIN-01 and GDR7-AUTH-01, round 2: the documents describe the record forms, the nested executions and the stage results the recorded-approval reader judges, no more, and the dispatch comment names the Node 24 slot by distinct executable', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  const dispatchText = repositoryText('scripts/security-dispatch.mjs');
  const dispatchComments = flatComments(dispatchText, '\\*');
  for (const [file, text, current] of [
    [
      'docs/engineering-quality.md',
      quality,
      "Each stage record may hold only the members of its class's record form and the data its own check records (`MAINTENANCE_RECORD_FORMS` and `MAINTENANCE_STAGE_DATA`), so `steps`, the 1.5 gate's composite form, and a member no producer writes are refused, and so is any record shaped as a stage record nested inside one",
    ],
    // The eighth round's own bullet (gate-draft-r9 corrects the reader's current description:
    // `--verify-commit` now derives the lint stages, GDR8-AUTH-LINT-01; see the test below).
    [
      'docs/engineering-quality.md',
      quality,
      "it still does not work out the lint stages a commit's own `package.json` requires",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'A corrective round of the eighth (2026-10-18 UTC) follows a check of it',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'the recorded-approval reader also judges the stage results the finalizer requires (a withheld or failed test stage gives no authority)',
    ],
    [
      'CHANGELOG.md',
      changelog,
      "each stage record of a maintenance run may now hold only the members of its class's record form, and a stage record nested in another, a test execution among them, is refused",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "it does not work out the lint stages a commit's `package.json` and its history require, which the commit guard does before the commit",
    ],
    [
      'scripts/security-dispatch.mjs',
      dispatchComments,
      "the gate identifies a maintenance run's own approved runtimes, the gate's own Node plus the configured Node 24 executable when that executable is different, as it does a contract run's",
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  assert.ok(
    !dispatchComments.includes("own approved runtimes, the gate's Node and Node 24, as it does"),
    'scripts/security-dispatch.mjs still names the Node 24 slot by the Node major'
  );
  // No document says the recorded-approval reader applies every rule of the finalizer again.
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'applies every check of the finalizer again',
      'the same rules again, so an old approval',
      'all of the finalizer',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r9 (wording; the maintainer's rule that docs and changelogs stay current): the ninth round is
// described where the eighth is, each claim scoped to what the code does: the recorded-approval
// reader's sealed scanner-result judgment and finding binding (GDR8-AUTH-SCAN-01), the closed
// nested schemas as a proposed interface, not an accepted one, with the maintenance producer's
// compatibility still to be shown (GDR8-SCHEMA-01), and the lint stages derived from the exact
// commit (GDR8-AUTH-LINT-01); the reader's description no longer says it does not derive them.
test('GDR8-AUTH-SCAN-01, GDR8-SCHEMA-01 and GDR8-AUTH-LINT-01: the documents describe the ninth round, the closed schema as a proposed interface, and the reader as it now is, no more', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "The gate draft's ninth round, for the security review of the eighth (GDR8-AUTH-SCAN-01, GDR8-SCHEMA-01, GDR8-AUTH-LINT-01)",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "the report, its findings, the exit and the status must agree (no finding, exit 0 and pass; findings, the scanner's finding exit and blocked, as the gate records them)",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "the schema is a proposed shared interface, not an accepted one, and the maintenance branch's own gate must still be shown to write exactly these forms",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "They now derive them from the commit's own tree, its parents in order and their history, as the commit guard does for its candidate, and never from the checkout, HEAD, a merge in progress or a caller",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "Still open, and not changed by this round: the runtime substitution limitation, the maintenance producer's compatibility with the schema, and parity of the reader with every other check of the finalizer",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the ninth round (2026-10-18, the security review's GDR8-AUTH-SCAN-01, GDR8-SCHEMA-01 and GDR8-AUTH-LINT-01 on the eighth round",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "This schema is a proposed shared interface, not an accepted one: the maintenance branch's own gate must still be shown to write exactly these forms",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "and the lint stages the commit's own `package.json`, its parents and their history require, which they derive from the commit as the commit guard does for its candidate, never from the checkout or a caller (GDR8-AUTH-LINT-01)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "with the findings it gives bound to the approval's count and to the retained review's dispositions, one each (GDR8-AUTH-SCAN-01)",
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The reader's current description no longer says it does not derive the lint stages.
  assert.ok(
    !quality.includes(
      "but not the lint stages a commit's `package.json` and its history require, which the commit guard works out before the commit, nor freshness"
    ),
    'docs/engineering-quality.md still says the reader does not derive the lint stages'
  );
  // No document calls the schema accepted, or the gate complete.
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'the schema is accepted',
      'an accepted shared interface',
      'the gate is complete',
      'applies every check of the finalizer again',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r9, round 2 (wording; the maintainer's rule that docs and changelogs stay current): the ninth
// round's corrective pass is described where the ninth round is, each claim scoped to what the
// code does: a history whose package.json object is missing refuses at the commit guard and after
// the commit (check-1 LINT-U1), the reader applies the finalizer's pending-stage rule to scanner
// stages, which now also holds a pending stage to record nothing a command leaves (CONTRACT-T4),
// and the reader reads a maintenance run's sealed coverage dispositions (SCHEMA-INFO2); the pass is
// not reviewed, and the reader's parity with the finalizer is still not claimed.
test("GDR8-AUTH-LINT-01 and GDR8-AUTH-SCAN-01, round 2: the documents describe the ninth round's corrective pass as it is, no more", () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      'Its corrective pass (2026-10-18, after an internal check of the ninth round) closes two more gaps and one named example of parity.',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'such a history is now refused, before the commit and after it, until the missing objects are fetched',
    ],
    [
      'CHANGELOG.md',
      changelog,
      "it now applies the finalizer's own rule that a pending stage has a reason and runs nothing, and that rule now also holds a pending stage to record no command, log, exit, signal or error, as the gate writes one (the finalizer's half of it is a tightening too)",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "The reader also reads a maintenance run's sealed coverage dispositions as the finalizer does. Still open, and not changed by this round:",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'Its corrective pass (2026-10-18, after an internal check) refuses a history whose `package.json` object is missing from the repository instead of reading that version as one without `package.json`, at the commit guard too',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'A version whose `package.json` Git records but cannot read blocks instead, because its object is missing from the repository (a partial or damaged clone) or because it is a submodule',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "and a scanner recorded as pending counting as one only when it has a reason and ran nothing, by the finalizer's own rule; a maintenance run's sealed coverage dispositions as the finalizer reads them",
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The parity of the reader with the finalizer stays open, and nothing calls the pass reviewed.
  assert.ok(
    changelog.includes(
      "Still open, and not changed by this round: the runtime substitution limitation, the maintenance producer's compatibility with the schema, and parity of the reader with every other check of the finalizer"
    )
  );
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'the corrective pass is reviewed',
      'the corrective pass was reviewed',
      'full parity',
      'every check of the finalizer again',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r10 (wording; the maintainer's rule that docs and changelogs stay current): the tenth round is
// described where the ninth is, each claim scoped to what the code does: the explicit repository
// binding (GDR9-AUTH-ROOT-01), the typed entry-first package.json reads with no lazy fetch and the
// correction of the ninth round's "can only refuse" claim (GDR9-AUTH-OBJECT-01), the shared
// stage/report reconciliation and the fixtures (GDR9-AUTH-SCAN-02), and the closed host forms as a
// proposed interface whose maintenance producer is still to be shown (GDR9-HOST-SCHEMA-01); nothing calls the gate
// complete, the schema accepted or the maintenance compatibility shown.
test('GDR9-AUTH-ROOT-01, GDR9-AUTH-OBJECT-01, GDR9-AUTH-SCAN-02 and GDR9-HOST-SCHEMA-01: the documents describe the tenth round as it is, no more', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "The gate draft's tenth round, for the security review of the ninth (GDR9-AUTH-ROOT-01, GDR9-AUTH-OBJECT-01, GDR9-AUTH-SCAN-02, GDR9-HOST-SCHEMA-01)",
    ],
    ['CHANGELOG.md', changelog, 'now goes through one runner bound to the repository at its root'],
    [
      'CHANGELOG.md',
      changelog,
      'only a tree with no `package.json` entry has none, and a missing or unreadable object, a directory, a submodule (readable or not), a symbolic link, a file over 16 MiB and any lookup error refuse, at the commit guard too',
    ],
    [
      'CHANGELOG.md',
      changelog,
      "The ninth round's own notes said that a commit whose `package.json` object is missing can only be refused; that was wrong, as the security review showed, and is corrected here.",
    ],
    ['CHANGELOG.md', changelog, 'this is a refusal path, not support for a first commit'],
    [
      'CHANGELOG.md',
      changelog,
      "one shared reconciliation of the scanners' stages and fixed reports now refuses a report beside a scanner that did not run, empty or not, and a report with no scanner stage at all",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "Both are part of the proposed shared interface, not an accepted one: no pinned source of the maintenance branch's gate was found that writes the three-member form (the one reachable source, the maintenance tree export `57b02f9d`, writes four members, `platform`, `arch`, `release` and `node`, in a record the shared reader does not read at all), so that producer's compatibility stays open and needs a decision.",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the tenth round (2026-10-18, the security review's GDR9-AUTH-ROOT-01, GDR9-AUTH-OBJECT-01, GDR9-AUTH-SCAN-02 and GDR9-HOST-SCHEMA-01 on the ninth round",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the tenth round every version, the candidate's and its parents' included, is read from its tree entry first and by its type (GDR9-AUTH-OBJECT-01)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the tenth round the record's own `host` is one of two closed, typed forms too (GDR9-HOST-SCHEMA-01; a proposed shared interface)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "an inherited `GIT_DIR`, `GIT_WORK_TREE` or `GIT_COMMON_DIR` must name that repository, as Git's own hook environment does in the main and in a linked worktree, and another one is refused rather than followed",
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The ninth round's overstated sentence is not repeated as current, and nothing claims more.
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'cannot be read or is not in canonical form (the form `candidate-policy` requires',
      'the gate is complete',
      'the schema is accepted',
      'an accepted shared interface',
      'the tenth round is reviewed',
      'compatibility is shown',
      'root commits are supported',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r10 round 2 (check-1's claim item; the maintainer's rule that docs and changelogs stay current):
// the tenth round's documents said that no check, or no authority or gate read, can fetch a
// missing object from a promisor remote. Only the authority reads and the gate's own Git runner are
// bound; the gate's stage commands (its snapshot clone and its history secret scan) still run Git
// with the gate's inherited environment. The documents now say so, and describe the round's
// corrective pass (the host form by record kind, malformed package.json content, alternates files
// and the root's letter case) as not reviewed; the overstated sentences are gone, the earlier
// "one malformed old version cannot block a branch" among them.
test('GDR9-AUTH-OBJECT-01, round 2 (check-1 claim): the documents scope the no-lazy-fetch claim to the authority reads and the gate runner, name the uncovered stage commands, and describe the corrective pass as not reviewed', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "No authority read, and no read of the gate's own Git runner, lets Git fetch a missing object from a partial clone's promisor remote",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "The gate's stage commands are not covered yet: its snapshot clone and its history secret scan still run Git with the gate's inherited environment",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "a record now carries the form its producer writes, the 1.5 gate's five members for a contract or companion run, and either form for a maintenance run, which both gates write",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'A `package.json` that can be read but is not well formed (not UTF-8 text, not JSON, not a JSON object, or a `scripts` member that is not an object) still gave authority',
    ],
    [
      'CHANGELOG.md',
      changelog,
      "An alternates file that names another object store, in the repository's own object directory or in its quarantine, now refuses as well",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "No read of the guard, `--verify-commit`, the `reference-transaction` hook or the gate's own Git runner fetches a missing object from a promisor remote",
    ],
    // gate-draft-r11 (GDR10-AUTH-STAGE-01): the stage commands are covered since the eleventh round,
    // so the sentence that said they were not is gone (the eleventh round's test below).
    [
      'docs/engineering-quality.md',
      quality,
      'a contract commit record and a companion record, which only the 1.5 gate writes, carry its five members',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "a file whose content is not well formed (since the round's corrective pass: not UTF-8 text, not JSON, not a JSON object, or a `scripts` member that is not an object)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "an alternates file that names another object store, in the repository's object directory or in its quarantine, is refused too",
    ],
    // gate-draft-r11: the tenth round and its corrective pass are now reviewed (REVISE BEFORE
    // INTEGRATION), and the stage commands are covered (the eleventh round's test below).
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'No authority or gate read lets Git fetch',
      'No check fetches a missing object',
      'no check fetches them',
      'one malformed or ambiguous old version cannot block a branch for good',
      'a `package.json` that is absent, does not parse or has no `scripts` object defines neither script',
      'the corrective pass is reviewed',
      'the stage commands are covered',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r11 (the maintainer's rule that docs and changelogs stay current; maintainer note 20261019T083721636234Z):
// the documents describe the eleventh round as it is, no more. The alternates file is read as Git
// reads it (GDR10-ALT-PARSE-01); every stage gets one environment with no Git selector, no injected
// configuration and no lazy fetch, the snapshot steps bound to the snapshot and the history scan to
// the validated root (GDR10-AUTH-STAGE-01); the maintenance host form is the producer's four
// members while its record family and parents stay open (GDR10-HOST-PRODUCER-01). The current-state
// sentences the eleventh round makes untrue are gone from the engineering-quality document (the changelog's tenth-round entry is history and stays as it was).
test('GDR10-ALT-PARSE-01, GDR10-AUTH-STAGE-01 and GDR10-HOST-PRODUCER-01: the documents describe the eleventh round as it is, no more', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "The gate draft's eleventh round, for the security review of the tenth (GDR10-ALT-PARSE-01, GDR10-AUTH-STAGE-01, GDR10-HOST-PRODUCER-01) and the maintainer's assignment of 2026-10-19 (engineering; a draft, not reviewed, never run as a full gate; no approval can come from it yet).",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'The file is now read byte for byte as Git reads it: only an empty record and a record whose first byte is `#` name no store',
    ],
    [
      'CHANGELOG.md',
      changelog,
      "Every process the gate starts now gets one environment of its own, with no Git selector, no injected configuration, no Git configuration file chosen by the caller's environment (since the corrective round below), no Git variable but a few named ones and `GIT_NO_LAZY_FETCH=1`",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "the snapshot is cloned with it alone, the snapshot's own two steps are bound to the snapshot, the history secret scan reads the repository the gate's binding validated, and the npm, test and documentation stages find the snapshot from the folder they run in",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'it is now the four members the maintenance producer writes, `platform`, `arch`, `release` and `node`',
    ],
    ['CHANGELOG.md', changelog, 'so its record-family and ordered-parent compatibility stay open'],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the eleventh round (2026-10-19, the security review's GDR10-ALT-PARSE-01, GDR10-AUTH-STAGE-01 and GDR10-HOST-PRODUCER-01 on the tenth round",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "since the eleventh round the maintenance producer's own `{ platform, arch, release, node }`",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'since the eleventh round its records are read byte for byte as Git reads them, so only an empty record and one whose first byte is `#` name none',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'Since the eleventh round no stage of the gate does either (GDR10-AUTH-STAGE-01)',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'The eleventh (2026-10-19) follows the security review of the tenth (REVISE BEFORE INTEGRATION, which closes GDR9-AUTH-SCAN-02',
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The current-state sentences the eleventh round makes untrue are gone.
  for (const [file, text, stale] of [
    ['docs/engineering-quality.md', quality, 'are not covered yet'],
    ['docs/engineering-quality.md', quality, "the maintenance form's `{ node, platform, arch }`"],
    [
      'docs/engineering-quality.md',
      quality,
      "the three-member maintenance form's producer is still to be shown",
    ],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'the eleventh round is reviewed',
      'the gate is complete',
      'the schema is accepted',
      'an accepted shared interface',
      'record-family compatibility is shown',
      'parent compatibility is shown',
      'compatibility is shown',
      'root commits are supported',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// Round 2 of gate-draft-r11 (check-1 R11C1-CLAIM-CONF; the maintainer's rule that docs and changelogs stay
// current): the documents describe the corrective round as it is, no more. A stage reads no Git
// configuration, attributes or ignore file the caller's environment chooses; the run record names
// the caller's own environment; the repository's own attributes, for the history secret scan, and
// the user's configuration files the binding still admits for the gate's own reads stay open; and
// the round-1 sentences that said more than its code did are gone.
test('GDR10-AUTH-STAGE-01, round 2: the documents describe the corrective round as it is, no more', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      'A corrective round of the eleventh (2026-10-21 UTC) follows a check of it',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'a URL rewrite there made the snapshot a clone of another repository, with every stage passing, or started a remote helper',
    ],
    [
      'CHANGELOG.md',
      changelog,
      '(`GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` are `/dev/null` and `GIT_CONFIG_NOSYSTEM=1`)',
    ],
    ['CHANGELOG.md', changelog, '(`core.attributesFile` and `core.excludesFile` are `/dev/null`)'],
    [
      'CHANGELOG.md',
      changelog,
      "The run record's `inheritedEnvironment` again names the caller's own environment, the Git variables no stage gets among them",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "Still open: the repository's own attributes (a committed `.gitattributes`, or `info/attributes`) can still hide history content from that scan's Git command",
    ],
    [
      'CHANGELOG.md',
      changelog,
      "the gate's own Git runner and the authority reads still read the user's configuration files, as the binding admits them",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'the eleventh round 2026-10-19 and its corrective round 2026-10-21',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'A corrective round of the eleventh (2026-10-21 UTC) follows a check of it',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "no Git configuration, attributes or ignore file chosen by the caller's environment (since the round's corrective pass of 2026-10-21)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'the names of every variable it inherits from you after those removals (before it sets Git variables of its own, so a Git variable named there may reach no stage)',
    ],
    // (gate-draft-r12: the current-state sentences that the round-2 correction left open, the
    // repository's own attributes and the binding's configuration files, are the twelfth round's
    // two findings, and their own test below holds the documents to what replaced them.)
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The round-1 sentences that said more than its code did (check-1 R11C1-CLAIM-CONF) are gone.
  for (const [file, text, stale] of [
    [
      'CHANGELOG.md',
      changelog,
      "(the user's own configuration files among them, as the binding admits them)",
    ],
    ['docs/engineering-quality.md', quality, 'no injected configuration and no lazy fetch'],
    [
      'docs/engineering-quality.md',
      quality,
      'no injected configuration and `GIT_NO_LAZY_FETCH=1`;',
    ],
    ['docs/engineering-quality.md', quality, 'the names of every variable the stages inherit'],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'the corrective round is reviewed',
      'its corrective round is reviewed',
      'no configuration reaches any stage',
      'the history scan cannot be hidden',
      'the history secret scan sees everything',
      'the stage environment is closed',
      'the gate is complete',
      'the schema is accepted',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// gate-draft-r12 (the security review's GDR11-AUTH-CONFIG-01 and GDR11-HISTORY-ATTRS-01; the maintainer's rule that docs
// and changelogs stay current): the documents describe the twelfth round as it is, no more. The
// gate's own reads and every authority read follow the stages' configuration policy, the history
// scan's Git command is independent of attributes and configuration, the metadata scan reads raw
// objects and is blocked when it cannot read them all, the pinned scanner's qualification stays
// pending, and the eleventh round's open sentences for these two findings are gone.
test('GDR11-AUTH-CONFIG-01 and GDR11-HISTORY-ATTRS-01: the documents describe the twelfth round as it is, no more', () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  const options =
    '--all --root --text --no-textconv --no-ext-diff --no-color --encoding=UTF-8 --pretty=medium --date=default --no-decorate --no-abbrev-commit --no-show-signature --no-notes --src-prefix=a/ --dst-prefix=b/';
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "The gate draft's twelfth round, for the security review of the eleventh (GDR11-AUTH-CONFIG-01, GDR11-HISTORY-ATTRS-01) and the maintainer's assignment of 2026-10-21 (engineering; a draft, not reviewed, never run as a full gate; no approval can come from it yet).",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'The binding now follows the one configuration policy every stage follows',
    ],
    [
      'CHANGELOG.md',
      changelog,
      '(`core.fsmonitor=false`, `i18n.logOutputEncoding=UTF-8`, `log.showSignature=false`, and each filter driver the repository defines switched off)',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'read raw (`rev-list --all`, then `cat-file --batch`), each checked by type, size and hash, with the enumeration checked for every parent, ref, HEAD and tag of a tag',
    ],
    ['CHANGELOG.md', changelog, 'blocks that scan instead of shrinking its input'],
    ['CHANGELOG.md', changelog, `set Git's default output form (\`${options}\`)`],
    [
      'CHANGELOG.md',
      changelog,
      'Still open: the pinned Gitleaks 8.30.1 has not run on these inputs, so whether it reports a real secret through the actual gate in every hostile case is still to be qualified',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'since the binding honours no `safe.directory` from any configuration file (not measured with a genuine other owner)',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the twelfth round (2026-10-21, the security review's GDR11-AUTH-CONFIG-01 and GDR11-HISTORY-ATTRS-01 on the eleventh round, under the maintainer's assignment of 2026-10-21)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'the eleventh round 2026-10-19 and its corrective round 2026-10-21, and the twelfth round 2026-10-21)',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'The twelfth (2026-10-21) follows the security review of the eleventh (REVISE BEFORE INTEGRATION',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the twelfth round the gate's own reads and every authority read follow that policy too (GDR11-AUTH-CONFIG-01)",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'the pinned Gitleaks 8.30.1 has not run on them, so its qualification on them is still to come',
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  // The eleventh round's sentences that this round makes untrue are gone from the current-state
  // documents (the eleventh round's own changelog entry keeps its history).
  for (const [file, text, stale] of [
    [
      'docs/engineering-quality.md',
      quality,
      "Still open: the repository's own attributes (a committed `.gitattributes`, `info/attributes`) apply to that scan's Git command",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "the gate's own reads still use the configuration files your environment names",
    ],
  ])
    assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ])
    for (const claim of [
      'the twelfth round is reviewed',
      'the eleventh round is accepted',
      'the scanner is qualified',
      'Gitleaks reports every',
      'the history scan cannot be hidden',
      'the gate is complete',
      'the schema is accepted',
      'VALIDATED',
      'cross-owner repositories are supported',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
});

// Round 2 of gate-draft-r12 (check-1 of its first round; the maintainer's rule that docs and changelogs stay
// current): the documents describe the corrective pass as it is. The encoding refusal of the
// metadata input (R12C1-META-ENC-01), the 'key'='value' switch-off of filter drivers
// (R12C1-FILTER-EQ-01), hooks (R12C1-HOOK-01), the binding's HOME (R12C1-HOME-INCLUDE-01) and the
// submodule disposition (R12C1-SUBMODULE-FILTER-01) are stated; the first pass's history claims
// that check-1 found broader than measured (R12C1-HISTORY-CLAIM-01: "every change as its own text",
// byte for byte "under every hostile setting measured") are gone, and the limits that replace them
// (header bytes under three settings, no patch for a merge) are stated.
test("R12C1-META-ENC-01, R12C1-FILTER-EQ-01, R12C1-HOOK-01, R12C1-HOME-INCLUDE-01, R12C1-SUBMODULE-FILTER-01 and R12C1-HISTORY-CLAIM-01: the documents describe the twelfth round's corrective pass as it is, no more", () => {
  const quality = flatText(repositoryText('docs/engineering-quality.md'));
  const changelog = flatText(repositoryText('CHANGELOG.md'));
  for (const [file, text, current] of [
    [
      'CHANGELOG.md',
      changelog,
      "Since the round's corrective pass (2026-10-21, after an internal check), those switch-off settings are given in Git's `'key'='value'` form, so a filter driver named with `=` is switched off too",
    ],
    [
      'CHANGELOG.md',
      changelog,
      'no hook runs for a bound read (no hooks folder, `core.hooksPath=/dev/null`, for every read but `git rev-parse`',
    ],
    ['CHANGELOG.md', changelog, "the binding's `HOME` names no folder"],
    [
      'CHANGELOG.md',
      changelog,
      'Since the corrective pass a commit whose `encoding` header names anything but UTF-8, US-ASCII, ISO-8859-1 to -16 or Windows-1250 to -1258 blocks it too',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'those three, `mailmap.file`, `core.quotePath=false` and `diff.renames=false`, still change header bytes',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'A merge shows no patch, so content that only a merge introduces is in none, as before.',
    ],
    [
      'CHANGELOG.md',
      changelog,
      'but the gate refuses a candidate that holds a submodule before that check',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'Its corrective pass (2026-10-21, after an internal check) corrects two problems that check found',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'no fsmonitor, filter, hook or signature program of the caller',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      "Since the round's corrective pass those switch-off settings are given in Git's `'key'='value'` form",
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'nor its own configuration can hide content from the patches it shows (GDR11-HISTORY-ATTRS-01); a merge shows no patch',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'and since the corrective pass so does a commit whose `encoding` header names anything but UTF-8',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'needs Git 2.31 or later for those settings, and with an older Git it is refused (not measured)',
    ],
    [
      'docs/engineering-quality.md',
      quality,
      'but for a file that a `~/` include in the configuration of the repository a stage reads names',
    ],
  ])
    assert.ok(text.includes(current), `${file} does not say: ${current}`);
  for (const [file, text] of [
    ['docs/engineering-quality.md', quality],
    ['CHANGELOG.md', changelog],
  ]) {
    for (const stale of [
      'every change as its own text',
      'under every hostile setting measured, what that command shows is byte for byte',
    ])
      assert.ok(!text.includes(stale), `${file} still says: ${stale}`);
    for (const claim of [
      'the corrective pass is reviewed',
      'cannot change the headers',
      'every setting Git has is measured',
      'the history scan cannot be hidden',
      'the scanner is qualified',
      'submodules are supported',
      'VALIDATED',
    ])
      assert.ok(!text.includes(claim), `${file} claims more than the code does: ${claim}`);
  }
});
