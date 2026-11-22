// The gate identity's version (Daybreak GCV3-03; GATE-CONTRACT v4 C1, C12, C14, a draft that has
// not been reviewed): the eight-part identity is version 3; every reader in this tree refuses
// versions 1 and 2 with no fallback, and binds the version wherever it binds the identity. The
// negative controls: a seven-part record labelled 3, an eight-part record labelled 2, and any
// fallback (no version, another form of 3, an older binding). Every record here is synthetic; no
// trusted bootstrap computed it, and this tree never passes the gate-identity stage.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const load = async () => ({
  identity: await import('../scripts/security-gate-identity.mjs'),
  catalog: await import('../scripts/security-catalog.mjs'),
  finalization: await import('../scripts/security-finalization.mjs'),
  platform: await import('../scripts/security-platform.mjs'),
  fixture: await import('./helpers/platform-run.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A version 1, 2 and 3 record of the same synthetic gate, each with the parts of its version. */
function records(fixture) {
  const v3 = fixture.syntheticGateIdentity();
  const { catalogSha256, ...v2 } = { ...v3, version: 2 };
  const v1 = {
    entrySha256: v3.entrySha256,
    closureSha256: v3.closureSha256,
    configSha256: v3.configSha256,
    toolPinsSha256: v3.toolPinsSha256,
    runtime: { node24: '4'.repeat(64), node26: '6'.repeat(64) },
  };
  assert.equal(catalogSha256, v3.catalogSha256);
  return { v1, v2, v3 };
}

test('the eight-part gate identity is version 3, and only version 3 is read', async () => {
  const { identity, catalog, fixture } = await load();
  assert.equal(identity.GATE_IDENTITY_VERSION, 3);
  assert.deepEqual(
    [...identity.GATE_IDENTITY_PARTS],
    [
      'catalogSha256',
      'closureSha256',
      'configSha256',
      'entrySha256',
      'runtime',
      'toolPaths',
      'toolPinsSha256',
      'version',
    ]
  );
  const { v3 } = records(fixture);
  const parsed = identity.parseGateIdentity(v3);
  assert.deepEqual(parsed, v3);
  assert.ok(Object.isFrozen(parsed));
  const bytes = Buffer.from(catalog.canonicalJson(v3));
  assert.deepEqual(identity.parseGateIdentityBytes(bytes), v3);
  assert.equal(identity.gateIdentitySha256(v3), sha(bytes));
  // Wherever the identity is bound by digest, its version is bound beside it.
  assert.deepEqual(identity.gateIdentityBinding(v3), { sha256: sha(bytes), version: 3 });
  assert.deepEqual(identity.parseGateIdentityBinding({ sha256: sha(bytes), version: 3 }), {
    sha256: sha(bytes),
    version: 3,
  });
});

test('GCV3-03 negative controls: a seven-part record labelled 3, an eight-part record labelled 2, older versions and every fallback fail', async () => {
  const { identity, catalog, fixture } = await load();
  const { v1, v2, v3 } = records(fixture);
  const { catalogSha256: _dropped, ...sevenLabelled3 } = v3;
  for (const [label, value, pattern] of [
    ['a seven-part record labelled 3', sevenLabelled3, /version 3 lacks catalogSha256/],
    [
      'an eight-part record labelled 2',
      { ...v3, version: 2 },
      /is version 2 \(seven parts\), which gives no authority/,
    ],
    ['the version 2 record itself', v2, /is version 2 \(seven parts\), which gives no authority/],
    [
      'an eight-part record labelled 1',
      { ...v3, version: 1 },
      /is version 1 \(five parts\), which gives no authority/,
    ],
    [
      'the version 1 record (no version member)',
      v1,
      /names no version: there is no default version, and none is inferred from its parts/,
    ],
    ['eight parts and no version', (({ version: _v, ...rest }) => rest)(v3), /names no version/],
    ['the version as text', { ...v3, version: '3' }, /unknown version "3"/],
    ['version 4', { ...v3, version: 4 }, /unknown version 4/],
    [
      'version 3 with a ninth part',
      { ...v3, gateIdentityVersion: 2 },
      /has the unknown part "gateIdentityVersion"/,
    ],
    [
      'version 3 with a seven-part runtime',
      { ...v3, runtime: { node24: '4'.repeat(64), node26: '6'.repeat(64) } },
      /runtime\.node24 is not an object/,
    ],
    [
      'a relative tool path',
      { ...v3, toolPaths: { ...v3.toolPaths, trivy: 'trivy' } },
      /toolPaths\.trivy is not an absolute/,
    ],
    [
      'a catalog digest in upper case',
      { ...v3, catalogSha256: v3.catalogSha256.toUpperCase() },
      /catalogSha256 is not 64 lowercase hex/,
    ],
    ['a list holding the record', [v3], /is not an object/],
  ])
    assert.throws(() => identity.parseGateIdentity(value), pattern, label);
  // Version 1 and 2 are refused before any other part is read: an eight-part record labelled 2
  // gives the version as the reason, never its parts.
  assert.throws(
    () => identity.parseGateIdentity({ version: 2, anything: true }),
    /is version 2 .*no reader for an older version and no fallback/
  );
  // Bytes: only the canonical JSON of a version 3 record (so no member named twice, and 3.0 is
  // not 3 in another form).
  const canonical = catalog.canonicalJson(v3);
  for (const [label, text, pattern] of [
    ['pretty-printed', JSON.stringify(v3, null, 2), /not canonical JSON/],
    ['a member named twice', canonical.replace('{', '{"version":2,'), /not canonical JSON/],
    ['3.0', canonical.replace('"version":3', '"version":3.0'), /not canonical JSON/],
    ['the version 2 record', catalog.canonicalJson(v2), /is version 2/],
  ])
    assert.throws(() => identity.parseGateIdentityBytes(Buffer.from(text)), pattern, label);
  // Bindings: { sha256, version: 3 } exactly.
  const sha256 = identity.gateIdentitySha256(v3);
  for (const [label, value, pattern] of [
    ['version 2', { sha256, version: 2 }, /binding is version 2/],
    ['version 1', { sha256, version: 1 }, /binding is version 1/],
    ['no version', { sha256 }, /binding names no version/],
    ['the version as text', { sha256, version: '3' }, /binding has the unknown version/],
    ['the record instead of a binding', v3, /binding lacks sha256, has the unknown part/],
    ['a digest in a list', { sha256: [sha256], version: 3 }, /binding sha256 is not/],
    ['nothing', undefined, /binding is not an object/],
  ])
    assert.throws(() => identity.parseGateIdentityBinding(value), pattern, label);
  // There is no reader for an older version: the module exports none.
  assert.deepEqual(
    Object.keys(identity).filter(name => /v1|v2|legacy|fallback|migrat/i.test(name)),
    []
  );
});

/** A Linux gate run with a darwin-platform companion; `main` and `companion` change the records. */
async function scenario(t, { main = {}, companion = {}, now = Date.now() } = {}) {
  const modules = await load();
  const security = temporary(t, 'orbit-gate-identity-runs-');
  const candidate = modules.fixture.platformCandidate();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  modules.fixture.writeMainRun(run, candidate, { platform: 'linux', now, change: main });
  const companions = [
    modules.fixture.writeCompanion(security, candidate, { now, change: companion }),
  ];
  const inspect = () =>
    modules.finalization.inspectRun(run, { ...candidate.current, companions }, now);
  return { ...modules, security, candidate, run, companions, inspect, now };
}
const gateStage = record => record.stages.find(stage => stage.name === 'gate-identity');

test("the finalizer reads a run's gate identity as version 3 only, refuses versions 1 and 2, and never passes it", async t => {
  const control = await scenario(t);
  const inventory = control.inspect();
  assert.deepEqual(inventory.blockers, []);
  // A valid version 3 record is bound with its version, and still pending: only F compares it.
  assert.deepEqual(
    inventory.gateIdentity,
    control.identity.gateIdentityBinding(control.fixture.syntheticGateIdentity())
  );
  assert.equal(inventory.verdict, 'pending');
  assert.match(inventory.pending.join('\n'), /gate-identity is pending/);
  assert.match(inventory.pending.join('\n'), /only F compares it with the Mac-side record/);
  const { v1, v2, v3 } = records(control.fixture);
  const { catalogSha256: _dropped, ...sevenLabelled3 } = v3;
  for (const [label, change, pattern] of [
    [
      'a seven-part record labelled 3',
      r => (gateStage(r).gateIdentity = sevenLabelled3),
      /Gate identity: .*version 3 lacks catalogSha256/,
    ],
    [
      'an eight-part record labelled 2',
      r => (gateStage(r).gateIdentity = { ...v3, version: 2 }),
      /Gate identity: .*is version 2/,
    ],
    [
      'the version 2 record',
      r => (gateStage(r).gateIdentity = v2),
      /Gate identity: .*is version 2/,
    ],
    [
      'the version 1 record',
      r => (gateStage(r).gateIdentity = v1),
      /Gate identity: .*names no version/,
    ],
    [
      'another catalog',
      r => (gateStage(r).gateIdentity = { ...v3, catalogSha256: '0'.repeat(64) }),
      /binds the catalog 0{64}, not the installed/,
    ],
    [
      'a pass with no record',
      r => delete gateStage(r).gateIdentity,
      /passed without a gate identity record/,
    ],
    [
      'a pending stage holding a version 2 record',
      r =>
        Object.assign(gateStage(r), {
          status: 'pending',
          reason: 'synthetic: the trusted bootstrap is pending',
          gateIdentity: v2,
        }),
      /Gate identity: .*is version 2/,
    ],
  ]) {
    const s = await scenario(t, { main: { record: change } });
    assert.match(s.inspect().blockers.join('\n'), pattern, label);
  }
  // A companion's gate identity is read the same way.
  const companion = await scenario(t, {
    companion: { record: r => (gateStage(r).gateIdentity = { ...v3, version: 2 }) },
  });
  assert.match(companion.inspect().blockers.join('\n'), /is version 2/);
  // A pending stage without a record is pending (the gate's own state today).
  const pending = await scenario(t, {
    main: {
      record: r => {
        const stage = gateStage(r);
        delete stage.gateIdentity;
        Object.assign(stage, { status: 'pending', reason: 'synthetic: the bootstrap is pending' });
      },
    },
  });
  const pendingInventory = pending.inspect();
  assert.deepEqual(pendingInventory.blockers, []);
  assert.equal(pendingInventory.gateIdentity, null);
});

test('a finalization binds the gate identity with its version, and the commit guard and the history cache accept only that version 3 binding', async t => {
  const modules = await load();
  const security = temporary(t, 'orbit-gate-identity-final-');
  const candidate = modules.fixture.platformCandidate();
  const now = Date.now();
  const { run, companions, approval } = modules.fixture.finalizePlatformRun(security, candidate, {
    now,
  });
  assert.equal(approval.status, 'pending');
  const binding = modules.identity.gateIdentityBinding(modules.fixture.syntheticGateIdentity());
  assert.deepEqual(approval.gateIdentity, binding);
  modules.fixture.asIfFinalizedByF(run);
  const current = { ...candidate.current, companions: undefined };
  const file = path.join(run, 'finalization', 'approval.json');
  const original = fs.readFileSync(file, 'utf8');
  // Control: as F would write it, the guard accepts it, and recordedApproval reads it.
  assert.equal(modules.finalization.validateFinalization(run, current, now).status, 'pass');
  assert.equal(
    modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages })
      .approval.status,
    'pass'
  );
  for (const [label, change, pattern] of [
    [
      'version 2',
      a => (a.gateIdentity = { ...a.gateIdentity, version: 2 }),
      /binding is version 2/,
    ],
    [
      'version 1',
      a => (a.gateIdentity = { ...a.gateIdentity, version: 1 }),
      /binding is version 1/,
    ],
    ['no binding', a => delete a.gateIdentity, /binding is not an object/],
    ['no version', a => delete a.gateIdentity.version, /binding names no version/],
    [
      'another digest',
      a => (a.gateIdentity = { ...a.gateIdentity, sha256: '0'.repeat(64) }),
      /does not bind the gate identity its run records/,
    ],
    [
      'the eight-part record labelled 2',
      a => (a.gateIdentity = { ...modules.fixture.syntheticGateIdentity(), version: 2 }),
      /binding is version 2/,
    ],
  ]) {
    const value = JSON.parse(original);
    change(value);
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    assert.throws(
      () => modules.finalization.validateFinalization(run, current, now),
      pattern,
      label
    );
    assert.throws(
      () =>
        modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages }),
      pattern,
      label
    );
  }
  fs.writeFileSync(file, original, { mode: 0o600 });
  assert.equal(modules.finalization.validateFinalization(run, current, now).status, 'pass');
  assert.ok(companions.length);
});

// verify-1 of gate-draft-r3: the canonical-bytes rule lived only in parseGateIdentityBytes, which
// no consumer calls, and the finalizer, the guard and recordedApproval read result.json with
// JSON.parse, where the last of two members wins: a sealed gate identity naming "version" 2 and
// then 3 was read as version 3. Every reader of a sealed run, its review and its approval now
// refuses a member named twice in any object (GCV3-03, the reader-disagreement class).
test('a sealed record, review or approval that names a member twice is refused by every reader', async t => {
  const modules = await load();
  const twice = (file, marker, extra) => {
    const text = fs.readFileSync(file, 'utf8');
    assert.ok(text.includes(marker), `${path.basename(file)} holds ${marker}`);
    fs.writeFileSync(file, text.replace(marker, `${marker}${extra}`), { mode: 0o600 });
  };
  const reseal = run => {
    fs.rmSync(path.join(run, 'run-manifest.json'));
    modules.finalization.sealRun(run);
  };
  // The main run's gate identity, "version" 2 before its 3.
  const main = await scenario(t, {});
  assert.deepEqual(main.inspect().blockers, []);
  twice(path.join(main.run, 'result.json'), '"gateIdentity":{', '"version":2,');
  reseal(main.run);
  assert.throws(
    () => main.inspect(),
    /Invalid evidence JSON: result\.json names the member "version" twice/
  );
  // A companion's.
  const companion = await scenario(t, {});
  twice(path.join(companion.companions[0], 'result.json'), '"gateIdentity":{', '"version":2,');
  reseal(companion.companions[0]);
  assert.match(
    companion.inspect().blockers.join('\n'),
    /Invalid evidence JSON: result\.json names the member "version" twice/
  );
  // A finalization: its approval and its retained review, for the guard, recordedApproval and the
  // history cache.
  const security = temporary(t, 'orbit-gate-identity-twice-');
  const candidate = modules.fixture.platformCandidate();
  const now = Date.now();
  const { run } = modules.fixture.finalizePlatformRun(security, candidate, { now });
  modules.fixture.asIfFinalizedByF(run);
  const current = { ...candidate.current, companions: undefined };
  const keys = new Set([
    modules.platform.identityKey(candidate.current.tree, candidate.current.parents),
  ]);
  assert.equal(modules.finalization.validateFinalization(run, current, now).status, 'pass');
  assert.equal(
    modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages })
      .approval.status,
    'pass'
  );
  assert.equal(modules.finalization.approvedManifests(security, keys).size, 1);
  const approvalFile = path.join(run, 'finalization', 'approval.json');
  const approvalText = fs.readFileSync(approvalFile, 'utf8');
  twice(approvalFile, '"status": "pass"', ',\n  "status": "pass"');
  assert.throws(
    () => modules.finalization.validateFinalization(run, current, now),
    /approval\.json names the member "status" twice/
  );
  assert.throws(
    () => modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages }),
    /approval\.json names the member "status" twice/
  );
  assert.equal(modules.finalization.approvedManifests(security, keys).size, 0);
  fs.writeFileSync(approvalFile, approvalText, { mode: 0o600 });
  const reviewFile = path.join(run, 'finalization', 'review.json');
  const reviewText = fs.readFileSync(reviewFile, 'utf8');
  const reviewed = reviewText.replace('{', '{"reviewer":"Another synthetic reviewer",');
  fs.writeFileSync(reviewFile, reviewed, { mode: 0o600 });
  // The approval names the review's digest, so bind it to these bytes to reach the reader.
  const approval = JSON.parse(approvalText);
  approval.reviewSha256 = sha(Buffer.from(reviewed));
  fs.writeFileSync(approvalFile, `${JSON.stringify(approval, null, 2)}\n`, { mode: 0o600 });
  assert.throws(
    () => modules.finalization.validateFinalization(run, current, now),
    /review\.json names the member "reviewer" twice/
  );
  assert.throws(
    () => modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages }),
    /review\.json names the member "reviewer" twice/
  );
  assert.equal(modules.finalization.approvedManifests(security, keys).size, 0);
});

// verify-1 of gate-draft-r3 (Codex decision 3 asks to bind the profile to the reviewed identity
// and evidence; GCV3-03 binds the identity wherever records name it): the approval now binds the
// record-pack entry profile its packs were read with, and each companion's own gate identity,
// inside the platform evidence its review names.
test("a finalization binds the record-pack profile and each companion's gate identity with the platform evidence", async t => {
  const modules = await load();
  const security = temporary(t, 'orbit-gate-identity-bindings-');
  const candidate = modules.fixture.platformCandidate();
  const now = Date.now();
  const { run, approval } = modules.fixture.finalizePlatformRun(security, candidate, { now });
  assert.deepEqual(approval.platform.recordPack, modules.platform.recordPackIdentity());
  assert.equal(approval.platform.recordPack.name, 'record-pack');
  assert.equal(approval.platform.recordPack.version, 1);
  assert.equal(approval.platform.companions.length, 1);
  assert.deepEqual(
    approval.platform.companions[0].gateIdentity,
    modules.identity.gateIdentityBinding(modules.fixture.syntheticGateIdentity())
  );
  modules.fixture.asIfFinalizedByF(run);
  assert.equal(
    modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages })
      .approval.status,
    'pass'
  );
  // An approval naming another profile, its platform digest and its review rebound to match: the
  // installed validator refuses it once the commit exists.
  const approvalFile = path.join(run, 'finalization', 'approval.json');
  const reviewFile = path.join(run, 'finalization', 'review.json');
  const forged = JSON.parse(fs.readFileSync(approvalFile, 'utf8'));
  forged.platform.recordPack = { ...forged.platform.recordPack, sha256: '0'.repeat(64) };
  forged.platformSha256 = sha(JSON.stringify(forged.platform));
  const review = JSON.parse(fs.readFileSync(reviewFile, 'utf8'));
  review.platformSha256 = forged.platformSha256;
  const reviewBytes = Buffer.from(JSON.stringify(review));
  fs.writeFileSync(reviewFile, reviewBytes, { mode: 0o600 });
  forged.reviewSha256 = sha(reviewBytes);
  fs.writeFileSync(approvalFile, `${JSON.stringify(forged, null, 2)}\n`, { mode: 0o600 });
  assert.throws(
    () => modules.finalization.recordedApproval(run, { lintStages: candidate.current.lintStages }),
    /binds another record-pack entry profile than the installed validator and catalog \(Codex decision 3; v5 C21, C24\)/
  );
  // The guard, which judges the platform evidence again, refuses it too.
  assert.throws(() =>
    modules.finalization.validateFinalization(
      run,
      { ...candidate.current, companions: undefined },
      now
    )
  );
});
