// gate-draft-r5: the local run record's own family (Daybreak GDR4-02, P2; a new defect fixed).
//
// gate-draft-r4's local one-run result named `schemaVersion: 3` and its documents described reading
// it as GATE-CONTRACT v5 C12's phase-record schema 3, a different and much larger form. Codex's
// answer 014104 item 6c: the local result is not a C12 phase record; if it stays, it gets an
// explicit record kind of its own, checked before its fields, with its version in that family.
// Since gate-draft-r5 it is `kind: "orbit-gate-local-diagnostic-run"`, `kindVersion: 1`, and C12's
// vocabulary (`schema`, phase-record schema 3) is the C12 forms' alone. These tests check that the
// family is judged first and alone, in both directions: a local record presented as a C12 phase
// record and a C12-shaped record presented as a local record are each refused before any other
// member is read; so are a record with no family, an unknown family, a wrong version, the keys of
// two families, the frozen r4 form (no inferred migration) and every fallback. They test the
// family selection only: no C12 phase record is produced or read in this draft (the controller's
// producers and F's readers are int-d's work), and nothing here is evidence of C12 compliance.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const finalization = await import('../scripts/security-finalization.mjs');
const platform = await import('../scripts/security-platform.mjs');
const fixture = await import('./helpers/platform-run.mjs');

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// A sealed synthetic gate run and its record, as the gate writes the local family.
function localRun(t, change = {}) {
  const security = temporary(t, 'orbit-record-family-');
  const candidate = fixture.platformCandidate();
  const run = path.join(security, `${candidate.current.tree}-commit-synthetic`);
  fixture.writeMainRun(run, candidate, { platform: 'linux', change });
  const record = JSON.parse(fs.readFileSync(path.join(run, 'result.json'), 'utf8'));
  return { run, record, candidate };
}

// A record shaped as v5 C12 phase-record schema 3 lists it (C12 "Fields, exactly these"), with
// synthetic values: what a C12 producer would write for `phase`. Shape only, for the family test.
function c12Record(phase) {
  const hex = digit => digit.repeat(64);
  return {
    schema: 3,
    phase,
    runId: 'synthetic-run',
    runNonce: hex('a'),
    mode: 'commit',
    profile: phase === 'platform' ? 'darwin-platform' : 'linux-full',
    catalogSha256: hex('b'),
    candidate: {
      tree: 'c'.repeat(40),
      parents: ['d'.repeat(40)],
      filesSha256: hex('e'),
      platformManifest: { state: 'valid', sha256: hex('f') },
      identitySha256: hex('1'),
    },
    controllerSha256: hex('2'),
    reviewFileSha256: hex('3'),
    gateIdentity: { version: 3 },
    environment: {},
    preparedInputs: {},
    startedAt: '2026-10-16T10:00:00.000Z',
    endedAt: '2026-10-16T10:10:00.000Z',
    stages: [],
    ...(phase === 'platform'
      ? { platformRun: 'darwin-platform', host: { platform: 'darwin' } }
      : phase === 'offline'
        ? { grantSha256: hex('4') }
        : {}),
  };
}
const asBytes = value => Buffer.from(JSON.stringify(value));
const without = (value, ...keys) => {
  const copy = structuredClone(value);
  for (const key of keys) delete copy[key];
  return copy;
};

test('GDR4-02: the gate writes, and the reader accepts, only its own local family; the family names no C12 vocabulary', t => {
  const { record } = localRun(t);
  assert.equal(platform.LOCAL_RUN_KIND, 'orbit-gate-local-diagnostic-run');
  assert.equal(platform.LOCAL_RUN_KIND_VERSION, 1);
  assert.equal(finalization.LOCAL_RUN_KIND, platform.LOCAL_RUN_KIND);
  assert.equal(record.kind, platform.LOCAL_RUN_KIND);
  assert.equal(record.kindVersion, 1);
  for (const key of ['schema', 'schemaVersion', 'phase', 'runNonce', 'startedAt', 'endedAt'])
    assert.equal(Object.hasOwn(record, key), false, key);
  assert.deepEqual(finalization.recordFamily(record), { family: 'local-run', version: 1 });
  assert.doesNotThrow(() => finalization.parseRunRecord(asBytes(record)));
  // The gate itself writes the family (scripts/security-gate.mjs), not schemaVersion.
  const gate = fs.readFileSync(new URL('../scripts/security-gate.mjs', import.meta.url), 'utf8');
  assert.match(gate, /kind: LOCAL_RUN_KIND,\n\s*kindVersion: LOCAL_RUN_KIND_VERSION,/);
  assert.doesNotMatch(gate, /schemaVersion: 3/);
});

test('GDR4-02: a C12-shaped phase record presented as a local run record is refused by its family, before any other member is read', t => {
  const { run } = localRun(t);
  for (const phase of finalization.C12_PHASES) {
    const value = c12Record(phase);
    assert.deepEqual(finalization.recordFamily(value), { family: 'c12-phase', schema: 3, phase });
    const refusal = new RegExp(
      `presents itself as a C12 phase record \\(schema 3, phase ${phase}\\): it is not an orbit-gate-local-diagnostic-run record, and this reader reads no C12 record`
    );
    assert.throws(() => finalization.parseRunRecord(asBytes(value)), refusal, phase);
    // Before any other member: the same refusal with only the family's members, or with a mode
    // the reader would refuse, or with the local members added (then it is mixed, below).
    assert.throws(() => finalization.parseRunRecord(asBytes({ schema: 3, phase })), refusal, phase);
    assert.throws(
      () => finalization.parseRunRecord(asBytes({ ...value, mode: 'scan' }), { mode: 'platform' }),
      refusal,
      phase
    );
    assert.throws(() => finalization.expectRecordFamily(value, 'local-run'), refusal, phase);
  }
  // Through the finalizer: a sealed run whose result.json is C12-shaped.
  fs.chmodSync(path.join(run, 'result.json'), 0o600);
  const sealedC12 = path.join(path.dirname(run), 'c12-shaped-commit-run');
  fs.mkdirSync(sealedC12, { mode: 0o700 });
  for (const name of fs.readdirSync(run).filter(item => item !== 'run-manifest.json'))
    fs.copyFileSync(path.join(run, name), path.join(sealedC12, name));
  fs.writeFileSync(path.join(sealedC12, 'result.json'), JSON.stringify(c12Record('offline')), {
    mode: 0o600,
  });
  finalization.sealRun(sealedC12);
  assert.throws(
    () => finalization.readSealedRun(sealedC12),
    /presents itself as a C12 phase record \(schema 3, phase offline\)/
  );
});

test('GDR4-02: a local run record presented as a C12 phase record is refused by its family, before any other member is read', t => {
  const { record } = localRun(t);
  const refusal =
    /is an orbit-gate-local-diagnostic-run record \(version 1\), a local diagnostic run record: it is not a C12 phase record, and it is not read as one/;
  assert.throws(() => finalization.expectRecordFamily(record, 'c12-phase'), refusal);
  // With only its family members, or with a phase and C12 members added but no `schema`.
  assert.throws(
    () => finalization.expectRecordFamily({ kind: record.kind, kindVersion: 1 }, 'c12-phase'),
    refusal
  );
  assert.throws(
    () =>
      finalization.expectRecordFamily(
        { ...record, phase: 'offline', runNonce: 'a'.repeat(64), grantSha256: 'b'.repeat(64) },
        'c12-phase'
      ),
    refusal
  );
  // An unknown family is no family: refused, never taken as either.
  assert.throws(
    () => finalization.expectRecordFamily({ kind: 'c12-phase' }, 'c12-phase'),
    /names the unknown record family "c12-phase"/
  );
  assert.throws(() => finalization.expectRecordFamily(record, 'another-family'), refusal);
});

test('GDR4-02: no family, an unknown family, a wrong version, mixed family keys, the frozen r4 form, inferred migration and every fallback are refused', t => {
  const { record: good, run } = localRun(t);
  const read = value => finalization.parseRunRecord(asBytes(value));
  const unlabelled = without(good, 'kind', 'kindVersion');
  const frozen =
    /names schemaVersion 3: that is the frozen gate-draft-r4 local form \(schemaVersion 3\), a record pack or another form, not a record of the local run family, and it is not migrated, converted or read as one/;
  for (const [label, value, pattern] of [
    // No family, or only part of one.
    [
      'no family (the r4 members, unlabelled)',
      unlabelled,
      /names no record family: none is assumed or inferred from its members/,
    ],
    ['an empty object', {}, /names no record family/],
    [
      'a version without a family',
      without(good, 'kind'),
      /names a family version but no family \(kind\): none is assumed/,
    ],
    [
      'a family without a version',
      without(good, 'kindVersion'),
      /names no kindVersion: no version of the family is assumed/,
    ],
    // Unknown families.
    [
      'another kind',
      { ...good, kind: 'orbit-gate-run' },
      /names the unknown record family "orbit-gate-run"/,
    ],
    [
      'the kind in another case',
      { ...good, kind: 'Orbit-Gate-Local-Diagnostic-Run' },
      /unknown record family/,
    ],
    ['a kind that is not text', { ...good, kind: 1 }, /names the unknown record family 1/],
    // Wrong versions: no fallback to version 1.
    [
      'version 2',
      { ...good, kindVersion: 2 },
      /names kindVersion 2: only version 1 of the family is read, with no fallback or migration/,
    ],
    ['version 0', { ...good, kindVersion: 0 }, /names kindVersion 0/],
    [
      'version 3 (the r4 number, as this family)',
      { ...good, kindVersion: 3 },
      /names kindVersion 3/,
    ],
    ['the text "1"', { ...good, kindVersion: '1' }, /names kindVersion "1"/],
    ['null', { ...good, kindVersion: null }, /names kindVersion null/],
    ['1.5', { ...good, kindVersion: 1.5 }, /names kindVersion 1\.5/],
    // Mixed keys of two families.
    [
      'the family and C12 schema 3',
      { ...good, schema: 3 },
      /names members of more than one record family \(kind, kindVersion, schema\): a mixed record is refused/,
    ],
    [
      'the family and the r4 schemaVersion 3',
      { ...good, schemaVersion: 3 },
      /names members of more than one record family \(kind, kindVersion, schemaVersion\)/,
    ],
    [
      'a family version and C12 schema 3',
      { ...unlabelled, kindVersion: 1, schema: 3, phase: 'network' },
      /names members of more than one record family \(kindVersion, schema\)/,
    ],
    [
      'C12 schema and the r4 schemaVersion',
      { ...c12Record('network'), schemaVersion: 3 },
      /names members of more than one record family \(schema, schemaVersion\)/,
    ],
    // The frozen r4 form, and other schemaVersion forms: no inferred migration.
    ['the frozen gate-draft-r4 form', { ...unlabelled, schemaVersion: 3 }, frozen],
    [
      'the r4 number as text',
      { ...unlabelled, schemaVersion: '3' },
      /names schemaVersion "3": that is the frozen gate-draft-r4 local form/,
    ],
    [
      'an older schemaVersion 2 form',
      { ...unlabelled, schemaVersion: 2 },
      /names schemaVersion 2: that is the frozen gate-draft-r4 local form/,
    ],
    // C12 forms other than schema 3, or without a phase: no fallback.
    [
      'C12 schema 2',
      { ...c12Record('network'), schema: 2 },
      /presents itself as a C12 phase record of schema 2: only phase-record schema 3 is a C12 form, with no fallback/,
    ],
    [
      'C12 schema 4',
      { ...c12Record('network'), schema: 4 },
      /of schema 4: only phase-record schema 3/,
    ],
    [
      'C12 schema "3"',
      { ...c12Record('network'), schema: '3' },
      /of schema "3": only phase-record schema 3/,
    ],
    [
      'C12 without a phase',
      without(c12Record('network'), 'phase'),
      /without one of the phases network, offline, platform/,
    ],
    [
      'C12 with an unknown phase',
      { ...c12Record('network'), phase: 'local' },
      /without one of the phases network, offline, platform/,
    ],
    // Not a record at all.
    ['a list', [good], /is not a run record/],
  ])
    assert.throws(() => read(value), pattern, label);
  // The family is judged before the mode and every other member.
  assert.throws(
    () => finalization.parseRunRecord(asBytes({ ...good, kindVersion: 2 }), { mode: 'platform' }),
    /names kindVersion 2/
  );
  // A member named twice is refused by the strict reader before any family is chosen.
  assert.throws(
    () =>
      finalization.parseRunRecord(Buffer.from(`{"kindVersion":2,${JSON.stringify(good).slice(1)}`)),
    /names the member "kindVersion" twice/
  );
  // The record pack's own format is no run record either.
  const records = temporary(t, 'orbit-record-family-pack-');
  fs.writeFileSync(
    path.join(records, '4242-00000000-0000-0000-0000-000000000000.jsonl'),
    '{"kind":"result"}\n'
  );
  assert.throws(
    () => finalization.parseRunRecord(platform.packRecords(records)),
    /names schemaVersion 2: that is the frozen gate-draft-r4 local form \(schemaVersion 3\), a record pack/
  );
  // Through the finalizer: a sealed run in the frozen r4 form is refused, not migrated.
  const security = path.dirname(run);
  const r4 = path.join(security, 'r4-form-commit-run');
  fs.mkdirSync(r4, { mode: 0o700 });
  for (const name of fs.readdirSync(run).filter(item => item !== 'run-manifest.json'))
    fs.copyFileSync(path.join(run, name), path.join(r4, name));
  fs.chmodSync(path.join(r4, 'result.json'), 0o600);
  fs.writeFileSync(
    path.join(r4, 'result.json'),
    JSON.stringify({ ...unlabelled, schemaVersion: 3 })
  );
  finalization.sealRun(r4);
  assert.throws(() => finalization.readSealedRun(r4), frozen);
});

test('GDR4-02: the documents no longer describe the local run record as C12 phase-record schema 3', () => {
  const quality = fs.readFileSync(
    new URL('../docs/engineering-quality.md', import.meta.url),
    'utf8'
  );
  const bullet = quality.split('\n').find(line => line.startsWith('- **The run record'));
  assert.ok(bullet, 'the run record bullet');
  assert.match(bullet, /orbit-gate-local-diagnostic-run/);
  assert.match(bullet, /not a C12 phase record/);
  assert.doesNotMatch(bullet, /only schema 3 is read/);
  const reader = fs.readFileSync(
    new URL('../scripts/security-finalization.mjs', import.meta.url),
    'utf8'
  );
  assert.doesNotMatch(reader, /RUN_SCHEMA/);
});
