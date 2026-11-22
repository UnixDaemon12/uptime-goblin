// The platform coverage contract (test/platform-manifest.json) and the helpers that bind a test
// to its platform (test/helpers/platform.mjs): the tracked manifest is valid, every entry is
// registered exactly once through platformTest or platformSubtest in its file and no call names
// an id the manifest lacks; the validator refuses what Codex listed (2026-10-11, items 3 and 4);
// a test is absent on another platform and fails on a missing prerequisite; and a run with
// TEST_PLATFORM_RECORDS writes a record of each bound test, while malformed settings fail.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  allTestFiles,
  duplicateMembers,
  limits,
  parseManifest,
  readRecords,
} from '../scripts/check-platform-coverage.mjs';
import {
  bindEntry,
  platformDecision,
  platformManifest,
  platformSubtest,
  platformTest,
  recordSettings,
  runPlatform,
  writePlatformRecord,
} from './helpers/platform.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
const tracked = JSON.parse(read('test/platform-manifest.json'));
const temporary = t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-platform-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
};

// Calls that bind a test to a platform: the first literal after import.meta.url is the id.
const bindingCall =
  /\b(platformTest|platformSubtest|partBTest)\(\s*(?:[A-Za-z_$][\w$]*,\s*)?import\.meta\.url,\s*'([^'\n]*)'/g;
/**
 * The lines of `source` with a call of platformTest, platformSubtest or partBTest that does not
 * pass its own file's import.meta.url and a literal id. The helper takes the file from the URL it
 * is given (verify-1): a call with a URL made for another file would bind that file's entry.
 */
function unboundCalls(source) {
  const shape =
    /(?:platformTest|platformSubtest|partBTest)\(\s*(?:[A-Za-z_$][\w$]*,\s*)?import\.meta\.url,\s*'[^'\n]*'/y;
  return [...source.matchAll(/\b(?:platformTest|platformSubtest|partBTest)\(/g)]
    .filter(match => {
      shape.lastIndex = match.index;
      return !shape.test(source);
    })
    .map(match => source.slice(0, match.index).split('\n').length);
}

test('platform manifest: the tracked contract is valid, and each entry is registered once in its own file', () => {
  const { problems, manifest } = parseManifest(read('test/platform-manifest.json'));
  assert.deepEqual(problems, []);
  assert.deepEqual(Object.keys(manifest.runs), [
    'darwin-full',
    'darwin-platform',
    'linux-full',
    't8-container',
  ]);
  const calls = new Map();
  // This file is left out: it calls platformTest with other files' ids to show the refusal.
  for (const file of allTestFiles(repository)
    .concat(['test/helpers/t8.mjs'])
    .filter(name => name !== 'test/platform-manifest.test.mjs'))
    for (const match of read(file).matchAll(bindingCall)) {
      const list = calls.get(match[2]) ?? [];
      list.push(file);
      calls.set(match[2], list);
    }
  for (const entry of manifest.entries) {
    assert.ok(fs.existsSync(path.join(repository, entry.file)), entry.file);
    assert.deepEqual(calls.get(entry.id), [entry.file], `${entry.id}: one call, in ${entry.file}`);
  }
  for (const id of calls.keys())
    assert.ok(
      manifest.entries.some(entry => entry.id === id),
      `${id} is bound in ${calls.get(id)} but not listed`
    );
  // Every call names its own file: import.meta.url, then a literal id.
  for (const file of allTestFiles(repository)
    .concat(['test/helpers/t8.mjs'])
    .filter(name => name !== 'test/platform-manifest.test.mjs'))
    assert.deepEqual(unboundCalls(read(file)), [], `${file}: calls without import.meta.url`);
  assert.deepEqual(
    unboundCalls(
      [
        "platformTest(import.meta.url, 'a.b', 'name', {}, () => {});",
        "await platformSubtest(t, import.meta.url, 'a.c', 'name', {}, () => {});",
        "platformTest(new URL('./docs-audit.test.mjs', import.meta.url), 'a.d', 'n', {}, f);",
        "platformTest(url, 'a.e', 'n', {}, f);",
        "partBTest(import.meta.url, id, 'n', {}, f);",
      ].join('\n')
    ),
    [3, 4, 5]
  );
  // Every run's listed file exists, and the macOS platform run covers every file that holds a
  // Linux or macOS test (keyring, CLI, upgrade identity, the access lists and the rest).
  for (const run of Object.values(manifest.runs))
    if (Array.isArray(run.files))
      for (const file of run.files) assert.ok(fs.existsSync(path.join(repository, file)), file);
  const hostFiles = [
    ...new Set(
      manifest.entries
        .filter(entry => entry.platforms.length === 1 && entry.platforms[0] !== 'container')
        .map(entry => entry.file)
    ),
  ].sort();
  assert.deepEqual(manifest.runs['darwin-platform'].files, hostFiles);
  // The test files the glob runs; none under fixtures.
  assert.ok(allTestFiles(repository).includes('test/disk-full.test.mjs'));
  assert.ok(!allTestFiles(repository).some(file => file.startsWith('test/fixtures/')));
});

// Codex 2026-10-11 item 3: strict data. Each case is the tracked manifest with one change.
test('platform manifest: the validator refuses duplicates, unknown fields, unbounded paths, names TAP cannot match exactly, and inconsistent runs', () => {
  const problems = change => {
    const copy = structuredClone(tracked);
    change(copy);
    return parseManifest(JSON.stringify(copy)).problems.join('\n');
  };
  const entry = copy => copy.entries.find(item => item.id === 'docs-audit.log-acl.linux');
  const cases = [
    [c => (c.schemaVersion = 2), /schemaVersion is 2, not 1/],
    [c => (c.extra = true), /the manifest has the unknown field "extra"/],
    [c => (c.runs['linux-full'].note = 'x'), /run "linux-full" has the unknown field "note"/],
    [c => (entry(c).reviewer = 'x'), /has the unknown field "reviewer"/],
    [c => delete entry(c).evidence, /lacks evidence/],
    [c => (c.entries = []), /entries is empty/],
    [c => (c.runs = {}), /runs is empty/],
    [c => c.entries.push(structuredClone(entry(c))), /the id is used twice/],
    [
      c => c.entries.push({ ...structuredClone(entry(c)), id: 'docs-audit.log-acl.copy' }),
      /another entry has the same file and name/,
    ],
    [c => (entry(c).id = 'Docs.Audit'), /not a valid id/],
    [c => (entry(c).id = 'a'.repeat(81)), /not a valid id/],
    [c => (entry(c).file = '/etc/passwd'), /file is not a bounded test file path/],
    [c => (entry(c).file = 'test/../../x.test.mjs'), /file is not a bounded test file path/],
    [c => (entry(c).file = 'test/docs-audit.mjs'), /file is not a bounded test file path/],
    [c => (entry(c).file = 'test/Docs-audit.test.mjs'), /file is not a bounded test file path/],
    [c => (entry(c).file = `test/${'a/'.repeat(4)}x.test.mjs`), /not a bounded test file path/],
    [c => (entry(c).file = `test/${'a'.repeat(200)}.test.mjs`), /not a bounded test file path/],
    [c => (entry(c).name = []), /name is not a path of 1 to 3 test names/],
    [c => (entry(c).name = ['a', 'b', 'c', 'd']), /name is not a path of 1 to 3 test names/],
    [c => (entry(c).name = ['a # SKIP']), /holds #, \\ or a control character/],
    [c => (entry(c).name = ['a \\ b']), /holds #, \\ or a control character/],
    [c => (entry(c).name = ['line\nbreak']), /holds #, \\ or a control character/],
    [c => (entry(c).name = ['tab\there']), /holds #, \\ or a control character/],
    [c => (entry(c).name = ['line separator']), /holds #, \\ or a control character/],
    [c => (entry(c).name = ['parent > child']), /holds " > "/],
    [c => (entry(c).name = [' leading']), /starts or ends with white space/],
    [c => (entry(c).name = ['é']), /is not in NFC form/],
    [c => (entry(c).name = ['x'.repeat(301)]), /is longer than 300 characters/],
    // verify-1: what TAP cannot show exactly, or a reviewer cannot see.
    [c => (entry(c).name = ['lone \uD800 surrogate']), /holds a lone UTF-16 surrogate/],
    [c => (entry(c).name = ['zero\u200Bwidth']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['bidi \u202E override']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['byte\uFEFForder mark']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['soft\u00ADhyphen']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['private \uE000 use']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['no-break\u00A0space']), /holds an invisible character or a space/],
    [c => (entry(c).name = ['ideographic\u3000space']), /holds an invisible character or a space/],
    [c => (entry(c).name = [7]), /is not a non-empty string/],
    [c => (entry(c).platforms = []), /platforms is empty/],
    [c => (entry(c).platforms = ['windows']), /platforms holds "windows"/],
    [c => (entry(c).platforms = ['linux', 'darwin']), /platforms is not sorted/],
    [c => (entry(c).platforms = ['linux', 'linux']), /platforms holds a value twice/],
    [c => (entry(c).runtimes = ['25']), /runtimes holds "25"/],
    [c => (entry(c).prerequisites = ['sudo']), /prerequisites holds "sudo"/],
    [c => (entry(c).evidence = ['linux-nightly']), /evidence holds "linux-nightly"/],
    [c => (entry(c).evidence = []), /evidence is empty/],
    // The evidence a run can give: its platform, its files, its runtimes.
    [c => (entry(c).evidence = ['darwin-full']), /evidence run darwin-full is on darwin/],
    [
      c => (c.runs['darwin-platform'].files = ['test/docs-keys.test.mjs']),
      /evidence run darwin-platform does not run test\/docs-audit\.test\.mjs/,
    ],
    [c => (c.runs['linux-full'].runtimes = ['26']), /linux-full is not run on Node 24/],
    [c => (c.runs['linux-full'].platform = 'windows'), /platform "windows" is not one of/],
    [c => (c.runs['linux-full'].files = []), /files is neither "all" nor a non-empty list/],
    [c => (c.runs['linux-full'].requiredFor = ['merge']), /requiredFor holds "merge"/],
    [c => (c.runs['Linux Full'] = c.runs['linux-full']), /not a valid run id/],
    // A name Object.prototype has would reach the prototype where a run is looked up.
    [c => (c.runs.constructor = c.runs['darwin-full']), /run "constructor": not a valid run id/],
    [c => (c.runs['linux-full'].images = {}), /only a container run has images and hostRuns/],
    // The container run: its images, pinned by digest, and its driver.
    [c => delete c.runs['t8-container'].images, /a container run needs images/],
    [c => delete c.runs['t8-container'].images['26'], /images names runtimes 24, not its runtimes/],
    [
      c => (c.runs['t8-container'].images['24'].image = 'node:24-bookworm-slim'),
      /images\.24\.image is not node:24… pinned by its sha256 digest/,
    ],
    [
      c => (c.runs['t8-container'].images['24'].image = `node:24@sha256:${'A'.repeat(64)}`),
      /images\.24\.image is not node:24…/,
    ],
    [c => (c.runs['t8-container'].images['24'].note = 'x'), /has the unknown field "note"/],
    [
      c => (c.runs['t8-container'].images['24'].driver = 't8.part-b'),
      /driver t8\.part-b is not a host test of the file the container runs/,
    ],
    [c => (c.runs['t8-container'].hostRuns = []), /a container run needs hostRuns/],
    // Each runtime's evidence comes from its own driver, which runs Docker.
    [
      c =>
        (c.runs['t8-container'].images['26'] = {
          image: `node:26-bookworm-slim@sha256:${'2'.repeat(64)}`,
          driver: 't8.driver.node24',
        }),
      /two runtimes name one driver; each needs a driver of its own/,
    ],
    [
      c => (c.entries.find(item => item.id === 't8.driver.node24').prerequisites = []),
      /driver t8\.driver\.node24 does not list the docker prerequisite/,
    ],
    [
      c => (c.runs['t8-container'].images['24'].driver = 't8.host-regression'),
      /driver t8\.host-regression does not list the docker prerequisite/,
    ],
    [c => (c.runs['t8-container'].hostRuns = ['t8-container']), /hostRuns holds "t8-container"/],
    [
      c => (c.entries.find(item => item.id === 't8.driver.node24').evidence = ['linux-full']),
      /its driver t8\.driver\.node24 is not required of its host run darwin-full/,
    ],
  ];
  for (const [change, expected] of cases) assert.match(problems(change), expected, `${expected}`);
  // The tracked manifest itself has none of them.
  assert.equal(
    problems(() => {}),
    ''
  );
});

test('platform manifest: the text is bounded UTF-8 JSON with no member named twice', () => {
  const text = read('test/platform-manifest.json');
  assert.deepEqual(parseManifest(text).problems, []);
  // JSON.parse keeps the last of two members: a reviewer would read the first.
  const twice = text.replace('"schemaVersion": 1,', '"schemaVersion": 1,\n  "schemaVersion": 1,');
  assert.notEqual(twice, text);
  assert.match(parseManifest(twice).problems.join('\n'), /names the member "schemaVersion" twice/);
  const nested = text.replace(
    '"platform": "linux",',
    '"platform": "linux",\n "platform": "linux",'
  );
  assert.match(parseManifest(nested).problems.join('\n'), /"platform" twice/);
  // Escapes name the same member.
  const escaped = text.replace(
    '"schemaVersion": 1,',
    '"schemaVersion": 1,\n  "schema\\u0056ersion": 1,'
  );
  assert.match(parseManifest(escaped).problems.join('\n'), /"schemaVersion" twice/);
  assert.deepEqual(duplicateMembers('{"a":{"a":1},"b":[{"a":1},{"a":2}]}'), []);
  assert.deepEqual(duplicateMembers('{"a":"\\"a\\"","a":2}'), ['a']);
  assert.match(parseManifest('{"schemaVersion": 1,').problems.join(), /not JSON/);
  assert.match(parseManifest(Buffer.from([0x7b, 0xff, 0x7d])).problems.join(), /not valid UTF-8/);
  assert.match(
    parseManifest(' '.repeat(limits.manifestBytes + 1)).problems.join(),
    /larger than 262144 bytes/
  );
  // A __proto__ member is an unknown field like any other, never a prototype.
  assert.match(
    parseManifest(
      text.replace('"schemaVersion": 1,', '"schemaVersion": 1, "__proto__": {},')
    ).problems.join(),
    /unknown field "__proto__"/
  );
});

test('platformTest and platformSubtest: an id, file, name or parent other than the manifest’s, or a skip, todo or only option, throws on every platform', () => {
  const { manifest } = platformManifest();
  const name =
    'keeping Orbit’s log on Linux: the entries a folder’s default access list hands down reach the new file masked by its mode 0600, and an access list on the old file does not reach it, as the docs say';
  assert.equal(
    bindEntry(manifest, 'test/docs-audit.test.mjs', 'docs-audit.log-acl.linux', name, []).id,
    'docs-audit.log-acl.linux'
  );
  assert.throws(
    () => bindEntry(manifest, 'test/docs-audit.test.mjs', 'docs-audit.unknown', name, []),
    /"docs-audit\.unknown" is not in test\/platform-manifest\.json/
  );
  assert.throws(
    () => bindEntry(manifest, 'test/keyring.test.mjs', 'docs-audit.log-acl.linux', name, []),
    /is registered from test\/keyring\.test\.mjs, not test\/docs-audit\.test\.mjs/
  );
  assert.throws(
    () =>
      bindEntry(manifest, 'test/docs-audit.test.mjs', 'docs-audit.log-acl.linux', `${name}.`, []),
    /is named/
  );
  assert.throws(
    () =>
      bindEntry(manifest, 'test/docs-audit.test.mjs', 'docs-audit.log-acl.linux', name, [
        'a parent',
      ]),
    /is registered under "a parent", not ""/
  );
  const sub = manifest.entries.find(entry => entry.id === 'docs-keys.old-key-file.eacces');
  assert.equal(
    bindEntry(manifest, sub.file, sub.id, sub.name[1], [sub.name[0]]).id,
    'docs-keys.old-key-file.eacces'
  );
  assert.throws(
    () => bindEntry(manifest, sub.file, sub.id, sub.name[1], []),
    /is registered under ""/
  );
  // From this file, which holds no entry: refused before anything is registered.
  assert.throws(
    () => platformTest(import.meta.url, 'docs-audit.log-acl.linux', name, {}, () => {}),
    /is registered from test\/platform-manifest\.test\.mjs, not test\/docs-audit\.test\.mjs/
  );
  assert.throws(
    () => platformTest(import.meta.url, 'no.such.entry', 'x', {}, () => {}),
    /"no\.such\.entry" is not in test\/platform-manifest\.json/
  );
  for (const option of ['skip', 'todo', 'only'])
    assert.throws(
      () =>
        platformTest(
          new URL('./docs-audit.test.mjs', import.meta.url),
          'docs-audit.log-acl.linux',
          name,
          { [option]: false },
          () => {}
        ),
      new RegExp(`takes no ${option} option`)
    );
});

test('platformSubtest: refused under a parent other than the entry’s', async t => {
  const sub = platformManifest().manifest.entries.find(
    entry => entry.id === 'docs-keys.old-key-file.eacces'
  );
  await assert.rejects(
    platformSubtest(
      t,
      new URL('./docs-keys.test.mjs', import.meta.url),
      sub.id,
      sub.name[1],
      {},
      () => {}
    ),
    /is registered under "platformSubtest: refused under a parent other than the entry’s"/
  );
});

test('platformDecision: absent on another platform, never a skip; a missing prerequisite fails; docker follows TEST_REQUIRE', () => {
  const entry = (platforms, prerequisites = []) => ({ id: 'x.y', platforms, prerequisites });
  const host = { uid: () => 1000, setfacl: () => true, docker: () => true };
  assert.deepEqual(platformDecision(entry(['linux']), { platform: 'darwin', probe: host }), {
    action: 'absent',
  });
  assert.deepEqual(platformDecision(entry(['darwin']), { platform: 'linux', probe: host }), {
    action: 'absent',
  });
  assert.deepEqual(platformDecision(entry(['container']), { platform: 'linux', probe: host }), {
    action: 'absent',
  });
  assert.deepEqual(
    platformDecision(entry(['darwin', 'linux']), { platform: 'container', probe: host }),
    {
      action: 'absent',
    }
  );
  assert.deepEqual(platformDecision(entry(['linux']), { platform: 'linux', probe: host }), {
    action: 'run',
  });
  assert.deepEqual(
    platformDecision(entry(['linux'], ['non-root']), {
      platform: 'linux',
      probe: { ...host, uid: () => 0 },
    }),
    { action: 'fail', reason: 'x.y needs non-root on linux, and it runs as root' }
  );
  assert.deepEqual(
    platformDecision(entry(['linux'], ['acl-tmpdir', 'setfacl']), {
      platform: 'linux',
      probe: { ...host, setfacl: () => false },
    }),
    {
      action: 'fail',
      reason: 'x.y needs setfacl on linux, and setfacl is not installed (the acl package)',
    }
  );
  // acl-tmpdir is the test's own check.
  assert.deepEqual(
    platformDecision(entry(['linux'], ['acl-tmpdir']), { platform: 'linux', probe: host }),
    {
      action: 'run',
    }
  );
  const docker = entry(['darwin', 'linux'], ['docker']);
  assert.equal(
    platformDecision(docker, { platform: 'darwin', requires: () => false, probe: host }).action,
    'skip'
  );
  assert.deepEqual(
    platformDecision(docker, {
      platform: 'darwin',
      requires: name => name === 'docker',
      probe: { ...host, docker: () => false },
    }),
    {
      action: 'fail',
      reason: 'x.y needs docker on darwin, and Docker is not available (TEST_REQUIRE=docker)',
    }
  );
  assert.equal(
    platformDecision(docker, {
      platform: 'linux',
      requires: name => name === 'docker',
      probe: host,
    }).action,
    'run'
  );
  // The platform: TEST_T8_DIR (set only by the T8 driver) makes it the container.
  assert.equal(runPlatform({}, 'linux'), 'linux');
  assert.equal(runPlatform({}, 'darwin'), 'darwin');
  assert.equal(runPlatform({ TEST_T8_DIR: '' }, 'darwin'), 'darwin');
  assert.equal(runPlatform({ TEST_T8_DIR: '/t8' }, 'darwin'), 'container');
});

// Codex 2026-10-11 item 5: malicious and accidental inherited values are refused, not used.
test('record settings: neither set is a developer run; a partial, relative, linked, oversized or malformed setting throws', t => {
  const directory = temporary(t);
  const run = 'a'.repeat(64);
  assert.equal(recordSettings({}), null);
  assert.deepEqual(recordSettings({ TEST_PLATFORM_RECORDS: directory, TEST_PLATFORM_RUN: run }), {
    directory,
    run,
  });
  const link = path.join(directory, 'link');
  fs.symlinkSync(directory, link);
  const file = path.join(directory, 'file');
  fs.writeFileSync(file, '');
  for (const [env, why] of [
    [{ TEST_PLATFORM_RECORDS: directory }, /TEST_PLATFORM_RUN must be 64 lowercase hex digits/],
    [{ TEST_PLATFORM_RUN: run }, /TEST_PLATFORM_RECORDS must be an absolute path/],
    [{ TEST_PLATFORM_RECORDS: '', TEST_PLATFORM_RUN: run }, /must be an absolute path/],
    [{ TEST_PLATFORM_RECORDS: 'records', TEST_PLATFORM_RUN: run }, /must be an absolute path/],
    [
      { TEST_PLATFORM_RECORDS: `${directory}\n/x`, TEST_PLATFORM_RUN: run },
      /must be an absolute path/,
    ],
    [
      { TEST_PLATFORM_RECORDS: `/${'a'.repeat(1024)}`, TEST_PLATFORM_RUN: run },
      /must be an absolute path/,
    ],
    [{ TEST_PLATFORM_RECORDS: directory, TEST_PLATFORM_RUN: 'A'.repeat(64) }, /64 lowercase hex/],
    [{ TEST_PLATFORM_RECORDS: directory, TEST_PLATFORM_RUN: `${run}\n` }, /64 lowercase hex/],
    [{ TEST_PLATFORM_RECORDS: directory, TEST_PLATFORM_RUN: 'a'.repeat(63) }, /64 lowercase hex/],
    [
      { TEST_PLATFORM_RECORDS: link, TEST_PLATFORM_RUN: run },
      /not a directory \(a link to one is refused\)/,
    ],
    [{ TEST_PLATFORM_RECORDS: file, TEST_PLATFORM_RUN: run }, /not a directory/],
    [
      { TEST_PLATFORM_RECORDS: path.join(directory, 'gone'), TEST_PLATFORM_RUN: run },
      /cannot be read: ENOENT/,
    ],
  ])
    assert.throws(() => recordSettings(env), why, JSON.stringify(env));
});

// verify-1: the exported writer took any record, so a plain test of an entry's name plus a
// forged result record covered the entry without platformTest. A result record now comes only
// from the wrapper platformTest gives a bound test.
test('writePlatformRecord writes the T8 driver’s container records only, never a test’s result', () => {
  for (const kind of ['result', 'other', undefined])
    assert.throws(
      () =>
        writePlatformRecord({
          kind,
          id: 'docs-audit.log-acl.linux',
          file: 'test/docs-audit.test.mjs',
          name: ['x'],
          platform: runPlatform(),
          node: process.version,
          result: 'completed',
        }),
      /writePlatformRecord writes container records only: a platform test records its own result/,
      String(kind)
    );
  assert.throws(() => writePlatformRecord(null), /container records only/);
});

// A real run of one platform test of this platform in a nested runner: with the settings it writes
// one record, which readRecords accepts; without them it writes nothing; with a broken setting the
// file fails before any test runs.
test(
  'a run with TEST_PLATFORM_RECORDS records each platform test it ran, with its id, file, name, platform, Node and result',
  { timeout: 120000 },
  t => {
    const { manifest, sha256 } = platformManifest();
    const here = runPlatform();
    const entry = {
      darwin: 'docs-audit.log-acl.darwin-file',
      linux: 'healthcheck.run-status-swap',
    }[here];
    assert.ok(entry, `Orbit's tests run on Linux and macOS, not on ${here}`);
    const { file, name } = manifest.entries.find(item => item.id === entry);
    const escaped = name[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const environment = Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => !key.startsWith('TEST_') && key !== 'NODE_TEST_CONTEXT'
      )
    );
    const nested = extra =>
      spawnSync(
        process.execPath,
        [
          '--test',
          '--test-reporter=tap',
          '--import',
          './test/setup.mjs',
          `--test-name-pattern=^${escaped}$`,
          file,
        ],
        { cwd: repository, encoding: 'utf8', timeout: 100000, env: { ...environment, ...extra } }
      );
    const records = temporary(t);
    const run = randomBytes(32).toString('hex');
    const recorded = nested({ TEST_PLATFORM_RECORDS: records, TEST_PLATFORM_RUN: run });
    assert.equal(recorded.status, 0, recorded.stdout + recorded.stderr);
    assert.match(recorded.stdout, new RegExp(`^ok 1 - ${escaped}$`, 'm'));
    const { records: found, problems } = readRecords(records);
    assert.deepEqual(problems, []);
    assert.equal(found.length, 1);
    const { source, ...record } = found[0];
    assert.match(source, /^\d+-[0-9a-f-]{36}\.jsonl:1$/);
    assert.deepEqual(record, {
      kind: 'result',
      id: entry,
      file,
      name,
      platform: here,
      node: process.version,
      result: 'completed',
      run,
      manifest: sha256,
    });
    const mode = fs.statSync(path.join(records, source.split(':')[0])).mode & 0o777;
    assert.equal(mode, 0o644);
    // A developer's run (neither variable) passes and writes nowhere.
    assert.equal(nested({}).status, 0);
    assert.equal(readRecords(records).records.length, 1);
    // A partial setting fails the file, before any test runs.
    const partial = nested({ TEST_PLATFORM_RECORDS: records });
    assert.notEqual(partial.status, 0);
    assert.match(
      partial.stdout + partial.stderr,
      /TEST_PLATFORM_RUN must be 64 lowercase hex digits/
    );
    assert.doesNotMatch(partial.stdout, new RegExp(`^ok \\d+ - ${escaped}$`, 'm'));
  }
);

// A TEST_T8_DIR exported on a host must not quietly remove the platform tests of every other file.
test(
  'a file without T8 container tests, run with TEST_T8_DIR set, fails instead of dropping its platform tests',
  { timeout: 120000 },
  t => {
    const environment = Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => !key.startsWith('TEST_') && key !== 'NODE_TEST_CONTEXT'
      )
    );
    const directory = temporary(t);
    const run = spawnSync(
      process.execPath,
      [
        '--test',
        '--test-reporter=tap',
        '--import',
        './test/setup.mjs',
        '--test-name-pattern=^(platform: |readRunStatusFile reads the run/ it opened)',
        'test/healthcheck.test.mjs',
      ],
      {
        cwd: repository,
        encoding: 'utf8',
        timeout: 100000,
        env: { ...environment, TEST_T8_DIR: directory, TEST_T8_RUN: 'a'.repeat(64) },
      }
    );
    assert.equal(run.status, 1, run.stdout + run.stderr);
    assert.match(
      run.stdout,
      /^not ok 1 - platform: test\/healthcheck\.test\.mjs has no test for the T8 driver's container$/m
    );
    assert.match(run.stdout, /unset TEST_T8_DIR/);
    assert.doesNotMatch(run.stdout, /^(?:not )?ok \d+ - readRunStatusFile reads the run/m);
  }
);
