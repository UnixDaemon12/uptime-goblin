// The build ID against real 1.4.3. This lives with the upgrade tests because it needs the
// v1.4.3 tag, which it takes as the other upgrade suites do (test/upgrade/fixtures.mjs): from
// TEST_TAG_TREES when that is set (the git-less Node 24 container, with exports made by
// export-tag.mjs), otherwise from git. Without either it skips, naming why, unless TEST_REQUIRE
// lists fixtures: the CI upgrade job fetches every tag and sets it, so a missing tag fails
// there (in test:fast, a shallow checkout has no tags).
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { computeBuild } from '../../lib/healthcheck.mjs';
import { readRelease } from '../../lib/http/static.mjs';
import { buildAsIn143 } from '../helpers/build-reference.mjs';
import { installTag, skipWithoutTag } from './fixtures.mjs';
import { temporary } from './harness.mjs';

function buildOf(root) {
  const build = computeBuild(root);
  assert.equal(readRelease(root).build, build, 'readRelease() agrees with computeBuild()');
  return build;
}

test('1.4.3 keeps the build its own lib/healthcheck.mjs --print-build prints', t => {
  if (skipWithoutTag(t, 'v1.4.3')) return;
  const root = installTag('v1.4.3', path.join(temporary(t, 'orbit-build-v143-'), 'app'));
  const own = spawnSync(
    process.execPath,
    [path.join(root, 'lib/healthcheck.mjs'), '--print-build', root],
    { encoding: 'utf8' }
  );
  assert.equal(own.status, 0, own.stderr);
  assert.match(own.stdout.trim(), /^[0-9a-f]{12}$/);
  assert.equal(buildOf(root), own.stdout.trim());
  assert.equal(buildAsIn143(root), own.stdout.trim(), 'the frozen reference is 1.4.3’s own');
});
