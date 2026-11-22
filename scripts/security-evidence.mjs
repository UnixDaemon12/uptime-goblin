// Small, independently testable invariants used by the local security gate.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export function sourceManifest(root, treeListing) {
  return treeListing
    .split('\0')
    .filter(Boolean)
    .map(entry => {
      const match = /^(100644|100755) blob ([0-9a-f]+)\t(.+)$/s.exec(entry);
      if (!match) throw new Error('Candidate contains an unsupported symlink or submodule');
      const [, mode, blob, file] = match;
      const target = path.resolve(root, file);
      if (!target.startsWith(`${path.resolve(root)}${path.sep}`))
        throw new Error('Candidate path escapes the snapshot');
      if (fs.realpathSync(target) !== path.resolve(fs.realpathSync(root), file))
        throw new Error(`Candidate path traverses a symlink: ${file}`);
      const stat = fs.lstatSync(target);
      if (!stat.isFile()) throw new Error(`Candidate is not a regular file: ${file}`);
      const bytes = fs.readFileSync(target);
      const objectId = createHash(blob.length === 40 ? 'sha1' : 'sha256')
        .update(`blob ${bytes.length}\0`)
        .update(bytes)
        .digest('hex');
      if (objectId !== blob || ((stat.mode & 0o100) !== 0) !== (mode === '100755'))
        throw new Error(`Snapshot content or executable mode differs from the index: ${file}`);
      return { file, mode, blob, sha256: sha256(bytes) };
    });
}

export function testTotals(tap) {
  const totals = {};
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...tap.matchAll(new RegExp(`^# ${name} (\\d+)\\s*$`, 'gm'))];
    if (matches.length !== 1) throw new Error(`Missing or ambiguous test total: ${name}`);
    totals[name] = Number(matches[0][1]);
    if (!Number.isSafeInteger(totals[name])) throw new Error(`Invalid test total: ${name}`);
  }
  if (
    !totals.tests ||
    totals.pass !== totals.tests ||
    totals.fail ||
    totals.cancelled ||
    totals.skipped ||
    totals.todo
  )
    throw new Error(`Incomplete test coverage: ${JSON.stringify(totals)}`);
  return totals;
}

// A review is bound to the candidate's tree and its complete ordered parent vector (`parents`:
// HEAD, then each MERGE_HEAD in order; GATE-CONTRACT v3 C18). A review that names a single
// `parent` is the earlier form, which gives no authority (COORDINATOR-DECISIONS "C18 legacy
// approvals"), even for a commit with one parent.
export function checkReview(review, { tree, parents, files, release = false }) {
  if (Object.hasOwn(review, 'parent'))
    throw new Error(
      'Independent review names a single parent, which gives no authority: bind the complete ordered parent vector (parents)'
    );
  if (
    review.tree !== tree ||
    !Array.isArray(parents) ||
    !parents.length ||
    !Array.isArray(review.parents) ||
    review.parents.length !== parents.length ||
    !review.parents.every((item, index) => item === parents[index])
  )
    throw new Error('Independent review does not match this tree and complete parent vector');
  if (
    typeof review.reviewer !== 'string' ||
    !review.reviewer.trim() ||
    typeof review.reference !== 'string' ||
    !review.reference.trim()
  )
    throw new Error('Independent review needs a reviewer and an evidence reference');
  if (!Array.isArray(review.unresolved) || review.unresolved.length)
    throw new Error('Independent review has missing or unresolved findings');
  const documents = files
    .filter(({ file }) => /\.(?:md|txt)$/i.test(file) && !file.startsWith('test/'))
    .map(({ file }) => file);
  for (const file of documents) {
    const item = review.documents?.[file];
    if (
      !item ||
      !['updated', 'checked unchanged'].includes(item.status) ||
      typeof item.reason !== 'string' ||
      !item.reason.trim()
    )
      throw new Error(`Missing documentation disposition: ${file}`);
  }
  if (release) {
    // These are review references, never substitutes for automated scans or signatures.
    for (const name of [
      'threatModel',
      'authentication',
      'ssrf',
      'storageRecovery',
      'browserAccessibility',
      'installUpgradeRollback',
      'historyPublication',
      'artifactSignatures',
      'buildProvenance',
      'platformMatrix',
      'netxeoAudit',
      'performance',
      'clairImageScan',
      'snykScan',
    ]) {
      if (typeof review.release?.[name] !== 'string' || !review.release[name].trim())
        throw new Error(`Missing final release evidence: ${name}`);
    }
  }
}
