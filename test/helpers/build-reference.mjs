// The build ID exactly as Orbit 1.4.3 computed it, frozen as the reference that 1.5's computeBuild()
// and readRelease() must match on every tree shaped like 1.4.x (see test/healthcheck.test.mjs and
// test/upgrade/build.test.mjs).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

// C1 exactly as Orbit 1.4.3 shipped it (git show v1.4.3:lib/healthcheck.mjs), frozen here as
// the reference: only lib/*.mjs, no subdirectories. On rollback the installer computes the
// previous release's build with the new release's computeBuild() and compares it with what
// that release's own server reports, so the two must agree on every tree shaped like 1.4.x.
export function buildAsIn143(root) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  const files = ['server.mjs'];
  for (const entry of fs.readdirSync(path.join(root, 'lib'), { withFileTypes: true }))
    if (entry.isFile() && entry.name.endsWith('.mjs') && !entry.name.startsWith('.'))
      files.push(`lib/${entry.name}`);
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const item = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(item);
      else if (entry.isFile()) files.push(item);
    }
  };
  walk('public');
  const hash = createHash('sha256').update(`${version}\n`);
  for (const file of files.sort()) {
    const digest = createHash('sha256')
      .update(fs.readFileSync(path.join(root, file)))
      .digest('hex');
    hash.update(`${file}\n${digest}\n`);
  }
  return hash.digest('hex').slice(0, 12);
}
