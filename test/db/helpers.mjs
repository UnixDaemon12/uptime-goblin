// Shared helpers for the lane P database tests (test/db/**).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

/** A temporary directory removed after the test. */
export function temporary(t, prefix = 'orbit-db-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** {relative path: sha256} of every file under `directory`, skipping `skip` (names or prefixes). */
export function fingerprint(directory, skip = []) {
  const out = {};
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
      const item = relative ? `${relative}/${entry.name}` : entry.name;
      if (skip.some(prefix => item === prefix || item.startsWith(`${prefix}/`))) continue;
      if (entry.isDirectory()) walk(item);
      else
        out[item] = createHash('sha256')
          .update(fs.readFileSync(path.join(directory, item)))
          .digest('hex');
    }
  };
  walk('');
  return out;
}

export const mode = file => fs.statSync(file).mode & 0o777;

/** A manual clock: now() returns `value`; advance(ms) moves it. */
export function manualClock(start = Date.UTC(2026, 8, 1)) {
  let value = start;
  const clock = () => value;
  clock.advance = ms => (value += ms);
  clock.set = ms => (value = ms);
  return clock;
}
