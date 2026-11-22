// public/shared/csv.js, the formula guard the history export (in the browser) and the audit
// export (lib/audit/export.mjs) share, tested without a browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { csvCell } from '../public/shared/csv.js';
import { csvCell as auditCell } from '../lib/audit/export.mjs';

test('CSV cells neutralise formulas in upstream labels, keys, units and error text', () => {
  for (const [value, cell] of [
    ['=HYPERLINK("http://x","y")', `"'=HYPERLINK(""http://x"",""y"")"`],
    ['+cmd', `"'+cmd"`],
    ['-1+2', `"'-1+2"`],
    ['@SUM(A1)', `"'@SUM(A1)"`],
    ['\t=1', `"'\t=1"`],
    ['\r=1', `"'\r=1"`],
    // Only a leading character starts a formula; everything is quoted, quotes doubled.
    ['CPU · a=b', '"CPU · a=b"'],
    ['say "hi"', '"say ""hi"""'],
    [null, '""'],
    [undefined, '""'],
    [false, '"false"'],
    [-1, `"'-1"`],
    // Direction embeddings, overrides and isolates are dropped (a spreadsheet would show the rest
    // reordered), and before the guard, so one cannot hide a formula's first character from it.
    ['Plex\u202egnp.exe', '"Plexgnp.exe"'],
    ['\u2066\u202e=SUM(A1)\u2069', `"'=SUM(A1)"`],
    // The marks (the Arabic letter mark, the right-to-left and left-to-right marks) stay, as
    // lib/config.mjs keeps them in a name: a right-to-left name saved with one is exported as
    // saved. The guard looks past them, so they cannot hide a formula either.
    ['x\u061cy\u200fz\u200e', '"x\u061cy\u200fz\u200e"'],
    ['\u05e9\u05e8\u05ea 2\u200f', '"\u05e9\u05e8\u05ea 2\u200f"'],
    ['\u061c=SUM(A1)', `"'\u061c=SUM(A1)"`],
    ['\u200e\u200f\u061c+cmd', `"'\u200e\u200f\u061c+cmd"`],
    ['\u200f\u202e-1+2', `"'\u200f-1+2"`],
  ])
    assert.equal(csvCell(value), cell, JSON.stringify(value));
  // One rule for both exports.
  assert.equal(auditCell, csvCell);
  // The history export uses it for every cell but a numeric reading.
  const exports = fs.readFileSync(
    new URL('../public/modules/configure/exports.js', import.meta.url),
    'utf8'
  );
  assert.match(exports, /import \{ csvCell \} from '\.\.\/\.\.\/shared\/csv\.js';/);
  assert.match(exports, /typeof value === 'number' \? String\(value\) : csvCell\(value\)/);
});
