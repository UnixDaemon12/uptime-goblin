// The display code's check symbol (B6 design §7.1): Uptime Goblin's and the page's copies give the
// design's pinned answers, and catch every single typo and every swap of two different symbols.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { checkSymbol, displayAlphabet } from '../../lib/identity/display-code.mjs';
import { displayCodeHash, newDisplayCode } from '../../lib/identity/secrets.mjs';

const vectors = [
  ['0123456789ABCDEFGHJKMNPQR', 'H'],
  ['ZYXWVTSRQPNMKJHGFEDCBA987', 'Q'],
];

/** The page's copy of the arithmetic, from public/modules/identity/signin.js, run on its own. */
function pageCopy() {
  const text = fs.readFileSync(
    new URL('../../public/modules/identity/signin.js', import.meta.url),
    'utf8'
  );
  const start = text.indexOf('function times(');
  const end = text.indexOf('/** The 26 symbols of `input`');
  assert.ok(start > 0 && end > start, 'signin.js keeps its copy of the check symbol');
  const source = text.slice(start, end).replace(/^export /gm, '');
  return new Function('displayAlphabet', `${source}; return checkSymbol;`)(displayAlphabet);
}

test('both copies give the pinned check symbols', () => {
  const page = pageCopy();
  for (const [data, check] of vectors) {
    assert.equal(checkSymbol(data), check, data);
    assert.equal(page(data), check, data);
  }
  for (let i = 0; i < 200; i++) {
    const data = newDisplayCode().code.replaceAll('-', '').slice(0, 25);
    assert.equal(page(data), checkSymbol(data));
  }
});

test('every single wrong symbol and every swap of two different symbols is caught', () => {
  for (let round = 0; round < 50; round++) {
    const symbols = newDisplayCode().code.replaceAll('-', '');
    assert.ok(displayCodeHash(symbols));
    for (let i = 0; i < 26; i++) {
      for (const other of displayAlphabet) {
        if (other === symbols[i]) continue;
        const typo = symbols.slice(0, i) + other + symbols.slice(i + 1);
        assert.equal(displayCodeHash(typo), null, `${typo} (position ${i})`);
      }
      for (let j = i + 1; j < 26; j++) {
        if (symbols[i] === symbols[j]) continue;
        const swapped = [...symbols];
        [swapped[i], swapped[j]] = [swapped[j], swapped[i]];
        assert.equal(displayCodeHash(swapped.join('')), null, `swap ${i} and ${j}`);
      }
    }
  }
});
