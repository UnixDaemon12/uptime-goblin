// The display code's check symbol (B6 design §7.1). Plain arithmetic, so a wall display's page
// runs the same check in any context, plain HTTP included, without crypto.subtle. The browser
// copy in public/modules/identity/signin.js must give the same answers: test/identity/display-code
// pins both to the design's vectors.

export const displayAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Multiplication in GF(2^5) with x^5 + x^2 + 1. */
function times(a, b) {
  let product = 0;
  for (; b; b >>= 1) {
    if (b & 1) product ^= a;
    a <<= 1;
    if (a & 32) a ^= 0b100101;
  }
  return product;
}

/**
 * The check symbol of 25 data symbols: Σ α^(i+1)·d_i with α = x. Every weight differs and none is
 * zero, so any one wrong symbol, and any swap of two different symbols, changes it.
 */
export function checkSymbol(data) {
  let sum = 0,
    weight = 1;
  for (const symbol of data) {
    weight = times(weight, 2);
    sum ^= times(weight, displayAlphabet.indexOf(symbol));
  }
  return displayAlphabet[sum];
}
