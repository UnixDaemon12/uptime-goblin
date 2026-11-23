// Credential-like parameters in an address, shared by the server (lib/config.mjs, which
// re-exports secretName and withoutCredentials for the audit's diffs and for its own checks) and
// the browser (public/shared/uptime-kuma.js cleans a monitor's address before it is sent). No
// imports, no DOM, no eval.

// A parameter name marks a credential when one of its words (private_token, apiToken,
// X-Api-Key, passkey, sessionkey, adminpass) is or contains a credential word; a few common
// harmless names (?authuser=1, ?author=, ?keyword=, ?hotkey=) stay allowed.
const harmlessWords = new Set([
  ...['author', 'authors', 'authuser', 'authority', 'pubkey', 'publickey', 'hotkey', 'hotkeys'],
  ...['monkey', 'donkey', 'turkey', 'whiskey', 'hockey', 'jockey', 'bypass', 'compass'],
]);
const secretWord = word =>
  !harmlessWords.has(word) &&
  (/token|secret|passw|passhash|passcode|passphrase|session|sessid|signature|credential|bearer|jwt/.test(
    word
  ) ||
    /^auth|(?:key|keys|pass)$/.test(word) ||
    /^(?:sid|sig)$/.test(word));
/** Whether a parameter or field name looks like it holds a credential (also the audit's diffs). */
export const secretName = name =>
  name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some(word => secretWord(word.replace(/\d+$/, '')));
// Key=value pairs in a fragment, as in an OAuth return (#access_token=...&state=/home?tab=1).
// Independent review A2: each '&'-separated member of the fragment, and of each text directive after
// ':~:', is judged on its own, as the query's parameters are: a member is a pair when it holds
// '=' (also spelled %3D), and a credential when secretName matches its decoded name, whatever
// route characters that name holds (#a=1&api/key=..., ##access_token=...) and whatever its
// neighbours (#access_token=...&, #access_token=...&state, #/home&access_token=..., #!&...).
// Anchors and other valueless members (#api-key, #state) are never credentials. Only a route's
// own parameters are left alone, as in 1.4.1: when the first member's name holds '?' after a
// route (#!/server/...?key=..., #dashboard?view=1, #/callback?x=1&...), that member and the
// fragment's later ones are the application's. `stripped` is the fragment without the
// credential pairs (a text directive they emptied is dropped).
function fragmentPairs(hash) {
  const parts = hash
      .slice(1)
      .split(':~:')
      .map(part => part.split('&')),
    routeQuery = parts[0][0].split('=')[0].indexOf('?') > 0;
  const name = member => [...new URLSearchParams(member).keys()][0] ?? '';
  const secret = (member, part) =>
    !(part === 0 && routeQuery) &&
    (member.includes('=') || name(member).includes('=')) &&
    secretName(name(member));
  return {
    secret: parts.some((members, part) => members.some(member => secret(member, part))),
    stripped: parts
      .map((members, part) => members.filter(member => !secret(member, part)).join('&'))
      .filter((text, part) => part === 0 || text)
      .join(':~:'),
  };
}
export function credentialParams(u) {
  return [...u.searchParams.keys()].some(secretName) || fragmentPairs(u.hash).secret;
}
/**
 * The destination without its credential-like parameters (used to repair older settings, and by
 * the audit's diffs, which must never hold one).
 */
export function withoutCredentials(value) {
  const u = new URL(value);
  for (const name of [...u.searchParams.keys()]) if (secretName(name)) u.searchParams.delete(name);
  const fragment = fragmentPairs(u.hash);
  if (fragment.secret) u.hash = fragment.stripped;
  return u.href;
}
