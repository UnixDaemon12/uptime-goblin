// Synthetic dispatch authority for the gate's throwaway fixture repositories. The gate takes its
// dispatch authority from scripts/security-authority.mjs alone, which gives none in this draft, so
// the gate withholds every stage that needs one (scripts/security-dispatch.mjs). A test that needs
// such a stage to run (to check what it does once it runs, or to show that the same gate then
// dispatches it exactly once) writes this module's text over that file in its fixture repository,
// which is the candidate the fixture's gate runs. The authority it gives names itself synthetic: it
// stands for no reviewed record, qualified listener, approved image or stage policy, and nothing
// outside a fixture reads it.
import { DISPATCH_AUTHORITIES } from '../../scripts/security-dispatch.mjs';

/** Every purpose the gate asks authority for. */
export const allPurposes = Object.freeze(Object.keys(DISPATCH_AUTHORITIES));

/**
 * The text of a scripts/security-authority.mjs that grants a synthetic authority for each of
 * `purposes` ('all' for every one) and nothing else. With `malformed`, what it gives for those
 * purposes has an extra member, which the gate must refuse as no authority.
 */
export function syntheticAuthority(purposes, { malformed = false } = {}) {
  const granted = purposes === 'all' ? allPurposes : purposes;
  for (const purpose of granted)
    if (!allPurposes.includes(purpose)) throw new Error(`no such purpose: ${purpose}`);
  return `// Synthetic dispatch authority, written by a test into a throwaway fixture repository: it is
// never a real authority (test/helpers/dispatch-authority.mjs).
const granted = new Set(${JSON.stringify(granted)});
export function dispatchAuthority(purpose) {
  if (!granted.has(purpose)) return null;
  return {
    purpose,
    source: 'synthetic test authority',
    reference: 'test fixture only; no reviewed record stands behind it',${malformed ? "\n    qualified: 'synthetic'," : ''}
  };
}
`;
}
