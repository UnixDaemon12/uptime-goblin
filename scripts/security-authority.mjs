// The one source of dispatch authority for the gate (scripts/security-dispatch.mjs names the
// purposes and why each is needed). An authority here would let the gate start an operation whose
// prerequisites are external to it: a qualified host listener for the registry stages, an approved
// Semgrep image, a reviewed Docker stage policy and endpoint for docker version and for the T8
// image inspect with the operational hold lifted, pre-build authority for the scan's image build
// and for the builds the candidate's tests start.
//
// None of those exists in this draft, and no producer of any of them is reviewed or qualified
// (GATE-CONTRACT v5 C5, C6, C17 item 12; the maintainer's answers of 20261016T014104832374Z). So this module
// grants nothing: every purpose gets null, the gate withholds each stage that needs one, and the run
// is never a pass. It reads no file, environment variable or record: a local file nothing
// authenticates must not become authority. Once a reviewed producer exists, its verified record is
// what this module would read, in the change that adds it, with its own review.
//
// Tests replace this file in their throwaway fixture repositories with a synthetic one, to show
// that the same gate dispatches exactly once when an authority is given (test/helpers/
// dispatch-authority.mjs); such an authority names itself synthetic, and is never a real one.
//
// This seam is not an authority boundary yet (verify-1 of gate-draft-r5). The gate imports the
// candidate's own copy of this module, as it runs the candidate's own copy of every gate file:
// gate-implementation checks only that the worktree's copy is the staged one, and the trusted
// bootstrap that would check the gate identity and its import closure before any stage is pending.
// So a candidate that changes this file can grant itself every authority, as it can change the
// gate itself. Nor is an authority tied to the stages that record its preconditions: a
// semgrep-image or scan-image-build authority is not checked against the recorded image-approval
// stage (which this draft always records pending), and the finalizer does not read the authority
// a dispatched stage records. The reviewed producer that would give a real authority has to tie
// both, under the trusted bootstrap.

/** The authority for a purpose (its one argument), or null: in this draft always null. */
export function dispatchAuthority() {
  return null;
}
