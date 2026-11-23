// The audit service that records nothing (audit spec §2.1 item 13, Phase 0; frozen): the §4.1
// interface with writes that do nothing and reads that answer "unavailable". server.mjs gives
// it to identity until lane H wires the real one (createAudit, lib/audit/index.mjs), and tests
// of other components use it where the audit is not what they check. Its method names, in the
// §4.1 order, are the interface's: test/audit/noop.test.mjs pins them and lane O's writer test
// asserts that createAudit() has the same.
import { auditError } from './errors.mjs';

const nothing = async () => {};
const unreadable = async () => {
  throw auditError('audit_read_unavailable');
};

/** A §4.1 audit service whose writes do nothing and whose reads are unavailable. */
export function noopAudit() {
  const change = Object.freeze({ seq: 0, note() {}, end: nothing });
  const operation = Object.freeze({ note() {}, end: nothing });
  return Object.freeze({
    attach: nothing,
    record() {},
    unrecorded() {},
    append: async () => ({ seq: 0 }),
    system: nothing,
    count() {},
    begin: async () => change,
    single: nothing,
    operation: () => operation,
    configSnapshot: value => ({ revision: value?.revision ?? null, public: {}, secrets: {} }),
    start: nothing,
    started: nothing,
    maintain: nothing,
    list: unreadable,
    export: unreadable,
    verify: unreadable,
    fromDelivery() {},
    state: () => ({ ready: false, unwritten: null, retention: null }),
    idle: nothing,
    close: nothing,
  });
}
