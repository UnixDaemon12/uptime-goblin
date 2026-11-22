// The shared identity contract (test/helpers/identity-contract.mjs) against the real service:
// a real control.sqlite, GOBLIN_PASSWORD as the source, a deterministic KDF for speed, and the
// contract's recorder, which sees the audit spec §5.1 rows the units record.
//
// The contract checks the rows of requests, from an identity that recorded nothing before them;
// a data directory's first start records `account.bootstrap` (§5.1, tested in audit.test.mjs),
// so the directory is started once first and the contract's recorder sees a later start.
import test from 'node:test';
import { identityContract } from '../helpers/identity-contract.mjs';
import { temporary, startIdentity } from './helpers.mjs';

identityContract(test, async ({ clock, password, insecureHttpSessions, audit }, t) => {
  const directory = temporary(t);
  const options = { clock, password: password ?? '', insecureHttpSessions };
  (await startIdentity(t, directory, options)).stop();
  const { identity } = await startIdentity(t, directory, { ...options, audit });
  return identity;
});
