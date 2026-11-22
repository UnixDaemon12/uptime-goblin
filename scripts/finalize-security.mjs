import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  currentCandidate,
  inspectRun,
  finalizeRun,
  lintStageNames,
  platformInputs,
} from './security-finalization.mjs';
import { hardenGitHistory } from './security-platform.mjs';

function isMain() {
  if (!process.argv[1]) return false;
  const entry = path.resolve(process.argv[1]);
  const module = fileURLToPath(import.meta.url);
  if (entry === module) return true;
  try {
    return fs.realpathSync(entry) === fs.realpathSync(module);
  } catch {
    // stdin and eval imports can have a non-file argument in argv[1].
    return false;
  }
}

if (isMain()) {
  try {
    const [command, run, ...rest] = process.argv.slice(2);
    const review = command === 'finalize' ? rest.shift() : undefined;
    if (!run || !['inspect', 'finalize'].includes(command) || (command === 'finalize' && !review))
      throw new Error(
        'Usage: node scripts/finalize-security.mjs inspect <run> [<companion run>...] | finalize <run> <review.json> [<companion run>...]'
      );
    // 1.5: a 1.5 commit run records both lint stages (run once the pre-dispatch barrier is open,
    // otherwise withheld and pending), so a 1.5 run must carry both. The
    // shared module requires none of a caller that names none (the maintenance finalizer). The
    // same holds for the platform coverage contract: this finalizer names its inputs (the
    // candidate's manifest, its parents and the history behind them) and the companion runs given
    // after the run (and review), each a sealed platform-mode run beside it; the module requires
    // the runs the candidate's manifest names, and none of a candidate without a manifest.
    // Git reads each commit as it is here too: no grafts, replace refs or commit-graph
    // (scripts/security-platform.mjs; platformInputs also refuses a shallow repository).
    hardenGitHistory(process.env);
    const candidate = currentCandidate();
    const current = {
      ...candidate,
      lintStages: lintStageNames,
      platform: platformInputs(process.cwd(), candidate.tree, {
        heads: candidate.parents,
        complete: candidate.parentsComplete,
        reason: candidate.parentsReason,
      }),
      companions: rest.map(item => path.resolve(item)),
    };
    const result =
      command === 'inspect' ? inspectRun(run, current) : finalizeRun(run, review, current);
    console.log(JSON.stringify(result, null, 2));
    // A finalization that is pending (every one this draft writes for a candidate with a platform
    // contract: its F obligations are F's, on the Mac) approves nothing; say so and fail.
    if (command === 'finalize' && result.status !== 'pass') {
      console.error(
        `Security finalization is ${result.status}, not pass: the commit guard will not accept it. ${(result.pending ?? []).slice(0, 5).join('; ')}`
      );
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(`Security finalization blocked: ${error.message}`);
    process.exitCode = 1;
  }
}
