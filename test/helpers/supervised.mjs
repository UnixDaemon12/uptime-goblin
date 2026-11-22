// The environment of a test that starts `node server.mjs` under a service manager's
// GOBLIN_SUPERVISED=1. Such a start refuses (exit status 78) unless the cgroup it runs in holds
// Uptime Goblin's memory, CPU and process limits (lib/resource-limits.mjs), which a developer's Mac (not
// Linux) and most CI runners do not, while a limited container may hold all three. So these tests
// name in GOBLIN_ALLOW_UNLIMITED exactly the limits that are not in force for the process running
// them, whose cgroup the server they spawn shares (empty, which is none, where all three are):
// the start then goes on as it would where they are, and its log names only what this machine
// lacks. The refusal itself is tested in test/startup.test.mjs and test/resource-limits.test.mjs.
// This reads the cgroup of the machine running the tests, as the server they spawn does.
import { LIMIT_NAMES, readLimits } from '../../lib/resource-limits.mjs';

export function supervisedEnv() {
  const { limits } = readLimits();
  return {
    GOBLIN_SUPERVISED: '1',
    GOBLIN_ALLOW_UNLIMITED: LIMIT_NAMES.filter(name => limits[name].state !== 'enforced').join(','),
  };
}
