import { installDockerGuard } from './helpers/docker-guard.mjs';

// Loaded before every test file (see the npm test script). createApp reads GOBLIN_* and
// HOST/PORT from the environment by default, so a developer's exported deployment settings
// (for example from /etc/uptime-goblin.env) must not change what the tests exercise.
for (const name of Object.keys(process.env))
  if (name.startsWith('GOBLIN_') || name.startsWith('ORBIT_') || name === 'HOST' || name === 'PORT')
    delete process.env[name];
// The Basic suites run on new data directories, where G2 turns Basic off. Tests of that default
// delete this or pass their own environment.
process.env.GOBLIN_LEGACY_BASIC = '1';

// No test listens on 4317, Uptime Goblin's default port: an Uptime Goblin run with its defaults, or another
// test's, may hold it, and the test would then fail with EADDRINUSE or reach that Uptime Goblin. With
// PORT deleted above, createApp without a `port` listens there: pass `port: 0` (any free port);
// a spawned Uptime Goblin takes PORT from freePortSync() (test/helpers/net.mjs).
{
  const { Server } = await import('node:net');
  const listen = Server.prototype.listen;
  Server.prototype.listen = function (...args) {
    const port = args[0] !== null && typeof args[0] === 'object' ? args[0].port : args[0];
    if (Number(port) === 4317)
      throw new Error(
        "A test tried to listen on port 4317, Uptime Goblin's default, which a running Uptime Goblin may hold: pass port: 0 to createApp (any free port)."
      );
    return listen.apply(this, args);
  };
}

// TEST_REQUIRE (a comma-separated list, kept because it has no GOBLIN_ prefix) makes a suite fail
// instead of skipping when what it needs is missing. CI sets it per job:
//   browser  - Chrome or Chromium for the browser suites
//   fixtures - the committed release fixtures for the upgrade simulation
//   systemd  - the Debian 13 systemd image for the real installer test
//   docker   - a Docker daemon that can build and run the image
//   postgres - a PostgreSQL server (from 1.7)
//   capacity - the 250,000-row audit measurement (test/audit/capacity.test.mjs), and the
//              chart budget's absolute target (test/series/summaries.test.mjs)
//   git      - a git executable for the tests that run one (test/helpers/git.mjs)
//   history  - the private history input (TEST_HISTORY, test/upgrade/history.mjs) for the tests
//              that start from a release tag or development milestone of the project's history;
//              public CI does not have it
// An unknown name fails every file at once, so a typo cannot quietly turn a check off.
const known = [
  'browser',
  'fixtures',
  'systemd',
  'docker',
  'postgres',
  'capacity',
  'git',
  'history',
];
const unknown = (process.env.TEST_REQUIRE || '')
  .split(',')
  .map(name => name.trim())
  .filter(name => name && !known.includes(name));
if (unknown.length)
  throw new Error(
    `Unknown TEST_REQUIRE entries: ${unknown.join(', ')} (known: ${known.join(', ')})`
  );

// Every container a test starts has finite memory, CPU and process limits. A docker (and
// docker-compose) of the tests' own goes first on PATH while a real one is there, and refuses a
// container without them, or a Compose project whose services lack them, before Docker sees it
// (test/helpers/docker-guard.mjs; test/docker-limits.test.mjs reads the test files for the same).
// It throws, failing every test file, where a search of PATH would pass it over (a TMPDIR
// mounted noexec).
installDockerGuard();

// The Store keeps its 1.x connection private (lib/store.mjs); tests inspect and plant rows in
// history.sqlite through store.db, which this opens to them. Server code never calls it
// (scripts/import-graph.mjs lets no server module but lib/store.mjs import its module).
const { exposeStoreConnections } = await import('../lib/store-connections.mjs');
exposeStoreConnections();
