// Installed as server.mjs by the installer tests: implements only what the installer checks
// (public /health with ?instance, run/status.json) and misbehaves on request. The test sets
// `mode` below to one of: ok, crash (exit 1), refuse (exit 78), refuse-limits (prints the
// arguments it was given, then a refusal for want of a resource limit that begins with
// LIMITS_REFUSAL, and exits 78 before it listens), hang (never listens), stale-version (reports
// another version), mismatch (never confirms the instance) or foreign-status (status.json names
// another process). Once it listens it reports ready to systemd, as Uptime Goblin does.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { computeBuild } from './lib/healthcheck.mjs';
import { notifyReady } from './lib/systemd-notify.mjs';

const mode = '__MODE__';
const root = path.dirname(fileURLToPath(import.meta.url));
const version =
  mode === 'stale-version'
    ? '0.0.1'
    : JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
console.log(
  `fake orbit ${version} starting (${mode}), supervised=${process.env.GOBLIN_SUPERVISED ?? process.env.ORBIT_SUPERVISED}`
);
if (mode === 'crash') {
  console.error('fake orbit: simulated crash');
  process.exit(1);
}
if (mode === 'refuse') {
  console.error('fake orbit: refusing to start');
  process.exit(78);
}
// As a supervised Uptime Goblin refuses where a resource limit is not in force (lib/resource-limits.mjs):
// the arguments it was started with (the unit's --supervised), then, in one write, a refusal for
// a CPU limit alone as the service logs it: its first line (LIMITS_REFUSAL), the CPU limit's line
// and its last line, the two ways out, which names GOBLIN_ALLOW_UNLIMITED=cpu. The installer shows
// these lines as they are and draws nothing from them. A synthetic model of superviseLimits's
// refusal, written out here: it reads no cgroup, as its CPU line says, and judges no limit.
// Imported here only, so that the other modes load as before.
if (mode === 'refuse-limits') {
  const { LIMITS_REFUSAL } = await import('./lib/resource-limits.mjs');
  const refusal = [
    `${LIMITS_REFUSAL} under a service manager (started with --supervised or GOBLIN_SUPERVISED=1) it starts only where its own cgroup holds its memory, CPU time and processes to a limit, and here its CPU limit is not in force.`,
    `CPU limit: none (fake orbit, refuse-limits: no cgroup was read). Under Docker, give cpus in compose.yaml or compose.override.yaml (docker run --cpus), or, where the kernel cannot limit CPU time, a CPU set (cpuset: '0') that Docker applies; under systemd, CPUQuota= in uptime-goblin.service or a drop-in (an empty CPUQuota= lifts it); in an LXC, its host must delegate the cpu controller to the container.`,
    `To start Uptime Goblin, apply each limit named above (docs/installation.md, "Resource limits", has the steps for Docker, systemd and LXC hosts), or, on a platform that cannot apply it, set GOBLIN_ALLOW_UNLIMITED=cpu in Uptime Goblin's environment (/etc/uptime-goblin.env for the systemd unit, .env for Docker Compose): Uptime Goblin then starts without that limit and says so at every start.`,
  ];
  console.log(`fake orbit arguments: ${JSON.stringify(process.argv.slice(2))}`);
  console.error(refusal.join('\n'));
  process.exit(78);
}
// Never on 4317, Uptime Goblin's default: an Uptime Goblin run with its defaults, or another test's, may hold it
// on the test machine. A test of a first install takes makeFreshHost (helpers.mjs), which gives
// /etc/uptime-goblin.env the host's free port. Exit 78, so the unit is not restarted.
if (process.env.PORT === '4317') {
  console.error(
    'fake orbit: PORT is 4317, which a real Uptime Goblin may hold; give the test host a free port'
  );
  process.exit(78);
}
if (mode === 'hang') setInterval(() => {}, 60000);
else {
  const nonce = randomBytes(16).toString('hex');
  // GOBLIN_DATA_DIR, or ORBIT_DATA_DIR under the Orbit layout's unit (as a release before 1.5).
  const statusFile = path.join(
    process.env.GOBLIN_DATA_DIR ?? process.env.ORBIT_DATA_DIR,
    'run',
    'status.json'
  );
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/health') {
      res.writeHead(404);
      res.end();
      return;
    }
    const body = { status: 'ok' };
    if (url.searchParams.has('instance'))
      body.instance =
        mode !== 'mismatch' && url.searchParams.get('instance') === nonce ? 'match' : 'mismatch';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  server.listen(Number(process.env.PORT), process.env.HOST, () => {
    fs.mkdirSync(path.dirname(statusFile), { recursive: true, mode: 0o700 });
    const status = {
      version,
      build: computeBuild(root),
      pid: mode === 'foreign-status' ? 1 : process.pid,
      nonce,
      startedAt: Date.now(),
      listen: { host: process.env.HOST, port: Number(process.env.PORT) },
      observed: { forwardedProto: null },
    };
    fs.writeFileSync(`${statusFile}.tmp`, JSON.stringify(status), { mode: 0o600 });
    fs.renameSync(`${statusFile}.tmp`, statusFile);
    console.log(`fake orbit ${version} ready`);
    // As Uptime Goblin tells the Type=notify unit (real systemd only: NOTIFY_SOCKET).
    void notifyReady();
  });
  process.on('SIGTERM', () => {
    fs.rmSync(statusFile, { force: true });
    server.close();
    process.exit(0);
  });
}
