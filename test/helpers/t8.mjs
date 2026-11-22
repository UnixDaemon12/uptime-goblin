// T8 part B's registration and its driver's check (test/disk-full.test.mjs). Part B fills the
// file system of TEST_T8_DIR until a write is refused, so its tests are registered only where
// that is a file system like the driver's own throwaway one: on Linux, not as root, an empty and
// unused tmpfs of exactly 96 MiB, with TEST_T8_RUN in the form of the driver's one-time code. The
// run cannot tell whether that code is the one the driver chose; the driver checks it afterwards.
// A TEST_T8_DIR that fails any of these checks gives one failing test and fills nothing. One
// that passes is such a tmpfs, so part B fills at most those 96 MiB of memory-backed space,
// never a disk, even where someone made that tmpfs on purpose outside the driver. Without
// TEST_T8_DIR (every host run) part B's tests are not registered at all. The driver then reads
// the run inside its container by exact test name and requires every test there to have passed
// (no skip, no todo), this run's code reported, and the Node version its image is for.
//
// Right before each filler file, t8Fill() checks again: Linux, not root, the code still the one
// checked at registration, the fill folder a real, empty folder inside TEST_T8_DIR on the same
// file system, and that file system an exactly 96 MiB tmpfs. Any failed check throws before the
// file is created.
import fs from 'node:fs';
import path from 'node:path';

// The size of the driver's tmpfs (docker run --tmpfs …,size=96m).
const t8Bytes = 96 * 2 ** 20;
// statfs(2)'s f_type of a tmpfs on Linux (TMPFS_MAGIC).
const tmpfsMagic = 0x01021994;

/** The exact test names: the three that run inside the driver's container, and the driver. */
export const t8Names = Object.freeze({
  environment:
    'T8 environment: TEST_T8_DIR is an empty 96 MiB tmpfs like the driver’s, and TEST_T8_RUN has the form of its code',
  partB:
    'T8 part B: on a real full file system, sign-in, delivery and a restart work, and space returns',
  measurements:
    'T8 measurements (recorded, not gating): WAL slack, and sign-in without the reserve',
  driver: 'T8 part B passes in node:24-bookworm-slim on a size-limited tmpfs',
});

const system = {
  platform: () => process.platform,
  uid: () => process.getuid?.(),
  version: () => process.version,
  readdir: directory => fs.readdirSync(directory),
  statfs: directory => fs.statfsSync(directory),
  lstat: file => fs.lstatSync(file),
  stat: file => fs.statSync(file),
  realpath: file => fs.realpathSync(file),
  open: (file, flags, mode) => fs.openSync(file, flags, mode),
  write: (fd, bytes) => fs.writeSync(fd, bytes),
  close: fd => fs.closeSync(fd),
};

/**
 * Where part B may run, judged before any test is registered: null without TEST_T8_DIR (a host
 * run: part B is absent), `{ok: false, reason}` when it names anything but the driver's
 * throwaway tmpfs, or `{ok: true, dir, run, bytes, node, uid}`. Nothing is written. `probe`
 * stands in for the system in tests.
 */
export function t8Environment(env = process.env, probe = system) {
  const dir = env.TEST_T8_DIR;
  if (!dir) return null;
  const refuse = why => ({
    ok: false,
    reason: `TEST_T8_DIR=${dir} is not the T8 driver's container tmpfs: ${why}. Part B fills that file system, so it is not registered.`,
  });
  const platform = probe.platform();
  if (platform !== 'linux') return refuse(`this is ${platform}, not Linux`);
  if (probe.uid() === 0) return refuse('this runs as root, and the driver runs part B as node');
  const run = env.TEST_T8_RUN ?? '';
  if (!/^[0-9a-f]{64}$/.test(run))
    return refuse('TEST_T8_RUN is not a one-time code of 64 lowercase hex digits');
  if (!path.isAbsolute(dir)) return refuse('it is not an absolute path');
  let entries, stats;
  try {
    entries = probe.readdir(dir);
    stats = probe.statfs(dir);
  } catch (error) {
    return refuse(`it cannot be read (${error.code || error.message})`);
  }
  if (entries.length) return refuse('it is not empty');
  if (Number(stats.type) !== tmpfsMagic)
    return refuse(`it is not on a tmpfs (file system type 0x${Number(stats.type).toString(16)})`);
  const bytes = Number(stats.blocks) * Number(stats.bsize);
  if (bytes !== t8Bytes) return refuse(`its tmpfs holds ${bytes} bytes, not ${t8Bytes} (96 MiB)`);
  if (Number(stats.bfree) !== Number(stats.blocks)) return refuse('its tmpfs already holds data');
  return { ok: true, dir, run, bytes, node: (probe.version ?? system.version)(), uid: probe.uid() };
}

/**
 * The diagnostic the environment test prints, which the driver looks for: this run's code, and
 * the Node version and user that produced the evidence inside the container.
 */
export const t8RunLine = ({ run, dir, bytes, node, uid }) =>
  `T8 run ${run}: ${dir} is an empty tmpfs of ${bytes} bytes; node ${node}, uid ${uid}`;

/**
 * Fills the file system of `directory` until a write is refused (ENOSPC or EDQUOT), with the file
 * `filler` there, and returns the bytes written. Before the file is created it checks, and throws
 * on the first that fails: Linux; not root; TEST_T8_RUN still `expected`, the code checked when
 * part B was registered; TEST_T8_DIR and `directory` absolute; `directory` a real folder (not a
 * link) inside TEST_T8_DIR on the same device, and empty; its file system a tmpfs of exactly
 * 96 MiB. The file is opened with O_EXCL and O_NOFOLLOW. `probe` stands in for the system in tests.
 */
export function t8Fill(directory, { env = process.env, expected, probe = system } = {}) {
  const refuse = why => {
    throw new Error(`T8 will not fill ${directory}: ${why}. Nothing was written.`);
  };
  const platform = probe.platform();
  if (platform !== 'linux') refuse(`this is ${platform}, not Linux`);
  if (probe.uid() === 0) refuse('this runs as root');
  const run = env.TEST_T8_RUN ?? '';
  if (!/^[0-9a-f]{64}$/.test(run) || run !== expected)
    refuse('TEST_T8_RUN is not the code checked when part B was registered');
  const t8 = env.TEST_T8_DIR ?? '';
  if (!path.isAbsolute(t8) || !path.isAbsolute(directory))
    refuse('TEST_T8_DIR or the fill folder is not an absolute path');
  const folder = probe.lstat(directory);
  if (!folder.isDirectory()) refuse('it is not a folder (or it is a link)');
  const root = probe.realpath(t8);
  if (!probe.realpath(directory).startsWith(`${root}${path.sep}`))
    refuse('it is not a folder inside TEST_T8_DIR');
  if (folder.dev !== probe.stat(t8).dev) refuse('it is not on the file system of TEST_T8_DIR');
  if (probe.readdir(directory).length) refuse('it is not empty');
  const stats = probe.statfs(directory);
  if (Number(stats.type) !== tmpfsMagic)
    refuse(`it is not on a tmpfs (file system type 0x${Number(stats.type).toString(16)})`);
  const bytes = Number(stats.blocks) * Number(stats.bsize);
  if (bytes !== t8Bytes) refuse(`its tmpfs holds ${bytes} bytes, not ${t8Bytes} (96 MiB)`);
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
  const fd = probe.open(
    path.join(directory, 'filler'),
    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
    0o600
  );
  const chunk = Buffer.alloc(2 ** 20, 0x5a);
  let written = 0;
  try {
    for (;;) {
      try {
        written += probe.write(fd, chunk);
      } catch (error) {
        if (error.code === 'ENOSPC' || error.code === 'EDQUOT') break;
        throw error;
      }
    }
    // The last bytes of a partly written chunk, until nothing more fits.
    for (let size = 64 * 1024; size >= 512; size /= 2)
      for (;;)
        try {
          written += probe.write(fd, chunk.subarray(0, size));
        } catch {
          break;
        }
  } finally {
    probe.close(fd);
  }
  return written;
}

/**
 * The pinned images of the T8 container run (test/platform-manifest.json, runs.t8-container):
 * [{ runtime, image, driver }] for each runtime that has one. A runtime whose image is null has
 * no driver; the coverage check reports its missing evidence.
 */
export function t8Images(manifest) {
  return Object.entries(manifest.runs['t8-container'].images)
    .filter(([, configured]) => configured)
    .map(([runtime, configured]) => ({ runtime, ...configured }));
}

// A TAP line reporting a test's result: [line, indent, ok, name, directive].
const resultLine = /^(\s*)(not ok|ok) \d+ - (.*?)(?: # (.*))?$/;

/**
 * The driver's check of the TAP of the run inside its container (its stdout). Returns what is
 * wrong, [] for none: each total must be there exactly once, every test must have passed (pass
 * equals tests; fail, cancelled, skipped and todo are 0), the environment test, part B and the
 * measurements must each have exactly one result line, a top-level `ok` with no directive, the
 * driver must be absent, and the environment test must report `run`, this run's one-time code,
 * and, given `runtime` ('24' or '26'), a Node version of that major: the image's runtime.
 */
export function t8InnerProblems(tap, run, runtime) {
  const lines = String(tap).split('\n');
  const problems = [];
  const totals = {};
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const found = lines.filter(line => line.startsWith(`# ${name} `));
    if (found.length !== 1 || !/^# \w+ \d+$/.test(found[0]))
      problems.push(`the run inside has ${found.length} "# ${name}" lines, not one total`);
    else totals[name] = Number(found[0].split(' ')[2]);
  }
  if ('tests' in totals && 'pass' in totals && (totals.tests === 0 || totals.pass !== totals.tests))
    problems.push(`the run inside passed ${totals.pass} of ${totals.tests} tests`);
  for (const name of ['fail', 'cancelled', 'skipped', 'todo'])
    if (name in totals && totals[name] !== 0)
      problems.push(`the run inside has ${totals[name]} ${name}`);
  const results = lines.map(line => resultLine.exec(line)).filter(Boolean);
  for (const name of [t8Names.environment, t8Names.partB, t8Names.measurements]) {
    const named = results.filter(match => match[3] === name);
    if (named.length !== 1) problems.push(`${named.length} result lines for "${name}", not one`);
    else if (named[0][1] || named[0][2] !== 'ok' || named[0][4] !== undefined)
      problems.push(`"${name}" did not pass at the top level: ${named[0][0]}`);
  }
  if (lines.some(line => line.includes(t8Names.driver)))
    problems.push('the driver itself is named in the run inside');
  const codes = lines.map(line => /^# T8 run ([0-9a-f]{64}): /.exec(line)?.[1]).filter(Boolean);
  if (codes.length !== 1 || codes[0] !== run)
    problems.push(
      `the run inside reported the one-time code ${codes.join(', ') || 'nowhere'}, not this run's ${run}`
    );
  if (runtime !== undefined) {
    const node = lines
      .map(line => /^# T8 run [0-9a-f]{64}: .*; node (v\d+\.\d+\.\d+), uid \d+$/.exec(line)?.[1])
      .filter(Boolean);
    if (node.length !== 1 || !node[0].startsWith(`v${runtime}.`))
      problems.push(
        `the run inside reported Node ${node.join(', ') || 'nowhere'}, not Node ${runtime}, the image's runtime`
      );
  }
  return problems;
}
