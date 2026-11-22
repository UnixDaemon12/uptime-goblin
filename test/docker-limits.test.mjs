// Every container a test starts has finite memory, CPU and process limits (the maintainer's rule for
// 1.5): each `docker run` and `docker create` in test/ gives --memory, --cpus and --pids-limit.
// test/helpers/docker-limits.mjs checks this without running anything: it reads every file below
// test/, whatever its name or mode, JavaScript as code and any other file line by line, where a
// line that mentions docker is refused unless it is reviewed (see there for exactly what it
// checks and what it cannot). So a call without them fails here, in test:fast, wherever the
// suite runs and whether or not Docker is there. The other tests show on synthetic sources and
// a synthetic tree that the check refuses what it should. What it cannot read, the guard that
// test/setup.mjs puts first on PATH refuses when it runs (test/docker-guard.test.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkFile,
  checkSource,
  checkTree,
  fixturePins,
  isFinderFile,
  tokenize,
} from './helpers/docker-limits.mjs';
import { fixturesRequired, missingFixtures } from './upgrade/fixtures.mjs';

const testDirectory = path.dirname(fileURLToPath(import.meta.url));

// Docker calls the check cannot read in full, each one reviewed: a subcommand that is not a
// literal (none of these makes a container), or a spread it cannot read where Docker reads the
// options of run or create (none gives a limit). A new caller is not checked: review it too.
// Then the lines of other files that mention docker ({file, line}: the line, trimmed).
const reviewed = [
  {
    file: 'installer/docker.test.mjs',
    call: "docker(kind, 'inspect', name)",
    why: 'absent(): `docker container|volume|image inspect`; every caller passes one of those three',
  },
  {
    file: 'installer/docker.test.mjs',
    call: "docker(...command, '--filter', `label=com.docker.compose.project=${name}`)",
    why: 'projectObjects(): `command` is ps --all --quiet, volume ls --quiet or network ls --quiet',
  },
  {
    file: 'installer/docker.test.mjs',
    call: "docker('create', ...limits, ...args)",
    why: 'dockerOwner().run(): its callers (own.run, five of them) give --name, --env, --publish, --volume and like options and the image, never --memory, -m, --cpus or --pids-limit',
  },
  {
    file: 'installer/docker.test.mjs',
    call: "docker( 'run', ...limits, '--rm', ...(init ? ['--init'] : []), '--user', 'node', '--network', 'none', '--read-only', '--volume', `${tree}:/app:ro`, '--volume', `${volume}:/data`, '--workdir', '/app', '--env', 'GOBLIN_DATA_DIR=/data', node, 'node', 'lib/cli/goblin-admin.mjs', command )",
    why: 'admin(): the spread is --init or nothing',
  },
  {
    file: 'installer/docker.test.mjs',
    call: "docker('run', '--memory', '128m', '--cpus', '1', '--pids-limit', '32', '--rm', ...args)",
    why: 'helper() of the Compose-as-shipped test: its two callers give --network, --pid, --user, the image and the command, never --memory, -m, --cpus or --pids-limit',
  },
  // Programs spawned by a name no literal gives ({file, program}: the command as written), each
  // one reviewed: none of them is docker.
  {
    file: 'db/cli.test.mjs',
    program: 'shell',
    why: "shellWords(): /bin/sh or /bin/zsh from its own list, on a PATH holding only the test's stub of sudo or docker, which prints its arguments",
  },
  {
    file: 'docker-guard.test.mjs',
    program: 'program',
    why: "run(): docker, docker-compose or sh, on a PATH that holds only the guard's stand-ins, the test's stand-in for the real docker (which reaches no daemon) and /usr/bin and /bin",
  },
  {
    file: 'helpers/cdp.mjs',
    program: 'chromePath',
    why: 'Chrome or Chromium: CHROME_PATH or the first of the browser paths this module lists',
  },
  {
    file: 'helpers/docker-guard.mjs',
    program: 'real',
    why: 'composeProblems(): the real docker (or docker-compose) the guard stands in for, run only with `config --profiles` or `config --format json`, which make no container',
  },
  {
    file: 'installer/fake-bin/systemctl.cjs',
    program: 'unit.exec[0]',
    why: "the stand-in systemctl's start: the ExecStart of a unit the installer tests install, the node that runs Orbit",
  },
  {
    file: 'installer/image-layers.mjs',
    program: 'program',
    why: 'layerContains(): tar, unless a caller passes `tar`; only image-layers.test.mjs does, with /bin/sh and stand-in-tar, a file below test/ that this check reads',
  },
  {
    file: 'security-dispatch.test.mjs',
    program: 'standIn',
    why: 'refusingStandIn(): the test writes this shell stand-in below its temporary directory; it only records its arguments and exits 97, never starting another program',
  },
  {
    file: 'sonarqube.test.mjs',
    program: 'command',
    why: "fixture()'s run(), which checkSonarQube() calls instead of spawning: it spawns `command` only when that is 'git', and answers every other call, asserted to be docker, itself",
  },
  // Literals that name docker by a path, and literals a module hands to another program that
  // mention docker ({file, literal}: as the source writes it), each one reviewed (rule 5). A
  // literal path cannot be listed, since this list would then name it too: write it as
  // path.join(dir, 'docker'), and list that.
  {
    file: 'docker-guard.test.mjs',
    literal: "path.join(bin, 'docker')",
    why: "fakeDocker(): the test's stand-in for the real docker, which records its arguments and reaches no daemon",
  },
  {
    file: 'helpers/docker-guard.mjs',
    literal: "path.join(bin, 'docker')",
    why: "installDockerGuard(): the guard's own stand-in, which it writes there",
  },
  {
    file: 'helpers/docker-guard.mjs',
    literal: "path.join(bin, 'docker-compose')",
    why: "installDockerGuard(): the guard's own stand-in for docker-compose, which it writes there",
  },
  {
    file: 'installer/docker.test.mjs',
    literal: "path.join(bin, 'docker')",
    why: 'the two Compose line tests: their stand-in docker (docker.mjs), first on the PATH of the lines they run, which reaches no daemon',
  },
  {
    file: 'installer/docker.test.mjs',
    literal: "'docker compose -f compose.yaml'",
    why: "volumeCheck(): the documented check line of compose.secret.yaml, run by sh in the test's own environment, so docker by name, where the guard stands first on PATH and reads the project's services",
  },
  {
    file: 'installer/docker.test.mjs',
    literal: "`docker compose --project-name ${name} ${files.map(file => `-f ${file}`).join(' ')}`",
    why: 'volumeCheck(): the same line, for the test project and its files',
  },
  {
    file: 'security-evidence.test.mjs',
    literal: "path.join(gate.bin, 'docker')",
    why: 'the pinned-T8 activation test writes its own stand-in here; it answers synthetic image-inspect/version data and never starts Docker or another program',
  },
  // Lines of files that are not JavaScript that mention docker, each one reviewed.
  {
    file: 'installer/systemd.Dockerfile',
    line: '#   docker build --pull -t orbit-installer-systemd:debian13 -f test/installer/systemd.Dockerfile test/installer',
    why: 'a comment: how to build the image by hand; the lines of a Dockerfile run only inside an image build, which cannot reach the Docker daemon',
  },
  {
    file: 'installer/systemd.Dockerfile',
    line: 'ENV container=docker DEBIAN_FRONTEND=noninteractive',
    why: 'the variable systemd reads to know that it runs in a container',
  },
  {
    file: 'platform-manifest.json',
    line: '"prerequisites": ["docker"],',
    why: "data, not a command: the T8 driver's prerequisite, which test/helpers/platform.mjs reads as `docker` listed in TEST_REQUIRE; nothing runs this file",
  },
];

// docker by a path, for the synthetic sources and files below: built at run time, since rule 5
// refuses a literal that names docker by a path in this file as in any other (these sources are
// only read, never run).
const dockerAt = (directory, name = 'docker') => `${directory}/${name}`;

const format = problem =>
  `test/${problem.file}:${problem.line}: ${problem.why}\n    ${problem.text}`;

test('synthetic fixture reviews do not allow real Docker launches or other executable paths', () => {
  const file = 'security-evidence.test.mjs';
  const source = fs.readFileSync(path.join(testDirectory, file), 'utf8');
  const launch = checkSource(source + "\nspawnSync('docker', ['run', 'unbounded-image']);\n", {
    file,
    reviewed,
  });
  assert.ok(
    launch.problems.some(
      problem => problem.text.includes("spawnSync('docker'") && /--memory/.test(problem.why)
    ),
    JSON.stringify(launch.problems)
  );
  const otherPath = checkSource(
    source + "\nconst unreviewedDockerPath = path.join(otherDirectory, 'docker');\n",
    { file, reviewed }
  );
  assert.ok(
    otherPath.problems.some(
      problem =>
        problem.text === "path.join(otherDirectory, 'docker')" &&
        /names docker by a path/.test(problem.why)
    ),
    JSON.stringify(otherPath.problems)
  );
});

test('every docker run and create in test/ gives finite --memory, --cpus and --pids-limit', t => {
  const { read, skipped, ignored, problems, containers } = checkTree(testDirectory, { reviewed });
  assert.deepEqual(problems.map(format), [], `\n${problems.map(format).join('\n')}`);
  // Every file is read, by what it holds: modules, CommonJS and shell stand-ins, and
  // stand-in-tar, which image-layers.test.mjs runs as /bin/sh stand-in-tar (no #! line, no .sh
  // name, mode 0644).
  const kinds = new Map(read.map(({ file, kind }) => [file, kind]));
  for (const [file, kind] of [
    ['setup.mjs', 'javascript'],
    ['installer/fake-bin/systemctl.cjs', 'javascript'],
    ['installer/fake-bin/systemctl', 'text'],
    ['installer/stand-in-tar', 'text'],
    ['installer/systemd.Dockerfile', 'text'],
    ['dialect/golden/reference-sqlite.sql', 'text'],
    ['fixtures/SHA256SUMS', 'text'],
  ])
    assert.equal(kinds.get(file), kind, `test/${file} was not read as ${kind}`);
  // Only the release fixtures pinned in fixtures/SHA256SUMS and Finder's .DS_Store files are
  // passed over; every other file below test/ is read.
  const all = fs
    .readdirSync(testDirectory, { recursive: true, withFileTypes: true })
    .filter(entry => !entry.isDirectory())
    .map(entry =>
      path
        .relative(testDirectory, path.join(entry.parentPath, entry.name))
        .split(path.sep)
        .join('/')
    );
  assert.deepEqual([...kinds.keys(), ...skipped, ...ignored].sort(), all.sort());
  for (const file of ignored) assert.equal(path.posix.basename(file), '.DS_Store');
  // Each pinned archive that is there is passed over (holding its pinned bytes: one that does not
  // is refused above). A release leaves them out (scripts/package-release.mjs), and the suite
  // still runs from it, so they must be there only when TEST_REQUIRE includes fixtures, as for
  // the upgrade tests.
  const pinned = [...fixturePins(testDirectory).keys()];
  const present = pinned.filter(file => fs.existsSync(path.join(testDirectory, file)));
  if (fixturesRequired()) {
    assert.deepEqual(
      missingFixtures(),
      [],
      'TEST_REQUIRE=fixtures: the release fixtures are there'
    );
    assert.deepEqual(present, pinned, 'TEST_REQUIRE=fixtures: every pinned fixture is there');
  } else if (present.length < pinned.length)
    t.diagnostic(`release fixtures not here, as in a release: ${pinned.length - present.length}`);
  assert.deepEqual(skipped, present.sort());
  for (const file of skipped)
    assert.match(file, /^fixtures\/(?:releases|npm)\/[^/]+\.(?:tar\.gz|tgz)$/);
  // The files that start containers were found to (a check that saw nothing would pass too).
  for (const file of [
    'disk-full.test.mjs',
    'installer/docker.test.mjs',
    'installer/systemd.test.mjs',
  ])
    assert.ok(containers.get(file) > 0, `no docker run or create found in test/${file}`);
});

test('the docker limits check refuses what it should, on synthetic sources', () => {
  const wrapper = "const docker = (...args) => spawnSync('docker', args, { encoding: 'utf8' });\n";
  const limits = "const limits = ['--memory=1g', '--cpus=2', '--pids-limit=256'];\n";
  const problems = (source, options) => checkSource(source, options).problems.map(p => p.why);
  const accepted = source => assert.deepEqual(problems(source), [], source);
  const refused = (source, why) => {
    const found = problems(source);
    assert.equal(found.length, 1, `${source}\n${found.join('\n')}`);
    assert.match(found[0], why, source);
  };

  // Accepted: the limits right after the subcommand, written out, split or spread.
  accepted(wrapper + limits + "docker('run', ...limits, '--rm', 'node:24');");
  accepted(
    wrapper +
      "docker('container', 'create', '--memory', '512m', '--cpus', '0.5', '--pids-limit', '64', 'img');"
  );
  accepted("spawnSync('docker', ['run', '-m', '1g', '--cpus=1', '--pids-limit=10', 'img']);");
  accepted(
    "execFileSync('docker', [...['run', '--memory=1g'], '--cpus=2', '--pids-limit=3', 'img']);"
  );
  // Other subcommands need none; a method named run is not docker.
  accepted(wrapper + "docker('rm', '--force', id); docker('exec', name, 'sh'); own.run('img');");
  // Text that only looks like a call: comments, strings, templates, regular expressions.
  accepted(
    [
      "// docker('run', 'img')",
      "/* spawnSync('docker', ['run', 'img']) */",
      wrapper,
      "const a = \"docker('run', 'img')\";",
      "const b = `spawnSync('docker', ['create', 'img'])`;",
      "const c = /(docker)\\('run', '[)]'\\)/;",
      "const d = x / 2 / docker('version');",
    ].join('\n')
  );

  // Refused: a limit missing, zero or unlimited, or not right after the subcommand.
  refused(wrapper + "docker('run', '--memory=1g', '--cpus=2', 'img');", /--pids-limit/);
  refused(
    wrapper + "docker('run', '--memory=0', '--cpus=2', '--pids-limit=256', 'img');",
    /--memory/
  );
  refused(
    wrapper + "docker('create', '--memory=1g', '--cpus=0', '--pids-limit=-1', 'img');",
    /--cpus, --pids-limit/
  );
  // Docker counts memory in whole bytes, dropping a fraction (0.5 and .9b reach it as 0, no
  // limit), and refuses a limit under 6 MiB; past int64 its count is undefined.
  for (const value of ['0.5', '.9b', '0.000001k', '1b', '6291455b', '0.0058g', '8589934592g'])
    refused(
      wrapper + `docker('run', '--memory=${value}', '--cpus=2', '--pids-limit=256', 'img');`,
      /--memory right/
    );
  refused(
    "spawnSync('docker', ['create', '-m', '.9b', '--cpus=2', '--pids-limit=9', 'i']);",
    /--memory/
  );
  for (const value of ['6291456b', '6m', '0.006g', '1.5G'])
    accepted(
      wrapper + `docker('run', '--memory=${value}', '--cpus=2', '--pids-limit=256', 'img');`
    );
  refused(
    wrapper + limits + "docker('run', '--rm', ...limits, 'img');",
    /--memory, --cpus, --pids-limit right after/
  );
  refused(
    wrapper + "docker('run', 'img', '--memory=1g', '--cpus=2', '--pids-limit=9');",
    /--memory/
  );
  refused(wrapper + "docker('container', 'run', 'img');", /docker run without/);
  refused("spawn('docker', ['create', 'img']);", /docker create without/);
  // A spread of anything but one array constant of strings is not trusted.
  refused(
    wrapper + limits + "const limits2 = [flag, '--cpus=2'];\ndocker('run', ...limits2, 'img');",
    /--memory/
  );
  refused(
    wrapper + limits + limits.replace('1g', '2g') + "docker('run', ...limits, 'img');",
    /--memory/
  );
  // Calls inside a template's substitution are code, and are checked.
  refused(wrapper + "const e = `${docker('run', 'img').stdout}`;", /docker run without/);
  // Wrappers that pass their arguments on are followed.
  refused(wrapper + "const d = (...a) => docker(...a);\nd('run', 'img');", /docker run without/);
  // docker named by a template literal, by a path (in any case: macOS finds it so), or inside the
  // command's expression is docker too.
  refused("spawnSync(`docker`, ['run', 'img']);", /docker run without/);
  refused(`spawnSync('${dockerAt('/usr/local/bin')}', ['run', 'img']);`, /docker run without/);
  refused(
    `spawn(\`${dockerAt('${bin}', 'Docker')}\`, ['create', 'img']);`,
    /docker create without/
  );
  refused("execFileSync(path.join(bin, 'docker'), ['run', 'img']);", /docker run without/);
  refused("const d = (...a) => spawnSync(`docker`, a);\nd('run', 'img');", /docker run without/);
  refused(`spawnSync('${dockerAt('/usr/bin')}', args);`, /cannot read/);
  refused(`execSync('${dockerAt('/usr/local/bin')} run --rm img');`, /shell command line/);
  refused("spawnSync('docker run --rm img', { shell: true });", /shell command line/);
  accepted(
    `spawnSync('${dockerAt('/usr/bin')}', ['run', '--memory=1g', '--cpus=2', '--pids-limit=3', 'i']);`
  );
  accepted("spawnSync('docker-credential-desktop', ['list']); spawnSync('dockerd', ['--help']);");
  // An option before the subcommand (--context, -H, --log-level) hides it: refused.
  refused(
    wrapper + "docker('--context', 'default', 'run', '--rm', 'img');",
    /before the subcommand/
  );
  refused(wrapper + "docker('--log-level', 'error', 'create', 'img');", /before the subcommand/);
  refused("spawnSync('docker', ['-H', 'unix:///run/docker.sock', 'run', 'img']);", /before the/);
  refused(wrapper + limits + "docker('-D', 'container', 'run', ...limits, 'img');", /before the/);
  refused(wrapper + "docker('--host=ssh://box', 'version');", /before the subcommand/);
  // What cannot be read is refused rather than passed.
  refused("spawnSync('docker', args);", /cannot read/);
  refused("execSync('docker run --rm img');", /shell command line/);
  refused(wrapper + "docker(sub, 'img');", /not a literal/);
  // A reviewed call passes; a reviewed call that is gone is reported.
  const listed = [{ file: 'x.mjs', call: "docker(sub, 'img')" }];
  assert.deepEqual(
    problems(wrapper + "docker(sub, 'img');", { file: 'x.mjs', reviewed: listed }),
    []
  );
  assert.deepEqual(problems(wrapper, { file: 'x.mjs', reviewed: listed }), [
    'listed as reviewed, but no longer found',
  ]);

  // A limit given again where Docker reads options replaces the first, since Docker keeps the
  // last value given: refused, whatever its value or form. After the image it is the command's.
  const again = /again where Docker may read it as an option/;
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '--memory=0', 'img');", again);
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '--pids-limit=-1', 'img');", again);
  refused(
    wrapper + limits + "docker('create', ...limits, '--name', 'x', '--cpus=0', 'img');",
    again
  );
  refused(
    "spawnSync('docker', ['run', '--memory=1g', '--cpus=2', '--pids-limit=256', '--rm', '-m', '0', 'i']);",
    again
  );
  refused(wrapper + limits + "docker('run', ...limits, '-itm0', 'img');", again);
  refused(wrapper + limits + "docker('run', ...limits, '--name', name, '-dm=0', 'img');", again);
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '--memory', '2g', 'img');", again);
  // Right after the subcommand, the last value given counts, as for Docker.
  accepted(wrapper + limits + "docker('run', ...limits, '--memory', '2g', 'img');");
  refused(wrapper + limits + "docker('run', ...limits, '--memory', '0', 'img');", /--memory right/);
  // A word built from a limit option is one, whatever value it is given.
  refused(wrapper + limits + "docker('run', ...limits, '--rm', `--memory=${size}`, 'img');", again);
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '-m' + size, 'img');", again);
  // docker update changes the limits of a container that runs.
  refused(wrapper + "docker('update', '--pids-limit=-1', id);", /docker update can change/);
  refused(wrapper + "docker('container', 'update', '--restart=no', id);", /docker update/);
  // A variable where Docker reads options could be an option taking the next word, so what
  // follows could be options too.
  refused(
    wrapper + limits + "docker('run', ...limits, image, 'python3', '-m', 'http.server');",
    again
  );
  accepted(
    wrapper + limits + "docker('run', ...limits, '--rm', 'img', 'sh', '-c', 'free -m', '-m');"
  );
  accepted(
    wrapper + limits + "docker('run', ...limits, '-it', '--rm', 'py', 'python3', '-m', 'x');"
  );
  accepted(wrapper + limits + "docker('run', ...limits, '-e', 'A=1', '--', 'img', '--memory=0');");
  accepted(
    wrapper + limits + "docker('run', ...limits, '--network', 'none', image, 'sh', '-c', 'x');"
  );
  // A spread this check cannot read, where Docker reads options, is refused unless reviewed.
  refused(
    wrapper + limits + "const id = docker('create', ...limits, ...args);",
    /spreads \.\.\.args/
  );
  assert.deepEqual(
    problems(wrapper + limits + "docker('create', ...limits, ...args);", {
      file: 'x.mjs',
      reviewed: [{ file: 'x.mjs', call: "docker('create', ...limits, ...args)" }],
    }),
    []
  );
  accepted(wrapper + limits + "docker('run', ...limits, '--rm', 'img', ...command);");
  // Only a const array that nothing else in the file can change or bind again is trusted.
  const untrusted = /docker run without finite --memory, --cpus, --pids-limit/;
  refused(wrapper + limits.replace('const', 'let') + "docker('run', ...limits, 'img');", untrusted);
  refused(
    wrapper + limits.replace('const', 'let') + "limits = [];\ndocker('run', ...limits, 'img');",
    untrusted
  );
  refused(
    wrapper + limits + "limits.push('--memory=0');\ndocker('run', ...limits, 'i');",
    untrusted
  );
  refused(
    wrapper + limits + "limits[0] = '--memory=0';\ndocker('run', ...limits, 'i');",
    untrusted
  );
  refused(wrapper + limits + "const f = (...limits) => docker('run', ...limits, 'i');", untrusted);
  refused(
    wrapper + limits + "function f(limits) { return docker('run', ...limits, 'i'); }",
    untrusted
  );
  refused(wrapper + 'export ' + limits + "docker('run', ...limits, 'img');", untrusted);
  refused(
    wrapper + limits.replace('];', '].slice(1);') + "docker('run', ...limits, 'img');",
    untrusted
  );
  accepted(
    wrapper + limits + "const o = { limits: 1 };\no.limits = 2;\ndocker('run', ...limits, 'i');"
  );

  // child_process's functions under the names a module gives them; used other than by calling
  // them, or taken in other ways, they are refused.
  const runImport = "import { spawnSync as sh } from 'node:child_process';\n";
  refused(runImport + "sh('docker', ['run', 'img']);", /docker run without/);
  refused(
    "const { execFileSync: run } = require('child_process');\nrun('docker', ['create', 'img']);",
    /docker create without/
  );
  refused(
    "import { execSync as sh } from 'node:child_process';\nsh('docker run --rm img');",
    /shell command line/
  );
  refused(
    "import cp from 'node:child_process';\ncp.spawnSync('docker', ['run', 'img']);",
    /docker run without/
  );
  const notCalled = /\(child_process\) is used other than by calling/;
  refused(
    "import { execFile } from 'node:child_process';\nconst run = promisify(execFile);\nrun('docker', a);",
    notCalled
  );
  refused(
    "import * as cp from 'node:child_process';\nconst run = util.promisify(cp.execFile);",
    notCalled
  );
  refused("const cp = require('node:child_process');\nconst sh = cp.spawnSync;", notCalled);
  refused(runImport + 'const run = sh;', notCalled);
  refused("export { spawnSync as run } from 'node:child_process';", /taken in a way/);
  refused("helper(require('child_process'));", /taken in a way/);
  accepted(
    [
      "import { spawnSync } from 'node:child_process';",
      "import * as cp from 'child_process';",
      "const { spawn } = require('node:child_process');",
      "spawnSync('git', ['status']); spawn('/usr/bin/env', args); cp.execFileSync('ls', []);",
      "require('child_process').execFileSync('ls', []);",
    ].join('\n')
  );
  // A program that no literal names could be docker: refused unless reviewed (by its text), so a
  // variable (the verifier's process.env.DOCKER ?? 'docker') cannot hide it. A literal, a path
  // ending in a literal name, or node itself is accepted; so is a method of another object that
  // has such a name (a regular expression's exec, a database's).
  const unnamed = /the program spawned here \((.*)\) is not named by a literal/;
  for (const call of [
    "const bin = process.env.DOCKER ?? 'docker';\nspawnSync(bin, ['run', '--rm', 'img']);",
    'spawn(command, args);',
    "execFileSync(tools[0], ['run', 'img']);",
    "spawnSync(`${bin}/${name}`, ['run', 'img']);",
    "spawnSync('/usr/bin/' + tool, ['run', 'img']);",
    "spawnSync(path.join(bin, name), ['run', 'img']);",
    "import cp from 'node:child_process';\ncp.spawnSync(bin, ['run', 'img']);",
    "require('child_process').spawn(bin, ['run', 'img']);",
  ])
    refused(call, unnamed);
  for (const call of [
    "spawnSync(process.execPath, ['--test']);",
    "spawn(`${bin}/tar`, ['-xf', archive]);",
    "spawnSync(path.join(bin, 'systemctl'), ['start', 'orbit']);",
    "spawnSync(path.resolve(root, 'bin', 'tool'), []);",
    'pattern.exec(text); db.exec(statement); child.spawn(job); worker.execFile(name, []);',
  ])
    accepted(call);
  const programs = [{ file: 'x.mjs', program: 'shell', why: 'synthetic' }];
  assert.deepEqual(
    problems("spawnSync(shell, ['-c', 'true']);", { file: 'x.mjs', reviewed: programs }),
    []
  );
  assert.deepEqual(problems('const a = 1;', { file: 'x.mjs', reviewed: programs }), [
    'listed as reviewed, but no longer found',
  ]);
  // A shell command line (exec, execSync, or a spawn given one, with a blank) is read as sh reads
  // a line: one that mentions docker anywhere, or one no literal gives, is refused.
  refused("execSync('cd /tmp && docker run --rm img');", /shell command line that mentions docker/);
  refused('spawnSync(\'cd /tmp && d""ocker run img\', { shell: true });', /mentions docker/);
  refused("spawnSync('d\"\"ocker', ['run', 'img'], { shell: true });", /mentions docker/);
  refused('exec(`${cd} && docker-compose up`);', /shell command line this check cannot read/);
  refused(
    "import { execSync as sh } from 'node:child_process';\nsh(line);",
    /cannot read \(line\)/
  );
  accepted("execSync('git status --short'); spawnSync('ls -la', { shell: true });");
  // A wrapper used other than by calling it, or exported, cannot be followed.
  const wrapperUse = /the docker wrapper docker is used other than by calling it/;
  refused(wrapper + "const d = docker;\nd('run', 'img');", wrapperUse);
  refused(wrapper + "docker.apply(null, ['run', 'img']);", wrapperUse);
  refused(
    wrapper + "const all = [['ps'], ['images']].map(args => docker.call(null, ...args));",
    wrapperUse
  );
  refused('export ' + wrapper, /docker wrapper docker is exported/);
  // Any other call naming docker first, with an array literal after it: a helper of another
  // module given docker's arguments.
  refused("run('docker', ['run', 'img']);", /docker run without/);
  refused("lib.sh(path.join(bin, 'docker'), ['create', 'img']);", /docker create without/);
  accepted(
    [
      "config.get('docker'); app.store.record('docker', [], 'unreachable');",
      "assert.deepEqual(['linux', 'docker'].map(id => status[id]), ['run', 'img']);",
    ].join('\n')
  );
  // Swarm services and a buildx (or builder, its alias) create run containers without these
  // limits, as the guard refuses them; for buildx and builder, a subcommand this check cannot
  // read could be create.
  refused(
    wrapper + "docker('builder', 'create', '--driver', 'docker-container');",
    /builder create/
  );
  refused("spawnSync('docker', ['buildx', 'create', '--name', 'b']);", /buildx create can start/);
  refused(wrapper + "docker('buildx', '--builder', 'b', 'create');", /cannot tell the subcommand/);
  refused(wrapper + "docker('builder', sub);", /cannot tell the subcommand/);
  refused(wrapper + "docker('service', 'create', 'img');", /swarm services/);
  refused(wrapper + "docker('stack', 'deploy', '-c', 'x.yaml', 's');", /swarm services/);
  accepted(wrapper + "docker('buildx', 'build', '.'); docker('builder', 'prune', '--force');");

  // Rule 5: docker named by a path, wherever a literal gives it, skips the guard (which stands in
  // for docker by name on the PATH test/setup.mjs gives), and so does docker by name in a line or
  // code a module hands to another program, which can run it on a PATH of its own: each is
  // refused unless reviewed (the verifier's probes: sh -c, env, node -e, eval, Function, a
  // Worker, fork's execPath, a line kept in a variable, a shell's stdin).
  const local = dockerAt('/usr/local/bin');
  const byPath = /^names docker by a path/;
  for (const source of [
    `spawnSync('sh', ['-c', '${local} run --rm img']);`,
    `spawnSync('/usr/bin/env', ['${local}', 'run', '--rm', 'img']);`,
    `spawnSync(process.execPath, ['-e', "require('child_process').execFileSync('${local}', ['run', '--rm', 'img'])"]);`,
    `eval("require('child_process').execFileSync('${local}', ['run', '--rm', 'img'])");`,
    `new Function("require('child_process').execFileSync('${local}', ['run'])")();`,
    `new Worker("require('child_process').execFileSync('${local}', ['run'])", { eval: true });`,
    `fork('run', ['--rm', 'img'], { execPath: '${local}', execArgv: [] });`,
    `const line = '${local} run --rm img';\nspawnSync('sh', ['-c', line]);`,
    `const real = \`${dockerAt('${bin}')}\`;`,
    `spawnSync('sh', [], { input: '${local} run --rm img' });`,
    `spawnSync('sh', ['-c', "'${dockerAt('/usr/local/bin', 'd\\\\ocker')}' run img"]);`,
    `eval("x('${dockerAt('\\\\x2fusr\\\\x2fbin', '\\\\x64ocker')}')");`,
    `const c = '${dockerAt('/usr/local/bin', 'docker-compose')}';`,
    `const d = '${['C:', 'Program Files', 'Docker', 'Docker.exe'].join('\\\\')}';`,
    "spawnSync('env', [path.join(dir, 'docker'), 'run', 'img']);",
    "const real = path.posix.resolve(bin, 'docker-compose');",
  ])
    refused(source, byPath);
  const handed =
    /^is handed to another program or to code this module runs \((\w+)\), and mentions docker/;
  for (const source of [
    "spawnSync('sh', ['-c', 'docker run --rm img'], { env: { PATH: '/usr/bin:/bin' } });",
    "spawnSync('/usr/bin/env', ['PATH=/usr/local/bin', 'docker', 'run', '--rm', 'img']);",
    "spawnSync(process.execPath, ['-e', \"require('child_process').execFileSync('docker', ['run'])\"]);",
    "spawn('sh', [], { input: 'd\"\"ocker run --rm img' });",
    "eval(\"require('child_process').execFileSync('\\\\x64ocker', ['run'])\");",
    "globalThis.eval('docker');",
    "import { fork as f } from 'node:child_process';\nf('x.mjs', ['docker']);",
    'await import(\'data:text/javascript,import("node:child_process").then(c => c.execFileSync("docker", ["run"]))\');',
    "vm.runInNewContext(\"process.mainModule.require('child_process').execSync('docker run img')\");",
    "new vm.Script(`require('child_process').execSync('docker run img')`).runInThisContext();",
    'execFileSync(process.execPath, [`--eval=${code}`, "docker"]);',
  ])
    refused(source, handed);
  // The same, reviewed: passed, and a reviewed literal that is gone is reported.
  const review = [{ file: 'x.mjs', literal: "'docker ps'", why: 'synthetic' }];
  assert.deepEqual(
    problems("spawnSync('sh', ['-c', 'docker ps']);", { file: 'x.mjs', reviewed: review }),
    []
  );
  assert.deepEqual(
    problems("spawnSync('sh', ['-c', 'ls']);", { file: 'x.mjs', reviewed: review }),
    ['listed as reviewed, but no longer found']
  );
  assert.deepEqual(
    problems("const p = path.join(bin, 'docker');", {
      file: 'x.mjs',
      reviewed: [{ file: 'x.mjs', literal: "path.join(bin, 'docker')", why: 'synthetic' }],
    }),
    []
  );
  // eval, Function, a Worker or node:vm's functions used as a value other than by calling them by
  // name could be handed code unseen: refused, as child_process's functions are.
  const runsCode = /which runs code, is used as a value other than by calling it/;
  for (const source of [
    'const run = eval;\nrun(line);',
    '(0, eval)(line);',
    'const e = globalThis.eval;',
    "import { Worker as W } from 'node:worker_threads';",
    'new (wt.Worker)(code, { eval: true });',
    'const { runInNewContext: run } = vm;',
    'helper(Function);',
  ])
    refused(source, runsCode);
  accepted(
    [
      "import { Worker } from 'node:worker_threads';",
      "const { runInNewContext } = require('node:vm');",
      'new Worker(code); runInNewContext(code); new vm.Script(code);',
      'const p = Function.prototype; const o = { eval: 1, Worker: 2 };',
    ].join('\n')
  );
  // fork under another name is followed, and used other than by calling it, refused.
  refused("import { fork } from 'node:child_process';\nconst f = fork;", notCalled);
  // Not docker by a path, nor handed on: docker by name in a literal kept apart (the guard sees it
  // run by name), a directory or a socket of that name, docker's own arguments, a program and
  // code that do not mention docker.
  accepted(
    [
      "const name = 'docker'; const tag = 'docker run --memory=4g';",
      "const dir = '/var/lib/docker/volumes'; const sock = '/var/run/docker.sock';",
      "spawnSync('docker', ['run', '--memory=1g', '--cpus=2', '--pids-limit=3', '--label', 'com.docker.x', 'i']);",
      `spawnSync('${local}', ['ps']); spawnSync(path.join(bin, 'docker'), ['ps']);`,
      "spawnSync('docker-compose', ['version']); spawnSync('sh', ['-c', 'ls -la']);",
      "spawnSync(process.execPath, ['--test', 'x.test.mjs']); fork('worker.mjs', ['a']); eval('1 + 1');",
      "new Worker(new URL('./worker.mjs', import.meta.url)); await import('./helpers/x.mjs');",
    ].join('\n')
  );

  // Files: JavaScript (by extension, or a first line `#!` that runs node) is read as code; any
  // other file, whatever its name or first line, line by line, refusing a line that mentions
  // docker in any case; a binary file is refused.
  const fileProblems = (file, content, options) =>
    checkFile(file, content, options).problems.map(p => `${p.line}: ${p.why}`);
  const notRead = /1: a file that is not JavaScript mentions docker/;
  assert.match(
    fileProblems('fake-bin/tool', '#!/bin/sh\nexec docker run --rm img\n').join(),
    /2: a file that is not JavaScript mentions docker/
  );
  assert.match(fileProblems('stand-in.sh', 'docker ps\n').join(), notRead);
  // stand-in-tar has no #! line and no .sh name: read all the same.
  assert.match(
    fileProblems('installer/stand-in-tar', 'real=$1\ndocker run --rm img\n').join(),
    /2: a file that is not JavaScript/
  );
  for (const [file, text] of [
    ['golden.sql', 'docker run img'],
    ['notes.json', `{"run": "${dockerAt('/usr/local/bin', 'Docker')} create img"}`],
    ['fake-bin/tool', '"$DOCKER" run img\n'],
    ['fake-bin/tool', 'docker run img\r\n'],
    ['fake-bin/tool', '#!/bin/sh # starts node\ndocker run img\n'],
    ['fake-bin/tool', '#!/usr/bin/nodejs\ndocker run img\n'],
  ])
    assert.match(
      fileProblems(file, text).join(),
      /a file that is not JavaScript mentions docker/,
      file + text
    );
  assert.equal(checkFile('fake-bin/tool', '#!/bin/sh # starts node\n').kind, 'text');
  assert.deepEqual(fileProblems('fake-bin/tool', '#!/bin/sh\nexec node tool.cjs "$@"\n'), []);
  assert.deepEqual(fileProblems('golden.sql', 'CREATE TABLE t (x);\n'), []);
  // A line is read as sh reads its words: quotes, backslashes and the escapes of $'…' (which bash
  // reads, macOS /bin/sh among them) do not hide docker, and a line ending in a backslash goes on
  // in the next (reported at its first line).
  for (const text of [
    "$'\\x64ocker' run --rm img",
    "$'\\144ocker' run --rm img",
    "$'\\u0064ocker' run --rm img",
    "$'\\U00000064ocker' run --rm img",
    '$\'d\\x6f\'"cker" run --rm img',
    "$'\\x64\\x6f\\x63\\x6b\\x65\\x72' run --rm img",
    'd""ocker run --rm img',
    "d''ocker run --rm img",
    '"d"ocker run --rm img',
    'd\\ocker run --rm img',
    "d$''ocker run --rm img",
    'd$""ocker run --rm img',
    'd``ocker run --rm img',
    'x=1; doc\\\nker run --rm img',
    'x=1; doc\\\r\nker run --rm img',
  ])
    assert.match(
      fileProblems('installer/stand-in-q', `real=$1\n${text}\n`).join(),
      /^2: a file that is not JavaScript mentions docker/,
      text
    );
  // A file not named as JavaScript is read line by line whatever its first line, since sh takes
  // `#!/usr/bin/env node` for a comment; read as JavaScript too, it still has its calls checked.
  const nodeFirst = checkFile('installer/stand-in-node', '#!/usr/bin/env node\ndocker run img\n');
  assert.equal(nodeFirst.kind, 'text');
  assert.deepEqual(
    nodeFirst.problems.map(p => p.line),
    [2]
  );
  assert.match(nodeFirst.problems[0].why, /^a file that is not JavaScript mentions docker/);
  assert.match(
    fileProblems(
      'fake-bin/tool',
      "#!/usr/bin/env node\nconst cp = require('child_process');\nconst run = cp.spawnSync;\n"
    ).join(),
    /cp \(child_process\) is used other than by calling/
  );
  // A reviewed line is the whole of what the backslashes join, as it reads.
  const joined = { file: 'x.Dockerfile', line: 'RUN echo \\ docker', why: '' };
  assert.deepEqual(
    fileProblems('x.Dockerfile', 'RUN echo \\\n  docker\n', { reviewed: [joined] }),
    []
  );
  assert.match(
    fileProblems('x.Dockerfile', 'RUN echo \\\n  docker \\\n  run img\n', {
      reviewed: [joined],
    }).join(),
    /^1: a file that is not JavaScript.*0: listed as reviewed, but no longer found$/
  );
  // A reviewed call of a file that is not read as JavaScript is not found.
  assert.deepEqual(
    fileProblems('fake-bin/tool', '#!/bin/sh\n', {
      reviewed: [{ file: 'fake-bin/tool', call: 'x' }],
    }),
    ['0: listed as reviewed, but no longer found']
  );
  assert.match(
    fileProblems(
      'fake-bin/tool.cjs',
      "require('child_process').spawnSync('docker', ['run', 'i']);"
    ).join(),
    /docker run without/
  );
  for (const first of [
    '#!/usr/bin/env node',
    '#!/usr/local/bin/node',
    '#!/usr/bin/env -S node --no-warnings',
  ])
    assert.match(
      fileProblems('fake-bin/tool', `${first}\nspawnSync('docker', ['run', 'i']);`).join(),
      /docker run without/,
      first
    );
  // Bytes: a NUL byte or bytes that are not UTF-8 cannot be read.
  for (const bytes of [
    Buffer.from('docker\0run'),
    Buffer.from([0x64, 0xff, 0xfe, 0x0a]),
    Buffer.from('\0'),
  ])
    assert.match(fileProblems('blob', bytes).join(), /a binary file cannot be checked/);
  assert.equal(checkFile('blob', Buffer.from('plain text\n')).kind, 'text');
  // A reviewed line passes, a reviewed line that is gone is reported, and so is one listed for a
  // file of the other kind.
  const line = { file: 'x.Dockerfile', line: 'ENV container=docker', why: '' };
  assert.deepEqual(
    fileProblems('x.Dockerfile', 'FROM debian\n  ENV container=docker\n', { reviewed: [line] }),
    []
  );
  assert.deepEqual(fileProblems('x.Dockerfile', 'FROM debian\n', { reviewed: [line] }), [
    '0: listed as reviewed, but no longer found',
  ]);
  assert.match(
    fileProblems('x.Dockerfile', 'ENV container=docker\nRUN docker ps\n', {
      reviewed: [line],
    }).join(),
    /^2: a file that is not JavaScript/
  );
  assert.deepEqual(
    fileProblems('x.mjs', 'const a = 1;\n', { reviewed: [{ ...line, file: 'x.mjs' }] }),
    ['0: listed as reviewed, but no longer found']
  );

  // The tokenizer keeps template text, substitutions and regular expressions apart.
  const tokens = tokenize('const t = `a${ {b: `c${d}`}.b }e`; const r = /[/]`/g; f(r);');
  assert.deepEqual(
    tokens.filter(token => token.type === 'tpl').map(token => token.text),
    ['ae', 'c']
  );
  assert.deepEqual(
    tokens.filter(token => token.type === 'regex').map(token => token.value),
    ['/[/]`/g']
  );
  assert.throws(() => tokenize("const s = 'open"), /unterminated string/);

  // Strings, templates and names are read as node reads them, escapes included, so an escape
  // does not hide docker, its subcommand or a limit given again (the verifier's probes).
  const runWithout = /docker (run|create) without/;
  for (const source of [
    "spawnSync('\\x64ocker', ['run', '--rm', 'img']);",
    "spawnSync('\\u0064ocker', ['run', '--rm', 'img']);",
    "spawnSync(`\\u{64}ocker`, ['create', 'img']);",
    "spawnSync('doc\\\nker', ['run', '--rm', 'img']);",
    "spawnSync('doc\\\r\nker', ['run', '--rm', 'img']);",
    "spawnSync('doc\\\u2028ker', ['run', '--rm', 'img']);",
    "spawnSync('\\144ocker', ['run', '--rm', 'img']);",
    "spawnSync('d\\o\\c\\k\\er', ['run', '--rm', 'img']);",
    wrapper + "docker('r\\x75n', '--rm', 'img');",
    wrapper + "docker('r\\\nun', '--rm', 'img');",
    wrapper + "docker('\\u{72}un', '--rm', 'img');",
    // A name written with escapes, or in letters beyond ASCII, is that name.
    "\\u0073pawnSync('docker', ['run', 'img']);",
    "sp\\u{61}wnSync('docker', ['run', 'img']);",
    "const é = (...a) => spawnSync('docker', a);\né('run', 'img');",
    // A line comment ends at any line terminator, not only \n.
    "// note\u2028spawnSync('docker', ['run', 'img']);",
    "// note\u2029spawnSync('docker', ['run', 'img']);",
    "// note\rspawnSync('docker', ['run', 'img']);",
    // A regular expression after the head of if, while, for or with; a division after i++.
    "if (x) /'/.test(y); spawnSync('docker', ['run', 'img']); // '",
    "for (;;) /`/.test(y); spawnSync('docker', ['run', 'img']); // `",
    "a++ /x;spawnSync('docker',['run','img']);x/ 1",
    "a-- /x;spawnSync('docker',['run','img']);x/ 1",
  ])
    refused(source, runWithout);
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '--m\\x65mory=0', 'img');", again);
  refused(wrapper + limits + "docker('run', ...limits, '--rm', '-\\155', '0', 'img');", again);
  // A division after a call, a regular expression after a keyword, as before.
  accepted("const half = Math.round(n) / 2 / 3; const s = '/'; return /'/.test(s);");
  // Where node may read either, or an escape node refuses: the file cannot be read, and fails.
  for (const [source, why] of [
    ["{}\n/'/.test(y); spawnSync('docker', ['run', 'img']); // '", /after \} can start a regular/],
    ["x = await /'/.exec(y); spawnSync('docker', ['run', 'img']); // '", /after await/],
    ["--> `\nspawnSync('docker', ['run', 'img']);\n// `", /HTML-like comment/],
    ["x = 1 <!-- `\nspawnSync('docker', ['run', 'img']);\n// `", /HTML-like comment/],
    ["const s = '\\x6';", /invalid \\x escape/],
    ['const s = `\\101`;', /octal escape in a template/],
    ["const s = '\\u{110000}';", /invalid \\u\{…\} escape/],
    ["sp\\x61wnSync('docker', ['run', 'img']);", /invalid escape in a name/],
    ['x \\ y', /does not read as code/],
  ]) {
    assert.throws(() => tokenize(source), why, source);
    assert.match(
      checkFile('x.cjs', source)
        .problems.map(p => `${p.line}: ${p.why}`)
        .join('\n'),
      /^\d+: this check cannot read it as JavaScript/,
      source
    );
  }
  assert.deepEqual(
    tokenize("const s = 'a\\x41\\u0042\\u{43}\\104\\0\\\n'; t\\u0061g`${1}/x`;")
      .filter(token => ['str', 'id', 'tpl'].includes(token.type))
      .map(token => token.value ?? token.tail),
    ['const', 's', 'aABCD\0', 'tag', '/x']
  );
});

test('the docker limits check reads every file of a tree, whatever its name, mode or kind', t => {
  const tree = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docker-limits-'));
  t.after(() => fs.rmSync(tree, { recursive: true, force: true }));
  const put = (file, content, mode = 0o644) => {
    fs.mkdirSync(path.dirname(path.join(tree, file)), { recursive: true });
    fs.writeFileSync(path.join(tree, file), content, { mode });
  };
  const archive = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]);
  const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
  put('fixtures/releases/a.tar.gz', archive);
  put('fixtures/releases/b.tar.gz', archive);
  // A pinned archive that a shell handed it would run docker in (its NUL bytes dropped) is read.
  const runs = Buffer.concat([archive, Buffer.from('\n\0;d\0ocker run --rm img\n')]);
  put('fixtures/releases/d.tar.gz', runs);
  // A pinned text file is read all the same.
  const script = 'docker run --rm img\n';
  put('fixtures/run.sh', script);
  // A pinned archive that is not there (a release leaves them out) is no problem for the check.
  put(
    'fixtures/SHA256SUMS',
    [
      `${sha256(archive)}  releases/a.tar.gz`,
      `${'0'.repeat(64)}  releases/b.tar.gz`,
      `${sha256(archive)}  releases/c.tar.gz`,
      `${sha256(script)}  run.sh`,
      `${sha256(runs)}  releases/d.tar.gz`,
    ].join('\n')
  );
  assert.deepEqual(
    [...fixturePins(tree).keys()],
    [
      'fixtures/releases/a.tar.gz',
      'fixtures/releases/b.tar.gz',
      'fixtures/releases/c.tar.gz',
      'fixtures/run.sh',
      'fixtures/releases/d.tar.gz',
    ]
  );
  put('installer/stand-in-tar', '# run as /bin/sh stand-in-tar\nreal=$1\ndocker run --rm img\n');
  // A file that starts as a node script, which /bin/sh runs all the same, and a docker word
  // split by quotes.
  put('installer/stand-in-node', '#!/usr/bin/env node\ndocker run --rm img\n');
  put('installer/stand-in-q', 'real=$1\nd""ocker run --rm img\n');
  // Finder's .DS_Store, by name and header, is passed over, with the file names it records
  // (docker.test.mjs, in UTF-16, after its length and before its record type); another file of
  // that name is not, nor one that a shell handed it would run docker in: dash (Debian's /bin/sh)
  // drops the NUL bytes and runs the rest (the verifier's file, and the same in UTF-16).
  const header = Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from('Bud1')]);
  const utf16 = text => Buffer.from(text, 'utf16le').swap16();
  const finder = Buffer.concat([
    header,
    Buffer.from([0, 0, 0x10, 0, 0, 0, 0, 0x08, 0, 0, 0x10]),
    Buffer.from('d\0o\0c\0k\0e\0r\0', 'latin1'),
    Buffer.from([0, 0, 0, 15]),
    utf16('docker.test.mjs'),
    Buffer.from('Ilocblob'),
    Buffer.from([0, 0, 0, 6]),
    utf16('docker'),
    Buffer.from('bwspblob'),
  ]);
  put('installer/.DS_Store', finder);
  put(
    'finder/.DS_Store',
    Buffer.concat([header, Buffer.from([0, 0, 0x10, 0, 0x0a]), Buffer.from(' docker run --rm img')])
  );
  put('finder/utf16/.DS_Store', Buffer.concat([header, Buffer.from([0x0a]), utf16('docker run')]));
  put('notes/.DS_Store', 'docker run --rm img\n');
  put('blob/.DS_Store', Buffer.concat([Buffer.from('Bud1'), Buffer.from([0, 0, 0, 1])]));
  assert.equal(isFinderFile('installer/.DS_Store', finder), true);
  assert.equal(isFinderFile('installer/DS_Store', finder), false);
  assert.equal(isFinderFile('installer/x.DS_Store', finder), false);
  put('installer/fake-bin/tool', '#!/bin/sh\nexec "$DOCKER_BIN" create img\n', 0o755);
  put('installer/data.json', '{"argv": ["docker", "run", "img"]}\n');
  put('installer/notes.txt', 'nothing to see\n');
  put('installer/x.Dockerfile', 'FROM debian\nENV container=docker\n');
  put('blob.bin', Buffer.from('docker\0run'));
  put('run.test.mjs', "spawnSync('docker', ['run', '--rm', 'img']);\n");
  // The verifier's module: docker by a path, handed to sh, env and node -e.
  const opt = dockerAt('/opt/x/bin');
  put(
    'installer/abs-probe.mjs',
    [
      "import { spawnSync } from 'node:child_process';",
      `spawnSync('sh', ['-c', '${opt} run --rm img']);`,
      `spawnSync('/usr/bin/env', ['${opt}', 'run', '--rm', 'img']);`,
      `spawnSync(process.execPath, ['-e', "require('child_process').execFileSync('${opt}', ['run'])"]);`,
      '',
    ].join('\n')
  );
  fs.symlinkSync('/usr/bin/true', path.join(tree, 'installer', 'linked'));
  const reviewed = [
    { file: 'installer/x.Dockerfile', line: 'ENV container=docker', why: 'synthetic' },
    { file: 'gone.sh', line: 'docker ps', why: 'synthetic' },
  ];
  const { read, skipped, ignored, problems } = checkTree(tree, { reviewed });
  assert.deepEqual(skipped, ['fixtures/releases/a.tar.gz'], 'only a fixture with its pinned bytes');
  assert.deepEqual(ignored, ['installer/.DS_Store'], 'only a .DS_Store with its header');
  assert.deepEqual(
    read.map(({ file, kind }) => `${file} ${kind}`),
    [
      'blob.bin binary',
      'blob/.DS_Store binary',
      'finder/.DS_Store binary',
      'finder/utf16/.DS_Store binary',
      'fixtures/SHA256SUMS text',
      'fixtures/releases/b.tar.gz binary',
      'fixtures/releases/d.tar.gz binary',
      'fixtures/run.sh text',
      'installer/abs-probe.mjs javascript',
      'installer/data.json text',
      'installer/fake-bin/tool text',
      'installer/notes.txt text',
      'installer/stand-in-node text',
      'installer/stand-in-q text',
      'installer/stand-in-tar text',
      'installer/x.Dockerfile text',
      'notes/.DS_Store text',
      'run.test.mjs javascript',
    ]
  );
  assert.deepEqual(
    problems.map(({ file, line, why }) => `${file}:${line} ${why.split(/[;,:(]/)[0]}`),
    [
      'blob.bin:0 a binary file cannot be checked for docker',
      'blob/.DS_Store:0 a binary file cannot be checked for docker',
      'finder/.DS_Store:2 a shell handed this .DS_Store file could run docker ',
      'finder/utf16/.DS_Store:2 a shell handed this .DS_Store file could run docker ',
      'fixtures/releases/b.tar.gz:0 a binary file cannot be checked for docker',
      'fixtures/releases/d.tar.gz:2 a shell handed this release archive could run docker ',
      'fixtures/run.sh:1 a file that is not JavaScript mentions docker',
      'installer/abs-probe.mjs:2 names docker by a path',
      'installer/abs-probe.mjs:3 names docker by a path',
      'installer/abs-probe.mjs:4 names docker by a path',
      'installer/data.json:1 a file that is not JavaScript mentions docker',
      'installer/fake-bin/tool:2 a file that is not JavaScript mentions docker',
      'installer/linked:0 not a regular file ',
      'installer/stand-in-node:2 a file that is not JavaScript mentions docker',
      'installer/stand-in-q:2 a file that is not JavaScript mentions docker',
      'installer/stand-in-tar:3 a file that is not JavaScript mentions docker',
      'notes/.DS_Store:1 a file that is not JavaScript mentions docker',
      'run.test.mjs:1 docker run without finite --memory',
      'gone.sh:0 listed as reviewed',
    ]
  );
});
