// CI bootstrap: download exact official release archives and verify their committed SHA-256
// before extracting or executing anything. The destination is a fresh runner-temp directory;
// no privileged installation, mutable installer script, or package-manager resolution is used.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

export const securityTools = [
  {
    name: 'gitleaks',
    version: '8.30.1',
    url: 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
    sha256: '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb',
  },
  {
    name: 'trivy',
    version: '0.74.0',
    url: 'https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz',
    sha256: '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a',
  },
  {
    name: 'actionlint',
    version: '1.7.12',
    url: 'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz',
    sha256: '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',
  },
];

// Exported so the checksum-failure boundary can be tested with synthetic archives offline.
export async function installTool(tool, destination, fetcher = fetch) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-tool-download-'));
  try {
    const archive = path.join(scratch, 'tool.tar.gz');
    const response = await fetcher(tool.url, { signal: AbortSignal.timeout(300000) });
    if (!response.ok || !response.body)
      throw new Error(`${tool.name}: release download failed (${response.status})`);
    const hash = createHash('sha256');
    let bytes = 0;
    const check = new Transform({
      transform(chunk, encoding, callback) {
        bytes += chunk.length;
        if (bytes > 256 * 1024 * 1024) {
          callback(new Error(`${tool.name}: release archive exceeds the download limit`));
          return;
        }
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    await pipeline(
      Readable.fromWeb(response.body),
      check,
      fs.createWriteStream(archive, { flags: 'wx', mode: 0o600 })
    );
    if (hash.digest('hex') !== tool.sha256)
      throw new Error(`${tool.name}: release archive SHA-256 mismatch; refusing installation`);
    // Extract only the expected executable, never an archive's arbitrary paths or scripts.
    const extracted = path.join(scratch, 'extracted');
    fs.mkdirSync(extracted, { mode: 0o700 });
    execFileSync('tar', ['-xzf', archive, '-C', extracted, '--', tool.name], {
      timeout: 60000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const binary = path.join(extracted, tool.name);
    if (!fs.lstatSync(binary).isFile())
      throw new Error(`${tool.name}: release executable is not a regular file`);
    const target = path.join(destination, tool.name);
    fs.copyFileSync(binary, target, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(target, 0o755);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

async function main() {
  if (process.platform !== 'linux' || process.arch !== 'x64')
    throw new Error('The CI security-tool bootstrap supports Linux x64 only');
  const root = fs.mkdtempSync(
    path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'orbit-security-tools-')
  );
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin, { mode: 0o700 });
  try {
    for (const tool of securityTools) {
      await installTool(tool, bin);
      console.log(`Installed ${tool.name} ${tool.version} from its verified release archive`);
    }
    if (process.env.GITHUB_PATH) fs.appendFileSync(process.env.GITHUB_PATH, `${bin}\n`);
    console.log(`Security tools are available in ${bin}`);
  } catch (error) {
    fs.rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
