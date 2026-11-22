// The 1.5 gate "a boot test that no server dialect or driver is resolved" (roadmap §10.7): a child
// process records every module Node resolves while Uptime Goblin boots in SQLite mode (createApp, listen,
// close) and the SQLite dialect loads, then proves the recorder works by loading a server dialect.
import test from 'node:test';
import assert from 'node:assert/strict';
import module from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = new URL('../../', import.meta.url);
const serverOnly =
  /\/lib\/db\/dialect\/(?:postgres|mssql)\.mjs$|\/lib\/db\/(?:postgres|mssql|entra-token)\.mjs$|\/lib\/cluster\/(?!lease\.mjs)|\/lib\/series\/(?:v2\/|codec|compact|planner)|^(?:node:)?(?:postgres|tedious|oauth4webapi|@azure\/)|\/node_modules\/(?:postgres|tedious|@azure)\//;

const child = `
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { registerHooks } from 'node:module';
const resolved = [];
registerHooks({
  resolve(specifier, context, next) {
    const result = next(specifier, context);
    resolved.push(result.url);
    return result;
  },
});
const serverOnly = ${serverOnly};
const { createApp } = await import(${JSON.stringify(new URL('server.mjs', root).href)});
const { loadDialect } = await import(${JSON.stringify(new URL('lib/db/dialect/index.mjs', root).href)});
const sqlite = await loadDialect('sqlite');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-boot-'));
try {
  const app = await createApp({ directory, host: '127.0.0.1', port: 0, password: 'fixture-boot-password', allowedHosts: '',
    webhook: '', trustProxy: '', startScheduler: false });
  await app.listen();
  await app.close();
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
const atBoot = resolved.filter(url => serverOnly.test(url));
const sqliteLoaded = resolved.some(url => url.endsWith('/lib/db/dialect/sqlite.mjs'));
await loadDialect('postgres');
const afterPostgres = resolved.filter(url => serverOnly.test(url));
console.log(JSON.stringify({ atBoot, sqliteLoaded, afterPostgres, dialect: sqlite.name, count: resolved.length }));
`;

test(
  'booting in SQLite mode resolves no server dialect, driver or cluster module',
  { skip: typeof module.registerHooks !== 'function' && 'module.registerHooks is unavailable' },
  () => {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', child], {
      cwd: fileURLToPath(root),
      encoding: 'utf8',
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout.trim().split('\n').at(-1));
    assert.ok(report.count > 10, 'the recorder saw the boot');
    assert.equal(report.dialect, 'sqlite');
    assert.equal(report.sqliteLoaded, true);
    assert.deepEqual(report.atBoot, []);
    // The recorder does see a server dialect once one is asked for, so the check above is real.
    assert.equal(report.afterPostgres.length, 1);
    assert.match(report.afterPostgres[0], /\/lib\/db\/dialect\/postgres\.mjs$/);
  }
);
