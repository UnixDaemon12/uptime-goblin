// orbit-admin, the name before the rename to Uptime Goblin (lib/legacy-names.mjs): it runs
// goblin-admin with the same arguments and exit status, after one line on stderr. Removed in 1.7.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { main } from './goblin-admin.mjs';

export * from './goblin-admin.mjs';

const isMain = () => {
  try {
    return (
      Boolean(process.argv[1]) &&
      fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
};
if (isMain()) {
  process.umask(0o077);
  process.stderr.write(
    'orbit-admin is deprecated: Orbit is now Uptime Goblin, and this command is lib/cli/goblin-admin.mjs (goblin-admin). This name stops working in 1.7.\n'
  );
  process.exitCode = await main(process.argv.slice(2));
}
