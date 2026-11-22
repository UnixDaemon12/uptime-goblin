// AO-2 §8.5. Formatting only: never execute these lines. The caller supplies static registry
// argument templates and configuration captured at server start, never request body values.
import { adminLine, shellWord } from '../admin-command.mjs';
import { inContainer } from '../container.mjs';

/**
 * A copyable host-recovery line. `container`, `supervised` and `keyFile` come only from server
 * configuration; explicit container injection also makes tests independent of their host.
 * Offline is metadata for the caller's stop/start warning, not permission to stop a service.
 * Placeholders are quoted too: copying an unresolved <id> must not become shell redirection.
 */
export function adminUiCommand(
  args,
  {
    key = false,
    offline = false,
    container = inContainer(),
    supervised = false,
    keyFile = null,
  } = {}
) {
  if (
    !Array.isArray(args) ||
    args.length === 0 ||
    args.some(arg => typeof arg !== 'string' || arg.length === 0 || /[\p{Cc}\p{Cf}]/u.test(arg))
  )
    throw new TypeError('Command arguments must be nonempty printable words');
  if ([key, offline, container, supervised].some(flag => typeof flag !== 'boolean'))
    throw new TypeError('Command configuration flags must be boolean');
  if (
    keyFile !== null &&
    (typeof keyFile !== 'string' || keyFile.length === 0 || /[\p{Cc}\p{Cf}]/u.test(keyFile))
  )
    throw new TypeError('Key file must be a printable path');
  const words = args.map(shellWord).join(' ');
  if (container) {
    const prefix = offline
      ? 'docker compose run --rm --no-deps uptime-goblin'
      : 'docker compose exec uptime-goblin';
    return `${prefix} node lib/cli/goblin-admin.mjs ${words}`;
  }
  if (supervised) return adminLine(words, { key, keyFile });
  return `node --env-file-if-exists=.env lib/cli/goblin-admin.mjs ${words}`;
}
