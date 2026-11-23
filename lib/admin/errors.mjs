// AO-2 §8.6 guard errors. Operation-specific snapshot/key/audit errors will be added with
// their services; unknown codes reject rather than becoming an arbitrary message channel.
import { ADMIN_ACTIONS, LOCK_NAMES, LOCK_TEXTS } from './actions.mjs';
import { adminUiCommand } from './commands.mjs';

const definition = (status, messages, retryAfter) =>
  Object.freeze({
    status,
    messages: Object.freeze(typeof messages === 'string' ? { default: messages } : messages),
    ...(retryAfter === undefined ? {} : { retryAfter }),
  });
export const ADMIN_ERRORS = Object.freeze({
  step_up_required: definition(403, 'Enter your Uptime Goblin password to confirm this action.'),
  step_up_failed: definition(403, 'That password is not correct, so nothing was done.'),
  step_up_unavailable: definition(403, {
    local: 'Set an Uptime Goblin password first: this action asks for it again to confirm.',
    basic:
      "This action asks for your password again, which a sign-in through HTTP Basic authentication cannot do. Sign in through Uptime Goblin's sign-in page, or use goblin-admin on the Uptime Goblin host.",
  }),
  admin_ui_locked: definition(403, {
    online:
      "This action is turned off in Uptime Goblin's web app on this server (GOBLIN_ADMIN_UI_LOCK). Run it on the Uptime Goblin host instead.",
    offline:
      "This action is turned off in Uptime Goblin's web app on this server (GOBLIN_ADMIN_UI_LOCK). On the Uptime Goblin host, stop Uptime Goblin, run the command, then start Uptime Goblin again.",
    logging: LOCK_TEXTS.logging,
  }),
  admin_busy: definition(
    409,
    'That action is already running on the Uptime Goblin host. Try again when it has finished.',
    5
  ),
});

/** Guard errors have a closed response schema. No supplied message, password, facts or command
 * is echoed. Lock commands derive exclusively from the registry and startup deployment config.
 */
export class AdminError extends Error {
  constructor(code, { variant, lock, deployment = {} } = {}) {
    if (!Object.hasOwn(ADMIN_ERRORS, code)) throw new TypeError('Unknown admin error code');
    const entry = ADMIN_ERRORS[code];
    let fields = {},
      selected = variant ?? 'default';
    if (code === 'admin_ui_locked') {
      if (!LOCK_NAMES.includes(lock)) throw new TypeError('Unknown admin lock');
      const action = ADMIN_ACTIONS.find(row => row.lock === lock);
      if (action) {
        fields = {
          lock,
          command: adminUiCommand(action.command, {
            ...deployment,
            // These are registry decisions, never an override from the caller.
            // Every locked registry action mutates audited state. Supply the server's
            // master-key file for signing, including display creation and future token/AO
            // commands; cancellation can then sign immediately instead of owing a receipt.
            key: true,
            offline: action.offline,
          }),
          stopFirst: action.offline,
        };
        selected = action.offline ? 'offline' : 'online';
      } else {
        fields = { lock, command: null, stopFirst: false };
        selected = lock;
      }
    }
    if (!Object.hasOwn(entry.messages, selected))
      throw new TypeError('Unknown admin error variant');
    super(entry.messages[selected]);
    this.name = 'AdminError';
    this.status = entry.status;
    this.code = code;
    if (entry.retryAfter !== undefined) this.retryAfter = entry.retryAfter;
    this.body = Object.freeze({ error: this.message, code, ...fields });
    Object.freeze(this);
  }
}
export const adminError = (code, options) => new AdminError(code, options);
