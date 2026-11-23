// The settings documents of the ntfy and Gotify channels (control.sqlite's settings, through
// lib/settings.mjs). Tokens and passwords are secret fields: sealed with the keyring at rest,
// never returned by view() or any route, and named in an audit diff only as set, changed or
// cleared. The ntfy topic is not a secret field (the page shows it so it can be edited), but on
// a public server whoever knows it can read the notifications, so the audit diff names it only
// as changed too (pushAuditDiff()).
import { defineSetting, validators } from '../settings.mjs';
import { MAX_PUSH_URL } from '../notify/channels/push.mjs';
import { NTFY_DEFAULT_SERVER, checkNtfy, ntfyFields } from '../notify/channels/ntfy.mjs';
import { checkGotify, gotifyFields } from '../notify/channels/gotify.mjs';

const address = validators.text(MAX_PUSH_URL);

export const ntfySettings = defineSetting({
  component: 'notify',
  key: 'ntfy',
  schema: 1,
  description: 'The ntfy notification channel: server, topic, credentials (sealed) and priorities.',
  fields: {
    enabled: { default: false, validate: validators.boolean },
    server: { default: NTFY_DEFAULT_SERVER, validate: address },
    topic: { default: '', validate: ntfyFields.topic },
    username: { default: '', validate: ntfyFields.username },
    password: { secret: true, validate: ntfyFields.password },
    token: { secret: true, validate: ntfyFields.token },
    priorityFiring: { default: 4, validate: ntfyFields.priority },
    priorityResolved: { default: 3, validate: ntfyFields.priority },
    tags: { default: [], validate: ntfyFields.tags },
    dashboardUrl: { default: '', validate: address },
    allowPlainHttp: { default: false, validate: validators.boolean },
  },
  check: checkNtfy,
});

export const gotifySettings = defineSetting({
  component: 'notify',
  key: 'gotify',
  schema: 1,
  description: 'The Gotify notification channel: server, application token (sealed), priorities.',
  fields: {
    enabled: { default: false, validate: validators.boolean },
    server: { default: '', validate: address },
    token: { secret: true, validate: gotifyFields.token },
    priorityFiring: { default: 8, validate: gotifyFields.priority },
    priorityResolved: { default: 4, validate: gotifyFields.priority },
    dashboardUrl: { default: '', validate: address },
    allowPlainHttp: { default: false, validate: validators.boolean },
  },
  check: checkGotify,
});

/** The push channels and their settings documents. */
export const PUSH_SETTINGS = Object.freeze({ ntfy: ntfySettings, gotify: gotifySettings });
export const PUSH_CHANNELS = Object.freeze(Object.keys(PUSH_SETTINGS));

// Fields whose value an audit diff never holds, besides the secret ones (lib/settings.mjs
// already gives those as {path, change}).
const AUDIT_HIDDEN = Object.freeze({ ntfy: ['topic'], gotify: [] });

/** The diff settings.update gives, as the audit row keeps it: hidden fields as "changed". */
export function pushAuditDiff(channelId, diff = []) {
  const hidden = AUDIT_HIDDEN[channelId] ?? [];
  return diff.map(entry =>
    hidden.includes(entry.path)
      ? {
          path: entry.path,
          change: !entry.from ? 'set' : !entry.to ? 'cleared' : 'changed',
        }
      : entry
  );
}
