// AO-2 §3.4 + coordinated proxy/B6 §§5–6. Metadata only: this does not register routes,
// advertise pipeline support, or grant credentials. Keep implementation enablement separate.
const row = (
  name,
  command,
  permission,
  method,
  path,
  { stepUp = false, lock = null, audit = 'none', offline = false } = {}
) =>
  Object.freeze({
    name,
    command: Object.freeze(command),
    offline,
    permission,
    stepUp,
    lock,
    audit,
    route: Object.freeze({ method, path }),
  });

export const ADMIN_ACTIONS = Object.freeze([
  row('status', ['status'], 'system:read', 'GET', '/api/admin/status'),
  row('snapshots', ['snapshots'], 'system:read', 'GET', '/api/admin/snapshots'),
  row('snapshot-create', ['snapshot'], 'backup:manage', 'POST', '/api/admin/snapshots', {
    stepUp: true,
    audit: 'admin',
  }),
  row(
    'snapshot-delete',
    ['snapshot', 'delete', '<id>'],
    'backup:manage',
    'POST',
    '/api/admin/snapshots/delete',
    { stepUp: true, lock: 'snapshot-delete', audit: 'admin', offline: true }
  ),
  row('check-data', ['check-data'], 'system:read', 'GET', '/api/admin/check-data'),
  row('keys', ['key', 'status'], 'system:read', 'GET', '/api/admin/keys'),
  row(
    'key-remove-data-copy',
    ['key', 'remove-data-copy'],
    'keys:manage',
    'POST',
    '/api/admin/keys/remove-data-copy',
    { stepUp: true, lock: 'key-remove-data-copy', audit: 'admin' }
  ),
  row('verify-audit', ['verify-audit'], 'audit:read', 'GET', '/api/audit/verify'),
  // Canonical registry entry is the mutation. The preview derives read-only metadata below,
  // preserving the specified17 actions without pretending one route has two methods.
  row(
    'audit-accept',
    ['audit', 'accept', '<entry>', '--confirm', '<code>'],
    'audit:manage',
    'POST',
    '/api/audit/accept',
    { stepUp: true, lock: 'audit-accept', audit: 'admin', offline: true }
  ),
  row(
    'token-create',
    ['token', 'create', '--name', '<name>'],
    'tokens:manage',
    'POST',
    '/api/tokens',
    { stepUp: true, lock: 'token-create', audit: 'identity' }
  ),
  row('tokens', ['token', 'list'], 'tokens:manage', 'GET', '/api/tokens'),
  row('token-revoke', ['token', 'revoke', '<id>'], 'tokens:manage', 'DELETE', '/api/tokens/:id', {
    lock: 'token-revoke',
    audit: 'identity',
  }),
  row('token-revoke-all', ['token', 'revoke', '--all'], 'tokens:manage', 'DELETE', '/api/tokens', {
    lock: 'token-revoke-all',
    audit: 'identity',
  }),
  row(
    'display-code',
    ['display', 'code', '--name', '<name>'],
    'kiosk:manage',
    'POST',
    '/api/displays/codes',
    { stepUp: true, lock: 'display-code', audit: 'identity' }
  ),
  row('display-codes', ['display', 'list'], 'kiosk:manage', 'GET', '/api/displays/codes'),
  row(
    'display-cancel',
    ['display', 'cancel', '<id>'],
    'kiosk:manage',
    'DELETE',
    '/api/displays/codes/:id',
    { lock: 'display-cancel', audit: 'identity' }
  ),
  row(
    'display-cancel-all',
    ['display', 'cancel', '--all'],
    'kiosk:manage',
    'DELETE',
    '/api/displays/codes',
    { lock: 'display-cancel-all', audit: 'identity' }
  ),
]);
const byName = new Map(ADMIN_ACTIONS.map(action => [action.name, action]));
const get = name => {
  const action = byName.get(name);
  if (!action) throw new TypeError('Unknown admin action');
  return action;
};
export function adminRoute(name) {
  const { permission, stepUp, lock, audit } = get(name);
  return Object.freeze({ permission, stepUp, lock, audit, action: name });
}
/** Only the explicitly specified audit preview may derive read-only keys from a mutation. */
export function adminPreviewRoute(name) {
  if (name !== 'audit-accept') throw new TypeError('Unknown admin preview');
  return Object.freeze({
    permission: get(name).permission,
    stepUp: false,
    lock: null,
    audit: 'none',
    action: name,
  });
}

export const ALL_LOCKS = Object.freeze([
  'snapshot-delete',
  'audit-accept',
  'key-remove-data-copy',
  'token-create',
  'token-revoke',
  'token-revoke-all',
  'display-code',
  'display-cancel',
  'display-cancel-all',
]);
export const LOCK_NAMES = Object.freeze([...ALL_LOCKS, 'logging']);
export const LOCK_TEXTS = Object.freeze({
  logging:
    "Changing the log level in the web app is turned off on this server (GOBLIN_ADMIN_UI_LOCK). Set GOBLIN_LOG_LEVEL in Uptime Goblin's environment instead: natively in /etc/uptime-goblin.env, then sudo systemctl restart uptime-goblin; with Docker Compose in .env, then docker compose up -d.",
});

// A Set subclass still permits Set.prototype.clear.call(instance). Keep the actual Set
// private instead; only read methods are bound, and forEach never exposes its mutable target.
function lockedSet(values) {
  const target = new Set(values);
  let view;
  const refuse = () => {
    throw new TypeError('Lock setting is read-only');
  };
  view = new Proxy(target, {
    get(set, key, receiver) {
      if (['add', 'delete', 'clear'].includes(key)) return refuse;
      if (key === 'size') return set.size;
      if (key === 'forEach')
        return (callback, thisArg) => {
          if (typeof callback !== 'function') throw new TypeError('Callback must be a function');
          set.forEach(value => Reflect.apply(callback, thisArg, [value, value, view]));
        };
      if (['has', 'keys', 'values', 'entries'].includes(key) || key === Symbol.iterator)
        return Set.prototype[key].bind(set);
      return Reflect.get(set, key, receiver);
    },
  });
  return Object.freeze(view);
}
/** Pure parser, read once by future startup wiring. `all` denotes the literal all policy:
 * it excludes logging. Invalid input instead locks all10 recognized names and is invalid:true.
 */
export function lockdownSetting(value) {
  const text = typeof value === 'string' ? value : value === undefined ? '' : null;
  let names = [],
    all = false,
    invalid = false;
  if (text === null || text.length > 1024 || /[\u0000-\u001f\u007f-\u009f]/.test(text))
    invalid = true;
  else if (text === '' || text === 'none') {
  } else if (text === 'all') {
    names = ALL_LOCKS;
    all = true;
  } else if (text !== null) {
    names = text.split(',');
    invalid =
      names.some(name => !LOCK_NAMES.includes(name)) || new Set(names).size !== names.length;
  } else invalid = true;
  if (invalid) names = LOCK_NAMES;
  const printable = Array.from(
    typeof value === 'string' ? value.slice(0, 1024).replace(/[\p{Cc}\p{Cf}]/gu, '') : '<invalid>'
  )
    .slice(0, 40)
    .join('');
  const warning = invalid
    ? `GOBLIN_ADMIN_UI_LOCK must be none, all or a list of: ${LOCK_NAMES.join(', ')}; it is set to ${printable}, so every lockable action is turned off in the web app.`
    : null;
  return Object.freeze({
    locked: lockedSet([...new Set(names)].sort()),
    all,
    invalid,
    warning,
  });
}
