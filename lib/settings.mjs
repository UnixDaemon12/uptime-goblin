// Settings documents of new features (roadmap §2.6): settings(component, key, schema, value,
// version, updated_at, updated_by) in control.sqlite. config.json keeps the 1.4.2 shape; nothing
// new goes there.
//
// - A definition names its component and key, a schema number, and its fields. Each field has a
//   default, a validator, and optionally `secret: true` (sealed with the keyring at rest, never
//   returned, shown in diffs only as "changed") and `env: 'GOBLIN_…'` (the environment variable
//   locks the field: its value wins and the API cannot change it).
// - update(component, key, patch, {ifVersion, by, audit}) validates strictly (unknown fields and
//   invalid values are refused), compares and swaps on `version`, and returns an audit diff.
//   audit(tx, {diff}) is called inside the store's unit when the swap changed the document, so
//   the change and its audit row commit together (audit spec D5).
// - A stored document whose schema is newer than this release knows is read-only (409
//   settings_newer); an older one is upgraded on read through the definition's upgrade().
// - Fields the stored document has but this release does not know are kept, never dropped.
//
// Like the keyring, this module issues no SQL: lib/db/control.mjs provides the store adapter
// ({get, put, list}); memorySettingsStore() is the in-memory one.

export class SettingsError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SettingsError';
    this.code = code;
    this.status =
      {
        settings_unknown: 404,
        settings_invalid: 400,
        settings_conflict: 409,
        settings_newer: 409,
        settings_locked: 409,
        settings_keyring: 503,
      }[code] ?? 500;
    Object.assign(this, details);
  }
}

const namePattern = /^[a-z][a-zA-Z0-9_.-]{0,127}$/;
const componentPattern = /^[a-z][a-z0-9_]{0,63}$/;
// Compared, never held as values: scripts/import-graph.mjs refuses the string 'constructor'
// anywhere else (a key that reaches the Function constructor).
const reserved = name => ['__proto__', 'constructor', 'prototype'].includes(name);
const sealedKey = '$sealed';
const plain = value =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const aadOf = (component, key, field) => `settings:${component}:${key}:${field}`;
// Definitions defineSetting() produced, so createSettings() does not validate them twice.
const definitionsMade = new WeakSet();

/**
 * Declares a settings document. fields: {name: {default, validate(value) -> value (throw to
 * refuse), secret?, env?, fromEnv?(text) -> value}}. check(value) validates the whole document;
 * upgrade(value, fromSchema) turns an older stored document into this schema.
 */
export function defineSetting({
  component,
  key,
  schema = 1,
  fields,
  check,
  upgrade,
  description = '',
}) {
  if (!componentPattern.test(component ?? ''))
    throw new TypeError(`Invalid settings component ${component}`);
  if (!namePattern.test(key ?? '')) throw new TypeError(`Invalid settings key ${key}`);
  if (!Number.isSafeInteger(schema) || schema < 1)
    throw new TypeError('schema is a positive integer');
  if (!plain(fields) || !Object.keys(fields).length) throw new TypeError('A setting needs fields');
  const normalized = Object.create(null);
  for (const [name, field] of Object.entries(fields)) {
    if (reserved(name) || name === sealedKey || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(name))
      throw new TypeError(`Invalid field name ${name}`);
    if (typeof field?.validate !== 'function') throw new TypeError(`${name} needs validate()`);
    if (field.secret && field.default !== null && field.default !== undefined)
      throw new TypeError(`Secret field ${name} cannot have a default`);
    if (field.env !== undefined && !/^GOBLIN_[A-Z0-9_]+$/.test(field.env))
      throw new TypeError(`${name}: env must name a GOBLIN_ variable`);
    normalized[name] = Object.freeze({
      default: field.secret ? null : field.default,
      validate: field.validate,
      secret: field.secret === true,
      env: field.env,
      fromEnv: field.fromEnv,
    });
  }
  const definition = Object.freeze({
    component,
    key,
    schema,
    fields: Object.freeze(normalized),
    check,
    upgrade,
    description,
  });
  definitionsMade.add(definition);
  return definition;
}

/** Validators for the common field shapes. */
export const validators = Object.freeze({
  boolean: value => {
    if (typeof value !== 'boolean') throw new Error('must be true or false');
    return value;
  },
  integer: (min, max) => value => {
    if (!Number.isSafeInteger(value) || value < min || value > max)
      throw new Error(`must be a whole number from ${min} to ${max}`);
    return value;
  },
  text:
    (max, { empty = true } = {}) =>
    value => {
      if (typeof value !== 'string') throw new Error('must be text');
      const text = value.trim();
      if (!empty && !text) throw new Error('is required');
      if ([...text].length > max) throw new Error(`must be at most ${max} characters`);
      if (/[\u0000-\u001f\u007f]/.test(text))
        throw new Error('must not contain control characters');
      return text;
    },
  oneOf:
    (...choices) =>
    value => {
      if (!choices.includes(value)) throw new Error(`must be one of ${choices.join(', ')}`);
      return value;
    },
  secret:
    (max = 4096) =>
    value => {
      if (typeof value !== 'string' || !value) throw new Error('must be non-empty text');
      if (value.length > max) throw new Error(`must be at most ${max} characters`);
      return value;
    },
});

/**
 * The settings service. `store` is the adapter; `keyring` (lib/keyring.mjs, or a function
 * returning it once it is open) seals secret fields; `env` is read for locked fields at every
 * get().
 */
export function createSettings({
  store,
  definitions = [],
  env = process.env,
  keyring: keyringSource = null,
  clock = Date.now,
} = {}) {
  if (!store) throw new TypeError('createSettings needs a store');
  const keyringNow = () => (typeof keyringSource === 'function' ? keyringSource() : keyringSource);
  const defs = new Map();
  const keyOf = (component, key) => `${component}\u0000${key}`;
  function define(definition) {
    const def = definitionsMade.has(definition) ? definition : defineSetting(definition);
    const name = keyOf(def.component, def.key);
    if (defs.has(name)) throw new TypeError(`${def.component}/${def.key} is defined twice`);
    defs.set(name, def);
    return def;
  }
  for (const definition of definitions) define(definition);
  const definitionOf = (component, key) => {
    const def = defs.get(keyOf(component, key));
    if (!def)
      throw new SettingsError('settings_unknown', `There is no setting ${component}/${key}`);
    return def;
  };

  const parse = text => {
    try {
      const value = JSON.parse(text);
      return plain(value) ? value : {};
    } catch {
      return {};
    }
  };
  function open(def, field, stored) {
    const keyring = keyringNow();
    if (stored === null || stored === undefined) return { value: null };
    if (!plain(stored) || typeof stored[sealedKey] !== 'string')
      return { value: null, unreadable: true };
    if (!keyring) return { value: null, unreadable: true };
    try {
      return {
        value: keyring.openText('seal', stored[sealedKey], aadOf(def.component, def.key, field)),
      };
    } catch {
      // Only this field degrades (roadmap §2.8): it reads as unset.
      return { value: null, unreadable: true };
    }
  }
  function validateField(def, name, value) {
    try {
      return def.fields[name].validate(value);
    } catch (error) {
      throw new SettingsError(
        'settings_invalid',
        `${def.component}/${def.key}.${name} ${error.message}`,
        {
          field: name,
        }
      );
    }
  }

  // The document as stored and understood by this release: {values, extra, row, readOnly}.
  async function load(def) {
    const row = await store.get(def.component, def.key);
    const raw = row ? parse(row.value) : {};
    const readOnly = Boolean(row && row.schema > def.schema);
    let source = raw;
    if (row && row.schema < def.schema && typeof def.upgrade === 'function') {
      const upgraded = def.upgrade(structuredClone(raw), row.schema);
      source = plain(upgraded) ? upgraded : raw;
    }
    const values = Object.create(null),
      unreadable = [];
    for (const [name, field] of Object.entries(def.fields)) {
      if (field.secret) {
        const opened = open(def, name, source[name]);
        values[name] = opened.value;
        if (opened.unreadable) unreadable.push(name);
        continue;
      }
      if (!Object.hasOwn(source, name)) {
        values[name] = field.default;
        continue;
      }
      try {
        values[name] = field.validate(source[name]);
      } catch {
        // A stored value this release refuses reads as the default; it is kept until rewritten.
        values[name] = field.default;
      }
    }
    const extra = Object.fromEntries(
      Object.entries(source).filter(([name]) => !Object.hasOwn(def.fields, name))
    );
    return { values, extra, row, readOnly, unreadable, sealed: source };
  }

  function locks(def) {
    const locked = Object.create(null);
    for (const [name, field] of Object.entries(def.fields)) {
      if (!field.env) continue;
      const text = env[field.env];
      if (text === undefined || text === '') continue;
      try {
        locked[name] = field.validate(field.fromEnv ? field.fromEnv(text) : text);
      } catch (error) {
        throw new SettingsError('settings_invalid', `${field.env} ${error.message}`, {
          field: name,
          env: field.env,
        });
      }
    }
    return locked;
  }

  async function get(component, key) {
    const def = definitionOf(component, key);
    const { values, row, readOnly, unreadable } = await load(def);
    const locked = locks(def);
    return {
      component,
      key,
      schema: row?.schema ?? def.schema,
      version: row?.version ?? 0,
      value: { ...values, ...locked },
      locked: Object.keys(locked),
      readOnly,
      unreadable,
      updatedAt: row?.updated_at ?? null,
      updatedBy: row?.updated_by ?? null,
    };
  }

  // Secrets are replaced by {set: boolean}; everything else is as get() returns it.
  function publicValue(def, value) {
    const out = {};
    for (const [name, item] of Object.entries(value))
      out[name] = def.fields[name]?.secret ? { set: item !== null && item !== undefined } : item;
    return out;
  }

  return Object.freeze({
    define,
    has: (component, key) => defs.has(keyOf(component, key)),
    definitions: () => [...defs.values()],
    get,
    /** get() with secret fields shown only as {set: true|false}: safe for API responses. */
    async view(component, key) {
      const def = definitionOf(component, key);
      const current = await get(component, key);
      return { ...current, value: publicValue(def, current.value) };
    },
    /**
     * Applies `patch` (fields to change; a secret set to null clears it, also one that could
     * not be opened: its sealed value is removed, and the diff says 'cleared') when the stored
     * version equals `ifVersion` (0 for a document never saved; omit to skip the check).
     * Resolves {version, value (secrets as {set}), diff: [{field, from, to} | {field, change}]}.
     * `audit(tx, {diff})`, when given, runs inside the store's unit once the document changed,
     * with the diff in the audit's form: each `field` named `path` ({path, change} for a
     * secret, {path, from, to} otherwise). A throw from it leaves the document unchanged.
     */
    async update(component, key, patch, { ifVersion, by = null, audit = null } = {}) {
      if (audit !== null && typeof audit !== 'function')
        throw new TypeError('audit must be a function');
      const def = definitionOf(component, key);
      if (!plain(patch))
        throw new SettingsError('settings_invalid', 'The change must be an object');
      for (const name of Object.keys(patch))
        if (reserved(name) || !Object.hasOwn(def.fields, name))
          throw new SettingsError('settings_invalid', `${component}/${key} has no field ${name}`, {
            field: name,
          });
      const current = await load(def);
      const version = current.row?.version ?? 0;
      if (current.readOnly)
        throw new SettingsError(
          'settings_newer',
          `${component}/${key} was saved by a newer Uptime Goblin (schema ${current.row.schema}); this release can read it but not change it.`
        );
      if (ifVersion !== undefined && ifVersion !== version)
        throw new SettingsError(
          'settings_conflict',
          `${component}/${key} changed meanwhile (now version ${version})`,
          {
            version,
          }
        );
      const locked = locks(def);
      const next = { ...current.values },
        stored = { ...current.extra },
        diff = [];
      for (const [name, given] of Object.entries(patch)) {
        const field = def.fields[name];
        if (Object.hasOwn(locked, name)) {
          if (same(given, locked[name])) continue;
          throw new SettingsError(
            'settings_locked',
            `${field.env} sets ${component}/${key}.${name}; change it there`,
            {
              field: name,
            }
          );
        }
        const value =
          field.secret && (given === null || given === '') ? null : validateField(def, name, given);
        if (field.secret) {
          // A field that could not be opened reads as null, but clearing it removes what is
          // sealed there (below), so the diff names it too.
          const sealedAway = value === null && current.unreadable.includes(name);
          if (value === current.values[name] && !sealedAway) continue;
          diff.push({
            field: name,
            change: value === null ? 'cleared' : current.values[name] === null ? 'set' : 'changed',
          });
        } else if (!same(value, current.values[name]))
          diff.push({ field: name, from: current.values[name], to: value });
        next[name] = value;
      }
      if (typeof def.check === 'function')
        try {
          def.check({ ...next, ...locked });
        } catch (error) {
          throw new SettingsError('settings_invalid', `${component}/${key}: ${error.message}`);
        }
      for (const [name, field] of Object.entries(def.fields)) {
        if (!field.secret) {
          stored[name] = next[name];
          continue;
        }
        if (next[name] === null) {
          // A field that could not be opened stays as it is unless it was changed.
          if (current.unreadable.includes(name) && !Object.hasOwn(patch, name))
            stored[name] = current.sealed[name];
          continue;
        }
        if (next[name] === current.values[name] && current.sealed[name] !== undefined) {
          stored[name] = current.sealed[name];
          continue;
        }
        const keyring = keyringNow();
        if (!keyring)
          throw new SettingsError(
            'settings_keyring',
            'Secret settings need the keyring, which is not open'
          );
        stored[name] = {
          [sealedKey]: keyring.sealText('seal', next[name], aadOf(component, key, name)),
        };
      }
      if (!diff.length && current.row && current.row.schema === def.schema)
        return { version, value: publicValue(def, { ...next, ...locked }), diff };
      const row = {
        component,
        key,
        schema: def.schema,
        value: JSON.stringify(stored),
        version: version + 1,
        updated_at: clock(),
        updated_by: by,
      };
      const recorded = audit
        ? {
            inUnit: tx =>
              audit(tx, { diff: diff.map(({ field, ...change }) => ({ path: field, ...change })) }),
          }
        : {};
      if (!(await store.put(row, { ifVersion: version, ...recorded })))
        throw new SettingsError('settings_conflict', `${component}/${key} changed meanwhile`, {
          version: (await store.get(component, key))?.version ?? 0,
        });
      return { version: row.version, value: publicValue(def, { ...next, ...locked }), diff };
    },
  });
}

/** The settings store adapter in memory (tests and offline tools). */
export function memorySettingsStore() {
  const rows = new Map();
  const name = (component, key) => `${component}\u0000${key}`;
  return {
    async get(component, key) {
      const row = rows.get(name(component, key));
      return row ? { ...row } : undefined;
    },
    // As the control store: inUnit runs after a swap that changed the row, and a throw from it
    // puts the previous row back.
    async put(row, { ifVersion, inUnit = null }) {
      const at = name(row.component, row.key),
        current = rows.get(at);
      if ((current?.version ?? 0) !== ifVersion) return false;
      rows.set(at, { ...row });
      try {
        inUnit?.(null);
      } catch (error) {
        if (current) rows.set(at, current);
        else rows.delete(at);
        throw error;
      }
      return true;
    },
    async list(component) {
      return [...rows.values()]
        .filter(row => component === undefined || row.component === component)
        .map(row => ({ ...row }));
    },
  };
}
