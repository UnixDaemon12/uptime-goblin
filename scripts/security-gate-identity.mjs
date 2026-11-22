// The trusted gate identity of GATE-CONTRACT v4 C1 (a draft that has not been reviewed), and the
// one reader every consumer in this tree uses for it.
//
// The security review of v3 found that the eight-part identity reused version 2, the number of the
// seven-part form (GCV3-03). The eight-part form is version 3. Every reader here accepts only
// version 3 with exactly its eight parts, and refuses versions 1 and 2 before it reads any other
// part: there is no reader for an older version, no migration, no default version, no
// compatibility mode, and no version is inferred from the parts a record happens to hold. A
// seven-part record labelled 3, an eight-part record labelled 2 and a record with no version all
// fail. Wherever a record binds the identity by its digest, it binds the version beside it
// ({ sha256, version: 3 }), so one digest cannot be read under another schema.
//
// This tree does not compute the identity: the trusted bootstrap, the Mac-side record and the
// reviewed tool pins and runtime records it needs are pending (v4 C1, C7, C16, C20), so the
// gate's gate-identity stage is pending and the finalizer never passes it. These are the
// reader's rules for the record when one is given. Only Node's own modules are used, so the
// commit guard carries this module (scripts/install-security-hooks.mjs).
import { createHash } from 'node:crypto';
import { canonicalJson } from './security-catalog.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const show = value => JSON.stringify(value)?.slice(0, 120);

export const GATE_IDENTITY_VERSION = 3;
/** The eight parts of version 3, in canonical (sorted) order. */
export const GATE_IDENTITY_PARTS = Object.freeze([
  'catalogSha256',
  'closureSha256',
  'configSha256',
  'entrySha256',
  'runtime',
  'toolPaths',
  'toolPinsSha256',
  'version',
]);
// The versions v1 and v2 of the contract defined, which no reader here accepts.
const OLDER = Object.freeze({ 1: 'five parts', 2: 'seven parts' });
// toolPaths: the absolute path at which the guest runs each pinned tool and each Node (v4 C1, a
// proposed form): exactly these names.
export const GATE_TOOL_PATHS = Object.freeze([
  'actionlint',
  'gitleaks',
  'node24',
  'node26',
  'trivy',
]);
const RUNTIMES = ['node24', 'node26'];
const RUNTIME_PARTS = ['binarySha256', 'runtimeRecordSha256'];

const where = 'the gate identity';
const fail = message => {
  throw new Error(`${where} ${message} (v4 C1; GCV3-03)`);
};

function exact(name, value, keys) {
  if (!isObject(value)) fail(`${name} is not an object`);
  const unknown = Object.keys(value).filter(key => !keys.includes(key));
  const missing = keys.filter(key => !own(value, key));
  if (unknown.length || missing.length)
    fail(
      `${name} ${[
        ...missing.map(key => `lacks ${key}`),
        ...unknown.map(key => `has the unknown part ${show(key)}`),
      ].join(', ')}`
    );
}

const absolutePath = value =>
  typeof value === 'string' &&
  value.length <= 4096 &&
  value.startsWith('/') &&
  !/[\u0000-\u001f\u007f\\]/.test(value) &&
  !value
    .split('/')
    .slice(1)
    .some(part => part === '' || part === '.' || part === '..');

/**
 * Reads a parsed gate identity record: exactly version 3 and its eight parts, each of its form.
 * The version is judged first, and alone: 1 or 2 is refused whatever parts the record holds, and
 * anything but the number 3 is unknown. Returns a frozen copy; throws otherwise.
 */
export function parseGateIdentity(value) {
  if (!isObject(value)) fail('is not an object');
  if (!own(value, 'version'))
    fail('names no version: there is no default version, and none is inferred from its parts');
  const { version } = value;
  if (typeof version === 'number' && own(OLDER, version))
    fail(
      `is version ${version} (${OLDER[version]}), which gives no authority: only the eight-part version 3 is read, and there is no reader for an older version and no fallback`
    );
  if (version !== GATE_IDENTITY_VERSION) fail(`has the unknown version ${show(version)}`);
  exact('version 3', value, GATE_IDENTITY_PARTS);
  for (const key of [
    'catalogSha256',
    'closureSha256',
    'configSha256',
    'entrySha256',
    'toolPinsSha256',
  ])
    if (typeof value[key] !== 'string' || !HEX64.test(value[key]))
      fail(`${key} is not 64 lowercase hex digits`);
  exact('runtime', value.runtime, RUNTIMES);
  for (const runtime of RUNTIMES) {
    exact(`runtime.${runtime}`, value.runtime[runtime], RUNTIME_PARTS);
    for (const key of RUNTIME_PARTS)
      if (
        typeof value.runtime[runtime][key] !== 'string' ||
        !HEX64.test(value.runtime[runtime][key])
      )
        fail(`runtime.${runtime}.${key} is not 64 lowercase hex digits`);
  }
  exact('toolPaths', value.toolPaths, GATE_TOOL_PATHS);
  for (const tool of GATE_TOOL_PATHS)
    if (!absolutePath(value.toolPaths[tool]))
      fail(`toolPaths.${tool} is not an absolute normalised path`);
  return Object.freeze(structuredClone(value));
}

/**
 * Reads gate identity bytes: at most 64 KiB of UTF-8 that are exactly the canonical JSON of the
 * record (keys sorted at every level, no white space; so no member can be named twice), then
 * parseGateIdentity.
 */
export function parseGateIdentityBytes(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length > 64 * 1024) fail('is larger than 64 KiB');
  const source = buffer.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(buffer)) fail('is not UTF-8');
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    fail('is not JSON');
  }
  if (canonicalJson(value) !== source)
    fail('is not canonical JSON (keys sorted, no white space, no member twice)');
  return parseGateIdentity(value);
}

/** The sha256 of a gate identity record's canonical JSON, after parseGateIdentity. */
export const gateIdentitySha256 = value => sha256(canonicalJson(parseGateIdentity(value)));

/** How a record binds a gate identity: its digest with its version, { sha256, version: 3 }. */
export const gateIdentityBinding = value => ({
  sha256: gateIdentitySha256(value),
  version: GATE_IDENTITY_VERSION,
});

/**
 * Reads a binding: exactly { sha256, version } with version 3 (1 and 2 are refused, with no
 * fallback) and a sha256 of 64 lowercase hex digits. Returns a frozen copy; throws otherwise.
 */
export function parseGateIdentityBinding(value) {
  if (!isObject(value)) fail('binding is not an object');
  if (!own(value, 'version')) fail('binding names no version');
  if (typeof value.version === 'number' && own(OLDER, value.version))
    fail(`binding is version ${value.version}, which gives no authority: only version 3 is read`);
  if (value.version !== GATE_IDENTITY_VERSION)
    fail(`binding has the unknown version ${show(value.version)}`);
  exact('binding', value, ['sha256', 'version']);
  if (typeof value.sha256 !== 'string' || !HEX64.test(value.sha256))
    fail('binding sha256 is not 64 lowercase hex digits');
  return Object.freeze({ sha256: value.sha256, version: value.version });
}

/**
 * Problems with the gate-identity stage of a run, as the finalizer and the commit guard judge it:
 * a stage that carries a record (`gateIdentity`) must hold a version 3 record that binds
 * `catalogSha256`, the installed catalog's; a passing stage must carry one. Returns
 * { problems, identity, binding }: the parsed record and its binding, or null. A valid record
 * still gives no pass here: F alone compares it with the Mac-side record (v4 C1, C14).
 */
export function gateIdentityStage(stage, { catalogSha256 }) {
  if (!stage) return { problems: [], identity: null, binding: null };
  if (!own(stage, 'gateIdentity'))
    return {
      problems:
        stage.status === 'pass'
          ? ['the gate-identity stage passed without a gate identity record (v4 C1)']
          : [],
      identity: null,
      binding: null,
    };
  try {
    const identity = parseGateIdentity(stage.gateIdentity);
    if (identity.catalogSha256 !== catalogSha256)
      return {
        problems: [
          `the gate identity binds the catalog ${identity.catalogSha256}, not the installed ${catalogSha256} (v4 C1, C23)`,
        ],
        identity: null,
        binding: null,
      };
    return { problems: [], identity, binding: gateIdentityBinding(identity) };
  } catch (error) {
    return { problems: [error.message], identity: null, binding: null };
  }
}
