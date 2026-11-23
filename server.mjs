import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { LoginThrottle, trustedProxies } from './lib/throttle.mjs';
import { publicConfig, definitions, collectorType } from './lib/catalog.mjs';
import { ConfigStore, InputError, checkConfigFile } from './lib/config.mjs';
import { acquireLock } from './lib/db/lock.mjs';
import { restoreLeftoversRemovedMessage, startControl } from './lib/db/control.mjs';
import {
  createIdentity,
  passwordRequiredMessage,
  readBuiltinSources,
} from './lib/identity/index.mjs';
import { auditLogSetting, createAudit, retentionSetting } from './lib/audit/index.mjs';
import { CLOSE_MS, MAX_ROWS } from './lib/audit/actions.mjs';
import { Store } from './lib/store.mjs';
import { CollectionError, collect, resetCollector } from './lib/collectors.mjs';
import { configureDestinations } from './lib/destinations.mjs';
import { EmailNotifier } from './lib/mail.mjs';
import { createJobRunner } from './lib/jobs.mjs';
import { createStorageGuard, RESERVE_BYTES } from './lib/storage-guard.mjs';
import { createAlerting } from './lib/alerting/service.mjs';
import { notifySettings } from './lib/alerting/settings.mjs';
import { dashboardNotifications } from './lib/alerting/view.mjs';
import { adminCommand } from './lib/admin-command.mjs';
import { json, replay } from './lib/http/body.mjs';
import { createExclusive } from './lib/http/exclusive.mjs';
import {
  applyServerLimits,
  connectionsPerClient,
  createPipeline,
  fail,
  serverOptions,
  trackConnections,
} from './lib/http/pipeline.mjs';
import { createRouter } from './lib/http/router.mjs';
import { routeTable, reservedPaths, supportedAuth, supportedFeatures } from './lib/http/routes.mjs';
import { readRelease, renderIndex, findReleasesDirectory } from './lib/http/static.mjs';
import { printable, readRegularFile, tightenMode } from './lib/saved-data.mjs';
import { notifyReady } from './lib/systemd-notify.mjs';
import {
  allowedHostList,
  dataDirectory,
  envFileWarnings,
  envFlag,
  insecureHttpSessionsSetting,
  displaySessionLimits,
  legacyBasicSetting,
  listenHost,
  listenPort,
  plainHttpWarning,
  unusedVariableWarnings,
} from './lib/environment.mjs';
import {
  limitsStatus,
  superviseLimits,
  supervision,
  unenforcedLimits,
} from './lib/resource-limits.mjs';
import {
  adoptLegacyDataMount,
  adoptLegacyEnvironment,
  legacyEnvironmentNotice,
  requestHeader,
} from './lib/legacy-names.mjs';
// server.mjs composes Uptime Goblin: the data-directory lock, the control database, identity (sign-in
// and sessions), configuration, history, the scheduler and notifications, and the HTTP
// pipeline, whose routes live in lib/http/routes/ (see lib/http/routes.mjs).
export { renderIndex };
const root = path.dirname(fileURLToPath(import.meta.url));
const noCollector = s => collectorType(s) === 'none';
const configured = s =>
  !noCollector(s) && Boolean(s.apiUrl || (collectorType(s) === 'http' && s.url));
/** `{version, build}` of the release at `appRoot` (default: this one). See readRelease(). */
export function buildInfo(appRoot = root, publicDirectory = path.join(appRoot, 'public')) {
  const { version, build } = readRelease(appRoot, publicDirectory);
  return { version, build };
}
// JavaScript's own error classes. Their messages describe Uptime Goblin's internals or quote what they
// failed on (a header value, a key, part of a response), never something to show the admin.
const builtinErrors = [RangeError, SyntaxError, ReferenceError, URIError, EvalError];
const genericCollectionError =
  'Collection failed. Check the endpoint, credentials, and source compatibility.';
// Every form in which a configured secret may appear in a message: as typed, percent-encoded (a
// query string or a path), form-encoded, and base64 (a Basic credential, or the secret alone).
function secretForms(service) {
  const forms = new Set();
  const add = value => {
    if (typeof value !== 'string' || !value) return;
    forms.add(value);
    forms.add(encodeURIComponent(value));
    forms.add(new URLSearchParams({ s: value }).toString().slice(2));
    forms.add(Buffer.from(value).toString('base64'));
  };
  add(service.apiKey);
  add(service.password);
  if (service.password) add(`${service.username ?? ''}:${service.password}`);
  // Longest first, so a short secret never splits a longer encoded form before it is matched.
  return [...forms].filter(Boolean).sort((a, b) => b.length - a.length);
}
/**
 * The text an admin sees for a failed collection. CollectionError texts are fixed and written by
 * the authors, so they pass through. Any other text that names an address or a credential fails
 * closed to a generic message, and every form of a configured secret is redacted first. A session
 * id counts in any spelling: sessionID, session ID, session-id, session_id, in any case.
 */
export function collectionError(e, service) {
  let error =
    e instanceof TypeError
      ? 'Collection failed. Check the address and credential format.'
      : builtinErrors.some(type => e instanceof type)
        ? genericCollectionError
        : String(e.message || 'Collection failed');
  for (const secret of secretForms(service)) error = error.split(secret).join('[redacted]');
  error = error.slice(0, 300);
  if (
    !(e instanceof CollectionError) &&
    /https?:\/\/|token|password|authorization|session[\s_-]*id/i.test(error)
  )
    error = genericCollectionError;
  return error;
}
const refusal = message => Object.assign(new Error(message), { refusal: true });

// Resolves `promise`, or undefined after `ms`: a stop must not hang on one stuck part.
function bounded(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise(resolve => {
      timer = setTimeout(resolve, ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * The start lines about the encryption key (delivery spec §6.7): `info`, where the key came from
 * and its fingerprint, and `warnings`, every warning about it (the key travels with copies of the
 * data directory, a key file every user can read, an unused <data>/secret.key beside another
 * source, the environment variable still visible in /proc, data keys that need a rewrap).
 * `key` is startControl()'s or createKeyring()'s ({source, file, fingerprint, warnings,
 * needsRewrap}); the key itself is never part of it, so it can never be printed.
 */
export function keyLines(key, directory) {
  const file = key.file ?? path.join(directory, 'secret.key');
  const where =
    {
      env: 'GOBLIN_SECRET_KEY',
      file: `GOBLIN_SECRET_KEY_FILE (${file})`,
      credentials: `the systemd credential (${file})`,
      secrets: `the Compose secret (${file})`,
      'data-directory': file,
      generated: `a new ${file} (generated now)`,
    }[key.source] ?? String(key.source);
  const warnings = [...(key.warnings ?? [])];
  if (key.source === 'env')
    warnings.push(
      "GOBLIN_SECRET_KEY was removed from Uptime Goblin's environment after it was read, but /proc/<pid>/environ still shows the environment Uptime Goblin started with to root and to the user Uptime Goblin runs as. Use GOBLIN_SECRET_KEY_FILE instead."
    );
  if (key.needsRewrap)
    warnings.push(
      `Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS; run, with Uptime Goblin stopped: ${adminCommand(
        'key rotate',
        // goblin-admin needs both keys in its own environment: the files this start read, if
        // any (a previous key from GOBLIN_SECRET_KEY_PREVIOUS itself keeps the placeholder).
        {
          key: true,
          previous: true,
          keyFile: key.source === 'file' ? path.resolve(file) : null,
          previousFile: key.previousFile ? path.resolve(key.previousFile) : null,
        }
      )}.`
    );
  return { info: [`Encryption key: ${where} · fingerprint ${key.fingerprint}`], warnings };
}

/**
 * The audit settings from the environment (audit spec D13, D14): `mirror` (GOBLIN_AUDIT_LOG: off,
 * the default, stdout or stdout-full), `retention` ({days, maxRows}: GOBLIN_AUDIT_RETENTION_DAYS,
 * 90 by default, held to 30-3650; at most 250,000 entries) and the start `warnings` a value
 * Uptime Goblin does not use gives. An empty value is the default, without a warning. The audit core's
 * own parsers, so there is one rule (review round 1): GOBLIN_AUDIT_LOG is one of its three values
 * exactly as D13 writes them, so `STDOUT` or ` stdout ` is another value: off, with the warning.
 */
export function auditSettings({ auditLog = '', auditRetentionDays = '' } = {}) {
  const log = auditLogSetting(auditLog);
  const retention = retentionSetting(auditRetentionDays);
  return {
    mirror: log.mirror,
    retention: { days: retention.days, maxRows: MAX_ROWS },
    warnings: [log.warning, retention.warning].filter(Boolean),
  };
}

/**
 * The security settings that come from the environment, as system.start records them (audit
 * spec D30): booleans, the trusted proxies as one normalised text (or null), the allowed hosts
 * sorted (at most 20), whether a webhook is set (never its URL, which can carry a token),
 * where the encryption key came from (never the key), how many connections one client may hold
 * open at once (`maxConnectionsPerClient`: GOBLIN_MAX_CONNECTIONS_PER_CLIENT as
 * connectionsPerClient() reads it, 32 by default; null when not given) and, only when there is
 * one, `unlimited`: the resource limits Uptime Goblin runs without because GOBLIN_ALLOW_UNLIMITED allows it
 * (lib/resource-limits.mjs). `displaySessionDays` and `displayIdleDays` are a wall display's
 * limits as Uptime Goblin applies them (displaySessionLimits(), B6 design §7.5). Each text at most 200
 * characters.
 */
export function securitySnapshot({
  legacyBasic,
  insecureHttpSessions,
  trustProxy = '',
  allowedHosts = '',
  webhook = '',
  keySource = null,
  maxConnectionsPerClient = null,
  unlimited = [],
  displaySessionDays = null,
  displayIdleDays = null,
}) {
  const text = value =>
    String(value)
      .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
      .slice(0, 200);
  const proxies = String(trustProxy ?? '')
    .split(',')
    .map(entry => entry.trim())
    .filter(Boolean);
  const hosts = [
    ...new Set(
      String(allowedHosts ?? '')
        .split(',')
        .map(host => host.trim().toLowerCase())
        .filter(Boolean)
    ),
  ]
    .sort()
    .slice(0, 20)
    .map(text);
  return {
    legacyBasic: Boolean(legacyBasic),
    insecureHttpSessions: Boolean(insecureHttpSessions),
    trustProxy: proxies.length ? text(proxies.join(',')) : null,
    allowedHosts: hosts,
    webhook: Boolean(webhook),
    keySource: keySource == null ? null : text(keySource),
    maxConnectionsPerClient: Number.isSafeInteger(maxConnectionsPerClient)
      ? maxConnectionsPerClient
      : null,
    ...(unlimited.length ? { unlimited: [...unlimited] } : {}),
    ...(Number.isSafeInteger(displaySessionDays) ? { displaySessionDays } : {}),
    ...(Number.isSafeInteger(displayIdleDays) ? { displayIdleDays } : {}),
  };
}

/** The start line after an upgrade while wall displays are signed in (B6 design §7.5). */
export const displaysAfterUpgradeMessage = count =>
  `${count === 1 ? '1 wall display is' : `${count} wall displays are`} signed in. If an earlier Uptime Goblin release ran since this one last did, it could not show or sign ${count === 1 ? 'it' : 'them'} out: check Configure → Account → Sessions.`;

/**
 * Starts Uptime Goblin's components on a data directory and resolves to the app object ({server,
 * listen(), close(), control, identity, lock, alerting, guard, jobs, …}); listen() then serves
 * it. The start sequence (sessions spec §3.1, delivery spec §6.1), each step undone when a later
 * one fails (before it, in the main block below, `node server.mjs` has made its supervision and
 * resource-limits check, after the modules loaded and the launch setup ran, and passes what it
 * found as `resourceLimits`; lib/resource-limits.mjs):
 *   0. the environment's settings (lib/environment.mjs): HOST, PORT, GOBLIN_DATA_DIR,
 *      GOBLIN_ALLOWED_HOSTS and GOBLIN_LEGACY_BASIC refuse a value that cannot work (exit 78)
 *      before anything is read or written; a flag or variable Uptime Goblin does not use is a start
 *      warning;
 *   1. destinations, the trusted proxies and each client's share of the connections
 *      (GOBLIN_MAX_CONNECTIONS_PER_CLIENT, a value that cannot work refuses: exit 78), and
 *      compose.yaml's GOBLIN_INSECURE_HTTP_SESSIONS default on a port published beyond loopback
 *      with no trusted proxy (a refusal too, exit 78);
 *   2. the admin password sources, read only (auth.json or GOBLIN_PASSWORD; an invalid one
 *      refuses as 1.4.x did); GOBLIN_PASSWORD is removed from process.env once read;
 *   3. the start guard: no start without an admin password (auth.json or GOBLIN_PASSWORD);
 *   4. goblin.lock (held by another process: LockHeldError, exit 75);
 *   5. config.json checked read-only, so a corrupt file refuses before control.sqlite, the
 *      snapshot or the password import exist;
 *  5b. the storage guard; on a disk that is already full it releases its reserve now, so the
 *      start has the space (it creates nothing yet);
 *   6. startControl() with keyring 'deferred': every refusal (exit 78), the key ones included,
 *      before any write, then the pre-upgrade snapshot, the control-database migration and
 *      created-by.json (G2 outlives a removed control.sqlite); an existing keyring is opened;
 *      GOBLIN_SECRET_KEY is read and removed from process.env here;
 *  6b. the audit log (audit spec §5.6): createAudit() over control.sqlite, and, when a keyring
 *      exists (every start but a data directory's first), attach() takes it before identity, so
 *      identity's rows are signed and chained in its own units;
 *   7. identity: imports or adopts the admin password, loads the built-in admin;
 *  7b. a missing keyring is created now (generating <data>/secret.key only when no key source
 *      exists), after identity accepted the start, so identity's refusals leave no key material;
 *      the key line and its warnings; on a first start the audit attaches now, chaining the rows
 *      identity left in its inbox;
 *   8. ConfigStore and Store (config.json, history.sqlite; readings pause while the disk is
 *      full); the audit's start rows (upgrades, snapshots, changes made while Uptime Goblin was
 *      stopped), which never fail the start;
 *  8b. the job runner and the delivery service (a storage error never fails it, D27), whose
 *      system events the audit records;
 *   9. the capability flags (GOBLIN_LEGACY_BASIC, GOBLIN_INSECURE_HTTP_SESSIONS) unless passed;
 *  10. the scheduler, the router and the pipeline, the start line, then the storage guard's
 *      reserve and check job, the audit's hourly maintenance and the delivery service's jobs.
 *      listen() records system.start once Uptime Goblin serves: a start that cannot listen records none.
 * Any failure rejects after releasing everything taken. `signal` (an AbortSignal: a stop
 * requested during the start) is checked between the steps and inside startControl(); an abort
 * rejects with the signal's reason, after releasing everything taken.
 */
export async function createApp({
  directory = process.env.GOBLIN_DATA_DIR || path.join(root, 'data'),
  host = process.env.HOST,
  // A number from a caller (tests: 0 for any free port), else PORT's text; see listenPort().
  port = process.env.PORT,
  password = process.env.GOBLIN_PASSWORD || '',
  allowedHosts = process.env.GOBLIN_ALLOWED_HOSTS || '',
  collector = collect,
  startScheduler = true,
  collectionTimeoutMs,
  webhook = process.env.GOBLIN_WEBHOOK_URL || '',
  mailTransportFactory,
  emailTimeoutMs = 20000,
  emailBatchMs = 60000,
  trustProxy = process.env.GOBLIN_TRUST_PROXY || '',
  // How many connections one client may hold open at once (see connectionsPerClient()).
  maxConnectionsPerClient = process.env.GOBLIN_MAX_CONNECTIONS_PER_CLIENT,
  loginThrottle = new LoginThrottle(),
  // Monotonic milliseconds for scheduling; tests may substitute a controllable clock.
  monotonic = () => performance.now(),
  // GOBLIN_ALLOW_LOOPBACK unless passed (a yes/no flag, see envFlag()).
  allowLoopback,
  // Where Docker Compose publishes Uptime Goblin's port (compose.yaml passes GOBLIN_BIND_ADDRESS as
  // this), for compose.yaml's GOBLIN_INSECURE_HTTP_SESSIONS default and the plain-HTTP sign-in
  // warning; natively HOST says.
  publishedAddress = process.env.GOBLIN_PUBLISHED_ADDRESS || '',
  // The web app to serve; tests start a release with a changed copy.
  publicDirectory = path.join(root, 'public'),
  // The guides /api/docs serves; tests put files that are not guides in their place.
  docsDirectory = path.join(root, 'docs'),
  // Configuration writes waiting their turn, and how long one may wait (see exclusive()).
  writeQueueLimit = 16,
  writeStartMs = 20000,
  // How long a settings response waits for pruning after lower retention is saved.
  settingsPruneMs = 20000,
  // Earlier releases kept beside this one (staged installs), whose web app files a page of
  // that release may still load from /assets/<build>/. Null when there are none.
  releasesDirectory = findReleasesDirectory(root),
  // Capability flags; by default GOBLIN_LEGACY_BASIC decides through the control database's
  // features (legacy Basic: G2), and GOBLIN_INSECURE_HTTP_SESSIONS by the rule of
  // insecureHttpSessionsSetting() with this call's publishedAddress and trustProxy.
  legacyBasic,
  insecureHttpSessions,
  // Tests only: {clock, derive, limits, log, writeAuthRecord} for createIdentity().
  identityOptions = {},
  // Tests only: a wall display's history budget ({burstMs, refillPerSecond}, see
  // lib/http/history-budget.mjs).
  historyBudget,
  // A stop requested while Uptime Goblin starts (the main block's stop signals).
  signal = null,
  // Tests only: the delivery service's seams ({clock, rng, policy, pollMs, webhookUnknown, ca,
  // lookup, wrapStore, wrapHistory}, see lib/alerting/service.mjs), and
  // `start: false` to leave its jobs unregistered.
  delivery = {},
  // Tests only: the storage guard's ({statfs, checkMs, reserveBytes, lowWater, highWater,
  // recreateBackoffMs}, see lib/storage-guard.mjs).
  storageGuard = {},
  // Tests only: where the systemd credential and the Compose secret are looked for
  // ({credentialsDirectory, secretsDirectory}, see resolveKey in lib/keyring.mjs).
  keySources,
  // The audit log's copy in Uptime Goblin's log and its retention (audit spec D13, D14).
  auditLog = process.env.GOBLIN_AUDIT_LOG || '',
  auditRetentionDays = process.env.GOBLIN_AUDIT_RETENTION_DAYS || '',
  // Tests only: the audit's seams ({clock, wrapDb, maxRows}, see lib/audit/index.mjs): its
  // clock, a wrapper of the database its own units write through, a lower row cap.
  audit: auditOptions = {},
  // What the main block found of the resource limits before the start (superviseLimits in
  // lib/resource-limits.mjs), for /api/system and the audit's start entry, shown and never set;
  // a start that is not supervised did not check them.
  resourceLimits = Object.freeze({ supervised: false }),
} = {}) {
  // 0. The environment's settings, before anything else: a refusal here leaves no file behind.
  const startWarnings = [...unusedVariableWarnings(process.env), ...envFileWarnings()];
  resourceLimits = limitsStatus(resourceLimits);
  host = listenHost(host);
  port = listenPort(port);
  // Absolute from here on: every file below it is then one path, the same for fs and for
  // node:sqlite (which reads a relative 'file:X' as a URI naming another file).
  directory = path.resolve(dataDirectory(directory, startWarnings));
  allowLoopback ??= envFlag(process.env, 'GOBLIN_ALLOW_LOOPBACK', startWarnings);
  // GOBLIN_LEGACY_BASIC: a value that is neither yes nor no refuses the start here, before
  // anything is written; legacy Basic is on by default for upgraded installs, so such a value is
  // never taken for that default (control.features reads it again, step 9).
  legacyBasicSetting(process.env.GOBLIN_LEGACY_BASIC);
  // GOBLIN_ALLOWED_HOSTS: only the entries a request's Host can match are kept; any other is a
  // start warning.
  const allowed = allowedHostList(allowedHosts);
  startWarnings.push(...allowed.warnings);
  configureDestinations({ allowLoopback });
  const trusted = trustedProxies(trustProxy);
  startWarnings.push(...(trusted?.warnings ?? []));
  // GOBLIN_INSECURE_HTTP_SESSIONS=compose-default (compose.yaml's while .env does not set it) on
  // a port Compose publishes beyond loopback with no trusted proxy: a refusal here, before
  // anything is written, never plain-HTTP sign-in turned on silently. The start takes its flag
  // from this reading unless `insecureHttpSessions` is passed (step 9).
  const plainHttpSetting = insecureHttpSessionsSetting({
    GOBLIN_INSECURE_HTTP_SESSIONS: process.env.GOBLIN_INSECURE_HTTP_SESSIONS,
    GOBLIN_PUBLISHED_ADDRESS: publishedAddress,
    GOBLIN_TRUST_PROXY: trustProxy,
  });
  if (plainHttpSetting.refusal) throw refusal(plainHttpSetting.refusal);
  // GOBLIN_DISPLAY_SESSION_DAYS and GOBLIN_DISPLAY_IDLE_DAYS: a value out of range refuses here.
  const displayLimits = displaySessionLimits(process.env);
  const perClient = connectionsPerClient(maxConnectionsPerClient);
  for (const warning of startWarnings) console.warn(warning);
  // Reads only (never creates the directory); refuses an invalid auth.json, or an invalid
  // GOBLIN_PASSWORD when there is no auth.json, as 1.4.x's PasswordAuth constructor did.
  let sources = readBuiltinSources({ directory, password });
  password = '';
  // The bootstrap password now lives in `sources` alone, until identity takes what it needs.
  // Like GOBLIN_SECRET_KEY (lib/keyring.mjs) it leaves the environment, so nothing that later
  // reads process.env (a child process, a diagnostic dump) finds it there.
  delete process.env.GOBLIN_PASSWORD;
  // Uptime Goblin always requires an admin password, whatever it listens on: without one, no start
  // (exit 78), before the lock is taken or anything is written. Nothing generates one: a native
  // install has the installer's, every other install sets GOBLIN_PASSWORD.
  if (!sources.configured) throw refusal(passwordRequiredMessage);
  const lock = acquireLock(directory);
  let control = null,
    identity = null,
    config = null,
    store = null,
    started = null,
    jobs = null,
    alerting = null,
    audit = null;
  // Undoes the steps taken so far, newest first; a failure to close one never keeps the rest
  // (or the lock) held.
  const abandon = () => {
    for (const [name, close] of [
      ['history', () => store?.close()],
      ['identity', () => identity?.close()],
      ['control database', () => control?.close()],
      // A key startControl() kept for createKeyring(), which will not run now: zeroed.
      ['encryption key', () => started?.discardKey?.()],
    ])
      try {
        close();
      } catch (error) {
        console.error(
          `Could not close the ${name} after a failed start:`,
          error.code || error.message
        );
      }
    lock.release();
  };
  try {
    checkConfigFile(directory);
    signal?.throwIfAborted();
    // 5b. The guard is told of every disk-full error from here on. Its notice goes through the
    // delivery service, which exists only from step 8b: a disk already full then is announced
    // once the service is up (below).
    const { checkMs: guardCheckMs = 10000, ...guardOptions } = storageGuard;
    const guard = createStorageGuard({
      directory,
      onChange: state => alerting?.diskChanged(state),
      ...guardOptions,
    });
    guard.atStart();
    started = await startControl(directory, {
      lock,
      keyring: 'deferred',
      settingsDefinitions: [notifySettings],
      keySources,
      // Always true here (no start gets this far without a password). startControl requires it
      // (true or false, no default) and refuses false; passed so it sees these sources.
      credentialConfigured: sources.configured,
      signal,
    });
    ({ control } = started);
    // Said once, so the operator knows where the free space came from.
    if (started.leftovers.length) console.warn(restoreLeftoversRemovedMessage(started.leftovers));
    for (const warning of started.warnings) console.warn(warning);
    signal?.throwIfAborted();
    legacyBasic ??= await control.features.enabled('legacyBasic');
    // The start's own reading (step 1), so its refusal and its flag come from the same values;
    // control.features applies the same rule to the environment for the admin list.
    insecureHttpSessions ??= plainHttpSetting.enabled;
    for (const warning of control.features.warnings) console.warn(warning);
    const plainHttp = plainHttpWarning({
      insecureHttpSessions,
      legacyBasic,
      host,
      published: publishedAddress,
      trustProxy,
      allowedHosts: allowed.hosts,
    });
    if (plainHttp) console.warn(plainHttp);
    // 6b. The audit log (audit spec §5.6). The release names this build in the start and
    // upgrade rows; a setting it does not use is said once and replaced by its default.
    const ownRelease = readRelease(root, publicDirectory);
    const { maxRows, ...auditSeams } = auditOptions;
    const settings = auditSettings({ auditLog, auditRetentionDays });
    for (const warning of settings.warnings) console.warn(warning);
    audit = createAudit({
      db: control.db,
      directory,
      release: { version: ownRelease.version, build: ownRelease.build },
      mirror: settings.mirror,
      retention: { ...settings.retention, ...(maxRows === undefined ? {} : { maxRows }) },
      guard,
      ...auditSeams,
    });
    // Every start but a data directory's first has a keyring: the audit takes it before
    // identity starts, so identity's rows (a restore's sign-out, an imported password) are
    // signed and chained in identity's own units. attach() never rejects.
    let attached = false;
    if (started.keyring) {
      await audit.attach({
        keyring: started.keyring,
        instanceId: await control.meta.instanceId(),
      });
      attached = true;
    }
    signal?.throwIfAborted();
    // Identity ends the sessions signed in over plain HTTP when the opt-in was removed.
    identity = await createIdentity({
      control,
      directory,
      sources,
      insecureHttpSessions,
      displayLimits,
      audit,
      ...identityOptions,
    });
    // Identity holds what it needs; the plain GOBLIN_PASSWORD is not kept here.
    sources = null;
    // A release that ran in between could neither show nor sign out wall displays (B6 design
    // §7.5, R2A-7): said once, at the start that records this release.
    if (started.migration?.upgraded) {
      const displays = await identity.signedInDisplays();
      if (displays) console.warn(displaysAfterUpgradeMessage(displays));
    }
    signal?.throwIfAborted();
    // 7b. Identity accepted the start: only now may a key be generated and a keyring created
    // (delivery spec D6), so no refusal before this leaves a keyring or a generated secret.key
    // behind (by then step 4 has taken goblin.lock, and step 6 may have written the pre-upgrade
    // snapshot, the migration and created-by.json).
    let { keyring, key } = started;
    if (!keyring) ({ keyring, key } = await started.createKeyring());
    // A data directory's first start: identity's rows waited in the audit inbox (no key
    // existed); attaching now chains them, signed, before anything else is recorded (D8).
    if (!attached) await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
    const keyLog = keyLines(key, directory);
    for (const line of keyLog.info) console.log(line);
    for (const warning of keyLog.warnings) console.warn(warning);
    // Where the key came from, for /api/system: never the key, nor the previous key's bytes, and
    // the data directory as <data>, as no diagnostic answer names that server path.
    const dataPaths = [...new Set([directory, fs.realpathSync(directory)])].filter(
      data => path.isAbsolute(data) && data.length > 1
    );
    const hideData = text =>
      typeof text === 'string'
        ? dataPaths.reduce((value, data) => value.split(data).join('<data>'), text)
        : text;
    const keyStatus = Object.freeze({
      source: key.source,
      file: hideData(key.file ?? null),
      fingerprint: key.fingerprint,
      previous:
        typeof key.previous === 'string' && /^[0-9a-f]{16}$/.test(key.previous)
          ? key.previous
          : Boolean(key.previous),
      needsRewrap: Boolean(key.needsRewrap),
      warnings: Object.freeze(keyLog.warnings.map(hideData)),
    });
    signal?.throwIfAborted();
    config = new ConfigStore(directory);
    // A full disk pauses the saving of readings (alerts are still evaluated): readings would
    // take the space sign-in and delivery need (D14).
    store = new Store(directory, { pauseReadings: () => guard.state().full });
    signal?.throwIfAborted();
    // 8. What happened while Uptime Goblin was stopped (audit spec §5.6): the releases that opened the
    // data, the snapshots taken, a config.json or password changed outside Uptime Goblin. Each row
    // moves its own marker in its own unit; none of this ever fails the start.
    await audit.start({ config, passwordChangedAt: identity.metadata().passwordChangedAt });
    signal?.throwIfAborted();
    // 8b. Job status goes to control.sqlite's jobs table, at most once per 5 minutes per job
    // unless its outcome changed (D20); a write the full disk refuses tells the guard.
    jobs = createJobRunner({
      statusSink: status => {
        // Stopping: control.sqlite is about to close, and nothing reads the last status.
        if (jobs.stopped) return;
        return Promise.resolve()
          .then(() => control.jobs.record(status))
          .catch(error => {
            guard.noteWriteError(error);
            throw error;
          });
      },
      statusMinIntervalMs: 300000,
    });
    const { start: startDelivery = true, ...deliveryOptions } = delivery;
    alerting = await createAlerting({
      control,
      keyring,
      history: store,
      config,
      jobs,
      webhook,
      mailTransportFactory,
      emailTimeoutMs,
      emailBatchMs,
      restored: identity.status().restoredAtStart,
      onStorageError: error => guard.noteWriteError(error),
      // Delivery's own system events (a new signing key, a paused channel, notifications
      // kept in memory) become system rows; the records of a person's action are left to the
      // route that recorded it (audit spec D24).
      onEvent: record => audit.fromDelivery(record),
      ...deliveryOptions,
    });
    // The disk filled before the service existed (step 5b, or a write since): its notice now,
    // or, when an earlier run left a disk episode open, that episode goes on (A40).
    if (guard.state().full) alerting.diskChanged(guard.state());
    signal?.throwIfAborted();
    return composeApp({
      directory,
      host,
      port,
      allowedHosts: allowed.hosts.join(','),
      collector,
      startScheduler,
      collectionTimeoutMs,
      webhook,
      mailTransportFactory,
      emailTimeoutMs,
      loginThrottle,
      monotonic,
      publicDirectory,
      docsDirectory,
      writeQueueLimit,
      writeStartMs,
      settingsPruneMs,
      releasesDirectory,
      historyBudget,
      trusted,
      perClient,
      lock,
      control,
      identity,
      config,
      store,
      legacyBasic,
      insecureHttpSessions,
      guard,
      guardCheckMs,
      reserveBytes: guardOptions.reserveBytes ?? RESERVE_BYTES,
      jobs,
      alerting,
      startDelivery,
      keyStatus,
      resourceLimits,
      audit,
      ownRelease,
      security: securitySnapshot({
        legacyBasic,
        insecureHttpSessions,
        trustProxy,
        allowedHosts,
        webhook,
        keySource: key.source,
        maxConnectionsPerClient: perClient,
        unlimited: unenforcedLimits(resourceLimits),
        displaySessionDays: displayLimits.absoluteMs / 86400e3,
        displayIdleDays: displayLimits.idleMs / 86400e3,
      }),
    });
  } catch (error) {
    // The delivery service and the job runner first (their timers and the email channel's
    // connections), then the audit's own writes, the stores and the lock. None may keep the
    // failure from being reported, nor the lock held.
    await bounded(
      Promise.resolve()
        .then(() => alerting?.stop({ timeoutMs: 2000 }))
        .catch(() => {}),
      7000
    );
    await bounded(
      Promise.resolve()
        .then(() => jobs?.stop({ timeoutMs: 2000 }))
        .catch(() => {}),
      3000
    );
    // No system.stop for a start that never served (none was started); what waits is written
    // or goes to stderr. Bounded like the stop.
    await bounded(
      Promise.resolve()
        .then(() => audit?.close())
        .catch(() => {}),
      CLOSE_MS + 500
    );
    abandon();
    throw error;
  }
}

// The app over the stores and services createApp() opened: the scheduler, the router and the
// pipeline, and the start of the storage guard and the delivery service. Returns the app
// object; its close() releases what createApp() took.
function composeApp({
  directory,
  host,
  port,
  allowedHosts,
  collector,
  startScheduler,
  collectionTimeoutMs,
  webhook,
  mailTransportFactory,
  emailTimeoutMs,
  loginThrottle,
  monotonic,
  publicDirectory,
  docsDirectory,
  writeQueueLimit,
  writeStartMs,
  settingsPruneMs,
  releasesDirectory,
  historyBudget,
  trusted,
  perClient,
  lock,
  control,
  identity,
  config,
  store,
  legacyBasic,
  insecureHttpSessions,
  guard,
  guardCheckMs,
  reserveBytes,
  jobs,
  alerting,
  startDelivery,
  keyStatus,
  resourceLimits,
  audit,
  ownRelease,
  security,
}) {
  const inflight = new Map(),
    due = new Map(),
    connectionTests = new Map();
  let closing = null,
    closed = false,
    lastPruned = null;
  // Scheduling and rate limits use a monotonic clock, so a system clock step (NTP, a
  // snapshot restore, a manual fix) cannot pause polling or pin a cooldown.
  const mono = monotonic;
  const startedAt = Date.now();
  // Computed once, at the start: the files were read then, so what is served always matches
  // the build the audit's start rows name.
  const { version, build, publicFiles } = ownRelease;
  const indexPage = Buffer.from(
    renderIndex(publicFiles.get('/index.html')?.toString('utf8') ?? '', build)
  );
  // Proves to the installer that the process answering is the one it started (run/status.json).
  const nonce = randomBytes(16).toString('hex'),
    runDirectory = path.join(directory, 'run'),
    statusFile = path.join(runDirectory, 'status.json');
  let status = null;
  function writeStatus() {
    const temporary = path.join(runDirectory, `.status-${process.pid}-${randomUUID()}.tmp`);
    try {
      fs.mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
      tightenMode(runDirectory, 0o700);
      fs.writeFileSync(temporary, JSON.stringify(status, null, 2) + '\n', {
        mode: 0o600,
        flag: 'wx',
      });
      fs.renameSync(temporary, statusFile);
    } catch (e) {
      fs.rmSync(temporary, { force: true });
      console.error('Could not write run/status.json:', e.code || e.message);
    }
  }
  function removeStatus() {
    if (!status) return;
    try {
      // Only this process's own file: another start may have replaced it meanwhile. Read as
      // goblin-admin reads it (never through a link, never waiting for a FIFO, at most 64 KiB),
      // so nothing put in its place can hold the stop.
      const bytes = readRegularFile(statusFile, { limit: 64 * 1024, follow: false });
      if (bytes && JSON.parse(bytes.toString('utf8')).nonce === nonce) fs.rmSync(statusFile);
    } catch {}
  }
  // The protocol nginx reports, recorded so the next release can check the proxy setup.
  function observeProxy(req) {
    if (!status || !trusted || !trusted(req.socket?.remoteAddress)) return;
    const forwarded = req.headers['x-forwarded-proto'],
      legacy = /(?:^|[;,\s])proto=["']?(https?)\b/i.exec(String(req.headers.forwarded ?? ''));
    if (forwarded === undefined && !legacy && req.headers['x-forwarded-for'] === undefined) return;
    const value = (
      typeof forwarded === 'string' ? forwarded.split(',')[0] : legacy ? legacy[1] : 'http'
    )
      .trim()
      .toLowerCase();
    if (!['http', 'https'].includes(value) || status.observed.forwardedProto === value) return;
    status.observed.forwardedProto = value;
    writeStatus();
  }
  // Which web app builds have polled in the last 10 minutes ("Open tabs by version").
  // Tabs from before 1.4.3 send no build; they are listed together.
  const clientBuilds = new Map();
  function noteClient(req, url) {
    if (req.method !== 'GET' || !['/api/dashboard', '/api/version'].includes(url.pathname)) return;
    const header = requestHeader(req.headers, 'Client'),
      match = /^web\/([0-9a-f]{6,64})$/.exec(header ?? '');
    const key = match ? match[1] : header === undefined ? 'legacy' : null;
    if (!key) return;
    clientBuilds.delete(key);
    clientBuilds.set(key, Date.now());
    for (const [old, seen] of clientBuilds)
      if (clientBuilds.size > 32 || Date.now() - seen > 600000) clientBuilds.delete(old);
  }
  const openClients = () =>
    [...clientBuilds]
      .filter(([, seen]) => Date.now() - seen <= 600000)
      .map(([key, lastSeen]) => ({
        build: key === 'legacy' ? null : key,
        current: key === build,
        lastSeen,
      }))
      .reverse();
  // Idempotency-Key: the outcome of each keyed write is kept for 10 minutes, so a browser
  // that lost the answer (a timeout, a dropped connection) can retry without doing it twice.
  // A retry that arrives while the first attempt still runs waits for it. Memory only: a
  // retry across a restart relies on If-Match instead. The pipeline calls this for writes
  // carrying the header; `scope` names the principal (access.scope: the user and its epoch,
  // D22), method and path, so a retry sent after signing in again (a new session) joins or
  // replays its first attempt instead of running twice. `access` is the request's credential,
  // rechecked before a retry runs or is answered from a reply. (A later wave replaces this
  // with lib/http/idempotency.mjs and its control-database store.)
  const replies = new Map(),
    // Bodies are compared by a keyed digest, so memory never holds a plain hash of them.
    replyKey = randomBytes(32);
  let replyBytes = 0;
  function forgetReplies() {
    const now = mono();
    for (const [scope, entry] of replies) {
      if (!entry.response) continue;
      if (entry.expires > now && replies.size <= 1000 && replyBytes <= 4 * 1024 * 1024) continue;
      replies.delete(scope);
      replyBytes -= entry.response.body.length;
    }
  }
  async function idempotent(req, res, { key: header, scope: target, body, access }, run) {
    const key = String(header);
    if (!/^[\w-]{8,128}$/.test(key))
      throw new InputError('Idempotency-Key must be 8-128 letters, digits, hyphens or underscores');
    const digest = createHmac('sha256', replyKey).update(body).digest('hex'),
      scope = [...(Array.isArray(target) ? target : [target]), key].join('\n');
    for (;;) {
      // The body or an earlier request may have kept this retry waiting across a sign-out,
      // a revocation or a password change. Recheck before running it or exposing a reply.
      identity.assertCurrent(access);
      forgetReplies();
      const entry = replies.get(scope);
      if (!entry) break;
      if (entry.digest !== digest) {
        json(res, 422, { error: 'This Idempotency-Key was already used for a different request.' });
        return;
      }
      if (entry.response) {
        replay(res, entry.response);
        return;
      }
      await entry.settled;
    }
    let settle;
    const entry = { digest, response: null, settled: new Promise(resolve => (settle = resolve)) };
    replies.set(scope, entry);
    try {
      await run();
    } catch (e) {
      fail(res, e);
    } finally {
      // Refusals that applied nothing (signed out, forbidden, busy, rate limited) are not kept:
      // a retry, for example after signing in again, must run or join, never replay a refusal.
      // A write applied before its session ended is answered 401 too, but what is kept is the
      // outcome its handler recorded with committed(), so the retry after signing in again
      // replays it instead of applying the write twice (a second Replace signing key would end
      // the 24 hours of the key replaced first; delivery spec A62). The loop above rechecks the
      // retry's own credential before replaying: an ended session never receives it.
      const response = res.orbitCommitted ?? res.orbitResponse;
      if (
        response &&
        ![401, 403, 429, 503].includes(response.status) &&
        response.body.length <= 65536
      ) {
        entry.response = response;
        entry.expires = mono() + 10 * 60 * 1000;
        replyBytes += response.body.length;
      } else replies.delete(scope);
      settle();
      forgetReplies();
    }
  }
  const interval = s => s.pollSeconds || config.value.pollSeconds;
  const monitoring = s => ({ ...config.value.monitoring, ...s?.monitoring });
  const timeoutMs = s => collectionTimeoutMs ?? monitoring(s).timeoutSeconds * 1000;
  // Test emails only (POST /api/email/test stays synchronous, D13); alerts go through the
  // delivery service's email channel.
  const email = new EmailNotifier({
    getSettings: () => config.value.email,
    transportFactory: mailTransportFactory,
    timeoutMs: emailTimeoutMs,
  });
  const configuredHosts = new Set(
    allowedHosts
      .split(',')
      .map(h => h.trim().toLowerCase())
      .filter(Boolean)
  );
  const allowedHost = value => {
    if (!value) return false;
    if (configuredHosts.has(value.toLowerCase())) return true;
    const currentPort = server.address()?.port || port;
    return [
      `127.0.0.1:${currentPort}`,
      `localhost:${currentPort}`,
      `[::1]:${currentPort}`,
    ].includes(value.toLowerCase());
  };
  // Notifications (delivery spec §6.2): alert changes are saved with their history event and
  // relayed to the delivery service's outbox, which sends, retries and records them (1.4.2's
  // switches, webhook body and email digest are the service's). Uptime Goblin's own notices and the
  // fallback events of a failed history write have no history row and are queued directly (the
  // history notice through alerting.storageChanged, which pairs it with its recovery). Queueing
  // never fails the caller: a notice that cannot be queued is logged.
  const queueFailed = error =>
    console.error(
      'An alert notification could not be queued for delivery:',
      error?.code || error?.name || 'error'
    );
  // Race the whole attempt against cancellation, including collectors that stop responding.
  function attempt(run, signal) {
    return new Promise((resolve, reject) => {
      const cancel = () => {
        signal.removeEventListener('abort', cancel);
        reject(signal.reason);
      };
      if (signal.aborted) {
        cancel();
        return;
      }
      signal.addEventListener('abort', cancel, { once: true });
      Promise.resolve()
        .then(() => {
          signal.throwIfAborted();
          return run();
        })
        .then(
          value => {
            signal.removeEventListener('abort', cancel);
            resolve(value);
          },
          error => {
            signal.removeEventListener('abort', cancel);
            reject(error);
          }
        );
    });
  }
  async function collectLogical(service, signal) {
    const options = monitoring(service),
      sessionRefreshBudget = { remaining: 1 },
      deadline = new AbortController(),
      // Abort in the next check phase, so a result that has already arrived beats a timer
      // that expired while the event loop was busy.
      timeout = setTimeout(() => setImmediate(() => deadline.abort()), timeoutMs(service)),
      combined = AbortSignal.any([signal, deadline.signal]);
    try {
      for (let index = 0; ; index++) {
        combined.throwIfAborted();
        const controller = new AbortController(),
          attemptSignal = AbortSignal.any([combined, controller.signal]);
        let failure;
        try {
          return await attempt(
            () =>
              collector({
                ...service,
                apiUrl: service.apiUrl || service.url,
                type: collectorType(service),
                signal: attemptSignal,
                sessionRefreshBudget,
                // Each request may use a quarter of the collection deadline (12-25 s), so a
                // slow but working source is not failed by a fixed short limit. Opening the
                // connection itself is limited to about 10 s by fetch, whatever this value.
                requestTimeoutMs: Math.min(25000, Math.max(12000, timeoutMs(service) / 4)),
              }),
            attemptSignal
          );
        } catch (error) {
          combined.throwIfAborted();
          if (error.retryable !== true || index >= options.retryCount) throw error;
          failure = error;
        } finally {
          controller.abort();
        }
        // Only transient failures reach this wait. The same total deadline covers every attempt.
        if (failure) await delay(options.retryDelaySeconds * 1000, undefined, { signal: combined });
      }
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      if (deadline.signal.aborted)
        throw new Error(
          'Collection exceeded its time limit. Try fewer devices or a more focused source.'
        );
      throw error;
    } finally {
      clearTimeout(timeout);
      deadline.abort();
    }
  }
  // Presentation and notification edits (name, group, colour, visibility, notification
  // overrides, rules) must not restart collection, so polls compare only these fields.
  const collectionFields = [
    'type',
    'collector',
    'apiUrl',
    'apiKey',
    'username',
    'password',
    'siteId',
    'nodeName',
    'metricPath',
    'httpMethod',
    'httpExpectedStatus',
    'metrics',
    'pollSeconds',
    'enabled',
  ];
  // Of the monitoring settings, only these change how a collection runs; the rest tune alerts.
  const collectionMonitoring = ['timeoutSeconds', 'retryCount', 'retryDelaySeconds'];
  const collectionKey = s =>
    s
      ? JSON.stringify([
          ...collectionFields.map(key => s[key]),
          collectionMonitoring.map(key => s.monitoring?.[key]),
          collectorType(s) === 'http' && !s.apiUrl ? s.url : '',
        ])
      : '';
  // One full collection cycle for a source, allowing for every enabled source sharing the
  // worker slots. Queueing within this is not a gap in monitoring.
  const cycleSeconds = s => {
    // The slowest active source sets how long a worker can be tied up.
    const active = config.value.services.filter(x => x.enabled && configured(x)),
      slowest = Math.max(timeoutMs(s), ...active.map(timeoutMs)) / 1000;
    return (
      interval(s) +
      Math.ceil(Math.max(1, active.length) / config.value.monitoring.concurrency) * slowest
    );
  };
  // Storage health: one notification when history writes start failing, and one when every
  // source whose write failed has written again and five quiet minutes (3+ writes) passed. The
  // delivery service sends both under the outage's since and keeps an outage open across a stop
  // (A40): one that an earlier run announced and did not see end is "carried". It ends by the
  // same rule (three writes and five quiet minutes from this run's first write), and the
  // dashboard does not show it, since no write of this run failed; a write that fails takes it
  // on, under its since and without a second notice.
  let storageFailure = null;
  function storageFailed(error, id) {
    const code = error?.errcode ?? error?.code ?? error?.name ?? 'unknown';
    console.error('History database write failed:', code, error?.errstr || '');
    if (storageFailure) {
      storageFailure.lastFailure = mono();
      storageFailure.successes = 0;
      if (id) storageFailure.pending.add(id);
      if (storageFailure.carried) {
        storageFailure.carried = false;
        storageFailure.code = String(code);
        alerting.storageChanged({ failing: true, since: storageFailure.since });
      }
      return;
    }
    const since = alerting.storageCarried() ?? Date.now();
    storageFailure = {
      since,
      lastFailure: mono(),
      successes: 0,
      code: String(code),
      alerted: new Set(),
      pending: new Set(id ? [id] : []),
    };
    // One delivery id per outage, so the notice is sent once however often it is queued.
    alerting.storageChanged({ failing: true, since });
  }
  const shownStorageFailure = () => (storageFailure?.carried ? null : storageFailure);
  function storageRecovered(id) {
    if (!storageFailure) {
      const carried = alerting.storageCarried();
      if (carried === null) return;
      storageFailure = {
        since: carried,
        carried: true,
        lastFailure: mono(),
        successes: 0,
        code: null,
        alerted: new Set(),
        pending: new Set(),
      };
    }
    storageFailure.successes++;
    storageFailure.pending.delete(id);
    // A source deleted, paused or unconfigured since its write failed will not write again.
    for (const pendingId of storageFailure.pending) {
      const source = config.get(pendingId);
      if (!source?.enabled || !configured(source)) storageFailure.pending.delete(pendingId);
    }
    if (
      storageFailure.pending.size ||
      storageFailure.successes < 3 ||
      mono() - storageFailure.lastFailure < 5 * 60 * 1000
    )
      return;
    // The service names the recovery with the outage's since, so the two pair up for the
    // receiver.
    storageFailure = null;
    alerting.storageChanged({ failing: false });
  }
  async function poll(service) {
    const version = collectionKey(service);
    if (
      closed ||
      inflight.has(service.id) ||
      !service.enabled ||
      !configured(service) ||
      collectionKey(config.get(service.id)) !== version
    )
      return;
    const controller = new AbortController();
    inflight.set(service.id, controller);
    let metrics = [],
      error = null;
    try {
      try {
        metrics = await collectLogical(service, controller.signal);
      } catch (e) {
        error = collectionError(e, service);
      }
      const current = config.get(service.id);
      if (
        closed ||
        controller.signal.aborted ||
        !current?.enabled ||
        collectionKey(current) !== version
      )
        return;
      const time = Date.now(),
        options = monitoring(current);
      // A failed history write must not stop alerting: alerts matter most when the
      // disk is full.
      try {
        // Collectors attach notes (readings a limit left out) to the array they return. A
        // reading the storage guard paused (a full disk) was not written, so it does not count
        // towards "Uptime Goblin can write its history database again" (§4.2: pausing never touches the
        // storage notice): that notice waits for readings that are saved.
        const written = store.record(service.id, metrics, error, time, error ? [] : metrics.notes);
        if (written !== false) storageRecovered(service.id);
      } catch (e) {
        storageFailed(e, service.id);
      }
      if (config.value.alerts.enabled) {
        let events = [],
          fallback = null;
        try {
          events = store.evaluate(
            {
              ...current,
              ...options,
              pollSeconds: interval(current),
              collectionTimeoutSeconds: timeoutMs(current) / 1000,
              staleAfterMs: cycleSeconds(current) * 3000,
            },
            metrics,
            error,
            time
          );
        } catch (e) {
          storageFailed(e);
          // Without alert state, still report a failed check (once per source per
          // storage outage) so an outage is not silent. It has no history row, so its
          // delivery id names the source and the outage instead.
          if (error && storageFailure && !storageFailure.alerted.has(current.id)) {
            storageFailure.alerted.add(current.id);
            fallback = {
              event: {
                service: current.id,
                name: current.name,
                kind: 'firing',
                category: 'availability',
                rule: '__availability',
                message: error
                  ? `Source is unavailable: ${String(error).slice(0, 300)}`
                  : 'Source is unavailable',
                time,
              },
              uid: `fb:${current.id}:${storageFailure.since}`,
            };
          }
        }
        // The relay's fast path (D2), awaited so the rows of one alert enter the outbox in the
        // order the alert changed; the history rows are saved already, so anything this misses
        // is relayed by the sweep. A failure never stops the poll.
        try {
          if (events.length) await alerting.transitions(events);
          if (fallback) await alerting.enqueueDirect(fallback.event, fallback.uid);
        } catch (e) {
          queueFailed(e);
        }
      }
    } finally {
      // Only this poll's own entry: a source being deleted holds a placeholder meanwhile.
      if (inflight.get(service.id) === controller) inflight.delete(service.id);
      if (!config.get(service.id)) due.delete(service.id);
      else
        due.set(
          service.id,
          !controller.signal.aborted && collectionKey(config.get(service.id)) === version
            ? mono() + interval(service) * 1000
            : 0
        );
    }
  }
  async function tick(force = false) {
    if (closed) return;
    const now = mono(),
      capacity = Math.max(0, config.value.monitoring.concurrency - inflight.size);
    const queue = config.value.services
      .filter(
        s =>
          s.enabled &&
          configured(s) &&
          !inflight.has(s.id) &&
          (force || !due.has(s.id) || due.get(s.id) <= now)
      )
      .sort((a, b) => (due.get(a.id) || 0) - (due.get(b.id) || 0));
    // Separate ticks may fill free slots while another source is still waiting.
    const workers = Array.from({ length: Math.min(capacity, queue.length) }, async () => {
      while (queue.length && !closed) {
        if (inflight.size >= config.value.monitoring.concurrency) return;
        const next = queue.shift();
        if (inflight.has(next.id) || (!force && due.get(next.id) > mono())) continue;
        await poll(next);
      }
    });
    await Promise.all(workers);
    if (!closed && (lastPruned === null || now - lastPruned > 3600000)) {
      lastPruned = now;
      try {
        const days = config.value.retentionDays;
        await store.prune(days, undefined, {
          shouldContinue: () => config.value.retentionDays <= days,
        });
      } catch (e) {
        storageFailed(e);
      }
    }
  }
  function dashboard() {
    const states = config.value.services.map(s => {
      const latest = store.latest(s.id);
      const status = !s.enabled
        ? 'disabled'
        : noCollector(s)
          ? 'link'
          : !configured(s)
            ? 'unconfigured'
            : latest.error
              ? latest.lastSuccess
                ? 'stale'
                : 'error'
              : !latest.lastSuccess
                ? 'collecting'
                : Date.now() - latest.lastSuccess > cycleSeconds(s) * 2000
                  ? 'stale'
                  : 'live';
      return {
        ...latest,
        // Collector notes of the latest successful collection, e.g. a capped library.
        notes: Array.isArray(latest.notes) ? latest.notes : [],
        status,
        collecting: inflight.has(s.id),
        configured: configured(s),
        collector: collectorType(s),
      };
    });
    const active = new Set(
      config.value.services.filter(s => s.enabled && configured(s)).map(s => s.id)
    );
    const alerts = store
      .alerts()
      .filter(a => active.has(a.service))
      .map(a => ({ ...a, name: config.get(a.service)?.name }));
    return {
      config: publicConfig(config.value),
      catalog: definitions.map(([type, name, group, color, icon, labels]) => ({
        type,
        name,
        group,
        color,
        icon,
        labels,
      })),
      services: states,
      alerts,
      events: store
        .events()
        .filter(e => config.get(e.service))
        .map(e => ({ ...e, name: config.get(e.service)?.name })),
      lastCollected: Math.max(0, ...states.map(s => s.lastSuccess || 0)) || null,
      // A failure of this run; an outage carried from an earlier run is not shown (A40).
      storage: shownStorageFailure()
        ? { since: storageFailure.since, code: storageFailure.code }
        : null,
      notifications: notifications(),
      // Set while the disk is full (the storage guard's banner), else null.
      disk: guard.banner(),
    };
  }
  /**
   * The dashboard's `notifications` (delivery spec §6.5, D12): 1.4.x's fields, now derived from
   * the persisted delivery status (alerting.legacy()), plus the additive fields the web app
   * reads, shaped by lib/alerting/view.mjs like every other delivery view. While the status
   * cannot be read every figure keeps its last computed value with `available: false`, so the
   * value sets external widgets read never change; the web app shows "unavailable" instead.
   */
  function notifications() {
    const status = alerting.snapshot();
    // A status that could not be read is read again in the background, so it becomes
    // available without waiting for the next delivery (the service limits how often).
    if (!status?.available)
      Promise.resolve()
        .then(() => alerting.refresh())
        .catch(() => {});
    return dashboardNotifications(alerting.legacy(), status);
  }
  // Configuration writes run one at a time (see lib/http/exclusive.mjs). A queued write
  // re-checks its credential when it starts; the queue is bounded by writeQueueLimit writes,
  // each waiting at most writeStartMs. While the disk is full a write is refused with 503
  // storage_full when its turn comes (admit), and a write the disk refused tells the guard.
  // Each write's attempt row is written at its turn, and its result notes the configuration
  // before and after as the audit snapshots it (public values, secrets as HMACs only).
  const exclusive = createExclusive({
    limit: writeQueueLimit,
    startMs: writeStartMs,
    assertCurrent: access => identity.assertCurrent(access),
    admit: () => guard.admitConfigWrite(),
    onError: error => guard.noteWriteError(error),
    snapshot: () => audit.configSnapshot(config.value),
  });
  // History side effects after a saved change must not turn the save into an error.
  function storageStep(step) {
    try {
      step();
    } catch (e) {
      storageFailed(e);
    }
  }
  // When the dashboard last received a reading, without building the whole dashboard.
  const lastCollected = () =>
    Math.max(0, ...config.value.services.map(s => store.latest(s.id).lastSuccess || 0)) || null;
  // The scheduler as the routes see it (lib/http/routes/sources.mjs lists each call).
  const collection = {
    collect: (service, signal) => collectLogical(service, signal),
    beginTest() {
      if (connectionTests.size >= 2) return null;
      const id = 'test-' + randomUUID(),
        controller = new AbortController();
      connectionTests.set(id, controller);
      return { id, controller };
    },
    endTest(id) {
      connectionTests.delete(id);
      resetCollector(id);
    },
    // A placeholder in `inflight` keeps the scheduler from polling the source meanwhile.
    async hold(id, task) {
      const placeholder = new AbortController();
      inflight.set(id, placeholder);
      try {
        return await task();
      } finally {
        // Only this placeholder: another hold (or poll) may own the entry by now.
        if (inflight.get(id) === placeholder) inflight.delete(id);
      }
    },
    stop: id => void inflight.get(id)?.abort(),
    forget(id) {
      resetCollector(id);
      due.delete(id);
    },
    unschedule: id => void due.delete(id),
    sourceChanged(id, old, next) {
      if (collectionKey(old) === collectionKey(next)) return;
      inflight.get(id)?.abort();
      resetCollector(id);
      due.delete(id);
    },
    restart() {
      for (const controller of inflight.values()) controller.abort();
      due.clear();
    },
    reschedule: () => due.clear(),
    refresh() {
      due.clear();
      void tick().catch(() => console.error('Collector refresh failed'));
    },
    monitoringKey: () =>
      JSON.stringify(collectionMonitoring.map(key => config.value.monitoring[key])),
    interval,
    timeoutMs,
    pending: () =>
      config.value.services.filter(
        s =>
          s.enabled &&
          configured(s) &&
          !inflight.has(s.id) &&
          (!due.has(s.id) || due.get(s.id) <= mono())
      ).length,
    inflightCount: () => inflight.size,
  };
  // Everything the route modules use (lib/http/routes/*.mjs), and the table built from them.
  // An incomplete table refuses the start (exit 78).
  const router = createRouter(
    routeTable({
      identity,
      loginThrottle,
      legacyBasic,
      insecureHttpSessions,
      trusted,
      config,
      store,
      email,
      directory,
      docsDirectory,
      release: { version, build, startedAt },
      nonce,
      dashboard,
      lastCollected,
      openClients,
      storage: { failure: shownStorageFailure, failed: storageFailed, step: storageStep },
      collection,
      exclusive,
      mono,
      settingsPruneMs,
      historyBudget,
      webhookConfigured: Boolean(webhook),
      configured,
      noCollector,
      collectionError,
      alerting,
      guard,
      reserveBytes,
      keyStatus,
      resourceLimits,
      audit,
      site: { build, publicFiles, indexPage, releases: releasesDirectory },
    }),
    { reserved: reservedPaths, auth: supportedAuth, supports: supportedFeatures }
  );
  const handle = createPipeline({
    router,
    identity,
    loginThrottle,
    release: { build, version },
    allowedHost,
    configuredHosts,
    trusted,
    isClosed: () => closed,
    observe: observeProxy,
    noteClient,
    idempotency: idempotent,
    legacyBasic,
    insecureHttpSessions,
    guard,
    audit,
  });
  // Request time limits (checked every second), a connection cap and each client's share of it
  // (a proxy named in GOBLIN_TRUST_PROXY has none: it carries many clients), and 100 Continue only
  // once a handler reads the body.
  const server = applyServerLimits(http.createServer(serverOptions, handle), handle, {
    perClient,
    trusted,
  });
  // So the stop can end at once a connection that never sent a byte (lib/http/pipeline.mjs).
  const connections = trackConnections(server);
  console.log(startLine({ identity, legacyBasic, insecureHttpSessions }));
  // The reserve that keeps sign-in and delivery working on a full disk, and the check that
  // notices the disk filling or freed (every 10 s, statfs only); then delivery's jobs (the
  // worker, the relay sweep, pruning). Nothing is sent before this point. A reserve that cannot
  // be written must not stop the start: the guard's check keeps trying (D27's rule, for the
  // guard's own write).
  try {
    guard.start();
  } catch (error) {
    guard.noteWriteError(error);
    console.error('The disk space reserve could not be set up:', error?.code || error?.message);
  }
  // The guard's state once it has measured and written its reserve, also when nothing changed:
  // a disk episode an earlier run left open (its notice sent, then a stop) ends now when space
  // was freed meanwhile, and goes on otherwise (A40). A disk with space and no open episode
  // sends nothing.
  alerting.diskChanged(guard.state());
  jobs.every('storage.guard', guardCheckMs, () => guard.check());
  // The audit's hourly maintenance (audit spec §4.7): an inbox drain a full disk left, and the
  // prune of entries past the retention or the row cap, in slices that yield to requests.
  jobs.every('audit.maintain', 3600000, ctx => audit.maintain(ctx), {
    leader: true,
    initialDelayMs: 60000,
  });
  if (startDelivery) alerting.start();
  // A restart is a break in collection: mark it so charts do not draw across the downtime.
  if (startScheduler)
    for (const s of config.value.services)
      if (s.enabled && configured(s)) storageStep(() => store.markGap(s.id));
  const timer = startScheduler
    ? setInterval(() => {
        void tick().catch(() => console.error('Collector scheduler error'));
      }, 1000)
    : null;
  return {
    server,
    store,
    config,
    dashboard,
    poll,
    tick,
    // Sends everything waiting now, email quiet windows included, and resolves once nothing is
    // left in flight (tests; the shutdown does the same, bounded).
    flushNotifications: () => alerting.flush({ timeoutMs: Infinity }),
    // Resolves once Uptime Goblin is serving, after run/status.json names this process.
    listen: () =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const address = server.address();
          status = {
            version,
            build,
            pid: process.pid,
            nonce,
            startedAt,
            listen: { host, port: address.port },
            observed: { forwardedProto: null },
          };
          writeStatus();
          // Only a start that serves is recorded (audit spec §5.6): one whose listen() fails,
          // which systemd retries every 5 s, writes no system.start. Never rejects.
          Promise.resolve()
            .then(() => audit.started({ security }))
            .catch(() => {})
            .finally(() => resolve(address));
        });
      }),
    build,
    version,
    // The control database (openControl's object), identity and the held goblin.lock; close()
    // releases them.
    control,
    identity,
    lock,
    // The delivery service, the storage guard, the job runner and the audit log (tests read
    // their state).
    alerting,
    guard,
    jobs,
    audit,
    // Idempotent: a second signal (or caller) waits for the same shutdown.
    close: () => (closing ??= shutdown()),
  };
  // One shutdown step: a failure is logged and never stops the steps after it.
  async function stopStep(what, run) {
    try {
      await run();
    } catch (error) {
      console.error(`Could not ${what} while stopping:`, error?.code || error?.message);
    }
  }
  // The reverse of the start: stop serving and collecting, let notifications and requests
  // finish, then close history, identity and the control database, and release goblin.lock
  // last, so a new start (in this process or another) can take the data directory at once.
  // The stop takes at most about 36 s (delivery spec §6.2): notifications 9 s, the delivery
  // service 7 s, jobs 2 s, open requests 10 s, sign-outs 5 s, the audit log 2.5 s.
  async function shutdown() {
    closed = true;
    if (timer) clearInterval(timer);
    try {
      // Stop accepting work first, so nothing new (such as a connection test) starts while
      // notifications drain.
      const serverClosed = new Promise(resolve => server.close(() => resolve()));
      server.closeIdleConnections?.();
      // A connection that never sent a byte (a browser's preconnect): closeIdleConnections()
      // leaves it, and on Node 24 close() would wait for it the whole 10 s below.
      connections.closeUnused();
      for (const controller of [...inflight.values(), ...connectionTests.values()])
        controller.abort();
      // Alerts waiting, email quiet windows included, get a bounded chance to go out (D9), so
      // a restart keeps 1.4.x's flush and a rollback to 1.4.x does not strand them. Bounded
      // here too, so a stuck relay cannot hold the stop past its budget.
      const flushMs = Math.min(emailTimeoutMs, 8000);
      await stopStep('send waiting notifications', () =>
        bounded(alerting.flush({ timeoutMs: flushMs }), flushMs + 1000)
      );
      // Then the worker's last pass ends before the outbox stops: no send starts after this.
      // What still waits (retrying, paused, in flight) stays saved for the next start.
      await stopStep('stop notification delivery', () =>
        bounded(alerting.stop({ timeoutMs: 2000 }), 7000)
      );
      await stopStep('close the test email sender', () => email.close());
      await stopStep('stop the background jobs', () => jobs.stop({ timeoutMs: 2000 }));
      // Requests still open after 10 s (a stalled client) must not hold the stop up for ever.
      let forced;
      await Promise.race([
        serverClosed,
        new Promise(resolve => (forced = setTimeout(resolve, 10000))),
      ]);
      clearTimeout(forced);
      server.closeAllConnections?.();
      await serverClosed;
    } finally {
      // Sign-outs whose delete failed are refused only in memory: one more try to delete them
      // before the control database closes, or a line saying a restart accepts them again.
      // Bounded, so a stuck disk cannot hold the stop up.
      let flushTimer;
      await Promise.race([
        Promise.resolve().then(() => identity.flushRevoked?.()),
        new Promise(resolve => (flushTimer = setTimeout(resolve, 5000))),
      ]).catch(() => {});
      clearTimeout(flushTimer);
      // The audit's waiting summaries and system.stop, while control.sqlite is still open; what
      // cannot be written goes to stderr (audit spec §5.6). Bounded: close() takes at most 2 s.
      await stopStep('close the audit log', () =>
        bounded(
          Promise.resolve().then(() => audit.close()),
          CLOSE_MS + 500
        )
      );
      // Whatever failed above, the files and the lock are released: a stop must never leave
      // the data directory locked by a process that is about to exit anyway.
      for (const [name, release] of [
        ['history', () => store.close()],
        ['identity', () => identity.close()],
        ['control database', () => control.close()],
        ['run/status.json', removeStatus],
      ])
        try {
          release();
        } catch (error) {
          console.error(`Could not close the ${name}:`, error.code || error.message);
        }
      lock.release();
    }
  }
}

/**
 * The one line a start prints about sign-in (sessions spec §3.6). It never contains a secret:
 * only where the admin password comes from and which of the two escape hatches are on.
 */
export function startLine({ identity, legacyBasic, insecureHttpSessions }) {
  // identity.status().source is 'auth.json' or 'env' once the admin has a password (a pending
  // auth.json mirror keeps the source it had; auth.json is where Uptime Goblin keeps the password).
  const source = identity.status().source === 'env' ? 'GOBLIN_PASSWORD' : 'auth.json';
  return `Sign-in: built-in admin (password from ${source}) · legacy Basic for scripts: ${legacyBasic ? 'on' : 'off'} · plain-HTTP sessions: ${insecureHttpSessions ? 'allowed' : 'refused'}`;
}
/**
 * How this file was started: 'main' (`node server.mjs`, through any symlink), 'library'
 * (imported by another program), or 'unknown' when that cannot be told, such as a start path
 * that no longer resolves or one named like this file that resolves elsewhere. Real paths are
 * compared: Node resolves symlinks for the module URL but not for argv[1].
 */
export function launchKind({
  argv1 = process.argv[1],
  self = fileURLToPath(import.meta.url),
  realpath = fs.realpathSync,
} = {}) {
  if (!argv1) return 'library';
  const named = path.basename(argv1) === path.basename(self);
  try {
    return realpath(argv1) === realpath(self) ? 'main' : named ? 'unknown' : 'library';
  } catch {
    return named ? 'unknown' : 'library';
  }
}
/**
 * Exit status for a failed start. 75 (EX_TEMPFAIL) when another process holds goblin.lock: in
 * the normal case the previous Uptime Goblin is still stopping after a restart, and the service manager
 * starts this one again shortly. 78 (EX_CONFIG) is only for a refusal Uptime Goblin checked itself
 * (settings, password rules, no admin password, a corrupt configuration or authentication file,
 * data from a newer release, a key problem): starting again cannot help until someone fixes
 * it, so the service manager stops retrying. Anything else, such as a full disk, an I/O or
 * database error or an unexpected failure, is 1 and retried, so Uptime Goblin comes back by itself once
 * the condition passes. (A start aborted by a stop signal is not a failure: the main block
 * exits 0.)
 */
export function startupExitCode(error) {
  if (error?.exitCode === 75) return 75;
  return error?.refusal === true || error instanceof InputError || error?.name === 'SyntaxError'
    ? 78
    : 1;
}
const launch = launchKind();
if (launch === 'unknown') {
  console.error(
    `Uptime Goblin refused to start: its start path (${process.argv[1]}) does not resolve to this file. Start it with the path of server.mjs.`
  );
  process.exit(78);
}
if (launch === 'main') {
  process.umask(0o077);
  // The settings' names from before the rename to Uptime Goblin (ORBIT_*), first of all: each
  // becomes its GOBLIN_ name while that is unset, so everything below reads one name; both set to
  // different values refuses (78) before anything is read or written (lib/legacy-names.mjs).
  try {
    const notice = legacyEnvironmentNotice(adoptLegacyEnvironment(process.env));
    if (notice) console.warn(notice);
    // In the container image, a data volume still mounted only where Orbit's image had it.
    const mount = adoptLegacyDataMount(process.env, { appRoot: root });
    if (mount) console.warn(mount);
  } catch (e) {
    console.error(printable(e?.message ?? e, 8000));
    console.error(
      'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.'
    );
    process.exit(78);
  }
  // Before any DNS or password work starts: a larger libuv pool keeps one slow DNS lookup
  // from delaying everything else (the systemd unit and Docker image also set this).
  process.env.UV_THREADPOOL_SIZE ??= '16';
  // Supervision and the resource limits (lib/resource-limits.mjs), here: after the modules have
  // loaded and the launch setup above has run, and before createApp(), so before the start
  // sequence takes goblin.lock or reads Uptime Goblin's data. (What the modules did as they loaded is not
  // part of this check.) Whether a service manager runs Uptime Goblin (supervision: --supervised, which
  // the systemd unit and the image give and the environment file cannot take away, or
  // GOBLIN_SUPERVISED=1; any other argument, or a value of GOBLIN_SUPERVISED that is neither yes nor
  // no, refuses), then GOBLIN_ALLOW_UNLIMITED (a malformed value refuses, supervised or not) and,
  // supervised, the memory, CPU and process limits it is meant to run under. Uptime Goblin refuses to
  // start (78) where one is not in force and GOBLIN_ALLOW_UNLIMITED does not name it; with it, it
  // starts and says which it runs without. Supervised, every exit that was not asked for with a
  // stop signal is non-zero, so the service manager restarts Uptime Goblin.
  let limits,
    supervised = false;
  try {
    const supervisor = supervision();
    supervised = supervisor.supervised;
    for (const warning of supervisor.warnings) console.warn(warning);
    limits = superviseLimits({ supervised });
  } catch (e) {
    console.error(printable(e?.message ?? e, 8000));
    limits = { refusal: [], refused: e?.refusal === true };
  }
  if (limits.refusal) {
    for (const line of limits.refusal) console.error(line);
    if (limits.refused === false) {
      console.error('Uptime Goblin could not start (exit status 1); it will be started again.');
      process.exit(1);
    }
    console.error(
      'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.'
    );
    process.exit(78);
  }
  for (const warning of limits.warnings) console.warn(warning);
  let stopSignal = null;
  process.on('exit', code => {
    if (code !== 0 || stopSignal) return;
    console.error('Uptime Goblin stopped although no stop signal was received.');
    if (supervised) process.exitCode = 1;
  });
  // Stop signals are handled from before the start. A stop that arrives while Uptime Goblin starts
  // aborts the start at its next step (the snapshot or a migration step already running
  // completes), so systemd never waits for start work nobody wants and never has to SIGKILL it
  // at TimeoutStopSec. A stop while the port is being bound, or right after run/status.json and
  // "ready" were written, is a clean stop too (exit 0, status file removed) instead of the
  // signal's default action ending the process.
  const starting = new AbortController();
  let app = null,
    listening = null;
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, async () => {
      stopSignal = signal;
      // Still starting: the start rejects with the abort, and the code below exits 0.
      if (!app) {
        starting.abort();
        return;
      }
      try {
        // Closing while the port is still being bound would leave it bound behind the close.
        await listening?.catch(() => {});
        await app.close();
      } catch (e) {
        console.error('Uptime Goblin did not stop cleanly:', e.code || e.message);
        process.exit(1);
      }
      process.exit(0);
    });
  let started;
  try {
    started = await createApp({ signal: starting.signal, resourceLimits: limits.status });
  } catch (e) {
    if (starting.signal.aborted && e === starting.signal.reason) {
      console.log('Uptime Goblin stopped while it was starting.');
      process.exit(0);
    }
    // One log line without control characters: the reason can quote saved data, as SQLite's
    // does a damaged database's own schema names (malformed database schema (<name>)), and a
    // start that fails is retried (every 5 seconds under systemd), so a forged line repeated in
    // the log. Uptime Goblin's own refusals are single lines, well under the cut.
    console.error(printable(e?.message ?? e, 8000));
    const code = startupExitCode(e);
    console.error(
      code === 75
        ? 'Another Uptime Goblin process holds the data directory; the service manager starts Uptime Goblin again shortly.'
        : code === 78
          ? 'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.'
          : 'Uptime Goblin could not start (exit status 1); it will be started again.'
    );
    process.exit(code);
  }
  app = started;
  // The start finished before the stop took effect: stop now, cleanly.
  if (stopSignal) {
    try {
      await app.close();
    } catch (e) {
      console.error('Uptime Goblin did not stop cleanly:', e.code || e.message);
      process.exit(1);
    }
    process.exit(0);
  }
  try {
    listening = app.listen();
    const addr = await listening;
    console.log(
      `Uptime Goblin is ready at http://${addr.address.includes(':') ? '[' + addr.address + ']' : addr.address}:${addr.port}`
    );
    // Under systemd's Type=notify unit: "active" from here, once it listens and run/status.json
    // names this process (lib/systemd-notify.mjs). Nothing without NOTIFY_SOCKET (Docker).
    await notifyReady();
  } catch (e) {
    console.error(`Uptime Goblin could not listen for connections: ${e.code || e.message}`);
    // A privileged port is a configuration problem. An address that is not up yet (a LAN
    // address at boot, before the network is configured) may pass, so systemd retries it.
    process.exit(e.code === 'EACCES' ? 78 : 1);
  }
}
