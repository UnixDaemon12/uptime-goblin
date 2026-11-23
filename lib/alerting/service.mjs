// The delivery service (delivery spec §5.5): it wires the outbox, its control.sqlite store, the
// built-in channels (email, GOBLIN_WEBHOOK_URL, ntfy and Gotify), the relay and the webhook
// signing key into the running server, and gives the routes and the dashboard what they show.
//
// - Alert changes reach it through transitions() (the relay's fast path, right after
//   store.evaluate()) and the relay's sweep; Uptime Goblin's own notices through enqueueDirect().
// - Routing is 1.4.2's notify(), unchanged (lib/alerting/policy.mjs legacyEntries): the webhook
//   when GOBLIN_WEBHOOK_URL is set, email when it is switched on and set up; and ntfy and Gotify
//   when each is switched on and set up (their settings documents, lib/alerting/push-settings.mjs,
//   kept in memory here and read again after every save).
// - A start never fails on the service's own writes (D27): the signing key (and the webhook's
//   hold for a new key pair, lib/alerting/signing.mjs: paused until Resume, never probed), the
//   start probes (D10), ending the pause of a channel switched off while Uptime Goblin was stopped
//   (A53), a restore (D16), a roll-forward (D26) and reading the open episodes (A40) are
//   best-effort and retried every 10 s by the notify.relay job. While a restore or roll-forward is pending nothing is sent, since those
//   decide what may be sent.
// - A send-time recheck (D24) skips a row whose source was deleted, or whose alert 1.4.2's
//   switches no longer allow, without touching the channel's health.
// - A channel that pauses tells the other built-in channel, and tells it again when it works
//   (D28); a full disk is announced to both (diskChanged), and so are failing history writes
//   (storageChanged). Those two pair a firing with its recovery across a stop (amendment A40).
import net from 'node:net';
import {
  createOutbox,
  planDigest,
  ACTIVE_STATES,
  deliveryUid,
  newEventUid,
} from '../notify/outbox.mjs';
import { createFailoverStore, isStorageError } from '../notify/memory-store.mjs';
import { createEmailChannel } from '../notify/channels/email.mjs';
import { createEnvWebhookChannel } from '../notify/channels/webhook.mjs';
import { createNtfyChannel } from '../notify/channels/ntfy.mjs';
import { createGotifyChannel } from '../notify/channels/gotify.mjs';
import { serverHost } from '../notify/channels/push.mjs';
import {
  parseWebhookUrl,
  envWebhookAddressProblem,
  plainWebhookHost,
  WebhookUrlError,
} from '../notify/address-policy.mjs';
import { safeReason } from '../notify/channel.mjs';
import { SettingsError } from '../settings.mjs';
import { emailConfigured } from '../mail.mjs';
import { systemClock, safeErrorText } from '../jobs.mjs';
import { createControlOutboxStore } from '../repo/outbox.mjs';
import { legacyEntries, legacyAllows } from './policy.mjs';
import { createRelay } from './relay.mjs';
import { createSigning, SIGNING_HOLD_REASON } from './signing.mjs';
import { notifySettings } from './settings.mjs';
import { PUSH_CHANNELS, PUSH_SETTINGS, pushAuditDiff } from './push-settings.mjs';
import { deliveryError } from './errors.mjs';
import {
  BUILT_IN_CHANNELS,
  channelName,
  channelSetup,
  channelView,
  deliveryView,
  failedSinceOf,
  isPaused,
  legacyView,
  statusView,
  webhookHost,
} from './view.mjs';

export const STALE_REASON =
  "Not sent: Uptime Goblin's control database is a different file than before (restored, copied or moved), and this notification is from before that.";
export const SUPERSEDED_REASON = 'Not sent: Orbit 1.4.x handled a later change of this alert.';
export const SOURCE_DELETED_REASON = 'Not sent: the source was deleted.';
export const SWITCHED_OFF_REASON =
  'Not sent: alerts of this kind were switched off after it was queued.';
export const DISK_FULL_MESSAGE =
  "The Uptime Goblin host's disk is full: settings cannot be saved and readings are paused until space is freed. Alerts are still sent.";
export const DISK_FREE_MESSAGE = "The Uptime Goblin host's disk has free space again.";
export const STORAGE_FAILED_MESSAGE =
  'Uptime Goblin cannot write its history database (is the disk full?). Alerts still run.';
export const STORAGE_OK_MESSAGE = 'Uptime Goblin can write its history database again.';

// Uptime Goblin's notices that pair a firing with its recovery under one since (sys:<name>:<since>:…):
// the control.sqlite meta key that keeps the open episode's since (A40), the rule and the texts.
const EPISODES = Object.freeze({
  disk: Object.freeze({
    meta: 'notice_disk_since',
    rule: '__disk',
    firing: DISK_FULL_MESSAGE,
    resolved: DISK_FREE_MESSAGE,
  }),
  storage: Object.freeze({
    meta: 'notice_storage_since',
    rule: '__storage',
    firing: STORAGE_FAILED_MESSAGE,
    resolved: STORAGE_OK_MESSAGE,
  }),
});

const ACTIVE = new Set(ACTIVE_STATES);
// The history filters (§6.4) as store.list() options. Problems are the queued rows that were
// tried (retrying), held and dead ones: the store leaves out the queued rows not tried yet, so a
// page holds `limit` problems whenever that many exist, however many rows wait for a first try.
const FILTERS = Object.freeze({
  all: {},
  active: { states: ['queued', 'sending', 'held'] },
  problems: { states: ['queued', 'held', 'dead'], excludeWaiting: true },
  delivered: { states: ['delivered'] },
});
// A history cursor that names a row kept in memory (store id m:<n>): the next page lists the
// memory rows below it, then the saved rows from the newest (amendment A30).
const MEMORY_CURSOR = /^m:[1-9][0-9]{0,15}$/;
const JOBS = Object.freeze(['notify.delivery', 'notify.relay', 'notify.prune']);
// The words of a settings field in a refusal (never its value).
const FIELD_WORDS = Object.freeze({
  enabled: 'the on/off switch',
  server: 'the server address',
  topic: 'the topic',
  username: 'the user name',
  password: 'the password',
  token: 'the token',
  priorityFiring: 'the alert priority',
  priorityResolved: 'the recovery priority',
  tags: 'the tags',
  dashboardUrl: "Uptime Goblin's address",
  allowPlainHttp: 'the "Allow plain HTTP" switch',
});
/** A SettingsError of a push channel's save as the DeliveryError the route answers. */
function settingsRefusal(channelId, error) {
  if (!(error instanceof SettingsError)) return error;
  if (error.code === 'settings_conflict') return deliveryError('channel_settings_conflict');
  if (error.code === 'settings_newer') return deliveryError('channel_settings_newer');
  if (error.code === 'settings_keyring') return deliveryError('channel_settings_unavailable');
  const prefix = `notify/${channelId}`;
  let text = String(error.message ?? '');
  if (error.field && Object.hasOwn(FIELD_WORDS, error.field) && text.startsWith(`${prefix}.`))
    text = `${FIELD_WORDS[error.field]} ${text.slice(prefix.length + error.field.length + 2)}`;
  else if (text.startsWith(`${prefix} has no field `))
    text = `there is no setting named ${text.slice(prefix.length + 14, prefix.length + 78)}`;
  else if (text.startsWith(`${prefix}: `)) text = text.slice(prefix.length + 2);
  else if (text === 'The change must be an object') text = 'send the settings as a JSON object';
  return deliveryError('channel_settings_invalid', {
    detail: `${text.charAt(0).toUpperCase()}${text.slice(1)}`.slice(0, 400),
  });
}
const loginOf = actor =>
  (typeof actor === 'string' ? actor : (actor?.login ?? actor?.name)) || 'an administrator';
const iso = ms => new Date(ms).toISOString();

/**
 * createAlerting({control, keyring, history, config, jobs, webhook, mailTransportFactory,
 * emailTimeoutMs, emailBatchMs, restored, clock, rng, policy, pollMs, webhookUnknown, pushUnknown,
 * pushAddressPolicy, ca, lookup, wrapStore, wrapHistory, logger, onStorageError, onEvent}) →
 * Promise<Alerting>
 * (spec §5.5). It never rejects because of a storage error, and registers no job until start().
 * `control` is openControl()'s object; without `control.meta` (tests) the open episodes are
 * kept in memory only.
 */
export async function createAlerting({
  control,
  keyring = null,
  history,
  config,
  jobs,
  webhook = '',
  mailTransportFactory,
  emailTimeoutMs = 20000,
  emailBatchMs = 60000,
  restored = false,
  clock = systemClock,
  rng = Math.random,
  policy = {},
  pollMs = 5000,
  webhookUnknown,
  pushUnknown,
  pushAddressPolicy,
  ca,
  lookup,
  wrapStore = store => store,
  wrapHistory = value => value,
  logger = console,
  onStorageError = () => {},
  onEvent = () => {},
} = {}) {
  if (!control?.settings || !control?.db) throw new TypeError('createAlerting needs control');
  if (!history) throw new TypeError('createAlerting needs history');
  if (!config?.value) throw new TypeError('createAlerting needs config');
  if (!jobs?.every || !jobs?.leaderTask) throw new TypeError('createAlerting needs a job runner');
  const settings = control.settings;
  if (!settings.has(notifySettings.component, notifySettings.key)) settings.define(notifySettings);
  for (const definition of Object.values(PUSH_SETTINGS))
    if (!settings.has(definition.component, definition.key)) settings.define(definition);

  // Lines that repeat (a full disk on every pass) are logged once a minute per kind.
  const logged = new Map();
  function logOnce(key, level, text) {
    const now = clock.now(),
      last = logged.get(key);
    if (last !== undefined && now - last < 60000) return;
    logged.set(key, now);
    logger[level]?.(text);
  }
  const reportStorage = error => {
    if (!isStorageError(error)) return;
    try {
      onStorageError(error);
    } catch {}
  };
  // The audit hook point: secret-free records, never a URL or a key.
  const emit = record => {
    try {
      onEvent({ at: clock.wall(), ...record });
    } catch {}
  };

  const historyApi = wrapHistory({
    unrelayedEvents: options => history.unrelayedEvents(options),
    markRelayed: uids => history.markRelayed(uids),
    legacyEventsAfter: (time, options) => history.legacyEventsAfter(time, options),
    discardUnrelayed: () => history.discardUnrelayed(),
  });

  let refreshSoon = () => {};
  const primary = wrapStore(
    createControlOutboxStore({ db: control.db, clock: () => clock.wall() })
  );
  const store = createFailoverStore({
    primary,
    logger,
    now: () => clock.wall(),
    onChange: (degraded, error) => {
      if (degraded) reportStorage(error);
      emit({
        action: degraded ? 'notifications.unsaved' : 'notifications.saved',
        outcome: 'ok',
        target: 'outbox',
      });
      refreshSoon();
    },
  });

  const signing = createSigning({
    settings,
    configured: Boolean(webhook),
    clock,
    logger,
    onStorageError: reportStorage,
    onEvent: emit,
  });

  const emailChannel = createEmailChannel({
    getSettings: () => config.value.email ?? {},
    transportFactory: mailTransportFactory,
    timeoutMs: emailTimeoutMs,
    digestWindowMs: emailBatchMs,
  });
  const webhookChannel = createEnvWebhookChannel({
    url: webhook,
    signingKeys: () => signing.keys(),
    // Whatever pauses or resumes the channel meanwhile, nothing is sent while it is held.
    hold: () => (signing.held ? SIGNING_HOLD_REASON : null),
    now: () => clock.wall(),
    ...(webhookUnknown ? { unknown: webhookUnknown } : {}),
    ...(ca ? { ca } : {}),
    ...(lookup ? { lookup } : {}),
  });

  // The ntfy and Gotify settings as saved ({value, unreadable, version}), read at the start and
  // after every save: routing, the channel cards and each send use this copy, so a send never
  // waits for the settings store. null while a document could not be read (the channel is then
  // treated as not set up, and the read is tried again by the notify.relay job).
  const push = Object.fromEntries(PUSH_CHANNELS.map(id => [id, null]));
  async function loadPush(id) {
    const definition = PUSH_SETTINGS[id];
    const current = await settings.get(definition.component, definition.key);
    push[id] = Object.freeze({
      value: Object.freeze({ ...current.value }),
      unreadable: Object.freeze([...(current.unreadable ?? [])]),
      version: current.version,
      readOnly: current.readOnly,
    });
    return push[id];
  }
  async function loadAllPush() {
    for (const id of PUSH_CHANNELS) await loadPush(id);
  }
  const pushChannelOptions = {
    now: () => clock.wall(),
    ...(pushUnknown ? { unknown: pushUnknown } : {}),
    ...(pushAddressPolicy ? { addressPolicy: pushAddressPolicy } : {}),
    ...(ca ? { ca } : {}),
    ...(lookup ? { lookup } : {}),
  };
  const ntfyChannel = createNtfyChannel({ getSettings: () => push.ntfy, ...pushChannelOptions });
  const gotifyChannel = createGotifyChannel({
    getSettings: () => push.gotify,
    ...pushChannelOptions,
  });
  const pushChannels = { ntfy: ntfyChannel, gotify: gotifyChannel };

  /** D24: null to send the row, or why it is skipped (the source is gone, alerts are off). */
  function recheck(row) {
    const event = row.event ?? {};
    const source = event.service === 'orbit' ? null : config.get(event.service);
    if (event.service !== 'orbit' && source === undefined) return SOURCE_DELETED_REASON;
    if (!legacyAllows(config.value.alerts ?? {}, source?.alerts, event)) return SWITCHED_OFF_REASON;
    return null;
  }

  const outbox = createOutbox({
    store,
    channels: [emailChannel, webhookChannel, ntfyChannel, gotifyChannel],
    clock,
    rng,
    policy,
    logger,
    maxInFlight: 4,
    candidateLimit: 200,
    pollMs,
    maxActive: 10000,
    singleProcess: true,
    recheck,
    onChannel: change => onChannel(change),
  });

  // Events routed while the ntfy and Gotify settings were not read (pending.push: the read at
  // the start failed, or the read after a save did): whether either channel gets an event is not
  // known then, so their rows wait while email's and the webhook's are queued at once. Keyed by
  // event uid: null for an alert change (route() answers `held`, and the relay keeps it
  // unrelayed, with any rows it put in memory, and relays it again once the settings are read),
  // {event, exclude} for an Uptime Goblin notice (nothing relays it again, so it is routed again
  // here once the settings are read: replayHeldNotices()). Routed again, only the ntfy and Gotify
  // rows are written. Bounded: past PUSH_HELD_MAX the oldest is forgotten (an alert change then
  // writes email's and the webhook's rows again, which the outbox ignores as duplicates while they
  // are kept; a notice is lost to ntfy and Gotify and counted).
  const PUSH_HELD_MAX = 1000;
  const pushHeld = new Map();
  let pushHeldLost = 0;
  const NOT_PUSH_CHANNELS = BUILT_IN_CHANNELS.filter(id => !PUSH_CHANNELS.includes(id));
  function holdForPush(eventUid, notice) {
    pushHeld.delete(eventUid);
    pushHeld.set(eventUid, notice);
    while (pushHeld.size > PUSH_HELD_MAX) {
      const [oldest, held] = pushHeld.entries().next().value;
      pushHeld.delete(oldest);
      if (held) {
        pushHeldLost++;
        logOnce(
          'push-held-lost',
          'error',
          `${pushHeldLost} Uptime Goblin notice(s) were not queued for ntfy or Gotify: their settings could not be read.`
        );
      }
    }
  }

  /**
   * 1.4.2's routing, read when relayed: the rows for one event (D5). While the ntfy and Gotify
   * settings are not read, their rows wait (pushHeld above): for an alert change the answer then
   * says `held`, beside what the other rows' enqueue answered (their memory rows included, which
   * the relay must still await), so the relay relays it again; a notice (`notice`) is kept here.
   */
  async function route(event, eventUid, { exclude = [], notice = false } = {}) {
    const mail = config.value.email ?? {};
    const holdPush = pending.push;
    const skip = pushHeld.has(eventUid) ? [...exclude, ...NOT_PUSH_CHANNELS] : exclude;
    const all = legacyEntries(event, {
      eventUid,
      settings: config.value.alerts ?? {},
      sourceAlerts: event.service === 'orbit' ? undefined : config.get(event.service)?.alerts,
      webhookConfigured: Boolean(webhook),
      emailEnabled: Boolean(mail.enabled) && emailConfigured(mail),
      // Every push channel while their settings wait: only to learn whether one would get it.
      push: holdPush
        ? PUSH_CHANNELS
        : PUSH_CHANNELS.filter(id => {
            const setup = setupOf(id);
            return setup.configured && setup.enabled;
          }),
    }).filter(entry => !skip.includes(entry.channelId));
    const held = holdPush && all.some(entry => PUSH_CHANNELS.includes(entry.channelId));
    const entries = holdPush ? all.filter(entry => !PUSH_CHANNELS.includes(entry.channelId)) : all;
    let result = { inserted: 0, duplicates: 0, dropped: 0, memoryUids: [] };
    if (entries.length) {
      result = await outbox.enqueue(entries);
      refreshSoon();
    }
    if (held) {
      holdForPush(eventUid, notice ? { event, exclude: [...exclude] } : null);
      if (!notice) return { ...result, held: true };
    } else pushHeld.delete(eventUid);
    return result;
  }

  /** The notices held for ntfy and Gotify, routed again once their settings are read. */
  function replayHeldNotices() {
    for (const [eventUid, held] of [...pushHeld])
      if (held) void notice(held.event, eventUid, { exclude: held.exclude });
  }

  async function isFinal(deliveryUid) {
    const row = await store.find(deliveryUid);
    return !row || !ACTIVE.has(row.state);
  }

  const relay = createRelay({
    history: historyApi,
    enqueue: route,
    isFinal,
    cancelSource: serviceId => outbox.cancelSource(serviceId, SOURCE_DELETED_REASON),
    nameOf: id => config.get(id)?.name,
    waiting: () => pending.push,
    clock,
    logger,
  });

  // -------------------------------------------------------------------------------------------
  // Uptime Goblin's own notices (D28)

  function notice(event, uid, options = {}) {
    return relay.direct(event, uid, { ...options, notice: true }).catch(error => {
      reportStorage(error);
      logOnce(
        'notice',
        'error',
        `An Uptime Goblin notice could not be queued: ${safeErrorText(error)}`
      );
      return { enqueued: 0 };
    });
  }

  function onChannel({ channelId, previous, next }) {
    refreshSoon();
    if (!BUILT_IN_CHANNELS.includes(channelId)) return;
    const name = channelName(channelId),
      wasPaused = previous?.pausedSince != null,
      nowPaused = next?.pausedSince != null;
    const retryAt = next?.state === 'paused' && next.nextSendAt > 0 ? next.nextSendAt : null;
    const pausedLine = () =>
      `${name} notifications are paused: ${next.pausedReason ?? 'paused'}${retryAt ? ` Uptime Goblin tries again at ${iso(retryAt)}.` : ''}`;
    const event = (kind, message, time) => ({
      service: 'orbit',
      name: 'Uptime Goblin',
      kind,
      category: 'system',
      rule: `__channel_${channelId}`,
      message,
      time,
    });
    if (!wasPaused && nowPaused) {
      logOnce(`pause:${channelId}`, 'warn', pausedLine());
      emit({
        action: 'channel.paused',
        outcome: 'ok',
        target: channelId,
        detail: { reason: next.pausedReason ?? null, transient: Boolean(retryAt) },
      });
      void notice(
        event(
          'firing',
          `${name} notifications are paused: ${next.pausedReason ?? ''}`.trim(),
          next.pausedSince
        ),
        `sys:pause:${channelId}:${next.pausedSince}:firing`,
        { exclude: [channelId] }
      );
    } else if (wasPaused && !nowPaused) {
      logger.info?.(`${name} notifications are working again.`);
      emit({ action: 'channel.working', outcome: 'ok', target: channelId });
      void notice(
        event('resolved', `${name} notifications are working again.`, clock.wall()),
        `sys:pause:${channelId}:${previous.pausedSince}:resolved`,
        { exclude: [channelId] }
      );
    } else if (wasPaused && previous.state === 'paused' && next.state === 'circuit-open')
      logger.info?.(`Trying ${name} notifications again with one notification.`);
    else if (wasPaused && previous.state !== 'paused' && next.state === 'paused')
      logOnce(`pause:${channelId}`, 'warn', pausedLine());
  }

  // -------------------------------------------------------------------------------------------
  // Episodes: the disk and history-storage notices (D28, amendment A40)
  //
  // Each pairs a firing with its recovery under one since, and a receiver keyed by service and
  // rule (orbit/__disk) shows the condition until the recovery arrives. Kept in memory alone, a
  // stop in between lost the pairing: space freed while Uptime Goblin was stopped (a restart after a
  // clean-up, a reboot, a rollback to 1.4.x and an upgrade again) never sent the recovery, a
  // firing still waiting to retry was sent after the start with no recovery behind it, and a
  // start on a disk still full began a second episode. So the open episode's since is kept in
  // control.sqlite's meta (EPISODES[name].meta; '' once it ended), and the next start carries it
  // on: the guard's state at that start (diskChanged) sends the recovery or keeps the episode;
  // the history-storage episode is ended by the server's own rule (storageCarried()).
  //
  // Changes are applied one at a time, in call order, once the open episodes are read
  // (pending.episodes) and D16's stale marking is done (it would mark a recovery queued before
  // it as never to be sent). A firing writes its since before it is queued, so a stop after the
  // queueing always finds the episode; a recovery is queued before the end is written, and a
  // start that finds the recovery's rows treats the episode as ended. A write that fails is
  // tried again at the next notify.relay run; a stop before it succeeds loses only that write.
  const meta = control.meta ?? null;
  const open = { disk: null, storage: null }, // the open episode's since, or null
    reported = { disk: false, storage: false }, // a change was reported since this start
    unsavedEpisodes = new Set(),
    episodeChanges = []; // [name, kind, time] in call order
  let episodesLoaded = false,
    episodeChain = Promise.resolve();

  async function eventRowExists(rule, eventUid) {
    const rows = await store.list({ orderKey: `orbit\n${rule}`, limit: 100 });
    return rows.some(row => row.eventUid === eventUid);
  }

  /** Start work: the episodes an earlier run left open (pending.episodes until it succeeds). */
  async function loadEpisodes() {
    const found = {};
    for (const [name, spec] of Object.entries(EPISODES)) {
      const text = meta ? await meta.get(spec.meta) : null;
      let since = typeof text === 'string' && /^[0-9]{1,15}$/.test(text) ? Number(text) : null;
      // Its recovery was queued, and Uptime Goblin stopped before the end could be written.
      if (since !== null && (await eventRowExists(spec.rule, `sys:${name}:${since}:resolved`))) {
        since = null;
        unsavedEpisodes.add(name);
      }
      found[name] = since;
    }
    Object.assign(open, found);
    episodesLoaded = true;
  }

  async function saveEpisodes() {
    for (const name of [...unsavedEpisodes]) {
      if (meta) await meta.set(EPISODES[name].meta, open[name] === null ? '' : String(open[name]));
      unsavedEpisodes.delete(name);
    }
  }
  const episodeSaveFailed = error => {
    reportStorage(error);
    logOnce(
      'episodes',
      'error',
      `Uptime Goblin could not record that its disk or history notice is open or ended (${safeErrorText(error)}); it tries again in 10 seconds.`
    );
  };

  const episodeEvent = (name, kind, time) => ({
    service: 'orbit',
    name: 'Uptime Goblin',
    kind,
    category: 'system',
    rule: EPISODES[name].rule,
    message: EPISODES[name][kind],
    time,
  });

  async function applyEpisodeChange([name, kind, time]) {
    if (kind === 'firing') {
      let since = open[name];
      if (since === null) {
        since = time;
        open[name] = since;
        unsavedEpisodes.add(name);
        await saveEpisodes().catch(episodeSaveFailed);
      }
      // Also for an episode already open: the outbox keeps one row per delivery id, and a start
      // that finds an episode whose firing never got queued (a stop between the two writes)
      // still announces it.
      await notice(episodeEvent(name, 'firing', since), `sys:${name}:${since}:firing`);
    } else {
      const since = open[name];
      if (since === null) return;
      await notice(episodeEvent(name, 'resolved', time), `sys:${name}:${since}:resolved`);
      open[name] = null;
      unsavedEpisodes.add(name);
      await saveEpisodes().catch(episodeSaveFailed);
    }
  }

  const episodesReady = () => episodesLoaded && !pending.stale && !stopped;
  /** Writes what is unsaved, then applies the changes waiting; one run at a time. */
  function runEpisodes() {
    episodeChain = episodeChain.then(async () => {
      try {
        if (!episodesReady()) return;
        if (unsavedEpisodes.size) await saveEpisodes().catch(episodeSaveFailed);
        while (episodeChanges.length && episodesReady())
          await applyEpisodeChange(episodeChanges.shift());
      } catch (error) {
        // Never expected (notice() and the writes catch their own errors), and never allowed
        // to stop the runs after it.
        logOnce('episodes-run', 'error', `An Uptime Goblin notice failed: ${safeErrorText(error)}`);
      }
    });
    return episodeChain;
  }
  function episodeChanged(name, kind, time) {
    reported[name] = true;
    episodeChanges.push([name, kind, Number.isSafeInteger(time) ? time : clock.wall()]);
    void runEpisodes();
  }

  /** The guard's onChange, and the guard's state at every start: the sys:disk notice. */
  function diskChanged(state) {
    if (state?.full) episodeChanged('disk', 'firing', state.since);
    else episodeChanged('disk', 'resolved', clock.wall());
  }

  // -------------------------------------------------------------------------------------------
  // Status

  let available = false,
    current = null,
    refreshing = null,
    refreshAgain = false,
    refreshTimer = null,
    lastRefreshAt = -Infinity,
    lastProbeAt = -Infinity,
    stopped = false;

  const setupOf = id =>
    channelSetup(id, {
      webhook,
      email: config.value.email ?? {},
      push: Object.fromEntries(PUSH_CHANNELS.map(name => [name, push[name]?.value ?? null])),
    });
  // The host a channel card names: the webhook's, or the ntfy or Gotify server's.
  const hostOf = id =>
    id === 'env-webhook'
      ? webhookHost(webhook)
      : PUSH_CHANNELS.includes(id)
        ? serverHost(push[id]?.value?.server)
        : null;
  // Set up and on: Retry is offered and accepted only then (amendment A45). A row of a channel
  // that is not (GOBLIN_WEBHOOK_URL removed at a restart, email switched off or incomplete) is
  // skipped when sent, so Retry would say it is sent again and then skip it. A channel this
  // release does not know (a newer one's rows) is left as it was.
  const ready = id => {
    if (!BUILT_IN_CHANNELS.includes(id)) return true;
    const setup = setupOf(id);
    return setup.configured && setup.enabled;
  };
  const notSetUpVariant = id =>
    id === 'email' || PUSH_CHANNELS.includes(id) ? (setupOf(id).configured ? `${id}-off` : id) : id;
  function emptyStatus() {
    const now = clock.wall();
    return statusView({
      channels: BUILT_IN_CHANNELS.map(id =>
        channelView(id, { status: null, now, ...setupOf(id), host: hostOf(id) })
      ),
      now,
      signing: signing.describe(),
    });
  }

  // The earliest moment a row of `channelId` waiting to retry may go (reads at most 100 rows).
  async function nextRetryOf(channelId) {
    const rows = await store.list({ states: ['queued'], channelId, limit: 100 });
    let next = null;
    for (const row of rows)
      if (row.attempts > 0 && (next === null || row.nextAt < next)) next = row.nextAt;
    return next;
  }

  // An email row waiting for its first try: it goes out with the next digest, whose time the
  // outbox works out only as it sends (amendment A31).
  const waitsForDigest = row =>
    row.channelId === emailChannel.name &&
    row.state === 'queued' &&
    !row.digestKey &&
    !(row.attempts > 0);
  /**
   * When the digest that `channel`'s waiting rows join goes out, by the outbox's own rule
   * (planDigest: once the newest is `windowMs` old, or the oldest `maxFactor` × `windowMs`),
   * or null when no row waits. A digest already due goes at the next pass: now. Read from the
   * newest 100 queued rows; with more waiting, the oldest of them stands in for the oldest,
   * which can make the time later than the send, never earlier.
   */
  async function digestDueOf(channel) {
    const rows = await store.list({ states: ['queued'], channelId: channel.name, limit: 100 });
    const waiting = rows.filter(waitsForDigest);
    if (!waiting.length) return null;
    const now = clock.wall();
    return planDigest(waiting, { now, ...channel.digest }).wakeAt ?? now;
  }

  async function compute() {
    lastRefreshAt = clock.now();
    // Degraded: try the database again (at most every 10 s), so "not being saved" ends without
    // waiting for the next alert.
    if (store.degraded && clock.now() - lastProbeAt >= 10000) {
      lastProbeAt = clock.now();
      await Promise.resolve()
        .then(() => outbox.probe())
        .catch(() => false);
    }
    const now = clock.wall();
    try {
      const statuses = {};
      for (const id of BUILT_IN_CHANNELS) statuses[id] = await store.channel(id);
      const failedSince = Object.fromEntries(
        BUILT_IN_CHANNELS.map(id => [id, failedSinceOf(statuses[id], now)])
      );
      const summary = await store.summary({ failedSince });
      const channels = [];
      for (const id of BUILT_IN_CHANNELS) {
        const part = summary?.[id] ?? null;
        channels.push(
          channelView(id, {
            status: statuses[id],
            summary: part,
            now,
            ...setupOf(id),
            host: hostOf(id),
            nextRetryAt: part?.retrying > 0 ? await nextRetryOf(id) : null,
            notQueued: outbox.notQueued(id),
          })
        );
      }
      current = statusView({
        channels,
        now,
        saving: !store.degraded,
        unsavedSince: store.degradedSince ?? null,
        unsavedReason: store.degraded
          ? `Uptime Goblin cannot write its control database (${store.reason ?? 'error'}).`
          : null,
        notQueued: outbox.dropped,
        signing: signing.describe(),
      });
      available = true;
    } catch (error) {
      reportStorage(error);
      available = false;
      logOnce(
        'status',
        'error',
        `Delivery status could not be read: ${safeErrorText(error)}. The page shows it as unavailable.`
      );
    }
  }

  /** Recomputes the Status; a refresh asked for while one runs runs once more after it. */
  function refresh() {
    if (refreshing) {
      refreshAgain = true;
      return refreshing;
    }
    refreshing = (async () => {
      try {
        do {
          refreshAgain = false;
          await compute();
        } while (refreshAgain && !stopped);
      } finally {
        refreshing = null;
      }
    })();
    return refreshing;
  }
  // After completions and new rows: at most one refresh a second.
  refreshSoon = () => {
    if (stopped || refreshTimer) return;
    const wait = Math.max(0, 1000 - (clock.now() - lastRefreshAt));
    refreshTimer = clock.setTimeout(() => {
      refreshTimer = null;
      void refresh();
    }, wait);
  };

  function snapshot() {
    const value = current ?? emptyStatus();
    return available ? value : { ...value, available: false };
  }

  // -------------------------------------------------------------------------------------------
  // Start work (D10, D16, D26, D27)

  const pending = {
    // At every start, webhook or not: without one, ensure() removes a pre-release HMAC secret.
    secret: true,
    probes: true,
    // A pause no probe can end: the channel was switched off or removed while Uptime Goblin was stopped.
    pauses: true,
    stale: Boolean(restored),
    // Cleared only by a pass that ran after the start sweep, so rows the sweep relays for alert
    // changes written before a rollback are checked too.
    supersede: true,
    // The disk and history-storage episodes an earlier run left open (A40).
    episodes: true,
    // The ntfy and Gotify settings (read before anything is routed or probed).
    push: true,
  };
  let started = false,
    startSweepDone = false,
    startSequence = null,
    deliveryRegistered = false,
    restoredHistory = false,
    restoreEvents = 0,
    // When the history half of D16 could not run at once: events at or after this time were
    // written by this process and are kept.
    discardBefore = null;
  const createdAt = clock.wall();

  async function attempt(name, work) {
    try {
      await work();
      pending[name] = false;
      return true;
    } catch (error) {
      reportStorage(error);
      if (name === 'stale' || name === 'supersede')
        logOnce(
          'start-work',
          'error',
          isStorageError(error)
            ? 'Notifications wait until Uptime Goblin can record which old notifications must not be sent (the disk is full).'
            : `Notifications wait until Uptime Goblin can record which old notifications must not be sent (${safeErrorText(error)}).`
        );
      else
        logOnce(
          `start-${name}`,
          'error',
          `Delivery start work (${name}) is pending: ${safeErrorText(error)}`
        );
      return false;
    }
  }

  /**
   * D10: every paused channel may send one probe now, except a webhook held for a new signing
   * key: only Resume ends that pause (a probe would only pause it again, unsent).
   */
  async function startProbes() {
    const now = clock.wall();
    for (const id of BUILT_IN_CHANNELS) {
      if (id === 'env-webhook' && signing.held) continue;
      const status = await primary.channel(id);
      if (status?.state === 'paused')
        await outbox.updateChannel(id, s => (s.state === 'paused' ? { ...s, nextSendAt: now } : s));
    }
  }

  /**
   * A built-in channel left paused by an earlier run that is not switched on now (email switched
   * off, under 1.4.x during a rollback or otherwise while Uptime Goblin was stopped; GOBLIN_WEBHOOK_URL
   * removed at a restart) can send nothing: its rows are skipped when sent, so neither the start
   * probe nor any later one ends the pause, and the other channel's receiver kept "… notifications
   * are paused" firing for good. Its pause ends here as saving the email settings ends it in a
   * running Uptime Goblin (emailChanged: channelChanged): the rows it holds are released, to be skipped,
   * and onChannel tells the other channel that it works again (D28). Email switched on but not
   * complete keeps its pause: its probe pauses it again ("Email is not set up: …"), as a save of
   * such settings would. Runs after D16's stale marking, which would mark that notice as never
   * to be sent.
   */
  async function endPausesSwitchedOff() {
    for (const id of BUILT_IN_CHANNELS) {
      if (setupOf(id).enabled) continue;
      const status = await primary.channel(id);
      if (status?.pausedSince != null) await outbox.channelChanged(id);
    }
  }

  // History events from before `bound` stay unsent (D16, retried after a failed first try).
  async function discardHistoryBefore(bound) {
    let count = 0,
      afterId = 0;
    for (;;) {
      const rows = await historyApi.unrelayedEvents({ afterId, limit: 200 });
      if (!rows.length) return count;
      afterId = rows.at(-1).id;
      const old = rows.filter(row => row.time < bound).map(row => row.uid);
      if (old.length) {
        await historyApi.markRelayed(old);
        count += old.length;
      }
      if (rows.length < 200) return count;
    }
  }

  /** D16: restored, copied or moved data never sends what waited before. */
  async function applyRestore() {
    if (!restoredHistory) {
      try {
        // No poll has run yet when this first runs: every unrelayed event is from before.
        restoreEvents =
          discardBefore === null
            ? await historyApi.discardUnrelayed()
            : await discardHistoryBefore(discardBefore);
      } catch (error) {
        discardBefore ??= createdAt;
        throw error;
      }
      restoredHistory = true;
    }
    // The control database only: rows kept in memory were made by this process.
    const rows = await primary.stale({ now: clock.wall(), reason: STALE_REASON });
    logger.warn?.(
      `${rows} notifications and ${restoreEvents} alert changes from before Uptime Goblin's control database became a different file were not sent.`
    );
  }

  /** D26: a waiting row whose alert 1.4.x handled a later change of is not sent. */
  async function rollForward() {
    // Rows an earlier process left 'sending' (killed during a send) are resolved first, as the
    // delivery worker's first pass would resolve them (acceptance unknown: queued for the
    // channel's resend), so this check covers them like any waiting row. Otherwise a firing in
    // flight when Uptime Goblin was killed, whose recovery 1.4.x then sent after a rollback, was sent
    // again after that recovery, and the receiver showed the alert firing for good. Nothing of
    // this process is sending yet: delivery starts only once this has run.
    await outbox.recover({ foreign: true });
    // A resolution the control database could not take is kept in memory (D15), and its row is
    // still 'sending' there, where the check below cannot see it: wait until it is written.
    if ((await primary.sending()).some(row => row.leaseOwner !== outbox.owner))
      throw new Error(
        'a notification an earlier run was sending is not resolved yet; its result waits to be written'
      );
    // Every waiting row's alert is checked (A63): the waiting rows are read in pages (by id,
    // newest first) and history is asked about their keys only, so no number of other alerts
    // 1.4.x changed meanwhile can push one out of the check. Before, the newest 1,000 changed
    // alerts were read instead, and a waiting firing older than those was sent after the
    // recovery 1.4.x had sent. A read that fails throws, so D26 stays pending and nothing is sent.
    const now = clock.wall();
    const waiting = new Map();
    let oldest = null;
    for (let beforeId = null; ; ) {
      const rows = await primary.list({ states: ['queued', 'held'], beforeId, limit: 100 });
      if (!rows.length) break;
      for (const row of rows) {
        if (oldest === null || row.createdAt < oldest) oldest = row.createdAt;
        const cut = typeof row.orderKey === 'string' ? row.orderKey.indexOf('\n') : -1;
        if (cut < 0) continue;
        let key = waiting.get(row.orderKey);
        if (!key)
          waiting.set(
            row.orderKey,
            (key = {
              service: row.orderKey.slice(0, cut),
              rule: row.orderKey.slice(cut + 1),
              channels: new Set(),
            })
          );
        key.channels.add(row.channelId);
      }
      beforeId = rows.at(-1).id;
    }
    if (!waiting.size) return 0;
    const changes = await historyApi.legacyEventsAfter(oldest, {
      keys: [...waiting.values()].map(({ service, rule }) => ({ service, rule })),
    });
    let superseded = 0;
    for (const change of changes) {
      const orderKey = `${change.service ?? ''}\n${change.rule ?? ''}`;
      const channels = waiting.get(orderKey)?.channels;
      if (!channels) continue;
      for (const channelId of BUILT_IN_CHANNELS)
        if (channels.has(channelId))
          superseded += await primary.supersede({
            channelId,
            orderKey,
            kinds: ['firing', 'resolved'],
            now,
            reason: SUPERSEDED_REASON,
            createdBefore: change.time,
          });
    }
    if (superseded)
      logger.warn?.(
        `${superseded} notifications were not sent: Orbit 1.4.x handled a later change of their alerts.`
      );
    return superseded;
  }

  /**
   * The webhook URL is checked once at start; host names are checked at connect time. Plain
   * http: to another computer still works, as in 1.4.2, but is said: the token many chat
   * webhooks carry in the URL, and every notification, would cross the network in clear.
   */
  async function checkWebhookUrl() {
    if (!webhook) return;
    let reason = null;
    try {
      const url = parseWebhookUrl(webhook);
      const host = url.hostname.replace(/^\[|\]$/g, '');
      const plain = plainWebhookHost(url);
      if (plain)
        logger.warn?.(
          `GOBLIN_WEBHOOK_URL uses plain HTTP to ${plain.slice(0, 253)}: the address (with any token in it), each notification and its signature cross the network unencrypted. Use an https:// address.`
        );
      if (net.isIP(host)) reason = await envWebhookAddressProblem(host);
    } catch (error) {
      if (!(error instanceof WebhookUrlError)) throw error;
      reason = error.message;
    }
    if (!reason) return;
    logger.warn?.(`GOBLIN_WEBHOOK_URL cannot be used: ${reason}`);
    try {
      await outbox.pause('env-webhook', reason);
    } catch (error) {
      // The channel pauses itself at its first send anyway.
      reportStorage(error);
    }
  }

  /**
   * A webhook held for a new signing key (signing.held) is paused with SIGNING_HOLD_REASON, at
   * once rather than at its next send, so the page, the banner and the other channel say so
   * before an alert waits. An existing pause for another reason stays in place; ending a
   * signing hold must not clear an independently required pause.
   */
  async function holdWebhook() {
    try {
      const version = outbox.channelVersion('env-webhook');
      const status = await store.channel('env-webhook');
      if (!signing.held) {
        // A transient missing-key pause may outlive a failed first save. Only a
        // ready, unheld authority clears this exact pause; persisted migration
        // and newer-schema holds remain held until an administrator resumes them.
        if (status?.state === 'paused' && status.pausedReason === SIGNING_HOLD_REASON)
          await outbox.resume('env-webhook', {
            ifStatus: status,
            ifVersion: version,
            canResume: () => !signing.held,
          });
        return;
      }
      if (status?.state === 'paused') return;
      await outbox.pause('env-webhook', SIGNING_HOLD_REASON, {
        ifStatus: status,
        ifVersion: version,
        canPause: () => signing.held,
      });
    } catch (error) {
      // The channel pauses itself at its next send anyway.
      reportStorage(error);
    }
  }

  async function runStartWork() {
    if (pending.push && (await attempt('push', loadAllPush))) replayHeldNotices();
    if (pending.secret) pending.secret = !(await signing.ensure());
    await holdWebhook();
    if (pending.probes) await attempt('probes', startProbes);
    if (pending.stale) await attempt('stale', applyRestore);
    if (pending.pauses && !pending.stale) await attempt('pauses', endPausesSwitchedOff);
    if (pending.episodes) await attempt('episodes', loadEpisodes);
  }

  function deliveryAllowed() {
    return started && !stopped && startSweepDone && !pending.stale && !pending.supersede;
  }
  function maybeStartDelivery() {
    if (deliveryRegistered || !deliveryAllowed()) return;
    deliveryRegistered = true;
    jobs.leaderTask('notify.delivery', ctx => outbox.run(ctx));
  }

  // The start sweep, then the roll-forward check over everything it relayed, then delivery.
  function runStartSequence() {
    startSequence ??= (async () => {
      try {
        await relay.sweep();
      } catch (error) {
        reportStorage(error);
        logOnce('sweep', 'error', `Alert changes could not be relayed: ${safeErrorText(error)}`);
      }
      startSweepDone = true;
      if (pending.supersede) await attempt('supersede', rollForward);
      maybeStartDelivery();
      refreshSoon();
    })();
    return startSequence;
  }

  async function relayJob(ctx) {
    if (
      pending.push ||
      pending.secret ||
      pending.probes ||
      pending.stale ||
      pending.pauses ||
      pending.episodes
    )
      await ctx.wait(runStartWork());
    // Episode changes that waited for that work, and episode writes that failed (A40).
    if (episodeChanges.length || unsavedEpisodes.size) await ctx.wait(runEpisodes());
    if (!pending.stale) {
      if (!startSweepDone) await ctx.wait(runStartSequence());
      else {
        try {
          await ctx.wait(relay.sweep({ signal: ctx.signal }));
        } catch (error) {
          reportStorage(error);
          logOnce('sweep', 'error', `Alert changes could not be relayed: ${safeErrorText(error)}`);
        }
        if (pending.supersede) await ctx.wait(attempt('supersede', rollForward));
      }
    }
    maybeStartDelivery();
    if (store.degraded || clock.now() - lastRefreshAt >= 60000) await ctx.wait(refresh());
  }

  async function pruneJob(ctx) {
    for (;;) {
      const removed = await ctx.wait(outbox.prune({ limit: 500 }));
      if (removed < 500 || ctx.signal.aborted) return;
      await ctx.yieldNow();
    }
  }

  // createAlerting's own start work: each item best-effort.
  await runStartWork();
  if (!pending.stale)
    try {
      // A first pass before anything is relayed (the required one runs after the start sweep).
      await rollForward();
    } catch (error) {
      reportStorage(error);
    }
  await checkWebhookUrl().catch(error =>
    logOnce(
      'webhook-url',
      'error',
      `GOBLIN_WEBHOOK_URL could not be checked: ${safeErrorText(error)}`
    )
  );
  await refresh();

  // -------------------------------------------------------------------------------------------
  // The service

  // `other`: the refusal is of another notification of the row's email digest, which is retried
  // or refused as a whole; the row's own state may be fine, so its text names the other one.
  // (A paused channel, and one that is not set up, are named by channel: every notification of
  // an email is on that one channel.)
  function refusal(result, uid) {
    switch (result.refused) {
      case 'not_found':
        return deliveryError('delivery_not_found');
      case 'sending':
      case 'waiting':
      case 'finished':
        return deliveryError('delivery_not_retryable', {
          variant: result.other ? 'digest_other' : result.refused,
        });
      case 'paused':
        return deliveryError('channel_paused', {
          name: channelName(result.channelId),
          reason: result.reason ?? 'paused.',
        });
      case 'outdated':
        return deliveryError('delivery_outdated', result.other ? { variant: 'digest' } : {});
      case 'not_set_up':
        return deliveryError('channel_not_set_up', { variant: notSetUpVariant(result.channelId) });
      case 'not_sent':
        return deliveryError('delivery_not_retryable', {
          variant: `${result.other ? 'digest_' : ''}${result.reason === SOURCE_DELETED_REASON ? 'source_deleted' : 'switched_off'}`,
        });
      default:
        return deliveryError('delivery_status_unavailable', { retryAfter: 15 });
    }
  }

  async function withTimeout(promise, ms) {
    if (!Number.isFinite(ms)) return promise.then(() => true);
    let timer;
    const done = await Promise.race([
      promise.then(
        () => true,
        () => true
      ),
      new Promise(resolve => (timer = clock.setTimeout(() => resolve(false), Math.max(0, ms)))),
    ]);
    clock.clearTimeout(timer);
    return done;
  }

  const unavailable = error => {
    reportStorage(error);
    return deliveryError('delivery_status_unavailable', { retryAfter: 15 });
  };

  /**
   * The ntfy or Gotify settings as the page edits them: every field, secrets only as
   * {set: true|false}, the document's version (for `version` on a save) and whether a newer
   * Uptime Goblin saved it (read-only). Rejects delivery_status_unavailable when it cannot be read.
   */
  async function pushView(channelId) {
    const definition = PUSH_SETTINGS[channelId];
    if (!definition) throw deliveryError('channel_unknown');
    let current;
    try {
      current = await settings.view(definition.component, definition.key);
    } catch (error) {
      throw unavailable(error);
    }
    return {
      channel: channelId,
      version: current.version,
      readOnly: current.readOnly,
      unreadable: current.unreadable.filter(name => definition.fields[name]?.secret),
      settings: current.value,
      updatedAt: current.updatedAt,
    };
  }

  return {
    start() {
      if (started || stopped) return;
      started = true;
      relay.started();
      if (!pending.stale) void runStartSequence();
      jobs.every('notify.relay', 10000, relayJob);
      jobs.every('notify.prune', 60 * 60 * 1000, pruneJob, { leader: true });
    },

    transitions(events) {
      return relay.relay(events);
    },

    enqueueDirect(event, uid, { exclude = [] } = {}) {
      return relay.direct(event, uid, { exclude });
    },

    async forgetSource(serviceId) {
      const result = await relay.forget(serviceId);
      refreshSoon();
      return result;
    },

    diskChanged,

    /**
     * The history-storage notice (server.mjs decides when writes fail and when they work
     * again): {failing: true, since} opens an episode unless one is open (also one an earlier
     * run left open), {failing: false} ends the open one.
     */
    storageChanged(state) {
      if (state?.failing) episodeChanged('storage', 'firing', state.since);
      else episodeChanged('storage', 'resolved', clock.wall());
    },

    /**
     * The since of the history-storage episode an earlier run announced and did not see end,
     * until this run reports a change of its own; null when there is none (or not known yet).
     */
    storageCarried() {
      return episodesLoaded && !reported.storage ? open.storage : null;
    },

    async emailChanged() {
      try {
        await outbox.channelChanged('email');
      } catch (error) {
        reportStorage(error);
        logOnce(
          'email-changed',
          'error',
          `Email delivery status could not be reset: ${safeErrorText(error)}`
        );
      }
      await refresh();
    },

    pushSettings: pushView,

    /**
     * Saves a change of the ntfy or Gotify settings (lib/settings.mjs update(): unknown fields
     * and invalid values refused, a secret set to null or '' cleared, an absent one kept) when
     * the document is still at `version` (when given). `audit` is the route's in-unit recorder
     * (channel.settings), which gets the diff with secrets and the ntfy topic only as
     * set/changed/cleared; `check()` (the route's re-check of its session) runs in that unit
     * too, before anything is written. The channel then resumes and a send in flight is
     * cancelled (sent again with the new settings), as a save of the email settings does.
     * Resolves what pushSettings() answers.
     */
    async savePush(channelId, patch, { version, actor, audit = null, check = () => {} } = {}) {
      const definition = PUSH_SETTINGS[channelId];
      if (!definition) throw deliveryError('channel_unknown');
      let result;
      try {
        result = await settings.update(definition.component, definition.key, patch, {
          ...(version === undefined ? {} : { ifVersion: version }),
          by: loginOf(actor),
          audit: (tx, { diff }) => {
            check();
            if (audit) audit(tx, { diff: pushAuditDiff(channelId, diff) });
          },
        });
      } catch (error) {
        throw settingsRefusal(channelId, error);
      }
      try {
        await loadPush(channelId);
      } catch (error) {
        reportStorage(error);
        pending.push = true;
      }
      if (result.diff.length) {
        logger.info?.(`${channelName(channelId)} settings were changed by ${loginOf(actor)}.`);
        try {
          await outbox.channelChanged(channelId);
        } catch (error) {
          reportStorage(error);
          logOnce(
            `push-changed:${channelId}`,
            'error',
            `${channelName(channelId)} delivery status could not be reset: ${safeErrorText(error)}`
          );
        }
      }
      await refresh().catch(() => {});
      return pushView(channelId);
    },

    /**
     * Sends one test notification with the saved ntfy or Gotify settings, straight through the
     * channel (not the queue): {accepted, message, status}. Its outcome goes into the channel's
     * status as a test email's does (an accepted test resumes a paused channel, since it used
     * the very settings the channel sends with). Refuses channel_not_set_up when the channel is
     * not set up; works while it is switched off, as a test email does.
     */
    async testPush(channelId, { signal } = {}) {
      const channel = pushChannels[channelId];
      if (!channel) throw deliveryError('channel_unknown');
      if (!setupOf(channelId).configured)
        throw deliveryError('channel_not_set_up', { variant: `${channelId}-test` });
      const outcome = await channel.send(
        {
          // A delivery id of its own, never one of a queued notification.
          uid: deliveryUid(newEventUid(), channelId, 'test'),
          channelId,
          kind: 'firing',
          attempt: 1,
          events: [
            {
              service: 'orbit',
              name: 'Uptime Goblin',
              kind: 'firing',
              category: 'system',
              rule: '__test',
              message: `This is a test notification from Uptime Goblin. ${channelName(channelId)} notifications work.`,
              time: clock.wall(),
            },
          ],
        },
        // A test works while the channel is switched off (its rows are skipped then).
        { signal, test: true }
      );
      const ok = outcome.type === 'accepted';
      const message = ok
        ? `${channelName(channelId)} accepted the test notification.`
        : outcome.reason || `${channelName(channelId)} did not accept the test notification.`;
      try {
        await outbox.recordTest(channelId, { accepted: ok, message: safeReason(message) });
      } catch (error) {
        reportStorage(error);
      }
      await refresh().catch(() => {});
      return { accepted: ok, message, status: outcome.status ?? null };
    },

    async flush({ timeoutMs = Infinity } = {}) {
      const deadline = clock.now() + timeoutMs;
      // Episode notices first: they reach the relay queue only once their since is written.
      await withTimeout(runEpisodes(), timeoutMs);
      await withTimeout(relay.idle(), Math.max(0, deadline - clock.now()));
      if (startSequence) await withTimeout(startSequence, deadline - clock.now());
      let done = outbox.inFlight === 0;
      if (deliveryAllowed())
        done = await outbox.flush({
          ignoreWindows: true,
          timeoutMs: Math.max(0, deadline - clock.now()),
        });
      await refresh().catch(() => {});
      return done;
    },

    async stop({ timeoutMs = 2000 } = {}) {
      stopped = true;
      if (refreshTimer) clock.clearTimeout(refreshTimer);
      refreshTimer = null;
      await Promise.all(JOBS.map(name => jobs.cancelAndWait(name, { timeoutMs: 2000 })));
      // An episode change being applied finishes its writes before control.sqlite closes.
      await withTimeout(episodeChain, timeoutMs);
      return outbox.stop({ timeoutMs });
    },

    snapshot,
    refresh,

    legacy() {
      return legacyView(snapshot(), { webhook, email: config.value.email ?? {} });
    },

    async deliveries({ filter = 'all', channel, cursor, limit = 50 } = {}) {
      if (!Object.hasOwn(FILTERS, filter))
        throw deliveryError('invalid_request', {
          detail: 'filter is all, active, problems or delivered',
        });
      if (channel !== undefined && channel !== null && !BUILT_IN_CHANNELS.includes(channel))
        throw deliveryError('invalid_request', { detail: 'channel is email or env-webhook' });
      // A cursor names where the next page starts: a control.sqlite row id (the saved rows
      // below it), or m:<n> (the rows kept in memory below that one, then the saved rows from
      // the newest).
      const memoryCursor = typeof cursor === 'string' && MEMORY_CURSOR.test(cursor) ? cursor : null;
      const before =
        memoryCursor !== null || cursor === undefined || cursor === null || cursor === ''
          ? null
          : Number(cursor);
      if (before !== null && !(Number.isSafeInteger(before) && before > 0))
        throw deliveryError('invalid_request', { detail: 'cursor is a delivery row id' });
      if (!(Number.isInteger(limit) && limit >= 1 && limit <= 100))
        throw deliveryError('invalid_request', { detail: 'limit is 1 to 100' });
      const query = { ...FILTERS[filter], ...(channel ? { channelId: channel } : {}) };
      let rows = [],
        statuses,
        nextCursor = null,
        digestDueAt = null;
      try {
        // A cursor only when an older row matches: a page that ends the history offers no
        // "Load more" that would find nothing. Each check reads at most one row.
        const more = async options => (await store.list({ ...query, ...options, limit: 1 })).length;
        // The rows kept in memory come first, page by page (amendment A30: before, the first
        // page listed at most `limit` of them and no later page any, so past `limit` the oldest
        // were never shown, and that page held up to twice `limit` rows).
        if (before === null) {
          rows = await store.list({
            ...query,
            part: 'memory',
            ...(memoryCursor !== null ? { beforeId: memoryCursor } : {}),
            limit,
          });
          if (rows.length >= limit) {
            const last = rows.at(-1).id;
            nextCursor =
              (await more({ part: 'memory', beforeId: last })) || (await more({ part: 'saved' }))
                ? last
                : null;
          }
        }
        // Then the saved rows, newest first, filling the page. A row saved from memory between
        // the two reads (a new id, the same delivery id) is listed once.
        if (rows.length < limit) {
          const room = limit - rows.length,
            listed = new Set(rows.map(row => row.uid));
          const saved = await store.list({
            ...query,
            part: 'saved',
            ...(before !== null ? { beforeId: before } : {}),
            limit: room,
          });
          rows = [...rows, ...saved.filter(row => !listed.has(row.uid))];
          if (saved.length >= room) {
            const last = saved.at(-1).id;
            nextCursor = (await more({ part: 'saved', beforeId: last })) ? String(last) : null;
          }
        }
        statuses = {};
        for (const id of BUILT_IN_CHANNELS) statuses[id] = await store.channel(id);
        if (rows.some(waitsForDigest)) digestDueAt = await digestDueOf(emailChannel);
      } catch (error) {
        throw unavailable(error);
      }
      const later = new Map();
      const deliveries = [];
      for (const row of rows) {
        let retryable = false;
        try {
          retryable = await outbox.retryable(row, {
            status: statuses[row.channelId],
            cache: later,
            ready,
          });
        } catch {
          retryable = false;
        }
        deliveries.push(
          deliveryView(row, {
            channel: statuses[row.channelId],
            retryable,
            digestDueAt: waitsForDigest(row) ? digestDueAt : null,
          })
        );
      }
      return { deliveries, nextCursor, unsaved: store.unsaved ?? 0 };
    },

    /**
     * Retry now for the delivery `uid`. `check()` (the route's re-check of its session) runs
     * right before the requeue, after every read: its error is passed on as it is, and nothing
     * is requeued.
     */
    async retry(uid, { actor, check = () => {} } = {}) {
      let result,
        ended = null;
      const current = () => {
        try {
          check();
        } catch (error) {
          ended = error;
          throw error;
        }
      };
      try {
        result = await outbox.retry(uid, { now: clock.wall(), ready, check: current });
      } catch (error) {
        if (ended !== null && error === ended) throw error;
        throw unavailable(error);
      }
      if (result.refused) {
        emit({
          action: 'delivery.retry',
          outcome: 'refused',
          actor: loginOf(actor),
          target: uid,
          detail: { reason: result.refused },
        });
        throw refusal(result, uid);
      }
      if (!result.retried) throw deliveryError('delivery_status_unavailable', { retryAfter: 15 });
      emit({
        action: 'delivery.retry',
        outcome: 'ok',
        actor: loginOf(actor),
        target: uid,
        detail: { retried: result.retried },
      });
      await refresh();
      let row, status, retryable;
      try {
        row = await store.find(uid);
        status = row ? await store.channel(row.channelId) : null;
        retryable = row ? await outbox.retryable(row, { status, ready }) : false;
      } catch (error) {
        throw unavailable(error);
      }
      return {
        retried: result.retried,
        delivery: row ? deliveryView(row, { channel: status, retryable }) : null,
      };
    },

    /**
     * Resumes `channelId`. `check()` (the route's re-check of its session) runs right before the
     * release, after every read: when it throws, the channel stays as it is. Resuming a webhook
     * held for a new signing key is the admin's word that receivers have its public key: the hold
     * ends first (signing.releaseHold(), which runs `check()` again in its write), and when it
     * cannot, the channel stays paused and Resume answers that error.
     */
    async resume(channelId, { actor, check = () => {} } = {}) {
      if (!BUILT_IN_CHANNELS.includes(channelId)) throw deliveryError('channel_unknown');
      const version = outbox.channelVersion(channelId);
      const holding = channelId === 'env-webhook' && signing.held;
      let status, held;
      try {
        status = await store.channel(channelId);
        // Held rows of a channel that is not paused (its last resume could not release them, the
        // disk being full): Resume releases them too, rather than answering "nothing to resume".
        held =
          !isPaused(status) &&
          (await store.list({ states: ['held'], channelId, limit: 1 })).length > 0;
      } catch (error) {
        throw unavailable(error);
      }
      let released = 0;
      if (isPaused(status) || held || holding) {
        const result = await outbox.resume(channelId, {
          ifStatus: status,
          ifVersion: version,
          beforeRelease: async () => {
            check();
            if (channelId === 'env-webhook' && signing.held)
              await signing.releaseHold({ actor: loginOf(actor), check });
          },
          canResume: () => channelId !== 'env-webhook' || !signing.held,
        });
        if (result === null) {
          await refresh();
          return {
            released: 0,
            channel: snapshot().channels.find(channel => channel.id === channelId),
          };
        }
        released = result;
        const login = loginOf(actor);
        logger.info?.(`${channelName(channelId)} notifications were resumed by ${login}.`);
        emit({
          action: 'channel.resume',
          outcome: 'ok',
          actor: login,
          target: channelId,
          detail: { released },
        });
      }
      await refresh();
      return { released, channel: snapshot().channels.find(channel => channel.id === channelId) };
    },

    emailSending() {
      return outbox.sending('email');
    },

    async recordTest({ accepted = false, message = '' } = {}) {
      try {
        await outbox.recordTest('email', {
          accepted: Boolean(accepted),
          message: safeReason(message) || (accepted ? '' : 'The test email was not accepted.'),
        });
      } catch (error) {
        reportStorage(error);
        logOnce(
          'record-test',
          'error',
          `The test email's result could not be recorded: ${safeErrorText(error)}`
        );
      }
      await refresh().catch(() => {});
    },

    signing: {
      describe: () => signing.describe(),
      publicKeys: () => signing.publicKeys(),
      async rotate(options) {
        const result = await signing.rotate(options);
        await refresh().catch(() => {});
        return result;
      },
    },

    /** For tests and diagnostics: the outbox and its store. */
    outbox,
    store,
    get keyring() {
      return keyring;
    },
  };
}
