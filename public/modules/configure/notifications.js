// Configure → Notifications (#configure/notifications): whether every alert got through. The page
// reads Uptime Goblin's delivery status (GET /api/notifications: a summary, each channel's health and the
// webhook signing key's state) and its delivery history, polls the status every 15 s with the
// dashboard (main.js), and offers Retry, Resume, the webhook's public key and Replace signing key.
// The ntfy and Gotify settings forms are configure/push.js's, drawn in a section of their own.
//
// This module also holds the delivery texts the other pages share, so each state is put into
// words in one place: the banners (core/load.js), the Alerts page's channel rows
// (configure/pages.js), the alerts dialog's lines (dashboard/dashboard.js) and the helpers of the
// Email page's status (configure/email.js). Where Uptime Goblin cannot read its delivery status, each of
// them says "Delivery status is unavailable." rather than showing older figures as current.
import { api } from '../core/api.js';
import { $, closeDialog, esc, icon, openDialog } from '../core/dom.js';
import { dateTime, when } from '../core/format.js';
import { focusable, holdFocus } from '../core/forms.js';
import { load, showNotices } from '../core/load.js';
import { page } from '../core/page.js';
import { patchHtml } from '../core/patch.js';
import { install as installPush, loadPush, pushSection } from './push.js';

/** The built-in channels, in the order Uptime Goblin lists them (spec D5, then ntfy and Gotify). */
const channelIds = Object.freeze(['email', 'env-webhook', 'ntfy', 'gotify']);
const channelNames = Object.freeze({
  email: 'Email',
  'env-webhook': 'Webhook',
  ntfy: 'ntfy',
  gotify: 'Gotify',
});
const pushIds = new Set(['ntfy', 'gotify']);
/** The link from a push channel's card or row to its settings form on this page. */
const pushLink = (id, cls = 'button') =>
  `<a class="${cls}" id="channel-${id}-configure" href="#push-${id}-title" data-in-page>Configure ${esc(channelNames[id])}</a>`;
export const channelName = id => channelNames[id] ?? String(id ?? 'Unknown channel');

/** "1 notification", "3 notifications". */
export const plural = (count, one, many = `${one}s`) =>
  `${count} ${Number(count) === 1 ? one : many}`;
/**
 * `text` as a sentence. Uptime Goblin's reasons and errors usually end with a full stop but need not
 * (an SMTP server's words, an older release), and the texts around them go on after it.
 */
export function sentence(text, fallback = 'Uptime Goblin gave no reason.') {
  const value = String(text ?? '').trim();
  if (!value) return fallback;
  return /[.!?…]$/.test(value) ? value : `${value}.`;
}

export const deliveryTexts = Object.freeze({
  unavailable: 'Delivery status is unavailable.',
  reading: 'Reading delivery status…',
  delivered: 'Delivered means the mail server or the receiver accepted it.',
  inApp: 'These in-app alerts remain available.',
  signed: 'Requests are signed (X-Goblin-Signature).',
  notSigned: 'Not signed yet: Uptime Goblin could not save the signing key (disk full).',
  noKey: 'Not signed yet: Uptime Goblin has not made a signing key yet.',
  copyFallback: 'Press Ctrl+C (⌘C on a Mac) to copy.',
  copied: 'Copied.',
  confirmUnconfirmed: 'This notification may already have arrived. Send it again?',
  confirmReplace:
    'Receivers that check signatures need the new public key within 24 hours: until then the current key also signs.',
});

/**
 * Whether the dashboard's delivery figures describe now. While Uptime Goblin cannot read its control
 * database it keeps sending the last figures it computed (their shape never changes for external
 * widgets) with `available: false`; this web app then says the status is unavailable instead.
 * A dashboard without the field (no delivery status at all) counts as unavailable too.
 */
export const deliveryKnown = (n = page.data?.notifications) => n?.available === true;

// GET /api/notifications, shared by the page, the Alerts page, the alerts dialog and the
// banners. A status younger than `freshMs` may be reused (and a request on its way joined) by a
// caller that asks for it, so a banner does not ask again what the page has just read. A failed
// read forgets the status: it is no longer known to be current.
const freshMs = 15000;
// `sent`/`kept`: the number of the last read sent and of the one the cache holds, so a slow
// read that is answered after a later one does not replace what that one found.
const statusCache = { status: null, at: 0, request: null, sent: 0, kept: 0 };
/**
 * The delivery status (the Status of the spec's §6.5). `maxAgeMs` 0 (the default) always asks
 * Uptime Goblin; a positive value reuses a status read that recently, or joins a read on its way.
 * Rejects as api() does: 503 `delivery_status_unavailable` when Uptime Goblin cannot read its control
 * database, an error without `status` when Uptime Goblin did not answer.
 */
export function deliveryStatus({ background = false, maxAgeMs = 0 } = {}) {
  if (maxAgeMs > 0) {
    if (statusCache.request) return statusCache.request;
    if (statusCache.status && performance.now() - statusCache.at < maxAgeMs)
      return Promise.resolve(statusCache.status);
  }
  const number = ++statusCache.sent;
  const request = api('/api/notifications', { background })
    .then(
      status => {
        if (number > statusCache.kept) {
          statusCache.kept = number;
          statusCache.status = status;
          statusCache.at = performance.now();
        }
        return status;
      },
      error => {
        if (number > statusCache.kept) {
          statusCache.kept = number;
          statusCache.status = null;
        }
        throw error;
      }
    )
    .finally(() => {
      if (statusCache.request === request) statusCache.request = null;
    });
  statusCache.request = request;
  return request;
}
/** The status read in the last 15 s, or null. */
function freshStatus() {
  return statusCache.status && performance.now() - statusCache.at < freshMs
    ? statusCache.status
    : null;
}

/**
 * What to say when `subject` (the delivery status, or the Audit log page's "The audit log") could
 * not be read: Uptime Goblin's reason, or that it did not answer.
 */
export function unavailableText(error, subject = 'Delivery status') {
  const reason =
    error?.status === undefined
      ? error?.timeout
        ? 'Uptime Goblin did not answer in time.'
        : 'Uptime Goblin is not answering.'
      : sentence(error.message);
  // Uptime Goblin's own 503 may already say it (delivery_status_unavailable).
  const unavailable = `${subject} is unavailable`;
  return reason.startsWith(unavailable) ? reason : `${unavailable}: ${reason}`;
}

/**
 * Whether a channel is set up and switched on. Only such a channel's notifications need
 * attention, as the dashboard's `attention` counts them (A45): one that is not (GOBLIN_WEBHOOK_URL
 * removed at a restart, email switched off) skips what it still holds when it comes to send it,
 * and Uptime Goblin offers no Retry for it.
 */
const setUp = c => !!c?.configured && !!c?.enabled;
/** A count (`waiting`, `retrying`, `failed`…) over the channels that are set up. */
const setUpCount = (channels, key) =>
  (Array.isArray(channels) ? channels : [])
    .filter(setUp)
    .reduce((sum, c) => sum + (Number(c.counts?.[key]) || 0), 0);

const notQueuedWindowMs = 24 * 60 * 60 * 1000;
/**
 * Alerts the backlog cap refused (A46): a refused alert has no row in the history, so the
 * summary and a banner say so, while the last refusal is less than 24 hours old (as D29 bounds
 * the failed count). `at` is when the last was refused, `count` how many since Uptime Goblin started.
 */
function notQueuedText(name, count, at) {
  const n = Number(count) || 0;
  return `${plural(n, 'notification')} for ${name} ${n === 1 ? 'was' : 'were'} not queued because its backlog was full (the last at ${dateTime(at)}): ${n === 1 ? 'it is' : 'they are'} not sent and not in the delivery history.`;
}
/** Whether a Channel's refusals by the backlog cap still need saying, as of `now` (A46). */
const notQueuedRecently = (c, now) =>
  setUp(c) && Number(c.notQueued) > 0 && !!c.notQueuedAt && c.notQueuedAt > now - notQueuedWindowMs;

/** A channel's state in words (spec §7.2 item 2): never colour alone. */
export function channelStateText(c) {
  switch (c?.state) {
    case 'not-configured':
      return 'Not set up';
    case 'off':
      return 'Off';
    case 'paused':
      return c.nextAttemptAt
        ? `Paused: ${sentence(c.pausedReason)} Uptime Goblin tries again at ${dateTime(c.nextAttemptAt)}.`
        : `Paused: ${sentence(c.pausedReason)}`;
    case 'circuit-open':
      return c.nextAttemptAt
        ? `Waiting before the next try (until ${dateTime(c.nextAttemptAt)})`
        : 'Waiting before the next try';
    case 'retrying':
      return c.nextAttemptAt ? `Retrying (next attempt ${dateTime(c.nextAttemptAt)})` : 'Retrying';
    case 'refusing':
      return c.lastError?.message
        ? `Refusing notifications: ${sentence(c.lastError.message)}`
        : 'Refusing notifications';
    case 'ok':
      return c.lastAttempt ? 'Working' : 'Ready (nothing sent yet)';
    default:
      return 'Unknown';
  }
}

// --- Banners (core/load.js draws them in #notice and #configuration-notice) -------------------

const openNotifications =
  ' <a class="notice-action text-link" href="#configure/notifications">Open Notifications</a>';
/** The full-disk banner (the first of all), as HTML, or null. */
export function diskNotice(disk = page.data?.disk) {
  if (!disk?.full) return null;
  const head = `The Uptime Goblin host's disk is full${disk.since ? ` (since ${dateTime(disk.since)})` : ''}. Settings cannot be saved until space is freed.`;
  // The reserve is what keeps sign-in and delivery working; say so only when it did.
  if (disk.reserveReleased && disk.freed !== false)
    return esc(
      `${head} Sign-in and alert delivery use space Uptime Goblin keeps in reserve; readings are not saved meanwhile.`
    );
  if (disk.reserveReleased)
    return esc(
      `${head} Uptime Goblin released the space it keeps in reserve, but the file system did not free it (snapshots or a shared pool keep it), so sign-in and alert delivery may fail too. Free space on the Uptime Goblin host.`
    );
  return esc(
    `${head} Uptime Goblin holds no space in reserve right now, so sign-in and alert delivery may fail too. Free space on the Uptime Goblin host.`
  );
}
/**
 * The delivery banner that applies first (after the disk and history ones), as HTML, or null:
 * the status unavailable, not being saved, a paused or refusing channel, alerts the backlog cap
 * refused in the last 24 hours (A46), failed notifications.
 * A webhook that refuses notifications is named with its last error, which the dashboard does not
 * carry: it is read from the delivery status (in the background, at most every 15 s while a
 * channel refuses), and the banner is drawn again once it is known.
 */
export function deliveryNotice(n = page.data?.notifications) {
  if (!n) return null;
  if (!deliveryKnown(n))
    return (
      esc(
        'Delivery status is unavailable: Uptime Goblin could not read its control database, so this page cannot tell whether alerts are being delivered.'
      ) + openNotifications
    );
  if (n.saving === false)
    return esc(
      `Notifications are not being saved${n.unsavedSince ? ` (since ${dateTime(n.unsavedSince)})` : ''}: Uptime Goblin cannot write its control database. Alerts are still sent. If Uptime Goblin restarts meanwhile, alerts not yet delivered are sent again after the restart, and Uptime Goblin's own notices still waiting are lost. Free disk space on the Uptime Goblin host.`
    );
  const attention = n.attention || {},
    channels = Array.isArray(n.channels) ? n.channels : [];
  const ordered = ids => channelIds.filter(id => Array.isArray(ids) && ids.includes(id));
  for (const id of ordered(attention.paused)) {
    const channel = channels.find(c => c.id === id);
    return (
      esc(`${channelName(id)} notifications are paused: ${sentence(channel?.pausedReason)}`) +
      openNotifications
    );
  }
  for (const id of ordered(attention.refusing)) {
    const message = refusalMessage(id, n);
    return (
      esc(
        message
          ? `${channelName(id)} is refusing notifications: ${sentence(message)}`
          : `${channelName(id)} is refusing notifications.`
      ) + openNotifications
    );
  }
  // The dashboard names the channels (the 24-hour window is Uptime Goblin's); each carries its figures.
  for (const id of ordered(attention.notQueued)) {
    const channel = channels.find(c => c.id === id);
    if (Number(channel?.notQueued) > 0 && channel.notQueuedAt)
      return (
        esc(notQueuedText(channelName(id), channel.notQueued, channel.notQueuedAt)) +
        openNotifications
      );
  }
  const failed = Number(attention.failed) || 0;
  if (failed > 0)
    return (
      esc(
        `${plural(failed, 'notification')} could not be delivered since the last successful one.`
      ) + openNotifications
    );
  return null;
}
// When the banners last read the status for a refusal's last error.
let refusalLookupAt = -Infinity;
function refusalMessage(id, n) {
  if (id === 'email' && n.email?.lastError?.message) return n.email.lastError.message;
  const known = freshStatus()?.channels?.find(c => c.id === id)?.lastError?.message;
  if (known) return known;
  // Not known: read the status (a fresh read, at most every 15 s, whatever it finds), then draw
  // the banners again. A status that still has no message for it leaves the banner without one
  // until the next read, so the redraw can never ask again at once.
  if (performance.now() - refusalLookupAt >= freshMs) {
    refusalLookupAt = performance.now();
    deliveryStatus({ background: true }).then(
      () => showNotices(),
      () => {}
    );
  }
  return null;
}

// --- The Alerts page's channel rows (configure/pages.js) ---------------------------------------

const alertsView = { status: null, problem: null };
/** The channel rows (Email, Webhook, ntfy, Gotify) of the Alerts page's "Delivery & thresholds" block. */
export function alertsDeliveryRows() {
  const { status, problem } = alertsView;
  const row = (id, symbol, text, action) =>
    `<div class="delivery-row" data-id="${esc(id)}"><span class="shortcut-icon">${icon(symbol, 21)}</span><div><strong>${esc(channelName(id))}</strong><p>${text}</p></div>${action}</div>`;
  const actions = {
    email: '<a class="button" href="#configure/email">Configure</a>',
    'env-webhook':
      '<a class="text-link" href="#configure/help" data-help="notifications">Setup guide ↗</a>',
    ntfy: '<a class="button" href="#configure/notifications">Configure</a>',
    gotify: '<a class="button" href="#configure/notifications">Configure</a>',
  };
  const symbols = { email: 'ticket', 'env-webhook': 'route', ntfy: 'activity', gotify: 'radar' };
  // ntfy and Gotify get a row once the status lists them (a release before them lists two).
  return channelIds
    .filter(id => !pushIds.has(id) || status?.channels?.some(channel => channel.id === id))
    .map(id => {
      if (problem || (!status && !deliveryKnown()))
        return row(id, symbols[id], esc(deliveryTexts.unavailable), actions[id]);
      if (!status) return row(id, symbols[id], esc(deliveryTexts.reading), actions[id]);
      const c = status.channels?.find(channel => channel.id === id);
      if (!c) return row(id, symbols[id], esc(deliveryTexts.unavailable), actions[id]);
      const parts = [channelStateText(c)];
      if (id === 'env-webhook') {
        if (c.state === 'not-configured')
          parts.push(
            'Set GOBLIN_WEBHOOK_URL on the Uptime Goblin server to send alerts to a webhook.'
          );
        else
          parts.push(
            status.signing?.configured && status.signing?.saved !== false
              ? 'Signed'
              : 'Not signed yet'
          );
      }
      if (pushIds.has(id) && c.state === 'not-configured')
        parts.push(
          `Set up ${channelName(id)} on the Notifications page to push alerts to a phone.`
        );
      return row(id, symbols[id], parts.map(esc).join(' · '), actions[id]);
    })
    .join('');
}
/**
 * Reads the delivery status for the Alerts page and draws its rows again. `background`: the
 * 15-second poll (a fresh read); otherwise a status read in the last 15 s is reused.
 */
export async function refreshAlertsDelivery({ background = false } = {}) {
  const target = $('#alerts-delivery');
  if (!target) return;
  try {
    alertsView.status = await deliveryStatus({ background, maxAgeMs: background ? 0 : freshMs });
    alertsView.problem = null;
  } catch (error) {
    alertsView.status = null;
    alertsView.problem = error;
  }
  if (target === $('#alerts-delivery')) patchHtml(target, alertsDeliveryRows());
}
/** Forgets what the Alerts page showed, so it starts from "Reading delivery status…". */
export function resetAlertsDelivery() {
  alertsView.status = freshStatus();
  alertsView.problem = null;
}

// --- The alerts dialog's delivery lines (dashboard/dashboard.js) --------------------------------

const attentionStates = new Set(['paused', 'refusing', 'retrying', 'circuit-open']);
const viewDeliveries =
  '<p class="inline-actions alerts-delivery-actions"><a class="button" href="#configure/notifications">View deliveries</a></p>';
/** Whether the dashboard says any channel needs attention (the dialog then reads the details). */
function dashboardNeedsAttention(n) {
  const a = n.attention || {};
  return (
    Number(a.retrying) > 0 ||
    Number(a.failed) > 0 ||
    (Array.isArray(a.paused) && a.paused.length > 0) ||
    (Array.isArray(a.refusing) && a.refusing.length > 0) ||
    (Array.isArray(n.channels) && n.channels.some(c => attentionStates.has(c.state)))
  );
}
const dialogView = { status: null, problem: null };
function retryWait(count, noun, c) {
  return `${plural(count, noun)} waiting to retry${c.nextAttemptAt ? ` (next attempt ${dateTime(c.nextAttemptAt)})` : ''}.`;
}
/** The email channel's reason for the dialog's "Email: {reason}", or null when it is fine. */
function emailReason(c) {
  if (c.state === 'paused') return sentence(c.pausedReason);
  if (c.state === 'refusing') return `refusing notifications: ${sentence(c.lastError?.message)}`;
  if ((c.state === 'retrying' || c.state === 'circuit-open') && c.counts?.retrying > 0)
    return retryWait(c.counts.retrying, 'message', c);
  return null;
}
function dialogLines(status) {
  const lines = [];
  for (const c of Array.isArray(status.channels) ? status.channels : []) {
    if (c.id === 'email') {
      const reason = emailReason(c);
      if (reason) lines.push(`${c.name || 'Email'}: ${reason}`);
      continue;
    }
    const name = c.name || channelName(c.id);
    if (c.state === 'paused')
      lines.push(`${name} is paused: ${sentence(c.pausedReason)} Alerts wait until it is resumed.`);
    else if (c.state === 'refusing')
      lines.push(`${name} is refusing notifications: ${sentence(c.lastError?.message)}`);
    else if ((c.state === 'retrying' || c.state === 'circuit-open') && c.counts?.retrying > 0)
      lines.push(`${name}: ${retryWait(c.counts.retrying, 'notification', c)}`);
  }
  const failed = setUpCount(status.channels, 'failed');
  if (failed > 0) lines.push(`${plural(failed, 'notification')} could not be delivered.`);
  return lines;
}
/** The dialog's delivery lines from what is known now, as HTML ('' when nothing needs saying). */
export function alertsDialogDelivery() {
  const n = page.data?.notifications;
  // A wall display may not read the delivery status, nor open the page that lists it.
  if (!n || document.body.classList.contains('display-mode')) return '';
  const unavailable = `<p class="detail-error">${esc(deliveryTexts.unavailable)} ${esc(deliveryTexts.inApp)}</p>${viewDeliveries}`;
  if (!deliveryKnown(n) || dialogView.problem) return unavailable;
  if (!dashboardNeedsAttention(n)) return '';
  if (!dialogView.status) return `<p class="settings-info">${esc(deliveryTexts.reading)}</p>`;
  const lines = dialogLines(dialogView.status);
  return lines.length
    ? lines
        .map(line => `<p class="detail-error">${esc(line)} ${esc(deliveryTexts.inApp)}</p>`)
        .join('') + viewDeliveries
    : '';
}
/**
 * Called when the alerts dialog opens: the dashboard says whether a channel needs attention, and
 * only then is the delivery status read for the lines' counts and reasons (a person opened the
 * dialog: a foreground read).
 */
export async function refreshAlertsDialog() {
  dialogView.status = null;
  dialogView.problem = null;
  const n = page.data?.notifications,
    target = $('#alerts-delivery-lines');
  if (!target) return;
  // Drawn at once from what the dashboard says (unavailable, nothing to say, or reading).
  patchHtml(target, alertsDialogDelivery());
  if (!n || !deliveryKnown(n) || !dashboardNeedsAttention(n)) return;
  if (document.body.classList.contains('display-mode')) return;
  try {
    dialogView.status = await deliveryStatus();
  } catch (error) {
    dialogView.problem = error;
  }
  if (target === $('#alerts-delivery-lines') && target.isConnected)
    patchHtml(target, alertsDialogDelivery());
}

// --- The Notifications page ---------------------------------------------------------------------

const historyFilters = Object.freeze([
  ['all', 'All'],
  ['active', 'Waiting and retrying'],
  ['problems', 'Problems'],
  ['delivered', 'Delivered'],
]);
const historyPageSize = 50,
  // Needs attention reads problems 100 at a time and keeps up to 20 rows: the next page is read
  // while fewer were found, at most 5 pages (see loadAttention()).
  attentionRead = 100,
  attentionPages = 5,
  attentionShown = 20;
const view = {
  status: null,
  problem: null,
  checkedAt: 0,
  filter: 'all',
  channel: '',
  history: { rows: [], nextCursor: null, unsaved: 0, problem: null, loaded: false, pages: 0 },
  attention: { rows: [], problem: null, loaded: false, unchecked: false },
  statusRequest: null,
  // The last status read begun, and the one shown: an older read answered late is dropped.
  statusSent: 0,
  statusShown: 0,
  historyGeneration: 0,
  attentionGeneration: 0,
};
const busy = new Set();

/** The page, drawn at once; loadNotifications() then reads what it shows. */
export function notificationsPage() {
  Object.assign(view, {
    status: null,
    problem: null,
    checkedAt: 0,
    filter: 'all',
    channel: '',
    history: { rows: [], nextCursor: null, unsaved: 0, problem: null, loaded: false, pages: 0 },
    attention: { rows: [], problem: null, loaded: false, unchecked: false },
    statusRequest: null,
  });
  view.historyGeneration++;
  view.attentionGeneration++;
  const select = (id, label, options, value) =>
    `<div class="field"><label for="${id}">${esc(label)}</label><select id="${id}">${options.map(([key, text]) => `<option value="${esc(key)}" ${key === value ? 'selected' : ''}>${esc(text)}</option>`).join('')}</select></div>`;
  return `<div id="notifications-page"><section class="settings-block" aria-labelledby="notifications-summary-title"><div class="settings-block-heading"><h3 id="notifications-summary-title">Summary</h3></div><p id="notifications-summary" class="notifications-summary" role="status">${esc(deliveryTexts.reading)}</p><p id="delivered-meaning" class="settings-info" tabindex="-1">${esc(deliveryTexts.delivered)} Uptime Goblin cannot know whether someone has read it.</p><div class="notifications-updated"><span id="notifications-updated"></span><button class="button" type="button" id="notifications-refresh">Refresh</button></div><p id="notifications-result" class="account-result" role="status" hidden></p></section><section class="settings-block" aria-labelledby="channels-title"><div class="settings-block-heading"><h3 id="channels-title" tabindex="-1">Channels</h3></div><div id="notification-channels" class="channel-cards">${channelCards()}</div></section>${pushSection()}<section class="settings-block" aria-labelledby="attention-title"><div class="settings-block-heading"><h3 id="attention-title" tabindex="-1">Needs attention</h3><p>Notifications waiting to retry, held while their channel is paused, or failed since the channel last delivered one (within the last 24 hours).</p></div><ul id="attention-list" class="delivery-list" aria-labelledby="attention-title">${attentionItems()}</ul></section><section class="settings-block" aria-labelledby="history-title"><div class="settings-block-heading"><h3 id="history-title" tabindex="-1">Delivery history</h3><p>Newest first. Notifications that finished are kept for 7 days (at most 50,000), failed ones for 30 days (at most 5,000).</p></div><div class="history-filters">${select('history-filter', 'Show', historyFilters, view.filter)}${select(
    'history-channel',
    'Channel',
    [['', 'All channels'], ...channelIds.map(id => [id, channelName(id)])],
    view.channel
  )}</div><ul id="history-list" class="delivery-list" aria-labelledby="history-title">${historyItems()}</ul><p id="history-unsaved" class="settings-info" hidden></p><p id="history-more-result" class="account-result failed" role="status" hidden></p><button class="button" type="button" id="history-more" hidden>Load more</button></section></div>`;
}
const pageShown = () => page.configurationSection === 'notifications' && !!$('#notifications-page');

/** Reads the status and both lists (the page opened, Refresh, or after an action). */
export async function loadNotifications() {
  if (!pageShown()) return;
  if (await statusRefused()) return;
  await Promise.all([loadAttention(), loadHistory(), loadPush()]);
}
/**
 * Reads the status, as before the lists. True when it was refused with 401: signing in again
 * was cancelled (api() asks first), or the session was refused again after it. The lists' reads
 * would only be refused too, and ask again while the dialog that Cancel is closing was in its
 * exit motion, so it took a second Cancel (sessions spec E4, delivery spec A64). They are not
 * read: each says why, as a refused read does, with Try again, until the page is signed in
 * again (reloadSection() in configure/pages.js reads them then).
 */
async function statusRefused() {
  const problem = await refreshStatus();
  if (problem?.status !== 401) return false;
  // The lists are drawn only while the summary shows this refusal: a later read, or the page
  // drawn again, reads its own.
  if (!pageShown() || view.problem !== problem) return true;
  // A list read begun before this one is dropped when it answers, as for a later read.
  view.attentionGeneration++;
  view.historyGeneration++;
  view.attention = { rows: [], problem, loaded: true, unchecked: false };
  patchHtml($('#attention-list'), attentionItems());
  view.history = { rows: [], nextCursor: null, unsaved: 0, problem, loaded: true, pages: 0 };
  renderHistory();
  return true;
}
/**
 * The 15-second poll (main.js, with the dashboard's): the status of whichever page shows it, as a
 * background request, so an open page does not keep an idle session signed in. The lists are
 * read again only after an action or Refresh.
 */
export function pollNotifications() {
  if (pageShown()) return refreshStatus({ background: true });
  if (page.configurationSection === 'alerts' && $('#alerts-delivery'))
    return refreshAlertsDelivery({ background: true });
  return Promise.resolve();
}
/** Reads the status and draws it; resolves to the read's error, or null when it worked. */
async function refreshStatus({ background = false } = {}) {
  // A poll that finds a read on its way leaves it be; a person's Refresh reads again.
  if (view.statusRequest && background) return view.statusRequest;
  const number = ++view.statusSent;
  const run = (async () => {
    const shown = $('#notifications-page');
    let status = null,
      problem = null;
    try {
      status = await deliveryStatus({ background });
    } catch (error) {
      problem = error;
    }
    if (!shown || shown !== $('#notifications-page') || number < view.statusShown) return problem;
    view.statusShown = number;
    view.status = problem ? null : status;
    view.problem = problem;
    view.checkedAt = Date.now();
    renderStatus();
    return problem;
  })();
  view.statusRequest = run;
  try {
    return await run;
  } finally {
    if (view.statusRequest === run) view.statusRequest = null;
  }
}

/** The summary sentence (spec §7.2 item 1): the first that applies, as HTML. */
function summaryHtml() {
  if (view.problem) return esc(unavailableText(view.problem));
  const s = view.status;
  if (!s) return esc(deliveryTexts.reading);
  // Counted over the channels that are set up (A45): a channel that is not skips what it holds.
  const channels = Array.isArray(s.channels) ? s.channels : [],
    count = key => setUpCount(channels, key);
  // Uptime Goblin's unsavedReason is the whole sentence ("Uptime Goblin cannot write its control database
  // (SQLITE_FULL)."), so it is said once, as the banner says it, and never followed by a second
  // full stop.
  if (s.saving === false)
    return esc(
      `Notifications are not being saved${s.unsavedSince ? ` (since ${dateTime(s.unsavedSince)})` : ''}: ${sentence(s.unsavedReason, 'Uptime Goblin cannot write its control database.')} Alerts are still sent.`
    );
  const paused = channels.find(c => c.state === 'paused');
  if (paused)
    return esc(
      `${paused.name || channelName(paused.id)} is paused: ${sentence(paused.pausedReason)}`
    );
  const refusing = channels.find(c => c.state === 'refusing');
  if (refusing)
    return esc(
      `${refusing.name || channelName(refusing.id)} is refusing notifications: ${sentence(refusing.lastError?.message)}`
    );
  // Before the counts: these alerts are in none of them (A46).
  const refused = channels.find(c => notQueuedRecently(c, s.updatedAt || Date.now()));
  if (refused)
    return esc(
      notQueuedText(refused.name || channelName(refused.id), refused.notQueued, refused.notQueuedAt)
    );
  if (count('failed') > 0) return esc(`${plural(count('failed'), 'notification')} failed.`);
  if (count('retrying') > 0) {
    const next = channels
      .filter(c => setUp(c) && c.counts?.retrying > 0 && c.nextAttemptAt)
      .map(c => c.nextAttemptAt)
      .sort((a, b) => a - b)[0];
    return esc(
      `${plural(count('retrying'), 'notification')} waiting to retry${next ? ` (next attempt ${dateTime(next)})` : ''}.`
    );
  }
  // Waiting for a first attempt (an email gathering others for one message) or being sent.
  const pending = count('waiting') + count('sending');
  if (pending > 0) return esc(`${plural(pending, 'notification')} waiting to be sent.`);
  if (!channels.some(setUp)) return esc('No notification channel is set up.');
  const delivered = channels
    .filter(setUp)
    .reduce((sum, c) => sum + (Number(c.deliveredTotal) || 0), 0);
  if (!channels.some(c => c.lastAttempt) && !delivered && !count('paused'))
    return esc('Nothing has been sent yet.');
  if (delivered > 0 && !count('paused'))
    return 'All notifications were <a class="text-link" href="#delivered-meaning" data-in-page>delivered</a>.';
  return esc('No notification is waiting.');
}
function renderStatus() {
  const summary = $('#notifications-summary');
  if (!summary) return;
  // Patched, so a sentence that stayed the same is not touched: it is a live region, read out
  // at every change, and the poll draws it every 15 s.
  patchHtml(summary, summaryHtml());
  const updated = $('#notifications-updated');
  const updatedText = view.problem
    ? `Could not read the status at ${when(view.checkedAt)}.`
    : view.status
      ? `Updated ${when(view.status.updatedAt || view.checkedAt)}`
      : '';
  if (updated.textContent !== updatedText) updated.textContent = updatedText;
  patchHtml($('#notification-channels'), channelCards());
  renderUnsaved();
}

const fact = (label, value) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`;
const timeOrNever = t => (t ? dateTime(t) : 'Never');
/**
 * A channel card's action, by its id ("channel-<id>-<action>"). The poll redraws the cards with
 * patchHtml(), which keeps a node by its id; an action without one would be matched by its place,
 * so Resume appearing before a focused "Show public key" would turn that very button into
 * Resume (the next Enter resuming the channel), and Resume going would turn the public-key
 * dialog's opener into "Replace signing key".
 */
const channelActionId = (channel, action) => `channel-${channel}-${action}`;
const configureEmail = `<a class="button" id="${channelActionId('email', 'configure')}" href="#configure/email">Configure email</a>`;
function channelCards() {
  const status = view.status;
  // Unknown: the figures last read are not shown as current (spec §7.2 item 2).
  if (!status)
    return channelIds
      .map(
        id =>
          `<article class="channel-card" data-id="${esc(id)}" aria-labelledby="channel-${esc(id)}-title"><h4 id="channel-${esc(id)}-title" tabindex="-1">${esc(channelName(id))}</h4><p class="channel-state" data-state="unknown">${esc(view.problem ? deliveryTexts.unavailable : deliveryTexts.reading)}</p><dl class="system-facts channel-facts">${fact('Last success', 'Unknown')}${fact('Last failure', 'Unknown')}</dl>${id === 'email' ? `<div class="channel-actions">${configureEmail}</div>` : pushIds.has(id) ? `<div class="channel-actions">${pushLink(id)}</div>` : ''}</article>`
      )
      .join('');
  return (Array.isArray(status.channels) ? status.channels : [])
    .map(c => channelCard(c, status))
    .join('');
}
function channelCard(c, status) {
  const id = esc(c.id),
    name = c.name || channelName(c.id),
    counts = c.counts || {},
    configured = c.state !== 'not-configured';
  const facts = configured
    ? [
        fact('Last success', timeOrNever(c.lastSuccess)),
        fact('Last failure', timeOrNever(c.lastFailure)),
        fact('Waiting to be sent', counts.waiting ?? 0),
        fact('Waiting to retry', counts.retrying ?? 0),
        fact('Sending', counts.sending ?? 0),
        fact('Held while paused', counts.paused ?? 0),
        fact(
          c.failedSince ? `Failed since ${dateTime(c.failedSince)}` : 'Failed',
          counts.failed ?? 0
        ),
        ...(c.oldestWaitingAt ? [fact('Oldest waiting', dateTime(c.oldestWaitingAt))] : []),
        // A46: alerts the backlog cap refused, which no row lists.
        ...(Number(c.notQueued) > 0
          ? [fact('Not queued since Uptime Goblin started (backlog full)', c.notQueued)]
          : []),
        ...(c.host ? [fact('Sends to', c.host)] : []),
      ].join('')
    : '';
  const lastError = c.lastError?.message
    ? `<p class="channel-error">Last error${c.lastError.time ? ` (${esc(dateTime(c.lastError.time))})` : ''}: ${esc(c.lastError.message)}</p>`
    : '';
  const actions = [];
  if (c.state === 'paused')
    actions.push(
      `<button class="button primary" type="button" id="${esc(channelActionId(c.id, 'resume'))}" data-resume-channel="${id}" aria-label="Resume ${esc(name)} notifications">Resume</button>`
    );
  if (c.id === 'email') actions.push(configureEmail);
  if (pushIds.has(c.id)) actions.push(pushLink(c.id));
  let signing = '';
  if (pushIds.has(c.id) && !configured)
    signing = `<p class="settings-info">Set up ${esc(name)} under Push notifications below to send alerts to it.</p>`;
  if (c.id === 'env-webhook') {
    const s = status.signing;
    if (!configured || !s)
      signing = `<p class="settings-info">Set GOBLIN_WEBHOOK_URL on the Uptime Goblin server and restart Uptime Goblin to send alerts to a webhook. See <a class="text-link" href="#configure/help" data-help="notifications">Help → Alerts and notifications</a>.</p>`;
    else if (s.saved === false)
      signing = `<p class="channel-signing">${esc(deliveryTexts.notSigned)}</p>`;
    else if (!s.configured) signing = `<p class="channel-signing">${esc(deliveryTexts.noKey)}</p>`;
    else {
      signing = `<p class="channel-signing">${esc(deliveryTexts.signed)}${s.previousUntil && s.previousUntil > Date.now() ? ` ${esc(`The previous key also signs until ${dateTime(s.previousUntil)}.`)}` : ''}</p>`;
      actions.push(
        `<button class="button" type="button" id="${channelActionId('env-webhook', 'public-key')}" data-public-key>Show public key</button>`,
        `<button class="button" type="button" id="${channelActionId('env-webhook', 'rotate')}" data-rotate-key>Replace signing key</button>`
      );
    }
  }
  return `<article class="channel-card" data-id="${id}" data-state="${esc(c.state)}" aria-labelledby="channel-${id}-title"><h4 id="channel-${id}-title" tabindex="-1">${esc(name)}</h4><p class="channel-state" data-state="${esc(c.state)}">${esc(channelStateText(c))}</p>${facts ? `<dl class="system-facts channel-facts">${facts}</dl>` : ''}${lastError}${signing}${actions.length ? `<div class="channel-actions">${actions.join('')}</div>` : ''}</article>`;
}

const statusTexts = Object.freeze({
  waiting: 'Waiting to be sent',
  retrying: 'Waiting to retry',
  sending: 'Sending now',
  paused: 'Held: the channel is paused',
  delivered: 'Delivered',
  failed: 'Failed',
  expired: 'Expired: not delivered within 24 hours',
  unconfirmed: 'May have arrived; Uptime Goblin could not confirm it.',
  replaced: 'Replaced: not sent',
  skipped: 'Skipped: not sent',
  'not-sent': 'Not sent',
});
// Rows that ended without a send: their last error is the reason.
const reasonStatuses = new Set(['replaced', 'skipped', 'not-sent']);
const deadStatuses = new Set(['failed', 'expired', 'unconfirmed']);
// Rows whose message went out: accepted, or sent with its acceptance unknown.
const sentStatuses = new Set(['delivered', 'unconfirmed']);
/** "the Plex alert on Webhook": names a row's Retry for a screen reader. */
function rowLabel(d) {
  const name = d.alert?.name || d.alert?.service || 'Uptime Goblin';
  return `the ${name} ${d.kind === 'resolved' ? 'recovery' : 'alert'} on ${channelName(d.channel)}`;
}
/** A row of a list; `list` ('attention' or 'history') keeps its ids apart from the other list's. */
function deliveryItem(d, list) {
  const name = d.alert?.name || d.alert?.service || 'Uptime Goblin',
    status = statusTexts[d.status] ?? 'Not sent',
    code = d.lastStatus ? `${d.channel === 'email' ? 'SMTP' : 'HTTP'} ${d.lastStatus}` : null,
    // A row takes the focus when its Retry goes (see refocus()): its name is its alert, kind,
    // channel and status, read from what it shows.
    idBase = `${list}-${String(d.uid).replace(/[^A-Za-z0-9_-]/g, '')}`;
  const facts = [
    fact('Created', dateTime(d.createdAt)),
    fact('Attempts', d.attempts ?? 0),
    ...(d.nextAttemptAt ? [fact('Next attempt', dateTime(d.nextAttemptAt))] : []),
    ...(d.sentAt ? [fact('Sent', dateTime(d.sentAt))] : []),
    ...(code ? [fact('Last answer', code)] : []),
    ...(d.lastError
      ? [fact(reasonStatuses.has(d.status) ? 'Reason' : 'Last error', d.lastError)]
      : []),
  ].join('');
  // The batch is given as the email is first tried, whatever the mail server then answers: only
  // a row that went out was sent as one email (amendment A59).
  const notes = [
    ...(d.batch
      ? [
          sentStatuses.has(d.status)
            ? 'Sent as one email with others'
            : 'Grouped into one email with others',
        ]
      : []),
    ...(d.saved === false ? ['Not saved (kept in memory)'] : []),
  ];
  return `<li class="delivery" data-id="${esc(d.uid)}" data-status="${esc(d.status)}" tabindex="-1" aria-labelledby="${idBase}-head ${idBase}-status"><div class="delivery-head" id="${idBase}-head"><strong>${esc(name)}</strong> <span class="delivery-kind">${d.kind === 'resolved' ? 'Recovered' : 'Alert'}</span> <span class="delivery-channel">${esc(channelName(d.channel))}</span></div><p class="delivery-status" id="${idBase}-status" data-status="${esc(d.status)}">${esc(status)}</p>${d.alert?.message ? `<p class="delivery-message">${esc(d.alert.message)}</p>` : ''}<dl class="system-facts delivery-facts">${facts}</dl>${notes.length ? `<p class="delivery-notes">${notes.map(esc).join(' · ')}</p>` : ''}${d.retryable ? `<div class="delivery-actions"><button class="button" type="button" data-retry-delivery="${esc(d.uid)}" data-status="${esc(d.status)}" aria-label="${esc(`Retry ${rowLabel(d)}`)}">Retry</button></div>` : ''}</li>`;
}
const listMessage = (html, retry = '') =>
  `<li class="delivery-empty">${html}${retry ? ` <button class="quiet-button" type="button" data-reload-notifications>Try again</button>` : ''}</li>`;
// Needs attention stopped reading before the problems ended (see loadAttention()).
const uncheckedText =
  'Older notifications were not checked: choose Problems under Delivery history to see them all.';
function attentionItems() {
  const a = view.attention;
  if (a.problem) return listMessage(esc(unavailableText(a.problem)), true);
  if (!a.loaded) return listMessage(esc('Reading notifications…'));
  if (!a.rows.length)
    return listMessage(
      esc(
        a.unchecked
          ? `None of the newest ${attentionRead * attentionPages} notifications with problems needs attention. ${uncheckedText}`
          : 'Nothing needs attention.'
      )
    );
  return (
    a.rows.map(d => deliveryItem(d, 'attention')).join('') +
    (a.unchecked ? listMessage(esc(uncheckedText)) : '')
  );
}
function historyItems() {
  const h = view.history;
  if (h.problem && !h.rows.length) return listMessage(esc(unavailableText(h.problem)), true);
  if (!h.loaded) return listMessage(esc('Reading notifications…'));
  if (!h.rows.length)
    return listMessage(
      esc(
        view.filter === 'all' && !view.channel
          ? 'No notification has been sent yet.'
          : 'No notification matches these filters.'
      )
    );
  return h.rows.map(d => deliveryItem(d, 'history')).join('');
}
/**
 * A row of a channel that is set up (A45) counts for attention while it waits to retry or is
 * held, and a dead one while it failed after the channel's last success (D29).
 */
function needsAttention(d, channels) {
  const channel = channels.find(c => c.id === d.channel);
  if (!setUp(channel)) return false;
  if (d.status === 'retrying' || d.status === 'paused') return true;
  if (!deadStatuses.has(d.status)) return false;
  return Number(d.updatedAt) > Number(channel.failedSince || 0);
}
/**
 * Needs attention: up to 20 problems that still need it. Uptime Goblin's Problems filter holds every
 * failed row of the last 30 days, and only those after their channel's failedSince count here
 * (D29), so a page of older failures can hold none of them while an older row still retries or
 * waits on a paused channel: the next page is read until 20 are found or the problems end, at
 * most 5 pages; beyond that the list says older notifications were not checked rather than that
 * nothing needs attention.
 */
async function loadAttention() {
  const generation = ++view.attentionGeneration;
  let rows = [],
    problem = null,
    unchecked = false;
  try {
    // Without the channels' failedSince, which dead rows still count cannot be told.
    if (!view.status) throw view.problem ?? new Error('Uptime Goblin is not answering.');
    const channels = view.status.channels || [],
      seen = new Set();
    let cursor = null;
    for (let read = 0; read < attentionPages; read++) {
      const query = new URLSearchParams({ filter: 'problems', limit: String(attentionRead) });
      if (cursor) query.set('cursor', cursor);
      const answer = await api(`/api/notifications/deliveries?${query}`);
      // A later read (Refresh, an action) or another page replaced this one: stop asking.
      if (generation !== view.attentionGeneration || !pageShown()) return;
      for (const d of Array.isArray(answer?.deliveries) ? answer.deliveries : [])
        if (!seen.has(d.uid) && needsAttention(d, channels)) {
          seen.add(d.uid);
          rows.push(d);
        }
      cursor = typeof answer?.nextCursor === 'string' ? answer.nextCursor : null;
      if (rows.length >= attentionShown || !cursor) break;
    }
    unchecked = rows.length < attentionShown && !!cursor;
    rows = rows.slice(0, attentionShown);
  } catch (error) {
    problem = error;
    rows = [];
  }
  if (generation !== view.attentionGeneration || !pageShown()) return;
  view.attention = { rows, problem, loaded: true, unchecked };
  patchHtml($('#attention-list'), attentionItems());
}
/**
 * Where a history cursor stands in the list: the rows kept in memory (m:<n>) come before every
 * saved row, and within each part the higher number is the newer row.
 */
const cursorRank = cursor =>
  cursor.startsWith('m:') ? [1, Number(cursor.slice(2))] : [0, Number(cursor)];
/** Whether the rows read up to `cursor` stop short of `depth` (null: the end of the history). */
function shallower(cursor, depth) {
  if (depth === null) return true;
  const [part, n] = cursorRank(cursor),
    [depthPart, depthN] = cursorRank(depth);
  return part !== depthPart ? part > depthPart : n > depthN;
}
// A deep read (after an action) reads at most this many pages more than were shown: rows that
// arrived meanwhile push the old ones down, and nothing can make it read without end.
const deepExtraPages = 4;
/**
 * The first page of the history (`more`: the next page, appended). `deep`: the first page and
 * then the next ones until the rows shown before are covered, so after an action (Retry, Resume)
 * a row that Load more brought in is still listed, with its control, and the focus stays on it
 * (§7.4); a reload to the first page alone dropped those rows and sent the focus to the
 * heading. Rows kept in memory while Uptime Goblin cannot write its control database come first, page by
 * page (their cursors are m:<n>, A30); `unsaved` says how many there are in all.
 */
async function loadHistory({ more = false, deep = false } = {}) {
  const generation = ++view.historyGeneration,
    h = view.history;
  const read = cursor => {
    const query = new URLSearchParams({ filter: view.filter, limit: String(historyPageSize) });
    if (view.channel) query.set('channel', view.channel);
    if (cursor) query.set('cursor', cursor);
    return api(`/api/notifications/deliveries?${query}`);
  };
  // How deep the rows shown reach: the cursor after the last page read (null: the end).
  const depth = deep && h.loaded && h.pages > 1 ? { cursor: h.nextCursor, pages: h.pages } : null;
  const answers = [];
  let cursor = more ? h.nextCursor : null,
    problem = null;
  try {
    for (;;) {
      const answer = await read(cursor);
      if (generation !== view.historyGeneration || !pageShown()) return [];
      answers.push(answer);
      cursor = typeof answer?.nextCursor === 'string' ? answer.nextCursor : null;
      if (
        !depth ||
        cursor === null ||
        answers.length >= depth.pages + deepExtraPages ||
        !shallower(cursor, depth.cursor)
      )
        break;
    }
  } catch (error) {
    problem = error;
  }
  if (generation !== view.historyGeneration || !pageShown()) return [];
  const rowsOf = answer => (Array.isArray(answer?.deliveries) ? answer.deliveries : []);
  // A row saved from memory between two reads comes again with a new cursor: listed once.
  const fresh = (known, rows) =>
    rows.filter(d => {
      if (known.has(d.uid)) return false;
      known.add(d.uid);
      return true;
    });
  let added = [];
  if (more) {
    // A failed "Load more" keeps what is shown, with its cursor.
    if (problem) view.history = { ...h, problem };
    else {
      added = fresh(new Set(h.rows.map(d => d.uid)), rowsOf(answers[0]));
      view.history = {
        ...h,
        rows: [...h.rows, ...added],
        nextCursor: cursor,
        problem: null,
        loaded: true,
        pages: h.pages + 1,
      };
    }
  } else if (!answers.length) {
    // A failed first page shows why.
    view.history = { rows: [], nextCursor: null, unsaved: 0, problem, loaded: true, pages: 0 };
  } else {
    // A later page of a deep read that failed keeps the pages read, and its cursor for Load
    // more, which says why beside it (A16).
    added = fresh(new Set(), answers.flatMap(rowsOf));
    view.history = {
      rows: added,
      nextCursor: cursor,
      unsaved: Number(answers[0]?.unsaved) || 0,
      problem,
      loaded: true,
      pages: answers.length,
    };
  }
  renderHistory();
  return added;
}
function renderHistory() {
  const h = view.history;
  patchHtml($('#history-list'), historyItems());
  renderUnsaved();
  // A "Load more" that failed keeps the rows shown and its cursor; it says so beside the button,
  // in a status region, so the older history is never silently missing.
  const failed = $('#history-more-result'),
    failedText =
      h.problem && h.rows.length
        ? `${unavailableText(h.problem)} Older notifications were not read: press Load more to try again.`
        : '';
  failed.hidden = !failedText;
  if (failed.textContent !== failedText) failed.textContent = failedText;
  $('#history-more').hidden = !h.nextCursor;
}
/**
 * The note on rows kept in memory. "Cannot write" only while the status says so: once Uptime Goblin
 * saves again, the rows still in memory are ones queued before that, saved when they finish.
 * They are listed first, page by page (A30), but only where they match the filter and channel
 * chosen: under a filter the note says so, and says that none of them matches when the list
 * shows none, rather than calling them listed first. Drawn with the history and again with each
 * status read, which may come after it.
 */
function renderUnsaved() {
  const unsaved = $('#history-unsaved'),
    n = Number(view.history.unsaved) || 0;
  if (!unsaved) return;
  const one = n === 1,
    filtered = view.filter !== 'all' || !!view.channel,
    shown = view.history.rows.filter(d => d.saved === false).length;
  const listed =
    filtered && !shown
      ? one
        ? 'It does not match these filters.'
        : 'None of them matches these filters.'
      : filtered && shown < n
        ? 'Those that match these filters are listed first.'
        : one
          ? 'It is listed first.'
          : 'They are listed first.';
  const text = !n
    ? ''
    : view.status?.saving === false
      ? `${plural(n, 'notification is', 'notifications are')} kept in memory only, because Uptime Goblin cannot write its control database. ${listed}`
      : `${plural(n, 'notification is', 'notifications are')} still kept in memory: ${one ? 'it was' : 'they were'} queued while Uptime Goblin could not write its control database, and ${one ? 'is' : 'are'} saved once finished. ${listed}`;
  unsaved.hidden = !text;
  if (unsaved.textContent !== text) unsaved.textContent = text;
}

// --- Actions ---------------------------------------------------------------------------------

/** Says what an action did (or why not) in the page's status region. */
function say(text, failed = false) {
  const result = $('#notifications-result');
  if (!result) return;
  result.textContent = text;
  result.hidden = !text;
  result.classList.toggle('failed', failed);
}
/** What an action that failed says: Uptime Goblin's reason, or that it did not answer. */
function failure(error, unanswered) {
  if (error.status === undefined) return unanswered;
  return error.message;
}
/**
 * After an action: the status, both lists and the dashboard's banners as they are now. The
 * history is read as deep as it was shown, so the acted-on row keeps its place and the focus.
 * A status read refused with 401 (the session ended after the action) stops there, as in
 * loadNotifications(): the lists and load() would ask to sign in again after Cancel.
 */
async function reloadAfterAction() {
  if (await statusRefused()) return;
  await Promise.all([loadAttention(), loadHistory({ deep: true }), load()]);
}
/**
 * Gives the focus back after the lists were drawn again: to the same control when it is still
 * there, else to the next control of its row (a delivery, or a channel's card), else to the row
 * itself (a delivery) or its heading (a card), else to `fallback` (the section's heading). Only
 * when the focus was on that control: it is lost to <body> while the control is disabled.
 */
function refocus(had, { list, uid, selector, fallback }) {
  const now = document.activeElement;
  if (!had || (now && now !== document.body && focusable(now))) return;
  const row = list && uid ? list.querySelector(`:scope > [data-id="${CSS.escape(uid)}"]`) : null;
  const same = row?.querySelector(selector);
  if (same && focusable(same)) return same.focus({ preventScroll: true });
  const next = row && [...row.querySelectorAll('button, a[href]')].find(focusable);
  if (next) return next.focus({ preventScroll: true });
  const self = row?.hasAttribute('tabindex') ? row : row?.querySelector('[tabindex="-1"]');
  (self || fallback)?.focus({ preventScroll: true });
}

async function retryDelivery(button) {
  const uid = button.dataset.retryDelivery,
    list = button.closest('ul');
  if (busy.has(uid)) return;
  // A notification that may have arrived is sent again only when the admin says so. The question
  // gives the focus back to Retry once it has closed (see confirmAction()).
  if (
    button.dataset.status === 'unconfirmed' &&
    !(await confirmAction({
      title: 'Send it again?',
      text: deliveryTexts.confirmUnconfirmed,
      accept: 'Send again',
      opener: button,
    }))
  )
    return;
  if (busy.has(uid) || !button.isConnected) return;
  busy.add(uid);
  const had = document.activeElement === button;
  if (had) page.busyFocus = button;
  button.disabled = true;
  say('');
  try {
    const answer = await api(`/api/notifications/deliveries/${encodeURIComponent(uid)}/retry`, {
      method: 'POST',
      body: '{}',
    });
    const retried = Number(answer?.retried) || 1;
    say(
      retried > 1
        ? `Uptime Goblin sends these ${retried} notifications again now, as one email.`
        : 'Uptime Goblin sends this notification again now.'
    );
  } catch (error) {
    say(
      failure(
        error,
        'Uptime Goblin did not confirm the retry. Refresh to see whether the notification is waiting again.'
      ),
      true
    );
    // 401: signing in again was cancelled. Reading again would only ask again.
    if (error.status === 401) {
      button.disabled = false;
      return;
    }
  } finally {
    busy.delete(uid);
    if (page.busyFocus === button) page.busyFocus = null;
  }
  await reloadAfterAction();
  if (button.isConnected) button.disabled = false;
  refocus(had, {
    list,
    uid,
    selector: '[data-retry-delivery]',
    fallback: list?.id === 'attention-list' ? $('#attention-title') : $('#history-title'),
  });
}

async function resumeChannel(button) {
  const id = button.dataset.resumeChannel,
    name = channelName(id);
  if (busy.has(`resume:${id}`)) return;
  busy.add(`resume:${id}`);
  const had = document.activeElement === button;
  if (had) page.busyFocus = button;
  button.disabled = true;
  say('');
  try {
    const answer = await api(`/api/notifications/channels/${encodeURIComponent(id)}/resume`, {
      method: 'POST',
      body: '{}',
    });
    const released = Number(answer?.released) || 0;
    say(
      released
        ? `${name} notifications resumed: ${plural(released, 'held notification')} ${released === 1 ? 'is' : 'are'} sent now.`
        : `${name} notifications resumed.`
    );
  } catch (error) {
    say(
      failure(
        error,
        `Uptime Goblin did not confirm that ${name} notifications resumed. Refresh to see the channel's state.`
      ),
      true
    );
    if (error.status === 401) {
      button.disabled = false;
      return;
    }
  } finally {
    busy.delete(`resume:${id}`);
    if (page.busyFocus === button) page.busyFocus = null;
  }
  await reloadAfterAction();
  if (button.isConnected) button.disabled = false;
  // Resume goes once the channel works again: the focus moves on within its card.
  refocus(had, {
    list: $('#notification-channels'),
    uid: id,
    selector: '[data-resume-channel]',
    fallback: $('#channels-title'),
  });
}

/**
 * `element`, or the control now in its place (the same id) when a redraw replaced it while a
 * dialog was open (the channel cards drawn without a status, then with one).
 */
const stillThere = element =>
  element?.isConnected ? element : element?.id ? document.getElementById(element.id) : null;

// The public-key dialog. The public key is not a secret; the dialog's fields are still filled
// only while it is open, so a key replaced meanwhile is never shown from an earlier read.
let keyOpener = null;
function showPublicKey({ publicKey, keyId, previous, previousUntil }, opener) {
  const dialog = $('#signing-key-dialog'),
    field = $('#signing-key-value');
  keyOpener = opener;
  field.value = publicKey;
  $('#signing-key-id').textContent = `Key id ${keyId} (X-Goblin-Signature names it in each v1a).`;
  const previousText = $('#signing-key-previous');
  previousText.hidden = !(previous && previousUntil && previousUntil > Date.now());
  previousText.textContent = previousText.hidden
    ? ''
    : `The previous key (key id ${previous.keyId}) also signs until ${dateTime(previousUntil)}.`;
  $('#signing-key-copy-result').textContent = '';
  openDialog(dialog);
  field.focus();
  field.select();
}
function forgetPublicKey() {
  $('#signing-key-value').value = '';
  $('#signing-key-id').textContent = '';
  $('#signing-key-copy-result').textContent = '';
}
function closePublicKey() {
  forgetPublicKey();
  closeDialog($('#signing-key-dialog'));
}
async function copyPublicKey() {
  const field = $('#signing-key-value'),
    note = $('#signing-key-copy-result');
  try {
    // Missing outside a secure context (Uptime Goblin on a plain-HTTP LAN address), and refused when
    // the browser does not allow it: the field's text is selected instead.
    if (!navigator.clipboard?.writeText) throw new Error('No clipboard');
    await navigator.clipboard.writeText(field.value);
    note.textContent = deliveryTexts.copied;
  } catch {
    field.focus();
    field.select();
    note.textContent = deliveryTexts.copyFallback;
  }
}
const readPublicKey = () => api('/api/notifications/webhook/public-key');
async function openPublicKey(button) {
  if (busy.has('signing')) return;
  busy.add('signing');
  const release = holdFocus(button);
  button.disabled = true;
  say('');
  try {
    const answer = await readPublicKey();
    button.disabled = false;
    release();
    showPublicKey(answer, button);
  } catch (error) {
    button.disabled = false;
    release();
    say(failure(error, 'Uptime Goblin did not answer. Try again in a moment.'), true);
  } finally {
    busy.delete('signing');
  }
}
/**
 * What Replace signing key asks. Uptime Goblin keeps one previous key (D7): while the one replaced last
 * still signs (the card says until when), a Replace stops it signing at once, and receivers
 * still on it reject every alert (a webhook answering 401 or 403 pauses). So the confirmation
 * says so before it happens (amendment A56). `signing` is the card's status.
 */
function replaceText(signing, now = Date.now()) {
  if (!(signing?.previousUntil > now)) return deliveryTexts.confirmReplace;
  return `${deliveryTexts.confirmReplace} Uptime Goblin keeps only one previous key, so the one that signs until ${dateTime(signing.previousUntil)} stops signing now: receivers that still use it reject alerts until they have the new public key.`;
}
async function rotateKey(button) {
  if (busy.has('signing')) return;
  if (
    !(await confirmAction({
      title: 'Replace the signing key?',
      text: replaceText(view.status?.signing),
      accept: 'Replace signing key',
      opener: button,
    }))
  )
    return;
  busy.add('signing');
  const release = holdFocus(button);
  button.disabled = true;
  say('');
  let replaced = null;
  try {
    replaced = await api('/api/notifications/webhook/signing-secret', {
      method: 'POST',
      body: '{}',
    });
  } catch (error) {
    button.disabled = false;
    release();
    busy.delete('signing');
    say(
      failure(
        error,
        'Uptime Goblin did not confirm the new signing key, so it may or may not have been replaced. Refresh to see when the current key was made.'
      ),
      true
    );
    return;
  }
  say(
    replaced?.previousUntil
      ? `Uptime Goblin replaced the signing key. The previous one also signs until ${dateTime(replaced.previousUntil)}.`
      : 'Uptime Goblin replaced the signing key.'
  );
  let shown = null;
  try {
    shown = await readPublicKey();
  } catch (error) {
    say(
      `Uptime Goblin replaced the signing key, but could not show its public key: ${failure(error, 'Uptime Goblin did not answer.')}`,
      true
    );
  }
  button.disabled = false;
  release();
  busy.delete('signing');
  await refreshStatus();
  if (shown) showPublicKey(shown, stillThere(button) ?? $('[data-rotate-key]'));
}

// The confirmation dialog (Retry of a notification that may have arrived, Replace signing key).
let pendingConfirm = null;
/**
 * Resolves true for the dialog's action, false for Cancel, Escape or a click outside, once the
 * dialog has closed (its exit motion included). Until then the rest of the page is inert, so the
 * focus could not go back to `opener`; the browser gives it back as the dialog closes, and only
 * then does the action begin, which may disable `opener` while its request is on its way.
 */
function confirmAction({ title, text, accept, opener }) {
  const dialog = $('#delivery-confirm-dialog');
  if (pendingConfirm) return Promise.resolve(false);
  $('#delivery-confirm-title').textContent = title;
  $('#delivery-confirm-text').textContent = text;
  $('#delivery-confirm-accept').textContent = accept;
  return new Promise(resolve => {
    pendingConfirm = { resolve, opener, value: false };
    openDialog(dialog);
    // Cancel has the focus, so Enter or Space alone never sends anything.
    $('#delivery-confirm-cancel').focus();
  });
}
function answerConfirm(value) {
  if (!pendingConfirm) return;
  pendingConfirm.value = value;
  closeDialog($('#delivery-confirm-dialog'));
}
function confirmClosed() {
  const pending = pendingConfirm;
  pendingConfirm = null;
  if (!pending) return;
  const opener = stillThere(pending.opener);
  if (focusable(opener) && document.activeElement !== opener) opener.focus({ preventScroll: true });
  pending.resolve(pending.value);
}

/**
 * Registers this module’s event handlers (and, where noted, reads what the page needs at
 * start). main.js calls it once, keeping the order in which public/app.js registered them.
 */
export function install() {
  // ntfy and Gotify: a save or a test reads the status again, so the cards say what changed.
  installPush({ refresh: () => refreshStatus() });
  document.addEventListener('click', async e => {
    // "delivered" in the summary leads to the sentence that says what it means; it is not a
    // route (configure/events.js leaves [data-in-page] links alone).
    const inPage = e.target.closest('a[data-in-page]');
    if (inPage) {
      e.preventDefault();
      const target = document.getElementById(inPage.getAttribute('href').slice(1));
      target?.focus({ preventScroll: true });
      target?.scrollIntoView({ block: 'nearest' });
      return;
    }
    const reload = e.target.closest('#notifications-refresh, [data-reload-notifications]');
    if (reload) {
      // Try again sits in its list's message, which the rows replace once the read works, so
      // the focus it had would fall to <body> (§7.4). It moves to the first row of that list,
      // or to the list's heading while the list still shows a message; a read that fails again
      // keeps the same message and button, and the focus with it.
      const list = reload.matches('[data-reload-notifications]') ? reload.closest('ul') : null,
        had = document.activeElement === reload;
      say('');
      await loadNotifications();
      const active = document.activeElement;
      if (list?.isConnected && had && (!active || active === document.body || !focusable(active)))
        (
          list.querySelector(':scope > li.delivery') ??
          $(list.id === 'attention-list' ? '#attention-title' : '#history-title')
        )?.focus({ preventScroll: true });
      return;
    }
    const retry = e.target.closest('[data-retry-delivery]');
    if (retry) {
      await retryDelivery(retry);
      return;
    }
    const resume = e.target.closest('[data-resume-channel]');
    if (resume) {
      await resumeChannel(resume);
      return;
    }
    const show = e.target.closest('[data-public-key]');
    if (show) {
      await openPublicKey(show);
      return;
    }
    const rotate = e.target.closest('[data-rotate-key]');
    if (rotate) {
      await rotateKey(rotate);
      return;
    }
    const more = e.target.closest('#history-more');
    if (more && !busy.has('more')) {
      busy.add('more');
      const release = holdFocus(more);
      more.disabled = true;
      let added = [];
      try {
        added = await loadHistory({ more: true });
      } finally {
        more.disabled = false;
        busy.delete('more');
        release();
      }
      // The last page: Load more goes, and the focus moves to the first row it added, or, when
      // it added none (the older rows went meanwhile), to the last row of the list (spec §7.4:
      // never to <body>).
      if (more.hidden && document.activeElement === document.body)
        (added.length
          ? $(`#history-list [data-id="${CSS.escape(added[0].uid)}"]`)
          : ($('#history-list > li.delivery:last-child') ?? $('#history-title'))
        )?.focus({ preventScroll: true });
      return;
    }
    if (e.target.closest('#signing-key-copy')) {
      await copyPublicKey();
      return;
    }
    if (e.target.closest('#signing-key-close')) {
      closePublicKey();
      return;
    }
    if (e.target.closest('#delivery-confirm-cancel')) answerConfirm(false);
    else if (e.target.closest('#delivery-confirm-accept')) answerConfirm(true);
  });
  document.addEventListener('change', async e => {
    if (e.target.id !== 'history-filter' && e.target.id !== 'history-channel') return;
    view.filter = $('#history-filter').value;
    view.channel = $('#history-channel').value;
    await loadHistory();
  });
  const keyDialog = $('#signing-key-dialog'),
    confirmDialog = $('#delivery-confirm-dialog');
  // Escape (and a phone's back gesture) closes them with the same exit motion as Close.
  keyDialog.addEventListener('cancel', e => {
    e.preventDefault();
    closePublicKey();
  });
  keyDialog.addEventListener('close', () => {
    forgetPublicKey();
    // Show public key, or Replace signing key, as the card has it now.
    const opener = stillThere(keyOpener);
    keyOpener = null;
    if (focusable(opener)) opener.focus({ preventScroll: true });
  });
  confirmDialog.addEventListener('cancel', e => {
    e.preventDefault();
    answerConfirm(false);
  });
  // However it closed (a second Escape that Chromium does not let a page cancel included).
  confirmDialog.addEventListener('close', confirmClosed);
  // A click on the dimmed area outside closes them too, as for the other dialogs.
  for (const [dialog, close] of [
    [keyDialog, closePublicKey],
    [confirmDialog, () => answerConfirm(false)],
  ]) {
    let pressedOutside = false;
    const outside = e => {
      if (e.target !== dialog) return false;
      const box = dialog.getBoundingClientRect();
      return (
        e.clientX < box.left ||
        e.clientX > box.right ||
        e.clientY < box.top ||
        e.clientY > box.bottom
      );
    };
    dialog.addEventListener('pointerdown', e => (pressedOutside = outside(e)));
    dialog.addEventListener('click', e => {
      const close_ = pressedOutside && outside(e);
      pressedOutside = false;
      if (close_) close();
    });
  }
}
