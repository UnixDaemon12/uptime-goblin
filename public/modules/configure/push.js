// The ntfy and Gotify settings on Configure → Notifications: one form each, with Save and
// Send test notification. The forms sit in their own section, apart from the channel cards the
// 15-second poll redraws, so a poll never replaces what is being typed.
//
// Tokens and passwords are write-only: Uptime Goblin answers them only as {set: true|false}, so their
// fields start empty ("Saved · leave blank to keep"), a value is sent only when one was typed,
// and a checkbox clears the saved one. Every check made here is made again by Uptime Goblin, which
// refuses what does not pass (400 channel_settings_invalid) without saving anything.
import { api } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { field, lockForm, selectField } from '../core/forms.js';

export const pushChannels = Object.freeze(['ntfy', 'gotify']);
const names = Object.freeze({ ntfy: 'ntfy', gotify: 'Gotify' });
const ntfyPriorities = Object.freeze([
  ['1', '1 · min'],
  ['2', '2 · low'],
  ['3', '3 · default'],
  ['4', '4 · high'],
  ['5', '5 · max (urgent)'],
]);
const gotifyPriorities = Object.freeze(
  Array.from({ length: 11 }, (_, n) => [
    String(n),
    n === 0
      ? '0 · no notification'
      : n <= 3
        ? `${n} · low`
        : n <= 7
          ? `${n} · normal`
          : `${n} · high`,
  ])
);
/** Client-side copies of Uptime Goblin's rules (lib/notify/channels/*.mjs); Uptime Goblin checks them again. */
export const pushRules = Object.freeze({
  topic: /^[A-Za-z0-9_-]{1,64}$/,
  tag: /^[A-Za-z0-9_+-]{1,32}$/,
  token: /^[\x21-\x7e]{1,512}$/,
  maxTags: 5,
});

// What each form last read: the version it saves against and which secrets are saved.
const state = { ntfy: null, gotify: null };
let refreshStatus = async () => {};

const value = id => $(`#${id}`)?.value ?? '';
const checked = id => Boolean($(`#${id}`)?.checked);
const savedText = set => (set ? 'Saved · leave blank to keep' : 'Not saved');

function say(id, text, failed = false) {
  const result = $(`#push-${id}-result`);
  if (!result) return;
  result.textContent = text;
  result.hidden = !text;
  result.classList.toggle('failed', failed);
}

const check = (id, label, isChecked, extra = '') =>
  `<label class="check-row"><input id="${id}" type="checkbox" ${isChecked ? 'checked' : ''} ${extra}> ${esc(label)}</label>`;

function ntfyForm(s) {
  const v = s?.settings ?? {};
  return `<form id="push-ntfy-form" class="push-form" data-push="ntfy" novalidate>
${check('push-ntfy-enabled', 'Send alerts to ntfy', v.enabled)}
${field('push-ntfy-server', 'Server', v.server ?? 'https://ntfy.sh', { maxLength: 2048, hint: 'https://ntfy.sh, or your own ntfy server.' })}
${field('push-ntfy-topic', 'Topic', v.topic ?? '', { maxLength: 64, hint: 'Letters, digits, _ and -. On a public server anyone who knows the topic can read it: choose one that is hard to guess, or use an access token.' })}
${field('push-ntfy-token', 'Access token (optional)', '', { type: 'password', maxLength: 512, autocomplete: 'new-password', placeholder: savedText(v.token?.set), hint: 'Stored sealed on the Uptime Goblin server and never returned to your browser.' })}
<details class="advanced"><summary>User name and password instead of a token</summary>
${field('push-ntfy-username', 'User name', v.username ?? '', { maxLength: 128, autocomplete: 'off' })}
${field('push-ntfy-password', 'Password', '', { type: 'password', maxLength: 512, autocomplete: 'new-password', placeholder: savedText(v.password?.set) })}
</details>
${check('push-ntfy-clear', 'Clear the saved token, user name and password')}
<div class="field-row">${selectField('push-ntfy-priority-firing', 'Priority of an alert', v.priorityFiring ?? 4, ntfyPriorities)}${selectField('push-ntfy-priority-resolved', 'Priority of a recovery', v.priorityResolved ?? 3, ntfyPriorities)}</div>
${field('push-ntfy-tags', 'Tags (optional)', (v.tags ?? []).join(', '), { maxLength: 200, hint: 'Up to 5, separated by commas: emoji short codes such as house, or words. Uptime Goblin adds warning or white_check_mark.' })}
${field('push-ntfy-dashboard', "Uptime Goblin's address (optional)", v.dashboardUrl ?? '', { maxLength: 2048, placeholder: 'https://goblin.example.com/', hint: 'Tapping a notification opens it.' })}
${check('push-ntfy-plain', 'Allow plain HTTP to another computer (the token and alerts cross the network unencrypted)', v.allowPlainHttp)}
<div class="form-buttons"><button class="button" type="submit">Save ntfy settings</button><button class="button" type="button" data-push-test="ntfy">Send test notification</button></div>
<p class="settings-info">Save first. A test sends one notification using saved settings, even while ntfy alerts are off. Tests are limited to one every 30 seconds.</p>
<p id="push-ntfy-result" class="connection-test" role="status" hidden></p></form>`;
}

function gotifyForm(s) {
  const v = s?.settings ?? {};
  return `<form id="push-gotify-form" class="push-form" data-push="gotify" novalidate>
${check('push-gotify-enabled', 'Send alerts to Gotify', v.enabled)}
${field('push-gotify-server', 'Server', v.server ?? '', { maxLength: 2048, placeholder: 'https://gotify.example.com', hint: 'Your Gotify server.' })}
${field('push-gotify-token', 'Application token', '', { type: 'password', maxLength: 512, autocomplete: 'new-password', placeholder: savedText(v.token?.set), hint: 'Create an application in Gotify and paste its token. Stored sealed on the Uptime Goblin server and never returned to your browser.' })}
${check('push-gotify-clear', 'Clear the saved application token')}
<div class="field-row">${selectField('push-gotify-priority-firing', 'Priority of an alert', v.priorityFiring ?? 8, gotifyPriorities)}${selectField('push-gotify-priority-resolved', 'Priority of a recovery', v.priorityResolved ?? 4, gotifyPriorities)}</div>
${field('push-gotify-dashboard', "Uptime Goblin's address (optional)", v.dashboardUrl ?? '', { maxLength: 2048, placeholder: 'https://goblin.example.com/', hint: 'Tapping a notification opens it.' })}
${check('push-gotify-plain', 'Allow plain HTTP to another computer (the token and alerts cross the network unencrypted)', v.allowPlainHttp)}
<div class="form-buttons"><button class="button" type="submit">Save Gotify settings</button><button class="button" type="button" data-push-test="gotify">Send test notification</button></div>
<p class="settings-info">Save first. A test sends one notification using saved settings, even while Gotify alerts are off. Tests are limited to one every 30 seconds.</p>
<p id="push-gotify-result" class="connection-test" role="status" hidden></p></form>`;
}

const forms = { ntfy: ntfyForm, gotify: gotifyForm };
const intro = {
  ntfy: 'Push alerts to your phone through ntfy.sh or your own ntfy server.',
  gotify: 'Push alerts to your phone through your own Gotify server.',
};

/** A card's content: its form once its settings were read, else why not. */
function bodyHtml(id) {
  const s = state[id];
  return s?.problem
    ? `<p class="settings-info">${esc(s.problem)} <button class="quiet-button" type="button" data-push-reload="${id}">Try again</button></p>`
    : s?.settings
      ? `${s.readOnly ? '<p class="settings-info">A newer Uptime Goblin saved these settings: they can be read here but not changed.</p>' : ''}${s.unreadable?.length ? `<p class="channel-error">The saved ${esc(s.unreadable.join(' and '))} can no longer be opened (the encryption key changed). Enter ${s.unreadable.length > 1 ? 'them' : 'it'} again.</p>` : ''}${forms[id](s)}`
      : '<p class="settings-info">Reading settings…</p>';
}
/** One card per channel. */
function card(id) {
  return `<article class="channel-card push-card" id="push-${id}" aria-labelledby="push-${id}-title"><h4 id="push-${id}-title" tabindex="-1">${esc(names[id])}</h4><p class="settings-info">${esc(intro[id])}</p><div id="push-${id}-body">${bodyHtml(id)}</div></article>`;
}

/** The section, drawn with the page (configure/notifications.js); loadPush() fills it. */
export function pushSection() {
  state.ntfy = null;
  state.gotify = null;
  return `<section class="settings-block" aria-labelledby="push-title"><div class="settings-block-heading"><h3 id="push-title" tabindex="-1">Push notifications</h3><p>Send each alert and recovery to ntfy or Gotify too. They are queued, retried and listed in the history like email and the webhook.</p></div><div id="push-cards" class="channel-cards">${pushChannels.map(card).join('')}</div></section>`;
}

function draw(id) {
  const target = $(`#push-${id}-body`);
  if (target) target.innerHTML = bodyHtml(id);
}

async function read(id) {
  try {
    state[id] = await api(`/api/notifications/channels/${id}/settings`);
  } catch (error) {
    state[id] = {
      problem:
        error.status === undefined
          ? `Uptime Goblin did not answer, so the ${names[id]} settings could not be read.`
          : error.message,
    };
  }
  draw(id);
}

/** Reads both channels' settings and draws their forms. */
export async function loadPush() {
  if (!$('#push-cards')) return;
  await Promise.all(pushChannels.map(read));
}

const isLoopback = host =>
  host === 'localhost' ||
  host.endsWith('.localhost') ||
  /^127\./.test(host) ||
  host === '[::1]' ||
  host === '::1';

/** An address problem in words, or null (Uptime Goblin checks the same again). */
export function addressProblem(text, { label, required = true, plainAllowed = false } = {}) {
  const value = String(text ?? '').trim();
  if (!value) return required ? `${label} is required.` : null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return `${label} is not a valid address.`;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:')
    return `${label} must start with https:// or http://.`;
  if (url.username || url.password) return `${label} must not contain a user name or password.`;
  if (required && (url.search || url.hash || value.includes('?') || value.includes('#')))
    return `${label} must not contain a query (?) or fragment (#).`;
  if (required && url.protocol === 'http:' && !plainAllowed && !isLoopback(url.hostname))
    return `${label} uses plain HTTP to another computer. Use https://, or allow plain HTTP.`;
  return null;
}

/** The change a form asks for, or {problem}. Only typed secrets are sent. */
export function pushInput(id) {
  const p = `push-${id}`;
  const enabled = checked(`${p}-enabled`),
    allowPlainHttp = checked(`${p}-plain`),
    server = value(`${p}-server`).trim(),
    dashboardUrl = value(`${p}-dashboard`).trim(),
    token = value(`${p}-token`),
    clear = checked(`${p}-clear`);
  const problem =
    addressProblem(server, {
      label: 'The server address',
      required: id === 'ntfy' || enabled || Boolean(server),
      plainAllowed: allowPlainHttp,
    }) ?? addressProblem(dashboardUrl, { label: "Uptime Goblin's address", required: false });
  if (problem) return { problem };
  if (token && !pushRules.token.test(token))
    return { problem: 'The token must be printable characters without spaces.' };
  const change = {
    enabled,
    server,
    priorityFiring: Number(value(`${p}-priority-firing`)),
    priorityResolved: Number(value(`${p}-priority-resolved`)),
    dashboardUrl,
    allowPlainHttp,
  };
  if (id === 'ntfy') {
    const topic = value(`${p}-topic`).trim(),
      username = value(`${p}-username`).trim(),
      password = value(`${p}-password`),
      tags = value(`${p}-tags`)
        .split(',')
        .map(tag => tag.trim())
        .filter(Boolean);
    if (enabled && !topic) return { problem: 'Enter the ntfy topic to send to.' };
    if (topic && !pushRules.topic.test(topic))
      return {
        problem: 'The topic may hold only letters, digits, _ and -, at most 64 characters.',
      };
    if (tags.length > pushRules.maxTags)
      return { problem: `Enter at most ${pushRules.maxTags} tags.` };
    if (!tags.every(tag => pushRules.tag.test(tag)))
      return { problem: 'Each tag holds only letters, digits, _, + and -, at most 32 characters.' };
    if (username.includes(':')) return { problem: 'The user name must not contain a colon.' };
    if (token && (username || password))
      return { problem: 'Use either an access token or a user name and password, not both.' };
    Object.assign(change, { topic, tags });
    if (clear) Object.assign(change, { token: null, password: null, username: '' });
    else {
      change.username = username;
      if (token) Object.assign(change, { token, password: null, username: '' });
      if (password) Object.assign(change, { password, token: null });
    }
  } else {
    if (clear) change.token = null;
    else if (token) change.token = token;
    if (enabled && !token && !state.gotify?.settings?.token?.set && !clear)
      return { problem: 'Enter the Gotify application token.' };
  }
  return { change };
}

async function save(form) {
  const id = form.dataset.push;
  const { change, problem } = pushInput(id);
  if (problem) {
    say(id, problem, true);
    return;
  }
  const unlock = lockForm(form);
  say(id, '');
  try {
    state[id] = await api(`/api/notifications/channels/${id}/settings`, {
      method: 'PATCH',
      body: JSON.stringify({ version: state[id]?.version ?? 0, ...change }),
    });
    unlock();
    draw(id);
    say(id, `${names[id]} settings saved.`);
  } catch (error) {
    unlock();
    say(
      id,
      error.status === undefined
        ? `Uptime Goblin did not confirm the ${names[id]} settings. Reload to see what is saved.`
        : error.message,
      true
    );
    return;
  }
  await refreshStatus();
}

async function test(button) {
  const id = button.dataset.pushTest;
  button.disabled = true;
  say(id, `Sending a test notification to ${names[id]}…`);
  try {
    const answer = await api(`/api/notifications/channels/${id}/test`, {
      method: 'POST',
      body: '{}',
    });
    say(id, answer?.message || `${names[id]} accepted the test notification.`);
  } catch (error) {
    say(
      id,
      error.status === undefined
        ? 'Uptime Goblin did not answer, so it is not known whether the test was sent.'
        : error.message,
      true
    );
  } finally {
    if (button.isConnected) button.disabled = false;
  }
  await refreshStatus();
}

/** Registers the forms' handlers; `refresh` reads the delivery status again after a change. */
export function install({ refresh } = {}) {
  if (typeof refresh === 'function') refreshStatus = refresh;
  document.addEventListener('submit', async e => {
    const form = e.target.closest?.('form.push-form');
    if (!form) return;
    e.preventDefault();
    await save(form);
  });
  document.addEventListener('click', async e => {
    const testButton = e.target.closest?.('[data-push-test]');
    if (testButton) {
      await test(testButton);
      return;
    }
    const reload = e.target.closest?.('[data-push-reload]');
    if (reload) await read(reload.dataset.pushReload);
  });
}
