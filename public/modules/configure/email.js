// Email alert settings and the test email.
import { api, conflictMessage, writeConfig } from '../core/api.js';
import { $, esc } from '../core/dom.js';
import { dateTime } from '../core/format.js';
import { field, formSnapshot, lockForm, updateDirtyIndicator } from '../core/forms.js';
import { load } from '../core/load.js';
import { page } from '../core/page.js';
import { deliveryKnown, deliveryTexts, plural, sentence } from './notifications.js';

export function emailHasCurrentError(status = page.data?.notifications?.email) {
  if (!status) return false;
  if (status.state) return status.state === 'error';
  return (
    status.enabled !== false &&
    !!status.lastError &&
    (!status.lastAccepted || Number(status.lastError.time) >= Number(status.lastAccepted))
  );
}
/**
 * The email channel's status in a sentence or two. Uptime Goblin keeps it in its control database, so it
 * survives a restart; while Uptime Goblin cannot read that, its last figures are not shown as current.
 * A paused, refusing or retrying channel says so first (with what to do); otherwise the email
 * settings' own state, as 1.4.x described it.
 */
export function emailStatusText() {
  const n = page.data.notifications,
    s = n?.email;
  if (!s) return 'Email alerts are off.';
  if (!deliveryKnown(n)) return deliveryTexts.unavailable;
  if (s.channelState === 'paused')
    return `Email alerts are paused: ${sentence(s.pausedReason)} Save corrected settings, send a test email, or press Resume on the Notifications page.`;
  if (s.channelState === 'refusing')
    return `Email is refusing notifications: ${sentence(s.lastError?.message, 'the mail server refused the last messages.')}`;
  // Only the messages waiting to retry go at the next attempt's time. `waiting` also counts newer
  // alerts waiting for their own first message (sent at their digest's time, often sooner) and
  // any held ones: they are said apart, so the count matches the Notifications page.
  const retrying = Number(s.retrying) || 0,
    others = Math.max(0, (Number(s.waiting) || 0) - retrying);
  if ((s.channelState === 'retrying' || s.channelState === 'circuit-open') && retrying > 0)
    return `${plural(retrying, 'message')} waiting to retry${s.nextAttemptAt ? ` (next attempt ${dateTime(s.nextAttemptAt)})` : ''}${others ? `, and ${others} waiting to be sent` : ''}.`;
  const state = !s.enabled
    ? 'Email alerts are off.'
    : !s.configured
      ? 'Email setup is incomplete.'
      : emailHasCurrentError(s)
        ? 'Email delivery needs attention.'
        : s.lastAccepted
          ? 'Email alerts are enabled.'
          : 'Email alerts are enabled; the mail server has not accepted a message yet.';
  return (
    state +
    (s.pending
      ? ` ${s.pending} message${s.pending === 1 ? ' is' : 's are'} waiting or sending.`
      : '') +
    (s.lastAccepted ? ` Last accepted by the mail server: ${dateTime(s.lastAccepted)}.` : '') +
    (s.lastError
      ? ` ${emailHasCurrentError(s) ? 'Current' : 'Previous'} delivery failure${s.lastError.time ? ' (' + dateTime(s.lastError.time) + ')' : ''}: ${s.lastError.message}`
      : '')
  );
}
export function emailSettings() {
  const s = page.data.config.email || {
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    from: '',
    to: '',
  };
  return `<section class="config-section"><h3>Email alerts</h3><p class="settings-info">Get an email when an alert starts and when it recovers. Use a Gmail app password from your Google Account, not your normal sign-in password.</p><form id="email-form">
 ${field('email-from', 'Gmail address (sender)', s.from, { type: 'email', maxLength: 254 })}${field('email-to', 'Send alerts to', s.to, { type: 'email', maxLength: 254 })}
 ${field('email-password', 'Gmail app password', '', { type: 'password', maxLength: 1024, autocomplete: 'new-password', placeholder: s.passwordConfigured ? 'Saved · leave blank to keep' : 'Enter an app password', hint: 'Stored privately on the Uptime Goblin server and never returned to your browser. Enter it over HTTPS.' })}
 <label class="check-row"><input id="email-enabled" type="checkbox" ${s.enabled ? 'checked' : ''}> Email alerts enabled</label>
 <label class="check-row"><input id="email-clear-password" type="checkbox"> Clear the saved app password</label>
 <details class="advanced"><summary>Mail server (Gmail defaults)</summary>${field('email-host', 'SMTP hostname', s.host, { maxLength: 253 })}<div class="field-row">${field('email-port', 'Port', s.port, { type: 'number', min: 1, max: 65535, required: true })}<div class="field"><label for="email-security">Encrypted connection</label><select id="email-security"><option value="tls" ${s.secure ? 'selected' : ''}>TLS · usually port 465</option><option value="starttls" ${!s.secure ? 'selected' : ''}>STARTTLS · usually port 587</option></select></div></div><p class="settings-info">Certificate verification is always required. Changing the server, connection mode or sender requires entering the app password again.</p></details>
 <div class="form-buttons"><button class="button" type="submit">Save email settings</button><button class="button" id="test-email" type="button">Send test email</button></div><p class="settings-info">Save first. A test sends one message using saved settings, even while automatic email alerts are off. Tests are limited to one per minute.</p><p id="email-status" class="settings-info">${esc(emailStatusText())}</p><p class="settings-info email-history-link"><a class="text-link" href="#configure/notifications">Delivery history</a></p><p id="email-result" class="connection-test" role="status" hidden></p></form></section>`;
}
function emailInput() {
  const input = {
    enabled: $('#email-enabled').checked,
    host: $('#email-host').value,
    port: Number($('#email-port').value),
    secure: $('#email-security').value === 'tls',
    from: $('#email-from').value,
    to: $('#email-to').value,
  };
  if ($('#email-password').value) input.password = $('#email-password').value;
  if ($('#email-clear-password').checked) input.clearPassword = true;
  return input;
}
export async function emailAction(test = false) {
  const form = $('#email-form');
  if (!form.reportValidity()) return;
  const result = $('#email-result');
  let unlock = () => {};
  result.hidden = false;
  result.className = 'connection-test';
  try {
    const input = emailInput(),
      saved = page.data.config.email;
    if (
      test &&
      (input.password || input.clearPassword || Object.keys(input).some(k => input[k] !== saved[k]))
    )
      throw new Error('Save email settings before sending a test.');
    unlock = lockForm(form);
    result.textContent = test ? 'Sending one test email…' : 'Saving email settings…';
    if (test) {
      const response = await api('/api/email/test', { method: 'POST', body: '{}' });
      result.textContent = response.message;
      await load();
    } else {
      const response = await writeConfig(
        '/api/settings',
        { method: 'PATCH', body: JSON.stringify({ email: input }) },
        {
          revision: () => page.pageRevision,
          apply: config => {
            // The app password itself is never returned, only whether one is saved.
            const { password, clearPassword, ...saved } = input;
            config.email = {
              ...config.email,
              ...saved,
              passwordConfigured: clearPassword
                ? false
                : password
                  ? true
                  : !!config.email?.passwordConfigured,
            };
          },
        }
      );
      page.pageRevision = response.revision ?? page.pageRevision;
      $('#email-password').value = '';
      $('#email-clear-password').checked = false;
      result.textContent = 'Email settings saved.';
      // Show the values as saved (the server trims and lowercases the host), so the
      // test-email check below compares like with like.
      if (await load())
        for (const key of ['host', 'port', 'from', 'to'])
          $('#email-' + key).value = page.data.config.email[key];
      page.pageBaseline = formSnapshot(form);
      updateDirtyIndicator();
    }
    $('#email-password').placeholder = page.data.config.email.passwordConfigured
      ? 'Saved · leave blank to keep'
      : 'Enter an app password';
    $('#email-status').textContent = emailStatusText();
    result.classList.add('success');
  } catch (error) {
    result.classList.add('failed');
    result.textContent =
      !test && error.status === 409
        ? `${conflictMessage} Choose Discard unsaved changes to load the latest settings.`
        : error.message;
    // 401: the user cancelled signing in again (api() asks first). A load would only be
    // refused too, and ask again: the dialog that Cancel is closing would open again at once,
    // so it took a second Cancel. The page already says it is signed out.
    if (error.status === 401) return;
    await load();
    if ($('#email-status')) $('#email-status').textContent = emailStatusText();
  } finally {
    unlock();
  }
}
