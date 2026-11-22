// The built-in email channel. It sends through lib/mail.mjs unchanged (the same message, SMTP
// options, destination check, 20 s deadline and cancellation), but reads the settings when it
// sends rather than when the alert happened, so a settings change no longer drops queued mail,
// and it tells the outbox what to do next instead of giving up:
//   accepted · nothing sent yet (DNS, connection, greeting, cancelled before sending): retry ·
//   sent but not confirmed (a timeout mid-conversation): unknown, sent once more after 5 min ·
//   sign-in, sender, address policy or settings incomplete: pause until something changes ·
//   TLS trust: a transient pause (a certificate being renewed; probed every 15 minutes) ·
//   recipient refused: failed · SMTP 4xx: retry · other 5xx: failed · email off: skipped.
// Batching follows 1.4.2: a message waits until no alert arrived for 60 s, and at most 180 s.
// Each message carries Message-ID <orbit.{batch id}@{sender domain}>: the outbox retries and
// resends a batch with the same id, so the same message keeps the same Message-ID. Threading
// headers (In-Reply-To, References) come with incidents.
import { EmailNotifier, EmailError, emailConfigured, orbitMessageId } from '../../mail.mjs';
import { destinationProblem } from '../../destinations.mjs';
import { accepted, retry, failed, unknown, pause, skipped, defineChannel } from '../channel.mjs';

const PAUSE_CODES = new Set(['EAUTH', 'ETLS', 'ENOAUTH', 'EOAUTH2']);

/** Classifies a raw nodemailer error from sendMail (pure). */
export function classifyMailError(error) {
  const code = error?.code,
    status = Number(error?.responseCode) || null;
  if (
    PAUSE_CODES.has(code) ||
    /certificate|self[- ]signed|unable to verify/i.test(error?.message ?? '')
  )
    return code === 'EAUTH' || code === 'ENOAUTH' || code === 'EOAUTH2'
      ? pause('Email sign-in failed. Check the sender address and Gmail app password.')
      : pause(
          "The mail server's TLS certificate is not trusted. Check the SMTP host and security setting.",
          { transient: true }
        );
  if (code === 'EENVELOPE' && error.command === 'RCPT TO')
    return failed('The mail server did not accept the recipient. Check the recipient address.', {
      status,
    });
  if (code === 'EENVELOPE' && error.command === 'MAIL FROM')
    return pause(
      'The mail server did not accept the sender. Check the sender address and that the account may send as it.'
    );
  if (code === 'ETIMEDOUT')
    return /^(Connection timeout|Greeting never received)\b/.test(error?.message ?? '')
      ? retry(null, 'The mail server did not respond in time. Nothing was sent.')
      : unknown('Email delivery timed out; acceptance is unknown.');
  if (status >= 400 && status <= 499)
    return retry(null, `The mail server asked Uptime Goblin to try later (${status}).`, { status });
  if (status >= 500 && status <= 599)
    return failed(`The mail server refused the message (${status}).`, { status });
  if (['ECONNECTION', 'ESOCKET', 'EDNS', 'ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND'].includes(code))
    return retry(null, 'Uptime Goblin could not connect to the mail server. Nothing was sent.');
  return retry(null, 'Email was not confirmed by the mail server; it will be retried.');
}

/** The 1.4.2 payload for EmailNotifier: one event, or a digest of several. */
export const mailPayload = events =>
  events.length === 1 ? events[0] : { digest: events, time: events[0].time };

/**
 * createEmailChannel({getSettings, transportFactory, timeoutMs, digestWindowMs,
 * destinationCheck}). `getSettings` returns config.value.email.
 */
export function createEmailChannel({
  getSettings,
  transportFactory,
  timeoutMs = 20000,
  digestWindowMs = 60000,
  destinationCheck = destinationProblem,
} = {}) {
  if (typeof getSettings !== 'function') throw new TypeError('getSettings is required');
  return defineChannel({
    name: 'email',
    digest: { windowMs: digestWindowMs, maxFactor: 3 },
    // "Resend once after 5 minutes" when acceptance is unknown (design §2.7).
    unknown: { resendAfterMs: 5 * 60 * 1000, maxResends: 1 },
    async send(message, { signal } = {}) {
      const settings = { ...getSettings() };
      if (!settings.enabled) return skipped('Email alerts are switched off.');
      if (!emailConfigured(settings))
        return pause('Email is not set up: save a sender, recipient and app password.');
      if (!message.events?.length) return failed('The delivery has no event.');
      let messageId;
      try {
        messageId = orbitMessageId(message.uid, settings.from);
      } catch {
        // config.json validates the sender; a value that still has no domain needs a fix.
        return pause('Email is not set up: the sender address is not valid.');
      }
      if (signal?.aborted)
        return retry(null, 'Uptime Goblin stopped before sending. Nothing was sent.');
      const refused = await destinationCheck('smtp://' + settings.host);
      if (refused) return pause('The SMTP server address is not allowed. ' + refused);
      if (signal?.aborted)
        return retry(null, 'Uptime Goblin stopped before sending. Nothing was sent.');

      // Where the attempt got to, seen through the transport: EmailNotifier turns errors into
      // safe messages, and the raw error decides what happens next.
      const attempt = { phase: 'before', error: null };
      const notifier = new EmailNotifier({
        getSettings: () => settings,
        timeoutMs,
        ...(transportFactory ? { transportFactory } : {}),
      });
      const create = notifier.transportFactory;
      notifier.transportFactory = options => {
        const transport = create(options),
          sendMail = transport.sendMail.bind(transport);
        transport.sendMail = async mail => {
          attempt.phase = 'sending';
          try {
            const info = await sendMail(mail);
            attempt.phase = 'answered';
            return info;
          } catch (error) {
            attempt.phase = 'failed';
            attempt.error = error;
            throw error;
          }
        };
        return transport;
      };
      const cancel = () => notifier.reconfigure();
      signal?.addEventListener('abort', cancel, { once: true });
      try {
        const result = await notifier.send(mailPayload(message.events), { messageId });
        // SMTP 250 after DATA: the mail server took responsibility for the message.
        if (result?.accepted) return accepted({ status: 250 });
        // Cancelled while queued inside the notifier: nothing was sent.
        return retry(null, 'Uptime Goblin stopped before sending. Nothing was sent.');
      } catch (error) {
        if (attempt.phase === 'failed') return classifyMailError(attempt.error);
        if (attempt.phase === 'sending')
          return unknown(
            error instanceof EmailError ? error.message : 'Email acceptance is unknown.'
          );
        if (attempt.phase === 'answered')
          return failed(
            'The mail server did not accept the recipient. Check the recipient address.'
          );
        return retry(
          null,
          error instanceof EmailError
            ? error.message
            : 'Email could not be sent; it will be retried.'
        );
      } finally {
        signal?.removeEventListener('abort', cancel);
        await notifier.close();
      }
    },
  });
}
