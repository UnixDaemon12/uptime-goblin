import net from 'node:net';
import nodemailer from 'nodemailer';
import { resolvedDestination } from './destinations.mjs';

// A pool's close() only ends idle connections. Cancelling must also end a connection
// that is mid-conversation, or it keeps authenticating and sending with old settings.
function closeTransport(transport) {
  try {
    for (const resource of [...(transport.transporter?._connections ?? [])]) resource.close?.();
  } catch {}
  try {
    transport.close();
  } catch {}
}

const escapeHtml = value =>
  String(value ?? '').replace(
    /[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );
// A source's text (its name, a reading's label from its API) as one line of an email: control
// characters (C0, DEL and C1) and the line and paragraph separators become a space, so it cannot
// start a header or a line of its own, and the direction embeddings, overrides and isolates are
// removed, so a label cannot display as another (an RLO turning "exe.gpj" round): what
// lib/config.mjs refuses in a name. The direction marks (U+061C, U+200E, U+200F) stay, as config
// keeps them: a right-to-left name may need one to show as saved, and unlike an override a mark
// cannot turn letters round (it can only move numbers and punctuation beside it). A label from a
// source's API has none by now (lib/collectors.mjs, upstreamText).
const plain = value =>
  String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '')
    .slice(0, 2000);
export const emailConfigured = settings =>
  Boolean(settings?.host && settings?.port && settings?.from && settings?.to && settings?.password);
/**
 * The Message-ID of an alert email: `<orbit.{id}@{sender domain}>`, where `id` is the delivery's
 * stable id (the digest batch id), so a retry or a resend whose acceptance was unknown carries
 * the same Message-ID and mail clients show it once. The domain is the sender address's, lower-
 * cased (config.json validates the sender as an address).
 */
export function orbitMessageId(id, from) {
  const address = String(from ?? ''),
    domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase();
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(id ?? '')))
    throw new TypeError('A Message-ID needs a delivery id of 1-64 letters, digits, _ or -');
  if (!address.includes('@') || !/^[a-z0-9.-]{1,253}$/.test(domain))
    throw new TypeError('A Message-ID needs a sender address with a domain');
  return `<orbit.${id}@${domain}>`;
}
export class EmailError extends Error {
  constructor(message, code = 'EMAIL_FAILED') {
    super(message);
    this.name = 'EmailError';
    this.code = code;
  }
}
// Bind the policy decision to the actual connection. Nodemailer's resolver uses raw DNS,
// which can differ from the OS lookup (/etc/hosts, split DNS) checked by Uptime Goblin.
function checkedSocket(port, addresses, callback) {
  // Alternate families without assuming that the host lacks a usable interface. Each
  // numeric address is already approved; an unsupported route can simply fail on its own.
  const unique = [...new Set(addresses)],
    firstFamily = net.isIP(unique[0] || ''),
    first = unique.filter(address => net.isIP(address) === firstFamily),
    other = unique.filter(address => net.isIP(address) !== firstFamily),
    candidates = [];
  for (let i = 0; i < Math.max(first.length, other.length); i++) {
    if (first[i]) candidates.push(first[i]);
    if (other[i]) candidates.push(other[i]);
  }
  // Start another attempt after 250 ms, but never discard a viable earlier handshake.
  // 32 is the most staggered starts in the shared eight-second budget. Fast failures
  // free slots immediately; even a long DNS answer cannot create unbounded live sockets.
  const pending = new Map(),
    maxPending = 32;
  let next = 0,
    stagger,
    deadline,
    finished = false;
  const discard = (socket, handlers, destroy) => {
    socket.off('connect', handlers.connected);
    socket.off('error', handlers.failed);
    if (destroy) {
      socket.on('error', () => {});
      socket.destroy();
    }
  };
  const finish = (error, winner) => {
    if (finished) return;
    finished = true;
    clearTimeout(stagger);
    clearTimeout(deadline);
    for (const [socket, handlers] of pending) discard(socket, handlers, socket !== winner);
    pending.clear();
    if (error) callback(error);
    else {
      // Keep an early greeting buffered until Nodemailer attaches its listeners. It also
      // upgrades this plain socket for implicit TLS, using the original TLS server name.
      winner.pause();
      callback(null, { connection: winner });
    }
  };
  const exhausted = () =>
    finish(
      new EmailError(
        'Could not connect to the SMTP server. Nothing was sent. Check the SMTP host, port and network access.'
      )
    );
  const start = () => {
    if (finished) return;
    clearTimeout(stagger);
    if (next < candidates.length && pending.size < maxPending) {
      const address = candidates[next++];
      try {
        // A numeric host plus explicit family bypasses every DNS resolver, including
        // Node's auto-selection, whose per-attempt timeout abandons earlier addresses.
        const socket = net.connect({
          host: address,
          port,
          family: net.isIP(address),
          autoSelectFamily: false,
        });
        const handlers = {
          connected: () => finish(null, socket),
          failed: () => {
            if (finished) return;
            pending.delete(socket);
            discard(socket, handlers, true);
            start();
          },
        };
        pending.set(socket, handlers);
        socket.once('connect', handlers.connected);
        socket.once('error', handlers.failed);
      } catch {
        // Unsupported families may fail before returning a socket. Try the next checked
        // address without recursing through a potentially long set of such failures.
        queueMicrotask(start);
        return;
      }
    }
    if (next < candidates.length && pending.size < maxPending) stagger = setTimeout(start, 250);
    else if (!pending.size && next === candidates.length) exhausted();
  };
  deadline = setTimeout(
    () =>
      finish(
        new EmailError('The SMTP connection timed out. Nothing was sent. Check network access.')
      ),
    8000
  );
  start();
  return () =>
    finish(new EmailError('Email delivery was cancelled before connecting. Nothing was sent.'));
}
const unknownAcceptance =
  'Email delivery timed out; acceptance is unknown. Check the mailbox before retrying.';
function safeFailure(error) {
  if (error instanceof EmailError) return error;
  if (error?.code === 'EAUTH')
    return new EmailError('Email sign-in failed. Check the sender address and Gmail app password.');
  // With one recipient, a refused RCPT fails the whole send instead of listing it as rejected.
  if (error?.code === 'EENVELOPE' && error.command === 'RCPT TO')
    return new EmailError(
      'The mail server did not accept the recipient. Check the recipient address.'
    );
  if (error?.code === 'EENVELOPE' && error.command === 'MAIL FROM')
    return new EmailError(
      'The mail server did not accept the sender. Check the sender address and that the account may send as it.'
    );
  if (error?.code === 'ETIMEDOUT')
    // Connecting and waiting for the greeting happen before any mail command. Other timeouts
    // (an idle socket) can follow the message itself, so acceptance stays unknown for them.
    return new EmailError(
      /^(Connection timeout|Greeting never received)\b/.test(error.message)
        ? 'The mail server did not respond in time. Nothing was sent. Check the SMTP host, port, security setting and firewall.'
        : unknownAcceptance
    );
  return new EmailError(
    'Email was not confirmed by the mail server. Check SMTP settings, credentials, TLS trust and network access.'
  );
}
// Several alerts within a short window (for example every source failing during a DNS
// outage) are sent as one email listing each of them.
function digestMessage(settings, events, messageId) {
  const firing = events.filter(e => e.kind !== 'resolved').length,
    resolved = events.length - firing;
  const counts = [
    firing ? `${firing} alert${firing === 1 ? '' : 's'}` : '',
    resolved ? `${resolved} recovered` : '',
  ]
    .filter(Boolean)
    .join(', ');
  const names = [...new Set(events.map(e => plain(e.name || 'Uptime Goblin')))];
  const shown =
    names.slice(0, 3).join(', ') + (names.length > 3 ? ` and ${names.length - 3} more` : '');
  const lines = events.map(e => ({
    kind: e.kind === 'resolved' ? 'Recovered' : 'Alert',
    name: plain(e.name || 'Uptime Goblin'),
    message: plain(e.message),
    time: new Date(Number.isFinite(e.time) ? e.time : Date.now()).toISOString(),
  }));
  return {
    from: { name: 'Uptime Goblin', address: settings.from },
    to: [{ address: settings.to }],
    envelope: { from: settings.from, to: [settings.to] },
    subject: `[Uptime Goblin] ${counts} · ${shown}`.slice(0, 250),
    text: `${counts}\n\n${lines.map(l => `${l.kind} — ${l.name}: ${l.message} (${l.time})`).join('\n')}\n\nOpen your Uptime Goblin dashboard for current status.`,
    html: `<h2>${escapeHtml(counts)}</h2><ul>${lines.map(l => `<li><strong>${escapeHtml(l.kind)} — ${escapeHtml(l.name)}</strong>: ${escapeHtml(l.message)} <small>(${escapeHtml(l.time)})</small></li>`).join('')}</ul><p>Open your Uptime Goblin dashboard for current status.</p>`,
    ...(messageId ? { messageId } : {}),
    disableFileAccess: true,
    disableUrlAccess: true,
  };
}
// The explanation under one of Uptime Goblin's own notices goes by its rule, not by its category: 1.4.x
// had one system notice (history writes failing, '__storage'), and 1.5 adds a full disk
// ('__disk') and a channel that pauses or works again ('__channel_<id>'), which must never send
// the admin to free disk space. A rule this release does not know gets none.
function systemExplanation(event) {
  const resolved = event.kind === 'resolved',
    rule = String(event.rule ?? '');
  if (rule === '__storage')
    return resolved
      ? 'Uptime Goblin is saving readings again.'
      : 'Uptime Goblin keeps collecting and alerting, but new readings are not saved. Free disk space on the Uptime Goblin host; lowering retention does not free disk space by itself.';
  if (rule === '__disk')
    return resolved
      ? ''
      : 'Free disk space on the Uptime Goblin host; lowering retention does not free disk space by itself.';
  if (rule.startsWith('__channel_'))
    return resolved
      ? ''
      : 'Its notifications are held until it works again (each for at most 24 hours); this channel keeps sending. Configure → Notifications in Uptime Goblin says why; once the cause is fixed, Resume there sends them.';
  return '';
}
/**
 * The nodemailer message for an alert, a digest ({digest: [events]}) or a test email. `messageId`
 * (alerts only) sets the Message-ID header; without it, and always for a test email, nodemailer
 * generates its own.
 */
export function mailMessage(settings, event, { test = false, messageId = null } = {}) {
  const id = test ? null : messageId;
  if (!test && Array.isArray(event?.digest)) return digestMessage(settings, event.digest, id);
  const kind = test ? 'Test email' : event.kind === 'resolved' ? 'Recovered' : 'Alert';
  const category = test
    ? ''
    : event.category === 'availability'
      ? 'Connection check'
      : event.category === 'measurement'
        ? 'Metric warning'
        : event.category === 'system'
          ? 'Uptime Goblin health'
          : '';
  const explanation = !category
    ? ''
    : event.category === 'system'
      ? systemExplanation(event)
      : event.kind === 'resolved'
        ? 'Recovery met the configured confirmation settings.'
        : event.category === 'availability'
          ? 'Uptime Goblin could not complete the configured monitoring check. Check the network path, API or website response, and source credentials.'
          : 'A measurement crossed its configured threshold. The service may still be responding normally.';
  const name = plain(event.name || 'Uptime Goblin'),
    message = test
      ? 'This test confirms that the mail server accepted an Uptime Goblin email. Automatic alerts are controlled separately by the Email alerts switch.'
      : plain(event.message);
  const time = new Date(Number.isFinite(event.time) ? event.time : Date.now()).toISOString();
  return {
    from: { name: 'Uptime Goblin', address: settings.from },
    to: [{ address: settings.to }],
    envelope: { from: settings.from, to: [settings.to] },
    subject: `[Uptime Goblin] ${kind}${category ? ' · ' + category : ''}${test ? '' : ' · ' + name.slice(0, 150)}`,
    text: `${kind}${test ? '' : ' — ' + name}\n\n${message}${explanation ? '\n\n' + explanation : ''}\n\nTime: ${time}\n\nOpen your Uptime Goblin dashboard for current status.`,
    html: `<h2>${escapeHtml(kind)}${test ? '' : ' — ' + escapeHtml(name)}</h2><p>${escapeHtml(message)}</p>${explanation ? '<p>' + escapeHtml(explanation) + '</p>' : ''}<p>Time: ${escapeHtml(time)}</p><p>Open your Uptime Goblin dashboard for current status.</p>`,
    ...(id ? { messageId: id } : {}),
    disableFileAccess: true,
    disableUrlAccess: true,
  };
}
export class EmailNotifier {
  constructor({
    getSettings,
    transportFactory = options => nodemailer.createTransport(options),
    timeoutMs = 20000,
    maxPending = 20,
    now = Date.now,
  } = {}) {
    this.getSettings = getSettings;
    this.transportFactory = transportFactory;
    this.timeoutMs = timeoutMs;
    this.maxPending = maxPending;
    this.now = now;
    this.queue = [];
    this.running = false;
    this.closed = false;
    this.generation = 0;
    this.lastAttempt = null;
    this.lastAccepted = null;
    this.lastError = null;
    this.failedCount = 0;
    this.cancelActive = null;
    this.idleWaiters = [];
  }
  status() {
    const s = this.getSettings();
    return {
      enabled: Boolean(s.enabled),
      configured: emailConfigured(s),
      state: !s.enabled
        ? 'disabled'
        : !emailConfigured(s)
          ? 'unconfigured'
          : this.lastError && (!this.lastAccepted || this.lastError.time >= this.lastAccepted)
            ? 'error'
            : this.lastAccepted
              ? 'accepted'
              : 'ready',
      pending: this.queue.length + Number(this.running),
      lastAttempt: this.lastAttempt,
      lastAccepted: this.lastAccepted,
      lastError: this.lastError,
      failedCount: this.failedCount,
    };
  }
  fail(error) {
    this.lastError = { time: this.now(), message: error.message };
    this.failedCount++;
  }
  send(event, { test = false, messageId = null } = {}) {
    const settings = { ...this.getSettings() };
    if (this.closed) return Promise.reject(new EmailError('Email delivery is stopping.'));
    if (!test && !settings.enabled) return Promise.resolve({ skipped: true });
    if (!emailConfigured(settings))
      return Promise.reject(
        new EmailError('Save a sender, recipient and app password before sending a test email.')
      );
    if (this.queue.length + Number(this.running) >= this.maxPending) {
      const error = new EmailError(
        'Email queue is full. Alerts remain available in Uptime Goblin.',
        'EMAIL_BUSY'
      );
      this.fail(error);
      return Promise.reject(error);
    }
    const promise = new Promise((resolve, reject) =>
      this.queue.push({
        settings,
        event,
        test,
        messageId,
        generation: this.generation,
        resolve,
        reject,
      })
    );
    void this.drain();
    return promise;
  }
  async deliver(job) {
    const s = job.settings;
    this.lastAttempt = this.now();
    let timer, transport, cancelSocket;
    let stopped = false,
      connecting = false;
    // The deadline and cancellation start before the address check: a stalled DNS lookup
    // must not hold the queue, a settings change or shutdown beyond the overall deadline.
    const deadline = new Promise((_, reject) => {
      const cancel = (beforeSending, whileSending) => {
        stopped = true;
        reject(new EmailError(transport && !connecting ? whileSending : beforeSending));
        cancelSocket?.();
        if (transport) closeTransport(transport);
      };
      this.cancelActive = () =>
        cancel(
          'Email settings changed or Uptime Goblin stopped before sending. Nothing was sent.',
          'Email settings changed or Uptime Goblin stopped; acceptance is unknown. Check the mailbox before retrying.'
        );
      timer = setTimeout(
        () =>
          cancel(
            connecting
              ? 'Email delivery timed out connecting to the SMTP server. Nothing was sent. Check network access.'
              : 'Email delivery timed out looking up the SMTP server. Nothing was sent. Check DNS on the Uptime Goblin host.',
            unknownAcceptance
          ),
        this.timeoutMs
      );
    });
    try {
      // The SMTP host follows the same outbound policy as collectors.
      const destination = await Promise.race([
        resolvedDestination('smtp://' + s.host).catch(() => {
          throw new EmailError(
            'DNS lookup failed for the SMTP server. Nothing was sent. Check DNS on the Uptime Goblin host.'
          );
        }),
        deadline,
      ]);
      if (destination.problem)
        throw new EmailError('The SMTP server address is not allowed. ' + destination.problem);
      // Settings may have changed, or Uptime Goblin may be stopping, while the address was checked.
      if (this.closed || job.generation !== this.generation)
        throw new EmailError(
          'Email settings changed or Uptime Goblin stopped before sending. Nothing was sent.'
        );
      transport = this.transportFactory({
        host: s.host,
        port: s.port,
        secure: s.secure,
        requireTLS: !s.secure,
        ignoreTLS: false,
        opportunisticTLS: false,
        tls: {
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          // Node 26 refuses an IP address as the TLS server name (24 deprecates it); without
          // one the certificate is checked against the IP address itself.
          ...(net.isIP(s.host) ? {} : { servername: s.host }),
        },
        auth: { user: s.from, pass: s.password },
        pool: true,
        // Uptime Goblin does not retry. Unlimited requeues reconnect every ~150 ms until the deadline
        // when a server closes before its greeting.
        maxRequeues: 0,
        // The pool opens its connection a loop turn after sendMail, when cancelling has no
        // connection to close yet, so the connection itself checks before it starts.
        getSocket: (_options, callback) => {
          connecting = true;
          setImmediate(() => {
            if (stopped) return callback(new EmailError('Email delivery was cancelled.'));
            cancelSocket = checkedSocket(s.port, destination.addresses, (error, socket) => {
              connecting = false;
              cancelSocket = null;
              callback(error, socket);
            });
          });
        },
        maxConnections: 1,
        maxMessages: 1,
        maxRecipients: 1,
        dnsTimeout: 8000,
        connectionTimeout: 8000,
        greetingTimeout: 8000,
        socketTimeout: 10000,
        // The largest server reply Uptime Goblin buffers (a greeting, or one reply with its
        // continuation lines). Real replies are a few hundred bytes; a server, or a man in the
        // middle before STARTTLS, that never ends one is dropped here. Set by Uptime Goblin rather than
        // left to nodemailer's internal default (1 MB), which an update could change.
        maxResponseSize: 64 * 1024,
        disableFileAccess: true,
        disableUrlAccess: true,
        logger: false,
        debug: false,
        transactionLog: false,
      });
      const info = await Promise.race([
        Promise.resolve().then(() =>
          transport.sendMail(
            mailMessage(s, job.event, { test: job.test, messageId: job.messageId })
          )
        ),
        deadline,
      ]);
      if (
        !info?.accepted?.some(address => String(address).toLowerCase() === s.to.toLowerCase()) ||
        info.rejected?.length
      )
        throw new EmailError(
          'The mail server did not accept the recipient. Check the recipient address.'
        );
      if (job.generation === this.generation) this.lastAccepted = this.now();
      return { accepted: true, acceptedAt: this.now() };
    } finally {
      clearTimeout(timer);
      this.cancelActive = null;
      stopped = true;
      cancelSocket?.();
      if (transport) closeTransport(transport);
    }
  }
  async drain() {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length) {
        const job = this.queue.shift();
        if (this.closed || job.generation !== this.generation) {
          job.resolve({ skipped: true });
          continue;
        }
        try {
          job.resolve(await this.deliver(job));
        } catch (error) {
          const safe = safeFailure(error);
          if (job.generation === this.generation) this.fail(safe);
          job.reject(safe);
        }
      }
    } finally {
      this.running = false;
      for (const resolve of this.idleWaiters.splice(0)) resolve();
    }
  }
  reconfigure() {
    this.generation++;
    for (const job of this.queue.splice(0)) job.resolve({ skipped: true });
    this.cancelActive?.();
    this.lastAttempt = null;
    this.lastAccepted = null;
    this.lastError = null;
    this.failedCount = 0;
  }
  async close() {
    this.closed = true;
    this.reconfigure();
    if (this.running) await new Promise(resolve => this.idleWaiters.push(resolve));
  }
}
