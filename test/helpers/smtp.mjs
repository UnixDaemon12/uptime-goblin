// An SMTP server for delivery tests (delivery spec §2.1 item 10; frozen once the lanes use it):
// implicit TLS (port-465 style, as Uptime Goblin's default Gmail settings use) on 127.0.0.1, speaking
// just enough SMTP for nodemailer: EHLO, AUTH PLAIN and LOGIN, MAIL, RCPT, DATA, RSET, NOOP and
// QUIT. It records every message's envelope, headers and body. Built on node:tls and
// test/helpers/tls.mjs: no new dependency, no openssl binary.
//
//   const smtp = await smtpServer(t, {authFails: true});
//   // a spawned release trusts it through NODE_EXTRA_CA_CERTS=smtp.caFile; SMTP host 127.0.0.1
//   // (with GOBLIN_ALLOW_LOOPBACK=1), port smtp.port, security "SSL/TLS".
//
// Options: cert and key (PEM; a fresh self-signed pair for localhost and 127.0.0.1 by default);
// authFails (true, or (user, pass) => boolean): answer 535; rcptRefused (true, or (address) =>
// boolean): answer 550 to RCPT; holdAfterData (true, or (message) => boolean): read the whole
// message and never answer it until release(), as a server that accepted it but never said so.
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { selfSignedCertificate } from './tls.mjs';

const decide = (option, ...args) => (typeof option === 'function' ? option(...args) : option);
const address = text => /<([^>]*)>/.exec(text)?.[1] ?? text.split(':').slice(1).join(':').trim();

// Splits a message into its headers (lower-case names, unfolded; the last of a repeated name
// wins) and its body.
function parseMessage(raw) {
  const split = raw.indexOf('\r\n\r\n');
  const head = split === -1 ? raw : raw.slice(0, split),
    body = split === -1 ? '' : raw.slice(split + 4);
  const headers = {};
  for (const line of head.replace(/\r\n[ \t]+/g, ' ').split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon > 0)
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return { headers, body };
}

export async function smtpServer(
  t,
  { cert, key, authFails = false, rcptRefused = false, holdAfterData = false } = {}
) {
  if (!cert || !key) ({ cert, key } = selfSignedCertificate({ hosts: ['localhost', '127.0.0.1'] }));
  const messages = [],
    sessions = [],
    sockets = new Set(),
    held = new Set();
  const server = tls.createServer({ cert, key, minVersion: 'TLSv1.2' }, socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    const session = { auth: null, from: null, to: [], commands: [] };
    sessions.push(session);
    let buffer = '',
      data = null, // the message being read after DATA
      pending = null; // a multi-step AUTH LOGIN: 'user' or 'pass'
    const reply = text => {
      if (!socket.destroyed) socket.write(`${text}\r\n`);
    };
    const finishAuth = (user, pass) => {
      if (decide(authFails, user, pass)) return reply('535 5.7.8 Authentication failed');
      session.auth = { user, pass };
      reply('235 2.7.0 Authentication successful');
    };
    const decode = text => Buffer.from(text, 'base64').toString('utf8');
    const line = text => {
      if (pending === 'user') {
        session.user = decode(text);
        pending = 'pass';
        return reply('334 UGFzc3dvcmQ6');
      }
      if (pending === 'pass') {
        pending = null;
        return finishAuth(session.user, decode(text));
      }
      if (pending === 'plain') {
        pending = null;
        const [, user, pass] = decode(text).split('\u0000');
        return finishAuth(user, pass);
      }
      session.commands.push(text.replace(/^(AUTH \w+) .*/i, '$1 ***'));
      const [verb] = text.split(' ');
      switch (verb.toUpperCase()) {
        case 'EHLO':
        case 'HELO':
          return reply(
            '250-orbit-test.example\r\n250-AUTH PLAIN LOGIN\r\n250-8BITMIME\r\n250 SMTPUTF8'
          );
        case 'AUTH': {
          const [, method, initial] = text.split(' ');
          if (/^plain$/i.test(method)) {
            if (!initial) {
              pending = 'plain';
              return reply('334 ');
            }
            const [, user, pass] = decode(initial).split('\u0000');
            return finishAuth(user, pass);
          }
          if (/^login$/i.test(method)) {
            pending = 'user';
            return reply('334 VXNlcm5hbWU6');
          }
          return reply('504 5.5.4 Unrecognized authentication type');
        }
        case 'MAIL':
          session.from = address(text);
          session.to = [];
          return reply('250 2.1.0 OK');
        case 'RCPT': {
          const to = address(text);
          if (decide(rcptRefused, to)) return reply('550 5.1.1 No such user here');
          session.to.push(to);
          return reply('250 2.1.5 OK');
        }
        case 'DATA':
          data = [];
          return reply('354 Go ahead');
        case 'RSET':
          session.from = null;
          session.to = [];
          return reply('250 2.0.0 OK');
        case 'NOOP':
          return reply('250 2.0.0 OK');
        case 'QUIT':
          reply('221 2.0.0 Bye');
          return socket.end();
        default:
          return reply('502 5.5.2 Command not implemented');
      }
    };
    const endOfData = () => {
      const raw = data.map(item => (item.startsWith('..') ? item.slice(1) : item)).join('\r\n');
      data = null;
      const { headers, body } = parseMessage(raw);
      const message = {
        envelope: { from: session.from, to: [...session.to] },
        auth: session.auth ? { user: session.auth.user } : null,
        headers,
        messageId: headers['message-id'] ?? null,
        subject: headers.subject ?? null,
        body,
        raw,
        receivedAt: Date.now(),
      };
      messages.push(message);
      if (decide(holdAfterData, message)) {
        const entry = { reply, socket };
        held.add(entry);
        socket.on('close', () => held.delete(entry));
        return;
      }
      reply('250 2.0.0 OK: queued');
    };
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      let index;
      while ((index = buffer.indexOf('\r\n')) !== -1) {
        const text = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (data) {
          if (text === '.') endOfData();
          else data.push(text);
        } else line(text);
      }
    });
    reply('220 orbit-test.example ESMTP ready');
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  // The certificate as a file, for NODE_EXTRA_CA_CERTS in spawned releases.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-smtp-'));
  const caFile = path.join(directory, 'smtp-ca.pem');
  fs.writeFileSync(caFile, cert);
  const close = () =>
    new Promise(resolve => {
      for (const socket of sockets) socket.destroy();
      server.close(() => {
        fs.rmSync(directory, { recursive: true, force: true });
        resolve();
      });
    });
  t?.after?.(close);
  return {
    host: '127.0.0.1',
    port: server.address().port,
    cert,
    caFile,
    messages,
    sessions,
    /** Answers every message held after DATA (default 250). */
    release(text = '250 2.0.0 OK: queued') {
      for (const entry of [...held]) {
        held.delete(entry);
        entry.reply(text);
      }
    },
    get held() {
      return held.size;
    },
    close,
  };
}
