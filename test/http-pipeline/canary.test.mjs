// The canary (T4/T19 scope, sessions spec §8.1): after sign-ins, Basic requests, a password
// change and a manual snapshot, no session secret and no plaintext password appears anywhere
// Uptime Goblin writes: its output, control.sqlite and its -wal/-shm, the snapshot, or an API answer.
// Real scrypt, a real control database, a real snapshot.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createSnapshot } from '../../lib/db/snapshot.mjs';
import { basic, browserWrite, cookieFrom, password, raw, startReal } from './harness.mjs';

const nextPassword = 'canary-next-admin-password';

/** Every file under `directory` (recursively), with its bytes. */
function filesUnder(directory) {
  const found = [];
  const walk = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) found.push([full, fs.readFileSync(full)]);
    }
  };
  if (fs.existsSync(directory)) walk(directory);
  return found;
}

/** The forms a secret could leak in: text, raw bytes, hex, base64 and base64url. */
function needles(values) {
  const list = [];
  for (const { label, value } of values) {
    list.push({ label, bytes: Buffer.from(value) });
    if (value.startsWith('v1.')) {
      const secret = Buffer.from(value.slice(3), 'base64url');
      list.push({ label: `${label} (base64url part)`, bytes: Buffer.from(value.slice(3)) });
      list.push({ label: `${label} (raw bytes)`, bytes: secret });
      list.push({ label: `${label} (hex)`, bytes: Buffer.from(secret.toString('hex')) });
      list.push({ label: `${label} (base64)`, bytes: Buffer.from(secret.toString('base64')) });
    } else {
      list.push({
        label: `${label} (hex)`,
        bytes: Buffer.from(Buffer.from(value).toString('hex')),
      });
      list.push({
        label: `${label} (Basic)`,
        bytes: Buffer.from(Buffer.from(`admin:${value}`).toString('base64')),
      });
    }
  }
  return list;
}

test('no session secret or password reaches the output, the databases, a snapshot or an answer', async t => {
  const output = [];
  const capture = (...args) => output.push(args.map(String).join(' '));
  for (const method of ['log', 'info', 'warn', 'error', 'debug'])
    t.mock.method(console, method, capture);
  for (const stream of [process.stdout, process.stderr]) {
    const write = stream.write.bind(stream);
    t.mock.method(stream, 'write', (chunk, ...rest) => {
      output.push(String(chunk));
      // node:test reports through stdout; keep its protocol intact.
      return write(chunk, ...rest);
    });
  }
  const { app, port, directory } = await startReal(t, {
    fastKdf: false,
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
  });
  const answers = [];
  const keep = answer => {
    const headers = { ...answer.headers };
    delete headers['set-cookie']; // the one place a cookie value belongs
    answers.push(JSON.stringify(headers) + '\n' + answer.body);
    return answer;
  };
  const self = `http://127.0.0.1:${port}`;
  const signIn = async (value, lines = [], origin = self) =>
    keep(
      await raw(
        port,
        ['POST /api/auth/login HTTP/1.1', ...lines, ...browserWrite(origin)],
        JSON.stringify({ login: 'admin', password: value, remember: true })
      )
    );
  const secrets = [
    { label: 'the bootstrap password', value: password },
    { label: 'the new password', value: nextPassword },
  ];
  // Sign-ins on loopback and through the proxy on https, a wrong one, and Basic scripts.
  const first = await signIn(password);
  const https = await signIn(
    password,
    ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.3', 'X-Forwarded-Proto: https'],
    'https://goblin.example'
  );
  await signIn('a wrong password for the canary');
  keep(await raw(port, ['GET /api/dashboard HTTP/1.1', `Authorization: ${basic()}`]));
  keep(await raw(port, ['GET /api/dashboard HTTP/1.1', `Authorization: ${basic('wrong')}`]));
  const cookies = [cookieFrom(first), cookieFrom(https)];
  for (const cookie of cookies) {
    assert.ok(cookie);
    secrets.push({ label: `the cookie ${cookie.split('=')[0]}`, value: cookie.split('=')[1] });
  }
  const as = cookie => [`Cookie: ${cookie}`, 'Sec-Fetch-Site: same-origin'];
  const session = keep(await raw(port, ['GET /api/session HTTP/1.1', ...as(cookies[0])]));
  assert.equal(session.status, 200);
  const list = keep(await raw(port, ['GET /api/account/sessions HTTP/1.1', ...as(cookies[0])]));
  assert.equal(list.status, 200);
  assert.doesNotMatch(list.body, /token_hash|tokenHash/);
  keep(await raw(port, ['GET /api/system HTTP/1.1', ...as(cookies[0])]));
  keep(await raw(port, ['GET /api/config/export HTTP/1.1', ...as(cookies[0])]));
  const changed = keep(
    await raw(
      port,
      ['POST /api/account/password HTTP/1.1', `Cookie: ${cookies[0]}`, ...browserWrite(self)],
      JSON.stringify({
        currentPassword: password,
        password: nextPassword,
        confirmPassword: nextPassword,
      })
    )
  );
  assert.equal(changed.status, 200);
  const rotated = cookieFrom(changed);
  secrets.push({ label: 'the rotated cookie', value: rotated.split('=')[1] });
  keep(await raw(port, ['GET /api/session HTTP/1.1', ...as(rotated)]));
  keep(await raw(port, ['GET /api/dashboard HTTP/1.1', `Authorization: ${basic(nextPassword)}`]));
  const signOut = keep(
    await raw(port, ['POST /api/auth/logout HTTP/1.1', `Cookie: ${rotated}`, ...browserWrite(self)])
  );
  assert.equal(signOut.status, 204);
  const live = ['control.sqlite', 'control.sqlite-wal', 'control.sqlite-shm']
    .map(name => path.join(directory, name))
    .filter(file => fs.existsSync(file))
    .map(file => [file, fs.readFileSync(file)]);
  assert.ok(live.length >= 1);
  await app.close();
  // A manual snapshot, taken as goblin-admin takes one (Uptime Goblin stopped).
  const snapshot = await createSnapshot(directory, { reason: 'manual', release: app.version });
  assert.ok(snapshot.manifest.files.some(file => file.name === 'control.sqlite'));
  t.mock.restoreAll();

  const places = [
    ['the output', Buffer.from(output.join('\n'))],
    ...answers.map((text, i) => [`answer ${i}`, Buffer.from(text)]),
    ...live.map(([file, bytes]) => [`${path.basename(file)} (running)`, bytes]),
    ...filesUnder(path.join(directory, 'snapshots')).map(([file, bytes]) => [
      path.relative(directory, file),
      bytes,
    ]),
    ...['control.sqlite', 'control.sqlite-wal', 'control.sqlite-shm']
      .map(name => path.join(directory, name))
      .filter(file => fs.existsSync(file))
      .map(file => [`${path.basename(file)} (stopped)`, fs.readFileSync(file)]),
  ];
  assert.ok(places.some(([name]) => name.startsWith(`snapshots${path.sep}`)));
  // The search itself finds a secret where it belongs: in the Set-Cookie header.
  const [ownCookie] = needles([secrets[2]]);
  assert.ok(
    Buffer.from([].concat(first.headers['set-cookie']).join('\n')).includes(ownCookie.bytes)
  );
  for (const [name, bytes] of places)
    for (const needle of needles(secrets))
      assert.equal(bytes.includes(needle.bytes), false, `${needle.label} found in ${name}`);
  // The session answers name sessions by their public id only.
  assert.match(session.json.session.id, /^s_[A-Za-z0-9_-]{16}$/);
});
