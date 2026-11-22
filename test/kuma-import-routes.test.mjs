// The Uptime Kuma import's routes through a real Uptime Goblin (createApp, no scheduler): the preview
// changes nothing and answers the revision it planned against; the apply needs that revision as
// If-Match, saves exactly the previewed plan in one revision and is recorded as one
// configuration change; both need a signed-in caller holding config:import and the CSRF header,
// and refuse a backup that cannot be imported before anything else. Synthetic backups only
// (test/kuma-import.test.mjs); nothing leaves 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { importRoutes } from '../lib/http/routes/import.mjs';
import { reduceKumaBackup } from '../public/shared/uptime-kuma.js';
import { kumaBackup, kumaMonitor, kumaSecrets, mixedBackup } from './helpers/kuma.mjs';
import { serveAuth, raw, basic } from './http-pipeline/harness.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const password = 'fixture-kuma-import-password';
const secrets = kumaSecrets;
const preview = '/api/import/uptime-kuma/preview',
  apply = '/api/import/uptime-kuma';

async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-kuma-routes-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = await createApp({
    directory,
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    trustProxy: '',
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const call = async (route, method = 'GET', body, headers = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: response.status, body: json, text };
  };
  const revision = async () => app.config.value.revision;
  const importRows = async () =>
    (await call('/api/audit?action=sources.import')).body.entries.filter(
      entry => entry.action === 'sources.import'
    );
  return { app, call, directory, revision, importRows };
}

test('the preview changes nothing; the apply saves exactly the previewed plan in one revision, recorded once', async t => {
  const { app, call, directory, revision, importRows } = await fixture(t);
  // A saved Website check of the same name as a Kuma monitor: the import changes it.
  const saved = await call('/api/services', 'POST', {
    type: 'http',
    name: 'Plex web',
    group: 'Media',
    url: 'https://old.example.com/',
  });
  assert.equal(saved.status, 201);
  const before = await revision(),
    count = app.config.value.services.length;
  const backup = reduceKumaBackup(mixedBackup());

  const shown = await call(preview, 'POST', backup);
  assert.equal(shown.status, 200);
  assert.equal(shown.body.revision, before);
  assert.equal(await revision(), before, 'a preview saves nothing');
  assert.equal(app.config.value.services.length, count);
  assert.deepEqual(
    shown.body.add.map(a => a.kumaId),
    [3, 4, 5, 6, 7, 8]
  );
  assert.deepEqual(
    shown.body.change.map(c => [c.kumaId, c.id]),
    [[2, saved.body.service.id]]
  );
  assert.equal(shown.body.skip.length, 13);
  assert.equal(shown.body.inputs, undefined, 'the settings to save are not shown');
  assert.deepEqual(await importRows(), [], 'a preview is not recorded');

  // Without If-Match: 428, nothing saved, nothing recorded.
  const unconditional = await call(apply, 'POST', backup);
  assert.equal(unconditional.status, 428);
  // An older revision: 409, nothing saved.
  const stale = await call(apply, 'POST', backup, { 'If-Match': String(before - 1) });
  assert.equal(stale.status, 409);
  assert.equal(await revision(), before);
  assert.equal(app.config.value.services.length, count);

  const done = await call(apply, 'POST', backup, { 'If-Match': String(before) });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.body.revision, before + 1, 'one revision');
  assert.equal(await revision(), before + 1);
  // What was saved is what the preview showed.
  assert.deepEqual(
    done.body.added.map(a => [a.kumaId, a.name]),
    shown.body.add.map(a => [a.kumaId, a.name])
  );
  assert.deepEqual(
    done.body.changed.map(c => [c.kumaId, c.id]),
    shown.body.change.map(c => [c.kumaId, c.id])
  );
  assert.equal(done.body.skipped, shown.body.skip.length);
  for (const [i, planned] of shown.body.add.entries()) {
    const source = app.config.get(done.body.added[i].id);
    assert.deepEqual(
      [
        source.type,
        source.name,
        source.group,
        source.url,
        source.apiUrl,
        source.httpMethod,
        source.httpExpectedStatus,
        source.pollSeconds,
        source.enabled,
        source.apiKey,
        source.password,
        source.username,
      ],
      [
        'http',
        planned.name,
        planned.group,
        planned.url,
        '',
        planned.method,
        planned.expectedStatus,
        planned.pollSeconds,
        planned.enabled,
        '',
        '',
        '',
      ]
    );
  }
  const changed = app.config.get(saved.body.service.id);
  assert.equal(changed.url, 'https://site2.example.com/');
  assert.equal(changed.httpExpectedStatus, '200-299');
  // The same backup again: everything is already there.
  const again = await call(preview, 'POST', backup);
  assert.deepEqual(again.body.add, []);
  assert.deepEqual(again.body.change, []);
  assert.equal(
    again.body.skip.filter(s => s.reason === 'Already in Uptime Goblin with the same settings.')
      .length,
    7
  );
  // Recorded as one configuration change, with its counts and what changed.
  const rows = await importRows();
  assert.equal(rows.length, 2, 'an attempt and its result');
  const result = rows.find(row => row.outcome === 'ok');
  assert.equal(result.status, 200);
  assert.deepEqual(result.target, { type: 'sources', id: 'uptime-kuma', name: null });
  assert.equal(result.detail.added, 6);
  assert.equal(result.detail.changed, 1);
  assert.equal(result.detail.skipped, 13);
  assert.equal(result.detail.ifMatch, true);
  assert.ok(Array.isArray(result.detail.diff) && result.detail.diff.length > 0);
  // No credential of the backup reached the configuration, the audit log or an answer.
  const stored = fs.readFileSync(path.join(directory, 'config.json'), 'utf8');
  const audit = JSON.stringify(rows);
  for (const secret of [...secrets, 'redacted'])
    for (const [where, text] of [
      ['config.json', stored],
      ['audit', audit],
      ['preview', shown.text],
      ['apply', done.text],
    ])
      assert.ok(!text.includes(secret), `${secret} in ${where}`);
});

test('the raw backup and its reduction preview the same plan, and a change in between is a conflict', async t => {
  const { call, revision } = await fixture(t);
  const backup = mixedBackup();
  const full = await call(preview, 'POST', backup),
    reduced = await call(preview, 'POST', reduceKumaBackup(backup));
  assert.equal(full.status, 200);
  assert.deepEqual(full.body, reduced.body);
  // Another change after the preview: the apply is refused, nothing is saved.
  const before = await revision();
  assert.equal(
    (
      await call('/api/services', 'POST', {
        type: 'http',
        name: 'Elsewhere',
        url: 'https://e.example.com/',
      })
    ).status,
    201
  );
  const refused = await call(apply, 'POST', reduceKumaBackup(backup), {
    'If-Match': String(full.body.revision),
  });
  assert.equal(refused.status, 409);
  assert.equal(await revision(), before + 1);
});

test('a backup that cannot be imported is refused before the write, unrecorded; a large one gets 413', async t => {
  const { call, revision, importRows } = await fixture(t);
  const before = await revision();
  for (const body of [
    kumaBackup([], '2.0.0'),
    { version: '1.23.16' },
    [],
    kumaBackup([kumaMonitor(1), kumaMonitor(1)]),
    '{"version":"1.23.16","monitorList":[{"id":1,"__proto__":{"x":1}}]}',
    '{"version":"1.23.16","monitorList":[{"id":1,"constructor":{"prototype":{"x":1}}}]}',
    'not json',
  ]) {
    for (const route of [preview, apply]) {
      const answer = await call(route, 'POST', body, { 'If-Match': String(before) });
      assert.equal(answer.status, 400, `${route} ${JSON.stringify(body).slice(0, 80)}`);
      assert.equal(typeof answer.body.error, 'string');
    }
  }
  assert.match(
    (await call(preview, 'POST', kumaBackup([], '2.0.0'))).body.error,
    /Only Uptime Kuma 1\.x backups can be imported; this one is from version 2\.0\.0\./
  );
  // Just above the API's request limit (sent whole, as hardening.test.mjs sends one): 413.
  const monitors = Array.from({ length: 100 }, (_, i) => kumaMonitor(i + 1));
  const pad = Math.ceil((152000 - JSON.stringify(kumaBackup(monitors)).length) / 100);
  const large = kumaBackup(monitors.map(m => ({ ...m, description: 'd'.repeat(pad) })));
  assert.ok(JSON.stringify(large).length > 150000);
  assert.equal((await call(preview, 'POST', large)).status, 413);
  assert.equal((await call(apply, 'POST', large, { 'If-Match': String(before) })).status, 413);
  // Its reduction fits.
  assert.equal((await call(preview, 'POST', reduceKumaBackup(large))).status, 200);
  assert.equal(await revision(), before);
  assert.deepEqual(await importRows(), []);
  // A backup with nothing to add saves nothing, and says so.
  const empty = await call(apply, 'POST', kumaBackup([kumaMonitor(1, { type: 'ping' })]), {
    'If-Match': String(before),
  });
  assert.equal(empty.status, 200);
  assert.deepEqual([empty.body.added, empty.body.changed, empty.body.skipped], [[], [], 1]);
  assert.equal(await revision(), before);
});

test('both routes need a signed-in caller and the CSRF header', async t => {
  const { call, revision } = await fixture(t);
  const before = await revision(),
    backup = reduceKumaBackup(mixedBackup());
  for (const route of [preview, apply]) {
    const headers = { 'If-Match': String(before) };
    assert.equal(
      (await call(route, 'POST', backup, { ...headers, Authorization: '' })).status,
      401
    );
    assert.equal(
      (await call(route, 'POST', backup, { ...headers, Authorization: basic('wrong-password-01') }))
        .status,
      401
    );
    // No X-Goblin-Request: a cross-site form could have sent it.
    assert.equal(
      (await call(route, 'POST', backup, { ...headers, 'X-Goblin-Request': '' })).status,
      403
    );
    // Only POST.
    assert.equal((await call(route, 'GET')).status, 405);
  }
  assert.equal(await revision(), before);
});

test('a caller without config:import is refused before the backup is read (deny by default)', async t => {
  let ran = 0;
  const app = {
    config: {
      get value() {
        ran++;
        return { revision: 1, services: [] };
      },
    },
  };
  const permitted = (access, permission) => permission !== 'config:import';
  const { port } = await serveAuth(t, { routes: importRoutes(app), permitted });
  for (const target of [preview, apply]) {
    const body = JSON.stringify(kumaBackup([kumaMonitor(1)]));
    const answer = await raw(
      port,
      [
        `POST ${target} HTTP/1.1`,
        `Authorization: ${basic()}`,
        'Content-Type: application/json',
        'X-Goblin-Request: 1',
        'If-Match: 1',
      ],
      body
    );
    assert.equal(answer.status, 403, target);
  }
  assert.equal(ran, 0, 'no handler ran');
  // With the permission, the same request reaches the preview.
  const allowed = await serveAuth(t, { routes: importRoutes(app) });
  const answer = await raw(
    allowed.port,
    [
      `POST ${preview} HTTP/1.1`,
      `Authorization: ${basic()}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
    ],
    JSON.stringify(kumaBackup([kumaMonitor(1)]))
  );
  assert.equal(answer.status, 200, answer.body);
  assert.equal(answer.json.add.length, 1);
});

test('a change the import saves runs the same follow-up steps as PATCH /api/services/:id', async t => {
  const { app, call, revision } = await fixture(t);
  const created = [];
  for (const [name, enabled] of [
    ['Site 1', true],
    ['Site 2', false],
  ]) {
    const saved = await call('/api/services', 'POST', {
      type: 'http',
      name,
      group: 'Media',
      enabled,
      url: `https://old${name.at(-1)}.example.com/`,
    });
    assert.equal(saved.status, 201, saved.text);
    created.push(saved.body.service.id);
  }
  const steps = [];
  for (const method of ['reconcileRules', 'clearAlerts', 'markGap'])
    t.mock.method(app.store, method, id => steps.push([method, id]));
  const done = await call(apply, 'POST', kumaBackup([kumaMonitor(1), kumaMonitor(2)]), {
    'If-Match': String(await revision()),
  });
  assert.equal(done.status, 200, done.text);
  assert.deepEqual(
    done.body.changed.map(c => c.id),
    created
  );
  // The running check keeps its alert rules; the paused one stays paused, its alerts cleared and
  // a gap marked, as a PATCH of the same settings does.
  assert.deepEqual(steps, [
    ['reconcileRules', created[0]],
    ['reconcileRules', created[1]],
    ['clearAlerts', created[1]],
    ['markGap', created[1]],
  ]);
  // Neither monitor names a Kuma group: both checks keep the group they were given in Uptime Goblin.
  for (const id of created) {
    assert.equal(app.config.get(id).group, 'Media');
    assert.equal(app.config.get(id).url, `https://site${id === created[0] ? 1 : 2}.example.com/`);
  }
  assert.equal(app.config.get(created[1]).enabled, false);
});
