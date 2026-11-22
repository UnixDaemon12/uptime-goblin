// The Uptime Kuma import without a server: the backup reader the browser and the server share
// (public/shared/uptime-kuma.js), the plan (lib/import/uptime-kuma.mjs) and the one-revision
// save (ConfigStore.importSources), against synthetic Kuma 1.x backups. Every address is a
// documentation one (example.com); no backup is fetched or evaluated.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  KUMA_MONITORS_MAX,
  KumaBackupError,
  readKumaBackup,
  reduceKumaBackup,
} from '../public/shared/uptime-kuma.js';
import { planKumaImport, publicPlan, SOURCES_MAX } from '../lib/import/uptime-kuma.mjs';
import { ConfigStore, InputError } from '../lib/config.mjs';
import { newService } from '../lib/catalog.mjs';
import { kumaBackup, kumaMonitor, kumaSecrets, mixedBackup } from './helpers/kuma.mjs';

// Secrets planted in the backups: none may reach a plan, a reduced backup or a saved source.
const secrets = kumaSecrets;

const services = (...list) => list;
const website = (id, name, fields = {}) => ({ ...newService('http', id, name), ...fields });
const byId = (plan, list, kumaId) => plan[list].find(item => item.kumaId === kumaId);

test('a backup of every kind: HTTP and keyword monitors are added, groups name them, everything else is skipped with its reason', () => {
  const plan = planKumaImport(mixedBackup(), []);
  assert.equal(plan.version, '1.23.16');
  assert.deepEqual(
    plan.add.map(a => a.kumaId),
    [2, 3, 4, 5, 6, 7, 8]
  );
  assert.deepEqual(plan.change, []);
  assert.deepEqual(
    plan.skip.map(s => [s.kumaId, s.type]),
    [
      [1, 'group'],
      [9, 'ping'],
      [10, 'port'],
      [11, 'dns'],
      [12, 'docker'],
      [13, 'push'],
      [14, 'json-query'],
      [15, 'steam'],
      [16, 'real-browser'],
      [17, 'http'],
      [18, 'http'],
      [19, 'http'],
      [20, 'http'],
    ]
  );
  for (const skipped of plan.skip) assert.ok(skipped.reason.length > 10, skipped.kumaId);
  assert.match(byId(plan, 'skip', 1).reason, /group/i);
  assert.match(byId(plan, 'skip', 9).reason, /Ping monitors are not supported/);
  assert.match(byId(plan, 'skip', 15).reason, /type steam are not supported/);
  assert.match(byId(plan, 'skip', 17).reason, /Upside down/);
  assert.match(byId(plan, 'skip', 18).reason, /sends POST/);
  assert.match(byId(plan, 'skip', 19).reason, /does not use HTTP or HTTPS/);
  assert.match(
    byId(plan, 'skip', 20).reason,
    /Uptime Goblin cannot check it: HTTP statuses must be 100–599/
  );

  // The group's name is its monitors' group; one without a group gets the Website default.
  assert.deepEqual(byId(plan, 'add', 2), {
    kumaId: 2,
    name: 'Plex web',
    group: 'Media',
    url: 'https://site2.example.com/',
    method: 'GET',
    expectedStatus: '200-299',
    pollSeconds: 60,
    enabled: true,
    needsCredentials: false,
    notes: [
      'Redirects are not followed: if the address redirects, use the final address or accept 300-399.',
    ],
  });
  assert.equal(byId(plan, 'add', 3).group, 'Utilities');
  // A keyword is listed as not checked; without redirects there is nothing to say about them.
  assert.deepEqual(byId(plan, 'add', 3).notes, [
    "Keyword not checked: Uptime Goblin's Website check tests the HTTP status only, not the page text.",
  ]);
  // HEAD is kept; the interval is clamped into Uptime Goblin's range; accepting 3xx needs no note.
  const head = byId(plan, 'add', 4);
  assert.equal(head.method, 'HEAD');
  assert.equal(head.pollSeconds, 15);
  assert.equal(head.expectedStatus, '200-299,300-399');
  assert.deepEqual(head.notes, ['Interval raised to 15 seconds (Uptime Goblin allows 15–3600).']);
  // Ignore TLS is never imitated; a paused monitor stays paused.
  const slow = byId(plan, 'add', 5);
  assert.equal(slow.pollSeconds, 3600);
  assert.equal(slow.enabled, false);
  assert.ok(
    slow.notes.includes('Interval lowered to 3600 seconds (Uptime Goblin allows 15–3600).')
  );
  assert.ok(
    slow.notes.some(note => note.startsWith('Uptime Goblin always verifies TLS certificates'))
  );
  assert.deepEqual(plan.notes.length, 2);
});

test('credentials are never imported: monitors that had them are marked, and the address loses them', () => {
  const plan = planKumaImport(mixedBackup(), []);
  for (const kumaId of [6, 7, 8]) {
    const added = byId(plan, 'add', kumaId);
    assert.equal(added.needsCredentials, true, kumaId);
    assert.ok(
      added.notes.some(note => note.startsWith('Needs credentials re-entered')),
      kumaId
    );
  }
  for (const kumaId of [2, 3, 4, 5])
    assert.equal(byId(plan, 'add', kumaId).needsCredentials, false);
  assert.equal(byId(plan, 'add', 7).url, 'https://site7.example.com/?q=1');
  assert.ok(byId(plan, 'add', 7).notes.includes('Credentials were removed from the address.'));
  // No secret anywhere in the plan, the settings it would save included.
  const text = JSON.stringify(plan);
  for (const secret of secrets) assert.ok(!text.includes(secret), secret);
  for (const input of plan.inputs.add)
    assert.deepEqual(Object.keys(input).sort(), [
      'enabled',
      'group',
      'httpExpectedStatus',
      'httpMethod',
      'name',
      'pollSeconds',
      'type',
      'url',
    ]);
  assert.equal(publicPlan(plan).inputs, undefined);
});

const withoutAuthMethod = monitor => {
  delete monitor.authMethod;
  return monitor;
};

test('authMethod and its parameters select a mode: only secrets, or the fields of the mode in use, mark a monitor', () => {
  const cases = [
    // Kuma 1.23's defaults (oauth_auth_method "client_secret_basic" and the rest) mark nothing.
    [kumaMonitor(1), false],
    [kumaMonitor(2, { authMethod: 'none' }), false],
    [kumaMonitor(3, { authMethod: 'basic' }), false],
    [
      kumaMonitor(4, { oauth_token_url: 'https://auth.example.com/token', oauth_scopes: 'read' }),
      false,
    ],
    [kumaMonitor(5, { oauth_client_id: 'orbit-client' }), false],
    [kumaMonitor(6, { authMethod: 'oauth2-cc', oauth_client_id: 'orbit-client' }), true],
    // authMethod null (the helper's default, as Kuma saves "None") or absent: a release before
    // authMethod sent basic authentication whenever a user name was set.
    [kumaMonitor(7, { basic_auth_user: 'admin' }), true],
    [kumaMonitor(8, { authMethod: 'basic', basic_auth_user: 'admin' }), true],
    [kumaMonitor(9, { authMethod: 'ntlm', authDomain: 'EXAMPLE' }), true],
    [kumaMonitor(10, { tlsCert: '-----BEGIN CERTIFICATE-----' }), false],
    [kumaMonitor(11, { authMethod: 'mtls', tlsCert: '-----BEGIN CERTIFICATE-----' }), true],
    [kumaMonitor(12, { authMethod: 'something-new', basic_auth_user: 'admin' }), false],
    // Secrets mark a monitor whatever the mode says.
    [kumaMonitor(13, { basic_auth_pass: 'kuma-basic-secret' }), true],
    [kumaMonitor(14, { authMethod: 'none', oauth_client_secret: 'kuma-oauth-secret' }), true],
    [kumaMonitor(15, { tlsKey: '-----BEGIN PRIVATE KEY-----' }), true],
    [kumaMonitor(16, { headers: '{"Authorization":"Bearer kuma-header-token"}' }), true],
    [kumaMonitor(17, { headers: '{}' }), false],
    [kumaMonitor(18, { body: 'token=kuma-header-token' }), true],
    [kumaMonitor(19, { authMethod: { not: 'text' } }), false],
    [withoutAuthMethod(kumaMonitor(20, { basic_auth_user: 'admin' })), true],
    [withoutAuthMethod(kumaMonitor(21, { basic_auth_user: '  ' })), false],
    [withoutAuthMethod(kumaMonitor(22)), false],
    [kumaMonitor(23, { authMethod: 'none', basic_auth_user: 'admin' }), false],
  ];
  // The cases start from the helper's defaults, named here: no mode, no user name, and no
  // address-credentials mark (only reduceKumaBackup() sets goblinAddressCredentials).
  const defaults = kumaMonitor(0);
  assert.equal(defaults.authMethod, null);
  assert.equal(defaults.basic_auth_user, null);
  assert.equal(Object.hasOwn(defaults, 'goblinAddressCredentials'), false);
  const backup = kumaBackup(cases.map(([monitor]) => monitor));
  for (const plan of [planKumaImport(backup, []), planKumaImport(reduceKumaBackup(backup), [])])
    for (const [monitor, marked] of cases) {
      const added = byId(plan, 'add', monitor.id);
      assert.equal(added.needsCredentials, marked, monitor.id);
      assert.equal(
        added.notes.some(note => note.startsWith('Needs credentials re-entered')),
        marked,
        monitor.id
      );
    }
  const reduced = reduceKumaBackup(backup).monitorList;
  assert.equal(reduced[0].authMethod, undefined);
  assert.equal(reduced[5].authMethod, 'oauth2-cc');
  assert.equal(reduced[11].authMethod, 'unknown', 'an unknown mode is sent as unknown');
  assert.equal(reduced[18].authMethod, 'unknown');
  assert.equal(reduced[19].authMethod, undefined, 'an absent mode stays absent');
  assert.equal(reduced[19].basic_auth_user, 'redacted');
  for (const field of ['oauth_auth_method', 'oauth_token_url', 'oauth_scopes'])
    assert.ok(
      reduced.every(monitor => !Object.hasOwn(monitor, field)),
      field
    );
});

test('a monitor Uptime Kuma checked through a proxy is noted: Uptime Goblin connects directly', () => {
  const plan = planKumaImport(
    kumaBackup([
      kumaMonitor(1, { proxyId: 3 }),
      kumaMonitor(2, { proxyId: null }),
      kumaMonitor(3, { proxyId: 0 }),
      kumaMonitor(4, { proxyId: 'x' }),
    ]),
    []
  );
  const note =
    'Uptime Kuma checked it through a proxy; Uptime Goblin connects directly, so the address must be reachable from Uptime Goblin.';
  assert.ok(byId(plan, 'add', 1).notes.includes(note));
  assert.ok(!byId(plan, 'add', 2).notes.includes(note));
  assert.ok(!byId(plan, 'add', 3).notes.includes(note));
  assert.equal(byId(plan, 'skip', 4).reason, 'Malformed entry: Its proxy is not valid.');
  const backup = kumaBackup([kumaMonitor(1, { proxyId: 3 }), kumaMonitor(4, { proxyId: 'x' })]);
  assert.deepEqual(planKumaImport(reduceKumaBackup(backup), []), planKumaImport(backup, []));
});

test('the reduced backup the browser sends gives the same plan and holds no credential', () => {
  const backup = mixedBackup();
  backup.monitorList.push(
    kumaMonitor(21, { name: 'x'.repeat(5000) }),
    kumaMonitor(22, { url: 'https://example.com/' + 'a'.repeat(5000) }),
    kumaMonitor(23, { accepted_statuscodes: Array(80).fill('200-299') }),
    kumaMonitor(24, { name: { nested: 'x'.repeat(1000) } }),
    'not a monitor',
    kumaMonitor(25, { active: 'yes' }),
    // Addresses the import skips send nothing of their credentials either.
    kumaMonitor(26, { url: 'ftp://user:kuma-url-pw@files.example.com/' }),
    kumaMonitor(27, { url: 'https://user:kuma-url-pw@example.com/' + 'a'.repeat(5000) }),
    kumaMonitor(28, { url: 'https://kuma-url-pw in a host.example.com/' }),
    kumaMonitor(29, { url: 'https://example.com/#/home&access_token=kuma-url-pw' })
  );
  const reduced = reduceKumaBackup(backup),
    text = JSON.stringify(reduced);
  for (const secret of secrets) assert.ok(!text.includes(secret), secret);
  assert.ok(!text.includes('notificationList'));
  const plain = mixedBackup();
  assert.ok(
    JSON.stringify(reduceKumaBackup(plain)).length < JSON.stringify(plain).length / 3,
    'much smaller'
  );
  assert.equal(reduced.monitorList[5].basic_auth_pass, 'redacted');
  // The mode is kept (it holds no secret); a mode selector without a secret is not sent.
  assert.equal(reduced.monitorList[5].authMethod, 'basic');
  assert.equal(reduced.monitorList[5].oauth_auth_method, undefined);
  assert.deepEqual(planKumaImport(reduced, []), planKumaImport(backup, []));
  // Through JSON, as it is sent.
  assert.deepEqual(planKumaImport(JSON.parse(text), []), planKumaImport(backup, []));
});

test('a malformed backup is refused with a fixed message; a malformed monitor is skipped', () => {
  for (const [value, message] of [
    [null, /not an Uptime Kuma backup/],
    [[], /not an Uptime Kuma backup/],
    ['{"version":"1.23.0"}', /not an Uptime Kuma backup/],
    [{ monitorList: [] }, /names no version/],
    [{ version: 1.23, monitorList: [] }, /names no version/],
    [{ version: '1.23.16' }, /no monitor list/],
    [{ version: '1.23.16', monitorList: {} }, /no monitor list/],
    [kumaBackup([kumaMonitor(1), kumaMonitor(1)]), /lists monitor id 1 twice/],
  ]) {
    assert.throws(() => readKumaBackup(value), KumaBackupError, JSON.stringify(value));
    assert.throws(
      () => planKumaImport(value, []),
      error => {
        assert.ok(error instanceof InputError);
        assert.match(error.message, message);
        return true;
      }
    );
  }
  const plan = planKumaImport(
    kumaBackup([
      'text',
      null,
      kumaMonitor(0),
      kumaMonitor(2, { name: 7 }),
      kumaMonitor(3, { type: '' }),
      kumaMonitor(4, { url: 42 }),
      kumaMonitor(5, { interval: '60' }),
      kumaMonitor(6, { parent: 'Media' }),
      kumaMonitor(7, { accepted_statuscodes: '200-299' }),
      kumaMonitor(8, { maxredirects: -1 }),
      kumaMonitor(9, { ignoreTls: 'no' }),
      kumaMonitor(10, { method: { GET: true } }),
      kumaMonitor(11, { keyword: ['a'] }),
      kumaMonitor(12, { url: '' }),
      kumaMonitor(13, { url: 'not a url' }),
      kumaMonitor(14),
    ]),
    []
  );
  assert.deepEqual(
    plan.add.map(a => a.kumaId),
    [14]
  );
  assert.deepEqual(
    plan.skip.map(s => s.reason),
    [
      'Malformed entry: Entry 1 is not a monitor.',
      'Malformed entry: Entry 2 is not a monitor.',
      'Malformed entry: It has no valid id.',
      'Malformed entry: It has no name.',
      'Malformed entry: It has no type.',
      'Malformed entry: Its address is not text.',
      'Malformed entry: Its interval is not a number.',
      'Malformed entry: Its group is not valid.',
      'Malformed entry: Its accepted status codes are not valid.',
      'Malformed entry: Its redirect limit is not valid.',
      'Malformed entry: Its ignoreTls setting is not valid.',
      'Malformed entry: Its HTTP method is not valid.',
      'Malformed entry: Its keyword is not valid.',
      'It has no address.',
      'Its address is not a complete HTTP or HTTPS URL.',
    ]
  );
});

test('only Uptime Kuma 1.x backups are read; a version is shown only when it is plain', () => {
  for (const version of ['1.0.0', '1.23.16', '1.23.0-beta.1'])
    assert.equal(readKumaBackup(kumaBackup([], version)).version, version);
  assert.throws(
    () => readKumaBackup(kumaBackup([], '2.0.0')),
    /Only Uptime Kuma 1\.x backups can be imported; this one is from version 2\.0\.0\./
  );
  assert.throws(() => readKumaBackup(kumaBackup([], '0.9.1')), /from version 0\.9\.1/);
  // Text that is not a plain version is never echoed.
  assert.throws(
    () => readKumaBackup(kumaBackup([], '<img src=x onerror=alert(1)>')),
    error => error.message === 'Only Uptime Kuma 1.x backups can be imported.'
  );
  assert.throws(() => readKumaBackup(kumaBackup([], '1.23')), /Only Uptime Kuma 1\.x/);
});

test('an oversized backup is refused, and long texts are cut or skipped, never kept whole', () => {
  const many = kumaBackup(
    Array.from({ length: KUMA_MONITORS_MAX + 1 }, (_, i) => kumaMonitor(i + 1))
  );
  assert.throws(() => readKumaBackup(many), /lists 1001 monitors; at most 1000/);
  assert.throws(() => reduceKumaBackup(many), KumaBackupError);
  const plan = planKumaImport(
    kumaBackup([
      kumaMonitor(1, { name: 'N'.repeat(150) }),
      kumaMonitor(2, { name: 'N'.repeat(1001) }),
      kumaMonitor(3, { url: 'https://example.com/' + 'a'.repeat(4100) }),
      kumaMonitor(4, { url: 'https://example.com/' + 'a'.repeat(3000) }),
      kumaMonitor(5, { keyword: 'k'.repeat(1001), type: 'keyword' }),
      // Line breaks and direction controls in a name become spaces or go.
      kumaMonitor(6, { name: 'Line\nbreak‮ and more\u0000' }),
      // A name of an emoji cut at 100 UTF-16 units keeps whole characters.
      kumaMonitor(7, { name: '\u{1f600}'.repeat(60) }),
      kumaMonitor(8, { name: '   ' }),
    ]),
    []
  );
  const first = byId(plan, 'add', 1);
  assert.equal(first.name, 'N'.repeat(100));
  assert.ok(first.notes.includes('Name shortened to 100 characters.'));
  assert.match(byId(plan, 'skip', 2).reason, /name is longer than 1000 characters/);
  assert.match(byId(plan, 'skip', 3).reason, /address is longer than 4096 characters/);
  assert.match(byId(plan, 'skip', 4).reason, /Uptime Goblin cannot check it: Invalid destination/);
  assert.match(byId(plan, 'skip', 5).reason, /keyword is not valid/);
  assert.equal(byId(plan, 'add', 6).name, 'Line break and more');
  assert.equal(byId(plan, 'add', 7).name, '\u{1f600}'.repeat(50));
  assert.equal(byId(plan, 'add', 8).name, 'Uptime Kuma monitor 8');
  // A skipped monitor's name is shown cut too.
  assert.equal(byId(plan, 'skip', 2).name.length, 100);
});

test('prototype-pollution keys are refused anywhere, and nothing reaches Object.prototype', () => {
  for (const text of [
    '{"version":"1.23.16","__proto__":{"polluted":1},"monitorList":[]}',
    '{"version":"1.23.16","constructor":{"prototype":{"polluted":1}},"monitorList":[]}',
    '{"version":"1.23.16","monitorList":[{"id":1,"name":"a","type":"http","__proto__":{"polluted":1}}]}',
    '{"version":"1.23.16","monitorList":[{"id":1,"name":"a","type":"http","prototype":{"polluted":1}}]}',
  ]) {
    const value = JSON.parse(text);
    assert.throws(
      () => readKumaBackup(value),
      /has a field named (__proto__|constructor|prototype)/
    );
    assert.throws(() => reduceKumaBackup(value), KumaBackupError);
    assert.throws(() => planKumaImport(value, []), InputError);
  }
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
});

test('a name collision changes the saved Website check, or skips with the reason, never two sources of one name', () => {
  const saved = services(
    website('http-1', 'Plex web', {
      url: 'https://old.example.com/',
      apiUrl: 'https://check.example.com',
      metricPath: '/health',
      pollSeconds: 0,
      group: 'Media',
    }),
    website('http-2', 'SITE 3', {
      url: 'https://site3.example.com/',
      httpExpectedStatus: '200-299',
      pollSeconds: 60,
      group: 'Utilities',
    }),
    { ...newService('linux', 'linux-1', 'Site 4') },
    website('http-3', 'Site 5'),
    website('http-4', 'site 5')
  );
  const plan = planKumaImport(
    kumaBackup([
      kumaMonitor(1, { type: 'group', name: 'Media', url: null }),
      kumaMonitor(2, { name: 'Plex web', parent: 1 }),
      kumaMonitor(3, { maxredirects: 0 }),
      kumaMonitor(4),
      kumaMonitor(5),
      // Another monitor of a name already taken in this import gets a number.
      kumaMonitor(6, { name: 'plex WEB' }),
      kumaMonitor(7, { name: 'Plex web (2)' }),
    ]),
    saved
  );
  assert.deepEqual(plan.change, [
    {
      kumaId: 2,
      id: 'http-1',
      name: 'Plex web',
      fields: ['url', 'apiUrl', 'metricPath', 'httpExpectedStatus', 'pollSeconds'],
      url: 'https://site2.example.com/',
      method: 'GET',
      expectedStatus: '200-299',
      pollSeconds: 60,
      group: 'Media',
      needsCredentials: false,
      notes: [
        'Redirects are not followed: if the address redirects, use the final address or accept 300-399.',
      ],
    },
  ]);
  assert.deepEqual(plan.inputs.change, [
    [
      'http-1',
      {
        url: 'https://site2.example.com/',
        apiUrl: '',
        metricPath: '',
        httpExpectedStatus: '200-299',
        pollSeconds: 60,
      },
    ],
  ]);
  assert.equal(byId(plan, 'skip', 3).reason, 'Already in Uptime Goblin with the same settings.');
  assert.equal(
    byId(plan, 'skip', 4).reason,
    'An Uptime Goblin Linux systems source is already named Site 4.'
  );
  assert.equal(byId(plan, 'skip', 5).reason, '2 Uptime Goblin sources are already named Site 5.');
  assert.deepEqual(
    plan.add.map(a => [a.kumaId, a.name]),
    [
      [6, 'plex WEB (2)'],
      [7, 'Plex web (2) (2)'],
    ]
  );
  assert.ok(
    byId(plan, 'add', 6).notes.includes('Renamed: another monitor in the backup has the same name.')
  );
  // A website check on another kind of card (a Sonarr card checked as a website) is not changed.
  const sonarr = { ...newService('sonarr', 'sonarr-1', 'Site 1'), collector: 'http' };
  assert.match(
    planKumaImport(kumaBackup([kumaMonitor(1)]), [sonarr]).skip[0].reason,
    /An Uptime Goblin Sonarr source is already named Site 1/
  );
});

test('on a name collision a monitor without a Kuma group keeps the Uptime Goblin group; a Kuma group moves it', () => {
  const saved = services(
    website('http-1', 'Site 1', { url: 'https://old1.example.com/', group: 'Media' }),
    website('http-2', 'Site 2', {
      url: 'https://site2.example.com/',
      group: 'Media',
      httpExpectedStatus: '200-299',
      pollSeconds: 60,
    }),
    website('http-3', 'Site 3', { url: 'https://old3.example.com/', group: 'Media' })
  );
  const plan = planKumaImport(
    kumaBackup([
      kumaMonitor(1),
      kumaMonitor(2),
      kumaMonitor(10, { type: 'group', name: 'Network', url: null }),
      kumaMonitor(3, { parent: 10 }),
    ]),
    saved
  );
  const one = byId(plan, 'change', 1);
  assert.ok(!one.fields.includes('group'));
  assert.equal(one.group, 'Media');
  assert.ok(!Object.hasOwn(plan.inputs.change[0][1], 'group'));
  // Only the group would differ, and Kuma names none: nothing to change.
  assert.equal(byId(plan, 'skip', 2).reason, 'Already in Uptime Goblin with the same settings.');
  const three = byId(plan, 'change', 3);
  assert.ok(three.fields.includes('group'));
  assert.equal(three.group, 'Network');
  assert.equal(plan.inputs.change[1][1].group, 'Network');
  // A change sets only the Website check's address, method, statuses, interval and group: never
  // what the save's follow-up steps react to (type, collector, enabled, rules, node, credentials).
  for (const [, change] of plan.inputs.change)
    for (const field of Object.keys(change))
      assert.ok(
        [
          'url',
          'apiUrl',
          'metricPath',
          'httpMethod',
          'httpExpectedStatus',
          'pollSeconds',
          'group',
        ].includes(field),
        field
      );
});

test('the import never takes Uptime Goblin past its 200 sources', () => {
  const saved = Array.from({ length: SOURCES_MAX - 1 }, (_, i) =>
    website(`http-${i + 1}`, `Saved ${i}`)
  );
  const plan = planKumaImport(kumaBackup([kumaMonitor(1), kumaMonitor(2), kumaMonitor(3)]), saved);
  assert.deepEqual(
    plan.add.map(a => a.kumaId),
    [1]
  );
  assert.deepEqual(
    plan.skip.map(s => [s.kumaId, s.reason]),
    [
      [2, 'Uptime Goblin holds at most 200 sources.'],
      [3, 'Uptime Goblin holds at most 200 sources.'],
    ]
  );
});

test('the plan of 1,000 monitors against 200 sources stays within its budget (250 ms)', () => {
  const saved = Array.from({ length: SOURCES_MAX }, (_, i) =>
    website(`http-${i + 1}`, `Saved ${i}`)
  );
  const backup = kumaBackup(
    Array.from({ length: KUMA_MONITORS_MAX }, (_, i) =>
      kumaMonitor(i + 1, {
        name: i % 3 ? `Saved ${i}` : `New ${i}`,
        type: i % 2 ? 'http' : 'keyword',
      })
    )
  );
  planKumaImport(backup, saved);
  const started = performance.now();
  const plan = planKumaImport(reduceKumaBackup(backup), saved);
  const elapsed = performance.now() - started;
  assert.equal(plan.add.length + plan.change.length + plan.skip.length, KUMA_MONITORS_MAX);
  assert.ok(elapsed < 250, `${Math.round(elapsed)} ms`);
});

test('importSources saves every added and changed source in one revision, with new IDs, or nothing', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-kuma-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const config = new ConfigStore(directory);
  const existing = config.add({ type: 'http', name: 'Plex web', url: 'https://old.example.com/' });
  config.remove(existing.id);
  const kept = config.add({ type: 'http', name: 'Plex web', url: 'https://old.example.com/' });
  const before = config.value.revision,
    count = config.value.services.length;
  const plan = planKumaImport(mixedBackup(), config.value.services);
  assert.equal(plan.change.length, 1);
  const { added, changed } = config.importSources(plan.inputs);
  assert.equal(config.value.revision, before + 1, 'one revision');
  assert.equal(config.value.services.length, count + plan.add.length);
  // IDs are never reused: the removed http-1 stays unused.
  assert.deepEqual(
    added.map(s => s.id),
    plan.add.map((_, i) => `http-${i + 3}`)
  );
  assert.deepEqual(
    added.map(s => s.name),
    plan.add.map(a => a.name)
  );
  assert.equal(changed[0][0].id, kept.id);
  assert.equal(config.get(kept.id).url, 'https://site2.example.com/');
  const saved = fs.readFileSync(path.join(directory, 'config.json'), 'utf8');
  for (const secret of [...secrets, 'redacted']) assert.ok(!saved.includes(secret), secret);
  // A refused source saves none of them.
  const revision = config.value.revision;
  assert.throws(
    () =>
      config.importSources({
        add: [
          { type: 'http', name: 'Fine', url: 'https://ok.example.com/' },
          { type: 'http', name: '' },
        ],
      }),
    InputError
  );
  assert.equal(config.value.revision, revision);
  assert.throws(
    () =>
      config.importSources({
        add: Array.from({ length: 201 }, (_, i) => ({
          type: 'http',
          name: `S${i}`,
          url: 'https://ok.example.com/',
        })),
      }),
    /At most 200 sources/
  );
  assert.equal(config.value.revision, revision);
});
