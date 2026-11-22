// Configuration diffs (lib/audit/diff.mjs, audit spec D11): leaf paths, sources by id, what is
// left out, value cuts, the 16 KiB cut, secrets only as set/changed/cleared (also a secret changed
// from one value to another, which publicConfig cannot show), the name mask, URL credentials
// stripped, and a property test that no planted secret ever reaches a diff in any encoding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { defaults, newService } from '../../lib/catalog.mjs';
import {
  configDiff,
  configSnapshot,
  sameContent,
  withoutUrlCredentials,
} from '../../lib/audit/diff.mjs';
import { launchUrl, withoutCredentials } from '../../lib/config.mjs';
import { buildRow, fitDetail } from '../../lib/audit/writer.mjs';
import { canonicalJSON } from '../../lib/audit/chain.mjs';
import { DETAIL_MAX_BYTES } from '../../lib/audit/actions.mjs';
import { findSentinels } from '../helpers/audit-sentinels.mjs';
import { adminRequest, auditFixture, storedRows } from './helpers.mjs';

const key = {
  kid: 'k1',
  mac: data => createHmac('sha256', Buffer.alloc(32, 9)).update(data).digest('hex'),
};
const snap = value => configSnapshot(value, key);
const config = (change = () => {}) => {
  const value = { ...structuredClone(defaults()), revision: 3, sourceCounters: { plex: 1 } };
  value.services = [newService('plex', 'plex-1', 'Plex'), newService('http', 'site-2', 'Blog')];
  change(value);
  return value;
};

test('leaf paths: dotted, sources by id never by index, arrays whole; revision, sourceCounters and *Configured left out', () => {
  const before = snap(config());
  assert.equal(before.revision, 3);
  assert.ok('title' in before.public);
  assert.ok('email.host' in before.public);
  assert.ok('services.plex-1.url' in before.public);
  assert.ok('services.site-2.metrics' in before.public);
  assert.ok(Array.isArray(before.public['services.plex-1.metrics']));
  for (const path of Object.keys(before.public)) {
    assert.doesNotMatch(path, /Configured$|^revision$|^sourceCounters/, path);
    assert.doesNotMatch(path, /^services\.\d/, 'never by index');
  }
  assert.deepEqual(Object.keys(before.public), Object.keys(before.public).sort(), 'sorted');
  // Reordering the sources changes nothing; a change to one source names it by id.
  const reordered = snap(config(value => value.services.reverse()));
  assert.deepEqual(configDiff(before, reordered), []);
  const after = snap(
    config(value => {
      value.services[1].name = 'New blog';
      value.services[0].metrics = [{ key: 'streams' }];
      value.email.host = 'mail.example.com';
      value.revision = 4;
      value.sourceCounters.plex = 9;
    })
  );
  assert.deepEqual(configDiff(before, after), [
    { path: 'email.host', from: 'smtp.gmail.com', to: 'mail.example.com' },
    { path: 'services.plex-1.metrics', from: [], to: [{ key: 'streams' }] },
    { path: 'services.site-2.name', from: 'Blog', to: 'New blog' },
  ]);
  // A source added or deleted: its leaves from or to null.
  const added = snap(
    config(value => value.services.push(newService('sonarr', 'unifi-3', 'UniFi')))
  );
  const changes = configDiff(before, added);
  assert.ok(changes.length > 5);
  assert.ok(
    changes.every(
      change =>
        change.path.startsWith('services.unifi-3.') && (change.from === null || change.change)
    )
  );
  assert.ok(
    sameContent(before, snap(config(value => (value.revision = 99)))),
    'the revision is not content'
  );
});

test('values are cut to 200 characters with … (their JSON text when not text); floats kept as their JSON text', () => {
  const long = 'x'.repeat(500);
  const before = snap(config());
  const after = snap(
    config(value => {
      value.subtitle = long;
      value.services[0].metrics = Array.from({ length: 40 }, (_, n) => ({ key: `metric-${n}` }));
      value.services[0].rules = [{ threshold: 85.5 }];
    })
  );
  const byPath = Object.fromEntries(configDiff(before, after).map(change => [change.path, change]));
  assert.equal(byPath.subtitle.to.length, 200);
  assert.ok(byPath.subtitle.to.endsWith('…'));
  const metrics = byPath['services.plex-1.metrics'].to;
  assert.equal(typeof metrics, 'string');
  assert.equal(Array.from(metrics).length, 200);
  assert.ok(metrics.startsWith('[{"key":"metric-0"}'));
  assert.deepEqual(byPath['services.plex-1.rules'].to, [{ threshold: '85.5' }]);
  // The writer keeps the mark (its own cut is at 200).
  const row = buildRow(
    { action: 'settings.update', outcome: 'ok', detail: { diff: configDiff(before, after) } },
    () => 1
  );
  assert.ok(row.detail.diff.find(change => change.path === 'subtitle').to.endsWith('…'));
});

test('the 16 KiB cut: the first changes that fit, truncated and the total', async t => {
  const diff = Array.from({ length: 400 }, (_, n) => ({
    path: `services.s-${String(n).padStart(3, '0')}.name`,
    from: 'a'.repeat(60),
    to: 'b'.repeat(60),
  }));
  const fitted = fitDetail({ ifMatch: true, diff });
  assert.ok(Buffer.byteLength(fitted.text) <= DETAIL_MAX_BYTES);
  assert.equal(fitted.detail.truncated, true);
  assert.equal(fitted.detail.changes, 400);
  assert.ok(fitted.detail.diff.length > 50 && fitted.detail.diff.length < 400);
  assert.deepEqual(fitted.detail.diff, diff.slice(0, fitted.detail.diff.length));
  // One more change would not fit.
  const more = { ...fitted.detail, diff: diff.slice(0, fitted.detail.diff.length + 1) };
  assert.ok(Buffer.byteLength(canonicalJSON(more)) > DETAIL_MAX_BYTES);
  // A small detail is kept whole; a large one without a diff is refused.
  assert.equal(fitDetail({ ifMatch: true, diff: diff.slice(0, 2) }).detail.truncated, undefined);
  assert.throws(() => fitDetail({ reason: 'x', other: 'y'.repeat(20000) }), /larger than/);
  // Through a result row: the stored detail is cut the same way.
  const { audit, db } = await auditFixture(t);
  const change = await audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: true },
  });
  const wide = config(value => {
    value.services = Array.from({ length: 200 }, (_, n) =>
      newService('http', `w-${n}`, `Site ${n}`)
    );
  });
  change.note({
    applied: true,
    before: audit.configSnapshot(config()),
    after: audit.configSnapshot(wide),
  });
  await change.end({ status: 200, outcome: 'ok' });
  const [, result] = await storedRows(db);
  assert.equal(result.detail.truncated, true);
  assert.ok(result.detail.changes > result.detail.diff.length);
  assert.ok(Buffer.byteLength(result.detailText) <= DETAIL_MAX_BYTES);
});

test('secrets: set, changed, cleared, never a value; a changed secret shows although publicConfig is equal', () => {
  const none = snap(config());
  const set = snap(config(value => (value.email.password = 'first')));
  const changed = snap(config(value => (value.email.password = 'second')));
  const apiKey = snap(config(value => (value.services[0].apiKey = 'key-1')));
  assert.deepEqual(configDiff(none, set), [{ path: 'email.password', change: 'set' }]);
  assert.deepEqual(configDiff(set, changed), [{ path: 'email.password', change: 'changed' }]);
  assert.deepEqual(configDiff(changed, none), [{ path: 'email.password', change: 'cleared' }]);
  assert.deepEqual(configDiff(none, apiKey), [{ path: 'services.plex-1.apiKey', change: 'set' }]);
  assert.deepEqual(configDiff(set, set), []);
  // publicConfig shows both as configured: only the MACs tell them apart.
  assert.deepEqual(set.public, changed.public);
  // The MAC is per path: the same value at two paths is not one secret.
  const both = snap(
    config(value => {
      value.email.password = 'same';
      value.services[0].password = 'same';
    })
  );
  assert.notEqual(
    both.secrets.macs['email.password'],
    both.secrets.macs['services.plex-1.password']
  );
  assert.equal(both.secrets.macs['email.password'].length, 32);
  assert.equal(both.secrets.key_id, 'k1');
  // Signed by a key that is gone (a lost-key reset): both sides set is unknown.
  const otherKey = configSnapshot(
    config(value => (value.email.password = 'first')),
    {
      kid: 'k2',
      mac: data => createHmac('sha256', Buffer.alloc(32, 1)).update(data).digest('hex'),
    }
  );
  assert.deepEqual(configDiff(set, otherKey), [{ path: 'email.password', change: 'unknown' }]);
  assert.deepEqual(configDiff(none, otherKey), [{ path: 'email.password', change: 'set' }]);
});

test('the name mask: any leaf whose name looks like a secret is one', () => {
  const masked = [
    'webhookUrl',
    'sessionCookie',
    'privateKey',
    'bearerToken',
    'api_key',
    'clientSecret',
    'credential',
  ];
  const before = snap(config());
  const after = snap(
    config(value => {
      for (const name of masked) value.services[0][name] = `value-of-${name}`;
      value.appearance.sessionTheme = 'dark';
    })
  );
  const changes = configDiff(before, after);
  for (const name of masked)
    assert.deepEqual(
      changes.find(change => change.path === `services.plex-1.${name}`),
      { path: `services.plex-1.${name}`, change: 'set' },
      name
    );
  assert.deepEqual(
    changes.find(change => change.path === 'appearance.sessionTheme'),
    {
      path: 'appearance.sessionTheme',
      change: 'set',
    }
  );
  assert.ok(!JSON.stringify(after.public).includes('value-of-'));
  assert.ok(!JSON.stringify(changes).includes('value-of-'));
});

test('URL stripping: user info and credential parameters go before a value is compared or stored', () => {
  assert.equal(
    withoutUrlCredentials(
      'https://user:pass@nas.example.com:5001/api?token=abc&view=2#access_token=x&state=1'
    ),
    'https://nas.example.com:5001/api?view=2#state=1'
  );
  assert.equal(withoutUrlCredentials('https://example.com/?apikey=1'), 'https://example.com/');
  // Values that only parse as URLs keep their spelling; plain text is untouched.
  assert.equal(withoutUrlCredentials('UTC+05:30'), 'UTC+05:30');
  assert.equal(withoutUrlCredentials('https://Example.com/Path'), 'https://Example.com/Path');
  assert.equal(withoutUrlCredentials('mail.example.com'), 'mail.example.com');
  const before = snap(config());
  const after = snap(
    config(value => {
      value.services[0].apiUrl =
        'http://admin:hunter2@plex.example.com:32400/?X-Plex-Token=SECRET-TOKEN';
      value.services[1].url = 'https://blog.example.com/?auth=SECRET-AUTH&page=1';
    })
  );
  const text = JSON.stringify([after.public, configDiff(before, after)]);
  assert.doesNotMatch(text, /hunter2|SECRET-TOKEN|SECRET-AUTH|admin:/);
  assert.match(text, /plex\.example\.com:32400/);
  assert.match(text, /blog\.example\.com\/\?page=1/);
});

// Independent review A2: one fragment member without "=" (an empty one after a trailing &, a bare
// name) made every member read as no credential, so validation took the destination and the
// diff kept its token. Each member is judged on its own now, and the destination is refused or
// stripped exactly as an ordinary #access_token=… is; routes and anchors keep their spelling.
test('URL stripping (independent review A2): a fragment credential pair is found beside empty or valueless members', () => {
  const token = 'synthetic-fragment-secret';
  for (const [url, stripped] of [
    // The ordinary pair (control), then the independent reviewer's two cases and their neighbours.
    [`https://example.test/#access_token=${token}`, 'https://example.test/'],
    [`https://example.test/#access_token=${token}&`, 'https://example.test/'],
    [`https://example.test/#access_token=${token}&state`, 'https://example.test/#state'],
    [`https://example.test/#&access_token=${token}`, 'https://example.test/'],
    [
      `https://example.test/#state&id_token=${token}&&page=2`,
      'https://example.test/#state&&page=2',
    ],
    [`https://example.test/#access_token=${token}&/home`, 'https://example.test/#/home'],
    // A text directive is not a route either.
    [`https://example.test/#:~:access_token=${token}`, 'https://example.test/'],
    [
      `https://example.test/#intro:~:text=a&access_token=${token}`,
      'https://example.test/#intro:~:text=a',
    ],
  ]) {
    assert.throws(() => launchUrl(url), /Keep credentials out of destination URLs/, url);
    assert.equal(withoutCredentials(url), stripped, url);
    assert.equal(withoutUrlCredentials(url), stripped, url);
    assert.equal(launchUrl(stripped), stripped, url);
  }
  // A fragment that starts with a route holds the application's parameters; anchors and
  // harmless pairs hold none: all keep their spelling, also beside empty or valueless members.
  for (const url of [
    'https://app.plex.tv/desktop/#!/server/abc/details?key=%2Flibrary%2Fmetadata%2F1',
    'https://app.plex.tv/desktop/#!/server/abc/list?key=%2Fl&context=content.library',
    'https://app.example.test/#/callback?x=1&',
    'https://app.example.test/#dashboard?view=1&token',
    'https://docs.example.test/page#api-key&',
    'https://docs.example.test/page#authentication:~:text=Basic%20auth',
    'https://app.example.test/#page=2&view=list&',
    'https://app.example.test/#state&page=2',
  ]) {
    assert.equal(launchUrl(url), url);
    assert.equal(withoutCredentials(url), url);
    assert.equal(withoutUrlCredentials(url), url);
  }
});

// Independent review A2, verification round: a route-like first member (/, !, ?, home/) made the whole
// fragment a route, so the same neighbours placed before the pair still hid it (#/home&… was
// taken while #…&/home was refused), and a route character in a later name (api/key, x?…) or an
// encoded "=" hid it too, though the query's equivalents are refused. Only a route's own
// parameters, after a first member's "<route>?", are the application's now.
test('URL stripping (independent review A2): a route-like member before the pair, a route character in its name or an encoded "=" no longer hides it', () => {
  const token = 'synthetic-fragment-secret';
  for (const [fragment, stripped] of [
    ['/&access_token=T', '#/'],
    ['/home&access_token=T', '#/home'],
    ['!&access_token=T', '#!'],
    ['?&access_token=T', '#?'],
    ['x/&access_token=T', '#x/'],
    ['home/&access_token=T&state', '#home/&state'],
    ['state!&access_token=T', '#state!'],
    ['a=1&api/key=T', '#a=1'],
    ['a=1&access_token!=T', '#a=1'],
    ['a=1&x?access_token=T', '#a=1'],
    ['access_token%3DT&state=1', '#state=1'],
    ['?access_token=T', ''],
    ['#access_token=T', ''],
    ['!access_token=T', ''],
    // The route-like pair itself (an implicit grant returned to a hash-routed application).
    ['/access_token=T&expires_in=3600', '#expires_in=3600'],
    // A text directive is judged also after a route or a route's parameters.
    ['a/b:~:access_token=T', '#a/b'],
    ['/callback?x=1:~:access_token=T', '#/callback?x=1'],
  ]) {
    const url = `https://example.test/#${fragment.replace('T', token)}`;
    assert.throws(() => launchUrl(url), /Keep credentials out of destination URLs/, url);
    assert.equal(withoutCredentials(url), `https://example.test/${stripped}`, url);
    assert.equal(withoutUrlCredentials(url), `https://example.test/${stripped}`, url);
    assert.equal(launchUrl(withoutCredentials(url)), withoutCredentials(url), url);
  }
  // Routes, including one with a harmless pair after it, keep their spelling, and so do a
  // route's parameters (Plex's ?key=…).
  for (const url of [
    'https://portainer.example.test:9443/#!/auth',
    'https://app.example.test/#/auth/login',
    'https://app.example.test/#tokens?page=2',
    'https://adguard.example.test/#logs?search=example.com',
    'https://app.example.test/#/home&page=2',
    'https://app.example.test/#/?page=2',
    'https://app.plex.tv/desktop/#!/server/abc/list?key=%2Flibrary%2Fsections%2F1%2Fall%3Fgenre%3D57&context=content.library',
  ]) {
    assert.equal(launchUrl(url), url);
    assert.equal(withoutCredentials(url), url);
    assert.equal(withoutUrlCredentials(url), url);
  }
});

// Independent review A2, through the writer: whatever let such a value into config.value (the API now
// refuses it and a start repairs a hand edit), the diff's own stripping keeps the token out of
// every row, the list, both exports and the stdout-full copy.
for (const [name, prefix, suffix, kept] of [
  ['an empty trailing member', '', '&', /https:\/\/example\.test\/(?![#\w])/],
  ['a valueless member', '', '&state', /https:\/\/example\.test\/#state\b/],
  // Verification round: the same neighbours before the pair.
  ['a route-like member before it', '/home&', '', /https:\/\/example\.test\/#\/home\b(?!&)/],
  ['a slash member before it', '/&', '', /https:\/\/example\.test\/#\/(?![\w&])/],
  ['a hashbang member before it', '!&', '&state', /https:\/\/example\.test\/#!&state\b/],
])
  test(`a fragment token beside ${name} reaches no row, list, export or stdout-full line (independent review A2)`, async t => {
    const { audit, db, out } = await auditFixture(t, { mirror: 'stdout-full' });
    const token = `synthetic-fragment-secret-${randomBytes(6).toString('hex')}`;
    const value = config();
    const before = audit.configSnapshot(value);
    const change = await audit.begin(adminRequest(), {
      action: 'source.create',
      target: { type: 'source', id: null, name: 'Fixture' },
      detail: { ifMatch: false },
    });
    value.services.push({
      ...newService('link', 'link-1', 'Fixture'),
      url: `https://example.test/#${prefix}access_token=${token}${suffix}`,
    });
    change.note({ applied: true, before, after: audit.configSnapshot(value) });
    await change.end({ status: 201, outcome: 'ok' });
    const rows = await storedRows(db);
    const places = {
      rows: JSON.stringify(rows),
      list: JSON.stringify(await audit.list({})),
      csv: (await audit.export({ format: 'csv' }, 'csv')).body.toString('utf8'),
      ndjson: (await audit.export({ format: 'ndjson' }, 'ndjson')).body.toString('utf8'),
      mirror: out.join('\n'),
    };
    for (const [where, text] of Object.entries(places)) {
      assert.equal(text.includes(token), false, where);
      // The stripped destination is there: each place was searched where the token would be.
      assert.match(text, kept, where);
    }
  });

test('configSnapshot holds no raw secret', () => {
  const secrets = ['smtp-secret-1', 'api-key-2', 'source-password-3'];
  const value = config(v => {
    v.email.password = secrets[0];
    v.services[0].apiKey = secrets[1];
    v.services[1].password = secrets[2];
  });
  const text = JSON.stringify(snap(value));
  for (const secret of secrets) assert.ok(!text.includes(secret), secret);
  assert.deepEqual(findSentinels(text, secrets), []);
});

test('property: 500 random settings and source changes with planted secrets never put one in a diff', () => {
  const planted = [];
  const sentinel = label => {
    const value = `Canary${label}-${randomBytes(9).toString('hex')}`;
    planted.push(value);
    return value;
  };
  const credentialNames = [
    'token',
    'apikey',
    'api_key',
    'access_token',
    'password',
    'secret',
    'sessionid',
    'auth',
  ];
  const pick = list => list[Math.floor(Math.random() * list.length)];
  let previous = snap(config());
  let value = config();
  for (let round = 0; round < 500; round++) {
    value = structuredClone(value);
    const source = pick(value.services);
    switch (round % 6) {
      case 0:
        value.email.password = sentinel('Smtp');
        break;
      case 1:
        source.apiKey = sentinel('ApiKey');
        break;
      case 2:
        source.password = sentinel('Password');
        break;
      case 3:
        source.url = `https://${round}.example.com/p?${pick(credentialNames)}=${sentinel('UrlParam')}&page=${round}`;
        break;
      case 4:
        source.apiUrl = `http://user${round}:${sentinel('UserInfo')}@host${round}.example.com/`;
        break;
      default:
        value.title = `Title ${round}`;
        value.services.push(newService('http', `added-${round}`, `Added ${round}`));
        // Independent review A2: also beside an empty or a valueless member, after a route-like one.
        value.services.at(-1).url = `https://h.example.com/#${
          ['', '', '', '/home&', '!&', '?&'][Math.floor(round / 6) % 6]
        }access_token=${sentinel('Fragment')}${[`&state=${round}`, '&', '&state'][Math.floor(round / 6) % 3]}`;
    }
    const next = snap(value);
    const diff = configDiff(previous, next);
    const found = findSentinels(JSON.stringify([diff, next.public]), planted);
    assert.deepEqual(found, [], `round ${round}`);
    previous = next;
  }
  assert.equal(planted.length, 500);
});
