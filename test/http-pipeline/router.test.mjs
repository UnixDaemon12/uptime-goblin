import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createRouter,
  compilePath,
  defineRoute,
  RouteError,
  permissions,
  enforcedFeatures,
  routeDate,
} from '../../lib/http/router.mjs';
import { bodyLimit, emptyBodyLimit } from '../../lib/http/body.mjs';

const handler = () => {};
const route = (method, path, extra = {}) => ({
  method,
  path,
  auth: 'session',
  permission: 'dashboard:read',
  summary: `${method} ${path}`,
  handler,
  ...extra,
});

test('the most specific path wins: literal, then parameter, then the rest wildcard', () => {
  const router = createRouter(
    [
      route('GET', '/api/services'),
      route('GET', '/api/services/:id'),
      route('GET', '/api/services/special'),
      route('GET', '/assets/:build/*'),
      route('GET', '/*', { head: true }),
    ],
    { reserved: ['/api/*'] }
  );
  const at = (method, path) => {
    const found = router.match(method, path);
    return found?.route ? [found.route.path, found.params] : found;
  };
  assert.deepEqual(at('GET', '/api/services'), ['/api/services', {}]);
  assert.deepEqual(at('GET', '/api/services/linux-2'), ['/api/services/:id', { id: 'linux-2' }]);
  assert.deepEqual(at('GET', '/api/services/special'), ['/api/services/special', {}]);
  assert.deepEqual(at('GET', '/assets/0123abcd/modules/core/api.js'), [
    '/assets/:build/*',
    { build: '0123abcd', '*': 'modules/core/api.js' },
  ]);
  assert.deepEqual(at('GET', '/'), ['/*', { '*': '' }]);
  assert.deepEqual(at('GET', '/app.js'), ['/*', { '*': 'app.js' }]);
  // /api/* is reserved: an unknown API path is a 404, never the static catch-all.
  assert.equal(at('GET', '/api/nothing'), null);
  assert.equal(at('GET', '/api/'), null);
  assert.equal(at('GET', '/api/services/a/b'), null);
  // Parameters are one segment of letters, digits, _ and -; anything else does not match.
  assert.equal(at('GET', '/api/services/a%20b'), null);
  assert.equal(at('GET', '/api/services/'), null);
  // `/api` itself is outside /api/ (the slash before * is required), as in 1.4.3.
  assert.deepEqual(at('GET', '/api'), ['/*', { '*': 'api' }]);
  // /assets/<build> without a file falls through to the static catch-all.
  assert.deepEqual(at('GET', '/assets/abc'), ['/*', { '*': 'assets/abc' }]);
});

test('a known path with another method is a 405 whose Allow comes from the table', () => {
  const router = createRouter([
    route('PATCH', '/api/services/:id', { permission: 'sources:write' }),
    route('DELETE', '/api/services/:id', { permission: 'sources:write' }),
    route('GET', '/health', { head: true, auth: 'public', permission: null }),
    route('GET', '/api/dashboard'),
  ]);
  assert.deepEqual(
    { ...router.match('PUT', '/api/services/linux'), routes: undefined },
    { allow: 'PATCH, DELETE', routes: undefined }
  );
  assert.equal(router.match('POST', '/health').allow, 'GET, HEAD');
  // HEAD is answered by a GET route only when that route says so.
  assert.equal(router.match('HEAD', '/health').route.path, '/health');
  assert.equal(router.match('HEAD', '/api/dashboard').allow, 'GET');
  assert.equal(router.match('GET', '/nowhere'), null);
});

test('an incomplete or ambiguous route table refuses to start', () => {
  const refused = (records, pattern, options) =>
    assert.throws(
      () => createRouter(records, options),
      error => error instanceof RouteError && error.refusal === true && pattern.test(error.message)
    );
  const { auth, ...noAuth } = route('GET', '/a');
  const { permission, ...noPermission } = route('GET', '/a');
  refused([noAuth], /auth must be one of/);
  refused([noPermission], /must declare its permission/);
  refused([route('GET', '/a', { permission: 'everything' })], /unknown permission/);
  refused([route('GET', '/a', { auth: 'public' })], /public route needs permission null/);
  refused([route('GET', '/a', { permission: null })], /unknown permission/);
  refused([route('GET', '/a', { auth: 'magic' })], /auth must be one of/);
  refused([route('GET', '/a', { auth: 'token' })], /not supported by this release/, {
    auth: ['public', 'session'],
  });
  refused([route('GET', '/a', { summary: ' ' })], /needs a summary/);
  refused([route('GET', '/a', { handler: 'nope' })], /handler must be a function/);
  refused([route('GET', '/a', { permision: 'dashboard:read' })], /unknown field permision/);
  refused([route('TRACE', '/a')], /unknown method/);
  refused([route('GET', 'a')], /must start with/);
  refused([route('GET', '/a/*/b')], /\* must come last/);
  refused([route('GET', '/a/:id/:id')], /invalid or repeated parameter/);
  refused([route('GET', '/a b')], /invalid segment/);
  refused([route('GET', '/a'), route('GET', '/a')], /declared twice/);
  refused([route('GET', '/a/:x'), route('POST', '/a/:y')], /match the same paths/);
  refused([route('GET', '/a', { head: true }), route('HEAD', '/a')], /HEAD \/a is declared twice/);
  refused([route('POST', '/a', { head: true })], /head is only for GET/);
  refused([route('POST', '/a', { csrf: 'yes' })], /csrf must be true or false/);
  refused([route('POST', '/a', { bodyLimit: -1 })], /bodyLimit/);
  // What a request may carry follows the method: a read takes no body at all.
  refused([route('POST', '/a', { body: 'none' })], /body must be json or empty/);
  refused([route('POST', '/a', { body: 'text' })], /body must be json or empty/);
  refused([route('GET', '/a', { body: 'json' })], /body must be none/);
  refused([route('GET', '/a', { bodyLimit: 10 })], /a read takes no body/);
  refused([route('POST', '/a', { ifMatch: 'sometimes' })], /ifMatch/);
  refused([route('POST', '/a', { contentType: 'xml' })], /contentType/);
  refused([route('POST', '/a', { audit: '' })], /audit/);
  // audit enum (audit spec D18): a closed list, so a misspelt kind cannot record nothing.
  for (const audit of ['confg', 'Config', 'none ', 7, null])
    refused(
      [route('POST', '/a', { audit })],
      /: audit must be one of none, identity, config, delivery, channel, secret, operation, export$/
    );
  for (const audit of [
    'none',
    'identity',
    'config',
    'delivery',
    'channel',
    'secret',
    'operation',
    'export',
  ])
    assert.equal(createRouter([route('POST', '/a', { audit })]).routes[0].audit, audit);
  // A handler that runs in place of the one-credential refusal (§19 G1), or of the 401 for a
  // session cookie that no longer signs in (§20 H1): only for a signed-in write that keeps the
  // CSRF rule.
  for (const hook of ['multipleSessions', 'endedSession']) {
    const pattern = new RegExp(`${hook} must be a function`);
    for (const extra of [
      { [hook]: 'yes' },
      { [hook]: handler, csrf: false },
      { [hook]: handler, auth: 'public', permission: null },
    ])
      refused([route('POST', '/a', extra)], pattern);
    refused([route('GET', '/a', { [hook]: handler })], pattern);
    assert.equal(
      createRouter([route('POST', '/a', { [hook]: handler })]).match('POST', '/a').route[hook],
      handler
    );
  }
  refused('not a list', /routes must be a list/);
  refused([null], /must be an object/);
});

test('route defaults follow the method: writes need CSRF and JSON and may be replayed', () => {
  const read = defineRoute(route('GET', '/a'));
  const write = defineRoute(route('POST', '/a'));
  assert.deepEqual(
    [read.csrf, read.contentType, read.idempotent, read.body, read.bodyLimit, read.ifMatch],
    [false, 'none', false, 'none', 0, 'none']
  );
  assert.equal(read.audit, 'none');
  assert.deepEqual(
    [write.csrf, write.contentType, write.idempotent, write.body, write.bodyLimit],
    [true, 'json', true, 'json', 150000]
  );
  // A write that takes no body reads at most a few bytes; a read takes none at all.
  assert.deepEqual(
    [defineRoute(route('POST', '/a', { body: 'empty' })).bodyLimit, emptyBodyLimit],
    [64, 64]
  );
  assert.equal(defineRoute(route('POST', '/a', { idempotent: false })).idempotent, false);
  assert.ok(Object.isFrozen(write));
  assert.equal(compilePath('/api/services/:id').shape, '/api/services/:');
  assert.ok(permissions.includes('dashboard:read') && permissions.includes('agent:ingest'));
});

// Before a credential signs in the pipeline holds every request that is not to a public route to
// the default limit (body.mjs), so a route that declared more would answer 413 before its
// credential was checked: such a table refuses the start. A public route keeps its own limit.
test('a route that is not public cannot take more than the default body limit', () => {
  assert.equal(bodyLimit, 150000);
  for (const auth of ['session', 'any'])
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'])
      assert.throws(
        () =>
          createRouter([route(method, '/a', { auth, bodyLimit: bodyLimit + 1 })], { auth: [auth] }),
        error =>
          error instanceof RouteError &&
          error.message ===
            `Route table: ${method} /a: bodyLimit 150001 is over 150000, the limit every request that is not to a public route is held to before it signs in`,
        `${auth} ${method}`
      );
  assert.equal(defineRoute(route('POST', '/a', { bodyLimit })).bodyLimit, bodyLimit);
  assert.equal(defineRoute(route('POST', '/a', { bodyLimit: 4096 })).bodyLimit, 4096);
  const upload = defineRoute(
    route('POST', '/a', {
      auth: 'public',
      permission: null,
      idempotent: false,
      bodyLimit: bodyLimit * 2,
    })
  );
  assert.equal(upload.bodyLimit, bodyLimit * 2);
});

test('a protection the pipeline does not enforce cannot be declared', () => {
  const refused = (extra, pattern, supports) =>
    assert.throws(
      () => createRouter([route('POST', '/a', extra)], supports ? { supports } : {}),
      error => error instanceof RouteError && error.refusal === true && pattern.test(error.message)
    );
  assert.deepEqual(enforcedFeatures, ['stepUp', 'lock', 'schema', 'bodyPermissions']);
  refused({ lock: 'logging' }, /lock is not enforced by this release/);
  refused({ stepUp: true }, /stepUp is not enforced by this release/);
  refused({ schema: { type: 'object' } }, /schema is not enforced/);
  refused({ bodyPermissions: { secret: 'settings:write' } }, /bodyPermissions is not enforced/);
  refused({ schema: {} }, /schema is not enforced/, ['stepUp', 'bodyPermissions']);
  // Declaring that a route does NOT need step-up is fine anywhere.
  assert.equal(createRouter([route('POST', '/a', { stepUp: false })]).routes[0].stepUp, false);
  // A pipeline that enforces a feature may serve routes that need it.
  const served = createRouter(
    [route('POST', '/a', { stepUp: true, idempotent: false, schema: {}, bodyPermissions: {} })],
    { supports: [...enforcedFeatures] }
  );
  assert.equal(served.routes[0].stepUp, true);
  // Documentation only, but it must be an object.
  assert.ok(createRouter([route('GET', '/a', { responses: { 200: 'ok' } })]));
  refused({ responses: 'ok' }, /responses must be an object/);
  refused({ responses: null }, /responses must be an object/);
});

test('public routes are never replayed: nothing identifies whose reply it would be', () => {
  const open = (method, extra = {}) =>
    route(method, '/a', { auth: 'public', permission: null, ...extra });
  assert.equal(defineRoute(open('POST')).idempotent, false);
  assert.equal(defineRoute(open('POST')).csrf, true, 'public writes are still CSRF-checked');
  assert.equal(defineRoute(open('POST')).contentType, 'json');
  assert.throws(
    () => defineRoute(open('POST', { idempotent: true })),
    /public route cannot be replayed/
  );
  assert.equal(defineRoute(route('POST', '/a')).idempotent, true);
});

test('deprecated routes carry Deprecation and Sunset from checked dates', () => {
  const at = extra => defineRoute(route('GET', '/a', extra)).headers;
  assert.deepEqual(at({}), {});
  assert.deepEqual(at({ deprecated: '2026-10-01' }), {
    Deprecation: `@${Date.UTC(2026, 9, 1) / 1000}`,
  });
  assert.deepEqual(at({ deprecated: '2026-10-01T12:00:00Z', sunset: '2027-04-01' }), {
    Deprecation: `@${Date.UTC(2026, 9, 1, 12) / 1000}`,
    Sunset: 'Thu, 01 Apr 2027 00:00:00 GMT',
  });
  assert.deepEqual(
    at({ deprecated: '2026-10-01', sunset: '2026-10-01' }).Sunset,
    new Date(Date.UTC(2026, 9, 1)).toUTCString()
  );
  assert.ok(Object.isFrozen(at({ deprecated: '2026-10-01' })));
  const refused = (extra, pattern) =>
    assert.throws(
      () => defineRoute(route('GET', '/a', extra)),
      error => error instanceof RouteError && pattern.test(error.message)
    );
  for (const bad of [
    '2027-02-30',
    '2027-13-01',
    '01/10/2026',
    'tomorrow',
    '2026-10-01T12:00:00',
    20261001,
    true,
    '',
  ])
    refused({ deprecated: bad }, /deprecated must be an ISO 8601 date/);
  refused({ deprecated: '2026-10-01', sunset: 'soon' }, /sunset must be an ISO 8601 date/);
  refused({ sunset: '2027-04-01' }, /sunset must also be deprecated/);
  refused({ deprecated: '2027-04-01', sunset: '2026-10-01' }, /sunset must not come before/);
  // The date check itself.
  assert.equal(routeDate('2028-02-29'), Date.UTC(2028, 1, 29));
  assert.ok(Number.isNaN(routeDate('2027-02-29')));
  assert.equal(routeDate('2026-10-01T02:00:00+02:00'), Date.UTC(2026, 9, 1));
  assert.ok(Number.isNaN(routeDate('2026-10-01T25:00:00Z')));
});
