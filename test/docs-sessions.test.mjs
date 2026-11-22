// The sign-in and session docs against the code they describe (1.5 docs audit, area "sessions",
// and the docs parts of release blockers B11 and B12). Each test reads the texts and the code
// that decides the behaviour, so a change to either that makes the docs wrong fails here.
import { currentNames, isDeploymentFile } from './helpers/deployed-names.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFeatures } from '../lib/features.mjs';
import { errorCodes } from '../lib/identity/errors.mjs';
import { defaultLimits } from '../lib/identity/index.mjs';
import { LoginThrottle, throttleKey } from '../lib/throttle.mjs';
import { authRoutes } from '../lib/http/routes/auth.mjs';
import { accountRoutes } from '../lib/http/routes/account.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
// Deployment files with their names from before the rename read as the current ones
// (test/helpers/deployed-names.mjs).
const read = file => {
  const text = fs.readFileSync(path.join(repository, file), 'utf8');
  return isDeploymentFile(file) ? currentNames(text) : text;
};
// What a reader sees of a Markdown paragraph or an HTML text: runs of blanks as one space.
const flat = text => text.replace(/\s+/g, ' ').trim();
// A `## heading` section of a Markdown file, up to the next heading of the same level.
function section(text, heading) {
  const start = text.indexOf(`\n## ${heading}\n`);
  assert.notEqual(start, -1, `section "${heading}"`);
  const end = text.indexOf('\n## ', start + 1);
  return text.slice(start, end === -1 ? undefined : end);
}
// The CHANGELOG's notes for the 1.5 branch: everything above the 1.4.3 release.
const unreleased = () => read('CHANGELOG.md').split('\n## 1.4.3')[0];
// Every doc, the README, the 1.5 notes, .env.example and the two sources that decide the
// transport and the browser context, comments included, as a reader sees them: [name, text].
function browserTexts() {
  const texts = {
    ...Object.fromEntries(
      fs
        .readdirSync(path.join(repository, 'docs'))
        .filter(name => name.endsWith('.md'))
        .map(name => [`docs/${name}`, read(`docs/${name}`)])
    ),
    'README.md': read('README.md'),
    'CHANGELOG.md (1.5)': unreleased(),
    '.env.example': read('.env.example'),
    'lib/http/pipeline.mjs': read('lib/http/pipeline.mjs'),
    'lib/http/transport.mjs': read('lib/http/transport.mjs'),
  };
  return Object.entries(texts).map(([name, text]) => [
    name,
    flat(text.replace(/^\s*(#|\*|\/\/) ?/gm, '')),
  ]);
}
// public/modules/identity/session.js: the banners every page shows (bannerTexts).
function bannerTexts() {
  const found = Object.fromEntries(
    [
      ...read('public/modules/identity/session.js').matchAll(
        /^ {2}(insecure|insecureBehindProxy|mirrorPending):\s*'([^']*)',$/gm
      ),
    ].map(match => [match[1], match[2]])
  );
  assert.deepEqual(Object.keys(found).sort(), ['insecure', 'insecureBehindProxy', 'mirrorPending']);
  return found;
}

test('docs: the plain-HTTP banners are quoted as the page shows them, and say the password crosses in clear', () => {
  const banners = bannerTexts();
  const guide = read('docs/authentication.md');
  for (const name of ['insecure', 'insecureBehindProxy'])
    assert.ok(guide.includes(`"${banners[name]}"`), `authentication.md quotes bannerTexts.${name}`);
  assert.match(banners.insecure, /your password each time you sign in or change it/);
  // The password crosses the network in clear too, not only the cookie (B12): every text that
  // explains the opt-in says so.
  const plain = section(guide, 'HTTPS, cookies and plain HTTP');
  assert.match(
    flat(plain),
    /the password itself crosses the network in clear, not only the cookie/
  );
  // The sign-in page warns before the password is typed (the B11 test checks its words).
  assert.match(
    flat(plain),
    /The sign-in page says so above the form, before you type the password/
  );
  assert.match(
    read('docs/configuration.md'),
    /\| `GOBLIN_INSECURE_HTTP_SESSIONS` \|[^\n]*the password and the cookie then cross that network unencrypted/
  );
  assert.match(
    flat(read('.env.example').replace(/^# ?/gm, '')),
    /the password at each sign-in and the session cookie \(without Secure\) cross the network unencrypted/
  );
  assert.match(
    read('docs/security.md'),
    /sends the password at each sign-in, as well as the cookie/
  );
  // The log line that turning it off writes, as identity writes it.
  const line = 'that signed in over plain HTTP: GOBLIN_INSECURE_HTTP_SESSIONS is off.';
  assert.ok(read('lib/identity/index.mjs').includes(line));
  assert.ok(guide.includes(`"Signed out N sessions ${line}"`));
  assert.match(
    read('server.mjs'),
    /plain-HTTP sessions: \$\{insecureHttpSessions \? 'allowed' : 'refused'\}/
  );
  assert.match(guide, /`plain-HTTP sessions: allowed`/);
  assert.match(guide, /`plain-HTTP sessions: refused`/);
});

test('docs: the way back from plain HTTP is =0 in every install mode, and an empty value is off under Compose too', async () => {
  // compose.yaml: compose-default only while unset (`${…-compose-default}`, no colon), so an
  // empty value stays empty.
  assert.match(
    read('compose.yaml'),
    /^ {6}GOBLIN_INSECURE_HTTP_SESSIONS: \$\{GOBLIN_INSECURE_HTTP_SESSIONS-\$\{ORBIT_INSECURE_HTTP_SESSIONS-compose-default\}\}$/m
  );
  const plainHttp = (value, published = '127.0.0.1') =>
    createFeatures({
      env: { GOBLIN_INSECURE_HTTP_SESSIONS: value, GOBLIN_PUBLISHED_ADDRESS: published },
      release: '1.5.0',
    }).enabled('insecureHttpSessions');
  // Wherever Compose publishes the port, 0 and an empty value are off and 1 is on.
  for (const published of ['127.0.0.1', '192.0.2.5']) {
    for (const off of ['', '0', 'false', 'no', 'off'])
      assert.equal(await plainHttp(off, published), false, off);
    assert.equal(await plainHttp('1', published), true);
  }
  // A removed line under Compose: on again, on the loopback port.
  assert.equal(await plainHttp('compose-default'), true);

  // No text tells anyone to remove the variable to turn it off: under Compose that leaves
  // compose-default, which is on for a loopback publish.
  const texts = {
    ...Object.fromEntries(
      fs
        .readdirSync(path.join(repository, 'docs'))
        .map(name => [`docs/${name}`, read(`docs/${name}`)])
    ),
    'README.md': read('README.md'),
    'CHANGELOG.md (1.5)': unreleased(),
    '.env.example': read('.env.example'),
    'compose.yaml': read('compose.yaml'),
    'deploy/install.sh': read('deploy/install.sh'),
    'public/modules/identity/session.js': read('public/modules/identity/session.js'),
  };
  for (const [name, text] of Object.entries(texts)) {
    assert.doesNotMatch(text, /\bremov(e|ing) `?GOBLIN_INSECURE_HTTP_SESSIONS/i, name);
    assert.doesNotMatch(text, /GOBLIN_INSECURE_HTTP_SESSIONS is no longer set/, name);
  }
  // Where Compose is explained, an empty value is off and the check is the real command.
  const check = '`docker compose config | grep GOBLIN_INSECURE_HTTP_SESSIONS`';
  for (const name of ['docs/installation.md', 'docs/authentication.md', 'CHANGELOG.md (1.5)'])
    assert.ok(texts[name].includes(check), `${name} gives ${check}`);
  assert.match(
    flat(section(read('docs/installation.md'), 'Docker Compose')),
    /an empty value is off too, but removing the line is not/
  );
  assert.match(
    flat(texts['.env.example'].replace(/^# ?/gm, '')),
    /an empty value is off too; deleting the line is not, under Compose/
  );
  // The row says what createFeatures reads (lib/features.mjs, through the one yes/no parser of
  // lib/environment.mjs and its one rule for this setting): only 1, true, yes or on allow it;
  // every other value refuses it, under Compose too, except Compose's own compose-default (docs
  // audit, code area).
  assert.match(
    read('lib/features.mjs'),
    /import \{\s+flagValue,\s+flagWarning,\s+insecureHttpSessionsSetting,\s+legacyBasicSetting,\s+quoted,\s+\} from '\.\/environment\.mjs';/
  );
  assert.match(read('lib/environment.mjs'), /const truthy = \/\^\(1\|true\|yes\|on\)\$\/i,/);
  const row = texts['docs/configuration.md']
    .split('\n')
    .find(line => line.startsWith('| `GOBLIN_INSECURE_HTTP_SESSIONS` |'));
  assert.ok(row.includes('`1` (or `true`, `yes`, `on`) allows browser sign-in over plain HTTP'));
  assert.ok(row.includes('Any other value refuses it, `0` and an empty value included'));
  assert.ok(row.includes("On Compose's loopback port a removed line turns it back on, so set `0`"));
  assert.ok(row.includes('The exception is `compose-default`, which Docker Compose passes'));
  assert.doesNotMatch(row, /only `0` or an empty value/);
  // The banners and the troubleshooting row give the same way back.
  for (const text of [bannerTexts().insecure, bannerTexts().insecureBehindProxy])
    assert.match(text, /set GOBLIN_INSECURE_HTTP_SESSIONS=0/);
  assert.match(
    texts['docs/troubleshooting.md'],
    /then set `GOBLIN_INSECURE_HTTP_SESSIONS=0`, restart Uptime Goblin \(Docker: in `\.env`, then `docker compose up -d`\)/
  );
});

test('docs: an http:// page Orbit would refuse shows no password form (B11), and nginx serves Orbit over HTTPS only', () => {
  // public/modules/identity/signin.js: the refusals for which no form asks for the password.
  const signin = read('public/modules/identity/signin.js');
  const body = /export function refusedInClear\([^)]*\) \{([\s\S]*?)\n\}/.exec(signin);
  assert.ok(body, 'refusedInClear() found');
  const codes = [...body[1].matchAll(/'([a-z_]+)'/g)].map(match => match[1]).sort();
  assert.deepEqual(codes, ['https_required', 'proxy_proto_mismatch']);
  assert.match(
    read('public/modules/identity/session.js'),
    /const noForm = blocked \|\| !!refusedInClear\(error\.transport\),[\s\S]*?\$\('#signin-form'\)\.hidden = noForm \|\| codeForm;\n\s+\$\('#display-form'\)\.hidden = noForm \|\| !codeForm;/
  );
  const refused = flat(section(read('docs/authentication.md'), 'When sign-in is refused'));
  assert.ok(
    refused.includes(
      `On an \`http://\` page that Uptime Goblin would refuse (${codes.map(code => `\`${code}\``).join(', ')}), the sign-in page shows the message without the form, and a page that was already open says the same at the top without **Sign in**`
    ),
    refused.slice(0, 600)
  );
  // The page knows a proxy on the Uptime Goblin host that sends no forwarding headers by its own
  // address, and an open sign-in dialog closes before its password is sent.
  assert.match(signin, /transport\.kind === 'loopback' && !loopbackHost\(host\)/);
  assert.ok(
    refused.includes(
      'This includes a page behind a proxy on the Uptime Goblin host that sends no forwarding headers'
    )
  );
  assert.ok(
    refused.includes(
      'A **Sign in again** dialog that was already open when Uptime Goblin started refusing (plain-HTTP sessions turned off while it waited) closes the next time you come back to the page, before its password is sent'
    )
  );
  // A sign-in view without a form asks Uptime Goblin again at a look at the tab (probeAgain()), so the
  // fix and a restart bring the form without a reload (the independent checkpoint-2 review, CLIENT-1).
  assert.match(
    read('public/modules/identity/session.js'),
    /if \(state\.started\) \{\n\s+if \(\n\s+!state\.starting &&\n\s+!\$\('#signin-page'\)\.hidden &&\n\s+\$\('#signin-form'\)\.hidden &&\n\s+\$\('#display-form'\)\.hidden\n\s+\)\n\s+probeAtStart\(\);/
  );
  assert.ok(
    refused.includes(
      'Once the fix is in place and Uptime Goblin restarted, a sign-in page that showed no form asks Uptime Goblin again the next time you come back to it (or reload it), and then offers the form, or the dashboard if you signed in from another tab meanwhile.'
    )
  );
  // Where Uptime Goblin allows plain HTTP, the sign-in page warns before the password is typed, in the
  // words the guide quotes.
  const warning = /plain_http:\s*'([^']*)'/.exec(signin)?.[1];
  assert.ok(warning, 'signInTexts.plain_http found');
  const guide = flat(read('docs/authentication.md'));
  assert.ok(
    guide.includes(
      `before you type the password, when its address is not a loopback name: "${warning}"`
    )
  );
  assert.doesNotMatch(guide, /The sign-in page itself shows no warning/);
  const rows = read('docs/troubleshooting.md');
  assert.match(
    rows,
    /\(`https_required`\) \|[^\n]*the sign-in page shows this message without the form/
  );
  assert.match(
    rows,
    /\(`proxy_proto_mismatch`\) \|[^\n]*The sign-in page shows this message without the form/
  );
  assert.match(
    unreleased(),
    /An `http:\/\/` page whose sign-in Uptime Goblin would refuse \(`https_required`, `proxy_proto_mismatch`\) shows the reason without a password form/
  );

  // The nginx recipe: plain HTTP only redirects, and HSTS keeps browsers on HTTPS.
  const https = section(read('docs/installation.md'), 'HTTPS, trust and network access');
  const blocks = [...https.matchAll(/```nginx\n([\s\S]*?)```/g)].map(match => match[1]);
  const servers = blocks.find(block => /listen 80;/.test(block));
  assert.ok(servers, 'an nginx block with the plain-HTTP server');
  assert.match(
    servers,
    /server \{\n {4}listen 80;\n {4}server_name goblin\.example\.com;\n {4}return 301 https:\/\/\$host\$request_uri;\n\}/
  );
  assert.match(
    servers,
    /listen 443 ssl;[\s\S]*add_header Strict-Transport-Security "max-age=31536000" always;/
  );
  // The recipe and the guide no longer assume a plain-HTTP server block sharing Uptime Goblin's location.
  for (const text of [https, read('docs/authentication.md')])
    assert.doesNotMatch(text, /plain-HTTP server block that shares the location/);
});

test('docs: the remember hint is the same in both forms and in the guide, and says when closing the browser may not sign out', () => {
  const html = read('public/index.html');
  const hints = ['signin-remember-hint', 'reauth-remember-hint'].map(id => {
    const match = new RegExp(`<small id="${id}"\\s*>([^<]*)</small`).exec(html);
    assert.ok(match, id);
    return flat(match[1]);
  });
  assert.equal(hints[0], hints[1]);
  assert.match(hints[0], /a browser that reopens your previous tabs may keep you signed in/);
  const guide = read('docs/authentication.md');
  assert.ok(guide.includes(`The hint beside the box says: "${hints[0]}"`));
  // Without the box the cookie has no Max-Age (lib/http/cookies.mjs), so the browser decides.
  assert.doesNotMatch(read('docs/security.md'), /without it the cookie ends with the browser/);
  assert.match(
    read('docs/security.md'),
    /without it the cookie lasts until the browser ends its session/
  );
});

test('docs: sign-in throttling after a password change is described for 1.5, not 1.4.x', () => {
  const throttle = new LoginThrottle();
  assert.equal(throttle.freeAttempts, 5);
  assert.equal(throttle.baseMs, 1000);
  assert.equal(throttle.maxMs, 15 * 60 * 1000);
  assert.equal(defaultLimits.retiredMs, 24 * 3600 * 1000);
  const guide = read('docs/security.md');
  assert.match(
    guide,
    /Every sign-in on Uptime Goblin's page and every password change checks the password in full/
  );
  assert.match(guide, /five free failures, then 1 second, doubling up to 15 minutes/);
  assert.match(
    guide,
    /for a day after a change \(until Uptime Goblin restarts\) a script's old password is refused without counting/
  );
  // 1.4.x's text: browsers signed in with Basic then, and a second browser was a cached check.
  assert.doesNotMatch(guide, /Once one browser is signed in, Uptime Goblin remembers the password/);
  assert.match(
    read('docs/authentication.md'),
    /Failed sign-ins are throttled as before, except that on the sign-in page the previous password counts like any wrong one/
  );
});

test('docs: the sign-in route lists every refusal it can answer, and the Idempotency-Key paragraph every identity write it never replays', () => {
  const row = read('docs/architecture.md')
    .split('\n')
    .find(line => line.startsWith('| `POST /api/auth/login` |'));
  assert.ok(row);
  for (const code of [
    'invalid_request',
    'https_required',
    'proxy_proto_missing',
    'proxy_proto_mismatch',
    'cross_origin',
    'invalid_credentials',
    'locked',
    'busy',
    'storage_full',
  ]) {
    assert.ok(errorCodes[code], code);
    assert.ok(row.includes(`${errorCodes[code].status} `) && row.includes(`\`${code}\``), code);
  }
  assert.ok(row.includes(`\`busy\` with \`Retry-After: ${errorCodes.busy.retryAfter}\``));
  assert.ok(
    row.includes(`\`storage_full\` with \`Retry-After: ${errorCodes.storage_full.retryAfter}\``)
  );
  assert.match(row, /415 without `Content-Type: application\/json`/);
  assert.match(row, /NFKC normalisation, ignoring case and surrounding spaces/);
  // No sign-in is refused for want of an admin password: Uptime Goblin does not start without one.
  assert.doesNotMatch(row, /signin_unavailable/);

  const app = { identity: {}, loginThrottle: {}, insecureHttpSessions: false, release: {} };
  const writes = [...authRoutes(app), ...accountRoutes(app)].filter(
    route => route.method !== 'GET' && route.idempotent === false
  );
  assert.ok(writes.length >= 6);
  const paragraph = read('docs/architecture.md')
    .split('\n')
    .find(line => line.startsWith('Writes accept `Idempotency-Key:'));
  for (const route of writes)
    assert.ok(
      paragraph.includes(`\`${route.method} ${route.path}\``),
      `${route.method} ${route.path}`
    );
});

test('docs: the address a session and an audit entry show is the lockout key, and the ssh tunnel works at Orbit’s own port', () => {
  const example = throttleKey('2001:db8:0:1::5');
  assert.equal(example, '2001:0db8:0000:0001::/64');
  const guide = read('docs/authentication.md');
  assert.ok(guide.includes(`an IPv6 device shows its /64 network (for example \`${example}\`)`));
  assert.match(
    read('docs/security.md'),
    /The address is the one the sign-in lockout counts, as in the sessions list/
  );
  // server.mjs: Uptime Goblin always allows the loopback names at the port it listens on.
  assert.match(
    read('server.mjs'),
    /`127\.0\.0\.1:\$\{currentPort\}`,\s*`localhost:\$\{currentPort\}`,\s*`\[::1\]:\$\{currentPort\}`/
  );
  assert.ok(
    guide.includes(
      'Uptime Goblin always accepts `localhost`, `127.0.0.1` and `[::1]` at the port it listens on, whatever `GOBLIN_ALLOWED_HOSTS` says'
    )
  );
  assert.doesNotMatch(guide, /which the default `GOBLIN_ALLOWED_HOSTS` names/);
});

test('docs: wall displays, stolen cookies, rollbacks while auth.json is behind, and what 1.5.0 still needs', () => {
  const guide = read('docs/authentication.md');
  const wall = flat(section(guide, 'Wall displays'));
  // public/modules/main.js: a hidden page does not poll, and every poll is background, kiosk or
  // not. public/modules/core/api.js: every read on ?kiosk=1 is background; a write never is.
  const main = read('public/modules/main.js');
  assert.match(main, /if \(!document\.hidden && \(kiosk \|\| /);
  assert.match(main, /load\(\{ background: true \}\)/);
  assert.match(
    read('public/modules/core/api.js'),
    /background: !write && \(kiosk \|\| background\)/
  );
  // A ?kiosk=1 page signed in with the password: its reads stay background (above), so it ends
  // after 12 hours, and holds every right the admin has.
  assert.match(
    wall,
    /A `\?kiosk=1` page signed in with the admin password, .* keeps every right the admin has, and since a `\?kiosk=1` page marks every read it makes as background, it is signed out after 12 hours without use/
  );
  // No stale kiosk exception survives anywhere the docs describe session use.
  for (const [name, stale] of [
    ['docs/authentication.md', /automatic refresh counts as use|The refresh counts as use/],
    ['docs/authentication.md', /Until kiosk sessions arrive/],
    ['docs/security.md', /`\?kiosk=1` is the exception/],
    ['docs/architecture.md', /`\?kiosk=1` sends its automatic refreshes without it/],
    ['docs/installation.md', /`\?kiosk=1`, and again at least every 30 days/],
    ['CHANGELOG.md', /`\?kiosk=1`; sign in again at least every 30 days/],
    ['docs/installation.md', /A wall display holds a full admin session/],
    ['CHANGELOG.md', /A wall display holds a full admin session/],
  ])
    assert.doesNotMatch(read(name), stale, name);

  // Display codes (B6 design §7): a kiosk session reads the dashboard only, every request it
  // makes is use, and its limits are GOBLIN_DISPLAY_SESSION_DAYS and GOBLIN_DISPLAY_IDLE_DAYS.
  assert.match(
    wall,
    /A wall display signs in with a one-time \*\*display code\*\*, not the admin password\. It then reads the dashboard and nothing else/
  );
  assert.match(wall, /up to 30 days, as long as it reads Uptime Goblin at least once every 7 days/);
  assert.match(
    wall,
    /`GOBLIN_DISPLAY_SESSION_DAYS` \(1 to 30, default 30\) and `GOBLIN_DISPLAY_IDLE_DAYS` \(1 to 7, default 7\)/
  );
  // On ?kiosk=1 only the code form (B6 design §7.7), and the old-display runbook (§7.6).
  assert.match(wall, /On `\?kiosk=1` the sign-in page offers only the code form/);
  assert.doesNotMatch(wall, /Sign in with the admin password instead/);
  assert.match(wall, /shows a banner offering \*\*Set up\*\*:/);
  assert.match(
    wall,
    /1\. If people you do not fully trust could use a display, change the admin password first\./
  );
  const identity = read('lib/identity/index.mjs');
  assert.match(
    identity,
    /kioskPermissions = new ReadonlySet\(\['dashboard:read', 'session:self'\]\)/
  );
  assert.match(identity, /activity === 'foreground' \|\| row\.kind === 'kiosk'/);
  assert.match(identity, /absoluteMs: 30 \* 86400e3,\s+idleMs: 7 \* 86400e3/);
  for (const name of ['docs/installation.md', 'CHANGELOG.md'])
    assert.match(read(name), /goblin-admin display code --name <name>/, name);

  // lib/http/pipeline.mjs: any request without the background mark counts as use.
  assert.match(
    read('lib/http/pipeline.mjs'),
    /requestHeader\(req\.headers, 'Activity'\) === 'background' \? 'background' : 'foreground'/
  );
  assert.match(
    read('docs/security.md'),
    /a cookie that someone else keeps using does not go idle: it stays valid until its 7- or 30-day limit/
  );

  // A rollback while the mirror is behind uses the previous password: every rollback text says
  // so, quoting the banner as the page shows it.
  const banner = 'Uptime Goblin saved the admin password but could not update auth.json';
  assert.ok(bannerTexts().mirrorPending.startsWith(banner));
  for (const name of [
    'docs/authentication.md',
    'docs/installation.md',
    'docs/configuration.md',
    'CHANGELOG.md',
  ]) {
    const text = read(name);
    assert.ok(text.includes(banner), name);
  }
  const rollbacks = [
    ...read('docs/installation.md').matchAll(/^- \*\*Rolling back\*\* to 1\.4\.3[^\n]*/gm),
    ...guide.matchAll(/^- \*\*Rolling back to 1\.4\.3 or 1\.4\.2\*\*[^\n]*/gm),
    ...unreleased().matchAll(
      /^- \*\*Rolling back to 1\.4\.3 or 1\.4\.2 uses the current password\*\*[^\n]*/gm
    ),
  ].map(match => match[0]);
  assert.equal(rollbacks.length, 3);
  for (const text of rollbacks) assert.ok(text.includes(`"${banner}"`), text.slice(0, 80));

  // The OD3 gates still open in the code are named as still to come, not as later releases.
  assert.match(read('lib/throttle.mjs'), /Only memory is used; a restart clears it\./);
  assert.match(
    guide,
    /\*\*Still to come before 1\.5\.0 is released:\*\* failed-sign-in counts and trusted clients kept across restarts, device cookies, and a `goblin-admin` command that signs out every session/
  );
  assert.match(unreleased(), /\*\*Not releasable as 1\.5\.0 yet\.\*\*/);
  assert.doesNotMatch(guide, /Failed-sign-in counts and trusted clients are still kept in memory/);

  // The Sign out text for two cookies is a fallback now (troubleshooting row).
  assert.match(
    read('docs/troubleshooting.md'),
    /\| Sign out: "Uptime Goblin could not sign this browser out: it sent two Uptime Goblin sign-in cookies, and another site set one of them" \| Not expected from 1\.5 on:/
  );
});

// Basic through a proxy on the Uptime Goblin computer, and where Basic keeps working (review of change
// C, items G3.3 and G3.4): the docs say what decideTransport and the pipeline decide.
test('docs: Basic through a proxy on the Orbit computer that sends no forwarding headers is the loopback transport, and plain HTTP refuses Basic with https_required only while legacy Basic is on', async t => {
  const { decideTransport } = await import('../lib/http/transport.mjs');
  // A loopback peer with a loopback Host and no forwarding header is the Uptime Goblin computer itself;
  // one forwarding header, or another Host, makes it the plain-HTTP transport.
  const kind = headers => decideTransport({ peer: '127.0.0.1', headers }).kind;
  assert.equal(kind({ host: '127.0.0.1:4317' }), 'loopback');
  assert.equal(kind({ host: '127.0.0.1:4317', 'x-forwarded-for': '192.0.2.7' }), 'http');
  assert.equal(kind({ host: '127.0.0.1:4317', 'x-forwarded-proto': 'http' }), 'http');
  assert.equal(kind({ host: 'goblin.example' }), 'http');
  // lib/http/pipeline.mjs: legacy Basic off is basic_disabled first, on every transport; only
  // then does the plain-HTTP transport without the opt-in get https_required (not loopback).
  const pipeline = read('lib/http/pipeline.mjs');
  const disabled = pipeline.indexOf(
    "if (!legacyBasic) throw basicRefused(identityError('basic_disabled'));"
  );
  const plain = pipeline.indexOf("if (transport.kind === 'http' && !insecureHttpSessions) {");
  assert.ok(disabled !== -1 && plain > disabled, 'basic_disabled is decided before https_required');
  // Through the real pipeline, without the plain-HTTP opt-in (review EXPO-2): a script's Basic
  // through such a proxy (nginx's default Host 127.0.0.1:<port>, no forwarding header) signs in
  // and logs nothing; once the proxy sends X-Forwarded-For and X-Forwarded-Proto: http and
  // GOBLIN_TRUST_PROXY names it, it is the `http` transport and gets 403 https_required.
  const harness = await import('./http-pipeline/harness.mjs');
  const script = ['GET /api/thing HTTP/1.1', `Authorization: ${harness.basic()}`];
  const bare = await harness.serveAuth(t);
  const accepted = await harness.raw(bare.port, script);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.json.via, 'basic');
  assert.deepEqual(bare.logged, [], 'no warning in the log');
  const named = await harness.serveAuth(t, { trustProxy: 'loopback' });
  const forwarded = ['X-Forwarded-For: 192.0.2.7', 'X-Forwarded-Proto: http'];
  const refused = await harness.raw(named.port, [...script, ...forwarded]);
  assert.equal(refused.status, 403);
  assert.equal(refused.json.code, 'https_required');

  const basic = flat(section(read('docs/authentication.md'), 'Scripts and legacy Basic'));
  assert.ok(
    basic.includes(
      'A reverse proxy on the Uptime Goblin computer must send `X-Forwarded-For` and `X-Forwarded-Proto`'
    ),
    basic.slice(0, 300)
  );
  assert.ok(
    basic.includes(
      'is treated as coming from the Uptime Goblin computer itself (`loopback`) and accepted without `GOBLIN_INSECURE_HTTP_SESSIONS=1`, from wherever the proxy took it: Uptime Goblin cannot tell such requests from local scripts.'
    )
  );
  const row = read('docs/troubleshooting.md')
    .split('\n')
    .find(line => line.startsWith('| A script gets 403 `https_required`'));
  assert.ok(
    row.includes(
      'A reverse proxy on the Uptime Goblin computer must send `X-Forwarded-For` and `X-Forwarded-Proto`: Basic through one that sends no forwarding headers and keeps a loopback `Host` is treated as coming from the Uptime Goblin computer itself and accepted without `GOBLIN_INSECURE_HTTP_SESSIONS=1`, since Uptime Goblin cannot tell such requests from local scripts.'
    ),
    row
  );
  const scripts = read('docs/installation.md')
    .split('\n')
    .find(line => line.startsWith('- **Scripts using Basic**'));
  assert.ok(
    scripts.includes(
      "keep working on upgraded installs over HTTPS (through a proxy named in `GOBLIN_TRUST_PROXY` that sends `X-Forwarded-Proto: https`), from the Uptime Goblin computer itself, or while plain-HTTP sign-in is on (`GOBLIN_INSECURE_HTTP_SESSIONS=1`, or Docker Compose's default on its loopback port); over plain HTTP otherwise they get 403 `https_required`"
    ),
    scripts
  );
  assert.ok(
    flat(section(read('docs/architecture.md'), 'HTTP API')).includes(
      "On the `http` transport without the plain-HTTP opt-in (`GOBLIN_INSECURE_HTTP_SESSIONS`) Basic is not accepted: a 401 there carries no Basic challenge, and, while legacy Basic is on, a script's Basic there gets 403 `https_required` before its password is checked; with it off, Basic gets 401 `basic_disabled` there as on every transport"
    )
  );
  // Review EXPO-2: every text that says Basic over plain HTTP needs the opt-in (or gets 403
  // https_required) says it of the `http` transport and names, in the same place, the proxy on
  // the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host: Uptime Goblin takes
  // it for the computer itself, so Basic through it needs no opt-in, and a script's Basic
  // there starts no log line (headerlessProxy() needs another Host or an allowed host's Origin).
  const upgrade = unreleased()
    .split('\n')
    .find(line => line.startsWith('- **Scripts using Basic keep working on upgraded installs;'));
  for (const text of [
    'On the plain-HTTP (`http`) transport (a script that calls `http://<uptime-goblin-host>:4317` across the network, or a proxy that does not send `X-Forwarded-Proto: https`) Basic needs `GOBLIN_INSECURE_HTTP_SESSIONS=1`',
    "The exception is a proxy on the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host (nginx's default `Host: 127.0.0.1:4317` with a bare `proxy_pass`): Uptime Goblin takes its requests for the Uptime Goblin computer's own (the `loopback` transport), so Basic through it is accepted with no opt-in and no warning in the log, also from clients that reach the proxy over plain HTTP",
    'Make such a proxy send `X-Forwarded-For` and `X-Forwarded-Proto` and name it in `GOBLIN_TRUST_PROXY` (`loopback`): over plain HTTP, Basic through it then needs the opt-in like any other.',
  ])
    assert.ok(upgrade.includes(text), text);
  const settings = read('docs/configuration.md').split('\n');
  const settingRow = name => settings.find(line => line.startsWith(`| \`${name}\` |`));
  for (const [name, text, exception] of [
    [
      'CHANGELOG.md (1.5, browser requests)',
      unreleased()
        .split('\n')
        .find(line => line.startsWith('- Browser requests (with `Sec-Fetch-Site`')),
      "on the plain-HTTP transport only with `GOBLIN_INSECURE_HTTP_SESSIONS=1` or Docker Compose's default while it publishes the port on loopback, but with neither, and no warning in the log, through a proxy on the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host, which is the `loopback` transport: make such a proxy send `X-Forwarded-For` and `X-Forwarded-Proto` and name it in `GOBLIN_TRUST_PROXY`",
    ],
    [
      'docs/security.md (trust boundary)',
      flat(section(read('docs/security.md'), 'Trust boundary')),
      'on the plain-HTTP (`http`) transport Uptime Goblin accepts it only under that same opt-in, `GOBLIN_INSECURE_HTTP_SESSIONS=1` (otherwise 403 `https_required`, before the password is checked). The exception is a proxy on the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host',
    ],
    [
      'docs/security.md (answers without sign-in)',
      flat(read('docs/security.md')),
      'not on the plain-HTTP (`http`) transport without the plain-HTTP opt-in',
    ],
    [
      'docs/configuration.md (GOBLIN_INSECURE_HTTP_SESSIONS)',
      settingRow('GOBLIN_INSECURE_HTTP_SESSIONS'),
      'The same setting admits legacy Basic on the plain-HTTP (`http`) transport (without it, 403 `https_required`); through a proxy on the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host, which is the `loopback` transport, Basic needs no opt-in',
    ],
    [
      'docs/configuration.md (GOBLIN_LEGACY_BASIC)',
      settingRow('GOBLIN_LEGACY_BASIC'),
      "On the plain-HTTP (`http`) transport Basic also needs plain-HTTP sign-in on (`GOBLIN_INSECURE_HTTP_SESSIONS=1`, or Docker Compose's default on a loopback port); through a proxy on the Uptime Goblin computer that sends no forwarding headers and keeps a loopback Host, which is the `loopback` transport, it needs neither",
    ],
    [
      '.env.example (GOBLIN_INSECURE_HTTP_SESSIONS)',
      flat(read('.env.example').replace(/^# ?/gm, '')),
      'It also lets scripts sign in with HTTP Basic over plain HTTP (refused otherwise). With npm start, Basic through a proxy on this computer that sends no forwarding headers and keeps a loopback Host needs no such line',
    ],
    [
      'docs/installation.md (scripts using Basic)',
      scripts,
      'over plain HTTP otherwise they get 403 `https_required`, except through a proxy on the Uptime Goblin host that sends no forwarding headers and keeps a loopback Host',
    ],
  ])
    assert.ok(text.includes(exception), `${name}: ${exception}`);
  // Review TD-3: security.md and authentication.md said the log names such a proxy "once it sees
  // one", but headerlessProxy() names it only for another Host or a page at an allowed name; a
  // script's Basic through it is logged nowhere (bare.logged above). Both say so now.
  const namedOnce =
    'The log names such a proxy once it relays a request under a Host that is not a loopback one, or one from a page at a `GOBLIN_ALLOWED_HOSTS` name ("A reverse proxy on this computer sends Uptime Goblin requests without any forwarding header…"); one that relays only requests that keep a loopback Host and come from no such page (a script\'s Basic or `Bearer` request, say) is never named';
  for (const file of ['docs/security.md', 'docs/authentication.md']) {
    const text = flat(read(file));
    assert.ok(text.includes(namedOnce), file);
    assert.ok(!text.includes('The log names such a proxy once it sees one'), file);
  }
});

// Compose's compose-default (review of change C, item G3.1): the texts that name the plain-HTTP
// opt-in say that Compose's default turns it on for a loopback publish, and that it judges only
// by GOBLIN_BIND_ADDRESS.
test('docs: Compose turns plain-HTTP sign-in on by itself only for a loopback publish, judged by GOBLIN_BIND_ADDRESS alone, and the texts that name the opt-in say so', () => {
  const changelog = unreleased();
  assert.match(
    changelog,
    /^- \*\*Breaking: plain-HTTP sign-in is never turned on where the network can see it unless you choose it \(security\)\.\*\*/m
  );
  assert.doesNotMatch(changelog, /never turned on silently/);
  // Every "only with =1" in the 1.5 notes names Compose's default too (sessions and Basic).
  const onlyWith = [
    ...changelog.matchAll(
      /(?:over plain HTTP|on the plain-HTTP transport) only with `GOBLIN_INSECURE_HTTP_SESSIONS=1`[^)(]{0,80}/g
    ),
  ].map(match => match[0]);
  assert.equal(onlyWith.length, 2, onlyWith.join('\n'));
  for (const text of onlyWith) assert.match(text, /Docker Compose's default/, text);
  assert.match(
    changelog,
    /Basic needs `GOBLIN_INSECURE_HTTP_SESSIONS=1` \(or Docker Compose's default on its loopback port\), or it gets 403 `https_required`/
  );
  // A way into the container other than the published port: Uptime Goblin cannot see it.
  const elsewhere =
    '(`network_mode: host`, a macvlan or ipvlan network, a network shared with other containers) must set `GOBLIN_INSECURE_HTTP_SESSIONS`';
  const bind = read('docs/configuration.md')
    .split('\n')
    .find(line => line.startsWith('| `GOBLIN_BIND_ADDRESS` |'));
  for (const [name, text] of [
    ['docs/installation.md', flat(section(read('docs/installation.md'), 'Docker Compose'))],
    ['docs/configuration.md (GOBLIN_BIND_ADDRESS)', bind],
    ['CHANGELOG.md (1.5)', changelog],
  ])
    assert.ok(text.includes(elsewhere), name);
  // The yes/no rule names compose-default as its exception.
  assert.match(
    flat(read('docs/configuration.md')),
    /any other value prints a warning at the start and the default applies \(`GOBLIN_SUPERVISED` and `GOBLIN_LEGACY_BASIC` refuse the start instead, and `compose-default`, which Docker Compose passes for `GOBLIN_INSECURE_HTTP_SESSIONS`, is decided as that row says\)/
  );
  // No text says an unset variable under Compose means 1.
  for (const name of ['public/modules/identity/session.js', 'docs/troubleshooting.md'])
    assert.doesNotMatch(read(name), /unset variable means `?1\b/, name);
});

// Review finding F8: a browser sends no Sec-Fetch-Site to a plain-HTTP address on the network,
// so wherever Uptime Goblin accepts Basic there, a request the browser makes on its own (a typed
// address, a link, an image) is a script's to Uptime Goblin: without a credential it gets the Basic
// challenge, and a 1.4.x Basic login the browser remembers is checked and counted. Only where
// the browser sends fetch metadata (or Uptime Goblin's page sends X-Goblin-Client) is its Authorization
// ignored. The texts that describe legacy Basic say exactly that: none says browsers never use
// it, and the 1.5 notes name the plain-HTTP opt-in as what Basic requires, not as what is
// missing when it is refused.
test('docs: over plain HTTP a browser that remembers a 1.4.x Basic login is a script to Uptime Goblin, and the texts say so (F8)', async t => {
  const { basic, raw, serveAuth } = await import('./http-pipeline/harness.mjs');
  const challenge = 'Basic realm="Orbit", charset="UTF-8"';
  // A loopback peer that asks for another name with no forwarding header: the `http` transport
  // (a proxy on this host that relays plain HTTP).
  const plain = ['GET /api/thing HTTP/1.1', 'Host: goblin.example'];
  for (const insecureHttpSessions of [false, true]) {
    const { port, identity, loginThrottle } = await serveAuth(t, {
      insecureHttpSessions,
      configuredHosts: ['goblin.example'],
    });
    const get = lines => raw(port, [...plain, ...lines]);
    // A typed address or an image, no credential: the challenge only where Basic is accepted.
    const none = await get([]);
    assert.equal(none.status, 401);
    assert.equal(none.json.code, 'signin_required');
    assert.equal(none.json.transport.kind, 'http');
    assert.equal(none.headers['www-authenticate'], insecureHttpSessions ? challenge : undefined);
    // The same request with the login the browser remembers from 1.4.x, right and wrong.
    const right = await get([`Authorization: ${basic()}`]);
    const wrong = await get([`Authorization: ${basic('an old 1.4.x password')}`]);
    if (insecureHttpSessions) {
      assert.equal(right.status, 200, 'checked like a script and signed in');
      assert.equal(wrong.status, 401);
      assert.equal(wrong.headers['www-authenticate'], challenge);
      assert.equal(loginThrottle.size, 1, 'the wrong one counted as a failed sign-in');
    } else {
      for (const answer of [right, wrong]) {
        assert.equal(answer.status, 403);
        assert.equal(answer.json.code, 'https_required');
        assert.equal(answer.headers['www-authenticate'], undefined);
      }
      assert.equal(identity.test.checks, 0, 'no password was checked');
      assert.equal(loginThrottle.size, 0);
    }
    // Where the browser sends fetch metadata, or Uptime Goblin's page its own header: never Basic.
    // Review R1: browsers do send Sec-Fetch-Site over plain HTTP to localhost, 127.x and [::1],
    // which is how Compose's default (the port published on the Docker host's loopback) is
    // reached: there, on the `http` transport and with the opt-in, the login is not checked.
    const checks = identity.test.checks;
    for (const context of ['Sec-Fetch-Site: none', 'X-Goblin-Client: web/0123456789ab']) {
      const browser = await get([`Authorization: ${basic()}`, context]);
      assert.equal(browser.status, 401, context);
      assert.equal(browser.json.code, 'signin_required', context);
      assert.equal(browser.json.transport.kind, 'http', context);
      assert.equal(browser.headers['www-authenticate'], undefined, context);
    }
    assert.equal(identity.test.checks, checks, 'a browser page’s Authorization is never checked');
  }

  // The texts. .env.example's GOBLIN_LEGACY_BASIC comment (a comment block, read as a reader
  // sees it) states the exception instead of "browsers never use it".
  const example = flat(read('.env.example').replace(/^# ?/gm, ''));
  assert.ok(
    example.includes(
      "HTTP Basic sign-in for scripts (deprecated). Browsers sign in on Uptime Goblin's page, but they send no Sec-Fetch-Site to a plain-HTTP address on the network (they do to localhost, 127.x and [::1]), so wherever Uptime Goblin accepts Basic over plain HTTP a browser's remembered 1.4.x Basic login sent to such an address is checked like a script's"
    ),
    example
  );
  // The 1.5 notes: Basic requires the opt-in, named as what turns it on; without it, 403.
  const notes = unreleased();
  assert.ok(
    notes.includes(
      "Legacy Basic requires the same opt-in on the plain-HTTP transport (`GOBLIN_INSECURE_HTTP_SESSIONS=1`, or Compose's `compose-default` while the port is published on loopback): without it a script's Basic there gets 403 `https_required`"
    )
  );
  assert.ok(
    notes.includes(
      "with it, Basic there is checked, a browser's remembered 1.4.x Basic login included wherever the browser reaches Uptime Goblin at a plain-HTTP address on the network: browsers send no `Sec-Fetch-Site` there, so a request a browser makes there on its own is taken for a script's (the entry on browser requests below). They do send it to `localhost`, `127.x` and `[::1]`, so a current browser at `http://localhost:4317`, where Compose's default publishes the port, is never checked."
    )
  );
  assert.doesNotMatch(notes, /without it \(`GOBLIN_INSECURE_HTTP_SESSIONS=1`/);
  // The guide and the settings table say the same.
  assert.ok(
    flat(section(read('docs/authentication.md'), 'Scripts and legacy Basic')).includes(
      'Without a credential such a request gets 401 with the Basic challenge, as a script does'
    )
  );
  assert.ok(
    read('docs/configuration.md').includes(
      "at a plain-HTTP address on the network, where they send no `Sec-Fetch-Site` (they do to `localhost`, `127.x` and `[::1]`), a browser's remembered 1.4.x Basic login is treated like a script's"
    )
  );
  // No text, comment included, says browsers never use Basic or are never challenged.
  for (const [name, text] of browserTexts())
    assert.doesNotMatch(
      text,
      /browsers never use|\(never browsers\)|never a browser, whose native prompt|every current browser sends it\)/i,
      name
    );
});

// Review R1 and its repair (REPA-1, EXPO-1): browsers send Sec-Fetch-Site over plain HTTP too,
// to localhost, 127.x and [::1] (lib/http/transport.mjs, browserContext()), so no text says
// they send none over plain HTTP without naming an address on the network, in any form the
// texts used: "over plain HTTP, browsers send no …", "Over plain HTTP it sends none", "sends no
// `Sec-Fetch-Site` (over plain HTTP, …", "…: over plain HTTP, …" and "(plain HTTP, …", a
// comment's "sends no fetch metadata that … cannot be told from a script: over plain HTTP", and
// "send `Sec-Fetch-Site` only over HTTPS and on `localhost`" (127.x and [::1] left out).
test('docs: no text says browsers send no Sec-Fetch-Site over plain HTTP without naming an address on the network (R1)', () => {
  const unqualified = [
    /(?:over|on) plain HTTP,? (?:where )?(?:it|the browser|a browser|browsers|they) sends? (?:no|none)\b/i,
    /sends? no (?:`?Sec-Fetch-Site`?|fetch metadata) over plain HTTP/i,
    /sends? no (?:`?Sec-Fetch-Site`?|fetch metadata)[^.()]{0,50}?[:(] ?(?:over )?plain HTTP[,)]/i,
    /Sec-Fetch-Site`? only over HTTPS and (?:on|to) `?localhost`?(?!`?,? `?127)/i,
  ];
  for (const [name, text] of browserTexts())
    for (const pattern of unqualified) assert.doesNotMatch(text, pattern, name);
});
