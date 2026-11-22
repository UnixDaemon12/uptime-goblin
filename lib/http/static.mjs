// The web app's files: the page, the stable /boot.js loader, build-stamped /assets/<build>/
// URLs, and every other file under public/ at its own path, as 1.4.3 served it (contract C-O).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const staticTypes = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
});
const contentType = file => staticTypes[path.extname(file)] ?? 'application/octet-stream';

/** How long a build-stamped asset may be cached: its URL changes whenever its bytes do. */
export const immutableCache = 'private, max-age=31536000, immutable';

/**
 * The release this code belongs to. `build` is the first 12 hex digits of
 * sha256(version "\n" + for each file sorted by path: path "\n" sha256hex(bytes) "\n"),
 * over every file under public/, every *.mjs file under lib/ (both recursively, dot files and
 * dot directories skipped) and server.mjs, with paths relative to the application root and
 * "/" separators. The installer computes the same value with computeBuild() in
 * lib/healthcheck.mjs; a test keeps the two in step. lib/ is walked because 1.5 keeps server
 * code in lib/http/, lib/db/ and so on; a tree without lib/ subdirectories (1.4.x) keeps
 * exactly the build it had, so a kept earlier release is still recognised.
 * `publicFiles` maps each file's URL path ("/app.js") to its bytes.
 */
export function readRelease(appRoot, publicDirectory = path.join(appRoot, 'public')) {
  const version = JSON.parse(fs.readFileSync(path.join(appRoot, 'package.json'), 'utf8')).version;
  const files = [],
    publicFiles = new Map();
  // Dirent types do not follow symlinks, so a symlink is neither walked nor hashed.
  const walk = (directory, prefix, keep) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const full = path.join(directory, entry.name),
        relative = `${prefix}/${entry.name}`;
      if (entry.isDirectory()) walk(full, relative, keep);
      else if (entry.isFile() && keep(entry.name)) files.push([relative, fs.readFileSync(full)]);
    }
  };
  walk(publicDirectory, 'public', () => true);
  // Only public/ has been walked so far: those are the files the static routes serve.
  for (const [relative, bytes] of files) publicFiles.set(relative.slice('public'.length), bytes);
  walk(path.join(appRoot, 'lib'), 'lib', name => name.endsWith('.mjs'));
  files.push(['server.mjs', fs.readFileSync(path.join(appRoot, 'server.mjs'))]);
  files.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const hash = createHash('sha256').update(`${version}\n`);
  for (const [relative, bytes] of files)
    hash.update(`${relative}\n${createHash('sha256').update(bytes).digest('hex')}\n`);
  return { version, build: hash.digest('hex').slice(0, 12), publicFiles };
}

const attribute = String.raw`(\s(?:src|href)=["'])`;
/**
 * index.html as served: the build in a meta tag, and asset URLs that name it, so a page can
 * tell which release it came from and a cache cannot pair it with another release's files.
 *
 * - Any `/assets/<anything>/…` URL is pointed at this build (a template may write any
 *   placeholder there, for example `/assets/build/style.css`).
 * - A page that loads the stable `/boot.js` (1.5 and later) gets its stylesheet from
 *   `/assets/<build>/style.css`; `/boot.js` itself is never stamped.
 * - An older page's `/app.js` and `/style.css` get `?v=<build>` (1.4.3).
 *
 * Rendering is idempotent: rendering the output again changes nothing.
 */
export function renderIndex(template, build) {
  const meta = `<meta name="orbit-build" content="${build}" />`;
  let html = template.replace(/[ \t]*<meta\s+name=["']orbit-build["'][^>]*>[ \t]*\r?\n?/gi, '');
  html = /<meta\s+charset=[^>]*>/i.test(html)
    ? html.replace(/(<meta\s+charset=[^>]*>)/i, `$1\n    ${meta}`)
    : html.replace(/<head>/i, `<head>\n    ${meta}`);
  html = html.replace(new RegExp(`${attribute}/assets/[^/"'\\s]+/`, 'g'), `$1/assets/${build}/`);
  if (new RegExp(`${attribute}/boot\\.js(?:\\?[^"']*)?["']`).test(html))
    html = html.replace(
      new RegExp(`${attribute}/style\\.css(["'])`, 'g'),
      `$1/assets/${build}/style.css$2`
    );
  return html.replace(
    new RegExp(`${attribute}/(app\\.js|style\\.css)(["'])`, 'g'),
    `$1/$2?v=${build}$3`
  );
}

const releaseName = /^\d+\.\d+\.\d+\S*-([0-9a-f]{12,64})$/;
/**
 * Where the releases kept beside this one live, or null. Staged installs (1.5 installer v2)
 * keep each release in `<prefix>/releases/<version>-<build>/`; any other layout (an in-place
 * install, a checkout, the Docker image) has no earlier release to serve.
 */
export function findReleasesDirectory(appRoot) {
  try {
    const parent = path.dirname(fs.realpathSync(appRoot));
    return path.basename(parent) === 'releases' ? parent : null;
  } catch {
    return null;
  }
}

async function readKept(publicDirectory, relative) {
  // The path came from a URL: plain names only, no dot files, no way out of public/.
  if (!/^\/[A-Za-z0-9._\/-]+$/.test(relative)) return null;
  const parts = relative.slice(1).split('/');
  if (parts.some(part => !part || part.startsWith('.'))) return null;
  try {
    const base = await fs.promises.realpath(publicDirectory),
      file = await fs.promises.realpath(path.join(base, ...parts));
    if (!file.startsWith(base + path.sep)) return null;
    const stat = await fs.promises.stat(file);
    if (!stat.isFile() || stat.size > 16 * 1024 * 1024) return null;
    return await fs.promises.readFile(file);
  } catch {
    return null;
  }
}

function send(req, res, bytes, file, headers) {
  res.writeHead(200, {
    'Content-Type': contentType(file),
    ...headers,
    'Content-Length': bytes.length,
  });
  res.end(req.method === 'HEAD' ? undefined : bytes);
}
function missing(res, headers = {}) {
  res.writeHead(404, headers);
  res.end('Not found');
}

/**
 * The static routes (all GET, also answering HEAD). They are public (D9): the sign-in view is
 * part of the web app and must load before anyone signs in. The page names its build in a
 * meta tag anyway, so nothing is gained by hiding it; the data comes only from the API, which
 * needs a session.
 *
 * - `/` and `/index.html`: the rendered page, `no-store`.
 * - `/assets/<build>/<path>`: `public/<path>` of this build, cached for a year (immutable);
 *   of an earlier release still kept in `releases` (`<version>-<build>/public/<path>`), the
 *   same. Anything else, including a build whose files were removed, is 404 `no-store`, so
 *   the page's /boot.js reloads once instead of caching the miss.
 * - Any other path: that file of this build, `no-cache` with the build as ETag. A `?v=` naming
 *   another build still gets the file (never a blank page) but `no-store`: that page reloads.
 */
export function staticRoutes({ build, publicFiles, indexPage, releases = null }) {
  const page = (req, res) => {
    res.writeHead(200, {
      'Content-Type': staticTypes['.html'],
      'Cache-Control': 'no-store',
      'Content-Length': indexPage.length,
    });
    res.end(req.method === 'HEAD' ? undefined : indexPage);
  };
  const route = (path, summary, handler) => ({
    method: 'GET',
    path,
    head: true,
    auth: 'public',
    permission: null,
    summary,
    handler,
  });
  return [
    route('/', 'The web app', ({ req, res }) => page(req, res)),
    route('/index.html', 'The web app', ({ req, res }) => page(req, res)),
    route('/assets/:build/*', 'A web app file of one build', async ({ req, res, params }) => {
      const relative = '/' + params['*'],
        immutable = { 'Cache-Control': immutableCache };
      if (params.build === build) {
        const bytes = relative === '/index.html' ? undefined : publicFiles.get(relative);
        if (bytes) send(req, res, bytes, relative, immutable);
        else missing(res, { 'Cache-Control': 'no-store' });
        return;
      }
      if (releases && relative !== '/index.html' && /^[0-9a-f]{12,64}$/.test(params.build)) {
        let kept = null;
        try {
          kept = (await fs.promises.readdir(releases)).find(
            name => releaseName.exec(name)?.[1] === params.build
          );
        } catch {}
        const bytes = kept && (await readKept(path.join(releases, kept, 'public'), relative));
        if (bytes) {
          send(req, res, bytes, relative, immutable);
          return;
        }
      }
      missing(res, { 'Cache-Control': 'no-store' });
    }),
    route('/*', 'A web app file', ({ req, res, url }) => {
      const bytes = publicFiles.get(url.pathname);
      if (!bytes) {
        missing(res);
        return;
      }
      const requested = url.searchParams.get('v'),
        tag = `"${build}"`,
        headers = {};
      // The page always comes fresh. An asset asked for by another build's page is still
      // answered (never a blank page), but never cached: that page reloads itself.
      if (requested !== null && requested !== build) headers['Cache-Control'] = 'no-store';
      else {
        headers['Cache-Control'] = 'no-cache';
        headers.ETag = tag;
        if (req.headers['if-none-match'] === tag) {
          res.writeHead(304, { 'Content-Type': contentType(url.pathname), ...headers });
          res.end();
          return;
        }
      }
      send(req, res, bytes, url.pathname, headers);
    }),
  ];
}
