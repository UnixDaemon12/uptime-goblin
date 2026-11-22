import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import { newService } from '../lib/catalog.mjs';
import {
  CollectionError,
  collect,
  parsePrometheus,
  readBudget,
  request,
  transport,
} from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const service = { ...newService('json', 'limits-test'), apiUrl: 'https://limits.example.com' };

test('Prometheus lines with many closing braces parse in linear time', () => {
  // Each '} 1 #' was a candidate end for a greedy label body, and the trailing '\r' made every
  // candidate fail only after scanning the rest of the line (about 6 ms per line before).
  const hostile = ('a{' + '} 1 #'.repeat(1700)).slice(0, 8190) + '\r\n';
  const started = performance.now();
  assert.deepEqual(parsePrometheus(hostile.repeat(400)), []);
  assert.ok(
    performance.now() - started < 500,
    'hostile exporter output must not stall Uptime Goblin'
  );
  const [sample] = parsePrometheus('sample{path="/a}b",mode="x"} 2 1700000000 # {trace="1"} 1\n');
  assert.equal(sample.value, 2);
  assert.equal(sample.labels.path, '/a}b');
  assert.equal(sample.labels.mode, 'x');
});

test('Prometheus bodies of empty or comment lines stop at the line limit, whatever their samples', () => {
  // 16 MB of '\n' (within the response limit) was split into 16 million strings, about 150 MB,
  // before any sample was looked at. Every line now counts, blank and comment ones too, and the
  // body is read line by line. A split before the count would still meet the limit, and quickly,
  // so the reading runs in a process whose heap holds 48 MB: the array a split builds of either
  // body (128 MB and 64 MB of references) ends that process, while reading line by line needs
  // little beyond the body.
  const child = spawnSync(
    process.execPath,
    [
      '--max-old-space-size=48',
      '--input-type=module',
      '--eval',
      `const { parsePrometheus, readBudget } = await import(${JSON.stringify(
        new URL('../lib/collectors.mjs', import.meta.url).href
      )});
      const outcome = body => {
        try {
          return 'parsed ' + parsePrometheus(body, readBudget()).length;
        } catch (error) {
          return String(error);
        }
      };
      console.log(JSON.stringify([outcome('\\n'.repeat(16 * 2 ** 20)), outcome('#\\n'.repeat(8 * 2 ** 20))]));`,
    ],
    { encoding: 'utf8', timeout: 60000 }
  );
  assert.equal(child.status, 0, `signal ${child.signal}: ${child.stderr.slice(-1000)}`);
  assert.deepEqual(
    JSON.parse(child.stdout),
    Array(2).fill('Error: Prometheus source exceeds the 1,000,000 line limit')
  );
  // At the limit, and with every sample family's # HELP and # TYPE lines, a body still parses.
  const [last] = parsePrometheus('\n'.repeat(999999) + 'a 1');
  assert.deepEqual([last.name, last.value], ['a', 1]);
  const families = Array.from(
    { length: 1000 },
    (_, i) => `# HELP m${i} Synthetic.\n# TYPE m${i} gauge\nm${i} ${i}`
  ).join('\n');
  assert.equal(parsePrometheus(families, readBudget()).length, 1000);
});

test('Prometheus samples and labels draw on the collection value budget', async t => {
  // 12,000 lines of 64 empty labels each: about 5 MB, well within the 16 MB response limit and
  // the 100,000-sample limit, but 780,000 values once parsed (one per sample and per label).
  const labels = Array.from({ length: 64 }, (_, i) => `l${i}=""`).join(',');
  const heavy = Array.from({ length: 12000 }, (_, i) => `m{${labels}} ${i}`).join('\n') + '\n';
  const tooComplex = error =>
    error instanceof CollectionError &&
    /too complex/.test(error.message) &&
    error.retryable === false;
  assert.throws(() => parsePrometheus(heavy, readBudget()), tooComplex);
  // Refused before the whole body is parsed: the budget runs out on the 11,539th sample, at the
  // first value beyond it.
  const budget = readBudget();
  assert.throws(() => parsePrometheus(heavy, budget), tooComplex);
  assert.equal(budget.tokens, -1);
  // The budget is the collection's: JSON already read in it leaves less for the text.
  const shared = { ...readBudget(), tokens: 100 };
  assert.equal(parsePrometheus('a 1\nb{x="1",y="2"} 2\n', shared).length, 2);
  assert.equal(shared.tokens, 100 - 1 - 3);
  // A collection of a Prometheus-family source charges its scrape.
  t.mock.method(transport, 'fetch', async () => new Response(heavy));
  for (const type of ['linux', 'windows', 'prometheus'])
    await assert.rejects(
      collect({
        ...newService(type, 'limits-' + type),
        apiUrl: 'https://limits.example.com',
        metrics: [{ key: 'm', label: 'M', path: 'm', unit: '' }],
      }),
      tooComplex,
      type
    );
  // An ordinary node_exporter scrape is far within it.
  const ordinary = Array.from(
    { length: 3000 },
    (_, i) => `node_cpu_seconds_total{cpu="${i % 64}",mode="m${i}"} ${i}`
  ).join('\n');
  assert.equal(parsePrometheus(ordinary, readBudget()).length, 3000);
});

test('Prometheus labels read on lines that are then left out draw on the value budget too', () => {
  // A line is left out at a 65th label, a repeated label name or a bad escape only after its
  // other labels were read (64 JSON.parse calls). Only kept samples were charged, so a 16 MB
  // body of such lines kept nothing, cost nothing and held the event loop as long as a body of
  // kept ones (about 0.4 s per scrape). 12,000 lines of 64 labels each read 768,000 labels.
  const labels = Array.from({ length: 64 }, (_, i) => `l${i}="v"`);
  const tooComplex = error => error instanceof CollectionError && /too complex/.test(error.message);
  for (const [what, line] of [
    ['a 65th label', `m{${labels.join(',')},z="v"} 1`],
    ['a repeated label name', `m{${labels.join(',')},l0="v"} 1`],
    ['a bad escape in the last label', `m{${labels.slice(0, 63).join(',')},z="\\q"} 1`],
  ]) {
    const body = Array(12000).fill(line).join('\n'),
      budget = readBudget();
    assert.throws(() => parsePrometheus(body, budget), tooComplex, what);
    assert.equal(budget.tokens, -1, what);
    // Each such line is still left out on its own, within the budget.
    const small = readBudget();
    assert.deepEqual(
      parsePrometheus(line + '\na 1', small).map(sample => [sample.name, sample.value]),
      [['a', 1]]
    );
    assert.ok(small.tokens <= readBudget().tokens - 64 - 1, what);
  }
});

test('JSON bodies are bounded by structure as well as size before parsing', async t => {
  let body;
  t.mock.method(transport, 'fetch', async () => new Response(body));
  // About 1.8 MB, far below the 16 MB cap, but JSON.parse would build 600,000 objects.
  body = '[' + '{},'.repeat(600000) + '{}]';
  await assert.rejects(
    request(service, '/objects'),
    error => /too complex/.test(error.message) && error.retryable === false
  );
  body = JSON.stringify(Array.from({ length: 1000 }, (_, i) => ({ id: i, tags: ['a', 'b'] })));
  assert.equal((await request(service, '/objects')).length, 1000);
  // Text responses (Prometheus) have their own line and sample limits instead.
  body = ','.repeat(1100000);
  assert.equal((await request(service, '/metrics', { text: true })).length, 1100000);
});

test('one collection has a read budget across all of its requests, independent of others', async t => {
  const chunk = new Uint8Array(12 * 1024 * 1024).fill(0x20),
    end = new TextEncoder().encode('{}');
  t.mock.method(
    transport,
    'fetch',
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(chunk);
            controller.enqueue(end);
            controller.close();
          },
        })
      )
  );
  // Two 12 MB responses fit one collection's 32 MB budget; a third does not.
  const shared = { ...service, readBudget: readBudget() };
  assert.deepEqual(await request(shared, '/a'), {});
  assert.deepEqual(await request(shared, '/b'), {});
  await assert.rejects(
    request(shared, '/c'),
    error => /32 MB/.test(error.message) && error.retryable !== true
  );
  // Another collection (or a request without a shared budget) is unaffected.
  assert.deepEqual(await request({ ...service, readBudget: readBudget() }, '/d'), {});
  assert.deepEqual(await request(service, '/e'), {});
});

test('JSON values are also budgeted per collection', async t => {
  const body = '[' + '0,'.repeat(500000) + '0]';
  t.mock.method(transport, 'fetch', async () => new Response(body));
  const shared = { ...service, readBudget: readBudget() };
  assert.equal((await request(shared, '/a')).length, 500001);
  await assert.rejects(request(shared, '/b'), /too complex/);
});

test('deeply nested JSON is refused, and brackets inside strings are not counted', async t => {
  let body;
  t.mock.method(transport, 'fetch', async () => new Response(body));
  body = '['.repeat(65) + ']'.repeat(65);
  await assert.rejects(request(service, '/deep'), /nests more than 64 levels/);
  body = '['.repeat(64) + ']'.repeat(64);
  assert.ok(Array.isArray(await request(service, '/ok')));
  // 2 MB of commas and brackets inside one string value: one value, not millions.
  body = JSON.stringify({ text: '[{,'.repeat(700000) + '\\"' });
  assert.equal((await request(service, '/string')).text.length, 2100002);
});

// Serves a body in chunks of `size` bytes, so values, escapes and multibyte characters split.
const chunked = (body, size) => {
  const bytes = new TextEncoder().encode(body);
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(offset, (offset += size)));
    },
  });
};
// Shaped like a Radarr v5 /api/v3/movie entry, indented as Radarr sends it (about 6 KB).
const movie = i => ({
  title: `Película "${i}" – Director’s Cut`,
  originalTitle: `Film ${i}`,
  originalLanguage: { id: 1, name: 'English' },
  alternateTitles: Array.from({ length: 8 }, (_, j) => ({
    sourceType: 'tmdb',
    movieMetadataId: i,
    title: `Alternate title ${j} for movie ${i}`,
    cleanTitle: `alternatetitle${j}formovie${i}`,
    id: i * 10 + j,
  })),
  sortTitle: `film ${i}`,
  sizeOnDisk: 4294967296 + i,
  status: 'released',
  overview:
    'A story with "quotes", back\\slashes, [brackets], {braces}, commas, and ünïcödé. '.repeat(8),
  images: ['poster', 'fanart'].map(coverType => ({
    coverType,
    url: `/MediaCover/${i}/${coverType}.jpg`,
    remoteUrl: `https://image.tmdb.org/t/p/original/${coverType}${i}.jpg`,
  })),
  year: 1990 + (i % 30),
  hasFile: i % 3 !== 0,
  monitored: i % 5 !== 0,
  isAvailable: i % 7 !== 0,
  path: `/data/media/movies/Film ${i} (${1990 + (i % 30)})`,
  qualityProfileId: 4,
  minimumAvailability: 'released',
  folderName: `/data/media/movies/Film ${i} (${1990 + (i % 30)})`,
  runtime: 123,
  cleanTitle: `film${i}`,
  imdbId: `tt${1000000 + i}`,
  tmdbId: 10000 + i,
  titleSlug: `film-${i}-${10000 + i}`,
  rootFolderPath: '/data/media/movies',
  certification: 'R',
  studio: 'Example Pictures International',
  website: `https://www.example.com/films/${i}`,
  youTubeTrailerId: 'dQw4w9WgXcQ',
  inCinemas: '2001-05-04T00:00:00Z',
  physicalRelease: '2001-11-20T00:00:00Z',
  digitalRelease: '2001-10-01T00:00:00Z',
  added: '2023-06-01T12:00:00Z',
  popularity: 23.456,
  collection: { title: `Film Collection ${i % 50}`, tmdbId: 5000 + (i % 50) },
  statistics: {
    movieFileCount: i % 3 !== 0 ? 1 : 0,
    sizeOnDisk: 4294967296 + i,
    releaseGroups: ['GROUP'],
  },
  genres: ['Drama', 'Thriller', 'Mystery'],
  keywords: ['heist', 'double cross', 'based on novel', 'neo-noir'],
  tags: [1, 2],
  ratings: {
    imdb: { votes: 1000 + i, value: 7.1, type: 'user' },
    tmdb: { votes: 500 + i, value: 6.9, type: 'user' },
  },
  movieFile:
    i % 3 !== 0
      ? {
          movieId: i,
          relativePath: `Film ${i} (2001) Bluray-1080p.mkv`,
          size: 4294967296 + i,
          dateAdded: '2024-01-01T00:00:00Z',
          quality: { quality: { id: 7, name: 'Bluray-1080p', source: 'bluray' } },
          mediaInfo: {
            audioBitrate: 1509000,
            audioChannels: 5.1,
            audioCodec: 'DTS',
            audioLanguages: 'eng/fra/spa',
            videoBitDepth: 8,
            videoCodec: 'x264',
            videoFps: 23.976,
            resolution: '1920x800',
            runTime: '2:03:12',
            subtitles: 'eng/fra/spa/deu/ita',
          },
          id: i,
        }
      : undefined,
  id: i,
});
const libraryFor = count =>
  JSON.stringify(
    Array.from({ length: count }, (_, i) => movie(i + 1)),
    null,
    2
  );

test('a large Radarr library is streamed past the buffered response limit and counted', async t => {
  const body = libraryFor(5000);
  assert.ok(body.length > 20 * 1024 * 1024, 'the fixture must exceed the 16 MB response limit');
  t.mock.method(transport, 'fetch', async url => {
    const route = new URL(url).pathname;
    if (route.endsWith('/movie')) return new Response(chunked(body, 65521));
    if (route.endsWith('/queue/status')) return Response.json({ totalCount: 3, errors: true });
    if (route.endsWith('/health')) return Response.json([{ type: 'error' }]);
    return Response.json([{ path: '/data', freeSpace: 1, totalSpace: 2 }]);
  });
  const readings = await collect({ ...newService('radarr'), apiUrl: 'https://arr.example.com' });
  const v = Object.fromEntries(readings.map(m => [m.key, m.value]));
  const expected = Array.from({ length: 5000 }, (_, i) => movie(i + 1)).filter(
    m => m.monitored && m.isAvailable && !m.hasFile
  ).length;
  assert.equal(v.movies, 5000);
  assert.equal(v.missing, expected);
  assert.equal(v.queue, 3);
  assert.equal(v.queue_errors, 1);
  assert.equal(v.health_issues, 1);
  assert.equal(v['disk_free_/data'], 1);
  assert.deepEqual(readings.notes, []);
});

test('streamed lists parse across chunk boundaries and refuse malformed or oversized bodies', async t => {
  let body, size;
  t.mock.method(transport, 'fetch', async () => new Response(chunked(body, size)));
  const read = async (text, { limit, chunk = 3 } = {}) => {
    body = text;
    size = chunk;
    const items = [];
    const count = await request(service, '/list', { each: item => items.push(item), limit });
    return { count, items };
  };
  const list = [{ a: '[{",\\"}]', b: [1, [2, { c: 'é' }]] }, 'x,y', 3, null, true, { '': [] }];
  assert.deepEqual(await read(JSON.stringify(list, null, 2)), { count: 6, items: list });
  assert.deepEqual(await read(' [ ] '), { count: 0, items: [] });
  assert.deepEqual(await read('null'), { count: null, items: [] });
  const invalid = /did not return valid JSON/;
  for (const text of ['', '[1,2', '[1,]', '[,1]', '[1 2]', '[1]x', 'nul', '[{"a":}]'])
    await assert.rejects(read(text), invalid, JSON.stringify(text));
  await assert.rejects(read('{"data":[]}'), /array was required/);
  await assert.rejects(read('[' + '['.repeat(64) + ']'.repeat(64) + ']'), /nests more than 64/);
  // Bounded however the source shapes it: bytes, entries and the size of one entry.
  const tooLarge = pattern => error => pattern.test(error.message) && error.tooLarge === true;
  const chunk = 65536;
  await assert.rejects(
    read('[' + '"abcdefgh",'.repeat(100000) + '0]', { limit: 1024 * 1024, chunk }),
    tooLarge(/exceeds the 1 MB collection limit/)
  );
  await assert.rejects(
    read('[' + '0,'.repeat(200000) + '0]', { chunk }),
    tooLarge(/200,000 entry limit/)
  );
  await assert.rejects(
    read(JSON.stringify([1, { overview: 'x'.repeat(1024 * 1024) }]), { chunk }),
    tooLarge(/entry exceeds the 1 MB limit/)
  );
  // Streamed elements are dropped as they are counted, so they do not use the read budget:
  // about a million values here, more than a buffered collection may read.
  size = chunk;
  body = '[' + '{"a":[1,2,3,4,5,6]},'.repeat(150000) + '{}]';
  const shared = { ...service, readBudget: readBudget() };
  assert.equal(await request(shared, '/objects', { each: () => {} }), 150001);
  assert.deepEqual(shared.readBudget, readBudget());
});

test('lists that are only counted keep no entry, so one entry over 1 MB is still counted', async t => {
  let body, size;
  t.mock.method(transport, 'fetch', async () => new Response(chunked(body, size)));
  const count = (text, { limit, chunk = 3 } = {}) => {
    body = text;
    size = chunk;
    return request(service, '/list', { count: true, limit });
  };
  const list = [{ a: '[{",\\"}]', b: [1, [2, { c: 'é' }]] }, 'x,y', 3, null, true, { '': [] }];
  assert.equal(await count(JSON.stringify(list, null, 2)), 6);
  assert.equal(await count(' [ ] '), 0);
  assert.equal(await count('null'), null);
  // A CrowdSec alert carrying a bulk `cscli decisions import` holds every imported decision.
  const decision = { origin: 'cscli-import', scope: 'Ip', type: 'ban', value: '192.0.2.1' };
  const alert = JSON.stringify({ id: 1, decisions: Array(20000).fill(decision) });
  assert.ok(alert.length > 1024 * 1024, 'the fixture must exceed the 1 MB entry limit');
  assert.equal(await count(`[${alert},{"id":2}]`, { chunk: 65536 }), 2);
  // Entries are not parsed, but the list's framing (strings, brackets and commas) is checked.
  for (const text of ['', '[1,2', '[1,]', '[,1]', '[1]x', 'nul', '[{]}', '[}', '["a]'])
    await assert.rejects(count(text), /did not return valid JSON/, JSON.stringify(text));
  await assert.rejects(count('{"data":[]}'), /array was required/);
  await assert.rejects(count('[' + '['.repeat(64) + ']'.repeat(64) + ']'), /nests more than 64/);
  // The response byte and entry limits still apply, and the read budget is not used.
  const tooLarge = pattern => error => pattern.test(error.message) && error.tooLarge === true;
  await assert.rejects(
    count('[' + '"abcdefgh",'.repeat(100000) + '0]', { limit: 1024 * 1024, chunk: 65536 }),
    tooLarge(/exceeds the 1 MB collection limit/)
  );
  await assert.rejects(
    count('[' + '0,'.repeat(200000) + '0]', { chunk: 65536 }),
    tooLarge(/200,000 entry limit/)
  );
  const shared = { ...service, readBudget: readBudget() };
  body = '[' + '{"a":[1,2,3,4,5,6]},'.repeat(150000) + '{}]';
  assert.equal(await request(shared, '/objects', { count: true }), 150001);
  assert.deepEqual(shared.readBudget, readBudget());
});

test('an *arr library over its 64 MB limit still leaves queue, health and disk readings', async t => {
  // 130 entries of 512 KB each, streamed without building the 65 MB body.
  const entry = new TextEncoder().encode(JSON.stringify({ overview: 'x'.repeat(512 * 1024) }));
  const comma = new TextEncoder().encode(',');
  const oversized = () => {
    let sent = 0;
    return new ReadableStream({
      pull(controller) {
        controller.enqueue(sent++ ? comma : new TextEncoder().encode('['));
        controller.enqueue(entry);
        if (sent === 130) {
          controller.enqueue(new TextEncoder().encode(']'));
          controller.close();
        }
      },
    });
  };
  t.mock.method(transport, 'fetch', async url => {
    const route = new URL(url).pathname;
    if (route.endsWith('/movie') || route.endsWith('/series')) return new Response(oversized());
    if (route.endsWith('/queue/status')) return Response.json({ totalCount: 2 });
    if (route.endsWith('/wanted/missing')) return Response.json({ totalRecords: 4 });
    if (route.endsWith('/health')) return Response.json([{ type: 'warning' }]);
    return Response.json([]);
  });
  for (const [type, library] of [
    ['radarr', ['movies', 'missing']],
    ['sonarr', ['series', 'episodes']],
  ]) {
    const readings = await collect({ ...newService(type), apiUrl: 'https://arr.example.com' }),
      v = Object.fromEntries(readings.map(m => [m.key, m.value]));
    assert.equal(v.queue, 2, type);
    assert.equal(v.health_issues, 1, type);
    for (const key of library) assert.equal(v[key], undefined, type + ' ' + key);
    if (type === 'sonarr') assert.equal(v.missing, 4);
    // The card says why the library counts are missing instead of dropping them silently.
    assert.deepEqual(
      readings.notes.map(n => n.code),
      ['arr_library_too_large']
    );
    assert.match(
      readings.notes[0].message,
      type === 'sonarr' ? /^The Sonarr library/ : /^The Radarr library/
    );
  }
});
