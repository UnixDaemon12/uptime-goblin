// The pinned client's body decoders (lib/net/outbound.mjs): a small compressed chunk must not
// expand into memory ahead of the reader, codings that were never asked for (zstd) or chains of
// them are not decoded, a skip-only layer cannot feed the next one without bound, and ordinary
// bodies still decode.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { setTimeout as delay } from 'node:timers/promises';
import { decoders, fetchPinned } from '../lib/net/outbound.mjs';

const KiB = 1024,
  MiB = 1024 * KiB;
// INTERMEDIATE_LIMIT in lib/net/outbound.mjs.
const INTERMEDIATE_LIMIT = 64 * MiB;

// The first 64 KiB of a deflate stream of 200 MB of zeros: on its own it inflates to about 64 MB.
const zeros = Buffer.alloc(200 * MiB);
const bombs = {
  deflate: zlib.deflateSync(zeros).subarray(0, 64 * KiB),
  'raw deflate': zlib.deflateRawSync(zeros).subarray(0, 64 * KiB),
};

for (const [name, bomb] of Object.entries(bombs))
  test(`a 64 KiB ${name} bomb behind a paused reader keeps the decoder's output under 1 MB`, async t => {
    const [decoder] = decoders('deflate');
    t.after(() => decoder.destroy());
    decoder.on('error', () => {});
    let written = false;
    decoder.write(bomb, () => (written = true));
    // Long enough for an unbounded inflater to expand the whole chunk (well under a second).
    await delay(500);
    assert.ok(
      decoder.readableLength < MiB,
      `decoder buffered ${decoder.readableLength} bytes of unread output`
    );
    assert.equal(written, false, 'the chunk is not consumed while its output is unread');
    assert.equal(decoder.destroyed, false);
    // Reading drains it a piece at a time, and the inflater goes on as it is read.
    let read = 0;
    for await (const chunk of decoder) {
      read += chunk.length;
      assert.ok(decoder.readableLength < MiB);
      if (read > 8 * MiB) break;
    }
    assert.ok(read > 8 * MiB);
  });

test('ordinary deflate, raw deflate, gzip and brotli bodies still decode, read slowly or at once', async () => {
  const body = Buffer.from(
    JSON.stringify(Array.from({ length: 80000 }, (_, i) => ({ id: i, host: 'example.com' })))
  );
  assert.ok(body.length > 2 * MiB);
  const encoded = {
    deflate: zlib.deflateSync(body),
    'deflate (raw)': zlib.deflateRawSync(body),
    gzip: zlib.gzipSync(body),
    br: zlib.brotliCompressSync(body),
    'gzip, br': zlib.brotliCompressSync(zlib.gzipSync(body)),
  };
  for (const [name, data] of Object.entries(encoded))
    for (const slow of [false, true]) {
      const chain = decoders(name.replace(' (raw)', ''));
      // One decoder per coding, with a counter between two of them.
      assert.equal(chain.length, 2 * name.split(',').length - 1, name);
      for (let i = 0; i + 1 < chain.length; i++) chain[i].pipe(chain[i + 1]);
      const first = chain[0],
        last = chain.at(-1);
      // Fed in socket-sized pieces, as a response arrives.
      (async () => {
        for (let i = 0; i < data.length; i += 16 * KiB)
          if (!first.write(data.subarray(i, i + 16 * KiB)))
            await new Promise(resolve => first.once('drain', resolve));
        first.end();
      })();
      const parts = [];
      for await (const chunk of last) {
        parts.push(chunk);
        if (slow && parts.length % 16 === 0) await delay(1);
      }
      assert.ok(Buffer.concat(parts).equals(body), `${name} (${slow ? 'slow' : 'fast'} reader)`);
    }
});

test('the decoders accept only the codings Accept-Encoding offers, at most two deep', () => {
  for (const coding of ['gzip', 'x-gzip', 'deflate', 'br', 'gzip, deflate', 'DEFLATE', 'gzip, br'])
    assert.ok(decoders(coding).length > 0, coding);
  for (const coding of [
    '',
    'identity',
    'compress',
    'a, b, c, d, e, f',
    // Never offered: its decoder takes the window a frame declares, up to 128 MB a layer.
    'zstd',
    'gzip, zstd',
    'zstd, gzip',
    'gzip, zstd, gzip, zstd',
    // Three or more codings.
    'gzip, gzip, gzip',
    'gzip, deflate, br',
  ])
    assert.deepEqual(decoders(coding), [], coding);
});

/** A server on 127.0.0.1 answering every request with `body` coded as `encoding`. */
async function answering(t, encoding, body) {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Encoding': encoding, 'Content-Length': body.length });
    res.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}/`;
}
const read = async response => Buffer.from(await new Response(response.body).arrayBuffer());

test('a zstd answer, never asked for, reaches the caller as it was sent', async t => {
  assert.equal(typeof zlib.zstdCompressSync, 'function', 'this Node has zstd');
  const sent = zlib.zstdCompressSync(Buffer.from('{"a":1}'));
  for (const encoding of ['zstd', 'gzip, zstd']) {
    const body = encoding === 'zstd' ? sent : zlib.zstdCompressSync(zlib.gzipSync('{"a":1}'));
    const url = await answering(t, encoding, body);
    const response = await fetchPinned(url, { signal: AbortSignal.timeout(10000) }, ['127.0.0.1']);
    assert.ok((await read(response)).equals(body), encoding);
  }
});

// A gzip member whose header carries a comment of `size` bytes, which gunzip skips without
// output, around `text`.
function commented(size, text) {
  const member = zlib.gzipSync(text);
  const header = Buffer.from(member.subarray(0, 10));
  header[3] |= 0x10; // FCOMMENT
  return Buffer.concat([header, Buffer.alloc(size, 0x61), Buffer.from([0]), member.subarray(10)]);
}

test('a layer that feeds the next more than the intermediate limit fails the body', async t => {
  // The inner member's comment is skipped by its decoder, so only a few bytes reach the caller
  // however much the outer layer hands it.
  const inner = commented(INTERMEDIATE_LIMIT + 1024 * KiB, 'hello world');
  const url = await answering(t, 'gzip, gzip', zlib.gzipSync(inner));
  const response = await fetchPinned(url, { signal: AbortSignal.timeout(20000) }, ['127.0.0.1']);
  await assert.rejects(
    read(response),
    error =>
      error instanceof TypeError &&
      error.message === 'terminated' &&
      error.cause?.code === 'ERR_CONTENT_CODING_LIMIT'
  );
  // Under the limit, the same shape still decodes.
  const small = await answering(t, 'gzip, gzip', zlib.gzipSync(commented(MiB, 'hello world')));
  const ok = await fetchPinned(small, { signal: AbortSignal.timeout(20000) }, ['127.0.0.1']);
  assert.equal((await read(ok)).toString(), 'hello world');
});
