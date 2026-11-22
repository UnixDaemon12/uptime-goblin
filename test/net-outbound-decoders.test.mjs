// The pinned client's body decoders (lib/net/outbound.mjs): a small compressed chunk must not
// expand into memory ahead of the reader, and ordinary bodies still decode.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { setTimeout as delay } from 'node:timers/promises';
import { decoders } from '../lib/net/outbound.mjs';

const KiB = 1024,
  MiB = 1024 * KiB;

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
      assert.equal(chain.length, name.split(',').length, name);
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

test('the decoders accept the same codings as before', () => {
  for (const coding of ['gzip', 'x-gzip', 'deflate', 'br', 'gzip, deflate', 'DEFLATE'])
    assert.ok(decoders(coding).length > 0, coding);
  for (const coding of ['', 'identity', 'compress', 'a, b, c, d, e, f'])
    assert.deepEqual(decoders(coding), [], coding);
});
