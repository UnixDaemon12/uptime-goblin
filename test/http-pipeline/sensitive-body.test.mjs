import test from 'node:test';
import assert from 'node:assert/strict';
import { readBody, readSensitiveBody, TooLargeError } from '../../lib/http/body.mjs';
import { withStepUpPassword } from '../../lib/admin/step-up.mjs';
const zero = bytes => bytes.every(byte => byte === 0);
const request = (chunks, { announced, failure } = {}) => ({
  headers:
    announced === undefined
      ? { 'transfer-encoding': 'chunked' }
      : { 'content-length': String(announced) },
  iterator(options) {
    assert.deepEqual(options, { destroyOnReturn: false });
    return (async function* () {
      for (const chunk of chunks) yield chunk;
      if (failure) throw failure;
    })();
  },
});

test('sensitive reader clears consumed chunks but returns intact caller-owned bytes', async () => {
  const chunks = [Buffer.from('fixture-'), Buffer.from('password')];
  const body = await readSensitiveBody(request(chunks), 16);
  assert.equal(body.toString(), 'fixture-password');
  assert.equal(chunks.every(zero), true);
  body.fill(0);
});

test('ordinary reader preserves existing input buffer semantics', async () => {
  const chunks = [Buffer.from('fixture')];
  const body = await readBody(request(chunks), 7);
  assert.equal(body.toString(), 'fixture');
  assert.equal(chunks[0].toString(), 'fixture');
});

test('oversize chunks clear both accumulated and offending bytes without reading remainder', async () => {
  const chunks = [Buffer.from('first'), Buffer.from('second'), Buffer.from('unread')];
  await assert.rejects(readSensitiveBody(request(chunks), 6), TooLargeError);
  assert.equal(zero(chunks[0]), true);
  assert.equal(zero(chunks[1]), true);
  assert.equal(chunks[2].toString(), 'unread');
});

test('announced oversize refuses before touching stream or taking ownership', async () => {
  let read = false;
  await assert.rejects(
    readSensitiveBody(
      {
        headers: { 'content-length': '17' },
        iterator() {
          read = true;
          throw new Error('not called');
        },
      },
      16
    ),
    TooLargeError
  );
  assert.equal(read, false);
});

test('disconnect-style iterator failure clears all chunks already consumed', async () => {
  const chunks = [Buffer.from('fixture')],
    failure = new Error('client closed');
  await assert.rejects(
    readSensitiveBody(request(chunks, { failure }), 16),
    error => error === failure
  );
  assert.equal(chunks.every(zero), true);
});

test('reader and envelope compose without leaving a consumed password byte buffer', async () => {
  const chunks = [
    Buffer.from('{"stepUp":{"password":"'),
    Buffer.from('fixture-password"},"name":"Display"}'),
  ];
  const raw = await readSensitiveBody(request(chunks), 4096);
  let borrowed;
  const result = await withStepUpPassword(raw, (bytes, body) => {
    borrowed = bytes;
    assert.equal(bytes.toString(), 'fixture-password');
    return body;
  });
  assert.deepEqual(result, { name: 'Display' });
  assert.equal(chunks.every(zero), true);
  assert.equal(zero(raw), true);
  assert.equal(zero(borrowed), true);
});
