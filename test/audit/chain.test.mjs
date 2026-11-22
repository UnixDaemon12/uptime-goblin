// The audit chain (lib/audit/chain.mjs, audit spec §4.2): canonical JSON, the hashed columns of
// row format 1, row hashes and checkpoint MACs. The vectors are pinned and never change: a row
// written by any release must keep its hash (they were checked against an independent
// implementation when they were pinned).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import {
  GENESIS,
  FORMATS,
  canonicalJSON,
  rowObject,
  rowHash,
  checkpointObject,
  checkpointMac,
} from '../../lib/audit/chain.mjs';

const mac = data => createHmac('sha256', Buffer.alloc(32, 7)).update(data).digest('hex');

// A fixed genesis row and a second row with a diff and Unicode text, as stored (prev_hash and
// hash are columns, but not hashed ones).
const genesisRow = {
  v: 1,
  seq: 1,
  time: 1759492800000,
  ref: null,
  actor_type: 'system',
  actor_id: null,
  actor_name: 'orbit',
  via: 'system',
  session_id: null,
  client_key: null,
  user_agent: null,
  request_id: null,
  action: 'system.start',
  target_type: 'orbit',
  target_id: null,
  target_name: null,
  outcome: 'info',
  status: null,
  count: 1,
  detail: { version: '1.5.0-dev.2', first: true, cleanStop: false },
  config_revision: 1,
  key_id: 'a1b2c3d4e5f6',
  prev_hash: GENESIS,
  hash: 'not hashed',
};
const secondRow = {
  v: 1,
  seq: 2,
  time: 1759492860000,
  ref: 1,
  actor_type: 'user',
  actor_id: 'u_admin',
  actor_name: 'admin',
  via: 'session',
  session_id: 's_AAAAAAAAAAAAAAAA',
  client_key: '192.0.2.10',
  user_agent: 'Mozilla/5.0 (Grüße ☃)',
  request_id: 'req-0001',
  action: 'settings.update',
  target_type: 'settings',
  target_id: 'workspace',
  target_name: null,
  outcome: 'ok',
  status: 200,
  count: 1,
  detail: {
    ifMatch: true,
    diff: [
      { path: 'title', from: 'Orbit', to: 'Grüße 🚀 "home"' },
      { path: 'email.password', change: 'changed' },
    ],
  },
  config_revision: 42,
  key_id: 'a1b2c3d4e5f6',
};
const vectors = {
  genesis: '7e807ac47d75b183f86b683823be16a5c33433d8c97a8c035c7f1a7f00e7014c',
  second: 'da35b384daa7ff4a51e8182575742dadb63d5f9b39ac8a6f966d1b967aa0096e',
  checkpoint: '1db2aeca940549aee12480eafcb3f09f2bc18358e3c0852225a8642447a13f98',
};

test('the pinned vectors: a genesis row, a row with a diff and Unicode text, and a checkpoint', () => {
  assert.equal(GENESIS, '0'.repeat(64));
  assert.equal(
    canonicalJSON(rowObject(genesisRow)),
    '{"action":"system.start","actor_id":null,"actor_name":"orbit","actor_type":"system","client_key":null,"config_revision":1,"count":1,"detail":{"cleanStop":false,"first":true,"version":"1.5.0-dev.2"},"key_id":"a1b2c3d4e5f6","outcome":"info","ref":null,"request_id":null,"seq":1,"session_id":null,"status":null,"target_id":null,"target_name":null,"target_type":"orbit","time":1759492800000,"user_agent":null,"v":1,"via":"system"}'
  );
  assert.equal(rowHash(mac, GENESIS, genesisRow), vectors.genesis);
  assert.equal(rowHash(mac, vectors.genesis, secondRow), vectors.second);
  // The previous hash is part of what is signed: the same row after another one differs.
  assert.notEqual(rowHash(mac, GENESIS, secondRow), vectors.second);
  const checkpoint = {
    instance: 'i_0123456789abcdef',
    seq: 2,
    time: 1759492860000,
    hash: vectors.second,
    reason: 'commit',
    key_id: 'a1b2c3d4e5f6',
  };
  assert.deepEqual(checkpointObject({ ...checkpoint, mac: 'ignored', extra: 1 }), {
    v: 1,
    kind: 'checkpoint',
    ...checkpoint,
  });
  assert.equal(checkpointMac(mac, checkpoint), vectors.checkpoint);
  assert.equal(
    checkpointMac(mac, { ...checkpoint, reason: 'prune' }) === vectors.checkpoint,
    false
  );
});

test('format 1 hashes v and the 21 stored columns, never prev_hash or hash; no other format exists', () => {
  assert.deepEqual(Object.keys(FORMATS), ['1']);
  assert.equal(FORMATS[1].length, 22);
  assert.equal(FORMATS[1][0], 'v');
  assert.ok(!FORMATS[1].includes('prev_hash') && !FORMATS[1].includes('hash'));
  assert.ok(Object.isFrozen(FORMATS) && Object.isFrozen(FORMATS[1]));
  // A missing column is hashed as null; anything that is not a column is left out.
  const object = rowObject({ v: 1, seq: 9, action: 'system.stop', extra: 'x', hash: 'h' });
  assert.deepEqual(Object.keys(object), FORMATS[1]);
  assert.equal(object.time, null);
  assert.equal(object.seq, 9);
  // A row written by a newer release: its columns are not known, so it cannot be hashed here.
  for (const v of [2, 0, '2', null, undefined, 'constructor', 'hasOwnProperty'])
    assert.throws(
      () => rowObject({ ...secondRow, v }),
      error => error instanceof RangeError && /not known to this release/.test(error.message),
      String(v)
    );
});

test('canonicalJSON: sorted keys at every depth, no spaces, safe integers and well-formed strings only', () => {
  assert.equal(
    canonicalJSON({ b: 1, a: { d: [3, { f: null, e: true }], c: 'x' } }),
    '{"a":{"c":"x","d":[3,{"e":true,"f":null}]},"b":1}'
  );
  // Keys sort by UTF-16 code units (as Array#sort does), not by code points.
  assert.equal(canonicalJSON({ '￿': 1, '\u{1f600}': 2, z: 3, Z: 4 }), '{"Z":4,"z":3,"😀":2,"￿":1}');
  // Undefined values are left out of objects, as JSON.stringify leaves them.
  assert.equal(canonicalJSON({ a: undefined, b: 2 }), '{"b":2}');
  assert.equal(canonicalJSON([]), '[]');
  assert.equal(canonicalJSON({}), '{}');
  assert.equal(canonicalJSON(-0), '0');
  assert.equal(canonicalJSON(Number.MAX_SAFE_INTEGER), '9007199254740991');
  assert.equal(canonicalJSON('line\nbreak "quoted"  '), JSON.stringify('line\nbreak "quoted"  '));
  assert.equal(canonicalJSON('🚀 a pair'), '"🚀 a pair"');
  for (const value of [1.5, Infinity, -Infinity, NaN, 2 ** 53, -(2 ** 53), { x: 0.1 }, [1e400]])
    assert.throws(() => canonicalJSON(value), /safe integers only/, String(value));
  // JSON.parse('{"x":1e400}') gives Infinity: such a stored detail cannot be hashed (D28).
  assert.throws(() => canonicalJSON(JSON.parse('{"x":1e400}')), TypeError);
  for (const value of ['\ud800', 'a\udc00b', { key: '\ud83d' }, ['\udfff']])
    assert.throws(() => canonicalJSON(value), /well-formed/, JSON.stringify(value));
  for (const value of [undefined, () => {}, Symbol('s'), 1n, [undefined]])
    assert.throws(() => canonicalJSON(value), TypeError, String(typeof value));
});

// A deviation from §4.2's text (recorded in lib/audit/chain.mjs): §4.2 wrote `[,1]` for a hole
// (not JSON, so json_valid failed the insert) and `{}` for a Date, Map or Buffer (a signed value
// other than the one recorded). Both are refused now; plain data hashes as before.
test('canonicalJSON refuses holes and objects that are not plain data', () => {
  for (const value of [[, 1], new Array(2), { list: [1, , 3] }])
    assert.throws(() => canonicalJSON(value), /cannot hold undefined/, JSON.stringify(value));
  class Row {
    constructor() {
      this.a = 1;
    }
  }
  for (const [value, kind] of [
    [new Date(0), 'Date'],
    [{ at: new Date(0) }, 'Date'],
    [new Map([['a', 1]]), 'Map'],
    [new Set([1]), 'Set'],
    [Buffer.from('ab'), 'Buffer'],
    [new Uint8Array(2), 'Uint8Array'],
    [new Row(), 'Row'],
    [[/x/], 'RegExp'],
  ])
    assert.throws(() => canonicalJSON(value), new RegExp(`cannot hold ${kind}$`), kind);
  // An object with no prototype (as node:sqlite returns rows) is plain data.
  const bare = Object.assign(Object.create(null), { b: [1, { c: null }], a: 'x' });
  assert.equal(canonicalJSON(bare), '{"a":"x","b":[1,{"c":null}]}');
  assert.equal(canonicalJSON(Object.freeze({ a: Object.freeze([1]) })), '{"a":[1]}');
});
