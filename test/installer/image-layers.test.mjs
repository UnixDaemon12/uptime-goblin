import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import { layerContains } from './image-layers.mjs';
import { temporary } from './helpers.mjs';
import { writeTar } from '../upgrade/tar.mjs';

const markers = ['shipped-control', 'synthetic-private-file', 'absent-control'].map(value =>
  Buffer.from(value)
);
const layer = writeTar([
  { path: 'app/public/readme', data: Buffer.from('shipped-control') },
  { path: 'app/private', data: Buffer.from('synthetic-private-file') },
]);
const encodings = {
  plain: bytes => bytes,
  gzip: bytes => zlib.gzipSync(bytes),
  zstd: bytes => zlib.zstdCompressSync(bytes),
};

function savedLayer(t, bytes) {
  const archive = path.join(temporary(t, 'orbit-layer-regression-'), 'image.tar');
  fs.writeFileSync(archive, writeTar([{ path: 'layer', data: bytes }]), { mode: 0o600 });
  return archive;
}

for (const [name, encode] of Object.entries(encodings)) {
  test(`${name} saved layers find shipped and excluded controls on the host tar`, async t => {
    assert.deepEqual(await layerContains(savedLayer(t, encode(layer)), 'layer', markers), [
      true,
      true,
      false,
    ]);
  });

  test(`${name} layer cut between complete entries is refused`, async t => {
    // One complete header and file, but neither the next entry nor the two end blocks.
    const cut = layer.subarray(0, 1024);
    await assert.rejects(
      layerContains(savedLayer(t, encode(cut)), 'layer', markers),
      /Image layer inspection failed:.*end-of-archive marker/
    );
  });

  test(`${name} zero-filled file content cannot stand in for tar end blocks`, async t => {
    const complete = writeTar([
      { path: 'first', data: Buffer.alloc(1536) },
      { path: 'second', data: markers[1] },
    ]);
    assert.deepEqual(await layerContains(savedLayer(t, encode(complete)), 'layer', markers), [
      false,
      true,
      false,
    ]);
    // Header + full first file. Its final 1024 bytes are zeros, but are not EOF headers.
    await assert.rejects(
      layerContains(savedLayer(t, encode(complete.subarray(0, 2048))), 'layer', markers),
      /Image layer inspection failed:[\s\S]*end-of-archive marker/
    );
  });
}

for (const [name, bytes] of Object.entries({
  'truncated gzip': zlib.gzipSync(layer).subarray(0, -12),
  'truncated zstd': zlib.zstdCompressSync(layer).subarray(0, -12),
  'truncated tar header': layer.subarray(0, 123),
  'only one tar end block': layer.subarray(0, -512),
  'misaligned tar ending': Buffer.concat([layer, Buffer.alloc(1)]),
  'nonzero bytes after tar ending': Buffer.concat([layer, Buffer.alloc(512, 0x58)]),
  'empty layer': Buffer.alloc(0),
  'garbage layer': Buffer.from('not a tar archive'),
  'invalid header with end blocks': Buffer.concat([Buffer.alloc(512, 0x58), Buffer.alloc(1024)]),
})) {
  test(`${name} fails instead of appearing to contain no secrets`, async t => {
    await assert.rejects(
      layerContains(savedLayer(t, bytes), 'layer', markers),
      /Image layer inspection failed:/
    );
  });
}

test('a zstd layer fails explicitly when the runtime decoder is unavailable', async t => {
  const bytes = zlib.zstdCompressSync(layer);
  const descriptor = Object.getOwnPropertyDescriptor(zlib, 'createZstdDecompress');
  Object.defineProperty(zlib, 'createZstdDecompress', { ...descriptor, value: undefined });
  try {
    await assert.rejects(
      layerContains(savedLayer(t, bytes), 'layer', markers),
      /Image layer inspection failed:[\s\S]*A zstd image layer needs Node\.js 22\.15\+/
    );
  } finally {
    Object.defineProperty(zlib, 'createZstdDecompress', descriptor);
  }
});

test('a missing layer and a missing saved image both fail', async t => {
  const archive = savedLayer(t, layer);
  await assert.rejects(
    layerContains(archive, 'missing', markers),
    /Image layer inspection failed:/
  );
  await assert.rejects(
    layerContains(archive + '.missing', 'layer', markers),
    /Image layer inspection failed:/
  );
});

test('a valid empty tar is inspected rather than rejected as an empty stream', async t => {
  assert.deepEqual(await layerContains(savedLayer(t, writeTar([])), 'layer', markers), [
    false,
    false,
    false,
  ]);
});

test('positive base-256 tar sizes preserve file framing', async t => {
  const bytes = writeTar([{ path: 'file', data: markers[0] }]);
  bytes.fill(0, 124, 136);
  bytes[124] = 0x80;
  bytes[135] = markers[0].length;
  bytes.fill(0x20, 148, 156);
  const checksum = bytes.subarray(0, 512).reduce((sum, byte) => sum + byte, 0);
  bytes.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  assert.deepEqual(await layerContains(savedLayer(t, bytes), 'layer', markers), [
    true,
    false,
    false,
  ]);
});

// Raw tar blocks for framing that writeTar does not write: pax, GNU and other entry types.
// sizeField replaces the 12-byte size field, raw writes bytes at header offsets, and checksum
// gives the 8-byte checksum field from the header's unsigned and signed byte sums.
const checksumField = ({ unsigned }) => unsigned.toString(8).padStart(6, '0') + '\0 ';
function tarHeader(
  name,
  size,
  type,
  {
    link = '',
    prefix = '',
    magic = 'ustar\u000000',
    sizeField,
    raw = {},
    checksum = checksumField,
  } = {}
) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write('0000644\0', 100, 'ascii');
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  header.write(sizeField ?? size.toString(8).padStart(11, '0') + '\0', 124, 12, 'latin1');
  header.write('07330604400\0', 136, 'ascii');
  header.fill(0x20, 148, 156);
  header.write(type, 156, 'latin1');
  header.write(link, 157, 100, 'utf8');
  header.write(magic, 257, 'latin1');
  header.write(prefix, 345, 155, 'utf8');
  for (const [at, bytes] of Object.entries(raw)) header.write(bytes, Number(at), 'latin1');
  const unsigned = header.reduce((sum, byte) => sum + byte, 0);
  const signed = header.reduce((sum, byte) => sum + (byte < 0x80 ? byte : byte - 0x100), 0);
  header.write(checksum({ unsigned, signed }), 148, 8, 'latin1');
  return header;
}
const gnu = { magic: 'ustar  \0' };
const shown = text => JSON.stringify(text).replace(/\\u0000/g, '\\0');
const padded = bytes => Buffer.concat([bytes, Buffer.alloc((512 - (bytes.length % 512)) % 512)]);
const zeros = length => Buffer.alloc(length);
// A pax record is "<length> <key>=<value>\n"; a string is written as given (for malformed ones).
function paxHeader(type, records) {
  const payload = records
    .map(record => {
      if (typeof record === 'string') return record;
      const body = Buffer.byteLength(` ${record[0]}=${record[1]}\n`);
      return `${body + String(body + String(body).length).length} ${record[0]}=${record[1]}\n`;
    })
    .join('');
  return [tarHeader('PaxHeader', Buffer.byteLength(payload), type), padded(Buffer.from(payload))];
}
const gnuLong = (type, name) => [
  tarHeader('././@LongLink', Buffer.byteLength(name) + 1, type, gnu),
  padded(Buffer.from(name + '\0')),
];
// The file after the construct under test, then the two end blocks.
const laterFile = writeTar([{ path: 'later', data: markers[1] }]);
// A file before it, without end blocks: bsdtar refuses an archive whose first header is damaged.
const leadFile = writeTar([{ path: 'lead', data: Buffer.from('lead') }]).subarray(0, -1024);

// A pax writer leaves the ustar size zero for a file of 8 GiB or more and stores the real size
// in a pax record. Read with the ustar size, a zero-filled payload looks like end blocks, so a
// layer cut right after that file was accepted and the complete layer was refused.
for (const [name, encode] of Object.entries(encodings)) {
  test(`${name} layer framed by a pax size record: complete is inspected, cut is refused`, async t => {
    const entry = [...paxHeader('x', [['size', 1536]]), tarHeader('zero', 0, '0'), zeros(1536)];
    const complete = Buffer.concat([...entry, laterFile]);
    assert.deepEqual(await layerContains(savedLayer(t, encode(complete)), 'layer', markers), [
      false,
      true,
      false,
    ]);
    await assert.rejects(
      layerContains(savedLayer(t, encode(Buffer.concat(entry))), 'layer', markers),
      /Image layer inspection failed:[\s\S]*end-of-archive marker/
    );
  });
}

// Headers that the scan framed differently from GNU tar or libarchive, so that one of them read
// the zero-filled data after the header as end blocks. Each was accepted: a complete layer could
// hide its later file from tar, or a layer cut after that data passed. Both are now refused.
const framedDifferently = {
  'a size field that starts with NULs': [
    [tarHeader('zero', 0, '0', { sizeField: '\0\0' + '0000003000' })],
    /invalid tar entry size/,
  ],
  'a GNU header with an old sparse map': [
    [tarHeader('zero', 1536, '0', { ...gnu, raw: { 386: '00000000000\0'.repeat(2) } })],
    /old GNU sparse fields set/,
  ],
  'a "ustarX" magic with the prefix "dir" and no name': [
    [tarHeader('', 1536, '0', { magic: 'ustarX00', prefix: 'dir' })],
    /unsupported tar header magic/,
  ],
  'a pax size record with two spaces after its length': [
    [...paxHeader('x', ['14  size=1536\n']), tarHeader('zero', 0, '0')],
    /malformed pax extended header record/,
  ],
  // bsdtar skips the header and exits 0; the zero-filled data then reads as end blocks.
  'a header whose checksum does not match, after another file': [
    [
      leadFile,
      tarHeader('zero', 1536, '0', {
        checksum: ({ unsigned }) => checksumField({ unsigned: unsigned + 1 }),
      }),
    ],
    /tar header checksum does not match/,
  ],
};
for (const [name, encode] of Object.entries(encodings)) {
  for (const [construct, [headers, refusal]] of Object.entries(framedDifferently)) {
    test(`${name} layer with ${construct} is refused, complete or cut`, async t => {
      const cut = Buffer.concat([...headers, zeros(1536)]);
      for (const bytes of [Buffer.concat([cut, laterFile]), cut])
        await assert.rejects(
          layerContains(savedLayer(t, encode(bytes)), 'layer', markers),
          new RegExp(`Image layer inspection failed:[\\s\\S]*${refusal.source}`)
        );
    });
  }
}

// Framing that GNU tar 1.34 and libarchive 3.7 read alike: the walker must agree with both.
for (const [name, entry] of Object.entries({
  "a Solaris 'X' size record": [...paxHeader('X', [['size', 1536]]), tarHeader('zero', 0, '0')],
  'a pax size record before a GNU long name': [
    ...paxHeader('x', [['size', 1536]]),
    ...gnuLong('L', 'long-zero'),
    tarHeader('zero', 0, '0', gnu),
  ],
  'a GNU long name before a pax size record': [
    ...gnuLong('L', 'long-zero'),
    ...paxHeader('x', [['size', 1536]]),
    tarHeader('zero', 0, '0'),
  ],
  'the last of two size records in one pax header': [
    ...paxHeader('x', [
      ['size', 512],
      ['size', 1536],
    ]),
    tarHeader('zero', 0, '0'),
  ],
  // Leading spaces, all twelve bytes as digits, or space and NUL after them: both read 1536.
  ...Object.fromEntries(
    [' 0000003000\0', '000000003000', '0000003000 \0', '       3000 '].map(field => [
      `the size field ${shown(field)}`,
      [tarHeader('zero', 0, '0', { sizeField: field })],
    ])
  ),
  'a ustar magic with a GNU-style version': [tarHeader('zero', 1536, '0', { magic: 'ustar\0 \0' })],
  // Neither tar joins the prefix field of a header without magic to its name.
  'an old-style header without magic and with bytes in the prefix field': [
    tarHeader('zero', 1536, '0', { magic: '\0'.repeat(8), prefix: 'dir/' }),
  ],
  // Both tars accept a checksum after a space, of seven digits, or summed with signed bytes.
  'a checksum after a space': [
    tarHeader('zero', 1536, '0', {
      checksum: ({ unsigned }) => ' ' + unsigned.toString(8).padStart(6, '0') + '\0',
    }),
  ],
  'a checksum of seven digits and a space': [
    tarHeader('zero', 1536, '0', {
      checksum: ({ unsigned }) => unsigned.toString(8).padStart(7, '0') + ' ',
    }),
  ],
  'a checksum summed with signed bytes': [
    tarHeader('z\u00e9ro', 1536, '0', {
      checksum: ({ signed }) => signed.toString(8).padStart(6, '0') + '\0 ',
    }),
  ],
})) {
  test(`${name} frames the next entry; a cut after it is refused`, async t => {
    const cut = Buffer.concat([...entry, zeros(1536)]);
    assert.deepEqual(
      await layerContains(savedLayer(t, Buffer.concat([cut, laterFile])), 'layer', markers),
      [false, true, false]
    );
    await assert.rejects(
      layerContains(savedLayer(t, cut), 'layer', markers),
      /Image layer inspection failed:[\s\S]*end-of-archive marker/
    );
  });
}

for (const [name, entry] of Object.entries({
  'a pax size of zero over a nonzero ustar size': [
    ...paxHeader('x', [['size', 0]]),
    tarHeader('empty', 1536, '0'),
  ],
  // Writers truncate a long path's ustar name; here the truncation ends in "/".
  'a long pax path whose ustar name ends in a slash': [
    ...paxHeader('x', [['path', 'p'.repeat(99) + '/file']]),
    tarHeader('p'.repeat(99) + '/', 1024, '0'),
    zeros(1024),
  ],
  'a GNU long name whose ustar name ends in a slash': [
    ...gnuLong('L', 'q'.repeat(99) + '/file'),
    tarHeader('q'.repeat(99) + '/', 1024, '0', gnu),
    zeros(1024),
  ],
  'header-only entries stored with size zero': [
    tarHeader('dir/', 0, '5'),
    tarHeader('dir/symlink', 0, '2', { link: 'later' }),
    tarHeader('dir/hardlink', 0, '1', { link: 'later' }),
    tarHeader('dir/fifo', 0, '6'),
    tarHeader('dir/old-style-dir/', 0, '0'),
    ...gnuLong('K', 'long-link-target'),
    ...gnuLong('L', 'dir/long-symlink'),
    tarHeader('dir/long-symlink', 0, '2', { ...gnu, link: 'long-link-target' }),
  ],
})) {
  test(`${name} is inspected`, async t => {
    assert.deepEqual(
      await layerContains(savedLayer(t, Buffer.concat([...entry, laterFile])), 'layer', markers),
      [false, true, false]
    );
  });
}

// Constructs that GNU tar and libarchive frame or name differently (or that no image writer
// uses) are refused: otherwise one tar can stop at zero-filled data, read as end blocks, and
// never reach the later file, while the walker accepts the layer.
const sized = (type, options) => [tarHeader(`entry-${type}`, 1024, type, options), zeros(1024)];
for (const [name, [entry, refusal]] of Object.entries({
  'a global pax header': [
    [...paxHeader('g', [['size', 0]]), tarHeader('zero', 1024, '0'), zeros(1024)],
    /unsupported global pax header/,
  ],
  'two pax headers for one entry': [
    [
      ...paxHeader('x', [['size', 1536]]),
      ...paxHeader('x', [['mtime', 1]]),
      tarHeader('zero', 0, '0'),
      zeros(1536),
    ],
    /more than one 'x' header for one tar entry/,
  ],
  'two GNU long names for one entry': [
    [...gnuLong('L', 'first'), ...gnuLong('L', 'second'), tarHeader('zero', 0, '0', gnu)],
    /more than one 'L' header for one tar entry/,
  ],
  ...Object.fromEntries(
    ['1', '2', '3', '4', '5', '6'].map(type => [
      `entry type ${type} with a nonzero size`,
      [sized(type, { link: 'later' }), new RegExp(`tar entry type ${type} has a nonzero size`)],
    ])
  ),
  'a hardlink with a pax size': [
    [
      ...paxHeader('x', [['size', 1024]]),
      tarHeader('hard', 0, '1', { link: 'later' }),
      zeros(1024),
    ],
    /tar entry type 1 has a nonzero size/,
  ],
  ...Object.fromEntries(
    ['S', 'V', 'M', 'D', 'Q'].map(type => [
      `entry type ${type}`,
      [sized(type, gnu), new RegExp(`unsupported tar entry type "${type}"`)],
    ])
  ),
  ...Object.fromEntries(
    Object.entries({
      'ustar name': [tarHeader('dir/', 1024, '0')],
      'ustar name of an old regular entry': [tarHeader('dir/', 1024, '\0')],
      'ustar prefix and empty name': [tarHeader('', 1024, '0', { prefix: 'dir' })],
      'GNU long name': [...gnuLong('L', 'dir/'), tarHeader('dir', 1024, '0', gnu)],
      'pax path': [...paxHeader('x', [['path', 'dir/']]), tarHeader('dir', 1024, '0')],
      // Both tars end the path at the NUL; libarchive then reads a directory without data.
      'pax path up to a NUL': [
        ...paxHeader('x', [['path', 'dir/\0x']]),
        tarHeader('dir', 1024, '0'),
      ],
    }).map(([source, headers]) => [
      `a file entry with data named as a directory by its ${source}`,
      [[...headers, zeros(1024)], /tar file entry named as a directory has data/],
    ])
  ),
  // GNU tar frames by GNU.sparse.size when no sparse map follows; libarchive does not.
  ...Object.fromEntries(
    [
      ['GNU.sparse.size', 0],
      ['GNU.sparse.realsize', 0],
      ['GNU.sparse.name', 'dir/'],
      ['GNU.sparse.major', 1],
      ['SUN.holesdata', '0 1024'],
      // libarchive extracts the file padded with zeros to this size, GNU tar ignores it.
      ['SCHILY.realsize', 1536],
    ].map(record => [
      `a pax ${record[0]} record`,
      [
        [...paxHeader('x', [record]), tarHeader('zero', 1024, '0'), zeros(1024)],
        /unsupported sparse tar entry/,
      ],
    ])
  ),
  ...Object.fromEntries(
    Object.entries({
      'NUL padding inside the payload': '13 size=1536\n\0\0\0',
      'a record length that overruns': '14 size=1536\n',
      'a record without "="': '12 size1536\n',
      'a record with an empty key': '8 =1536\n',
      'a record without a length': 'size=1536\n',
      // GNU tar skips the extra blanks and applies the size; libarchive reads the key " size".
      'two spaces after the length': '14  size=1536\n',
      'a space and a tab after the length': '14 \tsize=1536\n',
    }).map(([what, record]) => [
      `a pax header with ${what}`,
      [
        [...paxHeader('x', [record]), tarHeader('zero', 0, '0'), zeros(1536)],
        /malformed pax extended header record/,
      ],
    ])
  ),
  ...Object.fromEntries(
    ['', '15x', '-1', '+1', '9007199254740992'].map(value => [
      `a pax size of ${JSON.stringify(value)}`,
      [
        [...paxHeader('x', [['size', value]]), tarHeader('zero', 1536, '0'), zeros(1536)],
        /invalid pax size record/,
      ],
    ])
  ),
  'a pax header over 1 MiB': [
    [...paxHeader('x', [['comment', 'c'.repeat(1024 * 1024)]]), tarHeader('zero', 0, '0')],
    /tar 'x' extension header is too large/,
  ],
  ...Object.fromEntries(
    Object.entries({
      // GNU tar and libarchive both read zero; the scan used to read 1536.
      'two NULs before the digits': '\0\0' + '0000003000',
      'a space and a NUL before the digits': ' \0' + '000003000\0',
      // GNU tar skips the NUL (and the space) and reads 1536; libarchive reads zero.
      'a NUL before the digits': '\0' + '0000003000\0',
      'a NUL and a space before the digits': '\0 000003000\0',
      // libarchive reads zero and GNU tar fails; the scan's former 'ascii' decoding read "3000".
      'digits with the top bit set': '0000000\xb3\xb0\xb0\xb0\0',
      'a letter after the digits': '00000003000x',
      'no digits': '\0'.repeat(12),
    }).map(([what, field]) => [
      `a size field with ${what}`,
      [[tarHeader('zero', 0, '0', { sizeField: field }), zeros(1536)], /invalid tar entry size/],
    ])
  ),
  // libarchive reads old GNU sparse fields on any entry type (and frames the entry by a sparse
  // map), GNU tar only on type 'S'.
  ...Object.fromEntries(
    Object.entries({
      'an empty old sparse map': { 386: '00000000000\0'.repeat(2) },
      'an old sparse map with extension blocks': {
        386: '00000000000\0' + '00000003000\0',
        482: '\x01',
      },
      'an old real size': { 483: '00000003000\0' },
    }).map(([what, raw]) => [
      `a GNU file header with ${what}`,
      [[tarHeader('zero', 1536, '0', { ...gnu, raw }), zeros(1536)], /old GNU sparse fields set/],
    ])
  ),
  // libarchive reads the next header as the directory's sparse extension block.
  'a GNU directory header with an old sparse map and extension blocks': [
    [
      tarHeader('dir/', 0, '5', { ...gnu, raw: { 386: '00000000000\0'.repeat(2), 482: '\x01' } }),
      tarHeader('zero', 1536, '0'),
      zeros(1536),
    ],
    /old GNU sparse fields set/,
  ],
  // bsdtar skips a header whose checksum it does not accept, and exits 0.
  ...Object.fromEntries(
    Object.entries({
      'one more than the sum': ({ unsigned }) => checksumField({ unsigned: unsigned + 1 }),
      'only NULs': () => '\0'.repeat(8),
      // GNU tar skips the NUL and accepts the sum; libarchive reads zero.
      'a NUL before the digits': ({ unsigned }) =>
        '\0' + unsigned.toString(8).padStart(6, '0') + ' ',
      // GNU tar accepts it; libarchive refuses a byte other than a digit, space or NUL.
      'a letter after the digits': ({ unsigned }) => unsigned.toString(8).padStart(6, '0') + '\0x',
    }).map(([what, checksum]) => [
      `a header checksum with ${what}`,
      [
        [leadFile, tarHeader('zero', 1536, '0', { checksum }), zeros(1536)],
        /tar header checksum does not match/,
      ],
    ])
  ),
  // libarchive joins the prefix to the name for these magics ("dir/", a directory), GNU tar not.
  ...Object.fromEntries(
    ['ustarX00', 'ustar 00', 'ustar   '].map(magic => [
      `a header with the magic ${shown(magic)}`,
      [
        [tarHeader('', 1536, '0', { magic, prefix: 'dir' }), zeros(1536)],
        /unsupported tar header magic/,
      ],
    ])
  ),
})) {
  test(`${name} is refused`, async t => {
    await assert.rejects(
      layerContains(savedLayer(t, Buffer.concat([...entry, laterFile])), 'layer', markers),
      new RegExp(`Image layer inspection failed:[\\s\\S]*${refusal.source}`)
    );
  });
}

test('a pax header followed by the end blocks instead of its entry is refused', async t => {
  const archive = Buffer.concat([
    laterFile.subarray(0, -1024),
    ...paxHeader('x', [['mtime', 1]]),
    zeros(1024),
  ]);
  await assert.rejects(
    layerContains(savedLayer(t, archive), 'layer', markers),
    /Image layer inspection failed:[\s\S]*tar extension header without the entry it describes/
  );
});

// libarchive, the tar of macOS, read a file whose name starts with "._" as AppleDouble metadata
// for the next file: it neither extracted nor listed that file and exited 0, so the scan missed
// what the file held on macOS. GNU tar extracted it. A "._" file as the last entry, with no file
// after it, failed the scan on macOS instead ("Truncated tar archive"). writeTar orders the
// entries by path.
for (const [name, encode] of Object.entries(encodings)) {
  for (const [construct, files] of Object.entries({
    'a "._" file before the file it is named for': [
      ['app/public/._app.js', markers[1]],
      ['app/public/app.js', markers[0]],
    ],
    'a "._" file before a file it is not named for': [
      ['app/public/readme', markers[0]],
      ['._private', markers[1]],
    ],
    'a "._" file as the last entry': [
      ['app/public/readme', markers[0]],
      ['app/zz/._private', markers[1]],
    ],
  })) {
    test(`${name} layer with ${construct} is scanned`, async t => {
      const bytes = writeTar(files.map(([file, data]) => ({ path: file, data })));
      assert.deepEqual(await layerContains(savedLayer(t, encode(bytes)), 'layer', markers), [
        true,
        true,
        false,
      ]);
    });
  }
}

test('a layer stored under a "._" name in the saved image is read', async t => {
  const archive = path.join(temporary(t, 'orbit-layer-regression-'), 'image.tar');
  fs.writeFileSync(archive, writeTar([{ path: 'blobs/sha256/._layer', data: layer }]), {
    mode: 0o600,
  });
  assert.deepEqual(await layerContains(archive, 'blobs/sha256/._layer', markers), [
    true,
    true,
    false,
  ]);
});

// stand-in-tar runs the host tar but changes what it does with the layer (see that file). It is
// run with /bin/sh: a release archive keeps no executable bit on test files, so a stand-in found
// on PATH would be passed over there, and the real tar used instead. Its mode here is 0644 too.
const hostTar = spawnSync('/bin/sh', ['-c', 'command -v tar'], { encoding: 'utf8' }).stdout.trim();
const standIn = how => ({
  tar: ['/bin/sh', fileURLToPath(new URL('./stand-in-tar', import.meta.url)), hostTar, how],
});
const outcome = scan =>
  scan.then(
    found => `found ${JSON.stringify(found)}`,
    error => error.message
  );
// 15 bytes: the shipped control without the 22-byte private file.
const missingPrivateFile =
  "Image layer inspection failed: tar extracted 15 bytes, which differ from the layer's 37 bytes of file data";

// Any tar that leaves file data out of what it extracts and exits 0, as bsdtar did above, must
// fail the scan rather than pass it.
test('a tar that exits 0 without extracting all file data fails the scan', async t => {
  assert.ok(path.isAbsolute(hostTar), `tar must be on PATH, found ${JSON.stringify(hostTar)}`);
  assert.equal(
    await outcome(layerContains(savedLayer(t, layer), 'layer', markers, standIn('lossy'))),
    missingPrivateFile
  );
});

// tar exits once it has read a layer's end-of-archive headers (in 10 KiB records), leaving the
// rest of its input unread; the scan then failed to write the rest ("write EPIPE", or "Premature
// close" when tar exited first), now and then on real layers. The scan reads the whole layer
// itself, so where tar stops reading does not matter, only what it extracts. 4 MiB of padding
// after the end blocks makes the old failure certain with either tar; the stand-in stops right
// after them.
const withPadding = Buffer.concat([layer, Buffer.alloc(4 * 1024 * 1024)]);
for (const [name, encode] of Object.entries(encodings))
  test(`${name} layer whose tar stops reading at its end blocks is scanned`, async t => {
    const archive = savedLayer(t, encode(withPadding));
    const stopsAtEnd = standIn(`stops-at=${layer.length}`);
    assert.deepEqual(await layerContains(archive, 'layer', markers, stopsAtEnd), [
      true,
      true,
      false,
    ]);
    assert.deepEqual(await layerContains(archive, 'layer', markers), [true, true, false]);
  });

// The other side: a tar that stops reading before the private file, and exits 0 (both tars take
// an input that ends at a header as the end of the archive), still fails the scan.
test('a tar that stops reading before all file data and exits 0 fails the scan', async t => {
  const privateLast = writeTar([
    { path: 'app/public/readme', data: markers[0] },
    { path: 'app/z/private', data: markers[1] },
  ]);
  // 1024 bytes: the first file's header and data.
  const stopsEarly = standIn('stops-at=1024');
  assert.equal(
    await outcome(layerContains(savedLayer(t, privateLast), 'layer', markers, stopsEarly)),
    missingPrivateFile
  );
});
