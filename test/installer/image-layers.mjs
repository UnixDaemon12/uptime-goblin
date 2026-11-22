// Saved-image layer inspection used by the Docker test and its offline regressions.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import zlib from 'node:zlib';

// How a saved layer is stored, from its first bytes: a plain tar, or gzip or zstd as the
// containerd image store saves it. bsdtar (macOS) decompresses a piped archive by itself, but
// GNU tar (Linux) refuses one ("Archive is compressed. Use -z option"), so the layer is
// decompressed here and tar always reads a plain archive.
function layerDecoders(head) {
  if (head[0] === 0x1f && head[1] === 0x8b) return [zlib.createGunzip()];
  if (head.length >= 4 && head.readUInt32LE(0) === 0xfd2fb528) {
    if (!zlib.createZstdDecompress) throw new Error('A zstd image layer needs Node.js 22.15+');
    return [zlib.createZstdDecompress()];
  }
  return [];
}

// An octal number field must be optional leading spaces, at least one digit, then only spaces
// or NULs. GNU tar skips one leading NUL, but libarchive stops at the first byte that is not a
// digit and reads such a field as zero, so a NUL or any other byte before or among the digits
// could give the two tars different values.
function octal(header, start, end) {
  const digits = /^ *([0-7]+)[ \0]*$/.exec(header.toString('latin1', start, end));
  return digits ? parseInt(digits[1], 8) : undefined;
}

// Tar sizes are octal or positive base-256 integers (after a 0x80 byte).
function tarSize(header) {
  const field = header.subarray(124, 136);
  if (field[0] === 0x80) {
    let size = 0n;
    for (const byte of field.subarray(1)) size = (size << 8n) | BigInt(byte);
    if (size > BigInt(Number.MAX_SAFE_INTEGER - 511)) throw new Error('tar entry is too large');
    return Number(size);
  }
  const size = octal(header, 124, 136);
  if (size === undefined) throw new Error('invalid tar entry size');
  return size;
}

// bsdtar (3.5.3 with libarchive 3.7.4 here) skips a header whose checksum does not match
// ("Damaged tar archive", "Retrying...") and still exits 0, reading the next block as a header,
// so a zero-filled block there ends its archive; GNU tar fails. The checksum is the sum of the
// header bytes with its own field counted as spaces; both tars accept it summed unsigned or signed.
function checkChecksum(header) {
  let unsigned = 0,
    signed = 0;
  for (let i = 0; i < 512; i++) {
    const byte = i >= 148 && i < 156 ? 0x20 : header[i];
    unsigned += byte;
    signed += byte < 0x80 ? byte : byte - 0x100;
  }
  const recorded = octal(header, 148, 156);
  if (recorded !== unsigned && recorded !== signed)
    throw new Error('tar header checksum does not match');
}

// POSIX pax records are "<length> <key>=<value>\n", where the length counts the whole record.
// GNU tar and libarchive both let a later record replace an earlier one with the same key.
// GNU tar skips any spaces and tabs after the length, libarchive only the first space, so a key
// that starts with either is refused: GNU tar would apply " size", libarchive would ignore it.
function paxRecords(payload) {
  const records = new Map();
  for (let at = 0; at < payload.length; ) {
    const space = payload.indexOf(0x20, at);
    const digits = payload.toString('latin1', at, Math.max(at, space));
    const end = at + Number(digits);
    const equals = payload.indexOf(0x3d, space);
    if (
      !/^[1-9][0-9]*$/.test(digits) ||
      end > payload.length ||
      payload[end - 1] !== 0x0a ||
      equals <= space + 1 ||
      equals >= end ||
      payload[space + 1] === 0x20 ||
      payload[space + 1] === 0x09
    )
      throw new Error('malformed pax extended header record');
    records.set(
      payload.toString('utf8', space + 1, equals),
      payload.toString('utf8', equals + 1, end - 1)
    );
    at = end;
  }
  return records;
}

// A decimal pax size replaces the entry's ustar size field, which pax writers leave zero for
// files of 8 GiB or more. An empty value is refused: libarchive reads it as zero, GNU fails.
function paxSize(value) {
  if (!/^[0-9]+$/.test(value) || Number(value) > Number.MAX_SAFE_INTEGER - 511)
    throw new Error('invalid pax size record');
  return Number(value);
}

// A NUL-terminated (or field-filling) string.
const cString = (bytes, start, end) => {
  const nul = bytes.subarray(start, end).indexOf(0);
  return bytes.toString('latin1', start, nul < 0 ? end : start + nul);
};

// libarchive reads a file entry whose name ends in "/" as an old-style directory without data,
// but GNU tar skips its data. The name is a pax path or GNU long name when present; otherwise
// the ustar name, joined to the ustar prefix. Writers truncate the ustar name of a long path,
// so that field alone may end in "/" when the real name does not. Both tars end a pax path at
// its first NUL, as they do a GNU long name.
function namedAsDirectory(header, extensions) {
  const long = [extensions.x?.get('path')?.split('\0')[0], extensions.L].filter(Boolean);
  if (long.length) return long.some(name => name.endsWith('/'));
  const name = cString(header, 0, 100);
  const prefix = header.toString('latin1', 257, 263) === 'ustar\0' ? cString(header, 345, 500) : '';
  return name.endsWith('/') || (prefix !== '' && name === '');
}

// The walker refuses the header forms that GNU tar 1.34 and libarchive 3.7 (bsdtar) were seen
// to frame differently, and some that no image writer uses: if tar framed one differently from
// the walker, it could stop at zero-filled data read as end blocks while later files went
// unscanned.
const fileTypes = new Set(['0', '\0', '7']);
const headerOnlyTypes = new Set(['1', '2', '3', '4', '5', '6']); // links, devices, directory, FIFO
const extensionSlots = { x: 'x', X: 'x', L: 'L', K: 'K' };
const extensionLimit = 1024 * 1024;

// The two tars read sparse-file pax records differently: GNU tar frames an entry by
// GNU.sparse.size when no sparse map follows, libarchive does not; libarchive parses
// SUN.holesdata, and extracts a file padded with zeros to its SCHILY.realsize; GNU tar ignores
// both. Docker image layers hold none.
const sparseKey = key =>
  key.startsWith('GNU.sparse.') || key === 'SUN.holesdata' || key === 'SCHILY.realsize';

// A header is ustar ("ustar\0", whose prefix extends the name), GNU ("ustar  \0") or old-style
// (no magic). libarchive also joins the prefix for any other magic that starts with "ustar",
// GNU tar does not, so such a header is refused. In a GNU header, libarchive applies an old
// sparse map (and reads its extension blocks) on any entry type, GNU tar only on type 'S'.
// Writers leave that area (map, extension flag, real size) zero on other types, so any byte
// set there is refused.
function checkHeaderFormat(header) {
  const magic = header.toString('latin1', 257, 265);
  if (magic === 'ustar  \0') {
    if (header.subarray(386, 495).some(byte => byte !== 0))
      throw new Error('old GNU sparse fields set in a tar header');
  } else if (magic.startsWith('ustar') && !magic.startsWith('ustar\0'))
    throw new Error(`unsupported tar header magic ${JSON.stringify(magic)}`);
}

function entrySize(header, extensions) {
  const type = String.fromCharCode(header[156]);
  if ([...(extensions.x?.keys() ?? [])].some(sparseKey))
    throw new Error('unsupported sparse tar entry (pax sparse records)');
  const ustarSize = tarSize(header);
  const size = extensions.x?.has('size') ? paxSize(extensions.x.get('size')) : ustarSize;
  if (headerOnlyTypes.has(type)) {
    // Both tars ignore the ustar size of a hardlink or directory, and only GNU tar skips data
    // after a symlink, device or FIFO. Real writers store zero for all of them.
    if (size) throw new Error(`tar entry type ${type} has a nonzero size`);
    return 0;
  }
  if (!fileTypes.has(type)) throw new Error(`unsupported tar entry type ${JSON.stringify(type)}`);
  if (size && namedAsDirectory(header, extensions))
    throw new Error('tar file entry named as a directory has data');
  return size;
}

// Require two zero HEADER blocks, not merely zero bytes at the end: a file's payload can
// itself end in zeros. Node's zstd decoder and tar may accept a stream cut between entries.
// Walk the framing without storing file payloads so that such a cut cannot hide later files.
// Extension headers precede their entry: a pax 'x' (or Solaris 'X') header can set its size
// and name, and GNU 'L'/'K' headers carry its long name or link; their payloads are read.
// Every file's data goes, in order, to fileData, to be compared with what tar extracts.
async function* wholeTar(chunks, fileData) {
  const header = Buffer.alloc(512);
  let used = 0,
    data = 0, // file data left in the current entry
    skip = 0, // padding up to the next 512-byte block
    endBlocks = 0,
    reading = null, // the extension header whose payload is being read
    extensions = {}; // extension headers read for the next entry
  const extensionRead = () => {
    const { slot, payload } = reading;
    if (slot === 'x') extensions.x = paxRecords(payload);
    else if (slot === 'L') extensions.L = cString(payload, 0, payload.length);
    else extensions.K = true;
    skip = (512 - (payload.length % 512)) % 512;
    reading = null;
  };
  for await (const chunk of chunks) {
    let at = 0;
    while (at < chunk.length) {
      if (reading) {
        const length = Math.min(reading.payload.length - reading.read, chunk.length - at);
        chunk.copy(reading.payload, reading.read, at, at + length);
        reading.read += length;
        at += length;
        if (reading.read === reading.payload.length) extensionRead();
        continue;
      }
      if (data) {
        const length = Math.min(data, chunk.length - at);
        fileData.update(chunk.subarray(at, at + length));
        data -= length;
        at += length;
        continue;
      }
      if (skip) {
        const length = Math.min(skip, chunk.length - at);
        skip -= length;
        at += length;
        continue;
      }
      const length = Math.min(512 - used, chunk.length - at);
      chunk.copy(header, used, at, at + length);
      at += length;
      used += length;
      if (used !== 512) continue;
      used = 0;
      if (header.every(byte => byte === 0)) {
        if (Object.keys(extensions).length)
          throw new Error('tar extension header without the entry it describes');
        endBlocks++;
        continue;
      }
      if (endBlocks) throw new Error('nonzero header after the tar end-of-archive marker');
      checkChecksum(header);
      checkHeaderFormat(header);
      const type = String.fromCharCode(header[156]);
      if (type === 'g')
        throw new Error(
          'unsupported global pax header (GNU tar applies it to later entries, libarchive ignores it)'
        );
      const slot = extensionSlots[type];
      if (!slot) {
        data = entrySize(header, extensions);
        skip = (512 - (data % 512)) % 512;
        extensions = {};
        continue;
      }
      if (slot in extensions) throw new Error(`more than one '${type}' header for one tar entry`);
      const size = tarSize(header);
      if (size > extensionLimit) throw new Error(`tar '${type}' extension header is too large`);
      reading = { slot, payload: Buffer.alloc(size), read: 0 };
      if (!size) extensionRead();
    }
    yield chunk;
  }
  if (used || data || skip || reading || endBlocks < 2)
    throw new Error('the layer ends without the end-of-archive marker (truncated?)');
}

// libarchive (bsdtar, the tar of macOS) reads a file whose name starts with "._" as AppleDouble
// metadata for the next file, as macOS writes it, so it never extracts or lists that file and
// still exits 0 (bsdtar 3.5.3, libarchive 3.7.4). Its option "!mac-ext" reads such a file like
// any other. GNU tar has neither that reading nor --options. `tar` is the command as
// layerContains takes it: the program, then any arguments that come first.
const readOptions = new Map();
function tarReadOptions([program, ...first]) {
  const key = JSON.stringify([program, ...first]);
  if (!readOptions.has(key)) {
    const { stdout } = spawnSync(program, [...first, '--version'], {
      encoding: 'utf8',
      timeout: 30000,
    });
    readOptions.set(key, /\bbsdtar\b/.test(stdout ?? '') ? ['--options', '!mac-ext'] : []);
  }
  return readOptions.get(key);
}

// Where the walked layer goes: the inner tar's standard input. tar exits once it has read the
// end-of-archive headers, without reading the rest of its input (both tars here read it in 10 KiB
// records), and Node destroys a child's stdin when the child exits. Writing what was left, such
// as padding after those headers, then failed ("write EPIPE"), or the pipe closed before its end
// ("Premature close", even with nothing left to write), and a valid layer failed the scan now and
// then, with either tar. That alone says nothing about the layer, so it no longer stops the walk:
// the walker still reads and checks the whole layer, and tar's exit status and the byte-for-byte
// comparison in layerContains decide. A tar that stopped before all the file data was out fails
// that comparison.
const toTar = stdin =>
  new Writable({
    write(chunk, _encoding, next) {
      if (stdin.destroyed) next();
      else stdin.write(chunk, () => next());
    },
    final(next) {
      if (stdin.destroyed) next();
      else stdin.end(() => next());
    },
  });

// A running SHA-256 digest of a byte stream, and its length.
function runningDigest() {
  const hash = createHash('sha256');
  return {
    bytes: 0,
    update(chunk) {
      hash.update(chunk);
      this.bytes += chunk.length;
    },
    digest: () => hash.digest(),
  };
}

// Inspect every layer, including files removed by a later layer. tar streams the nested
// archive without unpacking the image or buffering it in RAM. A tar that reads an entry as
// something else may leave its data out and still exit 0, as bsdtar did with "._" files, so
// tar's output must be exactly the file data the walker framed, in order. `tar` is the tar on
// PATH unless a test passes a stand-in, as [program, ...arguments that come first].
export async function layerContains(archive, layer, markers, { tar = ['tar'] } = {}) {
  const [program, ...first] = tar;
  const options = [...first, ...tarReadOptions(tar)];
  const outer = spawn(program, [...options, '-xOf', archive, '--', layer], { timeout: 120000 });
  const inner = spawn(program, [...options, '-xOf', '-'], { timeout: 120000 });
  const framed = runningDigest(),
    extracted = runningDigest();
  const completed = child =>
    new Promise((resolve, reject) => {
      let stderr = '';
      child.stderr.on('data', chunk => (stderr = (stderr + chunk).slice(-4096)));
      child.once('error', reject);
      child.once('close', (code, signal) =>
        code === 0 ? resolve() : reject(new Error(stderr.trim() || `tar: ${signal ?? code}`))
      );
    });
  const steps = [completed(inner), completed(outer)];
  // A tar that stops reading makes a write fail; toTar carries on without it (see there).
  inner.stdin.on('error', () => {});
  steps.push(
    (async () => {
      const stored = outer.stdout[Symbol.asyncIterator]();
      try {
        let head = Buffer.alloc(0);
        for (let next; head.length < 4 && !(next = await stored.next()).done; )
          head = Buffer.concat([head, next.value]);
        const layerBytes = async function* () {
          if (head.length) yield head;
          for (let next; !(next = await stored.next()).done; ) yield next.value;
        };
        await pipeline(
          Readable.from(layerBytes(), { objectMode: false }),
          ...layerDecoders(head),
          chunks => wholeTar(chunks, framed),
          toTar(inner.stdin)
        );
      } catch (error) {
        inner.stdin.destroy();
        throw error;
      } finally {
        // Ends the outer tar too if the inner one stopped reading.
        await stored.return();
      }
    })()
  );
  const found = markers.map(() => false);
  const overlap = Math.max(...markers.map(marker => marker.length)) - 1;
  let tail = Buffer.alloc(0);
  steps.push(
    (async () => {
      for await (const chunk of inner.stdout) {
        extracted.update(chunk);
        const bytes = Buffer.concat([tail, chunk]);
        markers.forEach((marker, i) => (found[i] ||= bytes.includes(marker)));
        tail = bytes.subarray(Math.max(0, bytes.length - overlap));
      }
    })()
  );
  try {
    // Every failure is reported: a decompression error explains the inner tar's.
    const failures = (await Promise.allSettled(steps)).filter(step => step.status === 'rejected');
    if (failures.length)
      throw new Error(
        `Image layer inspection failed: ${failures.map(step => step.reason.message).join('; ')}`
      );
    if (!framed.digest().equals(extracted.digest()))
      throw new Error(
        `Image layer inspection failed: tar extracted ${extracted.bytes} bytes, which differ ` +
          `from the layer's ${framed.bytes} bytes of file data`
      );
    return found;
  } finally {
    outer.kill();
    inner.kill();
  }
}
