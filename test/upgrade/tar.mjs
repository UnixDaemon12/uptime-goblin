// Minimal ustar reader and writer for the upgrade fixtures: no dependency and no system tar,
// so fixtures build the same on every host and extract offline.
import zlib from 'node:zlib';

const BLOCK = 512;
const text = (block, start, length) => {
  const field = block.subarray(start, start + length),
    end = field.indexOf(0);
  return field.subarray(0, end === -1 ? length : end).toString('utf8');
};
const octal = (block, start, length) => {
  const value = text(block, start, length).trim();
  if (!/^[0-7]*$/.test(value)) throw new Error('Invalid tar header number');
  return value ? parseInt(value, 8) : 0;
};
// Paths must stay inside the extraction directory: relative, no '..', no empty segments.
export function safePath(name) {
  const clean = name.replace(/^\.\//, '').replace(/\/$/, '');
  if (
    !clean ||
    clean.startsWith('/') ||
    clean.includes('\\') ||
    clean.includes('\0') ||
    clean.split('/').some(part => part === '' || part === '.' || part === '..')
  )
    throw new Error(`Unsafe path in tar archive: ${JSON.stringify(name)}`);
  return clean;
}
function paxRecords(data) {
  const records = {};
  let at = 0;
  while (at < data.length) {
    const space = data.indexOf(0x20, at);
    if (space === -1) throw new Error('Invalid pax header');
    const length = Number(data.subarray(at, space).toString('ascii'));
    if (!Number.isSafeInteger(length) || length <= 0) throw new Error('Invalid pax header');
    const record = data.subarray(space + 1, at + length - 1).toString('utf8'),
      equals = record.indexOf('=');
    records[record.slice(0, equals)] = record.slice(equals + 1);
    at += length;
  }
  return records;
}
/**
 * Returns the regular files of a (gzipped) tar archive as [{path, mode, data}], in archive
 * order. Directories are implied by paths. Links and devices are refused, as are paths that
 * would leave the extraction directory.
 */
export function readTar(archive) {
  const bytes =
    archive[0] === 0x1f && archive[1] === 0x8b ? zlib.gunzipSync(archive) : Buffer.from(archive);
  const files = [];
  let at = 0,
    longName = null,
    pax = {};
  while (at + BLOCK <= bytes.length) {
    const header = bytes.subarray(at, at + BLOCK);
    if (header.every(byte => byte === 0)) break;
    let checksum = 0;
    for (let i = 0; i < BLOCK; i++) checksum += i >= 148 && i < 156 ? 0x20 : header[i];
    if (checksum !== octal(header, 148, 8)) throw new Error('Tar header checksum mismatch');
    const size = octal(header, 124, 12),
      type = String.fromCharCode(header[156] || 0x30),
      prefix = text(header, 257, 7) === 'ustar' ? text(header, 345, 155) : '',
      data = bytes.subarray(at + BLOCK, at + BLOCK + size);
    if (data.length !== size) throw new Error('Truncated tar archive');
    at += BLOCK + Math.ceil(size / BLOCK) * BLOCK;
    if (type === 'x') {
      pax = paxRecords(data);
      continue;
    }
    if (type === 'g') continue;
    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0+$/, '');
      continue;
    }
    const name = pax.path ?? longName ?? (prefix ? prefix + '/' : '') + text(header, 0, 100);
    longName = null;
    pax = {};
    if (type === '5') continue;
    if (type !== '0') throw new Error(`Unsupported tar entry type ${type} for ${name}`);
    files.push({ path: safePath(name), mode: octal(header, 100, 8), data: Buffer.from(data) });
  }
  return files;
}
function field(header, start, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > length) throw new Error(`Tar field too long: ${value}`);
  bytes.copy(header, start);
}
const number = (value, length) => value.toString(8).padStart(length - 1, '0');
/**
 * Writes [{path, data, mode?}] as an uncompressed ustar archive, sorted by path, with fixed
 * owner, time and modes, so the same files always give the same bytes.
 */
export function writeTar(files) {
  const blocks = [];
  for (const file of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    const name = safePath(file.path),
      header = Buffer.alloc(BLOCK);
    let prefix = '',
      rest = name;
    if (Buffer.byteLength(name) > 100) {
      const cut = name.lastIndexOf('/', 155);
      prefix = name.slice(0, cut);
      rest = name.slice(cut + 1);
    }
    field(header, 0, 100, rest);
    field(header, 100, 8, number(file.mode ?? 0o644, 8));
    field(header, 108, 8, number(0, 8));
    field(header, 116, 8, number(0, 8));
    field(header, 124, 12, number(file.data.length, 12));
    // 2000-01-01T00:00:00Z: a fixed time, so rebuilding a fixture does not change it.
    field(header, 136, 12, number(946684800, 12));
    header.fill(0x20, 148, 156);
    header[156] = 0x30;
    field(header, 257, 6, 'ustar');
    field(header, 263, 2, '00');
    field(header, 345, 155, prefix);
    let checksum = 0;
    for (const byte of header) checksum += byte;
    field(header, 148, 8, number(checksum, 7) + '\0');
    blocks.push(header, file.data, Buffer.alloc((BLOCK - (file.data.length % BLOCK)) % BLOCK));
  }
  blocks.push(Buffer.alloc(BLOCK * 2));
  return Buffer.concat(blocks);
}
// gzip with a fixed header: no time, maximum compression, and the "unknown" OS byte, which
// zlib otherwise sets per platform.
export function gzip(bytes) {
  const out = zlib.gzipSync(bytes, { level: 9 });
  out[9] = 0xff;
  return out;
}
