// The history disk budget (1.4.2's, moved out of lib/store.mjs so every connection that writes
// history.sqlite applies the same one). History may grow until the filesystem has `reserve`
// bytes left: room for the WAL, config.json, control.sqlite and the rest of the host. SQLite
// enforces it. A writing connection's max_page_count is set to the pages the database has plus
// the pages that fit in the free space above the reserve, so a write that would pass it fails
// with SQLITE_FULL and the writer recycles the oldest history, then retries (lib/store.mjs
// #write, lib/series/v1.mjs writeRows).
//
// max_page_count belongs to one connection, so each writer keeps a budget over its own
// connection's `pages`:
//   get(name)     reads page_count, page_size, freelist_count or max_page_count
//   setMax(pages) sets max_page_count (SQLite never sets it below page_count)
//   checkpoint()  optional: a passive WAL checkpoint after large deletes
//
//   const budget = createDiskBudget({directory, pages});
//   budget.refresh();                  // at open, after large deletes, on SQLITE_FULL
//   budget.beforeWrite();              // before each write: refreshes once a minute
//   if (budget.grow()) retry();        // on SQLITE_FULL: did space freed on the host raise it?
//   budget.room(bytes);                // before optional work that needs disk (an index build)
//
// The object also serves as the `budget` option of the v1 series store.
import fs from 'node:fs';

/** Bytes a filesystem of `size` bytes keeps free: 5 %, at least 64 MiB and at most 1 GiB. */
export const reserveBytes = size => Math.min(2 ** 30, Math.max(2 ** 26, size * 0.05));
/** How often writes re-check free space, so the cap follows space other programs use or free. */
export const refreshMs = 60000;

/**
 * Free space above the reserve on `directory`'s filesystem, in bytes; undefined when the
 * filesystem does not report its size (then nothing can be budgeted).
 */
export function spareBytes(directory) {
  let stats;
  try {
    stats = fs.statfsSync(directory);
  } catch {
    return;
  }
  const unit = stats.frsize || stats.bsize;
  if (stats.blocks > 0 && unit > 0)
    return Math.max(0, stats.bavail * unit - reserveBytes(stats.blocks * unit));
}

/**
 * The budget of one connection to a history database in `directory`. `clock` gives
 * milliseconds for the refresh interval (monotonic; default performance.now()).
 */
export function createDiskBudget({
  directory,
  pages,
  clock = () => performance.now(),
  every = refreshMs,
} = {}) {
  if (typeof directory !== 'string' || !directory)
    throw new TypeError('A disk budget needs the directory of its database');
  if (typeof pages?.get !== 'function' || typeof pages?.setMax !== 'function')
    throw new TypeError('A disk budget needs its connection’s pages: get(name) and setMax(n)');
  let refreshedAt = -Infinity;
  // Caps the database below the filesystem's free space. Returns whether the cap grew.
  const refresh = () => {
    refreshedAt = clock();
    const spare = spareBytes(directory);
    if (spare === undefined) return false; // Size not reported: leave the cap.
    const cap = pages.get('page_count') + Math.floor(spare / pages.get('page_size')),
      before = pages.get('max_page_count');
    pages.setMax(cap);
    return cap > before;
  };
  return Object.freeze({
    directory,
    refresh,
    /** Free space above the reserve (bytes), or undefined. */
    spare: () => spareBytes(directory),
    /** Whether `bytes` more fit above the reserve. An unknown size cannot be budgeted either. */
    room(bytes) {
      const spare = spareBytes(directory);
      return spare === undefined || spare >= bytes;
    },
    /** Before a write: refreshes the cap when the last refresh is `every` ms old. */
    beforeWrite() {
      if (clock() - refreshedAt >= every) refresh();
    },
    /**
     * After SQLITE_FULL: whether space freed on the host raised the cap, so the same write
     * is worth trying again before any history is recycled.
     */
    grow: () => refresh(),
    /**
     * After large deletes: checkpoints the WAL (best effort; SQLite retries at later commits)
     * so freed pages are reused, then refreshes the cap.
     */
    afterDelete() {
      try {
        pages.checkpoint?.();
      } catch {}
      refresh();
    },
  });
}
