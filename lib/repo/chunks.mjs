// Chunked deletes for retention and erasure (the Store's #drain, over a Db). Each chunk is its
// own short transaction and the event loop runs between chunks, so deleting days of history
// or a large source neither needs much WAL space (one large DELETE needs room for every page
// it touches, which a nearly full disk may not have) nor stalls collection and HTTP for
// seconds. Chunks start at a tenth of `max` and adapt to row size (a Proxmox reading can be
// 40 KB), so each step stays near `stepMs`.
import { setImmediate as nextTurn } from 'node:timers/promises';
import { classOf } from './errors.mjs';

export const chunkRows = 1000;
export const stepMs = 50;

/**
 * Runs `statement(limit)` (a DELETE of at most `limit` rows) until a chunk deletes less than
 * its limit, `signal` aborts, or the database closes (then it stops quietly and leaves the
 * rest for the next run). Returns the rows deleted.
 */
export async function drainChunks(
  db,
  statement,
  { signal, dialect = db.dialect, max = chunkRows, clock = () => performance.now() } = {}
) {
  let limit = Math.max(1, Math.round(max / 10)),
    deleted = 0;
  while (!signal?.aborted) {
    const started = clock();
    let changes;
    try {
      changes = await db.write(tx => tx.run(statement(limit)).changes);
    } catch (error) {
      if (classOf(error, dialect) === 'unavailable') return deleted;
      throw error;
    }
    deleted += changes;
    if (changes < limit) return deleted;
    const took = Math.max(1, clock() - started);
    limit = Math.max(10, Math.min(max, Math.round((limit * stepMs) / took)));
    await nextTurn();
  }
  return deleted;
}
