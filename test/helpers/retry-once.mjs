// Makes a write callback run twice, the way SQLITE_BUSY at COMMIT does (audit spec §2.1 item 16,
// §9): the callback runs to its end, then the attempt throws an error of class `retry`, so the
// real Db rolls the attempt back and runs the callback again. A lock held by a second
// connection cannot do this: BEGIN IMMEDIATE waits out the busy timeout before the callback
// runs, so the callback never runs twice that way.
//
//   const db = retryOnce(control.db);            // each write() unit's first attempt is retried
//   await db.write(tx => { …; tx.onCommit(…) });
//
// `times` (default 1) is how many attempts of each write() are thrown away; it must stay below
// the Db's `retries` (3 by default), or the write fails with the injected error. Everything
// else (read, dialect, name, close…) is the Db's own. This file is a Phase 0 contract (frozen).

/** A Db whose write units each run their callback `times` extra times (see above). */
export function retryOnce(db, { times = 1 } = {}) {
  if (!Number.isInteger(times) || times < 0) throw new TypeError('times must be 0 or more');
  const write = (fn, options) => {
    let left = times;
    return db.write(tx => {
      const result = fn(tx);
      if (left > 0) {
        left -= 1;
        throw Object.assign(new Error('injected retry'), { class: 'retry' });
      }
      return result;
    }, options);
  };
  return new Proxy(db, {
    get(target, key) {
      if (key === 'write') return write;
      const value = Reflect.get(target, key, target);
      // The Db's methods use private fields, so they run on the Db itself.
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
