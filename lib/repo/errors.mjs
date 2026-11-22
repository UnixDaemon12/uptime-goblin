// Errors at the repository boundary (roadmap §10.4). Every failure a repository or unit of work
// passes on is a RepoError whose `class` is one of the dialect error classes, so callers decide
// what to do from the class alone, whatever the engine:
//
//   retry        a transient conflict (SQLITE_BUSY, PostgreSQL 40001/40P01, SQL Server 1205/1222);
//                the Db already retried it (up to 3 times with jitter) before it arrives here
//   unique       a key that already exists
//   fenced       this node lost its lease; stop the work, never retry it
//   full         the disk or a partition is full (503 plus the storage alert)
//   unavailable  the database cannot be reached or is closing (503)
//   timeout      a statement or lock timed out, or the work was aborted (503)
//   poison       a value no engine can store; the row is rejected and counted (422), never retried
//   fatal        a programming error or damaged data (500)
import { ERROR_CLASSES } from '../db/sql.mjs';

export { ERROR_CLASSES };

/** The HTTP status each class answers with when a request meets it. */
export const statusFor = Object.freeze({
  retry: 503,
  unique: 409,
  fenced: 503,
  full: 503,
  unavailable: 503,
  timeout: 503,
  poison: 422,
  fatal: 500,
});

export class RepoError extends Error {
  /**
   * `errorClass` is one of ERROR_CLASSES (anything else is `fatal`). `details` may name the
   * `unit` of work and the `store` class the error came from, and carry the original `cause`.
   */
  constructor(errorClass, message, details = {}) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.name = 'RepoError';
    this.class = ERROR_CLASSES.includes(errorClass) ? errorClass : 'fatal';
    if (details.unit) this.unit = details.unit;
    if (details.store) this.store = details.store;
  }
  /** Whether the caller may try the same work again later (not now: the Db already retried). */
  get transient() {
    return ['retry', 'full', 'unavailable', 'timeout'].includes(this.class);
  }
  get status() {
    return statusFor[this.class];
  }
}

/**
 * The class of any error: its own `class` when it carries a valid one (errors from a Db and
 * from lib/db/sql.mjs do), otherwise what `dialect.classify` says (for errors raised by a
 * driver directly, as lib/store.mjs's connection does), otherwise `fatal`.
 */
export function classOf(error, dialect) {
  if (ERROR_CLASSES.includes(error?.class)) return error.class;
  if (dialect?.classify) {
    const found = dialect.classify(error);
    if (ERROR_CLASSES.includes(found)) return found;
  }
  return 'fatal';
}

/**
 * `error` as a RepoError, keeping the original as `cause`. A RepoError passes unchanged unless
 * it lacks the unit or store named here.
 */
export function toRepoError(error, { unit, store, dialect } = {}) {
  if (error instanceof RepoError) {
    if ((unit && !error.unit) || (store && !error.store))
      return new RepoError(error.class, error.message, {
        unit: error.unit ?? unit,
        store: error.store ?? store,
        cause: error.cause ?? error,
      });
    return error;
  }
  const errorClass = classOf(error, dialect),
    where = unit ? ` in ${unit}` : store ? ` in the ${store} store` : '';
  return new RepoError(errorClass, `${describe(errorClass)}${where}: ${message(error)}`, {
    unit,
    store,
    cause: error,
  });
}

const describe = errorClass =>
  ({
    retry: 'A write kept conflicting with another',
    unique: 'A record with this key already exists',
    fenced: 'This node no longer holds the lease',
    full: 'The database is full',
    unavailable: 'The database is unavailable',
    timeout: 'The database did not answer in time',
    poison: 'A value cannot be stored',
    fatal: 'A database operation failed',
  })[errorClass];

const message = error =>
  String(error?.message ?? error)
    .split('\n')[0]
    .slice(0, 300);
