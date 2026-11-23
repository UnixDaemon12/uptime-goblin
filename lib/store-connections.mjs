// The switch that lets tests read a Store's raw connection (store.db, lib/store.mjs). A module of
// its own, which scripts/import-graph.mjs lets only lib/store.mjs import among the shipped
// server modules: an export of lib/store.mjs itself could be reached by any route, under a name
// the lint cannot see (a namespace import read as S['exposeStoreConnections']). test/setup.mjs
// and scripts/gen-dataset.mjs, which are never shipped, turn it on.
let exposed = false;

/** For test/setup.mjs and scripts/gen-dataset.mjs only: store.db returns the connection. */
export function exposeStoreConnections() {
  exposed = true;
}

/** Whether exposeStoreConnections() was called in this process. */
export const storeConnectionsExposed = () => exposed;
