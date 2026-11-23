// CSV cells for the files Uptime Goblin hands to spreadsheets: the audit export (lib/audit/export.mjs,
// on the server) and the sampled-history export (public/modules/configure/exports.js, in the
// browser). Both put text a source controls into them (measurement keys, labels and units from
// an upstream API, collection errors), so they share this one rule: a value that starts like a
// formula (=HYPERLINK(…), +cmd, -1+2, @SUM(…), a tab or a carriage return) gets a leading
// apostrophe, which spreadsheets show as text and never run. The direction embeddings, overrides
// and isolates (U+202A to U+202E, U+2066 to U+2069), which lib/config.mjs refuses in a name, are
// removed first: they have no visible form, and a spreadsheet would show the rest of the cell in
// another order, so "Plex<U+202E>gnp.exe" read as "Plexexe.png". Removed before the guard, so one
// cannot hide a formula's leading character from it. The direction marks (U+061C, U+200E,
// U+200F) stay, as config keeps them in a name the admin saves: a right-to-left name may need one, and
// unlike an override a mark cannot turn letters round (it can only move numbers and punctuation
// beside it). The guard looks past any at the start, so they cannot hide a formula either.

/** One CSV cell: quoted, quotes doubled, without direction controls, after the formula guard. */
export const csvCell = value =>
  '"' +
  String(value ?? '')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/^[\u061c\u200e\u200f]*[=+@\-\t\r]/, "'$&")
    .replaceAll('"', '""') +
  '"';
