// Verification of the audit log (audit spec §6.4), shared by GET /api/audit/verify (through
// createAudit().verify) and `goblin-admin verify-audit`. It walks the chain once, oldest first,
// and reports the first broken entry by seq, every anchor (restores, upgrades, gaps, key resets)
// and what could not be checked:
//
//   1. the first row starts the log (prev_hash GENESIS at seq 1) or follows a stored prune
//      checkpoint; 2. every row follows the one before (a seq jump only for an audit.gap row);
//   3. every row's hash, under the key id it names: a kid the keyring does not hold is a break
//      (key_lost) unless a signed key.reset row lists it and covers that seq; a format this
//      release does not know is unverifiable (newer_format), its links still checked;
//   4. the stored prune checkpoints; 5. the newest row is the head; 6. a head-mismatch gap row is
//      log_truncated; 7. the journal lines (goblin-admin --checkpoints): each must be signed by
//      this Uptime Goblin and name a row the log holds, unless a restore anchored after it was printed or
//      a prune removed what it names; a line under a key the keyring does not hold (and no reset
//      removed, nor a prune covers) cannot be checked, so it leaves the result incomplete
//      (unknown_key).
//
// Only stored checkpoints whose reason is `prune` are read (review round 1): a commit line copied
// from the journal into the table explains nothing. The prune itself runs steps 1–4 over the rows
// it would remove before it signs anything (checkPrune).
//
// Codex review A1: Uptime Goblin numbers its entries from 1 (D27), so a stored row whose seq is 0 or
// below is never one of its entries: it was inserted or renumbered by someone with the database.
// The first unit reads the lowest and highest stored seq of the whole table (auditOps.first and
// last), and the walk starts at the lowest stored row, not after 0, so every stored row is read.
// A row outside 1…Number.MAX_SAFE_INTEGER is link_broken at its own seq (one beyond the safe range
// cannot be read at all: unreadable, D28) and takes no part in the chain: the rows from seq 1 on
// are checked as if it were not there. Without this, rows at seq 0 or -1 were listed and exported
// while both modes, against every genuine journal line, read intact.
//
// The check reads in units of VERIFY_CHUNK rows with the event loop running between them (the
// route), or in one read unit (the CLI). Everything is checked up to the newest row taken in the
// first unit, so rows appended meanwhile are outside the check and never mistaken for a cut end.
// A read that throws ERR_OUT_OF_RANGE (an integer beyond the safe range: class poison) ends the
// check as `unreadable`, broken, at the first seq of the unit that failed (D28). The texts never
// carry a stored value as it is: see fill().
import { setImmediate as nextTurn } from 'node:timers/promises';
import {
  ANCHOR_TEXTS,
  PROBLEM_TEXTS,
  UNVERIFIABLE_TEXTS,
  VERIFY_CHUNK,
  auditTime,
} from './actions.mjs';
import { FORMATS, GENESIS, canonicalJSON, checkpointMac, rowHash } from './chain.mjs';
import { auditOps } from '../repo/audit.mjs';

/** The codes that make the log broken (§6.4), in no particular order. */
export const BROKEN = Object.freeze([
  'start_missing',
  'link_broken',
  'seq_gap',
  'hash_mismatch',
  'head_mismatch',
  'checkpoint_mismatch',
  'checkpoint_mac',
  'journal_mismatch',
  'journal_ahead',
  'log_truncated',
  'key_lost',
  'unreadable',
]);
const anchorActions = new Set(['system.restore', 'system.upgrade', 'audit.gap', 'key.reset']);
// Codex review A1: the seqs Uptime Goblin gives its entries (D27: from 1; the canonical JSON that signs a
// row holds safe integers only).
const ownSeq = seq => Number.isSafeInteger(seq) && seq >= 1;
const unknownKid = error => error?.code === 'seal_unknown_key';
const outOfRange = error => error?.code === 'ERR_OUT_OF_RANGE' || error?.class === 'poison';

// ---------------------------------------------------------------------------------------------
// Texts (§7.1): shared by the API's problem and the CLI's lines.

/** A number as the texts write it: thousands separators, without Intl (the same everywhere). */
export const grouped = n =>
  Number.isSafeInteger(n) ? String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',') : String(n);

// Fills {name} placeholders: numbers grouped, *Time and at values as auditTime(). `nulls` gives
// what "#{name}" (with the "entry " before it, when there is one) reads when a value is null.
// Review round 1: the values come from stored rows, which someone with the database can set to
// anything, and these texts reach a terminal (goblin-admin verify-audit): an entry number that is
// not a whole number reads as null does, and a text loses its control and format characters
// (escape sequences, bidirectional controls) and is cut to 200 characters, as the writer cuts
// values (cleanText), so no stored value can rewrite or hide the lines around it.
const unshown = /[\p{Cc}\p{Cf}]/gu;
function shown(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? grouped(value) : 'unknown';
  if (typeof value !== 'string') return 'unknown';
  const text = value.replace(unshown, '');
  return text.length <= 200 ? text : Array.from(text).slice(0, 200).join('');
}
function fill(template, values, nulls = {}) {
  return template
    .replace(/(entry )?#\{([a-zA-Z.]+)\}/g, (whole, entry, name) => {
      const value = valueAt(values, name);
      if (!Number.isSafeInteger(value))
        return nulls[name] !== undefined ? nulls[name] : `${entry ?? ''}#?`;
      return `${entry ?? ''}#${grouped(value)}`;
    })
    .replace(/\{([a-zA-Z. ]+)\}/g, (whole, name) => {
      const value = valueAt(values, name);
      if (value === null || value === undefined) return 'unknown';
      return shown(value);
    });
}
const valueAt = (values, name) =>
  name.split('.').reduce((node, part) => (node == null ? undefined : node[part]), values);

/** {message, consequence} of a problem (§7.1), times as auditTime() writes them. */
export function problemTexts(code, values) {
  const texts = PROBLEM_TEXTS[code];
  const shown = {
    ...values,
    time: values.time === null || values.time === undefined ? null : auditTime(values.time),
    lineTime: values.lineTime === undefined ? undefined : auditTime(values.lineTime),
  };
  const nulls =
    texts.whenNull ?? (code === 'head_mismatch' ? PROBLEM_TEXTS.log_truncated.whenNull : {});
  return {
    message: fill(texts.message, shown, nulls),
    consequence: fill(texts.consequence, shown, nulls),
  };
}

/** The line of an unverifiable item (§7.1). `line` is key status's command line (no_key). */
export function unverifiableText(item, { line = '' } = {}) {
  if (item.reason === 'restore_unchecked') {
    // The restore words are filled on their own and put in after: a snapshot name is never
    // read as a placeholder of the sentence around it.
    const words = fill(
      Object.hasOwn(UNVERIFIABLE_TEXTS, `restore.${item.cause}`)
        ? UNVERIFIABLE_TEXTS[`restore.${item.cause}`]
        : 'a restore',
      item
    );
    const values = { ...item, at: auditTime(item.at) };
    return UNVERIFIABLE_TEXTS.restore_unchecked
      .split('{restore words}')
      .map(part => fill(part, values))
      .join(words);
  }
  if (item.reason === 'key_reset')
    return fill(UNVERIFIABLE_TEXTS.key_reset, { ...item, at: auditTime(item.at) });
  // {line} is this command's own, never a stored value, so it is put in whole.
  if (item.reason === 'no_key') return UNVERIFIABLE_TEXTS.no_key.split('{line}').join(line);
  return fill(UNVERIFIABLE_TEXTS[item.reason] ?? item.reason, item);
}

/** The lines of an anchor (§7.1, ANCHOR_TEXTS). */
export function anchorLines(anchor) {
  const time = auditTime(anchor.time);
  if (anchor.action === 'system.restore') {
    const cause = anchor.cause === 'control_file' ? 'control_file' : 'snapshot';
    const key = `system.restore.${cause}${anchor.restoredHead ? '' : '.empty'}`;
    return [
      fill(ANCHOR_TEXTS[key], {
        ...anchor,
        time,
        at: anchor.at === null || anchor.at === undefined ? time : auditTime(anchor.at),
      }),
    ];
  }
  if (anchor.action === 'system.upgrade') {
    const lines = anchor.markerLost
      ? [fill(ANCHOR_TEXTS['system.upgrade.markerLost'], { time })]
      : [];
    for (const entry of anchor.entries ?? [])
      lines.push(
        fill(
          ANCHOR_TEXTS[entry?.to === anchor.release ? 'system.upgrade' : 'system.upgrade.other'],
          {
            to: entry?.to ?? 'unknown',
            at: auditTime(entry?.at),
          }
        )
      );
    return lines;
  }
  if (anchor.action === 'audit.gap')
    return [
      fill(
        ANCHOR_TEXTS[
          `audit.gap.${anchor.reason === 'inbox-discarded' ? 'inbox-discarded' : 'head-mismatch'}`
        ],
        {
          ...anchor,
          time,
        }
      ),
    ];
  if (anchor.action === 'key.reset')
    return [fill(ANCHOR_TEXTS[anchor.head ? 'key.reset' : 'key.reset.empty'], { ...anchor, time })];
  return [];
}

// ---------------------------------------------------------------------------------------------
// Journal lines (§4.6, §6.4 step 7).

const checkpointPattern = /\{"orbit":"audit\.checkpoint".*\}$/;

/**
 * The checkpoint lines of a journal export (journalctl -o cat, docker compose logs): from each
 * line, the substring that matches {"orbit":"audit.checkpoint"…}, parsed. A line that matches but
 * does not parse, or lacks a field, is kept as {invalid: true} (counted not written by this Uptime Goblin).
 */
export function journalLines(text) {
  const lines = [];
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const match = checkpointPattern.exec(raw.trimEnd());
    if (!match) continue;
    let line = null;
    try {
      line = JSON.parse(match[0]);
    } catch {}
    const valid =
      line &&
      Number.isSafeInteger(line.seq) &&
      Number.isSafeInteger(line.time) &&
      typeof line.hash === 'string' &&
      typeof line.key_id === 'string' &&
      typeof line.mac === 'string' &&
      typeof line.reason === 'string';
    lines.push(
      valid
        ? {
            instance: line.instance ?? null,
            seq: line.seq,
            time: line.time,
            hash: line.hash,
            key_id: line.key_id,
            reason: line.reason,
            mac: line.mac,
          }
        : {
            invalid: true,
            seq: Number.isSafeInteger(line?.seq) ? line.seq : null,
            time: Number.isSafeInteger(line?.time) ? line.time : null,
          }
    );
  }
  return lines;
}

// ---------------------------------------------------------------------------------------------
// The check.

/**
 * The state of one check (§6.4). `mac(kid, data)` is the audit MAC under key `kid` (it throws
 * an error with code seal_unknown_key for a kid the keyring does not hold), or null when no key
 * reached the check (the CLI: then only links, seqs and hashes are compared). `start` is what
 * the first unit read: {head, last, first, checkpoints, instance, resets}, `resets` the key.reset
 * rows up to the end of the check with the stored hash at each one's head ({row, headHash}).
 */
function startCheck({ mac, start, lines }) {
  const { head, last, checkpoints, instance } = start;
  const toSeq = Math.max(head?.seq ?? 0, last?.seq ?? 0);
  const problems = [],
    anchors = [],
    rowsAt = new Map(); // the seqs a checkpoint or a journal line names: {hash, time}
  const wanted = new Set([...checkpoints.map(c => c.seq), ...lines.map(line => line.seq)]);
  const problem = (code, values) => problems.push({ code, ...values });
  // The key resets that may excuse an unknown kid (D17): key.reset rows of this chain that name
  // a stored row before them, with its hash, as their head, and are signed. Signed means checked:
  // the row's hash verifies under a key the keyring holds, so someone with the database but not
  // the key cannot excuse a kid they made up (SEC-1), nor with a reset in a format this release
  // cannot check. A reset whose own key a later reset lost is accepted when that later, accepted
  // reset covers it, so a second lost-key reset does not turn the first into a break. Resets are
  // read newest first and cover only rows before their head, so trust always starts at a reset
  // this keyring checks, and none vouches for itself.
  const signedReset = row => {
    try {
      return rowHash(data => mac(row.key_id, data), row.prev_hash, row) === row.hash;
    } catch (error) {
      return unknownKid(error) ? null : false; // null: its own key was lost
    }
  };
  const resets = [];
  const coveringReset = (kid, seq) =>
    resets.find(reset => reset.lostKeyIds.has(kid) && seq <= reset.headSeq) ?? null;
  if (mac)
    for (const { row, headHash } of [...start.resets].sort((a, b) => b.row.seq - a.row.seq)) {
      const detail = row.detail;
      if (!detail || typeof detail !== 'object' || !Array.isArray(detail.lostKeyIds)) continue;
      const headed =
        detail.head === null ||
        (Number.isSafeInteger(detail.head?.seq) &&
          detail.head.seq < row.seq &&
          headHash === detail.head.hash);
      if (!headed) continue;
      const signed = signedReset(row);
      if (signed === false || (signed === null && !coveringReset(row.key_id, row.seq))) continue;
      resets.push({
        seq: row.seq,
        time: row.time,
        lostKeyIds: new Set(detail.lostKeyIds.filter(kid => typeof kid === 'string')),
        headSeq: detail.head?.seq ?? 0,
      });
    }
  const keyReset = new Map(); // anchor seq → unverifiable item
  const resetItem = reset => {
    let item = keyReset.get(reset.seq);
    if (!item) {
      item = {
        reason: 'key_reset',
        from: null,
        to: null,
        keyIds: [],
        anchorSeq: reset.seq,
        at: reset.time,
      };
      keyReset.set(reset.seq, item);
    }
    return item;
  };
  const newerFormat = [];

  // `first` and `prev` are the chain's (rows from seq 1 on); `firstRead` and `lastRead` every
  // row given to row(), rows outside the chain included, which are only ever read before it.
  let checked = 0,
    first = null,
    prev = null,
    firstRead = null,
    lastRead = null,
    unreadableAt = null;

  // Codex review A1: the lowest stored seq of the whole table, read in the first unit, decides
  // before any row is walked; the walk then reads the row too, which reports nothing twice.
  const outside = new Set();
  const outsideRow = r => {
    if (outside.has(r.seq)) return;
    outside.add(r.seq);
    problem('link_broken', { seq: r.seq, time: r.time });
  };
  if (start.first && !ownSeq(start.first.seq)) outsideRow(start.first);

  function row(r) {
    checked += 1;
    firstRead ??= r;
    lastRead = r;
    // A row Uptime Goblin never numbered: inserted or renumbered. It is not part of the chain, so the
    // rows from seq 1 on are checked as if it were not there.
    if (!ownSeq(r.seq)) {
      outsideRow(r);
      return;
    }
    first ??= r;
    // 1. and 2. The links.
    if (prev === null) {
      if (r.seq === 1) {
        if (r.prev_hash !== GENESIS) problem('link_broken', { seq: r.seq, time: r.time });
      } else if (
        !checkpoints.some(c => c.seq >= r.seq || (c.seq < r.seq && c.hash === r.prev_hash))
      )
        problem('start_missing', { seq: r.seq, time: r.time });
    } else if (r.seq === prev.seq + 1) {
      if (r.prev_hash !== prev.hash) problem('link_broken', { seq: r.seq, time: r.time });
    } else if (!(r.action === 'audit.gap' && r.prev_hash === prev.hash))
      problem('seq_gap', { seq: prev.seq + 1, time: r.time, from: prev.seq + 1, to: r.seq - 1 });
    // 3. The hash.
    if (!Object.hasOwn(FORMATS, r.v)) {
      const run = newerFormat.at(-1);
      if (run && run.v === r.v && run.to === prev?.seq) run.to = r.seq;
      else newerFormat.push({ reason: 'newer_format', from: r.seq, to: r.seq, v: r.v });
    } else if (mac) {
      let expected = null;
      try {
        expected = rowHash(data => mac(r.key_id, data), r.prev_hash, r);
        // Review round 2: the hash covers the detail parsed, so the stored text must be its
        // canonical JSON (§4.2: the stored text and the hashed bytes are the same). A text with
        // a duplicate key (JSON.parse keeps the last) or with padding would otherwise show
        // something never signed, in the CSV export or any reader of the stored text.
        if (
          r.detailText !== null &&
          r.detailText !== undefined &&
          r.detailText !== canonicalJSON(r.detail)
        )
          expected = null;
      } catch (error) {
        if (unknownKid(error)) {
          const reset = coveringReset(r.key_id, r.seq);
          if (reset) {
            const item = resetItem(reset);
            item.from = item.from === null ? r.seq : Math.min(item.from, r.seq);
            item.to = item.to === null ? r.seq : Math.max(item.to, r.seq);
            if (!item.keyIds.includes(r.key_id)) item.keyIds.push(r.key_id);
          } else problem('key_lost', { seq: r.seq, time: r.time });
          expected = undefined;
        } else expected = null; // canonical JSON refused a stored value (D28)
      }
      if (expected !== undefined && expected !== r.hash)
        problem('hash_mismatch', { seq: r.seq, time: r.time });
    }
    // 6. Anchors.
    if (anchorActions.has(r.action)) {
      const anchor = anchorOf(r);
      anchors.push(anchor);
      if (r.action === 'audit.gap' && anchor.reason === 'head-mismatch')
        problem('log_truncated', {
          seq: r.seq,
          time: r.time,
          head: anchor.head?.seq ?? null,
          lastSeq: anchor.lastSeq,
        });
    }
    if (wanted.has(r.seq)) rowsAt.set(r.seq, { hash: r.hash, time: r.time });
    prev = r;
  }

  // 4. The stored checkpoints; those at or above `reach` are not compared with a row. Resolves
  // how many verify and match, and the time of the newest one whose mac verifies and that this
  // log follows from (null when none does), which step 7 uses.
  function storedCheckpoints(reach) {
    let matched = 0,
      newest = null;
    for (const c of checkpoints) {
      let signed = true;
      if (mac)
        try {
          signed = checkpointMac(data => mac(c.key_id, data), { ...c, instance }) === c.mac;
        } catch (error) {
          if (!unknownKid(error)) signed = false;
          else {
            const reset = coveringReset(c.key_id, c.seq);
            if (reset) {
              const item = resetItem(reset);
              if (!item.keyIds.includes(c.key_id)) item.keyIds.push(c.key_id);
              item.from ??= c.seq;
              item.to ??= c.seq;
              signed = null;
            } else signed = false;
          }
        }
      if (signed === false) problem('checkpoint_mac', { seq: c.seq, time: c.time });
      let same = true;
      if (first && c.seq >= first.seq) {
        if (c.seq >= reach) same = null;
        else if (rowsAt.get(c.seq)?.hash !== c.hash) {
          same = false;
          problem('checkpoint_mismatch', { seq: c.seq, time: c.time });
        }
      } else if (!first) same = null;
      if (signed === true && same === true) matched += 1;
      // The prune this log follows from: its row still here and the same, or the one before
      // the first row. A checkpoint copied from another log's journal (a restore's, say) is
      // neither, so it decides nothing in step 7.
      const follows =
        first !== null && (c.seq >= first.seq ? same === true : c.hash === first.prev_hash);
      if (signed === true && follows && (newest === null || c.seq > newest.seq)) newest = c;
    }
    return { matched, prunedTime: newest?.time ?? null };
  }

  function finish() {
    const unverifiable = [];
    const reach = unreadableAt === null ? Infinity : unreadableAt;
    const { matched, prunedTime } = storedCheckpoints(reach);
    // 5. The end: the newest row checked is the head.
    if (unreadableAt === null) {
      if (prev) {
        if (!head || head.seq !== prev.seq || head.hash !== prev.hash)
          problem('head_mismatch', { seq: prev.seq, time: prev.time, head: head?.seq ?? null });
      } else if (head) problem('head_mismatch', { seq: 0, time: null, head: head.seq });
    }
    // 7. The journal.
    let journal = null;
    if (lines.length || start.journalGiven) {
      journal = {
        lines: lines.length,
        matched: 0,
        unchecked: 0,
        foreign: 0,
        coveredTo: null,
        foreignLines: [],
      };
      const restores = new Map(); // anchor seq → restore_unchecked item
      const restoreAnchors = anchors.filter(anchor => anchor.action === 'system.restore');
      // Lines signed with a key the keyring does not hold, which no recorded reset removed
      // (integration: unknown_key). They count as not written by this Uptime Goblin and leave the result
      // incomplete, never intact: without that key nothing tells another Uptime Goblin's line from one
      // of this Uptime Goblin's whose key has left the keyring, through a restore of data from before a
      // rotation, or through someone with the database alone who cut the entries a rotated key
      // signed, put the head back, deleted that key and made the older one active again.
      // keyIds (shown by --json only): the first 10 distinct ids, each cut to 64 characters,
      // since anyone could have added lines to the journal.
      const unknownKeys = { reason: 'unknown_key', lines: 0, keyIds: new Set() };
      // Review round 1: a prune covers the lines about what it removed. It deletes restore and
      // key.reset rows like any other, and with them what explained older lines, so a line is
      // also covered (counted matched, as a line below the first entry already is) when:
      // - it was printed before the entry the newest verified prune checkpoint names. Entries
      //   after that one were all written after it, so a line older than it that names a later
      //   seq comes from a log a restore (or a cut) replaced, at a point now older than the
      //   retention period; until the prune passes that point, the restore anchor still makes
      //   the line not checked, and a cut is still journal_mismatch or journal_ahead;
      // - it is under a key the keyring does not hold and names an entry a prune removed (a
      //   pruned key.reset no longer covers it).
      const prunedBefore = line =>
        (first !== null &&
          Number.isSafeInteger(line.seq) &&
          line.seq < first.seq &&
          checkpoints.some(c => c.seq >= line.seq)) ||
        (prunedTime !== null && Number.isSafeInteger(line.time) && line.time < prunedTime);
      for (const line of lines) {
        let checkable = !line.invalid,
          keyNotHeld = false;
        if (checkable && mac)
          try {
            checkable = checkpointMac(data => mac(line.key_id, data), line) === line.mac;
          } catch (error) {
            // Signed with a key a recorded reset removed: its seq and hash are still compared.
            checkable = unknownKid(error) && coveringReset(line.key_id, line.seq) !== null;
            keyNotHeld = !checkable && unknownKid(error);
          }
        if (!checkable) {
          if (keyNotHeld && prunedBefore(line)) {
            journal.matched += 1;
            if (line.seq < (first?.seq ?? 0))
              journal.coveredTo = Math.max(journal.coveredTo ?? 0, line.seq);
            continue;
          }
          journal.foreign += 1;
          journal.foreignLines.push({ seq: line.seq ?? null, time: line.time ?? null });
          if (keyNotHeld) {
            unknownKeys.lines += 1;
            if (unknownKeys.keyIds.size < 10) unknownKeys.keyIds.add(line.key_id.slice(0, 64));
          }
          continue;
        }
        if (line.seq >= reach) continue;
        const end = prev?.seq ?? 0;
        if (
          first &&
          line.seq >= first.seq &&
          line.seq <= end &&
          rowsAt.get(line.seq)?.hash === line.hash
        ) {
          journal.matched += 1;
          journal.coveredTo = Math.max(journal.coveredTo ?? 0, line.seq);
          continue;
        }
        if (first && line.seq < first.seq) {
          if (checkpoints.some(c => c.seq >= line.seq)) {
            journal.matched += 1;
            journal.coveredTo = Math.max(journal.coveredTo ?? 0, line.seq);
          } else problem('start_missing', { seq: first.seq, time: first.time });
          continue;
        }
        const restore = restoreAnchors.find(anchor => anchor.time > line.time);
        if (restore) {
          journal.unchecked += 1;
          let item = restores.get(restore.seq);
          if (!item) {
            item = {
              reason: 'restore_unchecked',
              lines: 0,
              anchorSeq: restore.seq,
              at:
                restore.cause === 'snapshot' && Number.isSafeInteger(restore.at)
                  ? restore.at
                  : restore.time,
              cause: restore.cause,
              snapshot: restore.snapshot,
            };
            restores.set(restore.seq, item);
          }
          item.lines += 1;
        } else if (prunedBefore(line)) journal.matched += 1;
        else if (line.seq <= end)
          problem('journal_mismatch', {
            seq: line.seq,
            time: rowsAt.get(line.seq)?.time ?? null,
            lineTime: line.time,
          });
        else
          problem('journal_ahead', {
            seq: line.seq,
            time: null,
            head: prev?.seq ?? head?.seq ?? 0,
            lineTime: line.time,
          });
      }
      unverifiable.push(...restores.values());
      if (unknownKeys.lines)
        unverifiable.push({ ...unknownKeys, keyIds: [...unknownKeys.keyIds].sort() });
    }
    // Without a key nothing signed was checked, unless there was nothing to check at all.
    if (!mac && (checked || checkpoints.length || lines.length))
      unverifiable.unshift({ reason: 'no_key' });
    unverifiable.push(...newerFormat);
    for (const item of keyReset.values()) item.keyIds.sort();
    unverifiable.splice(unverifiable[0]?.reason === 'no_key' ? 1 : 0, 0, ...keyReset.values());
    // The first problem by seq (in the order found, for problems at the same seq).
    const found = problems
      .map((item, index) => ({ item, index }))
      .sort((a, b) => a.item.seq - b.item.seq || a.index - b.index)[0]?.item;
    let shown = null;
    if (found) {
      const { code, ...values } = found;
      shown = { code, ...values, ...problemTexts(code, values) };
    }
    return {
      result: shown ? 'broken' : unverifiable.length ? 'incomplete' : 'intact',
      keyChecked: Boolean(mac),
      rows: {
        checked,
        first: firstRead ? { seq: firstRead.seq, time: firstRead.time } : null,
        last: lastRead ? { seq: lastRead.seq, time: lastRead.time } : null,
      },
      checkpoints: { checked: checkpoints.length, matched },
      anchors,
      unverifiable,
      journal,
      problem: shown,
      coveredTime:
        journal?.coveredTo != null ? (rowsAt.get(journal.coveredTo)?.time ?? null) : null,
    };
  }

  return {
    toSeq,
    // Where the walk stands: the seq of the last row read, or null before the first, which reads
    // from the lowest stored row whatever its seq (Codex review A1: not after 0).
    get lastSeq() {
      return lastRead?.seq ?? null;
    },
    // The first seq of the next unit, for unreadable: the lowest stored one before any was read.
    get nextSeq() {
      return lastRead ? lastRead.seq + 1 : (start.first?.seq ?? 1);
    },
    row,
    unreadable(seq) {
      unreadableAt = seq;
      problem('unreadable', { seq, time: null });
    },
    finish,
    // The prune's verdict (checkPrune) once every row up to `through` was given to row(): the
    // seq of the first entry that does not check, or null. Steps 1–3 and 4 (the checkpoints
    // above `through` are not compared with a row); an entry of a newer format cannot be checked,
    // so it stops the prune too. A head-mismatch gap row (log_truncated) does not: it is Uptime Goblin's
    // own signed record, and expires like any entry.
    unchecked(through) {
      storedCheckpoints(through + 1);
      let found = null;
      const at = seq => (found = found === null ? seq : Math.min(found, seq));
      for (const item of problems) if (item.code !== 'log_truncated') at(item.seq);
      if (newerFormat.length) at(newerFormat[0].from);
      if (prev?.seq !== through) at(prev ? prev.seq + 1 : (first?.seq ?? through));
      return found;
    },
    get last() {
      return prev ? { hash: prev.hash, time: prev.time } : null;
    },
  };
}

/**
 * The check a prune makes before it signs anything (§4.7; review round 1): every entry it would
 * remove, from the first stored one to `through`, checked as verification checks it (the start
 * explained by seq 1 or a stored prune checkpoint, the links, each entry's hash under its key or
 * a recorded key reset, and the stored prune checkpoints), in read units of `chunk` rows with
 * the event loop running between them. Without it, someone with the database but not the key
 * could set the time of the oldest entries back and have the prune sign a checkpoint over them
 * and delete them, and what remains would read intact. Resolves {unchecked, hash, time}:
 * `unchecked` the seq of the first entry that does not check (null when all do), `hash` and
 * `time` those of the entry at `through` as the check read it (the prune signs that one, and
 * only that one). Rejects when a read fails. Codex review A1: from the lowest stored row whatever
 * its seq, so a row at seq 0 or below (never Uptime Goblin's) stops the prune like any entry that does
 * not check, and no prune signs a checkpoint over it or deletes it unchecked.
 */
export async function checkPrune(db, { keyring, through, chunk = VERIFY_CHUNK }) {
  const mac = (kid, data) => keyring.hmac('audit', data, kid).mac;
  let check = null;
  await db.read(tx => {
    check = startCheck({ mac, start: { ...readStart(tx), journalGiven: false }, lines: [] });
  });
  let more = true;
  while (more) {
    const after = check.lastSeq;
    more = await db.read(tx => {
      const rows = auditOps.rowsFrom(tx, { afterSeq: after, toSeq: through, limit: chunk });
      for (const r of rows) check.row(r);
      return rows.length === chunk;
    });
    if (more) await nextTurn();
  }
  return { unchecked: check.unchecked(through), ...check.last };
}

/** The anchor entry of a row (§6.3): {seq, time, action, …its fields}. */
export function anchorOf(row) {
  const d = row.detail && typeof row.detail === 'object' ? row.detail : {};
  const base = { seq: row.seq, time: row.time, action: row.action };
  switch (row.action) {
    case 'system.restore':
      return {
        ...base,
        cause: d.cause ?? null,
        snapshot: d.snapshot ?? null,
        at: d.at ?? null,
        restoredHead: d.restoredHead ?? null,
      };
    case 'system.upgrade':
      return {
        ...base,
        release: d.release ?? null,
        entries: Array.isArray(d.entries) ? d.entries : [],
        markerLost: d.markerLost === true,
      };
    case 'audit.gap':
      return {
        ...base,
        reason: d.reason ?? null,
        head: d.head ?? null,
        lastSeq: d.lastSeq ?? null,
        count: d.count ?? null,
      };
    default:
      return {
        ...base,
        lostKeyIds: Array.isArray(d.lostKeyIds) ? d.lostKeyIds : [],
        head: d.head ?? null,
      };
  }
}

// The first unit: the head, the newest and oldest rows, the stored checkpoints, the instance
// id, and the key.reset rows up to the end of the check with the stored hash at their heads.
function readStart(tx) {
  const head = auditOps.head(tx),
    last = auditOps.last(tx),
    first = auditOps.first(tx);
  const toSeq = Math.max(head?.seq ?? 0, last?.seq ?? 0);
  const resets = toSeq
    ? auditOps.rowsOf(tx, 'key.reset', { toSeq }).map(row => ({
        row,
        headHash: Number.isSafeInteger(row.detail?.head?.seq)
          ? (auditOps.rowAt(tx, row.detail.head.seq)?.hash ?? null)
          : null,
      }))
    : [];
  return {
    head,
    last,
    first,
    // Review round 1: only prune checkpoints are stored (D12). Uptime Goblin prints a commit checkpoint,
    // signed the same way, for every unit; one copied from the journal into the table must not
    // explain a missing start (step 1) or cover journal lines (step 7), so any other stored
    // checkpoint is not read at all, and removed entries read start_missing.
    checkpoints: auditOps.checkpoints(tx).filter(c => c.reason === 'prune'),
    instance: auditOps.meta(tx, 'instance_id'),
    resets,
  };
}

/**
 * Verifies the log of `db` (a Db, or anything with read(fn)). Options: keyring (null: no key,
 * only links and hashes compared, at best incomplete), journal (the text of a journal export, or
 * null), clock, oneUnit (the CLI: everything in one read unit), chunk (rows a unit). Resolves
 * the §6.3 verify object (with `journal` and its `foreignLines` when a journal was given).
 * Rejects with the read error when a read fails for any other reason than an unreadable value.
 */
export async function verifyAudit(
  db,
  {
    keyring = null,
    journal = null,
    clock = Date.now,
    oneUnit = false,
    chunk = VERIFY_CHUNK,
    onUnit,
  } = {}
) {
  const checkedAt = clock(),
    started = performance.now();
  const lines = journal === null ? [] : journalLines(journal);
  const mac = keyring ? (kid, data) => keyring.hmac('audit', data, kid).mac : null;
  let check;
  const begin = start => {
    check = startCheck({ mac, start: { ...start, journalGiven: journal !== null }, lines });
  };
  const empty = {
    head: null,
    last: null,
    first: null,
    checkpoints: [],
    instance: null,
    resets: [],
  };
  // One unit of rows after `afterSeq` (null: from the lowest stored row, Codex review A1); false
  // when the check reached its end.
  const unit = (tx, afterSeq) => {
    const rows = auditOps.rowsFrom(tx, { afterSeq, toSeq: check.toSeq, limit: chunk });
    for (const r of rows) check.row(r);
    return rows.length === chunk;
  };
  const guarded = (fn, failedAt) => {
    try {
      return fn();
    } catch (error) {
      if (!outOfRange(error)) throw error;
      check ??= startCheck({ mac, start: { ...empty, journalGiven: journal !== null }, lines });
      check.unreadable(failedAt());
      return false;
    }
  };
  if (oneUnit)
    await db.read(tx => {
      if (
        guarded(
          () => (begin(readStart(tx)), true),
          () => 1
        ) === false
      )
        return;
      let more = true;
      while (more) {
        const after = check.lastSeq,
          at = check.nextSeq;
        more = guarded(
          () => unit(tx, after),
          () => at
        );
      }
    });
  else {
    const ok = await db.read(tx =>
      guarded(
        () => (begin(readStart(tx)), true),
        () => 1
      )
    );
    let more = ok !== false;
    while (more) {
      const after = check.lastSeq,
        at = check.nextSeq;
      const begun = performance.now();
      more = await db.read(tx =>
        guarded(
          () => unit(tx, after),
          () => at
        )
      );
      onUnit?.(performance.now() - begun);
      if (more) await nextTurn();
    }
  }
  const { coveredTime, ...result } = check.finish();
  const answer = {
    result: result.result,
    checkedAt,
    durationMs: Math.round(performance.now() - started),
    keyChecked: result.keyChecked,
    rows: result.rows,
    checkpoints: result.checkpoints,
    anchors: result.anchors,
    unverifiable: result.unverifiable,
    journal: result.journal,
    problem: result.problem,
  };
  // The time of the newest entry a journal line covers, for the CLI's coverage line; not part of
  // the §6.3 object (not enumerable, so neither JSON nor a shape comparison sees it).
  Object.defineProperty(answer, 'coveredTime', { value: coveredTime, enumerable: false });
  return answer;
}
