import test from 'node:test';
import assert from 'node:assert/strict';
import { createExclusive, BusyError } from '../../lib/http/exclusive.mjs';
import { AuthError } from '../../lib/auth.mjs';
import { auditError } from '../../lib/audit/errors.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));

// The request's recorder as the pipeline gives it (ctx.audit, audit spec §4.4): begin() resolves
// a Change whose notes are kept; `fail` makes the next begin() reject; `hold` (a promise) keeps
// begin() waiting until it resolves, as a slow attempt write does.
function recorder({ fail = null, hold = null } = {}) {
  const begun = [];
  return {
    begun,
    async begin(values) {
      if (hold) await hold;
      if (fail) throw fail;
      const change = { seq: begun.length + 1, values, notes: [], note: v => change.notes.push(v) };
      begun.push(change);
      return change;
    },
  };
}
const audit = recorder();
const settings = { action: 'settings.update', target: { type: 'settings', id: 'workspace' } };

test('configuration writes run one at a time, in order, even when one fails', async () => {
  const exclusive = createExclusive();
  const order = [];
  let release;
  const first = exclusive({ access: {}, audit }, async () => {
    order.push('first starts');
    await new Promise(resolve => (release = resolve));
    order.push('first ends');
    throw new Error('first failed');
  });
  const second = exclusive({ access: {}, audit }, () => {
    order.push('second');
    return 2;
  });
  await tick();
  assert.deepEqual(order, ['first starts']);
  release();
  await assert.rejects(first, /first failed/);
  assert.equal(await second, 2);
  assert.deepEqual(order, ['first starts', 'first ends', 'second']);
});

test('a queued write re-checks its credential and is skipped once its browser left', async () => {
  let current = 1;
  const exclusive = createExclusive({
    assertCurrent: access => {
      if (access.revision !== current) throw new AuthError('Sign in to Uptime Goblin', 401);
    },
  });
  let release;
  const holding = exclusive(
    { access: { revision: 1 }, audit },
    () => new Promise(r => (release = r))
  );
  let ran = 0;
  const stale = exclusive({ access: { revision: 1 }, audit }, () => ran++);
  let gone = false;
  const abandoned = exclusive(
    { access: { revision: 2 }, abandoned: () => gone, audit },
    () => ran++
  );
  await tick();
  current = 2; // the password changed while both waited
  gone = true; // and the second browser gave up
  release();
  await holding;
  await assert.rejects(stale, error => error instanceof AuthError && error.status === 401);
  assert.equal(await abandoned, undefined);
  assert.equal(ran, 0, 'neither queued write ran');
});

test('the queue is bounded in length and in waiting time; a refused write never runs', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const exclusive = createExclusive({ limit: 2, startMs: 1000 });
  let release;
  const holding = exclusive({ access: {}, audit }, () => new Promise(r => (release = r)));
  let ran = 0;
  const waiting = exclusive({ access: {}, audit }, () => ran++);
  // Two are waiting (the running one counts until it starts): a third is refused at once.
  await assert.rejects(
    exclusive({ access: {}, audit }, () => ran++),
    error => error instanceof BusyError && /busy saving other changes/.test(error.message)
  );
  t.mock.timers.tick(1000);
  await assert.rejects(
    waiting,
    error => error instanceof BusyError && /could not start this change/.test(error.message)
  );
  release();
  await holding;
  await tick();
  assert.equal(ran, 0, 'a write that timed out is not applied later');
  // The queue has room again.
  assert.equal(await exclusive({ access: {}, audit }, () => 'later'), 'later');
});

test('admit() refuses a write when its turn comes, before the task, with nothing applied', async () => {
  let full = false;
  const order = [];
  const audit = recorder();
  const exclusive = createExclusive({
    assertCurrent: () => order.push('credential'),
    admit: () => {
      order.push('admit');
      if (full) throw Object.assign(new Error('disk full'), { code: 'storage_full' });
    },
  });
  let release;
  const holding = exclusive({ access: {}, audit }, () => new Promise(r => (release = r)));
  let ran = 0;
  // Queued while the disk still had space; refused because it is full when its turn comes.
  const queued = exclusive({ access: {}, audit }, () => ran++);
  await tick();
  full = true;
  release();
  await holding;
  await assert.rejects(queued, error => error.code === 'storage_full');
  assert.equal(ran, 0, 'the refused write never ran');
  // The write that ran checked its credential again after its attempt row (audit spec §5.4);
  // the refused one wrote no attempt row (a full disk refuses before the audit, D7).
  assert.deepEqual(order, ['credential', 'admit', 'credential', 'credential', 'admit']);
  assert.equal(audit.begun.length, 1);
  // Space again: the next write runs.
  full = false;
  assert.equal(await exclusive({ access: {}, audit }, () => 'saved'), 'saved');
});

test('onError() sees every error the task throws, which is rethrown unchanged', async () => {
  const seen = [];
  const exclusive = createExclusive({
    onError: error => {
      seen.push(error);
      throw new Error('a failing reporter is ignored');
    },
  });
  const enospc = Object.assign(new Error('no space'), { code: 'ENOSPC' });
  await assert.rejects(
    exclusive({ access: {}, audit }, () => {
      throw enospc;
    }),
    error => error === enospc
  );
  const later = new Error('async failure');
  await assert.rejects(
    exclusive({ access: {}, audit }, async () => {
      await tick();
      throw later;
    }),
    error => error === later
  );
  assert.deepEqual(seen, [enospc, later]);
  // A refusal before the task (credential, admission) is not a task error.
  const refusing = createExclusive({
    admit: () => {
      throw new Error('refused');
    },
    onError: error => seen.push(error),
  });
  await assert.rejects(
    refusing({ access: {}, audit }, () => 1),
    /refused/
  );
  assert.equal(seen.length, 2);
  assert.equal(await exclusive({ access: {}, audit }, () => 3), 3, 'the queue goes on');
});

// Audit spec §5.4: the attempt row at the write's turn, the re-checks after it, and the notes
// the result row is built from.
test('a write records its attempt at its turn, with the revision, and notes the configuration before and after', async () => {
  const audit = recorder();
  let revision = 7;
  const exclusive = createExclusive({ snapshot: () => ({ revision, public: { r: revision } }) });
  let given;
  const first = exclusive(
    { access: {}, audit },
    async change => {
      given = change;
      assert.equal(audit.begun.length, 1, 'the attempt row comes before the change');
      revision++;
      return 'saved';
    },
    settings
  );
  // The next write's change is not mixed into the first one's: its snapshot is taken inside the
  // first write's turn.
  const second = exclusive({ access: {}, audit }, () => revision++, {
    ...settings,
    detail: { ifMatch: true },
  });
  assert.equal(await first, 'saved');
  await second;
  const [one, two] = audit.begun;
  assert.equal(given, one, 'the task gets its Change to note what only it knows');
  assert.deepEqual(one.values, {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace' },
    detail: null,
    configRevision: 7,
  });
  assert.deepEqual(one.notes, [
    {
      applied: true,
      configRevision: 8,
      before: { revision: 7, public: { r: 7 } },
      after: { revision: 8, public: { r: 8 } },
    },
  ]);
  assert.deepEqual(two.values.detail, { ifMatch: true });
  assert.equal(two.values.configRevision, 8);
  assert.deepEqual(two.notes[0].after, { revision: 9, public: { r: 9 } });

  // A task that changed nothing (an If-Match conflict, a source not found) is noted unapplied,
  // and one that throws still gets its note.
  await exclusive({ access: {}, audit }, () => {}, settings);
  assert.equal(audit.begun[2].notes[0].applied, false);
  const failure = new Error('config.json refused');
  await assert.rejects(
    exclusive(
      { access: {}, audit },
      () => {
        throw failure;
      },
      settings
    ),
    error => error === failure
  );
  assert.equal(audit.begun[3].notes[0].applied, false);

  // A snapshot that cannot be taken after the task does not replace the task's own outcome;
  // the change is then not noted (its result row goes by the answer alone).
  let ran = false;
  const unsure = createExclusive({
    snapshot: () => {
      if (ran) throw new Error('snapshot failed');
      return { revision: 1 };
    },
  });
  const noted = recorder();
  assert.equal(
    await unsure({ access: {}, audit: noted }, () => ((ran = true), 'saved'), settings),
    'saved'
  );
  assert.deepEqual(noted.begun[0].notes, []);

  // The configuration as the task finds it is its "before": a change made while the attempt
  // was written (none can be made through exclusive(); this is another writer) is not noted as
  // this write's.
  let current = 1;
  const late = recorder();
  const begin = late.begin;
  late.begin = values => ((current = 2), begin(values));
  const outOfTurn = createExclusive({ snapshot: () => ({ revision: current }) });
  await outOfTurn({ access: {}, audit: late }, () => {}, settings);
  assert.equal(late.begun[0].values.configRevision, 1, 'the attempt names the revision found');
  assert.deepEqual(late.begun[0].notes, [
    { applied: false, configRevision: 2, before: { revision: 2 }, after: { revision: 2 } },
  ]);
});

test('fail closed: a write whose attempt row cannot be written is refused with nothing applied', async () => {
  const unavailable = auditError('audit_unavailable', { cause: new Error('disk') });
  const reported = [];
  const exclusive = createExclusive({ onError: error => reported.push(error) });
  let ran = 0;
  await assert.rejects(
    exclusive({ access: {}, audit: recorder({ fail: unavailable }) }, () => ran++, settings),
    error => error === unavailable
  );
  assert.equal(ran, 0);
  assert.deepEqual(reported, [], 'not a task error: the pipeline reports its cause');
  // The queue goes on.
  assert.equal(await exclusive({ access: {}, audit }, () => 'next', settings), 'next');
  // A write without the request's recorder is a defect, refused before it is queued: at once,
  // even while another write holds the queue (queued, it would wait its turn and then fail on
  // the missing recorder, or time out as busy).
  const queue = createExclusive({ startMs: 200 });
  let release;
  const held = new Promise(resolve => (release = resolve));
  const holding = queue({ access: {}, audit }, () => held, settings);
  await assert.rejects(
    queue({ access: {} }, () => ran++, settings),
    {
      name: 'TypeError',
      message: 'exclusive() needs the request audit recorder',
    }
  );
  release('held');
  assert.equal(await holding, 'held');
  assert.equal(ran, 0);
});

test('a browser that leaves, or a session that ends, during the attempt write applies nothing', async () => {
  let release;
  const hold = new Promise(resolve => (release = resolve));
  let current = 1;
  const exclusive = createExclusive({
    assertCurrent: access => {
      if (access.revision !== current) throw new AuthError('Sign in to Uptime Goblin', 401);
    },
  });
  let ran = 0,
    gone = false;
  // MEC-6: the client closes while its attempt row is written.
  const left = recorder({ hold });
  const abandoned = exclusive(
    { access: { revision: 1 }, abandoned: () => gone, audit: left },
    () => ran++,
    settings
  );
  await tick();
  gone = true;
  release();
  assert.equal(await abandoned, undefined);
  assert.equal(ran, 0, 'nothing applied behind a client that went away');
  assert.deepEqual(left.begun[0].notes, [{ outcome: 'failed', detail: { code: 'client_closed' } }]);

  // A sign-out lands while the attempt row is written: 401, nothing applied, and no note (the
  // pipeline ends the change `denied` from the 401).
  let again;
  const signedOut = recorder({ hold: new Promise(resolve => (again = resolve)) });
  const stale = exclusive({ access: { revision: 1 }, audit: signedOut }, () => ran++, settings);
  await tick();
  current = 2;
  again();
  await assert.rejects(stale, error => error instanceof AuthError && error.status === 401);
  assert.equal(ran, 0);
  assert.equal(signedOut.begun.length, 1);
  assert.deepEqual(signedOut.begun[0].notes, []);
});
