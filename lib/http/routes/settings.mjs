// Workspace settings and the email test.
import { setTimeout as delay } from 'node:timers/promises';
import { assertKnownSettings, InputError } from '../../config.mjs';
import { emailConfigured } from '../../mail.mjs';
import { json } from '../body.mjs';
import { revisionConflict } from '../pipeline.mjs';

/**
 * `app` (see createApp in server.mjs): config, store, email (the notifier of test emails),
 * alerting (the delivery service), exclusive(), mono(), settingsPruneMs, storage
 * {failed(), step()} and collection (see sources.mjs).
 */
export function settingsRoutes(app) {
  const { config, store, email, collection, storage } = app;
  // Test emails are at most one a minute (monotonic clock).
  let nextEmailTest = 0;
  return [
    {
      method: 'PATCH',
      path: '/api/settings',
      auth: 'session',
      permission: 'settings:write',
      ifMatch: 'optional',
      audit: 'config',
      summary: 'Change workspace settings',
      async handler({ req, res, access, body, gone, audit }) {
        const settings = await body();
        assertKnownSettings(settings);
        // Checked against the saved settings before the write takes its turn: a malformed
        // change writes no audit row, takes no queue slot and gets its 400 also while the disk is
        // full. save() checks it again against the settings as they are at its turn.
        config.globalCandidate(settings, config.value);
        // Attempt and result rows (audit spec §5.4): exclusive() writes the attempt at the
        // write's turn, before anything changes, and notes the configuration before and after.
        await app.exclusive({ access, abandoned: gone, audit }, save, {
          action: 'settings.update',
          target: { type: 'settings', id: 'workspace', name: null },
          detail: { ifMatch: req.headers['if-match'] !== undefined },
        });
        async function save() {
          if (revisionConflict(req, res, config.value.revision)) return;
          const previousEmail = JSON.stringify(config.value.email),
            previousMonitoring = collection.monitoringKey();
          const previousAlertEnabled = config.value.alerts.enabled,
            previousPoll = config.value.pollSeconds,
            previousRetention = config.value.retentionDays;
          // Persist the validated policy before deleting history: a failed settings save
          // must not apply a shorter retention. Pruning only reuses database pages and
          // cannot be relied on to free filesystem space for the configuration write.
          const candidate = config.globalCandidate(settings, config.value);
          config.updateGlobal(settings);
          // Apply all saved settings before pruning yields: old mail and collection must
          // not keep running while other requests can already read the new configuration.
          // A history error raises the storage notice instead of failing the saved change.
          const emailChanged = JSON.stringify(config.value.email) !== previousEmail;
          if (emailChanged) email.reconfigure();
          // Only collection settings restart collection; alert tuning applies next poll.
          if (previousMonitoring !== collection.monitoringKey()) collection.restart();
          if (previousPoll !== config.value.pollSeconds) collection.reschedule();
          if (previousAlertEnabled !== config.value.alerts.enabled)
            storage.step(() => store.clearAllAlerts());
          // New email settings may fix what paused or failed the email channel: it resumes,
          // and its old error and streaks are cleared, as 1.4.x's reconfigure() cleared them
          // (delivery spec D12). Awaited after everything above is applied; the settings are
          // saved either way, so a status write that fails (the service reports a full disk
          // itself) never turns the save into an error.
          if (emailChanged)
            try {
              await app.alerting.emailChanged();
            } catch (error) {
              console.error(
                'Could not record the new email settings in the delivery status:',
                error?.code || error?.name
              );
            }
          if (candidate.retentionDays < previousRetention) {
            const pruned = store
                .prune(candidate.retentionDays, undefined, {
                  // Every batch respects the saved policy, including a later increase
                  // after a long prune has continued in the background.
                  shouldContinue: () => config.value.retentionDays <= candidate.retentionDays,
                })
                .catch(e => storage.failed(e)),
              waited = new AbortController();
            // Give small prunes time to finish, without holding every other change
            // behind a large deletion for longer than settingsPruneMs.
            await Promise.race([
              pruned,
              delay(app.settingsPruneMs, undefined, { signal: waited.signal }).catch(() => {}),
            ]);
            waited.abort();
          }
          json(res, 200, { ok: true, revision: config.value.revision });
        }
      },
    },
    {
      method: 'POST',
      path: '/api/email/test',
      auth: 'session',
      permission: 'settings:write',
      // One row after the answer, best effort (audit spec §5.5): a test changes nothing stored.
      audit: 'operation',
      summary: 'Send a test email with the saved settings',
      async handler({ res, body, assertCurrent, committed, audit }) {
        const input = await body();
        if (
          !input ||
          typeof input !== 'object' ||
          Array.isArray(input) ||
          Object.keys(input).length
        )
          throw new InputError('Test email uses saved settings. Save email settings first.');
        if (!emailConfigured(config.value.email))
          throw new InputError(
            'Save a sender, recipient and app password before sending a test email.'
          );
        // Busy: a test is still being sent, or the email channel is sending (delivery spec
        // D13). Alerts waiting to retry do not block a test, which is how the admin checks a fix.
        if (app.mono() < nextEmailTest || app.alerting.emailSending() || email.status().pending) {
          res.setHeader(
            'Retry-After',
            String(Math.max(1, Math.ceil((nextEmailTest - app.mono()) / 1000)))
          );
          json(res, 429, {
            error:
              'Please wait one minute between test emails and let any current delivery finish.',
          });
          return;
        }
        nextEmailTest = app.mono() + 60000;
        // Its outcome comes from the answer (settle): 200 ok, 422 failed, a busy channel's 429
        // denied, settings changed before the send (409) conflict.
        const operation = audit.operation({
          action: 'email.test',
          target: { type: 'channel', id: 'email', name: null },
        });
        let result, failure;
        try {
          result = await email.send({ name: 'Uptime Goblin', time: Date.now() }, { test: true });
        } catch (error) {
          failure = error;
        }
        // What the mail server said goes into the email channel's status (an accepted test
        // also resumes a paused channel, D13). Only real attempts: a full queue (EMAIL_BUSY)
        // or settings changed before sending tried nothing. recordTest() never rejects, so a
        // status write the full disk refuses never turns a sent test into an error (D27).
        const attempted = failure ? failure.code !== 'EMAIL_BUSY' : Boolean(result?.accepted);
        if (attempted) operation.note({ detail: { accepted: !failure } });
        if (attempted)
          await app.alerting.recordTest(
            failure
              ? { accepted: false, message: failure.message }
              : { accepted: true, message: 'The mail server accepted the test email.' }
          );
        // Sending can take the mail server's whole timeout: a session signed out meanwhile
        // gets 401 and never sees the outcome (§6.5). Nothing tried, nothing kept: the keyed
        // retry after signing in again runs.
        if (!attempted) {
          assertCurrent();
          if (failure) json(res, 429, { error: failure.message });
          else
            json(res, 409, {
              error:
                'Email settings changed before the test was sent. Save settings and try again.',
            });
          return;
        }
        // Tried: what the status recorded is kept under the Idempotency-Key before the session
        // is checked, so the keyed retry after signing in again replays it instead of sending a
        // second test email (delivery spec A68, as A62).
        if (failure) {
          committed(422, { error: failure.message });
          return;
        }
        committed(200, {
          ok: true,
          accepted: true,
          message: 'The mail server accepted the test email. Check the inbox and spam folder.',
          acceptedAt: result.acceptedAt,
        });
      },
    },
  ];
}
