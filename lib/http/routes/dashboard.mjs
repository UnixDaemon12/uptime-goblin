// What the dashboard and the System page read.
import fs from 'node:fs';
import path from 'node:path';
import { publicConfig } from '../../catalog.mjs';
import { InputError } from '../../config.mjs';
import { periods } from '../../store.mjs';
import { json } from '../body.mjs';
import { displayDashboard, displayHistory, shownOnDisplay } from '../display-view.mjs';
import { queryValue } from '../pipeline.mjs';

/** The largest guide served; the installed ones are well under 100 KiB. */
export const guideLimit = 1024 * 1024;

/**
 * The text of an installed guide, or null when `file` is missing or is not a regular file of at
 * most guideLimit bytes. Opened without blocking and without following a symlink, then checked
 * on its descriptor: a FIFO in its place would otherwise stop the whole process (every request,
 * /health included) until something writes to it, and a huge file would be read into memory.
 * At most guideLimit + 1 bytes are read, so a file that grows after the check is refused too.
 */
export async function readGuide(file) {
  let handle;
  try {
    handle = await fs.promises.open(
      file,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
    );
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > guideLimit) return null;
    const buffer = Buffer.alloc(guideLimit + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (!bytesRead) break;
      size += bytesRead;
    }
    return size > guideLimit ? null : buffer.toString('utf8', 0, size);
  } catch (error) {
    // Missing, a symlink (ELOOP) or a socket (ENXIO): not installed as Uptime Goblin installs it. Other
    // errors (a failing disk) are the server's and answered 500.
    if (['ENOENT', 'ENOTDIR', 'ELOOP', 'ENXIO'].includes(error.code)) return null;
    throw error;
  } finally {
    await handle?.close();
  }
}

const docs = {
  installation: 'Installation',
  configuration: 'Configuration',
  integrations: 'Integrations',
  architecture: 'How Uptime Goblin works',
  security: 'Security',
  authentication: 'Signing in',
  troubleshooting: 'Troubleshooting',
  notifications: 'Alerts and notifications',
};

/**
 * `app` (see createApp in server.mjs): config, store, identity, directory, docsDirectory,
 * release {version, build, startedAt}, dashboard(), lastCollected(), openClients(),
 * storage.failure(), webhookConfigured, collection (the scheduler's view, see sources.mjs),
 * alerting (the delivery service), guard (the storage guard), reserveBytes (the size of the
 * guard's reserve), keyStatus (where the encryption key came from, never the key) and
 * resourceLimits (what a supervised start found of its memory, CPU and process limits, and the
 * GOBLIN_ALLOW_UNLIMITED it was given: shown, never set, here or by any other route).
 */
export function dashboardRoutes(app) {
  const { config, store, identity, release, collection } = app;
  const read = (path, summary, handler, extra = {}) => ({
    method: 'GET',
    path,
    auth: 'session',
    permission: 'dashboard:read',
    summary,
    handler,
    ...extra,
  });
  // An access that may not read the configuration (a wall display) gets the display view.
  const displayOnly = access => !access?.permissions?.has('config:read');
  return [
    read('/api/dashboard', 'Sources, their latest readings, alerts and events', ({ res, access }) =>
      json(res, 200, displayOnly(access) ? displayDashboard(app.dashboard()) : app.dashboard())
    ),
    // Hidden tabs ask this every few minutes to learn that Uptime Goblin was updated.
    read('/api/version', 'The running release', ({ res }) =>
      json(res, 200, { version: release.version, build: release.build })
    ),
    read(
      '/api/system',
      'Release, storage, collection and notification status',
      ({ res }) => {
        const size = name => {
          try {
            return fs.statSync(path.join(app.directory, name)).size;
          } catch {
            return 0;
          }
        };
        const failure = app.storage.failure();
        // The last computed delivery status; `available` false says the figures are from the
        // last successful read, never current (delivery spec D12).
        const delivery = app.alerting.snapshot(),
          legacy = app.alerting.legacy();
        json(res, 200, {
          version: release.version,
          build: release.build,
          // Web app builds seen in the last 10 minutes; build null means older than 1.4.3.
          clients: app.openClients(),
          uptimeSeconds: Math.floor((Date.now() - release.startedAt) / 1000),
          startedAt: release.startedAt,
          // Always: Uptime Goblin no longer starts without an admin password (1.4.x's field).
          authenticationRequired: true,
          // Same shape as 1.4.x ({username, passwordChangeAvailable, passwordChangedAt}).
          authentication: identity.metadata(),
          data: {
            databaseBytes: size('history.sqlite') + size('history.sqlite-wal'),
            writeFailure: failure ? { since: failure.since, code: failure.code } : null,
            configBytes: size('config.json'),
            controlBytes: size('control.sqlite') + size('control.sqlite-wal'),
            ...store.stats(),
          },
          collection: {
            concurrency: config.value.monitoring.concurrency,
            timeoutSeconds: collection.timeoutMs() / 1000,
            pending: collection.pending(),
            inflight: collection.inflightCount(),
            lastCollected: app.lastCollected(),
          },
          limits: { sources: 200, mappingsPerSource: 100, rulesPerSource: 30 },
          // 1.4.x's two fields keep their shape; email's now come from the persisted status.
          notifications: {
            email: legacy.email,
            webhookConfigured: app.webhookConfigured,
            available: delivery.available,
            saving: delivery.saving,
            totals: delivery.totals,
            oldestWaitingAt: delivery.oldestWaitingAt,
            // A46: alerts the backlog cap refused since this start (no row lists them).
            notQueued: delivery.notQueued,
          },
          keys: app.keyStatus,
          resourceLimits: app.resourceLimits ?? { supervised: false },
          disk: { ...app.guard.state(), reserveBytes: app.reserveBytes },
        });
      },
      { permission: 'system:read' }
    ),
    read(
      '/api/config/export',
      'The configuration without secrets, as a download',
      async ({ res, audit, assertCurrent }) => {
        const exported = {
          format: 'orbit-config',
          version: 1,
          exportedAt: new Date().toISOString(),
          containsSecrets: false,
          config: publicConfig(config.value),
        };
        // An export is a disclosure: its row is written before the answer, and when it cannot
        // be, nothing is exported (503 audit_unavailable, audit spec §5.5).
        await audit.single({
          action: 'config.export',
          target: { type: 'config', id: null, name: null },
          detail: {
            sources: exported.config.services?.length ?? 0,
            bytes: Buffer.byteLength(JSON.stringify(exported)),
          },
        });
        assertCurrent();
        res.setHeader(
          'Content-Disposition',
          'attachment; filename="uptime-goblin-config-redacted.json"'
        );
        json(res, 200, exported);
      },
      // Only from Uptime Goblin's page or a script (D29, applied by the pipeline before this runs).
      { permission: 'config:export', audit: 'export' }
    ),
    read('/api/docs', 'One of the installed guides, as Markdown', async ({ res, url }) => {
      const doc = queryValue(url, 'doc') || 'configuration';
      if (!Object.hasOwn(docs, doc)) {
        json(res, 404, { error: 'Document not found' });
        return;
      }
      const markdown = await readGuide(path.join(app.docsDirectory, doc + '.md'));
      if (markdown === null) {
        json(res, 404, { error: 'Documentation is not installed' });
        return;
      }
      json(res, 200, { title: docs[doc], markdown });
    }),
    read(
      '/api/history/:id',
      'Readings of one source over a period',
      ({ res, url, params, access }) => {
        const display = displayOnly(access);
        // A source hidden from the dashboard is no source to a wall display.
        if (!config.get(params.id) || (display && !shownOnDisplay(config.get(params.id)))) {
          json(res, 404, { error: 'Source not found' });
          return;
        }
        const period = queryValue(url, 'range') || '24h';
        if (!Object.hasOwn(periods, period)) throw new InputError('Unknown history period');
        // ?metric=<key>, repeatable: only those readings in each point (a chart needs one).
        // Keys the source never reported match nothing; without any, every reading is sent. A
        // key is held to what a collector may report (at most 200 characters, lib/collectors.mjs),
        // without control characters: keys of upstream readings are not only mapping-key syntax.
        const requested = url.searchParams.getAll('metric');
        if (requested.length > 20) throw new InputError('Ask for at most 20 metrics at a time');
        if (requested.some(key => key.length > 200 || /[\u0000-\u001f\u007f-\u009f]/.test(key)))
          throw new InputError('Unknown metric');
        const metrics = [...new Set(requested.filter(Boolean))];
        const source = config.get(params.id);
        const history = {
          ...store.history(
            params.id,
            period,
            Date.now(),
            collection.interval(source),
            // Charts break where readings are further apart than this source normally
            // needs; the scheduler-backlog allowance is for alert state, not for drawing.
            collection.timeoutMs(source) / 1000,
            metrics.length ? { metrics } : undefined
          ),
          pollSeconds: collection.interval(source),
        };
        json(res, 200, display ? displayHistory(history) : history);
      }
    ),
  ];
}
