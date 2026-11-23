// The route table: each route module registers with one line (roadmap §2.4). Order does not
// decide which route answers (the most specific path does); within one path it sets the order
// of the methods in a 405's Allow header.
import { healthRoutes } from './routes/health.mjs';
import { authRoutes } from './routes/auth.mjs';
import { accountRoutes } from './routes/account.mjs';
import { dashboardRoutes } from './routes/dashboard.mjs';
import { settingsRoutes } from './routes/settings.mjs';
import { sourceRoutes } from './routes/sources.mjs';
import { importRoutes } from './routes/import.mjs';
import { notificationRoutes } from './routes/notifications.mjs';
import { auditRoutes } from './routes/audit.mjs';
import { staticRoutes } from './static.mjs';

/** Paths that are never static files: an unknown one is a JSON 404, not the web app. */
export const reservedPaths = Object.freeze(['/api/*']);

/** The auth kinds this release's pipeline serves; a route needing another stops the start. */
export const supportedAuth = Object.freeze(['public', 'session']);

/**
 * The route features (lib/http/router.mjs enforcedFeatures) this release's pipeline enforces:
 * none yet. Step-up arrives after sessions (a recent re-authentication), schemas and body
 * permissions with accounts; each is added here in the change that makes the pipeline
 * enforce it.
 */
export const supportedFeatures = Object.freeze([]);

/**
 * Every route of the main listener, for createRouter(). `app` is built by createApp(); besides
 * the shared context the sign-in routes read identity, loginThrottle, legacyBasic,
 * insecureHttpSessions, release and trusted, the delivery routes alerting and guard, and the
 * audit routes audit.
 */
export function routeTable(app) {
  return [
    ...healthRoutes(app),
    ...authRoutes(app),
    ...accountRoutes(app),
    ...dashboardRoutes(app),
    ...settingsRoutes(app),
    ...sourceRoutes(app),
    ...importRoutes(app),
    ...notificationRoutes(app),
    ...auditRoutes(app),
    ...staticRoutes(app.site),
  ];
}
