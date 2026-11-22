// B6: permission names alone must not let future routes widen wall-display access.
// Public routes are handled before authentication; this is the signed-in route boundary.
const kioskRoutes = new Set([
  'GET /api/session',
  'POST /api/auth/logout',
  'GET /api/dashboard',
  'GET /api/version',
  'GET /api/docs',
  'GET /api/history/:id',
]);

/** A matched GET route also covers its router-generated HEAD; permission still applies. */
export function principalRouteAllowed(access, route) {
  return access.kind !== 'kiosk' || kioskRoutes.has(`${route.method} ${route.path}`);
}
