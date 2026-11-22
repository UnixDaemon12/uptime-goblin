// The server uses the browser's time zone module (public/shared/timezone.js) unchanged, so a
// setting the server accepts is one every page can show, and both format times the same way.
import { parseTimeZone, isSupported } from '../public/shared/timezone.js';
export * from '../public/shared/timezone.js';

/**
 * The canonical spelling to save for a display time zone setting, or null when it is refused:
 * 'local', 'UTC', 'UTC±HH:MM' (hours 00-14, minutes 00/15/30/45; UTC±00:00 is saved as 'UTC')
 * or a region-based IANA name this server's Intl knows.
 */
export function normalizeTimeZone(value) {
  const zone = parseTimeZone(value);
  if (!zone || (zone.kind === 'region' && !isSupported(zone.id))) return null;
  return zone.id;
}
