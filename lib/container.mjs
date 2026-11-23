// Shared deployment detection, with no dependency on CLI or database modules.
import fs from 'node:fs';

/**
 * True when this process runs in a Docker or Podman container (/.dockerenv, /run/.containerenv).
 * An Uptime Goblin in another container on the same data volume has its own process ids there, so a pid
 * in run/status.json says nothing here: it may be missing, or be any process of this container,
 * this one included. (The native LXC is not one of these: goblin-admin and Uptime Goblin share its ids.)
 */
export function inContainer() {
  return ['/.dockerenv', '/run/.containerenv'].some(file => fs.existsSync(file));
}
