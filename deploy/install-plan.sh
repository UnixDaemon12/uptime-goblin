#!/bin/sh
# Read-only packaging plan. Never invokes Docker, sudo, network or an installer.
set -eu
usage() {
  printf '%s\n' 'Usage: sh deploy/install-plan.sh --dry-run docker|linux' >&2
  exit 64
}
[ "$#" -eq 2 ] || usage
[ "$1" = '--dry-run' ] || usage
case "$2" in
  docker)
    printf '%s\n' '
Uptime Goblin Docker Compose installation plan (NOT executed)
Prerequisites: supported Linux Docker host, Compose v2, reviewed release source.
Require Docker Engine 28+ or separately evidenced equivalent isolation fix.
Engine version is not isolation proof: effective publish address, bridge routing,
firewall behavior and denied LAN/direct-route access still require qualification.
Preserve loopback publish default 127.0.0.1:4317; do not widen it automatically.
Use existing Dockerfile and compose.yaml; do not install Docker or change host security.
The Compose service is uptime-goblin; the orbit-data volume keeps its name and data
(mounted at /var/lib/uptime-goblin; an old mount at /app/data alone is still read).
Operator prepares private configuration and external key according to installation.md.
Never print, overwrite or pass existing secrets as command arguments.
Before update: verify release provenance, back up configuration/data/keys separately,
and verify the matching restore procedure. Do not assume image rollback restores data.
Run Compose validation only after private configuration is prepared locally.
Build/start is a separate explicitly authorized step, not performed by this plan.
Coordinated proxy/private-path and credential gates remain required before release.
'
    ;;
  linux)
    printf '%s\n' '
Uptime Goblin native Linux installation plan (NOT executed)
Prerequisites: supported Linux with running systemd, Node.js 24+ with built-in SQLite,
npm and the existing deploy/install.sh prerequisite checks.
Use existing deploy/install.sh and deploy/uptime-goblin.service; do not replace preflights.
An Orbit layout (orbit.service, /opt/orbit, /var/lib/orbit, /etc/orbit.env) is moved by renames
on one file system after the preflights; a failed upgrade restores it (installation.md).
Keep loopback binding unless an explicitly reviewed proxy deployment requires otherwise.
Operator prepares private configuration and encryption keys through the documented path.
Before update: verify release provenance, back up configuration/data/keys separately,
and verify the matching restore procedure. Do not assume binary rollback restores data.
Review installer options and changes before separately authorizing installation.
No package installation, privilege escalation, firewall, network or service change occurs here.
Linux runtime/recovery qualification remains required; Mac syntax tests do not qualify it.
'
    ;;
  *) usage ;;
esac
