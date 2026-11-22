#!/usr/bin/env bash
# The installer's name before the rename to Uptime Goblin (1.5). It runs deploy/install.sh with the
# same arguments, and exits with its exit status, so that scripts and notes that name this file
# keep working; it is removed in 1.7. Use deploy/install.sh.
set -euo pipefail
printf '%s\n' 'deploy/install-lxc.sh is deprecated and is removed in 1.7: run deploy/install.sh, which this runs now.' >&2
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/install.sh" "$@"
