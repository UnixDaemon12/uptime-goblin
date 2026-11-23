# Delivery requirements and gates

Both Docker Compose and a native Linux installer are required. These are separate supported delivery paths, not a requirement to install both on one host. macOS is a development/test host only.

Existing foundation: digest-pinned Node Dockerfile, non-root runtime, Compose resource limits and loopback publish default; native deploy/install.sh with Linux/systemd/configuration preflights and deploy/uptime-goblin.service. This audit did not build images or execute the installer. Presence is not qualification.

The new `deploy/install-plan.sh --dry-run docker|linux` is a read-only, deterministic checklist. It never reads configuration/secrets, runs Docker, installs packages, starts services or modifies host security. There is deliberately no apply mode. It does not claim the existing installer is dry-run or rerun-safe in every supported environment.

Before production: qualify clean install, rerun, upgrade, interrupted upgrade and restore on supported Linux; verify release provenance and artifact hashes, secret ownership/permissions, data retention, graceful stop, resource limits and health checks. Back up data/configuration/keys through documented separate handling. Database migration may prevent image-only rollback; prove the matching restore path.

Keep Compose loopback publish default. Docker Engine28+ or separately evidenced equivalent isolation fix is necessary for the planned private-path design, not sufficient proof: effective routing/firewall/publish configuration and actual denied LAN/direct-route access must be qualified. This packaging slice does not implement missing coordinated proxy evidence or change credential routes. Preserve existing installer refusal gates. Never silently widen bind addresses, change firewall/VLAN/security settings or overwrite operator secrets.

Private source checkpoint packaging is not a release. Required security-review scans, Linux/container qualification, recovery, load/soak and independent review remain release gates. No notification/provider/credential activation is implied.


## Stable image policy

Once an official stable Uptime Goblin image is published, ordinary user installs should default to its `:latest` tag. Version tags and digests are optional operator choices, not mandatory end-user pins. Maintainer build-input pins, signatures, SBOMs and release provenance remain required; they are separate from the convenient user-facing default.

**Current state:** this checkout has `build: .` and `image: uptime-goblin:local`, not an official registry image. No official repository/tag availability is established here. Do not substitute an invented image address or claim `:latest` is currently supported. Publication and a tested release Compose configuration are future gated work.

**Deliberate updates:** on a future official-image deployment, the operator explicitly pulls the chosen tag, reviews its resolved version/digest and release/migration notes, confirms backups and then deliberately recreates the service. Pulling alone does not replace a running container; restart alone does not fetch a newer image. A moving `:latest` tag does not authorize unattended pulls, recreation or automatic updates. Existing locally built Compose installs retain their documented build workflow until official-image delivery exists.

**Rollback:** record the previous resolved image digest/version before changing containers, retain the matching backup and use that prior artifact explicitly if rollback is needed. Do not assume the moving tag still identifies the prior build, or that image rollback reverses database migration. Restore compatibility must be proven before upgrading. No pull, recreation, publication or update was executed for this policy change.
