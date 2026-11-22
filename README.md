# Uptime Goblin

Uptime Goblin is a private homelab dashboard with service links, live measurements, SQLite history, and alerts. The required delivery targets are Docker Compose and a native Linux installer. macOS is a development/test host, not a supported server target. Open it in Firefox or another browser; no extension, cloud account, frontend build, or external font service is needed.

Uptime Goblin was called Orbit until 1.4.x. An upgrade from Orbit keeps your settings and data, and the old setting names, headers and cookie keep working until 1.7: see [renamed from Orbit](docs/installation.md#renamed-from-orbit).

Configure each card's destination separately from its collection address. Add multiple instances of any service, inspect expandable charts, adjust the layout and polling, and send alert/recovery messages through email or a JSON webhook.

Proxmox cards can show the whole cluster or one named node. Create one per host using a shared cluster API connection, separate launch links, and individual history and node-online alerts. See [node configuration](docs/configuration.md#one-proxmox-card-per-node).

Every card also offers **Website check**: enter a service's HTTPS URL to track availability, response time and HTTP status without API credentials. It supports GET/HEAD and configurable accepted statuses, including opt-in authentication responses. Redirects are checked without following them; a login redirect only proves the front door responds. This is a simple option for Docker-hosted services.

**Start with real connections.** Included cards have no addresses or credentials. Uptime Goblin neither discovers your lab nor fills graphs with sample measurements. History begins when collection starts. Some sources use native APIs, some need exporters, and bookmarks provide links only; see the [integration matrix](docs/integrations.md).

## Packaging requirement

Docker Compose and native Linux/systemd installation are both required. Existing artifacts are `Dockerfile`, `compose.yaml`, `deploy/install.sh` and `deploy/uptime-goblin.service`. Read-only plans are available with `sh deploy/install-plan.sh --dry-run docker` or `--dry-run linux`. These do not install anything, read secrets or qualify host isolation; see [delivery gates](docs/delivery.md). Future official stable image installs default to `:latest`, with optional version/digest selection and deliberate operator updates. The current Compose file builds `uptime-goblin:local`; no official image address is claimed.

## Start locally

Install Node.js 24 or newer with its built-in SQLite module and npm, then run from this directory:

```sh
npm ci --omit=dev --ignore-scripts
test -e .env || install -m 600 .env.example .env
```

Uptime Goblin always requires an admin password: set `GOBLIN_PASSWORD` in `.env` (12 to 1024 characters, inside the single quotes), then run `npm start`. Without one Uptime Goblin refuses to start (exit status 78); it never makes one up.

Open <http://127.0.0.1:4317> and sign in as `admin` with that password. Stop with Ctrl+C. Settings and readings remain in `data/`. For access from another machine, configure allowed browser hosts and a private HTTPS reverse proxy. Uptime Goblin serves HTTP itself and is designed for a trusted administrator. If you expose it through a reverse proxy, set `GOBLIN_TRUST_PROXY` to your proxy (`loopback` when it runs on the same host) so failed sign-ins are throttled per client, and make the proxy send `X-Forwarded-Proto $scheme` so browsers can sign in over HTTPS; see [signing in](docs/authentication.md#https-cookies-and-plain-http) and [sign-in throttling](docs/security.md#failed-sign-in-throttling).

Browsers sign in as `admin` on Uptime Goblin's own sign-in page and stay signed in with a session cookie (**Keep me signed in on this device** keeps it for up to 30 days of regular use). Change the password under **Configure → Account**, which also lists your sessions; a change signs your other devices out and this one stays signed in. Uptime Goblin stores a salted password hash in its private data directory and keeps `auth.json` up to date, so a rollback to 1.4.x signs in with the same password (once `auth.json` has been written; while it cannot be, a banner on every page says so). See [signing in](docs/authentication.md), [password settings](docs/configuration.md#uptime-goblin-login-password) and [operator recovery](docs/troubleshooting.md#forgotten-uptime-goblin-password).

**Configure → Audit log** records sign-ins and sign-outs, every settings, source and security change (with what changed, never a secret), tests, exports, the `goblin-admin` key commands and Uptime Goblin's own starts, upgrades and restores, with the client address and browser. Entries are signed in a chain, and **Check integrity** (or `goblin-admin verify-audit`) shows whether the log was changed. Keep Uptime Goblin's own log too: its checkpoint lines show entries removed from the end. Entries are kept 90 days by default (`GOBLIN_AUDIT_RETENTION_DAYS`). See [the audit log](docs/security.md#audit-log) and its limits.

## Updates

Open Uptime Goblin tabs update themselves after an upgrade and return to the same view. When reloading would lose unsaved edits, a banner offers **Reload** instead. Tabs opened on 1.4.2 or earlier contain no update check and need one manual reload. After the upgrade to 1.5, open tabs show the new sign-in page; sign in with the same password. The native installer proves that the new version is the one serving and restores the previous code by itself when it is not. See [updates and rollback](docs/installation.md#updates-and-rollback).

## Documentation

| Guide | Contents |
|---|---|
| [Installation](docs/installation.md) | Linux, Docker, native LXC, installer verification and automatic rollback, verifying a release, HTTPS, the encryption key, the space reserve, updates, backup and rollback, `goblin-admin`, keeping Uptime Goblin's log |
| [Signing in](docs/authentication.md) | The admin password, sessions and sign-out, HTTPS and the reverse proxy, refused sign-ins and their fixes, scripts with legacy Basic, rollback and recovery |
| [Configuration](docs/configuration.md) | Login password, dashboard appearance, sources, collection, thresholds, email and webhook settings, the Audit log page and its exports, environment variables |
| [Alerts and notifications](docs/notifications.md) | What is sent and when, durable delivery and retries, paused channels, Configure → Notifications, the webhook's headers and signature verification, a full disk, rollback |
| [Integrations](docs/integrations.md) | Every collector, credentials, available measurements and limits |
| [Architecture and API](docs/architecture.md) | Collection flow, history, alert behavior, update detection, API endpoints (the audit log's included) and headers, exit statuses and resource bounds |
| [Security](docs/security.md) | Trust boundaries, secrets, the audit log and its limits, sign-in sessions, the encryption key and sealed secrets, a leaked key, TLS, the public health check, release signing, supervised exits and source-only packaging |
| [Troubleshooting](docs/troubleshooting.md) | Connectivity, missing measurements, alerts, paused or refusing notifications, email, a full disk, the audit log (cannot be written, CHANGED, not fully checked, old entries kept), encryption key refusals and a lost key, permissions and diagnostics |
| [Examples](examples/README.md) | Generic source and numeric-mapping examples; no live configuration |

Uptime Goblin supports Proxmox, Linux/Windows exporters, UniFi, Cosmos, AMP, Plex, Tautulli, Seerr, Sonarr, Radarr, Prowlarr, SABnzbd, NZBGet, CrowdSec, Nginx Proxy Manager, AdGuard Home, Docker inventory, custom JSON/Prometheus, and HTTP checks. Synology and WireGuard need an exporter with mappings. NetBox and bookmarks open links by default.

The background collector works while the browser is closed. Pausing a source stops its collection and new alerts while keeping its history. Hiding a source is a display choice and does not pause it. Missing data stays missing; last-good values are marked stale and graphs break across outages.

Bounded retries and failure/recovery confirmation help brief interruptions settle before notifications. Per-source overrides and separate metric recovery boundaries handle slower or fluctuating services. Connection and metric notifications can be muted separately without hiding active warnings: a service can be reachable while a resource or application-health threshold still needs attention.

Email uses the exact locked Nodemailer dependency. Alerts are saved before they are sent, retried for up to 24 hours across restarts, and listed under **Configure → Notifications**, where a failed one can be sent again and a paused channel resumed; webhook requests are signed (see [alerts and notifications](docs/notifications.md)). Email and webhook are independent: when one pauses, the other says so. Neither can report an outage of Uptime Goblin's own host without an external monitor.

## Development and release status

```sh
npm ci --ignore-scripts
npm run format:check
npm run check
npm run lint:sql
npm run lint:imports
npm test
npm audit --omit=dev
```

`npm run check` checks `deploy/manifest.txt` (the files installed as the application), follows every import from it, syntax-checks each module and runs `bash -n` on the installer. `npm run lint:sql` and `npm run lint:imports` check the server modules' SQL and import rules. Run them yourself: `npm run check` and the CI test jobs do not run them, and the security scan (`node scripts/security-gate.mjs scan`; start the gate with `node`, as the CI security workflow does, not through npm) runs them only once its `candidate-policy` and `platform-manifest` checks have passed. On a CI runner `platform-manifest` cannot pass for a 1.5 commit, because the gate approvals and reviewed baselines it needs are kept only in a local repository, so CI runs neither lint. `npm test` runs every suite. Tests that need Chrome, the release fixtures, the Debian 13 systemd test image, a Docker daemon or Git skip when it is missing, unless `TEST_REQUIRE` names it (`browser`, `fixtures`, `systemd`, `docker`, `git`; for example `TEST_REQUIRE=browser`); the tests that start from a release tag or development milestone of the project's history read it from a private history input that `TEST_HISTORY` names (the published source has no history), skip without it and fail without it when `TEST_REQUIRE` names `history` (see [the private historical qualification](docs/engineering-quality.md#the-private-historical-qualification)). The 250,000-entry audit log measurement (`test/audit/capacity.test.mjs`) runs only when `TEST_REQUIRE` names `capacity`, so a plain `npm test` and CI skip it. The full check before a release is `TEST_REQUIRE=browser,fixtures,systemd,docker,capacity,git npm test`, with the two lint commands. `npm run test:fast`, `test:browser`, `test:upgrade`, `test:installer` and `test:docker` run one suite each. Uptime Goblin reads `public/` once at startup, so restart it after editing the web app.

Tests use temporary databases, local fixture servers, and fake mail transports. They do not establish compatibility with every installed service version or prove real mail delivery. The CI workflow runs these checks, except the two lint commands and the capacity measurement, with Node.js 24 on Ubuntu in five jobs (checks, browser, upgrade, installer with real systemd, Docker); it does not use homelab credentials or deploy anything.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md). Run `npm run package` to prepare a reviewed source-only staging tree/archive under `release/`; it does not publish anything. With `ORBIT_SIGNING_KEY=<path to the release key>` it also signs `SHA256SUMS`. Before uploading, use the [source-only packaging guide](docs/security.md#preparing-a-source-only-upload). Do not upload `data/`, `.env`, backups, redacted configuration exports, or private audit material.

## Release signing

Release archives from 1.4.3 on include `SHA256SUMS.sig`, an SSH signature over `SHA256SUMS`:

- Signer: `release@orbit-homelab`
- Namespace: `orbit-release`
- Public key: `deploy/allowed_signers`
- Key fingerprint: `SHA256:DtqYV4kTfpOQSCfobFVmE8pnND8Z/kzMTuQZsntRKIo` (ED25519)

In the extracted release directory, verify with a copy of `allowed_signers` you already trust (from this repository or an installed Uptime Goblin, never the copy inside the archive you are checking):

```sh
ssh-keygen -Y verify -f /path/to/trusted/allowed_signers -I release@orbit-homelab -n orbit-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --strict SHA256SUMS
```

`ssh-keygen` prints `Good "orbit-release" signature for release@orbit-homelab` followed by the key's fingerprint; it must match the fingerprint above. On macOS, use `shasum -a 256 -c SHA256SUMS`. See [verifying a release](docs/installation.md#verifying-a-release).

## License

Uptime Goblin is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version of Uptime Goblin for other people over a network, the AGPL requires you to offer them the corresponding source.
