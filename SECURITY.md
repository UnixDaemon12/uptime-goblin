# Security

Uptime Goblin is a private, single-administrator dashboard. Anyone who can sign in can configure destinations reachable from its server and exercise its saved service credentials. It is not a multi-tenant service or a secrets vault.

See the [security guide](docs/security.md) for deployment boundaries, credential handling, TLS, backups, and safe source packaging.

The [engineering quality policy](docs/engineering-quality.md) requires full checks and independent review of each commit, plus a separate final release validation. Scanner and test results describe their coverage; they do not establish that Uptime Goblin is vulnerability-free. Unresolved findings and unavailable required checks block approval. Follow the [documentation audit inventory](docs/documentation-inventory.md) for current coverage and outstanding publication work.

## Reporting a vulnerability

Do not publish credentials, private hostnames, raw service payloads, configuration exports or exploit details in a public issue. Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Include the affected revision, Node/runtime and deployment mode, a minimal sanitized reproduction, expected impact, and any proposed fix. Use fictional tokens and hosts. Do not test against another person's deployment.

## Release signing

Release archives from 1.4.3 on include `SHA256SUMS.sig`, an SSH signature over `SHA256SUMS`. Verify it before installing.

| Item | Value |
|---|---|
| Signer | `release@orbit-homelab` |
| Namespace | `orbit-release` |
| Public key | `deploy/allowed_signers` |
| Key fingerprint | `SHA256:DtqYV4kTfpOQSCfobFVmE8pnND8Z/kzMTuQZsntRKIo` (ED25519) |

In the extracted release directory, use a copy of `allowed_signers` you already trust (from the project repository or an installed Uptime Goblin, never the copy inside the archive you are checking):

```sh
ssh-keygen -Y verify -f /path/to/trusted/allowed_signers -I release@orbit-homelab -n orbit-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --strict SHA256SUMS
```

`ssh-keygen` prints `Good "orbit-release" signature for release@orbit-homelab` followed by the key's fingerprint, which must match the one above. Do not install a release whose signature or checksums fail, and report it privately as described above. The installer checks every installed file against `SHA256SUMS`, but not the signature itself. See [verifying a release](docs/installation.md#verifying-a-release).

## Support status

There is no formal supported-version or response-time policy yet. Keep the application, Node.js runtime, operating system, container base image and dependencies current. Dependency audit results and fixture tests cover only part of the system; they do not certify an entire homelab.
