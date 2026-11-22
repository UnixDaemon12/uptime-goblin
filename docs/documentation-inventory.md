# Documentation inventory

_This audit was made when the product was called Orbit, before its rename to Uptime Goblin in 1.5, and keeps the names and file paths of that time._

This records a bounded maintenance-documentation audit, not approval of a release. Follow the [engineering quality policy](engineering-quality.md) for the full per-commit and final-release gates. Changes after this baseline need a final documentation review against the exact candidate.

`ORBIT-HANDOFF.md`, the dated internal handoff that rows below name, has since been removed from the source tree: it was internal coordination material and is not published. The rows and hashes that name it stay as the record of this audit.

The baseline, hashes and corrections below describe the **maintenance** tree. In the 1.5 tree they are a record of that audit, not a 1.5 documentation audit; see [the 1.5 tree](#the-15-tree) for what the gate tooling port changed and what remains unreviewed there.

## Baseline and historical scope

- Audit started at `2026-10-04T05:44:22.848727+00:00`.
- Git HEAD: `b8e1b3fd0833e17e5f5e0736f1e69c2d1c2fd661`; HEAD tree: `f580e37d1c2ef22a7a5d51db3d404f272f3117af`.
- The working tree was under active development. The file hashes below identify the bytes inspected at audit start; they are not a claim that every file matched HEAD. `CONTRIBUTING.md` was modified and `docs/engineering-quality.md` was new. Other work was in progress outside this audit's ownership.
- There were 122 tracked files. The working-byte manifest digest was `9edf76aeacd7d7e00a58564918d1bb9c97e87b74293c0ab334cb60093e1a6bd2`: SHA-256 of a compact UTF-8 JSON array in `git ls-files -z` order, with each regular-file object using sorted keys `mode` (octal permission string), `path`, and `sha256`. It is a baseline identifier, not a signed release attestation.
- Available Git history starts at **1.4.2**; the changelog retains notes from **1.2.0 onward**. Earlier notes are historical documentation, not evidence of earlier commits or independently verified releases. Preserve existing commits, tags and attribution; do not invent missing history.
- Scope covers all tracked project-authored Markdown/text documentation, the examples and deployment instructions embedded in configuration files, plus the new engineering policy. The standard AGPL license text is preserved separately; this is not a legal review. Runtime comments outside the deployment files are source evidence, not a complete comment audit.
- The inventory itself was created after the baseline and cannot include its own final hash. Newly added documents and revised files must be included in the final candidate manifest.

## Review status

**Checked** means the listed static review was completed, with the limits in that row. It does not mean every sentence, external link or command was tested. **Needs update** identifies a concrete correction or incomplete required alignment. **Unreviewed** work is identified explicitly in the final-audit list below.

| Document or instructional file | Status at baseline | Coverage or remaining correction |
|---|---|---|
| `AGENTS.md` | Needs update | Machine-specific collaboration instructions need a portable, publication-safe form and the engineering-policy reference. |
| `CHANGELOG.md` | Needs update | Maintenance entries checked selectively; the 1.2.0 license footer needs explicit historical framing. Earlier release claims are not independently reconstructed. |
| `CONTRIBUTING.md` | Checked | New per-commit/release policy reviewed as requirements; implementation and final gate evidence remain pending. |
| `ORBIT-HANDOFF.md` | Needs update | Dated operational handoff contains private local context and stale branch/deployment assertions. Do not publish it as current product documentation. |
| `README.md` | Needs update | Setup and trust boundary checked; development/release instructions need to agree with the new engineering gates. |
| `SECURITY.md` | Needs update | Reporting/signing guidance checked; add the engineering-policy/full-history publication requirements. |
| `deploy/manifest.txt` | Checked | All six application guides are listed; contributor/audit documents are not application-guide API keys. |
| `docs/architecture.md` | Needs update | Auth, write ordering, retention, build/health and resource-bound claims checked selectively. Recent-client data does not prove which browser tabs remain open. |
| `docs/configuration.md` | Needs update | Settings, password precedence, retention and defaults checked; bootstrap environment table incorrectly expresses the upper limit as characters. |
| `docs/installation.md` | Needs update | Deployment, verification, backup/recovery and rollback paths inspected. See extraction, refusal-list and gate findings below. |
| `docs/integrations.md` | Checked | Adapter descriptions inspected; Sonarr fallback/overflow behavior checked against source. External vendor documentation and live compatibility remain unreviewed. |
| `docs/security.md` | Needs update | Auth, storage, SSRF, SMTP, packaging and backup claims checked against selected source paths. Publication guidance must cover all publishable Git history and full gates. |
| `docs/troubleshooting.md` | Needs update | Auth recovery and installer outcomes checked; installed-directory refusal list omits temporary copies. Recent-client wording needs qualification. |
| `examples/README.md` | Needs update | Fictional endpoints and API-write guidance inspected; the global-defaults example is incomplete despite its description. |
| `.env.example` | Needs update | Deployment variable mapping checked; bootstrap maximum is UTF-8 bytes, not characters. |
| `Dockerfile` | Checked | Pinned base, nonroot user, application/data permissions, manifest inclusion and health command inspected; no image rebuilt in this audit. |
| `compose.yaml` | Checked | Loopback publication, required bootstrap, persistent volume and runtime protections inspected; no Compose deployment run in this audit. |
| `deploy/allowed_signers` | Checked | Public verification-key role and trusted-copy requirement checked; no release signature or private key used. |
| `deploy/install-lxc.sh` | Checked | Selected preflight, staged unit, activation, reinstall, rollback and bounded legacy-probe paths read; no installer executed. |
| `deploy/orbit.service` | Checked | Runtime identity, data path, unit sandbox, restart policy and refusal exit checked statically; no systemd rehearsal in this audit. |
| `examples/global-settings.json` | Needs update | Valid partial settings shape, but missing retry/recovery and notification-category defaults. |
| `examples/json-mappings.json` | Checked | Fictional numeric paths reviewed; no live upstream response tested. |
| `examples/linux-source.json` | Checked | Reserved example endpoints and disabled monitoring reviewed; no source contacted. |
| `examples/prometheus-mappings.json` | Checked | Hypothetical series/labels reviewed; no exporter contacted. |
| `docs/engineering-quality.md` | Checked | New policy at audit start, then untracked; requirements do not claim completed validation. |

## Corrections identified

1. **Password units.** `.env.example` and the environment table in `docs/configuration.md` say 12–1,024 characters. `lib/auth.mjs` checks a minimum of 12 Unicode characters and a maximum of 1,024 UTF-8 bytes. Non-ASCII passwords make that distinction observable. The literal startup error also uses the older wording; quoting that error in troubleshooting should not redefine the actual limit.
2. **Reserved installer directories.** Installation and troubleshooting list installed, previous and failed copies, but `deploy/install-lxc.sh` also refuses running from `/opt/orbit.new` and `/opt/orbit.reinstall`, including their descendants. Describe all five paths.
3. **Complete settings example.** `examples/global-settings.json` omits `retryCount`, `retryDelaySeconds`, `recoverySuccesses`, `recoverySeconds`, `notifyAvailability` and `notifyMeasurements` from `lib/catalog.mjs` defaults. It remains a valid partial PATCH; its description as complete is inaccurate.
4. **Release extraction before verification.** The documented recipe extracts an unverified archive using elevated privileges into a shared system staging directory. Use a fresh private, unprivileged staging directory, an independently trusted verification key, successful signature and checksum checks, and only then the privileged installer. This is a procedure correction, not evidence of a reproduced tar exploit.
5. **Gate alignment.** README, security/publication guidance and the installation update checklist must link the full engineering gates. A focused suite or production-dependency audit alone is insufficient. Gate code and documentation were being changed during this audit; final alignment has not been approved.
6. **Publication-safe history and handoff.** `ORBIT-HANDOFF.md` is a dated internal operational record containing local context and obsolete current-state assertions. `AGENTS.md` also uses machine-specific collaboration paths. Resolve public/private scope before publication without silently rewriting history. Do not copy private context into this inventory.
7. **Recent-client interpretation.** `server.mjs` records successful GETs to `/api/dashboard` and `/api/version` by reported build; a request without `X-Orbit-Client` is grouped as legacy. This is recent build activity, not an authenticated inventory or count of open browser tabs. Qualify corresponding configuration, architecture, installation and troubleshooting wording.
8. **Historical license wording.** The 1.2.0 changelog footer's no-license/no-release statement needs an explicit date/version qualifier so it does not contradict the current AGPL license and existing release tags.

## Corrections during this audit

The baseline rows and hashes above remain unchanged as a record of what prompted the corrections. The following disposition applies to the working tree after the bounded edits; it is still subject to the final candidate review.

| Finding | Disposition |
|---|---|
| 1 — Password units | **Fixed** in `.env.example` and `docs/configuration.md`. The old upgrade paragraph now points to current password requirements. The runtime's quoted startup-error wording was not changed. |
| 2 — Installer directories | **Fixed** in installation and troubleshooting; all five reserved directory names are listed. |
| 3 — Settings defaults | **Fixed** by adding all six missing fields to `examples/global-settings.json`; its existing description as complete is now accurate for the documented nonsecret sections. |
| 4 — Archive verification | **Fixed**: the recipe uses a new private, unprivileged staging directory and stops on signature or checksum failure before printing the verified location. Only a subsequent, deliberate step runs the privileged installer. |
| 5 — Gate alignment | README, SECURITY, AGENTS, installation and security now reference the engineering gates. Gate implementation/evidence is being finalized separately and is not approved by this documentation audit. |
| 6 — Public handoff | **Fixed in the current tree**: the handoff is now public-safe navigation, and collaboration instructions use a portable path. Historical revisions still require publication/privacy review; replacing current files does not clear history. |
| 7 — Recent clients | **Fixed** in configuration, installation, architecture and troubleshooting: recent build activity does not establish an open-tab count. |
| 8 — Historical license | **Fixed**: the 1.2.0 footer explicitly describes its historical status and distinguishes the later AGPL license. |

Verification performed with synthetic data only: four example JSON files parsed and passed the current pure configuration validators under Node 26.5.1; every included global-default field matched `lib/catalog.mjs`. Seventeen documented `sh` blocks passed syntax checks, and the installer passed `bash -n`; these are not installation/backup rehearsals. The exact revised verification block passed eight synthetic cases: a valid signed archive, changed payload, wrong signer and invalid archive using both `sha256sum` and macOS `shasum`. Only the valid cases printed the verified directory, whose parent mode was 0700. That rehearsal used Python 3.9.6 and OpenSSH 10.3p1 with temporary generated fixture keys, no real signing key, installer, elevated privilege or network access. Final release signing and deployment checks remain unreviewed.

Subsequent changes on 2026-10-04 add the complete external security-rule inventory, local SonarQube release checks, finite container resource limits and bounded startup-file validation. Configuration, architecture, installation, security, changelog and engineering guidance were updated for those changes. Maintenance service credentials remain plaintext on disk; the new encryption requirement is explicitly unresolved here. The original audit hashes are preserved below; the final gate manifest identifies the revised candidate. The author-identity rewrite maps the baseline commit above to `3b0cce88fb35f72acaed94a90b3e6a4933debee7`, with its tree unchanged.

## Sensitive procedures checked

- **Authentication and recovery:** saved `auth.json` takes precedence over the bootstrap environment; malformed saved authentication refuses startup; password changes persist before switching the live credential; old credentials are checked again before queued writes. The stopped-service recovery procedure preserves the entire private data directory and authentication file before reverting to a known bootstrap password. Compose environment changes require recreation.
- **Settings and history:** validation/save precede pruning; saved poll and mail settings apply before the prune wait. Background deletion checks the latest retention policy before each batch. Increasing retention cannot recover rows already deleted. The docs correctly distinguish reclaimed SQLite pages from filesystem space.
- **Docker and backups:** configuration matches loopback host publication, a persistent data volume, nonroot runtime and a read-only application filesystem. Backups preserve the whole stopped data directory, environment and CA setup; redacted exports are not backups. No real backup, restore, image build or container operation was performed in this audit.
- **Installer:** dependencies and the replacement unit are prepared before stopping the old service; unit activation/service-management failures enter the described rollback path. An identical reinstall preserves the older rollback copy. Recovery still attempts restart after a unit-reload failure, distinguishes restart failure, and bounds legacy verification. Code rollback does not restore data, environment or the unit.
- **Health and signing:** current readiness is stricter than a 401 response; modern installer verification checks build/process/nonce. The pre-1.4.3 fallback is explicitly identity-unverified. The installer checks packaged hashes but does not verify signatures itself, so the trusted-key verification step is required before running it.
- **Outbound requests and integration claims:** selected destination and SMTP paths agree with the stated loopback/address checks and SMTP TLS/checked-address behavior. The documented HTTP second-resolution limitation remains explicit. Sonarr's Wanted count survives an oversized library when that endpoint succeeds; only 404 permits the library fallback. This did not test actual third-party services.
- **API examples:** `If-Match` is optional in the current source; the documentation does not falsely require it. It is still useful for protecting an API client's writes against concurrent changes.

## Final audit still required

- **Unreviewed:** external vendor pages, live service-version/permission compatibility, every historical changelog claim, and screenshots/accessibility behavior. No independent certification follows from fixture coverage.
- **Unreviewed:** an exact final source/archive/container candidate, final image SBOM and signature/provenance, current vulnerability disposition, all publishable history/privacy review, and a documentation check against the final tracked tree.
- Recheck every changed or newly added document and reconcile status rows after corrections. Include the inventory and engineering policy in the tracked candidate; confirm which guides are available in the in-app allowlist versus repository-only documentation.
- Rehearse installation, password recovery, stopped backups/restores and rollback using disposable synthetic data on supported runtimes/platforms. Record exact commands, versions, counts and failures; a syntax check is not a successful procedure rehearsal.
- Complete the full per-commit and final-release gates plus independent source/security review. Missing tools, unavailable checks, skips and unresolved blockers do not count as passes.

## The 1.5 tree

The gate tooling and these policy documents were ported into the 1.5 tree (candidate Git tree `801796a3b5c0be38f96c6b2e7cd4a2f081dd3ef1` before the port) on 2026-10-04 as uncommitted work. That port is not a documentation audit of 1.5. Its effect on each tracked document outside `test/`:

| Document | 1.5 status after the port |
|---|---|
| `AGENTS.md`, `SECURITY.md` | **Updated.** The 1.5 copies were byte-identical to the maintenance baseline, so the maintenance revisions apply: the engineering-policy references and, in `AGENTS.md`, the portable collaboration path and current assignments (confirm assignments in the room). `SECURITY.md` is unchanged from that revision; `AGENTS.md` differs in one command, the gate entry point `node scripts/security-gate.mjs commit` (started with node, not through npm). |
| `CONTRIBUTING.md` | **Updated** by a manual merge: the policy, commit and release gate sections are added, and 1.5's SQL/import lint and `TEST_REQUIRE=browser,fixtures,systemd,docker,capacity,git` instructions are kept. The commit and release commands start the gate with `node scripts/security-gate.mjs`, not through npm. Shell blocks carry no `#` comments. |
| `CHANGELOG.md` | **Updated:** the 1.5 section records the port and its remaining gaps. |
| `ORBIT-HANDOFF.md` | **Updated** with a section on the port. It is still the dated internal handoff with local paths and earlier state; finding 6 applies to the 1.5 copy, which needs publication review. |
| `docs/engineering-quality.md`, `docs/ai-development-security.md`, `docs/security-rule-matrix.md`, this inventory | **New in 1.5** from the maintenance export, each with a 1.5 addition (coverage accounting, scan status, inventory scope, this section). |
| `README.md` | **Unreviewed for 1.5; one sentence changed by the port:** the development section now says the security scan runs the SQL/import lints, because the gate's scan mode runs them, and gives the scan's command as `node scripts/security-gate.mjs scan`, the command the CI security workflow starts, rather than `npm run security:scan`, as CONTRIBUTING and the engineering policy require. Two more sentences changed with the Git test requirement: the list of `TEST_REQUIRE` names adds `git`, and the full pre-release command adds it too. It does not yet link the engineering gates (finding 5 applies). |
| `docs/delivery.md` | **New in 1.5** with the read-only install planner (`deploy/install-plan.sh`): the Docker Compose and native Linux delivery requirements, their release gates and the stable image policy. Repository-only (not in `deploy/manifest.txt` or the in-app guides); not yet covered by the full documentation audit. |
| `docs/architecture.md`, `docs/authentication.md`, `docs/configuration.md`, `docs/installation.md`, `docs/integrations.md`, `docs/notifications.md`, `docs/security.md`, `docs/troubleshooting.md`, `examples/README.md`, `deploy/manifest.txt` | **Unreviewed for 1.5; unchanged by the port.** Whether maintenance findings 1–4 and 7 apply to the 1.5 text has not been checked. |

`npm run docs:check` on 1.5 requires the sign-in and notification guides, the delivery guide and the four policy documents as well as the maintenance list. It checks structure and local links only. The full documentation audit of the exact 1.5 candidate, with a disposition for every tracked document, remains required before any 1.5 commit or release is approved.

## Audit-start documentation hashes

SHA-256 of file bytes; all listed files were mode 0644 except `deploy/install-lxc.sh` (0755).

| File | SHA-256 |
|---|---|
| `AGENTS.md` | `e38e067fca8d4c52b6cd56a817baeec7d8948a6373169b780c912dbf3173927f` |
| `CHANGELOG.md` | `7e398de4fc8c9ac812b06e219c67b6be2f43040131623d199095909ab2d0e007` |
| `CONTRIBUTING.md` | `ffc148244f7b2aae5f2315da7aebebf224c549c2a6dac49084c32f197845d871` |
| `ORBIT-HANDOFF.md` | `b0821b2f1e3cb5af2327a1195735c63b513a859e6ac16f55b2f37eb0850e8977` |
| `README.md` | `d1e84df26e1e1e7436e649b474e2ef691191b09a82c55967ffd1b249ce09110f` |
| `SECURITY.md` | `3f4813f02fc99038cbc3470a1a887330f2fad9c29b0b55cddbd25ac317dce3b0` |
| `deploy/manifest.txt` | `3714276e5ed8c364137eb5d6a06fc78ae69430ffbe82c6eb3787c9f774a04360` |
| `docs/architecture.md` | `853839dda31cc90b06ee82fa0b68ddb022e1397d7f0ca4a51f3b559a3aea3f62` |
| `docs/configuration.md` | `e3a745f63242f04ce05c5777934b58f8c4df9e54b7d1677d125f5f00ce29ed6c` |
| `docs/installation.md` | `a38ab9d6b4497bbdc8b9d40eaaf0ddee85245b5a72689426249411a433b6b1f4` |
| `docs/integrations.md` | `0f852c10125c7d26131966c8ece4609d9454e18ea89a8bbd4aa144ad9fc0fdd2` |
| `docs/security.md` | `0b050e3382f48a1153045b2548485f42701b4b8b1a88fb4db18a82fc6c2cc222` |
| `docs/troubleshooting.md` | `0d53deaf73974996e4116e0fd22a7a0f010f308012c54d1e8ea99a3912231ee4` |
| `examples/README.md` | `09a6bda92ecbd6d4eea75dff3a12d58ca98883add08f80ce08fa51bb92b86b26` |
| `.env.example` | `420a7acee01cf8247585d99b6a9087527f67f94e787477924b68cccfac2f3c95` |
| `Dockerfile` | `50e60784b681beb3adf5de324675af8c85c082bc916e5623a8119007f4919a4a` |
| `compose.yaml` | `51edcfd38e927ad668207ded9f196da5baed08320f0f152f0a18615e4c36251f` |
| `deploy/allowed_signers` | `79d4d2fcc2f0d2b2c4acad8f394584be6b3c8bc05970502bfebc0c79ee4d750c` |
| `deploy/install-lxc.sh` | `d5d619ee8f28cdf6c08fd2172a2f8480cd44959c26628caf845b58cb363e80ba` |
| `deploy/orbit.service` | `658088885cb02db47c3eb7c01f4e390c10b38ba541dc6085bd8bae1e4cc4fb7b` |
| `examples/global-settings.json` | `537fd669b136acb8b2ec0d2a085bfa61a2fac9d06bc5bd6b34ed0685f486cd7b` |
| `examples/json-mappings.json` | `5da4659c1480aebc8a89db94729e7dde244b338af5080d7535d181c496d8b693` |
| `examples/linux-source.json` | `a8ae12e5065887ac5940e9ee75053ed1972a01b3406a143f47c4f8e8413bd77a` |
| `examples/prometheus-mappings.json` | `0e2350b75e0a2c44f2276ded1dd05d80bc71811f0b5d25bf12ace832499b3965` |
| `docs/engineering-quality.md` (new, untracked)  | `c39172a8db528d7780482850a3126dc3be7ef7f3ca2a1745bc53fde2f651e153` |

## Audit-start source references

These hashes identify selected implementation references; they do not imply a full source-security review.

| File | SHA-256 |
|---|---|
| `.github/workflows/ci.yml` | `b9a19cba2f8581fb030275d9127d32c187abb1b4158dd22a35b0df2b7bba95eb` |
| `lib/auth.mjs` | `a725ab8fd55002c98525c596a464edf2a849a0d3357a82af3024d5344c10541d` |
| `lib/config.mjs` | `8e3a9333537170b4f029bfd8798071055d9cc64b303b99bbb606dac879c6b64e` |
| `lib/destinations.mjs` | `fea4610cfc097dd818cdafd2f5eed95a69a2b9a11096bbf5ddf4472da8689cc0` |
| `lib/healthcheck.mjs` | `40910499570c76a08cf232d34b8e23fc1d3400c7686e83df867908164aad1b8a` |
| `lib/mail.mjs` | `f98c82a344d0627ba01516d2d392f2a7c3d8fc60a38ea7dcdf5f233bd107eba8` |
| `lib/store.mjs` | `c1135827789422df778bab0f039e3ec378514214eb0befd1365f78ee7e647c57` |
| `lib/throttle.mjs` | `0a3e571a02b33fcde4e0b48e6d387598c696b233d06948b81d92f6307c8a2121` |
| `package-lock.json` | `cb473dbe4082f9490c98411e3b1b4b18920a4226a6aeedad545880f9438065f6` |
| `package.json` | `2fa9ff102832614e0d35fcfe71e35434dde2d1c731f61d574841f9a08db8a9d7` |
| `scripts/package-release.mjs` | `f152c12cd6101676b91e301e23b8e7d48dc1b2252acc213c101d3dd359df231f` |
| `server.mjs` | `a90cc16fc3bf63dfe0c7500c980e8e56627359639b3888e0f6e4b9aae98dc112` |
