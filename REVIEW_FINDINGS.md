# Code Review Findings

## Remediation Status

Completed on 2026-04-09:

- `internal/webui`: fixed `pre_clean` quarantine ID handling, quarantine restore path validation, and bounded mutating JSON request decoding.
- `internal/firewall`: fixed temporary subnet expiry in live cleanup and persisted reload paths.
- `internal/checks`: fixed symlink and path-boundary issues in automated remediation and permission auto-fix paths.
- `internal/daemon`: fixed suppression ordering so suppressed findings no longer trigger auto-response before filtering.
- `internal/emailav`: fixed quarantine release destination validation and unknown ClamAV response handling.
- `internal/state`: fixed finding-key consistency for `Details` variants and path-based suppression matching.
- `internal/modsec`: fixed hidden bookkeeping-rule disablement through the apply API.
- `internal/yara`: fixed fail-open reload behavior by keeping staged reloads atomic.
- `internal/signatures`: fixed fail-open YAML reload behavior by keeping staged reloads atomic.
- `internal/attackdb`: fixed non-persisted deletions in the bbolt-backed store path.
- `internal/integrity`: fixed ignored scanner errors during stable config hashing.
- `internal/config`: fixed silent acceptance of unknown YAML keys.
- `internal/geoip`: fixed update success being reported before `.mmdb` validation.
- `internal/mime`: fixed unbounded message-body buffering before size checks.
- `pam`: fixed failed-login event reporting and hardened the local PAM event socket.

Completed on 2026-04-09 (second pass):

- `internal/firewall`: fixed expired temporary allow rules restored on startup; fixed allowlist source-collision by keying state entries on IP+Source so DynDNS, challenge, and manual allows coexist independently.
- `internal/challenge`: fixed Apache rewrite redirect to use `%{HTTP_HOST}` instead of hardcoded `127.0.0.1`; fixed X-Forwarded-For trust to only accept XFF from configured `trusted_proxies`; fixed reflected XSS in post-verification redirect by sanitizing and HTML-escaping the destination URL.
- `internal/checks`: fixed runner timeout cancellation leak by adding `context.Context` to `CheckFunc` signature and cancelling on timeout so leaked goroutines can exit.
- `internal/daemon` and `internal/emailav`: added configurable `fail_mode: tempfail` for email AV so operators can choose to defer mail delivery when all scan engines are unavailable.
- `internal/signatures`: added ed25519 signature verification for YAML and YARA Forge rule updates (`signing_key` config).
- `scripts`: added ed25519 signature verification framework to `install.sh`, `deploy.sh`, and `deploy-gitlab.sh`.

Still pending:

- None — all review findings addressed.

## Component 1: `internal/webui`

Reviewed on: 2026-04-09

### 1. High: WebUI lists `pre_clean` quarantine backups but all follow-up actions resolve IDs only in the root quarantine directory

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/webui/api.go:344`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L344) includes both `/opt/csm/quarantine` and `/opt/csm/quarantine/pre_clean` in the listing returned by `/api/v1/quarantine`.
  - [`internal/webui/account_api.go:65`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/account_api.go#L65) does the same for per-account quarantine views.
  - [`internal/checks/clean.go:40`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/clean.go#L40) creates those pre-clean backups under `/opt/csm/quarantine/pre_clean`.
  - [`internal/webui/api.go:987`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L987), [`internal/webui/api.go:1092`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1092), and [`internal/webui/api.go:1146`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1146) resolve restore/preview/delete requests only against `/opt/csm/quarantine/{id}`.
- Impact:
  - Every `pre_clean` backup surfaced in the UI is not actually restorable, previewable, or deletable through the same UI/API path.
  - Because IDs are flattened to just the basename, a future collision between a root quarantine entry and a `pre_clean` entry would make the action target ambiguous.
- Why it matters:
  - Incident-response tooling must be dependable. Presenting backup artifacts that the operator cannot safely act on is a reliability failure during remediation.

### 2. Medium: Quarantine restore trusts on-disk metadata for the destination path and then writes/chowns/chmods it as the daemon user

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/webui/api.go:1002`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1002) loads `original_path`, owner, group, and mode from the `.meta` sidecar.
  - [`internal/webui/api.go:1013`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1013) creates the parent directory for that path without constraining it.
  - [`internal/webui/api.go:1035`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1035), [`internal/webui/api.go:1046`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1046), and [`internal/webui/api.go:1068`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1068) then restore file contents and ownership directly to that metadata-supplied path.
- Impact:
  - If a quarantine metadata file is ever tampered with through another bug, local compromise, or operator mistake, the restore endpoint becomes an arbitrary file-write primitive with ownership/mode restoration.
- Why it matters:
  - This code runs in a privileged monitoring/remediation context. Restore paths should be validated against a trusted allowlist or derived from immutable internal state rather than a mutable sidecar file alone.

### 3. Medium: Most mutating WebUI JSON endpoints have no request-body size limit, so an authenticated caller can force unbounded decode/allocation work

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/webui/api.go:648`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L648) decodes bulk-fix requests without `http.MaxBytesReader`.
  - [`internal/webui/api.go:1299`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L1299) decodes full import bundles without a body cap.
  - [`internal/webui/threat_api.go:443`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L443) decodes bulk threat actions without a body cap.
  - By contrast, [`internal/webui/modsec_rules_api.go:138`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/modsec_rules_api.go#L138) already applies a body limit on a similar JSON POST endpoint.
- Impact:
  - The later item-count checks do not help against a very large JSON body because the decoder must consume and allocate it first.
  - A leaked token or malicious authenticated client can turn this into a straightforward memory-pressure / availability attack against the daemon.
- Why it matters:
  - For a security product, the admin plane should fail closed and cheaply under hostile input, especially on endpoints that trigger privileged actions.

### Verification

- `go test ./internal/webui/...`
- `go test ./internal/emailav/...`

## Component 2: `internal/firewall`

Reviewed on: 2026-04-09

### 1. High: temporary subnet blocks do not actually expire in the live firewall and are reloaded after restart

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/firewall/engine.go:261`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L261) creates `blocked_nets` as a permanent interval set with no timeout support.
  - [`internal/firewall/engine.go:1458`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1458) accepts a `timeout` for `BlockSubnet` and records `ExpiresAt`, but never programs an nftables timeout on the subnet elements.
  - [`internal/firewall/engine.go:1595`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1595) reloads all persisted blocked subnets on startup without checking `ExpiresAt`.
  - [`internal/firewall/engine.go:1621`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1621) only prunes expired single-IP blocks from `state.json`, not expired subnet entries.
  - [`internal/firewall/state.go:39`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/state.go#L39) does prune expired subnets for read-only state consumers, so the CLI/UI view can disagree with the live ruleset.
- Impact:
  - Any subnet entered as “temporary” can remain enforced indefinitely in nftables until someone manually removes it.
  - After restart, expired subnet blocks can be silently reinstalled even when higher-level status views no longer show them.
- Why it matters:
  - This is a lockout-class reliability defect in the security enforcement plane. Operators will believe a temporary mitigation expired when the packet filter may still be dropping traffic.

### 2. Medium: expired temporary allow rules are restored on startup and can remain active for up to 10 more minutes

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/firewall/engine.go:1582`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1582) restores every persisted allowed IP into nftables on startup with no expiry check.
  - [`internal/firewall/engine.go:1621`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1621) does not prune expired `Allowed` entries from the state file.
  - [`internal/firewall/engine.go:1327`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1327) only removes expired temp allows when `CleanExpiredAllows()` runs.
  - [`internal/daemon/daemon.go:573`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L573) schedules that cleanup on a 10-minute heartbeat.
- Impact:
  - A temporary allow that should already be dead is revived on daemon restart and remains effective until the next cleanup tick.
  - The window is long enough to matter for incident response, especially when temporary challenge bypasses or customer whitelists are involved.
- Why it matters:
  - Temporary trust decisions need strict expiry semantics. Re-activating expired allows after restart weakens the firewall exactly when the service is recovering from disruption.

### 3. Medium: allowlist state is keyed only by IP, so different trust sources overwrite and delete each other

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/firewall/engine.go:1680`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1680) overwrites any existing `AllowedEntry` solely by matching `existing.IP == entry.IP`.
  - [`internal/firewall/engine.go:1696`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1696) removes all allow state for an IP without checking source or reason.
  - [`internal/firewall/dyndns.go:79`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/dyndns.go#L79) removes old DynDNS resolutions with `RemoveAllowIP(ip)` and [`internal/firewall/dyndns.go:95`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/dyndns.go#L95) adds new ones with the same generic `AllowIP`.
  - [`internal/firewall/engine.go:1292`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/firewall/engine.go#L1292) uses the same storage path for temporary allows.
- Impact:
  - A DynDNS refresh can delete a manually-added allow or whitelist if they happen to reference the same IP.
  - A temporary allow can overwrite a permanent allow for the same IP, and when the temporary entry expires, `CleanExpiredAllows()` removes the allow entirely.
- Why it matters:
  - Security exceptions from different sources need separate identity and lifecycle management. Collapsing them into one IP-keyed record makes the firewall state non-deterministic under normal admin workflows.

### Verification

- `go test ./internal/firewall/...`

## Component 3: `internal/challenge`

Reviewed on: 2026-04-09

### 1. High: the shipped Apache rewrite example redirects challenged clients to `127.0.0.1:8439`, which points to the client’s localhost, not the server

Status: Completed on 2026-04-09

- Evidence:
  - [`configs/csm_challenge.conf:24`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/configs/csm_challenge.conf#L24) issues `RewriteRule ... http://127.0.0.1:8439/challenge?... [R=307,L]`.
  - [`docs/src/challenge.md:7`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/docs/src/challenge.md#L7) documents challenge pages as a working end-user flow.
- Impact:
  - If deployed as written, browsers are redirected to their own loopback interface instead of the server-side challenge service, so the fallback application-level challenge flow cannot work for remote users.
- Why it matters:
  - This is a user-facing integration path for a security control. A broken redirect path means challenged traffic is effectively denied rather than recoverably verified.

### 2. Medium: challenge verification trusts `X-Forwarded-For` blindly while granting firewall allow rules

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/challenge/server.go:59`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L59) binds the challenge server on all interfaces for `listen_port`.
  - [`internal/challenge/server.go:99`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L99) uses `extractIP(r)` to bind verification to an IP.
  - [`internal/challenge/server.go:129`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L129) converts a successful challenge directly into `TempAllowIP(ip, "passed challenge", 4h)`.
  - [`internal/challenge/server.go:187`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L187) trusts the first `X-Forwarded-For` value with no proxy allowlist or source check.
- Impact:
  - If the challenge port is ever exposed directly or proxied incorrectly, an attacker can spoof `X-Forwarded-For`, solve the PoW for that spoofed address, and temporarily allow a victim IP through the firewall.
- Why it matters:
  - This endpoint mints firewall exceptions. Trusting a spoofable header at that boundary is too weak unless the server is strictly bound to localhost or enforces a trusted-proxy policy.

### 3. Medium: the post-verification redirect target is reflected into HTML without validation or escaping

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/challenge/page.go:75`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/page.go#L75) submits `dest: window.location.href`.
  - [`internal/challenge/server.go:152`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L152) accepts `dest` from the POST body.
  - [`internal/challenge/server.go:157`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/challenge/server.go#L157) injects that value directly into a `meta refresh` attribute.
- Impact:
  - A crafted POST can turn `/challenge/verify` into an open redirect, and HTML-breaking payloads can potentially become reflected XSS in the challenge origin.
- Why it matters:
  - Even auxiliary security flows need strict output handling. Redirect targets should be normalized to same-origin relative paths or escaped before being embedded in HTML.

### Verification

- `go test ./internal/challenge/...` (`[no test files]`)

## Component 4: `internal/checks`

Reviewed on: 2026-04-09

### 1. High: automatic permission fixing follows symlinks and mutates the resolved target, while the safer manual fixer explicitly blocks that escape

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/checks/autoresponse.go:251`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/autoresponse.go#L251) handles `world_writable_php` and `group_writable_php` findings by extracting a path from the finding message.
  - [`internal/checks/autoresponse.go:268`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/autoresponse.go#L268), [`internal/checks/autoresponse.go:273`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/autoresponse.go#L273), and [`internal/checks/autoresponse.go:279`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/autoresponse.go#L279) only check that the raw string starts with `/home/`, then call `os.Stat` and `os.Chmod` on that path. `os.Stat` follows symlinks.
  - By contrast, [`internal/checks/remediate.go:111`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L111) through [`internal/checks/remediate.go:124`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L124) resolve symlinks and refuse paths that escape `/home/` before chmodding.
  - The scan side can emit these finding types from user-controlled trees under `/home`, e.g. [`internal/checks/filesystem.go:246`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/filesystem.go#L246) and [`internal/checks/system.go:232`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/system.go#L232).
- Impact:
  - A symlinked PHP finding under `/home` can cause the auto-response path to chmod the symlink target rather than the path the operator expects.
  - Because this runs automatically in the privileged daemon path, it is a stronger primitive than the manual fix flow and can modify files outside the intended account boundary.
- Why it matters:
  - Auto-remediation has to be stricter than manual remediation, not weaker. Following attacker-controlled symlinks in a root-run permission fixer is a privilege-boundary failure.

### 2. High: the fix pipeline still trusts UI-supplied message text for the target path, and the `.htaccess` cleaner rewrites that path without any symlink or boundary validation

Status: Completed on 2026-04-09

- Evidence:
  - Findings already carry a structured path in [`internal/alert/alert.go:37`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/alert/alert.go#L37) through [`internal/alert/alert.go:45`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/alert/alert.go#L45).
  - The `.htaccess` scanner populates that field in [`internal/checks/web.go:241`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/web.go#L241) through [`internal/checks/web.go:268`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/web.go#L268).
  - The WebUI fix endpoint in [`internal/webui/api.go:607`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L607) through [`internal/webui/api.go:622`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L622) accepts only `check`, `message`, and `details`, and the UI sends only those fields in [`ui/static/js/findings.js:413`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L413) through [`ui/static/js/findings.js:415`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L415) and [`ui/static/js/findings.js:482`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L482) through [`ui/static/js/findings.js:483`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L483).
  - [`internal/checks/remediate.go:84`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L84) through [`internal/checks/remediate.go:97`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L97) derive the action target by parsing the human-readable message, and [`internal/checks/remediate.go:311`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L311) through [`internal/checks/remediate.go:327`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L327) accept the first `/home/`, `/tmp/`, `/dev/shm/`, or `/var/tmp/` substring they find.
  - The `.htaccess` fixer then reads and rewrites that parsed path in [`internal/checks/remediate.go:243`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L243) through [`internal/checks/remediate.go:300`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/remediate.go#L300) without `EvalSymlinks`, `Lstat`, or any trusted-boundary check.
- Impact:
  - An authenticated WebUI client does not have to operate on a real stored finding. It can submit a synthetic `check` + `message` pair that points the fixer at any parseable path under the accepted prefixes.
  - For `.htaccess` fixes in particular, a symlink under `/home` can turn this into a privileged arbitrary-file rewrite primitive against the symlink target.
- Why it matters:
  - This is privileged remediation code in an exposed admin plane. The action target should come from trusted structured state, not reparsed display text supplied back by the client.

### 3. Medium: timed-out checks are abandoned without cancellation, so long-running scans continue in leaked goroutines after the runner reports them as timed out

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/checks/runner.go:193`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/runner.go#L193) through [`internal/checks/runner.go:212`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/runner.go#L212) wrap each check in a second goroutine and wait on a `done` channel.
  - [`internal/checks/runner.go:221`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/runner.go#L221) through [`internal/checks/runner.go:229`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/runner.go#L229) emit a timeout finding after 5 minutes, but they do not signal cancellation to the underlying check.
  - The `CheckFunc` signature in [`internal/checks/runner.go:14`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/checks/runner.go#L14) has no context/cancel channel at all.
- Impact:
  - A pathological or attacker-inflated tree can keep filesystem-heavy checks running indefinitely even after the scheduler has moved on.
  - Repeated timeout cycles can accumulate orphaned scan work and unpredictable I/O pressure, which undermines daemon responsiveness during incidents.
- Why it matters:
  - In a monitoring daemon, “timed out” needs to mean the work actually stops. Otherwise timeout handling becomes cosmetic while resource exhaustion continues in the background.

### Verification

- `go test ./internal/checks/...`

## Component 5: `internal/daemon`

Reviewed on: 2026-04-09

### 1. High: suppression rules do not suppress daemon auto-response, so known false positives can still challenge, block, or chmod before they are filtered out

Status: Completed on 2026-04-09

- Evidence:
  - Suppressions are documented as a way to “silence known false positives” in [`docs/src/signatures.md:118`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/docs/src/signatures.md#L118) through [`docs/src/signatures.md:122`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/docs/src/signatures.md#L122).
  - The daemon runs challenge routing, IP blocking, and automatic permission fixing before it loads or applies suppression rules in [`internal/daemon/daemon.go:363`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L363) through [`internal/daemon/daemon.go:372`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L372).
  - Suppressions are only applied later, to `newFindings` used for alerting, in [`internal/daemon/daemon.go:388`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L388) through [`internal/daemon/daemon.go:408`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L408).
  - The startup baseline path in [`internal/daemon/daemon.go:166`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L166) through [`internal/daemon/daemon.go:185`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L185) also executes auto-response without consulting stored suppressions first.
  - The suppression matcher itself is path/check based and intended for active findings in [`internal/state/state.go:688`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L688) through [`internal/state/state.go:713`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L713).
- Impact:
  - A suppressed false positive can still auto-block an IP, place an IP onto the PoW challenge path, or chmod a file before the finding disappears from alerts/UI.
  - On restart, baseline findings can trigger those same actions again even though the operator already created a suppression rule for them.
- Why it matters:
  - In a security product, suppression of a known false positive has to suppress enforcement too, or the operator loses the only safe control they have to stop repeated self-inflicted actions.

### 2. Medium: the email AV spool watcher is explicitly fail-open on parser, scanner, and quarantine failures, so malicious mail can still be delivered when enforcement is degraded

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/daemon/spoolwatch.go:85`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L85) through [`internal/daemon/spoolwatch.go:99`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L99) fall back to notification-only mode when permission events are unavailable and log that a delivery race window is possible.
  - [`internal/daemon/spoolwatch.go:304`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L304) through [`internal/daemon/spoolwatch.go:316`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L316) allow delivery on MIME parse errors.
  - [`internal/daemon/spoolwatch.go:333`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L333) through [`internal/daemon/spoolwatch.go:357`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L357) warn when all engines are down or timed out, but still allow delivery; they also allow delivery if quarantine fails.
  - The scanner orchestrator is explicitly fail-open for unavailable engines, timeouts, and scan errors in [`internal/emailav/orchestrator.go:27`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L27) through [`internal/emailav/orchestrator.go:29`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L29), [`internal/emailav/orchestrator.go:49`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L49) through [`internal/emailav/orchestrator.go:52`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L52), and [`internal/emailav/orchestrator.go:109`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L109) through [`internal/emailav/orchestrator.go:114`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L114).
- Impact:
  - Malformed MIME, engine outages, scan timeouts, or quarantine-path failures all turn the enforcement path into “deliver and warn later.”
  - On hosts where `FAN_OPEN_PERM` is unavailable, mail delivery also has a built-in race window before scanning can react.
- Why it matters:
  - For a security control intended to stop malicious email, these branches create practical bypass conditions under stress or targeted fault induction, exactly when the enforcement path needs to be strongest.

### Verification

- `go test ./internal/daemon/...`

## Component 6: `internal/emailav`

Reviewed on: 2026-04-09

### 1. High: email quarantine release trusts `metadata.json` for the restore destination and moves quarantined spool files there without validating the path

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/emailav/quarantine.go:53`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L53) through [`internal/emailav/quarantine.go:63`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L63) persist `OriginalSpoolDir` inside `metadata.json`.
  - [`internal/emailav/quarantine.go:133`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L133) through [`internal/emailav/quarantine.go:149`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L149) read that metadata back and construct the restore destination as `filepath.Join(meta.OriginalSpoolDir, msgID+suffix)`.
  - [`internal/emailav/quarantine.go:191`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L191) through [`internal/emailav/quarantine.go:202`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L202) accept the sidecar metadata as authoritative with no trusted-boundary check.
  - [`internal/emailav/quarantine.go:205`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L205) through [`internal/emailav/quarantine.go:216`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/quarantine.go#L216) perform the actual move or copy-back to that path.
- Impact:
  - If `metadata.json` is tampered with, releasing a quarantined message becomes an arbitrary file-write primitive using privileged daemon code.
  - Because both `-H` and `-D` files are restored, the primitive can write two attacker-chosen files under the supplied directory.
- Why it matters:
  - Quarantine release is a privileged recovery operation. Its destination has to be derived from trusted internal state or strictly validated against known Exim spool roots, not from a mutable sidecar alone.

### 2. High: attachment parsing intentionally skips malformed or over-limit content and returns a partial-but-successful result, so malicious payloads can be delivered unscanned

Status: Partially addressed on 2026-04-09

- Evidence:
  - [`internal/mime/parser.go:89`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L89) through [`internal/mime/parser.go:103`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L103) treat unparseable MIME structure as a successful parse with no extracted attachments.
  - [`internal/mime/parser.go:307`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L307) through [`internal/mime/parser.go:316`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L316) skip individual attachment parts on decode errors or size overflow.
  - [`internal/mime/parser.go:364`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L364) through [`internal/mime/parser.go:403`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L403) and [`internal/mime/parser.go:441`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L441) through [`internal/mime/parser.go:466`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L466) stop archive extraction once file-count or total-size limits are hit, again without turning the message into a blocking failure.
  - The scanner layer only marks mail infected when extracted parts produce findings in [`internal/emailav/orchestrator.go:27`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L27) through [`internal/emailav/orchestrator.go:29`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L29) and [`internal/emailav/orchestrator.go:55`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L55) through [`internal/emailav/orchestrator.go:63`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/orchestrator.go#L55).
  - The intended behavior is covered by [`internal/mime/parser_test.go:78`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser_test.go#L78) through [`internal/mime/parser_test.go:96`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser_test.go#L96), which expects an oversize attachment to be skipped while the parse still succeeds.
- Impact:
  - An attacker can place payloads beyond attachment-size limits, beyond archive expansion limits, or inside malformed MIME structures and rely on the system to deliver the message with only a partial/non-fatal parse state.
  - This turns the configured limits into a content-evasion mechanism rather than a safe failure mode.
- Why it matters:
  - For a mail malware control, “could not fully inspect” is not equivalent to “clean.” Open-source attackers will actively tune payload shape to the parser’s skip behavior once it is visible.

### 3. Medium: the ClamAV adapter silently treats unknown daemon responses as clean instead of surfacing an error

Status: Completed on 2026-04-09

- Evidence:
  - [`internal/emailav/clamav.go:91`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav.go#L91) through [`internal/emailav/clamav.go:98`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav.go#L98) return whatever `parseClamdResponse` produces without distinguishing protocol errors from clean results.
  - [`internal/emailav/clamav.go:104`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav.go#L104) through [`internal/emailav/clamav.go:120`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav.go#L120) recognize only `OK` and `FOUND`; every other response is converted to `Verdict{Infected:false}`.
  - The current tests in [`internal/emailav/clamav_test.go:49`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav_test.go#L49) through [`internal/emailav/clamav_test.go:97`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/emailav/clamav_test.go#L97) cover only clean and infected responses, not daemon error strings.
- Impact:
  - Protocol errors, size-limit errors, or unexpected clamd responses can be misclassified as clean mail instead of degraded scanning.
  - That removes even the warning signal the higher layers depend on for fail-open visibility.
- Why it matters:
  - Security enforcement should never silently downgrade “scanner error” to “clean.” Unknown AV replies need to propagate as errors so operators can detect and respond to broken scanning.

### Verification

- `go test ./internal/emailav/... ./internal/mime/...`

## Component 7: `internal/state`

Reviewed on: 2026-04-09

### 1. High: finding dismissal and state lookups use a different key than the dedup store, so findings with `Details` can evade dismissal and lose their real history

Status: Completed on 2026-04-09

- Evidence:
  - The state store persists findings under `findingKey(f)`, and that key changes when `Details` is present by appending a truncated hash in [`internal/state/state.go:112`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L112) through [`internal/state/state.go:119`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L119).
  - The public/UI-facing key on `alert.Finding` is still only `check:message` in [`internal/alert/alert.go:61`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/alert/alert.go#L61) through [`internal/alert/alert.go:63`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/alert/alert.go#L63).
  - The WebUI history overlay looks up persistent first/last-seen timestamps by calling `EntryForKey(f.Key())` in [`internal/webui/api.go:70`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L70) through [`internal/webui/api.go:75`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L75), while `EntryForKey` performs an exact map lookup in [`internal/state/state.go:370`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L370) through [`internal/state/state.go:378`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L378).
  - The dismiss API only accepts a raw `key` string in [`internal/webui/api.go:956`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L956) through [`internal/webui/api.go:965`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/api.go#L965), and the findings UI submits `check + ':' + message` in [`ui/static/js/findings.js:493`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L493) through [`ui/static/js/findings.js:496`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L496).
  - `DismissFinding` then marks baseline only if that exact key exists in the store map in [`internal/state/state.go:626`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L626) through [`internal/state/state.go:633`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L633).
- Impact:
  - Any finding whose dedup entry was stored under the details-hashed key can miss `EntryForKey`, so the UI falls back to the current timestamp instead of the real first/last-seen history.
  - More importantly, dismissing that finding from the UI can fail to baseline the actual stored entry, so it will reappear on later scans even though the operator already dismissed it.
- Why it matters:
  - Dismissal and dedup state are operator trust controls. If they become inconsistent for a subset of findings, open-source attackers can keep noisy findings recurring, and operators lose confidence that the product is honoring their actions.

### 2. Medium: path-based suppressions created from the findings UI do not match message-only findings reliably, because the matcher compares the pattern to the full message text instead of the extracted path

Status: Completed on 2026-04-09

- Evidence:
  - When a finding has no `filePath`, the findings UI extracts a bare `/path/...` fragment from the message and uses that as the default suppression pattern in [`ui/static/js/findings.js:437`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L437) through [`ui/static/js/findings.js:452`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/findings.js#L452).
  - The suppression matcher checks `f.FilePath` first, but for message-only findings it falls back to `filepath.Match(rule.PathPattern, f.Message)` in [`internal/state/state.go:696`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L696) through [`internal/state/state.go:709`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/state/state.go#L709).
  - A pattern like `/home/user/site/*` will not match a full message string such as `YARA rule match: /home/user/site/index.php`, even though that is exactly the path the UI suggested to the operator.
- Impact:
  - Suppression rules created from the UI can silently fail for legacy or message-only findings, leaving operators with repeated alerts they believed they had scoped away.
  - In the daemon, those same findings also remain eligible for downstream handling because the suppression matcher never hits.
- Why it matters:
  - Suppressions are one of the few precise controls an operator has in an exposed security product. A path-scoped rule that looks valid but never matches is a reliability and operational safety problem.

### Verification

- `go test ./internal/state/...`
- `go test ./internal/store/...`

## Component 10: `internal/modsec`

Reviewed on: 2026-04-09

### 1. Medium: the ModSecurity apply API accepts hidden counter rules, so a direct caller can disable bookkeeping rules that visible rate-limit rules depend on while the UI still shows the visible rule as enabled

Status: Completed on 2026-04-09

- Evidence:
  - Counter rules are explicitly identified as `pass,nolog` bookkeeping rules in [`internal/modsec/parser.go:176`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/modsec/parser.go#L176) through [`internal/modsec/parser.go:179`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/modsec/parser.go#L179).
  - The ModSecurity rules API hides those counter rules from the UI by skipping `r.IsCounter` in [`internal/webui/modsec_rules_api.go:79`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/modsec_rules_api.go#L79) through [`internal/webui/modsec_rules_api.go:82`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/modsec_rules_api.go#L82).
  - But the apply endpoint validates requested disabled IDs against *all* parsed rules, including hidden counters, by adding every parsed rule to `knownIDs` in [`internal/webui/modsec_rules_api.go:151`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/modsec_rules_api.go#L151) through [`internal/webui/modsec_rules_api.go:159`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/modsec_rules_api.go#L159).
  - The shipped ModSecurity config includes hidden counter rules that feed visible deny rules, for example XML-RPC brute-force tracking in [`configs/csm_modsec_custom.conf:32`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/configs/csm_modsec_custom.conf#L32) through [`configs/csm_modsec_custom.conf:39`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/configs/csm_modsec_custom.conf#L39), and `wp-login.php` brute-force tracking in [`configs/csm_modsec_custom.conf:134`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/configs/csm_modsec_custom.conf#L134) through [`configs/csm_modsec_custom.conf:141`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/configs/csm_modsec_custom.conf#L141).
- Impact:
  - A direct API client can disable rule `900006` or `900113`, leaving the visible deny rule `900007` or `900114` still present in the UI but functionally neutered because the IP counters are never incremented.
  - That creates a misleading admin view where a protection appears enabled while its prerequisite logic has been removed.
- Why it matters:
  - Hidden implementation rules should not be user-disableable through the same public API unless the UI exposes that dependency clearly. Otherwise the management plane itself becomes a way to silently degrade WAF coverage.

### Verification

- `go test ./internal/modsec/...`

## Component 11: `internal/yara`

Reviewed on: 2026-04-09

### 1. Medium: YARA reload is fail-open and can silently keep stale or partial rule state while the daemon and UI report success

Status: Completed on 2026-04-09

- Evidence:
  - `Reload` logs per-file read/compile errors to stderr and simply skips those files in [`internal/yara/scanner.go:61`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/scanner.go#L61) through [`internal/yara/scanner.go:72`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/scanner.go#L72), but it does not return an error as long as at least one file compiled.
  - If zero rule files compile, `Reload` returns `nil` early in [`internal/yara/scanner.go:75`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/scanner.go#L75) through [`internal/yara/scanner.go:77`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/scanner.go#L77) without clearing `s.rules` or `s.ruleCount`, so previously loaded rules remain active.
  - The daemon treats a nil error as a successful reload and logs the current rule count in [`internal/daemon/daemon.go:1374`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1374) through [`internal/daemon/daemon.go:1379`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1379).
  - The WebUI reload endpoint also trusts only the returned error in [`internal/webui/rules_api.go:121`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/rules_api.go#L121) through [`internal/webui/rules_api.go:143`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/rules_api.go#L121), and the client shows a success toast when no error is returned in [`ui/static/js/rules.js:49`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/rules.js#L49) through [`ui/static/js/rules.js:56`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/rules.js#L56).
  - Startup has the same blind spot: `Init` installs the scanner even if no rules compiled, and the daemon logs “YARA-X scanner active” based only on a non-nil scanner in [`internal/yara/global.go:20`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/global.go#L20) through [`internal/yara/global.go:28`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/yara/global.go#L28) and [`internal/daemon/daemon.go:99`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L99) through [`internal/daemon/daemon.go:100`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L99).
- Impact:
  - A malformed or unreadable `.yar` file can silently remove just that protection from the live engine while reload still reports success.
  - If the rules directory is emptied or all rules stop compiling, the process can keep scanning with stale previously compiled rules instead of failing closed or unloading cleanly, leaving operators with a false view of what is actually enforced.
- Why it matters:
  - For a security engine, rule reload has to be auditable and exact. Silent partial loads and stale-state retention are bypass-friendly because they hide coverage loss behind a “reload succeeded” control path.

### Verification

- `go test ./internal/yara/...`

## Component 12: `internal/signatures`

Reviewed on: 2026-04-09

### 1. Medium: YAML signature reload is fail-open on bad files, so malformed or unreadable rule files can silently reduce coverage while reload still reports success

Status: Completed on 2026-04-09

- Evidence:
  - The YAML scanner skips unreadable files in [`internal/signatures/loader.go:86`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L86) through [`internal/signatures/loader.go:90`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L86), parse failures in [`internal/signatures/loader.go:93`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L93) through [`internal/signatures/loader.go:97`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L97), and per-rule compile failures in [`internal/signatures/loader.go:103`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L103) through [`internal/signatures/loader.go:108`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L103), but still returns `nil`.
  - After skipping those failures, `Reload` replaces the active ruleset with whatever partial set remains in [`internal/signatures/loader.go:117`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L117) through [`internal/signatures/loader.go:124`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/loader.go#L124).
  - The daemon treats a nil return as a successful reload in [`internal/daemon/daemon.go:1364`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1364) through [`internal/daemon/daemon.go:1370`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1370).
  - The WebUI reload endpoint also relies only on that returned error in [`internal/webui/rules_api.go:114`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/rules_api.go#L114) through [`internal/webui/rules_api.go:143`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/rules_api.go#L114), and the client shows “Rules reloaded successfully” when no error is reported in [`ui/static/js/rules.js:49`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/rules.js#L49) through [`ui/static/js/rules.js:56`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/ui/static/js/rules.js#L56).
- Impact:
  - A malformed or unreadable YAML rule file can silently remove just those detections from the live engine while operator-facing reload paths still look successful.
  - If all YAML files fail to parse or compile, the scanner is replaced with an empty ruleset and the product degrades to zero YAML coverage without surfacing a hard failure.
- Why it matters:
  - In a detection engine, reload should be exact and auditable. Silent partial loads are bypass-friendly because they hide rule loss behind a healthy-looking control path.

### 2. Medium: automatic rule updates trust remote content for policy changes without any cryptographic authenticity check beyond transport success

Status: Completed on 2026-04-09

- Evidence:
  - The YAML updater fetches the configured `update_url` directly over HTTP(S) in [`internal/signatures/updater.go:22`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/updater.go#L22) through [`internal/signatures/updater.go:37`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/updater.go#L22), then accepts and installs the result if it parses and regex-compiles in [`internal/signatures/updater.go:39`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/updater.go#L39) through [`internal/signatures/updater.go:71`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/updater.go#L71).
  - The daemon runs that updater automatically on a timer in [`internal/daemon/daemon.go:1233`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1233) through [`internal/daemon/daemon.go:1302`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1302).
  - The Forge updater similarly trusts the latest GitHub release metadata and downloaded ZIP asset in [`internal/signatures/forge.go:37`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/forge.go#L37) through [`internal/signatures/forge.go:56`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/forge.go#L56), and installs it after compile validation in [`internal/signatures/forge.go:64`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/forge.go#L64) through [`internal/signatures/forge.go:87`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/signatures/forge.go#L87).
- Impact:
  - Anyone who can control the configured update endpoint, or compromise the upstream content source, can push a syntactically valid but detection-weakening ruleset that is automatically installed by the daemon.
  - Because the only acceptance gate is “parses and compiles,” the update channel can be used to disable detections, create noisy false positives, or reshape enforcement policy without any signed trust root.
- Why it matters:
  - For a security product, the rule-update path is part of the trust boundary. Syntax validation is not enough; policy updates need authenticity guarantees if they are going to be fetched and installed unattended.

### Verification

- `go test ./internal/signatures/...`

## Component 13: `internal/attackdb`

Reviewed on: 2026-04-09

### 1. Medium: attack DB deletions are not persisted to the bbolt store, so removed or expired IP records come back after restart

Status: Completed on 2026-04-09

- Evidence:
  - The in-memory removal path only deletes from `db.records` and marks the DB dirty in [`internal/attackdb/db.go:437`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/db.go#L437) through [`internal/attackdb/db.go:442`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/db.go#L442).
  - Expiry pruning also only deletes from the in-memory map in [`internal/attackdb/db.go:450`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/db.go#L450) through [`internal/attackdb/db.go:459`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/db.go#L459).
  - When persistence uses the bbolt-backed store, `saveRecords` only calls `SaveIPRecord` for records that still exist in memory in [`internal/attackdb/persist.go:72`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/persist.go#L72) through [`internal/attackdb/persist.go:97`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/persist.go#L72).
  - The store layer does provide a delete primitive in [`internal/store/attacks.go:192`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/store/attacks.go#L192) through [`internal/store/attacks.go:197`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/store/attacks.go#L197), but attackdb never uses it.
  - On the next startup, `load()` repopulates attackdb from every persisted store record in [`internal/attackdb/persist.go:22`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/persist.go#L22) through [`internal/attackdb/persist.go:45`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/attackdb/persist.go#L22).
  - The WebUI relies on `RemoveIP` for whitelist and cleanup actions in [`internal/webui/threat_api.go:195`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L195) through [`internal/webui/threat_api.go:199`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L199), [`internal/webui/threat_api.go:345`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L345) through [`internal/webui/threat_api.go:348`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L345), and [`internal/webui/threat_api.go:414`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L414) through [`internal/webui/threat_api.go:417`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/webui/threat_api.go#L414).
- Impact:
  - IPs the operator explicitly removes from the attack DB can reappear after daemon restart and continue contributing stale threat intelligence.
  - Expired entries that should have aged out can also be resurrected from persistent state, undermining pruning and operator cleanup actions.
- Why it matters:
  - Threat-state cleanup needs to be authoritative. If “remove from attack DB” is only temporary until restart, operators cannot reliably clear false positives or stale attacker history.

## Component 14: `internal/integrity`

Reviewed on: 2026-04-09

### 1. Medium: config integrity hashing ignores scanner errors, so oversized lines can turn verification into a partial-file hash and let later config changes bypass detection

Status: Completed on 2026-04-09

- Evidence:
  - `HashConfigStable` reads the config with a default `bufio.Scanner` in [`internal/integrity/integrity.go:39`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/integrity/integrity.go#L39) through [`internal/integrity/integrity.go:42`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/integrity/integrity.go#L42), without increasing the scanner buffer.
  - It hashes each scanned line in [`internal/integrity/integrity.go:58`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/integrity/integrity.go#L58) but never checks `scanner.Err()` before returning the digest in [`internal/integrity/integrity.go:61`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/integrity/integrity.go#L61).
  - Both baseline/rehash and verification rely on that function in [`cmd/csm/main.go:471`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L471) through [`cmd/csm/main.go:474`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L474), [`cmd/csm/main.go:491`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L491) through [`cmd/csm/main.go:494`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L491), and [`cmd/csm/main.go:571`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L571) through [`cmd/csm/main.go:577`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/cmd/csm/main.go#L571).
- Impact:
  - If `csm.yaml` contains a line longer than the scanner token limit, hashing can stop early and still return a “valid” digest for only the prefix it managed to read.
  - An attacker who can place or preserve an oversized line in the config can potentially modify content after that point without changing the stored integrity hash comparison outcome.
- Why it matters:
  - Integrity verification has to fail safely. Returning a partial hash on read failure weakens the very tamper check that is supposed to stop configuration bypass.

### Verification

- `go test ./internal/attackdb/... ./internal/auditd/... ./internal/integrity/...`

## Component 15: `internal/config`

Reviewed on: 2026-04-09

### 1. Medium: config loading silently ignores unknown YAML keys, so typos in security-critical settings can disable protections without any load-time failure

Status: Completed on 2026-04-09

- Evidence:
  - Config loading uses plain `yaml.Unmarshal` in [`internal/config/config.go:180`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/config.go#L180) through [`internal/config/config.go:189`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/config.go#L180).
  - There is no strict decoding path such as `KnownFields`, `yaml.NewDecoder`, or any post-load unknown-key detection anywhere in `internal/config` (confirmed by code search of the package).
  - Validation only examines the fields that were successfully loaded into the struct in [`internal/config/validate.go:25`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/validate.go#L25) through [`internal/config/validate.go:176`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/validate.go#L25), so misspelled or obsolete keys are invisible to the validator too.
- Impact:
  - A typo in a protection-setting key such as a block/timeout/rules path/auth token field can be accepted silently, with the program falling back to defaults or zero values instead of rejecting the config.
  - Because the daemon continues to start, operators can believe a control is enabled or tuned when the running process has actually ignored that setting.
- Why it matters:
  - In a security product, configuration mistakes should fail loudly. Silent acceptance of unknown keys is a reliability and hardening problem because it turns simple misconfiguration into invisible loss of protection.

## Component 16: `internal/geoip`

Reviewed on: 2026-04-09

### 1. Medium: GeoIP updater marks databases as updated without validating that the extracted `.mmdb` is actually loadable, so operator-visible success can mask a broken database

Status: Completed on 2026-04-09

- Evidence:
  - The updater downloads and extracts the archive, then installs the extracted file by rename in [`internal/geoip/updater.go:94`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/geoip/updater.go#L94) through [`internal/geoip/updater.go:135`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/geoip/updater.go#L94).
  - `extractMMDB` only checks for a tar member with the expected filename suffix and copies it to disk in [`internal/geoip/updater.go:138`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/geoip/updater.go#L138) through [`internal/geoip/updater.go:179`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/geoip/updater.go#L138); it never verifies that the result can be opened as a MaxMind DB.
  - `EditionResult{Status:"updated"}` is returned immediately after rename in [`internal/geoip/updater.go:135`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/geoip/updater.go#L135), before any `maxminddb.Open` validation.
  - The daemon logs that success in [`internal/daemon/daemon.go:1117`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1117) through [`internal/daemon/daemon.go:1123`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1117), then only later attempts to reload readers in [`internal/daemon/daemon.go:1038`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1038) through [`internal/daemon/daemon.go:1047`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L1038).
- Impact:
  - A truncated, wrong, or otherwise invalid `.mmdb` can be reported as a successful update even though the runtime GeoIP database cannot actually use it.
  - On a first-time install this can leave GeoIP unavailable despite a logged “updated” result; on an existing install it can keep stale readers in place while the on-disk file is broken.
- Why it matters:
  - Update success needs to mean “the new database is usable,” not merely “a file with the right name was written.” Otherwise operator-facing health signals become unreliable and troubleshooting coverage loss gets much harder.

### Verification

- `go test ./internal/config/... ./internal/geoip/...`

## Component 17: `internal/mime`

Reviewed on: 2026-04-09

### 1. Medium: MIME parsing reads and decodes attacker-controlled message bodies before enforcing the configured size limits, which leaves the mail path open to memory-pressure DoS

Status: Completed on 2026-04-09

- Evidence:
  - `ParseSpoolMessage` loads the entire Exim body file into memory with `os.ReadFile` in [`internal/mime/parser.go:70`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L70) through [`internal/mime/parser.go:73`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L73), before any attachment or extraction limit is applied.
  - For single-part non-text messages, the parser fully base64- or quoted-printable-decodes the body into memory with `io.ReadAll` in [`internal/mime/parser.go:109`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L109) through [`internal/mime/parser.go:118`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L118), and only afterwards compares `len(decoded)` to `MaxAttachmentSize` in [`internal/mime/parser.go:120`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/mime/parser.go#L120).
  - The spool watcher feeds attacker-controlled mail directly into that parser in [`internal/daemon/spoolwatch.go:304`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L304) through [`internal/daemon/spoolwatch.go:317`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/spoolwatch.go#L317).
  - The email AV config advertises hard limits such as `MaxAttachmentSize` and `MaxExtractionSize` in [`internal/config/emailav.go:38`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/emailav.go#L38) through [`internal/config/emailav.go:49`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/config/emailav.go#L49), but those limits do not constrain the up-front whole-body read and whole-part decode.
- Impact:
  - A large or heavily encoded mail body can force the daemon to allocate substantial memory before the configured attachment limits are even consulted.
  - Under repeated delivery, this creates a cheap memory-pressure denial-of-service path against the mail scanning pipeline, especially because the surrounding spool watcher is already fail-open on parse problems.
- Why it matters:
  - Size limits in a mail security component need to be enforced during streaming, not after full buffering. Otherwise the documented guardrails do not actually protect the process from oversized attacker input.

### Verification

- `go test ./internal/alert/... ./internal/mime/... ./internal/wpcheck/...`

## Component 18: `pam`

Reviewed on: 2026-04-09

### 1. High: the shipped PAM module and install instructions do not actually report failed logins, so the advertised PAM brute-force detection is bypassed in normal deployment

Status: Completed on 2026-04-09

- Evidence:
  - The module documentation and `Makefile` instruct operators to install it as `auth optional pam_csm.so` in [`pam/pam_csm.c:12`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L12) through [`pam/pam_csm.c:14`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L14) and [`pam/Makefile:17`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/Makefile#L17) through [`pam/Makefile:19`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/Makefile#L19).
  - In that `auth` position, the only relevant hook is `pam_sm_authenticate`, but the implementation is a no-op that always returns success in [`pam/pam_csm.c:106`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L106) through [`pam/pam_csm.c:110`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L110).
  - `pam_sm_setcred` is also a no-op in [`pam/pam_csm.c:112`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L112) through [`pam/pam_csm.c:115`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L115).
  - The only hook that emits anything is `pam_sm_acct_mgmt`, and it only sends `OK` events for successful logins in [`pam/pam_csm.c:121`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L121) through [`pam/pam_csm.c:136`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/pam/pam_csm.c#L136).
  - There is no code anywhere in the module that sends a `FAIL` event, even though the daemon listener is built around `FAIL` lines to detect brute force in [`internal/daemon/pam_listener.go:107`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L107) through [`internal/daemon/pam_listener.go:152`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L152) and raises `pam_bruteforce` only from `recordFailure` in [`internal/daemon/pam_listener.go:154`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L154) through [`internal/daemon/pam_listener.go:211`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L211).
- Impact:
  - With the documented deployment, SSH/FTP/PAM authentication failures are never fed into the brute-force tracker, so attackers can keep guessing passwords without tripping the advertised PAM failure detector.
  - Even if an operator manually wires the module into an `account` stack, the current implementation still reports only successful logins, not failures.
- Why it matters:
  - This is a security control that appears present in the codebase and documentation, but it does not deliver its stated protection. That creates a dangerous false sense of coverage around one of the most common attack paths on Internet-facing servers.

### 2. Medium: the PAM listener socket is world-writable and does not authenticate the sender, so any local user can forge login events into the security pipeline

Status: Completed on 2026-04-09

- Evidence:
  - The daemon creates `/var/run/csm/pam.sock` and then explicitly chmods it to `0666` in [`internal/daemon/pam_listener.go:47`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L47) through [`internal/daemon/pam_listener.go:53`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L53).
  - The listener accepts arbitrary Unix socket clients in [`internal/daemon/pam_listener.go:63`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L63) through [`internal/daemon/pam_listener.go:104`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L104), but there is no peer-credential check, filesystem ownership check, or message authentication anywhere in the receive path.
  - Event parsing trusts plain text fields like `OK ip=...` and `FAIL ip=...` directly in [`internal/daemon/pam_listener.go:106`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L106) through [`internal/daemon/pam_listener.go:152`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L152).
  - Successful forged `OK` events become `pam_login` findings in [`internal/daemon/pam_listener.go:143`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L143) through [`internal/daemon/pam_listener.go:150`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/pam_listener.go#L143), and the daemon starts this listener automatically in [`internal/daemon/daemon.go:776`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L776) through [`internal/daemon/daemon.go:788`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/internal/daemon/daemon.go#L776).
- Impact:
  - Any unprivileged local user who can reach the socket can inject fake login-success or brute-force events into the daemon.
  - That can pollute history, generate false operator alerts, and make the PAM event stream untrustworthy as forensic evidence.
- Why it matters:
  - Security telemetry sourced from a local IPC channel has to authenticate the writer. Otherwise any low-privilege foothold on the host can manipulate incident signals and degrade operator trust in the product.

### Verification

- `go test ./cmd/csm/...`

## Component 19: `scripts`

Reviewed on: 2026-04-09

### 1. Medium: installer and upgrade scripts verify binaries only against checksums fetched from the same remote origin, so a compromised release channel can still deliver a fully trusted root-level implant

Status: Completed on 2026-04-09

- Evidence:
  - The public installer downloads the binary and its `.sha256` from the same GitHub release origin in [`scripts/install.sh:112`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/install.sh#L112) through [`scripts/install.sh:124`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/install.sh#L124), then treats that comparison as the trust decision before installing as root in [`scripts/install.sh:145`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/install.sh#L145) through [`scripts/install.sh:176`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/install.sh#L145).
  - The public deploy script follows the same pattern for install and upgrade in [`scripts/deploy.sh:50`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy.sh#L50) through [`scripts/deploy.sh:74`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy.sh#L74) and then copies the accepted binary into `/opt/csm/csm` in [`scripts/deploy.sh:127`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy.sh#L127) and [`scripts/deploy.sh:168`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy.sh#L168).
  - The internal GitLab deploy path does the same with package-registry downloads and sibling checksum files in [`scripts/deploy-gitlab.sh:124`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy-gitlab.sh#L124) through [`scripts/deploy-gitlab.sh:147`](/Users/claudiupopescu/git/pidgin-repos/cpanel-security-monitor/scripts/deploy-gitlab.sh#L124).
  - None of these scripts verify a detached signature, pinned signing key, or any other authenticity signal independent from the download origin itself (confirmed by review of all three scripts).
- Impact:
  - If the release channel, artifact storage, or release credentials are compromised, an attacker can publish both a malicious binary and a matching checksum and have it accepted as valid by fresh installs and upgrades.
  - Because these scripts are intended to run as root, that turns a release-channel compromise directly into privileged code execution on managed servers.
- Why it matters:
  - Checksums downloaded from the same place as the artifact protect against accidental corruption, not malicious substitution. For a root-installed security product, update authenticity needs an independent trust anchor.
