# CSM — Continuous Security Monitor

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/pidginhost/csm)](https://goreportcard.com/report/github.com/pidginhost/csm)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: MIT](https://img.shields.io/github/license/pidginhost/csm)](LICENSE)

> **Catch compromise in seconds. Block the next attempt automatically. Never wonder what happened.**

A Linux security daemon purpose-built for shared web hosting. Real-time detection, automatic response, and a single dashboard — designed for the attack patterns that actually hit cPanel and LAMP servers: stolen credentials, vulnerable WordPress plugins, hijacked mailboxes, phishing kits, kernel CVEs.

**[Documentation](https://pidginhost.github.io/csm/)** · **[Install](docs/src/installation.md)** · **[CLI](docs/src/cli.md)** · **[Web UI](docs/src/webui.md)**

---

## Why CSM

- **Catches what generic tools miss.** Purpose-built for shared-hosting attacks — WordPress brute force, mailbox takeover, PHP webshells, `.htaccess` tampering, cloud-relay abuse, the LEVIATHAN toolkit.
- **Stops the attack, not just alerts on it.** Auto-blocks IPs, quarantines files, kills reverse shells, cleans infected PHP. Never touches root or system processes; infrastructure IPs are safelisted.
- **One pane of glass.** Every signal in one web UI: findings, attackers, quarantine, firewall, ModSecurity, email, performance, hardening.
- **Zero-day kernel hardening.** Operator-driven CVE mitigations with continuous enforcement. Keep your hosts protected while you wait for distro patches.
- **Works out of the box.** Auto-detects cPanel/AlmaLinux/Ubuntu/Apache/Nginx. One install command per OS, no path tweaking.

---

## What you get

### Real-time detection
Webshells, PHP drops in upload directories, `.htaccess` tampering, brute-force floods, and outbound abuse — flagged within a second of the syscall via kernel-level file watchers (fanotify) and log tailers across auth, mail, WAF, and panel sessions.

### WordPress & PHP shield
Verifies core file integrity against `api.wordpress.org`. Detects obfuscated PHP, fragmented `eval` chains, hundreds-of-line concat payloads, tail-appended code, phishing kits, and database-injected admin users. Seven cleaning strategies for infected files; quarantine preserves owner/perm/mtime and is restoreable from the UI.

### Brute-force & bot protection
SSH, FTP, IMAP/POP3/SMTP, WordPress, cPanel, phpMyAdmin, Joomla admin — all tracked through one scoring pipeline. Per-IP, per-/24 subnet, and per-account auto-blocks. Optional proof-of-work challenge (with Cloudflare Turnstile / hCaptcha fallback) for grey-listed traffic; confirmed malware is always hard-blocked.

### Mailbox compromise & email security *(cPanel)*
Fires the instant a successful login arrives from an IP that was just failing auth against the same mailbox. Plus: Exim spool AV, mail-queue monitoring, spamming-script detection, weak-password audits, DKIM/SPF failure alerts, and cloud-relay (GCP/AWS/Azure) outbound abuse blocking with retro-scan on startup.

### CVE mitigations
Kernel-level CVE mitigations applied without a kernel patch. Operator-driven via `csm harden`, then continuously enforced by the daemon — drift gets reverted within minutes.

- **CVE-2026-31431 "Copy Fail"** — `csm harden --copy-fail` blacklists `algif_aead` + `af_alg` and unloads them. Detection layer fires Critical alerts on any `socket(AF_ALG, …)` attempt by a non-system UID. Periodic enforcement re-asserts the policy on every tick. Suspend with `auto_response.disable_enforce_af_alg: true`.

### Firewall & threat intel
nftables-managed IP and subnet bans with TTLs, escalation to permanent after repeated offenses, port allowlists, GeoIP and country blocks (MaxMind), AbuseIPDB lookups, attacker scoring, cross-signal correlation. Bulk operations from the web UI; full audit trail.

### Web Application Firewall management
ModSecurity rule discovery on Apache (cPanel EA4 included) and Nginx. Enable, disable, edit, and reload rules from the web UI. Repeated WAF blocks feed the attacker scoring pipeline.

### System hardening & integrity
Package integrity verification (`rpm -V` on RHEL family, `debsums` / `dpkg --verify` on Debian/Ubuntu). SSH/sysctl/kernel-module audits, world-writable and SUID inventory, outdated-package detection, suspicious process detection (fake kernel threads, reverse shells), performance health signals.

### Production-ready ops
- Single static Go binary; signed `.deb` and `.rpm` packages; reproducible builds.
- Hot-reload safe config — `systemctl reload csm` applies thresholds/alerts/auto-response/email tweaks with no fanotify drop.
- bbolt-backed state with TTL retention sweeps and on-demand `csm store compact`.
- JSONL + RFC 5424 syslog audit log for SIEM ingest; `csm export --since` backfills history.
- Backup/restore via `csm store export|import` (tar+zstd, sha256-verified).
- Prometheus metrics built in.

---

## Quick start

```bash
# Auto-installer (any supported distro)
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash

# Tune config, set baseline, start the daemon
vi /opt/csm/csm.yaml
csm validate && csm baseline
systemctl enable --now csm.service

# Optional: apply the Copy Fail (CVE-2026-31431) mitigation right now
sudo csm harden --copy-fail
```

Web UI at `https://<server>:9443`.

### Native packages

```bash
# Debian / Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo dpkg -i csm_VERSION_amd64.deb

# AlmaLinux / Rocky / RHEL / CloudLinux
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm
```

---

## Supported platforms

| Platform | Support |
|---|---|
| **cPanel/WHM** on AlmaLinux / CloudLinux / Rocky | First-class — all 69 checks, WHM plugin, full Exim integration |
| **AlmaLinux / Rocky / RHEL 8+** with Apache or Nginx | Supported — generic checks; cPanel-specific ones skipped cleanly |
| **Ubuntu 20.04+ / Debian 11+** with Apache or Nginx | Supported — same coverage with `debsums`-based integrity |

x86_64 and ARM64. cPanel itself is x86_64 only. Account-scanning checks (per-domain WordPress integrity, `.htaccess`, PHP content, phishing kits) assume a cPanel layout; everything else runs everywhere. See [detection-critical.md](docs/src/detection-critical.md) and [detection-deep.md](docs/src/detection-deep.md) for per-check coverage.

---

## Performance

| Workload | Speed | Memory |
|---|---|---|
| Real-time fanotify event | < 1 s | ~5 MB |
| 36 critical checks | < 1 s | ~35 MB peak |
| 33 deep checks | ~40 s | ~100 MB peak |
| Daemon idle | — | 45 MB resident |

Optional add-ons: YARA-X (`-tags yara`), email AV tooling, MaxMind GeoIP data.

---

## CLI cheat-sheet

```
csm daemon                    run the daemon
csm check                     one-shot scan (no auto-response)
csm status                    current findings + activity
csm baseline                  mark current state as known-good
csm scan <user>               scan a single cPanel account
csm firewall ...              manage IP/subnet bans, port allows, GeoIP
csm clean <path>              clean an infected PHP file
csm db-clean ...              remove WordPress DB injections
csm harden --copy-fail        apply CVE-2026-31431 mitigation
csm store compact             reclaim bbolt free pages
csm store export <path>       back up daemon state to tar.zst
csm export --since <when>     SIEM backfill in JSONL
csm validate                  dry-run config
```

Full reference: [CLI docs](docs/src/cli.md).

---

## Development

```bash
go build ./cmd/csm/                    # standard
go build -tags yara ./cmd/csm/         # with YARA-X
go test ./... -count=1                 # tests
go test -race -short ./...             # CI-style
make lint
```

Public releases on GitHub. Internal builds and packaging via the GitLab pipeline.

---

## Documentation

- [Installation](docs/src/installation.md) · [Configuration](docs/src/configuration.md) · [CLI](docs/src/cli.md) · [Web UI](docs/src/webui.md)
- [Real-time detection](docs/src/detection-realtime.md) · [Critical checks](docs/src/detection-critical.md) · [Deep checks](docs/src/detection-deep.md)
- [Auto-response](docs/src/auto-response.md) · [Challenge pages](docs/src/challenge.md)
- [ModSecurity](docs/src/modsecurity.md) · [Firewall](docs/src/firewall.md) · [Email AV](docs/src/email-av.md) · [Threat intel](docs/src/threat-intel.md)

## License

MIT — see [LICENSE](LICENSE). · [CONTRIBUTING](CONTRIBUTING.md) · [SECURITY](SECURITY.md) · [CHANGELOG](CHANGELOG.md)
