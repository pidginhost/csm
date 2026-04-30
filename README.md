# CSM (Continuous Security Monitor)

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/pidginhost/csm)](https://goreportcard.com/report/github.com/pidginhost/csm)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: MIT](https://img.shields.io/github/license/pidginhost/csm)](LICENSE)

CSM is a security daemon for Linux web servers. It catches the kinds of attacks that actually hit shared hosting (stolen logins, vulnerable WordPress plugins, hijacked mailboxes, phishing kits, the occasional kernel CVE), and it can block, quarantine, or clean up on its own. Everything ends up in one web UI.

It runs first class on cPanel/WHM and works cleanly on plain AlmaLinux, Rocky, RHEL, Ubuntu, and Debian with Apache or Nginx.

[Documentation](https://pidginhost.github.io/csm/) · [Install](docs/src/installation.md) · [CLI](docs/src/cli.md) · [Web UI](docs/src/webui.md)

## What it does

CSM watches the syscall layer (fanotify) and tails auth, mail, WAF, and panel logs. When something looks wrong it raises a finding and, if you let it, takes an action: block the IP, quarantine the file, kill the process, clean the infected PHP. It never touches root processes or your infrastructure IPs.

The detection set is targeted at real attacker behaviour on shared hosting:

- **WordPress and PHP.** Verifies WP core integrity against api.wordpress.org. Catches obfuscated PHP, fragmented eval chains, multi-line concat payloads, tail-appended code, and DB-injected admin users. Seven cleaning strategies for infected files. Quarantine keeps owner, perms, and mtime so files restore cleanly.

- **Brute force, every protocol.** SSH, FTP, IMAP/POP3/SMTP, WordPress, cPanel, phpMyAdmin, Joomla admin. Per-IP, per /24 subnet, and per-account scoring. Optional proof-of-work challenge with Cloudflare Turnstile or hCaptcha fallbacks for grey traffic. Confirmed malware always gets a hard block.

- **Mailbox takeover (cPanel).** Fires the moment a successful login arrives from an IP that was just failing auth against the same mailbox. Plus Exim spool AV, mail-queue spam detection, weak-password audits, DKIM/SPF alerts, and outbound cloud-relay (GCP/AWS/Azure) abuse blocking with a retro-scan on startup.

- **PHP-relay abuse (cPanel).** Real-time inotify watcher on `/var/spool/exim/input` catches WordPress contact-form spam relays where the attacker uses PHPMailer with a spoofed `From`, external `Reply-To`, and a script URL that doesn't belong to the account. Four detection paths (per-script header score, per-script absolute volume, per-account log-tail volume, HTTP-IP fanout) feed an optional auto-freeze that runs `exim -Mf` on the live spool. Operator controls via `csm phprelay`: status, ignore-script, dry-run toggle, thaw.

- **CVE mitigations.** Operator-driven via `csm harden`, then continuously enforced by the daemon. Currently shipped:
   - **CVE-2026-31431 ("Copy Fail").** Run `csm harden --copy-fail` once. CSM blacklists `algif_aead` and `af_alg`, unloads them, and from then on the daemon checks every ten minutes that the policy is still in place. If anything drifts (kernel update, manual edit, rogue script) it puts it back. Auditd rules separately log every `socket(AF_ALG, ...)` attempt by a non-system uid as a Critical finding. Set `auto_response.disable_enforce_af_alg: true` to pause enforcement without removing the marker.

- **Firewall and threat intel.** nftables-managed IPs and subnets with TTLs, escalation to permanent after repeated offenses, port allowlists, MaxMind GeoIP and country blocking, AbuseIPDB lookups, attacker scoring across signals. Bulk operations from the web UI and a full audit trail.

- **WAF management.** ModSecurity rule discovery on Apache (cPanel EA4 included) and Nginx. Enable, disable, edit, and reload rules from the UI. WAF blocks feed the attacker scoring pipeline.

- **System hardening.** Package integrity via `rpm -V` or `debsums`, SSH and sysctl audits, kernel module tracking, world-writable and SUID inventory, outdated-package detection, suspicious processes (fake kernel threads, reverse shells), and performance health signals that often correlate with compromise.

## Built for ops

- Single static Go binary. Signed `.deb` and `.rpm` packages. Reproducible builds.
- Hot-reload safe config. `systemctl reload csm` applies threshold and alert tweaks without dropping fanotify.
- bbolt-backed state with TTL retention sweeps. `csm store compact` reclaims free pages on demand.
- JSONL plus RFC 5424 syslog audit log for SIEM ingest. `csm export --since` backfills history.
- Backup and restore via `csm store export` and `csm store import` (tar+zstd, sha256-verified).
- Prometheus metrics built in.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
vi /opt/csm/csm.yaml
csm validate && csm baseline
systemctl enable --now csm.service
```

If you want the Copy Fail mitigation right away:

```bash
sudo csm harden --copy-fail
```

The web UI is at `https://<server>:9443`.

### Native packages

```bash
# Debian or Ubuntu
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm_VERSION_amd64.deb
sudo dpkg -i csm_VERSION_amd64.deb

# AlmaLinux, Rocky, RHEL, CloudLinux
curl -LO https://github.com/pidginhost/csm/releases/latest/download/csm-VERSION-1.x86_64.rpm
sudo dnf install -y ./csm-VERSION-1.x86_64.rpm
```

## Platforms

| Platform | Support |
|---|---|
| cPanel/WHM on AlmaLinux, CloudLinux, Rocky | First class. All 69 checks, WHM plugin, full Exim integration. |
| AlmaLinux, Rocky, RHEL 8+ on Apache or Nginx | Supported. Generic checks run, cPanel-specific ones skip cleanly. |
| Ubuntu 20.04+, Debian 11+ on Apache or Nginx | Supported. Same coverage with `debsums`-based integrity. |

x86_64 and ARM64. cPanel itself is x86_64 only.

Account-scanning checks (per-domain WordPress integrity, .htaccess, PHP content, phishing kits) assume a cPanel layout. Everything else runs anywhere. Per-check coverage is in [detection-critical.md](docs/src/detection-critical.md) and [detection-deep.md](docs/src/detection-deep.md).

## Performance

| Workload | Speed | Memory |
|---|---|---|
| Real-time fanotify event | under 1 s | ~5 MB |
| 36 critical checks | under 1 s | ~35 MB peak |
| 33 deep checks | ~40 s | ~100 MB peak |
| Daemon idle | n/a | 45 MB resident |

Optional add-ons: YARA-X (`-tags yara`), email AV tooling, MaxMind GeoIP data.

## CLI

```
csm daemon                    run the daemon
csm check                     one-shot scan, no auto-response
csm status                    current findings and activity
csm baseline                  mark current state as known-good
csm scan <user>               scan a single cPanel account
csm firewall ...              IP/subnet bans, port allows, GeoIP
csm clean <path>              clean an infected PHP file
csm db-clean ...              remove WordPress DB injections
csm harden --copy-fail        apply CVE-2026-31431 mitigation
csm phprelay status           PHP-relay detector state (cPanel only)
csm store compact             reclaim bbolt free pages
csm store export <path>       back up daemon state to tar.zst
csm export --since <when>     SIEM backfill in JSONL
csm validate                  dry-run config
```

Full reference: [CLI docs](docs/src/cli.md).

## Development

```bash
go build ./cmd/csm/                    # standard
go build -tags yara ./cmd/csm/         # with YARA-X
go test ./... -count=1                 # tests
go test -race -short ./...             # CI-style
make lint
```

Public releases land on GitHub. Internal builds and packaging go through the GitLab pipeline.

## Documentation

- [Installation](docs/src/installation.md), [Configuration](docs/src/configuration.md), [CLI](docs/src/cli.md), [Web UI](docs/src/webui.md)
- [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md)
- [Auto-response](docs/src/auto-response.md), [Challenge pages](docs/src/challenge.md)
- [ModSecurity](docs/src/modsecurity.md), [Firewall](docs/src/firewall.md), [Email AV](docs/src/email-av.md), [Threat intel](docs/src/threat-intel.md)

## License

MIT. See [LICENSE](LICENSE), [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md).
