# CSM (Continuous Security Monitor)

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/pidginhost/csm)](https://goreportcard.com/report/github.com/pidginhost/csm)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: AGPL-3.0-or-later](https://img.shields.io/github/license/pidginhost/csm)](LICENSE)

> **Real-time security daemon for cPanel and Linux web hosts.** Detects, blocks, and cleans up shared-hosting attacks from one binary, in seconds. First class on cPanel/WHM. Runs cleanly on AlmaLinux, Rocky, RHEL, Ubuntu, and Debian with Apache or Nginx.

[Documentation](https://pidginhost.github.io/csm/) | [Install](docs/src/installation.md) | [CLI](docs/src/cli.md) | [Web UI](docs/src/webui.md) | [CVE Mitigations](docs/src/cve-mitigations.md)

## Why CSM

**Hijacked mailboxes turn into spam relays in minutes, not hours.** A weak SMTP password gets cracked, the attacker logs in once, and Exim is sending phishing through your IPs before the next periodic scan would have noticed. CSM tails maillog in real time, blocks the IP on the failure-then-success pattern, and freezes the offending Exim spool messages.

**WordPress backdoors come back after cleanup.** CSM ties detection to action: WP core integrity checks, obfuscated PHP detection, seven file-cleaning paths, and database cleanup for injected admins, options, and spam.

**Brute force at /24 scale isn't fixed by per-IP rate limiting.** Attackers spray credentials from whole subnets. CSM scores per IP, per /24, and per account; escalates temp blocks to permanent after repeated offenses; and feeds WAF and login signals into one threat database with audit trail.

## What it solves

| You're dealing with... | CSM does... | Where |
|---|---|---|
| Mailbox takeover via SASL brute -> outbound spam | Tails maillog, blocks on the failure-then-success pattern, auto-freezes the Exim spool | [Real-time](docs/src/detection-realtime.md) |
| WordPress wp-login / xmlrpc flood | Real-time access-log monitor, blocks within seconds | [Real-time](docs/src/detection-realtime.md) |
| Compromised WP admin / siteurl injection | `csm db-clean --revoke-user`, `--option`, `--delete-spam` | [CLI](docs/src/cli.md) |
| Webshells, obfuscated/eval-chain PHP, tail-appended payloads | fanotify watcher + 7 cleaning strategies; quarantine preserves owner/perms/mtime | [Real-time](docs/src/detection-realtime.md), [Auto-response](docs/src/auto-response.md) |
| PHP-relay form abuse (PHPMailer with spoofed `From`) | Inotify watcher on `/var/spool/exim/input`, 4 detection paths, optional `exim -Mf` auto-freeze | [Real-time](docs/src/detection-realtime.md#php-relay-mail-abuse-cpanel-only) |
| Outbound abuse to GCP/AWS/Azure cloud relays | Realtime fanotify block + retro-scan on startup | [Real-time](docs/src/detection-realtime.md) |
| ModSecurity rule sprawl and triage | Web UI on/off + edit, WAF blocks feed attacker scoring | [ModSecurity](docs/src/modsecurity.md) |
| Subnet-spread brute force | Per-/24 scoring + auto-block of the whole CIDR | [Auto-response](docs/src/auto-response.md) |
| Kernel-level CVEs you can't immediately patch | `csm harden`, continuous enforcement, live exploit-signature detection | [CVE Mitigations](docs/src/cve-mitigations.md) |
| A fleet of servers to monitor as one | Prometheus, JSONL audit log, RFC 5424 syslog, SIEM backfill, panel-side webhooks | [Audit log](docs/src/audit-log.md), [Metrics](docs/src/metrics.md) |

## Headline features

- **Broad host coverage**: critical and deep checks plus real-time fanotify, inotify, PAM, and access-log watchers.
- **Sub-1-second** response on syscall events. **~45 MB** resident idle. **Single static Go binary.**
- **One web UI** at `:9443` with admin and read-scope tokens, SSE event stream, Prometheus metrics, and 65+ REST endpoints.
- **nftables firewall** with TTLs, subnet escalation, country blocking (MaxMind), commit-confirmed safety.
- **Pluggable threat intel**: local attack DB + AbuseIPDB + Rspamd + optional shared upstream cache.
- **Hot-reload safe config** + `/etc/csm/conf.d/*.yaml` drop-ins for automation.
- **bbolt-backed state** with TTL retention, `csm backup`/`csm restore`, and SIEM backfill via `csm export --since`.
- **Signed `.deb` and `.rpm` packages**, reproducible builds, OpenSSF Scorecard.

## Safety defaults

- Auto-response IP blocks start in dry-run unless `auto_response.dry_run: false` is explicit.
- Infrastructure IPs are protected from auto-block.
- Root processes and system daemons are not killed by auto-response.
- Quarantine keeps ownership, permissions, and mtime so restores are clean.

## Quick start

```bash
# Debian / Ubuntu
curl -fsSL https://mirrors.pidginhost.com/csm/csm-signing.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/csm.gpg
echo "deb [signed-by=/etc/apt/keyrings/csm.gpg] https://mirrors.pidginhost.com/csm/deb stable main" | sudo tee /etc/apt/sources.list.d/csm.list
sudo apt update && sudo apt install csm

# AlmaLinux / Rocky / RHEL / CloudLinux / cPanel
sudo rpm --import https://mirrors.pidginhost.com/csm/csm-signing.gpg
sudo dnf config-manager --add-repo https://mirrors.pidginhost.com/csm/rpm/csm.repo
sudo dnf install csm
```

Then:

```bash
sudo vi /etc/csm/csm.yaml         # set hostname, alert email, infra IPs
sudo csm validate && sudo csm baseline
sudo systemctl enable --now csm.service
```

Web UI at `https://<server>:9443`. Drop-in fragments under `/etc/csm/conf.d/*.yaml` are merged after the main config in lexicographic order. Scalars override; lists append. Use drop-ins for automation that should not touch the operator's config.

No repository setup: `curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash`. Full install reference: [Installation](docs/src/installation.md).

## Platforms

| Platform | Support |
|---|---|
| cPanel/WHM on AlmaLinux, CloudLinux, Rocky | First class. Full cPanel account, WordPress, Exim, WHM plugin, and firewall coverage. |
| AlmaLinux, Rocky, RHEL 8+ on Apache or Nginx | Supported. Generic checks run, cPanel-specific ones skip cleanly. |
| Ubuntu 20.04+, Debian 11+ on Apache or Nginx | Supported. Same coverage with `debsums`-based integrity. |

x86_64 and ARM64. cPanel itself is x86_64 only. Per-check coverage is in [detection-critical.md](docs/src/detection-critical.md) and [detection-deep.md](docs/src/detection-deep.md).

## Performance

| Workload | Speed | Memory |
|---|---|---|
| Real-time fanotify event | under 1 s | ~5 MB |
| 36 critical checks | under 1 s | ~35 MB peak |
| 33 deep checks | ~40 s | ~100 MB peak |
| Daemon idle | n/a | 45 MB resident |

Optional add-ons: YARA-X (`-tags yara`), email AV tooling, MaxMind GeoIP data.

## Best fit

CSM is built for operators who run shared web hosting, especially cPanel fleets, and need real-time response without stitching together fail2ban, AV, WAF tooling, and custom scripts. It is less useful as a desktop AV, a Kubernetes runtime agent, or a replacement for patching vendor packages.

## CLI

```
csm daemon                    run the daemon
csm check                     one-shot scan, no auto-response
csm status [--json]           current state and findings
csm doctor [--json]           config + daemon + watchers + store sanity check
csm baseline                  mark current state as known-good
csm scan <user>               scan a single cPanel account
csm firewall ...              IP/subnet bans, port allows, GeoIP
csm clean <path>              clean an infected PHP file
csm db-clean ...              remove WordPress DB injections
csm harden ...                operator-driven hardening (see csm harden --help)
csm phprelay status           PHP-relay detector state (cPanel only)
csm backup <path>             tar.gz of csm.yaml + conf.d + state
csm restore <archive>         extract a backup archive
csm store compact             reclaim bbolt free pages
csm store export <path>       backup daemon state to tar.zst
csm export --since <when>     SIEM backfill in JSONL
csm config schema --json      JSON Schema reflected from the Config struct
csm validate                  dry-run config
```

Full reference: [CLI docs](docs/src/cli.md).

## Hardening / CVE mitigations

Operator-driven via `csm harden`, then continuously enforced by the daemon. Live audit/BPF listeners flag exploit signatures even on hosts that can't be kernel-patched. Current list and operator commands: **[CVE Mitigations](docs/src/cve-mitigations.md)**.

## Development

```bash
go build ./cmd/csm/                    # standard
go build -tags yara ./cmd/csm/         # with YARA-X
go build -tags bpf  ./cmd/csm/         # with BPF LSM af_alg backend (Phase A)
go test ./... -count=1                 # tests
go test -race -short ./...             # CI-style
make lint
```

Public releases land on GitHub. Internal builds and packaging go through the GitLab pipeline.

## Documentation

- [Installation](docs/src/installation.md), [Configuration](docs/src/configuration.md), [Upgrading](docs/src/upgrading.md), [CLI](docs/src/cli.md), [Web UI](docs/src/webui.md)
- [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md)
- [Auto-response](docs/src/auto-response.md), [CVE Mitigations](docs/src/cve-mitigations.md), [Challenge pages](docs/src/challenge.md)
- [ModSecurity](docs/src/modsecurity.md), [Firewall](docs/src/firewall.md), [Email AV](docs/src/email-av.md), [Threat intel](docs/src/threat-intel.md)
- [API](docs/src/api.md), [Metrics](docs/src/metrics.md), [Audit log](docs/src/audit-log.md)

## License

CSM is licensed under **AGPL-3.0-or-later**. Running unmodified CSM to protect your own hosting servers — including commercially — has no source-disclosure obligation. Distributing CSM (binaries or source) or running a *modified* version that users interact with over a network triggers the AGPL's source-availability requirements.

Releases up to and including v2.x remain under the MIT License; v3.0.0 onward is AGPL-3.0-or-later.

See [LICENSE](LICENSE), [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md).
