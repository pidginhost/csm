# CSM (Continuous Security Monitor)

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go Report Card](https://goreportcard.com/badge/github.com/pidginhost/csm)](https://goreportcard.com/report/github.com/pidginhost/csm)
[![CodeQL](https://github.com/pidginhost/csm/actions/workflows/codeql.yml/badge.svg)](https://github.com/pidginhost/csm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: AGPL-3.0-or-later](https://img.shields.io/github/license/pidginhost/csm?color=blue)](LICENSE)

> **Local security monitoring and automated response for Linux web servers.** First-class coverage for cPanel/WHM shared hosting, with platform-aware checks for Plesk, DirectAdmin, and panel-free hosts.

CSM combines real-time file, authentication, web, mail, and network watchers with scheduled integrity, account, content, and database scans. Content scanning pairs YAML and YARA-X signatures with data-flow analyzers for PHP and JavaScript, and an optional PHP Shield blocks webshell execution at runtime. State stays on the host. CSM exposes a Web UI and API, and can respond through nftables, quarantine, reversible virtual patches, mail controls, and targeted remediation.

[Documentation](https://pidginhost.github.io/csm/) | [Installation](docs/src/installation.md) | [Configuration](docs/src/configuration.md) | [CLI](docs/src/cli.md) | [Web UI](docs/src/webui.md) | [Releases](https://github.com/pidginhost/csm/releases)

## What CSM covers

| Problem | Detection and response |
|---|---|
| Mailbox takeover and outbound spam | Mail log correlation, account attribution, filter and forwarder audit, PHP relay guard, blocking, mail freeze |
| WordPress and admin login attacks | Login flood, XML-RPC, and credential-stuffing detection; bundled ModSecurity rules for exploited CVEs |
| Webshells, phishing, and injected code | YAML and YARA-X signatures, PHP and JavaScript data-flow analysis, PHP Shield runtime blocking, quarantine |
| Exposed files and vulnerable software | Probe-confirmed exposed dumps, backups, and repositories; known-vulnerable plugin inventory; reversible virtual patches |
| Vulnerability and URL scanners | Per-source probe profiling, claimed-bot verification, ASN crawl detection, challenge routing, firewall response |
| Compromised CMS databases | WordPress, Joomla, Drupal, Magento, OpenCart: stored code, hidden links, spam, doorways, rogue admins; reversible cleanup for supported rows and objects |
| WAF and firewall operations | ModSecurity event correlation and per-domain coverage gaps, nftables, GeoIP, subnet escalation, rollback-confirmed changes |
| Host compromise indicators | Process, account, SSH, cron, and package drift, C2 connections, BPF telemetry, hardening audit, CVE mitigations |
| Fleet observability | HTTPS API, SSE findings, incidents, forensic snapshots, Prometheus, audit log, syslog, webhooks, SIEM backfill |

Detailed coverage is documented under [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md), and [Incidents](docs/src/incidents.md).

## Platform support

| Platform | Coverage |
|---|---|
| cPanel/WHM on CloudLinux, AlmaLinux, or Rocky with Apache/LiteSpeed | Primary target. Full account, WordPress, Exim, WHM plugin, firewall, PHP Shield (CageFS-aware on CloudLinux), and remediation coverage. |
| Plesk or DirectAdmin on a supported Linux distribution | Panel and web-server paths are detected. Generic host/web checks run; cPanel-only integrations skip. |
| AlmaLinux, Rocky, RHEL, or CentOS Stream 8+ | Generic checks with RPM integrity on Apache, Nginx, LiteSpeed, or hosts without a web server. |
| Ubuntu 20.04+ or Debian 11+ | Generic checks with dpkg/debsums integrity on Apache, Nginx, LiteSpeed, or hosts without a web server. |

Packages are published for x86_64 and ARM64; cPanel itself is x86_64-only. Release binaries link YARA-X statically, include journald and BPF support, and need glibc 2.28 or newer.

## Quick start

Install from the signed APT or DNF repository described in the [installation guide](docs/src/installation.md). Packages include the daemon, Web UI, rules, PAM module, systemd unit, and a `csm` command in `/usr/sbin`.

```bash
sudo vi /etc/csm/csm.yaml
sudo csm validate
sudo systemctl enable --now csm.service
sudo csm baseline
sudo csm doctor
```

Open `https://<server>:9443/login`. The package generates an initial admin token in `/etc/csm/csm.yaml` and a self-signed certificate under the state directory unless explicit TLS paths are configured.

The baseline signs the binary, `csm.yaml`, and every non-exempt conf.d drop-in. After a later hand edit, run `sudo csm rehash` before restarting: the daemon refuses a config it did not sign, and `csm doctor` reports the mismatch while the old daemon is still running. Automation-owned overrides go in `/etc/csm/conf.d/*.yaml`; see [Configuration](docs/src/configuration.md#confd-drop-ins) for merge order, trust, and integrity rules.

## How it runs

- Real-time watchers process filesystem, authentication, access-log, mail, PAM, BPF, and ModSecurity events.
- Critical checks run every 10 minutes; deeper account, CMS, package, content, and database checks run every 60 minutes by default.
- Eligible content and exposed-file findings are re-verified every deep-scan cycle. They clear only when the condition is confirmed gone. If flagged content is gone but its file changed, only a replacement proven inert is downgraded; uncertain cases stay open. See [Re-verifying findings](docs/src/detection-deep.md#re-verifying-findings).
- Signatures ship with the package: YAML rules cover real-time scanning and finding re-checks; optional YARA-X rules also cover scheduled and email attachment scanning. Remote YAML and optional [YARA Forge](docs/src/signatures.md#yara-forge-integration) updates are signature-verified.
- Platform detection picks the OS, control panel, web server, paths, logs, and applicable checks. Panel-specific checks skip where their panel is absent.
- State is stored in bbolt with optional retention sweeps, automatic compaction, backup/restore, and audit export.
- CSM has no required SaaS dependency. External reputation, GeoIP, reporting, and panel integrations are optional.

## Safety defaults

- `mode: observe` runs detection and alerting without automatic host remediation or integration updates, and refuses a config that still enables a state-changing subsystem. See [Observe mode](docs/src/observe-mode.md).
- Auto-response is disabled until explicitly enabled.
- Automatic IP and subnet blocking starts in dry-run unless `auto_response.dry_run: false` is explicit. This is a network-response guard, not a universal simulation mode for file cleanup or process actions.
- Exposed-file virtual patches are off by default. Set manual mode to preview or apply them by hand. Automatic mode also requires auto-response and honors its dry-run setting.
- BPF enforcement and PHP-relay freezing have their own dry-run controls.
- Infrastructure, local, allowed, and verified-bot addresses are protected from automatic blocking.
- Process termination excludes root and recognized system services.
- Quarantine preserves the original path, ownership, permissions, and mtime for restoration.
- Firewall configuration can be applied with a confirmation timer and automatic rollback.

Review [Auto-response](docs/src/auto-response.md) before enabling actions on a production host.

## Common commands

```text
csm status [--json]          daemon health, findings, watchers, and rollout state
csm doctor [--json]          config, integrity, daemon, watcher, and store diagnostics
csm privileges [--json]      what CSM does that needs privilege, and the key that stops each one
csm actions [--since 24h]    what CSM did to this host, with before/after digests on file changes
csm selftest                 scan known samples and report what the installed rules catch
csm baseline                 establish known state after first start or an approved reset
csm rehash                   re-sign binary, csm.yaml, and conf.d after an intentional change
csm scan <user> [--full]     scan one account, uncapped with --full
csm scan --all --full        scan every account without the per-account file cap
csm incidents ...            list, show, and update correlated incidents
csm firewall ...             inspect and manage IP, subnet, port, and rollback state
csm virtual-patch [--apply]  preview or apply confirmed exposed-file denies in manual/auto mode
csm harden ...               audit or apply supported host mitigations
```

See the [CLI reference](docs/src/cli.md) for backup and restore, forensic snapshots, PHP Shield, cleanup, and the full operator command reference.

## Development

```bash
go build ./...                         # standard build with YARA stubs
go build -tags yara ./cmd/csm/         # local YARA-X build; link the version pinned in go.mod
go test ./... -count=1 -race
go test -run=Fuzz ./...
make lint
make ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [development guide](docs/src/development.md). Public releases land on GitHub; packaging and integration tests run through GitLab CI. Each release page leads with highlights and security fixes, and the full record is in [CHANGELOG.md](CHANGELOG.md).

## License

CSM is licensed under **AGPL-3.0-or-later**. Releases through v2.x remain under the MIT License; v3.0.0 and newer use AGPL-3.0-or-later.

See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
