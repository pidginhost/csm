# CSM (Continuous Security Monitor)

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go version](https://img.shields.io/github/go-mod/go-version/pidginhost/csm?label=go)](go.mod)
[![CodeQL](https://github.com/pidginhost/csm/actions/workflows/codeql.yml/badge.svg)](https://github.com/pidginhost/csm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: AGPL-3.0-or-later](https://img.shields.io/github/license/pidginhost/csm?color=blue)](LICENSE)

> **Local security monitoring and automated response for Linux web servers.** Runs on AlmaLinux, Rocky, RHEL, CloudLinux, Ubuntu, and Debian, with or without a control panel. cPanel/WHM hosts get the deepest account and CMS integration.

CSM is one Go daemon. It watches files, logins, web traffic, mail, processes, and network connections in real time, and runs scheduled integrity, account, content, and database scans. Content scanning pairs YAML and YARA-X signatures with PHP and JavaScript data-flow analysis. CSM responds through nftables, quarantine, reversible virtual patches, mail controls, and targeted cleanup. State stays on the host, and the Web UI and API are built in.

[Documentation](https://pidginhost.github.io/csm/) | [Installation](docs/src/installation.md) | [Configuration](docs/src/configuration.md) | [CLI](docs/src/cli.md) | [Web UI](docs/src/webui.md) | [Releases](https://github.com/pidginhost/csm/releases)

## What CSM covers

| Threat | Detection and response |
|---|---|
| Mailbox takeover and outbound spam | SMTP, IMAP, and POP brute-force and slow password spray detection, mail log correlation, account attribution, bots abusing website forms, filter and forwarder audit, PHP relay detection, blocking, mail freeze |
| Inbound spam and mail malware | rspamd spam filtering with learning from users' spam folders and optional feeds such as Spamhaus DQS; attachment scanning with ClamAV and YARA-X; Email page statistics |
| WordPress and admin login attacks | Login flood, XML-RPC, and credential-stuffing detection; bundled ModSecurity rules for exploited CVEs |
| Webshells, phishing, and injected code | YAML and YARA-X signatures, PHP and JavaScript data-flow analysis, PHP Shield runtime blocking, quarantine |
| Exposed files and vulnerable software | Probe-confirmed exposed dumps, backups, and repositories; known-vulnerable plugin inventory; reversible virtual patches |
| Scanners and crawlers | Per-source probe profiling, claimed-bot verification, ASN crawl detection, challenge routing, firewall response |
| Compromised CMS databases | WordPress, Joomla, Drupal, Magento, OpenCart: stored code, hidden links, spam, doorways, rogue admins; reversible cleanup for supported rows and objects |
| WAF and firewall | ModSecurity event correlation and per-domain coverage gaps, nftables, GeoIP, subnet escalation, rollback-confirmed changes |
| Host compromise | Process, account, SSH, cron, and package drift, C2 connections, BPF telemetry, hardening audit, CVE mitigations |
| Fleet observability | HTTPS API, SSE findings, incidents, forensic snapshots, Prometheus, audit log, syslog, webhooks, SIEM backfill, optional read-only MCP endpoint for support agents |

Detailed coverage is documented under [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md), and [Incidents](docs/src/incidents.md).

## Platform support

CSM detects the OS, control panel, and web server at startup and runs the checks that apply. A host without a panel is a supported target, not a fallback.

| Host | Coverage |
|---|---|
| Every supported host | Real-time file and webshell scanning, web login attacks from access logs, SSH and PAM logins, ModSecurity monitoring, nftables firewall and auto-response, RPM or dpkg/debsums package integrity, host drift, BPF telemetry where the kernel supports it, hardening audit, Web UI, API, and alerts |
| Postfix with Dovecot | SMTP AUTH, IMAP, POP3, and ManageSieve brute-force and compromise detection from log files or journald, Postfix hardening checks, optional rspamd spam filtering |
| cPanel/WHM | Adds the account registry, WHM and cPanel login monitoring, Exim mail controls, rspamd spam filtering with the webmail Junk button, PHP relay detection, Email AV on the Exim spool, and the WHM plugin |
| Plesk or DirectAdmin | Account homes and web log paths are detected; cPanel integrations skip |

Requirements:

- AlmaLinux, Rocky, RHEL, CloudLinux, or CentOS Stream 8+, Ubuntu 20.04+, or Debian 11+. cPanel hosts run CloudLinux, AlmaLinux, Rocky, or Ubuntu.
- Apache, Nginx, LiteSpeed, or no web server.
- x86_64 or ARM64; cPanel itself is x86_64-only. Release binaries link YARA-X statically, include journald and BPF support, and need glibc 2.28 or newer.

On hosts without cPanel:

- Set `account_roots` to the web roots. Real-time document-root rules, scheduled YARA sweeps, web-root performance checks, and remediation then cover them. Many account and CMS scans still expect `public_html` beneath account homes; see [Deep checks](docs/src/detection-deep.md#platform-support).
- SMTP brute-force detection on Postfix needs [Dovecot rejection logging](docs/src/detection-realtime.md#smtp--dovecot-brute-force-tracker). Learning from Junk folders needs Dovecot 2.3 and Maildir; see [Postfix hosts](docs/src/antispam.md#postfix-hosts).
- PHP Shield setup finds EA-PHP, alt-PHP, and lsphp builds and handles CageFS on CloudLinux. Other PHP builds need a manual `auto_prepend_file` line.

## Quick start

Install from the signed APT or DNF repository described in the [installation guide](docs/src/installation.md). Packages include the daemon, Web UI, rules, PAM module, systemd unit, and a `csm` command in `/usr/sbin`.

```bash
sudo vi /etc/csm/csm.yaml
sudo csm validate
sudo systemctl enable --now csm.service
sudo csm baseline
sudo csm doctor
```

Open `https://<server>:9443/login`. The package writes an initial admin token to `/etc/csm/csm.yaml` and creates a self-signed certificate unless TLS paths are configured.

`csm baseline` records hashes of the binary and its configuration. After a hand edit, run `sudo csm rehash` before restarting: the daemon refuses a config it did not record, and `csm doctor` reports the mismatch before you restart. This catches unrecorded edits; it does not stop anyone who can write `/etc/csm`. Put automation-owned overrides in `/etc/csm/conf.d/*.yaml`; see [Configuration](docs/src/configuration.md#confd-drop-ins).

## How it runs

- Real-time watchers handle filesystem, authentication, access-log, mail, PAM, BPF, and ModSecurity events.
- Critical checks run every 10 minutes and deep checks every 60 minutes by default.
- Eligible content and exposed-file findings are re-checked every deep scan and clear only when the problem is confirmed gone. See [Re-verifying findings](docs/src/detection-deep.md#re-verifying-findings).
- Rules ship with the package. YAML rules cover real-time scanning and finding re-checks; optional YARA-X rules also cover scheduled and attachment scanning. Remote YAML and optional [YARA Forge](docs/src/signatures.md#yara-forge-integration) updates are signature-verified.
- State lives in bbolt, with optional retention sweeps, automatic compaction, backup and restore, and audit export.
- No SaaS dependency. Reputation, GeoIP, reporting, and panel integrations are optional.

## Safety defaults

- `mode: observe` detects and alerts without automatic remediation or integration updates, and refuses a config that still enables a state-changing subsystem. See [Observe mode](docs/src/observe-mode.md).
- Auto-response is off until enabled. Automatic IP and subnet blocking then starts in dry run until `auto_response.dry_run: false` is set. Dry run guards network responses only, not file cleanup or process actions.
- Virtual patches for exposed files are off by default. Manual mode previews or applies them by hand; automatic mode also needs auto-response and honors dry run.
- BPF enforcement and PHP relay freezing have their own dry-run controls.
- Infrastructure, local, allowed, and verified-bot addresses are never blocked automatically. Process termination skips root and recognized system services.
- Quarantine keeps the original path, owner, mode, and mtime for restore. Firewall changes can apply on a confirmation timer with automatic rollback.
- By default, YARA-X, PHP taint analysis, zip listings, and mail attachments run in separate workers with no capabilities, no IPv4 or IPv6 sockets, and a memory cap. Unix sockets remain available. See [Service confinement](docs/src/service-confinement.md#parse-worker-units).

Review [Auto-response](docs/src/auto-response.md) before enabling actions on a production host.

## Common commands

```text
csm status [--json]          daemon health, findings, watchers, and rollout state
csm doctor [--json]          config, integrity, daemon, watcher, and store diagnostics
csm privileges [--json]      what CSM does that needs privilege, and the key that stops each one
csm actions [--since 24h]    what CSM did to this host, with before/after digests on file changes
csm selftest                 scan known samples and report what the installed rules catch
csm baseline                 establish known state after first start or an approved reset
csm rehash                   re-hash binary, csm.yaml, and conf.d after an intentional change
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
