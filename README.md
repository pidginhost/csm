# CSM (Continuous Security Monitor)

[![Coverage](https://pidginhost.github.io/csm/coverage.svg)](https://pidginhost.github.io/csm/coverage.html)
[![Go version](https://img.shields.io/github/go-mod/go-version/pidginhost/csm?label=go)](go.mod)
[![CodeQL](https://github.com/pidginhost/csm/actions/workflows/codeql.yml/badge.svg)](https://github.com/pidginhost/csm/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pidginhost/csm/badge)](https://scorecard.dev/viewer/?uri=github.com/pidginhost/csm)
[![Go Reference](https://pkg.go.dev/badge/github.com/pidginhost/csm.svg)](https://pkg.go.dev/github.com/pidginhost/csm)
[![Release](https://img.shields.io/github/v/release/pidginhost/csm?display_name=tag)](https://github.com/pidginhost/csm/releases)
[![License: AGPL-3.0-or-later](https://img.shields.io/github/license/pidginhost/csm?color=blue)](LICENSE)

CSM is a security monitor for Linux web servers. It detects attacks and compromised accounts as they happen, and it can respond by itself: block the attacker, quarantine the file, hold the mail.

It runs on AlmaLinux, Rocky, RHEL, CloudLinux, Ubuntu and Debian, with or without a control panel. cPanel/WHM hosts get the deepest account and CMS integration.

[Documentation](https://pidginhost.github.io/csm/) | [Installation](docs/src/installation.md) | [Configuration](docs/src/configuration.md) | [CLI](docs/src/cli.md) | [Web UI](docs/src/webui.md) | [Releases](https://github.com/pidginhost/csm/releases)

## What it does

CSM is one Go daemon.

- It watches files, logins, web traffic, mail, processes and network connections in real time.
- It runs scheduled integrity, account, content and database scans.
- It scans content with YAML and YARA-X signatures and with PHP and JavaScript data-flow analysis.
- It responds through the nftables firewall, file quarantine, reversible virtual patches, mail controls and targeted cleanup.
- It keeps its state on the host. The Web UI and API are built in, and nothing depends on a cloud service.

## What CSM covers

| Threat | What CSM does |
|---|---|
| Mailbox takeover and outbound spam | Detects SMTP, IMAP and POP brute force, slow password sprays, bots abusing website forms, and PHP mail relays. Correlates mail logs to name the account, audits filters and forwarders, blocks the source and freezes the mail. |
| Inbound spam and mail malware | Filters spam with rspamd, which learns from users' spam folders and can use feeds such as Spamhaus DQS. Scans attachments with ClamAV and YARA-X. Shows statistics on the Email page. |
| WordPress and admin login attacks | Detects login floods, XML-RPC abuse and credential stuffing. Ships ModSecurity rules for exploited CVEs. |
| Webshells, phishing and injected code | Finds them with YAML and YARA-X signatures and with PHP and JavaScript data-flow analysis. PHP Shield blocks them at run time, and quarantine removes them. |
| Exposed files and vulnerable software | Confirms exposed dumps, backups and repositories with a probe. Lists known-vulnerable plugins. Applies reversible virtual patches. |
| Scanners and crawlers | Profiles probes per source, verifies claimed bots, detects crawls by ASN, and answers with a challenge page or a firewall block. |
| Compromised CMS databases | Finds stored code, hidden links, spam, doorways and rogue admins in WordPress, Joomla, Drupal, Magento, OpenCart and PrestaShop. Cleanup of supported rows and objects is reversible. |
| WAF and firewall | Correlates ModSecurity events and reports domains without WAF coverage. Manages nftables with GeoIP, subnet escalation, and changes that roll back unless confirmed. |
| Host compromise | Watches processes, accounts, SSH, cron and packages for drift, and outbound connections to C2 servers. Adds BPF telemetry, a hardening audit and CVE mitigations. |
| Fleet observability | HTTPS API, live findings over SSE, incidents, forensic snapshots, Prometheus metrics, audit log, syslog, webhooks, SIEM backfill, and an optional read-only MCP endpoint for support agents. |

The full coverage is in [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md) and [Incidents](docs/src/incidents.md).

## Platform support

CSM detects the OS, control panel and web server at startup and runs the checks that apply. A host without a panel is a supported target, not a fallback.

| Host | Coverage |
|---|---|
| Every supported host | Real-time file and webshell scanning, web login attacks from access logs, SSH and PAM logins, ModSecurity monitoring, nftables firewall and auto-response, package integrity (RPM or dpkg/debsums), host drift, BPF telemetry where the kernel supports it, hardening audit, Web UI, API and alerts. |
| Postfix with Dovecot | Brute-force and compromise detection for SMTP AUTH, IMAP, POP3 and ManageSieve, from log files or journald. Postfix hardening checks. Optional rspamd spam filtering. |
| cPanel/WHM | Adds the account registry, WHM and cPanel login monitoring, Exim mail controls, rspamd spam filtering with the webmail Junk button, PHP relay detection, Email AV on the Exim spool, and the WHM plugin. |
| Plesk or DirectAdmin | Account homes and web log paths are detected. cPanel integrations are skipped. |

Requirements:

- OS: AlmaLinux, Rocky, RHEL, CloudLinux or CentOS Stream 8+, Ubuntu 20.04+, or Debian 11+. cPanel hosts run CloudLinux, AlmaLinux, Rocky or Ubuntu.
- Web server: Apache, Nginx, LiteSpeed, or none.
- CPU: x86_64 or ARM64. cPanel itself is x86_64 only.
- glibc 2.28 or newer. Release binaries link YARA-X statically and include journald and BPF support.

On hosts without cPanel:

- Set `account_roots` to the web roots. Real-time document-root rules, scheduled YARA sweeps, web-root performance checks and remediation then cover them. Many account and CMS scans still expect `public_html` beneath account homes; see [Deep checks](docs/src/detection-deep.md#platform-support).
- SMTP brute-force detection on Postfix needs [Dovecot rejection logging](docs/src/detection-realtime.md#smtp--dovecot-brute-force-tracker). Learning from Junk folders needs Dovecot 2.3 and Maildir; see [Postfix hosts](docs/src/antispam.md#postfix-hosts).
- PHP Shield setup finds EA-PHP, alt-PHP and lsphp builds and handles CageFS on CloudLinux. Other PHP builds need a manual `auto_prepend_file` line.

## Quick start

Install from the signed APT or DNF repository as described in the [installation guide](docs/src/installation.md). The package includes the daemon, Web UI, rules, PAM module, systemd unit, and a `csm` command in `/usr/sbin`.

```bash
sudo vi /etc/csm/csm.yaml
sudo csm validate
sudo systemctl enable --now csm.service
sudo csm baseline
sudo csm doctor
```

Then open `https://<server>:9443/login`. The package writes an initial admin token to `/etc/csm/csm.yaml` and creates a self-signed certificate unless you configure TLS paths.

### Editing the config later

`csm baseline` records hashes of the binary and its configuration. The daemon refuses to start with a config it did not record, so after a hand edit run:

```bash
sudo csm rehash
sudo systemctl restart csm
```

`csm doctor` reports a mismatch before you restart. This check catches unrecorded edits. It does not stop someone who can write to `/etc/csm`.

Put overrides owned by automation in `/etc/csm/conf.d/*.yaml`; see [Configuration](docs/src/configuration.md#confd-drop-ins).

## How it runs

- Real-time watchers handle filesystem, authentication, access-log, mail, PAM, BPF and ModSecurity events.
- Critical checks run every 10 minutes and deep checks every 60 minutes by default.
- Eligible content and exposed-file findings are checked again on every deep scan. They clear only when the problem is confirmed gone. See [Re-verifying findings](docs/src/detection-deep.md#re-verifying-findings).
- Rules ship with the package. YAML rules cover real-time scanning and finding re-checks. Optional YARA-X rules also cover scheduled and attachment scanning.
- Remote YAML updates and optional [YARA Forge](docs/src/signatures.md#yara-forge-integration) updates are signature-verified.
- State lives in bbolt, with optional retention sweeps, automatic compaction, backup and restore, and audit export.
- There is no SaaS dependency. Reputation, GeoIP, reporting and panel integrations are optional.

## Safety defaults

- `mode: observe` keeps detection, correlation and alerting active. It skips automatic host remediation and integration updates, and it refuses a config that still enables a state-changing subsystem. See [Observe mode](docs/src/observe-mode.md).
- Auto-response is off until enabled. Automatic IP and subnet blocking then starts in dry run until you set `auto_response.dry_run: false`. Dry run also covers mailbox suspensions and account mail holds. File cleanup and process termination follow their own switches.
- Virtual patches for exposed files are off by default. Manual mode previews or applies them by hand. Automatic mode also needs auto-response and honors dry run.
- BPF enforcement and PHP relay freezing have their own dry-run controls.

CSM also applies these safeguards:

- Infrastructure, local, allowed and verified-bot addresses are never blocked automatically.
- Process termination skips root and recognized system services.
- Quarantine keeps the original path, owner, mode and mtime for restore.
- Firewall changes can apply on a confirmation timer and roll back automatically.
- By default, YARA-X, PHP taint analysis, zip listings and mail attachments run in separate workers with no capabilities, no IP network access and a memory cap. See [Service confinement](docs/src/service-confinement.md#parse-worker-units).

Read [Auto-response](docs/src/auto-response.md) before enabling actions on a production host.

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

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [development guide](docs/src/development.md).

Public releases land on GitHub. Packaging and integration tests run through GitLab CI. Each release page leads with highlights and security fixes; the full record is in [CHANGELOG.md](CHANGELOG.md).

## License

CSM is licensed under **AGPL-3.0-or-later**. Releases through v2.x remain under the MIT License; v3.0.0 and newer use AGPL-3.0-or-later.

See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).
