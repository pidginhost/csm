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

## Quick start

Install CSM from the signed APT or DNF repository described in the [installation guide](docs/src/installation.md). Packages include the daemon, Web UI, rules, PAM module, systemd unit, and a `csm` command in `/usr/sbin`.

After installation:

```bash
sudo vi /etc/csm/csm.yaml
sudo csm validate
sudo systemctl enable --now csm.service
sudo csm baseline
sudo csm doctor
```

Open `https://<server>:9443/login`. The package generates an initial admin token in `/etc/csm/csm.yaml` and a self-signed certificate under the state directory unless explicit TLS paths are configured.

The baseline signs the binary, `csm.yaml`, and every conf.d drop-in. After a later hand edit, run `sudo csm rehash` before restarting: the daemon refuses a config it did not sign, and `csm doctor` reports the mismatch while the old daemon is still running.

Use `/etc/csm/conf.d/*.yaml` for automation-owned overrides. Fragments load in lexicographic order; maps merge, scalars replace, and lists append. A fragment that an integration rewrites on its own schedule can be exempted from the integrity hash. See [Configuration](docs/src/configuration.md#confd-drop-ins) for trust and integrity rules.

## What CSM covers

| Problem | Detection and response |
|---|---|
| Mailbox takeover and outbound spam | Exim/Postfix/Dovecot log correlation, account attribution, mail-filter and Sieve forwarding audit, PHP mail-relay guard, direct SMTP egress control, IP or subnet blocking, optional mail freeze and forward-copy hold |
| WordPress and admin login attacks | Access-log and PAM watchers for login floods, XML-RPC abuse, credential stuffing, and distributed campaigns; bundled ModSecurity rules for actively exploited CVEs and mass-exploit tools |
| Webshells, phishing, and injected code | fanotify plus scheduled content scans, YARA-X and YAML signatures, PHP Shield runtime blocking, PHP remote-source and JavaScript keylogger data-flow analysis, self-deleting dropper detection, quarantine, and bounded cleanup strategies |
| Exposed files and vulnerable software | Web-root sweep for database dumps, backup archives, config and source backups, phpinfo, and served `.git` directories, each confirmed by a probe; known-vulnerable plugin inventory; alerts when ModSecurity is off for a domain; reversible `.htaccess` virtual patches |
| Vulnerability and URL scanners | Per-source probe profiling, claimed-bot verification, ASN crawl detection, challenge routing, and firewall response |
| Compromised CMS databases | WordPress, Joomla, Drupal, Magento, and OpenCart content checks, including PHP snippets stored in the database, hidden link blocks, spam taxonomy and publishing floods, doorway options, site-address hijack, rogue admins, and MySQL triggers, events, and procedures; reversible cleanup for supported rows and objects |
| WAF and firewall operations | ModSecurity event correlation, nftables management, GeoIP policy, temporary bans, subnet escalation, inbound and outbound lockout warnings, and rollback-confirmed changes |
| Host compromise indicators | Suspicious processes, account and SSH changes, cron and sshd drift, package integrity, C2 connections, BPF telemetry, CVE-specific mitigations, and a hardening audit covering SSH, firewall, PHP, mail, and web server settings |
| Fleet observability | HTTPS API, SSE findings, correlated incidents, forensic snapshots, Prometheus metrics, JSONL audit log, RFC 5424 syslog, webhooks, and SIEM backfill |

Detailed coverage is documented under [Real-time detection](docs/src/detection-realtime.md), [Critical checks](docs/src/detection-critical.md), [Deep checks](docs/src/detection-deep.md), and [Incidents](docs/src/incidents.md).

## Operating model

- Real-time watchers process filesystem, authentication, access-log, mail, PAM, BPF, and ModSecurity events.
- Critical checks run every 10 minutes; deeper account, CMS, package, content, and database checks run every 60 minutes by default.
- Findings are re-verified every deep-scan cycle. A finding is cleared only when the remediation is confirmed, and downgraded rather than cleared when a file changed but the proof is incomplete. See [Re-verifying findings](docs/src/detection-deep.md#re-verifying-findings).
- Signatures ship with the package: YAML and YARA-X rules for real-time, scheduled, and email attachment scanning, signed remote updates, and optional [YARA Forge](docs/src/signatures.md#yara-forge-integration) tiers.
- Platform detection selects the OS, control panel, web server, paths, logs, and applicable checks through `internal/platform`.
- State is stored in bbolt with optional retention sweeps, automatic compaction, backup/restore, and audit export.
- CSM has no required SaaS dependency. External reputation, GeoIP, reporting, and panel integrations are optional.

Production release binaries include YARA-X and journald/BPF support. YARA-X is statically linked into the executable, while glibc remains dynamically linked with a build floor of glibc 2.28.

## Safety defaults

- Auto-response is disabled until explicitly enabled.
- Automatic IP and subnet blocking starts in dry-run unless `auto_response.dry_run: false` is explicit. This is a network-response guard, not a universal simulation mode for file cleanup or process actions.
- Exposed-file virtual patches are off by default. Operators can preview or apply them by hand, or enable dry-run-gated automatic enforcement.
- BPF enforcement and PHP-relay freezing have their own dry-run controls.
- Infrastructure, local, allowed, and verified-bot addresses are protected from automatic blocking.
- Process termination excludes root and recognized system services.
- Quarantine preserves the original path, ownership, permissions, and mtime for restoration.
- Firewall configuration can be applied with a confirmation timer and automatic rollback.

Review [Auto-response](docs/src/auto-response.md) before enabling actions on a production host.

## Platform support

| Platform | Coverage |
|---|---|
| cPanel/WHM on CloudLinux, AlmaLinux, or Rocky with Apache/LiteSpeed | Primary target. Full account, WordPress, Exim, WHM plugin, firewall, PHP Shield (CageFS-aware on CloudLinux), and remediation coverage. |
| Plesk or DirectAdmin on a supported Linux distribution | Panel and web-server paths are detected. Generic host/web checks run; cPanel-only integrations skip. |
| AlmaLinux, Rocky, RHEL, or CentOS Stream 8+ | Generic checks with RPM integrity on Apache, Nginx, LiteSpeed, or hosts without a web server. |
| Ubuntu 20.04+ or Debian 11+ | Generic checks with dpkg/debsums integrity on Apache, Nginx, LiteSpeed, or hosts without a web server. |

Packages are published for x86_64 and ARM64. cPanel itself is x86_64-only.

## Common commands

```text
csm status [--json]           daemon health, findings, watchers, and rollout state
csm doctor [--json]           config, integrity, daemon, watcher, and store diagnostics
csm check                     run checks through the daemon without auto-response
csm baseline                  establish known state after first start or an approved reset
csm rehash                    re-sign binary, csm.yaml, and conf.d after an intentional change
csm scan <user> [--full]      scan one account; --full creates an uncapped job, --all covers every account
csm incidents ...             list, show, and update correlated incidents
csm forensic-snapshot <user>  evidence archive for incident handoff
csm firewall ...              inspect and manage IP, subnet, port, and rollback state
csm virtual-patch [--apply]   preview or apply reversible deny rules for confirmed exposed files
csm clean <path>              clean a supported infected PHP file with backup
csm harden ...                audit or apply supported host mitigations
csm enable --php-shield       turn on PHP runtime protection
csm backup <out>              bundle csm.yaml, conf.d, and state; csm restore reverses it
csm validate                  validate the merged main and conf.d configuration
```

See the [CLI reference](docs/src/cli.md) for full commands and maintenance requirements.

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
