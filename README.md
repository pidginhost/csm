# CSM - Continuous Security Monitor

A security daemon for **cPanel/WHM servers** that detects compromise in seconds, responds automatically, and gives operators one place to see what happened.

Shared hosting servers get hit the same ways: stolen credentials, vulnerable plugins, phishing kits, hijacked mailboxes, and backdoors that sit undiscovered until abuse reports arrive. CSM watches for all of it and acts before a small incident becomes a long cleanup.

**[Documentation](https://pidginhost.github.io/csm/)** | **[Installation](docs/src/installation.md)** | **[Configuration](docs/src/configuration.md)**

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
vi /opt/csm/csm.yaml
csm validate && csm baseline
systemctl enable --now csm.service
```

Web UI at `https://<server>:9443`

## What It Does

**Watches everything in real time** -- fanotify on `/home`, `/tmp`, `/dev/shm` for malicious files; inotify on logs for auth failures, WAF blocks, mail abuse, and suspicious logins; PAM listener for brute force across all services.

**Runs 62 security checks** -- 34 critical checks every 10 minutes (processes, auth, network, integrity) and 28 deep checks every hour (filesystem, WordPress, phishing, DNS/SSL, mail, database).

**Responds automatically** -- blocks IPs, quarantines files, kills reverse shells, cleans infected PHP, promotes repeat offenders to permanent bans, and routes suspicious traffic through proof-of-work challenges.

**Manages your firewall** -- nftables IP/subnet blocking, temp bans, country blocks, port allowlists, GeoIP decisions, and full audit trail.

**Covers email abuse** -- Exim spool AV scanning, attachment quarantine, queue monitoring, weak password audits, external forwarder checks, and DKIM/SPF failure alerting.

**Includes threat intelligence** -- AbuseIPDB lookups, GeoIP/ASN enrichment, attacker scoring, attack correlation, and bulk IP actions.

Plus: ModSecurity management, YARA-X scanning, server hardening audits, performance monitoring (PHP/MySQL/Redis/WordPress), and signature-based detection.

## Web UI

14 authenticated pages covering dashboard, findings, quarantine, firewall, ModSecurity, ModSec Rules, threat intel, email, performance, hardening, incidents, rules, audit, and account views. Also available as a WHM plugin.

The dashboard shows 24h stats, a timeline, live event feed, at-risk accounts, and response summary. Key investigation pages support filtering, bulk actions, and drill-down workflows.

## CLI

```
csm daemon              # run the daemon
csm check               # run all checks once
csm status              # show current findings
csm baseline            # set clean-state baseline
csm scan <user>         # scan a specific account
csm firewall ...        # manage firewall rules
csm clean <path>        # clean infected files
csm update-rules        # update detection signatures
csm validate            # validate config
csm verify              # verify binary integrity
```

## Performance

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify scan | < 1 sec | ~5 MB |
| 34 critical checks | < 1 sec | ~35 MB peak |
| 28 deep checks | ~40 sec | ~100 MB peak |
| Daemon idle | -- | 45 MB resident |

Single Go binary. Optional integrations include YARA-X support, email AV tooling, and MaxMind GeoIP data.

## Development

```bash
go build ./cmd/csm/                    # standard build
go build -tags yara ./cmd/csm/         # with YARA-X support
go test ./... -count=1                 # run tests
go test -race -short ./...             # CI-style test run
make lint                              # lint using repo-local caches
```

Public release artifacts are published on GitHub Releases. The GitLab pipeline remains the internal build and packaging system, but the GitHub repository is the public source of truth for releases, install script downloads, and docs.

## Docs

- [Installation](docs/src/installation.md)
- [Configuration](docs/src/configuration.md)
- [CLI Commands](docs/src/cli.md)
- [Real-Time Detection](docs/src/detection-realtime.md)
- [Critical Checks](docs/src/detection-critical.md)
- [Deep Checks](docs/src/detection-deep.md)
- [Web UI](docs/src/webui.md)

## License

MIT. See [LICENSE](LICENSE). Also see [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
