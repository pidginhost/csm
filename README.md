# CSM — Continuous Security Monitor

Real-time security monitoring for cPanel/WHM servers. Single Go binary that detects compromises, backdoors, phishing, and suspicious activity — then auto-responds and alerts within seconds.

Designed as a full **Imunify360 replacement**. Includes nftables firewall (replaces LFD/fail2ban), ModSecurity management, email AV, threat intelligence, and a web dashboard.

## Quick Start

```bash
curl -sSL https://get.example.com/csm | bash
# Or: rpm -i csm-VERSION.x86_64.rpm / dpkg -i csm_VERSION.deb

vi /opt/csm/csm.yaml
csm baseline
systemctl enable --now csm.service
```

Web UI: `https://<server>:9443/login`

## What It Does

```
csm daemon
 +-- fanotify file monitor         < 1s webshell/malware detection
 +-- inotify log watchers          ~2s login/auth anomaly detection
 +-- PAM brute-force listener      Real-time login failure blocking
 +-- critical scanner (10 min)     34 checks: processes, network, auth, reputation
 +-- deep scanner (60 min)         25 checks: filesystem, WP integrity, phishing, DB
 +-- nftables firewall             Kernel netlink API, IP sets, rate limiting
 +-- ModSecurity manager           Rule deployment, overrides, escalation
 +-- threat intelligence           IP scoring, GeoIP, attack correlation
 +-- email AV                      ClamAV + YARA-X on Exim spool
 +-- performance monitor           PHP, MySQL, Redis, WordPress metrics
 +-- web UI                        12-page HTTPS dashboard
 +-- alert dispatcher              Email, Slack, Discord, webhooks
```

## Auto-Response

| Action | Description |
|--------|-------------|
| Kill processes | Reverse shells, fake kernel threads, GSocket |
| Quarantine files | Webshells, backdoors, phishing (restorable) |
| Block IPs | nftables with configurable expiry |
| Clean malware | 7 remediation strategies |
| Subnet blocking | Auto-block /24 on repeated attacks |

## Web UI

| Page | Purpose |
|------|---------|
| Dashboard | 24h stats, live feed, accounts at risk |
| Findings | Active findings + History tab, fix/dismiss/suppress, bulk actions |
| Quarantine | File preview and restore |
| Firewall | Blocked IPs/subnets, GeoIP, whitelist |
| ModSecurity | WAF status, events, rule management |
| Threat Intel | IP scoring, top attackers, trends |
| Email | AV status, quarantine, scan stats |
| Performance | Load, PHP, MySQL, Redis, WordPress |
| + Incidents, Rules, Audit, Account | |

## Performance

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify | < 1 second | ~5 MB |
| Critical checks (34) | < 1 sec | ~35 MB peak |
| Deep checks (25) | ~40 sec | ~100 MB peak |
| Daemon idle | — | 45 MB resident |

## Documentation

Full documentation is in the [`docs/`](docs/src/SUMMARY.md) directory, built with [mdBook](https://rust-lang.github.io/mdBook/):

```bash
cd docs && mdbook serve    # local preview at http://localhost:3000
```

**Getting Started:** [Installation](docs/src/installation.md) | [Configuration](docs/src/configuration.md) | [CLI Commands](docs/src/cli.md)

**Detection:** [Real-Time](docs/src/detection-realtime.md) | [Critical Checks](docs/src/detection-critical.md) | [Deep Checks](docs/src/detection-deep.md) | [Auto-Response](docs/src/auto-response.md)

**Components:** [Firewall](docs/src/firewall.md) | [ModSecurity](docs/src/modsecurity.md) | [Signatures](docs/src/signatures.md) | [Email AV](docs/src/email-av.md) | [Threat Intel](docs/src/threat-intel.md) | [GeoIP](docs/src/geoip.md) | [Performance](docs/src/performance.md)

**Web UI & API:** [Web UI](docs/src/webui.md) | [API Reference](docs/src/api.md) | [Development](docs/src/development.md)

## Development

```bash
go build ./cmd/csm/              # standard build
go build -tags yara ./cmd/csm/   # with YARA-X
go test ./... -count=1           # tests
golangci-lint run --timeout 5m   # lint
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security vulnerabilities: [SECURITY.md](SECURITY.md). Changelog: [CHANGELOG.md](CHANGELOG.md).

## Roadmap

- Binary signing with cosign
- Multi-server management (centralized dashboard, block list sync)
- YUM/APT repository for automated updates
