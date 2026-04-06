# CSM - Continuous Security Monitor

Real-time security monitoring for cPanel/WHM servers. Single Go binary that detects compromises, backdoors, phishing, and suspicious activity - then auto-responds and alerts within seconds.

Full **Imunify360 replacement**. Includes nftables firewall, ModSecurity management, email AV, YARA-X scanning, threat intelligence, and a web dashboard.

**[Documentation](https://pidginhost.github.io/csm/)** | **[Installation](docs/src/installation.md)** | **[Configuration](docs/src/configuration.md)**

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/install.sh | bash
```

```bash
vi /opt/csm/csm.yaml
csm baseline
systemctl enable --now csm.service
```

Web UI at `https://<server>:9443/login`. Also available as RPM/DEB packages.

## Features

| Layer | What it does |
|-------|-------------|
| **Real-time file monitor** | fanotify - detects webshells and malware in < 1 second |
| **Log watchers** | inotify on auth logs - login anomaly detection in ~2 seconds |
| **PAM listener** | Brute-force blocking on SSH/FTP/cPanel in real time |
| **Critical scanner** | 34 checks every 10 min: processes, network, auth, reputation |
| **Deep scanner** | 28 checks every 60 min: filesystem, WP integrity, phishing, DB |
| **nftables firewall** | Kernel netlink API, IP/subnet blocking, rate limiting, country blocking |
| **ModSecurity** | Rule deployment, per-domain overrides, escalation control |
| **Signatures** | YAML + YARA-X dual scanner, auto-fetch from YARA Forge |
| **Email AV** | ClamAV + YARA-X on Exim spool, attachment scanning |
| **Challenge pages** | SHA-256 proof-of-work for gray-listed IPs (CAPTCHA alternative) |
| **Threat intelligence** | AbuseIPDB, GeoIP, attack correlation, IP scoring |
| **Performance monitor** | PHP, MySQL, Redis, WordPress, OOM detection |
| **Web UI** | 13-page HTTPS dashboard with audit log |
| **Alerts** | Email, Slack, Discord, generic webhooks |

## Auto-Response

| Action | Description |
|--------|-------------|
| Block IPs | nftables with configurable expiry, subnet blocking |
| Challenge IPs | Proof-of-work page for suspicious (not confirmed malicious) IPs |
| Kill processes | Reverse shells, fake kernel threads, GSocket |
| Quarantine files | Webshells, backdoors, phishing (restorable) |
| Clean malware | 7 remediation strategies |
| Permanent blocking | Auto-promote repeat offenders |

## Web UI

13 pages: Dashboard, Findings, Quarantine, Firewall, ModSecurity, Threat Intel, Email, Performance, Incidents, Rules, Audit, Account, Login.

## Performance

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify scan | < 1 second | ~5 MB |
| Critical checks (34) | < 1 second | ~35 MB peak |
| Deep checks (28) | ~40 seconds | ~100 MB peak |
| Daemon idle | - | 45 MB resident |

## Development

```bash
go build ./cmd/csm/                # standard build
go build -tags yara ./cmd/csm/     # with YARA-X
go test ./... -count=1             # tests
golangci-lint run --timeout 5m     # lint
```

## License

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CHANGELOG.md](CHANGELOG.md)
