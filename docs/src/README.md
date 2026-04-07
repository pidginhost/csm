# CSM - Continuous Security Monitor

Security monitoring and response for cPanel/WHM servers. Single Go binary that detects compromise, phishing, mail abuse, and suspicious activity - then auto-responds and alerts within seconds.

Designed as a full **Imunify360 replacement**. Includes nftables firewall (replaces LFD/fail2ban), ModSecurity management, email security, threat intelligence, hardening audit, performance monitoring, and a web dashboard.

## What CSM Does

```
csm daemon
 +-- fanotify file monitor         < 1s detection on /home, /tmp, /dev/shm
 +-- inotify log watchers          ~2s detection on auth, access, exim, FTP logs
 +-- PAM brute-force listener      Real-time login failure tracking
 +-- PHP runtime shield            auto_prepend_file protection
 +-- critical scanner (10 min)     34 checks: processes, network, tokens, logins, firewall
 +-- deep scanner (60 min)         28 checks: WP integrity, RPM, DB injection, phishing
 +-- nftables firewall engine      Kernel netlink API, IP sets, rate limiting
 +-- threat intelligence           IP reputation, attack scoring, GeoIP
 +-- ModSecurity manager           Rule deployment, overrides, escalation
 +-- email security                AV scanning, quarantine, password/forwarder audit
 +-- challenge server              Proof-of-work pages for suspicious IPs
 +-- alert dispatcher              Email, Slack, Discord, webhooks
 +-- web UI                        HTTPS dashboard with 14 authenticated pages
 +-- hardening audit               On-demand server hardening checks + scoring
 +-- performance monitor           PHP, MySQL, Redis, WordPress metrics
```

## Performance

Benchmarked on production (168 accounts, 275 WordPress sites, 28M files):

| Component | Speed | Memory |
|-----------|-------|--------|
| fanotify monitor | < 1 second | ~5 MB |
| Log watchers | ~2 seconds | ~1 MB |
| Critical checks (34) | < 1 sec | ~35 MB peak |
| Deep checks (28) | ~40 sec | ~100 MB peak |
| Daemon idle | - | 45 MB resident |
| Binary | - | ~8 MB static |

## Built From Real Incidents

CSM was built after real attacks where GSocket reverse shells, LEVIATHAN webshell toolkits, credential-stuffed cPanel accounts, and phishing kits were found across production servers.
