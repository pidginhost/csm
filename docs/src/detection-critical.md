# Critical Checks

Critical checks run every 10 minutes. On a busy shared host a run typically takes a few seconds of wall-clock time. The periodic scanner finishes its current run before it starts another.

The tables below name the finding identifiers CSM emits, grouped by area. Most are standalone scheduled checks. A few are produced by a parent scheduled check and are not scheduled on their own:

- The `http_*` traffic findings come from the access-log brute-force scan.
- `bad_asn_outbound` comes from the periodic connection scan.

Checks that need cPanel are skipped on plain Linux hosts. See [Platform Support](#platform-support).

## Process & System

| Check | Description |
|-------|-------------|
| `fake_kernel_threads` | Non-root processes masquerading as kernel threads (rootkit indicator) |
| `suspicious_processes` | Reverse shells, interactive shells, GSocket, suspicious executables |
| `detached_web_process` | A non-root process that a web request started and that outlived the request. A shell is Critical; anything else is a Warning. See [Processes left running by a web request](#processes-left-running-by-a-web-request). |
| `detached_web_process_respawn` | A shell from `detached_web_process` came back after CSM stopped it. See [Shells that come back](#shells-that-come-back). |
| `docroot_binary_exec` | A non-root program running from a document root. See [Programs running from a document root](#programs-running-from-a-document-root). |
| `php_processes` | PHP process execution, working dirs, environment variables |
| `shadow_changes` | /etc/shadow modification outside maintenance windows |
| `uid0_accounts` | Unauthorized root (UID 0) accounts |
| `kernel_modules` | Kernel module loading (post-baseline). High, with one Warning case. See [Kernel module severity](#kernel-module-severity). |
| `af_alg_socket_use` | AF_ALG socket use that may indicate Copy Fail exploit activity |
| `af_alg_enforcement` | AF_ALG hardening policy drift and correction status |

### Processes left running by a web request

`detached_web_process` reports a non-root process that meets all of these conditions:

- It has been running for at least five minutes.
- It holds a PHP handler listener (LiteSpeed LSAPI or PHP-FPM).
- It has no PHP or web server runtime in its ancestry.

Together these mean that a web request started the process and it outlived the request.

| Process | Severity | Response |
|---------|----------|----------|
| A shell | Critical. This is the loop shape a webshell leaves behind. | With `kill_processes` on, CSM stops it together with its shell parents of the same account. |
| Anything else, such as a site's PHP worker or an image job | Warning for review | Never stopped on this evidence. |

CSM stops the shell under the rules for loops that write back a removed file; see [Auto-Response](auto-response.md). It does not stop the shell when a terminal or an SSH, cron or cPanel session is in its ancestry.

BusyBox is treated as a shell only when running a shell applet. Processes with incomplete ancestry, and listeners in other network namespaces, are not classified.

### Shells that come back

`detached_web_process_respawn` means a shell from `detached_web_process` came back after CSM stopped it. CSM raises it on the second stop of a shell within 24 hours for the same account, or for the same user outside an account.

- The finding is raised once per account per day. It carries the latest PHP handler socket, which names the site starting the shell.
- For a hosting account CSM also queues a malware scan of the account. That scan quarantines only as automatic quarantine would.
- Stopping never backs off. Every shell that comes back is stopped again.

### Programs running from a document root

`docroot_binary_exec` reports a non-root program running from a document root. The live exec monitor judges each start. This check judges programs still running.

| Case | Result |
|------|--------|
| The program matches a YARA rule, whoever started it | Critical, or the rule's severity |
| A PHP interpreter started it and no rule matched | Warning |
| CGI programs run by the web server, build tools such as esbuild and other launchers | Quiet unless a rule matches |

Scripts are not programs here, because their interpreter lives outside the document root.

Starts that arrive faster than the live monitor can inspect them are counted in the `bpf.execution.docroot` queue health row. [How program verdicts are cached](#how-program-verdicts-are-cached) has the remaining rules.

### Kernel module severity

`kernel_modules` findings are High, with one exception. `af_alg` and `algif_hash`, which upgrades load on demand, are a Warning when a package was installed or updated since the previous scan. Every other module stays High, `algif_aead` (Copy Fail) included.

## SSH & Access

| Check | Description |
|-------|-------------|
| `ssh_keys` | Unauthorized entries in /root/.ssh/authorized_keys |
| `sshd_config` | SSH hardening (PermitRootLogin, PasswordAuthentication, etc.) |
| `ssh_logins` | SSH access anomalies with geolocation |
| `api_tokens` | cPanel/WHM API token usage |
| `whm_access` | WHM/root login patterns, multi-IP access |
| `cpanel_logins` | cPanel login anomalies, multi-IP correlation |
| `cpanel_filemanager` | File Manager usage for unauthorized access |

## Network

| Check | Description |
|-------|-------------|
| `outbound_connections` | Root-level outbound to non-infra IPs (C2, backdoor ports) |
| `user_outbound` | Per-user outbound connections (non-standard ports). See [Exempt system accounts](#exempt-system-accounts). |
| `bad_asn_outbound` | Outbound connection whose destination resolves (via GeoLite2-ASN) to a bad or unexpected autonomous system. Off by default. See [Bad ASN egress](#bad-asn-egress). |
| `dns_connections` | DNS exfiltration and suspicious queries |
| `firewall` | Firewall status and rule integrity |

### Exempt system accounts

`user_outbound` exempts two kinds of system account, each on one port only:

- The system account for Knot DNS, on TCP 853.
- The system accounts for chrony or ntpsec, on TCP 4460 (NTS key exchange).

Hosting accounts with those names are still reported.

### Bad ASN egress

`bad_asn_outbound` is off by default. Configure it under `detection.bad_asn_outbound` with one or both of these lists:

- `blocked_asns` lists systems that are always bad.
- `allowed_asns` turns on allowlist mode: anything outside the list is bad.

The periodic connection scan classifies connections for every process, including root. The live BPF tracker also flags non-root connections in real time.

This finding is the third leg of the `host_takeover` incident chain.

## Brute Force & Auth

| Check | Description |
|-------|-------------|
| `wp_bruteforce` | WordPress login brute force (wp-login.php, xmlrpc.php) |
| `http_scanner_profile` | Source IPs whose traffic is mostly probe-error responses across many distinct paths in one scheduled scan window |
| `http_claimed_bot_unverified` | High-volume claimed crawler traffic while reverse-DNS verification is still pending; challenge-routed when the challenge subsystem is enabled |
| `http_ua_spoof` | IP hitting the per-IP spoof threshold with a search-engine bot UA that fails reverse-DNS verification, or with scripting/headless/empty UAs when those opt-in flags are enabled |
| `http_distributed_flood` | Many already-abusive HTTP source IPs hitting the same vhost in one scheduled scan window |
| `http_asn_crawl` | A single ASN distributing expensive, uncacheable requests across many addresses while one account's PHP worker pool is saturated. See [ASN crawl](#asn-crawl). |
| `webshell_caller` | A client that requested a PHP file CSM flagged as a webshell. cPanel hosts only. Alert only: no automatic response. See [Webshell callers](#webshell-callers). |
| `webshell_path_public` | A flagged PHP file requested by many distinct clients across all domains serving it. See [Webshell callers](#webshell-callers). |
| `ftp_logins` | FTP access patterns and failed auth |
| `webmail_logins` | Roundcube/Horde access anomalies |
| `api_auth_failures` | API authentication failure patterns |

### ASN crawl

For `http_asn_crawl`, request classification is a heuristic, not proof of backend cost. Reverse-proxy ASNs and operator allowlists are excluded. Critical findings can carry the specific source CIDRs eligible for temporary blocking.

### Webshell callers

`webshell_caller` reports a client that requested a PHP file CSM flagged as a webshell. There is one finding per client and account. It carries request and POST counts, the files and a sample request.

A request alone does not prove the client operated the shell. A compromised page can direct visitors there. The finding is alert only, with no automatic response, and it runs on cPanel hosts only.

- Requests keep counting after CSM removes the file.
- Attribution counts probes, including 404 responses, and does not prove that PHP ran.
- A file detected only in real time counts once a scheduled scan reports it.
- CSM reads the recent tail of each site log, so a single request on a busy site can be missed.
- When a client accesses the same file through several domains, its account finding does not name a single domain.

These are excluded from caller attribution:

- Known site entry points.
- Files the installed WordPress or plugin release ships.
- A document root's own index.

These exclusions affect caller attribution only. File scanning is unchanged.

`webshell_path_public` is the summary for a flagged file that many distinct clients requested, across all domains serving it. Its clients are not reported one by one as `webshell_caller`. Infrastructure addresses and verified bots count toward this summary but never receive individual caller findings.

[How webshell requests are matched to files](#how-webshell-requests-are-matched-to-files) has the path rules.

## Email

| Check | Description |
|-------|-------------|
| `mail_queue` | Mail queue buildup (spam outbreak indicator). See [How CSM runs Exim queue commands](#how-csm-runs-exim-queue-commands). |
| `mail_queue_unavailable` | The queue depth could not be read, so buildup detection is inactive. Reported instead of assuming the queue is empty. |
| `mail_per_account` | Per-account email volume spikes |

## Data & Integrity

| Check | Description |
|-------|-------------|
| `crontabs` | Suspicious cron jobs and scheduled commands |
| `mysql_users` | MySQL user accounts and privileges |
| `database_dumps` | Database exfiltration attempts |
| `exfiltration_paste` | Connections to pastebin/code-sharing sites |

The MySQL audit exempts `mysql@localhost` only when MariaDB confirms its stock socket authentication setup with password authentication disabled. These remain reportable:

- Modified authentication.
- Other host literals.
- Accounts whose setup cannot be verified.

## Threat Intelligence

| Check | Description |
|-------|-------------|
| `ip_reputation` | IPs against external threat databases and optional rspamd history. See [IP reputation sightings](#ip-reputation-sightings). |
| `modsec_audit` | ModSecurity audit log parsing |

### IP reputation sightings

The severity of an `ip_reputation` finding depends on where the address was seen:

| Sighting | Severity |
|----------|----------|
| Passive HTTP or cPanel sighting | High |
| SSH or mail-auth activity | Critical |

CSM also weighs which log named the address:

- A sighting in a log the service wrote outranks one in a log file any local user can write.
- An address named only by such a user-writable file never causes a block and gets no AbuseIPDB lookup.
- A rewritten HTTP sighting cannot use a syslog record as proof that the address connected.

### The local threat score

The local threat score ranks addresses on the threat page and feeds the unified verdict. No scheduled check turns it into findings or blocks. The checks that provide attack evidence apply their own response policies.

These rules decide what builds the score:

- The attack database counts a finding only against the source address the finding carries as a structured field.
- Addresses that appear only in message text, such as a connection's destination, a process name or a file path, never build a score.
- Raw mail and SMTP login failures are not counted. The mail and SMTP brute-force detectors decide those blocks.
- The score retains evidence attributed to the server itself.

The mail and SMTP brute-force detectors account for successful logins and mail authentication backend outages. A mistyped password or a backend outage therefore never raises an address's local threat score.

Records attributed to the server itself can represent forwarded attacks or a compromised local process. Firewall protection against blocking the server does not establish that traffic is safe.

[Threat score changes on upgrade](#threat-score-changes-on-upgrade) covers scores and findings stored by older versions.

## Performance

| Check | Description |
|-------|-------------|
| `perf_load` | CPU load average thresholds |
| `perf_php_processes` | PHP process count and memory |
| `perf_memory` | Swap usage and OOM killer activity |

## Health

| Check | Description |
|-------|-------------|
| `health` | Daemon health, binary integrity, required services |

## Platform Support

Checks run on every supported platform unless noted below. The daemon auto-detects OS and panel at startup and silently skips cPanel-specific checks on plain Linux hosts (no "not found" spam).

### cPanel-only checks

These are skipped on plain Ubuntu/AlmaLinux:

| Checks | What they read |
|--------|----------------|
| `api_tokens`, `whm_access`, `cpanel_logins`, `cpanel_filemanager` | WHM API and cPanel session logs |
| `wp_bruteforce` | `/home/*/public_html/*/wp-login.php` and per-domain access logs |
| `webmail_logins` | cPanel Roundcube/Horde logs |
| `mail_per_account` | `/var/log/exim_mainlog` |

The `wp_bruteforce` domlog pass ranks recent logs first and honors `thresholds.domlog_max_files`, `thresholds.domlog_tail_lines`, and `thresholds.domlog_max_age_min`.

### Coverage on plain Linux

These plain Linux equivalents still provide coverage:

- `mail_queue` runs on any host where Exim is installed and is skipped when there is no Exim queue.
- Access log brute-force detection (`wp_login_bruteforce`, `xmlrpc_abuse`) runs against the detected web server's access log, `/var/log/nginx/access.log` or `/var/log/httpd/access_log`. WordPress brute-force alerts still fire on non-cPanel hosts. They rely on the live log watcher rather than per-domain domlog scanning.
- `modsec_audit` runs on any host with ModSecurity installed.
- `ssh_logins`, SSH brute force, PAM listener, firewall, kernel modules, RPM/DEB integrity, and threat intelligence all run on every supported platform.

## Details

This section is reference material: exact rules and upgrade behavior.

### How program verdicts are cached

These rules apply to `docroot_binary_exec`:

- Program verdicts are cached by file identity and change time, scan-size limit, and detection version.
- Rule reloads and worker restarts invalidate cached verdicts.
- Oversized images and scripts receive only a header read.
- Exited processes are inspected only through canonical absolute paths without symlinks.
- Missing processes and files are quiet.

### How webshell requests are matched to files

Webshell caller attribution uses dated requests from the last 24 hours. It preserves the full request target before resolving dot segments and PHP path info.

- Above-root traversal is rejected.
- URL paths are decoded once, including encoded slashes, before resolving dot segments.
- Double-encoded slashes are not decoded again.
- For a directory request, a trailing decoded slash permits an `index.php` lookup.

This assumes decoded path separators. CSM does not infer server settings that preserve them, such as [Apache's NoDecode policy](https://httpd.apache.org/docs/2.4/mod/core.html#allowencodedslashes). It does not infer URL rewrites or custom directory indexes either.

### How CSM runs Exim queue commands

Exim aborts when it cannot write its own log, and the daemon's sandbox makes `/var/log` read-only. The `mail_queue` query therefore runs as a transient unit forked by PID 1. Hosts without systemd-run query exim directly.

All Exim queue reads and actions started by the daemon run as transient services outside its read-only filesystem sandbox. This includes queue composition, safe backscatter flushing, and PHP relay freeze or thaw actions.

- If `systemd-run` is unavailable, CSM runs them directly.
- A host without Exim skips the Exim-only queue check.
- The target command is attempted at most once.
- Cancellation during the wrapper probe stops the command before execution.

### Threat score changes on upgrade

Scores that earlier releases built from message text are corrected automatically when the daemon starts. Blocks they already caused are not lifted. The correction has no setting; `auto_response.block_ips` controls new automatic blocks.

At the upgrade restart, CSM re-scores stored attack records. It removes retired scoring state on the next successful save, including for records whose score is unchanged.

- Existing counts and event history are retained.
- Existing blocks stay until expiry or operator removal.
- Rolling back before that save can restore the retired scoring state. An older daemon also resumes scoring new raw mail failures.

### The retired `local_threat_score` finding

No check produces `local_threat_score` findings. The database malware response reports the addresses of live WordPress sessions in its notice and does not block them, since the site owner's sessions are among them.

- Findings that older versions stored under that name clear after the next completed critical scan.
- A legacy `disabled_checks: [local_threat_score]` value is still accepted, but it does not disable `ip_reputation` or its health checks.
- Queued score findings and block retries under that name are discarded.
- Existing blocks stay until expiry or operator removal.
