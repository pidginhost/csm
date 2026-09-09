# Capability matrix

Every operation CSM performs that needs privilege beyond reading its own files,
or that writes outside its own directories, with the privilege it needs and the
setting that stops it.

Print it on any host, before or after install:

```bash
csm privileges              # table
csm privileges --json       # machine-readable
```

The command reads nothing from the host, so it answers "what would this do to
my server" before the package is installed.

## How to read it

**Needs** is what the operation requires from the kernel. `root` means uid 0
rather than one capability: the operation reads or writes files owned by many
different accounts, or drives a panel tool that assumes root. Today the daemon
runs as a single root process; splitting it into a small privileged helper plus
a reduced-privilege main process is planned, and this inventory is its first
stage.

**Trigger** is `automatic` when the daemon may start the operation on its own,
and `operator` when it runs only in response to a command or a button. Not
running the command is how an operator operation is turned off.

**Writes** lists what the operation writes while it runs, including writes made
by a tool it invokes. Paths starting with `/` are filesystem paths; everything
else is a resource named `<kind>:<name>`. "nothing (read-only)" means the
operation only reads.

**Turn it off** is the config key and value that stops the operation. Every
automatic operation that changes host state has one.

**Without the privilege** is what an operator loses by withholding it, so the
row reads as a decision rather than a demand.

## Relationship to the systemd sandbox

The daemon runs under `ProtectSystem=strict` with an explicit writable-path
allow-list; see [service confinement](service-confinement.md). The two lists are
kept in step by tests: every filesystem path in this matrix has to be granted by
the packaged unit, and every grant in the unit has to be claimed by an operation
here. A grant nothing claims is either a path CSM no longer writes or an
operation missing from the matrix.

Operations marked "outside the systemd sandbox" run in a transient unit forked
by PID 1, because the panel tool they drive writes an unbounded set of paths.
They are listed here for exactly that reason: the sandbox does not bound them.

## Turning most of it off at once

`mode: observe` stops every automatic host change in one setting, including the
startup integration deploys that have no switch of their own, and refuses a
config that still enables a state-changing subsystem. See
[observe mode](observe-mode.md).

## The matrix

<!-- BEGIN GENERATED MATRIX -->
| Operation | Needs | Trigger | Writes | Turn it off | Without the privilege |
| --- | --- | --- | --- | --- | --- |
| `state.mail_relay_policies`<br>keep per-account sending baselines used by the PHP-relay detector | root | automatic | /opt/csm/policies | `email_protection.php_relay.enabled: false` | mail abuse is judged on absolute thresholds only, which is noisier on busy accounts |
| `state.php_shield_events`<br>read and rotate the PHP Shield event log written by the PHP runtime hook | root | automatic | /var/log/csm-php-shield | `php_shield.enabled: false` | PHP runtime events are not collected |
| `state.sign_config`<br>rewrite CSM's own integrity hashes into csm.yaml after an approved change | root | operator | /etc/csm | do not run the command | the integrity gate cannot be re-signed, so the next restart refuses to start after any config edit |
| `state.update_signatures`<br>download and signature-verify malware rule updates | root | automatic | /opt/csm/rules | `signatures.auto_update: false` | detection freezes at the ruleset shipped with the installed package |
| `state.write_deploy_script`<br>refresh the embedded upgrade script in CSM's own directory at startup | root | automatic | /opt/csm/deploy.sh | `mode: observe` | the packaged upgrade helper is missing and upgrades are run by hand |
| `state.write_logs`<br>write the daemon log and the audit-log sinks that feed a SIEM | root | automatic | /var/log/csm | not configurable | no local record of findings or actions |
| `state.write_store`<br>write the bbolt state database, baselines, incidents and scan reports | root | automatic | /var/lib/csm, /opt/csm/state | not configurable | CSM cannot run: without state there is no baseline, no dedup and no incident history |
| `detect.account_databases`<br>read account MySQL credentials and scan databases for injected content and stored objects | root | automatic | nothing (read-only) | `detection.db_object_scanning: false` | no database detection: injected admin users, poisoned options and malicious triggers stay invisible |
| `detect.af_alg_sockets`<br>watch AF_ALG socket use (CVE-2026-31431) through BPF LSM or the audit log | CAP_BPF, root | automatic | nothing (read-only) | `detection.af_alg_backend: none` | the live monitor is gone; the periodic critical check still reports an exposed kernel |
| `detect.filesystem_events`<br>fanotify stream over account roots and world-writable temp directories | CAP_SYS_ADMIN | automatic | nothing (read-only) | not configurable | no real-time file detection; scheduled scans still run, so a webshell lives until the next cycle |
| `detect.kernel_livepatch_probe`<br>run kcarectl --patch-info to see whether a KernelCare livepatch covers Copy Fail; kcarectl rewrites its own cache on every run | root | automatic | /var/cache/kcare | `disabled_checks: af_alg_copy_fail` | a patched kernel reads as vulnerable, so the AF_ALG finding cannot be cleared |
| `detect.mail_queue_probe`<br>query the Exim queue through a transient unit, because Exim opens its logs even to answer a read | root | automatic | nothing (read-only) (outside the systemd sandbox) | not configurable | queue composition and freeze targets are unknown, so mail abuse is detected later and less precisely |
| `detect.outbound_connections`<br>watch outbound connections through BPF cgroup hooks, or by polling /proc/net/tcp | CAP_BPF, root | automatic | nothing (read-only) | `detection.connection_tracker_backend: none` | connection detection falls back to polling and misses short-lived connections |
| `detect.pam_events`<br>receive authentication attempts from the pam_csm.so hook over a private socket | root | automatic | /var/run/csm | not configurable | no immediate brute-force or credential-stuffing block; log parsing lags by up to a minute |
| `detect.process_exec`<br>watch process execution through a BPF tracepoint, or by walking /proc | CAP_BPF, root | automatic | nothing (read-only) | `detection.exec_monitor_backend: none` | exec detection falls back to periodic /proc sampling and misses short-lived processes |
| `detect.read_service_logs`<br>read mail, authentication, web server and ModSecurity logs | root | automatic | nothing (read-only) | not configurable | no mail abuse, brute-force or WAF detection: these logs are root-readable only |
| `detect.scan_account_files`<br>read every account's files for scheduled, real-time and on-demand scans | CAP_DAC_READ_SEARCH, root | automatic | nothing (read-only) | `disabled_checks: name the checks to drop` | only files readable by CSM's own uid are scanned, which on a shared host is close to nothing |
| `detect.sensitive_file_writes`<br>watch writes to /etc/shadow and comparable files through a BPF LSM hook | CAP_BPF, root | automatic | nothing (read-only) | `detection.sensitive_files_backend: none` | sensitive-file changes are found by periodic hashing instead of at the moment of the write |
| `integrate.auditd_rules`<br>write CSM's auditd rules and reload them, so audit-backed detection survives package upgrades | root | automatic | /etc/audit | `mode: observe` | audit-backed detection layers stay inactive after an upgrade |
| `integrate.challenge_snippet`<br>refresh the web server snippet and rewrite maps that route challenged visitors to CSM's proof-of-work listener, and reload the web server when the snippet changed | root | automatic | /etc/apache2/conf.d, /etc/apache2/conf-enabled, /etc/httpd/conf.d, /etc/nginx/conf.d, /usr/local/lsws/conf/templates, /var/cache/csm | `mode: observe` | suspicious visitors are blocked outright instead of being offered a challenge |
| `integrate.firewall_ruleset`<br>build and load CSM's nftables table, including the operator's port policy and rate limits | CAP_NET_ADMIN, root | automatic | nftables:csm table | `firewall.enabled: false` | no firewall management; another tool owns the host's packet policy |
| `integrate.modsec_section`<br>rewrite CSM's marker-delimited section of the ModSecurity user configuration, preserving every byte outside it | root | automatic | /etc/apache2/conf.d, /usr/local/apache/conf | `mode: observe` | CSM's virtual-patch WAF rules are not installed |
| `integrate.panel_plugin`<br>deploy the WHM plugin CGI and its AppConfig entry, and register it with the panel | root | automatic | /usr/local/cpanel/whostmgr/docroot/cgi, /var/cpanel | `mode: observe` | no panel plugin; the web UI is still reachable on its own port |
| `integrate.php_shield`<br>install the PHP runtime hook and make its event directory visible inside account cages | root | operator | php:runtime configuration, cagefs:mounts | `php_shield.enabled: false` | no PHP runtime blocking of uploads and temp-directory execution |
| `integrate.waf_vendor_rules`<br>ask the panel to update stale ModSecurity vendor rulesets when a periodic check finds them out of date | root | automatic | modsec:vendor rulesets | `mode: observe` | stale WAF rules are reported but not refreshed |
| `operate.harden_host`<br>apply a supported CVE mitigation: a modprobe blacklist, or seccomp drop-ins for the services that need one | root | operator | /etc/modprobe.d, systemd:service drop-ins, kernel:modules | do not run the command | the mitigation is applied by hand from the command the audit prints |
| `operate.install_service`<br>install or remove CSM itself: the systemd unit, the PAM hook, logrotate and the panel integrations | root | operator | systemd:csm.service, pam:configuration, logrotate:configuration | do not run the command | CSM cannot be installed as a service |
| `operate.manual_firewall`<br>block, allow, tempban or flush addresses on request, and roll a firewall apply back | CAP_NET_ADMIN, root | operator | nftables:csm sets | do not run the command | firewall changes are made with nft or the panel's own tooling |
| `operate.manual_remediation`<br>clean, quarantine or restore a named file, or drop a named database object, on request | root | operator | /home, /opt/csm/quarantine, mysql:account databases | do not run the command | remediation is done by hand over SSH |
| `operate.truncate_error_log`<br>empty an account error log that has grown large enough to threaten the filesystem | root | operator | /home | do not run the command | a bloated log is reported and truncated by hand |
| `respond.af_alg_enforce`<br>unload the AF_ALG kernel modules again when an opted-in mitigation marker is present | root | automatic | kernel:modules (outside the systemd sandbox) | `auto_response.disable_enforce_af_alg: true` | a module reload silently reopens the Copy Fail exposure |
| `respond.block_ip`<br>add an attacker address or subnet to the firewall's deny sets | CAP_NET_ADMIN, root | automatic | nftables:csm sets | `auto_response.block_ips: false` | attacks are reported but not stopped; dry-run records what would have been blocked |
| `respond.bpf_deny_egress`<br>deny matched outbound connections in the kernel through a BPF cgroup hook | CAP_BPF, root | automatic | kernel:bpf cgroup program | `bpf_enforcement.enabled: false` | direct-to-MX spam egress is detected but not stopped at the source |
| `respond.clean_file`<br>strip injected code from a PHP or access file, keeping a pre-clean backup | root | automatic | /home, /opt/csm/quarantine | `auto_response.clean_htaccess: false` | injected files are reported and left in place |
| `respond.database_cleanup`<br>revoke a rogue CMS admin, sanitize poisoned options, and drop confirmed malicious stored objects after recording their definition | root | automatic | mysql:account databases | `auto_response.clean_database: false` | database persistence survives file cleanup and re-infects the account |
| `respond.enforce_permissions`<br>chmod a world-writable or group-writable PHP file back to 644 | root | automatic | /home | `auto_response.enforce_permissions: false` | writable code files are reported only |
| `respond.fix_wp_cron`<br>disable WP-Cron for an account and install a per-user system cron entry instead | root | automatic | /home, /var/spool/cron | `auto_response.fix_wp_cron: false` | runaway WP-Cron load is reported only |
| `respond.forward_guard`<br>maintain the managed Exim block that holds forwarded spam and backscatter, and rebuild the Exim configuration | root | automatic | exim:configuration (outside the systemd sandbox) | `email_protection.forward_guard.enabled: false` | forwarded spam keeps damaging the host's sending reputation |
| `respond.freeze_mail`<br>freeze queued Exim messages attributed to a confirmed PHP-relay finding | root | automatic | /var/spool/exim/input, /var/spool/exim4/input (outside the systemd sandbox) | `auto_response.php_relay.freeze: false` | a compromised script keeps sending until an operator freezes the queue |
| `respond.kill_process`<br>signal a malicious process through a kernel process handle, never a recycled PID, never root | CAP_KILL, root | automatic | process:signal | `auto_response.kill_processes: false` | reverse shells and miners keep running until an operator kills them |
| `respond.quarantine_file`<br>move a confirmed malicious file out of an account tree into CSM's quarantine, preserving owner, permissions and mtime | root | automatic | /home, /tmp, /var/tmp, /dev/shm, /opt/csm/quarantine | `auto_response.quarantine_files: false` | malware is reported and left in place |
| `respond.quarantine_mail`<br>move an infected message out of the Exim spool after an antivirus match | root | automatic | /var/spool/exim/input, /var/spool/exim4/input, /opt/csm/quarantine | `email_av.quarantine_infected: false` | infected mail is reported and delivered |
| `respond.restart_mail_auth`<br>restart the panel's mail authentication service after a sustained outage | root | automatic | service:mail authentication | `auto_response.mail_auth_recovery.restart_enabled: false` | an authentication backend outage is alerted but not repaired |
| `respond.virtual_patch`<br>write a reversible deny rule into an account access file to close an exposed file | root | automatic | /home | `auto_response.virtual_patch_exposed_files: off` | exposed backups, dumps and configs stay reachable until the account owner fixes them |
<!-- END GENERATED MATRIX -->

Regenerate the table with `go run ./cmd/csm privileges --markdown`. A gate in
`internal/ci` fails when the page and the inventory disagree.
