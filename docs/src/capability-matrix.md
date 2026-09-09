# Capability matrix

Every operation CSM performs that needs privilege beyond reading its own files,
or that writes outside its own directories, with the privilege it needs and the
setting that stops it.

Print it on any host, before or after install:

```bash
csm privileges              # table
csm privileges --json       # machine-readable
```

The command prints a static inventory. It does not load CSM configuration or
probe host privileges, so it can be used before installing the service. Output
failures produce a nonzero exit status in text, JSON and Markdown formats.

## How to read it

**Needs** is what the operation requires from the kernel. `root` means uid 0
rather than one capability: the operation reads or writes files owned by many
different accounts, or drives a panel tool that assumes root. Today the daemon
runs as a single root process; splitting it into a small privileged helper plus
a reduced-privilege main process is planned, and this inventory is its first
stage. Capability names describe the privileged kernel interfaces as well as
the root filesystem access. For BPF, tracing and LSM programs need
`CAP_BPF` plus `CAP_PERFMON`; cgroup socket programs need `CAP_BPF` plus
`CAP_NET_ADMIN`. `CAP_SYS_ADMIN` is the broader fallback on older kernels.
These requirements follow the [kernel program-load checks](https://github.com/torvalds/linux/blob/v6.6/kernel/bpf/syscall.c).

**Trigger** is `automatic` when the daemon may start the operation on its own,
and `operator` when it runs only in response to a command or a button. Not
running the command is how an operator operation is turned off.

**Writes** lists what the operation writes while it runs, including writes made
by a tool it invokes. Paths starting with `/` are filesystem paths; everything
else is a resource named `<kind>:<name>`. "nothing (read-only)" means the
operation only reads. Paths describe default locations; configured account roots,
state, rule, log, spool and policy paths replace those defaults and may require
service drop-ins. Shared CSM state and audit-log writes are grouped in the state
rows. This is not a list of every possible path written by an external panel tool.

**Turn it off** is the config key and YAML value that stops the named operation.
Dotted keys describe nested YAML mappings; they are not literal top-level keys.
Apply changes before restarting the daemon: several controls are read only at
startup. A row saying "not configurable" has no single config switch that stops
all its callers. `disabled_checks` takes a list and only affects scheduled checks.
Stopping new work does not undo installed rules, hooks, quarantines or blocks;
use the subsystem removal commands for that. Disabling the forward guard removes
its existing Exim configuration, which is itself a host write.

**Action record** says whether the operation writes to the
[action log](action-log.md). "no" does not mean the operation is silent; it
means it is not on that stream yet and the daemon log is where it appears.

**Without the privilege** is what an operator loses by withholding it, so the
row reads as a decision rather than a demand.

## Relationship to the systemd sandbox

The daemon runs under `ProtectSystem=strict` with an explicit writable-path
allow-list; see [service confinement](service-confinement.md). The two lists are
compared by tests: every declared in-daemon filesystem write must fit a packaged
grant, and every grant must have an in-daemon writer. Empty inventories and grant
lists fail. Paths are compared on directory boundaries, and an operation outside
the sandbox cannot justify a daemon grant. The unit parser rejects invalid paths
and unsupported syntax, including continuations, specifiers and directory flags,
instead of guessing which locations are writable. Tests cannot discover omitted operations
or prove the privilege and disable claims; those require tracing the runtime code.

Operations marked "outside the systemd sandbox" run as standalone operator
commands or transient services forked by PID 1. The latter use direct execution
on hosts without a reachable systemd service manager. Mixed operations have
separate rows for their in-daemon writes, such as the AF_ALG marker repair and
forward-guard lookup refresh. The service sandbox does not bound external tools.

## Turning most of it off at once

`mode: observe` stops automatic remediation and integration deployment, and
refuses configurations that enable those subsystems. It still maintains CSM state,
loads temporary BPF capability probes in BPF builds, and invokes the KernelCare
probe, which can update its own cache. It is not a guarantee of zero host writes. See
[observe mode](observe-mode.md).

## The matrix

<!-- BEGIN GENERATED MATRIX -->
| Operation | Needs | Trigger | Writes | Turn it off | Action record | Without the privilege |
| --- | --- | --- | --- | --- | --- | --- |
| `state.control_socket`<br>create the private control socket used by operator commands | root | automatic | /var/run/csm | not configurable | no | CLI commands cannot reach the daemon |
| `state.mail_relay_policies`<br>load operator-supplied mailer classes and proxy ranges for the PHP-relay detector | none | automatic | nothing (read-only) | `email_protection.php_relay.enabled: false` | no | only policy files readable by the daemon uid can be loaded |
| `state.php_shield_events`<br>receive PHP Shield events over a socket and append their local archive | root | automatic | /var/log/csm-php-shield | `php_shield.enabled: false` | no | PHP runtime events are not collected |
| `state.sign_config`<br>rewrite CSM's own integrity hashes into csm.yaml after an approved change | root | operator | /etc/csm | do not run the command | no | the integrity gate cannot be re-signed, so the next restart refuses to start after any config edit |
| `state.update_forge`<br>download and verify YARA Forge rules independently of YAML updates | root | automatic | /opt/csm/rules | `signatures.yara_forge.enabled: false` | no | YARA Forge rules are not refreshed |
| `state.update_signatures`<br>download and signature-verify YAML malware rule updates | root | automatic | /opt/csm/rules | `signatures.update_url: ""` | no | detection freezes at the ruleset shipped with the installed package |
| `state.write_deploy_script`<br>refresh the embedded upgrade script in CSM's own directory at startup | root | automatic | /opt/csm/deploy.sh | `mode: observe` | no | the packaged upgrade helper is missing and upgrades are run by hand |
| `state.write_logs`<br>write the daemon log and the audit-log sinks that feed a SIEM | root | automatic | /var/log/csm | not configurable | no | no local record of findings or actions |
| `state.write_store`<br>write the bbolt state database, baselines, incidents and scan reports | root | automatic | /var/lib/csm, /opt/csm/state | not configurable | no | CSM cannot run: without state there is no baseline, no dedup and no incident history |
| `detect.account_databases`<br>read account MySQL credentials and scan databases for injected content and stored objects | root | automatic | nothing (read-only) | not configurable: db_object_scanning only stops stored-object scans; content and requested scans remain | no | no database detection: injected admin users, poisoned options and malicious triggers stay invisible |
| `detect.af_alg_sockets`<br>deny AF_ALG sockets through BPF LSM, or observe socket use through the audit-log fallback | CAP_BPF, CAP_PERFMON, root | automatic | kernel:AF_ALG socket denial | `detection.af_alg_backend: none` | no | the live monitor is gone; the periodic critical check still reports an exposed kernel |
| `detect.audit_rules`<br>query loaded audit rules with auditctl to check detection coverage | CAP_AUDIT_CONTROL, root | automatic | nothing (read-only) | not configurable | no | audit-rule coverage cannot be verified |
| `detect.bpf_probe`<br>load and briefly attach BPF LSM, tracepoint and cgroup programs to discover kernel support | CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, root | automatic | kernel:temporary BPF programs and maps | not configurable: capability discovery runs independently of monitor settings in BPF builds | no | BPF capabilities report unavailable; configured automatic backends use their fallbacks |
| `detect.filesystem_events`<br>fanotify stream over account roots and world-writable temp directories | CAP_SYS_ADMIN | automatic | nothing (read-only) | not configurable | no | no real-time file detection; scheduled scans still run, so a webshell lives until the next cycle |
| `detect.kernel_livepatch_probe`<br>run kcarectl --patch-info to see whether a KernelCare livepatch covers Copy Fail; kcarectl rewrites its own cache on every run | root | automatic | /var/cache/kcare | not configurable: the startup kernel probe and hardening audits also invoke kcarectl, including in observe mode | no | a patched kernel reads as vulnerable, so the AF_ALG finding cannot be cleared |
| `detect.kernel_oom`<br>read the restricted kernel message buffer with dmesg to find recent OOM kills | CAP_SYSLOG, root | automatic | nothing (read-only) | not configurable | no | swap statistics remain available, but OOM kills are not reported |
| `detect.mail_queue_probe`<br>query the Exim queue through a transient unit, because Exim opens its logs even to answer a read | root | automatic | /var/log/exim_mainlog, /var/log/exim_paniclog, /var/log/exim4 (outside the systemd sandbox) | `disabled_checks: [mail_queue]` | no | queue depth is unknown, so a queue-size spam outbreak may go undetected |
| `detect.outbound_connections`<br>watch outbound connections through BPF cgroup hooks, or by polling /proc/net/tcp | CAP_BPF, CAP_NET_ADMIN, root | automatic | kernel:BPF programs and maps | `detection.connection_tracker_backend: none` | no | auto mode uses polling; an explicitly selected BPF backend stays unavailable |
| `detect.pam_events`<br>receive authentication attempts from the pam_csm.so hook over a private socket | root | automatic | /var/run/csm | not configurable | no | no immediate brute-force or credential-stuffing block; log parsing lags by up to a minute |
| `detect.process_exec`<br>watch process execution through a BPF tracepoint, or by walking /proc | CAP_BPF, CAP_PERFMON, root | automatic | kernel:BPF programs and maps | `detection.exec_monitor_backend: none` | no | auto mode uses periodic /proc sampling; an explicitly selected BPF backend stays unavailable |
| `detect.read_service_logs`<br>read mail, authentication, web server and ModSecurity logs | root | automatic | nothing (read-only) | not configurable | no | no mail abuse, brute-force or WAF detection: these logs are root-readable only |
| `detect.scan_account_files`<br>read every account's files for scheduled, real-time and on-demand scans | CAP_DAC_READ_SEARCH, root | automatic | nothing (read-only) | not configurable: disabled_checks only suppresses scheduled checks; realtime and requested scans remain | no | only files readable by CSM's own uid are scanned, which on a shared host is close to nothing |
| `detect.sensitive_file_writes`<br>watch writes to /etc/shadow and comparable files through a BPF LSM hook | CAP_BPF, CAP_PERFMON, root | automatic | kernel:BPF programs and maps | `detection.sensitive_files_backend: none` | no | sensitive-file changes are found by periodic hashing instead of at the moment of the write |
| `integrate.auditd_rules`<br>write CSM's auditd rules and reload them, so audit-backed detection survives package upgrades | CAP_AUDIT_CONTROL, root | automatic | /etc/audit, kernel:audit rules | `mode: observe` | no | audit-backed detection layers stay inactive after an upgrade |
| `integrate.challenge_port_gate`<br>install the separate nftables port gate for the public challenge listener | CAP_NET_ADMIN, root | automatic | nftables:challenge port gate | `challenge.port_gate.enabled: false` | no | the listener remains reachable without the challenge port filter |
| `integrate.challenge_snippet`<br>refresh the web server snippet and rewrite maps that route challenged visitors to CSM's proof-of-work listener, and reload the web server when the snippet changed | root | automatic | /etc/apache2/conf.d, /etc/apache2/conf-enabled, /etc/httpd/conf.d, /etc/nginx/conf.d, /usr/local/lsws/conf/templates, /var/cache/csm, service:web server reload | `mode: observe` | no | suspicious visitors are blocked outright instead of being offered a challenge |
| `integrate.firewall_ruleset`<br>build and load CSM's nftables table, including the operator's port policy and rate limits | CAP_NET_ADMIN, root | automatic | nftables:csm table | `firewall.enabled: false` | yes | no firewall management; another tool owns the host's packet policy |
| `integrate.modsec_section`<br>refresh the managed ModSecurity section at startup and during periodic WAF checks, preserving operator configuration | root | automatic | /etc/apache2/conf.d, /usr/local/apache/conf | `mode: observe` | no | CSM's virtual-patch WAF rules are not installed |
| `integrate.panel_plugin`<br>deploy the WHM plugin CGI and its AppConfig entry, and register it with the panel | root | automatic | /usr/local/cpanel/whostmgr/docroot/cgi, /var/cpanel | `mode: observe` | no | no panel plugin; the web UI is still reachable on its own port |
| `integrate.php_shield`<br>install the PHP runtime hook and register its shared event directory for an operator-scheduled CageFS remount | root | operator | /opt/csm, /var/log/csm-php-shield, /etc/cagefs, /etc/csm, /opt/cpanel, /opt/alt, /usr/local/lsws, php:runtime configuration (outside the systemd sandbox) | do not run the command | no | no PHP runtime blocking of uploads and temp-directory execution |
| `integrate.waf_vendor_rules`<br>ask the panel to update stale ModSecurity vendor rulesets when a periodic check finds them out of date | root | automatic | /etc/apache2/conf.d, /usr/local/apache/conf, /var/cpanel, service:web server reload | `mode: observe` | no | stale WAF rules are reported but not refreshed |
| `operate.export_archives`<br>read protected configuration, state or account evidence and export backup or forensic archives, temporary snapshots and checksum sidecars | root | operator | filesystem:operator-selected archive destinations (outside the systemd sandbox) | do not run the command | no | protected configuration, state and account evidence cannot be exported completely |
| `operate.harden_host`<br>apply a supported CVE mitigation: a modprobe blacklist, or seccomp drop-ins for the services that need one | CAP_SYS_MODULE, root | operator | /etc/modprobe.d, /etc/systemd/system, service:restart, kernel:modules (outside the systemd sandbox) | do not run the command | no | the mitigation is applied by hand from the command the audit prints |
| `operate.install_service`<br>install or remove CSM itself: the systemd unit, the PAM hook, logrotate and the panel integrations | CAP_AUDIT_CONTROL, CAP_LINUX_IMMUTABLE, root | operator | /opt/csm, /etc/csm, /var/lib/csm, /var/log/csm, /etc/systemd/system, /etc/pam.d, /etc/logrotate.d, /etc/audit, /usr/sbin/csm, /lib64/security, /usr/lib64/security, /lib/security, /lib/x86_64-linux-gnu/security, /usr/lib/x86_64-linux-gnu/security, /lib/aarch64-linux-gnu/security, /usr/lib/aarch64-linux-gnu/security, /usr/local/cpanel/whostmgr/docroot/cgi, /var/cpanel, service:csm and panel integrations, /etc/cron.d, /var/cache/csm, /opt/cpanel, /var/run/csm, /etc/apache2/conf.d, /etc/apache2/conf-enabled, /etc/httpd/conf.d, /etc/nginx/conf.d, /usr/local/apache/conf, /usr/local/lsws/conf/templates (outside the systemd sandbox) | do not run the command | no | CSM cannot be installed as a service |
| `operate.manual_firewall`<br>block, allow, tempban or flush addresses on request, and roll a firewall apply back | CAP_NET_ADMIN, root | operator | nftables:csm sets | do not run the command | yes | firewall changes are made with nft or the panel's own tooling |
| `operate.manual_remediation`<br>clean or quarantine files and spool messages, truncate malicious crontabs, kill verified malware processes, or change database objects on request | CAP_KILL, root | operator | /home, /tmp, /var/tmp, /dev/shm, /var/spool/cron, /var/spool/exim/input, /var/spool/exim4/input, /opt/csm/quarantine, mysql:account databases, process:signal | do not run the command | no | remediation is done by hand over SSH |
| `operate.rehash`<br>re-sign configuration, converge legacy config copies, set binary immutability and refresh the launcher, service and log rotation | CAP_LINUX_IMMUTABLE, root | operator | /opt/csm, /etc/csm, /etc/systemd/system, /etc/logrotate.d, /usr/sbin/csm, service:daemon reload (outside the systemd sandbox) | do not run the command | no | hash signing and upgrade integration refresh cannot complete |
| `operate.restore_backup`<br>stage and restore protected configuration, drop-ins and state from a backup while the daemon is stopped | root | operator | /etc/csm, /var/lib/csm, /opt/csm, /tmp (outside the systemd sandbox) | do not run the command | no | configuration and state cannot be restored |
| `operate.truncate_error_log`<br>empty an account error log that has grown large enough to threaten the filesystem | root | operator | /home | do not run the command | no | a bloated log is reported and truncated by hand |
| `respond.af_alg_enforce`<br>unload the AF_ALG kernel modules again when an opted-in mitigation marker is present | CAP_SYS_MODULE, root | automatic | kernel:modules (outside the systemd sandbox) | `auto_response.disable_enforce_af_alg: true` | no | a module reload silently reopens the Copy Fail exposure |
| `respond.af_alg_kill`<br>kill a verified AF_ALG socket caller through the separate Copy Fail response setting | CAP_KILL, root | automatic | process:signal | `auto_response.copy_fail_kill_process: false` | no | the process is reported but remains running; this path is independent of kill_processes |
| `respond.af_alg_marker`<br>restore a changed AF_ALG mitigation marker after the operator has opted in | root | automatic | /etc/modprobe.d | `auto_response.disable_enforce_af_alg: true` | no | a changed module blacklist is reported but cannot be repaired |
| `respond.block_ip`<br>add an attacker address or subnet to the firewall's deny sets | CAP_NET_ADMIN, root | automatic | nftables:csm sets | `auto_response.block_ips: false` | yes | attacks are reported but not stopped; dry-run records what would have been blocked |
| `respond.bpf_deny_egress`<br>deny matched outbound connections in the kernel through a BPF cgroup hook | CAP_BPF, CAP_NET_ADMIN, root | automatic | kernel:bpf cgroup program | `bpf_enforcement.enabled: false` | no | direct-to-MX spam egress is detected but not stopped at the source |
| `respond.clean_file`<br>strip injected code from a PHP or access file, keeping a pre-clean backup | root | automatic | /home, /tmp, /var/tmp, /dev/shm, /opt/csm/quarantine | `auto_response.enabled: false` | yes | injected files are reported and left in place |
| `respond.database_cleanup`<br>revoke a rogue CMS admin, sanitize poisoned options, and drop confirmed malicious stored objects after recording their definition | root | automatic | mysql:account databases | `auto_response.clean_database: false` | no | database persistence survives file cleanup and re-infects the account |
| `respond.enforce_permissions`<br>chmod a world-writable or group-writable PHP file back to 644 | root | automatic | /home | `auto_response.enforce_permissions: false` | no | writable code files are reported only |
| `respond.fix_wp_cron`<br>disable WP-Cron for an account and install a per-user system cron entry instead | root | automatic | /home, /var/spool/cron, /tmp | `auto_response.fix_wp_cron: false` | no | runaway WP-Cron load is reported only |
| `respond.forward_guard`<br>install or remove the managed Exim block that holds forwarded spam and backscatter, and rebuild the Exim configuration | root | automatic | /etc/exim.conf.local, /etc/exim.conf, /var/lib/csm, exim:rebuild artifacts and service reload (outside the systemd sandbox) | `mode: observe` | no | forwarded spam keeps damaging the host's sending reputation |
| `respond.forward_guard_lookup`<br>refresh the forward-guard bad-sender lookup inside the daemon sandbox | root | automatic | /var/lib/csm/forward_guard | `email_protection.forward_guard.enabled: false` | no | Exim continues using the last successfully written sender lookup |
| `respond.freeze_mail`<br>freeze queued Exim messages attributed to a confirmed PHP-relay finding | root | automatic | /var/spool/exim/input, /var/spool/exim4/input, /var/log/exim_mainlog, /var/log/exim_paniclog, /var/log/exim4 (outside the systemd sandbox) | `auto_response.php_relay.freeze: false` | no | a compromised script keeps sending until an operator freezes the queue |
| `respond.hold_outgoing_mail`<br>request a cPanel account outgoing-mail hold through whmapi1 after sustained mail abuse | root | automatic | cpanel:account outgoing mail hold | `auto_response.enabled: false` | no | the mail abuse finding is reported but the account can continue sending |
| `respond.kill_process`<br>signal a malicious process through a kernel process handle, never a recycled PID, never root | CAP_KILL, root | automatic | process:signal | `auto_response.kill_processes: false` | yes | reverse shells and miners keep running until an operator kills them |
| `respond.mail_delivery_gate`<br>defer Exim delivery with fanotify permission responses when tempfail policy requires it | CAP_SYS_ADMIN, root | automatic | fanotify:mail delivery decisions | `email_av.enabled: false` | no | mail AV falls back to notifications and cannot defer delivery on scan failures |
| `respond.quarantine_file`<br>move a confirmed malicious file out of an account tree into CSM's quarantine, preserving owner, permissions and mtime | root | automatic | /home, /tmp, /var/tmp, /dev/shm, /opt/csm/quarantine | `auto_response.quarantine_files: false` | yes | malware is reported and left in place |
| `respond.quarantine_mail`<br>move an infected message out of the Exim spool after an antivirus match | root | automatic | /var/spool/exim/input, /var/spool/exim4/input, /opt/csm/quarantine | `email_av.quarantine_infected: false` | no | infected mail is reported and delivered |
| `respond.restart_mail_auth`<br>restart the panel's mail authentication service after a sustained outage | root | automatic | service:mail authentication | `auto_response.mail_auth_recovery.restart_enabled: false` | no | an authentication backend outage is alerted but not repaired |
| `respond.virtual_patch`<br>write a reversible deny rule into an account access file to close an exposed file | root | automatic | /home, /opt/csm/quarantine | `auto_response.virtual_patch_exposed_files: off` | no | exposed backups, dumps and configs stay reachable until the account owner fixes them |
<!-- END GENERATED MATRIX -->

Regenerate the table with `go run ./cmd/csm privileges --markdown`. A gate in
`internal/ci` fails when the page and the inventory disagree.
