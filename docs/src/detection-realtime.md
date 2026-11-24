# Real-Time Detection

CSM detects threats in under 2 seconds using kernel and log watchers that run inside the daemon: a fanotify file monitor, inotify tailers on auth, access, mail and FTP logs and the Exim spool, and a PAM brute-force listener.

Each section below describes one watcher or tracker: what it reads, which findings it raises and what you can configure. Exact rules and rare cases are collected under [Details](#details) at the end.

## fanotify File Monitor (< 1 second)

The file monitor watches the filesystems that contain `/home`, `/tmp`, `/dev/shm`, `/var/tmp`, the configured `account_roots` and the detected cPanel document roots. Missing roots are skipped.

The watcher receives close-write events, not create events. It reads the file through the descriptor the event delivered, so it scans the file that was written even if that file was renamed, replaced or deleted before analysis. No rename event is needed to inspect those bytes.

A file renamed or hard-linked into a watched tree, or a directory moved into one, raises no close-write event at its new path. The [placement monitor](#files-moved-or-linked-into-a-site) covers those when a placement backend runs. Otherwise they are left to the deep scan.

### What it detects

- Executables in shared temporary directories, even when named `.htaccess`, `.user.ini`, or `php.ini`, including atomic-save names. Some root maintenance writes get a Warning instead of Critical. See [Executables in shared temporary directories](#executables-in-shared-temporary-directories).
- Webshell creation (PHP files in web directories).
- Self-deleting droppers: a PHP or executable file created under a document root and unlinked within `thresholds.dropper_unlink_ttl_sec` (default 300s). This is the loader technique that creates a rogue admin and then erases itself before any scan. See [Self-deleting droppers](#self-deleting-droppers).
- PHP in uploads, languages and upgrade directories.
- PHP in `.ssh`, `.cpanel`, `.gnupg` or `.cagefs` directories, or in the `mail` directory of an account home (critical escalation). See [PHP in account mail directories](#php-in-account-mail-directories).
- Executable drops in `.config`.
- `.htaccess` injection and tampering: auto_prepend, eval/base64 handlers, CGI execution remaps and ModSecurity disablement. Handler abuse keeps its own finding name. These findings never quarantine the file. Automatic cleaning waits for a deep scan and requires `auto_response.clean_htaccess`.
- `.user.ini` tampering and `php.ini` tampering under configured or detected web roots.
- Obfuscated PHP (encoded, packed, concatenated).
- Fragmented base64 evasion (`$a="base"; $b="64_decode"`, where the function name is split across variables).
- Concatenation payloads (hundreds of `$z .= "xxxx"` lines with eval at the end).
- Payloads appended to the end of large legitimate PHP files (tail scanning). Realtime PHP checks scan the first and last 32KB. Periodic PHP content analysis scans a larger head window plus the tail.
- CGI backdoors: Perl, Python, Bash and Ruby scripts in web directories (for example the LEVIATHAN toolkit).
- SEO spam: gambling/togel dofollow link injection in PHP/HTML files.
- Phishing pages and credential harvest logs.
- Phishing kit ZIP archives.
- PHP carried inside a file served as an image. Finding: `php_in_image_realtime`. See [PHP inside images](#php-inside-images).
- A PHP file that includes or requires an image, archive or other non-executable file while also reading request input. See [PHP inside images](#php-inside-images).
- YAML signature matches (PHP, HTML, .htaccess, .user.ini, php.ini).
- YARA-X rule matches (if built with `-tags yara`). A failed scan raises `yara_realtime_scan_error`.

### Alerts and automatic quarantine

- Alerts are deduplicated per path, with a 30s cooldown.
- Each alert is enriched with process information: PID, command and UID.
- CSM quarantines a file automatically on a high-confidence realtime signature match. The match is validated by category, size, entropy and hex/execution checks.
- CSM also quarantines automatically on confirmed PHP request-to-execution flows and executable packed payloads. It uses the stable file version that was inspected.

A Critical `obfuscated_php_realtime`, `webshell_content_realtime` or `php_dropper_realtime` alert also queues the scheduled content analysis of that file, unless the file already had a file response. See [Follow-up analysis after a Critical alert](#follow-up-analysis-after-a-critical-alert).

### What the watch covers

CSM places a filesystem mark. It covers the whole filesystem, including all its bind mounts, which makes writes inside CloudLinux CageFS visible. Roots on that filesystem share one mark. The mark is not limited to the root's own path, even when the root is a mount point. A symlink or a bind mount can show only part of a filesystem, and the mark still covers all of it.

On kernels that fall back to mount scope, the mark covers the whole containing mount and misses writes through other bind mounts.

The startup log describes these scopes and says which roots share a filesystem mark. It also says when a watch root sits on the same filesystem as `/`. The mark then raises an event for every write on the machine. Failures to inspect or mark a root are reported even when other roots succeed.

### Which writes are analyzed

The daemon filters delivered file events before it queues them for analysis. It queues:

- non-directory objects with executable permission bits
- watched user crontabs
- PHP source
- configuration files such as `.htaccess`, `.user.ini` or `php.ini`
- known webshell names
- files under `.config` directories
- images inside hosted trees
- writes needed for self-deleting-file tracking

Other writes are dropped without analysis. In the shared temporary trees (`/tmp`, `/var/tmp`, `/dev/shm`) the decision uses the event descriptor. A descriptor that cannot be inspected is analyzed, not skipped.

Staging names written by an atomic save are resolved first, so a configuration file saved through one is still analyzed. Files retained for tracking keep their normal analyzer route, including suppression and WordPress checksum checks.

Three metrics count these decisions:

| Metric | Counts |
|--------|--------|
| `csm_fanotify_events_total` | Completed admission decisions |
| `csm_fanotify_events_admitted_total` | Queued events |
| `csm_fanotify_events_dropped_total` | Events lost to a full analyzer queue |

Subtract both admitted and dropped events from the received total to count events rejected before queue admission. That count includes events whose file path could not be resolved.

Queue overflow and shutdown are described in [Analyzer queue, overflow and shutdown](#analyzer-queue-overflow-and-shutdown). The WordPress rules are in [WordPress update staging](#wordpress-update-staging).

## Files Moved or Linked Into a Site

A file written elsewhere and then renamed or hard-linked into a site raises no close-write event at its new path. The placement monitor reports these files. Each one goes through the same admission, analysis and response as a write at that path, including quarantine of confirmed shells, whatever the file's age.

The monitor rejects a symlink at the final path component and verifies the file's identity before analysis. [How the monitor verifies a placed file](#how-the-monitor-verifies-a-placed-file) has the rules for each backend.

### Choosing a backend

`detection.placement_backend` selects how the monitor sees placements. It takes effect after a restart.

- `bpf` uses BPF LSM rename and link hooks. It sees renames, including both sides of a rename exchange, hard links, including a temporary file published with `linkat`, and directories moved in. It needs a BPF-tagged build and a kernel that can attach BPF LSM programs. Chosen explicitly, it has no fallback.
- `legacy` uses a second fanotify group that reports directory entries, on kernel 5.9 or newer. It sees files and directories moved in, and new entries, which include hard links and temporary files published with `linkat`. A new file that its own close-write already analyzed is not analyzed twice.
- `auto` (default) tries `bpf`, then `legacy`, then runs without a backend.
- `none` turns the monitor off. Placed files are left to the deep scan.

### Checking which backend runs

- The status response names the selection under `backends.placement`: `bpf`, `legacy` or `none`.
- `csm doctor` shows it as the `backend: placement` check. That check warns on `none` unless the config chose it.
- `GET /api/v1/capabilities` lists `bpf-file-placement` while the BPF backend runs.

Without a backend the daemon logs a startup warning that files moved or linked into watched trees are checked only by the deep scan.

### When a backend fails to start

A failed start raises `bpf_unavailable`, as for the other BPF monitors.

| Case | Result |
|------|--------|
| An explicit `bpf` choice cannot start | `bpf_unavailable`, High |
| An explicit `legacy` choice or `auto` fails for an unexpected reason | `bpf_unavailable`, High |
| `auto` falls back to `legacy` | `bpf_unavailable`, Warning |
| The kernel supports neither backend under `auto` | Shows `none`, no finding |
| The kernel lacks the `legacy` backend and `legacy` was chosen explicitly | Shows `none`, no finding |

### Directories moved in

A directory moved into a watched tree is walked, because its files raised no events of their own. Each file gets the same identity check and analysis as a placed file.

The walk never follows symlinks and runs on its own worker. It waits for analyzer room, so live writes keep priority, and works through a large tree in bounded passes.

When realtime cannot finish a directory, it raises one High `placed_dir_incomplete_realtime` naming the directory. The next deep scan covers the files it did not check. This happens when:

- the directory holds too many entries
- too many moved-in directories are waiting
- the analyzers stay busy for a whole pass
- entries cannot be read

### What the monitor cannot see

`placement_unresolved_realtime` reports what the monitor cannot see, with either backend.

| Case | Finding |
|------|---------|
| A moved or linked file whose path realtime could not resolve | High. Repeats at most once per alert cooldown for each device |
| A watch root the running backend cannot see | High |
| Roots on a filesystem this kernel cannot watch for placements | One Warning per start, naming the roots. The deep scan covers those files |
| A file or directory removed before realtime reached it | Nothing |

An unresolved path is, for example, a path deeper or longer than realtime protection follows, or a directory the `legacy` backend could not open.

A kernel queue overflow in the `legacy` backend raises `fanotify_kernel_overflow`.

### Files saved under a temporary name

A PHP file saved under an atomic-save temporary name and then renamed to its final name is not scanned twice. CSM reuses a recent clean scan only when all of these hold:

- The file's content, size, modification time, permissions and owner match that scan.
- The final name is analyzed the same way as the temporary name was.
- No setting or rule changed since.

Executable files and files too large for a complete read are always analyzed.

### Metrics and queue health

- `csm_fanotify_placement_skipped_total` counts the reuses of a clean scan described above.
- `csm_fanotify_placement_unverified_total` counts placements that failed the identity check.
- Queue health for the monitor appears under `bpf.placement` and `placement.dir_walk` in [protection queue health](api.md#protection-queue-health).

What happens when the monitor's queue is full is described in [Placement queue recovery](#placement-queue-recovery).

## Sensitive System File Watcher

CSM tracks a fixed set of system-configuration paths:

- the account and credential databases
- `sudoers` and its drop-in directory
- the SSH daemon config and its drop-in directory
- the system cron drop-in directories
- per-user crontabs

You cannot configure the set. If a path could be excluded, an attacker who knew about it could write there unnoticed. Findings are `sensitive_file_modified`.

### Sensitive file backends

`detection.sensitive_files_backend` chooses the backend.

- The `bpf` backend attaches an LSM hook that catches writes as they happen. It also re-reads the watched files and directories every `detection.sensitive_files_poll_interval` (default 5m), which picks up new and replaced files.
- The `legacy` backend hashes the content of the watched files on the same interval.

### What counts as a change

Both backends key on the path, not the inode. Most tools replace a config file by writing a temporary file and renaming it over the target. That gives the path a new inode and hides the write from the LSM hook. The BPF refresh therefore compares content and security metadata per path:

- A rename-over is reported as a change on the existing file.
- Only a path no previous refresh had seen is reported as newly appeared.
- A regular-file rewrite that leaves bytes, permissions, and ownership unchanged is not reported.
- Symlink targets are tracked, so retargeting a watched path remains visible even when both targets contain the same bytes.
- Non-regular entries are tracked by path identity without opening them for content reads.

The legacy poller compares content digests by path. CSM's own managed writes are suppressed by content, not by path.

### Writes demoted to Warning

A write is demoted to Warning when it happens inside a package-manager window, or when the writing process has a package manager or the control panel's own maintenance tooling as an ancestor.

The demotion is refused when a cron payload carries obvious persistence tokens. This veto applies to live writes and to added and modified cron files found by polling. It includes the shared crontab persistence patterns and their bounded base64 inspection, in addition to suspicious shell fragments.

### Nightly cron reschedules

cPanel reschedules its own jobs every night by changing their minute and hour. A modified file in `/etc/cron.d` is therefore also demoted when the only difference from the version CSM saw last is the minute and hour of jobs that already ran once a day at a fixed time. This applies to a change found by the refresh, the legacy poller or the scheduled cron check.

The finding stays High in these cases:

- A command, argument, user, environment line, job list or line order changed.
- A job runs more often or on other days.
- CSM has not seen the file before.

The schedule-based demotion is also refused in these cases:

- The file's ownership, mode or symlink target changed in the same interval, or could not be checked.
- The file has randomized calendar fields. Reloading such a file can choose new execution days, including for jobs whose bytes stayed unchanged.

Persisted schedule evidence must belong to the recorded content baseline. An interrupted update cannot justify demotion.

How CSM proves control-panel ancestry, and how hook and refresh findings interact, is in [Sensitive file watcher rules](#sensitive-file-watcher-rules).

## inotify Log Watchers (~2 seconds)

CSM tails auth, access, and mail logs in real time. It chooses the exact file paths per platform at daemon startup. See the `platform: ...` line in the daemon log.

| Log | Platforms | What it detects |
|-----|-----------|-----------------|
| cPanel session log (`/usr/local/cpanel/logs/session_log`) | cPanel only | Logins from non-infra IPs, password changes, File Manager uploads, sessions ended for security token failures |
| cPanel access log (`/usr/local/cpanel/logs/access_log`) | cPanel only | cPanel-API auth patterns |
| Auth log | All | SSH logins and failures. See [Auth log source](#auth-log-source) |
| Exim mainlog (`/var/log/exim_mainlog`) | cPanel; non-cPanel when the file exists | Mail anomalies, queue issues, SMTP brute force, probe abuse, and cloud relay abuse |
| Apache/LiteSpeed/Nginx access log | All | WordPress brute force (wp-login.php, xmlrpc.php), real-time. See [Web access log selection](#web-access-log-selection) |
| Mail log (platform file or journal) | All hosts with Postfix/Dovecot logs | IMAP/POP3/ManageSieve account compromise and mail brute-force; SMTP brute force on Postfix hosts with Dovecot. See [Mail log source](#mail-log-source) |
| FTP log | All with journald, otherwise cPanel only | FTP logins and failures. See [FTP logins and blocking](#ftp-logins-and-blocking) |
| ModSecurity error log | All (if ModSec installed) | WAF blocks and attacks. Auto-discovered from the detected web server |
| Nginx error log (`/var/log/nginx/error.log`) | Nginx hosts | General web errors, ModSecurity denies |

cPanel-only log watchers are not registered on non-cPanel hosts, so you will not see "not found, retrying every 60s" warnings for them on plain Ubuntu or AlmaLinux.

### Auth log source

Where syslog goes through journald, CSM reads sshd's own journal entries (`sshd.service` or `ssh.service`, sent as root). Otherwise it reads the auth log file: `/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL family and cPanel. Lines read from either file only alert.

How CSM reads an SSH login record is in [SSH login records](#ssh-login-records).

### Web access log selection

The automatic candidates are:

- `/var/log/apache2/access.log` (Debian)
- `/var/log/httpd/access_log` (RHEL)
- `/var/log/nginx/access.log` (Nginx)
- `/usr/local/apache/logs/access_log`, then `/var/log/apache2/access_log` and `/etc/apache2/logs/access_log` (cPanel, also written by LiteSpeed)

Automatic candidates exclude the cPanel access log. `web_server.access_logs` replaces the automatic web log candidates.

Each consumer picks from the candidates in its own way:

| Consumer | Which log it reads |
|----------|--------------------|
| Realtime watcher | The first existing log at startup. If none exists, it retries every candidate in order until one can be opened, then watches that path until restart |
| Periodic WordPress check | The first candidate with lines. It excludes that log's symlink aliases from the per-vhost scan. Other candidates can still be scanned when a per-vhost glob matches them |
| Reputation collection | All listed web logs, with addresses deduplicated. The cPanel log remains a separate source for panel checks |

### FTP logins and blocking

Where syslog goes through journald, CSM reads pure-ftpd's own journal entries (`pure-ftpd.service`). Otherwise, on cPanel hosts only, it reads `/var/log/messages`.

| Where the line comes from | What it can do |
|---------------------------|----------------|
| A failure in a journal entry that pure-ftpd sends as root | Can block, when pure-ftpd's `DontResolve yes` is set |
| A journal entry pure-ftpd sends as the logged-in user, logins among them | Only alerts |
| `/var/log/messages` | Only alerts |

Without `DontResolve yes`, pure-ftpd logs the client's reverse DNS name. Whoever controls that DNS record can make the name look like another IP address, so a numeric peer in the log cannot be trusted. FTP failures then only alert and never count toward a block or attack score.

To let FTP failures block:

1. Use `DontResolve yes` (also `DontResolve = yes` or `DontResolve : yes`) in a pure-ftpd configuration. For Debian's `/etc/pure-ftpd/conf/DontResolve`, write only `yes`. Every configuration source present must enable it.
2. Restart pure-ftpd. It reads its configuration only when it starts.
3. Run `csm doctor`. It names the sources that need attention.

CSM checks the setting for each journal entry, so disabling it takes effect without restarting CSM. The other conditions that keep FTP alert-only are in [FTP rules](#ftp-rules).

The FTP journal reader keeps failure history for `thresholds.ftp_fail_window_min` and raises the same critical login-after-brute-force alert as the file scan.

### Which login findings are emailed

A successful FTP login and a cPanel File Manager write are not emailed. On shared hosting every customer connects from an address that is not infrastructure, so both fire on ordinary use of a core feature.

Both stay on the findings page, in history and in incident correlation. File Manager activity also enters the attack database. FTP activity from unverified sources does not.

Failed FTP authentication, FTP brute force, a login from a brute-force source, and SSH logins are all still emailed.

The phpanel webhook and SSE event stream still receive these successful operations. The email and operator-webhook filter runs after data delivery.

#### Login check names on upgrade

New findings use `ftp_login` in place of `ftp_login_realtime`, and `ssh_login_unknown_ip` in place of `ssh_login_realtime`. Update external phpanel, export and SIEM rules to accept the merged names. Historical records and already queued deliveries can still contain the old names. The JSON schema is unchanged.

Existing `alerts.email.disabled_checks` entries and saved suppression rules for either retired name also match its replacement. The Settings page displays and saves the current names. A mute for one former producer covers the shared finding from both producers. It does not mute FTP brute-force escalations.

Pending SSH blocks and restored SSH incident evidence retain their blocking policy. Historical successful FTP activity remains excluded from incident blocking, including events carrying its retired name.

### Mail log source

`mail_logs.source` chooses where the Postfix and Dovecot watcher reads from: `auto`, `file` or `journal`.

| Value | What CSM reads |
|-------|----------------|
| `auto` | The configured journal units when the journal is usable. Otherwise the configured or platform file if present, then the journal units. See [How auto picks a mail log source](#how-auto-picks-a-mail-log-source) |
| `file` | The configured or platform mail log file. CSM retries it without switching |
| `journal` | The journal units in `mail_logs.units`. CSM retries them without switching. Needs a build with journal support |

A working reader stays attached until it stops or loses its file.

The default units are `postfix`, `postfix@-` (the Postfix instance on Debian and Ubuntu) and `dovecot`. Unit names match exactly, so list any further Postfix instance, such as `postfix@postfix-out`, in `mail_logs.units`. Keep `mail_logs.units` limited to mail services.

Each journal record reaches the mail detectors with its program name, process id and time, as a mail log file records them. Every mail detection works the same with either source.

#### File lines alert but never block

Any local user can write a line into a mail log file under any program name. File input has no sender credentials: a local user who can submit mail-facility syslog messages can forge failures or successes there. So CSM limits what a file line can do:

- A line read from a file alerts but never blocks an address.
- A login read from a file earns no customer standing or mail trust.
- File alerts use separate counters, authentication pairing, outage state and notification identities.
- File lines cannot trigger or suppress a trusted authentication verdict or suspend a mailbox.
- File lines keep their own password-spray tracking. A file login after file failures still raises a compromise alert, which never blocks.

Trusted logins after password spraying raise compromise alerts from trusted lines alone. This includes SMTP logins and logins to a different mailbox from those that failed.

On hosts with untrusted local users, use `mail_logs.source: journal` with the mail service units, or restrict the syslog input that writes the mail log.

#### What journal input accepts

Journal input requires a configured systemd unit and a root sender, or the `postfix` user for Postfix units. Messages must arrive through the syslog socket or native journal API. Output streams and entries without these credentials are ignored before any mail detector processes them.

Journal input follows new records from the selected services, including services with no prior entries. It does not replay older records on attachment.

File rotation, long records and reconnect behavior are in [Mail log reader rules](#mail-log-reader-rules).

## SMTP / Dovecot Brute-Force Tracker

This tracker detects credential stuffing, password spray, and raw SMTP probe storms. It runs as part of the Exim mainlog watcher on cPanel hosts and on non-cPanel Exim hosts where `/var/log/exim_mainlog` exists. On hosts without that log, such as Postfix servers that check SMTP logins against Dovecot, it reads the mail log.

Infrastructure IPs (from `infra_ips`) are never counted or blocked. Tune the tracker with the `thresholds.smtp_bruteforce_*`, `thresholds.smtp_probe_*` and `thresholds.mail_spray_*` keys in `csm.yaml`.

### SMTP signals

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `smtp_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window, or, with spray detection in enforce mode, fails on several untrusted mailboxes or on a missing mailbox many networks tried | IP blocked via nftables |
| `smtp_probe_abuse` | A single attacker IP exceeds the raw SMTP connect-rate threshold before AUTH. Reads Exim lines only | IP blocked via nftables |
| `smtp_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `smtp_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_bruteforce_suspected` | Spray detection in observe mode: the spray rules matched an SMTP source, or an address failed only on mailboxes it has [login standing](#login-standing) on. The message names SMTP | Visibility finding only |
| `mail_account_compromised` | A successful SMTP login after failures on two or more mailboxes including another one, or on a missing one, or after repeated failures on the same mailbox, the first at least an hour before the login | See the table below |

The response to an SMTP `mail_account_compromised` depends on the case:

| Case | What CSM does |
|------|---------------|
| Enforce mode, and a failed name was a missing mailbox many networks tried | Critical. The IP is blocked. The mailbox gains one compromise sign and needs another sign before suspension |
| The Critical case above, but the source is trusted on two or more other mailboxes | Downgraded to a High advisory |
| Every other case | High advisory, visibility only |

### Preparing Dovecot on Postfix hosts

Dovecot writes rejections only with verbose auth logging on:

```
# /etc/dovecot/conf.d/10-logging.conf
auth_verbose = yes
```

Leave `auth_verbose_passwords` at `no`. Lines that carry a logged password are ignored. `csm doctor` checks both settings on Postfix hosts with Dovecot.

### How a failed SMTP login is counted on Postfix hosts

The tracker counts a failed SMTP login when two lines from the mail log agree:

- Postfix's `SASL ... authentication failed` warning, which is the final result of the request, and
- Dovecot's rejection for the same client address shortly before it: `Password mismatch`, `unknown user`, or PAM's authentication failure.

Neither line counts alone. Postfix logs a Dovecot outage the same way as a wrong password. A Dovecot rejection is one password database's answer, and a later database can still accept the login or fail.

| Case | What CSM does |
|------|---------------|
| A rejection followed by a successful login | Nothing counts: there is no Postfix warning |
| A Dovecot error or warning for the same client within the pairing window | Withholds the failure |
| Several databases rejected one request | One Postfix warning counts once |
| A Postfix SASL backend warning | Withholds failures from that SMTP process, including stale replies after a failed reconnect |
| A reply that blames the authentication server, or rejects the authentication protocol without checking credentials | Never counts |

The exact pairing rules are in [SMTP failure pairing rules](#smtp-failure-pairing-rules).

Rejections for IMAP, POP3 and ManageSieve logins carry a session id. The [mail tracker](#mail-auth-brute-force-tracker) counts them from their login summaries. See [Dovecot answers for IMAP and POP sessions](#dovecot-answers-for-imap-and-pop-sessions).

### Login trust

An address earns login trust on a mailbox by logging in to it. The spray rules and the slow brute-force block use that trust to excuse some failures.

CSM reads a successful SMTP login from Postfix's record of an authenticated client, logged when its first recipient is accepted, or from an authenticated Exim delivery. The login counts for the mailbox it names.

How an address earns trust:

- A login from an address with no recent failures on other mailboxes earns trust for that mailbox only.
- Failures on just one other mailbox do not count here. That is the shape of an office device with a stale saved password. They do count when that mailbox does not exist or the login's own mailbox also failed.
- Any other login that follows failures on other mailboxes earns no trust. The exceptions are an address that already held trust on that mailbox from before those failures and, for IPv6, another address of the same /64 that holds aged trust on it.
- The trust counts once it is older than the fast detection window. This page calls that aged trust.
- Trust lasts as long as the spray memory window.

What trust does and does not do:

- The slow brute-force block skips an address only when it holds aged trust for every mailbox it failed on.
- Failures without a mailbox prevent that exemption until they leave the slow detection window.
- Trust never exempts an address from fast brute-force or subnet detection.
- Trust earned beside a failing mailbox vouches only for the mailbox that logged in. It cannot excuse missing-mailbox probes or downgrade a compromise while the earlier untrusted failures remain in memory.

### Long-memory spray detection

Long-memory spray detection remembers each address's failed SMTP logins for days. A botnet that tries each address only now and then is still caught. It flags an address in two cases:

- The address fails on several mailboxes it holds no trust for (the several-mailboxes rule).
- The address fails on a missing mailbox after enough networks have tried the same name.

A mailbox is missing when Dovecot reports it as unknown or when the [cPanel lookup](#missing-mailboxes-on-cpanel) finds no such name. For an address that holds trust on some mailbox, a missing name only counts toward the several-mailboxes rule, so one address typo does not block an office.

A login after failures on other mailboxes raises `mail_account_compromised`. The exception is when the failures were on just one other mailbox that may exist and the login's own mailbox did not fail.

The `thresholds.mail_spray_*` keys control the mode, the memory window and both rules.

| Mode | What the spray rules do |
|------|-------------------------|
| Observe (default) | Report `mail_bruteforce_suspected` and block nothing. An address is reported once per memory window, and again sooner only when it fails on more mailboxes |
| Enforce | Emit `smtp_bruteforce` |

Exim spray evidence comes from authentication failure records. Greetings, subjects and SMTP commands cannot supply a failure record or replace its attempted mailbox.

#### What never counts as spray evidence

- Failures during an authentication backend outage.
- Exim's temporary authentication failures (a 4xx reply, logged when Dovecot cannot answer).
- Failures withheld by pairing.

An outage is detected a little late, so a failure during one also discards that address's spray failures from the fast detection window before it. Successful SMTP logins during an outage leave spray memory unchanged.

#### IPv6 sources

IPv6 failures are remembered per /64, since one host can rotate through many addresses in it.

- Failures from any address of the /64 count together.
- Aged login trust that any of its addresses earned on a mailbox excuses failures on that mailbox for all of them.
- Two more rules accept trust held by any address of the /64, when that trust predates the /64's current untrusted failures. A missing name does not flag a trusted source on its first failure. A compromise finding is downgraded for a source trusted on two or more other mailboxes.
- A correct login to a mailbox the /64 already trusts starts trust for a new address.
- Trust is still earned per address, and the slow brute-force exemption still needs the address's own trust.
- Each failing address is blocked on its own.
- In observe mode a /64 is reported as one address would be.

#### Clearing and saving the memory

An operator unblock, allow or flush clears the address's spray failure history, for IPv6 that of its /64, and keeps its login trust.

The memory is saved every few minutes and at shutdown, so a daemon restart keeps it. What a restart restores is described in [Restored spray memory](#restored-spray-memory).

### Missing mailboxes on cPanel

On cPanel hosts, in observe and enforce mode, CSM checks whether a failed SMTP, IMAP or POP login name is a real mailbox. It uses cPanel's own account, domain and mailbox lists.

| Login name | Counts as |
|------------|-----------|
| A domain the server does not host | Missing |
| An unknown mailbox on a hosted domain | Missing |
| A bare name that is not a cPanel account | Missing |
| A real mailbox or cPanel account | Existing |
| A name within two edits of a real mailbox, counting the local part and the domain together | That mailbox |
| Any name CSM cannot tell about | Unknown. It counts only toward the several-mailboxes rule |

For a name that counts as a real mailbox by typo, spray memory records the failure against the real mailbox. Aged login trust on it excuses the typo, and the typo is never a first strike.

Login trust and spray failures treat a valid mailbox domain with or without its final dot as the same name, including saved history. The fast, slow and per-mailbox failure counts use the attempted name with surrounding whitespace removed and ASCII case ignored. They do not use typo matches.

Limits of the lookup:

- CSM holds these lists for a short time, so a mailbox created or deleted just now can get its old answer.
- When the lists cannot be read, every name stays unknown. The daemon log gets one warning, and one line when they can be read again.
- Only the default `thresholds.mail_brute_account_key` reads the whole login name. With any other key, IMAP and POP failures skip this check and stay unknown.
- Each login keeps that setting through the check, even if configuration reloads while it is being handled.

## Cloud-Relay Credential Abuse

This check detects authenticated outbound Exim deliveries where the same mailbox is sending through public-cloud relay sources. The finding is `email_cloud_relay_abuse`.

The realtime Exim mainlog watcher evaluates new accepted deliveries. A bounded startup replay covers recent lines already on disk. The replay reads the time zone and process ID that Exim's `log_timezone` and `pid` log selector add. A restart does not repeat an alert for sends already reported.

Under the global auto-response and dry-run settings, CSM suspends the abused mailbox's logins and outgoing mail. The account-wide mail hold is the fallback.

If you have legitimate cloud mailers, opt out specific mailboxes or domains under `email_protection.cloud_relay`, or use `email_protection.high_volume_senders` for known high-volume senders.

## Authenticated Sender Profile

This check catches a stolen mailbox password that is used quietly: under the rate limits, from residential addresses with no cloud reverse DNS, using individually addressed messages. The finding is `email_compromised_account`.

Every authenticated Exim submission updates a rolling hourly window. It also updates the mailbox's own history of source addresses, source countries and envelope recipients, grouped by UTC day. Repeated sends keep each source current, and a busy mailbox continues to accept new source and country evidence.

### Sender profile signals

Four signals raise the finding:

| Signal | Severity |
|--------|----------|
| Sends from several countries within one hour, the pattern of a credential checker validating a stolen password | Critical |
| Far more distinct source addresses within one hour than the mailbox's own recent maximum | High, Critical when the sends also come from a country the mailbox never sent from |
| Far more distinct source addresses within one day than the mailbox's own recent maximum | High, Critical as above |
| Far more distinct recipients within one day than the mailbox's own recent maximum, each in its own message | High, Critical as above |

Each bar adapts to the mailbox's own prior maximum, with a fixed minimum. A shared office mailbox or a travelling owner is judged against their own habit, not a global number.

Repeated findings are suppressed during a cooldown. Escalation from High to Critical remains possible.

### Response

A Critical finding suspends the mailbox's logins and outgoing mail under the auto-response and dry-run settings, with the account-wide mail hold as the fallback.

Source addresses are never blocked for this finding. They rotate per message, and the owner's own address can be among them.

Mailboxes listed in `email_protection.high_volume_senders` are not profiled.

### New countries

- A country listed in `suppressions.trusted_countries` is never treated as new.
- A mailbox needs established prior activity before a new country counts.
- A newly seen country remains relevant if unusual sending develops later in the same UTC day.

CSM uses the time in the Exim record to place a loopback send. It uses the country of the mailbox's most recent webmail login only if that login preceded the send and was recent enough to locate it. An unlocated login clears the previous location.

### Recipient fan-out

Recipient fan-out counts distinct envelope recipients of individually addressed messages. Bulk announcements do not contribute. Quoted addresses remain single recipients. Records with ambiguous recipient metadata do not contribute recipient evidence, but verified source evidence still counts.

### History and restarts

Daily history covers the recent baseline period and expires even for inactive mailboxes. CSM caches it and saves it periodically, before idle eviction and during normal shutdown.

- An abrupt termination can lose submissions since the last save.
- A restart always starts a fresh hourly window.
- Save failures retain pending history for retry.
- An unreadable baseline pauses profiling for that mailbox until the store can be read again.

## Mailbox Compromise Evidence

A stolen mailbox rarely trips a single loud alarm. It shows a few weak signs, each of which an honest owner also produces now and then. CSM keeps a ledger of these signs per mailbox. Each sign is reported once in the audit log, history and the daily summary, and is not mailed on its own.

When the evidence adds up, CSM suspends the mailbox and raises one Critical `email_mailbox_compromise` finding.

### The signs

| Sign | Finding |
|------|---------|
| A login or send from a new country | `email_suspicious_geo` |
| A login after failed logins on the same mailbox | `mail_account_compromised` |
| A forged sender domain | `email_forged_sender` |
| Bulk recipients | `email_bulk_recipients` |
| An external redirect | `email_filter_exfil` |
| Outbound reputation deferrals | `email_outbound_reputation` |

Two new countries seen close together carry more weight. A redirect created soon after a foreign login also carries more weight.

How signs count:

- Each kind of sign counts once, however often it repeats.
- Signs expire a week after their last sighting.
- The ledger groups older details when many distinct values appear.
- Mailboxes in `email_protection.high_volume_senders` send mailings by design, so forged sender domains and bulk recipients do not count for them.

### When the evidence adds up

The `email_mailbox_compromise` finding lists the evidence and the restrictions applied. With automatic response disabled or dry-run enabled, the finding says CSM would suspend the mailbox. Further signs update the same incident.

Release restrictions applied by CSM on the Email page, Suspended tab. Release discards the mailbox's evidence, including delayed observations from before release.

New sending evidence reopens a login-only incident that left the mailbox open, so a suspension that the hourly cap held back can proceed. A completed suspension keeps its single incident.

### A login after failed logins

A mail login after failed logins on the same mailbox keeps its Critical `mail_account_compromised` finding and is also a sign. An owner who mistypes a password produces the same pattern, so the weight depends on the number of failures:

| Failures on the mailbox before the login | Weight of the sign |
|------------------------------------------|--------------------|
| A few | It weighs like a new country and never suspends a mailbox alone |
| At least `mail_bruteforce_threshold`, counted over every spelling of the address | The login was guessed. This sign suspends the mailbox on its own |

Failures count only inside the tracker window and on the same mailbox. A login to a mailbox the address has login standing on is a High finding and adds no sign.

A guessed login (at least `mail_bruteforce_threshold` failures) still raises the stronger sign when an earlier login after only a few failures has already alerted and repeat alerts for it are being held back. A spray verdict on the same login does not lower that weight. The stronger weight exists only in the running process. Replayed findings use the weaker sign.

This sign uses the logged login time, including when a backlog is read. Expired logins and logins from before a mailbox's release do not become new evidence. The resulting incident records which hosting account owns the mailbox. The response uses that record even if the general account lookup is unavailable or stale.

### A login or send from a new country

A login from a new country is an `email_suspicious_geo` finding, at most one per mailbox a day.

- A mailbox needs a few logins of history first.
- A country in `suppressions.trusted_countries` is never new.
- Webmail, IMAP and POP3 logins share the same history and use the login time in the log.
- A session opened by the panel or a reseller is not treated as the mailbox owner's location.
- A login read from a mail log file is checked against that history but never added to it or counted as evidence. Its alerts keep a separate daily limit.

Two kinds of send are the same sign: an authenticated send from a country the mailbox never logged in from, and a webmail send after a webmail login from a new country. A send reports `email_suspicious_geo` the first time the ledger records its country.

### External redirects

A mail filter or Sieve script that sends a mailbox's mail to an outside address keeps its own `email_filter_exfil` finding and is also a sign, dated by the script's file time.

A forward that leaves the mailbox its own copy, with nothing else corroborating it, is not a sign. It is what a webmail forward rule produces, and it stays a Warning for review.

The incident finding names the script and its target. CSM leaves the script in place as evidence, so remove it after review.

### Outbound reputation deferrals

When large providers refuse or defer this server's mail because of an address's reputation, the address is an `email_outbound_reputation` finding at most once a day. The finding names the authenticated mailbox that sent most of the refused mail.

A tie or an incomplete count leaves the finding at address level. If another mailbox leads a later burst, its ledger records that evidence even after the daily notice.

### Bulk recipients and forged senders

A mailing is an `email_bulk_recipients` finding the first time the ledger records it.

An authenticated send whose envelope sender is a domain the login's hosting account does not own is an `email_forged_sender` finding the first time the ledger records that domain. A subdomain follows its closest mapped parent, including aliases and subdomains delegated to another hosting account.

## Mail Auth Brute-Force Tracker

This tracker detects credential stuffing and password spray against IMAP, POP3, and ManageSieve. It runs through the `mail_logs` reader:

- The file source uses `/var/log/mail.log` on Debian-family hosts and `/var/log/maillog` on RHEL-family and cPanel hosts.
- The journal source reads the configured Postfix/Dovecot units.

The tracker works together with the geo-based login monitor, so `email_suspicious_geo` keeps reporting successful logins from novel countries as [compromise evidence](#mailbox-compromise-evidence).

Tune the tracker with the `thresholds.mail_bruteforce_*` keys in `csm.yaml`. It is independent from the SMTP tracker, so you can tune the Dovecot noise floor separately. Infrastructure IPs are never counted or blocked.

### Mail login signals

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `mail_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window without matching successful mailbox activity, or, with spray detection in enforce mode, fails on several mailboxes it holds no trust for or, on cPanel hosts, on a missing mailbox many networks tried | IP blocked via nftables |
| `mail_bruteforce_suspected` | An established good source hits the per-IP failed-auth threshold with a confined stale-password pattern, an address fails only on mailboxes it has [login standing](#login-standing) on, or spray detection in observe mode matched an IMAP/POP source. The spray message names IMAP/POP and the rule | Visibility finding only. No auto-block |
| `mail_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `mail_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_account_compromised` | A successful login comes from an IP that repeatedly failed auth against the same mailbox, or follows failures on two or more mailboxes including another one, or on a missing one, or repeated failures on the same mailbox, the first at least an hour before the login | See [Response to a compromised login](#response-to-a-compromised-login) |

The `mail_bruteforce` and `mail_bruteforce_suspected` alerts name the mailboxes the source was hitting. They give per-mailbox failure counts and a count of attempts that named no mailbox. That makes a real attack on a live mailbox easy to tell apart from dictionary noise.

### Response to a compromised login

| Case | What CSM does |
|------|---------------|
| A Critical `mail_account_compromised` | Blocks immediately and adds one mailbox compromise sign. Under auto-response on cPanel or on Stalwart with its API key, suspension requires another sign. A bare account login only alerts about the account |
| The source has established history on at least two other mailboxes from before its current untrusted failures | High advisory. The source is not auto-blocked and the mailbox is not suspended |
| The source has [login standing](#login-standing) on the mailbox from before the failures | High advisory. The source is not auto-blocked and the mailbox is not suspended |
| A login after failures on other mailboxes | Critical only in enforce mode when one of them was a missing mailbox many networks tried. Every other spray case is a High advisory |

A compromise from an IP with established history on at least two other mailboxes, from before its current untrusted failures, stays visible as a High advisory. It does not feed direct, incident, or spray auto-blocking.

### Established good sources

Established good sources with a confined stale-password pattern emit `mail_bruteforce_suspected` instead of an IP block. Wider spraying, and compromise from a source without established multi-mailbox history, still block.

### Spray detection shared with SMTP

IMAP and POP logins share the [long-memory spray detection](#long-memory-spray-detection) described for SMTP. One memory holds the failures and login trust of both. Failed SMTP and IMAP logins from one address on two different mailboxes therefore count together toward the several-mailboxes rule.

A login that follows failures on other mailboxes earns neither login trust nor good standing. There are three exceptions:

- The failures were all on one other mailbox that may exist, and none were on the login's mailbox.
- The address already held trust on the login's mailbox from before those failures.
- For IPv6, another address of the same /64 holds aged trust on the login's mailbox.

The slow brute-force block downgrades to `mail_bruteforce_suspected` only when the address holds good standing or aged login trust on every mailbox it failed on. A login to some other mailbox does not count.

### How often a finding repeats

| Finding | Limit |
|---------|-------|
| `mail_bruteforce` | At most one per address per suppression period |
| `mail_account_compromised` | At most one per login |
| The High advisory for a login after failures on other mailboxes | Once per address and mailbox per memory window, so a client that polls every few minutes does not repeat it |
| In observe mode, a login after a missing name that several networks tried | The same limit as the High advisory |

### After a password crack

A login identified as a short-window password crack revokes trust for that address and mailbox for the spray memory window. This happens even when the compromise alert is suppressed. For an IPv6 address it revokes that mailbox's trust for every address of its /64.

- Further SMTP, IMAP or POP logins cannot restore that trust during the window.
- Suspect logins do not count toward successful activity that exempts later failures.
- A crack also removes any good standing from a recent login that had not yet aged into established standing.
- Account cache pressure does not hide a crack while its per-address failure history remains.

### Authentication backend outages

When the mail authentication backend itself fails (for example dovecot cannot reach `cpdoveauthd`), every login fails regardless of password. CSM detects a burst of these backend errors and does the following:

- It pauses `mail_bruteforce` and `mail_subnet_spray` auto-blocking.
- It keeps the failures out of spray evidence.
- It raises a `mail_auth_backend_degraded` warning, so the outage is visible and CSM does not mass-block legitimate users.

IMAP and POP successes during this degraded period do not update spray memory, raise spray alerts, or earn good standing. The short-window compromise detector still uses recorded failures. Detection resumes automatically once the backend recovers.

### Attribution and the reputation exemption

Mail login attribution uses the connection fields outside the raw login name. Names containing field-like text or angle brackets remain one account name. Records without a usable remote address do not count toward IP blocking or login trust.

A reputation exemption requires a mail login in the last day that the mail service itself recorded (its own log or journal entry). A line in a mail log file, which any local user can write, never qualifies.

The last trusted mail login is saved independently of FTP and cPanel activity, which cannot erase or renew the exemption. Older saved customer summaries without verified mail history do not qualify. A new trusted mail login is required.

### Login standing

Login standing means an address has a history of trusted logins to a mailbox. CSM uses it to tell a device with an old saved password from a guessing tool. There is no setting.

An address has login standing on a mailbox when trusted logins from that exact address to that mailbox meet all of these conditions:

- They began at least a day before its current failures.
- They fall on at least two different days (UTC).
- The latest of them was within two weeks of the failures starting.

The current failures begin at the earliest failure episode (run of failures) still active for the address, across all spellings of that address. The same starting point applies to earning standing and to softening findings. Logins after the failures began never count, so a login cannot excuse the attack it follows.

IMAP, POP, ManageSieve and SMTP share one standing per mailbox, since they use one password. An IPv6 address is judged on its own, not by its /64.

#### What standing changes

| Case | What CSM does |
|------|---------------|
| A burst of failed logins, fast or paced, from an address that only fails on mailboxes it has standing on | Raises `mail_bruteforce_suspected` instead of a block. The usual cause is a device still trying an old saved password |
| A login that the IMAP/POP/ManageSieve tracker would otherwise report as a password crack, when the address had standing on that mailbox before the failures | Raises `mail_account_compromised` at High. No block or mailbox suspension from that finding, and the address keeps its trust |

The existing good-source and success-dominance exemptions still raise no compromise finding. Separate spray verdicts still apply.

Standing never excuses:

- failures on any other mailbox
- failures that name no mailbox
- spray, subnet or account-spray detection
- SSH, FTP and cPanel logins

#### How many failures standing excuses

Standing excuses failures on one mailbox up to two caps:

| Cap | Limit | Shared between protocols |
|-----|-------|--------------------------|
| Per brute-force window | Ten times the brute-force threshold (`mail_bruteforce_threshold`, or `smtp_bruteforce_threshold` for SMTP) | No. SMTP has a separate cap from IMAP/POP/Sieve |
| Per day | 1000 failures from that address in a day. The count starts again one day after its first failure | Yes. Counted over every mail protocol |

A device retrying an old saved password stays far below both. A guessing tool does not.

Past either cap the mailbox has no standing for that address. The failures block as they would without standing, and a login after them is reported as a password crack. An earlier standing advisory never silences the password-crack alert that follows once the cap is passed.

Alternate spellings of the same address share these counts. Delayed events from another protocol and backward clock changes do not reset the daily count. The existing good-source exemptions are unchanged.

#### The daily count

- The daily count is held in memory on the standing row and starts with its first counted failure.
- Clean logins and saves do not reset it.
- Removing the row also removes the count and its standing. A new row must earn standing again.
- A daemon restart restores saved standing but starts a new daily count.
- Failures without a standing row, during a backend outage, or answered with an SMTP temporary failure do not count toward this daily cap.

#### How standing is earned

Standing is earned only from trusted logins the trackers treat as clean. A login does not earn standing when it is:

- a line from a mail log file, not one the mail service itself recorded
- made during an authentication backend outage
- a login the spray memory calls unclean or the tracker calls a cracked password
- a login that follows failures from the same address, on any of these protocols, on the login's own mailbox or naming no mailbox, while those failures are among the address's current failures. This does not apply when the address already had standing when the failures began.

This earning check uses shared spray evidence, including IPv6 /64 evidence. It does not change the exact-address cutoff for softening a compromise finding. An idle gap longer than the trackers' failure windows starts a new episode even while older spray evidence remains.

#### How standing is lost

Two events remove the mailbox's standing from every address: an IMAP/POP/ManageSieve password crack from an address without prior standing, and any mailbox response to a compromise. The owner earns it again from new logins.

Mailbox response withdraws standing even in dry run or with auto-response disabled. SMTP has no separate password-crack detector that revokes standing.

#### Storage

Standing is saved every minute and at shutdown. It is never written to backups or exports.

The index is bounded. A mailbox drops its least recently used address when full. A full index refuses new addresses and does not remove any, so a flood of logins can never stop a block.

## Stalwart Mail Server

On hosts where the `stalwart` service is the mail server and cPanel is absent, CSM reads Stalwart's daily log instead of the Postfix and Dovecot mail log.

Stalwart logs failed logins at debug level by default. Password guessing over SMTP, IMAP and POP3 is invisible until the `auth.failed` event is raised to info. `csm stalwart setup` does that. See [Preparing Stalwart](#preparing-stalwart).

`csm doctor` reports whether the newest log holds failed logins, whether it is current, and whether its recent lines are in the layout CSM reads.

### The log CSM follows

CSM follows the newest `stalwart.log.YYYY-MM-DD` file in `stalwart.log_dir` (default `/var/log/stalwart`), starting at the end of the current file. Files dated later than tomorrow in UTC are ignored.

| Case | What CSM does |
|------|---------------|
| Stalwart starts the next day's file | Reads the old file to its end, then the new one from its start |
| The directory or file is missing | Raises `mail_log_source_unavailable` |
| The next day's file cannot be found or opened for a while | Raises `mail_log_source_unavailable` and keeps retrying |
| The current file is removed | Does not go back to an older day's file |

`stalwart_log_degraded` warns in three cases:

- An hour of log lines holds none in Stalwart's layout, as after an upgrade that changes it.
- Many authenticated SMTP sends in an hour cannot be matched to a login.
- The log stops growing for hours while Stalwart runs.

### Listener ports

CSM assigns each event a protocol from its listener port:

| Ports | Protocol |
|-------|----------|
| 25, 465 and 587 | SMTP |
| 143 and 993 | IMAP |
| 110 and 995 | POP3 |
| 4190 | ManageSieve |
| 80, 443 and 8080 | HTTP (JMAP and webmail) |

List other listeners in `stalwart.ports` as `PORT:PROTOCOL`. Logins and bans on an unmapped port are ignored. Sends on one, such as a local submission listener, count toward volume and recipients only.

### What CSM reads

- Failed and successful logins on SMTP listeners feed the SMTP brute-force tracker, and those on IMAP, POP3 and ManageSieve listeners feed the mail brute-force tracker. The same thresholds, findings, blocks and spray rules apply as on Postfix and Dovecot. Loopback, private and infrastructure addresses never count.
- Failed logins on the HTTP listener raise `stalwart_webmail_bruteforce` at the mail brute-force threshold. Stalwart can log an address from a forwarded header there, so this finding never blocks. Stalwart's own throttling and bans still apply to it.
- Authentication, abuse and scan bans Stalwart logs for an SMTP, IMAP, POP3 or ManageSieve listener raise `stalwart_ban`, which blocks the address for the auto-response block length. Stalwart's ban stays in place. Exception: a failed-login ban of an address a customer logged in from within the last 30 days, such as an office network with one stale password, raises `stalwart_ban` at High and is not blocked.
- Loiter bans, refused connections and bans on the HTTP listener or an unmapped port are ignored.
- Authenticated sends on SMTP listeners and unmapped ports are matched to the login on the same connection and feed the rate, sender profile and cloud-relay checks. Sends from a loopback or private address, such as sites on the same server, and sends on an unmapped port count toward volume and recipients only.
- Unauthenticated messages Stalwart queues are matched by queue id to the lines that record their delivery, so the Email page counts what the spam filter did with each one and the sending address gets spam evidence. Rejected and discarded mail is read from the filter's own line. Messages on the HTTP listener are ignored. See [Stalwart hosts](antispam.md#stalwart-hosts).

### Preparing Stalwart

`csm stalwart setup` prepares Stalwart for CSM through Stalwart's admin API at `stalwart.api_url` (default `http://127.0.0.1:8080`). It changes four settings and adds a spam rule, then reloads Stalwart's settings once. It also creates the role, service account and API key CSM uses to suspend mailboxes and lift bans.

The API address, including a `--url` override, must not contain a login, query or fragment. Remote addresses require HTTPS and cannot use this host's port locks as protection.

Run it as root with a Stalwart admin login:

```
STALWART_USER=admin csm stalwart setup --dry-run --password-file /root/stalwart-admin.pw
STALWART_USER=admin csm stalwart setup --password-file /root/stalwart-admin.pw
```

`--dry-run` shows each step and changes nothing.

#### Passing the admin login

- `STALWART_PASSWORD` works in place of `--password-file`.
- `--password-stdin` reads the password from stdin, for example `printf '%s\n' "$PW" | csm stalwart setup --password-stdin`. The user is then `STALWART_USER` or `admin`.
- On a terminal, setup prompts for missing values. When you enter both values, the username is hidden too.
- Press Enter at the user prompt for `admin`.
- Type the password at the password prompt, where echo is off even with `--password-stdin`.
- Ctrl-D at an empty prompt cancels setup.

Before sending the login to an address on this host, setup and doctor check that the API port and each connected peer belong to root or Stalwart's service user (`stalwart` or `stalwart-mail`). An unreadable ownership record stops the login. This also protects reconnects when Stalwart restarts.

#### The eight steps

| Step | Name | What setup does |
|------|------|-----------------|
| 1 | Failed-login logging | Sets the `auth.failed` event to info unless it is already logged at info, warn or error |
| 2 | Webmail client addresses | Makes Stalwart's HTTP listener take the client address from `X-Forwarded-For` (1 hop), when that is safe. See [Step 2](#step-2-webmail-client-addresses) |
| 3 | Ban expiry | Sets Stalwart's failed-login, abuse and scan ban periods to `auto_response.block_expiry`, so its bans end when CSM's blocks do. Loiter bans are left alone |
| 4 | Spam verdict logging | Sets the `spam.classify` event to info unless it is already logged at info, warn or error. This step changes nothing about how mail is handled |
| 5 | Address list | Creates the spam rule `CSM_IP` and one scoring tag per kind of listing. See [Step 5](#step-5-address-list) |
| 6 | Response role | Creates the role `CSM response`. See [Step 6](#step-6-response-role) |
| 7 | Response account | Creates the account `csm-response` holding only that role and no password. See [Step 7](#step-7-response-account) |
| 8 | Response key | Creates an API key of `csm-response` and writes it to `stalwart.api_key_file`. See [Step 8](#step-8-response-key) |

Step 4 exists because by default Stalwart logs the mail its spam filter rejects or discards only at debug level.

Steps 6 to 8 need no settings reload. They run only when the API address is on this host. Otherwise setup skips them and the key is never sent. When one of them warns, setup exits 1: CSM then can neither suspend mailboxes nor lift Stalwart's bans.

#### Reruns and failed steps

| Case | What to do |
|------|------------|
| A second run after a successful one | Nothing. It changes nothing and does not reload |
| A settings step fails | Part of it may already be stored. Resolve the error and reload settings in Stalwart before running setup again |
| One of steps 6 to 8 fails | Resolve the error and run setup again |
| Only the reload failed | Restart Stalwart. A second run reads the stored settings as done |

#### Step 2: webmail client addresses

With this step, webmail and JMAP failures name the real client instead of the web server. Anyone who can connect to the listener could forge the `X-Forwarded-For` header, so setup only does this when all of these hold:

- The API address names this host on loopback.
- Every HTTP listener has known loopback-only binds.
- The running CSM daemon locks each of their ports to the web server and Stalwart.

Otherwise setup skips the step and prints what is missing. That includes the line to add under `firewall` in `csm.yaml`, for example `local_port_locks: ["8080:www-data,stalwart"]`. Restart CSM after adding it. See [Local port locks](firewall.md#local-port-locks).

If Stalwart already takes forwarded addresses without that protection, setup reports the step as unsafe and exits 1 without changing it.

Two things remain for you to do:

1. Make the web server set the header. With one hop Stalwart reads the last `X-Forwarded-For` entry, so the web server in front of it must set that header itself. nginx passes a client's header through unchanged unless told otherwise. Add `proxy_set_header X-Forwarded-For $remote_addr;` (or `$proxy_add_x_forwarded_for`) to the Stalwart location. Without it a remote client chooses the address Stalwart logs and bans. Setup cannot check this.
2. Keep site code away from the users in the lock line. Run PHP-FPM pools as their own users, not as the web server's user. Use absolute PHP-FPM include paths, because relative includes depend on the FPM build or runtime prefix, which CSM cannot verify.

Setup and `csm doctor` check the second point. When a PHP-FPM pool, a running PHP or CGI worker, an Apache script module or LiteSpeed's PHP handler runs as a user the lock admits, or as root, setup skips the step. It lists each shared UID and what runs as it, and reports forwarded addresses already in use as unsafe.

The comparison uses the UIDs admitted by the running firewall, including numeric pool users and account aliases. Editing `firewall.local_port_locks` alone does not change that proof. Restart CSM after upgrading so it can report the installed identities.

When the inspection itself fails, setup and doctor report the inspection error without changing Stalwart to forwarded addresses. [Which users count as running site code](#which-users-count-as-running-site-code) lists what is inspected.

#### Step 5: address list

Setup creates the spam rule `CSM_IP` and one scoring tag per kind of listing. Stalwart then adds up to 4 to the spam score of a sender on CSM's address list. More of their mail goes to Junk, or is rejected or discarded at the scores set in Stalwart. This is the one setup step that changes what happens to mail.

- Setup creates the rule switched on. To stop it, switch the rule off in Stalwart's admin interface. Setup never switches it back on and reports a rule that is off as done.
- Setup creates missing tags but never changes an existing tag, so a tag's score is yours to set in Stalwart.
- When the rule's condition differs from CSM's, setup resets the condition and leaves the rule's other fields alone.
- A rule named `CSM_IP` that CSM did not make is left alone with a warning.
- If Stalwart's spam rules cannot be read, setup warns and continues with the other steps.

#### Step 6: response role

The role `CSM response` holds the permissions CSM needs to suspend accounts, lift bans, keep its address list in Stalwart and read the settings setup checks, plus Stalwart's own `User` role. Including `User` lets the key change user accounts.

When the role lacks any of these or denies permissions, setup rewrites it to CSM's list and clears denials. If Stalwart has no role named `User`, setup warns and skips the next two steps.

#### Step 7: response account

The account `csm-response` holds only that role and no password. It can still receive mail at its address.

- On a server with several domains, name the domain with `--account-domain NAME`. Otherwise setup skips the step and the next.
- On a server with tenant administrators, put the account in a domain only the server administrator controls. Whoever can edit the account could give it a password.
- If more than one account is named `csm-response`, setup warns and creates nothing.

Setup also refuses an existing `csm-response` account that has a password or another sign-in credential, has sign-ins stopped, or holds keys without CSM's role. It warns, changes nothing and skips the key step.

#### Step 8: response key

Setup creates an API key of `csm-response` that works only from `127.0.0.1` and `::1`. It writes the key to `stalwart.api_key_file` (default `/etc/csm/stalwart-api.key`, owned by root, mode 0600), then deletes the account's other keys. The key is never printed.

| Case | What setup does |
|------|-----------------|
| A key already in the file that Stalwart accepts for `csm-response`, and it is the account's only key | Keeps it |
| The account has other keys | Replaces them all, so a rerun finishes a clean-up that failed |
| The file cannot be written | Deletes the new key. The old one keeps working |
| The key file is not a root-owned regular file closed to group and others | Stops with exit 1 |

To rotate the key, delete the file and run setup again.

#### What setup also reports

Setup reports listeners that accept the PROXY protocol, which it does not change. It also reports whether Stalwart's spam filter is on and at which scores it files spam to Junk, rejects or discards. Doctor prints the same.

A filter that is off is a warning. Setup never switches it on or off. If its status cannot be read, setup warns and continues with the other steps. A refused admin login still stops setup.

#### What doctor checks

`csm doctor` checks the same steps read-only through CSM's API key, and says whether Stalwart accepts the key. Doctor warns about any step that setup would change. It also warns about a response step (steps 6 to 8) that setup refuses until you clear the problem it names.

Only root can read the key, and a missing key is reported even while Stalwart is down. Without a working key, or for an API address on another host, doctor uses an admin login from `STALWART_USER` and `STALWART_PASSWORD` when both are set.

Doctor's spam lines say:

- whether Stalwart logs the mail its filter rejects or discards
- whether the filter is on and at which scores it acts
- whether its DNS blocklists answer
- while the address list rule is on, whether Stalwart scores senders on CSM's address list
- when Stalwart's spam classifier is still learning, and how many ham and spam samples it has

Doctor also warns when Stalwart's HTTP listener logs a login from another host on a port CSM does not lock. It warns when Stalwart bans a CDN or proxy address, which locks out every client behind it.

The blocklist, address list and classifier checks have their own rules. See [Doctor's Stalwart spam checks](#doctors-stalwart-spam-checks).

### Known limits

- Suspending a Stalwart mailbox stops new sign-ins only. Sessions that are already open stay open until they end.
- Webmail logins appear in Stalwart's log from the proxy address, so a webmail login after failures is not detected as a compromise.
- Sends through webmail or JMAP are not tied to an account, because one proxy connection can carry several users, so the send checks do not see them.
- A listener behind PROXY protocol logs the client address, not the connecting peer. CSM cannot tell such listeners apart from the log alone.

### Suspending Stalwart mailboxes

CSM suspends a hacked Stalwart mailbox through the API key that `csm stalwart setup` writes. The auto-response and dry-run settings apply as on cPanel.

CSM stops the account's sign-ins through Stalwart's API after one of these:

- an `email_mailbox_compromise` incident
- a Critical `email_compromised_account` finding
- a Critical `email_cloud_relay_abuse` finding

Stopping sign-ins also stops the account sending. A Critical `mail_account_compromised` login adds one sign and needs another sign before the incident suspends the mailbox.

The mailbox is listed on the Email page, Suspended tab, where Release allows sign-ins again on the same account. Release does not change the password. Sign-ins someone else had already stopped are left alone and not listed.

#### Aliases

- A sign-in through a mailbox alias or a domain alias suspends the account behind it.
- All aliases share that account's suspension and release history.
- Sends that were buffered and logged before a release do not suspend the account again.
- Reassigning an address does not transfer a suspension to its new account.

#### What CSM does not suspend

CSM does not suspend admin accounts, its own API key account, accounts its key may not change, or account names without a domain. Bare names containing `+` or `%` are not converted to mailbox addresses. That login convention applies only to cPanel.

A refused suspension asks staff to change the password in Stalwart. Bare account logins only alert.

#### Without the key file

The API key is sent only to loopback addresses, after verifying the connected peer. Without the key file nothing is suspended:

- The `email_compromised_account` and `email_cloud_relay_abuse` findings say the mailbox stays active.
- An `email_mailbox_compromise` incident says CSM would suspend the mailbox.
- Address blocks apply either way.

## Admin-Panel Brute-Force Tracker

This tracker counts repeated POST requests to high-value non-WordPress admin login endpoints. It runs as part of the web access-log watcher.

The covered endpoints are a tight set, to avoid false positives on shared hosting:

- phpMyAdmin: `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`
- Joomla: `/administrator/index.php`

When an IP crosses the POST-rate threshold, `admin_panel_bruteforce` fires and the attacker IP is auto-blocked.

Drupal `/user/login` and Tomcat Manager `/manager/html` are intentionally out of scope here. Drupal's path is too generic on shared hosting. Tomcat Manager uses HTTP Basic auth (repeated GET requests with 401 responses), not POST form submissions. Both need different detectors and are tracked as follow-up work.

## PHP-Relay (Mail Abuse, cPanel Only)

A real-time inotify watcher on `/var/spool/exim/input` catches WordPress contact-form spam relays. In these, an attacker uses PHPMailer (or similar) with a spoofed `From`, an external `Reply-To`, and a script URL that doesn't belong to the cPanel account. The typical case is a legitimate site running a vulnerable contact-form plugin, which becomes a per-message spam relay through the operator's own mail account.

To opt a known-noisy contact form out, run `csm phprelay ignore-script <host:/path>`. See [Ignoring a script](#ignoring-a-script) and the [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only) for the full operator surface.

### The five paths

The detector runs five paths. Paths 1, 2, 2b and 4 fire `email_php_relay_abuse` (Critical) when one of them crosses threshold. Path 6 has its own findings.

| Path | Scope | Finding |
|------|-------|---------|
| **Path 1: header score** | Per script, using the `host:/path` from the `X-PHP-Script` Exim header | `email_php_relay_abuse` |
| **Path 2: absolute volume per script** | Per script, using the same `host:/path` | `email_php_relay_abuse` |
| **Path 2b: account log-tail volume** | Per cPanel user | `email_php_relay_abuse` |
| **Path 4: HTTP-IP fanout** | Per HTTP source IP across distinct scripts | `email_php_relay_abuse` |
| **Path 6: client recipient spread** | Per client IP across every script and account | See [What Path 6 raises](#what-path-6-raises) |

Paths 2 and 4 use a recipient-diversity gate that suppresses only known low-recipient notification mail. Path 5 (behavioral baseline) is deferred to Stage 2.

How CSM reads the source address and the script label from `X-PHP-Script` is in [The X-PHP-Script header](#the-x-php-script-header).

#### Path 1: header score

Path 1 fires when the `From` domain is not in the account's authorised domains and there is an additional signal: PHPMailer, a suspicious Reply-To or a suspicious User-Agent. CSM evaluates it over a rolling 5-min window once the script has emitted at least `header_score_volume_min` messages.

This is the spoofed-sender, contact-form shape. `FromMismatch` is a hard precondition: the score never accumulates without it.

#### Path 2: absolute volume per script

Path 2 fires when a single script emits at least `absolute_volume_per_hour` messages in the last hour. It catches a compromised script even if the headers themselves are legit-shaped.

The recipient gate leaves plugin notification mail to a fixed admin set alone. If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients suppresses this path. Unknown recipients or `fanout_distinct_recipients: 0` fail open: the path is not suppressed.

#### Path 2b: account log-tail volume

Path 2b is the backstop for when Path 2 misses the window. It fires when a cPanel user reaches at least `effective_account_limit` messages in the last hour that the account's own processes submitted locally (PHP `mail()`, `sendmail`), each with at least one recipient outside this host's mail domains.

The effective limit is auto-derived from `/var/cpanel/cpanel.config`'s `maxemailsperhour`: 60% of it, clamped to 20-60. When an operator override is set, it is capped at 95% of the cPanel limit.

Path 2b reads `/var/log/exim_mainlog` directly. What it counts:

- It names the account only from Exim's own submission fields, so a subject or sender address cannot.
- It reads recipients only from Exim's envelope recipient list. Message headers and sender text do not supply recipients.
- A missing recipient list or a truncated address cannot establish an outbound send.
- Mail to the host's own mailboxes, bounces, authenticated SMTP and mail arriving from the network never count.
- If a present mail-domain file cannot be read, or both `/etc/localdomains` and `/etc/virtualdomains` are absent, nothing counts. A missing optional file is allowed when the other file can be read.

The host's mail-domain inventory is refreshed once per minute.

#### Path 4: HTTP-IP fanout

Path 4 fires when one source IP appears in at least `fanout_distinct_scripts` distinct script keys in `fanout_window_min` minutes. Loaded HTTP-proxy ranges, loopback, and the host's own interface addresses are excluded first.

It catches one client walking many scripts. It avoids CDN/proxy traffic, local cron or panel callbacks, and fixed-admin notification fanout, including one client commenting on several hosted sites.

If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients outside each sending account's explicitly listed domains suppresses this path. Subdomains are exempt only when listed for that account. Missing account-domain data, unknown or partially parsed recipients, or `fanout_distinct_recipients: 0` fail open.

#### Path 6: client recipient spread

Path 6 catches bots that submit a site's forms with strangers' addresses, so the site sends each stranger an automatic reply. One bot sends too few of these per script or per hour for the other paths to notice.

It fires when, for one client IP, hosted sites mail at least `ip_recipient_spread` distinct recipients outside each sending account's own domains within `ip_recipient_window_hours`. The count runs across every script and account.

- An IPv6 client counts per /64.
- A message whose account domains cannot be read is not counted.
- A message whose recipients cannot be parsed counts as one new recipient.
- `ip_recipient_spread: 0` turns the path off.

### What Path 6 raises

When a client crosses the threshold, CSM raises a High finding for it, once per mode per window. `ip_recipient_mode` sets what follows.

| Mode | Finding | What CSM does |
|------|---------|---------------|
| `observe` (default) | `email_php_form_relay_observed` | The finding goes to the daily summary. It never challenges or blocks, so you can review it before switching on enforcement |
| `enforce` | `email_php_form_relay` | The client is sent to the [challenge page](challenge.md). A client that does not solve it within 30 minutes is blocked while `auto_response.enabled` and `auto_response.block_ips` are on |

In `enforce` mode with the challenge off, the client is blocked directly under the usual `auto_response` settings. `auto_response.php_relay.dry_run` applies only to the mail freeze and does not hold this response.

CSM also raises `email_php_form_relay_script` (High) for each script that sent at least two of that client's outside recipients, once per script per window. It names the account and the form to fix: add a captcha, or turn off the automatic reply to the submitter. For a legitimate bulk sender, use `csm phprelay ignore-script`. This finding has no source address field and never challenges or blocks.

If the client table fills up, CSM drops the clients with the fewest recipients first and reports `email_php_form_relay_table_full` at most once a day.

#### Switching between observe and enforce

After a reload from `observe` to `enforce`, the next eligible message can trigger enforcement using recipients still in the window. The earlier observe report does not delay enforcement.

Switching back to `observe` prevents new responses from retained findings, queued blocks, challenge timeouts and central corroboration. Existing challenges and blocks keep their expiry.

### Shared addresses the per-IP paths skip

Per-IP paths skip selected shared addresses:

- CDN and website firewall edges: Cloudflare, QUIC.cloud, Sucuri.
- Payment gateway webhooks: Stripe, PayPal, Braintree, PayU, Revolut, Mollie.

CSM ships this list built in, taken from each provider's published list. Membership is not proof that the target site chose the service. [Cloudflare Workers can make requests to third-party sites](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip-in-worker-subrequests), and [Sucuri can proxy requests before the site's DNS changes](https://docs.sucuri.net/website-firewall/configuration/testing-the-waf-before-changing-the-dns/). Traffic relayed through these retained providers remains exempt, including abusive requests.

#### What is not on the list

- Uptime monitors and cron services are not on the list. Anyone with an account there can schedule POSTs with any form body to any URL. Exempting their addresses would let a bot relay form spam through them, and the per-IP paths would miss it.
- Self-service CDNs such as Amazon CloudFront, Fastly and BunnyCDN are left out for the same reason: anyone can point a pull zone at any site and post through its edges.
- Netopia, EuPlatesc, Twispay, JCC and Adyen publish no source address list. If your shops use them, add their ranges yourself.
- Viva publishes a webhook address list. It is not built in yet, so add it yourself.

If you trust a specific cron service, or your sites sit behind one of those CDNs, you can add its ranges yourself, knowing that anyone with an account at that service can use them. Legitimate visitors of a site behind these CDNs share their edge's per-IP counts unless you exempt its ranges. For Path 6, review findings in `ip_recipient_mode: observe` before enforcing. This setting does not disable Path 4.

#### Replacing the list

An `http_proxy_ranges.yaml` in `policies_dir` replaces the built-in list whole and reloads on SIGHUP. The file holds `version: 1` plus a `cidrs:` list. A bare IP counts as /32 or /128. Without the file the built-in list applies.

To extend the list, start from the built-in file in the CSM source, `internal/emailspool/embed/http_proxy_ranges.yaml`. Your file replaces the whole list, so later CSM updates to the built-in entries do not reach you until you copy them in again.

| File state | Result |
|------------|--------|
| Cannot be read or parsed, has no `cidrs:` list, or has no valid entry | CSM keeps the last good list, which is the built-in one at startup |
| Has invalid entries, including blank or null list items | They are reported and skipped. Valid siblings still apply |
| Has an explicitly empty list (`cidrs: []`) | The proxy ranges are cleared. Only this clears them |

Load errors at startup or on SIGHUP raise `email_php_relay_policies_reload` (Warning).

CSM 4.10.0 exempted Amazon CloudFront, Fastly and BunnyCDN. Later releases do not. An operator file copied from the 4.10.0 list keeps them until you remove those entries and reload.

Cloudflare remains separately exempt from Path 6 through the daemon's refreshed infrastructure list, even when omitted from the operator proxy file.

### What Path 6 does not count

Path 6 does not count a client that is:

- on the proxy and payment list
- a Cloudflare edge the firewall knows
- a loopback or host address
- an `infra_ips` entry

It also skips mail sent from `wp-cron.php`, which mails whatever its trigger request queued. And it skips staff, as described next.

#### Staff by admin page

Staff is a client that sent mail through a WordPress admin page of the same account in the last 7 days. Every `.php` page directly in a `wp-admin/` directory counts as an admin page except `admin-ajax.php`, `admin-post.php`, `profile.php` and `index.php`, which logged-out visitors or subscribers can reach.

The staff exemption covers only that account. Becoming staff, or an `ignore-script` for a script, also drops the recipients counted earlier in the window through that account or script.

#### Staff by access log

Staff often mail customers without passing such a page, for example by completing orders with the quick actions of the WooCommerce order list. So when a client is about to cross the threshold, CSM reads the last 4 MiB of each involved site's current access logs (`/usr/local/apache/domlogs/<account>/<site>` and `<site>-ssl_log`). For a site starting with `www.`, it also checks the name with that prefix removed. Each distinct log is read once per crossing.

Access-log evidence requires a GET answered 200 on a recognized WordPress staff page, such as the post editor, the WooCommerce order list, uploads, comments, users, settings, plugins or themes.

- Both order lists qualify: the legacy one on `edit.php` and the HPOS one on `admin.php?page=wc-orders` (or `page=wc-orders--<order type>`).
- For HPOS, `page` must be the first query parameter so PHP's input limit cannot discard it.
- Public resources, setup pages, subscriber pages and every other `admin.php` page do not qualify.
- Requests with another parameter PHP would interpret as `page` do not qualify either.
- Encoded or ambiguous paths and extra path after the PHP filename do not qualify.
- A missing or unreadable log is no evidence.

The request must fall within the last 7 days, and the exemption expires 7 days after that request. Rereading a log does not renew it.

The client's address, or its IPv6 /64, becomes staff only on that account, whose mail stops counting. The client is challenged only if the other accounts' mail still crosses the threshold.

### Path 6 known limits

- A plugin that handles POST requests in its `init` or `wp_loaded` hook without checking for a login, or for `DOING_CRON`, lets a visitor who is not logged in make it send mail by posting to an admin page or to `wp-cron.php`. That mail is not counted, and a post to an admin page also earns the client the staff exemption on that account.
- Behind a proxy or CDN that does not pass the client address to PHP, CSM sees only the proxy's address. A proxy on the list is skipped, so its visitors are never counted. That includes a bot that sends its requests through a CDN account of its own.
- A proxy missing from the list is counted as one client for all its visitors, so add its ranges to `http_proxy_ranges.yaml`.
- Path 6 names a form by its host in lowercase and its path up to the PHP file. Extra path after the file or a change of case does not split it, and one `ignore-script` with that name covers every such variant. Other names for the same site, such as with and without `www.`, still count as separate forms.
- Only WordPress admin pages count as staff evidence. Staff of other back offices, such as PrestaShop, OpenCart or Joomla, who send many order or account mails can be challenged and then blocked. Put a fixed office address in `infra_ips`.
- Counts live in memory and are lost when the daemon restarts. The startup walk sees only mail still in the queue, and form replies usually leave it within seconds.
- A bot that rotates addresses and keeps each one below the threshold is never challenged, and its form is not named.
- An IPv6 client is counted per /64 but challenged or blocked only at the one address that crossed the threshold.
- A script finding names the client that triggered it. Later clients through the same form in the window get their own client findings but are not added to the script finding.
- One stranger mailed many times counts once.

### Ignoring a script

Operator suppressions (`csm phprelay ignore-script <host:/path>`) short-circuit the pipeline before any path scoring runs. You can opt a known-noisy contact form out individually without disabling the detector.

An ignore on a lowercase `host:/path` ending at the PHP file also covers that file reached with extra path after it or a different host case.

### Startup scan and spool overflow

The detector starts a one-shot retrospective scan of `exim_mainlog` at daemon startup, so Path 2b can fire on history already on disk.

`IN_Q_OVERFLOW` triggers a bounded recovery walk of the spool, capped at 1000 files. If more were skipped, an `email_php_relay_overflow_scan_truncated` Critical fires too. Path 2b backstops the missed messages.

## PAM Brute-Force Listener

The PAM listener monitors authentication in real time through the PAM module. It tracks SSH logins with geolocation. It integrates with the nftables firewall for instant blocking, and blocks IPs within seconds of a threshold breach.

| Finding | What triggers it |
|---------|------------------|
| `pam_bruteforce` | SSH failures (`service=sshd`) |
| `credential_stuffing` | Credential stuffing or password spray breadth: one source IP failing SSH logins against many distinct accounts inside `thresholds.multi_ip_login_window_min`. Tune the account floor with `thresholds.cred_stuffing_distinct_accounts` (default 5) |
| `pam_auth_failures` | Failures from other PAM services (FTP, mail, webmin and similar), once per window above `thresholds.pam_bruteforce_threshold`. It never blocks |

Only successful sshd logins clear SSH failure counts.

`pam_auth_failures` never blocks because CSM reads pure-ftpd, Dovecot and Exim logs separately, and counting one login twice would corroborate it with itself. Services without such a log detector, such as vsftpd, proftpd or webmin, have no blocking signal from PAM.

## Process Context

Exec and outbound-connection findings carry an optional `process` object. It holds PID, PPID, UID, user, cPanel account (when known), comm, exe, sanitized cmdline, and a parent chain up to depth 5.

CSM builds the chain from an in-memory LRU+TTL cache (cap 16384 entries, 30-minute TTL) populated from BPF exec events. Cache misses trigger a bounded async `/proc` read, so process-context enrichment does not add blocking work to the connection event loop.

When neither the cache nor the enricher has data, the `process` field is omitted entirely and the finding still emits. This happens, for example, for a process that exited before userspace reads its event.

Counters exposed at `/metrics`:

- `csm_process_context_cache_entries`
- `csm_process_context_cache_evictions_total` (LRU)
- `csm_process_context_cache_ttl_purges_total`
- `csm_process_context_cache_misses_total` (includes TTL purges)
- `csm_process_context_enrich_queue_drops_total`
- `csm_process_context_enrich_reads_total`
- `csm_process_context_enrich_errors_total`
- `csm_process_context_enrich_stale_total`
- `csm_process_context_enrich_latency_seconds`

Caveats:

- `started_at` is emitted only when the event source supplies a trustworthy start timestamp. CSM does not infer it from procfs directory metadata.
- After daemon restart, the `csm_process_context_enrich_*` counters may show a small `enqueued - reads` delta. Pending requests in the enricher queue are dropped on shutdown by design.
- Hosts without BPF support fall back to `/proc/net/tcp[6]` polling. That path has no PID, so emitted findings do not carry a `process` field.

## HTTP Flood, Scanner Profile, UA Spoof, and Distributed Flood

`http_request_flood`, `http_scanner_profile`, `http_claimed_bot_unverified`, `http_ua_spoof`, and `http_distributed_flood` are **periodic**, not real-time. They run inside the same `wp_bruteforce` scheduled check that scans per-vhost access logs every 10 minutes.

A real-time inotify tailer would need to hold per-IP state across log rotations and is out of scope. For attack types where sub-minute response matters, the access-log inotify watcher already covers wp_login_bruteforce and xmlrpc_abuse. The periodic scan adds volume-based rate enforcement, pending claimed-bot handling, scanner-profile detection, and per-vhost distributed attack rollups on top.

### Findings

| Finding | Fires when |
|---------|------------|
| `http_request_flood` | One source IP makes too many requests inside the rate window |
| `http_scanner_profile` | One source IP's in-window traffic is almost all probe-error responses spread across many distinct paths, the shape of URL enumeration hunting for backups, downloadable files, and dormant shells |
| `http_ua_spoof` | One source IP sends non-browser User-Agents |
| `http_distributed_flood` | Many distinct already-abusive source IPs hit one vhost in a single scan window |

Per-IP findings roll up per vhost, so a confirmed scanner that sprays a few probes across many vhosts still feeds the distributed rollup. Full threshold reference and tuning notes are in [Configuration](configuration.md).

### Gates and defaults

`http_request_flood` fires at `http_flood_threshold` requests within `http_flood_window_min` (5 min). It ships disabled (`0`) so operators sample baseline traffic first.

`http_scanner_profile` needs three gates to all pass:

- `http_scanner_min_requests` volume (ships `0`, disabled).
- At least `http_scanner_error_pct` (90) of requests on a probe-error status. Probe-error statuses default to 404 and 403.
- `http_scanner_min_distinct_paths` (10) distinct error paths. Query strings are stripped, so cache-buster URLs on one missing endpoint count once.

`http_ua_spoof` has two kinds of trigger:

- Known scanner agents (nikto, sqlmap, nmap, wpscan, nuclei, and similar) fire on the first hit.
- Claimed crawler UAs with a cache-confirmed reverse-DNS negative, scripting (curl/python/wget), headless (Puppeteer/Playwright), and empty agents fire at `http_ua_spoof_threshold` (30).

Scripting, headless and empty agents still require their opt-in flags: `http_ua_scripting_enabled`, `http_ua_headless_enabled`, `http_ua_empty_enabled`.

`http_distributed_flood` is opt-in. It fires once `http_distributed_min_ips` distinct IPs (sample 10), each having already crossed a per-IP abuse threshold above, hit the same vhost. It is built only from IPs that tripped another finding, so a popular site's normal visitor spread does not trip it.

### Verified crawlers

A verified crawler is dropped from the scan before any counter increments. A source IP whose claimed bot User-Agent passes IP-range or reverse-DNS verification cannot contribute to a flood, scanner, or spoof finding. Verified Googlebot and AI crawler traffic therefore does not produce false positives. Verification is covered in [Threat intel](threat-intel.md#verified-crawlers).

### cPanel proxy subdomains

Requests that a cPanel proxy subdomain (`cpanel.`, `webmail.`, `whm.` and similar) passes through the web server to the panel are skipped by the web detectors, realtime and periodic, when cPanel's own central access log records them as proxied.

The panel's own access log carries those requests. A busy cPanel or webmail session through a proxy subdomain does not count as web traffic, and one request does not count as two kinds of evidence.

Requests in a per-site log always count as website traffic. So do requests in a log chosen through `web_server.access_logs` that is not one of cPanel's own access logs.

### Which address counts as the client

Web counters use the request and timestamp written by the web server, including requests with Basic authentication usernames and quoted header values.

#### Periodic checks

For periodic client attribution, `web_server.trusted_proxies` and `challenge.trusted_proxies` together enable X-Forwarded-For from a configured remote proxy. The log format must record it immediately after User-Agent, optionally preceded by a vhost in `host:port` form.

Trust only proxies that append their observed peer or replace untrusted input with that address. Trusted ranges must not include visitors.

- The client is the first address from the right that is not a trusted proxy.
- The parser keeps complete tokens at the right end, so discarded client text to the left cannot name a client.
- If no client survives, including when the retained end contains only trusted proxies, the request is not counted against anyone.
- A listed address is never counted as a client, even where its header is not trusted.

#### Realtime checks

Realtime checks read the connecting address, not X-Forwarded-For, and act only on a bare address in its canonical form. The web server must log the connecting peer, not a forwarded client, in that field.

When the connecting address is a configured trusted proxy, in `web_server.trusted_proxies` or `challenge.trusted_proxies`:

| Check | What CSM does |
|-------|---------------|
| WordPress, XML-RPC and admin panel checks | Skip the request |
| ModSecurity denies and warnings | Stay visible without escalating |
| cPanel API auth failures | Not reported |
| Scheduled ModSecurity audit scan | Does not report the request |
| Other cPanel audit and login findings | Stay visible without blocking or scoring the proxy, and supply no automatic response forecast |

A listed address is skipped even where its forwarded header is not trusted, such as an address of this host.

## Web Peer Log and Forged Client Addresses

On Apache and LiteSpeed hosts with the CSM web peer log, the daemon reads one line per request: when it started, the virtual host, the connection's peer and the client address the web server logged.

When the web server rewrites client addresses from a proxy header, these lines tell CSM which addresses connected for themselves, which came through a trusted proxy or a known CDN edge, and which another peer chose. Automatic responses use that verdict for web findings. See [auto-response](auto-response.md).

### Setting up the peer log

- `csm webserver-integration peer-log install` sets up the peer log on Apache and on cPanel with LiteSpeed.
- `upgrade` refreshes a peer log that is already installed. Run it as `csm webserver-integration upgrade`. There is no `peer-log upgrade`.
- `csm doctor` shows whether it is active. It warns when the peer log has not been written for 15 minutes while an access log has.

Run `peer-log install` again after switching between Apache and LiteSpeed.

The web server writes the log to `/var/log/csm-web/peer.log`. The directory is `0750` and owned by root. With LiteSpeed on cPanel its group is `nobody`, because LiteSpeed's workers open the log themselves. Elsewhere the group is `root`. Other local users cannot read it. Install and upgrade restore that ownership and refuse a symlink in its place.

On Apache the log also covers virtual hosts with their own access logs. Apache skips it, and does not fail to start, when the directory is missing.

The CSM package creates the directory before the daemon starts. If `peer-log install` has to create it again, restart CSM: the daemon may only empty the log once the directory existed when it started.

### Hosts where the log gives no verdict

| Host | What CSM does |
|------|---------------|
| cPanel with nginx in front | Every peer is the server itself. CSM keeps the log bounded but takes no verdict or alert from it. `csm webserver-integration peer-log remove` still removes an earlier snippet |
| LiteSpeed running PHP as its own user (PHP suEXEC set to No) | The same, because site code could then change the log |
| Apache with unreadable configuration or with buffering | CSM does not trust the peer log |

`csm doctor` says which of the first two cases applies.

#### LiteSpeed

CSM requires exactly one `phpSuExec` value of `1` or `2` in LiteSpeed's `httpd_config.xml`. Missing, repeated, invalid or unreadable settings disable peer trust.

CSM rechecks before each log read and before using cached peer evidence. If isolation becomes unsafe, verdicts and forgery alerts stop while the log stays bounded. Trust stays disabled for that daemon run, since lines written while PHP shared the server user cannot be authenticated.

To restore peer verification, enable PHP suEXEC, reload LiteSpeed, then restart CSM.

#### Apache

Apache peer verification requires readable configuration with buffering disabled. Missing configuration or unresolved macro directives cannot rule out buffering, so CSM does not trust the peer log in those cases.

### Forged client addresses

A request logged with a client address chosen by a peer that is neither the client nor a trusted proxy raises `http_client_forged` (Critical). CSM never blocks an address chosen this way.

The finding is raised at most once an hour for peers on this server, and at most once an hour for remote peers. The hour is measured when CSM emits the alert, not when the request started.

A local peer is a process on this server, such as a site's script, or a proxy in front of the web server. A remote peer that is a proxy you run or use belongs in `web_server.trusted_proxies`.

The alert names the virtual host from the request, which the peer chooses, so it does not identify the account responsible.

### Gaps in the log

The daemon empties the peer log once it has read it past 256 MB.

Any verdict whose one-hour window reaches a gap is unknown. This includes verdicts for the hour after the gap. A gap follows any of these:

- a restart
- a truncation or rotation
- a read failure
- an unreadable line
- a line stamped more than five minutes ahead of the clock

Web findings keep the responses they get without the peer log. Unchanged files can be reopened without invalidating verdicts.

## Direct SMTP Egress

Outbound connections to SMTP ports from non-MTA local processes emit a `direct_smtp_egress` finding. See [Direct SMTP egress](direct-smtp-egress.md) for the full rule set, config schema, and metric.

## Details

This section is reference material: exact rules, edge cases and rare failure modes for the watchers above.

### Executables in shared temporary directories

An executable in a shared temporary directory is reported as Critical, even when it is named `.htaccess`, `.user.ini`, or `php.ini`, including atomic-save names. Configuration content checks still run, and operator path suppressions still apply.

A root-owned file receives a Warning when its writer has one of these ancestries:

- panel maintenance ancestry
- package-manager ancestry during an active package window
- verified live root ancestry of an initramfs build

Initramfs provenance requires both real and effective root credentials from the writer through the builder. Cached names or unknown credentials do not qualify.

#### When the writer has already exited

CSM reads the writer's ancestry when it sees the write. Build tools often exit before then. Such a file receives the same Warning only when all of these hold:

- A writer with proven ancestry recently wrote an executable into the same work directory, or a root process with proven ancestry is working inside it.
- The executable and every directory below the temporary root are owned by root and cannot be written by other users.
- For a root process working inside the directory (an occupant), its actual working directory and every directory back to the work directory are also root-owned and not writable by other users, without crossing a mount.

That proof has limits:

- It is tied to the open file and its directory placement. Symlinks, mounts below the temporary root, renamed or replaced files and directories, and a file that was not owned by root when it was written cannot carry it.
- A file the build itself has already removed keeps the proof.
- The proof's lifetime starts when the proven write was seen, and exited writers cannot extend it.
- Read errors and a known non-root process in the ancestry do not qualify as an exited root writer.
- Occupant scans are spaced per work directory. When scan capacity is full, findings without other proof stay Critical.

When the writer has exited and there is no such proof, the finding says so and stays Critical. The finding also stays Critical when the writer is still running and its ancestry proves nothing.

#### Grouping of maintenance warnings

The maintenance warnings are grouped: one finding stands for a work directory while maintenance writes into it. Files directly in a shared temporary directory retain separate warnings.

Other temporary executable findings remain Critical and are never grouped. An earlier maintenance warning cannot suppress them.

### Self-deleting droppers

Turn the detector off with `thresholds.dropper_detection: false`.

Self-deleting file tracking requires a close-write observation and a recent filesystem birth time. Filesystems that do not provide birth time cannot support this detector. Ordinary realtime content scanning still runs.

#### Files WordPress copies and then removes

A file whose exact bytes WordPress moved or copied into place before removing the original is not reported. This covers plugin, theme and core packages, language packs, and the version file a core update reads first. Other executable files do not qualify for this copy exception.

| Case | Rule |
|------|------|
| Language-pack and version-probe copies | They also require a complete, stable data-only snapshot with no suspicious content or earlier unsafe write |
| A core update that stops after reading its version file | The old release stays installed, so no installed copy matches. The version file is not reported when its bytes equal the wordpress.org checksum for the release and locale it declares |
| A staged core file that the update deletes without installing | Not reported when its bytes equal the wordpress.org checksum for that path in the release now installed |
| Other files removed from staging without an identical installed copy | Still reported |

The third case exists because a core update unpacks the whole release but installs only what changed, and never overwrites the bundled themes and plugins. The checksum must describe the same complete, stable snapshot as the retained content.

Package headers are read only from regular files, never blocking on an account-writable named pipe or device.

#### Earlier content always counts

For a staged core file to go unreported, earlier nonempty content must also be known and unchanged, including the first close-write snapshot. Later official bytes or an identical installed copy cannot erase that evidence.

The same history rule applies to every staged core, plugin and theme file and to the Safe Mode loader. A file whose content changed after it was first written is reported even when WordPress then moves it into place, an identical copy is installed, or its last bytes are official.

- Repeated analysis of the same snapshot does not count as another write.
- A single snapshot whose complete bytes could not be read can still match a move by file identity. A second nonempty snapshot leaves the unknown earlier bytes unaccounted for.
- Files too large for a complete snapshot retain their leading bytes for content checks.
- Completed upload execution probes remain tracked until the deletion check.
- Earlier unsafe or uncertain content remains reportable even when a later close-write contains a harmless probe.

#### Plugin probes and loaders

Really Simple Security copies a script into uploads to test whether PHP runs there, then deletes it. That script is not reported when its content is byte for byte the shipped script. Any other content under that name is reported.

Elementor Safe Mode copies its loader into mu-plugins while enabled and deletes it when switched off.

| Case | Result |
|------|--------|
| The loader's bytes equal the wordpress.org checksum for the same file in the Elementor release the same site had installed when the loader was written | Not reported |
| Those checksums cannot be consulted, and the loader is byte for byte identical to a complete, stable snapshot of the installed plugin's own file, reached without symlinks | Warning. The finding names that file |
| The checksums reject the loader, or its earlier payload was rewritten | Critical, even when its containing directory was removed |

The same package proof applies when a different file replaced the loader's path. Other capability-probe scripts cannot exempt executable content in this loader.

#### Lower severity and grouping

CSM recognizes these and reports them at a lower severity:

- upgrade staging
- atomic-save temp files
- template compile caches
- BackWPup job-state files: the running job's JSON and its folder list, written behind a PHP comment, including a captured head cut inside a CRLF line ending
- a path taken over by a newer file
- a file whose original directory was removed

Files removed together with the directory holding them, such as a language pack WordPress unpacked and discarded, are reported once for that directory. A create/delete burst collapses into one lower-severity notice.

Grouping is recalculated after ignored paths are removed. Remaining files can form directory groups, while a lone remaining file is reported on its own.

#### Blank files and uncertain snapshots

Complete blank files are excluded from dropper alerts after a close-write observation.

Any content or metadata change during the read, including an unlink, leaves the snapshot uncertain. WordPress data and its checksum are read within the same stat interval. A later complete close-write snapshot cannot rule out code that ran during an earlier unstable read. That uncertainty and code seen in any read remain attached to the tracked file.

Concurrent firewall-log writes can therefore still produce a warning when the log is replaced, or a critical finding when it is deleted.

#### PHP files that stop at their first statement

PHP files are also excluded when their first statement stops the interpreter: `exit`, `die`, or `__halt_compiler`, with at most a plain literal argument and no preceding comment. Plugins keep state and firewall data in files of that shape and rewrite them constantly, and the bytes behind the terminator are never compiled.

The exemption has limits:

- It is refused when those trailing bytes are made only of transport-encoding alphabet. With PHP source conversion turned on, PHP can decode a file before it parses it. The encoded tail would then become the program, and the first statement would be padding.
- A file with a comment before that first statement is never exempt, for the same reason: how PHP reads a comment depends on the interpreter's source encoding.
- Executable-mode files are not judged by PHP compilation rules, because a shell may read them instead.
- Content or signature findings and code observed earlier always override inert-content filtering.

#### Checksum downloads

Core checksum downloads start in the background when capacity permits. Plugin downloads do not consume core checksum capacity or share its admission limit. Concurrent requests for a release reuse its download and cached result. A file still unverified at the deletion probe is reported.

Core-release checksum downloads are non-blocking and bounded, including their retry timers. Repeated misses and streams of distinct release names share an admission budget. Release identifiers longer than 64 bytes are rejected before retention or lookup.

When that budget is exhausted, cached checksums remain usable. An uncached file stays unverified and receives the normal dropper assessment. A later observation can request checksums again after the budget recovers.

#### Capacity and suppressions

Candidate tracking and findings held for aggregation each accept up to 16,384 entries. Additional work is refused without evicting older evidence. Status and doctor report refusals, exhausted probes, overdue work and stalled processing through [protection queue health](api.md#protection-queue-health).

Dropper admission and pending findings follow the live `suppressions.ignore_paths` list after reload. Intentionally suppressed candidates consume no tracker capacity. Losses of eligible candidates still raise the capacity warning.

### PHP in account mail directories

The `mail` directory rule includes cPanel accounts on further home partitions such as `/home2`. Account mail locations ignore redundant separators but keep Linux directory-name case sensitivity.

Directories named `mail` inside applications or document roots do not count. Their PHP content is still scanned.

### PHP inside images

Image writes under an account or configured document root are inspected, including hosted `.config` directories and roots located in temporary directories.

- Images up to 128 KiB are inspected in one piece.
- Larger files get a 64 KiB head and a 64 KiB tail scan.
- Payloads outside those windows require a deep scan, subject to `thresholds.full_scan_max_file_mb`.

A PHP opening tag alone is not enough: a screenshot quoting one in its description chunk stays quiet. A file that only wears an image name while holding PHP source is reported the same way.

#### The loader half

A PHP file that includes or requires an image, archive or other non-executable file while also reading request input is the loader half of this technique. The payload lives in the picture and the one-line loader elsewhere.

- Literal targets ending an include statement, concatenated paths, paths held in a local, encoded paths and suppressed `@include` statements match in either statement order.
- Ordinary templating that pulls in `.html`, `.tpl`, `.txt` or `.svg` partials is outside the extension-based rule.
- Encoded targets still count because the source hides their extension.

#### Image writes and the queue

Image writes use the existing notification-only fanotify instance, its 16,384 event queue and 4-16 analyzer workers. They create no permission-event holds and do not enter the mail scanner. Mail permission holds retain their separate hold budget and watchdog.

Thumbnail and WebP bursts fill the same queue as other writes. Excess events are closed immediately and their parent directories enter the existing capped recovery tracker. Recovery rescans recent surviving files. Kernel queue loss and exhausted recovery coverage still rely on the next deep scan.

Queue health and content-read truncation remain visible through the existing metrics.

### Follow-up analysis after a Critical alert

A Critical `obfuscated_php_realtime`, `webshell_content_realtime` or `php_dropper_realtime` alert whose file has not already had a file response queues the scheduled content analysis of that file. The analysis runs on one background worker, so slow storage cannot delay other alerts.

A Critical result goes through normal dispatch and the scheduled response, under `quarantine_files` and the file response budget.

CSM refuses links in any path component, special files and a file that changed after analysis. A full queue is logged, and the original alert stays.

### Analyzer queue, overflow and shutdown

Atomic-save files enter the same bounded worker queue as ordinary writes. Repeated findings use the normal alert cooldown.

Queue overflow schedules a directory rescan of files that remain on disk:

- Recovery runs one pass at a time, under a time budget and with a minimum gap between passes.
- Unfinished directories stay queued and retry even after new drops stop.
- Recovery resumes within a directory and retains its original scan window, so deferred files do not age out while waiting.

Kernel notification loss still relies on the next deep scan.

Shutdown drains the queue under a fixed time budget. Events still waiting when it expires are released without being scanned. Files still on disk are covered by the next deep scan.

Both budgets are checked between scans, so a scan or directory read already in progress must still finish before shutdown completes.

### YARA snapshots and fingerprints

Realtime YARA scans hand the worker a sealed memory-backed copy of the captured bytes, whatever their size, without reopening the event path for scanning. Alert payload details describe that snapshot.

| Snapshot | Fingerprint on the finding |
|----------|----------------------------|
| The whole file | The snapshot's fingerprint |
| A partial read | CSM reopens the path to fingerprint the whole file when preparing the finding |
| An unreadable file, or a file above the fingerprint limit | None |

Re-check compares whole-file fingerprints, so an unchanged file can clear when YARA stops matching it. Content outside the read window remains subject to the scheduled scan limits.

### WordPress atomic saves

For WordPress atomic saves, the intended basename can select a core or plugin checksum entry. Only a match against the complete event-file content verifies the file. Missing checksums, partial content, and modifications proceed through normal detection. The finding retains the actual event path.

### WordPress update staging

A WordPress update is unpacked under `wp-content/upgrade/` before it is moved into place. CSM judges each staged PHP file by hash, not by location.

| Case | What CSM does |
|------|---------------|
| The file matches the official wordpress.org checksum for its package version | It is stock and skips detection like an installed stock file |
| The checksums are still being fetched | The file is content-scanned at once and compared once they land, even if the package header was written late or WordPress has already moved the tree into place |
| The official package does not ship the file | The file gets its own warning |
| The tree was removed before its release could be identified | A package warning, not file-by-file comparisons against the old release |

The last case covers refused updates (for example when the new release needs a newer PHP) and plugin copies whose staging identity was never captured. The warning does not establish whether installation succeeded. Reused staging paths follow the normal alert cooldown and do not suppress later unidentified uploads.

#### Identifying a plugin release

An installed plugin header can identify the release only in two cases:

- Its directory is the original staging directory moved into place.
- The installed path is still the very file the staged event wrote.

So a stock file first examined after the move skips detection like any other.

The installed plugin directory must remain the same directory during that check and cannot itself be a symlink. Its identity also connects earlier queued files from the same tree, including when the later file is already verified. Copies and unrelated trees do not establish that connection. Every retained digest still needs to match the official release.

#### Identifying a core release

A core update copies files. The installed version.php therefore identifies the release only if it was replaced or rewritten after the staged file was seen. A borrowed release still requires the file's bytes to be the official ones for that path.

#### Which path a finding names

An event identified at its installed location keeps that location while it exists, even if another update reuses the staging name. Other staged events name the installed path when it exists.

#### Package warnings

These raise one warning per staging directory:

- themes
- packages not published on wordpress.org
- a full verification queue
- a package whose checksums do not arrive within 60 seconds

WordPress picks a new staging directory for every upload. Once the package type and version are known, these warnings are identified by site, package type, name, version and reason.

Uploading the same declared release to the same site again is a repeat. It is emailed again only after 24 hours without a report, and history follows the normal 24-hour reminder. This groups checksum-availability warnings. It does not establish that the package contents are unchanged or safe.

- Incomplete headers keep an upload-specific warning.
- A later change of type, version or reason can raise a new warning in the same directory.
- Per-file checksum warnings repeat across uploads only when their package identity, relative path and complete digest match.
- Files that could not be hashed keep their upload-specific warning.
- Content findings inside staging keep their own per-file identity and normal alert cooldowns. Package-warning dismissal does not dismiss them.

### PHP in sensitive WordPress directories

Location warnings for PHP in sensitive WordPress directories are suppressed only for recognized inert content, including comment-only stubs and literal translation or version data. PHP attributes are executable syntax, not comments, and do not qualify a file for that suppression. Content scans still run.

### Head and tail scan windows

The head-window eval/decoder check ignores PHP comments and inline HTML. String boundaries and legacy line endings preserve the code that follows them.

Tail windows retain raw content, because they can begin inside a literal whose opening delimiter is outside the window.

### WordPress admin-creation signature

Both the real-time and the scheduled WordPress admin-creation signature require an administrator role token plus literal or request-derived credentials. Both accept the same ASCII whitespace, including the vertical tab.

An importer that creates users with a generated password does not trigger either one just for reading a login from an import form.

Two divergences between the engines are known and left in place:

- Go folds the Unicode long s into ASCII s and YARA's nocase does not, so a token spelled with it can match in real time where a scan declines.
- Bounded expressions count differently: the real-time engine counts characters and the scheduled one counts bytes.

Neither can occur in real PHP. Strictness parity is not enforced across the rulesets: the parity check compares rule names, not how strict each side is.

### How the monitor verifies a placed file

The [placement monitor](#files-moved-or-linked-into-a-site) verifies a file's identity before analysis. Where that identity comes from depends on the backend.

| Backend | Source of the identity |
|---------|------------------------|
| `bpf` | The kernel event |
| `legacy` | The event identifies the parent directory and entry name. CSM records the file's identity when it resolves that entry |

With `legacy`, a replacement made before that lookup can be analyzed, but a replacement made after it fails the identity check.

The event keeps the placing process's PID for restore detection. `legacy` cannot prove that process placed a replacement found during lookup.

When a watched filesystem has several whole-filesystem mounts, BPF checks each watched location separately. Admission uses that location's name, and a child mount hiding one view does not prevent checks through another view.

### Placement queue recovery

Placements that do not fit the monitor's queue go to the same recovery as a full analyzer queue. CSM rescans the directory each file landed in, whatever the files' age, and queues a moved-in directory for its walk.

BPF recovery allows the rename or link to finish before completing a rescan or starting a walk. It covers placements in the watched trees only: a file or directory inside a watch root, or a directory that holds one.

Recovery queues remain bounded. Evictions and unfinished work count as drops.

### Sensitive file watcher rules

These rules add to the [Sensitive System File Watcher](#sensitive-system-file-watcher) section.

#### Hook findings and refresh findings

When the LSM hook has already delivered a finding for a write, the refresh does not report that change again, as long as the path still has the exact state captured for that finding. The refresh also:

- reports a later rename-over separately
- retries a refresh finding if the alert queue was full
- always evaluates the bytes it read for its digest, not a later read

#### Proving control-panel ancestry

Control-panel ancestry is read from the executable a parent process actually runs, not from the name it reports. The executable must be a root-owned file inside the panel's own directory that no other user can write.

Cached executable evidence must come from a resolved procfs link. An exec-event filename or script argument does not qualify.

Ancestry is available on every Linux build before monitoring starts. A cached control-panel hit avoids a live ancestry walk. Otherwise CSM also reads procfs and keeps cached package-manager evidence.

### cPanel session log fields

cPanel session log readers match fields by position, so login names and address lists cannot supply the service, address, event or account.

- Scheduled and realtime login alerts skip loopback and non-address origins.
- API-created sessions never count as direct logins for multi-address or hijack correlation.
- A login that names its method twice counts as a direct login.
- A password change entry with an unreadable header or timestamp cannot suppress a shadow-file alert.

### cPanel API authentication failures

A cPanel API authentication failure is a 401 or 403 answer to one of these, percent-encoded or not:

- a UAPI, JSON API or XML API call
- a WHM DNS cluster call
- another endpoint that accepts API tokens (WebSocket, account transfer, WP Toolkit, Nova)

Page requests on a session URL are not API calls and are not counted. The periodic `api_auth_failures` check counts failures the same way, including the session URL rule below.

#### Failures on a session URL

A failure on a session URL (`/cpsess<token>/...`) waits a few seconds for the session log. The reason is a common harmless case. A browser tab left open after the account logged in again elsewhere still sends its old URL token, and cPanel ends that session after a few token failures.

When the session log shows cPanel ending such a session for the same address, CSM does not report the failures that name the session's account, or the tab's later requests that reuse its URL token. Nothing guessed a credential.

Any other failure is reported, including one from another client behind the same address. API calls with a token or password carry no session URL and are reported at once.

The wait covers both matching-window edges and the log watchers' polling delay. It ends at a fixed deadline, and evidence read after that deadline cannot erase a failure. Correlation evidence expires independently of alert delivery. Queue saturation is reported through the existing queue health counters and daemon warnings.

#### Password changes

Password-change suppression applies only to confirmed 401 responses. Ambiguous authentication failures remain visible.

### Frozen Exim messages

A frozen Exim message is reported once. Exim logs a still-frozen message again on every queue run, and those lines are not reported again, also after a daemon restart. The daemon keeps the messages it reported in its state database until a day passes without a queue run logging them.

A message that froze while the daemon was stopped has not been reported, so the first queue run after the start reports it.

Startup discards expired records and invalid message IDs, and adjusts timestamps ahead of the current clock. These corrections are saved even if no new mail event arrives, so another restart does not extend the corrected retention period.

### FTP rules

These rules add to [FTP logins and blocking](#ftp-logins-and-blocking).

#### Which field names the client

FTP findings use only the peer field directly after the pure-ftpd program tag, in both realtime monitoring and scheduled scans.

- Missing or malformed peers and hostname peers produce no finding.
- Addresses in usernames or later message fields never identify the client.
- To record numeric peers, use pure-ftpd's existing `DontResolve yes` setting.

#### When FTP failures only alert

FTP failures only alert in each of these cases:

- `DontResolve` is not enabled in every configuration source present.
- A source is unreadable, including a broken symlink.
- A server is installed with no known configuration.
- The running server started before any configuration source last changed, even when a rewrite left the setting as it was.
- There are only inetd sessions, the process is unreadable, or the configuration is uncertain.

To tell whether the running server started before a configuration change, CSM compares the start of the oldest root pure-ftpd process with each source's last change. That process must be the standalone server, not a connection worker. Process identity and configuration are rechecked before approval, and process table scans remain rate-limited. The daemon log warns once when FTP failures start to only alert because the server is older than its configuration or no standalone server is running.

When all sources enable `DontResolve` and a standalone server is confirmed, `csm doctor` asks for a restart if its configuration is newer.

Without `DontResolve yes`, a journal login cannot inherit earlier brute-force history. FTP file findings remain alert-only and do not build attack scores, regardless of this setting.

#### Loopback

Successful FTP logins over loopback do not raise an unfamiliar-address warning. Failed authentication remains reportable over loopback, including through local relays.

#### Journal entries

Root FTP journal entries have separate notification identities from user-uid entries and file alerts. A forged alert cannot silence a root failure alert in the same batch or in saved notification history, including after switching from file monitoring to the journal.

In the failure history the journal reader keeps, busy sources cannot displace another source's failures from the window. Journal timestamps date the failures, so delayed delivery does not turn old attempts into a fresh burst.

### SSH login records

An SSH login is reported only from sshd's own success record: the sshd program tag, then `Accepted <method> for <user> from <address> port <port>`. sshd also logs the login names that clients offer, so the same words anywhere else in a line are ignored and cannot name an address to alert on or block. The reputation check uses the same record parser when collecting SSH addresses.

The parser supports:

- traditional syslog, RFC3339 timestamps, and records without timestamps
- either `sshd` or `sshd-session` tags, with optional process IDs
- IPv4 and IPv6 addresses

Trailing key information does not change the account or source address.

The finding's identity uses the complete log record, including its timestamp and session fields, even when the displayed details are shortened. A later session from the same address is a new finding, even within the 24-hour history reminder window.

### Logins reported once

The FTP and file-based SSH log watchers read the same files as the periodic `ftp_logins` and `ssh_logins` checks. Each file login is reported once: the watcher and the periodic check build the same finding, and the second one is recognized as a repeat.

- When a file watcher is not running, the periodic check still reports file logins on its own.
- When SSH uses the journal, the periodic auth-file scan yields to it.
- Each journal entry has its own alert identity, so a later login with the same process ID and client port still alerts.

### How auto picks a mail log source

With `mail_logs.source: auto`, each retry reads the configured journal units when the journal is usable. That requires all of these:

- Syslog goes through journald (`/dev/log` is its socket).
- The running journal service holds an open journal. Old journal files alone do not qualify, including when journald uses `Storage=none`.
- Postfix does not write its own log file, including secondary instances listed in `multi_instance_directories`.
- The configured `mail_logs.units` cover all running Postfix and Dovecot master processes. Mail services that have not started yet do not keep auto on file input.

If these checks cannot confirm coverage, auto chooses the configured or platform file if present, then the journal units.

Set `mail_logs.units` to the actual service names for custom Dovecot services or named Postfix instances. Unit names are exact, not patterns. Postfix units must be named `postfix` or `postfix@<instance>` so their unprivileged workers pass the sender filter. Other Postfix unit names keep auto on file input.

A file missing for 90 seconds triggers a new selection. The old reader stops before a replacement starts.

### Mail log reader rules

#### Rotation and truncation

The Postfix/Dovecot file reader polls every two seconds. It reads replacement files from the start and rewinds when the current file shrinks below its read position. Truncation also clears buffered bytes from the previous file contents.

With `copytruncate`, a file that regrows past that position between polls can hide the truncation and lose events. Use rename/create rotation with the log writer reopening its file, or journal input, when that loss is unacceptable.

#### Partial and long records

Mail records are emitted only after their newline arrives. A partial record survives temporary EOF up to the 64 KiB limit, including its newline. Longer records are discarded through the next newline even when written across several polls. Rotation and detected truncation clear pending record state.

#### Reconnecting to the source

Mail source attachment retries after failures, starting at one second and doubling to a maximum delay of 30 seconds. The watcher remains unhealthy and reports an unavailable-source finding until a reader attaches successfully. Repeated identical errors are not re-emitted.

Retries use the current mail source configuration and start at the current tail, so delayed attachment does not count historical authentication failures as new activity.

### SMTP failure pairing rules

These rules add to [How a failed SMTP login is counted on Postfix hosts](#how-a-failed-smtp-login-is-counted-on-postfix-hosts).

- Pairing is bounded by both receipt time and, when present, the timestamps in traditional syslog or RFC3339 records. Reading a backlog does not make an old timestamped rejection fresh.
- Each credential or backend failure consumes one pending rejection, including failures withheld for backend errors.
- Authentication protocol refusals from Postfix or Dovecot neither count nor consume a pending rejection.
- Infrastructure protection is checked again before a paired failure counts.
- Tracking capacity is bounded. New verdicts are dropped when full, and error-mark overflow withholds pairing until the affected window expires.

#### Which mailbox a failure names

The mailbox for `smtp_account_spray` comes from Dovecot. When pending rejections for an address name different mailboxes, its failures count toward address and subnet detection with no mailbox. Long-memory spray detection counts each rejected name once.

The pairing bounds apply to every name in such an ambiguous batch:

- Only names eligible when a reply is paired enter that reply's evidence.
- A withheld backend reply discards the batch's pending names, so they cannot return as evidence after recovery.
- Names already counted or discarded remain consumed for their pairing window. A later rejection can start a new window.

#### When a mailbox's existence is unknown

Dovecot mailbox existence is unknown when the logged name is empty, sanitized, abbreviated, or disagrees with another pending rejection.

An `unknown user` answer for a name that is not in the mailbox's own spelling, such as mixed case or a final dot, is unknown too. The answer is about that spelling and not the mailbox.

These attempts still count toward address and subnet detection. For one unambiguous mailbox, a password mismatch from any database takes precedence over an unknown-user answer. Forged verdicts inside names or logged passwords do not supply mailbox evidence.

#### Postfix login names

Postfix login names are read only from the username field immediately after the authentication method. Sender and forwarding fields cannot supply a missing login name.

- Mailbox keys ignore surrounding whitespace and ASCII case, and remain stable when a long name must be shortened.
- Non-ASCII letters remain distinct and cannot borrow another mailbox's login trust.
- Names with invalid UTF-8 count as unnamed failures and cannot earn login trust.

#### Dovecot message levels

Dovecot's informational and debug authentication messages can contain client text. They never mark the authentication backend as unavailable. Error and warning diagnostics still reach the backend-outage detector.

### Dovecot answers for IMAP and POP sessions

Failed IMAP, POP3 and ManageSieve logins carry Dovecot's `unknown user` and `Password mismatch` answers too. CSM pairs each answer with the login summary of the same session, address and name. The spray rules use it to tell whether the mailbox exists.

- Answers from several databases combine as they do for SMTP.
- An answer on its own records nothing.
- An authentication error that names the session withholds the session's answers, so a failing database cannot make a real mailbox look missing.
- For IMAP and POP, a cut or unrecognized authentication message that names a session also withholds that session's answers, and a local mailbox lookup does not replace them.
- Each mailbox answer expires by its own log timestamp. Another name cannot renew it, and a later timestamp cannot answer an earlier login summary.
- Successful logins consume pending session answers too.

Session tracking runs only while the spray rules are on. It is held in memory and starts empty after a daemon restart.

### Restored spray memory

Restored spray memory stays within the configured capacity, and expired entries are discarded. Records dated in the future cannot establish login trust or corroborate a missing mailbox. Saved revocations override conflicting trust records.

### Which users count as running site code

Step 2 of [Preparing Stalwart](#preparing-stalwart) is safe only when no user the port lock admits runs site code. Setup and doctor inspect the following.

- PHP-FPM includes and pool files on supported distributions and panels, along with running workers.
- Apache's PHP, CGI, FastCGI (mod_fcgid and mod_fastcgi), Passenger, WSGI, Perl, Python, Lua and LSAPI modules. Each counts, since setup cannot see what isolates them.
- LiteSpeed's server user, unless its Enterprise configuration sets PHP suEXEC to 1 or 2.

Unreadable configurations or process credentials, unresolved users, and unsupported include expressions prevent trust.

#### LiteSpeed inspection

- LiteSpeed inspection covers the default installation, and custom installation directories identified by platform detection or a LiteSpeed server process running as root. A process any other user starts under that name never locates a configuration.
- Only direct server settings in a complete Enterprise XML document prove isolation. Nested application users and commented settings do not.
- OpenLiteSpeed's server user counts even when an Enterprise configuration is also present.
- Missing, ambiguous or malformed LiteSpeed settings and unsupported OpenLiteSpeed server includes stop the inspection. CSM does not guess a user.

#### Processes and their executables

A process name only excludes a runtime user when the executable and its parent directories are root-owned and not writable by other users, and the running executable matches that installed file.

| Process | How it counts |
|---------|---------------|
| User-renamed copies, hard links in writable directories, and unreadable executables | Their effective and filesystem users count as possible runtime users |
| A root-started process whose executable a package upgrade has replaced | Ignored only while its effective and filesystem users are also root. If either is non-root, both count as possible runtime users |
| A root process whose executable cannot be read, or a root LiteSpeed server whose executable cannot be verified | Stops the inspection |
| A process with a missing executable | Excluded only when it is a confirmed kernel thread or a fully exited process |
| A zombie leader with surviving threads | Stops the inspection, because its credentials cannot identify every remaining thread |

#### PHP-FPM supervisors

A root-owned FPM supervisor is distinct from a root-owned worker. The supervisor exemption requires a trusted installed FPM executable and root real, effective and filesystem UIDs. A process name or master-process title alone cannot exempt an unreadable executable.

### Doctor's Stalwart spam checks

#### DNS blocklists

The blocklist check runs only while the filter is on. Doctor sends Stalwart one test message, which Stalwart never delivers or learns from, and warns when the blocklists refuse this server's resolver.

Blocklist warnings show a bounded, terminal-safe list of refused tags. They do not report the test message's verdict or score. Stalwart keeps refused answers until it restarts, so restart it after changing the resolver.

#### Address list scoring

The same test message comes from the address the daemon keeps on CSM's address list. So while the address list rule is on, doctor also says whether Stalwart scores senders on that list.

The daemon writes the list within 10 minutes of setup, so this check can warn until then. Run doctor again after that. If it still warns, check the daemon's `stalwart_address_list` finding, and run `csm stalwart setup` only when that finding says to.

Observe mode skips this check, since the daemon then does not write the list to Stalwart.

#### Classifier status

From the newest log alone, doctor says when Stalwart's spam classifier is still learning and how many ham and spam samples it has. It omits that line if the latest classifier status is malformed or a later training run has started.

### The X-PHP-Script header

The [PHP-relay](#php-relay-mail-abuse-cpanel-only) detector takes the source address and the script label from the `X-PHP-Script` Exim header.

The source address is the final, server-observed address in `X-PHP-Script`. Client-supplied forwarding text cannot replace it. Behind a proxy this is the proxy's address. CSM does not recover a visitor address from untrusted forwarding text. A missing or invalid final address leaves IP attribution empty.

The script label ends at the first ` for ` separator, which keeps forwarding text out of per-script counts and queue actions. PHP includes `PATH_INFO` in this header without escaping separators. Paths containing a literal ` for ` therefore share the label before that separator. The source address is parsed separately from the header's end.
