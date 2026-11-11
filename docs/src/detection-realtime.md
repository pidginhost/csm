# Real-Time Detection

CSM detects threats in under 2 seconds using kernel and log watchers running inside the daemon: a fanotify file monitor, inotify tailers on auth/access/mail/FTP logs and the Exim spool, and a PAM brute-force listener.

## fanotify File Monitor (< 1 second)

Monitors the filesystems containing `/home`, `/tmp`, `/dev/shm`, `/var/tmp`, configured `account_roots`, and detected cPanel document roots.

A filesystem mark covers the whole filesystem, including all its bind mounts,
which makes writes inside CloudLinux CageFS visible. Roots on that filesystem
share one mark. A root being a mount point does not restrict a filesystem mark
to that path: symlinks and bind mounts can name only a subtree. On kernels that
fall back to mount scope, the mark covers the whole containing mount and misses
writes through other bind mounts. The startup log describes these scopes and
which roots share a filesystem mark, and says when a watch root sits on the same
filesystem as `/`, which is when the mark raises an event for every write on the
machine; failures to inspect or mark a root are reported even when other roots
succeed. Missing roots are skipped.

The daemon filters delivered file events before queueing them for analysis. In
the shared temporary trees (`/tmp`, `/var/tmp`, `/dev/shm`) that decision uses
the event descriptor. Non-directory objects with executable permission bits are
queued, as are watched user crontabs, PHP source, configuration files such as
`.htaccess`, `.user.ini` or `php.ini`, known webshell names, files under `.config`
directories, and images inside hosted trees. Writes needed for self-deleting-file
tracking are also queued. Other writes are dropped without analysis.
Files retained for tracking keep their normal analyzer route,
including suppression and WordPress checksum checks. Staging names written by an
atomic save are resolved first, so a configuration file saved through one is
still analysed. A descriptor that cannot be inspected is analysed rather than
skipped.
`csm_fanotify_events_total`, `csm_fanotify_events_admitted_total`, and
`csm_fanotify_events_dropped_total` distinguish completed admission decisions,
queued events, and events lost to a full analyzer queue. Subtract both admitted
and dropped events from the received total to count events rejected before
queue admission, including those whose file path could not be resolved.

Atomic-save files enter the same bounded worker queue as ordinary writes.
Where supported, create events inspect available content; close-write events inspect the
completed write. Scans read the original event descriptor even if the file has
been renamed, replaced, or deleted before analysis. No rename event is needed
to inspect those bytes. Repeated findings use the normal alert cooldown, and
queue overflow schedules a directory rescan of files that remain on disk.
That recovery runs one pass at a time, under a time budget and with a minimum
gap between passes. Unfinished directories stay queued and retry even after
new drops stop. Recovery resumes within a directory and retains its original
scan window so deferred files do not age out while waiting.
Kernel notification loss still relies on the next deep scan. Shutdown drains
the queue under a fixed time budget: events still waiting when it expires are
released without being scanned; files still on disk are covered by the next
deep scan. Both budgets are checked between scans, so a scan or directory
read already in progress must still finish before shutdown completes. A rename-only
arrival without a usable create or close-write event is also first examined
by the rolling content scan; the watcher does not subscribe to rename events.

Realtime YARA scans hand the worker a sealed memory-backed copy of the
captured bytes, whatever their size, without reopening the event path for
scanning. Alert payload details describe that snapshot. When it is the whole
file, the finding keeps the snapshot's fingerprint. For partial reads, CSM
reopens the path to fingerprint the whole file when preparing the finding;
unreadable files and files above the fingerprint limit receive no fingerprint.
Re-check compares whole-file fingerprints, so an unchanged file can clear when
YARA no longer matches it. Content outside the read window remains subject to
the scheduled scan limits.
A failed scan raises `yara_realtime_scan_error`.

For WordPress atomic saves, the intended basename can select a core or plugin
checksum entry. Only a match against the complete event-file content verifies
the file; missing checksums, partial content, and modifications proceed through
normal detection. The finding retains the actual event path.

A WordPress update is unpacked under `wp-content/upgrade/` before it is moved
into place, and each staged PHP file is judged by hash rather than by location.
A file that matches the official wordpress.org checksum for its package version
is stock and skips detection like an installed stock file. A file whose
checksums are still being fetched is content-scanned now and compared once they
land, even if the package header was written late or WordPress has already
moved the tree into place. An installed plugin header can identify the release
only when its directory is the original staging directory moved into place, or
when the installed path is still the very file the staged event wrote, so a
stock file first examined after the move skips detection like any other.
The installed plugin directory must remain the same directory during that
check and cannot itself be a symlink. Its identity also connects earlier
queued files from the same tree, including when the later file is already
verified. Copies and unrelated trees do not establish that connection; every
retained digest still needs to match the official release.
A core update copies files, so the installed version.php identifies the
release only if it was replaced or rewritten after the staged file was seen;
a borrowed release still requires the file's bytes to be the official ones for
that path. A tree removed before its release could be identified gets a
package warning, not file-by-file comparisons against the old release. This
covers refused updates (for example when the new release needs a newer PHP)
and plugin copies whose staging identity was never captured; the warning does
not establish whether installation succeeded. Reused staging paths follow the
normal alert cooldown rather than suppressing later unidentified uploads. A
file the official package does not ship gets its
own warning. An event identified at its installed location keeps that location
while it exists, even if another update reuses the staging name. Other staged
events name the installed path when it exists. Themes, packages
not published on wordpress.org, a full verification queue, and a package whose
checksums do not arrive within 60 seconds raise one warning per staging
directory. WordPress picks a new staging directory for every upload. Once the
package type and version are known, these warnings are identified by site,
package type, name, version and reason. Uploading the same declared release to
the same site again is a repeat. It is emailed again only after 24 hours without
a report, and history follows the normal 24-hour reminder. This
groups checksum-availability warnings; it does not establish that the package
contents are unchanged or safe. Incomplete headers keep an upload-specific
warning, and a later change of type, version or reason can raise a new warning
in the same directory. Per-file checksum warnings repeat across uploads only
when their package identity, relative path and complete digest match; files
that could not be hashed keep their upload-specific warning. Content findings
inside staging keep their own per-file identity and normal alert cooldowns;
package-warning dismissal does not dismiss them.

Location warnings for PHP in sensitive WordPress directories are suppressed
only for recognized inert content, including comment-only stubs and literal
translation or version data. PHP attributes are executable syntax, not comments,
and do not qualify a file for that suppression. Content scans still run.

The head-window eval/decoder check ignores PHP comments and inline HTML.
String boundaries and legacy line endings preserve the code that follows them.
Tail windows retain raw content because they can begin inside a literal whose
opening delimiter is outside the window.

**Detects:**
- Webshell creation (PHP files in web directories)
- Self-deleting droppers: a PHP or executable created under a document root and unlinked within `thresholds.dropper_unlink_ttl_sec` (default 300s), the loader technique that creates a rogue admin then erases itself before any scan. A file whose exact bytes WordPress moved or copied into place before removing the original is not reported: plugin, theme and core packages, language packs, and the version file a core update reads first. Language-pack and version-probe copies also require a complete, stable data-only snapshot with no suspicious content or earlier unsafe write. A core update that stops after reading its version file leaves the old release installed, so no installed copy matches; that version file is not reported when its bytes equal the wordpress.org checksum for the release and locale it declares. Core checksum downloads start in the background when capacity permits. Plugin downloads do not consume core checksum capacity or share its admission limit. Concurrent requests for a release reuse its download and cached result; a file still unverified at the deletion probe is reported. Package headers are read only from regular files, never blocking on an account-writable named pipe or device. Other executable files do not qualify for this copy exception. The script Really Simple Security copies into uploads to test whether PHP runs there, then deletes, is not reported when its content is byte for byte the shipped script; any other content under that name is. Elementor Safe Mode copies its loader into mu-plugins while enabled and deletes it when switched off; that removal is not reported when the loader's bytes equal the wordpress.org checksum for the same file in the Elementor release the same site had installed when the loader was written. When those checksums cannot be consulted, a loader byte for byte identical to a complete, stable snapshot of the installed plugin's own file, reached without symlinks, is reported as Warning and the finding names that file. The same package proof applies when a different file replaced the loader's path. Other capability-probe scripts cannot exempt executable content in this loader. A loader the checksums reject, or whose earlier payload was rewritten, stays Critical even when its containing directory was removed. A core update unpacks the whole release but installs only what changed and never overwrites the bundled themes and plugins; a staged file it deletes that way is not reported when its bytes equal the wordpress.org checksum for that path in the release now installed. The checksum must describe the same complete, stable snapshot as the retained content. Earlier nonempty content must also be known and unchanged, including content observed at creation; later official bytes or an identical installed copy cannot erase that evidence. The same history rule applies to every staged core, plugin and theme file and to the Safe Mode loader: a file whose content changed after it was first written is reported even when WordPress then moves it into place, an identical copy is installed, or its last bytes are official. Repeated analysis of the same snapshot does not count as another write. A single snapshot whose complete bytes could not be read can still match a move by file identity; a second nonempty snapshot leaves the unknown earlier bytes unaccounted for. Files too large for a complete snapshot retain their leading bytes for content checks. Other files removed from staging without an identical installed copy are still reported. Upgrade staging, atomic-save temp files, template compile caches, BackWPup job-state files (the running job's JSON and its folder list, written behind a PHP comment, including a captured head cut inside a CRLF line ending), a path taken over by a newer file, and a file whose original directory was removed are recognized and reported at a lower severity; files removed together with the directory holding them, such as a language pack WordPress unpacked and discarded, are reported once for that directory; a create/delete burst collapses into one lower-severity notice. Grouping is recalculated after ignored paths are removed: remaining files can form directory groups, while a lone remaining file is reported on its own. Off with `thresholds.dropper_detection: false`. Candidate tracking and findings held for aggregation each accept up to 16,384 entries; additional work is refused without evicting older evidence. Status and doctor report refusals, exhausted probes, overdue work and stalled processing through [protection queue health](api.md#protection-queue-health).
- Dropper admission and pending findings follow the live `suppressions.ignore_paths` list after reload. Intentionally suppressed candidates consume no tracker capacity; losses of eligible candidates still raise the capacity warning.
- PHP in uploads, languages, upgrade directories
- PHP in `.ssh`, `.cpanel`, `.gnupg` or `.cagefs` directories, or in the `mail` directory of an account home, including cPanel accounts on further home partitions such as `/home2` (critical escalation). Account mail locations ignore redundant separators but keep Linux directory-name case sensitivity. Directories named `mail` inside applications or document roots do not count; their PHP content is still scanned.
- Executable drops in `.config`
- `.htaccess` injection and tampering (auto_prepend, eval/base64 handlers, CGI execution remaps, and ModSecurity disablement). Handler abuse keeps its own finding name. These findings never quarantine the file; automatic cleaning waits for a deep scan and requires `auto_response.clean_htaccess`.
- `.user.ini` tampering and `php.ini` tampering under configured or detected web roots
- Obfuscated PHP (encoded, packed, concatenated)
- Fragmented base64 evasion (`$a="base"; $b="64_decode"` -- function name split across variables)
- Concatenation payloads (hundreds of `$z .= "xxxx"` lines with eval at end)
- Tail scanning: payloads appended to the end of large legitimate PHP files (beyond the 32KB head window)
- CGI backdoors: Perl, Python, Bash, Ruby scripts in web directories (e.g., LEVIATHAN toolkit)
- SEO spam: gambling/togel dofollow link injection in PHP/HTML files
- Phishing pages and credential harvest logs
- Phishing kit ZIP archives
- PHP carried inside a file served as an image. Image writes under an account or configured document root are inspected, including hosted `.config` directories and roots located in temporary directories. Images up to 128 KiB are inspected in one piece; larger files get a 64 KiB head and a 64 KiB tail scan. Payloads outside those windows require a deep scan, subject to `thresholds.full_scan_max_file_mb`. A PHP opening tag alone is not enough -- a screenshot quoting one in its description chunk stays quiet -- and a file that only wears an image name while holding PHP source is reported the same way. Finding: `php_in_image_realtime`.
- A PHP file that includes or requires an image, archive or other non-executable file while also reading request input. That pairing is the loader half of the technique above: the payload lives in the picture and the one-line loader elsewhere. Literal targets ending an include statement, concatenated paths, paths held in a local, encoded paths and suppressed `@include` statements match in either statement order. Ordinary templating that pulls in `.html`, `.tpl`, `.txt` or `.svg` partials is outside the extension-based rule. Encoded targets still count because the source hides their extension.
- YAML signature matches (PHP, HTML, .htaccess, .user.ini, php.ini)
- YARA-X rule matches (if built with `-tags yara`)

Completed upload execution probes remain tracked until the deletion check so
combined or out-of-order create and close-write events preserve completion
evidence. A probe without a completed write, or with earlier unsafe or
uncertain content, remains reportable.
Image writes use the existing notification-only fanotify instance, its 16,384
event queue and 4-16 analyzer workers. They create no permission-event holds
and do not enter the mail scanner. Thumbnail and WebP bursts fill the same
queue as other writes: excess events are closed immediately and their parent
directories enter the existing capped recovery tracker. Recovery rescans
recent surviving files; kernel queue loss and exhausted recovery coverage
still rely on the next deep scan. Queue health and content-read truncation
remain visible through the existing metrics. Mail permission holds retain
their separate hold budget and watchdog.

Both the real-time and the scheduled WordPress admin-creation signature
require an administrator role token plus literal or request-derived
credentials, and both accept the same ASCII whitespace, including the vertical
tab. An importer that creates users with a generated password does not trigger
either one just for reading a login from an import form.

Two divergences between the engines are known and left in place. Go folds the
Unicode long s into ASCII s and YARA's nocase does not, so a token spelled
with it can match in real time where a scan declines. Bounded expressions also
count differently: the real-time engine counts characters and the scheduled one
counts bytes. Neither can occur in real PHP, and both belong in the scanner's
regex compilation rather than in hand-written escapes inside every rule.
Strictness parity is not enforced across the rulesets: the parity check
compares rule names, not how strict each side is.

Complete blank files are excluded from dropper alerts after a close-write
observation. Any content or metadata change during the read, including an
unlink, leaves the snapshot uncertain. WordPress data and its checksum are
read within the same stat interval. A later complete close-write snapshot
cannot rule out code that ran during an earlier unstable read. That
uncertainty and code seen in any read remain attached to the tracked file.
Concurrent firewall-log writes can therefore still produce a warning when
the log is replaced, or a critical finding when it is deleted.

Core-release checksum downloads are non-blocking and bounded, including
their retry timers. Repeated misses and streams of distinct release names
share an admission budget. Release identifiers longer than 64 bytes are
rejected before retention or lookup. When that budget is exhausted, cached checksums
remain usable; an uncached file stays unverified and receives the normal
dropper assessment. A later observation can request checksums again after
the budget recovers.

PHP files are also excluded when their first statement stops the interpreter
(`exit`, `die`, or `__halt_compiler`, with at most a plain literal argument and
no preceding comment). Plugins keep state and firewall data in files of that
shape and rewrite them constantly, and the bytes behind the terminator are
never compiled. The exemption is refused when those trailing bytes are made
only of transport-encoding alphabet: an operator who turns on PHP source
conversion can have a file decoded before it is tokenized, which would make an
encoded tail the program and this header padding. Comment-bearing PHP remains
eligible for the same reason -- a comment's tokens depend on the interpreter's
source encoding. Executable-mode files are not judged by PHP compilation rules,
because a shell may read them instead. Content or signature findings and
previously observed code always override inert-content filtering.

**Features:**
- Per-path alert deduplication (30s cooldown)
- Process info enrichment (PID, command, UID)
- Auto-quarantine on high-confidence realtime signature matches (category, size, entropy, and hex/execution validation)
- Auto-quarantine on confirmed PHP request-to-execution flows and executable packed payloads, using the stable file version that was inspected

## Sensitive System File Watcher

Tracks a fixed set of system-configuration paths: the account and credential databases, `sudoers` and its drop-in directory, the SSH daemon config and its drop-in directory, the system cron drop-in directories, and per-user crontabs. The set is not operator-configurable -- a path an attacker knows is excluded is a free landing pad.

The backend is chosen by `detection.sensitive_files_backend`. The `bpf` backend attaches an LSM hook that catches writes as they happen, and re-expands the watchset every `detection.sensitive_files_poll_interval` (default 5m). The `legacy` backend content-hashes the watchset on the same interval.

Both backends key on the path, not the inode. Most tools replace a config file by writing a temporary file and renaming it over the target, which gives the path a new inode and hides the write from the LSM hook. The BPF refresh therefore compares content and security metadata per path: a rename-over is reported as a change on the existing file, only a path no previous refresh had seen is reported as newly appeared, and a regular-file rewrite that leaves bytes, permissions, and ownership unchanged is not reported. It also tracks symlink targets, so retargeting a watched path remains visible even when both targets contain the same bytes. Non-regular entries are tracked by path identity without opening them for content reads. The legacy poller compares content digests by path.

Findings are `sensitive_file_modified`. A write finding successfully delivered by the LSM hook wins only while the path still has the exact state captured for that finding. The refresh reports a later rename-over separately, retries a refresh finding if the alert queue was full, and always evaluates the bytes used for its digest rather than a later read. Writes inside a package-manager window, or by a process whose ancestor is a package manager or the control panel's own maintenance tooling, are demoted to Warning unless a cron payload carries obvious persistence tokens. This veto applies to live writes as well as added and modified cron files found by polling. It includes the shared crontab persistence patterns and their bounded base64 inspection, in addition to suspicious shell fragments. A modified file in `/etc/cron.d` found by the refresh, the legacy poller or the scheduled cron check is also demoted when the only difference from the version CSM saw last is the minute and hour of jobs that already ran once a day at a fixed time, which is how cPanel reschedules its own jobs every night. A changed command, argument, user, environment line, job list or line order, a job that now runs more often or on other days, and a file CSM has not seen before all keep the finding High, and all three paths also refuse schedule-based demotion when the file's ownership, mode or symlink target changed in the same interval or could not be checked. Files with randomized calendar fields do not qualify: reloading them can choose new execution days, including for jobs whose bytes stayed unchanged. Persisted schedule evidence must belong to the recorded content baseline; an interrupted update cannot justify demotion. Control-panel ancestry is read from the executable a parent process actually runs, not from the name it reports, and the executable must be a root-owned file inside the panel's own directory that no other user can write. Cached executable evidence must come from a resolved procfs link; an exec-event filename or script argument does not qualify. Ancestry is available on every Linux build before monitoring starts. A cache hit avoids a live ancestry walk; when the cache proves nothing, CSM falls back to procfs. CSM's own managed writes are suppressed by content, not by path.

## inotify Log Watchers (~2 seconds)

Tails auth, access, and mail logs in real-time. The exact file paths are chosen per platform at daemon startup -- see the `platform: ...` line in the daemon log.

| Log | Platforms | What it detects |
|-----|-----------|-----------------|
| cPanel session log (`/usr/local/cpanel/logs/session_log`) | cPanel only | Logins from non-infra IPs, password changes, File Manager uploads, sessions ended for security token failures |
| cPanel access log (`/usr/local/cpanel/logs/access_log`) | cPanel only | cPanel-API auth patterns |
| Auth log | All | SSH logins and failures. `/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL family and cPanel |
| Exim mainlog (`/var/log/exim_mainlog`) | cPanel; non-cPanel when the file exists | Mail anomalies, queue issues, SMTP brute force, probe abuse, and cloud relay abuse |
| Apache/LiteSpeed/Nginx access log | All | WordPress brute force (wp-login.php, xmlrpc.php), real-time. Paths: `/var/log/apache2/access.log` (Debian), `/var/log/httpd/access_log` (RHEL), `/var/log/nginx/access.log` (Nginx), `/usr/local/apache/logs/access_log`, then `/var/log/apache2/access_log` and `/etc/apache2/logs/access_log` (cPanel, also written by LiteSpeed). Automatic candidates exclude the cPanel access log |
| Mail log (platform file or journal) | All hosts with Postfix/Dovecot logs | IMAP/POP3/ManageSieve account compromise and mail brute-force; SMTP brute force on Postfix hosts with Dovecot |
| FTP log (`/var/log/messages`) | cPanel only | FTP logins and failures |
| ModSecurity error log | All (if ModSec installed) | WAF blocks and attacks. Auto-discovered from the detected web server |
| Nginx error log (`/var/log/nginx/error.log`) | Nginx hosts | General web errors, ModSecurity denies |

`web_server.access_logs` replaces the automatic web log candidates. The
realtime watcher selects the first existing log at startup. If none exists,
it retries every candidate in order until one can be opened, then watches
that path until restart. The periodic WordPress check uses the first
candidate with lines and excludes its symlink aliases from the per-vhost
scan; other candidates can still be scanned when a per-vhost glob matches
them. Reputation collection scans all listed web logs and deduplicates
addresses, while the cPanel log remains a separate source for panel checks.

cPanel session log readers match fields by position, so login names and
address lists cannot supply the service, address, event or account. Scheduled
and realtime login alerts skip loopback and non-address origins. API-created
sessions never count as direct logins for multi-address or hijack correlation,
and a login that names its method twice counts as a direct login. A password
change entry with an unreadable header or timestamp cannot suppress a
shadow-file alert.

A cPanel API authentication failure on a session URL (`/cpsess<token>/...`)
waits a few seconds for the session log. A browser tab left open after the
account logged in again elsewhere still sends its old URL token, and cPanel
ends that session after a few token failures. When the session log records
that for the same address, the failures that name the session's account, and
the tab's later requests that reuse its URL token, are not reported: nothing
guessed a credential. Any other failure, including one from another client
behind the same address, is reported as before. API calls with a token or
password carry no session URL and are reported at once. The periodic
`api_auth_failures` check counts failures the same way.

The wait covers both matching-window edges and the log watchers' polling
delay. It ends at a fixed deadline. Evidence read after that
deadline cannot erase a failure. Correlation evidence expires independently
of alert delivery, and queue saturation is reported through the existing
queue health counters and daemon warnings.

A frozen Exim message is reported once. Exim logs a still-frozen message again
on every queue run, and those lines are not reported again, also after a
daemon restart: the daemon keeps the messages it reported in its state
database until a day passes without a queue run logging them. A message that
froze while the daemon was stopped has not been reported, so the first queue
run after the start reports it.

Startup discards expired records and invalid message IDs, and adjusts
timestamps ahead of the current clock. These corrections are saved even if
no new mail event arrives, so another restart does not extend the corrected
retention period.

FTP findings use only the peer field directly after the pure-ftpd program tag,
in both realtime monitoring and scheduled scans. Missing or malformed peers and
hostname peers produce no finding. To record numeric peers, use pure-ftpd's
existing `DontResolve yes` setting. Addresses in usernames or later message
fields never identify the client.

Successful FTP logins over loopback do not raise an unfamiliar-address warning.
Failed authentication remains reportable over loopback, including through local
relays.

The FTP and SSH log watchers read the same files as the periodic `ftp_logins`
and `ssh_logins` checks, so both see every login. Each login is reported once:
the watcher and the periodic check build the same finding, and the second one
is recognised as a repeat. When the watcher is not running, on a non-cPanel
host or before the log file appears, the periodic check still reports the
login on its own.

An SSH login is reported only from sshd's own success record: the sshd program
tag, then `Accepted <method> for <user> from <address> port <port>`. sshd also
logs the login names that clients offer, so the same words anywhere else in a
line are ignored and cannot name an address to alert on or block. The
reputation check uses the same record parser when collecting SSH addresses.
Traditional syslog, RFC3339 timestamps, and records without timestamps are
supported, with either `sshd` or `sshd-session` tags and optional process IDs.
IPv4 and IPv6 addresses are accepted; trailing key information does not change
the account or source address.

The identity uses the complete log record, including its timestamp and session
fields, even when the displayed details are shortened. A later session from the
same address is a new finding, even within the 24-hour history reminder window.

A successful FTP login and a cPanel File Manager write are not emailed. On
shared hosting every customer connects from an address that is not
infrastructure, so both fire on ordinary use of a core feature. They stay on
the findings page, in history, in incident correlation and in the attack
database, where their value is correlation with other evidence on the same
account. Failed FTP authentication, FTP brute force, a login from a
brute-force source, and SSH logins are all still emailed.

The phpanel webhook and SSE event stream still receive these successful
operations; the email and operator-webhook filter runs after data delivery.

#### Login check names on upgrade

New findings use `ftp_login` in place of `ftp_login_realtime`, and
`ssh_login_unknown_ip` in place of `ssh_login_realtime`. Update external
phpanel, export and SIEM rules to accept the merged names. Historical records
and already queued deliveries can still contain the old names; the JSON schema
is unchanged.

Existing `alerts.email.disabled_checks` entries and saved suppression rules for
either retired name also match its replacement. The Settings page displays and
saves the current names. A mute for one former producer now covers the shared
finding from both producers; it does not mute FTP brute-force escalations.

Pending SSH blocks and restored SSH incident evidence retain their blocking
policy. Historical successful FTP activity remains excluded from incident
blocking, including events carrying its retired name.

cPanel-only log watchers are not registered on non-cPanel hosts, so you will not see "not found, retrying every 60s" warnings for them on plain Ubuntu or AlmaLinux.

The Postfix/Dovecot file reader polls every two seconds. It reads replacement
files from the start and rewinds when the current file shrinks below its read
position. Truncation also clears buffered bytes from the previous file contents.
With `copytruncate`, a file that regrows past that position between polls can
hide the truncation and lose events. Use rename/create rotation with the log
writer reopening its file, or journal input, when that loss is unacceptable.

Mail records are emitted only after their newline arrives. A partial record
survives temporary EOF up to the 64 KiB limit, including its newline. Longer
records are discarded through the next newline even when written across
several polls. Rotation and detected truncation clear pending record state.

Mail source attachment retries after failures, starting at one second and
doubling to a maximum delay of 30 seconds. The watcher remains unhealthy and
reports an unavailable-source finding until a reader attaches successfully.
Repeated identical errors are not re-emitted. Retries use the current mail
source configuration and start at the current tail, so delayed attachment does
not count historical authentication failures as new activity.

With `mail_logs.source: auto`, each retry chooses the configured or platform
file if present, otherwise the configured journal units. A file missing for
90 seconds triggers a new selection. The old reader stops before a replacement
starts. Journal input follows new records from the selected services, including
services with no prior entries; it does not replay older records on attachment.

Explicit `file` and `journal` modes retry their selected source without
switching, and a working reader stays attached until it stops or loses its file.
Journal input requires a build with journal support. The default units are
`postfix`, `postfix@-` (the Postfix instance on Debian and Ubuntu) and
`dovecot`. Unit names match exactly, so list any further Postfix instance, such
as `postfix@postfix-out`, in `mail_logs.units`. Each journal record reaches
the mail detectors with its program name, process id and time, as a mail log
file records them, so every mail detection works the same with either source.
Journal selection uses the trusted systemd unit, not the caller-supplied syslog
identifier. Keep `mail_logs.units` limited to mail services. File input has no
sender credentials: a local user who can submit mail-facility syslog messages
can forge failures or successes there. On hosts with untrusted local users,
use `mail_logs.source: journal` with the mail service units, or restrict the
syslog input that writes the mail log.

## SMTP / Dovecot Brute-Force Tracker

Detects credential stuffing, password spray, and raw SMTP probe storms. Runs as part of the Exim mainlog watcher on cPanel hosts and on non-cPanel Exim hosts where `/var/log/exim_mainlog` exists.

On hosts without that log, such as Postfix servers that check SMTP logins against Dovecot, the tracker counts a failed SMTP login when two lines from the mail log agree:

- Postfix's `SASL ... authentication failed` warning, which is the final result of the request, and
- Dovecot's rejection for the same client address shortly before it: `Password mismatch`, `unknown user`, or PAM's authentication failure.

Neither line counts alone. Postfix logs a Dovecot outage the same way as a wrong password, and a Dovecot rejection is one password database's answer: a later database can still accept the login or fail. A rejection followed by a successful login leaves no Postfix warning, a Dovecot error or warning for the same client within the pairing window withholds the failure, and one Postfix warning counts once however many databases rejected the request. Postfix SASL backend warnings also withhold failures from that SMTP process, including stale replies after a failed reconnect. Replies that blame the authentication server or reject the authentication protocol without checking credentials never count.

Pairing is bounded by both receipt time and, when present, the timestamps in traditional syslog or RFC3339 records. Reading a backlog does not make an old timestamped rejection fresh. The mailbox for `smtp_account_spray` comes from Dovecot; when pending rejections for an address name different mailboxes, its failures count toward address and subnet detection with no mailbox, and long-memory spray detection counts each rejected name once. Each credential or backend failure consumes one pending rejection, including failures withheld for backend errors. Authentication protocol refusals from Postfix or Dovecot neither count nor consume a pending rejection. Tracking capacity is bounded: new verdicts are dropped when full, and error-mark overflow withholds pairing until the affected window expires. Infrastructure protection is checked again before a paired failure counts.

The pairing bounds apply to every name in an ambiguous batch. Only names eligible when a reply is paired enter that reply's evidence. A withheld backend reply discards the batch's pending names, so they cannot return as evidence after recovery. Names already counted or discarded remain consumed for their pairing window; a later rejection can start a new window.

Dovecot mailbox existence is unknown when the logged name is empty, sanitized, abbreviated, or disagrees with another pending rejection. An `unknown user` answer for a name that is not in the mailbox's own spelling, such as mixed case or a final dot, is unknown too, because it is about that spelling and not the mailbox. These attempts still count toward address and subnet detection. For one unambiguous mailbox, a password mismatch from any database takes precedence over an unknown-user answer. Forged verdicts inside names or logged passwords do not supply mailbox evidence.

Postfix login names are read only from the username field immediately after the authentication method. Sender and forwarding fields cannot supply a missing login name. Mailbox keys ignore surrounding whitespace and case, and remain stable when a long name must be shortened.

Dovecot writes rejections only with verbose auth logging on:

```
# /etc/dovecot/conf.d/10-logging.conf
auth_verbose = yes
```

Leave `auth_verbose_passwords` at `no`; lines that carry a logged password are ignored. `csm doctor` checks both settings on Postfix hosts with Dovecot. Rejections for IMAP, POP3 and ManageSieve logins carry a session id and are counted by the mail tracker below from their login summaries. Those failures carry Dovecot's `unknown user` and `Password mismatch` answers too: CSM pairs each answer with the login summary of the same session, address and name, and the spray rules use it to tell whether the mailbox exists. Answers from several databases combine as they do for SMTP. An answer on its own records nothing, and an authentication error that names the session withholds the session's answers, so a failing database cannot make a real mailbox look missing.

For IMAP and POP, a cut or unrecognized authentication message that names a session also withholds that session's answers, and a local mailbox lookup does not replace them. Each mailbox answer expires by its own log timestamp; another name cannot renew it, and a later timestamp cannot answer an earlier login summary. Successful logins consume pending session answers too. Session tracking runs only while the spray rules are on, is held in memory and starts empty after a daemon restart.

A successful SMTP login is read from Postfix's record of an authenticated client, logged when its first recipient is accepted, or from an authenticated Exim delivery. It counts for the mailbox it names. A login from an address with no recent failures on other mailboxes earns trust for that mailbox only, and the trust counts once it is older than the fast detection window. Failures on just one other mailbox, the shape of an office device with a stale saved password, do not count here unless that mailbox does not exist or the login's own mailbox also failed. The slow brute-force block skips an address only when it holds such trust for every mailbox it failed on. Any other login that follows failures on other mailboxes earns no trust, unless the address already held trust on that mailbox from before those failures or, for IPv6, another address of the same /64 holds aged trust on it. Trust lasts as long as the spray memory window and never exempts an address from fast brute-force or subnet detection.

Trust earned beside a failing mailbox vouches only for the mailbox that logged in. It cannot excuse missing-mailbox probes or downgrade a compromise while the earlier untrusted failures remain in memory.

Failures without a mailbox prevent the slow brute-force trust exemption until they leave the slow detection window. Exim spray evidence comes from authentication failure records; greetings, subjects and SMTP commands cannot supply a failure record or replace its attempted mailbox.

Long-memory spray detection remembers each address's failed SMTP logins for days, so a botnet that tries each address only now and then is still caught. It flags an address that fails on several mailboxes it holds no trust for, or that fails on a missing mailbox after enough networks have tried the same name. A mailbox is missing when Dovecot reports it as unknown or when the cPanel lookup below finds no such name. For an address that holds trust on some mailbox, a missing name only counts toward the several-mailboxes rule, so one address typo does not block an office. A login after failures on other mailboxes raises `mail_account_compromised`, except when they were on just one other mailbox that may exist and the login's own mailbox did not fail. In observe mode, the default, the spray rules report `mail_bruteforce_suspected` and block nothing; an address is reported once per memory window, and again sooner only when it fails on more mailboxes. In enforce mode they emit `smtp_bruteforce`. IPv6 failures are remembered per /64, since one host can rotate through many addresses in it: failures from any address of the /64 count together, and aged login trust any of its addresses earned on a mailbox excuses failures on that mailbox for all of them. The missing-name first-strike exemption and the established-source compromise downgrade also count trust from any address of the /64 that predates its current untrusted failures, and a correct login to a mailbox the /64 already trusts starts trust for a new address. Trust is still earned per address, the slow brute-force exemption still needs the address's own trust, and each failing address is blocked on its own. In observe mode a /64 is reported as one address would be. An operator unblock, allow or flush clears the address's spray failure history, for IPv6 that of its /64, and keeps its login trust. Failures during an authentication backend outage, Exim's temporary authentication failures (a 4xx reply, logged when Dovecot cannot answer), and failures withheld by pairing are never spray evidence. An outage is detected a little late, so a failure during one also discards that address's spray failures from the fast detection window before it. Successful SMTP logins during an outage leave spray memory unchanged. The memory is saved every few minutes and at shutdown, so a daemon restart keeps it. The `thresholds.mail_spray_*` keys control the mode, the memory window and both rules.

On cPanel hosts, in observe and enforce mode, CSM checks whether a failed SMTP, IMAP or POP login name is a real mailbox, using cPanel's own account, domain and mailbox lists. A domain the server does not host, an unknown mailbox on a hosted domain, and a bare name that is not a cPanel account count as missing. A real mailbox or cPanel account counts as existing, and any name CSM cannot tell about stays unknown, so it counts only toward the several-mailboxes rule. A name within two edits of a real mailbox, counting the local part and the domain together, counts as that mailbox: spray memory records the failure against the real mailbox, so aged login trust on it excuses the typo and the typo is never a first strike. Login trust and spray failures treat a valid mailbox domain with or without its final dot as the same name, including saved history. The fast, slow and per-mailbox failure counts keep the name as typed. CSM holds these lists for a short time, so a mailbox created or deleted just now can get its old answer. When the lists cannot be read every name stays unknown; the daemon log gets one warning, and one line when they can be read again. Only the default `thresholds.mail_brute_account_key` reads the whole login name, so with any other key IMAP and POP failures skip this check and stay unknown. Each login keeps that setting through the check, even if configuration reloads while it is being handled.

Restored spray memory stays within the configured capacity, and expired entries are discarded. Records dated in the future cannot establish login trust or corroborate a missing mailbox. Saved revocations override conflicting trust records.

Dovecot's informational and debug authentication messages can contain client text; they never mark the authentication backend as unavailable. Error and warning diagnostics still reach the backend-outage detector. `smtp_probe_abuse` reads Exim lines only.

Signals:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `smtp_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window, or, with spray detection in enforce mode, fails on several untrusted mailboxes or on a missing mailbox many networks tried | IP blocked via nftables |
| `smtp_probe_abuse` | A single attacker IP exceeds the raw SMTP connect-rate threshold before AUTH | IP blocked via nftables |
| `smtp_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `smtp_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_bruteforce_suspected` | Spray detection in observe mode: the spray rules matched an SMTP source. The message names SMTP and the rule | Visibility finding only |
| `mail_account_compromised` | A successful SMTP login after failures on two or more mailboxes including another one, or on a missing one, or after repeated failures on the same mailbox, the first at least an hour before the login | Critical only in enforce mode when a failed name was a missing mailbox many networks tried, and the IP is then blocked. A source trusted on two or more other mailboxes is downgraded. Every other case is a High advisory, visibility only |

Tunable via the `thresholds.smtp_bruteforce_*`, `thresholds.smtp_probe_*` and `thresholds.mail_spray_*` keys in `csm.yaml`. Infrastructure IPs (from `infra_ips`) are never counted or blocked.

## Cloud-Relay Credential Abuse

Detects authenticated outbound Exim deliveries where the same mailbox is sending through public-cloud relay sources. The realtime Exim mainlog watcher evaluates new accepted deliveries, and a bounded startup replay covers recent lines already on disk.

Startup replay reads the time zone and process ID that Exim's `log_timezone` and `pid` log selector add, and a restart does not repeat an alert for sends already reported.

The finding is `email_cloud_relay_abuse`. Under the global auto-response and dry-run settings, the abused mailbox's logins and outgoing mail are suspended, with the account-wide mail hold as the fallback. Operators with legitimate cloud mailers can opt out specific mailboxes or domains under `email_protection.cloud_relay`, or use `email_protection.high_volume_senders` for known high-volume senders.

## Authenticated Sender Profile

Catches a stolen mailbox password that is used quietly: under the rate limits, from residential addresses with no cloud reverse DNS, using individually addressed messages. Every authenticated Exim submission updates a rolling hourly window and the mailbox's own history of source addresses, source countries and envelope recipients, grouped by UTC day. Repeated sends keep each source current, and a busy mailbox continues to accept new source and country evidence.

The finding is `email_compromised_account`. Four signals raise it:

| Signal | Severity |
|--------|----------|
| Sends from several countries within one hour, the pattern of a credential checker validating a stolen password | Critical |
| Far more distinct source addresses within one hour than the mailbox's own recent maximum | High, Critical when the sends also come from a country the mailbox never sent from |
| Far more distinct source addresses within one day than the mailbox's own recent maximum | High, Critical as above |
| Far more distinct recipients within one day than the mailbox's own recent maximum, each in its own message | High, Critical as above |

Each bar adapts to the mailbox's own prior maximum with a fixed minimum, so a shared office mailbox or a travelling owner is judged against their own habit rather than a global number. A country listed in `suppressions.trusted_countries` is never treated as new. A mailbox needs established prior activity before a new country counts. A newly seen country remains relevant if unusual sending develops later in the same UTC day. Repeated findings are suppressed during a cooldown, while escalation from High to Critical remains possible.

Recipient fan-out counts distinct envelope recipients of individually addressed messages; bulk announcements do not contribute. Quoted addresses remain single recipients. Records with ambiguous recipient metadata do not contribute recipient evidence, but verified source evidence still counts.

Daily history covers the recent baseline period and expires even for inactive mailboxes. It is cached and saved periodically, before idle eviction and during normal shutdown. An abrupt termination can lose submissions since the last save; a restart always starts a fresh hourly window. Save failures retain pending history for retry. An unreadable baseline pauses profiling for that mailbox until the store can be read again.

Source addresses are never blocked for this finding: they rotate per message and the owner's own address can be among them. A Critical finding suspends the mailbox's logins and outgoing mail under the auto-response and dry-run settings, with the account-wide mail hold as the fallback. Mailboxes listed in `email_protection.high_volume_senders` are not profiled.

## Mail Auth Brute-Force Tracker

Detects credential stuffing and password spray against IMAP, POP3, and ManageSieve. Runs through the `mail_logs` reader: file source uses `/var/log/mail.log` on Debian-family hosts and `/var/log/maillog` on RHEL-family and cPanel hosts, while journal source reads configured Postfix/Dovecot units. The wrapper composes with the existing geo-based login monitor, so `email_suspicious_geo` keeps firing for successful logins from novel countries.

Signals:

| Signal | What triggers it | Auto-response |
|--------|-----------------|---------------|
| `mail_bruteforce` | A single attacker IP exceeds the per-IP failed-auth threshold within the configured window without matching successful mailbox activity, or, with spray detection in enforce mode, fails on several mailboxes it holds no trust for or, on cPanel hosts, on a missing mailbox many networks tried | IP blocked via nftables |
| `mail_bruteforce_suspected` | An established good source hits the per-IP failed-auth threshold with a confined stale-password pattern, or spray detection in observe mode matched an IMAP/POP source. The spray message names IMAP/POP and the rule | Visibility finding only. No auto-block |
| `mail_subnet_spray` | Multiple distinct attacker IPs from the same /24 subnet exceed the subnet threshold | Entire /24 subnet blocked via nftables |
| `mail_account_spray` | Many distinct attacker IPs targeting the same mailbox exceed the account threshold | Visibility finding only. No auto-block, because attackers span many subnets and no single-IP action helps |
| `mail_account_compromised` | A successful login comes from an IP that repeatedly failed auth against the same mailbox, or follows failures on two or more mailboxes including another one, or on a missing one, or repeated failures on the same mailbox, the first at least an hour before the login | Critical findings block immediately. A source with established history on at least two other mailboxes from before its current untrusted failures emits a High advisory and is not auto-blocked. A login after failures on other mailboxes is Critical only in enforce mode when one of them was a missing mailbox many networks tried; every other spray case is a High advisory |

Tunable via the `thresholds.mail_bruteforce_*` keys in `csm.yaml`. Independent from the SMTP tracker so the Dovecot noise floor can be tuned separately. Infrastructure IPs are never counted or blocked. Established good sources with a confined stale-password pattern emit `mail_bruteforce_suspected` instead of an IP block, while wider spraying and compromise from a source without established multi-mailbox history still block. A compromise from an IP with established history on at least two other mailboxes from before its current untrusted failures remains visible as a High advisory but does not feed direct, incident, or spray auto-blocking. The `mail_bruteforce` and `mail_bruteforce_suspected` alerts name the mailboxes the source was hitting, with per-mailbox failure counts and a count of attempts that named no mailbox, so a real attack on a live mailbox is easy to tell apart from dictionary noise.

IMAP and POP logins share the long-memory spray detection described for SMTP above. One memory holds the failures and login trust of both, so failed SMTP and IMAP logins from one address on two different mailboxes count together toward the several-mailboxes rule. A login that follows failures on other mailboxes earns neither login trust nor good standing, unless the failures were all on one other mailbox that may exist and none on the login's mailbox, the address already held trust on the login's mailbox from before those failures or, for IPv6, another address of the same /64 holds aged trust on it. The slow brute-force block downgrades to `mail_bruteforce_suspected` only when the address holds good standing or aged login trust on every mailbox it failed on; a login to some other mailbox no longer counts. One address gets at most one `mail_bruteforce` per suppression period, and one login at most one `mail_account_compromised`. The High advisory for a login after failures on other mailboxes is raised once per address and mailbox per memory window, so a client that polls every few minutes does not repeat it. In observe mode the same limit applies to a login after a missing name that several networks tried.

A login identified as a short-window password crack revokes trust for that address and mailbox for the spray memory window, even when the compromise alert is suppressed; for an IPv6 address it revokes that mailbox's trust for every address of its /64. Account cache pressure does not hide a crack while its per-address failure history remains. Further SMTP, IMAP or POP logins cannot restore that trust during the window. Suspect logins do not count toward successful activity that exempts later failures. A crack also removes any good standing from a recent login that had not yet aged into established standing.

When the mail authentication backend itself fails (for example dovecot cannot reach `cpdoveauthd`), every login fails regardless of password. CSM detects a burst of these backend errors, pauses `mail_bruteforce` and `mail_subnet_spray` auto-blocking, keeps the failures out of spray evidence, and raises a `mail_auth_backend_degraded` warning so the outage is visible instead of mass-blocking legitimate users. IMAP and POP successes during this degraded period do not update spray memory, raise spray alerts, or earn good standing. The short-window compromise detector still uses recorded failures. Detection resumes automatically once the backend recovers.

Mail login attribution uses the connection fields outside the raw login name.
Names containing field-like text or angle brackets remain one account name.
Records without a usable remote address do not count toward IP blocking or
login trust. Reputation exemptions require a successful Dovecot login summary;
success wording in a failed login name does not qualify.

## Admin-Panel Brute-Force Tracker

Counts repeated POST requests to high-value non-WordPress admin login endpoints. Runs as part of the web access-log watcher.

Covered endpoints (tight set to avoid false positives on shared hosting):

- phpMyAdmin: `/phpmyadmin/index.php`, `/pma/index.php`, `/phpMyAdmin/index.php`
- Joomla: `/administrator/index.php`

When an IP crosses the POST-rate threshold, `admin_panel_bruteforce` fires and the attacker IP is auto-blocked.

Drupal `/user/login` and Tomcat Manager `/manager/html` are intentionally out of scope here. Drupal's path is too generic on shared hosting, and Tomcat Manager uses HTTP Basic auth (repeated GET requests with 401 responses), not POST form submissions. Both need different detectors and are tracked as follow-up work.

## PHP-Relay (Mail Abuse, cPanel Only)

Real-time inotify watcher on `/var/spool/exim/input` catches WordPress contact-form spam relays where an attacker uses PHPMailer (or similar) with a spoofed `From`, an external `Reply-To`, and a script URL that doesn't belong to the cPanel account. A contact-form relay incident drove the design: a legitimate site running a vulnerable contact-form plugin became a per-message spam relay through the operator's own mail account.

The detector runs five paths. Paths 1, 2, 2b and 4 fire `email_php_relay_abuse` (Critical) when one of them crosses threshold; Path 6 has its own findings, described below. Paths 1 and 2 are scoped per-script, using the `host:/path` from the `X-PHP-Script` Exim header. Path 2b is per cPanel user. Path 4 is per HTTP source IP across distinct scripts. Path 6 is per client IP across every script and account. Paths 2 and 4 use a recipient-diversity gate that suppresses only known low-recipient notification mail.

The source address is the final, server-observed address in `X-PHP-Script`.
Client-supplied forwarding text cannot replace it. Behind a proxy this is the
proxy's address; CSM does not recover a visitor address from untrusted forwarding
text. A missing or invalid final address leaves IP attribution empty.

The script label ends at the first ` for ` separator, keeping forwarding text
out of per-script counts and queue actions. PHP includes `PATH_INFO` in this
header without escaping separators. Paths containing a literal ` for ` therefore
share the label before that separator; the source address is parsed separately
from the header's end.

| Path | What triggers it | Why it exists |
|------|------------------|---------------|
| **Path 1: header score** | Per-script: `From` domain not in the account's authorised domains AND additional signal (PHPMailer / suspicious Reply-To / suspicious User-Agent), evaluated over a rolling 5-min window once the script has emitted at least `header_score_volume_min` messages | The shape that matched the original incident: spoofed sender, contact-form-style. `FromMismatch` is a HARD precondition -- the score never accumulates without it |
| **Path 2: absolute volume per script** | A single script emits at least `absolute_volume_per_hour` messages in the last hour. If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients suppresses this path; unknown recipients or `fanout_distinct_recipients: 0` fail open. | Catches a compromised script even if the headers themselves are legit-shaped, while leaving plugin notification mail to a fixed admin set alone |
| **Path 2b: account log-tail volume** | Per cPanel user: at least `effective_account_limit` messages in the last hour that the account's own processes submitted locally (PHP `mail()`, `sendmail`), each with at least one recipient outside this host's mail domains. The effective limit is auto-derived from `/var/cpanel/cpanel.config`'s `maxemailsperhour` (60% of it, clamped to 20-60), capped at 95% of the cPanel limit when an operator override is set | Backstop for when Path 2 misses the window. Reads `/var/log/exim_mainlog` directly and names the account only from Exim's own submission fields, so a subject or sender address cannot. Mail to the host's own mailboxes, bounces, authenticated SMTP and mail arriving from the network never count. If a present mail-domain file cannot be read, or both `/etc/localdomains` and `/etc/virtualdomains` are absent, nothing counts |
| **Path 4: HTTP-IP fanout** | Per HTTP source IP: one source IP appears in at least `fanout_distinct_scripts` distinct script keys in `fanout_window_min` minutes, after excluding loaded HTTP-proxy ranges, loopback, and the host's own interface addresses. If Exim envelope recipients are known, fewer than `fanout_distinct_recipients` distinct recipients outside each sending account's explicitly listed domains suppresses this path; subdomains are exempt only when listed for that account. Missing account-domain data, unknown or partially parsed recipients, or `fanout_distinct_recipients: 0` fail open. | Catches one client walking many scripts while avoiding CDN/proxy traffic, local cron or panel callbacks, and fixed-admin notification fanout, including one client commenting on several hosted sites |
| **Path 6: client recipient spread** | Per client IP: hosted sites mail at least `ip_recipient_spread` distinct recipients outside each sending account's own domains within `ip_recipient_window_hours`, counted across every script and account. An IPv6 client counts per /64. A message whose account domains cannot be read is not counted; a message whose recipients cannot be parsed counts as one new recipient. `ip_recipient_spread: 0` turns the path off. | Catches bots that submit a site's forms with strangers' addresses, so the site sends each stranger an automatic reply. One bot sends too few of these per script or per hour for the other paths to notice |

Path 2b reads recipients only from Exim's envelope recipient list. Message headers
and sender text do not supply recipients. A missing recipient list or a truncated
address cannot establish an outbound send. The host's mail-domain inventory is
refreshed once per minute; a missing optional file is allowed when the other file
can be read.

Path 5 (behavioural baseline) is deferred to Stage 2.

Per-IP paths skip selected shared addresses: CDN and website firewall edges (Cloudflare, QUIC.cloud, Sucuri) and payment gateway webhooks (Stripe, PayPal, Braintree, PayU, Revolut, Mollie). CSM ships this list built in, taken from each provider's published list. Membership is not proof that the target site chose the service. [Cloudflare Workers can make requests to third-party sites](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip-in-worker-subrequests), and [Sucuri can proxy requests before the site's DNS changes](https://docs.sucuri.net/website-firewall/configuration/testing-the-waf-before-changing-the-dns/). Traffic relayed through these retained providers remains exempt, including abusive requests.

Uptime monitors and cron services are not on the list. Anyone with an account there can schedule POSTs with any form body to any URL, so exempting their addresses would let a bot relay form spam through them, and the per-IP paths would miss it. Self-service CDNs such as Amazon CloudFront, Fastly and BunnyCDN are left out for the same reason: anyone can point a pull zone at any site and post through its edges. If you trust a specific cron service, or your sites sit behind one of those CDNs, you can add its ranges yourself, knowing that anyone with an account at that service can use them.

An `http_proxy_ranges.yaml` in `policies_dir` (`version: 1` plus a `cidrs:` list; a bare IP counts as /32 or /128) replaces the built-in list whole and reloads on SIGHUP. Without the file the built-in list applies. A file that cannot be read or parsed, has no `cidrs:` list, or has no valid entry keeps the last good list, which is the built-in one at startup. Invalid entries, including blank or null list items, are reported and skipped; valid siblings still apply. Only an explicitly empty list (`cidrs: []`) clears the proxy ranges. Load errors at startup or on SIGHUP raise `email_php_relay_policies_reload` (Warning). To extend the list, start from the built-in file in the CSM source, `internal/emailspool/embed/http_proxy_ranges.yaml`. Your file replaces the whole list, so later CSM updates to the built-in entries do not reach you until you copy them in again.

CSM 4.10.0 exempted Amazon CloudFront, Fastly and BunnyCDN; later releases do not. An operator file copied from the 4.10.0 list keeps them until you remove those entries and reload. Legitimate visitors of a site behind these CDNs share their edge's per-IP counts unless you exempt its ranges. For Path 6, review findings in `ip_recipient_mode: observe` before enforcing; this setting does not disable Path 4. Cloudflare remains separately exempt from Path 6 through the daemon's refreshed infrastructure list, even when omitted from the operator proxy file.

Netopia, EuPlatesc, Twispay, JCC and Adyen publish no source address list. If your shops use them, add their ranges yourself. Viva publishes a webhook address list; it is not built in yet, add it yourself.

Path 6 does not count a client on the proxy and payment list, a Cloudflare edge the firewall knows, a loopback or host address, or an `infra_ips` entry. It also skips mail sent from `wp-cron.php`, which mails whatever its trigger request queued, and staff: a client that sent mail through a WordPress admin page of the same account in the last 7 days. Every `.php` page directly in a `wp-admin/` directory counts as an admin page except `admin-ajax.php`, `admin-post.php`, `profile.php` and `index.php`, which logged-out visitors or subscribers can reach. The staff exemption covers only that account. Becoming staff, or an `ignore-script` for a script, also drops the recipients counted earlier in the window through that account or script.

Staff often mail customers without passing such a page, for example by completing orders with the quick actions of the WooCommerce order list. So when a client is about to cross the threshold, CSM reads the last 4 MiB of each involved site's current access logs (`/usr/local/apache/domlogs/<account>/<site>` and `<site>-ssl_log`). For a site starting with `www.`, it also checks the name with that prefix removed. Each distinct log is read once per crossing.

Access-log evidence requires a GET answered 200 on a recognized WordPress staff page, such as the post editor, the WooCommerce order list, uploads, comments, users, settings, plugins or themes. Both order lists qualify: the legacy one on `edit.php` and the HPOS one on `admin.php?page=wc-orders` (or `page=wc-orders--<order type>`). For HPOS, `page` must be the first query parameter so PHP's input limit cannot discard it. Public resources, setup pages, subscriber pages and every other `admin.php` page do not qualify. Requests with another parameter PHP would interpret as `page` do not qualify either. Encoded or ambiguous paths and extra path after the PHP filename do not qualify. The request must fall within the last 7 days, and the exemption expires 7 days after that request; rereading a log does not renew it. The client's address, or its IPv6 /64, becomes staff only on that account, whose mail stops counting; it is challenged only if the other accounts' mail still crosses the threshold. A missing or unreadable log is no evidence.

Path 6 has known limits:

- A plugin that handles POST requests in its `init` or `wp_loaded` hook without checking for a login, or for `DOING_CRON`, lets a visitor who is not logged in make it send mail by posting to an admin page or to `wp-cron.php`. That mail is not counted, and a post to an admin page also earns the client the staff exemption on that account.
- Behind a proxy or CDN that does not pass the client address to PHP, CSM sees only the proxy's address. A proxy on the list is skipped, so its visitors are never counted; that includes a bot that sends its requests through a CDN account of its own. A proxy missing from the list is counted as one client for all its visitors, so add its ranges to `http_proxy_ranges.yaml`.
- Path 6 names a form by its host in lowercase and its path up to the PHP file, so extra path after the file or a change of case does not split it, and one `ignore-script` with that name covers every such variant. Other names for the same site, such as with and without `www.`, still count as separate forms.
- Only WordPress admin pages count as staff evidence. Staff of other back offices, such as PrestaShop, OpenCart or Joomla, who send many order or account mails can be challenged and then blocked. Put a fixed office address in `infra_ips`.
- Counts live in memory and are lost when the daemon restarts. The startup walk sees only mail still in the queue, and form replies usually leave it within seconds.
- A bot that rotates addresses and keeps each one below the threshold is never challenged, and its form is not named.
- An IPv6 client is counted per /64 but challenged or blocked only at the one address that crossed the threshold.
- A script finding names the client that triggered it. Later clients through the same form in the window get their own client findings but are not added to the script finding.
- One stranger mailed many times counts once.

When a client crosses the threshold, CSM raises a High finding for it, once per mode per window. `ip_recipient_mode` sets what follows. In `observe` mode, the default, the finding is `email_php_form_relay_observed`: it goes to the daily summary and never challenges or blocks, so you can review it before switching on enforcement. In `enforce` mode the finding is `email_php_form_relay` and the client is sent to the [challenge page](challenge.md); a client that does not solve it within 30 minutes is blocked while `auto_response.enabled` and `auto_response.block_ips` are on. With the challenge off, the client is blocked directly under the usual `auto_response` settings. `auto_response.php_relay.dry_run` applies only to the mail freeze and does not hold this response.

After a reload from `observe` to `enforce`, the next eligible message can trigger enforcement using recipients still in the window. The earlier observe report does not delay enforcement. Switching back to `observe` prevents new responses from retained findings, queued blocks, challenge timeouts and central corroboration. Existing challenges and blocks keep their expiry.

CSM also raises `email_php_form_relay_script` (High) for each script that sent at least two of that client's outside recipients, once per script per window. It names the account and the form to fix: add a captcha, or turn off the automatic reply to the submitter. For a legitimate bulk sender, use `csm phprelay ignore-script`. This finding has no source address field and never challenges or blocks. If the client table fills up, CSM drops the clients with the fewest recipients first and reports `email_php_form_relay_table_full` at most once a day.

The detector starts a one-shot retrospective scan of `exim_mainlog` at daemon startup so Path 2b can fire on history already on disk. `IN_Q_OVERFLOW` triggers a bounded recovery walk of the spool (capped at 1000 files; if more were skipped, a `email_php_relay_overflow_scan_truncated` Critical fires too -- Path 2b backstops the missed messages).

Operator suppressions (`csm phprelay ignore-script <host:/path>`) short-circuit the pipeline before any path scoring runs, so a known-noisy contact form can be opted out individually without disabling the detector. An ignore on a lowercase `host:/path` ending at the PHP file also covers that file reached with extra path after it or a different host case. See [PHP-relay CLI](cli.md#php-relay-mail-abuse-cpanel-only) for the full operator surface.

## PAM Brute-Force Listener

Real-time authentication monitoring through the PAM module.

- SSH login tracking with geolocation
- SSH failures (`service=sshd`) drive `pam_bruteforce` and credential stuffing / password spray breadth: one source IP failing against many distinct accounts inside `thresholds.multi_ip_login_window_min`. The finding is `credential_stuffing`; tune the account floor with `thresholds.cred_stuffing_distinct_accounts` (default 5).
- Only successful sshd logins clear SSH failure counts.
- Failures from other PAM services (FTP, mail, webmin and similar) raise `pam_auth_failures` once per window above `thresholds.pam_bruteforce_threshold`. It never blocks: CSM reads pure-ftpd, Dovecot and Exim logs separately, and counting one login twice would corroborate it with itself. Services without such a log detector, such as vsftpd, proftpd or webmin, have no blocking signal from PAM.
- Blocks IPs within seconds of threshold breach
- Integrates with the nftables firewall for instant blocking

## Process Context

Exec and outbound-connection findings carry an optional `process` object with
PID, PPID, UID, user, cPanel account (when known), comm, exe, sanitized cmdline,
and a parent chain up to depth 5. The chain is materialized from an in-memory
LRU+TTL cache (cap 16384 entries, 30-minute TTL) populated from BPF exec
events. Cache misses trigger a bounded async `/proc` read, so process-context
enrichment does not add blocking work to the connection event loop. When
neither cache nor enricher has data (e.g., a process that exited before
userspace reads its event), the `process` field is omitted entirely and the
finding still emits.

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

- `started_at` is emitted only when the event source supplies a trustworthy
  start timestamp. CSM does not infer it from procfs directory metadata.
- After daemon restart, the `csm_process_context_enrich_*` counters may show a
  small `enqueued - reads` delta. Pending requests in the enricher queue are
  dropped on shutdown by design.
- Hosts without BPF support fall back to `/proc/net/tcp[6]` polling. That path
  has no PID, so emitted findings do not carry a `process` field.

## HTTP Flood, Scanner Profile, UA Spoof, and Distributed Flood

`http_request_flood`, `http_scanner_profile`, `http_claimed_bot_unverified`, `http_ua_spoof`, and `http_distributed_flood` are **periodic**, not real-time. They run inside the same `wp_bruteforce` scheduled check that scans per-vhost access logs every 10 minutes. A real-time inotify tailer would need to hold per-IP state across log rotations and is out of scope for the initial release (see the plan non-goals). For attack types where sub-minute response matters, the access-log inotify watcher already covers wp_login_bruteforce and xmlrpc_abuse; the periodic scan adds volume-based rate enforcement, pending claimed-bot handling, scanner-profile detection, and per-vhost distributed attack rollups on top.

Requests that a cPanel proxy subdomain (`cpanel.`, `webmail.`, `whm.` and similar) passes through the web server to the panel are skipped by the web detectors, realtime and periodic, when cPanel's own central access log records them as proxied. The panel's own access log carries those requests, so a busy cPanel or webmail session through a proxy subdomain does not count as web traffic, and one request does not count as two kinds of evidence. Requests in a per-site log, or in a log chosen through `web_server.access_logs` that is not one of cPanel's own access logs, always count as website traffic.

Web counters use the request and timestamp written by the web server, including requests with Basic authentication usernames and quoted header values. For periodic client attribution, `web_server.trusted_proxies` and `challenge.trusted_proxies` together enable X-Forwarded-For from a configured remote proxy; the log format must record it immediately after User-Agent, optionally preceded by a vhost in `host:port` form. Trust only proxies that append their observed peer or replace untrusted input with that address; trusted ranges must not include visitors. The client is the first address from the right that is not a trusted proxy. The parser keeps complete tokens at the right end, so discarded client text to the left cannot name a client. If no client survives, including when the retained end contains only trusted proxies, the request is not counted against anyone. A listed address is never counted as a client, even where its header is not trusted.

Realtime checks read the connecting address, not X-Forwarded-For, and act only on a bare address in its canonical form. When that address is a configured trusted proxy, in `web_server.trusted_proxies` or `challenge.trusted_proxies`, the WordPress, XML-RPC and admin panel checks skip the request, ModSecurity denies and warnings stay visible without escalating, and cPanel API auth failures are not reported. The scheduled ModSecurity audit scan does not report it either. Other cPanel audit and login findings stay visible without blocking or scoring the proxy, and supply no automatic response forecast. A listed address is skipped even where its forwarded header is not trusted, such as an address of this host. The web server must log the connecting peer, not a forwarded client, in that field.

A verified crawler is dropped from the scan before any counter increments: a source IP whose claimed bot User-Agent passes IP-range or reverse-DNS verification cannot contribute to a flood, scanner, or spoof finding, so verified Googlebot and AI crawler traffic does not produce false positives. Verification is covered in [Threat intel](threat-intel.md#verified-crawlers).

| Finding | Fires when | Key gates (defaults) |
|---------|------------|----------------------|
| `http_request_flood` | One source IP makes too many requests inside the rate window | `http_flood_threshold` requests within `http_flood_window_min` (5 min). Ships disabled (`0`) so operators sample baseline traffic first |
| `http_scanner_profile` | One source IP's in-window traffic is almost all probe-error responses spread across many distinct paths, the shape of URL enumeration hunting for backups, downloadable files, and dormant shells | Three gates must all pass: `http_scanner_min_requests` volume (ships `0`, disabled), at least `http_scanner_error_pct` (90) of requests on a probe-error status, and `http_scanner_min_distinct_paths` (10) distinct error paths. Probe-error statuses default to 404 and 403; query strings are stripped so cache-buster URLs on one missing endpoint count once |
| `http_ua_spoof` | One source IP sends non-browser User-Agents | Known scanner agents (nikto, sqlmap, nmap, wpscan, nuclei, and similar) fire on the first hit. Claimed crawler UAs with a cache-confirmed reverse-DNS negative, scripting (curl/python/wget), headless (Puppeteer/Playwright), and empty agents fire at `http_ua_spoof_threshold` (30); scripting/headless/empty still require their opt-in flags (`http_ua_scripting_enabled`, `http_ua_headless_enabled`, `http_ua_empty_enabled`) |
| `http_distributed_flood` | Many distinct already-abusive source IPs hit one vhost in a single scan window | Opt-in: fires once `http_distributed_min_ips` distinct IPs (sample 10), each having already crossed a per-IP abuse threshold above, hit the same vhost. Built only from IPs that tripped another finding, so a popular site's normal visitor spread does not trip it |

Per-IP findings roll up per vhost, so a confirmed scanner that sprays a few probes across many vhosts still feeds the distributed rollup. Full threshold reference and tuning notes are in [Configuration](configuration.md).

## Direct SMTP Egress

Outbound connections to SMTP ports from non-MTA local processes
emit a `direct_smtp_egress` finding. See
[Direct SMTP egress](direct-smtp-egress.md) for the full rule set,
config schema, and metric.
