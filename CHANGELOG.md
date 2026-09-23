# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 3.40.0 are archived: [3.30 to 3.39](docs/changelog/3.30-3.39.md), [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [Unreleased]

### Fixed

- The incident timeline, UI audit log, threat event, top attacker and ModSecurity event APIs now say when entries were left out, and the incident timeline no longer reports its page size as the total.
- Importing an exported state bundle works again, temporary whitelist entries stay temporary, and clearing cPHulk login history reports a failure instead of claiming success.
- Icons that showed blank, on the ModSecurity and Hardening firewall links and a Settings header, now display.
- Shared Web UI formatting helpers no longer pass an unreadable time or a non-number through as raw text, and a zero value is no longer shown as blank.
- Email Security findings with details now have an expand button that shows them; the details rows were built but could never be opened.
- A panel that fails to load now shows what failed, why, and a Retry button on every page. Retry on the Rules stats, firewall status and Threat Intel panels reloads them in place instead of breaking the panel or reloading the page.
- Threat Intel now names every attack type in its lookup badges, such as Reconnaissance and Known Malicious IP, using the same labels as the dashboard chart.
- An unrecognised severity now shows as Unknown on every Web UI page instead of being labelled Warning on some of them.
- The Web UI live-updates indicator now keeps saying Reconnecting while it retries after a dropped connection, instead of switching back to Connecting on each attempt.
- Web UI keyboard focus now survives refreshes and dialog transitions, and finding shortcuts follow the focused row without acting behind dialogs. Warning text, dashboard indicators and command palette hints are readable in both themes, and the skip link keeps a visible focus indicator.
- On a phone the Web UI header now wraps instead of running off the screen, and on a desktop the ModSecurity apply bar no longer covers the sidebar.
- Web UI widgets now report their role and state to screen readers: Firewall subviews are keyboard-navigable tabs, dashboard charts carry text descriptions, History expand buttons say whether details are open, and the connection-lost banner can be dismissed until the next outage.
- Every Web UI page now starts with a Skip to content link, and section headings follow the page title in order so screen reader users can move through the page outline.
- The light theme now covers the login page, the command palette, the undo banner and chart tooltips, and the chosen theme still applies when the browser blocks site storage.
- Status text, badges, toasts and chart labels in the Web UI now meet the WCAG AA contrast ratio in the light theme; orange, yellow and green were hard to read on white.
- Screen readers no longer read whole lists and the refresh clock aloud every time a Web UI page refreshes; only short status messages such as errors and connection changes are announced.
- Row checkboxes, rule switches, icon-only buttons and search fields in the Web UI now have names that screen readers announce, instead of relying on placeholders or icons.
- Closing the detail panel or a dialog now returns focus to what opened it, a dialog opened from the detail panel keeps the keyboard to itself, and the prompt dialog closes with Escape and keeps Tab inside.
- Refreshing pages now preserves ongoing edits and actions, keeps ModSecurity exclusions consistent, and updates the visible history and refresh timestamp. Detail panels ignore stale responses, and confirmation dialogs retain safe focus and button labels.
- A suppression created from a finding whose file name contains glob characters such as brackets now matches that file; the pre-filled pattern treated them as wildcards and hid nothing.
- Web UI caches now notice replaced assets and history changes, and compressed files respect client encoding preferences and header-only requests. History searches keep matching records, and limited findings stay ordered by severity even when every row fits.
- Table date filters no longer slow down on long lists, because each date is converted to the preferred time zone once instead of once per row.
- Web UI date filters now handle midnight clock changes and server time-zone overrides correctly, and preference saves reload only when the browser can retain them. Account views follow recorded owners and linked roots, limited email lists report omissions, refresh timers keep their deadlines, and performance fixes use current targets without overlapping.
- Importing a settings bundle now skips suppression rules whose check is not a check name or whose path pattern is not a valid glob, as the suppression form does.
- Suppression rules now refuse a check field that holds a pattern or free text, and warn when the check name matches no known check, since such a rule hides nothing.
- A hardening audit that runs longer than three minutes now returns its report instead of failing after saving it.
- Block, allow, remove-allow, cPHulk clear and unban now record an IPv6 address typed in any spelling under its canonical form, so audit entries and incident records match the firewall state.
- The scan jobs API now rejects request bodies with unknown fields or more than a few kilobytes, so a misspelt option no longer starts a scan without it.
- The History CSV export now applies the date range, severity and search shown on the History tab, so narrowing the filters reaches entries older than the newest 5,000. The button no longer claims to export the full history.
- The history API now reports truncated as true when more matching findings exist past the returned page. It was always false.
- Findings, dashboard account counts and the findings API now attribute a finding to the account its check recorded before guessing from paths in the message, so mail relay findings count against the sending account.
- The Account page and the scan account list now find accounts under every account root of the platform, including Plesk vhosts, and the Account page lists quarantined files from the configured quarantine directory.
- The incident groups API now filters by a status given in any letter case. Before, a status such as Open was accepted but matched no incidents.
- The dashboard now shows a scan in progress for every scan the daemon runs, including scheduled scans, command-line checks and scan jobs, not only scans started from the web UI.
- The health API and dashboard now count log watchers that start after the web UI, such as one waiting for a log file to appear, instead of the count at startup.
- Date filters on the Findings history, Email, Audit, Quarantine, Account and Threat Intel pages now mean days in the time zone preference. The history and email APIs accept an RFC 3339 range end as exclusive and reject a date they cannot read with 400 instead of ignoring it.
- Dates on the Firewall, Hardening and Browser sessions pages now follow the time zone preference. The firewall audit API reports its timestamps as RFC 3339 instants in UTC.
- Dates now use the saved time zone preference from the first render of a page, and changing the time zone re-renders the page. Before, a page could show dates in the browser zone until it was reloaded.
- The "Server time" display preference now shows the server's own time zone. It always showed UTC because the page was never told the server's zone.
- Pages opened in a background tab no longer double their refresh traffic when first shown, returning to a tab no longer reloads everything while auto-refresh is paused, and the Dashboard idle watcher list stays open across refreshes.
- Grouped findings stay grouped while searching, filtering or sorting, and a collapsed group stays collapsed. The group headers used to pile up at the top of the table after a search.
- On the Performance page an open Bulk fix menu no longer closes by itself every few seconds, and a fix that is still running cannot be started a second time.
- The Firewall and Threat Intel links from a ModSecurity block now open the lookup for that address instead of an unfiltered page.
- A failed incident status change or incident block now tells the operator why instead of failing silently.
- Searching or filtering the firewall audit log now covers the whole log. Filters ran only over the newest page of entries, so an address blocked earlier was reported as never blocked.
- The Email page action groups, auth-failure clusters and outbound relay abuse no longer come back empty or incomplete on a busy server. Unrelated findings, or findings newer than the chosen dates, used up the scan budget before the matching ones were reached, and a list that is cut short now says so.
- An expired or revoked browser session now returns the page to the login form instead of showing Unauthorized errors. The connection-lost banner appears only when the daemon cannot be reached, and a daemon restart no longer floods the page with repeated error messages.
- Tables that reload their data, such as the rules, ModSecurity and incident lists, no longer show stale duplicate rows after a reload, an apply or a filter change.
- Dates in the Web UI no longer turn into "3h ago" a minute after a page loads. Only times shown as relative are refreshed, so absolute dates, account history rows and exports keep their content, and an expiry still ahead reads "in 3h" instead of "just now".
- Undoing a dismissal preserves later operator decisions and restores alerting for findings first received in real time.
- Cleanup file selection counts and controls now follow pagination and filtering.
- Failed ModSecurity rollbacks are reported as failures in both the response and audit history.
- Suppression rules added, removed or imported at the same moment are all kept. Each change rewrote the whole rule set, so simultaneous changes silently dropped each other while every one reported success.
- A quarantined file that bulk delete cannot remove now stays listed and the page says so. Its metadata used to be removed anyway, which hid the file from the list so it could neither be deleted again nor restored.
- A quarantine restore that fails partway, for example because the account is over quota, no longer leaves a partial root-owned copy at the original path. That copy hid the entry from the quarantine list and made every retry fail.
- Dismissing a finding no longer claims it can be restored. The Findings page now says a dismissal stops alerts while the finding is unchanged and that a later scan can list it again, offers undo for 30 seconds, and dismisses a bulk selection as one action that one undo reverses.
- Select-all on the Cleanup file backups and the Threat Intel attackers table no longer reaches rows on other pages or hidden by a search, so a permanent delete, permanent block or whitelist acts only on the rows on screen.
- The deep scan no longer sends every file it reads to the PHP analysis worker. Files that cannot hold a remote-code flow are ruled out in the daemon, so images and plain text no longer queue behind real analyses, start the worker, or count as unexamined while it is unavailable.
- Deciding whether a written file sits under an account or document root, which the real-time monitor does for every watched write, is much cheaper.
- A rules download or package upgrade that leaves the rules unchanged no longer queues a full rescan of every file on the host. On hosts with a rules download URL set, the unchanged download rewrote the installed rules daily and after each restart, each time queuing a full rescan and a warning finding.
- A rules file reached through a symbolic link is now watched by the file it points to, so updating it queues the rescan that new rules need. A rules file that cannot be read, or is replaced while being read, keeps its last known contents and is retried.
- Real-time signature scanning costs a fraction of the CPU it did. Each rule pattern now runs only on files containing text it cannot match without, and a pattern shared by several rules runs once per file; what matches is unchanged.
- Judging an executable written to a temporary directory no longer walks the process tree when nothing about the host could lower the severity. On a server with no package transaction running and no control panel installed, the walk was pure cost on every such write.
- Process ancestry is available before file monitoring starts, including on hosts without kernel monitoring. Starting the optional process cache no longer races with ancestry readers.
- Nightly control panel maintenance no longer pages as a system compromise. A cron drop-in or a staged executable written by the panel's own scheduled work is reported as a Warning instead of High or Critical, recognised by the program a parent process is actually running rather than the name it reports. Nothing is skipped, and a cron file carrying persistence tokens still reports at full severity.
- The scheduled cron.d comparison now scores a changed or new file the same way the realtime write detector does. It was the one cron path with no provenance rescoring and no check for persistence tokens, so a vendor cron update reported High there while the same write was a Warning.
- Sensitive-file findings are rescored using process ancestry on every Linux host. Until now that evidence was only read on hosts running the optional kernel monitoring, so the same write scored differently depending on the build.

### Security

- Web UI activity tracking and request checks now keep idle sessions from lingering while preserving normal operator actions. Certificate renewal preserves working keys and operator-managed files, and IPv6 rate limits handle scoped addresses consistently.
- The self-signed Web UI certificate is now renewed automatically before it expires and served without a restart; a certificate installed by the operator is never replaced, and replacing its files takes effect without a restart.
- The Web UI's Content-Security-Policy now also forbids plugins, <base> tags, framing and form posts to other sites, and the legacy browser XSS auditor, which could be abused to disable page scripts, is turned off.
- CSRF tokens are now bound to the browser session instead of shared by every browser until the daemon restarts, and a form token is accepted only from the request body, not the query string.
- A loopback origin such as https://localhost:9443 is now trusted only when it is the origin the request was sent to, so another local web service in the same browser can no longer make authenticated requests to the Web UI.
- Startup, csm validate and csm doctor now warn about Web UI and metrics tokens shorter than 32 characters, since they can be guessed; such tokens keep working.
- A flood of requests from many new addresses no longer makes each request scan the whole rate-limit table; a full table is trimmed once for many new addresses.
- Login and API rate limits now count an IPv6 client by its /64 prefix, so rotating addresses inside one prefix no longer multiplies the allowed attempts.
- The /metrics endpoint is now rate limited per client address like the API, so its token cannot be guessed at unlimited speed.
- Background polling by an open page no longer extends a browser session, so a dashboard left open now logs out after the idle timeout; page loads and requests that follow operator input still count as activity.
- The incident timeline CSV export now writes cells that start a spreadsheet formula as text, like every other export.
- Settings validate the effective credentials from configuration drop-ins before changing a service address.
- Failed quarantine restores preserve files replaced by another writer and remain retryable after storage or destination changes.
- Audit entries retain the administrator who authorized an action even when a session ends before completion. Large bulk actions no longer hide later audit entries.
- The UI audit log now names the credential behind each action and records actions it used to miss: email quarantine release and delete, database object restores, ModSecurity rule changes, subnet blocks, allow-rule removals, cPHulk clears, bulk fixes, incident status changes, scans, logins, logouts and session revocations. An audit entry that cannot be written is now reported in the daemon log, and log rotation no longer loses history under concurrent writes.
- The Settings page can no longer set the ModSecurity reload command, the rules and overrides file paths, the WP-Cron PHP binary, the clamd socket, the mail log and country database paths, or any environment variable name. A web UI session could use them to run commands or write files as root; they are now shown read-only and change only in csm.yaml.
- A suppression rule that hides every finding of a check now has to be chosen explicitly. Leaving the path empty on the Findings or Rules page, or in an API request, used to create such a rule silently and stop all remediation for that check; a malformed path pattern, which never matched, is now refused as well.
- Changing the rspamd or upstream threat-intel address in Settings now requires entering its credential again, so a web UI session cannot send the stored credential to an address it chose.
- The scheduled PHP content scan no longer skips a file that was edited in place with its size kept and its modification time set back; the change time, which cannot be set that way, is now compared as well. After upgrading, each PHP file is read again the next time the scan visits it.
- Cron findings containing known persistence patterns now retain their severity during maintenance, including when the payload is encoded.
- Control-panel provenance now requires a resolved executable even when process details come from the cache. Live cron writes containing persistence tokens retain their original severity during maintenance.

### Changed

- **Breaking:** API routes that return a list now answer an object with the list under `items`, next to `total` and, where the list is paged or capped, `offset`, `limit` and `truncated`, instead of a bare array or a route-specific key. An empty list is `[]`, never null, and `/api/v1/incidents` always answers one page with its total.
- **Breaking:** API actions now answer `"ok": true` with their fields instead of `status` verbs or `success` flags (`success` stays on the firewall check and unban routes for existing callers). An action that did not happen, such as a fix that did not apply, an undeliverable test alert, a failed rule reload, a batch where nothing changed or an unknown rule or session, answers with an error status instead of 200.
- **Breaking:** read-only API routes that ran for any HTTP method now answer 405 to anything but GET.
- **Breaking:** every API failure, including CSRF, origin, rate-limit and wrong-method refusals, now answers with a JSON `{"error": ...}` body, and an unknown `/api/` path answers 404 instead of the dashboard page. Changing the status of an unknown incident answers 404.
- Whitelist and temporary whitelist now list the cPanel login history flush they perform, as Unblock & Clear already did.
- The Web UI server now checks at build time that the firewall offers every action the pages use, so a renamed firewall method can no longer turn an action into an error or a skipped step.
- The Web UI now ships Chart.js 4.5.1, Tabler 1.5.1 and Tabler Icons 3.48.0, with the icon font in WOFF2 only and no references to source maps it does not ship.
- The Web UI's shared script is split by purpose and every script keeps its helpers to itself, so scripts can no longer clash over names; scripts stay within ES2019.
- Removed unused Web UI and Web UI server code, including a read-only sidebar variant that no page could show, since every page needs an admin credential.
- Quarantine is now the one list of file backups: it shows pre-clean backups with their type and the live state of the original path, and filters by type. Cleanup History keeps the database object backups and links to it.
- The History tab now pages with the same first, previous, next and last controls and summary as the Incidents lists.
- The Findings select-all box now shows a partial state when only some visible findings are selected, as the other bulk tables do.
- Web UI layout fixes: stat cards and incident filters size to their content, whitelist and allow buttons use the warning colour, grouped incidents filter on every status, and the History tab offers 25 to 200 rows per page.
- Web UI pages now carry the same name in the sidebar, the browser tab and the heading, the product is named Continuous Security Monitor throughout, the Firewall page calls its whitelist mode Whitelist, and the old /blocked address redirects to the Firewall page.
- The Refresh button now reloads each page's data in place instead of reloading the whole page on some of them, and asks before discarding unsaved Settings, Verified Bots or staged ModSec rule changes.
- The Web UI header now says when the page's data was last loaded instead of when any request last succeeded, and shows the auto-refresh pause button only on pages that refresh on a timer.
- Web UI error notices now stay until closed instead of fading after five seconds, the same error is not stacked, and failure messages no longer read Error: Error:.
- Dashboard triage entries now open the finding they list, and the 24h severity counts open the History tab for exactly the last 24 hours; an open finding is kept in the page URL so the link reopens it.
- Confirmations for actions that delete data, block traffic, turn protection off or end sessions now show a red button named for the action and start on Cancel, and logging out every browser session asks first.
- The Web UI sidebar now groups Rules, ModSec Rules and Verified Bots with Settings under Configuration, and the ModSecurity page drops its tab that only linked to the rule manager.
- ModSecurity escalation exclusions are now managed only on the ModSec Rules page, which lists and edits them even when rule management is not configured, and each change affects one rule instead of rewriting the whole list.
- The whitelist is now managed only on the Firewall page under Allow Rules; Threat Intel keeps its whitelist actions and links there, and the two IP lookups link to each other.
- Filtered history requests, including the Email findings tab, now skip stored entries that cannot match the severity, check or search filter before decoding them, which makes them much faster on large histories.
- The list of saved database object backups now sorts in linear-logarithmic time, so hosts with many backups load Cleanup History faster.
- The scan job findings API now returns 500 findings per page by default and at most 5000, and reports when more pages exist, instead of every finding of a large job in one response.
- The ModSecurity blocks view no longer slows down sharply when many escalated addresses and many block rows coincide.
- Web UI API responses are sent as compact JSON, which makes large lists such as findings and history noticeably smaller.
- The audit page and incident timelines now read the UI audit log from the end and stop once they have the entries they show, instead of parsing the whole log each time.
- The quarantine list no longer hashes every quarantined file and its live copy on each request; a pair is compared again only when either file changes.
- Filtering, sorting and searching long tables no longer slows down with the number of rows squared.
- The dashboard now receives only the findings it shows, most severe first, and the Findings page checks for changes with a short version string every 15 seconds instead of downloading the full list.
- Web UI pages now link scripts and styles with a content version, so browsers cache them for a year and still load the new files after an upgrade; text files are sent gzip-compressed.
- Dashboard statistics, the findings timeline and the email workbench lists are now computed once per history change and shared by every open page, instead of reading a day of history on each refresh.
- The dashboard component list now reads when each watcher last reported from a small index kept with history, instead of decoding up to a week of history on every refresh, and keeps that time after history retention removes the finding.
- The status API no longer reads the whole daemon binary on every request to report its hash; it hashes the binary again only when the file changes.
- The web UI now samples host metrics only when the Performance page asks for them, at most once every ten seconds, instead of every ten seconds for as long as the daemon runs.

### Added

- Findings, Dashboard and Incidents now react to new findings as they are dispatched, over the Web UI's event stream, and their timed checks slow to a once-a-minute safety net while the stream is connected.
- Finding and incident rows, finding group headers and sortable table headers now work from the keyboard, sorted headers report their order to screen readers, and on Findings o or Enter opens the finding selected with j and k.
- Correlated incidents can now be selected and marked contained, resolved or dismissed together; the change stops at the first failure and reports how many were updated.
- A finding that reports an attacker address, such as a brute-force source, can now be blocked from its detail panel, as an incident can; other findings do not offer Block.
- Findings can now suppress a selection at once, creating one rule per selected file; findings that name no file are skipped so a check-wide rule is never created in bulk.
- The account page is now linked from the finding detail, account groups on Findings, incident detail and the accounts targeted in a Threat Intel lookup, and the command palette opens an account typed by name and lists Sessions.

### Removed

- **Breaking:** `POST /api/v1/rules/modsec-escalation`, which replaced the whole escalation exclusion list without checking rule IDs, is removed. Use `POST /api/v1/modsec/rules/escalation` to change one rule at a time.


## [3.43.0] - 2026-09-22

### Highlights

- This release is about what CSM costs the machine it protects. On a host where the watched paths share one filesystem, the real-time monitor receives an event for every write on the server, and several parts of the daemon did more work per event than they needed to.
- Stopping the daemon no longer waits for its real-time backlog. A busy host used to spend the whole systemd stop timeout draining queued scans and was killed at the end of it; the drain is now bounded and in-progress scans still finish.
- Recovery after an event storm no longer feeds the storm. Rescans ran on top of each other, competing with the workers whose backlog caused them, which produced more dropped events; they now run one at a time under a time budget and resume where they stopped.
- Scheduled and account scans share one concurrency budget sized from the machine's core count, and the service unit yields CPU to the web server and database under contention. A scan started from the Web UI during a scheduled one no longer doubles the load.
- Writes in the shared temporary directories are judged as the event arrives instead of being queued first. Session files and package working files no longer occupy the real-time queue to reach a verdict of nothing to report; executables, PHP and configuration files are analysed exactly as before.
- The startup log now describes the watch scope that was actually applied, including when a watched path sits on the same filesystem as `/`, and two new metrics show how many delivered events survive the path filter.
- Notice after upgrading: events still queued when the shutdown budget expires are covered by the next deep scan rather than at shutdown, and the temporary-directory filter is new. Read the first day of findings rather than dismissing it.
- Contention profiles from the optional debug endpoint are no longer empty, which is what a CPU investigation on a live host needs.

### Fixed

#### Real-time monitoring

- Stopping the daemon on a busy host no longer waits for the whole real-time scan backlog. The drain has a time budget for starting queued scans, and scans already in progress still finish before shutdown.
- Recovery rescans after an event storm no longer pile up on each other. They run one at a time under a time budget, resume where they stopped, keep their original coverage window, and retry once the storm ends.
- Writes in the shared temporary directories are judged when the event arrives instead of being queued for content analysis first, while executables, PHP, configuration files and staged copies of them are still analysed as before. Earlier detection and suppression decisions are preserved, including writes retained for self-deleting-file tracking.
- The monitor shares one watch per filesystem instead of marking the same filesystem once per watched path, and reports the scope it actually applied, including bind mounts, partial watch failures, and whether a watched path sits on the same filesystem as `/`.
- New counters distinguish events the kernel delivered, events queued for analysis, and events dropped by a full queue, so the cost of a wide watch scope is visible.
- The real-time scanner sizes its worker pool from the machine's core count instead of never dropping below four workers.

#### Scans

- Scheduled and account scans share one concurrency budget sized from the machine's core count, so a scan started from the interface during a scheduled one no longer doubles the load. A check still running after its caller gave up keeps its slot until it exits.
- Both the packaged and the installer-generated service units now yield CPU to the web server and database under contention, without capping what the daemon can use on an idle host.

#### ModSecurity

- The rule-action registry no longer re-detects the web server and reparses every vendor rule file every few minutes. It checks the rule tree for changes first, and keeps re-detecting only while no rules have loaded.
- Rule-action refreshes recover after an empty startup or missing vendor rules, and pick up replacements that preserve timestamps or use linked files. Transient read failures are retried, and rules appended during a refresh are picked up on the next check.

#### Health and diagnostics

- The mutex and block profiles served by the optional debug endpoint were always empty, because the daemon never turned on the sampling they need. They now record while the endpoint is enabled, and stop when the last listener exits.
- The daemon no longer hands systemd's notification socket to the commands it runs. Every one of those children could write to it, and systemd logged each attempt as a rejected notification from the wrong process.
- An unresponsive systemd notification socket no longer blocks daemon startup, status updates or shutdown indefinitely.
- The public documentation site stopped rebuilding after the Go version moved forward, because its workflow repeated the version instead of reading it from the module file.

## [3.42.0] - 2026-09-21

### Highlights

- Upgrade recommended: the deep scan for obfuscated and suspicious PHP content reported nothing at all on busy shared hosts. It ran out of its time budget every cycle and discarded everything it had found until that point, so droppers and webshells in the directories it covers went unreported.
- Several filesystem scans ran only when a signature update happened to force a full sweep: the index that spots new files, webshells, .htaccess injection, phishing content, setuid and backdoor binaries, and web-downloadable backups. They were treated as covered by the realtime monitor, which reports neither a file renamed into place nor a setuid bit being set.
- Expect more findings after upgrading, and read the first cycle rather than dismissing it. Setuid binaries and web-exposed backups had no coverage at all, so whatever is present has been accumulating.
- Scans that keep their own refresh interval no longer clear findings on the cycles they skip, and a scan cut short no longer discards what it had already found.
- Much less noise: hidden working files in the shared temporary directories, the same file reported twice where those directories share a filesystem, an account reaching its own memory limit reported as machine-wide exhaustion, false scan warnings on templates and data files, and suspended accounts counted as databases the scan failed to read.
- The mailbox password audit runs on its interval again instead of re-verifying every mailbox on every scan.
- CSM is now built with Go 1.27.

### Security

- The deep scan for obfuscated and suspicious PHP content reported nothing on busy shared hosts: it ran out of its time budget every cycle and everything it had found until then was discarded, so droppers and webshells in scanned directories went unreported. What a scan finds before it runs out of time is now reported.
- Deep PHP content scanning now spends one file budget per cycle across the host instead of one per account, and takes accounts least-recently-covered first. Accounts late in the alphabet were never reached on hosts with many accounts.
- While the realtime file monitor is attached, the scan that indexes files to spot new ones was skipped as covered by it. The monitor never reports a file renamed into place, so those files were never indexed and the baseline they are compared against stopped being refreshed until a signature update happened to force a full scan.
- The deep scans for webshells, .htaccess injection, phishing content, setuid and backdoor binaries, and web-exposed backups were skipped for the same reason, so they too ran only when a signature update forced a full scan. The monitor reports neither a file renamed into place nor a setuid bit being set, so these now run on every deep cycle, with the exposed-file scan on a longer interval because it confirms a finding by requesting the file from the site.
- A file written to disk was left unscanned by the realtime rule engine when its content was too large to send to the scanner in one message, even though the scanner could have opened the file itself. Padding a dropper past that size kept it from being scanned on write. The retry now inspects the exact bytes the write event carried rather than reopening the path, so a file swapped between the write and the retry cannot change what is scanned, and the evidence in the alert describes what was actually examined.
- PHP analysis now retains coverage for code embedded in binary content. PHP emits anything outside its tags verbatim, so a binary header cannot establish that executable code later in the file is inert; files that cannot be analyzed stay visible as coverage gaps and keep their earlier findings.
- Checks that keep their own refresh interval reported nothing on the cycles in between, which read as a completed scan, so the weak mailbox passwords and forwarder findings from the cycle that did look were cleared until the next one. A skipped cycle now says it skipped, its warnings stay visible, and the earlier findings remain.
- The mailbox password audit re-verified every mailbox on every scan instead of on its interval, because hashes it can never audit counted as unfinished work. Those are now reported separately and no longer hold the audit back, while a temporary verification failure still retries.
- Suspended accounts are no longer counted as WordPress databases the scan failed to read. Their database users are locked while the account is suspended, so every scan reported coverage it could never obtain.
- Incomplete filesystem and content scans now keep earlier alerts when accounts or files cannot be read or a candidate limit is reached. A failed exposure scan can retry on the next cycle instead of waiting for its normal interval.
- A canceled PHP scan that finishes late can no longer restore outdated clean-file records over a newer scan, and a partial scan discards outdated records after a detection or read failure. Periodic rescans also refresh files reached only by rolling coverage, and storage failures no longer let one account prevent others from being scanned.
- Repeated deep scans keep alerts for indexed files that still need attention, including when a file cannot be read. After a large deletion, cached scans no longer restore removed paths into the file baseline.
- A plugin that declares a method named `include()` or `require()`, which PHP allows and WordPress plugins commonly use, was reported as loading a file from request input. The method body was being read as the include target, so unrelated request handling anywhere inside it triggered the finding. Declarations with long separators or return-by-reference syntax are handled too.
- Hidden files in the shared temporary directories were all reported at high severity, so a root-owned control-panel working file came back as a security finding. A hidden file there is now reported only when it could actually execute, and inspection handles a file being replaced or unreadable without blocking or clearing earlier alerts.
- On hosts where the two temporary directories are the same filesystem, the same file was reported twice. Findings there are now reported once per file.
- A single account reaching its own memory limit was reported as critical, the same as the machine running out of memory. The account case is now a warning, reads differently, and no longer suppresses the machine-wide alert.
- Recognized templates, stylesheets, and data files no longer produce false JavaScript scan warnings, while JavaScript remains checked regardless of filename. JavaScript embedded in those documents is not covered by this analyzer.
- Web-downloadable Joomla site backups are now reported when the site sits in a folder inside the zip, as most backups are packed. Only the root-level layout was recognized before, so these archives and the database password inside them stayed exposed without a finding.

### Fixed

- A deep PHP content scan that runs out of time now keeps the record of the files it confirmed clean, so the next scan resumes instead of re-reading every file from the start. Deleted files are removed from that record even when an account needs several scan windows.
- Shutdown no longer waits for the grace period used to collect findings from timed-out checks.

### Changed

- PHP remote-code findings now say how the fetched source was identified, so an unresolved source is distinguishable from a proven remote one.
- PHP remote-code findings now keep the same identity when their wording changes. This release changes their identity once, so an earlier dismissal of one of these findings is shown once more.

## [3.41.0] - 2026-09-19

### Highlights

- Upgrade recommended: email attachments with malformed transfer encoding, such as spaces inside base64 lines, were delivered without being scanned when attachment scanning fails open. They are now decoded the way mail clients decode them.
- Outbound phishing detection now reads base64 message bodies it used to skip.
- WordPress update nights are much quieter: the core version file, release files that are unpacked but not installed, failed updates, discarded translation folders and BackWPup job files no longer page as modified or self-deleting files.
- Subnet blocking now catches ranges that rotate through addresses one at a time. Expect more subnet blocks after upgrading, since blocks from the last seven days count, including operator and permanent ones.
- Several ways to disguise executable PHP as a harmless stub, translation cache or version file in sensitive WordPress directories are closed.
- The WordPress REST API exploit rule no longer fires on security and analytics plugins, and now catches account takeover code it missed.

### Security

- Email attachments with malformed transfer encoding were delivered without being scanned: base64 with spaces, stray characters or odd padding, quoted-printable with raw control bytes, long lines or bare carriage returns, and encoded multipart sections, and one broken section also hid the attachments after it. These are now decoded the way mail clients decode them, ambiguous encodings are scanned under each reading, and malformed parts are reported as incompletely scanned.
- Outbound phishing detection skipped a base64 message body when a line held a space, the encoding header had no space after its colon, or a header was folded. Message parts are now read from their real MIME framing and decoded the same way as attachments, which also stops header-like body text from being treated as framing.
- A PHP file could hide code behind a comment ended by a bare carriage return, print its whole content as page text through a malformed opening tag, or otherwise carry executable code in a comment-only stub, and still pass as an empty stub, a translation cache or version data. That skipped the location warning for PHP in uploads and other sensitive WordPress directories.
- Re-checking a finding no longer lowers its severity when the replacement file hides active content behind a malformed PHP opening tag or a PHP 8 attribute.
- PHP scanning handles attribute metadata and multiline strings consistently, avoiding missed execution and false alarms from literal examples.
- A file staged in a WordPress core, plugin or theme update that held other content before it was overwritten and then moved into place or deleted beside an identical installed copy is reported again as a self-deleting file, instead of passing as update cleanup.
- Subnet blocking now catches ranges that rotate through addresses one block at a time. Addresses blocked in the last seven days count toward the threshold, including operator and permanent blocks, and the window is adjustable.

### Fixed

#### WordPress updates

- A WordPress core update no longer raises a warning for the version file it copies into the upgrade directory. The file is recognised by content and holds only version data.
- A WordPress core update no longer raises a self-deleting file notice for the release files it unpacks but does not install, such as bundled themes. Each file must match the official checksum of the release now installed.
- A WordPress core or plugin update that WordPress refused or failed to install, for example because the new release needs a newer PHP, no longer reports hundreds of stock files as modified against the old release. The removed package is reported once instead.
- Files deleted together with their directory, such as a translation pack WordPress unpacks and discards during an update, are reported once for the directory instead of once per file.
- The job-state files the BackWPup backup plugin writes and deletes during every run are reported as a lower-severity self-deleting file instead of paging Critical.

#### Detection rules

- The WordPress REST API exploit rule no longer fires High on security and analytics plugins that only mention the users endpoint in comments, settings or translations. It now requires a request to the endpoint that carries a password, which also catches account takeover code the old rule missed.

#### Web UI

- Deleting more than 100 selected quarantined files or file backups is sent in batches instead of failing as a whole, and file controls stay locked until it finishes. Threat page bulk actions and Findings bulk fixes explain their size limit instead of returning a raw error.
- The threat detail page labels the routed range an address belongs to as its GeoIP prefix, so it no longer reads as if the whole range were listed or blocked.

## [3.40.0] - 2026-09-18

### Highlights

- A backdoor hidden inside a working image file is now detected, together with the one line of PHP that loads it. Found from a live compromise where a picture carried a backdoor for two months without any check looking at it.
- Alert email drops sharply. Attacks whose source is already blocked or challenged, scanner probes answered by a verified front controller, successful FTP logins, and repeated scan-coverage warnings no longer reach the inbox. They all stay on the findings page.
- WordPress update activity no longer raises critical self-deleting file alerts: translations, the core version probe and plugin self-test files are recognised by content, not by path.
- A 24 hour block from the web interface no longer marks an address as malicious forever. A separate Block permanently action does that deliberately. Records created before this release are left as they are.
- Upgrade note: two login checks merge. `ftp_login_realtime` becomes `ftp_login` and `ssh_login_realtime` becomes `ssh_login_unknown_ip`. Old names in email exclusions and saved mutes keep working, so update them when convenient.
- The state database stopped growing from records that pruning skipped whenever the same write also pruned.

### Security

- Distinct FTP and SSH sessions no longer share an alert identity when log details are shortened. Queued SSH blocks also survive upgrades that merge login check names.
- Dismissing a scan coverage warning no longer hides it for good: it can alert again once the condition clears and returns. New analyzer failures stay visible, and account scan crashes keep separate alert histories for each account.
- Timed blocks in the web interface no longer shorten existing permanent or longer blocks. Undo respects later operator decisions.
- Image payload detection now covers more file layouts and avoids missed writes during recovery. Payload details no longer cause excessive processing on repetitive files.
- Executable code hidden inside a working image file is now detected. Image writes under hosted document roots were never inspected in real time and no rule looked past a file's name, so a picture could carry a backdoor indefinitely.
- A PHP file that pulls in an image, an archive or another non-executable file while reading request input is now reported, together with the file it pulls in. That one line is the loader half of the technique above and was previously indistinguishable from ordinary templating.
- A self-deleting file in WordPress update staging can no longer escape its alert by breaking the location where an installed copy of it would be looked for.
- Translation files with concealed executable content no longer qualify as harmless data.

### Added

- The Threat Intel page can now block an address permanently, on its own or over a selection, as a separate confirmed action next to the 24 hour block.

### Fixed

#### Alerts and email

- Existing login email exclusions and saved mutes survive the merged check names. Successful FTP logins and File Manager writes remain available to phpanel and event-stream consumers without sending operator notifications.
- A successful FTP login and a cPanel File Manager write are no longer emailed, and one FTP or SSH login is now reported once instead of twice by the realtime watcher and the periodic check. They stay on the findings page, in history and in correlation, and failed authentication, brute force and a login from a brute-force source still alert.
- A critical finding no longer carries the warnings batched with it past the hourly alert limit. Only delivered non-critical alerts count against that limit.
- Suppressing alerts for blocked addresses now also covers brute force, scanner and other attack alerts whose source was blocked or challenged, not only reputation alerts. Compromise evidence, successful logins, suspicious mail and attacks spread across many addresses still alert.
- Scan coverage warnings and check crash alerts no longer send a new email on every scan cycle when only their counts or crash details change; an ongoing condition now follows the normal daily reminder.
- Re-uploading the same identified WordPress plugin or theme release that cannot be checked against wordpress.org follows the normal daily reminder. A different version or site, or a package that cannot be fully identified, still alerts, and content findings remain separate.
- OWASP CRS attack rules logged by LiteSpeed are now recognised as attacks instead of unclassified, and an unclassified ModSecurity rule is reported once per day for the host instead of once for every source address.

#### Firewall and blocking

- Unblocking an IPv4-mapped address now clears the same temporary evidence as its IPv4 form.
- Manual block evidence survives threat-feed changes and migration, and bulk undo restores each address's prior block lifetime without reviving expired evidence. Duplicate selections no longer leave block records behind after undo.
- A 24 hour manual block from the web interface no longer marks the address as malicious forever. The threat record now expires with the firewall block, so a mistaken block of a customer address stops re-blocking it a day later. Blocks recorded before this release are left as they are, and the IP lookup now explains when an address is no longer blocked but still carries a permanent threat record.
- WAF attacker reports for link-local addresses no longer advise a block the firewall refuses, and subnet blocks rejected by safety guards are logged as refused rather than failed.

#### Detection

- PHP Shield no longer reports a webshell command parameter when a scanner probes a missing script and the site's verified, unmodified front controller answers instead. Modified or unverified scripts still alert, and quieted probes stay in the local event archive.
- WordPress translation and core updates no longer raise critical self-deleting file alerts when the updater copies a staged file into place and removes the original, including when file events arrive out of order. Only complete translation or version data qualifies, and a file removed from the same staging paths without an identical installed copy is still reported.
- Really Simple Security upload execution probes no longer raise critical self-deleting file alerts, including when file events arrive out of order or combined. Other content under the same name is still reported.
- A WordPress core update that stops after reading its new version file no longer raises a critical self-deleting file alert when that file matches the official release it names, while an unverified file is still reported. Checksum lookups are bounded, and a file changed while being read stays reported.
- Image and loader checks no longer mistake ordinary description text or plain-text partials for backdoors.

#### State and storage

- Pruning old firewall action records and daily finding totals now removes every expired entry. Some were skipped and left behind, so the state database kept growing.
- Restart advice now reflects reclaimable space in the state database, so a large file that is still mostly in use no longer triggers it.

#### Health and diagnostics

- `csm doctor` and the components view now keep reporting the YARA-X scanning worker as failed while it keeps crashing after restarts, instead of only when it cannot start at all. A restarted worker counts as recovered once it stays up for 30 seconds.
- The YARA-X worker crash alert now reports the current scanning outage without claiming recovery. It distinguishes scanning becoming available after a restart from worker health recovering after the replacement stays up for 30 seconds.

[3.43.0]: https://github.com/pidginhost/csm/compare/v3.42.0...v3.43.0
[3.42.0]: https://github.com/pidginhost/csm/compare/v3.41.0...v3.42.0
[3.41.0]: https://github.com/pidginhost/csm/compare/v3.40.0...v3.41.0
[3.40.0]: https://github.com/pidginhost/csm/compare/v3.39.0...v3.40.0
