# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 4.0.0 are archived: [3.40 to 3.43](docs/changelog/3.40-3.43.md), [3.30 to 3.39](docs/changelog/3.30-3.39.md), [3.20 to 3.29](docs/changelog/3.20-3.29.md), [3.10 to 3.19](docs/changelog/3.10-3.19.md), [3.0 to 3.9](docs/changelog/3.0-3.9.md), [2.x](docs/changelog/2.x.md).

## [4.0.0] - 2026-09-24

### Highlights

- Breaking: `/api/v1` response formats and pagination have changed: lists under `items`, `"ok": true` or an error status for actions, a JSON `error` for failures, RFC 3339 UTC times and severity labels, and read-only routes now reject other request methods. Update API clients before upgrading; the details are under Changed.
- Upgrade recommended: a Web UI session could set the ModSecurity reload command, several file paths and environment variable names from Settings, and through them run commands or write files as root. Those settings now change only in the daemon's configuration file.
- Web UI sessions are harder to abuse: CSRF tokens are bound to the browser session, only the Web UI's own loopback origin is trusted, the Content-Security-Policy is stricter, an open dashboard no longer keeps a session alive, and rate limits cover IPv6 prefixes and the metrics endpoint.
- The UI audit log now names the credential behind each recorded action and covers previously missing logins, scans, quarantine, firewall and ModSecurity changes.
- A cron file carrying known persistence patterns is no longer downgraded to Warning while a package update or panel maintenance runs. Routine nightly control panel maintenance, which used to page as a system compromise, is now a Warning, recognised by the executable actually running.
- Notice after upgrading: the scheduled PHP content scan now also compares change times, to catch a file edited in place with its modification time set back, so it reads each PHP file once more as it reaches it.
- Real-time signature scanning uses a fraction of the CPU it did, and a rules download that changes nothing no longer queues a full rescan of the host every day.
- Web UI: dates follow the time zone preference, Findings, Dashboard and Incidents update from the event stream, and keyboard, screen reader and light theme support are improved. Incident status and file suppressions have bulk actions, and attacker addresses can be blocked from findings.

### Security

- The Settings page can no longer set the ModSecurity reload command, the rules and overrides file paths, the WP-Cron PHP binary, the clamd socket, the mail log and country database paths, or any environment variable name. A web UI session could use them to run commands or write files as root; they are now shown read-only and change only in csm.yaml.
- Changing the rspamd or upstream threat-intel address in Settings now requires entering its credential again, checked against the effective configuration including drop-ins, so a web UI session cannot send the stored credential to an address it chose.
- CSRF tokens are now bound to the browser session instead of shared by every browser until the daemon restarts, and a form token is accepted only from the request body, not the query string.
- A loopback origin such as https://localhost:9443 is now trusted only when it is the origin the request was sent to, so another local web service in the same browser can no longer make authenticated requests to the Web UI.
- The Web UI's Content-Security-Policy now also forbids plugins, <base> tags, framing and form posts to other sites, and the legacy browser XSS auditor, which could be abused to disable page scripts, is turned off.
- Background polling by an open page no longer extends a browser session, so a dashboard left open now logs out after the idle timeout; page loads and requests that follow operator input still count as activity.
- Login and API rate limits now count an IPv6 client by its /64 prefix, scoped addresses included, so rotating addresses inside one prefix no longer multiplies the allowed attempts.
- The /metrics endpoint is now rate limited per client address like the API, so its token cannot be guessed at unlimited speed.
- A flood of requests from many new addresses no longer makes each request scan the whole rate-limit table; a full table is trimmed once for many new addresses.
- Startup, csm validate and csm doctor now warn about Web UI and metrics tokens shorter than 32 characters, since they can be guessed; such tokens keep working.
- The self-signed Web UI certificate is now renewed automatically before it expires and served without a restart; a certificate installed by the operator is never replaced, and replacing its files takes effect without a restart. Renewal in a combined certificate and key file keeps the key and the rest of the bundle.
- The UI audit log now names the credential behind each action and records actions it used to miss: email quarantine release and delete, database object restores, ModSecurity rule changes, subnet blocks, allow-rule removals, cPHulk clears, bulk fixes, incident status changes, scans, logins, logouts and session revocations. An entry keeps its administrator when the session ends before the action completes, large bulk actions no longer hide later entries, an entry that cannot be written is reported in the daemon log, and rotation no longer loses history under concurrent writes.
- The incident timeline CSV export now writes cells that start a spreadsheet formula as text, like every other export.
- A suppression rule that hides every finding of a check now has to be chosen explicitly. Leaving the path empty on the Findings or Rules page, or in an API request, used to create such a rule silently and stop all remediation for that check; a malformed path pattern, which never matched, is now refused as well.
- A suppression created from a finding whose file name contains glob characters such as brackets now matches that file; the pre-filled pattern treated them as wildcards and hid nothing.
- The scheduled PHP content scan no longer skips a file that was edited in place with its size kept and its modification time set back; the change time, which cannot be set that way, is now compared as well. After upgrading, each PHP file is read again the next time the scan visits it.
- A cron file carrying known persistence patterns, encoded ones included, now keeps its full severity while a package update or control panel maintenance runs; realtime cron writes were downgraded because their content was never checked. Control panel provenance also requires a resolved executable when process details come from the cache.
- A rules file reached through a symbolic link is now watched by the file it points to, so updating it queues the rescan that new rules need. A rules file that cannot be read, or is replaced while being read, keeps its last known contents and is retried.
- The Email page action groups, auth-failure clusters and outbound relay abuse no longer come back empty or incomplete on a busy server. Unrelated findings, or findings newer than the chosen dates, used up the scan budget before the matching ones were reached, and a list that is cut short now says so.
- A quarantine restore that fails partway, for example because the account is over quota, no longer leaves a partial root-owned copy at the original path that hid the entry and made every retry fail. A file another writer put there in the meantime is left in place, and the restore can be retried.
- The scan jobs API now rejects request bodies with unknown fields or more than a few kilobytes, so a misspelt option no longer starts a scan without it.

### Changed

#### API

- **Breaking:** API severities are now labels (`CRITICAL`, `HIGH`, `WARNING`) everywhere, including findings, history, the event stream and attack events, and the CSS class that came with some of them is gone. Severity filters also take the label in any case.
- **Breaking:** an empty list or map anywhere in an API response is now `[]` or `{}` instead of null.
- **Breaking:** API times are now RFC 3339 instants in UTC with sub-second precision, left out when not set, and durations are seconds in keys ending in `_seconds`. Relative ages, clock times without a date and duplicate `_iso` fields are gone, and hourly timeline buckets carry their start instant.
- **Breaking:** API routes that return a list now answer an object with the list under `items`, next to `total` and, where the list is paged or capped, `offset`, `limit` and `truncated`, instead of a bare array or a route-specific key. An empty list is `[]`, never null, and `/api/v1/incidents` always answers one page with its total.
- **Breaking:** the scan job findings API now returns 500 findings per page by default and at most 5000, and reports when more pages exist, instead of every finding of a large job in one response.
- **Breaking:** API actions now answer `"ok": true` with their fields instead of `status` verbs or `success` flags (`success` stays on the firewall check and unban routes for existing callers). An action that did not happen, such as a fix that did not apply, an undeliverable test alert, a failed rule reload, a batch where nothing changed or an unknown rule or session, answers with an error status instead of 200.
- **Breaking:** read-only API routes that ran for any HTTP method now answer 405 to anything but GET.
- **Breaking:** every API failure, including CSRF, origin, rate-limit and wrong-method refusals and a response that cannot be encoded, now answers with a JSON `{"error": ...}` body, and an unknown `/api/` path answers 404 instead of the dashboard page. Changing the status of an unknown incident answers 404.

#### Web UI

- Quarantine is now the one list of file backups: it shows pre-clean backups with their type and the live state of the original path, and filters by type. Cleanup History keeps the database object backups and links to it.
- The whitelist is now managed only on the Firewall page under Allow Rules; Threat Intel keeps its whitelist actions and links there, and the two IP lookups link to each other.
- ModSecurity escalation exclusions are now managed only on the ModSec Rules page, which lists and edits them even when rule management is not configured, and each change affects one rule instead of rewriting the whole list.
- The Web UI sidebar now groups Rules, ModSec Rules and Verified Bots with Settings under Configuration, and the ModSecurity page drops its tab that only linked to the rule manager.
- Web UI pages now carry the same name in the sidebar, the browser tab and the heading, the product is named Continuous Security Monitor throughout, the Firewall page calls its whitelist mode Whitelist, and the old /blocked address redirects to the Firewall page.
- The Refresh button now reloads each page's data in place instead of reloading the whole page on some of them, keeps edits in progress, and asks before discarding unsaved Settings, Verified Bots or staged ModSec rule changes.
- The Web UI header now says when the page's data was last loaded instead of when any request last succeeded, and shows the auto-refresh pause button only on pages that refresh on a timer.
- Web UI error notices now stay until closed instead of fading after five seconds, the same error is not stacked, and failure messages no longer read Error: Error:.
- Dashboard triage entries now open the finding they list, and the 24h severity counts open the History tab for exactly the last 24 hours; an open finding is kept in the page URL so the link reopens it.
- Confirmations for actions that delete data, block traffic, turn protection off or end sessions now show a red button named for the action and start on Cancel, and logging out every browser session asks first.
- The History tab now pages with the same first, previous, next and last controls and summary as the Incidents lists, with 25 to 200 rows per page.
- The Findings select-all box now shows a partial state when only some visible findings are selected, as the other bulk tables do.
- Whitelist and temporary whitelist now list the cPanel login history flush they perform, as Unblock & Clear already did.
- Web UI layout fixes: stat cards and incident filters size to their content, whitelist and allow buttons use the warning colour, and grouped incidents filter on every status.
- The Web UI now ships Chart.js 4.5.1, Tabler 1.5.1 and Tabler Icons 3.48.0, with the icon font in WOFF2 only and no references to source maps it does not ship.

#### Performance

- Filtered history requests, including the Email findings tab, now skip stored entries that cannot match the severity, check or search filter before decoding them. Dashboard statistics, the findings timeline and the email workbench lists are computed once per history change and shared by every open page instead of reading a day of history on each refresh.
- The dashboard component list now reads when each watcher last reported from a small index kept with history, instead of decoding up to a week of history on every refresh, and keeps that time after history retention removes the finding.
- The dashboard now receives only the findings it shows, most severe first, and the Findings page checks for changes with a short version string every 15 seconds instead of downloading the full list.
- Web UI pages now link scripts and styles with a content version, so browsers cache them for a year and still load the new files after an upgrade; text files are sent gzip-compressed, and API responses are sent as compact JSON.
- Filtering, sorting and searching long tables no longer slows down with the number of rows squared, and date filters convert each date to the preferred time zone once instead of once per row.
- The audit page and incident timelines now read the UI audit log from the end and stop once they have the entries they show, instead of parsing the whole log each time.
- The quarantine list no longer hashes every quarantined file and its live copy on each request; a pair is compared again only when either file changes.
- The ModSecurity blocks view no longer slows down sharply when many escalated addresses and many block rows coincide, and Cleanup History sorts database object backups faster on hosts with many of them.
- The status API no longer reads the whole daemon binary on every request to report its hash; it hashes the binary again only when the file changes.
- The web UI now samples host metrics only when the Performance page asks for them, at most once every ten seconds, instead of every ten seconds for as long as the daemon runs.

### Added

- Findings, Dashboard and Incidents now react to new findings as they are dispatched, over the Web UI's event stream, and their timed checks slow to a once-a-minute safety net while the stream is connected.
- Finding and incident rows, finding group headers and sortable table headers now work from the keyboard, sorted headers report their order to screen readers, and on Findings o or Enter opens the finding selected with j and k.
- Correlated incidents can now be selected and marked contained, resolved or dismissed together; the change stops at the first failure and reports how many were updated.
- A finding that reports an attacker address, such as a brute-force source, can now be blocked from its detail panel, as an incident can; other findings do not offer Block.
- Findings can now suppress a selection at once, creating one rule per selected file; findings that name no file are skipped so a check-wide rule is never created in bulk.
- The account page is now linked from the finding detail, account groups on Findings, incident detail and the accounts targeted in a Threat Intel lookup, and the command palette opens an account typed by name and lists Sessions.
- `csm privileges` and the capability matrix now show a risk tier for every privileged operation, from read-only detection to destructive responses, and the JSON inventory also reports each operation's current safety and recovery coverage.
- The finding-stream tool can anonymize the action and firewall audit logs alongside a recording and write a manifest of digests, join counts, missing streams and counts of addresses sharing a pseudonym, and recordings carry salted finding ids. Its summary and errors no longer repeat check names, paths or input values, equivalent IPv6 spellings map to one pseudonym, and it refuses rows it cannot classify, ambiguous input, output paths that alias its inputs and raw identifiers left in its output; a failed run preserves earlier output or retains recovery copies if rollback fails.
- A replay tool runs a recorded finding stream through a model of the current automatic block limit, retry queue and temporary deny limit, and reports aggregate outcomes with the assumptions they rest on and the block paths it leaves out.

### Fixed

#### Dates and time zones

- Web UI tables, desktop notifications, the incident timeline and merged IP reputation findings now compare times as instants instead of as text, which misordered entries from different time zones or within the same second.
- Date filters on the Findings history, Email, Audit, Quarantine, Account and Threat Intel pages now mean days in the time zone preference, including across daylight saving changes. The history and email APIs accept an RFC 3339 range end as exclusive and reject a date they cannot read with 400 instead of ignoring it.
- Dates on the Firewall, Hardening and Browser sessions pages now follow the time zone preference. The firewall audit API reports its timestamps as RFC 3339 instants in UTC.
- Dates now use the saved time zone preference from the first render of a page, and changing the time zone re-renders the page. The "Server time" preference now shows the server's own time zone instead of always UTC.
- Dates in the Web UI no longer turn into "3h ago" a minute after a page loads. Only times shown as relative are refreshed, so absolute dates, account history rows and exports keep their content, and an expiry still ahead reads "in 3h" instead of "just now".
- Shared Web UI formatting helpers no longer pass an unreadable time or a non-number through as raw text, and a zero value is no longer shown as blank.

#### Findings and suppressions

- Grouped findings stay grouped while searching, filtering or sorting, and a collapsed group stays collapsed. The group headers used to pile up at the top of the table after a search.
- Dismissing a finding no longer claims it can be restored. The Findings page now says a dismissal stops alerts while the finding is unchanged and that a later scan can list it again, offers undo for 30 seconds, and dismisses a bulk selection as one action that one undo reverses.
- Suppression rules now refuse a check field that holds a pattern or free text and warn when the check name matches no known check, since such a rule hides nothing. Importing a settings bundle skips such rules and rules with an invalid path pattern, as the suppression form does.
- Suppression rules added, removed or imported at the same moment are all kept. Each change rewrote the whole rule set, so simultaneous changes silently dropped each other while every one reported success.
- Findings, dashboard account counts and the findings API now attribute a finding to the account its check recorded before guessing from paths in the message, so mail relay findings count against the sending account. The Account page uses the same recorded ownership for current findings and history.
- The History CSV export now applies the date range, severity and search shown on the History tab, so narrowing the filters reaches entries older than the newest 5,000. The button no longer claims to export the full history.
- An unrecognised severity now shows as Unknown on every Web UI page instead of being labelled Warning on some of them.

#### Firewall, Threat Intel and incidents

- Searching or filtering the firewall audit log now covers the whole log. Filters ran only over the newest page of entries, so an address blocked earlier was reported as never blocked.
- Block, allow, remove-allow, cPHulk clear and unban now record an IPv6 address typed in any spelling under its canonical form, so audit entries and incident records match the firewall state.
- Temporary whitelist entries stay temporary, and clearing cPHulk login history reports a failure instead of claiming success.
- The Firewall and Threat Intel links from a ModSecurity block now open the lookup for that address instead of an unfiltered page.
- Threat Intel now names every attack type in its lookup badges, such as Reconnaissance and Known Malicious IP, using the same labels as the dashboard chart.
- A failed incident status change or incident block now tells the operator why instead of failing silently.
- The incident groups API now filters by a status given in any letter case. Before, a status such as Open was accepted but matched no incidents.
- Failed ModSecurity rollbacks are reported as failures in both the response and audit history.

#### Email, quarantine and cleanup

- Email Security findings with details now have an expand button that shows them; the details rows were built but could never be opened.
- A quarantined file that bulk delete cannot remove now stays listed and the page says so. Its metadata used to be removed anyway, which hid the file from the list so it could neither be deleted again nor restored.
- Select-all on the Cleanup file backups and the Threat Intel attackers table no longer reaches rows on other pages or hidden by a search, so a permanent delete, permanent block or whitelist acts only on the rows on screen.

#### Pages and dashboard

- A panel that fails to load now shows what failed, why, and a Retry button on every page. Retry on the Rules stats, firewall status and Threat Intel panels reloads them in place instead of breaking the panel or reloading the page.
- An expired or revoked browser session now returns the page to the login form instead of showing Unauthorized errors. The connection-lost banner appears only when the daemon cannot be reached, and a daemon restart no longer floods the page with repeated error messages.
- The Web UI live-updates indicator now keeps saying Reconnecting while it retries after a dropped connection, instead of switching back to Connecting on each attempt.
- Tables that reload their data, such as the rules, ModSecurity and incident lists, no longer show stale duplicate rows after a reload, an apply or a filter change.
- Finding details, Account tabs and History now ignore late responses to older requests, so switching views cannot replace the current view with stale content.
- Pages opened in a background tab no longer double their refresh traffic when first shown, returning to a tab no longer reloads everything while auto-refresh is paused, and the Dashboard idle watcher list stays open across refreshes.
- The dashboard now shows a scan in progress for every scan the daemon runs, including scheduled scans, command-line checks and scan jobs, not only scans started from the web UI.
- The health API and dashboard now count log watchers that start after the web UI, such as one waiting for a log file to appear, instead of the count at startup.
- The Account page and the scan account list now find accounts under every account root of the platform, including Plesk vhosts. The Account page recognises linked account roots and lists quarantined files from the configured quarantine directory.
- On the Performance page an open Bulk fix menu no longer closes by itself every few seconds, and a fix that is still running cannot be started a second time. A bulk fix cannot overlap another bulk or individual fix.
- A hardening audit that runs longer than three minutes now returns its report instead of failing after saving it.
- On a phone the Web UI header now wraps instead of running off the screen, and on a desktop the ModSecurity apply bar no longer covers the sidebar.
- Web UI header controls now share one line: the last-updated text, the Logout button and the What's new dot no longer sit above the icons. Logout and ModSecurity bulk actions keep a space after their icons.
- Icons that showed blank, on the ModSecurity and Hardening firewall links and a Settings header, now display.

#### Accessibility

- Web UI widgets now report their role and state to screen readers: Firewall subviews are keyboard-navigable tabs, dashboard charts carry text descriptions, History expand buttons say whether details are open, and the connection-lost banner can be dismissed until the next outage.
- Row checkboxes, rule switches, icon-only buttons and search fields in the Web UI now have names that screen readers announce, instead of relying on placeholders or icons.
- Screen readers no longer read whole lists and the refresh clock aloud every time a Web UI page refreshes; only short status messages such as errors and connection changes are announced.
- Every Web UI page now starts with a Skip to content link that keeps a visible focus indicator, and section headings follow the page title in order so screen reader users can move through the page outline.
- Keyboard focus now survives refreshes and dialog transitions and returns to what opened a panel or dialog. A dialog opened from the detail panel keeps the keyboard to itself, the prompt dialog closes with Escape and keeps Tab inside, and finding shortcuts follow the focused row without acting behind dialogs.
- The light theme now covers the login page, the command palette, the undo banner and chart tooltips, and its status text, badges, toasts and chart labels meet the WCAG AA contrast ratio. Warning text, dashboard indicators and command palette hints are readable in both themes, and the chosen theme still applies when the browser blocks site storage.

#### API

- The history, incident timeline, UI audit log, threat event, top attacker and ModSecurity event APIs now say when entries were left out. History always reported nothing truncated, and the incident timeline reported its page size as the total.
- Importing an exported state bundle works again.

#### Real-time monitoring and scans

- Real-time signature scanning costs a fraction of the CPU it did. Each rule pattern now runs only on files containing text it cannot match without, and a pattern shared by several rules runs once per file; what matches is unchanged.
- A rules download or package upgrade that leaves the rules unchanged no longer queues a full rescan of every file on the host. On hosts with a rules download URL set, the unchanged download rewrote the installed rules daily and after each restart, each time queuing a full rescan and a warning finding.
- The deep scan no longer sends every file it reads to the PHP analysis worker. Files that cannot hold a remote-code flow are ruled out in the daemon, so images and plain text no longer queue behind real analyses, start the worker, or count as unexamined while it is unavailable.
- Deciding whether a written file sits under an account or document root, which the real-time monitor does for every watched write, is much cheaper.

#### Control panel maintenance

- Nightly control panel maintenance no longer pages as a system compromise. A cron drop-in or a staged executable written by the panel's own scheduled work is reported as a Warning instead of High or Critical, recognised by the program a parent process is actually running rather than the name it reports; nothing is skipped.
- The scheduled cron.d comparison now scores a changed or new file the same way the realtime write detector does. It was the one cron path with no provenance rescoring and no check for persistence tokens, so a vendor cron update reported High there while the same write was a Warning.
- Sensitive-file findings are rescored using process ancestry on every Linux host, and ancestry is available before file monitoring starts. Until now that evidence was only read on hosts running the optional kernel monitoring, so the same write scored differently depending on the build.

### Removed

- **Breaking:** `POST /api/v1/rules/modsec-escalation`, which replaced the whole escalation exclusion list without checking rule IDs, is removed. Use `POST /api/v1/modsec/rules/escalation` to change one rule at a time.

[4.0.0]: https://github.com/pidginhost/csm/compare/v3.43.0...v4.0.0
