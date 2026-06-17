# Web UI Audit and Remediation Plan

Status: IN PROGRESS. Started 2026-06-16.

This document is the single source of truth for the web UI improvement effort.
It captures every finding from a 5-agent code-level audit of `ui/` and
`internal/webui/`, groups findings by leverage, and tracks remediation. It is
written to be resumable: a fresh session can read this file and continue.

## Method

Five parallel agents read every template (19 files), every JS file (~17k
lines), `ui/static/css/csm.css` (1365 lines), and cross-checked frontend
rendering against the `internal/webui` Go API handlers. This is a static
code-level audit. The app was not run live, so visual/responsive issues that
only appear in a browser are not covered here -- a live click-through on a
staging host should follow.

## Architecture constraints (read before fixing)

- `internal/webui/` is a server-rendered Go html/template app + Tabler CSS +
  vanilla JS. Per AGENTS.md: "no build step, no framework." Do NOT introduce
  jest/vitest/webpack or any JS toolchain.
- Consequence for TDD: automated red-green tests run at the Go handler layer
  (`internal/webui/*_test.go`). The data-correctness and API-shape findings are
  fully Go-testable and that is where TDD applies. Pure-JS-only behaviour
  (client-side sort comparators, select-all scope, DOM formatting) has no unit
  harness; the production-correct fix for most such findings is to move the
  decision into the Go layer (emit structured data, paginate server-side, etc.)
  which restores testability. Where a fix is unavoidably JS-only, verification
  is careful read-through + codex review + manual reasoning, and that limitation
  is stated explicitly in the commit.
- Templates live in `ui/templates`, static assets in `ui/static`. JS builds
  most data tables client-side from `/api/v1/*` JSON.
- Shared JS helpers: `csm-ui.js` (CSM namespace: esc, fmtDate, timeAgo,
  severityBadge, detailPanel, bulk, Table), `csrf.js` (request/post/loading/
  loadError + formatSize), `table.js` (sortable/paginated tables), `toast.js`
  (toast/confirm/prompt).

## Workflow per item (required by the goal)

1. TDD: write the failing Go test first (where Go-testable), then fix source.
2. Follow AGENTS.md conventions (plain ASCII, short CHANGELOG under
   `## [Unreleased]`, one-line commit subject, no Co-Authored-By).
3. Commit locally (do NOT push unless asked).
4. Run codex review on the commit, then review codex's changes back.
5. Update this file's progress tracker.

## Severity legend

- Critical: data loss or security-relevant, can fire in normal operation.
- High: wrong data shown to operator, or broken core workflow.
- Medium: inconsistency or UX gap that misleads or annoys.
- Low: polish, minor inconsistency, defense-in-depth.

---

## Progress tracker

P0 (data loss + wrong data):
- [x] 1. Bulk select-all selects paginated-away rows -> mass delete (Critical) -- DONE, see change log
- [x] 2. Timestamps shown in mixed UTC/local across pages (High) -- DONE, see change log
- [x] 3. Dashboard "(24h)" label on lifetime counts (High) -- DONE, see change log
- [x] 4. False "New findings detected" banner from endpoint dedup mismatch (High) -- DONE, see change log
- [x] 5. Size + Severity columns sort lexically, not numerically (High) -- DONE, see change log
- [x] 6. Email account/IP regex-scraped from message text, drops IPv6 (Medium-High) -- DONE, see change log
- [x] 7. NaN/null rendered: hardening score, Redis no-limit card (Medium) -- DONE, see change log

P1 (systemic consistency):
- [x] 8. Two disagreeing dark palettes + undefined CSS tokens (High) -- DONE, see change log
- [ ] 9. Four badge/severity color systems; CRITICAL gray on incident list (High)
- [ ] 10. Four dialog patterns incl. native window.confirm/prompt (High)
- [ ] 11. Dead CSM.loading/loadError helpers; silent fetch failures (High)
- [ ] 12. location.reload() after actions loses filters/scroll (Medium)
- [ ] 13. Global overflow-x:hidden hides overflow + breaks sticky (Medium)

P2 (safety, forms, interaction):
- [ ] 14. Destructive actions without confirm/undo (High)
- [ ] 15. Settings save races: lost-edit, double-submit, badge mismatch (High)
- [ ] 16. Dead error-handling branches in modsec-rules (High)
- [ ] 17. Interval leaks on tab visibility change -> fetch storms (Medium)
- [ ] 18. Loose IP/CIDR validators + dead date regexes (Medium)
- [ ] 19. Audit log renders all rows into one innerHTML; relative export (Medium)
- [ ] 20. A11y: confirm modal ARIA, fake focus traps, login states (Medium)

---

## P0 -- Data loss and wrong data

### 1. Bulk select-all selects paginated-away rows (Critical, quarantine/findings/email/cleanup)
Pagination hides rows with `display:none` instead of removing them, so a
select-all checkbox checks every row in the DOM including rows on other pages.
On quarantine, "Delete Selected" is a permanent `/quarantine/bulk-delete`. An
operator on page 1 who clicks select-all and deletes believes they acted on one
page but wipes the entire quarantine. No typed confirmation for permanent
delete. Selection is also not cleared on filter/search change, so hidden
previously-checked rows stay targeted.
Evidence: `quarantine.js:265-313`, `csm-ui.js:299` (`all()`), `table.js:396`,
`findings.js:280-291`, `email.js` bulk handlers, `cleanup-history.js:148-156`.
Fix: scope select-all to currently-visible rows, or relabel as "Select all N
across pages" with typed confirmation for permanent delete; clear selection on
any filter/search/date change.

### 2. Timestamps shown in mixed UTC/local across pages (High)
Quarantine, Verified-Bots, and ModSec render raw UTC RFC3339 strings
(`2026-06-16T12:34:56Z`); the rest of the UI uses local `CSM.fmtDate`. ModSec
"Last Seen"/"Time" are date-less UTC `15:04:05`, so a 23:00-yesterday event and
01:00-today event are indistinguishable, and column sort is time-of-day lexical
ignoring date.
Evidence: `quarantine.js:126`, `verified-bots.js:107`, `modsec.js:375,498` vs
`cleanup-history.js:129`; APIs already expose ISO fields (`last_seen_iso`).
Fix: route all timestamps through `CSM.fmtDate`/`timeAgo` + emit `data-timestamp`
(ISO) for correct sort. Add ISO field to the modsec events endpoint if missing.

### 3. Dashboard "(24h)" label on lifetime counts (High)
Subtitle "N critical / M high (24h)" reads `critical_count`/`high_count` from
`/api/v1/findings/enriched` (all active findings, no time window); will not match
the genuinely-24h posture card sourced from `/api/v1/stats`.
Evidence: `dashboard.js:1199,1127-1135` vs `api.go:223`.
Fix: drive the subtitle from `/stats` `last_24h`, or drop the "(24h)" suffix.

### 4. False "New findings detected" banner (High)
Auto-refresh poller hits `/api/v1/findings` (no IP dedup) and compares its
count/keys against the rendered table from `/api/v1/findings/enriched` (which
runs `dedupIPReputation`). The two return different row counts for the same
state, so the banner fires whenever any ip_reputation findings exist, with zero
changes.
Evidence: `findings.js:831-845` vs `api.go:222-298`.
Fix: poll the enriched endpoint, or compare against the dedup'd key set the
table actually rendered.

### 5. Size + Severity columns sort lexically (High)
Size cells are pre-formatted text ("9 B" sorts after "1.2 MB"). Findings
severity column has no numeric `data-sort` (alphabetical order works only by
coincidence and reverses on relabel).
Evidence: `quarantine.js:126`, `cleanup-history.js:128,294`, `rules.js:35`,
`table.js:373-380`; `findings.js:106`. Reference correct pattern:
`incident.js:444`.
Fix: emit numeric `data-sort` (raw bytes; severity rank) on those cells.

### 6. Email account/IP regex-scraped from message text (Medium-High)
Account and source IP are parsed by regex over the human-readable message
(`/for (\S+@\S+)/`, `/from (\d+\.\d+\.\d+\.\d+)/`). IPv6 sources never match so
the IP column is blank for v6 attackers; account parsing breaks on any wording
change.
Evidence: `email.js:572-598`.
Fix: return structured `account`/`ip` fields from the API (finding has them
server-side); this is the production-correct fix and is Go-testable.

### 7. NaN/null rendered to operators (Medium)
Hardening score `score/total` with `total==0` renders "NaN / 0 checks".
Performance Redis card paints a healthy no-maxmemory Redis red whenever memory
is above zero. The shared size formatter now blanks missing or invalid byte
counts instead of rendering `null B` or `NaN B`.
Evidence: `hardening.js:27-28`, `performance.js:333-339`.
Fix: guard zero/null; neutral styling for "no limit".

---

## P1 -- Systemic consistency

### 8. Two disagreeing dark palettes + undefined tokens (High)
`--csm-*` dark tokens (csm.css:20-32) define one dark surface set; the
`.theme-dark` override block (47-65) hardcodes a different set
(`#1a2234`/`#2d3a4e`/`#c8d3e0`) and repeats it ~40 times. `--csm-success` and
`--csm-secondary` are referenced but never defined, so SSE status dots fall back
to wrong colors. 56 `!important` exist mostly to win the literal-vs-token war.
Evidence: `csm.css:20-32`, `47-65`, `1108,1111,1082`.
Fix: pick one dark palette, define tokens once, replace literals with
`var(--csm-*)`, and drop the now-unneeded navbar `!important`. Keep
`!important` only where Tabler marks the competing utility rule important.

### 9. Four badge/severity color systems (High)
Custom `badge-critical/high/warning`, solid Tabler `bg-red/orange`, soft
`bg-*-lt`, and Bootstrap `dark/danger`. CRITICAL shows gray on the incident list
and red elsewhere. Toasts and type badges also bypass tokens.
Evidence: `incident.js:5-9` vs `csm-ui.js:26-30`; `modsec.js:105,496`;
`threat.js:10,20,25`; `modsec-rules.js:69-70`; `toast.js:39,48`.
Fix: funnel all severities through `CSM.severityBadge`/`sevMap` (`--csm-*`).

### 10. Four dialog patterns incl. native window.confirm/prompt (High)
Native `window.confirm`/`window.prompt` (settings, views, firewall) inside a
themed app; the shared confirm modal is hijacked for file previews; cleanup uses
a raw Bootstrap modal; everything else uses offcanvas `CSM.detailPanel`. The
most dangerous flow (firewall rollback timer) uses a native prompt.
Evidence: `settings.js:171,1049-1060,1202`; `views.js:163`; `quarantine.js:186`;
`cleanup-history.js`; vs `csm-ui.js` detailPanel.
Fix: standardize -- `CSM.detailPanel` for detail, `CSM.confirm`/`CSM.prompt` for
decisions; remove native dialogs and the confirm-modal hijack.

### 11. Dead CSM.loading/loadError helpers; silent fetch failures (High)
`CSM.loading`/`CSM.loadError` are used by zero templates; 15 pages hand-roll
their own spinner. Two competing empty-state helpers. Several panels swallow
fetch errors (`loadChallenges` `.catch(function(){})`), leaving spinners forever,
indistinguishable from empty.
Evidence: `csrf.js` (unused helpers), `csm-ui.js:33-38,75-86`; `firewall.js:852`;
`email.js:165-169,295`; `rules.js:139,239,251`.
Fix: adopt `CSM.loading`/`loadError` everywhere (with retry); delete duplicate
empty-state helper; no silent catches.

### 12. location.reload() after actions loses context (Medium)
Full page reload after fix/dismiss/bulk action destroys filters, scroll,
expanded detail, place in a long triage session.
Evidence: `findings.js:380`; `threat.js:507,520`.
Fix: mutate rows in place and update counts (firewall's `refreshFirewallData`).

### 13. Global overflow-x:hidden hides overflow + breaks sticky (Medium)
`html, body, .page { overflow-x: hidden }` clips real wide-table/long-IP overflow
and breaks `position:sticky` for findings header, settings footer, sticky table
headers.
Evidence: `csm.css:119` (sticky users at 182, 277, 360, 934).
Fix: remove the rule; fix overflow sources (`.table-responsive`, truncate-middle
with title on long paths/IPs/UAs).

---

## P2 -- Safety, forms, interaction

### 14. Destructive actions without confirm/undo (High)
Outbound-abuse "Block 24h" firewalls an IP on one click (every other block
confirms). Removing a modsec escalation exclusion fires immediately with no
confirm. `undo.js` exists but no destructive action uses it.
Evidence: `email.js:1232-1238`; `rules.js:270-276`; `quarantine`/`cleanup`/
`modsec` delete paths.
Fix: add `CSM.confirm` with consequence text; wire reversible actions to
`CSM.undo`.

### 15. Settings save races (High)
Post-save `loadSection` clobbers edits made during the round-trip (lost-edit on
slow links). Only Save button disabled, so rollback/discard allow duplicate
`If-Match` submit. "Applies live" badge is schema-guessed and can contradict the
post-save "restart required" banner; two restart notices can show at once.
Evidence: `settings.js:876-930,314-316,330-338`.
Fix: disable whole form during save; align badge with runtime `config.Diff`;
consolidate restart notices.

### 16. Dead error-handling branches in modsec-rules (High)
`CSM.post` rejects non-OK responses, so the `else { data.error }` and
`data.rolled_back` revert paths never run -- failed escalation/apply shows
double-prefixed "Error: Error:" and leaves the toggle in a false "applied" state.
Evidence: `modsec-rules.js:142-155,247-266`.
Fix: move revert + messaging into `.catch`.

### 17. Interval leaks on tab visibility change (Medium)
Chart pollers are re-added on every `visibilitychange` without clearing prior
ones -> escalating fetch storms against the daemon on tab switching.
Evidence: `dashboard.js:21-28,1012-1031,985-1002`.
Fix: stop existing intervals before re-adding (mirror existing `_stopIntervals`).

### 18. Loose validators + dead date regexes (Medium)
`CSM.validateIP` accepts `:::::` as IPv6; CIDR prefix `/99` not validated; the
`\s+/'$1T$2'` date regexes assume a non-RFC3339 format (dead code, work by luck).
Evidence: `csrf.js:771`; `firewall.js:949-953`; `threat.js:233`, `email.js:802`.
Fix: tighten validators; drop dead regexes; one shared date/IP helper.

### 19. Audit log renders all rows into one innerHTML (Medium)
No server-side pagination/limit; on a busy host this builds a huge HTML string
and can freeze the tab. CSV export emits the relative "3h ago" string as the
timestamp.
Evidence: `audit.js:100-113,179`.
Fix: server-side limit/pagination (Go-testable); export absolute ISO; add `title`
absolute time to the cell.

### 20. A11y gaps (Medium)
Confirm modal has no title/`role`/`aria-labelledby`/`aria-describedby`; command
palette and shortcuts-help "focus traps" collapse to one element (a real trap
exists in `detailPanel` -- share it); login form has no submit/loading state
(double-submit); shortcuts-help overlay hardcodes dark colors so it is a dark box
in light mode; sidebar nav toggles hardcode `aria-expanded="true"` while state is
restored from localStorage.
Evidence: `toast.js:91-167`; `palette.js:230`; `shortcuts.js:102-150,205`;
`login.js`; `layout.html:30,44,64,114,152`.
Fix: wire ARIA on confirm; extract one shared focus-trap; add login submit state;
theme the overlay; set initial `aria-expanded` from persisted state.

---

## Additional lower-severity findings (batch later)

These are real but lower-leverage; fold into the relevant item's commit when
touching that file.

- Dashboard brute-force "Attacks" total includes modsec rows but the IP list
  excludes them, so total can exceed sum of listed IPs. `dashboard.js:353` vs
  `api.go:498-501`.
- `/findings/enriched?limit=20` ignores `limit`; backend returns all findings.
  `dashboard.js:1138` vs `api.go:223`.
- Timeline chart x-axis is server-local hour buckets with no TZ label while the
  rest of the page is operator-local. `dashboard.js:494-626`.
- Timeline/trend charts return early on empty series -> permanently blank cards.
  `dashboard.js:495-501,814`.
- Incident CSV export uses 'WARNING' fallback but UI badge uses 'INFO'.
  `incident.js:642-643,670`.
- Incident timeline sort by invalid date -> NaN comparator, nondeterministic.
  `incident.js:518-526`.
- Findings CSV exports formatted display strings, not ISO. `findings.js:802-807`.
- Findings full reload after fix loses triage context (see item 12).
  `findings.js:360,380`.
- Findings account filter is exact-match on free-text input -> hides rows
  silently. `findings.js:341-353`.
- Dashboard "idle watchers" details re-collapses every 30s refresh.
  `dashboard.js:1305-1319`.
- Firewall "Conn rate 0/min per IP" shown when feature disabled. `firewall.js:255`.
- Firewall infra/country/dyndns lists overflow horizontally (no wrap/truncate).
  `firewall.js:252,258,259`.
- Firewall whitelist removal confirm lacks consequence text. `firewall.js:761`.
- ModSec domain string is server-truncated to 80 chars then tokenized -> bogus
  domain tokens. `modsec.js:177-204` vs `modsec_api.go:248`.
- ModSec events tab loads once, never refreshes with the 30s poller.
  `modsec.js:466-478`.
- Quarantine/cleanup previews hijack the shared confirm modal (two teardown
  paths, risk of stuck modal). `quarantine.js:186-241`, `cleanup-history.js:45`.
- Rules modsec escalation table interpolates API values unescaped (defense-in
  depth; currently ints). `rules.js:261-268`.
- Verified-bots editor has no dirty-state/beforeunload guard. `verified-bots.js`.
- Account page defaults unknown severity to WARNING (under-represents risk).
  `account.js:14-15`.
- Settings byte fields show raw byte counts (e.g. 26214400) with no MB helper.
  `settings.js:485-487`.
- Settings secret fields do not distinguish "configured" from "not set".
  `settings.js:540-558`.
- Login `autocomplete="off"` on the token field fights password managers.
  `login.html`.
- Threat IP-lookup errors render raw exception (`Error: [object Object]`).
  `threat.js:302,377`.
- Threat row-click anywhere auto-submits a lookup (fires on text selection).
  `threat.js:260-264`.
- Sidebar IA: ModSecurity (Response) and ModSec Rules (Operations) split across
  groups. `layout.html:93-148`.
- Width-utility scales duplicated; sidebar width `244px` magic number duplicated.
  `csm.css:144,970,998`.
- Stale "Not yet applied" / WEB_ROADMAP provenance comments in shipped CSS.
  `csm.css:588,15 roadmap tags`.

---

## Notes on XSS posture

Generally strong: `CSM.esc`/DOM builders dominate. The one flagged gap is the
modsec escalation table in `rules.js:261-268` (currently server-validated ints;
defense-in-depth, not a live hole). Keep `textContent` for quarantine file
preview content (untrusted malware sample text).

---

## Resume instructions for a fresh session

1. Read this file top to bottom.
2. Check the progress tracker for the next unchecked item.
3. Read the affected files end to end (AGENTS.md review discipline).
4. Follow the per-item workflow above (TDD where Go-testable, codex review,
   review-back, CHANGELOG, commit-not-push).
5. Update the tracker and append a short note under "Change log of this effort".

## Change log of this effort

- Item 1 (Critical): scoped `CSM.bulk` to visible rows. `all()` queried every
  checkbox in the DOM while pagination/filter only set `display:none`, so
  select-all and `selectedValues()` reached rows on other pages and rows hidden
  by a filter. Added `isVisible()`/`visible()` (offsetParent test) and routed
  `checked()`, the count/total in `paint()`, and the select-all toggle through
  it; `clear()` still unchecks everything. WYSIWYG selection is the safe default
  for destructive bulk ops; "act on all" remains reachable via page-size All.
  Fixes quarantine/email-quarantine/modsec bulk bars at the shared layer.
  `ui/static/js/csm-ui.js`. No JS unit harness in this repo (AGENTS: webui has
  no build step/framework); verified by full `internal/webui` Go suite plus
  read-through of all three consumers.
- Item 2 (High): timestamps. Added Go-TDD `time_iso` (RFC3339) to the modsec
  events endpoint (blocks already had `last_seen_iso`), then rendered quarantine
  `quarantined_at`, modsec blocks/events, and verified-bot `last_refresh` through
  `CSM.fmtDate` with cell-level sort keys so they show operator-local time and
  sort chronologically. Found and fixed a coupled latent bug: quarantine put
  `data-timestamp` on the `<tr>`, so the global 60s `initTimeAgo` (csrf.js) wiped
  whole rows; renamed the row's date-filter attribute to `data-quar-ts` (updated
  `_inRange` + the pinned static UI test) and kept absolute timestamp cells off
  the relative-time refresh hook. `modsec_api.go`,
  `modsec_blocks_extended_test.go`, `quarantine.js`, `modsec.js`,
  `verified-bots.js`, `static_ui_test.go`.
- Item 3 (High): dashboard subtitle. `loadPriorityQueue` labelled the summary
  "(24h)" but read all-active `critical_count`/`high_count` from
  `/findings/enriched`. Now also fetches `/api/v1/stats` and uses its genuinely
  24h-windowed `last_24h.critical`/`.high`, matching the posture cards. Pure-JS
  sourcing fix; the 24h counts already exist in `/stats` and are covered by
  existing Go tests (TestAPIStatsWithData et al.), so no new backend surface.
  `dashboard.js`. Codex review added a static-UI regression test pinning the
  24h sourcing (TestDashboardSummaryUsesWindowedStatsCounts, kept); it also tried
  to add a `validateDeepSection` injection seam to server.go/settings_api.go to
  dodge its sandbox's TCP-bind limit -- reverted as out-of-scope test-induced
  production change (the existing httptest-based settings test passes fine here).
- Follow-up review found that table pagination/search/filter renders did not
  repaint existing bulk bars, and ModSec still counted checked hidden rows
  directly. Quarantine, email quarantine, and ModSec now refresh bulk state
  after table renders; ModSec applies only visible-scoped `CSM.bulk` values.
- Item 4 (High): findings auto-refresh banner. The 15s poller hit raw
  `/api/v1/findings` (no IP dedup, original per-finding messages) and compared
  its count/keys against the table seeded from `/api/v1/findings/enriched`
  (`dedupIPReputation` collapses ip_reputation by IP and rewrites the message to
  "Known malicious IP accessing server: ..."). The two shapes never matched, so
  "New findings detected" fired on every poll whenever any ip_reputation finding
  existed, with zero state change. Pointed the poller at the enriched endpoint
  and read its `findings` array, making the comparison apples-to-apples with the
  rendered table while still catching genuine adds/removes/severity merges. The
  comparison key now includes severity, and merged IP reputation source labels
  are sorted before rendering so equivalent scan results do not flip the banner.
  Static-UI and dedup regression tests cover the browser/backend halves.
  `ui/static/js/findings.js`, `internal/webui/static_ui_test.go`,
  `internal/webui/api_findings_test.go`.
- Item 5 (High): numeric column sort. The shared table sorts a cell by its
  `data-sort` attribute (numeric when the whole value parses as a number) and
  otherwise falls back to lexical `textContent`. Size cells only had the
  pre-formatted text ("9 B", "1.2 MB"), so they sorted as strings, and the
  findings Severity cell had no `data-sort` (CRITICAL/HIGH/WARNING sorted right
  only by alphabetical coincidence and would reverse if a label changed). Added
  `data-sort` carrying the raw byte count to the quarantine, cleanup-files,
  DB-backup, and rule-file Size cells (the APIs already return raw bytes) and a
  numeric severity rank to the findings Severity cell, derived client-side from
  the already promoted label (the reference pattern is `incident.js`; deriving
  from the label avoids a stored rank field that the ip_reputation dedup
  promotion would leave stale). Pure-JS fix; pinned with
  TestSizeAndSeverityColumnsSortNumerically, with JavaScript syntax checked by
  `node --check`. `ui/static/js/findings.js`, `ui/static/js/quarantine.js`,
  `ui/static/js/cleanup-history.js`, `ui/static/js/rules.js`,
  `internal/webui/static_ui_test.go`.
- Follow-up review of item 5 found the new sort regression test pinned the
  quarantine size cell to the old missing-value rendering path. `CSM.formatSize`
  now returns blank for missing or invalid byte counts, and the shared formatting
  test pins that guard so size cells cannot show `null B` or `NaN B`. The same
  pass added the missing raw-byte sort key to the Rules file table.
- Item 6 (Medium-High): email account/IP scraping. The email findings table
  derived the account with `/for (\S+@\S+)/`-style regexes and the source IP
  with `/from (\d+\.\d+\.\d+\.\d+)/` over the human-readable message, so any
  IPv6 attacker left the IP column blank and any wording change broke the
  account column. The mail and account detectors already attach the attacker IP
  (`SourceIP`, filled from parsed log addresses, so IPv6-correct) and the account
  (`Mailbox`/`Domain`) as structured fields. The history endpoint now normalizes
  these into per-finding `account` and `ip` keys (account preferring `Mailbox`,
  `TenantID`, `CPUser`, then email legacy fallbacks, then the existing /home
  and "Account:"/"user:" extraction, then `Domain`), and email.js renders
  them directly, dropping both regex helpers. Backend surface, so TDD at the Go
  handler layer (TestAPIHistoryEmitsStructuredAccountAndIP, with an IPv6
  SourceIP that the old regex dropped) plus fallback coverage for bare cPanel
  auth users and old `set_id`/`rip=` mail-log rows, and a static-UI test pinning
  the JS render and the removed regex. `internal/webui/api.go`,
  `internal/webui/api_history_test.go`, `ui/static/js/email.js`,
  `internal/webui/static_ui_test.go`. The legacy fallbacks parse
  attacker-controlled message/detail text, so a fuzz target
  (FuzzHistoryAttribution) asserts they never panic and only ever attribute a
  netip-valid address. `internal/webui/fuzz_parsers_test.go`.
- Item 7 (Medium): NaN/no-limit rendering. The hardening score computed
  `Math.round((report.score / report.total) * 100)`; an absent or zero total
  made the percent NaN, which fell through every `pct >=` threshold and painted
  the progress bar danger-red. It now derives missing `score`/`total` values from
  the result rows, shows `score / total checks passed`, and renders a neutral
  `bg-secondary` bar when no checks ran. The performance Redis card painted a
  healthy no-maxmemory Redis red
  (`text-danger` whenever used memory was above zero); an unbounded maxmemory is
  the normal default and is surfaced as a `perf_redis_config` finding when it
  matters, so the "no limit" card is now neutral. Earlier in this effort the
  shared size formatter was also hardened to blank missing/invalid byte counts
  (see the item 5 follow-up), closing the third sub-bug. Pure-JS fixes, pinned
  with TestHardeningAndRedisGuardZeroAndNoLimit and `node --check`.
  `ui/static/js/hardening.js`, `ui/static/js/performance.js`,
  `internal/webui/static_ui_test.go`.
- Item 8 (High): two disagreeing dark palettes. The `:root`/`.theme-dark` token
  block defined one dark surface set (border `#334155`, text `#e2e8f0`) while a
  parallel block of hardcoded literals (page `#1a2234`, border `#2d3a4e`, text
  `#c8d3e0`, muted `#8d99ad`) repeated across ~40 rules defined another, so
  components styled via tokens and components styled via Tabler overrides drew
  slightly different borders and text. `--csm-success` and `--csm-secondary`
  were referenced by the SSE connection dots but never defined, so the dots fell
  back to the light-theme green/gray even in dark mode. Picked the
  literal-block values as the single dark palette (they were on the dominant
  page chrome, so the visible theme is essentially unchanged), added
  `--csm-bg-page`/`--csm-success`/`--csm-secondary` tokens, redefined the dark
  `--csm-border`/`--csm-text`/`--csm-text-muted` to the unified values, and
  replaced every hardcoded surface literal with `var(--csm-*)`. The navbar
  override no longer uses `!important`, so the tokenized top utility bar can
  keep the card surface while the sidebar uses the page surface. The remaining
  `!important` on muted text overrides Tabler's own important utility rule.
  Pure-CSS change (no build step/JS), pinned by
  TestDarkPaletteConsolidatedToSingleTokenSet, which counts each surface literal
  down to its single token definition and checks no `var(--csm-*)` is left
  undefined. `ui/static/css/csm.css`, `internal/webui/static_ui_test.go`.
