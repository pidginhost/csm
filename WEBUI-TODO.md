# Web UI Overhaul — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 6 structural issues, add 9 missing features, remove 3 pieces of dead weight, and implement 7 features not originally considered — bringing the Web UI from "functional dashboard" to "security operations platform."

**Architecture:** The plan is organized in 4 phases (cleanup, core fixes, simple features, complex features). Each task produces a buildable, testable commit. Tasks within a phase are ordered by dependency — later tasks may build on earlier ones.

**Tech Stack:** Go 1.26 (html/template, net/http), vanilla JS (ES5, no build step), Tabler CSS framework, JSONL state storage, nftables firewall backend.

---

## Phase 1: Quick Cleanup

### Task 1: Remove dead code and fix duplicate computation

**Covers:** Review items 5 (fix-preview dead), 6 (duplicate dashboard stats), 16 (dead pagination fields)

**Files:**
- Modify: `internal/webui/server.go` — remove `/api/v1/fix-preview` route
- Modify: `internal/webui/api.go` — remove `apiFixPreview` handler
- Modify: `internal/webui/handlers.go` — remove dead pagination fields from `historyData`, simplify `handleDashboard` to skip stats computation (JS polls `/api/v1/stats` immediately)

- [ ] **Step 1: Remove fix-preview route from server.go**

Delete the route registration line:
```go
mux.Handle("/api/v1/fix-preview", s.requireAuth(http.HandlerFunc(s.apiFixPreview)))
```

- [ ] **Step 2: Remove apiFixPreview handler from api.go**

Delete the entire `apiFixPreview` function.

- [ ] **Step 3: Remove dead pagination fields from handlers.go**

In `historyData` struct, remove these unused fields:
```go
Page     int
NextPage int
PrevPage int
HasNext  bool
HasPrev  bool
```

- [ ] **Step 4: Simplify handleDashboard stat computation**

The handler computes critical/high/warning counts from history, but `dashboard.js` overwrites them immediately via `/api/v1/stats` poll. Change the handler to pass zero values and let the JS populate them on load. This eliminates the redundant 500-entry history scan on every dashboard page load.

Replace the counting loop with simple zero initialization:
```go
data := dashboardData{
    Hostname:       s.cfg.Hostname,
    Uptime:         time.Since(s.startTime).Round(time.Second).String(),
    Critical:       0,
    High:           0,
    Warning:        0,
    Total:          0,
    // ... rest unchanged
}
```

Keep the timeline computation and recent findings — those are NOT duplicated by JS.

- [ ] **Step 5: Build and verify**

Run: `GOOS=linux go build ./...`

- [ ] **Step 6: Commit**

```
fix: remove dead code (fix-preview endpoint, unused pagination fields, duplicate stats)
```

---

### Task 2: Replace blocked ratio with "time since last critical"

**Covers:** Review items 18 (meaningless blocked ratio) and 22 (time since last critical)

**Files:**
- Modify: `ui/templates/dashboard.html` — replace blocked ratio card
- Modify: `internal/webui/handlers.go` — add `LastCriticalAgo` to dashboard data
- Modify: `ui/static/js/dashboard.js` — refresh the new metric
- Modify: `internal/webui/api.go` — add `last_critical_ago` to stats response

- [ ] **Step 1: Add LastCriticalAgo to dashboardData and compute it**

In `handlers.go`, add field to `dashboardData`:
```go
LastCriticalAgo string
```

In `handleDashboard`, after the history loop that builds timeline/recent, compute:
```go
lastCriticalAgo := "No critical findings"
for _, f := range findings {
    if f.Severity == alert.Critical {
        lastCriticalAgo = timeAgo(f.Timestamp)
        break // findings are newest-first
    }
}
```

Set `data.LastCriticalAgo = lastCriticalAgo`.

- [ ] **Step 2: Replace blocked ratio card in dashboard.html**

Replace the "Blocked / Total" card with a "Last Critical" card:
```html
<div class="col-sm-6 col-lg-3">
  <div class="card card-sm">
    <div class="card-body">
      <div class="row align-items-center">
        <div class="col-auto">
          <span class="bg-danger text-white avatar">!</span>
        </div>
        <div class="col">
          <div class="font-weight-medium" id="stat-last-critical">{{.LastCriticalAgo}}</div>
          <div class="text-muted">Last Critical</div>
        </div>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 3: Add last_critical_ago to apiStats**

In `api.go` `apiStats`, compute and include `last_critical_ago` in the JSON response using the same history scan logic.

- [ ] **Step 4: Update dashboard.js to refresh the metric**

In `refreshStats()`, after updating counters:
```js
if (data.last_critical_ago) {
    setText('stat-last-critical', data.last_critical_ago);
}
```

- [ ] **Step 5: Build, verify, commit**

```
feat: replace blocked ratio with "time since last critical" on dashboard
```

---

### Task 3: Keyboard shortcut discoverability

**Covers:** Review item 15

**Files:**
- Modify: `ui/templates/layout.html` — add `?` hint to navbar

- [ ] **Step 1: Add keyboard shortcut hint to navbar**

In `layout.html`, add a small button next to the theme toggle:
```html
<div class="nav-item d-none d-md-flex me-2">
  <a href="#" class="btn btn-ghost-secondary btn-icon" onclick="CSM.shortcuts.showHelp(); return false;" title="Keyboard shortcuts (?)">?</a>
</div>
```

- [ ] **Step 2: Commit**

```
feat: add keyboard shortcut hint icon to navbar
```

---

## Phase 2: Core UX Fixes

### Task 4: FirstSeen / LastSeen tracking for findings

**Covers:** Review item 1

**Files:**
- Modify: `internal/state/state.go` — add EntryForKey method
- Modify: `internal/webui/handlers.go` — use entry timestamps
- Modify: `internal/webui/api.go` — include first_seen in API response

The state store already tracks `FirstSeen` and `LastSeen` in its `Entry` struct for alert deduplication. The issue is that `handleFindings` uses `f.Timestamp` for both columns instead of querying the Entry's actual values.

- [ ] **Step 1: Add EntryForKey method to store**

In `state.go`:
```go
func (s *Store) EntryForKey(key string) (Entry, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    e, ok := s.entries[key]
    if !ok {
        return Entry{}, false
    }
    return *e, true
}
```

- [ ] **Step 2: Update handleFindings to use entry timestamps**

In `handlers.go` `handleFindings`, look up each finding's entry:
```go
firstSeen := f.Timestamp
lastSeen := f.Timestamp
if entry, ok := s.store.EntryForKey(f.Key()); ok {
    firstSeen = entry.FirstSeen
    lastSeen = entry.LastSeen
}
```

- [ ] **Step 3: Update apiFindings similarly**

In `api.go` `apiFindings`, add `first_seen` and `last_seen` fields using the same lookup.

- [ ] **Step 4: Build, verify, commit**

```
feat: track real FirstSeen/LastSeen for findings using state entries
```

---

### Task 5: Findings page auto-refresh

**Covers:** Review item 7

**Files:**
- Modify: `ui/static/js/findings.js` — add polling with "new findings" banner
- Modify: `ui/templates/findings.html` — add refresh banner element

- [ ] **Step 1: Add refresh banner to findings.html**

Before the findings table:
```html
<div id="refresh-banner" class="alert alert-info alert-dismissible d-none" role="alert">
  <div class="d-flex align-items-center">
    <div>New findings detected.</div>
    <a href="#" class="btn btn-sm btn-info ms-auto" onclick="location.reload(); return false;">Refresh</a>
  </div>
</div>
```

- [ ] **Step 2: Add polling logic to findings.js**

Poll `/api/v1/findings` every 15 seconds, compare count and keys with current page, show banner if changed.

- [ ] **Step 3: Commit**

```
feat: auto-refresh banner on findings page when new findings detected
```

---

### Task 6: Dashboard chart auto-refresh

**Covers:** Review items 3 (static charts) and remaining part of 6 (duplicate stats)

**Files:**
- Modify: `ui/static/js/dashboard.js` — refresh attack types chart, periodic page reload

- [ ] **Step 1: Add attack types chart refresh to refreshStats()**

In `refreshStats()`, after updating counters, rebuild the attack types chart from `data.by_check`.

- [ ] **Step 2: Add periodic page reload**

```js
setTimeout(function() { location.reload(); }, 300000); // 5 minutes
```

- [ ] **Step 3: Commit**

```
feat: auto-refresh attack types chart and periodic dashboard reload
```

---

### Task 7: History page — API-driven pagination

**Covers:** Review item 2 (5000 entries loaded server-side)

**Files:**
- Modify: `internal/webui/handlers.go` — simplify `handleHistory` to render empty shell
- Modify: `ui/templates/history.html` — remove server-rendered rows, add JS-driven content
- Modify: `ui/static/js/history.js` — fetch data from API, render table client-side
- Modify: `internal/webui/api.go` — add date filtering to `apiHistory`

- [ ] **Step 1: Add date filtering to apiHistory**

In `api.go` `apiHistory`, parse optional `from` and `to` query params (YYYY-MM-DD). Filter findings by date range server-side before applying limit/offset.

- [ ] **Step 2: Simplify handleHistory**

The handler only renders the template shell with hostname — no data loading.

- [ ] **Step 3: Rewrite history.html as a JS-driven shell**

Remove the `{{range .Findings}}` loop. Add container elements for JS to populate with an empty table body, date filter inputs, severity filter, search, CSV export, and a pager footer.

- [ ] **Step 4: Rewrite history.js to fetch and render from API**

Client-side pagination: fetch `/api/v1/history?limit=50&offset=N&from=&to=` and render table rows. Build pager controls.

- [ ] **Step 5: Build, verify, commit**

```
refactor: history page to API-driven pagination (removes 5000-entry server-side load)
```

---

### Task 8: Browser notifications for critical findings

**Covers:** Review item 8

**Files:**
- Modify: `ui/static/js/dashboard.js` — request notification permission, fire on critical

- [ ] **Step 1: Add notification support**

At the top of the IIFE, request permission:
```js
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}
```

In `addEntry(f)`, fire a browser notification for critical findings:
```js
if (f.severity === 2 && 'Notification' in window && Notification.permission === 'granted') {
    new Notification('CSM Critical Alert', {
        body: f.check + ': ' + f.message,
        tag: f.check + ':' + f.message
    });
}
```

- [ ] **Step 2: Commit**

```
feat: browser notifications for critical findings on dashboard
```

---

## Phase 3: Feature Additions

### Task 9: Bulk unblock on firewall page

**Covers:** Review item 12

**Files:**
- Modify: `internal/webui/api.go` — add `/api/v1/unblock-bulk` endpoint
- Modify: `internal/webui/server.go` — register new route
- Modify: `ui/static/js/firewall.js` — add checkboxes, select-all, bulk unblock

- [ ] **Step 1: Add bulk unblock API endpoint**

In `api.go`, add `apiUnblockBulk` that accepts `{"ips": ["1.2.3.4", ...]}`, iterates, unblocks each, flushes cphulk, audit logs, and returns results.

- [ ] **Step 2: Register route**

```go
mux.Handle("/api/v1/unblock-bulk", s.requireCSRF(s.requireAuth(http.HandlerFunc(s.apiUnblockBulk))))
```

- [ ] **Step 3: Add checkboxes and bulk unblock UI to firewall.js**

In `loadBlocked()`, add checkbox column to table header and each row. Add select-all checkbox and "Bulk Unblock" button.

- [ ] **Step 4: Build, verify, commit**

```
feat: bulk unblock IPs on firewall page
```

---

### Task 10: Firewall page GeoIP enrichment

**Covers:** Review item 13

**Files:**
- Modify: `ui/static/js/firewall.js` — fetch GeoIP for blocked IPs, add country column

- [ ] **Step 1: Enrich blocked IPs with GeoIP**

After rendering blocked IPs table, fetch `/api/v1/geoip?ip=X` for each row (throttled to avoid hammering) and populate a "Location" column with country and ASN info.

- [ ] **Step 2: Commit**

```
feat: GeoIP enrichment for blocked IPs on firewall page
```

---

### Task 11: Quarantine file content viewer

**Covers:** Review item 11

**Files:**
- Modify: `internal/webui/api.go` — add `/api/v1/quarantine-preview` endpoint
- Modify: `internal/webui/server.go` — register route
- Modify: `ui/static/js/quarantine.js` — add "View" button and content modal

- [ ] **Step 1: Add quarantine preview API**

In `api.go`, add `apiQuarantinePreview` that reads the first 8KB of a quarantined file, sanitizes the ID with `filepath.Base()`, and returns `{id, preview, truncated, total_size}`.

- [ ] **Step 2: Register route (read-only, no CSRF)**

```go
mux.Handle("/api/v1/quarantine-preview", s.requireAuth(http.HandlerFunc(s.apiQuarantinePreview)))
```

- [ ] **Step 3: Add View button and modal to quarantine.js**

Add a "View" button next to each "Restore" button. On click, fetch preview and display in a modal with `<pre>` tag using `CSM.esc()`.

- [ ] **Step 4: Build, verify, commit**

```
feat: quarantine file content preview via View button
```

---

### Task 12: Test notification button

**Covers:** Review item 14

**Files:**
- Modify: `internal/webui/api.go` — add `/api/v1/test-alert` endpoint
- Modify: `internal/webui/server.go` — register route
- Modify: `ui/templates/rules.html` — add button
- Modify: `ui/static/js/rules.js` — add handler

- [ ] **Step 1: Add test alert API**

Send a Warning-level test finding through `alert.Dispatch()`. Audit log the action.

- [ ] **Step 2: Register with CSRF**

```go
mux.Handle("/api/v1/test-alert", s.requireCSRF(s.requireAuth(http.HandlerFunc(s.apiTestAlert))))
```

- [ ] **Step 3: Add button to rules page and JS handler**

Button labeled "Send Test Alert" in the Actions section. JS shows spinner, calls API, toasts result.

- [ ] **Step 4: Build, verify, commit**

```
feat: test alert button on rules page to verify notification delivery
```

---

### Task 13: Scan progress indicator

**Covers:** Review item 25

**Files:**
- Modify: `internal/webui/api.go` — expose scan status in `/api/v1/status`
- Modify: `ui/templates/dashboard.html` — add scan status card
- Modify: `ui/static/js/dashboard.js` — refresh scan status

- [ ] **Step 1: Expose scan status in apiStatus**

Add `scan_running` and `last_scan_time` fields to the status response.

- [ ] **Step 2: Add scan status card to dashboard**

New card showing "Scanning..." or "Idle" with "Last scan: X ago".

- [ ] **Step 3: Update dashboard.js to refresh scan status**

In the stats refresh interval, also fetch `/api/v1/status` and update the scan indicator.

- [ ] **Step 4: Build, verify, commit**

```
feat: scan progress indicator on dashboard
```

---

### Task 14: Trend charts (30-day)

**Covers:** Review item 10

**Files:**
- Modify: `internal/webui/api.go` — add `/api/v1/stats/trend` endpoint
- Modify: `internal/webui/server.go` — register route
- Modify: `ui/templates/dashboard.html` — add trend chart container
- Modify: `ui/static/js/dashboard.js` — fetch and render trend chart

- [ ] **Step 1: Add trend API endpoint**

Returns 30 daily buckets with critical/high/warning/total counts, scanning history.

- [ ] **Step 2: Register route**

```go
mux.Handle("/api/v1/stats/trend", s.requireAuth(http.HandlerFunc(s.apiStatsTrend)))
```

- [ ] **Step 3: Add trend chart container to dashboard.html**

New card below the 24h timeline: "30-Day Trend" with a `<div id="trend-chart">`.

- [ ] **Step 4: Render SVG bar chart in dashboard.js**

Fetch `/api/v1/stats/trend`, render 30 bars with severity-based colors and date labels.

- [ ] **Step 5: Build, verify, commit**

```
feat: 30-day findings trend chart on dashboard
```

---

## Phase 4: Major Features

### Task 15: Suppression rules

**Covers:** Review item 21

**Files:**
- Create: `internal/webui/suppressions_api.go` — CRUD API for suppression rules
- Modify: `internal/state/state.go` — add suppression storage and filtering
- Modify: `internal/webui/server.go` — register routes
- Modify: `internal/webui/handlers.go` — apply suppressions to findings view
- Modify: `internal/webui/api.go` — apply suppressions to findings API
- Modify: `ui/templates/findings.html` — add "Suppress" action button
- Modify: `ui/static/js/findings.js` — add suppress action handler
- Modify: `ui/templates/rules.html` — add suppressions management section
- Modify: `ui/static/js/rules.js` — add suppression list/delete handlers

Suppression rules stored as JSON at `{StatePath}/suppressions.json`. Each rule matches by `check` type and optional `path_pattern` glob. Suppressed findings are hidden from UI/API but still in history.

- [ ] **Step 1: Define suppression types in state.go**

```go
type SuppressionRule struct {
    ID          string    `json:"id"`
    Check       string    `json:"check"`
    PathPattern string    `json:"path_pattern,omitempty"`
    Reason      string    `json:"reason"`
    CreatedAt   time.Time `json:"created_at"`
}
```

Add methods: `LoadSuppressions()`, `SaveSuppressions()`, `IsSuppressed(f)`.

- [ ] **Step 2: Create suppressions API in suppressions_api.go**

GET/POST/DELETE on `/api/v1/suppressions` with method-based dispatch.

- [ ] **Step 3: Apply suppressions in handleFindings and apiFindings**

Add `s.store.IsSuppressed(f)` check to filter loops.

- [ ] **Step 4: Add "Suppress" button to findings page**

Button triggers a prompt for optional path pattern, then POSTs to API.

- [ ] **Step 5: Add suppression management to rules page**

Table of active rules with "Remove" button for each.

- [ ] **Step 6: Build, verify, commit**

```
feat: suppression rules to hide recurring false-positive findings
```

---

### Task 16: Per-account security view

**Covers:** Review items 9 (per-account view) and 24 (cPanel integration hooks)

**Files:**
- Create: `internal/webui/account_api.go` — account detail API
- Modify: `internal/webui/server.go` — register routes, add page handler
- Create: `ui/templates/account.html` — account detail page
- Create: `ui/static/js/account.js` — account page JS
- Modify: `ui/static/js/findings.js` — make account names clickable

- [ ] **Step 1: Add account detail API in account_api.go**

GET `/api/v1/account?name=X` returns aggregated data: findings, quarantined files, history, and blocked IPs filtered to the account. Account matched by `/home/{name}/` in paths and messages.

- [ ] **Step 2: Register routes**

```go
mux.Handle("/account", s.requireAuth(http.HandlerFunc(s.handleAccount)))
mux.Handle("/api/v1/account", s.requireAuth(http.HandlerFunc(s.apiAccountDetail)))
```

- [ ] **Step 3: Create account.html**

Page sections: account header with WHM link, current findings, quarantined files, recent history, associated blocked IPs.

- [ ] **Step 4: Create account.js**

Fetch `/api/v1/account?name=X`, populate each section with tables, add fix/dismiss handlers.

- [ ] **Step 5: Make account names clickable in findings.js**

Detect `/home/{user}/` patterns in messages and link to `/account?name={user}`.

- [ ] **Step 6: Build, verify, commit**

```
feat: per-account security view with findings, quarantine, and history
```

---

### Task 17: Remediation action tracking

**Covers:** Review item 20

**Files:**
- Modify: `internal/webui/api.go` — add `/api/v1/finding-detail` endpoint
- Modify: `internal/webui/audit.go` — add search-by-target to audit queries
- Modify: `internal/webui/server.go` — register route
- Modify: `ui/static/js/findings.js` — show remediation history on finding expand
- Modify: `ui/templates/findings.html` — add expandable detail row structure

- [ ] **Step 1: Add audit search function**

In `audit.go`, add function that queries `ui_audit.jsonl` for entries matching a target string.

- [ ] **Step 2: Add finding detail API**

GET `/api/v1/finding-detail?check=X&message=Y` returns the finding, related audit actions, and related historical findings with the same check type.

- [ ] **Step 3: Register route**

```go
mux.Handle("/api/v1/finding-detail", s.requireAuth(http.HandlerFunc(s.apiFindingDetail)))
```

- [ ] **Step 4: Show remediation history in findings.js**

When finding row is clicked, fetch detail API, show expandable row below with auto-response actions taken, recurrence count, and related findings.

- [ ] **Step 5: Build, verify, commit**

```
feat: show remediation action history for each finding
```

---

### Task 18: Incident timeline view

**Covers:** Review item 19

**Files:**
- Create: `internal/webui/incident_api.go` — incident correlation API
- Modify: `internal/webui/server.go` — register routes
- Create: `ui/templates/incident.html` — incident timeline page
- Create: `ui/static/js/incident.js` — timeline rendering
- Modify: `ui/templates/layout.html` — add nav link

Correlates events by IP address and account across all data sources (threat DB, findings history, firewall audit, UI audit, quarantine) into a unified chronological timeline.

- [ ] **Step 1: Add incident correlation API in incident_api.go**

GET `/api/v1/incident?ip=X` or `?account=X&hours=24` returns a unified timeline of all related events sorted by timestamp. Each event: `{timestamp, type, severity, summary, details, source}`.

- [ ] **Step 2: Register routes**

```go
mux.Handle("/incident", s.requireAuth(http.HandlerFunc(s.handleIncident)))
mux.Handle("/api/v1/incident", s.requireAuth(http.HandlerFunc(s.apiIncident)))
```

- [ ] **Step 3: Create incident.html**

Page with IP/account search bar, summary cards (total events, time span, involved accounts/IPs), and timeline container.

- [ ] **Step 4: Create incident.js**

Fetch API, render vertical timeline with color-coded event types and expandable details. Add entry points from threat page and findings page.

- [ ] **Step 5: Add nav link to layout.html**

Add "Incidents" link between "Threat Intel" and "Rules".

- [ ] **Step 6: Build, verify, commit**

```
feat: incident timeline view correlating events by IP and account
```

---

### Task 19: Export/import state

**Covers:** Review item 23

**Files:**
- Modify: `internal/webui/api.go` — add export/import endpoints
- Modify: `internal/webui/server.go` — register routes
- Modify: `ui/templates/rules.html` — add export/import buttons
- Modify: `ui/static/js/rules.js` — add export/import handlers

- [ ] **Step 1: Add export API**

GET `/api/v1/export` returns JSON bundle of suppressions, whitelist, blocked IPs, blocked subnets. No config (contains secrets) or history (too large).

- [ ] **Step 2: Add import API**

POST `/api/v1/import` accepts the same JSON bundle, merges with existing state (dedup by ID/IP).

- [ ] **Step 3: Register routes**

```go
mux.Handle("/api/v1/export", s.requireAuth(http.HandlerFunc(s.apiExport)))
mux.Handle("/api/v1/import", s.requireCSRF(s.requireAuth(http.HandlerFunc(s.apiImport))))
```

- [ ] **Step 4: Add export/import buttons to rules page**

Export button triggers download. Import button uses file input with FileReader to upload JSON.

- [ ] **Step 5: Build, verify, commit**

```
feat: export/import state (suppressions, whitelist, blocked IPs)
```

---

## Final Steps

### Task 20: Full build, test, and push

- [ ] **Step 1: Full build and test**

```bash
GOOS=linux go build ./...
go test ./... -short
```

- [ ] **Step 2: Verify all new routes are registered in server.go**

- [ ] **Step 3: Verify navigation links**

- [ ] **Step 4: Push**

```bash
git push
```
