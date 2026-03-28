# WebUI TODO

Items identified from comprehensive code review. Grouped by category, sorted by impact.

---

## Code Quality & Refactoring

### CQ-1: Remove redundant POST method checks -- KEPT
`requireCSRF` only validates CSRF on POST but doesn't reject other methods. The handler-level POST checks are defense-in-depth. Keeping them.

### CQ-2: Deduplicate IP unblock + cphulk flush logic -- FIXED
Extracted `flushCphulk(ip)` helper in api.go, replaced all 5 occurrences.

### CQ-3: Deduplicate blocked-IP expiry formatting -- DEFERRED
Low impact, the two code paths are in the same function and easy to follow.

### CQ-4: Replace `containsBytes` with `bytes.Contains` -- FIXED
Replaced with stdlib `bytes.Contains`, deleted custom helper.

### CQ-5: Replace `parseIntSimple` with existing `queryInt` -- FIXED
Replaced with `queryInt(r, "limit", 100)`, deleted `parseIntSimple`.

### CQ-6: Move `geoIPDB` from package global to Server field -- DEFERRED
Medium effort — requires updating SetGeoIPDB callers in daemon.go. Low risk since write-once-at-startup.

### CQ-7: Eliminate dual-path dashboard (SSR + JS) -- DEFERRED
Medium effort — requires restructuring dashboard template and JS. Works correctly as-is.

### CQ-8: Use `writeJSON` in `apiRulesReload` -- FIXED
Replaced inline encoder with `writeJSON(w, result)`, removed unused `encoding/json` import.

### CQ-9: Deduplicate `fmtSize`/`formatSize` across JS files -- FIXED
Added `CSM.formatSize(bytes)` to csrf.js, replaced page-local versions in quarantine.js and rules.js.

### CQ-10: Share `fmtDate` as `CSM.fmtDate` -- FIXED
Added `CSM.fmtDate(isoStr)` to csrf.js, replaced page-local version in threat.js.

### CQ-11: Pre-allocate slice in `handleHistory` -- FIXED
Changed `var items []historyEntry` to `items := make([]historyEntry, 0, len(findings))`.

---

## Performance

### P-1: Cache firewall state reads -- DEFERRED
Medium effort — needs new caching struct. Low risk since reads are fast (small JSON file).

### P-2: Dashboard embeds timeline JSON in HTML then re-parses -- DEFERRED
Coupled to CQ-7 (dual-path dashboard). Works correctly as-is.

### P-3: Top attackers hardcodes limit=50 -- DEFERRED
Low impact UX improvement.

### P-4: No WebSocket server-initiated pings -- DEFERRED
Medium effort — needs changes to websocket write loop. Idle connections time out but reconnect.

---

## Security Hardening

### S-1: CSP allows `style-src 'unsafe-inline'` -- DEFERRED
Coupled to A-6 (creating csm.css). Medium effort — requires extracting all inline styles.

### S-2: No rate limiting on read API endpoints -- DEFERRED
Medium effort — needs new middleware. Risk is low since all endpoints require auth.

### S-3: WebSocket allows `http://` origins -- FIXED
Removed `"http://" + host` from validOrigins. Server only listens on TLS.

### S-4: Quarantine restore silently overwrites existing files -- FIXED
Changed to `os.OpenFile` with `O_EXCL` flag + `io.Copy` streaming. Returns 409 Conflict if file already exists.

### S-5: `quarantineDir` hardcoded in two places -- FIXED
Moved to single package-level constant.

### S-6: CSRF token is static — never rotates -- FIXED
Now uses `HMAC(authToken, "csm-csrf-v1:" + startTime.Unix())` so token rotates on each restart.

---

## UX Polish

### U-1: Active nav not highlighted with query params -- FIXED
Changed from `===` to `indexOf(href) === 0` for pathname matching.

### U-2: Pagination controls inside `table-responsive` overflow container -- DEFERRED
Medium effort — needs careful testing across all table pages.

### U-3: Filtered table doesn't show total unfiltered count -- DEFERRED
Low impact UX improvement.

### U-4: Bulk selection state goes stale on page change -- DEFERRED
Needs onRender callback in CSM.Table — medium effort.

### U-5: Firewall page: 4 uncoordinated fetches -- DEFERRED
Low impact — each section handles its own error state.

### U-6: Threat chart reads `offsetWidth` before layout -- DEFERRED
Low impact — fallback to 500px works in practice.

### U-7: Confirm/prompt modals don't trap keyboard focus -- FIXED
Added keydown listener for Tab focus trapping and Escape to cancel. OK button auto-focused on open.

### U-8: Login page dark mode doesn't set `data-bs-theme` -- FIXED
Added `document.documentElement.setAttribute('data-bs-theme', theme)` and className.

### U-9: Quarantine and audit pages show no item count -- FIXED
Both now update card title with count after data loads.

---

## Architecture

### A-1: `requireAuth` returns HTML redirect for API calls -- FIXED
API paths now get `401 {"error":"unauthorized"}` JSON instead of 302 redirect.

### A-2: `CSM.post` throws away JSON error body -- FIXED
Now tries `r.json()` first to extract `body.error`, falls back to HTTP status code.

### A-3: `fixableChecks` JS object duplicates server-side `HasFix` -- DEFERRED
Needs server-side change to include `has_fix` in scan results. Medium effort.

### A-4: History page mixes SSR date filtering with client-side search -- DEFERRED
Medium effort — needs full rewrite of history page to API-driven. Works correctly as-is.

### A-5: `CSM.skeleton` loaded on every page but never called -- DEFERRED
Low impact — skeleton infrastructure is ready but unused. Can wire in later.

### A-6: No `csm.css` file — all custom CSS in inline `<style>` blocks -- DEFERRED
Coupled to S-1 (strict CSP). Medium effort — requires extracting all inline styles from templates.
