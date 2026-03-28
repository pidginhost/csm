# WebUI TODO

All items from comprehensive code review. Status: 26 FIXED, 1 KEPT, 1 DEFERRED.

---

## Code Quality & Refactoring

- CQ-1: Remove redundant POST method checks -- **KEPT** (defense-in-depth)
- CQ-2: Deduplicate cphulk flush -- **FIXED** (extracted `flushCphulk` helper)
- CQ-3: Deduplicate blocked-IP expiry formatting -- **FIXED** (extracted `formatBlockedView`)
- CQ-4: Replace `containsBytes` with `bytes.Contains` -- **FIXED**
- CQ-5: Replace `parseIntSimple` with `queryInt` -- **FIXED**
- CQ-6: Move `geoIPDB` to Server field -- **FIXED**
- CQ-7: Eliminate dual-path dashboard -- **DEFERRED** (medium effort, works correctly)
- CQ-8: Use `writeJSON` in `apiRulesReload` -- **FIXED**
- CQ-9: Deduplicate `fmtSize`/`formatSize` -- **FIXED** (`CSM.formatSize`)
- CQ-10: Share `fmtDate` -- **FIXED** (`CSM.fmtDate`)
- CQ-11: Pre-allocate slice in `handleHistory` -- **FIXED**

## Performance

- P-1: Cache firewall state reads -- **DEFERRED** (low risk, fast reads)
- P-2: Dashboard timeline via API -- **DEFERRED** (coupled to CQ-7)
- P-3: Top attackers limit dropdown -- **DEFERRED** (low impact)
- P-4: WebSocket server pings -- **FIXED** (30s ping ticker)

## Security Hardening

- S-1: CSP strict style-src -- **FIXED** (created csm.css, dropped `unsafe-inline`)
- S-2: API rate limiting -- **FIXED** (120 req/min per IP)
- S-3: WebSocket http:// origin -- **FIXED** (removed)
- S-4: Quarantine restore O_EXCL -- **FIXED** (streaming + conflict detection)
- S-5: Single quarantineDir constant -- **FIXED**
- S-6: CSRF token rotation -- **FIXED** (includes startTime)

## UX Polish

- U-1: Nav active with query params -- **FIXED** (indexOf)
- U-2: Pagination controls placement -- **FIXED** (appends to `.card`)
- U-3: Show total unfiltered count -- **FIXED** ("3 of 3 (150 total)")
- U-4: Bulk selection reset on render -- **FIXED** (onRender callback)
- U-5: Firewall coordinated fetches -- **DEFERRED** (low impact)
- U-6: Threat chart offsetWidth -- **DEFERRED** (low impact, fallback works)
- U-7: Modal focus trap -- **FIXED** (Tab cycling + Escape)
- U-8: Login dark mode -- **FIXED** (data-bs-theme)
- U-9: Item counts in headers -- **FIXED** (quarantine + audit)

## Architecture

- A-1: requireAuth 401 for API -- **FIXED**
- A-2: CSM.post error body -- **FIXED**
- A-3: fixableChecks from server -- **DEFERRED** (needs server change)
- A-4: History page API-driven -- **DEFERRED** (medium effort)
- A-5: Remove unused skeleton -- **FIXED** (deleted)
- A-6: Create csm.css -- **FIXED** (all inline styles extracted)
