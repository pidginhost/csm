# CSM Web UI Roadmap

Forward-looking engineering plan to refine the operator web UI
(`internal/webui` + `ui/`) to production-grade polish. Items move from
here into commits + `CHANGELOG.md` entries as they land, then drop off
this list.

This file is for contributors. End-user documentation lives in `docs/`.
The companion `ROADMAP.md` covers daemon/detection work.

**Stable cross-references.** Older commits or CHANGELOG entries may
reference `WEB_ROADMAP item N` by frozen number. To resolve a historical
reference, search `git log` and `CHANGELOG.md` rather than this file.

The roadmap is split into six phases, ordered by risk reduction first
(security + reliability), then user-impact (UX foundation, feature
parity), then polish, then power features. Each phase lists discrete
steps. A step is one self-reviewable commit.

---

## Phase 1: Security + reliability

**Goal:** Close XSS surfaces, fix indefinite-hang polling, and bound
memory growth on unbounded handlers. No user-visible feature change.
This phase is a blocker for further refactors: every phase below adds
new fetches, new tables, and new state, and must build on hardened
primitives.

### Step 1.1: Audit and fix `innerHTML` callers in JS

Replace every `innerHTML =` and `insertAdjacentHTML` in `ui/static/js`
that interpolates server data with safe DOM construction or
`CSM.esc()`-wrapped strings. Files of immediate concern:
`findings.js` (err rendering, badge HTML), `cleanup-history.js`
(stateBadge, restore/delete row HTML), `csm-ui.js` (`summaryItem`),
`audit.js` (data-timestamp round trip), `dashboard.js` (queue rows).

**Acceptance:** grep `'innerHTML\s*='` across `ui/static/js` returns
only static HTML literals or call sites where every interpolated value
is wrapped in `CSM.esc()`. Add a `static_ui_test.go` regression that
parses each `.js` file and flags unsafe patterns.

### Step 1.2: Centralize fetch through `CSM.request`

`csrf.js`, `dashboard.js`, and `audit.js` call raw `fetch` for
polling. These have no timeout, no `AbortController`, and silently
freeze on a hung backend. Move every fetch in `ui/static/js` (excluding
vendored libs) through `CSM.request` with a default 30s timeout and an
explicit per-call override. Polling helpers (`CSM.poll`) use the same
path.

**Acceptance:** grep `'\bfetch\('` across `ui/static/js` returns only
calls inside `csrf.js` `CSM.request`. Add a unit test exercising
`CSM.poll` timeout and visibility-change behavior via JSDOM-style stub
in the existing test harness (or skip if not feasible and assert via
grep contract).

### Step 1.3: Harden `CSM.poll` lifecycle

Polling must survive (a) `run()` throwing before `.finally`, (b) tab
hidden/visible cycles without leaking listeners, (c) network errors
without busy-looping, (d) explicit `stop()` releasing all listeners.
Switch to a state machine: `idle | running | scheduled | stopped`.
Visibility listener attached once at module load, dispatches to active
pollers via a registry.

**Acceptance:** existing pages keep polling at current intervals; new
test asserts pollers survive injected errors and unbind on `stop()`.

### Step 1.4: SSE deadline + reconnect

`api_events.go` used to clear the write deadline, and active SSE
clients could keep graceful shutdown waiting. Use a finite per-write
deadline below the daemon shutdown budget, fail closed if deadlines are
unsupported, and make streams exit as soon as shutdown starts.

Client-side reconnect + "stream disconnected, retrying" banner is
deferred: no JS consumer exists for `/api/v1/events` today (the
dashboard polls instead). Wire when an `EventSource` consumer lands,
likely alongside the SSE health pill in Step 5.6.

**Acceptance:** server shutdown returns with an active SSE client;
unsupported write-deadline writers return 500; targeted tests pin both
contracts.

### Step 1.5: Bound memory on history/incident/modsec handlers

Three handlers load full result sets before applying output caps:

- `webui/api.go` `apiHistory` (5000-record cap loaded in full before
  filter).
- `webui/incident_api.go` `apiIncident` (loads all matches before 200
  cap).
- `webui/modsec_api.go` `apiModSecBlocks` (unbounded dedup map).

Push pagination into the store query, cap dedup maps at a configurable
ceiling (default 50000 entries) with eviction, and surface "truncated"
flags in API responses so the UI can show a "partial results" warning.

**Acceptance:** load tests with synthetic data (100k findings) keep
each handler under 100MB RSS and complete in under 1s.

### Step 1.6: Verify CSRF coverage end-to-end

Login form, settings POSTs, firewall mutators, modsec actions, and
account actions must all carry CSRF tokens. Audit `csrf.js`
interceptor, add server-side enforcement test asserting every
non-GET/HEAD/OPTIONS route requires either a valid CSRF header or a
Bearer token. Document the contract in a comment block in
`webui/server.go`.

**Acceptance:** new test in `webui` package iterates the registered
mux and POSTs to every non-GET route without CSRF, asserts 403.

### Step 1.7: Cookie + path-traversal hardening

`webui/email_api.go` `apiEmailQuarantineAction` uses `filepath.Base()`
but does not verify the final path lives under the quarantine root.
`webui/account_api.go` builds WHM URLs by concatenation. `webui/api.go`
runs `whmapi1` with caller-validated IPs; one missed call site is an
injection. Add a `mustBeWithin(root, candidate)` helper and a
`mustBeValidIP`/`mustBeValidAccount` wrapper around exec calls, plus
session cookie audit (HttpOnly, Secure, SameSite=Strict where
applicable).

**Acceptance:** new unit tests cover the helpers; existing handler
tests prove the helpers are wired.

### Phase 1 size

5-7 days. Touches `ui/static/js/*.js`, `internal/webui/*.go`,
`internal/webui/static_ui_test.go`.

---

## Phase 2: UX foundation

**Goal:** Standardize URL state, auto-refresh, and table behavior
across every page so the user learns one pattern instead of sixteen.

### Step 2.1: URL state scheme

Adopt one convention: query string for filter/search/page state, hash
for in-page anchors (tab + entity ID). Refactor `findings`,
`firewall`, `incident`, `audit`, `threat`, `settings` to share a
`CSM.urlState` API for read/write/sync. Existing query string keys
documented as stable contracts.

### Step 2.2: Sortable / paginated / searchable tables via `table.js`

Every data table (findings, firewall lists, incident grouped + linear,
audit, threat attackers, quarantine, email, modsec blocks, modsec
rules, cleanup history) uses `table.js` with sort, search, and
pagination uniformly. One toolbar layout, one empty-state component,
one loading skeleton.

### Step 2.3: Auto-refresh standardization

Global "data age" pill in the layout header showing seconds since last
fetch, plus an auto-refresh toggle. Per-page registers a fetcher; pill
calls it on interval, pauses when tab hidden, surfaces failure with
exponential backoff.

### Step 2.4: Shared CSV/JSON exporter

Extract per-page CSV/JSON download code into `CSM.export(rows, cols,
filename)`. Adds export to pages currently missing it (performance,
hardening, account, ModSec rules suppressions).

### Step 2.5: Bulk-action framework

`csm-ui.js` exports `CSM.bulk({checkboxSelector, actions, endpoint})`
that handles select-all, partial-select indicator, action button
enable/disable, optimistic UI, undo banner, and toast on completion.
Replace per-page bulk wiring (findings, threat, quarantine,
cleanup-history) and finish half-built buttons (threat
block/whitelist, rules import, findings fix).

### Phase 2 size

6-8 days.

---

## Phase 3: Feature parity

**Goal:** Every page that handles a list has search + filter + sort +
pagination + export + bulk where applicable.

### Step 3.1: Audit page filter pack

Date range, action type, actor filters. Export CSV/JSON.

### Step 3.2: Account page per-tab filters

Apply findings/quarantine filters scoped to the displayed account.

### Step 3.3: Quarantine filters

Account, date range, detector source filters; existing filename search
stays.

### Step 3.4: Email quarantine toolbar

Search by sender/recipient/subject; date range; size filter; bulk
release/delete.

### Step 3.5: Threat attackers pagination + date filter

Server-side pagination, date range, country filter.

### Step 3.6: Performance + hardening exports

JSON/CSV download of current findings + a printable report variant.

### Step 3.7: ModSec blocks bulk toggle

Bulk enable/disable rules from the blocks tab; share `CSM.bulk`.

### Step 3.8: Settings query-string deep-linking

Drop hash-only nav for query-string `?section=` to enable bookmarking
+ external links.

### Phase 3 size

5-7 days.

---

## Phase 4: Polish

**Goal:** Cosmetic + accessibility + cleanup.

### Step 4.1: Resolve duplicate IDs

Namespace per page (`fw-`, `tr-`, `ms-`) to remove the duplicate IDs
across `firewall.html` / `threat.html` / `audit.html` /
`modsec-rules.html` / `rules.html`.

### Step 4.2: Accessibility patches

`account.html` tabs to ARIA (`role=tab`, `aria-selected`,
`aria-controls`). Add missing aria-labels (`firewall.html`
`block-reason`, `email.html` `filter-from`/`filter-to`, `threat.html`
select-all). Loading states get `aria-busy`. Toasts get an
`aria-live=assertive` error region. Modal focus trap.

### Step 4.3: Dead-code removal

`js/email.js` unused `EMAIL_FINDINGS_LIMIT`, dashboard.html long
comment block, any `_test.go` file with weak/skipped assertions
(`low_coverage_test.go`, `more_coverage_test.go`,
`push_further_test.go` per AGENTS.md "no `t.Skip` as coverage
workaround").

### Step 4.4: Half-built features finished or removed

`findings.html` Fix button (wire to fix API or remove). `rules.html`
Import State (upload UX + feedback or remove). Decisions documented in
commit body.

### Phase 4 size

3-4 days.

---

## Phase 5: Power features

**Goal:** Move from "good ops UI" to "one of the best".

**Status:** P5.1, P5.5, P5.6, P5.7 landed (commits ed712030, 227e3f9a,
ebbf08be, fb0146ab and their codex fixups). P5.2, P5.3, P5.4 are
deferred — each needs a server-side operator-preferences store that
does not exist yet, so they are tracked separately in `ROADMAP.md`.

### Step 5.1: Command palette (Ctrl-K)

**Status:** done (commits ed712030, 9bb038e3).

Global jump: page navigation + entity search (account, IP, finding
ID, ModSec rule ID). Reuses `shortcuts.js`.

### Step 5.2: Saved filter views

Per-page named view dropdown ("Critical SSH brute force last 7d").
Stored server-side under operator session for cross-browser
persistence.

### Step 5.3: Bulk-action undo

Within 30s of a bulk fix/quarantine/block/whitelist, banner offers
"Undo last batch". Backend records inverse operation in the audit log.

### Step 5.4: User preferences server-side

Density (dense/cozy), timezone (server vs local vs explicit), default
auto-refresh on/off, per-table column visibility. Replace localStorage
table state for these.

### Step 5.5: Keyboard shortcut overlay

**Status:** done (commits 227e3f9a, e05deb80).

`?` opens a modal listing every shortcut, grouped by context.

### Step 5.6: SSE health pill

**Status:** done (commits ebbf08be, d5346f41).

Tied to step 1.4: show connected / reconnecting / disconnected state
in header.

### Step 5.7: What's new badge

**Status:** done (commit fb0146ab; codex review clean).

Read CHANGELOG `[Unreleased]` block (or last tag) and surface a small
notification dot until acknowledged.

### Phase 5 size

8-12 days.

---

## Phase 6: Mobile, print, CSP

**Goal:** Reach environments outside desktop Chrome.

**Status:** all four steps landed.

### Step 6.1: Responsive tables + nav

**Status:** done (commits a85a3912, 0b5a1c2a).

Horizontal scroll wrappers, collapsible sidebar at small breakpoints,
verified at 360px / 768px / 1024px.

### Step 6.2: Print stylesheet

**Status:** done (commits 057589f7, f376aca1).

Incident and audit pages used as evidence. Print CSS hides nav,
expands tables, includes timestamps + URL footer.

### Step 6.3: CSP nonces

**Status:** done (commits b85c8a12, 24e4af3e). The page already
shipped with `script-src 'self'` and the only inline `<script>` is a
`type="application/json"` data block (not executed by browsers), so no
nonce was needed. Closed the runtime `<style>` injection in
`shortcuts.js` and added regression coverage that parses the live CSP
header plus HTML templates.

Move every inline `<script>` to either an external file or a
nonce-tagged inline. Add `Content-Security-Policy` header in
`server.go` with `script-src 'self' 'nonce-...'`.

### Step 6.4: Dark mode contrast audit

**Status:** done (commits b397b63c, 15471f6d).

Run badge palette through WCAG AA contrast check in dark theme; fix
failing combinations.

### Phase 6 size

3-5 days.
