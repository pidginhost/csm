package webui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSharedEscapeHelperEscapesQuotedAttributes(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`.replace(/"/g, '&quot;')`,
		`.replace(/'/g, '&#39;')`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing attribute escaping fragment %q", fragment)
		}
	}
}

func TestSharedFormattingHelpersHandleMissingValues(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`if (n == null || (typeof n === 'string' && n.trim() === '')) return '';`,
		`if (v == null || (typeof v === 'string' && v.trim() === '')) return '';`,
		`d = Math.min(20, Math.floor(d));`,
		`parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing formatter guard fragment %q", fragment)
		}
	}
}

func TestWebUIToastCallsUseSupportedErrorType(t *testing.T) {
	files := webUISourceFiles(t, "../../ui/static/js/*.js", "../../ui/templates/*.html")
	dangerToast := regexp.MustCompile(`(?s)\b(?:CSM\.)?toast\s*\([^;]*,\s*['"]danger['"]`)
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if dangerToast.Match(src) {
			t.Errorf("%s passes unsupported danger type to CSM.toast; use error", path)
		}
	}
}

func TestRulesSuppressionCreatedAtUsesSharedDateFormat(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/rules.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "new Date(s.created_at).toLocaleString()") {
		t.Fatal("rules.js still formats suppression creation dates with browser locale")
	}
	if !strings.Contains(text, "var created = CSM.fmtDate(s.created_at);") {
		t.Fatal("rules.js must format suppression creation dates with CSM.fmtDate")
	}
}

func TestThreatIntelBulkCheckboxUsesCSPCompliantListener(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/threat.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, `onclick="`) {
		t.Fatal("threat.js still renders an inline onclick handler")
	}
	if !strings.Contains(text, `cb.addEventListener('click', function(e) { e.stopPropagation(); });`) {
		t.Fatal("threat.js missing checkbox click stopPropagation listener")
	}
}

func TestIncidentPageRendersCorrelatedIncidentSurface(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/incident.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile("../../ui/static/js/incident.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpl), `id="incidents-panel"`) {
		t.Fatal("incident page missing correlated incidents panel")
	}
	if !strings.Contains(string(js), `/api/v1/incidents`) {
		t.Fatal("incident.js does not load correlated incidents API")
	}
	if strings.Contains(string(js), `onclick="`) {
		t.Fatal("incident.js must not render inline onclick handlers")
	}
}

func TestNoInlineEventHandlersAcrossWebUISources(t *testing.T) {
	files := webUISourceFiles(t, "../../ui/static/js/*.js", "../../ui/templates/*.html")
	inlineEvent := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if inlineEvent.Match(src) {
			t.Errorf("%s contains an inline event handler; bind via addEventListener", path)
		}
	}
}

func TestNoInlineStyleAttributesAcrossWebUISources(t *testing.T) {
	files := webUISourceFiles(t, "../../ui/static/js/*.js", "../../ui/templates/*.html")
	inlineStyle := regexp.MustCompile(`(?i)\sstyle\s*=\s*["']`)
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if inlineStyle.Match(src) {
			t.Errorf("%s contains an inline style attribute; move static styles to csm.css", path)
		}
	}
}

func webUISourceFiles(t *testing.T, patterns ...string) []string {
	t.Helper()
	skip := map[string]struct{}{
		"chart.min.js":  {},
		"tabler.min.js": {},
	}
	var out []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 0 {
			t.Fatalf("no files matched %s", pattern)
		}
		for _, path := range matches {
			base := filepath.Base(path)
			if _, ok := skip[base]; ok {
				continue
			}
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		t.Fatal("no Web UI source files found")
	}
	return out
}

func sourceHasClass(text, className string) bool {
	classAttr := regexp.MustCompile(`class="([^"]*)"`)
	for _, match := range classAttr.FindAllStringSubmatch(text, -1) {
		for _, field := range strings.Fields(match[1]) {
			if field == className {
				return true
			}
		}
	}
	return false
}

// TestSharedUIPrimitivesPresent asserts the Phase 1 shared CSS classes and JS
// helpers exist. Pages adopt them in later phases; the test stops the
// primitives from drifting away while phases roll out.
func TestSharedUIPrimitivesPresent(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(css)
	wantClasses := []string{
		".csm-page-header",
		".csm-status-strip",
		".csm-queue-item",
		".csm-toolbar",
		".csm-summary-list",
		".csm-truncate-middle",
		".csm-empty",
		".csm-sticky-actions",
		".csm-detail-panel",
		".csm-danger-zone",
		".csm-table-rowcard",
		".csm-table-sticky",
	}
	for _, cls := range wantClasses {
		if !strings.Contains(cssText, cls) {
			t.Errorf("csm.css missing shared primitive %s", cls)
		}
	}
	// Renamed in phase 8 -- catch any straggler that still references the old
	// class so the design system stays canonical.
	if strings.Contains(cssText, ".csm-filter-toolbar") {
		t.Error("csm.css still defines .csm-filter-toolbar; renamed to .csm-toolbar")
	}

	js, err := os.ReadFile("../../ui/static/js/csm-ui.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"CSM.emptyStateBlock",
		"CSM.detailPanel",
		"CSM.applyProgressBars",
		"CSM.summaryItem",
		"CSM.truncateMiddle",
		"CSM.applyTruncateMiddle",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("csm-ui.js missing helper %s", want)
		}
	}

	tbl, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	tblText := string(tbl)
	for _, want := range []string{
		"clearFilters",
		"_renderEmptyState",
		"mobileRowCard",
		"_applyMobileRowLabels",
		"setAttribute('data-label'",
		"density",
		"countTargetId",
		"perPageSelectId",
		"onRowClick",
		"stickyHeader",
	} {
		if !strings.Contains(tblText, want) {
			t.Errorf("table.js missing extension hook %s", want)
		}
	}
	restoreIdx := strings.Index(tblText, "this._restoreState(opts);")
	if restoreIdx < 0 || !strings.Contains(tblText[restoreIdx:], "this._syncPerPageSelect(opts);") {
		t.Error("table.js must sync per-page select after restoring persisted state")
	}
}

func TestSharedTablePersistsFilterState(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{
		"tbl._saveState();",
		"filters: filters",
		"state.filters && typeof state.filters === 'object'",
		"this.filterValues[id] = val;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("table.js missing filter-state persistence fragment %q", want)
		}
	}
}

func TestModsecRuleFiltersTrackToggleState(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/modsec-rules.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{
		"setRowAttr(id, 'data-status', newEnabled ? 'enabled' : 'disabled')",
		"row.setAttribute('data-status', original ? 'enabled' : 'disabled');",
		"setRowAttr(id, 'data-escalate', escalate ? 'yes' : 'no')",
		"refreshRulesTable();",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("modsec-rules.js missing live filter-state update fragment %q", want)
		}
	}
}

func TestAuditExportDropdownCoversCSVAndJSON(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/audit.html")
	if err != nil {
		t.Fatal(err)
	}
	templateText := string(tmpl)
	for _, want := range []string{
		`data-bs-toggle="dropdown"`,
		`data-export="csv"`,
		`data-export="json"`,
	} {
		if !strings.Contains(templateText, want) {
			t.Errorf("audit.html missing export dropdown hook %q", want)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/audit.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		`function exportAuditRows()`,
		`document.querySelectorAll('[data-export]')`,
		`format === 'csv'`,
		`format === 'json'`,
		`admin_ip`,
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("audit.js missing export handler fragment %q", want)
		}
	}
}

// TestSidebarNavCoversEveryVisiblePage asserts the sidebar exposes every
// page that is part of the operator workflow. /history and /account are
// reached from deep links and are intentionally not in the sidebar; if
// you remove a page from the sidebar that is not on this allow-list, add
// it back or document the removal.
func TestSidebarNavCoversEveryVisiblePage(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)

	wantHrefs := []string{
		"/dashboard",
		"/incident",
		"/findings",
		"/firewall",
		"/quarantine",
		"/cleanup-history",
		"/email",
		"/modsec",
		"/threat",
		"/performance",
		"/hardening",
		"/rules",
		"/modsec/rules",
		"/audit",
		"/settings",
	}
	for _, href := range wantHrefs {
		needle := `href="` + href + `"`
		if !strings.Contains(text, needle) {
			t.Errorf("layout.html sidebar missing nav entry for %s", href)
		}
	}

	// Each entry must carry a data-csm-route hook so layout.js can light it.
	for _, route := range []string{
		"dashboard", "incident", "findings", "firewall", "quarantine",
		"cleanup-history", "email", "modsec", "threat", "performance",
		"hardening", "rules", "modsec-rules", "audit", "settings",
	} {
		needle := `data-csm-route="` + route + `"`
		if !strings.Contains(text, needle) {
			t.Errorf("layout.html sidebar missing data-csm-route hook %s", route)
		}
	}

	// Layout root carries the page name attribute that drives active state.
	if !strings.Contains(text, `data-csm-page="{{template "page" .}}"`) {
		t.Fatal("layout.html body must expose data-csm-page for sidebar active state")
	}

	// Sidebar groups must be present (workflow names visible to operators).
	for _, group := range []string{"overview", "triage", "response", "operations", "configuration"} {
		needle := `data-csm-nav-group="` + group + `"`
		if !strings.Contains(text, needle) {
			t.Errorf("layout.html sidebar missing group hook %s", group)
		}
		needle = `data-csm-nav-toggle="` + group + `"`
		if !strings.Contains(text, needle) {
			t.Errorf("layout.html sidebar missing group toggle %s", group)
		}
	}
	for _, group := range []string{"Overview", "Triage", "Response", "Operations", "Configuration"} {
		needle := `>` + group + `<`
		if !strings.Contains(text, needle) {
			t.Errorf("layout.html sidebar missing group label %s", group)
		}
	}
}

func TestSidebarNavScopeAndStateHooksPresent(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)
	for _, want := range []string{
		`data-csm-route="modsec-rules" data-csm-admin-only`,
		`data-csm-nav-group="configuration" data-csm-admin-only`,
		`data-csm-route="settings" data-csm-admin-only`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("layout.html missing admin-only nav hook %s", want)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"csm-nav-groups",
		"localStorage.setItem(NAV_GROUP_STATE_KEY",
		"data-csm-admin-only",
		"CSM_CONFIG.authScope",
		"href + '/'",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("layout.js missing sidebar behavior hook %s", want)
		}
	}

	modsecRules, err := os.ReadFile("../../ui/templates/modsec-rules.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(modsecRules), `{{define "page"}}modsec-rules{{end}}`) {
		t.Fatal("modsec-rules.html must expose page modsec-rules so its sidebar item is active")
	}
}

func TestSharedUIScriptsLoadBeforeTableExtensions(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)
	csrfIdx := strings.Index(text, `/static/js/csrf.js`)
	uiIdx := strings.Index(text, `/static/js/csm-ui.js`)
	tableIdx := strings.Index(text, `/static/js/table.js`)
	if csrfIdx < 0 || uiIdx < 0 || tableIdx < 0 {
		t.Fatal("layout.html missing shared Web UI scripts")
	}
	if csrfIdx >= uiIdx || uiIdx >= tableIdx {
		t.Fatal("layout.html must load csrf.js, then csm-ui.js, then table.js")
	}
}

// TestDashboardLeadsWithPriorityQueue ensures the dashboard surfaces the
// triage-first layout: page header, posture card (with runtime status
// strip), priority queue, and the Components matrix sit above the
// analytics charts. The Recent activity feed was removed; runtime
// watcher state lives in the Components card.
func TestDashboardLeadsWithPriorityQueue(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)

	for _, want := range []string{
		`class="csm-page-header`,
		`class="csm-status-strip`,
		`id="priority-queue"`,
		`id="components-matrix"`,
		`id="components-feature-flags"`,
		`id="dashboard-summary"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dashboard.html missing required section %q", want)
		}
	}

	// Priority queue must come before the analytics charts.
	priority := strings.Index(text, `id="priority-queue"`)
	timeline := strings.Index(text, `id="timeline-chart"`)
	if priority < 0 || timeline < 0 {
		t.Fatal("dashboard.html missing one of priority queue or timeline chart")
	}
	if priority >= timeline {
		t.Errorf("priority queue must precede the analytics charts (got %d vs %d)", priority, timeline)
	}

	js, err := os.ReadFile("../../ui/static/js/dashboard.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"loadPriorityQueue",
		"function _startPriorityQueueInterval",
		"renderFeatureFlags",
		"loadComponents",
		"/api/v1/incidents?status=open",
		"href: '/incident#'",
		"_incidentOwner",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("dashboard.js missing %q", want)
		}
	}
	if strings.Contains(jsText, "_trackInterval(setInterval(loadPriorityQueue") {
		t.Fatal("dashboard.js must not register the priority queue interval through the first IIFE's private _trackInterval")
	}
	if !strings.Contains(jsText, `'<span class="btn btn-sm btn-ghost-secondary csm-queue-item__action">'`) {
		t.Fatal("dashboard priority queue action affordance must not be a nested anchor")
	}
}

func TestIncidentPageUsesDetailPanelDeepLinks(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/incident.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)
	if strings.Contains(text, `id="incident-detail"`) {
		t.Fatal("incident.html should use the shared detail panel instead of an inline detail card")
	}

	js, err := os.ReadFile("../../ui/static/js/incident.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"incidentIDFromHash",
		"CSM.detailPanel.open",
		"hashchange",
		"pendingIncidentID",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("incident.js missing detail-panel deep-link hook %q", want)
		}
	}
}

// TestIncidentPageHasGroupedTab pins that the /incident page exposes the
// grouped view (Phase 8.10). The handler / builder are tested separately;
// this test only verifies the template hook the JS attaches to.
func TestIncidentPageHasGroupedTab(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/incident.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)
	for _, want := range []string{
		`id="grouped-tab"`,
		`id="grouped-panel"`,
		`id="grouped-content"`,
		`id="grouped-status-filter"`,
		`id="grouped-kind-filter"`,
		`csm-summary-list`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("incident.html missing grouped-view hook %q", want)
		}
	}
	js, err := os.ReadFile("../../ui/static/js/incident.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		`/api/v1/incidents/groups`,
		`function loadGroups`,
		`function renderGroups`,
		`function openGroupDetail`,
		`switchTab('grouped')`,
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("incident.js missing grouped-view hook %q", want)
		}
	}
}

func TestIncidentFirewallStatusGuardsAsyncPanelUpdates(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/incident.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"data-csm-fw-ip",
		"data-csm-fw-base-class",
		"function setFirewallStatus",
		"setFirewallStatus(target, requestedIP",
		"groupedPageTotal = 0",
		"groupedPageReturned = 0",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("incident.js missing firewall-status regression hook %q", want)
		}
	}
	if strings.Contains(jsText, "className = 'col-8 text-") {
		t.Fatal("incident.js must not replace firewall status layout classes with grouped-detail classes")
	}
}

// TestInventoryPagesAdoptCsmToolbar asserts the secondary cleanup pass
// migrated card-action filter rows on inventory pages onto the canonical
// csm-toolbar primitive so toolbars look consistent across the UI.
func TestInventoryPagesAdoptCsmToolbar(t *testing.T) {
	pages := []string{
		"audit.html",
		"quarantine.html",
		"cleanup-history.html",
		"threat.html",
	}
	for _, name := range pages {
		path := "../../ui/templates/" + name
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(src), "csm-toolbar") {
			t.Errorf("%s does not adopt csm-toolbar", name)
		}
	}
}

func TestCleanupHistoryBulkButtonsLockTogether(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/cleanup-history.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{
		`var buttonIDs = ['cleanup-files-restore-btn', 'cleanup-files-delete-btn'];`,
		`states.push({ btn: btn, disabled: btn.disabled, html: btn.innerHTML });`,
		`btn.disabled = true;`,
		`activeBtn.innerHTML = busyHTML;`,
		`state.btn.innerHTML = state.html;`,
		`updateFileBulkButtons();`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("cleanup-history.js missing bulk-button lock fragment %q", want)
		}
	}
	if strings.Contains(text, `var origText = btn.textContent`) || strings.Contains(text, `btn.textContent = label`) {
		t.Error("cleanup-history.js must preserve button HTML; textContent drops the action icons")
	}
}

// TestModSecPageUsesPhase8Primitives asserts the modsec workbench leads
// with the WAF pressure summary list and the side summaries, and that
// modsec.js wires up the new shared helpers.
func TestModSecPageUsesPhase8Primitives(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/modsec.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)
	for _, want := range []string{
		`class="csm-page-header`,
		`id="modsec-status-strip"`,
		`id="modsec-pressure"`,
		`csm-summary-list`,
		`id="modsec-top-rules"`,
		`id="modsec-top-domains"`,
		`id="modsec-tab-blocked"`,
		`id="modsec-tab-events"`,
		`id="modsec-tab-rules"`,
		`class="csm-toolbar"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("modsec.html missing phase-8 hook %q", want)
		}
	}
	for _, banned := range []string{
		`id="stat-total"`,
		`id="stat-ips"`,
		`id="stat-escalated"`,
		`id="stat-top-rule"`,
	} {
		if strings.Contains(text, banned) {
			t.Errorf("modsec.html still contains legacy stat element %q", banned)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/modsec.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		`/api/v1/modsec/blocks`,
		`/api/v1/modsec/events`,
		`renderActiveWAFPressure`,
		`renderSideSummaries`,
		`CSM.summaryItem`,
		`CSM.detailPanel.open`,
		`CSM.applyTruncateMiddle`,
		`stickyHeader`,
		`onRowClick`,
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("modsec.js missing phase-8 hook %q", want)
		}
	}
}

// TestEmailPageUsesPhase8Primitives asserts the email workbench dropped the
// old six-card stat row in favour of a status strip + grouped action rows
// + tabs (Findings / Auth failures / Queue / Quarantine / Senders), and
// that email.js no longer touches the removed stat-card IDs.
func TestEmailPageUsesPhase8Primitives(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/email.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)

	for _, want := range []string{
		`class="csm-page-header`,
		`id="email-status-strip"`,
		`id="email-action-groups"`,
		`csm-summary-list`,
		`id="email-protection-state"`,
		`id="email-tab-findings"`,
		`id="email-tab-auth"`,
		`id="email-tab-queue"`,
		`id="email-tab-quarantine"`,
		`id="email-tab-senders"`,
		`class="csm-toolbar"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("email.html missing phase-8 hook %q", want)
		}
	}

	// The legacy six-card stat row, single filter form, and recent-threats
	// card must be gone -- the plan rules them out as the first viewport.
	for _, banned := range []string{
		`id="stat-queue"`,
		`id="stat-phishing"`,
		`id="stat-accounts"`,
		`id="stat-malware-blocked"`,
		`id="stat-compromised"`,
		`id="stat-queue-alerts"`,
		`id="email-filters"`,
		`id="recent-threats"`,
	} {
		if strings.Contains(text, banned) {
			t.Errorf("email.html still contains legacy element %q", banned)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/email.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		`/api/v1/email/groups`,
		`renderActionGroups`,
		`refreshStatusStrip`,
		`CSM.summaryItem`,
		`CSM.detailPanel.open`,
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("email.js missing phase-8 hook %q", want)
		}
	}
	for _, banned := range []string{
		`updateStatCards`,
		`renderRecentThreats`,
	} {
		if strings.Contains(jsText, banned) {
			t.Errorf("email.js still references removed helper %q", banned)
		}
	}
}

// TestFindingsPageUsesPhase4Primitives ensures findings.html adopted the
// shared layout primitives in phase 4 and that findings.js routes detail
// rendering through CSM.detailPanel rather than inserting an inline
// `tr.finding-detail-row`.
func TestFindingsPageUsesPhase4Primitives(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/findings.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)

	for _, want := range []string{
		`class="csm-page-header`,
		`id="open-scan-modal"`,
		`id="scan-account-modal"`,
		`id="group-mode-toggle"`,
		`data-group-mode="account"`,
		`class="csm-toolbar"`,
		`id="findings-bulk-bar"`,
		`class="csm-sticky-actions"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("findings.html missing phase-4 hook %q", want)
		}
	}

	// The legacy scan card and inline bulk-action wrapper must be gone.
	for _, banned := range []string{
		`id="scan-card"`,
		`id="scan-header"`,
		`id="scan-body"`,
		`id="bulk-actions"`,
	} {
		if strings.Contains(text, banned) {
			t.Errorf("findings.html still contains legacy element %q", banned)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/findings.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"CSM.detailPanel.open",
		"findings-bulk-bar",
		"clearAllSelections",
		"syncGroupModeButtons",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("findings.js missing phase-4 hook %q", want)
		}
	}
	if strings.Contains(jsText, "finding-detail-row") {
		t.Error("findings.js still inserts the legacy finding-detail-row tr; use CSM.detailPanel")
	}
	if strings.Contains(jsText, "document.createElement('style')") {
		t.Error("findings.js must keep group-row CSS in csm.css, not inject a style tag")
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".csm-group-header") {
		t.Fatal("csm.css missing grouped findings row styles")
	}

	historyJS, err := os.ReadFile("../../ui/static/js/history.js")
	if err != nil {
		t.Fatal(err)
	}
	historyText := string(historyJS)
	for _, want := range []string{
		`params.get('tab') === 'history'`,
		`params.get('severity')`,
		`window.bootstrap && window.bootstrap.Tab`,
		`window.bootstrap.Tab.getOrCreateInstance(historyTabLink)`,
		`activateHistoryTabFallback`,
		`historyPane.classList.add('active', 'show')`,
		`initHistory();`,
	} {
		if !strings.Contains(historyText, want) {
			t.Errorf("history.js missing history URL restore hook %q", want)
		}
	}
	if strings.Contains(historyText, `typeof bootstrap`) || strings.Contains(historyText, `new bootstrap.Tab`) {
		t.Error("history.js should use window.bootstrap and keep the no-Bootstrap fallback path")
	}
}

// TestFirewallPageSplitIntoSubviews ensures the firewall page exposes the
// six routine subviews plus the danger zone, and that each subview is
// addressable through ?view=<name>. Destructive actions must live under
// the danger section so the default Overview cannot trigger them.
func TestFirewallPageSplitIntoSubviews(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/firewall.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tmpl)

	for _, want := range []string{
		`class="csm-page-header`,
		`id="fw-subview-nav"`,
		`id="lookup-form"`,
		`id="lookup-result"`,
		`class="csm-danger-zone`,
		`href="/settings#firewall"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("firewall.html missing phase-5 hook %q", want)
		}
	}

	for _, view := range []string{"overview", "blocks", "allow", "config", "audit", "danger"} {
		section := `data-fw-view="` + view + `"`
		if !strings.Contains(text, section) {
			t.Errorf("firewall.html missing subview section %s", section)
		}
		nav := `data-fw-nav="` + view + `"`
		if !strings.Contains(text, nav) {
			t.Errorf("firewall.html missing subview nav %s", nav)
		}
	}

	// The destructive Flush button must live inside the danger section.
	dangerStart := strings.Index(text, `data-fw-view="danger"`)
	flushIdx := strings.Index(text, `id="flush-blocked-btn"`)
	if dangerStart < 0 || flushIdx < 0 || flushIdx < dangerStart {
		t.Fatal("flush-blocked-btn must live under the danger subview, not the overview")
	}
	// The Unblock-selected-IPs orphan button was removed: per-row Unblock
	// covers single-IP cases and Flush blocked IPs covers the bulk case.
	if strings.Contains(text, `id="bulk-unblock-btn"`) {
		t.Fatal("bulk-unblock-btn must not be reintroduced; per-row Unblock and Flush blocked IPs cover the workflow")
	}

	js, err := os.ReadFile("../../ui/static/js/firewall.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		`URLSearchParams(window.location.search)`,
		`history.replaceState`,
		`data-fw-view`,
		`switchFirewallView('overview')`,
		`confirmDangerAction(msg, 'FLUSH')`,
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("firewall.js missing subview switcher hook %q", want)
		}
	}
}

// TestSettingsSchemaCarriesFieldGroups asserts the firewall and threshold
// sections expose inner field-group labels so settings.js can render
// fieldsets per topic instead of one flat grid. The test is presence-only;
// per-field assignment lives in the schema and is reviewed there.
func TestSettingsSchemaCarriesFieldGroups(t *testing.T) {
	src, err := os.ReadFile("../../internal/webui/settings_schema.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{
		`FieldGroup string`,
		`YAMLPath: "domlog_max_files"`,
		`YAMLPath: "domlog_tail_lines"`,
		`YAMLPath: "domlog_max_age_min"`,
		`YAMLPath: "mail_log_tail_lines"`,
		`YAMLPath: "syslog_messages_tail_lines"`,
		"FieldGroupAccessPorts",
		"FieldGroupRateLimits",
		"FieldGroupFloodProtection",
		"FieldGroupGeoDynDNS",
		"FieldGroupSMTPControls",
		"FieldGroupLogging",
		"FieldGroupLimits",
		"FieldGroupScanIntervals",
		"FieldGroupWebBruteForce",
		"FieldGroupMailBruteForce",
		"FieldGroupSMTPBruteForce",
		"FieldGroupAccountSpray",
		"FieldGroupStateRetention",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("settings_schema.go missing field-group constant %q", want)
		}
	}

	// Spot-check that firewall and thresholds carry FieldGroup annotations
	// (any occurrence beyond the type definition demonstrates application).
	if strings.Count(text, "FieldGroup: FieldGroup") < 20 {
		t.Errorf("settings_schema.go has too few FieldGroup annotations; firewall + thresholds were not annotated")
	}
}

// TestSettingsPageRendersFieldsetsAndSearch asserts the Phase 6 hooks land
// in settings.html and settings.js: a free-text section search plus the
// field-group rendering branch.
func TestSettingsPageRendersFieldsetsAndSearch(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpl), `id="settings-search"`) {
		t.Fatal("settings.html missing settings-search input")
	}

	js, err := os.ReadFile("../../ui/static/js/settings.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"filterNav",
		"sectionSearchText",
		"item.dataset.search",
		"field.label",
		"field.yaml_path",
		"hasGroups",
		"settings-field-group",
		"f.field_group",
		"showValidationErrors",
		"pendingSectionsSentence",
		"hideSettingsBanner",
		"settings-rollback-footer",
		"settings-secret-set",
	} {
		if !strings.Contains(jsText, want) {
			t.Errorf("settings.js missing phase-6 hook %q", want)
		}
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(css)
	for _, want := range []string{
		".settings-field-group",
		".settings-field-group__legend",
		".settings-search",
		".settings-secret-set",
	} {
		if !strings.Contains(cssText, want) {
			t.Errorf("csm.css missing phase-6 class %q", want)
		}
	}
	if !regexp.MustCompile(`(?s)\.settings-panel-footer\s*\{[^}]*position:\s*sticky`).MatchString(cssText) {
		t.Error("settings panel footer must be sticky so save controls stay visible while scrolling")
	}
}

// TestEveryOperatorPageUsesSharedHeader ensures every operator-facing page
// adopts the .csm-page-header primitive instead of the legacy Tabler
// page-header so the Web UI shares one skeleton. Login is excluded
// because it has no operator chrome.
func TestEveryOperatorPageUsesSharedHeader(t *testing.T) {
	pages := []string{
		"account.html", "audit.html", "cleanup-history.html",
		"dashboard.html", "email.html", "findings.html", "firewall.html",
		"hardening.html", "incident.html", "modsec.html",
		"modsec-rules.html", "performance.html", "quarantine.html",
		"rules.html", "settings.html", "threat.html",
	}
	for _, name := range pages {
		path := "../../ui/templates/" + name
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(src)
		if !sourceHasClass(text, "csm-page-header") {
			t.Errorf("%s missing .csm-page-header primitive", name)
		}
		if sourceHasClass(text, "page-header") {
			t.Errorf("%s still uses legacy Tabler page-header; switch to csm-page-header", name)
		}
		if !strings.Contains(text, `<h1 class="csm-page-header__title"`) {
			t.Errorf("%s must expose the page title as the page-level h1", name)
		}
		if strings.Contains(text, `<h2 class="csm-page-header__title"`) {
			t.Errorf("%s still renders the shared page title as h2", name)
		}
	}

	layout, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(layout), `<h1 class="navbar-brand`) {
		t.Fatal("layout.html must not use the product brand as the page-level h1")
	}
}

func TestModSecRulesPageHasNoPlaceholderCards(t *testing.T) {
	src, err := os.ReadFile("../../ui/templates/modsec-rules.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, banned := range []string{"owasp crs rule management coming soon", "owasp crs placeholder"} {
		if strings.Contains(strings.ToLower(text), banned) {
			t.Fatalf("modsec-rules.html still contains placeholder copy %q", banned)
		}
	}
	if !sourceHasClass(text, "csm-empty") {
		t.Fatal("modsec-rules.html should use the shared csm-empty state for loading/unconfigured states")
	}
}

func TestSettingsIntArraySubmitsRawTokens(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/settings.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "parseInt(tokens[i], 10)") {
		t.Fatal("settings.js must not coerce malformed port tokens before backend validation")
	}
	if !strings.Contains(text, `Number.isSafeInteger(n)`) {
		t.Fatal("settings.js should only coerce safe integer port tokens")
	}
	if !strings.Contains(text, `out.push(token)`) {
		t.Fatal("settings.js should keep malformed []int tokens for backend validation")
	}
}
