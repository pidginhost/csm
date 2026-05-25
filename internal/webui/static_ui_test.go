package webui

import (
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
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
		`function _auditExportRows()`,
		`document.querySelectorAll('[data-export]')`,
		`CSM.exportTable(_auditExportRows(),`,
		`'csm-audit'`,
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
		`href="/settings?section=firewall"`,
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

// TestThreatAccountListEscapesAccountNames pins WEB_ROADMAP P1.1: the
// "Accounts Targeted" cell in the IP lookup card joined account names raw
// into the table HTML. Account identifiers can contain "<" / ">" / "&" once
// custom-username modules are enabled, opening a stored XSS on whoever
// opens that detail card.
func TestThreatAccountListEscapesAccountNames(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/threat.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "Object.keys(rec.accounts).join(") {
		t.Fatal("threat.js still joins account names without CSM.esc; XSS regression")
	}
	if !strings.Contains(text, "Object.keys(rec.accounts).map(CSM.esc).join(") {
		t.Fatal("threat.js must escape every account name before joining for the IP lookup card")
	}
}

// TestCountryFlagRejectsMalformedInput pins WEB_ROADMAP P1.1: the unbounded
// String.fromCodePoint.apply path could throw RangeError on non-2-char
// input or smuggle non-regional-indicator code points into the document.
// The hardened version validates the original input as ASCII letters
// before Unicode case folding or fromCodePoint.
func TestCountryFlagRejectsMalformedInput(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csm-ui.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	start := strings.Index(text, "CSM.countryFlag = function(code) {")
	if start == -1 {
		t.Fatal("csm-ui.js missing countryFlag helper")
	}
	end := strings.Index(text[start:], "\n};")
	if end == -1 {
		t.Fatal("csm-ui.js countryFlag helper has no function terminator")
	}
	countryFlagBody := text[start : start+end]
	if strings.Contains(text, "String.fromCodePoint.apply(null,") {
		t.Fatal("csm-ui.js still uses fromCodePoint.apply; switch to validated direct call")
	}
	for _, fragment := range []string{
		`if (typeof code !== 'string' || code.length !== 2) return '';`,
		`var a = code.charCodeAt(0), b = code.charCodeAt(1);`,
		`if (a >= 97 && a <= 122) a -= 32;`,
		`else if (a < 65 || a > 90) return '';`,
		`if (b >= 97 && b <= 122) b -= 32;`,
		`else if (b < 65 || b > 90) return '';`,
		`return String.fromCodePoint(127397 + a, 127397 + b);`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csm-ui.js missing countryFlag guard fragment %q", fragment)
		}
	}
	if strings.Contains(countryFlagBody, "toUpperCase") {
		t.Fatal("countryFlag must not rely on Unicode case folding before ASCII validation")
	}
}

// TestNoRawObjectInterpolationInDOMWrites pins WEB_ROADMAP P1.1: each line
// that writes raw HTML to a DOM node must wrap interpolated object fields
// in CSM.esc / CSM.attr / CSM.fmtDate / CSM.timeAgo / CSM.formatSize /
// CSM.formatNumber / CSM.formatPercent / CSM.countryFlag, or use a
// pre-built helper (statusBadgeHTML, formatExpiresBadge, ...) that does
// its own escaping. Numeric primitives (count / size / length suffixes)
// are allowed because the API contracts type them as numbers.
//
// The regex is intentionally narrow: it catches "<literal>" + ident.field
// + "<literal>" patterns that immediately surround the interpolation with
// HTML. Multi-step builds where the field is first formatted into a local
// variable get past this lint by design; those cases are caught by the
// per-page tests above.
func TestNoRawObjectInterpolationInDOMWrites(t *testing.T) {
	files := webUISourceFiles(t, "../../ui/static/js/*.js")
	risky := regexp.MustCompile(`\+\s*([a-zA-Z_]\w*\.[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\+`)
	allowedWrappers := []string{
		"CSM.esc(", "CSM.attr(", "CSM.fmtDate(", "CSM.timeAgo(",
		"CSM.formatSize(", "CSM.formatNumber(", "CSM.formatPercent(",
		"CSM.countryFlag(", "encodeURIComponent(", "String(",
		"parseInt(", "parseFloat(", "Number(",
	}
	numericSuffixes := []string{
		".length", ".size", ".count", ".total", ".hits", ".event_count",
		".unique_ips", ".blocked_count", ".port_allow_count",
		".allowed_count", ".infra_count", ".port_flood_rules",
		".conn_limit", ".conn_rate_limit", ".deny_ip_limit",
		".blocked_temporary", ".blocked_permanent", ".allow_temporary",
		".blocked_net_count", ".body_bytes", ".total_size",
		".critical_count", ".high_count", ".warning_count",
		".local_score", ".unified_score", ".abuse_score", ".asn",
		".domain_count", ".succeeded", ".failed",
	}
	domToken := regexp.MustCompile(`\.(innerHTML|outerHTML)\s*=`)
	isAllowed := func(line string) bool {
		for _, m := range risky.FindAllStringSubmatch(line, -1) {
			field := m[1]
			ok := false
			for _, suf := range numericSuffixes {
				if strings.HasSuffix(field, suf) {
					ok = true
					break
				}
			}
			if ok {
				continue
			}
			wrapped := false
			for _, w := range allowedWrappers {
				if strings.Contains(line, w+field) {
					wrapped = true
					break
				}
			}
			if !wrapped {
				return false
			}
		}
		return true
	}
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !domToken.MatchString(line) {
				continue
			}
			if !risky.MatchString(line) {
				continue
			}
			if isAllowed(line) {
				continue
			}
			t.Errorf("%s:%d: DOM write interpolates a field without CSM.esc/CSM.attr/known formatter: %s",
				path, i+1, strings.TrimSpace(line))
		}
	}
}

// TestAllJSFetchesGoThroughCSMRequest pins WEB_ROADMAP P1.2: every page
// script must call the shared CSM.request / CSM.get / CSM.fetch / CSM.poll
// / CSM.post / CSM.delete helpers so the 30s timeout, AbortController, and
// CSRF token wiring stay uniform. csrf.js is the only file allowed to call
// the global `fetch` builtin directly (it is the wrapper).
func TestAllJSFetchesGoThroughCSMRequest(t *testing.T) {
	files := webUISourceFiles(t, "../../ui/static/js/*.js")
	// `\bfetch\(` would match `CSM.fetch(`, so require a leading
	// non-identifier (or start-of-line / whitespace) before the bareword.
	bareFetch := regexp.MustCompile(`(?:^|[^A-Za-z0-9_.])fetch\s*\(`)
	for _, path := range files {
		if filepath.Base(path) == "csrf.js" {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if bareFetch.MatchString(line) {
				t.Errorf("%s:%d: raw fetch() call; route through CSM.request / CSM.get / CSM.post / CSM.poll: %s",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestCSMRequestExposesAllowNonOKAndSilent pins WEB_ROADMAP P1.2: the
// shared request helper must accept allowNonOK (settings.js depends on
// inspecting 412 / 422 status codes directly) and silent (CSM.poll
// suppresses the auto-toast so it can surface its own errors).
func TestCSMRequestExposesAllowNonOKAndSilent(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`var allowNonOK = !!options.allowNonOK;`,
		`var silent = !!options.silent;`,
		`if (allowNonOK) {`,
		`if (!silent) {`,
		`delete opts.timeoutMs;`,
		`delete opts.allowNonOK;`,
		`delete opts.silent;`,
		`CSM.get = function(url, options) {`,
		`var opts = Object.assign({}, options || {});`,
		`opts.headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});`,
		`return CSM.fetch(url, opts);`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing CSM.request option fragment %q", fragment)
		}
	}
}

// TestCSMWriteHelpersUseCSMRequest pins the helper stack: POST and DELETE
// must inherit the shared timeout / AbortController path too. They stay
// silent because action handlers already render their own success/failure
// toast messages.
func TestCSMWriteHelpersUseCSMRequest(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, tc := range []struct {
		name        string
		mustHave    []string
		mustNotHave string
	}{
		{
			name: "CSM.post",
			mustHave: []string{
				`return CSM.request(url, {`,
				`method: 'POST',`,
				`'X-CSRF-Token': CSM.csrfToken`,
				`silent: true`,
				`}).then(function(r) { return r.json(); });`,
			},
			mustNotHave: `fetch(`,
		},
		{
			name: "CSM.delete",
			mustHave: []string{
				`method: 'DELETE',`,
				`'X-CSRF-Token': CSM.csrfToken`,
				`silent: true`,
				`return CSM.request(url, opts).then(function(r) { return r.json(); });`,
			},
			mustNotHave: `fetch(`,
		},
	} {
		start := strings.Index(text, tc.name+" = function")
		if start == -1 {
			t.Fatalf("csrf.js missing %s definition", tc.name)
		}
		end := strings.Index(text[start:], "\n};")
		if end == -1 {
			t.Fatalf("csrf.js %s has no terminator", tc.name)
		}
		body := text[start : start+end]
		for _, fragment := range tc.mustHave {
			if !strings.Contains(body, fragment) {
				t.Fatalf("csrf.js %s missing fragment %q", tc.name, fragment)
			}
		}
		if strings.Contains(body, tc.mustNotHave) {
			t.Fatalf("csrf.js %s must route through CSM.request, not fetch()", tc.name)
		}
	}
}

func TestOptionalJSONErrorCallersStaySilent(t *testing.T) {
	for _, tc := range []struct {
		path      string
		fragments []string
	}{
		{
			path: "../../ui/static/js/layout.js",
			fragments: []string{
				`CSM.request('/api/v1/status', { headers: { Accept: 'application/json' }, allowNonOK: true, silent: true })`,
				`return r.ok ? r.json() : null;`,
			},
		},
		{
			path: "../../ui/static/js/firewall.js",
			fragments: []string{
				`CSM.get('/api/v1/geoip?ip=' + encodeURIComponent(ip), { allowNonOK: true, silent: true })`,
			},
		},
		{
			path: "../../ui/static/js/quarantine.js",
			fragments: []string{
				`CSM.get('/api/v1/quarantine-preview?id=' + encodeURIComponent(id), { allowNonOK: true, silent: true })`,
			},
		},
		{
			path: "../../ui/static/js/threat.js",
			fragments: []string{
				`return CSM.get(url, { allowNonOK: true, silent: true });`,
				`getJSONAllowError('/api/v1/threat/ip?ip='+encodeURIComponent(ip))`,
			},
		},
	} {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		text := string(src)
		for _, fragment := range tc.fragments {
			if !strings.Contains(text, fragment) {
				t.Fatalf("%s missing silent optional/error-handling fragment %q", tc.path, fragment)
			}
		}
	}
}

func csmPollBody(t *testing.T, text string) string {
	t.Helper()
	pollStart := strings.Index(text, "CSM.poll = function(url, interval, callback) {")
	if pollStart == -1 {
		t.Fatal("csrf.js missing CSM.poll definition")
	}
	tail := text[pollStart:]
	for _, terminator := range []string{"\n    };\n})();", "\n};"} {
		if pollEnd := strings.Index(tail, terminator); pollEnd != -1 {
			return tail[:pollEnd]
		}
	}
	t.Fatal("csrf.js CSM.poll has no terminator")
	return ""
}

// TestCSMPollUsesCSMRequest pins WEB_ROADMAP P1.2: the polling utility
// must route its fetch through CSM.request(silent:true) so the 30s
// timeout applies and pollers cannot hang indefinitely on a stuck
// backend.
func TestCSMPollUsesCSMRequest(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	pollBody := csmPollBody(t, text)
	if !strings.Contains(pollBody, "CSM.request(url, { silent: true })") {
		t.Fatal("CSM.poll must route through CSM.request(silent:true)")
	}
	if strings.Contains(pollBody, "fetch((typeof CSM.apiUrl") || strings.Contains(pollBody, "fetch(CSM.apiUrl") {
		t.Fatal("CSM.poll must not call fetch directly anymore")
	}
}

// TestCSMPollHasStateMachineAndSurvivesCallbackThrow pins WEB_ROADMAP
// P1.3: CSM.poll uses an explicit state machine and wraps callback
// invocations in try/catch so a single page's broken handler cannot
// silently kill the next poll cycle. The synchronous-throw path around
// CSM.request also reschedules so a regression in the request helper
// cannot wedge every poller.
func TestCSMPollHasStateMachineAndSurvivesCallbackThrow(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	pollBody := csmPollBody(t, text)
	for _, fragment := range []string{
		`var pollers = [];`,
		`function addPoller(poller) {`,
		`function removePoller(poller) {`,
		`document.addEventListener('visibilitychange', function() {`,
		`snapshot[i].onVisibility();`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing poller registry fragment %q", fragment)
		}
	}
	for _, fragment := range []string{
		`var state = 'scheduled';`,
		`var timerSeq = 0;`,
		`var poller = { onVisibility: onVisibility, onPause: onPause, onResume: onResume, onRefreshNow: onRefreshNow };`,
		`function clearTimer() {`,
		`function scheduleNext(delayMs, force) {`,
		`if (state === 'stopped' || document.hidden) {`,
		`if (!force && CSM.refresh && !CSM.refresh.enabled) {`,
		`var seq = ++timerSeq;`,
		`timerId = setTimeout(function() { run(seq, !!force); }, delayMs);`,
		`function emit(err, data) {`,
		`try { callback(err, data); } catch (_cbErr) { /* swallow callback throw */ }`,
		`function fail(err) {`,
		`currentInterval = Math.min(currentInterval * 2, maxInterval);`,
		`function run(seq, force) {`,
		`if (seq !== timerSeq) return;`,
		`if (document.hidden) { state = 'idle'; return; }`,
		`state = 'running';`,
		`fail(e);`,
		`emit(null, data);`,
		`} else if (state === 'idle') {`,
		`scheduleNext(100);`,
		`function onPause() {`,
		`function onRefreshNow() {`,
		`scheduleNext(0, true);`,
		`state = 'stopped';`,
		`removePoller(poller);`,
	} {
		if !strings.Contains(pollBody, fragment) {
			t.Fatalf("CSM.poll missing lifecycle fragment %q", fragment)
		}
	}
	// The fetch primitive may only appear via CSM.request, never as a
	// direct fetch() call — pinned by TestCSMPollUsesCSMRequest too, but
	// repeated here so the state-machine test fails if the regression
	// drifts.
	if strings.Contains(pollBody, "fetch(") {
		t.Fatal("CSM.poll must route exclusively through CSM.request")
	}
}

func TestCSMPollVisibilityKeepsBackoffAndInvalidatesQueuedTimers(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	pollBody := csmPollBody(t, string(src))
	visibilityStart := strings.Index(pollBody, "function onVisibility() {")
	if visibilityStart == -1 {
		t.Fatal("CSM.poll missing onVisibility")
	}
	visibilityTail := pollBody[visibilityStart:]
	// onVisibility ends at the next `\n        }\n` whose following
	// line is not part of the same function. With pause/resume helpers,
	// the first such break is the `function onPause` marker.
	visibilityEnd := strings.Index(visibilityTail, "\n        }\n\n        function onPause")
	if visibilityEnd == -1 {
		visibilityEnd = strings.Index(visibilityTail, "\n        }\n\n        addPoller(poller);")
	}
	if visibilityEnd == -1 {
		t.Fatal("CSM.poll onVisibility has no terminator")
	}
	visibilityBody := visibilityTail[:visibilityEnd]
	if strings.Contains(visibilityBody, "currentInterval = baseInterval") {
		t.Fatal("CSM.poll must not reset exponential backoff on tab visibility restore")
	}
	for _, fragment := range []string{
		`clearTimer();`,
		`if (state === 'scheduled') state = 'idle';`,
		`scheduleNext(100);`,
		`if (seq !== timerSeq) return;`,
		`if (document.hidden) { state = 'idle'; return; }`,
	} {
		if !strings.Contains(pollBody, fragment) {
			t.Fatalf("CSM.poll missing visibility safety fragment %q", fragment)
		}
	}
}

// TestMemoryBoundedHandlersPinCaps pins WEB_ROADMAP P1.5: the three
// previously-unbounded JSON handlers (history filtered scan, incident
// timeline snapshot walk, modsec aggregate map) carry explicit caps in
// the source so a future refactor cannot silently remove them. The
// caps are checked by name to keep this lint cheap; the runtime tests
// for each handler live in their _test.go siblings.
func TestMemoryBoundedHandlersPinCaps(t *testing.T) {
	for _, tc := range []struct {
		path     string
		fragment string
	}{
		{"../../internal/webui/api.go", "const historyFilterScanCap = 5000"},
		{"../../internal/webui/api.go", "historyTruncated := historyTotal > len(allFindings)"},
		{"../../internal/webui/api.go", `w.Header().Set("X-CSM-Truncated", "1")`},
		{"../../internal/webui/incident_api.go", "const incidentSnapshotScanCap = 1000"},
		{"../../internal/webui/incident_api.go", "SnapshotPageStatuses(nil, 0, incidentSnapshotScanCap)"},
		{"../../internal/webui/incident_api.go", `w.Header().Set("X-CSM-Truncated", "1")`},
		{"../../internal/webui/modsec_api.go", "modsecFindingsScanCap = 10000"},
		{"../../internal/webui/modsec_api.go", "modsecBlocksMaxAggregates = 50000"},
		{"../../internal/webui/modsec_api.go", "if len(byBlock) >= modsecBlocksMaxAggregates {"},
		{"../../internal/webui/modsec_api.go", `w.Header().Set("X-CSM-Truncated", "1")`},
	} {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if !strings.Contains(string(src), tc.fragment) {
			t.Errorf("%s missing memory-cap fragment %q", tc.path, tc.fragment)
		}
	}
}

// TestEveryNamedMutatorRouteEnforcesCSRF checks every mux.Handle entry
// whose Go handler symbol name identifies a mutator
// (apiFix, apiBlock, apiUnblock, apiClear, apiRestore, apiBulkDelete,
// apiReload, apiApply, apiDeny*, apiAllow*, apiRemove*, apiFlush*,
// apiUnban, apiWhitelist*, apiUnwhitelist*, apiSettingsRestart,
// apiHardeningRun, etc.) must be wrapped in requireCSRF. The wrapper
// is a no-op for GET so adding it on a defense-in-depth basis is free.
// Dispatching handlers that serve both GET and POST must enforce CSRF
// before calling the mutating branch. Read-only handlers (apiStats,
// apiList, apiGet*) are explicitly excluded by the heuristic.
func TestEveryNamedMutatorRouteEnforcesCSRF(t *testing.T) {
	src, err := os.ReadFile("../../internal/webui/server.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	settingsSrc, err := os.ReadFile("../../internal/webui/settings_api.go")
	if err != nil {
		t.Fatal(err)
	}
	allText := text + "\n" + string(settingsSrc)
	muxLine := regexp.MustCompile(`mux\.Handle\("[^"]+",\s*(.+)\)\s*(?://.*)?$`)
	mutatorHandler := regexp.MustCompile(`\b(apiFix|apiBulkFix|apiDismissFinding|apiBlockIP|apiUnblockIP|apiUnblockBulk|apiQuarantineRestore|apiQuarantineBulkDelete|apiDBObjectBackupRestore|apiFirewallDenySubnet|apiFirewallAllowIP|apiFirewallRemoveAllow|apiFirewallRemoveSubnet|apiFirewallFlushCphulk|apiFirewallFlush|apiFirewallUnban|apiThreatWhitelistIP|apiThreatUnwhitelistIP|apiThreatBlockIP|apiThreatClearIP|apiThreatTempWhitelistIP|apiThreatBulkAction|apiRulesReload|apiModSecEscalation|apiModSecRulesApply|apiModSecRulesEscalation|apiSuppressions|apiHardeningRun|apiSettings|apiSettingsRestart|apiFirewallTentativeApply|apiFirewallRollbackConfirm|apiFirewallRollbackRevert|apiImport|apiScanAccount|apiTestAlert|apiPerfFixErrorLog|apiPerfFixDisplayErrors|apiEmailQuarantineAction|apiIncidentRouter|apiGeoIPBatch)\b`)
	handlerSymbol := regexp.MustCompile(`s\.(api[A-Za-z0-9]+)`)
	internalCSRF := map[string]string{
		"apiSettings": "s.requireCSRF(http.HandlerFunc(s.apiSettingsPost)).ServeHTTP(w, r)",
	}
	for _, line := range strings.Split(text, "\n") {
		m := muxLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		expr := m[1]
		if !mutatorHandler.MatchString(expr) {
			continue
		}
		if strings.Contains(expr, "requireCSRF(") {
			continue
		}
		hasInternalCSRF := false
		for _, symbol := range handlerSymbol.FindAllStringSubmatch(expr, -1) {
			fragment, ok := internalCSRF[symbol[1]]
			if ok && strings.Contains(allText, fragment) {
				hasInternalCSRF = true
				break
			}
		}
		if !hasInternalCSRF {
			t.Errorf("server.go route missing requireCSRF on mutator handler: %s", strings.TrimSpace(line))
		}
	}
}

// TestCSRFValidatorSkipsBearerAndChecksConstantTime pins the validator
// contract: Bearer-auth requests skip CSRF (the token itself proves
// identity), cookie-auth requests must carry X-CSRF-Token or csrf_token,
// and comparisons use subtle.ConstantTimeCompare.
func TestCSRFValidatorSkipsBearerAndChecksConstantTime(t *testing.T) {
	src, err := os.ReadFile("../../internal/webui/server.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`if s.isBearerAuth(r) {`,
		`subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1`,
		`if token := r.Header.Get("X-CSRF-Token"); token != "" {`,
		`if token := r.FormValue("csrf_token"); token != "" {`,
		`http.Error(w, "Invalid CSRF token", http.StatusForbidden)`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("server.go missing CSRF validator fragment %q", fragment)
		}
	}
}

// TestCSRFEnforcedAtRuntime exercises the live mux: cookie-authenticated
// POSTs and DELETEs without an X-CSRF-Token or csrf_token field must
// land at 403, never at the wrapped handler. Bearer-authenticated calls
// continue to bypass CSRF because the bearer token is not sent by a
// cross-origin browser form. The table covers
// each mutating API route, including dispatchers that enforce CSRF
// inside their POST branch.
func TestCSRFEnforcedAtRuntime(t *testing.T) {
	const tok = "admin-token"
	s := newTestServer(t, tok)
	mux := s.httpSrv.Handler

	cookie := &http.Cookie{Name: "csm_auth", Value: tok}

	cases := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/fix"},
		{"POST", "/api/v1/fix-bulk"},
		{"POST", "/api/v1/dismiss"},
		{"POST", "/api/v1/block-ip"},
		{"POST", "/api/v1/unblock-ip"},
		{"POST", "/api/v1/unblock-bulk"},
		{"POST", "/api/v1/quarantine-restore"},
		{"POST", "/api/v1/quarantine/bulk-delete"},
		{"POST", "/api/v1/db-object-backup-restore"},
		{"POST", "/api/v1/firewall/deny-subnet"},
		{"POST", "/api/v1/firewall/allow-ip"},
		{"POST", "/api/v1/firewall/remove-allow"},
		{"POST", "/api/v1/firewall/remove-subnet"},
		{"POST", "/api/v1/firewall/cphulk-clear"},
		{"POST", "/api/v1/firewall/flush"},
		{"POST", "/api/v1/firewall/unban"},
		{"POST", "/api/v1/threat/whitelist-ip"},
		{"POST", "/api/v1/threat/unwhitelist-ip"},
		{"POST", "/api/v1/threat/block-ip"},
		{"POST", "/api/v1/threat/clear-ip"},
		{"POST", "/api/v1/threat/temp-whitelist-ip"},
		{"POST", "/api/v1/threat/bulk-action"},
		{"POST", "/api/v1/rules/reload"},
		{"POST", "/api/v1/rules/modsec-escalation"},
		{"POST", "/api/v1/suppressions"},
		{"DELETE", "/api/v1/suppressions"},
		{"POST", "/api/v1/modsec/rules/apply"},
		{"POST", "/api/v1/modsec/rules/escalation"},
		{"POST", "/api/v1/import"},
		{"POST", "/api/v1/scan-account"},
		{"POST", "/api/v1/test-alert"},
		{"POST", "/api/v1/hardening/run"},
		{"POST", "/api/v1/settings/alerts"},
		{"POST", "/api/v1/settings/restart"},
		{"POST", "/api/v1/settings/firewall/tentative-apply"},
		{"POST", "/api/v1/settings/firewall/confirm"},
		{"POST", "/api/v1/settings/firewall/revert"},
		{"POST", "/api/v1/perf/fix-error-log"},
		{"POST", "/api/v1/perf/fix-display-errors"},
		{"POST", "/api/v1/email/quarantine/foo/release"},
		{"DELETE", "/api/v1/email/quarantine/foo"},
		{"POST", "/api/v1/geoip/batch"},
		{"POST", "/api/v1/incidents/abc/status"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			body := strings.NewReader(`{}`)
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s without CSRF token: got %d, want 403", tc.method, tc.path, w.Code)
			}
			if !strings.Contains(w.Body.String(), "Invalid CSRF token") {
				t.Errorf("%s %s without CSRF token: body %q, want CSRF rejection", tc.method, tc.path, w.Body.String())
			}
		})
	}

	// Bearer-auth must bypass CSRF for the same routes (server-to-server
	// callers don't have a way to obtain the cookie-bound CSRF token).
	bearerSample := []struct{ method, path string }{
		{"POST", "/api/v1/fix"},
		{"POST", "/api/v1/threat/whitelist-ip"},
	}
	for _, tc := range bearerSample {
		t.Run("bearer "+tc.method+" "+tc.path, func(t *testing.T) {
			body := strings.NewReader(`{}`)
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("Bearer %s %s: got %d, want 400 from wrapped handler", tc.method, tc.path, w.Code)
			}
		})
	}
}

// TestURLStateHelperExposesP21Surface pins WEB_ROADMAP P2.1: CSM.urlState
// must expose get, getAll, set, push, clear, replace, subscribe, and bind so
// page scripts can persist filter state to the URL declaratively. The
// per-input bind is the new affordance: pages call CSM.urlState.bind to
// wire a search / select to a query string key without writing custom
// load+sync code.
func TestURLStateHelperExposesP21Surface(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`get: function(key) {`,
		`getAll: function() {`,
		`set: function(params, opts) {`,
		`push: function(params, opts) {`,
		`clear: function(keys, opts) {`,
		`replace: function(params, opts) {`,
		`subscribe: function(fn) {`,
		`bind: function(opts) {`,
		`window.addEventListener('popstate', handler);`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing CSM.urlState fragment %q", fragment)
		}
	}
}

func TestURLStateBindKeepsQueryAuthoritative(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`function hasURLValue(value) {`,
		`return value !== undefined && value !== null && String(value) !== '';`,
		`function stateValue(state, defaults, name) {`,
		`if (own(state, name)) return state[name] == null ? '' : String(state[name]);`,
		`if (el.value !== desired) {`,
		`el.dispatchEvent(new Event(eventName(el), { bubbles: true }));`,
		`var unsubscribePopstate = CSM.urlState.subscribe(function(state) { applyState(state); });`,
		`if (applying) return;`,
		`if (l.cancel) l.cancel();`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing URL-state authority fragment %q", fragment)
		}
	}
}

func TestURLStateBindUsesChangeForDateInputs(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`var type = String(el.type || '').toLowerCase();`,
		`type === 'date'`,
		`type === 'datetime-local'`,
		`return 'change';`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing date input URL-state event fragment %q", fragment)
		}
	}
}

// TestAuditAndThreatPagesBindSearchToURLState pins WEB_ROADMAP P2.1: the
// two pages that previously had zero URL state (audit, threat) now
// persist their search input through CSM.urlState.bind so operators can
// bookmark and share filtered views.
func TestAuditAndThreatPagesBindSearchToURLState(t *testing.T) {
	for _, tc := range []struct{ path, fragment string }{
		{
			"../../ui/static/js/audit.js",
			`q: document.getElementById('audit-search'),`,
		},
		{
			"../../ui/static/js/threat.js",
			`q: document.getElementById('attackers-search'),`,
		},
	} {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), tc.fragment) {
			t.Errorf("%s missing URL-state bind fragment %q", tc.path, tc.fragment)
		}
	}
}

// TestAccountAndIncidentTabsUseCSMTable pins WEB_ROADMAP P2.2: tables
// that previously rendered as plain HTML (account findings / quarantine
// / history tabs, incident correlated tab) now mount through CSM.Table
// so sort / per-page / state persistence use the same helper as the
// other CSM tables.
func TestAccountAndIncidentTabsUseCSMTable(t *testing.T) {
	for _, tc := range []struct{ path, tableID, stateKey string }{
		{"../../ui/static/js/account.js", "account-findings-table", "csm-account-findings"},
		{"../../ui/static/js/account.js", "account-quarantine-table", "csm-account-quarantine"},
		{"../../ui/static/js/account.js", "account-history-table", "csm-account-history"},
		{"../../ui/static/js/incident.js", "incidents-correlated-table", "csm-incidents-correlated"},
	} {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		if !strings.Contains(text, `id="`+tc.tableID+`"`) {
			t.Errorf("%s missing table id %q", tc.path, tc.tableID)
		}
		if !strings.Contains(text, `tableId: '`+tc.tableID+`'`) {
			t.Errorf("%s missing CSM.Table init for %q", tc.path, tc.tableID)
		}
		if !strings.Contains(text, `stateKey: '`+tc.stateKey+`'`) {
			t.Errorf("%s missing stateKey %q", tc.path, tc.stateKey)
		}
	}
}

func TestSharedTableSortReordersDOMRows(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`this._orderRows();`,
		`document.createDocumentFragment()`,
		`fragment.appendChild(item.row);`,
		`if (item.detail) fragment.appendChild(item.detail);`,
		`this.tbody.appendChild(fragment);`,
		`getAttribute('data-sort')`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("table.js missing DOM sort-order fragment %q", fragment)
		}
	}
}

func TestAccountTablesUseSortableNumericColumns(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/account.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`data-sort="' + Number(f.severity || 0) + '"`,
		`data-sort="' + size + '"`,
		`data-sort="' + Number(e.severity || 0) + '"`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("account.js missing numeric sort fragment %q", fragment)
		}
	}
}

func TestIncidentCSMTableDoesNotShadowServerPagination(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/incident.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`perPage: 0`,
		`search: false`,
		`controls: false`,
		`persistPerPage: false`,
		`data-sort="' + severityNumber(inc.severity) + '"`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("incident.js missing server-pagination-safe CSM.Table fragment %q", fragment)
		}
	}

	table, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	tableText := string(table)
	for _, fragment := range []string{
		`this.perPage = typeof opts.perPage === 'number' ? opts.perPage : 25;`,
		`if (opts.controls === false)`,
		`if (!this.controlsEl) return;`,
		`opts.persistPerPage !== false`,
		`state.search && opts.search !== false && opts.searchId`,
	} {
		if !strings.Contains(tableText, fragment) {
			t.Errorf("table.js missing server-pagination support fragment %q", fragment)
		}
	}
}

func TestSharedTableCanSearchByRowAttribute(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`searchAttr: 'data-search'`,
		`if (opts.searchAttr) {`,
		`rowText = rows[i].getAttribute(opts.searchAttr) || '';`,
		`String(rowText || '').toLowerCase()`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("table.js missing searchAttr fragment %q", fragment)
		}
	}
}

// TestAutoRefreshPillWired pins WEB_ROADMAP P2.3: the shared CSM.refresh
// module exposes enabled / lastFetchAt / bump / manual / setEnabled,
// CSM.request bumps the timestamp on every successful response, CSM.poll
// gates on enabled, the layout template carries the pill + buttons, and
// layout.js wires them up.
func TestAutoRefreshPillWired(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for _, fragment := range []string{
		`CSM.refresh = (function() {`,
		`var STORAGE_KEY = 'csm-autorefresh';`,
		`enabled = raw !== 'off';`,
		`function createInterval(fn, interval) {`,
		`bump: function() {`,
		`manual: function() {`,
		`interval: function(fn, interval) {`,
		`setEnabled: function(next) {`,
		`window.dispatchEvent(new CustomEvent('csm:refresh-toggle'`,
		`if (CSM.refresh) CSM.refresh.bump();`,
		`if (!force && CSM.refresh && !CSM.refresh.enabled) { state = 'idle'; return; }`,
		`function onPause() {`,
		`function onResume() {`,
		`function onRefreshNow() {`,
		`scheduleNext(0, true);`,
		`window.addEventListener('csm:refresh-toggle', function(ev) {`,
		`window.addEventListener('csm:refresh-now', function() {`,
		`snapshot[i].onRefreshNow();`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csrf.js missing CSM.refresh fragment %q", fragment)
		}
	}

	layoutJS, err := os.ReadFile("../../ui/static/js/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	layoutText := string(layoutJS)
	for _, fragment := range []string{
		`var pill = document.getElementById('csm-refresh-pill');`,
		`nowBtn.addEventListener('click', function() { CSM.refresh.manual(); });`,
		`toggleBtn.addEventListener('click', function() { CSM.refresh.setEnabled(!CSM.refresh.enabled); });`,
		`window.addEventListener('csm:refresh-bump', paintAge);`,
		`return 'Updated ' + diff + 's ago';`,
		`toggleBtn.setAttribute('aria-label', enabled ? 'Pause auto-refresh' : 'Resume auto-refresh');`,
	} {
		if !strings.Contains(layoutText, fragment) {
			t.Fatalf("layout.js missing refresh-pill fragment %q", fragment)
		}
	}

	layout, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	layoutHTML := string(layout)
	for _, fragment := range []string{
		`id="csm-refresh-pill"`,
		`id="csm-refresh-age"`,
		`Never updated`,
		`id="csm-refresh-now"`,
		`id="csm-refresh-toggle"`,
		`aria-label="Pause auto-refresh"`,
	} {
		if !strings.Contains(layoutHTML, fragment) {
			t.Fatalf("layout.html missing refresh-pill id %q", fragment)
		}
	}
}

func TestAutoRefreshDataIntervalsUseSharedToggle(t *testing.T) {
	allowedDirectSetInterval := map[string]bool{
		"csrf.js":     true, // relative timestamp labels
		"findings.js": true, // per-finding countdown labels
		"layout.js":   true, // refresh-age label tick
		"settings.js": true, // firewall rollback countdown
	}
	for _, path := range webUISourceFiles(t, "../../ui/static/js/*.js") {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(src), "setInterval(") {
			continue
		}
		base := filepath.Base(path)
		if !allowedDirectSetInterval[base] {
			t.Errorf("%s starts a data refresh interval outside CSM.refresh.interval", path)
		}
	}
}

// TestSharedExportTableWired pins WEB_ROADMAP P2.4: pages that
// previously had no CSV/JSON export (hardening, performance, account
// per-tab, ModSec rules) now expose a dropdown wired to CSM.exportTable.
// Audit page migrated off its bespoke exporter onto the same helper.
// Pages with their own export rows keep a stable filename prefix so
// downloaded files are recognizable.
func TestSharedExportTableWired(t *testing.T) {
	cases := []struct {
		path        string
		jsFragments []string
	}{
		{
			"../../ui/static/js/audit.js",
			[]string{`CSM.exportTable(_auditExportRows(),`, `'csm-audit'`},
		},
		{
			"../../ui/static/js/hardening.js",
			[]string{`CSM.exportTable(_hardeningExportRows,`, `'csm-hardening'`, `_hardeningExportCols`},
		},
		{
			"../../ui/static/js/performance.js",
			[]string{`CSM.exportTable(rows, _perfExportCols,`, `'csm-performance'`, `_perfLastFindings = findings;`, `path:     perfFindingPath(f)`},
		},
		{
			"../../ui/static/js/account.js",
			[]string{`CSM.exportTable(rows, _accountExportCols[currentTab]`, `'csm-account-' + currentTab`},
		},
		{
			"../../ui/static/js/modsec-rules.js",
			[]string{`CSM.exportTable(rows, _modsecRulesExportCols,`, `'csm-modsec-rules'`, `currentRuleEnabled(r)`, `hits_24h`},
		},
	}
	for _, tc := range cases {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		text := string(src)
		for _, fragment := range tc.jsFragments {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s missing export fragment %q", tc.path, fragment)
			}
		}
	}

	// Templates must expose the dropdown so the JS handler has something
	// to bind against.
	tmplCases := []struct{ path string }{
		{"../../ui/templates/hardening.html"},
		{"../../ui/templates/performance.html"},
		{"../../ui/templates/account.html"},
		{"../../ui/templates/modsec-rules.html"},
	}
	for _, tc := range tmplCases {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		text := string(src)
		for _, want := range []string{
			`data-export="csv"`,
			`data-export="json"`,
			`data-bs-toggle="dropdown"`,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s missing export dropdown hook %q", tc.path, want)
			}
		}
	}
}

func TestSharedExportTableEscapesSpreadsheetFormulaCells(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatalf("read csrf.js: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		`function csmCSVCell(value)`,
		`/^[\t\r\n=+\-@]/.test(val)`,
		`/^\s+[=+\-@]/.test(val)`,
		`val = "'" + val;`,
		`obj[col.key] = row[col.key] != null ? row[col.key] : '';`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("csrf.js missing CSV export guard fragment %q", want)
		}
	}
}

// TestBulkHelperWired pins WEB_ROADMAP P2.5: csm-ui.js exposes CSM.bulk
// with the documented surface (selectedValues / selectedCount / clear /
// refresh, labelTemplate-driven button copy, indeterminate select-all)
// and quarantine.js drives its bulk bar through it.
func TestBulkHelperWired(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/csm-ui.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for _, fragment := range []string{
		`CSM.bulk = function(opts) {`,
		`var selectAllSelector = opts.selectAllSelector || '';`,
		`function resolveSelectAll() {`,
		`selectAll.indeterminate = (n > 0 && n < total);`,
		`b.el.textContent = b.labelTemplate.replace(/\{n\}/g, n);`,
		`b.el.disabled = (n === 0);`,
		`b.el.classList.toggle('d-none', n === 0);`,
		`if (cb.dataset.csmBulkBound === '1') return;`,
		`function bindSelectAllListener() {`,
		`if (selectAllEl.dataset.csmBulkSelectAllBound === '1') return;`,
		`selectedValues: function() {`,
		`selectedCount: function() {`,
		`clear: function() {`,
		`refresh: function() {`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("csm-ui.js missing CSM.bulk fragment %q", fragment)
		}
	}

	q, err := os.ReadFile("../../ui/static/js/quarantine.js")
	if err != nil {
		t.Fatal(err)
	}
	qText := string(q)
	emptyIdx := strings.Index(qText, `if (!files || files.length === 0) {`)
	if emptyIdx < 0 {
		t.Fatal("quarantine.js missing empty quarantine branch")
	}
	emptyUpdateIdx := strings.Index(qText[emptyIdx:], `updateBulkRestore();`)
	emptyReturnIdx := strings.Index(qText[emptyIdx:], `return;`)
	if emptyUpdateIdx < 0 || emptyReturnIdx < 0 || emptyUpdateIdx > emptyReturnIdx {
		t.Fatal("quarantine.js must repaint bulk buttons before returning from the empty quarantine branch")
	}
	for _, fragment := range []string{
		`_quarBulk = CSM.bulk({`,
		`if (!_quarBulk && !selectAll && !document.querySelector('.q-cb')) {`,
		`btn.disabled = true;`,
		`rowCheckboxSelector: '.q-cb',`,
		`selectAllSelector: '#q-select-all',`,
		`labelTemplate: 'Restore {n} file(s)'`,
		`labelTemplate: 'Delete {n} file(s)'`,
		`_quarBulk.selectedValues();`,
	} {
		if !strings.Contains(qText, fragment) {
			t.Fatalf("quarantine.js missing CSM.bulk fragment %q", fragment)
		}
	}
}

// TestAuditPageHasFilterPack pins WEB_ROADMAP P3.1: audit page exposes
// an action-type dropdown and from/to date inputs, both wired to
// CSM.Table (action via filters[], date via rowFilter) and persisted
// to URL state through CSM.urlState.bind.
func TestAuditPageHasFilterPack(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/audit.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="audit-action-filter"`,
		`id="audit-from"`,
		`id="audit-to"`,
		`<option value="block_ip">Block IP</option>`,
		`<option value="dismiss">Dismiss</option>`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("audit.html missing P3.1 filter fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/audit.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`data-action="' + CSM.attr(e.action`,
		`data-timestamp="' + CSM.attr(e.timestamp`,
		`function populateAuditActionFilter(entries) {`,
		`var current = CSM.urlState.get('action') || select.value || '';`,
		`var opt = document.createElement('option');`,
		`addOption(current);`,
		`populateAuditActionFilter(entries);`,
		`function auditURLInputs(fromInput, toInput) {`,
		`CSM.urlState.bind({ inputs: auditURLInputs(_auditFromInput, _auditToInput) });`,
		`function auditLocalDateMillis(value, endExclusive) {`,
		`if (d.getFullYear() !== year || d.getMonth() !== month || d.getDate() !== day) return null;`,
		`if (endExclusive) d.setDate(d.getDate() + 1);`,
		`if (to !== null && ts >= to) return false;`,
		`filters: [{ id: 'audit-action-filter', attr: 'data-action' }],`,
		`rowFilter: _auditDateInRange`,
		`function _auditDateInRange(row) {`,
		`_auditTable.currentPage = 1;`,
		`action: document.getElementById('audit-action-filter'),`,
		`from: fromInput,`,
		`to: toInput`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("audit.js missing P3.1 fragment %q", fragment)
		}
	}
	if strings.Contains(jsText, `select.value = current`) {
		t.Fatal("audit.js must let URL-state binding set the action select after CSM.Table listeners are installed")
	}

	table, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	tText := string(table)
	for _, fragment := range []string{
		`this.rowFilter = opts.rowFilter || null;`,
		`if (typeof self.rowFilter === 'function' && !self.rowFilter(item.row)) {`,
	} {
		if !strings.Contains(tText, fragment) {
			t.Fatalf("table.js missing rowFilter hook %q", fragment)
		}
	}
}

// TestAccountPerTabFilters pins WEB_ROADMAP P3.2: each account tab
// renders its own toolbar (search + severity / check / date filters
// scoped per tab) and feeds them into CSM.Table via filters[] and the
// rowFilter hook so users can drill into just one severity or a
// specific window.
func TestAccountPerTabFilters(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/account.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(js)
	for _, fragment := range []string{
		`id="account-findings-search"`,
		`id="account-findings-sev"`,
		`id="account-findings-check"`,
		`id="account-quarantine-search"`,
		`id="account-history-search"`,
		`id="account-history-sev"`,
		`id="account-history-from"`,
		`id="account-history-to"`,
		`data-index="' + i + '" data-severity="' + String(f.severity || 0) + '"`,
		`data-severity="' + String(f.severity || 0) + '"`,
		`data-check="' + CSM.attr(f.check || '') + '"`,
		`data-path="' + CSM.attr(quarantined[q].original_path || '') + '"`,
		`data-timestamp="' + CSM.attr(e.timestamp || '') + '"`,
		`{ id: 'account-findings-sev',   attr: 'data-severity' }`,
		`{ id: 'account-findings-check', attr: 'data-check' }`,
		`{ id: 'account-history-sev', attr: 'data-severity' }`,
		`searchAttr: 'data-path'`,
		`function _localDateMillis(value, endExclusive) {`,
		`if (endExclusive) d.setDate(d.getDate() + 1);`,
		`rowFilter: _inRange`,
		`function _filteredRowsForTab(tab, rows) {`,
		`tabTables[tab]`,
		`table.filteredRows`,
		`_filteredRowsForTab('findings', cachedData.findings || [])`,
		`_filteredRowsForTab('quarantine', cachedData.quarantined || [])`,
		`_filteredRowsForTab('history', cachedData.history || [])`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("account.js missing P3.2 fragment %q", fragment)
		}
	}
}

// TestQuarantinePageHasFilterPack pins WEB_ROADMAP P3.3: quarantine
// page exposes account / detector / date-range filters in addition to
// the existing path search, all persisted to URL via CSM.urlState.bind.
// Account and detector dropdowns are populated from observed rows so
// the lists stay aligned to actual quarantine contents.
func TestQuarantinePageHasFilterPack(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/quarantine.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="quarantine-account-filter"`,
		`id="quarantine-source-filter"`,
		`id="quarantine-from"`,
		`id="quarantine-to"`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("quarantine.html missing P3.3 filter fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/quarantine.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`function _quarAccountFromPath(path) {`,
		`function _quarDetectorFromReason(reason) {`,
		`function _quarLocalDateMillis(value, endExclusive) {`,
		`if (d.getFullYear() !== year || d.getMonth() !== month || d.getDate() !== day) return null;`,
		`if (endExclusive) d.setDate(d.getDate() + 1);`,
		`var accounts = Object.create(null), detectors = Object.create(null);`,
		`_resetQuarTable();`,
		`_populateQuarFilterOptions(files || []);`,
		`_bindQuarURLState(fromEl, toEl);`,
		`data-path="' + CSM.attr(f.original_path || '') + '" data-account="' + CSM.attr(acct) + '"`,
		`data-source="' + CSM.attr(det) + '"`,
		`data-timestamp="' + CSM.attr(f.quarantined_at || '') + '"`,
		`var from = fromEl ? _quarLocalDateMillis(fromEl.value, false) : null;`,
		`var to = toEl ? _quarLocalDateMillis(toEl.value, true) : null;`,
		`if (to !== null && ts >= to) return false;`,
		`searchAttr: 'data-path',`,
		`{ id: 'quarantine-account-filter', attr: 'data-account' },`,
		`{ id: 'quarantine-source-filter',  attr: 'data-source' }`,
		`rowFilter: _inRange`,
		`_bindQuarDateFilters(fromEl, toEl);`,
		`account: document.getElementById('quarantine-account-filter'),`,
		`source: document.getElementById('quarantine-source-filter'),`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("quarantine.js missing P3.3 fragment %q", fragment)
		}
	}
	if strings.Contains(jsText, `86400000`) || strings.Contains(jsText, `new Date(fromEl.value + 'T00:00:00')`) {
		t.Fatal("quarantine.js must use validated calendar-day bounds instead of fixed 24-hour date math")
	}
}

// TestEmailQuarantineToolbar pins WEB_ROADMAP P3.4: email quarantine
// pane gains search / direction / date-range filters and bulk
// release+delete via CSM.bulk. Search scope is limited to
// from/to/subject through searchAttr so badges and table chrome don't
// pollute matches.
func TestEmailQuarantineToolbar(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/email.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="email-quar-search"`,
		`id="email-quar-dir"`,
		`id="email-quar-from"`,
		`id="email-quar-to"`,
		`id="email-quar-bulk-release"`,
		`id="email-quar-bulk-delete"`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("email.html missing P3.4 fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/email.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`tableId: 'email-quar-table',`,
		`searchId: 'email-quar-search',`,
		`searchAttr: 'data-search',`,
		`filters: [{ id: 'email-quar-dir', attr: 'data-direction' }],`,
		`rowCheckboxSelector: '.email-quar-cb',`,
		`selectAllSelector: '#email-quar-select-all',`,
		`labelTemplate: 'Release {n} message(s)' }`,
		`labelTemplate: 'Delete {n} message(s)' }`,
		`data-direction="' + CSM.attr(msg.direction || '') + '"`,
		`data-quar-timestamp="' + CSM.attr(msg.quarantined_at || '') + '"`,
		`<td data-label="Time" data-timestamp="' + CSM.attr(msg.quarantined_at || '') + '">' + CSM.esc(time) + '</td>`,
		`data-search="' + CSM.attr(searchBlob.toLowerCase()) + '"`,
		`var _emailQuarURLUnbind = null;`,
		`email_quar_q: document.getElementById('email-quar-search'),`,
		`email_quar_dir: document.getElementById('email-quar-dir'),`,
		`email_quar_from: fromEl,`,
		`email_quar_to: toEl`,
		`_bindEmailQuarURLState(fromEl, toEl);`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("email.js missing P3.4 fragment %q", fragment)
		}
	}
	if strings.Contains(jsText, `<tr data-direction="' + CSM.attr(msg.direction || '') + '" data-timestamp=`) {
		t.Fatal("email quarantine rows must not use data-timestamp; CSM.initTimeAgo rewrites matching elements")
	}
}

// TestThreatAttackersFilterPack pins WEB_ROADMAP P3.5: threat
// intelligence top-attackers table gains country, verdict, and
// last-seen date-range filters in addition to the existing search.
// Country dropdown is populated from observed rows.
func TestThreatAttackersFilterPack(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/threat.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="attackers-country"`,
		`id="attackers-verdict"`,
		`id="attackers-from"`,
		`id="attackers-to"`,
		`<option value="malicious">Malicious</option>`,
		`<option value="clean">Clean</option>`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("threat.html missing P3.5 fragment %q", fragment)
		}
	}
	if strings.Contains(tmplText, `<option value="benign">`) {
		t.Fatal("threat verdict filter must use the API's clean verdict value, not benign")
	}

	js, err := os.ReadFile("../../ui/static/js/threat.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`data-country="'+CSM.attr((r.country||'').toUpperCase())+'"`,
		`data-verdict="'+CSM.attr((r.verdict||'').toLowerCase())+'"`,
		`data-last-seen="'+CSM.attr(r.last_seen||'')+'"`,
		`function attackerURLInputs(countrySel, fromEl, toEl) {`,
		`function populateAttackerCountryFilter(rows) {`,
		`var selected = CSM.urlState.get('country') || countrySel.value || '';`,
		`Object.keys(countries).sort().forEach(addCountry);`,
		`var countrySel = populateAttackerCountryFilter(data || []);`,
		`{ id: 'attackers-country', attr: 'data-country' },`,
		`{ id: 'attackers-verdict', attr: 'data-verdict' }`,
		`function threatLocalDateMillis(value, endExclusive) {`,
		`if (d.getFullYear() !== year || d.getMonth() !== month || d.getDate() !== day) return null;`,
		`if (endExclusive) d.setDate(d.getDate() + 1);`,
		`var from = fromEl ? threatLocalDateMillis(fromEl.value, false) : null;`,
		`var to = toEl ? threatLocalDateMillis(toEl.value, true) : null;`,
		`if (to !== null && ts >= to) return false;`,
		`rowFilter: _attackerInRange`,
		`country: countrySel,`,
		`verdict: document.getElementById('attackers-verdict'),`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("threat.js missing P3.5 fragment %q", fragment)
		}
	}
	if strings.Contains(jsText, `86400000`) || strings.Contains(jsText, `new Date(fromEl.value + 'T00:00:00')`) {
		t.Fatal("threat.js must use validated calendar-day bounds instead of fixed 24-hour date math")
	}
	emptyIdx := strings.Index(jsText, `if(!data||data.length===0){`)
	if emptyIdx < 0 {
		t.Fatal("threat.js missing no-attack-data branch")
	}
	emptyBody := jsText[emptyIdx:]
	emptyBindIdx := strings.Index(emptyBody, `CSM.urlState.bind({ inputs: attackerURLInputs(countrySel, fromEl, toEl) });`)
	emptyReturnIdx := strings.Index(emptyBody, `return;`)
	if emptyBindIdx < 0 || emptyReturnIdx < 0 || emptyBindIdx > emptyReturnIdx {
		t.Fatal("threat.js must bind top-attackers URL state before returning from the empty-data branch")
	}
}

// TestModSecBlocksBulkToggle pins WEB_ROADMAP P3.7: blocked-IPs tab on
// the ModSecurity page gains per-row checkboxes (keyed by rule_id) and
// a bulk-disable button wired through CSM.bulk + the existing
// /api/v1/modsec/rules/apply endpoint.
func TestModSecBlocksBulkToggle(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/modsec.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="modsec-bulk-disable"`,
		`Disable Selected`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("modsec.html missing P3.7 fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/modsec.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`function modsecRuleID(ruleID) {`,
		`if (id < 900000 || id > 900999) return null;`,
		`function selectedModSecRuleIDs() {`,
		`id="modsec-select-all"`,
		`class="form-check-input modsec-block-cb"`,
		`data-rule="' + CSM.attr(selectableRuleText) + '"`,
		`rowCheckboxSelector: '.modsec-block-cb:not(:disabled)',`,
		`selectAllSelector: '#modsec-select-all',`,
		`valueAttr: 'data-rule',`,
		`CSM.get('/api/v1/modsec/rules', { silent: true })`,
		`if (id !== null && rule.enabled === false) disabledSet[id] = true;`,
		`rules.forEach(function(id) { disabledSet[id] = true; });`,
		`return CSM.post('/api/v1/modsec/rules/apply', { disabled: disabled });`,
		`if (!data.ok) {`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("modsec.js missing P3.7 fragment %q", fragment)
		}
	}
	for _, bad := range []string{
		`data-rule="' + CSM.attr(b.rule_id || '') + '"`,
		`CSM.post('/api/v1/modsec/rules/apply', { disabled: rules })`,
		`var ruleSet = {};`,
	} {
		if strings.Contains(jsText, bad) {
			t.Fatalf("modsec.js still contains unsafe P3.7 fragment %q", bad)
		}
	}
}

// TestSettingsPageUsesQueryStringDeepLink pins WEB_ROADMAP P3.8: the
// settings page navigates between sections via ?section= so bookmarks
// and external links land on the right section without a reload. The
// legacy #hash form still resolves on first load so old links keep
// working.
func TestSettingsPageUsesQueryStringDeepLink(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/settings.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`item.href = sectionHref(s.id);`,
		`loadSection(s.id, {urlMode: "push"});`,
		`CSM.urlState.push({section: id}, opts);`,
		`CSM.urlState.set({section: id}, opts);`,
		`CSM.urlState.get("section")`,
		`url.hash = "";`,
		`loadSection(target, {urlMode: "replace"});`,
		`loadSection(next, {urlMode: "none"});`,
		`if (!confirmLeaveIfDirty()) {`,
		`window.addEventListener("popstate", function () {`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("settings.js missing P3.8 fragment %q", fragment)
		}
	}
	if strings.Contains(text, `item.href = "#" + s.id;`) {
		t.Fatal("settings.js still renders hash-only section links; use ?section=")
	}
	// loadSection() must no longer unconditionally write to
	// window.location.hash; the legacy assignment lives only in the
	// CSM-unavailable fallback branch.
	if strings.Contains(text, "window.location.hash = \"#\" + id;\n\n        const panel") {
		t.Fatal("settings.js still always writes #hash on section change; move to CSM.urlState")
	}
}

// TestNoCrossTemplateDuplicateIDs pins WEB_ROADMAP P4.1: prior audit
// found duplicate element IDs across templates (audit-search /
// audit-content in firewall+audit, lookup-form / lookup-ip /
// lookup-result in firewall+threat, rules-table / rules-tbody in
// rules+modsec-rules). Each page loads independently so no live
// breakage existed, but the dup IDs were a known foot-gun for
// future SPA work. After P4.1 each ID lives on only one template;
// cross-template collisions fail the test.
func TestNoCrossTemplateDuplicateIDs(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	idRe := regexp.MustCompile(`\bid=["']([a-zA-Z0-9_-]+)["']`)
	// owners[id] = path that first declared it; second declaration is
	// the regression.
	owners := map[string]string{}
	collisions := []string{}
	// IDs that legitimately appear in layout.html and every page (e.g.
	// shared modal / toast containers). Allowlisted to keep the lint
	// focused on page-scope IDs.
	allow := map[string]bool{
		"csm-confirm-modal": true, "csm-confirm-body": true,
		"csm-confirm-ok": true, "csm-confirm-cancel": true,
	}
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		seenInFile := map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(text, -1) {
			id := m[1]
			if allow[id] {
				continue
			}
			if seenInFile[id] {
				continue
			}
			seenInFile[id] = true
			if prev, ok := owners[id]; ok && prev != path {
				collisions = append(collisions, id+" in "+filepath.Base(prev)+" and "+filepath.Base(path))
			} else {
				owners[id] = path
			}
		}
	}
	if len(collisions) > 0 {
		for _, c := range collisions {
			t.Errorf("duplicate cross-template id: %s", c)
		}
	}
}

func TestTemplateLabelsReferenceExistingIDs(t *testing.T) {
	files, err := filepath.Glob("../../ui/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	idRe := regexp.MustCompile(`\bid=["']([a-zA-Z0-9_-]+)["']`)
	labelRe := regexp.MustCompile(`<label\b[^>]*\bfor=["']([a-zA-Z0-9_-]+)["']`)
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		ids := map[string]bool{}
		for _, m := range idRe.FindAllStringSubmatch(text, -1) {
			ids[m[1]] = true
		}
		for _, m := range labelRe.FindAllStringSubmatch(text, -1) {
			if !ids[m[1]] {
				t.Errorf("%s label for %q has no matching id", filepath.Base(path), m[1])
			}
		}
	}
}

// TestPhase4A11yPatchesPresent pins WEB_ROADMAP P4.2: account tab
// buttons carry aria-controls, the active tab labels the tabpanel, threat
// select-all has an aria-label, performance findings region is aria-busy +
// aria-live with a terminal error state, error toasts promote to role=alert +
// aria-live=assertive, and the shared detail panel traps Tab focus while open.
func TestPhase4A11yPatchesPresent(t *testing.T) {
	for _, tc := range []struct{ path, fragment string }{
		{"../../ui/templates/account.html", `aria-controls="account-tab-content"`},
		{"../../ui/templates/account.html", `id="account-tabbtn-findings"`},
		{"../../ui/templates/account.html", `role="tabpanel" aria-live="polite" aria-labelledby="account-tabbtn-findings" tabindex="0"`},
		{"../../ui/static/js/account.js", `content.setAttribute('aria-labelledby', activeID);`},
		{"../../ui/templates/threat.html", `id="select-all-attackers" aria-label="Select all visible attackers"`},
		{"../../ui/templates/performance.html", `id="perf-findings" aria-busy="true" aria-live="polite"`},
		{"../../ui/static/js/performance.js", `setFindingsBusy(true);`},
		{"../../ui/static/js/performance.js", `findingsEl.setAttribute('aria-busy', busy ? 'true' : 'false');`},
		{"../../ui/static/js/performance.js", `renderPerformanceError();`},
		{"../../ui/static/js/toast.js", `toast.setAttribute('role', type === 'error' ? 'alert' : 'status');`},
		{"../../ui/static/js/toast.js", `toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');`},
		{"../../ui/static/js/csm-ui.js", `if (e.key === 'Tab' && panelEl) {`},
		{"../../ui/static/js/csm-ui.js", `if (e.shiftKey && document.activeElement === first) {`},
		{"../../ui/static/js/csm-ui.js", `if (!panelEl.contains(document.activeElement)) {`},
	} {
		src, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), tc.fragment) {
			t.Errorf("%s missing P4.2 fragment %q", tc.path, tc.fragment)
		}
	}
}

// TestRulesImportStateHasInFlightUX pins WEB_ROADMAP P4.4: the rules
// page "Import State" upload now disables its label and surfaces
// "Importing..." text with aria-busy while the POST is in flight, and
// always restores the label after success / failure / parse error.
func TestRulesImportStateHasInFlightUX(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/rules.js")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := os.ReadFile("../../ui/templates/rules.html")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`label.classList.add('disabled');`,
		`label.setAttribute('aria-busy', 'true');`,
		`label.setAttribute('aria-disabled', 'true');`,
		`input.disabled = true;`,
		`labelText.textContent = 'Importing...';`,
		`function restore() {`,
		`input.disabled = false;`,
		`labelText.textContent = origText || 'Import State';`,
		`}).finally(restore);`,
		`reader.onerror = function() {`,
		`} catch(ex) {`,
		`} finally {`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("rules.js missing P4.4 fragment %q", fragment)
		}
	}
	if strings.Contains(text, `label.textContent =`) {
		t.Fatal("rules.js must not replace the whole import label; that detaches the file input while an import is in flight")
	}
	for _, fragment := range []string{
		`data-import-label-icon`,
		`data-import-label-text`,
	} {
		if !strings.Contains(string(tmpl), fragment) {
			t.Fatalf("rules.html missing import label fragment %q", fragment)
		}
	}
}

// TestShortcutsHelpGrouped pins WEB_ROADMAP P5.5: the ? help overlay
// now renders shortcuts grouped by context ("General", "Navigate",
// "Findings page") so operators scan by what they're trying to do,
// not by the keystroke alphabet. Overlay also carries role=dialog +
// aria-modal so screen readers announce it correctly.
func TestShortcutsHelpGrouped(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/shortcuts.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`var _shortcutGroups = [`,
		`label: 'General',`,
		`label: 'Navigate',`,
		`label: 'Findings page',`,
		`for (var g = 0; g < _shortcutGroups.length; g++) {`,
		`_helpOverlay.setAttribute('role', 'dialog');`,
		`_helpOverlay.setAttribute('aria-modal', 'true');`,
		`_helpOverlay.setAttribute('aria-labelledby', 'csm-shortcuts-title');`,
		`title.id = 'csm-shortcuts-title';`,
		`var groupHeader = document.createElement('h4');`,
		`table.setAttribute('aria-labelledby', groupID);`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("shortcuts.js missing P5.5 fragment %q", fragment)
		}
	}
	if strings.Contains(text, "var _descriptions = [") {
		t.Fatal("shortcuts.js still uses flat _descriptions; switch to grouped _shortcutGroups")
	}
}

func TestShortcutsHelpModalFocusContract(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/shortcuts.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, fragment := range []string{
		`var _helpReturnFocus = null;`,
		`_helpOverlay.tabIndex = -1;`,
		`_helpReturnFocus = document.activeElement;`,
		`_helpOverlay.focus();`,
		`_helpReturnFocus.focus();`,
		`if (e.key === 'Tab') {`,
		`if (_helpOverlay) _helpOverlay.focus();`,
		`if (_helpOverlay && document.activeElement !== _helpOverlay) {`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("shortcuts.js missing modal focus fragment %q", fragment)
		}
	}

	helpVisibleIdx := strings.Index(text, `if (_helpVisible) {`)
	inputGuardIdx := strings.Index(text, `if (_isInputFocused()) {`)
	if helpVisibleIdx < 0 || inputGuardIdx < 0 {
		t.Fatal("shortcuts.js missing help-visible or input-focus guard")
	}
	if helpVisibleIdx > inputGuardIdx {
		t.Fatal("shortcuts.js must handle the visible modal before the input-focus guard so focus cannot escape behind it")
	}
}

// TestRefreshManualHasFallback pins the fix for the
// dead-Refresh-button bug: CSM.refresh.manual must either dispatch the
// event (when at least one subscriber is registered) or fall back to a
// full window.location.reload so pages that fetch data once at load
// never leave the operator wondering why the icon spun without effect.
// The static-asset check is conservative; the contract is enforced by
// requiring the reload literal, the subscribers counter, the
// onRefresh helper, and the cross-IIFE _bumpSubscriber bridge from
// CSM.poll so pollers do not get treated as no-subscriber pages.
func TestRefreshManualHasFallback(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`var subscribers = 0;`,
		`if (subscribers === 0) {`,
		`window.location.reload();`,
		`onRefresh: function(fn)`,
		`_bumpSubscriber: function() { subscribers++; }`,
		`_dropSubscriber: function() { subscribers = Math.max(0, subscribers - 1); }`,
		`CSM.refresh._bumpSubscriber()`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("csrf.js missing refresh-fallback fragment %q", fragment)
		}
	}

	// The two pages from the bug report should wire onRefresh so they
	// refresh in-place instead of reloading, preserving filter state.
	for _, path := range []string{"quarantine.js", "audit.js", "firewall.js"} {
		body, err := os.ReadFile("../../ui/static/js/" + path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "CSM.refresh.onRefresh(") {
			t.Fatalf("%s does not register a refresh-now handler", path)
		}
	}
}

// TestToolbarFilterHasBoundedFlexWidth pins the toolbar filter sizing contract:
// Bootstrap form controls default to width:100%, while data-derived option
// labels can be longer than the intended toolbar slot. Filters need explicit
// flex sizing plus a max width so they stay inline without overflowing.
func TestToolbarFilterHasBoundedFlexWidth(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(css)
	filterRule := cssRule(t, cssText, `.csm-toolbar__filter`)
	assertCSSDeclaration(t, filterRule, "flex", "0 1 auto")
	assertCSSDeclaration(t, filterRule, "width", "auto")
	assertCSSDeclaration(t, filterRule, "min-width", "140px")
	assertCSSDeclaration(t, filterRule, "max-width", "220px")

	dateRule := cssRule(t, cssText, `.csm-toolbar__filter[type="date"]`)
	assertCSSDeclaration(t, dateRule, "min-width", "160px")
}

func cssRule(t *testing.T, cssText, selector string) string {
	t.Helper()

	rulePattern := regexp.MustCompile(regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	match := rulePattern.FindStringSubmatch(cssText)
	if len(match) != 2 {
		t.Fatalf("csm.css missing rule for %s", selector)
	}
	return match[1]
}

func assertCSSDeclaration(t *testing.T, rule, property, value string) {
	t.Helper()

	declarationPattern := regexp.MustCompile(`(?:^|;)\s*` + regexp.QuoteMeta(property) + `\s*:\s*` + regexp.QuoteMeta(value) + `\s*(?:;|$)`)
	if !declarationPattern.MatchString(rule) {
		t.Fatalf("CSS rule %q missing %s: %s", rule, property, value)
	}
}

// TestCSPScriptPolicyStrict pins WEB_ROADMAP P6.3: the runtime CSP keeps
// executable scripts same-origin only. Templates may carry inert JSON data
// blocks, but not inline executable script bodies.
func TestCSPScriptPolicyStrict(t *testing.T) {
	csp := webUISecurityHeader(t, "Content-Security-Policy")
	directives := parseCSPDirectives(csp)
	scriptSrc, ok := directives["script-src"]
	if !ok {
		t.Fatalf("CSP header missing script-src directive: %q", csp)
	}
	if len(scriptSrc) != 1 || scriptSrc[0] != "'self'" {
		t.Fatalf("script-src = %q, want exactly ['self']", strings.Join(scriptSrc, " "))
	}

	for _, name := range []string{"script-src", "script-src-elem", "script-src-attr"} {
		if sources, ok := directives[name]; ok {
			assertCSPDirectiveHasNoScriptRelaxation(t, name, sources)
		}
	}

	for _, p := range webUISourceFiles(t, "../../ui/templates/*.html") {
		assertNoInlineExecutableScripts(t, p)
	}

	styleTagCreation := regexp.MustCompile(`document\.createElement\(\s*['"]style['"]\s*\)`)
	for _, p := range webUISourceFiles(t, "../../ui/static/js/*.js") {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if styleTagCreation.Match(src) {
			t.Fatalf("%s creates a runtime <style> tag; keep static styles in csm.css", p)
		}
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".csm-kbd-selected {") {
		t.Fatal("csm.css missing .csm-kbd-selected rule lifted from shortcuts.js")
	}
}

func webUISecurityHeader(t *testing.T, name string) string {
	t.Helper()

	rr := httptest.NewRecorder()
	handler := (&Server{}).securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/dashboard", nil))

	value := rr.Header().Get(name)
	if value == "" {
		t.Fatalf("missing %s header", name)
	}
	return value
}

func parseCSPDirectives(csp string) map[string][]string {
	directives := make(map[string][]string)
	for _, rawDirective := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(rawDirective))
		if len(fields) == 0 {
			continue
		}
		directives[strings.ToLower(fields[0])] = fields[1:]
	}
	return directives
}

func assertCSPDirectiveHasNoScriptRelaxation(t *testing.T, name string, sources []string) {
	t.Helper()

	for _, source := range sources {
		switch source {
		case "'unsafe-inline'", "'unsafe-eval'":
			t.Fatalf("%s must not allow %s", name, source)
		}
		if strings.Contains(source, "*") {
			t.Fatalf("%s must not allow wildcard source %s", name, source)
		}
	}
}

func assertNoInlineExecutableScripts(t *testing.T, path string) {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			attrs := htmlNodeAttrs(n)
			if src, hasSrc := attrs["src"]; hasSrc {
				if !strings.HasPrefix(src, "/static/js/") {
					t.Errorf("%s contains non-static script source %q", path, src)
				}
			} else if !isAllowedNonExecutableScriptType(attrs["type"]) {
				t.Errorf("%s contains inline executable <script> tag", path)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
}

func htmlNodeAttrs(n *html.Node) map[string]string {
	attrs := make(map[string]string, len(n.Attr))
	for _, attr := range n.Attr {
		attrs[strings.ToLower(attr.Key)] = strings.TrimSpace(attr.Val)
	}
	return attrs
}

func isAllowedNonExecutableScriptType(scriptType string) bool {
	return strings.EqualFold(strings.TrimSpace(scriptType), "application/json")
}

// TestResponsivePolish pins WEB_ROADMAP P6.1: firewall config tables
// are wrapped in table-responsive so they don't overflow on phones,
// and the topbar's chatty pills visually hide their labels below 576px
// so the action buttons stay reachable while live status text remains
// available to assistive tech.
func TestResponsivePolish(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/firewall.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="fw-config-table">`,
		`<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="fw-config-table2">`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("firewall.html missing P6.1 responsive wrap %q", fragment)
		}
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(css)
	for _, fragment := range []string{
		`@media (max-width: 575.98px) {`,
		`#csm-sse-pill .csm-sse-pill__label,`,
		`#csm-refresh-pill {`,
		`position: absolute !important;`,
		`clip: rect(0, 0, 0, 0) !important;`,
		`white-space: nowrap !important;`,
	} {
		if !strings.Contains(cssText, fragment) {
			t.Fatalf("csm.css missing P6.1 fragment %q", fragment)
		}
	}
	if strings.Contains(cssText, `#csm-refresh-pill { display: none !important; }`) {
		t.Fatal("small-screen refresh status must be visually hidden, not display:none, so aria-live updates remain available")
	}
}

// TestDarkModeContrastPalette pins WEB_ROADMAP P6.4: severity badges,
// outline buttons, and muted text are recolored so WCAG AA contrast
// holds in dark mode. Pastel dark-mode backgrounds need dark text, and
// the previous muted #6b7a8d on the #1a2234 page background was
// below the threshold.
func TestDarkModeContrastPalette(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}

	rules := parseCSSRules(string(css))
	lightVars := cssVariables(rules[":root"])
	darkVars := cssVariables(rules[".theme-dark"])
	for name, value := range lightVars {
		if _, ok := darkVars[name]; !ok {
			darkVars[name] = value
		}
	}

	color := func(selector, property string, vars map[string]string) string {
		t.Helper()
		return resolveCSSColor(t, cssDeclaration(t, rules, selector, property), vars)
	}
	assertContrast := func(name, foreground, background string) {
		t.Helper()
		const wcagAANormalText = 4.5
		if ratio := contrastRatio(t, foreground, background); ratio < wcagAANormalText {
			t.Fatalf("%s contrast %.2f:1 for %s on %s, want at least %.1f:1", name, ratio, foreground, background, wcagAANormalText)
		}
	}

	pageDark := color(".theme-dark", "background-color", darkVars)
	cardDark := color(".theme-dark .card", "background-color", darkVars)
	for _, tc := range []struct {
		name       string
		foreground string
		background string
	}{
		{"light critical badge", color(".badge-critical", "color", lightVars), color(".badge-critical", "background", lightVars)},
		{"light high badge", color(".badge-high", "color", lightVars), color(".badge-high", "background", lightVars)},
		{"light warning badge", color(".badge-warning", "color", lightVars), color(".badge-warning", "background", lightVars)},
		{"dark critical badge", color(".theme-dark .badge-critical", "color", darkVars), color(".badge-critical", "background", darkVars)},
		{"dark high badge", color(".badge-high", "color", darkVars), color(".badge-high", "background", darkVars)},
		{"dark warning badge", color(".badge-warning", "color", darkVars), color(".badge-warning", "background", darkVars)},
		{"light high outline", color(".btn-outline-high", "color", lightVars), "#ffffff"},
		{"light warning outline", color(".btn-outline-warning", "color", lightVars), "#ffffff"},
		{"dark high outline on page", color(".btn-outline-high", "color", darkVars), pageDark},
		{"dark warning outline on page", color(".btn-outline-warning", "color", darkVars), pageDark},
		{"dark high outline on card", color(".btn-outline-high", "color", darkVars), cardDark},
		{"dark warning outline on card", color(".btn-outline-warning", "color", darkVars), cardDark},
		{"light critical outline hover", color(".btn-outline-critical:hover", "color", lightVars), color(".btn-outline-critical:hover", "background", lightVars)},
		{"light high outline hover", color(".btn-outline-high:hover", "color", lightVars), color(".btn-outline-high:hover", "background", lightVars)},
		{"light warning outline hover", color(".btn-outline-warning:hover", "color", lightVars), color(".btn-outline-warning:hover", "background", lightVars)},
		{"dark critical outline hover", color(".theme-dark .btn-outline-critical:hover", "color", darkVars), color(".btn-outline-critical:hover", "background", darkVars)},
		{"dark high outline hover", color(".btn-outline-high:hover", "color", darkVars), color(".btn-outline-high:hover", "background", darkVars)},
		{"dark warning outline hover", color(".btn-outline-warning:hover", "color", darkVars), color(".btn-outline-warning:hover", "background", darkVars)},
		{"dark muted text on page", color(".theme-dark .text-muted", "color", darkVars), pageDark},
		{"dark muted text on card", color(".theme-dark .text-muted", "color", darkVars), cardDark},
		{"dark subheader on page", color(".theme-dark .subheader", "color", darkVars), pageDark},
		{"dark subheader on card", color(".theme-dark .subheader", "color", darkVars), cardDark},
	} {
		assertContrast(tc.name, tc.foreground, tc.background)
	}
}

func parseCSSRules(cssText string) map[string]map[string]string {
	commentPattern := regexp.MustCompile(`(?s)/\*.*?\*/`)
	cssText = commentPattern.ReplaceAllString(cssText, "")
	rulePattern := regexp.MustCompile(`(?s)([^{}]+)\{([^{}]+)\}`)
	rules := make(map[string]map[string]string)
	for _, match := range rulePattern.FindAllStringSubmatch(cssText, -1) {
		declarations := parseCSSDeclarations(match[2])
		for _, selector := range strings.Split(match[1], ",") {
			selector = strings.Join(strings.Fields(selector), " ")
			if selector == "" || strings.HasPrefix(selector, "@") {
				continue
			}
			if _, ok := rules[selector]; !ok {
				rules[selector] = make(map[string]string)
			}
			for property, value := range declarations {
				rules[selector][property] = value
			}
		}
	}
	return rules
}

func parseCSSDeclarations(body string) map[string]string {
	declarations := make(map[string]string)
	for _, part := range strings.Split(body, ";") {
		property, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		declarations[strings.TrimSpace(property)] = strings.TrimSpace(value)
	}
	return declarations
}

func cssVariables(declarations map[string]string) map[string]string {
	vars := make(map[string]string)
	for property, value := range declarations {
		if strings.HasPrefix(property, "--") {
			vars[property] = value
		}
	}
	return vars
}

func cssDeclaration(t *testing.T, rules map[string]map[string]string, selector, property string) string {
	t.Helper()
	declarations, ok := rules[selector]
	if !ok {
		t.Fatalf("csm.css missing selector %s", selector)
	}
	value, ok := declarations[property]
	if !ok {
		t.Fatalf("csm.css selector %s missing property %s", selector, property)
	}
	return value
}

func resolveCSSColor(t *testing.T, value string, vars map[string]string) string {
	t.Helper()
	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "!important"))
	if strings.HasPrefix(value, "var(") && strings.HasSuffix(value, ")") {
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "var("), ")"))
		resolved, ok := vars[name]
		if !ok {
			t.Fatalf("csm.css variable %s is not defined", name)
		}
		return resolveCSSColor(t, resolved, vars)
	}
	return normalizeHexColor(t, value)
}

func normalizeHexColor(t *testing.T, value string) string {
	t.Helper()
	if !strings.HasPrefix(value, "#") {
		t.Fatalf("unsupported CSS color %q", value)
	}
	hex := strings.TrimPrefix(value, "#")
	switch len(hex) {
	case 3:
		hex = strings.Repeat(hex[0:1], 2) + strings.Repeat(hex[1:2], 2) + strings.Repeat(hex[2:3], 2)
	case 6:
	default:
		t.Fatalf("unsupported hex color %q", value)
	}
	return "#" + strings.ToLower(hex)
}

func contrastRatio(t *testing.T, foreground, background string) float64 {
	t.Helper()
	foregroundLum := relativeLuminance(t, foreground)
	backgroundLum := relativeLuminance(t, background)
	lighter := math.Max(foregroundLum, backgroundLum)
	darker := math.Min(foregroundLum, backgroundLum)
	return (lighter + 0.05) / (darker + 0.05)
}

func relativeLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	hex = strings.TrimPrefix(normalizeHexColor(t, hex), "#")
	red := srgbChannel(t, hex[0:2])
	green := srgbChannel(t, hex[2:4])
	blue := srgbChannel(t, hex[4:6])
	return 0.2126*red + 0.7152*green + 0.0722*blue
}

func srgbChannel(t *testing.T, hex string) float64 {
	t.Helper()
	n, err := strconv.ParseUint(hex, 16, 8)
	if err != nil {
		t.Fatalf("parse CSS color channel %q: %v", hex, err)
	}
	v := float64(n) / 255
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

// TestPrintStylesheetWired pins the static-evidence print path: chrome and
// controls are hidden, current filtered tables print without client-side
// pagination, open detail panels stay printable, and the footer stamp is
// scoped to pages where layout.js populated the metadata attributes.
func TestPrintStylesheetWired(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(css)
	for _, fragment := range []string{
		"@media print {",
		".csm-sidebar,",
		".csm-topbar,",
		".csm-page-header__actions,",
		".card-actions,",
		".csm-sticky-actions,",
		".table-responsive { overflow: visible !important; }",
		".csm-detail-panel.show",
		".offcanvas-backdrop",
		"body[data-csm-print-url][data-csm-print-at]::after",
		"data-csm-print-url",
		"data-csm-print-at",
	} {
		if !strings.Contains(cssText, fragment) {
			t.Fatalf("csm.css missing print fragment %q", fragment)
		}
	}
	if strings.Contains(cssText, ".csm-bulk-bar") {
		t.Fatal("csm.css hides stale .csm-bulk-bar selector instead of the real .csm-sticky-actions bulk bar")
	}
	if strings.Contains(cssText, ".csm-detail-panel,\n") {
		t.Fatal("csm.css must keep an open detail panel printable instead of hiding every detail panel")
	}

	js, err := os.ReadFile("../../ui/static/js/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`addEventListener('beforeprint', preparePrint)`,
		`addEventListener('afterprint', restorePrint)`,
		`CSM.printTables.prepare()`,
		`CSM.printTables.restore()`,
		`'data-csm-print-url'`,
		`'data-csm-print-at'`,
		`return 'UTC' + sign`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("layout.js missing print fragment %q", fragment)
		}
	}

	table, err := os.ReadFile("../../ui/static/js/table.js")
	if err != nil {
		t.Fatal(err)
	}
	tableText := string(table)
	for _, fragment := range []string{
		`CSM.printTables`,
		`prepare: function()`,
		`tbl.perPage = 0;`,
		`tbl.currentPage = 1;`,
		`snap.table.perPage = snap.perPage;`,
		`CSM._tableInstances.push(this);`,
	} {
		if !strings.Contains(tableText, fragment) {
			t.Fatalf("table.js missing print pagination fragment %q", fragment)
		}
	}
}

// TestCommandPaletteWired pins WEB_ROADMAP P5.1: a Ctrl/Cmd+K command
// palette ships in palette.js, is loaded by the layout, lists the
// shortcut in the help overlay, and ships its overlay CSS.
func TestCommandPaletteWired(t *testing.T) {
	js, err := os.ReadFile("../../ui/static/js/palette.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`CSM.palette = (function()`,
		`(ev.key === 'k' || ev.key === 'K')`,
		`document.querySelectorAll('#csm-nav [data-csm-route]')`,
		`item.closest('[data-csm-admin-only][hidden]')`,
		`if (ev.defaultPrevented && !visible) return;`,
		`'Jump to page'`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("palette.js missing P5.1 fragment %q", fragment)
		}
	}

	layout, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), `<script src="/static/js/palette.js"></script>`) {
		t.Fatal("layout.html does not load palette.js")
	}

	shortcuts, err := os.ReadFile("../../ui/static/js/shortcuts.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shortcuts), `Open command palette`) {
		t.Fatal("shortcuts.js does not advertise the command palette")
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".csm-palette {") {
		t.Fatal("csm.css missing .csm-palette rule")
	}
}

func TestCommandPaletteShortcutDoesNotFallThroughToPageShortcuts(t *testing.T) {
	shortcuts, err := os.ReadFile("../../ui/static/js/shortcuts.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(shortcuts)
	for _, fragment := range []string{
		`function _hasNonShiftModifier(e) {`,
		`return e.metaKey || e.ctrlKey || e.altKey;`,
		`if (_hasNonShiftModifier(e)) {`,
		`_cancelChord();`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("shortcuts.js missing modified-key guard fragment %q", fragment)
		}
	}

	modifierGuardIdx := strings.Index(text, `if (_hasNonShiftModifier(e)) {`)
	chordIdx := strings.Index(text, `if (_pendingChord === 'g') {`)
	findingsIdx := strings.Index(text, `if (_isFindingsPage()) {`)
	if modifierGuardIdx < 0 || chordIdx < 0 || findingsIdx < 0 {
		t.Fatal("shortcuts.js missing modifier guard, chord handler, or findings shortcut block")
	}
	if modifierGuardIdx > chordIdx || modifierGuardIdx > findingsIdx {
		t.Fatal("shortcuts.js must ignore Ctrl/Cmd/Alt-modified keys before page shortcuts can handle them")
	}
}

// TestSSEHealthPillWired pins WEB_ROADMAP P5.6: layout exposes a
// "Live updates" header pill, CSM.sse owns the EventSource lifecycle
// and broadcasts state on csm:sse-state, and layout.js subscribes and
// repaints the pill. Without this wiring operators have no signal that
// the finding stream has dropped.
func TestSSEHealthPillWired(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="csm-sse-pill"`,
		`class="csm-sse-pill__dot"`,
		`class="csm-sse-pill__label"`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("layout.html missing P5.6 fragment %q", fragment)
		}
	}

	csrf, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	csrfText := string(csrf)
	for _, fragment := range []string{
		`CSM.sse = (function()`,
		`new EventSource(resolvedUrl)`,
		`'csm:sse-state'`,
		`'/api/v1/events'`,
	} {
		if !strings.Contains(csrfText, fragment) {
			t.Fatalf("csrf.js missing P5.6 fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`document.getElementById('csm-sse-pill')`,
		`window.addEventListener('csm:sse-state'`,
		`CSM.sse.start();`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("layout.js missing P5.6 fragment %q", fragment)
		}
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".csm-sse-pill {") {
		t.Fatal("csm.css missing .csm-sse-pill rule")
	}
}

func TestSSEWrapperIgnoresStaleSources(t *testing.T) {
	src, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	body := csmSSEBody(t, string(src))
	for _, fragment := range []string{
		`if (!started || document.hidden) return;`,
		`var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;`,
		`var source = null;`,
		`source = new EventSource(resolvedUrl);`,
		`es = source;`,
		`source.onopen = function() {`,
		`source.onerror = function() {`,
		`source.onmessage = function(ev) {`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("CSM.sse missing stale-source guard fragment %q", fragment)
		}
	}
	if got := strings.Count(body, `if (source !== es) return;`); got != 3 {
		t.Fatalf("CSM.sse should guard open/error/message handlers against stale sources, got %d guards", got)
	}
}

func csmSSEBody(t *testing.T, text string) string {
	t.Helper()
	start := strings.Index(text, "CSM.sse = (function() {")
	if start == -1 {
		t.Fatal("csrf.js missing CSM.sse definition")
	}
	tail := text[start:]
	end := strings.Index(tail, "\n})();\n\n// Connection-lost banner")
	if end == -1 {
		t.Fatal("csrf.js CSM.sse has no terminator")
	}
	return tail[:end]
}

// TestWhatsNewBadgeWired pins WEB_ROADMAP P5.7: layout exposes a
// "What's new" header button with a notification dot, and layout.js
// shows/clears the dot based on whether the running daemon version
// differs from the acknowledged version stored in localStorage.
func TestWhatsNewBadgeWired(t *testing.T) {
	tmpl, err := os.ReadFile("../../ui/templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplText := string(tmpl)
	for _, fragment := range []string{
		`id="csm-whats-new"`,
		`class="csm-whats-new-dot position-absolute"`,
		`href="https://github.com/pidginhost/csm/releases"`,
	} {
		if !strings.Contains(tmplText, fragment) {
			t.Fatalf("layout.html missing P5.7 fragment %q", fragment)
		}
	}

	js, err := os.ReadFile("../../ui/static/js/layout.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, fragment := range []string{
		`var btn = document.getElementById('csm-whats-new');`,
		`var STORAGE_KEY = 'csm-whatsnew-ack';`,
		`if (acknowledged !== current) {`,
		`localStorage.setItem(STORAGE_KEY, current);`,
	} {
		if !strings.Contains(jsText, fragment) {
			t.Fatalf("layout.js missing P5.7 fragment %q", fragment)
		}
	}

	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".csm-whats-new-dot {") {
		t.Fatal("csm.css missing .csm-whats-new-dot rule")
	}
}
