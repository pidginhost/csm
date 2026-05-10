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
		".csm-filter-toolbar",
		".csm-empty",
		".csm-sticky-actions",
		".csm-detail-panel",
		".csm-danger-zone",
		".csm-table-rowcard",
	}
	for _, cls := range wantClasses {
		if !strings.Contains(cssText, cls) {
			t.Errorf("csm.css missing shared primitive %s", cls)
		}
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
	} {
		if !strings.Contains(tblText, want) {
			t.Errorf("table.js missing extension hook %s", want)
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
// triage-first layout: page header, status strip, priority queue, and
// system posture sit above the recent activity feed and the analytics
// charts. The legacy stat cards stay reachable but no longer dominate
// the first screen.
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
		`id="system-posture"`,
		`id="dashboard-summary"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dashboard.html missing required section %q", want)
		}
	}

	// Priority queue must come before the live feed and the charts.
	priority := strings.Index(text, `id="priority-queue"`)
	feed := strings.Index(text, `id="live-feed-entries"`)
	timeline := strings.Index(text, `id="timeline-chart"`)
	if priority < 0 || feed < 0 || timeline < 0 {
		t.Fatal("dashboard.html missing one of priority queue, live feed, or timeline chart")
	}
	if priority >= feed {
		t.Errorf("priority queue must precede the live feed (got %d vs %d)", priority, feed)
	}
	if feed >= timeline {
		t.Errorf("live feed must precede the analytics charts (got %d vs %d)", feed, timeline)
	}

	js, err := os.ReadFile("../../ui/static/js/dashboard.js")
	if err != nil {
		t.Fatal(err)
	}
	jsText := string(js)
	for _, want := range []string{
		"loadPriorityQueue",
		"function _startPriorityQueueInterval",
		"renderSystemPosture",
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
		`class="csm-filter-toolbar"`,
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
		`new bootstrap.Tab(historyTabLink)`,
	} {
		if !strings.Contains(historyText, want) {
			t.Errorf("history.js missing history URL restore hook %q", want)
		}
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
		`id="fw-command-form"`,
		`class="csm-danger-zone`,
		`href="/settings#firewall"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("firewall.html missing phase-5 hook %q", want)
		}
	}

	for _, view := range []string{"overview", "lookup", "blocks", "allow", "config", "audit", "danger"} {
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
	bulkIdx := strings.Index(text, `id="bulk-unblock-btn"`)
	if dangerStart < 0 || bulkIdx < 0 || bulkIdx < dangerStart {
		t.Fatal("bulk-unblock-btn must live under the danger subview, not the blocks table")
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
		`switchFirewallView('lookup')`,
		`confirmDangerAction(msg, 'FLUSH')`,
		`confirmDangerAction(msg, 'UNBLOCK')`,
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
		"FieldGroupAccessPorts",
		"FieldGroupRateLimits",
		"FieldGroupFloodProtection",
		"FieldGroupGeoDynDNS",
		"FieldGroupSMTPControls",
		"FieldGroupLogging",
		"FieldGroupLimits",
		"FieldGroupScanIntervals",
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
		"rules.html", "threat.html",
	}
	for _, name := range pages {
		path := "../../ui/templates/" + name
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(src)
		if !strings.Contains(text, "csm-page-header") {
			t.Errorf("%s missing .csm-page-header primitive", name)
		}
		// Block the legacy Tabler header attribute that Phase 7 removed
		// (matches `<div class="page-header...` but not the new one).
		if regexp.MustCompile(`class="page-header[ "]`).MatchString(text) {
			t.Errorf("%s still uses legacy Tabler page-header; switch to csm-page-header", name)
		}
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
