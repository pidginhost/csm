package webui

import (
	"os"
	"path/filepath"
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

// TestNoInlineOnclickHandlersAcrossWebUIJS guards every shipped JS file in
// ui/static/js/ from regressing into inline onclick attributes. Inline
// handlers break the page's CSP and rot the audit story; bind via
// addEventListener instead.
func TestNoInlineOnclickHandlersAcrossWebUIJS(t *testing.T) {
	matches, err := filepath.Glob("../../ui/static/js/*.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no JS files found under ui/static/js/")
	}
	skip := map[string]struct{}{
		"chart.min.js":  {},
		"tabler.min.js": {},
	}
	for _, path := range matches {
		base := filepath.Base(path)
		if _, ok := skip[base]; ok {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(src), `onclick="`) {
			t.Errorf("%s contains an inline onclick=\" handler; bind via addEventListener", base)
		}
	}
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
		"density",
	} {
		if !strings.Contains(tblText, want) {
			t.Errorf("table.js missing extension hook %s", want)
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
