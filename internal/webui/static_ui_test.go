package webui

import (
	"os"
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
