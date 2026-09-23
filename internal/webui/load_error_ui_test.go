package webui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// CSM.loadError hides the content it covers with the hidden attribute, but
// the Tabler display utilities (.d-flex and the like) are !important and
// come after its [hidden] rule, so they win. csm.css loads after Tabler, and
// its rule for the marker CSM.loadError sets is what hides such content.
func TestLoadErrorHidesContentWithDisplayUtilities(t *testing.T) {
	css, err := os.ReadFile("../../ui/static/css/csm.css")
	if err != nil {
		t.Fatal(err)
	}
	rule := regexp.MustCompile(`\[data-csm-load-error-hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}`)
	if !rule.Match(css) {
		t.Error("csm.css does not hide content marked by CSM.loadError over display utilities")
	}
	js, err := os.ReadFile("../../ui/static/js/csrf.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "setAttribute('data-csm-load-error-hidden', '')") {
		t.Error("CSM.loadError does not mark the content it hides")
	}
	for _, page := range []string{"layout.html", "login.html"} {
		html, err := os.ReadFile("../../ui/templates/" + page)
		if err != nil {
			t.Fatal(err)
		}
		tabler := strings.Index(string(html), `css/tabler.min.css`)
		own := strings.Index(string(html), `css/csm.css`)
		if tabler < 0 || own < 0 || own < tabler {
			t.Errorf("%s must load csm.css after tabler.min.css", page)
		}
	}
}
