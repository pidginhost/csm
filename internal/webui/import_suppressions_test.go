package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The import endpoint merged suppression rules straight from the bundle:
// a rule with no check suppressed nothing yet sat in the list forever, and a
// rule with an empty ID could never be deleted from the UI (the delete API
// requires an ID). Imported rules get the same validation as rules added
// through the UI, and a missing ID is generated.
func TestImportValidatesSuppressionRules(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `{"suppressions":[
		{"id":"","check":"webshell","path_pattern":"/home/a/*","reason":"vendor"},
		{"id":"r2","check":"","path_pattern":"/home/b/*","reason":"no check"},
		{"id":"r3","check":"phishing","reason":"ok"}
	]}`
	req := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", w.Code, w.Body.String())
	}

	rules := s.store.LoadSuppressions()
	if len(rules) != 2 {
		t.Fatalf("stored %d rules, want 2 (the check-less rule dropped): %+v", len(rules), rules)
	}
	for _, r := range rules {
		if r.ID == "" {
			t.Fatalf("imported rule stored without an ID and can never be deleted: %+v", r)
		}
		if r.Check == "" {
			t.Fatalf("check-less rule stored: %+v", r)
		}
	}
}

// An import applies the rules the suppressions route enforces: a check that
// is a pattern rather than a name, or an invalid glob, would be saved as a
// rule that matches nothing.
func TestImportSkipsSuppressionsTheRouteWouldRefuse(t *testing.T) {
	s := newTestServer(t, "tok")
	body := `{"suppressions":[
		{"id":"good","check":"webshell","path_pattern":"/home/a/*"},
		{"id":"glob-check","check":"webshell*","path_pattern":"/home/a/*"},
		{"id":"bad-glob","check":"webshell","path_pattern":"/home/a/[bad"}
	]}`
	req := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", w.Code, w.Body.String())
	}
	rules := s.store.LoadSuppressions()
	if len(rules) != 1 || rules[0].ID != "good" {
		t.Fatalf("stored %+v, want only the valid rule", rules)
	}
}
