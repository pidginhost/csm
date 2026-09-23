package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func postSuppression(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/suppressions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)
	return w
}

// An empty path pattern hides every finding of the check and stops its
// remediation. That scope must be asked for explicitly, never reached by
// leaving an optional field blank.
func TestSuppressionEmptyPathRequiresExplicitAllPaths(t *testing.T) {
	s := newTestServer(t, "tok")
	w := postSuppression(t, s, `{"check":"webshell","path_pattern":"","reason":"noise"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "all_paths") {
		t.Errorf("error should name the all_paths opt-in: %s", w.Body.String())
	}
	if rules := s.store.LoadSuppressions(); len(rules) != 0 {
		t.Fatalf("rule saved although the request was refused: %+v", rules)
	}
}

func TestSuppressionAllPathsCreatesCheckWideRule(t *testing.T) {
	s := newTestServer(t, "tok")
	w := postSuppression(t, s, `{"check":"webshell","all_paths":true,"reason":"lab host"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	rules := s.store.LoadSuppressions()
	if len(rules) != 1 || rules[0].Check != "webshell" || rules[0].PathPattern != "" {
		t.Fatalf("rules = %+v, want one check-wide webshell rule", rules)
	}
}

func TestSuppressionRejectsPatternTogetherWithAllPaths(t *testing.T) {
	s := newTestServer(t, "tok")
	w := postSuppression(t, s, `{"check":"webshell","path_pattern":"/home/a/*","all_paths":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	if rules := s.store.LoadSuppressions(); len(rules) != 0 {
		t.Fatalf("rule saved although the request was refused: %+v", rules)
	}
}

// A malformed glob never matches anything, so the operator would believe a
// finding is suppressed while it keeps alerting.
func TestSuppressionRejectsMalformedPathPattern(t *testing.T) {
	s := newTestServer(t, "tok")
	w := postSuppression(t, s, `{"check":"webshell","path_pattern":"/home/a/[bad"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400, body = %s", w.Code, w.Body.String())
	}
	if rules := s.store.LoadSuppressions(); len(rules) != 0 {
		t.Fatalf("rule saved although the request was refused: %+v", rules)
	}
}

// Every add, delete and import rewrites the whole rule set. Two requests at
// once must not lose each other's rule while both report success.
func TestConcurrentSuppressionChangesAreAllKept(t *testing.T) {
	s := newTestServer(t, "tok")
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := postSuppression(t, s, fmt.Sprintf(`{"check":"webshell","path_pattern":"/home/u%d/*"}`, i))
			if w.Code != http.StatusOK {
				t.Errorf("create %d = %d", i, w.Code)
			}
		}(i)
	}
	wg.Wait()
	if got := len(s.store.LoadSuppressions()); got != n {
		t.Fatalf("%d of %d concurrently created rules kept", got, n)
	}
}

func TestSuppressionWithPathPatternStillWorks(t *testing.T) {
	s := newTestServer(t, "tok")
	w := postSuppression(t, s, `{"check":"webshell","path_pattern":"/home/a/*","reason":"vendor"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", w.Code, w.Body.String())
	}
	rules := s.store.LoadSuppressions()
	if len(rules) != 1 || rules[0].PathPattern != "/home/a/*" {
		t.Fatalf("rules = %+v", rules)
	}
}
