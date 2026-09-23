package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
)

// --- handleModSec / handleModSecRules (page rendering) ----------------

func TestHandleModSecRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleModSec(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleModSecRulesRendersOK(t *testing.T) {
	s := newTestServerWithTemplates(t, "tok")
	w := httptest.NewRecorder()
	s.handleModSecRules(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

// --- apiModSecStats ---------------------------------------------------

func TestAPIModSecStatsReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecBlocks --------------------------------------------------

func TestAPIModSecBlocksReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecBlocks(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecEvents --------------------------------------------------

func TestAPIModSecEventsReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecEvents(w, httptest.NewRequest("GET", "/?limit=5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecRules ---------------------------------------------------

func TestAPIModSecRulesReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecRules(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiModSecRulesApply (POST guard) ---------------------------------

func TestAPIModSecRulesApplyGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecRulesApply(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET apply = %d, want 405", w.Code)
	}
}

// --- apiModSecRulesEscalation -----------------------------------------

func TestAPIModSecRulesEscalationPutRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecRulesEscalation(w, httptest.NewRequest("PUT", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT escalation = %d, want 405", w.Code)
	}
}

// The ModSec Rules page lists every excluded rule from the same endpoint it
// changes them with, including rules the parsed rules file does not show.
func TestAPIModSecRulesEscalationListsExclusions(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	for _, id := range []int{900500, 900001} {
		w := httptest.NewRecorder()
		body := fmt.Sprintf(`{"rule_id":%d,"escalate":false}`, id)
		s.apiModSecRulesEscalation(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("exclude %d = %d", id, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.apiModSecRulesEscalation(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET escalation = %d", w.Code)
	}
	var resp struct {
		Rules []int `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !sort.IntsAreSorted(resp.Rules) {
		t.Errorf("rules not sorted: %v", resp.Rules)
	}
	for _, id := range []int{900001, 900500} {
		if !slices.Contains(resp.Rules, id) {
			t.Errorf("rules %v missing %d", resp.Rules, id)
		}
	}
}
