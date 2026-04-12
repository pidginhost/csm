package webui

import (
	"net/http"
	"net/http/httptest"
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

func TestAPIModSecRulesEscalationGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiModSecRulesEscalation(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET escalation = %d, want 405", w.Code)
	}
}
