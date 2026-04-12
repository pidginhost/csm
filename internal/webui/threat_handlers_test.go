package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- apiThreatStats (attackdb not initialized in test) -----------------

func TestAPIThreatStatsNoAttackDB(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiThreatTopAttackers -------------------------------------------

func TestAPIThreatTopAttackersNoAttackDB(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatTopAttackers(w, httptest.NewRequest("GET", "/?limit=5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiThreatIP (validation) ----------------------------------------

func TestAPIThreatIPMissing(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatIPInvalid(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatIP(w, httptest.NewRequest("GET", "/?ip=not-an-ip", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatIPValid(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatIP(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiThreatEvents (validation) ------------------------------------

func TestAPIThreatEventsMissingIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatEvents(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

func TestAPIThreatEventsValidIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatEvents(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiThreatDBStats ------------------------------------------------

func TestAPIThreatDBStatsReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatDBStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

// --- apiThreatWhitelist (GET returns list) ----------------------------

func TestAPIThreatWhitelistReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatWhitelist(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiThreatWhitelistIP (POST validation) --------------------------

func TestAPIThreatWhitelistIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatWhitelistIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET whitelist = %d, want 405", w.Code)
	}
}

func TestAPIThreatWhitelistIPMissingIP(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiThreatWhitelistIP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing IP = %d, want 400", w.Code)
	}
}

// --- apiThreatUnwhitelistIP (POST validation) ------------------------

func TestAPIThreatUnwhitelistIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatUnwhitelistIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unwhitelist = %d, want 405", w.Code)
	}
}

// --- apiThreatBlockIP (POST validation) ------------------------------

func TestAPIThreatBlockIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatBlockIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET block = %d, want 405", w.Code)
	}
}

// --- apiThreatClearIP (POST validation) ------------------------------

func TestAPIThreatClearIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatClearIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET clear = %d, want 405", w.Code)
	}
}

// --- apiThreatTempWhitelistIP (POST validation) ----------------------

func TestAPIThreatTempWhitelistIPGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatTempWhitelistIP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET temp-whitelist = %d, want 405", w.Code)
	}
}

// --- apiThreatBulkAction (POST validation) ---------------------------

func TestAPIThreatBulkActionGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiThreatBulkAction(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET bulk-action = %d, want 405", w.Code)
	}
}
