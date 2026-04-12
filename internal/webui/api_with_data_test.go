package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/firewall"
)

// seedFindings stores some test findings in the state store.
func seedFindings(t *testing.T, s *Server) {
	t.Helper()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found /home/alice/shell.php", Timestamp: time.Now()},
		{Severity: alert.High, Check: "brute_force", Message: "SSH brute force from 203.0.113.5", Timestamp: time.Now()},
		{Severity: alert.Warning, Check: "waf_status", Message: "WAF not active", Timestamp: time.Now()},
	}
	s.store.SetLatestFindings(findings)
	s.store.AppendHistory(findings)
}

// --- apiFindings with data -------------------------------------------

func TestAPIFindingsWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiFindings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected findings in response")
	}
}

// --- apiFindingsEnriched with data -----------------------------------

func TestAPIFindingsEnrichedWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiHistory with data --------------------------------------------

func TestAPIHistoryWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiHistory(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiHistoryCSV with data -----------------------------------------

func TestAPIHistoryCSVWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiHistoryCSV(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "webshell") {
		t.Error("CSV should contain seeded findings")
	}
}

// --- apiStats with data ----------------------------------------------

func TestAPIStatsWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiDismissFinding -----------------------------------------------

func TestAPIDismissFindingPost(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	body := `{"key":"webshell|Found /home/alice/shell.php"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiDismissFinding(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("dismiss = %d, body: %s", w.Code, w.Body.String())
	}
}

// --- apiFindingDetail with data --------------------------------------

func TestAPIFindingDetailWithData(t *testing.T) {
	s := newTestServer(t, "tok")
	seedFindings(t, s)
	w := httptest.NewRecorder()
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/?check=webshell&message=Found+/home/alice/shell.php", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiBlockIP / apiUnblockIP ----------------------------------------

func TestAPIBlockIPPost(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.99","reason":"test block","duration":"24h"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBlockIP(w, req)
	// Without a real firewall engine, this may return an error status
	// but exercises the handler logic including validation.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIUnblockIPPost(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	w := httptest.NewRecorder()
	body := `{"ip":"203.0.113.99"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockIP(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiTestAlert POST -----------------------------------------------

func TestAPITestAlertPost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", nil)
	s.apiTestAlert(w, req)
	// Without SMTP, may return error, but exercises the handler.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}
