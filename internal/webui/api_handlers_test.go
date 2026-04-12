package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- apiStatus --------------------------------------------------------

func TestAPIStatusFields(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, key := range []string{"hostname", "uptime", "started_at", "rules_loaded", "scan_running", "last_scan_time"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing field %q", key)
		}
	}
}

// --- apiHealth --------------------------------------------------------

func TestAPIHealthFields(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHealth(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, key := range []string{"daemon_mode", "uptime", "rules_loaded"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing field %q", key)
		}
	}
}

// --- apiFindingsEnriched (fresh state) --------------------------------

func TestAPIFindingsEnrichedReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiFindingsEnriched(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiStats (fresh state) -------------------------------------------

func TestAPIStatsReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiStats(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
}

// --- apiStatsTrend / apiStatsTimeline --------------------------------

func TestAPIStatsTrendReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiStatsTrend(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIStatsTimelineReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiStatsTimeline(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiHistory (fresh state) -----------------------------------------

func TestAPIHistoryReturnsJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	req := httptest.NewRequest("GET", "/?limit=10", nil)
	w := httptest.NewRecorder()
	s.apiHistory(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiHistoryCSV ----------------------------------------------------

func TestAPIHistoryCSVHeader(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiHistoryCSV(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/csv") {
		t.Error("wrong Content-Type")
	}
	if !strings.Contains(w.Body.String(), "Timestamp,Severity") {
		t.Error("missing CSV header row")
	}
}

// --- apiBlockedIPs (fresh state) --------------------------------------

func TestAPIBlockedIPsFreshState(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiBlockedIPs(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiQuarantine (fresh state) --------------------------------------

func TestAPIQuarantineFreshState(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantine(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiAccounts (no /home on dev) ------------------------------------

func TestAPIAccountsReturns200(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiAccounts(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiExport --------------------------------------------------------

func TestAPIExportBundle(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiExport(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, key := range []string{"exported_at", "hostname", "suppressions", "whitelist"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing field %q", key)
		}
	}
}

// --- apiImport --------------------------------------------------------

func TestAPIImportEmptyBundle(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"suppressions":[],"whitelist":[]}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiImport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestAPIImportGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiImport(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET import = %d, want 405", w.Code)
	}
}

// --- apiFindingDetail -------------------------------------------------

func TestAPIFindingDetailMissingParams(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiFindingDetail(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing params = %d, want 400", w.Code)
	}
}

// --- apiFix / apiBulkFix / apiTestAlert (method guards) ---------------

func TestAPIFixGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiFix(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET fix = %d, want 405", w.Code)
	}
}

func TestAPIBulkFixGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiBulkFix(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET bulk fix = %d, want 405", w.Code)
	}
}

func TestAPITestAlertGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiTestAlert(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET test-alert = %d, want 405", w.Code)
	}
}

// --- apiQuarantineRestore / apiQuarantineBulkDelete (method guards) ---

func TestAPIQuarantineRestoreGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantineRestore(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET restore = %d, want 405", w.Code)
	}
}

func TestAPIQuarantineBulkDeleteGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantineBulkDelete(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET bulk-delete = %d, want 405", w.Code)
	}
}

// --- apiScanAccount (method guard) ------------------------------------

func TestAPIScanAccountGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiScanAccount(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET scan-account = %d, want 405", w.Code)
	}
}

// --- apiUnblockBulk (method guard) ------------------------------------

func TestAPIUnblockBulkGetRejected(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiUnblockBulk(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET unblock-bulk = %d, want 405", w.Code)
	}
}

// csvEscape tests are in coverage_test.go.
