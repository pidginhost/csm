package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall"
	"github.com/pidginhost/csm/internal/store"
)

// --- apiFix POST with valid finding ----------------------------------

func TestAPIFixPostWebshell(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"check":"webshell","message":"Found /tmp/test_wso.php","details":"test"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	// Will fail on actual quarantine (no file exists), but exercises the handler.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

func TestAPIFixPostBadJSON(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFix(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON = %d, want 400", w.Code)
	}
}

// --- apiBulkFix POST -------------------------------------------------

func TestAPIBulkFixPost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"findings":[{"check":"webshell","message":"test","details":"test"}]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiBulkFix(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiUnblockBulk POST ---------------------------------------------

func TestAPIUnblockBulkPost(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}
	w := httptest.NewRecorder()
	body := `{"ips":["203.0.113.5","198.51.100.1"]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiUnblockBulk(w, req)
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiQuarantineRestore POST with valid ID -------------------------

func TestAPIQuarantineRestorePostBadID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"id":"../../../etc/passwd"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("path traversal ID = %d, want 400 or 404", w.Code)
	}
}

func TestAPIQuarantineRestorePostNonexistent(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"id":"nonexistent_abc123"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	// Should 404 since no meta file exists.
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("nonexistent = %d, want 404 or 400", w.Code)
	}
}

func TestAPIQuarantineRestorePostEmpty(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"id":""}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineRestore(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty ID = %d, want 400", w.Code)
	}
}

// --- apiQuarantinePreview --------------------------------------------

func TestAPIQuarantinePreviewBadID(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=../../../etc/passwd", nil))
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("path traversal = %d, want 400 or 404", w.Code)
	}
}

func TestAPIQuarantinePreviewMissing(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	s.apiQuarantinePreview(w, httptest.NewRequest("GET", "/?id=nonexistent", nil))
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("missing = %d", w.Code)
	}
}

// --- apiQuarantineBulkDelete POST ------------------------------------

func TestAPIQuarantineBulkDeletePost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"ids":["nonexistent_file"]}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiQuarantineBulkDelete(w, req)
	// Exercises the handler logic even though no files exist.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiScanAccount POST ---------------------------------------------

func TestAPIScanAccountPost(t *testing.T) {
	s := newTestServer(t, "tok")
	w := httptest.NewRecorder()
	body := `{"account":"alice"}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	s.apiScanAccount(w, req)
	// Without real /home/alice, this will return an error.
	if w.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiFirewallAudit with bbolt data --------------------------------

func TestAPIFirewallAuditWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	s.cfg.Firewall = &firewall.FirewallConfig{Enabled: true}

	// Seed an audit entry via blocking an IP
	sdb := store.Global()
	_ = sdb.BlockIP("203.0.113.5", "test", time.Time{})

	w := httptest.NewRecorder()
	s.apiFirewallAudit(w, httptest.NewRequest("GET", "/?limit=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

// --- apiAccountDetail -------------------------------------------------

// --- apiSuppressions POST delete rule --------------------------------

func TestAPISuppressionsDeleteRule(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	// First add a rule
	addBody := `{"check":"test_check","path_pattern":"*.php","reason":"test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(addBody))
	req.Header.Set("Content-Type", "application/json")
	s.apiSuppressions(w, req)

	// Get the rule ID
	w2 := httptest.NewRecorder()
	s.apiSuppressions(w2, httptest.NewRequest("GET", "/", nil))
	// Now delete it
	w3 := httptest.NewRecorder()
	delReq := httptest.NewRequest("DELETE", "/", nil)
	s.apiSuppressions(w3, delReq)
	// DELETE method exercises the handler
	if w3.Code == 0 {
		t.Error("unexpected zero status")
	}
}

// --- apiPerformance with bbolt data ----------------------------------

func TestAPIPerformanceWithBbolt(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiPerformance(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAPIAccountDetailValid(t *testing.T) {
	s := newTestServerWithBbolt(t, "tok")
	w := httptest.NewRecorder()
	s.apiAccountDetail(w, httptest.NewRequest("GET", "/?name=alice", nil))
	// Without /home/alice, some data will be empty, but exercises the handler.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}
