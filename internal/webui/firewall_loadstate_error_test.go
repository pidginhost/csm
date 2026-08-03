package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
)

// writeCorruptFirewallState drops an unparseable firewall state.json so
// firewall.LoadState returns (nil, err). Handlers that ignored that error
// then nil-dereferenced the state and panicked (WUI-01).
func writeCorruptFirewallState(t *testing.T, statePath string) {
	t.Helper()
	dir := filepath.Join(statePath, "firewall")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

func TestAPIFirewallStatusCorruptStateNoPanic(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	writeCorruptFirewallState(t, s.cfg.StatePath)
	w := httptest.NewRecorder()
	s.apiFirewallStatus(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAPIFirewallAllowedCorruptStateNoPanic(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	writeCorruptFirewallState(t, s.cfg.StatePath)
	w := httptest.NewRecorder()
	s.apiFirewallAllowed(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAPIFirewallSubnetsCorruptStateNoPanic(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	writeCorruptFirewallState(t, s.cfg.StatePath)
	w := httptest.NewRecorder()
	s.apiFirewallSubnets(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAPIFirewallCheckCorruptStateReportsError(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	writeCorruptFirewallState(t, s.cfg.StatePath)
	w := httptest.NewRecorder()
	s.apiFirewallCheck(w, httptest.NewRequest("GET", "/?ip=203.0.113.5", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if body["success"] != false {
		t.Fatalf("success = %v, want false; body=%v", body["success"], body)
	}
}

func TestAPIFirewallUnbanCorruptStateStillUnbans(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	blocker := newFullBlocker()
	blocker.blocked["203.0.113.7"] = "web_attack"
	s.blocker = blocker
	writeCorruptFirewallState(t, s.cfg.StatePath)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ip":"203.0.113.7"}`))
	req.Header.Set("Content-Type", "application/json")
	s.apiFirewallUnban(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if body["success"] != true {
		t.Fatalf("success = %v, want true; body=%v", body["success"], body)
	}
	if _, still := blocker.blocked["203.0.113.7"]; still {
		t.Fatal("IP still blocked after unban with corrupt state")
	}
}

func TestAPIFirewallFlushCorruptEngineStateUsesAutoBlockTracker(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	restore := checks.SetGlobalThreatDBForTest(t.TempDir())
	t.Cleanup(restore)
	blocker := newFullBlocker()
	blocker.blocked["203.0.113.8"] = "web_attack"
	s.blocker = blocker
	writeCorruptFirewallState(t, s.cfg.StatePath)

	if err := os.WriteFile(filepath.Join(s.cfg.StatePath, "blocked_ips.json"),
		[]byte(`{"ips":[{"ip":"203.0.113.8","expires_at":"2099-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks.GetThreatDB().AddTemporary("203.0.113.8", "web_attack", time.Hour)

	w := httptest.NewRecorder()
	s.apiFirewallFlush(w, httptest.NewRequest(http.MethodPost, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if _, found := checks.GetThreatDB().Lookup("203.0.113.8"); found {
		t.Fatal("tracker-owned threat row survived flush with corrupt engine state")
	}
}

func TestAPIFirewallFlushReportsAutoBlockCleanupFailure(t *testing.T) {
	s := newTestServerWithFirewall(t, "tok")
	blocker := newFullBlocker()
	s.blocker = blocker
	if err := os.Mkdir(filepath.Join(s.cfg.StatePath, "blocked_ips.json"), 0o700); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.apiFirewallFlush(w, httptest.NewRequest(http.MethodPost, "/", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	if !blocker.flushed {
		t.Fatal("firewall flush did not run before cleanup failure")
	}
	if !strings.Contains(w.Body.String(), "auto-block cleanup failed") {
		t.Fatalf("response does not report partial failure: %s", w.Body.String())
	}
}
