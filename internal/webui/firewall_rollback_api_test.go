package webui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/firewall/rollback"
	"github.com/pidginhost/csm/internal/store"
)

// installRollbackManager wires a manager backed by a fresh per-test bbolt
// so each test has independent state. EnsureOpen uses sync.Once which
// would otherwise leak state across tests in the same package.
func installRollbackManager(t *testing.T, statePath, configPath string) *rollback.Manager {
	t.Helper()
	db, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	m := rollback.NewManager(db, configPath, func(_ context.Context) error { return nil }, time.Now)
	rollback.SetGlobal(m)
	t.Cleanup(func() {
		_ = m.Confirm()
		rollback.SetGlobal(nil)
		_ = db.Close()
	})
	return m
}

func TestAPIFirewallTentativeApplyAndConfirm(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	mgr := installRollbackManager(t, s.cfg.StatePath, cfgPath)
	s.restartDaemon = func() ([]byte, error) { return nil, nil }

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postBody := `{"changes":{"conn_limit":500},"timeout_min":2}`
	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall/tentative-apply", "tok", postBody)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiFirewallTentativeApply(postW, postReq)
	if postW.Code != 200 {
		t.Fatalf("tentative-apply code = %d, body = %s", postW.Code, postW.Body.String())
	}

	st := mgr.Status()
	if !st.Pending {
		t.Fatal("manager should report pending after tentative-apply")
	}
	if st.SecondsRemaining < 60 || st.SecondsRemaining > 130 {
		t.Errorf("SecondsRemaining = %d, want around 120", st.SecondsRemaining)
	}

	// Reading status via the API should match.
	statusReq := settingsAuthedReq("GET", "/api/v1/settings/firewall/rollback", "tok", "")
	statusW := httptest.NewRecorder()
	s.apiFirewallRollbackStatus(statusW, statusReq)
	if statusW.Code != 200 {
		t.Fatalf("rollback status code = %d", statusW.Code)
	}
	var got rollback.Status
	if err := json.Unmarshal(statusW.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Pending {
		t.Error("API rollback status should be pending")
	}

	// Confirm.
	confirmReq := settingsAuthedReq("POST", "/api/v1/settings/firewall/confirm", "tok", "")
	confirmReq.Header.Set("X-CSRF-Token", s.csrfToken())
	confirmW := httptest.NewRecorder()
	s.apiFirewallRollbackConfirm(confirmW, confirmReq)
	if confirmW.Code != 200 {
		t.Fatalf("confirm code = %d, body = %s", confirmW.Code, confirmW.Body.String())
	}
	if mgr.Status().Pending {
		t.Error("manager should be empty after confirm")
	}
}

func TestAPIFirewallTentativeApplyRefusesWhenAlreadyPending(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	mgr := installRollbackManager(t, s.cfg.StatePath, cfgPath)
	s.restartDaemon = func() ([]byte, error) { return nil, nil }

	if _, err := mgr.Apply([]byte("a"), []byte("b"), time.Minute, "seed"); err != nil {
		t.Fatal(err)
	}

	getReq := settingsAuthedReq("GET", "/api/v1/settings/firewall", "tok", "")
	getW := httptest.NewRecorder()
	s.apiSettingsGet(getW, getReq)
	etag := getW.Header().Get("ETag")

	postReq := settingsAuthedReq("POST", "/api/v1/settings/firewall/tentative-apply", "tok",
		`{"changes":{"conn_limit":500}}`)
	postReq.Header.Set("If-Match", etag)
	postReq.Header.Set("X-CSRF-Token", s.csrfToken())
	postW := httptest.NewRecorder()
	s.apiFirewallTentativeApply(postW, postReq)
	if postW.Code != 409 {
		t.Errorf("expected 409 Conflict, got %d body=%s", postW.Code, postW.Body.String())
	}
}

func TestAPIFirewallRollbackConfirmWithNoneReturns409(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	installRollbackManager(t, s.cfg.StatePath, cfgPath)

	req := settingsAuthedReq("POST", "/api/v1/settings/firewall/confirm", "tok", "")
	req.Header.Set("X-CSRF-Token", s.csrfToken())
	w := httptest.NewRecorder()
	s.apiFirewallRollbackConfirm(w, req)
	if w.Code != 409 {
		t.Errorf("expected 409, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no pending") {
		t.Errorf("expected 'no pending' in body, got %s", w.Body.String())
	}
}
