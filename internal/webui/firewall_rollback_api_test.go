package webui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// scheduleDaemonRestart must respect server shutdown so a tentative-apply
// issued just before Shutdown does not race a freshly-stopped HTTP server
// or, in the worst case, restart the daemon after the operator killed it.
func TestScheduleDaemonRestartAbortsOnShutdown(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	var calls int32
	s.restartDaemon = func() ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		return nil, nil
	}
	if err := s.Shutdown(context.Background()); err != nil {
		// httpSrv.Shutdown returns ErrServerClosed-ish errors when never
		// served. Either is acceptable here; the call must close pruneDone.
		t.Logf("Shutdown returned: %v", err)
	}
	s.scheduleDaemonRestart(50 * time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("restartDaemon called %d times after shutdown, want 0", got)
	}
}

// scheduleDaemonRestart must still fire the restart in the happy path.
// The delay-then-restart pattern lets the HTTP response flush first; this
// test pins the contract that the goroutine does eventually fire.
func TestScheduleDaemonRestartFiresAfterDelay(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	fired := make(chan struct{}, 1)
	s.restartDaemon = func() ([]byte, error) {
		fired <- struct{}{}
		return nil, nil
	}
	s.scheduleDaemonRestart(20 * time.Millisecond)
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("restartDaemon not called within 1s")
	}
}

// scheduleRollbackRevert must not let the daemon shutdown triggered by
// the revert's own restart cancel that restart context. Otherwise the
// config can be restored while the rollback record remains pending.
func TestScheduleRollbackRevertKeepsOwnRestartContextOnShutdown(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	restartErr := make(chan error, 1)
	db, err := store.Open(s.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mgr := rollback.NewManager(db, cfgPath, func(ctx context.Context) error {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Logf("Shutdown returned: %v", err)
		}
		select {
		case <-ctx.Done():
			restartErr <- ctx.Err()
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			restartErr <- nil
			return nil
		}
	}, time.Now)
	rollback.SetGlobal(mgr)
	t.Cleanup(func() {
		_ = mgr.Confirm()
		rollback.SetGlobal(nil)
	})
	if _, err := mgr.Apply([]byte("a"), []byte("b"), time.Minute, "seed"); err != nil {
		t.Fatal(err)
	}

	s.scheduleRollbackRevert(mgr, 30*time.Second)
	select {
	case err := <-restartErr:
		if err != nil {
			t.Fatalf("restart context was canceled during revert shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revert restart did not run")
	}
	deadline := time.Now().Add(2 * time.Second)
	for mgr.Status().Pending {
		if time.Now().After(deadline) {
			t.Fatal("rollback record stayed pending after successful revert")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestScheduleRollbackRevertDoesNotStartAfterShutdown(t *testing.T) {
	s, cfgPath := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	var calls int32
	db, err := store.Open(s.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mgr := rollback.NewManager(db, cfgPath, func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}, time.Now)
	t.Cleanup(func() { _ = mgr.Confirm() })
	if _, err := mgr.Apply([]byte("a"), []byte("b"), time.Minute, "seed"); err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Logf("Shutdown returned: %v", err)
	}

	s.scheduleRollbackRevert(mgr, 30*time.Second)
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("revert restart called %d times after shutdown, want 0", got)
	}
	if !mgr.Status().Pending {
		t.Error("rollback record should stay pending when revert was not started")
	}
}

// Server.Shutdown must be idempotent; the prior code panicked on a second
// close of pruneDone when tests (or callers that reuse a Server) invoke it
// twice. Guarding the close with sync.Once is the minimum fix.
func TestServerShutdownIdempotent(t *testing.T) {
	s, _ := newSettingsTestServer(t, "tok", firewallSettingsTestYAML())
	if err := s.Shutdown(context.Background()); err != nil {
		t.Logf("first Shutdown returned: %v", err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Shutdown panicked: %v", r)
		}
	}()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Logf("second Shutdown returned: %v", err)
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
