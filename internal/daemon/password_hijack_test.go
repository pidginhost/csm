package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

// --- NewPasswordHijackDetector ----------------------------------------

func TestNewPasswordHijackDetector(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))
	if d == nil {
		t.Fatal("detector should not be nil")
	}
}

// --- HandlePasswordChange ---------------------------------------------

func TestHandlePasswordChangeNonInfra(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandlePasswordChange("alice", "203.0.113.5")

	select {
	case f := <-ch:
		if f.Check != "whm_password_change_noninfra" {
			t.Errorf("check = %q", f.Check)
		}
	default:
		t.Error("expected alert for non-infra password change")
	}
}

func TestHandlePasswordChangeInfraSkipped(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandlePasswordChange("alice", "10.0.0.1")

	select {
	case f := <-ch:
		t.Errorf("infra IP should not emit alert, got %+v", f)
	default:
		// expected
	}
}

func TestHandlePasswordChangeLoopbackSkipped(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandlePasswordChange("alice", "127.0.0.1")

	select {
	case <-ch:
		t.Error("loopback should not emit alert")
	default:
	}
}

// --- HandleLogin (hijack correlation) ---------------------------------

func TestHandleLoginCorrelatesWithChange(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandlePasswordChange("alice", "203.0.113.5")
	<-ch // consume the password-change alert

	d.HandleLogin("alice", "198.51.100.1")

	select {
	case f := <-ch:
		if f.Check != "password_hijack_confirmed" {
			t.Errorf("check = %q, want password_hijack_confirmed", f.Check)
		}
	default:
		t.Error("expected hijack confirmation alert")
	}
}

func TestHandleLoginNoRecentChange(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandleLogin("alice", "203.0.113.5")

	select {
	case f := <-ch:
		t.Errorf("no recent change should not emit, got %+v", f)
	default:
	}
}

func TestHandleLoginInfraSkipped(t *testing.T) {
	cfg := &config.Config{InfraIPs: []string{"10.0.0.1"}}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	d.HandlePasswordChange("alice", "203.0.113.5")
	<-ch

	d.HandleLogin("alice", "10.0.0.1") // infra login

	select {
	case <-ch:
		t.Error("infra login should not trigger hijack")
	default:
	}
}

// --- shutdown safety --------------------------------------------------

func TestHandlePasswordChangeUnblocksOnStop(t *testing.T) {
	// Regression: the session-log watcher goroutine calls these handlers
	// synchronously. An unbuffered/saturated alertCh whose dispatcher has
	// stopped draining at shutdown must not wedge the watcher (and, for
	// HandlePasswordChange, must not wedge it while holding d.mu). The
	// send has to give up when stopCh is closed.
	cfg := &config.Config{}
	ch := make(chan alert.Finding) // no reader: a naive send blocks forever
	stop := make(chan struct{})
	d := NewPasswordHijackDetector(cfg, ch, stop)
	close(stop)

	done := make(chan struct{})
	go func() {
		d.HandlePasswordChange("alice", "203.0.113.5")
		d.HandleLogin("alice", "198.51.100.1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handlers blocked on a full alertCh after stop was signaled")
	}
}

func TestPasswordHijackNilStopChannelStillSends(t *testing.T) {
	ch := make(chan alert.Finding, 2)
	d := NewPasswordHijackDetector(&config.Config{}, ch, nil)

	d.HandlePasswordChange("alice", "203.0.113.5")
	d.HandleLogin("alice", "198.51.100.1")

	gotChange := <-ch
	gotLogin := <-ch
	if gotChange.Check != "whm_password_change_noninfra" {
		t.Fatalf("nil stopCh disabled password-change send, got %+v", gotChange)
	}
	if gotLogin.Check != "password_hijack_confirmed" {
		t.Fatalf("nil stopCh disabled correlated-login send, got %+v", gotLogin)
	}
}

// --- Cleanup ----------------------------------------------------------

func TestCleanupRemovesExpired(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	// Inject an old entry directly
	d.mu.Lock()
	d.recentChanges["old-account"] = &passwordChange{
		account:   "old-account",
		ip:        "203.0.113.5",
		timestamp: time.Now().Add(-5 * time.Minute),
	}
	d.mu.Unlock()

	d.Cleanup()

	d.mu.Lock()
	_, exists := d.recentChanges["old-account"]
	d.mu.Unlock()
	if exists {
		t.Error("expired entry should be cleaned up")
	}
}

// --- parseWHMPurge ----------------------------------------------------

func TestParseWHMPurgeStandard(t *testing.T) {
	line := `[2026-04-12 10:00:00 +0000] info [whostmgr] 198.51.100.50 PURGE alice:token password_change`
	ip, account := parseWHMPurge(line)
	if ip != "198.51.100.50" {
		t.Errorf("ip = %q", ip)
	}
	if account != "alice" {
		t.Errorf("account = %q", account)
	}
}

func TestParseWHMPurgeNoWhostmgr(t *testing.T) {
	ip, account := parseWHMPurge("no whostmgr here")
	if ip != "" || account != "" {
		t.Errorf("got (%q, %q)", ip, account)
	}
}

// --- ParseSessionLineForHijack ----------------------------------------

func TestParseSessionLineForHijackPasswordChange(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	line := `[2026-04-12 10:00:00 +0000] info [whostmgr] 198.51.100.50 PURGE alice:token password_change`
	ParseSessionLineForHijack(line, d)

	select {
	case f := <-ch:
		if f.Check != "whm_password_change_noninfra" {
			t.Errorf("check = %q", f.Check)
		}
	default:
		t.Error("expected alert from session line parsing")
	}
}

func TestParseSessionLineForHijackAPISessionSkipped(t *testing.T) {
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 10)
	d := NewPasswordHijackDetector(cfg, ch, make(chan struct{}))

	// API sessions with method=create_user_session should be skipped
	line := `[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.5 NEW alice:token method=create_user_session`
	ParseSessionLineForHijack(line, d)

	select {
	case <-ch:
		t.Error("API session should not trigger login handler")
	default:
	}
}
