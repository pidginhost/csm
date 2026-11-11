package daemon

import (
	"strings"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestSessionConsumersRejectFalseEvents(t *testing.T) {
	const prefix = "[2026-04-12 10:00:00 +0000] "
	for name, line := range map[string]string{
		"error login":      prefix + "warn [cpaneld] 203.0.113.5 NEW alice:tok method=handle_form_login",
		"error purge":      prefix + "warn [whostmgr] 203.0.113.5 PURGE alice:tok password_change",
		"login in account": prefix + "info [whostmgrd] 203.0.113.5 NEW x[cpaneld]:tok address=198.51.100.5 NEW alice:tok",
		"purge in account": prefix + "info [whostmgrd] 203.0.113.5 NEW PURGE:tok password_change [whostmgr] 198.51.100.5",
		"purge in detail":  prefix + "info [webmaild] 203.0.113.5 PURGE alice:tok logout [whostmgr] 198.51.100.5 PURGE bob:tok password_change",
	} {
		t.Run(name, func(t *testing.T) {
			resetPurgeTrackerState()
			t.Cleanup(resetPurgeTrackerState)
			cfg := &config.Config{}
			if got := parseSessionLogLine(line, cfg); len(got) != 0 {
				t.Errorf("false event emitted findings: %+v", got)
			}
			if len(purgeTracker.sessions) != 0 || len(purgeTracker.purges) != 0 {
				t.Error("false event populated purge tracking")
			}
			if _, _, _, ok := parseSessionNew(line); ok {
				t.Error("false event supplied a known customer")
			}
			ch := make(chan alert.Finding, 4)
			d := NewPasswordHijackDetector(cfg, ch, nil)
			d.HandlePasswordChange("alice", "198.51.100.5")
			<-ch
			ParseSessionLineForHijack(line, d)
			if len(ch) != 0 || len(d.recentChanges) != 1 {
				t.Error("false event changed hijack correlation")
			}
		})
	}
}

func TestSessionConsumersDoNotTrustDetailMethods(t *testing.T) {
	resetPurgeTrackerState()
	t.Cleanup(resetPurgeTrackerState)
	cfg := &config.Config{}
	ch := make(chan alert.Finding, 4)
	d := NewPasswordHijackDetector(cfg, ch, nil)
	d.HandlePasswordChange("alice", "198.51.100.5")
	<-ch
	line := "[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.5 NEW alice:tok address=203.0.113.5,method=create_user_session,app=cpaneld,method=handle_form_login"
	got := parseSessionLogLine(line, cfg)
	if len(got) != 1 || got[0].Check != "cpanel_login_realtime" || got[0].SourceIP != "203.0.113.5" {
		t.Fatalf("direct login findings = %+v", got)
	}
	ParseSessionLineForHijack(line, d)
	select {
	case f := <-ch:
		if f.Check != "password_hijack_confirmed" || f.SourceIP != "203.0.113.5" || f.TenantID != "alice" {
			t.Fatalf("hijack finding = %+v", f)
		}
	default:
		t.Fatal("forged method concealed the login after a password change")
	}
}

func TestSessionHijackExcludesBothAPIMethods(t *testing.T) {
	for _, method := range []string{"create_session", "create_user_session"} {
		t.Run(method, func(t *testing.T) {
			ch := make(chan alert.Finding, 4)
			d := NewPasswordHijackDetector(&config.Config{}, ch, nil)
			d.HandlePasswordChange("alice", "198.51.100.5")
			<-ch
			line := "[2026-04-12 10:00:00 +0000] info [cpaneld] 203.0.113.5 NEW alice:tok method=" + method
			ParseSessionLineForHijack(line, d)
			if len(ch) != 0 || len(d.recentChanges) != 1 {
				t.Fatal("API session consumed the pending password change")
			}
			ParseSessionLineForHijack(strings.Replace(line, method, "handle_form_login", 1), d)
			select {
			case f := <-ch:
				if f.Check != "password_hijack_confirmed" || f.SourceIP != "203.0.113.5" || f.TenantID != "alice" {
					t.Fatalf("direct login finding = %+v", f)
				}
			default:
				t.Fatal("later direct login did not correlate")
			}
		})
	}
}

func TestSessionHijackExcludesLoopbackEvents(t *testing.T) {
	for _, origin := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		t.Run(origin, func(t *testing.T) {
			ch := make(chan alert.Finding, 4)
			d := NewPasswordHijackDetector(&config.Config{}, ch, nil)
			const prefix = "[2026-04-12 10:00:00 +0000] info "
			ParseSessionLineForHijack(prefix+"[whostmgr] "+origin+" PURGE alice:tok password_change", d)
			if len(ch) != 0 || len(d.recentChanges) != 0 {
				t.Fatal("local password change was treated as an attack")
			}
			d.HandlePasswordChange("alice", "198.51.100.5")
			<-ch
			ParseSessionLineForHijack(prefix+"[cpaneld] "+origin+" NEW alice:tok method=handle_form_login", d)
			if len(ch) != 0 || len(d.recentChanges) != 1 {
				t.Fatal("local login consumed a pending password change")
			}
			ParseSessionLineForHijack(prefix+"[cpaneld] 203.0.113.5 NEW alice:tok method=handle_form_login", d)
			select {
			case f := <-ch:
				if f.Check != "password_hijack_confirmed" || f.SourceIP != "203.0.113.5" {
					t.Fatalf("remote login finding = %+v", f)
				}
			default:
				t.Fatal("remote login did not correlate after ignoring a local event")
			}
		})
	}
}
