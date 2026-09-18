package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/firewall"
)

type pausedNetblockSnapshot struct {
	snapshot, release, unblocked chan struct{}
}

func (b *pausedNetblockSnapshot) BlockIP(string, string, time.Duration) error { return nil }
func (b *pausedNetblockSnapshot) IsBlocked(string) bool                       { return false }
func (b *pausedNetblockSnapshot) UnblockIP(string) error                      { close(b.unblocked); return nil }
func (b *pausedNetblockSnapshot) LiveBlockedSet() (firewall.LiveBlockedSnapshot, error) {
	close(b.snapshot)
	<-b.release
	return firewall.LiveBlockedSnapshot{HasV4: true, HasV6: true}, nil
}

func TestThreatClearSerializesFirewallMutationWithNetblockCycle(t *testing.T) {
	s := newTestServer(t, "tok")
	s.cfg.AutoResponse.Enabled = true
	s.cfg.AutoResponse.BlockIPs = true
	s.cfg.AutoResponse.NetBlock = true
	b := &pausedNetblockSnapshot{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	s.blocker = b
	checks.SetIPBlocker(b)
	defer checks.SetIPBlocker(nil)
	cycleDone := make(chan struct{})
	go func() { defer close(cycleDone); checks.AutoBlockIPs(s.cfg, nil) }()
	<-b.snapshot
	cleared := make(chan struct{})
	w := httptest.NewRecorder()
	go func() {
		defer close(cleared)
		s.apiThreatClearIP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ip":"203.0.113.5"}`)))
	}()
	// Wait for either the queue admission or the unsafe firewall mutation.
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	waiting := false
	for !waiting {
		select {
		case <-b.unblocked:
			t.Error("clear mutated firewall while the auto-block cycle held a snapshot")
			waiting = true
		case <-ticker.C:
			waiting = checks.AutoBlockQueueStatuses(time.Now())["waiting"].Depth > 0
		case <-deadline:
			t.Error("clear did not reach the auto-block queue")
			waiting = true
		}
	}
	close(b.release)
	<-cycleDone
	<-cleared
	if w.Code != http.StatusOK {
		t.Fatalf("clear status = %d: %s", w.Code, w.Body.String())
	}
	select {
	case <-b.unblocked:
	default:
		t.Fatal("clear never unblocked the address")
	}
}

// History failures must not interrupt an already-applied operator action.
func TestThreatActionsFinishOnNetblockHistoryFailure(t *testing.T) {
	for _, action := range []struct {
		name    string
		handler func(*Server, http.ResponseWriter, *http.Request)
		allowed bool
	}{
		{"clear_ip", (*Server).apiThreatClearIP, false},
		{"whitelist_ip", (*Server).apiThreatWhitelistIP, true},
		{"temp_whitelist_ip", (*Server).apiThreatTempWhitelistIP, true},
	} {
		for _, failure := range []string{"decode", "write"} {
			t.Run(action.name+"/"+failure, func(t *testing.T) {
				s := newTestServer(t, "tok")
				blocker := newFullBlocker()
				blocker.blocked["203.0.113.5"] = "existing block"
				s.blocker = blocker
				path := filepath.Join(s.cfg.StatePath, "netblock_history.json")
				contents := `{"ips":{"203.0.113.5":"2026-09-18T10:00:00Z"}}`
				if failure == "decode" {
					contents = `{"ips":`
				} else {
					// Atomic writes refuse to remove a nonempty legacy temporary directory.
					if err := os.Mkdir(path+".tmp", 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(path+".tmp", "obstruction"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}

				binDir := t.TempDir()
				marker := filepath.Join(t.TempDir(), "whmapi1.args")
				script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CSM_TEST_MARKER\"\n"
				if err := os.WriteFile(filepath.Join(binDir, "whmapi1"), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", binDir)
				t.Setenv("CSM_TEST_MARKER", marker)

				w := httptest.NewRecorder()
				action.handler(s, w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ip":"203.0.113.5"}`)))
				if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "IP action applied, but subnet history cleanup failed:") {
					t.Fatalf("status = %d, want partial failure: %s", w.Code, w.Body.String())
				}
				if _, blocked := blocker.blocked["203.0.113.5"]; blocked {
					t.Error("IP remains blocked")
				}
				if _, allowed := blocker.allowed["203.0.113.5"]; allowed != action.allowed {
					t.Errorf("allowed = %v, want %v", allowed, action.allowed)
				}
				got, err := os.ReadFile(marker)
				if err != nil || string(got) != "flush_cphulk_login_history_for_ips\nip=203.0.113.5\n" {
					t.Errorf("cphulk flush args = %q, err = %v", got, err)
				}
				audit := readUIAuditLog(s.cfg.StatePath, 10)
				if len(audit) != 1 || audit[0].Action != action.name || audit[0].Target != "203.0.113.5" {
					t.Errorf("audit = %+v, want one %s entry for the applied IP action", audit, action.name)
				}
				got, err = os.ReadFile(path)
				if err != nil || string(got) != contents {
					t.Errorf("history changed despite cleanup failure: %s (%v)", got, err)
				}
			})
		}
	}
}
