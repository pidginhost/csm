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

func TestThreatClearReportsNetblockHistoryWriteFailure(t *testing.T) {
	s := newTestServer(t, "tok")
	s.blocker = newFullBlocker()
	path := filepath.Join(s.cfg.StatePath, "netblock_history.json")
	if err := os.WriteFile(path, []byte(`{"ips":{"203.0.113.5":"2026-09-18T10:00:00Z"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Atomic writes refuse to remove a nonempty legacy temporary directory.
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".tmp", "obstruction"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.apiThreatClearIP(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ip":"203.0.113.5"}`)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("clear status = %d, want partial failure: %s", w.Code, w.Body.String())
	}
}
