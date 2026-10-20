//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/firewall"
)

// A confirmation window a restart interrupted can still roll the firewall
// back, so the engine holds admission's batches before the owner can see
// it, until startup recovery settles the window (design C9).
func TestEngineIsHeldForAPendingWindowBeforeTheOwnerSeesIt(t *testing.T) {
	for _, pending := range []bool{false, true} {
		statePath := t.TempDir()
		confirmFile, _, _ := firewallRollbackFiles(statePath)
		if err := os.MkdirAll(filepath.Dir(confirmFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if pending {
			writeTestFile(t, confirmFile, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		}
		d := &Daemon{cfg: &config.Config{StatePath: statePath, Firewall: &firewall.FirewallConfig{Enabled: true}}}
		eng, err := firewall.NewEngine(&firewall.FirewallConfig{Enabled: true}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { setFirewallBatchHold(nil) })
		// Block hold installation and observe only the atomic owner pointer.
		// Publishing first would expose an engine that can still apply.
		firewallDeadmanMu.Lock()
		started, done := make(chan struct{}), make(chan struct{})
		go func() {
			close(started)
			d.setFirewallEngine(eng)
			close(done)
		}()
		<-started
		select {
		case <-done:
		case <-time.After(50 * time.Millisecond):
		}
		published := d.blockEngine.Load()
		firewallDeadmanMu.Unlock()
		<-done
		if published != nil {
			t.Fatal("owner saw the engine before its confirmation hold was installed")
		}
		if err := eng.ProbeBlockState(); errors.Is(err, firewall.ErrConfirmPending) != pending {
			t.Fatalf("pending %v: probe = %v", pending, err)
		}
	}
}
