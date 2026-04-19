package daemon

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

// TestReloadConfigRaceAgainstReaders hammers config.Active reads from
// many goroutines while a single goroutine issues SIGHUP-shaped
// reloads. The test is specifically aimed at `go test -race`: any
// concurrent-use-without-sync bug in reloadConfig, currentCfg, or
// the hot paths that walk d.currentCfg() should surface here.
//
// The test does NOT assert any functional property beyond "survives";
// every iteration already has a dedicated unit test (success /
// restart_required / error / noop). What this guards is the mixed
// read/write access pattern that production sees but no other test
// in the suite exercises.
func TestReloadConfigRaceAgainstReaders(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Thresholds.MailQueueWarn = 1
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	var (
		stop        atomic.Bool
		readers     sync.WaitGroup
		readerCount = 16
		reloadDone  = make(chan struct{})
	)

	for i := 0; i < readerCount; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				// Real hot-path shape: ask for the active cfg, then
				// read a safe-tagged sub-key on it. This matches
				// exactly what the check tick handlers and
				// dispatchBatch do.
				cfg := d.currentCfg()
				if cfg == nil {
					t.Error("currentCfg returned nil mid-race")
					return
				}
				_ = cfg.Thresholds.MailQueueWarn
			}
		}()
	}

	go func() {
		defer close(reloadDone)
		deadline := time.Now().Add(500 * time.Millisecond)
		i := 0
		for time.Now().Before(deadline) {
			i++
			edited := &config.Config{}
			edited.Thresholds.MailQueueWarn = i
			// Preserve integrity so Save+reload works on the same
			// file each iteration.
			edited.Integrity = config.Active().Integrity
			seedConfigAtPath(t, cfgPath, edited)
			d.reloadConfig()
			// Drain any finding the reload emitted so the alert
			// channel does not backfill and block the emitReloadFinding
			// non-blocking send.
			for drained := false; !drained; {
				select {
				case <-d.alertCh:
				default:
					drained = true
				}
			}
		}
	}()

	<-reloadDone
	stop.Store(true)
	readers.Wait()

	// Post-stress sanity: the last reload should have left Active
	// pointing somewhere with our seeded hostname still intact.
	got := config.Active()
	if got == nil {
		t.Fatal("Active is nil after stress loop")
	}
	if got.Hostname == "" {
		t.Error("Active has empty Hostname after stress loop")
	}
}

// TestReloadConfigRaceDuringDispatchBatch is a lighter-weight
// companion to the above: instead of a tight read loop, it runs
// d.currentCfg-based snapshot reads with the same cadence
// dispatchBatch would use (one snapshot per batch, hold it through
// a short critical section). The aim is to catch "writer freed the
// pointer while reader still holds it" -- impossible with
// atomic.Pointer, but worth a dedicated guard so that if the
// design is ever changed the test catches the regression.
func TestReloadConfigRaceDuringDispatchBatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "csm.yaml")

	orig := &config.Config{}
	orig.Thresholds.MailQueueWarn = 1
	orig.Alerts.MaxPerHour = 10
	seedConfigAtPath(t, cfgPath, orig)

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d := newDaemonForReloadTest(t, loaded)

	var wg sync.WaitGroup

	// Writer: issue 50 reloads.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			edited := &config.Config{}
			edited.Thresholds.MailQueueWarn = i + 100
			edited.Alerts.MaxPerHour = i + 1
			edited.Integrity = config.Active().Integrity
			seedConfigAtPath(t, cfgPath, edited)
			d.reloadConfig()
			for drained := false; !drained; {
				select {
				case <-d.alertCh:
				default:
					drained = true
				}
			}
		}
	}()

	// Readers: 8 goroutines simulating dispatchBatch pattern
	// (snapshot once, then reference the pointer for the duration
	// of a "batch").
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				cfg := d.currentCfg()
				if cfg == nil {
					t.Error("currentCfg returned nil")
					return
				}
				// Read several sub-keys to ensure the whole struct
				// is accessed consistently via the captured pointer.
				_ = cfg.Thresholds.MailQueueWarn
				_ = cfg.Alerts.MaxPerHour
				_ = cfg.Reputation.Whitelist
				// Short pause so the iteration doesn't just spin.
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()

	if got := config.Active(); got == nil {
		t.Fatal("Active is nil after race loop")
	}
}
