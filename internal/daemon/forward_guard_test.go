package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/mailfwd/adapter"
	"github.com/pidginhost/csm/internal/mailfwd/policy"
	"github.com/pidginhost/csm/internal/platform"
	"github.com/pidginhost/csm/internal/store"
)

type countingForwardGuard struct {
	mutations int
}

func (g *countingForwardGuard) Apply(policy.Config, []string) error { g.mutations++; return nil }
func (g *countingForwardGuard) Remove() error                       { g.mutations++; return nil }
func (g *countingForwardGuard) RefreshBadIPs([]string) error        { g.mutations++; return nil }
func (g *countingForwardGuard) Status() (adapter.Status, error)     { return adapter.Status{}, nil }

func TestObserveModeLeavesExistingForwardGuardUntouched(t *testing.T) {
	platform.ResetForTest()
	t.Cleanup(platform.ResetForTest)
	panel := platform.PanelCPanel
	platform.SetOverrides(platform.Overrides{Panel: &panel})
	prev := config.Active()
	t.Cleanup(func() { config.SetActive(prev) })
	for _, mode := range []string{config.ModeObserve, config.ModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{Mode: mode}
			config.SetActive(cfg)
			r := (&Daemon{cfg: cfg}).forwardGuardReconciler()
			g := &countingForwardGuard{}
			r.Guard = g
			if err := r.Reconcile(cfg.EmailProtection.ForwardGuard); err != nil {
				t.Fatal(err)
			}
			want := 0
			if mode == config.ModeEnforce {
				want = 1
			}
			if g.mutations != want {
				t.Fatalf("mutations = %d, want %d", g.mutations, want)
			}
		})
	}
}

func TestForwardGuardBadIPsNilStore(t *testing.T) {
	prev := store.Global()
	store.SetGlobal(nil)
	t.Cleanup(func() { store.SetGlobal(prev) })

	d := &Daemon{}
	if got := d.forwardGuardBadIPs(); len(got) != 0 {
		t.Fatalf("bad IPs with nil store = %v, want empty", got)
	}
}

func TestForwardGuardBadIPsFiltersReputationThreshold(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	prev := store.Global()
	store.SetGlobal(db)
	t.Cleanup(func() { store.SetGlobal(prev) })

	if err := db.SetReputation("198.51.100.7", store.ReputationEntry{Score: 49}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetReputation("203.0.113.9", store.ReputationEntry{Score: 50}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetReputation("192.0.2.44", store.ReputationEntry{Score: 80}); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	got := d.forwardGuardBadIPs()
	sort.Strings(got)
	want := []string{"192.0.2.44", "203.0.113.9"}
	if len(got) != len(want) {
		t.Fatalf("bad IPs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bad IPs = %v, want %v", got, want)
		}
	}
}

func TestForwardGuardRefresherStops(t *testing.T) {
	d := &Daemon{stopCh: make(chan struct{})}
	d.wg.Add(1)
	done := make(chan struct{})
	go func() {
		d.forwardGuardRefresher()
		close(done)
	}()

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardGuardRefresher did not stop after stopCh closed")
	}

	waited := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("forwardGuardRefresher returned without releasing wait group")
	}
}

func seedForwardQuarantine(t *testing.T, retentionDays int) (old, fresh string) {
	t.Helper()
	dir := t.TempDir()
	prev := forwardQuarantineDir
	forwardQuarantineDir = dir
	t.Cleanup(func() { forwardQuarantineDir = prev })
	for _, sub := range []string{"new", "cur"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old = filepath.Join(dir, "cur", "old.eml")
	fresh = filepath.Join(dir, "new", "fresh.eml")
	for _, path := range []string{old, fresh} {
		if err := os.WriteFile(path, []byte("X-CSM-Forwarder: a@example.com\n\nbody\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := time.Now().Add(-3 * 24 * time.Hour)
	if err := os.Chtimes(old, stale, stale); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.EmailProtection.ForwardGuard.QuarantineRetentionDays = retentionDays
	newDaemonForReloadTest(t, cfg)
	return old, fresh
}

func TestPruneForwardQuarantineRemovesCopiesPastRetention(t *testing.T) {
	old, fresh := seedForwardQuarantine(t, 2)
	d := &Daemon{}

	d.pruneForwardQuarantine()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("held copy older than the retention window still exists (err=%v)", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh held copy was removed: %v", err)
	}
}

func TestPruneForwardQuarantineKeepsEverythingWithoutRetention(t *testing.T) {
	old, _ := seedForwardQuarantine(t, 0)
	d := &Daemon{}

	d.pruneForwardQuarantine()

	if _, err := os.Stat(old); err != nil {
		t.Fatalf("retention 0 must keep held copies, got %v", err)
	}
}

// flakyForwardGuard fails its first fail reconcile attempts.
type flakyForwardGuard struct {
	applies, removes, refreshes int
	fail                        int
}

func (g *flakyForwardGuard) result() error {
	if g.applies+g.removes <= g.fail {
		return errors.New("exim mutation lock is held by another CSM transaction")
	}
	return nil
}

func (g *flakyForwardGuard) Apply(policy.Config, []string) error {
	g.applies++
	return g.result()
}
func (g *flakyForwardGuard) Remove() error {
	g.removes++
	return g.result()
}
func (g *flakyForwardGuard) RefreshBadIPs([]string) error { g.refreshes++; return nil }
func (g *flakyForwardGuard) Status() (adapter.Status, error) {
	return adapter.Status{}, nil
}

// A failed install or removal, such as one refused while an antispam
// transaction holds the Exim lock, is retried on the next refresh instead
// of waiting for a reload or restart.
func TestForwardGuardRetriesFailedReconcileOnRefresh(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "remove"
		if enabled {
			name = "apply"
		}
		t.Run(name, func(t *testing.T) {
			usePanel(t, platform.PanelCPanel)
			cfg := &config.Config{Mode: config.ModeEnforce}
			cfg.EmailProtection.ForwardGuard.Enabled = enabled
			cfg.EmailProtection.ForwardGuard.HoldSignals.BounceBackscatter = true
			useActiveConfig(t, cfg)
			g := &flakyForwardGuard{fail: 2}
			prev := newForwardGuard
			t.Cleanup(func() { newForwardGuard = prev })
			newForwardGuard = func() adapter.ForwardGuard { return g }
			d := &Daemon{cfg: cfg}

			d.reconcileForwardGuard()
			for want := 2; want <= 3; want++ {
				d.refreshForwardGuard()
				if got := g.applies + g.removes; got != want {
					t.Fatalf("reconcile attempts = %d, want %d", got, want)
				}
			}
			d.refreshForwardGuard()
			if got := g.applies + g.removes; got != 3 {
				t.Fatalf("successful reconcile was retried: %d attempts", got)
			}
			if enabled {
				if g.applies != 3 || g.removes != 0 || g.refreshes != 3 {
					t.Fatalf("enforcing guard calls: %+v", g)
				}
			} else if g.removes != 3 || g.applies != 0 || g.refreshes != 0 {
				t.Fatalf("disabled guard calls: %+v", g)
			}
		})
	}
}

func TestForwardGuardRetrySkipsInactiveHosts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		panel platform.Panel
		mode  string
	}{
		{"observe", platform.PanelCPanel, config.ModeObserve},
		{"no_panel", platform.PanelNone, config.ModeEnforce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usePanel(t, tc.panel)
			cfg := &config.Config{Mode: tc.mode}
			cfg.EmailProtection.ForwardGuard.Enabled = true
			cfg.EmailProtection.ForwardGuard.HoldSignals.BounceBackscatter = true
			useActiveConfig(t, cfg)
			g := &flakyForwardGuard{}
			prev := newForwardGuard
			t.Cleanup(func() { newForwardGuard = prev })
			newForwardGuard = func() adapter.ForwardGuard { return g }
			d := &Daemon{cfg: cfg}
			d.forwardGuardRetry.Store(true)

			d.refreshForwardGuard()
			d.reconcileForwardGuard()
			if g.applies != 0 || g.removes != 0 || g.refreshes != 0 {
				t.Fatalf("inactive host ran the forward guard: %+v", g)
			}
			if d.forwardGuardRetry.Load() {
				t.Fatal("inactive host kept retrying")
			}
		})
	}
}

// overlappingForwardGuard models a busy Exim lock followed by a slow retry.
type overlappingForwardGuard struct {
	mu        sync.Mutex
	entered   chan struct{}
	release   chan struct{}
	attempts  int
	installed policy.Config
}

func (g *overlappingForwardGuard) mutate(cfg policy.Config) error {
	if !g.mu.TryLock() {
		return errors.New("exim mutation lock is busy")
	}
	defer g.mu.Unlock()
	g.attempts++
	if g.attempts == 1 {
		return errors.New("exim mutation lock is busy")
	}
	if g.attempts == 2 {
		close(g.entered)
		<-g.release
	}
	g.installed = cfg
	return nil
}

func (g *overlappingForwardGuard) Apply(cfg policy.Config, _ []string) error {
	return g.mutate(cfg)
}
func (g *overlappingForwardGuard) Remove() error                { return g.mutate(policy.Config{}) }
func (g *overlappingForwardGuard) RefreshBadIPs([]string) error { return nil }
func (g *overlappingForwardGuard) Status() (adapter.Status, error) {
	return adapter.Status{}, nil
}

func TestForwardGuardReloadDuringRetryKeepsLatestConfigPending(t *testing.T) {
	for _, initiallyEnabled := range []bool{false, true} {
		name := "enable"
		if initiallyEnabled {
			name = "disable"
		}
		t.Run(name, func(t *testing.T) {
			usePanel(t, platform.PanelCPanel)
			cfg := &config.Config{Mode: config.ModeEnforce}
			cfg.EmailProtection.ForwardGuard.Enabled = initiallyEnabled
			cfg.EmailProtection.ForwardGuard.HoldSignals.BounceBackscatter = true
			useActiveConfig(t, cfg)
			g := &overlappingForwardGuard{entered: make(chan struct{}), release: make(chan struct{})}
			prev := newForwardGuard
			t.Cleanup(func() { newForwardGuard = prev })
			newForwardGuard = func() adapter.ForwardGuard { return g }
			d := &Daemon{cfg: cfg}
			d.reconcileForwardGuard()

			finished := make(chan struct{})
			go func() {
				d.refreshForwardGuard()
				close(finished)
			}()
			var release sync.Once
			t.Cleanup(func() {
				release.Do(func() { close(g.release) })
				<-finished
			})
			select {
			case <-g.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("failed reconcile was not retried")
			}

			next := *cfg
			next.EmailProtection.ForwardGuard.Enabled = !initiallyEnabled
			config.SetActive(&next)
			reloaded := make(chan struct{})
			go func() {
				d.reconcileForwardGuard()
				close(reloaded)
			}()
			t.Cleanup(func() {
				release.Do(func() { close(g.release) })
				<-reloaded
			})
			select {
			case <-reloaded:
			case <-time.After(5 * time.Second):
				t.Fatal("reload waited for the running forward-guard worker")
			}
			release.Do(func() { close(g.release) })
			<-finished

			d.refreshForwardGuard()
			if g.installed.Enabled != next.EmailProtection.ForwardGuard.Enabled {
				t.Fatalf("installed enabled = %v, want latest config %v", g.installed.Enabled, next.EmailProtection.ForwardGuard.Enabled)
			}
			if g.attempts != 3 {
				t.Fatalf("mutation attempts = %d, want 3", g.attempts)
			}
			d.refreshForwardGuard()
			if g.attempts != 3 {
				t.Fatalf("successful latest config was retried: %d attempts", g.attempts)
			}
		})
	}
}
