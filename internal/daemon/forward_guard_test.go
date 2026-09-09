package daemon

import (
	"sort"
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
