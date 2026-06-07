package daemon

import (
	"sort"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

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
