package webui

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/store"
)

// An unblock that lands while an applied batch is between its choice and
// its commit waits for the commit, then removes what the batch wrote.
func TestDropAutoBlockThreatRowWaitsForAnAppliedBatch(t *testing.T) {
	sdb, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Global()
	store.SetGlobal(sdb)
	t.Cleanup(func() {
		store.SetGlobal(prev)
		_ = sdb.Close()
	})
	t.Cleanup(checks.SetGlobalThreatDBForTest(t.TempDir()))
	const ip = "203.0.113.49"
	expires := time.Now().Add(time.Hour)
	chosen, release, committed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		committed <- checks.GetThreatDB().AddTemporaryBatchFrom(func() []store.PermanentBlockEntry {
			close(chosen)
			<-release
			return []store.PermanentBlockEntry{{IP: ip, Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires}}
		})
	}()
	<-chosen
	dropped := make(chan struct{})
	go func() {
		dropAutoBlockThreatRow(ip)
		close(dropped)
	}()
	select {
	case <-dropped:
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err = <-committed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-dropped:
	case <-time.After(5 * time.Second):
		t.Fatal("the unblock never finished")
	}
	if _, found := sdb.GetPermanentBlock(ip); found {
		t.Error("an unblock during an applied batch left a stored threat row")
	}
	if match, ok := checks.GetThreatDB().LookupMatch(ip); ok {
		t.Errorf("an unblock during an applied batch left threat evidence %+v", match)
	}
}
