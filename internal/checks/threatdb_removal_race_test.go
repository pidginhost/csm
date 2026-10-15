package checks

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/store"
)

// A flush that lands while an applied batch is between its choice and its
// commit waits for the commit, then removes what the batch wrote.
func TestFlushAutoBlockStateWaitsForAnAppliedBatch(t *testing.T) {
	withTestThreatStore(t)
	dir := t.TempDir()
	t.Cleanup(SetGlobalThreatDBForTest(dir))
	const ip = "203.0.113.52"
	expires := time.Now().Add(time.Hour)
	writeAdmissionBlock(t, dir, ip, expires)
	chosen, release, committed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		committed <- GetThreatDB().AddTemporaryBatchFrom(func() []store.PermanentBlockEntry {
			close(chosen)
			<-release
			return []store.PermanentBlockEntry{{IP: ip, Reason: "CSM auto-block: ssh_brute", ExpiresAt: expires}}
		})
	}()
	<-chosen
	flushed := make(chan error, 1)
	go func() {
		_, err := FlushAutoBlockState(dir, func() error { return nil })
		flushed <- err
	}()
	var flushErr error
	finished := false
	select {
	case flushErr = <-flushed:
		finished = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	if !finished {
		select {
		case flushErr = <-flushed:
		case <-time.After(5 * time.Second):
			t.Fatal("the flush never finished")
		}
	}
	if flushErr != nil {
		t.Fatal(flushErr)
	}
	if _, found := store.Global().GetPermanentBlock(ip); found {
		t.Error("a flush during an applied batch left a stored threat row")
	}
	if match, ok := GetThreatDB().LookupMatch(ip); ok {
		t.Errorf("a flush during an applied batch left threat evidence %+v", match)
	}
}
