package state

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestDeliveryReservationReleaseAndClear(t *testing.T) {
	s := openTestStore(t)
	f := alert.Finding{Check: "webshell", Message: "pending delivery"}
	batch := []alert.Finding{f}
	first, finishFirst := s.BeginDelivery(batch)
	if len(first) != 1 {
		t.Fatalf("first delivery: got %d findings", len(first))
	}
	overlap, finishOverlap := s.BeginDelivery(batch)
	finishOverlap(nil)
	if len(overlap) != 0 {
		t.Fatal("overlapping dispatch selected the same condition")
	}
	finishFirst(nil)
	if entry, _ := s.EntryForKey(f.Key()); entry.Emailed != "" {
		t.Fatal("failed delivery was marked sent")
	}

	retry, finishRetry := s.BeginDelivery(batch)
	if len(retry) != 1 {
		t.Fatal("failed delivery kept its reservation")
	}
	s.ForgetCleared(batch)
	returned, finishReturned := s.BeginDelivery(batch)
	if len(returned) != 1 {
		t.Fatal("in-flight delivery blocked a cleared condition's return")
	}
	finishRetry(retry)
	if entry, _ := s.EntryForKey(f.Key()); entry.Emailed != "" {
		t.Fatal("old completion marked the returned condition delivered")
	}
	overlap, finishOverlap = s.BeginDelivery(batch)
	finishOverlap(nil)
	if len(overlap) != 0 {
		t.Fatal("old completion released the returned condition's reservation")
	}
	finishReturned(returned)
	if got := s.FilterUnemailed(batch); len(got) != 0 {
		t.Fatal("successful current delivery was not recorded")
	}
	if len(s.emailPending) != 0 {
		t.Fatal("finished deliveries left pending reservations")
	}
}
