package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A spray parked at shutdown keeps the addresses it counted and their lines,
// and the queue identity covers them.
func TestPendingFindingsKeepSprayConstituents(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	constituents := []alert.SprayConstituent{
		{Address: "203.0.113.1", LastSeen: at, Observation: alert.Observation{Producer: "exim_log", Stream: "f:1:2:e.0", Cursor: "10", ObservedAt: at}},
		{Address: "203.0.113.2", LastSeen: at.Add(time.Second)},
	}
	spray := alert.Finding{Check: "smtp_subnet_spray", Message: "spray", CIDRs: []string{"203.0.113.0/24"}, SprayConstituents: constituents, Timestamp: at}
	if appendErr := st.AppendPendingFindings([]alert.Finding{spray}); appendErr != nil {
		t.Fatal(appendErr)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].SprayConstituents, constituents) {
		t.Fatalf("replayed %+v, want the constituents", got)
	}
	other := spray
	other.SprayConstituents = []alert.SprayConstituent{{Address: "203.0.113.3", LastSeen: at}}
	if pendingIdentity([]alert.Finding{spray}) == pendingIdentity([]alert.Finding{other}) {
		t.Fatal("queue identity ignores the constituents")
	}
}
