package state

import (
	"reflect"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// A reputation finding parked at shutdown keeps the intel it rests on, and
// the queue identity covers it.
func TestPendingFindingsKeepIntel(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	intel := &admission.IntelRef{Source: "abuseipdb", Expires: at.Add(6 * time.Hour)}
	f := alert.Finding{Check: "ip_reputation", Message: "listed", SourceIP: "192.0.2.86", Intel: intel, Timestamp: at}
	if appendErr := st.AppendPendingFindings([]alert.Finding{f}); appendErr != nil {
		t.Fatal(appendErr)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Intel, intel) {
		t.Fatalf("replayed %+v, want the intel", got)
	}
	other := f
	other.Intel = &admission.IntelRef{Source: "rspamd", Expires: intel.Expires}
	if pendingIdentity([]alert.Finding{f}) == pendingIdentity([]alert.Finding{other}) {
		t.Fatal("queue identity ignores the intel")
	}
}
