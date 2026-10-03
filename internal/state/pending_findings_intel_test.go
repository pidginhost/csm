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

func TestPendingFindingsKeepBatchWithUnencodableIntel(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		expires time.Time
	}{
		{name: "large year", expires: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "negative year", expires: time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)},
		{name: "invalid offset", expires: at.In(time.FixedZone("", 24*60*60))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, marshalErr := tc.expires.MarshalJSON(); marshalErr == nil {
				t.Fatal("fixture expiry encodes; the test proves nothing")
			}
			intel := &admission.IntelRef{Source: "abuseipdb", Expires: tc.expires}
			bad := alert.Finding{Check: "ip_reputation", Message: "listed", SourceIP: "192.0.2.87", Timestamp: at, Intel: intel,
				Observation: alert.Observation{Producer: "reputation", Stream: "s", Cursor: "1", ObservedAt: at},
				Claims:      []admission.Claim{{Kind: admission.ClaimAccount, Value: "example"}},
			}
			good := alert.Finding{Check: "ip_reputation", Message: "other", SourceIP: "198.51.100.87", Timestamp: at,
				Intel: &admission.IntelRef{Source: "upstream", Expires: at.Add(time.Hour)},
			}
			if appendErr := st.AppendPendingFindings([]alert.Finding{good}); appendErr != nil {
				t.Fatal(appendErr)
			}
			if appendErr := st.AppendPendingFindings([]alert.Finding{bad, good}); appendErr != nil {
				t.Fatalf("invalid intel prevented parking the batch: %v", appendErr)
			}
			got, err := st.TakePendingFindings()
			if err != nil {
				t.Fatal(err)
			}
			sanitized := bad
			sanitized.Intel = nil
			want := []alert.Finding{good, sanitized, good}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("replayed %+v, want all findings with only invalid intel dropped", got)
			}
			identity := pendingIdentity([]alert.Finding{good, bad, good})
			if !identity.valid || identity != pendingIdentity(want) {
				t.Fatal("queue identity does not match the recoverable batch")
			}
			if bad.Intel != intel || intel.Source != "abuseipdb" || !intel.Expires.Equal(tc.expires) {
				t.Fatal("parking mutated the caller's intel")
			}
		})
	}
}
