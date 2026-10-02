package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/admission"
	"github.com/pidginhost/csm/internal/alert"
)

// A finding parked at shutdown keeps where it was read and which account it
// claims, so the evidence a replay mints names the same observation and
// owner as the original would have.
func TestPendingFindingsKeepObservationAndClaims(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	parked := []alert.Finding{
		{
			Check: "ssh_login_unknown_ip", Message: "login", SourceIP: "192.0.2.40", Timestamp: observed,
			Observation: alert.Observation{Producer: "sshd_log", Stream: "f:801:42:1", Cursor: "4096", ObservedAt: observed},
			Claims:      []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}},
		},
		{Check: "auto_block", Message: "plain", Timestamp: observed},
	}
	if appendErr := st.AppendPendingFindings(parked); appendErr != nil {
		t.Fatal(appendErr)
	}
	data, err := os.ReadFile(filepath.Join(st.path, pendingFindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"response_observation"`) != 1 || strings.Count(string(data), `"response_claims"`) != 1 {
		t.Fatalf("parked file %s, want the observation and claims only on the finding that has them", data)
	}
	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Observation != parked[0].Observation || !reflect.DeepEqual(got[0].Claims, parked[0].Claims) {
		t.Fatalf("replayed %+v, want the observation and claims back", got)
	}
	if got[1].Observation != (alert.Observation{}) || got[1].Claims != nil {
		t.Fatalf("replayed %+v, want no observation or claims on the plain finding", got[1])
	}
}

// Storage metadata never enters public JSON; an older decoder ignores it
// while retaining the full public finding payload.
func TestPendingObservationDowngradeKeepsPublicPayload(t *testing.T) {
	base := alert.Finding{Check: "ssh_login_unknown_ip", Message: "login", SourceIP: "192.0.2.40"}
	f := base
	f.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}}
	f.Observation = alert.Observation{Producer: "sshd_log", Stream: "s", Cursor: "1", ObservedAt: time.Unix(1, 0)}
	plain, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(f)
	if err != nil || string(public) != string(plain) {
		t.Fatalf("public payload changed: %s (error %v)", public, err)
	}
	parked, err := json.Marshal(toPendingRecords([]alert.Finding{f}))
	if err != nil {
		t.Fatal(err)
	}
	var older []alert.Finding
	if err := json.Unmarshal(parked, &older); err != nil {
		t.Fatal(err)
	}
	if len(older) != 1 || !reflect.DeepEqual(older[0], base) {
		t.Fatalf("downgrade decoded %+v, want public payload %+v", older, base)
	}
}

// The queue identity covers the observation and the claims like every other
// persisted field.
func TestPendingIdentityCoversObservationAndClaims(t *testing.T) {
	base := alert.Finding{Check: "ssh_login_unknown_ip", Message: "login"}
	a, b := base, base
	a.Observation = alert.Observation{Producer: "sshd_log", Stream: "s", Cursor: "1"}
	b.Observation = alert.Observation{Producer: "sshd_log", Stream: "s", Cursor: "2"}
	if pendingIdentity([]alert.Finding{a}) == pendingIdentity([]alert.Finding{b}) {
		t.Fatal("identity ignores the observation")
	}
	c, d := base, base
	c.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: "alice"}}
	d.Claims = []admission.Claim{{Kind: admission.ClaimAccount, Value: "bob"}}
	if pendingIdentity([]alert.Finding{c}) == pendingIdentity([]alert.Finding{d}) {
		t.Fatal("identity ignores the claims")
	}
}
