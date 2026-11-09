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

// A parked finding keeps how its address was read, and so do the addresses
// a spray counted: a replay mints what the original would have.
func TestPendingFindingsKeepAttribution(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	obs := alert.Observation{Producer: "mail_log", Stream: "mail", Cursor: "offset=7", ObservedAt: at}
	constituents := []alert.SprayConstituent{{Address: "203.0.113.1", LastSeen: at, Observation: obs, Attribution: admission.AttributionPeer}}
	sshObs := alert.Observation{Producer: "sshd_log", Stream: "secure", Cursor: "offset=8", ObservedAt: at}
	parked := []alert.Finding{
		{Check: "ssh_login_unknown_ip", Message: "login", SourceIP: "192.0.2.40", Timestamp: at, Observation: sshObs, Attribution: admission.AttributionPeer},
		{Check: "smtp_subnet_spray", Message: "spray", CIDRs: []string{"203.0.113.0/24"}, SprayConstituents: constituents, Timestamp: at},
		{Check: "auto_block", Message: "plain", Timestamp: at},
	}
	if appendErr := st.AppendPendingFindings(parked); appendErr != nil {
		t.Fatal(appendErr)
	}
	data, err := os.ReadFile(filepath.Join(st.path, pendingFindingsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `"response_attribution"`) != 1 {
		t.Fatalf("parked file %s, want the attribution only on the finding that has one", data)
	}
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := reopened.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Observation != sshObs || got[0].SourceIP != "192.0.2.40" || got[0].Attribution != admission.AttributionPeer || got[2].Attribution != admission.AttributionUnknown ||
		!reflect.DeepEqual(got[1].SprayConstituents, constituents) {
		t.Fatalf("replayed %+v, want the attribution back", got)
	}
	other := parked[0]
	other.Attribution = admission.AttributionHTTPPeer
	if pendingIdentity(parked[:1]) == pendingIdentity([]alert.Finding{other}) {
		t.Fatal("queue identity ignores the attribution")
	}
	if alert.FindingID(parked[0]) != alert.FindingID(other) {
		t.Fatal("internal attribution changed the public finding ID")
	}
	public, err := json.Marshal(parked[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "attribution") {
		t.Fatal("public finding JSON exposes internal attribution")
	}
}

// Missing metadata from an older parked queue stays unknown after restart.
func TestPendingFindingsKeepAttributionUnknownForOldRecords(t *testing.T) {
	dir := t.TempDir()
	const old = `[{"check":"ssh_login_unknown_ip","source_ip":"192.0.2.40","response_observation":{"producer":"sshd_log","stream":"secure","cursor":"offset=8","observed_at":"2026-10-02T12:00:00Z"}},{"check":"mail_subnet_spray","response_spray_constituents":[{"address":"203.0.113.1","last_seen":"2026-10-02T12:00:00Z","observation":{"producer":"mail_log","stream":"mail","cursor":"offset=7","observed_at":"2026-10-02T12:00:00Z"}}]}]`
	if err := os.WriteFile(filepath.Join(dir, pendingFindingsFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	got, err := st.TakePendingFindings()
	if err != nil || len(got) != 2 {
		t.Fatalf("old queue: %+v %v", got, err)
	}
	if got[0].Attribution != admission.AttributionUnknown || got[0].SourceIP != "192.0.2.40" || got[0].Observation.Producer != "sshd_log" {
		t.Fatalf("old finding acquired attribution or lost provenance: %+v", got[0])
	}
	cs := got[1].SprayConstituents
	if len(cs) != 1 || cs[0].Attribution != admission.AttributionUnknown || cs[0].Address != "203.0.113.1" || cs[0].Observation.Producer != "mail_log" {
		t.Fatalf("old constituent acquired attribution or lost provenance: %+v", cs)
	}
}
