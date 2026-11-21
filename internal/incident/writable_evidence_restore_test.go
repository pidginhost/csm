package incident

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Evidence persisted without its producer, as every release before this one
// stored it, cannot be told apart from a forged syslog line for a check a
// syslog file producer emits: after a restore it attests nothing. Evidence
// that names a producer the daemon trusts survives, through the timeline
// and through the cached proof alike.
func TestRestoredEvidenceNeedsAVerifiedProducer(t *testing.T) {
	unverified := func(check, producer string) bool {
		return producer == "sshd_log" || (producer == "" && check == "ssh_login_unknown_ip")
	}
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name     string
		producer string
		timeline bool
		want     bool
	}{
		{"older cached proof", "", false, false},
		{"older timeline event", "", true, false},
		{"syslog file", "sshd_log", true, false},
		{"journal cached proof", "sshd_journal", false, true},
		{"journal timeline event", "sshd_journal", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := CorrelatorConfig{
				OpenThreshold:     1,
				AddressEvidence:   func(check string, _ alert.Severity) bool { return check == "ssh_login_unknown_ip" },
				UnverifiedAddress: unverified,
				AutoBlock:         IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
			}
			inc := Incident{
				ID: "stored", Kind: KindWebAttack, Status: StatusOpen, Severity: alert.Critical,
				CreatedAt: now, UpdatedAt: now, CorrelationKey: &Key{RemoteIP: "192.0.2.77"},
				RemoteIPEvidence: true, RemoteIPEvidenceFinding: "0123456789abcdef",
				RemoteIPEvidenceCheck: "ssh_login_unknown_ip", RemoteIPEvidenceSeverity: "CRITICAL",
				RemoteIPEvidenceProducer: tc.producer,
			}
			if tc.timeline {
				inc.Timeline = []IncidentEvent{{Kind: "finding", Check: "ssh_login_unknown_ip", Severity: "CRITICAL",
					RemoteIP: "192.0.2.77", FindingID: inc.RemoteIPEvidenceFinding, Producer: tc.producer}}
			}
			raw, err := json.Marshal(inc)
			if err != nil {
				t.Fatal(err)
			}
			var stored Incident
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Fatal(err)
			}
			c := NewCorrelator(cfg)
			c.now = func() time.Time { return now }
			c.Restore([]Incident{stored})
			got, _ := c.Get(inc.ID)
			if got.RemoteIPEvidence != tc.want {
				t.Fatalf("restored evidence = %v, want %v", got.RemoteIPEvidence, tc.want)
			}
		})
	}
}
