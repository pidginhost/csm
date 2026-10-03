package incident

import (
	"fmt"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Address evidence survives timeline trimming: an incident whose attesting
// finding was trimmed away still blocks when later advisories raise its
// severity, because the gate, not the advisories, decides the address.
func TestTrimmedEvidenceStillBlocksAfterAdvisories(t *testing.T) {
	var cap blockCapture
	c := NewCorrelator(CorrelatorConfig{
		AddressEvidence: registryEvidence,
		OpenThreshold:   1,
		AutoBlock:       IncidentAutoBlockConfig{Enabled: true, BlockAtSeverity: "critical"},
		OnIncidentBlock: cap.recordOK,
	})
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	for i := 0; i < 260; i++ {
		feed(t, c, &now, alert.Finding{Check: "mail_bruteforce_suspected", Severity: alert.High, SourceIP: "198.51.100.93", Message: fmt.Sprintf("advisory %d", i)})
	}
	feed(t, c, &now, alert.Finding{Check: "mail_bruteforce", Severity: alert.High, SourceIP: "198.51.100.93", Message: "brute force"})
	for i := 260; i < 860; i++ {
		feed(t, c, &now, alert.Finding{Check: "mail_bruteforce_suspected", Severity: alert.High, SourceIP: "198.51.100.93", Message: fmt.Sprintf("advisory %d", i)})
	}
	if cap.len() != 0 {
		t.Fatalf("blocked before the severity gate: %+v", cap.calls)
	}
	feed(t, c, &now, alert.Finding{Check: "mail_bruteforce_suspected", Severity: alert.Critical, SourceIP: "198.51.100.93", Message: "advisory final"})
	if cap.len() != 1 || cap.calls[0].IP != "198.51.100.93" {
		t.Fatalf("trimmed evidence blocks %+v, want one block of the attested address", cap.calls)
	}
}
