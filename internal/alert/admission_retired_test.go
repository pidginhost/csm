package alert

import (
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

// Retired session scores cannot be treated as handled network attacks by
// the unwired fallback policy, even while an address is challenged.
func TestRetiredSessionScoreIsNotHandledByTheAlertFilter(t *testing.T) {
	f := Finding{Check: "local_threat_score", Severity: Critical, SourceIP: "192.0.2.9"}
	for _, blocked := range []bool{false, true} {
		if ipResponseAnswers(nil, &config.Config{}, f, blocked) {
			t.Fatalf("retired score treated as handled, blocked=%v", blocked)
		}
	}
	if challengeHandlesFinding(f) {
		t.Fatal("retired session score remains challenge eligible")
	}
	if !ipResponseAnswers(nil, &config.Config{}, Finding{Check: "ip_reputation", Severity: High}, false) {
		t.Fatal("active HTTP reputation challenge eligibility was lost")
	}
}
