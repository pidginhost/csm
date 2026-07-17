package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestReputationSightingSeverityGradesBySurface(t *testing.T) {
	tests := []struct {
		via  string
		want alert.Severity
	}{
		// Passive sightings of a listed IP are ambient scanner noise.
		{"HTTP request", alert.High},
		{"cPanel/WHM access", alert.High},
		// Auth-surface activity is an active attack in progress.
		{"SSH login", alert.Critical},
		{"SMTP auth failure", alert.Critical},
		{"Dovecot IMAP/POP3 auth failure", alert.Critical},
		// Unknown future surfaces fail closed.
		{"carrier pigeon", alert.Critical},
	}
	for _, tt := range tests {
		if got := reputationSightingSeverity(tt.via); got != tt.want {
			t.Errorf("reputationSightingSeverity(%q) = %v, want %v", tt.via, got, tt.want)
		}
	}
}

func TestAppendReputationFindingUsesSurfaceSeverity(t *testing.T) {
	var findings []alert.Finding
	appendReputationFinding(&findings, "203.0.113.7", "HTTP request", "AbuseIPDB", 100, "Data Center")
	appendReputationFinding(&findings, "203.0.113.8", "SMTP auth failure", "AbuseIPDB", 100, "Fixed Line ISP")
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].Severity != alert.High {
		t.Errorf("passive HTTP sighting severity = %v, want High", findings[0].Severity)
	}
	if findings[1].Severity != alert.Critical {
		t.Errorf("SMTP auth-failure sighting severity = %v, want Critical", findings[1].Severity)
	}
}
