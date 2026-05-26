package daemon

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

func TestExpandWithCorrelation_EmitsCoordinatedAttack(t *testing.T) {
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/alice/public_html/shell.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/bob/public_html/x.php", Timestamp: now},
		{Severity: alert.Critical, Check: "webshell", Details: "found in /home/carol/public_html/y.php", Timestamp: now},
	}

	out := expandWithCorrelation(findings, now)

	if len(out) < len(findings)+1 {
		t.Fatalf("output len = %d, want at least %d (input + synthetic)", len(out), len(findings)+1)
	}
	got := ""
	for _, f := range out {
		if f.Check == "coordinated_attack" {
			got = f.Message
			if f.Timestamp.IsZero() {
				t.Errorf("synthetic finding must have a timestamp, message=%q", f.Message)
			}
			break
		}
	}
	if got == "" {
		t.Fatal("expected coordinated_attack synthetic finding, none emitted")
	}
}

func TestExpandWithCorrelation_StampsMissingTimestamp(t *testing.T) {
	stamp := time.Date(2026, 5, 26, 14, 30, 0, 0, time.UTC)
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "/home/alice/p.php"},
		{Severity: alert.Critical, Check: "webshell", Details: "/home/bob/q.php"},
		{Severity: alert.Critical, Check: "webshell", Details: "/home/carol/r.php"},
	}

	out := expandWithCorrelation(findings, stamp)
	stamped := 0
	for _, f := range out {
		if f.Check == "coordinated_attack" {
			if !f.Timestamp.Equal(stamp) {
				t.Errorf("synthetic timestamp = %v, want %v", f.Timestamp, stamp)
			}
			stamped++
		}
	}
	if stamped == 0 {
		t.Fatal("expected at least one stamped synthetic finding")
	}
}

func TestExpandWithCorrelation_DoesNotDuplicateExistingSyntheticFindings(t *testing.T) {
	stamp := time.Date(2026, 5, 26, 15, 0, 0, 0, time.UTC)
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/alice/public_html/p.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/bob/public_html/q.php"},
		{Severity: alert.Critical, Check: "webshell", Message: "Found in /home/carol/public_html/r.php"},
	}
	preCorrelated := append(append([]alert.Finding(nil), findings...), checks.CorrelateFindings(findings)...)

	out := expandWithCorrelation(preCorrelated, stamp)

	if len(out) != len(preCorrelated) {
		t.Fatalf("pre-correlated batch grew from %d to %d", len(preCorrelated), len(out))
	}
	gotCounts := map[string]int{}
	for _, f := range out {
		if !isCorrelationFinding(f.Check) {
			continue
		}
		gotCounts[f.Check]++
		if f.Timestamp.IsZero() {
			t.Errorf("synthetic finding %q was not timestamped", f.Check)
		}
	}
	for _, check := range []string{"coordinated_attack", "cross_account_malware"} {
		if gotCounts[check] != 1 {
			t.Errorf("synthetic finding count for %q = %d, want 1", check, gotCounts[check])
		}
	}
}

func TestExpandWithCorrelation_BelowThresholdEmitsNothingExtra(t *testing.T) {
	now := time.Now()
	findings := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell", Details: "/home/alice/p.php", Timestamp: now},
	}
	out := expandWithCorrelation(findings, now)
	if len(out) != len(findings) {
		t.Errorf("single-account batch should not synthesize anything, got %d vs %d", len(out), len(findings))
	}
}
