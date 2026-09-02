package alert

import "testing"

// PHP Shield findings collapse per source IP so one scanner sweeping every
// site on a host raises one alert. That collapse must never swallow an
// escalation: a Critical block from an IP that earlier produced a Warning
// observation is a different event, or the block is never alerted, never
// written to history and never correlated for the whole dedup window.
func TestPHPShieldEscalationIsDistinctFromObservation(t *testing.T) {
	observed := Finding{
		Severity: Warning,
		Check:    "php_shield_webshell",
		SourceIP: "203.0.113.9",
		Message:  "PHP Shield observed a webshell command parameter: /a.php",
	}
	blocked := Finding{
		Severity: Critical,
		Check:    "php_shield_webshell",
		SourceIP: "203.0.113.9",
		Message:  "PHP Shield blocked a webshell signature: /wp-content/uploads/x.php",
	}
	if observed.Key() == blocked.Key() {
		t.Fatalf("Warning and Critical from the same IP share Key %q", observed.Key())
	}
	if observed.Fingerprint() == blocked.Fingerprint() {
		t.Fatalf("Warning and Critical from the same IP share Fingerprint %q", observed.Fingerprint())
	}
	if got := Deduplicate([]Finding{observed, blocked}); len(got) != 2 {
		t.Fatalf("Deduplicate dropped the escalation: %d findings kept, want 2", len(got))
	}

	// Same severity from the same IP still collapses: one alert per scanner.
	again := Finding{
		Severity: Critical,
		Check:    "php_shield_webshell",
		SourceIP: "203.0.113.9",
		Message:  "PHP Shield blocked a webshell signature: /other.php",
	}
	if again.Key() != blocked.Key() {
		t.Fatalf("two blocks from one IP must share a Key, got %q vs %q", again.Key(), blocked.Key())
	}
	if again.Fingerprint() != blocked.Fingerprint() {
		t.Fatalf("two blocks from one IP must share the alert-window fingerprint, got %q vs %q", again.Fingerprint(), blocked.Fingerprint())
	}
}
