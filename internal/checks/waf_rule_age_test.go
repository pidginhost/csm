package checks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func wafVendorDir(t *testing.T, root, vendor string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(root, vendor)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf")
	if err := os.WriteFile(rule, []byte("SecRule ..."), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(rule, when, when); err != nil {
		t.Fatal(err)
	}
	return dir
}

// cPanel leaves a retired vendor's rule tree on disk after an operator switches
// to another one. On a live host OWASP3 was refreshed the same day while the
// abandoned COMODO tree sat at 31 days, and CSM reported "rules are 31 days
// old" -- pointing at a ruleset that no longer protects anything.
func TestCheckRuleAgeIgnoresAbandonedVendorWhenAnotherIsCurrent(t *testing.T) {
	root := t.TempDir()
	wafVendorDir(t, root, "comodo_litespeed", 31*24*time.Hour)
	wafVendorDir(t, root, "OWASP3", 2*time.Hour)

	if age := checkRuleAge([]string{root}); age != 0 {
		t.Errorf("a currently-maintained ruleset must not be reported stale, got age=%d", age)
	}
}

// Staleness is only real when nothing has been refreshed. With every vendor
// behind, the freshest one still clears the threshold and the alert must fire.
func TestCheckRuleAgeReportsWhenEveryVendorIsStale(t *testing.T) {
	root := t.TempDir()
	wafVendorDir(t, root, "comodo_litespeed", 90*24*time.Hour)
	wafVendorDir(t, root, "OWASP3", 45*24*time.Hour)

	age := checkRuleAge([]string{root})
	if age < 44 || age > 46 {
		t.Errorf("age = %d, want the freshest ruleset's age (~45 days)", age)
	}
}

// A single abandoned ruleset is still a real gap: there is nothing fresher to
// vouch for the host.
func TestCheckRuleAgeReportsSingleAbandonedVendor(t *testing.T) {
	root := t.TempDir()
	wafVendorDir(t, root, "comodo_litespeed", 60*24*time.Hour)

	if age := checkRuleAge([]string{root}); age < 30 {
		t.Errorf("age = %d, want the abandoned ruleset reported stale", age)
	}
}

// Separate rule directories are the same question as separate vendors: has any
// ruleset on this host been refreshed recently?
func TestCheckRuleAgeSpansMultipleRuleDirs(t *testing.T) {
	stale := t.TempDir()
	fresh := t.TempDir()
	wafVendorDir(t, stale, "comodo_litespeed", 40*24*time.Hour)
	wafVendorDir(t, fresh, "OWASP3", time.Hour)

	if age := checkRuleAge([]string{stale, fresh}); age != 0 {
		t.Errorf("a fresh ruleset in another rule dir must clear staleness, got age=%d", age)
	}
}
