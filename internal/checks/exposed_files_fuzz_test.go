package checks

import (
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// FuzzClassifyExposedFile exercises the filename classifier with arbitrary,
// attacker-controlled names. It must never panic, must be deterministic, and
// every non-None class it returns must carry a valid finding name + severity.
func FuzzClassifyExposedFile(f *testing.F) {
	seeds := []string{
		"", ".", "..", "~", ".env", ".env.", ".env.....", "wp-config.php",
		"wp-config-sample.php", "softsql.sql", "a.sql.zip", "x.php.old",
		"phpinfo.php", "....php", "name.PHP.OLD", "backup.tar.gz",
		"\x00\x00.sql", "................", "a.php~~~~", "/etc/passwd",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := classifyExposedFile(name)
		if classifyExposedFile(name) != got {
			t.Fatalf("classifyExposedFile(%q) is non-deterministic", name)
		}
		if got == classNone {
			return
		}
		if got.findingName() == "" {
			t.Errorf("classified %q as %v with empty finding name", name, got)
		}
		switch got.severity() {
		case alert.Warning, alert.High, alert.Critical:
		default:
			t.Errorf("classified %q as %v with invalid severity", name, got)
		}
	})
}
