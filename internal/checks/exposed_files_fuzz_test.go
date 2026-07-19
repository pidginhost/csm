package checks

import (
	"net"
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

// FuzzParseServingIP exercises malformed cPanel binding columns. Any accepted
// result must remain a canonical literal unicast address so the probe cannot
// fall through to DNS or pass malformed input to the dialer.
func FuzzParseServingIP(f *testing.F) {
	seeds := [][2]string{
		{"192.0.2.80:80", "192.0.2.43:443"},
		{"", "[2001:db8::43]:443"},
		{"", "2001:db8::43:443"},
		{"origin.example:80", "cdn.example:443"},
		{"127.0.0.1:80", "[::]:443"},
		{"192.0.2.80:443", "[2001:db8::43:443"},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, httpBinding, httpsBinding string) {
		fields := make([]string, 7)
		fields[5], fields[6] = httpBinding, httpsBinding
		got := parseServingIP(fields)
		if got == "" {
			return
		}
		ip := net.ParseIP(got)
		if ip == nil || !ip.IsGlobalUnicast() || got != ip.String() {
			t.Fatalf("parseServingIP() returned non-canonical serving address %q", got)
		}
	})
}
