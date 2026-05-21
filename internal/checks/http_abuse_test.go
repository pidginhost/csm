package checks

import (
	"sort"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// TestRefactorParity feeds a fixed set of access-log lines through the
// current countBruteForce / aggregator path and asserts that the same
// three legacy findings come out with the same messages and severities.
// This locks the refactor down to "zero behavior change".
func TestRefactorParity(t *testing.T) {
	lines := []string{
		// 20 wp-login POSTs from one IP (at wpLoginThreshold=20)
		`192.0.2.10 - - [20/May/2026:18:00:00 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:01 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:02 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:03 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:04 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:05 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:06 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:07 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:08 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:09 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:10 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:11 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:12 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:13 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:14 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:15 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:16 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:17 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:18 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		`192.0.2.10 - - [20/May/2026:18:00:19 +0300] "POST /wp-login.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`,
		// 32 xmlrpc POSTs from another IP (above xmlrpcThreshold=30)
	}
	for i := 0; i < 32; i++ {
		lines = append(lines,
			`198.51.100.20 - - [20/May/2026:18:00:00 +0300] "POST /xmlrpc.php HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
	}
	// 6 ?author= GETs from a third IP (above userEnumThreshold=5)
	for i := 0; i < 6; i++ {
		lines = append(lines,
			`203.0.113.30 - - [20/May/2026:18:00:00 +0300] "GET /?author=1 HTTP/1.1" 200 0 "-" "Mozilla/5.0"`)
	}

	stats := newDomlogStats()
	for _, ln := range lines {
		rec, ok := parseAccessLogRecord(ln)
		if !ok {
			t.Fatalf("parseAccessLogRecord rejected fixture line: %q", ln)
		}
		stats.scan(rec, nil, nopBotClassifier{})
	}

	got := stats.emitLegacy(nil)
	sort.Slice(got, func(i, j int) bool { return got[i].Check < got[j].Check })

	want := []struct {
		Check    string
		Severity alert.Severity
		Message  string
	}{
		{"wp_login_bruteforce", alert.Critical, "WordPress login brute force from 192.0.2.10: 20 attempts"},
		{"wp_user_enumeration", alert.High, "WordPress user enumeration from 203.0.113.30: 6 requests"},
		{"xmlrpc_abuse", alert.Critical, "XML-RPC abuse from 198.51.100.20: 32 requests"},
	}
	if len(got) != len(want) {
		t.Fatalf("findings=%d, want %d (%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Check != w.Check {
			t.Errorf("[%d] check=%q want %q", i, got[i].Check, w.Check)
		}
		if got[i].Severity != w.Severity {
			t.Errorf("[%d] severity=%v want %v", i, got[i].Severity, w.Severity)
		}
		if got[i].Message != w.Message {
			t.Errorf("[%d] message=%q want %q", i, got[i].Message, w.Message)
		}
		if got[i].SourceIP != "" {
			t.Errorf("[%d] SourceIP=%q, want empty to preserve legacy JSON shape", i, got[i].SourceIP)
		}
	}
}
