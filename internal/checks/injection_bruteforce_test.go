package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countBruteForce is pure-go — exercise every branch with a synthetic
// combined-log corpus.

func TestCountBruteForceAllBranches(t *testing.T) {
	lines := []string{
		// wp-login.php POST attempt from a single attacker.
		`203.0.113.5 - - [14/Apr/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 401 123 "-" "curl/8"`,
		`203.0.113.5 - - [14/Apr/2026:10:00:01 +0000] "POST /wp-login.php HTTP/1.1" 401 123 "-" "curl/8"`,
		// xmlrpc.php POST from a different attacker.
		`203.0.113.9 - - [14/Apr/2026:10:00:02 +0000] "POST /xmlrpc.php HTTP/1.1" 200 321 "-" "-"`,
		// User enumeration via author query.
		`203.0.113.77 - - [14/Apr/2026:10:00:03 +0000] "GET /?author=1 HTTP/1.1" 200 500 "-" "-"`,
		// User enumeration via REST endpoint.
		`203.0.113.78 - - [14/Apr/2026:10:00:04 +0000] "GET /wp-json/wp/v2/users HTTP/1.1" 200 500 "-" "-"`,
		// Authenticated self-check should NOT count as enumeration.
		`203.0.113.79 - - [14/Apr/2026:10:00:05 +0000] "GET /wp-json/wp/v2/users/me HTTP/1.1" 200 50 "-" "-"`,
		// Localhost, placeholder, infra IPs — must be ignored.
		`127.0.0.1 - - [14/Apr/2026:10:00:06 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		`::1 - - [14/Apr/2026:10:00:07 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		`- - - [14/Apr/2026:10:00:08 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		`192.168.1.1 - - [14/Apr/2026:10:00:09 +0000] "POST /wp-login.php HTTP/1.1" 401 0 "-" "-"`,
		// Too-short / malformed line — should be skipped, not panic.
		`short line not log format`,
		// GET on wp-login.php — not a brute force (only POSTs count).
		`203.0.113.100 - - [14/Apr/2026:10:00:10 +0000] "GET /wp-login.php HTTP/1.1" 200 1000 "-" "-"`,
	}

	wpLogin := map[string]int{}
	xmlrpc := map[string]int{}
	userEnum := map[string]int{}
	countBruteForce(lines, []string{"192.168.1.0/24"}, wpLogin, xmlrpc, userEnum)

	if wpLogin["203.0.113.5"] != 2 {
		t.Errorf("expected 2 wp-login hits for .5, got %d", wpLogin["203.0.113.5"])
	}
	if wpLogin["127.0.0.1"] != 0 || wpLogin["::1"] != 0 || wpLogin["-"] != 0 {
		t.Errorf("localhost/placeholder should be ignored, got %v", wpLogin)
	}
	if wpLogin["192.168.1.1"] != 0 {
		t.Errorf("infra IP should be ignored, got %d hits", wpLogin["192.168.1.1"])
	}
	if wpLogin["203.0.113.100"] != 0 {
		t.Errorf("GET on wp-login.php should not count, got %d", wpLogin["203.0.113.100"])
	}
	if xmlrpc["203.0.113.9"] != 1 {
		t.Errorf("expected 1 xmlrpc hit for .9, got %d", xmlrpc["203.0.113.9"])
	}
	if userEnum["203.0.113.77"] != 1 {
		t.Errorf("expected 1 author-enum hit for .77, got %d", userEnum["203.0.113.77"])
	}
	if userEnum["203.0.113.78"] != 1 {
		t.Errorf("expected 1 wp-json users hit for .78, got %d", userEnum["203.0.113.78"])
	}
	if userEnum["203.0.113.79"] != 0 {
		t.Errorf("/users/me should NOT count as enumeration, got %d", userEnum["203.0.113.79"])
	}
}

// scanDomlogs — dedupe symlinks, skip stale logs, respect file cap.

func TestScanDomlogsDeduplicatesSymlinks(t *testing.T) {
	tmp := t.TempDir()
	// Two log paths pointing at the same target via symlink.
	target := filepath.Join(tmp, "real.log")
	if err := os.WriteFile(target, []byte("203.0.113.1 - - [14/Apr/2026:10:00:00 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(tmp, "alias.log")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) {
			return []string{target, alias}, nil
		},
		stat: os.Stat,
		open: os.Open,
	})

	wpLogin := map[string]int{}
	scanned := scanDomlogs(nil, wpLogin, map[string]int{}, map[string]int{})
	if scanned != 1 {
		t.Errorf("expected 1 file scanned (symlink deduped), got %d", scanned)
	}
	if wpLogin["203.0.113.1"] != 1 {
		t.Errorf("expected 1 wp-login hit, got %d", wpLogin["203.0.113.1"])
	}
}

func TestScanDomlogsSkipsStaleLogs(t *testing.T) {
	tmp := t.TempDir()
	stale := filepath.Join(tmp, "stale.log")
	if err := os.WriteFile(stale, []byte("203.0.113.2 - - [14/Apr/2026:10:00:00 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Push mtime 2h into the past — beyond the 30-minute cutoff.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{stale}, nil },
		stat: os.Stat,
		open: os.Open,
	})

	wpLogin := map[string]int{}
	scanned := scanDomlogs(nil, wpLogin, map[string]int{}, map[string]int{})
	if scanned != 0 {
		t.Errorf("stale log should be skipped, got scanned=%d", scanned)
	}
	if len(wpLogin) != 0 {
		t.Errorf("stale log should contribute no hits, got %v", wpLogin)
	}
}

func TestScanDomlogsBrokenSymlinkSkipped(t *testing.T) {
	tmp := t.TempDir()
	dead := filepath.Join(tmp, "dead.log")
	// Symlink pointing at nothing — EvalSymlinks fails, loop continues.
	if err := os.Symlink(filepath.Join(tmp, "missing"), dead); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{dead}, nil },
		stat: os.Stat,
		open: os.Open,
	})

	wpLogin := map[string]int{}
	scanned := scanDomlogs(nil, wpLogin, map[string]int{}, map[string]int{})
	if scanned != 0 {
		t.Errorf("broken symlink should yield 0 scanned, got %d", scanned)
	}
}

func TestScanDomlogsNoMatches(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return nil, nil },
	})
	wpLogin := map[string]int{}
	if scanned := scanDomlogs(nil, wpLogin, map[string]int{}, map[string]int{}); scanned != 0 {
		t.Errorf("no matches should yield 0 scanned, got %d", scanned)
	}
}

func TestScanDomlogsFeedsAllCounters(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "access.log")
	entries := []string{
		// Repeating wp-login attacker.
		"203.0.113.5 - - [14/Apr/2026:10:00:00 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"",
		"203.0.113.5 - - [14/Apr/2026:10:00:01 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"",
		"203.0.113.5 - - [14/Apr/2026:10:00:02 +0000] \"POST /wp-login.php HTTP/1.1\" 401 0 \"-\" \"-\"",
		// xmlrpc + user enumeration.
		"203.0.113.9 - - [14/Apr/2026:10:00:03 +0000] \"POST /xmlrpc.php HTTP/1.1\" 200 0 \"-\" \"-\"",
		"203.0.113.9 - - [14/Apr/2026:10:00:04 +0000] \"GET /?author=2 HTTP/1.1\" 200 500 \"-\" \"-\"",
	}
	if err := os.WriteFile(log, []byte(strings.Join(entries, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	withMockOS(t, &mockOS{
		glob: func(string) ([]string, error) { return []string{log}, nil },
		stat: os.Stat,
		open: os.Open,
	})

	wpLogin := map[string]int{}
	xmlrpc := map[string]int{}
	userEnum := map[string]int{}
	scanned := scanDomlogs(nil, wpLogin, xmlrpc, userEnum)
	if scanned != 1 {
		t.Fatalf("expected 1 file scanned, got %d", scanned)
	}
	if wpLogin["203.0.113.5"] != 3 {
		t.Errorf("expected 3 wp-login hits, got %d", wpLogin["203.0.113.5"])
	}
	if xmlrpc["203.0.113.9"] != 1 {
		t.Errorf("expected 1 xmlrpc hit, got %d", xmlrpc["203.0.113.9"])
	}
	if userEnum["203.0.113.9"] != 1 {
		t.Errorf("expected 1 author-enum hit, got %d", userEnum["203.0.113.9"])
	}
}
