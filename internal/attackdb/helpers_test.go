package attackdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- extractIP --------------------------------------------------------

func TestExtractIPFromMessage(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"FTP login from 203.0.113.5 port 21", "203.0.113.5"},
		{"Known malicious IP accessing server: 198.51.100.1 (AbuseIPDB", "198.51.100.1"},
		{"SSH auth failure: 203.0.113.10, user root", "203.0.113.10"},
		{"no ip here", ""},
	}
	for _, tt := range tests {
		if got := extractIP(tt.msg); got != tt.want {
			t.Errorf("extractIP(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

// --- extractAccount ---------------------------------------------------

func TestExtractAccountFromDetailsField(t *testing.T) {
	if got := extractAccount("msg", "Account: alice\nSome details"); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestExtractAccountFromPath(t *testing.T) {
	if got := extractAccount("Malware in /home/bob/public_html/evil.php", ""); got != "bob" {
		t.Errorf("got %q, want bob", got)
	}
}

func TestExtractAccountMissing(t *testing.T) {
	if got := extractAccount("no account info", "no details"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- truncate ---------------------------------------------------------

func TestTruncateShort(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestTruncateLong(t *testing.T) {
	if got := truncate("hello world", 5); got != "hello" {
		t.Errorf("got %q", got)
	}
}

// --- DB methods (constructed directly) --------------------------------

func TestDBTotalIPs(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{IP: "1.1.1.1"}
	db.records["2.2.2.2"] = &IPRecord{IP: "2.2.2.2"}
	if got := db.TotalIPs(); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestDBAllRecordsDeepCopy(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{
		IP:           "1.1.1.1",
		AttackCounts: map[AttackType]int{AttackBruteForce: 5},
		Accounts:     map[string]int{"alice": 1},
	}
	recs := db.AllRecords()
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	// Mutate the copy — original should be unaffected.
	recs[0].AttackCounts[AttackC2] = 99
	if db.records["1.1.1.1"].AttackCounts[AttackC2] != 0 {
		t.Error("AllRecords should return deep copies")
	}
}

func TestDBFormatTopLine(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{IP: "1.1.1.1", AutoBlocked: true}
	db.records["2.2.2.2"] = &IPRecord{IP: "2.2.2.2"}
	got := db.FormatTopLine()
	if got != "2 IPs tracked, 1 auto-blocked" {
		t.Errorf("got %q", got)
	}
}

func TestDBRemoveIP(t *testing.T) {
	db := newTestDB(t)
	db.records["1.1.1.1"] = &IPRecord{IP: "1.1.1.1"}
	db.RemoveIP("1.1.1.1")
	if db.TotalIPs() != 0 {
		t.Error("RemoveIP should delete the record")
	}
	if _, ok := db.deletedIPs["1.1.1.1"]; !ok {
		t.Error("RemoveIP should mark as deleted")
	}
}

func TestRotateEventsFileKeepsHalf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	// Write enough data that rotation keeps the second half.
	line := `{"ip":"1.2.3.4","type":"brute","timestamp":"2026-04-12T10:00:00Z"}` + "\n"
	var data []byte
	for i := 0; i < 20; i++ {
		data = append(data, []byte(line)...)
	}
	_ = os.WriteFile(path, data, 0600)

	rotateEventsFile(path)

	after, _ := os.ReadFile(path)
	if len(after) >= len(data) {
		t.Errorf("rotation should reduce size: before=%d after=%d", len(data), len(after))
	}
	if len(after) == 0 {
		t.Error("rotation should keep some data")
	}
}

func TestRotateEventsFileMissing(t *testing.T) {
	rotateEventsFile(filepath.Join(t.TempDir(), "nope")) // should not panic
}

func TestDBPruneExpired(t *testing.T) {
	db := newTestDB(t)
	db.records["old"] = &IPRecord{IP: "old", LastSeen: time.Now().Add(-100 * 24 * time.Hour)}
	db.records["new"] = &IPRecord{IP: "new", LastSeen: time.Now()}
	db.PruneExpired()
	if db.TotalIPs() != 1 {
		t.Errorf("after prune: %d IPs, want 1", db.TotalIPs())
	}
	if _, ok := db.records["new"]; !ok {
		t.Error("recent record should survive")
	}
}
