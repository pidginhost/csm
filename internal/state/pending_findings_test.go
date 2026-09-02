package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// Findings still queued when the daemon stops are parked on disk so the next
// start can run them through the full dispatch pipeline. Two shutdown drains
// append to the same file; taking the findings clears it.
func TestPendingFindingsAppendThenTake(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first := []alert.Finding{
		{Severity: alert.Critical, Check: "webshell_realtime", FilePath: "/home/a/public_html/x.php", Message: "one", Timestamp: now},
		{Severity: alert.High, Check: "signature_match_realtime", FilePath: "/home/a/public_html/y.php", Message: "two", Timestamp: now},
	}
	if err := st.AppendPendingFindings(first); err != nil {
		t.Fatal(err)
	}
	second := []alert.Finding{{Severity: alert.Critical, Check: "auto_block", Message: "three", SourceIP: "203.0.113.5", Timestamp: now}}
	if err := st.AppendPendingFindings(second); err != nil {
		t.Fatal(err)
	}

	got := st.TakePendingFindings()
	if len(got) != 3 || got[0].Message != "one" || got[2].Message != "three" {
		t.Fatalf("pending findings = %+v, want the three appended in order", got)
	}
	if again := st.TakePendingFindings(); len(again) != 0 {
		t.Fatalf("second take returned %d findings, want none", len(again))
	}
	if _, err := os.Stat(filepath.Join(dir, "pending_findings.json")); !os.IsNotExist(err) {
		t.Fatalf("pending file still present after take: %v", err)
	}
}
