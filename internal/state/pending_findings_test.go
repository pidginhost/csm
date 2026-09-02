package state

import (
	"errors"
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
	if appendErr := st.AppendPendingFindings(first); appendErr != nil {
		t.Fatal(appendErr)
	}
	second := []alert.Finding{{Severity: alert.Critical, Check: "auto_block", Message: "three", SourceIP: "203.0.113.5", Timestamp: now}}
	if appendErr := st.AppendPendingFindings(second); appendErr != nil {
		t.Fatal(appendErr)
	}

	got, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Message != "one" || got[2].Message != "three" {
		t.Fatalf("pending findings = %+v, want the three appended in order", got)
	}
	again, err := st.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("second take returned %d findings, want none", len(again))
	}
	if _, err := os.Stat(filepath.Join(dir, "pending_findings.json")); !os.IsNotExist(err) {
		t.Fatalf("pending file still present after take: %v", err)
	}
}

// Replay is intentionally at-most-once: the parked file must be cleared
// before dispatch starts. If that clear fails, returning the batch would let
// this process dispatch it and the next process dispatch it again.
func TestPendingFindingsTakeFailsClosedWhenClearFails(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if appendErr := st.AppendPendingFindings([]alert.Finding{{Check: "webshell_realtime", Message: "one"}}); appendErr != nil {
		t.Fatal(appendErr)
	}

	previousRemove := removePendingFindingsFile
	removePendingFindingsFile = func(string) error { return errors.New("read-only state directory") }
	t.Cleanup(func() { removePendingFindingsFile = previousRemove })
	got, err := st.TakePendingFindings()
	if err == nil || len(got) != 0 {
		t.Fatalf("take with failed clear = (%+v, %v), want no dispatchable findings and an error", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, pendingFindingsFile)); err != nil {
		t.Fatalf("pending file lost after failed clear: %v", err)
	}
}
