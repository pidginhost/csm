package state

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

func latestFindingsInode(t *testing.T, s *Store) uint64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(s.path, "latest_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("inode not available on this platform")
	}
	return uint64(st.Ino)
}

func sampleFindings(n int) []alert.Finding {
	ts := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	out := make([]alert.Finding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, alert.Finding{
			Severity:  alert.Severity(i % 3),
			Check:     fmt.Sprintf("check_%d", i%5),
			Message:   fmt.Sprintf("finding %d", i),
			Timestamp: ts.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

// Every merge rewrote latest_findings.json (indent-marshalled, fsynced)
// even when nothing changed, twice per tier cycle. An unchanged set now
// leaves the file alone.
func TestLatestFindingsPersistSkipsUnchangedWrite(t *testing.T) {
	s := openTestStore(t)
	findings := sampleFindings(12)
	s.PurgeAndMergeFindings(nil, findings)
	first := latestFindingsInode(t, s)
	s.PurgeAndMergeFindings(nil, findings)
	if second := latestFindingsInode(t, s); second != first {
		t.Fatal("latest_findings.json was rewritten although the finding set did not change")
	}
	s.PurgeAndMergeFindings(nil, []alert.Finding{{Check: "new", Message: "changed"}})
	if third := latestFindingsInode(t, s); third == first {
		t.Fatal("a changed finding set must be persisted")
	}
}

// The persisted order used to follow map iteration, so two daemons with the
// same findings wrote different bytes and the 15000 cap dropped a random
// subset. The file is now ordered by severity, then recency, then key.
func TestLatestFindingsPersistIsDeterministic(t *testing.T) {
	findings := sampleFindings(40)
	reversed := make([]alert.Finding, len(findings))
	for i, f := range findings {
		reversed[len(findings)-1-i] = f
	}
	a := openTestStore(t)
	b := openTestStore(t)
	a.PurgeAndMergeFindings(nil, findings)
	b.PurgeAndMergeFindings(nil, reversed)
	da, err := os.ReadFile(filepath.Join(a.path, "latest_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := os.ReadFile(filepath.Join(b.path, "latest_findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(da) != string(db) {
		t.Fatal("same finding set persisted with different bytes")
	}
	got := a.LatestFindings()
	for i := 1; i < len(got); i++ {
		if got[i].Severity > got[i-1].Severity {
			t.Fatalf("findings not ordered by severity: %d after %d", got[i].Severity, got[i-1].Severity)
		}
	}
}
