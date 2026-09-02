package state

import (
	"os"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

// A tier cycle merges its scan findings and then the correlation findings
// derived from the merged set: two writes of the same file back to back.
// The derived step now runs inside the same store update, one write.
func TestPurgeAndMergeFindingsDerivedWritesOnce(t *testing.T) {
	s := openTestStore(t)
	s.PurgeAndMergeFindings(nil, []alert.Finding{{Check: "seed", Message: "old"}})
	before := latestFindingsInode(t, s)

	writes := 0
	old := latestFindingsWriter
	latestFindingsWriter = func(path string, perm os.FileMode, data []byte) error {
		writes++
		return old(path, perm, data)
	}
	t.Cleanup(func() { latestFindingsWriter = old })

	s.PurgeAndMergeFindingsDerived(
		[]string{"seed"},
		[]alert.Finding{{Check: "scan", Message: "fresh"}},
		[]string{"derived"},
		func(current []alert.Finding) []alert.Finding {
			if len(current) != 1 || current[0].Check != "scan" {
				t.Fatalf("derive saw %+v, want the merged scan set", current)
			}
			return []alert.Finding{{Check: "derived", Message: "from scan"}}
		},
	)
	if writes != 1 {
		t.Fatalf("writes = %d, want 1", writes)
	}
	if after := latestFindingsInode(t, s); after == before {
		t.Fatal("merged set changed but the file was not rewritten")
	}
	got := s.LatestFindings()
	if len(got) != 2 {
		t.Fatalf("latest = %+v, want scan + derived", got)
	}
}
