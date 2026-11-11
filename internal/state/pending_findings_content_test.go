package state

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
)

func TestPendingFindingsPreserveContentProvenance(t *testing.T) {
	s := openTestStore(t)
	fresh := contentFinding("yara_match_scheduled", shaB)
	carried := fresh
	carried.ScanCarryForward = true
	if err := s.AppendPendingFindings([]alert.Finding{carried}); err != nil {
		t.Fatal(err)
	}
	// A second append reads and rewrites the stored batch.
	if err := s.AppendPendingFindings([]alert.Finding{fresh}); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakePendingFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].ScanCarryForward || got[1].ScanCarryForward {
		t.Fatalf("replayed provenance = %+v, want carried then fresh", got)
	}
	for _, f := range got {
		if f.ContentSHA256 != shaB {
			t.Fatalf("replayed content = %q, want %q", f.ContentSHA256, shaB)
		}
	}
	if pendingIdentity([]alert.Finding{fresh}) == pendingIdentity([]alert.Finding{carried}) {
		t.Fatal("pending identity must distinguish fresh and carried content")
	}
	publicCarried, err := json.Marshal(carried)
	if err != nil {
		t.Fatal(err)
	}
	publicFresh, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicCarried, publicFresh) {
		t.Fatal("internal provenance leaked into the public finding contract")
	}
}
