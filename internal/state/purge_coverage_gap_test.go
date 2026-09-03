package state

import (
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
)

// A scan that could not read a few specific files must still retire findings
// for every file it did read. On a production host one 20.8 MB error_log --
// over the 16 MiB scan limit, and permanently so -- marked the whole YARA
// owner incomplete on every cycle, which meant no yara_match_scheduled
// finding anywhere on the box could ever be purged. Coverage is per file, so
// the protection has to be per file too.

func yaraFinding(path string, ts int64) alert.Finding {
	return alert.Finding{
		Check: "yara_match_scheduled", Message: "YARA rule match [x]: " + path,
		Details: "d " + path, FilePath: path,
		Severity: alert.Critical, Timestamp: time.Unix(ts, 0),
	}
}

func TestPurgeRetiresFindingsForFilesTheScanCovered(t *testing.T) {
	s := openTestStore(t)
	scanned := yaraFinding("/home/a/public_html/old.php", 100)
	gapped := yaraFinding("/home/b/public_html/error_log", 100)
	s.PurgeAndMergeFindings(nil, []alert.Finding{scanned, gapped})

	// The next scan covered old.php (and no longer flags it) but could not
	// read error_log at all.
	s.PurgeAndMergeFindingsPreservingPaths(
		[]string{"yara_match_scheduled"}, nil,
		map[string]bool{"/home/b/public_html/error_log": true})

	got := s.LatestFindings()
	if len(got) != 1 {
		t.Fatalf("want only the unscannable file's finding kept, got %d: %+v", len(got), got)
	}
	if got[0].FilePath != "/home/b/public_html/error_log" {
		t.Fatalf("kept the wrong finding: %+v", got[0])
	}
}

// The case that makes path preservation necessary rather than just tidy: a
// file that carried a finding and has since grown past the scan limit was
// never re-examined, so its finding must survive.
func TestPurgeKeepsAFindingForAFileThatOutgrewTheScanLimit(t *testing.T) {
	s := openTestStore(t)
	grew := yaraFinding("/home/c/public_html/grew.php", 100)
	s.PurgeAndMergeFindings(nil, []alert.Finding{grew})

	s.PurgeAndMergeFindingsPreservingPaths(
		[]string{"yara_match_scheduled"}, nil,
		map[string]bool{"/home/c/public_html/grew.php": true})

	if got := s.LatestFindings(); len(got) != 1 {
		t.Fatalf("an unscanned file's finding must survive the purge, got %+v", got)
	}
}

// With no gaps the behaviour is the ordinary purge.
func TestPurgeWithNoCoverageGapsRetiresEverythingUnraised(t *testing.T) {
	s := openTestStore(t)
	s.PurgeAndMergeFindings(nil, []alert.Finding{yaraFinding("/home/a/x.php", 100)})

	s.PurgeAndMergeFindingsPreservingPaths([]string{"yara_match_scheduled"}, nil, nil)

	if got := s.LatestFindings(); len(got) != 0 {
		t.Fatalf("a fully covered scan must retire what it did not raise, got %+v", got)
	}
}

// A fresh detection on a preserved path still replaces the old snapshot.
func TestPurgePreservedPathStillAcceptsAFreshFinding(t *testing.T) {
	s := openTestStore(t)
	old := yaraFinding("/home/b/error_log", 100)
	s.PurgeAndMergeFindings(nil, []alert.Finding{old})

	fresh := old
	fresh.Timestamp = time.Unix(200, 0)
	s.PurgeAndMergeFindingsPreservingPaths(
		[]string{"yara_match_scheduled"}, []alert.Finding{fresh},
		map[string]bool{"/home/b/error_log": true})

	got := s.LatestFindings()
	if len(got) != 1 || !got[0].Timestamp.Equal(time.Unix(200, 0)) {
		t.Fatalf("fresh detection must replace the preserved snapshot: %+v", got)
	}
}
